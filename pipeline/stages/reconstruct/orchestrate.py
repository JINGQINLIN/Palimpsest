"""Orchestrate the two-phase reconstruction across all functions in topo order.

Supports intra-layer parallelism: when reconstruction_workers > 1, functions
within the same topological layer (no mutual dependencies) are processed
concurrently via a thread pool with a shared registry lock.
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console

from config import AblationConfig
from pipeline.c_source import reconstruction_errors
from pipeline.console import make_progress, print_item, print_step
from pipeline.llm import LLMClient, TokenUsage
from pipeline.outputs import write_function_outputs
from pipeline.paths import FUNCTIONS_SUBDIR
from pipeline.prompts import PromptManager
from pipeline.registry import PLACEHOLDER_RE, NamingRegistry, StructRegistry
from pipeline.registry.coherence import (
    check_field_coherence,
    format_coherence_violations,
)
from pipeline.stages.ghidra import FunctionContext
from pipeline.stages.order import topo_plan

from pipeline.stages.reconstruct._llm import (
    _run_naming_phase,
    _run_structure_coherence_repair,
    _run_structure_phase,
)
from pipeline.stages.reconstruct._apply import _apply_struct_updates
from pipeline.stages.reconstruct.evidence import (
    build_access_evidence_index,
    format_evidence_bundle,
    write_access_evidence_index,
)
from pipeline.artifacts import ReconstructionArtifacts

_log = logging.getLogger("pipeline")


# One concurrent attempt is followed by at most this many sequential recovery
# rounds.  A layer with residual failures aborts the whole reconstruction; its
# callers must never be reconstructed from an incomplete dependency layer.
MAX_LAYER_RETRY_ROUNDS = 3


def prefetch(code: str, registry: NamingRegistry) -> tuple[dict[str, dict], list[str]]:
    """Resolve placeholders in ``code`` against ``registry``.

    Returns:
        (known, unknown) — known symbols have a registry entry, unknown ones do not.
    """
    known: dict[str, dict] = {}
    unknown: list[str] = []
    for symbol in dict.fromkeys(PLACEHOLDER_RE.findall(code)):
        entry = registry.lookup(symbol)
        if entry:
            known[symbol] = entry
        else:
            unknown.append(symbol)
    return known, unknown


def process_function(
    *,
    binary_name: str,
    address: int,
    ghidra_name: str,
    raw_decompile: str,
    known_symbols: dict[str, dict],
    unknown_symbols: list[str],
    registry: NamingRegistry,
    struct_registry: StructRegistry,
    llm: LLMClient,
    structure_context: str,
    naming_context: str,
    language_directive: str = "",
    pcode: str = "",
    access_evidence: str = "",
    ablation: AblationConfig | None = None,
) -> ReconstructionArtifacts:
    """Run structure + naming passes for one function."""
    prompts = PromptManager()
    usage = TokenUsage()
    abl = ablation or AblationConfig()

    # ── structure pass ────────────────────────────────────────────────
    if abl.skip_structure:
        structured = raw_decompile
        applied_structs: list = []
    else:
        structured, proposed_structs, skip_reason = _run_structure_phase(
            prompts=prompts,
            llm=llm,
            usage=usage,
            binary_name=binary_name,
            address=address,
            structure_context=structure_context,
            raw_decompile=raw_decompile,
            struct_registry=struct_registry,
            language_directive=language_directive,
            pcode="" if abl.disable_pcode else pcode,
            access_evidence="" if abl.disable_access_evidence else access_evidence,
        )
        if skip_reason:
            return ReconstructionArtifacts(usage=usage, skip_reason=skip_reason)

        # One repair budget covers both candidate coherence and actual registry
        # acceptance. A rejected layout must never reach Naming as if committed.
        applied_structs = []
        for attempt in range(2):
            errors = reconstruction_errors(raw_decompile, structured)
            report = check_field_coherence(
                structured, struct_registry.get_all(), extra_structs=proposed_structs,
            )
            if report.ok and not errors:
                applied_structs.extend(_apply_struct_updates(
                    struct_registry, proposed_structs, source_file=binary_name,
                ))
                # Candidate fields may have been rejected during conflict checking.
                report = check_field_coherence(structured, struct_registry.get_all())
            if report.ok and not errors:
                break
            violations = "\n".join(errors + ([] if report.ok else [format_coherence_violations(report)]))
            if attempt == 1:
                _log.warning(
                    "field coherence: revert structure 0x%x to raw (%s)",
                    address, violations,
                )
                structured = raw_decompile
                break
            _log.warning(
                "field coherence: repair structure 0x%x against accepted registry (%s)",
                address, violations,
            )
            repaired, repaired_structs = _run_structure_coherence_repair(
                prompts=prompts, llm=llm, usage=usage,
                binary_name=binary_name, address=address,
                raw_decompile=raw_decompile,
                candidate_structured=structured,
                candidate_structs=proposed_structs,
                struct_registry=struct_registry,
                coherence_violations=violations,
                language_directive=language_directive,
                pcode="" if abl.disable_pcode else pcode,
                access_evidence="" if abl.disable_access_evidence else access_evidence,
            )
            if not repaired:
                _log.warning("field coherence: empty repair 0x%x; revert to raw", address)
                structured = raw_decompile
                break
            structured, proposed_structs = repaired, repaired_structs
    # ── naming pass ───────────────────────────────────────────────────
    if abl.skip_naming:
        named = structured
        naming_map = ""
        applied = []
    else:
        named, naming_map, applied = _run_naming_phase(
            prompts=prompts,
            llm=llm,
            usage=usage,
            binary_name=binary_name,
            address=address,
            ghidra_name=ghidra_name,
            naming_context=naming_context,
            structured=structured,
            known_symbols=known_symbols,
            unknown_symbols=unknown_symbols,
            registry=registry,
            language_directive=language_directive,
            access_evidence="" if abl.disable_access_evidence else access_evidence,
        )

    # Naming can re-introduce typed field access; keep the coherent parent.
    if named and named.strip() != structured.strip():
        named_report = check_field_coherence(named, struct_registry.get_all())
        naming_errors = reconstruction_errors(structured, named)
        if not named_report.ok or naming_errors:
            _log.warning(
                "field coherence: revert named 0x%x to structured (%s)",
                address,
                "; ".join(naming_errors) or named_report.summary(),
            )
            named = structured

    return ReconstructionArtifacts(
        usage=usage,
        raw=raw_decompile,
        structured=structured,
        named=named,
        naming_map=naming_map,
        registry_updates=applied,
        struct_updates=applied_structs,
        pcode=pcode,
        access_evidence=access_evidence,
    )


def reconstruct_function(
    *,
    binary_name: str,
    package_dir: Path,
    ctx: FunctionContext,
    registry: NamingRegistry,
    struct_registry: StructRegistry,
    llm: LLMClient,
    structure_context: str,
    naming_context: str,
    language_directive: str = "",
    access_evidence: str = "",
    ablation: AblationConfig | None = None,
) -> dict:
    """Reconstruct one function and write its outputs to disk."""
    known_symbols, unknown_symbols = prefetch(ctx.code, registry)
    artifacts = process_function(
        binary_name=binary_name,
        address=int(ctx.address, 16),
        ghidra_name=ctx.ghidra_name,
        raw_decompile=ctx.code,
        known_symbols=known_symbols,
        unknown_symbols=unknown_symbols,
        registry=registry,
        struct_registry=struct_registry,
        llm=llm,
        structure_context=structure_context,
        naming_context=naming_context,
        language_directive=language_directive,
        pcode=ctx.pcode,
        access_evidence=access_evidence,
        ablation=ablation,
    )
    if not artifacts.skipped:
        func_dir = package_dir / FUNCTIONS_SUBDIR / f"0x{ctx.address}"
        write_function_outputs(func_dir, artifacts)
    return artifacts


def run_reconstruction(
    *,
    binary_name: str,
    package_dir: Path,
    contexts: dict[str, FunctionContext],
    registry: NamingRegistry,
    struct_registry: StructRegistry,
    llm: LLMClient,
    structure_context: str,
    naming_context: str,
    language_directive: str = "",
    console: Console,
    ablation: AblationConfig | None = None,
) -> tuple[TokenUsage, list[tuple[str, str]], list[tuple[str, str, str]]]:
    """Run reconstruction across all functions in leaf-first topo order.

    Returns:
        (total_usage, failed, skipped) where failed is (addr, error) and
        skipped is (addr, ghidra_name, skip_reason).
    """
    plan = topo_plan(contexts)
    abl = ablation or AblationConfig()
    access_index = None
    access_evidence_by_address: dict[str, str] = {}
    if not abl.disable_access_evidence:
        access_index = build_access_evidence_index(contexts)
        access_evidence_by_address = {
            addr: format_evidence_bundle(access_index, contexts, addr)
            for addr in contexts
        }
        evidence_path = write_access_evidence_index(package_dir, access_index)
    else:
        evidence_path = None

    print_step(console, "2. Semantic reconstruction")
    print_item(console, "functions", len(contexts))
    print_item(console, "model", llm.model)
    print_item(console, "output", package_dir)
    print_item(console, "topo depth", plan.summary())
    if evidence_path is not None:
        object_count = sum(len(items) for items in access_index.by_address.values()) if access_index else 0
        print_item(console, "access evidence", f"{object_count} object(s) -> {evidence_path}")
    console.print()

    total_usage = TokenUsage()
    failed: list[tuple[str, str]] = []
    skipped: list[tuple[str, str, str]] = []
    workers = max(1, getattr(abl, "reconstruction_workers", 1) or 1)
    # Single lock guards all shared mutable accumulators (total_usage, failed,
    # skipped). Previously only total_usage.merge() was locked; the list
    # appends were unprotected, which races under 32-way concurrency because
    # list.append() is not atomic across CPython's free-threaded paths and
    # can also be torn by GIL hand-off between the compare and the resize.
    state_lock = threading.Lock()

    def _process_one(addr_hex: str) -> tuple[bool, str]:
        """Process one function and return ``(success, error_message)``."""
        ctx = contexts[addr_hex]
        try:
            artifacts = reconstruct_function(
                binary_name=binary_name, package_dir=package_dir,
                ctx=ctx, registry=registry, struct_registry=struct_registry,
                llm=llm, structure_context=structure_context,
                naming_context=naming_context, language_directive=language_directive,
                access_evidence=access_evidence_by_address.get(addr_hex, ""),
                ablation=ablation,
            )
            with state_lock:
                total_usage.merge(artifacts.usage)
            if artifacts.skipped:
                raise ValueError(f"forbidden skip: {artifacts.skip_reason}")
            return True, ""
        except Exception as exc:
            console.print(f"  [red]failed[/red] 0x{addr_hex}: {exc}")
            return False, str(exc)

    steps = plan.walk()
    total = len(steps)

    with make_progress(console) as progress:
        task = progress.add_task(
            f"reconstructing ({workers} workers)", total=total
        )
        completed = 0  # thread-safe-ish counter (only main thread reads/writes)
        # Group steps by layer so we can batch concurrently.
        # Position format: "d{depth} {index}/{size}".  Compare only the depth prefix.
        step_index = 0
        while step_index < total:
            current_pos = steps[step_index][1]
            current_depth = current_pos.split()[0]  # e.g. "d0" from "d0 1/97"
            layer_addrs: list[str] = []
            while step_index < total and steps[step_index][1].split()[0] == current_depth:
                layer_addrs.append(steps[step_index][0])
                step_index += 1

            layer_workers = min(workers, len(layer_addrs))
            if layer_addrs:
                progress.update(task,
                    description=f"{current_depth}  x{layer_workers}  starting...",
                    completed=completed)

            # Run the layer concurrently once.
            done_lock = threading.Lock()
            layer_done = [0]
            layer_errors: dict[str, str] = {}
            pool = ThreadPoolExecutor(max_workers=layer_workers)
            futures = {pool.submit(_process_one, a): a for a in layer_addrs}
            for f in as_completed(futures):
                addr_hex = futures[f]
                ok, error = f.result()
                if not ok:
                    layer_errors[addr_hex] = error
                with done_lock:
                    layer_done[0] += 1
                    completed += 1
                progress.update(
                    task,
                    description=f"{current_depth}  x{layer_workers}  {layer_done[0]}/{len(layer_addrs)} done",
                    completed=completed,
                )
            pool.shutdown(wait=True)

            # Retry only residual failures, sequentially.  Do not advance to a
            # caller layer until every function in this dependency layer exists.
            for retry_round in range(1, MAX_LAYER_RETRY_ROUNDS + 1):
                if not layer_errors:
                    break
                retry_addrs = list(layer_errors)
                next_errors: dict[str, str] = {}
                for addr_hex in retry_addrs:
                    ok, error = _process_one(addr_hex)
                    if not ok:
                        next_errors[addr_hex] = error
                recovered = len(retry_addrs) - len(next_errors)
                console.print(
                    f"  [yellow]retry {current_depth} round {retry_round}/"
                    f"{MAX_LAYER_RETRY_ROUNDS}: recovered {recovered}/"
                    f"{len(retry_addrs)}, remaining {len(next_errors)}[/yellow]"
                )
                layer_errors = next_errors

            if layer_errors:
                failed.extend(sorted(layer_errors.items()))
                console.print(
                    f"  [red]aborting after {current_depth}:[/red] "
                    f"{len(layer_errors)} function(s) still failed; later layers were not run"
                )
                break

    # Conflict summary: read directly from the registries' conflict logs.
    naming_conflict_cnt = registry.get_conflict_count()
    struct_conflict_cnt = struct_registry.get_conflict_count()
    if naming_conflict_cnt or struct_conflict_cnt:
        print_item(
            console,
            "conflicts",
            f"{struct_conflict_cnt} struct log entries, {naming_conflict_cnt} naming log entries",
        )
    else:
        print_item(console, "conflicts", "none")

    return total_usage, failed, skipped
