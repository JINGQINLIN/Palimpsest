"""Two LLM phases: structure recovery and symbol naming."""
from __future__ import annotations

import logging
import re
from typing import Any

from pipeline.llm import DEFAULT_MAX_TOKENS, LLMClient, TokenUsage
from pipeline.c_source import apply_local_renames
from pipeline.prompts import PromptManager
from pipeline.registry import NamingRegistry, StructRegistry, format_struct_summary

from pipeline.stages.reconstruct._apply import (
    _apply_registry_updates,
)
from pipeline.stages.reconstruct._parsing import (
    _parse_naming_output,
    _parse_structure_output,
)

# P-Code operations relevant to struct inference.
_PCODE_RELEVANT_OPS = re.compile(r"\b(LOAD|STORE|PTRSUB|PTRADD|INT_ADD|CAST|CALL)\b")
_PCODE_PTRSUB = re.compile(r"^\S+:\s*\([^,]+,\s*([^,]+),\s*(\d+)\)\s*=\s*PTRSUB\([^,]+,\s*(0x[0-9a-fA-F]+)\)")
_PCODE_MAX_CHARS = 6_000

# P-Code / LLM struct cross-validation thresholds.
_ARRAY_MIN_ELEMENTS = 3
_ARRAY_OVERLAP_FLOOR = 3
_ARRAY_OVERLAP_RATIO = 0.5
_START_OFFSET_TOLERANCE_BYTES = 4
_START_OVERLAP_RATIO = 0.7
def _needs_pcode(raw_c_code: str) -> bool:
    """P-Code is only useful when the C code has offset-based memory access."""
    return bool(
        re.search(
            r"\*\s*\([^)]*\*\s*\)\s*\([^;\n]*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)",
            raw_c_code,
        )
        or re.search(r"\b[A-Za-z_]\w*\s*\[\s*0x[0-9a-fA-F]+\s*\]", raw_c_code)
    )


def _parse_pcode_offsets(raw: str) -> dict[str, dict]:
    """Parse raw P-Code into per-register access summaries for validation.

    Returns: {base_reg: {'offsets': {int offset, ...}, 'sizes': {int, ...},
                          'min_offset': int, 'is_array': bool, 'step': int}}
    """
    if not raw:
        return {}
    regs: dict[str, dict] = {}
    for line in raw.splitlines():
        # The raw P-Code dump is not SSA-stable enough to bind LOAD/STORE
        # varnodes back to source objects here. Keep this parser intentionally
        # empty until the Ghidra exporter provides definition identities.
        _ = line

    # detect array patterns
    for base, info in regs.items():
        offs = sorted(info["offsets"])
        info["is_array"] = False
        info["step"] = 0
        if len(offs) >= _ARRAY_MIN_ELEMENTS and len(info["sizes"]) == 1:
            step = offs[1] - offs[0]
            if step > 0 and all(offs[i] - offs[i-1] == step for i in range(1, len(offs))):
                info["is_array"] = True
                info["step"] = step

    return regs


def _validate_struct_updates(struct_updates: list[dict], pcode_raw: str) -> list[dict]:
    """Keep struct updates unless a trusted object-level P-Code validator exists.

    The current P-Code export contains register and unique varnodes without
    stable SSA definition links. Treating those varnode offsets as object field
    offsets can falsely reject real structs. Field coherence still runs after
    the LLM output and catches typed-field/layout mismatches in the emitted C.
    """
    _ = pcode_raw
    return struct_updates


def _filter_pcode(raw: str, raw_c_code: str = "") -> str:
    """Extract conservative P-Code lines for the prompt; skip if not needed."""
    if not raw or (raw_c_code and not _needs_pcode(raw_c_code)):
        return ""

    lines = [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and _PCODE_RELEVANT_OPS.search(line)
    ]
    if not lines:
        return ""

    text = "\n".join(lines)
    if len(text) > _PCODE_MAX_CHARS:
        text = text[:_PCODE_MAX_CHARS] + "\n…(truncated)"
    return text


def _format_known_structs(structs: dict[str, dict]) -> str:
    if not structs:
        return ""
    return "\n".join(
        format_struct_summary(name, entry) for name, entry in sorted(structs.items())
    )


def _format_known_symbols(known: dict[str, dict]) -> str:
    if not known:
        return "(none)"
    lines = []
    for symbol, entry in sorted(known.items()):
        type_part = f" :: {entry['inferred_type']}" if entry.get("inferred_type") else ""
        lines.append(
            f"{symbol} -> {entry['canonical_name']}{type_part} "
            f"[{entry['kind']}, {entry['confidence']}] # {entry['evidence']}"
        )
    return "\n".join(lines)


def _run_structure_phase(
    *,
    prompts: PromptManager,
    llm: LLMClient,
    usage: TokenUsage,
    binary_name: str,
    address: int,
    structure_context: str,
    raw_decompile: str,
    struct_registry: StructRegistry,
    language_directive: str,
    pcode: str = "",
    access_evidence: str = "",
) -> tuple[str, list[dict[str, Any]], str]:
    """Structure pass: recover control flow and infer struct layouts.

    Returns:
        (structured_code, proposed_struct_updates, skip_reason). A non-empty
        skip_reason means the LLM marked the function as trivial/skippable.
        Callers must run field-coherence then ``_apply_struct_updates``.
    """
    structure_prompt = prompts.load(
        "structure.jinja2",
        binary_name=binary_name,
        address=f"0x{address:x}",
        domain_context=structure_context,
        raw_decompile=raw_decompile,
        known_structs=_format_known_structs(struct_registry.get_all()),
        language_directive=language_directive,
        function_pcode=_filter_pcode(pcode, raw_c_code=raw_decompile),
        access_evidence=access_evidence,
    )
    # Keep the configured thinking mode for every reconstruction call. This is
    # enabled for the current GLM-5.2 configuration and avoids per-stage drift.
    structure_text, step_usage = llm.complete(
        structure_prompt,
        max_tokens=DEFAULT_MAX_TOKENS,
    )
    usage.merge(step_usage)
    structured, struct_updates, skip_reason = _parse_structure_output(structure_text)
    if skip_reason:
        raise ValueError(f"LLM attempted forbidden skip: {skip_reason}")
    if not structured:
        raise ValueError("LLM structure step returned empty output")
    # P-Code cross-validation: reject structs that contradict ground-truth memory access
    if struct_updates and pcode:
        before = len(struct_updates)
        struct_updates = _validate_struct_updates(struct_updates, pcode)
        if len(struct_updates) < before:
            rejected = before - len(struct_updates)
            logging.getLogger("pipeline").info(
                f"P-Code validation: rejected {rejected}/{before} struct(s) for 0x{address:x}"
            )
    # Do not apply to the registry here — the orchestrator runs field
    # coherence first and only commits layouts that match the structured body.
    return structured, struct_updates or [], ""


def _run_structure_coherence_repair(
    *,
    prompts: PromptManager,
    llm: LLMClient,
    usage: TokenUsage,
    binary_name: str,
    address: int,
    raw_decompile: str,
    candidate_structured: str,
    candidate_structs: list[dict[str, Any]],
    struct_registry: StructRegistry,
    coherence_violations: str,
    language_directive: str,
    pcode: str = "",
    access_evidence: str = "",
) -> tuple[str, list[dict[str, Any]]]:
    """One-shot repair after field-coherence failure.

    Returns:
        (repaired_structured, proposed_struct_updates). Empty structured means
        the repair call produced nothing usable; caller should fall back.
    """
    # A proposal is not an accepted definition: keep conflicting candidates
    # separate so the repair cannot mistake rejected fields for registry truth.
    known = struct_registry.get_all()
    candidates = {str(item.get("name")): item for item in candidate_structs if item.get("name")}

    repair_prompt = prompts.load(
        "structure_coherence_repair.jinja2",
        binary_name=binary_name,
        address=f"0x{address:x}",
        language_directive=language_directive,
        coherence_violations=coherence_violations,
        known_structs=_format_known_structs(known),
        candidate_structs=_format_known_structs(candidates),
        candidate_structured=candidate_structured,
        raw_decompile=raw_decompile,
        function_pcode=_filter_pcode(pcode, raw_c_code=raw_decompile),
        access_evidence=access_evidence,
    )
    repair_text, step_usage = llm.complete(
        repair_prompt,
        max_tokens=DEFAULT_MAX_TOKENS,
    )
    usage.merge(step_usage)
    structured, struct_updates, skip_reason = _parse_structure_output(repair_text)
    if skip_reason or not structured:
        return "", []
    if struct_updates and pcode:
        struct_updates = _validate_struct_updates(struct_updates, pcode)
    # If the model omits struct_updates, keep the prior proposal for re-check.
    if not struct_updates:
        struct_updates = list(candidate_structs)
    return structured, struct_updates


def _run_naming_phase(
    *,
    prompts: PromptManager,
    llm: LLMClient,
    usage: TokenUsage,
    binary_name: str,
    address: int,
    ghidra_name: str,
    naming_context: str,
    structured: str,
    known_symbols: dict[str, dict],
    unknown_symbols: list[str],
    registry: NamingRegistry,
    language_directive: str,
    access_evidence: str = "",
) -> tuple[str, str, list[dict[str, Any]]]:
    """Naming pass: assign canonical symbol names.

    Returns:
        (named_code, naming_map, applied_updates). named_code falls back to the
        structured code when the LLM returns nothing.
    """
    naming_prompt = prompts.load(
        "naming.jinja2",
        binary_name=binary_name,
        address=f"0x{address:x}",
        ghidra_symbol=ghidra_name,
        domain_context=naming_context,
        structured_code=structured,
        known_symbols=_format_known_symbols(known_symbols),
        unknown_symbols=", ".join(unknown_symbols) if unknown_symbols else "(none)",
        language_directive=language_directive,
        access_evidence=access_evidence,
    )
    naming_text, step_usage = llm.complete(
        naming_prompt,
        max_tokens=DEFAULT_MAX_TOKENS,
    )
    usage.merge(step_usage)

    if "<naming_map>" not in naming_text or "<registry_updates>" not in naming_text:
        raise ValueError("LLM naming step returned no naming table or registry updates")
    _, naming_map, updates = _parse_naming_output(naming_text)
    named, naming_map = apply_local_renames(structured, naming_map)
    applied = _apply_registry_updates(registry, updates, source_file=binary_name)
    return named, naming_map, applied
