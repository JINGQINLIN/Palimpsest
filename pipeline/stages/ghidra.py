"""Ghidra export stage.

Drives pyghidra-mcp (Ghidra Headless) to decompile every function and dumps the
raw pseudo-C as per-function JSON. By design it exports ONLY decompiled code,
not the Data Type Manager: struct layouts are re-inferred later by the LLM
(structure phase) instead of trusting Ghidra's often-incomplete type database.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from config import ghidra_settings, load_config
from pipeline.addresses import normalize_address
from pipeline.console import make_progress, print_item, print_step


@dataclass
class FunctionContext:
    address: str
    ghidra_name: str
    code: str = ""
    pcode: str = ""

    def to_json(self) -> str:
        return json.dumps(
            {
                "address": self.address,
                "ghidra_name": self.ghidra_name,
                "code": self.code,
                "pcode": self.pcode,
            },
            ensure_ascii=False,
            indent=2,
        )

    @classmethod
    def from_json(cls, text: str) -> "FunctionContext":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid function JSON: {exc}; first 200 chars: {text[:200]!r}"
            ) from exc
        return cls(
            address=normalize_address(data.get("address")),
            ghidra_name=str(data.get("ghidra_name") or ""),
            code=str(data.get("code") or ""),
            pcode=str(data.get("pcode") or ""),
        )


def load_raw_package(raw_dir: Path) -> dict[str, FunctionContext]:
    if not raw_dir.is_dir():
        raise FileNotFoundError(f"raw package not found: {raw_dir}")

    contexts: dict[str, FunctionContext] = {}
    for path in sorted(raw_dir.glob("*.json")):
        # Skip metadata files (e.g. _dedup_report.json) — they are not
        # FunctionContext payloads and would break from_json.
        if path.name.startswith("_"):
            continue
        ctx = FunctionContext.from_json(path.read_text(encoding="utf-8"))
        if ctx.address:
            contexts[ctx.address] = ctx

    if not contexts:
        raise RuntimeError(f"no *.json files found in raw package: {raw_dir}")
    return contexts


def filter_runtime_contexts(contexts: dict[str, FunctionContext]) -> dict[str, FunctionContext]:
    def is_runtime_stub(name: str) -> bool:
        return name == "_start" or name.startswith(("_INIT", "_FINI", "_DT_INIT", "_DT_FINI"))

    return {
        addr: ctx
        for addr, ctx in contexts.items()
        if not is_runtime_stub(ctx.ghidra_name)
    }


def load_ghidra_config(config=None) -> tuple[str, str]:
    """Return Ghidra settings from the pipeline's already-loaded config.

    The optional fallback preserves standalone callers, while ``main.py``
    passes its explicit ``--config`` result so behavior never depends on the
    shell's current working directory.
    """
    return ghidra_settings(config if config is not None else load_config())


# ---------------------------------------------------------------------------
# Overlap-entry dedup
# ---------------------------------------------------------------------------

# Ghidra's function manager frequently creates TWO symbol-table entries for
# one physical function when the prologue is recognized as a separate symbol:
#   - prologue entry at the function start (reached by call sites)
#   - body entry a few bytes later (12 bytes = 3 MIPS instructions on MIPS)
# Palimpsest would otherwise decompile both and emit duplicate APIs that
# differ only in naming (e.g. readfromclient vs read_from_client).
#
# We collapse these pairs right after the raw export:
#   1. callsite primary — drop the side with 0 callers (the body entry).
#   2. hash fallback — when both sides have 0 callers, drop one if their
#      normalized code hashes match.

_OVERLAP_GAP_THRESHOLD = 16


def _code_fingerprint(code: str) -> str:
    """Hash a function body so that structurally identical code collides.

    Strips comments, normalizes FUN_xxxxxxxx / 0x... literals and whitespace
    so that two entries of the same function (which may differ only in
    auto-generated names) hash to the same value.
    """
    text = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    text = re.sub(r"//.*", "", text)
    text = re.sub(r"\bFUN_[0-9a-fA-F]+\b", "FUN_", text)
    text = re.sub(r"\b0x[0-9a-fA-F]+\b", "0x", text)
    text = re.sub(r"\s+", " ", text).strip()
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _compute_callers_count(contexts: dict[str, "FunctionContext"]) -> dict[str, int]:
    """Count how many other functions reference each function by name.

    Mirrors the call-graph extraction in pipeline.agent.graph: regex-scan
    every function's code for `name(` occurrences, excluding self-calls.
    """
    name_to_addr: dict[str, str] = {}
    for addr, ctx in contexts.items():
        name = ctx.ghidra_name
        if name:
            name_to_addr.setdefault(name, addr)

    callers_count: dict[str, int] = {name: 0 for name in name_to_addr}
    names = [n for n in name_to_addr if n]
    if not names:
        return callers_count

    callee_re = re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\s*\(")
    for addr, ctx in contexts.items():
        code = ctx.code
        self_name = ctx.ghidra_name
        called = set(callee_re.findall(code))
        called.discard(self_name)
        for name in called:
            if name in callers_count:
                callers_count[name] += 1
    return callers_count


def dedup_overlap_entries(
    contexts: dict[str, "FunctionContext"],
    gap_threshold: int = _OVERLAP_GAP_THRESHOLD,
) -> tuple[dict[str, "FunctionContext"], list[dict]]:
    """Remove overlap-entry duplicates from a raw function set.

    Returns (filtered_contexts, report) where *report* is a list of dicts
    describing every dropped entry, with keys:
        kept, dropped, gap, kept_name, dropped_name,
        kept_callers, dropped_callers, reason
    """
    if not contexts:
        return contexts, []

    def sort_key(a: str) -> int:
        try:
            return int(a, 16)
        except ValueError:
            return 0

    addrs = sorted(contexts.keys(), key=sort_key)
    callers_count = _compute_callers_count(contexts)

    # Find address-adjacent pairs within gap_threshold bytes.
    pairs: list[tuple[str, str, int]] = []
    for i in range(len(addrs) - 1):
        a, b = addrs[i], addrs[i + 1]
        try:
            gap = int(b, 16) - int(a, 16)
        except ValueError:
            continue
        if 0 < gap <= gap_threshold:
            pairs.append((a, b, gap))

    drop_addrs: set[str] = set()
    report: list[dict] = []

    for a, b, gap in pairs:
        if a in drop_addrs or b in drop_addrs:
            continue  # chain effect: already removed by an earlier pair
        a_name = contexts[a].ghidra_name
        b_name = contexts[b].ghidra_name
        a_cs = callers_count.get(a_name, 0)
        b_cs = callers_count.get(b_name, 0)

        drop: str | None = None
        reason = ""
        if a_cs > 0 and b_cs == 0:
            drop = b
            reason = f"callsite: a={a_cs} b={b_cs} → drop body entry b"
        elif b_cs > 0 and a_cs == 0:
            drop = a
            reason = f"callsite: a={a_cs} b={b_cs} → drop body entry a"
        elif a_cs == 0 and b_cs == 0:
            # Both orphaned — only collapse if code is structurally identical.
            if _code_fingerprint(contexts[a].code) == _code_fingerprint(contexts[b].code):
                drop = b  # keep lower address (prologue entry)
                reason = "hash fallback: both 0 callers, code hash matches → drop b"
        # else: both have callers — not an overlap duplicate, skip.

        if drop is not None:
            kept = a if drop == b else b
            drop_addrs.add(drop)
            report.append({
                "kept": kept,
                "dropped": drop,
                "gap": gap,
                "kept_name": contexts[kept].ghidra_name,
                "dropped_name": contexts[drop].ghidra_name,
                "kept_callers": a_cs if drop == b else b_cs,
                "dropped_callers": b_cs if drop == b else a_cs,
                "reason": reason,
            })

    filtered = {addr: ctx for addr, ctx in contexts.items() if addr not in drop_addrs}
    return filtered, report



def _normalize_code(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


async def _call(session, tool: str, **args) -> dict:
    result = await session.call_tool(tool, args)
    text = "".join(item.text for item in result.content if hasattr(item, "text") and item.text)
    if getattr(result, "isError", False):
        raise RuntimeError(f"{tool} error: {text[:300] or '(empty)'}")
    if not text.strip():
        raise RuntimeError(f"{tool} returned empty content")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"{tool} returned non-JSON response: {exc}; first 200 chars: {text[:200]!r}"
        ) from exc


async def _wait_until_ready(session, binary: str, timeout: float = 300.0) -> None:
    waited = 0.0
    while waited < timeout:
        programs = (await _call(session, "list_project_binaries")).get("programs") or []
        ready = any(
            item.get("name", "").lstrip("/") == binary and item.get("analysis_complete")
            for item in programs
        )
        if ready:
            return
        await asyncio.sleep(3.0)
        waited += 3.0
    raise TimeoutError(f"Ghidra analysis not complete within {timeout}s")


async def _list_functions(session, binary: str) -> list[dict]:
    functions: list[dict] = []
    seen: set[str] = set()
    offset = 0
    page_size = 500

    while True:
        data = await _call(
            session,
            "search_symbols_by_name",
            binary_name=binary,
            query=".",
            functions_only=True,
            offset=offset,
            limit=page_size,
        )
        symbols = data.get("symbols") or []
        if not symbols:
            break

        for item in symbols:
            if item.get("external") or item.get("is_thunk"):
                continue
            addr = normalize_address(item.get("address"))
            if not addr or addr in seen:
                continue
            seen.add(addr)
            functions.append({"address": addr, "name": item.get("name") or f"FUN_{addr}"})

        if len(symbols) < page_size:
            break
        offset += page_size

    return functions


async def _decompile_all(
    session, binary: str, functions: list[dict], output_dir: Path, console: Console
) -> tuple[int, list[tuple[str, str]]]:
    """Decompile every function and write it as <addr>.json.

    Returns (ok_count, failed) where failed is a list of (address, error).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    ok = 0
    failed: list[tuple[str, str]] = []

    with make_progress(console) as progress:
        task = progress.add_task("fetching...", total=len(functions))
        for func in functions:
            addr = func["address"]
            progress.update(task, description=f"0x{addr}  {func['name']}")
            try:
                # Ghidra expects unpadded hex addresses (e.g. 0xa14c, not 0x0000a14c).
                ghidra_addr = "0x" + (addr.lstrip("0") or "0")
                data = await _call(
                    session,
                    "decompile_function",
                    binary_name=binary,
                    name_or_address=ghidra_addr,
                )
                code = _normalize_code(data.get("code") or "")
                if code:
                    pcode = str(data.get("pcode") or "")
                    ctx = FunctionContext(address=addr, ghidra_name=func["name"], code=code, pcode=pcode)
                    (output_dir / f"{addr}.json").write_text(ctx.to_json(), encoding="utf-8")
                    ok += 1
            except Exception as exc:
                failed.append((addr, str(exc)))
                console.print(f"  [red]failed[/red] 0x{addr}: {exc}")
            progress.advance(task)

    return ok, failed


async def fetch(
    binary_path: Path,
    output_dir: Path,
    ghidra_dir: str,
    mcp_exe: str,
    console: Console,
) -> int:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    print_step(console, "Ghidra fetch")
    print_item(console, "binary", binary_path)
    print_item(console, "output", output_dir)

    # pyghidra-mcp caches Ghidra projects in ./pyghidra_mcp_projects.
    # If a stale project from a previous run exists, list_project_binaries
    # may return the wrong binary.  Nuke it before each fetch so concurrent
    # runs don't step on each other.
    _PROJECT_DIR = Path("pyghidra_mcp_projects")
    if _PROJECT_DIR.exists():
        shutil.rmtree(_PROJECT_DIR, ignore_errors=True)

    params = StdioServerParameters(
        command=mcp_exe,
        args=["--wait-for-analysis", str(binary_path)],
        env={"GHIDRA_INSTALL_DIR": ghidra_dir},
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            programs = (await _call(session, "list_project_binaries")).get("programs") or []
            if not programs:
                raise RuntimeError("pyghidra-mcp has no loaded binaries")

            binary = programs[0]["name"].lstrip("/")
            print_item(console, "program", binary)
            print_item(console, "status", "waiting for analysis")
            await _wait_until_ready(session, binary)

            functions = await _list_functions(session, binary)
            print_item(console, "functions", len(functions))

            ok, failed = await _decompile_all(session, binary, functions, output_dir, console)

    # Collapse overlap-entry duplicates (prologue + body entries for the
    # same physical function) before downstream stages see them.
    contexts = load_raw_package(output_dir)
    filtered, dedup_report = dedup_overlap_entries(contexts)
    for entry in dedup_report:
        dropped_path = output_dir / f"{entry['dropped']}.json"
        if dropped_path.exists():
            dropped_path.unlink()
    # Write the report to the parent directory (not raw/) so it doesn't
    # pollute the function JSON set consumed by load_raw_package.
    dedup_report_path = output_dir.parent / "_dedup_report.json"
    dedup_report_path.write_text(
        json.dumps(dedup_report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print_item(console, "dedup", f"{len(dedup_report)} overlap duplicates removed")

    print_step(console, "[green]Ghidra fetch done[/green]")
    print_item(console, "functions", f"{ok} ok, {len(failed)} failed")
    print_item(console, "output", output_dir)
    return 0 if not failed else 2
