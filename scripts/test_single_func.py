"""Single-function regression test for prompt / thinking changes.

Target: WIRESchList (0x00495d3c) — the worst noise offender in the webs experiment.

Usage (from semant_func root, in semant conda env):
    python scripts/test_single_func.py

Compares the new structured + named output against the old named.c by counting:
  goto | LAB_ | w_var | tmp_ | local_ | acStack_ | 0x[0-9a-f]{3,} | *(uint32_t *)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rich.console import Console

from config import load_config
from pipeline.llm import TokenUsage, client_from_config
from pipeline.prompts import PromptManager
from pipeline.registry import NamingRegistry, StructRegistry
from pipeline.stages.reconstruct._llm import _run_structure_phase, _run_naming_phase
from pipeline.stages.ghidra import FunctionContext

FUNC_ADDR = "00495d3c"
RAW_PATH = ROOT / "output" / "webs" / "raw" / f"{FUNC_ADDR}.json"
OLD_NAMED = ROOT / "output" / "webs" / "reconstruction" / "functions" / f"0x{FUNC_ADDR}" / "named.c"

console = Console()

# ── metrics ────────────────────────────────────────────────────────────
NOISE_PATTERNS = {
    "goto": re.compile(r"\bgoto\b"),
    "LAB_": re.compile(r"\bLAB_\w+"),
    "iVar/uVar": re.compile(r"\b[iu]Var\d+\b"),
    "undefined*": re.compile(r"\bundefined\d*\b"),
    "local_*/acStack_*": re.compile(r"\b(local_[0-9a-f]{3,}|a[cifu]Stack_[0-9a-f]+)\b"),
    "w_var*": re.compile(r"\bw_var\d+\b"),
    "tmp_*": re.compile(r"\btmp_[a-z]\b"),
    "hex >= 3 digits": re.compile(r"\b0x[0-9a-fA-F]{3,}\b"),
    "bare ptr cast": re.compile(r"\*\(\w+\s*\*\)\s*\(\s*\(int\s*\)"),
    "word-by-word copy": re.compile(r"\*\(\s*uint32_t\s*\*\).*src.*dst"),
}

def count_noise(code: str) -> dict[str, int]:
    return {name: len(p.findall(code)) for name, p in NOISE_PATTERNS.items()}

def fmt_metrics(m: dict[str, int], label: str) -> None:
    total = sum(m.values())
    console.print(f"\n[bold]{label}[/bold] (noise score: {total})")
    for name, count in sorted(m.items(), key=lambda x: -x[1]):
        if count:
            console.print(f"  {name}: [red]{count}[/red]")
        else:
            console.print(f"  {name}: [green]{count}[/green]")


def main() -> int:
    if not RAW_PATH.is_file():
        console.print(f"[red]raw file not found:[/red] {RAW_PATH}")
        return 1

    console.print(f"[bold]Target:[/bold] WIRESchList (0x{FUNC_ADDR})")
    console.print(f"[bold]Raw:[/bold] {RAW_PATH}")
    console.print(f"[bold]Old named.c:[/bold] {OLD_NAMED}")

    # ── load old output ────────────────────────────────────────────────
    if OLD_NAMED.is_file():
        old_code = OLD_NAMED.read_text(encoding="utf-8")
        fmt_metrics(count_noise(old_code), "OLD named.c")
    else:
        console.print("[yellow]old named.c not found; skipping baseline[/yellow]")

    # ── load raw Ghidra data ───────────────────────────────────────────
    ctx = FunctionContext.from_json(RAW_PATH.read_text(encoding="utf-8"))
    console.print(f"\n[bold]Raw code:[/bold] {len(ctx.code)} chars, [bold]P-Code:[/bold] {len(ctx.pcode)} chars")

    # ── init LLM and registries ────────────────────────────────────────
    try:
        config = load_config()
        llm = client_from_config(config)
    except RuntimeError as exc:
        console.print(f"[red]config error:[/red] {exc}")
        return 1

    console.print(f"[bold]Model:[/bold] {llm.model}")
    prompts = PromptManager()
    struct_registry = StructRegistry(":memory:")
    naming_registry = NamingRegistry(":memory:")
    usage = TokenUsage()

    # ── run structure phase ────────────────────────────────────────────
    console.print("\n[bold cyan]=== Structure Phase ===[/bold cyan]")
    address_int = int(FUNC_ADDR, 16)

    structured, proposed_structs, skip_reason = _run_structure_phase(
        prompts=prompts,
        llm=llm,
        usage=usage,
        binary_name="webs",
        address=address_int,
        structure_context="",
        raw_decompile=ctx.code,
        struct_registry=struct_registry,
        language_directive="",
        pcode=ctx.pcode,
    )
    if skip_reason:
        console.print(f"[yellow]SKIPPED:[/yellow] {skip_reason}")
        return 0

    from pipeline.stages.reconstruct._apply import _apply_struct_updates
    from pipeline.stages.reconstruct._llm import _run_structure_coherence_repair
    from pipeline.registry.coherence import (
        check_field_coherence,
        format_coherence_violations,
    )

    report = check_field_coherence(
        structured, struct_registry.get_all(), extra_structs=proposed_structs
    )
    if not report.ok:
        console.print(f"[yellow]coherence FAIL — attempting 1 repair:[/yellow] {report.summary()}")
        repaired, repaired_structs = _run_structure_coherence_repair(
            prompts=prompts,
            llm=llm,
            usage=usage,
            binary_name="webs",
            address=address_int,
            raw_decompile=ctx.code,
            candidate_structured=structured,
            candidate_structs=proposed_structs,
            struct_registry=struct_registry,
            coherence_violations=format_coherence_violations(report),
            language_directive="",
            pcode=ctx.pcode,
        )
        if repaired:
            repair_report = check_field_coherence(
                repaired, struct_registry.get_all(), extra_structs=repaired_structs
            )
            if repair_report.ok:
                console.print(f"[green]coherence repaired:[/green] {repair_report.summary()}")
                structured, proposed_structs = repaired, repaired_structs
                report = repair_report
            else:
                console.print(f"[yellow]repair still failing:[/yellow] {repair_report.summary()}")
        else:
            console.print("[yellow]empty repair output[/yellow]")

    if not report.ok:
        console.print(f"[yellow]coherence FAIL — keeping structured for inspection:[/yellow] {report.summary()}")
        structs = []
    else:
        structs = _apply_struct_updates(
            struct_registry, proposed_structs, source_file="webs"
        )
    console.print(f"[bold]Structured output:[/bold] {len(structured)} chars")
    fmt_metrics(count_noise(structured), "NEW structured")

    # ── run naming phase ──────────────────────────────────────────────
    console.print("\n[bold cyan]=== Naming Phase ===[/bold cyan]")

    from pipeline.registry import PLACEHOLDER_RE
    known_symbols: dict[str, dict] = {}
    unknown_symbols: list[str] = []
    for symbol in dict.fromkeys(PLACEHOLDER_RE.findall(structured)):
        entry = naming_registry.lookup(symbol)
        if entry:
            known_symbols[symbol] = entry
        else:
            unknown_symbols.append(symbol)

    named, naming_map, updates = _run_naming_phase(
        prompts=prompts,
        llm=llm,
        usage=usage,
        binary_name="webs",
        address=address_int,
        ghidra_name=ctx.ghidra_name,
        naming_context="",
        structured=structured,
        known_symbols=known_symbols,
        unknown_symbols=unknown_symbols,
        registry=naming_registry,
        language_directive="",
    )

    console.print(f"[bold]Named output:[/bold] {len(named)} chars")
    fmt_metrics(count_noise(named), "NEW named")

    # ── summary ────────────────────────────────────────────────────────
    console.print(f"\n[bold green]Done.[/bold green]")
    console.print(f"[bold]Tokens:[/bold] {usage.format()}")

    # save for manual inspection
    out_dir = ROOT / "output" / "webs" / "reconstruction" / "functions" / f"0x{FUNC_ADDR}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "structured_new.c").write_text(structured, encoding="utf-8")
    (out_dir / "named_new.c").write_text(named, encoding="utf-8")
    if naming_map:
        (out_dir / "naming_map_new.txt").write_text(naming_map.strip() + "\n", encoding="utf-8")
    console.print(f"[bold]Output:[/bold] {out_dir} (structured_new.c, named_new.c, naming_map_new.txt)")

    naming_registry.close()
    struct_registry.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
