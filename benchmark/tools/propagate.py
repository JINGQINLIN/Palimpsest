"""Probe — extend string-anchor seeds along the call graph (experimental).

    python -m benchmark.tools.propagate --case r9000_udhcpd
"""

from __future__ import annotations

import argparse
from pathlib import Path

from benchmark.lib.anchor import anchor, raw_strings, src_strings
from benchmark.lib.callgraph import build_bin_callgraph, build_src_callgraph, propagate
from benchmark.lib.case import BenchmarkCase, write_json
from benchmark.lib.score import token_f1
from pipeline.paths import CODEQL_SUBDIR


def llm_names(package_dir: Path) -> dict[str, str]:
    """addr -> name from codeql/src/0xADDR_name.c filenames."""
    out: dict[str, str] = {}
    for path in (package_dir / CODEQL_SUBDIR).glob("0x*.c"):
        head = path.stem[2:] if path.stem.startswith("0x") else path.stem
        addr, _, name = head.partition("_")
        out[addr] = name
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe: call-graph seed propagation")
    parser.add_argument("--case", default="r9000_udhcpd")
    parser.add_argument("--package", type=Path, help="Pipeline output dir (default: output/<package>)")
    args = parser.parse_args()

    case = BenchmarkCase.load(args.case)
    package_dir = case.resolve_package_dir(args.package)
    gold_path = case.gold_dir() / "functions.json"

    pins = anchor(raw_strings(package_dir), src_strings(gold_path))["pinned"]
    seeds = {addr: info["func"] for addr, info in pins.items()}

    bin_cg = build_bin_callgraph(package_dir)
    src_cg = build_src_callgraph(gold_path)
    grown = propagate(seeds, bin_cg, src_cg)

    names = llm_names(package_dir)
    eligible = set(names)
    covered = (set(seeds) | set(grown)) & eligible
    coverage = len(covered) / len(eligible) if eligible else 0.0

    print(f"case            {case.id}")
    print(f"raw funcs       {len(bin_cg)}")
    print(f"scorable funcs  {len(eligible)} (rebuilt in codeql/src)")
    print(f"string seeds    {len(seeds)}  (scorable: {len(set(seeds) & eligible)})")
    print(f"propagated      {len(grown)}  (scorable: {len(set(grown) & eligible)})")
    print(f"covered         {len(covered)} / {len(eligible)} ({coverage:.1%})")

    print("\npropagated pairs (gold name vs LLM filename):")
    for addr in sorted(grown):
        src = grown[addr]["func"]
        llm = names.get(addr, "?")
        flag = "" if token_f1(src, llm) > 0.0 else "   <-- check"
        print(f"  0x{addr}  {src:<26} vs {llm:<26} {grown[addr]['via']}{flag}")

    out_path = case.case_dir / "propagation.json"
    write_json(
        out_path,
        {
            "case_id": case.id,
            "raw_funcs": len(bin_cg),
            "scorable_funcs": len(eligible),
            "covered": len(covered),
            "coverage": round(coverage, 4),
            "seeds": seeds,
            "propagated": grown,
        },
    )
    print(f"\nwritten         {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
