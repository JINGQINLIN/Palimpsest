"""Probe — string-anchoring feasibility (experimental alignment input).

    python -m benchmark.tools.anchor --case r9000_udhcpd
"""

from __future__ import annotations

import argparse
from pathlib import Path

from benchmark.lib.anchor import anchor, raw_strings, src_strings
from benchmark.lib.case import BenchmarkCase, write_json
from pipeline.paths import RAW_PACKAGE_SUBDIR


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe: string-anchoring pin rate")
    parser.add_argument("--case", default="r9000_udhcpd")
    parser.add_argument("--package", type=Path, help="Pipeline output dir (default: output/<package>)")
    args = parser.parse_args()

    case = BenchmarkCase.load(args.case)
    package_dir = case.resolve_package_dir(args.package)
    gold_path = case.gold_dir() / "functions.json"

    raw = raw_strings(package_dir)
    src = src_strings(gold_path)
    result = anchor(raw, src)

    raw_total = len(list((package_dir / RAW_PACKAGE_SUBDIR).glob("*.json")))
    pinned = result["pinned"]
    pin_rate = len(pinned) / len(raw) if raw else 0.0

    print(f"case              {case.id}")
    print(f"raw functions     {raw_total} ({len(raw)} carry usable strings)")
    print(f"src functions     {len(src)} carry usable strings")
    print(f"pinned            {len(pinned)} / {len(raw)} string-bearing ({pin_rate:.1%})")
    print(f"conflicts         {len(result['conflicts'])} addr -> >1 func")
    print(f"reverse conflicts {len(result['reverse_conflicts'])} func -> >1 addr")

    print("\nsample pins:")
    for addr in sorted(pinned)[:12]:
        info = pinned[addr]
        print(f"  0x{addr}  ->  {info['func']:<28}  via \"{info['evidence'][0]}\"")

    out_path = case.case_dir / "anchors.json"
    write_json(
        out_path,
        {
            "case_id": case.id,
            "pin_rate": round(pin_rate, 4),
            "raw_total": raw_total,
            "raw_with_strings": len(raw),
            "src_with_strings": len(src),
            **result,
        },
    )
    print(f"\nwritten           {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
