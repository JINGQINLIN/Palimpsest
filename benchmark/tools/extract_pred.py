"""Step 2 — extract pred fingerprints from a pipeline output package."""

from __future__ import annotations

import argparse
from pathlib import Path

from benchmark.lib.case import BenchmarkCase, load_json, write_json
from benchmark.lib.pred import STAGES, collect_pred_functions


def extract_stage(case: BenchmarkCase, package_dir: Path, stage: str) -> dict:
    functions, warnings = collect_pred_functions(package_dir, stage)
    pred_dir = case.pred_dir()
    out_path = pred_dir / f"{stage}.json"

    payload = {
        "case_id": case.id,
        "stage": stage,
        "package_dir": str(package_dir),
        "function_count": len(functions),
        "functions": functions,
    }
    write_json(out_path, payload)
    if warnings:
        warn_path = pred_dir / f"{stage}.warnings.txt"
        warn_path.write_text("\n".join(warnings) + "\n", encoding="utf-8")

    return {
        "stage": stage,
        "out_path": str(out_path),
        "function_count": len(functions),
        "warnings": len(warnings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark step 2: extract pred from pipeline output")
    parser.add_argument("--case", default="r9000_udhcpd")
    parser.add_argument("--package", type=Path, help="Pipeline output dir (default: output/<package_name>)")
    parser.add_argument("--stages", default="post_agent", help=f"Comma-separated: {', '.join(STAGES)}")
    args = parser.parse_args()

    case = BenchmarkCase.load(args.case)
    try:
        package_dir = case.resolve_package_dir(args.package)
    except FileNotFoundError as exc:
        print(f"error: {exc}")
        return 1

    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    unknown = [s for s in stages if s not in STAGES]
    if unknown:
        print(f"error: unknown stage(s): {', '.join(unknown)}")
        return 1

    print(f"case          {case.id}")
    print(f"package_dir   {package_dir}")

    summaries = []
    for stage in stages:
        try:
            summary = extract_stage(case, package_dir, stage)
        except FileNotFoundError as exc:
            print(f"error: {exc}")
            return 1
        summaries.append(summary)
        print(f"stage         {stage}")
        print(f"functions     {summary['function_count']}")
        print(f"warnings      {summary['warnings']}")
        print(f"written       {summary['out_path']}")
        print()

    if summaries:
        data = load_json(Path(summaries[-1]["out_path"]))
        sample = data["functions"].get("0x00009218")
        if sample:
            print("sample 0x00009218:")
            print(f"  func_name   {sample.get('func_name')}")
            print(f"  params      {sample.get('params')}")
            print(f"  api_calls   {(sample.get('api_calls') or [])[:10]} ...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
