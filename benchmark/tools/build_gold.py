"""Step 1 — build gold labels from open-source C."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmark.lib.case import BenchmarkCase, load_context_structs, write_json
from benchmark.lib.c_parse import extract_all_functions


def collect_source_functions(source_root: Path) -> tuple[dict, list[str]]:
    functions: dict = {}
    warnings: list[str] = []

    for path in sorted(source_root.rglob("*.c")):
        rel = str(path.relative_to(source_root)).replace("\\", "/")
        try:
            code = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            warnings.append(f"skip unreadable {rel}: {exc}")
            continue

        for name, features in extract_all_functions(code).items():
            entry = {
                "func_name": name,
                "file": rel,
                **features,
            }
            if name in functions:
                prev = functions[name]["file"]
                warnings.append(f"duplicate function name {name}: {prev} vs {rel}")
                name = f"{name}@{rel}"
            functions[name] = entry

    return functions, warnings


def build_gold(case: BenchmarkCase) -> dict:
    if not case.source_root.is_dir():
        raise FileNotFoundError(
            f"source_root not found: {case.source_root}\n"
            f"Edit {case.case_dir / 'case.yaml'} and set source_root to your udhcpd sources."
        )

    functions, warnings = collect_source_functions(case.source_root)
    structs = load_context_structs(case.context)

    gold_dir = case.gold_dir()
    write_json(gold_dir / "case.json", case.to_json())
    write_json(
        gold_dir / "functions.json",
        {
            "case_id": case.id,
            "source_root": str(case.source_root),
            "function_count": len(functions),
            "functions": functions,
        },
    )
    write_json(
        gold_dir / "structs.json",
        {
            "case_id": case.id,
            "context": case.context,
            "struct_count": len(structs),
            "structs": structs,
        },
    )
    if warnings:
        (gold_dir / "warnings.txt").write_text("\n".join(warnings) + "\n", encoding="utf-8")

    return {
        "gold_dir": str(gold_dir),
        "function_count": len(functions),
        "struct_count": len(structs),
        "warnings": len(warnings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark step 1: build gold from source")
    parser.add_argument("--case", default="r9000_udhcpd", help="Case id under benchmark/cases/")
    parser.add_argument("--source-root", type=Path, help="Override source_root from case.yaml")
    args = parser.parse_args()

    case = BenchmarkCase.load(args.case)
    if args.source_root:
        case = BenchmarkCase(
            id=case.id,
            case_dir=case.case_dir,
            binary=case.binary,
            source_root=args.source_root,
            source_headers=args.source_root,
            context=case.context,
            package_name=case.package_name,
        )

    try:
        summary = build_gold(case)
    except FileNotFoundError as exc:
        print(f"error: {exc}")
        return 1

    print(f"case          {case.id}")
    print(f"source_root   {case.source_root}")
    print(f"functions     {summary['function_count']}")
    print(f"structs       {summary['struct_count']}")
    print(f"warnings      {summary['warnings']}")
    print(f"gold_dir      {summary['gold_dir']}")

    functions_path = Path(summary["gold_dir"]) / "functions.json"
    data = json.loads(functions_path.read_text(encoding="utf-8"))
    sample = data["functions"].get("udhcpd_main_loop") or data["functions"].get("udhcpd_main")
    if sample:
        print(f"\nfound {sample.get('func_name')} in gold:")
        print(f"  file       {sample.get('file')}")
        print(f"  params     {sample.get('params')}")
        print(f"  strings    {sample.get('strings', [])[:5]}")
        print(f"  api_calls  {(sample.get('api_calls') or [])[:12]} ...")
    else:
        print("\nnote: no udhcpd_main / udhcpd_main_loop in gold; check warnings.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
