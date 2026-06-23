"""Step 4 — score aligned pred vs gold."""

from __future__ import annotations

import argparse
from pathlib import Path

from benchmark.lib.case import BenchmarkCase, load_json, write_json
from benchmark.lib.score import load_pred_structs, render_report, score_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark step 4: score benchmark results")
    parser.add_argument("--case", default="r9000_udhcpd")
    parser.add_argument("--stage", default="post_agent")
    parser.add_argument("--package", type=Path, help="Pipeline output dir (for struct registry)")
    args = parser.parse_args()

    case = BenchmarkCase.load(args.case)
    try:
        package_dir = case.resolve_package_dir(args.package)
    except FileNotFoundError as exc:
        print(f"error: {exc}")
        return 1

    alignment_path = case.case_dir / "alignment.json"
    gold_fn_path = case.gold_dir() / "functions.json"
    gold_st_path = case.gold_dir() / "structs.json"
    pred_path = case.pred_dir() / f"{args.stage}.json"

    for path in (alignment_path, gold_fn_path, gold_st_path, pred_path):
        if not path.is_file():
            print(f"error: missing {path}")
            return 1

    alignment = load_json(alignment_path)
    gold_functions = load_json(gold_fn_path).get("functions") or {}
    gold_structs = load_json(gold_st_path).get("structs") or {}
    pred_functions = load_json(pred_path).get("functions") or {}
    pred_structs = load_pred_structs(package_dir)

    result = score_benchmark(
        alignment=alignment,
        pred_functions=pred_functions,
        gold_functions=gold_functions,
        gold_structs=gold_structs,
        pred_structs=pred_structs,
    )
    result["case_id"] = case.id
    result["stage"] = args.stage
    result["package_dir"] = str(package_dir)

    scores_dir = case.case_dir / "scores"
    json_path = scores_dir / f"{args.stage}.json"
    md_path = scores_dir / f"{args.stage}.md"
    write_json(json_path, result)
    md_path.write_text(render_report(case.id, args.stage, result), encoding="utf-8")

    s = result["summary"]
    print(f"case                 {case.id}")
    print(f"stage                {args.stage}")
    print(f"align_coverage       {s['align_coverage']['pairs']}/{s['align_coverage']['pred_total']} "
          f"({s['align_coverage']['rate']:.1%})")
    print(f"param_type_acc       {s['param_type_acc']:.4f}")
    print(f"func_name_token_f1   {s['func_name_token_f1']:.4f}")
    print(f"libc_multiset_avg    {s['libc_multiset_avg']:.4f}")
    print(f"struct_field_recall  {s['struct_field_recall']:.4f}")
    print(f"placeholder_rate     {s['placeholder_rate']:.1%}")
    print(f"written              {json_path}")
    print(f"report               {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
