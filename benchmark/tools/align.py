"""Step 3 — align pred function addresses to gold source functions."""

from __future__ import annotations

import argparse

from benchmark.lib.align import DEFAULT_MARGIN, DEFAULT_THRESHOLD, align_functions
from benchmark.lib.case import BenchmarkCase, load_json, write_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark step 3: align pred to gold")
    parser.add_argument("--case", default="r9000_udhcpd")
    parser.add_argument("--stage", default="post_agent")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--margin", type=float, default=DEFAULT_MARGIN)
    parser.add_argument("--keep-diagnostics", action="store_true")
    args = parser.parse_args()

    case = BenchmarkCase.load(args.case)
    gold_path = case.gold_dir() / "functions.json"
    pred_path = case.pred_dir() / f"{args.stage}.json"
    for path, label in ((gold_path, "gold"), (pred_path, "pred")):
        if not path.is_file():
            print(f"error: missing {label}: {path}")
            return 1

    gold_functions = load_json(gold_path).get("functions") or {}
    pred_functions = load_json(pred_path).get("functions") or {}
    result = align_functions(
        pred_functions,
        gold_functions,
        threshold=args.threshold,
        margin=args.margin,
    )
    result["case_id"] = case.id
    result["stage"] = args.stage

    if not args.keep_diagnostics:
        result.pop("diagnostics", None)

    out_path = case.case_dir / "alignment.json"
    write_json(out_path, result)

    coverage = result["pair_count"] / result["pred_count"] if result["pred_count"] else 0.0
    print(f"case          {case.id}")
    print(f"stage         {args.stage}")
    print(f"method        {result['method']}")
    print(f"pairs         {result['pair_count']} / {result['pred_count']} pred ({coverage:.1%})")
    print(f"unmatched     pred {len(result['unmatched_pred'])}, gold {len(result['unmatched_gold'])}")
    print(f"written       {out_path}")

    sample = next((p for p in result["pairs"] if p["addr"] == "0x00009218"), None)
    if sample:
        print("\nsample 0x00009218:")
        print(f"  pred          {sample['pred_func_name']}")
        print(f"  src           {sample['src_func']} ({sample['src_file']})")
        print(f"  confidence    {sample['confidence']}")
        print(f"  scores        {sample['scores']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
