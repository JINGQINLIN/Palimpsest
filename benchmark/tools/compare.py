"""Compare two pipeline output packages on the same benchmark gold."""

from __future__ import annotations

import argparse
from pathlib import Path

from benchmark.lib.case import BenchmarkCase, load_json, write_json
from benchmark.lib.evaluate import evaluate_package


def _delta(new: float, old: float) -> str:
    diff = new - old
    sign = "+" if diff >= 0 else ""
    return f"{sign}{diff:.4f}"


def render_compare(case_id: str, stage: str, rows: list[dict]) -> str:
    if len(rows) != 2:
        raise ValueError("compare expects exactly two runs")

    new_row, old_row = rows[0], rows[1]
    ns = new_row["scores"]["summary"]
    os_ = old_row["scores"]["summary"]

    lines = [
        f"# Benchmark compare: {case_id}",
        "",
        f"- **New**: `{new_row['label']}`",
        f"  `{new_row['package_dir']}`",
        f"- **Old**: `{old_row['label']}`",
        f"  `{old_row['package_dir']}`",
        "",
        "## Recovery metrics (aligned pairs only)",
        "",
        "| Metric | New | Old | Δ (new-old) |",
        "|--------|-----|-----|-------------|",
        f"| Align coverage | {ns['align_coverage']['pairs']}/{ns['align_coverage']['pred_total']} "
        f"({ns['align_coverage']['rate']:.1%}) | "
        f"{os_['align_coverage']['pairs']}/{os_['align_coverage']['pred_total']} "
        f"({os_['align_coverage']['rate']:.1%}) | "
        f"{_delta(ns['align_coverage']['rate'], os_['align_coverage']['rate'])} |",
        f"| Param type acc | {ns['param_type_acc']:.4f} | {os_['param_type_acc']:.4f} | "
        f"{_delta(ns['param_type_acc'], os_['param_type_acc'])} |",
        f"| Func name token F1 | {ns['func_name_token_f1']:.4f} | {os_['func_name_token_f1']:.4f} | "
        f"{_delta(ns['func_name_token_f1'], os_['func_name_token_f1'])} |",
        f"| API multiset avg | {ns['api_multiset_avg']:.4f} | {os_['api_multiset_avg']:.4f} | "
        f"{_delta(ns['api_multiset_avg'], os_['api_multiset_avg'])} |",
        f"| API LCS avg | {ns['api_lcs_avg']:.4f} | {os_['api_lcs_avg']:.4f} | "
        f"{_delta(ns['api_lcs_avg'], os_['api_lcs_avg'])} |",
        f"| Libc multiset avg | {ns['libc_multiset_avg']:.4f} | {os_['libc_multiset_avg']:.4f} | "
        f"{_delta(ns['libc_multiset_avg'], os_['libc_multiset_avg'])} |",
        f"| Struct field recall | {ns['struct_field_recall']:.4f} | {os_['struct_field_recall']:.4f} | "
        f"{_delta(ns['struct_field_recall'], os_['struct_field_recall'])} |",
        f"| Placeholder-free rate | {ns['placeholder_rate']:.1%} | {os_['placeholder_rate']:.1%} | "
        f"{_delta(ns['placeholder_rate'], os_['placeholder_rate'])} |",
        "",
    ]

    nf, of = new_row.get("flows"), old_row.get("flows")
    lines.extend(["## Flow metrics (from reconstruction/flows.json)", ""])
    for label, metrics in (("New", nf), ("Old", of)):
        if metrics:
            lines.append(
                f"- {label}: sinks={metrics['sinks']} high={metrics['high']} "
                f"inferred={metrics['inferred']} root_only={metrics['root_only']} "
                f"clean_chains={metrics['clean_chains']} "
                f"placeholders_on_path_avg={metrics['placeholders_on_path_avg']:.2f}"
            )
        else:
            lines.append(f"- {label}: (no flows.json)")

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Gold is shared; only the pipeline output package differs.",
            "- Positive Δ means the new pipeline scored higher.",
            "- Flow metrics proxy sink-chain quality; not in gold yet.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="A/B compare two pipeline outputs")
    parser.add_argument("--case", default="r9000_udhcpd")
    parser.add_argument("--stage", default="post_agent")
    parser.add_argument("--new-package", type=Path, required=True)
    parser.add_argument("--old-package", type=Path, required=True)
    parser.add_argument("--new-label", default="new")
    parser.add_argument("--old-label", default="old")
    args = parser.parse_args()

    case = BenchmarkCase.load(args.case)
    gold_functions = load_json(case.gold_dir() / "functions.json").get("functions") or {}
    gold_structs = load_json(case.gold_dir() / "structs.json").get("structs") or {}

    rows = []
    for label, package in ((args.new_label, args.new_package), (args.old_label, args.old_package)):
        package_dir = package if package.is_dir() else case.resolve_package_dir(package)
        result = evaluate_package(
            case=case,
            package_dir=package_dir,
            gold_functions=gold_functions,
            gold_structs=gold_structs,
            stage=args.stage,
        )
        result["label"] = label
        rows.append(result)

        s = result["scores"]["summary"]
        print(f"\n[{label}] {package_dir}")
        print(f"  align        {s['align_coverage']['pairs']}/{s['align_coverage']['pred_total']} "
              f"({s['align_coverage']['rate']:.1%})")
        print(f"  param_type   {s['param_type_acc']:.4f}")
        print(f"  name_f1      {s['func_name_token_f1']:.4f}")
        print(f"  struct_recall {s['struct_field_recall']:.4f}")
        print(f"  placeholder  {s['placeholder_rate']:.1%}")
        if result["flows"]:
            f = result["flows"]
            print(f"  flows        sinks={f['sinks']} clean={f['clean_chains']}")

    out_dir = case.case_dir / "scores"
    write_json(out_dir / "compare.json", {"case_id": case.id, "stage": args.stage, "runs": rows})
    (out_dir / "compare.md").write_text(render_compare(case.id, args.stage, rows), encoding="utf-8")

    print(f"\nwritten       {out_dir / 'compare.json'}")
    print(f"report        {out_dir / 'compare.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
