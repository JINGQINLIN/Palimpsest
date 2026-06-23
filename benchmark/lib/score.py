"""Scoring metrics for aligned pred/gold function pairs."""

from __future__ import annotations

import re
from pathlib import Path

from pipeline.paths import REGISTRY_SUBDIR
from pipeline.registry import StructRegistry

from benchmark.lib.similarity import combined_similarity
from benchmark.lib.type_equiv import types_equivalent
_TOKEN_RE = re.compile(r"[A-Za-z]+|\d+")


def token_f1(pred_name: str, gold_name: str) -> float:
    pred_tokens = [t.lower() for t in _TOKEN_RE.findall(pred_name or "")]
    gold_tokens = [t.lower() for t in _TOKEN_RE.findall(gold_name or "")]
    if not pred_tokens and not gold_tokens:
        return 1.0
    if not pred_tokens or not gold_tokens:
        return 0.0
    pred_set = set(pred_tokens)
    gold_set = set(gold_tokens)
    common = pred_set & gold_set
    if not common:
        return 0.0
    precision = len(common) / len(pred_set)
    recall = len(common) / len(gold_set)
    return 2 * precision * recall / (precision + recall)


def score_param_types(pred_params: list[str], gold_params: list[str]) -> dict:
    total = min(len(pred_params), len(gold_params))
    if total == 0:
        return {"acc": 1.0 if pred_params == gold_params else 0.0, "correct": 0, "total": 0}
    correct = sum(
        1 for i in range(total) if types_equivalent(pred_params[i], gold_params[i])
    )
    return {"acc": correct / total, "correct": correct, "total": total}


def score_pair(pred: dict, gold: dict) -> dict:
    params = score_param_types(pred.get("params") or [], gold.get("params") or [])
    behavior = combined_similarity(pred, gold)
    return {
        "func_name_token_f1": round(token_f1(pred.get("func_name") or "", gold.get("func_name") or ""), 4),
        "param_type_acc": round(params["acc"], 4),
        "param_type_correct": params["correct"],
        "param_type_total": params["total"],
        "api_multiset": behavior["api_multiset"],
        "api_lcs": behavior["api_lcs"],
        "libc_multiset": behavior["libc_multiset"],
        "strings_jaccard": behavior["strings"],
    }


def load_pred_structs(package_dir: Path) -> dict:
    db_path = package_dir / REGISTRY_SUBDIR / "struct_registry.sqlite3"
    if not db_path.is_file():
        return {}
    registry = StructRegistry(db_path)
    try:
        return registry.get_all()
    finally:
        registry.close()


def struct_field_recall(gold_structs: dict, pred_structs: dict) -> dict:
    per_struct: dict = {}
    total_gold = 0
    total_matched = 0

    for name, gold in gold_structs.items():
        pred = pred_structs.get(name)
        gold_fields = gold.get("fields") or []
        pred_by_offset = {
            int(f["offset"]): f for f in (pred or {}).get("fields") or [] if "offset" in f
        }
        matched = 0
        details = []
        for field in gold_fields:
            offset = int(field["offset"])
            total_gold += 1
            pred_field = pred_by_offset.get(offset)
            ok = bool(
                pred_field
                and types_equivalent(str(pred_field.get("type") or ""), str(field.get("type") or ""))
            )
            if ok:
                matched += 1
                total_matched += 1
            details.append(
                {
                    "offset": offset,
                    "name": field.get("name"),
                    "gold_type": field.get("type"),
                    "pred_type": (pred_field or {}).get("type"),
                    "ok": ok,
                }
            )
        per_struct[name] = {
            "recall": matched / len(gold_fields) if gold_fields else 1.0,
            "matched": matched,
            "total": len(gold_fields),
            "fields": details,
        }

    return {
        "recall": total_matched / total_gold if total_gold else 1.0,
        "matched": total_matched,
        "total": total_gold,
        "per_struct": per_struct,
    }


def placeholder_rate(pred_functions: dict) -> dict:
    total = len(pred_functions)
    if total == 0:
        return {"rate": 1.0, "with_placeholders": 0, "total": 0, "placeholder_count": 0}
    with_ph = sum(1 for entry in pred_functions.values() if entry.get("placeholders"))
    placeholder_count = sum(len(entry.get("placeholders") or []) for entry in pred_functions.values())
    return {
        "rate": 1.0 - (with_ph / total),
        "with_placeholders": with_ph,
        "total": total,
        "placeholder_count": placeholder_count,
    }


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def score_benchmark(
    *,
    alignment: dict,
    pred_functions: dict,
    gold_functions: dict,
    gold_structs: dict,
    pred_structs: dict,
) -> dict:
    pairs_out: list[dict] = []
    param_correct = 0
    param_total = 0

    for pair in alignment.get("pairs") or []:
        addr = pair["addr"]
        gold_key = pair["gold_key"]
        pred = pred_functions.get(addr)
        gold = gold_functions.get(gold_key)
        if not pred or not gold:
            continue
        metrics = score_pair(pred, gold)
        param_correct += metrics["param_type_correct"]
        param_total += metrics["param_type_total"]
        pairs_out.append(
            {
                "addr": addr,
                "pred_func_name": pred.get("func_name") or pair.get("pred_func_name"),
                "src_func": gold.get("func_name") or pair.get("src_func"),
                "align_confidence": pair.get("confidence"),
                **metrics,
            }
        )

    structs = struct_field_recall(gold_structs, pred_structs)
    placeholders = placeholder_rate(pred_functions)

    summary = {
        "align_coverage": {
            "pairs": alignment.get("pair_count", 0),
            "pred_total": alignment.get("pred_count", 0),
            "rate": (
                alignment.get("pair_count", 0) / alignment.get("pred_count", 1)
                if alignment.get("pred_count")
                else 0.0
            ),
        },
        "param_type_acc": round(param_correct / param_total, 4) if param_total else 0.0,
        "param_type_correct": param_correct,
        "param_type_total": param_total,
        "func_name_token_f1": round(_mean([p["func_name_token_f1"] for p in pairs_out]), 4),
        "api_multiset_avg": round(_mean([p["api_multiset"] for p in pairs_out]), 4),
        "api_lcs_avg": round(_mean([p["api_lcs"] for p in pairs_out]), 4),
        "libc_multiset_avg": round(_mean([p["libc_multiset"] for p in pairs_out]), 4),
        "strings_jaccard_avg": round(_mean([p["strings_jaccard"] for p in pairs_out]), 4),
        "struct_field_recall": round(structs["recall"], 4),
        "placeholder_rate": round(placeholders["rate"], 4),
    }

    mismatches = sorted(
        [p for p in pairs_out if p["param_type_acc"] < 1.0],
        key=lambda item: item["param_type_acc"],
    )[:10]

    return {
        "summary": summary,
        "structs": structs,
        "placeholders": placeholders,
        "pairs": pairs_out,
        "param_type_mismatches": mismatches,
    }


def render_report(case_id: str, stage: str, result: dict) -> str:
    s = result["summary"]
    lines = [
        f"# Benchmark: {case_id} ({stage})",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Align coverage | {s['align_coverage']['pairs']}/{s['align_coverage']['pred_total']} "
        f"({s['align_coverage']['rate']:.1%}) |",
        f"| Param type accuracy | {s['param_type_acc']:.4f} ({s['param_type_correct']}/{s['param_type_total']}) |",
        f"| Func name token F1 (avg) | {s['func_name_token_f1']:.4f} |",
        f"| API multiset jaccard (avg) | {s['api_multiset_avg']:.4f} |",
        f"| API LCS (avg) | {s['api_lcs_avg']:.4f} |",
        f"| Libc multiset jaccard (avg) | {s['libc_multiset_avg']:.4f} |",
        f"| Struct field recall | {s['struct_field_recall']:.4f} |",
        f"| Placeholder-free rate | {s['placeholder_rate']:.1%} |",
        "",
    ]
    if result["param_type_mismatches"]:
        lines.extend(["## Param type mismatches (top 10)", ""])
        for item in result["param_type_mismatches"]:
            lines.append(
                f"- `{item['addr']}` {item['pred_func_name']} vs {item['src_func']}: "
                f"acc={item['param_type_acc']}"
            )
        lines.append("")
    return "\n".join(lines)
