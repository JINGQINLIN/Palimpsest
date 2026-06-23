"""Greedy pred→gold function alignment via behavioral fingerprints."""

from __future__ import annotations

from benchmark.lib.similarity import combined_similarity
DEFAULT_THRESHOLD = 0.35
DEFAULT_MARGIN = 0.05
DEFAULT_MIN_RELATIVE = 0.06


def _rank_candidates(pred: dict, gold_functions: dict) -> list[dict]:
    ranked: list[dict] = []
    for gold_key, gold in gold_functions.items():
        scores = combined_similarity(pred, gold)
        ranked.append(
            {
                "gold_key": gold_key,
                "src_func": gold.get("func_name") or gold_key,
                "src_file": gold.get("file") or "",
                **scores,
            }
        )
    ranked.sort(key=lambda item: item["combined"], reverse=True)
    return ranked


def align_functions(
    pred_functions: dict,
    gold_functions: dict,
    *,
    threshold: float = DEFAULT_THRESHOLD,
    margin: float = DEFAULT_MARGIN,
    min_relative: float = DEFAULT_MIN_RELATIVE,
) -> dict:
    # Score every pred x gold edge, then greedily assign high-confidence unique pairs.
    edges: list[tuple[float, str, str, dict]] = []
    diagnostics: dict[str, dict] = {}

    for addr, pred in pred_functions.items():
        ranked = _rank_candidates(pred, gold_functions)
        diagnostics[addr] = {
            "pred_func_name": pred.get("func_name") or "",
            "pred_file": pred.get("file") or "",
            "top": ranked[:3],
        }
        if not ranked:
            continue
        best = ranked[0]
        second = ranked[1]["combined"] if len(ranked) > 1 else 0.0
        lead = best["combined"] - second
        strong = best["combined"] >= threshold
        relative = best["combined"] >= min_relative and lead >= margin
        if not (strong or relative):
            continue
        edges.append((best["combined"], lead, addr, best["gold_key"], best))

    edges.sort(key=lambda item: (item[0], item[1]), reverse=True)

    used_pred: set[str] = set()
    used_gold: set[str] = set()
    pairs: list[dict] = []

    for combined, lead, addr, gold_key, best in edges:
        if addr in used_pred or gold_key in used_gold:
            continue
        pred = pred_functions[addr]
        pairs.append(
            {
                "addr": addr,
                "pred_func_name": pred.get("func_name") or "",
                "pred_file": pred.get("file") or "",
                "gold_key": gold_key,
                "src_func": best["src_func"],
                "src_file": best["src_file"],
                "confidence": best["combined"],
                "scores": {
                    "strings": best["strings"],
                    "api_multiset": best["api_multiset"],
                    "api_lcs": best["api_lcs"],
                    "libc_multiset": best["libc_multiset"],
                    "combined": best["combined"],
                },
                "margin": round(lead, 4),
            }
        )
        used_pred.add(addr)
        used_gold.add(gold_key)

    pairs.sort(key=lambda item: item["addr"])

    unmatched_pred = sorted(set(pred_functions) - used_pred)
    unmatched_gold = sorted(
        key for key in gold_functions if key not in used_gold
    )

    return {
        "method": "hybrid_jaccard_lcs_v1",
        "weights": {
            "strings": 0.30,
            "api_multiset": 0.25,
            "api_lcs": 0.20,
            "libc_multiset": 0.25,
        },
        "threshold": threshold,
        "margin": margin,
        "min_relative": min_relative,
        "pair_count": len(pairs),
        "pred_count": len(pred_functions),
        "gold_count": len(gold_functions),
        "pairs": pairs,
        "unmatched_pred": unmatched_pred,
        "unmatched_gold": unmatched_gold,
        "diagnostics": diagnostics,
    }
