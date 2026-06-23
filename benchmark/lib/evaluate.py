"""Evaluate one pipeline output package against benchmark gold."""

from __future__ import annotations

from pathlib import Path

from benchmark.lib.align import align_functions
from benchmark.lib.case import BenchmarkCase
from benchmark.lib.flows_metrics import load_flow_metrics
from benchmark.lib.pred import collect_pred_functions
from benchmark.lib.score import load_pred_structs, score_benchmark


def evaluate_package(
    *,
    case: BenchmarkCase,
    package_dir: Path,
    gold_functions: dict,
    gold_structs: dict,
    stage: str,
) -> dict:
    """Align pred fingerprints to gold and compute recovery + flow metrics."""
    pred_functions, pred_warnings = collect_pred_functions(package_dir, stage)
    alignment = align_functions(pred_functions, gold_functions)
    pred_structs = load_pred_structs(package_dir)
    scores = score_benchmark(
        alignment=alignment,
        pred_functions=pred_functions,
        gold_functions=gold_functions,
        gold_structs=gold_structs,
        pred_structs=pred_structs,
    )
    return {
        "package_dir": str(package_dir),
        "pred_warnings": pred_warnings,
        "pred_count": len(pred_functions),
        "alignment": alignment,
        "scores": scores,
        "flows": load_flow_metrics(package_dir),
    }
