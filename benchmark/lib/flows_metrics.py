"""Metrics derived from pipeline reconstruction/flows.json.

These proxy sink-chain quality for A/B comparisons. They are not part of gold
labels yet — alignment/score still use source fingerprints only.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_flow_metrics(package_dir: Path) -> dict | None:
    """Summarize flows.json if the package was built with sink-flow guidance."""
    path = package_dir / "reconstruction" / "flows.json"
    if not path.is_file():
        return None

    data = json.loads(path.read_text(encoding="utf-8"))
    summary = data.get("summary") or {}
    sinks = data.get("sinks") or []
    placeholders = [len(s.get("placeholders_on_path") or []) for s in sinks]
    traced_high = sum(
        1 for s in sinks if s.get("severity") == "high" and s.get("status") == "traced"
    )
    return {
        "sinks": summary.get("sinks", len(sinks)),
        "high": summary.get("high", 0),
        "low": summary.get("low", 0),
        "root_only": summary.get("root_only", 0),
        "inferred": summary.get("inferred", 0),
        "traced_high": traced_high,
        "placeholders_on_path_avg": (
            sum(placeholders) / len(placeholders) if placeholders else 0.0
        ),
        "clean_chains": sum(1 for n in placeholders if n == 0),
    }
