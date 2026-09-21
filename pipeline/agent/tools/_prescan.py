"""Pre-Scan tools: catalog summary writer + rule-based residual-noise scan."""
from __future__ import annotations

import json
import re
from pathlib import Path

from anthropic import beta_tool

from pipeline.agent.session import ReviewSession

# Deterministic residual-noise patterns (post structure/naming).
_NOISE_PATTERNS: dict[str, re.Pattern[str]] = {
    "FUN_": re.compile(r"\bFUN_[0-9a-fA-F]+\b"),
    "iVar_uVar": re.compile(r"\b[iu]Var\d+\b"),
    "local_acStack": re.compile(r"\b(local_[0-9a-fA-F]+|a[cifu]Stack_[0-9a-fA-F]+)\b"),
    "LAB_": re.compile(r"\bLAB_[0-9a-fA-F_]+\b"),
    "goto": re.compile(r"\bgoto\b"),
    "undefined": re.compile(r"\bundefined\d*\b"),
    "hex_ge3": re.compile(r"\b0x[0-9a-fA-F]{3,}\b"),
}

# Weights for ranking hotspots (goto/LAB_/undefined hurt CodeQL + readability most).
_NOISE_WEIGHTS: dict[str, int] = {
    "FUN_": 5,
    "iVar_uVar": 4,
    "local_acStack": 4,
    "LAB_": 3,
    "goto": 3,
    "undefined": 2,
    "hex_ge3": 1,
}


def _resolve_src_dir(session: ReviewSession) -> Path | None:
    if not session.graph.nodes:
        return None
    return next(iter(session.graph.nodes.values())).path.parent


def scan_src_noise(src_dir: Path, *, top_n: int = 10) -> dict:
    """Rule-scan all ``*.c`` / ``*.cpp`` under ``src_dir`` for residual noise.

    Returns a dict suitable for ``noise_report.rule_scan`` / ``priority_files``.
    """
    files = sorted(list(src_dir.rglob("*.c")) + list(src_dir.rglob("*.cpp")))
    by_type_counts: dict[str, int] = {k: 0 for k in _NOISE_PATTERNS}
    by_type_files: dict[str, list[str]] = {k: [] for k in _NOISE_PATTERNS}
    per_file: list[dict] = []

    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        counts: dict[str, int] = {}
        score = 0
        for key, rx in _NOISE_PATTERNS.items():
            n = len(rx.findall(text))
            counts[key] = n
            by_type_counts[key] += n
            if n:
                by_type_files[key].append(f"{path.name} ({n})")
                score += n * _NOISE_WEIGHTS.get(key, 1)
        if score > 0:
            per_file.append(
                {
                    "file": path.name,
                    "address": path.name.split("_", 1)[0] if "_" in path.name else "",
                    "score": score,
                    "counts": counts,
                    "lines": text.count("\n") + 1,
                }
            )

    per_file.sort(key=lambda r: (-r["score"], -sum(r["counts"].values()), r["file"]))
    priority = per_file[:top_n]

    by_type = {}
    for key, total in by_type_counts.items():
        if total <= 0:
            continue
        by_type[key] = {
            "count": total,
            "files": by_type_files[key][:8],
        }

    return {
        "files_scanned": len(files),
        "files_with_noise": len(per_file),
        "total_score": sum(r["score"] for r in per_file),
        "by_type": by_type,
        "priority_files": [
            {
                "file": r["file"],
                "address": r["address"],
                "score": r["score"],
                "counts": {k: v for k, v in r["counts"].items() if v},
                "lines": r["lines"],
            }
            for r in priority
        ],
        "recommendation": (
            "Rule-scanned residual noise. Specialist agents SHOULD spend limited "
            "iterations on priority_files (top scores): Types-Agent owns "
            "undefined/hex/goto-LAB structured cleanup; Naming-Agent owns remaining "
            "FUN_/DAT_/placeholder labels. Do not attempt whole-program CFG rewrites."
        ),
    }


def format_noise_scan(report: dict) -> str:
    """Human-readable summary for the PreScan agent."""
    lines = [
        f"rule noise scan: {report['files_scanned']} files, "
        f"{report['files_with_noise']} with noise, total_score={report['total_score']}",
        "by_type:",
    ]
    for key, info in (report.get("by_type") or {}).items():
        lines.append(f"  {key}: {info['count']}")
    lines.append("priority_files (focus these):")
    for i, item in enumerate(report.get("priority_files") or [], 1):
        counts = ",".join(f"{k}={v}" for k, v in (item.get("counts") or {}).items())
        lines.append(
            f"  {i}. score={item['score']}  {item['file']}  ({counts})"
        )
    lines.append("JSON follows:")
    lines.append(json.dumps(report, ensure_ascii=False, indent=2))
    return "\n".join(lines)


def build_prescan_tools(session: ReviewSession, output_path: Path) -> list:
    """Build Pre-Scan tools: rule noise scan + catalog summary writer."""

    @beta_tool
    def scan_residual_noise(top_n: int = 10) -> str:
        """Deterministic regex scan of codeql/src for residual decompiler noise.

        Call this BEFORE writing noise_report. Counts FUN_/iVar/local_/LAB_/goto/
        undefined/hex>=3 per file and returns ranked priority_files.

        Args:
            top_n: how many hottest files to list (default 10).

        Returns:
            human summary + JSON report (also auto-merged into catalog_summary
            when you call generate_catalog_summary).
        """
        src_dir = _resolve_src_dir(session)
        if src_dir is None or not src_dir.is_dir():
            return "error: codeql/src directory not found"
        try:
            n = int(top_n) if top_n else 10
        except (TypeError, ValueError):
            n = 10
        n = max(1, min(n, 30))
        report = scan_src_noise(src_dir, top_n=n)
        # Cache on session for generate_catalog_summary merge
        session._noise_rule_scan = report  # type: ignore[attr-defined]
        return format_noise_scan(report)

    @beta_tool
    def generate_catalog_summary(sections_json: str = "") -> str:
        """Write / merge the catalog summary JSON for specialist agents.

        Call at the end of your scan (may call incrementally). Always refreshes
        ``noise_report.rule_scan`` and ``noise_report.priority_files`` from a
        deterministic rule scan so later agents get reliable hotspots.

        Args:
            sections_json: JSON object with one or more of:
                meta, entry_points, function_groups, placeholder_inventory,
                dispatch_graph, signature_audit, struct_registry_snapshot,
                noise_report, dependency_map.

        Returns:
            confirmation with path and section names.
        """
        if not sections_json or not sections_json.strip():
            return "error: sections_json is required"

        try:
            incoming = json.loads(sections_json)
        except json.JSONDecodeError as e:
            return f"error: invalid JSON — {e}"

        if not isinstance(incoming, dict):
            return "error: top-level must be a JSON object"

        existing: dict = {}
        if output_path.is_file():
            try:
                existing = json.loads(output_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

        existing.update(incoming)

        # Always attach deterministic noise hotspots.
        src_dir = _resolve_src_dir(session)
        rule_scan = getattr(session, "_noise_rule_scan", None)
        if src_dir is not None and src_dir.is_dir():
            rule_scan = scan_src_noise(src_dir, top_n=10)
            session._noise_rule_scan = rule_scan  # type: ignore[attr-defined]

        if isinstance(rule_scan, dict):
            noise = existing.get("noise_report")
            if not isinstance(noise, dict):
                noise = {}
            # Keep any LLM narrative fields; overwrite rule-derived keys.
            if rule_scan.get("by_type") and "by_type" not in noise:
                noise["by_type"] = rule_scan["by_type"]
            noise["rule_scan"] = rule_scan
            noise["priority_files"] = rule_scan.get("priority_files") or []
            if not noise.get("recommendation"):
                noise["recommendation"] = rule_scan.get("recommendation")
            existing["noise_report"] = noise

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(existing, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        section_names = list(incoming.keys())
        extra = ""
        if isinstance(rule_scan, dict):
            pf = rule_scan.get("priority_files") or []
            extra = f"\nrule_scan attached: {len(pf)} priority_files, score={rule_scan.get('total_score', 0)}"
        return (
            f"catalog_summary written to {output_path}\n"
            f"sections: {', '.join(section_names)} ({len(section_names)} total)"
            f"{extra}"
        )

    return [scan_residual_noise, generate_catalog_summary]
