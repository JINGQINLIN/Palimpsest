"""Specialist tool for the Naming agent: batch placeholder resolution."""
from __future__ import annotations

import json
import re

from anthropic import beta_tool

from pipeline.agent.session import ReviewSession
from pipeline.agent.tools._shared import _replace_across_files


def build_naming_tools(session: ReviewSession) -> list:
    """Build naming-specific batch tools."""

    @beta_tool
    def batch_resolve_symbols(resolutions_json: str = "") -> str:
        """Resolve multiple FUN_/DAT_ placeholders in one call.

        Args:
            resolutions_json: JSON array of objects, each with:
                placeholder   — FUN_ or DAT_ name to replace
                canonical_name — new semantic name
                kind          — "function", "global_var", or "constant"
                confidence    — "high", "medium", or "low"
                evidence      — brief justification string

        Example::
            [{"placeholder": "FUN_00411a68", "canonical_name": "parse_http_request",
              "kind": "function", "confidence": "high", "evidence": "..."}]

        Returns:
            Summary of applied/skipped/conflict counts.
        """
        if not resolutions_json or not resolutions_json.strip():
            return "error: resolutions_json is required"

        try:
            resolutions = json.loads(resolutions_json)
        except json.JSONDecodeError as e:
            return f"error: invalid JSON — {e}"

        if not isinstance(resolutions, list):
            return "error: expected a JSON array"

        reg = session.registry
        if reg is None:
            return "error: naming registry not available (pre-scan phase?)"

        applied = 0
        skipped = 0
        conflicts = 0
        lines: list[str] = []

        for item in resolutions:
            if not isinstance(item, dict):
                continue
            placeholder = str(item.get("placeholder", "")).strip()
            canonical = str(item.get("canonical_name", "")).strip()
            kind = str(item.get("kind", "function")).strip()
            confidence = str(item.get("confidence", "medium")).strip()
            evidence = str(item.get("evidence", "")).strip()

            if not placeholder or not canonical:
                lines.append(f"  SKIP {placeholder!r}: missing placeholder or canonical_name")
                skipped += 1
                continue
            if not re.fullmatch(r"[A-Za-z_]\w*", canonical):
                lines.append(f"  SKIP {placeholder} -> {canonical}: invalid C identifier")
                skipped += 1
                continue
            if kind not in ("function", "global_var", "constant"):
                kind = "function"

            # Check registry for existing entry
            existing = reg.lookup(placeholder)
            if existing and existing.get("canonical_name") == canonical:
                lines.append(f"  SKIP {placeholder}: already {canonical}")
                skipped += 1
                continue
            if existing and existing.get("canonical_name") != canonical:
                lines.append(f"  CONFLICT {placeholder}: existing={existing['canonical_name']} vs incoming={canonical}")
                conflicts += 1
                continue

            # Write to registry
            result = reg.update(
                symbol=placeholder,
                canonical_name=canonical,
                kind=kind,
                confidence=confidence,
                evidence=evidence,
            )
            if result == "conflict":
                lines.append(f"  CONFLICT {placeholder} -> {canonical}: registry conflict")
                conflicts += 1
                continue

            # Replace across all source files
            pattern = re.compile(rf"\b{re.escape(placeholder)}\b")
            occurrences, files = _replace_across_files(session, pattern, canonical)
            session.record_change({
                "tool": "batch_resolve_symbols",
                "placeholder": placeholder,
                "canonical_name": canonical,
                "kind": kind,
                "occurrences": occurrences,
                "files": files,
            })
            lines.append(f"  OK {placeholder} -> {canonical}: {occurrences} hits in {files} files")
            applied += 1

        header = f"batch_resolve_symbols: {applied} applied, {skipped} skipped, {conflicts} conflicts"
        return header + "\n" + "\n".join(lines)

    return [batch_resolve_symbols]
