"""Specialist tool for the Syntax agent: batch syntax checking."""
from __future__ import annotations

import json
from pathlib import Path

from anthropic import beta_tool

from pipeline.agent.session import ReviewSession
from pipeline.agent.syntax_utils import check_file


def build_syntax_tools(session: ReviewSession, codeql_dir: Path) -> list:
    """Build syntax-specific tools."""

    @beta_tool
    def batch_check_syntax(addresses_json: str = "") -> str:
        """Check syntax for multiple files in one call.

        Args:
            addresses_json: JSON array of function addresses to check,
                e.g. ["0x00410880", "0x00410d44"].
                Pass "all" to check every file touched by other agents.

        Returns:
            JSON with passed count, failed count, and per-file error details.
        """
        if not addresses_json or not addresses_json.strip():
            return "error: addresses_json is required (or use 'all')"

        graph = session.graph

        if addresses_json.strip().lower() == "all":
            # Check files referenced in session's edit lock
            targets = list(session._edit_lock) if session._edit_lock else []
            if not targets:
                return "no files have been edited by other agents"
        else:
            try:
                targets = json.loads(addresses_json)
            except json.JSONDecodeError as e:
                return f"error: invalid JSON — {e}"
            if not isinstance(targets, list):
                return "error: expected a JSON array of addresses"

        passed = 0
        failed = 0
        errors_list: list[dict] = []

        for addr in targets:
            if not isinstance(addr, str):
                continue
            node, err = session.node_or_error(addr)
            if err:
                errors_list.append({"address": addr, "error": err})
                failed += 1
                continue

            file_errors = check_file(codeql_dir, node.path.name)
            if not file_errors:
                passed += 1
            else:
                failed += 1
                errors_list.append({
                    "address": f"0x{node.addr}",
                    "name": node.name,
                    "file": node.path.name,
                    "error_count": len(file_errors),
                    "errors": file_errors[:5],
                })
            session.record_change({"tool": "batch_check_syntax", "address": f"0x{node.addr}"})

        result = {"passed": passed, "failed": failed, "details": errors_list}
        return json.dumps(result, ensure_ascii=False, indent=2)

    return [batch_check_syntax]
