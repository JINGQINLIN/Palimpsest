"""Specialist tool for the Dispatch agent: indirect edge tracing."""
from __future__ import annotations

import json
import re

from anthropic import beta_tool

from pipeline.agent.session import ReviewSession


def build_dispatch_tools(session: ReviewSession) -> list:
    """Build dispatch-specific tools."""

    @beta_tool
    def trace_indirect_edge(from_address: str = "", suspected_callee: str = "") -> str:
        """Confirm or deny a suspected indirect call edge.

        Reads the dispatcher function at from_address, searches for evidence
        that suspected_callee is reachable through a function pointer, dispatch
        table, or callback array.

        Args:
            from_address: address of the dispatcher function (e.g. "0x00410900").
            suspected_callee: name or address of the suspected callee.

        Returns:
            JSON with confirmed (bool), evidence (str), signature_compatible (bool),
            and suggested_edit (str or null).
        """
        if not from_address or not suspected_callee:
            return "error: both from_address and suspected_callee are required"

        graph = session.graph
        catalog = session.catalog

        node, err = session.node_or_error(from_address)
        if err:
            return f"error: {err}"

        # Resolve suspected callee to an address or name
        callee_addr = graph.addr_of(suspected_callee)
        callee_node = graph.resolve(suspected_callee) if callee_addr is None else graph.resolve(callee_addr)
        callee_name = suspected_callee
        callee_info = None
        if callee_node:
            callee_name = callee_node.name
            callee_info = catalog.get(callee_node.addr)

        # Read dispatcher body
        text = node.path.read_text(encoding="utf-8", errors="ignore")
        evidence_parts: list[str] = []
        confirmed = False
        signature_compatible = False
        suggested_edit = None

        # Pattern 1: Direct function pointer usage
        if callee_name in text or suspected_callee in text:
            evidence_parts.append(f"callee name found in dispatcher body")
            # Check if it appears in a function-pointer context
            for lineno, line in enumerate(text.splitlines(), 1):
                if callee_name in line or suspected_callee in line:
                    if "(" in line and ("=" in line or "," in line or "{" in line or "[" in line):
                        evidence_parts.append(f"L{lineno}: potential dispatch reference")
                        confirmed = True
                        break

        # Pattern 2: Switch-based dispatch
        if not confirmed:
            switch_count = sum(1 for l in text.splitlines() if "case " in l or "switch " in l)
            if switch_count >= 2:
                evidence_parts.append(f"switch/case structure ({switch_count} cases)")

        # Pattern 3: Array index call
        if not confirmed:
            for lineno, line in enumerate(text.splitlines(), 1):
                if "[" in line and "]" in line and "(" in line:
                    if re.search(r"\[\s*\w+\s*\]\s*\(", line):
                        evidence_parts.append(f"L{lineno}: table[index](args) pattern")
                        confirmed = True
                        break

        # Check signature compatibility if callee info is available
        if callee_info and node:
            caller_info = catalog.get(node.addr)
            if caller_info:
                c_params = caller_info.params
                t_params = callee_info.params
                if len(c_params) == len(t_params) or len(c_params) <= 1:
                    signature_compatible = True

        if callee_node:
            suggested_edit = (
                f"At dispatch site, ensure the function pointer cast matches "
                f"the callee signature: {callee_info.signature if callee_info else callee_name}"
            )

        result = {
            "confirmed": confirmed,
            "evidence": "; ".join(evidence_parts) if evidence_parts else "no direct evidence found",
            "signature_compatible": signature_compatible,
            "suggested_edit": suggested_edit,
        }
        return json.dumps(result, ensure_ascii=False, indent=2)

    return [trace_indirect_edge]
