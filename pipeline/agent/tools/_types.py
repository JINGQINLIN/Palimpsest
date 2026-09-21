"""Specialist tool for the Types agent: batch signature checking."""
from __future__ import annotations

import json

from anthropic import beta_tool

from pipeline.agent.session import ReviewSession
from pipeline.registry.coherence import (
    check_field_coherence as run_field_coherence,
    format_coherence_violations,
)


def build_types_tools(session: ReviewSession) -> list:
    """Build types-specific tools."""

    @beta_tool
    def batch_check_signatures(function_names_json: str = "") -> str:
        """Check call-site argument types against callee parameter types.

        Scans all callers of each function and reports where the argument type
        at the call site does not match the callee's declared parameter type.

        Args:
            function_names_json: JSON array of function names to check,
                e.g. ["handle_http_request", "process_cgi"].

        Returns:
            JSON array of mismatches, each with caller, callee, site_line,
            expected_type, actual_type, and severity.
        """
        if not function_names_json or not function_names_json.strip():
            return "error: function_names_json is required"

        try:
            names = json.loads(function_names_json)
        except json.JSONDecodeError as e:
            return f"error: invalid JSON — {e}"
        if not isinstance(names, list):
            return "error: expected a JSON array of function names"

        catalog = session.catalog
        graph = session.graph
        mismatches: list[dict] = []

        for name in names:
            if not isinstance(name, str) or not name.strip():
                continue
            addr = graph.addr_of(name.strip())
            if not addr:
                mismatches.append({"callee": name, "error": "function not found in graph"})
                continue

            info = catalog.get(addr)
            if info is None:
                continue

            callee_params = info.params
            if not callee_params:
                continue  # no params to check

            callers = graph.callers(addr)
            for caller in callers:
                caller_info = catalog.get(caller.addr)
                if caller_info is None:
                    continue
                # Read the caller source to find call sites for this callee
                text = caller.path.read_text(encoding="utf-8", errors="ignore")
                for lineno, line in enumerate(text.splitlines(), 1):
                    if info.name not in line or "(" not in line:
                        continue
                    # Crude extraction: find argument expressions between parens
                    start = line.find("(")
                    end = line.rfind(")")
                    if start == -1 or end == -1 or start >= end:
                        continue
                    args_str = line[start + 1:end]
                    # Match this specific call by checking for the function name
                    before_paren = line[:start]
                    if info.name not in before_paren.split()[-1] if before_paren.split() else True:
                        continue

                    args = [a.strip() for a in args_str.split(",") if a.strip()]
                    for i, arg in enumerate(args):
                        if i >= len(callee_params):
                            break
                        expected = callee_params[i].strip()
                        # Heuristic type inference for call-site arguments.
                        has_field_access = "->" in arg
                        is_pointer_var = "*" in arg and "(" not in arg
                        is_string_literal = arg.startswith('"')
                        arg_stripped = arg.replace(" ", "").replace("0x", "")
                        is_numeric_or_call = (
                            arg_stripped.isdigit()
                            or "FUN_" in arg
                            or "DAT_" in arg
                            or "(" in arg
                        )

                        if has_field_access or is_pointer_var:
                            actual = "struct*"
                        elif is_string_literal or "char" in expected:
                            actual = "char*"
                        elif is_numeric_or_call:
                            actual = "int"
                        else:
                            actual = "unknown"

                        if actual in ("struct*", "char*") and "int" in expected and "*" not in expected:
                            mismatches.append({
                                "caller": caller.name,
                                "callee": info.name,
                                "site_line": lineno,
                                "param_index": i,
                                "expected_type": expected,
                                "actual_type": actual,
                                "severity": "high",
                                "snippet": line.strip()[:120],
                            })

        if not mismatches:
            return "No signature mismatches found."
        return json.dumps(mismatches, ensure_ascii=False, indent=2)

    @beta_tool
    def check_field_coherence(address: str = "") -> str:
        """Check that typed `base->field` / `base.field` exist on the declared struct.

        Use after struct edits or when a function mixes several struct types.
        Unbound bases (no declared struct type) are allowed; clear mismatches
        fail. Prefer bare offsets over inventing a field that is not in
        `get_structs` / `recopilot_types.h`.

        Args:
            address: function address to check.

        Returns:
            Pass/fail summary with violating accesses.
        """
        if not address or not address.strip():
            return "error: address is required"
        node, err = session.node_or_error(address)
        if err:
            return err
        if session.struct_registry is None:
            return "error: struct registry not available"
        text = node.path.read_text(encoding="utf-8", errors="ignore")
        report = run_field_coherence(text, session.struct_registry.get_all())
        if report.ok:
            return f"0x{node.addr} ({node.name}): {report.summary()}"
        return (
            f"0x{node.addr} ({node.name}): FAIL\n"
            + format_coherence_violations(report)
            + "\nAction: revert wrong typed fields to bare offsets, or align "
            "the variable's struct type / registry fields so names match."
        )

    return [batch_check_signatures, check_field_coherence]
