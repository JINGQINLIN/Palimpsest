"""Modification tools for the agent review loop.

Five tools that let the agent verify syntax, edit/rewrite function bodies, and
rename symbols or structs across the whole code set.
"""
from __future__ import annotations

import re
from pathlib import Path

from anthropic import beta_tool

from pipeline.agent.session import ReviewSession
from pipeline.registry.coherence import (
    check_field_coherence,
    format_coherence_violations,
)
from pipeline.agent.syntax_utils import check_file
from pipeline.agent.tools._shared import _replace_across_files, _require
from pipeline.paths import TYPES_HEADER_FILENAME


def build_edit_tools(
    session: ReviewSession, graph, catalog, codeql_dir: Path
) -> list:
    """Build the 5 modification tools closed over ``session``."""

    @beta_tool
    def check_syntax(address: str = "") -> str:
        """Run gcc -fsyntax-only on a function file to verify it compiles.

        Args:
            address: function address, e.g. "0xeb08".

        Example output (success)::

            0xeb08 (handle_request): ok.

        Example output (failure)::

            0xeb08 (handle_request): 2 syntax error(s):
            error: expected ';' after expression
            ...
        """
        if err := _require("check_syntax", [("address", address)]):
            return err
        node, err = session.node_or_error(address)
        if err:
            return err
        errors = check_file(codeql_dir, node.path.name)
        if not errors:
            return f"0x{node.addr} ({node.name}): ok."
        shown = errors[:10]
        more = len(errors) - len(shown)
        suffix = f"\n... ({more} more)" if more else ""
        session.record_change({"tool": "check_syntax", "address": f"0x{node.addr}"})
        return (
            f"0x{node.addr} ({node.name}): {len(errors)} syntax error(s):\n"
            + "\n".join(shown)
            + suffix
        )

    @beta_tool
    def edit_function(address: str = "", old_str: str = "", new_str: str = "") -> str:
        """Exact string replace in one function file (must be unique).

        Args:
            address: target function address.
            old_str: text to replace.
            new_str: replacement text.

        Example output::

            Edited 0xeb08 (handle_request).
        """
        if err := _require(
            "edit_function",
            [("address", address), ("old_str", old_str), ("new_str", new_str)],
        ):
            return err
        node, err = session.node_or_error(address)
        if err:
            return err
        if not session.acquire_edit(node.addr):
            return f"0x{node.addr} ({node.name}): locked by another agent — skip."
        text = node.path.read_text(encoding="utf-8", errors="ignore")
        count = text.count(old_str)
        if count == 0:
            return "old_str not found; use read_function or get_call_sites to confirm text."
        if count > 1:
            return f"old_str occurs {count} times; add more context."
        new_text = text.replace(old_str, new_str)
        node.path.write_text(new_text, encoding="utf-8")
        # Mirror the edit to the reconstruction artifact so named.c stays
        # consistent with codeql/src. Without this, human-readable named.c
        # would retain the old_str while CLARIS sees the new_str.
        if node.named_c_path and node.named_c_path.is_file():
            named_text = node.named_c_path.read_text(encoding="utf-8", errors="ignore")
            if old_str in named_text:
                node.named_c_path.write_text(
                    named_text.replace(old_str, new_str), encoding="utf-8"
                )
        session.read_addrs.discard(node.addr)
        session.record_change(
            {"tool": "edit_function", "address": f"0x{node.addr}", "old": old_str, "new": new_str}
        )
        msg = f"Edited 0x{node.addr} ({node.name})."
        if session.struct_registry is not None:
            report = check_field_coherence(new_text, session.struct_registry.get_all())
            if not report.ok:
                msg += (
                    "\nWARNING field coherence — typed `->`/`.` access missing "
                    "on declared struct; prefer bare offsets or fix the type:\n"
                    + format_coherence_violations(report)
                )
        return msg

    @beta_tool
    def rewrite_function(address: str = "", new_code: str = "") -> str:
        """Rewrite a whole function (semantically equivalent; prefer edit_function).

        Args:
            address: target function address.
            new_code: new full C source for the function.

        Example output::

            Rewrote 0xeb08 (handle_request).
        """
        if err := _require(
            "rewrite_function",
            [("address", address), ("new_code", new_code)],
        ):
            return err
        node, err = session.node_or_error(address)
        if err:
            return err
        if not session.acquire_edit(node.addr):
            return f"0x{node.addr} ({node.name}): locked by another agent — skip."
        include = f'#include "{TYPES_HEADER_FILENAME}"'
        body = new_code if include in new_code else f"{include}\n\n{new_code.lstrip()}"
        if not body.endswith("\n"):
            body += "\n"
        old = node.path.read_text(encoding="utf-8", errors="ignore")
        node.path.write_text(body, encoding="utf-8")
        # Mirror the rewrite to the reconstruction artifact. rewrite_function
        # replaces the whole file content, so named.c gets the same new body
        # (minus the codeql-specific #include header that named.c does not use).
        if node.named_c_path and node.named_c_path.is_file():
            named_body = new_code
            if not named_body.endswith("\n"):
                named_body += "\n"
            node.named_c_path.write_text(named_body, encoding="utf-8")
        session.read_addrs.discard(node.addr)
        session.record_change(
            {"tool": "rewrite_function", "address": f"0x{node.addr}", "old": old, "new": body}
        )
        msg = f"Rewrote 0x{node.addr} ({node.name})."
        if session.struct_registry is not None:
            report = check_field_coherence(body, session.struct_registry.get_all())
            if not report.ok:
                msg += (
                    "\nWARNING field coherence — typed `->`/`.` access missing "
                    "on declared struct; prefer bare offsets or fix the type:\n"
                    + format_coherence_violations(report)
                )
        return msg

    @beta_tool
    def rename_symbol(old_name: str = "", new_name: str = "") -> str:
        """Rename an identifier across the whole code set (word boundaries).

        Args:
            old_name: existing identifier.
            new_name: new identifier.

        Example output::

            Renamed FUN_0000f550 -> handle_request: 12 hits in 5 files.
        """
        if err := _require("rename_symbol", [("old_name", old_name), ("new_name", new_name)]):
            return err
        if not re.fullmatch(r"[A-Za-z_]\w*", new_name):
            return f"new_name {new_name!r} is not a valid C identifier."
        pattern = re.compile(rf"\b{re.escape(old_name)}\b")
        occurrences, files = _replace_across_files(session, pattern, new_name)
        if occurrences == 0:
            return f"Identifier {old_name!r} not found."
        session.record_change(
            {"tool": "rename_symbol", "old": old_name, "new": new_name,
             "occurrences": occurrences, "files": files}
        )
        return f"Renamed {old_name} -> {new_name}: {occurrences} hits in {files} files."

    @beta_tool
    def rename_struct(old_name: str = "", new_name: str = "") -> str:
        """Rename or merge a struct type across all .c files.

        Args:
            old_name: existing struct name.
            new_name: target name (merge if it already exists).

        Example output::

            struct struct_1 renamed to struct conn_state: 8 hits in 3 files.
        """
        if err := _require("rename_struct", [("old_name", old_name), ("new_name", new_name)]):
            return err
        if not re.fullmatch(r"[A-Za-z_]\w*", new_name):
            return f"new_name {new_name!r} is not a valid C identifier."
        reg = session.struct_registry
        source = reg.lookup(old_name)
        if source is None:
            return f"Struct {old_name!r} not found."
        if old_name == new_name:
            return "old_name equals new_name; nothing to do."

        merging = reg.lookup(new_name) is not None
        if not merging:
            reg.update(
                name=new_name,
                fields=source["fields"],
                size=source.get("size", 0),
                confidence=source.get("confidence", "medium"),
                evidence=source.get("evidence", ""),
                source_file=source.get("source_file", ""),
            )
        reg.delete(old_name)

        pattern = re.compile(rf"\bstruct\s+{re.escape(old_name)}\b")
        occurrences, files = _replace_across_files(session, pattern, f"struct {new_name}")
        verb = "merged into" if merging else "renamed to"
        session.record_change(
            {"tool": "rename_struct", "old": old_name, "new": new_name,
             "merged": merging, "code_occurrences": occurrences, "files": files}
        )
        return f"struct {old_name} {verb} struct {new_name}: {occurrences} hits in {files} files."

    return [
        check_syntax,
        edit_function,
        rewrite_function,
        rename_symbol,
        rename_struct,
    ]
