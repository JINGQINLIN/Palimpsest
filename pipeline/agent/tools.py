from __future__ import annotations

import re
from typing import Any

from anthropic import beta_tool

from pipeline.agent.session import ReviewSession
from pipeline.paths import TYPES_HEADER_FILENAME


def _require(tool: str, args: list[tuple[str, str]]) -> str:
    for name, value in args:
        if not value:
            required = ", ".join(n for n, _ in args)
            return f"{tool} requires '{name}'. Provide all of: {required}."
    return ""


def _replace_across_files(session: ReviewSession, pattern: re.Pattern, replacement: str) -> tuple[int, int]:
    occurrences = files = 0
    for node in session.graph.nodes.values():
        text = node.path.read_text(encoding="utf-8", errors="ignore")
        new_text, n = pattern.subn(replacement, text)
        if n:
            node.path.write_text(new_text, encoding="utf-8")
            occurrences += n
            files += 1
    return occurrences, files


def build_tools(session: ReviewSession) -> list:
    graph = session.graph
    catalog = session.catalog

    # --- exploration ---------------------------------------------------------

    @beta_tool
    def browse_functions(filter_name: str = "all", query: str = "") -> str:
        """Browse the function catalog without loading full source.

        Each row: addr | name | return type | params | caller/callee counts | flags.
        flags: entry, ph:N (residual placeholders), indirect:N, no_callers.

        Args:
            filter_name: all | placeholders | entries | indirect | isolated
            query: optional substring to match name, address, signature, or placeholder
        """
        infos = catalog.browse(filter_name=filter_name, query=query)
        if not infos:
            return f"(no functions match filter={filter_name!r} query={query!r})"
        header = "addr | name | return | params | graph | flags"
        return header + "\n" + "\n".join(catalog.format_row(i) for i in infos)

    @beta_tool
    def get_function_info(address: str = "") -> str:
        """Metadata card for one function: signature, params, return, graph role,
        placeholders, indirect call sites, body preview, naming_map excerpt.

        Use this to decide whether to read_function — especially for indirect dispatch
        (no static callers) or functions containing (*...)( calls.

        Args:
            address: function address, e.g. "0xeb08".
        """
        if err := _require("get_function_info", [("address", address)]):
            return err
        node, err = session.node_or_error(address)
        if err:
            return err
        info = catalog.get(address)
        if info is None:
            return f"No catalog entry for 0x{node.addr} ({node.name})."
        return catalog.format_detail(info, node)

    @beta_tool
    def search_code(pattern: str = "") -> str:
        """Search all function files for a substring (case-insensitive).

        Useful for dispatch tables, handler arrays, shared global names, or FUN_* placeholders.

        Args:
            pattern: text to find, e.g. "handler_table" or "FUN_0000f550".
        """
        if err := _require("search_code", [("pattern", pattern)]):
            return err
        hits = catalog.search_code(pattern)
        if not hits:
            return f"Pattern {pattern!r} not found."
        lines = ["addr | line | snippet"]
        for addr, lineno, snippet in hits:
            name = graph.nodes[addr].name
            lines.append(f"0x{addr} {name} | L{lineno} | {snippet}")
        return "\n".join(lines)

    @beta_tool
    def read_function(address: str = "") -> str:
        """Read a function's full C source. Re-reading returns a short reminder.

        Args:
            address: function address, e.g. "0xeb08".
        """
        if err := _require("read_function", [("address", address)]):
            return err
        node, err = session.node_or_error(address)
        if err:
            return err
        if node.addr in session.read_addrs:
            return f"Already read 0x{node.addr} ({node.name}) above; refer to it there."
        session.read_addrs.add(node.addr)
        return node.path.read_text(encoding="utf-8", errors="ignore")

    @beta_tool
    def get_callers(address: str = "") -> str:
        """List functions with a direct static call to this one.

        Args:
            address: callee address.
        """
        if err := _require("get_callers", [("address", address)]):
            return err
        node, err = session.node_or_error(address)
        if err:
            return err
        callers = graph.callers(address)
        if not callers:
            return (
                f"No static caller for {node.name} (0x{node.addr}). "
                "Likely entry point or reached via function pointer — use get_function_info, "
                "search_code, and read_function on candidates."
            )
        return "\n".join(f"0x{c.addr} | {c.name}" for c in callers)

    @beta_tool
    def get_callees(address: str = "") -> str:
        """List direct callees: resolved functions and unresolved names/placeholders.

        Args:
            address: function address.
        """
        if err := _require("get_callees", [("address", address)]):
            return err
        node, err = session.node_or_error(address)
        if err:
            return err
        resolved = graph.callee_nodes(address)
        lines = [f"0x{c.addr} | {c.name}" for c in resolved]
        unresolved = sorted(node.callees - {c.name for c in resolved}) + sorted(node.placeholders)
        if unresolved:
            lines.append("unresolved: " + ", ".join(unresolved))
        return "\n".join(lines) if lines else f"{node.name} calls no other known function."

    @beta_tool
    def get_call_sites(address: str = "") -> str:
        """Show direct call-site snippets from every static caller.

        Compare argument types/counts against the callee signature.

        Args:
            address: callee address.
        """
        if err := _require("get_call_sites", [("address", address)]):
            return err
        node, err = session.node_or_error(address)
        if err:
            return err
        hits = catalog.call_sites_for(address)
        if not hits:
            return (
                f"No direct call sites for {node.name} (0x{node.addr}). "
                "If invoked, the edge is likely indirect."
            )
        lines = [f"call sites for {node.name} (0x{node.addr}):"]
        for caller_addr, lineno, snippet in hits:
            caller = graph.nodes[caller_addr]
            lines.append(f"  0x{caller_addr} {caller.name} L{lineno}: {snippet}")
        return "\n".join(lines)

    @beta_tool
    def get_registry() -> str:
        """Cross-function symbol table: placeholder -> canonical name, type, evidence."""
        entries = session.registry.get_all()
        if not entries:
            return "(registry empty)"
        lines = []
        for symbol, entry in entries.items():
            type_part = f" :: {entry['inferred_type']}" if entry.get("inferred_type") else ""
            lines.append(
                f"{symbol} -> {entry['canonical_name']}{type_part} "
                f"[{entry['kind']}, {entry['confidence']}] {entry['evidence']}"
            )
        return "\n".join(lines)

    @beta_tool
    def get_structs() -> str:
        """Reconstructed struct layouts from recopilot_types.h (field names are authoritative)."""
        structs = session.struct_registry.get_all()
        if not structs:
            return "(no reconstructed structs yet)"
        lines = []
        for name, entry in sorted(structs.items()):
            fields = "; ".join(
                f"+0x{f['offset']:x} {f['name']} {f['type']}" for f in entry.get("fields", [])
            )
            lines.append(f"struct {name} (size 0x{entry.get('size', 0):x}): {fields}")
        return "\n".join(lines)

    # --- edits -----------------------------------------------------------------

    @beta_tool
    def edit_function(address: str = "", old_str: str = "", new_str: str = "") -> str:
        """Exact string replace in one function file (must be unique).

        Args:
            address: target function address.
            old_str: text to replace.
            new_str: replacement text.
        """
        if err := _require(
            "edit_function",
            [("address", address), ("old_str", old_str), ("new_str", new_str)],
        ):
            return err
        node, err = session.node_or_error(address)
        if err:
            return err
        text = node.path.read_text(encoding="utf-8", errors="ignore")
        count = text.count(old_str)
        if count == 0:
            return "old_str not found; use read_function or get_call_sites to confirm text."
        if count > 1:
            return f"old_str occurs {count} times; add more context."
        node.path.write_text(text.replace(old_str, new_str), encoding="utf-8")
        session.read_addrs.discard(node.addr)
        session.changes.append(
            {"tool": "edit_function", "address": f"0x{node.addr}", "old": old_str, "new": new_str}
        )
        return f"Edited 0x{node.addr} ({node.name})."

    @beta_tool
    def rewrite_function(address: str = "", new_code: str = "") -> str:
        """Rewrite a whole function (semantically equivalent; prefer edit_function).

        Args:
            address: target function address.
            new_code: new full C source for the function.
        """
        if err := _require(
            "rewrite_function",
            [("address", address), ("new_code", new_code)],
        ):
            return err
        node, err = session.node_or_error(address)
        if err:
            return err
        include = f'#include "{TYPES_HEADER_FILENAME}"'
        body = new_code if include in new_code else f"{include}\n\n{new_code.lstrip()}"
        if not body.endswith("\n"):
            body += "\n"
        old = node.path.read_text(encoding="utf-8", errors="ignore")
        node.path.write_text(body, encoding="utf-8")
        session.read_addrs.discard(node.addr)
        session.changes.append(
            {"tool": "rewrite_function", "address": f"0x{node.addr}", "old": old, "new": body}
        )
        return f"Rewrote 0x{node.addr} ({node.name})."

    @beta_tool
    def rename_symbol(old_name: str = "", new_name: str = "") -> str:
        """Rename an identifier across the whole code set (word boundaries).

        Args:
            old_name: existing identifier.
            new_name: new identifier.
        """
        if err := _require("rename_symbol", [("old_name", old_name), ("new_name", new_name)]):
            return err
        if not re.fullmatch(r"[A-Za-z_]\w*", new_name):
            return f"new_name {new_name!r} is not a valid C identifier."
        pattern = re.compile(rf"\b{re.escape(old_name)}\b")
        occurrences, files = _replace_across_files(session, pattern, new_name)
        if occurrences == 0:
            return f"Identifier {old_name!r} not found."
        session.changes.append(
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
        session.changes.append(
            {"tool": "rename_struct", "old": old_name, "new": new_name,
             "merged": merging, "code_occurrences": occurrences, "files": files}
        )
        return f"struct {old_name} {verb} struct {new_name}: {occurrences} hits in {files} files."

    return [
        browse_functions,
        get_function_info,
        search_code,
        read_function,
        get_callers,
        get_callees,
        get_call_sites,
        get_registry,
        get_structs,
        edit_function,
        rewrite_function,
        rename_symbol,
        rename_struct,
    ]
