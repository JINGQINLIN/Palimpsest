from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from anthropic import beta_tool

from pipeline.agent.flows import format_flows
from pipeline.agent.graph import CallGraph
from pipeline.paths import TYPES_HEADER_FILENAME
from pipeline.registry import NamingRegistry, StructRegistry


@dataclass
class ReviewSession:
    graph: CallGraph
    registry: NamingRegistry
    struct_registry: StructRegistry
    flows: dict[str, Any] = field(default_factory=dict)
    changes: list[dict[str, Any]] = field(default_factory=list)
    read_addrs: set[str] = field(default_factory=set)

    def _node_or_error(self, address: str):
        node = self.graph.resolve(address)
        if node is None:
            known = ", ".join(sorted(self.graph.nodes)[:12])
            return None, f"No function found for address {address!r}. Known examples: {known} ..."
        return node, ""


def _require(tool: str, args: list[tuple[str, str]]) -> str:
    """Return a model-friendly error message if any required argument is empty.

    Args:
        tool: tool name, used in the error message.
        args: ordered list of (arg_name, arg_value) pairs to validate.

    Returns:
        Empty string if every argument is non-empty; otherwise an error message
        naming the first missing argument and listing all required argument names.
    """
    for name, value in args:
        if not value:
            required = ", ".join(n for n, _ in args)
            return f"{tool} requires '{name}'. Provide all of: {required}."
    return ""


def _replace_across_files(graph: CallGraph, pattern: re.Pattern, replacement: str) -> tuple[int, int]:
    occurrences = files = 0
    for node in graph.nodes.values():
        text = node.path.read_text(encoding="utf-8", errors="ignore")
        new_text, n = pattern.subn(replacement, text)
        if n:
            node.path.write_text(new_text, encoding="utf-8")
            occurrences += n
            files += 1
    return occurrences, files


def build_tools(session: ReviewSession) -> list:
    graph = session.graph

    @beta_tool
    def get_flows() -> str:
        """List the source->sink chains to restore (from flows.json), ranked high/low.

        These are your primary targets. Each entry: a sink (command-exec = high,
        memory-write = low), the shortest call-graph route that reaches it, and a status.
        status=root means the sink's function has no resolved caller — verify whether it is
        the program entry or reached via an unseen (function-pointer) edge before acting.
        """
        if not session.flows.get("sinks"):
            return "(no sinks detected)"
        return format_flows(session.flows)

    @beta_tool
    def list_functions() -> str:
        """List every function: address, current name, callee count, residual placeholders.

        Use it for global context (placeholders, duplicate names); the chains from get_flows
        are the primary targets.
        """
        lines = ["addr | name | callees | placeholders"]
        for addr in sorted(graph.nodes):
            node = graph.nodes[addr]
            ph = ",".join(sorted(node.placeholders)) if node.placeholders else "-"
            lines.append(f"0x{addr} | {node.name} | {len(node.callees)} | {ph}")
        return "\n".join(lines)

    @beta_tool
    def read_function(address: str = "") -> str:
        """Read a function's full C source. Reading the same function again returns a
        short reminder instead of the full text (it is already in the conversation above).

        Args:
            address: function address, e.g. "0xeb08".
        """
        if err := _require("read_function", [("address", address)]):
            return err
        node, err = session._node_or_error(address)
        if err:
            return err
        if node.addr in session.read_addrs:
            return f"Already read 0x{node.addr} ({node.name}) above; refer to it there."
        session.read_addrs.add(node.addr)
        return node.path.read_text(encoding="utf-8", errors="ignore")

    @beta_tool
    def get_callers(address: str = "") -> str:
        """List functions that call this one. Use it to check call sites against the definition.

        Args:
            address: address of the callee.
        """
        if err := _require("get_callers", [("address", address)]):
            return err
        node, err = session._node_or_error(address)
        if err:
            return err
        callers = graph.callers(address)
        if not callers:
            return f"No function calls {node.name} (0x{node.addr})."
        return "\n".join(f"0x{c.addr} | {c.name}" for c in callers)

    @beta_tool
    def get_callees(address: str = "") -> str:
        """List functions this one calls, split into resolved and placeholder.

        Args:
            address: function address.
        """
        if err := _require("get_callees", [("address", address)]):
            return err
        node, err = session._node_or_error(address)
        if err:
            return err
        resolved = graph.callee_nodes(address)
        lines = [f"0x{c.addr} | {c.name}" for c in resolved]
        unresolved = sorted(node.callees - {c.name for c in resolved}) + sorted(node.placeholders)
        if unresolved:
            lines.append("unresolved: " + ", ".join(unresolved))
        return "\n".join(lines) if lines else f"{node.name} calls no other known function."

    @beta_tool
    def get_registry() -> str:
        """Read the cross-function symbol table: symbol -> canonical name, type, confidence, evidence."""
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
        """Read reconstructed struct layouts (the authoritative definitions in recopilot_types.h).

        The `struct NAME *` types and field accesses in the code are based on these layouts.
        Field names are defined in the shared header; do not rename struct fields with rename_symbol.
        """
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

    @beta_tool
    def edit_function(address: str = "", old_str: str = "", new_str: str = "") -> str:
        """Exact string replace in one function file (local consistency fix).

        old_str must occur exactly once in the file; otherwise add more context to make it unique.

        Args:
            address: target function address.
            old_str: text to replace (must be unique).
            new_str: replacement text.
        """
        if err := _require(
            "edit_function",
            [("address", address), ("old_str", old_str), ("new_str", new_str)],
        ):
            return err
        node, err = session._node_or_error(address)
        if err:
            return err
        text = node.path.read_text(encoding="utf-8", errors="ignore")
        count = text.count(old_str)
        if count == 0:
            return "old_str not found; nothing changed. read_function first to confirm the text."
        if count > 1:
            return f"old_str occurs {count} times and is not unique. Add more context."
        node.path.write_text(text.replace(old_str, new_str), encoding="utf-8")
        session.read_addrs.discard(node.addr)
        session.changes.append(
            {"tool": "edit_function", "address": f"0x{node.addr}",
             "old": old_str, "new": new_str}
        )
        return f"Edited 0x{node.addr} ({node.name})."

    @beta_tool
    def rewrite_function(address: str = "", new_code: str = "") -> str:
        """Rewrite a whole function with new source (for larger structural improvements).

        Use only when you are sure the result is semantically equivalent and clearly more
        readable/analyzable; prefer edit_function for small fixes. Do not change the signature.
        The recopilot_types.h include is preserved automatically; you need not write #include.

        Args:
            address: target function address.
            new_code: the function's new full C source.
        """
        if err := _require(
            "rewrite_function",
            [("address", address), ("new_code", new_code)],
        ):
            return err
        node, err = session._node_or_error(address)
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
            {"tool": "rewrite_function", "address": f"0x{node.addr}",
             "old": old, "new": body}
        )
        return f"Rewrote 0x{node.addr} ({node.name})."

    @beta_tool
    def rename_symbol(old_name: str = "", new_name: str = "") -> str:
        """Rename an identifier across the whole code set, on word boundaries (global naming fix).

        Use it to unify one semantic entity to a single name everywhere.

        Args:
            old_name: existing identifier.
            new_name: unified new identifier.
        """
        if err := _require(
            "rename_symbol",
            [("old_name", old_name), ("new_name", new_name)],
        ):
            return err
        if not re.fullmatch(r"[A-Za-z_]\w*", new_name):
            return f"new_name {new_name!r} is not a valid C identifier."
        pattern = re.compile(rf"\b{re.escape(old_name)}\b")
        occurrences, files = _replace_across_files(graph, pattern, new_name)
        if occurrences == 0:
            return f"Identifier {old_name!r} not found; nothing changed."
        session.changes.append(
            {"tool": "rename_symbol", "old": old_name, "new": new_name,
             "occurrences": occurrences, "files": files}
        )
        return f"Renamed {old_name} -> {new_name}: {occurrences} occurrences across {files} files."

    @beta_tool
    def rename_struct(old_name: str = "", new_name: str = "") -> str:
        """Rename or merge a struct type (for dedup and better names).

        - new_name does not exist -> pure rename.
        - new_name already exists -> merge: drop old_name's layout, keep new_name's as authoritative.

        Both replace every `struct old_name` with `struct new_name` across the .c files.
        Before merging, confirm with get_structs that the offset layouts match; if field names
        differ at the same offset, first use edit_function to change old_name's `->field`
        accesses to new_name's field names, then merge.

        Args:
            old_name: existing struct name.
            new_name: target struct name (a merge if it already exists).
        """
        if err := _require(
            "rename_struct",
            [("old_name", old_name), ("new_name", new_name)],
        ):
            return err
        if not re.fullmatch(r"[A-Za-z_]\w*", new_name):
            return f"new_name {new_name!r} is not a valid C identifier."
        registry = session.struct_registry
        source = registry.lookup(old_name)
        if source is None:
            return f"Struct {old_name!r} not found."
        if old_name == new_name:
            return "old_name equals new_name; nothing to do."

        merging = registry.lookup(new_name) is not None
        if not merging:
            registry.update(
                name=new_name,
                fields=source["fields"],
                size=source.get("size", 0),
                confidence=source.get("confidence", "medium"),
                evidence=source.get("evidence", ""),
                source_file=source.get("source_file", ""),
            )
        registry.delete(old_name)

        pattern = re.compile(rf"\bstruct\s+{re.escape(old_name)}\b")
        occurrences, files = _replace_across_files(graph, pattern, f"struct {new_name}")
        verb = "merged into" if merging else "renamed to"
        session.changes.append(
            {"tool": "rename_struct", "old": old_name, "new": new_name,
             "merged": merging, "code_occurrences": occurrences, "files": files}
        )
        return f"struct {old_name} {verb} struct {new_name}: {occurrences} code occurrences across {files} files."

    return [
        get_flows,
        list_functions,
        read_function,
        get_callers,
        get_callees,
        get_registry,
        get_structs,
        edit_function,
        rewrite_function,
        rename_symbol,
        rename_struct,
    ]
