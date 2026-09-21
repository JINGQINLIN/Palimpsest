"""Read-only exploration tools for the agent review loop.

Nine tools that let the agent browse the function catalog, inspect call-graph
edges, search code, and read registry/struct state — without modifying files.
"""
from __future__ import annotations

from pathlib import Path

from anthropic import beta_tool

from pipeline.agent.session import ReviewSession
from pipeline.agent.tools._shared import _require
from pipeline.registry import format_struct_summary


def build_explore_tools(
    session: ReviewSession, graph, catalog, codeql_dir: Path
) -> list:
    """Build the 9 read-only exploration tools closed over ``session``."""

    @beta_tool
    def browse_functions(filter: str = "all", query: str = "") -> str:
        """Browse the function catalog without loading full source.

        Each row: addr | name | return type | params | caller/callee counts | flags.
        flags: entry, ph:N (residual placeholders), indirect:N, no_callers.

        Args:
            filter: all | placeholders | entries | indirect | isolated
            query: optional substring to match name, address, signature, or placeholder

        Example output::

            addr | name | return | params | graph | flags
            0xeb08 | handle_request | int | (int fd) | 3/2 | entry
        """
        infos = catalog.browse(filter_name=filter, query=query)
        if not infos:
            return f"(no functions match filter={filter!r} query={query!r})"
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

        Example output::

            addr | line | snippet
            0xeb08 handle_request | L42 | (*handler_table[i])(fd);
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

        Example output::

            0xa14c | main
            0xb020 | init_server
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
        """Cross-function symbol table: placeholder -> canonical name, type, evidence.

        Example output::

            FUN_0000f550 -> handle_request :: int (*)(int) [function, high] # resolved via dispatch table
        """
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
        """Reconstructed struct layouts from recopilot_types.h (field names are authoritative).

        Example output::

            struct conn_state (size 0x10): +0x0 fd int; +0x4 flags uint; +0x8 next_ptr struct conn_state *
        """
        structs = session.struct_registry.get_all()
        if not structs:
            return "(no reconstructed structs yet)"
        return "\n".join(
            format_struct_summary(name, entry)
            for name, entry in sorted(structs.items())
        )

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
    ]
