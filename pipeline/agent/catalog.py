from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pipeline.agent.graph import CallGraph, FunctionNode
from pipeline.c_source import (
    find_direct_call_sites,
    find_indirect_call_sites,
    function_body_preview,
    parse_function_definition,
)
from pipeline.paths import FUNCTIONS_SUBDIR


@dataclass(frozen=True)
class FunctionInfo:
    addr: str
    name: str
    signature: str
    return_type: str
    params: tuple[str, ...]
    line_count: int
    caller_count: int
    callee_count: int
    placeholders: tuple[str, ...]
    indirect_sites: tuple[tuple[int, str], ...]
    is_entry: bool
    body_preview: str
    naming_map: str


class FunctionCatalog:
    """Indexed metadata for every recovered function in the code set."""

    FILTERS = frozenset({"all", "placeholders", "entries", "indirect", "isolated"})

    def __init__(self, graph: CallGraph, package_dir: Path | None = None) -> None:
        self.graph = graph
        self._infos: dict[str, FunctionInfo] = {}
        self._caller_counts = self._count_callers(graph)
        self._build(package_dir)

    @staticmethod
    def _count_callers(graph: CallGraph) -> dict[str, int]:
        counts: dict[str, int] = {}
        for node in graph.nodes.values():
            for callee_name in node.callees:
                callee_addr = graph.addr_of(callee_name)
                if callee_addr:
                    counts[callee_addr] = counts.get(callee_addr, 0) + 1
        return counts

    def _naming_map_for(self, package_dir: Path | None, addr: str) -> str:
        if package_dir is None:
            return ""
        path = package_dir / FUNCTIONS_SUBDIR / f"0x{addr}" / "naming_map.txt"
        if not path.is_file():
            return ""
        text = path.read_text(encoding="utf-8", errors="ignore").strip()
        if len(text) > 800:
            return text[:800] + "\n...(truncated)"
        return text

    def _build(self, package_dir: Path | None) -> None:
        called_names = {name for node in self.graph.nodes.values() for name in node.callees}
        for addr, node in self.graph.nodes.items():
            text = node.path.read_text(encoding="utf-8", errors="ignore")
            parsed = parse_function_definition(text) or {}
            indirect = tuple(find_indirect_call_sites(text))
            placeholders = tuple(sorted(node.placeholders))
            caller_count = self._caller_counts.get(addr, 0)
            self._infos[addr] = FunctionInfo(
                addr=addr,
                name=node.name,
                signature=parsed.get("signature", node.name),
                return_type=parsed.get("return_type", "?"),
                params=tuple(parsed.get("params", ())),
                line_count=len(text.splitlines()),
                caller_count=caller_count,
                callee_count=len(node.callees),
                placeholders=placeholders,
                indirect_sites=indirect,
                is_entry=node.name not in called_names,
                body_preview=function_body_preview(text),
                naming_map=self._naming_map_for(package_dir, addr),
            )

    def get(self, address: str) -> FunctionInfo | None:
        node = self.graph.resolve(address)
        if node is None:
            return None
        return self._infos.get(node.addr)

    def all_infos(self) -> list[FunctionInfo]:
        return [self._infos[a] for a in sorted(self._infos)]

    def browse(self, *, filter_name: str = "all", query: str = "") -> list[FunctionInfo]:
        filt = (filter_name or "all").strip().lower()
        if filt not in self.FILTERS:
            filt = "all"
        q = query.strip().lower()

        out: list[FunctionInfo] = []
        for info in self.all_infos():
            if filt == "placeholders" and not info.placeholders:
                continue
            if filt == "entries" and not info.is_entry:
                continue
            if filt == "indirect" and not info.indirect_sites:
                continue
            if filt == "isolated" and (info.caller_count > 0 or info.callee_count > 0):
                continue
            if q and q not in info.name.lower() and q not in info.addr and q not in info.signature.lower():
                if not any(q in ph.lower() for ph in info.placeholders):
                    continue
            out.append(info)
        return out

    def format_row(self, info: FunctionInfo) -> str:
        flags: list[str] = []
        if info.is_entry:
            flags.append("entry")
        if info.placeholders:
            flags.append(f"ph:{len(info.placeholders)}")
        if info.indirect_sites:
            flags.append(f"indirect:{len(info.indirect_sites)}")
        if info.caller_count == 0 and not info.is_entry:
            flags.append("no_callers")
        flag_str = ",".join(flags) if flags else "-"
        params = ", ".join(info.params) if info.params else "void"
        return (
            f"0x{info.addr} | {info.name} | {info.return_type} | ({params}) "
            f"| callers:{info.caller_count} callees:{info.callee_count} | {flag_str}"
        )

    def format_detail(self, info: FunctionInfo, node: FunctionNode) -> str:
        lines = [
            f"address: 0x{info.addr}",
            f"name: {info.name}",
            f"signature: {info.signature}",
            f"return: {info.return_type}",
            f"params: {', '.join(info.params) if info.params else 'void'}",
            f"lines: {info.line_count}",
            f"callers: {info.caller_count}  callees: {info.callee_count}  entry: {info.is_entry}",
        ]
        if info.placeholders:
            lines.append(f"placeholders: {', '.join(info.placeholders)}")
        if info.indirect_sites:
            lines.append("indirect calls:")
            for lineno, snippet in info.indirect_sites:
                lines.append(f"  L{lineno}: {snippet}")
        resolved = self.graph.callee_nodes(info.addr)
        if resolved:
            lines.append("resolved callees: " + ", ".join(f"{c.name}(0x{c.addr})" for c in resolved))
        callers = self.graph.callers(info.addr)
        if callers:
            lines.append("callers: " + ", ".join(f"{c.name}(0x{c.addr})" for c in callers))
        elif not info.is_entry:
            lines.append(
                "callers: (none in static graph — may be reached via function pointer / dispatch table)"
            )
        if info.body_preview:
            lines.append("body preview:")
            lines.append(info.body_preview)
        if info.naming_map:
            lines.append("naming_map:")
            lines.append(info.naming_map)
        lines.append(f"file: {node.path.name}")
        return "\n".join(lines)

    def call_sites_for(self, address: str, *, limit: int = 24) -> list[tuple[str, int, str]]:
        """Return (caller_addr, line_no, snippet) for direct invocations of address."""
        node = self.graph.resolve(address)
        if node is None:
            return []
        hits: list[tuple[str, int, str]] = []
        for caller in self.graph.callers(address):
            text = caller.path.read_text(encoding="utf-8", errors="ignore")
            for lineno, snippet in find_direct_call_sites(text, node.name, limit=limit):
                hits.append((caller.addr, lineno, snippet))
                if len(hits) >= limit:
                    return hits
        return hits

    def search_code(self, pattern: str, *, limit: int = 30) -> list[tuple[str, int, str]]:
        """Substring search across all function files."""
        needle = pattern.strip()
        if not needle:
            return []
        hits: list[tuple[str, int, str]] = []
        lower = needle.lower()
        for addr, node in self.graph.nodes.items():
            for lineno, line in enumerate(node.path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if lower in line.lower():
                    hits.append((addr, lineno, line.strip()[:240]))
                    if len(hits) >= limit:
                        return hits
        return hits
