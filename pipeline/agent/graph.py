from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from pipeline.addresses import addr_key
from pipeline.c_source import first_function_name
from pipeline.registry import PLACEHOLDER_RE


@dataclass
class FunctionNode:
    addr: str
    name: str
    path: Path
    callees: set[str] = field(default_factory=set)
    placeholders: set[str] = field(default_factory=set)


class CallGraph:
    def __init__(self, codeql_dir: Path) -> None:
        self.nodes: dict[str, FunctionNode] = {}
        self._name_to_addr: dict[str, str] = {}
        self._build(codeql_dir)

    def _build(self, codeql_dir: Path) -> None:
        sources: dict[str, str] = {}
        for path in sorted(codeql_dir.glob("0x*.c")):
            head = path.stem[2:] if path.stem.startswith("0x") else path.stem
            addr = addr_key(head.split("_", 1)[0])
            text = path.read_text(encoding="utf-8", errors="ignore")
            name = first_function_name(text)
            if not name:
                if "_" in head:
                    name = head.split("_", 1)[1]
                else:
                    name = f"FUN_{addr}"
            self.nodes[addr] = FunctionNode(addr=addr, name=name, path=path)
            self._name_to_addr.setdefault(name, addr)
            sources[addr] = text

        names = [name for name in self._name_to_addr if name]
        callee_re = (
            re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\s*\(")
            if names
            else None
        )
        for addr, text in sources.items():
            node = self.nodes[addr]
            if callee_re is not None:
                node.callees = {n for n in callee_re.findall(text) if self._name_to_addr.get(n) != addr}
            node.placeholders = set(PLACEHOLDER_RE.findall(text))

    def resolve(self, address: str) -> FunctionNode | None:
        return self.nodes.get(addr_key(address))

    def addr_of(self, name: str) -> str | None:
        return self._name_to_addr.get(name)

    def callers(self, address: str) -> list[FunctionNode]:
        node = self.resolve(address)
        if node is None:
            return []
        return [n for n in self.nodes.values() if node.name in n.callees]

    def callee_nodes(self, address: str) -> list[FunctionNode]:
        node = self.resolve(address)
        if node is None:
            return []
        out = []
        for callee_name in sorted(node.callees):
            callee_addr = self._name_to_addr.get(callee_name)
            if callee_addr and callee_addr in self.nodes:
                out.append(self.nodes[callee_addr])
        return out
