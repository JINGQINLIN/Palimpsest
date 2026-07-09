from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pipeline.agent.catalog import FunctionCatalog
from pipeline.agent.graph import CallGraph
from pipeline.registry import NamingRegistry, StructRegistry


@dataclass
class ReviewSession:
    graph: CallGraph
    catalog: FunctionCatalog
    registry: NamingRegistry
    struct_registry: StructRegistry
    changes: list[dict[str, Any]] = field(default_factory=list)
    read_addrs: set[str] = field(default_factory=set)

    def node_or_error(self, address: str):
        node = self.graph.resolve(address)
        if node is None:
            known = ", ".join(f"0x{a}" for a in sorted(self.graph.nodes)[:12])
            return None, f"No function at {address!r}. Examples: {known} ..."
        return node, ""
