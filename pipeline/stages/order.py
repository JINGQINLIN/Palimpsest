from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from pipeline.addresses import normalize_address
from pipeline.stages.ghidra import FunctionContext

_FUN_PLACEHOLDER_RE = re.compile(r"\bFUN_([0-9a-fA-F]+)\b")


def _build_callee_map(contexts: dict[str, FunctionContext]) -> dict[str, set[str]]:
    address_by_name: dict[str, str] = {
        ctx.ghidra_name: addr
        for addr, ctx in contexts.items()
        if not ctx.ghidra_name.startswith("FUN_")
    }
    name_pattern = (
        re.compile(
            r"\b(" + "|".join(re.escape(name) for name in address_by_name) + r")\s*\("
        )
        if address_by_name
        else None
    )

    callees: dict[str, set[str]] = {}
    for addr, ctx in contexts.items():
        targets: set[str] = set()

        for hex_suffix in _FUN_PLACEHOLDER_RE.findall(ctx.code):
            target = normalize_address(hex_suffix)
            if target in contexts and target != addr:
                targets.add(target)

        if name_pattern is not None:
            for name in name_pattern.findall(ctx.code):
                target = address_by_name[name]
                if target != addr:
                    targets.add(target)

        callees[addr] = targets

    return callees


@dataclass(frozen=True)
class TopoPlan:
    layers: list[list[str]]
    cycle: list[str]

    @property
    def order(self) -> list[str]:
        return [addr for layer in self.layers for addr in layer] + self.cycle

    def summary(self) -> str:
        text = " ".join(f"d{i}:{len(layer)}" for i, layer in enumerate(self.layers))
        if self.cycle:
            text += f"  cycles:{len(self.cycle)}"
        return text

    def walk(self) -> list[tuple[str, str]]:
        steps: list[tuple[str, str]] = []
        for depth, layer in enumerate(self.layers):
            size = len(layer)
            for index, addr in enumerate(layer, start=1):
                steps.append((addr, f"d{depth} {index}/{size}"))
        cycle_size = len(self.cycle)
        for index, addr in enumerate(self.cycle, start=1):
            steps.append((addr, f"cycle {index}/{cycle_size}"))
        return steps


def topo_plan(contexts: dict[str, FunctionContext]) -> TopoPlan:
    callees = _build_callee_map(contexts)

    callers: dict[str, list[str]] = defaultdict(list)
    for addr, targets in callees.items():
        for target in targets:
            callers[target].append(addr)

    pending = {addr: len(targets) for addr, targets in callees.items()}
    layers: list[list[str]] = []
    current = sorted(addr for addr, count in pending.items() if count == 0)

    while current:
        layers.append(current)
        next_layer: list[str] = []
        for addr in current:
            for caller in callers[addr]:
                pending[caller] -= 1
                if pending[caller] == 0:
                    next_layer.append(caller)
        current = sorted(next_layer)

    placed = {addr for layer in layers for addr in layer}
    cycle = sorted(addr for addr in contexts if addr not in placed)
    return TopoPlan(layers=layers, cycle=cycle)
