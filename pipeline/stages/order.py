from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from pipeline.stages.ghidra import FunctionContext

_FUN_PLACEHOLDER_RE = re.compile(r"\bFUN_([0-9a-fA-F]+)\b")


def _normalize_addr(hex_str: str) -> str:
    """Return the lowercase zero-padded form used as contexts dict keys."""
    return f"{int(hex_str, 16):08x}"


def _build_callee_map(contexts: dict[str, FunctionContext]) -> dict[str, set[str]]:
    """For each function, the set of in-package functions it calls.

    Calls are detected from the raw decompile text two ways:
    - ``FUN_<hex>`` placeholders, normalized to address form.
    - Known function names (any ``ghidra_name`` not starting with ``FUN_``)
      appearing as ``name(``.

    False positives from a name substring inside a string literal are possible
    but only add spurious edges; they never put a caller before its callee.
    """
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
            target = _normalize_addr(hex_suffix)
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
    """Leaf-first topological processing plan.

    Attributes:
        layers: addresses grouped by topological depth. ``layers[0]`` are pure
            leaves (no in-package callees). Each subsequent layer's functions
            only depend on earlier layers. Within a layer, addresses sort
            ascending for stable, reproducible output.
        cycle: addresses that could not be ordered because they participate in
            recursion or mutual recursion. Also sorted by address ascending.
    """

    layers: list[list[str]]
    cycle: list[str]

    @property
    def order(self) -> list[str]:
        """Flat processing order: every callee precedes its caller."""
        return [addr for layer in self.layers for addr in layer] + self.cycle

    def summary(self) -> str:
        """Single-line depth histogram, e.g. ``d0:36 d1:15 d2:9  cycles:0``.

        The ``cycles`` segment is omitted when no cycles were detected.
        """
        text = " ".join(f"d{i}:{len(layer)}" for i, layer in enumerate(self.layers))
        if self.cycle:
            text += f"  cycles:{len(self.cycle)}"
        return text

    def walk(self) -> list[tuple[str, str]]:
        """``(address, position_label)`` pairs in processing order.

        ``position_label`` is ``d{N} {i}/{size}`` for layer members and
        ``cycle {i}/{size}`` for cycle members, suitable for live progress
        display.
        """
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
    """Build the leaf-first topological plan for ``contexts``.

    Uses Kahn's algorithm: start from pure leaves, then peel one layer at a
    time. Functions left behind when the queue empties form cycles and are
    appended to ``cycle`` in address order.
    """
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
