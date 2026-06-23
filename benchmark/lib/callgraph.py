"""Call-graph construction and seed propagation for alignment.

Strings pin a handful of functions with certainty (benchmark/tools/anchor.py),
but most functions carry no distinctive string. We spread those certain seeds
along call edges: if a pinned binary function and its pinned source twin each
have exactly one still-unmatched callee (or caller), those two must be the same
function. Iterating this reaches internal helpers that strings cannot.

The two graphs live in different node spaces — binary side uses addresses
(FUN_xxxx), source side uses names — so the seed pairs are the only bridge.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from benchmark.lib.invariants import callee_addrs
from pipeline.paths import RAW_PACKAGE_SUBDIR


def build_bin_callgraph(package_dir: Path) -> dict[str, set[str]]:
    """addr -> internal callee addrs (edges within this binary only)."""
    code_by_addr: dict[str, str] = {}
    for path in sorted((package_dir / RAW_PACKAGE_SUBDIR).glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        addr = str(data.get("address") or path.stem)
        code_by_addr[addr] = str(data.get("code") or "")

    internal = set(code_by_addr)
    return {
        addr: {c for c in callee_addrs(code) if c in internal}
        for addr, code in code_by_addr.items()
    }


def build_src_callgraph(gold_functions_path: Path) -> dict[str, set[str]]:
    """func -> internal callee funcs (calls to other source functions only)."""
    data = json.loads(gold_functions_path.read_text(encoding="utf-8"))
    funcs = data.get("functions") or {}
    names = {entry.get("func_name") for entry in funcs.values()}

    graph: dict[str, set[str]] = defaultdict(set)
    for entry in funcs.values():
        name = entry.get("func_name")
        for callee in entry.get("api_calls") or []:
            if callee in names and callee != name:
                graph[name].add(callee)
    return dict(graph)


def _invert(graph: dict[str, set[str]]) -> dict[str, set[str]]:
    """callee -> callers."""
    inv: dict[str, set[str]] = defaultdict(set)
    for src, dsts in graph.items():
        for dst in dsts:
            inv[dst].add(src)
    return inv


def propagate(
    seeds: dict[str, str],
    bin_graph: dict[str, set[str]],
    src_graph: dict[str, set[str]],
) -> dict[str, dict]:
    """Spread seed pairs along call edges; return the NEW pairs only.

    Conservative, zero-ambiguity rule: for a matched pair (A, a), if A and a
    each have exactly one still-unmatched neighbour in the same direction, match
    those neighbours. Applied both down (callees) and up (callers), iterated to
    a fixed point.
    """
    matched: dict[str, str] = dict(seeds)
    used_funcs: set[str] = set(seeds.values())
    new_pairs: dict[str, dict] = {}

    directions = (
        ("callee", bin_graph, src_graph),
        ("caller", _invert(bin_graph), _invert(src_graph)),
    )

    changed = True
    while changed:
        changed = False
        for addr, func in list(matched.items()):
            for label, bin_dir, src_dir in directions:
                bin_un = [b for b in bin_dir.get(addr, ()) if b not in matched]
                src_un = [s for s in src_dir.get(func, ()) if s not in used_funcs]
                if len(bin_un) == 1 and len(src_un) == 1:
                    addr_new, func_new = bin_un[0], src_un[0]
                    matched[addr_new] = func_new
                    used_funcs.add(func_new)
                    new_pairs[addr_new] = {"func": func_new, "via": f"{label} of 0x{addr}/{func}"}
                    changed = True

    return new_pairs
