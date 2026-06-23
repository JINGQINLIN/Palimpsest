"""String-anchoring: pin binary functions to source via unique literals.

A normalized string that appears in exactly one raw function and exactly one
gold source function deterministically links those two. Used by the anchor probe
and as seeds for call-graph propagation (benchmark.lib.callgraph).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from benchmark.lib.invariants import normalize_string, normalized_strings
from pipeline.paths import RAW_PACKAGE_SUBDIR

MIN_STRING_LEN = 6


def raw_strings(package_dir: Path, *, min_len: int = MIN_STRING_LEN) -> dict[str, set[str]]:
    """addr -> normalized strings, from raw Ghidra decompilation."""
    out: dict[str, set[str]] = {}
    for path in sorted((package_dir / RAW_PACKAGE_SUBDIR).glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        addr = str(data.get("address") or path.stem)
        strings = normalized_strings(str(data.get("code") or ""), min_len=min_len)
        if strings:
            out[addr] = strings
    return out


def src_strings(gold_functions_path: Path, *, min_len: int = MIN_STRING_LEN) -> dict[str, set[str]]:
    """func_name -> normalized strings, from gold (one entry per source function)."""
    data = json.loads(gold_functions_path.read_text(encoding="utf-8"))
    out: dict[str, set[str]] = {}
    for name, entry in (data.get("functions") or {}).items():
        strings = {normalize_string(s) for s in (entry.get("strings") or [])}
        strings = {s for s in strings if len(s) >= min_len}
        if strings:
            out[name] = strings
    return out


def _invert(owner_strings: dict[str, set[str]]) -> dict[str, set[str]]:
    """string -> owners that contain it."""
    index: dict[str, set[str]] = defaultdict(set)
    for owner, strings in owner_strings.items():
        for text in strings:
            index[text].add(owner)
    return index


def anchor(raw: dict[str, set[str]], src: dict[str, set[str]]) -> dict:
    """Match pairs where a string is unique on both sides."""
    raw_index = _invert(raw)
    src_index = _invert(src)

    votes: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for text, raw_owners in raw_index.items():
        src_owners = src_index.get(text)
        if src_owners and len(raw_owners) == 1 and len(src_owners) == 1:
            addr = next(iter(raw_owners))
            func = next(iter(src_owners))
            votes[addr][func].append(text)

    pinned: dict[str, dict] = {}
    conflicts: dict[str, dict] = {}
    for addr, by_func in votes.items():
        if len(by_func) == 1:
            func, evidence = next(iter(by_func.items()))
            pinned[addr] = {"func": func, "evidence": sorted(evidence)}
        else:
            conflicts[addr] = {func: sorted(ev) for func, ev in by_func.items()}

    func_to_addrs: dict[str, list[str]] = defaultdict(list)
    for addr, info in pinned.items():
        func_to_addrs[info["func"]].append(addr)
    reverse_conflicts = {f: addrs for f, addrs in func_to_addrs.items() if len(addrs) > 1}

    return {"pinned": pinned, "conflicts": conflicts, "reverse_conflicts": reverse_conflicts}
