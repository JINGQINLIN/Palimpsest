"""Compiler-invariant features for alignment.

These signals survive both compilation and LLM reconstruction, so they can
anchor a binary function (raw decompilation) to its source function without
trusting any name the LLM invented:

- normalized string literals  -> strongest; near-unique identifiers
- callee addresses (FUN_xxxx)  -> call-graph edges (topology, not names)

Note: libc calls are deliberately left out here. On busybox firmware the
bb_error_msg/bb_info_msg wrappers get inlined into printf/syslog, so the libc
call stream diverges between source and binary and carries little signal.
"""

from __future__ import annotations

import re

from pipeline.addresses import normalize_address

from benchmark.lib.c_parse import extract_strings

_PUNCT = re.compile(r"[^\w\s]")
_WS = re.compile(r"\s+")
_FUN_ADDR = re.compile(r"\bFUN_([0-9a-fA-F]+)\b")


def normalize_string(text: str) -> str:
    """Fold version drift: lowercase, punctuation -> space, collapse spaces.

    "Sending OFFER of %s"  -> "sending offer of s"
    "-- OFFER abandoned"   -> "offer abandoned"   (same as the single-dash form)
    """
    text = _PUNCT.sub(" ", text.lower())
    return _WS.sub(" ", text).strip()


def normalized_strings(code: str, *, min_len: int = 6) -> set[str]:
    """Distinctive string literals, normalized; short/generic ones dropped."""
    out: set[str] = set()
    for raw in extract_strings(code):
        norm = normalize_string(raw)
        if len(norm) >= min_len:
            out.add(norm)
    return out


def callee_addrs(code: str) -> set[str]:
    """Ghidra FUN_xxxx callees -> normalized addresses (call-graph edges)."""
    return {normalize_address(h) for h in _FUN_ADDR.findall(code)}
