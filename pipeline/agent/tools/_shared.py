"""Shared helpers for tool builders (argument validation and cross-file replacement)."""
from __future__ import annotations

import re

from pipeline.agent.session import ReviewSession


def _require(tool: str, args: list[tuple[str, str]]) -> str:
    """Return an error message if any required argument is empty, else empty string."""
    for name, value in args:
        if not value:
            required = ", ".join(n for n, _ in args)
            return f"{tool} requires '{name}'. Provide all of: {required}."
    return ""


def _replace_across_files(session: ReviewSession, pattern: re.Pattern, replacement: str) -> tuple[int, int]:
    """Apply a regex substitution across all function files in the call graph.

    Writes to BOTH the codeql/src file (node.path) AND the reconstruction
    artifact (node.named_c_path) when the latter exists, so the human-readable
    named.c stays consistent with what CLARIS consumes. Without this mirror
    write, batch_resolve_symbols / rename_symbol would leave named.c with stale
    FUN_ placeholders at call sites and function definitions.

    Returns (occurrence_count, file_count). file_count counts distinct files
    touched (a node counts once even if both codeql/src and named.c changed).
    """
    occurrences = files = 0
    for node in session.graph.nodes.values():
        for path in (node.path, node.named_c_path):
            if path is None or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            new_text, n = pattern.subn(replacement, text)
            if n:
                path.write_text(new_text, encoding="utf-8")
                occurrences += n
                files += 1
    return occurrences, files
