from __future__ import annotations

import re

FUNC_DEF_RE = re.compile(
    r"(?m)^\s*([A-Za-z_][\w\s\*]*?)\s+([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{"
)
INDIRECT_CALL_RE = re.compile(
    r"\(\s*\*[^)]*\)\s*\(|"  # (*fn)(args)
    r"\[[^\]]+\]\s*\(|"  # table[i](args)
    r"\)\s*\([^;]*\)"  # expr)(args) — often vtable / cast call
)
DIRECT_CALL_RE = re.compile(r"\b({name})\s*\(")


def first_function_name(code: str) -> str | None:
    match = FUNC_DEF_RE.search(code)
    return match.group(2) if match else None


def parse_function_definition(code: str) -> dict | None:
    """Extract return type, name, params, and signature line from the first function."""
    match = FUNC_DEF_RE.search(code)
    if not match:
        return None

    return_type = " ".join(match.group(1).split())
    name = match.group(2)
    params_raw = match.group(3).strip()
    params = _split_params(params_raw)
    signature = f"{return_type} {name}({params_raw})"
    return {
        "name": name,
        "return_type": return_type,
        "params": params,
        "signature": signature,
    }


def _split_params(params_raw: str) -> list[str]:
    if not params_raw or params_raw.strip() == "void":
        return []
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in params_raw:
        if ch == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def find_indirect_call_sites(code: str, *, limit: int = 12) -> list[tuple[int, str]]:
    """Return (line_no, snippet) for likely indirect / function-pointer calls."""
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if INDIRECT_CALL_RE.search(line):
            hits.append((lineno, stripped[:240]))
        if len(hits) >= limit:
            break
    return hits


def find_direct_call_sites(code: str, callee_name: str, *, limit: int = 20) -> list[tuple[int, str]]:
    """Return (line_no, snippet) where callee_name is invoked directly."""
    pattern = re.compile(rf"\b{re.escape(callee_name)}\s*\(")
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(code.splitlines(), 1):
        if pattern.search(line):
            hits.append((lineno, line.strip()[:240]))
        if len(hits) >= limit:
            break
    return hits


def function_body_preview(code: str, *, max_lines: int = 6) -> str:
    """First few non-empty lines inside the function body (after opening brace)."""
    match = FUNC_DEF_RE.search(code)
    if not match:
        return ""
    start = match.end()
    lines: list[str] = []
    for line in code[start:].splitlines():
        stripped = line.strip()
        if not stripped or stripped in {"{", "}"}:
            continue
        if stripped.startswith("}"):
            break
        lines.append(stripped[:120])
        if len(lines) >= max_lines:
            break
    return "\n".join(lines)


def rename_function_definition(code: str, base_name: str, codeql_name: str) -> str:
    if base_name == codeql_name:
        return code
    pattern = (
        rf"(?m)^(\s*[A-Za-z_][\w\s\*]*\s+){re.escape(base_name)}(?=\s*\([^;{{}}]*\)\s*\{{)"
    )
    return re.sub(pattern, rf"\1{codeql_name}", code, count=1)
