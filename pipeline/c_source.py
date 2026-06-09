from __future__ import annotations

import re

FUNC_DEF_RE = re.compile(
    r"(?m)^\s*[A-Za-z_][\w\s\*]*?\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
)


def first_function_name(code: str) -> str | None:
    match = FUNC_DEF_RE.search(code)
    return match.group(1) if match else None


def rename_function_definition(code: str, base_name: str, codeql_name: str) -> str:
    if base_name == codeql_name:
        return code
    pattern = (
        rf"(?m)^(\s*[A-Za-z_][\w\s\*]*\s+){re.escape(base_name)}(?=\s*\([^;{{}}]*\)\s*\{{)"
    )
    return re.sub(pattern, rf"\1{codeql_name}", code, count=1)
