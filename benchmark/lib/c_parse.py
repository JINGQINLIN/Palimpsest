"""C function fingerprint extraction for benchmark gold/pred alignment."""

from __future__ import annotations

import re
from collections import Counter

from pipeline.c_source import first_function_name
from pipeline.registry import PLACEHOLDER_RE

# C keywords / known types — not treated as API calls.
_SKIP_CALLS = {
    "if", "for", "while", "switch", "return", "sizeof", "typeof",
    "uint8_t", "uint16_t", "uint32_t", "int8_t", "int16_t", "int32_t",
    "int", "char", "void", "short", "long", "float", "double",
    "struct", "union", "enum", "const", "static", "extern", "inline",
}

_STRING_RE = re.compile(r'"([^"\\]|\\.)*"')
_CHAR_RE = re.compile(r"'([^'\\]|\\.)*'")
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_FUNC_SIG_RE = re.compile(
    r"(?m)^\s*(?:[A-Za-z_][\w\s\*]*?\s+)?([A-Za-z_]\w*)\s*\(([^;{}]*)\)"
)
_PARAM_SPLIT_RE = re.compile(r"\s*,\s*")
_FUNC_START_RE = re.compile(
    r"(?m)"
    r"(?:^|\n)"
    r"(?:static\s+|inline\s+|extern\s+)*"
    r"(?:const\s+|unsigned\s+|signed\s+|long\s+|short\s+)*"
    r"(?:struct\s+\w+\s*\*?\s+|enum\s+\w+\s+)?"
    r"(?:void|int|char|size_t|ssize_t|time_t|pid_t|uint\d+_t|int\d+_t|\w+)\s+"
    r"(\*?\s*)?"
    r"(\w+)\s*"
    r"\("
    r"([^;{}]*)"
    r"\)"
    r"\s*\{"
)
_SKIP_FUNC_NAMES = _SKIP_CALLS | {"if", "while", "for", "switch", "else", "do"}


def _strip_c_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"//.*?$", "", code, flags=re.M)


def _match_brace(code: str, open_index: int) -> int:
    depth = 0
    for i in range(open_index, len(code)):
        ch = code[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def split_c_functions(code: str) -> list[tuple[str, str]]:
    """Split a translation unit into (func_name, snippet) pairs."""
    code = _strip_c_comments(code)
    out: list[tuple[str, str]] = []
    for match in _FUNC_START_RE.finditer(code):
        name = match.group(2)
        if name in _SKIP_FUNC_NAMES:
            continue
        brace = code.find("{", match.end() - 1)
        if brace < 0:
            continue
        close = _match_brace(code, brace)
        if close < 0:
            continue
        out.append((name, code[match.start(): close + 1]))
    return out


def extract_all_functions(code: str) -> dict[str, dict]:
    """Extract one or more functions from a C translation unit."""
    functions = split_c_functions(code)
    if not functions:
        features = extract_function_features(code)
        name = features.get("func_name") or "anonymous"
        return {name: features}
    return {name: extract_function_features(snippet) for name, snippet in functions}


def _strip_literals(code: str) -> str:
    """Remove string/char literals so call-regex does not match inside them."""
    code = _STRING_RE.sub('""', code)
    return _CHAR_RE.sub("''", code)


def extract_strings(code: str) -> list[str]:
    out: list[str] = []
    for match in _STRING_RE.finditer(code):
        raw = match.group(0)
        try:
            value = bytes(raw, "utf-8").decode("unicode_escape")[1:-1]
        except Exception:
            value = raw.strip('"')
        value = value.strip()
        if len(value) < 3:
            continue
        if value.endswith(".h"):
            continue
        out.append(value)
    return list(dict.fromkeys(out))


def extract_api_calls(code: str, *, skip_name: str = "") -> list[str]:
    """Ordered external-ish calls (best-effort regex; good enough for v0)."""
    calls: list[str] = []
    for name in _CALL_RE.findall(_strip_literals(code)):
        if skip_name and name == skip_name:
            continue
        if name in _SKIP_CALLS or (name and name[0].isupper() and name.isupper()):
            continue
        calls.append(name)
    return calls


def extract_param_types(signature_tail: str) -> list[str]:
    params: list[str] = []
    tail = signature_tail.strip()
    if not tail or tail == "void":
        return params

    for chunk in _PARAM_SPLIT_RE.split(tail):
        chunk = chunk.strip()
        if not chunk or chunk == "void":
            continue
        # Drop parameter name: "struct dhcp_packet *pkt" -> "struct dhcp_packet *"
        chunk = re.sub(r"\b[A-Za-z_]\w*\s*$", "", chunk).strip()
        chunk = re.sub(r"\s+", " ", chunk)
        if chunk:
            params.append(chunk)
    return params


def extract_function_features(code: str) -> dict:
    """
    Build a function fingerprint from one C translation unit.

    This is the atomic unit used later for:
    - gold extraction from source
    - pred extraction from pipeline output
    - function alignment (strings + api_calls)
    """
    func_name = first_function_name(code) or ""
    params: list[str] = []

    match = _FUNC_SIG_RE.search(code)
    if match:
        if not func_name:
            func_name = match.group(1)
        params = extract_param_types(match.group(2))

    api_calls = extract_api_calls(code, skip_name=func_name)
    return {
        "func_name": func_name,
        "params": params,
        "strings": extract_strings(code),
        "api_calls": api_calls,
        "api_multiset": dict(Counter(api_calls)),
        "placeholders": sorted(set(PLACEHOLDER_RE.findall(code))),
    }


def format_features(features: dict) -> str:
    lines = [
        f"func_name: {features.get('func_name') or '(none)'}",
        f"params: {features.get('params') or []}",
        f"strings ({len(features.get('strings') or [])}): {(features.get('strings') or [])[:5]}",
        f"api_calls: {features.get('api_calls') or []}",
    ]
    return "\n".join(lines)
