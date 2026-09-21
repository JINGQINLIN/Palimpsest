from __future__ import annotations

import re


def reconstruction_errors(original: str, candidate: str) -> list[str]:
    """Catch two concrete output regressions; this is not a C/ABI validator."""
    non_code = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*', re.S)
    before, after = (non_code.sub(" ", text) for text in (original, candidate))

    def balanced(text: str) -> bool:
        stack: list[str] = []
        pairs = {")": "(", "]": "[", "}": "{"}
        for char in text:
            if char in "([{":
                stack.append(char)
            elif char in pairs:
                if not stack or stack.pop() != pairs[char]:
                    return False
        return not stack

    errors = []
    if balanced(before) and not balanced(after):
        errors.append("Candidate introduced unmatched parentheses, brackets or braces; restore the original grouping.")
    arrays = set(re.findall(r"\b[A-Za-z_]\w*\s+([A-Za-z_]\w*)\s*\[\s*(?:0x[0-9a-fA-F]+|\d+)\s*\]\s*;", before))
    pointers = set(re.findall(
        r"(?:^|[;{}])\s*(?!(?:return|goto)\b)(?:[A-Za-z_]\w*\s+)+\*+\s*([A-Za-z_]\w*)\s*(?=[=;])",
        after, re.M,
    ))
    for name in sorted(arrays & pointers):
        errors.append(f"Local array {name} became a pointer variable; preserve its inline storage and call arguments.")
    return errors

# Group 1: return-type base words; group 2: "*"s or whitespace; group 3: name; group 4: params.
# Pointer stars must stay in the return type — dropping them turns `void *` into `void`
# and breaks cross-TU CodeQL dataflow via recopilot_decls.h.
FUNC_DEF_RE = re.compile(
    r"(?m)^\s*"
    r"([A-Za-z_][\w\s]*?)"
    r"((?:\s*\*+\s*)|\s+)"
    r"([A-Za-z_]\w*)"
    r"\s*\(([^;{}]*)\)\s*\{"
)
INDIRECT_CALL_RE = re.compile(
    r"\(\s*\*[^)]*\)\s*\(|"  # (*fn)(args)
    r"\[[^\]]+\]\s*\(|"  # table[i](args)
    r"\)\s*\([^;]*\)"  # expr)(args) — often vtable / cast call
)


def _normalize_return_type(base: str, stars_or_ws: str) -> str:
    base = " ".join(base.split())
    star_count = stars_or_ws.count("*")
    if star_count:
        return f"{base} {'*' * star_count}"
    return base


def first_function_name(code: str) -> str | None:
    match = FUNC_DEF_RE.search(code)
    return match.group(3) if match else None


def parse_function_definition(code: str) -> dict | None:
    """Extract return type, name, params, and signature line from the first function."""
    match = FUNC_DEF_RE.search(code)
    if not match:
        return None

    return_type = _normalize_return_type(match.group(1), match.group(2))
    name = match.group(3)
    params_raw = match.group(4).strip()
    params = _split_params(params_raw)
    signature = f"{return_type} {name}({params_raw})"
    return {
        "name": name,
        "return_type": return_type,
        "params": params,
        "signature": signature,
    }


def apply_local_renames(code: str, naming_map: str) -> tuple[str, str]:
    """Apply a local naming table simultaneously, preserving all C operations."""
    lexer = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*|\b[A-Za-z_]\w*\b', re.S)
    clean = lexer.sub(lambda m: " " * len(m[0]) if m[0].startswith(('"', "'", '/*', '//')) else m[0], code)
    signature = parse_function_definition(clean) or {}
    declared = set()
    for param in signature.get("params", []):
        match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?$", param)
        if match:
            declared.add(match[1])
    declared.update(re.findall(
        r"(?:^|[;{}])\s*(?!(?:return|goto)\b)(?:[A-Za-z_]\w*\s+)+\**\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?=[;=])",
        clean, re.M,
    ))
    occupied = set(re.findall(r"\b[A-Za-z_]\w*\b", clean))
    reserved = set("auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Bool _Complex _Imaginary _Atomic _Alignas _Alignof _Generic _Noreturn _Static_assert _Thread_local".split())
    renames: dict[str, str] = {}
    log: list[str] = []
    for line in naming_map.splitlines():
        match = re.match(r"\s*([A-Za-z_]\w*)\s*(?:->|→)\s*([A-Za-z_]\w*)\s*(?:\||$)", line)
        if not match:
            continue
        old, new = match.groups()
        if old not in declared or new in reserved or (new in occupied and new != old) or new in renames.values() or old in renames:
            log.append(f"# skipped unsupported or colliding rename: {old} -> {new}")
            continue
        renames[old] = new
        log.append(line.strip())

    def replace(match: re.Match[str]) -> str:
        word = match[0]
        if word not in renames:
            return word
        prefix = clean[:match.start()].rstrip()
        if prefix.endswith(("->", ".")) or re.search(r"\b(?:struct|union|enum|goto)\s*$", prefix):
            return word
        return renames[word]

    return lexer.sub(replace, code), "\n".join(log)


_CODE_TOKEN_LEXER = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*|\b[A-Za-z_]\w*\b',
    re.S,
)


def _replace_code_tokens(code: str, replacements: dict[str, str]) -> str:
    """Replace identifiers/types outside strings and comments."""
    if not replacements:
        return code

    def replace(match: re.Match[str]) -> str:
        word = match[0]
        if word.startswith(('"', "'", "/*", "//")):
            return word
        return replacements.get(word, word)

    return _CODE_TOKEN_LEXER.sub(replace, code)


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
