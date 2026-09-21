from __future__ import annotations

import re

_FUN_SYMBOL_RE = re.compile(r"^FUN_([0-9a-fA-F]+)$")


def normalize_address(value) -> str:
    if value is None:
        return ""
    if isinstance(value, int):
        return f"{value:08x}"
    text = str(value).strip().lower().removeprefix("0x")
    try:
        return f"{int(text, 16):08x}" if text else ""
    except ValueError:
        return ""


def fun_symbol_addr(symbol: str) -> str | None:
    match = _FUN_SYMBOL_RE.match(symbol)
    if not match:
        return None
    return normalize_address(match.group(1))


def addr_key(raw: str) -> str:
    text = raw.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    text = text.lstrip("0")
    return text or "0"
