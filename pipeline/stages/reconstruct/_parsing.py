"""Parsing helpers for LLM phase outputs (fenced code blocks and tagged sections)."""
from __future__ import annotations

import json
import re
from typing import Any

from pipeline.registry import normalize_offset_field_names

# Match a markdown fenced block wrapping the whole string.
# Example:  "```c\nint main() {}\n```"  ->  captures "int main() {}"
_FENCE_RE = re.compile(r"\A\s*```[a-zA-Z0-9_+-]*\s*\n(.*?)\n?```\s*\Z", re.DOTALL)

# Tags the LLM may emit to delimit structured sections of its reply.
_KNOWN_TAGS = ("structured", "struct_updates", "named", "naming_map", "registry_updates", "skip")
_NEXT_TAG_RE = re.compile(r"<(?:" + "|".join(_KNOWN_TAGS) + r")>")


def _strip_fence(text: str) -> str:
    text = text.strip()
    match = _FENCE_RE.match(text)
    return match.group(1).strip() if match else text


def _extract_block(text: str, tag: str) -> str:
    closed = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.DOTALL)
    if closed:
        return closed.group(1).strip()
    opened = re.search(rf"<{tag}>(.*)", text, re.DOTALL)
    if not opened:
        return ""
    body = opened.group(1)
    nxt = _NEXT_TAG_RE.search(body)
    return (body[: nxt.start()] if nxt else body).strip()


def _parse_json_list(raw: str) -> list[dict[str, Any]]:
    raw = _strip_fence(raw)
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []


def _parse_structure_output(text: str) -> tuple[str, list[dict[str, Any]], str]:
    structured = normalize_offset_field_names(_strip_fence(_extract_block(text, "structured")))
    if not structured:
        skip_reason = _extract_block(text, "skip")
        if skip_reason:
            return "", [], skip_reason
        structured = normalize_offset_field_names(_strip_fence(text))
    updates = _parse_json_list(_extract_block(text, "struct_updates"))
    return structured, updates, ""


def _parse_naming_output(text: str) -> tuple[str, str, list[dict[str, Any]]]:
    named = normalize_offset_field_names(_strip_fence(_extract_block(text, "named")))
    naming_map = _extract_block(text, "naming_map")
    updates = _parse_json_list(_extract_block(text, "registry_updates"))
    return named, naming_map, updates
