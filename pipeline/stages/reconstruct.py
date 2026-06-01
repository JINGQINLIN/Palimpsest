from __future__ import annotations

import json
import re
from typing import Any

from pipeline.llm import LLMClient, TokenUsage
from pipeline.prompts import PromptManager
from pipeline.registry import (
    PLACEHOLDER_RE,
    VALID_KINDS,
    NamingRegistry,
    StructRegistry,
    normalize_fields,
)

_FENCE_RE = re.compile(r"\A\s*```[a-zA-Z0-9_+-]*\s*\n(.*?)\n?```\s*\Z", re.DOTALL)
_KNOWN_TAGS = ("structured", "struct_updates", "named", "naming_map", "registry_updates")
_NEXT_TAG_RE = re.compile(r"<(?:" + "|".join(_KNOWN_TAGS) + r")>")
_MAX_TOKENS = 16384


def prefetch(code: str, registry: NamingRegistry) -> tuple[dict[str, dict], list[str]]:
    symbols = list(dict.fromkeys(PLACEHOLDER_RE.findall(code)))
    known: dict[str, dict] = {}
    unknown: list[str] = []

    for symbol in symbols:
        entry = registry.lookup(symbol)
        if entry:
            known[symbol] = entry
        else:
            unknown.append(symbol)
    return known, unknown


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


def _format_known_structs(structs: dict[str, dict]) -> str:
    if not structs:
        return ""
    lines = []
    for name, entry in sorted(structs.items()):
        fields = "; ".join(
            f"+0x{f['offset']:x} {f['name']} {f['type']}" for f in entry.get("fields", [])
        )
        lines.append(f"struct {name} (size 0x{entry.get('size', 0):x}): {fields}")
    return "\n".join(lines)


def _parse_structure_output(text: str) -> tuple[str, list[dict[str, Any]]]:
    structured = _strip_fence(_extract_block(text, "structured")) or _strip_fence(text)
    updates = _parse_json_list(_extract_block(text, "struct_updates"))
    return structured, updates


def _apply_struct_updates(
    struct_registry: StructRegistry,
    updates: list[dict[str, Any]],
    source_file: str,
) -> list[dict[str, Any]]:
    applied = []
    for item in updates:
        name = str(item.get("name") or "").strip()
        fields = normalize_fields(item.get("fields"))
        if not name or not fields:
            continue
        try:
            size = int(item.get("size"))
        except (TypeError, ValueError):
            size = 0
        confidence = str(item.get("confidence") or "medium").strip()
        evidence = str(item.get("evidence") or "").strip()
        struct_registry.update(
            name=name,
            fields=fields,
            size=size,
            confidence=confidence,
            evidence=evidence,
            source_file=source_file,
        )
        applied.append({"name": name, "size": size, "confidence": confidence, "fields": fields})
    return applied


def _format_known_symbols(known: dict[str, dict]) -> str:
    if not known:
        return "(none)"

    lines = []
    for symbol, entry in sorted(known.items()):
        type_part = f" :: {entry['inferred_type']}" if entry.get("inferred_type") else ""
        lines.append(
            f"{symbol} -> {entry['canonical_name']}{type_part} "
            f"[{entry['kind']}, {entry['confidence']}] # {entry['evidence']}"
        )
    return "\n".join(lines)


def _parse_naming_output(text: str) -> tuple[str, str, list[dict[str, Any]]]:
    named = _strip_fence(_extract_block(text, "named"))
    naming_map = _extract_block(text, "naming_map")
    updates = _parse_json_list(_extract_block(text, "registry_updates"))
    return named, naming_map, updates


def _apply_registry_updates(
    registry: NamingRegistry,
    updates: list[dict[str, Any]],
    source_file: str,
) -> list[dict[str, Any]]:
    applied = []

    for item in updates:
        symbol = str(item.get("symbol") or "").strip()
        canonical = str(item.get("canonical_name") or "").strip()
        kind = str(item.get("kind") or "function").strip()
        confidence = str(item.get("confidence") or "").strip()
        evidence = str(item.get("evidence") or "").strip()
        inferred_type = str(item.get("inferred_type") or "").strip()

        if not symbol or not canonical:
            continue
        if kind not in VALID_KINDS or confidence not in {"medium", "high"}:
            continue

        registry.update(
            symbol=symbol,
            canonical_name=canonical,
            confidence=confidence,
            evidence=evidence,
            kind=kind,
            inferred_type=inferred_type,
            source_file=source_file,
        )
        applied.append(
            {
                "symbol": symbol,
                "canonical_name": canonical,
                "kind": kind,
                "confidence": confidence,
                "inferred_type": inferred_type,
                "evidence": evidence,
            }
        )

    return applied


def process_function(
    *,
    binary_name: str,
    address: int,
    ghidra_name: str,
    raw_decompile: str,
    known_symbols: dict[str, dict],
    unknown_symbols: list[str],
    registry: NamingRegistry,
    struct_registry: StructRegistry,
    llm: LLMClient,
    domain_context: str,
) -> dict:
    prompts = PromptManager()
    usage = TokenUsage()

    structure_prompt = prompts.load(
        "structure.jinja2",
        binary_name=binary_name,
        address=f"0x{address:x}",
        domain_context=domain_context,
        raw_decompile=raw_decompile,
        known_structs=_format_known_structs(struct_registry.get_all()),
    )
    structure_text, step_usage = llm.complete(structure_prompt, max_tokens=_MAX_TOKENS)
    usage.merge(step_usage)
    structured, struct_updates = _parse_structure_output(structure_text)
    if not structured:
        raise ValueError("LLM structure step returned empty output")
    applied_structs = _apply_struct_updates(struct_registry, struct_updates, source_file=binary_name)

    naming_prompt = prompts.load(
        "naming.jinja2",
        binary_name=binary_name,
        address=f"0x{address:x}",
        ghidra_symbol=ghidra_name,
        domain_context=domain_context,
        structured_code=structured,
        known_symbols=_format_known_symbols(known_symbols),
        unknown_symbols=", ".join(unknown_symbols) if unknown_symbols else "(none)",
    )
    naming_text, step_usage = llm.complete(naming_prompt, max_tokens=_MAX_TOKENS)
    usage.merge(step_usage)

    named, naming_map, updates = _parse_naming_output(naming_text)
    named = named or structured
    applied = _apply_registry_updates(registry, updates, source_file=binary_name)

    return {
        "raw": raw_decompile,
        "structured": structured,
        "named": named,
        "naming_map": naming_map,
        "registry_updates": applied,
        "struct_updates": applied_structs,
        "usage": usage,
    }
