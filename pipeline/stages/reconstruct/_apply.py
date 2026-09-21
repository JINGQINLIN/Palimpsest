"""Apply LLM-produced updates to the struct and naming registries."""
from __future__ import annotations

from typing import Any

from pipeline.registry import (
    PLACEHOLDER_RE,
    VALID_KINDS,
    NamingRegistry,
    StructRegistry,
    normalize_fields,
)


def _apply_struct_updates(
    struct_registry: StructRegistry,
    updates: list[dict[str, Any]],
    source_file: str,
) -> list[dict[str, Any]]:
    """Apply struct updates; return the list of applied entries."""
    applied: list[dict[str, Any]] = []
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
        status = struct_registry.update(
            name=name,
            fields=fields,
            size=size,
            confidence=confidence,
            evidence=evidence,
            source_file=source_file,
        )
        if status in {"inserted", "updated", "merged"}:
            applied.append(
                {
                    "name": name,
                    "size": size,
                    "confidence": confidence,
                    "fields": fields,
                    "status": status,
                }
            )
    return applied


def _apply_registry_updates(
    registry: NamingRegistry,
    updates: list[dict[str, Any]],
    source_file: str,
) -> list[dict[str, Any]]:
    """Apply naming updates; return the list of applied entries."""
    applied: list[dict[str, Any]] = []

    for item in updates:
        symbol = str(item.get("symbol") or "").strip()
        canonical = str(item.get("canonical_name") or "").strip()
        kind = str(item.get("kind") or "function").strip()
        confidence = str(item.get("confidence") or "").strip()
        evidence = str(item.get("evidence") or "").strip()
        inferred_type = str(item.get("inferred_type") or "").strip()
        value = str(item.get("value") or "").strip()

        if not symbol or not canonical:
            continue
        if kind not in VALID_KINDS or confidence not in {"medium", "high"}:
            continue
        if PLACEHOLDER_RE.fullmatch(canonical):
            continue

        registry.update(
            symbol=symbol,
            canonical_name=canonical,
            confidence=confidence,
            evidence=evidence,
            kind=kind,
            inferred_type=inferred_type,
            source_file=source_file,
            value=value,
        )
        applied.append(
            {
                "symbol": symbol,
                "canonical_name": canonical,
                "kind": kind,
                "confidence": confidence,
                "inferred_type": inferred_type,
                "evidence": evidence,
                "value": value,
            }
        )

    return applied
