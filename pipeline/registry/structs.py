"""Struct registry: SQLite-backed store of reconstructed struct layouts.

Layouts are offset-anchored: every field is keyed by its byte offset (ground
truth from the decompiler), so header generation can reproduce the exact memory
layout with padding. Fields are normalized and de-duplicated by offset.

Conflict detection (v3):
- Structs are offset-anchored. A later update may fill previously unknown
  offsets or replace a neutral field_XX name when the offset and storage type
  remain identical; arbitrary same-offset changes are rejected.
- When update() detects an incompatible field layout for an existing struct
  name, the existing entry is kept and the incoming record is appended to
  conflicts_log.
- The main structs table is never mutated with extra columns or candidate
  tables.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from pipeline.registry.store import SqliteStore

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_OFFSET_FIELD_RE = re.compile(r"field_(?:0[xX])?([0-9A-Fa-f]+)$")


def normalize_offset_field_name(name: str) -> str:
    """Return the canonical spelling for generated offset-placeholder fields."""
    match = _OFFSET_FIELD_RE.fullmatch(name)
    if match:
        return f"field_{int(match.group(1), 16):x}"
    return name


def normalize_offset_field_names(text: str) -> str:
    """Canonicalize generated offset-placeholder field names in source text."""
    return re.sub(
        r"\bfield_0[xX]([0-9A-Fa-f]+)\b",
        lambda m: f"field_{int(m.group(1), 16):x}",
        text or "",
    )


def normalize_fields(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    by_offset: dict[int, dict] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            offset = int(item.get("offset"))
        except (TypeError, ValueError):
            continue
        name = normalize_offset_field_name(str(item.get("name") or "").strip())
        type_ = str(item.get("type") or "").strip()
        if offset < 0 or not _IDENT_RE.fullmatch(name) or not type_:
            continue
        try:
            size = int(item.get("size"))
        except (TypeError, ValueError):
            size = 0
        # offset-anchored: dedup by byte offset (last write wins), output sorted by offset
        by_offset[offset] = {"offset": offset, "name": name, "type": type_, "size": max(size, 0)}
    return [by_offset[off] for off in sorted(by_offset)]


def _fields_compatible(existing_fields: list[dict], incoming_fields: list[dict]) -> bool:
    """Return true when two layouts describe the same known fields exactly."""
    existing_by_offset: dict[int, dict] = {f["offset"]: f for f in existing_fields}
    incoming_by_offset: dict[int, dict] = {f["offset"]: f for f in incoming_fields}
    if set(existing_by_offset) != set(incoming_by_offset):
        return False
    for off, ef in existing_by_offset.items():
        inf = incoming_by_offset[off]
        if ef.get("name") != inf.get("name") or ef.get("type") != inf.get("type"):
            return False
    return True


def _field_span(field: dict) -> tuple[int, int]:
    offset = int(field.get("offset") or 0)
    try:
        size = int(field.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    return offset, offset + max(size, 1)


def _overlaps(left: dict, right: dict) -> bool:
    left_start, left_end = _field_span(left)
    right_start, right_end = _field_span(right)
    return left_start < right_end and right_start < left_end


def _same_anchored_field(existing: dict, incoming: dict) -> bool:
    return (
        existing.get("name") == incoming.get("name")
        and existing.get("type") == incoming.get("type")
    )


def _placeholder_offset(name: object) -> int | None:
    """Return the encoded offset for a neutral field_XX placeholder."""
    match = _OFFSET_FIELD_RE.fullmatch(str(name or "").strip())
    return int(match.group(1), 16) if match else None


def _mergeable_fields(existing_fields: list[dict], incoming_fields: list[dict]) -> bool:
    """Return true if incoming only fills holes in the existing layout.

    The merge is deliberately conservative. Same-offset fields must already
    agree on type; only a neutral field_XX name may be upgraded, and newly-added fields must not overlap an existing
    byte range, and a non-padding field name may not be reused at a different
    offset.  This lets independent functions extend a shared struct while
    preserving C buildability and earlier generated code.
    """
    existing_by_offset: dict[int, dict] = {f["offset"]: f for f in existing_fields}
    existing_name_offsets: dict[str, int] = {
        str(f.get("name")): int(f.get("offset") or 0)
        for f in existing_fields
        if str(f.get("name") or "").strip() and not str(f.get("name")).startswith("_pad")
    }

    for incoming in incoming_fields:
        off = incoming["offset"]
        existing = existing_by_offset.get(off)
        if existing is not None:
            same_type = existing.get("type") == incoming.get("type")
            placeholder_upgrade = (
                same_type
                and _placeholder_offset(existing.get("name")) == off
                and _placeholder_offset(incoming.get("name")) is None
            )
            if not _same_anchored_field(existing, incoming) and not placeholder_upgrade:
                return False
            continue

        name = str(incoming.get("name") or "").strip()
        if name and not name.startswith("_pad"):
            used_offset = existing_name_offsets.get(name)
            if used_offset is not None and used_offset != off:
                return False

        for existing in existing_fields:
            if _overlaps(existing, incoming):
                return False

    return True


def _merge_fields(existing_fields: list[dict], incoming_fields: list[dict]) -> list[dict]:
    merged: dict[int, dict] = {f["offset"]: dict(f) for f in existing_fields}
    for field in incoming_fields:
        current = merged.get(field["offset"])
        if current is None:
            merged[field["offset"]] = dict(field)
        elif (
            _placeholder_offset(current.get("name")) == field["offset"]
            and _placeholder_offset(field.get("name")) is None
            and current.get("type") == field.get("type")
        ):
            merged[field["offset"]] = dict(field)
    return [merged[off] for off in sorted(merged)]


def _field_end(fields: list[dict]) -> int:
    return max((_field_span(field)[1] for field in fields), default=0)


def _stronger_confidence(left: str, right: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return left if order.get(left, 1) >= order.get(right, 1) else right


def _combine_evidence(existing: str, incoming: str) -> str:
    existing = (existing or "").strip()
    incoming = (incoming or "").strip()
    if not existing:
        return incoming
    if not incoming or incoming in existing:
        return existing
    combined = f"{existing}\nMerged compatible fields: {incoming}"
    return combined[:4000]


class StructRegistry(SqliteStore):
    _DDL = """
    CREATE TABLE IF NOT EXISTS structs (
        name        TEXT PRIMARY KEY,
        fields      TEXT NOT NULL,
        size        INTEGER NOT NULL DEFAULT 0,
        confidence  TEXT NOT NULL CHECK(confidence IN ('low','medium','high')),
        evidence    TEXT NOT NULL DEFAULT '',
        source_file TEXT NOT NULL DEFAULT '',
        updated_at  TEXT NOT NULL
    );
    """

    def update(
        self,
        *,
        name: str,
        fields: list[dict],
        size: int = 0,
        confidence: str = "medium",
        evidence: str = "",
        source_file: str = "",
    ) -> str:
        """Apply a struct update.

        On no conflict: insert or update the main table.
        On conflict: keep the existing record, append the incoming record to
        conflicts_log, and return "conflict".
        """
        clean = normalize_fields(fields)
        if not _IDENT_RE.fullmatch(name or "") or not clean:
            return "rejected"
        if confidence not in ("low", "medium", "high"):
            confidence = "medium"

        existing = self.lookup(name)
        incoming_snapshot = {
            "name": name,
            "fields": clean,
            "size": int(size or 0),
            "confidence": confidence,
            "evidence": evidence,
            "source_file": source_file,
        }

        if existing is None:
            self._conn.execute(
                """INSERT INTO structs
                   (name, fields, size, confidence, evidence, source_file, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    name,
                    json.dumps(clean, ensure_ascii=False),
                    int(size or 0),
                    confidence,
                    evidence,
                    source_file,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()
            return "inserted"

        existing_fields = existing.get("fields", [])
        if _fields_compatible(existing_fields, clean):
            # Compatible: treat as metadata refresh for the same layout, overwrite with latest
            self._conn.execute(
                """UPDATE structs
                   SET fields = ?, size = ?, confidence = ?, evidence = ?,
                       source_file = ?, updated_at = ?
                   WHERE name = ?""",
                (
                    json.dumps(clean, ensure_ascii=False),
                    int(size or 0),
                    confidence,
                    evidence,
                    source_file,
                    datetime.now(timezone.utc).isoformat(),
                    name,
                ),
            )
            self._conn.commit()
            return "updated"

        if _mergeable_fields(existing_fields, clean):
            merged_fields = _merge_fields(existing_fields, clean)
            merged_size = max(
                int(existing.get("size") or 0),
                int(size or 0),
                _field_end(merged_fields),
            )
            merged_confidence = _stronger_confidence(
                str(existing.get("confidence") or "medium"),
                confidence,
            )
            merged_evidence = _combine_evidence(str(existing.get("evidence") or ""), evidence)
            self._conn.execute(
                """UPDATE structs
                   SET fields = ?, size = ?, confidence = ?, evidence = ?,
                       source_file = ?, updated_at = ?
                   WHERE name = ?""",
                (
                    json.dumps(merged_fields, ensure_ascii=False),
                    merged_size,
                    merged_confidence,
                    merged_evidence,
                    source_file or str(existing.get("source_file") or ""),
                    datetime.now(timezone.utc).isoformat(),
                    name,
                ),
            )
            self._conn.commit()
            return "merged"

        # Conflict: keep the existing baseline, write incoming to conflicts_log
        self._conn.execute(
            """INSERT INTO conflicts_log
               (category, name, existing, incoming, source_file, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                "struct",
                name,
                json.dumps(existing, ensure_ascii=False),
                json.dumps(incoming_snapshot, ensure_ascii=False),
                source_file,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
        return "conflict"

    def lookup(self, name: str) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM structs WHERE name = ?", (name,)).fetchone()
        return self._row_to_dict(row) if row else None

    def get_all(self) -> dict[str, dict]:
        rows = self._conn.execute("SELECT * FROM structs ORDER BY name").fetchall()
        return {row["name"]: self._row_to_dict(row) for row in rows}

    def delete(self, name: str) -> None:
        self._conn.execute("DELETE FROM structs WHERE name = ?", (name,))
        self._conn.commit()

    def get_conflict_count(self) -> int:
        """Return the number of struct-category entries in conflicts_log."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS cnt FROM conflicts_log WHERE category = ?", ("struct",)
        ).fetchone()
        return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["fields"] = json.loads(data["fields"])
        return data
