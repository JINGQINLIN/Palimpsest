"""Struct registry / 结构体注册表。

SQLite-backed store of reconstructed struct layouts. Layouts are
offset-anchored: every field is keyed by its byte offset (ground truth from the
decompiler), so header generation can reproduce the exact memory layout with
padding. Fields are normalized and de-duplicated by offset.

基于 SQLite 的结构体布局存储，采用 offset-anchored（以字节偏移为锚）策略：
字段以偏移为准绳，据此可在生成头文件时用填充还原精确内存布局。
已知局限：同名 struct 跨函数的偏移可能不一致，当前无一致性校验（见 P2）。
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from pipeline.registry.store import SqliteStore

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")


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
        name = str(item.get("name") or "").strip()
        type_ = str(item.get("type") or "").strip()
        if offset < 0 or not _IDENT_RE.fullmatch(name) or not type_:
            continue
        try:
            size = int(item.get("size"))
        except (TypeError, ValueError):
            size = 0
        # offset-anchored：以字节偏移为键去重（同偏移后写覆盖先写），再按偏移升序输出
        by_offset[offset] = {"offset": offset, "name": name, "type": type_, "size": max(size, 0)}
    return [by_offset[off] for off in sorted(by_offset)]


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
    )
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
    ) -> None:
        # TODO(P2): 添加同名 struct 跨函数偏移一致性校验
        clean = normalize_fields(fields)
        if not _IDENT_RE.fullmatch(name or "") or not clean:
            return
        if confidence not in ("low", "medium", "high"):
            confidence = "medium"
        self._conn.execute(
            """INSERT OR REPLACE INTO structs
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

    def lookup(self, name: str) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM structs WHERE name = ?", (name,)).fetchone()
        return self._row_to_dict(row) if row else None

    def get_all(self) -> dict[str, dict]:
        rows = self._conn.execute("SELECT * FROM structs ORDER BY name").fetchall()
        return {row["name"]: self._row_to_dict(row) for row in rows}

    def delete(self, name: str) -> None:
        self._conn.execute("DELETE FROM structs WHERE name = ?", (name,))
        self._conn.commit()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["fields"] = json.loads(data["fields"])
        return data
