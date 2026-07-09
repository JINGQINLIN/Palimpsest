"""Naming registry / 命名注册表。

SQLite-backed table mapping Ghidra placeholders (FUN_/DAT_/LAB_/...) to
canonical names. Policy is first-come, first-served: a symbol's first accepted
name is treated as fixed for the run — later functions read it back (it is fed
into the prompt as a known symbol) rather than re-proposing it.

基于 SQLite 的符号表，将 Ghidra 占位符映射为规范名。策略为"先到先得"：
符号一旦被命名即视为固定，后续函数读取复用而非覆盖。
已知局限：update() 底层为 INSERT OR REPLACE，不做冲突审查（见 P2）。
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from pipeline.registry.store import SqliteStore

VALID_KINDS = ("function", "global_var", "constant")
PLACEHOLDER_RE = re.compile(r"\b(?:FUN|DAT|LAB|sub|byte|word|dword|qword)_[0-9a-fA-F]+\b")


class NamingRegistry(SqliteStore):
    _DDL = """
    CREATE TABLE IF NOT EXISTS symbols (
        symbol         TEXT PRIMARY KEY,
        kind           TEXT NOT NULL CHECK(kind IN ('function','global_var','constant')),
        canonical_name TEXT NOT NULL,
        inferred_type  TEXT NOT NULL DEFAULT '',
        confidence     TEXT NOT NULL CHECK(confidence IN ('low','medium','high')),
        evidence       TEXT NOT NULL DEFAULT '',
        source_file    TEXT NOT NULL DEFAULT '',
        value          TEXT NOT NULL DEFAULT '',
        updated_at     TEXT NOT NULL
    )
    """

    def update(
        self,
        *,
        symbol: str,
        canonical_name: str,
        confidence: str,
        evidence: str,
        kind: str = "function",
        inferred_type: str = "",
        source_file: str = "",
        value: str = "",
    ) -> None:
        # TODO(P2): 添加同一地址/偏移命名覆盖冲突检测
        if kind not in VALID_KINDS:
            raise ValueError(f"invalid kind {kind!r}")

        self._conn.execute(
            """INSERT OR REPLACE INTO symbols
               (symbol, kind, canonical_name, inferred_type, confidence, evidence, source_file, value, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                symbol,
                kind,
                canonical_name,
                inferred_type,
                confidence,
                evidence,
                source_file,
                value,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()

    def lookup(self, symbol: str) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM symbols WHERE symbol = ?", (symbol,)).fetchone()
        return dict(row) if row else None

    def get_all(self, kind: Optional[str] = None) -> dict[str, dict]:
        if kind is None:
            rows = self._conn.execute("SELECT * FROM symbols ORDER BY symbol").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM symbols WHERE kind = ? ORDER BY symbol",
                (kind,),
            ).fetchall()
        return {row["symbol"]: dict(row) for row in rows}
