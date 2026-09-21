"""Naming registry: SQLite-backed table mapping Ghidra placeholders to canonical names.

Placeholders (FUN_/DAT_/LAB_/...) are mapped to canonical names. Policy is
first-come, first-served: a symbol's first accepted name is treated as fixed for
the run — later functions read it back (fed into the prompt as a known symbol)
rather than re-proposing it.

Conflict detection (v3):
- When update() detects that a symbol's canonical_name / kind / inferred_type /
  value differs from the existing baseline, the existing entry is kept and the
  incoming record is appended to conflicts_log.
- The main symbols table is never mutated with extra columns or candidate tables.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Optional

from pipeline.registry.store import SqliteStore

VALID_KINDS = ("function", "global_var", "constant")
PLACEHOLDER_RE = re.compile(r"\b(?:FUN|DAT|LAB|sub|byte|word|dword|qword)_[0-9a-fA-F]+\b")


def _symbol_compatible(existing: dict, incoming: dict) -> bool:
    """Check whether incoming is semantically equivalent to existing (only evidence/confidence/source_file may differ)."""
    return (
        existing.get("canonical_name") == incoming.get("canonical_name")
        and existing.get("kind") == incoming.get("kind")
        and existing.get("inferred_type") == incoming.get("inferred_type")
        and existing.get("value") == incoming.get("value")
    )


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
    );
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
    ) -> str:
        """Apply a naming update.

        On no conflict: insert or update the main table.
        On conflict: keep the existing record, append the incoming record to
        conflicts_log, and return "conflict".
        """
        if kind not in VALID_KINDS:
            raise ValueError(f"invalid kind {kind!r}")

        incoming_snapshot = {
            "symbol": symbol,
            "kind": kind,
            "canonical_name": canonical_name,
            "inferred_type": inferred_type,
            "confidence": confidence,
            "evidence": evidence,
            "source_file": source_file,
            "value": value,
        }

        existing = self.lookup(symbol)
        if existing is None:
            self._conn.execute(
                """INSERT INTO symbols
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
            return "inserted"

        if _symbol_compatible(existing, incoming_snapshot):
            # Semantically equivalent: refresh metadata only (confidence, evidence, source)
            self._conn.execute(
                """UPDATE symbols
                   SET confidence = ?, evidence = ?, source_file = ?, updated_at = ?
                   WHERE symbol = ?""",
                (
                    confidence,
                    evidence,
                    source_file,
                    datetime.now(timezone.utc).isoformat(),
                    symbol,
                ),
            )
            self._conn.commit()
            return "updated"

        # Conflict: keep the existing baseline, write incoming to conflicts_log
        self._conn.execute(
            """INSERT INTO conflicts_log
               (category, name, existing, incoming, source_file, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                "naming",
                symbol,
                json.dumps(existing, ensure_ascii=False),
                json.dumps(incoming_snapshot, ensure_ascii=False),
                source_file,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
        return "conflict"

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

    def get_conflict_count(self) -> int:
        """Return the number of naming-category entries in conflicts_log."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS cnt FROM conflicts_log WHERE category = ?", ("naming",)
        ).fetchone()
        return row["cnt"] if row else 0
