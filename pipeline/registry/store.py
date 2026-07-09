"""Shared SQLite store base / SQLite 存储基类。

Common connection setup and teardown for the naming and struct registries;
each subclass only declares its schema via the class attribute _DDL.

命名表与结构体表共用的 SQLite 连接/建表/关闭样板，子类只需声明各自的 _DDL。
"""
from __future__ import annotations

import sqlite3
from pathlib import Path


class SqliteStore:
    """Open a SQLite connection and apply the subclass-defined `_DDL` schema."""

    _DDL = ""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(self._DDL)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
