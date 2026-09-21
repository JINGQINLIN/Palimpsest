"""Shared SQLite store base for the naming and struct registries.

Common connection setup and teardown; each subclass declares its own table schema
via the class attribute _DDL, while the shared conflicts_log table is provided
here so both registries use an identical conflict-tracking schema.

Thread safety:
    SQLite connections are not safe to share across threads even with
    ``check_same_thread=False`` — that flag only silences Python's own
    thread-assertion; concurrent ``execute()``/``commit()`` calls on a single
    connection can still interleave and corrupt internal statement state,
    raising ``sqlite3.ProgrammingError`` or producing torn writes.

    To support the 32-way concurrent reconstruction workers (and the 4-way
    Multi-Agent review phase), each thread gets its own connection via
    ``threading.local()``. WAL journal mode plus a ``busy_timeout`` allow
    readers and a writer to coexist without ``database is locked`` errors
    under the bursty write patterns the registry sees.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path


class SqliteStore:
    """Open a SQLite connection and apply the shared + subclass-defined schema.

    _SHARED_DDL creates the conflicts_log table used by all subclasses for
    recording conflict entries. Each subclass's _DDL creates its own primary table.

    A per-thread connection is created lazily on first access via the
    ``_conn`` property; all subclass code that uses ``self._conn``
    transparently gets the current thread's connection.
    """

    # conflicts_log: shared conflict-tracking schema used by NamingRegistry and StructRegistry.
    _SHARED_DDL = """
    CREATE TABLE IF NOT EXISTS conflicts_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        category    TEXT NOT NULL,
        name        TEXT NOT NULL,
        existing    TEXT NOT NULL DEFAULT '',
        incoming    TEXT NOT NULL DEFAULT '',
        source_file TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_conflicts_category_name ON conflicts_log(category, name);
    """

    _DDL = ""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Per-thread connection storage. Each thread lazily creates its own
        # connection on first use; see the _conn property below.
        self._tls = threading.local()
        # Eagerly initialise the main-thread connection so that:
        #   (a) schema creation runs up-front once, and
        #   (b) any path/permission errors surface immediately at construction
        #       rather than on the first concurrent worker call.
        self._tls.conn = self._new_conn()

    def _new_conn(self) -> sqlite3.Connection:
        """Create a fresh connection configured for concurrent use.

        - ``check_same_thread=False`` is retained so the connection can be
          created on the main thread and used on a worker thread (only the
          thread that ends up using it ever touches it, thanks to _tls).
        - ``WAL`` journal mode lets readers proceed alongside a writer; this
          is the recommended mode for read/write concurrency in SQLite and
          is stored persistently on the database file.
        - ``busy_timeout=5000`` makes writers wait up to 5s for a lock
          instead of failing immediately with ``database is locked``.
        - The DDL is re-run on every new connection because CREATE IF NOT
          EXISTS is idempotent; this guarantees every thread's connection
          sees the same schema without relying on cross-connection schema
          caching.
        """
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(self._SHARED_DDL + self._DDL)
        conn.commit()
        return conn

    @property
    def _conn(self) -> sqlite3.Connection:
        """Return the calling thread's connection, creating one on first use."""
        conn = getattr(self._tls, "conn", None)
        if conn is None:
            conn = self._new_conn()
            self._tls.conn = conn
        return conn

    def close(self) -> None:
        """Close the calling thread's connection, if any.

        Other threads' connections are not reachable from here; callers that
        spin up worker threads are responsible for calling ``close()`` from
        within those threads, or letting the thread exit (which lets the
        connection be garbage-collected). The main-thread connection is
        always closed.
        """
        conn = getattr(self._tls, "conn", None)
        if conn is not None:
            conn.close()
            self._tls.conn = None
