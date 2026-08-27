"""SQLite store: one connection, WAL, disciplined pragmas (ADR-0007).

The controller is the single writer. Agents never open this file.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.migrator import Migration, current_version, run_migrations

if TYPE_CHECKING:
    from collections.abc import Iterator

_BUSY_TIMEOUT_MS = 5_000


class Store:
    """Owns the SQLite connection and migration lifecycle."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # One connection shared across threads (parallel fault execution, ADR-0022).
        # Access is serialized by ``_lock``; WAL + busy_timeout handle cross-process writers.
        self._conn = sqlite3.connect(
            self._path, timeout=_BUSY_TIMEOUT_MS / 1000, check_same_thread=False
        )
        self._lock = threading.RLock()
        self._conn.row_factory = sqlite3.Row
        for pragma in (
            "PRAGMA journal_mode=WAL",
            f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}",
            "PRAGMA foreign_keys=ON",
            "PRAGMA synchronous=NORMAL",
        ):
            self._conn.execute(pragma)

    @classmethod
    def open_migrated(
        cls, path: Path | str, migrations: tuple[Migration, ...] = ALL_MIGRATIONS
    ) -> Store:
        store = cls(path)
        store.migrate(migrations)
        return store

    def migrate(self, migrations: tuple[Migration, ...] = ALL_MIGRATIONS) -> list[str]:
        with self._lock:
            return run_migrations(self._conn, migrations)

    @property
    def schema_version(self) -> int | None:
        with self._lock:
            return current_version(self._conn)

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """Single-writer transaction boundary; commits or rolls back atomically."""
        try:
            with self._lock, self._conn:
                yield self._conn
        except sqlite3.Error:
            raise

    def query(self, sql: str, params: tuple[object, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params))

    def close(self) -> None:
        self._conn.close()
