"""Forward migration runner with down-migration support (ADR-M4-5).

Every migration is an ordered, immutable Python module exposing ``version``,
``name``, ``statements``, and optionally ``down_statements``. Applied versions
are recorded in ``_schema_migrations``; ``run_migrations`` applies pending ones
in a single transaction each and refuses out-of-order application
(testing-strategy §5). ``run_down_migrations`` reverses applied migrations
back to an older version in descending order — the mechanism ADR-M4-5's
"down-migration restores the baseline" acceptance relies on.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.errors import DomainError

if TYPE_CHECKING:
    from collections.abc import Sequence


class MigrationError(DomainError):
    """Migration machinery failure."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]
    down_statements: tuple[str, ...] = ()

    @property
    def migration_id(self) -> str:
        return f"{self.version:04d}_{self.name}"


def run_migrations(conn: sqlite3.Connection, migrations: Sequence[Migration]) -> list[str]:
    """Apply all pending migrations; returns ids applied this call."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS _schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        """)
    applied = {int(row[0]) for row in conn.execute("SELECT version FROM _schema_migrations")}
    applied_now: list[str] = []
    previous = -1
    for migration in migrations:
        if migration.version <= previous:
            raise MigrationError(
                f"migrations must be strictly increasing; got {migration.version} after {previous}"
            )
        previous = migration.version
        if migration.version in applied:
            continue
        try:
            # Schema changes may rebuild parent tables (e.g. extending a CHECK
            # constraint); FK enforcement blocks those DROP/RENAME steps, so it
            # is disabled per-migration and re-enabled afterwards. A migration
            # runs as the single writer with no concurrent readers, so this is
            # safe and matches the SQLite table-rebuild procedure.
            conn.execute("PRAGMA foreign_keys=OFF")
            with conn:
                for statement in migration.statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO _schema_migrations (version, name) VALUES (?, ?)",
                    (migration.version, migration.name),
                )
            conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error as exc:
            conn.execute("PRAGMA foreign_keys=ON")
            raise MigrationError(f"migration {migration.migration_id} failed: {exc}") from exc
        applied_now.append(migration.migration_id)
    return applied_now


def current_version(conn: sqlite3.Connection) -> int | None:
    """Latest applied schema version; None when database is fresh."""
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='_schema_migrations'"
    ).fetchone()
    if exists is None:
        return None
    row = conn.execute("SELECT MAX(version) FROM _schema_migrations").fetchone()
    return int(row[0]) if row and row[0] is not None else None


def run_down_migrations(
    conn: sqlite3.Connection,
    migrations: Sequence[Migration],
    target_version: int,
) -> list[str]:
    """Roll an upgraded schema back to ``target_version`` (ADR-M4-5).

    Applied migrations newer than ``target_version`` are reversed in descending
    order using their ``down_statements``; each reversal runs in its own
    transaction and the ``_schema_migrations`` row is deleted with it. A
    migration without a down path refuses to roll back rather than truncate
    history. Returns the migration ids reversed.
    """
    by_version = {m.version: m for m in migrations}
    applied = {
        int(row[0]): str(row[1])
        for row in conn.execute("SELECT version, name FROM _schema_migrations")
    }
    current = max(applied, default=-1)
    if current == -1:
        return []  # fresh database has nothing to roll back
    if target_version >= current:
        raise MigrationError(
            f"target version {target_version} is not below current schema {current}; "
            "nothing to roll back"
        )
    missing = set(applied) - set(by_version)
    if missing:
        raise MigrationError(
            f"database has applied migrations unknown to this store: {sorted(missing)}"
        )
    reversed_now: list[str] = []
    ordered = sorted(applied, reverse=True)
    for version in ordered:
        if version <= target_version:
            continue
        migration = by_version[version]
        if not migration.down_statements:
            raise MigrationError(
                f"migration {migration.migration_id} has no down path; "
                "refusing to truncate schema history"
            )
        try:
            conn.execute("PRAGMA foreign_keys=OFF")
            with conn:
                for statement in migration.down_statements:
                    conn.execute(statement)
                conn.execute(
                    "DELETE FROM _schema_migrations WHERE version = ?",
                    (version,),
                )
            conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error as exc:
            conn.execute("PRAGMA foreign_keys=ON")
            raise MigrationError(f"down-migration {migration.migration_id} failed: {exc}") from exc
        reversed_now.append(migration.migration_id)
    return reversed_now
