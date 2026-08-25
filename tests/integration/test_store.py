"""Migration runner + store pragmas (integration-tier, real SQLite)."""

import sqlite3
from pathlib import Path

import pytest

from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.migrator import (
    Migration,
    MigrationError,
    current_version,
    run_migrations,
)
from mayhem.infra.store import Store


class TestMigrator:
    def test_fresh_database_reaches_head(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "tg.db")
        assert store.schema_version == ALL_MIGRATIONS[-1].version
        store.close()

    def test_idempotent(self, tmp_path: Path) -> None:
        path = tmp_path / "tg.db"
        first = Store.open_migrated(path)
        second = Store.open_migrated(path)
        assert current_version(second._conn) == ALL_MIGRATIONS[-1].version
        assert run_migrations(first._conn, ALL_MIGRATIONS) == []
        first.close()
        second.close()

    def test_out_of_order_refused(self) -> None:
        conn = sqlite3.connect(":memory:")
        bad: tuple[Migration, ...] = (
            Migration(version=2, name="b", statements=()),
            Migration(version=1, name="a", statements=()),
        )
        with pytest.raises(MigrationError, match="strictly increasing"):
            run_migrations(conn, bad)

    def test_all_canonical_tables_exist(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "tg.db")
        names = {
            row["name"] for row in store.query("SELECT name FROM sqlite_master WHERE type='table'")
        }
        expected = {
            "config_snapshots",
            "topology_snapshots",
            "runs",
            "step_runs",
            "fault_leases",
            "fault_invocations",
            "recovery_records",
            "tool_runs",
            "agent_states",
            "events",
            "steady_state_evaluations",
            "maniac_decisions",
            "_schema_migrations",
        }
        assert expected <= names
        store.close()

    def test_wal_mode_active(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "tg.db")
        mode = store.query("PRAGMA journal_mode")[0][0]
        assert str(mode).lower() == "wal"
        store.close()

    def test_foreign_keys_enforced(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "tg.db")
        with pytest.raises(sqlite3.IntegrityError):
            with store.write() as conn:
                conn.execute(
                    "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json,"
                    " status, environment_fingerprint, config_snapshot_id)"
                    " VALUES ('r-1','x','deterministic','{}','{}','created','fp','nope')"
                )
        store.close()
