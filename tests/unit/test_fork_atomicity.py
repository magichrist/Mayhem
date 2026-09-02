"""ADR-M2 Phase 2.8 — fork atomicity tests.

A run commits the topology fork + plan as a pair. Either both land (inside a
single transaction) or neither does; a durable fork with no run (crash between
the two) is reconciled at startup by ``cleanup_orphaned_forks``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "fork.db")


def test_open_run_commits_pair_atomically(store: Store) -> None:
    """The run row and the topology snapshot land together (Phase 2.8)."""
    from test_executor import _plan

    from mayhem.controller.executor import RunEngine
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    engine = RunEngine(store, SQLiteLeaseSink(store))
    plan = _plan("r-fork", 1)
    engine._open_run(plan)

    runs = store.query("SELECT id, topology_snapshot_id FROM runs WHERE id = ?", (plan.run_id,))
    assert len(runs) == 1
    assert runs[0]["topology_snapshot_id"] is not None

    staging = store.query("SELECT * FROM run_fork_staging WHERE run_id = ?", (plan.run_id,))
    assert len(staging) == 1
    assert staging[0]["phase"] == "committed"


def test_cleanup_removes_orphaned_fork(store: Store) -> None:
    """A durable topology snapshot with no run is dropped at startup."""
    # Simulate a crash: fork durable but plan/run never committed. The schema
    # FK normally forbids a run-less snapshot, so emulate the crash window by
    # suspending FK enforcement for the orphan insert.
    with store.write() as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute(
            "INSERT INTO topology_snapshots (id, run_id, graph_json, drift_report, fingerprint)"
            " VALUES ('topo-orphan', 'r-never-committed', '{}', '{}', 'fp-orphan')"
        )
        conn.execute(
            "INSERT INTO run_fork_staging (run_id, topo_id, phase, created_at)"
            " VALUES ('r-never-committed', 'topo-orphan', 'planning', '2026-01-01T00:00:00+00:00')"
        )
        conn.execute("PRAGMA foreign_keys=ON")

    from mayhem.controller.executor import RunEngine
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    engine = RunEngine(store, SQLiteLeaseSink(store))
    engine.cleanup_orphaned_forks()

    rows = store.query("SELECT id FROM topology_snapshots WHERE id = 'topo-orphan'")
    assert rows == []
    staging = store.query("SELECT run_id FROM run_fork_staging WHERE phase = 'planning'")
    assert staging == []


def test_cleanup_preserves_committed_fork(store: Store) -> None:
    """Snapshots referenced by a real run survive startup reconciliation."""
    from test_executor import _plan

    from mayhem.controller.executor import RunEngine
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    engine = RunEngine(store, SQLiteLeaseSink(store))
    plan = _plan("r-keep", 1)
    engine._open_run(plan)

    engine.cleanup_orphaned_forks()

    runs = store.query("SELECT topology_snapshot_id FROM runs WHERE id = ?", (plan.run_id,))
    topo_id = runs[0]["topology_snapshot_id"]
    snapshots = store.query("SELECT id FROM topology_snapshots WHERE id = ?", (topo_id,))
    assert len(snapshots) == 1


def test_migration_0009_tables_exist(store: Store) -> None:
    """Migration 0009 creates the fork staging table and admits
    resource_conflict status."""
    tables = {r["name"] for r in store.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "run_fork_staging" in tables

    hm = store.query("SELECT sql FROM sqlite_master WHERE name = 'step_runs'")
    assert "resource_conflict" in hm[0]["sql"]


def test_migrations_run_once(store: Store) -> None:
    assert store.schema_version == len(ALL_MIGRATIONS)
