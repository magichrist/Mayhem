"""ADR-M2 Phase 2.7 — executor-level resource-conflict (one-inflight-writer).

A second run targeting a container that still holds an active mutation from
another run is rejected with ``RESOURCE_CONFLICT`` before any mutation.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest
from test_executor import _plan

from mayhem.controller.executor import RunEngine
from mayhem.controller.resource_manager import ResourceManager
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.resources import ResourceType
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path


def _spawn_sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen(["sleep", "30"])


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "conflict.db")


@pytest.fixture()
def rm(store: Store) -> ResourceManager:
    return ResourceManager(store)


def _engine(store: Store, rm: ResourceManager) -> RunEngine:
    return RunEngine(
        store,
        SQLiteLeaseSink(store),
        resource_manager=rm,
    )


def test_second_run_conflicts_on_held_target(store: Store, rm: ResourceManager) -> None:
    proc = _spawn_sleeper()
    try:
        # A first run may have completed and recovered; the conflict below is
        # driven by an unrelated concurrent run that still holds the target.
        engine2 = _engine(store, rm)
        plan2 = _plan("r-conflict-2", proc.pid)

        # Simulate a concurrent run that already holds the target: register +
        # journal an active mutation under a different run id.
        r = rm.register(
            resource_type=ResourceType.PROCESS_SPAWN,
            run_id="r-concurrent-other",
            step_id="s-0",
            fault_id="proc.pause",
            target_identity="podman|h-local|a",
            cleanup_op=UndoOp(op="lease.compensate", args={"lease_id": "l-zz"}),
            verify_probe=VerifyProbe(
                probe="lease.verify", args={"lease_id": "l-zz"}, expect_present=False
            ),
        )
        rm.journal_mutation(
            lease_id="l-zz",
            resource_id=r.id,
            run_id="r-concurrent-other",
            step_id="s-0",
            fault_id="proc.pause",
            defining_op=UndoOp(op="inject", args={"target": "podman|h-local|a"}),
            target_identity="podman|h-local|a",
        )

        # The competing run must conflict before mutating.
        result = engine2.execute(plan2)
        step = result.steps[0]

        assert not step.ok
        assert step.status == "resource_conflict"
        assert "RESOURCE_CONFLICT" in step.detail

        rows = store.query("SELECT status FROM step_runs WHERE run_id = ?", (plan2.run_id,))
        assert rows[0]["status"] == "resource_conflict"

        # No mutation was applied by the rejected run; its lease was
        # compensated (released with a resource_conflict mechanism).
        leases = store.query(
            "SELECT state, release_mechanism FROM fault_leases WHERE run_id = ?",
            (plan2.run_id,),
        )
        assert len(leases) == 1
        assert leases[0]["state"] == "released"
        assert leases[0]["release_mechanism"] == "resource_conflict"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_no_conflict_for_idle_target(store: Store, rm: ResourceManager) -> None:
    proc = _spawn_sleeper()
    try:
        engine = _engine(store, rm)
        plan = _plan("r-clean", proc.pid)
        result = engine.execute(plan)
        assert result.status == "completed"
        assert result.steps[0].status not in ("resource_conflict",)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
