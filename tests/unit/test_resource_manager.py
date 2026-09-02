"""Tests for ResourceManager — persistence and ownership-aware recovery (ADR-0015)."""

import uuid

import pytest

from mayhem.controller.resource_manager import ResourceManager
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.resources import ResourceState, ResourceType
from mayhem.infra.store import Store


@pytest.fixture()
def store(tmp_path: object) -> Store:
    return Store.open_migrated(tmp_path / "test.db")  # type: ignore[arg-type]


@pytest.fixture()
def rm(store: Store) -> ResourceManager:
    return ResourceManager(store)


def _undo() -> UndoOp:
    return UndoOp(op="tc.del_qdisc", args={"device": "eth0"})


def _probe() -> VerifyProbe:
    return VerifyProbe(probe="exec", args={"cmd": ["tc", "qdisc", "show"]}, expect_present=False)


class TestResourceManagerRegister:
    def test_register_returns_tracked_resource(self, rm: ResourceManager) -> None:
        r = rm.register(
            resource_type=ResourceType.TC_RULE,
            run_id="run-001",
            step_id="step-1",
            fault_id="net.latency",
            target_identity="host-1",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        assert r.state == ResourceState.PENDING
        assert r.resource_type == ResourceType.TC_RULE
        assert r.owner_run_id == "run-001"

    def test_register_activates_and_lists(self, rm: ResourceManager) -> None:
        r = rm.register(
            resource_type=ResourceType.TC_RULE,
            run_id="run-001",
            step_id="step-1",
            fault_id="net.latency",
            target_identity="host-1",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        rm.activate(r.id)
        active = rm.list_resources(run_id="run-001", state=ResourceState.ACTIVE)
        assert len(active) == 1
        assert active[0].id == r.id


class TestResourceManagerConflict:
    def test_register_conflict_raises(self, rm: ResourceManager) -> None:
        rm.register(
            resource_type=ResourceType.TC_RULE,
            run_id="run-001",
            step_id="step-1",
            fault_id="net.latency",
            target_identity="host-1",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        with pytest.raises(InvariantViolationError, match="resource_conflict"):
            rm.register(
                resource_type=ResourceType.TC_RULE,
                run_id="run-002",
                step_id="step-2",
                fault_id="net.latency",
                target_identity="host-1",
                cleanup_op=_undo(),
                verify_probe=_probe(),
            )

    def test_different_type_same_target_ok(self, rm: ResourceManager) -> None:
        rm.register(
            resource_type=ResourceType.TC_RULE,
            run_id="run-001",
            step_id="step-1",
            fault_id="net.latency",
            target_identity="host-1",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        r2 = rm.register(
            resource_type=ResourceType.IPTABLES_RULE,
            run_id="run-002",
            step_id="step-2",
            fault_id="net.partition",
            target_identity="host-1",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        assert r2.resource_type == ResourceType.IPTABLES_RULE


class TestResourceManagerRecovery:
    def test_recover_owned(self, rm: ResourceManager) -> None:
        r = rm.register(
            resource_type=ResourceType.TC_RULE,
            run_id="run-001",
            step_id="step-1",
            fault_id="net.latency",
            target_identity="host-1",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        rm.activate(r.id)
        results = rm.recover_owned("run-001")
        assert len(results) == 1
        assert results[0].success is True

    def test_mark_recovered(self, rm: ResourceManager) -> None:
        r = rm.register(
            resource_type=ResourceType.TC_RULE,
            run_id="run-001",
            step_id="step-1",
            fault_id="net.latency",
            target_identity="host-1",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        rm.activate(r.id)
        rm.start_recovery(r.id)
        rm.mark_recovered(r.id, verified=True)
        updated = rm.list_resources(run_id="run-001", state=ResourceState.RECOVERED)
        assert len(updated) == 1

    def test_mark_dirty_on_failed_verify(self, rm: ResourceManager) -> None:
        r = rm.register(
            resource_type=ResourceType.TC_RULE,
            run_id="run-001",
            step_id="step-1",
            fault_id="net.latency",
            target_identity="host-1",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        rm.activate(r.id)
        rm.start_recovery(r.id)
        rm.mark_recovered(r.id, verified=False)
        dirty = rm.list_resources(state=ResourceState.DIRTY)
        assert len(dirty) == 1


class TestResourceManagerPersistence:
    def test_survives_restart(self, tmp_path: object) -> None:
        db_path = tmp_path / "test.db"  # type: ignore[union-attr]
        # First lifecycle
        store1 = Store.open_migrated(db_path)
        rm1 = ResourceManager(store1)
        r = rm1.register(
            resource_type=ResourceType.TC_RULE,
            run_id="run-001",
            step_id="step-1",
            fault_id="net.latency",
            target_identity="host-1",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        rm1.activate(r.id)

        # Second lifecycle — graph should reload from SQLite
        store2 = Store.open_migrated(db_path)
        rm2 = ResourceManager(store2)
        assert rm2.graph.size == 1
        retrieved = rm2.graph.get(r.id)
        assert retrieved is not None
        assert retrieved.state == ResourceState.ACTIVE

    def test_unknown_resource_raises(self, rm: ResourceManager) -> None:
        with pytest.raises(InvariantViolationError, match="resource_unknown"):
            rm.activate(str(uuid.uuid4()))


# ------------------------------------------------------------------
# Phase 2.6 — mutation-boundary journal
# ------------------------------------------------------------------


class TestMutationJournal:
    def test_journal_mutation_activates_resource(self, rm: ResourceManager) -> None:
        r = rm.register(
            resource_type=ResourceType.PROCESS_SPAWN,
            run_id="run-j1",
            step_id="step-1",
            fault_id="proc.kill",
            target_identity="host-a",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        assert r.state == ResourceState.PENDING

        entry = rm.journal_mutation(
            lease_id="l-100",
            resource_id=r.id,
            run_id="run-j1",
            step_id="step-1",
            fault_id="proc.kill",
            defining_op=UndoOp(op="kill", args={"pid": "42"}),
            target_identity="host-a",
        )

        assert entry.lease_id == "l-100"
        assert entry.defining_op.args["pid"] == "42"
        assert entry.target_identity == "host-a"

        updated = rm.graph.get(r.id)
        assert updated is not None
        assert updated.state == ResourceState.ACTIVE

    def test_journal_mutation_survives_restart(self, tmp_path: object) -> None:
        db = tmp_path / "jm.db"  # type: ignore[union-attr]
        rm1 = ResourceManager(Store.open_migrated(db))
        r = rm1.register(
            resource_type=ResourceType.IPTABLES_RULE,
            run_id="run-j2",
            step_id="s-2",
            fault_id="fw.drop",
            target_identity="host-b",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        rm1.journal_mutation(
            lease_id="l-200",
            resource_id=r.id,
            run_id="run-j2",
            step_id="s-2",
            fault_id="fw.drop",
            defining_op=UndoOp(op="iptables", args={"cmd": "-A DROP"}),
            target_identity="host-b",
        )

        # Fresh manager
        rm2 = ResourceManager(Store.open_migrated(db))
        assert rm2.graph.size == 1
        res = rm2.graph.get(r.id)
        assert res is not None
        assert res.state == ResourceState.ACTIVE


# ------------------------------------------------------------------
# Phase 2.7 — one-inflight-writer (resource-conflict)
# ------------------------------------------------------------------


class TestInflightWriter:
    def test_no_conflict_on_idle_target(self, rm: ResourceManager) -> None:
        assert rm.check_no_inflight_writer("host-x") is None

    def test_conflict_when_target_held(self, rm: ResourceManager) -> None:
        r = rm.register(
            resource_type=ResourceType.TC_RULE,
            run_id="run-w1",
            step_id="s-1",
            fault_id="net.loss",
            target_identity="host-y",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        rm.journal_mutation(
            lease_id="l-300",
            resource_id=r.id,
            run_id="run-w1",
            step_id="s-1",
            fault_id="net.loss",
            defining_op=UndoOp(op="tc", args={"netem": "loss 100%"}),
            target_identity="host-y",
        )
        reason = rm.check_no_inflight_writer("host-y")
        assert reason is not None
        assert "RESOURCE_CONFLICT" in reason
        assert "l-300" in reason

    def test_no_conflict_for_same_run(self, rm: ResourceManager) -> None:
        """The same run should not conflict with itself (parallel steps)."""
        r = rm.register(
            resource_type=ResourceType.TC_RULE,
            run_id="run-w2",
            step_id="s-1",
            fault_id="net.latency",
            target_identity="host-z",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        rm.journal_mutation(
            lease_id="l-400",
            resource_id=r.id,
            run_id="run-w2",
            step_id="s-1",
            fault_id="net.latency",
            defining_op=UndoOp(op="tc", args={"netem": "delay"}),
            target_identity="host-z",
        )
        # Same run, different step → no conflict
        assert rm.check_no_inflight_writer("host-z", exclude_run_id="run-w2") is None

    def test_conflict_vanishes_after_recovery(self, rm: ResourceManager) -> None:
        r = rm.register(
            resource_type=ResourceType.PROCESS_SIGNAL,
            run_id="run-w3",
            step_id="s-1",
            fault_id="proc.pause",
            target_identity="host-w",
            cleanup_op=_undo(),
            verify_probe=_probe(),
        )
        rm.journal_mutation(
            lease_id="l-500",
            resource_id=r.id,
            run_id="run-w3",
            step_id="s-1",
            fault_id="proc.pause",
            defining_op=UndoOp(op="signal", args={"sig": "STOP"}),
            target_identity="host-w",
        )
        assert rm.check_no_inflight_writer("host-w") is not None

        # Recovery clears the conflict
        rm.mark_recovered(r.id, verified=True)
        assert rm.check_no_inflight_writer("host-w") is None
