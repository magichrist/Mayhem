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
