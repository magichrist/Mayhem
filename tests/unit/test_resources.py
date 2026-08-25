"""Tests for resource ownership and conflict detection (ADR-0015)."""

import uuid

from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.resources import (
    ConflictKind,
    ResourceOwnershipGraph,
    ResourceState,
    ResourceType,
    TrackedResource,
)


def _make_resource(
    *,
    resource_type: ResourceType = ResourceType.TC_RULE,
    run_id: str = "run-001",
    step_id: str = "step-1",
    fault_id: str = "net.latency",
    target: str = "host-1",
    state: ResourceState = ResourceState.ACTIVE,
) -> TrackedResource:
    return TrackedResource(
        id=str(uuid.uuid4()),
        resource_type=resource_type,
        owner_run_id=run_id,
        owner_step_id=step_id,
        owner_fault_id=fault_id,
        target_identity=target,
        state=state,
        cleanup_op=UndoOp(op="tc.del_qdisc", args={"device": "eth0"}),
        verify_probe=VerifyProbe(
            probe="exec", args={"cmd": ["tc", "qdisc", "show"]}, expect_present=False
        ),
    )


class TestTrackedResource:
    def test_create(self) -> None:
        r = _make_resource()
        assert r.state == ResourceState.ACTIVE
        assert r.resource_type == ResourceType.TC_RULE

    def test_frozen(self) -> None:
        r = _make_resource()
        r_copy = r.model_copy(update={"state": ResourceState.RECOVERED})
        assert r_copy.state == ResourceState.RECOVERED
        assert r.state == ResourceState.ACTIVE  # original unchanged


class TestResourceOwnershipGraph:
    def test_add_and_get(self) -> None:
        graph = ResourceOwnershipGraph()
        r = _make_resource()
        graph.add(r)
        assert graph.get(r.id) is r
        assert graph.size == 1

    def test_remove(self) -> None:
        graph = ResourceOwnershipGraph()
        r = _make_resource()
        graph.add(r)
        removed = graph.remove(r.id)
        assert removed is r
        assert graph.get(r.id) is None
        assert graph.size == 0

    def test_remove_nonexistent(self) -> None:
        graph = ResourceOwnershipGraph()
        assert graph.remove("nope") is None

    def test_active_for_target(self) -> None:
        graph = ResourceOwnershipGraph()
        r1 = _make_resource(target="host-1", resource_type=ResourceType.TC_RULE)
        r2 = _make_resource(target="host-1", resource_type=ResourceType.IPTABLES_RULE)
        r3 = _make_resource(target="host-2")
        graph.add(r1)
        graph.add(r2)
        graph.add(r3)
        active = graph.active_for_target("host-1")
        assert len(active) == 2

    def test_active_for_target_excludes_recovered(self) -> None:
        graph = ResourceOwnershipGraph()
        r = _make_resource(state=ResourceState.RECOVERED)
        graph.add(r)
        assert graph.active_for_target("host-1") == []

    def test_active_for_run(self) -> None:
        graph = ResourceOwnershipGraph()
        r1 = _make_resource(run_id="run-A")
        r2 = _make_resource(run_id="run-B")
        graph.add(r1)
        graph.add(r2)
        active = graph.active_for_run("run-A")
        assert len(active) == 1
        assert active[0].owner_run_id == "run-A"

    def test_orphans(self) -> None:
        graph = ResourceOwnershipGraph()
        r1 = _make_resource(state=ResourceState.ACTIVE)
        r2 = _make_resource(state=ResourceState.RECOVERED)
        graph.add(r1)
        graph.add(r2)
        orphans = graph.orphans()
        assert len(orphans) == 1


class TestConflictDetection:
    def test_same_type_same_target_different_runs(self) -> None:
        graph = ResourceOwnershipGraph()
        existing = _make_resource(
            run_id="run-A",
            resource_type=ResourceType.TC_RULE,
            target="host-1",
        )
        graph.add(existing)
        new = _make_resource(
            run_id="run-B",
            resource_type=ResourceType.TC_RULE,
            target="host-1",
        )
        conflicts = graph.detect_conflicts(new)
        assert len(conflicts) == 1
        assert conflicts[0].kind == ConflictKind.SERIALIZE

    def test_different_type_same_target(self) -> None:
        graph = ResourceOwnershipGraph()
        existing = _make_resource(
            run_id="run-A",
            resource_type=ResourceType.TC_RULE,
            target="host-1",
        )
        graph.add(existing)
        new = _make_resource(
            run_id="run-B",
            resource_type=ResourceType.IPTABLES_RULE,
            target="host-1",
        )
        conflicts = graph.detect_conflicts(new)
        assert len(conflicts) == 1
        assert conflicts[0].kind == ConflictKind.COEXIST

    def test_same_run_no_conflict(self) -> None:
        graph = ResourceOwnershipGraph()
        existing = _make_resource(
            run_id="run-A",
            resource_type=ResourceType.TC_RULE,
            target="host-1",
        )
        graph.add(existing)
        new = _make_resource(
            run_id="run-A",
            resource_type=ResourceType.TC_RULE,
            target="host-1",
        )
        conflicts = graph.detect_conflicts(new)
        assert len(conflicts) == 0

    def test_different_targets_no_conflict(self) -> None:
        graph = ResourceOwnershipGraph()
        existing = _make_resource(
            run_id="run-A",
            resource_type=ResourceType.TC_RULE,
            target="host-1",
        )
        graph.add(existing)
        new = _make_resource(
            run_id="run-B",
            resource_type=ResourceType.TC_RULE,
            target="host-2",
        )
        conflicts = graph.detect_conflicts(new)
        assert len(conflicts) == 0

    def test_has_serializable_conflicts_true(self) -> None:
        graph = ResourceOwnershipGraph()
        existing = _make_resource(run_id="run-A", resource_type=ResourceType.TC_RULE)
        graph.add(existing)
        new = _make_resource(run_id="run-B", resource_type=ResourceType.TC_RULE)
        assert graph.has_serializable_conflicts(new) is True

    def test_has_serializable_conflicts_false(self) -> None:
        graph = ResourceOwnershipGraph()
        existing = _make_resource(run_id="run-A", resource_type=ResourceType.TC_RULE)
        graph.add(existing)
        new = _make_resource(run_id="run-B", resource_type=ResourceType.IPTABLES_RULE)
        assert graph.has_serializable_conflicts(new) is False
