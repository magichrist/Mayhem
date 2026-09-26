from __future__ import annotations

from mayhem.domain.admission import admit_resolved_target, target_type
from mayhem.domain.resolution import ResolvedNodeTarget, ResolvedPodTarget


def _pod() -> ResolvedPodTarget:
    return ResolvedPodTarget(namespace="default", pod="api-0", container="api")


def _node() -> ResolvedNodeTarget:
    return ResolvedNodeTarget(node="node-a")


def test_target_type_distinguishes_pod_and_node() -> None:
    assert target_type(_pod()) == "pod"
    assert target_type(_node()) == "node"
    assert target_type(object()) is None


def test_admission_allows_matching_pod_target() -> None:
    decision = admit_resolved_target(
        "k8s.pod_kill",
        _pod(),
        required_target_types=("pod",),
        compensation_complete=True,
    )
    assert decision.allowed is True
    assert decision.code == ""
    assert decision.required_target_types == ("pod",)


def test_admission_refuses_node_pod_mismatch() -> None:
    decision = admit_resolved_target(
        "k8s.pod_kill",
        _node(),
        required_target_types=("pod",),
        compensation_complete=True,
    )
    assert decision.allowed is False
    assert decision.code == "target.type_mismatch"
    assert "pod" in decision.reason


def test_admission_refuses_unresolved_target() -> None:
    decision = admit_resolved_target(
        "k8s.pod_kill",
        None,
        required_target_types=("pod",),
        compensation_complete=True,
    )
    assert decision.allowed is False
    assert decision.code == "target.unresolved"


def test_admission_refuses_incomplete_compensation() -> None:
    decision = admit_resolved_target(
        "k8s.pod_kill",
        _pod(),
        required_target_types=("pod",),
        compensation_complete=False,
    )
    assert decision.allowed is False
    assert decision.code == "compensation.incomplete"


def test_admission_supports_container_service_and_workload_strings() -> None:
    for target_type_name in ("container", "service", "workload"):
        decision = admit_resolved_target(
            "fault",
            target_type_name,
            required_target_types=(target_type_name,),
            compensation_complete=True,
        )
        assert decision.allowed is False
        assert decision.code == "target.type_mismatch"


class _ExplodingLeaseClient:
    def acquire(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("lease must not be created for a refused target")


class _NodeTargetResolver:
    """Resolver stub that hands back a node target for a pod-scoped fault."""

    available = True

    def __init__(self) -> None:
        self.calls: list[str] = []

    def resolve_many(self, scope: object, *, pod_action: str = "") -> list[object]:
        self.calls.append("resolve_many")

        class _Outcome:
            resolved = _node()
            drift = False
            note = ""

        return [_Outcome()]

    def resolve(self, scope: object, *, preferred_pod: str | None = None) -> object:
        self.calls.append("resolve")
        raise AssertionError("node resolver path must not be used for pod faults")


def _pod_fault_plan() -> object:
    from mayhem.domain.experiments import (
        ExecutionPlan,
        ExperimentKind,
        PlannedFault,
        PlannedStep,
    )
    from mayhem.domain.identity import RuntimeLabel
    from mayhem.domain.target import ResourceKind, TargetScope
    from mayhem.domain.leases import UndoOp
    from mayhem.domain.experiments import Wait

    scope = TargetScope(
        logical_id="checkout",
        runtime=RuntimeLabel.KUBERNETES,
        kind=ResourceKind.DEPLOYMENT,
        authority={"namespace": "production", "kind": "deployment", "name": "checkout"},
        container="app",
    )
    fault = PlannedFault(
        fault_id="k8s.pod_kill",
        targets=(),
        target=scope,
        undo_ops=(UndoOp(op="k8s.exec", args={"undo_command": "CONT"}),),
        duration="0.1s",
    )
    step = PlannedStep(id="k8s-0000", seq=0, fault=fault, raw_action=Wait(type="wait", duration=0.0))
    return ExecutionPlan(
        run_id="admit-order",
        kind=ExperimentKind.DRILL,
        steps=(step,),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def test_pod_fault_refuses_node_target_before_lease_or_spec_construction(tmp_path) -> None:
    """A target-type mismatch must not reach lease creation or spec building."""
    from mayhem.controller.executor import RunEngine
    from mayhem.infra.store import Store

    from mayhem.infra.lease_repository import SQLiteLeaseSink

    store = Store.open_migrated(tmp_path / "admission.db")
    engine = RunEngine(
        store,
        SQLiteLeaseSink(store),
        k8s_resolver=_NodeTargetResolver(),  # type: ignore[arg-type]
        sleeper=lambda _s: None,
    )
    engine._client = _ExplodingLeaseClient()  # type: ignore[assignment]
    plan = _pod_fault_plan()
    report, dirty = engine._execute_k8s_pod_fault(plan, plan.steps[0])  # type: ignore[arg-type]
    assert report.ok is False
    assert report.status == "failed_to_apply"
    assert "target.type_mismatch" in report.detail
    assert dirty == []
