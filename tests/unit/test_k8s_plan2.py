from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pytest
from tests.unit.test_kplan6_runtime import _CORDON_TARGET

from mayhem.agents.executors import (
    DNS_CONTROL_UNSUPPORTED_MESSAGE,
    K8sDnsExecutor,
    K8sNodeImagePullExecutor,
    K8sPdbExecutor,
    K8sWorkloadExecutor,
    k8s_executor_for,
)
from mayhem.agents.k8s_control import ResourceRef
from mayhem.controller.k8s_runtime import (
    K8S_DISRUPTION_FAULTS,
    K8S_DNS_FAULTS,
    K8S_LIFECYCLE_FAULTS,
    K8S_MUTATION_FAULTS,
    K8S_NODE_FAULTS,
    K8S_PREEMPT_FAULTS,
    K8S_REVERSIBLE_FAULTS,
    k8s_available_faults,
)
from mayhem.domain.catalog import definition_for
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.resolution import ResolvedPodTarget

_PLAN2_IDS = {
    "k8s.pod_image_pull_delay",
    "k8s.container_termination_delay",
    "k8s.preemption_failure",
    "k8s.pdb_violation",
    "k8s.eviction_block",
    "k8s.dns_failure",
    "k8s.dns_delay",
    "k8s.service_dns_mismatch",
}


def _pod_target() -> ResolvedPodTarget:
    return ResolvedPodTarget(
        namespace="prod",
        pod="checkout-abc123",
        container="app",
        pod_uid="u-1",
        node="w1",
        labels={"app": "checkout"},
        pod_action="fault",
        exec_argv=("kubectl", "exec", "checkout-abc123", "-n", "prod", "-c", "app", "--"),
    )


def _lease(fault_id: str, params: dict[str, object] | None = None) -> FaultLease:
    target = _pod_target()
    return FaultLease(
        id=f"l-{fault_id.replace('.', '-')}",
        run_id="run",
        fault_id=fault_id,
        owner_agent="engine",
        targets=frozenset({target.pod}),
        undo_ops=(UndoOp(op="k8s.undo", args={"params": json.dumps(params or {})}),),
        verify_probes=(VerifyProbe(probe="k8s.undo", args={}),),
        ttl_seconds=30,
        state=LeaseState.ACTIVE,
        resolved_target=target,
    )


def test_plan2_families_are_registered() -> None:
    assert _PLAN2_IDS <= K8S_MUTATION_FAULTS | K8S_NODE_FAULTS
    assert _PLAN2_IDS <= (
        K8S_DISRUPTION_FAULTS | K8S_DNS_FAULTS | K8S_LIFECYCLE_FAULTS | K8S_PREEMPT_FAULTS
    )
    assert _PLAN2_IDS <= K8S_REVERSIBLE_FAULTS
    assert k8s_available_faults() >= _PLAN2_IDS
    assert all(definition_for(fault_id).category == "k8s" for fault_id in _PLAN2_IDS)
    assert isinstance(k8s_executor_for("k8s.dns_failure", RuntimeLabel.KUBERNETES), K8sDnsExecutor)
    assert isinstance(
        k8s_executor_for("k8s.pdb_violation", RuntimeLabel.KUBERNETES), K8sPdbExecutor
    )


def test_dns_executor_refuses_without_dns_control(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mayhem.agents.executors.k8s_dns_supported", lambda: False)
    lease = _lease("k8s.dns_failure", {"domain": "api.default.svc.cluster.local"})
    assert K8sDnsExecutor().can_apply(lease) == DNS_CONTROL_UNSUPPORTED_MESSAGE


def test_pdb_executor_mutates_and_restores(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshots: dict[str, Any] = {}
    objects = {
        "PodDisruptionBudget": {"spec": {"minAvailable": 1}},
    }

    def read(ref: Any) -> dict[str, Any] | None:
        return snapshots.get(ref.name)

    def write(ref: Any, snapshot: dict[str, Any]) -> bool:
        snapshots[ref.name] = snapshot
        return True

    def patch(ref: Any, payload: dict[str, Any]) -> bool:
        objects[ref.kind]["spec"] = dict(payload.get("spec", {}))
        return True

    def clear(ref: Any) -> None:
        snapshots.pop(ref.name, None)

    monkeypatch.setattr(
        "mayhem.agents.executors.kubectl_json",
        lambda _ref: objects["PodDisruptionBudget"],
    )
    monkeypatch.setattr(
        "mayhem.agents.executors.find_annotated",
        lambda _namespace, _kinds: ResourceRef(
            kind="PodDisruptionBudget", name="checkout", namespace="prod"
        ),
    )
    monkeypatch.setattr("mayhem.agents.executors.write_annotation", write)
    monkeypatch.setattr("mayhem.agents.executors.read_snapshot", read)
    monkeypatch.setattr("mayhem.agents.executors.apply_patch", patch)
    monkeypatch.setattr("mayhem.agents.executors.clear_annotation", clear)
    lease = _lease("k8s.pdb_violation", {"name": "checkout", "unavailable": 2})
    assert K8sPdbExecutor().inject(lease).ok is True
    assert objects["PodDisruptionBudget"]["spec"]["maxUnavailable"] == 2
    assert K8sPdbExecutor().undo(lease).ok is True
    assert objects["PodDisruptionBudget"]["spec"] == {"minAvailable": 1}


def test_workload_lifecycle_and_preemption_are_routed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "mayhem.agents.executors.kubectl_json",
        lambda _ref: {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"name": "app", "volumeMounts": []}],
                    }
                }
            }
        },
    )
    monkeypatch.setattr(
        "mayhem.agents.executors.workload_ref_for_pod",
        lambda _target: ResourceRef(kind="Deployment", name="checkout", namespace="prod"),
    )
    monkeypatch.setattr("mayhem.agents.executors.write_annotation", lambda *_args: True)
    monkeypatch.setattr(
        "mayhem.agents.executors.apply_patch",
        lambda _ref, payload: calls.append(payload) or True,
    )
    monkeypatch.setattr("mayhem.agents.executors.clear_annotation", lambda *_args: None)
    lease = _lease("k8s.container_termination_delay", {"seconds": "20s"})
    assert K8sWorkloadExecutor().inject(lease).ok is True
    assert calls[-1]["spec"]["template"]["spec"]["terminationGracePeriodSeconds"] == 25
    lease = _lease("k8s.preemption_failure")
    assert K8sWorkloadExecutor().inject(lease).ok is True
    assert calls[-1]["spec"]["template"]["spec"]["priority"] == -1


def test_dns_executor_mutates_and_restores(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshots: dict[str, Any] = {}
    data = {"Corefile": ".:53 {\n}\n"}

    monkeypatch.setattr("mayhem.agents.executors.k8s_dns_supported", lambda: True)
    monkeypatch.setattr("mayhem.agents.executors.kubectl_json", lambda _ref: {"data": data})
    monkeypatch.setattr(
        "mayhem.agents.executors.write_annotation",
        lambda _ref, snap: snapshots.update(snap) or True,
    )
    monkeypatch.setattr("mayhem.agents.executors.read_snapshot", lambda _ref: snapshots)
    monkeypatch.setattr(
        "mayhem.agents.executors.apply_patch",
        lambda _ref, payload: data.update(payload["data"]) or True,
    )
    monkeypatch.setattr("mayhem.agents.executors.clear_annotation", lambda _ref: snapshots.clear())
    monkeypatch.setattr("mayhem.agents.executors.rollout_restart", lambda *_args, **_kwargs: True)
    lease = _lease(
        "k8s.dns_failure",
        {"domain": "api.default.svc.cluster.local", "mode": "servfail"},
    )
    assert K8sDnsExecutor().inject(lease).ok is True
    assert "rcode servfail" in data["Corefile"]
    assert K8sDnsExecutor().undo(lease).ok is True
    assert data["Corefile"] == ".:53 {\n}\n"


def test_node_image_pull_executor_uses_node_control() -> None:
    lease = FaultLease(
        id="l-image",
        run_id="run",
        fault_id="k8s.pod_image_pull_delay",
        owner_agent="engine",
        targets=frozenset({_CORDON_TARGET.node}),
        undo_ops=(UndoOp(op="k8s.node.undo", args={}),),
        verify_probes=(VerifyProbe(probe="node", args={}),),
        ttl_seconds=30,
        state=LeaseState.ACTIVE,
        resolved_target=_CORDON_TARGET,
    )
    assert isinstance(
        k8s_executor_for(lease.fault_id, RuntimeLabel.KUBERNETES), K8sNodeImagePullExecutor
    )
