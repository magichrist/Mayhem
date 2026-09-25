from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from mayhem.agents import executors as executor_module
from mayhem.agents.executors import K8sExecutor, k8s_executor_for
from mayhem.agents.k8s_control import ResourceRef
from mayhem.controller.k8s_runtime import (
    K8S_MUTATION_FAULTS,
    K8S_NODE_FAULTS,
    K8S_REVERSIBLE_FAULTS,
    k8s_available_faults,
    k8s_contract_for,
    k8s_undo_ops_for,
)
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.resolution import ResolvedNodeTarget, ResolvedPodTarget

if TYPE_CHECKING:
    import pytest

K8S_IDS = (
    "k8s.pod_restart_churn",
    "k8s.sidecar_termination",
    "k8s.workload_stall",
    "k8s.service_5xx",
    "k8s.dns_timeout",
    "k8s.node_disk_pressure",
    "k8s.node_memory_pressure",
    "k8s.node_pid_pressure",
    "k8s.hpa_oscillation",
    "k8s.pdb_over_eviction",
)


def _pod() -> ResolvedPodTarget:
    return ResolvedPodTarget(
        namespace="prod",
        pod="checkout-abc",
        container="app",
        pod_uid="uid-1",
        node="worker-1",
        labels={"app": "checkout"},
        pod_action="fault",
        exec_argv=("kubectl", "exec", "checkout-abc", "-n", "prod", "-c", "app", "--"),
    )


def _node() -> ResolvedNodeTarget:
    return ResolvedNodeTarget(node="worker-1", node_uid="node-uid", ready=True)


def _lease(fault_id: str, target: ResolvedPodTarget | ResolvedNodeTarget) -> FaultLease:
    return FaultLease(
        id=f"l-{fault_id.replace('.', '-')}",
        run_id="run",
        fault_id=fault_id,
        owner_agent="test",
        targets=frozenset({"target"}),
        undo_ops=(
            UndoOp(
                op="k8s.undo",
                args={"params": json.dumps({"domain": "api.default.svc.cluster.local"})},
            ),
        ),
        verify_probes=(VerifyProbe(probe="k8s.undo", args={}),),
        state=LeaseState.ACTIVE,
        resolved_target=target,
    )


def _successful_tool(*args: Any, **kwargs: Any):
    return SimpleNamespace(succeeded=True, exit_code=0, stdout="", stderr="")


def test_all_kubernetes_ids_have_executor_and_undo_contract() -> None:
    assert set(K8S_IDS) <= k8s_available_faults()
    assert set(K8S_IDS) <= K8S_MUTATION_FAULTS | K8S_NODE_FAULTS
    for fault_id in K8S_IDS:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        assert isinstance(executor, K8sExecutor)
        assert k8s_contract_for(fault_id).executor != "k8s.unsupported"
        assert k8s_undo_ops_for(fault_id, _pod()) or fault_id in K8S_NODE_FAULTS
        assert k8s_contract_for(fault_id).evidence
        if fault_id not in {"k8s.pod_restart_churn", "k8s.sidecar_termination"}:
            assert fault_id in K8S_REVERSIBLE_FAULTS


def test_kubernetes_fake_mutations_restore_snapshots(monkeypatch: pytest.MonkeyPatch) -> None:
    objects: dict[str, dict[str, Any]] = {
        "Deployment": {
            "spec": {
                "replicas": 2,
                "template": {"spec": {"containers": [{"name": "app", "image": "api:1"}]}},
            }
        },
        "Service": {"spec": {"selector": {"app": "checkout"}, "ports": [{"port": 80}]}},
        "HorizontalPodAutoscaler": {
            "spec": {"minReplicas": 1, "maxReplicas": 5},
            "status": {"currentReplicas": 2},
        },
        "PodDisruptionBudget": {"spec": {"minAvailable": 1}},
        "ConfigMap": {"data": {"Corefile": ".:53 {\n}\n"}},
    }
    refs = {
        "Deployment": ResourceRef(kind="Deployment", name="checkout", namespace="prod"),
        "Service": ResourceRef(kind="Service", name="checkout", namespace="prod"),
        "HorizontalPodAutoscaler": ResourceRef(
            kind="HorizontalPodAutoscaler", name="checkout", namespace="prod"
        ),
        "PodDisruptionBudget": ResourceRef(
            kind="PodDisruptionBudget", name="checkout", namespace="prod"
        ),
        "ConfigMap": ResourceRef(kind="ConfigMap", name="coredns", namespace="kube-system"),
    }
    snapshots: dict[str, dict[str, Any]] = {}
    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(executor_module, "kubectl_json", lambda ref: objects.get(ref.kind))
    monkeypatch.setattr(executor_module, "workload_ref_for_pod", lambda _target: refs["Deployment"])
    monkeypatch.setattr(executor_module, "service_ref_for_pod", lambda _target: refs["Service"])
    monkeypatch.setattr(
        executor_module,
        "hpa_ref_for_pod",
        lambda _target: refs["HorizontalPodAutoscaler"],
    )
    monkeypatch.setattr(executor_module, "find_annotated", lambda _namespace, kinds: refs[kinds[0]])
    monkeypatch.setattr(
        executor_module,
        "write_annotation",
        lambda ref, snapshot: snapshots.__setitem__(ref.kind, dict(snapshot)) or True,
    )
    monkeypatch.setattr(executor_module, "read_snapshot", lambda ref: snapshots.get(ref.kind))
    monkeypatch.setattr(executor_module, "clear_annotation", lambda _ref: snapshots.clear())

    def fake_apply_patch(ref: Any, payload: dict[str, Any]) -> bool:
        calls.append((ref.kind, payload))
        objects[ref.kind].update(payload)
        return True

    monkeypatch.setattr(executor_module, "apply_patch", fake_apply_patch)
    monkeypatch.setattr(executor_module, "rollout_restart", lambda _ref: True)
    monkeypatch.setattr(executor_module, "k8s_dns_supported", lambda: True)
    monkeypatch.setattr(executor_module, "k8s_node_control_supported", lambda: True)
    monkeypatch.setattr(executor_module, "run_tool", _successful_tool)

    for fault_id in K8S_IDS:
        target = _node() if fault_id in K8S_NODE_FAULTS else _pod()
        lease = _lease(fault_id, target)
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        assert executor is not None
        if fault_id in K8S_NODE_FAULTS:
            assert executor.can_apply(lease) is None
        else:
            assert executor.can_apply(lease) is None
        assert executor.inject(lease).ok
        assert executor.undo(lease).ok


def test_kubernetes_target_kind_mismatches_are_typed_refusals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(executor_module, "k8s_dns_supported", lambda: True)
    for fault_id in K8S_IDS:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        assert executor is not None
        correct = _node() if fault_id in K8S_NODE_FAULTS else _pod()
        wrong = _pod() if fault_id in K8S_NODE_FAULTS else _node()
        assert executor.can_apply(_lease(fault_id, wrong)).startswith("k8s.unsupported")
        assert executor.can_apply(_lease(fault_id, correct)) is None


def test_kubernetes_missing_capability_refuses_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(executor_module, "k8s_dns_supported", lambda: False)
    executor = k8s_executor_for("k8s.dns_timeout", RuntimeLabel.KUBERNETES)
    assert executor is not None
    reason = executor.can_apply(_lease("k8s.dns_timeout", _pod()))
    assert reason is not None
    assert "DNS_CONTROL" in reason
