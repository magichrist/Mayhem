from __future__ import annotations

import json
from typing import Any, ClassVar

import pytest
from tests.unit.test_kplan6_runtime import (
    _CORDON_TARGET,
    _cm,
    _deploy,
    _FakeKube,
    _pod,
    _rs,
    _svc,
)

from mayhem.agents.executors import (
    NODE_CONTROL_UNSUPPORTED_MESSAGE,
    K8sCrashLoopExecutor,
    K8sKubeProxyExecutor,
    K8sNodeNotReadyExecutor,
    K8sNodePartitionExecutor,
    K8sPvcExecutor,
    K8sQuotaExecutor,
    K8sWorkloadExecutor,
    k8s_executor_for,
)
from mayhem.config import PolicyCfg
from mayhem.controller.k8s_runtime import (
    K8S_CONTROLLER_FAULTS,
    K8S_MUTATION_FAULTS,
    K8S_NODE_FAULTS,
    K8S_REVERSIBLE_FAULTS,
    k8s_available_faults,
)
from mayhem.controller.safety import SafetyContext, check_fault_admission
from mayhem.domain.catalog import definition_for
from mayhem.domain.experiments import BlastRadiusBudget
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.toolkit.tool_runner import ToolResult

_PLAN1_OBJECTS: tuple[dict[str, Any], ...] = (
    _deploy(),
    _svc(),
    _cm(),
    _pod(),
    _rs(),
)


class _Plan1Kube(_FakeKube):
    _KIND_ALIASES: ClassVar[dict[str, str]] = {
        **_FakeKube._KIND_ALIASES,
        "resourcequota": "ResourceQuota",
        "pvc": "PersistentVolumeClaim",
    }

    def __init__(self, objects: tuple[dict[str, Any], ...] = ()) -> None:
        super().__init__(objects or _PLAN1_OBJECTS)


def _pod_lease(fault_id: str, params: dict[str, object] | None = None) -> FaultLease:
    from mayhem.domain.resolution import ResolvedPodTarget

    target = ResolvedPodTarget(
        namespace="prod",
        pod="checkout-abc123",
        container="app",
        pod_uid="u-1",
        node="w1",
        labels={"app": "checkout"},
        pod_action=fault_id.rsplit(".", maxsplit=1)[-1],
        exec_argv=("kubectl", "exec", "checkout-abc123", "-n", "prod", "-c", "app", "--"),
    )
    bag = json.dumps(params or {}, separators=(",", ":"))
    return FaultLease(
        id="l-plan1",
        run_id="r-plan1",
        fault_id=fault_id,
        owner_agent="engine",
        targets=frozenset({target.pod}),
        undo_ops=(UndoOp(op="k8s.controller", args={"params": bag}),),
        verify_probes=(VerifyProbe(probe="k8s.undo", args={}),),
        ttl_seconds=30,
        state=LeaseState.ACTIVE,
        resolved_target=target,
    )


def _node_lease(fault_id: str) -> FaultLease:
    return FaultLease(
        id="l-node-plan1",
        run_id="r-plan1",
        fault_id=fault_id,
        owner_agent="engine",
        targets=frozenset({_CORDON_TARGET.node}),
        undo_ops=(UndoOp(op="k8s.node.undo", args={}),),
        verify_probes=(VerifyProbe(probe="k8s.node_restored", args={}),),
        ttl_seconds=30,
        state=LeaseState.ACTIVE,
        resolved_target=_CORDON_TARGET,
    )


def _tool(calls: list[tuple[tuple[str, ...], str | None]]):
    def run(argv: tuple[str, ...], **kwargs: Any) -> ToolResult:
        calls.append((argv, kwargs.get("stdin_data")))
        return ToolResult(
            argv=argv,
            argv_digest="",
            env_digest="",
            host="",
            cwd=None,
            exit_code=0,
            duration_ms=1,
            stdout="{}",
            stderr="",
            truncated=False,
        )

    return run


def _quota() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": {"name": "checkout-quota", "namespace": "prod", "annotations": {}},
        "spec": {"hard": {"pods": "10", "requests.cpu": "20"}},
        "status": {"used": {"pods": "4"}},
    }


def _pvc() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": "checkout-db", "namespace": "prod", "annotations": {}},
        "spec": {"storageClassName": "fast", "resources": {"requests": {"storage": "1Gi"}}},
    }


def test_plan1_registers_and_undo_contracts() -> None:
    ids = {
        "k8s.node_not_ready",
        "k8s.pod_crash_loop",
        "k8s.pod_pending",
        "k8s.node_network_partition",
        "k8s.deployment_scale_failure",
        "k8s.statefulset_scale_failure",
        "k8s.resource_quota_exhaust",
        "k8s.persistent_volume_mount_failure",
        "k8s.persistent_volume_claim_pending",
        "k8s.kube_proxy_failure",
    }
    assert ids <= K8S_MUTATION_FAULTS | K8S_NODE_FAULTS
    assert ids <= K8S_CONTROLLER_FAULTS | K8S_NODE_FAULTS
    assert ids <= K8S_REVERSIBLE_FAULTS | K8S_NODE_FAULTS
    assert ids <= k8s_available_faults()
    assert all(definition_for(fault_id).category == "k8s" for fault_id in ids)


def test_node_workers_are_pinned_and_node_control_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[str, ...], str | None]] = []
    monkeypatch.setattr("mayhem.agents.executors.k8s_node_control_supported", lambda: True)
    monkeypatch.setattr("mayhem.agents.executors.run_tool", _tool(calls))
    for fault_id, executor_type in (
        ("k8s.node_not_ready", K8sNodeNotReadyExecutor),
        ("k8s.node_network_partition", K8sNodePartitionExecutor),
        ("k8s.kube_proxy_failure", K8sKubeProxyExecutor),
    ):
        outcome = executor_type().inject(_node_lease(fault_id))
        assert outcome.ok is True
        body = json.loads(next(data for _argv, data in reversed(calls) if data) or "{}")
        spec = body["spec"]
        assert spec["nodeName"] == "w2"
        assert spec["hostPID"] is True
        assert spec["hostNetwork"] is True
        assert spec["containers"][0]["securityContext"]["privileged"] is True

    monkeypatch.setattr("mayhem.agents.executors.k8s_node_control_supported", lambda: False)
    executor = k8s_executor_for("k8s.node_not_ready", RuntimeLabel.KUBERNETES)
    assert executor is not None
    reason = executor.can_apply(_node_lease("k8s.node_not_ready"))
    assert reason == NODE_CONTROL_UNSUPPORTED_MESSAGE


def test_critical_families_require_existing_opt_in() -> None:
    ctx = SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(),
        fingerprint="f",
        allow_critical_cli=False,
    )
    for fault_id in ("k8s.node_network_partition", "k8s.kube_proxy_failure"):
        with pytest.raises(Exception, match="critical risk"):
            check_fault_admission(fault_id, definition_for(fault_id).risk, ctx)


def test_crash_loop_launches_and_reaps_pidfile(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[str, ...], str | None]] = []
    monkeypatch.setattr("mayhem.agents.executors.run_tool", _tool(calls))
    lease = _pod_lease("k8s.pod_crash_loop", {"restarts": 5, "interval": "5s"})
    assert K8sCrashLoopExecutor().inject(lease).ok is True
    launch = calls[-1][0][-1]
    assert "kill -KILL 1" in launch
    assert "5" in launch
    assert ".crash.pid" in launch
    assert K8sCrashLoopExecutor().undo(lease).ok is True
    assert "kill $(cat" in calls[-1][0][-1]


def test_pending_and_scale_patch_owner_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    kube = _Plan1Kube()
    monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
    monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
    lease = _pod_lease("k8s.pod_pending", {"reason": "no_matching_node"})
    assert K8sWorkloadExecutor().inject(lease).ok is True
    patch = next(call for call in reversed(kube.calls) if call[1] == "patch")
    payload = json.loads(patch[patch.index("-p") + 1])
    assert payload["spec"]["template"]["spec"]["nodeSelector"] == {"mayhem.invalid/node": "true"}
    assert K8sWorkloadExecutor().undo(lease).ok is True
    restore = next(call for call in reversed(kube.calls) if call[1] == "patch")
    restore_payload = json.loads(restore[restore.index("-p") + 1])
    assert "nodeSelector" not in restore_payload["spec"]["template"]["spec"]

    scale_lease = _pod_lease("k8s.deployment_scale_failure", {"replicas": 3})
    assert K8sWorkloadExecutor().inject(scale_lease).ok is True
    scale_patch = next(call for call in reversed(kube.calls) if call[1] == "patch")
    scale_payload = json.loads(scale_patch[scale_patch.index("-p") + 1])
    assert scale_payload["spec"]["replicas"] == 3
    assert scale_payload["spec"]["template"]["spec"]["topologySpreadConstraints"]


def test_quota_and_pvc_restore_original_spec(monkeypatch: pytest.MonkeyPatch) -> None:
    objects = (*_PLAN1_OBJECTS, _quota(), _pvc())
    kube = _Plan1Kube(objects)
    monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
    monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)

    quota_lease = _pod_lease("k8s.resource_quota_exhaust", {"resource": "pods", "amount": 2})
    assert K8sQuotaExecutor().inject(quota_lease).ok is True
    quota = kube.objects[("ResourceQuota", "checkout-quota", "prod")]
    assert quota["spec"]["hard"]["pods"] == 4
    assert K8sQuotaExecutor().undo(quota_lease).ok is True
    assert kube.objects[("ResourceQuota", "checkout-quota", "prod")]["spec"] == _quota()["spec"]

    pvc_lease = _pod_lease("k8s.persistent_volume_claim_pending")
    assert K8sPvcExecutor().inject(pvc_lease).ok is True
    pvc = kube.objects[("PersistentVolumeClaim", "checkout-db", "prod")]
    assert pvc["spec"]["storageClassName"] == "mayhem-missing-storage-class"
    assert K8sPvcExecutor().undo(pvc_lease).ok is True
    assert kube.objects[("PersistentVolumeClaim", "checkout-db", "prod")]["spec"] == _pvc()["spec"]


def _deploy_with_volume() -> dict[str, Any]:
    deployment = _deploy()
    template_spec = deployment["spec"]["template"]["spec"]
    template_spec["containers"][0]["volumeMounts"] = [{"name": "data", "mountPath": "/data"}]
    template_spec["volumes"] = [
        {"name": "data", "persistentVolumeClaim": {"claimName": "checkout-db"}}
    ]
    return deployment


def test_mount_failure_changes_named_mount_and_restores(monkeypatch: pytest.MonkeyPatch) -> None:
    kube = _Plan1Kube((_deploy_with_volume(), _pod(), _rs()))
    monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
    monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
    lease = _pod_lease("k8s.persistent_volume_mount_failure", {"volume": "data"})
    assert K8sWorkloadExecutor().inject(lease).ok is True
    patch = next(call for call in reversed(kube.calls) if call[1] == "patch")
    payload = json.loads(patch[patch.index("-p") + 1])
    mounts = payload["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
    assert next(m for m in mounts if m["name"] == "data")["mountPath"] == "/mayhem/shadow/data"
    assert K8sWorkloadExecutor().undo(lease).ok is True
    restore = next(call for call in reversed(kube.calls) if call[1] == "patch")
    restore_payload = json.loads(restore[restore.index("-p") + 1])
    assert (
        restore_payload["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][-1][
            "mountPath"
        ]
        == "/data"
    )
