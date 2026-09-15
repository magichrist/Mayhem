"""Unit tests for the k-plan-6 controller-level fault family rollout.

Covers the 19 new mutation families in ``k8s_new.md``: register admission
(K8S_MUTATION_FAULTS / K8S_REVERSIBLE_FAULTS), executor dispatch, snapshot-
annotated inject/undo for workload/service/config mutations, in-pod storage
workers, uncontrolled pod deletion, node cordon, and the image_pull_slow
catalog-only refusal path.
"""
from __future__ import annotations

import json as _json
from typing import Any

import pytest

from mayhem.agents.executors import (
    K8S_SIGNAL_FAULTS,
    K8sConfigExecutor,
    K8sExecutor,
    K8sNodeCordonExecutor,
    K8sPodDeleteExecutor,
    K8sServiceExecutor,
    K8sStorageExecutor,
    K8sWorkloadExecutor,
    k8s_executor_for,
    k8s_unsupported_reason,
)
from mayhem.agents.k8s_control import RESTORE_ANNOTATION, ResourceRef
from mayhem.controller.k8s_runtime import (
    K8S_MUTATION_FAULTS,
    K8S_NODE_FAULTS,
    K8S_REVERSIBLE_FAULTS,
    k8s_available_faults,
    k8s_node_routing,
    k8s_node_spec,
    k8s_node_undo_ops,
)
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.resolution import ResolvedNodeTarget, ResolvedPodTarget
from mayhem.toolkit.tool_runner import ToolResult

# ── shared test objects ─────────────────────────────────────────────────────────

_EXEC_TARGET = ResolvedPodTarget(
    namespace="prod",
    pod="checkout-abc123",
    container="app",
    pod_uid="u-1",
    node="w1",
    labels={"app": "checkout"},
    pod_action="readiness_fail",
    exec_argv=("kubectl", "exec", "checkout-abc123", "-n", "prod", "-c", "app", "--"),
)

_CORDON_TARGET = ResolvedNodeTarget(
    node="w2",
    node_uid="n-2",
    ready=True,
    unschedulable=False,
    labels={"kubernetes.io/role": "worker"},
    node_action="cordon",
)


def _target(**overrides: Any) -> ResolvedPodTarget:
    data = _EXEC_TARGET.model_dump()
    data.update(overrides)
    return ResolvedPodTarget(**data)


def _pod_target() -> ResolvedPodTarget:
    return _target()


def _lease(
    fault_id: str,
    *,
    resolved_target: ResolvedPodTarget | ResolvedNodeTarget | None = None,
    params: dict[str, object] | None = None,
    ttl: float = 120.0,
):
    from mayhem.domain.leases import FaultLease, LeaseState, VerifyProbe  # noqa: PLC0415

    target = resolved_target or (_CORDON_TARGET if "node" in fault_id else _pod_target())
    if params is not None:
        import json as _j  # noqa: PLC0415
        from mayhem.domain.experiments import UndoOp  # noqa: PLC0415
        undo_ops = (UndoOp(op="k8s.controller", args={"params": _j.dumps(params)}),)
    else:
        from mayhem.domain.experiments import UndoOp  # noqa: PLC0415
        undo_ops = (UndoOp(op="k8s.undo", args={}),)
    return FaultLease(
        id="l-6",
        run_id="rk6",
        fault_id=fault_id,
        owner_agent="engine",
        targets=frozenset({getattr(target, "pod", target.node if hasattr(target, "node") else "?")}),
        undo_ops=undo_ops,
        verify_probes=(VerifyProbe(probe="k8s.undo", args={}),),
        ttl_seconds=ttl,
        state=LeaseState.ACTIVE,
        resolved_target=target,
    )


# ── fake kubectl harness ───────────────────────────────────────────────────────


class _FakeKube:
    """Stateful kubectl replacement for executor unit tests.

    Records every call and writes annotated state so inject→undo sequences
    follow the same annotation lifecycle as a real cluster.
    """

    def __init__(
        self,
        objects: tuple[dict[str, Any], ...] = (),
        *,
        fail_on: tuple[str, ...] = (),
    ) -> None:
        self.objects: dict[tuple[str, str, str], dict[str, Any]] = {}
        for obj in objects:
            ns = obj.get("metadata", {}).get("namespace", "default")
            key = (obj["kind"], obj["metadata"]["name"], ns)
            self.objects[key] = obj
        self.calls: list[tuple[str, ...]] = []
        self.stdin: list[str | None] = []
        self.fail_on = set(fail_on)

    def _run(self, argv: tuple[str, ...], **kwargs: Any) -> ToolResult:
        self.calls.append(argv)
        self.stdin.append(kwargs.get("stdin_data"))
        joined = " ".join(argv)
        if any(m in joined for m in self.fail_on):
            return self._result(exit_code=1, stdout="fail")
        if not argv or argv[0] != "kubectl":
            return self._ok()
        verb = argv[1]
        if verb == "annotate":
            return self._do_annotate(argv)
        if verb == "get":
            return self._do_get(argv)
        if verb == "patch":
            return self._do_patch(argv)
        if verb == "apply":
            return self._ok()  # apply -f - (secret recreate)
        if verb == "exec":
            return self._ok()
        if verb in ("scale", "rollout", "cordon", "uncordon", "drain"):
            return self._ok()
        if verb == "delete":
            kind, name, ns = argv[2], argv[3], self._ns(argv)
            self.objects.pop((self._canonical(kind), name, ns), None)
            return self._ok(f"{name} deleted")
        return self._ok()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _ok(self, stdout: str = "") -> ToolResult:
        return self._result(exit_code=0, stdout=stdout)

    def _result(self, *, exit_code: int, stdout: str) -> ToolResult:
        return ToolResult(
            argv=(),
            argv_digest="",
            env_digest="",
            host="",
            cwd=None,
            exit_code=exit_code,
            duration_ms=1,
            stdout=stdout,
            stderr="",
            truncated=False,
        )

    @staticmethod
    def _ns(argv: tuple[str, ...]) -> str:
        try:
            i = argv.index("-n")
            return argv[i + 1]
        except (ValueError, IndexError):
            return "default"

    _KIND_ALIASES = {"svc": "Service", "cm": "ConfigMap", "rs": "ReplicaSet", "deploy": "Deployment", "secret": "Secret", "pod": "Pod", "node": "Node"}

    def _canonical(self, kind: str) -> str:
        return self._KIND_ALIASES.get(kind, kind)

    def _do_annotate(self, argv: tuple[str, ...]) -> ToolResult:
        kind, name, ns = argv[2], argv[3], self._ns(argv)
        key = (kind, name, ns)
        obj = self.objects.get(key, {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": ns, "annotations": {}}})
        ann_raw = argv[6] if len(argv) > 6 else ""
        anns = obj.setdefault("metadata", {}).setdefault("annotations", {})
        if ann_raw.endswith("-"):
            anns.pop(RESTORE_ANNOTATION, None)
        elif "=" in ann_raw:
            anns[RESTORE_ANNOTATION] = ann_raw.split("=", 1)[1]
        self.objects[key] = obj
        return self._ok()

    def _do_get(self, argv: tuple[str, ...]) -> ToolResult:
        flags_start = next((i for i in range(2, len(argv)) if argv[i].startswith("-")), len(argv))
        pos = [argv[i] for i in range(2, flags_start)]
        ns = self._ns(argv)
        if len(pos) == 2:
            kind, name = self._canonical(pos[0]), pos[1]
            obj = self.objects.get((kind, name, ns))
            if obj is None:
                return self._ok("{}")
            return self._ok(_json.dumps(obj))
        kinds = [self._canonical(k) for k in pos]
        items = [o for (k, _n, ns2), o in self.objects.items() if k in kinds and ns2 == ns]
        return self._ok(_json.dumps({"items": items}))

    def _do_patch(self, argv: tuple[str, ...]) -> ToolResult:
        import copy as _copy  # noqa: PLC0415

        kind, name, ns = argv[2], argv[3], self._ns(argv)
        patch_payload = argv[argv.index("-p") + 1] if "-p" in argv else "{}"
        p = _json.loads(patch_payload)
        obj = _copy.deepcopy(
            self.objects.get(
                (kind, name, ns),
                {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": ns, "annotations": {}}},
            )
        )
        spec = obj.get("spec") or {}
        for k, v in p.items():
            if k == "spec":
                if isinstance(spec, dict) and isinstance(v, dict):
                    spec.update(v)
                obj["spec"] = v
            else:
                obj[k] = v
        obj["spec"] = spec if "spec" not in p else obj["spec"]
        self.objects[(kind, name, ns)] = obj
        return self._ok(f"{kind}/{name} patched")


def _deploy() -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "checkout", "namespace": "prod", "uid": "d-1", "annotations": {}},
        "spec": {
            "replicas": 2,
            "selector": {"matchLabels": {"app": "checkout"}},
            "template": {
                "metadata": {"labels": {"app": "checkout"}},
                "spec": {
                    "schedulerName": "default-scheduler",
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:1.27",
                            "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
                        }
                    ],
                },
            },
        },
    }


def _svc() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "checkout-svc", "namespace": "prod", "annotations": {}},
        "spec": {
            "selector": {"app": "checkout"},
            "ports": [{"port": 80, "targetPort": 8080}],
        },
    }


def _cm() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "checkout-cfg", "namespace": "prod", "annotations": {}},
        "data": {"DB_HOST": "db.prod.svc"},
    }


def _secret() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "mayhem-creds", "namespace": "prod", "annotations": {}},
        "type": "Opaque",
        "data": {"key": "c2VjcmV0"},
    }


def _pod() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "checkout-abc123",
            "namespace": "prod",
            "annotations": {},
            "ownerReferences": [
                {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "checkout-7f8d9", "uid": "rs-1"}
            ],
        },
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx:1.27",
                    "volumeMounts": [
                        {"name": "cfg", "mountPath": "/etc/cfg"},
                        {"name": "creds", "mountPath": "/etc/creds"},
                        {"name": "data", "mountPath": "/data"},
                    ],
                }
            ],
            "volumes": [
                {"name": "cfg", "configMap": {"name": "checkout-cfg"}},
                {"name": "creds", "secret": {"secretName": "mayhem-creds"}},
                {"name": "data", "persistentVolumeClaim": {"claimName": "checkout-db"}},
            ],
        },
    }


def _rs() -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "checkout-7f8d9",
            "namespace": "prod",
            "ownerReferences": [
                {"apiVersion": "apps/v1", "kind": "Deployment", "name": "checkout", "uid": "d-1"}
            ],
        },
    }


_DEFAULT_OBJECTS = (_deploy(), _svc(), _cm(), _secret(), _pod(), _rs())


def _kube(objects: tuple[dict[str, Any], ...] = _DEFAULT_OBJECTS, **kw: Any) -> _FakeKube:
    return _FakeKube(objects, **kw)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Runtime registers
# ═══════════════════════════════════════════════════════════════════════════════

_NEW_MUTATION = (
    "k8s.pod_readiness_fail",
    "k8s.pod_liveness_fail",
    "k8s.pod_startup_fail",
    "k8s.pod_unschedulable",
    "k8s.schedule_delay",
    "k8s.image_pull_failure",
    "k8s.replica_reduce",
    "k8s.rollout_pause",
    "k8s.rollout_failure",
    "k8s.persistent_volume_detach",
    "k8s.service_no_endpoints",
    "k8s.service_endpoint_flap",
    "k8s.service_port_mismatch",
    "k8s.configmap_corrupt",
    "k8s.secret_unavailable",
    "k8s.persistent_volume_delay",
    "k8s.persistent_volume_error",
    "k8s.pod_delete_uncontrolled",
)


class TestRegisters:
    def test_new_mutation_faults_in_mutation_set(self) -> None:
        for fid in _NEW_MUTATION:
            assert fid in K8S_MUTATION_FAULTS, fid

    def test_all_mutation_faults_are_reversible_except_pod_lifecycle(self) -> None:
        IRREVERSIBLE = {"k8s.pod_kill", "k8s.pod_evict", "k8s.pod_oom", "k8s.pod_delete_uncontrolled"}
        for fid in K8S_MUTATION_FAULTS:
            if fid not in IRREVERSIBLE:
                assert fid in K8S_REVERSIBLE_FAULTS, fid

    def test_cordon_lives_in_node_faults(self) -> None:
        assert "k8s.node_cordon" in K8S_NODE_FAULTS

    def test_image_pull_slow_excluded_from_mutation(self) -> None:
        assert "k8s.image_pull_slow" not in K8S_MUTATION_FAULTS

    def test_image_pull_slow_not_in_available_faults(self) -> None:
        assert "k8s.image_pull_slow" not in k8s_available_faults()

    def test_node_routing_maps_cordon(self) -> None:
        assert k8s_node_routing().get("k8s.node_cordon") == "k8s.node"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Executor dispatch
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecutorDispatch:
    @pytest.mark.parametrize(
        "fault_id,expected",
        [
            ("k8s.pod_readiness_fail", K8sWorkloadExecutor),
            ("k8s.pod_liveness_fail", K8sWorkloadExecutor),
            ("k8s.pod_startup_fail", K8sWorkloadExecutor),
            ("k8s.pod_unschedulable", K8sWorkloadExecutor),
            ("k8s.schedule_delay", K8sWorkloadExecutor),
            ("k8s.image_pull_failure", K8sWorkloadExecutor),
            ("k8s.replica_reduce", K8sWorkloadExecutor),
            ("k8s.rollout_pause", K8sWorkloadExecutor),
            ("k8s.rollout_failure", K8sWorkloadExecutor),
            ("k8s.persistent_volume_detach", K8sWorkloadExecutor),
            ("k8s.service_no_endpoints", K8sServiceExecutor),
            ("k8s.service_endpoint_flap", K8sServiceExecutor),
            ("k8s.service_port_mismatch", K8sServiceExecutor),
            ("k8s.configmap_corrupt", K8sConfigExecutor),
            ("k8s.secret_unavailable", K8sConfigExecutor),
            ("k8s.persistent_volume_delay", K8sStorageExecutor),
            ("k8s.persistent_volume_error", K8sStorageExecutor),
            ("k8s.pod_delete_uncontrolled", K8sPodDeleteExecutor),
            ("k8s.node_cordon", K8sNodeCordonExecutor),
        ],
    )
    def test_dispatches_to_dedicated_class(self, fault_id: str, expected: type) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        assert isinstance(executor, expected)

    def test_unknown_mutation_falls_back_to_base_unsupported(self) -> None:
        executor = k8s_executor_for("k8s.image_pull_slow", RuntimeLabel.KUBERNETES)
        assert isinstance(executor, K8sExecutor)
        assert executor.can_apply(_lease("k8s.image_pull_slow")) is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 3. can_apply guards
# ═══════════════════════════════════════════════════════════════════════════════

class TestCanApply:
    def test_workload_executor_accepts_readiness(self) -> None:
        assert K8sWorkloadExecutor().can_apply(_lease("k8s.pod_readiness_fail")) is None

    def test_workload_executor_allows_daemonset_at_can_apply(self) -> None:
        # Replica reduce with an unsupported workload kind requires inject to refuse;
        # can_apply only checks target type, not workload kind (inject does).
        assert K8sWorkloadExecutor().can_apply(_lease("k8s.replica_reduce")) is None

    def test_service_executor_requires_pod_target(self) -> None:
        from mayhem.domain.leases import FaultLease, LeaseState, VerifyProbe  # noqa: PLC0415
        from mayhem.domain.experiments import UndoOp  # noqa: PLC0415
        bad = FaultLease(
            id="l-bad", run_id="r", fault_id="k8s.service_no_endpoints", owner_agent="engine",
            targets=frozenset(), undo_ops=(UndoOp(op="k8s.undo", args={}),),
            verify_probes=(VerifyProbe(probe="k8s.undo", args={}),),
            ttl_seconds=60, state=LeaseState.ACTIVE, resolved_target=None,
        )
        assert K8sServiceExecutor().can_apply(bad) is not None

    def test_node_cordon_requires_node_target(self) -> None:
        assert K8sNodeCordonExecutor().can_apply(_lease("k8s.node_cordon", resolved_target=_CORDON_TARGET)) is None


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Workload executor inject / undo
# ═══════════════════════════════════════════════════════════════════════════════

class TestWorkloadExecutor:
    def test_readiness_fail_inject_flips_probe(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        lease = _lease("k8s.pod_readiness_fail")
        outcome = K8sWorkloadExecutor().inject(lease)
        assert outcome.ok is True
        # Snapshot annotated on Deployment
        dep = kube.objects.get(("Deployment", "checkout", "prod"))
        assert dep is not None
        ann = dep["metadata"]["annotations"].get(RESTORE_ANNOTATION)
        assert ann is not None
        snap = _json.loads(ann)
        assert "spec" in snap and "replicas" in snap["spec"]
        # Patch issued with false readiness probe
        patch_calls = [c for c in kube.calls if c[1] == "patch"]
        assert patch_calls
        patch_payload = _json.loads(patch_calls[-1][patch_calls[-1].index("-p") + 1])
        container = patch_payload["spec"]["template"]["spec"]["containers"][0]
        assert container["readinessProbe"] == {"exec": {"command": ["/bin/sh", "-c", "/bin/false"]}}

    def test_readiness_fail_undo_restores_probe(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        executor = K8sWorkloadExecutor()
        # Pre-annotate with the snapshot
        executor.inject(_lease("k8s.pod_readiness_fail"))
        lease = _lease("k8s.pod_readiness_fail")
        outcome = executor.undo(lease)
        assert outcome.ok is True
        ann = kube.objects.get(("Deployment", "checkout", "prod"))["metadata"]["annotations"]
        assert RESTORE_ANNOTATION not in ann
        patch_calls = [c for c in kube.calls if c[1] == "patch"]
        restore = _json.loads(patch_calls[-1][patch_calls[-1].index("-p") + 1])
        assert restore["spec"]["template"]["spec"]["containers"][0]["readinessProbe"] == {
            "httpGet": {"path": "/ready", "port": 8080}
        }

    def test_replica_reduce_scales_zero(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        lease = _lease("k8s.replica_reduce", params={"replicas": 0})
        outcome = K8sWorkloadExecutor().inject(lease)
        assert outcome.ok is True
        scale_calls = [c for c in kube.calls if c[1] == "scale"]
        assert scale_calls

    def test_rollout_pause_issues_pause(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        lease = _lease("k8s.rollout_pause")
        outcome = K8sWorkloadExecutor().inject(lease)
        assert outcome.ok is True
        rollout_calls = [c for c in kube.calls if c[1] == "rollout"]
        assert any("pause" in c for c in rollout_calls)
        ann = _json.loads(kube.objects[("Deployment", "checkout", "prod")]["metadata"]["annotations"][RESTORE_ANNOTATION])
        assert ann["rollout_paused"] == "true"

    def test_unsupported_fault_refused_by_workload_executor(self) -> None:
        assert K8sWorkloadExecutor().can_apply(_lease("k8s.image_pull_slow")) is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Service executor
# ═══════════════════════════════════════════════════════════════════════════════

class TestServiceExecutor:
    def test_no_endpoints_inject_changes_selector(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        lease = _lease("k8s.service_no_endpoints", params={"selector_key": "bad", "selector_value": "gone"})
        outcome = K8sServiceExecutor().inject(lease)
        assert outcome.ok is True
        patch_calls = [c for c in kube.calls if c[1] == "patch"]
        payload = _json.loads(patch_calls[-1][patch_calls[-1].index("-p") + 1])
        assert payload["spec"]["selector"] == {"bad": "gone"}

    def test_port_mismatch_injects_broken_port(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        lease = _lease("k8s.service_port_mismatch")
        outcome = K8sServiceExecutor().inject(lease)
        assert outcome.ok is True
        patch_calls = [c for c in kube.calls if c[1] == "patch"]
        payload = _json.loads(patch_calls[-1][patch_calls[-1].index("-p") + 1])
        assert payload["spec"]["ports"][0]["targetPort"] == 8081


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Configmap corrupt
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigExecutor:
    def test_configmap_corrupt_and_undo(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        executor = K8sConfigExecutor()
        lease = _lease("k8s.configmap_corrupt", params={"configmap": "checkout-cfg", "prefix": "bad-"})
        inject = executor.inject(lease)
        assert inject.ok is True
        ann = _json.loads(kube.objects[("ConfigMap", "checkout-cfg", "prod")]["metadata"]["annotations"][RESTORE_ANNOTATION])
        assert ann["data"] == {"DB_HOST": "db.prod.svc"}
        patch_calls = [c for c in kube.calls if c[1] == "patch"]
        patched = _json.loads(patch_calls[-1][patch_calls[-1].index("-p") + 1])
        assert patched["data"]["DB_HOST"].startswith("bad-")
        undo = executor.undo(lease)
        assert undo.ok is True
        restore_patches = [c for c in kube.calls if c[1] == "patch"]
        restored = _json.loads(restore_patches[-1][restore_patches[-1].index("-p") + 1])
        assert restored["data"]["DB_HOST"] == "db.prod.svc"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Secret unavailable (recreate-on-undo)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecretExecutor:
    def test_inject_deletes_secret_annotates_pod(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        lease = _lease("k8s.secret_unavailable", params={"name": "mayhem-creds"})
        outcome = K8sConfigExecutor().inject(lease)
        assert outcome.ok is True
        # Secret removed from state
        assert ("Secret", "mayhem-creds", "prod") not in kube.objects
        # Pod annotated with snapshot
        pod = kube.objects[("Pod", "checkout-abc123", "prod")]
        ann = _json.loads(pod["metadata"]["annotations"][RESTORE_ANNOTATION])
        assert ann["secret"]["name"] == "mayhem-creds"
        assert ann["secret"]["data"] == {"key": "c2VjcmV0"}

    def test_undo_recreates_secret(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        executor = K8sConfigExecutor()
        executor.inject(_lease("k8s.secret_unavailable", params={"name": "mayhem-creds"}))
        lease = _lease("k8s.secret_unavailable", params={"name": "mayhem-creds"})
        outcome = executor.undo(lease)
        assert outcome.ok is True
        # Secret recreated via apply -f -
        apply_calls = [c for c in kube.calls if c[1] == "apply"]
        assert apply_calls
        apply_payload = _json.loads(kube.stdin[kube.calls.index(apply_calls[0])])
        assert apply_payload["kind"] == "Secret"
        assert apply_payload["metadata"]["name"] == "mayhem-creds"
        # Pod annotation cleared
        pod_ann = kube.objects.get(("Pod", "checkout-abc123", "prod"), {}).get("metadata", {}).get("annotations", {})
        assert RESTORE_ANNOTATION not in pod_ann

    def test_delete_refuses_non_synthetic(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        lease = _lease("k8s.secret_unavailable", params={"synthetic": "false", "name": "real-secret"})
        outcome = K8sConfigExecutor().inject(lease)
        assert outcome.ok is False
        assert "non-mayhem" in outcome.detail


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Pod delete uncontrolled
# ═══════════════════════════════════════════════════════════════════════════════

class TestPodDeleteExecutor:
    def test_inject_force_deletes(self, monkeypatch) -> None:
        kube = _kube()
        monkeypatch.setattr("mayhem.agents.executors.run_tool", kube._run)
        monkeypatch.setattr("mayhem.agents.k8s_control.run_tool", kube._run)
        lease = _lease("k8s.pod_delete_uncontrolled")
        outcome = K8sPodDeleteExecutor().inject(lease)
        assert outcome.ok is True
        delete_calls = [c for c in kube.calls if c[1] == "delete"]
        assert delete_calls
        assert "--force" in delete_calls[0] or "--grace-period=0" in delete_calls[0]

    def test_undo_is_always_ok(self) -> None:
        assert K8sPodDeleteExecutor().undo(_lease("k8s.pod_delete_uncontrolled")).ok is True


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Storage executors (in-pod)
# ═══════════════════════════════════════════════════════════════════════════════

class TestStorageExecutor:
    def test_pv_delay_uses_exec(self, monkeypatch) -> None:
        calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(calls, ok_stdout="ok"))
        lease = _lease("k8s.persistent_volume_delay")
        outcome = K8sStorageExecutor().inject(lease)
        assert outcome.ok is True
        exec_calls = [c for c in calls if c[1] == "exec"]
        assert exec_calls
        sh_cmd = exec_calls[0][-1]
        assert "chmod 000" in sh_cmd and "sleep" in sh_cmd

    def test_undo_reaps_worker(self, monkeypatch) -> None:
        calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(calls, ok_stdout="ok"))
        lease = _lease("k8s.persistent_volume_error")
        outcome = K8sStorageExecutor().undo(lease)
        assert outcome.ok is True
        exec_calls = [c for c in calls if c[1] == "exec"]
        assert exec_calls
        sh_cmd = " ".join(exec_calls[0])
        assert "xargs kill" in sh_cmd


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Node cordon
# ═══════════════════════════════════════════════════════════════════════════════

class TestNodeCordonExecutor:
    def test_inject_cordons(self, monkeypatch) -> None:
        calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(calls))
        lease = _lease("k8s.node_cordon", resolved_target=_CORDON_TARGET)
        outcome = K8sNodeCordonExecutor().inject(lease)
        assert outcome.ok is True
        cordon = [c for c in calls if c[1] == "cordon"]
        assert cordon
        assert cordon[0][2] == "w2"

    def test_undo_uncordons(self, monkeypatch) -> None:
        calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(calls))
        lease = _lease("k8s.node_cordon", resolved_target=_CORDON_TARGET)
        outcome = K8sNodeCordonExecutor().undo(lease)
        assert outcome.ok is True
        uncordon = [c for c in calls if c[1] == "uncordon"]
        assert uncordon
        assert uncordon[0][2] == "w2"


def _fake_tool(calls: list, ok_stdout: str = "", fail_on: tuple[str, ...] = ()):
    def _run(argv: tuple[str, ...], **kwargs: Any) -> ToolResult:
        calls.append(argv)
        joined = " ".join(argv)
        if any(m in joined for m in fail_on):
            return ToolResult(argv=argv, argv_digest="", env_digest="", host="", cwd=None, exit_code=1, duration_ms=1, stdout="", stderr="fail", truncated=False)
        return ToolResult(argv=argv, argv_digest="", env_digest="", host="", cwd=None, exit_code=0, duration_ms=1, stdout=ok_stdout, stderr="", truncated=False)
    return _run
