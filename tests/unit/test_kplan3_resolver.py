"""k-plan-3 SP-3.1/§3.4 — execution-time Kubernetes resolver.

Pins the seven-step resolution flow (ADR-M7-1 §3.1) against a fake cluster
client: workload lookup, eligible-pod selection with preferred-pod drift,
container presence, evidence capture (pod uid / container id / node /
exec_argv), and the primary-pid guard that feeds the signal-family inject.
"""
from __future__ import annotations

import pytest
from mayhem.agents.k8s_resolve import (
    K8sContainerStatus,
    K8sPod,
    K8sWorkload,
    KubernetesRuntimeResolver,
    _parse_proc_stat,
)
from mayhem.domain.errors import ResolutionError, SelectionError
from mayhem.domain.experiments import TargetScope
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.target import ResourceKind

# ── fake cluster client ───────────────────────────────────────────────────────
class FakeClusterClient:
    def __init__(
        self,
        *,
        workload: K8sWorkload | None,
        pods: list[K8sPod],
        exec_stdout: str = "",
    ) -> None:
        self._workload = workload
        self._pods = pods
        self._exec_stdout = exec_stdout
        self.exec_argv_calls: list[tuple[str, ...]] = []

    def workload(self, workload: K8sWorkload) -> K8sWorkload | None:
        return self._workload

    def pods_for(self, workload: K8sWorkload) -> list[K8sPod]:
        return [p for p in self._pods if p.namespace == workload.namespace]

    def exec(self, target, argv: tuple[str, ...]) -> str:
        self.exec_argv_calls.append(argv)
        return self._exec_stdout


def _pod(
    name: str = "checkout-abc123",
    *,
    phase: str = "Running",
    uid: str = "u-1",
    node: str = "w1",
    container: str = "app",
    running: bool = True,
    terminated: bool = False,
) -> K8sPod:
    return K8sPod(
        uid=uid,
        name=name,
        namespace="production",
        phase=phase,
        node=node,
        deletion_timestamp=("2026-09-13T10:00:00Z" if terminated else None),
        containers=(
            K8sContainerStatus(name=container, container_id="containerd://abc", ready=running),
        ),
        creation_timestamp="2026-01-01T00:00:00Z",
    )


_WORKLOAD = K8sWorkload(namespace="production", kind="deployment", name="checkout")


def _scope(*, container: str | None = "app") -> TargetScope:
    return TargetScope(
        logical_id="checkout",
        runtime=RuntimeLabel.KUBERNETES,
        kind=ResourceKind.DEPLOYMENT,
        authority={"namespace": "production", "kind": "deployment", "name": "checkout"},
        container=container,
    )


def _resolver(client: FakeClusterClient) -> KubernetesRuntimeResolver:
    return KubernetesRuntimeResolver(client=client)


# ── resolution flow ───────────────────────────────────────────────────────────
class TestResolveFlow:
    def test_preferred_eligible_pod_no_drift(self) -> None:
        client = FakeClusterClient(
            workload=_WORKLOAD,
            pods=[_pod("checkout-abcd"), _pod("checkout-xyz", uid="u-2")],
        )
        outcome = _resolver(client).resolve(_scope(), preferred_pod="checkout-abcd")
        assert outcome.resolved is not None
        assert outcome.resolved.pod == "checkout-abcd"
        assert outcome.drift is False
        assert outcome.resolved.pod_uid == "u-1"
        assert outcome.resolved.container_id == "containerd://abc"
        assert outcome.resolved.node == "w1"

    def test_preferred_absent_falls_back_and_reports_drift(self) -> None:
        client = FakeClusterClient(
            workload=_WORKLOAD,
            pods=[_pod("checkout-xyz", uid="u-2")],
        )
        outcome = _resolver(client).resolve(_scope(), preferred_pod="checkout-abcd")
        assert outcome.resolved is not None
        assert outcome.resolved.pod == "checkout-xyz"
        assert outcome.drift is True
        assert "drift" in outcome.note

    def test_no_eligible_pods_raises_selection_error(self) -> None:
        client = FakeClusterClient(
            workload=_WORKLOAD,
            pods=[_pod("pending", phase="Pending", uid="u-3"), _pod("terminating", terminated=True, uid="u-4")],
        )
        with pytest.raises(SelectionError) as exc_info:
            _resolver(client).resolve(_scope())
        assert exc_info.value.code == "selection.no_eligible_pods"

    def test_workload_missing_raises_resource_missing(self) -> None:
        client = FakeClusterClient(
            workload=None,
            pods=[_pod()],
        )
        with pytest.raises(ResolutionError) as exc_info:
            _resolver(client).resolve(_scope())
        assert exc_info.value.code == "resolution.resource_missing"

    def test_container_missing_raises_container_missing(self) -> None:
        client = FakeClusterClient(
            workload=_WORKLOAD,
            pods=[_pod(container="sidecar")],
        )
        with pytest.raises(ResolutionError) as exc_info:
            _resolver(client).resolve(_scope(container="app"))
        assert exc_info.value.code == "resolution.container_missing"
        assert "sidecar" in str(exc_info.value)

    def test_exec_argv_uses_resolved_pod_identity(self) -> None:
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        outcome = _resolver(client).resolve(_scope())
        argv = outcome.resolved.exec_argv  # type: ignore[union-attr]
        assert argv[:3] == ("kubectl", "exec", "-n")
        assert f"pod/checkout-abc123" in argv
        assert argv[-1] == "--"

    def test_primary_pid_guard_reads_proc_stat(self) -> None:
        client = FakeClusterClient(
            workload=_WORKLOAD,
            pods=[_pod()],
            exec_stdout="1 (nginx) S 0 1 1 0 -1 4194560 1 0 0 0 123 45 0 0 20 0 1 0 9999 0 0\n",
        )
        outcome = _resolver(client).resolve(_scope())
        pid, boot = _resolver(client).read_primary_pid(outcome.resolved)  # type: ignore[arg-type]
        assert pid == 1
        assert boot == 9999
        called = client.exec_argv_calls[0]
        assert called[-2:] == ("cat", "/proc/1/stat")

    def test_primary_pid_mismatch_is_loud(self) -> None:
        client = FakeClusterClient(
            workload=_WORKLOAD,
            pods=[_pod()],
            exec_stdout="42 (not-pid-1) S 0 1 1 0 -1 0 0 0 0 1 1 0 0 20 0 1 0 100 0 0\n",
        )
        outcome = _resolver(client).resolve(_scope())
        with pytest.raises(ResolutionError) as exc_info:
            _resolver(client).read_primary_pid(outcome.resolved)  # type: ignore[arg-type]
        assert exc_info.value.code == "resolution.primary_pid_unreadable"

    def test_wrong_runtime_refused(self) -> None:
        scope = _scope().model_copy(update={"runtime": RuntimeLabel.DOCKER})
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        with pytest.raises(ResolutionError) as exc_info:
            _resolver(client).resolve(scope)
        assert exc_info.value.code == "resolution.wrong_runtime"


# ── proc stat parsing ─────────────────────────────────────────────────────────
class TestProcStatParsing:
    def test_comm_with_spaces_and_parentheses(self) -> None:
        pid, boot = _parse_proc_stat("1 (a (weird) name) S 0 1 1 0 -1 4194560 0 0 0 0 1 1 0 0 20 0 1 0 4242 0 0\n")
        assert (pid, boot) == (1, 4242)

    def test_garbage_line_raises(self) -> None:
        with pytest.raises(ResolutionError, match="unreadable"):
            _parse_proc_stat("nonsense")

    def test_unparseable_fields_raise(self) -> None:
        with pytest.raises(ResolutionError, match="unreadable"):
            _parse_proc_stat("1 (x) S 0 1 1 0 -1 4194560 0 0 0 0 1 1 0 0 20 0 1 0")