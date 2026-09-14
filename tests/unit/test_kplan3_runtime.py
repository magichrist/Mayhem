"""k-plan-3 — RunEngine Kubernetes delivery + runtime adapter wiring (SP-3.4).

Pins the execution-side contract: the engine routes kubernetes steps through
the resolved pod (kubectl exec driver), records the resolved target on the
lease, and fails loud with the stable ``k8s.unsupported`` refusal for families
this milestone refuses — before any lease forms or mutation happens.
"""
from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from mayhem.agents.k8s_resolve import (
    K8sContainerStatus,
    K8sPod,
    K8sWorkload,
    KubernetesRuntimeResolver,
)
from mayhem.controller.executor import RunEngine
from mayhem.controller.k8s_runtime import (
    k8s_undo_spec,
    make_k8s_resolver,
    preferred_pod_from_graph,
)
from mayhem.controller.planner import plan_drill
from mayhem.domain.events import Event, EventKind
from mayhem.domain.experiments import (
    DrillSpec,
    ExecutionPlan,
    ExperimentKind,
    PlannedFault,
    PlannedStep,
    Wait,
)
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.leases import LeaseState, UndoOp
from mayhem.domain.target import ResourceKind, SelectionMode, SelectionSpec, TargetScope
from mayhem.domain.topology import PodNode, TopologyGraph
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store
from mayhem.toolkit.tool_runner import ToolResult

# ── fakes ─────────────────────────────────────────────────────────────────────
class FakeClusterClient:
    def __init__(
        self,
        *,
        workload: K8sWorkload | None,
        pods: list[K8sPod],
        exec_stdout: str = "",
        fail_exec_on: tuple[str, ...] = (),
        pod_sequence: list[list[K8sPod]] | None = None,
    ) -> None:
        self._workload = workload
        self._pods = pods
        self._pod_sequence = list(pod_sequence or [])
        self._exec_stdout = exec_stdout
        self._fail_exec_on = fail_exec_on
        self.exec_calls: list[tuple[str, ...]] = []
        self.pods_calls = 0

    def workload(self, workload: K8sWorkload) -> K8sWorkload | None:
        return self._workload

    def pods_for(self, workload: K8sWorkload) -> list[K8sPod]:
        self.pods_calls += 1
        if self._pod_sequence:
            return self._pod_sequence.pop(0)
        return [p for p in self._pods if p.namespace == workload.namespace]

    def exec(self, target: Any, argv: tuple[str, ...]) -> str:
        self.exec_calls.append(argv)
        if any(marker in " ".join(argv) for marker in self._fail_exec_on):
            raise RuntimeError(f"exec failed for {argv[-3:]}")
        if "cat" in argv and "/proc/1/stat" in argv:
            return "1 (nginx) S 0 1 1 0 -1 4194560 1 0 0 0 123 45 0 0 20 0 1 0 9999 0 0"
        return self._exec_stdout


def _pod() -> K8sPod:
    return K8sPod(
        uid="u-1",
        name="checkout-abc123",
        namespace="production",
        phase="Running",
        node="w1",
        containers=(K8sContainerStatus(name="app", container_id="containerd://abc", ready=True),),
        creation_timestamp="2026-01-01T00:00:00Z",
    )


def _replacement_pod() -> K8sPod:
    return replace(_pod(), uid="u-2", name="checkout-def456")


_WORKLOAD = K8sWorkload(namespace="production", kind="deployment", name="checkout")


def _fake_tool(
    calls: list,
    ok_stdout: str = "",
    fail_on: tuple[str, ...] = (),
):
    def _run(argv: tuple[str, ...], **kwargs: Any) -> ToolResult:
        calls.append(tuple(argv))
        joined = " ".join(argv)
        fail = any(marker in joined for marker in fail_on)
        return ToolResult(
            argv=tuple(argv),
            argv_digest="d",
            env_digest="e",
            host="h",
            cwd=None,
            exit_code=1 if fail else 0,
            duration_ms=1,
            stdout="boom" if fail else ok_stdout,
            stderr="",
            truncated=False,
        )

    return _run


def _scope() -> TargetScope:
    return TargetScope(
        logical_id="checkout",
        runtime=RuntimeLabel.KUBERNETES,
        kind=ResourceKind.DEPLOYMENT,
        authority={"namespace": "production", "kind": "deployment", "name": "checkout"},
        container="app",
    )


def _plan(fault_id: str = "proc.pause", *, duration: str = "0.1s") -> ExecutionPlan:
    scope = _scope()
    fault = PlannedFault(
        fault_id=fault_id,
        targets=(),
        target=scope,
        undo_ops=(UndoOp(op="k8s.exec", args={"undo_command": "CONT"}),),
        duration=duration,
    )
    step = PlannedStep(id="k8s-0000", seq=0, fault=fault, raw_action=Wait(type="wait", duration=0.0))
    return ExecutionPlan(
        run_id="rk3-e2e",
        kind=ExperimentKind.DRILL,
        steps=(step,),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def _plan_from_spec() -> ExecutionPlan:
    spec = DrillSpec.model_validate(
        {
            "kind": "drill",
            "name": "k8s-drill",
            "targets": {
                "checkout": {
                    "runtime": "kubernetes",
                    "kubernetes": {"kind": "deployment", "namespace": "production", "name": "checkout"},
                    "faults": [{"fault": "k8s.pod_latency", "duration": "1s"}],
                }
            },
            "execution": [{"sequential": ["checkout"]}],
        }
    )
    graph = TopologyGraph(
        nodes=(
            PodNode(
                id="pod-checkout-2",
                name="checkout-abc123",
                namespace="production",
                image="checkout:latest",
                state="Running",
                owner_kind="Deployment",
                owner_name="checkout",
            ),
        ),
        edges=(),
    )
    return plan_drill(
        "rk3-plan",
        spec,
        graph,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(PodNode(id="pod-checkout", name="checkout-abc123", namespace="production", image="x", state="Running"),),
        edges=(),
    )



def _all_leases(store: Store) -> list:
    sink = SQLiteLeaseSink(store)
    rows = store.query("SELECT id FROM fault_leases ORDER BY created_epoch_s")
    return [sink.load(str(row["id"])) for row in rows]


def _engine(
    store: Store,
    client: FakeClusterClient,
    *,
    resolver: KubernetesRuntimeResolver | None = None,
    recovery_grace: float = 10.0,
) -> tuple[RunEngine, list[Event]]:
    events: list[Event] = []
    engine = RunEngine(
        store,
        SQLiteLeaseSink(store),
        sleeper=lambda _seconds: None,
        live_graph=lambda: _graph(),
        on_event=events.append,
        k8s_resolver=resolver or KubernetesRuntimeResolver(client=client),
        recovery_grace=recovery_grace,
    )
    return engine, events


# ── adapter helpers ───────────────────────────────────────────────────────────
class TestK8sRuntimeAdapter:
    def test_undo_spec_carries_write_ahead_contract(self) -> None:
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        resolver = KubernetesRuntimeResolver(client=client)
        outcome = resolver.resolve(_scope())
        spec = k8s_undo_spec("proc.pause", outcome.resolved, pid=1, boot=4242)  # type: ignore[arg-type]
        args = cast(dict[str, str], spec["args"])
        assert spec["op"] == "k8s.exec"
        assert args["undo_command"] == "CONT"
        assert args["pid"] == "1"
        assert args["boot"] == "4242"
        assert args["pod"] == "checkout-abc123"
        assert args["namespace"] == "production"
        assert args["exec_argv"].startswith("kubectl exec -n production pod/checkout-abc123")

    def test_preferred_pod_from_graph(self) -> None:
        graph = _graph()
        assert preferred_pod_from_graph(lambda: graph, frozenset({"pod-checkout"})) == "checkout-abc123"

    def test_preferred_pod_from_graph_none_without_match(self) -> None:
        assert preferred_pod_from_graph(lambda: _graph(), frozenset({"nope"})) is None

    def test_make_k8s_resolver_passes_injected_resolver_through(self) -> None:
        resolver = KubernetesRuntimeResolver(client=None)
        assert make_k8s_resolver(resolver) is resolver

    def test_make_k8s_resolver_returns_none_when_no_client(self) -> None:
        if shutil.which("kubectl") is not None:
            pytest.skip("kubectl present; default resolver would be real")
        assert make_k8s_resolver(None) is None


# ── engine execution ──────────────────────────────────────────────────────────
class TestEngineK8sStep:
    def test_signal_step_injects_and_recovers_cleanly(self, tmp_path: Path, monkeypatch) -> None:
        tool_calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(tool_calls))
        store = Store.open_migrated(tmp_path / "rk3.db")
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        events: list[Event] = []
        engine = RunEngine(
            store,
            SQLiteLeaseSink(store),
            sleeper=lambda _s: None,
            live_graph=lambda: _graph(),
            on_event=events.append,
            k8s_resolver=KubernetesRuntimeResolver(client=client),
        )
        result = engine.execute(_plan())
        assert result.steps[0].ok is True
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.RELEASED
        assert lease.release_mechanism == "normal"
        assert lease.resolved_target is not None
        assert lease.resolved_target.pod == "checkout-abc123"
        assert lease.resolved_target.exec_argv[0] == "kubectl"
        assert lease.undo_ops[0].op == "k8s.exec"
        assert lease.undo_ops[0].args["undo_command"] == "CONT"
        kinds = {e.kind for e in events}
        assert EventKind.FAULT_INJECTED in kinds
        assert EventKind.FAULT_RECOVERED in kinds
        guard = client.exec_calls[0]
        assert guard[-2:] == ("cat", "/proc/1/stat")
        signals = [arg for argv in tool_calls for arg in argv if arg.startswith("-")]
        assert "-STOP" in signals and "-CONT" in signals

    def test_pod_kill_mutation_waits_for_replacement(self, tmp_path: Path, monkeypatch) -> None:
        """k-plan-4 §4.5: irreversible pod kill releases once a replacement runs."""
        tool_calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(tool_calls))
        store = Store.open_migrated(tmp_path / "rk3-mutation.db")
        client = FakeClusterClient(
            workload=_WORKLOAD,
            pods=[_pod()],
            pod_sequence=[[_pod()], [_replacement_pod()]],
        )
        engine, events = _engine(store, client)
        result = engine.execute(_plan("k8s.pod_kill"))
        assert result.steps[0].ok is True
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.RELEASED
        assert lease.release_mechanism == "normal"
        assert lease.resolved_target is not None
        assert lease.resolved_target.pod == "checkout-abc123"
        assert any(e.kind == EventKind.FAULT_RECOVERED for e in events)
        deletes = [
            argv for argv in tool_calls
            if argv[:2] == ("kubectl", "delete") and "pod" in argv
        ]
        assert deletes and "--grace-period" in deletes[0]

    def test_pod_kill_without_replacement_marks_dirty(self, tmp_path: Path, monkeypatch) -> None:
        """Compensation window expiring with no replacement ⇒ DIRTY lease."""
        tool_calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(tool_calls))
        store = Store.open_migrated(tmp_path / "rk3-mutation-dirty.db")
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        engine, events = _engine(store, client, recovery_grace=10.0)
        result = engine.execute(_plan("k8s.pod_kill"))
        assert result.steps[0].ok is False
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.DIRTY
        assert "replacement" in (lease.escalation_notes or "")
        assert any(e.kind == EventKind.FAULT_FAILED for e in events)

    def test_pod_pressure_reverses_live_undone(self, tmp_path: Path, monkeypatch) -> None:
        """k-plan-4 §4.4: pod_pressure release is pure live undo (no replacement)."""
        tool_calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(tool_calls))
        store = Store.open_migrated(tmp_path / "rk3-pressure.db")
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        engine, events = _engine(store, client)
        result = engine.execute(_plan("k8s.pod_pressure"))
        assert result.steps[0].ok is True
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.RELEASED
        assert lease.release_mechanism == "normal"
        assert any(e.kind == EventKind.FAULT_RECOVERED for e in events)

    def test_pod_partition_applies_and_revokes_network_policy(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """k-plan-4 §4.1: pod_partition routes through the network-policy executor."""
        tool_calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(tool_calls))
        store = Store.open_migrated(tmp_path / "rk3-partition.db")
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        engine, events = _engine(store, client)
        result = engine.execute(_plan("k8s.pod_partition"))
        assert result.steps[0].ok is True
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.RELEASED
        assert lease.release_mechanism == "normal"
        assert lease.resolved_target is not None
        assert lease.resolved_target.pod == "checkout-abc123"
        applies = [a for a in tool_calls if "apply" in a]
        deletes = [a for a in tool_calls if "delete" in a and "networkpolicy" in a]
        assert applies, "partition must apply a NetworkPolicy"
        assert deletes, "reversible undo must delete the NetworkPolicy"
        assert any(e.kind == EventKind.FAULT_RECOVERED for e in events)

    def test_inject_failure_on_kill_releases_without_mutation(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        tool_calls: list = []
        monkeypatch.setattr(
            "mayhem.agents.executors.run_tool",
            _fake_tool(tool_calls, fail_on=("delete",)),
        )
        store = Store.open_migrated(tmp_path / "rk3-mutation-inject.db")
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        engine, _events = _engine(store, client)
        result = engine.execute(_plan("k8s.pod_kill"))
        assert result.steps[0].ok is False
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.RELEASED
        assert lease.release_mechanism == "inject_failed"

    def test_pod_kill_multi_instance_selection(self, tmp_path: Path, monkeypatch) -> None:
        """k-plan-4 §4.2: count-mode selection leases one lease per resolved pod."""
        tool_calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(tool_calls))
        store = Store.open_migrated(tmp_path / "rk3-multi.db")
        pod_b = _replacement_pod()
        client = FakeClusterClient(
            workload=_WORKLOAD,
            pods=[_pod(), pod_b],
            pod_sequence=[[_pod(), pod_b], [_replacement_pod(), _replacement_pod()]],
        )
        scope = TargetScope(
            logical_id="checkout",
            runtime=RuntimeLabel.KUBERNETES,
            kind=ResourceKind.DEPLOYMENT,
            authority={"namespace": "production", "kind": "deployment", "name": "checkout"},
            container="app",
            selection=SelectionSpec(mode=SelectionMode.COUNT, count=2),
        )
        fault = PlannedFault(
            fault_id="k8s.pod_kill",
            targets=(),
            target=scope,
            undo_ops=(UndoOp(op="k8s.exec", args={"undo_command": "CONT"}),),
            duration="0.1s",
        )
        step = PlannedStep(id="k8s-0000", seq=0, fault=fault, raw_action=Wait(type="wait", duration=0.0))
        plan = ExecutionPlan(
            run_id="rk3-multi",
            kind=ExperimentKind.DRILL,
            steps=(step,),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        engine, events = _engine(store, client)
        result = engine.execute(plan)
        assert result.steps[0].ok is True
        leases = _all_leases(store)
        assert {l.resolved_target.pod for l in leases} == {"checkout-abc123", "checkout-def456"}
        assert {l.state for l in leases} == {LeaseState.RELEASED}
        deletes = [
            argv for argv in tool_calls
            if argv[:2] == ("kubectl", "delete") and "pod" in argv
        ]
        assert len(deletes) == 2  # one delete per selected pod
        assert any(e.kind == EventKind.FAULT_RECOVERED for e in events)

    def test_pod_latency_refused_without_netns(self, tmp_path: Path) -> None:
        """k8s.pod_latency needs NETNS capability; when UNSUPPORTED the engine
        acquires a lease, fails the capability gate, and releases it — no
        mutation happens."""
        store = Store.open_migrated(tmp_path / "rk3-refuse.db")
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        engine, _events = _engine(store, client)
        plan = _plan_from_spec()
        fault = next(s.fault for s in plan.steps if s.fault is not None)
        assert fault.fault_id == "k8s.pod_latency"
        result = engine.execute(plan)
        assert result.steps[0].ok is False
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.RELEASED
        assert lease.release_mechanism == "failed_to_apply"
        assert client.exec_calls == []  # no cluster I/O, no mutation

    def test_resolution_failure_leaves_no_lease(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "rk3-nf.db")
        client = FakeClusterClient(workload=None, pods=[_pod()])  # workload 404
        engine, _events = _engine(store, client)
        result = engine.execute(_plan())
        assert result.steps[0].ok is False
        assert _all_leases(store) == []
        assert client.exec_calls == []

    def test_injection_failure_releases_without_mutation(self, tmp_path: Path, monkeypatch) -> None:
        tool_calls: list = []
        monkeypatch.setattr(
            "mayhem.agents.executors.run_tool", _fake_tool(tool_calls, fail_on=("-STOP",))
        )
        store = Store.open_migrated(tmp_path / "rk3-ij.db")
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        engine, _events = _engine(store, client)
        result = engine.execute(_plan())
        assert result.steps[0].ok is False
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.RELEASED
        assert lease.release_mechanism == "inject_failed"
        # inject never succeeded: the undo contract is verified post-undo only,
        # and the lease was released with an explicit failure mechanism
        assert [c for c in tool_calls if "-CONT" in c] == []

    def test_undo_failure_escalates_to_dirty(self, tmp_path: Path, monkeypatch) -> None:
        tool_calls: list = []
        monkeypatch.setattr(
            "mayhem.agents.executors.run_tool", _fake_tool(tool_calls, fail_on=("-CONT",))
        )
        store = Store.open_migrated(tmp_path / "rk3-dirty.db")
        client = FakeClusterClient(workload=_WORKLOAD, pods=[_pod()])
        engine, events = _engine(store, client)
        result = engine.execute(_plan())
        assert result.steps[0].ok is False
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.DIRTY
        assert lease.escalation_notes and "DIRTY" in lease.escalation_notes
        assert not any(e.kind == EventKind.FAULT_RECOVERED for e in events)

    def test_primary_pid_guard_blocks_signal_reuse(self, tmp_path: Path) -> None:
        class RecycledPidClient(FakeClusterClient):
            # /proc/1/stat reports pid 200: the container was recycled, so the
            # signal family's PID-reuse guard must refuse to ever touch it.
            def exec(self, target: Any, argv: tuple[str, ...]) -> str:
                self.exec_calls.append(argv)
                if "cat" in argv and "/proc/1/stat" in argv:
                    return "200 (nginx) S 0 1 1 0 -1 4194560 1 0 0 0 123 45 0 0 20 0 1 0 9999 0 0"
                return self._exec_stdout

        store = Store.open_migrated(tmp_path / "rk3-guard.db")
        client = RecycledPidClient(workload=_WORKLOAD, pods=[_pod()])
        engine, _events = _engine(store, client)
        result = engine.execute(_plan())
        assert result.steps[0].ok is False
        assert _all_leases(store) == []
        assert any("cat" in argv for argv in client.exec_calls)  # guard read happened
        assert not any("kill" in argv for argv in client.exec_calls)  # ... but no signal