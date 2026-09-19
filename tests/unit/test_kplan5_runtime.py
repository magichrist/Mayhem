"""Unit tests for the k-plan-5 node-fault execution pipeline.

Covers the node resolution record (:meth:`KubernetesRuntimeResolver.resolve_node`),
the node write-ahead contracts (:func:`k8s_node_spec` /
:func:`k8s_node_undo_ops` / :func:`k8s_node_verify_spec`), the node executors
(``k8s.node_drain`` cordon+drain / uncordon, ``k8s.node_pressure`` apply /
delete), and the engine's node step lifecycle: a node fault forms a lease with
a resolved node target, activates it, injects, undoes, and releases — or fails
loud before any mutation and marks DIRTY when compensation cannot run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mayhem.agents.executors import K8sNodeDrainExecutor, K8sNodePressureExecutor
from mayhem.agents.k8s_resolve import K8sNodeInfo, KubernetesRuntimeResolver
from mayhem.controller.executor import RunEngine
from mayhem.controller.k8s_runtime import (
    K8S_NODE_FAULTS,
    k8s_node_routing,
    k8s_node_spec,
    k8s_node_undo_ops,
    k8s_node_verify_spec,
)
from mayhem.domain.errors import ResolutionError
from mayhem.domain.events import Event, EventKind
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    PlannedFault,
    PlannedStep,
    Wait,
)
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.leases import FaultLease, LeaseState, VerifyProbe
from mayhem.domain.resolution import ResolvedNodeTarget
from mayhem.domain.target import ResourceKind, TargetScope
from mayhem.domain.topology import TopologyGraph
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store
from mayhem.toolkit.tool_runner import ToolResult

# ── fakes ─────────────────────────────────────────────────────────────────────


class FakeClusterClient:
    """Minimal k8s client seam for node fault tests (works without kubectl)."""

    def __init__(
        self,
        node: K8sNodeInfo | None,
        *,
        nodes: list[K8sNodeInfo] | None = None,
        unavailable: bool = False,
    ) -> None:
        self._node = node
        self._nodes = list(nodes or ([node] if node is not None else []))
        self._unavailable = unavailable
        self.node_calls: list[str] = []
        self.nodes_calls = 0

    def node(self, name: str) -> K8sNodeInfo | None:
        self.node_calls.append(name)
        if self._unavailable:
            raise RuntimeError("cluster API unreachable")
        return self._node.value if isinstance(self._node, _NodeAbsent) else self._node

    def nodes(self) -> list[K8sNodeInfo]:
        self.nodes_calls += 1
        if self._unavailable:
            raise RuntimeError("cluster API unreachable")
        return list(self._nodes)

    def workload(self, workload: Any) -> Any:
        return None  # node faults never read workload descriptors

    def pods_for(self, workload: Any) -> list[Any]:
        return []  # node faults never select pods

    def exec(self, target: Any, argv: tuple[str, ...]) -> str:
        return ""  # node faults never exec into a container


class _NodeAbsent:
    """Sentinel so the fake can distinguish "no node" from "missing node"."""


def _resolved() -> ResolvedNodeTarget:
    return ResolvedNodeTarget(
        node="w1",
        node_uid="n-1",
        ready=True,
        unschedulable=False,
        labels={"kubernetes.io/role": "worker"},
        node_action="cordon",
    )


def _node_scope() -> TargetScope:
    return TargetScope(
        logical_id="w1",
        runtime=RuntimeLabel.KUBERNETES,
        kind=ResourceKind.K8S_NODE,
        authority={"name": "w1"},
    )


def _fake_tool(
    calls: list,
    ok_stdout: str = "",
    fail_on: tuple[str, ...] = (),
    stdin_calls: list | None = None,
):
    def _run(argv: tuple[str, ...], **kwargs: Any) -> ToolResult:
        calls.append(tuple(argv))
        if stdin_calls is not None:
            stdin_calls.append(kwargs.get("stdin_data"))
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


def _plan_node(fault_id: str = "k8s.node_drain", *, duration: str = "0.1s") -> ExecutionPlan:
    scope = _node_scope()
    fault = PlannedFault(
        fault_id=fault_id,
        targets=(),
        target=scope,
        undo_ops=k8s_node_undo_ops(fault_id, _resolved()),
        duration=duration,
    )
    wait = Wait(type="wait", duration=0.0)
    step = PlannedStep(
        id="node-0000",
        seq=0,
        fault=fault,
        raw_action=wait,
    )
    return ExecutionPlan(
        run_id="rk5-node",
        kind=ExperimentKind.DRILL,
        steps=(step,),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def _all_leases(store: Store) -> list:
    sink = SQLiteLeaseSink(store)
    rows = store.query("SELECT id FROM fault_leases ORDER BY created_epoch_s")
    return [sink.load(str(row["id"])) for row in rows]


def _engine(
    store: Store,
    client: FakeClusterClient,
    *,
    recovery_grace: float = 10.0,
) -> tuple[RunEngine, list[Event]]:
    events: list[Event] = []
    engine = RunEngine(
        store,
        SQLiteLeaseSink(store),
        sleeper=lambda _seconds: None,
        live_graph=lambda: TopologyGraph(nodes=(), edges=()),
        on_event=events.append,
        k8s_resolver=KubernetesRuntimeResolver(client=client),  # type: ignore[arg-type]
        recovery_grace=recovery_grace,
    )
    return engine, events


# ── resolver: node resolution record ─────────────────────────────────────────


class TestK8sNodeResolution:
    def test_resolve_node_with_concrete_name(self) -> None:
        client = FakeClusterClient(K8sNodeInfo(name="w1", uid="n-1", ready=True))
        resolver = KubernetesRuntimeResolver(client=client)  # type: ignore[arg-type]
        outcome = resolver.resolve_node(_node_scope(), node_name="w1")
        assert isinstance(outcome.resolved, ResolvedNodeTarget)
        assert outcome.resolved.node == "w1"
        assert outcome.resolved.node_uid == "n-1"
        assert outcome.resolved.ready is True

    def test_resolve_node_missing_is_hard_error(self) -> None:
        client = FakeClusterClient(None)
        resolver = KubernetesRuntimeResolver(client=client)  # type: ignore[arg-type]
        with pytest.raises(ResolutionError, match="resource_missing"):
            resolver.resolve_node(_node_scope(), node_name="w1")

    def test_resolve_node_wrong_runtime_is_hard_error(self) -> None:
        client = FakeClusterClient(K8sNodeInfo(name="w1", uid="n-1"))
        resolver = KubernetesRuntimeResolver(client=client)  # type: ignore[arg-type]
        scope = TargetScope(
            logical_id="c",
            runtime=RuntimeLabel.DOCKER,
            kind=ResourceKind.CONTAINER,
            authority={"container_name": "c"},
        )
        with pytest.raises(ResolutionError, match="wrong_runtime"):
            resolver.resolve_node(scope)


# ── write-ahead contracts ─────────────────────────────────────────────────────


class TestK8sNodeContracts:
    def test_node_spec_carries_write_ahead_contract(self) -> None:
        spec = k8s_node_spec("k8s.node_drain", _resolved(), {"grace_period": 30})
        assert spec["op"] == "k8s.node.mutation"
        args = spec["args"]
        assert isinstance(args, dict)
        assert args["node"] == "w1"
        assert args["node_uid"] == "n-1"
        assert args["reversible"] == "true"
        assert json.loads(str(args["params"])) == {"grace_period": 30}

    def test_node_drain_undo_is_uncordon(self) -> None:
        ops = k8s_node_undo_ops("k8s.node_drain", _resolved())
        assert ops[0].op == "k8s.uncordon"
        assert ops[0].args["node"] == "w1"
        assert ops[0].args["node_uid"] == "n-1"

    def test_node_pressure_undo_is_workload_delete(self) -> None:
        ops = k8s_node_undo_ops("k8s.node_pressure", _resolved())
        assert ops[0].op == "k8s.delete"
        assert ops[0].args["workload"] == "mayhem-node-pressure-w1"
        assert ops[0].args["kind"] == "pod"

    def test_node_undo_bag_carries_authored_params(self) -> None:
        drain = k8s_node_undo_ops("k8s.node_drain", _resolved(), {"grace_period": 45})
        assert json.loads(str(drain[0].args["params"])) == {"grace_period": 45}
        pressure = k8s_node_undo_ops(
            "k8s.node_pressure", _resolved(), {"resource": "memory", "target_percent": 80}
        )
        assert json.loads(str(pressure[0].args["params"])) == {
            "resource": "memory",
            "target_percent": 80,
        }

    def test_node_verify_spec_for_drain(self) -> None:
        spec = k8s_node_verify_spec("k8s.node_drain", _resolved())
        args = spec["args"]
        assert isinstance(args, dict)
        assert spec["op"] == "k8s.node_restored"
        assert args["expect_ready"] == "true"
        assert args["expect_unschedulable"] == "false"
        assert args["node"] == "w1"

    def test_node_verify_spec_for_pressure_names_workload(self) -> None:
        spec = k8s_node_verify_spec("k8s.node_pressure", _resolved())
        args = spec["args"]
        assert isinstance(args, dict)
        assert args["node"] == "w1"
        assert args["pressure_workload"] == "mayhem-node-pressure-w1"

    def test_node_routing_pins_every_node_fault_to_node_pipeline(self) -> None:
        routing = k8s_node_routing()
        for fault_id in K8S_NODE_FAULTS:
            assert routing.get(fault_id) == "k8s.node"


# ── executors: drain / pressure ───────────────────────────────────────────────


class TestK8sNodeDrainExecutor:
    def test_inject_cordons_then_drains(self, monkeypatch) -> None:
        calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(calls))
        lease = _lease_for("k8s.node_drain")
        outcome = K8sNodeDrainExecutor().inject(lease)
        assert outcome.ok is True
        injection = [argv for argv in calls if "drain" in argv or "cordon" in argv]
        assert [argv[1] for argv in injection] == ["cordon", "drain"]
        assert injection[0][2] == "w1"
        assert "--force" in injection[1], "drain must force-evict controller-less pods"

    def test_undo_uncordons(self, monkeypatch) -> None:
        calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(calls))
        lease = _lease_for("k8s.node_drain")
        outcome = K8sNodeDrainExecutor().undo(lease)
        assert outcome.ok is True
        assert calls[-1][1] == "uncordon"
        assert calls[-1][2] == "w1"

    def test_drain_failure_fails_inject(self, monkeypatch) -> None:
        calls: list = []
        monkeypatch.setattr(
            "mayhem.agents.executors.run_tool", _fake_tool(calls, fail_on=("drain",))
        )
        lease = _lease_for("k8s.node_drain")
        outcome = K8sNodeDrainExecutor().inject(lease)
        assert outcome.ok is False
        assert "kubectl drain failed" in outcome.detail

    def test_undo_failure_is_not_ok(self, monkeypatch) -> None:
        calls: list = []
        monkeypatch.setattr(
            "mayhem.agents.executors.run_tool", _fake_tool(calls, fail_on=("uncordon",))
        )
        lease = _lease_for("k8s.node_drain")
        outcome = K8sNodeDrainExecutor().undo(lease)
        assert outcome.ok is False

    def test_can_apply_accepts_resolved_node_lease(self) -> None:
        """can_apply is environment revalidation; a resolved node lease holds."""
        lease = _lease_for("k8s.node_drain")
        assert K8sNodeDrainExecutor().can_apply(lease) is None
        assert K8sNodePressureExecutor().can_apply(lease) is None


class TestK8sNodePressureExecutor:
    def test_inject_applies_pressure_workload(self, monkeypatch) -> None:
        calls: list = []
        stdin_calls: list = []
        monkeypatch.setattr(
            "mayhem.agents.executors.run_tool",
            _fake_tool(calls, stdin_calls=stdin_calls),
        )
        lease = _lease_for("k8s.node_pressure", params={"resource": "cpu", "target_percent": 80})
        outcome = K8sNodePressureExecutor().inject(lease)
        assert outcome.ok is True
        apply_argv = calls[0]
        assert apply_argv[:3] == ("kubectl", "apply", "-f")
        assert apply_argv[3] == "-", "manifest must stream via stdin"
        body = json.loads(stdin_calls[0])
        assert body["spec"]["nodeName"] == "w1"
        assert body["metadata"]["name"] == "mayhem-node-pressure-w1"
        assert body["spec"]["containers"][0]["resources"]["requests"] == {"cpu": "80m"}

    def test_undo_deletes_pressure_workload(self, monkeypatch) -> None:
        calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(calls))
        lease = _lease_for("k8s.node_pressure")
        outcome = K8sNodePressureExecutor().undo(lease)
        assert outcome.ok is True
        delete_argv = calls[0]
        assert delete_argv[:2] == ("kubectl", "delete")
        assert "mayhem-node-pressure-w1" in delete_argv


# ── engine: node step lifecycle ───────────────────────────────────────────────


class TestEngineK8sNodeStep:
    def test_node_drain_injects_holds_undoes_releases_cleanly(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        tool_calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(tool_calls))
        store = Store.open_migrated(tmp_path / "rk5.db")
        client = FakeClusterClient(K8sNodeInfo(name="w1", uid="n-1", ready=True))
        engine, events = _engine(store, client)
        result = engine.execute(_plan_node())
        assert result.steps[0].ok is True
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.RELEASED
        assert lease.resolved_target is not None
        assert lease.resolved_target.node == "w1"
        assert lease.resolved_target.ready is True
        kinds = {event.kind for event in events}
        assert EventKind.FAULT_INJECTED in kinds
        assert EventKind.FAULT_RECOVERED in kinds

    def test_node_fault_lease_carries_resolved_node_target(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        tool_calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(tool_calls))
        store = Store.open_migrated(tmp_path / "rk5.db")
        client = FakeClusterClient(K8sNodeInfo(name="w1", uid="n-1", ready=True))
        engine, _ = _engine(store, client)
        engine.execute(_plan_node())
        lease = _all_leases(store)[0]
        target = lease.resolved_target
        assert isinstance(target, ResolvedNodeTarget)
        assert target.node == "w1"
        assert target.node_uid == "n-1"
        assert lease.release_mechanism == "normal"

    def test_engine_refuses_before_mutation_when_drain_fails(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        tool_calls: list = []
        monkeypatch.setattr(
            "mayhem.agents.executors.run_tool",
            _fake_tool(tool_calls, fail_on=("kubectl cordon",)),
        )
        store = Store.open_migrated(tmp_path / "rk5.db")
        client = FakeClusterClient(K8sNodeInfo(name="w1", uid="n-1", ready=True))
        engine, events = _engine(store, client)
        result = engine.execute(_plan_node())
        assert result.steps[0].ok is False
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.RELEASED
        assert lease.release_mechanism == "failed_to_apply_undone"
        assert not any(event.kind == EventKind.FAULT_RECOVERED for event in events)
        # the inject failure must not leave the node mid-mutation: uncordon
        # was attempted last on a cordon failure.
        assert tool_calls[-1][1] == "uncordon"

    def test_engine_drain_failure_undoes_partial_cordon(self, tmp_path: Path, monkeypatch) -> None:
        """A drain that fails *after* a successful cordon must uncordon again
        (write-ahead undo on partial node mutation) — never leak a cordon."""
        tool_calls: list = []
        monkeypatch.setattr(
            "mayhem.agents.executors.run_tool", _fake_tool(tool_calls, fail_on=("drain",))
        )
        store = Store.open_migrated(tmp_path / "rk5.db")
        client = FakeClusterClient(K8sNodeInfo(name="w1", uid="n-1", ready=True))
        engine, events = _engine(store, client)
        result = engine.execute(_plan_node())
        assert result.steps[0].ok is False
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.RELEASED
        assert lease.release_mechanism == "failed_to_apply_undone"
        verbs = [(argv[1], argv[2] if len(argv) > 2 else "") for argv in tool_calls]
        assert verbs == [("cordon", "w1"), ("drain", "w1"), ("uncordon", "w1")]

    def test_engine_drain_failure_with_broken_undo_marks_dirty(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """If the partial-mutation undo also fails, the lease escalates DIRTY
        so the operator is told a cordon may be stuck on the node."""
        tool_calls: list = []
        monkeypatch.setattr(
            "mayhem.agents.executors.run_tool",
            _fake_tool(tool_calls, fail_on=("drain", "uncordon")),
        )
        store = Store.open_migrated(tmp_path / "rk5.db")
        client = FakeClusterClient(K8sNodeInfo(name="w1", uid="n-1", ready=True))
        engine, events = _engine(store, client)
        result = engine.execute(_plan_node())
        assert result.steps[0].ok is False
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.DIRTY
        assert not any(event.kind == EventKind.FAULT_RECOVERED for event in events)

    def test_engine_node_undo_failure_marks_dirty(self, tmp_path: Path, monkeypatch) -> None:
        tool_calls: list = []
        monkeypatch.setattr(
            "mayhem.agents.executors.run_tool", _fake_tool(tool_calls, fail_on=("uncordon",))
        )
        store = Store.open_migrated(tmp_path / "rk5.db")
        client = FakeClusterClient(K8sNodeInfo(name="w1", uid="n-1", ready=True))
        engine, events = _engine(store, client)
        result = engine.execute(_plan_node())
        assert result.steps[0].ok is False
        lease = _all_leases(store)[0]
        assert lease.state == LeaseState.DIRTY
        assert not any(event.kind == EventKind.FAULT_RECOVERED for event in events)

    def test_engine_node_pressure_runs_apply_and_delete(self, tmp_path: Path, monkeypatch) -> None:
        tool_calls: list = []
        monkeypatch.setattr("mayhem.agents.executors.run_tool", _fake_tool(tool_calls))
        store = Store.open_migrated(tmp_path / "rk5.db")
        client = FakeClusterClient(K8sNodeInfo(name="w1", uid="n-1", ready=True))
        engine, _ = _engine(store, client)
        result = engine.execute(_plan_node("k8s.node_pressure"))
        assert result.steps[0].ok is True
        applied = any(a[:2] == ("kubectl", "apply") for a in tool_calls)
        deleted = any(a[:2] == ("kubectl", "delete") for a in tool_calls)
        assert applied and deleted


def _lease_for(
    fault_id: str,
    *,
    params: dict[str, object] | None = None,
    resolved_target: ResolvedNodeTarget | None = None,
):
    """Build a :class:`FaultLease` shaped like the engine hands executors
    (node undo ops recorded, resolved node target carried).
    ``params`` reach the executor through the undo-op params bag."""
    target = resolved_target or _resolved()
    return FaultLease(
        id="l-node",
        run_id="rk5-node",
        fault_id=fault_id,
        owner_agent="engine",
        targets=frozenset({target.node}),
        undo_ops=k8s_node_undo_ops(fault_id, target, params),
        verify_probes=(VerifyProbe(probe="k8s.node_restored", args={"node": target.node}),),
        ttl_seconds=120.0,
        state=LeaseState.ACTIVE,
        resolved_target=target,
    )
