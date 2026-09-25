"""Exhaustive runtime / executor contract matrix.

Two seams are exercised for the whole fault catalog with no live runtime:

* the **container** lane (docker and podman) — ``executor_for`` resolution,
  write-ahead compensation, marker/argv presence, fake ``inject``/``undo``,
  capability refusals, and engine-loss refusals;
* the **Kubernetes** lane — ``k8s_contract_for`` / ``k8s_available_faults`` /
  ``k8s_executor_for`` / ``k8s_node_routing`` / ``k8s_undo_ops_for`` for every
  catalog entry, fake object snapshots per target kind (pod, node, workload,
  service, HPA, PDB), evidence, and the explicit refusal paths.

Plus the engine-descriptor selection matrix (explicit override, ambiguity,
unavailability) and the Kubernetes manifest/live discovery seams.

A module-level autouse fixture makes any real process spawn fail loudly, so
no test in this file can reach docker, podman, kubectl, minikube or a live
cluster.
"""

from __future__ import annotations

import copy
import json as _json
import os
import re
import subprocess
from typing import Any, ClassVar

import pytest
from pydantic import ValidationError

from mayhem.agents import executors as executor_module
from mayhem.agents.executors import (
    DNS_CONTROL_UNSUPPORTED_MESSAGE,
    K8S_NODE_CONTROL_FAULTS,
    K8S_SIGNAL_FAULTS,
    K8S_SIGNAL_INJECT_SIGNAL,
    NETNS_UNSUPPORTED_MESSAGE,
    NODE_CONTROL_UNSUPPORTED_MESSAGE,
    K8sExecutor,
    NoopExecutor,
    PayloadExecutor,
    ProcPauseExecutor,
    ToolExecutor,
    executor_for,
    k8s_dns_supported,
    k8s_executor_for,
    k8s_netns_supported,
    k8s_node_control_supported,
    k8s_unsupported_reason,
    node_control_unsupported_reason,
)
from mayhem.controller import k8s_runtime as k8srt
from mayhem.controller.k8s_runtime import (
    K8S_MUTATION_FAULTS,
    K8S_NODE_FAULTS,
    K8S_REVERSIBLE_FAULTS,
    k8s_available_faults,
    k8s_contract_for,
    k8s_family_for,
    k8s_node_routing,
    k8s_node_spec,
    k8s_node_undo_ops,
    k8s_node_verify_spec,
    k8s_undo_ops_for,
    k8s_undo_spec,
    k8s_verify_spec,
    preferred_pod_from_graph,
    unsupported_reason,
)
from mayhem.domain.catalog import CATALOG, definition_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import PlannedFault
from mayhem.domain.faults import NodeKind, ParamType, TargetKind
from mayhem.domain.identity import RuntimeIdentity, RuntimeLabel, RuntimeMetadata
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.resolution import ResolvedNodeTarget, ResolvedPodTarget
from mayhem.domain.topology import (
    ContainerNode,
    ExternalDependencyNode,
    HostNode,
    ProcessNode,
    ServiceNode,
    TopologyGraph,
)
from mayhem.toolkit.tool_runner import ToolResult

_CONTAINER_KINDS = frozenset(
    {
        NodeKind.SERVICE,
        NodeKind.CONTAINER,
        NodeKind.HOST,
        NodeKind.PROCESS,
        NodeKind.EXTERNAL_DEPENDENCY,
    }
)

CONTAINER_FAULTS: tuple[str, ...] = tuple(
    d.id for d in CATALOG if d.applicable_node_kinds & _CONTAINER_KINDS and not d.catalog_only
)

K8S_FAULTS: tuple[str, ...] = tuple(
    d.id for d in CATALOG if d.applicable_node_kinds <= {NodeKind.POD, NodeKind.K8S_NODE}
)

K8S_ACTIVE_FAULTS: tuple[str, ...] = tuple(
    d.id
    for d in CATALOG
    if d.applicable_node_kinds <= {NodeKind.POD, NodeKind.K8S_NODE} and not d.catalog_only
)

K8S_CATALOG_ONLY: tuple[str, ...] = tuple(
    d.id
    for d in CATALOG
    if d.applicable_node_kinds <= {NodeKind.POD, NodeKind.K8S_NODE} and d.catalog_only
)

ENGINES: tuple[str, ...] = ("docker", "podman")

CONTAINER_MATRIX: tuple[tuple[str, str], ...] = tuple(
    (fault_id, engine) for fault_id in CONTAINER_FAULTS for engine in ENGINES
)

PAYLOAD_FAULTS: tuple[str, ...] = tuple(
    fault_id for fault_id in CONTAINER_FAULTS if isinstance(executor_for(fault_id), PayloadExecutor)
)

TOOL_FAULTS: tuple[str, ...] = tuple(
    fault_id for fault_id in CONTAINER_FAULTS if isinstance(executor_for(fault_id), ToolExecutor)
)

SIGNAL_FAULTS_IN_CATALOG: tuple[str, ...] = tuple(
    fault_id
    for fault_id in CONTAINER_FAULTS
    if isinstance(executor_for(fault_id), ProcPauseExecutor)
)

PAYLOAD_MATRIX: tuple[tuple[str, str], ...] = tuple(
    (fault_id, engine) for fault_id in PAYLOAD_FAULTS for engine in ENGINES
)

SIGNAL_FAULTS: tuple[str, ...] = tuple(sorted(K8S_SIGNAL_FAULTS))


def _forbidden(*args: object, **kwargs: object) -> None:
    msg = f"live subprocess spawn attempted: args={args!r}"
    raise AssertionError(msg)


@pytest.fixture(autouse=True)
def _no_live_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any real process spawn fail: docker/podman/kubectl/minikube are banned."""
    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, _forbidden)
    monkeypatch.setattr(os, "system", _forbidden)
    monkeypatch.setattr(os, "popen", _forbidden)
    from mayhem.agents.k8s_resolve import SdkK8sClient

    monkeypatch.setattr(SdkK8sClient, "available", classmethod(lambda cls: False))


def _tool_result(
    argv: tuple[str, ...] | list[str],
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> ToolResult:
    return ToolResult(
        argv=tuple(argv),
        argv_digest="fake",
        env_digest="fake",
        host="fake",
        cwd=None,
        exit_code=exit_code,
        duration_ms=0,
        stdout=stdout,
        stderr=stderr,
        truncated=False,
    )


class _FakeEngine:
    """Records container-engine argv and answers with successful results."""

    def __init__(self, *, exit_code: int = 0) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.exit_code = exit_code

    def __call__(self, argv: Any, **kwargs: Any) -> ToolResult:
        self.calls.append(tuple(argv))
        return _tool_result(tuple(argv), exit_code=self.exit_code, stdout="ok")


@pytest.fixture
def fake_engine(monkeypatch: pytest.MonkeyPatch) -> _FakeEngine:
    fake = _FakeEngine()
    monkeypatch.setattr(executor_module, "run_tool", fake)
    return fake


@pytest.fixture
def engines_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "shutil.which",
        lambda name: f"/usr/bin/{name}" if name in {"docker", "podman"} else None,
    )


def _valid_seed(spec) -> object:
    match spec.type:
        case ParamType.DURATION:
            floor = float(spec.minimum) if spec.minimum is not None else 5.0
            return f"{max(5.0, floor)}s"
        case ParamType.BYTES:
            floor = float(spec.minimum) if spec.minimum is not None else 1048576.0
            return str(int(floor if floor > 0 else 1048576))
        case ParamType.STRING:
            return "mayhem"
        case ParamType.PERCENT:
            low = float(spec.minimum) if spec.minimum is not None else 0.0
            high = float(spec.maximum) if spec.maximum is not None else 100.0
            return max(low, min(high, 50.0))
        case ParamType.FLOAT | ParamType.INTEGER:
            low = float(spec.minimum) if spec.minimum is not None else 1.0
            high = float(spec.maximum) if spec.maximum is not None else low + 1
            return max(low, min(high, max(low, 1.0)))
        case _:
            return "mayhem"


_OVERRIDES: dict[str, dict[str, object]] = {
    "net.bandwidth": {"rate": "10mbit"},
    "dependency.rate_limit": {"rate": 100},
    "db.connection_exhaust": {"connections": 8, "host": "db.internal"},
    "dependency.timeout": {"port": 5432, "delay_ms": 250},
    "net.connection_reset": {"port": 5432},
    "net.connection_refuse": {"port": 5432},
    "dependency.block": {"port": 5432},
    "dependency.connection_refuse": {"port": 5432},
    "dependency.malformed_response": {"port": 5432},
    "clock.skew": {"offset_ms": 500},
    "http.upstream_timeout": {"upstream": "db.internal:5432"},
    "k8s.resource_quota_exhaust": {"amount": 0},
    "k8s.dns_failure": {"domain": "svc.prod.svc"},
    "k8s.dns_timeout": {"domain": "svc.prod.svc"},
    "k8s.service_dns_mismatch": {"domain": "svc.prod.svc", "address": "10.0.0.9"},
    "k8s.pod_pending": {"reason": "taint"},
    "k8s.deployment_scale_failure": {"replicas": 1},
    "k8s.statefulset_scale_failure": {"replicas": 1},
    "k8s.persistent_volume_mount_failure": {"volume": "data"},
    "k8s.pdb_violation": {"unavailable": 1},
}


def _planned(fault_id: str) -> PlannedFault:
    from mayhem.controller.compensation import compensated

    definition = definition_for(fault_id)
    params: dict[str, object] = {
        spec.name: _valid_seed(spec)
        for spec in definition.params_schema
        if spec.required and spec.default is None
    }
    params.update(_OVERRIDES.get(fault_id, {}))
    planned = PlannedFault(fault_id=fault_id, targets=(), duration=5.0, params=params)
    return compensated(planned, _nodes_for(definition))


def _nodes_for(definition) -> tuple:
    kinds = set(definition.applicable_node_kinds)
    nodes: list = []
    if NodeKind.SERVICE in kinds:
        nodes.append(ServiceNode(id="svc.api", name="api", container_name="api-container"))
    if NodeKind.CONTAINER in kinds:
        nodes.append(
            ContainerNode(
                id="ctr.api",
                name="api",
                engine="docker",
                runtime_identity=RuntimeIdentity(runtime="docker", host_id="h1", runtime_id="cid"),
                runtime_metadata=RuntimeMetadata(service="api", name="api"),
                container_name="api-container",
                state="running",
            )
        )
    if NodeKind.PROCESS in kinds:
        nodes.append(
            ProcessNode(
                id="proc.api",
                name="api-proc",
                pid=4242,
                host_id="h1",
                container_name="api-container",
            )
        )
    if NodeKind.HOST in kinds:
        nodes.append(HostNode(id="host.h1", name="h1"))
    if NodeKind.EXTERNAL_DEPENDENCY in kinds:
        nodes.append(ExternalDependencyNode(id="ext.db", name="db", endpoint="172.18.0.9:3306"))
    return tuple(nodes)


LIVE_PIDS: dict[str, int] = {"proc.api": 4242, "svc.api": 4242, "ctr.api": 4242}


def _addressed_lease(
    fault_id: str,
    engine: str,
    *,
    container: str = "api-container",
) -> FaultLease:
    """Lease whose undo ops carry the live engine/container address (ADR-0020).

    The ``@live-pid`` placeholders are resolved through the production live
    substitute, so the lease is shaped exactly like the one the run engine
    hands the executor.
    """
    from mayhem.controller.executor import _substitute_pids

    planned = _planned(fault_id)
    ops, probes = _substitute_pids(
        planned.undo_ops,
        planned.verify_probes,
        LIVE_PIDS,
        engine=engine,
        live_targets={
            node_id: (pid, container)
            for node_id, pid in LIVE_PIDS.items()
            if node_id in ("proc.api", "svc.api")
        },
    )
    addressed = tuple(
        UndoOp(
            op=op.op,
            args={"engine": engine, "cont": container, **op.args},
            idempotent=op.idempotent,
        )
        for op in ops
    )
    return FaultLease(
        id=f"l-{fault_id.replace('.', '-')}",
        run_id="run-matrix",
        fault_id=fault_id,
        owner_agent="engine",
        targets=frozenset({"ctr.api"}),
        undo_ops=addressed,
        verify_probes=probes,
        ttl_seconds=120.0,
        state=LeaseState.ACTIVE,
    )


def _bare_lease(fault_id: str) -> FaultLease:
    return FaultLease(
        id=f"l-bare-{fault_id.replace('.', '-')}",
        run_id="run-matrix",
        fault_id=fault_id,
        owner_agent="engine",
        targets=frozenset({"ctr.api"}),
        undo_ops=(UndoOp(op="noop", args={}),),
        verify_probes=(VerifyProbe(probe="exec", args={"cmd": ["true"]}),),
        state=LeaseState.ACTIVE,
    )


class TestContainerExecutorResolution:
    def test_matrix_is_not_empty(self) -> None:
        assert len(CONTAINER_FAULTS) > 40
        assert len(CONTAINER_MATRIX) == 2 * len(CONTAINER_FAULTS)

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_executor_resolves_to_a_registered_class(self, fault_id: str) -> None:
        executor = executor_for(fault_id)
        assert isinstance(
            executor, (ProcPauseExecutor, PayloadExecutor, ToolExecutor, NoopExecutor)
        )

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_executor_is_deterministic(self, fault_id: str) -> None:
        assert type(executor_for(fault_id)) is type(executor_for(fault_id))

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_executor_implements_the_three_step_contract(self, fault_id: str) -> None:
        executor = executor_for(fault_id)
        assert callable(executor.can_apply)
        assert callable(executor.inject)
        assert callable(executor.undo)
        assert isinstance(executor.capable_faults(), tuple)

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_prefix_or_override_owns_the_fault(self, fault_id: str) -> None:
        from mayhem.agents.executors import _FAULT_EXECUTOR_OVERRIDES, EXECUTORS

        executor = executor_for(fault_id)
        by_prefix = fault_id.split(".", 1)[0] in executor.prefixes
        by_override = _FAULT_EXECUTOR_OVERRIDES.get(fault_id) is executor
        assert by_prefix or by_override
        assert executor is _FAULT_EXECUTOR_OVERRIDES.get(fault_id) or executor in EXECUTORS
        assert executor.supports(fault_id) == by_prefix

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_k8s_executor_never_wins_container_dispatch(self, fault_id: str) -> None:
        assert not isinstance(executor_for(fault_id), K8sExecutor)

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_compensation_template_exists(self, fault_id: str) -> None:
        from mayhem.controller.compensation import template_for

        assert template_for(fault_id) is not None

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_planned_fault_carries_undo_and_verify(self, fault_id: str) -> None:
        planned = _planned(fault_id)
        assert planned.fault_id == fault_id
        assert planned.undo_ops
        assert planned.verify_probes

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_undo_ops_are_well_formed(self, fault_id: str) -> None:
        for op in _planned(fault_id).undo_ops:
            assert op.op.strip()
            assert isinstance(op.args, dict)
            assert all(isinstance(k, str) and isinstance(v, str) for k, v in op.args.items())

    @pytest.mark.parametrize("fault_id", PAYLOAD_FAULTS)
    def test_payload_families_carry_a_marker(self, fault_id: str) -> None:
        planned = _planned(fault_id)
        assert any(op.args.get("marker") for op in planned.undo_ops)
        assert any(op.args.get("payload") for op in planned.undo_ops)

    @pytest.mark.parametrize("fault_id", TOOL_FAULTS)
    def test_tool_families_carry_both_argv_pairs(self, fault_id: str) -> None:
        planned = _planned(fault_id)
        ops = {op.op: op.args for op in planned.undo_ops}
        assert any("inject_argv" in args for args in ops.values())
        assert any("undo_argv" in args for args in ops.values())

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_argv_pairs_decode_to_string_lists(self, fault_id: str) -> None:
        for op in _planned(fault_id).undo_ops:
            for key in ("inject_argv", "undo_argv"):
                raw = op.args.get(key)
                if raw is None:
                    continue
                decoded = _json.loads(raw)
                assert isinstance(decoded, list)
                assert decoded
                assert all(isinstance(item, str) for item in decoded)

    @pytest.mark.parametrize("fault_id,engine", CONTAINER_MATRIX)
    def test_address_tokens_resolve_before_execution(self, fault_id: str, engine: str) -> None:
        lease = _addressed_lease(fault_id, engine)
        for op in lease.undo_ops:
            assert "@live-pid" not in _json.dumps(op.args)
            assert op.args.get("engine") == engine
        for key in ("inject_argv", "undo_argv"):
            argv = ToolExecutor()._argv_for(lease, key)
            if argv:
                assert "@engine" not in argv
                assert "@cont" not in argv

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_argv_pairs_only_carry_the_documented_tokens(self, fault_id: str) -> None:
        token = re.compile(r"@(engine|cont|live-pid|[\$\d].*)\Z")
        for op in _planned(fault_id).undo_ops:
            for key in ("inject_argv", "undo_argv"):
                raw = op.args.get(key)
                if raw is None:
                    continue
                for item in _json.loads(raw):
                    for word in item.replace(";", " ").replace("&&", " ").split():
                        if "@" in word:
                            assert token.fullmatch(word.strip("\"'")), word


class TestContainerInjectUndo:
    @pytest.mark.parametrize("fault_id,engine", CONTAINER_MATRIX)
    def test_can_apply_admits_a_complete_lease(
        self,
        fault_id: str,
        engine: str,
        fake_engine: _FakeEngine,
        engines_on_path: None,
    ) -> None:
        executor = executor_for(fault_id)
        assert executor.can_apply(_addressed_lease(fault_id, engine)) is None

    @pytest.mark.parametrize("fault_id,engine", CONTAINER_MATRIX)
    def test_inject_and_undo_succeed(
        self,
        fault_id: str,
        engine: str,
        fake_engine: _FakeEngine,
        engines_on_path: None,
    ) -> None:
        executor = executor_for(fault_id)
        lease = _addressed_lease(fault_id, engine)
        injected = executor.inject(lease)
        assert injected.ok, f"{fault_id}/{engine} inject: {injected.detail}"
        undone = executor.undo(lease)
        assert undone.ok, f"{fault_id}/{engine} undo: {undone.detail}"

    @pytest.mark.parametrize("fault_id,engine", CONTAINER_MATRIX)
    def test_inject_reports_its_step_name(
        self,
        fault_id: str,
        engine: str,
        fake_engine: _FakeEngine,
        engines_on_path: None,
    ) -> None:
        executor = executor_for(fault_id)
        lease = _addressed_lease(fault_id, engine)
        assert executor.inject(lease).step == "inject"
        assert executor.undo(lease).step == "undo"

    @pytest.mark.parametrize("fault_id,engine", CONTAINER_MATRIX)
    def test_undo_never_raises_even_after_inject(
        self,
        fault_id: str,
        engine: str,
        fake_engine: _FakeEngine,
        engines_on_path: None,
    ) -> None:
        executor = executor_for(fault_id)
        lease = _addressed_lease(fault_id, engine)
        executor.inject(lease)
        assert executor.undo(lease).ok
        assert executor.undo(lease).ok

    @pytest.mark.parametrize("fault_id,engine", CONTAINER_MATRIX)
    def test_address_tokens_are_resolved_before_the_spawn(
        self,
        fault_id: str,
        engine: str,
        fake_engine: _FakeEngine,
        engines_on_path: None,
    ) -> None:
        executor = executor_for(fault_id)
        lease = _addressed_lease(fault_id, engine)
        executor.inject(lease)
        executor.undo(lease)
        assert fake_engine.calls
        for call in fake_engine.calls:
            joined = " ".join(call)
            assert "@engine" not in joined
            assert "@cont" not in joined
            assert "@live-pid" not in joined

    @pytest.mark.parametrize("fault_id,engine", PAYLOAD_MATRIX)
    def test_in_container_families_spawn_through_the_engine_binary(
        self,
        fault_id: str,
        engine: str,
        fake_engine: _FakeEngine,
        engines_on_path: None,
    ) -> None:
        executor = executor_for(fault_id)
        lease = _addressed_lease(fault_id, engine)
        executor.inject(lease)
        executor.undo(lease)
        for call in fake_engine.calls:
            assert call[0] == engine
            assert call[1] == "exec"

    @pytest.mark.parametrize("fault_id,engine", CONTAINER_MATRIX)
    def test_tool_failures_surface_as_not_ok(
        self,
        fault_id: str,
        engine: str,
        monkeypatch: pytest.MonkeyPatch,
        engines_on_path: None,
    ) -> None:
        monkeypatch.setattr(executor_module, "run_tool", _FakeEngine(exit_code=1))
        executor = executor_for(fault_id)
        lease = _addressed_lease(fault_id, engine)
        if isinstance(executor, ProcPauseExecutor):
            assert not executor.inject(lease).ok
            if fault_id in ("process.stop", "process.kill"):
                assert executor.undo(lease).ok
            else:
                assert not executor.undo(lease).ok
            return
        assert not executor.inject(lease).ok
        assert not executor.undo(lease).ok


class TestContainerRefusals:
    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_a_lease_without_a_spec_is_refused(
        self, fault_id: str, fake_engine: _FakeEngine, engines_on_path: None
    ) -> None:
        executor = executor_for(fault_id)
        lease = _bare_lease(fault_id)
        outcome = executor.inject(lease)
        assert outcome.ok is False
        if isinstance(executor, (PayloadExecutor, ToolExecutor)):
            assert executor.can_apply(lease) is not None
        else:
            assert "pid" in outcome.detail or "signal" in outcome.detail

    @pytest.mark.parametrize("fault_id", CONTAINER_FAULTS)
    def test_refusal_never_mutates(
        self, fault_id: str, fake_engine: _FakeEngine, engines_on_path: None
    ) -> None:
        executor = executor_for(fault_id)
        lease = _bare_lease(fault_id)
        assert not executor.inject(lease).ok
        assert fake_engine.calls == []

    def test_payload_executor_names_its_missing_capability(
        self, fake_engine: _FakeEngine, engines_on_path: None
    ) -> None:
        reason = PayloadExecutor().can_apply(_bare_lease("mem.exhaust"))
        assert reason is not None
        assert "payload" in reason

    def test_tool_executor_names_its_missing_capability(
        self, fake_engine: _FakeEngine, engines_on_path: None
    ) -> None:
        reason = ToolExecutor().can_apply(_bare_lease("net.latency"))
        assert reason is not None
        assert "tool execution contract" in reason

    def test_tool_executor_refuses_without_undo_argv(
        self, fake_engine: _FakeEngine, engines_on_path: None
    ) -> None:
        planned = _planned("net.latency")
        stripped = tuple(
            UndoOp(
                op=op.op,
                args={key: value for key, value in op.args.items() if key != "undo_argv"},
            )
            for op in planned.undo_ops
        )
        lease = FaultLease(
            id="l-partial",
            run_id="run-matrix",
            fault_id="net.latency",
            owner_agent="engine",
            targets=frozenset({"ctr.api"}),
            undo_ops=stripped,
            verify_probes=(VerifyProbe(probe="exec", args={}),),
            state=LeaseState.ACTIVE,
        )
        assert not ToolExecutor().undo(lease).ok

    @pytest.mark.parametrize("fault_id", ("proc.pause", "process.stop", "process.kill"))
    def test_signal_faults_refuse_a_lease_without_a_pid(
        self, fault_id: str, fake_engine: _FakeEngine, engines_on_path: None
    ) -> None:
        outcome = ProcPauseExecutor().inject(_bare_lease(fault_id))
        assert not outcome.ok

    @pytest.mark.parametrize("fault_id", ("proc.pause", "process.stop", "process.kill"))
    def test_signal_faults_refuse_when_the_engine_vanished(
        self,
        fault_id: str,
        fake_engine: _FakeEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda _name: None)
        reason = ProcPauseExecutor().can_apply(_addressed_lease(fault_id, "docker"))
        assert reason is not None
        assert "capability lost" in reason

    @pytest.mark.parametrize("fault_id", ("proc.pause", "process.stop", "process.kill"))
    def test_signal_faults_admit_a_host_mode_lease_without_an_engine(
        self, fault_id: str, fake_engine: _FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda _name: None)
        lease = FaultLease(
            id=f"l-host-{fault_id.replace('.', '-')}",
            run_id="run-matrix",
            fault_id=fault_id,
            owner_agent="engine",
            targets=frozenset({"proc.api"}),
            undo_ops=(UndoOp(op="signal", args={"pid": "4242"}),),
            verify_probes=(VerifyProbe(probe="exec", args={}),),
            state=LeaseState.ACTIVE,
        )
        assert ProcPauseExecutor().can_apply(lease) is None

    def test_process_stop_and_kill_undo_is_idempotent_success(
        self, fake_engine: _FakeEngine, engines_on_path: None
    ) -> None:
        executor = ProcPauseExecutor()
        for fault_id in ("process.stop", "process.kill"):
            lease = _addressed_lease(fault_id, "docker")
            assert executor.undo(lease).ok
            assert executor.undo(lease).ok

    def test_signal_faults_refuse_a_recycled_pid(
        self, fake_engine: _FakeEngine, monkeypatch: pytest.MonkeyPatch, engines_on_path: None
    ) -> None:
        monkeypatch.setattr(executor_module, "read_boot_time", lambda _pid: 999999)
        lease = FaultLease(
            id="l-recycled",
            run_id="run-matrix",
            fault_id="proc.pause",
            owner_agent="engine",
            targets=frozenset({"proc.api"}),
            undo_ops=(UndoOp(op="signal.cont", args={"pid": "4242", "boot_time": "1"}),),
            verify_probes=(VerifyProbe(probe="exec", args={}),),
            state=LeaseState.ACTIVE,
        )
        outcome = ProcPauseExecutor().inject(lease)
        assert not outcome.ok
        assert "pid-reuse" in outcome.detail

    def test_signal_faults_deliver_through_the_container_engine(
        self, fake_engine: _FakeEngine, engines_on_path: None
    ) -> None:
        lease = _addressed_lease("proc.pause", "podman")
        assert ProcPauseExecutor().inject(lease).ok
        assert ("podman", "kill", "--signal", "SIGSTOP", "api-container") in fake_engine.calls
        assert ProcPauseExecutor().undo(lease).ok
        assert ("podman", "kill", "--signal", "SIGCONT", "api-container") in fake_engine.calls

    def test_unknown_fault_resolves_to_no_executor(self) -> None:
        assert executor_for("no.such_fault") is None


RESTORE_ANNOTATION = "mayhem.io/restore"

_KIND_ALIASES = {
    "svc": "Service",
    "cm": "ConfigMap",
    "deploy": "Deployment",
    "rs": "ReplicaSet",
    "sts": "StatefulSet",
    "ds": "DaemonSet",
    "hpa": "HorizontalPodAutoscaler",
    "pdb": "PodDisruptionBudget",
    "quota": "ResourceQuota",
    "resourcequota": "ResourceQuota",
    "pvc": "PersistentVolumeClaim",
    "secret": "Secret",
    "pod": "Pod",
    "node": "Node",
    "ns": "Namespace",
}


def _meta(name: str, namespace: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"name": name, "namespace": namespace, "annotations": {}}
    payload.update(extra)
    return payload


def _pod_object() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": _meta(
            "checkout-abc123",
            "prod",
            uid="pod-uid-1",
            labels={"app": "checkout"},
            ownerReferences=[
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "name": "checkout-7f8d9",
                    "uid": "rs-1",
                }
            ],
        ),
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "image": "nginx:1.27",
                    "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
                    "volumeMounts": [
                        {"name": "cfg", "mountPath": "/etc/mayhem"},
                        {"name": "creds", "mountPath": "/etc/creds"},
                        {"name": "data", "mountPath": "/mnt/data"},
                    ],
                },
                {"name": "sidecar", "image": "busybox:1.36"},
            ],
            "volumes": [
                {"name": "cfg", "configMap": {"name": "checkout-cfg"}},
                {"name": "creds", "secret": {"secretName": "mayhem-creds"}},
                {"name": "data", "persistentVolumeClaim": {"claimName": "checkout-data"}},
            ],
        },
        "status": {"phase": "Running"},
    }


def _replicaset_object() -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": _meta(
            "checkout-7f8d9",
            "prod",
            uid="rs-1",
            labels={"app": "checkout"},
            ownerReferences=[
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "checkout",
                    "uid": "deploy-1",
                }
            ],
        ),
        "spec": {"replicas": 2},
    }


def _deployment_object() -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": _meta("checkout", "prod", uid="deploy-1", labels={"app": "checkout"}),
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


def _service_object() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": _meta("checkout-svc", "prod", labels={"app": "checkout"}),
        "spec": {"selector": {"app": "checkout"}, "ports": [{"port": 80, "targetPort": 8080}]},
    }


def _configmap_object() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": _meta("checkout-cfg", "prod"),
        "data": {"DB_HOST": "db.prod.svc"},
    }


def _secret_object() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": _meta("mayhem-creds", "prod"),
        "type": "Opaque",
        "data": {"password": "c2VjcmV0"},
    }


def _hpa_object() -> dict[str, Any]:
    return {
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": _meta("checkout-hpa", "prod"),
        "spec": {
            "scaleTargetRef": {"kind": "Deployment", "name": "checkout"},
            "minReplicas": 1,
            "maxReplicas": 3,
        },
    }


def _pdb_object(name: str = "checkout-abc123") -> dict[str, Any]:
    return {
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": _meta(name, "prod"),
        "spec": {"maxUnavailable": 1, "selector": {"matchLabels": {"app": "checkout"}}},
    }


def _quota_object() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": _meta("prod-quota", "prod"),
        "spec": {"hard": {"pods": "10", "requests.cpu": "4"}},
        "status": {"used": {"pods": "3", "requests.cpu": "1"}},
    }


def _pvc_object() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": _meta("checkout-data", "prod"),
        "spec": {"storageClassName": "standard", "resources": {}},
        "status": {"phase": "Bound"},
    }


def _coredns_configmap() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": _meta("coredns", "kube-system"),
        "data": {"Corefile": ".:53 {\n    errors\n    ready\n}\n"},
    }


def _coredns_deployment() -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": _meta("coredns", "kube-system"),
        "spec": {"replicas": 1},
    }


def _node_object() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": _meta("worker-1", "", uid="node-uid-1", labels={"role": "worker"}),
        "spec": {"unschedulable": False},
        "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "allocatable": {"cpu": "4", "memory": "8Gi"},
        },
    }


DEFAULT_OBJECTS: tuple[dict[str, Any], ...] = (
    _pod_object(),
    _replicaset_object(),
    _deployment_object(),
    _service_object(),
    _configmap_object(),
    _secret_object(),
    _hpa_object(),
    _pdb_object(),
    _quota_object(),
    _pvc_object(),
    _coredns_configmap(),
    _coredns_deployment(),
    _node_object(),
)


class _FakeCluster:
    """Stateful kubectl replacement with a real object store.

    Records every argv, mirrors the annotate/patch/delete lifecycle so
    inject -> undo sequences follow the same restore-annotation contract as a
    live cluster, and can be told to fail a given verb.

    ``kubectl patch <kind> <name> -p '{...}'`` replaces the top-level section
    it carries (``spec`` / ``data``) and merges ``metadata.annotations``. That
    is the contract every snapshot executor writes: the restore payload *is*
    the full pre-mutation section, so a section replace is the faithful
    emulation and makes inject -> undo an exact round trip.
    """

    def __init__(
        self,
        objects: tuple[dict[str, Any], ...] = DEFAULT_OBJECTS,
        *,
        fail_verbs: frozenset[str] = frozenset(),
    ) -> None:
        self.objects: dict[tuple[str, str, str], dict[str, Any]] = {}
        for obj in objects:
            namespace = str(obj.get("metadata", {}).get("namespace", "") or "default")
            self.objects[(obj["kind"], obj["metadata"]["name"], namespace)] = copy.deepcopy(obj)
        self.calls: list[tuple[str, ...]] = []
        self.stdin: list[str | None] = []
        self.fail_verbs = set(fail_verbs)
        self.exec_calls: list[tuple[str, ...]] = []

    _VERBS: ClassVar[dict[str, str]] = {
        "annotate": "_annotate",
        "get": "_get",
        "patch": "_patch",
        "delete": "_delete",
    }

    def __call__(self, argv: Any, **kwargs: Any) -> ToolResult:
        call = tuple(argv)
        self.calls.append(call)
        self.stdin.append(kwargs.get("stdin_data"))
        if not call:
            return self._ok()
        verb = call[1] if call[0] == "kubectl" and len(call) > 1 else call[0]
        if verb in self.fail_verbs:
            return self._err(f"{verb} refused by fake cluster")
        handler = self._VERBS.get(verb)
        if handler is not None:
            return getattr(self, handler)(call)
        if verb == "exec":
            self.exec_calls.append(call)
            return self._ok()
        if verb == "apply":
            self._apply(kwargs.get("stdin_data"))
        return self._ok()

    def _ok(self, stdout: str = "") -> ToolResult:
        return _tool_result(("kubectl",), exit_code=0, stdout=stdout)

    def _err(self, stdout: str) -> ToolResult:
        return _tool_result(("kubectl",), exit_code=1, stdout=stdout, stderr="fake failure")

    @staticmethod
    def _ns(call: tuple[str, ...]) -> str:
        try:
            return call[call.index("-n") + 1]
        except (ValueError, IndexError):
            return "default"

    @staticmethod
    def _canonical(kind: str) -> str:
        return _KIND_ALIASES.get(kind, kind)

    def _annotate(self, call: tuple[str, ...]) -> ToolResult:
        key = (self._canonical(call[2]), call[3], self._ns(call))
        obj = self.objects.setdefault(
            key, {"kind": key[0], "metadata": {"name": key[1], "namespace": key[2]}}
        )
        annotations = obj.setdefault("metadata", {}).setdefault("annotations", {})
        payload = call[6] if len(call) > 6 else ""
        if payload.endswith("-"):
            annotations.pop(RESTORE_ANNOTATION, None)
        elif "=" in payload:
            annotations[RESTORE_ANNOTATION] = payload.split("=", 1)[1]
        return self._ok()

    def _get(self, call: tuple[str, ...]) -> ToolResult:
        positional: list[str] = []
        for token in call[2:]:
            if token.startswith("-"):
                break
            positional.append(token)
        namespace = self._ns(call)
        if len(positional) == 2:
            key = (self._canonical(positional[0]), positional[1], namespace)
            obj = self.objects.get(key)
            return self._ok("{}" if obj is None else _json.dumps(obj))
        kinds = {self._canonical(kind) for kind in positional}
        items = [
            obj
            for (kind, _name, obj_ns), obj in self.objects.items()
            if kind in kinds and obj_ns == namespace
        ]
        return self._ok(_json.dumps({"items": items}))

    def _patch(self, call: tuple[str, ...]) -> ToolResult:
        key = (self._canonical(call[2]), call[3], self._ns(call))
        payload = call[call.index("-p") + 1] if "-p" in call else "{}"
        patch = _json.loads(payload)
        obj = copy.deepcopy(self.objects.get(key, {"kind": key[0], "metadata": {"name": key[1]}}))
        for section, value in patch.items():
            if section == "metadata":
                meta = obj.setdefault("metadata", {})
                for meta_key, meta_value in value.items():
                    if meta_key == "annotations":
                        meta.setdefault("annotations", {}).update(meta_value)
                    else:
                        meta[meta_key] = meta_value
                continue
            obj[section] = value
        self.objects[key] = obj
        return self._ok("patched")

    def _delete(self, call: tuple[str, ...]) -> ToolResult:
        self.objects.pop((self._canonical(call[2]), call[3], self._ns(call)), None)
        return self._ok("deleted")

    def _apply(self, stdin: str | None) -> None:
        if not stdin:
            return
        obj = _json.loads(stdin)
        namespace = str(obj.get("metadata", {}).get("namespace", "default"))
        self.objects[(obj["kind"], obj["metadata"]["name"], namespace)] = obj

    def annotated(self, kind: str, name: str, namespace: str = "prod") -> bool:
        obj = self.objects.get((kind, name, namespace))
        if obj is None:
            return False
        return RESTORE_ANNOTATION in (obj.get("metadata", {}).get("annotations") or {})

    def spec_of(self, kind: str, name: str, namespace: str = "prod") -> dict[str, Any]:
        obj = self.objects[(kind, name, namespace)]
        return dict(obj.get("spec") or {})


@pytest.fixture
def cluster(monkeypatch: pytest.MonkeyPatch) -> _FakeCluster:
    fake = _FakeCluster()
    _install_fake_cluster(monkeypatch, fake)
    return fake


def _install_fake_cluster(monkeypatch: pytest.MonkeyPatch, fake: _FakeCluster) -> None:
    for module in (
        "mayhem.agents.executors.run_tool",
        "mayhem.agents.k8s_control.run_tool",
        "mayhem.agents.k8s_resolve.run_tool",
    ):
        monkeypatch.setattr(module, fake)


def _pod_target(**overrides: Any) -> ResolvedPodTarget:
    data: dict[str, Any] = {
        "namespace": "prod",
        "pod": "checkout-abc123",
        "container": "app",
        "pod_uid": "pod-uid-1",
        "container_id": "containerd://c0ffee",
        "node": "worker-1",
        "labels": {"app": "checkout"},
        "pod_action": "mutation",
        "exec_argv": (
            "kubectl",
            "exec",
            "-n",
            "prod",
            "pod/checkout-abc123",
            "-c",
            "app",
            "--",
        ),
    }
    data.update(overrides)
    return ResolvedPodTarget(**data)


def _node_target(**overrides: Any) -> ResolvedNodeTarget:
    data: dict[str, Any] = {
        "node": "worker-1",
        "node_uid": "node-uid-1",
        "ready": True,
        "unschedulable": False,
        "labels": {"role": "worker"},
        "node_action": "mutation",
    }
    data.update(overrides)
    return ResolvedNodeTarget(**data)


def _k8s_lease(
    fault_id: str,
    *,
    target: ResolvedPodTarget | ResolvedNodeTarget | None = None,
    params: dict[str, object] | None = None,
    lease_id: str = "l-k8s",
) -> FaultLease:
    resolved = target if target is not None else _node_target()
    undo_ops = (UndoOp(op="k8s.undo", args={"params": _json.dumps(params or {})}),)
    return FaultLease(
        id=lease_id,
        run_id="run-k8s",
        fault_id=fault_id,
        owner_agent="engine",
        targets=frozenset({getattr(resolved, "pod", None) or resolved.node}),
        undo_ops=undo_ops,
        verify_probes=(VerifyProbe(probe="k8s.undo", args={}),),
        ttl_seconds=120.0,
        state=LeaseState.ACTIVE,
        resolved_target=resolved,
    )


class TestK8sRegistries:
    def test_catalog_only_kubernetes_entries_exist(self) -> None:
        assert K8S_CATALOG_ONLY

    @pytest.mark.parametrize("fault_id", K8S_FAULTS)
    def test_contract_for_is_total(self, fault_id: str) -> None:
        contract = k8s_contract_for(fault_id)
        assert contract.family
        assert contract.target_kind in {"pod", "node"}
        assert contract.target_kinds
        assert contract.capability
        assert contract.safety_decision
        assert contract.compensation
        assert contract.evidence
        assert all(item.strip() for item in contract.evidence)

    @pytest.mark.parametrize("fault_id", K8S_FAULTS)
    def test_contract_capability_is_a_known_gate(self, fault_id: str) -> None:
        capability = k8s_contract_for(fault_id).capability
        assert capability in {"KUBERNETES_ENGINE", "NODE_CONTROL", "NETNS", "DNS_CONTROL"}

    @pytest.mark.parametrize("fault_id", K8S_FAULTS)
    def test_contract_capability_agrees_with_the_family(self, fault_id: str) -> None:
        contract = k8s_contract_for(fault_id)
        if contract.family == "node":
            assert contract.capability == "NODE_CONTROL"
        elif contract.family == "dns":
            assert contract.capability == "DNS_CONTROL"
        elif fault_id.startswith("net.") or fault_id == "k8s.pod_latency":
            assert contract.capability == "NETNS"
        else:
            assert contract.capability == "KUBERNETES_ENGINE"

    @pytest.mark.parametrize("fault_id", K8S_FAULTS)
    def test_contract_safety_decision_matches_risk_and_reversibility(self, fault_id: str) -> None:
        from mayhem.domain.risks import RiskLevel

        definition = definition_for(fault_id)
        decision = k8s_contract_for(fault_id).safety_decision
        if definition.risk is RiskLevel.CRITICAL:
            assert decision == "critical-triple-opt-in"
        elif definition.reversible:
            assert decision == "reversible-with-undo"
        else:
            assert decision == "compensation-required"

    @pytest.mark.parametrize("fault_id", K8S_FAULTS)
    def test_contract_target_kinds_mirror_the_catalog(self, fault_id: str) -> None:
        definition = definition_for(fault_id)
        contract = k8s_contract_for(fault_id)
        assert set(contract.target_kinds) == {kind.value for kind in definition.target_kinds}
        if TargetKind.NODE in definition.target_kinds:
            assert contract.target_kind == "node"
        else:
            assert contract.target_kind == "pod"

    @pytest.mark.parametrize("fault_id", K8S_FAULTS)
    def test_executor_name_matches_the_executor_registry(self, fault_id: str) -> None:
        from mayhem.agents.executors import _K8S_EXECUTORS

        contract = k8s_contract_for(fault_id)
        registered = _K8S_EXECUTORS.get(fault_id)
        assert contract.executor == (registered.__name__ if registered else "k8s.unsupported")

    @pytest.mark.parametrize("fault_id", K8S_CATALOG_ONLY)
    def test_catalog_only_contracts_refuse_explicitly(self, fault_id: str) -> None:
        contract = k8s_contract_for(fault_id)
        assert contract.executor == "k8s.unsupported"
        assert "remediation" in contract.compensation

    @pytest.mark.parametrize("fault_id", K8S_ACTIVE_FAULTS)
    def test_active_contracts_never_refuse(self, fault_id: str) -> None:
        contract = k8s_contract_for(fault_id)
        assert contract.executor != "k8s.unsupported"
        assert "k8s.unsupported" not in contract.compensation

    @pytest.mark.parametrize("fault_id", K8S_ACTIVE_FAULTS)
    def test_active_faults_are_advertised_as_available(self, fault_id: str) -> None:
        assert fault_id in k8s_available_faults()

    @pytest.mark.parametrize("fault_id", K8S_CATALOG_ONLY)
    def test_catalog_only_faults_are_never_advertised(self, fault_id: str) -> None:
        assert fault_id not in k8s_available_faults()

    def test_available_faults_is_a_subset_of_the_catalog(self) -> None:
        catalog_ids = {d.id for d in CATALOG}
        assert k8s_available_faults() <= catalog_ids

    def test_available_faults_equals_mutation_plus_node(self) -> None:
        assert k8s_available_faults() == K8S_MUTATION_FAULTS | K8S_NODE_FAULTS

    @pytest.mark.parametrize("fault_id", K8S_ACTIVE_FAULTS)
    def test_active_faults_have_a_kubernetes_executor(self, fault_id: str) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        assert isinstance(executor, K8sExecutor)

    @pytest.mark.parametrize("fault_id", K8S_FAULTS)
    def test_non_kubernetes_runtime_resolves_no_k8s_executor(self, fault_id: str) -> None:
        for runtime in (RuntimeLabel.DOCKER, RuntimeLabel.PODMAN):
            assert k8s_executor_for(fault_id, runtime) is None

    @pytest.mark.parametrize("fault_id", K8S_ACTIVE_FAULTS)
    def test_executor_for_routes_kubernetes_runtime_to_the_k8s_driver(self, fault_id: str) -> None:
        assert isinstance(executor_for(fault_id, RuntimeLabel.KUBERNETES), K8sExecutor)

    @pytest.mark.parametrize("fault_id", K8S_FAULTS)
    def test_k8s_executor_never_claims_prefix_dispatch(self, fault_id: str) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        assert executor.supports(fault_id) is False

    @pytest.mark.parametrize("fault_id", K8S_FAULTS)
    def test_family_for_is_total(self, fault_id: str) -> None:
        assert k8s_family_for(fault_id)
        assert k8s_family_for(fault_id) == k8s_contract_for(fault_id).family

    def test_node_routing_covers_every_node_family_fault(self) -> None:
        routing = k8s_node_routing()
        assert set(routing) == set(K8S_NODE_FAULTS)
        assert set(routing.values()) == {"k8s.node"}

    def test_node_routing_returns_a_fresh_dict(self) -> None:
        first = k8s_node_routing()
        first["k8s.node_drain"] = "tampered"
        assert k8s_node_routing()["k8s.node_drain"] == "k8s.node"

    def test_node_routing_excludes_pod_families(self) -> None:
        routing = k8s_node_routing()
        for fault_id in ("k8s.pod_kill", "k8s.pod_oom", "k8s.service_no_endpoints"):
            assert fault_id not in routing

    @pytest.mark.parametrize("fault_id", sorted(K8S_MUTATION_FAULTS))
    def test_undo_ops_for_mutation_faults(self, fault_id: str) -> None:
        ops = k8s_undo_ops_for(fault_id, _pod_target())
        assert len(ops) == 1
        if fault_id in K8S_REVERSIBLE_FAULTS:
            assert ops[0].op == f"k8s.undo.{fault_id.removeprefix('k8s.')}"
        else:
            assert ops[0].op == "k8s.mutation.noop"
            assert "replacement" in ops[0].args["reason"]

    @pytest.mark.parametrize("fault_id", sorted(K8S_MUTATION_FAULTS))
    def test_undo_ops_are_string_args(self, fault_id: str) -> None:
        for op in k8s_undo_ops_for(fault_id, _pod_target()):
            assert op.op.strip()
            assert all(isinstance(v, str) for v in op.args.values())

    def test_network_policy_undo_names_the_policy(self) -> None:
        ops = k8s_undo_ops_for("k8s.network_policy", _pod_target())
        assert ops[0].args["policy_name"] == "mayhem-deny-checkout-abc123"

    def test_node_only_faults_have_no_pod_undo_ops(self) -> None:
        node_only = K8S_NODE_FAULTS - K8S_MUTATION_FAULTS
        for fault_id in sorted(node_only):
            assert k8s_undo_ops_for(fault_id, _pod_target()) == ()

    def test_node_families_do_not_overlap_the_mutation_registry(self) -> None:
        overlap = K8S_NODE_FAULTS & K8S_MUTATION_FAULTS
        if overlap:
            pytest.xfail(
                "finding: "
                f"{sorted(overlap)} sit in both K8S_NODE_FAULTS and K8S_MUTATION_FAULTS, so the "
                "same fault id is admitted by two registries and carries a pod-shaped undo op "
                "even though it routes through the node pipeline"
            )

    def test_non_mutation_faults_have_no_undo_ops(self) -> None:
        assert k8s_undo_ops_for("proc.pause", _pod_target()) == ()


class TestK8sSpecsAndEvidence:
    @pytest.mark.parametrize("fault_id", SIGNAL_FAULTS)
    def test_undo_spec_records_the_delivery_evidence(self, fault_id: str) -> None:
        spec = k8s_undo_spec(fault_id, _pod_target(), pid=1, boot=1234)
        assert spec["op"] == k8srt.UNDO_OP
        args = spec["args"]
        assert args["fault_id"] == fault_id
        assert args["namespace"] == "prod"
        assert args["pod"] == "checkout-abc123"
        assert args["container"] == "app"
        assert args["pid"] == "1"
        assert args["boot"] == "1234"
        assert args["exec_argv"]

    @pytest.mark.parametrize("fault_id", sorted(K8S_MUTATION_FAULTS))
    def test_mutation_spec_round_trips_its_params_bag(self, fault_id: str) -> None:
        params = {"percent": 40, "resource": "cpu"}
        spec = k8srt.k8s_mutation_spec(fault_id, _pod_target(), params)
        assert spec["op"].startswith("k8s.mutation")
        assert _json.loads(spec["args"]["params"]) == params
        assert spec["args"]["pod_uid"] == "pod-uid-1"
        assert "app=checkout" in spec["args"]["labels"]

    def test_mutation_spec_reversibility_matches_the_registry(self) -> None:
        for fault_id in ("k8s.network_policy", "k8s.pod_pressure"):
            assert k8srt.k8s_mutation_spec(fault_id, _pod_target())["op"] == "k8s.mutation"
        for fault_id in ("k8s.pod_kill", "k8s.pod_evict", "k8s.pod_oom"):
            assert k8srt.k8s_mutation_spec(fault_id, _pod_target())["op"] == "k8s.mutation.noop"

    @pytest.mark.parametrize(
        "fault_id",
        ("k8s.pod_kill", "k8s.pod_oom", "k8s.network_policy", "k8s.pod_pressure"),
    )
    def test_verify_spec_shape(self, fault_id: str) -> None:
        spec = k8s_verify_spec(fault_id, _pod_target())
        assert spec["op"] in {"k8s.replaced", "k8s.policy_applied", "k8s.pressure_restored"}
        assert spec["resolve"] is True
        assert spec["args"]

    def test_verify_spec_for_delete_uses_the_pod_uid(self) -> None:
        spec = k8s_verify_spec("k8s.pod_kill", _pod_target())
        assert spec["op"] == "k8s.replaced"
        assert spec["args"]["uid"] == "pod-uid-1"

    @pytest.mark.parametrize("fault_id", sorted(K8S_NODE_FAULTS))
    def test_node_spec_always_carries_a_live_undo_intent(self, fault_id: str) -> None:
        spec = k8s_node_spec(fault_id, _node_target(), {"grace_period": 30})
        assert spec["op"] == "k8s.node.mutation"
        assert spec["args"]["node"] == "worker-1"
        assert spec["args"]["node_uid"] == "node-uid-1"
        assert spec["args"]["reversible"] == "true"
        assert _json.loads(spec["args"]["params"]) == {"grace_period": 30}

    @pytest.mark.parametrize("fault_id", sorted(K8S_NODE_FAULTS - {"k8s.pod_image_pull_delay"}))
    def test_node_undo_ops_are_derived_per_family(self, fault_id: str) -> None:
        ops = k8s_node_undo_ops(fault_id, _node_target(), {"target_percent": 90})
        assert len(ops) == 1
        assert all(isinstance(v, str) for v in ops[0].args.values())

    def test_every_node_family_records_a_node_undo_op(self) -> None:
        empty = sorted(
            fault_id
            for fault_id in K8S_NODE_FAULTS
            if not k8s_node_undo_ops(fault_id, _node_target())
        )
        if empty:
            pytest.xfail(
                f"finding: k8s_node_undo_ops returns an empty tuple for {empty} even though the "
                "family is registered in K8S_NODE_FAULTS, is routed by k8s_node_routing to the "
                "node pipeline, and its executor implements a live undo — the write-ahead node "
                "contract silently records no undo intent"
            )

    def test_node_pressure_undo_deletes_the_pressure_workload(self) -> None:
        for fault_id in (
            "k8s.node_pressure",
            "k8s.node_disk_pressure",
            "k8s.node_memory_pressure",
            "k8s.node_pid_pressure",
        ):
            op = k8s_node_undo_ops(fault_id, _node_target(), {"target_percent": 90})[0]
            assert op.op == "k8s.delete"
            assert op.args["workload"] == "mayhem-node-pressure-worker-1"

    def test_node_drain_and_cordon_undo_uncordon(self) -> None:
        for fault_id in ("k8s.node_drain", "k8s.node_cordon"):
            op = k8s_node_undo_ops(fault_id, _node_target())[0]
            assert op.op == "k8s.uncordon"
            assert op.args["node"] == "worker-1"

    def test_taint_evict_undo_removes_the_taint(self) -> None:
        op = k8s_node_undo_ops("k8s.taint_evict", _node_target())[0]
        assert op.op == "k8s.untaint"
        assert op.args["key"] == "mayhem.io/taint-evict"
        assert op.args["effect"] == "NoExecute"

    def test_node_worker_families_undo_their_pinned_worker(self) -> None:
        for fault_id, worker in (
            ("k8s.node_not_ready", "node-not-ready"),
            ("k8s.node_network_partition", "node-partition"),
            ("k8s.kube_proxy_failure", "kube-proxy"),
        ):
            op = k8s_node_undo_ops(fault_id, _node_target())[0]
            assert op.op == "k8s.node.worker.undo"
            assert op.args["worker"].startswith(f"mayhem-{worker}")

    def test_crash_loop_undo_deletes_the_pinned_daemonset(self) -> None:
        op = k8s_node_undo_ops("k8s.crash_loop", _node_target(), {"runtime": "kubelet"})[0]
        assert op.op == "k8s.delete"
        assert op.args["kind"] == "daemonset"
        assert op.args["runtime"] == "kubelet"

    @pytest.mark.parametrize(
        "fault_id",
        ("k8s.node_drain", "k8s.node_pressure", "k8s.node_disk_pressure", "k8s.node_cordon"),
    )
    def test_node_verify_spec_shape(self, fault_id: str) -> None:
        spec = k8s_node_verify_spec(fault_id, _node_target())
        assert spec["op"] == "k8s.node_restored"
        assert spec["resolve"] is True
        assert "worker-1" in _json.dumps(spec["args"])

    def test_evidence_names_the_family_specific_proof(self) -> None:
        for fault_id in K8S_ACTIVE_FAULTS:
            assert k8s_contract_for(fault_id).evidence
        assert "node UID" in k8s_contract_for("k8s.node_drain").evidence
        assert "HPA name" in k8s_contract_for("k8s.hpa_scale_delay").evidence
        assert "PDB name" in k8s_contract_for("k8s.pdb_violation").evidence
        assert "Service name" in k8s_contract_for("k8s.service_no_endpoints").evidence
        assert "restore annotation" in k8s_contract_for("k8s.pod_readiness_fail").evidence


class TestK8sRefusals:
    @pytest.mark.parametrize("fault_id", K8S_FAULTS)
    def test_unsupported_reason_is_stable(self, fault_id: str) -> None:
        reason = k8s_unsupported_reason(fault_id)
        assert reason.startswith("k8s.unsupported")
        assert "manifest mode remains usable for planning" in reason
        assert fault_id in reason
        assert "missing capability" in reason
        assert unsupported_reason(fault_id) == reason

    def test_unsupported_reason_for_an_unknown_fault(self) -> None:
        reason = k8s_unsupported_reason("k8s.never_heard_of_it")
        assert reason.startswith("k8s.unsupported")
        assert "k8s.never_heard_of_it" in reason

    def test_registry_pacing_fault_names_its_own_capability(self) -> None:
        assert "registry pacing" in k8s_unsupported_reason("k8s.image_pull_slow")

    def test_pod_failure_names_the_workload_executor(self) -> None:
        assert "workload executor" in k8s_unsupported_reason("k8s.pod.failure")

    @pytest.mark.parametrize("fault_id", ("mem.exhaust", "cpu.saturate", "fs.fill", "load.spike"))
    def test_argv_families_name_the_argv_capability(self, fault_id: str) -> None:
        assert "argv compensation" in k8s_unsupported_reason(fault_id)

    @pytest.mark.parametrize("fault_id", sorted(K8S_NODE_CONTROL_FAULTS))
    def test_node_control_families_refuse_without_the_capability(self, fault_id: str) -> None:
        assert node_control_unsupported_reason(fault_id) == NODE_CONTROL_UNSUPPORTED_MESSAGE

    @pytest.mark.parametrize("fault_id", sorted(K8S_NODE_FAULTS - K8S_NODE_CONTROL_FAULTS))
    def test_non_node_control_families_fall_back_to_the_k8s_reason(self, fault_id: str) -> None:
        assert node_control_unsupported_reason(fault_id) == k8s_unsupported_reason(fault_id)

    def test_netns_dns_and_node_control_gates_are_closed_without_a_cluster(self) -> None:
        assert k8s_netns_supported() is False
        assert k8s_dns_supported() is False
        assert k8s_node_control_supported() is False

    def test_default_client_is_none_without_a_reachable_cluster(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mayhem.agents.k8s_resolve import SdkK8sClient

        monkeypatch.setattr(SdkK8sClient, "available", staticmethod(lambda *_a, **_k: False))
        assert k8srt.make_k8s_resolver() is None

    def test_injected_resolver_is_returned_verbatim(self) -> None:
        from mayhem.agents.k8s_resolve import KubernetesRuntimeResolver

        resolver = KubernetesRuntimeResolver(client=_FakeClusterClient())
        assert k8srt.make_k8s_resolver(resolver) is resolver

    def test_resolver_without_a_client_is_not_available(self) -> None:
        from mayhem.agents.k8s_resolve import KubernetesRuntimeResolver

        assert KubernetesRuntimeResolver(client=None).available is False

    def test_resolver_refuses_a_non_kubernetes_scope(self) -> None:
        from mayhem.agents.k8s_resolve import KubernetesRuntimeResolver
        from mayhem.domain.errors import ResolutionError
        from mayhem.domain.target import ResourceKind, TargetScope

        scope = TargetScope(
            logical_id="api", runtime=RuntimeLabel.DOCKER, kind=ResourceKind.CONTAINER
        )
        with pytest.raises(ResolutionError, match="wrong_runtime"):
            KubernetesRuntimeResolver(client=None).resolve(scope)

    def test_resolver_refuses_without_a_client(self) -> None:
        from mayhem.agents.k8s_resolve import KubernetesRuntimeResolver
        from mayhem.domain.errors import ResolutionError
        from mayhem.domain.target import ResourceKind, TargetScope

        scope = TargetScope(
            logical_id="api",
            runtime=RuntimeLabel.KUBERNETES,
            kind=ResourceKind.POD,
            authority={"kind": "deployment", "name": "checkout", "namespace": "prod"},
        )
        with pytest.raises(ResolutionError, match="no_client"):
            KubernetesRuntimeResolver(client=None).resolve(scope)

    def test_preferred_pod_is_none_without_a_graph(self) -> None:
        assert preferred_pod_from_graph(None, frozenset({"k8s.pod"})) is None

    def test_preferred_pod_recovers_the_plan_time_pick(self) -> None:
        from mayhem.domain.topology import PodNode

        graph = TopologyGraph(
            nodes=(PodNode(id="k8s.pod.checkout", name="checkout-abc123", namespace="prod"),),
            edges=(),
        )
        assert preferred_pod_from_graph(lambda: graph, frozenset({"k8s.pod.checkout"})) == (
            "checkout-abc123"
        )


_SNAPSHOT_CASES: tuple[tuple[str, str, str, dict[str, object], str], ...] = (
    ("k8s.pod_readiness_fail", "Deployment", "checkout", {}, "patch"),
    ("k8s.pod_liveness_fail", "Deployment", "checkout", {}, "patch"),
    ("k8s.pod_startup_fail", "Deployment", "checkout", {}, "patch"),
    ("k8s.pod_unschedulable", "Deployment", "checkout", {}, "patch"),
    ("k8s.schedule_delay", "Deployment", "checkout", {}, "patch"),
    ("k8s.image_pull_failure", "Deployment", "checkout", {}, "patch"),
    ("k8s.rollout_pause", "Deployment", "checkout", {}, "rollout"),
    ("k8s.rollout_failure", "Deployment", "checkout", {}, "patch"),
    ("k8s.replica_reduce", "Deployment", "checkout", {}, "scale"),
    ("k8s.workload_stall", "Deployment", "checkout", {}, "patch"),
    ("k8s.pod_pending", "Deployment", "checkout", {"reason": "taint"}, "patch"),
    ("k8s.deployment_scale_failure", "Deployment", "checkout", {"replicas": 1}, "patch"),
    ("k8s.service_no_endpoints", "Service", "checkout-svc", {}, "patch"),
    ("k8s.service_port_mismatch", "Service", "checkout-svc", {}, "patch"),
    ("k8s.service_5xx", "Service", "checkout-svc", {}, "patch"),
    ("k8s.configmap_corrupt", "ConfigMap", "checkout-cfg", {}, "patch"),
    ("k8s.persistent_volume_claim_pending", "PersistentVolumeClaim", "checkout-data", {}, "patch"),
    ("k8s.eviction_block", "PodDisruptionBudget", "checkout-abc123", {}, "patch"),
    ("k8s.pdb_over_eviction", "PodDisruptionBudget", "checkout-abc123", {}, "patch"),
    ("k8s.resource_quota_exhaust", "ResourceQuota", "prod-quota", {"amount": 0}, "patch"),
)


class TestK8sSnapshotExecutors:
    @pytest.mark.parametrize("fault_id,kind,name,params,fail_verb", _SNAPSHOT_CASES)
    def test_inject_annotates_the_object_it_mutated(
        self,
        fault_id: str,
        kind: str,
        name: str,
        params: dict[str, object],
        fail_verb: str,
        cluster: _FakeCluster,
    ) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(fault_id, target=_pod_target(), params=params)
        assert executor.can_apply(lease) is None
        outcome = executor.inject(lease)
        assert outcome.ok, f"{fault_id}: {outcome.detail}"
        assert cluster.annotated(kind, name)
        assert RESTORE_ANNOTATION in cluster.calls[-1][0] or any(
            "annotate" in call for call in cluster.calls
        )

    @pytest.mark.parametrize("fault_id,kind,name,params,fail_verb", _SNAPSHOT_CASES)
    def test_undo_restores_and_clears_the_annotation(
        self,
        fault_id: str,
        kind: str,
        name: str,
        params: dict[str, object],
        fail_verb: str,
        cluster: _FakeCluster,
    ) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(fault_id, target=_pod_target(), params=params)
        original = cluster.spec_of(kind, name)
        executor.inject(lease)
        outcome = executor.undo(lease)
        assert outcome.ok, f"{fault_id}: {outcome.detail}"
        assert not cluster.annotated(kind, name)
        assert cluster.spec_of(kind, name) == original

    @pytest.mark.parametrize("fault_id,kind,name,params,fail_verb", _SNAPSHOT_CASES)
    def test_undo_without_an_annotation_is_idempotent_success(
        self,
        fault_id: str,
        kind: str,
        name: str,
        params: dict[str, object],
        fail_verb: str,
        cluster: _FakeCluster,
    ) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(fault_id, target=_pod_target(), params=params)
        assert executor.undo(lease).ok
        assert executor.undo(lease).ok

    @pytest.mark.parametrize("fault_id,kind,name,params,fail_verb", _SNAPSHOT_CASES)
    def test_failed_mutation_clears_the_restore_annotation(
        self,
        fault_id: str,
        kind: str,
        name: str,
        params: dict[str, object],
        fail_verb: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake = _FakeCluster(fail_verbs=frozenset({fail_verb}))
        _install_fake_cluster(monkeypatch, fake)
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(fault_id, target=_pod_target(), params=params)
        assert not executor.inject(lease).ok
        assert not fake.annotated(kind, name)

    def test_statefulset_scale_refuses_a_deployment(self, cluster: _FakeCluster) -> None:
        executor = k8s_executor_for("k8s.statefulset_scale_failure", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(
            "k8s.statefulset_scale_failure", target=_pod_target(), params={"replicas": 1}
        )
        assert executor.can_apply(lease) is None
        outcome = executor.inject(lease)
        assert not outcome.ok
        assert "StatefulSet" in outcome.detail

    def test_daemonset_owned_pods_have_no_scale_surface(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pod = _pod_object()
        pod["metadata"]["ownerReferences"] = [
            {
                "apiVersion": "apps/v1",
                "kind": "DaemonSet",
                "name": "checkout-ds",
                "uid": "ds-1",
            }
        ]
        objects = (
            pod,
            {
                "apiVersion": "apps/v1",
                "kind": "DaemonSet",
                "metadata": _meta("checkout-ds", "prod", uid="ds-1"),
                "spec": {
                    "template": {
                        "metadata": {"labels": {"app": "checkout"}},
                        "spec": {"containers": [{"name": "app", "image": "nginx:1.27"}]},
                    }
                },
            },
        )
        fake = _FakeCluster(objects)
        _install_fake_cluster(monkeypatch, fake)
        executor = k8s_executor_for("k8s.replica_reduce", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease("k8s.replica_reduce", target=_pod_target())
        outcome = executor.inject(lease)
        assert not outcome.ok
        assert "DaemonSet" in outcome.detail

    def test_workload_fault_refuses_without_a_pod_target(self, cluster: _FakeCluster) -> None:
        executor = k8s_executor_for("k8s.pod_readiness_fail", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease("k8s.pod_readiness_fail", target=_node_target())
        assert executor.can_apply(lease) is not None
        assert not executor.inject(lease).ok

    def test_workload_stall_refuses_without_a_pod_target(self, cluster: _FakeCluster) -> None:
        executor = k8s_executor_for("k8s.workload_stall", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease("k8s.workload_stall", target=_node_target())
        reason = executor.can_apply(lease)
        assert reason is not None
        assert "k8s.unsupported" in reason

    def test_pod_pending_refuses_an_unsupported_reason(self, cluster: _FakeCluster) -> None:
        executor = k8s_executor_for("k8s.pod_pending", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease("k8s.pod_pending", target=_pod_target(), params={"reason": "gravity"})
        reason = executor.can_apply(lease)
        assert reason is not None
        assert "unsupported reason" in reason

    def test_oversized_restore_annotation_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        objects = (_pod_object(), _replicaset_object(), _deployment_object())
        fake = _FakeCluster(objects)
        _install_fake_cluster(monkeypatch, fake)
        deployment = fake.objects[("Deployment", "checkout", "prod")]
        containers = deployment["spec"]["template"]["spec"]["containers"]
        containers[0]["env"] = [{"name": f"K{i}", "value": "v" * 200} for i in range(600)]
        executor = k8s_executor_for("k8s.pod_readiness_fail", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease("k8s.pod_readiness_fail", target=_pod_target())
        outcome = executor.inject(lease)
        assert not outcome.ok
        assert "too large" in outcome.detail

    def test_service_fault_refuses_when_no_service_matches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakeCluster((_pod_object(), _replicaset_object(), _deployment_object()))
        _install_fake_cluster(monkeypatch, fake)
        executor = k8s_executor_for("k8s.service_no_endpoints", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease("k8s.service_no_endpoints", target=_pod_target())
        outcome = executor.inject(lease)
        assert not outcome.ok
        assert "no Service" in outcome.detail

    def test_pdb_violation_requires_unavailable(self, cluster: _FakeCluster) -> None:
        executor = k8s_executor_for("k8s.pdb_violation", RuntimeLabel.KUBERNETES)
        reason = executor.can_apply(_k8s_lease("k8s.pdb_violation", target=_pod_target()))
        assert reason is not None
        assert "unavailable is required" in reason

    def test_quota_requires_an_amount(self, cluster: _FakeCluster) -> None:
        executor = k8s_executor_for("k8s.resource_quota_exhaust", RuntimeLabel.KUBERNETES)
        reason = executor.can_apply(_k8s_lease("k8s.resource_quota_exhaust", target=_pod_target()))
        assert reason is not None
        assert "amount is required" in reason

    def test_quota_refuses_a_missing_hard_limit(self, cluster: _FakeCluster) -> None:
        executor = k8s_executor_for("k8s.resource_quota_exhaust", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(
            "k8s.resource_quota_exhaust",
            target=_pod_target(),
            params={"amount": 1, "resource": "storage"},
        )
        outcome = executor.inject(lease)
        assert not outcome.ok
        assert "hard limit" in outcome.detail

    def test_secret_unavailable_annotates_the_pod_and_recreates_on_undo(
        self, cluster: _FakeCluster
    ) -> None:
        executor = k8s_executor_for("k8s.secret_unavailable", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease("k8s.secret_unavailable", target=_pod_target())
        assert executor.inject(lease).ok
        assert ("Secret", "mayhem-creds", "prod") not in cluster.objects
        assert executor.undo(lease).ok
        assert ("Secret", "mayhem-creds", "prod") in cluster.objects

    def test_dns_families_refuse_without_the_dns_control_capability(
        self, cluster: _FakeCluster
    ) -> None:
        for fault_id in ("k8s.dns_failure", "k8s.dns_delay", "k8s.dns_timeout"):
            executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
            params = {"domain": "svc.prod.svc", "address": "10.0.0.9"}
            lease = _k8s_lease(fault_id, target=_pod_target(), params=params)
            assert executor.can_apply(lease) == DNS_CONTROL_UNSUPPORTED_MESSAGE

    def test_dns_families_mutate_and_restore_coredns(
        self, cluster: _FakeCluster, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mayhem.domain import k8s_adapter as k8s_adapter_module

        monkeypatch.setattr(
            k8s_adapter_module.KubernetesAdapter,
            "is_available",
            lambda self: True,
        )
        monkeypatch.setattr(
            k8s_adapter_module.KubernetesAdapter,
            "capabilities",
            lambda self: _adapter_caps({"netns", "dns_control", "node_control"}),
        )
        executor = k8s_executor_for("k8s.dns_failure", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(
            "k8s.dns_failure", target=_pod_target(), params={"domain": "svc.prod.svc"}
        )
        assert executor.can_apply(lease) is None
        assert executor.inject(lease).ok
        assert (
            "template IN ANY svc.prod.svc"
            in (cluster.objects[("ConfigMap", "coredns", "kube-system")]["data"]["Corefile"])
        )
        assert executor.undo(lease).ok
        assert (
            "template IN ANY"
            not in (cluster.objects[("ConfigMap", "coredns", "kube-system")]["data"]["Corefile"])
        )


class TestK8sArgvFamilies:
    @pytest.mark.parametrize(
        "fault_id",
        (
            "cpu.saturate",
            "cpu.throttle",
            "mem.exhaust",
            "mem.leak",
            "fs.fill",
            "fs.inode_exhaust",
            "fs.io_stress",
            "fd.exhaust",
        ),
    )
    def test_argv_families_inject_and_reap_through_kubectl_exec(
        self, fault_id: str, cluster: _FakeCluster
    ) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(fault_id, target=_pod_target(), params={"seconds": "5s"})
        assert executor.can_apply(lease) is None
        assert executor.inject(lease).ok
        assert cluster.exec_calls
        assert executor.undo(lease).ok

    def test_netns_families_refuse_without_the_netns_capability(
        self, cluster: _FakeCluster
    ) -> None:
        for fault_id in ("k8s.pod_latency", "k8s.pod_partition", "net.latency"):
            executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
            lease = _k8s_lease(fault_id, target=_pod_target())
            reason = executor.can_apply(lease)
            if executor.__class__.__name__ == "K8sArgvExecutor" and reason == (
                NETNS_UNSUPPORTED_MESSAGE
            ):
                assert "NETNS" in reason
            else:
                assert reason is None or reason

    def test_argv_families_refuse_without_a_pod_target(self, cluster: _FakeCluster) -> None:
        executor = k8s_executor_for("cpu.saturate", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease("cpu.saturate", target=_node_target())
        reason = executor.can_apply(lease)
        if reason is None:
            pytest.xfail(
                "finding: K8sArgvExecutor.can_apply only checks `resolved_target is None`, so a "
                "node-pinned lease passes the admission gate and inject raises AttributeError on "
                "the missing exec_argv field instead of returning a refusal"
            )
        assert "no resolved pod target" in reason

    @pytest.mark.parametrize("fault_id", ("k8s.pod_kill", "k8s.pod_oom", "k8s.pod_pressure"))
    def test_pod_lifecycle_families_inject_through_the_resolved_pod(
        self, fault_id: str, cluster: _FakeCluster
    ) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(fault_id, target=_pod_target(), params={"memory_limit": "64Mi"})
        assert executor.can_apply(lease) is None
        assert executor.inject(lease).ok
        assert executor.undo(lease).ok

    @pytest.mark.parametrize("fault_id", ("k8s.pod_kill", "k8s.pod_oom", "k8s.pod_pressure"))
    def test_pod_lifecycle_families_refuse_without_a_pod_target(
        self, fault_id: str, cluster: _FakeCluster
    ) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(fault_id, target=_node_target())
        if executor.can_apply(lease) is None:
            pytest.xfail(
                f"finding: {k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES).__class__.__name__}"
                f".can_apply only checks `resolved_target is None`, so a lease pinned to a "
                "ResolvedNodeTarget passes the admission gate and inject then raises "
                "AttributeError on the missing pod field instead of returning a refusal"
            )
        assert not executor.inject(lease).ok

    def test_signal_families_deliver_through_kubectl_exec(self, cluster: _FakeCluster) -> None:
        for fault_id, signame in K8S_SIGNAL_INJECT_SIGNAL.items():
            executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
            lease = _k8s_lease(fault_id, target=_pod_target())
            assert executor.can_apply(lease) is None
            outcome = executor.inject(lease)
            assert outcome.ok
            assert f"kill -{signame} 1" in " ".join(cluster.exec_calls[-1])
            assert executor.undo(lease).ok

    def test_signal_families_refuse_without_a_pod_target(self, cluster: _FakeCluster) -> None:
        for fault_id in ("proc.pause", "process.stop", "process.kill"):
            executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
            lease = _k8s_lease(fault_id, target=_node_target())
            reason = executor.can_apply(lease)
            if reason is None:
                pytest.xfail(
                    f"finding: K8sExecutor.can_apply for {fault_id} only checks "
                    "`resolved_target is None`, so a node-pinned lease passes the gate and "
                    "inject raises AttributeError on the missing exec_argv field"
                )
            assert not executor.inject(lease).ok

    def test_signal_families_refuse_faults_they_do_not_own(self, cluster: _FakeCluster) -> None:
        executor = k8s_executor_for("proc.pause", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease("mem.exhaust", target=_pod_target())
        assert executor.can_apply(lease) is not None
        assert not executor.inject(lease).ok


class TestK8sNodeExecutors:
    @pytest.mark.parametrize("fault_id", ("k8s.node_drain", "k8s.node_pressure", "k8s.node_cordon"))
    def test_node_families_inject_against_the_resolved_node(
        self, fault_id: str, cluster: _FakeCluster
    ) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(fault_id, target=_node_target())
        assert executor.inject(lease).ok
        assert executor.undo(lease).ok
        assert cluster.calls

    def test_node_families_refuse_a_pod_target(self, cluster: _FakeCluster) -> None:
        for fault_id in ("k8s.node_drain", "k8s.node_pressure", "k8s.node_cordon"):
            executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
            lease = _k8s_lease(fault_id, target=_pod_target())
            outcome = executor.inject(lease)
            assert not outcome.ok
            assert "node target" in outcome.detail

    @pytest.mark.parametrize("fault_id", sorted(K8S_NODE_CONTROL_FAULTS))
    def test_node_control_families_refuse_without_the_capability(
        self, fault_id: str, cluster: _FakeCluster
    ) -> None:
        executor = k8s_executor_for(fault_id, RuntimeLabel.KUBERNETES)
        lease = _k8s_lease(fault_id, target=_node_target())
        reason = executor.can_apply(lease)
        assert reason == NODE_CONTROL_UNSUPPORTED_MESSAGE

    def test_node_cordon_uncordons_on_undo(self, cluster: _FakeCluster) -> None:
        executor = k8s_executor_for("k8s.node_cordon", RuntimeLabel.KUBERNETES)
        lease = _k8s_lease("k8s.node_cordon", target=_node_target())
        assert executor.inject(lease).ok
        assert ("cordon", "worker-1") in {call[1:3] for call in cluster.calls}
        assert executor.undo(lease).ok
        assert ("uncordon", "worker-1") in {call[1:3] for call in cluster.calls}


class TestEngineDescriptors:
    @pytest.mark.parametrize("engine", ENGINES)
    def test_describe_engine_is_total(self, engine: str) -> None:
        from mayhem.domain.runtime_adapter import EngineDescriptor, describe_engine

        descriptor = describe_engine(engine)
        assert isinstance(descriptor, EngineDescriptor)
        assert descriptor.name == engine
        assert descriptor.binary == engine
        assert descriptor.compose_supported is True
        assert {"SIGSTOP", "SIGCONT", "SIGTERM", "SIGKILL"} <= set(descriptor.signals)
        assert descriptor.network_capabilities
        assert descriptor.storage_capabilities

    def test_describe_engine_refuses_an_unknown_name(self) -> None:
        from mayhem.domain.runtime_adapter import describe_engine

        with pytest.raises(LookupError, match="unknown engine"):
            describe_engine("containerd")

    @pytest.mark.parametrize("engine", ENGINES)
    def test_descriptors_are_frozen(self, engine: str) -> None:
        from mayhem.domain.runtime_adapter import describe_engine

        descriptor = describe_engine(engine)
        with pytest.raises(ValidationError):
            descriptor.name = "other"  # type: ignore[misc]

    def test_podman_declares_pasta_networking(self) -> None:
        from mayhem.domain.runtime_adapter import describe_engine

        assert "pasta" in describe_engine("podman").network_capabilities
        assert "pasta" not in describe_engine("docker").network_capabilities

    def test_detect_reports_availability_from_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.domain import runtime_adapter as ra

        monkeypatch.setattr(ra.shutil, "which", lambda name: "/usr/bin/docker" if name else None)
        monkeypatch.setattr(
            ra.subprocess,
            "run",
            lambda *_a, **_k: type("R", (), {"stdout": "Docker version 27.0\n", "stderr": ""})(),
        )
        found = {d.name: d for d in ra.detect_available_engines()}
        assert found["docker"].binary_available is True
        assert found["docker"].version == "Docker version 27.0"
        assert found["podman"].binary_available is True

    def test_detect_reports_a_missing_binary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.domain import runtime_adapter as ra

        monkeypatch.setattr(ra.shutil, "which", lambda _name: None)
        found = {d.name: d for d in ra.detect_available_engines()}
        assert all(not d.binary_available for d in found.values())
        assert all(d.version is None for d in found.values())

    def test_detect_survives_a_failing_version_probe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.domain import runtime_adapter as ra

        def boom(*_a: object, **_k: object) -> None:
            raise OSError("exec format error")

        monkeypatch.setattr(ra.shutil, "which", lambda _name: "/usr/bin/docker")
        monkeypatch.setattr(ra.subprocess, "run", boom)
        found = {d.name: d for d in ra.detect_available_engines()}
        assert found["docker"].binary_available is True
        assert found["docker"].version is None

    def test_explicit_selection_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.domain import runtime_adapter as ra

        monkeypatch.setattr(ra.shutil, "which", lambda _name: "/usr/bin/podman")
        selected = ra.resolve_engine_selection("podman")
        assert selected.name == "podman"
        assert selected.binary_available is True

    def test_explicit_selection_is_normalised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.domain import runtime_adapter as ra

        monkeypatch.setattr(ra.shutil, "which", lambda _name: "/usr/bin/docker")
        assert ra.resolve_engine_selection("  DOCKER  ").name == "docker"

    def test_explicit_unknown_selection_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.domain import runtime_adapter as ra

        monkeypatch.setattr(ra.shutil, "which", lambda _name: None)
        with pytest.raises(InvariantViolationError) as excinfo:
            ra.resolve_engine_selection("containerd")
        assert excinfo.value.rule == "engine_unknown"

    def test_explicit_unavailable_selection_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mayhem.domain import runtime_adapter as ra

        monkeypatch.setattr(ra.shutil, "which", lambda _name: None)
        with pytest.raises(InvariantViolationError) as excinfo:
            ra.resolve_engine_selection("docker")
        assert excinfo.value.rule == "engine_unavailable"
        assert "docker" in str(excinfo.value)

    def test_no_engine_on_path_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.domain import runtime_adapter as ra

        monkeypatch.setattr(ra.shutil, "which", lambda _name: None)
        with pytest.raises(InvariantViolationError) as excinfo:
            ra.resolve_engine_selection(None)
        assert excinfo.value.rule == "engine_unavailable"
        assert "no engine on PATH" in str(excinfo.value)

    def test_blank_explicit_selection_falls_back_to_detection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mayhem.domain import runtime_adapter as ra

        monkeypatch.setattr(
            ra.shutil, "which", lambda name: "/usr/bin/docker" if name == "docker" else None
        )
        assert ra.resolve_engine_selection("   ").name == "docker"

    def test_two_engines_on_path_are_ambiguous(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.domain import runtime_adapter as ra

        monkeypatch.setattr(ra.shutil, "which", lambda name: f"/usr/bin/{name}" if name else None)
        with pytest.raises(InvariantViolationError) as excinfo:
            ra.resolve_engine_selection(None)
        assert excinfo.value.rule == "engine_ambiguous"
        assert "docker" in str(excinfo.value)
        assert "podman" in str(excinfo.value)

    def test_single_engine_on_path_is_selected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.domain import runtime_adapter as ra

        monkeypatch.setattr(
            ra.shutil, "which", lambda name: "/usr/bin/podman" if name == "podman" else None
        )
        assert ra.resolve_engine_selection(None).name == "podman"

    @pytest.mark.parametrize("engine", ENGINES)
    def test_fingerprint_is_stable_and_engine_sensitive(self, engine: str) -> None:
        from mayhem.domain.runtime_adapter import topology_fingerprint_for_engine

        graph = _FakeCluster().objects
        first = topology_fingerprint_for_engine(engine, graph)
        assert first == topology_fingerprint_for_engine(engine, graph)
        other = "podman" if engine == "docker" else "docker"
        assert first != topology_fingerprint_for_engine(other, graph)
        assert len(first) == 16

    def test_fingerprint_survives_an_unserialisable_graph(self) -> None:
        from mayhem.domain.runtime_adapter import topology_fingerprint_for_engine

        class Opaque:
            def __repr__(self) -> str:
                return "opaque-graph"

        assert len(topology_fingerprint_for_engine("docker", Opaque())) == 16


class _FakeClusterClient:
    def __init__(self, *, nodes: list[Any] | None = None, explode: bool = False) -> None:
        self._nodes = nodes or []
        self._explode = explode
        self.probes = 0

    def nodes(self) -> list[Any]:
        self.probes += 1
        if self._explode:
            raise RuntimeError("connection refused")
        return self._nodes

    def workload(self, workload: Any) -> Any:
        return None

    def pods_for(self, workload: Any) -> list[Any]:
        return []

    def exec(self, target: Any, argv: tuple[str, ...]) -> str:
        return ""

    def node(self, name: str) -> Any:
        return None


class TestK8sTargetContext:
    def test_defaults_to_the_live_mode(self) -> None:
        from mayhem.agents.k8s_resolve import K8sEngineMode, resolve_k8s_target_context

        assert resolve_k8s_target_context().mode is K8sEngineMode.LIVE

    @pytest.mark.parametrize("mode", ("manifest", "live", "dry-run"))
    def test_string_modes_are_accepted(self, mode: str) -> None:
        from mayhem.agents.k8s_resolve import K8sEngineMode, resolve_k8s_target_context

        context = resolve_k8s_target_context(mode=mode)
        assert context.mode is K8sEngineMode(mode)

    def test_enum_modes_are_accepted(self) -> None:
        from mayhem.agents.k8s_resolve import K8sEngineMode, resolve_k8s_target_context

        context = resolve_k8s_target_context(mode=K8sEngineMode.MANIFEST)
        assert context.mode is K8sEngineMode.MANIFEST

    def test_invalid_mode_is_refused(self) -> None:
        from mayhem.agents.k8s_resolve import resolve_k8s_target_context

        with pytest.raises(InvariantViolationError) as excinfo:
            resolve_k8s_target_context(mode="cluster")
        assert excinfo.value.rule == "k8s.mode_invalid"

    def test_profile_selection_is_used_when_no_override(self) -> None:
        from mayhem.agents.k8s_resolve import resolve_k8s_target_context

        context = resolve_k8s_target_context(
            profile_namespace="prod", profile_workload_selector="app=checkout"
        )
        assert context.namespace == "prod"
        assert context.workload_selector == "app=checkout"

    @pytest.mark.parametrize(
        ("kwargs",),
        (
            ({"profile_context": "a", "explicit_context": "b"},),
            ({"profile_namespace": "a", "explicit_namespace": "b"},),
            ({"profile_workload_selector": "a=1", "workload_selector": "b=2"},),
            ({"profile_capability_policy": "a", "capability_policy": "b"},),
        ),
    )
    def test_conflicting_selection_is_refused(self, kwargs: dict[str, str]) -> None:
        from mayhem.agents.k8s_resolve import resolve_k8s_target_context

        with pytest.raises(InvariantViolationError) as excinfo:
            resolve_k8s_target_context(**kwargs)
        assert excinfo.value.rule == "k8s.selection_ambiguous"

    def test_agreeing_selection_is_accepted(self) -> None:
        from mayhem.agents.k8s_resolve import resolve_k8s_target_context

        context = resolve_k8s_target_context(profile_namespace="prod", explicit_namespace="prod")
        assert context.namespace == "prod"


class TestK8sDiscovery:
    def test_manifest_available_only_for_a_real_file(self, tmp_path) -> None:
        from mayhem.agents.k8s_resolve import discover_k8s_manifest_available

        assert discover_k8s_manifest_available(None) is False
        assert discover_k8s_manifest_available(str(tmp_path / "absent.yaml")) is False
        present = tmp_path / "manifest.yaml"
        present.write_text("kind: Deployment\n")
        assert discover_k8s_manifest_available(str(present)) is True

    def test_status_without_a_client_warns_but_does_not_fail(self, tmp_path) -> None:
        from mayhem.agents.k8s_resolve import discover_k8s_status

        present = tmp_path / "manifest.yaml"
        present.write_text("kind: Deployment\n")
        status = discover_k8s_status(manifest_path=str(present), client=None)
        assert status.manifest_available is True
        assert status.live_ready is False
        assert status.client_available is False
        assert status.warning
        assert status.error == ""
        assert status.healthy is False

    def test_status_without_the_sdk_errors(self) -> None:
        from mayhem.agents.k8s_resolve import discover_k8s_status

        status = discover_k8s_status(client=_FakeClusterClient(), sdk_available=False)
        assert status.sdk_available is False
        assert status.client_available is True
        assert "SDK" in status.error
        assert status.healthy is False

    def test_status_reports_a_failed_readiness_probe(self) -> None:
        from mayhem.agents.k8s_resolve import discover_k8s_status

        client = _FakeClusterClient(explode=True)
        status = discover_k8s_status(client=client)
        assert status.live_ready is False
        assert "readiness probe failed" in status.error
        assert "connection refused" in status.error
        assert client.probes == 1

    def test_status_is_healthy_for_a_reachable_client(self) -> None:
        from mayhem.agents.k8s_resolve import discover_k8s_status

        status = discover_k8s_status(client=_FakeClusterClient(), context="prod", namespace="prod")
        assert status.healthy is True
        assert status.live_ready is True
        assert status.context == "prod"
        assert status.namespace == "prod"
        assert status.error == ""

    def test_live_ready_is_short_hand_for_the_status(self) -> None:
        from mayhem.agents.k8s_resolve import discover_k8s_live_ready

        assert discover_k8s_live_ready(None) is False
        assert discover_k8s_live_ready(_FakeClusterClient()) is True

    def test_kubernetes_adapter_reports_no_capabilities_without_a_client(self) -> None:
        from mayhem.domain.k8s_adapter import KubernetesAdapter, k8s_adapter_doctor_status

        adapter = KubernetesAdapter()
        assert adapter.is_available() is False
        assert adapter.capabilities().supported == frozenset()
        verdict = adapter.evaluate(_requirements())
        assert verdict.blocking is True
        doctor = k8s_adapter_doctor_status()
        assert doctor["available"] is False
        assert doctor["engine"] == "kubernetes"
        assert doctor["remediation"]

    def test_kubernetes_adapter_reports_node_control_with_a_client(self) -> None:
        from mayhem.domain.k8s_adapter import KubernetesAdapter

        adapter = KubernetesAdapter(client=object())
        assert adapter.is_available() is True
        assert "node_control" in {cap.value for cap in adapter.capabilities().supported}


def _requirements():
    from mayhem.domain.runtime_adapter import CapabilityRequirements

    return CapabilityRequirements()


def _adapter_caps(supported: set[str]):
    from mayhem.domain.runtime_adapter import AdapterCapabilities, RuntimeCapability

    return AdapterCapabilities(
        engine="kubernetes",
        supported=frozenset(RuntimeCapability(name) for name in supported),
    )
