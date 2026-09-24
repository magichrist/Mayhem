from __future__ import annotations

import json
from typing import TYPE_CHECKING

from mayhem.agents import executors as executor_module
from mayhem.agents.executors import PayloadExecutor, ToolExecutor, executor_for
from mayhem.controller.compensation import compensated, template_for
from mayhem.domain.catalog import definition_for
from mayhem.domain.experiments import PlannedFault
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.topology import ContainerNode, ProcessNode, ServiceNode

if TYPE_CHECKING:
    import pytest

CONTAINER_IDS = (
    "cpu.burst",
    "mem.freeze",
    "mem.swap_pressure",
    "fs.quota",
    "fs.write_delay",
    "net.corrupt",
    "net.congestion",
    "process.restart_delay",
    "http.upstream_timeout",
    "app.response_5xx",
)


def _node() -> tuple[ContainerNode, ProcessNode]:
    container = ContainerNode(
        id="ctr-api",
        name="api",
        engine="podman",
        runtime_identity=RuntimeIdentity(runtime="podman", host_id="h1", runtime_id="api"),
        runtime_metadata=RuntimeMetadata(service="api", name="api"),
        container_name="api-container",
        state="running",
    )
    process = ProcessNode(
        id="proc-api",
        name="api",
        pid=4242,
        host_id="h1",
        container_name="api-container",
    )
    return container, process


def _params(fault_id: str) -> dict[str, object]:
    definition = definition_for(fault_id)
    params: dict[str, object] = {}
    for spec in definition.params_schema:
        if spec.required and spec.default is None:
            params[spec.name] = "5s" if spec.type.value == "duration" else 5
    return params


def _lease(fault_id: str, undo_ops: tuple[UndoOp, ...]) -> FaultLease:
    addressed = tuple(
        UndoOp(
            op=op.op,
            args={**op.args, "engine": "podman", "cont": "api-container"},
            idempotent=op.idempotent,
        )
        for op in undo_ops
    )
    return FaultLease(
        id=f"l-{fault_id.replace('.', '-')}",
        run_id="run",
        fault_id=fault_id,
        owner_agent="test",
        targets=frozenset({"ctr-api"}),
        undo_ops=addressed,
        verify_probes=(VerifyProbe(probe="exec", args={"cmd": ["true"]}),),
        state=LeaseState.ACTIVE,
    )


def test_each_container_id_has_deterministic_executor_and_compensation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(executor_module, "run_tool", lambda _argv, **_kwargs: _successful_tool())
    container, process = _node()
    for fault_id in CONTAINER_IDS:
        executor = executor_for(fault_id)
        assert isinstance(executor, (PayloadExecutor, ToolExecutor))
        planned = PlannedFault(
            fault_id=fault_id,
            targets=(),
            duration=5.0,
            params=_params(fault_id),
        )
        compensated_fault = compensated(planned, (container, process))
        lease = _lease(fault_id, compensated_fault.undo_ops)
        assert template_for(fault_id) is not None
        assert executor.inject(lease).ok
        assert executor.undo(lease).ok


def test_container_executors_use_original_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        executor_module,
        "run_tool",
        lambda argv, **kwargs: calls.append(list(argv)) or _successful_tool(),
    )
    container, process = _node()
    for fault_id in CONTAINER_IDS:
        planned = PlannedFault(
            fault_id=fault_id,
            targets=(),
            duration=5.0,
            params=_params(fault_id),
        )
        lease = _lease(fault_id, compensated(planned, (container, process)).undo_ops)
        executor = executor_for(fault_id)
        assert executor is not None
        assert executor.inject(lease).ok
        assert executor.undo(lease).ok
    assert calls


def test_container_executor_refuses_missing_execution_spec() -> None:
    lease = FaultLease(
        id="l-missing-spec",
        run_id="run",
        fault_id="cpu.burst",
        owner_agent="test",
        targets=frozenset({"ctr-api"}),
        state=LeaseState.ACTIVE,
        undo_ops=(UndoOp(op="noop", args={}),),
        verify_probes=(VerifyProbe(probe="exec", args={"cmd": ["true"]}),),
    )
    executor = executor_for("cpu.burst")
    assert isinstance(executor, PayloadExecutor)
    assert not executor.inject(lease).ok


def test_service_target_compensation_uses_stable_json_contract() -> None:
    service = ServiceNode(id="svc-api", name="api", container_name="api-container")
    process = ProcessNode(id="proc-api", name="api", pid=4242, host_id="h1")
    for fault_id in ("http.upstream_timeout", "app.response_5xx"):
        planned = PlannedFault(
            fault_id=fault_id,
            targets=(),
            duration=5.0,
            params=_params(fault_id),
        )
        result = compensated(planned, (service, process))
        op = result.undo_ops[0]
        assert isinstance(json.loads(op.args["inject_argv"]), list)
        assert isinstance(json.loads(op.args["undo_argv"]), list)


def _successful_tool():
    from types import SimpleNamespace

    return SimpleNamespace(succeeded=True, stdout="", stderr="", exit_code=0)
