"""Milestone 8 — Operations Arsenal: DNS/TLS/app operations + load/stress/fuzz generators.

Phase 8.1 (operations) wires DNS/TLS/application-level faults as cancellable,
fingerprintable operations; the TLS family is a real gap (``tls`` was not
declared on any executor prefix) and is exercised here. Phase 8.2 (generators)
verifies the load/stress/fuzz families are bounded, deadline-bound, cancellable
operations with the M6 no-leftover guarantee (undo kills the recorded marker pid
idempotently).
"""

from __future__ import annotations

import json

import pytest

from mayhem.agents.executors import PayloadExecutor, ToolExecutor, executor_for
from mayhem.controller.compensation import _payload_source, template_for
from mayhem.domain.capabilities import Capability
from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import PlannedFault
from mayhem.domain.faults import FaultCategory
from mayhem.domain.topology import ProcessNode, ServiceNode

# Phase 8.1/8.2 archetypes exercised in this milestone.
_M8_DNS_OPS = ("dns.resolve_delay", "dns.nxdomain")
_M8_TLS_OPS = ("tls.certificate_expired",)
_M8_APP_OPS = ("net.latency", "http.error_injection", "db.slow_query")
_M8_GENERATORS = ("load.spike", "fuzz.protocol_abuse")


def _tool_fault(fault_id: str, **params: object) -> PlannedFault:
    return PlannedFault(fault_id=fault_id, targets=(), params=params or {}, duration=10.0)


def _svc_api() -> tuple[ServiceNode, ProcessNode]:
    return (
        ServiceNode(id="svc-api", name="api", container_name="testcase-api"),
        ProcessNode(id="p-api", name="api", pid=4242, host_id="h1", container_name=None),
    )


class TestPhase81Operations:
    """DNS/TLS/application faults are distinct, dispatcheable operations."""

    def test_all_operations_resolve_to_an_executor(self) -> None:
        for fid in (
            *_M8_DNS_OPS,
            *_M8_TLS_OPS,
            *_M8_APP_OPS,
        ):
            ex = executor_for(fid)
            assert ex is not None, f"{fid}: no executor claims this operation prefix"
            assert isinstance(ex, ToolExecutor), f"{fid}: expected ToolExecutor"

    def test_tls_was_missing_from_tool_dispatch(self) -> None:
        """ADR-M8-1 regression: tls must not fall through to a missing executor."""
        for fid in _M8_TLS_OPS:
            assert isinstance(executor_for(fid), ToolExecutor), (
                f"{fid}: TLS prefix must route to ToolExecutor (previously unresolved)"
            )

    def test_tls_operation_has_catalog_and_compensation(self) -> None:
        for fid in _M8_TLS_OPS:
            defn = definition_for(fid)
            assert defn.category == FaultCategory.TLS
            assert template_for(fid) is not None, f"{fid}: missing compensation"

    def test_operations_are_fingerprinted_path_operations(self) -> None:
        """DNS/TLS operations carry the M2 network fingerprint ancestry."""
        for fid in _M8_DNS_OPS:
            defn = definition_for(fid)
            assert Capability.NET_ADMIN in defn.required_caps

    def test_dns_resolve_delay_template_reversible(self) -> None:
        ops, probes = template_for("dns.resolve_delay").build(
            _tool_fault("dns.resolve_delay", seconds=5), _svc_api()
        )
        assert len(ops) == 1 and len(probes) == 1
        op = ops[0]
        inject = json.loads(op.args["inject_argv"])
        undo = json.loads(op.args["undo_argv"])
        assert "cp " in inject[-1]  # backs up before mutating
        assert "mv -f" in undo[-1]  # restores original
        # no leftover: undo removes the marker
        marker = probes[0].args["cmd"][-1].split(" ")[-1]
        assert marker in undo[-1]

    def test_tls_certificate_expired_template_reversible(self) -> None:
        ops, probes = template_for("tls.certificate_expired").build(
            _tool_fault("tls.certificate_expired"), _svc_api()
        )
        assert len(ops) == 1 and len(probes) == 1
        op = ops[0]
        inject = json.loads(op.args["inject_argv"])
        undo = json.loads(op.args["undo_argv"])
        assert "cp " in inject[-1]
        assert "mv -f" in undo[-1]
        marker = probes[0].args["cmd"][-1].split(" ")[-1]
        assert marker in undo[-1]


class TestPhase82Generators:
    """load/stress/fuzz generators are bounded, cancellable, no-leftover."""

    def test_generators_resolve_to_payload_executor(self) -> None:
        for fid in _M8_GENERATORS:
            assert isinstance(executor_for(fid), PayloadExecutor), (
                f"{fid}: generator must run via PayloadExecutor (backgrounded, killable)"
            )

    def test_generators_are_deadline_bound_by_max_duration(self) -> None:
        for fid in _M8_GENERATORS:
            defn = definition_for(fid)
            assert defn.max_duration_s > 0
            # generator payload must be deadline-bound, never "unbounded": the
            # payload sleeps through its blast window so the experiment's
            # duration is the operation's bound (ADR-M8-2).
            fault = PlannedFault(fault_id=fid, targets=(), params={}, duration=8.0)
            source = _payload_source(fault, "/tmp/mayhem.m8.pid")
            assert "time.sleep(8.0)" in source, (
                f"{fid}: payload must sleep through its blast window (bounded op)"
            )

    def test_generator_undo_kills_recorded_pid_idempotently(self) -> None:
        for fid in _M8_GENERATORS:
            fault = PlannedFault(fault_id=fid, targets=(), params={}, duration=8.0)
            source = _payload_source(fault, "/tmp/mayhem.m8.pid")
            assert "open('/tmp/mayhem.m8.pid', 'w').write(str(os.getpid()))" in source
            ops, _probes = template_for(fid).build(fault, _svc_api())
            undo = ops[0]
            assert undo.op == "payload.undo"
            marker = undo.args.get("marker")
            assert undo.args.get("payload"), f"{fid}: generator undo must carry a kill payload"
            assert marker, f"{fid}: generator undo must carry a marker pid path"

    def test_fuzz_is_high_risk_and_bounded(self) -> None:
        defn = definition_for("fuzz.protocol_abuse")
        assert defn.risk.value == "high"
        assert defn.max_duration_s <= 300.0

    def test_generator_params_validated(self) -> None:
        defn = definition_for("load.spike")
        with pytest.raises((SchemaValidationError, ValueError)):
            defn.validate_params({"rps": "not-an-int"})
