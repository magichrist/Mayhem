"""Wave 1: parameters that retire 31 proposed fault ids.

Two of these are regression guards for defects that shipped:

* ``db.query_error`` declared ``error: "deadlock"`` but its compensation read
  only ``probability`` and ``port``, so every value produced the same TCP RST.
  The param was advertised in ``mayhem discover faults`` and did nothing.
* ``db.slow_query`` advertised latency while shipping an ``iptables DROP`` — a
  blackhole, which is the wire behaviour of the very fault id it was contrasted
  against. ``mode`` makes the default honest and keeps the old behaviour
  reachable.
"""

from __future__ import annotations

import json

import pytest

from mayhem.controller.compensation import compensated
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import PlannedFault
from mayhem.domain.identity import RuntimeIdentity
from mayhem.domain.topology import ContainerNode

_RUNTIME = RuntimeIdentity(runtime="podman", host_id="h1", runtime_id="api")
_NODE = ContainerNode(
    id="ctr.api",
    name="api",
    engine="podman",
    runtime_identity=_RUNTIME,
    container_name="testcase-api",
    state="running",
)
_NODES = (_NODE,)


def _fault(fault_id: str, params: dict[str, object]) -> PlannedFault:
    # Go through validate_params the way the planner does: it normalises
    # DURATION params ("10s" -> 10.0), and the compensation builders rely on
    # that normalisation having happened.
    from mayhem.domain.catalog import definition_for

    normalized = definition_for(fault_id).validate_params(params)
    return PlannedFault(
        fault_id=fault_id,
        params=normalized,
        duration=5.0,
        targets=(),
        undo_ops=(),
        verify_probes=(),
        runtime_identity=_RUNTIME,
    )


def _argv(fault_id: str, params: dict[str, object]) -> tuple[list[str], list[str]]:
    written = compensated(_fault(fault_id, params), _NODES)
    assert written.undo_ops and written.verify_probes
    op = written.undo_ops[0]
    return json.loads(op.args["inject_argv"]), json.loads(op.args["undo_argv"])


def _payload(fault_id: str, params: dict[str, object]) -> str:
    from mayhem.controller.compensation import _payload_source

    return _payload_source(_fault(fault_id, params), "/tmp/mayhem.test.pid")


class TestDbQueryErrorParamIsLive:
    """The regression guard for the inert-param defect."""

    @pytest.mark.parametrize(
        "error",
        ["deadlock", "lock_timeout", "serialization_failure"],
    )
    def test_each_error_value_builds_a_compensated_step(self, error: str) -> None:
        inject, undo = _argv("db.query_error", {"error": error})
        assert inject and undo

    def test_error_values_produce_distinct_argv(self) -> None:
        """If this fails, the param is inert again."""
        argv_by_error = {
            error: " ".join(_argv("db.query_error", {"error": error})[0])
            for error in ("deadlock", "lock_timeout", "serialization_failure")
        }
        assert len(set(argv_by_error.values())) == 3, argv_by_error

    def test_deadlock_resets_the_connection(self) -> None:
        inject, _ = _argv("db.query_error", {"error": "deadlock"})
        assert "REJECT" in inject
        assert "tcp-reset" in inject

    def test_lock_timeout_blackholes_so_the_client_deadline_fires(self) -> None:
        inject, _ = _argv("db.query_error", {"error": "lock_timeout"})
        assert "DROP" in inject
        assert "REJECT" not in inject

    def test_serialization_failure_injects_latency_on_the_db_flow_only(self) -> None:
        inject, undo = _argv(
            "db.query_error", {"error": "serialization_failure", "timeout_ms": 3000}
        )
        body = " ".join(inject)
        assert "netem delay 3000ms" in body
        # port-scoped: a filter steers only the DB dport into the shaped band,
        # so unrelated container egress is not degraded.
        assert "match ip dport 3306" in body
        assert undo == ["@engine", "exec", "@cont", "sh", "-c", "tc qdisc del dev eth0 root"]

    def test_unknown_error_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="fault_error_mode"):
            _argv("db.query_error", {"error": "nonsense"})

    def test_timeout_ms_is_range_checked(self) -> None:
        from mayhem.domain.catalog import definition_for
        from mayhem.domain.errors import SchemaValidationError
        from mayhem.domain.faults import ParamType

        spec = next(
            p for p in definition_for("db.query_error").params_schema if p.name == "timeout_ms"
        )
        assert spec.type is ParamType.INTEGER
        assert (spec.minimum, spec.maximum) == (100, 120000)
        assert definition_for("db.query_error").validate_params({"timeout_ms": 120000})
        with pytest.raises(SchemaValidationError):
            definition_for("db.query_error").validate_params({"timeout_ms": 1})


class TestDbSlowQueryMode:
    def test_default_is_latency_not_a_blackhole(self) -> None:
        inject, _ = _argv("db.slow_query", {"seconds": 2})
        assert "netem delay 2000ms" in " ".join(inject)

    def test_timeout_mode_keeps_the_previous_drop_behaviour(self) -> None:
        inject, undo = _argv("db.slow_query", {"mode": "timeout", "seconds": 2})
        assert "DROP" in inject
        assert "-D" in undo

    def test_the_two_modes_differ(self) -> None:
        latency = _argv("db.slow_query", {"mode": "latency", "seconds": 2})[0]
        timeout = _argv("db.slow_query", {"mode": "timeout", "seconds": 2})[0]
        assert latency != timeout

    def test_unknown_mode_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="fault_error_mode"):
            _argv("db.slow_query", {"mode": "nonsense"})

    def test_requires_the_net_admin_capability_it_actually_uses(self) -> None:
        from mayhem.domain.capabilities import Capability
        from mayhem.domain.catalog import definition_for

        assert Capability.NET_ADMIN in definition_for("db.slow_query").required_caps


class TestPortScopedNetemTeardown:
    @pytest.mark.parametrize(
        ("fault_id", "params"),
        [
            ("db.slow_query", {"mode": "latency", "seconds": 2}),
            ("db.query_error", {"error": "serialization_failure"}),
        ],
    )
    def test_undo_removes_the_whole_qdisc_tree(
        self, fault_id: str, params: dict[str, object]
    ) -> None:
        """A single root delete must not leave a band or filter behind."""
        _, undo = _argv(fault_id, params)
        assert undo == ["@engine", "exec", "@cont", "sh", "-c", "tc qdisc del dev eth0 root"]

    def test_verify_probe_asserts_the_netem_qdisc_is_gone(self) -> None:
        written = compensated(_fault("db.slow_query", {"mode": "latency", "seconds": 2}), _NODES)
        raw = written.verify_probes[0].args["cmd"]
        assert isinstance(raw, list)
        cmd = " ".join(str(part) for part in raw)
        # the shell body must negate the probe: the qdisc must be *absent*
        assert "tc qdisc show" in cmd
        assert "netem" in cmd
        assert "! tc qdisc show" in cmd


class TestFsFillPath:
    def test_defaults_to_tmp(self) -> None:
        assert "'/tmp'" in _payload("fs.fill", {"percent": 20})

    @pytest.mark.parametrize("path", ["/var/log", "/data", "/var/lib/postgresql"])
    def test_honours_an_explicit_path(self, path: str) -> None:
        src = _payload("fs.fill", {"path": path, "percent": 20})
        assert repr(path) in src
        compile(src, "<fs.fill>", "exec")

    def test_relative_path_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="fault_path"):
            _payload("fs.fill", {"path": "relative/dir"})

    def test_the_target_path_is_a_catalog_param(self) -> None:
        from mayhem.domain.catalog import definition_for

        spec = next(p for p in definition_for("fs.fill").params_schema if p.name == "path")
        assert spec.default == "/tmp"


class TestFdExhaustMode:
    def test_exhaust_is_the_default_and_writes_the_count_artifact(self) -> None:
        src = _payload("fd.exhaust", {"limit": 32})
        assert ".count" in src
        assert "time.sleep(0.05)" not in src

    def test_leak_drips_descriptors_and_never_completes_a_burst(self) -> None:
        src = _payload("fd.exhaust", {"mode": "leak", "limit": 32})
        assert "time.sleep(0.05)" in src
        assert ".count" not in src
        compile(src, "<fd.exhaust>", "exec")

    def test_unknown_mode_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="fault_error_mode"):
            _payload("fd.exhaust", {"mode": "nonsense"})


class TestMemExhaustMode:
    @pytest.mark.parametrize("mode", ["allocate", "reclaim", "freeze"])
    def test_every_declared_mode_compiles(self, mode: str) -> None:
        src = _payload("mem.exhaust", {"mode": mode, "hold_s": "10s", "percent": 40})
        compile(src, "<mem.exhaust>", "exec")

    def test_reclaim_returns_pages_with_madvise_free(self) -> None:
        """The mechanism that distinguishes reclaim from plain allocation."""
        src = _payload("mem.exhaust", {"mode": "reclaim", "hold_s": "10s", "percent": 40})
        assert "MADV_FREE" in src
        assert "libc.madvise" in src

    def test_freeze_holds_a_bounded_window(self) -> None:
        src = _payload("mem.exhaust", {"mode": "freeze", "hold_s": "10s", "percent": 40})
        assert "time.sleep(10)" in src
        assert "MADV_FREE" not in src

    def test_allocate_still_refuses_to_oom_the_container(self) -> None:
        """The 95% cgroup cap is a safety property and must not be lost."""
        for mode in ("allocate", "reclaim", "freeze"):
            assert "lim * 95 // 100" in _payload("mem.exhaust", {"mode": mode, "percent": 90})

    def test_unknown_mode_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="fault_error_mode"):
            _payload("mem.exhaust", {"mode": "nonsense"})


class TestFsIoStressOp:
    def test_both_is_the_default(self) -> None:
        src = _payload("fs.io_stress", {"read_mb_s": 10, "write_mb_s": 10})
        assert "rd = 10485760" in src
        assert "wr = 10485760" in src

    def test_read_does_not_drive_the_write_rate(self) -> None:
        src = _payload("fs.io_stress", {"op": "read", "read_mb_s": 10, "write_mb_s": 10})
        assert "rd = 10485760" in src
        assert "wr = 0" in src

    def test_write_does_not_drive_the_read_rate(self) -> None:
        src = _payload("fs.io_stress", {"op": "write", "read_mb_s": 10, "write_mb_s": 10})
        assert "wr = 10485760" in src
        assert "rd = 0" in src

    def test_unknown_op_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="fault_error_mode"):
            _payload("fs.io_stress", {"op": "nonsense"})


class TestImpactRequirementsTrackRealTooling:
    @pytest.mark.parametrize("fault_id", ["db.query_error", "db.slow_query"])
    def test_latency_modes_declare_tc(self, fault_id: str) -> None:
        """The gate must require what the injector actually shells out to."""
        from mayhem.agents.impact import REQUIREMENTS

        assert "tc" in REQUIREMENTS[fault_id].bins
        assert "NET_ADMIN" in REQUIREMENTS[fault_id].caps

    @pytest.mark.parametrize("fault_id", ["fs.fill", "fd.exhaust", "mem.exhaust", "fs.io_stress"])
    def test_widened_payload_faults_still_require_python(self, fault_id: str) -> None:
        from mayhem.agents.impact import REQUIREMENTS

        assert "python" in REQUIREMENTS[fault_id].bins

    def test_every_new_mode_enum_is_a_catalog_param(self) -> None:
        from mayhem.domain.catalog import definition_for

        expected = {
            "db.query_error": "error",
            "db.slow_query": "mode",
            "fs.fill": "path",
            "fd.exhaust": "mode",
            "mem.exhaust": "mode",
            "fs.io_stress": "op",
        }
        for fault_id, param in expected.items():
            names = {p.name for p in definition_for(fault_id).params_schema}
            assert param in names, f"{fault_id} is missing the {param} param"
