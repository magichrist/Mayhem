"""ADR-M4-3: machine-evaluable success criteria over recorded observations.

Covers the criterion model, closed-union parsing, deterministic evaluation
(including missing observations -> false, never a crash), observation
collection, planner wiring, and the executor's criteria-derived verdict.
"""

from __future__ import annotations

import http.server
import subprocess
import sys
import threading
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from mayhem.controller.executor import RunEngine, RunResult
from mayhem.controller.planner import plan_drill
from mayhem.domain.experiments import (
    CheckExpectation,
    CheckProbe,
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
)
from mayhem.domain.identity import RuntimeIdentity
from mayhem.domain.run_outcome import RunVerdict
from mayhem.domain.success import (
    BooleanCriterion,
    CountCriterion,
    LatencyCriterion,
    MetricCriterion,
    Observation,
    ObservationKind,
    StatusCriterion,
    SuccessCriteria,
    evaluate_criteria,
    observations_for_step,
    parse_criterion,
)
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    ProcessNode,
    TopologyGraph,
)
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

# -- evaluation unit tests -------------------------------------------------


def _obs(source_id: str, kind: ObservationKind, value: float | int | bool | str) -> Observation:
    return Observation(source_id=source_id, kind=kind, value=value)


def test_status_criterion_judged_by_recorded_status() -> None:
    criteria = SuccessCriteria(criteria=(StatusCriterion(source_id="c.status", expected=200),))
    recorded = _obs("c.status", ObservationKind.STATUS, 200)
    assert evaluate_criteria(criteria, {"c.status": recorded}).all_satisfied
    assert not evaluate_criteria(
        criteria, {"c.status": _obs("c.status", ObservationKind.STATUS, 500)}
    ).all_satisfied


def test_latency_criterion_judged_by_measured_latency() -> None:
    criteria = SuccessCriteria(criteria=(LatencyCriterion(source_id="c.latency_ms", lt_ms=200.0),))
    assert evaluate_criteria(
        criteria, {"c.latency_ms": _obs("c.latency_ms", ObservationKind.LATENCY, 45.5)}
    ).all_satisfied
    assert not evaluate_criteria(
        criteria, {"c.latency_ms": _obs("c.latency_ms", ObservationKind.LATENCY, 500.0)}
    ).all_satisfied


def test_metric_criterion_respects_bounds() -> None:
    low = SuccessCriteria(criteria=(MetricCriterion(source_id="m", gt=8.0),))
    high = SuccessCriteria(criteria=(MetricCriterion(source_id="m", lt=8.0),))
    band = SuccessCriteria(criteria=(MetricCriterion(source_id="m", gt=5.0, lt=10.0),))
    at = _obs("m", ObservationKind.METRIC, 10.0)
    assert evaluate_criteria(low, {"m": at}).all_satisfied
    assert not evaluate_criteria(high, {"m": at}).all_satisfied
    assert not evaluate_criteria(band, {"m": at}).all_satisfied  # bounds exclusive


def test_metric_criterion_requires_a_bound() -> None:
    with pytest.raises(ValueError):
        MetricCriterion(source_id="m", gt=None, lt=None)


def test_count_criterion_enforces_minimum() -> None:
    criteria = SuccessCriteria(criteria=(CountCriterion(source_id="leases", gte=2),))
    assert evaluate_criteria(
        criteria, {"leases": _obs("leases", ObservationKind.COUNT, 3)}
    ).all_satisfied
    assert not evaluate_criteria(
        criteria, {"leases": _obs("leases", ObservationKind.COUNT, 1)}
    ).all_satisfied


def test_boolean_criterion_checks_recorded_outcome() -> None:
    criteria = SuccessCriteria(criteria=(BooleanCriterion(source_id="step-a"),))
    assert evaluate_criteria(
        criteria, {"step-a": _obs("step-a", ObservationKind.BOOLEAN, True)}
    ).all_satisfied
    assert not evaluate_criteria(
        criteria, {"step-a": _obs("step-a", ObservationKind.BOOLEAN, False)}
    ).all_satisfied
    flipped = SuccessCriteria(criteria=(BooleanCriterion(source_id="step-a", value=False),))
    assert evaluate_criteria(
        flipped, {"step-a": _obs("step-a", ObservationKind.BOOLEAN, False)}
    ).all_satisfied


def test_missing_observation_evaluates_false_and_never_raises() -> None:
    criteria = SuccessCriteria(criteria=(StatusCriterion(source_id="c.status", expected=200),))
    evaluation = evaluate_criteria(criteria, {})
    assert not evaluation.all_satisfied
    (result,) = evaluation.results
    assert not result.satisfied
    assert "no observation" in result.detail


def test_incomparable_observation_is_a_failure_not_a_crash() -> None:
    criteria = SuccessCriteria(criteria=(LatencyCriterion(source_id="step-a", lt_ms=500.0),))
    evaluation = evaluate_criteria(
        criteria, {"step-a": _obs("step-a", ObservationKind.BOOLEAN, True)}
    )
    assert not evaluation.all_satisfied
    (result,) = evaluation.results
    assert "not comparable" in result.detail


def test_empty_criteria_are_satisfied_and_yield_no_rows() -> None:
    evaluation = evaluate_criteria(SuccessCriteria(), {})
    assert evaluation.all_satisfied
    assert evaluation.empty
    assert evaluate_criteria(None, {}).empty


def test_require_any_derives_any_semantics() -> None:
    criteria = SuccessCriteria(
        criteria=(
            StatusCriterion(source_id="a.status", expected=200),
            BooleanCriterion(source_id="b"),
        ),
        require_all=False,
    )
    partial = {
        "a.status": _obs("a.status", ObservationKind.STATUS, 500),
        "b": _obs("b", ObservationKind.BOOLEAN, True),
    }
    assert evaluate_criteria(criteria, partial).all_satisfied


def test_evaluation_is_deterministic() -> None:
    criteria = SuccessCriteria(
        criteria=(
            StatusCriterion(source_id="a.status", expected=200),
            LatencyCriterion(source_id="b.latency_ms", lt_ms=100.0),
        )
    )
    observations = {
        "a.status": _obs("a.status", ObservationKind.STATUS, 200),
        "b.latency_ms": _obs("b.latency_ms", ObservationKind.LATENCY, 5.0),
    }
    first = evaluate_criteria(criteria, observations)
    second = evaluate_criteria(criteria, observations)
    assert first == second
    assert first.all_satisfied
    assert [r.satisfied for r in first.results] == [True, True]


def test_status_and_latency_can_address_the_same_step() -> None:
    criteria = SuccessCriteria(
        criteria=(
            StatusCriterion(source_id="check-0000-0.status", expected=200),
            LatencyCriterion(source_id="check-0000-0.latency_ms", lt_ms=1000.0),
        )
    )
    observations = {
        row.source_id: row
        for row in observations_for_step(
            "check-0000-0", ok=True, measured={"status": 200, "latency_ms": 12.5}
        )
    }
    assert evaluate_criteria(criteria, observations).all_satisfied


def test_parse_criterion_discriminates_the_closed_union() -> None:
    parsed = parse_criterion({"type": "status", "source_id": "c", "expected": 204})
    assert isinstance(parsed, StatusCriterion)
    assert isinstance(
        parse_criterion({"type": "latency", "source_id": "c", "lt_ms": 10}), LatencyCriterion
    )
    assert isinstance(
        parse_criterion({"type": "metric", "source_id": "c", "gt": 1.0}), MetricCriterion
    )
    assert isinstance(
        parse_criterion({"type": "count", "source_id": "c", "gte": 1}), CountCriterion
    )
    assert isinstance(parse_criterion({"type": "boolean", "source_id": "c"}), BooleanCriterion)
    with pytest.raises(ValueError):
        parse_criterion({"type": "status", "source_id": "c"})


# -- planner wiring ---------------------------------------------------------


def test_planner_carries_success_criteria_onto_the_plan() -> None:
    graph = _graph()
    spec = DrillSpec(
        kind="drill",
        name="success-carry",
        containers={"c-a": DrillContainer(faults=(DrillFault(fault="proc.pause", duration="1s"),))},
        execution=(ExecutionStep(parallel=("c-a",)),),
        success=SuccessCriteria(criteria=(BooleanCriterion(source_id="x"),)),
    )
    plan = plan_drill(
        "r-carry",
        spec,
        graph,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )
    assert plan.success is not None
    assert not plan.success.empty
    assert all(s.raw_action.type != "check_spec" for s in plan.steps)


def test_plan_without_criteria_keeps_success_none() -> None:
    graph = _graph()
    spec = DrillSpec(
        kind="drill",
        name="no-success",
        containers={"c-a": DrillContainer(faults=(DrillFault(fault="proc.pause", duration="1s"),))},
        execution=(ExecutionStep(parallel=("c-a",)),),
    )
    plan = plan_drill(
        "r-none",
        spec,
        graph,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )
    assert plan.success is None


class TestExecutorVerdict:
    """End-to-end: criteria-derived verdict is deterministic and stored."""

    def _quiet(self) -> type[http.server.BaseHTTPRequestHandler]:
        class Quiet(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args: object) -> None:  # pragma: no cover
                pass

        return Quiet

    def _run_drill(
        self,
        tmp_path: Path,
        port: int,
        criteria: SuccessCriteria,
        monkeypatch: pytest.MonkeyPatch,
    ) -> tuple[Store, RunResult]:
        pa = _spawn_sleeper()
        try:
            graph = _graph(pa.pid)
            _patch_resolve(monkeypatch, {"c-a": pa.pid})
            _patch_run_tool(monkeypatch)
            store = Store.open_migrated(tmp_path / "tg.db")
            sink = SQLiteLeaseSink(store)
            engine = RunEngine(store, sink, live_graph=lambda: graph, engine="podman")
            spec = DrillSpec(
                kind="drill",
                name="verdict",
                containers={"c-a": DrillContainer(faults=_faults())},
                execution=(
                    ExecutionStep(parallel=("c-a",)),
                    ExecutionStep(
                        check=(
                            CheckProbe(
                                http=f"http://127.0.0.1:{port}/health",
                                expect=CheckExpectation(status=200),
                            ),
                        ),
                    ),
                ),
                success=criteria,
            )
            plan = plan_drill(
                "r-verdict",
                spec,
                graph,
                config_snapshot_id="c",
                topology_snapshot_id="t",
                environment_fingerprint="f",
            )
            result = engine.execute(plan)
            return store, result
        finally:
            pa.terminate()
            pa.wait(timeout=10)

    def _server(
        self,
    ) -> tuple[http.server.HTTPServer, threading.Thread, int]:
        server = http.server.HTTPServer(("127.0.0.1", 0), self._quiet())
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, port

    def test_satisfied_criteria_yield_pass_verdict_stored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server, thread, port = self._server()
        try:
            criteria = SuccessCriteria(
                criteria=(
                    StatusCriterion(source_id="check-0001-0.status", expected=200),
                    LatencyCriterion(source_id="check-0001-0.latency_ms", lt_ms=2000.0),
                )
            )
            store, result = self._run_drill(tmp_path, port, criteria, monkeypatch)
            assert result.status == "completed", result.summary_md()
            assert result.verdict == RunVerdict.PASS, result.summary_md()
            assert result.criteria_evaluation is not None
            assert result.criteria_evaluation.all_satisfied
            rows = store.query("SELECT verdict, criteria_json FROM runs WHERE id='r-verdict'")
            assert rows[0]["verdict"] == "pass"
            assert rows[0]["criteria_json"] is not None
            import json as _json

            assert _json.loads(rows[0]["criteria_json"])["all_satisfied"] is True
        finally:
            server.shutdown()
            thread.join(timeout=5)

    def test_violated_criteria_yield_fail_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server, thread, port = self._server()
        try:
            criteria = SuccessCriteria(
                criteria=(StatusCriterion(source_id="check-0001-0.status", expected=200),)
            )
            _store1, result1 = self._run_drill(tmp_path / "sub1", port, criteria, monkeypatch)
            assert result1.verdict == RunVerdict.PASS, result1.summary_md()
            # Now a criterion the live check cannot satisfy: status must be 503.
            bad_criteria = SuccessCriteria(
                criteria=(StatusCriterion(source_id="check-0001-0.status", expected=503),)
            )
            store2, result2 = self._run_drill(tmp_path / "sub2", port, bad_criteria, monkeypatch)
            assert result2.status == "completed", result2.summary_md()
            assert result2.verdict == RunVerdict.FAIL
            rows = store2.query("SELECT verdict FROM runs WHERE id='r-verdict'")
            assert rows[0]["verdict"] == "fail"
        finally:
            server.shutdown()
            thread.join(timeout=5)


# -- migration --------------------------------------------------------------


def test_m0013_adds_verdict_columns_and_preserves_data(tmp_path: Path) -> None:
    store = Store.open_migrated(tmp_path / "tg.db", migrations=ALL_MIGRATIONS[:12])
    with store.write() as conn:
        conn.execute(
            "INSERT INTO config_snapshots (id, resolved_json, source_map, created_at)"
            " VALUES ('c1', '{}', '{}', 'now')"
        )
        conn.execute(
            "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed,"
            " status, environment_fingerprint, config_snapshot_id)"
            " VALUES ('r1', 'exp', 'drill', '{}', '{}', NULL, 'running', 'env', 'c1')"
        )
    applied = store.migrate()
    assert "0013_m4_success_observability" in applied
    with store.write() as conn:
        conn.execute("UPDATE runs SET verdict = 'pass', criteria_json = '{}' WHERE id = 'r1'")
    row = store.query("SELECT verdict, criteria_json, status FROM runs WHERE id='r1'")[0]
    assert row["verdict"] == "pass"
    assert row["status"] == "running"
    assert store.query("PRAGMA foreign_key_check") == []
    store.close()


# -- helpers (mirror test_executor_drill) ----------------------------------


def _spawn_sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdout=subprocess.DEVNULL,
    )


def _faults() -> tuple[DrillFault, ...]:
    return (DrillFault(fault="proc.pause", duration="1s"),)


def _graph(pid: int | None = None) -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-a",
                name="c-a",
                engine="podman",
                runtime_identity=RuntimeIdentity(runtime="podman", host_id="h", runtime_id="a"),
                container_name="c-a",
                state="running",
            ),
            ProcessNode(
                id="proc-a",
                name="pa",
                pid=pid or os_getpid_fallback(),
                host_id="h",
                container_name="c-a",
            ),
        ),
        edges=(Edge(src="ctr-a", dst="proc-a", kind=EdgeKind.RUNS_ON),),
    )


def os_getpid_fallback() -> int:
    import os

    return os.getpid()


def _patch_resolve(monkeypatch: pytest.MonkeyPatch, pids: dict[str, int]) -> None:
    from mayhem.controller import executor as executor_mod
    from mayhem.domain.identity import RuntimeIdentity
    from mayhem.topology.resolve import ContainerInfo

    def fake_resolve(container_name: str, engine: str | None = None) -> ContainerInfo:
        return ContainerInfo(pid=pids[container_name], ip_address="127.0.0.1", state="running")

    def fake_resolve_identity(container_name: str, engine: str | None = None) -> RuntimeIdentity:
        return RuntimeIdentity(
            runtime=engine or "podman",
            host_id="h",
            runtime_id=container_name.split("-", 1)[-1],
        )

    monkeypatch.setattr(executor_mod, "resolve_container", fake_resolve)
    monkeypatch.setattr(executor_mod, "resolve_identity", fake_resolve_identity)


def _patch_run_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    from mayhem.agents import executors as agents_mod
    from mayhem.agents import probes as probes_mod
    from mayhem.toolkit.tool_runner import ToolResult

    def fake_run_tool(
        argv: tuple[str, ...],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout_s: float | None = None,
        max_output_bytes: int | None = None,
        stdin_data: bytes | None = None,
    ) -> ToolResult:
        argv = tuple(argv)
        stdout = "2310872" if len(argv) >= 2 and argv[1] == "inspect" else ""
        return ToolResult(
            argv=argv,
            argv_digest="x",
            env_digest="x",
            host="",
            cwd=None,
            exit_code=0,
            duration_ms=1,
            stdout=stdout,
            stderr="",
            truncated=False,
        )

    monkeypatch.setattr(agents_mod, "run_tool", fake_run_tool)
    monkeypatch.setattr(probes_mod, "run_tool", fake_run_tool)
