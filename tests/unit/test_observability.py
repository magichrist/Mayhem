"""ADR-M4-4: declarative observability sources collected into run evidence.

Covers the observability config model, planner wiring (the config is copied
onto the plan), decision-ref capture (ADR-M4-1/M4-5), the collector's
best-effort semantics, and the executor persisting collected evidence onto
the run row and spooling per-source events into the journal.
"""

from __future__ import annotations

import http.server
import json
import subprocess
import sys
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

from mayhem.controller.executor import RunEngine, RunResult
from mayhem.controller.observability_collector import collect_observability
from mayhem.controller.planner import plan_drill
from mayhem.domain.checks import HttpProbe, TcpProbe
from mayhem.domain.experiments import (
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
)
from mayhem.domain.identity import RuntimeIdentity
from mayhem.domain.observability import (
    LogsSource,
    MetricsSource,
    ObservabilityConfig,
    ProbeSource,
)
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    ProcessNode,
    TopologyGraph,
)
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store


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
                pid=pid if pid is not None else 999999,
                host_id="h",
                container_name="c-a",
            ),
        ),
        edges=(Edge(src="ctr-a", dst="proc-a", kind=EdgeKind.RUNS_ON),),
    )


def _patch_resolve(monkeypatch: pytest.MonkeyPatch, pids: dict[str, int]) -> None:
    from mayhem.controller import executor as executor_mod
    from mayhem.domain.identity import RuntimeIdentity
    from mayhem.topology.resolve import ContainerInfo

    def fake_resolve(container_name: str, engine: str | None = None) -> ContainerInfo:
        return ContainerInfo(pid=pids[container_name], ip_address="127.0.0.1", state="running")

    def fake_resolve_identity(container_name: str, engine: str | None = None) -> RuntimeIdentity:
        return RuntimeIdentity(runtime=engine or "podman", host_id="h", runtime_id="a")

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


# -- domain + parse ---------------------------------------------------------


def test_observability_config_parses_declared_sources() -> None:
    cfg = ObservabilityConfig.model_validate(
        {
            "total_timeout": "10s",
            "cadence": "1s",
            "sources": [
                {"kind": "logs", "source_id": "s1", "container": "c-a", "tail": 50},
                {"kind": "inspection", "source_id": "s2", "container": "c-a"},
                {
                    "kind": "probe",
                    "source_id": "s3",
                    "probe": {
                        "type": "http",
                        "url": "http://127.0.0.1:8080/h",
                        "expected_status": 200,
                    },
                },
                {
                    "kind": "metrics",
                    "source_id": "s4",
                    "endpoint": "http://127.0.0.1:9090/metrics",
                    "metric": "http_requests_total",
                },
            ],
        }
    )
    assert [s.kind for s in cfg.sources] == ["logs", "inspection", "probe", "metrics"]
    assert not cfg.empty


def test_empty_observability_config_is_empty() -> None:
    assert ObservabilityConfig().empty
    assert ObservabilityConfig(sources=()).empty
    assert not ObservabilityConfig(sources=(LogsSource(source_id="s", container="c"),)).empty


# -- planner wiring (ADR-M4-1 / M4-4 / M4-5) ---------------------------------


def _spec_with_observability(cfg: ObservabilityConfig) -> DrillSpec:
    return DrillSpec(
        kind="drill",
        name="obs",
        containers={"c-a": DrillContainer(faults=_faults())},
        execution=(ExecutionStep(parallel=("c-a",)),),
        observability=cfg,
    )


def test_plan_carries_observability_and_governing_decisions() -> None:
    pa = _spawn_sleeper()
    try:
        graph = _graph(pa.pid)
        cfg = ObservabilityConfig(
            sources=(
                ProbeSource(
                    source_id="obs.probe",
                    probe=TcpProbe(host="127.0.0.1", port=8080),
                ),
            )
        )
        plan = plan_drill(
            "r-planner",
            _spec_with_observability(cfg),
            graph,
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        assert plan.observability is not None
        assert plan.observability.sources[0].source_id == "obs.probe"
        decision_ids = {ref.decision_id for ref in plan.decision_refs}
        assert "ADR-M4-4" in decision_ids
        assert "ADR-M4-1" in decision_ids
        assert "ADR-M4-5" in decision_ids
        assert "ADR-M4-3" not in decision_ids  # no success section on the spec
    finally:
        pa.terminate()
        pa.wait(timeout=10)


def test_plan_without_observability_has_no_m4_4_ref() -> None:
    pa = _spawn_sleeper()
    try:
        graph = _graph(pa.pid)
        plan = plan_drill(
            "r-planner-bare",
            DrillSpec(
                kind="drill",
                name="bare",
                containers={"c-a": DrillContainer(faults=_faults())},
                execution=(ExecutionStep(parallel=("c-a",)),),
            ),
            graph,
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        assert plan.observability is None
        assert "ADR-M4-4" not in {ref.decision_id for ref in plan.decision_refs}
    finally:
        pa.terminate()
        pa.wait(timeout=10)


def _failing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace run_tool with a deterministic failure for collector unit tests."""
    from mayhem.controller import observability_collector as collector_mod
    from mayhem.toolkit.tool_runner import ToolResult

    def tool_fails(
        argv: tuple[str, ...],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout_s: float | None = None,
        max_output_bytes: int | None = None,
        stdin_data: bytes | None = None,
    ) -> ToolResult:
        return ToolResult(
            argv=tuple(argv),
            argv_digest="x",
            env_digest="x",
            host="",
            cwd=None,
            exit_code=3,
            duration_ms=1,
            stdout="",
            stderr="no such container",
            truncated=False,
        )

    monkeypatch.setattr(collector_mod, "run_tool", tool_fails)


# -- collector ----------------------------------------------------------------


def test_collector_is_best_effort_and_never_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _failing_tool(monkeypatch)
    cfg = ObservabilityConfig(
        total_timeout=15.0,
        sources=(LogsSource(source_id="missing", container="does-not-exist"),),
    )
    collections = collect_observability(cfg, engine="podman")
    assert len(collections) == 1
    assert collections[0].ok is False
    assert "failed" in collections[0].note.lower()


def test_collector_defers_late_sources_when_pass_budget_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_monotonic = time.monotonic
    calls = {"n": 0}

    def time_jumps_after_first_source() -> float:
        calls["n"] += 1
        if calls["n"] >= 3:  # deadline + first-source budget check are already done
            return real_monotonic() + 100.0
        return real_monotonic()

    monkeypatch.setattr(time, "monotonic", time_jumps_after_first_source)
    cfg = ObservabilityConfig(
        total_timeout=15.0,
        sources=(
            LogsSource(source_id="a", container="c-a"),
            MetricsSource(source_id="b", endpoint="http://127.0.0.1:1/metrics", metric="m"),
        ),
    )
    collections = collect_observability(cfg)
    assert collections[0].skipped is False  # first source still had its budget
    assert collections[1].skipped is True  # pass budget exhausted => late source deferred
    assert "total_timeout" in collections[1].note


def test_prometheus_metric_parse() -> None:
    from mayhem.controller.observability_collector import _parse_prometheus_text

    body = (
        "# HELP http_requests_total The total number of HTTP requests.\n"
        "# TYPE http_requests_total counter\n"
        'http_requests_total{method="get",code="200"} 1027.0\n'
        'http_requests_total{method="post",code="200"} 42\n'
    )
    assert _parse_prometheus_text(body, "http_requests_total") == 42.0
    assert _parse_prometheus_text(body, "no_such_metric") is None


# -- executor end-to-end (evidence lands on the run + journal) ---------------


class TestExecutorObservability:
    def _quiet(self) -> type[http.server.BaseHTTPRequestHandler]:
        class Quiet(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args: object) -> None:  # pragma: no cover
                pass

        return Quiet

    def _server(self) -> tuple[http.server.HTTPServer, threading.Thread, int]:
        server = http.server.HTTPServer(("127.0.0.1", 0), self._quiet())
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, port

    def _run_drill(
        self,
        tmp_path: Path,
        port: int,
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
            cfg = ObservabilityConfig(
                total_timeout=15.0,
                sources=(
                    ProbeSource(
                        source_id="obs.probe",
                        cadence="0s",
                        probe=HttpProbe(
                            url=f"http://127.0.0.1:{port}/health",
                            expected_status=200,
                        ),
                    ),
                ),
            )
            spec = _spec_with_observability(cfg)
            plan = plan_drill(
                "r-obs",
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

    def test_probe_source_collected_and_persisted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server, thread, port = self._server()
        try:
            store, result = self._run_drill(tmp_path, port, monkeypatch)
            assert result.status == "completed", result.summary_md()
            assert result.observability, result.summary_md()
            by_id = {c.source_id: c for c in result.observability}
            assert by_id["obs.probe"].ok, by_id["obs.probe"].note
            sample = by_id["obs.probe"].samples[0]
            assert isinstance(sample.value, dict)
            assert sample.value["satisfied"] is True

            rows = store.query(
                "SELECT observability_json, governing_decisions_json FROM runs WHERE id='r-obs'"
            )
            persisted = json.loads(rows[0]["observability_json"])
            assert persisted[0]["source_id"] == "obs.probe"
            assert persisted[0]["samples"][0]["value"]["satisfied"] is True
            decisions = json.loads(rows[0]["governing_decisions_json"])
            assert any(d["decision_id"] == "ADR-M4-4" for d in decisions)

            kinds = {r["kind"] for r in store.query("SELECT kind FROM events")}
            assert "observability.collected" in kinds
            assert "observability.source_failed" not in kinds
        finally:
            server.shutdown()
            thread.join(timeout=5)

    def test_source_failure_journals_failed_event(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server, thread, _port = self._server()
        try:
            pa = _spawn_sleeper()
            try:
                graph = _graph(pa.pid)
                _patch_resolve(monkeypatch, {"c-a": pa.pid})
                _patch_run_tool(monkeypatch)
                store = Store.open_migrated(tmp_path / "tg2.db")
                sink = SQLiteLeaseSink(store)
                engine = RunEngine(store, sink, live_graph=lambda: graph, engine="podman")
                cfg = ObservabilityConfig(
                    total_timeout="15s",
                    sources=(LogsSource(source_id="obs.logs", container="c-nope"),),
                )
                plan = plan_drill(
                    "r-obs-fail",
                    _spec_with_observability(cfg),
                    graph,
                    config_snapshot_id="c",
                    topology_snapshot_id="t",
                    environment_fingerprint="f",
                )
                result = engine.execute(plan)
                assert result.status == "completed"  # evidence failure never fails the run
                assert result.observability[0].ok is False
                kinds = {r["kind"] for r in store.query("SELECT kind FROM events")}
                assert "observability.source_failed" in kinds
            finally:
                pa.terminate()
                pa.wait(timeout=10)
        finally:
            server.shutdown()
            thread.join(timeout=5)
