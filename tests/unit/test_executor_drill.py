"""Phase 5: RunEngine drill execution — parallel faults, inline check, PID resolution."""

import http.server
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from mayhem.controller.executor import RunEngine
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
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    ProcessNode,
    TopologyGraph,
)
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store


def _spawn_sleeper() -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdout=subprocess.DEVNULL,
    )


def _graph(pid_a: int, pid_b: int) -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-a",
                name="a",
                engine="podman",
                runtime_identity=RuntimeIdentity(runtime="podman", host_id="h", runtime_id="a"),
                container_name="c-a",
                state="running",
            ),
            ContainerNode(
                id="ctr-b",
                name="b",
                engine="podman",
                runtime_identity=RuntimeIdentity(runtime="podman", host_id="h", runtime_id="b"),
                container_name="c-b",
                state="running",
            ),
            ProcessNode(id="proc-a", name="pa", pid=pid_a, host_id="h", container_name="c-a"),
            ProcessNode(id="proc-b", name="pb", pid=pid_b, host_id="h", container_name="c-b"),
        ),
        edges=(
            Edge(src="ctr-a", dst="proc-a", kind=EdgeKind.RUNS_ON),
            Edge(src="ctr-b", dst="proc-b", kind=EdgeKind.RUNS_ON),
        ),
    )


def _faults() -> tuple[DrillFault, ...]:
    return (DrillFault(fault="proc.pause", duration="1s"),)


def _drill() -> DrillSpec:
    return DrillSpec(
        kind="drill",
        name="exec-drill",
        containers={
            "c-a": DrillContainer(faults=_faults()),
            "c-b": DrillContainer(faults=_faults()),
        },
        execution=(ExecutionStep(parallel=("c-a", "c-b")),),
    )


def _engine(tmp_path: Path, graph: TopologyGraph, **kwargs) -> tuple[RunEngine, Store]:
    store = Store.open_migrated(tmp_path / "tg.db")
    sink = SQLiteLeaseSink(store)
    engine = RunEngine(store, sink, live_graph=lambda: graph, engine="podman", **kwargs)
    return engine, store


def _patch_resolve(
    monkeypatch: pytest.MonkeyPatch, pids: dict[str, int], *, fail: bool = False
) -> None:
    from mayhem.controller import executor as executor_mod
    from mayhem.domain.identity import RuntimeIdentity
    from mayhem.topology.resolve import ContainerInfo

    def fake_resolve(container_name: str, engine: str | None = None) -> ContainerInfo:
        if fail:
            raise RuntimeError(f"{engine} inspect failed for {container_name}")
        return ContainerInfo(
            pid=pids[container_name],
            ip_address="127.0.0.1",
            state="running",
        )

    def fake_resolve_identity(container_name: str, engine: str | None = None) -> RuntimeIdentity:
        if fail:
            raise RuntimeError(f"{engine} inspect failed for {container_name}")
        # Match the plan-time identity (host "h", runtime_id equal to the short
        # container id) so ADR-M2-3 drift detection sees no recreation.
        return RuntimeIdentity(
            runtime=engine or "podman",
            host_id="h",
            runtime_id=container_name.split("-", 1)[-1],
        )

    monkeypatch.setattr(executor_mod, "resolve_container", fake_resolve)
    monkeypatch.setattr(executor_mod, "resolve_identity", fake_resolve_identity)


def _patch_run_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the in-container signal delivery + inspect presence check.

    Container-addressed faults send SIGSTOP/SIGCONT via ``engine kill`` and
    verify presence via ``engine inspect``. Unit tests have no live container,
    so the delivery is stubbed as a successful invocation and the inspect
    returns a nonzero pid (process present).
    """
    from mayhem.agents import executors as agents_mod
    from mayhem.agents import probes as probes_mod
    from mayhem.toolkit.tool_runner import ToolResult

    def fake_run_tool(
        argv, *, env=None, cwd=None, timeout_s=None, max_output_bytes=None, stdin_data=None
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


def _plan(run_id: str, graph: TopologyGraph, spec: DrillSpec):
    return plan_drill(
        run_id,
        spec,
        graph,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


class TestParallelExecution:
    def test_parallel_containers_run_concurrently_and_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pa = _spawn_sleeper()
        pb = _spawn_sleeper()
        try:
            graph = _graph(pa.pid, pb.pid)
            _patch_resolve(monkeypatch, {"c-a": pa.pid, "c-b": pb.pid})
            _patch_run_tool(monkeypatch)
            engine, store = _engine(tmp_path, graph)
            plan = _plan("r-par", graph, _drill())

            result = engine.execute(plan)

            assert result.status == "completed", result.summary_md()
            assert not result.dirty_leases
            leases = store.query(
                "SELECT state, fault_id, runtime_identity FROM fault_leases WHERE run_id='r-par'"
            )
            assert len(leases) == 2
            assert {r["fault_id"] for r in leases} == {"proc.pause"}
            assert all(r["state"] == "released" for r in leases)
            # ADR-M1-3: the canonical identity persists alongside each lease.
            assert {r["runtime_identity"] for r in leases} == {
                "podman|h|a",
                "podman|h|b",
            }
            # ADR-M1-3: the same identity lands on the step_runs rows.
            step_identities = {
                r["runtime_identity"]
                for r in store.query("SELECT runtime_identity FROM step_runs WHERE run_id='r-par'")
            }
            assert step_identities == {"podman|h|a", "podman|h|b"}
        finally:
            pa.terminate()
            pb.terminate()
            pa.wait(timeout=10)
            pb.wait(timeout=10)

    def test_parallel_steps_share_a_seq(self) -> None:
        pa, pb = _spawn_sleeper(), _spawn_sleeper()
        try:
            graph = _graph(pa.pid, pb.pid)
            plan = _plan("r-parseq", graph, _drill())
            seqs = [s.seq for s in plan.steps]
            assert len(set(seqs)) == 1
        finally:
            pa.terminate()
            pb.terminate()
            pa.wait(timeout=10)
            pb.wait(timeout=10)


class TestPidResolution:
    def test_resolution_failure_fails_step_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pa = _spawn_sleeper()
        pb = _spawn_sleeper()
        try:
            graph = _graph(pa.pid, pb.pid)
            _patch_resolve(monkeypatch, {}, fail=True)
            engine, store = _engine(tmp_path, graph)
            plan = _plan("r-failpid", graph, _drill())

            result = engine.execute(plan)

            assert result.status == "failed", result.summary_md()
            # No stranded leases after the clean failure.
            leases = store.query("SELECT state FROM fault_leases WHERE run_id='r-failpid'")
            assert all(r["state"] == "released" for r in leases)
        finally:
            pa.terminate()
            pb.terminate()
            pa.wait(timeout=10)
            pb.wait(timeout=10)


class TestInlineCheck:
    def test_check_http_step_against_live_endpoint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Quiet(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):  # pragma: no cover
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Quiet)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        pa = _spawn_sleeper()
        try:
            graph = _graph(pa.pid, 999998)
            _patch_resolve(monkeypatch, {"c-a": pa.pid})
            _patch_run_tool(monkeypatch)
            engine, _store = _engine(tmp_path, graph)
            spec = DrillSpec(
                kind="drill",
                name="check",
                containers={
                    "c-a": DrillContainer(faults=_faults()),
                },
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
            )
            plan = _plan("r-check", graph, spec)

            result = engine.execute(plan)

            assert result.status == "completed", result.summary_md()
            action_types = [s.raw_action.type for s in plan.steps]
            assert "check_http" in action_types
            check_step = next(s for s in plan.steps if s.raw_action.type == "check_http")
            report = engine._execute_check_http(check_step)
            assert report.ok, report.detail
        finally:
            pa.terminate()
            pa.wait(timeout=10)
            server.shutdown()
            thread.join(timeout=5)


class TestWaitStep:
    def test_wait_step_sleeps(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        pa = _spawn_sleeper()
        try:
            graph = _graph(pa.pid, 999998)
            _patch_resolve(monkeypatch, {"c-a": pa.pid})
            store = Store.open_migrated(tmp_path / "tg.db")
            sink = SQLiteLeaseSink(store)
            calls: list[float] = []
            engine = RunEngine(store, sink, sleeper=calls.append, live_graph=lambda: graph)
            spec = DrillSpec(
                kind="drill",
                name="wait",
                containers={
                    "c-a": DrillContainer(faults=_faults()),
                },
                execution=(
                    ExecutionStep(parallel=("c-a",)),
                    ExecutionStep(wait="2s"),
                ),
            )
            plan = _plan("r-wait", graph, spec)
            result = engine.execute(plan)
            assert result.status == "completed", result.summary_md()
            assert [s.raw_action.type for s in plan.steps].count("wait") == 1
            assert 2.0 in calls
        finally:
            pa.terminate()
            pa.wait(timeout=10)
