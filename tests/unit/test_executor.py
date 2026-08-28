"""RunEngine: durable execution of a frozen plan, real executors, real SQLite."""

import subprocess
import sys
from pathlib import Path

from mayhem.agents.lease_client import LeaseClient
from mayhem.controller.executor import RunEngine
from mayhem.controller.planner import plan_drill
from mayhem.domain.experiments import (
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
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


def _spawn_sleeper() -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdout=subprocess.DEVNULL,
    )


def _graph(pid: int) -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-a",
                name="a",
                engine="podman",
                runtime_id="a",
                container_name="c-a",
                state="running",
            ),
            ProcessNode(
                id="proc-a",
                name=f"sleeper-{pid}",
                pid=pid,
                host_id="h-local",
            ),
        ),
        edges=(Edge(src="ctr-a", dst="proc-a", kind=EdgeKind.RUNS_ON),),
    )


def _plan(run_id: str, pid: int):
    spec = DrillSpec(
        kind="drill",
        name="engine-e2e",
        containers={"c-a": DrillContainer(faults=(DrillFault(fault="proc.pause", duration="1s"),))},
        execution=(ExecutionStep(parallel=("c-a",)),),
    )
    return plan_drill(
        run_id,
        spec,
        _graph(pid),
        config_snapshot_id="cfg-1",
        topology_snapshot_id="topo-1",
        environment_fingerprint="fp-test",
    )


def _engine(tmp_path: Path) -> tuple[RunEngine, Store]:
    store = Store.open_migrated(tmp_path / "tg.db")
    sink = SQLiteLeaseSink(store)
    engine = RunEngine(store, sink)
    return engine, store


class TestEndToEnd:
    def test_proc_pause_run_completes_and_leases_released(self, tmp_path: Path) -> None:
        proc = _spawn_sleeper()
        try:
            engine, store = _engine(tmp_path)
            plan = _plan("r-e2e", proc.pid)
            result = engine.execute(plan)

            assert result.status == "completed", result.summary_md()
            assert not result.dirty_leases

            rows = store.query("SELECT status FROM runs WHERE id = 'r-e2e'")
            assert rows[0]["status"] == "completed"

            leases = store.query(
                "SELECT state, release_mechanism FROM fault_leases WHERE run_id = 'r-e2e'"
            )
            assert len(leases) == 1
            assert leases[0]["state"] == "released"

            recovery = store.query("SELECT verified FROM recovery_records")
            assert recovery and recovery[0]["verified"] == 1

            events = store.query("SELECT kind FROM events WHERE run_id = 'r-e2e' ORDER BY id")
            kinds = [str(row["kind"]) for row in events]
            assert "run.started" in kinds
            assert "fault.injected" in kinds
            assert "fault.recovered" in kinds
            assert "run.completed" in kinds
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_first_run_row_persists_spec_and_plan(self, tmp_path: Path) -> None:
        proc = _spawn_sleeper()
        try:
            engine, store = _engine(tmp_path)
            engine.execute(_plan("r-durable", proc.pid))
            rows = store.query("SELECT spec_json, plan_json, seed FROM runs WHERE id = 'r-durable'")
            assert rows[0]["plan_json"].startswith("{")
        finally:
            proc.terminate()
            proc.wait(timeout=10)


class TestRecovery:
    def test_recover_run_releases_stranded_lease(self, tmp_path: Path) -> None:
        engine, store = _engine(tmp_path)
        sink = SQLiteLeaseSink(store)
        client = LeaseClient(sink, agent_id="ag-crash")
        client.acquire(
            run_id="r-dead",
            fault_id="proc.pause",
            targets={"n-x"},
            undo_ops=({"op": "noop", "args": {}},),
            verify_probes=({"probe": "exec", "args": {"cmd": ["true"]}, "expect_present": True},),
        )
        client.activate(client.active_leases()[0].id)
        recovered = engine.recover_run("r-dead")
        assert recovered, "orphaned lease should be compensated"
        final = sink.load(recovered[0])
        assert final is not None
        assert final.state.value == "released"
