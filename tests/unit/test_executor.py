"""RunEngine: durable execution of a frozen plan, real executors, real SQLite."""

import subprocess
import sys
from pathlib import Path

import pytest

from mayhem.agents.lease_client import LeaseClient
from mayhem.controller.executor import RunEngine
from mayhem.controller.planner import plan_drill
from mayhem.domain.experiments import (
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


def _graph(pid: int) -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-a",
                name="a",
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h-local", runtime_id="a"
                ),
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


def _engine(
    tmp_path: Path,
    *,
    live_graph=None,
    bypass: dict[tuple[str, str], str] | None = None,
) -> tuple[RunEngine, Store]:
    store = Store.open_migrated(tmp_path / "tg.db")
    sink = SQLiteLeaseSink(store)
    engine = RunEngine(store, sink, live_graph=live_graph, bypass=bypass)
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

    def test_gate_verified_inert_fault_is_bypassed_not_failed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A fault the impact gate proved inert (missing tooling) is skipped as
        ``bypass due to <reason>`` — the run completes and no lease forms."""
        from types import SimpleNamespace

        from mayhem.controller import executor as executor_mod

        proc = _spawn_sleeper()
        try:
            engine, store = _engine(
                tmp_path,
                live_graph=lambda: _graph(proc.pid),
                bypass={("proc.pause", "c-a"): "missing bin:k6"},
            )
            monkeypatch.setattr(
                executor_mod,
                "resolve_container",
                lambda *a, **k: SimpleNamespace(pid=proc.pid),
            )
            result = engine.execute(_plan("r-bypass", proc.pid))
            step = result.steps[0]
            assert result.status == "completed", result.summary_md()
            assert step.status == "bypassed"
            assert step.ok
            assert "bypass due to c-a: missing bin:k6" in step.detail
            assert not result.dirty_leases
            rows = store.query("SELECT status FROM step_runs WHERE run_id = 'r-bypass'")
            assert rows[0]["status"] == "bypassed"
            leases = store.query("SELECT id FROM fault_leases WHERE run_id = 'r-bypass'")
            assert not leases
        finally:
            proc.terminate()
            proc.wait(timeout=10)


class TestTargetDrift:
    def test_recreated_container_records_target_drift_and_no_mutation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ADR-M2-3: a container recreated under the same name (live identity !=
        planned identity) is TARGET_DRIFT — safe-abort the fault, persist the
        status, and never form a lease or touch the process."""
        from types import SimpleNamespace

        from mayhem.controller import executor as executor_mod
        from mayhem.domain.identity import RuntimeIdentity

        proc = _spawn_sleeper()
        try:
            engine, store = _engine(
                tmp_path,
                live_graph=lambda: _graph(proc.pid),
            )
            # Live resolver reports a NEW container id (simulated recreate).
            monkeypatch.setattr(
                executor_mod,
                "resolve_identity",
                lambda *a, **k: RuntimeIdentity(
                    runtime="podman", host_id="h-local", runtime_id="RECREATED"
                ),
            )
            monkeypatch.setattr(
                executor_mod,
                "resolve_container",
                lambda *a, **k: SimpleNamespace(pid=proc.pid, ip_address="", state="running"),
            )
            result = engine.execute(_plan("r-drift", proc.pid))
            step = result.steps[0]
            assert result.status == "failed"
            assert step.target_drift
            assert "TARGET_DRIFT" in step.detail
            rows = store.query("SELECT status FROM step_runs WHERE run_id = 'r-drift'")
            assert rows[0]["status"] == "target_drift"
            leases = store.query("SELECT id FROM fault_leases WHERE run_id = 'r-drift'")
            assert not leases  # no mutation, no lease
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_matched_live_identity_does_not_drift(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A live identity equal to the planned one proceeds normally."""
        from types import SimpleNamespace

        from mayhem.controller import executor as executor_mod
        from mayhem.domain.identity import RuntimeIdentity

        proc = _spawn_sleeper()
        try:
            engine, store = _engine(
                tmp_path,
                live_graph=lambda: _graph(proc.pid),
            )
            monkeypatch.setattr(
                executor_mod,
                "resolve_identity",
                lambda *a, **k: RuntimeIdentity(
                    runtime="podman", host_id="h-local", runtime_id="a"
                ),
            )
            monkeypatch.setattr(
                executor_mod,
                "resolve_container",
                lambda *a, **k: SimpleNamespace(pid=proc.pid, ip_address="", state="running"),
            )
            result = engine.execute(_plan("r-match", proc.pid))
            assert result.status == "completed", result.summary_md()
            step = result.steps[0]
            assert not step.target_drift
            assert not result.dirty_leases
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_pid_reuse_detected_as_target_drift(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ADR-M2 Phase 2.4: when the boot time captured at target resolution
        no longer matches at the mutation boundary, the PID was recycled — a
        TARGET_DRIFT abort with no mutation."""
        from types import SimpleNamespace

        from mayhem.controller import executor as executor_mod
        from mayhem.domain.identity import ProcessRuntimeIdentity, RuntimeIdentity

        proc = _spawn_sleeper()
        baseline = ProcessRuntimeIdentity(
            host_id="h-podman-local",
            pid=proc.pid,
            boot_time=1000,
            container_name="c-a",
        )
        recycled = ProcessRuntimeIdentity(
            host_id="h-podman-local",
            pid=proc.pid,
            boot_time=9999,  # an unrelated process now owns this pid
            container_name="c-a",
        )
        calls = {"n": 0}

        def fake_resolve_process_identity(
            pid, host_id=None, container_name=None, _baseline=baseline, _recycled=recycled
        ):
            calls["n"] += 1
            # first call = baseline capture at resolution; second = re-read at
            # mutation boundary, which now sees a recycled boot time.
            return _baseline if calls["n"] == 1 else _recycled

        try:
            engine, store = _engine(
                tmp_path,
                live_graph=lambda: _graph(proc.pid),
            )
            monkeypatch.setattr(
                executor_mod,
                "resolve_identity",
                lambda *a, **k: RuntimeIdentity(
                    runtime="podman", host_id="h-local", runtime_id="a"
                ),
            )
            monkeypatch.setattr(
                executor_mod,
                "resolve_container",
                lambda *a, **k: SimpleNamespace(pid=proc.pid, ip_address="", state="running"),
            )
            monkeypatch.setattr(
                executor_mod,
                "resolve_process_identity",
                fake_resolve_process_identity,
            )
            result = engine.execute(_plan("r-reused", proc.pid))
            step = result.steps[0]
            assert result.status == "failed"
            assert step.target_drift
            assert "recycled" in step.detail
            leases = store.query("SELECT id FROM fault_leases WHERE run_id = 'r-reused'")
            assert not leases  # no mutation, no lease formed
        finally:
            proc.terminate()
            proc.wait(timeout=10)


class TestFailedToApply:
    def test_capability_lost_at_execution_records_failed_to_apply(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ADR-M2 Phase 2.3: a capability that vanished between plan time and
        the mutation boundary records `failed_to_apply` — no mutation, lease
        released, run continues to completion."""
        from types import SimpleNamespace

        from mayhem.controller import executor as executor_mod
        from mayhem.domain.identity import RuntimeIdentity

        proc = _spawn_sleeper()
        try:
            engine, store = _engine(
                tmp_path,
                live_graph=lambda: _graph(proc.pid),
            )
            monkeypatch.setattr(
                executor_mod,
                "resolve_identity",
                lambda *a, **k: RuntimeIdentity(
                    runtime="podman", host_id="h-local", runtime_id="a"
                ),
            )
            monkeypatch.setattr(
                executor_mod,
                "resolve_container",
                lambda *a, **k: SimpleNamespace(pid=proc.pid, ip_address="", state="running"),
            )
            # Capability revalidation fails at the mutation boundary.
            from mayhem.agents import executors as execs_mod

            monkeypatch.setattr(
                execs_mod.ProcPauseExecutor,
                "can_apply",
                lambda self, lease: "capability lost: container engine 'podman' no longer on PATH",
            )

            result = engine.execute(_plan("r-f2a", proc.pid))
            step = result.steps[0]
            assert step.failed_to_apply
            assert "failed_to_apply" in step.detail
            rows = store.query("SELECT status FROM step_runs WHERE run_id = 'r-f2a'")
            assert rows[0]["status"] == "failed_to_apply"
            # Lease released, never mutated, no paused pid.
            leases = store.query(
                "SELECT state, release_mechanism FROM fault_leases WHERE run_id = 'r-f2a'"
            )
            assert len(leases) == 1
            assert leases[0]["state"] == "released"
            assert leases[0]["release_mechanism"] == "failed_to_apply"
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
