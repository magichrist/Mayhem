"""RunEngine: durable execution of a frozen plan, real executors, real SQLite."""

import subprocess
import sys
from pathlib import Path

import pytest

from mayhem.agents.executors import read_boot_time
from mayhem.agents.lease_client import LeaseClient
from mayhem.controller.executor import RunEngine
from mayhem.controller.planner import plan_drill
from mayhem.domain.experiments import (
    DrillConfig,
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
)
from mayhem.domain.identity import RuntimeIdentity
from mayhem.domain.leases import FaultLease, UndoOp
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

    def test_recovery_false_keeps_perturbation_in_place(self, tmp_path: Path) -> None:
        proc = _spawn_sleeper()
        pid = proc.pid
        try:
            assert proc.poll() is None  # running before the drill
            spec = DrillSpec(
                kind="drill",
                name="engine-e2e-norecover",
                config=DrillConfig(recovery=False),
                containers={
                    "c-a": DrillContainer(faults=(DrillFault(fault="proc.pause", duration="1s"),)),
                },
                execution=(ExecutionStep(parallel=("c-a",)),),
            )
            plan = plan_drill(
                "r-kept",
                spec,
                _graph(pid),
                config_snapshot_id="cfg-1",
                topology_snapshot_id="topo-1",
                environment_fingerprint="fp-test",
            )
            assert plan.steps[0].fault is not None
            assert plan.steps[0].fault.recovery is False

            engine, store = _engine(tmp_path)
            result = engine.execute(plan)
            assert result.status == "completed", result.summary_md()
            assert not result.dirty_leases

            # The process must still be SIGSTOPped: the undo (SIGCONT) never ran.
            stat = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(pid)],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            assert stat.startswith("T"), f"expected stopped state, got {stat!r}"

            leases = store.query(
                "SELECT state, release_mechanism FROM fault_leases WHERE run_id = 'r-kept'"
            )
            assert len(leases) == 1
            assert leases[0]["state"] == "released"
            assert leases[0]["release_mechanism"] == "kept_faulted"

            recovery = store.query(
                "SELECT mechanism, verified, undo_results_json FROM recovery_records"
            )
            assert len(recovery) == 1
            assert recovery[0]["mechanism"] == "kept_faulted"
            assert recovery[0]["verified"] == 0
            assert "skipped (recovery: false)" in recovery[0]["undo_results_json"]

            events = store.query("SELECT kind FROM events WHERE run_id = 'r-kept' ORDER BY id")
            kinds = [str(row["kind"]) for row in events]
            assert "fault.injected" in kinds
            assert "fault.recovered" not in kinds  # no auto-recovery happened

            # Self-healing path: the operator revives the process and the next
            # drill can acquire the targets again (lease is terminal).
            import os

            os.kill(pid, 18)  # SIGCONT — manual recovery
            assert proc.poll() is None
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_proc_kill_run_terminates_process_and_releases(self, tmp_path: Path) -> None:
        proc = _spawn_sleeper()
        pid = proc.pid
        try:
            assert proc.poll() is None  # running before the drill
            engine, store = _engine(tmp_path)

            def _kill_plan(run_id: str, target: int):
                spec = DrillSpec(
                    kind="drill",
                    name="engine-e2e-kill",
                    containers={
                        "c-a": DrillContainer(
                            faults=(DrillFault(fault="process.kill", duration="1s"),)
                        ),
                    },
                    execution=(ExecutionStep(parallel=("c-a",)),),
                )
                return plan_drill(
                    run_id,
                    spec,
                    _graph(target),
                    config_snapshot_id="cfg-1",
                    topology_snapshot_id="topo-1",
                    environment_fingerprint="fp-test",
                )

            result = engine.execute(_kill_plan("r-kill", pid))
            assert result.status == "completed", result.summary_md()
            assert not result.dirty_leases

            proc.wait(timeout=10)
            assert proc.poll() is not None  # SIGKILL terminated the sleeper

            leases = store.query(
                "SELECT state, release_mechanism FROM fault_leases WHERE run_id = 'r-kill'"
            )
            assert len(leases) == 1
            assert leases[0]["state"] == "released"
            events = store.query("SELECT kind FROM events WHERE run_id = 'r-kill' ORDER BY id")
            kinds = [str(row["kind"]) for row in events]
            assert "fault.injected" in kinds
            assert "fault.recovered" in kinds
            assert "run.completed" in kinds
        finally:
            if proc.poll() is None:
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
            engine, _store = _engine(
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


class TestProcReuseGuard:
    """ADR-M2 Phase 2.4 / ADR-M6-2 — the process executor refuses to signal a
    recycled PID when the recorded boot_time no longer matches."""

    def _lease(self, *, pid: int, boot_time: str | None) -> FaultLease:
        return FaultLease(
            id="l-guard",
            run_id="r-guard",
            fault_id="proc.pause",
            owner_agent="test",
            targets=frozenset({"proc-a"}),
            undo_ops=(
                UndoOp(
                    op="signal.cont",
                    args={
                        "pid": str(pid),
                        **({"boot_time": boot_time} if boot_time is not None else {}),
                    },
                ),
            ),
        )

    @staticmethod
    def _spawn_and_read_boot():
        proc = _spawn_sleeper()
        return proc, read_boot_time(proc.pid)

    def test_recycled_pid_guard_refuses_to_signal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.agents import executors as exec_mod
        from mayhem.agents.executors import StepOutcome
        from mayhem.controller.executor import executor_for

        proc = _spawn_sleeper()
        live = read_boot_time(proc.pid)
        try:
            # The PID is genuinely alive with `live` as its true boot_time, but the
            # lease records a different (stale/recycled) boot_time.
            real_boot = live if live is not None else 12345
            stale = real_boot + 7777
            exec_mod.read_boot_time = lambda pid: real_boot
            kills: list[int] = []
            exec_mod.os_kill = lambda pid, sig: kills.append(pid)

            executor = executor_for("proc.pause")
            outcome = executor.inject(self._lease(pid=proc.pid, boot_time=str(stale)))
            assert isinstance(outcome, StepOutcome)
            assert not outcome.ok
            assert "pid-reuse guard" in outcome.detail
            assert kills == []  # no signal was delivered to the recycled PID
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_matching_boot_time_signals(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mayhem.agents import executors as exec_mod
        from mayhem.agents.executors import StepOutcome
        from mayhem.controller.executor import executor_for

        proc = _spawn_sleeper()
        real_boot = read_boot_time(proc.pid) or 12345
        try:
            exec_mod.read_boot_time = lambda pid: real_boot
            kills: list[int] = []
            exec_mod.os_kill = lambda pid, sig: kills.append(pid)

            executor = executor_for("proc.pause")
            outcome = executor.inject(self._lease(pid=proc.pid, boot_time=str(real_boot)))
            assert isinstance(outcome, StepOutcome)
            assert outcome.ok, outcome.detail
            assert kills == [proc.pid]  # signal delivered to the matching process
        finally:
            proc.terminate()
            proc.wait(timeout=10)


class TestVmContainedEngine:
    """Regression: VM-contained engines (podman-machine on macOS, Docker
    Desktop) report ``State.Pid == 0`` for running containers. Exec-addressed
    faults must resolve to the sentinel pid instead of failing with
    "cannot resolve live pid" (ADR-0020 exec addressing needs only the
    container name + engine)."""

    def test_running_container_zero_host_pid_still_resolves(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mayhem.controller import executor as executor_mod
        from mayhem.controller.executor import (
            _missing_live_pids,
            _substitute_pids,
        )

        proc = _spawn_sleeper()
        try:
            engine, _store = _engine(tmp_path, live_graph=lambda: _graph(proc.pid))
            plan = _plan("r-pid0", proc.pid)
            fault = plan.steps[0].fault

            monkeypatch.setattr(
                executor_mod,
                "resolve_container",
                lambda *a, **k: (_ for _ in ()).throw(
                    RuntimeError("container c-a has no running process (pid=0)")
                ),
            )
            monkeypatch.setattr(executor_mod, "resolve_status", lambda *a, **k: "running")

            live_targets = engine._resolve_live_targets(fault)
            assert live_targets == {"ctr-a": (0, "c-a")}

            live_pids = {nid: pid for nid, (pid, _c) in live_targets.items()}
            assert not _missing_live_pids(fault, live_pids)

            undo_ops, _probes = _substitute_pids(
                (UndoOp(op="signal.cont", args={"pid": "ctr-a:@live-pid"}),),
                (),
                live_pids,
                engine="podman",
                live_targets=live_targets,
            )
            op = undo_ops[0]
            assert op.args.get("pid") == "0"
            assert op.args.get("cont") == "c-a"
            assert op.args.get("engine") == "podman"
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_stopped_container_still_fails_resolution(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mayhem.controller import executor as executor_mod

        proc = _spawn_sleeper()
        try:
            engine, _store = _engine(tmp_path, live_graph=lambda: _graph(proc.pid))
            fault = _plan("r-stopped", proc.pid).steps[0].fault

            monkeypatch.setattr(
                executor_mod,
                "resolve_container",
                lambda *a, **k: (_ for _ in ()).throw(
                    RuntimeError("container c-a has no running process (pid=0)")
                ),
            )
            monkeypatch.setattr(executor_mod, "resolve_status", lambda *a, **k: "exited")

            live_targets = engine._resolve_live_targets(fault)
            assert live_targets == {}
        finally:
            proc.terminate()
            proc.wait(timeout=10)


class TestExecAddressedSignals:
    def test_injection_with_sentinel_pid_uses_engine_kill(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from mayhem.agents import executors as exec_mod
        from mayhem.agents.executors import StepOutcome
        from mayhem.controller.executor import executor_for

        lease = FaultLease(
            id="l-exec",
            run_id="r-exec",
            fault_id="proc.pause",
            owner_agent="test",
            targets=frozenset({"proc-a"}),
            undo_ops=(
                UndoOp(
                    op="signal.cont",
                    args={"pid": "0", "cont": "c-a", "engine": "podman"},
                ),
            ),
        )
        sent: list[list[str]] = []

        def fake_run_tool(argv, timeout_s=30):
            sent.append(argv)
            return SimpleNamespace(succeeded=True, stdout="", stderr="")

        monkeypatch.setattr(exec_mod, "run_tool", fake_run_tool)
        executor = executor_for("proc.pause")
        outcome = executor.inject(lease)
        assert isinstance(outcome, StepOutcome)
        assert outcome.ok, outcome.detail
        assert sent == [["podman", "kill", "--signal", "SIGSTOP", "c-a"]]
