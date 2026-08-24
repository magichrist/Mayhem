"""RunEngine — executes a frozen ExecutionPlan against real executors.

The engine owns every durable artifact of a run: runs/step_runs rows,
fault_invocations, recovery_records, and the event journal. Lease lifecycles
go through the LeaseClient so no state transition bypasses the domain rules.
"""

from __future__ import annotations

import json
import signal
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from mayhem.agents.executors import executor_for
from mayhem.agents.lease_client import LeaseClient
from mayhem.agents.probes import run_probe, verify_all
from mayhem.controller.safety import pre_exec_assertion, validate_plan
from mayhem.domain.common import utc_now
from mayhem.domain.events import Event, EventKind
from mayhem.domain.leases import VerifyProbe

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from mayhem.agents.sinks import LeaseSink
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.checks import SteadyStateCheck
    from mayhem.domain.experiments import ExecutionPlan, PlannedStep
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.store import Store


@dataclass(frozen=True)
class StepReport:
    step_id: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class RunResult:
    run_id: str
    status: str  # completed | failed | aborted
    started_at_epoch_s: float
    ended_at_epoch_s: float
    steps: tuple[StepReport, ...] = ()
    dirty_leases: tuple[str, ...] = field(default=())

    @property
    def wall_seconds(self) -> float:
        return self.ended_at_epoch_s - self.started_at_epoch_s

    def summary_md(self) -> str:
        lines = [f"# Run {self.run_id}", "", f"**status**: {self.status}"]
        lines.append(f"**wall**: {self.wall_seconds:.1f}s")
        for step in self.steps:
            mark = "ok" if step.ok else "FAIL"
            lines.append(f"- [{mark}] {step.step_id}: {step.detail}")
        for lease_id in self.dirty_leases:
            lines.append(f"- **DIRTY LEASE** {lease_id}: manual remediation required")
        return "\n".join(lines)


class RunEngine:
    """Sequential plan execution; abort-and-recover on first failing fault."""

    def __init__(
        self,
        store: Store,
        sink: LeaseSink,
        *,
        client_factory: Callable[[LeaseSink], LeaseClient] = LeaseClient,
        spec_json: str = "{}",
        sleeper: Callable[[float], None] = time.sleep,
        checks: Mapping[str, SteadyStateCheck] | None = None,
        safety: SafetyContext | None = None,
        live_graph: Callable[[], TopologyGraph] | None = None,
        abort_file: Path | None = None,
    ) -> None:
        self._store = store
        self._sink = sink
        self._client = client_factory(sink)
        self._spec_json = spec_json
        self._sleeper = sleeper
        self._checks = dict(checks or {})
        self._safety = safety
        self._live_graph = live_graph
        self._abort_file = abort_file
        self._abort_mode: str | None = None  # "graceful" | "immediate"

    # -- public -----------------------------------------------------------------------

    def execute(self, plan: ExecutionPlan) -> RunResult:
        if self._safety is not None:
            graph = self._live_graph() if self._live_graph else None
            if graph is not None:
                validate_plan(plan, graph, self._safety)  # G1+G2, raises SafetyRefusedError
        started = utc_now().timestamp()
        self._open_run(plan)
        self._emit(Event(kind=EventKind.RUN_STARTED, run_id=plan.run_id))
        reports: list[StepReport] = []
        dirty: list[str] = []
        status = "completed"
        with _AbortMatrix(self, plan.run_id):
            for step in plan.steps:
                if self._abort_requested():
                    status = "aborted"
                    break
                report, lease_dirty = self._run_step(plan, step)
                reports.append(report)
                dirty.extend(lease_dirty)
                if not report.ok:
                    status = "failed"
                    break  # on_failure defaults to abort_and_recover; later steps cancelled
                if self._abort_mode == "immediate":
                    status = "aborted"
                    break
        ended = utc_now().timestamp()
        recovered = ()
        if dirty or status in ("aborted", "failed"):
            try:
                recovered = self.recover_run(plan.run_id)
            except Exception:
                recovered = ()
        if recovered and status == "aborted":
            dirty = [d for d in dirty if d not in recovered]
        self._close_run(plan.run_id, status, ended)
        result = RunResult(
            run_id=plan.run_id,
            status=status,
            started_at_epoch_s=started,
            ended_at_epoch_s=ended,
            steps=tuple(reports),
            dirty_leases=tuple(dirty),
        )
        self._store.query(
            "UPDATE runs SET summary_md = ? WHERE id = ?",
            (result.summary_md(), plan.run_id),
        )
        kind = (
            EventKind.RUN_COMPLETED
            if status == "completed"
            else EventKind.RUN_FAILED
        )
        self._emit(Event(kind=kind, run_id=plan.run_id))
        return result

    def recover_run(self, run_id: str) -> tuple[str, ...]:
        """Compensate any non-terminal leases a crashed run left behind."""
        recovered: list[str] = []
        for lease in self._sink.active_leases():
            if lease.run_id != run_id:
                continue
            try:
                releasing = self._client.mark_orphaned(lease.id, notes="engine recovery pass")
                _ = releasing
                self._client.mark_releasing(lease.id)
                final = self._client.confirm_release(lease.id, mechanism="watchdog")
                recovered.append(final.id)
            except Exception as exc:
                self._client.mark_dirty(lease.id, notes=f"recovery failed: {exc}")
        return tuple(recovered)

    # -- internals --------------------------------------------------------------------

    def _abort_requested(self) -> bool:
        if self._abort_mode is not None:
            return True
        if self._abort_file is not None and self._abort_file.exists():
            self._abort_mode = "immediate"
            return True
        return False

    def _sleep_interruptible(self, seconds: float) -> None:
        """Sleep honoring the abort matrix: SIGUSR1 cuts sleeps short."""
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self._abort_requested():
                return
            chunk = min(0.1, remaining)
            self._sleeper(chunk)

    def _run_step(self, plan: ExecutionPlan, step: PlannedStep) -> tuple[StepReport, list[str]]:
        action_type = getattr(step.raw_action, "type", "unknown")
        self._insert_step(plan.run_id, step)
        self._emit(Event(kind=EventKind.STEP_STARTED, run_id=plan.run_id, detail={"step": step.id}))
        try:
            if step.fault is not None:
                report, dirty = self._execute_fault(plan, step)
            elif action_type == "wait":
                duration = float(getattr(step.raw_action, "duration", 0.0) or 0.0)
                self._sleeper(duration)
                report = StepReport(step.id, True, f"waited {duration:.1f}s")
                dirty = []
            elif action_type == "check":
                report, dirty = self._execute_check(step), []
            elif action_type in ("start_load", "stop_load", "notify"):
                report = StepReport(
                    step.id, True, f"{action_type} acknowledged (no backend wired yet)"
                )
                dirty = []
            else:
                report = StepReport(step.id, False, f"unplannable action {action_type!r}")
                dirty = []
        except Exception as exc:
            report = StepReport(step.id, False, f"{type(exc).__name__}: {exc}")
            dirty = []
        self._finish_step(step, ok=report.ok)
        self._emit(
            Event(
                kind=(
                    EventKind.STEP_FINISHED
                    if report.ok
                    else EventKind.STEP_SKIPPED
                ),
                run_id=plan.run_id,
                detail={"step": step.id, "detail": report.detail},
            )
        )
        return report, dirty

    def _execute_fault(
        self, plan: ExecutionPlan, step: PlannedStep
    ) -> tuple[StepReport, list[str]]:
        fault = step.fault
        assert fault is not None  # planner contract
        targets: frozenset[str] = frozenset().union(*(t.node_ids for t in fault.targets))
        if self._safety is not None and self._live_graph is not None:
            # G3: re-check resolved targets against *live* topology seconds before injection.
            pre_exec_assertion(
                [(t.selector, t.node_ids) for t in fault.targets], self._live_graph()
            )
        ttl = max(float(fault.duration) + 60.0, 120.0)
        lease = self._client.acquire(
            run_id=plan.run_id,
            fault_id=fault.fault_id,
            targets=targets,
            undo_ops=tuple(op.model_dump(mode="json") for op in fault.undo_ops),
            verify_probes=tuple(p.model_dump(mode="json") for p in fault.verify_probes),
            ttl_seconds=ttl,
        )
        self._record_invocation(plan, step, fault, lease.id)

        self._client.activate(lease.id)
        self._emit(
            Event(
                kind=EventKind.FAULT_INJECTED,
                run_id=plan.run_id,
                detail={"fault": fault.fault_id, "lease": lease.id},
            )
        )
        executor = executor_for(fault.fault_id)
        inject_outcome = executor.inject(lease) if executor is not None else None
        self._record_tool_result(inject_outcome.tool_result if inject_outcome else None)
        self._sleep_interruptible(float(fault.duration))

        self._client.mark_releasing(lease.id)
        undo_outcome = executor.undo(lease) if executor is not None else None
        self._record_tool_result(undo_outcome.tool_result if undo_outcome else None)
        undo_ok = inject_ok = True
        detail_parts: list[str] = []
        if inject_outcome is not None and not inject_outcome.ok:
            inject_ok = False
            detail_parts.append(f"inject: {inject_outcome.detail}")
        if undo_outcome is not None and not undo_outcome.ok:
            undo_ok = False
            detail_parts.append(f"undo: {undo_outcome.detail}")

        report = verify_all(tuple(lease.verify_probes), lease.id)
        verified = report.all_satisfied
        self._record_recovery(lease.id, mechanism="executor", undo_results_json=json.dumps(
            {"inject": inject_outcome.detail if inject_outcome else "no-executor",
             "undo": undo_outcome.detail if undo_outcome else "no-executor"}
        ), verified=verified)

        if undo_ok and verified:
            self._client.confirm_release(lease.id, mechanism="normal")
            self._emit(
                Event(
                    kind=EventKind.FAULT_RECOVERED,
                    run_id=plan.run_id,
                    detail={"fault": fault.fault_id, "lease": lease.id},
                )
            )
            detail = "; ".join(detail_parts) or f"{fault.fault_id} injected+recovered"
            return StepReport(step.id, inject_ok, detail), []

        notes = f"undo_ok={undo_ok} verified={verified}; " + "; ".join(detail_parts)
        dirty_lease = self._client.mark_dirty(lease.id, notes=notes)
        self._emit(
            Event(
                kind=EventKind.FAULT_FAILED,
                run_id=plan.run_id,
                detail={"fault": fault.fault_id, "lease": dirty_lease.id},
            )
        )
        return StepReport(step.id, False, notes), [dirty_lease.id]

    def _execute_check(self, step: PlannedStep) -> StepReport:
        ref = getattr(step.raw_action, "ref", "")
        check = self._checks.get(ref)
        if check is None:
            return StepReport(step.id, False, f"check {ref!r} not compiled into engine")
        verify = _domain_probe_to_verify(check.probe)
        result = run_probe(verify)
        passed = result.satisfied
        return StepReport(step.id, passed, f"{ref}: {'pass' if passed else result.detail}")

    def _open_run(self, plan: ExecutionPlan) -> None:
        now_iso = utc_now().isoformat()
        topo_id = plan.topology_snapshot_id or f"topo-{uuid.uuid4().hex[:12]}"
        config_id = plan.config_snapshot_id
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO config_snapshots (id, resolved_json, source_map, created_at)"
                " VALUES (?, '{}', '{}', ?)",
                (config_id, now_iso),
            )
            # Circular FK (runs<->topology_snapshots): insert runs bare,
            # then the snapshot, then link back.
            conn.execute(
                """
                INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed,
                    status, environment_fingerprint, config_snapshot_id, started_at)
                VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)
                """,
                (
                    plan.run_id,
                    plan.run_id,
                    plan.kind.value,
                    self._spec_json,
                    plan.model_dump_json(),
                    plan.seed,
                    plan.environment_fingerprint,
                    config_id,
                    now_iso,
                ),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO topology_snapshots
                    (id, run_id, graph_json, drift_report, fingerprint)
                VALUES (?, ?, '{}', '{}', ?)
                """,
                (topo_id, plan.run_id, plan.environment_fingerprint),
            )
            conn.execute(
                "UPDATE runs SET topology_snapshot_id = ? WHERE id = ?",
                (topo_id, plan.run_id),
            )

    def _close_run(self, run_id: str, status: str, ended_epoch_s: float) -> None:
        ended_iso = datetime.fromtimestamp(ended_epoch_s, tz=UTC).isoformat()
        with self._store.write() as conn:
            conn.execute(
                "UPDATE runs SET status = ?, ended_at = ? WHERE id = ?",
                (status, ended_iso, run_id),
            )

    def _insert_step(self, run_id: str, step: PlannedStep) -> None:
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO step_runs (id, run_id, seq, parent_step_id,
                    action_type, action_json, status)
                VALUES (?, ?, ?, NULL, ?, ?, 'running')
                """,
                (
                    f"{step.seq:04d}-{step.id}",
                    run_id,
                    step.seq,
                    type(step.raw_action).__name__,
                    step.raw_action.model_dump_json(),
                ),
            )

    def _finish_step(self, step: PlannedStep, *, ok: bool) -> None:
        with self._store.write() as conn:
            conn.execute(
                "UPDATE step_runs SET status = ?, ended_at = ? WHERE id = ?",
                (
                    "completed" if ok else "failed",
                    utc_now().isoformat(),
                    f"{step.seq:04d}-{step.id}",
                ),
            )

    def _record_invocation(
        self, plan: ExecutionPlan, step: PlannedStep, fault, lease_id: str
    ) -> None:
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT INTO fault_invocations (id, run_id, step_run_id, fault_id, targets_json,
                    params_json, backend, lease_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"fi-{uuid.uuid4().hex[:12]}",
                    plan.run_id,
                    f"{step.seq:04d}-{step.id}",
                    fault.fault_id,
                    json.dumps(sorted(n for t in fault.targets for n in t.node_ids)),
                    json.dumps(fault.params),
                    fault.backend or "default",
                    lease_id,
                ),
            )

    def _record_recovery(
        self, lease_id: str, *, mechanism: str, undo_results_json: str, verified: bool
    ) -> None:
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT INTO recovery_records
                    (id, lease_id, attempt, mechanism, undo_results_json, verified, at)
                VALUES (?, ?, 1, ?, ?, ?, ?)
                """,
                (
                    f"rec-{uuid.uuid4().hex[:12]}",
                    lease_id,
                    mechanism,
                    undo_results_json,
                    int(verified),
                    utc_now().isoformat(),
                ),
            )

    def _record_tool_result(self, tool_result) -> None:
        if tool_result is None:
            return
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tool_runs (id, invocation_ref, argv_digest, argv_json,
                    env_digest, host, exit_code, duration_ms, truncated)
                VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"tr-{uuid.uuid4().hex[:12]}",
                    tool_result.argv_digest,
                    json.dumps(tool_result.argv),
                    tool_result.env_digest,
                    tool_result.host,
                    tool_result.exit_code,
                    int(tool_result.duration_ms),
                    int(tool_result.truncated),
                ),
            )

    def _emit(self, event: Event) -> None:
        with self._store.write() as conn:
            conn.execute(
                "INSERT INTO events (run_id, ts, kind, payload_json) VALUES (?, ?, ?, ?)",
                (
                    event.run_id,
                    utc_now().isoformat(),
                    event.kind.value,
                    json.dumps(event.detail),
                ),
            )


def _domain_probe_to_verify(probe: object) -> VerifyProbe:
    """Map a domain checks.Probe onto the agents VerifyProbe runner."""
    kind = getattr(probe, "type", None)
    value = getattr(kind, "value", kind)
    if value == "exec":
        return VerifyProbe(
            probe="exec",
            args={"cmd": list(probe.cmd), "timeout_s": getattr(probe, "timeout", 10.0)},
            expect_present=True,
        )
    if value == "tcp":
        return VerifyProbe(
            probe="tcp",
            args={
                "host": probe.host,
                "port": int(probe.port),
                "timeout_s": getattr(probe, "timeout", 3.0),
            },
            expect_present=True,
        )
    if value == "http":
        return VerifyProbe(
            probe="http",
            args={
                "url": probe.url,
                "expect_status": int(getattr(probe, "expected_status", 200)),
                "timeout_s": getattr(probe, "timeout", 5.0),
            },
            expect_present=True,
        )
    msg = f"unsupported probe type {probe!r}"
    raise ValueError(msg)


class _AbortMatrix:
    """Arms SIGINT (graceful, second signal escalates) and SIGUSR1 (immediate)."""

    def __init__(self, engine: RunEngine, run_id: str) -> None:
        self._engine = engine
        self._run_id = run_id
        self._previous: dict[int, object] = {}

    def __enter__(self) -> _AbortMatrix:
        for signum, mode in ((signal.SIGINT, "graceful"), (signal.SIGUSR1, "immediate")):
            try:
                self._previous[signum] = signal.signal(signum, self._make_handler(mode))
            except (ValueError, OSError):  # non-main thread / unsupported platform
                pass
        return self

    def __exit__(self, *exc_info: object) -> None:
        for signum, previous in self._previous.items():
            try:
                signal.signal(signum, previous)  # type: ignore[arg-type]
            except (ValueError, OSError):
                pass
        self._engine._abort_mode = None

    def _make_handler(self, mode: str) -> Callable[[int, object], None]:
        def handler(signum: int, frame: object) -> None:
            del signum, frame
            if mode == "graceful" and getattr(handler, "seen_once", False):
                effective = "immediate"  # operator insists; escalate
            else:
                if mode == "graceful":
                    handler.seen_once = True  # type: ignore[attr-defined]
                effective = mode
            self._engine._abort_mode = effective
            try:
                self._engine._emit(
                    Event(
                        kind=EventKind.RUN_ABORT_REQUESTED,
                        run_id=self._run_id,
                        detail={"mode": effective},
                    )
                )
            except Exception:
                pass

        return handler
