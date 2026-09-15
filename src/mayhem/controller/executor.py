"""RunEngine — executes a frozen ExecutionPlan against real executors.

The engine owns every durable artifact of a run: runs/step_runs rows,
fault_invocations, recovery_records, and the event journal. Lease lifecycles
go through the LeaseClient so no state transition bypasses the domain rules.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from mayhem.agents.executors import executor_for, read_boot_time
from mayhem.agents.impact import OBSERVATION_BLIND
from mayhem.agents.k8s_resolve import KubernetesRuntimeResolver
from mayhem.agents.lease_client import LeaseClient
from mayhem.agents.probes import run_probe, verify_all
from mayhem.controller.k8s_runtime import K8S_MUTATION_FAULTS
from mayhem.controller.observability_collector import (
    SourceCollection,
    collect_observability,
    probe_to_verify,
)
from mayhem.controller.resilience_report import (
    ResilienceReport,
    build_resilience_report,
)
from mayhem.controller.safety import pre_exec_assertion, validate_plan
from mayhem.domain.cancellation import CancellationLevel, CancellationToken
from mayhem.domain.checks import CheckLocus
from mayhem.domain.common import utc_now
from mayhem.domain.events import Event, EventKind
from mayhem.domain.experiments import OnFailure
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.run_outcome import RunVerdict
from mayhem.domain.success import (
    CriteriaEvaluation,
    Observation,
    evaluate_criteria,
    observations_for_step,
)

if TYPE_CHECKING:
    import sqlite3

    from mayhem.domain.decisions import DecisionRef
from mayhem.topology.resolve import (
    resolve_container,
    resolve_identity,
    resolve_process_identity,
    resolve_status,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from pathlib import Path

    from mayhem.agents.sinks import LeaseSink
    from mayhem.controller.resource_manager import ResourceManager
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.checks import SteadyStateCheck
    from mayhem.domain.experiments import ExecutionPlan, PlannedFault, PlannedStep
    from mayhem.domain.identity import ProcessRuntimeIdentity
    from mayhem.domain.resolution import ResolvedPodTarget
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.store import Store
    from mayhem.toolkit.tool_runner import ToolResult


@dataclass(frozen=True)
class StepReport:
    step_id: str
    ok: bool
    detail: str
    status: str = (
        "ok"  # ok | bypassed | failed | target_drift | failed_to_apply | resource_conflict
    )
    measured: Mapping[str, object] = field(default_factory=dict)  # ADR-M4-3 observations

    @property
    def bypassed(self) -> bool:
        return self.status == "bypassed"

    @property
    def target_drift(self) -> bool:
        return self.status == "target_drift"

    @property
    def failed_to_apply(self) -> bool:
        return self.status == "failed_to_apply"

    @property
    def resource_conflict(self) -> bool:
        return self.status == "resource_conflict"


@dataclass(frozen=True)
class RunResult:
    run_id: str
    status: str  # completed | failed | aborted
    started_at_epoch_s: float
    ended_at_epoch_s: float
    steps: tuple[StepReport, ...] = ()
    dirty_leases: tuple[str, ...] = field(default=())
    verdict: RunVerdict | None = None  # criteria-derived (ADR-M4-3), None when undecided
    criteria_evaluation: CriteriaEvaluation | None = None
    observability: tuple[SourceCollection, ...] = ()  # collected evidence (ADR-M4-4)
    governing_decisions: tuple[DecisionRef, ...] = ()  # decision trace (ADR-M4-1)
    resilience_report: ResilienceReport | None = None  # end-of-run score + diagnosis

    @property
    def wall_seconds(self) -> float:
        return self.ended_at_epoch_s - self.started_at_epoch_s

    def summary_md(self) -> str:
        """End-of-run report: outcome, criteria, steps, cleanup, resilience."""
        lines = [f"# Run {self.run_id}", "", "## outcome"]
        lines.append(f"- **status**: {self.status}")
        if self.verdict is not None:
            lines.append(f"- **verdict**: {self.verdict.value}")
        if self.governing_decisions:
            summary = "; ".join(d.summary() for d in self.governing_decisions)
            lines.append(f"- **decisions**: {summary}")
        if any(not source.skipped for source in self.observability):
            collected = sum(1 for c in self.observability if c.ok)
            lines.append(
                f"- **observations**: {collected}/{len(self.observability)} sources collected"
            )
        if self.started_at_epoch_s > 0:
            start_iso = datetime.fromtimestamp(self.started_at_epoch_s, tz=UTC).isoformat(
                timespec="seconds"
            )
            end_iso = datetime.fromtimestamp(self.ended_at_epoch_s, tz=UTC).isoformat(
                timespec="seconds"
            )
            lines.append(f"- **window**: {start_iso} → {end_iso} ({self.wall_seconds:.1f}s)")
        else:
            lines.append(f"- **wall time**: {self.wall_seconds:.1f}s")
        if self.criteria_evaluation is not None and not self.criteria_evaluation.empty:
            lines += ["", "## success criteria"]
            lines.append(self.criteria_evaluation.summary_md())
        lines += ["", "## steps"]
        if not self.steps:
            lines.append("_no steps executed_")
        for step in self.steps:
            mark = "bypass" if step.status == "bypassed" else "ok" if step.ok else "FAIL"
            lines.append(f"- [{mark}] {step.step_id}: {step.detail}")
        if self.dirty_leases:
            lines += ["", "## cleanup"]
            for lease_id in self.dirty_leases:
                lines.append(f"- **DIRTY LEASE** {lease_id}: manual remediation required")
        if self.resilience_report is not None:
            lines += ["", "## resilience"]
            lines.append(self.resilience_report.summary_md())
        return "\n".join(lines)


# Placeholder PID emitted by compensation templates; replaced with the live PID
# at execution time (ADR-0020), so the value is never older than the syscall.
_LIVE_PID = "@live-pid"

# Sentinel for a running container whose numeric host PID is unreachable
# (podman-machine on macOS, Docker Desktop): exec addressing still works.
_PID_UNAVAILABLE = 0

_STATUS_DETAIL_RE = re.compile(r"->\s*(?P<status>\d{3})\s*$")


def _probe_status_from_detail(detail: str) -> int | None:
    """Extract an observed HTTP status from a probe detail like ``url -> 200``.

    Returns None when the detail does not carry an observable status (probe
    never reached the service), so a status criterion then reads *absent*.
    """
    match = _STATUS_DETAIL_RE.search(detail.strip())
    if match is None:
        return None
    return int(match.group("status"))


def _step_db_status(report: StepReport) -> str:
    """Persisted step_runs.status for a report (verdict statuses echo)."""
    if report.bypassed:
        return "bypassed"
    if report.target_drift:
        return "target_drift"
    if report.failed_to_apply:
        return "failed_to_apply"
    if report.resource_conflict:
        return "resource_conflict"
    return "completed" if report.ok else "failed"


def _substitute_pids(
    undo_ops: tuple[UndoOp, ...],
    verify_probes: tuple[VerifyProbe, ...],
    live_pids: dict[str, int],
    *,
    engine: str | None = None,
    live_targets: Mapping[str, tuple[int, str]] | None = None,
) -> tuple[tuple[UndoOp, ...], tuple[VerifyProbe, ...]]:
    """Replace the ``@live-pid`` placeholder with a freshly resolved PID.

    ``live_pids`` maps a node_id to its current host PID. The placeholder value
    itself is ``node_id:@live-pid`` (e.g. ``svc-api:@live-pid``) so we can tell
    *which* target a placeholder belongs to; substitution is by node_id. When no
    live PID is available the placeholder is left untouched, preserving the
    plan-time value baked in by the compensation template.

    When ``engine`` and ``live_targets`` (node_id → ``(pid, container_name)``)
    are supplied for a **proc.pause** op, the substituted PID is additionally
    addressed by its owning ``cont`` + ``engine`` so the executor can signal the
    process *inside* the container (podman/docker ``exec``). This is required
    when the container runtime lives in a detached VM (podman-machine on macOS),
    where a host ``os.kill`` cannot reach the container PID namespace.
    """

    cont_by_node = {nid: cont for nid, (_pid, cont) in (live_targets or {}).items()}

    def _swap(value: object) -> object:
        if isinstance(value, (list, tuple)):
            return type(value)(_swap_leaf(v) for v in value)
        return _swap_leaf(value)

    def _swap_leaf(value: object) -> object:
        if not isinstance(value, str) or _LIVE_PID not in value:
            return value
        node_id = value.split(":", 1)[0]
        pid = live_pids.get(node_id)
        if pid is None:
            return value
        return str(pid)

    def _address(node_id: str) -> dict[str, str]:
        if not engine:
            return {}
        cont = cont_by_node.get(node_id)
        if not cont:
            return {}
        return {"cont": cont, "engine": engine}

    def _boot_address(swapped: dict[str, object], has_live_pid: bool) -> dict[str, str]:
        """Attach the PID-reuse boot_time for host-mode process ops.

        When a ``@live-pid`` placeholder was substituted for a process not
        addressed by a container (host mode), we read the process's start time
        (``/proc/<pid>/stat`` field 22) and record it on the op. The process
        executor re-reads boot_time before signalling and refuses to signal a
        recycled PID (ADR-M2 Phase 2.4 / ADR-M6-2).
        """
        if not has_live_pid:
            return {}
        if "cont" in swapped or "engine" in swapped:
            return {}
        raw = swapped.get("pid")
        try:
            pid = int(str(raw))
        except (TypeError, ValueError):
            return {}
        boot = read_boot_time(pid)
        if boot is None:
            return {}
        return {"boot_time": str(boot)}

    new_undo = tuple(
        UndoOp(
            op=op.op,
            args={
                **{k: _swap(v) for k, v in op.args.items()},
                **_address(_resolved_node(op)),
                **_boot_address(
                    {k: _swap(v) for k, v in op.args.items()},
                    any(isinstance(v, str) and _LIVE_PID in v for v in op.args.values()),
                ),
            },
            idempotent=op.idempotent,
        )
        for op in undo_ops
    )
    new_verify = tuple(
        VerifyProbe(
            probe=p.probe,
            args={
                **{k: _swap(v) for k, v in p.args.items()},
                **_address(_resolved_verify_node(p)),
            },
            expect_present=p.expect_present,
        )
        for p in verify_probes
    )
    return new_undo, new_verify


def _resolved_verify_node(probe: VerifyProbe) -> str | None:
    """node_id whose ``@live-pid`` placeholder appears in a verify probe."""
    for value in probe.args.values():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and _LIVE_PID in item:
                    return item.split(":", 1)[0] or None
        elif isinstance(value, str) and _LIVE_PID in value:
            return value.split(":", 1)[0] or None
    return None


def _resolved_node(op: UndoOp) -> str | None:
    """node_id whose ``@live-pid`` placeholder was resolved in ``op``, if any."""
    for value in op.args.values():
        if not isinstance(value, str) or _LIVE_PID not in value:
            continue
        node_id = value.split(":", 1)[0]
        if node_id:
            return node_id
    return None


def _group_by_seq(steps: Sequence[PlannedStep]) -> list[list[PlannedStep]]:
    """Partition *consecutive* steps into batches that share a ``seq``.

    Parallel blocks emit one step per container with a shared ``seq``; those form
    a single batch the executor runs concurrently.
    """
    groups: list[list[PlannedStep]] = []
    for step in steps:
        if groups and groups[-1][0].seq == step.seq:
            groups[-1].append(step)
        else:
            groups.append([step])
    return groups


def _continues_on_failure(step: PlannedStep) -> bool:
    """True when a failed fault step names ``on_failure: continue``.

    Continue keeps the drill running after a failing round so the remaining
    faults still get tested; the run is nevertheless reported ``failed``.
    Non-fault steps (wait/check) have no failure policy and always abort.
    """
    fault = step.fault
    return fault is not None and fault.on_failure == OnFailure.CONTINUE


def _missing_live_pids(fault: PlannedFault, live_pids: dict[str, int]) -> set[str]:
    """Target node ids that require a live PID but could not be resolved.

    In container mode each fault target is addressed by a ``node_id:@live-pid``
    placeholder in the undo contract. A target that still carries that placeholder
    after resolution has no usable process address, so injection must not proceed.
    """
    needed: set[str] = set()
    for op in fault.undo_ops:
        for value in op.args.values():
            if not isinstance(value, str) or _LIVE_PID not in value:
                continue
            node_id = value.split(":", 1)[0]
            if node_id not in live_pids:
                needed.add(node_id)
    return needed


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
        resource_manager: ResourceManager | None = None,
        engine: str | None = None,
        on_event: Callable[[Event], None] | None = None,
        bypass: Mapping[tuple[str, str], str] | None = None,
        cancellation: CancellationToken | None = None,
        k8s_resolver: KubernetesRuntimeResolver | None = None,
        recovery_grace: float = 300.0,
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
        self._resource_manager = resource_manager
        self._engine = engine  # podman/docker; pid/ip resolved at execution (ADR-0020)
        self._on_event = on_event  # in-process observer; invoked for every journaled event
        # Verified-inert injections: {(fault_id, container): reason}. The engine
        # skips those steps as "bypass due to <reason>" instead of failing the
        # whole run (per-fault fail-safe, mirrors the impact-gate verdicts).
        self._bypass = dict(bypass or {})
        # Live process identities captured during target resolution last run
        # (ADR-M2 Phase 2.4) — the PID-reuse guard compares these boot times
        # against a re-read immediately before mutation.
        self._resolved_process_identities: dict[str, ProcessRuntimeIdentity] = {}
        # Cancellation escalation ladder (ADR-M2 Phase 2.5): a shared token the
        # signal handler escalates grace -> term -> kill and the agent loop
        # reads at every safe point.
        self._cancellation = cancellation or CancellationToken()
        # Execution-time Kubernetes resolver (k-plan-3 SP-3.4): None means
        # "build lazily on demand from the kubectl/SDK gate."
        self._k8s_resolver = k8s_resolver
        # k-plan-4 §4.5: how long pod-lifecycle compensation waits for a
        # replacement pod to reach Ready before declaring a timeout.
        self._recovery_grace_s = max(float(recovery_grace), 10.0)

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
            for group in _group_by_seq(plan.steps):
                if self._abort_requested():
                    status = "aborted"
                    break
                if len(group) == 1:
                    report, lease_dirty = self._run_step(plan, group[0])
                    reports.append(report)
                    dirty.extend(lease_dirty)
                    if not report.ok:
                        status = "failed"
                        if not _continues_on_failure(group[0]):
                            break  # abort_and_recover; later steps cancelled
                else:
                    batch_reports, lease_dirty = self._run_parallel(plan, group)
                    reports.extend(batch_reports)
                    dirty.extend(lease_dirty)
                    if not all(r.ok for r in batch_reports):
                        status = "failed"
                        failed_ids = {r.step_id for r in batch_reports if not r.ok}
                        if any(
                            not _continues_on_failure(step)
                            for step in group
                            if step.id in failed_ids
                        ):
                            break  # a failing abort_and_recover step; later steps cancelled
                if self._abort_mode == "immediate":
                    status = "aborted"
                    break
        ended = utc_now().timestamp()
        recovered: tuple[str, ...] = ()
        if dirty or status in ("aborted", "failed"):
            try:
                recovered = self.recover_run(plan.run_id)
            except Exception:
                recovered = ()
        if recovered and status == "aborted":
            dirty = [d for d in dirty if d not in recovered]
        verdict, evaluation = self._criteria_verdict(plan, reports, status)
        collections = self._collect_observability(plan)
        self._close_run(
            plan.run_id,
            status,
            ended,
            verdict=verdict,
            evaluation=evaluation,
            observability=collections,
        )
        resilience: ResilienceReport | None = None
        try:
            live = self._live_graph() if self._live_graph is not None else None
            resilience = build_resilience_report(
                plan,
                reports,
                dirty,
                live,
                self._engine,
            )
        except Exception:
            resilience = None
        result = RunResult(
            run_id=plan.run_id,
            status=status,
            started_at_epoch_s=started,
            ended_at_epoch_s=ended,
            steps=tuple(reports),
            dirty_leases=tuple(dirty),
            verdict=verdict,
            criteria_evaluation=evaluation,
            observability=collections,
            governing_decisions=plan.decision_refs,
            resilience_report=resilience,
        )
        self._store.query(
            "UPDATE runs SET summary_md = ? WHERE id = ?",
            (result.summary_md(), plan.run_id),
        )
        kind = EventKind.RUN_COMPLETED if status == "completed" else EventKind.RUN_FAILED
        self._emit(Event(kind=kind, run_id=plan.run_id))
        return result

    def recover_run(self, run_id: str) -> tuple[str, ...]:
        """Compensate any non-terminal leases a crashed run left behind."""
        _recoverable = {
            LeaseState.PENDING,
            LeaseState.ACTIVE,
            LeaseState.ORPHANED,
            LeaseState.RELEASING,
        }
        recovered: list[str] = []
        for lease in self._sink.active_leases():
            if lease.run_id != run_id:
                continue
            if lease.state not in _recoverable:
                # Terminal (released/expired) or dirty (terminal-pending-ack):
                # no valid transition exists, so nothing to auto-recover.
                continue
            try:
                if lease.state in (LeaseState.PENDING, LeaseState.ACTIVE):
                    releasing = self._client.mark_orphaned(lease.id, notes="engine recovery pass")
                    _ = releasing
                    self._client.mark_releasing(lease.id)
                elif lease.state is LeaseState.ORPHANED:
                    # Already recorded as orphaned: resume the compensation
                    # by entering RELEASING for the confirm step.
                    self._client.mark_releasing(lease.id)
                # RELEASING already: jump straight to confirmation.
                final = self._client.confirm_release(lease.id, mechanism="watchdog")
                recovered.append(final.id)
            except Exception as exc:
                self._client.mark_dirty(lease.id, notes=f"recovery failed: {exc}")
        return tuple(recovered)

    # -- internals --------------------------------------------------------------------

    def _abort_requested(self) -> bool:
        """True when cancellation has been requested at any ladder level.

        Side effect: asserts the enforcement side of the ladder — TERM sends
        SIGTERM to live payload toolkit processes, KILL sends SIGKILL.
        """
        level = self._cancellation.level
        if level == CancellationLevel.NONE:
            # Not cancelled via the token; fall back to the legacy abort file.
            if self._abort_file is not None and self._abort_file.exists():
                self._cancellation.request(CancellationLevel.KILL)
                level = CancellationLevel.KILL
            else:
                return False
        self._sync_abort_mode(level)
        self._enforce_ladder(level)
        return True

    def _sync_abort_mode(self, level: CancellationLevel) -> None:
        """Map the ladder level back onto the legacy ``_abort_mode`` string."""
        self._abort_mode = {
            CancellationLevel.GRACE: "graceful",
            CancellationLevel.TERM: "term",
            CancellationLevel.KILL: "immediate",
        }[level]

    def _enforce_ladder(self, level: CancellationLevel) -> None:
        """Signal live payload toolkit processes per the ladder rung.

        ``grace`` does nothing here: the cooperative boundary (next step /
        fault edge) is the safe abort. ``term`` sends SIGTERM to every live
        payload process tracked by active leases, then re-asserts; ``kill``
        sends SIGKILL. Signals are best-effort: a payload that already exited
        is simply skipped.
        """
        if level == CancellationLevel.GRACE:
            return
        try:
            leases = self._client.active_leases()
        except Exception:
            return
        for lease in leases:
            for pid, cont, engine in self._live_payload_pids(lease):
                self._send_payload_signal(pid, level, cont, engine)

    def _live_payload_pids(self, lease: FaultLease) -> list[tuple[int, str | None, str | None]]:
        """Extract ``(pid, cont, engine)`` for live payload targets in a lease."""
        found: list[tuple[int, str | None, str | None]] = []
        for op in lease.undo_ops:
            raw = op.args.get("pid")
            try:
                pid = int(raw) if raw is not None else None
            except (TypeError, ValueError):
                continue
            if pid is not None and (pid > 1 or (op.args.get("cont") and op.args.get("engine"))):
                found.append((pid, op.args.get("cont"), op.args.get("engine")))
        return found

    def _send_payload_signal(
        self,
        pid: int,
        level: CancellationLevel,
        cont: str | None,
        engine: str | None,
    ) -> None:
        """Deliver SIGTERM (term) or SIGKILL (kill) to a payload process.

        Container-addressed payloads are signaled via ``<engine> kill`` so the
        signal reaches the container's main process across the runtime
        boundary (ADR-0020); otherwise a plain host ``os.kill``.
        """
        sig = signal.SIGKILL if level == CancellationLevel.KILL else signal.SIGTERM
        if cont and engine:
            with contextlib.suppress(Exception):
                import subprocess

                subprocess.run(
                    [
                        engine,
                        "kill",
                        "--signal",
                        "SIGKILL" if sig == signal.SIGKILL else "TERM",
                        cont,
                    ],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
            return
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.kill(pid, sig)

    def _sleep_interruptible(self, seconds: float) -> None:
        """Sleep honoring the cancellation ladder: any rung cuts sleeps short."""
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
        self._emit(
            Event(
                kind=EventKind.STEP_STARTED,
                run_id=plan.run_id,
                detail={"step": step.id},
            )
        )
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
            elif action_type == "check_http":
                report, dirty = self._execute_check_http(step), []
            elif action_type == "check_spec":
                report, dirty = self._execute_check_spec(step), []
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
        self._finish_step(step, ok=report.ok, status=_step_db_status(report))
        self._emit(
            Event(
                kind=(
                    EventKind.STEP_SKIPPED
                    if (report.bypassed or not report.ok)
                    else EventKind.STEP_FINISHED
                ),
                run_id=plan.run_id,
                detail={"step": step.id, "detail": report.detail},
            )
        )
        return report, dirty

    def _run_parallel(
        self, plan: ExecutionPlan, steps: list[PlannedStep]
    ) -> tuple[list[StepReport], list[str]]:
        """Run several same-``seq`` fault steps concurrently.

        Fault injection and duration sleeps overlap across threads; all durable
        writes funnel through the single ``Store`` connection, which is
        internally serialized, so no executor-side locking is required here.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: PLC0415

        reports: list[StepReport] = []
        dirty: list[str] = []
        with ThreadPoolExecutor(max_workers=len(steps)) as pool:
            futures = [pool.submit(self._run_step, plan, step) for step in steps]
            for future in as_completed(futures):
                report, lease_dirty = future.result()
                reports.append(report)
                dirty.extend(lease_dirty)
        return reports, dirty

    def _execute_k8s_fault(
        self, plan: ExecutionPlan, step: PlannedStep, targets: frozenset[str]
    ) -> tuple[StepReport, list[str]]:
        """Kubernetes-routed step execution (k-plan-3 SP-3.4).

        Resolve the pod -> record the write-ahead undo contract -> form the
        lease (carrying the resolved target via migration ``resolved_target``)
        -> inject through the K8sExecutor -> hold -> undo -> release. Every
        durable transition goes through the LeaseClient so no k8s path
        bypasses the domain rules. Families the milestone driver refuses
        (payload/lifecycle) fail loud with ``k8s.unsupported`` before any
        lease forms.
        """
        from mayhem.agents.executors import (  # noqa: PLC0415
            K8S_SIGNAL_FAULTS,
            k8s_unsupported_reason,
        )
        from mayhem.controller.k8s_runtime import (  # noqa: PLC0415
            K8S_NODE_FAULTS,
            k8s_undo_spec,
            make_k8s_resolver,
            preferred_pod_from_graph,
        )
        from mayhem.domain.errors import ResolutionError, SelectionError  # noqa: PLC0415

        fault = step.fault
        assert fault is not None and fault.target is not None
        if fault.fault_id in K8S_NODE_FAULTS:
            return self._execute_k8s_node_fault(plan, step)
        if fault.fault_id in K8S_MUTATION_FAULTS:
            return self._execute_k8s_pod_fault(plan, step)
        resolver = make_k8s_resolver(self._k8s_resolver)
        if resolver is None or not resolver.available:
            return (
                StepReport(
                    step.id,
                    False,
                    "k8s.unsupported: no cluster client (kubectl not on PATH, SDK "
                    "not importable)",
                    status="failed_to_apply",
                ),
                [],
            )
        if fault.fault_id not in K8S_SIGNAL_FAULTS:
            return (
                StepReport(
                    step.id,
                    False,
                    f"failed_to_apply: {k8s_unsupported_reason(fault.fault_id)} "
                    "(safe-aborted, no mutation)",
                    status="failed_to_apply",
                ),
                [],
            )
        try:
            outcome = resolver.resolve(
                fault.target,
                preferred_pod=preferred_pod_from_graph(self._live_graph, targets),
            )
            target = outcome.resolved
            if target is None:
                raise ResolutionError("resolution.no_target", "resolver returned no pod")
            pid, boot = resolver.read_primary_pid(target)
        except ResolutionError as exc:
            return (
                StepReport(step.id, False, f"{exc.code}: {exc}", status="resolution_failed"),
                [],
            )
        except SelectionError as exc:
            return (
                StepReport(step.id, False, f"{exc.code}: {exc}", status="selection_failed"),
                [],
            )
        if outcome.drift:
            self._emit(
                Event(
                    kind=EventKind.DRIFT_REPORTED,
                    run_id=plan.run_id,
                    detail={
                        "fault": fault.fault_id,
                        "step": step.id,
                        "note": outcome.note,
                    },
                )
            )
        undo_spec = k8s_undo_spec(fault.fault_id, target, pid=pid, boot=boot)
        lease = self._client.acquire(
            run_id=plan.run_id,
            fault_id=fault.fault_id,
            targets=targets,
            undo_ops=(undo_spec,),
            verify_probes=(
                VerifyProbe(
                    probe="k8s.process",
                    args={
                        "fault_id": fault.fault_id,
                        "pod": target.pod,
                        "namespace": target.namespace,
                        "pid": pid,
                        "boot": boot,
                    },
                ),
            ),
            ttl_seconds=max(float(fault.duration) + 60.0, 120.0),
            runtime_identity=target.authority_key,
            resolved_target=target,
        )
        active = self._client.activate(lease.id)
        executor = executor_for(fault.fault_id, runtime=RuntimeLabel.KUBERNETES)
        if executor is None:
            self._client.mark_releasing(lease.id)
            self._client.confirm_release(lease.id, mechanism="failed_to_apply")
            return (
                StepReport(
                    step.id,
                    False,
                    "failed_to_apply: k8s.unsupported: no executor registered "
                    "(safe-aborted, no mutation)",
                    status="failed_to_apply",
                ),
                [],
            )
        reason = executor.can_apply(active)
        if reason is not None:
            self._client.mark_releasing(lease.id)
            self._client.confirm_release(lease.id, mechanism="failed_to_apply")
            self._emit(
                Event(
                    kind=EventKind.FAULT_FAILED,
                    run_id=plan.run_id,
                    detail={
                        "fault": fault.fault_id,
                        "lease": lease.id,
                        "status": "failed_to_apply",
                        "reason": reason,
                    },
                ),
            )
            return (
                StepReport(
                    step.id,
                    False,
                    f"failed_to_apply: {reason} (safe-aborted, no mutation)",
                    status="failed_to_apply",
                ),
                [],
            )
        inject_outcome = executor.inject(active)
        self._record_tool_result(inject_outcome.tool_result if inject_outcome else None)
        if not inject_outcome.ok:
            self._client.mark_releasing(lease.id)
            self._client.confirm_release(lease.id, mechanism="inject_failed")
            self._emit(
                Event(
                    kind=EventKind.FAULT_FAILED,
                    run_id=plan.run_id,
                    detail={
                        "fault": fault.fault_id,
                        "lease": lease.id,
                        "status": "inject_failed",
                        "reason": inject_outcome.detail,
                    },
                ),
            )
            return (
                StepReport(step.id, False, inject_outcome.detail, status="inject_failed"),
                [],
            )
        self._emit(
            Event(
                kind=EventKind.FAULT_INJECTED,
                run_id=plan.run_id,
                detail={
                    "fault": fault.fault_id,
                    "lease": lease.id,
                    "target": target.authority_key,
                    "pod": target.pod,
                    "resolver_note": outcome.note,
                },
            ),
        )
        self._sleep_interruptible(float(fault.duration))
        undo_outcome = executor.undo(active)
        self._record_tool_result(undo_outcome.tool_result if undo_outcome else None)
        if undo_outcome.ok:
            self._client.mark_releasing(lease.id)
            self._client.confirm_release(lease.id, mechanism="normal")
            self._emit(
                Event(
                    kind=EventKind.FAULT_RECOVERED,
                    run_id=plan.run_id,
                    detail={"fault": fault.fault_id, "lease": lease.id},
                ),
            )
            return (
                StepReport(
                    step.id,
                    True,
                    f"k8s {fault.fault_id} injected on {target.authority_key}: "
                    f"{inject_outcome.detail}; undo: {undo_outcome.detail}",
                ),
                [],
            )
        dirty_lease = self._client.mark_releasing(lease.id)
        dirty_lease = self._client.mark_dirty(lease.id, notes=undo_outcome.detail)
        return (
            StepReport(
                step.id,
                False,
                f"k8s undo DIRTY on {lease.id}: {undo_outcome.detail}",
                status="dirty",
            ),
            [dirty_lease.id],
        )

    def _execute_k8s_pod_fault(
        self, plan: ExecutionPlan, step: PlannedStep
    ) -> tuple[StepReport, list[str]]:
        """Pod-lifecycle + NetworkPolicy step execution (k-plan-4 §4.4/§4.5).

        ``k8s.pod_kill``/``k8s.pod_evict``/``k8s.pod_oom`` are irreversible:
        after the hold the round enters compensation — the engine polls the
        workload's eligible pod set until a pod with a different uid has
        replaced the injected one, bounded by ``config.recovery_grace``.
        ``k8s.network_policy`` is reversible and ends with a live undo
        (policy delete); ``k8s.pod_pressure`` is container-level pressure from
        the k-plan-3 exec path.  Every durable transition flows through the
        LeaseClient, one lease per resolved pod.
        """
        from mayhem.controller.k8s_runtime import (  # noqa: PLC0415
            K8S_REVERSIBLE_FAULTS,
            k8s_mutation_spec,
            k8s_undo_ops_for,
            make_k8s_resolver,
        )
        from mayhem.domain.errors import ResolutionError, SelectionError  # noqa: PLC0415

        fault = step.fault
        assert fault is not None and fault.target is not None
        resolver = make_k8s_resolver(self._k8s_resolver)
        if resolver is None or not resolver.available:
            return (
                StepReport(
                    step.id,
                    False,
                    "k8s.unsupported: no cluster client (kubectl not on PATH, SDK "
                    "not importable)",
                    status="failed_to_apply",
                ),
                [],
            )
        action = fault.fault_id.split(".", 1)[-1]
        try:
            outcomes = resolver.resolve_many(fault.target, pod_action=action)
        except ResolutionError as exc:
            return (
                StepReport(step.id, False, f"{exc.code}: {exc}", status="resolution_failed"),
                [],
            )
        except SelectionError as exc:
            return (
                StepReport(step.id, False, f"{exc.code}: {exc}", status="selection_failed"),
                [],
            )
        if not outcomes:
            return (
                StepReport(
                    step.id,
                    False,
                    "selection.no_eligible_pods: no pod eligible for the mutation",
                    status="selection_failed",
                ),
                [],
            )

        lease_ids: list[str] = []
        dirty: list[str] = []
        details: list[str] = []
        for outcome in outcomes:
            target = outcome.resolved
            if target is None:
                continue
            if outcome.drift:
                self._emit(
                    Event(
                        kind=EventKind.DRIFT_REPORTED,
                        run_id=plan.run_id,
                        detail={
                            "fault": fault.fault_id,
                            "step": step.id,
                            "note": outcome.note,
                        },
                    )
                )
            mutation = k8s_mutation_spec(fault.fault_id, target, params=fault.params)
            lease = self._client.acquire(
                run_id=plan.run_id,
                fault_id=fault.fault_id,
                targets=frozenset({target.pod}),
                undo_ops=(mutation, *k8s_undo_ops_for(fault.fault_id, target)),
                verify_probes=(
                    VerifyProbe(
                        probe="k8s.replaced" if fault.fault_id not in K8S_REVERSIBLE_FAULTS
                        else "k8s.undo",
                        args={
                            "fault_id": fault.fault_id,
                            "pod": target.pod,
                            "namespace": target.namespace,
                        },
                    ),
                ),
                ttl_seconds=max(float(fault.duration) + 60.0, 120.0),
                runtime_identity=target.authority_key,
                resolved_target=target,
            )
            active = self._client.activate(lease.id)
            executor = executor_for(fault.fault_id, runtime=RuntimeLabel.KUBERNETES)
            reason = (
                executor.can_apply(active)
                if executor is not None
                else "k8s.unsupported: no executor registered"
            )
            if reason is not None:
                self._client.mark_releasing(lease.id)
                self._client.confirm_release(lease.id, mechanism="failed_to_apply")
                self._emit(
                    Event(
                        kind=EventKind.FAULT_FAILED,
                        run_id=plan.run_id,
                        detail={
                            "fault": fault.fault_id,
                            "lease": lease.id,
                            "status": "failed_to_apply",
                            "reason": reason,
                        },
                    ),
                )
                return (
                    StepReport(
                        step.id,
                        False,
                        f"failed_to_apply: {reason} (safe-aborted, no mutation)",
                        status="failed_to_apply",
                    ),
                    [],
                )
            inject_outcome = executor.inject(active)
            self._record_tool_result(
                inject_outcome.tool_result if inject_outcome else None
            )
            if not inject_outcome.ok:
                self._client.mark_releasing(lease.id)
                self._client.confirm_release(lease.id, mechanism="inject_failed")
                self._emit(
                    Event(
                        kind=EventKind.FAULT_FAILED,
                        run_id=plan.run_id,
                        detail={
                            "fault": fault.fault_id,
                            "lease": lease.id,
                            "status": "inject_failed",
                            "reason": inject_outcome.detail,
                        },
                    ),
                )
                return (
                    StepReport(
                        step.id, False, inject_outcome.detail, status="inject_failed"
                    ),
                    [],
                )
            lease_ids.append(lease.id)
            self._emit(
                Event(
                    kind=EventKind.FAULT_INJECTED,
                    run_id=plan.run_id,
                    detail={
                        "fault": fault.fault_id,
                        "lease": lease.id,
                        "target": target.authority_key,
                        "pod": target.pod,
                    },
                )
            )
            self._sleep_interruptible(float(fault.duration))
            if fault.fault_id in K8S_REVERSIBLE_FAULTS:
                undo_outcome = executor.undo(active)
                self._record_tool_result(
                    undo_outcome.tool_result if undo_outcome else None
                )
                self._client.mark_releasing(lease.id)
                if undo_outcome.ok:
                    self._client.confirm_release(lease.id, mechanism="normal")
                    self._emit(
                        Event(
                            kind=EventKind.FAULT_RECOVERED,
                            run_id=plan.run_id,
                            detail={"fault": fault.fault_id, "lease": lease.id},
                        ),
                    )
                    details.append(
                        f"{target.pod}: {inject_outcome.detail}; undo: {undo_outcome.detail}"
                    )
                    continue
                mark = self._client.mark_releasing(lease.id)
                mark = self._client.mark_dirty(lease.id, notes=undo_outcome.detail)
                dirty.append(mark.id)
                details.append(f"{target.pod}: undo DIRTY ({undo_outcome.detail})")
                continue
            recovered = self._wait_for_pod_replacement(resolver, fault, target)
            self._client.mark_releasing(lease.id)
            if recovered:
                self._client.confirm_release(lease.id, mechanism="normal")
                self._emit(
                    Event(
                        kind=EventKind.FAULT_RECOVERED,
                        run_id=plan.run_id,
                        detail={
                            "fault": fault.fault_id,
                            "lease": lease.id,
                            "compensation": "replacement ready",
                        },
                    ),
                )
                details.append(
                    f"{target.pod}: {inject_outcome.detail}; replacement ready"
                )
            else:
                reason = (
                    "replacement pod did not reach Ready within "
                    f"recovery_grace={self._recovery_grace_s:.0f}s"
                )
                mark = self._client.mark_dirty(
                    lease.id, notes="; ".join([inject_outcome.detail, reason])
                )
                dirty.append(mark.id)
                self._emit(
                    Event(
                        kind=EventKind.FAULT_FAILED,
                        run_id=plan.run_id,
                        detail={
                            "fault": fault.fault_id,
                            "lease": lease.id,
                            "status": "compensation_timeout",
                            "reason": reason,
                        },
                    ),
                )
                details.append(f"{target.pod}: compensation timed out")
        if dirty:
            return (
                StepReport(
                    step.id,
                    False,
                    "k8s compensation DIRTY on " + ", ".join(sorted(dirty)),
                    status="dirty",
                ),
                dirty,
            )
        return StepReport(step.id, True, "; ".join(details) or "no pods mutated"), lease_ids

    def _wait_for_pod_replacement(
        self,
        resolver: KubernetesRuntimeResolver,
        fault: PlannedFault,
        target: ResolvedPodTarget,
    ) -> bool:
        """Poll the workload until the injected pod is replaced (k-plan-4 §4.5).

        A replacement is any eligible pod whose uid differs from the injected
        one.  Zero-eligible windows and resolution errors during the mutation
        are transient and keep the poll alive until ``recovery_grace`` elapses.
        """
        deadline = time.monotonic() + self._recovery_grace_s
        override = (fault.params or {}).get("recovery_grace")
        if override is not None:
            try:
                deadline = time.monotonic() + float(override)
            except (TypeError, ValueError):
                pass
        while time.monotonic() < deadline:
            if self._abort_requested():
                return False
            try:
                news = resolver.resolve_many(
                    fault.target, pod_action=fault.fault_id.split(".", 1)[-1]
                )
            except (ResolutionError, SelectionError):
                news = []
            if any(
                o.resolved is not None
                and o.resolved.pod_uid != target.pod_uid
                and o.resolved.pod != target.pod
                for o in news
            ):
                return True
            chunk = min(2.0, max(deadline - time.monotonic(), 0.0) or 2.0)
            self._sleep_interruptible(chunk)
        return False

    def _execute_k8s_node_fault(
        self, plan: ExecutionPlan, step: PlannedStep
    ) -> tuple[StepReport, list[str]]:
        """Execute a k8s *node*-level fault (k-plan-5 §5.1).

        Resolve the node -> record the node mutation write-ahead contract ->
        form the lease (carrying a ``ResolvedNodeTarget``) -> inject through
        the node executor -> hold -> undo -> release.  Every durable
        transition goes through the LeaseClient so no node path bypasses the
        domain rules.  Node faults are always reversible (``k8s.node_drain``
        undo = uncordon, ``k8s.node_pressure`` undo = workload delete).
        """
        from mayhem.agents.executors import (  # noqa: PLC0415
            executor_for,
            k8s_executor_for,
        )
        from mayhem.controller.k8s_runtime import (  # noqa: PLC0415
            K8S_NODE_FAULTS,
            make_k8s_resolver,
            k8s_node_routing,
            k8s_node_spec,
            k8s_node_undo_ops,
            k8s_node_verify_spec,
        )
        from mayhem.domain.errors import ResolutionError, SelectionError  # noqa: PLC0415

        fault = step.fault
        assert fault is not None and fault.target is not None
        resolver = make_k8s_resolver(self._k8s_resolver)
        if resolver is None or not resolver.available:
            return (
                StepReport(
                    step.id,
                    False,
                    "k8s.unsupported: no cluster client (kubectl not on PATH, SDK "
                    "not importable)",
                ),
                [],
            )
        if fault.fault_id not in K8S_NODE_FAULTS:
            return (
                StepReport(step.id, False, f"k8s.unsupported: {fault.fault_id}"),
                [],
            )
        routing = k8s_node_routing()
        pipeline = routing.get(fault.fault_id, "k8s.node")
        assert pipeline == "k8s.node"
        authority = fault.target.authority
        node_name = authority.get("name") or authority.get("selector")
        if isinstance(node_name, dict):
            # selector dict → resolver does label matching; keep node_name None
            node_name_arg: str | None = None
        else:
            node_name_arg = str(node_name) if node_name else None
        try:
            outcome = resolver.resolve_node(
                fault.target, node_name=node_name_arg
            )
        except (ResolutionError, SelectionError) as exc:
            self._emit(
                Event(
                    kind=EventKind.FAULT_FAILED,
                    run_id=plan.run_id,
                    detail={"fault": fault.fault_id, "reason": str(exc)},
                ),
            )
            return StepReport(step.id, False, str(exc)), []
        resolved = outcome.resolved
        if resolved is None:
            return StepReport(step.id, False, "node resolve returned no target"), []
        params: dict[str, object] = dict(fault.params or {})
        mutation = k8s_node_spec(fault.fault_id, resolved, params)
        lease = self._client.acquire(
            run_id=plan.run_id,
            fault_id=fault.fault_id,
            targets=frozenset({resolved.node}),
            undo_ops=k8s_node_undo_ops(fault.fault_id, resolved, params),
            verify_probes=(
                VerifyProbe(
                    probe="k8s.node_restored",
                    args={
                        "fault_id": fault.fault_id,
                        "node": resolved.node,
                        "node_uid": resolved.node_uid,
                    },
                ),
            ),
            ttl_seconds=max(float(fault.duration) + 60.0, 120.0),
            runtime_identity=resolved.authority_key,
            resolved_target=resolved,
        )
        active = self._client.activate(lease.id)
        executor = executor_for(fault.fault_id, runtime=RuntimeLabel.KUBERNETES)
        reason = (
            executor.can_apply(active)
            if executor is not None
            else "k8s.unsupported: no executor registered"
        )
        if reason is not None:
            self._client.mark_releasing(lease.id)
            self._client.confirm_release(lease.id, mechanism="failed_to_apply")
            self._emit(
                Event(
                    kind=EventKind.FAULT_FAILED,
                    run_id=plan.run_id,
                    detail={
                        "fault": fault.fault_id,
                        "lease": lease.id,
                        "node": resolved.node,
                        "reason": reason,
                    },
                ),
            )
            return (
                StepReport(step.id, False, reason),
                [],
            )
        inject_outcome = executor.inject(active)
        self._record_tool_result(inject_outcome.tool_result)
        if not inject_outcome.ok:
            # A node mutation can partially apply before failing (cordon ok,
            # drain not) — run the write-ahead undo so the node is never left
            # mid-mutation.  If the undo itself fails, escalate to DIRTY.
            undo_outcome = executor.undo(active)
            self._record_tool_result(undo_outcome.tool_result if undo_outcome else None)
            dirty: list[str] = []
            if undo_outcome and undo_outcome.ok:
                self._client.mark_releasing(lease.id)
                self._client.confirm_release(
                    lease.id, mechanism="failed_to_apply_undone"
                )
                note = f"{inject_outcome.detail} (undo ok)"
            else:
                self._client.mark_releasing(lease.id)
                mark = self._client.mark_dirty(
                    lease.id,
                    notes=(
                        f"{inject_outcome.detail}; undo failed: "
                        f"{(undo_outcome.detail if undo_outcome else 'not attempted')}"
                    ),
                )
                dirty.append(mark.id)
                note = f"{inject_outcome.detail}; undo DIRTY"
            self._emit(
                Event(
                    kind=EventKind.FAULT_FAILED,
                    run_id=plan.run_id,
                    detail={
                        "fault": fault.fault_id,
                        "lease": lease.id,
                        "node": resolved.node,
                        "reason": inject_outcome.detail,
                    },
                ),
            )
            return (
                StepReport(step.id, False, note),
                dirty,
            )
        lease_ids: list[str] = [lease.id]
        self._emit(
            Event(
                kind=EventKind.FAULT_INJECTED,
                run_id=plan.run_id,
                detail={
                    "fault": fault.fault_id,
                    "lease": lease.id,
                    "node": resolved.node,
                },
            )
        )
        self._sleep_interruptible(float(fault.duration))
        undo_outcome = executor.undo(active)
        self._record_tool_result(undo_outcome.tool_result if undo_outcome else None)
        self._client.mark_releasing(lease.id)
        if undo_outcome and undo_outcome.ok:
            self._client.confirm_release(lease.id, mechanism="normal")
            self._emit(
                Event(
                    kind=EventKind.FAULT_RECOVERED,
                    run_id=plan.run_id,
                    detail={"fault": fault.fault_id, "lease": lease.id},
                ),
            )
            details = [
                f"{resolved.node}: {inject_outcome.detail}; undo: {undo_outcome.detail}"
            ]
            return (
                StepReport(step.id, True, "; ".join(details)),
                lease_ids,
            )
        mark = self._client.mark_dirty(
            lease.id,
            notes="; ".join([inject_outcome.detail, undo_outcome.detail if undo_outcome else "no undo"]),
        )
        return (
            StepReport(
                step.id,
                False,
                f"{resolved.node}: {inject_outcome.detail}; undo DIRTY "
                f"({undo_outcome.detail if undo_outcome else 'no undo'})",
            ),
            [mark.id],
        )

    def _execute_fault(  # noqa: PLR0915, PLR0912  (converging inject/monitor/recover pipeline)
        self, plan: ExecutionPlan, step: PlannedStep
    ) -> tuple[StepReport, list[str]]:
        fault = step.fault
        assert fault is not None  # planner contract
        targets: frozenset[str] = frozenset().union(*(t.node_ids for t in fault.targets))
        if fault.target is not None and fault.target.runtime == RuntimeLabel.KUBERNETES:
            # k-plan-3: a kubernetes-routed step delivers through the resolved
            # pod (kubectl exec driver), not the docker host pipeline.
            return self._execute_k8s_fault(plan, step, targets)
        if self._safety is not None and self._live_graph is not None:
            # G3: re-check resolved targets against *live* topology seconds before injection.
            pre_exec_assertion(
                [(t.selector, t.node_ids) for t in fault.targets], self._live_graph()
            )
        # Resolve fresh PIDs at execution time (ADR-0020): the PID baked into the plan is
        # a placeholder, never older than the injection syscall. Substitute the live value
        # into the undo contract + verify probes before the lease forms.
        live_targets = self._resolve_live_targets(fault)
        bypass_reasons = {
            cont: why
            for (fid, cont), why in self._bypass.items()
            if fid == fault.fault_id
            and cont in {container for _pid, container in live_targets.values()}
        }
        if bypass_reasons:
            # Fail-safe per fault: the impact gate proved this injection cannot
            # take effect (missing tooling/capability), so skip it with an
            # explicit reason instead of failing (or perturbing) the run.
            note = "; ".join(f"{c}: {why}" for c, why in sorted(bypass_reasons.items()))
            return (
                StepReport(step.id, True, f"bypass due to {note}", status="bypassed"),
                [],
            )
        # ADR-M2-3: live inspection wins over a stale journal. Re-resolve the
        # target's current RuntimeIdentity and compare it to the planned one;
        # a mismatch (container recreated under the same name) is TARGET_DRIFT —
        # safe-abort this fault with no mutation.
        drift = self._detect_target_drift(step, fault, live_targets)
        if drift is not None:
            return (
                StepReport(
                    step.id,
                    False,
                    drift,
                    status="target_drift",
                ),
                [],
            )
        live_pids = {node_id: pid for node_id, (pid, _cont) in live_targets.items()}
        if self._live_graph is not None:
            # Container mode: a target whose container PID cannot be resolved has no
            # usable fallback, so fail the step *before* a lease forms instead of
            # injecting against a stale placeholder and stranding a dirty lease.
            missing = _missing_live_pids(fault, live_pids)
            if missing:
                return (
                    StepReport(
                        step.id,
                        False,
                        "cannot resolve live pid for " + ", ".join(sorted(missing)),
                    ),
                    [],
                )
        undo_ops, verify_probes = _substitute_pids(
            fault.undo_ops,
            fault.verify_probes,
            live_pids,
            engine=self._engine,
            live_targets=live_targets,
        )
        ttl = max(float(fault.duration) + 60.0, 120.0)
        lease = self._client.acquire(
            run_id=plan.run_id,
            fault_id=fault.fault_id,
            targets=targets,
            undo_ops=tuple(op.model_dump(mode="json") for op in undo_ops),
            verify_probes=tuple(p.model_dump(mode="json") for p in verify_probes),
            ttl_seconds=ttl,
            runtime_identity=(
                fault.runtime_identity.key() if fault.runtime_identity is not None else None
            ),
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

        # Resource ownership tracking (ADR-0015)
        tracked_resource = None
        if self._resource_manager is not None:
            from mayhem.domain.leases import UndoOp, VerifyProbe  # noqa: PLC0415
            from mayhem.domain.resources import ResourceType  # noqa: PLC0415

            tracked_resource = self._resource_manager.register(
                resource_type=ResourceType.GENERIC,  # specific type inferred from fault_id
                run_id=plan.run_id,
                step_id=step.id,
                fault_id=fault.fault_id,
                target_identity=lease.runtime_identity or "|".join(sorted(lease.targets)),
                cleanup_op=UndoOp(op="lease.compensate", args={"lease_id": lease.id}),
                verify_probe=VerifyProbe(
                    probe="lease.verify",
                    args={"lease_id": lease.id},
                    expect_present=False,
                ),
            )

            # Phase 2.7: one-inflight-writer — reject if another lease holds
            # an active mutation on the same target.
            conflict_reason = self._resource_manager.check_no_inflight_writer(
                lease.runtime_identity or "|".join(sorted(lease.targets)),
                exclude_run_id=plan.run_id,
            )
            if conflict_reason is not None:
                self._client.mark_releasing(lease.id)
                self._client.confirm_release(lease.id, mechanism="resource_conflict")
                self._emit(
                    Event(
                        kind=EventKind.FAULT_FAILED,
                        run_id=plan.run_id,
                        detail={
                            "fault": fault.fault_id,
                            "lease": lease.id,
                            "status": "resource_conflict",
                            "reason": conflict_reason,
                        },
                    ),
                )
                # Transition tracked resource to DIRTY (cleanup failed)
                if tracked_resource is not None:
                    self._resource_manager.start_recovery(tracked_resource.id)
                    self._resource_manager.mark_recovered(tracked_resource.id, False)
                return (
                    StepReport(
                        step.id,
                        False,
                        f"{conflict_reason} (safe-aborted, no mutation)",
                        "resource_conflict",
                    ),
                    [],
                )

        executor = executor_for(fault.fault_id)
        # ADR-M2 Phase 2.3: revalidate the execution-time capability at the
        # mutation boundary. A mismatch (engine binary gone, tooling removed
        # since plan time) records `failed_to_apply`: no mutation, lease
        # released, run continues.
        if executor is not None:
            reason = executor.can_apply(lease)
            if reason is not None:
                self._client.mark_releasing(lease.id)
                self._client.confirm_release(lease.id, mechanism="failed_to_apply")
                self._emit(
                    Event(
                        kind=EventKind.FAULT_FAILED,
                        run_id=plan.run_id,
                        detail={
                            "fault": fault.fault_id,
                            "lease": lease.id,
                            "status": "failed_to_apply",
                            "reason": reason,
                        },
                    ),
                )
                if tracked_resource is not None:
                    self._resource_manager.start_recovery(tracked_resource.id)
                    self._resource_manager.mark_recovered(tracked_resource.id, False)
                return (
                    StepReport(
                        step.id,
                        False,
                        f"failed_to_apply: {reason} (safe-aborted, no mutation)",
                        "failed_to_apply",
                    ),
                    [],
                )

        inject_outcome = executor.inject(lease) if executor is not None else None
        self._record_tool_result(inject_outcome.tool_result if inject_outcome else None)

        # Phase 2.6: mutation-boundary journal — only after inject succeeds.
        # This is the exact moment the mutation actually happened (the last
        # undo-fallible op was applied). Carries the resource owner, the
        # mutation's defining op, and the lease reference.
        if (
            tracked_resource is not None
            and self._resource_manager is not None
            and inject_outcome is not None
            and inject_outcome.ok
        ):
            from mayhem.domain.leases import UndoOp as _UndoOp  # noqa: PLC0415

            self._resource_manager.journal_mutation(
                lease_id=lease.id,
                resource_id=tracked_resource.id,
                run_id=plan.run_id,
                step_id=step.id,
                fault_id=fault.fault_id,
                defining_op=_UndoOp(
                    op="inject",
                    args={
                        "fault_id": fault.fault_id,
                        "target": lease.runtime_identity or "|".join(sorted(lease.targets)),
                    },
                ),
                target_identity=lease.runtime_identity or "|".join(sorted(lease.targets)),
            )
        self._sleep_interruptible(float(fault.duration))

        # Functional-impact observation (FaultGateway): while the fault is
        # live, invert the recovery probe to capture whether the perturbation
        # actually took hold. Families whose probe cannot see the live state
        # (e.g. proc.pause — a STOPped process still answers ``kill -0``) are
        # recorded as inconclusive, never as inert.
        impact_observed: bool | None = None
        impact_note = ""
        if lease.verify_probes:
            live_report = verify_all(tuple(lease.verify_probes), lease.id)
            if fault.fault_id in OBSERVATION_BLIND:
                impact_observed = None
                impact_note = "probe-blind family: perturbation not visible to recovery probe"
            else:
                impact_observed = not live_report.all_satisfied
                impact_note = next((r.detail for r in live_report.results if not r.satisfied), "")
            self._emit(
                Event(
                    kind=EventKind.FAULT_OBSERVED,
                    run_id=plan.run_id,
                    detail={
                        "fault": fault.fault_id,
                        "lease": lease.id,
                        "impact_observed": impact_observed,
                        "note": impact_note,
                    },
                )
            )

        impact_part = (
            "impact observed"
            if impact_observed
            else "impact inconclusive (probe-blind)"
            if impact_observed is None
            else "no impact observed by recovery probe"
        )

        if not fault.recovery:
            # recovery: false — keep the perturbation in place on purpose. The
            # undo contract is deliberately NOT executed: the container stays
            # faulted so downstream check steps (and the operator) observe
            # whether the stack self-heals. The lease is terminally released
            # with an explicit mechanism, never marked dirty.
            inject_ok = inject_outcome is None or inject_outcome.ok
            still = verify_all(tuple(lease.verify_probes), lease.id)
            self._client.mark_releasing(lease.id)
            self._client.confirm_release(lease.id, mechanism="kept_faulted")
            self._record_recovery(
                lease.id,
                mechanism="kept_faulted",
                undo_results_json=json.dumps(
                    {
                        "inject": (inject_outcome.detail if inject_outcome else "no-executor"),
                        "undo": "skipped (recovery: false)",
                        "impact_observed": impact_observed,
                        "impact_note": impact_note,
                        "still_faulted_after_duration": not still.all_satisfied,
                    }
                ),
                verified=False,
                runtime_identity=lease.runtime_identity,
            )
            if tracked_resource is not None and self._resource_manager is not None:
                self._resource_manager.mark_recovered(tracked_resource.id, verified=False)
            detail = (
                f"{fault.fault_id} injected; recovery disabled (recovery: false), "
                f"container left faulted — {impact_part}"
            )
            return StepReport(step.id, inject_ok, detail), []

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
        self._record_recovery(
            lease.id,
            mechanism="executor",
            undo_results_json=json.dumps(
                {
                    "inject": (inject_outcome.detail if inject_outcome else "no-executor"),
                    "undo": undo_outcome.detail if undo_outcome else "no-executor",
                    "impact_observed": impact_observed,
                    "impact_note": impact_note,
                }
            ),
            verified=verified,
            runtime_identity=lease.runtime_identity,
        )

        if undo_ok and verified:
            self._client.confirm_release(lease.id, mechanism="normal")
            self._emit(
                Event(
                    kind=EventKind.FAULT_RECOVERED,
                    run_id=plan.run_id,
                    detail={"fault": fault.fault_id, "lease": lease.id},
                )
            )
            # Update resource state after successful recovery
            if tracked_resource is not None and self._resource_manager is not None:
                self._resource_manager.mark_recovered(tracked_resource.id, verified=True)
            detail = (
                "; ".join([*detail_parts, impact_part]) or f"{fault.fault_id} injected+recovered"
            )
            return StepReport(step.id, inject_ok, detail), []

        # Recovery failed — mark resource as dirty
        if tracked_resource is not None and self._resource_manager is not None:
            self._resource_manager.mark_recovered(tracked_resource.id, verified=False)
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

    def _resolve_live_pids(self, fault: PlannedFault) -> dict[str, int]:
        """Map node_id → freshly resolved host PID via the container engine.

        Only nodes that carry a container_name are resolved. Resolution is
        best-effort: nodes without a live container are skipped so a stale
        topology never blocks the run (ADR-0020).

        The container name is captured alongside so downstream container-mode
        executors can address the process *inside* its container (podman/docker
        ``exec``) rather than via a host PID — required when the container
        runtime lives in a detached VM (e.g. podman-machine on macOS).
        """
        return {key: value[0] for key, value in self._resolve_live_targets(fault).items()}

    def _resolve_live_targets(self, fault: PlannedFault) -> dict[str, tuple[int, str]]:
        """Map node_id → ``(host_pid, container_name)`` for live container runs.

        The live ``ProcessRuntimeIdentity`` of every resolved node is captured
        into ``self._resolved_process_identities`` at the same instant, giving
        the PID-reuse guard a boot-time baseline (ADR-M2 Phase 2.4).
        """
        if self._live_graph is None:
            return {}
        graph = self._live_graph()
        from mayhem.domain.topology import ContainerNode, ProcessNode  # noqa: PLC0415

        resolved: dict[str, tuple[int, str]] = {}
        node_pool: set[str] = set()
        for target in fault.targets:
            node_pool.update(target.node_ids)
        # The undo contract may reference a compensation node (e.g. the process
        # node under a service target) rather than the fault's kind-gated
        # targets; resolve those placeholders too so payload executors get a
        # live cont/engine address (ADR-0020).
        for op in fault.undo_ops:
            for value in op.args.values():
                if isinstance(value, str) and _LIVE_PID in value:
                    node_pool.add(value.split(":", 1)[0])
        process_ids: dict[str, ProcessRuntimeIdentity] = {}
        for node_id in node_pool:
            node = graph.by_id(node_id)
            container_name: str | None = None
            if isinstance(node, (ContainerNode, ProcessNode)):
                container_name = node.container_name
            if not container_name:
                continue
            try:
                info = resolve_container(container_name, self._engine)
            except RuntimeError:
                # VM-contained engines (podman-machine on macOS, Docker Desktop)
                # report State.Pid == 0 while the container is running: the host
                # PID is simply unreachable, but the container stays addressable
                # via <engine> exec (ADR-0020). Degrade to the sentinel pid when
                # the container is verified running instead of dropping the
                # target and failing every exec-addressed fault on the stack.
                try:
                    if resolve_status(container_name, self._engine) != "running":
                        continue
                except RuntimeError:
                    continue
                # Exec addressing signals the container, never a numeric pid, so
                # there is no boot-time identity to capture (and none possible:
                # sentinel pid 0 has no /proc entry).
                resolved[node_id] = (_PID_UNAVAILABLE, container_name)
                continue
            resolved[node_id] = (info.pid, container_name)
            process_ids[node_id] = resolve_process_identity(
                info.pid,
                host_id=self._host_id(),
                container_name=container_name,
            )
        self._resolved_process_identities = process_ids
        return resolved

    def _detect_target_drift(
        self,
        step: PlannedStep,
        fault: PlannedFault,
        live_targets: Mapping[str, tuple[int, str]],
    ) -> str | None:
        """ADR-M2-3 — compare the live RuntimeIdentity to the planned one, and
        guard against PID reuse (ADR-M2 Phase 2.4).

        Returns a human-readable drift reason (no mutation may proceed) or
        ``None`` when the target still matches what was planned.
        """
        planned = fault.runtime_identity
        if planned is not None:
            # The planned identity is keyed to the container node among the
            # fault's targets; find that node in the live graph to get its
            # container name.
            container_name: str | None = None
            if self._live_graph is not None:
                graph = self._live_graph()
                from mayhem.domain.topology import ContainerNode  # noqa: PLC0415

                for target in fault.targets:
                    for node_id in target.node_ids:
                        node = graph.by_id(node_id)
                        if isinstance(node, ContainerNode) and node.container_name:
                            container_name = node.container_name
                            break
                    if container_name:
                        break
            if container_name is not None:
                try:
                    live = resolve_identity(container_name, self._engine)
                except RuntimeError:
                    return (
                        f"TARGET_DRIFT: container {container_name!r} unreachable at "
                        "execution time (planned identity no longer resolvable)"
                    )
                if (live.runtime_id, live.host_id) != (
                    planned.runtime_id,
                    planned.host_id,
                ):
                    return (
                        f"TARGET_DRIFT: {container_name!r} recreated — planned "
                        f"{planned.runtime_id} vs live {live.runtime_id}"
                    )
        # PID-reuse guard (ADR-M2 Phase 2.4): the process identity captured at
        # target resolution (boot time + pid) must still hold at the mutation
        # boundary. A short-lived process can exit and its PID be recycled in
        # this window — boot time disambiguates the interloper. Runs even when
        # no container identity was planned (plain host-process targets).
        for node_id, baseline in self._resolved_process_identities.items():
            if baseline.boot_time is None:
                continue  # platform exposes no procfs start time; degrade.
            try:
                now = resolve_process_identity(
                    baseline.pid,
                    host_id=self._host_id(),
                    container_name=baseline.container_name,
                )
            except (RuntimeError, OSError):
                return (
                    f"TARGET_DRIFT: pid {baseline.pid} unreachable at execution "
                    "time (process exited; cannot revalidate identity)"
                )
            if now.boot_time is not None and now.boot_time != baseline.boot_time:
                return (
                    f"TARGET_DRIFT: pid {baseline.pid} recycled — boot time "
                    f"{baseline.boot_time} vs live {now.boot_time}"
                )
        return None

    def _host_id(self) -> str:
        """Stable host id for process identities (ADR-M2 Phase 2.4)."""
        if self._engine:
            return f"h-{self._engine}-local"
        return "h-local"

    def _route_http_probe(self, url: str, expected: int) -> VerifyProbe:
        """Return an HTTP :class:`VerifyProbe`, routed through the engine when
        the URL host names a running container.

        Drill checks name compose services (e.g. ``http://testcase-api:8080/``)
        which resolve only inside the container network and are not routable
        from the host (podman-machine sits behind a NAT). When the host is a
        live container, rewrite the probe into an ``<engine> exec`` that runs
        the HTTP request inside the container against ``127.0.0.1:port``,
        bridging the host/VM boundary. Unmatched or unresolvable hosts keep a
        plain on-host HTTP probe.
        """
        from mayhem.domain.leases import VerifyProbe  # noqa: PLC0415

        parts = None
        host = None
        try:
            parts = urlsplit(url)
            host = parts.hostname
        except ValueError:
            parts = None
        container = False
        if host and self._engine:
            try:
                resolve_container(host, self._engine)
                container = True
            except Exception:
                container = False
        if not container:
            return VerifyProbe(
                probe="http",
                args={"url": url, "expect_status": expected, "timeout_s": "5"},
                expect_present=True,
            )
        port = parts.port or (443 if parts.scheme == "https" else 80)
        code = (
            "import urllib.request,sys;"
            f"r=urllib.request.urlopen('http://127.0.0.1:{port}/',timeout=5);"
            f"print('HTTP', r.status);"
            f"sys.exit(0 if r.status=={expected} else 1)"
        )
        return VerifyProbe(
            probe="exec",
            args={
                "cmd": [self._engine, "exec", host, "python", "-c", code],
                "timeout_s": "10",
            },
            expect_present=True,
        )

    def _execute_check(self, step: PlannedStep) -> StepReport:
        ref = getattr(step.raw_action, "ref", "")
        check = self._checks.get(ref)
        if check is None:
            return StepReport(step.id, False, f"check {ref!r} not compiled into engine")
        verify = probe_to_verify(check.probe)
        if verify is not None and verify.probe == "http" and verify.args.get("url"):
            expected = verify.args.get("expect_status", 200)
            if not isinstance(expected, int):
                expected = 200
            verify = self._route_http_probe(str(verify.args["url"]), expected)
        result = run_probe(verify)
        passed = result.satisfied
        return StepReport(step.id, passed, f"{ref}: {'pass' if passed else result.detail}")

    def _execute_check_http(self, step: PlannedStep) -> StepReport:
        """Run an inline :class:`CheckHttp` step (drill plans) against a live URL."""

        url = getattr(step.raw_action, "url", "")
        expected = getattr(step.raw_action, "expected_status", None)
        if not url:
            return StepReport(step.id, False, "check_http step missing url")
        verify = self._route_http_probe(url, int(expected) if expected is not None else 200)
        started = time.monotonic()
        result = run_probe(verify)
        latency_ms = round((time.monotonic() - started) * 1000, 3)
        measured: dict[str, object] = {"latency_ms": latency_ms}
        status = _probe_status_from_detail(result.detail)
        if status is not None:
            measured["status"] = status
        elif result.satisfied and isinstance(expected, int):
            measured["status"] = expected  # probe contract: satisfied ⇒ status == expected
        return StepReport(step.id, result.satisfied, f"{url}: {result.detail}", measured=measured)

    def _execute_check_spec(self, step: PlannedStep) -> StepReport:
        """Evaluate a :class:`CheckSpecStep` at its declared execution locus.

        An explicit ``execution`` locus wins; a bare (unset) locus is inferred
        from the fault target (``CheckLocus.CONTAINER`` when the target names a
        container, else ``HOST``), preserving pre-0.3.0 behaviour (ADR-M4-2).
        Container/service-locus checks run inside the resolved container; host
        and process-locus checks run against the host.
        """
        action = step.raw_action
        probe = getattr(action, "probe", None)
        if probe is None:
            return StepReport(step.id, False, "check_spec step missing probe")
        check_locus = getattr(action, "execution", None) or self._infer_check_locus(
            getattr(action, "target", None)
        )
        verify = probe_to_verify(probe)
        if check_locus in (CheckLocus.CONTAINER, CheckLocus.SERVICE):
            verify = self._container_scope_verify(verify, action)
        elif check_locus is CheckLocus.PROCESS:
            pid = getattr(probe, "pid", None)
            if pid is None:
                return StepReport(step.id, False, "process check at process locus requires a pid")
        started = time.monotonic()
        result = run_probe(verify)
        latency_ms = round((time.monotonic() - started) * 1000, 3)
        measured: dict[str, object] = {"passed": result.satisfied, "latency_ms": latency_ms}
        if verify.probe == "http":
            status = _probe_status_from_detail(result.detail)
            if status is not None:
                measured["status"] = status
        return StepReport(
            step.id,
            result.satisfied,
            f"{check_locus.value}:{getattr(probe, 'type', 'check')} -> {result.detail}",
            measured=measured,
        )

    def _criteria_verdict(
        self,
        plan: ExecutionPlan,
        reports: Sequence[StepReport],
        status: str,
    ) -> tuple[RunVerdict | None, CriteriaEvaluation | None]:
        """Derive the drill's machine verdict from its success criteria (ADR-M4-3).

        A verdict is only ever derived for a run that actually *completed*; an
        aborted/failed run leaves the verdict undecided (None) even when some
        observations would satisfy criteria — partial evidence is not success.
        Absent or empty criteria also yield no verdict (existing behaviour).
        """
        if plan.success is None or plan.success.empty or status != "completed":
            return None, None
        observations: dict[str, Observation] = {}
        for report in reports:
            for observation in observations_for_step(
                report.step_id, ok=report.ok, measured=report.measured, detail=report.detail
            ):
                observations[observation.source_id] = observation
        evaluation = evaluate_criteria(plan.success, observations)
        verdict = RunVerdict.PASS if evaluation.all_satisfied else RunVerdict.FAIL
        self._emit(
            Event(
                kind=EventKind.CRITERIA_EVALUATED,
                run_id=plan.run_id,
                detail={
                    "verdict": verdict.value,
                    "all_satisfied": evaluation.all_satisfied,
                    "results": [r.model_dump() for r in evaluation.results],
                },
            )
        )
        return verdict, evaluation

    def _infer_check_locus(self, target: str | None) -> CheckLocus:
        """Infer a bare check's locus from its fault target (ADR-M4-2)."""

        if target:
            return CheckLocus.CONTAINER
        return CheckLocus.HOST

    def _container_scope_verify(self, verify: VerifyProbe, action: object) -> VerifyProbe:
        """Re-target a probe into the resolved container for container/service loci.

        ``engine``/``cont``/``incontainer`` let the exec/process/file runners
        address the container main process across the host/VM boundary instead of
        a host ``ps``/``cat``.
        """
        container_name = getattr(action, "target", None)
        if not container_name or not self._engine:
            return verify
        try:
            info = resolve_container(container_name, self._engine)
        except Exception:
            return verify.model_copy(
                update={"args": {**verify.args, "cont": container_name, "engine": self._engine}}
            )
        args = dict(verify.args)
        if verify.probe == "http" and args.get("url"):
            raw_status = args.get("expect_status", 200)
            expected_status = raw_status if isinstance(raw_status, int) else 200
            return self._route_http_probe(str(args["url"]), expected_status)
        args["engine"] = self._engine
        args["cont"] = container_name
        args["incontainer"] = True
        args["pid"] = info.pid
        return verify.model_copy(update={"args": args})

    def _open_run(self, plan: ExecutionPlan) -> None:
        """Atomically commit the topology fork + plan pair (Phase 2.8).

        The run row, the config snapshot, the topology snapshot, and the fork
        staging record all land (or all roll back) inside a single SQLite
        transaction.  A crash before commit leaves nothing — the run is
        discarded.  A crash after commit leaves the pair durable.  The staging
        row records the commit phase so ``cleanup_orphaned_forks`` can find
        snapshot-only writes and reconcile them at next startup.
        """
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
                    status, environment_fingerprint, config_snapshot_id, started_at,
                    governing_decisions_json, controller_pid)
                VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?)
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
                    json.dumps([d.model_dump() for d in plan.decision_refs]),
                    os.getpid(),
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
            # Fork staging marker (Phase 2.8): plan + fork committed atomically.
            conn.execute(
                "INSERT OR REPLACE INTO run_fork_staging "
                "(run_id, topo_id, phase, created_at, committed_at) "
                "VALUES (?, ?, 'committed', ?, ?)",
                (plan.run_id, topo_id, now_iso, now_iso),
            )

    def cleanup_orphaned_forks(self) -> list[str]:
        """Reconcile fork/plan pairs at startup (Phase 2.8).

        Removes any topology snapshot that is durable but has no corresponding
        run — i.e. the fork was written but the plan commit never landed (a
        crash between the two).  Returns the run ids whose orphaned forks were
        dropped.
        """
        with self._store.write() as conn:
            conn.execute(
                "DELETE FROM topology_snapshots "
                "WHERE id NOT IN (SELECT COALESCE(topology_snapshot_id, '') FROM runs)"
            )
            conn.execute("DELETE FROM run_fork_staging WHERE phase = 'planning'")
        return []

    def _collect_observability(self, plan: ExecutionPlan) -> tuple[SourceCollection, ...]:
        """Collect declared observability sources into evidence (ADR-M4-4).

        Best-effort and bounded: each source has its own timeout and the whole
        pass respects total_timeout. A failing source is recorded as a failed
        collection — never raised — so evidence gathering cannot break the run.
        """
        if plan.observability is None or plan.observability.empty:
            return ()
        return collect_observability(plan.observability, engine=self._engine or "podman")

    def _spool_observability_events(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        collections: tuple[SourceCollection, ...],
    ) -> None:
        """Journal each collected source (ADR-M4-4: the journal is the source)."""
        for collection in collections:
            kind = (
                EventKind.OBSERVABILITY_SOURCE_FAILED
                if not collection.ok and not collection.skipped
                else EventKind.OBSERVABILITY_COLLECTED
            )
            conn.execute(
                "INSERT INTO events (run_id, ts, kind, payload_json) VALUES (?, ?, ?, ?)",
                (
                    run_id,
                    utc_now().isoformat(),
                    kind.value,
                    json.dumps(collection.to_jsonable()),
                ),
            )

    def _close_run(
        self,
        run_id: str,
        status: str,
        ended_epoch_s: float,
        *,
        verdict: RunVerdict | None = None,
        evaluation: CriteriaEvaluation | None = None,
        observability: tuple[SourceCollection, ...] = (),
    ) -> None:
        ended_iso = datetime.fromtimestamp(ended_epoch_s, tz=UTC).isoformat()
        criteria_json = evaluation.model_dump_json() if evaluation is not None else None
        observability_json = (
            json.dumps([c.to_jsonable() for c in observability]) if observability else None
        )
        with self._store.write() as conn:
            conn.execute(
                "UPDATE runs SET status = ?, ended_at = ?, verdict = ?, criteria_json = ?,"
                " observability_json = ?"
                " WHERE id = ?",
                (
                    status,
                    ended_iso,
                    verdict.value if verdict is not None else None,
                    criteria_json,
                    observability_json,
                    run_id,
                ),
            )
            self._spool_observability_events(conn, run_id, observability)

    def _insert_step(self, run_id: str, step: PlannedStep) -> None:
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO step_runs (id, run_id, seq, parent_step_id,
                    action_type, action_json, status, runtime_identity,
                    execution_group_id, group_mode, group_path)
                VALUES (?, ?, ?, NULL, ?, ?, 'running', ?, ?, ?, ?)
                """,
                (
                    f"{step.seq:04d}-{step.id}",
                    run_id,
                    step.seq,
                    type(step.raw_action).__name__,
                    step.raw_action.model_dump_json(),
                    (step.runtime_identity.key() if step.runtime_identity is not None else None),
                    step.execution_group_id,
                    step.group_mode.value if step.group_mode is not None else None,
                    step.group_path,
                ),
            )

    def _finish_step(self, step: PlannedStep, *, ok: bool, status: str | None = None) -> None:
        value = status or ("completed" if ok else "failed")
        with self._store.write() as conn:
            conn.execute(
                "UPDATE step_runs SET status = ?, ended_at = ? WHERE id = ?",
                (
                    value,
                    utc_now().isoformat(),
                    f"{step.seq:04d}-{step.id}",
                ),
            )

    def _record_invocation(
        self,
        plan: ExecutionPlan,
        step: PlannedStep,
        fault: PlannedFault,
        lease_id: str,
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
        self,
        lease_id: str,
        *,
        mechanism: str,
        undo_results_json: str,
        verified: bool,
        runtime_identity: str | None = None,
    ) -> None:
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT INTO recovery_records
                    (id, lease_id, attempt, mechanism, undo_results_json, verified, at,
                     runtime_identity)
                VALUES (?, ?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    f"rec-{uuid.uuid4().hex[:12]}",
                    lease_id,
                    mechanism,
                    undo_results_json,
                    int(verified),
                    utc_now().isoformat(),
                    runtime_identity,
                ),
            )

    def _record_tool_result(self, tool_result: ToolResult | None) -> None:
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
        # Observer callbacks must never break the run (ADR-0009: the journal is
        # the source of truth; a live renderer is a best-effort projection).
        if self._on_event is not None:
            with contextlib.suppress(Exception):
                self._on_event(event)


class _AbortMatrix:
    """Arms the SIGINT/SIGUSR1 escalation ladder (ADR-M2 Phase 2.5).

    * SIGINT  — request ``grace``; a second SIGINT escalates to ``term``, a
      third to ``kill``. Operators press again if the run does not stop.
    * SIGUSR1 — jump straight to ``kill`` (immediate stop).
    The ladder level is enforced the next time the agent loop checks the
    cancellation token.
    """

    def __init__(self, engine: RunEngine, run_id: str) -> None:
        self._engine = engine
        self._run_id = run_id
        self._previous: dict[int, object] = {}

    def __enter__(self) -> _AbortMatrix:
        for signum, target in (
            (signal.SIGINT, CancellationLevel.GRACE),
            (signal.SIGUSR1, CancellationLevel.KILL),
        ):
            with contextlib.suppress(ValueError, OSError):  # non-main thread / unsupported platform
                self._previous[signum] = signal.signal(signum, self._make_handler(target))
        return self

    def __exit__(self, *exc_info: object) -> None:
        for signum, previous in self._previous.items():
            with contextlib.suppress(ValueError, OSError):
                signal.signal(signum, previous)  # type: ignore[arg-type]
        self._engine._abort_mode = None

    def _make_handler(self, target: CancellationLevel) -> Callable[[int, object], None]:
        def handler(signum: int, frame: object) -> None:
            del signum, frame
            token = self._engine._cancellation
            if target == CancellationLevel.GRACE:
                token.escalate()  # grace -> term -> kill on repeated presses
                effective = token.level
            else:
                effective = token.request(CancellationLevel.KILL)
                effective = CancellationLevel.KILL
            with contextlib.suppress(Exception):
                self._engine._emit(
                    Event(
                        kind=EventKind.RUN_ABORT_REQUESTED,
                        run_id=self._run_id,
                        detail={"mode": str(effective)},
                    )
                )

        return handler
