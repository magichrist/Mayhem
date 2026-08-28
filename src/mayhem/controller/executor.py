"""RunEngine — executes a frozen ExecutionPlan against real executors.

The engine owns every durable artifact of a run: runs/step_runs rows,
fault_invocations, recovery_records, and the event journal. Lease lifecycles
go through the LeaseClient so no state transition bypasses the domain rules.
"""

from __future__ import annotations

import contextlib
import json
import signal
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, assert_never
from urllib.parse import urlsplit

from mayhem.agents.executors import executor_for
from mayhem.agents.impact import OBSERVATION_BLIND
from mayhem.agents.lease_client import LeaseClient
from mayhem.agents.probes import run_probe, verify_all
from mayhem.controller.resource_manager import ResourceManager
from mayhem.controller.safety import pre_exec_assertion, validate_plan
from mayhem.domain.checks import ProbeType
from mayhem.domain.common import utc_now
from mayhem.domain.events import Event, EventKind
from mayhem.domain.leases import LeaseState, UndoOp, VerifyProbe
from mayhem.topology.resolve import resolve_container

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from pathlib import Path

    from mayhem.agents.sinks import LeaseSink
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.checks import Probe, SteadyStateCheck
    from mayhem.domain.experiments import ExecutionPlan, PlannedFault, PlannedStep
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.store import Store
    from mayhem.toolkit.tool_runner import ToolResult


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


# Placeholder PID emitted by compensation templates; replaced with the live PID
# at execution time (ADR-0020), so the value is never older than the syscall.
_LIVE_PID = "@live-pid"


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

    new_undo = tuple(
        UndoOp(
            op=op.op,
            args={**{k: _swap(v) for k, v in op.args.items()}, **_address(_resolved_node(op))},
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
                        break  # on_failure defaults to abort_and_recover; later steps cancelled
                else:
                    batch_reports, lease_dirty = self._run_parallel(plan, group)
                    reports.extend(batch_reports)
                    dirty.extend(lease_dirty)
                    if not all(r.ok for r in batch_reports):
                        status = "failed"
                        break
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
                kind=(EventKind.STEP_FINISHED if report.ok else EventKind.STEP_SKIPPED),
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
        # Resolve fresh PIDs at execution time (ADR-0020): the PID baked into the plan is
        # a placeholder, never older than the injection syscall. Substitute the live value
        # into the undo contract + verify probes before the lease forms.
        live_targets = self._resolve_live_targets(fault)
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
                target_identity=lease.target_id,
                cleanup_op=UndoOp(op="lease.compensate", args={"lease_id": lease.id}),
                verify_probe=VerifyProbe(
                    probe="lease.verify",
                    args={"lease_id": lease.id},
                    expect_present=False,
                ),
            )
            self._resource_manager.activate(tracked_resource.id)

        executor = executor_for(fault.fault_id)
        inject_outcome = executor.inject(lease) if executor is not None else None
        self._record_tool_result(inject_outcome.tool_result if inject_outcome else None)
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
                impact_note = next(
                    (r.detail for r in live_report.results if not r.satisfied), ""
                )
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
            detail = "; ".join([*detail_parts, impact_part]) or f"{fault.fault_id} injected+recovered"
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
        resolved = {key: value[0] for key, value in self._resolve_live_targets(fault).items()}
        return resolved

    def _resolve_live_targets(self, fault: PlannedFault) -> dict[str, tuple[int, str]]:
        """Map node_id → ``(host_pid, container_name)`` for live container runs."""
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
                continue
            resolved[node_id] = (info.pid, container_name)
        return resolved

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
        verify = _domain_probe_to_verify(check.probe)
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
        result = run_probe(verify)
        return StepReport(step.id, result.satisfied, f"{url}: {result.detail}")

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


def _domain_probe_to_verify(probe: Probe) -> VerifyProbe:
    """Map a domain checks.Probe onto the agents VerifyProbe runner."""
    if probe.type is ProbeType.EXEC:
        return VerifyProbe(
            probe="exec",
            args={"cmd": list(probe.cmd), "timeout_s": float(probe.timeout)},
            expect_present=True,
        )
    if probe.type is ProbeType.TCP:
        return VerifyProbe(
            probe="tcp",
            args={
                "host": probe.host,
                "port": int(probe.port),
                "timeout_s": float(probe.timeout),
            },
            expect_present=True,
        )
    if probe.type is ProbeType.HTTP:
        return VerifyProbe(
            probe="http",
            args={
                "url": probe.url,
                "expect_status": int(probe.expected_status),
                "timeout_s": float(probe.timeout),
            },
            expect_present=True,
        )
    assert_never(probe)  # exhaustive over the Probe union


class _AbortMatrix:
    """Arms SIGINT (graceful, second signal escalates) and SIGUSR1 (immediate)."""

    def __init__(self, engine: RunEngine, run_id: str) -> None:
        self._engine = engine
        self._run_id = run_id
        self._previous: dict[int, object] = {}

    def __enter__(self) -> _AbortMatrix:
        for signum, mode in (
            (signal.SIGINT, "graceful"),
            (signal.SIGUSR1, "immediate"),
        ):
            with contextlib.suppress(ValueError, OSError):  # non-main thread / unsupported platform
                self._previous[signum] = signal.signal(signum, self._make_handler(mode))
        return self

    def __exit__(self, *exc_info: object) -> None:
        for signum, previous in self._previous.items():
            with contextlib.suppress(ValueError, OSError):
                signal.signal(signum, previous)  # type: ignore[arg-type]
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
            with contextlib.suppress(Exception):
                self._engine._emit(
                    Event(
                        kind=EventKind.RUN_ABORT_REQUESTED,
                        run_id=self._run_id,
                        detail={"mode": effective},
                    )
                )

        return handler
