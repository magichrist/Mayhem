"""Plan 13 Phase 2 — the durable scheduler over the campaign engine.

Phase 1 proved the *decisions* (``tests/unit/test_scheduling.py``). This proves
the *service* that acts on them, and the properties under test are the ones a
scheduler can quietly lose:

* **the fire decision is real.** Every refusal is checked against the actual
  :class:`~mayhem.domain.scheduling.FireCode` the domain produced, at the fire
  instant — a maintenance window that opened *after* registration, a blackout
  date, a closed horizon. Windows are read live, which is the difference between
  a schedule and a wish;
* **fairness governs dispatch order**, and the guarantee is proved by *removal*:
  the starvation tier and the FIFO tiebreak are deleted from the policy and the
  bound is watched to break. Restating a promise is not evidence;
* **two conflicting experiments serialize**, and the queue message names the
  lock owner because the owner is in the state the second run is compared
  against, not in a message somebody remembered to write;
* **a restart does not double-fire**, and that is a drill: the store is closed,
  a second controller is built over the same database file, and the same slot is
  offered again. The claim ledger's primary key is the mechanism, and one test
  shows a raw duplicate INSERT failing rather than trusting the wrapper;
* **a scheduled run is not a privileged run.** The pipeline's gates are bound to
  the *real* ``validate_plan`` and ``verify_approvals`` in the bypass tests, so
  "schedules skip admission" is not a thing this service is able to express.

The negative controls are the ones that would let a scheduler misbehave
quietly: firing through an active incident, running into a deployment freeze,
executing past a facilitator hold, and a non-fire with no recorded reason.
"""

from __future__ import annotations

import ast
import sqlite3
import tokenize
from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.approval_gate import (
    ApprovalGateInputs,
    candidate_plan_digest,
    verify_approvals,
)
from mayhem.controller.safety import SafetyContext, validate_plan
from mayhem.controller.scheduler import (
    DEFAULT_FAIRNESS,
    CommanderOverride,
    DeploymentState,
    DispatchCode,
    DispatchPipeline,
    DueSchedule,
    ExecutionReceipt,
    GateVerdict,
    IncidentState,
    PlannedDispatch,
    Scheduler,
    SchedulerInputs,
    mark_dispatched,
    order_by_fairness,
    release_hold,
    slot_idempotency_key,
    slot_run_id,
)
from mayhem.domain.approval import Approval
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.game_day import GameDaySession, OperatorAcknowledgement
from mayhem.domain.hashing import digest
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    Role,
    RoleGrant,
)
from mayhem.domain.safety_proof import (
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    SafetyProof,
)
from mayhem.domain.scheduling import (
    BlackoutDates,
    BusinessHours,
    ConcurrencyClass,
    ConcurrencyRequest,
    CronSpec,
    DailyWindow,
    FairnessPolicy,
    FireCode,
    FireDecision,
    GrantRecord,
    IntervalSpec,
    MaintenanceWindow,
    Schedule,
    ScheduleKind,
    longest_skip_runs,
)
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.infra.game_day_repository import GameDayRepository
from mayhem.infra.schedule_store import (
    GameDayStepRecord,
    HoldState,
    RunClaimState,
    ScheduleEntry,
    ScheduleRunRecord,
    ScheduleStore,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEDULER_MODULE = REPO_ROOT / "src" / "mayhem" / "controller" / "scheduler.py"

T0 = datetime(2026, 6, 1, 9, 0, tzinfo=UTC)
BEFORE_T0 = T0 - timedelta(days=1)
HOUR = 3600.0
NY = ZoneInfo("America/New_York")
INCIDENT = "inc-4417"

#: 2026-06-01 is a Monday, which is what makes the office-hours rows below
#: ordinary weekdays rather than a special case.
OPERATOR = Principal(principal_id="u-operator", display_name="Operator")
POLICY_DIGEST = digest({"bundle": "sched", "version": 1})


# =============================================================================
# Fixtures-as-values: every test builds its own, so order cannot matter
# =============================================================================


def _store(path: str | Path = ":memory:") -> tuple[Store, ScheduleStore]:
    """A migrated store plus its schedule repository."""
    store = Store.open_migrated(path)
    return store, ScheduleStore(store)


def _interval_entry(
    *,
    schedule_id: str = "poller",
    team: str = "sre",
    campaign_id: str = "camp-1",
    experiment_id: str = "exp-1",
    every_s: float = HOUR,
    anchor_at: datetime = T0,
    concurrency_class: ConcurrencyClass = ConcurrencyClass.EXCLUSIVE,
    resources: tuple[str, ...] = ("db-primary",),
    max_runs: int | None = 10_000,
    poll_resolution_s: float = HOUR,
    enabled: bool = True,
    business_hours: BusinessHours | None = None,
    maintenance_windows: tuple[MaintenanceWindow, ...] = (),
    blackout_dates: BlackoutDates | None = None,
    ends_at: datetime | None = None,
) -> ScheduleEntry:
    return ScheduleEntry(
        schedule=Schedule(
            schedule_id=schedule_id,
            team=team,
            kind=ScheduleKind.INTERVAL,
            interval=IntervalSpec(every_s=every_s, anchor_at=anchor_at),
            created_at=BEFORE_T0,
            max_runs=max_runs,
            poll_resolution_s=poll_resolution_s,
            business_hours=business_hours,
            maintenance_windows=maintenance_windows,
            blackout_dates=blackout_dates,
            ends_at=ends_at,
        ),
        campaign_id=campaign_id,
        experiment_id=experiment_id,
        concurrency_class=concurrency_class,
        resources=resources,
        enabled=enabled,
    )


def _cron_entry(
    *,
    schedule_id: str = "nightly",
    expression: str = "0 9 * * *",
    team: str = "sre",
    campaign_id: str = "camp-1",
    experiment_id: str = "exp-1",
    timezone_name: str = "UTC",
    business_hours: BusinessHours | None = None,
) -> ScheduleEntry:
    return ScheduleEntry(
        schedule=Schedule(
            schedule_id=schedule_id,
            team=team,
            kind=ScheduleKind.CRON,
            cron=CronSpec.parse(expression),
            timezone_name=timezone_name,
            created_at=BEFORE_T0,
            max_runs=10_000,
            business_hours=business_hours,
        ),
        campaign_id=campaign_id,
        experiment_id=experiment_id,
        resources=("db-primary",),
    )


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(ServiceNode(id="n-web", name="web"), ServiceNode(id="n-db", name="db")),
        edges=(Edge(src="n-web", dst="n-db", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
    )


def _plan(run_id: str = "run-scheduled", *, fingerprint: str = "fp") -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="web")
    step = PlannedStep(
        id="s0",
        seq=0,
        raw_action=InjectFault(fault="proc.pause", selectors=(selector,), duration=5.0),
        fault=PlannedFault(
            fault_id="proc.pause",
            targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-web"})),),
            duration=5.0,
        ),
    )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=(step,),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=fingerprint,
    )


def _safety_ctx(fingerprint: str = "fp") -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(max_services_pct=100.0),
        fingerprint=fingerprint,
    )


def _passing_proof(plan: ExecutionPlan) -> SafetyProof:
    obligations = tuple(
        Obligation(
            name=name,
            status=ObligationStatus.PASS,
            gate_digest=digest({"gate": name.value}),
            evidence_ref=f"evidence://{name.value}",
            evaluated_at=BEFORE_T0,
        )
        for name in ObligationName
    )
    return SafetyProof(
        plan_digest=candidate_plan_digest(plan),
        obligations=obligations,
        verdict=ProofVerdict.PASS,
        generated_at=BEFORE_T0,
    )


def _approval_inputs(
    plan: ExecutionPlan, *, approvals: tuple[Approval, ...] = ()
) -> ApprovalGateInputs:
    """The real plan-09 approval inputs, with real role grants.

    One principal holding both roles keeps the fixture short; separation of
    duties is off on these inputs by default, and plan 09's own suite is where
    the split-role matrix is proved. What matters here is that the gate is the
    real one, so a missing or non-matching approval really does refuse.
    """
    return ApprovalGateInputs(
        now=T0,
        environment=EnvironmentScope.any(),
        executor=OPERATOR,
        proof=_passing_proof(plan),
        policy_digest=POLICY_DIGEST,
        approvals=approvals,
        grants=tuple(
            RoleGrant(
                role=role,
                scope=EnvironmentScope.any(),
                granted_at=BEFORE_T0,
                principal=OPERATOR,
            )
            for role in (Role.APPROVE, Role.EXECUTE)
        ),
    )


def _real_gate(record: Recorder, call: str, **kwargs: Any) -> Any:
    """Bind one pipeline slot to a real controller gate."""

    def gate(request: Any, planned: PlannedDispatch) -> GateVerdict:
        record.calls.append(call)
        if call == "admission":
            validate_plan(planned.plan, _graph(), _safety_ctx(**kwargs))
        else:
            result = verify_approvals(planned.plan, _approval_inputs(planned.plan, **kwargs))
            if result.denied:
                refusal = result.refusal
                return GateVerdict(
                    passed=False,
                    reason=refusal.reason if refusal is not None else "denied",
                    rule_id=refusal.rule_id if refusal is not None else "",
                )
        return GateVerdict(passed=True, reason=f"{call} passed")

    return gate


@dataclass
class Recorder:
    """What the pipeline was actually asked to do, in order.

    Assertions about "the executor was never called" are made against this
    object rather than against a return value, because a gate that refuses
    *after* the executor ran would still return a refusal.
    """

    calls: list[str] = field(default_factory=list)
    run_ids: list[str] = field(default_factory=list)

    @property
    def executions(self) -> int:
        return self.calls.count("executor")


def _pipeline(
    recorder: Recorder | None = None,
    *,
    planner: Any = None,
    admission: Any = None,
    approver: Any = None,
    executor: Any = None,
) -> DispatchPipeline:
    """A pipeline of recording stubs, with every stage overridable per test.

    The default executor echoes the run id the scheduler derived from the slot's
    idempotency key, because that is what the real executor would return and
    because a refusal that has to name the holder is only checkable if the two
    sides agree on what the run is called.
    """
    log = recorder if recorder is not None else Recorder()

    def default_planner(request: Any) -> PlannedDispatch:
        log.calls.append("planner")
        return PlannedDispatch(
            plan=_plan(request.concurrency.run_id),
            plan_digest=digest({"plan": request.idempotency_key}),
        )

    def default_admission(request: Any, planned: PlannedDispatch) -> GateVerdict:
        log.calls.append("admission")
        return GateVerdict(passed=True, reason="admitted")

    def default_approver(request: Any, planned: PlannedDispatch) -> GateVerdict:
        log.calls.append("approver")
        return GateVerdict(passed=True, reason="approved")

    def default_executor(request: Any, planned: PlannedDispatch) -> ExecutionReceipt:
        log.calls.append("executor")
        log.run_ids.append(request.concurrency.run_id)
        return ExecutionReceipt(run_id=request.concurrency.run_id, outcome_id="out-1")

    return DispatchPipeline(
        planner=planner if planner is not None else default_planner,
        admission=admission if admission is not None else default_admission,
        approver=approver if approver is not None else default_approver,
        executor=executor if executor is not None else default_executor,
    )


def _scheduler(
    repo: ScheduleStore,
    *,
    pipeline: DispatchPipeline | None = None,
    fairness: FairnessPolicy | None = None,
    controller_id: str = "ctl-1",
) -> Scheduler:
    return Scheduler(
        store=repo,
        pipeline=pipeline if pipeline is not None else _pipeline(),
        fairness=fairness,
        controller_id=controller_id,
    )


def _inputs(now: datetime = T0, window_index: int = 0, **kwargs: Any) -> SchedulerInputs:
    return SchedulerInputs(now=now, window_index=window_index, **kwargs)


def _office_hours() -> BusinessHours:
    return BusinessHours(
        windows=(
            DailyWindow(
                label="office",
                days=frozenset({0, 1, 2, 3, 4}),
                start_time=time(9, 0),
                end_time=time(17, 0),
            ),
        )
    )


def _due(schedule_id: str, team: str, *, slot: datetime = T0) -> DueSchedule:
    """A fired schedule, without a store behind it."""
    fire = FireDecision(
        fired=True,
        code=FireCode.FIRED,
        reason="due",
        schedule_id=schedule_id,
        now=slot,
        slot_start=slot,
        effective_at=slot,
    )
    return DueSchedule(entry=_interval_entry(schedule_id=schedule_id, team=team), fire=fire)


# =============================================================================
# 1. The fire decision is real, and it is read at fire time
# =============================================================================


def test_a_due_schedule_dispatches_and_records_the_real_fire_code() -> None:
    store, repo = _store()
    recorder = Recorder()
    scheduler = _scheduler(repo, pipeline=_pipeline(recorder))
    scheduler.register(_interval_entry())

    report = scheduler.tick(_inputs())

    decision = report.for_schedule("poller")
    assert decision is not None
    assert decision.dispatched is True
    assert decision.code is DispatchCode.DISPATCHED
    assert decision.fire is not None
    assert decision.fire.code is FireCode.FIRED
    assert decision.fire.fired is True
    assert decision.fire.slot_start == T0
    assert decision.gates == ("admission", "approval", "execute")
    assert recorder.calls == ["planner", "admission", "approver", "executor"]
    store.close()


def test_a_schedule_outside_its_slot_is_recorded_as_not_due() -> None:
    """A quiet instant is recorded as quiet, with a reason.

    Probed five minutes *before* the schedule's anchor, so there is no occurrence
    in play at all and nothing has been missed. A tick that found no slot and
    reported nothing would leave an operator unable to distinguish "the scheduler
    is idle" from "the scheduler is broken".
    """
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry(poll_resolution_s=60.0, anchor_at=T0))

    report = scheduler.tick(_inputs(now=T0 - timedelta(minutes=5)))

    decision = report.for_schedule("poller")
    assert decision is not None
    assert decision.dispatched is False
    assert decision.code is None
    assert decision.fire is not None
    assert decision.fire.code is FireCode.NOT_DUE
    assert decision.fire.reason
    assert decision.schedule_code == FireCode.NOT_DUE.value
    store.close()


def test_a_recurrence_the_poller_slept_through_is_reported_as_missed() -> None:
    """Phase 4's acceptance criterion at the service layer, not just the domain.

    The tick is five minutes past a 60-second interval slot. The slot is gone, the
    next occurrence is an hour away and is a *different* slot with a different
    idempotency key, so this occurrence will never run. What the tick must not do
    is report that as success, or as an ordinary "not due" that reads like a quiet
    afternoon; what it must do is name the missed instant and the reason it cannot
    be retried.
    """
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry(poll_resolution_s=60.0))

    report = scheduler.tick(_inputs(now=T0 + timedelta(minutes=5)))

    decision = report.for_schedule("poller")
    assert decision is not None
    assert decision.dispatched is False
    assert decision.held is True
    assert decision.fire is not None
    assert decision.fire.code is FireCode.MISSED
    assert decision.fire.missed_window is True
    assert decision.fire.slot_start == T0
    assert decision.fire.fired is False
    assert decision.schedule_code == FireCode.MISSED.value
    assert T0.isoformat() in decision.fire.reason
    assert "idempotency key" in decision.fire.reason
    # Nothing was claimed: a missed slot is not a dispatch in progress.
    assert repo.runs_for_schedule("poller") == ()
    assert "MISSED" not in decision.describe() or decision.schedule_code in decision.describe()
    store.close()


def test_a_missed_recurrence_does_not_consume_a_slot_or_the_run_budget() -> None:
    """A missed window must not quietly spend the schedule's run budget.

    The budget exists to bound *dispatches*. If a miss decremented it, a schedule
    whose poller was down for a weekend would arrive on Monday with fewer runs
    left and nobody would be able to say why -- so the negative control is that
    the run count is untouched by a tick that dispatched nothing.
    """
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry(poll_resolution_s=60.0, max_runs=3))

    for offset in (1, 2, 3):
        scheduler.tick(_inputs(now=T0 + timedelta(minutes=offset), window_index=offset))

    entry = repo.load_schedule("poller")
    assert entry is not None
    assert entry.run_count == 0
    assert repo.dispatch_count("poller") == 0
    store.close()


def test_a_maintenance_window_opened_after_registration_refuses_at_fire_time() -> None:
    """The window is a *fire-time* gate, not a creation-time one.

    The schedule is registered with no windows at all, minutes before a change
    freeze opens over its slot. A gate read at creation would have passed; the
    scheduler asks at ``now`` and is refused.
    """
    store, repo = _store()
    scheduler = _scheduler(repo)
    entry = _interval_entry()
    assert entry.schedule.maintenance_windows == ()
    scheduler.register(entry)

    repo.save_schedule(
        _interval_entry(
            maintenance_windows=(
                MaintenanceWindow(
                    window_id="freeze-1",
                    starts_at=T0 - timedelta(minutes=5),
                    ends_at=T0 + timedelta(minutes=5),
                    reason="change freeze",
                ),
            )
        )
    )
    report = scheduler.tick(_inputs())

    decision = report.for_schedule("poller")
    assert decision is not None
    assert decision.fire is not None
    assert decision.fire.code is FireCode.MAINTENANCE
    assert decision.fire.blocked_by == ("maintenance:freeze-1",)
    assert "change freeze" in decision.reason
    assert decision.dispatched is False
    store.close()


def test_a_blackout_date_refuses_at_fire_time() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(
        _interval_entry(blackout_dates=BlackoutDates(dates=frozenset({T0.date()})))
    )

    decision = scheduler.tick(_inputs()).for_schedule("poller")

    assert decision is not None
    assert decision.fire is not None
    assert decision.fire.code is FireCode.BLACKOUT
    assert decision.fire.blocked_by == (f"blackout:{T0.date().isoformat()}",)
    store.close()


def test_business_hours_are_read_at_fire_time_not_at_creation() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(
        _interval_entry(
            schedule_id="night-shift",
            every_s=24 * HOUR,
            anchor_at=T0.replace(hour=23),
            business_hours=_office_hours(),
        )
    )

    # 23:00 is inside the interval's own slot and well outside the office band,
    # so the only gate that can refuse it is the live business-hours one.
    decision = scheduler.tick(_inputs(now=T0.replace(hour=23))).for_schedule("night-shift")

    assert decision is not None
    assert decision.fire is not None
    assert decision.fire.code is FireCode.OUTSIDE_BUSINESS_HOURS
    assert decision.fire.blocked_by == ("business_hours",)
    assert "09:00-17:00" in decision.reason
    store.close()


def test_a_cron_schedule_inside_its_business_hours_dispatches() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_cron_entry(business_hours=_office_hours()))

    report = scheduler.tick(_inputs())

    assert report.codes == (DispatchCode.DISPATCHED.value,)
    store.close()


def test_a_closed_horizon_refuses_with_the_expired_code() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(
        _interval_entry(
            anchor_at=T0 - timedelta(hours=5),
            max_runs=None,
            ends_at=T0 - timedelta(hours=1),
        )
    )

    decision = scheduler.tick(_inputs()).for_schedule("poller")

    assert decision is not None
    assert decision.fire is not None
    assert decision.fire.code is FireCode.EXPIRED
    assert decision.fire.blocked_by == ("ends_at",)
    store.close()


def test_the_run_budget_is_charged_from_the_durable_count() -> None:
    """``max_runs`` is enforced against the persisted count, not an in-memory one."""
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry(max_runs=1))

    first = scheduler.tick(_inputs(window_index=0))
    assert first.codes == (DispatchCode.DISPATCHED.value,)
    second = scheduler.tick(_inputs(now=T0 + timedelta(hours=1), window_index=1))

    decision = second.for_schedule("poller")
    assert decision is not None
    assert decision.fire is not None
    assert decision.fire.code is FireCode.EXHAUSTED
    assert decision.fire.blocked_by == ("max_runs",)
    stored = repo.load_schedule("poller")
    assert stored is not None
    assert stored.run_count == 1
    store.close()


def test_a_disabled_schedule_is_recorded_rather_than_silently_skipped() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry(enabled=False))

    decision = scheduler.tick(_inputs()).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.DISABLED
    assert "disabled" in decision.reason
    assert repo.list_schedules(enabled_only=True) == ()
    store.close()


def test_a_disabled_schedule_can_be_switched_back_on() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry(enabled=False))
    repo.set_enabled("poller", enabled=True)

    report = scheduler.tick(_inputs())

    assert report.codes == (DispatchCode.DISPATCHED.value,)
    store.close()


def test_every_non_fire_carries_a_code_and_a_reason() -> None:
    """No silent skips: a held decision always names why."""
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(
        _interval_entry(blackout_dates=BlackoutDates(dates=frozenset({T0.date()})))
    )
    scheduler.register(_interval_entry(schedule_id="switched-off", enabled=False))

    report = scheduler.tick(_inputs())

    assert len(report.held) == 2
    assert set(report.codes) == {FireCode.BLACKOUT.value, DispatchCode.DISABLED.value}
    for decision in report.decisions:
        assert decision.schedule_code
        assert decision.reason
    store.close()


def test_a_non_fire_is_recorded_in_the_durable_tick_observation() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo, controller_id="ctl-observer")
    scheduler.register(
        _interval_entry(blackout_dates=BlackoutDates(dates=frozenset({T0.date()})))
    )

    scheduler.tick(_inputs())

    rows = store.query(
        "SELECT data_json, source FROM observations WHERE kind = 'schedule.tick'"
    )
    assert len(rows) == 1
    assert str(dict(rows[0])["source"]) == "ctl-observer"
    payload = str(dict(rows[0])["data_json"])
    assert FireCode.BLACKOUT.value in payload
    assert "poller" in payload
    store.close()


# =============================================================================
# 2. Fairness governs dispatch order — and the bound is proved by removal
# =============================================================================


class _NoStarvationTier(FairnessPolicy):
    """The real policy with the starvation tier deleted.

    Weighted deficit round robin only. Every other rule is Phase 1's, so the
    only variable is the tier the guarantee is supposed to rest on.
    """

    def select_team(
        self, pending: Sequence[str], history: Sequence[GrantRecord], *, window_index: int
    ) -> str | None:
        if not pending:
            return None
        return min(
            pending,
            key=lambda team: (-round(self.normalised_deficit(team, pending, history), 9), team),
        )


class _NoFifoTiebreak(FairnessPolicy):
    """The starvation tier kept, its longest-wait-first ordering deleted.

    Inside the starving tier this falls through to weight, which is the exact
    inversion the FIFO tiebreak exists to prevent: a fifty-weight team that has
    waited two windows would jump a one-weight team that has waited three.
    """

    def select_team(
        self, pending: Sequence[str], history: Sequence[GrantRecord], *, window_index: int
    ) -> str | None:
        if not pending:
            return None
        return min(
            pending,
            key=lambda team: (
                0 if self.is_starving(team, history, window_index=window_index) else 1,
                -round(self.normalised_deficit(team, pending, history), 9),
                team,
            ),
        )


def _served_over(
    repo: ScheduleStore,
    fairness: FairnessPolicy,
    *,
    teams: tuple[str, ...],
    windows: int,
) -> dict[str, list[int]]:
    """Drive ``windows`` real scheduler ticks, one per hourly slot.

    Returns the window indices each team was dispatched in, so the starvation
    measurement is taken from what the scheduler *did* rather than from what a
    simulation of it claims it would have done.
    """
    scheduler = _scheduler(repo, fairness=fairness)
    for team in teams:
        scheduler.register(_interval_entry(schedule_id=f"job-{team}", team=team))
    served: dict[str, list[int]] = {team: [] for team in teams}
    for index in range(windows):
        report = scheduler.tick(_inputs(now=T0 + timedelta(hours=index), window_index=index))
        for decision in report.dispatched:
            served[decision.team].append(index)
    return served


def _grants_from(served: dict[str, list[int]]) -> list[GrantRecord]:
    return [
        GrantRecord(window_index=index, team=team)
        for team, indices in sorted(served.items())
        for index in indices
    ]


def test_the_small_share_team_is_served_inside_the_provable_bound() -> None:
    """A 20:1 skew still serves the light team, and the bound says how often."""
    teams = ("heavy", "light")
    bound = 3 + (len(teams) - 1)
    policy = FairnessPolicy(
        policy_id="skewed", shares={"heavy": 20.0, "light": 1.0}, max_grants_per_window=1
    )
    store, repo = _store()

    served = _served_over(repo, policy, teams=teams, windows=400)
    skips = longest_skip_runs(_grants_from(served), teams=teams, windows=400)

    assert sum(len(indices) for indices in served.values()) == 400
    assert skips["light"] <= bound, f"light starved {skips['light']} windows, bound {bound}"
    # The bound is *tight*: one grant every `starvation_window + 1` windows, which
    # is the tier doing its job and not a coincidence of the weights.
    assert skips["light"] == 3
    assert len(served["light"]) == 100
    # The 20:1 skew survives as a preference, just not as an unbounded one:
    # unconstrained WDRR would give the light team 20 of 400, not 100.
    assert len(served["heavy"]) == 300
    assert len(served["heavy"]) > 2 * len(served["light"])
    store.close()


def test_removing_the_starvation_tier_breaks_the_bound() -> None:
    """The mutation test: delete the guarantee and watch the bound fail.

    If the tier were decorative this pair of tests could not both pass — the
    mutant runs the same schedules, the same ledger, and the same ticks.
    """
    teams = ("heavy", "light")
    shares = {"heavy": 20.0, "light": 1.0}
    bound = 3 + (len(teams) - 1)

    store, repo = _store()
    real = FairnessPolicy(
        policy_id="real", shares=shares, starvation_window=3, max_grants_per_window=1
    )
    real_served = _served_over(repo, real, teams=teams, windows=400)
    real_skips = longest_skip_runs(_grants_from(real_served), teams=teams, windows=400)
    store.close()

    store2, repo2 = _store()
    mutant = _NoStarvationTier(
        policy_id="mutant", shares=shares, starvation_window=3, max_grants_per_window=1
    )
    mutant_served = _served_over(repo2, mutant, teams=teams, windows=400)
    mutant_skips = longest_skip_runs(_grants_from(mutant_served), teams=teams, windows=400)
    store2.close()

    assert real_skips["light"] <= bound
    assert mutant_skips["light"] > bound, (
        "removing the starvation tier did not break the bound, so the bound was "
        "never resting on it"
    )
    # And the heavy team is served strictly more, which is what the tier costs.
    assert len(mutant_served["heavy"]) > len(real_served["heavy"])


def test_removing_the_fifo_tiebreak_changes_who_dispatches_first() -> None:
    """Two teams starve at once; the longer-waiting one goes first, and only it."""
    shares = {"heavy": 50.0, "light": 1.0, "never": 1.0}
    teams = ("heavy", "light", "never")
    # Shaped so the inversion is unavoidable: at window 3 'heavy' has waited two
    # windows and 'never' has waited three, and 'heavy' carries fifty times the
    # weight and ten times the deficit.
    seeded: tuple[tuple[int, str], ...] = ((0, "heavy"), (1, "light"), (2, "light"))

    def serve(policy: FairnessPolicy) -> str | None:
        store, repo = _store()
        scheduler = _scheduler(repo, fairness=policy)
        for team in teams:
            scheduler.register(_interval_entry(schedule_id=f"job-{team}", team=team))
        for index, team in seeded:
            record = _claim(
                schedule_id=f"job-{team}",
                team=team,
                window_index=index,
                at=T0 + timedelta(hours=index - 3),
            )
            repo.claim_slot(record)
            repo.settle_slot(
                record.idempotency_key,
                state=RunClaimState.DISPATCHED,
                code=DispatchCode.DISPATCHED.value,
                reason="seeded",
                at=T0,
                run_id=f"seed-{index}",
            )
        report = scheduler.tick(_inputs(window_index=3))
        store.close()
        return report.grants[0].team if report.grants else None

    real = FairnessPolicy(
        policy_id="real", shares=shares, starvation_window=2, max_grants_per_window=1
    )
    mutant = _NoFifoTiebreak(
        policy_id="mutant", shares=shares, starvation_window=2, max_grants_per_window=1
    )

    assert serve(real) == "never", "the longest-waiting starving team must go first"
    assert serve(mutant) == "heavy", (
        "without the FIFO tiebreak the heavy team takes the slot; if this ever "
        "became 'never' the tiebreak would be doing nothing"
    )


def test_the_scheduler_agrees_with_the_pure_simulation_it_is_built_on() -> None:
    """The service and the simulation must not be two different policies.

    Phase 1's :meth:`FairnessPolicy.simulate_fairness` is the reference; the
    scheduler drives real schedules through the same selection. Over constant
    demand the two grant sequences have to be identical, or one of them is
    describing a fairness rule the other does not implement.
    """
    teams = ("a", "b", "c")
    policy = FairnessPolicy(
        policy_id="agree",
        shares={"a": 5.0, "b": 1.0, "c": 1.0},
        starvation_window=3,
        max_grants_per_window=1,
    )
    store, repo = _store()

    served = _served_over(repo, policy, teams=teams, windows=120)
    store.close()

    from_scheduler: list[str] = [""] * 120
    for team, indices in served.items():
        for index in indices:
            from_scheduler[index] = team
    from_simulation = [grant[0] for grant in policy.simulate_fairness(teams, windows=120).grants]

    assert from_scheduler == from_simulation


def test_fairness_history_survives_a_controller_restart(tmp_path: Path) -> None:
    """The history is read from the durable ledger, not from controller memory."""
    path = tmp_path / "mayhem.db"
    policy = FairnessPolicy(
        policy_id="durable",
        shares={"heavy": 9.0, "light": 1.0},
        starvation_window=2,
        max_grants_per_window=1,
    )
    store, repo = _store(path)
    first = _scheduler(repo, fairness=policy, controller_id="ctl-a")
    for team in ("heavy", "light"):
        first.register(_interval_entry(schedule_id=f"job-{team}", team=team))
    for index in range(6):
        first.tick(_inputs(now=T0 + timedelta(hours=index), window_index=index))
    before = repo.grant_history()
    assert before
    store.close()

    reopened = Store.open_migrated(path)
    repo2 = ScheduleStore(reopened)
    second = _scheduler(repo2, fairness=policy, controller_id="ctl-b")

    assert repo2.grant_history() == before
    assert second.resume_window_index() == 5
    assert second.fairness.policy_id == "durable"
    reopened.close()


def test_a_deferred_schedule_is_recorded_rather_than_dropped() -> None:
    """Fairness spent the window; the loser is told so."""
    store, repo = _store()
    scheduler = _scheduler(
        repo,
        fairness=FairnessPolicy(
            policy_id="one-slot",
            shares={"a": 1.0, "b": 1.0},
            max_grants_per_window=1,
        ),
    )
    for team in ("a", "b"):
        scheduler.register(_interval_entry(schedule_id=f"job-{team}", team=team))

    report = scheduler.tick(_inputs())

    assert len(report.dispatched) == 1
    deferred = [d for d in report.held if d.code is DispatchCode.WINDOW_BUDGET_SPENT]
    assert len(deferred) == 1
    assert "deferred" in deferred[0].reason
    assert len(report.grants) == 1
    store.close()


def test_a_window_dispatch_budget_stops_the_tick_and_is_recorded() -> None:
    store, repo = _store()
    scheduler = _scheduler(
        repo,
        fairness=FairnessPolicy(
            policy_id="budgeted",
            shares={"a": 1.0, "b": 1.0},
            max_grants_per_window=4,
        ),
    )
    for team in ("a", "b"):
        scheduler.register(_interval_entry(schedule_id=f"job-{team}", team=team))

    report = scheduler.tick(_inputs(dispatch_budget=1))

    assert len(report.dispatched) == 1
    spent = [d for d in report.held if d.code is DispatchCode.WINDOW_BUDGET_SPENT]
    assert len(spent) == 1
    assert "budget of 1 is spent" in spent[0].reason
    store.close()


def test_the_default_policy_is_an_equal_share_policy_not_the_absence_of_one() -> None:
    assert DEFAULT_FAIRNESS.share_of("anyone") == DEFAULT_FAIRNESS.share_of("else")
    assert DEFAULT_FAIRNESS.max_grants_per_window >= 1
    order = order_by_fairness(
        (_due("job-z", "z-team"), _due("job-a", "a-team")),
        DEFAULT_FAIRNESS,
        (),
        window_index=0,
    )

    assert [item.entry.schedule_id for item in order.ordered] == ["job-a"]


def test_order_by_fairness_takes_each_teams_earliest_slot_first() -> None:
    early, late = T0, T0 + timedelta(minutes=30)
    policy = FairnessPolicy(
        policy_id="fifo", shares={"t": 1.0}, max_grants_per_window=3
    )

    order = order_by_fairness(
        (_due("job-late", "t", slot=late), _due("job-early", "t", slot=early)),
        policy,
        (),
        window_index=0,
    )

    assert [item.entry.schedule_id for item in order.ordered] == ["job-early", "job-late"]


def test_order_by_fairness_is_independent_of_the_input_order() -> None:
    policy = FairnessPolicy(policy_id="f", shares={"a": 1.0, "b": 1.0}, max_grants_per_window=2)
    due = (_due("job-a", "a"), _due("job-b", "b"))

    forward = order_by_fairness(due, policy, (), window_index=0)
    backward = order_by_fairness(tuple(reversed(due)), policy, (), window_index=0)

    assert [item.entry.schedule_id for item in forward.ordered] == [
        item.entry.schedule_id for item in backward.ordered
    ]


def test_order_by_fairness_has_nothing_to_order_when_nothing_is_due() -> None:
    policy = FairnessPolicy(policy_id="f", shares={"a": 1.0})

    order = order_by_fairness((), policy, (), window_index=0)

    assert order.ordered == ()
    assert order.deferred == ()
    assert order.grants == ()


# =============================================================================
# 3. Concurrency: two conflicting experiments serialize, naming the holder
# =============================================================================


def _two_slot_policy() -> FairnessPolicy:
    """A policy that lets both contending teams be considered in one window."""
    return FairnessPolicy(
        policy_id="two-slots",
        shares={"a": 1.0, "b": 1.0},
        max_grants_per_window=2,
    )


def _register_pair(scheduler: Scheduler) -> None:
    """Two teams contending for one database, both demanding in the same window.

    ``job-a`` is budgeted at a single run so the pair also demonstrates the
    drain: once a's budget is spent its slot frees the resource for b.
    """
    for team in ("a", "b"):
        scheduler.register(
            _interval_entry(
                schedule_id=f"job-{team}",
                team=team,
                experiment_id=f"exp-{team}",
                max_runs=1 if team == "a" else 10,
            )
        )


def test_two_conflicting_experiments_serialize_naming_the_lock_owner() -> None:
    store, repo = _store()
    recorder = Recorder()
    scheduler = _scheduler(repo, pipeline=_pipeline(recorder), fairness=_two_slot_policy())
    _register_pair(scheduler)

    report = scheduler.tick(_inputs())

    dispatched = [d for d in report.decisions if d.dispatched]
    queued = [d for d in report.held if d.code is DispatchCode.CONCURRENCY_QUEUED]
    assert len(dispatched) == 1
    assert len(queued) == 1
    # The owner is named, and it is the run that actually holds the resource.
    assert queued[0].queued_behind == dispatched[0].run_id
    assert queued[0].blocking_experiment_id == f"exp-{dispatched[0].team}"
    assert queued[0].blocking_resource == "db-primary"
    assert dispatched[0].run_id in queued[0].reason
    # And the second one really did not execute: one run, not two.
    assert recorder.executions == 1
    store.close()


def test_the_refused_second_run_dispatches_once_the_resource_is_free() -> None:
    store, repo = _store()
    recorder = Recorder()
    scheduler = _scheduler(repo, pipeline=_pipeline(recorder), fairness=_two_slot_policy())
    _register_pair(scheduler)
    scheduler.tick(_inputs())

    report = scheduler.tick(_inputs(now=T0 + timedelta(hours=1), window_index=1))

    # job-a's one-run budget is spent, so the resource it held is free and the
    # run that queued behind it gets its turn exactly one window later.
    assert recorder.executions == 2
    assert [d.schedule_id for d in report.dispatched] == ["job-b"]
    spent = report.for_schedule("job-a")
    assert spent is not None
    assert spent.fire is not None
    assert spent.fire.code is FireCode.EXHAUSTED
    store.close()


def test_a_live_policy_lock_blocks_the_scheduled_run_and_names_its_holder() -> None:
    """The 07 resource-lock layer, underneath the compatibility matrix."""
    store, repo = _store()
    recorder = Recorder()
    scheduler = _scheduler(repo, pipeline=_pipeline(recorder))
    scheduler.register(_interval_entry(experiment_id="exp-a"))
    holder = ConcurrencyRequest(
        run_id="run-holder",
        experiment_id="exp-other",
        concurrency_class=ConcurrencyClass.SHARED_RESOURCE,
        resources=("db-primary",),
        acquired_at=T0 - timedelta(minutes=5),
        expires_at=T0 + timedelta(hours=5),
    )

    decision = scheduler.tick(
        _inputs(active_locks=(holder.lock_for("db-primary"),))
    ).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.CONCURRENCY_QUEUED
    assert decision.queued_behind == "run-holder"
    assert decision.blocking_resource == "db-primary"
    assert recorder.executions == 0
    store.close()


def test_shared_resource_runs_coexist_on_the_same_resource() -> None:
    store, repo = _store()
    recorder = Recorder()
    scheduler = _scheduler(repo, pipeline=_pipeline(recorder), fairness=_two_slot_policy())
    for team in ("a", "b"):
        scheduler.register(
            _interval_entry(
                schedule_id=f"job-{team}",
                team=team,
                experiment_id=f"exp-{team}",
                concurrency_class=ConcurrencyClass.SHARED_RESOURCE,
            )
        )

    report = scheduler.tick(_inputs())

    assert len(report.dispatched) == 2
    assert recorder.executions == 2
    store.close()


def test_an_expired_holder_stops_fencing_the_resource() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry())
    expired = ConcurrencyRequest(
        run_id="run-dead",
        experiment_id="exp-other",
        concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",),
        acquired_at=T0 - timedelta(hours=5),
        expires_at=T0 - timedelta(hours=1),
    )

    decision = scheduler.tick(_inputs(active_requests=(expired,))).for_schedule("poller")

    assert decision is not None
    assert decision.dispatched is True
    store.close()


def test_runs_on_different_resources_never_queue() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo, fairness=_two_slot_policy())
    scheduler.register(_interval_entry(schedule_id="job-a", team="a", resources=("db-a",)))
    scheduler.register(_interval_entry(schedule_id="job-b", team="b", resources=("db-b",)))

    report = scheduler.tick(_inputs())

    assert len(report.dispatched) == 2
    store.close()


# =============================================================================
# 4. Idempotency: the restart drill
# =============================================================================


def _claim(
    *,
    schedule_id: str,
    team: str,
    window_index: int,
    at: datetime,
) -> ScheduleRunRecord:
    return ScheduleRunRecord(
        idempotency_key=slot_idempotency_key(
            schedule_id=schedule_id,
            campaign_id="camp-1",
            experiment_id="exp-1",
            slot_start=at,
        ),
        schedule_id=schedule_id,
        team=team,
        campaign_id="camp-1",
        experiment_id="exp-1",
        window_index=window_index,
        slot_start=at,
        effective_at=at,
        controller_id="seed",
        recorded_at=at,
    )


def test_the_idempotency_key_is_a_pure_function_of_the_slot() -> None:
    """Two controllers handed the same slot agree on the key without talking."""
    kwargs = {
        "schedule_id": "poller",
        "campaign_id": "camp-1",
        "experiment_id": "exp-1",
        "slot_start": T0,
    }
    key = slot_idempotency_key(**kwargs)

    assert key == slot_idempotency_key(**kwargs)
    assert key != slot_idempotency_key(**{**kwargs, "slot_start": T0 + timedelta(hours=1)})
    # The same instant expressed in another zone is the same slot.
    assert slot_idempotency_key(**{**kwargs, "slot_start": T0.astimezone(NY)}) == key
    # The run id is derived from the key, so a resumed attempt is the same run.
    assert slot_run_id(key) == slot_run_id(slot_idempotency_key(**kwargs))
    assert slot_run_id(key).startswith("sr-")


def test_a_restart_mid_schedule_does_not_double_fire(tmp_path: Path) -> None:
    """The drill: kill the controller, start another, offer the same slot again."""
    path = tmp_path / "mayhem.db"
    store, repo = _store(path)
    first_calls = Recorder()
    first = _scheduler(repo, pipeline=_pipeline(first_calls), controller_id="ctl-a")
    first.register(_interval_entry())

    before = first.tick(_inputs(window_index=0))
    assert before.codes == (DispatchCode.DISPATCHED.value,)
    assert first_calls.executions == 1
    dispatched_run = before.dispatched[0].run_id
    store.close()

    # ---- the process is gone; a new one opens the same database file ----
    reopened = Store.open_migrated(path)
    repo2 = ScheduleStore(reopened)
    second_calls = Recorder()
    second = _scheduler(repo2, pipeline=_pipeline(second_calls), controller_id="ctl-b")

    after = second.tick(_inputs(window_index=second.resume_window_index()))

    assert after.codes == (DispatchCode.ALREADY_DISPATCHED.value,)
    assert after.dispatched == ()
    assert second_calls.calls == [], "the restarted controller planned nothing"
    decision = after.for_schedule("poller")
    assert decision is not None
    assert dispatched_run in decision.reason
    reopened.close()


def test_a_controller_killed_mid_dispatch_leaves_the_slot_unretried(tmp_path: Path) -> None:
    """The harder case: the executor ran, then the process died.

    The outcome of that run is unknown, so nothing may retry the slot. Assuming
    it failed and running it again is exactly how a chaos drill gets injected
    twice into the same window.
    """
    path = tmp_path / "mayhem.db"
    attempts: list[str] = []

    class _KilledError(RuntimeError):
        """Stands in for the process going away mid-execution."""

    def dying_executor(request: Any, planned: PlannedDispatch) -> ExecutionReceipt:
        attempts.append(request.concurrency.run_id)
        raise _KilledError("controller killed mid-dispatch")

    store, repo = _store(path)
    first = _scheduler(repo, pipeline=_pipeline(executor=dying_executor), controller_id="ctl-a")
    first.register(_interval_entry())

    with pytest.raises(_KilledError):
        first.tick(_inputs(window_index=0))

    assert len(attempts) == 1
    key = slot_idempotency_key(
        schedule_id="poller", campaign_id="camp-1", experiment_id="exp-1", slot_start=T0
    )
    stuck = repo.load_run(key)
    assert stuck is not None
    assert stuck.is_live_claim() is True, "the claim stays unsettled: the outcome is unknown"
    store.close()

    # ---- the replacement controller finds the unknown outcome ----
    reopened = Store.open_migrated(path)
    repo2 = ScheduleStore(reopened)
    second_calls = Recorder()
    second = _scheduler(repo2, pipeline=_pipeline(second_calls), controller_id="ctl-b")

    report = second.tick(_inputs(window_index=second.resume_window_index()))

    decision = report.for_schedule("poller")
    assert decision is not None
    assert decision.code is DispatchCode.CLAIM_IN_FLIGHT
    assert "unknown" in decision.reason
    assert len(attempts) == 1, "the drill was injected twice for one slot"
    assert second_calls.executions == 0
    reopened.close()


def test_a_claim_is_enforced_by_the_primary_key_not_by_a_prior_read(tmp_path: Path) -> None:
    """The mechanism, shown directly: a duplicate key is a database error.

    If the guarantee were a read-then-write, the statement below would succeed
    and silently overwrite the first attempt's run id.
    """
    path = tmp_path / "mayhem.db"
    store, repo = _store(path)
    repo.save_schedule(_interval_entry())
    record = _claim(schedule_id="poller", team="sre", window_index=0, at=T0)

    assert repo.claim_slot(record).fresh is True
    assert repo.claim_slot(record).outcome.value == "already_claimed"

    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(
                "INSERT INTO schedule_runs (idempotency_key, schedule_id, team, "
                "campaign_id, experiment_id, window_index, slot_start, effective_at, "
                "state, code, reason, run_id, controller_id, detail_json, recorded_at, "
                "settled_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.idempotency_key,
                    "poller",
                    "sre",
                    "camp-1",
                    "exp-1",
                    0,
                    T0.isoformat(),
                    T0.isoformat(),
                    RunClaimState.DISPATCHED.value,
                    "",
                    "",
                    "run-smuggled",
                    "rogue",
                    "{}",
                    T0.isoformat(),
                    T0.isoformat(),
                ),
            )

    assert repo.dispatch_count("poller") == 0, "the rogue row must not have landed"
    store.close()


def test_a_recurring_schedule_survives_a_controller_restart(tmp_path: Path) -> None:
    """State persists: the next slot fires after a restart; the spent one does not."""
    path = tmp_path / "mayhem.db"
    store, repo = _store(path)
    first = _scheduler(repo, controller_id="ctl-a")
    first.register(_interval_entry(max_runs=5))
    first.tick(_inputs(window_index=0))
    store.close()

    reopened = Store.open_migrated(path)
    repo2 = ScheduleStore(reopened)
    second = _scheduler(repo2, controller_id="ctl-b")

    spent = second.tick(_inputs(window_index=0))
    assert spent.codes == (DispatchCode.ALREADY_DISPATCHED.value,)

    following = second.tick(_inputs(now=T0 + timedelta(hours=1), window_index=1))
    assert following.codes == (DispatchCode.DISPATCHED.value,)
    assert repo2.dispatch_count("poller") == 2
    stored = repo2.load_schedule("poller")
    assert stored is not None
    assert stored.run_count == 2
    assert stored.last_slot_start == T0 + timedelta(hours=1)
    reopened.close()


def test_settling_a_claim_that_was_never_taken_is_refused() -> None:
    store, repo = _store()
    repo.save_schedule(_interval_entry())

    with pytest.raises(InvariantViolationError) as excinfo:
        repo.settle_slot(
            "sk-nobody-claimed-this",
            state=RunClaimState.DISPATCHED,
            code="",
            reason="",
            at=T0,
        )

    assert excinfo.value.rule == "schedule.claim_missing"
    store.close()


# =============================================================================
# 5. Negative controls: a scheduled run is not a privileged run
# =============================================================================


def test_a_scheduled_run_cannot_bypass_admission() -> None:
    """The *real* ``validate_plan`` refuses, and the executor is never reached."""
    store, repo = _store()
    recorder = Recorder()
    scheduler = _scheduler(
        repo,
        pipeline=_pipeline(
            recorder, admission=_real_gate(recorder, "admission", fingerprint="live-fp")
        ),
    )
    scheduler.register(_interval_entry())

    decision = scheduler.tick(_inputs()).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.ADMISSION_REFUSED
    assert "fingerprint" in decision.reason
    assert recorder.calls == ["planner", "admission"]
    assert recorder.executions == 0
    store.close()


def test_the_real_admission_gate_admits_a_matching_plan() -> None:
    """The positive control for the row above: the same gate, same plan, admitted."""
    store, repo = _store()
    recorder = Recorder()
    scheduler = _scheduler(
        repo, pipeline=_pipeline(recorder, admission=_real_gate(recorder, "admission"))
    )
    scheduler.register(_interval_entry())

    decision = scheduler.tick(_inputs()).for_schedule("poller")

    assert decision is not None
    assert decision.dispatched is True
    assert recorder.executions == 1
    store.close()


def test_a_scheduled_run_cannot_bypass_approval() -> None:
    """The *real* approval gate refuses an unapproved run; the executor is untouched."""
    store, repo = _store()
    recorder = Recorder()
    scheduler = _scheduler(
        repo, pipeline=_pipeline(recorder, approver=_real_gate(recorder, "approver"))
    )
    scheduler.register(_interval_entry())

    decision = scheduler.tick(_inputs()).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.APPROVAL_DENIED
    assert decision.gates == ("admission",)
    assert recorder.calls == ["planner", "admission", "approver"]
    assert recorder.executions == 0
    store.close()


def test_a_real_approval_lets_the_scheduled_run_through() -> None:
    """The positive control for approval: a real approval, the real gate, admitted."""
    store, repo = _store()
    recorder = Recorder()
    plan = _plan("run-approved")
    approval = Approval(
        approval_id="a-1",
        plan_digest=candidate_plan_digest(plan),
        policy_digest=POLICY_DIGEST,
        proof_digest=_passing_proof(plan).proof_digest,
        approver=OPERATOR,
        environment=EnvironmentScope.any(),
        issued_at=BEFORE_T0,
    )

    def approving(request: Any, planned: PlannedDispatch) -> GateVerdict:
        recorder.calls.append("approver")
        result = verify_approvals(plan, _approval_inputs(plan, approvals=(approval,)))
        return GateVerdict(passed=not result.denied, reason="approved")

    def fixed_planner(request: Any) -> PlannedDispatch:
        recorder.calls.append("planner")
        return PlannedDispatch(plan=plan, plan_digest=candidate_plan_digest(plan))

    scheduler = _scheduler(
        repo, pipeline=_pipeline(recorder, planner=fixed_planner, approver=approving)
    )
    scheduler.register(_interval_entry())

    decision = scheduler.tick(_inputs()).for_schedule("poller")

    assert decision is not None
    assert decision.dispatched is True
    assert recorder.calls == ["planner", "admission", "approver", "executor"]
    store.close()


def test_an_approval_for_another_plan_does_not_authorise_this_one() -> None:
    """An approval is a statement about one exact plan, and this proves it."""
    store, repo = _store()
    recorder = Recorder()
    approved, scheduled = _plan("run-approved"), _plan("run-scheduled")
    approval = Approval(
        approval_id="a-1",
        plan_digest=candidate_plan_digest(approved),
        policy_digest=POLICY_DIGEST,
        proof_digest=_passing_proof(approved).proof_digest,
        approver=OPERATOR,
        environment=EnvironmentScope.any(),
        issued_at=BEFORE_T0,
    )

    def approving(request: Any, planned: PlannedDispatch) -> GateVerdict:
        recorder.calls.append("approver")
        result = verify_approvals(
            planned.plan, _approval_inputs(planned.plan, approvals=(approval,))
        )
        return GateVerdict(
            passed=not result.denied, reason="approved" if not result.denied else "denied"
        )

    scheduler = _scheduler(repo, pipeline=_pipeline(recorder, approver=approving))
    scheduler.register(_interval_entry())

    decision = scheduler.tick(_inputs()).for_schedule("poller")

    assert scheduled.run_id != approved.run_id
    assert decision is not None
    assert decision.code is DispatchCode.APPROVAL_DENIED
    assert recorder.executions == 0
    store.close()


def test_a_pipeline_cannot_be_built_without_a_gate() -> None:
    """The structural half of "never exempt": no construction path omits a gate."""
    full = _pipeline()
    complete = {
        "planner": full.planner,
        "admission": full.admission,
        "approver": full.approver,
        "executor": full.executor,
    }

    for missing in complete:
        kwargs = {name: fn for name, fn in complete.items() if name != missing}
        with pytest.raises(TypeError):
            DispatchPipeline(**kwargs)  # type: ignore[arg-type]


def test_a_firing_during_an_active_incident_is_refused_without_a_commander() -> None:
    store, repo = _store()
    recorder = Recorder()
    scheduler = _scheduler(repo, pipeline=_pipeline(recorder))
    scheduler.register(_interval_entry())

    decision = scheduler.tick(
        _inputs(incident=IncidentState(incident_id=INCIDENT, summary="paging"))
    ).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.INCIDENT_ACTIVE
    assert INCIDENT in decision.reason
    assert "commander override" in decision.reason
    assert recorder.calls == [], "an incident must be refused before anything is planned"
    store.close()


def test_a_named_commander_override_lets_the_run_through() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry())

    decision = scheduler.tick(
        _inputs(
            incident=IncidentState(incident_id=INCIDENT),
            commander_override=CommanderOverride(
                actor="cmdr-sre", reason="drill approved for the change window", at=T0
            ),
        )
    ).for_schedule("poller")

    assert decision is not None
    assert decision.dispatched is True
    store.close()


def test_an_override_written_for_another_incident_does_not_authorise_this_one() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry())

    decision = scheduler.tick(
        _inputs(
            incident=IncidentState(incident_id=INCIDENT),
            commander_override=CommanderOverride(
                actor="cmdr-sre", reason="stale paperwork", at=T0, incident_id="inc-0001"
            ),
        )
    ).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.INCIDENT_ACTIVE
    assert "does not cover" in decision.reason
    store.close()


def test_a_closed_incident_does_not_refuse_anything() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry())

    decision = scheduler.tick(
        _inputs(incident=IncidentState(incident_id=INCIDENT, active=False))
    ).for_schedule("poller")

    assert decision is not None
    assert decision.dispatched is True
    store.close()


def test_a_commander_override_must_name_somebody_and_something() -> None:
    with pytest.raises(InvariantViolationError):
        CommanderOverride(actor="  ", reason="because", at=T0)
    with pytest.raises(InvariantViolationError):
        CommanderOverride(actor="cmdr-sre", reason="", at=T0)


def test_a_deployment_freeze_refuses_the_fire() -> None:
    store, repo = _store()
    recorder = Recorder()
    scheduler = _scheduler(repo, pipeline=_pipeline(recorder))
    scheduler.register(_interval_entry())

    decision = scheduler.tick(
        _inputs(deployment=DeploymentState(frozen=True, reason="change freeze"))
    ).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.DEPLOYMENT_BLOCKED
    assert "change freeze" in decision.reason
    assert recorder.calls == []
    store.close()


def test_a_deploy_in_progress_refuses_the_fire() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry())

    decision = scheduler.tick(
        _inputs(deployment=DeploymentState(in_progress=True, deployment_id="dep-9"))
    ).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.DEPLOYMENT_BLOCKED
    assert "dep-9" in decision.reason
    store.close()


def test_a_clear_deployment_does_not_refuse() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry())

    decision = scheduler.tick(_inputs(deployment=DeploymentState())).for_schedule("poller")

    assert decision is not None
    assert decision.dispatched is True
    store.close()


def test_a_declared_executor_failure_settles_the_slot_failed() -> None:
    store, repo = _store()

    def failing_executor(request: Any, planned: PlannedDispatch) -> ExecutionReceipt:
        return ExecutionReceipt(run_id="", detail="runner refused the lease")

    scheduler = _scheduler(repo, pipeline=_pipeline(executor=failing_executor))
    scheduler.register(_interval_entry())

    decision = scheduler.tick(_inputs()).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.EXECUTION_FAILED
    assert "lease" in decision.reason
    record = repo.load_run(decision.idempotency_key)
    assert record is not None
    assert record.state is RunClaimState.FAILED
    assert record.settled is True
    assert repo.dispatch_count("poller") == 0
    store.close()


def test_a_planner_that_raises_is_a_refusal_rather_than_a_crash() -> None:
    store, repo = _store()

    def broken_planner(request: Any) -> PlannedDispatch:
        raise RuntimeError("planner has no target profile")

    scheduler = _scheduler(repo, pipeline=_pipeline(planner=broken_planner))
    scheduler.register(_interval_entry())

    decision = scheduler.tick(_inputs()).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.PLAN_FAILED
    assert "target profile" in decision.reason
    record = repo.load_run(decision.idempotency_key)
    assert record is not None
    assert record.state is RunClaimState.FAILED
    store.close()


def test_scheduler_inputs_refuse_an_ambient_clock() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        SchedulerInputs(now=datetime(2026, 6, 1, 9, 0), window_index=0)  # noqa: DTZ001

    assert excinfo.value.rule == "scheduler.naive_clock"


def test_scheduler_inputs_refuse_a_negative_window_or_budget() -> None:
    with pytest.raises(InvariantViolationError):
        SchedulerInputs(now=T0, window_index=-1)
    with pytest.raises(InvariantViolationError):
        SchedulerInputs(now=T0, window_index=0, dispatch_budget=-1)


def test_inputs_can_be_replayed_at_another_instant() -> None:
    inputs = _inputs(incident=IncidentState(incident_id=INCIDENT))

    later = inputs.with_now(T0 + timedelta(hours=1))

    assert later.now == T0 + timedelta(hours=1)
    assert later.incident == inputs.incident
    assert later.window_index == inputs.window_index


# =============================================================================
# 6. Game day: dispatch as a scheduled step behind a facilitator hold
# =============================================================================


def _game_day(store: Store, session_id: str = "gd-1") -> str:
    GameDayRepository(store).save(
        GameDaySession(id=session_id, name="quarterly", created_at=T0.isoformat())
    )
    return session_id


def _step(
    *, session_id: str, schedule_id: str = "poller", step_id: str = "inject-1"
) -> GameDayStepRecord:
    return GameDayStepRecord(
        session_id=session_id,
        step_id=step_id,
        step_seq=1,
        scenario="regional-outage",
        schedule_id=schedule_id,
        hold_reason="wait for the facilitator's go",
        created_at=T0.isoformat(),
    )


def _ack(actor: str = "facil-1", reason: str = "participants ready") -> OperatorAcknowledgement:
    return OperatorAcknowledgement(
        actor=actor, role="facilitator", reason=reason, at=T0.isoformat()
    )


def test_a_facilitator_hold_refuses_the_dispatch_until_it_is_released() -> None:
    store, repo = _store()
    recorder = Recorder()
    session_id = _game_day(store)
    scheduler = _scheduler(repo, pipeline=_pipeline(recorder))
    scheduler.register(_interval_entry())
    repo.save_step(_step(session_id=session_id))

    held = scheduler.tick(_inputs()).for_schedule("poller")

    assert held is not None
    assert held.code is DispatchCode.FACILITATOR_HOLD
    assert f"{session_id}:inject-1" in held.reason
    assert recorder.calls == [], "a held step is refused before the pipeline is entered"

    repo.save_step(
        release_hold(repo.steps_for_schedule("poller")[0], _ack(), at=T0.isoformat())
    )
    released = scheduler.tick(_inputs(now=T0 + timedelta(seconds=1))).for_schedule("poller")

    assert released is not None
    assert released.dispatched is True
    step = repo.load_step(session_id, "inject-1")
    assert step is not None
    assert step.hold_state is HoldState.DISPATCHED
    assert step.released_by == "facil-1"
    assert step.dispatched_at
    store.close()


def test_a_hold_needs_a_named_facilitator_and_a_reason() -> None:
    step = _step(session_id="gd-1")

    with pytest.raises(InvariantViolationError) as no_actor:
        release_hold(step, OperatorAcknowledgement(actor=""), at=T0.isoformat())
    assert no_actor.value.rule == "game_day.hold_needs_facilitator"

    with pytest.raises(InvariantViolationError) as no_reason:
        release_hold(step, _ack(reason="  "), at=T0.isoformat())
    assert no_reason.value.rule == "game_day.hold_needs_reason"

    with pytest.raises(InvariantViolationError) as twice:
        release_hold(
            step.model_copy(update={"hold_state": HoldState.RELEASED}), _ack(), at=T0.isoformat()
        )
    assert twice.value.rule == "game_day.hold_not_held"


def test_a_hold_survives_a_controller_restart(tmp_path: Path) -> None:
    """The hold is durable state, not a flag a restarted controller loses."""
    path = tmp_path / "mayhem.db"
    store, repo = _store(path)
    session_id = _game_day(store)
    first = _scheduler(repo, controller_id="ctl-a")
    first.register(_interval_entry())
    repo.save_step(_step(session_id=session_id))
    first.tick(_inputs())
    store.close()

    reopened = Store.open_migrated(path)
    repo2 = ScheduleStore(reopened)
    second = _scheduler(repo2, controller_id="ctl-b")

    decision = second.tick(_inputs(now=T0 + timedelta(seconds=1))).for_schedule("poller")

    assert decision is not None
    assert decision.code is DispatchCode.FACILITATOR_HOLD
    reopened.close()


def test_a_held_step_cannot_be_marked_dispatched() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        mark_dispatched(_step(session_id="gd-1"), at=T0.isoformat())

    assert excinfo.value.rule == "game_day.step_still_held"


# =============================================================================
# 7. Persistence: registration rules and the migration chain
# =============================================================================


def test_a_schedule_must_name_a_team_and_the_resources_it_touches() -> None:
    schedule = _interval_entry().schedule
    with pytest.raises(InvariantViolationError) as no_team:
        ScheduleEntry(
            schedule=schedule.model_copy(update={"team": ""}),
            campaign_id="camp-1",
            experiment_id="exp-1",
            resources=("db-primary",),
        )
    assert no_team.value.rule == "schedule.entry_team"

    with pytest.raises(InvariantViolationError) as no_resources:
        ScheduleEntry(
            schedule=schedule,
            campaign_id="camp-1",
            experiment_id="exp-1",
            concurrency_class=ConcurrencyClass.EXCLUSIVE,
            resources=(),
        )
    assert no_resources.value.rule == "schedule.entry_resources"

    with pytest.raises(InvariantViolationError) as parallel_resources:
        ScheduleEntry(
            schedule=schedule,
            campaign_id="camp-1",
            experiment_id="exp-1",
            concurrency_class=ConcurrencyClass.PARALLEL,
            resources=("db-primary",),
        )
    assert parallel_resources.value.rule == "schedule.entry_parallel_resources"

    with pytest.raises(InvariantViolationError) as twice:
        ScheduleEntry(
            schedule=schedule,
            campaign_id="camp-1",
            experiment_id="exp-1",
            resources=("db-primary", "db-primary"),
        )
    assert twice.value.rule == "schedule.entry_resource_duplicate"


def test_a_registered_schedule_round_trips_through_the_store() -> None:
    store, repo = _store()
    entry = _cron_entry(
        campaign_id="camp-7",
        experiment_id="exp-7",
        expression="30 2 * * 1-5",
        timezone_name="America/New_York",
        business_hours=_office_hours(),
    )

    repo.save_schedule(entry)
    loaded = repo.load_schedule("nightly")

    assert loaded is not None
    assert loaded.schedule == entry.schedule
    assert loaded.campaign_id == "camp-7"
    assert loaded.experiment_id == "exp-7"
    assert loaded.concurrency_class is ConcurrencyClass.EXCLUSIVE
    assert loaded.resources == ("db-primary",)
    assert loaded.body_digest == entry.body_digest
    assert [item.schedule_id for item in repo.list_schedules()] == ["nightly"]
    store.close()


def test_a_schedule_with_dispatch_evidence_cannot_be_deleted() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_interval_entry())
    scheduler.tick(_inputs())

    with pytest.raises(InvariantViolationError) as excinfo:
        repo.delete_schedule("poller")

    assert excinfo.value.rule == "schedule.delete_with_claims"
    assert repo.load_schedule("poller") is not None
    store.close()


def test_an_undispatched_schedule_can_be_deleted() -> None:
    store, repo = _store()
    repo.save_schedule(_interval_entry())

    assert repo.delete_schedule("poller") is True
    assert repo.load_schedule("poller") is None
    store.close()


def test_the_migration_chain_is_contiguous_and_reversible() -> None:
    from mayhem.infra.migrations import ALL_MIGRATIONS

    versions = tuple(migration.version for migration in ALL_MIGRATIONS)
    assert versions == tuple(range(1, len(versions) + 1))
    assert ALL_MIGRATIONS[25].migration_id == "0026_schedules"
    assert ALL_MIGRATIONS[25].down_statements

    store = Store.open_migrated(":memory:")
    assert store.schema_version == len(ALL_MIGRATIONS)
    store.migrate_down(25)
    assert store.schema_version == 25
    tables = {
        str(row[0])
        for row in store.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    assert "schedules" not in tables
    assert "schedule_runs" not in tables
    assert "game_day_dispatch_steps" not in tables
    store.migrate()
    assert store.schema_version == len(ALL_MIGRATIONS)
    store.close()


def test_a_claim_cannot_name_a_schedule_nobody_registered() -> None:
    store, repo = _store()

    with pytest.raises(sqlite3.IntegrityError):
        repo.claim_slot(_claim(schedule_id="ghost", team="sre", window_index=0, at=T0))

    key = slot_idempotency_key(
        schedule_id="ghost", campaign_id="camp-1", experiment_id="exp-1", slot_start=T0
    )
    assert repo.load_run(key) is None
    store.close()


def test_a_dispatch_step_cannot_exist_for_a_session_nobody_approved() -> None:
    store, repo = _store()

    with pytest.raises(sqlite3.IntegrityError):
        repo.save_step(_step(session_id="gd-never-approved"))

    assert repo.steps_for_schedule("poller") == ()
    store.close()


# =============================================================================
# 8. Module law
# =============================================================================


def test_the_scheduler_never_reads_an_ambient_clock() -> None:
    """Every instant is an argument. Scanned as code, so the docstring may lie."""
    code_only: list[str] = []
    with SCHEDULER_MODULE.open("rb") as handle:
        for token in tokenize.tokenize(handle.readline):
            if token.type not in (tokenize.STRING, tokenize.COMMENT):
                code_only.append(token.string)
    body = " ".join(code_only)

    for forbidden in ("datetime.now(", "utcnow(", "utc_now(", "monotonic("):
        assert forbidden not in body, f"{forbidden} makes a fire decision ambient"


def test_the_scheduler_reaches_no_above_the_controller_layer() -> None:
    tree = ast.parse(SCHEDULER_MODULE.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    assert [name for name in imported if name.startswith("mayhem.cli")] == []


# =============================================================================
# 9. What a tick is not allowed to spend time on
# =============================================================================


def test_a_tick_that_dispatches_nothing_does_not_walk_any_cron(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tick must not pay for the next-fire cache it does not need.

    ``Schedule.next_fire_time`` walks the cron minute by minute inside a bounded
    search, so a sparse expression such as ``@yearly`` costs six figures of
    iterations. Paying that on every tick of every schedule — for a column that
    is documented as a hint — would make a poll loop spend its time on a cache.
    Counted rather than timed, so the property is exact and not flaky.
    """
    calls: list[str] = []
    original = Schedule.next_fire_time

    def counting(self: Schedule, after: datetime) -> datetime | None:
        calls.append(self.schedule_id)
        return original(self, after)

    monkeypatch.setattr(Schedule, "next_fire_time", counting)
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_cron_entry(schedule_id="yearly", expression="@yearly"))

    scheduler.tick(_inputs(now=T0.replace(month=6, day=15)))
    scheduler.tick(_inputs(now=T0.replace(month=6, day=15), window_index=1))

    assert calls == [], "a non-dispatching tick recomputed next_fire_time"
    stored = repo.load_schedule("yearly")
    assert stored is not None
    assert stored.next_fire_at is None, "the cache is only refreshed by a dispatch"
    store.close()


def test_a_dispatch_refreshes_the_next_fire_cache() -> None:
    store, repo = _store()
    scheduler = _scheduler(repo)
    scheduler.register(_cron_entry(schedule_id="hourly", expression="0 * * * *"))

    scheduler.tick(_inputs())

    stored = repo.load_schedule("hourly")
    assert stored is not None
    assert stored.next_fire_at == T0 + timedelta(hours=1)
    store.close()


def test_seen_in_advances_the_window_without_touching_anything_else() -> None:
    entry = _interval_entry()

    advanced = entry.seen_in(window_index=7)
    unchanged = entry.seen_in(window_index=0)

    assert advanced.window_index == 7
    assert advanced.run_count == entry.run_count
    assert advanced.next_fire_at == entry.next_fire_at
    assert unchanged == entry, "a tick in an earlier window changes nothing"
