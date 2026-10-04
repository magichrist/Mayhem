"""Plan 13 Phase 2 — the durable scheduler over the campaign engine.

Phase 1 (:mod:`mayhem.domain.scheduling`) said *when* a run may fire and *who*
gets the next slot, as pure functions of an injected instant. This module is the
service that acts on those answers: it evaluates registered schedules against
policy windows, blackouts, deployment and incident state, budgets and fairness
shares, dispatches what survives through the ordinary plan → admission →
approval → execute flow, and persists enough state that a controller which dies
mid-schedule resumes without firing a slot twice.

Three properties are structural here rather than documented, because each one is
a thing that is easy to *promise* and easy to *lose*:

**A scheduled run is not a privileged run.** :class:`DispatchPipeline` is a
frozen dataclass whose four callables are all *required* — there is no
construction path that omits the planner, the admission gate, the approver, or
the executor, so "schedules bypass admission" is not a decision this module
could express. :meth:`Scheduler.tick` calls them in one fixed order and records
which gates it cleared in :attr:`DispatchDecision.gates`; a refusal at any gate
stops the pipeline with the executor untouched. The bindings are the ordinary
ones: ``controller.safety.validate_plan`` for admission, the plan-09 approval
gate for approval, ``controller.executor`` for execution.

**A slot fires at most once, enforced by the database.** The idempotency key is
a pure function of ``(schedule_id, campaign_id, experiment_id, slot_start)``, so
a restarted controller re-derives the same key for the same slot;
:meth:`~mayhem.infra.schedule_store.ScheduleStore.claim_slot` inserts it under
a primary key and never replaces. A repeat is a reported conflict, not a
silently rewritten row. A claim that was written but never settled is treated as
an *unknown* outcome and is not retried — re-running a dispatch whose fate
nobody recorded is the double fire this design exists to prevent, so resolving
one is an operator's decision, not a scheduler's guess.

**A non-fire is evidence.** Every evaluated schedule produces a
:class:`DispatchDecision`, whether it dispatched or not, carrying either the
schedule's own :class:`~mayhem.domain.scheduling.FireCode` or a
:class:`DispatchCode` for the gate that refused. A refusal is recorded in the
tick observation, not only returned, so "it did not run" always has a reason
attached to an instant.

Fairness is not decoration: :func:`order_by_fairness` decides the dispatch order
itself, reading the grant history back out of the durable claim ledger so the
history a restarted controller compares against is the history the previous one
built. The starvation guarantee is
:meth:`mayhem.domain.scheduling.FairnessPolicy.select_team`'s, and the test
suite proves it here by *removing* the starvation tier and the FIFO tiebreak and
watching the bound break rather than by restating the promise.

Game-day dispatch reuses the same machinery: a session step holds a schedule's
fire behind a facilitator hold, and :func:`release_hold` is the only way past
it. The hold lives in the store, so it is a gate the scheduler reads at fire
time — not a sleep it waits out, and not a flag a restart loses.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest
from mayhem.domain.scheduling import (
    ConcurrencyRequest,
    FairnessPolicy,
    FireDecision,
    GrantRecord,
    evaluate_concurrency,
)
from mayhem.infra.schedule_store import (
    DEFAULT_LOCK_WINDOW_S,
    ClaimOutcome,
    GameDayStepRecord,
    HoldState,
    RunClaimState,
    ScheduleEntry,
    ScheduleRunRecord,
    ScheduleStore,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.game_day import OperatorAcknowledgement
    from mayhem.domain.policy import ResourceLock

SCHEDULER_SCHEMA_VERSION: Final[str] = "1.0"

#: The policy a scheduler uses when none is configured: every team weighted the
#: same. Not "no fairness" — an actual equal-share policy, so a caller who never
#: configures one still gets a total, replayable order rather than list order.
DEFAULT_FAIRNESS: Final[FairnessPolicy] = FairnessPolicy(
    policy_id="default-equal-share",
    shares={"scheduler": 1.0},
    default_share=1.0,
    starvation_window=3,
    max_grants_per_window=1,
)

#: Characters of the idempotency digest kept in the derived run id. Enough to
#: make two slots of one schedule distinguishable in a log line, short enough
#: that the id stays readable when a refusal quotes it.
RUN_ID_DIGEST_CHARS: Final[int] = 16


# =============================================================================
# The world the scheduler reads at fire time
# =============================================================================


class CommanderOverride(BaseModel):
    """A named human accepting responsibility for firing during an incident.

    ``incident_id`` may be empty, which is a *blanket* override: the commander
    accepts responsibility for whatever is open. Naming an incident that is not
    the one open is refused at the incident gate rather than honoured, because
    an override written for the last incident is exactly the stale paperwork
    that should not authorise the next one.

    ``actor`` and ``reason`` are stripped and must survive stripping: a record
    naming "   " is not a named human, and the whole value of the override is
    that somebody can be held to it afterwards.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    actor: str
    reason: str
    at: datetime
    incident_id: str = ""

    @model_validator(mode="after")
    def _check_override(self) -> Self:
        for field_name in ("actor", "reason"):
            value = getattr(self, field_name)
            if not value.strip():
                msg = (
                    f"commander override {field_name} is blank; an override nobody can "
                    "be named to authorises nothing and accounts to no one"
                )
                raise InvariantViolationError(f"commander.{field_name}_blank", msg)
        if self.at.tzinfo is None or self.at.utcoffset() is None:
            msg = (
                "a commander override must be timestamped with an aware instant; a "
                "naive one cannot be ordered against the incident it authorises"
            )
            raise InvariantViolationError("commander.naive_at", msg)
        return self

    @property
    def describe(self) -> str:
        scope = self.incident_id or "any open incident"
        return f"{self.actor} ({scope}): {self.reason}"

    def covers(self, incident_id: str) -> bool:
        """True when this override was written for ``incident_id``."""
        return self.incident_id in {"", incident_id}


class IncidentState(BaseModel):
    """The incident the scheduler refuses to fire through without a human."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: str = Field(min_length=1)
    active: bool = True
    summary: str = ""

    def describe(self) -> str:
        state = "active" if self.active else "closed"
        detail = f" - {self.summary}" if self.summary else ""
        return f"incident {self.incident_id} ({state}){detail}"


class DeploymentState(BaseModel):
    """Deployment activity, which is not the moment for a chaos run.

    Both flags refuse, for the same reason: a run injected mid-deploy or into a
    frozen environment cannot be attributed to the deploy, and a rollback cannot
    be reasoned about while a drill is mutating the same nodes.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    frozen: bool = False
    in_progress: bool = False
    deployment_id: str = ""
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.frozen or self.in_progress

    def describe(self) -> str:
        if self.frozen:
            state = "frozen"
        elif self.in_progress:
            state = f"deploying {self.deployment_id}" if self.deployment_id else "deploying"
        else:
            state = "clear"
        detail = f" - {self.reason}" if self.reason else ""
        return f"deployment {state}{detail}"


# =============================================================================
# The dispatch vocabulary
# =============================================================================


class DispatchCode(StrEnum):
    """Why a fire attempt did or did not reach an executed run.

    A non-fire is evidence, so every value here is a *reason someone can act
    on*. The codes that mirror the schedule's own gates are deliberately absent:
    those live on :class:`~mayhem.domain.scheduling.FireCode` and reach the
    report through :attr:`DispatchDecision.fire`, so there is one vocabulary per
    decision and not two that overlap.
    """

    DISPATCHED = "schedule.dispatched"
    ALREADY_DISPATCHED = "schedule.already_dispatched"
    CLAIM_IN_FLIGHT = "schedule.claim_in_flight"
    DISABLED = "schedule.disabled"
    WINDOW_BUDGET_SPENT = "schedule.window_budget_spent"
    INCIDENT_ACTIVE = "schedule.incident_active"
    DEPLOYMENT_BLOCKED = "schedule.deployment_blocked"
    FACILITATOR_HOLD = "schedule.facilitator_hold"
    CONCURRENCY_QUEUED = "schedule.concurrency_queued"
    PLAN_FAILED = "schedule.plan_failed"
    ADMISSION_REFUSED = "schedule.admission_refused"
    APPROVAL_DENIED = "schedule.approval_denied"
    EXECUTION_FAILED = "schedule.execution_failed"


def slot_idempotency_key(
    *,
    schedule_id: str,
    campaign_id: str,
    experiment_id: str,
    slot_start: datetime,
) -> str:
    """The key that makes one fire slot fire at most once, ever.

    A pure function of the *slot's identity* and nothing else. No clock, no
    counter, no jitter: a restarted controller handed the same slot computes the
    same key, and the claim ledger's primary key does the rest. Jitter is
    excluded deliberately — it moves the effective instant, not the slot, and
    the slot is the thing that must not fire twice.
    """
    payload = {
        "schedule_id": schedule_id,
        "campaign_id": campaign_id,
        "experiment_id": experiment_id,
        "slot_start": slot_start.astimezone(UTC).isoformat(),
    }
    return f"sk-{digest(payload)[:32]}"


def slot_run_id(idempotency_key: str) -> str:
    """The run id one slot's dispatch takes, derived from its key.

    Derived rather than minted so it is identical before and after a restart,
    which is what lets the concurrency layer recognise a resumed attempt as the
    *same* run rather than as a second one racing the first.
    """
    body = idempotency_key.removeprefix("sk-") or idempotency_key
    return f"sr-{body[:RUN_ID_DIGEST_CHARS]}"


# -- the pipeline: the ordinary flow, as a port -------------------------------


@dataclass(frozen=True)
class PlannedDispatch:
    """What the planner produced for one scheduled run.

    ``dispatch`` is plan 13 Phase 4's addition and it is the reason this type is
    a dataclass with fields rather than a bare tuple: a planner that ran the
    shared compiler
    (:func:`mayhem.controller.campaign_dispatch.compile_campaign_run`) attaches
    the compilation it produced, and the admission gate judges *that* proof
    rather than recompiling one and hoping the two agree. It is optional and
    defaults to ``None``, which the campaign binding treats as **no proof at
    all** and refuses -- so a bespoke pipeline cannot borrow this module's
    admission gate without also bringing a proof.
    """

    plan: ExecutionPlan
    plan_digest: str = ""
    note: str = ""
    #: Whatever the planner produced alongside the plan, carried opaquely. Typed
    #: ``Any`` on purpose: this module must not import
    #: :mod:`mayhem.controller.campaign_dispatch`, which imports *this* module.
    dispatch: Any | None = None


@dataclass(frozen=True)
class GateVerdict:
    """One gate's answer. ``passed=False`` is a refusal, never a default."""

    passed: bool
    reason: str = ""
    rule_id: str = ""


@dataclass(frozen=True)
class ExecutionReceipt:
    """What the executor returned.

    An empty ``run_id`` is a *declared* failure the executor chose to report
    (the slot is settled ``failed`` and may be re-driven deliberately). A
    raising executor is a different thing entirely — the outcome is unknown, so
    the claim is left unsettled and nothing retries the slot. See
    :meth:`Scheduler.tick`.
    """

    run_id: str
    outcome_id: str = ""
    detail: str = ""


@dataclass(frozen=True)
class DispatchRequest:
    """One scheduled run on its way through the pipeline."""

    idempotency_key: str
    schedule_id: str
    campaign_id: str
    experiment_id: str
    team: str
    slot_start: datetime
    effective_at: datetime
    requested_at: datetime
    window_index: int
    concurrency: ConcurrencyRequest
    fire: FireDecision


PlannerFn = Callable[[DispatchRequest], PlannedDispatch]
GateFn = Callable[[DispatchRequest, PlannedDispatch], GateVerdict]
ExecutorFn = Callable[[DispatchRequest, PlannedDispatch], ExecutionReceipt]

#: Which code a *raising* gate is recorded under. The planner has its own entry
#: because it is asked before there is a plan to hand a gate; see
#: :meth:`Scheduler._enter_pipeline`.
_GATE_REFUSALS: Final[dict[str, DispatchCode]] = {
    "admission": DispatchCode.ADMISSION_REFUSED,
    "approval": DispatchCode.APPROVAL_DENIED,
}


@dataclass(frozen=True)
class DispatchPipeline:
    """The normal plan → admit → approve → execute flow, as four callables.

    Every field is required and none has a default. That is the whole
    enforcement of "a scheduled run is never exempt from admission, approval, or
    the safety gate": there is no way to build a pipeline that skips one, so
    there is no code path in which a schedule runs ungated. The order is the
    ordinary one — may this plan exist at all, then is this run approved, then
    run it — matching :func:`mayhem.controller.safety.validate_plan`, where the
    policy gate speaks before the approval gate because an approval cannot
    legalise a plan the policy half refuses.

    Bind them to the ordinary controllers: ``planner`` to the campaign planner,
    ``admission`` to :func:`mayhem.controller.safety.validate_plan`,
    ``approver`` to :func:`mayhem.controller.approval_gate.verify_approvals`,
    ``executor`` to the campaign executor.
    """

    planner: PlannerFn
    admission: GateFn
    approver: GateFn
    executor: ExecutorFn


# -- what a tick produced ------------------------------------------------------


class DispatchDecision(BaseModel):
    """The recorded outcome of one schedule in one tick.

    ``code`` is ``None`` exactly when the *schedule itself* refused to fire; in
    that case :attr:`fire` holds the schedule's own
    :class:`~mayhem.domain.scheduling.FireCode` and reason, and
    :attr:`schedule_code` is the accessor that names either vocabulary. Any
    other code is a gate in this module refusing a fire the schedule had
    cleared.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schedule_id: str
    idempotency_key: str = ""
    dispatched: bool = False
    code: DispatchCode | None = None
    reason: str = ""
    now: datetime
    team: str = ""
    fire: FireDecision | None = None
    run_id: str = ""
    #: The run this one is queued behind, named from the concurrency verdict.
    queued_behind: str = ""
    blocking_experiment_id: str = ""
    blocking_resource: str = ""
    #: Gates cleared before whatever happened, in order.
    gates: tuple[str, ...] = ()

    @property
    def schedule_code(self) -> str:
        """The schedule's own code when it did not fire, else this module's."""
        if self.code is not None:
            return self.code.value
        return self.fire.code.value if self.fire is not None else ""

    @property
    def held(self) -> bool:
        """True when nothing ran: the attempt is evidence, not a fire."""
        return not self.dispatched

    def describe(self) -> str:
        verdict = "DISPATCHED" if self.dispatched else "HELD"
        body = self.reason or self.schedule_code
        owner = f" queued behind {self.queued_behind}" if self.queued_behind else ""
        return f"{self.schedule_id}: {verdict} [{self.schedule_code}]{owner} {body}"


class TickReport(BaseModel):
    """Everything one :meth:`Scheduler.tick` decided, in the order it decided it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    controller_id: str = ""
    now: datetime
    window_index: int
    decisions: tuple[DispatchDecision, ...] = ()
    #: The fairness grants this tick attempted, in the order fairness chose.
    grants: tuple[GrantRecord, ...] = ()

    @property
    def dispatched(self) -> tuple[DispatchDecision, ...]:
        return tuple(decision for decision in self.decisions if decision.dispatched)

    @property
    def held(self) -> tuple[DispatchDecision, ...]:
        return tuple(decision for decision in self.decisions if decision.held)

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(decision.schedule_code for decision in self.decisions)

    def for_schedule(self, schedule_id: str) -> DispatchDecision | None:
        for decision in self.decisions:
            if decision.schedule_id == schedule_id:
                return decision
        return None

    def describe(self) -> str:
        return (
            f"tick at {self.now.isoformat()} (window {self.window_index}): "
            f"{len(self.dispatched)} dispatched, {len(self.held)} held"
        )

    def to_payload(self) -> dict[str, object]:
        """The JSON-able body recorded as this tick's observation."""
        return {
            "schema_version": SCHEDULER_SCHEMA_VERSION,
            "controller_id": self.controller_id,
            "now": self.now.isoformat(),
            "window_index": self.window_index,
            "grants": [grant.model_dump(mode="json") for grant in self.grants],
            "decisions": [decision.model_dump(mode="json") for decision in self.decisions],
        }


# =============================================================================
# Inputs
# =============================================================================


@dataclass(frozen=True)
class SchedulerInputs:
    """Everything a tick reads besides the schedules themselves.

    ``now`` and ``window_index`` are required rather than defaulted, and the
    difference matters. ``now`` is the fire instant the schedule's own gates are
    evaluated against — the scheduler never reads a clock. ``window_index`` is
    the fairness window this tick belongs to, and it is caller-owned because a
    *per-schedule* counter would leave each schedule convinced it is in a
    different window, which is precisely how a starvation guarantee stops
    meaning anything. Reusing an index is a fairness coordinate, never a fire
    permission: a slot already claimed stays claimed whatever the index says.

    The live-world fields default to "nothing is happening", which is a
    *conservative* default in the safe direction for the ones that block
    (no incident, no deployment, no holds, no active runs) and the permissive
    one for ``dispatch_budget`` (unbounded), which is why it is a separate
    explicit argument.
    """

    now: datetime
    window_index: int
    incident: IncidentState | None = None
    deployment: DeploymentState | None = None
    commander_override: CommanderOverride | None = None
    active_requests: tuple[ConcurrencyRequest, ...] = ()
    active_locks: tuple[ResourceLock, ...] = ()
    #: Dispatch slots issuable in this window; ``None`` means unbounded.
    dispatch_budget: int | None = None

    def __post_init__(self) -> None:
        if self.now.tzinfo is None or self.now.utcoffset() is None:
            msg = (
                "scheduler inputs require a timezone-aware `now`; a naive clock makes "
                "every fire decision unreproducible"
            )
            raise InvariantViolationError("scheduler.naive_clock", msg)
        if self.window_index < 0:
            msg = f"scheduler window_index must be >= 0, got {self.window_index}"
            raise InvariantViolationError("scheduler.window_index", msg)
        if self.dispatch_budget is not None and self.dispatch_budget < 0:
            msg = f"scheduler dispatch_budget must be >= 0, got {self.dispatch_budget}"
            raise InvariantViolationError("scheduler.dispatch_budget", msg)

    def with_now(self, now: datetime) -> SchedulerInputs:
        """The same inputs as of a different instant — a replay, not a re-plan."""
        return SchedulerInputs(
            now=now,
            window_index=self.window_index,
            incident=self.incident,
            deployment=self.deployment,
            commander_override=self.commander_override,
            active_requests=self.active_requests,
            active_locks=self.active_locks,
            dispatch_budget=self.dispatch_budget,
        )


# =============================================================================
# Fairness ordering
# =============================================================================


@dataclass(frozen=True)
class DueSchedule:
    """A schedule whose own gates cleared, paired with the decision that said so.

    The pairing is the point: a schedule fires on a *slot*, and two schedules of
    the same team competing for one window have to be ordered by which slot they
    are competing for, not by whichever one happened to be registered first. The
    entry's persisted ``last_slot_start`` is history and must never be used for
    that comparison.
    """

    entry: ScheduleEntry
    fire: FireDecision

    @property
    def slot_start(self) -> datetime:
        """The slot being contended. Non-``None`` for any fired decision."""
        return self.fire.slot_start or self.fire.now


@dataclass(frozen=True)
class FairnessOrder:
    """The dispatch order fairness chose, and what it deferred."""

    ordered: tuple[DueSchedule, ...]
    deferred: tuple[DueSchedule, ...]
    grants: tuple[GrantRecord, ...]

    @property
    def teams(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(grant.team for grant in self.grants))


def order_by_fairness(
    due: Sequence[DueSchedule],
    policy: FairnessPolicy,
    history: Sequence[GrantRecord],
    *,
    window_index: int,
) -> FairnessOrder:
    """Order due schedules by :meth:`FairnessPolicy.select_team`.

    Pure, and the same loop :meth:`FairnessPolicy.simulate_fairness` runs, over
    real schedules instead of team names. Each round asks the policy which team
    gets the next slot, takes that team's earliest due schedule, and appends the
    grant to a *local* history so the next round sees it. Round count is the
    policy's ``max_grants_per_window``: schedules that would have been
    considered past that are returned as ``deferred`` rather than dropped, so
    the caller can record why they did not run.

    ``due`` is sorted by ``(slot_start, schedule_id)`` before the first round so
    "this team's earliest due schedule" is a function of the arguments and not
    of the order SQLite happened to return rows in.
    """
    queued: dict[str, list[DueSchedule]] = {}
    for candidate in sorted(due, key=lambda item: (item.slot_start, item.entry.schedule_id)):
        queued.setdefault(candidate.entry.team, []).append(candidate)
    local = list(history)
    ordered: list[DueSchedule] = []
    grants: list[GrantRecord] = []
    for _ in range(policy.max_grants_per_window):
        pending = tuple(sorted(queued))
        if not pending:
            break
        team = policy.select_team(pending, local, window_index=window_index)
        if team is None:
            break
        chosen = queued[team].pop(0)
        # Prune the team once it has nothing left asking: a team key with an
        # empty list would otherwise be handed to ``select_team`` as a demanding
        # team and then popped from nothing.
        if not queued[team]:
            del queued[team]
        ordered.append(chosen)
        grant = GrantRecord(
            window_index=window_index, team=team, schedule_id=chosen.entry.schedule_id
        )
        grants.append(grant)
        local.append(grant)
    chosen_ids = {candidate.entry.schedule_id for candidate in ordered}
    deferred = tuple(
        candidate for candidate in due if candidate.entry.schedule_id not in chosen_ids
    )
    return FairnessOrder(ordered=tuple(ordered), deferred=deferred, grants=tuple(grants))


# =============================================================================
# Game-day holds
# =============================================================================


def release_hold(
    step: GameDayStepRecord, acknowledgement: OperatorAcknowledgement, *, at: str
) -> GameDayStepRecord:
    """Release a held game-day dispatch step, naming the facilitator.

    Raises:
        InvariantViolationError: If the step is not held, names no facilitator,
            or the acknowledgement carries no reason. A hold released by nobody
            in particular is indistinguishable from a hold that expired, and an
            expiry nobody can audit is not a gate.
    """
    if not acknowledgement.actor.strip():
        msg = (
            f"game-day step {step.key!r} cannot be released without naming the "
            "facilitator who released it"
        )
        raise InvariantViolationError("game_day.hold_needs_facilitator", msg)
    if not acknowledgement.reason.strip():
        msg = (
            f"game-day step {step.key!r} cannot be released without a reason; a "
            "hold that opens for no stated cause is not reviewable afterwards"
        )
        raise InvariantViolationError("game_day.hold_needs_reason", msg)
    if step.hold_state is not HoldState.HELD:
        msg = (
            f"game-day step {step.key!r} is {step.hold_state.value}, not held; "
            "releasing it again would erase who actually let it run"
        )
        raise InvariantViolationError("game_day.hold_not_held", msg)
    return step.model_copy(
        update={
            "hold_state": HoldState.RELEASED,
            "released_by": acknowledgement.actor,
            "released_at": acknowledgement.at or at,
            "updated_at": at,
        }
    )


def mark_dispatched(step: GameDayStepRecord, *, at: str) -> GameDayStepRecord:
    """Record that a released step's dispatch actually ran."""
    if step.hold_state is HoldState.HELD:
        msg = (
            f"game-day step {step.key!r} cannot be marked dispatched while it is "
            "still held; the hold is the gate and it has not been released"
        )
        raise InvariantViolationError("game_day.step_still_held", msg)
    return step.model_copy(
        update={
            "hold_state": HoldState.DISPATCHED,
            "dispatched_at": step.dispatched_at or at,
            "updated_at": at,
        }
    )


# =============================================================================
# The service
# =============================================================================


class Scheduler:
    """Evaluates due schedules and dispatches the fair subset of them.

    The only class here with state, and its state is entirely in the store: a
    restarted :class:`Scheduler` over the same database is the same scheduler.
    ``pipeline`` and ``fairness`` are configuration, not memory.
    """

    def __init__(
        self,
        *,
        store: ScheduleStore,
        pipeline: DispatchPipeline,
        fairness: FairnessPolicy | None = None,
        controller_id: str = "",
    ) -> None:
        self._store = store
        self._pipeline = pipeline
        self._fairness = fairness or DEFAULT_FAIRNESS
        self.controller_id = controller_id

    @property
    def fairness(self) -> FairnessPolicy:
        return self._fairness

    # -- registration -------------------------------------------------------

    def register(self, entry: ScheduleEntry) -> ScheduleEntry:
        """Register (or replace) one schedule and return it as persisted."""
        return self._store.save_schedule(entry)

    def schedules(self, *, enabled_only: bool = False) -> tuple[ScheduleEntry, ...]:
        return self._store.list_schedules(enabled_only=enabled_only)

    def resume_window_index(self) -> int:
        """The fairness window this deployment was last in.

        A restart mid-window passes this straight back, so the numbering stays
        continuous and the fairness history lines up. It grants no permission:
        a slot whose claim is already in the ledger is refused whatever window
        the caller claims to be in.
        """
        return self._store.max_window_index()

    def grant_history(self, *, upto_window: int | None = None) -> tuple[GrantRecord, ...]:
        """Every dispatch ever made, as fairness grants, read from the ledger."""
        return self._store.grant_history(upto_window=upto_window)

    # -- the tick -----------------------------------------------------------

    def tick(self, inputs: SchedulerInputs) -> TickReport:
        """Evaluate every registered schedule once and dispatch what may run.

        The order of the whole tick:

        1. **Evaluate** every registered schedule at ``inputs.now`` — including
           disabled ones, which are recorded as held, so "it did not run because
           it is switched off" is an answer rather than an absence.
        2. **Order** the ones that fired through
           :func:`order_by_fairness`, reading the grant history out of the
           durable ledger.
        3. **Dispatch** in that order, spending at most
           ``max_grants_per_window`` slots and at most ``dispatch_budget``
           dispatches, refusing each candidate at the first gate it fails.

        A raising ``executor`` propagates. That is deliberate and it is the
        conservative direction: the claim stays ``claimed``, the slot is refused
        to everyone afterwards as an unknown outcome, and the operator decides
        what happened. Swallowing the exception and settling the slot would
        either claim the run did not happen (it may have) or that it did (nobody
        knows), and the first of those is how a scheduler runs the same drill
        twice.
        """
        now = inputs.now
        decisions: list[DispatchDecision] = []
        due: list[DueSchedule] = []
        for entry in self._store.list_schedules():
            if not entry.enabled:
                decisions.append(
                    self._refusal(
                        entry,
                        inputs,
                        code=DispatchCode.DISABLED,
                        reason=f"schedule {entry.schedule_id} is disabled",
                    )
                )
                self._touch(entry, window_index=inputs.window_index)
                continue
            fire = entry.schedule.evaluate(now=now, run_count=entry.run_count)
            if not fire.fired:
                decisions.append(
                    DispatchDecision(
                        schedule_id=entry.schedule_id,
                        now=now,
                        team=entry.team,
                        fire=fire,
                        reason=fire.reason,
                    )
                )
                self._touch(entry, window_index=inputs.window_index)
                continue
            due.append(DueSchedule(entry=entry, fire=fire))

        order = order_by_fairness(
            due, self._fairness, self._store.grant_history(), window_index=inputs.window_index
        )
        live = list(inputs.active_requests)
        budget = inputs.dispatch_budget
        for candidate in order.ordered:
            if budget is not None and budget <= 0:
                decisions.append(
                    self._refusal(
                        candidate.entry,
                        inputs,
                        code=DispatchCode.WINDOW_BUDGET_SPENT,
                        reason=(
                            f"the window's dispatch budget of {inputs.dispatch_budget} "
                            f"is spent; window {inputs.window_index} issued no further slot"
                        ),
                    )
                )
                continue
            decision = self._dispatch(candidate, inputs=inputs, live=live)
            decisions.append(decision)
            if decision.dispatched and budget is not None:
                budget -= 1
        for candidate in order.deferred:
            decisions.append(
                self._refusal(
                    candidate.entry,
                    inputs,
                    code=DispatchCode.WINDOW_BUDGET_SPENT,
                    reason=(
                        f"deferred: fairness spent this window's "
                        f"{self._fairness.max_grants_per_window} grant(s) on "
                        f"{list(order.teams)}"
                    ),
                )
            )
        report = TickReport(
            controller_id=self.controller_id,
            now=now,
            window_index=inputs.window_index,
            decisions=tuple(decisions),
            grants=order.grants,
        )
        self._store.record_tick(report.to_payload(), controller_id=self.controller_id)
        return report

    # -- one dispatch -------------------------------------------------------

    def _dispatch(
        self,
        candidate: DueSchedule,
        *,
        inputs: SchedulerInputs,
        live: list[ConcurrencyRequest],
    ) -> DispatchDecision:
        """Take one due schedule through the pre-gates and the pipeline.

        Refusal order is most-actionable-first and every step is a hard
        refusal: deployment, then the incident, then the game-day hold, then
        concurrency, then the claim, then the pipeline. The claim comes *last*
        among the pre-gates on purpose — a slot that is refused for an active
        incident has not fired, and consuming its key would retire the slot for
        the rest of its window over a condition that may well clear.

        ``live`` is the set of runs that currently hold the resources this
        candidate names, and a successful dispatch *adds to it* before returning.
        That is what makes "the second run queues behind the first" a fact
        about the state of this tick rather than a message: two due schedules
        contending for one database in one window cannot both run, because the
        second one is compared against a set that already contains the first.
        """
        entry, fire = candidate.entry, candidate.fire
        now = inputs.now
        slot = fire.slot_start or now
        effective = fire.effective_at or now
        key = slot_idempotency_key(
            schedule_id=entry.schedule_id,
            campaign_id=entry.campaign_id,
            experiment_id=entry.experiment_id,
            slot_start=slot,
        )
        request = ConcurrencyRequest(
            run_id=slot_run_id(key),
            experiment_id=entry.experiment_id,
            team=entry.team,
            concurrency_class=entry.concurrency_class,
            resources=entry.resources,
            acquired_at=effective,
            expires_at=effective + timedelta(seconds=entry.lock_window_s),
        )
        request_pair = DispatchRequest(
            idempotency_key=key,
            schedule_id=entry.schedule_id,
            campaign_id=entry.campaign_id,
            experiment_id=entry.experiment_id,
            team=entry.team,
            slot_start=slot,
            effective_at=effective,
            requested_at=now,
            window_index=inputs.window_index,
            concurrency=request,
            fire=fire,
        )

        deployment = inputs.deployment
        if deployment is not None and deployment.blocked:
            return self._refusal(
                entry,
                inputs,
                code=DispatchCode.DEPLOYMENT_BLOCKED,
                reason=f"refused during {deployment.describe()}",
                request=request_pair,
            )
        incident = self._incident_refusal(inputs)
        if incident is not None:
            return self._refusal(entry, inputs, code=DispatchCode.INCIDENT_ACTIVE, reason=incident,
                                 request=request_pair)
        held = [step for step in self._store.steps_for_schedule(entry.schedule_id) if step.held]
        if held:
            names = ", ".join(step.key for step in held)
            return self._refusal(
                entry,
                inputs,
                code=DispatchCode.FACILITATOR_HOLD,
                reason=(
                    f"game-day step(s) {names} hold this schedule's fire; a facilitator "
                    "must release the hold before the dispatch may run"
                ),
                request=request_pair,
            )
        verdict = evaluate_concurrency(
            live, request, inputs.active_locks, now=now
        )
        if not verdict.runnable:
            return self._refusal(
                entry,
                inputs,
                code=DispatchCode.CONCURRENCY_QUEUED,
                reason=verdict.reason,
                request=request_pair,
                queued_behind=verdict.queued_behind(),
                blocking_experiment_id=verdict.blocking_experiment_id,
                blocking_resource=verdict.blocking_resource,
            )

        claim = self._store.claim_slot(
            ScheduleRunRecord(
                idempotency_key=key,
                schedule_id=entry.schedule_id,
                team=entry.team,
                campaign_id=entry.campaign_id,
                experiment_id=entry.experiment_id,
                window_index=inputs.window_index,
                slot_start=slot,
                effective_at=effective,
                controller_id=self.controller_id,
                recorded_at=now,
            )
        )
        if claim.outcome is not ClaimOutcome.CLAIMED:
            holder = claim.holder
            assert holder is not None
            if holder.state is RunClaimState.CLAIMED and not holder.settled:
                code = DispatchCode.CLAIM_IN_FLIGHT
                reason = (
                    f"slot {slot.isoformat()} was claimed by controller "
                    f"{holder.controller_id or 'unknown'} at "
                    f"{holder.recorded_at.isoformat()} and never settled; its outcome "
                    "is unknown, so it is not retried"
                )
            else:
                code = DispatchCode.ALREADY_DISPATCHED
                reason = (
                    f"slot {slot.isoformat()} already ran as {holder.run_id or holder.state.value} "
                    f"under key {key}"
                )
            return DispatchDecision(
                schedule_id=entry.schedule_id,
                idempotency_key=key,
                code=code,
                reason=reason,
                now=now,
                team=entry.team,
                fire=fire,
                queued_behind=holder.controller_id,
            )

        return self._enter_pipeline(entry, fire, request_pair, inputs=inputs, live=live)

    def _enter_pipeline(
        self,
        entry: ScheduleEntry,
        fire: FireDecision,
        request: DispatchRequest,
        *,
        inputs: SchedulerInputs,
        live: list[ConcurrencyRequest],
    ) -> DispatchDecision:
        """Run plan → admission → approval → execute, refusing at the first gate."""
        now = inputs.now
        gates: list[str] = []

        def refusal(code: DispatchCode, reason: str, rule_id: str = "") -> DispatchDecision:
            self._store.settle_slot(
                request.idempotency_key,
                state=RunClaimState.FAILED,
                code=code.value,
                reason=reason,
                at=now,
                detail={"rule_id": rule_id, "gates": tuple(gates)},
            )
            return DispatchDecision(
                schedule_id=entry.schedule_id,
                idempotency_key=request.idempotency_key,
                code=code,
                reason=reason,
                now=now,
                team=entry.team,
                fire=fire,
                gates=tuple(gates),
            )

        def cleared(stage: str, call: GateFn) -> GateVerdict | DispatchDecision:
            """Run one gate, turning a *raising* gate into a refusal.

            A gate that raises has refused — it just refused by exception rather
            than by verdict, which is exactly how
            :func:`mayhem.controller.safety.validate_plan` refuses. Swallowing it
            into a :class:`DispatchDecision` is what lets the real gates be bound
            to this port unchanged instead of being wrapped in an adapter that
            could be forgotten.

            It is safe here and *not* safe for the executor because nothing has
            run yet: a gate that raised ran no fault, so settling the slot
            ``failed`` is an honest record rather than a guess. The executor is
            called bare for the opposite reason.

            ``stage`` is appended to ``gates`` only when the gate *passes*, so
            ``DispatchDecision.gates`` reads as the list of gates this run
            actually cleared rather than the list it was asked.
            """
            try:
                verdict = call(request, planned)
            except Exception as exc:
                # A port's failure mode is whatever its implementation raises;
                # naming the type in the reason is what makes that auditable.
                return refusal(
                    _GATE_REFUSALS[stage],
                    f"{stage} refused by raising {type(exc).__name__}: {exc}",
                )
            if not verdict.passed:
                return refusal(_GATE_REFUSALS[stage], verdict.reason, verdict.rule_id)
            gates.append(stage)
            return verdict

        try:
            planned = self._pipeline.planner(request)
        except Exception as exc:
            # A planner that raises is a refusal, not a crash: the slot is
            # settled `failed` and is not retried, so a broken planner cannot
            # become a retry storm.
            return refusal(DispatchCode.PLAN_FAILED, f"planner raised {type(exc).__name__}: {exc}")
        admission = cleared("admission", self._pipeline.admission)
        if not isinstance(admission, GateVerdict):
            return admission
        approval = cleared("approval", self._pipeline.approver)
        if not isinstance(approval, GateVerdict):
            return approval
        gates.append("execute")
        # Deliberately not wrapped: a raising executor is an *unknown outcome*,
        # not a refusal. The claim stays `claimed`, the slot is refused to
        # everyone afterwards, and an operator decides. See ``Scheduler.tick``.
        receipt = self._pipeline.executor(request, planned)
        if not receipt.run_id:
            return refusal(
                DispatchCode.EXECUTION_FAILED,
                receipt.detail or "executor returned no run id",
            )
        self._store.settle_slot(
            request.idempotency_key,
            state=RunClaimState.DISPATCHED,
            code=DispatchCode.DISPATCHED.value,
            reason=f"dispatched as {receipt.run_id}",
            at=now,
            run_id=receipt.run_id,
            detail={"outcome_id": receipt.outcome_id, "gates": tuple(gates)},
        )
        self._store.save_schedule(
            entry.after_dispatch(
                slot_start=request.slot_start, at=now, window_index=inputs.window_index
            )
        )
        self._mark_steps_dispatched(entry.schedule_id, at=now.isoformat())
        # The run now holds what it declared for the rest of the tick. Adding it
        # *after* the pipeline returns (rather than before) is what keeps a
        # failed dispatch from fencing the resource it never got.
        live.append(request.concurrency)
        return DispatchDecision(
            schedule_id=entry.schedule_id,
            idempotency_key=request.idempotency_key,
            dispatched=True,
            code=DispatchCode.DISPATCHED,
            reason=receipt.detail or f"dispatched as {receipt.run_id}",
            now=now,
            team=entry.team,
            fire=fire,
            run_id=receipt.run_id,
            gates=tuple(gates),
        )

    # -- helpers ------------------------------------------------------------

    def _touch(self, entry: ScheduleEntry, *, window_index: int) -> None:
        """Persist a schedule a tick looked at, if that tick changed anything.

        A poll loop evaluates every schedule on every tick, and most ticks
        change nothing about a schedule that was already seen in this window.
        Writing the row regardless would turn a no-op evaluation into a durable
        write, so the comparison is done here and the store is only touched when
        the entry would actually differ.
        """
        seen = entry.seen_in(window_index=window_index)
        if seen != entry:
            self._store.save_schedule(seen)

    def _mark_steps_dispatched(self, schedule_id: str, *, at: str) -> None:
        """Move every released game-day step for this schedule to ``dispatched``."""
        for step in self._store.steps_for_schedule(schedule_id):
            if step.released:
                self._store.save_step(mark_dispatched(step, at=at))

    def _incident_refusal(self, inputs: SchedulerInputs) -> str | None:
        """Why an active incident refuses this fire, or ``None`` when it may run."""
        incident = inputs.incident
        if incident is None or not incident.active:
            return None
        override = inputs.commander_override
        if override is None:
            return (
                f"{incident.describe()}; firing during an incident needs a named "
                "commander override"
            )
        if not override.covers(incident.incident_id):
            return (
                f"{incident.describe()}; the commander override names "
                f"{override.incident_id or 'nothing'!r} and does not cover it"
            )
        return None

    def _refusal(
        self,
        entry: ScheduleEntry,
        inputs: SchedulerInputs,
        *,
        code: DispatchCode,
        reason: str,
        request: DispatchRequest | None = None,
        queued_behind: str = "",
        blocking_experiment_id: str = "",
        blocking_resource: str = "",
    ) -> DispatchDecision:
        """Build a pre-claim refusal. Writes nothing to the claim ledger."""
        return DispatchDecision(
            schedule_id=entry.schedule_id,
            idempotency_key=request.idempotency_key if request is not None else "",
            code=code,
            reason=reason,
            now=inputs.now,
            team=entry.team,
            queued_behind=queued_behind,
            blocking_experiment_id=blocking_experiment_id,
            blocking_resource=blocking_resource,
        )


def scheduling_state(entries: Sequence[ScheduleEntry], *, now: datetime) -> dict[str, str]:
    """A one-line-per-schedule readiness view, for reports and CLI surfaces.

    Deliberately a *view* and not a decision: it calls
    :meth:`Schedule.next_fire_time` and says nothing about whether a run would
    be admitted, because that depends on live state this function does not read.
    """
    view: dict[str, str] = {}
    for entry in sorted(entries, key=lambda item: item.schedule_id):
        upcoming = entry.schedule.next_fire_time(now)
        when = upcoming.isoformat() if upcoming is not None else "retired"
        state = "enabled" if entry.enabled else "disabled"
        view[entry.schedule_id] = f"{entry.schedule.describe()} -> {when} ({state})"
    return view


__all__ = [
    "DEFAULT_FAIRNESS",
    "DEFAULT_LOCK_WINDOW_S",
    "SCHEDULER_SCHEMA_VERSION",
    "CommanderOverride",
    "DeploymentState",
    "DispatchCode",
    "DispatchDecision",
    "DispatchPipeline",
    "DispatchRequest",
    "ExecutionReceipt",
    "FairnessOrder",
    "GateVerdict",
    "IncidentState",
    "PlannedDispatch",
    "ScheduleEntry",
    "Scheduler",
    "SchedulerInputs",
    "TickReport",
    "mark_dispatched",
    "order_by_fairness",
    "release_hold",
    "slot_idempotency_key",
    "slot_run_id",
]
