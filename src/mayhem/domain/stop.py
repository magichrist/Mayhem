"""Emergency-stop vocabulary: reasons, commands, and the pure escalation ladder
(docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md, Phase 1).

Phase 1 is vocabulary and pure predicates. Nothing here freezes a dispatch, undoes
an action, promotes a standby, or opens a socket — it defines the words those
layers will use and the rules that make the words unforgeable.

Four types carry the contract:

* :class:`StopReason` — *why* a run stopped. Five members, no more: a human, a
  fired runtime condition, a preflight refusal, a lost controller, an applied
  override. There is no ``UNKNOWN`` member and no free-text escape hatch: a
  reason that can be spelled at a call site is a reason that will be spelled one
  day, and a stop whose cause cannot be named is a stop nobody can learn from.
* :class:`StopTrigger` — a reason bound to the evidence that produced it: the
  condition id and the values observed when it tripped. The binding is what
  makes "every stop path maps to exactly one reason" a *type* rule rather than a
  convention. A :class:`StopSignal` (how the stop was raised) resolves through
  :data:`_REASON_FOR_SIGNAL` to its one legal reason, so a trigger cannot claim
  a condition id it has no business carrying — a "human" stop that also names a
  tripped condition is a mislabelled stop, and is refused.
* :class:`StopCommand` — who asked, when, and over what scope: one run, or the
  whole environment. A run-scoped command must name its run; an environment-wide
  one must name its environment and may not smuggle a run id along, so "stop
  everything except that one run" is unrepresentable rather than merely
  discouraged. Authorisation for the environment-wide case is plan 09's job and
  is deliberately *not* modelled here — Phase 1 owns the vocabulary, not the
  role check.
* :class:`PostflightReport` — per-check pass/fail with evidence references. A
  ``pass`` line with no evidence reference is malformed, not passing: it is
  refused at construction, exactly as a lease cannot become ``ACTIVE`` without
  write-ahead undo ops (:mod:`mayhem.domain.leases`). The report's
  :attr:`~PostflightReport.verdict` is recomputed from its checks on every read,
  so "probably recovered" is not a state a caller can assert.

The ladder (:func:`stop_flow`, :func:`mandatory_stages`, :func:`next_stage`) is
the emergency stop flow the plan spells out — freeze, cancel pending, compensate
active, reconcile, residue-scan, verify, seal — projected onto run state. It
*extends* :class:`mayhem.domain.cancellation.CancellationLevel` by reference
rather than forking a second escalation scale: each stage names the cancellation
level it needs, and the mandatory set for a run state never shrinks as that
level rises. The mutable :class:`mayhem.domain.cancellation.CancellationToken` is
deliberately not used — the ladder is a pure function over run state, which is
what makes it testable without a thread.

Time is never read implicitly. Every time-dependent predicate takes ``now`` as an
injected argument defaulting to ``utc_now()`` (the convention in
:mod:`mayhem.domain.leases`), and every timestamp is tz-aware by validation
(DTZ discipline).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.cancellation import CancellationLevel
from mayhem.domain.common import Duration, utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import canonical_json, sha256_hex


class StopReason(StrEnum):
    """Why a run stopped. The exhaustive, closed set of causes.

    Every member is a *cause*, never a severity and never a catch-all. Adding a
    member here is a claim that the cause is distinguishable in sealed evidence,
    which is a Phase 4 decision — not a convenience.
    """

    HUMAN = "human"
    CONDITION_FIRED = "condition_fired"
    PREFLIGHT_FAILED = "preflight_failed"
    CONTROLLER_LOST = "controller_lost"
    OVERRIDE = "override"


class StopSignal(StrEnum):
    """How a stop was *raised* — the stop path, before it acquires a reason.

    This is the vocabulary a detector, an operator console, or the preflight
    gate speaks in. Every path maps to exactly one :class:`StopReason` through
    :data:`_REASON_FOR_SIGNAL`; the mapping is total in both directions, so a
    path cannot be added without also committing to the reason it produces.
    """

    OPERATOR_REQUEST = "operator_request"
    CONDITION_TRIPPED = "condition_tripped"
    PREFLIGHT_REFUSAL = "preflight_refusal"
    CONTROLLER_LOST = "controller_lost"
    OVERRIDE_APPLIED = "override_applied"


_REASON_FOR_SIGNAL: Final[dict[StopSignal, StopReason]] = {
    StopSignal.OPERATOR_REQUEST: StopReason.HUMAN,
    StopSignal.CONDITION_TRIPPED: StopReason.CONDITION_FIRED,
    StopSignal.PREFLIGHT_REFUSAL: StopReason.PREFLIGHT_FAILED,
    StopSignal.CONTROLLER_LOST: StopReason.CONTROLLER_LOST,
    StopSignal.OVERRIDE_APPLIED: StopReason.OVERRIDE,
}
"""The reason each stop path produces. Exhaustive over both enums, by test."""


def reason_for(signal: StopSignal) -> StopReason:
    """The one reason *signal* may carry.

    Raises:
        InvariantViolationError: If the signal is not in the mapping — which can
            only happen if a member were added to one enum and not the other.
    """
    try:
        return _REASON_FOR_SIGNAL[StopSignal(signal)]
    except (KeyError, ValueError) as exc:
        msg = f"stop signal {signal!r} has no mapped reason"
        raise InvariantViolationError("stop_signal_without_reason", msg) from exc


class RunState(StrEnum):
    """The run-state projection the stop ladder reasons about.

    Deliberately narrower than :class:`mayhem.domain.run_outcome.RunStatus`: the
    ladder needs to know only whether anything was injected and whether the run
    is still open, and importing the run-record status would couple stop
    vocabulary to storage shape. ``FINISHED`` and ``STOPPED`` are the terminals —
    a stop raised against either is a command with nothing to escalate.
    """

    PENDING = "pending"  # accepted; nothing injected yet
    RUNNING = "running"  # actively injecting and/or observing
    FINISHED = "finished"  # completed without a stop (terminal)
    STOPPED = "stopped"  # stop already sealed (terminal)

    @property
    def is_terminal(self) -> bool:
        return self in (RunState.FINISHED, RunState.STOPPED)


class StopStage(StrEnum):
    """The emergency stop flow, one rung per step (the plan's flow verbatim).

    ``FREEZE`` through ``VERIFY`` are the recovery work; ``SEAL`` is what makes
    it evidence. Each stage names the :class:`CancellationLevel` it needs, so
    escalation reuses the existing ladder rather than inventing a second one.
    """

    FREEZE = "freeze"  # stop dispatching new actions
    CANCEL_PENDING = "cancel_pending"  # cancel queued, not-yet-injected actions
    COMPENSATE_ACTIVE = "compensate_active"  # undo what already landed
    RECONCILE = "reconcile"  # compare observed state against intent
    RESIDUE_SCAN = "residue_scan"  # look for what the undo missed
    VERIFY = "verify"  # assert the system is actually clean
    SEAL = "seal"  # seal the evidence


STOP_FLOW: Final[tuple[StopStage, ...]] = tuple(StopStage)
"""The canonical flow, in order — the order stages are owed in."""

_STAGE_LEVEL: Final[dict[StopStage, CancellationLevel]] = {
    StopStage.FREEZE: CancellationLevel.GRACE,
    StopStage.CANCEL_PENDING: CancellationLevel.GRACE,
    StopStage.COMPENSATE_ACTIVE: CancellationLevel.TERM,
    StopStage.RECONCILE: CancellationLevel.TERM,
    StopStage.RESIDUE_SCAN: CancellationLevel.KILL,
    StopStage.VERIFY: CancellationLevel.KILL,
    # SEAL is owed at any level that constitutes a stop: the record of an
    # incomplete stop is exactly the record that must not go missing.
    StopStage.SEAL: CancellationLevel.GRACE,
}
"""Cancellation level each stage requires. An extension-by-reference table: the
levels belong to :mod:`mayhem.domain.cancellation`, not to this module."""

_LEVEL_STAGES: Final[dict[CancellationLevel, tuple[StopStage, ...]]] = {
    CancellationLevel.NONE: (),
    # Cooperative freeze: nothing to undo, so nothing to undo-verify — but the
    # stop itself is real and gets sealed.
    CancellationLevel.GRACE: (
        StopStage.FREEZE,
        StopStage.CANCEL_PENDING,
        StopStage.SEAL,
    ),
    # Live payloads must be asserted on, then reconciled.
    CancellationLevel.TERM: (
        StopStage.FREEZE,
        StopStage.CANCEL_PENDING,
        StopStage.COMPENSATE_ACTIVE,
        StopStage.RECONCILE,
        StopStage.SEAL,
    ),
    # Hard kill is precisely the case where "the payload died" cannot be
    # trusted, so the residue must be looked for and proved.
    CancellationLevel.KILL: STOP_FLOW,
}
"""Stages owed at each cancellation level — monotone by inclusion in the level."""

_STATE_OWED: Final[dict[RunState, frozenset[StopStage]]] = {
    # Nothing was injected, so compensate/reconcile/scan/verify have no subject.
    # Skipping them is not an optimisation; it is the truth, and undoing an
    # action that never happened would be theatre.
    RunState.PENDING: frozenset({StopStage.FREEZE, StopStage.CANCEL_PENDING, StopStage.SEAL}),
    RunState.RUNNING: frozenset(STOP_FLOW),
    # A stop raised against a terminal run has nothing to escalate.
    RunState.FINISHED: frozenset(),
    RunState.STOPPED: frozenset(),
}
"""Which stages a run state actually has work for."""


def required_level(stage: StopStage) -> CancellationLevel:
    """The cancellation level *stage* needs.

    Raises:
        InvariantViolationError: If the stage is not in the ladder table.
    """
    try:
        return _STAGE_LEVEL[StopStage(stage)]
    except (KeyError, ValueError) as exc:
        msg = f"stop stage {stage!r} is not on the ladder"
        raise InvariantViolationError("stop_stage_not_on_ladder", msg) from exc


def stop_flow(state: RunState) -> tuple[StopStage, ...]:
    """Every stage *state* owes, in flow order.

    An empty tuple is a real answer, not a gap: a terminal run owes nothing.
    """
    return tuple(stage for stage in STOP_FLOW if stage in _STATE_OWED[RunState(state)])


def mandatory_stages(state: RunState, level: CancellationLevel) -> tuple[StopStage, ...]:
    """Stages the ladder owes *right now*: the level's stages, narrowed to what
    *state* has work for, in flow order.

    Monotone by inclusion in the level — raising ``level`` never removes a stage
    this function returned for a lower one. That is the property the escalation
    ladder rests on, and it is a property of these tables, not of any caller's
    bookkeeping.
    """
    owed = _STATE_OWED[RunState(state)]
    return tuple(
        stage for stage in _LEVEL_STAGES[CancellationLevel(level)] if stage in owed
    )


def next_stage(
    state: RunState,
    level: CancellationLevel,
    done: tuple[StopStage, ...] = (),
) -> StopStage | None:
    """The next stage owed, or ``None`` when the stop is complete at *level*.

    ``done`` is the caller's record of completed stages; the ladder does not keep
    state of its own, so it stays a pure function.
    """
    completed = frozenset(StopStage(s) for s in done)
    for stage in mandatory_stages(state, level):
        if stage not in completed:
            return stage
    return None


def is_complete(
    state: RunState,
    level: CancellationLevel,
    done: tuple[StopStage, ...] = (),
) -> bool:
    """True when no stage remains owed at *level*."""
    return next_stage(state, level, done) is None


def _require_aware(value: datetime, rule: str, subject: str) -> datetime:
    if value.tzinfo is None:
        msg = f"{subject} must be tz-aware; got naive {value!r}"
        raise InvariantViolationError(rule, msg)
    return value


def _require_nonblank(value: str, rule: str, subject: str) -> str:
    if not value.strip():
        msg = f"{subject} must be a non-blank string"
        raise InvariantViolationError(rule, msg)
    if value != value.strip():
        msg = f"{subject} must be trimmed; got {value!r}"
        raise InvariantViolationError(rule, msg)
    return value


class ObservedValue(BaseModel):
    """One value observed at the moment a stop fired, kept as evidence.

    A frozen named record rather than a mapping: the ordering stays canonical
    (so a report digest is byte-stable) and duplicate names are refused at
    construction rather than silently collapsing in a dict.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    value: str  # rendered for evidence: "0.97", "5m", "true"
    unit: str = ""

    @field_validator("name")
    @classmethod
    def _name_nonblank(cls, value: str) -> str:
        return _require_nonblank(value, "observed_value_name_not_blank", "observed value name")

    def describe(self) -> str:
        return f"{self.name}={self.value}{self.unit}"


class StopTrigger(BaseModel):
    """A reason plus the evidence that produced it — one stop, one cause.

    Built through :meth:`for_signal` when a stop path is known, which binds the
    reason for you; constructed directly only when the reason has already been
    decided. Either way the invariants below refuse a trigger whose payload
    contradicts its reason.
    """

    model_config = ConfigDict(frozen=True)

    reason: StopReason
    condition_id: str = ""  # set iff reason is CONDITION_FIRED
    observed_values: tuple[ObservedValue, ...] = ()
    detail: str = ""

    @classmethod
    def for_signal(
        cls,
        signal: StopSignal,
        *,
        condition_id: str = "",
        observed_values: tuple[ObservedValue, ...] = (),
        detail: str = "",
    ) -> StopTrigger:
        """Build the trigger *signal* raises, binding its one reason.

        Raises:
            InvariantViolationError: If *signal* has no mapped reason, or if a
                condition id is supplied for a path that cannot carry one.
        """
        return cls(
            reason=reason_for(signal),
            condition_id=condition_id,
            observed_values=observed_values,
            detail=detail,
        )

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        names = [v.name for v in self.observed_values]
        if len(set(names)) != len(names):
            repeated = sorted({n for n in names if names.count(n) > 1})
            msg = f"stop trigger repeats an observed value name: {repeated}"
            raise InvariantViolationError("observed_values_unique", msg)
        if self.reason is StopReason.CONDITION_FIRED:
            # A fired condition that names no condition is not evidence of
            # anything: sealed evidence could not reproduce it.
            _require_nonblank(
                self.condition_id, "condition_fired_requires_condition_id", "condition-fired stop"
            )
        elif self.condition_id.strip():
            msg = (
                f"stop reason {self.reason.value!r} cannot carry a condition id "
                f"(got {self.condition_id!r})"
            )
            raise InvariantViolationError("condition_id_only_for_condition", msg)
        return self

    @property
    def is_condition_fired(self) -> bool:
        return self.reason is StopReason.CONDITION_FIRED

    def describe(self) -> str:
        """One-line human description for logs and sealed evidence."""
        if self.is_condition_fired:
            observed = ", ".join(v.describe() for v in self.observed_values)
            suffix = f" ({observed})" if observed else ""
            return f"condition_fired:{self.condition_id}{suffix}"
        return self.reason.value


class StopScope(StrEnum):
    """What a stop command is addressed to."""

    RUN = "run"  # exactly one run
    ENVIRONMENT = "environment"  # every run in the environment


class StopCommand(BaseModel):
    """A request to stop, from a named principal, over a named scope.

    The command carries no *authority* — it records that someone asked. Phase 2
    executes it, plan 09 decides who may issue an environment-wide one, and
    Phase 5 rejects a command against a run that has already stopped. What this
    type does fix is the shape: a scope that cannot name its subject is refused,
    and an environment-wide command cannot carry a run id, so a narrow stop
    cannot be smuggled through as a broad one.
    """

    model_config = ConfigDict(frozen=True)

    id: str  # sc-<hex>
    scope: StopScope
    principal: str  # who asked
    trigger: StopTrigger
    issued_at: datetime
    run_id: str = ""  # required iff scope is RUN
    environment: str = ""  # required iff scope is ENVIRONMENT
    ttl_seconds: Duration = 300.0
    """How long this command still authorises a stop. A stale emergency stop is
    worse than none: it acts on a world that has since changed."""

    @field_validator("id")
    @classmethod
    def _id_nonblank(cls, value: str) -> str:
        return _require_nonblank(value, "stop_command_id_not_blank", "stop command id")

    @field_validator("principal")
    @classmethod
    def _principal_nonblank(cls, value: str) -> str:
        return _require_nonblank(value, "stop_principal_not_blank", "stop command principal")

    @field_validator("issued_at")
    @classmethod
    def _issued_at_aware(cls, value: datetime) -> datetime:
        return _require_aware(value, "stop_command_issued_at_aware", "stop command issued_at")

    @model_validator(mode="after")
    def _check_scope(self) -> Self:
        if self.scope is StopScope.RUN:
            _require_nonblank(self.run_id, "run_scope_requires_run_id", "run-scoped stop command")
            if self.environment.strip():
                msg = "run-scoped stop command cannot name an environment"
                raise InvariantViolationError("run_scope_has_no_environment", msg)
        else:
            _require_nonblank(
                self.environment, "environment_scope_requires_environment", "environment-wide stop"
            )
            if self.run_id.strip():
                # "Stop everything except that one run" is not a scope; it is a
                # bug with a blast radius.
                msg = (
                    "environment-wide stop command cannot carry a run_id; "
                    "narrow the scope instead"
                )
                raise InvariantViolationError("environment_scope_has_no_run_id", msg)
        return self

    @property
    def reason(self) -> StopReason:
        return self.trigger.reason

    @property
    def is_environment_wide(self) -> bool:
        return self.scope is StopScope.ENVIRONMENT

    @property
    def expires_at(self) -> datetime:
        return self.issued_at + timedelta(seconds=float(self.ttl_seconds))

    def is_stale(self, now: datetime | None = None) -> bool:
        """True once *now* is past the command's expiry.

        ``now`` is injected (defaulting to ``utc_now()``) so the predicate is pure
        under test; a caller that needs a different clock passes it.
        """
        moment = _require_aware(
            now if now is not None else utc_now(), "stop_command_now_aware", "stop command now"
        )
        return moment >= self.expires_at


class CheckStatus(StrEnum):
    """Result of one postflight check, as the probe that ran it reported it."""

    PASS = "pass"
    FAIL = "fail"


class PostflightVerdict(StrEnum):
    """Overall postflight result.

    ``UNKNOWN`` is the fail-closed third state: a report with no checks, or one
    whose evidence has gone stale, has not established recovery — and "probably
    recovered" is not a state.
    """

    CLEAN = "clean"
    DIRTY = "dirty"
    UNKNOWN = "unknown"


class PostflightCheck(BaseModel):
    """One postflight check and the evidence behind its verdict.

    ``PASS`` is refused without an evidence reference: a check that claims to
    have passed with nothing behind it is not a weak claim, it is a malformed
    one. ``FAIL`` may stand uncited — a found problem is admissible on the
    report of the thing that found it — but citing it is always better.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    status: CheckStatus
    evidence_refs: tuple[str, ...] = ()
    detail: str = ""
    observed_at: datetime = Field(default_factory=utc_now)
    ttl_seconds: Duration = 900.0
    """How long this check's observation still counts as evidence of recovery."""

    @field_validator("name")
    @classmethod
    def _name_nonblank(cls, value: str) -> str:
        return _require_nonblank(value, "postflight_check_name_not_blank", "postflight check name")

    @field_validator("observed_at")
    @classmethod
    def _observed_at_aware(cls, value: datetime) -> datetime:
        return _require_aware(value, "postflight_observed_at_aware", "postflight observed_at")

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        refs = [ref.strip() for ref in self.evidence_refs]
        if len(set(refs)) != len(refs):
            msg = f"postflight check {self.name!r} repeats an evidence reference"
            raise InvariantViolationError("postflight_evidence_refs_unique", msg)
        if any(not ref for ref in refs):
            msg = f"postflight check {self.name!r} carries a blank evidence reference"
            raise InvariantViolationError("postflight_evidence_ref_not_blank", msg)
        if self.status is CheckStatus.PASS and not self.evidence_refs:
            msg = f"postflight check {self.name!r} is pass without an evidence reference"
            raise InvariantViolationError("pass_requires_evidence_ref", msg)
        return self

    @property
    def is_pass(self) -> bool:
        return self.status is CheckStatus.PASS

    @property
    def expires_at(self) -> datetime:
        return self.observed_at + timedelta(seconds=float(self.ttl_seconds))

    def is_stale(self, now: datetime | None = None) -> bool:
        """True once *now* is past this observation's TTL (``now`` injected)."""
        moment = _require_aware(
            now if now is not None else utc_now(), "postflight_now_aware", "postflight now"
        )
        return moment >= self.expires_at


class PostflightReport(BaseModel):
    """The postflight mirror of preflight: per-check verdicts with evidence, plus
    the stop that produced them.

    The report's :attr:`verdict` is *recomputed* from the checks on every read
    rather than stored-and-trusted, for the same reason a lease's state is only
    ever advanced through its transition table: a caller that writes
    ``verdict=CLEAN`` over a failing check is refused by the evidence, not
    believed. An empty report is constructible — a preflight refusal genuinely
    has no postflight checks — and verdicts ``UNKNOWN``, not ``CLEAN``.
    """

    model_config = ConfigDict(frozen=True)

    run_id: str
    stop: StopTrigger
    checks: tuple[PostflightCheck, ...] = ()
    sealed_at: datetime | None = None
    generated_at: datetime = Field(default_factory=utc_now)

    @field_validator("run_id")
    @classmethod
    def _run_id_nonblank(cls, value: str) -> str:
        return _require_nonblank(value, "postflight_run_id_not_blank", "postflight run_id")

    @field_validator("sealed_at", "generated_at")
    @classmethod
    def _timestamps_aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _require_aware(value, "postflight_timestamp_aware", "postflight timestamp")

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        names = [c.name for c in self.checks]
        if len(set(names)) != len(names):
            repeated = sorted({n for n in names if names.count(n) > 1})
            msg = f"postflight report repeats a check name: {repeated}"
            raise InvariantViolationError("postflight_check_names_unique", msg)
        return self

    # -- catalogue ------------------------------------------------------------

    @property
    def stop_reason(self) -> StopReason:
        return self.stop.reason

    def check(self, name: str) -> PostflightCheck | None:
        for candidate in self.checks:
            if candidate.name == name:
                return candidate
        return None

    @property
    def failed_checks(self) -> tuple[PostflightCheck, ...]:
        return tuple(c for c in self.checks if not c.is_pass)

    @property
    def stale_checks(self) -> tuple[PostflightCheck, ...]:
        """Checks whose evidence has aged out, as of report generation time.

        Judged against ``generated_at`` — a fixed point in the artifact — so the
        report's own verdict is reproducible from the report alone.
        """
        return tuple(c for c in self.checks if self.generated_at >= c.expires_at)

    # -- pure predicates -------------------------------------------------------

    def verdict(self, now: datetime | None = None) -> PostflightVerdict:
        """Verdict implied by the checks, and (optionally) by *now*.

        Precedence is ``DIRTY`` > ``UNKNOWN`` > ``CLEAN``: one failed check
        settles it, because a found residue is a fact about the world rather than
        an absence of evidence. Otherwise, no checks or stale evidence means
        ``UNKNOWN`` — unchecked is not clean, and unchecked is not dirty either.
        """
        if self.failed_checks:
            return PostflightVerdict.DIRTY
        if not self.checks:
            return PostflightVerdict.UNKNOWN
        moment = _require_aware(
            now if now is not None else self.generated_at, "postflight_now_aware", "postflight now"
        )
        if any(c.is_stale(moment) for c in self.checks):
            return PostflightVerdict.UNKNOWN
        return PostflightVerdict.CLEAN

    def recovery_verified(self, now: datetime | None = None) -> bool:
        """True only when every check passed on evidence that is still current."""
        return self.verdict(now) is PostflightVerdict.CLEAN

    @property
    def report_digest(self) -> str:
        """Canonical digest of the whole report, checks and verdict input alike.

        Phase 4 seals this; keeping it a property of the frozen model means the
        digest cannot drift from the evidence beside it.
        """
        return sha256_hex(canonical_json(self.model_dump(mode="json")))


@dataclass(frozen=True, slots=True)
class StopEscalation:
    """A stop's position on the ladder, resolved once and read many times.

    The ladder's pure functions answer "what is owed"; this is the frozen answer
    for one (state, level, done) triple, so a caller can carry a stop's position
    in sealed evidence without re-deriving it and without holding mutable state.
    """

    state: RunState
    level: CancellationLevel
    done: tuple[StopStage, ...] = ()

    @property
    def outstanding(self) -> tuple[StopStage, ...]:
        """Stages still owed, in flow order."""
        owed = set(mandatory_stages(self.state, self.level))
        return tuple(s for s in stop_flow(self.state) if s in owed and s not in set(self.done))

    @property
    def current(self) -> StopStage | None:
        """The next stage owed, or ``None`` when the stop is complete."""
        return next_stage(self.state, self.level, self.done)

    @property
    def complete(self) -> bool:
        return is_complete(self.state, self.level, self.done)

    def advance(self, stage: StopStage) -> StopEscalation:
        """Return this escalation with *stage* recorded as done.

        Raises:
            InvariantViolationError: If *stage* was not owed at this level — so
                a caller cannot "complete" a stop by asserting a stage it was
                never required to perform.
        """
        outstanding = self.outstanding
        if StopStage(stage) not in outstanding:
            msg = f"stage {stage!r} is not outstanding at {self.level} for run state {self.state}"
            raise InvariantViolationError("stage_not_outstanding", msg)
        return StopEscalation(state=self.state, level=self.level, done=(*self.done, stage))
