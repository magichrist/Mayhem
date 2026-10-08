"""Bounded search for a resilience boundary (docs/v1.1.0/15_RESILIENCE_ANALYTICS_ADAPTIVE.md,
Phase 1).

Plan 15 wants two searches that neither Chaos Mesh nor Litmus can express:
*find the impairment at which the system stops tolerating anything* (the
boundary: ``1% -> 5% -> 10% -> 20%`` then minimize), and *find the smallest
fault/target combination that still reproduces a failure* (the counterexample:
``20 -> 10 -> 5 -> 2.5 -> 3.75 -> 3.1``). This module is the **policy and the
planner** for both: what the next step would be, and what would stop the
search. It is pure over what has already been tried. It runs nothing, admits
nothing, and holds no budget — it takes the remaining budget as an argument and
refuses to plan a step it cannot pay for.

**Two phases, one history.** Escalation starts at ``start`` and adds ``step``
until a trial breaches the declared tolerance. Minimization then bisects the
bracket between the smallest value known to breach and the largest value known
to clear below it — and while nothing below has cleared yet, that edge is
zero, so the first probe is a halving of the boundary. Plan 15's illustrative
ladder is a *shape*, not arithmetic — its final move (``3.1``) steps away from
the known reproducer, which refines the wrong end of the bracket — so this
implementation bisects toward the reproducer, which is the end that matters
when the question is "how little can we break it by".

**Minimization assumes a roughly monotone surface.** A boundary search that
could be crossed and uncrossed by the same impairment would need the surface
characterised rather than bracketed; that is a later phase. The bracket rule
here degrades honestly instead of silently: every trial updates either the
breaker or the clearer, so a non-monotone surface yields a reported bracket
rather than a wrong single number.

**A search stops, and the stop is a value.** Every decision is a
:class:`SearchDecision`: either a :class:`SearchStep` to run *with the stop
condition attached*, or a :class:`StopReason` with the boundary established so
far. There is no in-between, and a decision carrying both is refused at
construction. Budget exhaustion is a stop that keeps the findings, never a
search that quietly continues.

**Generated candidates have zero authority, and the type says so.** An
AI-proposed candidate is an :class:`UntrustedSearchDraft`: the same
:class:`SearchStep` body, compiled into the same :class:`SearchPlan` type an
authored proposal uses, with no field in which an approval could travel. The
distinction is enforced twice — the draft type has no ``approval`` attribute
to populate, and :class:`SearchPlan` refuses to be *constructed* with an
approval on a ``generated`` origin — so the AI path cannot carry a token by
accident, by field copy, or by a reviewer who meant well. Authority is a
property of the plan, never of the caller that produced it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from math import isfinite

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest

__all__ = [
    "RULE_APPROVAL_MISMATCH",
    "RULE_BUDGET_REFERENCE_MISMATCH",
    "RULE_GENERATED_CANNOT_BE_APPROVED",
    "RULE_MINIMIZE_REQUIRES_STOP_ON_BREACH",
    "Approval",
    "ApprovalAuthority",
    "BudgetKind",
    "BudgetReference",
    "MinimizationStrategy",
    "SafetyBudget",
    "SearchDecision",
    "SearchHistory",
    "SearchOrigin",
    "SearchPhase",
    "SearchPlan",
    "SearchPolicy",
    "SearchStep",
    "SearchStrategy",
    "StopCondition",
    "StopReason",
    "Trial",
    "UntrustedSearchDraft",
    "plan_next_step",
]

RULE_MINIMIZE_REQUIRES_STOP_ON_BREACH = "search.minimize_requires_stop_on_breach"
RULE_GENERATED_CANNOT_BE_APPROVED = "search.generated_plan_cannot_be_approved"
RULE_APPROVAL_MISMATCH = "search.approval_does_not_match_plan"
RULE_BUDGET_REFERENCE_MISMATCH = "search.budget_reference_mismatch"


# -- vocabulary -----------------------------------------------------------------------


class SearchStrategy(StrEnum):
    """Which search a policy describes.

    ``BOUNDARY_ESCALATION`` starts below the boundary and climbs until a trial
    breaches. ``COUNTEREXAMPLE_MINIMIZATION`` starts from a value already known
    to reproduce and shrinks it; it needs that breaching trial to already exist
    in the history, because the whole question is "how much of this can be
    removed and still fail".
    """

    BOUNDARY_ESCALATION = "boundary-escalation"
    COUNTEREXAMPLE_MINIMIZATION = "counterexample-minimization"


class MinimizationStrategy(StrEnum):
    """What happens at the first breach.

    ``NONE`` stops there and reports the value. ``BISECTION`` narrows the
    bracket below it, which is only meaningful when the search also stops on
    that breach — otherwise the search is a sweep and there is no boundary to
    minimize towards.
    """

    NONE = "none"
    BISECTION = "bisection"


class SearchPhase(StrEnum):
    """Which half of the search a step belongs to."""

    ESCALATION = "escalation"
    MINIMIZATION = "minimization"


class StopReason(StrEnum):
    """Why the search ended. Every value is a stop with findings attached."""

    BREACH_FOUND = "breach-found"
    BOUNDARY_RESOLVED = "boundary-resolved"
    LADDER_EXHAUSTED = "ladder-exhausted"
    MAX_STEPS = "max-steps"
    NO_FURTHER_VALUE = "no-further-value"
    NO_REMAINING_BUDGET = "no-remaining-budget"
    COMBINATION_BUDGET_EXHAUSTED = "combination-budget-exhausted"
    NO_REPRODUCER = "no-reproducer"
    INSUFFICIENT_MEASUREMENT = "insufficient-measurement"


class BudgetKind(StrEnum):
    """Which budget a step draws on.

    ``DAMAGE_SECONDS`` is the cumulative damage ledger in
    :mod:`mayhem.domain.quota`, which is the default reading of "remaining
    safety budget" here: a search that runs out of impairment allowance must
    stop, whatever the ladder would have done next.
    """

    DAMAGE_SECONDS = "damage-seconds"
    WALL_CLOCK_SECONDS = "wall-clock-seconds"
    STEPS = "steps"
    COMBINATIONS = "combinations"


class SearchOrigin(StrEnum):
    """Who wrote the plan. Decides authority; nothing else does."""

    AUTHORED = "authored"
    GENERATED = "generated"


class ApprovalAuthority(StrEnum):
    """What a plan is allowed to do next."""

    NONE = "none"
    APPROVED = "approved"


# -- budgets --------------------------------------------------------------------------


class BudgetReference(BaseModel):
    """A named handle on a budget, not the budget itself.

    A policy holds the *reference* so a decision can be refused when it is
    handed a different budget than the one the policy was declared against —
    charging a search against an unrelated ledger is a bug worth refusing, not
    a rounding difference.
    """

    model_config = ConfigDict(frozen=True)

    kind: BudgetKind
    label: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind.value, "label": self.label}


class SafetyBudget(BaseModel):
    """How much of a referenced budget is left, and what one step costs it.

    ``remaining`` is finite by construction: an unbounded budget is expressed
    by a very large one, and refusing ``inf`` here keeps "no remaining budget"
    and "infinite budget" from being the same value — which is exactly the
    confusion the negative control in the test suite is written against.
    """

    model_config = ConfigDict(frozen=True)

    reference: BudgetReference
    remaining: float = Field(ge=0.0)
    step_cost: float = Field(default=1.0, gt=0.0)

    @field_validator("remaining")
    @classmethod
    def _remaining_is_finite(cls, value: float) -> float:
        if not isfinite(value):
            raise InvariantViolationError(
                "search.budget_not_finite",
                f"remaining budget must be a finite number, got {value}: an infinite "
                "budget is indistinguishable from a missing one at the moment it "
                "matters, which is when it is too late",
            )
        return value

    @property
    def exhausted(self) -> bool:
        return self.remaining < self.step_cost

    def allows(self, cost: float) -> bool:
        """True when ``cost`` fits inside what is left."""
        return self.remaining >= cost

    def charge(self, cost: float) -> SafetyBudget:
        """The same budget after ``cost`` has been spent. Pure."""
        return self.model_copy(update={"remaining": self.remaining - cost})

    def to_dict(self) -> dict[str, object]:
        return {
            "reference": self.reference.to_dict(),
            "remaining": self.remaining,
            "step_cost": self.step_cost,
            "exhausted": self.exhausted,
        }


# -- the policy -----------------------------------------------------------------------


class SearchPolicy(BaseModel):
    """The authored rules for one bounded search.

    Every bound is validated at construction. A policy that starts at zero, or
    that both escalates forever and declares no way to stop, or that declares
    a budget of nothing, is refused here rather than producing a search that
    fails at step forty.

    ``start`` means different things per strategy and is documented rather than
    overloaded: under ``BOUNDARY_ESCALATION`` it is the first impairment tried,
    under ``COUNTEREXAMPLE_MINIMIZATION`` it is the value the caller *already
    knows* reproduces — a starting point the search records as a breaching
    trial, not a number it will try. The planner reads the boundary from the
    history in both cases, which is why an empty history stops minimization
    with ``NO_REPRODUCER`` instead of guessing at one.
    """

    model_config = ConfigDict(frozen=True)

    strategy: SearchStrategy = SearchStrategy.BOUNDARY_ESCALATION
    start: float = Field(default=1.0, gt=0.0)
    step: float = Field(default=5.0, gt=0.0)
    stop_on_breach: bool = True
    minimization: MinimizationStrategy = MinimizationStrategy.BISECTION
    combination_budget: int = Field(default=1, ge=1)
    budget_ref: BudgetReference
    step_cost: float = Field(default=1.0, gt=0.0)
    max_steps: int = Field(default=12, ge=1)
    resolution: float = Field(default=0.0, ge=0.0)
    name: str = "boundary-search"

    @field_validator("start", "step", "resolution")
    @classmethod
    def _finite_bounds(cls, value: float) -> float:
        if not isfinite(value):
            raise InvariantViolationError(
                "search.bound_not_finite",
                f"search bounds must be finite, got {value}: an infinite ladder never "
                "terminates and an infinite resolution never resolves",
            )
        return value

    @model_validator(mode="after")
    def _minimize_needs_a_boundary(self) -> SearchPolicy:
        if self.minimization is not MinimizationStrategy.NONE and not self.stop_on_breach:
            raise InvariantViolationError(
                RULE_MINIMIZE_REQUIRES_STOP_ON_BREACH,
                "minimization requires stop_on_breach: a search that walks past every "
                "breach is a sweep, and a sweep has no boundary to minimize towards",
            )
        return self

    @property
    def reference(self) -> BudgetReference:
        """Alias — the policy's handle on the budget it draws from."""
        return self.budget_ref

    def budget(self, remaining: float) -> SafetyBudget:
        """A :class:`SafetyBudget` on this policy's own reference."""
        return SafetyBudget(
            reference=self.budget_ref, remaining=remaining, step_cost=self.step_cost
        )

    def to_dict(self) -> dict[str, object]:
        payload = self.model_dump(mode="json")
        payload["budget_ref"] = self.budget_ref.to_dict()
        return payload


# -- results -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SearchStep:
    """One micro-plan the runner may execute — never one it must.

    The step carries the budget it was planned against, so a later evidence
    record can show which entry it drew from rather than asserting in prose
    that it was within budget.
    """

    index: int
    value: float
    phase: SearchPhase
    combination: str
    budget_remaining: float
    budget_ref: BudgetReference
    expected_cost: float

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["phase"] = self.phase.value
        payload["budget_ref"] = self.budget_ref.to_dict()
        return payload


@dataclass(frozen=True, slots=True)
class StopCondition:
    """What about this step's outcome ends the search.

    ``on_breach``/``on_clear`` of ``None`` mean "carry on": the search does not
    end on that result. ``on_insufficient`` is always a stop — a step whose
    measurement could not be separated from noise neither confirms nor refutes
    the bracket, and letting the search continue would silently re-propose the
    same value forever.
    """

    on_breach: StopReason | None
    on_clear: StopReason | None
    on_insufficient: StopReason
    next_phase: SearchPhase | None

    def to_dict(self) -> dict[str, object]:
        return {
            "on_breach": None if self.on_breach is None else self.on_breach.value,
            "on_clear": None if self.on_clear is None else self.on_clear.value,
            "on_insufficient": self.on_insufficient.value,
            "next_phase": None if self.next_phase is None else self.next_phase.value,
        }


@dataclass(frozen=True, slots=True)
class SearchDecision:
    """The next step, or the reason there is not one. Never both.

    ``boundary`` is what the search has established so far and survives every
    stop, including budget exhaustion — plan 15's acceptance criterion is that a
    halted search reports the findings it does have.
    """

    step: SearchStep | None = None
    stop: StopReason | None = None
    stop_condition: StopCondition | None = None
    boundary: float | None = None
    bracket_low: float = 0.0
    phase: SearchPhase | None = None
    trials: int = 0
    combinations_used: int = 0
    note: str = ""

    def __post_init__(self) -> None:
        if (self.step is None) == (self.stop is None):
            raise InvariantViolationError(
                "search.decision_is_ambiguous",
                "a search decision is either a step to run or a reason there is not one; "
                "a decision carrying both (or neither) is not a decision",
            )
        if self.step is not None and self.stop_condition is None:
            raise InvariantViolationError(
                "search.step_without_stop_condition",
                "a planned step must carry the stop condition it will be judged by: a "
                "search step with no stated stopping rule is an unbounded search",
            )
        if self.step is None and self.stop_condition is not None:
            raise InvariantViolationError(
                "search.stop_with_step_condition",
                "a stop carries no next step, so it cannot carry a condition on one",
            )

    @property
    def proceed(self) -> bool:
        return self.step is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "proceed": self.proceed,
            "step": None if self.step is None else self.step.to_dict(),
            "stop": None if self.stop is None else self.stop.value,
            "stop_condition": None
            if self.stop_condition is None
            else self.stop_condition.to_dict(),
            "boundary": self.boundary,
            "bracket_low": self.bracket_low,
            "phase": None if self.phase is None else self.phase.value,
            "trials": self.trials,
            "combinations_used": self.combinations_used,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class Trial:
    """One completed step and what it showed."""

    step: SearchStep
    breached: bool
    sufficient: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "step": self.step.to_dict(),
            "breached": self.breached,
            "sufficient": self.sufficient,
        }


@dataclass(frozen=True, slots=True)
class SearchHistory:
    """Everything the search has tried, in order. Immutable; ``record`` extends it."""

    trials: tuple[Trial, ...] = ()

    def record(self, step: SearchStep, *, breached: bool, sufficient: bool = True) -> SearchHistory:
        """The history with one more trial appended."""
        return SearchHistory(
            trials=(*self.trials, Trial(step=step, breached=breached, sufficient=sufficient))
        )

    @property
    def steps_used(self) -> int:
        return len(self.trials)

    @property
    def combinations(self) -> frozenset[str]:
        return frozenset(trial.step.combination for trial in self.trials)

    @property
    def boundary(self) -> float | None:
        """The smallest impairment known to breach. ``None`` if nothing has."""
        breaches = [trial.step.value for trial in self.trials if trial.breached]
        return min(breaches) if breaches else None

    @property
    def bracket_low(self) -> float:
        """The lower edge of the bracket the boundary is known to lie inside.

        The largest value known to *clear* that sits below the boundary; ``0.0``
        when nothing below the boundary has cleared yet. Minimization bisects
        ``(bracket_low, boundary]``, so a search whose first trial breached
        immediately starts with ``bracket_low = 0`` and its first probe is a
        halving of the boundary. A ladder's earlier clears *are* this edge,
        which is why they are recorded as clears rather than discarded: they
        are what turns a re-probe into a bisection.
        """
        boundary = self.boundary
        if boundary is None:
            return 0.0
        clears = [
            trial.step.value
            for trial in self.trials
            if not trial.breached and trial.step.value < boundary
        ]
        return max(clears) if clears else 0.0

    @property
    def last_step(self) -> SearchStep | None:
        return self.trials[-1].step if self.trials else None

    @property
    def last_trial(self) -> Trial | None:
        return self.trials[-1] if self.trials else None

    def to_dict(self) -> dict[str, object]:
        return {
            "trials": [trial.to_dict() for trial in self.trials],
            "boundary": self.boundary,
            "bracket_low": self.bracket_low,
            "steps_used": self.steps_used,
            "combinations": sorted(self.combinations),
        }


# -- planning ------------------------------------------------------------------------


def plan_next_step(
    policy: SearchPolicy,
    history: SearchHistory,
    *,
    budget: SafetyBudget | None,
    combination: str = "default",
) -> SearchDecision:
    """The next step for this search, or the reason there is not one.

    Pure: the same ``(policy, history, budget)`` always yields the same
    decision, which is what makes a search auditable after the fact — the
    ladder that was walked can be recomputed from the trials alone.

    Refusals are checked before any arithmetic, in the order a safety reviewer
    would ask for them: combinations already spent, then remaining budget, then
    whether the last measurement was trustworthy, then steps spent, then
    whether the bracket is already resolved. The boundary and bracket
    established so far are carried on every stop, so a halted search still
    reports what it found.

    ``budget`` is a required keyword argument with no default on purpose: a
    caller that has not been handed a budget cannot accidentally plan against
    an implicit "unlimited" one.
    """
    _require_matching_budget(policy, budget)
    phase = _next_phase(policy, history)
    refusal = _refusal(policy, history, budget=budget, phase=phase, combination=combination)
    if refusal is not None or budget is None:
        # `budget is None` is unreachable here — _safety_refusal returns a stop
        # for it — and it is tested rather than asserted so the refusal still
        # holds under ``python -O``.
        assert refusal is not None
        return refusal
    value = _next_value(
        policy,
        history,
        phase=phase,
        boundary=history.boundary,
        bracket_low=history.bracket_low,
    )
    last = history.last_step
    if value is None or (last is not None and value == last.value):
        # A repeated value means the bracket has stopped narrowing — float
        # exhaustion, or a surface that answers the same input two ways. Either
        # way the honest outcome is a stop, not another identical probe.
        return _stop(
            history,
            StopReason.NO_FURTHER_VALUE,
            "the search cannot derive a further value: the next probe would repeat the last one",
            phase,
        )
    step = SearchStep(
        index=history.steps_used,
        value=value,
        phase=phase,
        combination=combination,
        budget_remaining=budget.remaining,
        budget_ref=policy.budget_ref,
        expected_cost=policy.step_cost,
    )
    return SearchDecision(
        step=step,
        stop_condition=_stop_condition(policy, phase),
        boundary=history.boundary,
        bracket_low=history.bracket_low,
        phase=phase,
        trials=history.steps_used,
        combinations_used=len(history.combinations),
    )


def _require_matching_budget(policy: SearchPolicy, budget: SafetyBudget | None) -> None:
    """Refuse a budget the policy was not declared against.

    A caller bug, not a stop: charging a search to an unrelated ledger is a
    wiring mistake, and turning it into a "no remaining budget" stop would
    hide it behind a plausible-looking message.
    """
    if budget is not None and budget.reference != policy.budget_ref:
        raise InvariantViolationError(
            RULE_BUDGET_REFERENCE_MISMATCH,
            f"policy {policy.name!r} draws on {policy.budget_ref.to_dict()} but was "
            f"offered {budget.reference.to_dict()}: a search must not be charged to a "
            "budget it was not declared against",
        )


def _stop(
    history: SearchHistory,
    reason: StopReason,
    note: str,
    phase: SearchPhase | None = None,
) -> SearchDecision:
    """A stop that keeps the findings: boundary, bracket, and counts so far."""
    return SearchDecision(
        stop=reason,
        boundary=history.boundary,
        bracket_low=history.bracket_low,
        phase=phase,
        trials=history.steps_used,
        combinations_used=len(history.combinations),
        note=note,
    )


def _refusal(
    policy: SearchPolicy,
    history: SearchHistory,
    *,
    budget: SafetyBudget | None,
    phase: SearchPhase,
    combination: str,
) -> SearchDecision | None:
    """The reason this search cannot take another step, or ``None`` if it can.

    Safety refusals come first — combinations already spent, then remaining
    budget — because they are the two that must hold regardless of what the
    search found. Only then does the state of the search itself get a say.
    The boundary found so far rides along on every one of them.
    """
    spent = _safety_refusal(policy, history, budget=budget, phase=phase, combination=combination)
    return spent if spent is not None else _progress_refusal(policy, history, phase=phase)


def _safety_refusal(
    policy: SearchPolicy,
    history: SearchHistory,
    *,
    budget: SafetyBudget | None,
    phase: SearchPhase,
    combination: str,
) -> SearchDecision | None:
    """Refusals that hold whatever the search has learned: budget-shaped only.

    The combination budget caps how many *distinct* fault/target pairs the
    search may open, not how many steps it may take: iterating a pair the
    search is already on is the whole point of a ladder, so continuing on an
    open pair is never what trips this.
    """
    if (
        combination not in history.combinations
        and len(history.combinations) >= policy.combination_budget
    ):
        return _stop(
            history,
            StopReason.COMBINATION_BUDGET_EXHAUSTED,
            f"{len(history.combinations)} of {policy.combination_budget} combinations "
            f"already tried and {combination!r} is not one of them: the search refuses "
            "to open another fault/target pair",
            phase,
        )
    if budget is None or not budget.allows(policy.step_cost):
        remaining = "unknown" if budget is None else f"{budget.remaining}"
        return _stop(
            history,
            StopReason.NO_REMAINING_BUDGET,
            f"no remaining {policy.budget_ref.kind.value} budget ({remaining}) covers a "
            f"step costing {policy.step_cost}: search halts with the findings so far",
            phase,
        )
    return None


def _progress_refusal(
    policy: SearchPolicy,
    history: SearchHistory,
    *,
    phase: SearchPhase,
) -> SearchDecision | None:
    """Refusals that come from what the search has already tried."""
    last = history.last_trial
    if last is not None and not last.sufficient:
        return _stop(
            history,
            StopReason.INSUFFICIENT_MEASUREMENT,
            f"the last trial at {last.step.value} did not clear the sample floor: it "
            "neither confirms nor refutes the boundary, so the search stops rather than "
            "re-proposing the same value",
            phase,
        )
    if (
        policy.stop_on_breach
        and last is not None
        and last.breached
        and policy.minimization is MinimizationStrategy.NONE
    ):
        return _stop(
            history,
            StopReason.BREACH_FOUND,
            f"{last.step.value} breached the declared tolerance and the policy stops on "
            "breach with nowhere to minimize: the boundary is reported as found, not "
            "walked past",
            phase,
        )
    if policy.strategy is SearchStrategy.COUNTEREXAMPLE_MINIMIZATION and history.boundary is None:
        return _stop(
            history,
            StopReason.NO_REPRODUCER,
            "minimization needs a value already known to reproduce the failure, and no "
            "trial in this history breached",
            phase,
        )
    if history.steps_used >= policy.max_steps:
        exhausted_ladder = phase is SearchPhase.ESCALATION and history.boundary is None
        reason = StopReason.LADDER_EXHAUSTED if exhausted_ladder else StopReason.MAX_STEPS
        note = (
            f"{history.steps_used} steps up the ladder without a breach: no boundary was "
            f"reached within the declared ladder starting at {policy.start}"
            if exhausted_ladder
            else f"{history.steps_used} of {policy.max_steps} steps used; the bracket "
            "stands as far as this search narrowed it"
        )
        return _stop(history, reason, note, phase)
    if (
        phase is SearchPhase.MINIMIZATION
        and history.boundary is not None
        and (history.boundary - history.bracket_low) <= policy.resolution
    ):
        return _stop(
            history,
            StopReason.BOUNDARY_RESOLVED,
            f"the bracket ({history.bracket_low}, {history.boundary}] is within the "
            f"declared resolution {policy.resolution}",
            phase,
        )
    return None


def _next_phase(policy: SearchPolicy, history: SearchHistory) -> SearchPhase:
    """Escalate until something breaches, then minimize if the policy says to."""
    if policy.strategy is SearchStrategy.COUNTEREXAMPLE_MINIMIZATION:
        return SearchPhase.MINIMIZATION
    if policy.stop_on_breach and policy.minimization is not MinimizationStrategy.NONE:
        return SearchPhase.MINIMIZATION if history.boundary is not None else SearchPhase.ESCALATION
    return SearchPhase.ESCALATION


def _next_value(
    policy: SearchPolicy,
    history: SearchHistory,
    *,
    phase: SearchPhase,
    boundary: float | None,
    bracket_low: float,
) -> float | None:
    """The impairment the next step would use.

    Escalation adds ``step`` to the last value tried, or starts at ``start``.
    Minimization bisects the bracket ``(bracket_low, boundary]`` — and with
    nothing known to clear below the boundary, ``bracket_low`` is ``0.0`` and
    the first probe is a halving of it.
    """
    if phase is SearchPhase.ESCALATION:
        last = history.last_step
        return policy.start if last is None else last.value + policy.step
    if boundary is None:
        return None
    return (boundary + bracket_low) / 2.0


def _stop_condition(policy: SearchPolicy, phase: SearchPhase) -> StopCondition:
    """The stop condition attached to a step planned in ``phase``.

    A breaching escalation step stops the search outright when the policy both
    stops on breach and has nowhere to minimize; otherwise it hands over to
    minimization. A breaching minimization step never stops by itself — the
    next planning call sees the tightened bracket and decides whether it is
    resolved.
    """
    if phase is SearchPhase.ESCALATION:
        if policy.stop_on_breach:
            on_breach = (
                None
                if policy.minimization is not MinimizationStrategy.NONE
                else StopReason.BREACH_FOUND
            )
            next_phase = (
                SearchPhase.MINIMIZATION
                if policy.minimization is not MinimizationStrategy.NONE
                else None
            )
        else:
            on_breach = None
            next_phase = SearchPhase.ESCALATION
        return StopCondition(
            on_breach=on_breach,
            on_clear=None,
            on_insufficient=StopReason.INSUFFICIENT_MEASUREMENT,
            next_phase=next_phase,
        )
    return StopCondition(
        on_breach=None,
        on_clear=None,
        on_insufficient=StopReason.INSUFFICIENT_MEASUREMENT,
        next_phase=SearchPhase.MINIMIZATION,
    )


# -- plans, approvals, and AI drafts --------------------------------------------------


class Approval(BaseModel):
    """A human approval bound to one exact plan by digest.

    Binding by digest rather than by identity is what makes the binding
    meaningful: change the step after approval and the digest no longer
    matches, so the approval cannot be carried across a change nobody re-read.
    """

    model_config = ConfigDict(frozen=True)

    approved_by: str
    plan_digest: str

    @field_validator("approved_by")
    @classmethod
    def _named_approver(cls, value: str) -> str:
        if not value.strip():
            raise InvariantViolationError(
                "search.approval_without_an_approver",
                "an approval must name who gave it: an unnamed approver is how an "
                "unattributed decision acquires authority",
            )
        return value


class SearchPlan(BaseModel):
    """One planned step, and where it came from. One type, two origins.

    The origin alone decides authority. A ``generated`` plan cannot be
    constructed with an approval at all (:class:`UntrustedSearchDraft` is the
    only way to make one, and it has nowhere to put a token), and an approval
    whose digest does not match this plan is refused too. Both are refusals at
    construction rather than checks a reviewer has to remember to run.
    """

    model_config = ConfigDict(frozen=True)

    step: SearchStep
    origin: SearchOrigin
    rationale: str = ""
    approval: Approval | None = None

    @model_validator(mode="after")
    def _authority_rules(self) -> SearchPlan:
        if self.approval is None:
            return self
        if self.origin is not SearchOrigin.AUTHORED:
            raise InvariantViolationError(
                RULE_GENERATED_CANNOT_BE_APPROVED,
                "a generated candidate cannot carry an approval: an AI-drafted plan "
                "reaches exactly as far as the gates and the approval an authored one "
                "would, and it cannot supply its own. It must be reviewed as one",
            )
        if self.approval.plan_digest != self.plan_digest:
            raise InvariantViolationError(
                RULE_APPROVAL_MISMATCH,
                f"approval names digest {self.approval.plan_digest[:12]}… but this plan "
                f"hashes to {self.plan_digest[:12]}…: an approval binds to the plan that "
                "was read, not to the plan that happens to sit here now",
            )
        return self

    @property
    def plan_digest(self) -> str:
        """The digest an approval must name to bind to this plan."""
        return digest(
            {
                "step": self.step.to_dict(),
                "origin": self.origin.value,
                "rationale": self.rationale,
            }
        )

    @property
    def authority(self) -> ApprovalAuthority:
        return ApprovalAuthority.NONE if self.approval is None else ApprovalAuthority.APPROVED

    def to_dict(self) -> dict[str, object]:
        return {
            "step": self.step.to_dict(),
            "origin": self.origin.value,
            "rationale": self.rationale,
            "authority": self.authority.value,
            "plan_digest": self.plan_digest,
            "approval": None
            if self.approval is None
            else {"approved_by": self.approval.approved_by},
        }


class UntrustedSearchDraft(BaseModel):
    """An AI-generated candidate: the same body, with nowhere to put a token.

    There is no ``approval`` field on this type — not one defaulted to
    ``None``, but no field at all — so a generated candidate cannot be
    *composed* into an approved plan; the only thing it can become is a
    ``generated`` :class:`SearchPlan`, and that type refuses an approval on
    construction. Downstream of :meth:`compile`, generated and authored plans
    are the same object travelling the same gates (plan 15, phase 3).
    """

    model_config = ConfigDict(frozen=True)

    step: SearchStep
    rationale: str = ""

    def compile(self) -> SearchPlan:
        """The draft as a plan — same type as an authored one, zero authority."""
        return SearchPlan(step=self.step, origin=SearchOrigin.GENERATED, rationale=self.rationale)

    def to_dict(self) -> dict[str, object]:
        return {"step": self.step.to_dict(), "rationale": self.rationale}
