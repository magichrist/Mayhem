"""Search policy and step planning: determinism, planted boundaries, and the
negative controls that keep a search bounded (plan 15, Phase 1).

The search tests run against a *simulated response surface* — ``value >= 8.0``
breaches — rather than a mock, so the assertion is that the planner finds a
planted boundary and narrows onto it, not that it calls the objects it was
handed. The negative controls are the reason the module exists in this shape:

* a step with no remaining budget is refused, and the refusal keeps the
  boundary found so far instead of discarding it;
* an untrusted draft cannot carry an approval token — not because a caller
  forgot to check, but because the type has nowhere to put one;
* a comparison that could not be measured halts the search rather than
  silently counting as a clear result, which would move a real boundary;
* a search step with no stated stopping rule cannot be constructed at all.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from pydantic import ValidationError

from mayhem.domain.errors import InvariantViolationError

if TYPE_CHECKING:
    from collections.abc import Callable

from mayhem.domain.search import (
    RULE_APPROVAL_MISMATCH,
    RULE_BUDGET_REFERENCE_MISMATCH,
    RULE_GENERATED_CANNOT_BE_APPROVED,
    RULE_MINIMIZE_REQUIRES_STOP_ON_BREACH,
    Approval,
    ApprovalAuthority,
    BudgetKind,
    BudgetReference,
    MinimizationStrategy,
    SafetyBudget,
    SearchDecision,
    SearchHistory,
    SearchOrigin,
    SearchPhase,
    SearchPlan,
    SearchPolicy,
    SearchStep,
    SearchStrategy,
    StopCondition,
    StopReason,
    UntrustedSearchDraft,
    plan_next_step,
)

QUOTA = BudgetReference(kind=BudgetKind.DAMAGE_SECONDS, label="run-42/damage-quota")
CLOCK = BudgetReference(kind=BudgetKind.WALL_CLOCK_SECONDS, label="run-42/wall-clock")

PLANTED_BOUNDARY = 8.0
COMBINATION = "checkout/latency-injection"


def breaches(value: float) -> bool:
    """The simulated surface: anything at or above 8.0 breaks the service."""
    return value >= PLANTED_BOUNDARY


def policy(**overrides: object) -> SearchPolicy:
    """A search policy with the planted surface's budget and ladder."""
    kwargs: dict[str, object] = {
        "start": 1.0,
        "step": 3.0,
        "budget_ref": QUOTA,
        "combination_budget": 4,
        "max_steps": 12,
        "resolution": 0.25,
    }
    kwargs.update(overrides)
    return SearchPolicy(**kwargs)  # type: ignore[arg-type]


def run(
    search: SearchPolicy,
    surface: Callable[[float], bool] = breaches,
    *,
    remaining: float = 500.0,
    combination: str = COMBINATION,
) -> tuple[SearchDecision, list[tuple[float, bool]], SearchHistory]:
    """Walk a search to its stop against a simulated surface."""
    history = SearchHistory()
    budget = search.budget(remaining)
    walked: list[tuple[float, bool]] = []
    for _ in range(search.max_steps * 4):
        decision = plan_next_step(search, history, budget=budget, combination=combination)
        if not decision.proceed:
            return decision, walked, history
        assert decision.step is not None
        verdict = surface(decision.step.value)
        walked.append((decision.step.value, verdict))
        history = history.record(decision.step, breached=verdict)
        budget = budget.charge(decision.step.expected_cost)
    raise AssertionError("the search never stopped")


# -- the policy -----------------------------------------------------------------------


def test_policy_carries_the_whole_search_on_one_value() -> None:
    search = policy()

    assert search.start == 1.0
    assert search.step == 3.0
    assert search.stop_on_breach is True
    assert search.minimization is MinimizationStrategy.BISECTION
    assert search.combination_budget == 4
    assert search.reference == QUOTA
    assert search.to_dict()["budget_ref"] == {"kind": "damage-seconds", "label": QUOTA.label}


@pytest.mark.parametrize(
    "overrides",
    [
        {"start": 0.0},
        {"start": -1.0},
        {"step": 0.0},
        {"max_steps": 0},
        {"combination_budget": 0},
        {"step_cost": 0.0},
        {"resolution": -1.0},
    ],
)
def test_policy_bounds_are_refused_at_construction(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        policy(**overrides)


@pytest.mark.parametrize("overrides", [{"start": float("inf")}, {"resolution": float("inf")}])
def test_non_finite_policy_bounds_are_domain_refusals(overrides: dict[str, object]) -> None:
    """An infinite ladder never terminates and an infinite resolution never
    resolves; both are domain claims about the search, not value ranges."""
    with pytest.raises(InvariantViolationError):
        policy(**overrides)


def test_minimization_without_stopping_on_breach_is_refused() -> None:
    """A sweep has no boundary, so there is nothing for minimization to narrow."""
    with pytest.raises(InvariantViolationError) as caught:
        policy(stop_on_breach=False, minimization=MinimizationStrategy.BISECTION)

    assert caught.value.rule == RULE_MINIMIZE_REQUIRES_STOP_ON_BREACH


def test_a_sweep_is_expressible_without_minimization() -> None:
    sweep = policy(stop_on_breach=False, minimization=MinimizationStrategy.NONE)

    assert sweep.stop_on_breach is False
    assert sweep.minimization is MinimizationStrategy.NONE


# -- budgets --------------------------------------------------------------------------


def test_a_budget_is_a_reference_plus_what_is_left() -> None:
    budget = SafetyBudget(reference=QUOTA, remaining=10.0, step_cost=4.0)

    assert budget.allows(4.0) is True
    assert budget.allows(10.0) is True
    assert budget.allows(10.1) is False
    assert budget.exhausted is False
    assert budget.charge(4.0).remaining == 6.0
    assert budget.remaining == 10.0  # charge is pure


def test_an_unbounded_budget_is_refused() -> None:
    """``inf`` is how a missing budget and an unlimited one get confused."""
    with pytest.raises(InvariantViolationError):
        SafetyBudget(reference=QUOTA, remaining=float("inf"))
    # nan is not even comparable, so the value range refuses it first.
    with pytest.raises(ValidationError):
        SafetyBudget(reference=QUOTA, remaining=float("nan"))
    with pytest.raises(ValidationError):
        SafetyBudget(reference=QUOTA, remaining=-1.0)


# -- determinism ----------------------------------------------------------------------


def test_the_first_step_is_the_declared_start() -> None:
    decision = plan_next_step(policy(), SearchHistory(), budget=policy().budget(100.0))

    assert decision.proceed is True
    assert decision.step is not None
    assert decision.step.value == 1.0
    assert decision.step.index == 0
    assert decision.step.phase is SearchPhase.ESCALATION
    assert decision.step.combination == "default"


def test_the_ladder_adds_step_each_time() -> None:
    search = policy()
    decision, walked, _ = run(search, lambda _value: False)

    assert [value for value, _ in walked] == [
        1.0,
        4.0,
        7.0,
        10.0,
        13.0,
        16.0,
        19.0,
        22.0,
        25.0,
        28.0,
        31.0,
        34.0,
    ]
    assert decision.stop is StopReason.LADDER_EXHAUSTED
    assert decision.boundary is None


def test_planning_is_deterministic() -> None:
    """The same policy and history always yield the same decision.

    This is what makes a search auditable after the fact: the ladder can be
    recomputed from the trials alone, and a rerun cannot quietly take a
    different path.
    """
    search = policy()
    _, _, history = run(search)

    first = plan_next_step(search, history, budget=search.budget(500.0))
    second = plan_next_step(search, history, budget=search.budget(500.0))

    assert first == second
    assert first.to_dict() == second.to_dict()


def test_a_planned_step_carries_the_budget_it_was_planned_against() -> None:
    search = policy()
    decision = plan_next_step(search, SearchHistory(), budget=search.budget(37.5))

    assert decision.step is not None
    assert decision.step.budget_remaining == 37.5
    assert decision.step.budget_ref == QUOTA
    assert decision.step.expected_cost == search.step_cost
    step_payload = cast("dict[str, object]", decision.to_dict()["step"])
    assert step_payload["budget_ref"] == {"kind": "damage-seconds", "label": QUOTA.label}


def test_a_budget_from_another_ledger_is_refused() -> None:
    wrong = SafetyBudget(reference=CLOCK, remaining=100.0)

    with pytest.raises(InvariantViolationError) as caught:
        plan_next_step(policy(), SearchHistory(), budget=wrong)

    assert caught.value.rule == RULE_BUDGET_REFERENCE_MISMATCH


# -- escalation, breach, minimization --------------------------------------------------


def test_a_planted_boundary_is_found_and_narrowed_onto() -> None:
    """The acceptance case: walk up the ladder, then bisect onto the boundary."""
    decision, walked, history = run(policy())

    assert decision.stop is StopReason.BOUNDARY_RESOLVED
    assert decision.boundary == pytest.approx(PLANTED_BOUNDARY, abs=0.25)
    assert decision.bracket_low == pytest.approx(PLANTED_BOUNDARY, abs=0.25)
    assert history.boundary == decision.boundary
    # Escalation first, then minimization: never the other way round.
    phases = _phases(history)
    assert phases[0] == SearchPhase.ESCALATION
    assert phases[-1] == SearchPhase.MINIMIZATION
    # Minimization only ever tightens downward, so the breaching values it
    # finds are monotonically smaller — the boundary is the last of them.
    breaching = [value for value, breached in walked if breached]
    assert breaching == sorted(breaching, reverse=True)
    assert breaching[-1] == decision.boundary


def _phases(history: SearchHistory) -> list[SearchPhase]:
    return [trial.step.phase for trial in history.trials]


def test_the_bracket_is_the_largest_clear_below_the_boundary() -> None:
    search = policy()
    _, _, history = run(search)

    assert history.boundary is not None
    clears = [
        trial.step.value
        for trial in history.trials
        if not trial.breached and trial.step.value < history.boundary
    ]
    assert history.bracket_low == max(clears)


def test_stopping_on_breach_without_minimization_reports_the_first_breach() -> None:
    search = policy(minimization=MinimizationStrategy.NONE)
    decision, walked, _ = run(search)

    assert decision.stop is StopReason.BREACH_FOUND
    assert decision.boundary == 10.0
    assert walked[-1][1] is True
    # It stopped at the breach rather than walking past it.
    assert len(walked) == 4


def test_the_stop_condition_is_attached_to_the_step_it_governs() -> None:
    stopping = plan_next_step(
        policy(minimization=MinimizationStrategy.NONE), SearchHistory(), budget=policy().budget(1.0)
    )
    minimizing = plan_next_step(policy(), SearchHistory(), budget=policy().budget(1.0))

    assert stopping.step is not None and stopping.stop_condition is not None
    assert stopping.stop_condition.on_breach is StopReason.BREACH_FOUND
    assert stopping.stop_condition.next_phase is None
    assert stopping.step.to_dict() == stopping.to_dict()["step"]

    assert minimizing.step is not None and minimizing.stop_condition is not None
    assert minimizing.stop_condition.on_breach is None
    assert minimizing.stop_condition.next_phase is SearchPhase.MINIMIZATION
    assert minimizing.stop_condition.on_clear is None
    # Whatever happens, an unmeasurable result ends the search.
    assert minimizing.stop_condition.on_insufficient is StopReason.INSUFFICIENT_MEASUREMENT


def test_a_sweep_walks_past_every_breach() -> None:
    sweep = policy(stop_on_breach=False, minimization=MinimizationStrategy.NONE, max_steps=5)
    decision, walked, _ = run(sweep)

    assert decision.stop is StopReason.MAX_STEPS
    assert decision.boundary == 10.0  # the smallest breach it saw, reported
    assert [value for value, _ in walked] == [1.0, 4.0, 7.0, 10.0, 13.0]


def test_counterexample_minimization_needs_a_reproducer() -> None:
    shrinking = policy(strategy=SearchStrategy.COUNTEREXAMPLE_MINIMIZATION)

    decision = plan_next_step(shrinking, SearchHistory(), budget=shrinking.budget(100.0))

    assert decision.proceed is False
    assert decision.stop is StopReason.NO_REPRODUCER
    assert decision.step is None


def test_counterexample_minimization_starts_from_a_known_reproducer() -> None:
    search = policy(strategy=SearchStrategy.COUNTEREXAMPLE_MINIMIZATION, start=12.0)
    seed = step(12.0)
    history = SearchHistory().record(seed, breached=True)

    decision = plan_next_step(search, history, budget=search.budget(100.0))

    assert decision.step is not None
    assert decision.step.phase is SearchPhase.MINIMIZATION
    # Nothing below 12.0 has cleared yet, so the first probe halves it.
    assert decision.step.value == 6.0


def test_the_step_budget_is_a_backstop() -> None:
    decision, walked, _ = run(policy(minimization=MinimizationStrategy.NONE, max_steps=2))

    assert decision.stop is StopReason.LADDER_EXHAUSTED
    assert len(walked) == 2


# -- negative controls ---------------------------------------------------------------


def test_a_search_with_no_remaining_budget_refuses_its_next_step() -> None:
    search = policy()
    history = SearchHistory()
    spent = search.budget(0.0)

    decision = plan_next_step(search, history, budget=spent)

    assert decision.proceed is False
    assert decision.step is None
    assert decision.stop is StopReason.NO_REMAINING_BUDGET
    assert "no remaining damage-seconds budget" in decision.note


def test_a_missing_budget_refuses_the_step_rather_than_assuming_an_unlimited_one() -> None:
    decision = plan_next_step(policy(), SearchHistory(), budget=None)

    assert decision.proceed is False
    assert decision.stop is StopReason.NO_REMAINING_BUDGET
    assert "unknown" in decision.note


def test_a_step_that_costs_more_than_remains_is_refused() -> None:
    search = policy(step_cost=10.0)

    decision = plan_next_step(search, SearchHistory(), budget=search.budget(9.9))

    assert decision.proceed is False
    assert decision.stop is StopReason.NO_REMAINING_BUDGET


def test_budget_exhaustion_keeps_the_boundary_found_so_far() -> None:
    """The findings outlive the budget — that is what phase 2 reports on."""
    search = policy()
    history = SearchHistory()
    for _value, verdict in ((1.0, False), (4.0, False), (7.0, False), (10.0, True)):
        decision = plan_next_step(search, history, budget=search.budget(500.0))
        assert decision.step is not None
        history = history.record(decision.step, breached=verdict)

    decision = plan_next_step(search, history, budget=search.budget(0.0))

    assert decision.stop is StopReason.NO_REMAINING_BUDGET
    assert decision.boundary == 10.0
    assert decision.trials == 4
    assert history.boundary == 10.0


def test_a_second_fault_target_pair_is_refused_once_the_combination_budget_is_spent() -> None:
    search = policy(combination_budget=1)
    history = SearchHistory()

    first = plan_next_step(search, history, budget=search.budget(500.0), combination="a/latency")
    assert first.proceed is True
    assert first.step is not None
    history = history.record(first.step, breached=False)

    same_pair = plan_next_step(
        search, history, budget=search.budget(500.0), combination="a/latency"
    )
    new_pair = plan_next_step(search, history, budget=search.budget(500.0), combination="b/dns")

    assert same_pair.proceed is True  # iterating an open pair is the point
    assert new_pair.proceed is False
    assert new_pair.stop is StopReason.COMBINATION_BUDGET_EXHAUSTED
    assert "'b/dns' is not one of them" in new_pair.note


def test_an_unmeasurable_trial_halts_the_search() -> None:
    """A step that could not be measured neither confirms nor refutes.

    Counting it as a clear result would push the bracket down and report a
    boundary lower than the system's real one — the failure mode an analytics
    module that can say "insufficient" exists to prevent.
    """
    search = policy(minimization=MinimizationStrategy.NONE)
    decision = plan_next_step(search, SearchHistory(), budget=search.budget(500.0))
    assert decision.step is not None
    history = SearchHistory().record(decision.step, breached=False, sufficient=False)

    decision = plan_next_step(search, history, budget=search.budget(500.0))

    assert decision.proceed is False
    assert decision.stop is StopReason.INSUFFICIENT_MEASUREMENT
    assert "did not clear the sample floor" in decision.note


def test_a_step_too_small_to_move_the_value_stops_the_search() -> None:
    """A ladder increment below float64 resolution is not a ladder.

    ``1.0 + 1e-18 == 1.0``, so the search would re-propose the value it just
    ran, forever. The planner notices and stops with a reason instead.
    """
    search = policy(step=1e-18, minimization=MinimizationStrategy.NONE, max_steps=3)
    decision, walked, _ = run(search, lambda _value: False)

    assert decision.stop is StopReason.NO_FURTHER_VALUE
    assert "would repeat" in decision.note
    assert [value for value, _ in walked] == [1.0]


def test_a_decision_is_either_a_step_or_a_reason() -> None:
    with pytest.raises(InvariantViolationError):
        SearchDecision()
    with pytest.raises(InvariantViolationError):
        SearchDecision(
            step=SearchStep(
                index=0,
                value=1.0,
                phase=SearchPhase.ESCALATION,
                combination="a",
                budget_remaining=1.0,
                budget_ref=QUOTA,
                expected_cost=1.0,
            ),
            stop=StopReason.MAX_STEPS,
            stop_condition=StopCondition(
                on_breach=None,
                on_clear=None,
                on_insufficient=StopReason.INSUFFICIENT_MEASUREMENT,
                next_phase=None,
            ),
        )


def test_a_step_without_a_stated_stopping_rule_cannot_be_built() -> None:
    step = SearchStep(
        index=0,
        value=1.0,
        phase=SearchPhase.ESCALATION,
        combination="a",
        budget_remaining=1.0,
        budget_ref=QUOTA,
        expected_cost=1.0,
    )

    with pytest.raises(InvariantViolationError):
        SearchDecision(step=step)


def test_history_is_immutable_and_extends_by_returning_a_new_value() -> None:
    history = SearchHistory()
    decision = plan_next_step(policy(), history, budget=policy().budget(100.0))
    assert decision.step is not None

    extended = history.record(decision.step, breached=True)

    assert extended is not history
    assert history.steps_used == 0
    assert extended.steps_used == 1
    assert extended.boundary == 1.0
    assert extended.bracket_low == 0.0
    assert extended.combinations == frozenset({"default"})
    with pytest.raises(AttributeError):
        extended.trials = ()  # type: ignore[misc]


# -- plans, approvals, and AI drafts -------------------------------------------------


def step(value: float = 5.0) -> SearchStep:
    return SearchStep(
        index=0,
        value=value,
        phase=SearchPhase.ESCALATION,
        combination=COMBINATION,
        budget_remaining=100.0,
        budget_ref=QUOTA,
        expected_cost=1.0,
    )


def test_an_untrusted_draft_compiles_into_the_same_plan_type_with_zero_authority() -> None:
    draft = UntrustedSearchDraft(step=step(), rationale="try 5% first")

    plan = draft.compile()

    assert isinstance(plan, SearchPlan)
    assert plan.origin is SearchOrigin.GENERATED
    assert plan.step == draft.step  # the same body an authored plan carries
    assert plan.authority is ApprovalAuthority.NONE
    assert plan.approval is None


def test_the_draft_type_has_nowhere_to_put_an_approval_token() -> None:
    """The distinction is structural: there is no field to populate.

    A comment, a docstring, or a convention "don't set this" would all fail
    here. The field does not exist, and pydantic's frozen config means it
    cannot be attached afterwards either.
    """
    assert "approval" not in UntrustedSearchDraft.model_fields
    draft = UntrustedSearchDraft(step=step())

    with pytest.raises(AttributeError):
        _ = draft.approval  # type: ignore[attr-defined]
    with pytest.raises(ValidationError):
        draft.approval = Approval(  # type: ignore[attr-defined]
            approved_by="sre", plan_digest="0" * 64
        )


def test_a_generated_plan_cannot_be_constructed_with_an_approval() -> None:
    """The negative control: an embedded approval token is refused outright."""
    draft = UntrustedSearchDraft(step=step())
    token = Approval(approved_by="sre-oncall", plan_digest=draft.compile().plan_digest)

    with pytest.raises(InvariantViolationError) as caught:
        SearchPlan(
            step=draft.step,
            origin=SearchOrigin.GENERATED,
            rationale=draft.rationale,
            approval=token,
        )

    assert caught.value.rule == RULE_GENERATED_CANNOT_BE_APPROVED
    assert "cannot supply its own" in str(caught.value)


def test_an_authored_plan_needs_no_approval_to_exist_but_only_one_to_carry_authority() -> None:
    authored = SearchPlan(step=step(), origin=SearchOrigin.AUTHORED, rationale="authored")

    assert authored.authority is ApprovalAuthority.NONE

    approved = SearchPlan(
        step=step(),
        origin=SearchOrigin.AUTHORED,
        rationale="authored",
        approval=Approval(approved_by="sre-oncall", plan_digest=authored.plan_digest),
    )

    assert approved.authority is ApprovalAuthority.APPROVED
    assert approved.plan_digest == authored.plan_digest


def test_an_approval_binds_to_the_plan_that_was_read() -> None:
    """Changing the step after approval breaks the binding."""
    approved = SearchPlan(
        step=step(5.0),
        origin=SearchOrigin.AUTHORED,
        approval=Approval(
            approved_by="sre-oncall",
            plan_digest=SearchPlan(step=step(5.0), origin=SearchOrigin.AUTHORED).plan_digest,
        ),
    )

    with pytest.raises(InvariantViolationError) as caught:
        SearchPlan(
            step=step(50.0),
            origin=SearchOrigin.AUTHORED,
            approval=approved.approval,
        )

    assert caught.value.rule == RULE_APPROVAL_MISMATCH


def test_an_approval_must_name_who_gave_it() -> None:
    with pytest.raises(InvariantViolationError):
        Approval(approved_by="   ", plan_digest="a" * 64)


def test_generated_and_authored_plans_serialise_to_the_same_shape() -> None:
    """Plan 15's phase-3 property, already true of the types."""
    generated = UntrustedSearchDraft(step=step(), rationale="r").compile().to_dict()
    authored = SearchPlan(step=step(), origin=SearchOrigin.AUTHORED, rationale="r").to_dict()

    assert set(generated) == set(authored)
    assert generated["origin"] == "generated"
    assert authored["origin"] == "authored"
    # Only the origin and the authority differ, and only one of them is authority.
    assert generated["authority"] == authored["authority"] == "none"
