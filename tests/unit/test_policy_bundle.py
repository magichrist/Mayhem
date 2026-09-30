"""Plan 07 Phase 1 — the policy vocabulary's own tests.

Four groups, in the order the plan names them: decision determinism,
budget-exhaustion arithmetic, lock predicates, and compatibility lookups —
then the negative controls Phase 5 asks for and Phase 1 already owes: an
expired policy version must not be able to authorize anything, and a decision
rebuilt from its recorded inputs must come back bit-for-bit.

Everything here is driven by explicit inputs, including the clock: no test
reads ``utc_now()``, because a test that depends on the wall clock is a test
that fails on a slow machine and hides real regressions behind retries.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.policy import (
    BUILTIN_PROFILES,
    BudgetCharge,
    BudgetNode,
    BudgetScope,
    CompatibilityCondition,
    CompatibilityEdge,
    CompatibilityVerdict,
    PolicyBundle,
    PolicyDimension,
    PolicyEffect,
    PolicyFacts,
    PolicyOperator,
    PolicyPredicate,
    PolicyRule,
    ResourceLock,
    acquire_lock,
    blocking_locks,
    compatibility_edge,
    effective_rules,
    evaluate_bundle,
    evaluate_compatibility,
    evaluate_rules,
    inherited_rules,
    is_environment_allowed,
    lock_conflicts,
    resolve_precedence,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

T0 = datetime(2026, 1, 1, tzinfo=UTC)
BEFORE_T0 = T0 - timedelta(hours=1)
AFTER_T0 = T0 + timedelta(hours=1)


def digest_of(rules: Iterable[PolicyRule]) -> str:
    """The rule digest ``evaluate_rules`` computes for these rules."""
    return evaluate_rules(rules, PolicyFacts(), default_effect=PolicyEffect.ALLOW).rule_digest


def _facts(**values: tuple[str, ...]) -> PolicyFacts:
    return PolicyFacts(values={PolicyDimension(name): vals for name, vals in values.items()})


def _rule(
    rule_id: str,
    dimension: PolicyDimension,
    operator: PolicyOperator,
    values: tuple[str, ...],
    effect: PolicyEffect,
    *,
    precedence: int = 0,
    reason: str = "",
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        dimension=dimension,
        predicate=PolicyPredicate(operator=operator, values=values),
        effect=effect,
        precedence=precedence,
        reason=reason,
    )


ALLOW_STAGING = _rule(
    "staging.allow",
    PolicyDimension.ENVIRONMENT,
    PolicyOperator.IN,
    ("staging",),
    PolicyEffect.ALLOW,
)
ALLOW_LOW_RISK = _rule(
    "risk.allow-low",
    PolicyDimension.RISK,
    PolicyOperator.AT_MOST,
    ("2",),
    PolicyEffect.ALLOW,
    precedence=5,
)
DENY_PRODUCTION_CRITICAL = _rule(
    "production.deny-critical",
    PolicyDimension.ENVIRONMENT,
    PolicyOperator.IN,
    ("production",),
    PolicyEffect.DENY,
    precedence=10,
    reason="production policy forbids critical faults without two approvals",
)


def _bundle(*rules: PolicyRule, **kwargs: object) -> PolicyBundle:
    payload: dict[str, object] = {
        "bundle_id": "test-bundle",
        "version": 1,
        "rules": rules,
        "created_at": T0,
    }
    payload.update(kwargs)
    return PolicyBundle(**payload)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Decision determinism
# --------------------------------------------------------------------------


def test_same_bundle_and_facts_yield_the_same_decision():
    bundle = _bundle(ALLOW_STAGING, ALLOW_LOW_RISK).pin()
    facts = _facts(environment=("staging",), risk=("1",))

    first = evaluate_bundle(bundle, facts, now=BEFORE_T0)
    second = evaluate_bundle(bundle, facts, now=BEFORE_T0)

    assert first == second
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.decision_digest() == second.decision_digest()


def test_collection_order_of_rules_cannot_change_the_decision():
    rules = (ALLOW_STAGING, DENY_PRODUCTION_CRITICAL, ALLOW_LOW_RISK)
    facts = _facts(environment=("production",), risk=("1",))

    forwards = evaluate_rules(rules, facts)
    backwards = evaluate_rules(tuple(reversed(rules)), facts)
    unordered = evaluate_rules(frozenset(rules), facts)

    assert forwards.decision_digest() == backwards.decision_digest()
    assert forwards.decision_digest() == unordered.decision_digest()
    # Determinism is not vacuous: all three really did decide the same way.
    assert forwards.denied


def test_precedence_orders_rules_by_content_not_arrival():
    ordered = resolve_precedence((ALLOW_STAGING, ALLOW_LOW_RISK, DENY_PRODUCTION_CRITICAL))
    assert [rule.rule_id for rule in ordered] == [
        DENY_PRODUCTION_CRITICAL.rule_id,  # precedence 10
        ALLOW_LOW_RISK.rule_id,  # precedence 5
        ALLOW_STAGING.rule_id,  # precedence 0
    ]
    assert resolve_precedence(tuple(reversed(ordered))) == ordered


def test_deny_overrides_allow_however_high_the_allow_precedence():
    loud_allow = _rule(
        "prod.allow-everything",
        PolicyDimension.ENVIRONMENT,
        PolicyOperator.IN,
        ("production",),
        PolicyEffect.ALLOW,
        precedence=1000,
        reason="explicitly permits production",
    )
    facts = _facts(environment=("production",))

    decision = evaluate_rules((loud_allow, DENY_PRODUCTION_CRITICAL), facts)

    assert decision.denied
    assert decision.matched_rules == (DENY_PRODUCTION_CRITICAL.rule_id,)
    assert "two approvals" in decision.reasons[0]


def test_unmatched_facts_are_refused_by_default():
    decision = evaluate_rules((ALLOW_STAGING,), _facts(environment=("dev",)))

    assert decision.denied
    assert "policy.default_deny" in decision.reasons[0]
    assert decision.matched_rules == ()


def test_a_permissive_bundle_allows_what_no_rule_mentions():
    bundle = _bundle(ALLOW_STAGING, default_effect=PolicyEffect.ALLOW)
    decision = evaluate_bundle(bundle, _facts(environment=("dev",)), now=BEFORE_T0)

    assert decision.allowed
    assert decision.matched_rules == ()


def test_allow_rules_that_match_all_report_themselves():
    bundle = _bundle(ALLOW_STAGING, ALLOW_LOW_RISK)
    facts = _facts(environment=("staging",), risk=("0",))

    decision = evaluate_bundle(bundle, facts, now=BEFORE_T0)

    assert decision.allowed
    assert set(decision.matched_rules) == {ALLOW_STAGING.rule_id, ALLOW_LOW_RISK.rule_id}
    assert all(
        f"[{rule_id}]" in reason
        for rule_id, reason in zip(decision.matched_rules, decision.reasons, strict=True)
    )


def test_rule_explanation_names_dimension_test_and_observation():
    facts = _facts(environment=("production", "staging"))

    explanation = DENY_PRODUCTION_CRITICAL.explain(facts)

    assert "production.deny-critical" in explanation
    assert "environment in(production)" in explanation
    assert "observed production, staging" in explanation


def test_child_bundle_overrides_the_inherited_rule():
    parent = _bundle(ALLOW_STAGING, bundle_id="parent")
    override = _rule(
        ALLOW_STAGING.rule_id,
        PolicyDimension.ENVIRONMENT,
        PolicyOperator.IN,
        ("dev",),
        PolicyEffect.ALLOW,
        reason="parent allowed staging; child allows dev",
    )
    child = _bundle(override, bundle_id="child", version=2, parents=("parent",))

    index = {"parent": parent, "child": child}
    resolved = effective_rules(child, index)
    facts = _facts(environment=("staging",))

    assert [rule.rule_id for rule in resolved] == [ALLOW_STAGING.rule_id]
    # The override is in force: staging no longer matches the surviving rule.
    assert evaluate_rules(resolved, facts).denied
    assert evaluate_rules(resolved, _facts(environment=("dev",))).allowed


def test_inheritance_keeps_unrelated_parent_rules():
    parent = _bundle(ALLOW_STAGING, ALLOW_LOW_RISK, bundle_id="parent")
    child = _bundle(DENY_PRODUCTION_CRITICAL, bundle_id="child", version=3, parents=("parent",))

    assert [rule.rule_id for rule in effective_rules(child, {"parent": parent})] == [
        DENY_PRODUCTION_CRITICAL.rule_id,
        ALLOW_LOW_RISK.rule_id,
        ALLOW_STAGING.rule_id,
    ]


def test_inherited_rules_rejects_an_unknown_parent():
    with pytest.raises(InvariantViolationError) as excinfo:
        inherited_rules(_bundle(bundle_id="orphan", parents=("missing",)), {})
    assert excinfo.value.rule == "policy.bundle_parent_missing"


def test_inherited_rules_rejects_an_inheritance_cycle():
    left = _bundle(bundle_id="left", parents=("right",))
    right = _bundle(bundle_id="right", parents=("left",))

    with pytest.raises(InvariantViolationError) as excinfo:
        inherited_rules(left, {"left": left, "right": right})
    assert excinfo.value.rule == "policy.bundle_cycle"


# --------------------------------------------------------------------------
# Digests, pinning, replay
# --------------------------------------------------------------------------


def test_bundle_digest_is_stable_for_identical_content():
    assert _bundle(ALLOW_STAGING).compute_digest() == _bundle(ALLOW_STAGING).compute_digest()


def test_bundle_digest_changes_when_any_rule_changes():
    baseline = _bundle(ALLOW_STAGING).compute_digest()

    assert _bundle(ALLOW_STAGING, DENY_PRODUCTION_CRITICAL).compute_digest() != baseline
    assert _bundle(ALLOW_STAGING, version=2).compute_digest() != baseline


def test_pin_round_trips_and_verifies():
    pinned = _bundle(ALLOW_STAGING).pin()

    assert pinned.is_pinned()
    assert pinned.content_digest == pinned.compute_digest()
    assert pinned.verify_pin()


def test_a_pinned_bundle_refuses_to_exist_with_a_drifted_pin():
    bundle = _bundle(ALLOW_STAGING)
    payload = bundle.model_dump(mode="json")
    payload["content_digest"] = "0" * 64

    with pytest.raises(InvariantViolationError) as excinfo:
        PolicyBundle.model_validate(payload)
    assert excinfo.value.rule == "policy.bundle_digest_mismatch"


def test_decision_carries_the_rule_and_policy_digests():
    pinned = _bundle(ALLOW_STAGING).pin()
    decision = evaluate_bundle(pinned, _facts(environment=("staging",)), now=BEFORE_T0)

    assert decision.policy_digest == pinned.compute_digest()
    assert decision.rule_digest == digest_of([ALLOW_STAGING])
    assert decision.facts_digest == _facts(environment=("staging",)).facts_digest()
    assert decision.inputs()["bundle"] == "test-bundle v1"


def test_two_different_rule_sets_cannot_share_a_decision_digest():
    facts = _facts(environment=("staging",))
    with_low_risk = evaluate_rules((ALLOW_STAGING, ALLOW_LOW_RISK), facts)
    without_low_risk = evaluate_rules((ALLOW_STAGING,), facts, default_effect=PolicyEffect.ALLOW)

    assert with_low_risk.allowed and without_low_risk.allowed
    assert with_low_risk.decision_digest() != without_low_risk.decision_digest()


def test_decision_replay_from_recorded_inputs_reproduces_it_bit_for_bit():
    bundle = _bundle(ALLOW_STAGING, DENY_PRODUCTION_CRITICAL).pin()
    facts = _facts(environment=("production",), risk=("3",))

    recorded = evaluate_bundle(bundle, facts, now=BEFORE_T0)
    envelope = recorded.model_dump(mode="json")

    # Replay: rebuild the inputs from the record and evaluate again.
    replayed_bundle = PolicyBundle.model_validate(
        {**bundle.model_dump(mode="json"), "content_digest": recorded.policy_digest}
    )
    replayed = evaluate_bundle(replayed_bundle, facts, now=BEFORE_T0)

    assert replayed.model_dump(mode="json") == envelope
    assert replayed.decision_digest() == recorded.decision_digest()
    assert replayed.reasons == recorded.reasons


# --------------------------------------------------------------------------
# Negative controls
# --------------------------------------------------------------------------


def test_expired_bundle_version_cannot_authorize_a_run():
    bundle = _bundle(
        ALLOW_STAGING,
        expires_at=T0 + timedelta(minutes=30),
    )
    facts = _facts(environment=("staging",))

    assert evaluate_bundle(bundle, facts, now=BEFORE_T0).allowed
    decision = evaluate_bundle(bundle, facts, now=T0 + timedelta(minutes=30))

    assert decision.denied
    assert "expired" in decision.reasons[0]
    assert "policy.bundle_expired" in decision.reasons[0]


def test_expiry_refuses_before_any_rule_is_consulted():
    bundle = _bundle(ALLOW_STAGING, DENY_PRODUCTION_CRITICAL, expires_at=T0 + timedelta(minutes=30))
    facts = _facts(environment=("staging",))

    decision = evaluate_bundle(bundle, facts, now=AFTER_T0)

    assert decision.matched_rules == ()
    assert decision.reasons == (
        "policy bundle test-bundle v1 (expires 2026-01-01T00:30:00+00:00) expired at "
        "2026-01-01T00:30:00+00:00; an expired policy version cannot authorize a run "
        "[policy.bundle_expired]",
    )
    # The digests are still filled in: a refusal is evidence too.
    assert decision.policy_digest == bundle.compute_digest()


def test_an_unexpiring_bundle_never_goes_stale():
    bundle = _bundle(ALLOW_STAGING)

    assert bundle.authorizes(datetime(2099, 1, 1, tzinfo=UTC))
    assert evaluate_bundle(
        bundle, _facts(environment=("staging",)), now=datetime(2099, 1, 1, tzinfo=UTC)
    )


def test_bundle_expiry_must_follow_creation():
    with pytest.raises(InvariantViolationError) as excinfo:
        _bundle(ALLOW_STAGING, created_at=T0, expires_at=T0 - timedelta(seconds=1))
    assert excinfo.value.rule == "policy.bundle_window"


def test_not_in_does_not_match_a_dimension_the_facts_never_recorded():
    deny_unstaged = _rule(
        "schedule.deny-unstaged",
        PolicyDimension.SCHEDULE,
        PolicyOperator.NOT_IN,
        ("approved",),
        PolicyEffect.DENY,
        reason="unapproved schedule",
    )

    decision = evaluate_rules((deny_unstaged, ALLOW_STAGING), _facts(environment=("staging",)))

    # The schedule dimension is unobserved, so the "not in" rule cannot speak —
    # and the allow rule that does speak decides the outcome.
    assert decision.allowed
    assert decision.matched_rules == (ALLOW_STAGING.rule_id,)


def test_absent_and_present_speak_only_about_observability():
    absent_ok = _rule(
        "incident.absent-ok",
        PolicyDimension.INCIDENT_STATE,
        PolicyOperator.ABSENT,
        (),
        PolicyEffect.ALLOW,
        reason="no open incident",
    )
    present_denied = _rule(
        "incident.deny-open",
        PolicyDimension.INCIDENT_STATE,
        PolicyOperator.PRESENT,
        (),
        PolicyEffect.DENY,
        reason="an incident is open",
    )

    rules = (absent_ok, present_denied)
    assert evaluate_rules(rules, PolicyFacts()).matched_rules == (absent_ok.rule_id,)
    assert evaluate_rules(rules, _facts(incident_state=("open",))).matched_rules == (
        present_denied.rule_id,
    )


def test_a_numeric_rule_needs_a_numeric_threshold():
    with pytest.raises(InvariantViolationError) as excinfo:
        _rule(
            "risk.at-most",
            PolicyDimension.RISK,
            PolicyOperator.AT_MOST,
            ("high",),
            PolicyEffect.DENY,
        )
    assert excinfo.value.rule == "policy.predicate_values"

    with pytest.raises(InvariantViolationError) as excinfo:
        PolicyPredicate(operator=PolicyOperator.IN)
    assert excinfo.value.rule == "policy.predicate_values"


# --------------------------------------------------------------------------
# Hierarchical damage budgets (gap 67)
# --------------------------------------------------------------------------


def _budget_tree(
    *,
    team: float | None = 100.0,
    environment: float | None = 80.0,
    service: float | None = 50.0,
    experiment: float | None = 30.0,
    fault: float | None = 10.0,
) -> BudgetNode:
    """The five-level tree, built leaf-up because ``with_child`` returns the parent."""
    node = BudgetNode(scope=BudgetScope.FAULT, key="net.partition", limit_s=fault)
    node = BudgetNode(scope=BudgetScope.EXPERIMENT, key="exp-1", limit_s=experiment).with_child(
        node
    )
    node = BudgetNode(scope=BudgetScope.SERVICE, key="checkout", limit_s=service).with_child(node)
    node = BudgetNode(
        scope=BudgetScope.ENVIRONMENT, key="production", limit_s=environment
    ).with_child(node)
    return BudgetNode(scope=BudgetScope.TEAM, key="platform", limit_s=team).with_child(node)


FULL_PATH = ("platform", "production", "checkout", "exp-1", "net.partition")


def _at(tree: BudgetNode, scope: BudgetScope, key: str) -> BudgetNode:
    """``find`` with the assertion the type checker and the reader both want."""
    found = tree.find(scope, key)
    assert found is not None, f"{scope.value} {key!r} is missing from the budget tree"
    return found


def test_a_charge_posts_to_every_level_widest_first():
    _, charges = _budget_tree().post_charge(FULL_PATH, 7.5)

    assert [charge.scope for charge in charges] == [
        BudgetScope.TEAM,
        BudgetScope.ENVIRONMENT,
        BudgetScope.SERVICE,
        BudgetScope.EXPERIMENT,
        BudgetScope.FAULT,
    ]
    assert [(c.before_s, c.after_s) for c in charges] == [(0.0, 7.5)] * 5
    assert [c.headroom_s for c in charges] == [92.5, 72.5, 42.5, 22.5, 2.5]
    assert not any(charge.exceeded for charge in charges)


def test_charges_accumulate_across_posts():
    tree, _ = _budget_tree().post_charge(FULL_PATH, 7.5)
    charged, charges = tree.post_charge(FULL_PATH, 2.5)

    assert _at(charged, BudgetScope.FAULT, "net.partition").spent_s == 10.0
    assert [c.after_s for c in charges] == [10.0, 10.0, 10.0, 10.0, 10.0]
    # 10.0 is the fault's limit exactly: over-budget is strictly greater.
    assert not any(c.exceeded for c in charges)


def test_budget_exhaustion_is_reported_on_the_level_that_blew():
    before, _ = _budget_tree().post_charge(FULL_PATH, 9.0)
    charged, charges = before.post_charge(FULL_PATH, 2.0)

    exhausted = [c for c in charges if c.exceeded]
    assert [c.scope for c in exhausted] == [BudgetScope.FAULT]
    assert exhausted[0].after_s == 11.0
    assert exhausted[0].headroom_s == -1.0
    assert before.is_exhausted() is False
    assert charged.is_exhausted() is True
    assert _at(charged, BudgetScope.FAULT, "net.partition").exhausted is True
    # The levels above it still have room, and still know it.
    assert _at(charged, BudgetScope.EXPERIMENT, "exp-1").headroom_s == 19.0


def test_a_wide_charge_exhausts_the_widest_level_only():
    # Team budget deliberately tighter than every level beneath it, which is
    # what "the team runs out first" means when the limits are nested.
    tree = _budget_tree(team=50.0, environment=500.0, service=500.0, experiment=500.0, fault=500.0)
    before, first = tree.post_charge(FULL_PATH, 45.0)
    charged, second = before.post_charge(FULL_PATH, 60.0)

    assert not any(c.exceeded for c in first)  # the first post fits everywhere
    assert [c.scope for c in second if c.exceeded] == [BudgetScope.TEAM]
    assert _at(charged, BudgetScope.TEAM, "platform").headroom_s == -55.0
    assert charged.is_exhausted()


def test_a_partial_path_charges_only_the_levels_it_names():
    charged, charges = _budget_tree().post_charge(("platform", "production"), 12.0)

    assert [c.scope for c in charges] == [BudgetScope.TEAM, BudgetScope.ENVIRONMENT]
    assert _at(charged, BudgetScope.FAULT, "net.partition").spent_s == 0.0


def test_posting_never_mutates_the_tree_it_was_given():
    tree = _budget_tree()

    charged, _ = tree.post_charge(FULL_PATH, 7.5)

    assert _at(tree, BudgetScope.TEAM, "platform").spent_s == 0.0
    assert _at(charged, BudgetScope.TEAM, "platform").spent_s == 7.5
    assert charged is not tree


def test_charging_is_exact_under_repetition():
    """1000 x 0.1 must land on 100.0, not 99.99999999999792."""
    tree = _budget_tree()
    for _ in range(999):
        tree, _ = tree.post_charge(FULL_PATH, 0.1)
    tree, charges = tree.post_charge(FULL_PATH, 0.1)

    assert _at(tree, BudgetScope.TEAM, "platform").spent_s == 100.0
    assert charges[0].exceeded is False  # the limit, not past it


def test_posting_to_a_path_that_does_not_exist_refuses():
    with pytest.raises(InvariantViolationError) as excinfo:
        _budget_tree().post_charge((*FULL_PATH[:-1], "node.reboot"), 1.0)
    assert excinfo.value.rule == "budget.path_missing"


def test_posting_a_negative_charge_refuses():
    with pytest.raises(InvariantViolationError) as excinfo:
        _budget_tree().post_charge(FULL_PATH, -1.0)
    assert excinfo.value.rule == "budget.negative_charge"


def test_an_unbounded_level_never_goes_over():
    tree = _budget_tree(fault=None)
    charged, charges = tree.post_charge(FULL_PATH, 10_000.0)

    fault_charge = next(c for c in charges if c.scope is BudgetScope.FAULT)
    assert fault_charge.unbounded
    assert fault_charge.headroom_s is None
    assert fault_charge.exceeded is False
    # The bounded levels above it still do the refusing.
    assert [c.scope for c in charges if c.exceeded] == [
        BudgetScope.TEAM,
        BudgetScope.ENVIRONMENT,
        BudgetScope.SERVICE,
        BudgetScope.EXPERIMENT,
    ]
    assert charged.is_exhausted()


def test_a_node_cannot_hold_a_level_that_is_not_next():
    team = BudgetNode(scope=BudgetScope.TEAM, key="platform")
    service = BudgetNode(scope=BudgetScope.SERVICE, key="checkout")

    with pytest.raises(InvariantViolationError) as excinfo:
        team.with_child(service)
    assert excinfo.value.rule == "budget.scope_order"


def test_a_node_cannot_hold_two_children_with_the_same_name():
    team = BudgetNode(scope=BudgetScope.TEAM, key="platform").with_child(
        BudgetNode(scope=BudgetScope.ENVIRONMENT, key="production")
    )

    with pytest.raises(InvariantViolationError) as excinfo:
        team.with_child(BudgetNode(scope=BudgetScope.ENVIRONMENT, key="production"))
    assert excinfo.value.rule == "budget.duplicate_child"


def test_charges_are_frozen_records_of_one_post():
    charge = BudgetCharge(
        scope=BudgetScope.FAULT,
        key="net.partition",
        amount_s=1.0,
        before_s=0.0,
        after_s=1.0,
        limit_s=2.0,
    )

    assert charge.headroom_s == 1.0
    with pytest.raises(ValidationError):
        charge.after_s = 5.0  # type: ignore[misc]


# --------------------------------------------------------------------------
# Environment locking (gap 86)
# --------------------------------------------------------------------------


def _lock(
    lock_id: str,
    *,
    resource: str = "db-primary",
    experiment: str = "exp-a",
    owner: str = "run-1",
    start: datetime = T0,
    end: datetime | None = None,
) -> ResourceLock:
    return ResourceLock(
        lock_id=lock_id,
        resource=resource,
        experiment_id=experiment,
        owner_run_id=owner,
        acquired_at=start,
        expires_at=end if end is not None else start + timedelta(minutes=30),
    )


def test_a_live_lock_refuses_a_second_experiment_and_names_the_owner():
    held = _lock("rl-1")
    wanted = _lock("rl-2", experiment="exp-b", owner="run-2", start=T0 + timedelta(minutes=1))

    verdict = acquire_lock([held], wanted, now=T0 + timedelta(minutes=2))

    assert verdict.granted is False
    assert verdict.queued_behind() == "run-1"
    assert verdict.holder_experiment_id == "exp-a"
    assert verdict.blockers == ("rl-1",)
    assert "run-1" in verdict.reason


def test_an_expired_lock_fences_nothing():
    held = _lock("rl-1", end=T0 + timedelta(minutes=10))
    wanted = _lock("rl-2", experiment="exp-b", owner="run-2", start=T0 + timedelta(minutes=1))

    assert acquire_lock([held], wanted, now=T0 + timedelta(minutes=5)).granted is False
    assert acquire_lock([held], wanted, now=T0 + timedelta(minutes=10)).granted is True


def test_an_experiment_may_retake_its_own_lock():
    held = _lock("rl-1", experiment="exp-a", owner="run-1")
    wanted = _lock(
        "rl-2", experiment="exp-a", owner="run-1-step-2", start=T0 + timedelta(minutes=1)
    )

    assert lock_conflicts(held, wanted) is False
    assert acquire_lock([held], wanted, now=T0 + timedelta(minutes=2)).granted is True


def test_locks_on_other_resources_do_not_conflict():
    held = _lock("rl-1", resource="db-primary")
    wanted = _lock("rl-2", resource="cache", experiment="exp-b", owner="run-2")

    assert lock_conflicts(held, wanted) is False
    assert acquire_lock([held], wanted, now=T0 + timedelta(minutes=1)).granted is True


def test_a_lock_does_not_block_a_window_that_never_overlaps():
    held = _lock("rl-1", start=T0, end=T0 + timedelta(minutes=5))
    wanted = _lock(
        "rl-2",
        experiment="exp-b",
        owner="run-2",
        start=T0 + timedelta(minutes=10),
        end=T0 + timedelta(minutes=20),
    )

    assert lock_conflicts(held, wanted) is False


def test_blockers_are_reported_in_a_stable_order():
    held = [_lock("rl-2"), _lock("rl-1"), _lock("rl-0", experiment="exp-c", owner="run-0")]
    wanted = _lock("rl-9", experiment="exp-b", owner="run-9", start=T0 + timedelta(minutes=1))

    assert [
        lock.lock_id for lock in blocking_locks(held, wanted, now=T0 + timedelta(minutes=2))
    ] == [
        "rl-0",
        "rl-1",
        "rl-2",
    ]
    assert acquire_lock(held, wanted, now=T0 + timedelta(minutes=2)).blockers == (
        "rl-0",
        "rl-1",
        "rl-2",
    )


def test_a_lock_window_must_close_after_it_opens():
    with pytest.raises(InvariantViolationError) as excinfo:
        _lock("rl-1", start=T0, end=T0)
    assert excinfo.value.rule == "lock.window"


def test_lock_liveness_predicates():
    lock = _lock("rl-1", start=T0, end=T0 + timedelta(minutes=10))

    assert lock.is_live(T0 + timedelta(minutes=9)) is True
    assert lock.is_expired(T0 + timedelta(minutes=9)) is False
    assert lock.is_live(T0 + timedelta(minutes=10)) is False
    assert lock.is_expired(T0 + timedelta(minutes=10)) is True
    assert lock.covers("db-primary") is True
    assert lock.is_owned_by("exp-a") is True


# --------------------------------------------------------------------------
# Fault-pair compatibility (gap 66)
# --------------------------------------------------------------------------


CONFLICT = CompatibilityEdge(
    left_fault="node.reboot",
    right_fault="net.partition",
    verdict=CompatibilityVerdict.CONFLICTING,
    reason="a reboot tears the network plane out from under the partition",
)
CONDITIONAL = CompatibilityEdge(
    left_fault="net.latency",
    right_fault="cpu.throttle",
    verdict=CompatibilityVerdict.CONDITIONALLY_SAFE,
    conditions=(
        CompatibilityCondition(dimension=PolicyDimension.ENVIRONMENT, values=("staging", "dev")),
    ),
)
PERMITTED = CompatibilityEdge(
    left_fault="net.latency",
    right_fault="net.latency.deep",
    verdict=CompatibilityVerdict.PERMITTED,
    reason="both stay inside the data plane",
)
EDGES = (CONFLICT, CONDITIONAL, PERMITTED)


def test_a_declared_pair_is_found_in_either_order():
    assert compatibility_edge(EDGES, "node.reboot", "net.partition") is CONFLICT
    assert compatibility_edge(EDGES, "net.partition", "node.reboot") is CONFLICT
    assert compatibility_edge(EDGES, "node.drain", "net.latency") is None


def test_lookup_does_not_depend_on_the_order_edges_were_declared_in():
    forwards = evaluate_compatibility(EDGES, "node.reboot", "net.partition", PolicyFacts())
    backwards = evaluate_compatibility(
        tuple(reversed(EDGES)), "node.reboot", "net.partition", PolicyFacts()
    )

    assert forwards.model_dump(mode="json") == backwards.model_dump(mode="json")


def test_a_conflicting_pair_is_refused_and_says_why():
    outcome = evaluate_compatibility(EDGES, "net.partition", "node.reboot", PolicyFacts())

    assert outcome.verdict is CompatibilityVerdict.CONFLICTING
    assert outcome.safe is False
    assert outcome.declared is True
    assert "network plane" in outcome.reason


def test_an_undeclared_pair_is_permitted_by_default():
    outcome = evaluate_compatibility(EDGES, "node.drain", "net.latency", PolicyFacts())

    assert outcome.verdict is CompatibilityVerdict.PERMITTED
    assert outcome.safe is True
    assert outcome.declared is False
    assert "no collision edge" in outcome.reason


def test_a_conditionally_safe_pair_needs_its_facts():
    unset = evaluate_compatibility(EDGES, "net.latency", "cpu.throttle", PolicyFacts())
    wrong_env = evaluate_compatibility(
        EDGES, "net.latency", "cpu.throttle", _facts(environment=("production",))
    )
    right_env = evaluate_compatibility(
        EDGES, "net.latency", "cpu.throttle", _facts(environment=("staging",))
    )

    assert unset.verdict is CompatibilityVerdict.CONFLICTING
    assert unset.unsatisfied == ("environment",)
    assert unset.safe is False
    assert wrong_env.safe is False
    assert right_env.verdict is CompatibilityVerdict.CONDITIONALLY_SAFE
    assert right_env.conditional is True
    assert right_env.safe is True
    assert right_env.unsatisfied == ()


def test_an_explicitly_permitted_pair_says_so():
    outcome = evaluate_compatibility(EDGES, "net.latency", "net.latency.deep", PolicyFacts())

    assert outcome.safe is True
    assert outcome.declared is True
    assert "data plane" in outcome.reason


def test_a_conflicting_edge_must_carry_a_reason():
    with pytest.raises(InvariantViolationError) as excinfo:
        CompatibilityEdge(
            left_fault="a.b",
            right_fault="c.d",
            verdict=CompatibilityVerdict.CONFLICTING,
        )
    assert excinfo.value.rule == "compat.reason_required"


def test_a_conditionally_safe_edge_must_carry_conditions():
    with pytest.raises(InvariantViolationError) as excinfo:
        CompatibilityEdge(
            left_fault="a.b",
            right_fault="c.d",
            verdict=CompatibilityVerdict.CONDITIONALLY_SAFE,
        )
    assert excinfo.value.rule == "compat.conditions_required"


def test_an_edge_cannot_pair_a_fault_with_itself():
    with pytest.raises(InvariantViolationError) as excinfo:
        CompatibilityEdge(
            left_fault="a.b",
            right_fault="a.b",
            verdict=CompatibilityVerdict.CONFLICTING,
            reason="itself",
        )
    assert excinfo.value.rule == "compat.self_pair"


# --------------------------------------------------------------------------
# The target-profile half of this module is untouched by the work above
# --------------------------------------------------------------------------


def test_builtin_profiles_and_the_environment_predicate_still_behave():
    assert "strict" in BUILTIN_PROFILES
    assert is_environment_allowed(BUILTIN_PROFILES["production"], "production") is True
    assert is_environment_allowed(BUILTIN_PROFILES["production"], "dev") is False
    assert is_environment_allowed(BUILTIN_PROFILES["production"], None) is True
