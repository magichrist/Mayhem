"""Plan 07 Phase 2 — policy evaluation inside the real gate.

The Phase 1 suite (``test_policy_bundle.py``) proved the vocabulary decides.
This suite proves the thing that was missing: that the decision is reached
*inside* ``safety.validate_plan``, that it is additive, and that simulating it
changes nothing.

Four groups, in the order the plan's acceptance names them — a DENY refuses and
names its rule, the preconditions (lock, budget, pair compatibility) are
consulted at admission, simulation is provably pure, and a replay reproduces
the decision — then the negative controls: an expired bundle version cannot
authorize, no ALLOW outranks a DENY, and a simulation cannot mutate.

Every input is explicit, including the clock. ``PolicyGateInputs`` has no
default for ``now`` precisely so a test cannot smuggle one in.
"""

from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.policy_gate import (
    RULE_APPROVAL_REQUIRED,
    RULE_BUDGET_EXHAUSTED,
    RULE_BUNDLE_ALLOW,
    RULE_BUNDLE_DENY,
    RULE_BUNDLE_EXPIRED,
    RULE_COMPAT_CONFLICT,
    RULE_LOCK_CONTENDED,
    RULE_POLICY_CONFIG,
    BudgetAuthority,
    ConfigDefect,
    HierarchyBudgetView,
    MutationSink,
    PolicyGateInputs,
    QuotaBudgetView,
    _risk_of,
    derive_facts,
    detect_config_defect,
    evaluate_gate,
    probe_budget,
    probe_quota,
    reconcile_budgets,
    simulate_gate,
)
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    simulate_plan_policy,
    validate_plan,
)
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
from mayhem.domain.policy import (
    BudgetCharge,
    BudgetNode,
    BudgetScope,
    CompatibilityCondition,
    CompatibilityEdge,
    CompatibilityVerdict,
    PolicyBundle,
    PolicyDimension,
    PolicyEffect,
    PolicyOperator,
    PolicyPredicate,
    PolicyRule,
    ResourceLock,
)
from mayhem.domain.quota import DamageQuota
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
BEFORE = T0 - timedelta(hours=1)
AFTER = T0 + timedelta(hours=1)
STEP_S = 5.0

#: Where this run sits in the five-level budget hierarchy. The gate appends the
#: fault id for the leaf.
BUDGET_PATH = ("sre", "production", "web", "exp-1")


# -- fixtures -----------------------------------------------------------------------


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-api", name="api"),
            ServiceNode(id="n-web", name="web"),
            ServiceNode(id="n-db", name="db"),
        ),
        edges=(
            Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON, weight=1.0),
            Edge(src="n-api", dst="n-db", kind=EdgeKind.DEPENDS_ON, weight=2.0),
        ),
    )


def _plan(*fault_ids: str, duration: float = STEP_S, run_id: str = "run-1") -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="web")
    steps = tuple(
        PlannedStep(
            id=f"s{seq}",
            seq=seq,
            raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=duration),
            fault=PlannedFault(
                fault_id=fault_id,
                targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-web"})),),
                duration=duration,
            ),
        )
        for seq, fault_id in enumerate(fault_ids)
    )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=steps,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def _rule(
    rule_id: str,
    dimension: PolicyDimension,
    operator: PolicyOperator,
    values: tuple[str, ...],
    effect: PolicyEffect = PolicyEffect.DENY,
    *,
    precedence: int = 0,
    reason: str = "",
    remediation: str = "",
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        dimension=dimension,
        predicate=PolicyPredicate(operator=operator, values=values),
        effect=effect,
        precedence=precedence,
        reason=reason,
        remediation=remediation,
    )


def _prod_deny(reason: str = "production policy forbids this") -> PolicyRule:
    return _rule(
        "prod.forbids",
        PolicyDimension.ENVIRONMENT,
        PolicyOperator.IN,
        ("production",),
        reason=reason,
        remediation="use --environment staging",
    )


def _bundle(
    *rules: PolicyRule,
    default: PolicyEffect = PolicyEffect.ALLOW,
    version: int = 1,
    expires_at: datetime | None = None,
    bundle_id: str = "gate-test",
    parents: tuple[str, ...] = (),
) -> PolicyBundle:
    return PolicyBundle(
        bundle_id=bundle_id,
        version=version,
        rules=rules,
        parents=parents,
        default_effect=default,
        created_at=T0 - timedelta(days=1),
        expires_at=expires_at,
    )


def _inputs(
    bundle: PolicyBundle | None = None, *, now: datetime = T0, **kwargs: Any
) -> PolicyGateInputs:
    return PolicyGateInputs(bundle=bundle or _bundle(), now=now, **kwargs)


def _ctx(gate: PolicyGateInputs | None = None, **kwargs: Any) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        # Wide enough that the per-step blast caps never fire: these tests are
        # about the policy half, and a refusal has to have exactly one cause.
        budget=BlastRadiusBudget(max_services_pct=100.0),
        fingerprint="f",
        policy_gate=gate,
        **kwargs,
    )


def _dump(ctx: SafetyContext) -> str:
    """A stable rendering of everything one validation pass recorded."""
    return "\n".join(
        f"{d.rule_id}|{d.outcome}|{d.reason}|{d.remediation}|{sorted(d.inputs)}"
        for d in ctx.decisions
    )


def _budget_tree(
    leaf_limit: float, *fault_ids: str, path: tuple[str, ...] = BUDGET_PATH
) -> BudgetNode:
    """A full five-level budget; only the per-fault leaves carry a tight limit."""
    team, environment, service, experiment = path
    leaves = tuple(
        BudgetNode(scope=BudgetScope.FAULT, key=fault_id, limit_s=leaf_limit)
        for fault_id in fault_ids
    )
    return BudgetNode(
        scope=BudgetScope.TEAM,
        key=team,
        limit_s=1e6,
        children=(
            BudgetNode(
                scope=BudgetScope.ENVIRONMENT,
                key=environment,
                limit_s=1e6,
                children=(
                    BudgetNode(
                        scope=BudgetScope.SERVICE,
                        key=service,
                        limit_s=1e6,
                        children=(
                            BudgetNode(
                                scope=BudgetScope.EXPERIMENT,
                                key=experiment,
                                limit_s=1e6,
                                children=leaves,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )


def _lock(
    lock_id: str = "lock-1",
    *,
    resource: str = "db-primary",
    experiment_id: str = "exp-other",
    owner_run_id: str = "run-holder",
    acquired_at: datetime = BEFORE,
    expires_at: datetime = AFTER,
) -> ResourceLock:
    return ResourceLock(
        lock_id=lock_id,
        resource=resource,
        experiment_id=experiment_id,
        owner_run_id=owner_run_id,
        acquired_at=acquired_at,
        expires_at=expires_at,
    )


def _conflict(left: str, right: str, reason: str = "declared conflict") -> CompatibilityEdge:
    return CompatibilityEdge(
        left_fault=left, right_fault=right, verdict=CompatibilityVerdict.CONFLICTING, reason=reason
    )


# -- decision to refusal ------------------------------------------------------------


def test_deny_refuses_the_plan_and_names_the_rule():
    ctx = _ctx(_inputs(_bundle(_prod_deny())), environment="production")
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(_plan("proc.pause"), _graph(), ctx)
    decision = excinfo.value.decision
    assert decision is not None
    assert decision.rule_id == RULE_BUNDLE_DENY
    # The rule that refused is named in the reason *and* machine-readably, so a
    # log line and a query cannot disagree about which rule spoke.
    assert "prod.forbids" in decision.reason
    assert decision.inputs["policy_rule_ids"] == ["prod.forbids"]
    assert decision.remediation == "use --environment staging"
    assert decision.inputs["policy_digest"] == ctx.policy_gate.bundle.compute_digest()  # type: ignore[union-attr]


def test_allow_records_a_decision_naming_the_bundle():
    bundle = _bundle(_prod_deny())
    ctx = _ctx(_inputs(bundle), environment="staging")
    validate_plan(_plan("proc.pause"), _graph(), ctx)
    allow = [d for d in ctx.decisions if d.rule_id == RULE_BUNDLE_ALLOW]
    assert len(allow) == 1
    assert allow[0].inputs["bundle"] == "gate-test v1"
    assert allow[0].inputs["policy_digest"] == bundle.compute_digest()
    assert allow[0].inputs["refusal_rule_id"] == ""


def _approval_bundle() -> PolicyBundle:
    return _bundle(
        _rule(
            "prod.approval-level",
            PolicyDimension.APPROVAL_LEVEL,
            PolicyOperator.IN,
            ("sre", "service_owner"),
            effect=PolicyEffect.ALLOW,
        )
    )


def test_approval_already_held_is_not_reported_as_outstanding():
    """A requirement that is met is not something a human still has to do."""
    ctx = _ctx(
        _inputs(
            _approval_bundle(),
            observed={PolicyDimension.APPROVAL_LEVEL: ("sre", "service_owner")},
        ),
        environment="production",
    )
    # The plan is *not* refused: a requirement that refuses would be an
    # approval implementation, and a premature one.
    validate_plan(_plan("proc.pause"), _graph(), ctx)
    assert [d for d in ctx.decisions if d.rule_id == RULE_APPROVAL_REQUIRED] == []
    assert ctx.warnings == []


def test_approval_requirement_reports_only_the_levels_still_outstanding():
    """Plan 09 implements approvals; Phase 2 only says what is required."""
    ctx = _ctx(
        _inputs(
            _approval_bundle(),
            observed={PolicyDimension.APPROVAL_LEVEL: ("sre",)},
        ),
        environment="production",
    )
    validate_plan(_plan("proc.pause"), _graph(), ctx)
    surfaced = [d for d in ctx.decisions if d.rule_id == RULE_APPROVAL_REQUIRED]
    assert [d.inputs["approval_level"] for d in surfaced] == ["service_owner"]
    assert all(d.outcome == "warn" for d in surfaced)
    assert ctx.warnings == [d.reason for d in surfaced]


def test_approval_requirement_is_named_inside_a_refusal():
    bundle = _bundle(
        _prod_deny("production policy forbids critical faults without two approvals"),
        _rule(
            "prod.approval-level",
            PolicyDimension.APPROVAL_LEVEL,
            PolicyOperator.IN,
            ("sre", "service_owner"),
            effect=PolicyEffect.ALLOW,
        ),
    )
    # The approval rule matches only when a level is in hand; the levels it
    # names that are *not* in hand are what the refusal reports as required.
    ctx = _ctx(
        _inputs(bundle, observed={PolicyDimension.APPROVAL_LEVEL: ("sre",)}),
        environment="production",
    )
    with pytest.raises(SafetyRefusedError, match=r"Required: service_owner"):
        validate_plan(_plan("proc.pause"), _graph(), ctx)
    # With nothing in hand the full set is what the plan's example renders.
    ctx_bare = _ctx(_inputs(bundle), environment="production")
    assert evaluate_gate(_plan("proc.pause"), ctx_bare.policy_gate, environment="production").denied


# -- no-bundle behaviour is untouched ------------------------------------------------

#: Golden rendering of a full validation pass with no policy bundle. Any drift in
#: the existing gate — a reworded reason, a reordered check, a decision recorded
#: at a different point — breaks this line.
GOLDEN_NO_BUNDLE = "\n".join(
    (
        "policy.allow|allow|proc.pause: admitted||['fault_id', 'risk']",
        "blast_radius.allow|allow|proc.pause: blast radius within budget||"
        "['fault_id', 'stats']",
        "policy.allow|allow|net.latency: admitted||['fault_id', 'risk']",
        "blast_radius.allow|allow|net.latency: blast radius within budget||"
        "['fault_id', 'stats']",
    )
)


def test_no_bundle_pass_is_byte_identical_to_the_golden():
    ctx = _ctx()
    assert ctx.policy_gate is None
    validate_plan(_plan("proc.pause", "net.latency"), _graph(), ctx)
    assert _dump(ctx) == GOLDEN_NO_BUNDLE


def test_policy_gate_field_is_optional_and_defaults_to_absent():
    assert [f.name for f in fields(SafetyContext)][-1] == "policy_gate"
    # A context built with only the pre-Phase-2 arguments still constructs, and
    # the new field is absent rather than empty.
    legacy = SafetyContext(policy=PolicyCfg(), budget=BlastRadiusBudget(), fingerprint="f")
    assert legacy.policy_gate is None
    assert simulate_plan_policy(_plan("proc.pause"), legacy) is None


def test_bundle_is_additive_to_the_config_policy_half():
    """A configured bundle may add a refusal, never displace an existing one."""
    gate = _inputs(_bundle(_prod_deny()))
    plan = _plan("proc.pause")
    # The bundle's own verdict is what the gate reaches first.
    with pytest.raises(SafetyRefusedError, match=r"prod\.forbids"):
        validate_plan(plan, _graph(), _ctx(gate, environment="production"))
    # With a bundle that permits, the *existing* blast cap still refuses: the
    # bundle did not consume the gate's other half.
    tight = SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(max_services_pct=10.0),
        fingerprint="f",
        policy_gate=gate,
    )
    with pytest.raises(SafetyRefusedError, match="max_services_pct"):
        validate_plan(plan, _graph(), tight)
    # And the config-policy denylist still speaks with a bundle present.
    denylisted = SafetyContext(
        policy=PolicyCfg(deny_faults=frozenset({"proc.pause"})),
        budget=BlastRadiusBudget(max_services_pct=100.0),
        fingerprint="f",
        policy_gate=gate,
    )
    with pytest.raises(SafetyRefusedError, match=r"policy\.deny_faults"):
        validate_plan(plan, _graph(), denylisted)


# -- preconditions at admission -----------------------------------------------------


def test_lock_contention_refuses_and_names_the_holder():
    gate = _inputs(
        locks=(_lock(),),
        lock_resources=("db-primary",),
        experiment_id="exp-mine",
        run_id="run-mine",
    )
    ctx = _ctx(gate)
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(_plan("proc.pause"), _graph(), ctx)
    decision = excinfo.value.decision
    assert decision is not None
    assert decision.rule_id == RULE_LOCK_CONTENDED
    # The holder is named in the reason *and* machine-readably, so a queue can
    # be built without parsing prose.
    assert "run-holder" in decision.reason
    assert "exp-other" in decision.reason
    assert decision.inputs["holder_run_id"] == "run-holder"
    assert decision.inputs["holder_experiment_id"] == "exp-other"
    assert decision.inputs["blockers"] == ["lock-1"]
    assert decision.inputs["resource"] == "db-primary"


def test_expired_lock_does_not_block():
    gate = _inputs(
        locks=(_lock(expires_at=BEFORE + timedelta(minutes=1)),),
        lock_resources=("db-primary",),
        experiment_id="exp-mine",
    )
    validate_plan(_plan("proc.pause"), _graph(), _ctx(gate))
    result = evaluate_gate(_plan("proc.pause"), gate)
    assert [v.granted for v in result.lock_verdicts] == [True]


def test_own_lock_is_reentrant():
    gate = _inputs(
        locks=(_lock(experiment_id="exp-mine", owner_run_id="run-mine"),),
        lock_resources=("db-primary",),
        experiment_id="exp-mine",
        run_id="run-mine",
    )
    result = evaluate_gate(_plan("proc.pause"), gate)
    assert result.allowed
    assert result.lock_verdicts[0].granted


def test_budget_exhaustion_refuses_and_names_the_level():
    gate = _inputs(budget=_budget_tree(1.0, "proc.pause"), budget_path=BUDGET_PATH)
    ctx = _ctx(gate)
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(_plan("proc.pause"), _graph(), ctx)
    decision = excinfo.value.decision
    assert decision is not None
    assert decision.rule_id == RULE_BUDGET_EXHAUSTED
    assert "fault budget 'proc.pause'" in decision.reason
    assert decision.inputs["scope"] == "fault"
    assert decision.inputs["key"] == "proc.pause"
    assert decision.inputs["after_s"] == pytest.approx(STEP_S)
    assert decision.inputs["headroom_s"] == pytest.approx(1.0 - STEP_S)


def test_budget_probe_does_not_spend_the_budget():
    tree = _budget_tree(1e6, "proc.pause")
    gate = _inputs(budget=tree, budget_path=BUDGET_PATH)
    before = tree.model_dump_json()
    result = evaluate_gate(_plan("proc.pause"), gate)
    assert result.allowed
    # The charges a commit *would* post are returned, widest level first; the
    # tree the caller holds is untouched.
    assert [(c.scope, c.key) for c in result.pending_charges] == [
        (BudgetScope.TEAM, "sre"),
        (BudgetScope.ENVIRONMENT, "production"),
        (BudgetScope.SERVICE, "web"),
        (BudgetScope.EXPERIMENT, "exp-1"),
        (BudgetScope.FAULT, "proc.pause"),
    ]
    assert tree.model_dump_json() == before


def test_budget_charges_accumulate_across_steps():
    gate = _inputs(budget=_budget_tree(1e6, "proc.pause"), budget_path=BUDGET_PATH)
    result = evaluate_gate(_plan("proc.pause", "proc.pause", "proc.pause", duration=10.0), gate)
    leaf = [c for c in result.pending_charges if c.scope is BudgetScope.FAULT]
    assert [c.after_s for c in leaf] == [10.0, 20.0, 30.0]
    team = [c for c in result.pending_charges if c.scope is BudgetScope.TEAM]
    assert [c.after_s for c in team] == [10.0, 20.0, 30.0]


def test_unmappable_budget_path_refuses_rather_than_skipping_the_charge():
    """Phase 4: the *gate* refuses an unmappable path; the primitive still raises.

    Phase 2 asserted that ``evaluate_gate`` raised here. That was a defect
    surfacing correctly through the wrong layer: skipping the charge would lose
    the damage, and raising told whoever ran the plan nothing they could act on.
    The gate now names the defect and the fix. The raising contract is not
    withdrawn from ``probe_budget`` — it is what the gate's own conversion is
    built on, and a caller that reaches past the gate still gets the loud failure.
    """
    gate = _inputs(budget=_budget_tree(1e6, "proc.pause"), budget_path=("typo",))
    result = evaluate_gate(_plan("proc.pause"), gate)
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_POLICY_CONFIG
    assert result.refusal.inputs["config_defect"] == ConfigDefect.BUDGET_PATH_UNMAPPABLE.value
    assert result.refusal.inputs["budget_path"] == ["typo"]
    assert "no level of" in result.refusal.reason
    assert result.pending_charges == ()
    assert result.budget is None
    # The primitive keeps raising: the gate converts, it does not swallow.
    with pytest.raises(InvariantViolationError, match="no level of"):
        probe_budget(_plan("proc.pause"), gate)


def test_compatibility_conflict_refuses_per_pair():
    gate = _inputs(
        compatibility=(_conflict("proc.pause", "net.latency", "pause hides the latency"),)
    )
    ctx = _ctx(gate)
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(_plan("proc.pause", "net.latency"), _graph(), ctx)
    decision = excinfo.value.decision
    assert decision is not None
    assert decision.rule_id == RULE_COMPAT_CONFLICT
    assert "net.latency" in decision.reason
    assert "proc.pause" in decision.reason
    assert decision.inputs["verdict"] == "conflicting"
    assert decision.inputs["reason"] == "pause hides the latency"


def test_compatibility_is_checked_on_a_three_fault_plan():
    """The 1.0.0 inertness case: pairs are {earlier, new}, never one big set."""
    gate = _inputs(compatibility=(_conflict("net.latency", "proc.pause"),))
    result = evaluate_gate(_plan("proc.pause", "proc.pause", "net.latency"), gate)
    # One pair per *distinct* earlier fault, exactly as
    # ``safety._first_forbidden_pair`` enumerates them, in (earlier, new)
    # order. The self-pair is never asked about, and declaring the edge in the
    # reverse order finds it anyway.
    assert [(o.left_fault, o.right_fault) for o in result.compatibility] == [
        ("proc.pause", "net.latency")
    ]
    assert result.denied


def test_every_earlier_step_is_paired_with_the_new_one():
    gate = _inputs(compatibility=(_conflict("db.slow_query", "proc.pause"),))
    plan = _plan("proc.pause", "net.latency", "db.slow_query")
    result = evaluate_gate(plan, gate)
    # 0 + 1 + 2 pairs, one per *distinct* earlier fault — the same enumeration
    # ``safety._first_forbidden_pair`` uses, which is what makes the check
    # complete on a three-step plan instead of silently inert past two.
    assert [(o.left_fault, o.right_fault) for o in result.compatibility] == [
        ("proc.pause", "net.latency"),
        ("net.latency", "db.slow_query"),
        ("proc.pause", "db.slow_query"),
    ]
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_COMPAT_CONFLICT


def test_undeclared_pair_is_permitted_because_safety_remains_authoritative():
    result = evaluate_gate(_plan("proc.pause", "net.latency"), _inputs())
    assert result.allowed
    assert [o.declared for o in result.compatibility] == [False]
    assert [o.safe for o in result.compatibility] == [True]


def test_conditional_pair_passes_only_when_its_condition_holds():
    edges = (
        CompatibilityEdge(
            left_fault="proc.pause",
            right_fault="net.latency",
            verdict=CompatibilityVerdict.CONDITIONALLY_SAFE,
            conditions=(
                CompatibilityCondition(dimension=PolicyDimension.ENVIRONMENT, values=("staging",)),
            ),
        ),
    )
    staging = _inputs(compatibility=edges)
    assert evaluate_gate(_plan("proc.pause", "net.latency"), staging, environment="staging").allowed
    production = _inputs(compatibility=edges)
    assert evaluate_gate(
        _plan("proc.pause", "net.latency"), production, environment="production"
    ).denied


# -- simulation purity --------------------------------------------------------------


def test_simulation_mutates_nothing():
    tree = _budget_tree(1.0, "proc.pause")
    gate = _inputs(
        budget=tree,
        budget_path=BUDGET_PATH,
        locks=(_lock(),),
        lock_resources=("db-primary",),
        experiment_id="exp-mine",
    )
    plan = _plan("proc.pause", "proc.pause")
    plan_before = plan.model_dump_json()
    locks_before = tuple(lock.model_dump_json() for lock in gate.locks)
    tree_before = tree.model_dump_json()
    sink = MutationSink()

    result = simulate_gate(plan, gate, environment="staging", sink=sink)

    # The mutation backend received zero calls...
    assert len(sink) == 0
    assert sink.calls == ()
    # ...the frozen plan is byte-identical...
    assert plan.model_dump_json() == plan_before
    # ...and so are the budget and the lock set the gate read.
    assert tree.model_dump_json() == tree_before
    assert tuple(lock.model_dump_json() for lock in gate.locks) == locks_before
    # A real decision was still reached: purity is not an early return.
    assert result.simulated
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_LOCK_CONTENDED
    assert result.pending_charges


def test_simulation_and_admission_agree_bit_for_bit():
    gate = _inputs(_bundle(_prod_deny()))
    plan = _plan("proc.pause")
    simulated = simulate_gate(plan, gate, environment="production")
    admitted = evaluate_gate(plan, gate, environment="production")
    assert simulated.decision_digest() == admitted.decision_digest()
    assert simulated.denied and admitted.denied
    assert simulated.refusal is not None and admitted.refusal is not None
    assert simulated.refusal.reason == admitted.refusal.reason
    assert simulated.facts.facts_digest() == admitted.facts.facts_digest()


def test_simulate_plan_policy_leaves_the_caller_context_untouched():
    gate = _inputs(_bundle(_rule("team.sre", PolicyDimension.TEAM, PolicyOperator.IN, ("sre",))))
    ctx = _ctx(gate, environment="production")
    result = simulate_plan_policy(_plan("proc.pause"), ctx)
    assert result is not None
    assert result.simulated
    assert result.allowed
    # Nothing was recorded: a preview is not an admission.
    assert ctx.decisions == []
    assert ctx.warnings == []


def test_simulation_does_not_spend_a_budget_a_later_run_still_needs():
    gate = _inputs(budget=_budget_tree(8.0, "proc.pause"), budget_path=BUDGET_PATH)
    plan = _plan("proc.pause")
    assert simulate_gate(plan, gate).allowed
    # Two simulations must not accumulate into a refusal the gate never made.
    assert simulate_gate(plan, gate).allowed
    assert evaluate_gate(plan, gate).allowed


# -- replay determinism -------------------------------------------------------------


def test_replay_reproduces_the_decision_digest():
    gate = _inputs(
        _bundle(
            _prod_deny(),
            _rule(
                "risky", PolicyDimension.RISK, PolicyOperator.IN, ("high", "critical")
            ),
        ),
        locks=(_lock(),),
        lock_resources=("db-primary",),
        experiment_id="exp-mine",
        compatibility=(_conflict("proc.pause", "net.latency"),),
    )
    plan = _plan("proc.pause", "net.latency")
    first = evaluate_gate(plan, gate, environment="production")
    # A second pass, explicitly re-timed to the same instant.
    replay = evaluate_gate(plan, gate.with_now(T0), environment="production")
    assert replay.decision_digest() == first.decision_digest()
    assert replay.facts.facts_digest() == first.facts.facts_digest()
    assert replay.decision.policy_digest == first.decision.policy_digest
    assert replay.decision.rule_digest == first.decision.rule_digest
    assert replay.refusal is not None and first.refusal is not None
    assert replay.refusal.reason == first.refusal.reason
    assert replay.refusal.inputs == first.refusal.inputs


def test_different_inputs_produce_different_digests():
    strict = _inputs(_bundle(_prod_deny()))
    loose = _inputs(_bundle(default=PolicyEffect.ALLOW))
    plan = _plan("proc.pause")
    assert (
        evaluate_gate(plan, strict, environment="production").decision_digest()
        != evaluate_gate(plan, loose, environment="production").decision_digest()
    )


# -- negative controls --------------------------------------------------------------


def test_expired_bundle_version_cannot_authorize():
    """Control 1: no combination of allow rules rescues an expired version."""
    bundle = _bundle(
        _rule(
            "prod.allowed",
            PolicyDimension.ENVIRONMENT,
            PolicyOperator.IN,
            ("production",),
            effect=PolicyEffect.ALLOW,
        ),
        expires_at=T0 - timedelta(hours=1),
    )
    gate = _inputs(bundle, now=T0)
    ctx = _ctx(gate, environment="production")
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(_plan("proc.pause"), _graph(), ctx)
    decision = excinfo.value.decision
    assert decision is not None
    assert decision.rule_id == RULE_BUNDLE_EXPIRED
    assert "expired" in decision.reason
    assert evaluate_gate(_plan("proc.pause"), gate, environment="production").denied


def test_bundle_expires_exactly_at_its_window():
    bundle = _bundle(expires_at=T0)
    assert _inputs(bundle, now=BEFORE).bundle.authorizes(BEFORE)
    # At and after the boundary the version cannot authorize.
    assert not _inputs(bundle, now=T0).bundle.authorizes(T0)
    assert evaluate_gate(_plan("proc.pause"), _inputs(bundle, now=T0)).denied


def test_no_allow_outranks_a_deny():
    """Control 2: a lower-precedence ALLOW cannot rescue a DENY…"""
    allow = _rule(
        "prod.allow",
        PolicyDimension.ENVIRONMENT,
        PolicyOperator.IN,
        ("production",),
        effect=PolicyEffect.ALLOW,
        precedence=-100,
    )
    deny = _prod_deny()
    plan = _plan("proc.pause")
    assert evaluate_gate(plan, _inputs(_bundle(allow, deny)), environment="production").denied
    # …and neither does a *higher*-precedence one. Precedence orders which rule
    # is reported first; it never decides whether a refusal stands.
    high = allow.model_copy(update={"rule_id": "prod.allow.hi", "precedence": 100})
    assert evaluate_gate(plan, _inputs(_bundle(high, deny)), environment="production").denied


def test_native_default_deny_refuses_a_facts_set_no_rule_permits():
    """A facts set no rule speaks to is refused, not waved through."""
    bundle = _bundle(_prod_deny(), default=PolicyEffect.DENY)
    result = evaluate_gate(_plan("proc.pause"), _inputs(bundle), environment="staging")
    assert result.denied
    assert "policy.default_deny" in (result.refusal.reason if result.refusal else "")
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_BUNDLE_DENY
    # One notch tighter: the same bundle's ALLOW effect lets the same plan in.
    permissive = _bundle(_prod_deny(), default=PolicyEffect.ALLOW)
    assert evaluate_gate(
        _plan("proc.pause"), _inputs(permissive), environment="staging"
    ).allowed


def test_naive_clock_is_refused_at_construction():
    with pytest.raises(InvariantViolationError, match="timezone-aware"):
        PolicyGateInputs(bundle=_bundle(), now=datetime(2026, 3, 1, 12, 0))  # noqa: DTZ001


def test_lock_check_without_an_experiment_identity_is_refused():
    with pytest.raises(InvariantViolationError, match="experiment_id"):
        PolicyGateInputs(bundle=_bundle(), now=T0, lock_resources=("db-primary",))


# -- facts -------------------------------------------------------------------------


def test_facts_are_derived_from_the_plan_and_never_from_the_caller():
    gate = _inputs(observed={PolicyDimension.TARGET: ("spoofed",)})
    facts = derive_facts(_plan("proc.pause"), gate, environment="staging")
    assert facts.observed(PolicyDimension.TARGET) == frozenset({"n-web"})
    assert facts.observed(PolicyDimension.ENVIRONMENT) == frozenset({"staging"})
    assert facts.observed(PolicyDimension.FAULT_FAMILY) == frozenset({"process"})
    assert facts.observed(PolicyDimension.RISK) == frozenset({"low"})
    assert facts.observed(PolicyDimension.CONCURRENCY) == frozenset({"1"})


def test_derived_dimensions_left_empty_stay_unobserved():
    """Unobserved, not observed-empty: that is what stops a NOT_IN rule firing."""
    facts = derive_facts(_plan("proc.pause"), _inputs(), environment=None)
    assert facts.observed(PolicyDimension.ENVIRONMENT) is None
    assert facts.observed(PolicyDimension.DAMAGE_BUDGET) is None
    assert facts.observed(PolicyDimension.FAULT_FAMILY) is not None


def test_caller_fills_only_the_dimensions_the_gate_cannot_derive():
    gate = _inputs(
        observed={
            PolicyDimension.TEAM: ("sre",),
            PolicyDimension.SCHEDULE: ("off-hours",),
        }
    )
    facts = derive_facts(_plan("proc.pause"), gate)
    assert facts.observed(PolicyDimension.TEAM) == frozenset({"sre"})
    assert facts.observed(PolicyDimension.SCHEDULE) == frozenset({"off-hours"})


def test_damage_budget_fact_is_observed_only_when_a_budget_exists():
    without = derive_facts(_plan("proc.pause"), _inputs())
    with_budget = derive_facts(
        _plan("proc.pause"),
        _inputs(budget=_budget_tree(1e6, "proc.pause"), budget_path=BUDGET_PATH),
    )
    assert without.observed(PolicyDimension.DAMAGE_BUDGET) is None
    # 5s at proc.pause's weight of 1.0.
    assert with_budget.observed(PolicyDimension.DAMAGE_BUDGET) == frozenset({"5.0"})


# -- the risk ladder has exactly one implementation ---------------------------------


def test_risk_resolution_is_one_implementation_shared_with_admission():
    """``policy_gate._risk_of`` and ``controller.safety._risk_of`` are the same object.

    Admission (``check_fault_admission``) and the policy facts both need a fault's
    catalog risk, and they must never price a fault differently: a RISK fact
    derived at a higher rung than admission read would refuse a plan the gate
    admits. The two modules used to carry byte-identical private copies, and
    nothing tested that they agreed, so a one-sided edit would have split the
    ladder silently. ``safety`` is the upper module and already imports from
    ``policy_gate``, so ``policy_gate`` owns the implementation and ``safety``
    re-exports it. Identity is the assertion, not equality: equality would still
    pass for two copies that happen to agree today.
    """
    from mayhem.controller import safety

    assert safety._risk_of is _risk_of


def test_shared_risk_resolution_floors_an_unknown_fault_at_low():
    """The shared helper keeps the ``LOW`` floor, and the fact derivation inherits it.

    ``domain.quota`` documents the opposite choice for damage pricing; admission
    deliberately floors at the bottom of the ladder because over-pricing refuses
    valid plans. Both behaviours are only safe while there is one helper, so the
    floor is pinned here on both the helper and the observable RISK fact.
    """
    assert _risk_of("proc.no_such_fault") is RiskLevel.LOW

    facts = derive_facts(_plan("proc.no_such_fault"), _inputs())
    assert facts.observed(PolicyDimension.RISK) == frozenset({"low"})


def test_shared_risk_resolution_prices_a_known_critical_fault_at_critical():
    """The floor is a floor, not a constant: a real critical fault still reads critical.

    Without this, an implementation that returned ``LOW`` unconditionally would
    satisfy the two tests above and silently drop the critical opt-in that
    ``check_fault_admission`` keys on.
    """
    assert _risk_of("k8s.node_drain") is RiskLevel.CRITICAL


# -- Phase 4: broken configurations refuse, they do not raise ----------------------


def _drifted_pin_bundle() -> PolicyBundle:
    """A bundle whose content moved after it was pinned.

    ``model_copy`` does not re-run validators, which is the only way to produce
    one: constructing a bundle whose ``content_digest`` disagrees with its content
    raises at construction, by design. Drift is what happens to a bundle *in
    flight*, so it has to be reachable from a well-formed object.
    """
    return _bundle(_prod_deny()).pin().model_copy(update={"version": 2})


def test_drifted_pin_refuses_instead_of_raising():
    gate = _inputs(_drifted_pin_bundle())
    result = evaluate_gate(_plan("proc.pause"), gate)
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_POLICY_CONFIG
    assert result.config_defect is not None
    assert result.config_defect.defect is ConfigDefect.PIN_DRIFTED
    assert result.config_defect.reason_code == "policy.bundle_digest_mismatch"
    assert "re-pin" in result.refusal.remediation
    # Nothing was evaluated, so nothing claims to have been digested.
    assert result.decision.policy_digest == ""
    assert result.decision.rule_digest == ""
    assert result.decision.facts_digest == ""
    # …but the facts the plan carries are still on the record, for whoever fixes it.
    assert result.facts.observed(PolicyDimension.TARGET) == frozenset({"n-web"})


def test_a_broken_bundle_never_escapes_the_admission_gate():
    """A refused admission, not a traceback: ``validate_plan`` speaks ``SafetyRefusedError``."""
    for label, gate in (
        ("pin", _inputs(_drifted_pin_bundle())),
        ("parent", _inputs(_bundle(parents=("absent",)))),
        ("cycle", _inputs(_bundle(parents=("loop-b",)))),
    ):
        ctx = _ctx(gate, environment="production")
        with pytest.raises(SafetyRefusedError, match=r"policy\.config_invalid"):
            validate_plan(_plan("proc.pause"), _graph(), ctx)
        denial = [d for d in ctx.decisions if d.rule_id == RULE_POLICY_CONFIG]
        assert len(denial) == 1, label
        assert denial[0].outcome == "deny"
        assert denial[0].remediation


def test_detect_config_defect_is_none_for_a_readable_bundle():
    assert detect_config_defect(_inputs()) is None
    parent = _bundle(_prod_deny(), bundle_id="parent")
    index = {"parent": parent}
    assert detect_config_defect(_inputs(_bundle(), index=index)) is None


# -- Phase 4: the gate asks one budget question of both systems ----------------------


def test_gate_refuses_on_the_quota_alone_when_no_hierarchy_is_configured():
    """One system configured and refusing is enough: the conjunction has no escape."""
    gate = _inputs(damage_quota=DamageQuota(budget_s=1.0, per_fault_ceiling_s=1e6))
    result = evaluate_gate(_plan("proc.pause"), gate)
    assert result.denied
    assert result.refusal is not None
    # The quota's own rule id, so a log line reads the same whichever half spoke.
    assert result.refusal.rule_id == "damage_quota.budget"
    assert result.budget is not None
    assert result.budget.authority is BudgetAuthority.QUOTA
    assert not result.budget.within_budget


def test_gate_reconciles_both_systems_and_reports_the_hierarchy_first():
    gate = _inputs(
        budget=_budget_tree(1.0, "proc.pause"),
        budget_path=BUDGET_PATH,
        damage_quota=DamageQuota(budget_s=1.0, per_fault_ceiling_s=1e6),
    )
    result = evaluate_gate(_plan("proc.pause"), gate)
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_BUDGET_EXHAUSTED
    assert result.budget is not None
    assert result.budget.authority is BudgetAuthority.BOTH_REFUSE
    # The other system's verdict is in the record, not discarded by the reporting
    # preference.
    assert result.refusal.inputs["also_refused_by"] == "damage_quota.budget"
    assert result.refusal.inputs["budget_rule_ids"] == [
        RULE_BUDGET_EXHAUSTED,
        "damage_quota.budget",
    ]


def test_reconciliation_is_a_pure_function_of_two_views():
    """The matrix, at the level the decision is actually made."""
    permitting = HierarchyBudgetView(configured=True)
    breaching = HierarchyBudgetView(
        configured=True,
        breached=(
            BudgetCharge(
                scope=BudgetScope.TEAM,
                key="sre",
                amount_s=5.0,
                before_s=0.0,
                after_s=5.0,
                limit_s=1.0,
            ),
        ),
    )
    assert reconcile_budgets(permitting, QuotaBudgetView(configured=True)).authority is (
        BudgetAuthority.BOTH_PERMIT
    )
    assert reconcile_budgets(permitting, QuotaBudgetView(configured=False)).authority is (
        BudgetAuthority.HIERARCHY_PERMITS
    )
    assert reconcile_budgets(permitting, QuotaBudgetView(configured=False)).within_budget
    assert reconcile_budgets(
        HierarchyBudgetView(configured=False), QuotaBudgetView(configured=False)
    ).authority is BudgetAuthority.NONE
    assert reconcile_budgets(breaching, QuotaBudgetView(configured=True)).authority is (
        BudgetAuthority.HIERARCHY
    )


def test_quota_probe_is_absent_unless_a_quota_is_configured():
    """Default-absent is what keeps the no-bundle golden byte-identical."""
    assert probe_quota(_plan("proc.pause"), _inputs()) == QuotaBudgetView(configured=False)


def test_gate_damage_budget_fact_is_independent_of_the_quota_system():
    """Two budget systems, one dimension: ``damage_budget`` still reads the plan total."""
    facts = derive_facts(
        _plan("proc.pause"),
        _inputs(damage_quota=DamageQuota(budget_s=1.0, per_fault_ceiling_s=1e6)),
    )
    assert facts.observed(PolicyDimension.DAMAGE_BUDGET) is None
