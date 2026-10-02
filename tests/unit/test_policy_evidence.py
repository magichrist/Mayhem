"""Plan 07 Phase 4 — budget reconciliation, typed refusals, and sealed evidence.

Phase 2's suite (``test_policy_gate.py``) proved the gate decides. This suite
proves the three things Phase 4 added on top of that decision, and proves them
the way the plan's acceptance names them:

* **one budget answer.** The hierarchical tree and the per-target
  ``DamageQuota`` are reconciled by one pure function, and a plan refused by
  either is refused. The matrix is asserted directly rather than through the gate,
  because the matrix *is* the decision.
* **broken configurations refuse.** A drifted pin, a missing parent, an
  inheritance cycle, and an unmappable budget path each produce a typed refusal
  naming its own defect and its own remediation — never a raised exception out of
  the gate.
* **the decision is sealed and the version change is recorded.** The decision's
  rule/policy/facts digests and the bundle version land in the run's attested
  chain via plan 12's sealer; a bundle change lands in the audit stream.

The negative controls are load-bearing and are asserted against real objects
rather than against a comment: a plan refused by either budget system is refused;
a drifted-pin bundle refuses instead of raising; an expired bundle cannot
authorize; a decision replayed from recorded inputs reproduces bit-for-bit; and a
decision whose digest disagrees with its bundle is refused rather than sealed.

Every clock is explicit. Nothing here reads one.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.policy_evidence import (
    KIND_POLICY_VERSION_CHANGED,
    RULE_BUNDLE_CANNOT_AUTHORIZE,
    RULE_CONFIG_DEFECT,
    RULE_DECISION_BINDING,
    RULE_DECISION_DENIED,
    PolicyAuthorizationRefusedError,
    PolicyEvidenceError,
    build_authorization,
    policy_evidence,
    record_policy_bundle_change,
    seal_policy_decision,
    verify_decision_binding,
)
from mayhem.controller.policy_gate import (
    RULE_BUDGET_EXHAUSTED,
    RULE_POLICY_CONFIG,
    BudgetAuthority,
    ConfigDefect,
    HierarchyBudgetView,
    PolicyGateInputs,
    QuotaBudgetView,
    evaluate_gate,
    reconcile_budgets,
)
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, validate_plan
from mayhem.domain.approval import ApprovalState
from mayhem.domain.attestation import AttestedTimestamp
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.hashing import canonical_json, sha256_hex
from mayhem.domain.policy import (
    BudgetCharge,
    BudgetNode,
    BudgetScope,
    PolicyBundle,
    PolicyDimension,
    PolicyEffect,
    PolicyFacts,
    PolicyOperator,
    PolicyPredicate,
    PolicyRule,
    evaluate_bundle,
)
from mayhem.domain.quota import (
    RULE_BUDGET as QUOTA_RULE_BUDGET,
)
from mayhem.domain.quota import (
    UNRESOLVED_FAULT_WEIGHT,
    DamageLedger,
    DamageQuota,
)
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.infra.attestation_store import (
    EVENT_APPROVAL_EVALUATED,
    EVENT_POLICY_DECIDED,
    AttestationRepository,
)
from mayhem.infra.audit_stream import AuditStream
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

    from mayhem.domain.quota import QuotaCharge

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
LATER = T0 + timedelta(minutes=1)
STEP_S = 30.0
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


def _plan(*fault_ids: str, duration: float = STEP_S) -> ExecutionPlan:
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
        run_id="run-1",
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
    reason: str = "",
    remediation: str = "",
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        dimension=dimension,
        predicate=PolicyPredicate(operator=operator, values=values),
        effect=effect,
        reason=reason,
        remediation=remediation,
    )


def _env_production() -> tuple[PolicyDimension, PolicyOperator, tuple[str, ...]]:
    """The ``environment in (production,)`` test, spelled once."""
    return (PolicyDimension.ENVIRONMENT, PolicyOperator.IN, ("production",))


def _bundle(
    *rules: PolicyRule,
    default: PolicyEffect = PolicyEffect.ALLOW,
    version: int = 1,
    bundle_id: str = "evidence-test",
    parents: tuple[str, ...] = (),
    expires_at: datetime | None = None,
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


def _budget_tree(leaf_limit: float, *fault_ids: str) -> BudgetNode:
    team, environment, service, experiment = BUDGET_PATH
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


def _quota(budget_s: float = 1e6, per_fault_ceiling_s: float = 1e6) -> DamageQuota:
    return DamageQuota(budget_s=budget_s, per_fault_ceiling_s=per_fault_ceiling_s)


def _ledger_verdict(
    plan: ExecutionPlan, graph: TopologyGraph, quota: DamageQuota
) -> tuple[bool, QuotaCharge]:
    """What the *authoritative* per-step ledger says, run by hand.

    Deliberately not the gate's :func:`probe_quota`: it reproduces
    ``safety.check_blast_radius``'s charging rule (targets unioned with their
    dependents closure, fresh ledger per pass) so the two can be compared.
    """
    ledger = DamageLedger()
    charge: QuotaCharge | None = None
    for step in plan.steps:
        if step.fault is None:
            continue
        affected: set[str] = set()
        for target in step.fault.targets:
            for node_id in target.node_ids:
                affected.add(node_id)
                affected |= graph.dependents_closure(node_id)
        charge = ledger.charge(
            fault_id=step.fault.fault_id,
            duration_s=float(step.fault.duration),
            node_ids=affected,
            quota=quota,
        )
        if charge.exceeded:
            return True, charge
    assert charge is not None
    return False, charge


def _ctx(gate: PolicyGateInputs | None = None, **kwargs: Any) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(max_services_pct=100.0),
        fingerprint="f",
        policy_gate=gate,
        **kwargs,
    )


def _state(valid: bool = True, approvers: tuple[str, ...] = ("ana",)) -> ApprovalState:
    return ApprovalState(valid=valid, approvers=approvers if valid else (), required=1)


def _envelope(run_id: str = "run-1", *, plan_hash: str, mutating: bool = True) -> EvidenceEnvelope:
    fields: dict[str, object] = {
        "run_id": run_id,
        "plan_hash": plan_hash,
        "verdict": "pass",
        "step_reports": ({"step_id": "s0", "status": "completed"},),
        "created_at": T0.isoformat(),
        "redaction_metrics": {"policy_version": "redaction-v9", "redacted_path_count": 0},
    }
    if mutating:
        fields["action_outcomes"] = ("applied",)
    return EvidenceEnvelope.model_validate(fields)


def _reading(seconds: int = 0) -> AttestedTimestamp:
    return AttestedTimestamp(
        wall_clock=T0 + timedelta(seconds=seconds),
        monotonic_ns=1_000_000 * (seconds + 1),
        uncertainty_ms=0.0,
        source="test",
    )


def open_store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


# =============================================================================
# Requirement 1 — the budget reconciliation matrix
# =============================================================================


def _breach() -> HierarchyBudgetView:
    return HierarchyBudgetView(
        configured=True,
        breached=(
            BudgetCharge(
                scope=BudgetScope.TEAM,
                key="sre",
                amount_s=STEP_S,
                before_s=0.0,
                after_s=STEP_S,
                limit_s=1.0,
            ),
        ),
    )


def _quota_refusal() -> QuotaCharge:
    """The quota's own refusal object, built through the real ledger."""
    ledger = DamageLedger()
    return ledger.charge(
        fault_id="proc.pause",
        duration_s=STEP_S,
        node_ids=frozenset({"n-web"}),
        quota=_quota(budget_s=1.0),
    )


def _quota_view_refused() -> QuotaBudgetView:
    charge = _quota_refusal()
    assert charge.exceeded
    return QuotaBudgetView(configured=True, charges=(charge,), refusal=charge)


#: Every combination of the two systems, as a table rather than a list of cases:
#: ``(hierarchy, quota, expected within_budget, expected authority)``. The
#: conjunction is the whole rule, so it is asserted over the whole product
#: instead of case by case — a plan is within budget in exactly the four
#: combinations where nothing refused, and in no other.
MATRIX = [
    (
        HierarchyBudgetView(configured=False),
        QuotaBudgetView(configured=False),
        True,
        BudgetAuthority.NONE,
    ),
    (
        HierarchyBudgetView(configured=True),
        QuotaBudgetView(configured=False),
        True,
        BudgetAuthority.HIERARCHY_PERMITS,
    ),
    (
        HierarchyBudgetView(configured=False),
        QuotaBudgetView(configured=True),
        True,
        BudgetAuthority.QUOTA_PERMITS,
    ),
    (
        HierarchyBudgetView(configured=True),
        QuotaBudgetView(configured=True),
        True,
        BudgetAuthority.BOTH_PERMIT,
    ),
    (_breach(), QuotaBudgetView(configured=True), False, BudgetAuthority.HIERARCHY),
    (HierarchyBudgetView(configured=True), _quota_view_refused(), False, BudgetAuthority.QUOTA),
    (_breach(), _quota_view_refused(), False, BudgetAuthority.BOTH_REFUSE),
]


@pytest.mark.parametrize(("hierarchy", "quota", "within", "authority"), MATRIX)
def test_reconciliation_matrix(
    hierarchy: HierarchyBudgetView,
    quota: QuotaBudgetView,
    within: bool,
    authority: BudgetAuthority,
) -> None:
    """One row of :data:`MATRIX`: one assertion of the conjunction."""
    result = reconcile_budgets(hierarchy, quota)
    assert result.within_budget is within
    assert result.authority is authority
    assert (result.refusal is None) is within


def test_reconciliation_is_pure_and_repeatable() -> None:
    """Same views in, same verdict out — no clock, no store, no ambient state."""
    first = reconcile_budgets(_breach(), _quota_view_refused())
    second = reconcile_budgets(_breach(), _quota_view_refused())
    assert first == second
    assert first.refusal is not None and second.refusal is not None
    assert first.refusal.reason == second.refusal.reason
    assert first.refusal.inputs == second.refusal.inputs


def test_neither_system_overrides_the_other_on_disagreement() -> None:
    """The disagreement case: both fired, and neither was discarded."""
    result = reconcile_budgets(_breach(), _quota_view_refused())
    assert result.authority is BudgetAuthority.BOTH_REFUSE
    assert result.refusal is not None
    # The hierarchy reports (documented preference), and the quota's verdict and
    # numbers survive in the record rather than being dropped by that preference.
    assert result.refusal.rule_id == RULE_BUDGET_EXHAUSTED
    assert result.refusal.inputs["also_refused_by"] == QUOTA_RULE_BUDGET
    assert result.refusal.inputs["budget_rule_ids"] == [RULE_BUDGET_EXHAUSTED, QUOTA_RULE_BUDGET]
    # Both views are retained on the result itself, so nothing is lost.
    assert result.hierarchy.refused and result.quota.refused


def test_a_plan_refused_by_either_budget_system_is_refused_through_the_gate() -> None:
    """The matrix, end to end, on a real plan."""
    plan = _plan("proc.pause")
    hierarchy_only = evaluate_gate(
        plan, _inputs(budget=_budget_tree(1.0, "proc.pause"), budget_path=BUDGET_PATH)
    )
    quota_only = evaluate_gate(plan, _inputs(damage_quota=_quota(budget_s=1.0)))
    both = evaluate_gate(
        plan,
        _inputs(
            budget=_budget_tree(1.0, "proc.pause"),
            budget_path=BUDGET_PATH,
            damage_quota=_quota(budget_s=1.0),
        ),
    )
    assert hierarchy_only.denied
    assert quota_only.denied
    assert both.denied
    assert hierarchy_only.budget is not None and quota_only.budget is not None
    assert both.budget is not None
    assert both.budget.authority is BudgetAuthority.BOTH_REFUSE
    # The two systems report under their own rule ids, so a log line says which
    # one spoke without the reader having to know which half of the gate it was.
    assert hierarchy_only.refusal is not None
    assert hierarchy_only.refusal.rule_id == RULE_BUDGET_EXHAUSTED
    assert quota_only.refusal is not None
    assert quota_only.refusal.rule_id == QUOTA_RULE_BUDGET


def test_a_plan_allowed_by_both_budget_systems_is_allowed() -> None:
    plan = _plan("proc.pause")
    result = evaluate_gate(
        plan,
        _inputs(
            budget=_budget_tree(1e6, "proc.pause"),
            budget_path=BUDGET_PATH,
            damage_quota=_quota(),
        ),
    )
    assert result.allowed
    assert result.budget is not None
    assert result.budget.authority is BudgetAuthority.BOTH_PERMIT
    assert result.budget.within_budget


def test_neither_budget_systems_configuration_is_still_a_permission() -> None:
    """Default-absent: the gate must not start refusing because Phase 4 arrived."""
    result = evaluate_gate(_plan("proc.pause"), _inputs())
    assert result.allowed
    assert result.budget is not None
    assert result.budget.authority is BudgetAuthority.NONE


def test_the_quota_probe_can_only_move_a_refusal_earlier_never_past_one() -> None:
    """The one-way invariant that justifies the gate re-deriving the quota verdict.

    ``probe_quota`` recomputes the per-target verdict without the dependents
    closure that ``check_blast_radius`` has. The closure can only *add* damage to
    a target, so a gate-side refusal is final (the authoritative ledger agrees or
    is stricter) while a gate-side permit may be overturned downstream. Asserting
    the direction against the real ledger is what makes the shortcut safe: an
    implementation that charged the closure wrongly, or that compared totals
    instead of the worst target, would break one row of this loop.
    """
    from mayhem.controller.policy_gate import probe_quota

    graph = _graph()
    plans = (
        _plan("proc.pause"),
        _plan("proc.pause", "net.latency"),
        _plan("proc.pause", duration=600.0),
        _plan("k8s.node_drain"),
        _plan("proc.pause", "k8s.node_drain", duration=300.0),
    )
    for budget_s, ceiling_s in ((1.0, 1e6), (60.0, 1e6), (1e6, 1.0), (1e6, 20.0), (1e6, 1e6)):
        quota = _quota(budget_s=budget_s, per_fault_ceiling_s=ceiling_s)
        for plan in plans:
            gate_refused = probe_quota(plan, _inputs(damage_quota=quota)).refused
            ledger_refused, _ = _ledger_verdict(plan, graph, quota)
            if gate_refused:
                assert ledger_refused, (budget_s, ceiling_s, plan.run_id)


def test_the_quota_probe_and_the_authoritative_ledger_agree_on_a_single_target() -> None:
    """With no closure widening them, the two are the same numbers, not similar."""
    from mayhem.controller.policy_gate import probe_quota

    quota = _quota(budget_s=1e6)
    plan = _plan("proc.pause", "net.latency")
    view = probe_quota(plan, _inputs(damage_quota=quota))
    ledger_refused, charge = _ledger_verdict(plan, _graph(), quota)
    assert not view.refused
    assert not ledger_refused
    assert view.charges[-1].worst_node_s == pytest.approx(charge.worst_node_s)


# =============================================================================
# Requirement 2 — a broken configuration refuses, with its own remediation
# =============================================================================


def _drifted() -> PolicyBundle:
    """A pinned bundle whose content moved afterwards (``model_copy`` skips validators)."""
    return _bundle().pin().model_copy(update={"version": 2})


def _cycle_pair() -> tuple[PolicyBundle, PolicyBundle]:
    child = _bundle(bundle_id="loop-a", parents=("loop-b",))
    parent = _bundle(bundle_id="loop-b", parents=("loop-a",))
    return child, parent


def _broken_cases() -> list[tuple[str, PolicyGateInputs, ConfigDefect, str]]:
    child, parent = _cycle_pair()
    return [
        (
            "drifted pin",
            _inputs(_drifted()),
            ConfigDefect.PIN_DRIFTED,
            "policy.bundle_digest_mismatch",
        ),
        (
            "missing parent",
            _inputs(_bundle(parents=("absent",))),
            ConfigDefect.PARENT_MISSING,
            "policy.bundle_parent_missing",
        ),
        (
            "inheritance cycle",
            _inputs(child, index={"loop-a": child, "loop-b": parent}),
            ConfigDefect.INHERITANCE_CYCLE,
            "policy.bundle_cycle",
        ),
        (
            "unmappable budget path",
            _inputs(budget=_budget_tree(1e6, "proc.pause"), budget_path=("typo",)),
            ConfigDefect.BUDGET_PATH_UNMAPPABLE,
            "policy.budget_path_missing",
        ),
    ]


@pytest.mark.parametrize(
    ("_label", "gate", "defect", "reason_code"),
    _broken_cases(),
    ids=[case[0] for case in _broken_cases()],
)
def test_each_broken_configuration_refuses_with_its_own_remediation(
    _label: str,
    gate: PolicyGateInputs,
    defect: ConfigDefect,
    reason_code: str,
) -> None:
    """No exception escapes the gate, and no two defects share a message."""
    result = evaluate_gate(_plan("proc.pause"), gate)  # would raise before Phase 4
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_POLICY_CONFIG
    assert result.config_defect is not None
    assert result.config_defect.defect is defect
    # The primitive's own reason code and message survive the conversion: the
    # evidence needed to find the typo is the one the primitive produced.
    assert result.config_defect.reason_code == reason_code
    assert reason_code in result.refusal.reason
    assert result.refusal.remediation == result.config_defect.remediation
    assert result.refusal.inputs["config_defect"] == defect.value


def test_every_broken_configuration_names_a_different_remediation() -> None:
    """Four defects, four fixes. A shared generic string would pass the rest."""
    remediations = {
        evaluate_gate(_plan("proc.pause"), gate).refusal.remediation  # type: ignore[union-attr]
        for _label, gate, _defect, _code in _broken_cases()
    }
    assert len(remediations) == 4
    # …and each one is actionable rather than "fix the config".
    assert all(len(text.split()) >= 8 for text in remediations)


def test_a_broken_configuration_refuses_admission_rather_than_crashing_the_run() -> None:
    for _label, gate, _defect, _code in _broken_cases():
        ctx = _ctx(gate, environment="production")
        with pytest.raises(SafetyRefusedError, match=RULE_POLICY_CONFIG):
            validate_plan(_plan("proc.pause"), _graph(), ctx)
        recorded = [d for d in ctx.decisions if d.rule_id == RULE_POLICY_CONFIG]
        assert len(recorded) == 1
        assert recorded[0].outcome == "deny"
        assert recorded[0].remediation


def test_a_broken_configuration_never_produced_a_decision_to_seal() -> None:
    """The empty digests are the point, not a placeholder.

    Nothing was read, so nothing was digested. ``build_authorization`` refuses
    these records on that basis before it ever looks at the reason — a machine
    cannot be asked to distinguish "no rule set" from "a rule set that said no".
    """
    for _label, gate, _defect, _code in _broken_cases():
        result = evaluate_gate(_plan("proc.pause"), gate)
        assert result.decision.policy_digest == ""
        assert result.decision.rule_digest == ""
        assert result.decision.facts_digest == ""
        with pytest.raises(PolicyAuthorizationRefusedError) as excinfo:
            build_authorization(result, approval_state=_state(), plan_digest="0" * 64)
        assert excinfo.value.rule_id == RULE_CONFIG_DEFECT


def test_a_readable_configuration_is_not_a_defect() -> None:
    """The conversion is not a blanket refusal: good configurations still decide."""
    parent = _bundle(
        _rule("prod.x", *_env_production()),
        bundle_id="evidence-base",
    )
    gate = _inputs(_bundle(parents=("evidence-base",)), index={"evidence-base": parent})
    result = evaluate_gate(_plan("proc.pause"), gate)
    assert result.allowed
    assert result.config_defect is None
    assert result.decision.rule_digest


# =============================================================================
# Requirement 3 — the decision is sealed
# =============================================================================


def _allowing_result(**kwargs: Any) -> Any:
    bundle = kwargs.pop("bundle", None) or _bundle(
        _rule(
            "prod.allowed",
            PolicyDimension.ENVIRONMENT,
            PolicyOperator.IN,
            ("production",),
            effect=PolicyEffect.ALLOW,
        )
    )
    return evaluate_gate(
        _plan("proc.pause"), _inputs(bundle, **kwargs), environment="production"
    )


PLAN_DIGEST = sha256_hex(canonical_json({"plan": "run-1"}))


def test_a_bound_decision_becomes_a_sealed_chain_entry(tmp_path: Path) -> None:
    """The round trip: decision and bundle version out of the gate, into the chain."""
    store = open_store(tmp_path)
    try:
        result = _allowing_result()
        assert result.allowed
        sealed = seal_policy_decision(
            store,
            result,
            _envelope(plan_hash=PLAN_DIGEST),
            approval_state=_state(),
            plan_digest=PLAN_DIGEST,
            run_status="completed",
            verdict="pass",
            recorded_at=_reading(),
        )
        kinds = [event.event_kind for event in sealed.events]
        assert EVENT_POLICY_DECIDED in kinds
        assert EVENT_APPROVAL_EVALUATED in kinds
        assert sealed.chain_verification.valid
        assert sealed.manifest_verification.valid
        assert sealed.completeness is not None and sealed.completeness.complete
        assert not sealed.signed  # Phase 4 seals nothing; integrity is not authorship

        payload = next(
            event.payload for event in sealed.events if event.event_kind == EVENT_POLICY_DECIDED
        )
        assert payload["policy_digest"] == result.decision.policy_digest
        assert payload["rule_digest"] == result.decision.rule_digest
        assert payload["facts_digest"] == result.decision.facts_digest
        assert payload["decision_digest"] == result.decision.decision_digest()
        # The bundle *version*, named in the sealed bytes rather than implied.
        assert payload["policy_bundle"] == "evidence-test v1"
        assert payload["policy_outcome"] == "allow"

        # And it survives a reload: the stored bytes reproduce the sealed ones.
        stored = AttestationRepository(store).load_chain("run-1")
        assert tuple(event.model_dump_json() for event in stored) == tuple(
            event.model_dump_json() for event in sealed.events
        )
        assert AttestationRepository(store).verify_run_chain("run-1").valid
    finally:
        store.close()


def test_the_sealed_chain_carries_the_budget_conjunction_too(tmp_path: Path) -> None:
    """The evidence must show which budget system refused, not just that one did."""
    store = open_store(tmp_path)
    try:
        result = evaluate_gate(
            _plan("proc.pause"),
            _inputs(
                bundle=_bundle(
                    _rule(
                        "prod.allowed",
                        PolicyDimension.ENVIRONMENT,
                        PolicyOperator.IN,
                        ("production",),
                        effect=PolicyEffect.ALLOW,
                    )
                ),
                budget=_budget_tree(1.0, "proc.pause"),
                budget_path=BUDGET_PATH,
                damage_quota=_quota(budget_s=1.0),
            ),
            environment="production",
        )
        # Both budget systems refused, so this decision cannot be sealed at all.
        assert result.denied
        assert result.budget is not None
        assert result.budget.authority is BudgetAuthority.BOTH_REFUSE
        evidence = policy_evidence(result)
        assert evidence["budget"]["budget_authority"] == BudgetAuthority.BOTH_REFUSE.value
        assert evidence["budget"]["hierarchy_scope"] == "fault"
        assert evidence["budget"]["quota_rule_id"] == QUOTA_RULE_BUDGET
        # But the refusal itself is evidence, and it is inside the sealed payload.
        assert evidence["refusal"] is not None
        assert evidence["refusal"]["inputs"]["also_refused_by"] == QUOTA_RULE_BUDGET
    finally:
        store.close()


def test_the_policy_evidence_payload_is_sealed_against_its_own_edits() -> None:
    """``sealed_digest`` is recomputable, so a doctored record is detectable."""
    result = _allowing_result()
    evidence = policy_evidence(result)
    digest = evidence.pop("sealed_digest")
    assert digest == sha256_hex(canonical_json(evidence))
    tampered = {**evidence, "allowed": False}
    assert sha256_hex(canonical_json(tampered)) != digest
    assert evidence["decision"]["outcome"] == "allow"
    assert evidence["decided_at"] == T0.isoformat()


# =============================================================================
# Requirement 3 — a version change belongs in the audit stream
# =============================================================================


def test_a_bundle_change_is_recorded_as_a_privileged_action(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    try:
        audit = AuditStream(store)
        previous = _bundle(version=1)
        current = _bundle(
            _rule("prod.forbids", PolicyDimension.ENVIRONMENT, PolicyOperator.IN, ("production",)),
            version=2,
        )
        event = record_policy_bundle_change(
            audit,
            principal="ana",
            previous=previous,
            current=current,
            reason="production forbids this environment",
            recorded_at=_reading(),
        )
        assert event.event_kind == KIND_POLICY_VERSION_CHANGED
        assert event.payload["principal"] == "ana"
        assert event.payload["policy_digest"] == current.compute_digest()
        detail = event.payload["detail"]
        assert detail["previous_version"] == 1
        assert detail["current_version"] == 2
        assert detail["previous_digest"] == previous.compute_digest()
        assert detail["current_digest"] == current.compute_digest()
        # The stream verifies, and the entry is the tip.
        assert audit.verify().valid
        assert audit.entry_count() == 1
        head = audit.head()
        assert head is not None
        assert head.chain_root == event.chain_link
    finally:
        store.close()


def test_a_version_change_is_recorded_in_the_stream_and_not_in_a_run_chain(
    tmp_path: Path,
) -> None:
    """A bundle change spans runs; no single run's chain can attest to it."""
    store = open_store(tmp_path)
    try:
        record_policy_bundle_change(
            AuditStream(store),
            principal="ana",
            previous=_bundle(version=1),
            current=_bundle(version=2),
            recorded_at=_reading(),
        )
        assert AttestationRepository(store).load_chain_row("run-1") is None
        entries = AuditStream(store).load()
        assert [entry.event_kind for entry in entries] == [KIND_POLICY_VERSION_CHANGED]
    finally:
        store.close()


def test_a_version_change_that_changed_nothing_is_refused(tmp_path: Path) -> None:
    """Recording an event that says a change happened is worse than no event."""
    store = open_store(tmp_path)
    try:
        audit = AuditStream(store)
        bundle = _bundle(version=3)
        with pytest.raises(PolicyEvidenceError, match="nothing changed"):
            record_policy_bundle_change(
                audit, principal="ana", previous=bundle, current=bundle, recorded_at=_reading()
            )
        assert audit.entry_count() == 0
    finally:
        store.close()


def test_a_republished_version_is_still_a_change(tmp_path: Path) -> None:
    """Same content, higher version: the version is what a decision pins."""
    store = open_store(tmp_path)
    try:
        audit = AuditStream(store)
        record_policy_bundle_change(
            audit,
            principal="ana",
            previous=_bundle(version=1),
            current=_bundle(version=2),
            recorded_at=_reading(),
        )
        assert audit.entry_count() == 1
        assert audit.verify().valid
    finally:
        store.close()


# =============================================================================
# Negative controls
# =============================================================================


def test_control_a_drifted_pin_bundle_refuses_instead_of_raising() -> None:
    """The headline of Requirement 2, as a control.

    Phase 2's ``evaluate_gate`` raised ``InvariantViolationError`` here. Phase 4
    refuses. Both refuse the run; only one tells the operator what to do.
    """
    gate = _inputs(_drifted())
    result = evaluate_gate(_plan("proc.pause"), gate)
    assert result.denied
    assert result.config_defect is not None
    assert result.config_defect.defect is ConfigDefect.PIN_DRIFTED
    assert "re-pin" in result.refusal.remediation  # type: ignore[union-attr]
    with pytest.raises(SafetyRefusedError, match=RULE_POLICY_CONFIG):
        validate_plan(_plan("proc.pause"), _graph(), _ctx(gate, environment="production"))


def test_control_an_expired_bundle_cannot_authorize_a_sealed_decision() -> None:
    """Refused at the gate, refused again at the seal, and both named."""
    expired = _bundle(
        _rule(
            "prod.allowed",
            PolicyDimension.ENVIRONMENT,
            PolicyOperator.IN,
            ("production",),
            effect=PolicyEffect.ALLOW,
        ),
        expires_at=T0 - timedelta(hours=1),
    )
    gate = _inputs(expired, now=T0)
    assert evaluate_gate(_plan("proc.pause"), gate, environment="production").denied

    # A decision taken *while* the version was valid, sealed after it expired, is
    # refused: a run cannot cite a policy version that has since stopped speaking.
    valid = evaluate_gate(
        _plan("proc.pause"),
        _inputs(expired, now=T0 - timedelta(hours=2)),
        environment="production",
    )
    assert valid.allowed
    assert valid.bundle is not None
    sealing_instant = T0 + timedelta(minutes=1)
    refusal = verify_decision_binding(
        valid.decision, valid.bundle, now=sealing_instant
    )
    assert refusal is not None
    assert refusal.rule_id == RULE_BUNDLE_CANNOT_AUTHORIZE
    # The sealer's own clock is the result's clock, so a caller cannot hand it an
    # earlier ``now`` and slip a stale decision past the check.
    stale = dataclasses.replace(valid, now=sealing_instant)
    with pytest.raises(PolicyAuthorizationRefusedError) as excinfo:
        build_authorization(stale, approval_state=_state(), plan_digest=PLAN_DIGEST)
    assert excinfo.value.rule_id == RULE_BUNDLE_CANNOT_AUTHORIZE
    assert "expired" in excinfo.value.refusal.reason


def test_control_a_decision_whose_digest_disagrees_with_its_bundle_is_refused() -> None:
    """The digest check is the one that cannot be talked around.

    The two bundles here agree on id *and* version — so the identity check passes
    and the content check is what refuses. A version bump would have been caught
    by the identity check and would have proven nothing about digests.
    """
    decided_bundle = _bundle(version=1)
    same_version_other_content = _bundle(
        _rule("prod.forbids", *_env_production()),
        version=1,
    )
    assert decided_bundle.bundle_id == same_version_other_content.bundle_id
    assert decided_bundle.version == same_version_other_content.version
    assert decided_bundle.compute_digest() != same_version_other_content.compute_digest()

    decided = evaluate_gate(_plan("proc.pause"), _inputs(decided_bundle), environment="production")
    assert decided.allowed
    assert decided.decision.policy_digest == decided_bundle.compute_digest()

    refusal = verify_decision_binding(decided.decision, same_version_other_content)
    assert refusal is not None
    assert refusal.rule_id == RULE_DECISION_BINDING
    assert decided_bundle.compute_digest() in refusal.reason
    assert refusal.inputs["bundle_policy_digest"] == same_version_other_content.compute_digest()

    # …and the identity check runs first, so a different version never reaches
    # the digest comparison at all.
    other_version = _bundle(version=2)
    identity = verify_decision_binding(decided.decision, other_version)
    assert identity is not None
    assert identity.inputs["decision_bundle"] == "evidence-test v1"
    assert identity.inputs["supplied_bundle"].startswith("evidence-test v2")
    other_id = _bundle(bundle_id="other-test", version=1)
    assert verify_decision_binding(decided.decision, other_id) is not None


def test_control_a_denied_decision_cannot_be_sealed_as_an_authorization(tmp_path: Path) -> None:
    """A refusal is evidence; it is not an authorization."""
    store = open_store(tmp_path)
    try:
        denied = evaluate_gate(
            _plan("proc.pause"),
            _inputs(
                _bundle(_rule("prod.forbids", *_env_production()))
            ),
            environment="production",
        )
        assert denied.denied
        with pytest.raises(PolicyAuthorizationRefusedError) as excinfo:
            build_authorization(denied, approval_state=_state(), plan_digest=PLAN_DIGEST)
        assert excinfo.value.rule_id == RULE_DECISION_DENIED
        assert "prod.forbids" in excinfo.value.refusal.reason
        # Nothing was written by the refusal.
        assert AttestationRepository(store).load_chain_row("run-1") is None
        with pytest.raises(PolicyAuthorizationRefusedError):
            seal_policy_decision(
                store,
                denied,
                _envelope(plan_hash=PLAN_DIGEST),
                approval_state=_state(),
                plan_digest=PLAN_DIGEST,
                run_status="completed",
                recorded_at=_reading(),
            )
        assert AttestationRepository(store).load_chain_row("run-1") is None
    finally:
        store.close()


def test_control_a_result_without_a_bundle_cannot_be_bound(tmp_path: Path) -> None:
    """A check that is skipped when the artifact is absent is not a check."""
    store = open_store(tmp_path)
    try:
        result = _allowing_result()
        unbound = dataclasses.replace(result, bundle=None)
        assert unbound.bundle is None
        with pytest.raises(PolicyAuthorizationRefusedError) as excinfo:
            build_authorization(unbound, approval_state=_state(), plan_digest=PLAN_DIGEST)
        assert excinfo.value.rule_id == RULE_DECISION_BINDING
    finally:
        store.close()


def test_control_a_decision_replayed_from_recorded_inputs_reproduces_bit_for_bit() -> None:
    """Phase 4's acceptance: replaying a decision reproduces it exactly.

    The evidence payload carries everything a replay needs — the facts, the
    clock, the bundle digest — and re-running the gate from those recorded inputs
    must produce the same ``sealed_digest`` down to the last byte. This is the
    property that makes sealing a decision worth anything.
    """
    bundle = _bundle(
        _rule(
            "prod.forbids",
            PolicyDimension.ENVIRONMENT,
            PolicyOperator.IN,
            ("production",),
        )
    )
    gate = _inputs(
        bundle,
        budget=_budget_tree(1e6, "proc.pause"),
        budget_path=BUDGET_PATH,
        damage_quota=_quota(),
    )
    plan = _plan("proc.pause", "net.latency")
    first = policy_evidence(evaluate_gate(plan, gate, environment="production"))

    # The bundle the record names is the bundle a replay has to use, so the
    # record is self-locating: if the id/version/digest disagree there is
    # nothing to replay against.
    assert first["bundle_digest"] == bundle.compute_digest()
    assert first["bundle"] == bundle.describe()

    # (a) The decision itself, replayed from the recorded facts and clock.
    #     ``evaluate_bundle`` is a pure function of exactly those three things,
    #     so this is the whole of "replaying a decision from evidence".
    recorded_facts = PolicyFacts(
        values={
            PolicyDimension(dimension): tuple(values)
            for dimension, values in first["facts"].items()
        }
    )
    replayed = evaluate_bundle(
        bundle, recorded_facts, now=datetime.fromisoformat(first["decided_at"])
    )
    assert replayed.model_dump(mode="json") == first["decision"]
    assert replayed.decision_digest() == first["decision_digest"]

    # (b) The whole gate verdict, replayed from the same inputs.
    second = policy_evidence(
        evaluate_gate(plan, gate.with_now(T0), environment="production")
    )
    assert second["facts"] == first["facts"]
    assert second["facts_digest"] == first["facts_digest"]
    assert second["decision"] == first["decision"]
    assert second["budget"] == first["budget"]
    assert second["refusal"]["reason"] == first["refusal"]["reason"]
    # …down to the last byte of the sealed digest. That is the property that
    # makes sealing a decision worth anything: an auditor recomputes it.
    assert second["sealed_digest"] == first["sealed_digest"]
    # The clock really was part of the record, not inferred.
    assert first["decided_at"] == T0.isoformat()


def test_control_a_replay_after_the_bundle_changes_does_not_reproduce() -> None:
    """The negative half: the seal is sensitive to the policy, not just the plan.

    Without this, the previous control would pass for an implementation whose
    ``sealed_digest`` covered only the outcome.
    """
    bundle = _bundle(
        _rule(
            "prod.allowed",
            PolicyDimension.ENVIRONMENT,
            PolicyOperator.IN,
            ("production",),
            effect=PolicyEffect.ALLOW,
        )
    )
    plan = _plan("proc.pause")
    before = policy_evidence(evaluate_gate(plan, _inputs(bundle), environment="production"))
    after_policy = _bundle(
        _rule("prod.allowed", *_env_production(), effect=PolicyEffect.ALLOW),
        version=2,
    )
    after = policy_evidence(
        evaluate_gate(plan, _inputs(after_policy), environment="production")
    )
    assert before["sealed_digest"] != after["sealed_digest"]
    assert before["decision"]["outcome"] == after["decision"]["outcome"] == "allow"


def test_control_the_gate_still_refuses_an_expired_bundle_in_production() -> None:
    """The Phase 2 control, restated so Phase 4 cannot have weakened it."""
    expired = _bundle(
        _rule(
            "prod.allowed",
            PolicyDimension.ENVIRONMENT,
            PolicyOperator.IN,
            ("production",),
            effect=PolicyEffect.ALLOW,
        ),
        expires_at=T0,
    )
    gate = _inputs(expired, now=T0)
    result = evaluate_gate(_plan("proc.pause"), gate, environment="production")
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == "policy.bundle_expired"
    # …and it is the *bundle* that refused, not a rule.
    assert result.decision.matched_rules == ()


def test_the_unknown_fault_pricing_is_shared_with_the_quota() -> None:
    """An unpriced fault is priced at the top of the ladder in both halves.

    ``probe_quota`` reaches ``DamageLedger`` through the same catalog pricing the
    authoritative ledger uses, so a gate-side pre-check cannot be cheaper than the
    check it stands in front of.
    """
    from mayhem.controller.policy_gate import probe_quota

    quota = _quota(per_fault_ceiling_s=1.0)
    view = probe_quota(_plan("proc.no_such_fault"), _inputs(damage_quota=quota))
    assert view.refused is not None
    assert view.refusal.rule_id == "damage_quota.per_fault_ceiling"  # type: ignore[union-attr]
    # Priced at the top of both ladders, so it is the *most* expensive rung.
    assert view.charges[0].weight == pytest.approx(UNRESOLVED_FAULT_WEIGHT)
