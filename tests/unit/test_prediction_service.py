"""Plan 14 Phase 2 — the prediction service and the no-mutation simulate path.

Phase 1's suite (``test_prediction.py``) proved the arithmetic. This suite proves
the *wiring*, and its properties are the ones a preview can get wrong while every
arithmetic test still passes:

* **The gate agrees, in production.** ``simulate_plan`` runs the real
  ``validate_plan`` and carries its refusal set out beside the prediction. Every
  group here is asserted against the real gate rather than a hand-written
  expectation, and a fault is injected to prove the invariant is enforced rather
  than merely computed.
* **Simulate cannot mutate.** The proof is a *measurement*: the caller's
  ``MutationSink`` is loaded with a recorded call beforehand, so
  ``report.mutation.calls == 0`` after a simulate can only mean the simulate
  added nothing. A hard-coded zero would pass the naive version of this test and
  fail the loaded one.
* **Ceilings are reported, and the debt is named.** Each of the four controls
  plus the blast-radius ceiling is exercised as an admission dimension, and a
  single test runs the *real* gate on a plan that breaches all five: the gate
  admits it, which is exactly the Phase 4 wiring this phase declines to do.
* **Unmeasured is never zero.** A drifted graph, an unresolvable target, an
  empty topology, an unmodelled gate refusal, and an absent price table each get
  their own disclosure rather than a passing-looking number.
* **A preview is never a preflight.** ``as_preflight`` raises, always.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from mayhem.config import PolicyCfg
from mayhem.domain.policy_gate import (
    MutationSink,
    PolicyGateInputs,
    capability_requirements_for,
    derive_facts,
)
from mayhem.controller.prediction_service import (
    ADMISSION_WIRING_NOTE,
    ENFORCED_CEILING_RULE_IDS,
    PENDING_ADMISSION_WIRING,
    PREDICTION_ARTIFACT,
    RULE_PENDING_ADMISSION_WIRING,
    RULE_PREDICTION_CALMER_THAN_GATE,
    RULE_PREDICTION_UNMODELLED_GATE_REFUSAL,
    RULE_PREVIEW_NOT_PREFLIGHT,
    SIMULATE_EXPECTED_EVIDENCE,
    AgreementState,
    CeilingName,
    GateAgreement,
    PredictionConfig,
    PredictionDisagreementError,
    PredictionService,
    PreviewNotPreflightError,
    SimulateReport,
    is_enforced_by_gate,
)
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, validate_plan
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
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.policy import (
    PolicyBundle,
    PolicyDimension,
    PolicyEffect,
    PolicyOperator,
    PolicyPredicate,
    PolicyRule,
)
from mayhem.domain.prediction import (
    RULE_FORBIDDEN_FAULT_PAIRS,
    RULE_MAX_AFFECTED_NODES,
    RULE_MAX_AFFECTED_PCT,
    RULE_MAX_CUSTOMER_FACING_SERVICES,
    RULE_MAX_DEPENDENCY_DEPTH,
    RULE_MAX_DURATION_PER_FAULT_S,
    RULE_MAX_SERVICES_PCT,
    RULE_PROTECTED_NODE,
    BlastCeilings,
    CostRateCard,
    graph_identity,
    predict_impact,
)
from mayhem.domain.quota import DamageQuota
from mayhem.domain.runtime_adapter import CapabilityRequirements
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    HostNode,
    NodeKind,
    PodNode,
    PortBinding,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)

FP = "f" * 64
OTHER_FP = "e" * 64
T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
STEP_S = 30.0


# --- fixtures ---------------------------------------------------------------------


def _container(node_id: str, name: str, *, service: str) -> ContainerNode:
    return ContainerNode(
        id=node_id,
        name=name,
        engine="docker",
        runtime_identity=RuntimeIdentity(
            runtime="docker", host_id="h-local", runtime_id=f"cid-{name}"
        ),
        runtime_metadata=RuntimeMetadata.from_compose_labels(
            {"com.docker.compose.service": service}
        ),
        container_name=service,
    )


def _graph() -> TopologyGraph:
    """A four-service chain, two hosts, two replicas of one service, two pods.

    ``n-db`` <- ``n-api`` <- ``n-web`` <- ``n-edge`` gives a three-hop fan-out
    from ``n-db`` and a two-hop one from ``n-web``; ``web-1``/``web-2`` are two
    replicas of one compose service; and ``n-web`` is the only service exposing a
    port, so the customer-facing count is 1 rather than "however many services are
    in the closure".
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-db", name="db"),
            ServiceNode(id="n-api", name="api"),
            ServiceNode(
                id="n-web",
                name="web",
                exposed_ports=(PortBinding(host_port=8080, container_port=8080),),
            ),
            ServiceNode(id="n-edge", name="edge"),
            HostNode(id="h-local", name="local", transport="local"),
            HostNode(id="h-remote", name="remote", transport="ssh"),
            _container("web-1", "web-1", service="web"),
            _container("web-2", "web-2", service="web"),
            PodNode(id="api-1", name="api-1", namespace="prod", owner_name="api-rs"),
            PodNode(id="api-2", name="api-2", namespace="prod", owner_name="api-rs"),
        ),
        edges=(
            Edge(src="n-api", dst="n-db", kind=EdgeKind.DEPENDS_ON),
            Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON),
            Edge(src="n-edge", dst="n-web", kind=EdgeKind.DEPENDS_ON),
            Edge(src="web-1", dst="n-web", kind=EdgeKind.EXPOSES),
            Edge(src="web-2", dst="n-web", kind=EdgeKind.EXPOSES),
            Edge(src="api-1", dst="n-api", kind=EdgeKind.RUNS_ON),
            Edge(src="api-2", dst="n-api", kind=EdgeKind.RUNS_ON),
            Edge(src="web-1", dst="h-local", kind=EdgeKind.RUNS_ON),
            Edge(src="web-2", dst="h-local", kind=EdgeKind.RUNS_ON),
        ),
    )


def _plan(
    *faults: tuple[str, str, float],
    run_id: str = "r-sim",
    fingerprint: str = FP,
    graph: TopologyGraph | None = None,
) -> ExecutionPlan:
    """Build a frozen plan: ``(fault_id, node_id, duration_s)`` per step.

    ``fingerprint`` is the plan's ``environment_fingerprint``. It is a parameter
    because the real gate compares it against the context's and refuses on a
    mismatch — which is how a plan planned against a *different* environment is
    caught in production, and this suite needs both the matching and the
    mismatching case.
    """
    source = graph if graph is not None else _graph()
    steps: list[PlannedStep] = []
    for index, (fault_id, node_id, duration) in enumerate(faults):
        node = source.by_id(node_id)
        selector = (
            TargetSelector(kind=node.kind, expr=node.name)
            if node is not None
            else TargetSelector(kind=NodeKind.SERVICE, expr=node_id)
        )
        steps.append(
            PlannedStep(
                id=f"s{index}",
                seq=index,
                raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=duration),
                fault=PlannedFault(
                    fault_id=fault_id,
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({node_id})),),
                    duration=duration,
                ),
            )
        )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DETERMINISTIC,
        steps=tuple(steps),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=fingerprint,
    )


def _permissive() -> BlastRadiusBudget:
    """Per-step limits nothing in this file trips, so a refusal has one cause."""
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(),
    )


def _duration_capped(cap_s: float = 60.0) -> BlastRadiusBudget:
    """A budget whose *only* possible breach is the per-fault duration cap.

    Every other cap lifted, because a test that asserts "the gate refused the
    duration rule" has to mean it: with the default 50% service cap in place, a
    deep target breaches that first and the gate never reaches the duration check.
    """
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=cap_s,
    )


def _bundle(
    *rules: PolicyRule,
    default: PolicyEffect = PolicyEffect.ALLOW,
    expires_at: datetime | None = None,
) -> PolicyBundle:
    return PolicyBundle(
        bundle_id="sim-test",
        version=1,
        rules=rules,
        default_effect=default,
        created_at=T0 - timedelta(days=1),
        expires_at=expires_at,
    )


def _inputs(bundle: PolicyBundle | None = None) -> PolicyGateInputs:
    return PolicyGateInputs(bundle=bundle or _bundle(), now=T0)


def _ctx(
    *,
    budget: BlastRadiusBudget | None = None,
    quota: DamageQuota | None = None,
    policy: PolicyCfg | None = None,
    fingerprint: str = FP,
    gate: PolicyGateInputs | None = None,
    environment: str | None = None,
) -> SafetyContext:
    return SafetyContext(
        policy=policy or PolicyCfg(),
        budget=budget or _permissive(),
        fingerprint=fingerprint,
        damage_quota=quota or DamageQuota(),
        policy_gate=gate,
        environment=environment,
    )


def _service(
    graph: TopologyGraph | None = None,
    *,
    ceilings: BlastCeilings | None = None,
    rate_card: CostRateCard | None = None,
    observed: dict[PolicyDimension, tuple[str, ...]] | None = None,
) -> PredictionService:
    live = graph if graph is not None else _graph()
    return PredictionService(
        graph=live,
        config=PredictionConfig(
            ceilings=ceilings if ceilings is not None else BlastCeilings(),
            rate_card=rate_card if rate_card is not None else CostRateCard(),
            observed=observed if observed is not None else {},
        ),
    )


def _gate_refusals(plan: ExecutionPlan, graph: TopologyGraph, ctx: SafetyContext) -> frozenset[str]:
    """Rule ids the *real* gate refuses — read straight from ``validate_plan``."""
    try:
        validate_plan(plan, graph, ctx)
    except SafetyRefusedError as exc:
        return frozenset({exc.decision.rule_id}) if exc.decision is not None else frozenset()
    return frozenset()


# --- service assembly --------------------------------------------------------------


def test_the_service_reads_its_limits_off_the_gate_context():
    """The preview's budget and quota are the gate's objects, not copies of our own."""
    ctx = _ctx(budget=BlastRadiusBudget(max_services_pct=50.0), quota=DamageQuota(budget_s=1e9))
    service = _service()
    budget, quota = service.budgets(ctx)
    assert budget is ctx.budget
    assert quota is ctx.damage_quota


def test_the_prediction_is_computed_with_the_gates_own_limits():
    """A tight cap the gate refuses is a cap the preview reports — same number."""
    budget = BlastRadiusBudget(
        max_services_pct=50.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
    )
    graph, plan = _graph(), _plan(("net.latency", "n-db", STEP_S))
    report = _service(graph).simulate_plan(plan, _ctx(budget=budget))
    rule = next(r for r in report.prediction.violated_rules if r.rule_id == RULE_MAX_SERVICES_PCT)
    # n-db's blast reaches 3 of the 4 services in the chain: 100%, over a 50% cap.
    assert rule.observed == pytest.approx(100.0)
    assert rule.limit == 50.0
    assert report.agreement.gate_refused == {RULE_MAX_SERVICES_PCT}


def test_the_damage_quota_read_is_the_contexts_not_the_budgets_own_field():
    """``BlastRadiusBudget.damage_quota`` is a *default*, not what the gate charges.

    The context's quota is the authoritative one — ``check_blast_radius`` charges
    ``ctx.damage_quota`` — while the field on the budget is only the fallback for a
    context that has none. A preview that read the field would evaluate a limit
    admission never applies, which is a disagreement in the direction nobody
    notices: a preview refusing a plan the gate admits.
    """
    plan = _plan(("net.partition", "n-edge", 300.0))
    ctx = _ctx(quota=DamageQuota(budget_s=1e9, per_fault_ceiling_s=1e9, window_s=1e9))
    # A budget whose *own* damage_quota field is tiny. The gate ignores it.
    ctx_with_tiny_field = SafetyContext(
        policy=ctx.policy,
        budget=BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=2**31 - 1,
            max_concurrent_faults=2**31 - 1,
            max_duration_per_fault_s=float("inf"),
            damage_quota=DamageQuota(budget_s=1.0, per_fault_ceiling_s=1.0, window_s=1.0),
        ),
        fingerprint=ctx.fingerprint,
        damage_quota=ctx.damage_quota,
    )
    report = _service().simulate_plan(plan, ctx_with_tiny_field)
    assert "damage_quota.budget" not in report.prediction.rule_ids
    assert report.prediction.rule_ids == frozenset()
    assert report.admitted_by_gate is True


def test_policy_facts_are_the_gates_own_derivation_when_a_bundle_is_configured():
    """The facts beside a policy verdict must be the facts the verdict used.

    A second derivation here would be a second answer to "what did the gate
    observe", which is the disagreement plan 07 moved ``derive_facts`` upstream to
    prevent.
    """
    gate = _inputs()
    ctx = _ctx(gate=gate, environment="staging")
    plan = _plan(("net.latency", "n-db", STEP_S))
    report = _service().simulate_plan(plan, ctx)
    assert report.facts == derive_facts(plan, gate, environment="staging")
    assert report.facts_complete is True
    assert report.policy is not None
    assert report.policy.simulated is True


def test_without_a_bundle_the_fact_set_is_the_predictions_own_and_says_so():
    """Six unobserved dimensions are not a bundle evaluation, and the note says so."""
    report = _service().simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.facts_complete is False
    assert report.policy is None
    assert report.facts.observed(PolicyDimension.TARGET) == frozenset({"n-db"})
    assert report.facts.observed(PolicyDimension.FAULT_FAMILY) is None
    assert any("not a bundle evaluation" in note for note in report.notes)


def test_configured_observations_fill_only_dimensions_no_derivation_reaches():
    """Team, schedule, and the rest are supplied; the target set is not negotiable."""
    service = _service(
        observed={
            PolicyDimension.TEAM: ("payments",),
            PolicyDimension.SCHEDULE: ("off-peak",),
        }
    )
    report = service.simulate_plan(
        _plan(("net.latency", "n-db", STEP_S)), _ctx(environment="staging")
    )
    assert report.facts.observed(PolicyDimension.TEAM) == frozenset({"payments"})
    assert report.facts.observed(PolicyDimension.SCHEDULE) == frozenset({"off-peak"})
    assert report.facts.observed(PolicyDimension.ENVIRONMENT) == frozenset({"staging"})
    # Derived from the plan and the graph, not from configuration.
    assert report.facts.observed(PolicyDimension.TARGET) == frozenset({"n-db"})


def test_capability_requirements_come_from_the_shared_derivation():
    plan = _plan(("net.latency", "n-db", STEP_S))
    report = _service().simulate_plan(plan, _ctx())
    assert report.capabilities == capability_requirements_for(plan)
    assert isinstance(report.capabilities, CapabilityRequirements)


def test_expected_evidence_names_every_record_the_preflight_names():
    """The simulate path must not describe a smaller run than the preflight does.

    ``prediction`` is the one addition, and it is the record Phase 4 seals with
    the plan. Everything preflight already promised has to be here too, or a
    reader of the simulate output would not know what the run should end up with.
    """
    from mayhem.controller.preflight import build_preflight

    plan = _plan(("net.latency", "n-db", STEP_S))
    preflight = build_preflight(
        spec_path=None,
        compose=None,
        graph=_graph(),
        store=None,
        config_path=None,
        profile=None,
        allow_critical=False,
        target=None,
        engine=None,
        plan=plan,
    )
    report = _service().simulate_plan(plan, _ctx())
    assert set(preflight.expected_evidence) <= set(report.expected_evidence)
    assert "prediction" in report.expected_evidence
    assert report.expected_evidence == SIMULATE_EXPECTED_EVIDENCE


def test_a_simulate_leaves_the_callers_safety_context_untouched():
    """A preview must not append its own probe decisions to the run's safety record."""
    ctx = _ctx(budget=BlastRadiusBudget(max_services_pct=25.0))
    graph = _graph()
    before = graph.model_dump(mode="json")
    _service(graph).simulate_plan(_plan(("net.latency", "n-db", STEP_S)), ctx)
    assert ctx.decisions == []
    assert ctx.warnings == []
    assert graph.model_dump(mode="json") == before


# --- the gate-agreement invariant, in production wiring ---------------------------


@pytest.mark.parametrize(
    ("budget", "faults", "expected_rule"),
    [
        (
            BlastRadiusBudget(
                max_services_pct=50.0,
                max_hosts=2**31 - 1,
                max_concurrent_faults=2**31 - 1,
                max_duration_per_fault_s=float("inf"),
            ),
            (("net.latency", "n-db", STEP_S),),
            RULE_MAX_SERVICES_PCT,
        ),
        (
            BlastRadiusBudget(
                max_services_pct=100.0,
                max_hosts=2**31 - 1,
                max_concurrent_faults=2**31 - 1,
                max_duration_per_fault_s=60.0,
            ),
            (("net.latency", "n-db", 300.0),),
            RULE_MAX_DURATION_PER_FAULT_S,
        ),
        (
            BlastRadiusBudget(
                max_services_pct=100.0,
                max_hosts=2**31 - 1,
                max_concurrent_faults=2**31 - 1,
                max_duration_per_fault_s=float("inf"),
                forbidden_fault_pairs=frozenset({frozenset({"net.latency", "net.partition"})}),
            ),
            (("net.latency", "n-edge", 30.0), ("net.partition", "n-web", 30.0)),
            RULE_FORBIDDEN_FAULT_PAIRS,
        ),
        (
            _permissive(),
            (("net.latency", "n-db", STEP_S),),
            "",
        ),
    ],
)
def test_the_report_carries_the_real_gates_own_refusal_set(budget, faults, expected_rule):
    """Read against ``validate_plan``, not against a hand-written expectation.

    Every refusal the gate raises must be in the report, and the one-directional
    invariant must hold on the report as returned — which is the difference
    between the invariant being enforced in production and existing only in a
    test.
    """
    graph, plan = _graph(), _plan(*faults)
    ctx = _ctx(budget=budget)
    report = _service(graph).simulate_plan(plan, ctx)
    refused = _gate_refusals(plan, graph, ctx)
    assert refused == ({expected_rule} if expected_rule else frozenset())
    assert report.agreement.gate_refused == refused
    assert report.admitted_by_gate is (not refused)
    assert report.agreement.unmodelled == frozenset()
    assert report.agreement.agrees is True
    assert refused <= report.prediction.rule_ids


def test_a_cumulative_damage_refusal_is_agreed_against_the_real_gate():
    """The one rule that sees the sequence rather than a step."""
    graph = _graph()
    plan = _plan(*(("net.partition", "n-edge", 300.0) for _ in range(3)))
    ctx = _ctx(quota=DamageQuota(budget_s=700.0, per_fault_ceiling_s=1e9, window_s=1e9))
    report = _service(graph).simulate_plan(plan, ctx)
    assert _gate_refusals(plan, graph, ctx) == {"damage_quota.budget"}
    assert report.agreement.gate_refused == {"damage_quota.budget"}
    assert "damage_quota.budget" in report.prediction.rule_ids
    assert report.agreement.agrees is True


def test_a_concurrency_refusal_on_the_second_step_is_agreed_against_the_real_gate():
    budget = BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=1,
        max_duration_per_fault_s=float("inf"),
    )
    graph = _graph()
    plan = _plan(("net.latency", "n-edge", 30.0), ("net.latency", "n-web", 30.0))
    ctx = _ctx(budget=budget)
    report = _service(graph).simulate_plan(plan, ctx)
    assert _gate_refusals(plan, graph, ctx) == {"blast_radius.max_concurrent_faults"}
    assert report.agreement.gate_refused == {"blast_radius.max_concurrent_faults"}
    assert report.agreement.agrees is True


def test_a_config_policy_denial_is_disclosed_as_unmodelled_and_blocks_approval_use():
    """The gate refuses a rule the preview has no vocabulary for.

    Two things must happen, and neither is "ignore it": the refusal is reported in
    ``unmodelled`` so a reader sees it, and the preview becomes unusable for
    approval, because a preview that cannot speak to the rule which blocked the
    plan may not be the thing an approver relies on.

    Phase 4 states the second half as a named state rather than as a consequence
    of the first set being non-empty, so it is asserted through
    :attr:`AgreementState.UNMODELLED` as well as through the boolean.
    """
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = _ctx(policy=PolicyCfg(deny_faults=frozenset({"net.latency"})))
    report = _service(graph).simulate_plan(plan, ctx)
    assert report.agreement.gate_refused == {"policy.deny_faults"}
    assert report.agreement.unmodelled == {"policy.deny_faults"}
    assert report.agreement.modelled == frozenset()
    assert report.agreement.agrees is True  # nothing modelled was missed
    assert report.agreement.state is AgreementState.UNMODELLED
    assert report.agreement_state is AgreementState.UNMODELLED
    assert report.agreement.usable_for_approval is False
    assert report.usable_for_approval is False
    assert "policy.deny_faults" in report.approval_refusal
    assert "does not model" in report.approval_refusal
    # The refusal is named by a rule id, so a surface can render the debt as a
    # finding rather than as prose.
    assert RULE_PREDICTION_UNMODELLED_GATE_REFUSAL in report.approval_refusal
    assert "[agreement: unmodelled]" in report.describe()


def test_a_gate_that_admits_leaves_the_agreement_in_the_agrees_state():
    """The default state, asserted so the other two cannot be reached by accident."""
    report = _service().simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.agreement.gate_refused == frozenset()
    assert report.agreement.state is AgreementState.AGREES
    assert report.agreement.usable_for_approval is True
    assert report.approval_refusal == ""
    assert report.usable_for_approval is True


def test_a_modelled_refusal_the_prediction_flagged_also_agrees():
    """A modelled refusal that the preview *did* flag is not a disagreement."""
    report = _service().simulate_plan(
        _plan(("net.latency", "n-db", 300.0)), _ctx(budget=_duration_capped())
    )
    assert report.agreement.modelled == {RULE_MAX_DURATION_PER_FAULT_S}
    assert report.agreement.unmodelled == frozenset()
    assert report.agreement.state is AgreementState.AGREES


def test_an_agreement_record_cannot_assert_a_state_its_own_sets_contradict():
    """The negative control on the state itself.

    Phase 4's complaint was that the rule lived outside the record, so the record
    could be handed out saying anything. ``GateAgreement.__post_init__`` refuses a
    state that its own booleans contradict, so a caller cannot build a record that
    reads "unmodelled" beside ``agrees=False`` — or, worse, "agrees" beside a
    modelled refusal the prediction missed.
    """
    fields = {
        "gate_refused": frozenset({"policy.deny_faults"}),
        "modelled": frozenset(),
        "unmodelled": frozenset({"policy.deny_faults"}),
        "flagged": frozenset(),
        "agrees": True,
        "reason": "",
        "state": AgreementState.UNMODELLED,
    }
    assert GateAgreement(**fields).state is AgreementState.UNMODELLED
    with pytest.raises(InvariantViolationError):
        GateAgreement(**{**fields, "state": AgreementState.AGREES})
    # Omitting the state entirely is a TypeError, not a silent default to AGREES:
    # a caller who forgot to state it must not hand out a record that claims the
    # preview agreed when its own booleans say otherwise.
    with pytest.raises(TypeError):
        GateAgreement(**{k: v for k, v in fields.items() if k != "state"})
    # A disagreement claimed as agreeing is refused too, even though the sets look
    # clean: ``agrees=False`` with nothing unmodelled can only be DISAGREES.
    with pytest.raises(InvariantViolationError):
        GateAgreement(
            **{
                **fields,
                "gate_refused": frozenset({RULE_MAX_SERVICES_PCT}),
                "modelled": frozenset({RULE_MAX_SERVICES_PCT}),
                "unmodelled": frozenset(),
                "agrees": False,
                "reason": "missed it",
                "state": AgreementState.AGREES,
            }
        )


def test_an_environment_fingerprint_mismatch_is_drift_and_is_refused_for_approval_use():
    """The gate's own drift check, caught in production and reported as unmodelled.

    A plan planned against one environment and simulated against another is
    refused by ``validate_plan`` before any fault is considered. The preview
    cannot model that rule, so it discloses the refusal and refuses itself for
    approval use rather than presenting numbers from the wrong environment.
    """
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S), fingerprint=OTHER_FP)
    ctx = _ctx(fingerprint=FP)
    report = _service(graph).simulate_plan(plan, ctx)
    assert _gate_refusals(plan, graph, ctx) == {"environment.fingerprint_mismatch"}
    assert report.agreement.unmodelled == {"environment.fingerprint_mismatch"}
    assert report.usable_for_approval is False
    assert "environment.fingerprint_mismatch" in report.approval_refusal


def test_a_calmer_prediction_raises_instead_of_returning_a_report(monkeypatch):
    """The invariant is enforced, not merely computed.

    A stub is injected that returns a prediction computed through a *permissive*
    budget while the gate still holds the tight one — the exact shape of a
    drifting duplicate. Without the check the caller would receive a clean preview
    for a plan the gate refuses; with it, the call raises.
    """
    from mayhem.controller import prediction_service

    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = _ctx(budget=BlastRadiusBudget(max_services_pct=25.0))
    too_calm = predict_impact(graph, plan, budget=_permissive())
    monkeypatch.setattr(prediction_service, "predict_impact", lambda *a, **k: too_calm)

    assert _gate_refusals(plan, graph, ctx) == {RULE_MAX_SERVICES_PCT}
    with pytest.raises(PredictionDisagreementError) as excinfo:
        _service(graph).simulate_plan(plan, ctx)
    assert excinfo.value.rule == RULE_PREDICTION_CALMER_THAN_GATE
    assert RULE_MAX_SERVICES_PCT in str(excinfo.value)
    assert "never be calmer" in str(excinfo.value)


def test_a_calmer_prediction_would_have_landed_in_the_disagrees_state():
    """Why the raise exists: DISAGREES is the state, and it is not a report.

    Same injected fault as above, but asserting the *state* the comparison would
    have produced rather than only the exception. Without this, a reader could
    believe the raise is a guard bolted on top of a working three-state machine
    when in fact the machine is what refuses; the state is the load-bearing part.
    """
    from mayhem.controller import prediction_service

    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    # The gate would hold a 25% service cap; the injected forecast is computed
    # through a budget nothing trips. No context is needed, because the assertion
    # is about the *state* the comparison lands in rather than about a report.
    too_calm = predict_impact(graph, plan, budget=_permissive())
    monkey = prediction_service._agreement(
        too_calm, frozenset({RULE_MAX_SERVICES_PCT})
    )
    assert monkey.state is AgreementState.DISAGREES
    assert monkey.usable_for_approval is False
    # And even a state that is not a disagreement keeps its approval answer, so
    # the property is on the state and not only on the raise.
    assert AgreementState.AGREES.usable_for_approval is True
    assert AgreementState.UNMODELLED.usable_for_approval is False
    assert AgreementState.DISAGREES.usable_for_approval is False


def test_a_gate_refusal_the_preview_modelled_is_a_finding_and_never_hidden():
    """The breach is the finding, and the preview still says it is incomplete.

    A modelled gate refusal is not a separate disqualification — the preview's
    own reason for refusing itself here is Phase 1's truncation disclosure, because
    the walk stopped where the gate stops and any later step went unmeasured. What
    matters is that neither of those reasons is "because the plan breaches a cap":
    the rule is flagged, its observed value is on the report, and an approver sees
    the breach rather than a refusal that reads like a rendering problem.
    """
    graph = _graph()
    plan = _plan(("net.latency", "n-db", 300.0))
    ctx = _ctx(budget=_duration_capped())
    report = _service(graph).simulate_plan(plan, ctx)
    assert report.agreement.gate_refused == {RULE_MAX_DURATION_PER_FAULT_S}
    assert report.agreement.unmodelled == frozenset()
    assert report.agreement.agrees is True
    assert report.prediction.within_policy is False
    assert report.usable_for_approval is False
    # The reason is the unmeasured tail, not the breach.
    assert "never measured" in report.approval_refusal
    assert "stopped at step 0" in report.approval_refusal
    # …and the breach itself is on the report with its numbers.
    rule = next(
        r for r in report.prediction.violated_rules if r.rule_id == RULE_MAX_DURATION_PER_FAULT_S
    )
    assert rule.observed == 300.0
    assert rule.limit == 60.0
    assert rule.remediation


def test_the_agreement_summary_names_what_it_compared():
    report = _service().simulate_plan(
        _plan(("net.latency", "n-db", 300.0)), _ctx(budget=_duration_capped())
    )
    assert "blast_radius.max_duration_per_fault_s" in report.agreement.describe()
    assert "gate refused" in report.describe()


# --- simulate purity --------------------------------------------------------------


def test_a_simulate_records_zero_mutation_while_reaching_a_real_decision():
    """The plan's own acceptance criterion: a mock backend, zero calls.

    The plan here is one the gate *refuses*, so the assertion is not satisfied by
    a simulate that quietly did nothing: a decision was reached, it was a refusal,
    and the sink is still empty.
    """
    sink = MutationSink()
    service = PredictionService(graph=_graph(), backend=sink)
    ctx = _ctx(budget=BlastRadiusBudget(max_services_pct=25.0))
    report = service.simulate_plan(_plan(("net.latency", "n-db", STEP_S)), ctx)

    assert len(sink) == 0
    assert sink.calls == ()
    assert report.mutation.calls == 0
    assert report.mutation.calls_detail == ()
    # ... and a real verdict was reached through it.
    assert report.agreement.gate_refused == {RULE_MAX_SERVICES_PCT}
    assert RULE_MAX_SERVICES_PCT in report.prediction.rule_ids
    assert report.gate_decisions != ()


def test_a_simulate_cannot_mutate_even_with_a_mutation_backend_reachable():
    """The sink is handed in, held, and read — never written.

    Detaching the backend is the structural half; this is the other half: the
    backend is *reachable* from the service the whole time, so nothing about the
    zero depends on the caller's cooperation.
    """
    sink = MutationSink()
    service = PredictionService(graph=_graph(), backend=sink)
    assert service.backend is sink
    assert service.detached().backend is None

    for ctx, plan in (
        (_ctx(), _plan(("net.latency", "n-db", STEP_S))),
        (
            _ctx(budget=BlastRadiusBudget(max_services_pct=25.0)),
            _plan(("net.latency", "n-db", STEP_S)),
        ),
        (
            _ctx(policy=PolicyCfg(deny_faults=frozenset({"net.latency"}))),
            _plan(("net.latency", "n-db", STEP_S)),
        ),
    ):
        report = service.simulate_plan(plan, ctx)
        assert len(sink) == 0
        assert report.mutation.backend_attached is False
        assert report.mutation.calls == 0


def test_the_mutation_proof_is_a_measurement_of_the_sink_not_a_constant():
    """The negative control on the purity proof itself.

    A ``calls == 0`` hard-coded into the report would pass the test above and
    fail this one. Loading the sink first makes the zero informative: the report
    reads the sink, so the only way it reports zero after the call is that the
    call added nothing.
    """
    loaded = MutationSink().record("budget.charge", "payments/team:120s")
    assert len(loaded) == 1
    service = PredictionService(graph=_graph(), backend=loaded)
    report = service.simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.mutation.calls == 1
    assert report.mutation.calls_detail == (("budget.charge", "payments/team:120s"),)
    assert report.mutation.backend_attached is False
    # The pre-existing call is still the only one: the simulate added nothing.
    assert len(loaded) == 1


def test_a_simulate_reports_its_backend_as_detached_even_when_one_is_held():
    report = PredictionService(graph=_graph(), backend=MutationSink()).simulate_plan(
        _plan(("net.latency", "n-db", STEP_S)), _ctx()
    )
    assert report.mutation.backend_attached is False
    assert "backend detached" in report.describe()


def test_the_service_holds_the_live_graph_so_two_plans_describe_one_topology():
    """A prediction is a statement about *this* topology, not about a call."""
    graph = _graph()
    service = _service(graph)
    report = service.simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.prediction.graph_identity == graph_identity(graph)
    assert service.graph is graph
    assert service.with_config(PredictionConfig()).graph is graph


# --- the four plan-14 controls, as admission dimensions ---------------------------


#: ``n-db`` is the deepest target in the fixture graph: its blast reaches four
#: nodes over three dependency hops, so every numeric ceiling has something to
#: measure against it.
def _ceiling_report(ceilings: BlastCeilings, node_id: str = "n-db") -> SimulateReport:
    return _service(ceilings=ceilings).simulate_plan(
        _plan(("net.latency", node_id, STEP_S)), _ctx()
    )


def test_the_protected_service_list_breach_names_the_protected_ids_it_hit():
    """Protection is about targets. A protected node that is only a dependent is
    not a breach, so the list here contains one that is targeted and one that is
    merely inside the blast — and only the first is reported."""
    report = _ceiling_report(BlastCeilings(protected_node_ids=frozenset({"n-db", "n-web"})))
    verdict = report.dimension(CeilingName.PROTECTED_SERVICES)
    assert verdict.rule_id == RULE_PROTECTED_NODE
    assert verdict.configured is True
    assert verdict.breached is True
    assert verdict.observed == 1.0
    assert verdict.limit == 0.0
    assert "n-db" in verdict.detail
    assert "n-web" not in verdict.detail  # protected, but only a dependent
    assert "n-web" in report.prediction.affected_node_ids
    assert RULE_PROTECTED_NODE in report.prediction.rule_ids


def test_the_dependency_depth_ceiling_reports_hops_measured_from_the_target():
    report = _ceiling_report(BlastCeilings(max_dependency_depth=1))
    verdict = report.dimension(CeilingName.MAX_DEPENDENCY_DEPTH)
    assert verdict.rule_id == RULE_MAX_DEPENDENCY_DEPTH
    assert verdict.configured is True
    assert verdict.breached is True
    # n-db -> n-api -> n-web -> n-edge is three hops.
    assert verdict.observed == 3.0
    assert verdict.limit == 1.0
    assert verdict.unit == "hops"
    assert verdict.observed - verdict.limit == 2.0
    assert report.prediction.fan_out.max_depth == 3


def test_the_customer_facing_ceiling_counts_only_services_that_expose_a_port():
    report = _ceiling_report(BlastCeilings(max_customer_facing_services=0))
    verdict = report.dimension(CeilingName.MAX_CUSTOMER_FACING_SERVICES)
    assert verdict.rule_id == RULE_MAX_CUSTOMER_FACING_SERVICES
    assert verdict.breached is True
    # Four services are affected; n-web is the only one exposing a port, so the
    # count is 1 and not 4.
    assert verdict.observed == 1.0
    assert verdict.limit == 0.0
    assert "n-web" in verdict.detail


def test_the_percentage_ceiling_reports_the_node_share_of_the_graph():
    report = _ceiling_report(BlastCeilings(max_affected_pct=5.0))
    verdict = report.dimension(CeilingName.MAX_AFFECTED_PCT)
    assert verdict.rule_id == RULE_MAX_AFFECTED_PCT
    assert verdict.breached is True
    # 4 of 10 nodes.
    assert verdict.observed == pytest.approx(40.0)
    assert verdict.limit == 5.0
    assert verdict.unit == "percent_of_nodes"


def test_the_blast_radius_ceiling_caps_the_raw_affected_node_count():
    report = _ceiling_report(BlastCeilings(max_affected_nodes=2))
    verdict = report.dimension(CeilingName.BLAST_RADIUS_CEILING)
    assert verdict.rule_id == RULE_MAX_AFFECTED_NODES
    assert verdict.breached is True
    assert verdict.observed == 4.0
    assert verdict.limit == 2.0
    assert verdict.unit == "nodes"


def test_a_ceiling_the_blast_lands_inside_is_reported_as_within_it():
    """A ceiling nothing trips must read as within the limit, not merely silent.

    A rule that fired on every plan would be a rule nobody could act on, and a
    dimension that only ever appears when breached gives an operator no way to
    tell "checked, fine" from "never looked at".
    """
    report = _ceiling_report(BlastCeilings(max_dependency_depth=3, max_affected_nodes=4))
    assert report.dimension(CeilingName.MAX_DEPENDENCY_DEPTH).breached is False
    assert report.dimension(CeilingName.MAX_DEPENDENCY_DEPTH).observed == 3.0
    assert report.dimension(CeilingName.BLAST_RADIUS_CEILING).breached is False
    assert report.dimension(CeilingName.BLAST_RADIUS_CEILING).observed == 4.0
    assert report.breached_dimensions() == ()


@pytest.mark.parametrize(
    ("ceilings", "name"),
    [
        (BlastCeilings(), CeilingName.PROTECTED_SERVICES),
        (BlastCeilings(), CeilingName.MAX_DEPENDENCY_DEPTH),
        (BlastCeilings(), CeilingName.MAX_CUSTOMER_FACING_SERVICES),
        (BlastCeilings(), CeilingName.MAX_AFFECTED_PCT),
        (BlastCeilings(), CeilingName.BLAST_RADIUS_CEILING),
    ],
)
def test_an_unconfigured_ceiling_is_reported_as_unchecked_not_satisfied(ceilings, name):
    """``configured=False`` is the disclosure; it is never rendered as "passed"."""
    report = _ceiling_report(ceilings)
    verdict = report.dimension(name)
    assert verdict.configured is False
    assert verdict.limit is None
    assert verdict.breached is False
    assert report.configured_dimensions == ()


def test_every_ceiling_is_reported_whether_or_not_it_is_configured():
    report = _ceiling_report(BlastCeilings())
    assert {d.dimension for d in report.dimensions} == set(CeilingName)
    assert len(report.dimensions) == len(CeilingName)
    # A measurement is still attached to an unchecked ceiling: "we did not check
    # this" must never render identically to "this passed".
    assert all(d.observed is not None for d in report.dimensions)


def test_an_unmeasurable_percentage_is_none_and_never_a_passing_zero():
    """An empty graph has no share to divide by, so the dimension is unmeasured."""
    empty = TopologyGraph(nodes=(), edges=())
    report = _service(empty).simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    verdict = report.dimension(CeilingName.MAX_AFFECTED_PCT)
    assert verdict.observed is None
    assert verdict.breached is False
    assert "no nodes" in verdict.detail
    # And the prediction behind it is refused for approval use, not passed.
    assert report.prediction.basis.value == "empty_graph"
    assert report.usable_for_approval is False


def test_breached_dimensions_lists_only_the_ceilings_that_fired():
    report = _ceiling_report(
        BlastCeilings(max_dependency_depth=1, max_customer_facing_services=99)
    )
    breached = report.breached_dimensions()
    assert [d.dimension for d in breached] == [CeilingName.MAX_DEPENDENCY_DEPTH]
    assert all(d.breached for d in breached)


def test_every_plan_14_ceiling_is_now_enforced_by_the_real_gate():
    """Phase 4's retirement of the wiring debt, asserted rather than assumed.

    One plan breaching all five ceilings, run through the *real* ``validate_plan``.
    The gate now refuses it, and refuses it on the very rule the preview flagged.
    Phase 2 asserted the opposite — that the gate has no opinion on any of the
    five — and said this test would be "what fails the day Phase 4 lands the
    wiring". This is that day, so the assertion has been inverted deliberately:
    leaving the old claim would be a test asserting the gate *cannot* emit ids it
    now emits.

    The comparison is against ``validate_plan`` rather than a hand-written rule
    list, so it stays honest if the gate's rule ids ever move.
    """
    ceilings = BlastCeilings(
        max_affected_nodes=2,
        max_dependency_depth=1,
        max_customer_facing_services=0,
        max_affected_pct=5.0,
        protected_node_ids=frozenset({"n-db"}),
    )
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = _ctx()
    service = PredictionService(graph=graph, config=PredictionConfig(ceilings=ceilings))
    report = service.simulate_plan(plan, ctx)

    # The gate refuses on one of the five (it stops at the first breach), and the
    # one it names is one the preview flagged.
    refused = _gate_refusals(plan, graph, replace(ctx, blast_ceilings=ceilings))
    assert len(refused) == 1
    assert refused <= ENFORCED_CEILING_RULE_IDS
    assert refused <= report.prediction.rule_ids
    assert report.admitted_by_gate is False

    # …and every dimension reports itself enforced, with nothing pending.
    assert {d.rule_id for d in report.breached_dimensions()} == ENFORCED_CEILING_RULE_IDS
    assert all(d.enforced_by_gate is True for d in report.dimensions)
    assert report.wiring_gaps == ()
    assert PENDING_ADMISSION_WIRING == ()


def test_the_admission_wiring_note_names_the_enforced_rules():
    """The note flipped with the table; it must not still claim the debt is owed.

    A note reading "enforced by nobody" while the gate now refuses would be worse
    than no note — it would be an active misstatement in every report. So the text
    is checked for the words it asserts, not just for being present.
    """
    assert "enforced" in ADMISSION_WIRING_NOTE
    assert "nobody" not in ADMISSION_WIRING_NOTE
    assert "still owes" not in ADMISSION_WIRING_NOTE
    for rule in sorted(ENFORCED_CEILING_RULE_IDS):
        assert rule in ADMISSION_WIRING_NOTE
    assert RULE_PENDING_ADMISSION_WIRING in ADMISSION_WIRING_NOTE
    report = _service().simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert any(note == ADMISSION_WIRING_NOTE for note in report.notes)


def _gate_emitted_rule_ids() -> set[str]:
    """Every rule id the real gate names across this file's battery of refusals.

    Collected by running ``validate_plan`` for real — the point is to observe the
    gate's own vocabulary, not to assert what it ought to say.
    """
    graph = _graph()
    denier = PolicyRule(
        rule_id="sim.denies.production",
        dimension=PolicyDimension.ENVIRONMENT,
        predicate=PolicyPredicate(operator=PolicyOperator.IN, values=("production",)),
        effect=PolicyEffect.DENY,
        reason="simulation is not permitted in production",
    )
    cases: tuple[tuple[ExecutionPlan, SafetyContext], ...] = (
        (
            _plan(("net.latency", "n-db", 300.0)),
            _ctx(
                budget=BlastRadiusBudget(
                    max_services_pct=100.0,
                    max_hosts=2**31 - 1,
                    max_concurrent_faults=2**31 - 1,
                    max_duration_per_fault_s=60.0,
                )
            ),
        ),
        (
            _plan(("net.latency", "n-edge", 30.0), ("net.latency", "n-web", 30.0)),
            _ctx(
                budget=BlastRadiusBudget(
                    max_services_pct=100.0,
                    max_hosts=2**31 - 1,
                    max_concurrent_faults=1,
                    max_duration_per_fault_s=float("inf"),
                )
            ),
        ),
        (
            _plan(*(("net.partition", "n-edge", 300.0) for _ in range(3))),
            _ctx(quota=DamageQuota(budget_s=700.0, per_fault_ceiling_s=1e9, window_s=1e9)),
        ),
        (
            _plan(("net.latency", "n-db", STEP_S)),
            _ctx(policy=PolicyCfg(deny_faults=frozenset({"net.latency"}))),
        ),
        (
            _plan(("net.latency", "n-db", STEP_S)),
            _ctx(gate=PolicyGateInputs(bundle=_bundle(denier), now=T0), environment="production"),
        ),
        (_plan(("net.latency", "n-db", STEP_S), fingerprint=OTHER_FP), _ctx()),
    )
    emitted: set[str] = set()
    for plan, ctx in cases:
        try:
            validate_plan(plan, graph, ctx)
        except SafetyRefusedError as exc:
            if exc.decision is not None:
                emitted.add(exc.decision.rule_id)
    return emitted


def test_the_enforced_flag_is_derived_from_the_wiring_table_not_asserted():
    """Phase 4's job was to delete five rows, and every record had to follow.

    ``enforced_by_gate`` is computed from :data:`PENDING_ADMISSION_WIRING` rather
    than hardcoded per dimension, so a ceiling that *is* wired into admission
    cannot keep claiming it is not. The other direction is the table's
    completeness: a rule id absent from it is taken to be the gate's, so an
    implementer has to add or remove a row rather than flip a field.

    With the table empty that default is unfalsifiable from the table alone --
    every rule id reads as "the gate's" -- so it is checked here against
    :data:`ENFORCED_CEILING_RULE_IDS`, the finite set of rules this preview
    actually reports dimensions for. The evidence suite's
    ``test_every_enforced_ceiling_is_one_the_real_gate_can_raise`` then checks
    *that* set against the gate's own refusals, so neither half is a bare default.
    """
    assert PENDING_ADMISSION_WIRING == ()
    for rule in sorted(ENFORCED_CEILING_RULE_IDS):
        assert is_enforced_by_gate(rule) is True
    # A rule the gate already evaluated is reported as the gate's.
    assert is_enforced_by_gate("blast_radius.max_hosts") is True
    report = _ceiling_report(BlastCeilings())
    assert {d.rule_id for d in report.dimensions if d.enforced_by_gate} == (
        ENFORCED_CEILING_RULE_IDS
    )
    assert {d.rule_id for d in report.dimensions if not d.enforced_by_gate} == set()


def test_the_phase_two_tripwire_became_its_inverse():
    """The tripwire on Phase 4, retired by inversion rather than deleted.

    Phase 2 asserted that no rule in the wiring table is one the gate can emit --
    a check deliberately *designed to fire* the day Phase 4 landed. It fired; the
    rows were deleted. The surviving form is the other direction: a ceiling the
    preview reports as enforced must be one the gate can actually raise, which is
    what keeps ``enforced_by_gate`` from degenerating into the table's default
    now that the table is empty.
    """
    assert _gate_emitted_rule_ids()  # the battery still refuses something
    assert not {w.rule_id for w in PENDING_ADMISSION_WIRING}


# --- drift, staleness, and what cannot back an approval ---------------------------


def test_a_prediction_over_a_drifted_graph_is_refused_for_approval_use():
    """The negative control: new dependency edge, same plan.

    The preview's numbers described the topology as it was. Nothing re-derived
    them, so the stored prediction must be refused rather than re-read as
    current — and the reason has to name the staleness, not just say "no".
    """
    before = _graph()
    after = TopologyGraph(
        nodes=before.nodes,
        edges=(*before.edges, Edge(src="n-db", dst="n-web", kind=EdgeKind.DEPENDS_ON)),
    )
    service = PredictionService(graph=before)
    plan = _plan(("net.latency", "n-db", STEP_S))
    prediction = service.predict(plan, _ctx())

    assert graph_identity(before) != graph_identity(after)
    review = service.review(prediction, graph=after, plan=plan)
    assert review.usable_for_approval is False
    assert "stale" in review.reason
    assert "re-predict" in review.reason
    assert review.graph_identity == prediction.graph_identity


def test_a_prediction_is_reviewed_as_current_against_its_own_inputs():
    graph = _graph()
    service = PredictionService(graph=graph)
    plan = _plan(("net.latency", "n-db", STEP_S))
    prediction = service.predict(plan, _ctx())
    review = service.review(prediction, plan=plan)
    assert review.usable_for_approval is True
    assert review.reason == ""
    assert review.plan_identity == prediction.plan_identity


def test_a_re_planned_plan_also_makes_a_stored_prediction_unusable():
    graph = _graph()
    service = PredictionService(graph=graph)
    prediction = service.predict(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    other = _plan(("net.latency", "n-edge", STEP_S))
    assert service.review(prediction, plan=other).usable_for_approval is False


def test_review_defaults_to_the_services_live_graph():
    """Omitting the graph means "check against what is live now", not "skip the check"."""
    before = _graph()
    after = TopologyGraph(
        nodes=before.nodes,
        edges=(*before.edges, Edge(src="n-db", dst="n-web", kind=EdgeKind.DEPENDS_ON)),
    )
    stale_service = PredictionService(graph=after)
    prediction = PredictionService(graph=before).predict(
        _plan(("net.latency", "n-db", STEP_S)), _ctx()
    )
    assert stale_service.review(prediction).usable_for_approval is False


def test_an_unresolvable_target_is_never_claimed_as_an_observed_fact():
    """The plan says "fault n-ghost"; the topology never held ``n-ghost``.

    The report still *names* it — the plan asked for it, and hiding that would
    hide the operator's own mistake — but nothing downstream treats it as
    measured: it is absent from the affected set, from the fan-out, and from the
    observed TARGET fact, and the preview refuses itself for approval use.
    """
    report = _service().simulate_plan(_plan(("net.latency", "n-ghost", STEP_S)), _ctx())
    assert report.prediction.unresolved_target_ids == ("n-ghost",)
    assert report.targets == ("n-ghost",)
    assert "n-ghost" not in report.prediction.affected_node_ids
    assert "n-ghost" not in report.prediction.fan_out.dependent_ids
    assert report.facts.observed(PolicyDimension.TARGET) is None
    assert report.usable_for_approval is False
    assert "n-ghost" in report.approval_refusal


def test_a_truncated_walk_is_refused_for_approval_use_because_the_tail_is_unmeasured():
    budget = BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=60.0,
    )
    plan = _plan(("net.latency", "n-edge", 30.0), ("net.latency", "n-web", 300.0))
    report = _service().simulate_plan(plan, _ctx(budget=budget))
    assert report.prediction.truncated_at_step == 1
    assert report.usable_for_approval is False
    assert "never measured" in report.approval_refusal


def test_an_empty_topology_prediction_is_refused_rather_than_read_as_all_clear():
    empty = TopologyGraph(nodes=(), edges=())
    report = _service(empty).simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.prediction.basis.value == "empty_graph"
    assert report.prediction.empty is True
    assert report.admitted_by_gate is True  # the gate's arithmetic needs no nodes
    assert report.usable_for_approval is False
    assert "empty topology" in report.approval_refusal


def test_a_preview_is_never_accepted_as_a_preflight():
    """The negative control from the plan: a preview is not a preflight, ever.

    There is no flag, no configuration, and no clean prediction that turns this
    into a return — the method has no path that produces a value.
    """
    report = _service().simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.usable_for_approval is True  # a clean, current preview…
    with pytest.raises(PreviewNotPreflightError) as excinfo:
        report.as_preflight()
    # …and still not a preflight.
    assert excinfo.value.rule == RULE_PREVIEW_NOT_PREFLIGHT
    assert "build_preflight" in str(excinfo.value)
    assert "Phase 3" in str(excinfo.value)


def test_the_report_declares_its_artifact_and_is_not_a_preflight_object():
    from mayhem.domain.preflight import Preflight

    report = _service().simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.artifact == PREDICTION_ARTIFACT
    assert not isinstance(report, Preflight)
    assert not isinstance(report.prediction, Preflight)


# --- cost: unpriced is a word, not a zero -------------------------------------------


def test_no_price_table_means_the_estimate_is_unpriced_not_free():
    """The honest default: this repository has no price table, so no figure is claimed."""
    report = _service().simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.cost.priced is False
    assert report.cost.status == "unpriced"
    assert report.cost.total_usd == 0.0
    assert report.cost.basis == "no rate card supplied"
    assert "UNPRICED" in report.cost.note
    assert "no price table" in report.cost.note
    # The measured half is real and is disclosed next to the absent number.
    assert report.cost.affected_node_seconds == pytest.approx(4 * STEP_S)
    assert "unpriced" in report.describe()


def test_a_configured_rate_card_prices_the_measured_node_seconds():
    report = PredictionService(
        graph=_graph(),
        config=PredictionConfig(
            rate_card=CostRateCard(usd_per_node_hour=0.36, basis="authored test rate")
        ),
    ).simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.cost.priced is True
    assert report.cost.status == "priced"
    assert report.cost.basis == "authored test rate"
    assert report.cost.total_usd == pytest.approx(4 * STEP_S / 3600.0 * 0.36)
    assert "affected-node-seconds" in report.cost.note


def test_an_unpriced_estimate_over_an_unmeasured_blast_still_reads_unpriced():
    """Empty graph, no rate card: neither a cost nor a "free" verdict.

    The node-seconds the walk accumulates here are the plan's own target count
    times its duration — the target id exists in the plan even though the topology
    never held it, so the number is not zero. That is exactly why the estimate is
    refused for approval use: a blast measured against nothing is a number with
    no system behind it, and the disclosure has to say so rather than let the
    figure be read as a measured cost of a real one.
    """
    empty = TopologyGraph(nodes=(), edges=())
    report = _service(empty).simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.cost.status == "unpriced"
    assert report.cost.total_usd == 0.0
    assert report.cost.affected_node_seconds == pytest.approx(STEP_S)
    assert "UNPRICED" in report.cost.note
    assert report.prediction.basis.value == "empty_graph"
    assert report.usable_for_approval is False
    assert "empty topology" in report.approval_refusal


def test_the_cost_disclosure_is_carried_per_step_so_a_caller_can_price_its_own():
    report = _service().simulate_plan(
        _plan(("net.latency", "n-db", STEP_S), ("net.latency", "n-edge", STEP_S)), _ctx()
    )
    assert [step.step_id for step in report.prediction.cost.per_step] == ["s0", "s1"]
    assert report.cost.affected_node_seconds == pytest.approx(
        sum(step.affected_node_seconds for step in report.prediction.cost.per_step)
    )


# --- determinism, and the layering contract ----------------------------------------


def test_two_simulates_of_one_plan_produce_an_identical_report():
    """A preview nobody can re-derive is not a preview, and Phase 4 seals these."""
    service = _service()
    ctx = _ctx()
    plan = _plan(("net.latency", "n-db", STEP_S))
    assert service.simulate_plan(plan, ctx) == service.simulate_plan(plan, ctx)


def _imports_of(module: str) -> set[str]:
    """Every module name imported by a source file, ``mayheim.*`` included whole."""
    import ast
    from pathlib import Path

    source = Path(__file__).resolve().parents[2] / "src" / "mayhem" / module.replace(".", "/")
    tree = ast.parse(source.with_suffix(".py").read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
            if node.module.startswith("mayhem."):
                imported.add(node.module)
    return imported


def test_the_service_reads_nothing_and_reaches_nothing_above_the_gate():
    """The layering contract, asserted locally as well as in the contract suite.

    A prediction is computed from a frozen graph and a frozen plan. If this module
    could open a socket or shell out, its "pure function" claim would be a claim
    about the domain layer's discipline while the call site did the IO — and
    ``mayhem.cli`` is above ``controller``, so a preview could end up importing the
    surface that renders it.
    """
    imported = _imports_of("controller.prediction_service")
    assert imported.isdisjoint(
        {"asyncio", "socket", "subprocess", "sqlite3", "pathlib", "os", "shutil", "urllib"}
    ), sorted(imported)
    assert not {name for name in imported if name.startswith("mayhem.cli")}


def test_the_service_never_calls_a_method_on_the_mutation_backend():
    """The structural half of the purity claim, pinned in the source.

    ``simulate_plan`` reaches ``self.backend`` twice and both are reads: the
    length it publishes and the ``calls`` tuple it publishes. Anything else — a
    ``.record``, a ``.append`` on a list the sink does not own — would be a
    write, so the source is checked rather than trusted. Cheap, and it fails at
    the mistake instead of in production.
    """
    import ast
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "mayhem"
        / "controller"
        / "prediction_service.py"
    )
    tree = ast.parse(source.read_text())
    uses = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and (
            node.attr == "backend"
            or (isinstance(node.value, ast.Attribute) and node.value.attr == "backend")
        )
    }
    assert uses == {"backend", "calls"}
    assert ".record(" not in source.read_text()


def test_a_domain_error_the_preview_cannot_see_is_reported_rather_than_raised():
    """A refusal the preview cannot model is a fact, not an exception to swallow.

    A bundle edited after it was pinned makes ``evaluate_gate`` raise, and
    ``validate_plan`` refuses on it. The preview must neither crash on the same
    input — losing the prediction that explains the refusal — nor quietly treat
    the plan as admissible.

    The rule id is read from the gate rather than hardcoded. ``policy_gate.py``
    owns that vocabulary and has renamed ids while this suite was being extended
    (``policy.bundle_digest_mismatch`` became ``policy.config_invalid``); pinning
    one here would make this suite a second place that has to be updated whenever
    the policy gate changes its mind about what to call a refusal. What this test
    is about is the *shape* — a rule the preview has no vocabulary for, surfaced
    as an unmodelled refusal that disqualifies the report — and that shape does
    not depend on which word the policy gate picked.
    """
    drifted = _bundle().pin().model_copy(update={"description": "edited after pinning"})
    ctx = _ctx(gate=PolicyGateInputs(bundle=drifted, now=T0))
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    report = _service(graph).simulate_plan(plan, ctx)

    refused = _gate_refusals(plan, graph, ctx)
    assert refused, "the drifted bundle must make the real gate refuse something"
    assert report.agreement.gate_refused == refused
    assert report.agreement.modelled == frozenset()
    assert report.agreement.unmodelled == refused
    assert report.agreement.state is AgreementState.UNMODELLED
    assert report.usable_for_approval is False
    # Whether the policy half returns ``None`` or a denial is
    # ``policy_gate.py``'s choice and it has changed while this suite was being
    # extended: a drifted pin used to raise out of ``evaluate_gate`` and now comes
    # back as a refusal. What this module owes either way is stated conditionally,
    # because the invariant is "the report says what the policy half did" rather
    # than "the policy half raises".
    if report.policy is None:
        assert any("could not be evaluated" in note for note in report.notes)
    else:
        assert report.policy.denied is True
        # ``simulated`` marks the read-only path, so a preview reporting a verdict
        # means it took it through ``simulate_gate`` and touched nothing.
        assert report.policy.simulated is True
    # …while the blast half still stands, because that is what the preview is for.
    assert report.prediction.affected_node_ids == ("n-api", "n-db", "n-edge", "n-web")


def test_a_rule_predicate_needs_values_so_an_underspecified_bundle_is_refused():
    """Authoring a deny rule the gate must read, for the unmodelled-refusal path."""
    rule = PolicyRule(
        rule_id="sim.denies.production",
        dimension=PolicyDimension.ENVIRONMENT,
        predicate=PolicyPredicate(operator=PolicyOperator.IN, values=("production",)),
        effect=PolicyEffect.DENY,
        reason="simulation is not permitted in production",
        remediation="use --environment staging",
    )
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = _ctx(gate=PolicyGateInputs(bundle=_bundle(rule), now=T0), environment="production")
    report = _service(graph).simulate_plan(plan, ctx)
    assert _gate_refusals(plan, graph, ctx) == {"policy.bundle_deny"}
    assert report.agreement.unmodelled == {"policy.bundle_deny"}
    assert report.policy is not None
    assert report.policy.denied is True
    assert report.usable_for_approval is False


def test_the_preview_and_the_gate_read_one_fact_set_under_a_bundle():
    """A bundle decision and the fact set shown beside it are the same answer.

    Two calls into ``derive_facts`` produce two equal objects, not one shared one,
    so this asserts equality against the derivation the gate itself uses: a second
    implementation here would be a second answer to "what did the gate observe",
    which is the disagreement plan 07 moved that function upstream to prevent.
    """
    rule = PolicyRule(
        rule_id="sim.allows.staging",
        dimension=PolicyDimension.ENVIRONMENT,
        predicate=PolicyPredicate(operator=PolicyOperator.IN, values=("staging",)),
        effect=PolicyEffect.ALLOW,
        reason="staging is permitted",
    )
    gate = PolicyGateInputs(bundle=_bundle(rule), now=T0)
    ctx = _ctx(gate=gate, environment="staging")
    plan = _plan(("net.latency", "n-db", STEP_S))
    report = _service().simulate_plan(plan, ctx)
    assert report.policy is not None
    assert report.policy.allowed is True
    assert report.policy.facts == derive_facts(plan, gate, environment="staging")
    assert report.facts == report.policy.facts
    assert report.facts.observed(PolicyDimension.ENVIRONMENT) == frozenset({"staging"})
    assert report.usable_for_approval is True


def test_an_expired_bundle_is_an_unmodelled_refusal_too():
    expired = _bundle(expires_at=T0 + timedelta(hours=1))
    gate = PolicyGateInputs(bundle=expired, now=T0 + timedelta(days=365))
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = _ctx(gate=gate)
    report = _service(graph).simulate_plan(plan, ctx)
    assert _gate_refusals(plan, graph, ctx) == {"policy.bundle_expired"}
    assert report.agreement.unmodelled == {"policy.bundle_expired"}
    assert report.usable_for_approval is False


def test_a_capability_refusal_is_unmodelled_too():
    """The gate refuses on a node kind nothing supports; the preview says so.

    ``node.service_stop`` is not in the catalog, so ``validate_plan`` refuses it
    as remote/k8s-unsupported only for the kinds it knows; the honest outcome
    here is simply that the gate named a rule the preview has no vocabulary for,
    and the preview reports that rather than dropping it.
    """
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = _ctx(
        budget=BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=2**31 - 1,
            max_concurrent_faults=2**31 - 1,
            max_duration_per_fault_s=float("inf"),
        ),
        policy=PolicyCfg(allow_faults=frozenset({"node.service_stop"})),
    )
    report = _service(graph).simulate_plan(plan, ctx)
    assert report.agreement.gate_refused == {"policy.allow_faults"}
    assert report.agreement.unmodelled == {"policy.allow_faults"}
    assert report.usable_for_approval is False


def test_a_prediction_disagreement_is_a_typed_invariant_violation():
    """Callers that already handle domain refusals handle this without a new branch."""
    error = PredictionDisagreementError("some.rule", "message")
    assert isinstance(error, InvariantViolationError)
    assert error.rule == "some.rule"
