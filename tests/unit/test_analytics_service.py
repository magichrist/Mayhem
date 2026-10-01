"""The analysis service, causal chains, and the adaptive runner — plan 15 Phase 2.

The tests are arranged around the four things this phase claims, plus the negative
controls the plan itself names. Each group has a test that fails if the property
stops being true, rather than a smoke test that would pass on a weaker
implementation.

* **Boundary on a planted surface.** The search is walked against a simulated
  response surface with a known break point, and the report is asserted to bracket
  *that* point — plus the honesty case: a boundary whose capture could not be
  graded produces a bracket and a confidence statement that says so, never an
  invented interval on the boundary value.
* **Recovery curves.** A curve that comes back, one that does not, one with no
  post-fault samples, and one whose baseline is too short. The last two are the
  interesting ones: neither may read as recovered.
* **Causal chains (gap 53).** A fully cited chain, the digest of every citation
  recomputed from the record it names (so a mutated trial breaks the chain rather
  than silently keeping a stale citation), and the negative control — a claim
  over a missing edge is **withheld**, not guessed.
* **Adaptive runner.** Every step goes through admission; the budget is checked and
  charged per step; budget exhaustion halts with the boundary preserved rather than
  discarding it; and an approval that does not bind is refused.
* **Stages (gaps 90, 91).** One experiment compiles to the plan's ladder, each
  stage is a distinct plan-level construct of that experiment, promotion requires
  SLO health, and an unhealthy SLO stops the ladder — including the "no observation
  at all" case, which is not healthy.
* **The AI boundary (gap 25).** A draft with an embedded approval token is
  rejected at compilation, a compiled candidate reaches policy evaluation only
  through the compiler, and the runner refuses to execute a plan that is not
  approved.

Fixtures are fixed lists and fixed graphs, never generated: a statistic or a
boundary test that depended on a seed would be a test of the seed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest

from mayhem.controller.analytics_service import (
    CANARY_LADDER,
    MAX_CERTIFIABLE_COMPONENTS,
    RULE_ADMISSION_REFUSED,
    RULE_CAUSAL_NO_IMPACT,
    RULE_CAUSAL_NOT_CUSTOMER_FACING,
    RULE_CAUSAL_TARGET_NOT_IN_GRAPH,
    RULE_CITATION_NOT_A_DIGEST,
    RULE_DRAFT_BUDGET_REFERENCE_MISMATCH,
    RULE_DRAFT_CARRIES_AUTHORITY,
    RULE_DRAFT_STEP_COST_MISMATCH,
    RULE_DRAFT_UNKNOWN_FIELD,
    RULE_DRAFT_VALUE_OUT_OF_LADDER,
    RULE_HOP_UNSUPPORTED,
    RULE_HOP_WITHOUT_EDGE,
    RULE_LADDER_NOT_INCREASING,
    RULE_NO_TARGETS,
    RULE_STAGE_NO_CRITERIA,
    RULE_STAGE_NOT_HEALTHY,
    RULE_STEP_NOT_APPROVED,
    RULE_STEP_UNAFFORDABLE,
    AdaptiveRun,
    CausalChain,
    CausalClaimRequest,
    CausalHop,
    CausalStep,
    CitationKind,
    CustomerImpactCheck,
    EdgeCitation,
    FailureCase,
    MetricChange,
    ObservationCitation,
    Promotion,
    Stage,
    StepOutcome,
    adaptive_run,
    analyze_run,
    boundary_report,
    causal_chains,
    compile_candidate,
    compile_stages,
    dependency_path,
    evaluate_stage,
    minimal_failure_case,
    promote_to,
    recovery_curve,
    run_progressive,
    stage_ladder,
    step_affordable,
)
from mayhem.domain.analytics import Comparison, compare
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
    Wait,
)
from mayhem.domain.hashing import digest
from mayhem.domain.observations import (
    CriterionKind,
    CriterionOperator,
    ObservationResult,
    SloCriterion,
)
from mayhem.domain.search import (
    RULE_APPROVAL_MISMATCH,
    RULE_GENERATED_CANNOT_BE_APPROVED,
    Approval,
    BudgetKind,
    BudgetReference,
    SearchHistory,
    SearchOrigin,
    SearchPhase,
    SearchPlan,
    SearchPolicy,
    SearchStep,
    StopReason,
    Trial,
    plan_next_step,
)
from mayhem.domain.steady_state import Tolerance, Verdict
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    PortBinding,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

FP = "f" * 64
QUOTA = BudgetReference(kind=BudgetKind.DAMAGE_SECONDS, label="run-99/damage-quota")
OTHER_QUOTA = BudgetReference(kind=BudgetKind.WALL_CLOCK_SECONDS, label="run-99/clock")
COMBINATION = "checkout/latency-injection"

# The planted surface: anything at or above this impairment breaks the service.
PLANTED_BOUNDARY = 8.0


# =======================================================================================
# Fixtures
# =======================================================================================


def breaches(value: float) -> bool:
    """The simulated response surface."""
    return value >= PLANTED_BOUNDARY


def policy(**overrides: Any) -> SearchPolicy:
    """A search policy over the planted surface's budget and ladder."""
    kwargs: dict[str, Any] = {
        "start": 1.0,
        "step": 3.0,
        "budget_ref": QUOTA,
        "combination_budget": 4,
        "max_steps": 12,
        "resolution": 0.25,
    }
    kwargs.update(overrides)
    return SearchPolicy(**kwargs)


def walk(
    search: SearchPolicy,
    *,
    surface: Any = breaches,
    remaining: float = 500.0,
) -> SearchHistory:
    """Walk a search to its stop against a simulated surface."""
    history = SearchHistory()
    budget = search.budget(remaining)
    for _ in range(search.max_steps * 4):
        decision = plan_next_step(search, history, budget=budget, combination=COMBINATION)
        if not decision.proceed:
            return history
        step = decision.step
        assert step is not None
        history = history.record(step, breached=surface(step.value))
        budget = budget.charge(step.expected_cost)
    raise AssertionError("the search never stopped")


def step(index: int, value: float, *, phase: SearchPhase = SearchPhase.ESCALATION) -> SearchStep:
    return SearchStep(
        index=index,
        value=value,
        phase=phase,
        combination=COMBINATION,
        budget_remaining=100.0,
        budget_ref=QUOTA,
        expected_cost=1.0,
    )


def graph() -> TopologyGraph:
    """``checkout`` depends on ``postgres``; ``checkout`` is the customer-facing door.

    ``postgres`` is not customer facing — it exposes no port — so it can be the
    dependency hop of a chain but never its customer-impact hop.
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(
                id="n-checkout",
                name="checkout",
                exposed_ports=(PortBinding(host_port=8080, container_port=8080),),
            ),
            ServiceNode(id="n-postgres", name="postgres"),
            ServiceNode(id="n-search", name="search"),
        ),
        edges=(
            Edge(src="n-checkout", dst="n-postgres", kind=EdgeKind.DEPENDS_ON),
        ),
    )


def _samples(base: float, spread: float, count: int = 8) -> list[float]:
    """A fixed alternating series around ``base`` — no RNG anywhere in this file."""
    offsets = (0.0, spread, -spread, spread * 0.5, -spread * 0.5, spread * 0.8, -spread * 0.8, 0.2)
    return [base + offsets[index % len(offsets)] for index in range(count)]


CALM = _samples(500.0, 8.0)
DEGRADED = _samples(900.0, 12.0)
SETTLED = _samples(500.0, 6.0)
STILL_HOT = _samples(880.0, 10.0)


def material_comparison(name: str = "checkout-latency") -> Comparison:
    return compare(CALM, DEGRADED, name=name, percentile=99.0, materiality_pct=10.0)


def quiet_comparison(name: str = "checkout-latency") -> Comparison:
    """A graded comparison whose movement is inside the materiality floor."""
    return compare(
        _samples(500.0, 8.0),
        _samples(510.0, 8.0),
        name=name,
        percentile=99.0,
        materiality_pct=10.0,
    )


def slo(threshold: float = 500.0) -> SloCriterion:
    return SloCriterion(
        kind=CriterionKind.LATENCY,
        metric="checkout-p99",
        operator=CriterionOperator.LT,
        threshold=threshold,
        unit="ms",
    )


def observation(value: float, *, metric: str = "checkout-p99") -> ObservationResult:
    return ObservationResult(metric=metric, value=value, unit="ms", window_s=60.0)


def trial(breached: bool = True) -> Trial:
    return Trial(step=step(0, 10.0), breached=breached)


def full_chain(**overrides: Any) -> CausalChain:
    """A chain whose every hop is cited — built through the same constructors the
    builder uses, so a test cannot pass on a shape the builder never produces."""
    hops = (
        CausalStep(
            hop=CausalHop.FAULT_TO_TARGET,
            src="net.latency",
            dst="n-checkout",
            observations=(
                ObservationCitation(
                    kind=CitationKind.TRIAL,
                    ref=digest(trial().to_dict()),
                    detail="trial 0",
                ),
            ),
        ),
        CausalStep(
            hop=CausalHop.TARGET_TO_DEPENDENCY,
            src="n-checkout",
            dst="n-postgres",
            edges=(EdgeCitation(src="n-checkout", dst="n-postgres", kind=EdgeKind.DEPENDS_ON),),
        ),
        CausalStep(
            hop=CausalHop.DEPENDENCY_TO_METRIC,
            src="n-postgres",
            dst="checkout-latency",
            observations=(
                ObservationCitation(
                    kind=CitationKind.METRIC,
                    ref=digest(material_comparison().to_dict()),
                ),
            ),
        ),
        CausalStep(
            hop=CausalHop.METRIC_TO_CUSTOMER,
            src="checkout-latency",
            dst="n-checkout",
            observations=(
                ObservationCitation(kind=CitationKind.SLO, ref=digest({"impact": "checkout"})),
            ),
        ),
    )
    return CausalChain(fault_id="net.latency", hops=overrides.get("hops", hops))


def request(
    *,
    fault_id: str = "net.latency",
    targets: tuple[str, ...] = ("n-checkout",),
    dependencies: tuple[str, ...] = ("n-postgres",),
    changes: tuple[MetricChange, ...] | None = None,
    impacts: tuple[CustomerImpactCheck, ...] | None = None,
    executed: Trial | None = None,
) -> CausalClaimRequest:
    return CausalClaimRequest(
        fault_id=fault_id,
        target_ids=targets,
        dependency_ids=dependencies,
        trial=trial() if executed is None else executed,
        metric_changes=(
            (MetricChange(node_id="n-postgres", comparison=material_comparison()),)
            if changes is None
            else changes
        ),
        customer_impacts=(
            (
                CustomerImpactCheck(
                    node_id="n-checkout", criterion=slo(), observation=observation(910.0)
                ),
            )
            if impacts is None
            else impacts
        ),
    )


def experiment(
    target_ids: Sequence[str] = ("n-postgres",), *, run_id: str = "r-canary"
) -> ExecutionPlan:
    """One compiled plan, faulting every named node in a single step."""
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="postgres")
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=(
            PlannedStep(
                id="s0",
                seq=0,
                raw_action=InjectFault(
                    fault="db.slow_query", selectors=(selector,), duration=30.0
                ),
                fault=PlannedFault(
                    fault_id="db.slow_query",
                    targets=(
                        ResolvedTarget(
                            selector=selector, node_ids=frozenset(target_ids)
                        ),
                    ),
                    duration=30.0,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )


# =======================================================================================
# Boundary on a planted surface
# =======================================================================================


def test_boundary_report_brackets_the_planted_boundary() -> None:
    """The planted surface breaks at exactly 8.0. A bisecting search does not land
    on it — it brackets it, which is the honest result: the bracket must contain
    the planted point, with the clearing value below and the breaching value above.
    Asserting equality with the planted point would be asserting a precision the
    search never had."""
    search = policy()
    history = walk(search)

    report = boundary_report(search, history)

    assert report.bracket_low < PLANTED_BOUNDARY <= report.boundary  # type: ignore[operator]
    assert report.resolved is True
    assert (report.boundary - report.bracket_low) <= search.resolution
    assert report.trials == history.steps_used
    assert "NOT RESOLVED" not in report.tolerance_statement
    assert report.note == ""
    # The bracket is a bracket: nothing is claimed between the clearing value and
    # the boundary other than the interval itself.
    assert report.bracket_high == report.boundary


def test_boundary_confidence_quotes_the_metric_and_never_an_interval_on_the_boundary() -> None:
    """The honest form of "with confidence": what the metric did, not a band on
    the boundary value. Nothing here estimates one, so the statement must not
    invent one."""
    search = policy()
    history = walk(search)
    assert history.boundary is not None
    boundary_index = next(
        record.step.index
        for record in history.trials
        if record.breached and record.step.value == history.boundary
    )

    report = boundary_report(search, history, {boundary_index: material_comparison()})

    assert report.boundary_comparison is not None
    statement = report.confidence_statement
    assert statement.startswith(f"at the boundary {history.boundary:g}")
    assert "MATERIAL" in statement
    assert "not an interval on the boundary value itself" in statement


def test_boundary_without_a_graded_capture_says_it_has_no_evidence() -> None:
    search = policy()
    history = walk(search)

    report = boundary_report(search, history, {})

    assert report.boundary == history.boundary
    assert report.boundary_comparison is None
    assert report.confidence_statement.startswith("no comparison was recorded")


def test_boundary_says_how_far_the_search_went_when_nothing_broke() -> None:
    search = policy()
    history = walk(search, surface=lambda value: False)

    report = boundary_report(search, history)

    assert report.boundary is None
    assert report.resolved is False
    assert "no impairment in this search crossed the declared tolerance" in (
        report.tolerance_statement
    )
    assert report.highest_tried is not None
    assert "not where the boundary is" in report.note


def test_an_unresolved_bracket_is_reported_as_a_bracket_not_a_number() -> None:
    """A declared resolution the search could not meet: the boundary is reported as
    the interval it is, and the statement says the resolution was not reached
    rather than quoting a midpoint."""
    search = policy(resolution=0.0)
    history = walk(search, surface=lambda value: value >= 20.0)

    report = boundary_report(search, history)

    assert report.boundary is not None
    assert report.boundary >= 20.0
    assert report.bracket_low < 20.0
    assert report.resolved is False
    assert "NOT RESOLVED" in report.tolerance_statement
    assert "reported as a bracket" in report.note


def test_insufficient_trials_are_named_and_excluded_from_the_bracket() -> None:
    search = policy()
    history = SearchHistory()
    history = history.record(step(0, 4.0), breached=False)
    history = history.record(step(1, 8.0), breached=True, sufficient=False)

    report = boundary_report(search, history)

    assert report.insufficient_trials == (1,)
    # The breach still stands — the search recorded it — but the unmeasurable
    # trial is disclosed rather than being treated as a clearance below it.
    assert report.bracket_low == 4.0


def test_boundary_report_serialises_without_inventing_numbers() -> None:
    report = boundary_report(policy(), walk(policy()))

    payload = report.to_dict()

    assert payload["boundary"] == report.boundary
    assert payload["boundary_comparison"] is None
    assert payload["tolerance_statement"] == report.tolerance_statement
    assert payload["confidence_statement"] == report.confidence_statement


# =======================================================================================
# Recovery curves
# =======================================================================================


def test_recovery_curve_reports_where_the_signal_came_back() -> None:
    curve = recovery_curve(
        name="checkout-p99",
        baseline_values=CALM,
        cooldown_values=[880.0, 700.0, 620.0, 505.0, 501.0, 499.0, 508.0, 502.0],
        tolerance=Tolerance(at_most=550.0),
    )

    assert curve.graded is True
    assert curve.recovered is True
    assert curve.recovered_at_index == 3
    assert curve.verdict is Verdict.AS_HYPOTHESISED
    assert curve.curve == (880.0, 700.0, 620.0, 505.0, 501.0, 499.0, 508.0, 502.0)
    assert "RECOVERED" in curve.statement


def test_a_signal_that_never_comes_back_is_not_recovered() -> None:
    curve = recovery_curve(
        name="checkout-p99",
        baseline_values=CALM,
        cooldown_values=STILL_HOT,
        tolerance=Tolerance(at_most=550.0),
    )

    assert curve.recovered is False
    assert curve.verdict is Verdict.NOT_RECOVERED
    assert curve.recovered_at_index is None
    assert "NOT RECOVERED" in curve.statement
    assert curve.residual_pct is not None and curve.residual_pct > 50.0


def test_an_empty_recovery_curve_is_not_a_recovery() -> None:
    """No post-fault samples is the residue this tool exists to surface. It may not
    be graded as clean, and it may not be graded at all."""
    curve = recovery_curve(
        name="checkout-p99",
        baseline_values=CALM,
        cooldown_values=[],
        tolerance=Tolerance(at_most=550.0),
    )

    assert curve.points == ()
    assert curve.recovered is False
    assert curve.graded is False
    assert curve.verdict is None
    assert "not observed" in curve.statement
    assert "empty recovery curve is not a recovery" in curve.note


def test_an_under_sampled_baseline_leaves_recovery_ungraded() -> None:
    curve = recovery_curve(
        name="checkout-p99",
        baseline_values=[500.0, 501.0],
        cooldown_values=SETTLED,
        tolerance=Tolerance(at_most=550.0),
    )

    assert curve.graded is False
    assert curve.verdict is None
    assert curve.points == ()
    # The refusal names the two counts and the floor, so a reader can see exactly
    # what was short rather than being told "insufficient".
    assert "compared on 2 baseline / 8 window samples" in curve.note
    assert "required minimum of 5/5" in curve.note


def test_recovery_curve_carries_the_comparison_it_was_graded_against() -> None:
    curve = recovery_curve(
        name="checkout-p99",
        baseline_values=CALM,
        cooldown_values=SETTLED,
        tolerance=Tolerance(at_most=550.0),
        materiality_pct=10.0,
    )

    assert curve.comparison is not None
    assert curve.comparison.name == "checkout-p99"
    assert curve.comparison.graded is True
    # The cooldown series matches the baseline, so the comparison says so.
    assert curve.comparison.material is False


# =======================================================================================
# Causal chains (gap 53)
# =======================================================================================


def test_a_fully_cited_chain_is_produced_when_the_evidence_is_there() -> None:
    analysis = causal_chains(graph(), request())

    assert analysis.complete is True
    assert analysis.withheld == ()
    assert len(analysis.claims) == 1
    chain = analysis.claims[0]
    assert chain.fault_id == "net.latency"
    assert chain.target_id == "n-checkout"
    assert chain.dependency_id == "n-postgres"
    assert chain.metric == "checkout-latency"
    assert chain.customer_node_id == "n-checkout"
    edges, observations = chain.citation_counts()
    assert edges == 2  # checkout→postgres and postgres→checkout path back to the door
    assert observations == 3  # trial, metric comparison, SLO failure


def test_every_citation_is_the_digest_of_the_record_it_names() -> None:
    analysis = causal_chains(graph(), request())
    chain = analysis.claims[0]

    cited = {citation.ref for citation in chain.observations}
    assert digest(trial().to_dict()) in cited
    assert digest(material_comparison().to_dict()) in cited
    # Every edge citation is a real edge in the graph it was computed over.
    real = {
        f"{edge.kind.value}:{edge.src}->{edge.dst}" for edge in graph().edges
    }
    assert all(edge.key() in real for edge in chain.edges)


def test_a_citation_that_is_not_a_digest_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        ObservationCitation(kind=CitationKind.TRIAL, ref="the-third-trial-looked-bad")

    assert caught.value.rule == RULE_CITATION_NOT_A_DIGEST
    assert "a typed-in reference is not evidence" in str(caught.value)


def test_a_hop_with_no_evidence_cannot_be_constructed() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        CausalStep(hop=CausalHop.DEPENDENCY_TO_METRIC, src="n-postgres", dst="p99")

    assert caught.value.rule == RULE_HOP_UNSUPPORTED
    assert "cites neither an observation nor a topology edge" in str(caught.value)


def test_the_dependency_hop_needs_a_real_edge() -> None:
    """A metric moving is not evidence that a dependency exists."""
    with pytest.raises(InvariantViolationError) as caught:
        CausalStep(
            hop=CausalHop.TARGET_TO_DEPENDENCY,
            src="n-checkout",
            dst="n-postgres",
            observations=(
                ObservationCitation(kind=CitationKind.METRIC, ref=digest({"x": 1})),
            ),
        )

    assert caught.value.rule == RULE_HOP_WITHOUT_EDGE
    assert "must name the edge that makes it true" in str(caught.value)


def test_a_chain_missing_a_hop_cannot_be_constructed() -> None:
    chain = full_chain()
    with pytest.raises(InvariantViolationError) as caught:
        CausalChain(fault_id="net.latency", hops=chain.hops[:-1])

    assert caught.value.rule == RULE_HOP_UNSUPPORTED
    assert "metric->customer" in str(caught.value)


def test_a_chain_over_a_missing_edge_is_withheld_not_guessed() -> None:
    """The negative control the plan names. ``n-search`` is in the graph but nothing
    depends on it, so the chain has no edge to cite."""
    analysis = causal_chains(graph(), request(dependencies=("n-search",)))

    assert analysis.claims == ()
    assert analysis.complete is False
    assert len(analysis.withheld) == 1
    withheld = analysis.withheld[0]
    assert withheld.rule_id == RULE_HOP_WITHOUT_EDGE
    assert withheld.hop is CausalHop.TARGET_TO_DEPENDENCY
    assert "no dependency path" in withheld.reason
    assert "n-checkout" in withheld.reason and "n-search" in withheld.reason


def test_a_chain_over_a_target_that_is_not_in_the_graph_is_withheld() -> None:
    analysis = causal_chains(graph(), request(targets=("n-ghost",)))

    assert analysis.claims == ()
    assert analysis.withheld[0].rule_id == RULE_CAUSAL_TARGET_NOT_IN_GRAPH
    assert analysis.withheld[0].hop is CausalHop.FAULT_TO_TARGET


def test_a_chain_over_an_ungraded_metric_change_is_withheld() -> None:
    """``NO_MATERIAL_EFFECT`` is a real conclusion and it is *not* a metric change.
    The chain may not assert a movement the comparison refuses to grade."""
    analysis = causal_chains(
        graph(),
        request(
            changes=(
                MetricChange(node_id="n-postgres", comparison=quiet_comparison()),
            )
        ),
    )

    assert analysis.claims == ()
    assert analysis.withheld[0].rule_id == RULE_HOP_UNSUPPORTED
    assert analysis.withheld[0].hop is CausalHop.DEPENDENCY_TO_METRIC
    assert "could not be separated from the noise" in analysis.withheld[0].reason


def test_a_chain_with_no_customer_impact_is_withheld() -> None:
    analysis = causal_chains(graph(), request(impacts=()))

    assert analysis.claims == ()
    assert analysis.withheld[0].rule_id == RULE_CAUSAL_NO_IMPACT
    assert analysis.withheld[0].hop is CausalHop.METRIC_TO_CUSTOMER


def test_an_impact_on_a_node_that_is_not_customer_facing_is_withheld_as_such() -> None:
    """``n-postgres`` can fail an SLO and still not be a *customer* impact — it
    exposes no port. The report must say which of the two reasons applied."""
    analysis = causal_chains(
        graph(),
        request(
            impacts=(
                CustomerImpactCheck(
                    node_id="n-postgres",
                    criterion=slo(),
                    observation=observation(910.0, metric="db-p99"),
                ),
            )
        ),
    )

    assert analysis.claims == ()
    assert analysis.withheld[0].rule_id == RULE_CAUSAL_NOT_CUSTOMER_FACING
    assert "expose no port" in analysis.withheld[0].reason


def test_a_passing_slo_is_not_a_customer_impact() -> None:
    analysis = causal_chains(
        graph(), request(impacts=(CustomerImpactCheck(
            node_id="n-checkout", criterion=slo(), observation=observation(120.0)
        ),))
    )

    assert analysis.claims == ()
    assert analysis.withheld[0].rule_id == RULE_CAUSAL_NO_IMPACT


def test_the_graph_digest_travels_with_the_analysis() -> None:
    """A claim is only meaningful against the snapshot it was computed over."""
    from mayhem.domain.prediction import graph_identity

    analysis = causal_chains(graph(), request())

    assert analysis.graph_digest == graph_identity(graph())


def test_dependency_path_is_a_shortest_path_and_empty_for_unrelated_nodes() -> None:
    assert [edge.key() for edge in dependency_path(graph(), "n-checkout", "n-postgres")] == [
        "depends_on:n-checkout->n-postgres"
    ]
    assert dependency_path(graph(), "n-search", "n-postgres") == ()
    # A node does not depend on itself.
    assert dependency_path(graph(), "n-checkout", "n-checkout") == ()


def test_chains_are_deterministic_across_calls() -> None:
    first = causal_chains(graph(), request())
    second = causal_chains(graph(), request())

    assert first.to_dict() == second.to_dict()


# =======================================================================================
# Minimal failure cases
# =======================================================================================


def test_minimal_failure_case_certifies_minimality_when_every_subset_was_tried() -> None:
    cases = (
        FailureCase(fault_ids=("db.slow_query",), target_ids=(), reproduced=False),
        FailureCase(fault_ids=("db.slow_query",), target_ids=("n-postgres",), reproduced=True),
        FailureCase(
            fault_ids=("db.slow_query", "net.latency"),
            target_ids=("n-postgres",),
            reproduced=True,
        ),
    )

    minimal = minimal_failure_case(cases)

    assert minimal.found is True
    assert minimal.minimal is True
    assert minimal.size == 2
    assert minimal.case is not None
    assert minimal.case.key() == "fault:db.slow_query+target:n-postgres"


def test_an_untried_subset_blocks_the_minimality_claim() -> None:
    cases = (
        FailureCase(fault_ids=("db.slow_query",), target_ids=(), reproduced=False),
        FailureCase(
            fault_ids=("db.slow_query", "net.latency"),
            target_ids=("n-postgres",),
            reproduced=True,
        ),
    )

    minimal = minimal_failure_case(cases)

    assert minimal.minimal is False
    assert "not certified minimal" in minimal.note
    # The single-fault case *was* tried and did not reproduce; the untried subsets
    # are named so a reader knows what is missing.
    assert "fault:net.latency" in minimal.note


def test_an_unmeasurable_trial_is_neither_a_reproduction_nor_a_clearance() -> None:
    """An unmeasurable single-component case must not certify that the two-component
    case is minimal."""
    cases = (
        FailureCase(
            fault_ids=("db.slow_query",),
            target_ids=(),
            reproduced=False,
            sufficient=False,
        ),
        FailureCase(
            fault_ids=("db.slow_query", "net.latency"),
            target_ids=("n-postgres",),
            reproduced=True,
        ),
    )

    minimal = minimal_failure_case(cases)

    assert minimal.considered == 1
    assert minimal.minimal is False


def test_no_reproduction_is_reported_as_the_finding_not_as_a_pass() -> None:
    cases = (
        FailureCase(fault_ids=("db.slow_query",), target_ids=(), reproduced=False),
    )

    minimal = minimal_failure_case(cases)

    assert minimal.found is False
    assert minimal.case is None
    assert "the absence is the finding" in minimal.note


def test_a_very_wide_case_is_not_certified_minimal() -> None:
    wide = tuple(f"fault:f{index}" for index in range(MAX_CERTIFIABLE_COMPONENTS + 1))

    minimal = minimal_failure_case((FailureCase(fault_ids=wide, target_ids=(), reproduced=True),))

    assert minimal.found is True
    assert minimal.minimal is False
    assert "certification ceiling" in minimal.note


def test_minimization_is_deterministic_on_ties() -> None:
    cases = (
        FailureCase(fault_ids=("b.fault",), target_ids=(), reproduced=True),
        FailureCase(fault_ids=("a.fault",), target_ids=(), reproduced=True),
    )

    assert minimal_failure_case(cases).to_dict() == minimal_failure_case(
        tuple(reversed(cases))
    ).to_dict()


# =======================================================================================
# The AI boundary (gap 25) — compilation
# =======================================================================================


def _payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "step": {
            "index": 0,
            "value": 4.0,
            "phase": SearchPhase.ESCALATION.value,
            "combination": COMBINATION,
            "budget_remaining": 100.0,
            "budget_ref": QUOTA.model_dump(mode="json"),
            "expected_cost": 1.0,
        },
        "rationale": "try 4% first",
    }
    payload.update(overrides)
    return payload


def test_a_compiled_candidate_is_the_same_plan_type_with_zero_authority() -> None:
    candidate = compile_candidate(_payload(), policy())

    assert isinstance(candidate, SearchPlan)
    assert candidate.origin is SearchOrigin.GENERATED
    assert candidate.approval is None
    assert candidate.authority.value == "none"
    assert candidate.step.value == 4.0


def test_a_draft_with_an_embedded_approval_token_is_rejected() -> None:
    """The negative control the plan names. The AI may not supply its own
    authority, and the refusal happens in the compiler — upstream of admission,
    policy evaluation, and the runner."""
    payload = _payload(approval={"approved_by": "sre-oncall", "plan_digest": "0" * 64})

    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(payload, policy())

    assert caught.value.rule == RULE_DRAFT_CARRIES_AUTHORITY
    assert "cannot supply its own" in str(caught.value)


def test_a_nested_approval_token_is_rejected_too() -> None:
    """The obvious attack is the nested one, so the scan walks the payload."""
    payload = _payload()
    payload["step"]["approved_by"] = "sre-oncall"  # type: ignore[index]

    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(cast("Mapping[str, object]", payload), policy())

    assert caught.value.rule == RULE_DRAFT_CARRIES_AUTHORITY
    assert "step.approved_by" in str(caught.value)


def test_an_unknown_field_is_refused_rather_than_ignored() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(_payload(priority=0.99), policy())

    assert caught.value.rule == RULE_DRAFT_UNKNOWN_FIELD
    assert "priority" in str(caught.value)


def test_a_candidate_priced_on_another_budget_is_refused() -> None:
    payload = _payload()
    payload["step"]["budget_ref"] = OTHER_QUOTA.model_dump(mode="json")  # type: ignore[index]

    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(cast("Mapping[str, object]", payload), policy())

    assert caught.value.rule == RULE_DRAFT_BUDGET_REFERENCE_MISMATCH


def test_a_candidate_may_not_reprice_the_search() -> None:
    payload = _payload()
    payload["step"]["expected_cost"] = 0.01  # type: ignore[index]

    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(cast("Mapping[str, object]", payload), policy())

    assert caught.value.rule == RULE_DRAFT_STEP_COST_MISMATCH
    assert "may not reprice the search" in str(caught.value)


@pytest.mark.parametrize("value", [-1.0, 0.0, 1e9])
def test_a_candidate_outside_the_ladder_is_refused(value: float) -> None:
    payload = _payload()
    payload["step"]["value"] = value  # type: ignore[index]

    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(cast("Mapping[str, object]", payload), policy())

    assert caught.value.rule == RULE_DRAFT_VALUE_OUT_OF_LADDER


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_candidate_field_is_refused_before_the_ladder_check(value: float) -> None:
    """``nan`` is a field that cannot be a number at all, which is earlier and more
    precise than refusing it as out-of-ladder."""
    payload = _payload()
    payload["step"]["value"] = value  # type: ignore[index]

    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(cast("Mapping[str, object]", payload), policy())

    assert caught.value.rule == RULE_DRAFT_UNKNOWN_FIELD
    assert "must be finite" in str(caught.value)


def test_a_candidate_field_of_the_wrong_type_is_refused() -> None:
    payload = _payload()
    payload["step"]["index"] = True  # type: ignore[index]

    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(cast("Mapping[str, object]", payload), policy())

    assert caught.value.rule == RULE_DRAFT_UNKNOWN_FIELD
    assert "must be an integer" in str(caught.value)


def test_a_candidate_step_with_an_unknown_field_is_refused() -> None:
    payload = _payload()
    payload["step"]["severity"] = "critical"  # type: ignore[index]

    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(cast("Mapping[str, object]", payload), policy())

    assert caught.value.rule == RULE_DRAFT_UNKNOWN_FIELD
    assert "severity" in str(caught.value)


def test_the_runner_will_not_execute_a_step_it_cannot_pay_for() -> None:
    """The runner's own budget predicate, tested directly — including the case it
    exists for, which the ordinary wiring never reaches: a budget the runner is
    spending that the planner did not see."""
    budget = policy().budget(0.5)

    assert step_affordable(budget, step(0, 4.0)) != ""
    assert "0.5 of damage-seconds left" in step_affordable(budget, step(0, 4.0))
    assert "costing 1.0" in step_affordable(budget, step(0, 4.0))
    assert step_affordable(policy().budget(1.0), step(0, 4.0)) == ""
    # The refusal names the numbers it decided on, and the runner records it under
    # its own rule id so an operator reading an admission record can tell "the gate
    # said no" from "the budget said no".
    assert "search halts with the findings so far" in step_affordable(budget, step(0, 4.0))
    assert RULE_STEP_UNAFFORDABLE != RULE_ADMISSION_REFUSED


def test_a_candidate_with_no_step_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate({"rationale": "trust me"}, policy())

    assert caught.value.rule == RULE_DRAFT_UNKNOWN_FIELD


def test_a_failing_candidate_never_reaches_policy_evaluation() -> None:
    """The acceptance criterion in the negative direction: compilation refuses
    *before* anything downstream is asked, so there is no path by which a bad draft
    reaches the gate. Asserted by construction — the only public entry is the
    compiler, and it raises rather than returning."""
    reached = False

    def would_evaluate(_candidate: SearchPlan) -> None:
        nonlocal reached
        reached = True

    with pytest.raises(InvariantViolationError):
        candidate = compile_candidate(_payload(approval={"approved_by": "x"}), policy())
        would_evaluate(candidate)

    assert reached is False


def test_a_compiled_candidate_is_never_constructed_with_an_approval() -> None:
    """The type-level half of the boundary, re-asserted from this module's side:
    the compiler's only output is a ``generated`` plan, and that type refuses an
    approval outright."""
    candidate = compile_candidate(_payload(), policy())
    token = Approval(approved_by="sre", plan_digest=candidate.plan_digest)

    with pytest.raises(InvariantViolationError) as caught:
        SearchPlan(
            step=candidate.step,
            origin=SearchOrigin.GENERATED,
            rationale=candidate.rationale,
            approval=token,
        )

    assert caught.value.rule == RULE_GENERATED_CANNOT_BE_APPROVED


# =======================================================================================
# The adaptive runner
# =======================================================================================


class _Recorder:
    """Records every call the runner makes, in the order it made them.

    A hand-written recorder rather than a mock library: the assertions are about
    *what the runner did and in what order* — approve before admit, admit before
    execute, a refused step never executed — and a reordered loop would fail a
    sequence assertion rather than quietly pass a call-count one.
    """

    def __init__(self, *, surface: Any = breaches) -> None:
        self.surface = surface
        self.calls: list[str] = []
        self.values: list[float] = []
        self.plan = experiment()

    def _note(self, label: str, value: float) -> None:
        self.calls.append(label)
        self.values.append(value)

    def compile_step(self, step: SearchStep) -> ExecutionPlan:
        self._note("compile", step.value)
        return self.plan

    def note(self, label: str, value: float) -> None:
        self.calls.append(label)
        self.values.append(value)

    def default_approve(self, plan: SearchPlan) -> Approval:
        return Approval(approved_by="sre-oncall", plan_digest=plan.plan_digest)

    def default_admit(self, plan: ExecutionPlan) -> None:
        self._note("admit", len(self.values))

    def execute(self, plan: ExecutionPlan, step: SearchStep) -> StepOutcome:
        self._note("execute", step.value)
        return StepOutcome(breached=self.surface(step.value))


def _run(
    search: SearchPolicy,
    *,
    remaining: float = 500.0,
    surface: Any = breaches,
    approve: Any = None,
    admit: Any = None,
    origin: SearchOrigin = SearchOrigin.AUTHORED,
    outcome: Any = None,
    history: SearchHistory | None = None,
) -> tuple[AdaptiveRun, _Recorder]:
    """Walk a search forward with a recorder attached to every collaborator."""
    recorder = _Recorder(surface=surface)

    def note_approval(plan: SearchPlan) -> Approval | None:
        recorder.note("approve", plan.step.value)
        return recorder.default_approve(plan) if approve is None else approve(plan)

    run = adaptive_run(
        search,
        budget=search.budget(remaining),
        compile_step=recorder.compile_step,
        admit=admit if admit is not None else recorder.default_admit,
        execute=outcome if outcome is not None else recorder.execute,
        approve=note_approval,
        origin=origin,
        history=history,
        combination=COMBINATION,
    )
    return run, recorder


def test_the_runner_walks_the_search_to_its_boundary() -> None:
    search = policy()

    run, _ = _run(search)

    assert run.executed > 0
    assert run.executed == sum(1 for admission in run.admissions if admission.admitted)
    assert run.findings_preserved is True
    assert run.report.boundary == run.boundary
    # The planted break point at 8.0 is bracketed, not hit: bisection narrows the
    # interval rather than claiming a precision the search did not have.
    assert run.report.bracket_low < PLANTED_BOUNDARY <= run.boundary  # type: ignore[operator]
    assert run.report.resolved is True
    # The search cleared a value below the boundary before breaching, so the
    # bracket has a lower edge at all.
    assert run.report.bracket_low > 0.0


def test_every_step_is_approved_compiled_admitted_then_executed_in_that_order() -> None:
    """The safety order is the claim, asserted as a sequence rather than as four
    independent call counts: an approval after admission would pass a count check
    and fail this one."""
    search = policy(start=1.0, step=3.0)
    remaining = 9.0  # three steps: clear, clear, breach

    run, recorder = _run(search, remaining=remaining)

    per_step = [
        tuple(recorder.calls[index : index + 4])
        for index in range(0, len(recorder.calls), 4)
    ]
    assert per_step
    assert all(labels == ("approve", "compile", "admit", "execute") for labels in per_step)
    assert run.executed == len(per_step)


def test_admission_refusal_stops_the_run_and_is_recorded() -> None:
    search = policy()
    seen: list[int] = []

    def admit(_plan: ExecutionPlan) -> None:
        seen.append(1)
        if len(seen) == 2:
            raise InvariantViolationError("blast_radius.max_hosts", "too many hosts")

    run, recorder = _run(search, admit=admit)

    assert run.executed == 1
    last = run.admissions[-1]
    assert last.admitted is False
    assert last.rule_id == "blast_radius.max_hosts"
    assert last.charged == 0.0
    assert "admission refused" in run.stop_note
    assert "too many hosts" in run.stop_note
    # The refused step was compiled and offered to the gate, then never executed.
    assert recorder.calls == ["approve", "compile", "execute", "approve", "compile"]


def test_a_refused_admission_costs_no_budget() -> None:
    search = policy()
    seen: list[int] = []

    def admit(_plan: ExecutionPlan) -> None:
        seen.append(1)
        if len(seen) == 2:
            raise InvariantViolationError("blast_radius.max_hosts", "too many hosts")

    run, _ = _run(search, admit=admit)

    assert run.budget_remaining == pytest.approx(500.0 - run.executed)


def test_the_budget_is_checked_and_charged_at_every_step() -> None:
    """Each executed step is charged exactly its cost, and the running total
    decreases monotonically by that amount."""
    search = policy()
    budget = 6.0

    run, _ = _run(search, remaining=budget)

    admitted = [admission for admission in run.admissions if admission.admitted]
    assert [admission.charged for admission in admitted] == [1.0] * len(admitted)
    remaining = [admission.budget_remaining for admission in admitted]
    assert remaining == [budget - float(index + 1) for index in range(len(admitted))]
    assert run.budget_remaining == pytest.approx(remaining[-1])
    assert run.stop is StopReason.NO_REMAINING_BUDGET
    assert len(admitted) == 6


def test_budget_exhaustion_halts_the_search_and_keeps_the_findings() -> None:
    """The acceptance criterion: a search that runs out of budget reports what it
    established rather than discarding it."""
    search = policy()

    run, _ = _run(search, remaining=2.0)

    assert run.stop is StopReason.NO_REMAINING_BUDGET
    assert run.stopped_on_budget is True
    assert run.executed == 2
    assert run.history.steps_used == 2
    assert run.report.trials == 2
    # The stop is the planner's, so the note names the numbers it decided on.
    assert "no remaining damage-seconds budget (0.0)" in run.stop_note
    assert "search halts with the findings so far" in run.stop_note
    # Nothing is thrown away: the history, the bracket, and the report survive.
    assert run.to_dict()["history"]["trials"] != []
    assert run.findings_preserved is True
    assert run.budget_remaining == 0.0


def test_budget_exhaustion_preserves_an_established_boundary() -> None:
    search = policy()

    run, _ = _run(search, remaining=3.0, surface=lambda value: value >= 4.0)

    assert run.stop is StopReason.NO_REMAINING_BUDGET
    assert run.boundary == 4.0
    assert run.report.boundary == 4.0
    assert run.report.to_dict()["findings_preserved" if False else "boundary"] == 4.0


def test_a_step_with_no_approval_is_refused_and_costs_nothing() -> None:
    search = policy()
    calls: list[int] = []

    def approve(plan: SearchPlan) -> Approval | None:
        calls.append(1)
        if len(calls) == 2:
            return None
        return Approval(approved_by="sre-oncall", plan_digest=plan.plan_digest)

    run, recorder = _run(search, approve=approve)

    assert run.executed == 1
    last = run.admissions[-1]
    assert last.admitted is False
    assert last.charged == 0.0
    assert last.approved_by == ""
    assert last.rule_id == RULE_STEP_NOT_APPROVED
    assert "no approval token" in last.reason
    # The refused step was offered for approval and stopped there: no compilation,
    # no gate, no execution.
    assert recorder.calls == ["approve", "compile", "admit", "execute", "approve"]


def test_an_approval_that_does_not_bind_to_the_step_is_refused() -> None:
    search = policy()
    other = Approval(approved_by="sre-oncall", plan_digest="0" * 64)

    run, recorder = _run(search, approve=lambda plan: other)

    assert run.executed == 0
    assert recorder.calls == ["approve"]
    assert run.admissions[-1].rule_id == RULE_STEP_NOT_APPROVED
    assert RULE_APPROVAL_MISMATCH in run.admissions[-1].reason


def test_the_runner_refuses_a_generated_step_it_cannot_approve() -> None:
    """The second half of the AI boundary: handed a candidate origin, the runner
    cannot obtain an approval for it, because the plan type refuses one."""
    search = policy()

    def approve(plan: SearchPlan) -> Approval:
        # A reviewer who "meant well": try to approve the generated plan directly.
        return Approval(approved_by="sre-oncall", plan_digest=plan.plan_digest)

    run, recorder = _run(search, approve=approve, origin=SearchOrigin.GENERATED)

    assert run.executed == 0
    assert recorder.calls == ["approve"]
    assert run.admissions[-1].rule_id == RULE_STEP_NOT_APPROVED
    assert RULE_GENERATED_CANNOT_BE_APPROVED in run.admissions[-1].reason


def test_an_unapproved_step_never_reaches_the_gate() -> None:
    """Approval comes before compilation and admission, so the gate is never asked
    about a plan nobody authorised."""
    search = policy()
    gate_calls: list[int] = []

    run, _ = _run(
        search,
        approve=lambda plan: None,
        admit=lambda plan: gate_calls.append(1),
    )

    assert gate_calls == []
    assert run.admissions[-1].admitted is False


def test_an_unmeasurable_trial_stops_the_search_instead_of_being_a_clearance() -> None:
    """The runner hands ``sufficient=False`` straight to the search history, and
    the planner's ``INSUFFICIENT_MEASUREMENT`` stop is what ends the run — the
    unmeasurable trial is never recorded as a clearance."""
    search = policy()
    values: list[float] = []

    def execute(_plan: ExecutionPlan, step: SearchStep) -> StepOutcome:
        values.append(step.value)
        return StepOutcome(breached=False, sufficient=False)

    run, _ = _run(search, outcome=execute)

    assert len(values) == 1
    assert run.stop is StopReason.INSUFFICIENT_MEASUREMENT
    assert run.history.trials[-1].sufficient is False
    assert run.history.trials[-1].breached is False
    assert "did not clear the sample floor" in run.stop_note


def test_resuming_a_search_carries_the_boundary_it_already_found() -> None:
    """A resumed search reports the boundary the earlier walk established rather
    than starting the report from an empty history."""
    search = policy()
    walked = walk(search)
    assert walked.boundary is not None

    run, _ = _run(search, history=walked)

    assert run.boundary == walked.boundary
    assert run.history.steps_used >= walked.steps_used
    assert run.report.boundary == walked.boundary
    assert run.report.bracket_low == walked.bracket_low


# =======================================================================================
# Progressive stages (gaps 90, 91)
# =======================================================================================


def test_stage_ladder_is_single_target_then_the_canary_percentages() -> None:
    assert stage_ladder(100) == (1, 5, 10, 25, 50)
    # Small target sets round up and never exceed the count.
    assert stage_ladder(4) == (1, 1, 1, 1, 2)
    assert stage_ladder(1) == (1, 1, 1, 1, 1)


def test_an_empty_target_set_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        stage_ladder(0)

    assert caught.value.rule == RULE_NO_TARGETS


def test_a_ladder_that_narrows_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        stage_ladder(100, (50.0, 10.0))

    assert caught.value.rule == RULE_LADDER_NOT_INCREASING


def test_one_experiment_compiles_to_the_whole_ladder() -> None:
    plan = experiment(("n-a", "n-b", "n-c", "n-d", "n-e", "n-f", "n-g", "n-h",
                       "n-i", "n-j", "n-k", "n-l", "n-m", "n-n", "n-o", "n-p",
                       "n-q", "n-r", "n-s", "n-t"))

    stages = compile_stages(plan, (slo(),))

    assert [stage.share_pct for stage in stages] == [None, *CANARY_LADDER]
    assert [len(stage.targets) for stage in stages] == [1, 1, 2, 5, 10]
    assert stages[0].single_target is True
    assert stages[0].name == "single"
    assert stages[1].name == "canary-5"


def test_every_stage_is_a_distinct_plan_of_the_same_experiment() -> None:
    """The stages are plan-level constructs compiled from one experiment, not
    ad-hoc reruns: they share the experiment's identity, and each one is its own
    narrowed plan."""
    plan = experiment(("n-a", "n-b", "n-c", "n-d"))
    from mayhem.domain.prediction import plan_identity

    stages = compile_stages(plan, (slo(),))

    assert {stage.experiment_digest for stage in stages} == {plan_identity(plan)}
    # Every rung has its own identity even where two rungs narrow to the same node,
    # so an approval may bind to a *stage* rather than to whichever rung compiled
    # that plan first.
    stage_digests = [stage.stage_digest for stage in stages]
    assert len(set(stage_digests)) == len(stage_digests)
    # The widest stage still carries the experiment's identity, and its plan
    # narrows only the targets.
    assert stages[-1].plan.run_id == plan.run_id
    assert stages[-1].targets == ("n-a", "n-b")
    assert plan.steps[0].fault is not None
    assert plan.steps[0].fault.targets[0].node_ids == frozenset({"n-a", "n-b", "n-c", "n-d"})


def test_two_rungs_narrowing_to_the_same_node_share_a_plan_but_not_an_identity() -> None:
    """On a four-target experiment ``ceil(5%)`` and ``ceil(10%)`` are both one node,
    so those two stages compile the same plan. Their *identities* must still
    differ, or an approval for the 5% stage would bind to the 10% stage."""
    stages = compile_stages(experiment(("n-a", "n-b", "n-c", "n-d")), (slo(),))

    assert stages[1].plan_digest == stages[2].plan_digest
    assert stages[1].stage_digest != stages[2].stage_digest
    assert stages[1].name != stages[2].name


def test_a_stage_that_declares_no_criteria_is_refused() -> None:
    plan = experiment(("n-a", "n-b"))

    with pytest.raises(InvariantViolationError) as caught:
        compile_stages(plan, ())

    assert caught.value.rule == RULE_STAGE_NO_CRITERIA
    assert "a canary with no canary in it" in str(caught.value)


def test_an_experiment_with_no_targets_has_no_ladder() -> None:
    """A plan of wait steps resolves no fault targets, so there is nothing for a
    canary to widen. It cannot reach ``compile_stages`` through a fault step at all
    — ``ResolvedTarget`` refuses an empty node set — which is the same refusal one
    layer down."""
    plan = ExecutionPlan(
        run_id="r-empty",
        kind=ExperimentKind.DRILL,
        steps=(
            PlannedStep(id="w0", seq=0, raw_action=Wait(duration=5.0)),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )

    with pytest.raises(InvariantViolationError) as caught:
        compile_stages(plan, (slo(),))

    assert caught.value.rule == RULE_NO_TARGETS
    assert "no progressive ladder to compile" in str(caught.value)


def test_a_resolved_target_with_no_nodes_is_refused_by_the_domain() -> None:
    """The refusal one layer down, asserted so the ladder's own empty-target check
    is not mistaken for the only thing standing between a plan and an empty stage."""
    with pytest.raises(InvariantViolationError) as caught:
        ResolvedTarget(
            selector=TargetSelector(kind=NodeKind.SERVICE, expr="postgres"),
            node_ids=frozenset(),
        )

    assert caught.value.rule == "plan_targets_resolved"


def test_a_healthy_stage_promotes_to_the_next_one() -> None:
    stages = compile_stages(experiment(("n-a", "n-b", "n-c", "n-d")), (slo(),))

    outcome = evaluate_stage(stages[0], {"checkout-p99": observation(120.0)})
    decision = promote_to(stages, outcome)

    assert outcome.healthy is True
    assert decision.promoted is True
    assert decision.stopped is False
    assert decision.next_stage is not None
    assert decision.next_stage.name == stages[1].name
    assert "promoting to" in decision.reason


def test_an_unhealthy_slo_refuses_promotion_and_stops_the_ladder() -> None:
    """The negative control the plan names: a stage promotes only on SLO health,
    and a breach stops the ladder before the next stage is named."""
    stages = compile_stages(experiment(("n-a", "n-b", "n-c", "n-d")), (slo(),))

    outcome = evaluate_stage(stages[1], {"checkout-p99": observation(910.0)})
    decision = promote_to(stages, outcome)

    assert outcome.healthy is False
    assert outcome.breaches[0].criterion_id == "latency:checkout-p99"
    assert decision.promoted is False
    assert decision.stopped is True
    assert decision.next_stage is None
    assert "ladder stops here" in decision.reason
    assert "910.0ms violates lt 500.0ms" in decision.reason


def test_a_stage_with_no_observation_is_not_healthy() -> None:
    """"Could not see it" is not "nothing is wrong", and only one of them may
    promote a canary."""
    stages = compile_stages(experiment(("n-a", "n-b")), (slo(),))

    outcome = evaluate_stage(stages[0], {})
    decision = promote_to(stages, outcome)

    assert outcome.healthy is False
    assert decision.stopped is True
    assert outcome.breaches[0].observed is None
    assert "unobserved stage is not a healthy stage" in outcome.note


def test_one_failing_criterion_out_of_several_stops_the_stage() -> None:
    stages = compile_stages(
        experiment(("n-a", "n-b")),
        (slo(), SloCriterion(kind=CriterionKind.ERROR_BUDGET, metric="errors",
                             operator=CriterionOperator.LT, threshold=0.01, unit="ratio")),
    )

    healthy = evaluate_stage(
        stages[0], {"checkout-p99": observation(120.0), "errors": observation(0.001)}
    )
    breached = evaluate_stage(
        stages[0], {"checkout-p99": observation(120.0), "errors": observation(0.5)}
    )

    assert healthy.healthy is True
    assert breached.healthy is False
    assert [outcome.criterion_id for outcome in breached.breaches] == ["error_budget:errors"]


def test_a_healthy_top_of_ladder_completes_rather_than_promoting_into_nowhere() -> None:
    stages = compile_stages(experiment(("n-a", "n-b")), (slo(),))
    last = stages[-1]

    decision = promote_to(stages, evaluate_stage(last, {"checkout-p99": observation(120.0)}))

    assert decision.promoted is False
    assert decision.stopped is False
    assert decision.complete is True
    assert "top of the ladder" in decision.reason


def test_a_promotion_without_a_next_stage_cannot_be_constructed() -> None:
    stages = compile_stages(experiment(("n-a", "n-b")), (slo(),))
    outcome = evaluate_stage(stages[-1], {"checkout-p99": observation(120.0)})

    with pytest.raises(InvariantViolationError) as caught:
        Promotion(outcome=outcome, promoted=True, stopped=False, next_stage=None)

    assert caught.value.rule == RULE_STAGE_NOT_HEALTHY
    assert "must name the stage it promotes to" in str(caught.value)


def test_a_stop_that_names_a_next_stage_cannot_be_constructed() -> None:
    stages = compile_stages(experiment(("n-a", "n-b")), (slo(),))
    outcome = evaluate_stage(stages[0], {"checkout-p99": observation(910.0)})

    with pytest.raises(InvariantViolationError) as caught:
        Promotion(
            outcome=outcome, promoted=False, stopped=True, next_stage=stages[1]
        )

    assert caught.value.rule == RULE_STAGE_NOT_HEALTHY
    assert "continued after a breach" in str(caught.value)


def test_the_ladder_stops_at_the_first_unhealthy_stage() -> None:
    """An automatic stop has to mean the experiment stopped, not that the runner
    recorded a few more rows."""
    stages = compile_stages(experiment(("n-a", "n-b", "n-c", "n-d")), (slo(),))
    observed: list[str] = []

    def observe(stage: Stage) -> Mapping[str, ObservationResult]:
        observed.append(stage.name)
        healthy = stage.name != stages[1].name
        return {"checkout-p99": observation(120.0 if healthy else 910.0)}

    decisions = run_progressive(stages, observe)

    assert observed == [stages[0].name, stages[1].name]
    assert decisions[0].promoted is True
    assert decisions[1].stopped is True
    assert len(decisions) == 2


def test_stage_and_outcome_serialise_with_their_evidence() -> None:
    stages = compile_stages(experiment(("n-a", "n-b")), (slo(),))
    outcome = evaluate_stage(stages[0], {"checkout-p99": observation(910.0)})

    payload = outcome.to_dict()

    assert payload["stage"]["plan_digest"] == stages[0].plan_digest
    assert payload["stage"]["stage_digest"] == stages[0].stage_digest
    assert payload["stage"]["experiment_digest"] == stages[0].experiment_digest
    assert payload["healthy"] is False
    assert payload["breaches"][0]["passed"] is False


# =======================================================================================
# The aggregate report
# =======================================================================================


def test_analyze_run_collects_every_section_and_names_what_is_absent() -> None:
    search = policy()
    history = walk(search)
    curve = recovery_curve(
        name="checkout-p99",
        baseline_values=CALM,
        cooldown_values=SETTLED,
        tolerance=Tolerance(at_most=550.0),
    )
    analysis = causal_chains(graph(), request())

    report = analyze_run(
        search,
        history,
        recovery=(curve,),
        failure_cases=(FailureCase(fault_ids=("db.slow_query",), target_ids=(), reproduced=True),),
        causal=(analysis,),
    )

    payload = report.to_dict()
    assert payload["boundary"]["boundary"] == report.boundary.boundary
    assert report.boundary.bracket_low < PLANTED_BOUNDARY <= report.boundary.boundary  # type: ignore[operator]
    assert payload["recovery"][0]["recovered"] is True
    assert payload["minimal_case"]["found"] is True
    assert payload["causal"]["complete"] is True
    assert payload["notes"] == []


def test_an_analysis_with_no_causal_or_recovery_says_so() -> None:
    report = analyze_run(policy(), walk(policy()))

    payload = report.to_dict()

    assert payload["causal"] is None
    assert payload["minimal_case"] is None
    assert any("not evidence that no chain exists" in note for note in payload["notes"])
    assert any("unreported, not clean" in note for note in payload["notes"])
