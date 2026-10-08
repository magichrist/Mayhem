"""Phase 4 of docs/v1.1.0/15_RESILIENCE_ANALYTICS_ADAPTIVE.md: safety and evidence.

Phase 2 computed boundaries, recovery curves, minimal failure cases, and causal
chains. This file is about the three things its author left open, plus the negative
controls the plan names for this phase.

* **The runner's own budget check is live.** Phase 2's ``step_affordable`` could only
  be reached by a test that called the predicate directly, because the runner handed
  the planner the same budget it was spending. ``planner_budget`` closes that, and the
  tests here go through :func:`adaptive_run` — the runner path, not the helper — twice:
  once where the divergence stops the search with the boundary it already found, and
  once where it does not stop it and the planner's reading is recorded in the trial
  history that gets sealed.
* **Evidence is sealed, and an unsupported claim is withheld.** The chain verifies,
  the manifest verifies, the chain reloads from stored bytes and comes back with the
  same digests, and it never claims to be signed. A claim with no support cannot be
  constructed; a report with no support is a withholding beside the claims that
  survived.
* **A boundary search is a privileged action.** The runner hands its record to a
  recorder exactly once, on every path, and the recorder puts it in the cross-run
  audit stream with the policy digest and the escalating ladder. A search the stream
  cannot show is refused.

The negative controls are the point of the file: a step the runner cannot pay for
stops the search *with the findings it already had*; an unsealed boundary report
cannot back a decision even when every number in it is true; a causal chain citing a
missing edge is withheld rather than guessed; and a generated candidate reaches no
execution at all — which is why its analysis has nothing to seal.

Fixtures are fixed lists and fixed graphs, never generated.
"""

from __future__ import annotations

from dataclasses import fields, replace
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.controller.analytics_service import (
    AUTHORITY_FIELDS,
    KIND_RESILIENCE_BOUNDARY_SEARCHED,
    RULE_DRAFT_CARRIES_AUTHORITY,
    RULE_EVIDENCE_NOT_SEALED,
    RULE_EVIDENCE_UNSUPPORTED,
    RULE_HOP_WITHOUT_EDGE,
    RULE_PLANNER_BUDGET_DIVERGED,
    RULE_SEARCH_NOT_RECORDED,
    RULE_STEP_NOT_APPROVED,
    AnalyticsClaim,
    CausalClaimRequest,
    ClaimKind,
    CustomerImpactCheck,
    EdgeCitation,
    FailureCase,
    MetricChange,
    ObservationCitation,
    RecoveryCurve,
    SearchRecord,
    StepOutcome,
    WithheldEvidence,
    adaptive_run,
    analytics_evidence,
    analyze_run,
    boundary_claim,
    boundary_decision_support,
    boundary_report,
    causal_chains,
    compile_candidate,
    minimal_failure_case,
    record_boundary_search,
    recovery_curve,
    require_recorded_search,
    require_sealed_claim,
    seal_analytics_evidence,
    search_policy_digest,
    verify_analytics_evidence,
)
from mayhem.domain.analytics import Comparison, compare
from mayhem.domain.attestation import ChainVerification
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
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
    RULE_BUDGET_REFERENCE_MISMATCH,
    RULE_GENERATED_CANNOT_BE_APPROVED,
    Approval,
    BudgetKind,
    BudgetReference,
    SafetyBudget,
    SearchHistory,
    SearchOrigin,
    SearchPhase,
    SearchPlan,
    SearchPolicy,
    SearchStep,
    StopReason,
    Trial,
)
from mayhem.domain.steady_state import Tolerance
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    PortBinding,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
)
from mayhem.infra.audit_stream import AuditStream
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

    from mayhem.controller.analytics_service import AdaptiveRun, ResilienceAnalysis

FP = "f" * 64
QUOTA = BudgetReference(kind=BudgetKind.DAMAGE_SECONDS, label="r-15/damage-quota")
COMBINATION = "checkout/latency-injection"
RUN_ID = "r-15"

#: The planted surface: anything at or above this impairment breaks the service.
PLANTED_BOUNDARY = 8.0


# =======================================================================================
# Fixtures
# =======================================================================================


def breaches(value: float) -> bool:
    """The simulated response surface."""
    return value >= PLANTED_BOUNDARY


def policy(**overrides: Any) -> SearchPolicy:
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


def experiment(target_ids: tuple[str, ...] = ("n-postgres",)) -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="postgres")
    return ExecutionPlan(
        run_id="r-15-step",
        kind=ExperimentKind.DRILL,
        steps=(
            PlannedStep(
                id="s0",
                seq=0,
                raw_action=InjectFault(fault="db.slow_query", selectors=(selector,), duration=30.0),
                fault=PlannedFault(
                    fault_id="db.slow_query",
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset(target_ids)),),
                    duration=30.0,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )


class _Recorder:
    """Records every collaborator call, in order.

    No mock library: the assertions are about *whether execution happened*, so the
    recorder has to be the only thing standing between the runner and an executed
    step, and a call list reads that directly.
    """

    def __init__(self, *, surface: Any = breaches) -> None:
        self.surface = surface
        self.calls: list[str] = []
        self.plan = experiment()

    def compile_step(self, step: SearchStep) -> ExecutionPlan:
        self.calls.append("compile")
        return self.plan

    def admit(self, plan: ExecutionPlan) -> None:
        self.calls.append("admit")

    def execute(self, plan: ExecutionPlan, step: SearchStep) -> StepOutcome:
        self.calls.append("execute")
        return StepOutcome(breached=self.surface(step.value))

    @staticmethod
    def approve(plan: SearchPlan) -> Approval:
        return Approval(approved_by="sre-oncall", plan_digest=plan.plan_digest)


def run_search(
    search: SearchPolicy | None = None,
    *,
    remaining: float = 500.0,
    surface: Any = breaches,
    planner_remaining: float | None = None,
    history: SearchHistory | None = None,
    origin: SearchOrigin = SearchOrigin.AUTHORED,
    approve: Any = None,
    recorder: _Recorder | None = None,
    record: Any = None,
) -> AdaptiveRun:
    """Walk a search with a recorder attached to every collaborator.

    ``planner_remaining`` is the deliberate Phase 4 divergence: the budget the
    *planner* sees, which is not the budget the runner spends. Left ``None``, the
    runner hands the planner its own running total, as Phase 2 did.
    """
    search = policy() if search is None else search
    harness = _Recorder(surface=surface) if recorder is None else recorder
    return adaptive_run(
        search,
        budget=search.budget(remaining),
        compile_step=harness.compile_step,
        admit=harness.admit,
        execute=harness.execute,
        approve=_Recorder.approve if approve is None else approve,
        origin=origin,
        history=history,
        combination=COMBINATION,
        planner_budget=None if planner_remaining is None else search.budget(planner_remaining),
        search_record=record,
    )


def _samples(base: float, spread: float, count: int = 8) -> list[float]:
    """A fixed alternating series around ``base`` — no RNG anywhere in this file."""
    offsets = (0.0, spread, -spread, spread * 0.5, -spread * 0.5, spread * 0.8, -spread * 0.8, 0.2)
    return [base + offsets[index % len(offsets)] for index in range(count)]


CALM = _samples(500.0, 8.0)
DEGRADED = _samples(900.0, 12.0)
SETTLED = _samples(500.0, 6.0)


def material_comparison(name: str = "checkout-latency") -> Comparison:
    return compare(CALM, DEGRADED, name=name, percentile=99.0, materiality_pct=10.0)


def curve(name: str = "checkout-p99", cooldown: list[float] | None = None) -> RecoveryCurve:
    return recovery_curve(
        name=name,
        baseline_values=CALM,
        cooldown_values=SETTLED if cooldown is None else cooldown,
        tolerance=Tolerance(at_most=550.0),
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


def observation(value: float = 910.0) -> ObservationResult:
    return ObservationResult(metric="checkout-p99", value=value, unit="ms", window_s=60.0)


def _graph(*, connected: bool) -> TopologyGraph:
    """``checkout`` depends on ``postgres`` and *is* the customer-facing door.

    ``connected=False`` is the same snapshot with the edge removed — the negative
    control's graph, so the two tests differ in exactly one fact.
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(
                id="n-checkout",
                name="checkout",
                exposed_ports=(PortBinding(host_port=8080, container_port=8080),),
            ),
            ServiceNode(id="n-postgres", name="postgres"),
        ),
        edges=(Edge(src="n-checkout", dst="n-postgres", kind=EdgeKind.DEPENDS_ON),)
        if connected
        else (),
    )


def claim_request() -> CausalClaimRequest:
    return CausalClaimRequest(
        fault_id="net.latency",
        target_ids=("n-checkout",),
        dependency_ids=("n-postgres",),
        trial=Trial(
            step=SearchStep(
                index=0,
                value=10.0,
                phase=SearchPhase.ESCALATION,
                combination=COMBINATION,
                budget_remaining=100.0,
                budget_ref=QUOTA,
                expected_cost=1.0,
            ),
            breached=True,
        ),
        metric_changes=(MetricChange(node_id="n-postgres", comparison=material_comparison()),),
        customer_impacts=(
            CustomerImpactCheck(node_id="n-checkout", criterion=slo(), observation=observation()),
        ),
    )


def tried_cases() -> list[FailureCase]:
    """Three clearances and the reproduction that needs both targets.

    Every fault-bearing proper subset of the winner has to appear *and* have failed to
    reproduce before the reduction may call itself minimal, so the fault-only and each
    single-target combination are all here. Without them the same reduction reports the
    smallest *tried* case and names the subset it never tried, which is the behaviour
    the support digests are there to make auditable.
    """
    return [
        FailureCase(
            fault_ids=("net.latency",),
            target_ids=("n-checkout",),
            reproduced=False,
            value=1.0,
            combination=COMBINATION,
        ),
        FailureCase(
            fault_ids=("net.latency",),
            target_ids=("n-postgres",),
            reproduced=False,
            value=1.0,
            combination="postgres-only",
        ),
        FailureCase(
            fault_ids=("net.latency",),
            target_ids=(),
            reproduced=False,
            value=1.0,
            combination="fault-only",
        ),
        FailureCase(
            fault_ids=("net.latency",),
            target_ids=("n-checkout", "n-postgres"),
            reproduced=True,
            value=10.0,
            combination="checkout+postgres",
        ),
    ]


def full_analysis(
    run: AdaptiveRun,
    *,
    recovery: list[RecoveryCurve] | None = None,
    failure_cases: list[FailureCase] | None = None,
    causal_connected: bool = True,
) -> ResilienceAnalysis:
    """One walked search's report, with every section present by default."""
    boundary_index = next((trial.step.index for trial in run.history.trials if trial.breached), 0)
    return analyze_run(
        policy(),
        run.history,
        comparisons={boundary_index: material_comparison()},
        recovery=[curve()] if recovery is None else recovery,
        failure_cases=tried_cases() if failure_cases is None else failure_cases,
        causal=[causal_chains(_graph(connected=causal_connected), claim_request())],
    )


def search_halted_on_budget() -> tuple[SearchPolicy, AdaptiveRun]:
    """A search that found a boundary and then ran out of budget mid-bracket.

    The state a resumed call starts from, and the only state in which the resumed
    planner still wants a step: ``resolution=0.0`` keeps the bracket unresolved, so
    ``plan_next_step`` proposes the next bisection rather than stopping on
    ``BOUNDARY_RESOLVED`` before the runner's own check is ever reached.
    """
    search = policy(resolution=0.0)
    halted = run_search(search, remaining=4.0)
    assert halted.stop is StopReason.NO_REMAINING_BUDGET
    assert halted.boundary is not None
    assert halted.findings_preserved is True
    return search, halted


def open_store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "mayhem.db")


def store_and_stream(tmp_path: Path) -> tuple[Store, AuditStream]:
    store = open_store(tmp_path)
    return store, AuditStream(store)


def sealed(tmp_path: Path, run: AdaptiveRun) -> tuple[Store, Any]:
    store = open_store(tmp_path)
    return store, seal_analytics_evidence(store, full_analysis(run), run_id=RUN_ID)


# =======================================================================================
# The runner's own budget check is live
# =======================================================================================


def test_the_runner_stops_on_a_step_the_planner_thought_it_could_afford() -> None:
    """The live path Phase 2 could not reach, taken through the runner.

    The search first establishes a boundary. It is then *resumed* with a runner
    budget of 0.5 and a ``planner_budget`` of 100 — the ledger-drained case. The
    planner, working from 100, proposes a step; the runner cannot pay for it; and the
    run halts on the runner's own check rather than the planner's.

    Four things are asserted because all four are the claim: the step never executed,
    the refusal carries the runner's rule id rather than the ordinary one, it costs
    nothing, and the boundary the earlier call established survives the halt.
    """
    search, first = search_halted_on_budget()
    recorder = _Recorder()

    resumed = run_search(
        search,
        remaining=0.5,
        planner_remaining=100.0,
        history=first.history,
        recorder=recorder,
    )

    assert "execute" not in recorder.calls
    assert resumed.executed == 0
    assert resumed.stop is StopReason.NO_REMAINING_BUDGET
    assert resumed.stops_on_divergent_budget is True
    # The findings survive the halt: the boundary is the one the first call found.
    assert resumed.boundary == first.boundary
    assert resumed.findings_preserved is True
    assert resumed.report.boundary == first.boundary
    # The refusal is the runner's, under its own rule id, and it costs nothing.
    refusal = resumed.admissions[-1]
    assert refusal.rule_id == RULE_PLANNER_BUDGET_DIVERGED
    assert refusal.charged == 0.0
    assert refusal.admitted is False
    assert refusal.budget_remaining == 0.5


def test_the_divergence_names_both_budgets_and_the_step_they_disagreed_on() -> None:
    """The numbers, not a boolean: which budget the planner read, which the runner
    had, and the step that caught it. A divergence recorded as a flag would not let
    an operator work out what went wrong."""
    search, first = search_halted_on_budget()

    resumed = run_search(search, remaining=0.5, planner_remaining=100.0, history=first.history)

    divergence = resumed.divergence
    assert divergence is not None
    assert divergence.planner_remaining == 100.0
    assert divergence.runner_remaining == 0.5
    assert divergence.stopped is True
    assert divergence.rule_id == RULE_PLANNER_BUDGET_DIVERGED
    assert divergence.step_index == len(first.history.trials)
    assert divergence.shortfall == pytest.approx(99.5)
    # The stop note carries both numbers, so the operator does not have to know the
    # difference between the two rule ids to read the run.
    assert "100.0 of damage-seconds" in resumed.stop_note
    assert "0.5 to spend" in resumed.stop_note


def test_a_divergence_the_runner_can_afford_is_recorded_and_sealed() -> None:
    """Not every divergence is a stop, and the non-stopping one still has to be
    visible. This is the "the evidence is in the step itself" case: the executed trial
    carries the *planner's* reading, so the report's trial digests are digests of steps
    that were planned against 100 while the runner spent 5."""
    recorder = _Recorder(surface=lambda value: value >= 4.0)

    run = run_search(
        policy(minimization="none", resolution=0.0),
        remaining=5.0,
        planner_remaining=100.0,
        recorder=recorder,
    )

    assert run.stop is StopReason.BREACH_FOUND
    assert run.divergence is not None
    assert run.divergence.stopped is False
    assert run.stops_on_divergent_budget is False
    assert all(trial.step.budget_remaining == 100.0 for trial in run.history.trials)
    assert run.report.trial_digests == tuple(
        digest(trial.to_dict()) for trial in run.history.trials
    )
    assert recorder.calls.count("execute") == run.executed


def test_an_ordinary_run_records_no_divergence_at_all() -> None:
    """The default wiring must be quiet. A divergence record on every run would make
    the record meaningless and would hide the one that mattered — and the ordinary
    runner still refuses an unaffordable step, because with one budget the planner
    refuses first."""
    run = run_search(policy())

    assert run.divergence is None
    assert run.stops_on_divergent_budget is False

    starved = run_search(policy(), remaining=0.5)

    assert starved.executed == 0
    assert starved.admissions == ()
    assert starved.stop is StopReason.NO_REMAINING_BUDGET
    assert starved.divergence is None


def test_a_planner_budget_on_another_ledger_is_refused_before_anything_runs() -> None:
    """A divergence against an unrelated ledger is a wiring bug, not a search. The
    planner refuses it on the first iteration — before an approval, a compile, or an
    admission — with the domain's own rule, and this module deliberately adds no
    second check of its own."""
    recorder = _Recorder()

    with pytest.raises(InvariantViolationError) as caught:
        adaptive_run(
            policy(),
            budget=policy().budget(5.0),
            planner_budget=SafetyBudget(
                reference=BudgetReference(kind=BudgetKind.WALL_CLOCK_SECONDS, label="clock"),
                remaining=100.0,
                step_cost=1.0,
            ),
            compile_step=recorder.compile_step,
            admit=recorder.admit,
            execute=recorder.execute,
            approve=_Recorder.approve,
        )

    assert caught.value.rule == RULE_BUDGET_REFERENCE_MISMATCH
    assert recorder.calls == []


# =======================================================================================
# Sealed analytics evidence
# =======================================================================================


def test_a_sealed_analysis_round_trips_through_storage(tmp_path: Path) -> None:
    """Seal, reload, and get the same claims back from the stored bytes alone.

    The round trip is the point of sealing: a report in memory proves nothing later,
    so a claim has to come back out of SQLite with its support intact and its digests
    unchanged. Re-verification is plan 12's own verifier, not a re-implemented check.
    """
    store, seal = sealed(tmp_path, run_search(policy()))

    assert seal.verified is True
    assert seal.chain_verification.valid is True
    assert seal.manifest_verification.valid is True
    assert seal.evidence.complete is True
    assert {claim.kind for claim in seal.claims} == {
        ClaimKind.BOUNDARY,
        ClaimKind.RECOVERY,
        ClaimKind.MINIMAL_FAILURE_CASE,
        ClaimKind.CAUSAL_CHAIN,
    }

    verdict = verify_analytics_evidence(store, RUN_ID)

    assert (verdict.present, verdict.verified) == (True, True)
    assert [claim.claim_digest for claim in verdict.claims] == list(seal.evidence.claim_digests)
    for original in seal.claims:
        reloaded = next(
            claim for claim in verdict.claims if claim.claim_digest == original.claim_digest
        )
        assert reloaded.support_refs == original.support_refs
        assert reloaded.subject == original.subject
        assert reloaded.statement == original.statement
        assert reloaded.kind is original.kind
    store.close()


def test_a_seal_reports_itself_unsigned_and_says_why(tmp_path: Path) -> None:
    """Sealing attests integrity, never authorship. The state and the reason are plan
    12's own strings, imported rather than restated, so a reader who finds an unsigned
    manifest in the database is told the reason rather than left to guess whether an
    absence is a bug or a phase boundary."""
    store, seal = sealed(tmp_path, run_search(policy()))

    assert seal.signed is False
    assert seal.signature_state == SIGNATURE_UNSIGNED_NO_SIGNING
    assert seal.signature_reason == UNSIGNED_REASON_NO_SIGNING
    assert "no signature bytes" in seal.signature_reason
    store.close()


def test_every_claim_cites_the_observations_and_edges_it_rests_on(tmp_path: Path) -> None:
    """No claim is sealed on its own authority. The boundary cites the trials its
    bracket was read from, the curve the samples it was computed from, the minimal
    case every measurable case it tried, and the chain the records and edges Phase 2
    already required — each recomputed here from the record, so a citation that drifted
    would fail."""
    store, seal = sealed(tmp_path, run_search(policy()))
    run = run_search(policy())

    by_kind = {claim.kind: claim for claim in seal.claims}

    boundary = by_kind[ClaimKind.BOUNDARY]
    assert list(boundary.support_refs) == [
        digest(trial.to_dict()) for trial in run.history.trials
    ]  # order preserved

    recovery = by_kind[ClaimKind.RECOVERY]
    assert recovery.support_refs == (curve().samples_digest,)
    assert recovery.detail["graded"] is True

    minimal = by_kind[ClaimKind.MINIMAL_FAILURE_CASE]
    assert list(minimal.support_refs) == [
        digest(case.to_dict()) for case in sorted(tried_cases(), key=lambda c: c.key())
    ]
    assert minimal.detail["minimal"] is True
    assert minimal.detail["considered"] == len(tried_cases())

    chain = by_kind[ClaimKind.CAUSAL_CHAIN]
    assert chain.subject == "net.latency"
    assert "depends_on:n-checkout->n-postgres" in chain.support_refs
    # One edge, cited by each of the two hops that traverse it, and one observation
    # per hop that rests on a record.
    assert chain.detail["edge_citations"] == 2
    assert chain.detail["observation_citations"] >= 2
    assert chain.detail["hops"] == [
        "fault->target",
        "target->dependency",
        "dependency->metric",
        "metric->customer",
    ]
    store.close()


def test_a_claim_with_no_support_cannot_even_be_constructed() -> None:
    """The type-level half of withholding: there is no way to hold a claim that rests
    on nothing, so no downstream step can mistake one for a finding."""
    with pytest.raises(InvariantViolationError) as caught:
        AnalyticsClaim(
            kind=ClaimKind.BOUNDARY, subject="boundary-search", claim_digest="d" * 64, support=()
        )

    assert caught.value.rule == RULE_EVIDENCE_UNSUPPORTED


def test_a_claim_digest_that_is_not_a_digest_is_refused() -> None:
    """The same law Phase 2 applies to every citation, applied to the claim itself: a
    claim digest is either the hash of the report it describes or it is not one — so a
    reader cannot be handed a human-readable claim name where a digest belongs."""
    report = boundary_report(policy(), run_search(policy()).history)
    support = boundary_claim(report)
    assert not isinstance(support, WithheldEvidence)

    with pytest.raises(InvariantViolationError) as caught:
        AnalyticsClaim(
            kind=ClaimKind.BOUNDARY,
            subject="boundary-search",
            claim_digest="the boundary is 8.0",
            support=support.support,
        )

    assert caught.value.rule == "analytics.citation_not_a_digest"


def test_a_report_with_no_trials_is_withheld_rather_than_sealed() -> None:
    """The negative control on the boundary itself: a search that executed nothing must
    not be able to produce a sealed finding. "No impairment crossed the tolerance" over
    an empty history is a statement that nobody ran anything."""
    run = run_search(policy(), remaining=0.0)
    assert run.history.steps_used == 0

    evidence = analytics_evidence(full_analysis(run), run_id=RUN_ID)

    withheld = [claim for claim in evidence.withheld if claim.kind is ClaimKind.BOUNDARY]
    assert len(withheld) == 1
    assert withheld[0].rule_id == RULE_EVIDENCE_UNSUPPORTED
    assert "executed no trial" in withheld[0].reason
    assert all(claim.kind is not ClaimKind.BOUNDARY for claim in evidence.claims)
    assert evidence.complete is False


def test_a_recovery_curve_with_no_post_fault_samples_is_withheld() -> None:
    """An empty curve is not a recovery, and it is not evidence of one either. The
    digest of an empty sample list would match any other empty capture, so the curve
    carries none and the claim cannot be built."""
    empty = curve(cooldown=[])

    evidence = analytics_evidence(
        full_analysis(run_search(policy()), recovery=[empty]), run_id=RUN_ID
    )

    withheld = [claim for claim in evidence.withheld if claim.kind is ClaimKind.RECOVERY]
    assert len(withheld) == 1
    assert withheld[0].subject == "checkout-p99"
    assert "no post-fault sample" in withheld[0].reason
    assert all(claim.kind is not ClaimKind.RECOVERY for claim in evidence.claims)


def test_a_minimal_case_with_no_measurable_trial_is_withheld() -> None:
    """Minimality is a claim about the subsets that were tried and cleared. With
    nothing *measurable* tried there is nothing to certify, and the reduction says so
    rather than reporting a minimal case of size zero."""
    unmeasurable = [
        FailureCase(
            fault_ids=("net.latency",),
            target_ids=("n-checkout",),
            reproduced=True,
            sufficient=False,
        )
    ]

    evidence = analytics_evidence(
        full_analysis(run_search(policy()), failure_cases=unmeasurable), run_id=RUN_ID
    )

    withheld = [
        claim for claim in evidence.withheld if claim.kind is ClaimKind.MINIMAL_FAILURE_CASE
    ]
    assert len(withheld) == 1
    assert withheld[0].rule_id == RULE_EVIDENCE_UNSUPPORTED
    assert all(claim.kind is not ClaimKind.MINIMAL_FAILURE_CASE for claim in evidence.claims)


def test_a_recovery_curve_digests_the_samples_it_was_computed_from() -> None:
    """The citation is over the *inputs*, not over the curve: re-reading the same
    samples differently is different evidence, not the same evidence quoted again."""
    settled = curve()

    assert settled.samples_digest == digest(
        {"baseline": [float(value) for value in CALM], "cooldown": [float(v) for v in SETTLED]}
    )
    assert curve(cooldown=_samples(500.0, 7.0)).samples_digest != settled.samples_digest
    assert curve(cooldown=[]).samples_digest == ""


def test_minimal_failure_case_carries_the_cases_it_reduced() -> None:
    """The support includes the cases that did *not* reproduce — otherwise minimality
    is an assertion with nothing behind it. Asserted on the report itself so a reader
    sees the reduction and its inputs together."""
    reduced = minimal_failure_case(tried_cases())

    assert reduced.minimal is True
    assert reduced.case is not None
    assert reduced.case_digests == tuple(
        digest(case.to_dict()) for case in sorted(tried_cases(), key=lambda c: c.key())
    )


def test_a_boundary_report_carries_the_trials_it_was_reduced_from() -> None:
    """And the bracket itself is still the history's, not a second computation: one
    definition of where the boundary is, so the runner and a later re-analysis cannot
    disagree about it."""
    run = run_search(policy())

    report = boundary_report(policy(), run.history)

    assert report.trial_digests == tuple(digest(trial.to_dict()) for trial in run.history.trials)
    assert report.boundary == run.history.boundary
    assert report.bracket_low == run.history.bracket_low


def test_sealing_names_the_run_it_describes_and_refuses_an_unnamed_one(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    analysis = full_analysis(run_search(policy()))

    with pytest.raises(InvariantViolationError) as caught:
        seal_analytics_evidence(store, analysis, run_id="   ")

    assert caught.value.rule == RULE_EVIDENCE_UNSUPPORTED

    seal = seal_analytics_evidence(store, analysis, run_id=RUN_ID)

    assert seal.chain_id.endswith(RUN_ID)
    assert any(event.payload.get("run_id") == RUN_ID for event in seal.events)
    store.close()


def test_an_absent_chain_reports_absent_rather_than_empty(tmp_path: Path) -> None:
    """A run with nothing sealed must not verify as "no claims" — that is the reading
    that would let a lost seal pass for a clean one."""
    store = open_store(tmp_path)

    verdict = verify_analytics_evidence(store, "r-never-sealed")

    assert verdict.present is False
    assert verdict.verified is False
    assert verdict.claims == ()
    assert "no analytics chain stored" in verdict.describe()
    assert verdict.backing("d" * 64) is None
    store.close()


# =======================================================================================
# Negative control: an unsealed report cannot back a decision
# =======================================================================================


def test_an_unsealed_boundary_report_cannot_back_a_decision() -> None:
    """Every number in the report is true; it is still unusable as evidence, because
    nothing sealed it. This is the difference between a report and a finding."""
    report = boundary_report(policy(), run_search(policy()).history)

    with pytest.raises(InvariantViolationError) as caught:
        boundary_decision_support(None, report)

    assert caught.value.rule == RULE_EVIDENCE_NOT_SEALED
    assert "not sealed" in str(caught.value)


def test_a_boundary_report_that_was_edited_after_the_seal_cannot_back_a_decision(
    tmp_path: Path,
) -> None:
    """The seal binds the report's bytes, not its subject. Change the number and the
    digest changes, so the edited report is a *different* claim and the chain no longer
    holds it — which is the property that makes a seal worth having over a row."""
    store, seal = sealed(tmp_path, run_search(policy()))
    report = boundary_report(policy(), run_search(policy()).history)
    assert boundary_decision_support(seal, report) == digest(report.to_dict())

    edited = replace(report, boundary=3.0)

    with pytest.raises(InvariantViolationError) as caught:
        boundary_decision_support(seal, edited)

    assert caught.value.rule == RULE_EVIDENCE_NOT_SEALED
    assert "is not in the chain sealed" in str(caught.value)
    store.close()


def test_a_report_whose_own_support_is_absent_cannot_back_a_decision() -> None:
    """The withholding reaches the gate: a report that never rested on anything is
    refused before the "is it sealed" question is even asked, because there is nothing
    to look up."""
    report = boundary_report(policy(), SearchHistory())

    with pytest.raises(InvariantViolationError) as caught:
        boundary_decision_support(None, report)

    assert caught.value.rule == RULE_EVIDENCE_NOT_SEALED
    assert "rests on no trial" in str(caught.value)


def test_a_sealed_claim_backs_a_decision_only_from_a_verified_chain(tmp_path: Path) -> None:
    """The gate reads the chain's own verdict. A seal whose verification failed is
    refused even though the claim is in it, because integrity is the only thing that
    makes the bytes evidence."""
    store, seal = sealed(tmp_path, run_search(policy()))
    report = boundary_report(policy(), run_search(policy()).history)
    claim = boundary_claim(report)
    assert isinstance(claim, AnalyticsClaim)

    assert require_sealed_claim(seal, claim) == claim.claim_digest

    unverified = replace(
        seal,
        chain_verification=ChainVerification(valid=False, checked=0, errors=("tampered",)),
    )

    with pytest.raises(InvariantViolationError) as caught:
        require_sealed_claim(unverified, claim)

    assert caught.value.rule == RULE_EVIDENCE_NOT_SEALED
    assert "does not verify" in str(caught.value)
    store.close()


def test_a_tampered_chain_stops_backing_claims_after_a_reload(tmp_path: Path) -> None:
    """Integrity is checked on reload, from the stored bytes, with no control plane.
    Rewriting a stored event's payload breaks its digest and the claim stops backing
    anything — which is what "sealed" buys over "recorded in a table"."""
    store, seal = sealed(tmp_path, run_search(policy()))
    assert verify_analytics_evidence(store, RUN_ID).verified is True
    rows = store.query(
        "SELECT sequence, event_json FROM attestation_events WHERE run_id = ? ORDER BY sequence",
        (seal.chain_id,),
    )
    row = dict(rows[1])
    tampered = str(row["event_json"]).replace(
        '"subject":"boundary-search"', '"subject":"some-other-policy"'
    )
    assert tampered != str(row["event_json"])
    with store.write() as conn:
        conn.execute(
            "UPDATE attestation_events SET event_json = ? WHERE run_id = ? AND sequence = ?",
            (tampered, seal.chain_id, int(str(row["sequence"]))),
        )

    verdict = verify_analytics_evidence(store, RUN_ID)

    assert verdict.verified is False
    assert verdict.errors
    assert verdict.backing(seal.evidence.claim_digests[0]) is None
    store.close()


# =======================================================================================
# The search as a privileged action
# =======================================================================================


def test_the_runner_hands_its_record_to_a_recorder_exactly_once() -> None:
    """The recording hook is part of the run, not something a caller remembers: it
    fires once, and ``recorded`` says whether anything actually took it."""
    records: list[SearchRecord] = []

    run = run_search(policy(), record=records.append)

    assert records == [run.record]
    assert run.recorded is True
    unrecorded = run_search(policy())
    assert unrecorded.recorded is False
    # The record is on the run either way, so a caller may record it afterwards.
    assert unrecorded.record.policy_digest == search_policy_digest(policy())


def test_a_recorder_that_refuses_propagates_rather_than_being_swallowed() -> None:
    """A search nobody can find afterwards is not a result. Raising is the same choice
    :func:`mayhem.infra.audit_stream.seal_run_evidence_at_run_close` makes for a seal
    whose audit entry could not be written."""

    def unavailable(_: SearchRecord) -> None:
        raise RuntimeError("audit stream unreachable")

    with pytest.raises(RuntimeError, match="unreachable"):
        run_search(policy(), record=unavailable)


def test_a_boundary_search_is_recorded_with_its_policy_digest_and_ladder(
    tmp_path: Path,
) -> None:
    """The entry an operator reads months later: who searched, which policy authorised
    it, what authorization existed, and — the point of the action — the escalating
    ladder that was actually applied to the system."""
    store, stream = store_and_stream(tmp_path)
    search = policy()
    run = run_search(search)

    entry = record_boundary_search(stream, run.record, principal="sre-oncall", run_id=RUN_ID)

    assert entry.event_kind == KIND_RESILIENCE_BOUNDARY_SEARCHED
    payload = entry.payload
    assert payload["principal"] == "sre-oncall"
    assert payload["subject_run_id"] == RUN_ID
    assert payload["policy_digest"] == search_policy_digest(search)
    recorded = payload["detail"]
    assert recorded["search"]["origin"] == "authored"
    assert recorded["search"]["stop"] == run.stop.value
    assert recorded["perturbations"] == list(run.record.perturbations)
    assert [trace["value"] for trace in recorded["search"]["ladder"]] == [
        trial.step.value for trial in run.history.trials
    ]
    assert stream.verify().valid is True
    assert [event.event_id for event in stream.entries_for_run(RUN_ID)] == [entry.event_id]
    store.close()


def test_the_recorded_search_matches_on_its_own_bytes_not_its_name(tmp_path: Path) -> None:
    """``require_recorded_search`` matches on the run's decision digest, so a different
    search under the same policy and run cannot stand in for this one."""
    store, stream = store_and_stream(tmp_path)
    run = run_search(policy())
    record_boundary_search(stream, run.record, principal="sre-oncall", run_id=RUN_ID)

    assert require_recorded_search(stream, run.record) == run.record.decision_digest

    other = run_search(policy(step=5.0))
    assert other.record.decision_digest != run.record.decision_digest
    with pytest.raises(InvariantViolationError) as caught:
        require_recorded_search(stream, other.record)

    assert caught.value.rule == RULE_SEARCH_NOT_RECORDED
    store.close()


def test_a_search_the_stream_cannot_show_is_refused(tmp_path: Path) -> None:
    """The fail-closed counterpart: perturbing a system in escalating steps and leaving
    no entry behind means nothing the search found may be acted on."""
    store, stream = store_and_stream(tmp_path)
    run = run_search(policy())

    with pytest.raises(InvariantViolationError) as caught:
        require_recorded_search(stream, run.record)

    assert caught.value.rule == RULE_SEARCH_NOT_RECORDED
    store.close()


def test_recording_a_search_with_no_run_is_refused_rather_than_unattributed(
    tmp_path: Path,
) -> None:
    """An audit entry with no subject cannot answer "what was done to this run", so the
    recorder refuses rather than writing one."""
    store, stream = store_and_stream(tmp_path)
    run = run_search(policy())

    with pytest.raises(InvariantViolationError) as caught:
        record_boundary_search(stream, run.record, principal="sre-oncall")

    assert caught.value.rule == RULE_SEARCH_NOT_RECORDED
    assert stream.entry_count() == 0
    store.close()


def test_the_policy_digest_changes_when_the_policy_does() -> None:
    """One definition of a policy's identity, so "under which authorization" has an
    answer that a changed ladder cannot keep wearing."""
    assert search_policy_digest(policy()) == search_policy_digest(policy())
    assert search_policy_digest(policy()) != search_policy_digest(policy(step=5.0))
    assert search_policy_digest(policy()) != search_policy_digest(policy(resolution=1.0))
    assert len(search_policy_digest(policy())) == 64


# =======================================================================================
# Negative control: a causal chain citing a missing edge is withheld
# =======================================================================================


def test_a_chain_over_a_missing_edge_is_withheld_and_never_sealed(tmp_path: Path) -> None:
    """The gap-53 negative control at the evidence layer. The graph snapshot has no edge
    from ``checkout`` to ``postgres``, so there is no chain, and what is sealed is the
    *withholding* — under the causal rule that stopped it — rather than a claim naming a
    dependency the graph does not contain."""
    run = run_search(policy())
    analysis = full_analysis(run, causal_connected=False)
    assert analysis.causal is not None
    assert analysis.causal.claims == ()
    assert analysis.causal.withheld[0].rule_id == RULE_HOP_WITHOUT_EDGE

    evidence = analytics_evidence(analysis, run_id=RUN_ID)

    assert all(claim.kind is not ClaimKind.CAUSAL_CHAIN for claim in evidence.claims)
    causal_withheld = [
        claim
        for claim in evidence.withheld
        if claim.kind is ClaimKind.CAUSAL_CHAIN and claim.rule_id == RULE_HOP_WITHOUT_EDGE
    ]
    assert len(causal_withheld) == 1
    assert "target->dependency" in causal_withheld[0].subject
    assert "no dependency path" in causal_withheld[0].reason

    store = open_store(tmp_path)
    seal = seal_analytics_evidence(store, analysis, run_id=RUN_ID)

    assert all(claim.kind is not ClaimKind.CAUSAL_CHAIN for claim in seal.claims)
    assert "analytics.claim.withheld" in [event.event_kind for event in seal.events]
    reloaded = verify_analytics_evidence(store, RUN_ID)
    assert reloaded.verified is True
    assert any(claim.rule_id == RULE_HOP_WITHOUT_EDGE for claim in reloaded.withheld)
    store.close()


def test_a_chain_is_sealed_with_its_edges_named_in_full(tmp_path: Path) -> None:
    """The positive half, so the withholding test above is not passing because nothing
    was ever produced: the same request against the connected graph does produce a claim,
    and its edge citation names both endpoints and its kind."""
    store, seal = sealed(tmp_path, run_search(policy()))

    chain = next(claim for claim in seal.claims if claim.kind is ClaimKind.CAUSAL_CHAIN)
    edges = [citation for citation in chain.support if isinstance(citation, EdgeCitation)]

    assert chain.subject == "net.latency"
    # Both the target→dependency hop and the metric→customer hop traverse the one
    # edge this graph has, so it is cited twice — once per hop, in the hop's own
    # order. Two citations of one edge, not two edges.
    assert [edge.key() for edge in edges] == [
        "depends_on:n-checkout->n-postgres",
        "depends_on:n-checkout->n-postgres",
    ]
    assert (edges[0].src, edges[0].dst) == ("n-checkout", "n-postgres")
    assert all(isinstance(citation, ObservationCitation) for citation in chain.observations)
    store.close()


# =======================================================================================
# Negative control: a generated candidate cannot reach execution
# =======================================================================================


def candidate_payload(**step_overrides: Any) -> dict[str, object]:
    step: dict[str, object] = {
        "index": 0,
        "value": 1.0,
        "phase": SearchPhase.ESCALATION.value,
        "combination": COMBINATION,
        "budget_ref": {"kind": QUOTA.kind.value, "label": QUOTA.label},
    }
    step.update(step_overrides)
    return {"step": step, "rationale": "the advisor suggests starting here"}


def test_a_generated_candidate_cannot_reach_execution() -> None:
    """The AI boundary (gap 25), end to end: a compiled candidate, a reviewer who
    approves it anyway, and a runner that executes nothing. Then the consequence for the
    evidence — a search that ran zero steps has nothing to seal, so its analysis produces
    a withheld boundary rather than a signed one."""
    recorder = _Recorder()
    candidate = compile_candidate(candidate_payload(), policy())
    assert candidate.origin is SearchOrigin.GENERATED

    run = run_search(
        policy(),
        origin=SearchOrigin.GENERATED,
        approve=lambda plan: Approval(approved_by="sre-oncall", plan_digest=plan.plan_digest),
        recorder=recorder,
    )

    assert "execute" not in recorder.calls
    assert run.executed == 0
    refusal = run.admissions[-1]
    assert refusal.rule_id == RULE_STEP_NOT_APPROVED
    assert RULE_GENERATED_CANNOT_BE_APPROVED in refusal.reason
    assert refusal.charged == 0.0
    # The search is recorded as the generated one it was, which is the point of putting
    # the origin in the audit record: visible, and powerless.
    assert run.record.origin is SearchOrigin.GENERATED

    evidence = analytics_evidence(analyze_run(policy(), run.history), run_id=RUN_ID)

    assert evidence.claims == ()
    assert [claim.rule_id for claim in evidence.withheld] == [RULE_EVIDENCE_UNSUPPORTED]


def test_an_approval_that_does_not_bind_still_refuses_the_step() -> None:
    """The other half of the type-level boundary: a token minted for a different plan
    digest is refused even for an authored plan, so "the reviewer approved it" cannot be
    satisfied by a digest from somewhere else."""
    recorder = _Recorder()

    run = run_search(
        policy(),
        approve=lambda plan: Approval(approved_by="sre-oncall", plan_digest="0" * 64),
        recorder=recorder,
    )

    assert "execute" not in recorder.calls
    assert run.executed == 0
    assert RULE_APPROVAL_MISMATCH in run.admissions[-1].reason


@pytest.mark.parametrize("authority_field", sorted(AUTHORITY_FIELDS))
def test_a_draft_carrying_any_authority_field_is_refused(authority_field: str) -> None:
    """Every name in the shared vocabulary, at a depth — because the obvious attack is
    the nested one. :data:`AUTHORITY_FIELDS` and
    :func:`~mayhem.controller.analytics_service._authority_keys` are unchanged by this
    phase and remain the single scan plan 21's advisor service imports; this test pins
    the behaviour rather than restating the list.
    """
    payload = candidate_payload()
    payload["meta"] = {authority_field: "sre-oncall"}

    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(payload, policy())

    assert caught.value.rule == RULE_DRAFT_CARRIES_AUTHORITY
    assert authority_field in str(caught.value)


def test_evidence_cannot_become_an_authority_channel() -> None:
    """Structural, not behavioural: neither the sealed claim nor the audit record has a
    field an approval could travel in. A caller who wants to attach an authorization to
    evidence has to write it into the audit stream, where it is checked, rather than into
    the evidence, where it would not be."""
    for record_type in (AnalyticsClaim, SearchRecord):
        names = {entry.name for entry in fields(record_type)}
        assert names.isdisjoint(AUTHORITY_FIELDS)
        assert "approval" not in names


def test_the_recorder_reads_authority_from_the_admission_not_from_a_flag() -> None:
    """``SearchRecord.approved_by`` is projected from :class:`StepAdmission`, which is
    itself derived from a token that bound to a plan digest — so the approver in the
    audit stream is a read-back of a real check, not a label a caller set."""
    run = run_search(policy())

    (approver,) = run.record.approved_by

    assert approver == "sre-oncall"
    assert {admission.approved_by for admission in run.admissions} == {"sre-oncall"}
    # And a search that never got a step admitted carries no approver at all.
    starved = run_search(policy(), remaining=0.5)
    assert starved.record.approved_by == ()
