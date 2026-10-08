"""Plan 21 Phase 2 — the advisor engine: findings from sealed inputs, incident
replay, and the road a generated candidate has to travel.

Every property asserted here is one the *engine* could get wrong while the Phase 1
arithmetic stayed perfectly correct:

* **Correlate, don't decide.** A cell the coverage record already covers, a cell
  sealed evidence already established, and a cell whose target is in no node of
  the sealed topology all produce *no* finding — and each says so by name, so the
  gap between the declared landscape and the findings is a list a reader can
  check rather than an arithmetic difference.
* **Every generated parameter traces to an incident fact.** A percentile label
  the capture never observed, an observation with nothing behind it, and a unit
  the binding did not declare are three refusals rather than three defaults,
  because a default is how a replay reproduces nothing while looking faithful.
* **Read-only is measured, not promised.** The mutation sink is *pre-loaded*
  before every analysis, so ``calls`` equalling the loaded length is evidence,
  and a hard-coded zero would fail these tests where a naive one would pass.
* **A generated candidate takes the same road as an authored one.** The compile,
  the proof, and the policy verdict come from the same three functions for both
  origins, and a candidate that will not compile never reaches the proof compiler
  or the policy gate — asserted by counting calls to both.
* **The negatives.** The advisor context has nowhere to put an execution intent
  and no handle through which to mint one; a payload carrying an approval token is
  rejected at the boundary by *plan 15's own* scan, not a second copy of it;
  advisor output is never certified evidence, and the predicate that says so is
  positive for the sealed evidence the engine reads; and a recommendation whose
  rationale does not name the criteria it was ranked by cannot render.
"""

from __future__ import annotations

import inspect
from dataclasses import fields as dataclass_fields
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.agents.sinks import LeaseSink
from mayhem.config import PolicyCfg
from mayhem.controller import advisor_service
from mayhem.controller.advisor_service import (
    ALLOWED_DRAFT_FIELDS,
    RULE_DRAFT_CARRIES_AUTHORITY,
    RULE_DRAFT_UNKNOWN_FIELD,
    RULE_NO_DECLARED_BINDINGS,
    RULE_REPLAY_INCOMPLETE,
    RULE_REPLAY_NO_USABLE_OBSERVATION,
    RULE_REPLAY_PARAMETER_UNTRACEABLE,
    RULE_REPLAY_TOPOLOGY_PIN_MISMATCH,
    RULE_REPLAY_UNIT_MISMATCH,
    RULE_REPLAY_VERSION_SUPERSEDED,
    RULE_SUBMISSION_UNTRACEABLE_PARAMETER,
    RULE_SUBMISSION_WILL_NOT_COMPILE,
    AdvisorAnalysis,
    AdvisorService,
    AdvisorSubmission,
    ParameterBinding,
    ParameterSource,
    ParameterTrace,
    ReplayRequest,
    SealedCell,
    SuppressReason,
    build_draft_payload,
    read_draft_payload,
)
from mayhem.controller.analytics_service import AUTHORITY_FIELDS as PLAN15_AUTHORITY_FIELDS
from mayhem.controller.analytics_service import compile_candidate
from mayhem.controller.safety import SafetyContext
from mayhem.domain.advisor import (
    AdvisorAuthority,
    CitedFactKind,
    CriterionReading,
    CustomerCriterion,
    ExperimentCandidate,
    IncidentFacts,
    PriorityCriteria,
    RecommendationOrigin,
    UntrustedRecommendationDraft,
    is_certified_evidence,
)
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_intent import (
    INTENT_REQUIRED,
    ExecutionIntentRefused,
    require_execution_intent,
)
from mayhem.domain.experiments import BlastRadiusBudget
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.policy import PolicyBundle, PolicyEffect
from mayhem.domain.policy_gate import MutationSink, PolicyGateInputs
from mayhem.domain.search import BudgetKind, BudgetReference, SearchPolicy
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    HostNode,
    ServiceNode,
    TopologyGraph,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mayhem.domain.advisor import Finding

# --- fixtures ---------------------------------------------------------------------

SNAPSHOT_ID = "graph-7f3c"
OTHER_SNAPSHOT_ID = "graph-9a11"
FINGERPRINT = "f" * 64
RUN_ID = "run-advisor-1"
CONFIG_SNAPSHOT_ID = "cfg-advisor-1"
SERVICE = "checkout"
DEPENDENCY = "redis-cache"
FAULT_ID = "net.latency"

#: The incident the replay tests are built from: 41s of p99 latency above 4s on
#: checkout, caused by the redis cache, observed against one pinned snapshot.
INCIDENT_DURATION_S = 41.0
P99_MS = 4200.0
P99_SAMPLES = 900


def sealed_graph() -> TopologyGraph:
    """checkout -> redis-cache, with one live container behind checkout."""
    return TopologyGraph(
        nodes=(
            ServiceNode(id=SERVICE, name=SERVICE),
            ServiceNode(id=DEPENDENCY, name=DEPENDENCY),
            ContainerNode(
                id=f"ctr-{SERVICE}",
                name=SERVICE,
                engine="docker",
                runtime_identity=RuntimeIdentity(
                    runtime="docker", host_id="h-local", runtime_id=f"cid-{SERVICE}"
                ),
                runtime_metadata=RuntimeMetadata(service=SERVICE, name=SERVICE),
                container_name=SERVICE,
                state="running",
            ),
            HostNode(id="h-local", name="local", transport="local"),
        ),
        edges=(
            Edge(src=SERVICE, dst=DEPENDENCY, kind=EdgeKind.DEPENDS_ON),
            Edge(src=f"ctr-{SERVICE}", dst=SERVICE, kind=EdgeKind.RUNS_ON),
        ),
    )


def cell(
    target: str = SERVICE,
    fault_kind: str = FAULT_ID,
    *,
    execution_context: str = "container",
    parameter_band: str = "default",
) -> CoverageCell:
    return CoverageCell(
        target=target,
        fault_kind=fault_kind,
        execution_context=execution_context,
        parameter_band=parameter_band,
    )


GAP_CELL = cell()
COVERED_CELL = cell(target="search", fault_kind="pod-churn")
UNANCHORED_CELL = cell(target="never-deployed", fault_kind="dns-failure")
SEALED_CELL = cell(target="billing", fault_kind="partition")
SEALED_CELL_KEY = SEALED_CELL.key
SEALED_DIGEST = "d" * 64


def incident(**overrides: object) -> IncidentFacts:
    """The normalised capture every replay test replays."""
    kwargs: dict[str, object] = {
        "incident_id": "inc-2026-03-04-cache-loss",
        "service": SERVICE,
        "failure_signature": "p99 latency on cache miss above 4s",
        "dependency": DEPENDENCY,
        "topology_snapshot_id": SNAPSHOT_ID,
        "duration_s": INCIDENT_DURATION_S,
        "percentiles": {
            "p99": {
                "metric": "latency",
                "value": P99_MS,
                "unit": "ms",
                "samples": P99_SAMPLES,
            },
            "p50": {"metric": "latency", "value": 90.0, "unit": "ms", "samples": 900},
        },
        "versions": {"mayhem": "1.1.0", "kubernetes": "1.29.4"},
        "started_at": "2026-03-04T09:12:00+00:00",
        "ended_at": "2026-03-04T09:18:52+00:00",
    }
    kwargs.update(overrides)
    return IncidentFacts.normalise(**kwargs)  # type: ignore[arg-type]


INCIDENT = incident()


# -- the five read ports ----------------------------------------------------------


class SealedTopology:
    """A topology port over one snapshot. Nothing here can write."""

    def __init__(self, snapshot: str = SNAPSHOT_ID, graph: TopologyGraph | None = None) -> None:
        self._snapshot = snapshot
        self._graph = graph if graph is not None else sealed_graph()

    def topology(self) -> TopologyGraph:
        return self._graph

    def snapshot_id(self) -> str:
        return self._snapshot


class SealedCoverage:
    """A coverage port over one declared landscape."""

    def __init__(
        self,
        cells: tuple[CoverageCell, ...] = (GAP_CELL, COVERED_CELL),
        states: Mapping[str, CellState] | None = None,
        landscape_id: str = "landscape-checkout-v4",
    ) -> None:
        self._cells = cells
        self._states = states
        self._landscape_id = landscape_id

    def landscape_id(self) -> str:
        return self._landscape_id

    def cells(self) -> tuple[CoverageCell, ...]:
        return self._cells

    def states(self) -> Mapping[str, CellState]:
        if self._states is not None:
            return self._states
        return {GAP_CELL.key: CellState.UNKNOWN, COVERED_CELL.key: CellState.PASSED}


class SealedIncidents:
    """An incident port over normalised captures."""

    def __init__(self, captures: tuple[IncidentFacts, ...] = (INCIDENT,)) -> None:
        self._captures = captures

    def captures(self) -> tuple[IncidentFacts, ...]:
        return self._captures


class DeployedReleases:
    """A deployment port: what is running now, per component."""

    def __init__(self, releases: Mapping[str, str] | None = None) -> None:
        self._releases = (
            releases
            if releases is not None
            else {
                "mayhem": "1.1.0",
                "kubernetes": "1.29.4",
            }
        )

    def releases(self) -> Mapping[str, str]:
        return self._releases


class SealedEvidenceLedger:
    """An evidence port over cells a sealed run already established."""

    def __init__(self, records: tuple[SealedCell, ...] = ()) -> None:
        self._records = records

    def established(self) -> tuple[SealedCell, ...]:
        return self._records


# -- the declared weighting --------------------------------------------------------

CUSTOMER_IMPACT = CustomerCriterion(
    name="customer_impact",
    weight=1.0,
    question="how many customers meet this failure in a normal week?",
)
COVERAGE_GAP = CustomerCriterion(
    name="coverage_gap",
    weight=0.25,
    question="how little of this area has ever been exercised?",
)
CRITERIA = PriorityCriteria(name="q1-customer-priorities", criteria=(CUSTOMER_IMPACT, COVERAGE_GAP))


def weight(finding: Finding) -> Mapping[str, CriterionReading]:
    """The customer's reading of one finding, against the declared criteria."""
    return {
        "customer_impact": CriterionReading(
            criterion=CUSTOMER_IMPACT,
            value=0.9,
            evidence="checkout fronts the gap on the customer path",
        ),
        "coverage_gap": CriterionReading(
            criterion=COVERAGE_GAP,
            value=0.8,
            evidence=f"{finding.cell_key} has never executed",
        ),
    }


def propose(finding: Finding) -> ExperimentCandidate:
    """A deterministic stand-in for whatever proposes candidates, human or model."""
    return ExperimentCandidate(
        experiment_id=f"exp:{finding.finding_id}",
        hypothesis=(
            f"breaking {finding.cell.fault_kind} on {finding.cell.target} does what "
            "nobody has measured"
        ),
        suggested_probes=(f"{finding.cell.fault_kind}@{finding.cell.target}",),
        stop_conditions=("p99 > 2s for 60s",),
    )


def replay_request(
    *,
    fault_id: str = FAULT_ID,
    bindings: tuple[ParameterBinding, ...] | None = None,
) -> ReplayRequest:
    return ReplayRequest(
        fault_id=fault_id,
        execution_context="container",
        parameter_band="default",
        bindings=bindings
        if bindings is not None
        else (
            ParameterBinding("seconds", ParameterSource.DURATION),
            ParameterBinding("jitter_ms", ParameterSource.PERCENTILE, label="p99", unit="ms"),
        ),
    )


def service(
    *,
    topology: SealedTopology | None = None,
    coverage: SealedCoverage | None = None,
    incidents: SealedIncidents | None = None,
    deployments: DeployedReleases | None = None,
    evidence: SealedEvidenceLedger | None = None,
    sink: MutationSink | None = None,
) -> AdvisorService:
    return AdvisorService(
        topology=topology if topology is not None else SealedTopology(),
        coverage=coverage if coverage is not None else SealedCoverage(),
        incidents=incidents if incidents is not None else SealedIncidents(),
        deployments=deployments if deployments is not None else DeployedReleases(),
        evidence=evidence if evidence is not None else SealedEvidenceLedger(),
        sink=sink,
    )


# -- the gate context -------------------------------------------------------------

T0 = datetime(2026, 3, 4, 12, 0, tzinfo=UTC)


def gate_context(*, bundle: bool = True) -> SafetyContext:
    """A safety context whose limits nothing in this file trips.

    Every per-step cap is lifted so a refusal in these tests has exactly one
    cause, and the policy bundle is present so the policy gate is genuinely
    consulted rather than reported as "no bundle configured".
    """
    inputs = None
    if bundle:
        inputs = PolicyGateInputs(
            bundle=PolicyBundle(
                bundle_id="advisor-test",
                version=1,
                rules=(),
                default_effect=PolicyEffect.ALLOW,
                created_at=T0 - timedelta(days=1),
            ),
            now=T0,
            experiment_id=f"exp:replay:{INCIDENT.incident_id}",
            run_id=RUN_ID,
        )
    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=2**31 - 1,
            max_concurrent_faults=2**31 - 1,
            max_duration_per_fault_s=float("inf"),
            forbidden_fault_pairs=frozenset(),
        ),
        fingerprint=FINGERPRINT,
        policy_gate=inputs,
    )


# -- analysis over sealed inputs ---------------------------------------------------


def test_a_gap_cell_in_the_sealed_landscape_becomes_a_cited_finding() -> None:
    report = service().analyse(propose, CRITERIA, weight)

    assert len(report.findings) == 1
    found = report.findings[0]
    assert found.cell.key == GAP_CELL.key
    assert found.cell_state is CellState.UNKNOWN
    kinds = [fact.kind for fact in found.cited_facts]
    assert CitedFactKind.COVERAGE_CELL in kinds
    assert CitedFactKind.TOPOLOGY_SNAPSHOT in kinds
    assert [f.ref for f in found.cited_facts if f.kind is CitedFactKind.TOPOLOGY_NODE] == [
        SERVICE,
        DEPENDENCY,
    ]


def test_a_finding_cites_the_incident_that_observed_the_same_service() -> None:
    report = service().analyse(propose, CRITERIA, weight)

    incident_citations = [
        f for f in report.findings[0].cited_facts if f.kind is CitedFactKind.INCIDENT
    ]
    assert [f.ref for f in incident_citations] == [INCIDENT.incident_id]
    assert DEPENDENCY in report.findings[0].topology_node_ids


def test_the_analysis_emits_drafts_and_nothing_with_authority() -> None:
    report = service().analyse(propose, CRITERIA, weight)

    assert all(isinstance(draft, UntrustedRecommendationDraft) for draft in report.drafts)
    assert all("approval" not in UntrustedRecommendationDraft.model_fields for _ in report.drafts)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})
    assert [r.origin for r in ranked] == [RecommendationOrigin.GENERATED]
    assert [r.authority for r in ranked] == [AdvisorAuthority.NONE]


def test_a_covered_cell_produces_no_finding_and_names_why() -> None:
    """``PASSED`` is coverage, and a regression is not a gap either.

    Both refusals belong to the domain's ``GAP_STATES`` and to plan 22's
    comparison vocabulary. Re-deciding them here would give one event two owners,
    and a triage queue that spends its time disproving its own findings is a
    triage queue nobody trusts.
    """
    report = service().analyse(propose, CRITERIA, weight)

    suppressed = report.suppressed_for(SuppressReason.NOT_A_GAP_STATE)
    assert [s.cell_key for s in suppressed] == [COVERED_CELL.key]
    assert "passed" in suppressed[0].detail
    assert all(f.cell.key != COVERED_CELL.key for f in report.findings)


def test_a_cell_sealed_evidence_established_is_not_an_uncovered_failure_mode() -> None:
    """Evidence is read to *withhold* work, and the withholding is visible."""
    sealed = SealedCell(
        cell_key=GAP_CELL.key, evidence_digest=SEALED_DIGEST, run_label="exp:prior@1.1.0#run-9"
    )
    report = service(
        evidence=SealedEvidenceLedger((sealed,)),
        coverage=SealedCoverage(cells=(GAP_CELL,), states={GAP_CELL.key: CellState.UNKNOWN}),
    ).analyse(propose, CRITERIA, weight)

    assert report.findings == ()
    assert report.drafts == ()
    suppressed = report.suppressed_for(SuppressReason.ESTABLISHED_BY_SEALED_EVIDENCE)
    assert [s.cell_key for s in suppressed] == [GAP_CELL.key]
    assert SEALED_DIGEST[:12] in suppressed[0].detail
    assert "exp:prior@1.1.0#run-9" in suppressed[0].detail
    assert any("sealed evidence" in note for note in report.notes)


def test_a_cell_whose_target_is_in_no_topology_node_is_refused_not_guessed() -> None:
    """A finding must cite the nodes its failure would travel through."""
    report = service(
        coverage=SealedCoverage(
            cells=(UNANCHORED_CELL,), states={UNANCHORED_CELL.key: CellState.UNKNOWN}
        )
    ).analyse(propose, CRITERIA, weight)

    assert report.findings == ()
    suppressed = report.suppressed_for(SuppressReason.TARGET_NOT_IN_TOPOLOGY)
    assert [s.cell_key for s in suppressed] == [UNANCHORED_CELL.key]
    assert UNANCHORED_CELL.target in suppressed[0].detail


def test_every_declared_cell_is_either_a_finding_or_a_named_suppression() -> None:
    """The honesty half: the gap between the landscape and the findings is a list."""
    cells = (GAP_CELL, COVERED_CELL, UNANCHORED_CELL, SEALED_CELL)
    sealed = SealedCell(
        cell_key=SEALED_CELL_KEY, evidence_digest=SEALED_DIGEST, run_label="exp:prior#run-1"
    )
    report = service(
        coverage=SealedCoverage(cells=cells, states={c.key: CellState.UNKNOWN for c in cells}),
        evidence=SealedEvidenceLedger((sealed,)),
    ).analyse(propose, CRITERIA, weight)

    accounted = {f.cell.key for f in report.findings} | {s.cell_key for s in report.suppressed}
    assert accounted == {c.key for c in cells}
    assert len(report.findings) == 1
    assert {s.reason for s in report.suppressed} == {
        SuppressReason.ESTABLISHED_BY_SEALED_EVIDENCE,
        SuppressReason.TARGET_NOT_IN_TOPOLOGY,
    }


def test_a_topology_snapshot_with_no_identity_is_refused() -> None:
    """Without a snapshot id every finding would be pinned to a graph nobody can name."""
    with pytest.raises(InvariantViolationError) as caught:
        service(topology=SealedTopology(snapshot="  ")).analyse(propose, CRITERIA, weight)

    assert caught.value.rule == RULE_REPLAY_TOPOLOGY_PIN_MISMATCH
    assert "snapshot id" in str(caught.value)


def test_the_analysis_is_a_pure_function_of_the_sealed_inputs() -> None:
    first = service().analyse(propose, CRITERIA, weight)
    second = service().analyse(propose, CRITERIA, weight)

    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]
    assert first.graph_identity == second.graph_identity
    assert [d.to_dict() for d in first.drafts] == [d.to_dict() for d in second.drafts]


# -- traceability and declared weighting -------------------------------------------


def test_a_recommendation_cites_its_finding_and_every_declared_weighting() -> None:
    report = service().analyse(propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})

    rendered = ranked[0].render()
    for name in CRITERIA.names:
        assert name in rendered
    assert "- finding: " in rendered
    assert f"- incident: {INCIDENT.incident_id}" in rendered


def test_priority_is_the_weighted_mean_of_the_declared_criteria() -> None:
    report = service().analyse(propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})

    # 1.0*0.9 + 0.25*0.8 = 1.10 over a declared total weight of 1.25
    assert ranked[0].priority.weighted_sum == pytest.approx(1.10)
    assert ranked[0].priority.total == pytest.approx(1.10 / 1.25)


def test_changing_the_declared_weighting_changes_the_priority() -> None:
    """A priority is a function of the *declared* weights, not a stored score."""
    report = service().analyse(propose, CRITERIA, weight)
    readings = {f.finding_id: dict(weight(f)) for f in report.findings}
    declared = report.rank(CRITERIA, readings)

    heavier_gap = PriorityCriteria(
        name="q1-customer-priorities",
        criteria=(
            CUSTOMER_IMPACT,
            CustomerCriterion(
                name="coverage_gap",
                weight=4.0,
                question="how untested is this area?",
            ),
        ),
    )
    reweighed = report.rank(
        heavier_gap,
        {
            f.finding_id: {
                "customer_impact": readings[f.finding_id]["customer_impact"],
                "coverage_gap": CriterionReading(
                    criterion=heavier_gap.criteria[1],
                    value=0.8,
                    evidence=f"{f.cell_key} has never executed",
                ),
            }
            for f in report.findings
        },
    )

    assert declared[0].total != pytest.approx(reweighed[0].total)
    assert reweighed[0].total < declared[0].total  # a heavier low score pulls it down


def test_a_finding_the_caller_cannot_weigh_is_refused_rather_than_dropped() -> None:
    """The engine proposes nothing for work that was going to be rejected anyway."""
    with pytest.raises(InvariantViolationError) as caught:
        service().analyse(propose, CRITERIA, lambda _finding: {})

    assert caught.value.rule == "advisor.criterion_not_read"
    assert "coverage_gap" in str(caught.value)


def test_the_analysis_supplies_no_priority_of_its_own() -> None:
    """Nothing the engine emits carries a score, a weight, or a criteria list."""
    stored = {f.name for f in dataclass_fields(AdvisorAnalysis)}
    assert "priority" not in stored
    assert "weights" not in stored
    assert "score" not in stored

    report = service().analyse(propose, CRITERIA, weight)
    for _draft in report.drafts:
        assert set(UntrustedRecommendationDraft.model_fields) == {
            "recommendation_id",
            "finding",
            "candidate",
            "rationale",
        }


# -- incident replay ----------------------------------------------------------------


def replay(service_: AdvisorService | None = None, captured: IncidentFacts | None = None):
    """Compile the fixture incident through the engine's replay compiler."""
    engine = service_ if service_ is not None else service()
    return engine.replay(
        replay_request(),
        captured if captured is not None else INCIDENT,
        engine.landscape(),
    )


def test_replay_produces_a_candidate_whose_every_parameter_traces_to_an_incident_fact() -> None:
    compiled = replay()

    assert compiled.parameters == (
        ParameterTrace(
            parameter="seconds",
            value=INCIDENT_DURATION_S,
            unit="s",
            source="incident.duration_s",
            incident_id=INCIDENT.incident_id,
            detail=compiled.parameters[0].detail,
        ),
        ParameterTrace(
            parameter="jitter_ms",
            value=P99_MS,
            unit="ms",
            source='incident.percentile("p99")',
            incident_id=INCIDENT.incident_id,
            detail=compiled.parameters[1].detail,
        ),
    )
    assert {trace.source for trace in compiled.parameters} <= {
        "incident.duration_s",
        'incident.percentile("p99")',
    }
    assert all(trace.incident_id == INCIDENT.incident_id for trace in compiled.parameters)
    assert compiled.parameter_values == {"seconds": INCIDENT_DURATION_S, "jitter_ms": P99_MS}


def test_a_parameter_trace_with_no_source_fact_is_not_constructible() -> None:
    """Traceability is a constructor rule, so a trace to nowhere cannot exist."""
    with pytest.raises(InvariantViolationError) as caught:
        ParameterTrace(
            parameter="seconds", value=41.0, unit="s", source="  ", incident_id=INCIDENT.incident_id
        )

    assert caught.value.rule == RULE_REPLAY_PARAMETER_UNTRACEABLE
    assert "invents none" in str(caught.value)


def test_a_replay_cites_the_incident_in_its_candidate_and_its_stop_conditions() -> None:
    compiled = replay()
    candidate = compiled.candidate

    assert candidate.experiment_id == f"exp:replay:{INCIDENT.incident_id}"
    assert INCIDENT.failure_signature in candidate.hypothesis
    assert INCIDENT.service in candidate.hypothesis
    assert candidate.suggested_probes == (f"{FAULT_ID}@{DEPENDENCY}",)
    assert any(f"{P99_MS:g}ms" in stop for stop in candidate.stop_conditions)
    assert any(f"{INCIDENT_DURATION_S:g}s" in stop for stop in candidate.stop_conditions)


def test_a_replay_is_pinned_to_the_incidents_topology_snapshot() -> None:
    compiled = replay()

    assert compiled.topology_snapshot_id == INCIDENT.topology_snapshot_id
    assert compiled.graph_identity == service().graph_identity()
    assert compiled.finding.graph_identity == compiled.graph_identity
    assert compiled.cell.key != ""


def test_a_replay_pinned_to_another_snapshot_is_refused() -> None:
    """Replaying against a different graph reproduces a different incident."""
    captured = incident(topology_snapshot_id=OTHER_SNAPSHOT_ID)
    engine = service()  # the port still reports the snapshot it read
    with pytest.raises(InvariantViolationError) as caught:
        engine.replay(replay_request(), captured, engine.landscape())

    assert caught.value.rule == RULE_REPLAY_TOPOLOGY_PIN_MISMATCH
    assert "different graph" in str(caught.value)
    assert OTHER_SNAPSHOT_ID in str(caught.value)


def test_a_replay_cannot_be_pinned_after_the_fact() -> None:
    """The pin is checked twice: on the way in and in the type it lands in."""
    compiled = replay()
    with pytest.raises(InvariantViolationError) as caught:
        replace(compiled, topology_snapshot_id=OTHER_SNAPSHOT_ID)

    assert caught.value.rule == RULE_REPLAY_TOPOLOGY_PIN_MISMATCH


def test_a_replay_whose_versions_have_been_superseded_is_refused() -> None:
    """A replay runs against whatever happens to be deployed — the one thing to avoid."""
    engine = service(deployments=DeployedReleases({"mayhem": "1.2.0"}))
    with pytest.raises(InvariantViolationError) as caught:
        engine.replay(replay_request(), INCIDENT, engine.landscape())

    assert caught.value.rule == RULE_REPLAY_VERSION_SUPERSEDED
    assert "incident pinned 1.1.0, deployed 1.2.0" in str(caught.value)


def test_a_component_the_deployment_record_does_not_name_is_not_a_supersession() -> None:
    """An absent component is the absence of evidence, not evidence of movement."""
    engine = service(deployments=DeployedReleases({"kubernetes": "1.29.4"}))

    assert engine.replay(replay_request(), INCIDENT, engine.landscape()).fault_id == FAULT_ID


def test_an_untraceable_parameter_is_refused_not_defaulted() -> None:
    """A percentile label the capture never observed has no fact behind it."""
    engine = service()
    request = replay_request(
        bindings=(
            ParameterBinding("jitter_ms", ParameterSource.PERCENTILE, label="p999", unit="ms"),
        )
    )
    with pytest.raises(InvariantViolationError) as caught:
        engine.replay(request, INCIDENT, engine.landscape())

    assert caught.value.rule == RULE_REPLAY_PARAMETER_UNTRACEABLE
    assert "never observed" in str(caught.value)
    assert "not a substitute" in str(caught.value)


def test_an_observation_with_nothing_behind_it_cannot_carry_a_parameter() -> None:
    """``samples == 0`` is the domain saying "observed once, or not at all"."""
    # p50 stands behind its observation, so the capture *is* replayable; p99 is
    # the one that was observed without anything behind it.
    captured = incident(
        percentiles={
            "p99": {"metric": "latency", "value": P99_MS, "unit": "ms", "samples": 0},
            "p50": {"metric": "latency", "value": 90.0, "unit": "ms", "samples": 900},
        }
    )
    engine = service()
    with pytest.raises(InvariantViolationError) as caught:
        engine.replay(
            replay_request(
                bindings=(
                    ParameterBinding(
                        "jitter_ms", ParameterSource.PERCENTILE, label="p99", unit="ms"
                    ),
                )
            ),
            captured,
            engine.landscape(),
        )

    assert caught.value.rule == RULE_REPLAY_PARAMETER_UNTRACEABLE
    assert "0 time(s)" in str(caught.value)
    assert "dress an absence up as a measurement" in str(caught.value)


def test_a_replay_with_no_usable_observation_is_refused() -> None:
    """A replay whose stop condition cannot be built on a measurement cannot stop."""
    captured = incident(
        percentiles={"p99": {"metric": "latency", "value": P99_MS, "unit": "ms", "samples": 0}}
    )
    engine = service()
    with pytest.raises(InvariantViolationError) as caught:
        engine.replay(
            replay_request(bindings=(ParameterBinding("seconds", ParameterSource.DURATION),)),
            captured,
            engine.landscape(),
        )

    assert caught.value.rule == RULE_REPLAY_NO_USABLE_OBSERVATION


def test_a_unit_mismatch_is_refused_rather_than_translated() -> None:
    """A latency in milliseconds cannot quietly become a count in seconds."""
    engine = service()
    request = replay_request(
        bindings=(ParameterBinding("seconds", ParameterSource.PERCENTILE, label="p99", unit="s"),)
    )
    with pytest.raises(InvariantViolationError) as caught:
        engine.replay(request, INCIDENT, engine.landscape())

    assert caught.value.rule == RULE_REPLAY_UNIT_MISMATCH
    assert "reproduces a different incident" in str(caught.value)


def test_a_binding_that_names_no_unit_is_refused_at_construction() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        ParameterBinding("jitter_ms", ParameterSource.PERCENTILE, label="p99")

    assert caught.value.rule == RULE_REPLAY_UNIT_MISMATCH


def test_a_binding_must_read_exactly_one_fact() -> None:
    """A duration binding that also carries a label could be read two ways."""
    with pytest.raises(InvariantViolationError) as caught:
        ParameterBinding("seconds", ParameterSource.DURATION, label="p99")

    assert caught.value.rule == RULE_REPLAY_PARAMETER_UNTRACEABLE
    assert "exactly one fact" in str(caught.value)


def test_a_replay_with_no_declared_bindings_is_refused() -> None:
    """Otherwise every value would be a catalog default wearing the incident's name."""
    engine = service()
    with pytest.raises(InvariantViolationError) as caught:
        engine.replay(replay_request(bindings=()), INCIDENT, engine.landscape())

    assert caught.value.rule == RULE_NO_DECLARED_BINDINGS
    assert "reproduces" in str(caught.value)


def test_a_replay_request_must_declare_the_cell_it_replays() -> None:
    for missing in ("fault_id", "execution_context", "parameter_band"):
        kwargs = {
            "fault_id": FAULT_ID,
            "execution_context": "container",
            "parameter_band": "default",
            "bindings": (ParameterBinding("seconds", ParameterSource.DURATION),),
        }
        kwargs[missing] = "  "  # type: ignore[literal-required]
        with pytest.raises(InvariantViolationError) as caught:
            ReplayRequest(**kwargs)  # type: ignore[arg-type]
        assert caught.value.rule == RULE_REPLAY_INCOMPLETE


def test_a_replay_binding_the_same_parameter_twice_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        ReplayRequest(
            fault_id=FAULT_ID,
            execution_context="container",
            parameter_band="default",
            bindings=(
                ParameterBinding("seconds", ParameterSource.DURATION),
                ParameterBinding("seconds", ParameterSource.PERCENTILE, label="p99", unit="ms"),
            ),
        )

    assert caught.value.rule == RULE_REPLAY_INCOMPLETE
    assert "twice" in str(caught.value)


def test_two_replays_of_one_incident_are_one_value() -> None:
    """Normalisation order does not change the replay, so a diff does not fire on it."""
    reordered = incident(
        percentiles={
            "p50": {"metric": "latency", "value": 90.0, "unit": "ms", "samples": 900},
            "p99": {
                "metric": "latency",
                "value": P99_MS,
                "unit": "ms",
                "samples": P99_SAMPLES,
            },
        },
        versions={"kubernetes": "1.29.4", "mayhem": "1.1.0"},
    )

    assert replay(service(), reordered).replay_digest == replay().replay_digest


def test_a_replay_that_changes_a_parameter_is_a_different_value() -> None:
    engine = service()
    slower = incident(
        percentiles={
            "p99": {
                "metric": "latency",
                "value": P99_MS * 2,
                "unit": "ms",
                "samples": P99_SAMPLES,
            }
        },
        versions={"mayhem": "1.1.0"},
    )

    assert engine.replay(replay_request(), slower, engine.landscape()).replay_digest != (
        replay().replay_digest
    )


def test_a_replay_digest_covers_the_capture_the_cell_and_every_value() -> None:
    payload = replay().to_dict()

    assert payload["incident_id"] == INCIDENT.incident_id
    assert payload["topology_snapshot_id"] == SNAPSHOT_ID
    assert [p["parameter"] for p in payload["parameters"]] == ["seconds", "jitter_ms"]  # type: ignore[index]
    assert payload["replay_digest"] == replay().replay_digest


# -- read-only by construction ------------------------------------------------------


def test_the_advisor_context_holds_no_mutation_backend_and_no_lease_sink() -> None:
    """The structural half of the boundary, checked against the field list itself.

    Every field is a read port, the inert :class:`MutationSink`, or the engine's
    own value types. There is no statement handle, no lease client, no agent sink
    and no executor, so "analysis code never acquires execution authority" is a
    property of the signature.
    """
    field_types = {f.name: f.type for f in dataclass_fields(AdvisorService)}

    assert set(field_types) == {
        "topology",
        "coverage",
        "incidents",
        "deployments",
        "evidence",
        "sink",
    }
    for name, annotation in field_types.items():
        text = str(annotation)
        assert "Store" not in text, name
        assert "LeaseSink" not in text, name
        assert "LeaseClient" not in text, name
        assert "Executor" not in text, name
        assert "Connection" not in text, name
    assert field_types["sink"] in {
        "MutationSink | None",
        "mayhem.domain.policy_gate.MutationSink | None",
    }


def test_the_ports_expose_reads_and_nothing_else() -> None:
    """Each port is a Protocol whose whole surface is a read."""
    for port in (
        service().topology,
        service().coverage,
        service().incidents,
        service().deployments,
        service().evidence,
    ):
        for name, member in vars(type(port)).items():
            if name.startswith("_"):
                continue
            assert callable(member), (port, name)
            assert not any(
                verb in name for verb in ("write", "save", "record", "delete", "commit", "insert")
            ), (port, name)


def test_the_analysis_runs_through_a_service_with_no_mutation_sink() -> None:
    loaded = MutationSink().record("k8s", "inject fault")
    engine = service(sink=loaded)

    detached = engine.detached()

    assert detached.sink is None
    assert engine.sink is loaded  # the caller's own handle is untouched, still readable


def test_the_analysis_mutates_nothing_and_the_report_is_a_measurement() -> None:
    """The sink is *pre-loaded*, so a reported zero can only mean "added nothing".

    A hard-coded ``calls = 0`` would pass a naive version of this test and fail
    here, which is the whole point of reading the length off a real object.
    """
    loaded = MutationSink().record("lease", "acquire run lease").record("k8s", "inject net.latency")
    assert len(loaded) == 2

    report = service(sink=loaded).analyse(propose, CRITERIA, weight)

    assert report.purity.backend_attached is False
    assert report.purity.calls == 2  # the two we loaded, not zero, and not three
    assert report.purity.calls_detail == (
        ("lease", "acquire run lease"),
        ("k8s", "inject net.latency"),
    )
    assert len(loaded) == 2  # the analysis added nothing


def test_the_analysis_with_no_caller_sink_reports_zero_and_says_so() -> None:
    report = service().analyse(propose, CRITERIA, weight)

    assert report.purity.calls == 0
    assert report.purity.calls_detail == ()
    assert "backend detached" in report.describe()


def test_the_analysis_reports_the_same_purity_on_every_repeat() -> None:
    loaded = MutationSink().record("lease", "acquire")

    engine = service(sink=loaded)
    first = engine.analyse(propose, CRITERIA, weight)
    second = engine.analyse(propose, CRITERIA, weight)

    assert first.purity == second.purity
    assert len(loaded) == 1


def test_replay_and_submission_are_read_only_too() -> None:
    loaded = MutationSink().record("lease", "acquire")
    engine = service(sink=loaded)
    compiled = engine.replay(replay_request(), INCIDENT, engine.landscape())

    assert compiled.parameters  # the work happened
    assert len(loaded) == 1  # and nothing was written through the sink


# -- generated candidates take the authored road ------------------------------------


def submitted(
    engine: AdvisorService | None = None, *, traces: tuple[ParameterTrace, ...] | None = None
) -> AdvisorSubmission:
    """The fixture incident, replayed and taken all the way to a policy verdict."""
    resolved = engine if engine is not None else service()
    report = resolved.analyse(propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})
    compiled = resolved.replay(replay_request(), INCIDENT, resolved.landscape())
    return resolved.submit(
        ranked[0],
        gate_context(),
        fault_id=compiled.fault_id,
        target=SERVICE,
        duration_s=compiled.duration_s,
        parameters=compiled.parameter_values,
        traces=compiled.parameters if traces is None else traces,
        run_id=RUN_ID,
        config_snapshot_id=CONFIG_SNAPSHOT_ID,
        environment_fingerprint=FINGERPRINT,
    )


def test_a_generated_recommendation_reaches_the_proof_and_the_policy_gate() -> None:
    submission = submitted()

    assert submission.recommendation.origin is RecommendationOrigin.GENERATED
    assert submission.recommendation.authority is AdvisorAuthority.NONE
    assert submission.plan.steps  # a frozen plan exists
    assert submission.plan.topology_snapshot_id == SNAPSHOT_ID
    assert submission.plan_digest == submission.compilation.plan_digest
    assert submission.policy is not None
    assert submission.policy_allowed is True
    assert "policy: allowed" in submission.describe()


def test_an_authored_recommendation_takes_the_identical_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same function, same order, same three artifacts — for both origins.

    The stage sequence is asserted rather than the digest, and the reason is
    worth stating: ``plan_drill`` stamps a fresh ``execution_group_id`` per
    container fault, so two runs of the *same* plan never share a plan digest.
    Comparing digests would therefore be a weak assertion that could only ever
    pass by accident of the planner's randomness. What must match is *which*
    stages ran, in what order, and what came out of them.
    """
    assert "origin" not in inspect.signature(AdvisorService.submit).parameters
    assert "generated" not in inspect.signature(AdvisorService.submit).parameters

    stages: list[str] = []
    original_proof = advisor_service.compile_safety_evidence
    original_policy = advisor_service.simulate_plan_policy

    def traced_proof(*args: object, **kwargs: object) -> object:
        stages.append("proof")
        return original_proof(*args, **kwargs)  # type: ignore[arg-type]

    def traced_policy(*args: object, **kwargs: object) -> object:
        stages.append("policy")
        return original_policy(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("mayhem.controller.advisor_service.compile_safety_evidence", traced_proof)
    monkeypatch.setattr("mayhem.controller.advisor_service.simulate_plan_policy", traced_policy)

    generated = submitted()
    assert stages == ["proof", "policy"]
    generated_stages = list(stages)
    stages.clear()

    authored = replace(generated.recommendation, origin=RecommendationOrigin.AUTHORED)
    assert authored.authority is AdvisorAuthority.NONE  # flipping the origin grants nothing
    engine = service()
    same = engine.submit(
        authored,
        gate_context(),
        fault_id=FAULT_ID,
        target=SERVICE,
        duration_s=INCIDENT_DURATION_S,
        parameters=replay().parameter_values,
        run_id=RUN_ID,
        config_snapshot_id=CONFIG_SNAPSHOT_ID,
        environment_fingerprint=FINGERPRINT,
    )

    assert stages == generated_stages == ["proof", "policy"]
    assert same.recommendation.origin is RecommendationOrigin.AUTHORED
    assert same.proof_verdict == generated.proof_verdict
    assert same.policy_allowed == generated.policy_allowed
    assert same.plan.topology_snapshot_id == generated.plan.topology_snapshot_id
    assert [step.fault.fault_id for step in same.plan.steps if step.fault] == [
        step.fault.fault_id for step in generated.plan.steps if step.fault
    ]
    assert [step.fault.params for step in same.plan.steps if step.fault] == [
        step.fault.params for step in generated.plan.steps if step.fault
    ]
    assert set(same.to_dict()) == set(generated.to_dict())


def test_the_proof_of_a_generated_plan_is_not_claimed_to_pass() -> None:
    """No adapter means the capability line is unestablished, and the proof says so.

    This is the honest answer rather than a disappointing one: the advisor read
    sealed inputs and has no live runtime to ask what the cluster can do, so the
    capability line is ``VOID`` and the verdict with it. A proof that reached
    ``PASS`` here would mean the compiler had invented a capability answer.
    """
    submission = submitted()

    assert submission.proof_verdict == "VOID"
    assert "capability_requirements" in submission.compilation.void_reason
    assert submission.admitted_by_gate is True
    assert submission.compilation.gate_refusals == ()


def test_a_candidate_that_will_not_compile_never_reaches_the_proof_or_the_policy_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal order, asserted by counting calls to both downstream stages."""
    calls: list[str] = []

    def spy(name: str):
        def _spy(*args: object, **kwargs: object) -> object:
            calls.append(name)
            raise AssertionError(f"{name} must not be reached by a draft that will not compile")

        return _spy

    monkeypatch.setattr("mayhem.controller.advisor_service.compile_safety_evidence", spy("proof"))
    monkeypatch.setattr("mayhem.controller.advisor_service.simulate_plan_policy", spy("policy"))

    engine = service()
    report = engine.analyse(propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})

    with pytest.raises(InvariantViolationError) as caught:
        engine.submit(
            ranked[0],
            gate_context(),
            fault_id="net.not-a-catalog-fault",
            target=SERVICE,
            duration_s=INCIDENT_DURATION_S,
            parameters={},
            run_id=RUN_ID,
            config_snapshot_id=CONFIG_SNAPSHOT_ID,
            environment_fingerprint=FINGERPRINT,
        )

    assert caught.value.rule == RULE_SUBMISSION_WILL_NOT_COMPILE
    assert "not in catalog" in str(caught.value)
    assert calls == []


def test_a_submission_for_a_target_that_is_not_in_the_graph_never_reaches_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        "mayhem.controller.advisor_service.compile_safety_evidence",
        lambda *a, **k: calls.append("proof"),
    )
    monkeypatch.setattr(
        "mayhem.controller.advisor_service.simulate_plan_policy",
        lambda *a, **k: calls.append("policy"),
    )
    engine = service()
    report = engine.analyse(propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})

    with pytest.raises(InvariantViolationError) as caught:
        engine.submit(
            ranked[0],
            gate_context(),
            fault_id=FAULT_ID,
            target="a-container-that-does-not-exist",
            duration_s=INCIDENT_DURATION_S,
            parameters={},
            run_id=RUN_ID,
            config_snapshot_id=CONFIG_SNAPSHOT_ID,
            environment_fingerprint=FINGERPRINT,
        )

    assert caught.value.rule == RULE_SUBMISSION_WILL_NOT_COMPILE
    assert "not found in topology" in str(caught.value)
    assert calls == []


def test_a_generated_parameter_that_is_not_traced_is_refused_at_the_door() -> None:
    engine = service()
    report = engine.analyse(propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})
    compiled = engine.replay(replay_request(), INCIDENT, engine.landscape())

    with pytest.raises(InvariantViolationError) as caught:
        engine.submit(
            ranked[0],
            gate_context(),
            fault_id=FAULT_ID,
            target=SERVICE,
            duration_s=compiled.duration_s,
            parameters={**compiled.parameter_values, "jitter_pct": 12.0},
            traces=compiled.parameters,
            run_id=RUN_ID,
            config_snapshot_id=CONFIG_SNAPSHOT_ID,
            environment_fingerprint=FINGERPRINT,
        )

    assert caught.value.rule == RULE_SUBMISSION_UNTRACEABLE_PARAMETER
    assert "jitter_pct" in str(caught.value)


def test_a_trace_that_names_one_value_while_another_travels_is_refused() -> None:
    engine = service()
    report = engine.analyse(propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})
    compiled = engine.replay(replay_request(), INCIDENT, engine.landscape())

    with pytest.raises(InvariantViolationError) as caught:
        engine.submit(
            ranked[0],
            gate_context(),
            fault_id=FAULT_ID,
            target=SERVICE,
            duration_s=compiled.duration_s,
            parameters={**compiled.parameter_values, "jitter_ms": 1.0},
            traces=compiled.parameters,
            run_id=RUN_ID,
            config_snapshot_id=CONFIG_SNAPSHOT_ID,
            environment_fingerprint=FINGERPRINT,
        )

    assert caught.value.rule == RULE_SUBMISSION_UNTRACEABLE_PARAMETER
    assert "disagree with their trace" in str(caught.value)


def test_a_submission_grants_no_authority_of_its_own() -> None:
    submission = submitted()
    stored = {f.name for f in dataclass_fields(AdvisorSubmission)}

    assert "approval" not in stored
    assert "intent" not in stored
    assert "execution_intent" not in stored
    assert "run_id" not in stored
    assert submission.recommendation.approval is None
    assert submission.to_dict()["recommendation"]["authority"] == "none"


# -- negative controls ---------------------------------------------------------------


def test_the_advisor_context_cannot_mint_execution_intent() -> None:
    """The penetration-style control, in three parts.

    1. Structurally: no type the engine emits has a field an
       :class:`~mayhem.domain.execution_intent.ExecutionIntent` could be stored
       in, and ``ExecutionIntent.from_dict`` is a permissive constructor — it
       would happily build an intent out of *anything* with a ``plan_hash`` — so
       the absence of a field is the only thing standing between an advisor and
       an approval.
    2. The real gate refuses: with no intent supplied, asking to execute the plan
       the advisor just compiled is refused with
       :data:`~mayhem.domain.execution_intent.INTENT_REQUIRED`, and knowing the
       plan digest does not help, because the digest is not the token.
    3. Nothing in the engine can supply one: :meth:`AdvisorService.submit` takes
       no intent argument, and the proof compiler's own ``required_approvals``
       line records that no intent was presented and that the grant is bound
       later, against the proof digest — the advisor's own opinion is nowhere in
       that line.
    """
    submission = submitted()
    report = service().analyse(propose, CRITERIA, weight)
    compiled = replay()

    for artifact in (
        report,
        report.findings[0],
        report.drafts[0],
        submission,
        submission.plan,
        compiled,
        compiled.candidate,
    ):
        for name in ("intent", "execution_intent", "approval", "approved_by"):
            assert not hasattr(artifact, name), (type(artifact).__name__, name)
        assert (
            not any("intent" in str(f.name) for f in dataclass_fields(type(artifact)))
            if (hasattr(type(artifact), "__dataclass_fields__"))
            else True
        )

    with pytest.raises(ExecutionIntentRefused) as caught:
        require_execution_intent(
            None, plan_hash=submission.plan_digest, engine="docker", target_identity=SERVICE
        )

    assert caught.value.code == INTENT_REQUIRED
    assert "execution is an approved act" in str(caught.value)
    # And the submission cannot be talked into carrying one.
    assert "intent" not in inspect.signature(AdvisorService.submit).parameters
    required = submission.compilation.proof.obligation("required_approvals")
    assert required is not None
    assert "no intent presented at compile time" in required.detail.lower()
    assert "advisor" not in required.detail.lower()


@pytest.mark.parametrize("authority_field", sorted(PLAN15_AUTHORITY_FIELDS))
def test_a_payload_carrying_an_authority_field_is_rejected_at_the_boundary(
    authority_field: str,
) -> None:
    payload = build_draft_payload(
        recommendation_id="rec:1", finding_id="finding:1", rationale="r", hypothesis="h"
    )
    payload[authority_field] = {"approved_by": "sre-oncall", "recommendation_digest": "0" * 64}

    with pytest.raises(InvariantViolationError) as caught:
        read_draft_payload(payload)

    assert caught.value.rule == RULE_DRAFT_CARRIES_AUTHORITY
    assert authority_field in str(caught.value)


def test_a_nested_approval_token_is_rejected_before_any_field_is_read() -> None:
    """The obvious attack is a nested one, so the scan is over the whole payload."""
    payload = build_draft_payload(
        recommendation_id="rec:1", finding_id="finding:1", rationale="", hypothesis="h"
    )
    payload["meta"] = {"approved_by": "sre-oncall"}

    with pytest.raises(InvariantViolationError) as caught:
        read_draft_payload(payload)

    # The blank ``rationale`` would also be refused; the authority scan runs
    # first, which is the difference between "this tried to be an approval" and
    # "this happened to be malformed".
    assert caught.value.rule == RULE_DRAFT_CARRIES_AUTHORITY
    assert "meta.approved_by" in str(caught.value)


def test_the_authority_scan_is_plan15s_and_not_a_second_copy() -> None:
    """Reuse, asserted: one vocabulary of authority keys, not two that can drift."""
    from mayhem.controller import analytics_service

    payload = build_draft_payload(
        recommendation_id="rec:1", finding_id="finding:1", rationale="r", hypothesis="h"
    )
    payload["meta"] = {"token": "abc", "nested": {"authorization": "bearer x"}}

    assert analytics_service.AUTHORITY_FIELDS is PLAN15_AUTHORITY_FIELDS
    assert sorted(PLAN15_AUTHORITY_FIELDS) == sorted(
        {"approval", "approved_by", "authority", "plan_digest", "authorization", "token"}
    )
    assert sorted(analytics_service._authority_keys(payload)) == sorted(_scanned(payload))
    # And the very same payload is refused by plan 15's own compiler.
    with pytest.raises(InvariantViolationError) as caught:
        compile_candidate(payload, _search_policy())
    assert caught.value.rule == analytics_service.RULE_DRAFT_CARRIES_AUTHORITY


def _search_policy() -> SearchPolicy:
    """The minimal search policy plan 15's compiler validates a payload against."""
    return SearchPolicy(
        name="advisor-test",
        budget_ref=BudgetReference(kind=BudgetKind.STEPS, label="advisor-replay"),
    )


def _scanned(payload: Mapping[str, object]) -> set[str]:
    """The keys the reused scan reports, read through this module's alias."""
    from mayhem.controller.advisor_service import authority_keys

    return authority_keys(payload)


def test_the_advisor_payload_vocabulary_holds_no_authority_or_execution_field() -> None:
    assert ALLOWED_DRAFT_FIELDS.isdisjoint(PLAN15_AUTHORITY_FIELDS)
    assert ALLOWED_DRAFT_FIELDS.isdisjoint(
        {"execute", "intent", "run_id", "weight", "weights", "priority", "criteria", "score"}
    )
    assert not any("intent" in field for field in ALLOWED_DRAFT_FIELDS)


def test_an_unknown_payload_field_is_refused_rather_than_ignored() -> None:
    payload = build_draft_payload(
        recommendation_id="rec:1", finding_id="finding:1", rationale="r", hypothesis="h"
    )
    payload["priority"] = 0.99

    with pytest.raises(InvariantViolationError) as caught:
        read_draft_payload(payload)

    assert caught.value.rule == RULE_DRAFT_UNKNOWN_FIELD
    assert "priority" in str(caught.value)


def test_a_blank_payload_field_is_refused() -> None:
    payload = build_draft_payload(
        recommendation_id="rec:1", finding_id="finding:1", rationale="r", hypothesis="  "
    )
    with pytest.raises(InvariantViolationError) as caught:
        read_draft_payload(payload)

    assert caught.value.rule == RULE_DRAFT_UNKNOWN_FIELD


def test_a_clean_payload_is_read_without_complaint() -> None:
    payload = build_draft_payload(
        recommendation_id="rec:1",
        finding_id="finding:1",
        rationale="checkout cache loss is uncovered on the customer path",
        hypothesis="breaking net.latency does what nobody has measured",
    )

    assert read_draft_payload(payload) == (
        "rec:1",
        "checkout cache loss is uncovered on the customer path",
        "breaking net.latency does what nobody has measured",
    )


def test_advisor_output_is_never_treated_as_certified_evidence() -> None:
    """The negative control — and the predicate is positive for real evidence.

    Everything the engine emits is a correlation: it has no verdict, so it can
    never be sealed. The one certified-evidence value in this file is the
    :class:`SealedCell` the evidence port handed the engine, and it is used only
    to *withhold* a finding.
    """
    report = service().analyse(propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})
    compiled = replay()
    sealed = SealedCell(
        cell_key=SEALED_CELL_KEY, evidence_digest=SEALED_DIGEST, run_label="exp:prior#run-1"
    )

    for claim in (
        report,
        report.findings[0],
        report.drafts[0],
        ranked[0],
        compiled,
        compiled.candidate,
        compiled.finding,
        submitted(),
        sealed,
    ):
        assert is_certified_evidence(claim) is (
            claim is sealed  # the only sealed thing here is real evidence
        )
    assert is_certified_evidence(sealed) is True
    assert "evidence_digest" not in vars(AdvisorAnalysis)
    assert not hasattr(report, "evidence_digest")
    assert not hasattr(compiled.candidate, "evidence_digest")


def test_a_sealed_cell_carrying_an_unverifiable_digest_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        SealedCell(cell_key=GAP_CELL.key, evidence_digest="not-a-digest", run_label="exp#run-1")

    assert caught.value.rule == RULE_REPLAY_INCOMPLETE


def test_a_recommendation_without_a_traceable_rationale_cannot_render() -> None:
    """Prose the draft owns is not checkable by itself, so the view layer refuses."""
    report = service().analyse(propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})
    untraceable = replace(ranked[0], rationale="checkout cache loss is worth fixing")

    assert untraceable.priority.criteria_names  # the weighting it omits
    assert untraceable.render_refusal_reason() != ""
    with pytest.raises(InvariantViolationError) as caught:
        untraceable.render()

    assert caught.value.rule == "advisor.recommendation_rationale_not_traceable"
    assert "customer_impact" in str(caught.value)


def test_a_traceable_rationale_renders_with_its_citations_and_no_authority() -> None:
    report = service().analyse(propose, CRITERIA, weight)
    rendered = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})[
        0
    ].render()

    assert "authority: none" in rendered
    assert "origin: generated" in rendered
    assert "cites:" in rendered
    for name in CRITERIA.names:
        assert name in rendered


def test_a_replay_cannot_be_built_without_its_facts() -> None:
    """Deleting a cited fact deletes the replay, the way it deletes a recommendation."""
    compiled = replay()

    with pytest.raises(InvariantViolationError) as caught:
        replace(compiled, parameters=())

    assert caught.value.rule == RULE_NO_DECLARED_BINDINGS

    with pytest.raises(InvariantViolationError) as caught:
        replace(compiled, duration_s=INCIDENT_DURATION_S + 1.0)

    assert caught.value.rule == RULE_REPLAY_INCOMPLETE
    assert "stop condition" in str(caught.value)


def test_the_replay_types_cannot_be_built_from_an_incident_that_is_not_a_replay_cell() -> None:
    compiled = replay()

    with pytest.raises(InvariantViolationError) as caught:
        replace(compiled, cell=COVERED_CELL)

    assert caught.value.rule == RULE_REPLAY_INCOMPLETE
    assert "one fact, not two" in str(caught.value)


def test_the_engine_reads_evidence_and_holds_no_lease_sink() -> None:
    """Evidence is a read; a lease is not reachable at all.

    :class:`mayhem.agents.sinks.LeaseSink` is the one Protocol in the tree whose
    whole surface is writes and reads of fault leases, and it is named here to
    state what the engine is *not*: none of the five ports presents ``save``,
    ``load``, ``active_leases`` or ``next_sequence``, and the engine carries no
    field to pass one to.
    """
    field_names = {f.name for f in dataclass_fields(AdvisorService)}
    assert {"topology", "coverage", "incidents", "deployments", "evidence"} <= field_names
    assert not hasattr(AdvisorAnalysis, "evidence_digest")

    lease_surface = {
        name for name in vars(LeaseSink) if not name.startswith("_") and name != "next_sequence"
    }
    assert lease_surface  # the Protocol is not empty — the comparison means something
    for port in (
        service().topology,
        service().coverage,
        service().incidents,
        service().deployments,
        service().evidence,
    ):
        assert lease_surface.isdisjoint(vars(type(port)))
