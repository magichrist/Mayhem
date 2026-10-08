"""Advisor findings, recommendations, and incident facts: traceability, declared
criteria, and the AI boundary that has to be a type (plan 21, Phase 1).

The negative controls are the reason this module exists in this shape:

* a finding cannot be constructed without its coverage cell and its topology, so
  "a finding with no facts" is a ``TypeError`` rather than a convention;
* a priority is the weighted mean of *declared* weights and has no score field,
  so an opaque ranking cannot be written, injected, or carried across a change
  of weighting;
* a recommendation that does not name the criteria it was ranked by cannot
  render — the view layer refuses rather than degrades;
* a generated draft has nowhere to put an approval token, cannot supply its own
  weights, and compiles into a recommendation that refuses an approval outright;
* deleting a cited fact deletes the recommendation, and deleting a fact while
  leaving its readings behind is *refused* rather than silently dropped;
* advisor output is not certified evidence, and the predicate that says so is
  positive for a value that genuinely carries a sealed digest.
"""

from __future__ import annotations

from dataclasses import fields as dataclass_fields
from math import isfinite
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from mayhem.domain.advisor import (
    RULE_APPROVAL_MISMATCH,
    RULE_APPROVAL_WITHOUT_AN_APPROVER,
    RULE_CANDIDATE_INCOMPLETE,
    RULE_CRITERIA_HAVE_NO_WEIGHT,
    RULE_CRITERION_NOT_DECLARED,
    RULE_CRITERION_NOT_READ,
    RULE_CRITERION_VALUE_OUT_OF_RANGE,
    RULE_CRITERION_WITHOUT_EVIDENCE,
    RULE_CRITERION_WITHOUT_QUESTION,
    RULE_DUPLICATE_CRITERION,
    RULE_FINDING_CELL_IS_NOT_A_GAP,
    RULE_FINDING_CELL_NOT_IN_LANDSCAPE,
    RULE_FINDING_NOT_READ,
    RULE_FINDING_UNEXPLAINED,
    RULE_FINDING_UNNAMED,
    RULE_FINDING_WITHOUT_TOPOLOGY,
    RULE_GENERATED_CANNOT_BE_APPROVED,
    RULE_INCIDENT_DURATION_INVALID,
    RULE_INCIDENT_WITHOUT_IDENTITY,
    RULE_INCIDENT_WITHOUT_OBSERVATION,
    RULE_INCIDENT_WITHOUT_TOPOLOGY_PIN,
    RULE_INCIDENT_WITHOUT_VERSION_PINS,
    RULE_LANDSCAPE_DUPLICATE_CELL,
    RULE_LANDSCAPE_EMPTY,
    RULE_LANDSCAPE_UNIDENTIFIED,
    RULE_NO_DECLARED_CRITERIA,
    RULE_OBSERVED_VALUE_NOT_FINITE,
    RULE_PREDICTION_DIGEST_INVALID,
    RULE_READING_FOR_UNKNOWN_FINDING,
    RULE_RECOMMENDATION_RATIONALE_NOT_TRACEABLE,
    RULE_RECOMMENDATION_UNNAMED,
    AdvisorAuthority,
    Approval,
    CitedFact,
    CitedFactKind,
    CoverageLandscape,
    CriterionReading,
    CustomerCriterion,
    ExperimentCandidate,
    Finding,
    IncidentFacts,
    ObservedPercentile,
    Priority,
    PriorityCriteria,
    Recommendation,
    RecommendationOrigin,
    UntrustedRecommendationDraft,
    is_certified_evidence,
    rank_drafts,
    recommendations_for,
)
from mayhem.domain.comparison import RunPin
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.errors import InvariantViolationError

if TYPE_CHECKING:
    from collections.abc import Mapping

GRAPH_ID = "a" * 64
INCIDENT_ID = "inc-2026-03-04-cache-loss"
SNAPSHOT_ID = "graph-7f3c"

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
BLAST_REACH = CustomerCriterion(
    name="blast_reach",
    weight=0.5,
    question="how far does the damage reach from what we would target?",
)

CRITERIA = PriorityCriteria(
    name="q1-customer-priorities",
    criteria=(CUSTOMER_IMPACT, COVERAGE_GAP, BLAST_REACH),
)


def cell(target: str = "checkout", fault: str = "cache-loss") -> CoverageCell:
    return CoverageCell(
        target=target,
        fault_kind=fault,
        execution_context="container",
        parameter_band="default",
    )


#: The declared cells a finding may cite in these tests. Anything outside it is
#: the "nonexistent cell" case.
DECLARED_CELLS = (
    cell(),
    cell(target="payments", fault="dns-failure"),
    cell(target="search", fault="pod-churn"),
    cell(target="auth", fault="certificate-expiry"),
    cell(target="billing", fault="partition"),
)
LANDSCAPE = CoverageLandscape(landscape_id="landscape-checkout-v4", cells=DECLARED_CELLS)


def incident(**overrides: object) -> IncidentFacts:
    """A normalised capture of a cache-loss incident on checkout."""
    kwargs: dict[str, object] = {
        "incident_id": INCIDENT_ID,
        "service": "checkout",
        "failure_signature": "p99 latency on cache miss above 4s",
        "dependency": "redis-cache",
        "topology_snapshot_id": SNAPSHOT_ID,
        "duration_s": 412.0,
        "percentiles": {
            "p99": {"metric": "latency", "value": 4200.0, "unit": "ms", "samples": 900},
            "p50": {"metric": "latency", "value": 90.0, "unit": "ms", "samples": 900},
        },
        "versions": {"mayhem": "1.1.0", "kubernetes": "1.29.4"},
        "started_at": "2026-03-04T09:12:00+00:00",
        "ended_at": "2026-03-04T09:18:52+00:00",
    }
    kwargs.update(overrides)
    return IncidentFacts.normalise(**kwargs)  # type: ignore[arg-type]


def finding(finding_id: str = "F1", **overrides: object) -> Finding:
    """A gap on one declared coverage cell, anchored in one topology snapshot."""
    kwargs: dict[str, object] = {
        "finding_id": finding_id,
        "failure_mode": "total cache loss with no warm replica",
        "summary": "nothing has established how checkout behaves when the cache is gone",
        "cell": cell(),
        "cell_state": CellState.UNKNOWN,
        "landscape": LANDSCAPE,
        "topology_node_ids": ("checkout", "redis-cache"),
        "graph_identity": GRAPH_ID,
        "incident": incident(),
    }
    kwargs.update(overrides)
    return Finding(**kwargs)  # type: ignore[arg-type]


def readings_for(values: Mapping[str, float] | None = None) -> dict[str, CriterionReading]:
    """A complete set of readings keyed by the declared criterion names."""
    scores = {"customer_impact": 0.9, "coverage_gap": 0.2, "blast_reach": 0.5}
    scores.update(values or {})
    evidence = {
        "customer_impact": "three services front the gap on the customer path",
        "coverage_gap": "the cell has never executed",
        "blast_reach": "damage reaches one dependency hop from the target",
    }
    return {
        name: CriterionReading(criterion=criterion, value=scores[name], evidence=evidence[name])
        for name, criterion in (
            ("customer_impact", CUSTOMER_IMPACT),
            ("coverage_gap", COVERAGE_GAP),
            ("blast_reach", BLAST_REACH),
        )
    }


def propose(f: Finding) -> ExperimentCandidate:
    """A deterministic stand-in for whatever proposes candidates, human or model."""
    return ExperimentCandidate(
        experiment_id=f"exp-{f.finding_id.lower()}",
        hypothesis=f"breaking {f.cell.fault_kind} on {f.cell.target} does what nobody has measured",
        suggested_probes=(f"cache-loss@{f.cell.target}",),
        stop_conditions=("p99 > 2s for 60s",),
        impact_prediction_digest="b" * 64,
    )


def recommendation(**overrides: object) -> Recommendation:
    """A generated recommendation for ``F1`` built through the normal path."""
    kwargs: dict[str, object] = {
        "recommendation_id": "rec:F1",
        "finding": finding(),
        "candidate": propose(finding()),
        "priority": Priority.from_readings(CRITERIA, readings_for()),
        "rationale": Priority.from_readings(CRITERIA, readings_for()).rationale,
        "origin": RecommendationOrigin.GENERATED,
    }
    kwargs.update(overrides)
    return Recommendation(**kwargs)  # type: ignore[arg-type]


# -- findings ---------------------------------------------------------------------


def test_a_finding_carries_the_coverage_fact_that_makes_it_a_gap() -> None:
    gap = finding()

    assert gap.cell_state is CellState.UNKNOWN
    assert gap.cell_key == gap.cell.key
    assert "cache-loss" in gap.cell_key


def test_a_finding_cites_its_coverage_cell_and_its_topology() -> None:
    gap = finding()

    kinds = [fact.kind for fact in gap.cited_facts]
    assert CitedFactKind.COVERAGE_CELL in kinds
    assert CitedFactKind.TOPOLOGY_SNAPSHOT in kinds
    assert [f.ref for f in gap.cited_facts if f.kind is CitedFactKind.TOPOLOGY_NODE] == [
        "checkout",
        "redis-cache",
    ]
    assert all(fact.detail for fact in gap.cited_facts)


def test_a_finding_cites_the_incident_that_makes_it_urgent() -> None:
    gap = finding()
    orphan = finding(incident=None)

    incident_facts = [f for f in gap.cited_facts if f.kind is CitedFactKind.INCIDENT]
    assert [f.ref for f in incident_facts] == [INCIDENT_ID]
    # An incident corroborates; it is not the basis. A gap without one is still a gap.
    assert not [f for f in orphan.cited_facts if f.kind is CitedFactKind.INCIDENT]
    assert len(orphan.cited_facts) == len(gap.cited_facts) - 1


def test_a_finding_without_its_coverage_fact_does_not_compile() -> None:
    """The enforcement is the constructor signature, not a validator.

    ``cell``/``cell_state`` have no defaults, so "a finding that cites no
    coverage cell" cannot be spelled — a caller cannot satisfy the requirement
    with ``None`` and have a reviewer wave it through.
    """
    with pytest.raises(TypeError):
        Finding(  # type: ignore[call-arg]
            finding_id="F1",
            failure_mode="total cache loss",
            summary="nothing established",
            cell_state=CellState.UNKNOWN,
            landscape=LANDSCAPE,
            topology_node_ids=("checkout",),
            graph_identity=GRAPH_ID,
        )


def test_a_finding_without_its_topology_fact_does_not_compile() -> None:
    with pytest.raises(TypeError):
        Finding(  # type: ignore[call-arg]
            finding_id="F1",
            failure_mode="total cache loss",
            summary="nothing established",
            cell=cell(),
            cell_state=CellState.UNKNOWN,
            landscape=LANDSCAPE,
            graph_identity=GRAPH_ID,
        )


def test_a_finding_citing_a_nonexistent_coverage_cell_is_refused() -> None:
    """The negative control: a cell that is in no declared landscape is not a fact.

    ``CoverageCell`` is a four-part value, so ``cell()`` can always be typed — the
    landscape is what makes "this cell exists" a checkable claim rather than a
    plausible-looking key nobody can look up.
    """
    undeclared = cell(target="checkout", fault="quantum-decoherence")

    assert undeclared.key not in LANDSCAPE
    with pytest.raises(InvariantViolationError) as caught:
        finding(cell=undeclared)

    assert caught.value.rule == RULE_FINDING_CELL_NOT_IN_LANDSCAPE
    assert "not a coverage fact" in str(caught.value)


def test_a_cell_outside_the_landscape_is_not_a_member_of_it() -> None:
    assert cell() in LANDSCAPE
    assert cell(target="nowhere", fault="never-declared") not in LANDSCAPE
    assert "checkout" not in LANDSCAPE  # membership is by cell, not by target string


def test_an_empty_or_duplicate_landscape_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        CoverageLandscape(landscape_id="empty", cells=())
    assert caught.value.rule == RULE_LANDSCAPE_EMPTY

    with pytest.raises(InvariantViolationError) as caught:
        CoverageLandscape(landscape_id="dupes", cells=(cell(), cell()))
    assert caught.value.rule == RULE_LANDSCAPE_DUPLICATE_CELL

    with pytest.raises(InvariantViolationError) as caught:
        CoverageLandscape(landscape_id="  ", cells=(cell(),))
    assert caught.value.rule == RULE_LANDSCAPE_UNIDENTIFIED


def test_a_covered_cell_is_not_an_uncovered_failure_mode() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        finding(cell_state=CellState.PASSED)

    assert caught.value.rule == RULE_FINDING_CELL_IS_NOT_A_GAP
    assert "a passed cell is covered" in str(caught.value)


def test_a_failed_cell_is_a_regression_not_a_gap() -> None:
    """A failure that was observed and graded belongs to plan 22's vocabulary.

    Raising it here too would give one event two owners, and the triage queue
    would spend its time disproving findings that were never gaps.
    """
    with pytest.raises(InvariantViolationError) as caught:
        finding(cell_state=CellState.FAILED)

    assert caught.value.rule == RULE_FINDING_CELL_IS_NOT_A_GAP
    assert "regression" in str(caught.value)


def test_a_finding_with_no_topology_nodes_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        finding(topology_node_ids=())

    assert caught.value.rule == RULE_FINDING_WITHOUT_TOPOLOGY


def test_a_finding_with_a_blank_topology_node_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        finding(topology_node_ids=("checkout", "  "))

    assert caught.value.rule == RULE_FINDING_WITHOUT_TOPOLOGY
    assert "unnamed node" in str(caught.value)


def test_a_finding_with_no_graph_identity_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        finding(graph_identity="")

    assert caught.value.rule == RULE_FINDING_WITHOUT_TOPOLOGY


def test_an_unnamed_finding_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        finding(finding_id="   ")

    assert caught.value.rule == RULE_FINDING_UNNAMED


def test_a_finding_with_no_explanation_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        finding(summary="")

    assert caught.value.rule == RULE_FINDING_UNEXPLAINED

    with pytest.raises(InvariantViolationError):
        finding(failure_mode="")


def test_every_gap_state_is_representable() -> None:
    """The refusal is on non-gap states only — the vocabulary is not narrowed away."""
    for state in (
        CellState.UNKNOWN,
        CellState.PLANNED,
        CellState.BLOCKED,
        CellState.SKIPPED,
        CellState.INCONCLUSIVE,
    ):
        assert finding(cell_state=state).cell_state is state


# -- declared criteria and the arithmetic -----------------------------------------


def test_criteria_with_no_declared_criteria_are_refused() -> None:
    """The negative control: a priority needs a declared basis, and there is no default one."""
    with pytest.raises(InvariantViolationError) as caught:
        PriorityCriteria(name="q1", criteria=())

    assert caught.value.rule == RULE_NO_DECLARED_CRITERIA
    assert "ranking with no basis" in str(caught.value)


def test_an_empty_criteria_declaration_cannot_even_be_defaulted() -> None:
    with pytest.raises(TypeError):
        PriorityCriteria(name="q1")  # type: ignore[call-arg]


def test_a_criteria_declaration_with_no_weight_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        PriorityCriteria(
            name="q1",
            criteria=(
                CustomerCriterion(name="customer_impact", weight=0.0, question="q"),
                CustomerCriterion(name="coverage_gap", weight=0.0, question="q"),
            ),
        )

    assert caught.value.rule == RULE_CRITERIA_HAVE_NO_WEIGHT


def test_a_duplicate_criterion_name_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        PriorityCriteria(
            name="q1",
            criteria=(
                CustomerCriterion(name="customer_impact", weight=1.0, question="q"),
                CustomerCriterion(name="customer_impact", weight=0.5, question="q"),
            ),
        )

    assert caught.value.rule == RULE_DUPLICATE_CRITERION


def test_a_criterion_must_state_the_customer_question_it_answers() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        CustomerCriterion(name="customer_impact", weight=1.0, question="  ")

    assert caught.value.rule == RULE_CRITERION_WITHOUT_QUESTION
    assert "opaque ranking" in str(caught.value)


def test_a_non_finite_or_negative_weight_is_refused() -> None:
    for weight in (float("inf"), float("nan"), -0.5):
        with pytest.raises(InvariantViolationError) as caught:
            CustomerCriterion(name="customer_impact", weight=weight, question="q")
        assert caught.value.rule == RULE_CRITERIA_HAVE_NO_WEIGHT


def test_priority_is_the_weighted_mean_of_the_declared_weights() -> None:
    priority = Priority.from_readings(CRITERIA, readings_for())

    # 1.0*0.9 + 0.25*0.2 + 0.5*0.5 = 1.20 over a declared total weight of 1.75
    assert priority.weighted_sum == pytest.approx(1.20)
    assert priority.total_weight == pytest.approx(1.75)
    assert priority.total == pytest.approx(1.20 / 1.75)


def test_priority_is_a_pure_function_of_the_declared_weights() -> None:
    """The same readings under a different declared weighting give a different score."""
    base = Priority.from_readings(CRITERIA, readings_for())
    heavier_gap = Priority.from_readings(
        CRITERIA,
        {
            **readings_for(),
            "coverage_gap": CriterionReading(
                criterion=CustomerCriterion(
                    name="coverage_gap", weight=4.0, question="how untested is this area?"
                ),
                value=0.2,
                evidence="the cell has never executed",
            ),
        },
    )

    assert base.total != pytest.approx(heavier_gap.total)
    assert heavier_gap.total < base.total  # a heavier, low-scoring criterion pulls it down


def test_a_priority_stores_no_score_to_inject_or_freeze() -> None:
    """There is no number in the type, so an opaque score cannot be written into one."""
    stored = {f.name for f in dataclass_fields(Priority)}

    assert stored == {"criteria_name", "readings"}
    assert "total" not in stored
    assert "score" not in stored
    assert "rank" not in stored


def test_a_priority_with_no_readings_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        Priority(criteria_name="q1", readings=())

    assert caught.value.rule == RULE_NO_DECLARED_CRITERIA


def test_a_reading_for_an_undeclared_criterion_is_refused() -> None:
    """The negative control: a weight invented at the last minute cannot be weighed."""
    undeclared = CustomerCriterion(name="vibes", weight=5.0, question="does it feel right?")

    with pytest.raises(InvariantViolationError) as caught:
        Priority.from_readings(
            CRITERIA,
            {**readings_for(), "vibes": CriterionReading(undeclared, 1.0, "the room felt it")},
        )

    assert caught.value.rule == RULE_CRITERION_NOT_DECLARED
    assert "nobody agreed to it" in str(caught.value)


def test_a_declared_criterion_with_no_reading_is_refused() -> None:
    """A criterion the author can drop is a criterion they can always lose points on."""
    partial = readings_for()
    del partial["blast_reach"]

    with pytest.raises(InvariantViolationError) as caught:
        Priority.from_readings(CRITERIA, partial)

    assert caught.value.rule == RULE_CRITERION_NOT_READ
    assert "blast_reach" in str(caught.value)


def test_a_reading_without_evidence_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        CriterionReading(criterion=CUSTOMER_IMPACT, value=0.9, evidence="  ")

    assert caught.value.rule == RULE_CRITERION_WITHOUT_EVIDENCE


@pytest.mark.parametrize("value", [-0.1, 1.1, float("inf"), float("nan")])
def test_a_reading_outside_the_unit_interval_is_refused(value: float) -> None:
    with pytest.raises(InvariantViolationError) as caught:
        CriterionReading(criterion=CUSTOMER_IMPACT, value=value, evidence="three services")

    assert caught.value.rule == RULE_CRITERION_VALUE_OUT_OF_RANGE
    assert not isfinite(value) or value in (-0.1, 1.1)


def test_the_priority_rationale_names_every_criterion_and_its_fact() -> None:
    priority = Priority.from_readings(CRITERIA, readings_for())

    for name in CRITERIA.names:
        assert name in priority.rationale
    assert "three services front the gap" in priority.rationale
    assert "q1-customer-priorities" in priority.rationale
    assert "0.686" in priority.rationale  # 1.20 / 1.75, rendered not stored


# -- incident facts ---------------------------------------------------------------


def test_an_incident_capture_carries_the_declared_observations() -> None:
    captured = incident()

    assert captured.service == "checkout"
    assert captured.failure_signature.startswith("p99 latency")
    assert captured.dependency == "redis-cache"
    assert captured.topology_snapshot_id == SNAPSHOT_ID
    assert captured.duration_s == pytest.approx(412.0)
    assert captured.version("mayhem") == "1.1.0"
    assert captured.percentile("p99") is not None
    assert captured.percentile("p99").value == pytest.approx(4200.0)  # type: ignore[union-attr]
    assert captured.started_at and captured.ended_at


def test_normalisation_is_order_independent() -> None:
    """Two captures of one incident assembled in different orders are one value."""
    reordered = incident(
        percentiles={
            "p50": {"metric": "latency", "value": 90.0, "unit": "ms", "samples": 900},
            "p99": {"metric": "latency", "value": 4200.0, "unit": "ms", "samples": 900},
        },
        versions={"kubernetes": "1.29.4", "mayhem": "1.1.0"},
    )

    assert reordered == incident()
    assert [p.label for p in reordered.percentiles] == ["p50", "p99"]
    assert [v.component for v in reordered.versions] == ["kubernetes", "mayhem"]
    assert reordered.to_dict() == incident().to_dict()


def test_an_incident_with_no_observed_percentiles_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        incident(percentiles={})

    assert caught.value.rule == RULE_INCIDENT_WITHOUT_OBSERVATION
    assert "anecdote" in str(caught.value)


def test_an_incident_with_no_version_pins_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        incident(versions={})

    assert caught.value.rule == RULE_INCIDENT_WITHOUT_VERSION_PINS


def test_an_incident_with_no_topology_pin_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        incident(topology_snapshot_id="  ")

    assert caught.value.rule == RULE_INCIDENT_WITHOUT_TOPOLOGY_PIN
    assert "different graph" in str(caught.value)


def test_an_unidentified_incident_is_refused() -> None:
    for field in ("incident_id", "service", "failure_signature", "dependency"):
        with pytest.raises(InvariantViolationError) as caught:
            incident(**{field: "  "})
        assert caught.value.rule == RULE_INCIDENT_WITHOUT_IDENTITY


def test_a_non_finite_observed_percentile_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        ObservedPercentile(label="p99", metric="latency", value=float("nan"), unit="ms", samples=3)

    assert caught.value.rule == RULE_OBSERVED_VALUE_NOT_FINITE

    with pytest.raises(InvariantViolationError):
        incident(percentiles={"p99": {"metric": "latency", "value": float("inf"), "samples": 3}})


def test_a_capture_refuses_a_value_that_is_not_a_number() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        incident(percentiles={"p99": {"metric": "latency", "value": "4200", "samples": 3}})

    assert caught.value.rule == RULE_OBSERVED_VALUE_NOT_FINITE
    assert "normalised, not guessed at" in str(caught.value)


def test_a_negative_incident_duration_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        incident(duration_s=-1.0)

    assert caught.value.rule == RULE_INCIDENT_DURATION_INVALID
    assert "cannot stop" in str(caught.value)


def test_an_observation_with_no_samples_says_so_instead_of_reading_as_measured() -> None:
    observed = ObservedPercentile(label="p99", metric="latency", value=4200.0, unit="ms", samples=0)

    assert observed.usable is False
    assert observed.to_dict()["samples"] == 0
    assert (
        ObservedPercentile(label="p99", metric="latency", value=4200.0, unit="ms", samples=1).usable
        is True
    )


# -- candidates and recommendations ------------------------------------------------


def test_a_candidate_without_an_id_or_a_hypothesis_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        ExperimentCandidate(experiment_id="", hypothesis="break it")

    assert caught.value.rule == RULE_CANDIDATE_INCOMPLETE

    with pytest.raises(InvariantViolationError):
        ExperimentCandidate(experiment_id="exp-1", hypothesis="   ")


def test_a_candidate_cites_the_impact_prediction_rather_than_recomputing_it() -> None:
    candidate = ExperimentCandidate(
        experiment_id="exp-1",
        hypothesis="h",
        impact_prediction_digest="c" * 64,
    )

    assert candidate.to_dict()["impact_prediction_digest"] == "c" * 64

    with pytest.raises(InvariantViolationError) as caught:
        ExperimentCandidate(
            experiment_id="exp-1", hypothesis="h", impact_prediction_digest="not-a-digest"
        )

    assert caught.value.rule == RULE_PREDICTION_DIGEST_INVALID


def test_a_recommendation_cannot_be_built_without_its_finding() -> None:
    with pytest.raises(TypeError):
        Recommendation(  # type: ignore[call-arg]
            recommendation_id="rec:F1",
            candidate=propose(finding()),
            priority=Priority.from_readings(CRITERIA, readings_for()),
            rationale="r",
        )


def test_a_recommendation_cites_its_finding_and_every_criterion_reading() -> None:
    rec = recommendation()

    kinds = [fact.kind for fact in rec.cited_facts]
    assert kinds[0] is CitedFactKind.FINDING
    assert rec.cited_facts[0].ref == "F1"
    assert [f.ref for f in rec.cited_facts if f.kind is CitedFactKind.CRITERION_READING] == list(
        CRITERIA.names
    )
    # The finding's own citations travel with it, so the chain is one value deep.
    assert [f for f in rec.cited_facts if f.kind is CitedFactKind.TOPOLOGY_NODE]


def test_a_recommendation_with_no_rationale_is_refused_at_construction() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        recommendation(rationale="   ")

    assert caught.value.rule == RULE_RECOMMENDATION_RATIONALE_NOT_TRACEABLE


def test_a_recommendation_with_no_traceable_rationale_cannot_render() -> None:
    """The negative control: prose that never mentions the weighting is not shown.

    It constructs — the rationale is prose, and prose is the advisor's job — but
    the view layer refuses it, because a reader cannot check a sentence against a
    weighting the sentence does not name.
    """
    untraceable = recommendation(rationale="checkout cache loss is worth fixing")

    assert untraceable.priority.criteria_names  # the weighting it omits
    assert untraceable.render_refusal_reason() != ""

    with pytest.raises(InvariantViolationError) as caught:
        untraceable.render()

    assert caught.value.rule == RULE_RECOMMENDATION_RATIONALE_NOT_TRACEABLE
    assert "customer_impact" in str(caught.value)


def test_a_traceable_rationale_renders_with_its_citations() -> None:
    rendered = recommendation().render()

    assert "rec:F1" in rendered
    assert "authority: none" in rendered
    assert "origin: generated" in rendered
    assert "cites:" in rendered
    assert "- finding: F1" in rendered
    for name in CRITERIA.names:
        assert name in rendered


def test_an_unnamed_recommendation_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        recommendation(recommendation_id=" ")

    assert caught.value.rule == RULE_RECOMMENDATION_UNNAMED


def test_an_unapproved_recommendation_carries_no_authority() -> None:
    assert recommendation().approval is None
    assert recommendation().authority is AdvisorAuthority.NONE
    assert recommendation().to_dict()["authority"] == "none"


# -- traceability -----------------------------------------------------------------


def test_removing_a_cited_fact_deletes_the_recommendation() -> None:
    """Plan 21's acceptance criterion, as a property of the two pure functions."""
    first, second = finding("F1"), finding("F2", cell=cell(target="payments", fault="dns-failure"))
    all_readings = {
        "F1": readings_for(),
        "F2": readings_for({"customer_impact": 0.4}),
    }
    drafts = recommendations_for((first, second), CRITERIA, all_readings, propose=propose)

    ranked = rank_drafts(drafts, CRITERIA, all_readings)
    assert [r.recommendation_id for r in ranked] == ["rec:F1", "rec:F2"]

    # Delete the fact, and its recommendation is not produced.
    without_first = {"F2": all_readings["F2"]}
    surviving = rank_drafts(
        tuple(d for d in drafts if d.finding.finding_id != "F1"), CRITERIA, without_first
    )
    assert [r.recommendation_id for r in surviving] == ["rec:F2"]


def test_deleting_a_fact_but_leaving_its_readings_is_refused() -> None:
    """The other half: it is refused rather than quietly dropped on the floor."""
    first, second = finding("F1"), finding("F2", cell=cell(target="payments", fault="dns-failure"))
    all_readings = {"F1": readings_for(), "F2": readings_for({"customer_impact": 0.4})}
    drafts = recommendations_for((first, second), CRITERIA, all_readings, propose=propose)

    with pytest.raises(InvariantViolationError) as caught:
        rank_drafts(
            tuple(d for d in drafts if d.finding.finding_id != "F1"),
            CRITERIA,
            all_readings,
        )

    assert caught.value.rule == RULE_READING_FOR_UNKNOWN_FINDING
    assert "F1" in str(caught.value)


def test_a_finding_with_no_readings_is_refused_rather_than_skipped() -> None:
    first, second = finding("F1"), finding("F2", cell=cell(target="payments", fault="dns-failure"))

    with pytest.raises(InvariantViolationError) as caught:
        recommendations_for((first, second), CRITERIA, {"F2": readings_for()}, propose=propose)

    assert caught.value.rule == RULE_FINDING_NOT_READ
    assert "F1" in str(caught.value)


def test_recommendations_are_ranked_by_the_declared_priority_with_deterministic_ties() -> None:
    low = finding("F-low", cell=cell(target="search", fault="pod-churn"))
    high = finding("F-high", cell=cell(target="checkout", fault="cache-loss"))
    tied_a = finding("F-a", cell=cell(target="auth", fault="certificate-expiry"))
    tied_b = finding("F-b", cell=cell(target="billing", fault="partition"))
    weights = {
        "F-low": readings_for({"customer_impact": 0.1, "blast_reach": 0.1}),
        "F-high": readings_for({"customer_impact": 1.0, "blast_reach": 1.0}),
        "F-a": readings_for({"customer_impact": 0.5, "blast_reach": 0.5}),
        "F-b": readings_for({"customer_impact": 0.5, "blast_reach": 0.5}),
    }
    findings_in = (tied_a, low, high, tied_b)

    drafts = recommendations_for(findings_in, CRITERIA, weights, propose=propose)
    ranked = rank_drafts(drafts, CRITERIA, weights)

    assert [r.recommendation_id for r in ranked] == [
        "rec:F-high",
        "rec:F-a",
        "rec:F-b",
        "rec:F-low",
    ]
    assert ranked[0].total > ranked[-1].total
    assert ranked[1].total == pytest.approx(ranked[2].total)  # the tie is a real tie


def test_ranking_is_a_pure_function_of_its_inputs() -> None:
    gap = finding()
    weights = {"F1": readings_for()}

    drafts = recommendations_for((gap,), CRITERIA, weights, propose=propose)

    first = rank_drafts(drafts, CRITERIA, weights)
    second = rank_drafts(drafts, CRITERIA, weights)

    assert [r.to_dict() for r in first] == [r.to_dict() for r in second]


def test_an_empty_landscape_produces_no_recommendations() -> None:
    assert recommendations_for((), CRITERIA, {}, propose=propose) == ()
    assert rank_drafts((), CRITERIA, {}) == ()


# -- the AI boundary ---------------------------------------------------------------


def test_the_machine_path_can_only_emit_drafts() -> None:
    """Plan 21's analysis emits findings and *draft* candidates, never approvals."""
    gap = finding()
    weights = {"F1": readings_for()}

    drafts = recommendations_for((gap,), CRITERIA, weights, propose=propose)
    ranked = rank_drafts(drafts, CRITERIA, weights)

    assert all(isinstance(draft, UntrustedRecommendationDraft) for draft in drafts)
    assert all(rec.origin is RecommendationOrigin.GENERATED for rec in ranked)
    assert all(rec.approval is None and rec.authority is AdvisorAuthority.NONE for rec in ranked)


def test_a_draft_compiles_to_the_same_type_an_authored_recommendation_uses() -> None:
    weights = {"F1": readings_for()}
    draft = recommendations_for((finding(),), CRITERIA, weights, propose=propose)[0]

    compiled = draft.compile(CRITERIA, weights["F1"])

    assert isinstance(compiled, Recommendation)
    assert compiled.origin is RecommendationOrigin.GENERATED
    assert compiled.finding == draft.finding
    assert compiled.candidate == draft.candidate
    assert compiled.authority is AdvisorAuthority.NONE
    assert compiled.approval is None
    assert compiled.total == pytest.approx(1.20 / 1.75)


def test_a_draft_has_nowhere_to_put_an_approval_token() -> None:
    """Structural, not conventional: there is no field, and the model is frozen."""
    assert "approval" not in UntrustedRecommendationDraft.model_fields
    draft = recommendations_for((finding(),), CRITERIA, {"F1": readings_for()}, propose=propose)[0]

    with pytest.raises(AttributeError):
        _ = draft.approval  # type: ignore[attr-defined]
    with pytest.raises(ValidationError):
        draft.approval = Approval(  # type: ignore[attr-defined, call-arg]
            approved_by="sre-oncall", recommendation_digest="0" * 64
        )


def test_a_draft_carrying_an_approval_token_is_rejected() -> None:
    """The negative control: smuggling a token into the draft is refused at the boundary."""
    gap = finding()
    with pytest.raises(ValidationError):
        UntrustedRecommendationDraft(
            recommendation_id="rec:F1",
            finding=gap,
            candidate=propose(gap),
            rationale="h",
            approval={"approved_by": "sre-oncall", "recommendation_digest": "0" * 64},
        )


def test_a_generated_recommendation_cannot_be_constructed_with_an_approval() -> None:
    draft = recommendations_for((finding(),), CRITERIA, {"F1": readings_for()}, propose=propose)[0]
    token = Approval(
        approved_by="sre-oncall",
        recommendation_digest=draft.compile(CRITERIA, readings_for()).recommendation_digest,
    )

    with pytest.raises(InvariantViolationError) as caught:
        Recommendation(
            recommendation_id=draft.recommendation_id,
            finding=draft.finding,
            candidate=draft.candidate,
            priority=Priority.from_readings(CRITERIA, readings_for()),
            rationale=draft.rationale,
            origin=RecommendationOrigin.GENERATED,
            approval=token,
        )

    assert caught.value.rule == RULE_GENERATED_CANNOT_BE_APPROVED
    assert "cannot supply its own" in str(caught.value)


def test_a_draft_cannot_supply_its_own_priority_or_weights() -> None:
    """The declared criteria are not the draft's to write, and compile requires them."""
    fields = set(UntrustedRecommendationDraft.model_fields)

    assert "priority" not in fields
    assert "criteria" not in fields
    assert "weight" not in fields
    assert "weights" not in fields
    assert "score" not in fields
    with pytest.raises(ValidationError):
        UntrustedRecommendationDraft(
            recommendation_id="rec:F1",
            finding=finding(),
            candidate=propose(finding()),
            rationale="h",
            total=0.99,  # type: ignore[call-arg]
        )
    with pytest.raises(ValidationError):
        UntrustedRecommendationDraft(
            recommendation_id="rec:F1",
            finding=finding(),
            candidate=propose(finding()),
            rationale="h",
            criteria=CRITERIA,  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError):
        UntrustedRecommendationDraft(
            recommendation_id="rec:F1",
            finding=finding(),
            candidate=propose(finding()),
            rationale="h",
        ).compile(CRITERIA)  # type: ignore[call-arg]


def test_an_authored_recommendation_binds_an_approval_to_its_own_digest() -> None:
    authored = Recommendation(
        recommendation_id="rec:hand-written",
        finding=finding(),
        candidate=propose(finding()),
        priority=Priority.from_readings(CRITERIA, readings_for()),
        rationale=Priority.from_readings(CRITERIA, readings_for()).rationale,
        origin=RecommendationOrigin.AUTHORED,
    )

    assert authored.authority is AdvisorAuthority.NONE

    approved = Recommendation(
        recommendation_id="rec:hand-written",
        finding=authored.finding,
        candidate=authored.candidate,
        priority=authored.priority,
        rationale=authored.rationale,
        origin=RecommendationOrigin.AUTHORED,
        approval=Approval(
            approved_by="sre-oncall", recommendation_digest=authored.recommendation_digest
        ),
    )
    assert approved.authority is AdvisorAuthority.APPROVED

    # Change anything the approval was given for and the binding is gone.
    with pytest.raises(InvariantViolationError) as caught:
        Recommendation(
            recommendation_id="rec:hand-written",
            finding=authored.finding,
            candidate=ExperimentCandidate(experiment_id="exp-swapped", hypothesis="something else"),
            priority=authored.priority,
            rationale=authored.rationale,
            origin=RecommendationOrigin.AUTHORED,
            approval=approved.approval,
        )
    assert caught.value.rule == RULE_APPROVAL_MISMATCH


def test_an_approval_must_name_its_approver_and_name_a_real_digest() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        Approval(approved_by="  ", recommendation_digest="0" * 64)
    assert caught.value.rule == RULE_APPROVAL_WITHOUT_AN_APPROVER

    with pytest.raises(InvariantViolationError) as caught:
        Approval(approved_by="sre-oncall", recommendation_digest="whatever")
    assert caught.value.rule == RULE_APPROVAL_MISMATCH


def test_a_proposer_however_opaque_produces_a_recommendation_with_no_authority() -> None:
    """The boundary does not depend on the proposer being well-behaved.

    The stand-in proposer here is as close to an opaque generator as this test can
    get without a model: it ignores the finding's content and answers from a
    constant. What it still cannot do is produce anything but a generated,
    unapproved recommendation with a derived priority.
    """

    def opaque_proposer(f: Finding) -> ExperimentCandidate:
        return ExperimentCandidate(
            experiment_id="exp-from-a-black-box",
            hypothesis="the model says this is important",
        )

    weights = {"F1": readings_for()}
    ranked = rank_drafts(
        recommendations_for((finding(),), CRITERIA, weights, propose=opaque_proposer),
        CRITERIA,
        weights,
    )

    assert len(ranked) == 1
    assert ranked[0].origin is RecommendationOrigin.GENERATED
    assert ranked[0].authority is AdvisorAuthority.NONE
    assert ranked[0].total == pytest.approx(1.20 / 1.75)
    assert ranked[0].render_refusal_reason() == ""  # the criteria are named for it


# -- advisor output is not evidence ------------------------------------------------


def test_advisor_output_is_never_treated_as_certified_evidence() -> None:
    """The negative control, and the predicate is a real predicate, not a constant False."""
    gap = finding()
    weights = {"F1": readings_for()}
    draft = recommendations_for((gap,), CRITERIA, weights, propose=propose)[0]
    rec = draft.compile(CRITERIA, weights["F1"])

    for claim in (gap, rec, draft, rec.cited_facts, rec.priority, weights["F1"]):
        assert is_certified_evidence(claim) is False

    # Positive control: a run pin carries the sealed digest a verifier accepts, so
    # the check above is not simply refusing everything.
    sealed = RunPin(
        run_id="run-42",
        experiment="exp-f1",
        release="1.1.0",
        environment="staging",
        plan_version="p1",
        policy_version="pol1",
        catalog_version="c1",
        agent_version="a1",
        runtime_version="r1",
        evidence_digest="d" * 64,
    )
    assert is_certified_evidence(sealed) is True
    assert not is_certified_evidence(sealed.model_copy(update={"evidence_digest": "not-a-digest"}))


def test_no_advisor_type_carries_an_evidence_digest_field() -> None:
    for claim in (
        finding(),
        Finding,
        Recommendation,
        Priority,
        IncidentFacts,
        UntrustedRecommendationDraft,
    ):
        assert "evidence_digest" not in getattr(claim, "model_fields", {})
        assert getattr(claim, "evidence_digest", None) is None


def test_citations_are_plain_readable_facts() -> None:
    fact = CitedFact(kind=CitedFactKind.TOPOLOGY_NODE, ref="checkout", detail="the target")

    assert fact.to_dict() == {
        "kind": "topology_node",
        "ref": "checkout",
        "detail": "the target",
    }
