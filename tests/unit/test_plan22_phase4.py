"""Plan 22 Phase 4 — safety and evidence integration.

Why this file exists
--------------------

Phase 4's acceptance is one sentence: *"a regression finding without two cited
runs is unrepresentable."* The domain already refuses to build one — a
:class:`~mayhem.domain.comparison.RegressionFinding` can only be opened from a
graded regression between two distinct run pins, each carrying an evidence
digest. What this phase adds is everything around that sentence:

* **Findings are computed from sealed evidence only.** ``record_finding`` now
  refuses a finding whose cited runs were never recorded, or whose cited
  digests are not the ones its runs are sealed against — the direct path a
  hand-built finding could otherwise take past ``open_finding``.
* **Journey probes are versioned and pinned into plans.** A change link's
  :class:`~mayhem.domain.pipeline.PipelinePins` now records the journey
  program pin its cited run carried, so a re-pinned journey cannot silently
  back a release decision.
* **Regression findings feed release decisions (plan 16).** ``release_gate``
  blocks while an open finding's candidate is the release the cited run
  measured, and the refusal names the finding and both runs.
* **Regression findings feed advisor input (plan 21).**
  :func:`mayhem.domain.advisor.regression_citations` converts findings into
  the advisor's own citation vocabulary — a finding is not a gap Finding, so
  it crosses as a cited fact, never as a second kind of gap.

The tests are grouped the way the phase names them, and every refusal is
asserted by rule id, because the sentence a refusal carries is part of the
interface.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from mayhem.controller.check_gate import (
    ChangeKind,
    ReleaseGateRequest,
    ResilienceSuite,
    release_gate,
)
from mayhem.domain.advisor import CitedFactKind, regression_citations
from mayhem.domain.comparison import (
    ComparisonMetric,
    MetricKind,
    RegressionFinding,
    RunPin,
    RunReport,
    RunSample,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.journeys import JourneyPin
from mayhem.domain.pipeline import (
    ChangeLink,
    CheckOutcome,
    CheckScope,
    PipelinePins,
    PipelineVerdict,
    PRCheck,
    blocking_reasons,
)
from mayhem.infra.coverage_service import ComparisonService
from mayhem.infra.store import Store

NOW = datetime(2026, 9, 30, 12, 0, 0, tzinfo=UTC)
BASE_DIGEST = "0" * 64
CANDIDATE_DIGEST = "1" * 64
JOURNEY = JourneyPin(name="checkout-journey", version="1.0.0", digest="c" * 64)

METRICS = (ComparisonMetric(name="p95_latency_ms", kind=MetricKind.LATENCY, tolerance_pct=20.0),)


def _pin(**overrides: Any) -> RunPin:
    fields: dict[str, Any] = {
        "run_id": "run-v24-0001",
        "experiment": "checkout-resilience",
        "release": "v2.4",
        "environment": "staging",
        "plan_version": "plan-7",
        "policy_version": "policy-7",
        "catalog_version": "catalog-2026.09",
        "agent_version": "agent-2.0.0",
        "runtime_version": "runtime-2.1.0",
        "evidence_digest": BASE_DIGEST,
    }
    fields.update(overrides)
    return RunPin(**fields)


def _report(**overrides: Any) -> RunReport:
    samples = (RunSample(metric="p95_latency_ms", value=200.0, samples=10),)
    fields: dict[str, Any] = {"pin": _pin(**overrides), "metrics": samples}
    return RunReport(**fields)


def _regressing_pair(
    baseline_digest: str = BASE_DIGEST,
    candidate_digest: str = CANDIDATE_DIGEST,
    **pin_overrides: Any,
) -> tuple[RunReport, RunReport]:
    """A baseline at 200ms and a candidate at 260ms: +30%, past the 20% bound."""
    baseline = _report(evidence_digest=baseline_digest, **pin_overrides)
    candidate = RunReport(
        pin=_pin(
            run_id="run-v25-0001",
            release="v2.5",
            evidence_digest=candidate_digest,
            **pin_overrides,
        ),
        metrics=(RunSample(metric="p95_latency_ms", value=260.0, samples=10),),
    )
    return baseline, candidate


def _finding(finding_id: str = "F-2026-09-checkout") -> RegressionFinding:
    baseline, candidate = _regressing_pair()
    return RegressionFinding.open(finding_id, baseline, candidate, METRICS, "because")


def _comparison(tmp_path: Any) -> tuple[Store, ComparisonService]:
    store = Store.open_migrated(tmp_path / "compare.db")
    return store, ComparisonService(store)


def _passing_check() -> PRCheck:
    return PRCheck(
        name="blast-radius",
        scope=CheckScope.BLAST_RADIUS,
        outcome=CheckOutcome.PASS,
        evidence_refs=("check_blast_radius/staging",),
        observed_at=NOW,
    )


def _verdict(cited_run: RunPin | None = None, **link_overrides: Any) -> PipelineVerdict:
    pin = cited_run if cited_run is not None else _pin()
    fields: dict[str, Any] = {
        "git_sha": "abcdef0",
        "change_ticket": "CH-1421",
        "linked_at": NOW,
    }
    fields.update(link_overrides)
    if "pins" not in fields:
        fields["pins"] = PipelinePins.from_run(pin)
    change = ChangeLink(**fields)
    return PipelineVerdict.decide(
        change,
        (_passing_check(),),
        evidence_refs=("check_blast_radius/staging",),
        cited_run=pin,
        decided_at=NOW,
    )


def _request(change: ChangeLink) -> ReleaseGateRequest:
    return ReleaseGateRequest(
        change=change,
        kind=ChangeKind.DEPLOYMENT,
        subject="checkout",
        suites=("perf-suite",),
    )


def _suite(run: RunPin) -> ResilienceSuite:
    return ResilienceSuite(
        name="perf-suite",
        outcome=CheckOutcome.PASS,
        evidence_refs=("perf-suite/run-1",),
        run=run,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Sealed evidence only: findings cite stored runs, at the digests they carry
# ═══════════════════════════════════════════════════════════════════════════


def test_a_finding_citing_a_run_that_was_never_recorded_is_refused(tmp_path: Any) -> None:
    store, service = _comparison(tmp_path)
    _, candidate = _regressing_pair()
    service.record_run(candidate)
    baseline, _ = _regressing_pair()
    finding = RegressionFinding.open("F-1", baseline, candidate, METRICS, "because")

    with pytest.raises(InvariantViolationError) as caught:
        service.record_finding(finding)

    assert caught.value.rule == "comparison_service.finding_cites_unrecorded_run"
    store.close()


def test_a_finding_citing_a_digest_its_run_is_not_sealed_against_is_refused(
    tmp_path: Any,
) -> None:
    store, service = _comparison(tmp_path)
    baseline, candidate = _regressing_pair()
    service.record_run(baseline)
    service.record_run(candidate)
    # The same runs, but the finding cites a digest the baseline never sealed.
    forged_baseline, real_candidate = _regressing_pair(
        baseline_digest="e" * 64, candidate_digest=CANDIDATE_DIGEST
    )
    finding = RegressionFinding.open("F-1", forged_baseline, real_candidate, METRICS, "because")

    with pytest.raises(InvariantViolationError) as caught:
        service.record_finding(finding)

    assert caught.value.rule == "comparison_service.finding_cites_wrong_digest"
    store.close()


def test_a_hand_built_finding_over_recorded_runs_persists(tmp_path: Any) -> None:
    """The green control for the two refusals above: the honest path still works."""
    store, service = _comparison(tmp_path)
    baseline, candidate = _regressing_pair()
    service.record_run(baseline)
    service.record_run(candidate)
    finding = RegressionFinding.open("F-1", baseline, candidate, METRICS, "because")

    service.record_finding(finding)

    row = service.finding("F-1")
    assert row is not None
    assert row["baseline_run"] == "run-v24-0001"
    assert row["candidate_run"] == "run-v25-0001"
    assert row["baseline_evidence_digest"] == BASE_DIGEST
    assert row["candidate_evidence_digest"] == CANDIDATE_DIGEST
    assert len(service.findings()) == 1
    store.close()


# ═══════════════════════════════════════════════════════════════════════════
# Journey probes versioned and pinned into plans
# ═══════════════════════════════════════════════════════════════════════════


def test_a_journey_pin_identity_carries_every_digest_byte() -> None:
    assert JOURNEY.identity == f"checkout-journey@1.0.0#{'c' * 64}"
    # The report label stays short; the pin does not.
    assert JOURNEY.label == f"checkout-journey@1.0.0#{'c' * 12}"


def test_from_run_pins_the_journey_a_run_carried() -> None:
    pins = PipelinePins.from_run(_pin(journey=JOURNEY))

    assert pins.journey == JOURNEY.identity


def test_a_run_without_a_journey_leaves_the_axis_blank() -> None:
    assert PipelinePins.from_run(_pin()).journey == ""


def test_a_link_that_omitted_the_journey_cannot_cite_a_journey_run() -> None:
    """The pinning rule: an unattributed journey run blocks the release."""
    run = _pin(release="v2.5", evidence_digest=CANDIDATE_DIGEST, journey=JOURNEY)
    # A complete link — every required axis pinned — that never recorded which
    # journey program version the run carried.
    pins = PipelinePins(
        plan_version="plan-7",
        policy_version="policy-7",
        catalog_version="catalog-2026.09",
        agent_version="agent-2.0.0",
        runtime_version="runtime-2.1.0",
    )

    assert pins.differences_from(PipelinePins.from_run(run)) == ("journey",)
    assert pins.matches_run(run) is False

    verdict = _verdict(cited_run=run, pins=pins)
    reasons = blocking_reasons(verdict)
    assert any("journey" in reason for reason in reasons)


def test_two_programs_sharing_a_name_and_version_are_not_the_same_pin() -> None:
    edited = JourneyPin(name="checkout-journey", version="1.0.0", digest="d" * 64)

    assert JOURNEY.identity != edited.identity


def test_a_link_built_from_the_run_never_disagrees_with_it() -> None:
    run = _pin(release="v2.5", evidence_digest=CANDIDATE_DIGEST, journey=JOURNEY)
    verdict = _verdict(cited_run=run)

    assert blocking_reasons(verdict) == ()


# ═══════════════════════════════════════════════════════════════════════════
# Findings feed release decisions (plan 16)
# ═══════════════════════════════════════════════════════════════════════════


def test_the_gate_blocks_while_the_cited_release_is_an_open_finding_s_candidate() -> None:
    run = _pin(release="v2.5", evidence_digest=CANDIDATE_DIGEST)
    verdict = _verdict(cited_run=run)
    finding = _finding()

    decision = release_gate(
        verdict, _request(verdict.change), suites=(_suite(run),), open_findings=(finding,)
    )

    assert decision.opens_release is False
    assert any(
        "regression finding 'F-2026-09-checkout' is open against this release" in reason
        for reason in decision.reasons
    )
    # The refusal names both cited runs, so the sentence is re-derivable.
    assert any("run-v24-0001" in reason and "run-v25-0001" in reason for reason in decision.reasons)


def test_a_finding_on_another_release_or_experiment_does_not_block() -> None:
    run = _pin(release="v2.5", evidence_digest=CANDIDATE_DIGEST)
    verdict = _verdict(cited_run=run)
    baseline, candidate = _regressing_pair(experiment="sign-up-resilience")
    elsewhere = RegressionFinding.open("F-2", baseline, candidate, METRICS, "because")

    decision = release_gate(
        verdict, _request(verdict.change), suites=(_suite(run),), open_findings=(elsewhere,)
    )

    assert decision.opens_release is True


def test_the_gate_still_allows_when_no_findings_are_open() -> None:
    run = _pin(release="v2.5", evidence_digest=CANDIDATE_DIGEST)
    verdict = _verdict(cited_run=run)

    decision = release_gate(verdict, _request(verdict.change), suites=(_suite(run),))

    assert decision.opens_release is True


def test_the_gate_blocks_even_when_the_finding_is_the_only_reason() -> None:
    run = _pin(release="v2.5", evidence_digest=CANDIDATE_DIGEST)
    verdict = _verdict(cited_run=run)
    finding = _finding()

    decision = release_gate(
        verdict, _request(verdict.change), suites=(_suite(run),), open_findings=(finding,)
    )

    assert decision.reasons == tuple(
        reason for reason in decision.reasons if "regression finding" in reason
    )
    assert len(decision.reasons) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# Findings feed advisor input (plan 21): citations, never a second gap type
# ═══════════════════════════════════════════════════════════════════════════


def test_a_regression_finding_becomes_one_citation_naming_both_runs() -> None:
    finding = _finding()

    (fact,) = regression_citations(finding)

    assert fact.kind is CitedFactKind.FINDING
    assert fact.ref == finding.finding_id
    assert "run-v24-0001" in fact.detail
    assert "run-v25-0001" in fact.detail
    assert "p95_latency_ms" in fact.detail
    assert finding.summary in fact.detail


def test_no_findings_yield_no_citations() -> None:
    assert regression_citations() == ()


def test_each_finding_becomes_its_own_citation() -> None:
    first = _finding("F-1")
    second = _finding("F-2")

    facts = regression_citations(first, second)

    assert [fact.ref for fact in facts] == ["F-1", "F-2"]
