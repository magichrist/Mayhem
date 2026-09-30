"""Maturity promotion must be earned, and refused loudly when it is not.

These tests exist because the previous state was the opposite of what they
assert. ``catalog._define()`` stamped ``VERIFIED_UNIT`` on every executable
fault, so the badge was a constant that carried no information, and nothing in
the codebase could reach ``verified-live`` or ``stable`` at all. Every test
here fails against that state: there is no promotion engine to import, no
criterion that can be reported unmet, and no way to show a rung being earned.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from mayhem.controller import catalog_report
from mayhem.domain.catalog import all_definitions, definition_for
from mayhem.domain.faults import FaultDefinition, MaturityLevel
from mayhem.infra.promotion import (
    CUMULATIVE_CRITERIA,
    MIN_LIVE_OBSERVATION_DAYS,
    REQUIRED_BUNDLE_DIGESTS,
    REQUIRED_LIVE_ENGINES,
    BundleRef,
    CatalogProbe,
    Criterion,
    EvidenceStore,
    LiveRunRecord,
    Observation,
    build_probe,
    evaluate_maturity,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FAULT_ID = "proc.pause"
_DAY_ONE = datetime(2026, 1, 10, 12, 0, tzinfo=UTC)
_DAY_TWO = datetime(2026, 1, 11, 12, 0, tzinfo=UTC)
_BUNDLE_HASH = "a" * 64
_DIGEST = "b" * 64


# ── builders ────────────────────────────────────────────────────────────────


def _observations() -> tuple[Observation, ...]:
    """A complete, passing run: injected, undone, and back inside tolerance."""
    return (
        Observation(
            stage="injected",
            probe="signal",
            baseline=10.0,
            observed=250.0,
            tolerance=5.0,
            passed=True,
        ),
        Observation(
            stage="undo", probe="signal", baseline=10.0, observed=11.0, tolerance=5.0, passed=True
        ),
        Observation(
            stage="residue",
            probe="signal",
            baseline=10.0,
            observed=10.5,
            tolerance=5.0,
            passed=True,
        ),
    )


def _bundle(*, complete: bool = True) -> BundleRef:
    digests = dict.fromkeys(REQUIRED_BUNDLE_DIGESTS, _DIGEST) if complete else {}
    return BundleRef(
        bundle_hash=_BUNDLE_HASH,
        mayhem_version="1.0.0.test",
        bundle_path="/tmp/evidence/bundle.json",
        digests=digests,
    )


def _record(
    definition: FaultDefinition,
    *,
    engine: str = "docker",
    when: datetime = _DAY_ONE,
    run_id: str = "run-1",
    complete_bundle: bool = True,
    undo_performed: bool = True,
    params: dict[str, object] | None = None,
) -> LiveRunRecord:
    return LiveRunRecord(
        fault_id=definition.id,
        engine=engine,
        platform="linux/amd64",
        run_id=run_id,
        environment="fixture-stack",
        params=dict(params or {}),
        target="fixture-api",
        observed_effect=definition.observable_effect,
        undo_performed=undo_performed,
        undo_description="write-ahead undo and verification probe",
        started_at=when,
        finished_at=when + timedelta(seconds=1),
        bundle=_bundle(complete=complete_bundle),
        observations=_observations(),
    )


def _store(definition: FaultDefinition, *records: LiveRunRecord) -> EvidenceStore:
    store = EvidenceStore()
    for record in records:
        store = store.record(record)
    assert definition.id
    return store


def _probe(definition: FaultDefinition, **overrides: object) -> CatalogProbe:
    """A probe for ``definition`` with every fact satisfied unless overridden."""
    base = build_probe(
        definition,
        executor_registered=lambda _fault_id: True,
        compensation_registered=lambda _fault_id: True,
        unit_evidence=("tests/unit/test_maturity_promotion.py",),
    )
    return base.model_copy(update=overrides)


def _verified_definition(fault_id: str = FAULT_ID) -> FaultDefinition:
    return definition_for(fault_id)


def _full_live_store(definition: FaultDefinition) -> EvidenceStore:
    """A store that satisfies every criterion for every declared engine lane."""
    records: list[LiveRunRecord] = []
    for lane in sorted(lane.value for lane in definition.engine_lanes):
        for index, when in enumerate((_DAY_ONE, _DAY_TWO)):
            records.append(_record(definition, engine=lane, when=when, run_id=f"{lane}-{index}"))
    return _store(definition, *records)


def _decision(definition: FaultDefinition, store: EvidenceStore, **probe: object):
    return evaluate_maturity(definition, probe=_probe(definition, **probe), store=store)


def _refusal_names(decision) -> set[str]:
    return {outcome.name for outcome in decision.outcomes if not outcome.met}


# ── the badge must not be a constant ────────────────────────────────────────


def test_verified_unit_is_derived_and_can_fail_per_fault() -> None:
    """``verified-unit`` is recomputed, not read off the catalog.

    A fault whose compensation contract is no longer registered must lose the
    badge even though the catalog still declares it, and only that fault must
    lose it.
    """
    definition = _verified_definition()
    intact = _decision(definition, EvidenceStore())
    assert definition.maturity is MaturityLevel.VERIFIED_UNIT
    assert intact.maturity is MaturityLevel.VERIFIED_UNIT
    assert intact.declared is MaturityLevel.VERIFIED_UNIT

    broken = build_probe(
        definition,
        executor_registered=lambda _fault_id: True,
        compensation_registered=lambda _fault_id: False,
        unit_evidence=("tests/unit/test_maturity_promotion.py",),
    )
    decision = evaluate_maturity(definition, probe=broken, store=EvidenceStore())
    assert decision.maturity is MaturityLevel.EXPERIMENTAL
    assert decision.declared is MaturityLevel.VERIFIED_UNIT
    assert Criterion.UNIT_TEST_COVERAGE.value in _refusal_names(decision)


def test_no_recorded_unit_coverage_means_no_unit_verification() -> None:
    """The unit rung needs recorded coverage, not a constant in the catalog."""
    definition = _verified_definition()
    decision = _decision(definition, EvidenceStore(), unit_evidence=())
    assert decision.maturity is MaturityLevel.EXPERIMENTAL
    refusal = next(
        refusal for refusal in decision.refusals if Criterion.UNIT_TEST_COVERAGE.value in refusal
    )
    assert "no unit-verification evidence recorded" in refusal


def test_report_derives_maturity_instead_of_copying_the_declaration() -> None:
    """Declaring a fault ``verified-live`` in the catalog must not do it."""
    definition = _verified_definition().model_copy(
        update={
            "maturity": MaturityLevel.STABLE,
            "verification_date": date(2026, 1, 1),
            "deprecation_path": "documented: retire before removal",
        }
    )
    decision = _decision(definition, EvidenceStore())
    assert decision.declared is MaturityLevel.STABLE
    assert decision.maturity is MaturityLevel.VERIFIED_UNIT
    assert decision.live_verified is False


def test_the_whole_catalog_is_not_one_uniform_badge() -> None:
    """Recomputing the whole catalogue must separate it, not echo it.

    With no recorded unit coverage, nothing is unit-verified. With coverage but
    no registered compensation, only the faults that still have a contract are.
    """
    uncovered = [
        evaluate_maturity(
            definition, probe=_probe(definition, unit_evidence=()), store=EvidenceStore()
        ).maturity
        for definition in all_definitions()
    ]
    assert set(uncovered) == {MaturityLevel.EXPERIMENTAL}

    with_coverage = [
        evaluate_maturity(definition, probe=_probe(definition), store=EvidenceStore()).maturity
        for definition in all_definitions()
    ]
    assert MaturityLevel.VERIFIED_UNIT in with_coverage
    assert MaturityLevel.EXPERIMENTAL in with_coverage
    assert MaturityLevel.VERIFIED_LIVE not in with_coverage
    assert MaturityLevel.STABLE not in with_coverage


def test_coverage_report_counts_maturity_it_recomputed() -> None:
    coverage = catalog_report.build_coverage()
    assert coverage["by_maturity"] == {"experimental": 13, "verified-unit": 128}
    assert sum(coverage["by_maturity"].values()) == coverage["total"]


# ── empty evidence is refused, and says why ─────────────────────────────────


def test_empty_evidence_store_refuses_verified_live() -> None:
    definition = _verified_definition()
    decision = _decision(definition, EvidenceStore())
    assert decision.maturity is MaturityLevel.VERIFIED_UNIT
    assert decision.live_verified is False
    assert decision.live_record_count == 0
    assert decision.eligible is False
    assert Criterion.LIVE_RUNTIME_COMPLETED.value in _refusal_names(decision)
    assert Criterion.EVIDENCE_RECORDED.value in _refusal_names(decision)


def test_empty_evidence_refusal_names_the_criterion_and_what_it_saw() -> None:
    decision = _decision(_verified_definition(), EvidenceStore())
    live = next(
        refusal
        for refusal in decision.refusals
        if Criterion.LIVE_RUNTIME_COMPLETED.value in refusal
    )
    assert "no passing run recorded for docker, podman" in live
    assert Criterion.LIVE_RUNTIME_COMPLETED.value in live


def test_a_fault_with_no_live_evidence_can_never_be_reported_live_verified() -> None:
    """The headline claim: no fault, no evidence store, no live-verified badge."""
    for definition in all_definitions():
        decision = catalog_report.maturity_decision(definition)
        assert decision.maturity is not MaturityLevel.VERIFIED_LIVE, definition.id
        assert decision.maturity is not MaturityLevel.STABLE, definition.id
        assert decision.live_verified is False, definition.id


def test_catalog_report_live_count_is_zero_with_an_empty_evidence_store() -> None:
    coverage = catalog_report.build_coverage()
    assert coverage["verified_live"] == 0
    assert coverage["verified_live_faults"] == []
    assert coverage["live_evidence_records"] == 0
    assert "verified-live" not in coverage["by_maturity"]
    assert "stable" not in coverage["by_maturity"]


def test_capability_dashboard_reports_zero_live_verified_rows() -> None:
    dashboard = catalog_report.build_capability_dashboard()
    assert dashboard.summary()["live_verified"] == 0
    assert all(row.live_verified is False for row in dashboard.rows)


# ── each criterion can fail, and is named when it does ─────────────────────


def test_every_criterion_has_an_executable_name_and_text() -> None:
    for level, criteria in CUMULATIVE_CRITERIA.items():
        for criterion in criteria:
            assert criterion.value, level
            assert any(
                criterion.value in texts
                for texts in catalog_report.MATURITY_PROMOTION_CRITERIA.values()
            )


def test_catalog_metadata_complete_is_named_when_metadata_is_missing() -> None:
    definition = _verified_definition().model_copy(update={"observable_effect": ""})
    decision = _decision(definition, EvidenceStore())
    assert Criterion.CATALOG_METADATA_COMPLETE.value in _refusal_names(decision)


def test_parameter_grammar_is_named_when_the_defaults_do_not_validate() -> None:
    decision = _decision(_verified_definition(), EvidenceStore(), params_grammar_ok=False)
    assert Criterion.PLANNER_VALIDATES_PARAMS.value in _refusal_names(decision)


def test_deterministic_refusal_is_named_when_it_is_absent() -> None:
    decision = _decision(_verified_definition(), EvidenceStore(), refusal_deterministic=False)
    assert Criterion.EXECUTION_REFUSES_DETERMINISTICALLY.value in _refusal_names(decision)


def test_verification_date_is_named_when_it_is_absent() -> None:
    definition = _verified_definition().model_copy(update={"verification_date": None})
    decision = _decision(definition, EvidenceStore())
    assert decision.maturity is MaturityLevel.EXPERIMENTAL
    assert Criterion.VERIFICATION_DATE_RECORDED.value in _refusal_names(decision)
    assert any("verification_date=None" in refusal for refusal in decision.refusals)


def test_live_runtime_is_named_when_only_one_required_engine_passed() -> None:
    definition = _verified_definition()
    store = _store(definition, _record(definition, engine="docker"))
    decision = _decision(definition, store)
    assert decision.maturity is MaturityLevel.VERIFIED_UNIT
    names = _refusal_names(decision)
    assert Criterion.LIVE_RUNTIME_COMPLETED.value in names
    # the climb stops at verified-live, so no stable-level criterion is consulted yet
    assert Criterion.ENGINE_MATRIX_VERIFIED.value not in names
    assert any("no passing run recorded for podman" in r for r in decision.refusals)


def test_evidence_recorded_is_named_when_the_bundle_carries_no_digests() -> None:
    definition = _verified_definition()
    store = _store(definition, _record(definition, complete_bundle=False))
    decision = _decision(definition, store)
    assert Criterion.EVIDENCE_RECORDED.value in _refusal_names(decision)
    assert any("no params digest in its bundle" in r for r in decision.refusals)


def test_engine_matrix_is_named_when_a_declared_lane_is_unverified() -> None:
    """``proc.pause`` declares docker, podman *and* host; docker+podman is not enough."""
    definition = _verified_definition()
    assert {lane.value for lane in definition.engine_lanes} >= {"docker", "podman", "host"}
    store = _store(
        definition,
        _record(definition, engine="docker", run_id="d"),
        _record(definition, engine="podman", run_id="p"),
    )
    decision = _decision(definition, store)
    # docker + podman earn verified-live; the unverified host lane blocks stable
    assert decision.maturity is MaturityLevel.VERIFIED_LIVE
    assert decision.live_verified is True
    assert Criterion.ENGINE_MATRIX_VERIFIED.value in _refusal_names(decision)
    assert any("no passing run for host" in r for r in decision.refusals)


def test_repetition_is_named_when_one_day_only() -> None:
    definition = _verified_definition()
    store = _store(
        definition,
        _record(definition, engine="docker", when=_DAY_ONE, run_id="d1"),
        _record(definition, engine="podman", when=_DAY_ONE, run_id="p1"),
        _record(definition, engine="host", when=_DAY_ONE, run_id="h1"),
    )
    decision = _decision(definition, store)
    assert decision.maturity is MaturityLevel.VERIFIED_LIVE
    # one run per engine: the matrix is covered, but no verification was repeated
    assert decision.distinct_observation_days == 0
    assert Criterion.REPEATED_ACROSS_DAYS.value in _refusal_names(decision)


def test_recording_the_same_run_twice_does_not_count_as_repetition() -> None:
    """One run recorded twice is one piece of evidence, not two."""
    definition = _verified_definition()
    records = [
        _record(definition, engine=lane, when=_DAY_ONE, run_id="dup")
        for lane in ("docker", "podman", "host")
    ]
    store = _store(definition, *(record for record in records for _ in range(3)))
    decision = _decision(definition, store)
    assert decision.maturity is MaturityLevel.VERIFIED_LIVE
    assert decision.live_record_count == 9
    assert decision.distinct_observation_days == 1
    assert Criterion.REPEATED_ACROSS_DAYS.value in _refusal_names(decision)


def test_deprecation_policy_is_named_when_it_is_absent() -> None:
    definition = _verified_definition()
    assert definition.deprecation_path is None
    decision = _decision(definition, _full_live_store(definition))
    assert Criterion.DEPRECATION_POLICY_DOCUMENTED.value in _refusal_names(decision)
    assert any("deprecation_path=None" in r for r in decision.refusals)


# ── live requires more than stable; stable is strictly more ────────────────


def test_verified_live_requires_strictly_more_than_stable() -> None:
    stable_only = set(CUMULATIVE_CRITERIA[MaturityLevel.STABLE])
    live_only = set(CUMULATIVE_CRITERIA[MaturityLevel.VERIFIED_LIVE])
    extra = stable_only - live_only
    assert extra, "stable must require something verified-live does not"
    assert extra <= set(CUMULATIVE_CRITERIA[MaturityLevel.STABLE])
    assert not (live_only - stable_only), "stable must be a superset of verified-live"


def test_a_run_that_earns_verified_live_still_cannot_reach_stable() -> None:
    definition = _verified_definition()
    store = _store(
        definition,
        _record(definition, engine="docker", when=_DAY_ONE, run_id="d1"),
        _record(definition, engine="podman", when=_DAY_ONE, run_id="p1"),
    )
    decision = _decision(definition, store)
    assert decision.maturity is MaturityLevel.VERIFIED_LIVE
    live_names = _refusal_names(decision)
    assert Criterion.REPEATED_ACROSS_DAYS.value in live_names
    assert Criterion.ENGINE_MATRIX_VERIFIED.value in live_names
    assert Criterion.DEPRECATION_POLICY_DOCUMENTED.value in live_names


def test_full_matrix_repetition_and_policy_earns_stable() -> None:
    definition = _verified_definition().model_copy(
        update={"deprecation_path": "retire on 1.2.0 with a release note and a rollback runbook"}
    )
    store = _store(
        definition,
        *(
            _record(definition, engine=lane, when=when, run_id=f"{lane}-{index}")
            for lane in ("docker", "podman", "host")
            for index, when in enumerate((_DAY_ONE, _DAY_TWO))
        ),
    )
    decision = _decision(definition, store)
    assert decision.distinct_observation_days >= MIN_LIVE_OBSERVATION_DAYS
    assert decision.refusals == ()
    assert decision.maturity is MaturityLevel.STABLE
    assert decision.live_verified is True


def test_verified_live_needs_both_required_engines() -> None:
    definition = _verified_definition().model_copy(
        update={"deprecation_path": "retire on 1.2.0 with a release note and a rollback runbook"}
    )
    store = _store(
        definition,
        *(
            _record(definition, engine=lane, when=when, run_id=f"{lane}-{index}")
            for lane in REQUIRED_LIVE_ENGINES
            for index, when in enumerate((_DAY_ONE, _DAY_TWO))
        ),
    )
    decision = _decision(definition, store)
    assert decision.maturity is MaturityLevel.VERIFIED_LIVE
    assert decision.live_verified is True
    # the declared host lane has no evidence, so stable is still refused
    assert Criterion.ENGINE_MATRIX_VERIFIED.value in _refusal_names(decision)


# ── fabricated evidence is unrepresentable ──────────────────────────────────


def test_an_observation_that_moves_nothing_cannot_be_evidence() -> None:
    with pytest.raises(ValidationError, match="does not move the signal"):
        Observation(
            stage="injected",
            probe="signal",
            baseline=10.0,
            observed=10.0,
            tolerance=5.0,
            passed=True,
        )


def test_an_undo_that_did_not_restore_the_baseline_cannot_be_evidence() -> None:
    with pytest.raises(ValidationError, match="undo did not restore the baseline"):
        Observation(
            stage="residue",
            probe="signal",
            baseline=10.0,
            observed=90.0,
            tolerance=5.0,
            passed=True,
        )


def test_a_record_without_an_undo_cannot_be_constructed() -> None:
    definition = _verified_definition()
    with pytest.raises(ValidationError, match="records no undo"):
        _record(definition, undo_performed=False)


def test_a_naive_timestamp_cannot_be_recorded() -> None:
    payload = _record(_verified_definition()).model_dump()
    payload["started_at"] = _DAY_ONE.replace(tzinfo=None)  # deliberately naive
    with pytest.raises(ValidationError, match="timezone-aware"):
        LiveRunRecord.model_validate(payload)


def test_evidence_about_a_different_fault_does_not_promote_this_one() -> None:
    """A record's fault id is part of its identity, so a stray bundle cannot leak."""
    definition = _verified_definition()
    neighbour = _verified_definition("process.stop")
    store = _store(definition, _record(definition))
    assert store.fault_ids() == {FAULT_ID}
    decision = evaluate_maturity(neighbour, probe=_probe(neighbour), store=store)
    assert decision.live_record_count == 0
    assert decision.live_verified is False
    assert any(Criterion.LIVE_RUNTIME_COMPLETED.value in refusal for refusal in decision.refusals)


def test_evidence_claiming_a_different_effect_is_not_evidence_for_this_fault() -> None:
    definition = _verified_definition()
    record = _record(definition).model_copy(
        update={"observed_effect": "something entirely different happened"}
    )
    store = _store(definition, record)
    decision = _decision(definition, store)
    assert decision.live_record_count == 0
    assert decision.maturity is MaturityLevel.VERIFIED_UNIT
    assert Criterion.LIVE_RUNTIME_COMPLETED.value in _refusal_names(decision)


def test_evidence_using_undeclared_parameters_is_not_evidence_for_this_fault() -> None:
    definition = _verified_definition()
    record = _record(definition, params={"not_a_parameter": 1})
    decision = _decision(definition, _store(definition, record))
    assert decision.live_record_count == 0
    assert Criterion.LIVE_RUNTIME_COMPLETED.value in _refusal_names(decision)


def test_evidence_on_an_undeclared_engine_is_not_evidence_for_this_fault() -> None:
    definition = _verified_definition()
    record = _record(definition, engine="kubernetes")
    decision = _decision(definition, _store(definition, record))
    assert decision.live_record_count == 0
    assert decision.maturity is MaturityLevel.VERIFIED_UNIT


# ── the report must not overstate ───────────────────────────────────────────


def test_explain_states_plainly_that_nothing_is_live_verified() -> None:
    explained = catalog_report.explain_catalog_fault(FAULT_ID, engine="docker")
    assert explained["maturity"] == MaturityLevel.VERIFIED_UNIT.value
    assert explained["declared_maturity"] == MaturityLevel.VERIFIED_UNIT.value
    assert explained["maturity_evidence"]["live_verified"] is False
    assert explained["maturity_evidence"]["live_record_count"] == 0
    assert explained["unmet_criteria"]
    assert "not about the fault working" in explained["maturity_disclaimer"]
    assert "verified-live" not in explained["promotion_criteria"][0]


def test_explain_shows_the_gap_between_claimed_and_earned() -> None:
    explained = catalog_report.explain_catalog_fault(FAULT_ID, engine="docker")
    assert explained["maturity"] != explained["declared_maturity"] or (
        explained["maturity"] == MaturityLevel.VERIFIED_UNIT.value
    )
    assert set(explained["maturity_evidence"]["refusals"]) == set(explained["unmet_criteria"])


def test_coverage_carries_the_disclaimer() -> None:
    coverage = catalog_report.build_coverage()
    assert "zero until such a run is executed" in coverage["maturity_disclaimer"]


def test_recorded_unit_coverage_points_at_modules_that_exist() -> None:
    """The one input the engine cannot recompute is a *checked* declaration."""
    assert catalog_report.CATALOG_UNIT_COVERAGE
    for module in catalog_report.CATALOG_UNIT_COVERAGE:
        assert (REPO_ROOT / module).is_file(), module


def test_evidence_store_starts_empty_and_grows_only_by_recording() -> None:
    assert not EvidenceStore()
    assert len(EvidenceStore()) == 0
    assert EvidenceStore().fault_ids() == frozenset()
