"""The failure-mode library: taxonomy integrity, mapping completeness over the
live catalog, and the negative controls (docs/v1.1.0/20_ENTERPRISE_PRODUCT_HARDENING.md,
Phase 1, gap 55).

The load-bearing test here is
:func:`test_every_catalog_fault_maps_to_at_least_one_failure_mode`, which walks
the **live** :data:`mayhem.domain.catalog.CATALOG` rather than a snapshot of it.
That is the plan's acceptance criterion and it is what makes adding a fault to
the catalog without adding a mapping a *test failure* instead of a documentation
hole nobody notices until a customer asks.

The rest exists because a mapping table can be complete and still be useless:

* **A taxonomy member with no fault behind it is a hole too.** A mode no report
  can populate means any sentence about the product's coverage of that mode is
  unearned, so :func:`test_no_taxonomy_member_is_empty` asserts all eighteen have
  faults.
* **The table may not restate a fault as less risky.** ``validate_mappings``
  cross-checks the mapping's risk against the catalog's, and one negative-control
  test proves the check has teeth by handing it a mapping that *did* downgrade
  ``process.kill`` from high to low.
* **A refused fault may not describe an outage.** The 13 ``catalog_only`` entries
  inject nothing, so their expected symptom is the plan-time refusal. A test
  asserts every one of them carries a refusal note and that an executable fault
  carrying one is refused too.
* **A compliance template cannot assert compliance.** The negative control sets
  ``asserts_compliance=True`` and asserts the refusal, and a second test asserts
  the only sentence the type can produce says so even for a template whose
  *title* is a compliance claim.
"""

from __future__ import annotations

import dataclasses

import pytest

from mayhem.domain import failure_modes
from mayhem.domain.catalog import CATALOG, all_definitions
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.failure_modes import (
    COMPLIANCE_TEMPLATES,
    FAILURE_MODE_PROFILES,
    FAILURE_MODES,
    ComplianceControl,
    FailureMode,
    FaultFailureMapping,
    compliance_statement,
    failure_modes_for,
    faults_for_mode,
    mapped_fault_ids,
    mapping_for,
    require_non_asserting_template,
    taxonomy_coverage,
    unmapped_fault_ids,
    validate_failure_mode,
    validate_failure_modes,
    validate_mapping,
    validate_mappings,
)
from mayhem.domain.faults import VerificationMethod
from mayhem.domain.risks import RiskLevel

CATALOG_IDS = tuple(sorted(definition.id for definition in all_definitions()))


def mapping_without(fault_id: str, **overrides: object) -> FaultFailureMapping:
    """The real mapping for ``fault_id`` with fields replaced, for negative controls."""
    return dataclasses.replace(mapping_for(fault_id), **overrides)  # type: ignore[arg-type]


# -- the acceptance criterion ---------------------------------------------------


def test_every_catalog_fault_maps_to_at_least_one_failure_mode() -> None:
    """The plan's Phase 1 acceptance criterion, enforced over the live catalog.

    An unmapped fault can be injected, can be hit in production, and has no story
    in any enterprise report. ``unmapped_fault_ids`` returning empty is the
    assertion; the message says which faults are missing if it ever does not.
    """
    assert unmapped_fault_ids() == (), (
        f"catalog faults with no failure-mode mapping: {unmapped_fault_ids()}"
    )
    for definition in all_definitions():
        modes = failure_modes_for(definition.id)
        assert modes, f"{definition.id} maps to no failure mode"


def test_the_table_has_one_entry_per_catalog_fault_and_no_others() -> None:
    assert len(mapped_fault_ids()) == len(CATALOG_IDS) == 141
    assert mapped_fault_ids() == frozenset(CATALOG_IDS)
    validate_mappings()  # raises on any inconsistency; does not raise today


def test_every_mapping_answers_all_six_questions_a_report_asks() -> None:
    for fault_id in sorted(mapped_fault_ids()):
        mapping = mapping_for(fault_id)

        assert mapping.failure_modes, fault_id
        assert mapping.primary in mapping.failure_modes, fault_id
        assert mapping.mechanism.strip(), fault_id
        assert mapping.expected_symptom.strip(), fault_id
        assert isinstance(mapping.risk, RiskLevel), fault_id
        assert mapping.recovery.strip(), fault_id
        assert isinstance(mapping.verification_method, VerificationMethod), fault_id
        assert mapping.verification.strip(), fault_id
        assert validate_mapping(mapping) == "", fault_id


def test_an_unmapped_catalog_fault_fails_validation() -> None:
    """The negative control: add a fault to the catalog with no mapping beside it.

    Built by copying a real definition under a new id, so the only thing that
    makes it unmapped is the missing mapping. This is the shape a future
    catalog addition takes, and it must fail rather than ship.
    """
    intruder = CATALOG[0].model_copy(update={"id": "proc.unmapped_probe"})
    catalog_with_hole = (*CATALOG, intruder)

    assert unmapped_fault_ids(catalog_with_hole) == ("proc.unmapped_probe",)
    with pytest.raises(InvariantViolationError) as caught:
        validate_mappings(catalog_with_hole)

    assert caught.value.rule == "failure_mode.unmapped"
    assert "proc.unmapped_probe" in str(caught.value)
    # Every real fault is still mapped; only the intruder is the hole.
    assert unmapped_fault_ids() == ()


def test_a_mapping_naming_a_fault_outside_the_catalog_is_an_orphan() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        validate_mappings(CATALOG[1:])

    assert caught.value.rule == "failure_mode.orphan"
    assert "proc.pause" in str(caught.value)


def test_an_unknown_fault_id_is_a_planning_error_not_a_key_error() -> None:
    with pytest.raises(LookupError, match="no failure-mode mapping"):
        mapping_for("no.such.fault")


# -- the mapping may not restate a fault ----------------------------------------


@pytest.fixture
def swap_mapping(monkeypatch: pytest.MonkeyPatch):
    """Install a caller-supplied mapping in place of its own fault id.

    Monkeypatch restores the real table afterwards, so a negative control can
    prove a validation rule has teeth without leaking a fake mapping into the
    rest of the suite. That matters: without restoration, these tests would
    leave the table in a broken state and the completeness test would fail for
    the wrong reason.
    """

    def install(mapping: FaultFailureMapping) -> FaultFailureMapping:
        monkeypatch.setitem(failure_modes._MAPPINGS_BY_FAULT, mapping.fault_id, mapping)
        return mapping

    return install


def test_a_mapping_that_downgrades_a_faults_risk_is_refused(swap_mapping: object) -> None:
    """A reporting library that lowers a risk is a reclassification, and is refused."""
    original = mapping_for("process.kill")

    with pytest.raises(InvariantViolationError) as caught:
        swap_mapping(mapping_without("process.kill", risk=RiskLevel.LOW))
        validate_mappings()

    assert caught.value.rule == "failure_mode.risk_mismatch"
    assert original.risk is RiskLevel.HIGH
    assert "'high'" in str(caught.value)


def test_the_verification_method_cross_check_has_teeth(swap_mapping: object) -> None:
    """Substituting a different instrument is refused: the library may explain a
    probe, not replace it."""
    with pytest.raises(InvariantViolationError) as caught:
        swap_mapping(
            mapping_without("net.latency", verification_method=VerificationMethod.HTTP_RESPONSE)
        )
        validate_mappings()

    assert caught.value.rule == "failure_mode.verification_mismatch"


# -- refused faults -------------------------------------------------------------


def test_every_catalog_only_fault_carries_a_refusal_note() -> None:
    """Nothing is injected for these, so their expected symptom is the refusal."""
    refused = [d for d in all_definitions() if d.catalog_only]

    assert len(refused) == 13
    for definition in refused:
        mapping = mapping_for(definition.id)
        assert mapping.refusal_note.strip(), definition.id
        assert mapping.is_refused, definition.id
        assert "refuse" in mapping.expected_symptom, definition.id
        assert "refused" in mapping.recovery, definition.id


def test_every_executable_fault_carries_no_refusal_note() -> None:
    executable = [d for d in all_definitions() if not d.catalog_only]

    assert len(executable) == 128
    for definition in executable:
        assert not mapping_for(definition.id).refusal_note, definition.id


def test_a_refusal_note_on_an_executable_fault_is_refused_as_a_hiding_capability(
    swap_mapping: object,
) -> None:
    with pytest.raises(InvariantViolationError) as caught:
        swap_mapping(mapping_without("net.latency", refusal_note="catalog-only: not implemented"))
        validate_mappings()

    assert caught.value.rule == "failure_mode.refusal_note_unexpected"


def test_a_catalog_only_fault_without_a_refusal_note_is_refused(swap_mapping: object) -> None:
    with pytest.raises(InvariantViolationError) as caught:
        swap_mapping(mapping_without("app.deadlock", refusal_note=""))
        validate_mappings()

    assert caught.value.rule == "failure_mode.refusal_note_missing"


# -- a mapping that answers nothing ---------------------------------------------


def test_a_failure_mode_entry_with_no_recovery_statement_is_refused() -> None:
    """A mode nobody can act on is a category, not a failure mode."""
    profile = dataclasses.replace(
        FAILURE_MODE_PROFILES[FailureMode.AVAILABILITY], recovery_guidance="   "
    )

    reason = validate_failure_mode(profile)

    assert reason.startswith("failure_mode.recovery_guidance")
    assert "a category, not a failure mode" in reason


def test_a_failure_mode_entry_with_no_distinguishing_question_is_refused() -> None:
    profile = dataclasses.replace(
        FAILURE_MODE_PROFILES[FailureMode.LATENCY], distinguishing_question=""
    )

    assert validate_failure_mode(profile).startswith("failure_mode.distinguishing_question")


def test_a_mapping_with_no_recovery_statement_is_refused() -> None:
    reason = validate_mapping(mapping_without("db.slow_query", recovery="  "))

    assert reason.startswith("failure_mode.recovery")
    assert "how the failure is undone" in reason


def test_a_mapping_with_no_verification_statement_is_refused() -> None:
    reason = validate_mapping(mapping_without("db.slow_query", verification=""))

    assert reason.startswith("failure_mode.verification")
    assert "how the undo is known" in reason


def test_a_mapping_with_no_symptom_is_refused() -> None:
    reason = validate_mapping(mapping_without("db.slow_query", expected_symptom=" "))

    assert reason.startswith("failure_mode.expected_symptom")


def test_a_mapping_with_no_mechanism_is_refused() -> None:
    reason = validate_mapping(mapping_without("db.slow_query", mechanism=""))

    assert reason.startswith("failure_mode.mechanism")


def test_a_mapping_to_no_failure_mode_is_refused() -> None:
    reason = validate_mapping(mapping_without("db.slow_query", failure_modes=frozenset()))

    assert reason.startswith("failure_mode.empty")
    assert "cannot classify it at all" in reason


def test_a_primary_mode_outside_the_mapped_set_is_refused() -> None:
    reason = validate_mapping(
        mapping_without(
            "db.slow_query",
            failure_modes=frozenset({FailureMode.LATENCY}),
            primary=FailureMode.CAPACITY,
        )
    )

    assert reason.startswith("failure_mode.primary")
    assert "the answer and the set disagree" in reason


# -- taxonomy integrity ---------------------------------------------------------


def test_the_taxonomy_table_itself_validates() -> None:
    assert validate_failure_modes() == ""
    assert set(FAILURE_MODE_PROFILES) == set(FAILURE_MODES)
    assert len(FAILURE_MODES) == 18


def test_no_taxonomy_member_is_empty() -> None:
    """A mode nothing maps to is a mode the reports can never populate."""
    coverage = taxonomy_coverage()

    assert coverage.empty == ()
    assert coverage.complete


def test_coverage_counts_the_whole_live_catalog() -> None:
    coverage = taxonomy_coverage()

    assert coverage.mapped == coverage.total == 141
    # A fault presenting as three modes counts once per mode, so the counts sum
    # to more than the fault count — that is what "presents as" means.
    assert sum(coverage.by_mode.values()) > coverage.total
    assert coverage.count(FailureMode.AVAILABILITY) > 0
    assert coverage.share_pct(FailureMode.AVAILABILITY) > 0.0
    assert coverage.count(FailureMode.AVAILABILITY) == len(
        faults_for_mode(FailureMode.AVAILABILITY)
    )


def test_coverage_counts_cannot_be_edited_in_place() -> None:
    """``frozen=True`` does not reach inside a dict field, so the hole is closed.

    ``FailureModeCoverage`` is a *measurement*. If a caller can bump a count it
    can turn a coverage report into a claim the catalog does not support, and
    nothing downstream would notice — ``complete`` is derived from these very
    numbers.
    """
    coverage = taxonomy_coverage()
    mode = FailureMode.AVAILABILITY
    before = coverage.count(mode)

    with pytest.raises(TypeError):
        coverage.by_mode[mode] = before + 1  # type: ignore[index]

    assert coverage.count(mode) == before


def test_coverage_is_frozen_against_attribute_rebinding_too() -> None:
    """The dataclass half of the contract, asserted next to the container half."""
    coverage = taxonomy_coverage()

    with pytest.raises(dataclasses.FrozenInstanceError):
        coverage.total = 0  # type: ignore[misc]

    assert coverage.total > 0


def test_every_mode_is_reachable_through_its_own_lookup() -> None:
    for mode in FAILURE_MODES:
        faults = faults_for_mode(mode)
        assert faults, mode
        for fault_id in faults:
            assert mode in failure_modes_for(fault_id), fault_id


def test_a_mode_outside_the_taxonomy_is_a_lookup_error() -> None:
    with pytest.raises(LookupError, match="not in the taxonomy"):
        faults_for_mode("not-a-mode")  # type: ignore[arg-type]


def test_the_also_set_is_exactly_the_non_primary_modes() -> None:
    for fault_id in sorted(mapped_fault_ids()):
        mapping = mapping_for(fault_id)

        assert mapping.also == mapping.failure_modes - {mapping.primary}, fault_id
        assert mapping.primary not in mapping.also, fault_id


# -- compliance templates -------------------------------------------------------


def test_a_compliance_template_cannot_assert_compliance() -> None:
    """The plan's honesty rule, enforced: a template's existence is not evidence."""
    template = dataclasses.replace(COMPLIANCE_TEMPLATES[0], asserts_compliance=True)
    assert isinstance(template, ComplianceControl)

    with pytest.raises(InvariantViolationError) as caught:
        require_non_asserting_template(template)

    assert caught.value.rule == "compliance.template_must_not_assert"
    assert "someone else's control programme" in str(caught.value)


def test_a_template_with_no_customer_obligations_is_refused() -> None:
    """A control is satisfied by the customer's programme, not by a document here."""
    template = dataclasses.replace(COMPLIANCE_TEMPLATES[0], customer_obligations=())

    with pytest.raises(InvariantViolationError) as caught:
        compliance_statement(template)

    assert caught.value.rule == "compliance.template_must_record_obligations"


def test_a_template_requesting_no_evidence_is_refused() -> None:
    template = dataclasses.replace(COMPLIANCE_TEMPLATES[0], required_evidence=())

    with pytest.raises(InvariantViolationError) as caught:
        compliance_statement(template)

    assert caught.value.rule == "compliance.template_must_request_evidence"


def test_a_template_covering_no_failure_mode_is_refused() -> None:
    template = dataclasses.replace(COMPLIANCE_TEMPLATES[0], covered_failure_modes=frozenset())

    with pytest.raises(InvariantViolationError) as caught:
        compliance_statement(template)

    assert caught.value.rule == "compliance.template_must_cover_failure_modes"


def test_a_shipped_template_passes_and_its_statement_never_claims_conformance() -> None:
    for template in COMPLIANCE_TEMPLATES:
        assert template.asserts_compliance is False
        statement = compliance_statement(template)

        assert template.control_id in statement
        assert "not a finding" in statement
        assert "an attestation of conformance" in statement
        assert "must perform their own assessment" in statement
        # The strongest thing the type may claim is about the supplied evidence.
        assert template.evidence_complete


def test_a_template_titled_as_a_compliance_claim_still_cannot_become_one() -> None:
    """Naming compliance in the title is not a licence to assert it."""
    template = dataclasses.replace(
        COMPLIANCE_TEMPLATES[0], title="SOC 2 Type II compliant resilience testing"
    )

    statement = compliance_statement(template)

    assert "compliant resilience testing" in statement
    assert "an attestation of conformance" in statement
    assert not statement.rstrip().endswith("compliant.")


def test_a_template_statement_names_the_evidence_it_would_need_not_the_evidence_it_found() -> None:
    template = COMPLIANCE_TEMPLATES[1]

    statement = compliance_statement(template)

    for kind in template.required_evidence:
        assert kind in statement
    assert "failure modes" in statement
    assert "customer's remaining obligations" in statement
