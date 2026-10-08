"""Plan 11 Phase 4 — observations as evidence, citations verified, conditions sealed.

The plan's Phase 4 acceptance criterion is one sentence: *a verdict whose cited
observations cannot be found in evidence fails verification*. This suite is that
criterion plus the three things it depends on:

* **Redaction on the way in.** :func:`mayhem.domain.probe_evidence.envelope_observations`
  is the only place a reading becomes a document, and every attempt produces a row —
  including the ones with no number, because "the run could not watch this" and "the
  run watched this and it was fine" are different facts and a filter that keeps only
  the rows with values in them erases the first.
* **Citations findable.** :func:`fingerprint_for` computes a digest from the *sample*
  side and :meth:`ProbeEvidenceRecord.with_fingerprint` computes the same digest from
  the *record* side, from one shared payload function. The negative control for that
  is the important one: a fingerprint payload that had drifted between the two sides
  would make every citation unmatched — which looks exactly like fabricated evidence,
  and would be indistinguishable from a working verification.
* **Conditions sealed with the run.** A condition tree edited after the run is a stop
  nobody can reproduce, so a sealed set refuses drift in the conditions *and* in the
  probe pins, together.

Plus the synthetic-transaction rule: a business transaction graded on status codes
alone is a network check wearing a business check's name, and a transaction mayhem
watched three steps of is not a correct transaction.

The seal store is exercised against a **real migrated SQLite database** built from
this module's own ``MIGRATION_SQL``, so the schema under test is the schema a
deployment would run — not a table a fixture conjured to fit the code.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from mayhem.controller.probe_service import (
    ProbeObservation,
    ProbePorts,
    ProbeService,
    reading_view,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.probe_evidence import (
    BUSINESS_ASSERTIONS,
    BusinessAssertion,
    CitationVerification,
    ProbeEvidenceRecord,
    ReadingView,
    SealedConditionSet,
    SyntheticOutcome,
    SyntheticStepResult,
    assert_citations_verified,
    envelope_observations,
    fingerprint_for,
    synthetic_outcome,
    synthetic_verdict,
    verify_citations,
)
from mayhem.domain.probes import (
    LifecycleStage,
    ProbeCatalog,
    ProbeDefinition,
    ProbeFamily,
    ProbePin,
    ProbePlan,
)
from mayhem.domain.steady_state import AbsoluteExpect
from mayhem.domain.stop_conditions import (
    Condition,
    FiresWhen,
    Threshold,
)
from mayhem.infra.migrator import run_migrations
from mayhem.infra.probe_seal_store import (
    DOWN_SQL,
    PROBE_SEAL_MIGRATION,
    PROBE_SEAL_TABLE,
    PROBE_SEAL_VERSION,
    ProbeSealIntegrityError,
    ProbeSealTable,
    probe_seal_artifact,
    records_from,
)

RUN_ID = "r-drill-a1b2c3d4"


# -- fakes ---------------------------------------------------------------------------


class FakePort:
    """A port answering a fixed value, or declining."""

    name = "fake"

    def __init__(self, value: float | None = 400.0, *, unit: str = "ms") -> None:
        self.value = value
        self.unit = unit

    def observe(self, definition: ProbeDefinition) -> ProbeObservation | None:
        if self.value is None:
            return None
        return ProbeObservation(
            value=self.value,
            unit=self.unit,
            provenance="fake",
            evidence_ref=f"fake://api/{definition.id}",
            detail="token=sk-live-should-not-survive",
        )


def _http(probe_id: str = "http.api", *, unit: str = "ms", version: str = "1.0") -> ProbeDefinition:
    return ProbeDefinition(
        id=probe_id,
        family=ProbeFamily.HTTP,
        version=version,
        unit=unit,
        endpoint="https://api.internal/latency",
        stages=(LifecycleStage.DURING_FAULT,),
        cadence=1.0,
    )


def _service(definition: ProbeDefinition, port: FakePort) -> ProbeService:
    return ProbeService(
        catalogue=ProbeCatalog(definitions=(definition,)),
        plan=ProbePlan(pins=(ProbePin.of(definition),)),
        ports=ProbePorts(ports={definition.family: port}),
    )


def _breach(metric: str = "http.api", *, name: str = "latency") -> Condition:
    return Condition.metric(
        metric,
        Threshold(fires_when=FiresWhen.BROKEN, expect=AbsoluteExpect(lte=250.0)),
        for_samples=2,
        name=name,
    )


#: The two instants the fired-result fixture records at. Named because several
#: assertions below depend on which reading is present and which is missing.
FIRST_AT = 2.0
SECOND_AT = 3.0


def _readings():
    """Two breaching readings at :data:`FIRST_AT` and :data:`SECOND_AT`."""
    definition = _http()
    service = _service(definition, FakePort(400.0))
    return definition, [
        service.collect(definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=at)
        for at in (FIRST_AT, SECOND_AT)
    ]


def _fired(condition: Condition | None = None):
    """A fired result over two recorded readings, plus those readings."""
    definition, readings = _readings()
    result = ProbeService.evaluate(condition or _breach(), readings, now_epoch_s=3.0)
    return definition, readings, result


# -- 1. observations become rows, redacted, gaps kept --------------------------------


class TestObservationsBecomeEvidenceRows:
    def test_every_attempt_becomes_a_row_including_the_ones_with_no_number(self) -> None:
        """The load-bearing row property: an absent reading is still a row."""
        definition = _http()
        service = _service(definition, FakePort(None))

        reading = service.collect(definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)
        rows = envelope_observations([reading_view(reading)])

        assert len(rows) == 1
        assert rows[0]["availability"] == "unavailable"
        assert rows[0]["value"] is None
        assert rows[0]["note"]

    def test_a_zero_reading_is_distinguishable_from_an_absent_one(self) -> None:
        """Both are "no number" to a naive reader; they are different findings."""
        definition = _http()
        zero = _service(definition, FakePort(0.0)).collect(
            definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )
        absent = _service(definition, FakePort(None)).collect(
            definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )

        rows = envelope_observations([reading_view(zero), reading_view(absent)])

        assert rows[0]["availability"] == "available"
        assert rows[0]["value"] == 0.0
        assert rows[1]["availability"] == "unavailable"
        assert rows[1]["value"] is None

    def test_the_row_is_json_safe_and_never_carries_a_non_finite_value(self) -> None:
        """The payload is hash-chained; ``inf`` in it would be unreadable."""
        definition = _http()
        reading = _service(definition, FakePort(1.5)).collect(
            definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )

        row = envelope_observations([reading_view(reading)])[0]
        serialised = json.dumps(row)

        assert "Infinity" not in serialised
        assert "NaN" not in serialised
        assert json.loads(serialised)["value"] == 1.5

    def test_a_non_finite_reading_is_refused_before_it_can_reach_a_row(self) -> None:
        """The row guard, and the reason it is at the row and not in the engine."""
        with pytest.raises(InvariantViolationError) as caught:
            ProbeEvidenceRecord.of(
                ReadingView(
                    probe_id="http.api",
                    family="http",
                    stage="during-fault",
                    availability="available",
                    at_epoch_s=1.0,
                    value=float("inf"),
                    unit="ms",
                    provenance="fake",
                    evidence_ref="fake://api/http.api",
                )
            )

        assert caught.value.rule == "probes.reading_value_not_finite"
        assert "hash-chained" in str(caught.value)

    def test_a_credential_in_a_note_is_redacted_before_the_row_exists(self) -> None:
        """``FakePort`` plants a token in every note, so this cannot pass by luck."""
        definition = _http()
        reading = _service(definition, FakePort(400.0)).collect(
            definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )

        rows = envelope_observations([reading_view(reading)])
        serialised = json.dumps(rows)

        assert "sk-live-should-not-survive" not in serialised
        assert "REDACTED" in serialised
        assert rows[0]["value"] == 400.0

    def test_a_blank_probe_id_is_refused_because_evidence_must_be_nameable(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            ProbeEvidenceRecord.of(
                ReadingView(
                    probe_id="   ",
                    family="http",
                    stage="during-fault",
                    availability="unavailable",
                    at_epoch_s=1.0,
                    value=None,
                    unit="",
                    provenance="",
                    evidence_ref="probe/x/unbound",
                )
            )

        assert caught.value.rule == "probes.reading_field_blank"
        assert "cannot be cited" in str(caught.value)

    def test_the_provenance_and_the_evidence_reference_survive_into_the_row(self) -> None:
        definition = _http()
        reading = _service(definition, FakePort(400.0)).collect(
            definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )

        row = envelope_observations([reading_view(reading)])[0]

        assert row["provenance"] == "fake"
        assert row["evidence_ref"] == "fake://api/http.api"
        assert row["family"] == "http"
        assert row["stage"] == "during-fault"


# -- 2. citations must be findable ---------------------------------------------------


class TestAVerdictWhoseCitationsCannotBeFoundFailsVerification:
    """The plan's Phase 4 acceptance criterion, as tests."""

    def test_a_firing_citing_recorded_observations_verifies(self) -> None:
        _definition, readings, result = _fired()
        records = tuple(ProbeEvidenceRecord.of(reading_view(reading)) for reading in readings)

        verification = assert_citations_verified(result, records)

        assert isinstance(verification, CitationVerification)
        assert verification.ok
        assert len(verification.verified) == 2
        assert verification.missing == ()
        assert "all found in the recorded evidence" in verification.describe()

    def test_a_firing_whose_observations_are_absent_fails_verification(self) -> None:
        """The criterion, negatively: evidence that was never recorded.

        **The control.** An implementation that returned a
        :class:`CitationVerification` with ``ok=True`` and no checks would pass the
        positive test above. This one has nothing to match against, so any
        implementation that does not actually compare cannot pass it.
        """
        _definition, _readings, result = _fired()

        with pytest.raises(InvariantViolationError) as caught:
            assert_citations_verified(result, ())

        assert caught.value.rule == "probes.verdict_cites_unrecorded_observation"
        assert "cannot be reviewed, replayed or defended" in str(caught.value)
        assert "http.api@2" in str(caught.value)
        assert "http.api@3" in str(caught.value)

    def test_a_partially_recorded_firing_fails_and_names_only_the_missing_citations(self) -> None:
        _definition, readings, result = _fired()
        records = (
            ProbeEvidenceRecord.of(reading_view(readings[0])),
            # The second reading was recorded with a different value — i.e. the
            # evidence does not describe the sample the stop cites.
            ProbeEvidenceRecord.of(
                ReadingView(
                    probe_id="http.api",
                    family="http",
                    stage="during-fault",
                    availability="available",
                    at_epoch_s=3.0,
                    value=999.0,
                    unit="ms",
                    provenance="fake",
                    evidence_ref="fake://api/http.api",
                )
            ),
        )

        verification = verify_citations(result, records)

        assert not verification.ok
        assert len(verification.verified) == 1
        assert len(verification.missing) == 1
        assert "http.api@3" in verification.missing[0]

    def test_a_citation_never_matches_an_unavailable_record(self) -> None:
        """The "no probe data may support a verdict" rule at the evidence layer.

        An unavailable row shares the metric, the unit and the instant with the
        sample — everything but the value. If it were matchable, a fabricated
        citation would validate against a row that says mayhem saw nothing, which
        is the whole failure.
        """
        _definition, _readings, result = _fired()
        unavailable = ProbeEvidenceRecord(
            probe_id="http.api",
            family="http",
            stage="during-fault",
            availability="unavailable",
            at_epoch_s=2.0,
            value=None,
            unit="",
            provenance="",
            evidence_ref="probe/http.api/unbound",
            fingerprint="0" * 64,
        )

        verification = verify_citations(result, [unavailable])

        assert not verification.ok
        assert len(verification.missing) == 2
        # And with the check off, the row is at least considered — which is what
        # makes the default a decision rather than an accident of the data.
        relaxed = verify_citations(result, [unavailable], require_all_available=False)
        assert relaxed.verified == ()

    def test_the_two_fingerprint_sides_compute_the_same_digest(self) -> None:
        """The negative control for the shared payload.

        **This is the control that matters most in this file.** If the sample side
        and the record side computed their payloads from two different field sets,
        every citation would be unmatched — and an unmatched citation looks exactly
        like fabricated evidence, so the failure would be indistinguishable from the
        thing this phase exists to catch. The assertion is that both sides agree on a
        reading produced by the real engine.
        """
        _definition, readings, result = _fired()
        records = [ProbeEvidenceRecord.of(reading_view(reading)) for reading in readings]

        sample_fingerprints = [fingerprint_for(sample) for sample in result.samples]
        record_fingerprints = [record.fingerprint for record in records]

        assert set(sample_fingerprints) <= set(record_fingerprints)
        assert all(len(fingerprint) == 64 for fingerprint in sample_fingerprints)

    def test_the_stage_is_not_part_of_a_readings_identity(self) -> None:
        """Why, stated as a test, because it is easy to "fix" the wrong way.

        A sample carries no lifecycle stage. Hashing the stage into the fingerprint
        would make a citation unmatched against evidence recorded by a sweep that
        walked a different stage list — a false positive that reads as tampering.
        """
        _definition, readings, _result = _fired()
        in_fault = ProbeEvidenceRecord.of(reading_view(readings[0]))
        view = reading_view(readings[0])

        elsewhere = ProbeEvidenceRecord.of(
            ReadingView(
                probe_id=view.probe_id,
                family=view.family,
                stage="final-verification",
                availability=view.availability,
                at_epoch_s=view.at_epoch_s,
                value=view.value,
                unit=view.unit,
                provenance=view.provenance,
                evidence_ref=view.evidence_ref,
            )
        )

        assert elsewhere.stage != in_fault.stage
        assert elsewhere.fingerprint == in_fault.fingerprint

    def test_the_verification_result_serialises_for_an_artifact(self) -> None:
        _definition, readings, result = _fired()
        records = [ProbeEvidenceRecord.of(reading_view(reading)) for reading in readings]

        payload = verify_citations(result, records).to_dict()

        assert json.loads(json.dumps(payload))["ok"] is True
        assert payload["condition"] == "latency"


# -- 3. conditions sealed with the run ------------------------------------------------


class TestConditionsAreSealedWithTheRun:
    def test_a_sealed_set_carries_a_digest_over_conditions_and_pins(self) -> None:
        definition = _http()
        sealed = SealedConditionSet(
            run_id=RUN_ID, conditions=(_breach(),), pins=(ProbePin.of(definition),)
        ).seal()

        sealed.assert_unchanged()
        assert len(sealed.sealed_digest) == 64
        assert sealed.to_dict()["sealed_digest"] == sealed.sealed_digest

    def test_an_unsealed_set_is_refused_rather_than_assumed_intact(self) -> None:
        """A set with no digest cannot be checked for drift, so it is refused."""
        unsealed = SealedConditionSet(run_id=RUN_ID, conditions=(_breach(),))

        with pytest.raises(InvariantViolationError) as caught:
            unsealed.assert_unchanged()

        assert caught.value.rule == "probes.sealed_conditions_unsealed"
        assert "cannot be checked for drift" in str(caught.value)

    def test_a_rewritten_bound_is_seal_drift(self) -> None:
        sealed = SealedConditionSet(run_id=RUN_ID, conditions=(_breach(),)).seal()
        tampered = sealed.model_copy(update={"conditions": (_breach(name="looser"),)})

        with pytest.raises(InvariantViolationError) as caught:
            tampered.assert_unchanged()

        assert caught.value.rule == "probes.sealed_conditions_drifted"
        assert "no longer reproducible" in str(caught.value)

    def test_a_moved_probe_pin_is_seal_drift_even_with_the_conditions_unchanged(self) -> None:
        """The whole reason the pins are inside the digest.

        A condition tree that never changed while the probe definition it reads was
        edited in place is the drift :mod:`mayhem.domain.probes` exists to catch, and
        at this boundary it is caught by asking the question that is actually asked:
        did the thing that read differ from the thing that was pinned?
        """
        pinned = _http()
        sealed = SealedConditionSet(
            run_id=RUN_ID, conditions=(_breach(),), pins=(ProbePin.of(pinned),)
        ).seal()
        moved = sealed.model_copy(update={"pins": (ProbePin.of(_http(version="2.0")),)})

        with pytest.raises(InvariantViolationError) as caught:
            moved.assert_unchanged()

        assert caught.value.rule == "probes.sealed_conditions_drifted"

    def test_two_runs_with_the_same_conditions_have_different_digests(self) -> None:
        first = SealedConditionSet(run_id="r-a", conditions=(_breach(),)).seal()
        second = SealedConditionSet(run_id="r-b", conditions=(_breach(),)).seal()

        assert first.sealed_digest != second.sealed_digest


# -- 4. the durable seal --------------------------------------------------------------


@pytest.fixture
def conn() -> sqlite3.Connection:
    """A real migrated database from this module's own DDL.

    Spliced rather than imported from :mod:`mayhem.infra.migrations`, because that
    registry is owned by another work item and the claim under test is *this*
    module's schema — so the migration object and its ``down_statements`` are applied
    here and both are exercised.
    """
    connection = sqlite3.connect(":memory:")
    applied = run_migrations(connection, [PROBE_SEAL_MIGRATION])
    assert applied == [PROBE_SEAL_MIGRATION.migration_id]
    yield connection
    for statement in DOWN_SQL:
        connection.execute(statement)
    connection.close()


class TestTheSealIsDurableAndVerified:
    def test_a_seal_round_trips_through_a_migrated_database(self, conn: sqlite3.Connection) -> None:
        _definition, readings, result = _fired()
        records = [ProbeEvidenceRecord.of(reading_view(reading)) for reading in readings]
        verification = verify_citations(result, records)
        sealed = SealedConditionSet(
            run_id=RUN_ID, conditions=(_breach(),), pins=(ProbePin.of(_definition),)
        ).seal()

        table = ProbeSealTable(conn)
        written = table.seal(
            run_id=RUN_ID,
            stage="during-fault",
            at_epoch_s=3.0,
            views=[reading_view(reading) for reading in readings],
            sealed=sealed,
            citations=verification.to_dict(),
        )

        read_back = table.read(RUN_ID)

        assert len(read_back) == 1
        assert read_back[0].payload_digest == written.payload_digest
        assert read_back[0].conditions_digest == sealed.sealed_digest
        assert len(read_back[0].observations) == 2
        assert json.loads(json.dumps(read_back[0].observations))[0]["value"] == 400.0

    def test_citations_are_verified_against_the_persisted_bytes(
        self, conn: sqlite3.Connection
    ) -> None:
        """Against persisted evidence, not against the objects still in memory.

        The objects in memory are the ones a bug could have produced. Re-deriving a
        firing's verification from the database is the case that matters for a
        reviewer in another process.
        """
        _definition, readings, result = _fired()
        sealed = SealedConditionSet(run_id=RUN_ID, conditions=(_breach(),)).seal()
        table = ProbeSealTable(conn)
        table.seal(
            run_id=RUN_ID,
            stage="during-fault",
            at_epoch_s=3.0,
            views=[reading_view(reading) for reading in readings],
            sealed=sealed,
            citations=verify_citations(
                result,
                [ProbeEvidenceRecord.of(reading_view(reading)) for reading in readings],
            ).to_dict(),
        )

        seal = table.read(RUN_ID)[0]
        rechecked = assert_citations_verified(result, records_from(seal))

        assert rechecked.ok
        table.assert_citations_in_evidence(RUN_ID)

    def test_a_stored_observation_that_moved_fails_the_read(self, conn: sqlite3.Connection) -> None:
        """The negative control for the read path's digest check.

        **The control:** without the digest check on read, this test's own edit
        would be indistinguishable from a legitimate seal, and a reviewer would be
        handed altered evidence with a valid-looking digest column.
        """
        _definition, readings, _result = _fired()
        table = ProbeSealTable(conn)
        table.seal(
            run_id=RUN_ID,
            stage="during-fault",
            at_epoch_s=3.0,
            views=[reading_view(reading) for reading in readings],
            sealed=SealedConditionSet(run_id=RUN_ID, conditions=(_breach(),)).seal(),
            citations={"ok": True, "verified": []},
        )

        conn.execute(
            f"UPDATE {PROBE_SEAL_TABLE} SET observations_json = ? WHERE run_id = ?",
            (json.dumps([{"probe_id": "http.api", "value": 1.0}]), RUN_ID),
        )

        with pytest.raises(ProbeSealIntegrityError) as caught:
            table.read(RUN_ID)

        assert caught.value.rule == "probes.seal_payload_drifted"
        assert caught.value.stored_digest != caught.value.recomputed_digest
        assert "nothing this seal says can be relied on" in str(caught.value)

    def test_a_citation_in_the_seal_that_is_not_in_the_evidence_is_named(
        self, conn: sqlite3.Connection
    ) -> None:
        """The acceptance criterion again, against persisted bytes."""
        _definition, readings, _result = _fired()
        table = ProbeSealTable(conn)
        table.seal(
            run_id=RUN_ID,
            stage="during-fault",
            at_epoch_s=3.0,
            views=[reading_view(reading) for reading in readings],
            sealed=SealedConditionSet(run_id=RUN_ID, conditions=(_breach(),)).seal(),
            citations={"ok": True, "verified": ["f" * 64]},
        )

        with pytest.raises(ProbeSealIntegrityError) as caught:
            table.assert_citations_in_evidence(RUN_ID)

        assert caught.value.rule == "probes.seal_cites_unrecorded_observation"
        assert "f" * 64 in str(caught.value)

    def test_sealing_with_an_unsealed_set_is_refused(self, conn: sqlite3.Connection) -> None:
        _definition, readings, _result = _fired()
        table = ProbeSealTable(conn)

        with pytest.raises(InvariantViolationError) as caught:
            table.seal(
                run_id=RUN_ID,
                stage="during-fault",
                at_epoch_s=3.0,
                views=[reading_view(reading) for reading in readings],
                sealed=SealedConditionSet(run_id=RUN_ID, conditions=(_breach(),)),
                citations={},
            )

        assert caught.value.rule == "probes.seal_conditions_unsealed"
        # Nothing was written on the way to the refusal.
        assert table.read(RUN_ID) == ()

    def test_sealing_a_run_with_another_runs_conditions_is_refused(
        self, conn: sqlite3.Connection
    ) -> None:
        _definition, readings, _result = _fired()
        table = ProbeSealTable(conn)

        with pytest.raises(InvariantViolationError) as caught:
            table.seal(
                run_id=RUN_ID,
                stage="during-fault",
                at_epoch_s=3.0,
                views=[reading_view(reading) for reading in readings],
                sealed=SealedConditionSet(run_id="r-other", conditions=(_breach(),)).seal(),
                citations={},
            )

        assert caught.value.rule == "probes.seal_run_id_mismatch"

    def test_a_sealed_row_keeps_both_the_observed_and_the_unobserved(
        self, conn: sqlite3.Connection
    ) -> None:
        """The reviewer's question — *what could this run not see?* — has an answer.

        **The control:** a seal that only stored the readings with numbers in it
        would pass every digest and citation check above and still answer this
        question wrongly, by omitting it.
        """
        definition = _http()
        good = _service(definition, FakePort(400.0)).collect(
            definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=2.0
        )
        dead = _service(definition, FakePort(None)).collect(
            definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=3.0
        )
        table = ProbeSealTable(conn)
        table.seal(
            run_id=RUN_ID,
            stage="during-fault",
            at_epoch_s=3.0,
            views=[reading_view(good), reading_view(dead)],
            sealed=SealedConditionSet(run_id=RUN_ID, conditions=(_breach(),)).seal(),
            citations={"ok": True, "verified": []},
        )

        rows = table.observations_for(RUN_ID)

        assert [row["availability"] for row in rows] == ["available", "unavailable"]
        assert rows[1]["value"] is None
        assert "no observation" in rows[1]["note"]

    def test_the_migration_is_version_36_and_reversible(self) -> None:
        assert PROBE_SEAL_VERSION == 36
        assert PROBE_SEAL_MIGRATION.version == 36
        assert PROBE_SEAL_MIGRATION.name == "probe_seal"
        assert PROBE_SEAL_MIGRATION.migration_id == "0036_probe_seal"
        assert DOWN_SQL, "a migration with no down statements cannot be rolled back"
        assert any("DROP TABLE" in statement for statement in DOWN_SQL)

    def test_the_artifact_label_names_the_write_path(self) -> None:
        assert probe_seal_artifact(RUN_ID) == f"probe:seal:{RUN_ID}"


# -- 5. synthetic transactions --------------------------------------------------------


def _step(step: str, assertion: BusinessAssertion, ok: bool | None, at: float = 1.0):
    return SyntheticStepResult(step=step, assertion=assertion, ok=ok, at_epoch_s=at)


class TestSyntheticTransactionsJudgeBusinessCorrectness:
    def test_all_status_ok_is_not_business_correctness(self) -> None:
        """**The negative control for the whole synthetic rule.**

        Every step returned 200 and one of them charged a card without creating an
        order. A probe that graded "the calls worked" would report this transaction
        as correct. It is not.
        """
        steps = (
            _step("cart", BusinessAssertion.STATUS_OK, True, 1.0),
            _step("pay", BusinessAssertion.STATUS_OK, True, 2.0),
            _step("confirm", BusinessAssertion.STATUS_OK, True, 3.0),
            _step("confirm", BusinessAssertion.FIELD_EQUALS, False, 3.0),
        )

        verdict = synthetic_outcome(steps)

        assert verdict.outcome is SyntheticOutcome.INCORRECT
        assert verdict.asserts_correctness is False
        assert "confirm:field-equals" in verdict.failed_steps

    def test_a_transaction_with_every_assertion_holding_is_correct(self) -> None:
        steps = (
            _step("cart", BusinessAssertion.STATUS_OK, True, 1.0),
            _step("pay", BusinessAssertion.STATUS_OK, True, 2.0),
            _step("pay", BusinessAssertion.NO_ERROR_SIGNAL, True, 2.0),
            _step("confirm", BusinessAssertion.ORDER_RESPECTED, True, 3.0),
        )

        verdict = synthetic_outcome(steps)

        assert verdict.outcome is SyntheticOutcome.CORRECT
        assert verdict.supports_verdict
        assert verdict.asserts_correctness

    def test_a_step_mayhem_could_not_observe_is_not_a_passing_step(self) -> None:
        """The third outcome, and the reason it exists."""
        steps = (
            _step("cart", BusinessAssertion.STATUS_OK, True, 1.0),
            _step("pay", BusinessAssertion.STATUS_OK, True, 2.0),
            _step("confirm", BusinessAssertion.FIELD_EQUALS, None, 3.0),
        )

        verdict = synthetic_outcome(steps)

        assert verdict.outcome is SyntheticOutcome.UNDETERMINED
        assert verdict.supports_verdict is False
        assert verdict.asserts_correctness is False
        assert "confirm:field-equals" in verdict.undetermined_steps
        assert "not a business check that passed" in verdict.describe()

    def test_undetermined_wins_over_observed_failures(self) -> None:
        """We also saw a failure is not a reason to assert we saw everything."""
        steps = (
            _step("cart", BusinessAssertion.STATUS_OK, False, 1.0),
            _step("pay", BusinessAssertion.FIELD_EQUALS, None, 2.0),
        )

        verdict = synthetic_outcome(steps)

        assert verdict.outcome is SyntheticOutcome.UNDETERMINED
        assert "cart:status-ok" in verdict.failed_steps

    def test_a_transaction_with_no_steps_is_refused_rather_than_passed(self) -> None:
        """A vacuous check is refused, exactly as a vacuous gate is."""
        with pytest.raises(InvariantViolationError) as caught:
            synthetic_outcome(())

        assert caught.value.rule == "probes.synthetic_transaction_vacuous"
        assert "evaluated nothing is refused rather than passed" in str(caught.value)

    def test_an_assertion_outside_the_vocabulary_is_refused(self) -> None:
        """An assertion nobody can check is not a business check."""
        with pytest.raises(InvariantViolationError) as caught:
            SyntheticStepResult(
                step="pay",
                assertion="looks-fine-to-me",  # type: ignore[arg-type]
                ok=True,
            )

        assert caught.value.rule == "probes.synthetic_assertion_unknown"
        assert "certifies nothing" in str(caught.value)

    def test_a_blank_step_name_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            SyntheticStepResult(step="  ", assertion=BusinessAssertion.STATUS_OK, ok=True)

        assert caught.value.rule == "probes.synthetic_step_unnamed"

    def test_a_non_finite_step_time_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            SyntheticStepResult(
                step="pay",
                assertion=BusinessAssertion.ORDER_RESPECTED,
                ok=True,
                at_epoch_s=float("inf"),
            )

        assert caught.value.rule == "probes.synthetic_step_time_not_finite"
        assert "order respected" in str(caught.value)

    def test_the_status_assertion_is_one_of_four_not_the_verdict(self) -> None:
        """Spelled as an assertion so the vocabulary cannot shrink to one."""
        assert BusinessAssertion.STATUS_OK in BUSINESS_ASSERTIONS
        assert len(BUSINESS_ASSERTIONS) == 4
        assert {member.value for member in BusinessAssertion} == {
            "status-ok",
            "field-equals",
            "order-respected",
            "no-error-signal",
        }

    def test_a_verdict_serialises_for_an_envelope_row(self) -> None:
        steps = (_step("cart", BusinessAssertion.STATUS_OK, True, 1.0),)

        payload = synthetic_verdict(steps)

        assert json.loads(json.dumps(payload))["outcome"] == "correct"
        assert payload["supports_verdict"] is True
