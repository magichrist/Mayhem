"""Plan 12 Phase 2: the attestation engine — migration, sealing, persistence.

The load-bearing assertion in this file is negative: a chain row edited behind the
model's back must be rejected by the *persisted* verifier, naming the event that
failed. A store that only ever re-verified its own in-memory objects would pass
every positive test here and still be worthless.

Honesty under test throughout: Phase 2 signs nothing, so every stored manifest is
unsigned and says so, with a reason. These tests fail the day that stops being
true in either direction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from mayhem.domain.approval import ApprovalState
from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    Manifest,
    RetentionClass,
    seal_events,
)
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.domain.policy import PolicyDecision
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationError,
    AttestationRepository,
    AuthorizationMismatchError,
    EvidenceNotAttestableError,
    RunAuthorization,
    SigningNotImplementedError,
    seal_run_evidence,
)
from mayhem.infra.migrations import ALL_MIGRATIONS, M0023_ATTESTATION_RETENTION
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

#: Position of this phase's migration in the ordered tuple. Slicing by index
#: rather than by version keeps the test correct whatever other agents append.
MIGRATION_INDEX = ALL_MIGRATIONS.index(M0023_ATTESTATION_RETENTION)
BEFORE = ALL_MIGRATIONS[:MIGRATION_INDEX]
PRIOR_HEAD = M0023_ATTESTATION_RETENTION.version - 1

READING = AttestedTimestamp(
    wall_clock=datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC),
    monotonic_ns=1_000_000,
    uncertainty_ms=0.5,
    source="system",
)
LATER = AttestedTimestamp(
    wall_clock=datetime(2026, 3, 1, 12, 5, 0, tzinfo=UTC),
    monotonic_ns=2_000_000,
    uncertainty_ms=0.5,
    source="system",
)

ATTESTATION_TABLES = (
    "attestation_chains",
    "attestation_events",
    "attestation_manifests",
    "evidence_retention",
    "retention_tombstones",
)


def make_envelope(
    run_id: str = "run-1", *, redaction_marker: bool = True, **overrides: object
) -> EvidenceEnvelope:
    """A written, redacted evidence envelope — the thing being attested to."""
    fields: dict[str, object] = {
        "run_id": run_id,
        "plan_hash": "plan-hash-1",
        "verdict": "pass",
        "step_reports": ({"step_id": "s1", "status": "completed"},),
        "created_at": "2026-03-01T12:00:00+00:00",
        "redaction_metrics": (
            {"policy_version": "redaction-v9", "redacted_path_count": 0} if redaction_marker else {}
        ),
    }
    fields.update(overrides)
    return EvidenceEnvelope.model_validate(fields)


def _object_names(store: Store, kind: str) -> list[str]:
    rows = store.query("SELECT name FROM sqlite_master WHERE type = ?", (kind,))
    return [str(dict(row)["name"]) for row in rows]


def open_store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


def seal(store: Store, run_id: str = "run-1", **kwargs: object):
    """Seal a default envelope, with an injected reading for determinism."""
    params: dict[str, object] = {
        "run_status": "completed",
        "verdict": "pass",
        "recorded_at": READING,
        "created_at": READING,
        "manifest_id": f"{run_id}:manifest",
    }
    params.update(kwargs)
    return seal_run_evidence(store, make_envelope(run_id), **params)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Migration                                                                    #
# --------------------------------------------------------------------------- #


def test_migration_applies_tables_and_preserves_prior_schema(tmp_path: Path) -> None:
    store = Store.open_migrated(tmp_path / "mayhem.db", migrations=BEFORE)
    assert store.schema_version == PRIOR_HEAD
    assert set(_object_names(store, "table")).isdisjoint(ATTESTATION_TABLES)

    applied = store.migrate()

    assert "0023_attestation_retention" in applied
    assert store.schema_version == ALL_MIGRATIONS[-1].version
    tables = set(_object_names(store, "table"))
    assert set(ATTESTATION_TABLES) <= tables
    indexes = set(_object_names(store, "index"))
    assert {
        "idx_attestation_chains_created",
        "idx_attestation_events_identity",
        "idx_attestation_events_digest",
        "idx_attestation_manifests_run",
        "idx_evidence_retention_due",
        "idx_retention_tombstones_manifest",
    } <= indexes
    assert store.query("PRAGMA foreign_key_check") == []
    store.close()


def test_migration_down_drops_tables_and_up_again_recreates_them(tmp_path: Path) -> None:
    """The full round trip ADR-M4-5's down-migration acceptance relies on."""
    store = open_store(tmp_path)
    seal(store)

    reversed_ids = store.migrate_down(PRIOR_HEAD)

    assert "0023_attestation_retention" in reversed_ids
    tables = set(_object_names(store, "table"))
    assert set(ATTESTATION_TABLES).isdisjoint(tables)
    assert store.schema_version == PRIOR_HEAD

    reapplied = store.migrate()

    assert "0023_attestation_retention" in reapplied
    tables = set(_object_names(store, "table"))
    assert set(ATTESTATION_TABLES) <= tables
    assert store.query("SELECT COUNT(*) AS n FROM attestation_chains")[0]["n"] == 0
    store.close()


# --------------------------------------------------------------------------- #
# Sealing and persistence                                                      #
# --------------------------------------------------------------------------- #


def test_seal_run_persists_a_chain_that_reverifies_after_reload(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    sealed = seal(store)
    assert sealed.chain_verification.valid
    assert sealed.manifest_verification.valid

    root = sealed.chain_root
    manifest_digest = sealed.manifest.manifest_digest
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    repository = AttestationRepository(reopened)

    events = repository.load_chain("run-1")

    assert [event.event_kind for event in events] == ["evidence.recorded", "run.closed"]
    assert [event.sequence for event in events] == [0, 1]
    assert all(event.is_sealed for event in events)
    assert events[1].previous_digest == events[0].chain_link
    verification = repository.verify_run_chain("run-1")
    assert verification.valid
    assert verification.checked == 2
    assert verification.root_digest == root
    chain_row = repository.load_chain_row("run-1")
    assert chain_row is not None
    assert chain_row["chain_root"] == root

    manifest = repository.load_manifest("run-1:manifest")
    assert manifest is not None
    assert manifest.manifest_digest == manifest_digest
    assert manifest.event_roots == tuple(event.digest for event in events)
    assert repository.verify_stored_manifest("run-1:manifest").valid
    reopened.close()


def test_events_reference_the_envelope_rather_than_copying_it(tmp_path: Path) -> None:
    """The chain points at the evidence; it never becomes a second copy of it."""
    store = open_store(tmp_path)
    envelope = make_envelope()
    sealed = seal_run_evidence(
        store,
        envelope,
        run_status="completed",
        verdict="pass",
        recorded_at=READING,
        created_at=READING,
        manifest_id="run-1:manifest",
    )

    recorded = sealed.events[0].payload

    assert len(recorded["evidence_digest"]) == 64
    assert recorded["plan_hash"] == envelope.plan_hash
    assert recorded["report_id"] == envelope.report_id
    assert sealed.events[0].redaction_policy == "redaction-v9"
    assert sealed.events[1].payload["verdict"] == "pass"
    assert sealed.events[1].payload["run_status"] == "completed"
    # The envelope's own collections are not duplicated into the chain.
    assert "step_reports" not in recorded
    store.close()


def test_stored_manifest_is_unsigned_and_records_why(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    sealed = seal(store)

    assert sealed.signed is False
    assert not sealed.manifest.signed
    assert sealed.manifest.signer_identity == ""
    assert sealed.manifest.trust_root_ref == ""
    assert "unsigned" in sealed.manifest_verification.warnings[0]

    state, reason = AttestationRepository(store).load_signature_state("run-1:manifest")

    assert state == SIGNATURE_UNSIGNED_NO_SIGNING
    assert reason == UNSIGNED_REASON_NO_SIGNING
    assert "no signature bytes" in reason
    store.close()


def test_sealing_is_deterministic_for_the_same_reading(tmp_path: Path) -> None:
    first_store = open_store(tmp_path / "a")
    first = seal(first_store, "run-dup")
    first_store.close()
    second_store = open_store(tmp_path / "b")
    second = seal(second_store, "run-dup")

    assert first.chain_root == second.chain_root
    assert first.manifest.manifest_digest == second.manifest.manifest_digest
    first_store.close()
    second_store.close()


def test_each_run_gets_its_own_chain_and_manifests_chain_by_digest(tmp_path: Path) -> None:
    """Phase 1 defines a chain as starting at genesis; runs link at the manifest."""
    store = open_store(tmp_path)
    first = seal(store, "run-a")
    second = seal(store, "run-b", previous_manifest_digest=first.manifest.manifest_digest)
    repository = AttestationRepository(store)

    assert repository.load_chain("run-b")[0].previous_digest == GENESIS_DIGEST
    assert repository.verify_run_chain("run-a").valid
    assert repository.verify_run_chain("run-b").valid
    linked = repository.load_manifest("run-b:manifest")
    assert linked is not None
    assert linked.previous_manifest_digest == first.manifest.manifest_digest
    # The linkage is inside the sealed digest, so it cannot be edited after sealing.
    assert second.manifest.manifest_digest != first.manifest.manifest_digest
    store.close()


def test_retained_class_travels_from_seal_to_manifest_row(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    seal(store, retention_class=RetentionClass.LEGAL_HOLD)
    row = store.query(
        "SELECT retention_class FROM attestation_manifests WHERE manifest_id = 'run-1:manifest'"
    )[0]

    assert row["retention_class"] == "legal_hold"
    stored = AttestationRepository(store).load_manifest("run-1:manifest")
    assert stored is not None
    assert stored.retention_class is RetentionClass.LEGAL_HOLD
    store.close()


# --------------------------------------------------------------------------- #
# Negative controls                                                            #
# --------------------------------------------------------------------------- #


def test_tampered_event_payload_is_rejected_by_the_persisted_verifier(tmp_path: Path) -> None:
    """Tamper with any covered byte → verification fails, naming the event."""
    store = open_store(tmp_path)
    seal(store)
    with store.write() as conn:
        conn.execute(
            "UPDATE attestation_events SET event_json ="
            ' replace(event_json, \'"verdict":"pass"\', \'"verdict":"not-what-ran"\')'
            " WHERE run_id = 'run-1' AND sequence = 1"
        )
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    repository = AttestationRepository(reopened)

    verification = repository.verify_run_chain("run-1")

    assert not verification.valid
    assert any("run-1:closure" in error for error in verification.errors)
    assert any("content digest mismatch" in error for error in verification.errors)

    manifest_check = repository.verify_stored_manifest("run-1:manifest")
    assert not manifest_check.valid
    reopened.close()


def test_chain_row_naming_a_foreign_root_is_rejected(tmp_path: Path) -> None:
    """Editing the stored root is caught even though every event still hashes."""
    store = open_store(tmp_path)
    seal(store)
    with store.write() as conn:
        conn.execute(
            "UPDATE attestation_chains SET chain_root = ? WHERE run_id = 'run-1'",
            ("a" * 64,),
        )
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    verification = AttestationRepository(reopened).verify_run_chain("run-1")

    assert not verification.valid
    assert any("stored chain root" in error for error in verification.errors)
    reopened.close()


def test_deleting_an_event_row_is_rejected(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    seal(store)
    with store.write() as conn:
        conn.execute("DELETE FROM attestation_events WHERE run_id = 'run-1' AND sequence = 1")
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    verification = AttestationRepository(reopened).verify_run_chain("run-1")

    assert not verification.valid
    assert any("2 events, 1 stored" in error for error in verification.errors)
    reopened.close()


def test_sealing_refuses_evidence_with_no_redaction_marker(tmp_path: Path) -> None:
    store = open_store(tmp_path)

    with pytest.raises(EvidenceNotAttestableError, match="no redaction marker"):
        seal_run_evidence(
            store,
            make_envelope(redaction_marker=False),
            run_status="completed",
            verdict="pass",
            recorded_at=READING,
        )

    assert store.query("SELECT COUNT(*) AS n FROM attestation_events")[0]["n"] == 0
    assert store.query("SELECT COUNT(*) AS n FROM attestation_manifests")[0]["n"] == 0
    store.close()


def test_sealing_refuses_a_signer_because_phase_two_signs_nothing(tmp_path: Path) -> None:
    """A signer seam exists and is refused: Phase 2 mints no signature bytes."""

    class SigningKey:
        identity = "mayhem-local-key-1"
        trust_root_ref = "mayhem-trust-root-v1"

    store = open_store(tmp_path)

    with pytest.raises(SigningNotImplementedError, match="mints no signature bytes"):
        seal(store, signer=SigningKey())

    assert store.query("SELECT COUNT(*) AS n FROM attestation_manifests")[0]["n"] == 0
    store.close()


def test_save_chain_refuses_a_broken_chain_and_writes_nothing(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    sealed = seal(store)
    broken = list(sealed.events)
    broken[1] = broken[1].model_copy(update={"payload": {"run_status": "completed"}})

    with pytest.raises(AttestationError, match="refusing to persist an invalid chain"):
        AttestationRepository(store).save_chain("run-2", broken)

    assert AttestationRepository(store).load_chain("run-2") == ()
    store.close()


def test_save_chain_refuses_unsealed_events(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    unsealed = AttestedEvent(
        event_id="run-3:evidence",
        event_kind="evidence.recorded",
        run_id="run-3",
        sequence=0,
        payload={"evidence_digest": "b" * 64},
        recorded_at=READING,
    )

    with pytest.raises(AttestationError, match="unsealed"):
        AttestationRepository(store).save_chain("run-3", [unsealed])

    assert AttestationRepository(store).load_chain("run-3") == ()
    store.close()


def test_save_manifest_refuses_a_signer_with_no_trust_root(tmp_path: Path) -> None:
    """Phase 1's honesty gate, enforced at the persistence boundary."""
    store = open_store(tmp_path)
    sealed = seal(store)
    overclaiming = Manifest(
        manifest_id="run-4:manifest",
        run_id="run-4",
        signer_identity="mayhem-local-key-1",
        event_ids=sealed.manifest.event_ids,
        event_roots=sealed.manifest.event_roots,
    ).seal()

    with pytest.raises(AttestationError, match="no trust root"):
        AttestationRepository(store).save_manifest(overclaiming)

    assert AttestationRepository(store).load_manifest("run-4:manifest") is None
    store.close()


def test_verify_run_chain_on_an_unknown_run_reports_absence(tmp_path: Path) -> None:
    store = open_store(tmp_path)

    verification = AttestationRepository(store).verify_run_chain("run-nope")

    assert not verification.valid
    assert verification.errors == ("no chain stored for run 'run-nope'",)
    store.close()


def test_verify_stored_manifest_without_events_checks_the_manifest_alone(tmp_path: Path) -> None:
    """The audit path with no chain rows: digest and signer honesty only."""
    store = open_store(tmp_path)
    seal(store)
    repository = AttestationRepository(store)

    alone = repository.verify_stored_manifest("run-1:manifest", with_events=False)
    together = repository.verify_stored_manifest("run-1:manifest")

    assert alone.valid and together.valid
    assert alone.events_checked == 0
    assert together.events_checked == 2
    assert "unsigned" in alone.warnings[0]

    with store.write() as conn:
        conn.execute(
            "UPDATE attestation_manifests SET manifest_json ="
            ' replace(manifest_json, \'"retention_class":"hot"\','
            ' \'"retention_class":"ephemeral"\')'
            " WHERE manifest_id = 'run-1:manifest'"
        )
    downgraded = repository.verify_stored_manifest("run-1:manifest", with_events=False)

    assert not downgraded.valid
    assert any("digest mismatch" in error for error in downgraded.errors)
    store.close()


def test_events_survive_a_schema_round_trip_with_digests_intact(tmp_path: Path) -> None:
    """Unicode and nested payload shapes must reload byte-identically."""
    store = open_store(tmp_path)
    reading = READING
    events = seal_events(
        [
            AttestedEvent(
                event_id="run-5:unicode",
                event_kind="evidence.recorded",
                run_id="run-5",
                sequence=0,
                payload={"note": "café", "nested": {"steps": [1, 2.5, True, None]}},
                recorded_at=reading,
            ),
            AttestedEvent(
                event_id="run-5:closure",
                event_kind="run.closed",
                run_id="run-5",
                sequence=1,
                payload={"verdict": ""},
                recorded_at=reading,
            ),
        ]
    )
    AttestationRepository(store).save_chain("run-5", events, sealed_at=reading.wall_clock)
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    repository = AttestationRepository(reopened)
    reloaded = repository.load_chain("run-5")

    assert [event.to_dict() for event in reloaded] == [event.to_dict() for event in events]
    assert repository.verify_run_chain("run-5").valid
    reopened.close()


def test_blank_run_id_cannot_become_an_attested_event(tmp_path: Path) -> None:
    """The domain refuses a blank run id before anything reaches the store."""
    store = open_store(tmp_path)

    with pytest.raises(ValidationError):
        AttestedEvent(
            event_id="x",
            event_kind="evidence.recorded",
            run_id="   ",
            sequence=0,
            recorded_at=READING,
        )

    assert AttestationRepository(store).load_chain("run-blank") == ()
    store.close()


# --------------------------------------------------------------------------- #
# Phase 4 — authorization sealed into the chain, and chain completeness          #
# --------------------------------------------------------------------------- #


def authorization(plan_digest: str = "1" * 64) -> RunAuthorization:
    """A passing policy decision plus the approval state that consumed it."""
    return RunAuthorization(
        policy_decision=PolicyDecision(
            outcome="allow",
            reasons=("production permits this fault family",),
            matched_rules=("prod.family.allow",),
            bundle_id="production",
            bundle_version=2,
            rule_digest="2" * 64,
            policy_digest="3" * 64,
            facts_digest="4" * 64,
        ),
        approval_state=ApprovalState(valid=True, approvers=("ana",), required=1),
        plan_digest=plan_digest,
        proof_digest="5" * 64,
    )


def mutating_envelope(run_id: str = "run-1") -> EvidenceEnvelope:
    """A read-only envelope plus the two facts that make the run mutating."""
    return make_envelope(
        run_id,
        plan_hash="1" * 64,
        action_outcomes=("applied",),
        execution_intent={"actor": "ana"},
    )


def test_seal_with_authorization_persists_four_events_and_one_manifest(tmp_path: Path) -> None:
    """The persisted chain carries the artifacts, and reloads them intact."""
    store = open_store(tmp_path)
    sealed = seal_run_evidence(
        store,
        mutating_envelope(),
        run_status="completed",
        verdict="pass",
        recorded_at=READING,
        created_at=READING,
        manifest_id="run-1:manifest",
        authorization=authorization(),
    )

    assert [event.event_kind for event in sealed.events] == [
        "evidence.recorded",
        "policy.decided",
        "approval.evaluated",
        "run.closed",
    ]
    assert sealed.completeness is not None
    assert sealed.completeness.complete is True
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    repository = AttestationRepository(reopened)
    reloaded = repository.load_chain("run-1")

    assert [event.to_dict() for event in reloaded] == [e.to_dict() for e in sealed.events]
    assert repository.verify_run_chain("run-1").valid
    completeness = repository.verify_run_completeness("run-1")
    assert completeness.complete is True
    assert completeness.missing == ()
    assert completeness.plan_digest == "1" * 64
    reopened.close()


def test_the_authorization_digests_are_the_chain_inputs(tmp_path: Path) -> None:
    """09/07 digests enter the chain, and the domain objects are not copied."""
    store = open_store(tmp_path)
    record = authorization()
    sealed = seal_run_evidence(
        store,
        mutating_envelope(),
        run_status="completed",
        verdict="pass",
        recorded_at=READING,
        manifest_id="run-1:manifest",
        authorization=record,
    )
    payload = sealed.events[1].payload

    assert payload["decision_digest"] == record.policy_decision.decision_digest()
    assert payload["approval_state_digest"] == record.approval_state_digest()
    assert payload["policy_digest"] == "3" * 64
    assert payload["approval_proof_digest"] == "5" * 64
    # The decision is referenced by digest, not vendored: its full rule dump is
    # not inlined, only what an operator reads.
    assert "predicate" not in payload
    assert "discarded" not in payload
    store.close()


def test_seal_refuses_an_approval_bound_to_a_different_plan(tmp_path: Path) -> None:
    """An approval for one plan does not authorize another — and says so loudly."""
    store = open_store(tmp_path)

    with pytest.raises(AuthorizationMismatchError, match="does not authorize another"):
        seal_run_evidence(
            store,
            mutating_envelope(),
            run_status="completed",
            verdict="pass",
            recorded_at=READING,
            manifest_id="run-1:manifest",
            authorization=authorization(plan_digest="9" * 64),
        )

    assert store.query("SELECT COUNT(*) AS n FROM attestation_events")[0]["n"] == 0
    assert store.query("SELECT COUNT(*) AS n FROM attestation_manifests")[0]["n"] == 0
    store.close()


def test_a_mutating_run_with_no_authorization_is_persisted_but_incomplete(
    tmp_path: Path,
) -> None:
    """The load-bearing Phase 4 assertion: sealed, and honestly incomplete.

    Not refused. A run's evidence has to survive even when the evidence about how
    it was authorized did not, and a chain that verifies while carrying no
    explanation of its own authorization is the failure this closes.
    """
    store = open_store(tmp_path)
    sealed = seal_run_evidence(
        store,
        mutating_envelope(),
        run_status="completed",
        verdict="pass",
        recorded_at=READING,
        manifest_id="run-1:manifest",
    )

    assert sealed.chain_verification.valid
    assert sealed.completeness is not None
    assert sealed.completeness.mutating is True
    assert sealed.completeness.complete is False
    assert sealed.complete is False
    assert sealed.completeness.missing == ("policy.decided", "approval.evaluated")
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    completeness = AttestationRepository(reopened).verify_run_completeness("run-1")
    assert completeness.complete is False
    assert AttestationRepository(reopened).verify_run_chain("run-1").valid
    reopened.close()


def test_a_read_only_run_is_complete_without_any_authorization(tmp_path: Path) -> None:
    """Nothing changed, so there is nothing to justify. Reported, not implied."""
    store = open_store(tmp_path)
    sealed = seal(store)

    assert sealed.completeness is not None
    assert sealed.completeness.mutating is False
    assert sealed.completeness.complete is True
    assert "read-only" in sealed.completeness.errors[0]
    store.close()


def test_completeness_does_not_make_an_unsigned_manifest_signed(tmp_path: Path) -> None:
    """The two axes are independent: complete is not the same as authenticated."""
    store = open_store(tmp_path)
    sealed = seal_run_evidence(
        store,
        mutating_envelope(),
        run_status="completed",
        verdict="pass",
        recorded_at=READING,
        manifest_id="run-1:manifest",
        authorization=authorization(),
    )

    assert sealed.completeness is not None and sealed.completeness.complete is True
    assert sealed.signed is False
    assert sealed.signature_state == SIGNATURE_UNSIGNED_NO_SIGNING
    assert any("authorship is not" in w for w in sealed.manifest_verification.warnings)
    store.close()


def test_the_seal_stays_deterministic_with_the_same_authorization(tmp_path: Path) -> None:
    """Two stores, one reading, one authorization: the same chain root."""
    first_store = open_store(tmp_path / "a")
    first = seal_run_evidence(
        first_store,
        mutating_envelope("run-dup"),
        run_status="completed",
        verdict="pass",
        recorded_at=READING,
        created_at=READING,
        manifest_id="run-dup:manifest",
        authorization=authorization(),
    )
    first_store.close()
    second_store = open_store(tmp_path / "b")
    second = seal_run_evidence(
        second_store,
        mutating_envelope("run-dup"),
        run_status="completed",
        verdict="pass",
        recorded_at=READING,
        created_at=READING,
        manifest_id="run-dup:manifest",
        authorization=authorization(),
    )
    second_store.close()

    assert first.chain_root == second.chain_root
    assert first.manifest.manifest_digest == second.manifest.manifest_digest
