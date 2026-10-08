"""Plan 12 Phase 4: the audit log as an attested event stream, and authorization.

The load-bearing assertions in this file are all negative or compositional,
because the failure modes that matter are not "the logger did not work":

* a **mutating run whose chain lacks its policy or approval artifact must verify
  as INCOMPLETE**, never as clean — an incomplete-but-honest chain is the whole
  point, and a chain that verifies silently would be worse than none;
* a **mutated or reordered audit entry must fail verification** — append-only is
  a claim, and only a tamper test makes it a fact;
* a **dual-control deletion must leave an audit entry that survives the
  deletion** — the record of a removal cannot be part of what the removal
  removes;
* an **unsigned manifest never reports itself signed**, a **policy artifact from
  a different plan digest cannot be attached**, and a **deleted record's audit
  entry cannot be removed**.

Every test that seals a run also asserts the signature state, because Phase 4
adds integrity and completeness and adds no authorship: if that ever changes, the
tests here must fail rather than quietly follow.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from mayhem.domain.approval import ApprovalState, InvalidationReason
from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    RetentionClass,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.domain.policy import PolicyDecision
from mayhem.infra.attestation_store import (
    EVENT_APPROVAL_EVALUATED,
    EVENT_EVIDENCE_RECORDED,
    EVENT_POLICY_DECIDED,
    EVENT_RUN_CLOSED,
    REQUIRED_AUTHORIZATION_KINDS,
    AttestationRepository,
    AuthorizationMismatchError,
    RunAuthorization,
    chain_completeness,
    is_mutating_run,
    seal_run_evidence,
)
from mayhem.infra.attestation_store import (
    UNSIGNED_REASON_NO_SIGNING as SHARED_UNSIGNED_REASON,
)
from mayhem.infra.audit_stream import (
    KIND_EVIDENCE_ARCHIVED,
    KIND_EVIDENCE_DELETED,
    KIND_EVIDENCE_REGISTERED,
    KIND_LEGAL_HOLD_PLACED,
    KIND_LEGAL_HOLD_RELEASED,
    NO_SECOND_FORMAT_REASON,
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AuditEntry,
    AuditError,
    AuditStream,
    AuditStreamAppendError,
    seal_run_evidence_at_run_close,
    verify_audit_chain,
)
from mayhem.infra.migrations import ALL_MIGRATIONS, M0029_AUDIT_STREAM
from mayhem.infra.retention import (
    InMemoryRetentionBackend,
    RetentionEngine,
    RetentionRefusedError,
    RetentionState,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

#: Position of this phase's migration. Slicing by index rather than by version
#: keeps the test correct whatever other agents append.
MIGRATION_INDEX = ALL_MIGRATIONS.index(M0029_AUDIT_STREAM)
BEFORE = ALL_MIGRATIONS[:MIGRATION_INDEX]
PRIOR_HEAD = M0029_AUDIT_STREAM.version - 1

T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 3, 1, 12, 0, 1, tzinfo=UTC)


def reading(seconds: int = 0) -> AttestedTimestamp:
    return AttestedTimestamp(
        wall_clock=T0.replace(second=seconds),
        monotonic_ns=1_000_000 + seconds * 1_000,
        uncertainty_ms=0.5,
        source="system",
    )


READING = reading()
PLAN_DIGEST = "1" * 64
OTHER_PLAN_DIGEST = "2" * 64
RULE_DIGEST = "3" * 64
POLICY_DIGEST = "4" * 64
FACTS_DIGEST = "5" * 64
PROOF_DIGEST = "6" * 64
OTHER_POLICY_DIGEST = "7" * 64

AUDIT_TABLES = ("audit_entries", "audit_stream_heads")


# --------------------------------------------------------------------------- #
# Fixtures                                                                      #
# --------------------------------------------------------------------------- #


def make_decision(
    *,
    outcome: str = "allow",
    policy_digest: str = POLICY_DIGEST,
) -> PolicyDecision:
    return PolicyDecision(
        outcome=outcome,  # type: ignore[arg-type]
        reasons=("production allows this fault family",),
        matched_rules=("prod.fault_family.allow",),
        bundle_id="production",
        bundle_version=3,
        rule_digest=RULE_DIGEST,
        policy_digest=policy_digest,
        facts_digest=FACTS_DIGEST,
    )


def make_state(
    *,
    valid: bool = True,
    approvers: tuple[str, ...] = ("ana",),
    reasons: tuple[InvalidationReason, ...] = (),
) -> ApprovalState:
    if valid:
        return ApprovalState(valid=True, approvers=approvers, required=1)
    return ApprovalState(
        valid=False, reasons=reasons or (InvalidationReason.NO_APPROVALS,), required=1
    )


def make_authorization(
    *,
    plan_digest: str = PLAN_DIGEST,
    decision: PolicyDecision | None = None,
    state: ApprovalState | None = None,
    proof_digest: str = PROOF_DIGEST,
) -> RunAuthorization:
    return RunAuthorization(
        policy_decision=decision if decision is not None else make_decision(),
        approval_state=state if state is not None else make_state(),
        plan_digest=plan_digest,
        proof_digest=proof_digest,
    )


def make_envelope(
    run_id: str = "run-1",
    *,
    plan_hash: str = PLAN_DIGEST,
    mutating: bool = False,
    **overrides: object,
) -> EvidenceEnvelope:
    """A written, redacted evidence envelope.

    ``mutating`` toggles the two facts :func:`is_mutating_run` reads: a mutating
    action outcome, or an execution intent. Both are drawn from the envelope's own
    fields, never asserted by the caller.
    """
    fields: dict[str, object] = {
        "run_id": run_id,
        "plan_hash": plan_hash,
        "verdict": "pass",
        "step_reports": ({"step_id": "s1", "status": "completed"},),
        "created_at": T0.isoformat(),
        "redaction_metrics": {"policy_version": "redaction-v9", "redacted_path_count": 0},
    }
    if mutating:
        fields["action_outcomes"] = ("applied",)
        fields["execution_intent"] = {"actor": "ana", "plan_hash": plan_hash}
    fields.update(overrides)
    return EvidenceEnvelope.model_validate(fields)


def open_store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


def seal(
    store: Store,
    run_id: str = "run-1",
    *,
    authorization: RunAuthorization | None = None,
    mutating: bool = False,
    plan_hash: str = PLAN_DIGEST,
    **kwargs: object,
):
    """Seal a default envelope with an injected reading, for determinism.

    ``mutating`` shapes the *envelope*, not the seal: whether a run is mutating is
    derived from what the envelope recorded, never asserted to the sealer.
    """
    params: dict[str, object] = {
        "run_status": "completed",
        "verdict": "pass",
        "recorded_at": READING,
        "created_at": READING,
        "manifest_id": f"{run_id}:manifest",
    }
    params.update(kwargs)
    return seal_run_evidence(
        store,
        make_envelope(run_id, plan_hash=plan_hash, mutating=mutating),
        authorization=authorization,
        **params,  # type: ignore[arg-type]
    )


def stream(store: Store, *, stream_id: str = "mayhem.audit") -> AuditStream:
    return AuditStream(store, stream_id=stream_id)


def entry(seconds: int = 0, **overrides: object) -> AuditEntry:
    fields: dict[str, object] = {
        "principal": "ana",
        "action": "audit.action",
        "target": "run-1:manifest",
        "subject_run_id": "run-1",
        "policy_digest": POLICY_DIGEST,
        "approval_digest": PROOF_DIGEST,
    }
    fields.update(overrides)
    return AuditEntry(**fields)  # type: ignore[arg-type]


def seeded(store: Store, count: int = 3) -> AuditStream:
    """A stream with ``count`` entries, one per second, all verifying."""
    log = stream(store)
    for index in range(count):
        log.record(
            entry(
                seconds=index,
                target=f"run-{index}:manifest",
                subject_run_id=f"run-{index}",
            ),
            recorded_at=reading(index),
        )
    return log


def drop_append_only_guards(store: Store) -> None:
    """Simulate a writer with DDL access, by dropping the M0029 triggers.

    Every tamper test needs this, and needs to *say* it needs it: without the
    triggers, ``UPDATE``/``DELETE`` are refused outright, which is the property
    :func:`test_the_append_only_triggers_refuse_update_and_delete` asserts. These
    tests are about the *second* line of defence — that a bypass is detected by
    verification — so they bypass deliberately and then check it is noticed.
    """
    with store.write() as conn:
        conn.execute("DROP TRIGGER audit_entries_no_update")
        conn.execute("DROP TRIGGER audit_entries_no_delete")


def _archived_engine(tmp_path: Path, retention_class: RetentionClass = RetentionClass.EPHEMERAL):
    """A store whose record is cold→archive in a backend, ready to delete."""
    from datetime import timedelta

    from mayhem.infra.retention import RETENTION_TTL_SECONDS

    store = open_store(tmp_path)
    sealed = seal(store, retention_class=retention_class)
    engine = RetentionEngine(store, backend=InMemoryRetentionBackend())
    engine.register(sealed.manifest, now=T0)
    # Past the ephemeral window: expiry is evaluated against an explicit `now`,
    # never a clock read, so the tests stay deterministic.
    expired = T0 + timedelta(days=RETENTION_TTL_SECONDS[retention_class] + 1)  # type: ignore[operator]
    engine.cool("run-1:manifest", now=T0)
    engine.archive("run-1:manifest", now=T0)
    return store, engine, sealed, expired


# --------------------------------------------------------------------------- #
# Migration                                                                     #
# --------------------------------------------------------------------------- #


def test_migration_is_additive_and_reversible(tmp_path: Path) -> None:
    store = Store.open_migrated(tmp_path / "mayhem.db", migrations=BEFORE)
    assert store.schema_version == PRIOR_HEAD
    before = {
        str(row["name"])
        for row in store.query("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert set(AUDIT_TABLES).isdisjoint(before)

    applied = store.migrate()

    assert "0029_audit_stream" in applied
    assert store.schema_version == ALL_MIGRATIONS[-1].version
    after = {
        str(row["name"])
        for row in store.query("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert set(AUDIT_TABLES) <= after
    triggers = {
        str(row["name"])
        for row in store.query("SELECT name FROM sqlite_master WHERE type = 'trigger'")
    }
    assert {
        "audit_entries_no_update",
        "audit_entries_no_delete",
        "audit_stream_heads_no_delete",
    } <= triggers
    assert store.query("PRAGMA foreign_key_check") == []
    store.close()

    reversed_store = open_store(tmp_path)
    reversed_ids = reversed_store.migrate_down(PRIOR_HEAD)
    assert "0029_audit_stream" in reversed_ids
    final = {
        str(row["name"])
        for row in reversed_store.query(
            "SELECT name FROM sqlite_master WHERE type IN ('table','trigger')"
        )
    }
    assert set(AUDIT_TABLES).isdisjoint(final)
    assert "audit_entries_no_delete" not in final
    assert reversed_store.schema_version == PRIOR_HEAD
    reversed_store.close()


def test_migration_has_down_statements() -> None:
    """The additive gate requires reversibility; assert it for this migration."""
    assert M0029_AUDIT_STREAM.down_statements


def test_the_migration_carries_no_signature_column(tmp_path: Path) -> None:
    """No per-row signature state: the stream is unsigned, and says so once."""
    store = open_store(tmp_path)
    columns = {str(row[1]) for row in store.query("PRAGMA table_info(audit_entries)")}
    assert "signature_state" not in columns
    assert "signer_identity" not in columns
    store.close()


# --------------------------------------------------------------------------- #
# Requirement 1 — authorization sealed into the chain                           #
# --------------------------------------------------------------------------- #


def test_authorization_adds_both_events_between_evidence_and_closure(
    tmp_path: Path,
) -> None:
    store = open_store(tmp_path)
    sealed = seal(store, authorization=make_authorization(), mutating=True)

    kinds = [event.event_kind for event in sealed.events]

    assert kinds == [
        EVENT_EVIDENCE_RECORDED,
        EVENT_POLICY_DECIDED,
        EVENT_APPROVAL_EVALUATED,
        EVENT_RUN_CLOSED,
    ]
    assert [event.sequence for event in sealed.events] == [0, 1, 2, 3]
    # The chain still verifies and the manifest still covers every event in order.
    assert sealed.chain_verification.valid
    assert sealed.manifest.event_ids == tuple(event.event_id for event in sealed.events)
    assert sealed.manifest_verification.valid
    store.close()


def test_the_chain_carries_the_artifact_digests_not_a_copy_of_the_artifacts(
    tmp_path: Path,
) -> None:
    """A later reader can reconstruct WHY from digests plus the operator's fields."""
    store = open_store(tmp_path)
    authorization = make_authorization()
    sealed = seal(store, authorization=authorization, mutating=True)
    policy_event = sealed.events[1]
    approval_event = sealed.events[2]

    payload = policy_event.payload

    assert payload["decision_digest"] == authorization.policy_decision.decision_digest()
    assert payload["policy_digest"] == POLICY_DIGEST
    assert payload["rule_digest"] == RULE_DIGEST
    assert payload["facts_digest"] == FACTS_DIGEST
    assert payload["policy_outcome"] == "allow"
    assert payload["policy_matched_rules"] == ["prod.fault_family.allow"]
    assert payload["approval_state_digest"] == authorization.approval_state_digest()
    assert payload["approval_proof_digest"] == PROOF_DIGEST
    assert payload["approval_valid"] is True
    assert payload["approval_approvers"] == ["ana"]
    # Both events carry the same authorization summary, so neither is a stub.
    assert approval_event.payload == payload
    # The full domain objects are referenced by digest, not duplicated: the
    # approval state's whole dump is not inlined, only its digest.
    assert "discarded" not in payload
    assert "step_reports" not in payload
    store.close()


def test_a_refused_approval_is_recorded_rather_than_hidden(tmp_path: Path) -> None:
    """A refusal is evidence too. Sealing must not launder a "valid: true"."""
    store = open_store(tmp_path)
    authorization = make_authorization(
        state=make_state(valid=False, reasons=(InvalidationReason.EXPIRED,)),
    )
    sealed = seal(store, authorization=authorization, mutating=True)
    payload = sealed.events[2].payload

    assert payload["approval_valid"] is False
    assert payload["approval_reasons"] == ["expired"]
    assert payload["approval_approvers"] == []
    assert payload["approval_describe"] == "refused: expired"
    store.close()


def test_omitting_authorization_keeps_the_phase_two_chain_shape(tmp_path: Path) -> None:
    """The addition is additive: no authorization means the chain Phase 2 sealed."""
    store = open_store(tmp_path)
    sealed = seal(store)

    assert [event.event_kind for event in sealed.events] == [
        EVENT_EVIDENCE_RECORDED,
        EVENT_RUN_CLOSED,
    ]
    assert sealed.chain_verification.valid
    store.close()


# --------------------------------------------------------------------------- #
# Requirement 1 (negative) — an incomplete chain never verifies as clean        #
# --------------------------------------------------------------------------- #


def test_a_mutating_run_with_no_authorization_verifies_as_incomplete(
    tmp_path: Path,
) -> None:
    store = open_store(tmp_path)
    sealed = seal(store, mutating=True)

    completeness = sealed.completeness
    assert completeness is not None
    assert completeness.mutating is True
    assert completeness.complete is False
    assert completeness.missing == REQUIRED_AUTHORIZATION_KINDS
    assert sealed.complete is False
    # Integrity still verifies: the two verdicts are independent questions, and
    # conflating them is the bug this test exists to prevent.
    assert sealed.chain_verification.valid
    assert any("policy.decided" in error for error in completeness.errors)
    assert any("approval.evaluated" in error for error in completeness.errors)
    store.close()


def test_incompleteness_survives_a_store_reload(tmp_path: Path) -> None:
    """The persisted verifier must say it too, not just the in-memory seal."""
    store = open_store(tmp_path)
    seal(store, mutating=True)
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    completeness = AttestationRepository(reopened).verify_run_completeness("run-1")

    assert completeness.mutating is True
    assert completeness.complete is False
    assert completeness.missing == REQUIRED_AUTHORIZATION_KINDS
    assert AttestationRepository(reopened).verify_run_chain("run-1").valid
    reopened.close()


def test_a_mutating_run_missing_only_one_artifact_is_still_incomplete(
    tmp_path: Path,
) -> None:
    """Half the answer is not an answer: the missing half is named, not glossed."""
    store = open_store(tmp_path)
    sealed = seal(store, mutating=True, authorization=None)
    # Hand-build the half-complete chain by re-sealing with only a policy event.
    partial = tuple(
        event for event in sealed.events if event.event_kind != EVENT_RUN_CLOSED
    ) + tuple(event for event in sealed.events if event.event_kind == EVENT_RUN_CLOSED)
    partial = tuple(
        event.model_copy(update={"event_kind": EVENT_POLICY_DECIDED})
        if event.event_kind == EVENT_EVIDENCE_RECORDED
        else event
        for event in partial
    )
    (policy_event,) = _one_sealed(
        partial[0],
        run_id="run-1",
        event_id="run-1:policy",
        sequence=1,
        previous_digest=partial[0].chain_link,
    )

    completeness = chain_completeness((*partial, policy_event))

    assert completeness.mutating is True
    assert completeness.complete is False
    assert completeness.missing == (EVENT_APPROVAL_EVALUATED,)
    assert any("approval.evaluated" in error for error in completeness.errors)
    store.close()


def _one_sealed(
    template: AttestedEvent,
    *,
    run_id: str,
    event_id: str,
    sequence: int,
    previous_digest: str,
) -> tuple[AttestedEvent, ...]:
    """One sealed event of ``template``'s shape, for the half-complete test."""
    return seal_events(
        (
            AttestedEvent(
                event_id=event_id,
                event_kind=EVENT_POLICY_DECIDED,
                run_id=run_id,
                sequence=sequence,
                payload={"plan_digest": PLAN_DIGEST, "policy_outcome": "allow"},
                recorded_at=template.recorded_at,
                previous_digest=previous_digest,
            ),
        ),
        previous_digest=previous_digest,
    )


def test_a_read_only_run_is_not_required_to_carry_authorization(
    tmp_path: Path,
) -> None:
    """A run that changed nothing has nothing to justify. Not a pass — 'N/A'."""
    store = open_store(tmp_path)
    sealed = seal(store, mutating=False)

    completeness = sealed.completeness
    assert completeness is not None
    assert completeness.mutating is False
    assert completeness.complete is True
    assert completeness.missing == ()
    assert sealed.complete is True
    assert "read-only" in completeness.errors[0]
    store.close()


def test_mutating_is_derived_from_the_envelope_not_asserted() -> None:
    """A caller cannot declare its own run read-only to dodge the rule."""
    assert is_mutating_run(make_envelope(mutating=True)) is True
    assert is_mutating_run(make_envelope(mutating=False)) is False
    # An execution intent alone is enough: v0.9.0 makes execution an approved act.
    assert is_mutating_run(make_envelope(execution_intent={"actor": "ana"})) is True
    # So is a mutating outcome on its own, with no intent recorded.
    assert is_mutating_run(make_envelope(action_outcomes=("applied",))) is True
    # A read-only outcome is not.
    assert is_mutating_run(make_envelope(action_outcomes=("verified",))) is False


def test_a_chain_with_no_recorded_mutating_fact_is_treated_as_mutating() -> None:
    """Fail closed: absent evidence that nothing changed is not evidence of it."""
    (event,) = seal_events(
        (
            AttestedEvent(
                event_id="legacy:evidence",
                event_kind=EVENT_EVIDENCE_RECORDED,
                run_id="legacy",
                sequence=0,
                payload={"evidence_digest": "a" * 64},  # no "mutating" key
                recorded_at=READING,
            ),
        )
    )

    completeness = chain_completeness((event,))

    assert completeness.mutating is True
    assert completeness.complete is False


def test_no_stored_chain_reports_incomplete_not_read_only(tmp_path: Path) -> None:
    """An absent chain has not been shown to be a read-only run."""
    store = open_store(tmp_path)
    completeness = AttestationRepository(store).verify_run_completeness("run-nope")

    assert completeness.complete is False
    assert completeness.mutating is True
    assert completeness.missing == REQUIRED_AUTHORIZATION_KINDS
    assert "no chain stored" in completeness.errors[0]
    store.close()


# --------------------------------------------------------------------------- #
# Requirement 1 (negative) — a policy artifact from another plan              #
# --------------------------------------------------------------------------- #


def test_a_policy_artifact_from_a_different_plan_cannot_be_attached(
    tmp_path: Path,
) -> None:
    """The negative control for "an approval is a statement about an exact plan"."""
    store = open_store(tmp_path)

    with pytest.raises(AuthorizationMismatchError, match="does not authorize another"):
        seal(store, authorization=make_authorization(plan_digest=OTHER_PLAN_DIGEST))

    assert store.query("SELECT COUNT(*) AS n FROM attestation_events")[0]["n"] == 0
    assert store.query("SELECT COUNT(*) AS n FROM attestation_manifests")[0]["n"] == 0
    store.close()


def test_a_different_policy_digest_is_recorded_not_refused(tmp_path: Path) -> None:
    """A different *policy* is legitimate; a different *plan* is not.

    Confined to the plan pin on purpose: refusing a policy change here would
    re-decide admission, which is the gate's job and not this store's.
    """
    store = open_store(tmp_path)
    authorization = make_authorization(decision=make_decision(policy_digest=OTHER_POLICY_DIGEST))
    sealed = seal(store, authorization=authorization, mutating=True)

    assert sealed.events[1].payload["policy_digest"] == OTHER_POLICY_DIGEST
    assert sealed.completeness is not None
    assert sealed.completeness.complete is True
    store.close()


def test_an_authorization_with_a_malformed_digest_is_refused() -> None:
    """A chain input that cannot name a digest did not name an artifact."""
    with pytest.raises(AuthorizationMismatchError, match="plan_digest"):
        RunAuthorization(
            policy_decision=make_decision(),
            approval_state=make_state(),
            plan_digest="not-a-digest",
        )
    with pytest.raises(AuthorizationMismatchError, match="proof_digest"):
        RunAuthorization(
            policy_decision=make_decision(),
            approval_state=make_state(),
            plan_digest=PLAN_DIGEST,
            proof_digest="NOTHEX" + "0" * 59,
        )


def test_an_empty_plan_digest_skips_the_pin_rather_than_matching_it(tmp_path: Path) -> None:
    """Documented escape hatch, and it is *skipping* the check, not passing it."""
    store = open_store(tmp_path)
    authorization = make_authorization(plan_digest="")
    sealed = seal(store, authorization=authorization, mutating=True, plan_hash="")

    assert sealed.events[1].payload["plan_digest"] == ""
    assert sealed.completeness is not None
    assert sealed.completeness.complete is True
    store.close()


# --------------------------------------------------------------------------- #
# Requirement 2 — the audit log is an attested stream, not a second format     #
# --------------------------------------------------------------------------- #


def test_audit_entries_are_attested_events_verified_by_the_domain_verifier(
    tmp_path: Path,
) -> None:
    store = open_store(tmp_path)
    log = seeded(store, 3)
    loaded = log.load()

    assert all(isinstance(event, AttestedEvent) for event in loaded)
    # The domain verifier, the domain chain law: one format, not two.
    assert verify_chain(loaded).valid
    assert verify_audit_chain(loaded).valid
    assert [event.sequence for event in loaded] == [0, 1, 2]
    assert loaded[0].previous_digest == GENESIS_DIGEST
    assert all(event.digest_matches() and event.chain_link_matches() for event in loaded)
    assert loaded[1].previous_digest == loaded[0].chain_link
    assert log.verify().valid
    store.close()


def test_the_stream_uses_the_stream_id_as_run_id_and_names_the_run_in_the_payload(
    tmp_path: Path,
) -> None:
    """Why the stream is cross-run and how it stays legal under Phase 1's law."""
    store = open_store(tmp_path)
    log = seeded(store, 2)

    # Phase 1 requires one run_id per chain, so the chain's run_id is the stream.
    assert {event.run_id for event in log.load()} == {"mayhem.audit"}
    # The run actually acted on is named in the sealed bytes, not lost.
    assert [event.payload["subject_run_id"] for event in log.load()] == ["run-0", "run-1"]
    store.close()


def test_the_stream_records_principal_action_target_and_decision_digests(
    tmp_path: Path,
) -> None:
    store = open_store(tmp_path)
    log = stream(store)
    event = log.record(entry(), recorded_at=READING)
    payload = event.payload

    assert payload["principal"] == "ana"
    assert payload["action"] == "audit.action"
    assert payload["target"] == "run-1:manifest"
    assert payload["policy_digest"] == POLICY_DIGEST
    assert payload["approval_digest"] == PROOF_DIGEST
    # And the denormalised columns an auditor's SQL needs, from the sealed payload.
    row = dict(store.query("SELECT * FROM audit_entries WHERE event_id = ?", (event.event_id,))[0])
    assert row["principal"] == "ana"
    assert row["action"] == "audit.action"
    assert row["target"] == "run-1:manifest"
    assert row["subject_run_id"] == "run-1"
    assert row["digest"] == event.digest
    assert row["chain_link"] == event.chain_link
    store.close()


@pytest.mark.parametrize("field", ["principal", "action", "target"])
def test_an_entry_without_an_actor_is_refused_at_construction(field: str) -> None:
    fields: dict[str, object] = {
        "principal": "ana",
        "action": "audit.action",
        "target": "run-1:manifest",
    }
    fields[field] = "   "
    with pytest.raises(AuditError, match=field):
        AuditEntry(**fields)  # type: ignore[arg-type]


def test_the_module_states_why_there_is_no_second_format() -> None:
    """The anti-duplication claim is asserted, not just written in a docstring."""
    assert "AttestedEvent" in NO_SECOND_FORMAT_REASON
    assert "verify_chain" in NO_SECOND_FORMAT_REASON


def test_streams_are_isolated_from_one_another(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    first = seeded(store, 2)
    second = stream(store, stream_id="mayhem.audit.other")
    second.record(entry(target="run-9:manifest"), recorded_at=READING)

    assert len(first.load()) == 2
    assert len(second.load()) == 1
    assert first.verify().valid
    assert second.verify().valid
    # And they do not chain to each other.
    first_head, second_head = first.head(), second.head()
    assert first_head is not None and second_head is not None
    assert first_head.chain_root != second_head.chain_root
    store.close()


def test_entries_for_run_answers_the_question_operators_ask_most(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    log = seeded(store, 3)

    assert len(log.entries_for_run("run-1")) == 1
    assert len(log.entries_for_run("run-nope")) == 0
    assert [e.payload["target"] for e in log.entries_for_run("run-1")] == ["run-1:manifest"]
    store.close()


def test_a_repeated_action_is_not_deduplicated(tmp_path: Path) -> None:
    """An audit log that collapsed two identical events would miscount them."""
    store = open_store(tmp_path)
    log = stream(store)
    for index in range(3):
        log.record(entry(), recorded_at=reading(index))

    loaded = log.load()

    assert len(loaded) == 3
    assert len({event.event_id for event in loaded}) == 3
    assert log.verify().valid
    store.close()


# --------------------------------------------------------------------------- #
# Requirement 2 (negative) — append-only enforcement                           #
# --------------------------------------------------------------------------- #


def test_a_mutated_audit_entry_fails_verification(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    log = seeded(store, 3)
    target = log.load()[1]
    forged = target.model_copy(update={"payload": {**target.payload, "principal": "mallory"}})
    drop_append_only_guards(store)
    with store.write() as conn:
        conn.execute(
            "UPDATE audit_entries SET event_json = ? WHERE stream_id = ? AND sequence = 1",
            (forged.model_dump_json(), "mayhem.audit"),
        )
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    verification = stream(reopened).verify()

    assert not verification.valid
    assert any("content digest mismatch" in error for error in verification.errors)
    assert any(target.event_id in error for error in verification.errors)
    reopened.close()


def test_a_reordered_audit_entry_fails_verification(tmp_path: Path) -> None:
    """Re-numbering a row's sequence breaks both the chain order and the head.

    Deliberately the hard case: every event keeps its own digest and chain link,
    so nothing about the *content* moved — only the order, and the count is
    unchanged, so the "entries were removed" check cannot fire. The chain link
    and the recorded head are what catch it.
    """
    store = open_store(tmp_path)
    log = seeded(store, 3)
    assert log.verify().valid
    drop_append_only_guards(store)
    with store.write() as conn:
        conn.execute(
            "UPDATE audit_entries SET sequence = 99 WHERE stream_id = ? AND sequence = 1",
            ("mayhem.audit",),
        )
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    verification = stream(reopened).verify()

    assert not verification.valid
    assert any("does not link to predecessor" in error for error in verification.errors)
    assert any("does not follow" in error for error in verification.errors)
    assert any("chain to" in error for error in verification.errors)
    # The count is untouched, so nothing here is a deletion — it is a reorder.
    assert not any("entries were removed" in error for error in verification.errors)
    reopened.close()


def test_a_reordered_audit_entry_fails_the_domain_verifier_too(tmp_path: Path) -> None:
    """The same reorder seen through the events alone, with no head row at all.

    Proves the head check is not the *only* thing standing between a reorder and
    a pass: the domain verifier rejects an out-of-order sequence on its own, so an
    auditor holding just the bytes still gets the right answer.
    """
    store = open_store(tmp_path)
    log = seeded(store, 3)
    first, second, third = log.load()
    # Renumber the last entry to sit between the first and second, keeping its
    # own digest and link — only the ordering is wrong.
    moved = third.model_copy(update={"sequence": 1})
    verification = verify_chain((first, moved, second))

    assert not verification.valid
    assert any("does not link to predecessor" in error for error in verification.errors)
    assert any("does not follow" in error for error in verification.errors)
    store.close()


def test_a_swapped_payload_order_fails_the_domain_verifier(tmp_path: Path) -> None:
    """The reordering the domain verifier itself catches, on the events, no store."""
    template = entry()
    (first,) = seal_events(
        (
            AttestedEvent(
                event_id="s:0",
                event_kind="audit.action",
                run_id="s",
                sequence=0,
                payload=template.payload(),
                recorded_at=READING,
            ),
        )
    )
    second = AttestedEvent(
        event_id="s:1",
        event_kind="audit.action",
        run_id="s",
        sequence=1,
        payload={"principal": "mallory", "action": "audit.action", "target": "t"},
        recorded_at=reading(1),
        previous_digest=first.chain_link,
    ).seal()

    assert verify_chain((first, second)).valid
    swapped = verify_chain((second, first))

    assert not swapped.valid
    assert any("does not link to predecessor" in error for error in swapped.errors)
    assert any("sequence 0 does not follow" in error for error in swapped.errors)


def test_the_append_only_triggers_refuse_update_and_delete(tmp_path: Path) -> None:
    """Enforced by the database, not by the absence of a code path."""
    import sqlite3

    store = open_store(tmp_path)
    log = seeded(store, 2)

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with store.write() as conn:
            conn.execute("UPDATE audit_entries SET principal = 'mallory'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with store.write() as conn:
            conn.execute("DELETE FROM audit_entries")

    assert log.verify().valid
    assert [e.payload["principal"] for e in log.load()] == ["ana", "ana"]
    store.close()


def test_the_stream_class_exposes_no_update_or_delete_method(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    for forbidden in ("update", "delete", "remove", "purge", "truncate"):
        assert not hasattr(AuditStream, forbidden), (
            f"AuditStream.{forbidden} would be a way to rewrite the record; "
            "a caller wanting a different answer must write a new entry"
        )
    store.close()


def test_appending_onto_a_broken_stream_is_refused(tmp_path: Path) -> None:
    """Extending a chain nobody can verify would launder the break."""
    store = open_store(tmp_path)
    log = seeded(store, 2)
    drop_append_only_guards(store)
    with store.write() as conn:
        conn.execute(
            "UPDATE audit_entries SET event_json = ? WHERE stream_id = ? AND sequence = 0",
            (
                AttestedEvent(
                    event_id="mayhem.audit:00000000:audit.action",
                    event_kind="audit.action",
                    run_id="mayhem.audit",
                    sequence=0,
                    payload={"principal": "mallory", "action": "audit.action", "target": "t"},
                    recorded_at=READING,
                ).model_dump_json(),
                "mayhem.audit",
            ),
        )

    with pytest.raises(AuditStreamAppendError, match="does not verify"):
        log.record(entry(seconds=9), recorded_at=reading(9))

    assert log.entry_count() == 2
    assert not log.verify().valid
    store.close()


def test_appending_onto_a_truncated_stream_is_refused(tmp_path: Path) -> None:
    """A head that disagrees with the rows is not silently trusted."""
    store = open_store(tmp_path)
    log = seeded(store, 3)
    with store.write() as conn:
        conn.execute(
            "UPDATE audit_stream_heads SET entry_count = 9 WHERE stream_id = ?",
            ("mayhem.audit",),
        )

    with pytest.raises(AuditStreamAppendError, match="entries but"):
        log.record(entry(seconds=9), recorded_at=reading(9))

    assert log.entry_count() == 3
    store.close()


def test_a_replayed_append_is_refused_by_the_unique_index(tmp_path: Path) -> None:
    """The plain INSERT (not OR REPLACE) is what makes a replay fail loudly."""
    store = open_store(tmp_path)
    log = seeded(store, 1)
    (event,) = log.load()
    with store.write() as conn:
        with pytest.raises(Exception, match="UNIQUE constraint failed"):
            conn.execute(
                "INSERT INTO audit_entries"
                " (stream_id, sequence, event_id, event_kind, principal, action, target,"
                "  subject_run_id, policy_digest, approval_digest, decision_digest,"
                "  previous_digest, digest, chain_link, recorded_at, event_json)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "mayhem.audit",
                    event.sequence,
                    event.event_id,
                    event.event_kind,
                    "ana",
                    "audit.action",
                    "t",
                    "",
                    "",
                    "",
                    "",
                    event.previous_digest,
                    event.digest,
                    event.chain_link,
                    READING.wall_clock.isoformat(),
                    event.model_dump_json(),
                ),
            )
    store.close()


# --------------------------------------------------------------------------- #
# Requirement 4 — dual-control deletion leaves a surviving audit entry          #
# --------------------------------------------------------------------------- #


def test_a_dual_control_deletion_leaves_an_audit_entry_that_survives_it(
    tmp_path: Path,
) -> None:
    """The record of a removal must not be part of what the removal removes."""
    store, engine, sealed, expired = _archived_engine(tmp_path)
    manifest_id = "run-1:manifest"

    tombstone = engine.expire(
        manifest_id, requester="ana", approver="bo", reason="gdpr erasure", now=expired
    )

    assert tombstone.dual_control_satisfied is True
    # The retention side really did delete.
    assert engine.get(manifest_id).state is RetentionState.DELETED
    # And the audit entry recording it is still there, still verifying.
    log = engine.audit
    entries = log.entries_for_run("run-1")
    deleted = [e for e in entries if e.event_kind == KIND_EVIDENCE_DELETED]
    assert len(deleted) == 1
    payload = deleted[0].payload
    assert payload["principal"] == "ana"
    assert payload["target"] == manifest_id
    # Both halves of the dual control, because naming only the requester would
    # under-record the deletion.
    assert payload["detail"]["approver"] == "bo"
    assert payload["detail"]["manifest_digest"] == sealed.manifest.manifest_digest
    assert payload["detail"]["tombstone_id"] == tombstone.tombstone_id
    assert log.verify().valid
    store.close()


def test_the_deletion_audit_entry_cannot_be_removed(tmp_path: Path) -> None:
    """Requirement 5's negative control, against a real deletion."""
    import sqlite3

    store, engine, _sealed, expired = _archived_engine(tmp_path)
    engine.expire("run-1:manifest", requester="ana", approver="bo", now=expired)
    log = engine.audit
    before = log.load()

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with store.write() as conn:
            conn.execute("DELETE FROM audit_entries WHERE action = ?", (KIND_EVIDENCE_DELETED,))

    assert log.load() == before
    assert log.verify().valid
    store.close()


def test_removing_an_audit_row_behind_the_api_is_detected(tmp_path: Path) -> None:
    """If the trigger is ever bypassed, verification still catches the gap."""
    store, engine, _sealed, expired = _archived_engine(tmp_path)
    engine.expire("run-1:manifest", requester="ana", approver="bo", now=expired)
    log = engine.audit
    assert log.verify().valid

    # Bypass the trigger, then remove the tail. A chain whose tail is gone is
    # still internally consistent, so this is the case only the recorded head
    # can catch.
    drop_append_only_guards(store)
    with store.write() as conn:
        conn.execute("DELETE FROM audit_entries WHERE sequence = 1")

    verification = log.verify()

    assert not verification.valid
    assert any("entries were removed" in error for error in verification.errors)
    store.close()


def test_every_retention_state_change_is_audited(tmp_path: Path) -> None:
    """The ladder, the hold, and the release all leave a named record."""
    store = open_store(tmp_path)
    sealed = seal(store)
    engine = RetentionEngine(store, backend=InMemoryRetentionBackend())
    engine.register(sealed.manifest, now=T0)
    engine.place_legal_hold("run-1:manifest", reason="pending litigation", now=T0)
    engine.release_legal_hold("run-1:manifest", actor="ana", reason="litigation closed", now=T0)
    engine.cool("run-1:manifest", now=T0)
    engine.archive("run-1:manifest", now=T0)
    log = engine.audit

    actions = [e.event_kind for e in log.load()]

    assert actions == [
        KIND_EVIDENCE_REGISTERED,
        KIND_LEGAL_HOLD_PLACED,
        KIND_LEGAL_HOLD_RELEASED,
        KIND_EVIDENCE_ARCHIVED,
    ]
    assert log.verify().valid
    assert [e.sequence for e in log.load()] == [0, 1, 2, 3]
    store.close()


def test_a_refused_deletion_leaves_no_deletion_audit_entry(tmp_path: Path) -> None:
    """A refusal is not an action. The stream records what happened, not intent."""
    store, engine, _sealed, _expired = _archived_engine(tmp_path)
    before = len(engine.audit.load())

    with pytest.raises(RetentionRefusedError):
        # Not archived-to-deleted in policy terms: the record is at ARCHIVE but
        # has not expired, so the ladder refuses.
        engine.expire("run-1:manifest", requester="ana", approver="bo", now=T0)

    assert len(engine.audit.load()) == before
    assert not any(e.event_kind == KIND_EVIDENCE_DELETED for e in engine.audit.load())
    store.close()


def test_dual_control_is_still_enforced_with_the_audit_stream_attached(
    tmp_path: Path,
) -> None:
    """Phase 4 must not have loosened Phase 2's two-person rule."""
    store, engine, _sealed, expired = _archived_engine(tmp_path)

    with pytest.raises(RetentionRefusedError, match="self-approval is refused"):
        engine.expire("run-1:manifest", requester="ana", approver="ana", now=expired)

    assert not any(e.event_kind == KIND_EVIDENCE_DELETED for e in engine.audit.load())
    assert engine.get("run-1:manifest").state is RetentionState.ARCHIVE
    store.close()


def test_a_run_seal_is_recorded_in_the_audit_stream(tmp_path: Path) -> None:
    """The stream is not only for deletions: the seal is a privileged action too."""
    store = open_store(tmp_path)
    log = stream(store)
    sealed = seal(store, authorization=make_authorization(), mutating=True)

    log.record_run_sealed(
        principal="ana",
        run_id="run-1",
        manifest_id=sealed.manifest.manifest_id,
        policy_digest=POLICY_DIGEST,
        approval_digest=PROOF_DIGEST,
        recorded_at=READING,
    )

    entry_event = log.load()[0]
    assert entry_event.event_kind == "audit.run.sealed"
    assert entry_event.payload["target"] == "run-1:manifest"
    assert entry_event.payload["policy_digest"] == POLICY_DIGEST
    assert log.verify().valid
    store.close()


# --------------------------------------------------------------------------- #
# Negative controls on the honesty claims                                       #
# --------------------------------------------------------------------------- #


def test_an_unsigned_manifest_never_reports_itself_signed(tmp_path: Path) -> None:
    """Phase 4 adds integrity and completeness. It adds no authorship."""
    store = open_store(tmp_path)
    sealed = seal(store, authorization=make_authorization(), mutating=True)

    assert sealed.signed is False
    assert not sealed.manifest.signed
    assert sealed.manifest.signer_identity == ""
    assert sealed.manifest.trust_root_ref == ""
    assert sealed.signature_state == SIGNATURE_UNSIGNED_NO_SIGNING
    assert "no signature bytes" in sealed.signature_reason

    verification = verify_manifest(sealed.manifest, sealed.events)
    assert verification.signed is False
    assert any("authorship is not" in warning for warning in verification.warnings)
    # And the stored row says the same thing, with the reason.
    state, reason = AttestationRepository(store).load_signature_state("run-1:manifest")
    assert state == SIGNATURE_UNSIGNED_NO_SIGNING
    assert reason == sealed.signature_reason
    store.close()


def test_the_audit_stream_never_claims_to_be_signed(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    log = seeded(store, 2)

    assert log.signed is False
    assert log.signature_state == SIGNATURE_UNSIGNED_NO_SIGNING
    # The reason is the *same sentence* plan 12 already uses, imported not
    # restated, and it says the one thing a caller must not soften.
    assert UNSIGNED_REASON_NO_SIGNING is SHARED_UNSIGNED_REASON
    assert "attests integrity, not authorship" in UNSIGNED_REASON_NO_SIGNING
    assert "no signature bytes were minted" in UNSIGNED_REASON_NO_SIGNING
    store.close()


def test_a_complete_chain_does_not_become_a_signed_one(tmp_path: Path) -> None:
    """Completeness and authenticity are different axes; one does not imply the other."""
    store = open_store(tmp_path)
    sealed = seal(store, authorization=make_authorization(), mutating=True)

    assert sealed.completeness is not None
    assert sealed.completeness.complete is True
    assert sealed.signed is False
    assert verify_manifest(sealed.manifest, sealed.events).signed is False
    store.close()


def test_the_attestation_chain_rejects_a_non_attestable_payload() -> None:
    """Phase 1's discipline still holds: no lossy coercion into a digest."""
    with pytest.raises(ValidationError, match="not attestable JSON"):
        AttestedEvent(
            event_id="x",
            event_kind="audit.action",
            run_id="s",
            sequence=0,
            payload={"value": object()},  # type: ignore[dict-item]
            recorded_at=READING,
        )


# --------------------------------------------------------------------------- #
# The run-close seam                                                            #
# --------------------------------------------------------------------------- #


def test_the_run_close_seam_seals_and_audits_in_one_call(tmp_path: Path) -> None:
    """The single call a later lane makes. Unwired, but exercised here."""
    store = open_store(tmp_path)
    log = stream(store)

    sealed = seal_run_evidence_at_run_close(
        store,
        make_envelope(mutating=True),
        run_status="completed",
        verdict="pass",
        authorization=make_authorization(),
        audit=log,
        principal="ana",
        recorded_at=READING,
    )

    assert sealed.chain_verification.valid
    assert sealed.completeness is not None
    assert sealed.completeness.complete is True
    (entry_event,) = log.load()
    assert entry_event.event_kind == "audit.run.sealed"
    assert entry_event.payload["principal"] == "ana"
    assert entry_event.payload["policy_digest"] == POLICY_DIGEST
    detail = entry_event.payload["detail"]
    assert detail["chain_root"] == sealed.chain_root
    assert detail["manifest_digest"] == sealed.manifest.manifest_digest
    assert detail["complete"] is True
    assert detail["mutating"] is True
    # And the seal is still honestly unsigned in the audit record too.
    assert detail["signature_state"] == SIGNATURE_UNSIGNED_NO_SIGNING
    store.close()


def test_the_seam_audits_an_incomplete_chain_as_incomplete(tmp_path: Path) -> None:
    """The gap is recorded, not smoothed over: this is the whole point."""
    store = open_store(tmp_path)
    log = stream(store)

    sealed = seal_run_evidence_at_run_close(
        store,
        make_envelope(mutating=True),
        run_status="completed",
        verdict="pass",
        audit=log,
        recorded_at=READING,
    )

    detail = log.load()[0].payload["detail"]
    assert detail["complete"] is False
    assert detail["mutating"] is True
    # No policy or approval digest, because there was no authorization to name.
    assert log.load()[0].payload["policy_digest"] == ""
    assert sealed.completeness is not None
    assert sealed.completeness.complete is False
    store.close()


def test_the_seam_refuses_a_mismatched_plan_before_writing_anything(
    tmp_path: Path,
) -> None:
    store = open_store(tmp_path)
    log = stream(store)

    with pytest.raises(AuthorizationMismatchError):
        seal_run_evidence_at_run_close(
            store,
            make_envelope(plan_hash=PLAN_DIGEST, mutating=True),
            run_status="completed",
            verdict="pass",
            authorization=make_authorization(plan_digest=OTHER_PLAN_DIGEST),
            audit=log,
            recorded_at=READING,
        )

    assert log.load() == ()
    assert log.head() is None
    assert store.query("SELECT COUNT(*) AS n FROM attestation_events")[0]["n"] == 0
    store.close()
