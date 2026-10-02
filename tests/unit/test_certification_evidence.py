"""Plan 01 Phase 4: a certification's evidence is sealed, verifiable, and retained.

Phases 1-3 made a live claim *falsifiable by construction*: a ``certified`` record
cannot be built without complete content digests, and the runner refuses a bundle
whose digests are not the ones the run's own facts produce. Every one of those
checks is arithmetic over bytes the process was handed, though. Nothing asked
whether those bytes are still there, and the demotion event was a ``demotion``
digest in a bundle — a claim about the demotion, recorded beside a hash.

So this file is written as three groups, in increasing order of how badly the
system would lie if the property did not hold:

* **the round trip.** Sealing a certification's facts produces an attestation
  chain and a manifest that the *domain* verifier re-verifies from stored bytes,
  with the residue scan, the recovery probe, and the content digests inside it
  rather than beside it. Sealing goes through plan 12's store; there is no second
  sealer here and the test asserts the rows landed in plan 12's tables.
* **the retention interaction.** A certification's evidence has to outlive the
  run that produced it, and losing it must never be silent. Both remedies are
  implemented on purpose — a refusal by default, and an explicit demote-first
  path — and each is tested separately, including the negative control that a
  *lapsed* claim does not hold evidence hostage (otherwise the ladder could never
  reclaim anything for a fault that was ever certified).
* **the negative controls.** A bundle that was never sealed, a residue scan that
  was never performed, a recovery that never came home, a chain edited behind the
  model's back, and a chain sealed over a different bundle or different digests
  each fail to grant live verification, and the promotion gate follows the
  failure down rather than reporting the level anyway.

The last group pins the two things that are easy to overstate. Omitting the
sealer still certifies — Phase 2's weaker claim is preserved deliberately, for
the unit suite and for the pre-Phase-4 surfaces — but no chain exists in that
case, so :func:`sealed_certification_gate` withdraws the claim. A weaker pipeline
therefore cannot quietly become a stronger claim, and the README's live-verified
count stays ``0 of N`` (N the live catalogue size) for a second, independent
reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.controller.certification_evidence import (
    CHAIN_EVENT_DEMOTED,
    CHAIN_EVENT_RECORDED,
    CHAIN_EVENT_SEALED,
    CertificationEvidenceHeldError,
    CertificationEvidenceStore,
    CertificationFacts,
    CertificationSeal,
    bundle_hash_for_manifest,
    certification_chain_id,
    certification_events,
    certification_manifest_id,
    expire_certification_evidence,
    reconcile_certification_evidence,
    seal_certification_evidence,
    sealed_certification_gate,
    verify_bundle_evidence,
    verify_record_evidence,
)
from mayhem.controller.executor import RunResult, StepReport
from mayhem.domain.attestation import AttestedTimestamp, RetentionClass
from mayhem.domain.catalog import definition_for
from mayhem.domain.certification import (
    DEFAULT_CERTIFICATION_TTL,
    Arch,
    CellPrivilege,
    CertificationRecord,
    CertificationState,
    EvidenceBundleRef,
    MatrixCell,
    certified_engines,
    certify,
)
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
    Wait,
)
from mayhem.domain.faults import EngineLane
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.run_outcome import RunVerdict
from mayhem.domain.target import ResourceKind, TargetScope
from mayhem.domain.topology import NodeKind, TargetSelector
from mayhem.infra.attestation_store import AttestationRepository
from mayhem.infra.certification_repository import CertificationRepository
from mayhem.infra.certification_runner import (
    CellRequest,
    CertificationRequest,
    CertifiedRun,
    DemotionEvent,
    EvidenceSealReceipt,
    RecoveryEvidence,
    RecurrenceVerdict,
    RefusalClass,
    ResidueFinding,
    ResidueScan,
    certify_fault,
    evidence_digest,
    expected_evidence_digests,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.promotion import (
    CERTIFICATION_RECORDED,
    REQUIRED_LIVE_ENGINES,
    build_probe,
    evaluate_maturity,
)
from mayhem.infra.retention import (
    RETENTION_TTL_SECONDS,
    InMemoryRetentionBackend,
    RetentionEngine,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

FAULT_ID = "proc.pause"
STEP_ID = "s1"
RUN_ID = "r-certify-phase4"
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
READING = AttestedTimestamp(wall_clock=NOW, monotonic_ns=1_000_000, source="system")

#: One second past the ephemeral window, so a registered certification manifest is
#: expired *and* the claim resting on it is still inside its own 30-day TTL. Those
#: two facts have to hold at once: the first so retention would otherwise allow the
#: deletion, the second so the certification is genuinely still live to guard.
LATER = NOW + timedelta(seconds=RETENTION_TTL_SECONDS[RetentionClass.EPHEMERAL] + 1)  # type: ignore[operator]

#: Past the certification's own 30-day validity, so the claim has lapsed on its own
#: terms. Distinct from :data:`LATER` on purpose: the two facts "the evidence may be
#: deleted" and "the claim still stands" only coexist inside that window.
LAPSED = NOW + DEFAULT_CERTIFICATION_TTL + timedelta(seconds=1)

_GOOD_RECOVERY = RecoveryEvidence(
    probe="lease.released", baseline=0.0, observed=0.0, tolerance=0.0, undo_ran=True
)
_DRIFTED_RECOVERY = RecoveryEvidence(
    probe="lease.released", baseline=0.0, observed=5.0, tolerance=0.0, undo_ran=True
)


# ── builders ────────────────────────────────────────────────────────────────


def _cell(engine: EngineLane = EngineLane.DOCKER) -> MatrixCell:
    return MatrixCell(
        engine=engine,
        engine_version="27.1.1",
        os_distro="Alpine 3.20",
        kernel_version="6.6.13-0-lts",
        arch=Arch.AMD64,
        privilege=CellPrivilege.ROOT,
    )


def _digests(
    *,
    residue: ResidueScan | None = None,
    recovery: RecoveryEvidence | None = _GOOD_RECOVERY,
    demotions: tuple[DemotionEvent, ...] = (),
    compensated: bool = True,
) -> dict[str, str]:
    """The digests an honest run of this drill earns, from the same function."""
    return expected_evidence_digests(
        params={},
        target="docker/testcase-api",
        observed_effect=(
            f"{definition_for(FAULT_ID).observable_effect}"
            "|observed=proc.pause injected on testcase-api: undo: SIGCONT"
        ),
        recovery=recovery,
        residue=residue if residue is not None else ResidueScan(performed=True),
        demotions=demotions,
        compensated=compensated,
    )


def _bundle(
    *,
    residue: ResidueScan | None = None,
    recovery: RecoveryEvidence | None = _GOOD_RECOVERY,
    demotions: tuple[DemotionEvent, ...] = (),
    compensated: bool = True,
) -> EvidenceBundleRef:
    digests = _digests(
        residue=residue, recovery=recovery, demotions=demotions, compensated=compensated
    )
    return EvidenceBundleRef(
        bundle_hash=evidence_digest("bundle", digests),
        mayhem_version="1.1.0",
        digests=digests,
    )


def _facts(
    bundle: EvidenceBundleRef,
    *,
    residue: ResidueScan | None = None,
    recovery: RecoveryEvidence | None = _GOOD_RECOVERY,
    demotions: tuple[DemotionEvent, ...] = (),
    compensated: bool = True,
) -> CertificationFacts:
    """The attempt's facts, as the sealer assembles them from the run."""
    return CertificationFacts(
        bundle=bundle,
        fault_id=FAULT_ID,
        cell_label=_cell().label,
        cell_fingerprint=_cell().fingerprint,
        injector_version="1.0.0",
        run_id=RUN_ID,
        residue=residue if residue is not None else ResidueScan(performed=True),
        recovery=recovery,
        recovery_required=True,
        compensated=compensated,
        outcome="certified on a real cell",
        demotions=demotions,
    )


def _irreversible_facts(bundle: EvidenceBundleRef, *, compensated: bool) -> CertificationFacts:
    """The same facts, for a catalog entry that declares itself irreversible."""
    return CertificationFacts(
        bundle=bundle,
        fault_id=FAULT_ID,
        cell_label=_cell().label,
        cell_fingerprint=_cell().fingerprint,
        injector_version="1.0.0",
        run_id=RUN_ID,
        residue=ResidueScan(performed=True),
        recovery=None,
        recovery_required=False,
        compensated=compensated,
        outcome="certified on a real cell",
    )


def _pending(cell: MatrixCell | None = None) -> CertificationRecord:
    return CertificationRecord(
        fault_id=FAULT_ID,
        cell=cell or _cell(),
        injector_version="1.0.0",
        expires_at=NOW + DEFAULT_CERTIFICATION_TTL,
    )


def _demotion(sequence: int = 1) -> DemotionEvent:
    return DemotionEvent(
        fault_id=FAULT_ID,
        cell_label=_cell().label,
        previous_sequence=sequence,
        previous_state=CertificationState.CERTIFIED.value,
        new_state=CertificationState.FAILED.value,
        at=NOW,
        reason="a re-run did not reproduce the certified recovery",
    )


def _store(path: Path) -> Store:
    return Store.open_migrated(path / "mayhem.db", migrations=ALL_MIGRATIONS)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    """A migrated store holding both the certification and attestation tables."""
    opened = _store(tmp_path)
    yield opened
    opened.close()


def _certify(
    store: Store,
    repository: CertificationRepository,
    *,
    cell: MatrixCell | None = None,
    bundle: EvidenceBundleRef | None = None,
    residue: ResidueScan | None = None,
    recovery: RecoveryEvidence | None = _GOOD_RECOVERY,
    demotions: tuple[DemotionEvent, ...] = (),
    seal: bool = True,
    retention: RetentionEngine | None = None,
    retention_class: RetentionClass = RetentionClass.HOT,
) -> tuple[CertificationRecord, CertificationSeal | None]:
    """Certify a claim and — unless told not to — seal the evidence behind it."""
    bundle = (
        bundle
        if bundle is not None
        else _bundle(residue=residue, recovery=recovery, demotions=demotions)
    )
    record = certify(
        _pending(cell),
        at=NOW,
        evidence=(bundle,),
        outcome="certified on a real cell",
    )
    repository.append(record, run_id=RUN_ID, now=NOW)
    sealed = None
    if seal:
        sealed = seal_certification_evidence(
            store,
            _facts(bundle, residue=residue, recovery=recovery, demotions=demotions),
            recorded_at=READING,
            retention_class=retention_class,
            retention=retention,
        )
    return record, sealed


def _gate_engines(
    repository: CertificationRepository,
    store: Store,
    *,
    fault_id: str = FAULT_ID,
    now: datetime = NOW,
) -> frozenset[EngineLane]:
    """Which engines the sealed gate still counts as certified."""
    gate = sealed_certification_gate(repository, store, now=now)
    return certified_engines(gate.get(fault_id, ()))


def _decision(repository: CertificationRepository, store: Store, *, now: datetime = NOW) -> str:
    """The reported maturity, evaluated with the *sealed* gate armed."""
    definition = definition_for(FAULT_ID)
    probe = build_probe(
        definition,
        executor_registered=lambda _id: True,
        compensation_registered=lambda _id: True,
        unit_evidence=("unit",),
    )
    return evaluate_maturity(
        definition,
        probe=probe,
        records=sealed_certification_gate(repository, store, now=now),
    ).maturity.value


# ── seal and verify ─────────────────────────────────────────────────────────


def test_sealing_produces_a_chain_and_manifest_the_domain_verifier_accepts(
    store: Store, tmp_path: Path
) -> None:
    """The seal is plan 12's, not a private one: same verifier, same tables."""
    repository = CertificationRepository(store)
    bundle = _bundle()
    record, seal = _certify(store, repository, bundle=bundle)
    assert seal is not None

    attestations = AttestationRepository(store)
    chain = attestations.verify_run_chain(certification_chain_id(bundle.bundle_hash))
    assert chain.valid, chain.errors
    assert chain.root_digest == seal.chain_root
    assert attestations.verify_stored_manifest(seal.manifest_id).valid
    assert seal.manifest_id == certification_manifest_id(bundle.bundle_hash)

    # Plan 12's own tables, with plan 12's unsigned-since-Phase-2 honesty intact.
    rows = store.query("SELECT manifest_id FROM attestation_manifests")
    assert [str(dict(row)["manifest_id"]) for row in rows] == [seal.manifest_id]
    state, reason = attestations.load_signature_state(seal.manifest_id)
    assert state == "unsigned_no_signing"
    assert "no signature bytes" in reason

    # And the record cites exactly that evidence.
    verdict = verify_record_evidence(store, record)
    assert verdict.grants_runtime_verification, verdict.describe()


def test_the_chain_carries_the_residue_scan_and_the_recovery_probe(store: Store) -> None:
    """The residue scan is a member of the chain, not a field beside it.

    This is the plan's acceptance criterion made structural: a runtime-verified
    claim rests on a scan that was *performed* and a probe that came home, and
    both have to be readable from the sealed bytes with no runner and no cell.
    """
    repository = CertificationRepository(store)
    bundle = _bundle()
    _certify(store, repository, bundle=bundle)

    events = AttestationRepository(store).load_chain(certification_chain_id(bundle.bundle_hash))
    kinds = [event.event_kind for event in events]
    assert kinds[0] == CHAIN_EVENT_RECORDED
    assert kinds[-1] == CHAIN_EVENT_SEALED

    payload = events[0].payload
    assert payload["residue"] == {"performed": True, "clean": True, "findings": []}
    assert payload["recovery"] == {
        "probe": "lease.released",
        "undo_ran": True,
        "baseline": 0.0,
        "observed": 0.0,
        "tolerance": 0.0,
    }
    assert payload["recovery_required"] is True
    assert payload["compensated"] is True
    assert payload["digests"] == bundle.digests


def test_a_regression_demotion_is_a_member_of_the_chain(store: Store) -> None:
    """The demotion travels in the chain, not only in a row's reason string."""
    repository = CertificationRepository(store)
    demotion = _demotion()
    bundle = _bundle(demotions=(demotion,))
    _certify(store, repository, bundle=bundle, demotions=(demotion,))

    events = AttestationRepository(store).load_chain(certification_chain_id(bundle.bundle_hash))
    demoted = [event for event in events if event.event_kind == CHAIN_EVENT_DEMOTED]
    assert len(demoted) == 1
    assert demoted[0].payload["fault_id"] == FAULT_ID
    assert demoted[0].payload["previous_sequence"] == "1"
    assert demoted[0].payload["new_state"] == CertificationState.FAILED.value
    assert demoted[0].payload["bundle_hash"] == bundle.bundle_hash

    verdict = verify_record_evidence(store, repository.latest(FAULT_ID).record)  # type: ignore[union-attr]
    assert verdict.demotions == (f"{FAULT_ID}@1",)
    assert verdict.grants_runtime_verification


def test_two_demotions_in_one_attempt_both_survive_the_chain(store: Store) -> None:
    """Distinct ids, so a second withdrawal is not refused for a name collision.

    The runner demotes one claim per attempt so this cannot arise yet; a
    duplicate event id would be caught by the chain verifier as a *duplicate*
    rather than as what it actually is, and the error would point at the wrong
    thing.
    """
    repository = CertificationRepository(store)
    first, second = _demotion(1), _demotion(2)
    bundle = _bundle(demotions=(first, second))
    _certify(store, repository, bundle=bundle, demotions=(first, second))

    events = AttestationRepository(store).load_chain(certification_chain_id(bundle.bundle_hash))
    assert [event.event_kind for event in events] == [
        CHAIN_EVENT_RECORDED,
        CHAIN_EVENT_DEMOTED,
        CHAIN_EVENT_DEMOTED,
        CHAIN_EVENT_SEALED,
    ]
    assert len({event.event_id for event in events}) == 4


def test_certification_events_are_pure_and_still_reference_the_run() -> None:
    """The derivation is a function of the facts, and never embeds the bundle."""
    facts = _facts(_bundle(), demotions=(_demotion(),))
    first = certification_events(facts, recorded_at=READING)
    second = certification_events(facts, recorded_at=READING)

    assert [event.event_kind for event in first] == [
        CHAIN_EVENT_RECORDED,
        CHAIN_EVENT_DEMOTED,
        CHAIN_EVENT_SEALED,
    ]
    assert [event.event_id for event in first] == [event.event_id for event in second]
    assert all(event.is_sealed is False for event in first), "sealing is a separate step"
    assert all(event.run_id == certification_chain_id(facts.bundle.bundle_hash) for event in first)
    assert "bundle_json" not in str(first[0].payload)


# ── retention interaction ───────────────────────────────────────────────────


def _archived_certification(
    store: Store, tmp_path: Path
) -> tuple[CertificationRepository, RetentionEngine, str]:
    """A certification whose evidence is registered, cold, archived, and expired.

    The ladder is walked all the way to ``archive`` on purpose: a deletion test
    that only ever trips the "not expired yet" rule would prove nothing about the
    certification guard, because retention would have refused it anyway.
    """
    backend = InMemoryRetentionBackend()
    engine = RetentionEngine(store, backend=backend)
    repository = CertificationRepository(store)
    bundle = _bundle()
    _certify(
        store,
        repository,
        bundle=bundle,
        retention=engine,
        retention_class=RetentionClass.EPHEMERAL,
    )
    manifest_id = certification_manifest_id(bundle.bundle_hash)
    engine.cool(manifest_id, now=NOW)
    engine.archive(manifest_id, now=NOW)
    return repository, engine, manifest_id


def test_deleting_evidence_a_live_certification_depends_on_is_refused(
    store: Store, tmp_path: Path
) -> None:
    """The hazard: bytes gone, claim still reporting a level. Refused instead.

    Everything retention would otherwise allow is in place — expired, archived
    externally, two named approvers — so the refusal can only be the guard.
    """
    repository, engine, manifest_id = _archived_certification(store, tmp_path)

    with pytest.raises(CertificationEvidenceHeldError) as refusal:
        expire_certification_evidence(
            engine,
            repository,
            store,
            manifest_id=manifest_id,
            requester="ana",
            approver="bo",
            reason="routine cleanup",
            now=LATER,
        )

    assert "proc.pause" in str(refusal.value)
    assert "demote_dependents=True" in str(refusal.value)
    # Nothing was changed: no tombstone, and the claim is untouched.
    assert store.query("SELECT * FROM retention_tombstones") == []
    assert repository.latest(FAULT_ID).record.state is CertificationState.CERTIFIED  # type: ignore[union-attr]
    assert _gate_engines(repository, store) == frozenset({EngineLane.DOCKER})
    assert _decision(repository, store) != "verified-live"


def test_the_demote_first_path_withdraws_the_claim_and_then_deletes(
    store: Store, tmp_path: Path
) -> None:
    """The deliberate second path: demote in place, then delete the bytes.

    Ordering is the point. There is no window in which the record has been
    withdrawn and its evidence has not yet gone, so a reader never sees a demoted
    claim whose evidence is still intact, nor an intact claim whose evidence is
    gone.
    """
    repository, engine, manifest_id = _archived_certification(store, tmp_path)

    tombstone = expire_certification_evidence(
        engine,
        repository,
        store,
        manifest_id=manifest_id,
        requester="ana",
        approver="bo",
        reason="the cell it was made on is gone",
        now=LATER,
        demote_dependents=True,
    )

    assert tombstone.dual_control_satisfied
    record = repository.latest(FAULT_ID).record  # type: ignore[union-attr]
    assert record.state is CertificationState.FAILED
    assert manifest_id in record.reason
    assert "approved by bo" in record.reason
    assert _gate_engines(repository, store) == frozenset()
    assert _decision(repository, store) != "verified-live"


def test_a_lapsed_claim_does_not_hold_its_evidence_hostage(
    store: Store, tmp_path: Path
) -> None:
    """An expired claim protects nothing, so the ladder may still reclaim.

    Without this the guard would be unusable: a fault that had *ever* been
    certified could never have its evidence deleted, and the retention ladder
    would quietly stop working for exactly the faults most worth keeping records
    of.
    """
    repository, engine, manifest_id = _archived_certification(store, tmp_path)

    tombstone = expire_certification_evidence(
        engine,
        repository,
        store,
        manifest_id=manifest_id,
        requester="ana",
        approver="bo",
        now=LAPSED,
    )

    assert tombstone.manifest_id == manifest_id
    stored = repository.latest(FAULT_ID).record  # type: ignore[union-attr]
    assert stored.state is CertificationState.CERTIFIED, "the row itself is not aged by a read"


def test_a_certification_whose_evidence_vanished_is_demoted_not_left_standing(
    store: Store,
) -> None:
    """The unsanctioned case: evidence removed behind retention's back.

    The guard stops the deletion it can see. This is the sweep for the ones it
    cannot — a hand-edited attestation row, a restored snapshot, a cleaned bundle
    directory — and it exists so a claim can never outlive what it is checked
    against.
    """
    repository = CertificationRepository(store)
    bundle = _bundle()
    _certify(store, repository, bundle=bundle)
    assert _gate_engines(repository, store) == frozenset({EngineLane.DOCKER})

    with store.write() as conn:
        conn.execute("DELETE FROM attestation_events WHERE event_kind = ?", (CHAIN_EVENT_RECORDED,))

    withdrawn = reconcile_certification_evidence(repository, store, now=NOW)

    assert len(withdrawn) == 1
    record = repository.latest(FAULT_ID).record  # type: ignore[union-attr]
    assert record.state is CertificationState.FAILED
    assert "does not verify" in record.reason
    assert _gate_engines(repository, store) == frozenset()


# ── negative controls ───────────────────────────────────────────────────────


def test_a_record_whose_bundle_was_never_sealed_grants_no_level(store: Store) -> None:
    """A reference to bytes nothing has verified is not evidence.

    This is the exact shape of the pre-Phase-4 record: complete digests, a real
    bundle hash, nothing attested. It still has to be refused, and the reported
    level has to follow the refusal down.
    """
    repository = CertificationRepository(store)
    record, _ = _certify(store, repository, seal=False)

    assert record.state is CertificationState.CERTIFIED, "the weaker claim still stands in the row"
    verdict = verify_record_evidence(store, record)
    assert not verdict.verified
    assert "no sealed certification evidence" in verdict.errors[0]
    assert _gate_engines(repository, store) == frozenset()

    definition = definition_for(FAULT_ID)
    probe = build_probe(
        definition,
        executor_registered=lambda _id: True,
        compensation_registered=lambda _id: True,
        unit_evidence=("unit",),
    )
    decision = evaluate_maturity(
        definition,
        probe=probe,
        records=sealed_certification_gate(repository, store, now=NOW),
    )
    assert decision.live_verified is False
    unmet = [
        outcome
        for outcome in decision.outcomes
        if outcome.name == CERTIFICATION_RECORDED and not outcome.met
    ]
    assert unmet and "no certified certification record" in unmet[0].observed


def test_a_record_with_no_residue_scan_is_not_runtime_verified(store: Store) -> None:
    """``performed=False`` fails even with an empty finding list.

    A record with a digest for a scan nobody ran is constructible — Phase 1
    refuses to know what the digest contained — so the sealed chain is the only
    place this can be caught, which is exactly why the scan is in the chain.
    """
    repository = CertificationRepository(store)
    residue = ResidueScan(performed=False, note="the probe timed out")
    bundle = _bundle(residue=residue)
    record, _ = _certify(store, repository, bundle=bundle, residue=residue)

    assert record.state is CertificationState.CERTIFIED
    verdict = verify_record_evidence(store, record)
    assert verdict.verified, verdict.errors
    assert verdict.residue_clean is False
    assert not verdict.grants_runtime_verification
    assert _gate_engines(repository, store) == frozenset()


def test_residue_left_on_the_cell_is_not_runtime_verified(store: Store) -> None:
    """A scan that looked and found something is not clean, and is refused."""
    repository = CertificationRepository(store)
    residue = ResidueScan(
        performed=True, findings=(ResidueFinding(kind="tc_rule", detail="filter/tc/MAYHEM"),)
    )
    bundle = _bundle(residue=residue)
    _certify(store, repository, bundle=bundle, residue=residue)

    verdict = verify_record_evidence(store, repository.latest(FAULT_ID).record)  # type: ignore[union-attr]
    assert verdict.verified
    assert verdict.residue_clean is False


def test_recovery_that_never_came_home_is_not_runtime_verification(store: Store) -> None:
    """An undo that ran but drifted past tolerance fails the recovery half."""
    repository = CertificationRepository(store)
    bundle = _bundle(recovery=_DRIFTED_RECOVERY)
    _certify(store, repository, bundle=bundle, recovery=_DRIFTED_RECOVERY)

    verdict = verify_record_evidence(store, repository.latest(FAULT_ID).record)  # type: ignore[union-attr]
    assert verdict.verified
    assert verdict.residue_clean is True
    assert verdict.recovery_verified is False
    assert _gate_engines(repository, store) == frozenset()


def test_an_irreversible_fault_is_held_to_the_compensation_claim_instead(
    store: Store,
) -> None:
    """No recovery probe required, but no unrecovered lease either.

    An irreversible fault has no baseline to come home to, so the obligation moves
    rather than disappears: what must hold instead is that the run left nothing
    unrecovered. Which branch applies is read from the chain's own
    ``recovery_required`` flag, not from anything a caller says at verification
    time, so the two cannot be edited apart.
    """
    compensated_bundle = _bundle(compensated=True)
    seal_certification_evidence(
        store,
        _irreversible_facts(compensated_bundle, compensated=True),
        recorded_at=READING,
    )
    clean = verify_bundle_evidence(
        store, compensated_bundle.bundle_hash, digests=compensated_bundle.digests
    )
    assert clean.verified and clean.recovery_verified
    assert clean.grants_runtime_verification

    dirty_bundle = _bundle(compensated=False)
    seal_certification_evidence(
        store, _irreversible_facts(dirty_bundle, compensated=False), recorded_at=READING
    )
    dirty = verify_bundle_evidence(store, dirty_bundle.bundle_hash, digests=dirty_bundle.digests)
    assert dirty.verified and dirty.residue_clean
    assert dirty.recovery_verified is False
    assert not dirty.grants_runtime_verification


def test_a_tampered_chain_is_rejected(store: Store) -> None:
    """An event edited behind the model is caught by re-verification, not trust."""
    repository = CertificationRepository(store)
    bundle = _bundle()
    _certify(store, repository, bundle=bundle)
    record = repository.latest(FAULT_ID).record  # type: ignore[union-attr]
    assert verify_record_evidence(store, record).grants_runtime_verification

    chain_id = certification_chain_id(bundle.bundle_hash)
    rows = store.query("SELECT event_json FROM attestation_events WHERE run_id = ?", (chain_id,))
    raw = str(dict(rows[0])["event_json"])
    tampered = raw.replace('"performed":true', '"performed":false')
    assert tampered != raw, "the tamper did not land; the negative control is not testing anything"
    with store.write() as conn:
        conn.execute(
            "UPDATE attestation_events SET event_json = ? WHERE run_id = ?", (tampered, chain_id)
        )

    verdict = verify_record_evidence(store, record)
    assert not verdict.verified
    assert verdict.errors
    assert not verdict.grants_runtime_verification
    assert _gate_engines(repository, store) == frozenset()


def test_a_chain_sealed_for_a_different_bundle_or_digests_is_rejected(
    store: Store,
) -> None:
    """Two refutations, both reachable by pointing a record at the wrong bytes."""
    repository = CertificationRepository(store)
    bundle = _bundle()
    _certify(store, repository, bundle=bundle)

    other = verify_bundle_evidence(store, "f" * 64, digests=bundle.digests)
    assert not other.verified
    assert "no sealed certification evidence" in other.errors[0]

    relabelled = dict(bundle.digests)
    relabelled["residue"] = "0" * 64
    mismatched = verify_bundle_evidence(store, bundle.bundle_hash, digests=relabelled)
    assert not mismatched.verified
    assert any("differ from the ones the record cites" in error for error in mismatched.errors)


def test_a_manifest_with_no_chain_behind_it_names_the_absence(store: Store) -> None:
    """Unknown is reported as unknown, never resolved to a wrong bundle."""
    assert bundle_hash_for_manifest(store, "certification:absent:manifest") == ""

    bundle = _bundle()
    sealed = seal_certification_evidence(store, _facts(bundle), recorded_at=READING)
    assert bundle_hash_for_manifest(store, sealed.manifest_id) == bundle.bundle_hash


def test_a_record_citing_a_second_bundle_is_still_guarded(store: Store) -> None:
    """The reverse index reads the refs, not only the indexed first column.

    ``certification_records.bundle_hash`` stores the *first* reference only, so a
    record citing two bundles would be invisible to a column query — and an
    invisible claim is an unguarded one.
    """
    repository = CertificationRepository(store)
    first = _bundle()
    second = _bundle(recovery=_DRIFTED_RECOVERY)
    assert first.bundle_hash != second.bundle_hash
    engine = RetentionEngine(store, backend=InMemoryRetentionBackend())
    for bundle in (first, second):
        seal_certification_evidence(
            store,
            _facts(bundle),
            recorded_at=READING,
            retention_class=RetentionClass.EPHEMERAL,
            retention=engine,
        )
    record = certify(
        _pending(),
        at=NOW,
        evidence=(first, second),
        outcome="certified with two bundles",
    )
    repository.append(record, run_id=RUN_ID, now=NOW)

    assert repository.records_citing_bundle(second.bundle_hash)
    for bundle in (first, second):
        manifest_id = certification_manifest_id(bundle.bundle_hash)
        engine.cool(manifest_id, now=NOW)
        engine.archive(manifest_id, now=NOW)
    manifest_id = certification_manifest_id(second.bundle_hash)
    with pytest.raises(CertificationEvidenceHeldError):
        expire_certification_evidence(
            engine,
            repository,
            store,
            manifest_id=manifest_id,
            requester="ana",
            approver="bo",
            now=LATER,
        )


# ── the runner seam ─────────────────────────────────────────────────────────


def _plan() -> ExecutionPlan:
    scope = TargetScope(
        logical_id="testcase-api",
        runtime=RuntimeLabel.DOCKER,
        kind=ResourceKind.CONTAINER,
        authority={"container_name": "testcase-api"},
    )
    return ExecutionPlan(
        run_id=RUN_ID,
        kind=ExperimentKind.DRILL,
        steps=(
            PlannedStep(
                id=STEP_ID,
                seq=1,
                fault=PlannedFault(
                    fault_id=FAULT_ID,
                    targets=(
                        ResolvedTarget(
                            selector=TargetSelector(kind=NodeKind.CONTAINER, expr="testcase-api"),
                            node_ids=frozenset({"testcase-api"}),
                        ),
                    ),
                    target=scope,
                    params={},
                    duration="5.0s",
                ),
                target=scope,
                raw_action=Wait(duration="5.0s"),
            ),
        ),
        config_snapshot_id="cfg-1",
        topology_snapshot_id="topo-1",
        environment_fingerprint="f" * 64,
    )


def _run_result(*, ok: bool = True) -> RunResult:
    return RunResult(
        run_id=RUN_ID,
        status="completed",
        started_at_epoch_s=NOW.timestamp(),
        ended_at_epoch_s=NOW.timestamp() + 1.0,
        steps=(
            StepReport(
                STEP_ID,
                ok,
                "proc.pause injected on testcase-api: undo: SIGCONT",
                status="compensated",
                measured={"injected": True},
            ),
        ),
        dirty_leases=(),
        verdict=RunVerdict.PASS,
    )


@dataclass
class _Cell:
    """A disposable cell with no runtime behind it; every fact is a knob."""

    recovery: RecoveryEvidence | None = field(default_factory=lambda: _GOOD_RECOVERY)
    residue: ResidueScan = field(default_factory=lambda: ResidueScan(performed=True))
    injector: str = "1.0.0"

    @property
    def cell(self) -> MatrixCell:
        return _cell()

    @property
    def injector_version(self) -> str:
        return self.injector

    def execute(self, plan: ExecutionPlan) -> RunResult:
        del plan
        return _run_result()

    def recovery_evidence(self, run: CertifiedRun) -> RecoveryEvidence | None:
        del run
        return self.recovery

    def residue_scan(self) -> ResidueScan:
        return self.residue

    def dispose(self) -> None:
        return None


@dataclass
class _Provisioner:
    cell: _Cell = field(default_factory=_Cell)

    def provision(self, request: CertificationRequest) -> _Cell:
        del request
        return self.cell


@dataclass
class _FaithfulCapturer:
    """Derives the bundle from the attempt's own facts, as the live capturer does."""

    def capture(
        self,
        run: CertifiedRun,
        *,
        request: CertificationRequest,
        cell: MatrixCell,
        plan: ExecutionPlan,
        residue: ResidueScan,
        recovery: RecoveryEvidence | None,
        demotions: tuple[DemotionEvent, ...] = (),
    ) -> EvidenceBundleRef:
        del cell
        step = next(step for step in plan.steps if step.fault is not None)
        assert step.fault is not None
        detail = next(report.detail for report in run.steps if report.step_id == step.id)
        digests = expected_evidence_digests(
            params=dict(step.fault.params),
            target="docker/testcase-api",
            observed_effect=f"{definition_for(request.fault_id).observable_effect}"
            f"|observed={detail}",
            recovery=recovery,
            residue=residue,
            demotions=demotions,
            compensated=not run.dirty_leases,
        )
        return EvidenceBundleRef(
            bundle_hash=evidence_digest("bundle", digests),
            mayhem_version="1.1.0",
            digests=digests,
        )


class _SpySealer:
    """Records what the runner handed the sealer, then seals for real."""

    def __init__(self, inner: CertificationEvidenceStore, store: Store) -> None:
        self.inner = inner
        self.store = store
        self.calls: list[dict[str, object]] = []

    def seal_evidence(self, **kwargs: Any) -> EvidenceSealReceipt:
        self.calls.append(kwargs)
        return self.inner.seal_evidence(**kwargs)


class _BrokenSealer:
    """Raises instead of sealing — an infrastructure failure mid-attempt."""

    def __init__(self, message: str = "the attestation store is unreachable") -> None:
        self.message = message

    def seal_evidence(self, **kwargs: Any) -> EvidenceSealReceipt:
        del kwargs
        raise RuntimeError(self.message)


class _DishonestSealer:
    """Reports success for a bundle it never sealed."""

    def seal_evidence(self, **kwargs: Any) -> EvidenceSealReceipt:
        del kwargs
        return EvidenceSealReceipt(
            bundle_hash="c" * 64,
            manifest_id="certification:unrelated:manifest",
            chain_root="d" * 64,
            verified=True,
        )


def _attempt(
    *,
    repository: CertificationRepository,
    cell: _Cell | None = None,
    sealer: object | None = None,
) -> Any:
    request = CertificationRequest(
        fault_id=FAULT_ID,
        cell=CellRequest(
            engine=EngineLane.DOCKER,
            engine_version="27.1.1",
            os_distro="Alpine 3.20",
            kernel_version="6.6.13-0-lts",
            arch=Arch.AMD64,
            privilege=CellPrivilege.ROOT,
        ),
        target="testcase-api",
        injector_version="1.0.0",
    )
    return certify_fault(
        request,
        provisioner=_Provisioner(cell=cell or _Cell()),
        compile_plan=lambda _request: _plan(),
        capture=_FaithfulCapturer(),
        sink=repository,
        now=NOW,
        evidence_sealer=sealer,  # type: ignore[arg-type]
    )



def test_the_runner_certifies_when_the_sealer_verifies(store: Store) -> None:
    """The whole loop: run, residue-scan, cross-check, seal, certify, re-verify."""
    repository = CertificationRepository(store)
    sealer = _SpySealer(CertificationEvidenceStore(store, repository=repository), store)

    attempt = _attempt(sealer=sealer, repository=repository)

    assert attempt.certified
    assert attempt.recurrence is RecurrenceVerdict.RECOVERED
    assert attempt.residue.clean
    assert len(sealer.calls) == 1
    # Re-read the verdict from plan 12's own tables rather than trusting the
    # receipt the sealer handed back.
    bundle = sealer.calls[0]["bundle"]
    assert isinstance(bundle, EvidenceBundleRef)
    assert AttestationRepository(sealer.store).verify_stored_manifest(
        certification_manifest_id(bundle.bundle_hash)
    ).valid
    assert verify_record_evidence(store, attempt.record).grants_runtime_verification
    assert _gate_engines(repository, store) == frozenset({EngineLane.DOCKER})


def test_a_sealer_that_raises_refuses_the_certification(store: Store) -> None:
    """An infrastructure failure in the sealer is a refusal, not a certification."""
    repository = CertificationRepository(store)

    attempt = _attempt(sealer=_BrokenSealer(), repository=repository)

    assert not attempt.certified
    assert attempt.record.state is CertificationState.PENDING
    assert any(RefusalClass.EVIDENCE_UNSEALABLE in refusal for refusal in attempt.refusals)
    assert any("unreachable" in refusal for refusal in attempt.refusals)
    assert _gate_engines(repository, store) == frozenset()


def test_a_sealer_that_reports_another_bundle_is_refused(store: Store) -> None:
    """A receipt for bytes this attempt did not produce is not its evidence."""
    repository = CertificationRepository(store)

    attempt = _attempt(sealer=_DishonestSealer(), repository=repository)

    assert not attempt.certified
    refusals = [r for r in attempt.refusals if RefusalClass.EVIDENCE_UNSEALABLE in r]
    assert len(refusals) == 1, refusals
    assert "must be sealed for the run that produced it" in refusals[0]


def test_omitting_the_sealer_certifies_but_leaves_no_chain_behind(store: Store) -> None:
    """The honest weaker claim, pinned so it cannot become a silent stronger one.

    Omitting the sealer is the pre-Phase-4 behaviour and is preserved on purpose,
    which means a caller can still produce a ``certified`` record with nothing
    attested. The gate is what closes that: no chain means no verification, so the
    claim does not reach the reported level even though the row says certified.
    """
    repository = CertificationRepository(store)

    attempt = _attempt(repository=repository)

    assert attempt.record.state is CertificationState.CERTIFIED
    events = store.query(
        "SELECT * FROM attestation_events WHERE event_kind LIKE 'certification%'"
    )
    assert events == []
    assert _gate_engines(repository, store) == frozenset()
    assert _decision(repository, store) != "verified-live"


def test_a_regression_is_demoted_and_the_demotion_reaches_the_chain(store: Store) -> None:
    """The end-to-end requirement: a demotion event inside sealed evidence.

    The first attempt certifies and seals. The second run contradicts it, so the
    runner demotes the standing claim in place and hands the demotion to the
    sealer — which is what puts it in the chain rather than only in a reason
    string beside it.
    """
    repository = CertificationRepository(store)
    sealer = _SpySealer(CertificationEvidenceStore(store, repository=repository), store)

    first = _attempt(sealer=sealer, repository=repository)
    assert first.certified

    second = _attempt(cell=_Cell(recovery=_DRIFTED_RECOVERY), sealer=sealer, repository=repository)

    assert len(second.demotions) == 1
    demotion = second.demotions[0]
    assert demotion.previous_state == CertificationState.CERTIFIED.value
    assert demotion.new_state == CertificationState.FAILED.value
    assert sealer.calls[-1]["demotions"] == (demotion,)

    demoted_bundle = sealer.calls[-1]["bundle"]
    assert isinstance(demoted_bundle, EvidenceBundleRef)
    events = AttestationRepository(store).load_chain(
        certification_chain_id(demoted_bundle.bundle_hash)
    )
    assert [event.event_kind for event in events] == [
        CHAIN_EVENT_RECORDED,
        CHAIN_EVENT_DEMOTED,
        CHAIN_EVENT_SEALED,
    ]
    assert events[1].payload["reason"] == demotion.reason

    standing = repository.load(FAULT_ID)[0]
    assert standing.record.state is CertificationState.FAILED
    assert _gate_engines(repository, store) == frozenset()


def test_the_gate_agrees_across_every_required_engine(store: Store) -> None:
    """Both engines certified with sealed evidence: the gate stops refusing."""
    repository = CertificationRepository(store)
    for engine in REQUIRED_LIVE_ENGINES:
        cell = _cell(engine)
        bundle = _bundle()
        facts = CertificationFacts(
            bundle=bundle,
            fault_id=FAULT_ID,
            cell_label=cell.label,
            cell_fingerprint=cell.fingerprint,
            injector_version="1.0.0",
            run_id=RUN_ID,
            residue=ResidueScan(performed=True),
            recovery=_GOOD_RECOVERY,
            recovery_required=True,
            compensated=True,
            outcome="certified on a real cell",
        )
        seal_certification_evidence(store, facts, recorded_at=READING)
        repository.append(
            certify(_pending(cell), at=NOW, evidence=(bundle,), outcome="certified"),
            run_id=RUN_ID,
            now=NOW,
        )

    assert _gate_engines(repository, store) == frozenset(REQUIRED_LIVE_ENGINES)
    decision = _decision(repository, store)
    assert decision in {"verified-unit", "verified-live", "stable"}


# ── module guards ───────────────────────────────────────────────────────────


def test_this_module_never_calls_the_bundle_producer() -> None:
    """Phase 4 attests the bundle; it does not assemble a second one.

    The mention gate in ``tests/unit/test_withdrawal_asset.py`` grants permission
    to *name* the producer, never to call it, and a second producer would be the
    duplication plan 12's store exists to prevent. Asserting it here means the
    rule survives even if that allowlist is ever edited.
    """
    from pathlib import Path as _Path

    source = _Path(__file__).parents[2] / "src" / "mayhem" / "controller" / (
        "certification_evidence.py"
    )
    assert "build_bundle(" not in source.read_text(encoding="utf-8")


def test_a_second_sealer_is_not_smuggled_in(store: Store) -> None:
    """Sealing goes through plan 12's functions, not a private hash rule.

    ``verify_chain``/``verify_manifest`` are the domain verifier's job, and the
    sealed rows must be readable by plan 12's own repository — which is what makes
    an auditor's offline re-verification possible at all.
    """
    bundle = _bundle()
    sealed = seal_certification_evidence(store, _facts(bundle), recorded_at=READING)

    attestations = AttestationRepository(store)
    assert attestations.load_chain(sealed.chain_id) == sealed.events
    assert attestations.load_manifest(sealed.manifest_id) == sealed.manifest
    assert sealed.chain_verification.valid and sealed.manifest_verification.valid
    assert "verified" in sealed.describe()

