"""Plan 01 Phase 4: a certification's evidence is *sealed*, not merely referenced.

What Phase 3 left behind
-------------------------
Phases 1-3 made a live claim falsifiable in three layers of the domain: a
``certified`` :class:`~mayhem.domain.certification.CertificationRecord` cannot be
constructed without an evidence reference carrying every required content
digest, the runner refuses a bundle whose digests are not the ones the run's own
facts produce, and the promotion gate drops a level when a record stops granting
one. Every one of those checks is arithmetic over bytes someone handed to the
process. None of them asks whether those bytes are still *there*, or whether
they were altered afterwards. Phase 2's own status line admitted this: the
demotion event was "a ``demotion`` digest inside the bundle", which is a claim
about the demotion recorded next to a hash, not the demotion itself being
sealed.

What this module adds
---------------------
An :class:`~mayhem.domain.attestation.AttestedEvent` chain per certification,
sealed and verified by the machinery that already exists —
:func:`~mayhem.domain.attestation.seal_events`,
:func:`~mayhem.domain.attestation.build_manifest`,
:func:`~mayhem.domain.attestation.verify_chain`,
:func:`~mayhem.domain.attestation.verify_manifest`, and
:class:`~mayhem.infra.attestation_store.AttestationRepository`. There is no second
sealer here: this module derives *what* to attest, and the plan 12 store does
the sealing, the persistence, and the evidence-boundary gate. The residue scan,
the recovery probe, the demotion events, and the bundle digests all become
chain members, so a reader can re-verify the certification months later with
no control plane and no runner.

Three properties follow, and each is enforced rather than described.

**A reference must resolve.** :func:`verify_record_evidence` answers "does this
record's bundle reference name a chain that verifies *and* describes this
record?". A record whose evidence was never sealed, was altered, or describes a
different fault or a different set of digests returns a verdict with
``verified=False`` and the reasons named.
:func:`sealed_certification_gate` folds that into the mapping
:func:`mayhem.infra.promotion.evaluate_maturity` consumes, so the only function
that decides a reported level still does — it is simply handed a mapping in
which an unverifiable claim no longer grants one, because such a record is
handed on in the ``failed`` state instead of the ``certified`` one.

**A claim is recoverable-verified and residue-clean, or it is not a live claim.**
:attr:`CertificationEvidenceVerdict.grants_runtime_verification` is the single
predicate, and it is conjunctive: the chain verifies, the recorded residue scan
was *performed* and found nothing, and recovery is verified (or the catalog says
the fault is irreversible and the run left no unrecovered lease). "I did not look"
is not a scan, so ``performed=False`` fails even with an empty finding list.

**Evidence outlives the run, and losing it is not silent.**
:class:`CertificationEvidenceStore` registers each sealed chain with the
retention ladder so its bytes are governed like any other evidence. Deletion
then needs a decision from this module, not from retention alone:
:func:`expire_certification_evidence` **refuses by default** while a live claim
cites the evidence, because a certification that quietly lost its bundle would
keep reporting a level, and the only honest options are to withdraw the claim
first or to say no. :func:`reconcile_certification_evidence` catches the
remaining case — evidence removed without going through retention at all — by
demoting every live claim whose chain no longer verifies.

Why refuse by default rather than always demote
-----------------------------------------------
Both are implemented, and the default is the conservative one. An unconditional
refusal would make a fault that has *ever* been certified permanently
undeletable, so retention could never reclaim anything on its behalf and the
ladder would silently stop working for the faults most worth keeping evidence
for. Demoting automatically, on the other hand, lets whoever runs a retention
sweep withdraw a maturity claim by touching only the evidence — the
certification surface would be reporting less than it actually knows, with no
transition on the record and no event anyone asked for. So the default is a
refusal naming the dependents and the remedy, and ``demote_dependents=True`` is
the explicit, in-band way to accept the withdrawal at the same moment the bytes
go away. Both write the demotion through
:func:`~mayhem.domain.certification.mark_failed` and the repository's
``store_transition``, so the record's own history says why it stopped granting a
level.

Nothing here is wired into the CLI
-----------------------------------
:mod:`mayhem.cli.certify` is outside this phase's ownership, so no call site
passes an :class:`~mayhem.infra.certification_runner.EvidenceSealer` yet. The
consequence is stated rather than hidden: in a default deployment no certification
chain exists, :func:`sealed_certification_gate` therefore grants nothing, and
every fault stays capped at ``verified-unit`` — which is why the README's
live-verified count is still ``0 of N`` (N the live catalogue size) and must
stay there until a real cell
both runs *and* seals.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    ChainVerification,
    Manifest,
    ManifestVerification,
    RetentionClass,
    build_manifest,
    chain_root,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.catalog import definition_for
from mayhem.domain.certification import expire_by_time, mark_failed
from mayhem.domain.common import utc_now
from mayhem.infra.attestation_store import AttestationError, AttestationRepository
from mayhem.infra.certification_repository import CertificationRepository, StoredCertification
from mayhem.infra.certification_runner import (
    EvidenceSealReceipt,
    RecoveryEvidence,
    ResidueScan,
    requires_recovery_verification,
)
from mayhem.infra.retention import RetentionEngine, RetentionRefusedError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mayhem.domain.certification import CertificationRecord, EvidenceBundleRef, MatrixCell
    from mayhem.infra.certification_runner import (
        CertificationRequest,
        CertifiedRun,
        DemotionEvent,
    )
    from mayhem.infra.retention import RetentionTombstone
    from mayhem.infra.store import Store

__all__ = [
    "CERTIFICATION_CHAIN_PREFIX",
    "CHAIN_EVENT_DEMOTED",
    "CHAIN_EVENT_RECORDED",
    "CHAIN_EVENT_SEALED",
    "CertificationEvidenceHeldError",
    "CertificationEvidenceStore",
    "CertificationEvidenceVerdict",
    "CertificationFacts",
    "CertificationSeal",
    "bundle_hash_for_manifest",
    "certification_chain_id",
    "certification_events",
    "certification_evidence_dependents",
    "certification_manifest_id",
    "demote_certifications_losing_evidence",
    "expire_certification_evidence",
    "reconcile_certification_evidence",
    "seal_certification_evidence",
    "sealed_certification_gate",
    "verify_bundle_evidence",
    "verify_record_evidence",
]

#: The first chain member: what this certification claims, and on which cell.
CHAIN_EVENT_RECORDED: Final[str] = "certification.recorded"

#: One member per withdrawn claim. A regression demotion is an event in the
#: chain, not only a reason string on a row.
CHAIN_EVENT_DEMOTED: Final[str] = "certification.demoted"

#: The last member: closes the chain by naming the bundle the record cites.
CHAIN_EVENT_SEALED: Final[str] = "certification.sealed"

#: Namespace for the synthetic run a certification chain hangs off. Plan 12's
#: law is one chain per run starting at genesis, so a certification is given a
#: run identity of its own rather than being hung off the run that produced it —
#: which also keeps a second certification of the same fault from overwriting the
#: first chain.
CERTIFICATION_CHAIN_PREFIX: Final[str] = "certification"

_MANIFEST_SUFFIX: Final[str] = ":manifest"

#: Why a claim is withdrawn when its evidence stops verifying. One sentence, used
#: by all three withdrawal paths, so a reader sees the same cause everywhere.
_UNVERIFIED_REASON: Final[str] = (
    "the sealed evidence for this claim does not verify, so it is withdrawn rather than kept"
)
_DELETED_EVIDENCE_REASON: Final[str] = (
    "the sealed evidence this claim cites was deleted, so the claim is withdrawn rather "
    "than kept reporting a level it can no longer support"
)


class CertificationEvidenceHeldError(RetentionRefusedError):
    """Deletion refused: live certifications still depend on this evidence.

    A :class:`~mayhem.infra.retention.RetentionRefusedError` subclass on purpose.
    A caller already handling retention refusals catches this one for free, and a
    caller that does not is still refused — the subclass only says *why*, and
    never turns a refusal into a partial success.
    """


# ── identity ────────────────────────────────────────────────────────────────


def certification_chain_id(bundle_hash: str) -> str:
    """The synthetic run a bundle's certification chain hangs off.

    Derived from the bundle hash rather than the run id so it is stable across a
    re-load and unique per bundle: two certifications of the same fault on the
    same cell produce two chains, and neither can clobber the other.
    """
    return f"{CERTIFICATION_CHAIN_PREFIX}:{bundle_hash}"


def certification_manifest_id(bundle_hash: str) -> str:
    """The manifest id for ``bundle_hash``'s certification chain."""
    return f"{CERTIFICATION_CHAIN_PREFIX}:{bundle_hash}{_MANIFEST_SUFFIX}"


def bundle_hash_for_manifest(store: Store, manifest_id: str) -> str:
    """The bundle hash a certification manifest was sealed for, or ``""``.

    Read out of the manifest's own chain rather than parsed from the id, so an id
    that does not follow this module's convention reports *unknown* instead of
    silently resolving to the wrong bundle — a wrong answer here would attach a
    deletion guard to the wrong evidence.
    """
    rows = store.query(
        "SELECT manifest_json FROM attestation_manifests WHERE manifest_id = ?", (manifest_id,)
    )
    if not rows:
        return ""
    try:
        manifest = Manifest.model_validate_json(str(dict(rows[0])["manifest_json"]))
        events = AttestationRepository(store).load_chain(manifest.run_id)
    except Exception:  # an unreadable manifest is unknown, never guessed at
        return ""
    for event in events:
        if event.event_kind == CHAIN_EVENT_RECORDED:
            return str(event.payload.get("bundle_hash", ""))
    return ""


# ── the facts a chain attests to ─────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CertificationFacts:
    """Everything one certification attempt contributes to the chain.

    Assembled by the caller from the run's own facts and the bundle the record
    cites, and then frozen: the chain must describe the attempt that happened, so
    nothing here may be edited after the fact.
    """

    bundle: EvidenceBundleRef
    fault_id: str
    cell_label: str
    cell_fingerprint: str
    injector_version: str
    run_id: str
    residue: ResidueScan
    recovery: RecoveryEvidence | None
    recovery_required: bool
    compensated: bool
    outcome: str = ""
    demotions: tuple[DemotionEvent, ...] = ()


def _residue_payload(residue: ResidueScan) -> dict[str, object]:
    """The residue scan, recorded in full: performed or not, and what was found.

    ``performed`` is a first-class member rather than inferred from an empty
    finding list, because the two are different facts and only one of them is
    clean.
    """
    return {
        "performed": residue.performed,
        "clean": residue.clean,
        "findings": [[finding.kind, finding.detail] for finding in residue.findings],
    }


def _recovery_payload(recovery: RecoveryEvidence | None) -> dict[str, object] | None:
    """The recovery probe's numbers, or ``None`` when the cell reported none."""
    if recovery is None:
        return None
    return {
        "probe": recovery.probe,
        "undo_ran": recovery.undo_ran,
        "baseline": recovery.baseline,
        "observed": recovery.observed,
        "tolerance": recovery.tolerance,
    }


def certification_payload(facts: CertificationFacts) -> dict[str, object]:
    """The attested claim, as one payload dict.

    Digests are carried whole rather than by count: the verification step
    re-compares them field by field, so a bundle that describes a different run
    cannot pass by carrying the right *number* of them.
    """
    return {
        "bundle_hash": facts.bundle.bundle_hash,
        "mayhem_version": facts.bundle.mayhem_version,
        "digests": dict(sorted(facts.bundle.digests.items())),
        "fault_id": facts.fault_id,
        "cell_label": facts.cell_label,
        "cell_fingerprint": facts.cell_fingerprint,
        "injector_version": facts.injector_version,
        "certification_run_id": facts.run_id,
        "outcome": facts.outcome,
        "residue": _residue_payload(facts.residue),
        "recovery_required": facts.recovery_required,
        "compensated": facts.compensated,
        "recovery": _recovery_payload(facts.recovery),
    }


def certification_events(
    facts: CertificationFacts,
    *,
    recorded_at: AttestedTimestamp,
) -> tuple[AttestedEvent, ...]:
    """The events one certification seals, in chain order (pure).

    Always at least two: the claim itself, then the seal that closes it. Between
    them sits one :data:`CHAIN_EVENT_DEMOTED` per regression demotion, which is
    what makes "the demotion event in evidence" literal — a withdrawn claim
    becomes a hash-linked member of the chain rather than a reason string on a
    row somebody can edit.

    Event ids carry the demotion's position as well as its identity. The runner
    demotes at most one claim per attempt, so the index is not load-bearing
    today, but a duplicate id would be caught by the chain verifier as a
    duplicate rather than as the thing it is, and two withdrawals in one attempt
    should not be refused for a naming collision.

    The events *reference* the bundle by digest and carry its content digests;
    they never re-host the bundle's bytes, so this chain cannot become a second
    copy of the evidence.
    """
    chain_id = certification_chain_id(facts.bundle.bundle_hash)
    events: list[AttestedEvent] = [
        AttestedEvent(
            event_id=f"{chain_id}:recorded",
            event_kind=CHAIN_EVENT_RECORDED,
            run_id=chain_id,
            sequence=0,
            payload=certification_payload(facts),
            recorded_at=recorded_at,
        )
    ]
    for index, demotion in enumerate(facts.demotions):
        events.append(
            AttestedEvent(
                event_id=f"{chain_id}:demoted:{index}:{facts.fault_id}:{demotion.previous_sequence}",
                event_kind=CHAIN_EVENT_DEMOTED,
                run_id=chain_id,
                sequence=len(events),
                payload={
                    **demotion.payload(),
                    "bundle_hash": facts.bundle.bundle_hash,
                },
                recorded_at=recorded_at,
            )
        )
    events.append(
        AttestedEvent(
            event_id=f"{chain_id}:sealed",
            event_kind=CHAIN_EVENT_SEALED,
            run_id=chain_id,
            sequence=len(events),
            payload={
                "bundle_hash": facts.bundle.bundle_hash,
                "claims_before": len(events),
            },
            recorded_at=recorded_at,
        )
    )
    return tuple(events)


# ── sealing ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CertificationSeal:
    """What sealing a certification produced, plus both verification verdicts."""

    bundle_hash: str
    chain_id: str
    manifest_id: str
    events: tuple[AttestedEvent, ...]
    manifest: Manifest
    chain_verification: ChainVerification
    manifest_verification: ManifestVerification

    @property
    def chain_root(self) -> str:
        """The root the manifest commits to."""
        return chain_root(self.events)

    @property
    def verified(self) -> bool:
        """Both the chain and its manifest verified."""
        return self.chain_verification.valid and self.manifest_verification.valid

    def describe(self) -> str:
        return (
            f"{self.bundle_hash[:12]}… sealed as {self.manifest_id} "
            f"(root {self.chain_root[:12]}…, {len(self.events)} event(s), "
            f"{'verified' if self.verified else 'UNVERIFIED'})"
        )


def _reading(at: datetime, recorded_at: AttestedTimestamp | None) -> AttestedTimestamp:
    """The caller's reading, or a wall-clock + monotonic pair for ``at``.

    The monotonic half comes from :func:`time.monotonic_ns` rather than the wall
    clock, so a host whose clock steps mid-attempt still orders the chain
    correctly — the same reason :mod:`mayhem.infra.attestation_store` builds its
    reading this way.
    """
    if recorded_at is not None:
        return recorded_at
    return AttestedTimestamp(
        wall_clock=at.astimezone(UTC),
        monotonic_ns=time.monotonic_ns(),
        source="system",
    )


def seal_certification_evidence(
    store: Store,
    facts: CertificationFacts,
    *,
    recorded_at: AttestedTimestamp | None = None,
    retention_class: RetentionClass = RetentionClass.HOT,
    retention: RetentionEngine | None = None,
) -> CertificationSeal:
    """Seal one certification's evidence into a persisted chain and manifest.

    Delegates every part of the sealing to plan 12's machinery — this function
    decides *what* is attested and nothing else. The chain is verified and the
    manifest is verified **before** anything is written, so a chain that does not
    hold leaves no row behind to be mistaken for evidence.

    Args:
        store: The migrated store.
        facts: The attempt's own facts plus the bundle its record will cite.
        recorded_at: The reading to stamp the events with (tests inject one).
        retention_class: The class the retention ladder will enforce for this
            evidence. ``HOT`` by default: a certification claim is meant to be
            re-earned, not kept forever.
        retention: When supplied, the sealed manifest is registered with this
            engine, so its bytes enter the retention ladder and a deletion has to
            come through :func:`expire_certification_evidence`.

    Returns:
        The sealed chain, its manifest, and both verdicts.

    Raises:
        AttestationError: If the derived chain or the manifest fails verification.
            Nothing is written.
        InvariantViolationError: From the evidence boundary inside the plan 12
            writers, if a derived document carries a secret-classified field or a
            value this run resolved.
    """
    reading = _reading(utc_now(), recorded_at)
    events = seal_events(certification_events(facts, recorded_at=reading))
    chain_id = certification_chain_id(facts.bundle.bundle_hash)
    manifest = build_manifest(
        events,
        manifest_id=certification_manifest_id(facts.bundle.bundle_hash),
        run_id=chain_id,
        signer_identity="",
        trust_root_ref="",
        retention_class=retention_class,
        created_at=reading,
        previous_manifest_digest=GENESIS_DIGEST,
    )

    chain_verification = verify_chain(events)
    if not chain_verification.valid:
        raise AttestationError(
            f"refusing to seal an invalid certification chain for "
            f"{facts.fault_id}@{facts.cell_label}: {'; '.join(chain_verification.errors)}"
        )
    manifest_verification = verify_manifest(manifest, events)
    if not manifest_verification.valid:
        raise AttestationError(
            f"refusing to seal an invalid certification manifest for "
            f"{facts.fault_id}@{facts.cell_label}: "
            f"{'; '.join(manifest_verification.errors)}"
        )

    repository = AttestationRepository(store)
    repository.save_chain(chain_id, events, sealed_at=reading.wall_clock)
    repository.save_manifest(manifest)
    if retention is not None:
        retention.register(manifest, now=reading.wall_clock)
    return CertificationSeal(
        bundle_hash=facts.bundle.bundle_hash,
        chain_id=chain_id,
        manifest=manifest,
        manifest_id=manifest.manifest_id,
        events=events,
        chain_verification=chain_verification,
        manifest_verification=manifest_verification,
    )


# ── verification ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CertificationEvidenceVerdict:
    """Whether a bundle's sealed evidence supports the claim it is cited for.

    ``verified`` answers the integrity question — is there a chain, does it
    verify, and does it describe this bundle's digests. The two recovery
    questions are separate members on purpose: a chain can be perfectly intact
    and still record a residue scan that was never performed or a recovery probe
    that never came home. Only :attr:`grants_runtime_verification` answers "may
    this support a live claim", and it requires all three.
    """

    bundle_hash: str
    manifest_id: str
    verified: bool
    errors: tuple[str, ...] = ()
    residue_clean: bool = False
    recovery_verified: bool = False
    demotions: tuple[str, ...] = ()

    @property
    def grants_runtime_verification(self) -> bool:
        """The conjunction a ``runtime_verified`` claim has to satisfy."""
        return self.verified and self.residue_clean and self.recovery_verified

    def describe(self) -> str:
        if self.grants_runtime_verification:
            return f"{self.bundle_hash[:12]}…: sealed evidence verifies"
        reasons = "; ".join(self.errors) or (
            f"residue {'clean' if self.residue_clean else 'unverified'}, "
            f"recovery {'verified' if self.recovery_verified else 'unverified'}"
        )
        return f"{self.bundle_hash[:12]}…: {reasons}"


def _first_recorded_event(events: tuple[AttestedEvent, ...]) -> AttestedEvent | None:
    return next((event for event in events if event.event_kind == CHAIN_EVENT_RECORDED), None)


def _recovery_verified(payload: Mapping[str, object]) -> bool:
    """Whether the recorded recovery facts satisfy the recovery obligation.

    Two branches, from the chain's own ``recovery_required`` flag rather than
    from anything the caller asserts now:

    * required — a probe must be present, its undo must have run, and its drift
      must be inside the recorded tolerance;
    * not required — the fault is irreversible, so the obligation is instead that
      the run left no unrecovered lease behind.
    """
    compensated = bool(payload.get("compensated"))
    if not bool(payload.get("recovery_required")):
        return compensated
    raw = payload.get("recovery")
    if not isinstance(raw, dict):
        return False
    try:
        baseline = float(raw["baseline"])
        observed = float(raw["observed"])
        tolerance = float(raw["tolerance"])
    except (KeyError, TypeError, ValueError):
        return False
    return bool(raw.get("undo_ran")) and abs(observed - baseline) <= tolerance


def _residue_clean(payload: Mapping[str, object]) -> bool:
    """Whether the recorded residue scan was performed and found nothing.

    ``clean`` is taken from ``performed and not findings`` rather than from a
    stored flag, so a chain that claims a clean scan without having performed one
    cannot pass by asserting the flag.
    """
    residue = payload.get("residue")
    if not isinstance(residue, dict):
        return False
    performed = bool(residue.get("performed"))
    findings = residue.get("findings")
    return performed and isinstance(findings, list) and not findings


def verify_bundle_evidence(
    store: Store,
    bundle_hash: str,
    *,
    digests: Mapping[str, str] | None = None,
) -> CertificationEvidenceVerdict:
    """Re-verify one bundle's sealed certification evidence from stored bytes.

    Four independent things are checked, and all four failures are reported:

    * the manifest and the chain exist and both verify with the domain verifier,
      with the stored ``chain_root`` cross-checked against the recomputed one;
    * the chain contains a ``certification.recorded`` event — a chain of
      something else is not evidence for this claim;
    * that event names this ``bundle_hash`` and, when ``digests`` is supplied,
      carries exactly the digests the record cites;
    * the recorded residue scan was performed and clean, and recovery verifies.
    """
    manifest_id = certification_manifest_id(bundle_hash)
    chain_id = certification_chain_id(bundle_hash)
    repository = AttestationRepository(store)
    errors: list[str] = []

    if repository.load_manifest(manifest_id) is None:
        return CertificationEvidenceVerdict(
            bundle_hash=bundle_hash,
            manifest_id=manifest_id,
            verified=False,
            errors=(
                f"no sealed certification evidence is stored for bundle {bundle_hash[:12]}… "
                f"(manifest {manifest_id!r}); a bundle nothing has verified cannot support a "
                "live claim",
            ),
        )

    chain_verification = repository.verify_run_chain(chain_id)
    errors.extend(chain_verification.errors)
    manifest_verification = repository.verify_stored_manifest(manifest_id)
    errors.extend(manifest_verification.errors)
    events = repository.load_chain(chain_id)

    recorded = _first_recorded_event(events)
    if recorded is None:
        errors.append(
            f"the chain for {bundle_hash[:12]}… carries no {CHAIN_EVENT_RECORDED!r} event, so it "
            "attests to something other than this certification"
        )
        return CertificationEvidenceVerdict(
            bundle_hash=bundle_hash,
            manifest_id=manifest_id,
            verified=False,
            errors=tuple(errors),
        )

    payload = recorded.payload
    if str(payload.get("bundle_hash", "")) != bundle_hash:
        errors.append(
            f"the sealed chain names bundle {str(payload.get('bundle_hash', ''))[:12]}… but was "
            f"looked up as {bundle_hash[:12]}…"
        )
    if digests is not None:
        recorded_digests = payload.get("digests")
        claimed = dict(digests)
        if not isinstance(recorded_digests, dict) or dict(recorded_digests) != claimed:
            errors.append(
                "the sealed chain carries content digests that differ from the ones the record "
                "cites, so the evidence describes a different run than the claim"
            )
    if not any(event.event_kind == CHAIN_EVENT_SEALED for event in events):
        errors.append(
            f"the chain for {bundle_hash[:12]}… has no {CHAIN_EVENT_SEALED!r} event: it does not "
            "close its own claim"
        )

    demotions = tuple(
        f"{event.payload.get('fault_id', '')}@{event.payload.get('previous_sequence', '')}"
        for event in events
        if event.event_kind == CHAIN_EVENT_DEMOTED
    )
    integrity_ok = not errors
    return CertificationEvidenceVerdict(
        bundle_hash=bundle_hash,
        manifest_id=manifest_id,
        verified=integrity_ok,
        errors=tuple(errors),
        residue_clean=_residue_clean(payload),
        recovery_verified=_recovery_verified(payload),
        demotions=demotions,
    )


def verify_record_evidence(
    store: Store,
    record: CertificationRecord,
    *,
    reference: EvidenceBundleRef | None = None,
) -> CertificationEvidenceVerdict:
    """Re-verify the evidence one stored record cites.

    Uses the record's first evidence reference unless ``reference`` names
    another. A record with no evidence at all cannot be verified by construction
    — Phase 1 refuses to build a certified one — and a ``pending`` record that
    cites nothing is reported as unverified rather than raising, so a caller can
    sweep a whole store without special-casing the refusals.
    """
    ref = reference if reference is not None else (record.evidence[0] if record.evidence else None)
    if ref is None:
        return CertificationEvidenceVerdict(
            bundle_hash="",
            manifest_id="",
            verified=False,
            errors=(f"{record.label} cites no evidence bundle, so there is nothing to verify",),
        )
    return verify_bundle_evidence(store, ref.bundle_hash, digests=ref.digests)


def _withdrawn(
    record: CertificationRecord,
    verdict: CertificationEvidenceVerdict,
) -> CertificationRecord:
    """The same record, withdrawn: a ``failed`` claim naming why.

    Rebuilt through :func:`~mayhem.domain.certification.mark_failed` so the
    withdrawal is a legal transition with a recorded reason rather than a state
    patched onto the object.
    """
    detail = "; ".join(verdict.errors) or (
        f"residue {'clean' if verdict.residue_clean else 'not clean'}, "
        f"recovery {'verified' if verdict.recovery_verified else 'not verified'}"
    )
    return mark_failed(record, reason=f"{_UNVERIFIED_REASON}: {detail}")


def sealed_certification_gate(
    repository: CertificationRepository,
    store: Store,
    *,
    now: datetime | None = None,
) -> Mapping[str, tuple[CertificationRecord, ...]]:
    """The record store, with every unverifiable live claim withdrawn.

    Same shape :meth:`~mayhem.infra.certification_repository.CertificationRepository`
    ``.certification_gate`` returns and
    :func:`mayhem.infra.promotion.evaluate_maturity` consumes, so this is a
    drop-in for it: age every record as that method does, then for each record
    that would otherwise grant live verification re-verify its sealed evidence
    and hand on the **withdrawn** copy when it does not verify.

    Withdrawing rather than dropping is deliberate. Dropping would also stop the
    level being reported, but it would erase the record from the mapping and
    leave a reader unable to tell "never certified" from "certified and since
    lost its evidence". A ``failed`` record says the second thing, which is the
    one that is true.
    """
    aged = repository.certification_gate(now=now)
    gate: dict[str, tuple[CertificationRecord, ...]] = {}
    for fault_id, records in aged.items():
        kept: list[CertificationRecord] = []
        for record in records:
            if not record.grants_live_verification:
                kept.append(record)
                continue
            verdict = verify_record_evidence(store, record)
            kept.append(
                record if verdict.grants_runtime_verification else _withdrawn(record, verdict)
            )
        gate[fault_id] = tuple(kept)
    return gate


# ── retention interaction ────────────────────────────────────────────────────


def certification_evidence_dependents(
    repository: CertificationRepository,
    store: Store,
    *,
    manifest_id: str,
    now: datetime | None = None,
) -> tuple[StoredCertification, ...]:
    """Stored rows whose *live* claim cites the evidence behind ``manifest_id``.

    "Live" is evaluated with the domain's own ageing, so an already-lapsed claim
    does not hold evidence hostage — a stale claim protects nothing, and treating
    it as though it did would make the ladder unusable for exactly the faults
    most worth retaining evidence for.
    """
    bundle_hash = bundle_hash_for_manifest(store, manifest_id)
    if not bundle_hash:
        return ()
    moment = now or utc_now()
    live = []
    for stored in repository.records_citing_bundle(bundle_hash):
        if expire_by_time(stored.record, now=moment).grants_live_verification:
            live.append(stored)
    return tuple(live)


def demote_certifications_losing_evidence(
    repository: CertificationRepository,
    store: Store,
    *,
    manifest_id: str,
    now: datetime | None = None,
    reason: str = "",
) -> tuple[StoredCertification, ...]:
    """Withdraw every live claim citing ``manifest_id``'s evidence.

    The demotion-first path, and also the recovery path for evidence that
    disappeared without going through retention. Each claim is moved to
    ``failed`` with a reason naming the manifest, so the row itself says why it
    stopped granting a level rather than going quiet.
    """
    moment = now or utc_now()
    withdrawn: list[StoredCertification] = []
    for stored in certification_evidence_dependents(
        repository, store, manifest_id=manifest_id, now=moment
    ):
        why = reason or (
            f"{_DELETED_EVIDENCE_REASON}: manifest {manifest_id!r} was deleted"
        )
        withdrawn.append(
            repository.store_transition(
                stored, mark_failed(stored.record, reason=why), now=moment
            )
        )
    return tuple(withdrawn)


def expire_certification_evidence(
    engine: RetentionEngine,
    repository: CertificationRepository,
    store: Store,
    *,
    manifest_id: str,
    requester: str,
    approver: str,
    reason: str = "",
    now: datetime | None = None,
    demote_dependents: bool = False,
) -> RetentionTombstone:
    """Delete retained certification evidence, holding it while a claim needs it.

    The refusal is the default and the reason is in the module docstring: a
    certification that quietly lost its evidence would keep reporting a level, so
    the deletion is refused with the dependents named and the two remedies
    offered. ``demote_dependents=True`` is the deliberate second path — the claim
    is withdrawn in place, through the repository's own transition, *before* the
    bytes are deleted, so there is no window in which a record is demoted and its
    evidence is not yet gone.

    Everything else — dual control, the legal hold, the external copy, the
    tombstone — is still
    :meth:`~mayhem.infra.retention.RetentionEngine.expire`'s job. This adds one
    gate in front of it and does not weaken any of the others.

    Args:
        engine: The retention engine that performs the deletion.
        repository: The record store holding the dependent claims.
        store: The store the evidence lives in.
        manifest_id: The manifest whose evidence is to be deleted.
        requester: The person requesting deletion.
        approver: A *different* named person approving it.
        reason: Recorded on the tombstone and on every withdrawal.
        now: The instant to evaluate expiry against.
        demote_dependents: Withdraw the dependent claims instead of refusing.

    Returns:
        The tombstone :meth:`RetentionEngine.expire` wrote.

    Raises:
        CertificationEvidenceHeldError: If a live claim cites the evidence and
            ``demote_dependents`` is ``False``. Nothing was changed.
        RetentionRefusedError: If dual control is absent or policy blocks the
            deletion, from the retention engine.
        RetentionBackendUnavailableError: From the retention engine, if the
            external store is missing or refuses. The local record survives.
    """
    moment = now or utc_now()
    dependents = certification_evidence_dependents(
        repository, store, manifest_id=manifest_id, now=moment
    )
    if dependents and not demote_dependents:
        listed = ", ".join(stored.record.label for stored in dependents)
        raise CertificationEvidenceHeldError(
            f"deleting evidence for manifest {manifest_id!r} refused: "
            f"{len(dependents)} live certification(s) cite it ({listed}). Evidence a live "
            "claim rests on cannot be deleted while that claim stands — it would keep "
            "reporting a level with nothing behind it. Withdraw the claim first, or pass "
            "demote_dependents=True to withdraw it here, before the bytes go."
        )
    if dependents:
        demote_certifications_losing_evidence(
            repository,
            store,
            manifest_id=manifest_id,
            now=moment,
            reason=(
                f"{_DELETED_EVIDENCE_REASON}: manifest {manifest_id!r} was deleted "
                f"(requested by {requester}, approved by {approver})"
            ),
        )
    return engine.expire(
        manifest_id,
        requester=requester,
        approver=approver,
        reason=reason,
        now=moment,
    )


def reconcile_certification_evidence(
    repository: CertificationRepository,
    store: Store,
    *,
    now: datetime | None = None,
) -> tuple[StoredCertification, ...]:
    """Withdraw every live claim whose sealed evidence no longer verifies.

    The sweep for evidence that went away without passing through retention: an
    attestation row removed by hand, a bundle directory cleaned out, a database
    restored from an older snapshot. :func:`expire_certification_evidence` stops
    the *sanctioned* deletion; this catches the rest, so a claim can never outlive
    the evidence it is checked against.

    Returns the rows it withdrew, so a caller can log or re-seal them.
    """
    moment = now or utc_now()
    withdrawn: list[StoredCertification] = []
    for stored in repository.live_records(now=moment):
        verdict = verify_record_evidence(store, stored.record)
        if verdict.grants_runtime_verification:
            continue
        withdrawn.append(
            repository.store_transition(stored, _withdrawn(stored.record, verdict), now=moment)
        )
    return tuple(withdrawn)


# ── the store the runner is handed ───────────────────────────────────────────


class CertificationEvidenceStore:
    """Seals, verifies, and guards the evidence a certification cites.

    This is the object :mod:`mayhem.infra.certification_runner` is handed as its
    ``EvidenceSealer``: it satisfies that protocol's
    :meth:`~mayhem.infra.certification_runner.EvidenceSealer.seal_evidence`, and
    the richer :func:`seal_certification_evidence` remains available directly for
    a caller that wants the manifest and both verdicts back.
    """

    def __init__(
        self,
        store: Store,
        *,
        repository: CertificationRepository | None = None,
        retention: RetentionEngine | None = None,
        retention_class: RetentionClass = RetentionClass.HOT,
    ) -> None:
        self._store = store
        self._repository = (
            repository if repository is not None else CertificationRepository(store)
        )
        self._retention = retention
        self._retention_class = retention_class

    @property
    def repository(self) -> CertificationRepository:
        return self._repository

    def seal_evidence(
        self,
        *,
        bundle: EvidenceBundleRef,
        request: CertificationRequest,
        cell: MatrixCell,
        injector_version: str,
        run: CertifiedRun,
        residue: ResidueScan,
        recovery: RecoveryEvidence | None,
        demotions: tuple[DemotionEvent, ...] = (),
        now: datetime,
    ) -> EvidenceSealReceipt:
        """Seal the attempt's evidence, including its residue scan and demotions.

        The sealer is the last thing between a run and a live claim: whatever it
        returns, the runner treats as the truth about whether those bytes are
        sealed, so it verifies before persisting and reports the verdict rather
        than assuming success.
        """
        del now  # the seal is stamped when it happens, not when the run started
        facts = CertificationFacts(
            bundle=bundle,
            fault_id=request.fault_id,
            cell_label=cell.label,
            cell_fingerprint=cell.fingerprint,
            injector_version=injector_version,
            run_id=run.run_id,
            residue=residue,
            recovery=recovery,
            recovery_required=requires_recovery_verification(
                definition_for(request.fault_id)
            ),
            compensated=not run.dirty_leases,
            demotions=demotions,
        )
        seal = seal_certification_evidence(
            self._store,
            facts,
            retention_class=self._retention_class,
            retention=self._retention,
        )
        return EvidenceSealReceipt(
            bundle_hash=seal.bundle_hash,
            manifest_id=seal.manifest_id,
            chain_root=seal.chain_root,
            verified=seal.verified,
        )

    def verify(self, record: CertificationRecord) -> CertificationEvidenceVerdict:
        """Re-verify one stored record's sealed evidence."""
        return verify_record_evidence(self._store, record)

    def gate(self, *, now: datetime | None = None) -> Mapping[str, tuple[CertificationRecord, ...]]:
        """The promotion-ready mapping, with unverifiable live claims withdrawn."""
        return sealed_certification_gate(self._repository, self._store, now=now)
