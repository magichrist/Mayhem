"""Phase 4 of docs/v1.1.0/30_SAFETY_PROOF.md — sealing, residue discharge, and
approval binding, as one verifiable chain.

Phase 2 compiled the proof. Phases 1 to 3 made it a type, a gate, and an artifact a
human can read. None of that makes it *evidence*. This module is the part that
does, and it is three things welded together because each is worthless without
the other two:

1. **The proof is sealed pre-execution.** Not "hashed somewhere" — hashed into
   the same hash-chained, manifest-committed attestation chain plan 12 already
   builds, by the same functions, through the same
   :class:`~mayhem.infra.attestation_store.AttestationRepository`. See
   `Why there is no second sealer` below.
2. **Residue obligations are discharged post-run, line by line.** The plan-01
   residue-scan definitions become the scan this module asks for, and each
   fault's obligation moves through
   :meth:`~mayhem.domain.safety_proof.ResidueObligation.discharge`. Found
   residue **voids** its line, and a run with an open obligation cannot close
   clean — see :func:`discharge_residue` and :meth:`ResidueDischarge.closes_clean`.
3. **Approvals bind to the sealed proof's digest.** An approval minted against
   a *different* proof is refused at admission, which closes the plan-09 loop:
   the thing that was approved is byte-identical to the thing that was sealed
   and to the thing that ran.

Why there is no second sealer
-----------------------------

The obvious implementation — a bespoke ``proof_sealed`` table, or a private
chain root computed here — is exactly what this module refuses to do, for two
reasons that are load-bearing rather than stylistic.

**The withdrawal gate.** ``tests/unit/test_withdrawal_asset.py`` restricts which
modules may invoke the evidence-bundle producer, and why: a second producer is
how a project ends up with two bundles that disagree. Sealing has the identical
failure mode, and this module is subject to the same rule — the gate checks for
the mention as well as the call, so even naming the function here would read as
a producer. So this module *reuses* :func:`~mayhem.domain.attestation.seal_events`
and :func:`~mayhem.domain.attestation.build_manifest` and persists through
:class:`~mayhem.infra.attestation_store.AttestationRepository` — the same
domain functions, the same M0023 tables, the same unsigned-manifest honesty
gate, and the same offline verifier a plan-12 auditor already runs. There is no
second hashing rule to keep in step and no second format to write a reader for.

**One chain per run.** ``domain.attestation``'s verifier defines a chain as
starting at genesis, so an event chain cannot be hung off another chain's root.
The attestation store is explicit that runs therefore link at the *manifest*
layer, through ``Manifest.previous_manifest_digest`` — and this module honours
that rather than inventing a cross-chain link the domain verifier would reject.
The proof seal is its own chain (one chain per run, sealed pre-execution); the
run-close seal is the run's own chain; the two are linked by the caller passing
the proof manifest's digest as ``previous_manifest_digest``. :func:`seal_proof`
takes that argument and refuses a signer for the same reason
:func:`~mayhem.infra.attestation_store.seal_run_evidence` does: naming a signer
on a manifest that carries no signature bytes would turn "integrity verified"
into "authorship verified", which is precisely the overclaim plan 12 removes.

What Phase 4 deliberately does not claim
----------------------------------------

* **Nothing here wires the executor.** ``seal_proof`` and
  :func:`seal_and_discharge` are seams a run-close path calls; like
  :func:`~mayhem.infra.attestation_store.seal_run_evidence`, which plan 12
  Phase 2 also left unwired, they are written to be read and reviewed.
* **A clean residue scan is not a guarantee that nothing is wrong.** It is a
  statement that six named predicates were observed on the cell that reported
  them. The predicates are enumerated in :data:`SCANNED_RESIDUE_PREDICATES`
  precisely so a reader can see the boundary.
* **The seal does not authorise anything.** It says "this exact proof, with this
  exact verdict, existed before the run started". Whether the run was allowed
  is the gate's question; what the seal guarantees is that the artifact the
  approver signed is the artifact the run carried.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    RetentionClass,
    build_manifest,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.hashing import digest as digest_of
from mayhem.domain.safety_proof import (
    Obligation,
    ObligationStatus,
    ProofVerdict,
    ResidueObligation,
    ResiduePredicate,
    ResidueScan,
    SafetyProof,
)
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationError,
    AttestationRepository,
    SigningNotImplementedError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from mayhem.domain.approval import Approval
    from mayhem.domain.attestation import (
        ChainVerification,
        Manifest,
        ManifestVerification,
    )
    from mayhem.infra.store import Store

#: The event kind a sealed proof contributes to its chain. Named here rather than
#: imported because ``attestation_store`` owns the *run-close* event kinds
#: (``evidence.recorded`` / ``run.closed``); the proof's is a different fact at a
#: different moment in the run, and inventing it inside that module would make
#: that module the owner of a chain it never builds.
EVENT_PROOF_SEALED = "proof.sealed"

#: The attestation scope a proof seal is stored under, derived from the run.
#:
#: A chain is keyed by this string in ``attestation_chains.run_id``, which is a
#: primary key — so the proof's chain and the run-close chain are keyed
#: differently and cannot overwrite one another. The manifest is built with the
#: same id, and the two manifests are linked at the manifest layer by
#: ``previous_manifest_digest`` (the module docstring).
PROOF_ATTESTATION_SCOPE = ":proof"


class ProofSealingError(DomainError):
    """A proof could not be sealed, discharged, or bound as requested."""


def proof_scope(run_id: str) -> str:
    """The attestation scope ``run_id``'s proof seal is stored under."""
    if not run_id.strip():
        msg = "a proof seal needs a non-blank run id to name its attestation scope"
        raise InvariantViolationError("proof_sealing.blank_run_id", msg)
    return f"{run_id}{PROOF_ATTESTATION_SCOPE}"


# --------------------------------------------------------------------------- #
# Residue: the plan-01 scan definitions, narrowed to predicates
# --------------------------------------------------------------------------- #


class ResidueScanner(Protocol):
    """Whatever can answer "did this fault leave anything behind?".

    A Protocol rather than a concrete class because the observation has to come
    from somewhere real — a container the run mutated — and no controller
    module may shell out or hold an engine handle. The live implementations
    are :meth:`mayhem.cli.certify.EngineCell.residue_scan` (in-container
    probes) and whatever the promotion engine can observe; both already answer
    in the plan-01 vocabulary this module reads.

    The contract that matters is :meth:`residue_scan` returning ``scanned=False``
    when it could not look. "I did not look" is a real answer and it is the
    answer that keeps a run from closing clean.
    """

    def residue_scan(self) -> ScanOutcome: ...


#: The plan-01 residue classes, and which proof predicate each discharges.
#:
#: :data:`mayhem.infra.certification_runner.RESIDUE_KINDS` names five:
#: ``tc_rule``, ``iptables_entry``, ``marker_process``, ``marker_file``,
#: ``cgroup_override``. The proof asserts six (gap 65 adds ``no_leases_held``).
#: The table below is the join, and it is data rather than prose so a test can
#: assert the two vocabularies have not drifted apart — a residue class the
#: proof cannot name would be a class it cannot check, which is the whole
#: failure gap 65 exists to close.
RESIDUE_PREDICATE_FOR_KIND: dict[str, str] = {
    "tc_rule": "no_tc_rules",
    "iptables_entry": "no_iptables_entries",
    "marker_process": "no_marker_processes",
    "marker_file": "no_files",
    "cgroup_override": "no_cgroup_overrides",
}

#: The predicate the plan-01 *lease* half discharges. A lease in any state other
#: than a safe terminal is residue, and it is the one predicate no shell probe
#: can observe — it lives in the store, not on the cell.
LEASE_RESIDUE_PREDICATE = "no_leases_held"

#: Lease states that count as "no residue held". Taken from
#: :data:`mayhem.domain.leases.LeaseState`'s own safe terminals rather than
#: restated, so a new terminal state cannot silently become residue.
SAFE_LEASE_STATES: frozenset[str] = frozenset({"released", "expired"})


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    """What one residue scan observed, including *not having looked*.

    Mirrors the plan-01 scan shape (``performed`` / ``findings``) so an existing
    cell scanner can be adapted by returning this instead of reimplementing the
    observation. ``performed=False`` with an empty ``kinds`` tuple is the case
    that matters: an empty finding list from a scan that never ran is
    indistinguishable from a clean cell to any consumer that forgets to check,
    so "not checked" is its own value here and a run may not close on it.
    """

    performed: bool = False
    kinds: tuple[str, ...] = ()
    detail: str = ""
    #: Lease states the run left behind, for the ``no_leases_held`` predicate.
    #: Empty means "no lease was observed at all", which is *not* clean — a
    #: fault that never acquired a lease has nothing to release, and the
    #: predicate is discharged by the run's own lease record, not by absence.
    lease_states: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return self.performed and not self.kinds and not self.dirty_leases

    @property
    def dirty_leases(self) -> tuple[str, ...]:
        return tuple(state for state in self.lease_states if state not in SAFE_LEASE_STATES)

    def render(self) -> str:
        if not self.performed:
            return f"residue scan not performed{': ' + self.detail if self.detail else ''}"
        parts = [f"residue: {', '.join(self.kinds)}" if self.kinds else "residue clean"]
        if self.dirty_leases:
            parts.append(f"leases not safe: {', '.join(self.dirty_leases)}")
        return "; ".join(parts)


def scan_outcome_from_certification_scan(
    *,
    performed: bool,
    findings: Iterable[tuple[str, str]],
    lease_states: Sequence[str] = (),
    detail: str = "",
) -> ScanOutcome:
    """Adapt a plan-01 style ``(performed, findings)`` scan into a :class:`ScanOutcome`.

    The adapter exists so the live cell scanner
    (:meth:`mayhem.cli.certify.EngineCell.residue_scan`) keeps its own shape and
    this module does not grow a second definition of "what a residue finding is".
    A finding whose ``kind`` is not in :data:`RESIDUE_PREDICATE_FOR_KIND` is
    **kept** under its own name and reported as unrecognised rather than
    dropped: residue the proof cannot name must not become residue the proof
    does not report.
    """
    kinds: list[str] = []
    unrecognised: list[str] = []
    for kind, _detail in findings:
        if kind in RESIDUE_PREDICATE_FOR_KIND:
            if kind not in kinds:
                kinds.append(kind)
        elif kind not in unrecognised:
            unrecognised.append(kind)
    note = detail
    if unrecognised:
        suffix = f"unrecognised residue kind(s): {', '.join(unrecognised)}"
        note = f"{note}; {suffix}" if note else suffix
    return ScanOutcome(
        performed=performed,
        kinds=tuple(kinds),
        detail=note,
        lease_states=tuple(lease_states),
    )


def dirty_predicates(outcome: ScanOutcome) -> tuple[str, ...]:
    """The :class:`~mayhem.domain.safety_proof.ResiduePredicate` values a scan dirtied.

    Pure mapping over the plan-01 vocabulary. A lease outside a safe terminal
    dirties ``no_leases_held`` — that is the predicate the store's lease record
    discharges and no shell probe can.
    """
    predicates: list[str] = []
    for kind in outcome.kinds:
        predicate = RESIDUE_PREDICATE_FOR_KIND[kind]
        if predicate not in predicates:
            predicates.append(predicate)
    if outcome.dirty_leases and LEASE_RESIDUE_PREDICATE not in predicates:
        predicates.append(LEASE_RESIDUE_PREDICATE)
    return tuple(predicates)


#: Every predicate the scan vocabulary can reach, as the proof spells it.
SCANNED_RESIDUE_PREDICATES: frozenset[str] = frozenset(RESIDUE_PREDICATE_FOR_KIND.values()) | {
    LEASE_RESIDUE_PREDICATE
}


def residue_scan_for(fault_id: str, outcome: ScanOutcome) -> ResidueScan:
    """The :class:`~mayhem.domain.safety_proof.ResidueScan` a :class:`ScanOutcome` states.

    The scan's ``gate_digest`` is taken over the *observation* — what the cell
    reported — rather than over the predicates derived from it, so an auditor
    recomputes it from the scan output and not from this module's mapping. An
    unperformed scan still gets a digest (over the record that nothing was
    observed), because a ``FAIL`` line is a finding about the run and findings
    are cited too.

    The predicates go in at construction rather than being patched in
    afterwards: :class:`~mayhem.domain.safety_proof.ResidueScan` is frozen *and*
    refuses a scan that found residue without citing a digest, so both have to
    be true at once and a ``model_copy`` would skip the check that enforces it.
    """
    return ResidueScan(
        fault_id=fault_id,
        scanned=outcome.performed,
        dirty_predicates=tuple(ResiduePredicate(p) for p in dirty_predicates(outcome)),
        gate_digest=digest_of(
            {
                "source": "residue_scan_for",
                "fault_id": fault_id,
                "performed": outcome.performed,
                "kinds": list(outcome.kinds),
                "lease_states": list(outcome.lease_states),
                "detail": outcome.detail,
            }
        ),
        evidence_ref=f"residue-scan/{fault_id}",
    )


# --------------------------------------------------------------------------- #
# Residue discharge
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ResidueDischarge:
    """The post-run verdict on every fault's residue obligation, and whether the run may close.

    ``proof`` is the original proof with each residue line advanced by what its
    scan observed. ``dirty_faults`` names the faults whose line the scan voided;
    ``unscanned_faults`` names those nobody looked at. :meth:`closes_clean` is
    the single predicate a run-close path needs, and it is deliberately a
    conjunction: a found residue voids the proof, and an unchecked obligation
    fails it. There is no third reading where "I did not look" means "clean".
    """

    proof: SafetyProof
    discharges: tuple[tuple[str, ObligationStatus], ...]
    dirty_faults: tuple[str, ...]
    unscanned_faults: tuple[str, ...]

    @property
    def closes_clean(self) -> bool:
        """True only when every residue line passed *and* every one was checked."""
        return not self.dirty_faults and not self.unscanned_faults

    @property
    def open_faults(self) -> tuple[str, ...]:
        """Faults whose residue obligation is not ``PASS``, open in either sense."""
        return tuple(
            fault for fault, status in self.discharges if status is not ObligationStatus.PASS
        )

    def describe(self) -> str:
        if not self.discharges:
            return "no residue obligations to discharge"
        rows = ", ".join(f"{fault}={status.value}" for fault, status in self.discharges)
        if self.dirty_faults:
            return f"residue found: {rows}; the run cannot close clean"
        if self.unscanned_faults:
            return f"residue unchecked: {rows}; the run cannot close clean"
        return f"residue clean on every asserted predicate: {rows}"


def discharge_residue(
    proof: SafetyProof,
    outcomes: dict[str, ScanOutcome],
) -> ResidueDischarge:
    """Discharge every residue obligation on ``proof`` from the observed scans.

    Line by line, through
    :meth:`~mayhem.domain.safety_proof.ResidueObligation.discharge` — the
    domain's own transition, not a reimplementation of it. Three outcomes
    survive into :meth:`ResidueDischarge.closes_clean`:

    * residue found on an asserted predicate -> the line goes ``VOID`` and the
      fault is named dirty;
    * the scan never ran -> the line goes ``FAIL`` and the fault is named
      unscanned;
    * observed clean on every predicate -> ``PASS``.

    A fault with **no** scan in ``outcomes`` is treated as unscanned rather than
    assumed clean, which is the whole point: a caller that forgets a fault gets
    the fail-closed answer, not a pass.

    Raises:
        ProofSealingError: If ``outcomes`` carries a fault the proof does not
            assert an obligation for. That is a scan of something the proof does
            not cover, and silently ignoring it would lose a finding.
    """
    obligations = {obligation.fault_id: obligation for obligation in proof.residue_obligations}
    unknown = sorted(set(outcomes) - set(obligations))
    if unknown:
        msg = (
            f"residue scan(s) supplied for fault(s) the proof asserts no residue obligation "
            f"for: {', '.join(unknown)}; a scan of something the proof does not cover cannot "
            f"discharge anything and must not be dropped"
        )
        raise ProofSealingError(msg)

    advanced: list[ResidueObligation] = []
    discharges: list[tuple[str, ObligationStatus]] = []
    dirty: list[str] = []
    unscanned: list[str] = []
    for fault_id, obligation in obligations.items():
        outcome = outcomes.get(fault_id, ScanOutcome(detail="no scan supplied for this fault"))
        discharged = obligation.discharge(residue_scan_for(fault_id, outcome))
        advanced.append(discharged)
        discharges.append((fault_id, discharged.status))
        if discharged.status is ObligationStatus.VOID:
            dirty.append(fault_id)
        elif discharged.status is ObligationStatus.FAIL:
            unscanned.append(fault_id)

    rebuilt = proof_with_residue(proof, tuple(advanced))
    return ResidueDischarge(
        proof=rebuilt,
        discharges=tuple(discharges),
        dirty_faults=tuple(dirty),
        unscanned_faults=tuple(unscanned),
    )


def proof_with_residue(
    proof: SafetyProof,
    residue: Sequence[ResidueObligation],
) -> SafetyProof:
    """``proof`` with its residue lines replaced, verdict re-derived from scratch.

    The verdict is recomputed rather than adjusted. That is what makes the
    invariant structural: a proof whose residue line is ``VOID`` cannot be
    reassembled as ``PASS``, because
    :meth:`~mayhem.domain.safety_proof.SafetyProof.recompute_verdict` puts
    ``VOID`` above ``FAIL`` above ``PASS`` and the model validator refuses any
    verdict stronger than the lines support. A found residue therefore *dirties
    the run* by construction rather than by a check somebody could forget.
    """
    replaced = {obligation.fault_id: obligation for obligation in residue}
    kept: list[Obligation | ResidueObligation] = []
    for obligation in proof.obligations:
        # Only a ``ResidueObligation`` carries ``fault_id``; the nine spine lines
        # are plain ``Obligation``s and pass through untouched.
        replacement = (
            replaced.get(obligation.fault_id) if isinstance(obligation, ResidueObligation) else None
        )
        kept.append(replacement if replacement is not None else obligation)
    provisional = SafetyProof(
        plan_digest=proof.plan_digest,
        obligations=tuple(kept),
        verdict=ProofVerdict.VOID,
        void_reason="provisional assembly",
    )
    implied = provisional.recompute_verdict()
    if implied is ProofVerdict.PASS:
        return SafetyProof(
            plan_digest=provisional.plan_digest,
            obligations=provisional.obligations,
            verdict=ProofVerdict.PASS,
            generated_at=proof.generated_at,
        )
    unproven = [o.name for o in provisional.obligations if o.status is not ObligationStatus.PASS]
    summary = (
        f"residue obligations not discharged: {', '.join(unproven)}"
        if residue
        else f"lines not established: {', '.join(unproven)}"
    )
    # ``void_reason`` is only legal on a VOID proof. A FAIL verdict is a finding
    # about the plan and its lines already carry the reason, so the summary
    # would be refused at construction — the domain rule, honoured here rather
    # than worked around.
    return SafetyProof(
        plan_digest=provisional.plan_digest,
        obligations=provisional.obligations,
        verdict=implied,
        void_reason=summary if implied is ProofVerdict.VOID else "",
        generated_at=proof.generated_at,
    )


# --------------------------------------------------------------------------- #
# Sealing
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class SealedProof:
    """A sealed proof plus the verdicts that prove the seal is real."""

    run_id: str
    scope: str
    proof: SafetyProof
    events: tuple[AttestedEvent, ...]
    manifest: Manifest
    signature_state: str
    signature_reason: str
    chain_verification: ChainVerification
    manifest_verification: ManifestVerification

    @property
    def proof_digest(self) -> str:
        """The digest an approval must bind to speak for this proof."""
        return self.proof.proof_digest

    @property
    def chain_root(self) -> str:
        return self.events[-1].chain_link if self.events else GENESIS_DIGEST

    @property
    def manifest_digest(self) -> str:
        """What a later manifest (the run-close seal) chains to."""
        return self.manifest.manifest_digest

    @property
    def signed(self) -> bool:
        """Always False — plan 12 Phase 2 signs nothing. See the module docstring."""
        return self.manifest.signed


def proof_seal_event(
    proof: SafetyProof,
    *,
    run_id: str,
    recorded_at: AttestedTimestamp,
    redaction_policy: str = "",
) -> AttestedEvent:
    """The one event a proof seal contributes, referencing the proof by digest.

    Pure, and *referencing* rather than copying: the payload names the proof's
    digest, plan digest, verdict, and per-line gate digests, so the chain attests
    "this proof, in this state, existed before the run" without becoming a second
    copy of the artifact. An auditor who wants the whole proof has the digest;
    an auditor who wants to know what was authorised has the verdict and the
    lines behind it.

    Every field inside :attr:`SafetyProof.proof_digest` is written, including
    ``generated_at`` and each line's ``evaluated_at``. That is not thoroughness
    for its own sake: the digest is taken over ``model_dump``, so omitting a
    timestamp would make the seal unreloadable — :func:`verify_sealed_proof`
    would reconstruct a different proof and refuse its own seal.
    """
    return AttestedEvent(
        event_id=f"{proof_scope(run_id)}:sealed",
        event_kind=EVENT_PROOF_SEALED,
        run_id=proof_scope(run_id),
        sequence=0,
        payload={
            "proof_digest": proof.proof_digest,
            "plan_digest": proof.plan_digest,
            "verdict": proof.verdict.value,
            "void_reason": proof.void_reason,
            "generated_at": proof.generated_at.isoformat(),
            "obligations": [
                {
                    "name": obligation.name,
                    "status": obligation.status.value,
                    "gate_digest": obligation.gate_digest,
                    "evidence_ref": obligation.evidence_ref,
                    "evaluated_at": obligation.evaluated_at.isoformat(),
                    "detail": obligation.detail,
                }
                for obligation in proof.obligations
            ],
        },
        recorded_at=recorded_at,
        redaction_policy=redaction_policy,
    )


def seal_proof(
    store: Store,
    proof: SafetyProof,
    *,
    run_id: str,
    recorded_at: AttestedTimestamp,
    retention_class: RetentionClass | None = None,
    manifest_id: str = "",
    previous_manifest_digest: str = GENESIS_DIGEST,
    signer: object | None = None,
) -> SealedProof:
    """Seal a compiled proof, pre-execution, into plan 12's existing chain machinery.

    The seam the run path calls between "the proof compiled" and "the first
    fault step runs". Every stage is plan 12's: :func:`seal_events` wires the
    links, :func:`build_manifest` commits to the event digests,
    :func:`verify_chain` and :func:`verify_manifest` check both before anything
    is written, and :class:`~mayhem.infra.attestation_store.AttestationRepository`
    persists into the same M0023 tables the run-close seal uses. Nothing is
    re-hashed here and no table is created.

    Args:
        store: The migrated store.
        proof: The compiled proof to seal. Any verdict is sealed — a sealed
            ``VOID`` proof is a true and useful record ("we compiled this and it
            did not hold"), and refusing it would lose the artifact.
        run_id: The run the proof belongs to.
        recorded_at: The reading to stamp the event with (tests inject one).
        retention_class: The class the retention engine will enforce; defaults to
            ``HOT``, matching the run-close seal.
        manifest_id: Defaults to ``<run_id>:proof:manifest``.
        previous_manifest_digest: The manifest this seal chains to. Pass the
            prior run's manifest digest to link runs; the default is genesis.
        signer: The Phase 6 signing seam. There is no implementation, and naming
            one is refused for the reason
            :func:`~mayhem.infra.attestation_store.seal_run_evidence` refuses it.

    Raises:
        SigningNotImplementedError: If a signer is supplied.
        AttestationError: If the derived chain or manifest fails verification, in
            which case nothing is written.
    """
    if signer is not None:
        raise SigningNotImplementedError(
            "plan 12 Phase 2 mints no signature bytes: no key material, KMS/HSM "
            "custody or Sigstore integration exists, so naming a signer would claim "
            "an authentication that was never performed. The manifest is written "
            f"unsigned and the reason is stored: {UNSIGNED_REASON_NO_SIGNING}"
        )
    scope = proof_scope(run_id)
    events = seal_events([proof_seal_event(proof, run_id=run_id, recorded_at=recorded_at)])
    manifest = build_manifest(
        events,
        manifest_id=manifest_id or f"{run_id}:proof:manifest",
        run_id=scope,
        signer_identity="",
        trust_root_ref="",
        retention_class=(retention_class if retention_class is not None else RetentionClass.HOT),
        created_at=recorded_at,
        previous_manifest_digest=previous_manifest_digest,
    )

    chain_verification = verify_chain(events)
    if not chain_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid proof chain for run {run_id!r}: "
            f"{'; '.join(chain_verification.errors)}"
        )
    manifest_verification = verify_manifest(manifest, events)
    if not manifest_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid proof manifest for run {run_id!r}: "
            f"{'; '.join(manifest_verification.errors)}"
        )

    repository = AttestationRepository(store)
    repository.save_chain(scope, events, sealed_at=recorded_at.wall_clock)
    repository.save_manifest(manifest)
    return SealedProof(
        run_id=run_id,
        scope=scope,
        proof=proof,
        events=events,
        manifest=manifest,
        signature_state=SIGNATURE_UNSIGNED_NO_SIGNING,
        signature_reason=UNSIGNED_REASON_NO_SIGNING,
        chain_verification=chain_verification,
        manifest_verification=manifest_verification,
    )


def verify_sealed_proof(store: Store, run_id: str) -> tuple[SafetyProof | None, str]:
    """Reload a sealed proof from the store and re-verify it, offline.

    Returns ``(proof, manifest_digest)``, or ``(None, reason)`` when nothing is
    stored or the stored bytes do not verify. The proof is reconstructed *from
    the stored event payload* and re-validated by :class:`SafetyProof`, so a
    payload edited behind the model's back fails construction rather than being
    believed — the same discipline
    :meth:`~mayhem.infra.attestation_store.AttestationRepository.verify_run_chain`
    applies to a chain row.

    This is also how a reader checks the stored manifest digest without a control
    plane, and hands it to a later seal as ``previous_manifest_digest``.
    """
    scope = proof_scope(run_id)
    repository = AttestationRepository(store)
    found = _verify_stored_seal(repository, scope, run_id)
    if isinstance(found, str):
        return None, found
    payload, manifest_digest = found
    try:
        proof = _proof_from_payload(payload)
    except (InvariantViolationError, ValueError, TypeError) as exc:
        return None, f"stored proof payload does not re-validate: {exc}"
    committed = str(payload.get("proof_digest", ""))
    if proof.proof_digest != committed:
        return None, (
            f"stored proof digest {proof.proof_digest[:12]} does not match the digest the "
            f"chain committed to {committed[:12]}"
        )
    return proof, manifest_digest


def _verify_stored_seal(
    repository: AttestationRepository,
    scope: str,
    run_id: str,
) -> tuple[dict[str, object], str] | str:
    """The stored proof payload and manifest digest, or the reason there is none.

    Split out of :func:`verify_sealed_proof` because these are four independent
    *store* checks and none of them is about the proof type — the payload is
    handed back unparsed so the caller can report a construction failure in the
    proof's own terms rather than in SQL's.
    """
    verification = repository.verify_run_chain(scope)
    if not verification.valid:
        return f"chain does not verify: {'; '.join(verification.errors)}"
    manifests = repository.list_manifests(scope)
    if not manifests:
        return f"no proof manifest stored for run {run_id!r}"
    manifest = manifests[-1]
    manifest_verification = verify_manifest(manifest, repository.load_chain(scope))
    if not manifest_verification.valid:
        return f"manifest does not verify: {'; '.join(manifest_verification.errors)}"
    sealed = [
        event for event in repository.load_chain(scope) if event.event_kind == EVENT_PROOF_SEALED
    ]
    if not sealed:
        return f"no {EVENT_PROOF_SEALED} event stored for run {run_id!r}"
    return sealed[0].payload, manifest.manifest_digest


def _proof_from_payload(payload: dict[str, object]) -> SafetyProof:
    """Rebuild a :class:`SafetyProof` from a sealed event payload.

    Every field inside :attr:`SafetyProof.proof_digest` is restored, including
    both timestamps. The verdict is *not* trusted: it is declared and then
    re-derived by the model validator from the reconstructed obligations, so a
    payload claiming ``PASS`` over a voided line is refused at construction
    rather than believed. Restoring ``detail`` is what makes the digest
    reproduce, and reproducing the digest is the point of the reload.
    """
    raw_lines = payload.get("obligations")
    if not isinstance(raw_lines, (list, tuple)):
        msg = (
            "sealed proof payload carries no obligation list; a seal with no lines "
            f"cannot be reloaded (payload keys: {sorted(payload)})"
        )
        raise InvariantViolationError("proof_sealing.bad_obligation_payload", msg)
    obligations: list[Obligation | ResidueObligation] = []
    for raw in raw_lines:
        if not isinstance(raw, dict):
            msg = f"sealed obligation payload is not a mapping: {raw!r}"
            raise InvariantViolationError("proof_sealing.bad_obligation_payload", msg)
        line = str(raw.get("name", ""))
        fields = {
            "status": str(raw.get("status", ObligationStatus.VOID.value)),
            "gate_digest": str(raw.get("gate_digest", "")),
            "evidence_ref": str(raw.get("evidence_ref", "")),
            "evaluated_at": _timestamp(raw.get("evaluated_at")),
            "detail": str(raw.get("detail", "")),
        }
        if line.startswith("residue:"):
            obligations.append(
                ResidueObligation.model_validate({"fault_id": line.split(":", 1)[1], **fields})
            )
            continue
        obligations.append(Obligation.model_validate({"name": line, **fields}))
    return SafetyProof(
        plan_digest=str(payload["plan_digest"]),
        obligations=tuple(obligations),
        verdict=ProofVerdict(str(payload.get("verdict", ProofVerdict.VOID.value))),
        void_reason=str(payload.get("void_reason", "")),
        generated_at=_timestamp(payload.get("generated_at")),
    )


def _timestamp(value: object) -> datetime:
    """Parse a sealed ISO-8601 stamp, refusing one that is not a timestamp.

    A malformed stamp has to fail loudly: defaulting it would produce a proof
    whose digest differs from the one on file, and the honest failure for that is
    "this seal does not reload", not a plausible-looking proof.
    """
    if isinstance(value, datetime):
        return value
    text = str(value or "")
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        msg = f"sealed proof timestamp {text!r} is not ISO-8601: {exc}"
        raise InvariantViolationError("proof_sealing.bad_timestamp", msg) from exc


# --------------------------------------------------------------------------- #
# Approval binding
# --------------------------------------------------------------------------- #


def verify_approval_binding(
    approvals: Sequence[Approval],
    proof: SafetyProof,
) -> tuple[str, ...]:
    """Approvals that do not speak for ``proof``, as reasons.

    Phase 4 closes the plan-09 loop. An approval binds four digests; the one
    this function enforces is ``proof_digest``, and it enforces it by comparing
    against :attr:`~mayhem.domain.safety_proof.SafetyProof.proof_digest` — a
    single comparison, deliberately *not*
    :meth:`~mayhem.domain.approval.Approval.speaks_for`, which also compares the
    plan and policy digests. Those two are the gate's business (see
    :func:`~mayhem.domain.approval.evaluate_approvals`); the proof digest is the
    proof's, and this is the one check that answers "is this approval bound to
    *the sealed proof*".

    An approval bound to a stale proof is refused here rather than silently
    counted. The gate would also discard it (it raises
    ``PROOF_DIGEST_MISMATCH``), but the gate compares against whatever proof the
    caller handed it; comparing against the *sealed* artifact is what makes the
    binding durable.
    """
    proof_digest = proof.proof_digest
    return tuple(
        f"{approval.approval_id} is bound to proof {approval.proof_digest[:12]}, "
        f"not the sealed proof {proof_digest[:12]}"
        for approval in approvals
        if approval.proof_digest != proof_digest
    )


def require_approval_binding(approvals: Sequence[Approval], proof: SafetyProof) -> None:
    """Refuse the whole set if any approval names a different proof.

    Strictly stronger than :func:`verify_approval_binding` returning reasons,
    and deliberately so: a quorum met by other approvers with one stale token
    attached is an authorized run with a stale record, which
    :func:`~mayhem.domain.approval.evaluate_approvals` allows on purpose. For a
    *sealed* proof the stale token is a different question — it says somebody
    approved a proof that is not the one on file — and the honest answer is to
    refuse rather than bury it in the discarded list.

    Raises:
        ProofSealingError: If any approval's ``proof_digest`` differs.
    """
    unbound = verify_approval_binding(approvals, proof)
    if unbound:
        msg = (
            "an approval is bound to a different proof than the sealed one; "
            f"{'; '.join(unbound)}. Re-approve against the sealed proof digest "
            f"{proof.proof_digest[:12]}"
        )
        raise ProofSealingError(msg)


# --------------------------------------------------------------------------- #
# The whole chain
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class SealedAndDischargedRun:
    """One run's sealed proof, its residue discharge, and the verdict they agree on.

    The three facts the plan asks to be one verifiable chain, held together so a
    reader cannot read one of them without the other two. :meth:`closes_clean`
    is the answer to "may this run close", and it is false whenever the residue
    did not discharge clean *or* the proof was sealed over a plan that has since
    moved — a chain whose plan digest no longer matches is not a chain about this
    run any more.
    """

    sealed: SealedProof
    discharge: ResidueDischarge
    plan_digest: str

    @property
    def proof(self) -> SafetyProof:
        """The proof *after* discharge — what the run actually closed on."""
        return self.discharge.proof

    @property
    def verdict(self) -> ProofVerdict:
        return self.discharge.proof.verdict

    @property
    def closes_clean(self) -> bool:
        return self.discharge.closes_clean and self.discharge.proof.is_valid(self.plan_digest)

    def describe(self) -> str:
        return (
            f"run {self.sealed.run_id}: sealed proof {self.sealed.proof_digest[:12]} "
            f"(manifest {self.sealed.manifest_digest[:12]}, chain {self.sealed.chain_root[:12]}, "
            f"{self.sealed.signature_state}); {self.discharge.describe()}; verdict "
            f"{self.verdict.value}; closes clean: {self.closes_clean}"
        )


def seal_and_discharge(
    store: Store,
    proof: SafetyProof,
    *,
    run_id: str,
    recorded_at: AttestedTimestamp,
    outcomes: dict[str, ScanOutcome],
    plan_digest: str,
    retention_class: RetentionClass | None = None,
    manifest_id: str = "",
    previous_manifest_digest: str = GENESIS_DIGEST,
    signer: object | None = None,
) -> SealedAndDischargedRun:
    """Seal the proof, discharge its residue lines, and hold the two together.

    The end-to-end shape plan 30 Phase 4 asks for. The seal happens on the
    *pre-execution* proof (which is what an approver signs and what the run
    carries), and the discharge is applied to the sealed copy afterwards, so the
    chain records the admission case and the residue case as two facts about one
    artifact rather than two artifacts that happen to share a digest.

    ``plan_digest`` is the plan frozen *now*, supplied separately from
    ``proof.plan_digest`` precisely so a superseded plan yields
    :attr:`SealedAndDischargedRun.closes_clean` ``False`` rather than an old
    pass read as a current one.
    """
    sealed = seal_proof(
        store,
        proof,
        run_id=run_id,
        recorded_at=recorded_at,
        retention_class=retention_class,
        manifest_id=manifest_id,
        previous_manifest_digest=previous_manifest_digest,
        signer=signer,
    )
    discharge = discharge_residue(sealed.proof, outcomes)
    return SealedAndDischargedRun(
        sealed=sealed,
        discharge=discharge,
        plan_digest=plan_digest,
    )


__all__ = [
    "EVENT_PROOF_SEALED",
    "LEASE_RESIDUE_PREDICATE",
    "PROOF_ATTESTATION_SCOPE",
    "RESIDUE_PREDICATE_FOR_KIND",
    "SAFE_LEASE_STATES",
    "SCANNED_RESIDUE_PREDICATES",
    "ProofSealingError",
    "ResidueDischarge",
    "ResidueScanner",
    "ScanOutcome",
    "SealedAndDischargedRun",
    "SealedProof",
    "dirty_predicates",
    "discharge_residue",
    "proof_scope",
    "proof_seal_event",
    "proof_with_residue",
    "require_approval_binding",
    "residue_scan_for",
    "seal_and_discharge",
    "seal_proof",
    "verify_approval_binding",
    "verify_sealed_proof",
]
