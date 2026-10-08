"""Durable persistence for attestation chains and manifests (plan 12, Phase 2).

Phase 1 (:mod:`mayhem.domain.attestation`) made the rules pure: canonical
bytes, digests, chain links, manifests, and an offline verifier. This module is
the IO half. It *derives* attested events from an already-written
:class:`~mayhem.domain.evidence.EvidenceEnvelope`, hashes them into a chain,
builds the manifest, and writes both to SQLite behind the M0023 migration, so a
verifier months later can reload the rows and re-verify with no control plane.

What this module does NOT do
----------------------------

* **It does not sign.** Phase 2 mints no signature bytes, holds no key material,
  and has no KMS/HSM or Sigstore custody. Every manifest written here is
  *unsigned*, and the store records **why** in
  ``attestation_manifests.signature_state`` / ``signature_reason`` rather than
  leaving the absence silent. :func:`seal_run_evidence` refuses a signer
  outright (:class:`SigningNotImplementedError`): naming a signer on a manifest that
  carries no signature would turn "integrity verified" into "authorship
  verified", which is precisely the overclaim plan 12 exists to remove.
* **It is not a second bundle producer.** Nothing here assembles a portable
  bundle, writes artifact directories, or re-implements the manifest hashing
  rules of :mod:`mayhem.domain.evidence_bundle`. Attested events *reference* the
  evidence envelope by digest and key fields; the portable bundle stays the one
  container it already is, built by the one function that already builds it.
* **It is not wired into the executor.** :func:`seal_run_evidence` is the seam
  the run-close path calls once Phase 3 wires it; the controller is unchanged
  here. Phase 4 confirms that verdict rather than revisiting it: the call site is
  ``cli/lifecycle._write_evidence_after_run`` immediately after
  ``write_evidence(store, envelope)`` — the first place the store, the redacted
  envelope, and the run result all exist. The executor never builds an
  ``EvidenceEnvelope`` (the type does not appear in ``controller/executor.py`` at
  all), so sealing there would require a *second* envelope producer, which is the
  duplication this module exists to avoid. Requirement 3's "additive or
  documented" branch is the documented one:
  :func:`mayhem.infra.audit_stream.seal_run_evidence_at_run_close` is the single
  call that lane makes, and its docstring carries the exact call site.
* **Phase 4 scope: authorization and completeness.** :class:`RunAuthorization`
  and :func:`chain_completeness` are the only things added here, and both are
  additive: a call that passes no authorization seals exactly the chain Phase 2
  sealed. What changed is that a *mutating* run's chain now has to say **why**
  it was allowed — see :func:`chain_completeness` for the fail-closed rule and
  :data:`MUTATING_ACTION_OUTCOMES` for how "mutating" is decided (from the
  envelope's own recorded facts, never from a caller asserting it).

Honesty rules inherited from Phase 1
------------------------------------

* Every write is one transaction (repo convention, ADR-0007): a chain row and
  all of its events land together or not at all.
* No foreign key to ``runs``. Gap 101 exists because evidence must survive the
  control plane deleting the run it describes, so an attestation that cascaded
  away with its run would defeat the point.
* Re-verification is the domain verifier's job, never a re-implemented check:
  :meth:`AttestationRepository.verify_run_chain` reloads the stored bytes and
  calls :func:`~mayhem.domain.attestation.verify_chain`, then additionally
  checks the stored root against the recomputed one.
* **One chain per run.** Phase 1's verifier defines a chain as starting at
    genesis, so an event chain cannot be hung off a previous run's root without
    changing the domain's law. Runs are linked at the *manifest* layer instead
    (``Manifest.previous_manifest_digest``, which the manifest digest covers).
    The cross-run event stream is :mod:`mayhem.infra.audit_stream`, and it is
    still the *same* ``AttestedEvent`` format verified by the *same*
    :func:`~mayhem.domain.attestation.verify_chain` — not a second logger.

What this IS inside
-------------------

An attestation row is evidence. It is persisted, it is exported (a chain plus its
manifest is what an auditor or an offline verifier is handed), and it is covered
by the retention and audit machinery — :mod:`mayhem.infra.retention` reads these
manifests to apply legal holds and expiry, and archives their bytes to external
storage. So plan 12's "secrets must never enter evidence" binds this module
exactly as it binds the envelope row, a sealed bundle, or an audit entry.

Every write path therefore calls
:func:`~mayhem.infra.secret_resolver.require_persistable_document`: the
``AttestedEvent`` rows :meth:`AttestationRepository.save_chain` persists, the
``Manifest`` row :meth:`AttestationRepository.save_manifest` persists, and
:func:`seal_run_evidence` — which gates the whole derived document before its
first transaction opens, so a refusal leaves neither a chain nor a manifest. The
gate is the same one, with the same two rules, in the same placement
:mod:`mayhem.infra.audit_stream` chose: after sealing, before the transaction
opens, on the document the column actually receives. There is no
attestation-specific rule, no attestation-specific guard, and no opt-out
parameter, and no writer here takes a ``guard=`` or reads configuration.

The practical exposure before that was small, and the reason is worth recording
so nobody overstates what the gate adds: the derived events *reference* the
envelope by digest rather than embedding it, so most of what
:func:`seal_run_evidence` persists is already-boundary content by the time it
gets here. What is genuinely free-form is the authorization payload — the
approver and rule strings a caller supplies — and the event ``payload`` dict of
any chain written through :meth:`AttestationRepository.save_chain` directly.
That is exactly what the byte rule is for: neither surface carries a key name a
name-based rule could grade.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from mayhem.domain.attestation import (
    ATTESTATION_SCHEMA_VERSION,
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    ChainVerification,
    Manifest,
    ManifestVerification,
    RetentionClass,
    build_manifest,
    chain_root,
    content_digest,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.infra.secret_resolver import require_persistable_document

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mayhem.domain.approval import ApprovalState
    from mayhem.domain.evidence import EvidenceEnvelope
    from mayhem.domain.policy import PolicyDecision
    from mayhem.infra.store import Store

#: The only ``signature_state`` this phase can write. Read it as "integrity is
#: sealed; authorship is not claimed". Phase 6 adds the signed states.
SIGNATURE_UNSIGNED_NO_SIGNING = "unsigned_no_signing"

#: Why every Phase 2 manifest is unsigned. Stored verbatim, so a reader who finds
#: an unsigned manifest in the database is told the reason rather than left to
#: guess whether an absence is a bug or a phase boundary.
UNSIGNED_REASON_NO_SIGNING = (
    "plan 12 Phase 2 implements sealing and retention only: no key material, no "
    "KMS/HSM custody and no Sigstore integration exist, so no signature bytes were "
    "minted. This manifest attests integrity, not authorship."
)

#: Event kinds emitted at run close, in chain order.
EVENT_EVIDENCE_RECORDED = "evidence.recorded"
EVENT_POLICY_DECIDED = "policy.decided"
EVENT_APPROVAL_EVALUATED = "approval.evaluated"
EVENT_RUN_CLOSED = "run.closed"

#: Phase 4: the event kinds a *mutating* run's chain must carry for a later
#: reader to be able to reconstruct why it was allowed. Named as a tuple so the
#: completeness check and its tests cannot disagree about the list.
REQUIRED_AUTHORIZATION_KINDS: tuple[str, ...] = (EVENT_POLICY_DECIDED, EVENT_APPROVAL_EVALUATED)

#: A digest field is a lowercase sha256 hex string and nothing looser — the same
#: rule and regex ``domain/approval.py``, ``domain/policy.py`` and
#: ``controller/approval_gate.py`` already use. A chain input that cannot name a
#: digest did not name an artifact.
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

#: The action outcomes that mean the run changed something. Derived from the
#: envelope's own recorded ``action_outcomes`` — never from a caller asserting
#: that the run "was" mutating. See :func:`is_mutating_run`.
MUTATING_ACTION_OUTCOMES: frozenset[str] = frozenset(
    {"applied", "compensated", "acknowledged_no_backend"}
)

#: The ``artifact`` label the evidence boundary reports under for this module.
#:
#: Named per write path, for the reason :mod:`mayhem.infra.audit_stream` names
#: its own: an operator reading a refusal has to be able to tell *which* write
#: path refused, and ``attestation:chain:r-1`` answers that where a bare
#: "evidence" would not. The three suffixes are the three writers.
ATTESTATION_ARTIFACT_PREFIX = "attestation:"


def _seal_artifact(run_id: str) -> str:
    """The boundary label for :func:`seal_run_evidence`."""
    return f"{ATTESTATION_ARTIFACT_PREFIX}seal:{run_id}"


def _chain_artifact(run_id: str) -> str:
    """The boundary label for :meth:`AttestationRepository.save_chain`."""
    return f"{ATTESTATION_ARTIFACT_PREFIX}chain:{run_id}"


def _manifest_artifact(manifest_id: str) -> str:
    """The boundary label for :meth:`AttestationRepository.save_manifest`."""
    return f"{ATTESTATION_ARTIFACT_PREFIX}manifest:{manifest_id}"


class AttestationError(DomainError):
    """Attestation derivation or persistence refused a request."""


class SigningNotImplementedError(AttestationError):
    """A caller tried to name a signer; Phase 2 can only write unsigned manifests."""


class EvidenceNotAttestableError(AttestationError):
    """The evidence envelope cannot be sealed — e.g. it carries no redaction marker."""


class AuthorizationMismatchError(AttestationError):
    """The supplied authorization does not describe the plan it is being sealed against.

    The negative control for "an approval is a statement about an *exact* plan"
    (:mod:`mayhem.domain.approval`). Raised rather than recorded, because a chain
    that carried an approval for a different plan would answer "why was this run
    allowed?" with a lie.
    """


class AttestationSigner(Protocol):
    """The signing seam. **No implementation of this protocol is shipped.**

    It exists so the *shape* of Phase 6 custody is decided now, and so the
    refusal in :func:`seal_run_evidence` guards a real interface rather than a
    hypothetical one. Satisfying it means holding key material and producing
    signature bytes, which is Phase 6 work.
    """

    identity: str
    trust_root_ref: str


# --------------------------------------------------------------------------- #
# Authorization (Phase 4)                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RunAuthorization:
    """The policy decision and approval state that authorized one run.

    Phase 4's addition, and the answer to "reconstruct WHY the run was allowed".
    Two artifacts, not one, because they answer different questions and only
    together close the gap:

    * :class:`~mayhem.domain.policy.PolicyDecision` — *was this shape of action
      permitted at all*, under which bundle version, over which facts. Carries
      its own ``policy_digest`` (the bundle) and ``rule_digest`` (the resolved
      rule set), so a reader can name both the policy version and the rules that
      spoke.
    * :class:`~mayhem.domain.approval.ApprovalState` — *did named people approve
      this exact plan under this exact policy and proof*, and if not, every
      reason why not. Carries no digest of its own, so this module computes one
      over its canonical bytes via :func:`~mayhem.domain.attestation.content_digest`
      — Phase 1's canonicalization, not a second convention.

    Both are *referenced by digest and summarised*, never copied wholesale. The
    domain objects stay where they were minted; the chain names them, so a later
    reader can go and get the whole thing.

    ``plan_digest`` is the pin both artifacts are checked against. It is compared
    against ``envelope.plan_hash`` at seal time and refused on mismatch — see
    :class:`AuthorizationMismatchError`.
    """

    policy_decision: PolicyDecision
    approval_state: ApprovalState
    plan_digest: str
    #: Optional proof digest the approval bound, when the caller has one. Recorded
    #: in the payload when supplied; not required, because
    #: :class:`~mayhem.domain.approval.ApprovalState` does not carry one itself.
    proof_digest: str = ""

    def __post_init__(self) -> None:
        """Validate the digests this record will assert.

        Raises:
            AuthorizationMismatchError: If ``plan_digest`` or ``proof_digest`` is
                not a lowercase sha256 hex digest. A chain input that cannot name
                a digest did not name an artifact.
        """
        for name, value in (("plan_digest", self.plan_digest), ("proof_digest", self.proof_digest)):
            if value and not _SHA256_HEX.fullmatch(value):
                raise AuthorizationMismatchError(
                    f"run authorization {name} must be a lowercase 64-char sha256 hex "
                    f"digest or empty, got {value!r}"
                )

    def approval_state_digest(self) -> str:
        """Digest of the approval state over Phase 1's canonical bytes.

        Computed here rather than in :mod:`mayhem.domain.approval` because that
        module mints no digest for a bare :class:`ApprovalState` and is not ours
        to change. The canonicalizer is the same one every other chain input uses.
        """
        return content_digest(self.approval_state.model_dump(mode="json"))

    def payload(self) -> dict[str, object]:
        """The attested summary of both artifacts — what a reader gets back.

        Digests plus the fields an operator actually asks for (the outcome, the
        matched rule ids, the approvers, the refusal reasons). Deliberately not
        the full ``model_dump``: the chain is not a second copy of the artifacts,
        it is a signed-by-digest reference to them.
        """
        decision = self.policy_decision
        state = self.approval_state
        return {
            "plan_digest": self.plan_digest,
            "policy_digest": decision.policy_digest,
            "rule_digest": decision.rule_digest,
            "facts_digest": decision.facts_digest,
            "decision_digest": decision.decision_digest(),
            "policy_outcome": decision.outcome,
            "policy_bundle": decision.describe(),
            "policy_matched_rules": list(decision.matched_rules),
            "policy_reasons": list(decision.reasons),
            "approval_state_digest": self.approval_state_digest(),
            "approval_proof_digest": self.proof_digest,
            "approval_valid": state.valid,
            "approval_approvers": list(state.approvers),
            "approval_required": state.required,
            "approval_reasons": [reason.value for reason in state.reasons],
            "approval_detail": list(state.detail),
            "approval_describe": state.describe(),
        }


def is_mutating_run(envelope: EvidenceEnvelope) -> bool:
    """Whether this run actually changed something, from the envelope's own record.

    Derived, never asserted: a caller cannot declare its own run non-mutating to
    dodge the completeness rule. Two signals, either sufficient:

    * any recorded ``action_outcome`` in :data:`MUTATING_ACTION_OUTCOMES` — the
      envelope records what each step did, and "applied" means it happened;
    * a recorded ``execution_intent`` — v0.9.0 makes execution an approved act,
      so an intent on the envelope is a statement that this was a real action.

    A read-only run (checks, probes, simulation) records neither and is not
    required to carry authorization: it changed nothing, so there is nothing to
    justify. The distinction is recorded *in the chain* as the ``mutating`` key of
    the evidence event, so a later reader does not have to re-derive it from an
    envelope that may since have been redacted.
    """
    if any(outcome in MUTATING_ACTION_OUTCOMES for outcome in envelope.action_outcomes):
        return True
    return envelope.execution_intent is not None


@dataclass(frozen=True, slots=True)
class SealedRun:
    """What sealing a run produced, plus the verdicts that prove it."""

    run_id: str
    events: tuple[AttestedEvent, ...]
    manifest: Manifest
    signature_state: str
    signature_reason: str
    chain_verification: ChainVerification
    manifest_verification: ManifestVerification
    completeness: ChainCompleteness | None = None

    @property
    def chain_root(self) -> str:
        """The root the manifest commits to."""
        return chain_root(self.events)

    @property
    def signed(self) -> bool:
        """Always False in Phase 2. Present so callers cannot assume otherwise."""
        return self.manifest.signed

    @property
    def complete(self) -> bool:
        """Whether the chain carries the authorization this run needs (Phase 4).

        ``True`` when :attr:`completeness` says so, and ``True`` when there is no
        verdict at all — an older seal, or one made before Phase 4 existed. The
        absence of a verdict is not a pass, so callers that care should read
        :attr:`completeness` and treat ``None`` as "not assessed".
        """
        return True if self.completeness is None else self.completeness.complete


def _iso(value: datetime | str | None) -> str:
    """ISO-8601 text for a datetime or an already-formatted stamp."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return value


# --------------------------------------------------------------------------- #
# Event derivation                                                             #
# --------------------------------------------------------------------------- #


def _redaction_policy(envelope: EvidenceEnvelope) -> str:
    """The redaction policy version the envelope was written under.

    Raises:
        EvidenceNotAttestableError: If the envelope carries no redaction marker. Plan
            12's privacy rule is "secrets must never enter evidence", and an
            unmarked envelope is one whose contents were never screened.
    """
    policy = str(envelope.redaction_metrics.get("policy_version", "") or "")
    if not policy:
        raise EvidenceNotAttestableError(
            f"evidence for run {envelope.run_id!r} carries no redaction marker "
            "(redaction_metrics.policy_version is empty); sealing unmarked evidence "
            "would attest bytes nobody screened for secrets"
        )
    return policy


def _event(
    *,
    event_id: str,
    event_kind: str,
    run_id: str,
    sequence: int,
    payload: dict[str, object],
    recorded_at: AttestedTimestamp,
    redaction_policy: str = "",
) -> AttestedEvent:
    """One unsealed event; :func:`seal_events` computes its digest and link."""
    return AttestedEvent(
        event_id=event_id,
        event_kind=event_kind,
        run_id=run_id,
        sequence=sequence,
        payload=payload,
        recorded_at=recorded_at,
        redaction_policy=redaction_policy,
    )


def run_close_events(
    envelope: EvidenceEnvelope,
    *,
    run_status: str,
    verdict: str,
    recorded_at: AttestedTimestamp,
    authorization: RunAuthorization | None = None,
) -> tuple[AttestedEvent, ...]:
    """The events a run close attests to, in chain order (pure).

    Always at least two events, and they *reference* the envelope rather than
    copying it: the first records which evidence this chain is about (by digest,
    plan hash, redaction policy, and whether the run mutated anything), the last
    records the run's outcome. The evidence stays exactly where the bundle
    producer put it — this chain never becomes a second copy of it.

    With ``authorization`` supplied, two more events are inserted *between* those
    two, in this order: :data:`EVENT_POLICY_DECIDED` then
    :data:`EVENT_APPROVAL_EVALUATED`. Both carry the digests of the artifacts
    that authorized the run (:meth:`RunAuthorization.payload`), so a reader months
    later can reconstruct *why* the run was allowed without re-running the gates
    and hoping the inputs still agree — which is the whole point of sealing the
    decision rather than only the outcome.

    The events are conditional but the *rule* is not: a mutating run with no
    authorization seals a chain that
    :func:`~mayhem.infra.audit_stream.verify_audit_chain` and
    :func:`chain_completeness` report as incomplete. It is not refused here,
    because a run's evidence must survive even when the evidence about how it was
    authorized is missing — an incomplete-but-honest chain is worth more than no
    chain, and the seal is what makes the gap visible.

    An incomplete envelope is sealed, not refused: an aborted run legitimately
    has no verdict, and its ``completeness_errors`` travel in the payload so an
    auditor sees the gap instead of a confident-looking empty field.

    Raises:
        EvidenceNotAttestableError: If the envelope carries no redaction marker.
    """
    policy = _redaction_policy(envelope)
    evidence_digest = content_digest(envelope.to_dict())
    events: list[AttestedEvent] = [
        _event(
            event_id=f"{envelope.run_id}:evidence",
            event_kind=EVENT_EVIDENCE_RECORDED,
            run_id=envelope.run_id,
            sequence=0,
            payload={
                "evidence_digest": evidence_digest,
                "plan_hash": envelope.plan_hash,
                "report_id": envelope.report_id,
                "evidence_status": envelope.evidence_status,
                "evidence_created_at": envelope.created_at,
                "redacted_path_count": int(
                    envelope.redaction_metrics.get("redacted_path_count", 0) or 0
                ),
                "completeness_errors": envelope.completeness_errors(),
                # Recorded, not re-derived later: whether the run mutated is a
                # fact about this chain, and a reader must not have to trust a
                # possibly-redacted envelope to learn it.
                "mutating": is_mutating_run(envelope),
            },
            recorded_at=recorded_at,
            redaction_policy=policy,
        )
    ]
    if authorization is not None:
        events.append(
            _event(
                event_id=f"{envelope.run_id}:policy",
                event_kind=EVENT_POLICY_DECIDED,
                run_id=envelope.run_id,
                sequence=len(events),
                payload=authorization.payload(),
                recorded_at=recorded_at,
                redaction_policy=policy,
            )
        )
        events.append(
            _event(
                event_id=f"{envelope.run_id}:approval",
                event_kind=EVENT_APPROVAL_EVALUATED,
                run_id=envelope.run_id,
                sequence=len(events),
                payload=authorization.payload(),
                recorded_at=recorded_at,
                redaction_policy=policy,
            )
        )
    events.append(
        _event(
            event_id=f"{envelope.run_id}:closure",
            event_kind=EVENT_RUN_CLOSED,
            run_id=envelope.run_id,
            sequence=len(events),
            payload={
                "evidence_digest": evidence_digest,
                "run_status": run_status,
                "verdict": verdict,
                "recovery_state": envelope.recovery_state,
                "compensation_status": envelope.compensation_status,
                "remediation": list(envelope.remediation),
            },
            recorded_at=recorded_at,
            redaction_policy=policy,
        )
    )
    return tuple(events)


# --------------------------------------------------------------------------- #
# Completeness (Phase 4)                                                        #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ChainCompleteness:
    """Whether a run's chain carries the authorization a mutating run needs.

    ``complete`` is the one field to read. It is ``True`` for a read-only run and
    for a mutating run that carries both authorization events — and ``False``,
    with the missing kinds named, for a mutating run that carries fewer.

    The asymmetry is the point. A chain that verifies *integrity* but is missing
    its authorization is not clean, and this type is what says so: integrity is
    :func:`~mayhem.domain.attestation.verify_chain`'s question, completeness is
    this one, and neither answers for the other.
    """

    run_id: str
    mutating: bool
    complete: bool
    present: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    plan_digest: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "mutating": self.mutating,
            "complete": self.complete,
            "present": list(self.present),
            "missing": list(self.missing),
            "errors": list(self.errors),
            "plan_digest": self.plan_digest,
        }

    def describe(self) -> str:
        if not self.mutating:
            return f"{self.run_id}: read-only run; no authorization required"
        if self.complete:
            return f"{self.run_id}: complete ({', '.join(self.present)})"
        return f"{self.run_id}: INCOMPLETE — missing {', '.join(self.missing)}"


def _first_evidence_event(events: Sequence[AttestedEvent]) -> AttestedEvent | None:
    return next((e for e in events if e.event_kind == EVENT_EVIDENCE_RECORDED), None)


def chain_completeness(
    events: Sequence[AttestedEvent],
    *,
    mutating: bool | None = None,
) -> ChainCompleteness:
    """Does this chain carry the authorization a mutating run must have? (pure).

    Args:
        events: The chain's events, in order.
        mutating: Override the recorded fact. ``None`` (the default) reads the
            ``mutating`` key the evidence event recorded, and falls back to
            ``True`` when that key is absent — a chain written before this key
            existed, or one whose evidence event is missing entirely, is treated
            as mutating, because assuming a run changed nothing is exactly the
            overclaim this check exists to prevent.

    Returns:
        A :class:`ChainCompleteness` naming what is present and what is missing.
    """
    evidence_event = _first_evidence_event(events)
    run_id = events[0].run_id if events else ""
    if mutating is None:
        recorded = evidence_event.payload.get("mutating") if evidence_event else None
        mutating = True if recorded is None else bool(recorded)

    present = tuple(
        kind
        for kind in REQUIRED_AUTHORIZATION_KINDS
        if any(event.event_kind == kind for event in events)
    )
    plan_digest = str(events[0].payload.get("plan_digest", "")) if events else ""
    for event in events:
        if event.event_kind in REQUIRED_AUTHORIZATION_KINDS:
            plan_digest = str(event.payload.get("plan_digest", "")) or plan_digest
            break

    errors: list[str] = []
    if not mutating:
        # A read-only run changed nothing, so there is nothing to justify. Not
        # a pass on the authorization — an explicit "not applicable".
        return ChainCompleteness(
            run_id=run_id,
            mutating=False,
            complete=True,
            present=present,
            plan_digest=plan_digest,
            errors=("read-only run: no policy or approval artifact is required",),
        )

    missing = tuple(kind for kind in REQUIRED_AUTHORIZATION_KINDS if kind not in present)
    for kind in missing:
        errors.append(
            f"run {run_id!r} is recorded as mutating but its chain carries no {kind!r} "
            "event, so it cannot say why it was allowed"
        )
    if not missing:
        errors.append(f"run {run_id!r} carries its authorization artifacts; the chain is complete")
    return ChainCompleteness(
        run_id=run_id,
        mutating=True,
        complete=not missing,
        present=present,
        missing=missing,
        errors=tuple(errors),
        plan_digest=plan_digest,
    )


def _recorded_at(recorded_at: AttestedTimestamp | None) -> AttestedTimestamp:
    """The caller's reading, or a fresh wall-clock + monotonic pair.

    The monotonic half comes from :func:`time.monotonic_ns` rather than the wall
    clock, so a host whose clock steps mid-run still orders these events correctly
    (gap 98). The uncertainty bound is 0 because a local reading is measured, not
    estimated — which is a claim about *this* host's clock, not a synchronised one.
    """
    if recorded_at is not None:
        return recorded_at
    return AttestedTimestamp(
        wall_clock=utc_now(),
        monotonic_ns=time.monotonic_ns(),
        uncertainty_ms=0.0,
        source="system",
    )


# --------------------------------------------------------------------------- #
# Sealing                                                                      #
# --------------------------------------------------------------------------- #


def seal_run_evidence(
    store: Store,
    envelope: EvidenceEnvelope,
    *,
    run_status: str,
    verdict: str,
    retention_class: RetentionClass = RetentionClass.HOT,
    manifest_id: str = "",
    previous_manifest_digest: str = GENESIS_DIGEST,
    recorded_at: AttestedTimestamp | None = None,
    created_at: AttestedTimestamp | None = None,
    signer: AttestationSigner | None = None,
    authorization: RunAuthorization | None = None,
) -> SealedRun:
    """Seal a closed run's evidence into a persisted chain and manifest.

    Call this at run close with the values the run-close path just computed:
    ``run_status`` is ``completed``/``aborted``/``failed`` and ``verdict`` is the
    criteria-derived verdict (empty when the run never reached one).

    Args:
        store: The migrated store.
        envelope: The written, redacted evidence envelope for the run.
        run_status: Run status at close.
        verdict: Criteria-derived verdict at close, or ``""``.
        retention_class: The class the retention engine will enforce (gap 57).
        manifest_id: Manifest identifier; defaults to ``<run_id>:manifest``.
        previous_manifest_digest: Prior manifest root, for a manifest chain.
        recorded_at: The reading to stamp the events with (tests inject one).
        created_at: The manifest's creation reading (defaults to ``recorded_at``).
        signer: The Phase 6 signing seam. Phase 2 has no implementation.
        authorization: The policy decision and approval state that authorized
            this run (Phase 4). Additive: omit it and the chain is exactly the one
            Phase 2 sealed. Supply it and two events carrying the artifacts'
            digests are inserted into the chain.

    Returns:
        The sealed chain, the manifest, and both verification verdicts.

    Raises:
        SigningNotImplementedError: If a signer is supplied. Phase 2 signs nothing.
        EvidenceNotAttestableError: If the envelope has no redaction marker.
        AuthorizationMismatchError: If the authorization's ``plan_digest`` is
            non-empty and does not match the envelope's ``plan_hash``.
        InvariantViolationError: From the evidence boundary, if the derived chain
            or manifest carries a secret-classified field or a value this run
            resolved. Nothing is written at all — neither the chain nor the
            manifest.
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

    # The negative control for "an approval is a statement about an exact plan".
    # Refused here, at the only point where both values are in hand, rather than
    # recorded: a chain that named an approval for a different plan would answer
    # "why was this allowed?" with a confident lie.
    if (
        authorization is not None
        and authorization.plan_digest
        and authorization.plan_digest != envelope.plan_hash
    ):
        raise AuthorizationMismatchError(
            f"refusing to seal run {envelope.run_id!r}: the supplied authorization "
            f"binds plan digest {authorization.plan_digest[:12]} but the evidence "
            f"envelope describes plan hash {envelope.plan_hash[:12]}; an approval "
            "for one plan does not authorize another"
        )

    reading = _recorded_at(recorded_at)
    events = seal_events(
        run_close_events(
            envelope,
            run_status=run_status,
            verdict=verdict,
            recorded_at=reading,
            authorization=authorization,
        ),
    )
    manifest = build_manifest(
        events,
        manifest_id=manifest_id or f"{envelope.run_id}:manifest",
        run_id=envelope.run_id,
        signer_identity="",
        trust_root_ref="",
        retention_class=retention_class,
        created_at=created_at or reading,
        previous_manifest_digest=previous_manifest_digest,
    )

    chain_verification = verify_chain(events)
    if not chain_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid chain for run {envelope.run_id!r}: "
            f"{'; '.join(chain_verification.errors)}"
        )
    manifest_verification = verify_manifest(manifest, events)
    if not manifest_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid manifest for run {envelope.run_id!r}: "
            f"{'; '.join(manifest_verification.errors)}"
        )
    completeness = chain_completeness(events)

    # The evidence boundary, after sealing and before the first transaction opens.
    # Gating here rather than only in the two repository writers below is what makes
    # "nothing is written" true of the whole call: the chain and the manifest are two
    # transactions, so a repository-level refusal could still leave a chain with no
    # manifest. The document is the one the two columns receive — the sealed events
    # and the manifest, as the writers serialise them.
    require_persistable_document(
        {
            "events": [event.model_dump(mode="json") for event in events],
            "manifest": manifest.model_dump(mode="json"),
        },
        artifact=_seal_artifact(envelope.run_id),
    )

    repository = AttestationRepository(store)
    repository.save_chain(envelope.run_id, events, sealed_at=reading.wall_clock)
    repository.save_manifest(manifest)
    return SealedRun(
        run_id=envelope.run_id,
        events=events,
        manifest=manifest,
        signature_state=SIGNATURE_UNSIGNED_NO_SIGNING,
        signature_reason=UNSIGNED_REASON_NO_SIGNING,
        chain_verification=chain_verification,
        manifest_verification=manifest_verification,
        completeness=completeness,
    )


# --------------------------------------------------------------------------- #
# Repository                                                                   #
# --------------------------------------------------------------------------- #


class AttestationRepository:
    """Reads and writes the M0023 attestation tables.

    One transaction per write, the pattern every repository in this package
    follows. Rows carry both the derived columns (digest, chain link, root) and
    the canonical JSON they were derived from: the columns make an auditor's SQL
    cheap, the JSON makes re-verification exact.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    # -- chains -------------------------------------------------------------- #

    def save_chain(
        self,
        run_id: str,
        events: Sequence[AttestedEvent],
        *,
        sealed_at: datetime | str | None = None,
    ) -> str:
        """Persist a sealed chain and every event in one transaction.

        Args:
            run_id: The run the chain belongs to.
            events: The sealed events, in chain order.
            sealed_at: Stamp for the chain row (defaults to now).

        Returns:
            The chain root written.

        Raises:
            InvariantViolationError: From the evidence boundary, if any event
                carries a secret-classified field or a value this run resolved.
                No chain row and no event row is written.
            AttestationError: If ``events`` is not a valid sealed chain.
        """
        verification = verify_chain(events)
        if not verification.valid:
            raise AttestationError(
                f"refusing to persist an invalid chain for run {run_id!r}: "
                f"{'; '.join(verification.errors)}"
            )
        root = chain_root(events)
        stamp = _iso(sealed_at) or utc_now().isoformat()

        # The evidence boundary, before the transaction opens, on the events as the
        # column below serialises them. An ``AttestedEvent.payload`` is a free-form
        # dict by construction, so this is the one write path in this module where a
        # caller can plant a value under a field name nobody graded — which is the
        # byte rule's whole reason to exist, and why the gate cannot be the envelope's.
        # ``run_id`` is gated with them because it is a caller-supplied column.
        require_persistable_document(
            {"run_id": run_id, "events": [event.model_dump(mode="json") for event in events]},
            artifact=_chain_artifact(run_id),
        )

        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO attestation_chains "
                "(run_id, schema_version, chain_root, event_count,"
                " first_event_id, last_event_id, sealed_at, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    ATTESTATION_SCHEMA_VERSION,
                    root,
                    len(events),
                    events[0].event_id if events else "",
                    events[-1].event_id if events else "",
                    stamp,
                    stamp,
                ),
            )
            conn.executemany(
                "INSERT OR REPLACE INTO attestation_events "
                "(run_id, sequence, event_id, event_kind, digest, chain_link,"
                " previous_digest, recorded_at, event_json) VALUES (?,?,?,?,?,?,?,?,?)",
                [
                    (
                        run_id,
                        event.sequence,
                        event.event_id,
                        event.event_kind,
                        event.digest,
                        event.chain_link,
                        event.previous_digest,
                        event.recorded_at.wall_clock.isoformat(),
                        event.model_dump_json(),
                    )
                    for event in events
                ],
            )
        return root

    def load_chain(self, run_id: str) -> tuple[AttestedEvent, ...]:
        """Every stored event for ``run_id``, in sequence order.

        Reload is exact: the rows carry the same canonical bytes the digests were
        computed from, which is what makes re-verification meaningful.
        """
        rows = self._store.query(
            "SELECT event_json FROM attestation_events WHERE run_id = ? ORDER BY sequence",
            (run_id,),
        )
        return tuple(
            AttestedEvent.model_validate_json(str(dict(row)["event_json"])) for row in rows
        )

    def load_chain_row(self, run_id: str) -> dict[str, object] | None:
        """The chain header row, or ``None`` when nothing is stored."""
        rows = self._store.query("SELECT * FROM attestation_chains WHERE run_id = ?", (run_id,))
        return dict(rows[0]) if rows else None

    def verify_run_chain(self, run_id: str) -> ChainVerification:
        """Re-verify the stored chain with the domain verifier.

        The stored ``chain_root`` and ``event_count`` are checked against the
        recomputed ones, so a row edited to name a different root than its events
        produce is rejected even when every event still hashes correctly.
        """
        stored = self.load_chain_row(run_id)
        if stored is None:
            return ChainVerification(valid=False, errors=(f"no chain stored for run {run_id!r}",))
        events = self.load_chain(run_id)
        verification = verify_chain(events)
        errors = list(verification.errors)
        declared_root = str(stored["chain_root"])
        if declared_root != verification.root_digest:
            errors.append(
                f"stored chain root {declared_root[:12]} does not match the recomputed "
                f"root {verification.root_digest[:12]}"
            )
        declared_count = int(str(stored["event_count"]))
        if declared_count != len(events):
            errors.append(f"chain row records {declared_count} events, {len(events)} stored")
        return ChainVerification(
            valid=not errors,
            checked=len(events),
            errors=tuple(errors),
            root_digest=verification.root_digest,
        )

    def verify_run_completeness(
        self, run_id: str, *, mutating: bool | None = None
    ) -> ChainCompleteness:
        """Reload a run's chain and report whether it carries its authorization.

        The persisted counterpart of :func:`chain_completeness`: a chain that
        verifies integrity while missing its policy/approval events is *not*
        clean, and this is what says so from stored bytes.

        A run with no stored chain reports incomplete with the absence named,
        rather than the ``mutating=False`` a fresh chain would report — an absent
        chain has not been shown to be a read-only run.
        """
        events = self.load_chain(run_id)
        if not events:
            return ChainCompleteness(
                run_id=run_id,
                mutating=True,
                complete=False,
                missing=REQUIRED_AUTHORIZATION_KINDS,
                errors=(f"no chain stored for run {run_id!r}",),
            )
        return chain_completeness(events, mutating=mutating)

    # -- manifests ----------------------------------------------------------- #

    def save_manifest(
        self,
        manifest: Manifest,
        *,
        signature_state: str = SIGNATURE_UNSIGNED_NO_SIGNING,
        signature_reason: str = UNSIGNED_REASON_NO_SIGNING,
    ) -> Manifest:
        """Persist a sealed manifest and its signature state, in one transaction.

        ``signature_state`` is written beside the manifest rather than inferred
        from it, so "unsigned" is a recorded fact with a reason — never an absence
        a reader has to infer.

        Raises:
            InvariantViolationError: From the evidence boundary, if the manifest
                carries a secret-classified field or a value this run resolved.
                No row is written.
            AttestationError: If the manifest fails its own verification.
        """
        verification = verify_manifest(manifest)
        if not verification.valid:
            raise AttestationError(
                f"refusing to persist an invalid manifest {manifest.manifest_id!r}: "
                f"{'; '.join(verification.errors)}"
            )
        stamp = (
            manifest.created_at.wall_clock.isoformat()
            if manifest.created_at is not None
            else utc_now().isoformat()
        )

        # The evidence boundary, before the transaction opens, on the manifest as the
        # column below serialises it, plus the two caller-supplied columns beside it.
        # The manifest is what an auditor is handed and what ``infra.retention``
        # archives to external storage, so it is inside the boundary for the same
        # reason the chain is; ``signature_state``/``signature_reason`` are gated with
        # it because they are parameters a caller passes, not fields the manifest
        # derives — the same argument ``SecretGrantRepository.save`` makes about a
        # table with no value column.
        require_persistable_document(
            {
                "manifest": manifest.model_dump(mode="json"),
                "signature_state": signature_state,
                "signature_reason": signature_reason,
            },
            artifact=_manifest_artifact(manifest.manifest_id),
        )

        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO attestation_manifests "
                "(manifest_id, run_id, manifest_digest, signature_state, signature_reason,"
                " signer_identity, trust_root_ref, retention_class, event_count,"
                " previous_manifest_digest, created_at, manifest_json)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    manifest.manifest_id,
                    manifest.run_id,
                    manifest.manifest_digest,
                    signature_state,
                    signature_reason,
                    manifest.signer_identity,
                    manifest.trust_root_ref,
                    manifest.retention_class.value,
                    manifest.covered_events,
                    manifest.previous_manifest_digest,
                    stamp,
                    manifest.model_dump_json(),
                ),
            )
        return manifest

    def load_manifest(self, manifest_id: str) -> Manifest | None:
        """The stored manifest, or ``None`` when absent."""
        rows = self._store.query(
            "SELECT manifest_json FROM attestation_manifests WHERE manifest_id = ?",
            (manifest_id,),
        )
        if not rows:
            return None
        return Manifest.model_validate_json(str(dict(rows[0])["manifest_json"]))

    def list_manifests(self, run_id: str) -> tuple[Manifest, ...]:
        """Every manifest stored for ``run_id``, oldest first."""
        rows = self._store.query(
            "SELECT manifest_json FROM attestation_manifests WHERE run_id = ?"
            " ORDER BY created_at, manifest_id",
            (run_id,),
        )
        return tuple(Manifest.model_validate_json(str(dict(row)["manifest_json"])) for row in rows)

    def load_signature_state(self, manifest_id: str) -> tuple[str, str]:
        """``(signature_state, signature_reason)`` for a stored manifest.

        The second element is the reason the manifest is unsigned, so a caller
        reporting on it never has to invent an explanation.

        Raises:
            KeyError: If no such manifest is stored.
        """
        rows = self._store.query(
            "SELECT signature_state, signature_reason FROM attestation_manifests"
            " WHERE manifest_id = ?",
            (manifest_id,),
        )
        if not rows:
            raise KeyError(manifest_id)
        row = dict(rows[0])
        return str(row["signature_state"]), str(row["signature_reason"])

    def verify_stored_manifest(
        self, manifest_id: str, *, with_events: bool = True
    ) -> ManifestVerification:
        """Re-verify a stored manifest, against its stored events by default.

        With ``with_events=False`` the manifest's own digest and signer honesty
        are checked alone — the check an auditor can run with no chain rows.

        Raises:
            KeyError: If no such manifest is stored.
        """
        manifest = self.load_manifest(manifest_id)
        if manifest is None:
            raise KeyError(manifest_id)
        events = self.load_chain(manifest.run_id) if with_events else None
        return verify_manifest(manifest, events)
