"""Durable fabric evidence: the journal binding, verification wiring, and sealing.

Plan ``docs/v1.1.0/03_EXECUTION_FABRIC.md``, Phase 4 — *safety and evidence
integration*. Three things, and the reason they live together is that all three
are the same question asked at the dispatch boundary: **may this command act, and
will anyone be able to prove what happened?**

1. :class:`SqliteFabricJournal` — the durable
   :class:`~mayhem.controller.fabric_engine.FabricJournal`. Phase 2 declared the
   protocol and recorded, honestly, that nothing implemented it; this is that, over
   :mod:`mayhem.infra.fabric_journal`'s table, in the same store as the lease
   sink. Crash-resume is therefore now a claim about a *real* database rather
   than about an in-memory double.

2. :func:`decode_wire_command` + :func:`verify_dispatch_command` — the receiver
   seam. Verification is **not** reimplemented here: plan 19's
   :class:`~mayhem.infra.agent_identity_verifier.AgentCommandVerifier` already
   does HMAC over the canonical envelope, nonce freshness, plan binding, key
   binding, identity usability and revocation, and this module only
   *re-spells its refusals* in the fabric's vocabulary
   (:func:`~mayhem.controller.fabric_engine.translate_verification_refusal`) and
   decodes untrusted frames. Two raise sites for
   :data:`~mayhem.domain.fabric.FABRIC_UNDERSIGNED` exist as a result: one here
   for a frame that fails the envelope's own constraints, one in the engine for a
   signature that does not verify.

3. :class:`SealingFabricEvidence` + :func:`fabric_timeline` — the fabric's
   decisions go into plan 12's sealed chain, so a run's evidence reconstructs
   who dispatched what, under which epoch, and what the provider reported.

Why a separate chain, and not the run's own
-------------------------------------------

``attestation_events`` is keyed ``(run_id, sequence)`` and
:func:`~mayhem.domain.attestation.verify_chain` requires every event to link to
its predecessor and to share its ``run_id``. A run's own chain is minted whole at
run close by :func:`~mayhem.infra.attestation_store.seal_run_evidence`, with
sequences ``0..n``. Dispatches are minted *during* the run, one per effect, an
unbounded number of times. They cannot be interleaved into that chain without a
sequence collision and without changing what "the run's chain" means to a reader
who already has one.

So the fabric gets **its own chain per run**, keyed
``<run_id>:fabric`` (:func:`fabric_chain_id`), with the real ``run_id`` restated
inside every payload. That is the same answer plan 12 already gave for runs
themselves: runs are linked at the *manifest* layer
(``Manifest.previous_manifest_digest``), not by hanging one chain off another's
root. Each seal rewrites the chain from its stored events plus the new one and
re-seals it, so the manifest always covers the current state of the run's dispatch
record and its ``previous_manifest_digest`` chains it to the manifest it replaced.

What this chain is *not*
------------------------

* **It is not a second run-close chain.** It carries no
  ``evidence.recorded``/``policy.decided``/``approval.evaluated`` events, so
  :func:`~mayhem.infra.attestation_store.chain_completeness` would (correctly)
  report it incomplete for a mutating run. Run-level *authorization* completeness
  is :meth:`~mayhem.infra.attestation_store.AttestationRepository.verify_run_completeness`
  on the run's own chain; this one answers a different question — whether every
  dispatch of this run can be reconstructed.
* **It is not signed.** Every manifest it writes carries plan 12's
  ``unsigned_no_signing`` state and the reason beside it, so a reader who finds
  one is told the absence rather than left to guess. Sealing attests integrity,
  not authorship.
* **It stores no key material and no signature bytes.** The dispatch payload names
  the signing key id, the digest of the signed payload, and the algorithm — which
  together identify exactly what was checked — and never the MAC. Every write goes
  through :func:`~mayhem.infra.secret_resolver.require_persistable_document`,
  like every other evidence write path in this repository.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from mayhem.controller.fabric_engine import (
    FABRIC_MALFORMED_ENVELOPE,
    DispatchClaim,
    DispatchResult,
    DispatchSettlement,
    FabricCommandVerifierPort,
    FabricJournal,
    JournalEntry,
    VerifiedDispatch,
    translate_verification_refusal,
)
from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    ChainVerification,
    Manifest,
    RetentionClass,
    build_manifest,
    content_digest,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.common import iso_utc, utc_now
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.fabric import FABRIC_UNDERSIGNED, FabricCommand, FabricCommandRefused
from mayhem.domain.outcomes import StepOutcome, TargetOutcome
from mayhem.infra.agent_identity_verifier import CommandRefusedError
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationError,
    AttestationRepository,
)
from mayhem.infra.fabric_journal import FabricJournalRow, FabricJournalTable

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from datetime import datetime

    from mayhem.domain.fabric import FencingToken
    from mayhem.infra.store import Store

#: The suffix that makes a run's fabric chain distinct from the run's own chain.
FABRIC_CHAIN_SUFFIX = ":fabric"

# --------------------------------------------------------------------------- #
# Event kinds                                                                  #
# --------------------------------------------------------------------------- #

#: An envelope claimed an effect on a step. The payload names who dispatched it,
#: under which epoch, and (when a verifier was bound) how the envelope was
#: checked.
EVENT_FABRIC_DISPATCHED = "fabric.dispatched"

#: An idempotent retry was settled from a recorded outcome instead of dispatched
#: again. A distinct kind rather than a flag on the settlement, because "this ran
#: a second time" and "this did not run again" are different facts about a run.
EVENT_FABRIC_RETRY = "fabric.retry_served"

#: A dispatch settled, whatever it became.
EVENT_FABRIC_SETTLED = "fabric.settled"

#: A target the plan named is not the target the provider touched. Drift is
#: *mismatched*, not failed, and it is sealed under its own kind so a run's
#: evidence can be filtered for it without reading a detail string.
EVENT_FABRIC_DRIFT = "fabric.drift"

#: A command was refused before it could act — by this controller, or by the agent
#: that received it.
EVENT_FABRIC_REFUSED = "fabric.refused"

#: Every kind this module can emit, in the order a reader meets them. Named as a
#: tuple so the tests and a reader's expectation cannot disagree about the list.
FABRIC_EVENT_KINDS: tuple[str, ...] = (
    EVENT_FABRIC_DISPATCHED,
    EVENT_FABRIC_RETRY,
    EVENT_FABRIC_SETTLED,
    EVENT_FABRIC_DRIFT,
    EVENT_FABRIC_REFUSED,
)


def fabric_chain_id(run_id: str) -> str:
    """The chain id carrying ``run_id``'s dispatch record."""
    return f"{run_id}{FABRIC_CHAIN_SUFFIX}"


def fabric_manifest_id(run_id: str) -> str:
    """The manifest id covering ``run_id``'s fabric chain."""
    return f"{fabric_chain_id(run_id)}:manifest"


def run_id_of_chain(chain_id: str) -> str:
    """The run a fabric chain belongs to.

    A chain id that is not a fabric chain returns it unchanged, so a caller
    asking the wrong question gets its own value back rather than a silent lie.
    """
    return chain_id[: -len(FABRIC_CHAIN_SUFFIX)] if chain_id.endswith(FABRIC_CHAIN_SUFFIX) else (
        chain_id
    )


# --------------------------------------------------------------------------- #
# The durable journal                                                         #
# --------------------------------------------------------------------------- #


class SqliteFabricJournal:
    """:class:`~mayhem.controller.fabric_engine.FabricJournal` over SQLite.

    Single writer, same store as the lease sink (ADR-0007), which is what makes
    the rendezvous in :meth:`~mayhem.controller.fabric_engine.FabricEngine.dispatch`
    an *atomic* fact rather than two writes that might disagree.

    The whole entry is stored — never a projection of it — and every row is
    re-checked against its own payload on read, so the journal cannot disagree
    with the command it is a record of. An entry whose JSON was edited behind the
    model's back is refused by :meth:`~mayhem.infra.fabric_journal.FabricJournalTable.rows`
    rather than served to the engine as a real dispatch.

    The mapping is deliberately thin:

    * a claim's ``epoch`` is the fence it was taken under — an index column the
      engine's own projections do not query, kept because "which epoch claimed
      this" is the question every post-mortem asks first;
    * a settlement's ``epoch`` is recorded as ``1``. :class:`DispatchSettlement`
      does not carry a fence (it points at the command, which does), and inventing
      one here would put a number in a column that looked authoritative. The value
      is a schema floor, not a claim, and the settlement's payload has no epoch to
      disagree with.
    """

    def __init__(self, store: Store) -> None:
        self._table = FabricJournalTable(store)

    def append(self, entry: JournalEntry) -> None:
        """Persist one claim or settlement, or refuse to.

        Raises:
            FabricJournalIntegrityError: If the entry disagrees with the row it
                would produce.
            FabricJournalDuplicateEntryError: If the same ``(step, phase,
                command)`` is already recorded.
            InvariantViolationError: From the evidence boundary, if the entry
                carries a secret-classified field or a value this run resolved.
                Nothing is written.
        """
        self._table.append(self._row(entry))

    def entries(self, run_id: str, step_id: str | None = None) -> tuple[JournalEntry, ...]:
        """Every stored entry for ``run_id``, in append order.

        Raises:
            FabricJournalIntegrityError: If any row disagrees with its payload.
        """
        return tuple(
            self._entry(row) for row in self._table.rows(run_id, step_id)
        )

    def rows(self, run_id: str, step_id: str | None = None) -> tuple[FabricJournalRow, ...]:
        """The stored rows themselves — the raw record, for an auditor."""
        return self._table.rows(run_id, step_id)

    def count(self, run_id: str | None = None) -> int:
        """How many rows this journal holds."""
        return self._table.count(run_id)

    # -- mapping ------------------------------------------------------------ #

    def _row(self, entry: JournalEntry) -> FabricJournalRow:
        """A checked row for ``entry``."""
        payload = entry.model_dump(mode="json")
        if isinstance(entry, DispatchClaim):
            return FabricJournalRow.of(
                run_id=entry.run_id,
                step_id=entry.step_id,
                phase=entry.phase.value,
                command_id=entry.command.command_id,
                epoch=entry.command.fencing_token.epoch,
                entry=payload,
                controller_id=entry.controller_id,
                recorded_at=iso_utc(entry.claimed_at),
            )
        return FabricJournalRow.of(
            run_id=entry.run_id,
            step_id=entry.step_id,
            phase=entry.phase.value,
            command_id=entry.command_id,
            epoch=1,
            entry=payload,
            recorded_at=iso_utc(entry.settled_at),
        )

    def _entry(self, row: FabricJournalRow) -> JournalEntry:
        """The domain entry a checked row is a record of.

        Raises:
            FabricJournalIntegrityError: If the phase is one the schema allows but
                the domain does not — which cannot happen while both are
                maintained together, and is refused loudly if it ever does.
        """
        try:
            if row.phase == "claimed":
                return DispatchClaim.model_validate(row.payload())
            return DispatchSettlement.model_validate(row.payload())
        except ValidationError as exc:
            raise InvariantViolationError(
                "fabric_journal_entry_unreadable",
                f"journal row for command '{row.command_id}' stores a payload that is "
                f"not a valid {row.phase} entry: {exc}",
            ) from exc


# --------------------------------------------------------------------------- #
# Verification at the receiver                                                 #
# --------------------------------------------------------------------------- #

_REMEDIATION_DECODE = (
    "a fabric command is a complete envelope: protocol, command_id, run_id, step_id, "
    "agent_id, plan_digest, nonce, idempotency_key, fencing_token, command, issued_at, "
    "signing_key_id and signature are all required and none may be blank"
)


def _failure_locations(exc: ValidationError) -> tuple[str, ...]:
    """The field names a validation failure named, innermost first."""
    return tuple(
        ".".join(str(part) for part in error["loc"] if part != "__root__") or "<root>"
        for error in exc.errors()
    )


def decode_wire_command(raw: Mapping[str, Any] | str | bytes) -> FabricCommand:
    """Decode an untrusted frame into an envelope, or refuse it by name.

    This is the seam Phase 2 declared and Phase 4 gives a body. It is the only
    place in the fabric where an envelope arrives as *untrusted bytes*, so it is
    the only place :data:`~mayhem.domain.fabric.FABRIC_UNDERSIGNED` can mean
    "the frame never had a signature" rather than "the signature does not verify".

    Two codes, deliberately, because they are different facts:

    * :data:`FABRIC_MALFORMED_ENVELOPE` when a field is missing, blank or of the
      wrong shape — including a missing or empty ``signature``/``signing_key_id``;
    * :data:`FABRIC_UNDERSIGNED` when the frame parses but ``is_signed`` is false.

      In practice the second is unreachable for a *parsed* envelope, since
      :class:`~mayhem.domain.fabric.FabricCommand`'s field constraints refuse a
      blank signature at validation. It is kept because the alternative is that
      the vocabulary has no code for "this frame arrived without a signature",
      and the receiver that eventually decodes frames must not have to invent
      one. Saying so is cheaper than pretending it is reachable.
    """
    try:
        if isinstance(raw, str | bytes):
            command = FabricCommand.model_validate_json(raw)
        else:
            command = FabricCommand.model_validate(raw)
    except ValidationError as exc:
        fields = _failure_locations(exc)
        unsigned = tuple(name for name in fields if "signature" in name)
        if unsigned:
            raise FabricCommandRefused(
                FABRIC_UNDERSIGNED,
                f"untrusted frame does not satisfy the envelope's signature fields "
                f"({', '.join(unsigned)}); it never carried a usable signature",
                details={"fields": list(unsigned)},
                remediation=_REMEDIATION_DECODE,
            ) from exc
        raise FabricCommandRefused(
            FABRIC_MALFORMED_ENVELOPE,
            f"untrusted frame does not satisfy the envelope: {', '.join(fields)}",
            details={"fields": list(fields)},
            remediation=_REMEDIATION_DECODE,
        ) from exc
    if not command.is_signed:  # pragma: no cover - the field constraints refuse first
        raise FabricCommandRefused(
            FABRIC_UNDERSIGNED,
            f"command '{command.command_id}' arrived without a signature",
            details={"command_id": command.command_id, "run_id": command.run_id},
            remediation=_REMEDIATION_DECODE,
        )
    return command


def verify_dispatch_command(
    command: FabricCommand,
    *,
    verifier: FabricCommandVerifierPort,
    expected_plan_digest: str | None = None,
    served_fence: FencingToken | None = None,
    now: datetime | None = None,
) -> VerifiedDispatch:
    """Verify one command at a receiver, or refuse it by name.

    The receiver-side counterpart to
    :meth:`~mayhem.controller.fabric_engine.FabricEngine.dispatch`'s preflight,
    for the surface that receives frames rather than dispatching them. It calls
    the same :class:`~mayhem.controller.fabric_engine.FabricCommandVerifierPort`
    and re-spells the refusal the same way, so "who may act on this command" has
    one answer in this repository rather than one per surface.

    Raises:
        FabricCommandRefused: Re-spelled from
            :class:`~mayhem.infra.agent_identity_verifier.CommandRefusedError`;
            :data:`FABRIC_UNDERSIGNED` when the signature does not verify.
        SignaturePortUnavailableError: When the port cannot verify its own
            algorithm — propagated unchanged, because "nothing was checked" is
            the verifier's own honest answer and re-spelling it would lose the
            distinction.
    """
    try:
        verified = verifier.verify(
            command,
            expected_plan_digest=expected_plan_digest,
            served_fence=served_fence,
            now=now,
        )
    except CommandRefusedError as exc:
        raise translate_verification_refusal(exc) from exc
    return VerifiedDispatch.of(verified)


# --------------------------------------------------------------------------- #
# Sealing                                                                      #
# --------------------------------------------------------------------------- #


def _reading(recorded_at: AttestedTimestamp | None) -> AttestedTimestamp:
    """The caller's reading, or a fresh wall-clock + monotonic pair.

    The monotonic half is :func:`time.monotonic_ns` rather than a second read of
    the wall clock, so a host whose clock steps mid-run still orders these events
    correctly (gap 98) — the same reasoning
    :func:`~mayhem.infra.attestation_store.seal_run_evidence` records.
    """
    if recorded_at is not None:
        return recorded_at
    return AttestedTimestamp(
        wall_clock=utc_now(),
        monotonic_ns=time.monotonic_ns(),
        uncertainty_ms=0.0,
        source="system",
    )


@dataclass(frozen=True)
class FabricEvidenceRecorder:
    """Writes a run's fabric decisions into its own sealed chain.

    The clock is injected for the same reason the engine's is: a sealed event's
    ``recorded_at`` is a claim about time, and a reproducible one is worth more
    than a convenient one.
    """

    store: Store
    clock: Callable[[], AttestedTimestamp] | None = None
    retention_class: RetentionClass = RetentionClass.HOT

    def reading(self) -> AttestedTimestamp:
        """The stamp this recorder's next event will carry."""
        return _reading(self.clock() if self.clock is not None else None)

    # -- the recorder protocol ---------------------------------------------- #

    def dispatch_recorded(
        self, claim: DispatchClaim, *, verification: VerifiedDispatch | None = None
    ) -> AttestedEvent:
        """Seal a landed claim."""
        command = claim.command
        payload: dict[str, object] = {
            "run_id": command.run_id,
            "step_id": command.step_id,
            "agent_id": command.agent_id,
            "controller_id": claim.controller_id,
            "command_id": command.command_id,
            "epoch": command.fencing_token.epoch,
            "fence_holder": command.fencing_token.holder,
            "plan_digest": command.plan_digest,
            "idempotency_key": command.idempotency_key,
            "command_type": command.command.command_type.value,
            "body_digest": command.command.body_digest,
            "signing_key_id": command.signing_key_id,
            "claimed_at": claim.claimed_at.isoformat(),
            # Present and explicit on every dispatch, because "no verifier was
            # bound" is a fact a reader must be able to see rather than infer
            # from an absent key.
            "verified": verification is not None,
        }
        if verification is not None:
            payload["verification"] = verification.evidence()
        return self.seal(
            run_id=command.run_id,
            kind=EVENT_FABRIC_DISPATCHED,
            identity=f"{command.command_id}:claimed:{claim.claimed_at.isoformat()}",
            payload=payload,
        )

    def settlement_recorded(
        self, settlement: DispatchSettlement, *, result: DispatchResult | None = None
    ) -> AttestedEvent:
        """Seal a landed settlement, under the kind its outcome implies.

        A drift settles under :data:`EVENT_FABRIC_DRIFT` *instead of*
        :data:`EVENT_FABRIC_SETTLED` rather than as both: one event, one fact. The
        outcome is in the payload either way, so nothing is lost by not emitting a
        second, redundant event.
        """
        kind = (
            EVENT_FABRIC_DRIFT
            if settlement.outcome is StepOutcome.TARGET_DRIFT
            else (
                EVENT_FABRIC_RETRY
                if result is not None and result.retried
                else EVENT_FABRIC_SETTLED
            )
        )
        payload: dict[str, object] = {
            "run_id": settlement.run_id,
            "step_id": settlement.step_id,
            "command_id": settlement.command_id,
            "outcome": settlement.outcome.value,
            "target_outcome": (
                settlement.target_outcome.value if settlement.target_outcome is not None else ""
            ),
            "detail": settlement.detail,
            "lease_id": settlement.lease_id or "",
            "settled_at": settlement.settled_at.isoformat(),
            "retried": bool(result.retried) if result is not None else False,
            "epoch": result.epoch if result is not None else 0,
        }
        if result is not None and result.refusal_code:
            payload["agent_refusal_code"] = result.refusal_code
        return self.seal(
            run_id=settlement.run_id,
            kind=kind,
            identity=f"{settlement.command_id}:settled:{settlement.settled_at.isoformat()}",
            payload=payload,
        )

    def refusal_recorded(self, command: FabricCommand, *, code: str, reason: str) -> AttestedEvent:
        """Seal a refusal. The command's own identifiers, never its body."""
        return self.seal(
            run_id=command.run_id,
            kind=EVENT_FABRIC_REFUSED,
            identity=f"{command.command_id}:refused:{code}",
            payload={
                "run_id": command.run_id,
                "step_id": command.step_id,
                "agent_id": command.agent_id,
                "command_id": command.command_id,
                "epoch": command.fencing_token.epoch,
                "plan_digest": command.plan_digest,
                "refusal_code": code,
                "reason": reason,
                "signing_key_id": command.signing_key_id,
            },
        )

    # -- the sealer ------------------------------------------------------------ #

    def seal(
        self,
        *,
        run_id: str,
        kind: str,
        identity: str,
        payload: Mapping[str, Any],
        recorded_at: AttestedTimestamp | None = None,
    ) -> AttestedEvent:
        """Append one event to ``run_id``'s fabric chain and re-seal the chain.

        The chain is rewritten whole from its stored events plus this one. That
        is not an accident of storage: ``chain_link`` is a hash of the
        predecessor's link, so appending means re-deriving every link after it, and
        re-deriving them from *stored bytes* is what makes the chain's integrity a
        property of what is on disk rather than of this process's memory. A
        controller that dies mid-seal leaves the previous chain intact — the write
        is one transaction, so the worst case is a decision that is journalled but
        not yet sealed, and the journal is the record of record.

        Raises:
            DomainError: If ``kind`` is not one of :data:`FABRIC_EVENT_KINDS`.
            AttestationError: If the re-sealed chain or its manifest fails
                verification. Nothing is written.
            InvariantViolationError: From the evidence boundary, if the derived
                event or manifest carries a secret-classified field or a value this
                run resolved. Nothing is written.
        """
        if kind not in FABRIC_EVENT_KINDS:
            raise DomainError(
                f"unknown fabric evidence kind {kind!r}; known kinds are "
                f"{list(FABRIC_EVENT_KINDS)}"
            )
        chain_id = fabric_chain_id(run_id)
        repository = AttestationRepository(self.store)
        reading = recorded_at or self.reading()
        previous = repository.load_chain(chain_id)
        # A stable sequence keeps a re-seal of the *same* identity idempotent in
        # shape: the same decision re-recorded produces the same event id, and the
        # unique (run_id, event_id) index then says so instead of the chain
        # silently growing a second copy of one fact.
        event = AttestedEvent(
            event_id=f"{chain_id}:{kind}:{identity}",
            event_kind=kind,
            run_id=chain_id,
            sequence=len(previous),
            payload=dict(payload),
            recorded_at=reading,
        )
        sealed = seal_events([*previous, event])
        self._manifest(repository, chain_id, sealed, reading)
        return sealed[-1]

    def _manifest(
        self,
        repository: AttestationRepository,
        chain_id: str,
        events: tuple[AttestedEvent, ...],
        reading: AttestedTimestamp,
    ) -> Manifest:
        """Build, verify and persist the manifest over ``events``.

        ``previous_manifest_digest`` chains this manifest to the one it replaces,
        so a reader can see that the chain grew rather than only what it says now.
        """
        manifest_id = f"{chain_id}:manifest"
        prior = repository.load_manifest(manifest_id)
        manifest = build_manifest(
            events,
            manifest_id=manifest_id,
            run_id=chain_id,
            signer_identity="",
            trust_root_ref="",
            retention_class=self.retention_class,
            created_at=reading,
            previous_manifest_digest=(
                prior.manifest_digest if prior is not None else GENESIS_DIGEST
            ),
        )
        chain_verification = verify_chain(events)
        if not chain_verification.valid:
            raise AttestationError(
                f"refusing to persist an invalid fabric chain for {chain_id!r}: "
                f"{'; '.join(chain_verification.errors)}"
            )
        manifest_verification = verify_manifest(manifest, events)
        if not manifest_verification.valid:
            raise AttestationError(
                f"refusing to persist an invalid fabric manifest {manifest_id!r}: "
                f"{'; '.join(manifest_verification.errors)}"
            )
        repository.save_chain(chain_id, events, sealed_at=reading.wall_clock)
        repository.save_manifest(
            manifest,
            signature_state=SIGNATURE_UNSIGNED_NO_SIGNING,
            signature_reason=UNSIGNED_REASON_NO_SIGNING,
        )
        return manifest


def verify_fabric_chain(store: Store, run_id: str) -> ChainVerification:
    """Re-verify a run's fabric chain from stored bytes.

    The offline answer to "is this dispatch record intact", computed by plan 12's
    verifier over the reloaded rows — never by re-running the sealer, which would
    only prove the sealer agrees with itself.
    """
    return AttestationRepository(store).verify_run_chain(fabric_chain_id(run_id))


def load_fabric_chain(store: Store, run_id: str) -> tuple[AttestedEvent, ...]:
    """Every sealed fabric event for ``run_id``, in chain order."""
    return AttestationRepository(store).load_chain(fabric_chain_id(run_id))


def load_fabric_manifest(store: Store, run_id: str) -> Manifest | None:
    """The manifest covering ``run_id``'s fabric chain as of now, or ``None``."""
    return AttestationRepository(store).load_manifest(fabric_manifest_id(run_id))


def fabric_manifest_chain(store: Store, run_id: str) -> tuple[str, ...]:
    """The manifest digests this run's fabric record has committed to, oldest first.

    The manifest row is replaced in place on each seal rather than appended, so
    this is the *current* digest followed by the digest it replaced — the chain
    of record, held in one row. A reader who needs every intermediate state wants
    the journal, which is append-only by construction.
    """
    manifest = load_fabric_manifest(store, run_id)
    if manifest is None:
        return ()
    if not manifest.previous_manifest_digest:
        return (manifest.manifest_digest,)
    return (manifest.previous_manifest_digest, manifest.manifest_digest)


# --------------------------------------------------------------------------- #
# Reconstructing a run's dispatch record                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FabricDispatch:
    """One dispatch, as the sealed chain reports it."""

    command_id: str
    step_id: str
    agent_id: str
    controller_id: str
    epoch: int
    plan_digest: str
    idempotency_key: str
    verified: bool
    algorithm: str = ""
    envelope_digest: str = ""
    identity_version: int = 0


@dataclass(frozen=True)
class FabricRefusal:
    """One refused command, as the sealed chain reports it."""

    command_id: str
    step_id: str
    epoch: int
    code: str
    reason: str


@dataclass(frozen=True)
class FabricSettlement:
    """One settled effect, as the sealed chain reports it."""

    command_id: str
    step_id: str
    outcome: str
    target_outcome: str
    lease_id: str
    retried: bool
    epoch: int
    detail: str


@dataclass(frozen=True)
class FabricTimeline:
    """A run's dispatch record, read back out of the sealed chain.

    This is the answer to plan 03 Phase 4's acceptance question — *who dispatched
    what, under which epoch, and what did the provider report* — assembled from
    attested bytes rather than from whatever a controller still remembers.

    ``chain_verification`` travels with it on purpose: a timeline assembled from a
    chain that does not verify is a list, not a record, and a caller that ignores
    the verdict can end up quoting it as one.
    """

    run_id: str
    chain_id: str
    chain_root: str
    dispatches: tuple[FabricDispatch, ...]
    settlements: tuple[FabricSettlement, ...]
    refusals: tuple[FabricRefusal, ...]
    chain_verification: ChainVerification

    @property
    def verified(self) -> bool:
        """Whether the chain this timeline was read from verifies."""
        return self.chain_verification.valid

    @property
    def epochs(self) -> tuple[int, ...]:
        """Every epoch claimed, in chain order."""
        return tuple(dispatch.epoch for dispatch in self.dispatches)

    def dispatches_of(self, step_id: str) -> tuple[FabricDispatch, ...]:
        """The dispatches of one step."""
        return tuple(dispatch for dispatch in self.dispatches if dispatch.step_id == step_id)

    def owners_of(self, step_id: str) -> tuple[str, ...]:
        """Which controllers claimed ``step_id``, in chain order."""
        return tuple(d.controller_id for d in self.dispatches_of(step_id))

    def verify(self) -> ChainVerification:
        """Re-verify the chain these records were read from."""
        return self.chain_verification


def _text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key, "")
    return value if isinstance(value, str) else str(value)


def _number(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key, 0)
    return int(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0


def _flag(payload: Mapping[str, Any], key: str) -> bool:
    return payload.get(key) is True


def fabric_timeline(store: Store, run_id: str) -> FabricTimeline:
    """Reconstruct ``run_id``'s dispatch record from its sealed chain.

    An empty chain is not an error: a run that dispatched nothing has an empty
    record, and saying so is the honest answer. The returned timeline carries an
    *invalid* verification in that case, so a caller cannot mistake "nothing was
    recorded" for "nothing happened" — :meth:`FabricTimeline.verified` is ``False``
    and the errors say why.
    """
    chain_id = fabric_chain_id(run_id)
    events = load_fabric_chain(store, run_id)
    verification = verify_fabric_chain(store, run_id)
    dispatches: list[FabricDispatch] = []
    settlements: list[FabricSettlement] = []
    refusals: list[FabricRefusal] = []
    for event in events:
        payload = event.payload
        if event.event_kind == EVENT_FABRIC_DISPATCHED:
            verification_payload = payload.get("verification")
            verification_map: Mapping[str, Any] = (
                verification_payload if isinstance(verification_payload, dict) else {}
            )
            dispatches.append(
                FabricDispatch(
                    command_id=_text(payload, "command_id"),
                    step_id=_text(payload, "step_id"),
                    agent_id=_text(payload, "agent_id"),
                    controller_id=_text(payload, "controller_id"),
                    epoch=_number(payload, "epoch"),
                    plan_digest=_text(payload, "plan_digest"),
                    idempotency_key=_text(payload, "idempotency_key"),
                    verified=_flag(payload, "verified"),
                    algorithm=_text(verification_map, "algorithm"),
                    envelope_digest=_text(verification_map, "envelope_digest"),
                    identity_version=_number(verification_map, "identity_version"),
                )
            )
        elif event.event_kind in (EVENT_FABRIC_SETTLED, EVENT_FABRIC_DRIFT, EVENT_FABRIC_RETRY):
            settlements.append(
                FabricSettlement(
                    command_id=_text(payload, "command_id"),
                    step_id=_text(payload, "step_id"),
                    outcome=_text(payload, "outcome"),
                    target_outcome=_text(payload, "target_outcome"),
                    lease_id=_text(payload, "lease_id"),
                    retried=_flag(payload, "retried"),
                    epoch=_number(payload, "epoch"),
                    detail=_text(payload, "detail"),
                )
            )
        elif event.event_kind == EVENT_FABRIC_REFUSED:
            refusals.append(
                FabricRefusal(
                    command_id=_text(payload, "command_id"),
                    step_id=_text(payload, "step_id"),
                    epoch=_number(payload, "epoch"),
                    code=_text(payload, "refusal_code"),
                    reason=_text(payload, "reason"),
                )
            )
    return FabricTimeline(
        run_id=run_id,
        chain_id=chain_id,
        chain_root=verification.root_digest,
        dispatches=tuple(dispatches),
        settlements=tuple(settlements),
        refusals=tuple(refusals),
        chain_verification=verification,
    )


def timeline_matches_journal(
    timeline: FabricTimeline,
    journal: FabricJournal,
    run_id: str,
    step_id: str | None = None,
) -> tuple[str, ...]:
    """Compare a timeline against the durable journal; name every disagreement.

    The two records are produced independently — one from attested events, one
    from journal rows — so agreement between them is *evidence*, not a tautology,
    and this function is how a reader collects it. It compares the facts both
    sides must agree on: which commands were claimed and settled, and under which
    epochs. Detail strings and digests are deliberately not compared: the journal
    holds more of the envelope than the chain does, by design.

    Returns:
        One message per disagreement; empty when the two records agree.
    """
    journal_claims = {
        entry.command.command_id: entry.command.fencing_token.epoch
        for entry in journal.entries(run_id, step_id)
        if isinstance(entry, DispatchClaim)
    }
    journal_settlements = {
        entry.command_id for entry in journal.entries(run_id, step_id)
        if isinstance(entry, DispatchSettlement)
    }
    problems: list[str] = []
    for command_id, epoch in journal_claims.items():
        sealed = next(
            (d for d in timeline.dispatches if d.command_id == command_id), None
        )
        if sealed is None:
            problems.append(f"journal claims '{command_id}' but no sealed dispatch attests it")
        elif sealed.epoch != epoch:
            problems.append(
                f"journal claims '{command_id}' at epoch {epoch} but the chain attests "
                f"epoch {sealed.epoch}"
            )
    for command_id in journal_settlements:
        if not any(s.command_id == command_id for s in timeline.settlements):
            problems.append(f"journal settles '{command_id}' but no sealed settlement attests it")
    for dispatch in timeline.dispatches:
        if dispatch.command_id not in journal_claims:
            problems.append(
                f"chain attests dispatch '{dispatch.command_id}' which the journal "
                "does not hold"
            )
    return tuple(problems)


def fabric_digest(entry: JournalEntry) -> str:
    """Digest of a journal entry's canonical payload.

    Exposed so an auditor can check a journal row against the value they compute
    themselves with the same canonicalizer plan 12's chain uses, rather than
    trusting this module's derivation.
    """
    return content_digest(entry.model_dump(mode="json"))


def outcomes_of(settlement: FabricSettlement) -> tuple[StepOutcome, TargetOutcome | None]:
    """Read a settlement's outcome pair back as the enums the engine speaks.

    Raises:
        ValueError: If a sealed payload carries an outcome this vocabulary does
            not have — which would mean the chain was written by a build that
            knows a category this one does not, and guessing is not an option.
    """
    outcome = StepOutcome(settlement.outcome)
    target = TargetOutcome(settlement.target_outcome) if settlement.target_outcome else None
    return outcome, target
