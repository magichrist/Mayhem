"""Sealed evidence for high-availability decisions (plan 19, Phase 4).

Phase 4's sentence for this plan is *"every failover and restore sealed into
evidence"*. Restores were sealed in Phase 2 (the drill hands its observations to
:mod:`mayhem.domain.backup`, which derives the outcome and writes a verification
row). **Failovers** had no such path until this module: the promotion decisions
were durable in :mod:`mayhem.infra.failover_store`, but a durable row is not
evidence — it can be edited by anything holding the database file, and nothing
chains one decision to the next.

What this module adds is exactly the gap between those two things:

* :class:`FailoverEvidenceRecorder` writes every HA decision into plan 12's
  :class:`~mayhem.domain.attestation.AttestedEvent` chain and re-seals it after
  each event, so the chain's integrity is a property of *stored bytes* rather than
  of a process's memory.
* **Refusals are sealed too, under their own kind.** "We observed the partition,
  the evidence did not establish death, and we did not promote" is the record an
  incident review needs, and a success-only chain could not produce it — the same
  argument :mod:`mayhem.infra.failover_store` makes for its table.
* :func:`failover_timeline` and :func:`rotation_timeline` reconstruct the sequence
  from **reloaded** rows, re-verified by plan 12's own domain verifier. Never by
  re-running the sealer, which would only prove the sealer agrees with itself.

Two chains, and why
-------------------

``<scope>:failover``
    Leadership decisions for one scope: standby registrations and promotion
    decisions. The scope is the unit — two scopes are two control planes and must
    not share a chain.

``<controller_id>:rotation``
    Credential rotations and revocations for the identities one controller owns.
    Split from the failover chain because they answer a different question ("what
    credentials did this controller issue?") at a different cadence, and a reader
    of a promotion should not have to page past ninety credential events.

Neither chain is a run's chain, for plan 03's reason: ``attestation_events`` is
keyed ``(run_id, sequence)``, a run's own chain is minted whole at run close, and
these events are minted continuously during the controller's life.

What this chain is **not**
-------------------------

* **It is not signed.** Every manifest carries plan 12's ``unsigned_no_signing``
  state and the reason beside it. Sealing attests integrity, not authorship — the
  same statement plan 03's ledger and Phase 2's both make.
* **It does not verify anything cryptographic about the standby.** A promotion
  record proves that *this process, holding the store, wrote these bytes*. It does
  not prove a particular controller at a particular address took the scope: the
  evidence carries the ``standby_id`` as a **claim**, and the payload says so.
* **It stores no key material, no certificate body, and no signature.** It names
  the algorithm, the signing key id, and the digests, which together identify what
  was checked — never the bytes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    ChainVerification,
    Manifest,
    RetentionClass,
    build_manifest,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationError,
    AttestationRepository,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from mayhem.controller.credential_rotation import RotationOutcome
    from mayhem.domain.failover import PromotionDecision
    from mayhem.infra.failover_store import PromotionRecord, StandbyRecord
    from mayhem.infra.store import Store

__all__ = [
    "EVENT_HA_CREDENTIAL_REVOKED",
    "EVENT_HA_CREDENTIAL_ROTATED",
    "EVENT_HA_CREDENTIAL_ROTATION_FAILED",
    "EVENT_HA_PROMOTED",
    "EVENT_HA_PROMOTION_REFUSED",
    "EVENT_HA_STANDBY_REGISTERED",
    "HA_EVENT_KINDS",
    "FailoverEvidenceRecorder",
    "FailoverTimeline",
    "RotationTimeline",
    "failover_chain_id",
    "failover_timeline",
    "load_failover_chain",
    "load_failover_manifest",
    "load_rotation_chain",
    "rotation_chain_id",
    "rotation_timeline",
    "verify_failover_chain",
    "verify_rotation_chain",
]

#: A controller registered as a standby for a scope. A **claim**: the payload says
#: so in words, because a registration row that reads like an authentication is
#: how an operator ends up believing a controller was reachable when nothing ever
#: checked.
EVENT_HA_STANDBY_REGISTERED = "ha.standby_registered"

#: A standby took the leadership scope. The payload carries the terms on both
#: sides of the handover, the operator, and whether it was forced.
EVENT_HA_PROMOTED = "ha.promoted"

#: A promotion did not happen, and why. Sealed with the same weight as a success:
#: the refusal is the interesting record.
EVENT_HA_PROMOTION_REFUSED = "ha.promotion_refused"

#: A credential was rotated. ``key_provisioned`` rides along because "rotated"
#: without it is a fail-closed window an operator has to be told about.
EVENT_HA_CREDENTIAL_ROTATED = "ha.credential_rotated"

#: An identity was revoked through the append-only ledger.
EVENT_HA_CREDENTIAL_REVOKED = "ha.credential_revoked"

#: A rotation was refused. The agent id is in the payload, so one failure in a
#: sweep of a hundred does not hide behind the ninety-nine that worked.
EVENT_HA_CREDENTIAL_ROTATION_FAILED = "ha.credential_rotation_failed"

#: Every kind this module can emit, in the order a reader meets them.
HA_EVENT_KINDS: tuple[str, ...] = (
    EVENT_HA_STANDBY_REGISTERED,
    EVENT_HA_PROMOTED,
    EVENT_HA_PROMOTION_REFUSED,
    EVENT_HA_CREDENTIAL_ROTATED,
    EVENT_HA_CREDENTIAL_REVOKED,
    EVENT_HA_CREDENTIAL_ROTATION_FAILED,
)

#: The suffix that keeps a control-plane chain distinct from anything else keyed
#: on the same string.
FAILOVER_CHAIN_SUFFIX = ":failover"
ROTATION_CHAIN_SUFFIX = ":rotation"


def failover_chain_id(scope: str) -> str:
    """The evidence chain id for one leadership scope."""
    return f"{scope}{FAILOVER_CHAIN_SUFFIX}"


def rotation_chain_id(controller_id: str) -> str:
    """The evidence chain id for one controller's credential rotations."""
    return f"{controller_id}{ROTATION_CHAIN_SUFFIX}"


def _reading(recorded_at: AttestedTimestamp | None) -> AttestedTimestamp:
    """The caller's reading, or a fresh wall-clock + monotonic pair.

    ``time.monotonic_ns`` rather than a second wall-clock read, so a host whose
    clock steps mid-sweep still orders these events correctly.
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
class FailoverEvidenceRecorder:
    """Seal high-availability decisions into plan 12's chains.

    Args:
        store: The replicated store every other HA record already lives in.
        clock: Injected reading. A sealed event's ``recorded_at`` is a claim about
            time, and a reproducible one is worth more than a convenient one.
        retention_class: Plan 12's retention label for these events.

    Holds no state. Every call recomputes the chain from stored events, so a
    second recorder over the same store is a second controller and it agrees with
    the first immediately.
    """

    store: Store
    clock: Callable[[], AttestedTimestamp] | None = None
    retention_class: RetentionClass = RetentionClass.HOT

    def reading(self) -> AttestedTimestamp:
        """The stamp this recorder's next event will carry."""
        return _reading(self.clock() if self.clock is not None else None)

    # -- failover --------------------------------------------------------------
    def standby_registered(
        self, record: StandbyRecord, *, recorded_at: AttestedTimestamp | None = None
    ) -> AttestedEvent:
        """Seal a standby registration, as a claim about itself."""
        return self.seal(
            chain_id=failover_chain_id(record.scope),
            kind=EVENT_HA_STANDBY_REGISTERED,
            identity=f"{record.standby_id}:registered:{record.registered_at.isoformat()}",
            payload={
                "scope": record.scope,
                "standby_id": record.standby_id,
                "role": record.role.value,
                "advertised_version": record.advertised_version,
                "observed_term": record.observed_term,
                "registered_at": record.registered_at.isoformat(),
                "identity_claim": (
                    "standby_id is a claim this process wrote, not an authenticated "
                    "identity; no handshake or certificate exchange took place here"
                ),
            },
            recorded_at=recorded_at,
        )

    def promotion_decided(
        self,
        decision: PromotionDecision,
        record: PromotionRecord,
        *,
        recorded_at: AttestedTimestamp | None = None,
    ) -> AttestedEvent:
        """Seal one promotion decision, promoted or refused.

        The two outcomes get different kinds rather than one kind with a flag, so
        a reader filtering for "did anything actually take over" does not have to
        read a detail string, and a refusal can never be mistaken for a promotion
        by a query that forgot to check a boolean.
        """
        payload: dict[str, object] = {
            "scope": decision.request.scope,
            "standby_id": decision.request.standby_id,
            "standby_id_is_a_claim": True,
            "operator": decision.request.operator,
            "reason": decision.request.reason,
            "forced": decision.request.forced,
            "requested_term": decision.request.expected_term,
            "new_term": decision.new_term if decision.new_term is not None else 0,
            "deposed_leader_id": record.deposed_leader_id,
            "deposed_term": record.deposed_term,
            "refusals": [reason.value for reason in decision.refusals],
            "evidence": decision.request.assessment.model_dump(mode="json"),
            "promotion_id": record.promotion_id,
            "decided_at": decision.decided_at.isoformat(),
        }
        return self.seal(
            chain_id=failover_chain_id(decision.request.scope),
            kind=EVENT_HA_PROMOTED if decision.promoted else EVENT_HA_PROMOTION_REFUSED,
            identity=f"{record.promotion_id}:{record.status}",
            payload=payload,
            recorded_at=recorded_at,
        )

    # -- credentials -----------------------------------------------------------
    def rotation_recorded(
        self,
        outcome: RotationOutcome,
        *,
        controller_id: str,
        recorded_at: AttestedTimestamp | None = None,
    ) -> AttestedEvent:
        """Seal one credential action, whatever it was."""
        kind = {
            "rotated": EVENT_HA_CREDENTIAL_ROTATED,
            "revoked": EVENT_HA_CREDENTIAL_REVOKED,
        }.get(outcome.action.value, EVENT_HA_CREDENTIAL_ROTATION_FAILED)
        return self.seal(
            chain_id=rotation_chain_id(controller_id),
            kind=kind,
            identity=(
                f"{outcome.agent_id}:{outcome.action.value}:"
                f"{outcome.to_credential or outcome.from_credential}"
            ),
            payload={
                "controller_id": controller_id,
                "agent_id": outcome.agent_id,
                "action": outcome.action.value,
                "from_credential": outcome.from_credential,
                "to_credential": outcome.to_credential,
                "generation": outcome.generation,
                # The field to read first: a rotated agent that holds a credential
                # it cannot authenticate with is a fail-closed window, not a done
                # rotation, and the chain must not read as though it were one.
                "key_provisioned": outcome.key_provisioned,
                "detail": outcome.detail,
            },
            recorded_at=recorded_at,
        )

    # -- the sealer ------------------------------------------------------------
    def seal(
        self,
        *,
        chain_id: str,
        kind: str,
        identity: str,
        payload: Mapping[str, Any],
        recorded_at: AttestedTimestamp | None = None,
    ) -> AttestedEvent:
        """Append one event to ``chain_id`` and re-seal that chain.

        The chain is rewritten whole from its stored events plus this one, because
        ``chain_link`` is a hash of its predecessor's link: appending means
        re-deriving every link after it, and re-deriving them from *stored bytes*
        is what makes integrity a property of what is on disk. The write is one
        transaction, so a controller that dies mid-seal leaves the previous chain
        intact rather than a half-linked one.

        Raises:
            DomainError: If ``kind`` is not one of :data:`HA_EVENT_KINDS`.
            AttestationError: If the re-sealed chain or its manifest fails
                verification. Nothing is written.
        """
        if kind not in HA_EVENT_KINDS:
            raise DomainError(
                f"unknown HA evidence kind {kind!r}; known kinds are {list(HA_EVENT_KINDS)}"
            )
        repository = AttestationRepository(self.store)
        reading = recorded_at or self.reading()
        previous = repository.load_chain(chain_id)
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
        """Build, verify, and persist the manifest over ``events``.

        ``previous_manifest_digest`` chains this manifest to the one it replaces,
        so a reader can see that the chain *grew* and not only what it says now.
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
        if not verify_chain(events).valid:
            raise AttestationError(f"refusing to persist an invalid HA chain for {chain_id!r}")
        if not verify_manifest(manifest, events).valid:
            raise AttestationError(f"refusing to persist an invalid HA manifest {manifest_id!r}")
        repository.save_chain(chain_id, events, sealed_at=reading.wall_clock)
        repository.save_manifest(
            manifest,
            signature_state=SIGNATURE_UNSIGNED_NO_SIGNING,
            signature_reason=UNSIGNED_REASON_NO_SIGNING,
        )
        return manifest


# --------------------------------------------------------------------------- #
# Reading back                                                                   #
# --------------------------------------------------------------------------- #


def verify_failover_chain(store: Store, scope: str) -> ChainVerification:
    """Re-verify a scope's failover chain from stored bytes.

    The offline answer to "is this promotion record intact", computed by plan 12's
    verifier over reloaded rows — never by re-running the sealer.
    """
    return verify_chain(load_failover_chain(store, scope))


def verify_rotation_chain(store: Store, controller_id: str) -> ChainVerification:
    """Re-verify a controller's rotation chain from stored bytes."""
    return verify_chain(load_rotation_chain(store, controller_id))


def load_failover_chain(store: Store, scope: str) -> tuple[AttestedEvent, ...]:
    """Every sealed HA decision for ``scope``, in order."""
    return AttestationRepository(store).load_chain(failover_chain_id(scope))


def load_rotation_chain(store: Store, controller_id: str) -> tuple[AttestedEvent, ...]:
    """Every sealed credential action for ``controller_id``, in order."""
    return AttestationRepository(store).load_chain(rotation_chain_id(controller_id))


def load_failover_manifest(store: Store, scope: str) -> Manifest | None:
    """The manifest covering ``scope``'s HA chain, or ``None`` before the first seal."""
    return AttestationRepository(store).load_manifest(f"{failover_chain_id(scope)}:manifest")


@dataclass(frozen=True)
class FailoverTimeline:
    """What happened to one scope's leadership, reconstructed from sealed bytes.

    Attributes:
        scope: The leadership scope.
        events: Every sealed event, in order.
        verified: Whether plan 12's verifier accepts the reloaded chain.
    """

    scope: str
    events: tuple[AttestedEvent, ...]
    verified: bool

    @property
    def promotions(self) -> tuple[AttestedEvent, ...]:
        """Only the decisions that actually moved the scope."""
        return tuple(e for e in self.events if e.event_kind == EVENT_HA_PROMOTED)

    @property
    def refusals(self) -> tuple[AttestedEvent, ...]:
        """Only the decisions that did not — the record a post-mortem wants."""
        return tuple(e for e in self.events if e.event_kind == EVENT_HA_PROMOTION_REFUSED)

    @property
    def terms_taken(self) -> tuple[int, ...]:
        """Every term a promotion in this chain took, in order."""
        return tuple(int(e.payload.get("new_term", 0)) for e in self.promotions)

    @property
    def last_term(self) -> int:
        """The highest term this chain says was taken, ``0`` when nothing was."""
        return max(self.terms_taken, default=0)

    def describe(self) -> str:
        return (
            f"scope {self.scope!r}: {len(self.promotions)} promotion(s) "
            f"{list(self.terms_taken)}, {len(self.refusals)} refusal(s), "
            f"chain_verified={self.verified}"
        )


@dataclass(frozen=True)
class RotationTimeline:
    """One controller's credential history, reconstructed from sealed bytes."""

    controller_id: str
    events: tuple[AttestedEvent, ...]
    verified: bool

    @property
    def rotated(self) -> tuple[AttestedEvent, ...]:
        return tuple(e for e in self.events if e.event_kind == EVENT_HA_CREDENTIAL_ROTATED)

    @property
    def revoked(self) -> tuple[AttestedEvent, ...]:
        return tuple(e for e in self.events if e.event_kind == EVENT_HA_CREDENTIAL_REVOKED)

    @property
    def without_key(self) -> tuple[str, ...]:
        """Agents whose rotation left them holding a credential they cannot use."""
        return tuple(
            str(e.payload.get("agent_id", ""))
            for e in self.rotated
            if not bool(e.payload.get("key_provisioned", False))
        )

    def describe(self) -> str:
        return (
            f"{self.controller_id}: {len(self.rotated)} rotation(s), "
            f"{len(self.revoked)} revocation(s), "
            f"{len(self.without_key)} without a provisioned key, "
            f"chain_verified={self.verified}"
        )


def failover_timeline(store: Store, scope: str) -> FailoverTimeline:
    """Rebuild ``scope``'s leadership history from stored, re-verified bytes."""
    events = load_failover_chain(store, scope)
    return FailoverTimeline(scope=scope, events=events, verified=verify_chain(events).valid)


def rotation_timeline(store: Store, controller_id: str) -> RotationTimeline:
    """Rebuild one controller's credential history from stored, re-verified bytes."""
    events = load_rotation_chain(store, controller_id)
    return RotationTimeline(
        controller_id=controller_id, events=events, verified=verify_chain(events).valid
    )
