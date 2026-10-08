"""Seal a run's development-only credential marker into the attested chain.

Plan 29 Phase 3 requires the explicit per-run development-only marker to be
*sealed into evidence*. What existed before this module was the in-memory half:
:class:`~mayhem.infra.secret_resolver.SecretResolver` refuses a
development-only provider without ``allow_development_only=True`` and records a
:class:`~mayhem.infra.secret_resolver.ResolutionReceipt` per resolution — but a
receipt that lives only in :attr:`SecretResolver.receipts
<mayhem.infra.secret_resolver.SecretResolver.receipts>` dies with the process,
so a run that resolved a development-only credential left no evidence it did.
This module is the sealed half: it takes the resolver's
:meth:`~mayhem.infra.secret_resolver.SecretResolver.development_marker`
(metadata only, never a value) and seals it through
:class:`~mayhem.infra.attestation_store.AttestationRepository` — the existing
seal path, the existing verifier, no second sealer, no new dependency, no
crypto added.

The shape follows :mod:`mayhem.controller.k8s_evidence` and
:mod:`mayhem.controller.cloud_evidence` exactly: the events are built pure, the
chain is sealed with :func:`~mayhem.domain.attestation.seal_events` and
:func:`~mayhem.domain.attestation.build_manifest`, both verifications must pass
before anything is written, and the rows live under a namespaced chain key
(:func:`secret_chain_key`) because ``attestation_chains.run_id`` is a PRIMARY
KEY already claimed by ``seal_run_evidence`` at run close. The repository's own
evidence-boundary gates cover the write, so this module calls no gate itself —
and therefore contributes no ``BOUNDARY_CALL_SITES`` row, exactly like the two
lanes it mirrors.

The run-close call site for the lane that owns ``cli/`` is
``src/mayhem/cli/lifecycle.py``, in ``_write_evidence_after_run``, which takes
the marker as ``secret_development_marker`` and seals it after the envelope is
built and before ``write_evidence`` persists it, so the envelope's remediation
note and the sealed chain agree. Stated honestly: no production caller passes a
marker yet, because no executor reads ``DrillSpec.credential_refs`` — a drill
that declares a reference does not yet receive a credential at run time. The
seam, the call site, and the tests exist so the first executor that resolves
one has exactly one place to seal the marker; until then a missing marker seals
nothing and :func:`seal_secret_development_marker` returns ``None``.

What is sealed is metadata, and the read is read-only: :func:`load_secret_\
development_marker` reloads the sealed record without mutating it, and the
payload carries ``allow_development_only`` plus the development-only receipts'
provider, canonical key, purpose, scope, principal, environment, grant pattern
and timestamps — never a value, so the byte rule has nothing to find and the
grade rule has no secret-graded field to refuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    ChainVerification,
    Manifest,
    ManifestVerification,
    build_manifest,
    chain_root,
    seal_events,
    verify_chain,
    verify_manifest,
)

# ``_recorded_at`` is plan 12's single clock policy for attested events — a
# wall-clock/monotonic pair taken once for a chain. Re-implementing it here would
# be a second clock policy disagreeing with the first by a monotonic tick, so the
# private helper is imported rather than copied; it is the only private name this
# module reaches for, and :func:`seal_secret_development_marker` is its only caller.
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationError,
    AttestationRepository,
    _recorded_at,
)
from mayhem.infra.secret_resolver import development_marker_is_sealable

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mayhem.infra.store import Store


#: The chain event kind a sealed development marker is stored under. It is a
#: *chain* kind (``AttestedEvent.event_kind``), not a ``domain.events.EventKind``:
#: the two vocabularies are separate by design — the first is what a verifier
#: re-hashes offline, the second is what the run journal renders.
EVENT_SECRET_DEVELOPMENT_MARKED = "secret.development_marked"

#: The chain key suffix. ``attestation_chains.run_id`` is a PRIMARY KEY, so a
#: chain for the run itself is already claimed by ``seal_run_evidence`` at run
#: close — writing the marker under the bare run id would replace the evidence
#: chain (or be replaced by it) and the marker would be lost either way.
#: Namespacing the *chain key* keeps both: the rows are namespaced, the events
#: still name the real run, and both verify independently.
CHAIN_KEY_SUFFIX = ":secret-development"


def secret_chain_key(run_id: str) -> str:
    """The ``attestation_chains`` key this lane writes under for ``run_id``."""
    return f"{run_id}{CHAIN_KEY_SUFFIX}"


def secret_manifest_id(run_id: str) -> str:
    """The ``attestation_manifests`` id covering the marker chain."""
    return secret_chain_key(run_id)


def development_marker_chain_events(
    run_id: str,
    marker: Mapping[str, Any],
    *,
    recorded_at: AttestedTimestamp,
) -> tuple[AttestedEvent, ...]:
    """The unsealed chain event for one run's development marker (pure).

    Exactly one event: the marker is one fact about the run (the per-run flag
    plus the development-only receipts), not one fact per receipt. The
    ``AttestedEvent.run_id`` is the **real** run id, so a reloaded event says
    which run it describes; only the chain row key is namespaced (see
    :func:`secret_chain_key`).
    """
    return (
        AttestedEvent(
            event_id=f"{run_id}:secret-development",
            event_kind=EVENT_SECRET_DEVELOPMENT_MARKED,
            run_id=run_id,
            sequence=0,
            payload={
                "allow_development_only": bool(marker.get("allow_development_only", False)),
                "development_only_providers": list(
                    marker.get("development_only_providers", []) or []
                ),
                "development_only_receipts": [
                    dict(receipt) for receipt in marker.get("development_only_receipts", []) or []
                ],
                "receipt_count": int(marker.get("receipt_count", 0) or 0),
            },
            recorded_at=recorded_at,
        ),
    )


@dataclass(frozen=True)
class SecretDevelopmentSeal:
    """A sealed development marker, with the verdicts that prove it.

    Mirrors :class:`~mayhem.controller.k8s_evidence.K8sAdmissionSeal` for this
    lane: the events, the manifest over them, both verification verdicts, and the
    same unsigned-with-a-reason honesty state — this phase attests integrity,
    never authorship, exactly as plan 12 does.
    """

    run_id: str
    events: tuple[AttestedEvent, ...]
    manifest: Manifest
    chain_verification: ChainVerification
    manifest_verification: ManifestVerification
    signature_state: str = SIGNATURE_UNSIGNED_NO_SIGNING
    signature_reason: str = UNSIGNED_REASON_NO_SIGNING

    @property
    def chain_root(self) -> str:
        return chain_root(self.events)

    @property
    def signed(self) -> bool:
        """Always False here. Present so a caller cannot assume otherwise."""
        return self.manifest.signed

    @property
    def valid(self) -> bool:
        """True when both the chain and its manifest verify."""
        return self.chain_verification.valid and self.manifest_verification.valid

    @property
    def marker(self) -> dict[str, Any]:
        """The sealed marker payload, read-only: the flag, the providers, the receipts."""
        return dict(self.events[0].payload) if self.events else {}


def seal_secret_development_marker(
    store: Store,
    run_id: str,
    marker: Mapping[str, Any],
    *,
    recorded_at: AttestedTimestamp | None = None,
    created_at: AttestedTimestamp | None = None,
) -> SecretDevelopmentSeal | None:
    """Seal one run's development-only marker into the attested chain.

    Writes through :class:`~mayhem.infra.attestation_store.AttestationRepository`
    — the module's own persistence, its own evidence-boundary gate, and its own
    verification. This function builds *events*; it does not build a sealer.

    Returns:
        The :class:`SecretDevelopmentSeal`, or ``None`` when there is nothing to
        seal (the per-run flag unset and no development-only receipt). An empty
        marker is not written: a row that proves nothing is noise a later reader
        has to rule out.

    Raises:
        AttestationError: If the derived chain or manifest fails verification, in
            which case nothing is written.
        InvariantViolationError: From the evidence boundary, if the derived
            record carries a secret-classified field or a resolved value.
            Nothing is written. The marker payload cannot do this by
            construction — it is receipt metadata — so a refusal here names a
            caller-built marker that smuggled one in.
    """
    if not development_marker_is_sealable(marker):
        return None
    reading = _recorded_at(recorded_at)
    events = seal_events(
        development_marker_chain_events(run_id, marker, recorded_at=reading),
    )
    manifest = build_manifest(
        events,
        manifest_id=secret_manifest_id(run_id),
        run_id=run_id,
        signer_identity="",
        trust_root_ref="",
        created_at=created_at or reading,
        previous_manifest_digest=GENESIS_DIGEST,
    )
    chain_verification = verify_chain(events)
    if not chain_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid secret development chain for run "
            f"{run_id!r}: {'; '.join(chain_verification.errors)}"
        )
    manifest_verification = verify_manifest(manifest, events)
    if not manifest_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid secret development manifest for run "
            f"{run_id!r}: {'; '.join(manifest_verification.errors)}"
        )

    repository = AttestationRepository(store)
    repository.save_chain(secret_chain_key(run_id), events, sealed_at=reading.wall_clock)
    repository.save_manifest(manifest)
    return SecretDevelopmentSeal(
        run_id=run_id,
        events=events,
        manifest=manifest,
        chain_verification=chain_verification,
        manifest_verification=manifest_verification,
    )


def load_secret_development_marker(store: Store, run_id: str) -> SecretDevelopmentSeal | None:
    """Reload a sealed development marker from stored bytes, or ``None``.

    Read-only: reload is exact — the rows carry the canonical JSON the digests
    were computed from, so what comes back verifies the same way it went in.
    The ``signature_state`` is reloaded rather than re-asserted, so an unsigned
    record stays visibly unsigned to whoever reads it.
    """
    repository = AttestationRepository(store)
    events = repository.load_chain(secret_chain_key(run_id))
    if not events:
        return None
    manifest = repository.load_manifest(secret_manifest_id(run_id))
    if manifest is None:
        return None
    state, reason = repository.load_signature_state(manifest.manifest_id)
    return SecretDevelopmentSeal(
        run_id=run_id,
        events=events,
        manifest=manifest,
        chain_verification=verify_chain(events),
        manifest_verification=verify_manifest(manifest, events),
        signature_state=state,
        signature_reason=reason,
    )


def verify_secret_development_chain(store: Store, run_id: str) -> ChainVerification:
    """Re-verify the stored marker chain, naming an unsealed marker as absent.

    Delegates the re-hashing to
    :meth:`~mayhem.infra.attestation_store.AttestationRepository.verify_run_chain`,
    which reloads the stored bytes, calls the domain verifier, and additionally
    checks the stored root and count against the recomputed ones. A run whose
    marker was never sealed reports ``valid=False`` with "no chain stored" —
    an *unsealed* marker is detectable, never silently treated as unmarked.
    """
    return AttestationRepository(store).verify_run_chain(secret_chain_key(run_id))


__all__ = (
    "CHAIN_KEY_SUFFIX",
    "EVENT_SECRET_DEVELOPMENT_MARKED",
    "SecretDevelopmentSeal",
    "development_marker_chain_events",
    "load_secret_development_marker",
    "seal_secret_development_marker",
    "secret_chain_key",
    "secret_manifest_id",
    "verify_secret_development_chain",
)
