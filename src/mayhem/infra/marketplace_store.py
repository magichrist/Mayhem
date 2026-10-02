"""The marketplace registry: pins, compatibility, and the dispatch gate (plan 18, Phase 2).

v1.1.0 plan 18 §Phase 2 (``docs/v1.1.0/18_MARKETPLACE_CATALOG.md``). Phase 1 put
the *rules* in :mod:`mayhem.domain.marketplace`; this module is the engine that
holds artifacts in a store, resolves a pin to exact bytes, answers whether those
bytes may run on this runtime, and — the part the phase exists for — stops a
dispatch once a revocation's propagation deadline has passed.

The honesty position, restated because this is the layer that would be tempted
to drop it
------------------------------------------------------------------------------
Nothing here verifies a signature.
:data:`mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is ``False`` in
this build and this module re-asserts the same fact as
:data:`SIGNATURE_VERIFICATION_IMPLEMENTED` rather than importing it, for the
reason Phase 1 gave: the domain layer may not depend on the loader layer, and
two literals a test pins equal are safer than a dependency. What the registry
*does* establish is real and is called by its real name: the sha256 content
digest of the bytes being installed is compared against the digest the catalog
published, and a mismatch is refused. That is integrity. It says nothing about
who wrote the bytes, and :attr:`DispatchAdmission.notice`,
:attr:`ListingEntry.notice`, and :attr:`ResolvedPin.notice` all return
:data:`~mayhem.domain.marketplace.SIGNATURE_TRUST_NOTICE`, so a renderer cannot
print one of these objects without the qualification within reach.

The structural commitment this module adds on top of Phase 1's
------------------------------------------------------------------------
**No class is ever stored.** :class:`ResolvedPin`, :class:`ListingEntry`, and
:class:`DispatchAdmission` each carry a
:class:`~mayhem.domain.marketplace.TrustLabel` — the frozen pydantic model whose
``artifact_class`` is a *derived property* over registry scope, deprecation, and
certifications — and each exposes ``artifact_class`` as a property that reads it
off that label. A plain dataclass field would have been constructible with any
value (``DispatchAdmission(artifact_class=ArtifactClass.OFFICIAL, ...)``), which
is precisely the shortcut Phase 1 removed from the domain. So the schema has no
column for a class, the models have no field for one, and the only way to read
the word off any object in this module is to supply records that justify it.

The two axes, kept apart end to end
------------------------------------
* **Integrity** is the digest, and it is checked at install: an install carries
  the observed sha256 of the bytes in hand, and a mismatch is refused with
  ``marketplace.tampered_artifact`` *and* written down as
  :data:`~mayhem.domain.marketplace.DigestCheckState.DIGEST_MISMATCHED` on the
  supply-chain record, so the failure survives the refusal.
* **Evidence** is a plan-01 :class:`~mayhem.domain.certification.CertificationRecord`
  paired with the artifact digest it was made against
  (:class:`~mayhem.domain.marketplace.ArtifactCertification`). The store persists
  that *pairing* under ``marketplace_certifications``, keyed by the digest, so no
  record can be pointed at bytes it was not made against. Reads are aged and
  writes are not, exactly as
  :mod:`mayhem.infra.certification_repository` does it: a lapsed record stops
  counting the moment it lapses, whether or not anybody has run a sweep.
* **Authorship** is not established, anywhere, by anything in this module.

Deprecation at dispatch: the decision, and why
----------------------------------------------
Phase 1 deliberately left ``dispatches()`` permissive about deprecation and
handed the question to this phase, on the grounds that only an admission path
knows whether an artifact is *already installed and running*. That knowledge is
used, and the answer is **a deprecated artifact still dispatches**.

Three reasons, in the order they decided it:

1. **Revocation is the withdrawal instrument, and deprecation is not.** A
   :class:`~mayhem.domain.marketplace.Revocation` carries a reason, a deadline,
   and an id a refusal can name; ``RevocationReason.SUPERSEDED`` exists for the
   "use the newer version instead" case. If a bare deprecation notice also
   stopped running code, a publisher could withdraw bytes *without a deadline
   and without a record to trace*, and that path would be strictly stronger than
   the instrument designed to be auditable. An operator would have to know which
   of the two words to use, or lose the deadline.
2. **Phase 1 already separated "we told you" from "we stopped it".**
   ``pending_revocations`` and ``blocking_revocations`` are distinct
   predicates, and a :class:`~mayhem.domain.marketplace.DeprecationNotice` has no
   deadline at all — treating it as blocking-at-dispatch collapses that
   distinction for the one case that cannot express it.
3. **The plan says approvals.** ``approval_refusals`` already lists
   ``artifact.deprecated``, and an install *is* a fresh grant of standing to
   bytes nobody had admitted before. So deprecation is enforced at
   :meth:`MarketplaceRegistry.install` (``marketplace.deprecated_install``) and
   through :meth:`MarketplaceRegistry.approval_gate`, and it is *reported* — never
   silently dropped — on every dispatch through
   :attr:`DispatchAdmission.deprecated`.

An operator who wants a deprecated artifact to stop executing revokes it, and
then the dispatch gate refuses it by name.

How revocation reaches the loader's dispatch path
-------------------------------------------------
:mod:`mayhem.providers.loader` is the single enforcement point for third-party
providers and this module does not sit beside it. Two seams, both going *through*
a real :class:`~mayhem.providers.loader.ProviderLoader`:

* :meth:`MarketplaceRegistry.admit` is the admission decision. It refuses a
  revoked artifact (message from
  :func:`~mayhem.domain.marketplace.dispatch_refusal`, so the refusal names the
  revocation that caused it), and then asks the *same loader* for the sandbox
  profile the provider was admitted with and re-runs that loader's own
  ``SandboxEnforcer.admit()``. The marketplace rule is checked first and is not a
  substitute for the loader's gates; a provider the loader would refuse is still
  refused here, by the loader's own exception.
* :meth:`MarketplaceRegistry.guarded_factory` wraps a runtime factory so the
  revocation check happens at the moment the runtime is *materialised*, not only
  when it was admitted. A caller holding the
  :class:`~mayhem.providers.registry.ProviderRegistry` therefore cannot obtain
  the runtime of an artifact whose deadline has passed — which is the defect this
  phase exists to prevent: **a revoked provider that still executes.**

Federation is distribution, not standing
----------------------------------------
:meth:`MarketplaceRegistry.listing` takes a private registry id by the same
argument a public one uses, and :meth:`MarketplaceRegistry.federation` computes
the same closure over the same edges for both, so an organization-private
catalogue is reachable through the *same protocol* as the official one. There is
no extra admission step for a private registry because
:func:`~mayhem.domain.marketplace.federated_registries` seeds its walk with every
registry it is handed, so being published *is* being federated. What that buys is
bytes, never a class:
:func:`~mayhem.domain.marketplace.classify_artifact` takes no registry argument,
so an artifact listed through a private registry still derives
``organization_private`` here, and a test asserts it through this module rather
than trusting Phase 1's own suite to say it.

Phase 4 — sealing, audit, and one honest correction to Phase 2
----------------------------------------------------------------
Phase 2 left three things open. This section records what happened to each,
because the answers change how the module should be read.

**Sealing.** :class:`MarketplaceEvidence` writes each catalog activity into
plan 12's chain through :class:`~mayhem.infra.attestation_store.AttestationRepository`
— the same :class:`~mayhem.domain.attestation.AttestedEvent` type, the same
:func:`~mayhem.domain.attestation.seal_events`, the same
:func:`~mayhem.domain.attestation.verify_chain`, the same
:class:`~mayhem.domain.attestation.Manifest`. A *publish*, a *pin*, an
*install*, a *revocation*, a *deprecation*, and a *federation closure* each seal
one event and one manifest, and every one of those payloads names the artifact
digest, the registry, and the **derived** trust class together with
:data:`~mayhem.domain.marketplace.SIGNATURE_TRUST_NOTICE` and
``signature_verification_implemented: False``. A consumer holding only the
exported chain can therefore answer "which bytes were admitted, under which
label, from which digest" without this database and without trusting a field
nobody derived.

Sealing is **not** signing. Every manifest this module writes is unsigned, and
the reason string is stored with it exactly as plan 12 stores its own. The
chain proves the recorded bytes are unaltered and in order; it proves nothing
about who wrote them.

**Audit.** :class:`~mayhem.infra.audit_stream.AuditStream` records the three
privileged actions in :data:`MARKETPLACE_PRIVILEGED_ACTIONS` — installing,
revoking, and trusting a publisher — through its own
:meth:`~mayhem.infra.audit_stream.AuditStream.record` seam, with no second audit
format invented here. ``principal`` is what the caller declared; nothing
authenticates it, for the same reason nothing signs the manifest.

**The no-FK correction.** Phase 2 claimed the absence of a foreign key from
``marketplace_certifications`` to ``certification_records`` was free. It is not,
and the claim was checked rather than restated (see
:meth:`MarketplaceStore.certifications`). The row surviving a transition is
the *easy* half; the pairing's **standing** staying true is the half that was
false, because a record demoted in place to ``failed`` or ``incompatible`` left
the catalogue promoting an artifact off a snapshot. Reads now resolve each
pairing against the authoritative record when plan 01 knows that fault and cell,
and fail closed when it cannot.

**The one clock read that decides.** See :data:`CLOCK_DECISION_NOTE`.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
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
    content_digest,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.certification import CertificationRecord, CertificationState
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.domain.marketplace import (
    SIGNATURE_TRUST_NOTICE,
    Artifact,
    ArtifactCertification,
    ArtifactClass,
    DeprecationNotice,
    DigestCheckState,
    RegistryFederation,
    RegistryRef,
    Revocation,
    SupplyChainRecord,
    TrustLabel,
    approval_refusals,
    blocking_revocations,
    check_digest,
    dispatch_refusal,
    dispatches,
    federated_registries,
    matching_certifications,
    pending_revocations,
    require_trust_label,
    trust_label,
)
from mayhem.domain.provider import ProviderError
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationRepository,
)
from mayhem.infra.audit_stream import AuditEntry, AuditStream
from mayhem.infra.certification_repository import CertificationRepository

if TYPE_CHECKING:
    import sqlite3
    from collections.abc import Callable

    from pydantic import BaseModel

    from mayhem.domain.certification import MatrixCell
    from mayhem.infra.store import Store
    from mayhem.providers.loader import ProviderLoader
    from mayhem.providers.sandbox import SandboxAdmission, SandboxProfile

__all__ = [
    "MARKETPLACE_ACTIVITY_KINDS",
    "MARKETPLACE_ACTIVITY_PREFIX",
    "MARKETPLACE_PRIVILEGED_ACTIONS",
    "MARKETPLACE_TABLES",
    "SIGNATURE_TRUST_NOTICE",
    "SIGNATURE_VERIFICATION_IMPLEMENTED",
    "CompatibilityVerdict",
    "DispatchAdmission",
    "ListingEntry",
    "MarketplaceActivity",
    "MarketplaceError",
    "MarketplaceEvidence",
    "MarketplaceRegistry",
    "MarketplaceStore",
    "PinState",
    "ResolvedPin",
    "StoredPin",
]


# ── the honesty constant, restated rather than imported ──────────────────────

#: Mirrors :data:`mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` and
#: :data:`mayhem.domain.marketplace.SIGNATURE_VERIFICATION_IMPLEMENTED`, both
#: ``False``. A third literal, same rule as Phase 1: the infra layer may not
#: import the providers layer for a constant, and three literals a test pins
#: equal are safer than one that could be edited in a hurry. If the signing lane
#: lands, all three change in the same commit and the promotion predicates are
#: re-audited before any label reads as provenance.
SIGNATURE_VERIFICATION_IMPLEMENTED: Final[bool] = False

#: The tables this module owns, named for the migration test that checks they
#: appear, disappear on ``down``, and come back on ``up``.
MARKETPLACE_TABLES: Final[tuple[str, ...]] = (
    "marketplace_registries",
    "marketplace_artifacts",
    "marketplace_certifications",
    "marketplace_supply_chain",
    "marketplace_revocations",
    "marketplace_pins",
)


# ── Phase 4: the activity vocabulary ─────────────────────────────────────────

#: Every marketplace activity that gets sealed, as the ``event_kind`` of its
#: :class:`~mayhem.domain.attestation.AttestedEvent`.
#:
#: A tuple rather than prose so a test, a grep, and this module cannot disagree
#: about the list — the same reason :mod:`mayhem.infra.audit_stream` keeps its
#: action vocabulary in one place. Nothing here is an authenticity claim; these
#: name *what happened to bytes in a catalog*.
ACTIVITY_ARTIFACT_PUBLISHED = "marketplace.artifact.published"
ACTIVITY_ARTIFACT_DEPRECATED = "marketplace.artifact.deprecated"
ACTIVITY_ARTIFACT_PINNED = "marketplace.artifact.pinned"
ACTIVITY_ARTIFACT_UNPINNED = "marketplace.artifact.unpinned"
ACTIVITY_ARTIFACT_INSTALLED = "marketplace.artifact.installed"
ACTIVITY_INSTALL_REFUSED = "marketplace.install.refused"
ACTIVITY_ARTIFACT_REVOKED = "marketplace.artifact.revoked"
ACTIVITY_TRUST_PUBLISHER = "marketplace.trust.publisher"
ACTIVITY_FEDERATION_CLOSED = "marketplace.federation.closed"

MARKETPLACE_ACTIVITY_KINDS: Final[tuple[str, ...]] = (
    ACTIVITY_ARTIFACT_PUBLISHED,
    ACTIVITY_ARTIFACT_DEPRECATED,
    ACTIVITY_ARTIFACT_PINNED,
    ACTIVITY_ARTIFACT_UNPINNED,
    ACTIVITY_ARTIFACT_INSTALLED,
    ACTIVITY_INSTALL_REFUSED,
    ACTIVITY_ARTIFACT_REVOKED,
    ACTIVITY_TRUST_PUBLISHER,
    ACTIVITY_FEDERATION_CLOSED,
)

#: Prefix on every marketplace activity id and manifest id. One namespace in
#: plan 12's two shared tables, so a consumer exporting one store's evidence can
#: tell marketplace activity apart from run evidence and from audit entries
#: without joining on anything else.
MARKETPLACE_ACTIVITY_PREFIX: Final[str] = "marketplace:"

#: The privileged actions this module records in
#: :class:`~mayhem.infra.audit_stream.AuditStream`.
#:
#: Three, and the list is the argument for it. *Installing* grants bytes
#: standing on a runtime, *revoking* withdraws it on every node that reads the
#: catalogue, and *trusting a publisher* is the act that lets one publisher's
#: certification evidence reach an artifact at all. Publishing a catalog row and
#: recording a deprecation are **not** privileged in the same sense: neither
#: grants nor withdraws standing on a runtime, and both are still sealed, so
#: they leave a chain without cluttering the privileged-action log with entries
#: no operator will ever filter for.
MARKETPLACE_PRIVILEGED_ACTIONS: Final[tuple[str, ...]] = (
    "audit.marketplace.artifact.installed",
    "audit.marketplace.artifact.revoked",
    "audit.marketplace.trust_publisher",
)

#: The principal recorded when a caller does not name one.
#:
#: This is a **declaration**, exactly like
#: :class:`~mayhem.domain.marketplace.PublisherDeclaration` and exactly like the
#: ``principal`` column in
#: :mod:`mayhem.infra.audit_stream`: the identity the writer recorded, with
#: nothing in this build able to check it. It says "the marketplace engine did
#: this on someone's behalf", not "this person did this".
MARKETPLACE_DEFAULT_PRINCIPAL: Final[str] = "marketplace.registry"

#: The one clock read in this module that *decides* something, stated once so a
#: reader does not have to infer it from a comment in a docstring.
#:
#: Every policy decision this module makes — resolve, verify, install, admit,
#: list, compatibility, federation — takes ``now`` as a parameter, so a policy
#: can be replayed and a test can prove a refusal without waiting out a
#: deadline. :meth:`MarketplaceRegistry.guarded_factory` is the single exception
#: and deliberately has no ``now``, because it runs at the moment a runtime is
#: *materialised* and a caller-supplied instant is precisely the stale value
#: that lets a revoked provider execute. Injecting a clock there would make the
#: one safety property this phase cannot compromise opt-out-able, which is
#: theatre in the exact sense the phrase is used elsewhere in this repository.
#:
#: The other wall-clock reads in this module are *stamps*, not decisions:
#: :func:`_stamp` and the attestation reading default to the clock and are
#: overridable by the caller on every path that takes one. Nothing about a
#: stamp can change a verdict, and a test pins that the two categories stay
#: apart.
CLOCK_DECISION_NOTE: Final[str] = (
    "guarded_factory is the only clock read that decides: every other policy "
    "decision takes an injected now so it can be replayed, and this one runs at "
    "runtime-materialisation time where a stale now would be the defect itself"
)


class MarketplaceError(DomainError):
    """The registry refused: a pin, an install, a listing, or a dispatch.

    Distinct from :class:`~mayhem.domain.marketplace.TrustLabelError`, which
    reports that *records* do not justify a class. This type reports that the
    *engine* would not do something — these are not the published bytes, the
    artifact is withdrawn, the provider was never loaded. The code is the first
    thing a caller routes on, so each refusal has its own rather than a bucket.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"[{code}] {message}")


# ── value types ──────────────────────────────────────────────────────────────


class PinState(StrEnum):
    """Whether a pin currently binds bytes, or is kept only as history.

    ``REMOVED`` rows are retained rather than deleted so an uninstall/reinstall
    drill is replayable and a supply-chain reader can still see that these bytes
    were once pinned here.
    """

    INSTALLED = "installed"
    REMOVED = "removed"


@dataclass(frozen=True, slots=True)
class StoredPin:
    """A pin row: an artifact version, its exact bytes, and the provider bound to it.

    The provider binding is *persistence* state, not domain state, and for the
    same reason as
    :class:`~mayhem.infra.certification_repository.StoredCertification` it travels
    beside the domain models rather than inside one:
    :class:`~mayhem.domain.marketplace.Artifact` has no provider field, and
    adding one would let an artifact claim which runtime executes it.
    """

    artifact_id: str
    version: str
    digest: str
    registry_id: str
    provider_id: str
    state: PinState
    installed_at: str
    removed_at: str = ""

    @property
    def ref(self) -> str:
        """``id@version`` — the identity a refusal or a listing quotes."""
        return f"{self.artifact_id}@{self.version}"

    @property
    def installed(self) -> bool:
        return self.state is PinState.INSTALLED


@dataclass(frozen=True, slots=True)
class ResolvedPin:
    """A pin resolved to exact bytes, with every record a caller must not skip.

    Carries the :class:`~mayhem.domain.marketplace.TrustLabel` rather than a
    class: :attr:`artifact_class` below is read off that label, so it cannot be
    constructed with a value the records do not support.
    """

    artifact: Artifact
    supply_chain: SupplyChainRecord | None
    label: TrustLabel
    installed: bool

    @property
    def ref(self) -> str:
        return self.artifact.ref

    @property
    def digest(self) -> str:
        """The bytes this pin resolves to. Never a range, never "latest"."""
        return self.artifact.digest

    @property
    def artifact_class(self) -> ArtifactClass:
        return self.label.artifact_class

    @property
    def notice(self) -> str:
        return SIGNATURE_TRUST_NOTICE

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact.artifact_id,
            "version": self.artifact.version,
            "digest": self.digest,
            "registry_id": self.artifact.registry.registry_id,
            "artifact_class": self.artifact_class.value,
            "installed": self.installed,
            "deprecated": self.artifact.is_deprecated,
            "meaning": self.label.meaning(),
            "notice": self.notice,
        }


@dataclass(frozen=True, slots=True)
class CompatibilityVerdict:
    """Whether an artifact's evidence speaks for the cell that exists here.

    The cell is the only compatibility surface an artifact has, and that is a
    fact rather than an omission: a plan-01
    :class:`~mayhem.domain.certification.CertificationRecord` certifies a fault
    *on a cell*, so the only question this build can answer honestly is whether a
    current record for **these exact bytes** was made on **this exact cell**.
    Evidence from another cell is evidence about another machine, and averaging
    it across cells is the thing plan 01 exists to prevent.
    """

    artifact_ref: str
    cell: str
    cell_fingerprint: str
    compatible: bool
    refusals: tuple[str, ...]
    certified_fault_ids: tuple[str, ...]

    @property
    def reason(self) -> str:
        """The first refusal, or ``""`` when the verdict is compatible."""
        return self.refusals[0] if self.refusals else ""

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_ref": self.artifact_ref,
            "cell": self.cell,
            "cell_fingerprint": self.cell_fingerprint,
            "compatible": self.compatible,
            "refusals": list(self.refusals),
            "certified_fault_ids": list(self.certified_fault_ids),
            "notice": SIGNATURE_TRUST_NOTICE,
        }


@dataclass(frozen=True, slots=True)
class ListingEntry:
    """One row of a catalog listing, and the label that row may display.

    The class is a property over the carried
    :class:`~mayhem.domain.marketplace.TrustLabel`, never a field — see the
    module docstring. ``meaning`` travels with it, because "official" on its own
    is the sentence this repository refuses to print.
    """

    artifact: Artifact
    label: TrustLabel
    supply_chain: SupplyChainRecord | None

    @property
    def artifact_class(self) -> ArtifactClass:
        return self.label.artifact_class

    @property
    def notice(self) -> str:
        return SIGNATURE_TRUST_NOTICE

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact.artifact_id,
            "version": self.artifact.version,
            "digest": self.artifact.digest,
            "registry_id": self.artifact.registry.registry_id,
            "artifact_class": self.artifact_class.value,
            "meaning": self.label.meaning(),
            "may_display_certified_state": self.label.may_display_certified_state,
            "certified_fault_ids": list(self.label.certified_fault_ids),
            "deprecated": self.artifact.is_deprecated,
            "dependency_count": len(self.artifact.dependencies),
            "declared_permissions": sorted(p.value for p in self.artifact.permissions),
            "verification_state": (
                self.supply_chain.verification_state.value
                if self.supply_chain is not None
                else "not_recorded"
            ),
            "notice": self.notice,
        }


@dataclass(frozen=True, slots=True)
class DispatchAdmission:
    """What admitting a dispatch established — and what it did not.

    ``announced_revocations`` is the honest middle state: a revocation exists for
    these bytes whose propagation deadline has *not* arrived. The dispatch
    proceeds, and this object says so out loud, because "we told you yesterday"
    and "we stopped it" are different claims and a report that collapses them
    reports an enforcement that has not happened.

    ``deprecated`` is here for the same reason. Deprecation does not stop an
    installed artifact from dispatching (see the module docstring for why), so if
    this is not surfaced then the only record that a withdrawn version is still
    running is the absence of a refusal.
    """

    artifact_ref: str
    digest: str
    provider_id: str
    label: TrustLabel
    profile: SandboxProfile
    sandbox_admission: SandboxAdmission
    deprecated: bool
    deprecation_reason: str
    announced_revocations: tuple[str, ...]

    @property
    def artifact_class(self) -> ArtifactClass:
        return self.label.artifact_class

    @property
    def sandbox_enforced(self) -> bool:
        """Whatever the loader's own admission concluded. Not this module's call."""
        return self.sandbox_admission.enforced

    @property
    def notice(self) -> str:
        return SIGNATURE_TRUST_NOTICE

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_ref": self.artifact_ref,
            "digest": self.digest,
            "provider_id": self.provider_id,
            "artifact_class": self.artifact_class.value,
            "meaning": self.label.meaning(),
            "profile_id": self.profile.profile_id,
            "sandbox_enforced": self.sandbox_enforced,
            "sandbox": self.sandbox_admission.to_dict(),
            "deprecated": self.deprecated,
            "deprecation_reason": self.deprecation_reason,
            "announced_revocations": list(self.announced_revocations),
            "notice": self.notice,
        }


@dataclass(frozen=True, slots=True)
class MarketplaceActivity:
    """One sealed marketplace activity, and the verdicts that prove it sealed.

    ``signature_state`` is always :data:`SIGNATURE_UNSIGNED_NO_SIGNING` and
    :attr:`signed` is always ``False``. They are here so a caller reading an
    activity cannot assume otherwise by omission: this build mints no signature
    bytes, has no key material, and no KMS/HSM custody, so a marketplace
    manifest attests **integrity** — these bytes are unaltered and in this order
    — and attests nothing whatsoever about who produced them.

    The reason string travels beside the state for the same reason plan 12
    stores one: a reader who finds an unsigned manifest is told why, rather
    than left to guess whether the absence is a bug or a phase boundary.
    """

    activity_id: str
    kind: str
    event: AttestedEvent
    manifest: Manifest
    signature_state: str
    signature_reason: str
    chain_verification: ChainVerification
    manifest_verification: ManifestVerification

    @property
    def sealed(self) -> bool:
        """Both verdicts clean. Integrity of the recorded bytes, nothing more."""
        return self.chain_verification.valid and self.manifest_verification.valid

    @property
    def signed(self) -> bool:
        """Always ``False``. See :data:`SIGNATURE_UNSIGNED_NO_SIGNING`."""
        return False

    @property
    def chain_root(self) -> str:
        """The root the manifest commits to."""
        return self.event.chain_link

    @property
    def payload(self) -> dict[str, object]:
        """The attested body — which bytes, which label, which digest."""
        return dict(self.event.payload)

    @property
    def notice(self) -> str:
        """Always :data:`~mayhem.domain.marketplace.SIGNATURE_TRUST_NOTICE`."""
        return SIGNATURE_TRUST_NOTICE

    def to_dict(self) -> dict[str, object]:
        return {
            "activity_id": self.activity_id,
            "kind": self.kind,
            "sealed": self.sealed,
            "signed": self.signed,
            "signature_state": self.signature_state,
            "signature_reason": self.signature_reason,
            "chain_root": self.chain_root,
            "manifest_digest": self.manifest.manifest_digest,
            "previous_manifest_digest": self.manifest.previous_manifest_digest,
            "chain_verification": self.chain_verification.to_dict(),
            "manifest_verification": self.manifest_verification.to_dict(),
            "payload": self.payload,
            "notice": self.notice,
        }


# ── sealing (plan 18 Phase 4) ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _InstallAttempt:
    """What one install attempt *offered*, so a refusal can be sealed precisely.

    Four values, and the reason they are grouped is that an install has two
    digests on purpose: ``requested_digest`` is what the caller intended to
    install, ``observed_digest`` is the sha256 of the bytes actually in hand. The
    refusal that matters most — the integrity one — is exactly the disagreement
    between them, so an evidence record of a refused install that carried only
    one of the two would be unable to say which check failed.
    """

    artifact_id: str
    version: str
    requested_digest: str
    observed_digest: str


class MarketplaceEvidence:
    """Seals marketplace activity into plan 12's attested chain.

    Reuse, not reinvention. This class owns no event type, no encoder, no chain
    rule and no verifier: every one of those belongs to
    :mod:`mayhem.domain.attestation` and is reached through
    :class:`~mayhem.infra.attestation_store.AttestationRepository`. What this
    class adds is the *catalogue-specific content* of a marketplace event —
    which artifact digest, which registry, which **derived** trust class — and
    the decision about what to seal.

    One activity, one chain
    -----------------------
    Plan 12's verifier defines a chain as starting at genesis, so
    ``attestation_chains.run_id`` is used the way
    :mod:`mayhem.infra.audit_stream` uses ``stream_id``: the activity id *is*
    the chain key. Ordering across activities is not lost — it is carried by
    the manifest chain, each manifest recording the previous marketplace
    manifest's digest in ``previous_manifest_digest`` — so an export of the
    manifests alone reconstructs the order the catalog moved in.

    The id is derived from the payload's own content digest
    (:func:`~mayhem.domain.attestation.content_digest`), so recording the same
    activity twice produces the same chain and the same manifest rather than a
    near-duplicate, and two genuinely different activities can never collide.
    Replay is therefore idempotent by construction, and an operator replaying a
    recorded drill gets the same digests back.

    Nothing here is signed
    ----------------------
    :meth:`seal` writes an unsigned manifest with the reason recorded beside it,
    exactly as :func:`~mayhem.infra.attestation_store.seal_run_evidence` does.
    This class has no signer parameter and cannot grow one without the signing
    lane that does not exist yet.
    """

    def __init__(
        self,
        store: Store,
        *,
        repository: AttestationRepository | None = None,
        activity_prefix: str = MARKETPLACE_ACTIVITY_PREFIX,
    ) -> None:
        self._store = store
        self._repository = repository if repository is not None else AttestationRepository(store)
        self._prefix = activity_prefix

    @property
    def repository(self) -> AttestationRepository:
        """Plan 12's repository, exposed so a caller can verify directly."""
        return self._repository

    @property
    def activity_prefix(self) -> str:
        return self._prefix

    @property
    def signature_state(self) -> str:
        """Always :data:`SIGNATURE_UNSIGNED_NO_SIGNING`."""
        return SIGNATURE_UNSIGNED_NO_SIGNING

    @property
    def signature_reason(self) -> str:
        """Why every marketplace manifest is unsigned, in plan 12's own words."""
        return UNSIGNED_REASON_NO_SIGNING

    @property
    def signed(self) -> bool:
        """Always ``False``. Authorship is not established anywhere in here."""
        return False

    # -- writing -------------------------------------------------------------

    def seal(
        self,
        kind: str,
        *,
        subject: str,
        payload: dict[str, object],
        recorded_at: AttestedTimestamp | None = None,
        retention_class: RetentionClass = RetentionClass.HOT,
    ) -> MarketplaceActivity:
        """Seal one activity: an event, a chain, and a manifest.

        ``subject`` is the human-facing identity of the thing acted on
        (``id@version#digest12``, a revocation id, a federation seed list); it
        goes into the payload under ``subject`` so a consumer reading only the
        sealed bytes can name the subject without a join.

        The event is verified *before* it is persisted and the manifest is
        verified before it is persisted, by plan 12's own verifiers — this class
        never writes bytes it has not first proved.

        Raises:
            MarketplaceError: If ``kind`` is not in
                :data:`MARKETPLACE_ACTIVITY_KINDS`, or if the derived chain or
                manifest fails verification. Nothing is written in either case.
        """
        if kind not in MARKETPLACE_ACTIVITY_KINDS:
            raise MarketplaceError(
                "marketplace.unknown_activity_kind",
                f"{kind!r} is not a marketplace activity kind; the vocabulary is "
                f"{', '.join(MARKETPLACE_ACTIVITY_KINDS)}",
            )
        reading = recorded_at or _reading()
        body = {**payload, "subject": subject, "activity_kind": kind}
        activity_id = f"{self._prefix}{kind}:{content_digest(body)[:32]}"
        (sealed,) = seal_events(
            (
                AttestedEvent(
                    event_id=f"{activity_id}:0",
                    event_kind=kind,
                    run_id=activity_id,
                    sequence=0,
                    payload=body,
                    recorded_at=reading,
                ),
            )
        )
        chain = verify_chain((sealed,))
        if not chain.valid:
            raise MarketplaceError(
                "marketplace.activity_chain_invalid",
                f"refusing to seal marketplace activity {kind!r}: "
                f"{'; '.join(chain.errors)}",
            )
        manifest = build_manifest(
            (sealed,),
            manifest_id=f"{activity_id}:manifest",
            run_id=activity_id,
            signer_identity="",
            trust_root_ref="",
            retention_class=retention_class,
            created_at=reading,
            previous_manifest_digest=self._previous_manifest_digest(),
        )
        manifest_check = verify_manifest(manifest, (sealed,))
        if not manifest_check.valid:
            raise MarketplaceError(
                "marketplace.activity_manifest_invalid",
                f"refusing to seal marketplace activity {kind!r}: "
                f"{'; '.join(manifest_check.errors)}",
            )
        self._repository.save_chain(activity_id, (sealed,), sealed_at=reading.wall_clock)
        self._repository.save_manifest(
            manifest,
            signature_state=SIGNATURE_UNSIGNED_NO_SIGNING,
            signature_reason=UNSIGNED_REASON_NO_SIGNING,
        )
        return MarketplaceActivity(
            activity_id=activity_id,
            kind=kind,
            event=sealed,
            manifest=manifest,
            signature_state=SIGNATURE_UNSIGNED_NO_SIGNING,
            signature_reason=UNSIGNED_REASON_NO_SIGNING,
            chain_verification=chain,
            manifest_verification=manifest_check,
        )

    def _previous_manifest_digest(self) -> str:
        """The newest marketplace manifest's digest, or genesis for the first.

        Insertion order rather than ``created_at`` because a caller may inject
        a ``recorded_at`` that predates an already-sealed activity; ordering by
        the timestamp a test supplied would let a replay reorder the catalogue's
        attested history. ``rowid`` is the write order, which is the only order
        that cannot be back-dated.
        """
        rows = self._store.query(
            "SELECT manifest_digest FROM attestation_manifests WHERE manifest_id GLOB ? "
            "ORDER BY rowid DESC LIMIT 1",
            (f"{self._prefix}*",),
        )
        return str(rows[0][0]) if rows else GENESIS_DIGEST

    # -- reading -------------------------------------------------------------

    def activities(self) -> tuple[str, ...]:
        """Every sealed activity id, in the order it was written."""
        rows = self._store.query(
            "SELECT manifest_id FROM attestation_manifests WHERE manifest_id GLOB ? "
            "ORDER BY rowid",
            (f"{self._prefix}*",),
        )
        return tuple(str(row[0]).removesuffix(":manifest") for row in rows)

    def load(self, activity_id: str) -> tuple[AttestedEvent, ...]:
        """The stored chain for one activity, in sequence order."""
        return self._repository.load_chain(activity_id)

    def verify(self, activity_id: str) -> ChainVerification:
        """Re-verify one activity's stored chain, offline.

        Plan 12's verifier plus a check of the stored root and event count, so a
        row edited to name a different root than its events produce is caught
        even when every event still hashes correctly.
        """
        return self._repository.verify_run_chain(activity_id)

    def verify_manifest(self, activity_id: str) -> ManifestVerification:
        """Re-verify one activity's stored manifest against its stored events.

        Raises:
            KeyError: If no manifest is stored for ``activity_id``.
        """
        return self._repository.verify_stored_manifest(f"{activity_id}:manifest")

    def signature_state_of(self, activity_id: str) -> tuple[str, str]:
        """``(signature_state, signature_reason)`` as stored.

        The reason comes back with the state so a caller reporting on the
        activity never has to invent an explanation for the absence.

        Raises:
            KeyError: If no manifest is stored for ``activity_id``.
        """
        return self._repository.load_signature_state(f"{activity_id}:manifest")


# ── the store ────────────────────────────────────────────────────────────────


class MarketplaceStore:
    """Persistence for the catalog, behind ``M0028_MARKETPLACE``.

    One transaction per write, one ``*_json`` column beside the derived columns so
    a reload is exact, and nothing derived cached: there is no column recording
    whether a revocation is in force, because that verdict changes with the clock
    and a stored copy would be wrong in the window between the deadline and the
    next write. Every enforcement decision re-reads ``propagation_deadline``
    against the caller's ``now``.

    Four properties a reader should be able to confirm by reading the DDL alone:
    no trust class column, the artifact digest in the certification primary key,
    ``signature_verified CHECK (signature_verified = 0)``, and a pin that must
    name 64 lowercase hex characters.

    Phase 4's three collaborators
    -----------------------------
    Constructed by default over the *same* :class:`~mayhem.infra.store.Store`,
    so sealing and audit are not opt-in and cannot be forgotten at a call site:

    * :class:`MarketplaceEvidence` — every catalog write seals an attested event
      and an unsigned manifest. See its docstring, and note that sealing is not
      signing.
    * :class:`~mayhem.infra.audit_stream.AuditStream` — the three actions in
      :data:`MARKETPLACE_PRIVILEGED_ACTIONS` are recorded as privileged actions.
    * :class:`~mayhem.infra.certification_repository.CertificationRepository` —
      the authority that decides whether a stored pairing is still evidence.
      See :meth:`certifications` for why the no-FK decision is not, on its own,
      sufficient.
    """

    def __init__(
        self,
        store: Store,
        *,
        evidence: MarketplaceEvidence | None = None,
        audit: AuditStream | None = None,
        certifications: CertificationRepository | None = None,
    ) -> None:
        self._store = store
        self._evidence = evidence if evidence is not None else MarketplaceEvidence(store)
        self._audit = audit if audit is not None else AuditStream(store)
        self._certifications = (
            certifications if certifications is not None else CertificationRepository(store)
        )

    @property
    def evidence(self) -> MarketplaceEvidence:
        """The sealing half, so a caller can verify what this store has attested."""
        return self._evidence

    @property
    def audit(self) -> AuditStream:
        """The privileged-action log this store writes into."""
        return self._audit

    @property
    def certifications_authority(self) -> CertificationRepository:
        """The plan-01 record store pairings are resolved against."""
        return self._certifications

    # -- sealing and audit (Phase 4) -----------------------------------------

    def seal_activity(
        self,
        kind: str,
        *,
        subject: str,
        payload: dict[str, object],
        now: datetime | None = None,
    ) -> MarketplaceActivity:
        """Seal one activity, stamped at the caller's instant when supplied.

        The stamp is the write's ``now``, not a fresh clock read, so a replayed
        drill produces byte-identical activity ids. See
        :data:`CLOCK_DECISION_NOTE` for why this is a stamp and not a decision.

        ``uncertainty_ms`` is ``0`` and ``source`` is ``"caller"``: the instant
        was supplied rather than measured, and the source string is what says so
        to a reader. :attr:`~mayhem.domain.attestation.AttestedTimestamp.is_exact`
        is a claim about a *measurement*, and a caller-injected instant is not
        one.
        """
        return self._evidence.seal(
            kind,
            subject=subject,
            payload=payload,
            recorded_at=AttestedTimestamp(
                wall_clock=_moment(now),
                monotonic_ns=0,
                uncertainty_ms=0.0,
                source="caller",
            ),
        )

    def audit_privileged(
        self,
        action: str,
        *,
        target: str,
        principal: str,
        detail: dict[str, object],
    ) -> None:
        """Record one privileged action through plan 12's own audit stream.

        No second format and no second log: this is
        :meth:`mayhem.infra.audit_stream.AuditStream.record` with an
        :class:`~mayhem.infra.audit_stream.AuditEntry`, so the entry is the same
        :class:`~mayhem.domain.attestation.AttestedEvent` type, canonicalized by
        the same encoder and verified by the same verifier as everything else in
        this repository.

        ``principal`` is what the caller declared. Nothing here authenticates it —
        no signature exists in this build — so it is recorded as a claim and
        never upgraded to a fact.
        """
        if action not in MARKETPLACE_PRIVILEGED_ACTIONS:
            raise MarketplaceError(
                "marketplace.unknown_privileged_action",
                f"{action!r} is not a marketplace privileged action; the vocabulary is "
                f"{', '.join(MARKETPLACE_PRIVILEGED_ACTIONS)}",
            )
        self._audit.record(
            AuditEntry(
                principal=principal or MARKETPLACE_DEFAULT_PRINCIPAL,
                action=action,
                target=target,
                detail=detail,
            )
        )

    # -- registries -----------------------------------------------------------

    def publish_registry(
        self,
        registry: RegistryRef,
        *,
        now: datetime | None = None,
    ) -> RegistryRef:
        """Record a catalogue, replacing any previous row for the same id.

        Federation edges are rewritten with the row, so a registry that gains or
        loses a peer is updated by publishing it again — there is no second place
        where a peer could be added and forgotten.
        """
        stamp = _stamp(now)
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO marketplace_registries "
                "(registry_id, display_name, scope, organization, federates_with_json, "
                " registry_json, created_at) VALUES (?,?,?,?,?,?,?)",
                _registry_row(registry, stamp),
            )
        return registry

    def registry(self, registry_id: str) -> RegistryRef | None:
        rows = self._store.query(
            "SELECT registry_json FROM marketplace_registries WHERE registry_id = ?",
            (registry_id,),
        )
        return RegistryRef.model_validate_json(str(rows[0][0])) if rows else None

    def registries(self) -> tuple[RegistryRef, ...]:
        """Every known catalogue, ordered by id so a closure walk is deterministic."""
        rows = self._store.query(
            "SELECT registry_json FROM marketplace_registries ORDER BY registry_id"
        )
        return tuple(RegistryRef.model_validate_json(str(row[0])) for row in rows)

    # -- artifacts ------------------------------------------------------------

    def publish_artifact(
        self,
        artifact: Artifact,
        *,
        supply_chain: SupplyChainRecord,
        now: datetime | None = None,
    ) -> Artifact:
        """Publish one artifact version together with its supply-chain record.

        The two are written in a single transaction and cross-checked first: a
        supply-chain record describing different bytes than the artifact it is
        filed under is the exact "verified against something else" failure Phase 1
        removed, so it is refused here rather than stored and noticed later. The
        write is an upsert, so re-declaring the same version replaces the row.

        The supply chain must carry at least one release entry whose digest is the
        artifact's own. ``marketplace_supply_chain`` CHECKs that, because a
        supply-chain record with no release history cannot answer the question a
        supply chain exists to answer: where did these bytes come from.

        The publish is sealed as :data:`ACTIVITY_ARTIFACT_PUBLISHED` (Phase 4), so
        "these bytes entered the catalog" is a fact a consumer of the exported
        chain can read. Publishing is **not** in
        :data:`MARKETPLACE_PRIVILEGED_ACTIONS`: it grants no standing on a
        runtime and withdraws none, so it belongs in the sealed chain and not in
        the privileged-action log.
        """
        written = self._write_artifact(artifact, supply_chain=supply_chain, now=now)
        moment = _moment(now)
        self.seal_activity(
            ACTIVITY_ARTIFACT_PUBLISHED,
            subject=artifact.label,
            payload=_artifact_payload(
                artifact,
                self.label(artifact, now=moment),
                kind=ACTIVITY_ARTIFACT_PUBLISHED,
                supply_chain=supply_chain,
                now=moment,
                recorded_at=_iso(moment),
            ),
            now=now,
        )
        return written

    def _write_artifact(
        self,
        artifact: Artifact,
        *,
        supply_chain: SupplyChainRecord,
        now: datetime | None,
    ) -> Artifact:
        """The row writes :meth:`publish_artifact` and :meth:`deprecate` share.

        Split out so a deprecation seals *one* activity naming the withdrawal
        rather than a publish and then a deprecation: a consumer reconstructing
        the catalogue's history from the chain should see one withdrawal, and
        reading it as "this version was republished" would be a second thing to
        explain away.
        """
        _require_same_bytes(artifact, supply_chain)
        stamp = _stamp(now)
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO marketplace_registries "
                "(registry_id, display_name, scope, organization, federates_with_json, "
                " registry_json, created_at) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(registry_id) DO NOTHING",
                _registry_row(artifact.registry, stamp),
            )
            # ``ON CONFLICT`` on the *primary key*, never ``INSERT OR REPLACE``:
            # the latter also resolves a conflict on the
            # ``(artifact_id, digest)`` unique index by deleting the other row, so
            # republishing the same bytes under a second version would silently
            # erase the first. With the conflict target named, that case is an
            # IntegrityError — which is what "one id, one digest" has to mean.
            conn.execute(
                "INSERT INTO marketplace_artifacts "
                "(artifact_id, version, digest, registry_id, publisher_id, license_id, "
                " changelog_ref, deprecation_json, permissions_json, dependencies_json, "
                " artifact_json, published_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(artifact_id, version) DO UPDATE SET "
                "digest = excluded.digest, registry_id = excluded.registry_id, "
                "publisher_id = excluded.publisher_id, license_id = excluded.license_id, "
                "changelog_ref = excluded.changelog_ref, "
                "deprecation_json = excluded.deprecation_json, "
                "permissions_json = excluded.permissions_json, "
                "dependencies_json = excluded.dependencies_json, "
                "artifact_json = excluded.artifact_json, "
                "published_at = excluded.published_at",
                (
                    artifact.artifact_id,
                    artifact.version,
                    artifact.digest,
                    artifact.registry.registry_id,
                    artifact.publisher.publisher_id,
                    artifact.license_id,
                    artifact.changelog_ref,
                    _model_json(artifact.deprecation),
                    json.dumps(sorted(p.value for p in artifact.permissions)),
                    json.dumps([dep.model_dump(mode="json") for dep in artifact.dependencies]),
                    artifact.model_dump_json(),
                    stamp,
                ),
            )
            self._write_supply_chain(conn, supply_chain, stamp=stamp)
        return artifact

    def deprecate(
        self,
        artifact_id: str,
        version: str,
        notice: DeprecationNotice,
        *,
        now: datetime | None = None,
    ) -> Artifact:
        """Withdraw one artifact version from new use.

        A narrow write rather than a re-publish, so withdrawing a version cannot
        quietly change the bytes, the dependencies, or the declared permissions in
        the same breath: only the notice moves.

        Sealed as :data:`ACTIVITY_ARTIFACT_DEPRECATED` (Phase 4), and *not*
        audited as a privileged action: a deprecation grants nothing and stops
        nothing at dispatch (see the module docstring on why revocation is the
        instrument that withdraws bytes). The sealed chain is where an operator
        goes to find out that a version was withdrawn.
        """
        artifact = self.artifact(artifact_id, version)
        if artifact is None:
            raise MarketplaceError(
                "marketplace.artifact_not_found",
                f"no artifact {artifact_id}@{version} is published, so there is nothing "
                "to deprecate",
            )
        withdrawn = Artifact.model_validate({**artifact.model_dump(), "deprecation": notice})
        chain = self.require_supply_chain(artifact_id, version)
        moment = _moment(now)
        written = self._write_artifact(withdrawn, supply_chain=chain, now=now)
        self.seal_activity(
            ACTIVITY_ARTIFACT_DEPRECATED,
            subject=withdrawn.label,
            payload=_artifact_payload(
                withdrawn,
                self.label(withdrawn, now=moment),
                kind=ACTIVITY_ARTIFACT_DEPRECATED,
                supply_chain=chain,
                now=moment,
                recorded_at=_iso(moment),
            )
            | {
                "deprecation_reason": notice.reason,
                "replaced_by": notice.replaced_by,
                "deprecation_announced_at": _iso(notice.announced_at),
            },
            now=now,
        )
        return written

    def artifact(self, artifact_id: str, version: str) -> Artifact | None:
        rows = self._store.query(
            "SELECT artifact_json FROM marketplace_artifacts WHERE artifact_id = ? AND version = ?",
            (artifact_id, version),
        )
        return Artifact.model_validate_json(str(rows[0][0])) if rows else None

    def artifacts(
        self,
        *,
        artifact_id: str = "",
        registry_id: str = "",
    ) -> tuple[Artifact, ...]:
        """Published artifacts, optionally narrowed to one id or one registry."""
        clauses: list[str] = []
        params: list[object] = []
        if artifact_id:
            clauses.append("artifact_id = ?")
            params.append(artifact_id)
        if registry_id:
            clauses.append("registry_id = ?")
            params.append(registry_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._store.query(
            f"SELECT artifact_json FROM marketplace_artifacts{where} ORDER BY artifact_id, version",
            tuple(params),
        )
        return tuple(Artifact.model_validate_json(str(row[0])) for row in rows)

    def versions(self, artifact_id: str) -> tuple[str, ...]:
        """Every published version of ``artifact_id``, ascending as text."""
        rows = self._store.query(
            "SELECT version FROM marketplace_artifacts WHERE artifact_id = ? ORDER BY version",
            (artifact_id,),
        )
        return tuple(str(row[0]) for row in rows)

    # -- certifications -------------------------------------------------------

    def link(
        self,
        certification: ArtifactCertification,
        *,
        now: datetime | None = None,
        principal: str = "",
    ) -> ArtifactCertification:
        """Append a record **paired with the digest it was made against**.

        Append-only, and the pairing is the primary key's first column: a
        :class:`~mayhem.domain.certification.CertificationRecord` on its own names
        a fault on a cell and nothing about any artifact, so storing it without
        ``artifact_digest`` would let one certified fault make every artifact in
        the catalog look evidenced. There is deliberately no foreign key to
        ``certification_records`` — a record ages in place there, and the catalog
        must be able to answer "were these bytes ever certified" without a join a
        later transition could erase.

        Phase 4 corrected the second half of that sentence: the row surviving is
        necessary but not sufficient, and :meth:`certifications` now resolves
        each pairing against the authoritative record. Read that method before
        trusting the docstring above as the whole design.

        Linking is :data:`ACTIVITY_TRUST_PUBLISHER` — the act by which one
        publisher's certification evidence reaches one artifact's bytes, and the
        first of the three :data:`MARKETPLACE_PRIVILEGED_ACTIONS`. It is sealed
        *and* audited, because an operator asking "how did these bytes become
        evidenced?" should not have to reconstruct the answer from a diff of the
        pairings table.

        Args:
            certification: The record paired with the digest it was made against.
            now: Write stamp, defaulting to the wall clock.
            principal: The identity recorded in the privileged-action log. A
                **declaration**: nothing in this build can authenticate it, so
                it defaults to :data:`MARKETPLACE_DEFAULT_PRINCIPAL` rather than
                to a guess about who is calling.
        """
        record = certification.record
        stamp = _stamp(now)
        with self._store.write() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(sequence), 0) AS seq FROM marketplace_certifications "
                "WHERE artifact_digest = ? AND fault_id = ?",
                (certification.artifact_digest, record.fault_id),
            ).fetchone()
            sequence = int(row["seq"]) + 1
            conn.execute(
                "INSERT INTO marketplace_certifications "
                "(artifact_digest, fault_id, sequence, cell_fingerprint, cell_label, state, "
                " expires_at, certification_json, linked_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    certification.artifact_digest,
                    record.fault_id,
                    sequence,
                    record.cell.fingerprint,
                    record.cell.label,
                    record.state.value,
                    _iso(record.expires_at),
                    certification.model_dump_json(),
                    stamp,
                ),
            )
        moment = _moment(now)
        artifact = self._artifact_for_digest(certification.artifact_digest)
        label = (
            trust_label(artifact, (certification,), now=moment)
            if artifact is not None
            else None
        )
        payload: dict[str, object] = {
            "activity_kind": ACTIVITY_TRUST_PUBLISHER,
            "artifact_digest": certification.artifact_digest,
            "fault_id": record.fault_id,
            "certification_label": record.label,
            "certification_state": record.state.value,
            "certification_expires_at": _iso(record.expires_at),
            "cell_label": record.cell.label,
            "cell_fingerprint": record.cell.fingerprint,
            "link_sequence": sequence,
            "recorded_at": _iso(moment),
            "signature_verification_implemented": SIGNATURE_VERIFICATION_IMPLEMENTED,
            "trust_notice": SIGNATURE_TRUST_NOTICE,
        }
        if artifact is not None and label is not None:
            payload |= {
                "artifact_id": artifact.artifact_id,
                "version": artifact.version,
                "registry_id": artifact.registry.registry_id,
                "registry_scope": artifact.registry.scope.value,
                "publisher_id": artifact.publisher.publisher_id,
                "publisher_is_declared_only": True,
                "artifact_class": label.artifact_class.value,
                "artifact_class_meaning": label.meaning(),
            }
        self.seal_activity(
            ACTIVITY_TRUST_PUBLISHER,
            subject=f"{certification.artifact_digest[:12]}:{record.fault_id}",
            payload=payload,
            now=now,
        )
        self.audit_privileged(
            "audit.marketplace.trust_publisher",
            target=f"{certification.artifact_digest[:12]}:{record.fault_id}",
            principal=principal,
            detail={
                "artifact_digest": certification.artifact_digest,
                "fault_id": record.fault_id,
                "certification_state": record.state.value,
                "publisher_id": artifact.publisher.publisher_id if artifact is not None else "",
                "publisher_is_declared_only": True,
            },
        )
        return certification

    def _artifact_for_digest(self, digest: str) -> Artifact | None:
        """The published artifact whose bytes are ``digest``, if one is.

        A pairing may legitimately be linked before the artifact is published —
        evidence is often recorded first and the release follows — so ``None`` is
        a real answer here rather than an error. When there is no artifact, the
        sealed payload names the digest, the fault and the record, and omits the
        artifact fields rather than inventing them.
        """
        rows = self._store.query(
            "SELECT artifact_json FROM marketplace_artifacts WHERE digest = ? "
            "ORDER BY artifact_id, version LIMIT 1",
            (digest,),
        )
        return Artifact.model_validate_json(str(rows[0][0])) if rows else None

    def certifications(self, *, artifact_digest: str = "") -> tuple[ArtifactCertification, ...]:
        """Every stored pairing, ordered by digest, fault, then sequence.

        Each pairing's *record* is resolved against the plan-01 record store
        before it is returned — see :meth:`_resolve_pairing` for why a snapshot
        alone is not the same answer. The digest pairing is returned unchanged,
        because that is the part this table owns.
        """
        if artifact_digest:
            rows = self._store.query(
                "SELECT certification_json FROM marketplace_certifications "
                "WHERE artifact_digest = ? ORDER BY artifact_digest, fault_id, sequence",
                (artifact_digest,),
            )
        else:
            rows = self._store.query(
                "SELECT certification_json FROM marketplace_certifications "
                "ORDER BY artifact_digest, fault_id, sequence"
            )
        return tuple(
            self._resolve_pairing(ArtifactCertification.model_validate_json(str(row[0])))
            for row in rows
        )

    def _resolve_pairing(self, certification: ArtifactCertification) -> ArtifactCertification:
        """Return this pairing carrying the record's *current* standing.

        Phase 2 asserted that having no foreign key from
        ``marketplace_certifications`` to ``certification_records`` was free. It
        is only half free, and this method is the half that was wrong.

        **What the no-FK decision does buy.** The row survives whatever plan 01
        does. A record that ages, is demoted, is invalidated, or is deleted
        cannot cascade the pairing away, so the catalog can always answer "were
        these bytes ever certified, and by whom" — which is a question about
        *history* and which no join could answer once the far side moved.

        **What it does not buy.** Survival is not truth. A pairing stores a
        *snapshot* of the record it was linked from, and a snapshot cannot
        follow an in-place transition:
        :meth:`~mayhem.infra.certification_repository.CertificationRepository.store_transition`
        rewrites ``state`` on the same row, so a record demoted to ``failed`` or
        moved to the terminal ``incompatible`` would leave the catalog still
        promoting an artifact off ``certified`` — reporting ``verified_community``
        for evidence that had been withdrawn. Time ageing is the one transition a
        snapshot survives unaided, because :func:`is_current_record` compares
        ``expires_at`` against the caller's ``now`` independently. Demotion and
        invalidation have no such independent check.

        **The resolution.** When the record store holds rows for this pairing's
        ``(fault_id, cell)``, the authoritative record decides, matched by the
        identity a transition provably cannot move. When the record store holds
        no rows at all for that fault, the catalog is the *only* authority for
        this pairing — it was recorded here and nowhere else — so the snapshot
        stands and ages by time exactly as Phase 2 described.

        **Fail closed.** If the record store knows the fault and the cell but
        cannot match this pairing's identity, the claim cannot be confirmed, so
        it is returned as ``stale`` rather than trusted. The row is still there
        for the history question; it simply no longer counts as evidence, and
        :func:`~mayhem.domain.marketplace.approval_refusals` reports it as
        ``artifact.certification_not_current`` rather than as a weak artifact.
        """
        record = certification.record
        stored = self._certifications.load(record.fault_id)
        if not stored:
            # The catalog recorded this pairing and plan 01 has never heard of
            # the fault, so there is no authority that could move it.
            return certification
        identity = _claim_identity(record)
        matches = [row for row in stored if _claim_identity(row.record) == identity]
        if not matches:
            return ArtifactCertification(
                artifact_digest=certification.artifact_digest,
                record=_withdrawn(
                    record,
                    f"the certification record this pairing names is no longer stored under "
                    f"that identity in the plan-01 record store (it holds "
                    f"{len(stored)} record(s) for {record.fault_id!r} on other cells or "
                    f"other certifications); an unconfirmable claim is not evidence",
                ),
            )
        authoritative = max(matches, key=lambda row: row.sequence).record
        return ArtifactCertification(
            artifact_digest=certification.artifact_digest,
            record=authoritative,
        )

    def certifications_for(self, artifact: Artifact) -> tuple[ArtifactCertification, ...]:
        """The pairings filed against ``artifact``'s own digest.

        Includes lapsed ones: ageing is a read-time decision here, exactly as in
        the certification repository, so a record that expired an hour ago stops
        counting an hour ago without anything having to rewrite it.
        """
        return self.certifications(artifact_digest=artifact.digest)

    # -- supply chain ---------------------------------------------------------

    def record_supply_chain(
        self,
        record: SupplyChainRecord,
        *,
        now: datetime | None = None,
    ) -> SupplyChainRecord:
        """Store or replace one artifact version's supply-chain record."""
        if not record.release_history:
            raise MarketplaceError(
                "marketplace.no_release_history",
                f"supply-chain record for {record.ref} lists no release event; a record with "
                "no release history cannot say which bytes it describes",
            )
        with self._store.write() as conn:
            self._write_supply_chain(conn, record, stamp=_stamp(now))
        return record

    def supply_chain(self, artifact_id: str, version: str) -> SupplyChainRecord | None:
        rows = self._store.query(
            "SELECT record_json FROM marketplace_supply_chain "
            "WHERE artifact_id = ? AND version = ?",
            (artifact_id, version),
        )
        return SupplyChainRecord.model_validate_json(str(rows[0][0])) if rows else None

    def require_supply_chain(self, artifact_id: str, version: str) -> SupplyChainRecord:
        """The stored record, or a refusal saying there is none."""
        record = self.supply_chain(artifact_id, version)
        if record is None:
            raise MarketplaceError(
                "marketplace.no_supply_chain_record",
                f"{artifact_id}@{version} has no stored supply-chain record; a catalog row "
                "without one cannot report a digest, an SBOM, or a declared permission set",
            )
        return record

    def _write_supply_chain(
        self,
        conn: sqlite3.Connection,
        record: SupplyChainRecord,
        *,
        stamp: str,
    ) -> None:
        """One supply-chain row. Called inside the caller's transaction only.

        The release-history check lives here rather than at each call site because
        this is the only place a supply-chain row is written, and the column
        layout (``release_head_digest``) cannot be filled without a head entry.
        """
        if not record.release_history:
            raise MarketplaceError(
                "marketplace.no_release_history",
                f"supply-chain record for {record.ref} lists no release event; a record with "
                "no release history cannot say which bytes it describes",
            )
        conn.execute(
            "INSERT OR REPLACE INTO marketplace_supply_chain "
            "(artifact_id, version, digest, publisher_id, publisher_json, verification_state, "
            " signature_verified, sbom_digest, sbom_json, dependency_count, "
            " declared_permissions_json, release_count, release_head_digest, record_json, "
            " updated_at) VALUES (?,?,?,?,?,?,0,?,?,?,?,?,?,?,?)",
            (
                record.artifact_id,
                record.version,
                record.digest,
                record.publisher.publisher_id,
                record.publisher.model_dump_json(),
                record.verification_state.value,
                record.sbom.digest if record.sbom is not None else "",
                _model_json(record.sbom),
                len(record.dependencies),
                json.dumps(sorted(p.value for p in record.declared_permissions)),
                len(record.release_history),
                record.release_history[-1].digest,
                record.model_dump_json(),
                stamp,
            ),
        )

    # -- revocations ----------------------------------------------------------

    def revoke(
        self,
        revocation: Revocation,
        *,
        now: datetime | None = None,
        principal: str = "",
    ) -> Revocation:
        """Record a withdrawal. One row per revocation id, replaceable.

        A revocation is a fact about a *decision*, so re-recording the same id
        with different content is an operator correcting a typo rather than a
        revocation being lifted. Lifting one means the deadline moves into the
        future, which this upsert permits and the history does not record.

        Sealed as :data:`ACTIVITY_ARTIFACT_REVOKED` and audited as
        :data:`MARKETPLACE_PRIVILEGED_ACTIONS`' second entry. A revocation is the
        second most consequential thing this store can do — it withdraws bytes on
        every node reading the catalogue — so both records are written, and the
        sealed payload carries the deadline, because "announced" and "in force"
        are different claims and a reader reconstructing the catalogue months
        later needs to know which one this was at the time.
        """
        stamp = _stamp(now)
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO marketplace_revocations "
                "(revocation_id, scope, reason, artifact_id, version, digest, publisher_id, "
                " registry_id, issued_at, propagation_deadline, detail, revocation_json, "
                " recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    revocation.revocation_id,
                    revocation.scope.value,
                    revocation.reason.value,
                    revocation.artifact_id or "",
                    revocation.version or "",
                    revocation.digest or "",
                    revocation.publisher_id or "",
                    revocation.registry_id or "",
                    _iso(revocation.issued_at),
                    _iso(revocation.propagation_deadline),
                    revocation.detail,
                    revocation.model_dump_json(),
                    stamp,
                ),
            )
        moment = _moment(now)
        self.seal_activity(
            ACTIVITY_ARTIFACT_REVOKED,
            subject=f"{revocation.revocation_id}:{revocation.names}",
            payload={
                "activity_kind": ACTIVITY_ARTIFACT_REVOKED,
                "revocation_id": revocation.revocation_id,
                "revocation_scope": revocation.scope.value,
                "revocation_reason": revocation.reason.value,
                "revocation_detail": revocation.detail,
                "revocation_names": revocation.names,
                "artifact_id": revocation.artifact_id or "",
                "version": revocation.version or "",
                "artifact_digest": revocation.digest or "",
                "publisher_id": revocation.publisher_id or "",
                "registry_id": revocation.registry_id or "",
                "issued_at": _iso(revocation.issued_at),
                "propagation_deadline": _iso(revocation.propagation_deadline),
                "in_force_at_record": revocation.is_in_force_at(now=moment),
                "recorded_at": _iso(moment),
                "signature_verification_implemented": SIGNATURE_VERIFICATION_IMPLEMENTED,
                "trust_notice": SIGNATURE_TRUST_NOTICE,
            },
            now=now,
        )
        self.audit_privileged(
            "audit.marketplace.artifact.revoked",
            target=f"{revocation.revocation_id}:{revocation.names}",
            principal=principal,
            detail={
                "revocation_id": revocation.revocation_id,
                "revocation_scope": revocation.scope.value,
                "revocation_reason": revocation.reason.value,
                "artifact_digest": revocation.digest or "",
                "propagation_deadline": _iso(revocation.propagation_deadline),
            },
        )
        return revocation

    def revocations(self) -> tuple[Revocation, ...]:
        """Every recorded withdrawal, ordered by id so a refusal is byte-stable."""
        rows = self._store.query(
            "SELECT revocation_json FROM marketplace_revocations ORDER BY revocation_id"
        )
        return tuple(Revocation.model_validate_json(str(row[0])) for row in rows)

    def blocking(self, artifact: Artifact, *, now: datetime) -> tuple[Revocation, ...]:
        """Revocations naming ``artifact`` whose deadline has arrived."""
        return blocking_revocations(artifact, self.revocations(), now=now)

    def pending(self, artifact: Artifact, *, now: datetime) -> tuple[Revocation, ...]:
        """Revocations naming ``artifact`` that are announced but not yet in force."""
        return pending_revocations(artifact, self.revocations(), now=now)

    # -- pins -----------------------------------------------------------------

    def install(
        self,
        artifact_id: str,
        version: str,
        digest: str,
        registry_id: str,
        provider_id: str,
        *,
        now: datetime | None = None,
    ) -> StoredPin:
        """Write a live pin binding exact bytes to a provider.

        A live pin is not silently repointed: if one is already installed for this
        ``(artifact_id, version)`` with different bytes, the refusal names both
        digests, because the pin is what an installed run's evidence cites and
        quietly changing it would make that evidence describe bytes that were
        never run. Remove the pin first, then install the new one.

        Sealed as :data:`ACTIVITY_ARTIFACT_PINNED`. This is the *pin* — the row
        that binds bytes to a provider id — and it is deliberately a different
        activity from :data:`ACTIVITY_ARTIFACT_INSTALLED`, which
        :meth:`MarketplaceRegistry.install` seals once the gates have passed. A
        consumer holding only the chain can therefore tell "these bytes were
        bound" from "these bytes were admitted onto this runtime", and the gap
        between the two is exactly what the gates in between are for.
        """
        if not provider_id:
            raise MarketplaceError(
                "marketplace.provider_id_required",
                f"pinning {artifact_id}@{version} requires the provider id whose "
                "registration will execute these bytes; a pin that names no runtime cannot "
                "be refused at dispatch",
            )
        stamp = _stamp(now)
        with self._store.write() as conn:
            live = conn.execute(
                "SELECT digest FROM marketplace_pins "
                "WHERE artifact_id = ? AND version = ? AND state = 'installed'",
                (artifact_id, version),
            ).fetchone()
            if live is not None and str(live["digest"]) != digest:
                raise MarketplaceError(
                    "marketplace.pin_already_held",
                    f"{artifact_id}@{version} is already pinned to digest {live['digest']} and "
                    f"cannot be repointed to {digest} while installed; remove the pin first, or "
                    "install a different version",
                )
            conn.execute(
                "INSERT INTO marketplace_pins "
                "(artifact_id, version, digest, registry_id, provider_id, state, installed_at, "
                " removed_at) VALUES (?,?,?,?,?,'installed',?,'') "
                "ON CONFLICT(artifact_id, version, digest) DO UPDATE SET "
                "registry_id = excluded.registry_id, provider_id = excluded.provider_id, "
                "state = 'installed', installed_at = excluded.installed_at, removed_at = ''",
                (artifact_id, version, digest, registry_id, provider_id, stamp),
            )
        moment = _moment(now)
        self.seal_activity(
            ACTIVITY_ARTIFACT_PINNED,
            subject=f"{artifact_id}@{version}#{digest[:12]}",
            payload={
                "activity_kind": ACTIVITY_ARTIFACT_PINNED,
                "artifact_id": artifact_id,
                "version": version,
                "artifact_digest": digest,
                "registry_id": registry_id,
                "provider_id": provider_id,
                "pin_state": PinState.INSTALLED.value,
                "installed_at": stamp,
                "recorded_at": _iso(moment),
                "signature_verification_implemented": SIGNATURE_VERIFICATION_IMPLEMENTED,
                "trust_notice": SIGNATURE_TRUST_NOTICE,
            },
            now=now,
        )
        return StoredPin(
            artifact_id=artifact_id,
            version=version,
            digest=digest,
            registry_id=registry_id,
            provider_id=provider_id,
            state=PinState.INSTALLED,
            installed_at=stamp,
        )

    def remove(
        self,
        artifact_id: str,
        version: str,
        *,
        now: datetime | None = None,
    ) -> StoredPin | None:
        """Mark a live pin removed, keeping the row as history.

        Returns ``None`` when there was nothing installed, so a caller can tell an
        uninstall from a no-op instead of inferring it from a count. Only the
        removal is sealed: a no-op uninstall is not an event, and sealing one
        would put "something happened here" in the chain about something that did
        not.
        """
        stamp = _stamp(now)
        with self._store.write() as conn:
            cursor = conn.execute(
                "UPDATE marketplace_pins SET state = 'removed', removed_at = ? "
                "WHERE artifact_id = ? AND version = ? AND state = 'installed'",
                (stamp, artifact_id, version),
            )
            if not cursor.rowcount:
                return None
        removed = self.pin(artifact_id, version)
        if removed is None:  # pragma: no cover — the UPDATE found the row
            return None
        self.seal_activity(
            ACTIVITY_ARTIFACT_UNPINNED,
            subject=f"{removed.ref}#{removed.digest[:12]}",
            payload={
                "activity_kind": ACTIVITY_ARTIFACT_UNPINNED,
                "artifact_id": removed.artifact_id,
                "version": removed.version,
                "artifact_digest": removed.digest,
                "registry_id": removed.registry_id,
                "provider_id": removed.provider_id,
                "pin_state": PinState.REMOVED.value,
                "removed_at": removed.removed_at,
                "recorded_at": stamp,
                "signature_verification_implemented": SIGNATURE_VERIFICATION_IMPLEMENTED,
                "trust_notice": SIGNATURE_TRUST_NOTICE,
            },
            now=now,
        )
        return removed

    def pin(self, artifact_id: str, version: str) -> StoredPin | None:
        """The most recent pin row for this version, live or removed."""
        rows = self._store.query(
            "SELECT * FROM marketplace_pins WHERE artifact_id = ? AND version = ? "
            "ORDER BY installed_at DESC, rowid DESC LIMIT 1",
            (artifact_id, version),
        )
        return _hydrate_pin(rows[0]) if rows else None

    def pins(self, *, state: PinState | None = None) -> tuple[StoredPin, ...]:
        """Pin rows, narrowed to a state when asked, ordered by artifact then version."""
        if state is None:
            rows = self._store.query(
                "SELECT * FROM marketplace_pins ORDER BY artifact_id, version, installed_at"
            )
        else:
            rows = self._store.query(
                "SELECT * FROM marketplace_pins WHERE state = ? ORDER BY artifact_id, version",
                (state.value,),
            )
        return tuple(_hydrate_pin(row) for row in rows)

    def installed(self, artifact_id: str = "") -> tuple[StoredPin, ...]:
        """Every live pin, optionally narrowed to one artifact."""
        if artifact_id:
            rows = self._store.query(
                "SELECT * FROM marketplace_pins "
                "WHERE state = 'installed' AND artifact_id = ? ORDER BY version",
                (artifact_id,),
            )
        else:
            rows = self._store.query(
                "SELECT * FROM marketplace_pins WHERE state = 'installed' "
                "ORDER BY artifact_id, version"
            )
        return tuple(_hydrate_pin(row) for row in rows)

    # -- derived, never stored ------------------------------------------------

    def label(self, artifact: Artifact, *, now: datetime) -> TrustLabel:
        """The label this artifact *can* hold, from the stored records.

        Derived on every read through
        :func:`~mayhem.domain.marketplace.trust_label`, from the pairings filed
        against this artifact's own digest. There is no column to read and no
        cache to go stale: the class is recomputed every time, so a record that
        lapsed five minutes ago changes the answer five minutes later with nothing
        having been written.
        """
        return trust_label(artifact, self.certifications_for(artifact), now=now)


# ── the engine ───────────────────────────────────────────────────────────────


class MarketplaceRegistry:
    """Pin resolution, compatibility, federation, listing, and the dispatch gate.

    Constructed with a :class:`MarketplaceStore` and the
    :class:`~mayhem.providers.loader.ProviderLoader` that admits the providers
    behind the artifacts. The loader is not optional and not decorative:
    :meth:`admit` ends by asking that loader for the sandbox enforcer over the
    profile it chose and running that loader's own admission, so a marketplace
    dispatch passes through the single enforcement point rather than around it.

    No decision here reads a clock. ``now`` is a parameter on :meth:`admit`,
    :meth:`compatibility`, :meth:`listing`, and :meth:`resolve`, so a policy can be
    replayed and a test can prove a refusal without waiting out a deadline. The
    one exception is :meth:`guarded_factory`, which must consult the real clock
    because it runs at the moment a runtime is materialised.
    """

    def __init__(self, *, store: MarketplaceStore, loader: ProviderLoader) -> None:
        self._store = store
        self._loader = loader

    @property
    def store(self) -> MarketplaceStore:
        """The persistence half, for callers that write rather than decide."""
        return self._store

    @property
    def loader(self) -> ProviderLoader:
        """The provider loader every dispatch is admitted through."""
        return self._loader

    # -- registries and federation -------------------------------------------

    def adopt_registry(self, registry: RegistryRef) -> RegistryRef:
        """Record a catalogue. The same operation for a private one and a public one."""
        return self._store.publish_registry(registry)

    def registries(self) -> tuple[RegistryRef, ...]:
        return self._store.registries()

    def federation(self) -> RegistryFederation | None:
        """The transitive closure of every stored registry's federation edges.

        ``None`` when no registry has been published yet, because
        :func:`~mayhem.domain.marketplace.federated_registries` refuses a
        federation with no seeds and this method is total: an empty catalogue has
        *no* federation rather than an empty one. ``None`` and "a closure that
        happens to be small" are different answers, so they are different values.

        Two things this does **not** answer, both of which Phase 1 settled:

        * not "is this registry official?" — officialness is an editorial fact
          about one id, not a graph property;
        * not "is this registry inside the federation?", which is trivially yes
          for every stored row. :func:`~mayhem.domain.marketplace.federated_registries`
          seeds the walk with *every* registry it is handed, so membership follows
          from being published. Federation is therefore a **distribution**
          relationship, and the honest engine work is storing the edges and
          computing the closure — there is no admission gate here to bypass,
          because a published private registry is a peer, not a peer-with-extra-standing.
        """
        registries = self._store.registries()
        if not registries:
            return None
        known = {registry.registry_id for registry in registries}
        dangling = sorted(
            {
                peer
                for registry in registries
                for peer in registry.federates_with
                if peer not in known
            }
        )
        if dangling:
            # Named here rather than caught as a ``KeyError`` from inside the walk:
            # the closure is computed over stored rows, so a peer nobody published
            # is a catalogue that cannot be walked, and "we federate with a
            # registry we do not have" is a fact an operator has to fix. Silently
            # dropping the edge would understate the federation; letting the walk
            # fail would report it as a crash.
            raise MarketplaceError(
                "marketplace.dangling_federation_edge",
                f"these registries name a federation peer that is not published in this "
                f"catalog: {', '.join(dangling)}; the closure cannot be computed over a "
                "registry with no row, so publish the peer or drop the edge",
            )
        return federated_registries(registries)

    def federates(self, registry_id: str) -> bool:
        """True when ``registry_id`` is inside the stored federation closure."""
        federation = self.federation()
        return federation is not None and federation.contains(registry_id)

    def seal_federation(
        self,
        federation: RegistryFederation | None = None,
        *,
        now: datetime | None = None,
    ) -> MarketplaceActivity:
        """Seal the federation closure as a Phase 4 activity.

        The closure is a *read* — nothing changed when it was computed — which is
        exactly why this is an explicit call rather than a side effect of
        :meth:`federation`. A method that silently sealed every invocation would
        put an attested event in the chain for every listing, every search, and
        every screen a Phase 3 surface draws, and an evidence chain that records
        "nothing happened" is a chain nobody can read. So an operator or a Phase
        3 surface decides *when* the closure is worth attesting, and this method
        is the decision point.

        What the payload deliberately does **not** say: nothing about promotion.
        A closure is a set of registry ids and this catalog shares bytes with all
        of them. :func:`~mayhem.domain.marketplace.classify_artifact` takes no
        registry argument, so a sealed federation cannot become standing, and the
        payload repeats
        :data:`~mayhem.domain.marketplace.SIGNATURE_TRUST_NOTICE` so a consumer
        reading only the chain cannot mistake membership for trust.

        Args:
            federation: The closure to seal; the stored one is computed when
                omitted.
            now: Write stamp, defaulting to the wall clock.

        Raises:
            MarketplaceError: ``marketplace.no_federation`` when there is no
                closure to seal — an empty catalog has *no* federation, and
                sealing an empty set of registry ids would be attesting to a
                closure that does not exist.
        """
        closure = self.federation() if federation is None else federation
        if closure is None:
            raise MarketplaceError(
                "marketplace.no_federation",
                "no registry has been published, so this catalog has no federation to "
                "close over; there is nothing to attest and an empty closure would be "
                "attesting to a set that does not exist",
            )
        moment = _moment(now)
        return self._store.seal_activity(
            ACTIVITY_FEDERATION_CLOSED,
            subject=f"{len(closure.registry_ids)} registries",
            payload={
                "activity_kind": ACTIVITY_FEDERATION_CLOSED,
                "seed_registry_ids": list(closure.seed_registry_ids),
                "registry_ids": list(closure.registry_ids),
                "federation_size": len(closure.registry_ids),
                "grants_any_standing": False,
                "recorded_at": _iso(moment),
                "signature_verification_implemented": SIGNATURE_VERIFICATION_IMPLEMENTED,
                "trust_notice": SIGNATURE_TRUST_NOTICE,
            },
            now=now,
        )

    def require_registry(self, registry_id: str) -> RegistryRef:
        """The stored registry, or a refusal naming what this catalog holds.

        This is the whole admission gate for a registry id, and it is small on
        purpose: :meth:`federation` explains why a published registry is already
        inside the closure, so a second check would be a check that cannot fail.
        """
        registry = self._store.registry(registry_id)
        if registry is None:
            known = [entry.registry_id for entry in self._store.registries()]
            raise MarketplaceError(
                "marketplace.registry_not_found",
                f"no registry {registry_id!r} is known to this catalog"
                + (f"; it federates {', '.join(known)}" if known else ""),
            )
        return registry

    # -- pins -----------------------------------------------------------------

    def resolve(
        self,
        artifact_id: str,
        *,
        version: str,
        digest: str = "",
        now: datetime | None = None,
    ) -> ResolvedPin:
        """Resolve a pin to exact bytes.

        ``version`` is required and never "latest": a pin that floats is a range
        wearing a pin's name, and the point of pinning is that the bytes a run
        used are nameable afterwards. ``digest`` is optional but checked when
        given — supply it whenever the caller has it, because it is the only part
        of the pin that says *which* bytes, and a version alone is ambiguous the
        moment a publisher ships a rebuild under the same version.

        Raises:
            MarketplaceError: ``marketplace.artifact_not_found`` when the id or
                version is unknown, ``marketplace.digest_mismatch`` when a supplied
                digest is not the published one. Both name the digests in full,
                because a truncated digest does not let an operator tell two
                artifacts apart.
        """
        artifact = self._store.artifact(artifact_id, version)
        if artifact is None:
            known = self._store.versions(artifact_id)
            raise MarketplaceError(
                "marketplace.artifact_not_found",
                f"no artifact {artifact_id}@{version} is published"
                + (f"; published versions are {', '.join(known)}" if known else ""),
            )
        if digest and digest != artifact.digest:
            raise MarketplaceError(
                "marketplace.digest_mismatch",
                f"{artifact_id}@{version} is published at digest {artifact.digest} but the pin "
                f"names {digest}; a pin that resolves to different bytes is not a pin",
            )
        return self._pin(artifact, now=now)

    def _pin(self, artifact: Artifact, *, now: datetime | None) -> ResolvedPin:
        """A resolved pin for an artifact the store already holds."""
        return ResolvedPin(
            artifact=artifact,
            supply_chain=self._store.supply_chain(artifact.artifact_id, artifact.version),
            label=self._store.label(artifact, now=_moment(now)),
            installed=self._live_pin(artifact.artifact_id, artifact.version) is not None,
        )

    def verify_bytes(
        self,
        artifact_id: str,
        version: str,
        observed_digest: str,
        *,
        now: datetime | None = None,
    ) -> SupplyChainRecord:
        """Compare the bytes in hand with the published digest, and write the verdict down.

        Integrity, and only integrity: a match proves the bytes were not modified,
        and the recorded :data:`~mayhem.domain.marketplace.DigestCheckState` says
        exactly that much. On a mismatch the refusal names both digests and the
        mismatch is *not* recorded — the row would then disagree with the
        published digest, and a reader is better served by the refusal naming them
        than by a row asserting a state the catalog cannot support. A matching
        observation is recorded, so "we hashed these bytes" is a durable fact
        rather than a claim.

        Raises:
            MarketplaceError: ``marketplace.artifact_not_found``,
                ``marketplace.digest_mismatch`` naming both digests, or
                ``marketplace.no_supply_chain_record`` when the version has none to
                record the verdict on.
        """
        artifact = self._store.artifact(artifact_id, version)
        if artifact is None:
            raise MarketplaceError(
                "marketplace.artifact_not_found",
                f"no artifact {artifact_id}@{version} is published to verify bytes against",
            )
        if observed_digest != artifact.digest:
            raise MarketplaceError(
                "marketplace.digest_mismatch",
                f"{artifact_id}@{version} is published at digest {artifact.digest} but the bytes "
                f"in hand digest to {observed_digest} (sha256); integrity is the only axis "
                "checked here, and it just failed",
            )
        record = self._store.require_supply_chain(artifact_id, version)
        checked = check_digest(record, observed_digest=observed_digest)
        self._store.record_supply_chain(checked, now=now)
        return checked

    def install(
        self,
        artifact_id: str,
        *,
        version: str,
        digest: str,
        provider_id: str,
        observed_digest: str,
        cell: MatrixCell | None = None,
        now: datetime | None = None,
        principal: str = "",
    ) -> ResolvedPin:
        """Install an artifact: pin it, having checked it, and record what it may not do.

        The gates, in order, every one of which refuses:

        1. the pin's digest must be the published digest
           (``marketplace.digest_mismatch``);
        2. the sha256 of the bytes actually being installed must equal that digest
           (``marketplace.digest_mismatch`` again, from
           :meth:`verify_bytes`, and it is checked before anything else so a
           tampered download is never treated as an ordinary version conflict);
        3. the artifact must not be deprecated (``marketplace.deprecated_install``)
           — deprecation governs new pins, and an install is a new pin;
        4. no revocation naming these bytes may already be in force
           (``marketplace.revoked``);
        5. if ``cell`` is supplied, the artifact's certification evidence must
           speak for that cell (:func:`compatibility`);
        6. a supply-chain record must exist for this version, because that is what
           a post-install audit reads. Checked by :meth:`verify_bytes`, which
           needs somewhere to record the digest verdict.

        ``digest`` and ``observed_digest`` are separate arguments on purpose. The
        first is what the caller *intends* to install; the second is what it
        *has*. Collapsing them into one argument is how "we checked the digest"
        becomes a claim about a file nobody hashed.

        Phase 4 (evidence)
        ------------------
        A successful install seals :data:`ACTIVITY_ARTIFACT_INSTALLED` and is
        audited as :data:`MARKETPLACE_PRIVILEGED_ACTIONS`' first entry. The sealed
        payload is the answer to the phase's reconstruction question — which
        digest, which registry, which **derived** class, with the label's own
        ``meaning`` and :data:`SIGNATURE_TRUST_NOTICE` beside the class word.

        A *refused* install seals :data:`ACTIVITY_INSTALL_REFUSED` instead, and
        is deliberately **not** audited as a privileged action: a refusal grants
        nothing, so putting it in the privileged-action log would dilute the log
        with entries that mean the opposite of what the log is for. It is still
        sealed, because "a tampered download of these bytes was offered to this
        catalogue and refused" is exactly the fact an incident review needs and
        cannot get from the absence of a pin.

        Args:
            principal: The identity recorded in the privileged-action log on
                success. A **declaration** — nothing here authenticates it.
        """
        moment = _moment(now)
        attempt = _InstallAttempt(
            artifact_id=artifact_id,
            version=version,
            requested_digest=digest,
            observed_digest=observed_digest,
        )
        try:
            resolved = self._install(
                artifact_id,
                version=version,
                digest=digest,
                provider_id=provider_id,
                observed_digest=observed_digest,
                cell=cell,
                now=now,
            )
        except MarketplaceError as exc:
            self._seal_refusal(attempt, exc, moment, now)
            raise
        self._store.seal_activity(
            ACTIVITY_ARTIFACT_INSTALLED,
            subject=resolved.artifact.label,
            payload=_artifact_payload(
                resolved.artifact,
                resolved.label,
                kind=ACTIVITY_ARTIFACT_INSTALLED,
                supply_chain=resolved.supply_chain,
                now=moment,
                recorded_at=_iso(moment),
            )
            | {
                "provider_id": provider_id,
                "pin_state": PinState.INSTALLED.value,
                "observed_digest": observed_digest,
                "integrity_verified": True,
            },
            now=now,
        )
        self._store.audit_privileged(
            "audit.marketplace.artifact.installed",
            target=resolved.artifact.label,
            principal=principal,
            detail={
                "artifact_digest": resolved.artifact.digest,
                "artifact_class": resolved.artifact_class.value,
                "registry_id": resolved.artifact.registry.registry_id,
                "publisher_id": resolved.artifact.publisher.publisher_id,
                "publisher_is_declared_only": True,
                "provider_id": provider_id,
            },
        )
        return resolved

    def _seal_refusal(
        self,
        attempt: _InstallAttempt,
        error: MarketplaceError,
        moment: datetime,
        now: datetime | None,
    ) -> None:
        """Seal one refused install attempt.

        Deliberately narrow in what it claims. It records that an attempt was
        made and refused, with the code and the message, and it does **not**
        record a class: the bytes were not admitted, so there is no label to
        report and inventing one would be the very overclaim this phase exists to
        prevent. Both digests are recorded — the one intended and the one
        observed — because for the integrity refusal those are the two facts that
        make the entry useful.
        """
        self._store.seal_activity(
            ACTIVITY_INSTALL_REFUSED,
            subject=f"{attempt.artifact_id}@{attempt.version}",
            payload={
                "activity_kind": ACTIVITY_INSTALL_REFUSED,
                "artifact_id": attempt.artifact_id,
                "version": attempt.version,
                "requested_digest": attempt.requested_digest,
                "observed_digest": attempt.observed_digest,
                "refusal_code": error.code,
                "refusal_message": str(error),
                "artifact_class": None,
                "artifact_class_meaning": (
                    "no label is reported for a refused install: the bytes were not admitted, "
                    "and a refusal is not evidence"
                ),
                "integrity_state": (
                    DigestCheckState.DIGEST_MISMATCHED.value
                    if error.code == "marketplace.digest_mismatch"
                    and attempt.observed_digest != attempt.requested_digest
                    else "not_checked"
                ),
                "recorded_at": _iso(moment),
                "signature_verification_implemented": SIGNATURE_VERIFICATION_IMPLEMENTED,
                "trust_notice": SIGNATURE_TRUST_NOTICE,
            },
            now=now,
        )

    def _install(
        self,
        artifact_id: str,
        *,
        version: str,
        digest: str,
        provider_id: str,
        observed_digest: str,
        cell: MatrixCell | None,
        now: datetime | None,
    ) -> ResolvedPin:
        """The gated body of :meth:`install`, with no evidence side effects."""
        pin = self.resolve(artifact_id, version=version, digest=digest, now=now)
        artifact = pin.artifact
        moment = _moment(now)
        self.verify_bytes(artifact_id, version, observed_digest, now=now)
        if artifact.deprecation is not None:
            raise MarketplaceError(
                "marketplace.deprecated_install",
                f"{artifact.ref} was withdrawn ({artifact.deprecation.reason!r}) and replaced "
                f"by {artifact.deprecation.replaced_by!r}; a deprecated version cannot be newly "
                "installed or newly pinned. Bytes already installed under an earlier pin keep "
                "dispatching until a revocation withdraws them",
            )
        if self._store.blocking(artifact, now=moment):
            raise MarketplaceError(
                "marketplace.revoked",
                dispatch_refusal(artifact, self._store.revocations(), now=moment),
            )
        if cell is not None:
            verdict = self.compatibility(artifact, cell, now=moment)
            if not verdict.compatible:
                raise MarketplaceError("marketplace.incompatible", verdict.reason)
        self._store.install(
            artifact_id,
            version,
            artifact.digest,
            artifact.registry.registry_id,
            provider_id,
            now=now,
        )
        return self._pin(artifact, now=now)

    def uninstall(
        self,
        artifact_id: str,
        version: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Remove a pin. ``False`` when nothing was installed."""
        return self._store.remove(artifact_id, version, now=now) is not None

    def installed(self, artifact_id: str = "") -> tuple[ResolvedPin, ...]:
        """Every live pin, resolved, so a caller sees the class and the bytes together."""
        moment = _moment(None)
        return tuple(
            self._pin(artifact, now=moment)
            for artifact in self._artifacts_for_pins(artifact_id)
        )

    def _artifacts_for_pins(self, artifact_id: str) -> tuple[Artifact, ...]:
        return tuple(
            artifact
            for pin in self._store.installed(artifact_id)
            if (artifact := self._store.artifact(pin.artifact_id, pin.version)) is not None
        )

    def approval_gate(self, artifact: Artifact, *, now: datetime | None = None) -> tuple[str, ...]:
        """Every reason ``artifact`` may not back a **new** approval.

        Delegates to the domain's :func:`~mayhem.domain.marketplace.approval_refusals`
        rather than restating it, because those rules are the plan's and there is
        one copy of them. :meth:`install` enforces the two withdrawal gates
        (``artifact.deprecated`` and ``artifact.revoked``); the evidence rules
        belong to approval, which is a separate decision with a separate caller.
        """
        return approval_refusals(
            artifact,
            self._store.certifications_for(artifact),
            self._store.revocations(),
            now=_moment(now),
        )

    # -- compatibility --------------------------------------------------------

    def compatibility(
        self,
        artifact: Artifact,
        cell: MatrixCell,
        *,
        now: datetime | None = None,
    ) -> CompatibilityVerdict:
        """Whether this artifact's evidence speaks for ``cell``.

        A current certification record for **this artifact's own digest**, made on
        **this exact cell**, is the only compatibility evidence an artifact has.
        Refusals, in order:

        * ``marketplace.no_certification_evidence`` — nothing current for these
          bytes on any cell, so no statement can be made about this runtime;
        * ``marketplace.cell_not_certified`` — evidence exists, but it was made on
          another cell. A record from a different kernel, engine version, or
          privilege mode describes another machine, and this verdict names the cell
          and the fingerprint it found instead of averaging them.

        A compatible verdict means "a fault this artifact contributed was certified
        on this cell, against these bytes". It is not a statement that the artifact
        is safe, correct, or authored by anyone in particular.
        """
        moment = _moment(now)
        supplied = self._store.certifications_for(artifact)
        current = matching_certifications(artifact, supplied, now=moment)
        on_cell = tuple(
            cert for cert in current if cert.record.cell.fingerprint == cell.fingerprint
        )
        refusals: list[str] = []
        if not current:
            refusals.append(
                f"marketplace.no_certification_evidence: {artifact.ref} has no current "
                f"certification record for its own digest at {moment.isoformat()}, so nothing "
                "has been demonstrated about these bytes on any runtime"
            )
        elif not on_cell:
            elsewhere = sorted({cert.record.cell.label for cert in current})
            refusals.append(
                f"marketplace.cell_not_certified: {artifact.ref} is certified on "
                f"{', '.join(elsewhere)} but this runtime is {cell.label} (fingerprint "
                f"{cell.fingerprint[:24]}…); a record made on another cell is evidence about "
                "another machine"
            )
        return CompatibilityVerdict(
            artifact_ref=artifact.ref,
            cell=cell.label,
            cell_fingerprint=cell.fingerprint,
            compatible=not refusals,
            refusals=tuple(refusals),
            certified_fault_ids=tuple(sorted({cert.record.fault_id for cert in on_cell})),
        )

    # -- listing --------------------------------------------------------------

    def listing(
        self,
        *,
        registry_id: str = "",
        now: datetime | None = None,
    ) -> tuple[ListingEntry, ...]:
        """Every listed artifact, each carrying the label its records support.

        A private registry is listed through exactly this call — the only
        difference is that its id must be a published one, because federation is
        distribution and a private catalogue is a peer like any other. Nothing
        about the resulting class differs, because
        :func:`~mayhem.domain.marketplace.classify_artifact` never sees the
        registry *set*; see the module docstring on federation.
        """
        moment = _moment(now)
        if registry_id:
            self.require_registry(registry_id)
        return tuple(
            self._entry(artifact, now=moment)
            for artifact in self._store.artifacts(registry_id=registry_id)
        )

    def listing_entry(
        self,
        artifact: Artifact,
        *,
        claimed: ArtifactClass | None = None,
        now: datetime | None = None,
    ) -> ListingEntry:
        """One listing row, refusing a ``claimed`` class the records do not support.

        ``claimed`` is a *request*, not an assignment: it goes straight to
        :func:`~mayhem.domain.marketplace.require_trust_label`, which is the only
        way in the system to ask for a class and which refuses by name. So a
        listing that wants to print "verified community" for an artifact with no
        current record for its digest raises
        :class:`~mayhem.domain.marketplace.TrustLabelError` before anything is
        returned — that refusal is the negative control the plan asks for.
        """
        moment = _moment(now)
        if claimed is not None:
            require_trust_label(
                artifact,
                self._store.certifications_for(artifact),
                claimed=claimed,
                now=moment,
            )
        return self._entry(artifact, now=moment)

    def _entry(self, artifact: Artifact, *, now: datetime) -> ListingEntry:
        return ListingEntry(
            artifact=artifact,
            label=self._store.label(artifact, now=now),
            supply_chain=self._store.supply_chain(artifact.artifact_id, artifact.version),
        )

    # -- the dispatch path ----------------------------------------------------

    def admit(
        self,
        artifact_id: str,
        *,
        version: str = "",
        now: datetime | None = None,
    ) -> DispatchAdmission:
        """Admit one dispatch of an installed artifact, or refuse it.

        This is the admission decision, and the order is the enforcement:

        1. the artifact must be **installed** — a live pin. This is the knowledge
           Phase 1's :func:`~mayhem.domain.marketplace.dispatches` did not have, and
           it is what lets this path answer the deprecation question (see the module
           docstring) rather than guess;
        2. a revocation naming these bytes whose propagation deadline has passed
           refuses the dispatch, with a message from
           :func:`~mayhem.domain.marketplace.dispatch_refusal` so the refusal names
           the record that caused it;
        3. deprecation does **not** refuse — it is reported on the admission;
        4. the *same* :class:`~mayhem.providers.loader.ProviderLoader` that admitted
           the provider is asked for the sandbox enforcer over the profile it chose,
           and its own ``SandboxEnforcer.admit()`` runs again here. A provider the
           loader would refuse is still refused by the loader's own exception; this
           method does not swallow or re-code it.

        Refusals: ``marketplace.not_installed``, ``marketplace.artifact_not_found``,
        ``marketplace.revoked``, and ``marketplace.provider_not_loaded``.
        """
        moment = _moment(now)
        pin = self._require_live_pin(artifact_id, version)
        artifact = self._require_artifact(pin)
        revocations = self._store.revocations()
        if not dispatches(artifact, revocations, now=moment):
            raise MarketplaceError(
                "marketplace.revoked",
                dispatch_refusal(artifact, revocations, now=moment),
            )
        profile, sandbox = self._loader_admission(pin.provider_id)
        deprecation = artifact.deprecation
        return DispatchAdmission(
            artifact_ref=artifact.ref,
            digest=artifact.digest,
            provider_id=pin.provider_id,
            label=self._store.label(artifact, now=moment),
            profile=profile,
            sandbox_admission=sandbox,
            deprecated=deprecation is not None,
            deprecation_reason=deprecation.reason if deprecation is not None else "",
            announced_revocations=tuple(
                f"{rev.revocation_id} (in force at {rev.propagation_deadline.isoformat()})"
                for rev in pending_revocations(artifact, revocations, now=moment)
            ),
        )

    def guarded_factory(
        self,
        artifact_id: str,
        *,
        version: str = "",
        factory: Callable[[], object],
    ) -> Callable[[], object]:
        """Wrap a runtime factory so revocation is re-checked when the bytes are built.

        :meth:`admit` is a decision taken before a run; this is the same rule
        applied at the moment :meth:`mayhem.providers.registry.ProviderRegistry.runtime`
        hands the runtime to a caller. A run admitted before a revocation's
        deadline that materialises its runtime after it is refused here — which is
        the whole point: **a revoked provider that still executes is the defect
        this phase exists to prevent**, and an admission-time check alone leaves
        exactly that window open.

        The one clock read that *decides* lives here on purpose, and there is
        deliberately no ``now`` parameter through which a caller could supply a
        stale one — see :data:`CLOCK_DECISION_NOTE` for the full argument.
        Everything else takes ``now`` so a policy can be replayed; this cannot,
        because it runs at materialisation time and a decision made against a
        stale ``now`` would be theatre.

        Raises:
            MarketplaceError: ``marketplace.not_installed``,
                ``marketplace.artifact_not_found``, or ``marketplace.revoked``.
        """
        pin = self._require_live_pin(artifact_id, version)

        def guarded() -> object:
            artifact = self._require_artifact(pin)
            revocations = self._store.revocations()
            moment = utc_now()
            if not dispatches(artifact, revocations, now=moment):
                raise MarketplaceError(
                    "marketplace.revoked",
                    dispatch_refusal(artifact, revocations, now=moment),
                )
            return factory()

        return guarded

    def _require_live_pin(self, artifact_id: str, version: str) -> StoredPin:
        """The live pin for this artifact, or a refusal that nothing is installed."""
        pin = (
            self._live_pin(artifact_id, version)
            if version
            else next(iter(self._store.installed(artifact_id)), None)
        )
        if pin is None:
            where = f"{artifact_id}@{version}" if version else artifact_id
            raise MarketplaceError(
                "marketplace.not_installed",
                f"{where} is not installed: only a pinned artifact version may be dispatched",
            )
        return pin

    def _live_pin(self, artifact_id: str, version: str) -> StoredPin | None:
        pin = self._store.pin(artifact_id, version)
        return pin if pin is not None and pin.installed else None

    def _require_artifact(self, pin: StoredPin) -> Artifact:
        artifact = self._store.artifact(pin.artifact_id, pin.version)
        if artifact is None:  # pragma: no cover — a pin is written beside its artifact
            raise MarketplaceError(
                "marketplace.artifact_not_found",
                f"pin {pin.ref} names an artifact that is no longer published",
            )
        return artifact

    def _loader_admission(self, provider_id: str) -> tuple[SandboxProfile, SandboxAdmission]:
        """The loader's own admission for ``provider_id``, run again at dispatch.

        Goes *through* :meth:`~mayhem.providers.loader.ProviderLoader.sandbox_enforcer`
        rather than constructing a :class:`~mayhem.providers.sandbox.SandboxEnforcer`
        here, because the profile must be the one the loader chose at load time and
        the enforcement posture must be the loader's own
        ``require_sandbox_enforcement`` setting. A built-in provider has no profile
        here, because it never passed through this loader — which is correct: a
        marketplace artifact's bytes must be admitted by the loader, and a built-in
        that was never admitted is not something this registry may run on an
        artifact's say-so.

        Raises:
            MarketplaceError: ``marketplace.provider_not_loaded`` when the loader
                holds no profile for this provider. Any other refusal — including
                the loader's own ``provider_sandbox_mechanism_unapplied`` — is left
                exactly as the loader raised it.
        """
        try:
            enforcer = self._loader.sandbox_enforcer(
                provider_id,
                require_enforced=self._loader.require_sandbox_enforcement,
            )
        except ProviderError as exc:
            if exc.code != "provider_not_found":
                raise
            raise MarketplaceError(
                "marketplace.provider_not_loaded",
                f"provider {provider_id!r} has no sandbox profile on this loader, so it never "
                f"passed provider admission: {exc}",
            ) from exc
        return enforcer.profile, enforcer.admit()


# ── helpers ──────────────────────────────────────────────────────────────────


def _claim_identity(record: CertificationRecord) -> tuple[str, ...]:
    """The parts of a certification record an in-place transition cannot move.

    :meth:`~mayhem.infra.certification_repository.CertificationRepository.store_transition`
    refuses to move ``fault_id`` or ``cell``, and its ``UPDATE`` touches only
    ``state``, ``outcome``, ``reason`` and ``bundle_hash`` — so ``certified_at``
    and the evidence bundle set are fixed for the life of a row, and together
    with the fault and cell they identify it.

    This tuple is what makes the read-time resolution in
    :meth:`MarketplaceStore._resolve_pairing` exact rather than approximate. It
    is deliberately **not** the record's digest: a transition *should* change
    that, and a resolution keyed on it could never find anything.
    """
    return (
        record.fault_id,
        record.cell.fingerprint,
        record.certified_at.isoformat() if record.certified_at is not None else "",
        *(ref.bundle_hash for ref in record.evidence),
    )


def _withdrawn(record: CertificationRecord, reason: str) -> CertificationRecord:
    """A record with its claim withdrawn in place, through the domain's validators.

    Rebuilt with :meth:`~pydantic.BaseModel.model_validate` rather than
    ``model_copy`` for the same reason :func:`mayhem.domain.certification._replace`
    does: the validators run, so this can never produce a record that
    construction would have refused.
    """
    return CertificationRecord.model_validate(
        {**record.model_dump(), "state": CertificationState.STALE, "reason": reason}
    )


def _reading(recorded_at: AttestedTimestamp | None = None) -> AttestedTimestamp:
    """The caller's reading, or a fresh wall-clock + monotonic pair.

    A **stamp**, not a decision: see :data:`CLOCK_DECISION_NOTE`. The monotonic
    half comes from :func:`time.monotonic_ns` rather than the wall clock, so a
    host whose clock steps mid-activity still orders its readings correctly — the
    same rule, and the same reason, as
    :func:`mayhem.infra.attestation_store._recorded_at`, which this deliberately
    mirrors rather than forks.
    """
    if recorded_at is not None:
        return recorded_at
    return AttestedTimestamp(
        wall_clock=utc_now(),
        monotonic_ns=time.monotonic_ns(),
        uncertainty_ms=0.0,
        source="system",
    )


def _artifact_payload(
    artifact: Artifact,
    label: TrustLabel,
    *,
    kind: str,
    supply_chain: SupplyChainRecord | None,
    now: datetime,
    recorded_at: str,
) -> dict[str, object]:
    """The attested body of an activity about one artifact version.

    This is the dictionary that answers the phase's question — *which bytes, under
    which label, from which digest* — so every one of those three is here, in
    full, alongside the two fields that stop it being read as more than it is:

    * ``signature_verification_implemented`` is
      :data:`SIGNATURE_VERIFICATION_IMPLEMENTED`, which is ``False``;
    * ``trust_notice`` is :data:`~mayhem.domain.marketplace.SIGNATURE_TRUST_NOTICE`.

    The class word travels *with* :meth:`TrustLabel.meaning`, the sentence that
    says what it does not establish, for the same reason
    :attr:`ListingEntry.to_dict` does: "official" on its own is the sentence this
    repository refuses to print. And the class is derived — it is read off a
    :class:`~mayhem.domain.marketplace.TrustLabel`, which has no class field, so
    there is no code path here that could assert one.

    ``publisher_id`` is recorded because the catalog needs to know whose bytes
    these are, and ``publisher_is_declared_only`` is recorded beside it because
    the honest sentence about that field is not optional.
    """
    return {
        "activity_kind": kind,
        "artifact_id": artifact.artifact_id,
        "version": artifact.version,
        "artifact_digest": artifact.digest,
        "registry_id": artifact.registry.registry_id,
        "registry_scope": artifact.registry.scope.value,
        "publisher_id": artifact.publisher.publisher_id,
        "publisher_is_declared_only": True,
        "artifact_class": label.artifact_class.value,
        "artifact_class_meaning": label.meaning(),
        "may_display_certified_state": label.may_display_certified_state,
        "certified_fault_ids": list(label.certified_fault_ids),
        "deprecated": artifact.is_deprecated,
        "integrity_state": (
            supply_chain.verification_state.value if supply_chain is not None else "not_recorded"
        ),
        "label_evaluated_at": now.isoformat(),
        "recorded_at": recorded_at,
        "signature_verification_implemented": SIGNATURE_VERIFICATION_IMPLEMENTED,
        "trust_notice": SIGNATURE_TRUST_NOTICE,
    }


def _moment(now: datetime | None) -> datetime:
    """A timezone-aware instant, defaulting to the wall clock.

    A stamp or a decision's *default*, never a decision's source: everything
    that can change a verdict takes ``now`` from its caller.
    """
    if now is None:
        return utc_now()
    _require_aware(now)
    return now


def _require_aware(moment: datetime) -> None:
    if moment.tzinfo is None:
        raise MarketplaceError(
            "marketplace.naive_timestamp",
            f"marketplace timestamps must be timezone-aware, got {moment!r}",
        )


def _iso(moment: datetime) -> str:
    """UTC ISO-8601, so a lexicographic comparison in SQL is chronological.

    Normalising here rather than trusting the caller is what makes
    ``CHECK (propagation_deadline > issued_at)`` a real constraint: two
    offset-aware timestamps that are the same instant can print differently.
    """
    _require_aware(moment)
    return moment.astimezone(UTC).isoformat()


def _stamp(now: datetime | None) -> str:
    """The write stamp for one row: the caller's instant, or the wall clock."""
    return _iso(now) if now is not None else utc_now().isoformat()


def _model_json(value: BaseModel | None) -> str:
    """``""`` for an absent value, the model's own JSON otherwise.

    A nullable column would do the same job, but an empty string keeps every
    "is this present?" question in one place and matches the convention the
    certification and attestation tables already use.
    """
    return "" if value is None else value.model_dump_json()


def _registry_row(registry: RegistryRef, stamp: str) -> tuple[object, ...]:
    return (
        registry.registry_id,
        registry.display_name,
        registry.scope.value,
        registry.organization or "",
        json.dumps(list(registry.federates_with)),
        registry.model_dump_json(),
        stamp,
    )


def _require_same_bytes(artifact: Artifact, record: SupplyChainRecord) -> None:
    """Refuse a supply-chain record filed under bytes it does not describe."""
    if (
        record.artifact_id != artifact.artifact_id
        or record.version != artifact.version
        or record.digest != artifact.digest
    ):
        raise MarketplaceError(
            "marketplace.supply_chain_digest_mismatch",
            f"supply-chain record for {record.ref} carries digest {record.digest} but it is "
            f"being published as {artifact.label}; a record filed against other bytes is not "
            "evidence about this artifact",
        )
    if record.publisher != artifact.publisher:
        raise MarketplaceError(
            "marketplace.supply_chain_publisher_mismatch",
            f"supply-chain record for {record.ref} names publisher "
            f"{record.publisher.publisher_id!r} but the artifact declares "
            f"{artifact.publisher.publisher_id!r}",
        )


def _hydrate_pin(row: sqlite3.Row) -> StoredPin:
    return StoredPin(
        artifact_id=str(row["artifact_id"]),
        version=str(row["version"]),
        digest=str(row["digest"]),
        registry_id=str(row["registry_id"]),
        provider_id=str(row["provider_id"]),
        state=PinState(str(row["state"])),
        installed_at=str(row["installed_at"]),
        removed_at=str(row["removed_at"]),
    )
