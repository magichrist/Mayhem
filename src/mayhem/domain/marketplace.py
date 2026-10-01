"""Marketplace artifacts, trust labels, and revocations (plan 18, Phase 1).

v1.1.0 plan 18 §Phase 1 (``docs/v1.1.0/18_MARKETPLACE_CATALOG.md``). This
module is the *type* half of the catalog: what an artifact **is**, what may be
**claimed** about it, and what **stops it running**. It has no engine, no
registry, and no network; Phase 2 adds the registry that resolves pins and
propagates revocations to dispatch.

The honesty problem, stated once and then enforced by construction
------------------------------------------------------------------------
The repository already holds the sharpest version of this problem. A fault
pack's SHA-256 content digest is checked — that is *integrity* — and
``mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED`` is ``False``
because the format carries no key, no algorithm, and no trust store. So the
format can tell you a pack was not **tampered with**, and can tell you nothing
at all about **who wrote it**.

A marketplace is where that gap becomes expensive: "verified" and "trusted"
are the two words a catalog listing reaches for first. This module therefore
makes three structural commitments instead of writing a careful docstring:

1. **A trust label has no class field.** :class:`TrustLabel` stores *facts* —
   the artifact's digest, the distribution scope, the deprecation notice, and
   the certification records — and exposes ``artifact_class`` as a **derived
   property**. There is no field to set, so there is no value a future change
   could write that the records do not support. ``extra="forbid"`` closes the
   obvious back door.
2. **Two axes are never collapsed.** The *distribution* axis (which registry
   the artifact was published to) and the *evidence* axis (whether a current
   :class:`~mayhem.domain.certification.CertificationRecord` certifies this
   exact digest) are separate facts. Federation is a third thing again, and it
   is deliberately **not an input** to promotion: peers share bytes, not
   standing. :func:`classify_artifact` takes no registry set, so a private
   registry cannot promote anything by being federated with the official one.
3. **A publisher is a declaration, never an authentication.**
   :class:`PublisherDeclaration` carries an id, a name, and a contact — the
   same standing as a ``# written by`` comment. There is no signature field, no
   key id, and no algorithm field anywhere in this module for a future change
   to fill in, and :data:`SIGNATURE_VERIFICATION_IMPLEMENTED` repeats the
   providers-layer flag as a second literal that a test pins equal to it.

What a label does and does not mean (repeated because the table is the page)
------------------------------------------------------------------------------
============================ =================================================
``ArtifactClass``           Establishes
============================ =================================================
``UNVERIFIED``              Nothing yet. No certification record, so no
                            certified state may be displayed. Never a claim
                            about the publisher.
``ORGANIZATION_PRIVATE``    Distributed on an organization-private registry.
                            A **distribution** fact, not a verification one:
                            the publisher is still only declared.
``VERIFIED_COMMUNITY``      A current certification record exists **for this
                            exact artifact digest**. Certification evidence
                            exists and the bytes match — nothing about the
                            author's identity, reputation, or honesty.
``OFFICIAL``                Distributed on the official Mayhem registry *and*
                            carrying the same certification evidence. An
                            editorial fact plus evidence; still no signature.
``DEPRECATED``              Withdrawn from new use. Overrides the class above
                            it and cannot back a new approval.
============================ =================================================

Every one of those rows is evidence about **bytes on a cell** or about **where
the bytes were published**. None of them is evidence about **who typed them**.
:data:`SIGNATURE_TRUST_NOTICE` is returned by :attr:`TrustLabel.notice` so a
renderer cannot print a label without the qualification sitting next to it.

Promotions are pure
-------------------
:func:`classify_artifact`, :func:`trust_label`, and :func:`require_trust_label`
read only their arguments; ``now`` is a parameter, never a clock read, so a
promotion decision can be replayed and a test can prove the refusal without
waiting out a TTL. :func:`require_trust_label` is the only way to *ask* for a
class, and it raises :class:`TrustLabelError` naming the requirement that was
missing — the shortcut does not exist, it just has a refusal message.

Revocation is a fact with a deadline
------------------------------------
A :class:`Revocation` names a scope (one artifact version, one publisher, or
one registry), a reason, and the instant by which the refusal must be in force.
Before that instant the revocation is **announced but not yet enforceable** —
:func:`pending_revocations` reports it separately from
:func:`blocking_revocations`, because "we told you yesterday" and "we stopped
it" are different claims. :func:`dispatches` is the pure predicate the Phase 2
dispatch path calls, and :func:`dispatch_refusal` names the revocation in the
message so a refusal is traceable to the record that caused it.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.certification import CertificationRecord, CertificationState
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.provider import ProviderPermission

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

__all__ = [
    "ARTIFACT_DIGEST_RE",
    "OFFICIAL_REGISTRY_ID",
    "PUBLISHER_DECLARATION_NOTICE",
    "SIGNATURE_TRUST_NOTICE",
    "SIGNATURE_VERIFICATION_IMPLEMENTED",
    "Artifact",
    "ArtifactCertification",
    "ArtifactClass",
    "ArtifactDeclarationError",
    "ArtifactDependency",
    "DeprecationNotice",
    "DigestCheckState",
    "PublisherDeclaration",
    "RegistryFederation",
    "RegistryRef",
    "RegistryScope",
    "ReleaseEvent",
    "Revocation",
    "RevocationReason",
    "RevocationScope",
    "SbomRef",
    "SourceChainEntry",
    "SourceStage",
    "SupplyChainRecord",
    "TrustLabel",
    "TrustLabelError",
    "applicable_revocations",
    "approval_refusals",
    "backs_new_approval",
    "blocking_revocations",
    "check_digest",
    "classify_artifact",
    "dispatch_refusal",
    "dispatches",
    "federated_registries",
    "is_current_record",
    "matching_certifications",
    "pending_revocations",
    "require_trust_label",
    "trust_label",
]


# ── the honesty constants ───────────────────────────────────────────────────

#: A SHA-256 hex digest, or nothing. Same shape as
#: ``mayhem.domain.certification.BUNDLE_DIGEST_RE``; kept as a separate literal
#: so the two cannot drift, and a test asserts they are the same pattern
#: rather than asserting one is defined in terms of the other.
ARTIFACT_DIGEST_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

#: Mirrors ``mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED``, which
#: is ``False`` in this build and is pinned ``False`` by the provider-declaration
#: and pack test suites. It is repeated here as a second literal rather than
#: imported: the domain layer may not depend on the loader layer, and two
#: literals that a test pins equal are safer than a dependency that cannot be
#: checked from here. If the signing lane ever lands, **both** literals change
#: in the same commit, and this module's promotion predicates have to be
#: re-audited before any label may read as provenance.
SIGNATURE_VERIFICATION_IMPLEMENTED: Final[bool] = False

#: The sentence that must accompany any rendering of a trust label. It is a
#: module constant, next to the flag above, so a renderer that reads the label
#: has the qualification within reach of the same import and cannot report a
#: label without the caveat structurally next to it.
SIGNATURE_TRUST_NOTICE: Final[str] = (
    "mayhem cannot verify artifact signatures: no public key, no algorithm, and no trust "
    "store exist in this build, so a publisher field is an unverified declaration of "
    "authorship. Only the sha256 content digest is checked, and that proves integrity, not "
    "provenance."
)

#: The same caveat narrowed to the publisher field itself, for a UI that shows
#: ``publisher: acme`` and needs the qualifier on that line.
PUBLISHER_DECLARATION_NOTICE: Final[str] = (
    "a publisher declaration records who says they published this artifact; it is not "
    "authentication, and nothing in this build can check it"
)

#: The registry id that means "distributed by the Mayhem project itself". An
#: ``OFFICIAL`` label requires this registry **and** certification evidence, and
#: even then it is an editorial fact plus evidence — not a signature.
OFFICIAL_REGISTRY_ID: Final[str] = "mayhem.official"


class TrustLabelError(DomainError):
    """A trust label was asked for that the supplied records do not justify."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"[{code}] {message}")


class ArtifactDeclarationError(DomainError):
    """An artifact was proposed for a class it cannot hold. Rarely reachable.

    Kept as its own type because the two failures need different reactions: a
    trust-label overclaim is a *reporting* bug (something displayed a label it
    did not derive), while a class the publisher legitimately declared —
    ``DEPRECATED`` with no notice, ``UNVERIFIED`` with a certification record
    pinned — is an *input* bug. Both are refused at construction.
    """

    def __init__(self, rule: str, message: str) -> None:
        self.rule = rule
        super().__init__(f"[{rule}] {message}")


# ── the label vocabulary ─────────────────────────────────────────────────────


class ArtifactClass(StrEnum):
    """What an artifact may be labelled, in ascending order of assertion.

    Attributes:
        UNVERIFIED: Listed, with no certification evidence. Cannot display a
            certified state. The floor every other class sits above.
        ORGANIZATION_PRIVATE: Published on an organization-private registry. A
            distribution fact; the publisher is still only declared.
        VERIFIED_COMMUNITY: A **current** certification record exists for this
            exact artifact digest. Evidence about bytes on a cell — nothing
            about who wrote them.
        OFFICIAL: Distributed on :data:`OFFICIAL_REGISTRY_ID` *and* carrying
            the same certification evidence. Editorial plus evidence; still no
            signature is checked.
        DEPRECATED: Withdrawn from new use. Terminal: it overrides every other
            class, and a deprecated artifact cannot back a new approval.
    """

    UNVERIFIED = "unverified"
    ORGANIZATION_PRIVATE = "organization_private"
    VERIFIED_COMMUNITY = "verified_community"
    OFFICIAL = "official"
    DEPRECATED = "deprecated"


#: The classes a catalog listing may display, weakest assertion first. Exported
#: so a renderer iterates the vocabulary rather than hard-coding an order that
#: can drift from the enum.
ASSERTION_ORDER: Final[tuple[ArtifactClass, ...]] = tuple(ArtifactClass)


class RegistryScope(StrEnum):
    """Which catalogue an artifact was published to.

    A distribution axis, deliberately separate from the evidence axis: knowing
    where bytes were published says nothing about whether they were certified,
    and knowing they were certified says nothing about where they came from.
    """

    OFFICIAL = "official"
    COMMUNITY = "community"
    ORGANIZATION_PRIVATE = "organization_private"


# ── declarations (never authentication) ──────────────────────────────────────


class PublisherDeclaration(BaseModel):
    """Who says they published this. That is the whole of it.

    Fields here are a name, an id, and a way to be contacted — the same standing
    as a comment header. There is no signature field, no key id, and no
    algorithm field for a later commit to fill in, because
    :data:`SIGNATURE_VERIFICATION_IMPLEMENTED` is ``False`` and adding such a
    field would be the first step of pretending otherwise.

    A private registry does not upgrade this into a statement of identity; it
    only states which organisation the declaration is *scoped* to.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    publisher_id: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=100)
    contact: str = Field(default="", max_length=200)
    organization: str | None = Field(default=None, max_length=100)

    @field_validator("publisher_id")
    @classmethod
    def _plausible_publisher_id(cls, value: str) -> str:
        if re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", value) is None:
            raise ValueError("publisher_id must be a lowercase dotted identifier")
        return value

    @property
    def notice(self) -> str:
        """:data:`PUBLISHER_DECLARATION_NOTICE`, so a renderer cannot skip it."""
        return PUBLISHER_DECLARATION_NOTICE

    @property
    def declaration_only(self) -> bool:
        """Always ``True``, and asserted by a test.

        Exists so that a caller who wants to branch on "do we know who this
        is?" has one obvious place to look and finds that the answer is fixed
        by the build, not by the data.
        """
        return True


class RegistryRef(BaseModel):
    """The catalogue an artifact was published to, plus who may peer with it.

    ``federates_with`` is a *distribution* relationship: it says these
    registries exchange bytes. It is not an input to
    :func:`classify_artifact`, because a registry that mirrors the official
    catalogue has not thereby certified anything.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    registry_id: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=100)
    scope: RegistryScope
    organization: str | None = Field(default=None, max_length=100)
    federates_with: tuple[str, ...] = ()

    @field_validator("registry_id")
    @classmethod
    def _plausible_registry_id(cls, value: str) -> str:
        if re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", value) is None:
            raise ValueError("registry_id must be a lowercase dotted identifier")
        return value

    @model_validator(mode="after")
    def _scope_matches_organization(self) -> RegistryRef:
        if self.scope is RegistryScope.ORGANIZATION_PRIVATE and not self.organization:
            raise ValueError(
                f"registry {self.registry_id!r} is organization-private but names no organization; "
                "a private catalogue with no owner is not a boundary"
            )
        if self.scope is not RegistryScope.ORGANIZATION_PRIVATE and self.organization:
            raise ValueError(
                f"registry {self.registry_id!r} has scope {self.scope.value!r} but names "
                f"organization {self.organization!r}; only an organization-private registry is "
                "scoped to an organization"
            )
        if self.registry_id in self.federates_with:
            raise ValueError(f"registry {self.registry_id!r} federates with itself")
        if len(set(self.federates_with)) != len(self.federates_with):
            raise ValueError(f"registry {self.registry_id!r} lists a federation peer twice")
        return self

    @property
    def is_official(self) -> bool:
        """True only for the official Mayhem registry id at official scope."""
        return self.registry_id == OFFICIAL_REGISTRY_ID and self.scope is RegistryScope.OFFICIAL


class ArtifactDependency(BaseModel):
    """One dependency of an artifact: a name, a constraint, and a digest if pinned.

    The digest is optional on purpose. An unpinned dependency is an honest
    statement ("this artifact needs something at this version range") and the
    catalog records it as such; a *pinned* one additionally carries the bytes
    that will actually be resolved, and the supply-chain record for the parent
    says which.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    constraint: str = Field(min_length=1, max_length=64)
    digest: str | None = None

    @field_validator("digest")
    @classmethod
    def _digest_is_sha256(cls, value: str | None) -> str | None:
        if value is not None and ARTIFACT_DIGEST_RE.match(value) is None:
            raise ValueError("dependency digest must be 64 lowercase hex characters (sha256)")
        return value

    @property
    def pinned(self) -> bool:
        """True when this dependency names the exact bytes, not just a range."""
        return self.digest is not None


class SbomRef(BaseModel):
    """A reference to an SBOM, never an embedding of one.

    Carries the SBOM's own digest so "the SBOM we published" is checkable
    against "the SBOM the artifact was built from" without the catalog holding
    a second copy that could drift.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    format: str = Field(min_length=1, max_length=32)
    digest: str
    locator: str = Field(default="", max_length=500)

    @field_validator("digest")
    @classmethod
    def _digest_is_sha256(cls, value: str) -> str:
        if ARTIFACT_DIGEST_RE.match(value) is None:
            raise ValueError("sbom digest must be 64 lowercase hex characters (sha256)")
        return value


class DeprecationNotice(BaseModel):
    """Why an artifact was withdrawn, and what replaces it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: str = Field(min_length=1, max_length=500)
    replaced_by: str = Field(min_length=1, max_length=64)
    announced_at: AwareDatetime

    @field_validator("replaced_by")
    @classmethod
    def _plausible_replacement(cls, value: str) -> str:
        if re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", value) is None:
            raise ValueError("replaced_by must be a lowercase dotted identifier")
        return value


class ReleaseEvent(BaseModel):
    """One entry in an artifact's release history."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = Field(min_length=1, max_length=64)
    digest: str
    released_at: AwareDatetime
    summary: str = Field(default="", max_length=500)

    @field_validator("digest")
    @classmethod
    def _digest_is_sha256(cls, value: str) -> str:
        if ARTIFACT_DIGEST_RE.match(value) is None:
            raise ValueError("release digest must be 64 lowercase hex characters (sha256)")
        return value


# ── the artifact ─────────────────────────────────────────────────────────────


class Artifact(BaseModel):
    """One version of one distributable thing, with no trust claim on it.

    Note what is **absent**: there is no ``class``, ``verified``, ``trusted``,
    or ``trust_label`` field. :attr:`trust_label` is a method that derives one
    from records the caller supplies, so an artifact cannot *be* labelled —
    only be *about* one. Together with ``extra="forbid"`` this means an
    artifact claiming its own standing is not a value this type can hold.

    The artifact carries a publisher **declaration** (see
    :class:`PublisherDeclaration`), a content digest, its dependency list, its
    license, and a changelog *reference*. Everything about whether those bytes
    did anything on a machine lives in
    :class:`~mayhem.domain.certification.CertificationRecord`, not here.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    version: str
    digest: str
    publisher: PublisherDeclaration
    registry: RegistryRef
    dependencies: tuple[ArtifactDependency, ...] = ()
    permissions: frozenset[ProviderPermission] = Field(default_factory=frozenset)
    license_id: str = Field(min_length=1, max_length=64)
    changelog_ref: str = Field(min_length=1, max_length=500)
    deprecation: DeprecationNotice | None = None

    @field_validator("artifact_id")
    @classmethod
    def _plausible_artifact_id(cls, value: str) -> str:
        if re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", value) is None:
            raise ValueError("artifact_id must be a lowercase dotted identifier")
        return value

    @field_validator("version")
    @classmethod
    def _plausible_version(cls, value: str) -> str:
        if re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}", value) is None:
            raise ValueError("artifact version must be a readable version string")
        return value

    @field_validator("digest")
    @classmethod
    def _digest_is_sha256(cls, value: str) -> str:
        if ARTIFACT_DIGEST_RE.match(value) is None:
            raise ValueError("artifact digest must be 64 lowercase hex characters (sha256)")
        return value

    @field_validator("changelog_ref")
    @classmethod
    def _changelog_reference_not_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("changelog_ref is required and must be a reference, not empty")
        return value

    @model_validator(mode="after")
    def _declared_shape_is_coherent(self) -> Artifact:
        names = [(dep.name, dep.constraint) for dep in self.dependencies]
        if len(set(names)) != len(names):
            raise ArtifactDeclarationError(
                "artifact.duplicate_dependency",
                f"artifact {self.ref} declares the same dependency twice: "
                f"{', '.join(sorted({f'{n}@{c}' for n, c in names}))}",
            )
        if self.registry.scope is RegistryScope.ORGANIZATION_PRIVATE and (
            self.publisher.organization != self.registry.organization
        ):
            raise ArtifactDeclarationError(
                "artifact.organization_mismatch",
                f"artifact {self.ref} is published to organization-private registry "
                f"{self.registry.registry_id!r} ({self.registry.organization!r}) but its "
                f"publisher declaration names {self.publisher.organization!r}",
            )
        return self

    @property
    def ref(self) -> str:
        """``id@version`` — the identity a refusal or a listing should quote."""
        return f"{self.artifact_id}@{self.version}"

    @property
    def label(self) -> str:
        """``id@version#digest12`` — identity plus enough bytes to be unambiguous."""
        return f"{self.ref}#{self.digest[:12]}"

    @property
    def is_deprecated(self) -> bool:
        """True when this exact version has been withdrawn from new use."""
        return self.deprecation is not None

    def trust_label(
        self,
        certifications: Iterable[ArtifactCertification],
        *,
        now: datetime,
    ) -> TrustLabel:
        """Derive the label this artifact *can* hold, given records. Pure.

        Never consults a clock, a registry, or a cache; ``now`` is an argument
        so the decision is replayable and testable. Raises
        :class:`TrustLabelError` if the supplied certifications describe
        different bytes than this artifact — a mismatched digest is a bug in
        the record store, not a weaker label.
        """
        return trust_label(self, certifications, now=now)

    def class_of(
        self,
        certifications: Iterable[ArtifactCertification],
        *,
        now: datetime,
    ) -> ArtifactClass:
        """The derived class, for a caller that only wants the word."""
        return classify_artifact(self, certifications, now=now)


class ArtifactCertification(BaseModel):
    """A certification record **plus** the artifact digest it was made against.

    The pairing is the whole mechanism, and it exists because
    :class:`~mayhem.domain.certification.CertificationRecord` identifies a
    fault on a *cell* and never names an artifact. Without this type a record
    could be pointed at any bytes at all, and "verified community" would mean
    "some fault was certified once, somewhere" — which is not a statement about
    this artifact.

    :func:`is_current_record` is the only definition of "current": the record
    grants live verification **and** has not passed ``expires_at`` at the
    supplied ``now``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_digest: str
    record: CertificationRecord

    @field_validator("artifact_digest")
    @classmethod
    def _digest_is_sha256(cls, value: str) -> str:
        if ARTIFACT_DIGEST_RE.match(value) is None:
            raise ValueError("artifact_digest must be 64 lowercase hex characters (sha256)")
        return value

    @property
    def is_current(self) -> bool:
        """State-based liveness only; the clock check needs ``now``."""
        return self.record.grants_live_verification

    def current_at(self, *, now: datetime) -> bool:
        """:func:`is_current_record` over this pairing."""
        return is_current_record(self, now=now)


# ── the trust label ──────────────────────────────────────────────────────────


class TrustLabel(BaseModel):
    """The facts a trust label is derived from — and nothing else.

    There is no ``artifact_class`` field here on purpose.
    :attr:`artifact_class` is a property computed by :func:`classify_artifact`
    from three stored facts:

    * ``registry_scope`` — the distribution axis;
    * ``deprecation`` — whether this exact version is withdrawn;
    * ``certifications`` — the evidence axis, each entry naming the artifact
      digest it was made against.

    Storing the class would put a claim in the type where a future change could
    write it without consulting a record, which is the exact failure the plan
    is written against. Deriving it means the only way to read "verified
    community" off this object is to supply a certification that is current for
    these bytes.

    :attr:`notice` returns :data:`SIGNATURE_TRUST_NOTICE` so a renderer cannot
    print the class word without the qualification reachable in the same breath.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    version: str
    artifact_digest: str
    registry_id: str
    registry_scope: RegistryScope
    certifications: tuple[ArtifactCertification, ...] = ()
    deprecation: DeprecationNotice | None = None
    evaluated_at: AwareDatetime

    @field_validator("artifact_digest")
    @classmethod
    def _digest_is_sha256(cls, value: str) -> str:
        if ARTIFACT_DIGEST_RE.match(value) is None:
            raise ValueError("artifact_digest must be 64 lowercase hex characters (sha256)")
        return value

    @property
    def ref(self) -> str:
        """``id@version`` — what a listing row identifies itself by."""
        return f"{self.artifact_id}@{self.version}"

    @property
    def artifact_class(self) -> ArtifactClass:
        """The class these facts support. Derived; see :func:`classify_artifact`."""
        return _classify(
            registry_scope=self.registry_scope,
            registry_id=self.registry_id,
            certifications=self.certifications,
            deprecation=self.deprecation,
            now=self.evaluated_at,
        )

    @property
    def current_certifications(self) -> tuple[ArtifactCertification, ...]:
        """Certifications that are live *and* unexpired at ``evaluated_at``."""
        return tuple(
            cert for cert in self.certifications if is_current_record(cert, now=self.evaluated_at)
        )

    @property
    def certified_fault_ids(self) -> tuple[str, ...]:
        """Faults with a current certification, in sorted order.

        These are the *certification* states, reported rather than re-invented:
        the marketplace displays what plan 01 recorded and never produces a
        maturity level of its own.
        """
        return tuple(sorted({cert.record.fault_id for cert in self.current_certifications}))

    @property
    def certified_states(self) -> tuple[CertificationState, ...]:
        """The record states behind :attr:`certified_fault_ids`, unsimplified."""
        return tuple(cert.record.state for cert in self.current_certifications)

    @property
    def may_display_certified_state(self) -> bool:
        """True only when a current certification exists for these bytes.

        An ``UNVERIFIED`` artifact answers ``False``, which is the plan's rule
        stated as a queryable property: it can never display a certified state
        because it has none to display.
        """
        return bool(self.current_certifications)

    @property
    def notice(self) -> str:
        """:data:`SIGNATURE_TRUST_NOTICE` — the qualification, always reachable."""
        return SIGNATURE_TRUST_NOTICE

    def meaning(self) -> str:
        """One sentence on what this class does and does not establish."""
        return CLASS_MEANING[self.artifact_class]

    def assertion_level(self) -> int:
        """Rank in :data:`ASSERTION_ORDER`, so a UI can pick a weakest-first view."""
        return ASSERTION_ORDER.index(self.artifact_class)


#: What each class establishes, and — in the same string — what it does not.
#: Kept as data so the semantics page in Phase 6 and a CLI renderer read the
#: same sentence rather than each inventing one.
CLASS_MEANING: Final[dict[ArtifactClass, str]] = {
    ArtifactClass.UNVERIFIED: (
        "no certification record: nothing has been demonstrated on any runtime, and the "
        "publisher is only declared"
    ),
    ArtifactClass.ORGANIZATION_PRIVATE: (
        "distributed on an organization-private registry: a distribution fact only, no "
        "certification evidence and no authentication of the publisher"
    ),
    ArtifactClass.VERIFIED_COMMUNITY: (
        "a current certification record exists for this exact artifact digest: evidence "
        "about bytes on a cell, NOT about who wrote them — signatures are not verified in "
        "this build"
    ),
    ArtifactClass.OFFICIAL: (
        "distributed on the official Mayhem registry with certification evidence for this "
        "exact digest: an editorial fact plus evidence, NOT a signature check — nothing "
        "here authenticates the publisher"
    ),
    ArtifactClass.DEPRECATED: (
        "withdrawn from new use: it cannot back a new approval, whatever certification "
        "evidence it once carried, and no signature of the publisher is checked either"
    ),
}


# ── promotion: pure predicates over certification records ────────────────────


def is_current_record(certification: ArtifactCertification, *, now: datetime) -> bool:
    """True when this record is a live claim that has not lapsed at ``now``.

    Two independent conditions, both required. ``grants_live_verification``
    covers the state machine (``certified`` / ``expiring`` grant, ``pending`` /
    ``stale`` / ``failed`` / ``incompatible`` do not). The ``expires_at``
    comparison covers time decay, which the state field alone does not: a
    ``certified`` record whose window has passed is not evidence, and this
    predicate says so without waiting for anything to rewrite it.

    Pure: ``now`` is a parameter. No clock is read, so the decision can be
    replayed and a test can prove the demotion without sleeping.
    """
    record = certification.record
    return record.grants_live_verification and now < record.expires_at


def matching_certifications(
    artifact: Artifact,
    certifications: Iterable[ArtifactCertification],
    *,
    now: datetime,
) -> tuple[ArtifactCertification, ...]:
    """The certifications that are about *these bytes* and still current.

    The digest filter is the load-bearing one: a record for a different
    artifact version is evidence about different bytes, and counting it would
    turn "some fault was certified once" into a statement about this artifact.
    """
    return tuple(
        cert
        for cert in certifications
        if cert.artifact_digest == artifact.digest and is_current_record(cert, now=now)
    )


def _classify(
    *,
    registry_scope: RegistryScope,
    registry_id: str,
    certifications: tuple[ArtifactCertification, ...],
    deprecation: DeprecationNotice | None,
    now: datetime,
) -> ArtifactClass:
    """The single decision every public entry point funnels through.

    Order matters and is deliberate: ``DEPRECATED`` first, because withdrawal
    must not be masked by a certification the artifact once earned, then the
    distribution axis, then evidence. Evidence is checked *after* distribution
    only in the sense that it is checked for both public classes — an
    organization-private artifact with a current record is still reported as
    ``ORGANIZATION_PRIVATE``, because the label means "this came from your own
    catalogue" and a certification record does not change where it came from.
    """
    if deprecation is not None:
        return ArtifactClass.DEPRECATED
    has_evidence = any(is_current_record(cert, now=now) for cert in certifications)
    if registry_scope is RegistryScope.OFFICIAL and registry_id == OFFICIAL_REGISTRY_ID:
        return ArtifactClass.OFFICIAL if has_evidence else ArtifactClass.UNVERIFIED
    if registry_scope is RegistryScope.ORGANIZATION_PRIVATE:
        return ArtifactClass.ORGANIZATION_PRIVATE
    return ArtifactClass.VERIFIED_COMMUNITY if has_evidence else ArtifactClass.UNVERIFIED


def classify_artifact(
    artifact: Artifact,
    certifications: Iterable[ArtifactCertification],
    *,
    now: datetime,
) -> ArtifactClass:
    """The class ``artifact`` may be displayed as, given ``certifications``.

    Pure and total: it returns a word, it never raises, and it reads nothing
    but its arguments. Note the signature — there is no registry *set* and no
    federation input, so being federated with the official catalogue cannot
    promote anything. Peers share bytes, not standing.
    """
    return _classify(
        registry_scope=artifact.registry.scope,
        registry_id=artifact.registry.registry_id,
        certifications=matching_certifications(artifact, certifications, now=now),
        deprecation=artifact.deprecation,
        now=now,
    )


def trust_label(
    artifact: Artifact,
    certifications: Iterable[ArtifactCertification],
    *,
    now: datetime,
) -> TrustLabel:
    """Build the label this artifact and these records justify. Pure.

    Certifications that describe other bytes are **dropped**, not rejected: a
    record store legitimately holds records for many artifacts, and refusing the
    whole label because one of them is about something else would be a worse
    failure than ignoring it. What is refused is the ambiguity of a record that
    claims to be about *these* bytes but cannot be — see
    :func:`require_trust_label`.
    """
    return TrustLabel(
        artifact_id=artifact.artifact_id,
        version=artifact.version,
        artifact_digest=artifact.digest,
        registry_id=artifact.registry.registry_id,
        registry_scope=artifact.registry.scope,
        certifications=matching_certifications(artifact, certifications, now=now),
        deprecation=artifact.deprecation,
        evaluated_at=now,
    )


def require_trust_label(
    artifact: Artifact,
    certifications: Iterable[ArtifactCertification],
    *,
    claimed: ArtifactClass,
    now: datetime,
) -> TrustLabel:
    """Return the label, or refuse the ``claimed`` class by name.

    This is the only way to *ask* for a class, and it is a request rather than
    an assignment: there is no code path here that writes a class into a
    model. Each refusal names the requirement that was missing, so the message
    says which record to go and produce rather than merely "not allowed".

    Refusals, all :class:`TrustLabelError`:

    * ``artifact_class_not_supported`` — a class word outside the vocabulary.
    * ``deprecated_artifact`` — a deprecated artifact cannot be displayed as
      anything else.
    * ``not_official_registry`` / ``registry_scope_mismatch`` — the
      distribution axis does not reach the claimed class. Checked before the
      evidence axis, because the registry is a permanent fact about the
      artifact while a missing record is a fact about what the caller supplied.
    * ``no_certification_record`` — anything above ``UNVERIFIED`` claimed with
      no record supplied at all.
    * ``certification_digest_mismatch`` — records were supplied but all are
      about other bytes, so none can support a claim about this artifact.
      Named separately because it is a record-store bug, not a weak artifact.
    * ``certification_not_current`` — a record exists for this digest but has
      lapsed or been invalidated.
    """
    if claimed not in ASSERTION_ORDER:
        raise TrustLabelError(
            "artifact_class_not_supported",
            f"{claimed!r} is not an artifact class; the vocabulary is "
            f"{', '.join(cls.value for cls in ASSERTION_ORDER)}",
        )
    supplied = tuple(certifications)
    matching = matching_certifications(artifact, supplied, now=now)
    derived = classify_artifact(artifact, supplied, now=now)
    label = trust_label(artifact, supplied, now=now)
    if claimed is derived:
        return label

    if artifact.deprecation is not None:
        raise TrustLabelError(
            "deprecated_artifact",
            f"{artifact.ref} is deprecated ({artifact.deprecation.reason!r}); it is displayed as "
            f"{derived.value} and cannot be displayed as {claimed.value}",
        )
    # Distribution is checked before evidence on purpose. Which registry an
    # artifact came from is a permanent fact about it; a missing record is a
    # fact about what the caller supplied, and naming the permanent blocker
    # first is the more actionable of the two messages.
    if claimed is ArtifactClass.OFFICIAL and not artifact.registry.is_official:
        raise TrustLabelError(
            "not_official_registry",
            f"{artifact.ref} claims official but was published to "
            f"{artifact.registry.registry_id!r} at scope {artifact.registry.scope.value!r}; the "
            f"official class requires {OFFICIAL_REGISTRY_ID!r}, and federation with it grants "
            "nothing",
        )
    if claimed is ArtifactClass.ORGANIZATION_PRIVATE and (
        artifact.registry.scope is not RegistryScope.ORGANIZATION_PRIVATE
    ):
        raise TrustLabelError(
            "registry_scope_mismatch",
            f"{artifact.ref} claims organization_private but was published to "
            f"{artifact.registry.registry_id!r} at scope {artifact.registry.scope.value!r}",
        )
    if claimed in (ArtifactClass.OFFICIAL, ArtifactClass.VERIFIED_COMMUNITY):
        same_digest = tuple(cert for cert in supplied if cert.artifact_digest == artifact.digest)
        if not supplied:
            raise TrustLabelError(
                "no_certification_record",
                f"{artifact.ref} claims {claimed.value} and no certification record was supplied; "
                f"the class means {label.meaning()}",
            )
        if not same_digest:
            raise TrustLabelError(
                "certification_digest_mismatch",
                f"{artifact.ref} claims {claimed.value} but every supplied certification is "
                "about other artifact digests; a record for different bytes is not evidence "
                "about this artifact",
            )
        if not matching:
            states = ", ".join(
                sorted({cert.record.state.value for cert in same_digest})
            )
            raise TrustLabelError(
                "certification_not_current",
                f"{artifact.ref} has {len(same_digest)} certification record(s) for its digest "
                f"in state {states}, none current at {now.isoformat()}; a lapsed claim is not "
                "evidence",
            )
    raise TrustLabelError(
        "no_certification_record",
        f"{artifact.ref} claims {claimed.value} but the records support {derived.value}: "
        f"{label.meaning()}",
    )


# ── revocation ───────────────────────────────────────────────────────────────


class RevocationScope(StrEnum):
    """What a revocation withdraws.

    Scopes are deliberately coarse. A revocation names a *publisher* or a
    *registry* to withdraw a whole class of versions at once, and names an
    exact ``artifact@version`` **plus its digest** to withdraw one. It does not
    take a fault id, because a revocation withdraws *bytes*, not a claim
    about a fault — a fault's certification standing is plan 01's business and
    has its own state machine.
    """

    ARTIFACT_VERSION = "artifact_version"
    PUBLISHER = "publisher"
    REGISTRY = "registry"


class RevocationReason(StrEnum):
    """Why bytes were withdrawn. A vocabulary, so a report can group them."""

    SECURITY_DEFECT = "security_defect"
    LICENSE = "license"
    MALFORMED = "malformed"
    SUPERSEDED = "superseded"
    POLICY = "policy"
    OTHER = "other"


class Revocation(BaseModel):
    """A withdrawal, a reason, and the deadline by which it must be enforced.

    ``propagation_deadline`` is the honest bit. A revocation issued now cannot
    stop a dispatch that is already in flight, so the record says when the
    refusal must be in force rather than pretending the announcement was
    instantaneous. Before that instant the revocation is visible
    (:func:`pending_revocations`) but not yet blocking
    (:func:`blocking_revocations`); "we told you yesterday" and "we stopped it"
    are different claims and the type keeps them apart.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    revocation_id: str
    scope: RevocationScope
    reason: RevocationReason
    detail: str = Field(min_length=1, max_length=500)
    issued_at: AwareDatetime
    propagation_deadline: AwareDatetime
    artifact_id: str | None = None
    version: str | None = None
    digest: str | None = None
    publisher_id: str | None = None
    registry_id: str | None = None

    @field_validator("revocation_id")
    @classmethod
    def _plausible_revocation_id(cls, value: str) -> str:
        if re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", value) is None:
            raise ValueError("revocation_id must be a lowercase dotted identifier")
        return value

    @field_validator("digest")
    @classmethod
    def _digest_is_sha256(cls, value: str | None) -> str | None:
        if value is not None and ARTIFACT_DIGEST_RE.match(value) is None:
            raise ValueError("revocation digest must be 64 lowercase hex characters (sha256)")
        return value

    @model_validator(mode="after")
    def _scope_is_complete(self) -> Revocation:
        """Each scope must carry exactly the fields that identify its target.

        An incomplete revocation is worse than none: it reads as "we withdrew
        something" while matching nothing. Refused here, at construction.
        """
        if self.propagation_deadline <= self.issued_at:
            raise InvariantViolationError(
                "revocation.deadline_before_issue",
                f"revocation {self.revocation_id!r} has propagation deadline "
                f"{self.propagation_deadline.isoformat()} at or before its issue time "
                f"{self.issued_at.isoformat()}",
            )
        artifact_fields = ("artifact_id", "version", "digest")
        by_scope: dict[RevocationScope, tuple[str, ...]] = {
            RevocationScope.ARTIFACT_VERSION: artifact_fields,
            RevocationScope.PUBLISHER: ("publisher_id",),
            RevocationScope.REGISTRY: ("registry_id",),
        }
        required = by_scope[self.scope]
        missing = [name for name in required if getattr(self, name) is None]
        if missing:
            raise InvariantViolationError(
                "revocation.incomplete_scope",
                f"revocation {self.revocation_id!r} has scope {self.scope.value!r} but names no "
                f"{', '.join(missing)}",
            )
        for name in ("publisher_id", "registry_id", *artifact_fields):
            if name not in required and getattr(self, name) is not None:
                raise InvariantViolationError(
                    "revocation.scope_overreach",
                    f"revocation {self.revocation_id!r} has scope {self.scope.value!r} but also "
                    f"names {name}; a revocation is withdrawn by exactly one scope",
                )
        return self

    @property
    def names(self) -> str:
        """The target, rendered for a refusal message."""
        if self.scope is RevocationScope.ARTIFACT_VERSION:
            return f"{self.artifact_id}@{self.version}#{self.digest}"
        if self.scope is RevocationScope.PUBLISHER:
            return f"publisher {self.publisher_id}"
        return f"registry {self.registry_id}"

    def applies_to(self, artifact: Artifact) -> bool:
        """Pure membership test: does this revocation name ``artifact``?"""
        if self.scope is RevocationScope.ARTIFACT_VERSION:
            return (
                self.artifact_id == artifact.artifact_id
                and self.version == artifact.version
                and self.digest == artifact.digest
            )
        if self.scope is RevocationScope.PUBLISHER:
            return self.publisher_id == artifact.publisher.publisher_id
        return self.registry_id == artifact.registry.registry_id

    def is_in_force_at(self, *, now: datetime) -> bool:
        """True once ``now`` has reached :attr:`propagation_deadline`."""
        return now >= self.propagation_deadline


def applicable_revocations(
    artifact: Artifact,
    revocations: Iterable[Revocation],
) -> tuple[Revocation, ...]:
    """Every revocation naming ``artifact``, in force or not.

    Deterministic order — sorted by ``revocation_id`` — so a refusal message
    built from this is byte-stable and a test can assert on it.
    """
    return tuple(
        sorted(
            (rev for rev in revocations if rev.applies_to(artifact)),
            key=lambda rev: rev.revocation_id,
        )
    )


def blocking_revocations(
    artifact: Artifact,
    revocations: Iterable[Revocation],
    *,
    now: datetime,
) -> tuple[Revocation, ...]:
    """Revocations naming ``artifact`` whose deadline has arrived."""
    return tuple(
        rev
        for rev in applicable_revocations(artifact, revocations)
        if rev.is_in_force_at(now=now)
    )


def pending_revocations(
    artifact: Artifact,
    revocations: Iterable[Revocation],
    *,
    now: datetime,
) -> tuple[Revocation, ...]:
    """Revocations naming ``artifact`` that are announced but not yet in force.

    Kept separate because the gap is the interesting part: an operator who
    published a revocation five minutes ago is running a system that can still
    dispatch the artifact, and a report that collapses the two states is
    reporting an enforcement that has not happened.
    """
    return tuple(
        rev
        for rev in applicable_revocations(artifact, revocations)
        if not rev.is_in_force_at(now=now)
    )


def dispatches(
    artifact: Artifact,
    revocations: Iterable[Revocation],
    *,
    now: datetime,
) -> bool:
    """True when ``artifact`` may be dispatched at ``now``.

    The single predicate the Phase 2 dispatch path calls. Note what it does
    **not** check: a deprecated artifact still dispatches, because
    deprecation governs new approvals and pinning, not whether bytes that are
    already installed may run — a decision the plan leaves to Phase 2's
    admission path, which is where "already running" is knowable.
    """
    return not blocking_revocations(artifact, revocations, now=now)


def dispatch_refusal(
    artifact: Artifact,
    revocations: Iterable[Revocation],
    *,
    now: datetime,
) -> str:
    """The refusal message, naming the revocation that caused it.

    Empty string when :func:`dispatches` is true, so the caller can branch on
    truthiness without a second predicate. A refusal that does not name its
    record is not traceable, which is the same standard
    :func:`dispatch_refusal` exists to meet.
    """
    blocking = blocking_revocations(artifact, revocations, now=now)
    if not blocking:
        return ""
    first = blocking[0]
    return (
        f"{artifact.ref} refused: revocation {first.revocation_id} withdrew {first.names} "
        f"({first.reason.value}) and its propagation deadline "
        f"{first.propagation_deadline.isoformat()} has passed; detail: {first.detail}"
    )


# ── approvals ────────────────────────────────────────────────────────────────


def approval_refusals(
    artifact: Artifact,
    certifications: Iterable[ArtifactCertification],
    revocations: Iterable[Revocation],
    *,
    now: datetime,
) -> tuple[str, ...]:
    """Every reason ``artifact`` may not back a *new* approval, in a fixed order.

    Returns problems rather than raising, so a pre-install screen can show all
    of them at once instead of making an operator discover them one refusal at
    a time. Empty tuple means the artifact may back a new approval.

    The rules, each a distinct code so a caller can branch:

    * ``artifact.deprecated`` — the plan's rule: a deprecated artifact cannot
      back a new approval. Not overridable by evidence, because withdrawal is
      a statement about the future and evidence is about the past.
    * ``artifact.revoked`` — a revocation naming these bytes is in force.
    * ``artifact.unverified`` — no current certification record for this exact
      digest, so an approval would rest on a declaration and nothing else.
    * ``artifact.digest_mismatch`` — records were supplied but none are about
      these bytes, which is a record-store problem rather than a weak artifact
      and is reported as its own code.
    """
    supplied = tuple(certifications)
    refusals: list[str] = []
    if artifact.deprecation is not None:
        refusals.append(
            f"artifact.deprecated: {artifact.ref} was withdrawn "
            f"({artifact.deprecation.reason!r}); it cannot back a new approval"
        )
    if blocking_revocations(artifact, revocations, now=now):
        first = blocking_revocations(artifact, revocations, now=now)[0]
        refusals.append(
            f"artifact.revoked: {artifact.ref} is withdrawn by revocation "
            f"{first.revocation_id} ({first.reason.value})"
        )
    matching = matching_certifications(artifact, supplied, now=now)
    if not matching:
        same_digest = [cert for cert in supplied if cert.artifact_digest == artifact.digest]
        if same_digest:
            refusals.append(
                f"artifact.certification_not_current: {artifact.ref} has "
                f"{len(same_digest)} record(s) for its digest, none current at {now.isoformat()}"
            )
        elif supplied:
            refusals.append(
                f"artifact.digest_mismatch: {artifact.ref} was approved against records that "
                "are all about other artifact digests"
            )
        else:
            refusals.append(
                f"artifact.unverified: {artifact.ref} has no certification record; an approval "
                "would rest on a publisher declaration alone"
            )
    return tuple(refusals)


def backs_new_approval(
    artifact: Artifact,
    certifications: Iterable[ArtifactCertification],
    revocations: Iterable[Revocation],
    *,
    now: datetime,
) -> bool:
    """True when :func:`approval_refusals` is empty for this artifact."""
    return not approval_refusals(artifact, certifications, revocations, now=now)


# ── federation ───────────────────────────────────────────────────────────────


class RegistryFederation(BaseModel):
    """The transitive closure of a set of registries' federation edges.

    A value rather than a graph walk, so a catalogue can be reasoned about (and
    tested) without holding the whole registry table. It exists to answer "is
    this registry inside our federation?" for Phase 3 — deliberately *not* to
    answer "is this registry official?", because federation is distribution and
    officialness is a separate editorial fact.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    seed_registry_ids: tuple[str, ...]
    registry_ids: tuple[str, ...]

    @model_validator(mode="after")
    def _seeds_are_members(self) -> RegistryFederation:
        if not self.seed_registry_ids:
            raise ValueError("a federation needs at least one seed registry")
        outside = sorted(set(self.seed_registry_ids) - set(self.registry_ids))
        if outside:
            raise ValueError(
                f"federation seeds are not in its own membership: {', '.join(outside)}"
            )
        if len(set(self.registry_ids)) != len(self.registry_ids):
            raise ValueError("federation membership must be unique")
        return self

    def contains(self, registry_id: str) -> bool:
        """Pure membership test over the closure."""
        return registry_id in self.registry_ids


def federated_registries(registries: Iterable[RegistryRef]) -> RegistryFederation:
    """Transitive closure of every registry's ``federates_with`` edges.

    Pure and total over the supplied table: it computes what the edges say and
    nothing about who is *allowed* in the federation. Cycles terminate — a
    visited set, not a recursion bound — and an unknown peer id is simply absent
    from the closure rather than raising, because a registry that has not been
    loaded yet is a fact about the caller's table, not about the peer.
    """
    table = {registry.registry_id: registry for registry in registries}
    seeds = tuple(sorted(table))
    closure: set[str] = set(seeds)
    frontier = list(seeds)
    while frontier:
        current = frontier.pop()
        for peer in table[current].federates_with:
            # An edge naming a peer this table does not carry is a fact about
            # the caller's table, not about the peer, so the edge is skipped
            # rather than followed. Following it would put an id in the closure
            # with no row behind it and then index the table with it — a
            # ``KeyError`` out of a function documented as total, and a crash
            # standing in for an answer the docstring already gives. The
            # closure therefore only ever names registries that exist here.
            if peer in table and peer not in closure:
                closure.add(peer)
                frontier.append(peer)
    return RegistryFederation(seed_registry_ids=seeds, registry_ids=tuple(sorted(closure)))


# ── supply chain (gap 76), per artifact version ──────────────────────────────


class SourceStage(StrEnum):
    """Which step of the path a source-chain entry records.

    Not a trust ladder. ``PUBLISHED`` and ``MIRRORED`` say where bytes came
    from; ``CERTIFICATION_RECORDED`` says plan 01 wrote a record about them.
    None of them says who typed them.
    """

    PUBLISHED = "published"
    MIRRORED = "mirrored"
    RESOLVED = "resolved"
    INSTALLED = "installed"
    CERTIFICATION_RECORDED = "certification_recorded"


class SourceChainEntry(BaseModel):
    """One hop of provenance-as-data: a step, an actor *label*, a locator.

    ``actor`` is a name a registry or a person supplied, held to the same
    standard as :class:`PublisherDeclaration` — a declaration. The chain is
    valuable for *reconstruction* ("which mirror served these bytes, and when")
    and is not evidence of authorship; :attr:`notice` says so in the same breath
    as the data.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    stage: SourceStage
    actor: str = Field(min_length=1, max_length=100)
    locator: str = Field(default="", max_length=500)
    recorded_at: AwareDatetime
    detail: str = Field(default="", max_length=500)

    @property
    def notice(self) -> str:
        """:data:`SIGNATURE_TRUST_NOTICE` — provenance here is declaration-only."""
        return SIGNATURE_TRUST_NOTICE


class DigestCheckState(StrEnum):
    """The integrity axis, and only the integrity axis.

    There is deliberately no ``SIGNED`` or ``TRUSTED`` member. The strongest
    statement this build can make about bytes is that they hash to what was
    declared, so the vocabulary stops there; a test asserts that no member name
    reads as provenance, which is what keeps a future change from adding one in
    a hurry.
    """

    NOT_CHECKED = "not_checked"
    DIGEST_MATCHED = "digest_matched"
    DIGEST_MISMATCHED = "digest_mismatched"


class SupplyChainRecord(BaseModel):
    """Everything the catalog knows about one artifact **version**, as data.

    Gap 76's fields, all present: publisher declaration, digest, SBOM,
    dependency set, declared permissions, verification state, release history,
    plus the source chain. Per *version* rather than per artifact, because
    every one of those facts is version-scoped — a digest that matched at
    1.2.0 says nothing about 1.3.0, which is exactly why
    :class:`ArtifactCertification` pairs a record with a digest instead of an
    artifact id.

    ``verification_state`` is :class:`DigestCheckState` and nothing more. A test
    pins that no field name on this model reads as authentication.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    version: str
    digest: str
    publisher: PublisherDeclaration
    declared_permissions: frozenset[ProviderPermission] = Field(default_factory=frozenset)
    dependencies: tuple[ArtifactDependency, ...] = ()
    sbom: SbomRef | None = None
    verification_state: DigestCheckState = DigestCheckState.NOT_CHECKED
    release_history: tuple[ReleaseEvent, ...] = ()
    source_chain: tuple[SourceChainEntry, ...] = ()

    @field_validator("digest")
    @classmethod
    def _digest_is_sha256(cls, value: str) -> str:
        if ARTIFACT_DIGEST_RE.match(value) is None:
            raise ValueError("supply-chain digest must be 64 lowercase hex characters (sha256)")
        return value

    @model_validator(mode="after")
    def _release_history_is_sane(self) -> SupplyChainRecord:
        versions = [event.version for event in self.release_history]
        if len(set(versions)) != len(versions):
            duplicates = sorted({v for v in versions if versions.count(v) > 1})
            raise ArtifactDeclarationError(
                "supply_chain.duplicate_release",
                f"supply-chain record for {self.artifact_id}@{self.version} lists release(s) "
                f"{', '.join(duplicates)} twice",
            )
        if self.release_history and self.release_history[-1].digest != self.digest:
            raise ArtifactDeclarationError(
                "supply_chain.head_digest_mismatch",
                f"supply-chain record for {self.artifact_id}@{self.version} declares digest "
                f"{self.digest[:12]} but its newest release entry carries "
                f"{self.release_history[-1].digest[:12]}; release history is append-only and the "
                "head must be the artifact's own bytes",
            )
        return self

    @property
    def ref(self) -> str:
        """``id@version`` — the identity this record describes."""
        return f"{self.artifact_id}@{self.version}"

    @property
    def notice(self) -> str:
        """:data:`SIGNATURE_TRUST_NOTICE` — the record, not the author."""
        return SIGNATURE_TRUST_NOTICE

    def pinned_dependencies(self) -> tuple[ArtifactDependency, ...]:
        """Dependencies that name exact bytes rather than a version range."""
        return tuple(dep for dep in self.dependencies if dep.pinned)


def check_digest(
    record: SupplyChainRecord,
    *,
    observed_digest: str,
) -> SupplyChainRecord:
    """Compare the declared digest with ``observed_digest``; return the verdict.

    Pure, and deliberately clock-free: hashing does not consult a time, so
    there is no ``now`` to inject and none is accepted. The refusal is
    directional — an unreadable ``observed_digest`` is neither a match nor a
    mismatch, and this function says so rather than guessing.

    Re-checking the same record with a *different* observed digest is allowed,
    because a later observation is a legitimate new fact about the same bytes
    being served. What the function refuses is a record that claims to be
    matched while the bytes in hand hash to something else, which is the
    tampering case the whole integrity axis exists for.
    """
    if ARTIFACT_DIGEST_RE.match(observed_digest) is None:
        raise ValueError(
            "observed_digest must be 64 lowercase hex characters (sha256); an unreadable "
            "digest is not a mismatch and not a match"
        )
    state = (
        DigestCheckState.DIGEST_MATCHED
        if observed_digest == record.digest
        else DigestCheckState.DIGEST_MISMATCHED
    )
    return SupplyChainRecord.model_validate({**record.model_dump(), "verification_state": state})
