"""Marketplace artifacts and trust labels: the promotion matrix and its refusals.

Why this file exists
--------------------
A marketplace is where "verified" and "trusted" get spent. This build cannot
authenticate anything: ``mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED``
is ``False`` and is pinned ``False`` by its own suite, because the format carries
no key, no algorithm, and no trust store. Everything the catalog can honestly
establish is therefore *integrity* (the bytes hash to the declared digest) and
*evidence* (a certification record exists for those bytes on a cell). Nothing it
can establish is *authorship*.

So the tests are written against one question — **can this artifact reach this
class without a current certification record?** — asked exhaustively rather than
by example:

* **the matrix.** Every ``ArtifactClass`` by every registry scope by every record
  state, asserted against the derived class. A path that reached "verified"
  without the record would fail a cell, not a prose review.
* **the shortcut does not compile.** :class:`TrustLabel` has no class field and
  :class:`Artifact` has no trust field, so "marking" is not a value either type
  can hold. Two tests assert that structurally — over the model fields and over
  the source AST — plus one that hands the constructor a class field and watches
  it be refused.
* **digest mismatch.** A record for other bytes is evidence about other bytes,
  whether the record is live, stale, or brand new.
* **revocation propagation.** A revocation is announced at ``issued_at`` and in
  force at ``propagation_deadline``; the two states are separate predicates, and
  the dispatch refusal names the revocation that caused it.
* **federation shape.** A private registry federated with the official catalogue
  still classifies as organization-private, because peers share bytes, not
  standing.
* **negative controls.** An artifact claiming a verified label with no record, a
  revoked artifact dispatching after its deadline, a deprecated artifact backing
  a new approval, and a publisher declaration being mistaken for authentication.

The last test restates the domain law locally: this module may not import the
toolkit, agents, controller, infra, or the IO modules. ``pyproject.toml``'s
import-linter contract enforces the same thing in CI; the guard also lives here
so a missing optional dependency cannot hide it.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

import mayhem.domain.marketplace as marketplace_module
from mayhem.domain.capabilities import Capability
from mayhem.domain.certification import (
    REQUIRED_EVIDENCE_DIGESTS,
    Arch,
    CellPrivilege,
    CertificationRecord,
    CertificationState,
    EvidenceBundleRef,
    MatrixCell,
    certify,
    expire_by_time,
    mark_failed,
    mark_incompatible,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.faults import EngineLane
from mayhem.domain.marketplace import (
    ARTIFACT_DIGEST_RE,
    ASSERTION_ORDER,
    CLASS_MEANING,
    OFFICIAL_REGISTRY_ID,
    PUBLISHER_DECLARATION_NOTICE,
    SIGNATURE_TRUST_NOTICE,
    SIGNATURE_VERIFICATION_IMPLEMENTED,
    Artifact,
    ArtifactCertification,
    ArtifactClass,
    ArtifactDeclarationError,
    ArtifactDependency,
    DeprecationNotice,
    DigestCheckState,
    PublisherDeclaration,
    RegistryFederation,
    RegistryRef,
    RegistryScope,
    ReleaseEvent,
    Revocation,
    RevocationReason,
    RevocationScope,
    SbomRef,
    SourceChainEntry,
    SourceStage,
    SupplyChainRecord,
    TrustLabel,
    TrustLabelError,
    applicable_revocations,
    approval_refusals,
    backs_new_approval,
    blocking_revocations,
    check_digest,
    classify_artifact,
    dispatch_refusal,
    dispatches,
    federated_registries,
    is_current_record,
    matching_certifications,
    pending_revocations,
    require_trust_label,
    trust_label,
)
from mayhem.domain.provider import ProviderPermission
from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED as PACK_SIGNATURE_IMPLEMENTED

if TYPE_CHECKING:
    from collections.abc import Callable

_NOW = datetime(2026, 5, 4, 9, 0, tzinfo=UTC)
_TTL = timedelta(days=30)
_LATER = _NOW + timedelta(days=1)
_BEYOND = _NOW + timedelta(days=90)

_BUNDLE_HASH = "a" * 64
_OTHER_DIGEST = "b" * 64
_ARTIFACT_DIGEST = "c" * 64
_TAMPERED_DIGEST = "d" * 64
_DEP_DIGEST = "e" * 64

FAULT_ID = "proc.pause"
OTHER_FAULT_ID = "net.latency"


# ── builders ────────────────────────────────────────────────────────────────


def _cell(*, engine: EngineLane = EngineLane.DOCKER) -> MatrixCell:
    return MatrixCell(
        engine=engine,
        engine_version="24.0.7",
        os_distro="ubuntu-24.04",
        kernel_version="6.11.0-13-generic",
        arch=Arch.AMD64,
        privilege=CellPrivilege.ROOTLESS,
        capabilities=frozenset({Capability.NET_ADMIN}),
    )


def _bundle() -> EvidenceBundleRef:
    return EvidenceBundleRef(
        bundle_hash=_BUNDLE_HASH,
        mayhem_version="1.1.0.test",
        digests=dict.fromkeys(REQUIRED_EVIDENCE_DIGESTS, _BUNDLE_HASH),
    )


def _pending(
    *, cell: MatrixCell | None = None, expires_at: datetime | None = None
) -> CertificationRecord:
    return CertificationRecord(
        fault_id=FAULT_ID,
        cell=cell or _cell(),
        injector_version="acme-tc 1.4.0",
        expires_at=expires_at or (_NOW + _TTL * 3),
    )


def _certified(
    *,
    cell: MatrixCell | None = None,
    at: datetime = _NOW,
    ttl: timedelta = _TTL,
    fault_id: str = FAULT_ID,
) -> CertificationRecord:
    record = CertificationRecord(
        fault_id=fault_id,
        cell=cell or _cell(),
        injector_version="acme-tc 1.4.0",
        expires_at=at + _TTL * 3,
    )
    return certify(
        record,
        at=at,
        expires_at=at + ttl,
        evidence=(_bundle(),),
        outcome="latency observed; undo restored the pre-injection baseline",
    )


def _cert(*, record: CertificationRecord, digest: str = _ARTIFACT_DIGEST) -> ArtifactCertification:
    return ArtifactCertification(artifact_digest=digest, record=record)


def _publisher(*, organization: str | None = None) -> PublisherDeclaration:
    return PublisherDeclaration(
        publisher_id="acme.labs",
        display_name="Acme Labs",
        contact="maintainers@acme.invalid",
        organization=organization,
    )


def _registry(
    *,
    registry_id: str = "community.registry",
    scope: RegistryScope = RegistryScope.COMMUNITY,
    organization: str | None = None,
    federates_with: tuple[str, ...] = (),
) -> RegistryRef:
    return RegistryRef(
        registry_id=registry_id,
        display_name=registry_id,
        scope=scope,
        organization=organization,
        federates_with=federates_with,
    )


def _artifact(
    *,
    registry: RegistryRef | None = None,
    digest: str = _ARTIFACT_DIGEST,
    deprecation: DeprecationNotice | None = None,
    publisher: PublisherDeclaration | None = None,
    dependencies: tuple[ArtifactDependency, ...] = (),
) -> Artifact:
    return Artifact(
        artifact_id="acme.packs.net",
        version="1.4.2",
        digest=digest,
        publisher=publisher or _publisher(),
        registry=registry or _registry(),
        dependencies=dependencies,
        permissions=frozenset({ProviderPermission.NETWORK}),
        license_id="Apache-2.0",
        changelog_ref="https://acme.invalid/CHANGELOG.md",
        deprecation=deprecation,
    )


def _deprecation() -> DeprecationNotice:
    return DeprecationNotice(
        reason="the injector reached an unsupported kernel path on 6.9",
        replaced_by="acme.packs.net",
        announced_at=_NOW - timedelta(days=3),
    )


def _revocation(
    *,
    revocation_id: str = "acme.rev.0001",
    scope: RevocationScope = RevocationScope.ARTIFACT_VERSION,
    reason: RevocationReason = RevocationReason.SECURITY_DEFECT,
    issued_at: datetime = _NOW - timedelta(days=1),
    propagation_deadline: datetime = _NOW - timedelta(hours=1),
    artifact_id: str | None = "acme.packs.net",
    version: str | None = "1.4.2",
    digest: str | None = _ARTIFACT_DIGEST,
    publisher_id: str | None = None,
    registry_id: str | None = None,
) -> Revocation:
    return Revocation(
        revocation_id=revocation_id,
        scope=scope,
        reason=reason,
        detail="upstream advisory GHSA-0000-0000-0000",
        issued_at=issued_at,
        propagation_deadline=propagation_deadline,
        artifact_id=artifact_id,
        version=version,
        digest=digest,
        publisher_id=publisher_id,
        registry_id=registry_id,
    )


def _pending_claim() -> CertificationRecord:
    """A recorded claim that has not been certified."""
    return _pending()


def _failed_claim() -> CertificationRecord:
    """A claim that a re-run did not reproduce."""
    return mark_failed(_certified(), reason="did not reproduce")


def _incompatible_claim() -> CertificationRecord:
    """A claim whose cell no longer describes the runtime."""
    return mark_incompatible(_certified(), reason="the kernel moved")


def _stale_claim() -> CertificationRecord:
    """A claim whose validity window has passed."""
    return expire_by_time(_certified(), now=_BEYOND)


# ── the structural claims: a label cannot be *marked* ───────────────────────


class TestNoShortcutCompiles:
    """The type has nowhere to put a class, so no code can write one."""

    def test_trust_label_stores_no_class_field(self) -> None:
        assert "artifact_class" not in TrustLabel.model_fields
        assert "class" not in TrustLabel.model_fields
        assert "label" not in TrustLabel.model_fields

    def test_artifact_stores_no_trust_field(self) -> None:
        fields = set(Artifact.model_fields)
        forbidden = {
            "class",
            "artifact_class",
            "trust",
            "trust_label",
            "label",
            "verified",
            "trusted",
            "signature",
            "signature_verified",
            "signer",
            "signer_trusted",
            "provenance",
            "authenticated",
            "attestation",
        }
        assert not fields & forbidden

    def test_supply_chain_carries_no_authentication_field(self) -> None:
        fields = set(SupplyChainRecord.model_fields)
        forbidden = {
            "signature",
            "signature_verified",
            "signer",
            "signer_verified",
            "trusted",
            "trusted_publisher",
            "verified",
            "verified_publisher",
            "attestation",
            "provenance_verified",
        }
        assert not fields & forbidden

    def test_constructing_a_label_with_a_class_field_is_refused(self) -> None:
        payload = {
            **_artifact().model_dump(),
            "registry_id": "community.registry",
            "registry_scope": RegistryScope.COMMUNITY.value,
            "evaluated_at": _NOW,
            "artifact_class": ArtifactClass.VERIFIED_COMMUNITY.value,
        }
        with pytest.raises(ValidationError, match="artifact_class"):
            TrustLabel.model_validate(payload)

    def test_constructing_an_artifact_with_a_trust_field_is_refused(self) -> None:
        payload = _artifact().model_dump()
        payload["trust_label"] = ArtifactClass.VERIFIED_COMMUNITY.value
        with pytest.raises(ValidationError, match="trust_label"):
            Artifact.model_validate(payload)

    def test_no_marketplace_model_field_reads_as_authentication(self) -> None:
        """Every field name on every model, checked against the trust vocabulary.

        Broader than the three targeted tests above on purpose: a new model
        added to this module is covered by the same assertion without anyone
        remembering to extend a list.
        """
        banned = ("verified", "trusted", "signature", "signed", "authenticated", "attestation")
        for name, model in vars(marketplace_module).items():
            fields = getattr(model, "model_fields", None)
            if not isinstance(fields, dict):
                continue
            for field in fields:
                assert not any(word in field.lower() for word in banned), (
                    f"{name}.{field} reads as an authentication claim"
                )

    def test_digest_check_state_has_no_provenance_member(self) -> None:
        banned = ("signed", "trusted", "verified", "signed_by", "attested")
        for member in DigestCheckState:
            assert not any(word in member.value for word in banned), (
                f"DigestCheckState.{member.name} reads as provenance; this build checks integrity "
                "only"
            )

    def test_the_domain_flag_agrees_with_the_providers_flag_and_is_false(self) -> None:
        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
        assert PACK_SIGNATURE_IMPLEMENTED is False
        assert SIGNATURE_VERIFICATION_IMPLEMENTED is PACK_SIGNATURE_IMPLEMENTED

    def test_the_notice_says_provenance_is_not_established(self) -> None:
        assert "cannot verify" in SIGNATURE_TRUST_NOTICE
        assert "provenance" in SIGNATURE_TRUST_NOTICE
        assert "declaration of authorship" in SIGNATURE_TRUST_NOTICE
        assert PUBLISHER_DECLARATION_NOTICE in SIGNATURE_TRUST_NOTICE or (
            "not\nauthentication" in PUBLISHER_DECLARATION_NOTICE
            or "not authentication" in PUBLISHER_DECLARATION_NOTICE
        )

    def test_every_class_meaning_disclaims_authorship(self) -> None:
        for artifact_class, meaning in CLASS_MEANING.items():
            lowered = meaning.lower()
            assert meaning, artifact_class
            assert any(
                word in lowered for word in ("no certification", "declaration", "signature")
            ), f"{artifact_class.value} meaning does not say what it is not"

    def test_no_class_meaning_overclaims_what_the_domain_can_establish(self) -> None:
        """The honesty claim extends to source data, not just published prose.

        Gate 4 in ``test_readme_honesty.py`` scans ``docs/**``, which is why the
        overclaim detectors live there and are imported here rather than
        reimplemented. Without this, ``CLASS_MEANING`` was the one place the
        claim was made in a form nothing checked.

        The check above only asks for a disclaimer *keyword*, so it is not
        sufficient on its own: an entry rewritten to keep the word "signature"
        while asserting that the publisher is authenticated passes it. This is
        the test that catches that, and it was written by making exactly that
        edit and watching it fail.
        """
        from test_readme_honesty import honesty_overclaims

        for artifact_class, meaning in CLASS_MEANING.items():
            overclaims = honesty_overclaims(meaning)
            assert not overclaims, (
                f"{artifact_class.value} meaning overclaims what mayhem can "
                f"establish: {overclaims}\n{meaning!r}"
            )

    def test_the_module_never_reads_a_clock(self) -> None:
        """No ``datetime.now``/``utc_now`` call anywhere in the module.

        Every predicate takes ``now`` as an argument. A clock read hidden in the
        module would make a promotion unreplayable and untestable, so this is
        checked against the AST rather than trusted to review.
        """
        source = Path(marketplace_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        clock_reads = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        } & {"now", "utcnow", "today"}
        assert not clock_reads, f"marketplace reads a clock: {sorted(clock_reads)}"
        assert "utc_now(" not in source

    def test_the_module_does_not_import_providers(self) -> None:
        """The domain layer must not reach up into the loader layer."""
        source = Path(marketplace_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        upward_prefixes = (
            "mayhem.providers",
            "mayhem.toolkit",
            "mayhem.agents",
            "mayhem.controller",
            "mayhem.infra",
        )
        upward = {name for name in imported if name.startswith(upward_prefixes)}
        assert not upward, f"marketplace imports upward: {sorted(upward)}"


# ── the promotion matrix ────────────────────────────────────────────────────


class TestPromotionMatrix:
    """Every class by scope by record state. No path to verified without a record."""

    @pytest.mark.parametrize(
        ("scope", "registry_id", "organization", "expected"),
        [
            (RegistryScope.COMMUNITY, "community.registry", None, ArtifactClass.UNVERIFIED),
            (
                RegistryScope.ORGANIZATION_PRIVATE,
                "acme.private",
                "Acme",
                ArtifactClass.ORGANIZATION_PRIVATE,
            ),
            (RegistryScope.OFFICIAL, OFFICIAL_REGISTRY_ID, None, ArtifactClass.UNVERIFIED),
        ],
        ids=["community", "organization_private", "official"],
    )
    def test_without_a_record_no_scope_reaches_verified(
        self,
        scope: RegistryScope,
        registry_id: str,
        organization: str | None,
        expected: ArtifactClass,
    ) -> None:
        artifact = _artifact(
            registry=_registry(registry_id=registry_id, scope=scope, organization=organization),
            publisher=_publisher(organization=organization),
        )
        assert classify_artifact(artifact, [], now=_NOW) is expected
        assert artifact.class_of([], now=_NOW) is expected
        label = artifact.trust_label([], now=_NOW)
        assert label.artifact_class is expected
        if expected is not ArtifactClass.VERIFIED_COMMUNITY:
            assert label.may_display_certified_state is False
            assert label.certified_fault_ids == ()

    @pytest.mark.parametrize(
        "state_builder",
        [_pending_claim, _failed_claim, _incompatible_claim, _stale_claim],
        ids=["pending", "failed", "incompatible", "stale"],
    )
    def test_a_non_live_record_never_promotes(
        self, state_builder: Callable[[], CertificationRecord]
    ) -> None:
        record = state_builder()
        assert isinstance(record, CertificationRecord)
        assert record.grants_live_verification is False
        artifact = _artifact()
        assert classify_artifact(artifact, [_cert(record=record)], now=_BEYOND) is (
            ArtifactClass.UNVERIFIED
        )

    def test_a_live_record_for_these_bytes_promotes_to_verified_community(self) -> None:
        artifact = _artifact()
        certification = _cert(record=_certified())
        assert classify_artifact(artifact, [certification], now=_NOW) is (
            ArtifactClass.VERIFIED_COMMUNITY
        )

    def test_expiring_still_counts_but_warns(self) -> None:
        record = expire_by_time(_certified(), now=_NOW + timedelta(days=25))
        assert record.state is CertificationState.EXPIRING
        certification = _cert(record=record)
        label = _artifact().trust_label([certification], now=_NOW + timedelta(days=25))
        assert label.artifact_class is ArtifactClass.VERIFIED_COMMUNITY
        assert label.certified_states == (CertificationState.EXPIRING,)

    def test_lapsed_record_demotes_at_the_expiry_instant(self) -> None:
        record = _certified(ttl=timedelta(hours=2))
        certification = _cert(record=record)
        artifact = _artifact()
        assert is_current_record(certification, now=record.expires_at - timedelta(seconds=1))
        assert not is_current_record(certification, now=record.expires_at)
        assert classify_artifact(artifact, [certification], now=record.expires_at) is (
            ArtifactClass.UNVERIFIED
        )

    def test_official_needs_both_the_registry_and_the_record(self) -> None:
        official = _artifact(
            registry=_registry(registry_id=OFFICIAL_REGISTRY_ID, scope=RegistryScope.OFFICIAL)
        )
        assert classify_artifact(official, [], now=_NOW) is ArtifactClass.UNVERIFIED
        assert classify_artifact(official, [_cert(record=_certified())], now=_NOW) is (
            ArtifactClass.OFFICIAL
        )

    def test_an_official_scope_on_the_wrong_registry_is_not_official(self) -> None:
        impostor = _artifact(
            registry=_registry(registry_id="acme.lookalike", scope=RegistryScope.OFFICIAL)
        )
        assert impostor.registry.is_official is False
        assert classify_artifact(impostor, [_cert(record=_certified())], now=_NOW) is (
            ArtifactClass.VERIFIED_COMMUNITY
        )

    def test_organization_private_is_not_promoted_by_certification(self) -> None:
        private = _artifact(
            registry=_registry(
                registry_id="acme.private",
                scope=RegistryScope.ORGANIZATION_PRIVATE,
                organization="Acme",
            ),
            publisher=_publisher(organization="Acme"),
        )
        assert classify_artifact(private, [_cert(record=_certified())], now=_NOW) is (
            ArtifactClass.ORGANIZATION_PRIVATE
        )

    def test_deprecation_overrides_every_other_class(self) -> None:
        official = _artifact(
            registry=_registry(registry_id=OFFICIAL_REGISTRY_ID, scope=RegistryScope.OFFICIAL),
            deprecation=_deprecation(),
        )
        assert official.is_deprecated is True
        assert classify_artifact(official, [_cert(record=_certified())], now=_NOW) is (
            ArtifactClass.DEPRECATED
        )

    def test_multiple_records_from_multiple_cells_all_count(self) -> None:
        certifications = (
            _cert(record=_certified(cell=_cell(engine=EngineLane.DOCKER))),
            _cert(
                record=_certified(cell=_cell(engine=EngineLane.KUBERNETES), fault_id=OTHER_FAULT_ID)
            ),
        )
        label = _artifact().trust_label(certifications, now=_NOW)
        assert label.certified_fault_ids == tuple(sorted((FAULT_ID, OTHER_FAULT_ID)))
        assert label.may_display_certified_state is True
        assert len(label.certified_states) == 2


class TestRequireTrustLabel:
    """``require_trust_label`` is a request, and every overclaim is refused."""

    def test_the_derived_class_is_granted(self) -> None:
        artifact = _artifact()
        certification = _cert(record=_certified())
        label = require_trust_label(
            artifact, [certification], claimed=ArtifactClass.VERIFIED_COMMUNITY, now=_NOW
        )
        assert label.artifact_class is ArtifactClass.VERIFIED_COMMUNITY

    def test_verified_with_no_record_is_refused(self) -> None:
        with pytest.raises(TrustLabelError) as excinfo:
            require_trust_label(_artifact(), [], claimed=ArtifactClass.VERIFIED_COMMUNITY, now=_NOW)
        assert excinfo.value.code == "no_certification_record"
        assert "no certification record was supplied" in str(excinfo.value)

    @pytest.mark.parametrize(
        ("claimed", "registry"),
        [
            pytest.param(ArtifactClass.VERIFIED_COMMUNITY, _registry(), id="verified"),
            pytest.param(
                ArtifactClass.OFFICIAL,
                _registry(registry_id=OFFICIAL_REGISTRY_ID, scope=RegistryScope.OFFICIAL),
                id="official",
            ),
        ],
    )
    def test_verified_with_only_other_bytes_is_refused(
        self, claimed: ArtifactClass, registry: RegistryRef
    ) -> None:
        """Both evidence classes refuse a record that is about different bytes.

        Parameterised over the registry too, because the distribution axis is
        checked first: an ``official`` claim on a community registry would fail
        on the registry and never reach the digest check, so this case has to
        put the artifact *on* the official registry to actually test the digest.
        """
        other = _cert(record=_certified(), digest=_OTHER_DIGEST)
        with pytest.raises(TrustLabelError) as excinfo:
            require_trust_label(_artifact(registry=registry), [other], claimed=claimed, now=_NOW)
        assert excinfo.value.code == "certification_digest_mismatch"

    def test_verified_with_a_lapsed_record_is_refused(self) -> None:
        lapsed = expire_by_time(_certified(), now=_BEYOND)
        with pytest.raises(TrustLabelError) as excinfo:
            require_trust_label(
                _artifact(),
                [_cert(record=lapsed)],
                claimed=ArtifactClass.VERIFIED_COMMUNITY,
                now=_BEYOND,
            )
        assert excinfo.value.code == "certification_not_current"
        assert "lapsed claim is not evidence" in str(excinfo.value)

    def test_official_off_the_official_registry_is_refused(self) -> None:
        artifact = _artifact()
        with pytest.raises(TrustLabelError) as excinfo:
            require_trust_label(
                artifact,
                [_cert(record=_certified())],
                claimed=ArtifactClass.OFFICIAL,
                now=_NOW,
            )
        assert excinfo.value.code == "not_official_registry"

    def test_organization_private_claimed_on_a_public_registry_is_refused(self) -> None:
        with pytest.raises(TrustLabelError) as excinfo:
            require_trust_label(
                _artifact(),
                [_cert(record=_certified())],
                claimed=ArtifactClass.ORGANIZATION_PRIVATE,
                now=_NOW,
            )
        assert excinfo.value.code == "registry_scope_mismatch"

    def test_a_deprecated_artifact_cannot_be_displayed_as_anything_else(self) -> None:
        artifact = _artifact(deprecation=_deprecation())
        with pytest.raises(TrustLabelError) as excinfo:
            require_trust_label(
                artifact,
                [_cert(record=_certified())],
                claimed=ArtifactClass.VERIFIED_COMMUNITY,
                now=_NOW,
            )
        assert excinfo.value.code == "deprecated_artifact"

    def test_a_word_outside_the_vocabulary_is_refused(self) -> None:
        with pytest.raises(TrustLabelError) as excinfo:
            require_trust_label(
                _artifact(),
                [],
                claimed="trusted",
                now=_NOW,  # type: ignore[arg-type]
            )
        assert excinfo.value.code == "artifact_class_not_supported"

    def test_every_overclaim_path_to_verified_names_a_missing_record(self) -> None:
        """No supply of records short of a current one reaches the class.

        Exhaustively: every combination of record-state and digest-agreement
        that a caller could plausibly assemble, checked against the one class
        that asserts evidence.
        """
        states: dict[str, CertificationRecord] = {
            "pending": _pending(),
            "certified": _certified(),
            "failed": mark_failed(_certified(), reason="did not reproduce"),
            "incompatible": mark_incompatible(_certified(), reason="the cell moved"),
            "stale": expire_by_time(_certified(), now=_BEYOND),
        }
        digests = {"matching": _ARTIFACT_DIGEST, "other": _OTHER_DIGEST}
        refused = 0
        for state_name, record in states.items():
            for digest_name, digest in digests.items():
                artifact = _artifact()
                certification = _cert(record=record, digest=digest)
                derived = classify_artifact(artifact, [certification], now=_BEYOND)
                if derived is ArtifactClass.VERIFIED_COMMUNITY:
                    assert record.grants_live_verification, (
                        f"{state_name}/{digest_name} reached verified_community on a "
                        "non-live record"
                    )
                    refused += 1
                    continue
                with pytest.raises(TrustLabelError):
                    require_trust_label(
                        artifact,
                        [certification],
                        claimed=ArtifactClass.VERIFIED_COMMUNITY,
                        now=_BEYOND,
                    )
                refused += 1
        assert refused == len(states) * len(digests)


# ── digest matching ─────────────────────────────────────────────────────────


class TestDigestMismatch:
    def test_a_record_for_other_bytes_is_not_evidence_here(self) -> None:
        artifact = _artifact()
        certification = _cert(record=_certified(), digest=_OTHER_DIGEST)
        assert matching_certifications(artifact, [certification], now=_NOW) == ()
        assert classify_artifact(artifact, [certification], now=_NOW) is ArtifactClass.UNVERIFIED

    def test_a_record_for_a_different_artifact_version_does_not_transfer(self) -> None:
        artifact = _artifact()
        older = _artifact(digest=_OTHER_DIGEST)
        assert older.version == artifact.version
        certification = _cert(record=_certified(), digest=older.digest)
        assert matching_certifications(artifact, [certification], now=_NOW) == ()

    def test_a_label_built_from_other_bytes_reports_none_of_them(self) -> None:
        label = trust_label(
            _artifact(), [_cert(record=_certified(), digest=_OTHER_DIGEST)], now=_NOW
        )
        assert label.certifications == ()
        assert label.certified_fault_ids == ()
        assert label.may_display_certified_state is False
        assert label.artifact_digest == _ARTIFACT_DIGEST

    def test_a_cold_label_cannot_claim_a_certified_state(self) -> None:
        label = trust_label(_artifact(), [], now=_NOW)
        assert label.artifact_class is ArtifactClass.UNVERIFIED
        assert label.may_display_certified_state is False
        assert label.certified_states == ()
        assert label.notice == SIGNATURE_TRUST_NOTICE

    def test_the_supply_chain_digest_check_is_integrity_only(self) -> None:
        record = _supply_chain()
        matched = check_digest(record, observed_digest=_ARTIFACT_DIGEST)
        assert matched.verification_state is DigestCheckState.DIGEST_MATCHED
        assert matched.notice == SIGNATURE_TRUST_NOTICE

    def test_tampered_bytes_are_mismatched(self) -> None:
        record = check_digest(_supply_chain(), observed_digest=_TAMPERED_DIGEST)
        assert record.verification_state is DigestCheckState.DIGEST_MISMATCHED
        assert record.digest == _ARTIFACT_DIGEST

    def test_an_unreadable_observed_digest_is_neither_match_nor_mismatch(self) -> None:
        with pytest.raises(ValueError, match="not a mismatch and not a match"):
            check_digest(_supply_chain(), observed_digest="not-a-digest")

    def test_the_digest_regex_is_the_certification_bundle_shape(self) -> None:
        from mayhem.domain.certification import BUNDLE_DIGEST_RE

        assert ARTIFACT_DIGEST_RE.pattern == BUNDLE_DIGEST_RE.pattern

    def test_a_non_sha256_artifact_digest_is_refused_at_construction(self) -> None:
        with pytest.raises(ValidationError, match="64 lowercase hex"):
            _artifact(digest="zzz")


# ── supply chain, per artifact version ───────────────────────────────────────


def _supply_chain(**overrides: object) -> SupplyChainRecord:
    payload: dict[str, object] = {
        "artifact_id": "acme.packs.net",
        "version": "1.4.2",
        "digest": _ARTIFACT_DIGEST,
        "publisher": _publisher(),
        "declared_permissions": frozenset(
            {ProviderPermission.NETWORK, ProviderPermission.SUBPROCESS}
        ),
        "dependencies": (
            ArtifactDependency(name="acme-tc", constraint=">=1.4,<2", digest=_OTHER_DIGEST),
            ArtifactDependency(name="prometheus-client", constraint=">=0.20"),
        ),
        "sbom": SbomRef(format="spdx-json", digest=_BUNDLE_HASH, locator="sbom/1.4.2.spdx.json"),
        "verification_state": DigestCheckState.NOT_CHECKED,
        "release_history": (
            ReleaseEvent(
                version="1.4.1", digest=_OTHER_DIGEST, released_at=_NOW - timedelta(days=30)
            ),
            ReleaseEvent(
                version="1.4.2", digest=_ARTIFACT_DIGEST, released_at=_NOW - timedelta(days=2)
            ),
        ),
        "source_chain": (
            SourceChainEntry(
                stage=SourceStage.PUBLISHED,
                actor="acme.labs",
                locator="https://acme.invalid/packs/1.4.2.tar.gz",
                recorded_at=_NOW - timedelta(days=2),
            ),
            SourceChainEntry(
                stage=SourceStage.MIRRORED,
                actor="community.registry",
                locator="registry://community.registry/acme.packs.net/1.4.2",
                recorded_at=_NOW - timedelta(days=1),
                detail="federated mirror of the publisher upload",
            ),
            SourceChainEntry(
                stage=SourceStage.CERTIFICATION_RECORDED,
                actor="mayhem",
                locator="certification/proc.pause@docker",
                recorded_at=_NOW,
                detail="plan 01 record; evidence for these bytes, not for the author",
            ),
        ),
    }
    payload.update(overrides)
    return SupplyChainRecord.model_validate(payload)


class TestSupplyChainRecord:
    def test_it_carries_every_gap_76_field(self) -> None:
        record = _supply_chain()
        assert record.publisher.publisher_id == "acme.labs"
        assert record.digest == _ARTIFACT_DIGEST
        assert record.sbom is not None and record.sbom.format == "spdx-json"
        assert {dep.name for dep in record.dependencies} == {"acme-tc", "prometheus-client"}
        assert record.declared_permissions == frozenset(
            {ProviderPermission.NETWORK, ProviderPermission.SUBPROCESS}
        )
        assert record.verification_state is DigestCheckState.NOT_CHECKED
        assert [event.version for event in record.release_history] == ["1.4.1", "1.4.2"]
        assert len(record.source_chain) == 3

    def test_it_is_keyed_per_version(self) -> None:
        assert _supply_chain().ref == "acme.packs.net@1.4.2"
        assert _supply_chain(version="1.4.1").ref != _supply_chain().ref

    def test_only_pinned_dependencies_are_reported_as_pinned(self) -> None:
        pinned = _supply_chain().pinned_dependencies()
        assert [dep.name for dep in pinned] == ["acme-tc"]

    def test_a_release_history_head_that_is_not_the_artifact_is_refused(self) -> None:
        with pytest.raises(ArtifactDeclarationError) as excinfo:
            _supply_chain(
                release_history=(
                    ReleaseEvent(
                        version="1.4.2", digest=_OTHER_DIGEST, released_at=_NOW - timedelta(days=2)
                    ),
                )
            )
        assert excinfo.value.rule == "supply_chain.head_digest_mismatch"

    def test_a_duplicate_release_is_refused(self) -> None:
        event = ReleaseEvent(
            version="1.4.2", digest=_ARTIFACT_DIGEST, released_at=_NOW - timedelta(days=2)
        )
        with pytest.raises(ArtifactDeclarationError) as excinfo:
            _supply_chain(release_history=(event, event))
        assert excinfo.value.rule == "supply_chain.duplicate_release"

    def test_every_source_chain_entry_carries_the_notice(self) -> None:
        for entry in _supply_chain().source_chain:
            assert entry.notice == SIGNATURE_TRUST_NOTICE

    def test_the_actor_field_is_a_declaration_not_an_identity(self) -> None:
        entry = _supply_chain().source_chain[0]
        assert entry.actor == "acme.labs"
        assert "cannot verify artifact signatures" in entry.notice


# ── revocation ──────────────────────────────────────────────────────────────


class TestRevocation:
    def test_a_revocation_is_announced_before_it_is_in_force(self) -> None:
        revocation = _revocation(
            issued_at=_NOW - timedelta(hours=2), propagation_deadline=_NOW + timedelta(hours=1)
        )
        artifact = _artifact()
        assert revocation.applies_to(artifact) is True
        assert dispatches(artifact, [revocation], now=_NOW) is True
        pending = pending_revocations(artifact, [revocation], now=_NOW)
        assert [rev.revocation_id for rev in pending] == ["acme.rev.0001"]
        assert blocking_revocations(artifact, [revocation], now=_NOW) == ()

    def test_a_revoked_artifact_cannot_dispatch_after_its_deadline(self) -> None:
        revocation = _revocation(
            issued_at=_NOW - timedelta(hours=6), propagation_deadline=_NOW - timedelta(hours=1)
        )
        artifact = _artifact()
        assert dispatches(artifact, [revocation], now=_NOW) is False
        assert len(blocking_revocations(artifact, [revocation], now=_NOW)) == 1
        assert pending_revocations(artifact, [revocation], now=_NOW) == ()

    def test_the_deadline_instant_itself_is_in_force(self) -> None:
        revocation = _revocation(propagation_deadline=_NOW)
        artifact = _artifact()
        assert dispatches(artifact, [revocation], now=_NOW - timedelta(seconds=1)) is True
        assert dispatches(artifact, [revocation], now=_NOW) is False

    def test_the_refusal_names_the_revocation_that_caused_it(self) -> None:
        revocation = _revocation()
        message = dispatch_refusal(_artifact(), [revocation], now=_NOW)
        assert "acme.rev.0001" in message
        assert "security_defect" in message
        assert _ARTIFACT_DIGEST in message
        assert "acme.packs.net@1.4.2" in message

    def test_no_refusal_is_an_empty_string(self) -> None:
        assert dispatch_refusal(_artifact(), [], now=_NOW) == ""

    def test_a_digest_mismatch_in_the_revocation_does_not_match(self) -> None:
        revocation = _revocation(digest=_TAMPERED_DIGEST)
        assert applicable_revocations(_artifact(), [revocation]) == ()
        assert dispatches(_artifact(), [revocation], now=_NOW) is True

    def test_a_publisher_scoped_revocation_withdraws_every_version(self) -> None:
        revocation = _revocation(
            scope=RevocationScope.PUBLISHER,
            artifact_id=None,
            version=None,
            digest=None,
            publisher_id="acme.labs",
        )
        assert revocation.applies_to(_artifact()) is True
        assert dispatches(_artifact(), [revocation], now=_NOW) is False

    def test_a_registry_scoped_revocation_withdraws_only_that_registry(self) -> None:
        revocation = _revocation(
            scope=RevocationScope.REGISTRY,
            artifact_id=None,
            version=None,
            digest=None,
            registry_id="community.registry",
        )
        assert revocation.applies_to(_artifact()) is True
        other = _artifact(
            registry=_registry(
                registry_id="acme.private",
                scope=RegistryScope.ORGANIZATION_PRIVATE,
                organization="Acme",
            ),
            publisher=_publisher(organization="Acme"),
        )
        assert revocation.applies_to(other) is False
        assert dispatches(other, [revocation], now=_NOW) is True

    @pytest.mark.parametrize(
        ("overrides", "rule"),
        [
            pytest.param({"artifact_id": None}, "revocation.incomplete_scope", id="no-artifact"),
            pytest.param(
                {"artifact_id": None, "version": None, "digest": None},
                "revocation.incomplete_scope",
                id="empty-version-scope",
            ),
            pytest.param(
                {"publisher_id": "acme.labs"},
                "revocation.scope_overreach",
                id="version-scope-also-names-publisher",
            ),
            pytest.param(
                {"propagation_deadline": _NOW - timedelta(days=2)},
                "revocation.deadline_before_issue",
                id="deadline-before-issue",
            ),
        ],
    )
    def test_a_malformed_revocation_is_refused_at_construction(
        self, overrides: dict[str, object], rule: str
    ) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _revocation(**overrides)  # type: ignore[arg-type]
        assert excinfo.value.rule == rule

    def test_the_scope_to_field_mapping_is_one_to_one(self) -> None:
        targets = {
            RevocationScope.ARTIFACT_VERSION: {
                "artifact_id": "acme.packs.net",
                "version": "1.4.2",
                "digest": _ARTIFACT_DIGEST,
            },
            RevocationScope.PUBLISHER: {"publisher_id": "acme.labs"},
            RevocationScope.REGISTRY: {"registry_id": "community.registry"},
        }
        every_field = ("artifact_id", "version", "digest", "publisher_id", "registry_id")
        for scope, named in targets.items():
            complete = _revocation(
                scope=scope,
                **{name: named.get(name) for name in every_field},
            )
            assert complete.scope is scope
            for name, value in named.items():
                assert getattr(complete, name) == value
            for name in set(every_field) - set(named):
                assert getattr(complete, name) is None

    def test_applicable_revocations_are_sorted_and_deterministic(self) -> None:
        first = _revocation(revocation_id="acme.rev.0001")
        second = _revocation(revocation_id="acme.rev.0002", reason=RevocationReason.LICENSE)
        ids = [rev.revocation_id for rev in applicable_revocations(_artifact(), [second, first])]
        assert ids == ["acme.rev.0001", "acme.rev.0002"]

    def test_every_revocation_names_its_target(self) -> None:
        assert "acme.packs.net@1.4.2" in _revocation().names
        assert (
            "publisher acme.labs"
            in _revocation(
                scope=RevocationScope.PUBLISHER,
                artifact_id=None,
                version=None,
                digest=None,
                publisher_id="acme.labs",
            ).names
        )
        assert (
            "registry community.registry"
            in _revocation(
                scope=RevocationScope.REGISTRY,
                artifact_id=None,
                version=None,
                digest=None,
                registry_id="community.registry",
            ).names
        )


# ── approvals ───────────────────────────────────────────────────────────────


class TestNewApprovals:
    def test_a_deprecated_artifact_cannot_back_a_new_approval(self) -> None:
        artifact = _artifact(deprecation=_deprecation())
        certification = _cert(record=_certified())
        refusals = approval_refusals(artifact, [certification], [], now=_NOW)
        assert any(refusal.startswith("artifact.deprecated:") for refusal in refusals)
        assert backs_new_approval(artifact, [certification], [], now=_NOW) is False
        with pytest.raises(TrustLabelError) as excinfo:
            require_trust_label(
                artifact, [certification], claimed=ArtifactClass.VERIFIED_COMMUNITY, now=_NOW
            )
        assert excinfo.value.code == "deprecated_artifact"

    def test_deprecation_is_not_overridable_by_evidence(self) -> None:
        artifact = _artifact(deprecation=_deprecation())
        official = _artifact(
            registry=_registry(registry_id=OFFICIAL_REGISTRY_ID, scope=RegistryScope.OFFICIAL),
            deprecation=_deprecation(),
        )
        certification = _cert(record=_certified())
        assert classify_artifact(artifact, [certification], now=_NOW) is ArtifactClass.DEPRECATED
        assert classify_artifact(official, [certification], now=_NOW) is ArtifactClass.DEPRECATED
        assert backs_new_approval(artifact, [certification], [], now=_NOW) is False
        assert backs_new_approval(official, [certification], [], now=_NOW) is False

    def test_a_revoked_artifact_cannot_back_a_new_approval(self) -> None:
        certification = _cert(record=_certified())
        assert backs_new_approval(_artifact(), [certification], [], now=_NOW) is True
        assert backs_new_approval(_artifact(), [certification], [_revocation()], now=_NOW) is False
        assert any(
            refusal.startswith("artifact.revoked:")
            for refusal in approval_refusals(
                _artifact(), [certification], [_revocation()], now=_NOW
            )
        )

    def test_an_unverified_artifact_cannot_back_a_new_approval(self) -> None:
        refusals = approval_refusals(_artifact(), [], [], now=_NOW)
        assert refusals == (
            "artifact.unverified: acme.packs.net@1.4.2 has no certification record; an approval "
            "would rest on a publisher declaration alone",
        )

    def test_records_about_other_bytes_are_reported_as_a_mismatch(self) -> None:
        certification = _cert(record=_certified(), digest=_OTHER_DIGEST)
        refusals = approval_refusals(_artifact(), [certification], [], now=_NOW)
        assert len(refusals) == 1
        assert refusals[0].startswith("artifact.digest_mismatch:")

    def test_a_lapsed_record_is_reported_as_not_current(self) -> None:
        lapsed = expire_by_time(_certified(), now=_BEYOND)
        refusals = approval_refusals(_artifact(), [_cert(record=lapsed)], [], now=_BEYOND)
        assert len(refusals) == 1
        assert refusals[0].startswith("artifact.certification_not_current:")

    def test_every_refusal_is_reported_at_once(self) -> None:
        artifact = _artifact(deprecation=_deprecation())
        refusals = approval_refusals(artifact, [], [_revocation()], now=_NOW)
        codes = [refusal.split(":")[0] for refusal in refusals]
        assert codes == ["artifact.deprecated", "artifact.revoked", "artifact.unverified"]


# ── federation ──────────────────────────────────────────────────────────────


class TestFederation:
    def test_a_private_registry_federated_with_official_is_still_private(self) -> None:
        """Peers share bytes, not standing.

        This is the negative control for the whole distribution axis: the only
        way an organization could self-promote is by federating with the
        official catalogue, and that must change nothing.
        """
        federated = _registry(
            registry_id="acme.private",
            scope=RegistryScope.ORGANIZATION_PRIVATE,
            organization="Acme",
            federates_with=(OFFICIAL_REGISTRY_ID,),
        )
        artifact = _artifact(registry=federated, publisher=_publisher(organization="Acme"))
        assert artifact.registry.is_official is False
        assert classify_artifact(artifact, [], now=_NOW) is ArtifactClass.ORGANIZATION_PRIVATE
        assert classify_artifact(artifact, [_cert(record=_certified())], now=_NOW) is (
            ArtifactClass.ORGANIZATION_PRIVATE
        )
        with pytest.raises(TrustLabelError) as excinfo:
            require_trust_label(artifact, [], claimed=ArtifactClass.OFFICIAL, now=_NOW)
        assert excinfo.value.code == "not_official_registry"
        assert "federation with it grants nothing" in str(excinfo.value)

    def test_federation_is_not_an_input_to_classification_at_all(self) -> None:
        """Adding a federation edge changes no label, for any scope.

        Stated over the whole matrix rather than one case, because "federation
        is not a promotion input" is a claim about the *signature* of
        :func:`classify_artifact` — it takes an artifact and records, and a
        registry set is not among them.
        """
        import inspect

        parameters = set(inspect.signature(classify_artifact).parameters)
        assert parameters == {"artifact", "certifications", "now"}
        assert not parameters & {"registries", "federation", "peers", "trust_store"}

    def test_federation_closure_is_transitive_and_deterministic(self) -> None:
        official = _registry(registry_id=OFFICIAL_REGISTRY_ID, scope=RegistryScope.OFFICIAL)
        community = _registry(federates_with=(OFFICIAL_REGISTRY_ID,))
        private = _registry(
            registry_id="acme.private",
            scope=RegistryScope.ORGANIZATION_PRIVATE,
            organization="Acme",
            federates_with=("community.registry",),
        )
        federation = federated_registries([private, community, official])
        assert federation.registry_ids == (
            "acme.private",
            "community.registry",
            OFFICIAL_REGISTRY_ID,
        )
        assert federation.contains("acme.private") is True
        assert federation.contains("unknown.registry") is False
        assert federation == federated_registries([official, community, private])

    def test_a_federation_cycle_terminates(self) -> None:
        a = _registry(registry_id="a.registry", federates_with=("b.registry",))
        b = _registry(registry_id="b.registry", federates_with=("a.registry",))
        federation = federated_registries([a, b])
        assert federation.registry_ids == ("a.registry", "b.registry")

    def test_an_unknown_peer_is_absent_from_the_closure_rather_than_a_crash(self) -> None:
        """The docstring promises totality; the walk used to raise ``KeyError``.

        A registry naming a peer this table does not carry is a fact about the
        caller's table, not about the peer. Following the edge put an id in the
        closure with no row behind it and then indexed the table with it, so a
        documented input crashed a function documented as total.
        """
        alone = _registry(registry_id="a.registry", federates_with=("ghost.registry",))
        federation = federated_registries([alone])

        assert federation.registry_ids == ("a.registry",)
        assert federation.contains("ghost.registry") is False

    def test_a_dangling_edge_does_not_hide_the_peers_that_do_resolve(self) -> None:
        """Skipping the unknown peer must not truncate the reachable closure."""
        a = _registry(registry_id="a.registry", federates_with=("ghost.registry", "b.registry"))
        b = _registry(registry_id="b.registry", federates_with=("c.registry",))
        c = _registry(registry_id="c.registry")

        assert federated_registries([a, b, c]).registry_ids == (
            "a.registry",
            "b.registry",
            "c.registry",
        )

    def test_a_seed_outside_the_membership_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="federation seeds are not in its own"):
            RegistryFederation(
                seed_registry_ids=("acme.private",), registry_ids=("community.registry",)
            )

    def test_an_empty_federation_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="at least one seed"):
            RegistryFederation(seed_registry_ids=(), registry_ids=())

    def test_a_private_registry_with_no_owner_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="names no organization"):
            _registry(registry_id="acme.private", scope=RegistryScope.ORGANIZATION_PRIVATE)

    def test_a_public_registry_cannot_claim_an_organization(self) -> None:
        with pytest.raises(ValidationError, match="names organization"):
            _registry(scope=RegistryScope.COMMUNITY, organization="Acme")

    def test_a_registry_cannot_federate_with_itself(self) -> None:
        with pytest.raises(ValidationError, match="federates with itself"):
            _registry(federates_with=("community.registry",))

    def test_a_private_artifact_whose_publisher_names_another_org_is_refused(self) -> None:
        with pytest.raises(ArtifactDeclarationError) as excinfo:
            _artifact(
                registry=_registry(
                    registry_id="acme.private",
                    scope=RegistryScope.ORGANIZATION_PRIVATE,
                    organization="Acme",
                ),
                publisher=_publisher(organization="Othercorp"),
            )
        assert excinfo.value.rule == "artifact.organization_mismatch"


# ── publisher declarations are never authentication ─────────────────────────


class TestPublisherDeclarationIsNotAuthentication:
    def test_a_declaration_is_exactly_a_name_an_id_and_a_contact(self) -> None:
        fields = set(PublisherDeclaration.model_fields)
        assert fields == {"publisher_id", "display_name", "contact", "organization"}

    def test_it_reports_itself_as_declaration_only_and_carries_the_notice(self) -> None:
        publisher = _publisher()
        assert publisher.declaration_only is True
        assert publisher.notice == PUBLISHER_DECLARATION_NOTICE
        assert "not" in PUBLISHER_DECLARATION_NOTICE

    def test_a_perfect_declaration_does_not_promote_anything(self) -> None:
        """The strongest declaration available still earns no label.

        This is the assertion that matters most for the honesty of the whole
        module: there is no string a publisher can put in these fields that
        moves an artifact up a class.
        """
        artifact = _artifact(publisher=_publisher(organization=None))
        assert classify_artifact(artifact, [], now=_NOW) is ArtifactClass.UNVERIFIED
        label = artifact.trust_label([], now=_NOW)
        assert label.artifact_class is ArtifactClass.UNVERIFIED
        assert label.may_display_certified_state is False

    def test_the_label_notice_sits_next_to_the_class(self) -> None:
        label = trust_label(_artifact(), [], now=_NOW)
        assert label.notice == SIGNATURE_TRUST_NOTICE
        assert label.meaning() == CLASS_MEANING[ArtifactClass.UNVERIFIED]

    def test_every_class_reports_a_notice(self) -> None:
        for certification in ([], [_cert(record=_certified())]):
            label = trust_label(_artifact(), certification, now=_NOW)
            assert label.notice == SIGNATURE_TRUST_NOTICE
            assert label.meaning() in set(CLASS_MEANING.values())

    def test_the_class_vocabulary_has_no_word_for_authorship(self) -> None:
        banned = ("signed", "trusted", "authenticated", "attested", "official_verified")
        for artifact_class in ArtifactClass:
            assert not any(word in artifact_class.value for word in banned)

    def test_the_assertion_order_covers_every_class_exactly_once(self) -> None:
        assert set(ASSERTION_ORDER) == set(ArtifactClass)
        assert len(ASSERTION_ORDER) == len(ArtifactClass)
        assert ASSERTION_ORDER[0] is ArtifactClass.UNVERIFIED


# ── the artifact type itself ────────────────────────────────────────────────


class TestArtifactShape:
    def test_it_refuses_a_malformed_identifier(self) -> None:
        with pytest.raises(ValidationError, match="lowercase dotted identifier"):
            Artifact(
                artifact_id="Not An Id",
                version="1.0.0",
                digest=_ARTIFACT_DIGEST,
                publisher=_publisher(),
                registry=_registry(),
                license_id="MIT",
                changelog_ref="c",
            )

    def test_it_refuses_a_malformed_digest(self) -> None:
        with pytest.raises(ValidationError, match="64 lowercase hex"):
            Artifact(
                artifact_id="acme.packs.net",
                version="1.0.0",
                digest="nope",
                publisher=_publisher(),
                registry=_registry(),
                license_id="MIT",
                changelog_ref="c",
            )

    def test_it_refuses_an_empty_changelog_reference(self) -> None:
        with pytest.raises(ValidationError, match="changelog_ref is required"):
            Artifact(
                artifact_id="acme.packs.net",
                version="1.0.0",
                digest=_ARTIFACT_DIGEST,
                publisher=_publisher(),
                registry=_registry(),
                license_id="MIT",
                changelog_ref="   ",
            )

    def test_it_refuses_a_duplicate_dependency(self) -> None:
        dependency = ArtifactDependency(name="acme-tc", constraint=">=1.4")
        with pytest.raises(ArtifactDeclarationError) as excinfo:
            _artifact(dependencies=(dependency, dependency))
        assert excinfo.value.rule == "artifact.duplicate_dependency"

    def test_it_is_frozen(self) -> None:
        artifact = _artifact()
        with pytest.raises(ValidationError):
            artifact.digest = _OTHER_DIGEST  # type: ignore[misc]

    def test_its_label_reads_the_digest_and_the_version(self) -> None:
        artifact = _artifact()
        assert artifact.ref == "acme.packs.net@1.4.2"
        assert artifact.label == f"acme.packs.net@1.4.2#{_ARTIFACT_DIGEST[:12]}"
        assert artifact.is_deprecated is False

    def test_it_serialises_and_revalidates(self) -> None:
        artifact = _artifact(deprecation=_deprecation())
        document = artifact.model_dump(mode="json")
        assert Artifact.model_validate(document) == artifact


# ── the domain law, restated locally ────────────────────────────────────────


def test_the_module_has_no_io_or_upward_imports() -> None:
    source = Path(marketplace_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    banned = {
        "asyncio",
        "socket",
        "subprocess",
        "sqlite3",
        "pathlib",
        "os",
        "mayhem.toolkit",
        "mayhem.agents",
        "mayhem.controller",
        "mayhem.infra",
        "mayhem.providers",
    }
    assert not imported & banned, f"marketplace imports {sorted(imported & banned)}"
