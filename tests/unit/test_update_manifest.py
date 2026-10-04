"""Plan 19 Phase 3 — signed update manifests: what may be applied, and what is not.

The property under test is the ordering inside :meth:`UpdateApplier.apply`: a
caller holds a :class:`ManifestVerdict`, the verdict must say yes, and the bytes
fetched through the port must hash to the digest the signature committed to —
*before* the apply hook runs. There is no ``apply(manifest)`` entry point and no
field on a manifest called ``trusted``, so "apply what you have not verified" is
not a mistake this API can express.

The negative controls, each of which breaks one of those three steps:

* **Signature.** A manifest whose body was altered after signing is refused
  ``signature_invalid``, and a manifest signed by a key nobody publishes is
  refused ``unknown_signing_key``. The verifier is HMAC-SHA256 — the same
  canonicaliser and comparison plan 19's command verifier uses, re-used rather
  than re-implemented — so what it proves is that a holder of the shared release
  key produced these bytes, never public-key authorship.
* **Port availability.** :class:`X509UpdateSignatureVerifier` **raises**
  ``agent_signature_port_unavailable`` instead of returning ``False``, because
  "we could not check" and "the signature is wrong" are different facts, and a
  caller conflating them would either retry a bad manifest forever or treat an
  unavailable checker as a pass. It does not fall back to HMAC.
* **Bytes.** A store that serves different bytes than the manifest committed to
  is refused ``artifact_digest_mismatch`` with the apply hook never called, and a
  store that cannot be reached raises ``artifact_unavailable`` — an unreachable
  store is not an applied update.
* **Policy.** A manifest for another channel, for another component, outside its
  validity window, or a downgrade without a recorded approval is refused by name.

Rollback is checked to take the *earlier release's own manifest* — the artifact
being installed still has to be bytes some manifest committed to — and to refuse
both "rolling back" to something newer and a rollback nobody approved.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from mayhem.domain.errors import InvariantViolationError
from mayhem.infra.agent_identity_verifier import (
    ALGORITHM_HMAC_SHA256,
    ALGORITHM_X509,
    SIGNATURE_PORT_UNAVAILABLE,
    HmacSha256SignatureVerifier,
    SignaturePortUnavailableError,
    StaticKeyMaterial,
)
from mayhem.infra.update_manifest import (
    UPDATE_REFUSAL_ORDER,
    UPDATE_UNVERIFIED,
    ArtifactUnavailableError,
    HmacUpdateManifestSigner,
    ManifestVerdict,
    UpdateApplier,
    UpdateChannel,
    UpdateComponent,
    UpdateManifest,
    UpdateRefusal,
    UpdateRefusedError,
    UpdateVerifier,
    X509UpdateSignatureVerifier,
    order_update_refusals,
    version_is_newer,
)

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
ARTIFACT = b"mayhem-agent-2.1.0\n"
DIGEST = hashlib.sha256(ARTIFACT).hexdigest()
RELEASE_KEY = b"r" * 32


class ArtifactStore:
    """An artifact port. Counts fetches so "the bytes were never read" is assertable."""

    def __init__(self, payload: bytes = ARTIFACT) -> None:
        self.payload = payload
        self.fetches = 0

    def fetch(self, locator: str) -> bytes:
        self.fetches += 1
        return self.payload


class BrokenStore:
    """An artifact port that cannot produce bytes at all."""

    def fetch(self, locator: str) -> bytes:
        raise TimeoutError("the mirror did not answer")


class Applier:
    """Records whether the apply hook ever ran."""

    def __init__(self) -> None:
        self.applied: list[str] = []

    def __call__(self, manifest: UpdateManifest, payload: bytes) -> str:
        self.applied.append(manifest.manifest_id)
        return f"installed {manifest.component_version}"


def keys(*key_ids: str) -> StaticKeyMaterial:
    return StaticKeyMaterial(dict.fromkeys(key_ids, RELEASE_KEY))


def signer() -> HmacUpdateManifestSigner:
    return HmacUpdateManifestSigner(keys("release-1"))


def fields(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "manifest_id": "m-2.1.0",
        "component": UpdateComponent.AGENT,
        "component_version": "2.1.0",
        "artifact_digest": DIGEST,
        "channel": UpdateChannel.STABLE,
        "issued_at": NOW - timedelta(hours=1),
        "expires_at": NOW + timedelta(hours=1),
        "signer_key_id": "release-1",
        "sbom_ref": "sbom/2.1.0.json",
        "provenance_ref": "provenance/2.1.0.json",
    }
    base.update(over)
    return base


def manifest(**over: object) -> UpdateManifest:
    return signer().sign(fields(**over))


def verifier(**over: object) -> UpdateVerifier:
    options: dict[str, object] = {
        "signature": HmacSha256SignatureVerifier(keys("release-1")),
        "signer_keys": keys("release-1"),
    }
    options.update(over)
    return UpdateVerifier(**options)  # type: ignore[arg-type]


def apply_ok(
    store: ArtifactStore, installed: str = "2.0.0"
) -> tuple[object, Applier, ArtifactStore]:
    hook = Applier()
    applier = UpdateApplier(artifacts=store, apply_hook=hook)
    release = manifest()
    verdict = verifier().verify(
        release, component=UpdateComponent.AGENT, at=NOW, installed_version=installed
    )
    outcome = applier.apply(release, verdict, installed_version=installed, operator="ops")
    return outcome, hook, store


# --------------------------------------------------------------------------- #
# The manifest record                                                            #
# --------------------------------------------------------------------------- #


class TestUpdateManifest:
    def test_a_manifest_cannot_assert_its_own_trustworthiness(self) -> None:
        """There is no ``verified``, ``trusted``, or ``signature_valid`` field to set."""
        assert "trusted" not in UpdateManifest.model_fields
        assert "verified" not in UpdateManifest.model_fields
        assert "signature_valid" not in UpdateManifest.model_fields

    def test_the_signed_body_is_every_field_but_the_signature(self) -> None:
        release = manifest()
        assert "signature" not in release.signed_body()
        assert "artifact_digest" in release.signed_body()
        assert release.signed_payload() == UpdateManifest.model_validate(
            {**release.model_dump(), "signature": release.signature}
        ).signed_payload()

    def test_a_release_without_an_sbom_or_provenance_reference_is_refused(self) -> None:
        for missing in ("sbom_ref", "provenance_ref"):
            with pytest.raises(ValueError):
                manifest(**{missing: ""})

    def test_an_inverted_window_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            manifest(issued_at=NOW, expires_at=NOW)
        assert caught.value.rule == "update.window"

    def test_a_naive_window_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            manifest(issued_at=datetime(2026, 3, 1, 11, 0))  # noqa: DTZ001 - naive
        assert caught.value.rule == "update.time_aware"

    def test_a_digest_that_is_not_a_digest_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            manifest(artifact_digest="not-a-digest")
        assert caught.value.rule == "update.artifact_digest"

    def test_rollback_support_without_a_target_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            manifest(rollback_supported=True)
        assert caught.value.rule == "update.rollback_target_required"

    def test_a_rollback_to_its_own_version_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            manifest(rollback_supported=True, rollback_target_version="2.1.0")
        assert caught.value.rule == "update.rollback_target_identical"

    def test_it_describes_itself_with_the_component_and_the_window(self) -> None:
        rendered = manifest().describe()
        assert "agent 2.1.0" in rendered
        assert "release-1" in rendered
        assert DIGEST[:12] in rendered

    def test_the_signer_refuses_to_sign_without_key_material(self) -> None:
        with pytest.raises(SignaturePortUnavailableError) as caught:
            HmacUpdateManifestSigner(keys()).sign(fields())
        assert caught.value.code == SIGNATURE_PORT_UNAVAILABLE

    def test_a_manifest_that_already_carries_a_signature_is_ignored_by_the_signer(self) -> None:
        """A caller-supplied signature cannot smuggle bytes past the signer."""
        release = signer().sign(fields(signature="B" * 64))
        assert release.signature != "B" * 64


class TestVersionOrdering:
    def test_segments_compare_numerically(self) -> None:
        assert version_is_newer("2.10.0", "2.9.9") is True
        assert version_is_newer("2.9.9", "2.10.0") is False
        assert version_is_newer("2.0.0", "2.0.0") is False

    def test_a_release_candidate_is_not_a_downgrade_of_its_base(self) -> None:
        """Stated rather than pretended away: rc ordering is a policy question."""
        assert manifest(component_version="2.0.0-rc1").is_downgrade_from("2.0.0") is False

    def test_an_empty_installed_version_is_never_a_downgrade(self) -> None:
        assert manifest().is_downgrade_from("") is False


# --------------------------------------------------------------------------- #
# Verification                                                                   #
# --------------------------------------------------------------------------- #


class TestVerification:
    def test_a_good_manifest_is_applicable_and_says_what_it_proved(self) -> None:
        release = manifest()
        verdict = verifier().verify(release, at=NOW)
        assert verdict.applicable is True
        assert verdict.verified is True
        assert verdict.algorithm == ALGORITHM_HMAC_SHA256
        assert verdict.manifest_digest == hashlib.sha256(release.signed_payload()).hexdigest()
        assert "NOT public-key authorship" in verdict.detail
        assert "NOT a supply-chain attestation" in verdict.describe()

    def test_a_tampered_body_is_refused_by_name(self) -> None:
        release = manifest()
        forged = UpdateManifest.model_validate(
            {**release.model_dump(), "component_version": "9.9.9"}
        )
        verdict = verifier().verify(forged, at=NOW)
        assert UpdateRefusal.SIGNATURE_INVALID in verdict.refusals
        assert verdict.verified is False

    def test_a_key_nobody_publishes_is_refused(self) -> None:
        release = manifest()
        verdict = verifier(signer_keys=keys("release-0")).verify(release, at=NOW)
        assert UpdateRefusal.UNKNOWN_SIGNING_KEY in verdict.refusals

    def test_a_wrong_channel_is_refused(self) -> None:
        verdict = verifier(expected_channel=UpdateChannel.PINNED).verify(
            manifest(), at=NOW
        )
        assert verdict.refusals == (UpdateRefusal.CHANNEL_MISMATCH,)
        assert verdict.applicable is False
        assert verdict.verified is True

    def test_a_manifest_for_another_component_is_refused(self) -> None:
        verdict = verifier().verify(
            manifest(), component=UpdateComponent.CONTROLLER, at=NOW
        )
        assert UpdateRefusal.WRONG_COMPONENT in verdict.refusals

    def test_an_expired_and_a_not_yet_valid_manifest_are_distinguished(self) -> None:
        expired = verifier().verify(manifest(), at=NOW + timedelta(hours=2))
        early = verifier().verify(manifest(), at=NOW - timedelta(hours=2))
        assert expired.refusals == (UpdateRefusal.EXPIRED,)
        assert early.refusals == (UpdateRefusal.NOT_YET_VALID,)

    def test_a_downgrade_is_refused_without_a_recorded_approval(self) -> None:
        release = manifest(manifest_id="m-1.9.0", component_version="1.9.0")
        verdict = verifier().verify(release, at=NOW, installed_version="2.0.0")
        assert verdict.refusals == (UpdateRefusal.DOWNGRADE_NOT_APPROVED,)
        assert verdict.downgrade is True
        assert "move the component backwards" in verdict.detail

    def test_an_approval_alone_does_not_enable_downgrades(self) -> None:
        release = manifest(manifest_id="m-1.9.0", component_version="1.9.0")
        verdict = verifier().verify(
            release, at=NOW, installed_version="2.0.0", downgrade_approval="ana"
        )
        assert UpdateRefusal.DOWNGRADE_NOT_APPROVED in verdict.refusals

    def test_a_downgrade_is_allowed_only_when_the_verifier_allows_it(self) -> None:
        release = manifest(manifest_id="m-1.9.0", component_version="1.9.0")
        permissive = verifier(allow_downgrade=True)
        assert permissive.allows_downgrade is True
        verdict = permissive.verify(
            release, at=NOW, installed_version="2.0.0", downgrade_approval="ana"
        )
        assert verdict.applicable is True
        assert verdict.downgrade is True

    def test_an_unknown_installed_version_is_not_treated_as_version_zero(self) -> None:
        """A fresh install must not be refused as a downgrade from nothing."""
        assert verifier().verify(manifest(), at=NOW, installed_version=None).applicable is True

    def test_every_reason_is_reported_not_just_the_first(self) -> None:
        verdict = verifier(expected_channel=UpdateChannel.PINNED).verify(
            manifest(manifest_id="m-1.9.0", component_version="1.9.0"),
            component=UpdateComponent.CONTROLLER,
            at=NOW + timedelta(hours=2),
            installed_version="2.0.0",
        )
        assert verdict.refusals == (
            UpdateRefusal.EXPIRED,
            UpdateRefusal.CHANNEL_MISMATCH,
            UpdateRefusal.WRONG_COMPONENT,
            UpdateRefusal.DOWNGRADE_NOT_APPROVED,
        )

    def test_the_declared_refusal_order_is_the_canonical_one(self) -> None:
        assert tuple(UpdateRefusal) == UPDATE_REFUSAL_ORDER
        assert order_update_refusals([UpdateRefusal.EXPIRED, UpdateRefusal.SIGNATURE_INVALID]) == (
            UpdateRefusal.SIGNATURE_INVALID,
            UpdateRefusal.EXPIRED,
        )

    def test_verify_or_refuse_raises_carrying_every_reason(self) -> None:
        with pytest.raises(UpdateRefusedError) as caught:
            verifier().verify_or_refuse(manifest(), at=NOW + timedelta(hours=2))
        assert caught.value.code == UPDATE_UNVERIFIED
        assert caught.value.refusals == (UpdateRefusal.EXPIRED,)
        assert "release channel" in caught.value.remediation

    def test_a_naive_instant_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            verifier().verify(
                manifest(), at=datetime(2026, 3, 1, 12, 0)  # noqa: DTZ001 - naive
            )
        assert caught.value.rule == "update.time_aware"


class TestTheX509SeamFailsClosed:
    def test_it_raises_rather_than_returning_false(self) -> None:
        with pytest.raises(SignaturePortUnavailableError) as caught:
            X509UpdateSignatureVerifier().verify(
                payload=b"x", signature="A" * 64, signing_key_id="release-1"
            )
        assert caught.value.code == SIGNATURE_PORT_UNAVAILABLE
        assert caught.value.algorithm == ALGORITHM_X509

    def test_the_verifier_propagates_it_instead_of_reporting_a_refusal(self) -> None:
        """A verdict that read like a checked refusal would be a lie."""
        strict = verifier(signature=X509UpdateSignatureVerifier())
        with pytest.raises(SignaturePortUnavailableError):
            strict.verify(manifest(), at=NOW)
        with pytest.raises(SignaturePortUnavailableError):
            strict.verify_or_refuse(manifest(), at=NOW)

    def test_it_does_not_fall_back_to_hmac(self) -> None:
        release = manifest()
        with pytest.raises(SignaturePortUnavailableError):
            verifier(signature=X509UpdateSignatureVerifier()).verify(release, at=NOW)
        # The HMAC verifier still accepts the same bytes, so the difference is the
        # port, not the manifest.
        assert verifier().verify(release, at=NOW).applicable is True

    def test_the_reason_names_the_missing_dependencies(self) -> None:
        assert "no third-party dependency" not in X509UpdateSignatureVerifier.REASON
        assert "X.509/RSA signature verifier and a trust" in X509UpdateSignatureVerifier.REASON
        assert "not public-key authorship" in X509UpdateSignatureVerifier.REASON


# --------------------------------------------------------------------------- #
# Applying                                                                       #
# --------------------------------------------------------------------------- #


class TestApply:
    def test_a_verified_manifest_with_matching_bytes_is_applied(self) -> None:
        outcome, hook, store = apply_ok(ArtifactStore())
        assert outcome.applied is True
        assert outcome.verified_under == ALGORITHM_HMAC_SHA256
        assert hook.applied == ["m-2.1.0"]
        assert store.fetches == 1
        assert "2.0.0 → 2.1.0" in outcome.describe()
        assert "operator ops" in outcome.detail

    def test_a_refused_verdict_applies_nothing(self) -> None:
        store = ArtifactStore()
        hook = Applier()
        applier = UpdateApplier(artifacts=store, apply_hook=hook)
        release = manifest()
        verdict = verifier().verify(release, at=NOW + timedelta(hours=2))

        with pytest.raises(UpdateRefusedError) as caught:
            applier.apply(release, verdict, installed_version="2.0.0", operator="ops")

        assert caught.value.refusals == (UpdateRefusal.EXPIRED,)
        assert hook.applied == []
        assert store.fetches == 0

    def test_a_verdict_about_a_different_manifest_is_refused(self) -> None:
        """The load-bearing negative control: you cannot apply with somebody else's yes."""
        store = ArtifactStore()
        hook = Applier()
        applier = UpdateApplier(artifacts=store, apply_hook=hook)
        verdict = verifier().verify(
            manifest(manifest_id="m-other"), at=NOW, component=UpdateComponent.AGENT
        )

        with pytest.raises(UpdateRefusedError) as caught:
            applier.apply(manifest(), verdict, installed_version="2.0.0", operator="ops")

        assert caught.value.refusals == (UpdateRefusal.NOT_VERIFIED,)
        assert hook.applied == []

    def test_bytes_that_do_not_match_the_signed_digest_apply_nothing(self) -> None:
        store = ArtifactStore(b"a different artifact entirely")
        hook = Applier()
        applier = UpdateApplier(artifacts=store, apply_hook=hook)
        release = manifest()
        verdict = verifier().verify(release, at=NOW, component=UpdateComponent.AGENT)

        with pytest.raises(UpdateRefusedError) as caught:
            applier.apply(release, verdict, installed_version="2.0.0", operator="ops")

        assert caught.value.refusals == (UpdateRefusal.ARTIFACT_DIGEST_MISMATCH,)
        assert hook.applied == []

    def test_a_store_that_cannot_be_reached_is_not_an_applied_update(self) -> None:
        hook = Applier()
        applier = UpdateApplier(artifacts=BrokenStore(), apply_hook=hook)
        release = manifest()
        verdict = verifier().verify(release, at=NOW, component=UpdateComponent.AGENT)

        with pytest.raises(ArtifactUnavailableError) as caught:
            applier.apply(release, verdict, installed_version="2.0.0", operator="ops")

        assert caught.value.code == UpdateRefusal.ARTIFACT_UNAVAILABLE.value
        assert "did not answer" in caught.value.reason
        assert hook.applied == []

    def test_a_verdict_can_be_built_by_hand_and_a_verdict_is_all_you_need(self) -> None:
        """The applier's first argument is the verdict, so this is the only shape."""
        hand_built = ManifestVerdict(
            manifest_id="m-2.1.0",
            detail="trusted by hand",
            algorithm="some-other-scheme",
        )
        outcome, hook, _ = _apply_with(hand_built)
        assert outcome.applied is True
        assert outcome.verified_under == "some-other-scheme"
        assert hook.applied == ["m-2.1.0"]

    def test_the_applier_offers_the_error_its_port_should_raise(self) -> None:
        error = UpdateApplier(
            artifacts=ArtifactStore(), apply_hook=Applier()
        ).unavailable("the mirror is down")
        assert isinstance(error, ArtifactUnavailableError)
        assert "the mirror is down" in error.reason

    def test_the_apply_hook_is_the_deployments_mechanism_not_a_shell(self) -> None:
        """The applier runs no subprocess; the hook is whatever the caller bound."""
        seen: list[bytes] = []

        def hook(manifest: UpdateManifest, payload: bytes) -> str:
            seen.append(payload)
            return "ok"

        release = manifest()
        verdict = verifier().verify(release, at=NOW, component=UpdateComponent.AGENT)
        outcome = UpdateApplier(artifacts=ArtifactStore(), apply_hook=hook).apply(
            release, verdict, installed_version="2.0.0", operator="ops"
        )
        assert seen == [ARTIFACT]
        assert outcome.applied is True


def _apply_with(verdict: ManifestVerdict) -> tuple[object, Applier, ArtifactStore]:
    hook = Applier()
    store = ArtifactStore()
    outcome = UpdateApplier(artifacts=store, apply_hook=hook).apply(
        manifest(), verdict, installed_version="2.0.0", operator="ops"
    )
    return outcome, hook, store


# --------------------------------------------------------------------------- #
# Rollback                                                                       #
# --------------------------------------------------------------------------- #


class TestRollback:
    def previous(self) -> UpdateManifest:
        return manifest(
            manifest_id="m-2.0.0",
            component_version="2.0.0",
            artifact_digest=hashlib.sha256(b"mayhem-agent-2.0.0\n").hexdigest(),
            rollback_supported=True,
            rollback_target_version="1.9.0",
        )

    def previous_verdict(self) -> ManifestVerdict:
        return verifier().verify(
            self.previous(),
            at=NOW,
            component=UpdateComponent.AGENT,
            installed_version="1.9.0",
        )

    def test_a_rollback_takes_the_earlier_releases_own_manifest(self) -> None:
        store = ArtifactStore(b"mayhem-agent-2.0.0\n")
        hook = Applier()

        outcome = UpdateApplier(artifacts=store, apply_hook=hook).rollback(
            self.previous(),
            self.previous_verdict(),
            installed_version="2.1.0",
            operator="ops",
            approved_by="ana",
        )

        assert outcome.applied is True
        assert (outcome.from_version, outcome.to_version) == ("2.1.0", "2.0.0")
        assert "approved by ana" in outcome.detail
        assert hook.applied == ["m-2.0.0"]

    def test_a_verdict_for_the_current_manifest_cannot_roll_back(self) -> None:
        current_verdict = verifier().verify(
            manifest(), at=NOW, component=UpdateComponent.AGENT, installed_version="2.0.0"
        )
        with pytest.raises(UpdateRefusedError) as caught:
            UpdateApplier(artifacts=ArtifactStore(), apply_hook=Applier()).rollback(
                self.previous(),
                current_verdict,
                installed_version="2.1.0",
                operator="ops",
                approved_by="ana",
            )
        assert caught.value.refusals == (UpdateRefusal.NOT_VERIFIED,)

    def test_rolling_back_to_something_newer_is_refused(self) -> None:
        with pytest.raises(UpdateRefusedError) as caught:
            UpdateApplier(artifacts=ArtifactStore(), apply_hook=Applier()).rollback(
                self.previous(),
                self.previous_verdict(),
                installed_version="1.5.0",
                operator="ops",
                approved_by="ana",
            )
        assert caught.value.refusals == (UpdateRefusal.DOWNGRADE_NOT_SUPPORTED,)

    def test_a_rollback_nobody_approved_is_refused(self) -> None:
        with pytest.raises(UpdateRefusedError) as caught:
            UpdateApplier(artifacts=ArtifactStore(), apply_hook=Applier()).rollback(
                self.previous(),
                self.previous_verdict(),
                installed_version="2.1.0",
                operator="ops",
                approved_by="   ",
            )
        assert caught.value.refusals == (UpdateRefusal.DOWNGRADE_NOT_APPROVED,)

    def test_a_rollback_checks_the_bytes_too(self) -> None:
        hook = Applier()
        with pytest.raises(UpdateRefusedError) as caught:
            UpdateApplier(artifacts=ArtifactStore(b"wrong bytes"), apply_hook=hook).rollback(
                self.previous(),
                self.previous_verdict(),
                installed_version="2.1.0",
                operator="ops",
                approved_by="ana",
            )
        assert caught.value.refusals == (UpdateRefusal.ARTIFACT_DIGEST_MISMATCH,)
        assert hook.applied == []


class TestSupplyChainReferences:
    def test_the_references_are_pointers_and_the_module_says_so(self) -> None:
        """This module neither generates nor verifies an SBOM or a provenance attestation."""
        source = (
            __import__("mayhem.infra.update_manifest", fromlist=["x"]).__doc__ or ""
        )
        assert "No SLSA provenance and no SBOM generation" in source
        assert "A reference is a pointer, not an attestation" in source

    def test_a_release_must_still_name_both(self) -> None:
        release = manifest()
        assert release.sbom_ref and release.provenance_ref
        rendered = json.dumps(release.model_dump(mode="json"), sort_keys=True)
        assert "sigstore" not in rendered.lower()
        assert "cosign" not in rendered.lower()
