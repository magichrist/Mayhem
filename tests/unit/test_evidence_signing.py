"""Plan 12 Phase 3: evidence signing — sign, verify, refuse.

Every refusal in this file has a negative control beside it, because the failure
mode that matters for signing is not "the happy path is broken" — it is that a
requested algorithm gets silently downgraded, a rotated key keeps verifying, an
unsafe key file loads anyway, or an unsigned manifest reports as signed. Those
are asserted explicitly.

The suite also pins the honesty gates: the scheme is HMAC-SHA256, it is
symmetric, and no verdict may claim public-key verification is available.
"""

from __future__ import annotations

import stat
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from mayhem.domain.attestation import AttestedTimestamp, Manifest, RetentionClass
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.infra.attestation_store import seal_run_evidence
from mayhem.infra.evidence_signing import (
    PUBLIC_KEY_ALGORITHMS_IMPLEMENTED,
    CustodyMode,
    CustodyUnavailableError,
    EvidenceSignature,
    HmacLocalKeySigner,
    KeyMaterialError,
    KeyStoreBackedVerifier,
    LocalKeyStore,
    LocalKeyVerifier,
    SignatureAlgorithm,
    SignatureRepository,
    SignatureStateError,
    SigningNotImplementedError,
    TrustRoot,
    TrustRootRefusedError,
    UnavailableCustodySigner,
    signer_for,
    trust_store_for,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

T0 = datetime(2026, 4, 1, 9, 0, 0, tzinfo=UTC)
READING = AttestedTimestamp(wall_clock=T0, monotonic_ns=1_000_000, source="system")
TRUST_ROOT = "mayhem-local"


# --------------------------------------------------------------------------- #
# Fixtures                                                                      #
# --------------------------------------------------------------------------- #


@pytest.fixture
def key_store(tmp_path: Path) -> LocalKeyStore:
    store = LocalKeyStore(tmp_path / "keys")
    store.create_key("alpha", note="release CI")
    return store


@pytest.fixture
def manifest() -> Manifest:
    return Manifest(
        manifest_id="run-1:manifest",
        run_id="run-1",
        retention_class=RetentionClass.HOT,
    )


@pytest.fixture
def open_store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


def seal(store: Store, run_id: str = "run-1") -> Manifest:
    """Seal a run through Phase 2's own path and return its stored manifest."""
    envelope = EvidenceEnvelope.model_validate(
        {
            "run_id": run_id,
            "plan_hash": "plan-hash-1",
            "verdict": "pass",
            "step_reports": ({"step_id": "s1", "status": "completed"},),
            "created_at": T0.isoformat(),
            "redaction_metrics": {"policy_version": "redaction-v9", "redacted_path_count": 0},
        }
    )
    sealed = seal_run_evidence(
        store,
        envelope,
        run_status="completed",
        verdict="pass",
        manifest_id=f"{run_id}:manifest",
        recorded_at=READING,
        created_at=READING,
    )
    return sealed.manifest


# --------------------------------------------------------------------------- #
# The algorithm honesty gate                                                    #
# --------------------------------------------------------------------------- #


def test_public_key_algorithms_are_declared_and_refused(key_store: LocalKeyStore) -> None:
    """Ed25519/X.509 exist as names and refuse; nothing silently downgrades."""
    assert PUBLIC_KEY_ALGORITHMS_IMPLEMENTED is False
    for algorithm in (SignatureAlgorithm.ED25519, SignatureAlgorithm.X509):
        with pytest.raises(SigningNotImplementedError) as refusal:
            signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT, algorithm=algorithm)
        assert refusal.value.algorithm == str(algorithm)
        # The refusal must name the gap and the reason for refusing rather than
        # falling back, so an operator cannot read a downgrade as a success.
        assert "hmac-sha256 only" in str(refusal.value)


def test_verification_of_an_unimplemented_algorithm_reports_rather_than_raises(
    manifest: Manifest,
) -> None:
    """An unknown algorithm is a verdict with a reason, never a traceback."""
    signature = EvidenceSignature(
        artifact_kind="attestation_manifest",
        artifact_id=manifest.manifest_id,
        algorithm=SignatureAlgorithm.ED25519,
        key_id="alpha",
        key_fingerprint="0" * 64,
        trust_root_id=TRUST_ROOT,
        signature="AAAA",
        signed_digest="0" * 64,
    )
    verdict = LocalKeyVerifier(()).verify_signature(signature, manifest)
    assert verdict.verified is False
    assert verdict.trusted is False
    assert any("not implemented" in error for error in verdict.errors)


def test_unavailable_custody_modes_refuse_with_no_fallback(manifest: Manifest) -> None:
    """The KMS/HSM and Sigstore rungs refuse rather than signing locally."""
    for mode in (CustodyMode.KMS_HSM, CustodyMode.SIGSTORE):
        signer = UnavailableCustodySigner(trust_root_id=TRUST_ROOT, mode=mode)
        with pytest.raises(CustodyUnavailableError) as refusal:
            signer.sign_manifest(manifest)
        assert refusal.value.mode == str(mode)


def test_a_signature_must_name_a_trust_root(key_store: LocalKeyStore) -> None:
    """An unnamed trust root would let any key holder claim deployment trust."""
    key = key_store.load_key("alpha")
    with pytest.raises(TrustRootRefusedError) as refusal:
        HmacLocalKeySigner(key=key, trust_root_id="")
    assert "trust root" in str(refusal.value)


# --------------------------------------------------------------------------- #
# Sign and verify                                                               #
# --------------------------------------------------------------------------- #


def test_sign_then_verify_offline(key_store: LocalKeyStore, manifest: Manifest) -> None:
    """The whole point: sign with a local key, verify with no database."""
    trust_store = trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    signature = signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT).sign_manifest(manifest)

    verdict = KeyStoreBackedVerifier(key_store, trust_store).verify_signature(signature, manifest)
    assert verdict.verified is True
    assert verdict.trusted is True
    assert verdict.signed_digest == signature.signed_digest
    assert verdict.public_key is False


def test_every_pass_records_the_symmetric_caveat(
    key_store: LocalKeyStore, manifest: Manifest
) -> None:
    """A pass must never read as authorship verifiable by a third party."""
    signature = signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT).sign_manifest(manifest)
    verdict = KeyStoreBackedVerifier(
        key_store, trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    ).verify_signature(signature, manifest)

    assert verdict.verified is True
    assert verdict.public_key is False
    assert any("symmetric" in warning for warning in verdict.warnings)
    assert verdict.to_dict()["public_key_verification_available"] is False


def test_verification_needs_no_database_no_store_and_no_network(
    key_store: LocalKeyStore, manifest: Manifest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Phase 5's negative control: verification with the control plane absent.

    The claim under test is that a third party can check evidence with nothing
    but the signature and the key material. That claim is worth nothing if it
    quietly depends on the database being reachable, so the control plane is
    *made hostile* rather than merely absent: ``Store.open_migrated`` and the
    sqlite3 module are replaced with bombs that fail the test if touched. A
    verifier that reached for either would raise, not pass.
    """
    import sqlite3

    import mayhem.infra.store as store_module

    def bomb(*args: object, **kwargs: object) -> object:
        raise AssertionError("signature verification must not touch the store")

    monkeypatch.setattr(store_module.Store, "open_migrated", bomb)
    monkeypatch.setattr(sqlite3, "connect", bomb)

    trust_store = trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    signature = signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT).sign_manifest(manifest)

    verdict = KeyStoreBackedVerifier(key_store, trust_store).verify_signature(signature, manifest)
    assert verdict.verified is True
    assert verdict.trusted is True

    # And it still refuses honestly with the store still unreachable.
    tampered = manifest.model_copy(update={"run_id": "run-2"})
    refused = KeyStoreBackedVerifier(key_store, trust_store).verify_signature(signature, tampered)
    assert refused.verified is False


def test_a_manifest_swapped_under_a_valid_signature_is_rejected(
    key_store: LocalKeyStore, manifest: Manifest
) -> None:
    """Phase 5's second negative control: a bundle with a swapped artifact.

    Substituting an entirely different, internally-consistent manifest for the
    signed one is the attack a digest check alone can miss — the replacement has
    its own self-consistent ``chain_root``. The signature binds the artifact by
    id and digest, so the swap is named rather than accepted.
    """
    trust_store = trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    signature = signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT).sign_manifest(manifest)
    swapped = Manifest(manifest_id=manifest.manifest_id, run_id="attacker-run")

    verdict = KeyStoreBackedVerifier(key_store, trust_store).verify_signature(signature, swapped)

    assert verdict.verified is False
    # Caught by the signed-digest gate before the HMAC is even computed, which is
    # the better outcome: the failure names *what* happened (the bytes under this
    # signature are not the bytes that were signed) rather than reporting a bare
    # "does not verify" with no cause.
    assert any("signed digest does not match" in error for error in verdict.errors)


def test_tampering_with_the_manifest_fails_verification(
    key_store: LocalKeyStore, manifest: Manifest
) -> None:
    """Any covered byte changing names the failure instead of passing."""
    signature = signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT).sign_manifest(manifest)
    altered = manifest.model_copy(update={"run_id": "run-2"})
    verdict = KeyStoreBackedVerifier(
        key_store, trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    ).verify_signature(signature, altered)

    assert verdict.verified is False
    assert any("signed digest does not match" in error for error in verdict.errors)


def test_tampering_with_the_signature_bytes_fails(
    key_store: LocalKeyStore, manifest: Manifest
) -> None:
    """Flipped signature bytes must not verify, and must not raise."""
    signature = signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT).sign_manifest(manifest)
    forged = EvidenceSignature(
        **{
            **signature.to_dict(),
            "signature": ("B" if signature.signature[0] != "B" else "C") + signature.signature[1:],
        }
        | {"algorithm": SignatureAlgorithm.HMAC_SHA256}
    )
    verdict = KeyStoreBackedVerifier(
        key_store, trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    ).verify_signature(forged, manifest)

    assert verdict.verified is False
    assert any("does not verify" in error for error in verdict.errors)


def test_a_signature_for_another_manifest_is_refused(
    key_store: LocalKeyStore, manifest: Manifest
) -> None:
    """A signature is evidence about a named artifact, never a bearer token."""
    other = manifest.model_copy(update={"manifest_id": "run-9:manifest"})
    signature = signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT).sign_manifest(manifest)
    verdict = KeyStoreBackedVerifier(
        key_store, trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    ).verify_signature(signature, other)

    assert verdict.verified is False
    assert any("covers manifest" in error for error in verdict.errors)


def test_unsigned_is_distinguished_from_invalid(manifest: Manifest) -> None:
    """Absent and wrong are two different facts and must never be conflated."""
    verdict = LocalKeyVerifier(()).verify_signature(None, manifest)
    assert verdict.verified is False
    assert verdict.trusted is False
    assert any("no signature" in error for error in verdict.errors)


# --------------------------------------------------------------------------- #
# Trust                                                                         #
# --------------------------------------------------------------------------- #


def test_an_unknown_key_is_reported_untrusted_even_when_bytes_verify(
    key_store: LocalKeyStore, manifest: Manifest
) -> None:
    """Trust is the reader's question; a stranger's valid signature is untrusted."""
    signature = signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT).sign_manifest(manifest)
    verdict = KeyStoreBackedVerifier(key_store, (TrustRoot(trust_root_id="someone-elses"),))
    verdict_ = verdict.verify_signature(signature, manifest)

    assert verdict_.verified is True
    assert verdict_.trusted is False
    assert any("no trust root" in error for error in verdict_.errors)


def test_no_trust_store_verifies_nothing(key_store: LocalKeyStore, manifest: Manifest) -> None:
    """An empty trust store must not read as "everything is fine"."""
    signature = signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT).sign_manifest(manifest)
    verdict = KeyStoreBackedVerifier(key_store, ()).verify_signature(signature, manifest)

    assert verdict.verified is False
    assert any("no trust store" in error for error in verdict.errors)


def test_rotation_archives_the_old_key_so_old_evidence_stays_checkable(
    key_store: LocalKeyStore,
) -> None:
    """Rotation revokes *trust in the new key*, and never rewrites history.

    INVERTED from the pin that asserted rotation makes old signatures
    unverifiable. That premise left the operator no safe move at all: rotate and
    every historical signature becomes permanently unverifiable, or don't rotate
    and a leaked key stays live forever. Phase 5's acceptance is "old signatures
    verify under archived trust roots, new events use new keys", which needs the
    retired generation preserved rather than truncated.

    So rotation now archives the old secret and the assertion splits the two
    questions the verdict already reports separately:

    * against the **old** trust root — still verified, still trusted, because the
      archived material genuinely still checks the bytes;
    * against a trust root over the **new** key — bytes still verify (the archive
      found the right generation) but trust is refused, because the old
      fingerprint is no longer vouched for.

    The second half is the property that actually revokes: a rotated key can
    never produce anything new, because nothing forward trusts it.
    """
    manifest = Manifest(manifest_id="m", run_id="r")
    before = trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    signature = signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT).sign_manifest(manifest)
    assert KeyStoreBackedVerifier(key_store, before).verify_signature(signature, manifest).verified

    key_store.rotate_key("alpha")

    # The retired generation is retained, addressable by its own fingerprint.
    assert signature.key_fingerprint in key_store.archived_fingerprints("alpha")
    archived = key_store.load_archived_key("alpha", signature.key_fingerprint)
    assert archived.fingerprint == signature.key_fingerprint
    assert archived.fingerprint != key_store.fingerprint_for("alpha"), (
        "the archived generation must differ from the live one or rotation archived nothing"
    )

    # An archived trust root still vouches for the evidence it was made under.
    archived_root = TrustRoot(TRUST_ROOT).with_key(archived)
    kept = KeyStoreBackedVerifier(key_store, (archived_root,)).verify_signature(signature, manifest)
    assert kept.verified is True
    assert kept.trusted is True

    # The forward trust store covers the new key only, so the retired
    # fingerprint is refused even though the bytes still check out.
    forward = trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    lapsed = KeyStoreBackedVerifier(key_store, forward).verify_signature(signature, manifest)
    assert lapsed.trusted is False
    assert any("no trust root" in error for error in lapsed.errors)


def test_rotation_never_lets_a_retired_key_sign_anything_new(key_store: LocalKeyStore) -> None:
    """A rotated-out key must not be able to mint evidence the deployment accepts."""
    key_store.rotate_key("alpha")
    # The retired generation is now in the archive; take it from there.
    (archived_fingerprint,) = key_store.archived_fingerprints("alpha")
    retired = key_store.load_archived_key("alpha", archived_fingerprint)
    forward = trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    manifest = Manifest(manifest_id="m2", run_id="r")

    # Signing with the retired secret is technically possible for anyone holding
    # the archive file, so the verdict is what has to refuse it.
    forged = HmacLocalKeySigner(key=retired, trust_root_id=TRUST_ROOT).sign_manifest(manifest)
    verdict = KeyStoreBackedVerifier(key_store, forward).verify_signature(forged, manifest)

    assert verdict.trusted is False
    # ``verified`` is deliberately still True here, and asserting otherwise would
    # be asserting a lie about what the flag means. The bytes genuinely were
    # produced by the retired secret — that is what makes it a *forgery by a
    # deposed key* rather than random noise, and an auditor needs to see it.
    # Revocation is carried by ``trusted``: no forward root vouches for the
    # retired fingerprint, so the deployment does not accept it. Collapsing the
    # two flags would destroy exactly the distinction that names the attack.
    assert verdict.verified is True
    assert any("no trust root" in error for error in verdict.errors)


def test_archived_material_is_never_in_the_forward_trust_store(key_store: LocalKeyStore) -> None:
    """The trust store a deployment derives from itself covers live keys only."""
    key_store.rotate_key("alpha")
    key_store.rotate_key("alpha")

    assert key_store.active_key_ids() == key_store.list_keys()
    assert len(key_store.archived_fingerprints("alpha")) == 2
    forward = trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    (root,) = forward
    for fingerprint in key_store.archived_fingerprints("alpha"):
        assert root.vouches_for(fingerprint) is False


def test_an_unknown_archived_fingerprint_is_refused_not_guessed(key_store: LocalKeyStore) -> None:
    """Resolving the wrong generation would be worse than reporting unverified."""
    key_store.rotate_key("alpha")

    with pytest.raises(KeyMaterialError):
        key_store.load_archived_key("alpha", "a" * 64)
    with pytest.raises(KeyMaterialError):
        # Not even a fingerprint: the shape is refused before any filesystem access.
        key_store.load_archived_key("alpha", "not-a-fingerprint")


def test_a_trust_root_refuses_a_key_of_another_algorithm(key_store: LocalKeyStore) -> None:
    """Algorithm substitution is refused at the trust root, not coerced."""
    """A root vouching for Ed25519 must not accept an HMAC key."""
    root = TrustRoot(trust_root_id=TRUST_ROOT, algorithm=SignatureAlgorithm.ED25519)
    with pytest.raises(TrustRootRefusedError):
        root.with_key(key_store.load_key("alpha"))


def test_derived_trust_store_vouches_only_for_keys_that_exist(
    key_store: LocalKeyStore,
) -> None:
    """The trust store is derived from real keys, so it cannot drift from them."""
    (root,) = trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    assert root.vouches_for(key_store.fingerprint_for("alpha")) is True
    assert root.vouches_for("f" * 64) is False
    assert "f" * 64 not in root.fingerprints


# --------------------------------------------------------------------------- #
# Key custody                                                                   #
# --------------------------------------------------------------------------- #


def test_key_files_are_owner_only(tmp_path: Path) -> None:
    """A world-readable key would let any local user mint trusted evidence."""
    store = LocalKeyStore(tmp_path / "keys")
    store.create_key("alpha")
    assert stat.S_IMODE(store._path("alpha").stat().st_mode) == 0o600


def test_an_unsafe_key_file_is_refused_on_read(tmp_path: Path) -> None:
    """A key chmod-ed readable after the fact is refused at load, not audit."""
    store = LocalKeyStore(tmp_path / "keys")
    store.create_key("alpha")
    store._path("alpha").chmod(0o644)

    with pytest.raises(KeyMaterialError) as refusal:
        store.load_key("alpha")
    assert "0600" in str(refusal.value)


def test_a_short_key_is_refused(tmp_path: Path) -> None:
    """A brute-forceable key makes the authenticity claim worthless."""
    from mayhem.infra.evidence_signing import SigningKey

    with pytest.raises(KeyMaterialError):
        SigningKey(key_id="tiny", secret=b"tooshort")


def test_a_key_id_may_not_name_a_path(tmp_path: Path) -> None:
    """A key id is an identifier; escaping the key directory is refused."""
    store = LocalKeyStore(tmp_path / "keys")
    with pytest.raises(KeyMaterialError):
        store.load_key("../escape")


def test_a_secret_never_appears_in_serialised_forms(key_store: LocalKeyStore) -> None:
    """The identity may be published; the secret must never be serialised.

    The fingerprint is *supposed* to appear — naming which key signed is the
    point of a signature record. The secret must not, in any form.
    """

    key = key_store.load_key("alpha")
    rendered = repr(key.to_dict())
    assert key.fingerprint in rendered  # identity is publishable
    assert key.secret.hex() not in rendered
    assert "secret" not in key.to_dict()

    # And the trust root vouches by fingerprint only.
    (root,) = trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    assert key.secret.hex() not in repr(root.to_dict())
    assert key.fingerprint in root.to_dict()["fingerprints"]


# --------------------------------------------------------------------------- #
# Persistence                                                                   #
# --------------------------------------------------------------------------- #


def test_signing_records_signature_and_state_in_one_step(
    open_store: Store, key_store: LocalKeyStore
) -> None:
    """The surface seam signs and records together, so the halves cannot drift."""
    manifest = seal(open_store)
    repository = SignatureRepository(open_store)
    verifier = KeyStoreBackedVerifier(
        key_store, trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    )

    signature = repository.sign_manifest(
        manifest.manifest_id,
        signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT),
        verifier=verifier,
    )

    assert repository.load_signature(manifest.manifest_id) == signature
    state, reason = repository.load_signature_state(manifest.manifest_id)
    assert state == SignatureRepository.SIGNATURE_SIGNED
    assert "alpha" in reason


def test_a_foreign_key_is_recorded_as_signed_but_untrusted(
    open_store: Store, key_store: LocalKeyStore
) -> None:
    """Evidence signed by a key we do not hold is recorded, not hidden."""
    manifest = seal(open_store)
    repository = SignatureRepository(open_store)
    verifier = KeyStoreBackedVerifier(key_store, (TrustRoot(trust_root_id="other-root"),))

    repository.sign_manifest(
        manifest.manifest_id,
        signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT),
        verifier=verifier,
    )

    state, reason = repository.load_signature_state(manifest.manifest_id)
    assert state == SignatureRepository.SIGNATURE_SIGNED_UNTRUSTED
    assert "not trusted" in reason


def test_signing_an_unsealed_manifest_is_refused(
    open_store: Store, key_store: LocalKeyStore
) -> None:
    """A signature over evidence that was never recorded authenticates nothing."""
    repository = SignatureRepository(open_store)
    verifier = KeyStoreBackedVerifier(key_store, ())

    with pytest.raises(SignatureStateError) as refusal:
        repository.sign_manifest(
            "never-sealed",
            signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT),
            verifier=verifier,
        )
    assert "no such sealed manifest" in str(refusal.value)


def test_phase2_unsigned_state_is_preserved(open_store: Store) -> None:
    """Phase 2's value and reason are unchanged: old rows still read truthfully."""
    from mayhem.infra.attestation_store import (
        SIGNATURE_UNSIGNED_NO_SIGNING,
        UNSIGNED_REASON_NO_SIGNING,
    )

    manifest = seal(open_store)
    state, reason = SignatureRepository(open_store).load_signature_state(manifest.manifest_id)
    assert state == SIGNATURE_UNSIGNED_NO_SIGNING
    assert reason == UNSIGNED_REASON_NO_SIGNING


def test_an_unsigned_reason_can_be_recorded(open_store: Store) -> None:
    """A deployment with signing available but no signer records why."""
    manifest = seal(open_store)
    repository = SignatureRepository(open_store)

    repository.record_unsigned_reason(manifest.manifest_id, "no signing key configured")

    state, reason = repository.load_signature_state(manifest.manifest_id)
    assert state == SignatureRepository.UNSIGNED_NO_SIGNING
    assert reason == "no signing key configured"


def test_an_incomplete_signature_record_is_refused() -> None:
    """A record that lost a field is refused, not verified against blanks."""
    with pytest.raises(SignatureStateError) as refusal:
        EvidenceSignature.from_dict(
            {"artifact_kind": "attestation_manifest", "artifact_id": "m", "signature": "AA"}
        )
    assert "missing required field" in str(refusal.value)


def test_signatures_are_listed_per_run(open_store: Store, key_store: LocalKeyStore) -> None:
    """An auditor can enumerate every signature for a run."""
    manifest = seal(open_store)
    repository = SignatureRepository(open_store)
    verifier = KeyStoreBackedVerifier(
        key_store, trust_store_for(key_store, trust_root_id=TRUST_ROOT)
    )
    repository.sign_manifest(
        manifest.manifest_id,
        signer_for(key_store, "alpha", trust_root_id=TRUST_ROOT),
        verifier=verifier,
    )

    listed = repository.list_signatures("run-1")
    assert [item.artifact_id for item in listed] == [manifest.manifest_id]
