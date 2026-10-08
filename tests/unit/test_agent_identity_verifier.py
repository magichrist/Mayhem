"""Tests for agent-command verification (plan 19 Phase 2).

What is being tested, and what is deliberately not
--------------------------------------------------

:mod:`mayhem.infra.agent_identity_verifier` implements **HMAC-SHA256 over the
canonical envelope payload, compared in constant time**. That is a real
cryptographic check and these tests exercise it as one: a valid signature passes, a
tampered envelope fails, a different key fails, a rotated-out key fails, and the
canonical payload a signer signs is asserted to be byte-identical to what the
verifier checks.

What is *not* implemented and is pinned as such:

* **CA-backed X.509 mTLS.** :class:`X509CommandSignatureVerifier` is asserted to
  refuse with :data:`SIGNATURE_PORT_UNAVAILABLE` and to never return ``True``. It is
  the port, not the implementation.
* **Fault-pack signing.** ``providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED`` is
  ``False`` and is re-asserted here from the *other* direction: agent-command
  verification being real does not make pack verification real, and the two flags
  are independent. A test that pinned them together would be the bug.

The rest is the negative-control matrix the phase's acceptance implies: an unsigned
or tampered command is refused *by name* (the refusal names which check failed), a
command signed for another plan is refused, a replayed nonce is refused, and a
revoked or expired agent is refused.

Only the store is real IO; every clock is injected.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mayhem.domain.agent_identity import (
    AgentCredential,
    AgentIdentity,
    CertificateRef,
    Revocation,
    RevocationReason,
    TrustAnchorRef,
)
from mayhem.domain.attestation import canonical_event_bytes
from mayhem.domain.fabric import (
    FABRIC_PROTOCOL_VERSION,
    CommandBodyRef,
    FabricCommand,
    FabricCommandType,
    FencingToken,
)
from mayhem.domain.hashing import sha256_hex
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.infra.agent_identity_store import (
    REVOCATION_SCOPE_IDENTITY,
    AgentIdentityRepository,
)
from mayhem.infra.agent_identity_verifier import (
    ALGORITHM_HMAC_SHA256,
    ALGORITHM_X509,
    CHECK_ORDER,
    COMMAND_UNVERIFIED,
    SIGNATURE_PORT_UNAVAILABLE,
    AgentCommandVerifier,
    CheckOutcome,
    CommandRefusedError,
    HmacSha256CommandSigner,
    HmacSha256SignatureVerifier,
    SignaturePortUnavailableError,
    SqliteNonceLedger,
    StaticKeyMaterial,
    VerificationCheck,
    X509CommandSignatureVerifier,
    signed_payload,
    signing_key_for,
)
from mayhem.infra.store import Store
from mayhem.providers.pack import SIGNATURE_TRUST_NOTICE, SIGNATURE_VERIFICATION_IMPLEMENTED

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
AGENT = "ag-1"
CONTROLLER = "ctl-a"
OTHER_CONTROLLER = "ctl-b"
CREDENTIAL = "cr-1"
SUCCESSOR_CREDENTIAL = "cr-2"
SECRET = b"k" * 32
OTHER_SECRET = b"z" * 32
PLAN = sha256_hex('{"steps":1}')
OTHER_PLAN = sha256_hex('{"steps":2}')
CERT_FINGERPRINT = "a" * 64
CA_FINGERPRINT = "c" * 64
RUN_ID = "r-1"
STEP_ID = "s-1"
NONCE = "0123456789abcdef0123456789abcdef"


# --------------------------------------------------------------------------- #
# Builders                                                                     #
# --------------------------------------------------------------------------- #


def credential(
    *, credential_id: str = CREDENTIAL, expires_at: datetime | None = None
) -> AgentCredential:
    return AgentCredential(
        credential_id=credential_id,
        agent_id=AGENT,
        issued_at=NOW - timedelta(seconds=60),
        expires_at=NOW + timedelta(seconds=900) if expires_at is None else expires_at,
        rotate_before=300.0,
    )


def certificate(
    *, not_before: datetime | None = None, not_after: datetime | None = None
) -> CertificateRef:
    return CertificateRef(
        subject=f"agent={AGENT}",
        issuer="ca-mesh-1",
        serial="01",
        sha256_fingerprint=CERT_FINGERPRINT,
        not_before=NOW - timedelta(hours=1) if not_before is None else not_before,
        not_after=NOW + timedelta(hours=1) if not_after is None else not_after,
    )


def anchors() -> tuple[TrustAnchorRef, ...]:
    return (
        TrustAnchorRef(
            ca_id="ca-mesh-1",
            subject="ca-mesh-1",
            sha256_fingerprint=CERT_FINGERPRINT,
        ),
    )


def identity(
    *,
    cert: AgentCredential | None = None,
    with_certificate: bool = True,
    with_anchors: bool = True,
    cert_ref: CertificateRef | None = None,
) -> AgentIdentity:
    return AgentIdentity(
        agent_id=AGENT,
        controller_id=CONTROLLER,
        principal=Principal(principal_id="sa-agent-1", kind=PrincipalKind.WORKLOAD),
        scope=EnvironmentScope(environment="staging"),
        credential=credential() if cert is None else cert,
        certificate=(
            (certificate() if cert_ref is None else cert_ref) if with_certificate else None
        ),
        trust_anchors=anchors() if with_anchors else (),
    )


def fence(*, epoch: int = 1, holder: str = CONTROLLER) -> FencingToken:
    return FencingToken(run_id=RUN_ID, step_id=STEP_ID, holder=holder, epoch=epoch, issued_at=NOW)


def command_fields(
    *,
    nonce: str = NONCE,
    signing_key_id: str = CREDENTIAL,
    plan_digest: str = PLAN,
    token: FencingToken | None = None,
    command_id: str = "fc-1",
    idempotency_key: str | None = None,
    step_id: str = STEP_ID,
    agent_id: str = AGENT,
) -> dict[str, object]:
    """An unsigned envelope. ``signature`` is deliberately absent.

    Built as a field mapping rather than a :class:`FabricCommand` so the signer can
    mint it: the envelope has no construction path that omits ``signature``, which
    is exactly why signing goes through :class:`HmacSha256CommandSigner`.
    """
    return {
        "protocol": FABRIC_PROTOCOL_VERSION,
        "command_id": command_id,
        "run_id": RUN_ID,
        "step_id": step_id,
        "agent_id": agent_id,
        "plan_digest": plan_digest,
        "nonce": nonce,
        "idempotency_key": f"idem-{command_id}" if idempotency_key is None else idempotency_key,
        "fencing_token": (token if token is not None else fence()).model_dump(mode="json"),
        "command": CommandBodyRef(
            command_type=FabricCommandType.PREPARE,
            body_digest="d" * 64,
            body_ref="body-1",
        ).model_dump(mode="json"),
        "issued_at": NOW.isoformat(),
        "signing_key_id": signing_key_id,
    }


def signer(keys: StaticKeyMaterial) -> HmacSha256CommandSigner:
    return HmacSha256CommandSigner(keys)


def signed(
    keys: StaticKeyMaterial, *, nonce: str = NONCE, plan_digest: str = PLAN, **kwargs: object
) -> FabricCommand:
    """A validly signed envelope. ``**kwargs`` reaches :func:`command_fields`."""
    return signer(keys).sign_fields(
        command_fields(nonce=nonce, plan_digest=plan_digest, **kwargs)  # type: ignore[arg-type]
    )


def tampered(command: FabricCommand, **changes: object) -> FabricCommand:
    """A re-validated command with fields altered after signing.

    ``model_copy`` would skip validation, so the point of a tamper test is to prove
    the *verifier* notices — going through ``model_validate`` keeps the record
    honest about being a well-formed envelope that lies.
    """
    return FabricCommand.model_validate({**command.model_dump(), **changes})


@pytest.fixture
def store() -> Store:
    return Store.open_migrated(":memory:")


def enrol(store: Store, record: AgentIdentity | None = None) -> AgentIdentity:
    saved = identity() if record is None else record
    AgentIdentityRepository(store).save(saved)
    return saved


def keys_for(*ids: str) -> StaticKeyMaterial:
    material = StaticKeyMaterial()
    for key_id in ids:
        material.add(key_id, SECRET)
    return material


def verifier(store: Store, keys: StaticKeyMaterial, **kwargs: object) -> AgentCommandVerifier:
    """A verifier over the real store, the real nonce table, and a chosen port."""
    options: dict[str, object] = {
        "identities": AgentIdentityRepository(store),
        "signature": HmacSha256SignatureVerifier(keys),
        "nonces": SqliteNonceLedger(store),
    }
    options.update(kwargs)
    return AgentCommandVerifier(**options)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The canonical payload: signer and verifier cannot disagree                   #
# --------------------------------------------------------------------------- #


def test_signed_payload_agrees_with_the_domains_signing_payload() -> None:
    """The two canonicalisers must produce identical bytes for an ASCII envelope.

    ``FabricCommand.signing_payload`` (plan 03, ``domain.hashing.canonical_json``)
    and this module's :func:`signed_payload`
    (``domain.attestation.canonical_event_json``) are two spellings of "the bytes a
    signature covers". If they could drift, a command minted by a controller using
    one would be refused by an agent using the other — a failure that would look
    like a signature bug. Asserted rather than documented.
    """
    command = signed(keys_for(CREDENTIAL))
    assert signed_payload(command).decode("utf-8") == command.signing_payload()


def test_signed_payload_is_the_excluded_canonical_dump() -> None:
    command = signed(keys_for(CREDENTIAL))
    expected = canonical_event_bytes(command.model_dump(mode="json", exclude={"signature"}))
    assert signed_payload(command) == expected


def test_a_signature_over_different_bytes_does_not_verify() -> None:
    """NEGATIVE CONTROL: the MAC covers the payload, not the field named ``signature``."""
    keys = keys_for(CREDENTIAL)
    command = signed(keys)
    detached = signer(keys).algorithm_mac(b"some other bytes", SECRET)
    assert signed_payload(command) != b"some other bytes"
    assert command.signature != detached


# --------------------------------------------------------------------------- #
# Happy path                                                                   #
# --------------------------------------------------------------------------- #


def test_valid_command_verifies_and_spends_its_nonce(store: Store) -> None:
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)

    result = engine.verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert result.agent_id == AGENT
    assert result.algorithm == ALGORITHM_HMAC_SHA256
    assert result.identity_version == identity().version
    assert result.grant.identity.credential_id == CREDENTIAL
    # The nonce is spent by the time the caller holds the value: there is no window
    # in which a verified command could be replayed.
    assert NONCE in result.nonce_ledger.consumed
    assert engine.requires_nonce_recording is True
    assert "hmac-sha256" in result.describe()


def test_every_named_check_runs_and_passes_on_the_happy_path(store: Store) -> None:
    enrol(store)
    keys = keys_for(CREDENTIAL)
    result = verifier(store, keys).verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert tuple(o.check for o in result.outcomes) == CHECK_ORDER
    assert all(o.passed for o in result.outcomes)
    # CHECK_ORDER is the documented evaluation order and is asserted equal to the
    # enum's own declaration order, so the two cannot drift apart quietly.
    assert tuple(VerificationCheck) == CHECK_ORDER


# --------------------------------------------------------------------------- #
# Negative control: signature                                                   #
# --------------------------------------------------------------------------- #


def test_tampered_envelope_is_refused_by_name(store: Store) -> None:
    """NEGATIVE CONTROL: altered bytes ⇒ ``signature`` failed, by that name."""
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)
    altered = tampered(signed(keys), idempotency_key="idem-rewritten")

    with pytest.raises(CommandRefusedError) as excinfo:
        engine.verify(altered, expected_plan_digest=PLAN, now=NOW)

    refused = excinfo.value
    assert refused.code == COMMAND_UNVERIFIED
    assert VerificationCheck.SIGNATURE in refused.failed
    assert refused.command_id == "fc-1"
    detail = next(o.detail for o in refused.outcomes if o.check is VerificationCheck.SIGNATURE)
    assert "did not verify" in detail


def test_wrong_key_is_refused(store: Store) -> None:
    """NEGATIVE CONTROL: a MAC made with another agent's secret does not verify."""
    enrol(store)
    keys = keys_for(CREDENTIAL)
    forged = StaticKeyMaterial({CREDENTIAL: OTHER_SECRET})
    engine = verifier(store, keys)

    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(signed(forged), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.SIGNATURE in refused.value.failed


def test_unknown_signing_key_id_is_refused_not_bypassed(store: Store) -> None:
    """NEGATIVE CONTROL: an unresolvable key must never verify against empty bytes."""
    enrol(store)
    keys = keys_for(CREDENTIAL)
    # The verifier resolves no keys at all, while the command is signed under the
    # real one: the MAC is arithmetically correct and there is still nothing to
    # verify it with. This is the case that must refuse.
    engine_no_keys = verifier(store, StaticKeyMaterial())
    with pytest.raises(CommandRefusedError) as refused:
        engine_no_keys.verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.SIGNATURE in refused.value.failed
    detail = next(
        o.detail for o in refused.value.outcomes if o.check is VerificationCheck.SIGNATURE
    )
    assert "unknown key" in detail


def test_signer_refuses_to_mint_with_no_key_material() -> None:
    """NEGATIVE CONTROL: no key ⇒ no command, rather than a MAC over an empty key."""
    with pytest.raises(SignaturePortUnavailableError) as excinfo:
        signer(StaticKeyMaterial()).sign_fields(command_fields())
    assert excinfo.value.code == SIGNATURE_PORT_UNAVAILABLE


def test_short_key_is_refused(store: Store) -> None:
    """NEGATIVE CONTROL: a key below the block size cannot verify anything."""
    enrol(store)
    weak = StaticKeyMaterial({CREDENTIAL: b"short"})
    engine = verifier(store, weak)

    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(signed(weak), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.SIGNATURE in refused.value.failed


def test_malformed_signature_is_refused_without_raising(store: Store) -> None:
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)
    mangled = tampered(signed(keys), signature="A" * 64)

    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(mangled, expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.SIGNATURE in refused.value.failed


# --------------------------------------------------------------------------- #
# Negative control: the X.509 / mTLS port is defined and fails closed           #
# --------------------------------------------------------------------------- #


def test_x509_seam_is_defined_and_always_refuses() -> None:
    """The mTLS port exists and fails closed. **It is not an implementation.**

    Asserted with a fake over the real port shape, which is the only honest way to
    "prove the decision": a test that passed a real CA fixture would be claiming an
    X.509 implementation this build does not have.
    """
    port = X509CommandSignatureVerifier()
    assert port.algorithm == ALGORITHM_X509
    with pytest.raises(SignaturePortUnavailableError) as excinfo:
        port.verify(payload=b"x", signature="sig", signing_key_id=CREDENTIAL)
    assert excinfo.value.code == SIGNATURE_PORT_UNAVAILABLE
    assert excinfo.value.algorithm == ALGORITHM_X509
    assert "Phase 3" in excinfo.value.reason


def test_verifier_over_the_x509_seam_refuses_and_names_the_check(store: Store) -> None:
    """A verifier configured for X.509 refuses; it does not silently downgrade to HMAC.

    The downgrade is the dangerous failure mode: an attacker who can influence the
    algorithm name would otherwise choose the weaker scheme. Asserted by checking
    both the refusal *and* that the recorded algorithm is still the X.509 name.
    """
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys, signature=X509CommandSignatureVerifier())

    assert engine.algorithm == ALGORITHM_X509
    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.SIGNATURE in refused.value.failed
    outcome = next(o for o in refused.value.outcomes if o.check is VerificationCheck.SIGNATURE)
    assert outcome.algorithm == ALGORITHM_X509
    assert "not checked" in outcome.detail


def test_pack_signature_verification_is_still_unimplemented_and_unrelated() -> None:
    """Agent-command verification being real does **not** make pack signing real.

    The two flags are about different artefacts. This test exists so that nobody
    later "notices" the HMAC work above and relaxes the pack flag on the strength of
    it: a fault pack still carries an unverified claim of authorship, and the trust
    notice still has to ship with every pack verdict.
    """
    assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
    assert "cannot verify fault-pack signatures" in SIGNATURE_TRUST_NOTICE


# --------------------------------------------------------------------------- #
# Negative control: key binding and rotation                                   #
# --------------------------------------------------------------------------- #


def test_key_bound_to_a_superseded_credential_is_refused(store: Store) -> None:
    """NEGATIVE CONTROL: rotation retires the old key, not just the old record.

    The old key still resolves in the port and its MAC is still arithmetically
    correct; only ``key_binding`` refuses. Without that check "rotate the credential"
    would not actually retire anything.
    """
    rotated = identity().with_credential(
        credential(credential_id=SUCCESSOR_CREDENTIAL).successor(
            credential_id=SUCCESSOR_CREDENTIAL, ttl_s=900.0, now=NOW
        )
    )
    enrol(store, rotated)
    keys = keys_for(CREDENTIAL, SUCCESSOR_CREDENTIAL)
    engine = verifier(store, keys)
    stale = signed(keys, signing_key_id=CREDENTIAL)

    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(stale, expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.KEY_BINDING in refused.value.failed
    # The signature itself is fine — the refusal is about binding, not crypto.
    assert VerificationCheck.SIGNATURE not in refused.value.failed
    detail = next(
        o.detail for o in refused.value.outcomes if o.check is VerificationCheck.KEY_BINDING
    )
    assert "superseded" in detail


def test_current_credential_key_verifies_after_rotation(store: Store) -> None:
    rotated = identity().with_credential(
        credential(credential_id=SUCCESSOR_CREDENTIAL).successor(
            credential_id=SUCCESSOR_CREDENTIAL, ttl_s=900.0, now=NOW
        )
    )
    enrol(store, rotated)
    keys = keys_for(CREDENTIAL, SUCCESSOR_CREDENTIAL)

    result = verifier(store, keys).verify(
        signed(keys, signing_key_id=SUCCESSOR_CREDENTIAL), expected_plan_digest=PLAN, now=NOW
    )

    assert result.identity_version == rotated.version


def test_signing_key_for_follows_the_recorded_serial_when_present() -> None:
    with_serial = identity(cert=credential())
    serialised = AgentIdentity.model_validate(
        {
            **with_serial.model_dump(),
            "credential": {**with_serial.credential.model_dump(), "serial": "serial-9"},
        }
    )
    assert signing_key_for(serialised) == "serial-9"
    assert signing_key_for(with_serial) == CREDENTIAL


def test_unenrolled_agent_fails_closed_on_key_binding(store: Store) -> None:
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)

    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert {VerificationCheck.KEY_BINDING, VerificationCheck.IDENTITY_USABLE} <= set(
        refused.value.failed
    )
    assert VerificationCheck.CERTIFICATE_LIFETIME in refused.value.failed


# --------------------------------------------------------------------------- #
# Negative control: identity lifetime and revocation                            #
# --------------------------------------------------------------------------- #


def test_expired_credential_is_refused(store: Store) -> None:
    """NEGATIVE CONTROL: a live signature does not outlive the credential."""
    expired = credential(expires_at=NOW - timedelta(seconds=1))
    enrol(store, identity(cert=expired))
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)

    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.IDENTITY_USABLE in refused.value.failed
    # The MAC is still good — the agent simply may no longer be used.
    assert VerificationCheck.SIGNATURE not in refused.value.failed
    detail = next(
        o.detail for o in refused.value.outcomes if o.check is VerificationCheck.IDENTITY_USABLE
    )
    assert "expired" in detail


def test_revoked_agent_is_refused_even_with_a_valid_signature(store: Store) -> None:
    """NEGATIVE CONTROL: revocation beats a cryptographically perfect command."""
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)
    AgentIdentityRepository(store).revoke_agent(
        AGENT,
        Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by=CONTROLLER),
    )

    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.IDENTITY_USABLE in refused.value.failed
    detail = next(
        o.detail for o in refused.value.outcomes if o.check is VerificationCheck.IDENTITY_USABLE
    )
    assert "identity_revoked" in detail


def test_revocation_row_alone_refuses_when_the_identity_row_predates_it(store: Store) -> None:
    """NEGATIVE CONTROL: propagation holds across the crash between two writes.

    The revocation ledger row is written without updating the identity row — the
    exact state a crash between the two writes leaves. The agent must still be
    refused, because the repository consults the ledger on every authorization.
    """
    repository = AgentIdentityRepository(store)
    enrol(store)
    repository.record_revocation(
        AGENT,
        CREDENTIAL,
        Revocation(reason=RevocationReason.DECOMMISSIONED, revoked_at=NOW, revoked_by=CONTROLLER),
        scope=REVOCATION_SCOPE_IDENTITY,
    )
    assert repository.load(AGENT).revoked is False  # the identity row was not updated

    keys = keys_for(CREDENTIAL)
    with pytest.raises(CommandRefusedError) as refused:
        verifier(store, keys).verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.IDENTITY_USABLE in refused.value.failed


def test_credential_scoped_revocation_refuses_without_killing_the_identity(store: Store) -> None:
    """A burned key refuses; the *identity* stays usable. No invented outage."""
    repository = AgentIdentityRepository(store)
    enrol(store)
    repository.revoke_credential(
        AGENT,
        Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by=CONTROLLER),
    )
    keys = keys_for(CREDENTIAL)

    with pytest.raises(CommandRefusedError) as refused:
        verifier(store, keys).verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.IDENTITY_USABLE in refused.value.failed
    detail = next(
        o.detail for o in refused.value.outcomes if o.check is VerificationCheck.IDENTITY_USABLE
    )
    assert "credential_revoked" in detail
    assert "identity_revoked" not in detail


def test_command_for_another_controllers_agent_is_refused(store: Store) -> None:
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys, controller_id=OTHER_CONTROLLER)

    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.IDENTITY_USABLE in refused.value.failed
    detail = next(
        o.detail for o in refused.value.outcomes if o.check is VerificationCheck.IDENTITY_USABLE
    )
    assert "controller_mismatch" in detail


def test_own_controller_id_is_accepted(store: Store) -> None:
    enrol(store)
    keys = keys_for(CREDENTIAL)
    result = verifier(store, keys, controller_id=CONTROLLER).verify(
        signed(keys), expected_plan_digest=PLAN, now=NOW
    )
    assert result.agent_id == AGENT


# --------------------------------------------------------------------------- #
# Negative control: certificate window and pinning                             #
# --------------------------------------------------------------------------- #


def test_expired_certificate_is_refused(store: Store) -> None:
    enrol(store, identity(cert_ref=certificate(not_after=NOW - timedelta(seconds=1))))
    keys = keys_for(CREDENTIAL)

    with pytest.raises(CommandRefusedError) as refused:
        verifier(store, keys).verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.CERTIFICATE_LIFETIME in refused.value.failed


def test_unpinned_certificate_fails_closed(store: Store) -> None:
    """NEGATIVE CONTROL: an agent with no configured anchor is refused, not trusted."""
    enrol(store, identity(with_anchors=False))
    keys = keys_for(CREDENTIAL)

    with pytest.raises(CommandRefusedError) as refused:
        verifier(store, keys).verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.CERTIFICATE_LIFETIME in refused.value.failed
    detail = next(
        o.detail
        for o in refused.value.outcomes
        if o.check is VerificationCheck.CERTIFICATE_LIFETIME
    )
    assert "no_anchors" in detail


def test_certificate_pinning_is_a_window_check_not_chain_validation(store: Store) -> None:
    """A passing certificate check must say what it did **not** do.

    ``CertificateRef.chain_verified`` is ``False`` by construction in Phase 1 and
    nothing here changes that. Asserted on the detail text so the log line cannot be
    quoted as evidence of an X.509 chain check.
    """
    enrol(store)
    keys = keys_for(CREDENTIAL)
    result = verifier(store, keys).verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    passed = result.outcome_for(VerificationCheck.CERTIFICATE_LIFETIME)
    assert passed.passed
    assert "no X.509 chain was validated" in passed.detail


def test_agent_with_no_recorded_certificate_fails_closed_by_default(store: Store) -> None:
    enrol(store, identity(with_certificate=False))
    keys = keys_for(CREDENTIAL)

    with pytest.raises(CommandRefusedError) as refused:
        verifier(store, keys).verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.CERTIFICATE_LIFETIME in refused.value.failed


def test_certificate_requirement_can_be_turned_off_explicitly(store: Store) -> None:
    enrol(store, identity(with_certificate=False))
    keys = keys_for(CREDENTIAL)
    result = verifier(store, keys, require_certificate=False).verify(
        signed(keys), expected_plan_digest=PLAN, now=NOW
    )
    assert result.agent_id == AGENT


# --------------------------------------------------------------------------- #
# Negative control: plan-digest binding                                        #
# --------------------------------------------------------------------------- #


def test_command_signed_for_another_plan_is_refused(store: Store) -> None:
    """NEGATIVE CONTROL: a validly signed command for a superseded plan is refused.

    The signature is good and the key is bound — approvals are invalidated by a plan
    change, so binding is a separate decision from crypto.
    """
    enrol(store)
    keys = keys_for(CREDENTIAL)
    stale_plan_command = signed(keys, plan_digest=OTHER_PLAN)

    with pytest.raises(CommandRefusedError) as refused:
        verifier(store, keys).verify(stale_plan_command, expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.PLAN_BINDING in refused.value.failed
    assert VerificationCheck.SIGNATURE not in refused.value.failed
    detail = next(
        o.detail for o in refused.value.outcomes if o.check is VerificationCheck.PLAN_BINDING
    )
    assert "fabric_plan_mismatch" in detail


def test_no_expected_plan_digest_fails_closed(store: Store) -> None:
    """NEGATIVE CONTROL: a command that cannot be checked against a plan is refused.

    Skipping the binding check would be the convenient reading, and it is exactly
    the one that lets an approval outlive the plan it was granted against.
    """
    enrol(store)
    keys = keys_for(CREDENTIAL)

    with pytest.raises(CommandRefusedError) as refused:
        verifier(store, keys).verify(signed(keys), now=NOW)

    assert VerificationCheck.PLAN_BINDING in refused.value.failed


# --------------------------------------------------------------------------- #
# Negative control: nonce replay                                               #
# --------------------------------------------------------------------------- #


def test_replayed_nonce_is_refused_after_the_nonce_is_spent(store: Store) -> None:
    """NEGATIVE CONTROL: one nonce, one dispatch. The second is a replay."""
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)
    first = signed(keys)

    engine.verify(first, expected_plan_digest=PLAN, now=NOW)
    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(first, expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.NONCE_FRESHNESS in refused.value.failed
    detail = next(
        o.detail for o in refused.value.outcomes if o.check is VerificationCheck.NONCE_FRESHNESS
    )
    assert "fabric_replayed_nonce" in detail


def test_a_refused_command_does_not_burn_its_nonce(store: Store) -> None:
    """NEGATIVE CONTROL: only a *good* command spends a nonce.

    This is why ``nonce_freshness`` is evaluated last. A command refused for a
    superseded plan that also burned its nonce could never be re-minted, and the
    controller would have to invent a nonce to retry the same intent.
    """
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)
    stale = signed(keys, plan_digest=OTHER_PLAN)

    with pytest.raises(CommandRefusedError):
        engine.verify(stale, expected_plan_digest=PLAN, now=NOW)

    assert SqliteNonceLedger(store).load(RUN_ID, STEP_ID).consumed == frozenset()
    # The same envelope now passes once the receiver holds the right plan.
    result = engine.verify(stale, expected_plan_digest=OTHER_PLAN, now=NOW)
    assert NONCE in result.nonce_ledger.consumed


def test_nonce_is_durable_across_receiver_instances(store: Store) -> None:
    """NEGATIVE CONTROL: the ledger is in the store, not in the verifier's memory."""
    enrol(store)
    keys = keys_for(CREDENTIAL)
    verifier(store, keys).verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    # A different receiver object over the same store is a different process.
    with pytest.raises(CommandRefusedError) as refused:
        verifier(store, keys).verify(signed(keys), expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.NONCE_FRESHNESS in refused.value.failed
    assert SqliteNonceLedger(store).consumed_count() == 1


def test_a_fresh_nonce_for_the_same_intent_is_accepted(store: Store) -> None:
    """A retry re-spends the idempotency key and mints a fresh nonce. That is legal."""
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)
    first = signed(keys)
    engine.verify(first, expected_plan_digest=PLAN, now=NOW)

    retry = signed(
        keys,
        nonce="fedcba9876543210fedcba9876543210",
        command_id="fc-2",
        idempotency_key=first.idempotency_key,
    )
    result = engine.verify(retry, expected_plan_digest=PLAN, now=NOW)

    assert retry.idempotency_key == first.idempotency_key  # same effect
    assert retry.nonce != first.nonce  # a fresh nonce, never a reused one
    assert len(result.nonce_ledger.consumed) == 2


def test_a_retry_cannot_reuse_a_signed_field_by_editing_it(store: Store) -> None:
    """NEGATIVE CONTROL: the idempotency key is inside the signed payload.

    A retry that reuses the key has to be **re-signed**, because the key is part of
    the bytes the MAC covers. Editing it after signing is tampering, and is caught
    as such rather than being quietly accepted as a retry.
    """
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)
    first = signed(keys)
    engine.verify(first, expected_plan_digest=PLAN, now=NOW)

    edited = FabricCommand.model_validate(
        {
            **first.model_dump(),
            "command_id": "fc-2",
            "idempotency_key": first.idempotency_key,
            "nonce": "fedcba9876543210fedcba9876543210",
        }
    )
    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(edited, expected_plan_digest=PLAN, now=NOW)

    assert VerificationCheck.SIGNATURE in refused.value.failed


def test_no_nonce_port_makes_the_gap_observable(store: Store) -> None:
    """NEGATIVE CONTROL: without a nonce port the check is vacuous — and says so.

    :attr:`AgentCommandVerifier.requires_nonce_recording` exists so a deployment that
    believes it is recording nonces can assert that it is, instead of discovering
    otherwise after an incident.
    """
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys, nonces=None)

    assert engine.requires_nonce_recording is False
    result = engine.verify(signed(keys), expected_plan_digest=PLAN, now=NOW)
    detail = result.outcome_for(VerificationCheck.NONCE_FRESHNESS).detail
    assert "in memory only" in detail


# --------------------------------------------------------------------------- #
# Negative control: fencing                                                    #
# --------------------------------------------------------------------------- #


def test_command_from_a_deposed_owner_is_refused(store: Store) -> None:
    """NEGATIVE CONTROL: an older fence does not dispatch, MAC or not."""
    enrol(store)
    keys = keys_for(CREDENTIAL)
    engine = verifier(store, keys)
    served = fence(epoch=3)
    stale = signed(keys, token=fence(epoch=1, holder="ctl-deposed"))

    with pytest.raises(CommandRefusedError) as refused:
        engine.verify(stale, expected_plan_digest=PLAN, served_fence=served, now=NOW)

    assert VerificationCheck.FENCE in refused.value.failed
    detail = next(o.detail for o in refused.value.outcomes if o.check is VerificationCheck.FENCE)
    assert "fabric_stale_fence" in detail


def test_same_epoch_retry_still_dispatches(store: Store) -> None:
    """Plan 03's rule, unchanged: an equal fence is the same owner continuing."""
    enrol(store)
    keys = keys_for(CREDENTIAL)
    result = verifier(store, keys).verify(
        signed(keys, nonce="aaaa1111bbbb2222cccc3333dddd4444"),
        expected_plan_digest=PLAN,
        served_fence=fence(epoch=1),
        now=NOW,
    )
    assert result.agent_id == AGENT


def test_no_served_fence_skips_the_comparison_and_says_so(store: Store) -> None:
    enrol(store)
    keys = keys_for(CREDENTIAL)
    result = verifier(store, keys).verify(signed(keys), expected_plan_digest=PLAN, now=NOW)
    detail = result.outcome_for(VerificationCheck.FENCE).detail
    assert "no fence served yet" in detail


# --------------------------------------------------------------------------- #
# The refusal shape itself                                                     #
# --------------------------------------------------------------------------- #


def test_refusal_names_every_failed_check_in_canonical_order(store: Store) -> None:
    """A refusal lists the whole set, ordered, and carries the per-check detail."""
    enrol(store, identity(with_certificate=False))
    keys = keys_for(CREDENTIAL)
    command = signed(keys, plan_digest=OTHER_PLAN)

    with pytest.raises(CommandRefusedError) as refused:
        verifier(store, keys).verify(command, expected_plan_digest=PLAN, now=NOW)

    value = refused.value
    assert value.failed == (VerificationCheck.CERTIFICATE_LIFETIME, VerificationCheck.PLAN_BINDING)
    assert [o.check for o in value.outcomes if not o.passed] == list(value.failed)
    assert value.describe().startswith(COMMAND_UNVERIFIED)
    assert "remediation:" in value.describe()


def test_check_outcome_refuses_a_pass_with_no_observation() -> None:
    """``passed=True`` with no ``detail`` is refused at construction.

    Same rule as Phase 1's :class:`~mayhem.domain.backup.RestoreCheckResult`: "the row
    count matched" and "I clicked the button" are the same boolean, and only one of
    them is evidence.
    """
    with pytest.raises(Exception, match="detail"):
        CheckOutcome(check=VerificationCheck.SIGNATURE, passed=True, detail="")


def test_naive_verification_instant_is_refused(store: Store) -> None:
    enrol(store)
    keys = keys_for(CREDENTIAL)
    with pytest.raises(Exception, match="timezone-aware"):
        verifier(store, keys).verify(
            signed(keys),
            expected_plan_digest=PLAN,
            now=datetime(2026, 3, 1, 12, 0),  # noqa: DTZ001
        )
