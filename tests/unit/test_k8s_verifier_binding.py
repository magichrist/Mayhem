"""v1.1.0 plan 02 Phase 4 — the verifier the lane's debt note said was unbound.

`docs/v1.1.0/02_KUBERNETES_RUNTIME.md` recorded: *"No verifier bound by default…
no DaemonSet transport exists… Consequently the phase acceptance — controller-kill
mid-fault recovers with evidence proving it — is still not met."*

This file covers the **first** of those three, which is closable without a
cluster: `build_k8s_verifier` / `build_k8s_signer` join plan 19 Phase 2's
`AgentCommandVerifier` to the durable store, so a caller no longer assembles four
collaborators by hand and no longer gets "signature is a claim" by accident.

The store is **real** — `Store.open_migrated(":memory:")`, so the nonce ledger is
the durable `agent_command_nonces` table and the identity check reads the real
repository — and the cryptography is **real** HMAC-SHA256 over the canonical
envelope. That is the difference from the existing `test_k8s_fabric.py`, which
uses a deterministic stub signature precisely because no verifier was bound.

What is **not** claimed, repeated here so this file cannot be read as closing
Phase 4:

* the DaemonSet agent transport does not exist and no cluster was contacted;
* no live cell has run, so the phase acceptance is still open debt;
* HMAC is symmetric. It proves a key holder produced these bytes, not authorship
  to a third party; no X.509 chain is validated.

`plan 19`'s own verifier suite covers the check matrix in depth. What is asserted
*here* is narrower and specific to this lane: that the k8s dispatcher can be given
a real verifier, that the binding fails closed, and that the engine visibly
reports whether verification is on.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mayhem.controller import k8s_fabric
from mayhem.controller.k8s_fabric import (
    K8sVerifierUnavailable,
    build_k8s_signer,
    build_k8s_verifier,
)
from mayhem.domain.agent_identity import (
    AgentCredential,
    AgentIdentity,
    CertificateRef,
    TrustAnchorRef,
)
from mayhem.domain.errors import DomainError
from mayhem.domain.fabric import (
    FABRIC_PROTOCOL_VERSION,
    CommandBodyRef,
    FabricCommand,
    FabricCommandType,
    FencingToken,
)
from mayhem.domain.hashing import sha256_hex
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.infra.agent_identity_store import AgentIdentityRepository
from mayhem.infra.agent_identity_verifier import (
    ALGORITHM_HMAC_SHA256,
    ALGORITHM_X509,
    CommandRefusedError,
    HmacSha256CommandSigner,
    SignaturePortUnavailableError,
    StaticKeyMaterial,
    X509CommandSignatureVerifier,
)
from mayhem.infra.store import Store

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
AGENT = "agent-node-0"
CONTROLLER = "ctl-a"
CREDENTIAL = "cr-1"
SECRET = b"k" * 32
PLAN = sha256_hex('{"steps":1}')
RUN_ID = "r-1"
STEP_ID = "s-1"
NONCE = "0123456789abcdef0123456789abcdef"
CERT_FINGERPRINT = "a" * 64


@pytest.fixture
def store() -> Store:
    """A fully migrated control plane. Real tables, no fakes."""
    return Store.open_migrated(":memory:")


def keys() -> StaticKeyMaterial:
    """Key material keyed by **credential id**.

    That is the shape plan 19 Phase 2 established: a command's `signing_key_id`
    names the credential it was minted under, and `key_binding` refuses when the
    identity no longer names that key. Keying by an unrelated string here would
    make `key_binding` fail for a reason that has nothing to do with this lane.
    """
    return StaticKeyMaterial({CREDENTIAL: SECRET})


def enrol(store: Store) -> AgentIdentity:
    identity = AgentIdentity(
        agent_id=AGENT,
        controller_id=CONTROLLER,
        principal=Principal(principal_id="sa-agent-0", kind=PrincipalKind.WORKLOAD),
        scope=EnvironmentScope(environment="staging"),
        credential=AgentCredential(
            credential_id=CREDENTIAL,
            agent_id=AGENT,
            issued_at=NOW - timedelta(seconds=60),
            expires_at=NOW + timedelta(seconds=900),
            rotate_before=300.0,
        ),
        certificate=CertificateRef(
            subject=f"agent={AGENT}",
            issuer="ca-mesh-1",
            serial="01",
            sha256_fingerprint=CERT_FINGERPRINT,
            not_before=NOW - timedelta(hours=1),
            not_after=NOW + timedelta(hours=1),
        ),
        trust_anchors=(
            TrustAnchorRef(
                ca_id="ca-mesh-1",
                subject="ca-mesh-1",
                sha256_fingerprint=CERT_FINGERPRINT,
            ),
        ),
    )
    AgentIdentityRepository(store).save(identity)
    return identity


def command_fields(*, signing_key_id: str = CREDENTIAL, **overrides: object) -> dict[str, object]:
    """An unsigned envelope; ``signature`` is deliberately absent."""
    fields: dict[str, object] = {
        "protocol": FABRIC_PROTOCOL_VERSION,
        "command_id": "fc-1",
        "run_id": RUN_ID,
        "step_id": STEP_ID,
        "agent_id": AGENT,
        "plan_digest": PLAN,
        "nonce": NONCE,
        "idempotency_key": "idem-1",
        "fencing_token": FencingToken(
            run_id=RUN_ID, step_id=STEP_ID, holder=CONTROLLER, epoch=1, issued_at=NOW
        ).model_dump(mode="json"),
        "command": CommandBodyRef(
            command_type=FabricCommandType.INJECT,
            body_digest="d" * 64,
            body_ref="k8s.pod_kill",
        ).model_dump(mode="json"),
        "issued_at": NOW.isoformat(),
        "signing_key_id": signing_key_id,
    }
    fields.update(overrides)
    return fields


def signed(**overrides: object) -> FabricCommand:
    """A validly signed envelope, produced by the k8s lane's own signer."""
    return HmacSha256CommandSigner(keys()).sign_fields(command_fields(**overrides))  # type: ignore[arg-type]


# ── the binding ───────────────────────────────────────────────────────────────


class TestTheBindingIsFailClosed:
    def test_it_binds_a_real_verifier_over_the_durable_store(self, store: Store) -> None:
        verifier = build_k8s_verifier(store, keys=keys(), controller_id=CONTROLLER)
        assert verifier.algorithm == ALGORITHM_HMAC_SHA256
        # True means the replay check is backed by the `agent_command_nonces`
        # table, not by an in-memory set that dies with the process.
        assert verifier.requires_nonce_recording is True

    def test_an_unresolvable_key_id_is_refused_at_construction(self, store: Store) -> None:
        with pytest.raises(K8sVerifierUnavailable) as exc:
            build_k8s_verifier(
                store, keys=keys(), controller_id=CONTROLLER, require_key_ids=("nope",)
            )
        assert "nope" in str(exc.value)

    def test_a_resolvable_key_id_passes_the_same_gate(self, store: Store) -> None:
        verifier = build_k8s_verifier(
            store, keys=keys(), controller_id=CONTROLLER, require_key_ids=(CREDENTIAL,)
        )
        assert verifier is not None

    def test_the_refusal_names_the_key_and_the_deliberate_alternative(self, store: Store) -> None:
        with pytest.raises(K8sVerifierUnavailable) as exc:
            build_k8s_verifier(
                store, keys=keys(), controller_id=CONTROLLER, require_key_ids=("nope",)
            )
        message = str(exc.value)
        assert "nope" in message
        # The escape hatch has to be discoverable from the error itself, or an
        # operator's only option is to guess.
        assert "verifier=None" in message

    def test_an_empty_key_map_is_never_silently_accepted(self, store: Store) -> None:
        with pytest.raises(K8sVerifierUnavailable):
            build_k8s_verifier(
                store,
                keys=StaticKeyMaterial(),
                controller_id=CONTROLLER,
                require_key_ids=("anything",),
            )

    def test_the_refusal_is_a_domain_error(self) -> None:
        assert issubclass(K8sVerifierUnavailable, DomainError)


class TestTheSignatureIsNowAProof:
    """The property the debt note said did not hold."""

    def test_a_command_signed_by_the_lane_signer_verifies(self, store: Store) -> None:
        enrol(store)
        verifier = build_k8s_verifier(store, keys=keys(), controller_id=CONTROLLER)
        verified = verifier.verify(signed(), expected_plan_digest=PLAN, now=NOW)
        assert verified.command.command_id == "fc-1"
        assert verified.algorithm == ALGORITHM_HMAC_SHA256

    def test_a_stub_signature_is_refused_by_name(self, store: Store) -> None:
        enrol(store)
        verifier = build_k8s_verifier(store, keys=keys(), controller_id=CONTROLLER)
        # Long enough to satisfy the envelope's own field constraint, so the
        # refusal that follows is the *verifier's* and not a parse error.
        stub = FabricCommand.model_validate(
            {**command_fields(), "signature": "not-a-real-mac-value"}
        )
        with pytest.raises(CommandRefusedError) as exc:
            verifier.verify(stub, expected_plan_digest=PLAN, now=NOW)
        assert "signature" in {str(check) for check in exc.value.failed}

    def test_a_tampered_envelope_is_refused(self, store: Store) -> None:
        enrol(store)
        verifier = build_k8s_verifier(store, keys=keys(), controller_id=CONTROLLER)
        tampered = FabricCommand.model_validate(
            {**signed().model_dump(), "idempotency_key": "idem-2"}
        )
        with pytest.raises(CommandRefusedError) as exc:
            verifier.verify(tampered, expected_plan_digest=PLAN, now=NOW)
        assert "signature" in {str(check) for check in exc.value.failed}

    def test_a_replay_is_refused_against_the_durable_nonce_table(self, store: Store) -> None:
        enrol(store)
        verifier = build_k8s_verifier(store, keys=keys(), controller_id=CONTROLLER)
        verifier.verify(signed(), expected_plan_digest=PLAN, now=NOW)
        with pytest.raises(CommandRefusedError) as exc:
            verifier.verify(signed(), expected_plan_digest=PLAN, now=NOW)
        assert "nonce" in " ".join(str(check) for check in exc.value.failed)

    def test_a_command_for_another_plan_is_refused(self, store: Store) -> None:
        enrol(store)
        verifier = build_k8s_verifier(store, keys=keys(), controller_id=CONTROLLER)
        with pytest.raises(CommandRefusedError) as exc:
            verifier.verify(signed(), expected_plan_digest=sha256_hex("other"), now=NOW)
        assert "plan" in " ".join(str(check) for check in exc.value.failed)


class TestTheControlThatKeepsThePositiveCaseHonest:
    """Without this class the positive tests prove nothing.

    If every command were refused — a signer and verifier disagreeing about the
    canonical payload, an identity store that never resolves — the four tests
    above would still be green except for the ones asserting a *pass*. The two
    here pin that a pass is reachable and that the opt-out still reads as off.
    """

    def test_the_verifier_accepts_at_least_one_command(self, store: Store) -> None:
        enrol(store)
        verifier = build_k8s_verifier(store, keys=keys(), controller_id=CONTROLLER)
        assert verifier.verify(signed(), expected_plan_digest=PLAN, now=NOW) is not None

    def test_the_signer_and_verifier_share_one_canonicaliser(self) -> None:
        from mayhem.infra.agent_identity_verifier import signed_payload

        command = signed()
        signer = HmacSha256CommandSigner(keys())
        assert command.signature == signer.algorithm_mac(signed_payload(command), SECRET)

    def test_the_lane_signer_is_the_same_type_as_the_verifier_expects(self, store: Store) -> None:
        signer = build_k8s_signer(keys())
        assert isinstance(signer, HmacSha256CommandSigner)
        assert signer.algorithm == ALGORITHM_HMAC_SHA256
        assert build_k8s_verifier(store, keys=keys(), controller_id=CONTROLLER).algorithm == (
            ALGORITHM_HMAC_SHA256
        )

    def test_a_dispatcher_without_a_verifier_is_visibly_unverified(self) -> None:
        from mayhem.controller.k8s_fabric import K8sFabricDispatcher

        dispatcher = K8sFabricDispatcher(session=_NeverCalled(), controller_id=CONTROLLER)
        assert dispatcher.engine.verification_enabled is False
        assert dispatcher.engine.verification_algorithm == ""

    def test_a_dispatcher_with_a_bound_verifier_reports_the_algorithm(self, store: Store) -> None:
        from mayhem.controller.k8s_fabric import K8sFabricDispatcher

        dispatcher = K8sFabricDispatcher(
            session=_NeverCalled(),
            controller_id=CONTROLLER,
            verifier=build_k8s_verifier(store, keys=keys(), controller_id=CONTROLLER),
        )
        assert dispatcher.engine.verification_enabled is True
        assert dispatcher.engine.verification_algorithm == ALGORITHM_HMAC_SHA256


class _NeverCalled:
    """A `FabricSession` that fails if a test ever reaches it.

    Verification happens in preflight, before the provider runs, so these tests
    need no agent transport at all — and this double makes that structural: if a
    future change moved verification *after* the dispatch, these tests would fail
    loudly instead of quietly passing with a stub.
    """

    def __call__(self, *args: object, **kwargs: object) -> object:
        raise AssertionError(
            "these tests must not reach the agent session: verification belongs in "
            "the fabric's preflight, before the provider is called"
        )


class TestTheSymmetricCaveatStillHolds:
    """Binding a verifier must not quietly become a PKI claim."""

    def test_the_algorithm_is_symmetric_hmac_not_x509(self) -> None:
        assert ALGORITHM_HMAC_SHA256 == "hmac-sha256"
        assert ALGORITHM_HMAC_SHA256 != ALGORITHM_X509

    def test_the_x509_seam_still_refuses_and_never_downgrades(self) -> None:
        with pytest.raises(SignaturePortUnavailableError):
            X509CommandSignatureVerifier().verify(payload=b"x", signature="y", signing_key_id="k")


class TestTheHonestStateOfThePhase:
    def test_the_module_still_says_the_live_acceptance_is_unmet(self) -> None:
        # If a live cell is ever certified, this is the assertion to update —
        # deliberately, because until then the phase is not closed.
        doc = k8s_fabric.__doc__ or ""
        assert "No live agent session" in doc
        assert "is therefore **not met**" in doc
