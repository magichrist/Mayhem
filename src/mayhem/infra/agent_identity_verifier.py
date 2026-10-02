"""Agent-command verification: real HMAC verification behind injectable ports.

Plan ``docs/v1.1.0/19_HA_DR_SECURITY.md`` Phase 2 -- "mTLS on all
controller-agent links with rotation and revocation propagation", reduced to what
can be honestly built in this repository without a new third-party dependency.

What cryptographic verification IS implemented here
---------------------------------------------------

**HMAC-SHA256 over the canonical envelope payload, verified with a constant-time
comparison.** A real cryptographic check, not a digest equality test and not a
claim:

* the signed bytes are ``canonical_event_json(command.model_dump(mode="json",
  exclude={"signature"}))`` -- :mod:`mayhem.domain.attestation`'s canonicalization
  (sorted keys, no insignificant whitespace, raw UTF-8, NFC-normalized,
  ``allow_nan=False``, no lossy ``default`` fallback);
* the MAC is ``hmac.new(secret, payload, hashlib.sha256).digest()``, base64url
  encoded, compared with :func:`hmac.compare_digest`;
* an unknown ``signing_key_id`` is a **refusal**, never an empty-secret bypass.

It is a *symmetric* scheme, so what it proves is: *this command was produced by a
holder of the shared key, and the bytes have not changed since.* That is the
honest description. It is not an asymmetric signature, it does not prove
authorship to a third party who does not hold the secret, and it is not a
public-key scheme.

What is NOT implemented (stated here so no doc may imply otherwise)
------------------------------------------------------------------

* **No CA-backed X.509 mTLS.** No handshake, no session, no certificate chain
  validation, no revocation-checking protocol, and no ``cryptography``/OpenSSL
  binding -- this phase adds **no third-party dependency**. The seam is defined
  (:class:`X509CommandSignatureVerifier`) and it **fails closed**: asked to verify
  an X.509-declared algorithm it refuses with
  :data:`SIGNATURE_PORT_UNAVAILABLE`, naming what is missing. Real CA fixtures and
  chain validation are plan 19 Phase 3 ("fixture certificate authorities").
* **No Sigstore/Cosign, and no fault-pack signing.** Both unrelated to this
  module. ``providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED`` is ``False``, is
  pinned by a test, and refers to *fault-pack authorship*; nothing in this file
  contradicts it, relaxes it, or may be quoted as evidence that pack signing
  exists.
* **This module revokes nothing a caller already holds.** It refuses a command
  whose *stored* identity is revoked at the instant it is asked. Push-based
  revocation of a live peer is the transport's job, and the agents-never-listen
  invariant (ADR-0003, :mod:`mayhem.agents.transports`) means the controller
  dials out to a peer -- never the reverse.

The named checks, and why there is a name for each
---------------------------------------------------

:class:`VerificationCheck` enumerates every decision this module can refuse, and
:meth:`AgentCommandVerifier.verify` names *all* the ones that failed rather than
the first -- the same discipline
:func:`mayhem.domain.agent_identity.authorize_credential` follows with
:class:`~mayhem.domain.agent_identity.CredentialRefusal`.

``SIGNATURE``
    the MAC over the canonical payload matches under a key the
    :class:`KeyMaterialPort` resolves. First, because a command that did not come
    from the controller must not be able to spend any other check.
``KEY_BINDING``
    ``signing_key_id`` is the agent's **current** credential id (or its recorded
    serial). This is what makes rotation bite: a superseded credential's key may
    still resolve in the port and is still refused, because the identity no longer
    names it.
``IDENTITY_USABLE``
    credential lifetime, rotation state, revocation and controller match, via
    :meth:`~mayhem.infra.agent_identity_store.AgentIdentityRepository.usable_credential`
    -- which consults the append-only revocation ledger, so a revocation row that
    landed without its identity update still refuses.
``CERTIFICATE_LIFETIME``
    the *recorded* certificate reference covers ``now`` and its fingerprint is
    pinned to a configured anchor. Two honest limits, stated because they matter:
    this compares recorded values, and Phase 1's
    :attr:`~mayhem.domain.agent_identity.CertificateRef.chain_verified` is
    ``False`` by construction. So this check reports *window and pinning* only,
    and its own :attr:`CheckOutcome.detail` says so in those words. It never
    reports chain validation, because none is performed here.
``PLAN_BINDING``
    the command's ``plan_digest`` equals the frozen plan digest the receiver
    holds. Delegates to
    :func:`mayhem.domain.fabric.assert_plan_digest_matches`.
``FENCE``
    the command's fencing token is not older than the highest fence the receiver
    has served for that step. Delegates to
    :func:`mayhem.domain.fabric.assert_fence_current`. Run only when the caller
    supplies ``served_fence``: a receiver serving no fence yet has nothing to
    compare against, and saying so beats inventing a fence.
``NONCE_FRESHNESS``
    the nonce has not been spent, recorded through the existing
    :class:`~mayhem.domain.fabric.NonceLedger`. Run **last**, because recording a
    nonce spends it -- a command refused for a wrong plan digest must not also
    burn its nonce, or a legitimate retry of that intent could never be minted.

Every refusal is a :class:`CommandRefusedError` carrying :attr:`failed` (the
:class:`VerificationCheck` members that did not pass) plus the stable
:data:`COMMAND_UNVERIFIED`. There is no code path that returns a "verified" value
for a command that failed a check, and none that reports a partial pass as a pass.
"""

from __future__ import annotations

import base64
import hmac
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import TYPE_CHECKING, Protocol

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.agent_identity import CredentialGrant, CredentialRefusedError
from mayhem.domain.attestation import canonical_event_bytes
from mayhem.domain.common import iso_utc, utc_now
from mayhem.domain.errors import DomainError
from mayhem.domain.fabric import (
    FABRIC_REPLAYED_NONCE,
    FabricCommand,
    FabricCommandRefused,
    FencingToken,
    NonceLedger,
    assert_fence_current,
    assert_plan_digest_matches,
)
from mayhem.domain.hashing import sha256_hex

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from mayhem.domain.agent_identity import AgentIdentity
    from mayhem.infra.agent_identity_store import AgentIdentityRepository
    from mayhem.infra.store import Store

#: The only algorithm this phase can actually verify, by name.
ALGORITHM_HMAC_SHA256 = "hmac-sha256"

#: The algorithm a future CA-backed mTLS verifier will declare. Named here so the
#: refusal below has something to be *about* rather than being a blanket
#: "unsupported".
ALGORITHM_X509 = "x509-chain-sha256"

#: Stable refusal code for any command that did not pass every check.
COMMAND_UNVERIFIED = "agent_command_unverified"

#: Stable refusal code for "the signature port cannot do this in this build, and
#: guessing is not an option". Deliberately distinct from a *bad signature*:
#: nothing was checked, which is a different fact from "checked and wrong".
SIGNATURE_PORT_UNAVAILABLE = "agent_signature_port_unavailable"

#: A syntactically valid stand-in used only to shape the envelope before the
#: real signature replaces it. It is never emitted: :meth:`sign_fields` re-validates
#: with the computed MAC.
_PLACEHOLDER_SIGNATURE = "A" * 64

_REMEDIATION = (
    "a command must be minted by the elected controller for the agent's current "
    "credential, bound to the frozen plan digest, carrying an unspent nonce and a "
    "fence at least as new as the served one; nothing is dispatched on a refusal"
)


def _now_of(moment: datetime | None) -> datetime:
    """The supplied instant, or the clock. Never a naive value from a caller."""
    resolved = utc_now() if moment is None else moment
    if resolved.tzinfo is None:
        msg = f"verification requires a timezone-aware instant, got naive {resolved!r}"
        raise DomainError(msg)
    return resolved


def signed_payload(command: FabricCommand) -> bytes:
    """The exact bytes a signature covers.

    ``canonical_event_json`` over the JSON-mode dump with ``signature`` removed.
    This is :mod:`mayhem.domain.attestation`'s encoder, not a second convention:
    signer and verifier therefore cannot disagree about what was signed.

    Relationship to :meth:`mayhem.domain.fabric.FabricCommand.signing_payload`: for
    a plain-ASCII envelope the two agree byte for byte (both sort keys and strip
    whitespace); ``canonical_event_json`` additionally NFC-normalizes and refuses
    non-finite floats. The agreement for the ASCII case is asserted in
    ``tests/unit/test_agent_identity_verifier.py`` rather than left to be
    remembered, because an envelope payload is machine-minted and therefore ASCII
    in practice -- but the assertion is what makes "the two cannot disagree" a
    checked fact instead of a comment.
    """
    return canonical_event_bytes(command.model_dump(mode="json", exclude={"signature"}))


def signing_key_for(identity: AgentIdentity) -> str:
    """The only ``signing_key_id`` this identity may sign with right now.

    The current credential id, or its recorded serial when one was captured at
    issuance. Deliberately *not* the whole credential history: a superseded
    credential is precisely the key a rotated-out holder still possesses.
    """
    serial = identity.credential.serial.strip()
    return serial or identity.credential.credential_id


# --------------------------------------------------------------------------- #
# Key material and signature ports                                             #
# --------------------------------------------------------------------------- #


class KeyMaterialPort(Protocol):
    """Where a ``signing_key_id`` becomes a secret. **No key material in this repo.**

    Phase 1's rule (``M0022_SECRET_GRANTS``: no column a credential value could
    occupy) is unchanged: nothing here persists a secret, and
    :class:`StaticKeyMaterial` is a test/dev double whose lifetime is the process.

    ``lookup`` returning ``None`` means *unknown key*, and the verifier turns that
    into a refusal. There is deliberately no "return empty bytes and let the MAC
    fail" path: an empty secret would make the check vacuous rather than failing.
    """

    def lookup(self, signing_key_id: str) -> bytes | None: ...


class SignaturePortUnavailableError(DomainError):
    """The signature port cannot verify this algorithm in this build."""

    def __init__(self, algorithm: str, reason: str) -> None:
        self.code = SIGNATURE_PORT_UNAVAILABLE
        self.algorithm = algorithm
        self.reason = reason
        super().__init__(f"{SIGNATURE_PORT_UNAVAILABLE}: cannot verify {algorithm!r}: {reason}")


class CommandSignaturePort(Protocol):
    """Verify a MAC/signature over the canonical envelope payload.

    A port, not an algorithm, so the decision about *which* scheme backs agent
    commands is injectable and recorded rather than assumed.
    """

    #: Algorithm name the port verifies. Recorded on every outcome, so an audit
    #: can see *how* a command was checked, not merely that it was.
    algorithm: str

    def verify(self, *, payload: bytes, signature: str, signing_key_id: str) -> bool: ...


class StaticKeyMaterial:
    """A test/dev key map. **Never a production key store, never persisted.**"""

    def __init__(self, keys: Mapping[str, bytes] | None = None) -> None:
        self._keys: dict[str, bytes] = dict(keys or {})

    def add(self, signing_key_id: str, secret: bytes) -> None:
        self._keys[signing_key_id] = secret

    def lookup(self, signing_key_id: str) -> bytes | None:
        return self._keys.get(signing_key_id)


class HmacSha256SignatureVerifier:
    """HMAC-SHA256 over the canonical payload, constant-time compared. **Real.**

    The only verifier in this phase that actually computes a MAC. Symmetric: both
    parties hold ``secret``, so the proof is "produced by a key holder", not a
    public-key signature.

    ``minimum_key_bytes`` refuses a short secret (32 by default, the SHA-256
    block/output size). A key shorter than the block is a configuration mistake
    that buys no size and weakens the MAC, and this build has no reason to accept
    one.
    """

    algorithm = ALGORITHM_HMAC_SHA256

    def __init__(self, keys: KeyMaterialPort, *, minimum_key_bytes: int = 32) -> None:
        if minimum_key_bytes < 1:
            msg = f"minimum_key_bytes must be positive, got {minimum_key_bytes}"
            raise DomainError(msg)
        self._keys = keys
        self._minimum_key_bytes = minimum_key_bytes

    def mac(self, payload: bytes, secret: bytes) -> str:
        """The base64url MAC this verifier accepts for ``payload``."""
        return base64.urlsafe_b64encode(hmac.new(secret, payload, sha256).digest()).decode("ascii")

    def verify(self, *, payload: bytes, signature: str, signing_key_id: str) -> bool:
        secret = self._keys.lookup(signing_key_id)
        if secret is None:
            return False
        if len(secret) < self._minimum_key_bytes:
            return False
        try:
            offered = base64.urlsafe_b64decode(signature.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            return False
        expected = hmac.new(secret, payload, sha256).digest()
        # compare_digest, not == : a byte-by-byte early-exit comparison leaks the
        # matching prefix length to a patient attacker.
        return hmac.compare_digest(offered, expected)


class HmacSha256CommandSigner:
    """Mint a signed :class:`~mayhem.domain.fabric.FabricCommand`. Symmetric.

    Lives beside the verifier on purpose: the canonical payload comes from one
    place (:func:`signed_payload`) and is used by both sides, so "the signer and
    the verifier disagree about what was signed" is not a state this module can be
    in. The signer is *not* a trust boundary -- holding the secret is the whole of
    its authority.
    """

    algorithm = ALGORITHM_HMAC_SHA256

    def __init__(self, keys: KeyMaterialPort) -> None:
        self._keys = keys

    def sign_fields(self, fields: Mapping[str, object]) -> FabricCommand:
        """Return a validated command from an unsigned field mapping.

        Raises:
            SignaturePortUnavailableError: If the key is unknown -- minting with an
                empty secret would produce a command nothing can verify.
            DomainError: If the payload is not canonicalizable (a non-finite float,
                a non-JSON-native value).
        """
        secret = self._keys.lookup(str(fields.get("signing_key_id", "")))
        if secret is None:
            msg = (
                "no key material for signing_key_id "
                f"{fields.get('signing_key_id')!r}; refusing to mint an unverifiable command"
            )
            raise SignaturePortUnavailableError(ALGORITHM_HMAC_SHA256, msg)
        unsigned = {key: value for key, value in fields.items() if key != "signature"}
        # Validate first, then MAC the *validated* dump. Canonicalising the raw
        # input instead would mean the signer hashed whatever spellings the caller
        # happened to use (an ISO string vs. a datetime, say) while the verifier
        # canonicalises ``model_dump(mode="json")`` — and the two would disagree
        # about what was signed. The placeholder signature exists only to satisfy
        # the envelope's own field constraints so the shape can be validated; it is
        # excluded from the payload and replaced immediately.
        shaped = FabricCommand.model_validate({**unsigned, "signature": _PLACEHOLDER_SIGNATURE})
        payload = signed_payload(shaped)
        return FabricCommand.model_validate(
            {**shaped.model_dump(), "signature": self.algorithm_mac(payload, secret)}
        )

    def algorithm_mac(self, payload: bytes, secret: bytes) -> str:
        """The signature string for ``payload``. Same spelling the verifier accepts."""
        return base64.urlsafe_b64encode(hmac.new(secret, payload, sha256).digest()).decode("ascii")


class X509CommandSignatureVerifier:
    """The CA-backed mTLS seam. **Defined; not implemented; fails closed.**

    This class is the plan-19 Phase 3 hand-off point. It exists so that the
    *decision* is on the record and so that a caller who configures
    :data:`ALGORITHM_X509` gets a named refusal instead of a silent downgrade to
    :data:`ALGORITHM_HMAC_SHA256` -- a downgrade that would let anyone who could
    influence the algorithm name choose the weaker scheme.

    What is missing, precisely, and why it is missing: chain building and
    validation needs X.509 parsing and a signature algorithm this build has no
    dependency for (``cryptography``, or an OpenSSL binding). Phase 2's
    constraint is no new third-party dependency, so this is a refusal, not a
    stub that "verifies" anything. Replacing the body with a real implementation is
    the Phase 3 change, and the tests pin the refusal so the replacement cannot
    land silently.
    """

    algorithm = ALGORITHM_X509

    #: Stated as data so a caller can test the port without importing the class.
    REASON = (
        "CA-backed X.509 verification needs an X.509 parser and chain validator, "
        "which this build has no dependency for; plan 19 Phase 3 supplies it "
        "behind this port with fixture certificate authorities"
    )

    def verify(self, *, payload: bytes, signature: str, signing_key_id: str) -> bool:
        """Always refuses. Never returns ``True``.

        Raises:
            SignaturePortUnavailableError: Always.
        """
        del payload, signature, signing_key_id
        raise SignaturePortUnavailableError(ALGORITHM_X509, self.REASON)


# --------------------------------------------------------------------------- #
# Nonce ledger over the replicated store                                        #
# --------------------------------------------------------------------------- #


class NonceLedgerPort(Protocol):
    """Durable record of spent nonces, shaped like the domain ledger.

    The store is the persistence; :class:`~mayhem.domain.fabric.NonceLedger` stays
    the *rule* (``accept`` refuses a replay). This port deliberately does not
    re-express "is this fresh" -- it loads and records, and
    :class:`~mayhem.domain.fabric.NonceLedger.accept` decides.
    """

    def load(self, run_id: str, step_id: str | None = None) -> NonceLedger: ...

    def record(self, command: FabricCommand, *, at: datetime) -> NonceLedger: ...


class SqliteNonceLedger:
    """:class:`NonceLedgerPort` over ``agent_command_nonces`` (``M0032_HA_DR``).

    ``record`` is idempotent on the nonce **primary key**: re-recording a spent
    nonce raises :data:`FABRIC_REPLAYED_NONCE` rather than inserting a second row,
    so two receivers racing on the same command cannot both come away believing
    they consumed it.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def load(self, run_id: str, step_id: str | None = None) -> NonceLedger:
        if step_id is None:
            rows = self._store.query(
                "SELECT nonce FROM agent_command_nonces WHERE run_id = ?", (run_id,)
            )
        else:
            rows = self._store.query(
                "SELECT nonce FROM agent_command_nonces WHERE run_id = ? AND step_id = ?",
                (run_id, step_id),
            )
        return NonceLedger(consumed=frozenset(str(dict(row)["nonce"]) for row in rows))

    def record(self, command: FabricCommand, *, at: datetime) -> NonceLedger:
        existing = self.load(command.run_id, command.step_id)
        # The domain rule decides; this call is what raises FABRIC_REPLAYED_NONCE.
        advanced = existing.accept(command)
        with self._store.write() as conn:
            try:
                conn.execute(
                    "INSERT INTO agent_command_nonces "
                    "(nonce, command_id, run_id, step_id, agent_id, consumed_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        command.nonce,
                        command.command_id,
                        command.run_id,
                        command.step_id,
                        command.agent_id,
                        iso_utc(at),
                    ),
                )
            except Exception as exc:  # pragma: no cover - UNIQUE violation path
                # A concurrent receiver inserted the same nonce between load and
                # insert. Fail closed: the nonce is spent either way, and reporting
                # the replay is the honest answer.
                if "UNIQUE" not in str(exc).upper():
                    raise
                raise FabricCommandRefused(
                    FABRIC_REPLAYED_NONCE,
                    f"command '{command.command_id}' lost the race for nonce "
                    f"{command.nonce[:8]}… and is a replay",
                    details={"command_id": command.command_id, "run_id": command.run_id},
                    remediation="mint a fresh nonce for every dispatch",
                ) from exc
        return advanced

    def consumed_count(self) -> int:
        rows = self._store.query("SELECT COUNT(*) FROM agent_command_nonces")
        return int(dict(rows[0])["COUNT(*)"]) if rows else 0


# --------------------------------------------------------------------------- #
# Outcomes                                                                     #
# --------------------------------------------------------------------------- #


class VerificationCheck(StrEnum):
    """Every decision that can refuse a command, in evaluation order.

    Declared as the evaluation order so a log line reads top to bottom, and so
    ``NONCE_FRESHNESS`` being last is a documented consequence (spending a nonce on
    a command that was going to be refused anyway) rather than an accident.
    """

    SIGNATURE = "signature"
    KEY_BINDING = "key_binding"
    IDENTITY_USABLE = "identity_usable"
    CERTIFICATE_LIFETIME = "certificate_lifetime"
    PLAN_BINDING = "plan_binding"
    FENCE = "fence"
    NONCE_FRESHNESS = "nonce_freshness"


#: Canonical order outcomes are reported in. Authored, and asserted equal to
#: :class:`VerificationCheck`'s declaration order by the unit tests, so the enum
#: and this tuple cannot drift apart quietly.
CHECK_ORDER: tuple[VerificationCheck, ...] = tuple(VerificationCheck)


def order_checks(checks: Iterable[VerificationCheck]) -> tuple[VerificationCheck, ...]:
    """De-duplicate and canonically order a refusal set, by :data:`CHECK_ORDER`."""
    present = set(checks)
    return tuple(check for check in CHECK_ORDER if check in present)


class CheckOutcome(BaseModel):
    """One check's result, with the observation that decided it.

    ``detail`` is required on both outcomes. A bare ``passed=True`` is the same
    defect Phase 1 refuses in
    :class:`~mayhem.domain.backup.RestoreCheckResult` ("'the row count matched' and
    'I clicked the button' are the same boolean and only one of them is
    evidence"), and the rule is applied here for the same reason: a verification
    report that cannot say *what was observed* is not a verification report.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    check: VerificationCheck
    passed: bool
    detail: str = Field(min_length=1)
    algorithm: str = ""

    def describe(self) -> str:
        mark = "pass" if self.passed else "FAIL"
        suffix = f" [{self.algorithm}]" if self.algorithm else ""
        return f"{self.check.value}{suffix} {mark}: {self.detail}"


class VerifiedCommand(BaseModel):
    """A command that passed every check. **Only constructible by the verifier.**

    Attributes:
        command: The envelope, unchanged.
        grant: The :class:`~mayhem.domain.agent_identity.CredentialGrant` the
            identity check produced. A statement about the past; a caller acting
            later still owes :func:`~mayhem.domain.agent_identity.require_still_usable`
            if it wants a fresh decision.
        verified_at: The instant the checks ran at (tz-aware).
        algorithm: The signature algorithm that was actually used, so the record
            says *how* rather than only *that*.
        envelope_digest: sha256 of the signed payload bytes.
        identity_version: The identity version the checks cleared against, which is
            how a later revocation becomes *detectable* (registry ``version`` moves
            past it).
        nonce_ledger: The ledger including this command's nonce. The nonce is spent
            by the time a caller holds this value, by construction.
        outcomes: Every check's result, passing ones included. Kept on the *success*
            value as well as the refusal, because "which checks ran, and what did
            each observe" is exactly the record an audit wants -- and because a
            passing certificate check has to be readable as a window check rather
            than as a chain validation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    command: FabricCommand
    grant: CredentialGrant
    verified_at: datetime
    algorithm: str
    envelope_digest: str
    identity_version: int
    nonce_ledger: NonceLedger
    outcomes: tuple[CheckOutcome, ...] = ()

    @property
    def agent_id(self) -> str:
        return self.command.agent_id

    @property
    def consumed_nonces(self) -> int:
        return len(self.nonce_ledger.consumed)

    def outcome_for(self, check: VerificationCheck) -> CheckOutcome:
        """The recorded outcome of one check.

        Raises:
            KeyError: If the check did not run -- a caller asking about a decision
                that was never made gets an error rather than a silent default.
        """
        for outcome in self.outcomes:
            if outcome.check is check:
                return outcome
        msg = f"check {check.value!r} was not evaluated for {self.command.command_id}"
        raise KeyError(msg)

    def describe(self) -> str:
        return (
            f"verified {self.command.command_id} for {self.agent_id} at "
            f"{self.verified_at.isoformat()} via {self.algorithm} "
            f"(envelope {self.envelope_digest[:12]}…, identity v{self.identity_version}, "
            f"{self.consumed_nonces} nonce(s) spent for this step)"
        )


class CommandRefusedError(DomainError):
    """A fabric command did not pass verification. **Nothing was dispatched.**

    Carries :attr:`failed` -- every :class:`VerificationCheck` that did not pass,
    in :data:`CHECK_ORDER` -- so the refusal names which check failed rather than
    merely that something did. Also carries :attr:`outcomes` for the full per-check
    detail, which is what an operator reads; :attr:`failed` is what a test and a
    routing decision read.
    """

    def __init__(
        self,
        command_id: str,
        failed: tuple[VerificationCheck, ...],
        outcomes: tuple[CheckOutcome, ...] = (),
        *,
        code: str = COMMAND_UNVERIFIED,
        remediation: str = _REMEDIATION,
    ) -> None:
        self.code = code
        self.command_id = command_id
        self.failed = tuple(failed)
        self.outcomes = tuple(outcomes)
        self.remediation = remediation
        names = ", ".join(check.value for check in self.failed) or "no check recorded"
        super().__init__(
            f"{code}: command '{command_id}' refused; failed check(s): {names}"
        )

    def describe(self) -> str:
        lines = [str(self)]
        lines.extend(f"  {outcome.describe()}" for outcome in self.outcomes if not outcome.passed)
        lines.append(f"  remediation: {self.remediation}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# The verifier                                                                 #
# --------------------------------------------------------------------------- #


class AgentCommandVerifier:
    """Verify one :class:`~mayhem.domain.fabric.FabricCommand` before it acts.

    Args:
        identities: The authoritative identity/revocation store. Consulted through
            :meth:`~mayhem.infra.agent_identity_store.AgentIdentityRepository.usable_credential`
            rather than by reading rows, so the append-only revocation ledger is
            always part of the decision.
        signature: The signature port. :class:`HmacSha256SignatureVerifier` is the
            one real implementation; :class:`X509CommandSignatureVerifier` fails
            closed.
        nonces: Durable nonce ledger (port). Optional only to keep the type honest
            about the difference between *check* and *record*: with ``None``, the
            replay check runs against an empty ledger and
            :attr:`requires_nonce_recording` is ``False``, which the caller can
            assert on rather than discover.
        controller_id: The receiving controller. Stated, it enables the
            controller-mismatch refusal so a compromised controller cannot spend
            another controller's agents.
        require_certificate: When true (the default) a command for an agent with
            **no recorded certificate** is refused. Fail closed, and the same
            default-deny answer
            :meth:`~mayhem.domain.agent_identity.AgentIdentityRegistry.authorize`
            gives for an unenrolled agent. Set false only for a deployment that has
            deliberately turned certificate recording off, and say so out loud.

    Every decision is recomputed from the injected objects on each call, so a
    second verifier over the same store is a receiving peer, not a stale copy of
    the first one's memory.
    """

    def __init__(
        self,
        *,
        identities: AgentIdentityRepository,
        signature: CommandSignaturePort,
        nonces: NonceLedgerPort | None = None,
        controller_id: str | None = None,
        require_certificate: bool = True,
    ) -> None:
        self._identities = identities
        self._signature = signature
        self._nonces = nonces
        self._controller_id = controller_id
        self._require_certificate = require_certificate

    @property
    def algorithm(self) -> str:
        """The algorithm this verifier will actually use, for the record."""
        return self._signature.algorithm

    @property
    def requires_nonce_recording(self) -> bool:
        """False when no nonce port was supplied, so the caller can assert on it."""
        return self._nonces is not None

    # -- the one public entry point --------------------------------------------
    def verify(
        self,
        command: FabricCommand,
        *,
        expected_plan_digest: str | None = None,
        served_fence: FencingToken | None = None,
        now: datetime | None = None,
    ) -> VerifiedCommand:
        """Verify ``command``, or refuse naming every check that failed.

        Raises:
            CommandRefusedError: With :attr:`~CommandRefusedError.failed` naming
                each :class:`VerificationCheck` that did not pass.
            SignaturePortUnavailableError: When the signature port cannot verify
                its own algorithm in this build (see
                :class:`X509CommandSignatureVerifier`). Kept distinct from
                :class:`CommandRefusedError` because *nothing was checked* is a
                different fact from *checked and refused* -- the caller may want to
                reconfigure rather than re-dispatch.

        Returns:
            A :class:`VerifiedCommand`. There is no other success shape, so
            "verified" cannot be a field somebody sets.
        """
        moment = _now_of(now)
        outcomes: list[CheckOutcome] = []
        payload = signed_payload(command)

        outcomes.append(self._check_signature(command, payload))
        identity = self._load_identity(command.agent_id)
        outcomes.append(self._check_key_binding(identity, command))
        grant = self._check_identity_usable(command, moment, outcomes)
        outcomes.append(self._check_certificate(identity, moment))
        outcomes.append(self._check_plan_binding(command, expected_plan_digest))
        outcomes.append(self._check_fence(command, served_fence))
        outcomes.append(self._check_nonce_freshness(command, outcomes))

        # Ordered by CHECK_ORDER rather than by evaluation order, so the refusal's
        # ordering is a property of the enum's canonical order and not an accident
        # of the sequence of `_check_*` calls below.
        failed = order_checks(outcome.check for outcome in outcomes if not outcome.passed)
        if failed:
            raise CommandRefusedError(command.command_id, failed, tuple(outcomes))
        ledger = self._record_nonce(command, moment)
        # Both of these are narrowed by checks that only pass when they are set:
        # IDENTITY_USABLE passing means ``_check_identity_usable`` returned a grant,
        # and KEY_BINDING passing means the identity was loaded. Written as an
        # explicit refusal rather than an ``assert`` so a future edit that reorders
        # the checks cannot turn a logic slip into an ``-O``-stripped pass.
        if grant is None or identity is None:  # pragma: no cover - unreachable
            msg = (
                f"internal: command {command.command_id} reached the success path without "
                "an identity or a grant; refusing rather than returning a partial result"
            )
            raise DomainError(msg)
        return VerifiedCommand(
            command=command,
            grant=grant,
            verified_at=moment,
            algorithm=self._signature.algorithm,
            envelope_digest=sha256_hex(payload.decode("utf-8")),
            identity_version=identity.version,
            nonce_ledger=ledger,
            outcomes=tuple(outcomes),
        )

    # -- checks ---------------------------------------------------------------
    def _check_signature(self, command: FabricCommand, payload: bytes) -> CheckOutcome:
        """The MAC over the canonical payload, under a resolvable key."""
        try:
            ok = self._signature.verify(
                payload=payload,
                signature=command.signature,
                signing_key_id=command.signing_key_id,
            )
        except SignaturePortUnavailableError as exc:
            return CheckOutcome(
                check=VerificationCheck.SIGNATURE,
                passed=False,
                detail=f"not checked: {exc.reason}",
                algorithm=exc.algorithm,
            )
        if ok:
            return CheckOutcome(
                check=VerificationCheck.SIGNATURE,
                passed=True,
                detail=(
                    f"{self._signature.algorithm} MAC verified over the canonical "
                    f"envelope ({len(payload)} bytes) with key {command.signing_key_id!r}; "
                    "this proves a holder of that shared key produced these bytes, not "
                    "public-key authorship"
                ),
                algorithm=self._signature.algorithm,
            )
        return CheckOutcome(
            check=VerificationCheck.SIGNATURE,
            passed=False,
            detail=(
                f"{self._signature.algorithm} MAC did not verify for key "
                f"{command.signing_key_id!r} (unknown key, key too short, malformed "
                "signature, or altered bytes)"
            ),
            algorithm=self._signature.algorithm,
        )

    def _load_identity(self, agent_id: str) -> AgentIdentity | None:
        """The stored identity, or ``None``. Looked up once, reused by every check."""
        return self._identities.load(agent_id)

    def _check_key_binding(
        self, identity: AgentIdentity | None, command: FabricCommand
    ) -> CheckOutcome:
        """The signing key must be the agent's **current** credential.

        This is where rotation bites. A superseded credential's secret may still
        resolve in the key port and its MAC may still be arithmetically correct --
        and the command is still refused, because the identity no longer names that
        credential. Without this check, "rotate the credential" would not actually
        retire the old key.
        """
        if identity is None:
            return CheckOutcome(
                check=VerificationCheck.KEY_BINDING,
                passed=False,
                detail=(
                    f"agent {command.agent_id!r} is not enrolled; there is no current "
                    "credential to bind a signing key to"
                ),
            )
        expected = signing_key_for(identity)
        if command.signing_key_id == expected:
            return CheckOutcome(
                check=VerificationCheck.KEY_BINDING,
                passed=True,
                detail=(
                    f"signing_key_id {expected!r} is the current credential of "
                    f"{identity.agent_id} (identity v{identity.version})"
                ),
            )
        retired = [
            credential.credential_id
            for credential in identity.superseded_credentials
            if credential.credential_id == command.signing_key_id
        ]
        hint = (
            " (that credential is superseded; rotation retires its key)"
            if retired
            else ""
        )
        return CheckOutcome(
            check=VerificationCheck.KEY_BINDING,
            passed=False,
            detail=(
                f"signing_key_id {command.signing_key_id!r} is not the current credential "
                f"{expected!r} of {identity.agent_id}{hint}"
            ),
        )

    def _check_identity_usable(
        self, command: FabricCommand, moment: datetime, outcomes: list[CheckOutcome]
    ) -> CredentialGrant | None:
        """Credential lifetime, rotation, revocation, and controller match.

        Evaluated at the caller's ``moment``, not at a fresh clock read, so a replayed
        decision reproduces exactly.

        Delegates the whole decision to
        :meth:`~mayhem.infra.agent_identity_store.AgentIdentityRepository.usable_credential`.
        The refusal reason is copied out of the domain's own enumeration, so the log
        line reads in Phase 1's vocabulary instead of inventing a second one.
        """
        try:
            grant = self._identities.usable_credential(
                command.agent_id,
                now=moment,
                controller_id=self._controller_id,
            )
        except CredentialRefusedError as exc:
            reasons = ", ".join(reason.value for reason in exc.reasons) or "not enrolled"
            outcomes.append(
                CheckOutcome(
                    check=VerificationCheck.IDENTITY_USABLE,
                    passed=False,
                    detail=f"credential refused for {command.agent_id}: {reasons}",
                )
            )
            return None
        outcomes.append(
            CheckOutcome(
                check=VerificationCheck.IDENTITY_USABLE,
                passed=True,
                detail=(
                    f"{grant.agent_id} credential {grant.identity.credential_id} usable "
                    f"[{grant.identity.credential.issued_at.isoformat()} → "
                    f"{grant.identity.credential.expires_at.isoformat()}] against identity "
                    f"v{grant.identity_version}"
                    + (
                        f" on controller {self._controller_id!r}"
                        if self._controller_id is not None
                        else ""
                    )
                ),
            )
        )
        return grant

    def _check_certificate(
        self, identity: AgentIdentity | None, moment: datetime
    ) -> CheckOutcome:
        """Recorded certificate window and pinning. **Not chain validation.**

        ``CertificateRef.chain_verified`` is ``False`` by construction in Phase 1
        and nothing here changes that, so the detail string says "recorded window
        and pinned fingerprint; no X.509 chain was validated" every time it passes.
        That sentence in the log is the reason a reader cannot mistake this check
        for an mTLS handshake.
        """
        if identity is None:
            return CheckOutcome(
                check=VerificationCheck.CERTIFICATE_LIFETIME,
                passed=False,
                detail="no enrolled identity, so no certificate to evaluate",
            )
        certificate = identity.certificate
        if certificate is None:
            passed = not self._require_certificate
            return CheckOutcome(
                check=VerificationCheck.CERTIFICATE_LIFETIME,
                passed=passed,
                detail=(
                    "no certificate recorded and certificate recording is not required by "
                    "this verifier's configuration"
                    if passed
                    else "no certificate recorded; certificate recording is required, so "
                    "the command fails closed"
                ),
            )
        if not certificate.covers(moment):
            return CheckOutcome(
                check=VerificationCheck.CERTIFICATE_LIFETIME,
                passed=False,
                detail=(
                    f"recorded certificate {certificate.serial} window "
                    f"[{certificate.not_before.isoformat()} → "
                    f"{certificate.not_after.isoformat()}) does not cover "
                    f"{moment.isoformat()}"
                ),
            )
        verdict = identity.pin_verdict()
        if not verdict.pinned:
            return CheckOutcome(
                check=VerificationCheck.CERTIFICATE_LIFETIME,
                passed=False,
                detail=(
                    f"recorded certificate fingerprint is not pinned: {verdict.describe()} "
                    f"({verdict.reason.value}); an agent that trusts an unpinned "
                    "certificate fails closed"
                ),
            )
        return CheckOutcome(
            check=VerificationCheck.CERTIFICATE_LIFETIME,
            passed=True,
            detail=(
                f"recorded certificate {certificate.serial} covers "
                f"{moment.isoformat()}, {verdict.describe()}; recorded window and pinned "
                "fingerprint only — no X.509 chain was validated"
            ),
        )

    def _check_plan_binding(
        self, command: FabricCommand, expected_plan_digest: str | None
    ) -> CheckOutcome:
        """The command's ``plan_digest`` must equal the frozen plan the receiver holds."""
        if expected_plan_digest is None:
            return CheckOutcome(
                check=VerificationCheck.PLAN_BINDING,
                passed=False,
                detail=(
                    "no frozen plan digest was supplied to verify against; a command that "
                    "cannot be checked against a plan is refused rather than assumed fresh"
                ),
            )
        try:
            assert_plan_digest_matches(command, current_plan_digest=expected_plan_digest)
        except FabricCommandRefused as exc:
            return CheckOutcome(
                check=VerificationCheck.PLAN_BINDING,
                passed=False,
                detail=f"{exc.code}: {exc}",
            )
        return CheckOutcome(
            check=VerificationCheck.PLAN_BINDING,
            passed=True,
            detail=f"bound to frozen plan {expected_plan_digest[:12]}…",
        )

    def _check_fence(
        self, command: FabricCommand, served_fence: FencingToken | None
    ) -> CheckOutcome:
        """The command's fence must not be older than the served one.

        Skipped (and passed with that stated) when no fence has been served yet --
        there is nothing to compare against, and refusing every first command would
        make the fabric unusable rather than safe.
        """
        if served_fence is None:
            return CheckOutcome(
                check=VerificationCheck.FENCE,
                passed=True,
                detail=(
                    f"no fence served yet for {command.run_id}/{command.step_id}; fence "
                    "comparison skipped, command carries epoch "
                    f"{command.fencing_token.epoch}"
                ),
            )
        try:
            assert_fence_current(command, served_fence=served_fence)
        except FabricCommandRefused as exc:
            return CheckOutcome(
                check=VerificationCheck.FENCE,
                passed=False,
                detail=(
                    f"{exc.code}: command carries fence epoch {command.fencing_token.epoch} "
                    f"but the step is served under epoch {served_fence.epoch}"
                ),
            )
        return CheckOutcome(
            check=VerificationCheck.FENCE,
            passed=True,
            detail=(
                f"fence epoch {command.fencing_token.epoch} is at least the served epoch "
                f"{served_fence.epoch} for {command.run_id}/{command.step_id}"
            ),
        )

    def _check_nonce_freshness(
        self, command: FabricCommand, outcomes: list[CheckOutcome]
    ) -> CheckOutcome:
        """Is this nonce unspent? **Reads only — it does not spend it.**

        The domain's :meth:`~mayhem.domain.fabric.NonceLedger.accept` is the rule
        and the refusal; this method supplies the durable ledger and nothing else.
        The spend happens in :meth:`_record_nonce`, on the success path only: a
        command refused for, say, a superseded plan must not also burn its nonce, or
        the controller could never mint a retry of the same intent.

        With no nonce port the check runs against an empty ledger and passes
        vacuously — which is why :attr:`requires_nonce_recording` exists, so a
        deployment that means to record can assert that it is.
        """
        ledger = (
            self._nonces.load(command.run_id, command.step_id)
            if self._nonces is not None
            else NonceLedger()
        )
        try:
            ledger.accept(command)
        except FabricCommandRefused as exc:
            if exc.code != FABRIC_REPLAYED_NONCE:
                raise
            return CheckOutcome(
                check=VerificationCheck.NONCE_FRESHNESS,
                passed=False,
                detail=f"{exc.code}: {exc}",
            )
        return CheckOutcome(
            check=VerificationCheck.NONCE_FRESHNESS,
            passed=True,
            detail=(
                f"nonce {command.nonce[:8]}… is unspent "
                f"({len(ledger.consumed)} already spent for this step); it is recorded "
                "only if every other check passes"
                + (
                    ""
                    if self._nonces is not None
                    else " — in memory only: no nonce port is bound, so this replay check "
                    "is vacuous and nothing is recorded"
                )
            ),
        )

    def _record_nonce(self, command: FabricCommand, moment: datetime) -> NonceLedger:
        """Spend the nonce. Called only after every check has passed.

        Separate from the check on purpose — see :meth:`_check_nonce_freshness`. The
        returned ledger is the *advanced* one, so a caller holding a
        :class:`VerifiedCommand` knows the nonce is already spent and there is no
        window in which a verified command could be replayed.

        Raises:
            FabricCommandRefused: With :data:`FABRIC_REPLAYED_NONCE` if a concurrent
                receiver spent the nonce between the check and this write. That is a
                refusal, not a success: the command was not verified, and the store's
                primary key is what makes the race decidable rather than a
                double-spend.
        """
        if self._nonces is None:
            return NonceLedger(consumed=frozenset({command.nonce}))
        return self._nonces.record(command, at=moment)
