"""Distributed dispatch engine: fencing, idempotent retries, error normalisation.

Plan ``docs/v1.1.0/03_EXECUTION_FABRIC.md``. Phase 1 gave the fabric its *words*
(:mod:`mayhem.domain.fabric`); Phase 2 built this dispatch layer on top of them;
Phase 4 added *verification* and *evidence* to the dispatch path. It is a
**dispatch layer**, not a second run engine: the run shape is still
``RunEngine.execute``'s (intent -> gate -> open run -> grouped steps -> recover
-> verdict -> close, :mod:`mayhem.controller.executor`) and nothing here reorders
it. What this module adds is the one thing the run engine cannot express — *who*
is allowed to act on a step right now, and what to believe when they come back.

Five properties, in the order they are checked on every dispatch:

1. **A command is verified before it acts, and the signature claim is honoured
   as a claim until it is checked.** Phase 2 wired
   :data:`FABRIC_UNDERSIGNED` at :meth:`FabricEngine._require_signed` even though
   the Phase 1 envelope makes it unreachable in-process. Phase 4 gives the code
   its real raise sites by *actually verifying*: the engine takes a
   :class:`FabricCommandVerifierPort` — plan 19's
   :class:`~mayhem.infra.agent_identity_verifier.AgentCommandVerifier` satisfies
   it, and no verification logic is reimplemented here. A signature that does not
   verify under a key the agent's current credential names is refused by
   :data:`FABRIC_UNDERSIGNED`; an envelope that fails its own field constraints on
   the wire is refused by :data:`FABRIC_MALFORMED_ENVELOPE` (see
   :func:`mayhem.controller.fabric_evidence.decode_wire_command`).
2. **Only the highest epoch dispatches.** A claim is served only when its
   fencing token is at least as new as the highest one already *claimed* for the
   step. A deposed owner is refused by :data:`FABRIC_STALE_FENCE`; a second
   effect at the same epoch is refused by :data:`FABRIC_DUPLICATE_DISPATCH`.
3. **Reservations are checked before anything is dispatched** — a lapsed lock
   (:data:`FABRIC_RESERVATION_EXPIRED`) and a lock taken under a *newer* fence
   than the one presented (deposed owner's lock, not the successor's) both
   refuse with :data:`FABRIC_RESOURCE_CONFLICT`.
4. **A replayed nonce is refused** (:data:`FABRIC_REPLAYED_NONCE`) and an
   idempotent retry is a *different envelope with the same key*: the retry
   re-spends a fresh nonce, is claimed, and is settled from the recorded outcome
   without a second provider call. This is the distinction Phase 1 drew
   (``idempotency_key`` stable, ``nonce`` single-use) and this phase preserves
   it exactly.
5. **Provider errors are normalised into the existing taxonomy**
   (:class:`StepOutcome` + :class:`TargetOutcome`). A target that moved is
   :attr:`~mayhem.domain.outcomes.TargetOutcome.TARGET_DRIFT` — *mismatched,
   not failed* — and a provider that reports ``ok`` while the object it touched
   is not the object the plan named is still drift, never a pass.

**Refusals are raised, outcomes are returned.** Everything the engine can decide
*before* the provider is touched raises :class:`FabricCommandRefused` with a
stable code, so a refusal can never be mistaken for a settled outcome. Anything
the provider does is normalised and *returned* as a :class:`DispatchResult`,
because a provider failure is a result of the step, not a bug in the fabric.

**The engine holds no dispatch state.** Every decision is a projection over
``journal.entries()`` plus ``lease_sink``, both injected. That is the whole
crash-safety mechanism: a resumed controller is not a controller that recovered
its memory, it is a *new* :class:`FabricEngine` handed the same durable objects,
and it is immediately correct because there was nothing in the old one to lose.
The rendezvous is the lease sink (ADR-0005's write-ahead record, written by the
controller because the controller is the single writer, ADR-0007) joined to the
journal, which records which envelope claimed which step under which epoch:

* :meth:`FabricEngine.open_claims` — claims with no settlement. Either the
  dispatch never reached the provider or it is genuinely in flight; the two are
  indistinguishable from the journal alone, so the engine refuses to guess.
* :meth:`FabricEngine.unreconciled_leases` — live leases in the sink that no
  settlement references. A controller that died between *receiving* a lease and
  *settling* it leaves exactly this pair, and it is the signature of a crash.
* :meth:`FabricEngine.unrecovered_steps` — steps whose recorded lease is not yet
  in a safe terminal state, so the resumed controller knows what to compensate
  before it re-dispatches anything.

The journal itself is a :class:`FabricJournal` protocol here. Phase 4 bound it to
a durable implementation: :class:`mayhem.controller.fabric_evidence.SqliteFabricJournal`
over :mod:`mayhem.infra.fabric_journal`'s table, in the same store as the lease
sink.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from pydantic import BaseModel, ConfigDict, model_validator

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.fabric import (
    FABRIC_PLAN_MISMATCH,
    FABRIC_REPLAYED_NONCE,
    FABRIC_RESERVATION_EXPIRED,
    FABRIC_RESOURCE_CONFLICT,
    FABRIC_STALE_FENCE,
    FABRIC_UNDERSIGNED,
    FabricCommand,
    FabricCommandRefused,
    FencingToken,
    NonceLedger,
    PlanDigest,
    Reservation,
    StepSpec,
    assert_fence_current,
    assert_plan_digest_matches,
    assert_reservation_available,
)
from mayhem.domain.leases import FaultLease
from mayhem.domain.outcomes import StepOutcome, TargetOutcome
from mayhem.infra.agent_identity_verifier import (
    CommandRefusedError,
    SignaturePortUnavailableError,
    VerificationCheck,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.agents.sinks import LeaseSink
    from mayhem.infra.agent_identity_verifier import VerifiedCommand

#: Raised when a second *effect* is claimed for one step at one epoch. The domain
#: owns the wire-facing vocabulary; this code is dispatch-layer state, so it
#: lives here rather than being smuggled into :mod:`mayhem.domain.fabric`.
FABRIC_DUPLICATE_DISPATCH = "fabric_duplicate_dispatch"

#: Raised when a command arrives for a claim that was never settled. A prior
#: owner may have died mid-dispatch, so whether the effect happened is unknown —
#: and an unknown effect is never retried into a *second* effect.
FABRIC_INFLIGHT_UNRESOLVED = "fabric_inflight_unresolved"

#: Raised when a command fails verification for a reason the fabric has no
#: narrower code for — an unenrolled or revoked agent, a superseded signing
#: credential, a signature port that cannot verify its own algorithm. **The
#: verification checks that failed are named on
#: :attr:`FabricCommandRefused.details["failed_checks"]`**, because "unverified"
#: without the list is exactly the bare boolean plan 19 refuses to report.
FABRIC_COMMAND_UNVERIFIED = "fabric_command_unverified"

#: Raised when a frame off the wire does not satisfy the envelope's own field
#: constraints at all. Distinct from :data:`FABRIC_UNDERSIGNED` on purpose: a
#: frame missing its fencing token is malformed, and calling that "undersigned"
#: would spend the one code that means *the signature did not verify* on a
#: question about a different field.
FABRIC_MALFORMED_ENVELOPE = "fabric_malformed_envelope"

_REMEDIATION_RETRY = (
    "reuse the idempotency key of the original command, mint a fresh nonce, and "
    "dispatch under the current fencing token"
)

#: Provider error codes that mean *the target moved*. Docker, podman, Kubernetes
#: and the host executors all spell this differently; the fabric fixes one
#: vocabulary so a caller never has to know which provider ran.
DRIFT_ERROR_CODES: frozenset[str] = frozenset(
    {
        "target_drift",
        "target_missing",
        "identity_mismatch",
        "no_such_container",
        "container_not_found",
        "no_such_pod",
        "pod_not_found",
        "pod_replaced",
        "not_found",
    }
)

#: Provider error codes that mean *someone else owns the target*.
CONFLICT_ERROR_CODES: frozenset[str] = frozenset(
    {
        "resource_conflict",
        "resource_busy",
        "container_busy",
        "operation_conflict",
        "lease_held",
        "already_locked",
    }
)

#: How an agent-side fabric refusal normalises. A refusal is a settled, recorded
#: result of the dispatch — never an exception out of the engine, and never a
#: silent success.
_REFUSAL_OUTCOMES: dict[str, TargetOutcome] = {
    FABRIC_STALE_FENCE: TargetOutcome.RESOURCE_CONFLICT,
    FABRIC_RESOURCE_CONFLICT: TargetOutcome.RESOURCE_CONFLICT,
    FABRIC_RESERVATION_EXPIRED: TargetOutcome.RESOURCE_CONFLICT,
    FABRIC_PLAN_MISMATCH: TargetOutcome.FAILED_TO_APPLY,
    FABRIC_UNDERSIGNED: TargetOutcome.FAILED_TO_APPLY,
    FABRIC_REPLAYED_NONCE: TargetOutcome.FAILED_TO_APPLY,
}


def _agreeing_reason(
    outcome: StepOutcome,
    target_outcome: TargetOutcome | None,
) -> TargetOutcome | None:
    """Return the reason a lead outcome may carry, or refuse an incoherent pair.

    The two enums are siblings, not layers: a ``COMPLETED`` step has no reason at
    all, drift is always drift, and a ``FAILED`` step must say *why* it failed.
    Deriving the drift reason instead of demanding it keeps a caller from having
    to spell out the one thing that has no alternative reading.
    """
    if outcome is StepOutcome.COMPLETED:
        if target_outcome is not None:
            raise InvariantViolationError(
                "fabric_outcome_pair",
                f"a completed step cannot carry reason {target_outcome.value!r}",
            )
        return None
    if outcome is StepOutcome.TARGET_DRIFT:
        if target_outcome not in (None, TargetOutcome.TARGET_DRIFT):
            raise InvariantViolationError(
                "fabric_outcome_pair",
                f"a drifted target cannot be reported as {target_outcome.value!r}; "
                "drift is mismatched, not failed",
            )
        return TargetOutcome.TARGET_DRIFT
    if target_outcome is None:
        raise InvariantViolationError(
            "fabric_outcome_pair",
            "a failed step must name why it failed (failed_to_apply or resource_conflict)",
        )
    return target_outcome


@dataclass(frozen=True)
class ProviderNormalisation:
    """The normalised reading of one provider exchange.

    Attributes:
        outcome: Lead step outcome.
        target_outcome: Why, or ``None`` when the step completed.
        detail: Secret-free, human-readable reason.
    """

    outcome: StepOutcome
    target_outcome: TargetOutcome | None
    detail: str


def normalise_provider_result(
    result: ProviderResult,
    *,
    expected_target: str | None = None,
) -> ProviderNormalisation:
    """Read a provider exchange in the fabric's taxonomy.

    Drift is decided **first** and it outranks the provider's own verdict: a
    provider that reports ``ok`` for an object other than the one the plan named
    did not apply the plan, and reporting that as success is the failure mode
    this function exists to prevent. Everything else is a plain provider error,
    and an unrecognised code is a capability/mutation failure on a present
    target (:attr:`TargetOutcome.FAILED_TO_APPLY`) rather than an invented
    fourth category.
    """
    if (
        expected_target is not None
        and result.target_ref is not None
        and result.target_ref != expected_target
    ):
        return ProviderNormalisation(
            StepOutcome.TARGET_DRIFT,
            TargetOutcome.TARGET_DRIFT,
            f"target drift: plan targeted '{expected_target}' but the provider addressed "
            f"'{result.target_ref}' (provider claimed ok={result.ok}); mismatched, not failed",
        )
    if result.ok:
        return ProviderNormalisation(
            StepOutcome.COMPLETED, None, result.detail or f"applied to '{result.target_ref or '?'}'"
        )
    code = (result.error_code or "").strip().lower()
    detail = result.detail or code or "provider reported failure without a code"
    if code in DRIFT_ERROR_CODES:
        return ProviderNormalisation(
            StepOutcome.TARGET_DRIFT,
            TargetOutcome.TARGET_DRIFT,
            f"target drift: {detail} (mismatched, not failed)",
        )
    if code in CONFLICT_ERROR_CODES:
        return ProviderNormalisation(
            StepOutcome.FAILED,
            TargetOutcome.RESOURCE_CONFLICT,
            f"resource conflict: {detail}",
        )
    return ProviderNormalisation(
        StepOutcome.FAILED,
        TargetOutcome.FAILED_TO_APPLY,
        f"failed to apply: {detail}",
    )


def _normalise_refusal(exc: FabricCommandRefused) -> ProviderNormalisation:
    """Read an agent-side fabric refusal as a settled dispatch result.

    An unknown code normalises to a failure to apply: the effect demonstrably did
    not happen and the fabric will not invent a category for a code it does not
    know. A stale fence is contention, because that is what it is — a newer owner
    holds the step.
    """
    reason = _REFUSAL_OUTCOMES.get(exc.code, TargetOutcome.FAILED_TO_APPLY)
    return ProviderNormalisation(
        StepOutcome.FAILED,
        reason,
        f"refused by agent [{exc.code}]: {exc} (remediation: {exc.remediation})",
    )


class ProviderResult(BaseModel):
    """What one agent session reports back about a dispatched command.

    Providers are not asked to speak the fabric's outcome vocabulary: they
    report what they saw, and :func:`normalise_provider_result` decides what it
    means. ``target_ref`` is the identity the provider *actually addressed* —
    the field that makes "reported ok, but the target moved" expressible at all.

    Attributes:
        ok: The provider's own verdict, before normalisation.
        detail: Free-text detail from the provider.
        error_code: Machine-readable provider code (``no_such_container``, …).
        target_ref: Identity the provider touched, when it can name one.
        lease: Write-ahead lease the agent created, if any. The engine persists
            it through the sink — the controller is the single writer.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    detail: str = ""
    error_code: str | None = None
    target_ref: str | None = None
    lease: FaultLease | None = None


class DispatchRequest(BaseModel):
    """One step, the envelope that acts on it, and the frozen plan it belongs to.

    Attributes:
        step: The planned step being dispatched.
        command: The signed-command envelope. No defaulted field on it, so a
            command that arrives without a fence or a nonce does not parse.
        current_plan_digest: Digest of the plan that is frozen *now*; a command
            minted against a superseded plan is refused (plan 03 Phase 4).
        expected_target: Identity the plan believes it is acting on. Drift is
            decided against this, so a step that genuinely targets nothing
            passes ``None`` and loses only mismatch detection.
        reservations: Locks this step claims. Empty means the step needs none.
        held_by_others: The rest of the lock table, so a claim is checked against
            contention and not only against itself.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    step: StepSpec
    command: FabricCommand
    current_plan_digest: PlanDigest
    expected_target: str | None = None
    reservations: tuple[Reservation, ...] = ()
    held_by_others: tuple[Reservation, ...] = ()


class DispatchResult(BaseModel):
    """The settled reading of one dispatch.

    Attributes:
        run_id: Run the step belongs to.
        step_id: Step acted on.
        command_id: Envelope that produced this reading.
        epoch: Fence epoch the effect was claimed under.
        outcome: Lead step outcome.
        target_outcome: Why, or ``None`` when the step completed.
        detail: Secret-free reason.
        refusal_code: Fabric code when the *agent* refused, else ``None``.
        retried: True when this reading was served from the recorded outcome of
            an earlier command with the same idempotency key.
        lease_id: Write-ahead lease the agent created, if any.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    step_id: str
    command_id: str
    epoch: int
    outcome: StepOutcome
    target_outcome: TargetOutcome | None = None
    detail: str = ""
    refusal_code: str | None = None
    retried: bool = False
    lease_id: str | None = None

    @model_validator(mode="after")
    def _coherent(self) -> DispatchResult:
        _agreeing_reason(self.outcome, self.target_outcome)
        return self

    @property
    def ok(self) -> bool:
        """True only for a completed step. Drift is never ``ok``."""
        return self.outcome is StepOutcome.COMPLETED

    @property
    def is_drift(self) -> bool:
        return self.outcome is StepOutcome.TARGET_DRIFT


class DispatchPhase(StrEnum):
    """Which half of the dispatch a journal entry records."""

    CLAIMED = "claimed"
    SETTLED = "settled"


class DispatchClaim(BaseModel):
    """A claim: an envelope spent against a step, before any provider was touched.

    The whole envelope is stored rather than a projection of it, so the journal
    cannot disagree with the command it is a record of. Appending this *is* the
    nonce spend and the fence service; :meth:`FabricEngine.dispatch` appends it
    only after the refusal checks pass.

    Attributes:
        phase: Discriminator.
        command: The envelope claimed.
        controller_id: Which controller claimed it.
        claimed_at: When (tz-aware).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    phase: DispatchPhase = DispatchPhase.CLAIMED
    command: FabricCommand
    controller_id: str
    claimed_at: datetime

    @model_validator(mode="after")
    def _time(self) -> DispatchClaim:
        _require_aware(self.claimed_at, f"claim on '{self.command.step_id}'")
        return self

    @property
    def run_id(self) -> str:
        """Restated from the envelope so a journal row is queryable on its own."""
        return self.command.run_id

    @property
    def step_id(self) -> str:
        """Restated from the envelope so a journal row is queryable on its own."""
        return self.command.step_id


class DispatchSettlement(BaseModel):
    """A settlement: the normalised reading of one claimed envelope.

    ``run_id``/``step_id`` are restated rather than joined from the claim because
    a journal is queried by run and step: a durable row that can only be found by
    reading every other row first is not a row.

    Attributes:
        phase: Discriminator.
        run_id: Run the step belongs to.
        step_id: Step acted on.
        command_id: The claim this settles.
        outcome: Lead step outcome.
        target_outcome: Why, or ``None`` when the step completed.
        detail: Secret-free reason.
        lease_id: Lease the agent created, if any.
        settled_at: When (tz-aware).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    phase: DispatchPhase = DispatchPhase.SETTLED
    run_id: str
    step_id: str
    command_id: str
    outcome: StepOutcome
    target_outcome: TargetOutcome | None = None
    detail: str = ""
    lease_id: str | None = None
    settled_at: datetime

    @model_validator(mode="after")
    def _coherent(self) -> DispatchSettlement:
        _require_aware(self.settled_at, f"settlement of '{self.command_id}'")
        _agreeing_reason(self.outcome, self.target_outcome)
        return self


#: The append-only journal's element type. A claim says an effect was *started*;
#: a settlement says what it *became*. The gap between the two is the crash
#: window, and it is the only thing a resumed controller has to reason about.
JournalEntry = DispatchClaim | DispatchSettlement


def _require_aware(moment: datetime, subject: str) -> None:
    """Refuse naive timestamps: a claim with no usable clock is unrecoverable."""
    if moment.tzinfo is None:
        raise InvariantViolationError(
            "fabric_entry_time_ordering", f"{subject} must be timezone-aware, got naive {moment!r}"
        )


class FabricSession(Protocol):
    """One controller-initiated agent session (agents never listen, ADR-0003).

    The engine never parses a command body: :attr:`FabricCommand.command.body_ref`
    is transport-owned, so the session resolves it. The session may raise
    :class:`FabricCommandRefused` for a protocol refusal — that is a settled
    result, not an engine failure — and must not raise ``BaseException`` (a
    cancelled or killed controller has to stay uncatchable here).
    """

    def dispatch(self, command: FabricCommand) -> ProviderResult: ...


class FabricJournal(Protocol):
    """Durable, append-only controller-side dispatch state.

    The controller binds a single-writer implementation in the same store as the
    lease sink; ``entries`` is the only read, which is what lets a *new* engine
    instance resume with nothing but this object. Entries are returned in
    append order.

    Phase 4's implementation is
    :class:`mayhem.controller.fabric_evidence.SqliteFabricJournal`, over
    :mod:`mayhem.infra.fabric_journal`'s table. It stores the whole entry (never
    a projection) and re-checks every row against its own payload on read, so a
    journal can never disagree with the command it is a record of.
    """

    def append(self, entry: JournalEntry) -> None: ...

    def entries(self, run_id: str, step_id: str | None = None) -> tuple[JournalEntry, ...]: ...


class FabricCommandVerifierPort(Protocol):
    """What the engine needs from a command verifier — and nothing else.

    Satisfied by plan 19's
    :class:`~mayhem.infra.agent_identity_verifier.AgentCommandVerifier`: same
    keyword arguments, same return type, same refusal type. The protocol exists
    so the *dispatch layer* depends on a shape rather than on a class, and so a
    test can assert the real verifier satisfies it instead of a stand-in.

    The engine adds no cryptographic check of its own. Verification is HMAC (or,
    once plan 19 Phase 3 lands, a CA-backed chain) over the canonical envelope,
    and re-deriving any of it here would be the second verifier this phase
    explicitly does not build.
    """

    @property
    def algorithm(self) -> str:
        """The algorithm actually in use, recorded on every verification."""
        ...

    def verify(
        self,
        command: FabricCommand,
        *,
        expected_plan_digest: str | None = None,
        served_fence: FencingToken | None = None,
        now: datetime | None = None,
    ) -> VerifiedCommand:
        """Verify ``command``, or raise :class:`CommandRefusedError`.

        Raises:
            CommandRefusedError: Naming every check that did not pass.
            SignaturePortUnavailableError: When the port cannot verify its own
                algorithm — nothing was checked, which is a different fact from
                "checked and refused".
        """
        ...


@dataclass(frozen=True)
class VerifiedCheck:
    """One verification check's outcome, flattened for the sealed record.

    A dispatch record has to survive the verifier's own lifetime: the details
    string is the observation, and the check name is what a later reader routes
    on. Both are copied out rather than referenced so the evidence cannot be
    edited by mutating the object that produced it.
    """

    check: str
    passed: bool
    detail: str

    def evidence(self) -> dict[str, object]:
        return {"check": self.check, "passed": self.passed, "detail": self.detail}


@dataclass(frozen=True)
class VerifiedDispatch:
    """What verification established about one command, in the dispatch layer's shape.

    **Not** a re-verification and **not** a cache of a decision: it is the
    transcription of plan 19's :class:`~mayhem.infra.agent_identity_verifier.VerifiedCommand`
    into something the journal and the sealed chain can carry. ``algorithm`` and
    ``envelope_digest`` are the two fields that make the record answer *how* the
    command was checked rather than merely *that* it was.

    The ``signature`` itself is **not** carried, and neither is any key material:
    plan 19's store holds no secret, and a MAC copied into a journal row would be
    the one artefact this system must not duplicate. The digest of the signed
    payload plus the credential id already identify exactly which bytes were
    checked.
    """

    command_id: str
    agent_id: str
    algorithm: str
    envelope_digest: str
    identity_version: int
    verified_at: datetime
    checks: tuple[VerifiedCheck, ...]

    @classmethod
    def of(cls, verified: VerifiedCommand) -> VerifiedDispatch:
        """Transcribe plan 19's verification result."""
        return cls(
            command_id=verified.command.command_id,
            agent_id=verified.agent_id,
            algorithm=verified.algorithm,
            envelope_digest=verified.envelope_digest,
            identity_version=verified.identity_version,
            verified_at=verified.verified_at,
            checks=tuple(
                VerifiedCheck(
                    check=outcome.check.value,
                    passed=outcome.passed,
                    detail=outcome.detail,
                )
                for outcome in verified.outcomes
            ),
        )

    @property
    def failed(self) -> tuple[str, ...]:
        """Names of the checks that did not pass (empty — we only record successes)."""
        return tuple(check.check for check in self.checks if not check.passed)

    def evidence(self) -> dict[str, object]:
        """The sealed payload for this verification."""
        return {
            "algorithm": self.algorithm,
            "envelope_digest": self.envelope_digest,
            "identity_version": self.identity_version,
            "verified_at": self.verified_at.isoformat(),
            "checks": [check.evidence() for check in self.checks],
        }


class FabricEvidenceRecorder(Protocol):
    """Where a dispatch decision goes once it has been *made*.

    Deliberately narrow and deliberately optional. The engine raises refusals and
    returns outcomes; it does not decide how a run's evidence is stored, and it
    must not grow a second writer for it. Phase 4's implementation is
    :class:`mayhem.controller.fabric_evidence.SealingFabricEvidence`, which writes
    into the sealed chain plan 12 already owns.

    Every method is called *after* the journal append it describes, so a sealed
    event can never claim a row that did not land.
    """

    def dispatch_recorded(
        self, claim: DispatchClaim, *, verification: VerifiedDispatch | None = None
    ) -> None:
        """A claim landed. ``verification`` is ``None`` when no verifier was bound."""
        ...

    def settlement_recorded(
        self, settlement: DispatchSettlement, *, result: DispatchResult | None = None
    ) -> None:
        """A settlement landed. ``result`` is ``None`` for a reconciled claim."""
        ...

    def refusal_recorded(self, command: FabricCommand, *, code: str, reason: str) -> None:
        """A command was refused before it could act."""
        ...


#: Which of plan 19's verification checks map to which fabric refusal code. A
#: refusal that crosses the dispatch boundary has to be spelled in the fabric's
#: vocabulary or a caller would have to know which plan raised it; the check name
#: is preserved on ``details["failed_checks"]`` either way, so nothing is lost.
_VERIFICATION_CODE_BY_CHECK: dict[VerificationCheck, str] = {
    VerificationCheck.SIGNATURE: FABRIC_UNDERSIGNED,
    VerificationCheck.PLAN_BINDING: FABRIC_PLAN_MISMATCH,
    VerificationCheck.FENCE: FABRIC_STALE_FENCE,
    VerificationCheck.NONCE_FRESHNESS: FABRIC_REPLAYED_NONCE,
}

_REFUSED_REMEDIATION = (
    "a fabric command is dispatched only after plan 19's verifier accepts it: a "
    "resolvable signing key bound to the agent's current credential, a usable "
    "identity, the frozen plan digest, a fence at least as new as the served one, "
    "and an unspent nonce"
)


def translate_verification_refusal(exc: CommandRefusedError) -> FabricCommandRefused:
    """Re-spell a plan 19 refusal in the fabric's vocabulary.

    Picks the narrowest code among the checks that failed — a command whose
    signature does not verify *and* whose plan digest is stale is
    :data:`FABRIC_UNDERSIGNED`, because the signature is the earlier and the more
    serious fact. Checks with no fabric counterpart (key binding, identity
    usability, certificate lifetime) roll up to :data:`FABRIC_COMMAND_UNVERIFIED`,
    which always carries ``failed_checks`` so the refusal never degrades to a
    bare "no".
    """
    failed = tuple(exc.failed)
    for check in failed:
        code = _VERIFICATION_CODE_BY_CHECK.get(check)
        if code is not None:
            break
    else:
        code = FABRIC_COMMAND_UNVERIFIED
    return FabricCommandRefused(
        code,
        f"command '{exc.command_id}' refused by verification: "
        f"{', '.join(check.value for check in failed)}",
        details={
            "command_id": exc.command_id,
            "code": exc.code,
            "failed_checks": [check.value for check in failed],
        },
        remediation=_REFUSED_REMEDIATION,
    )


class FabricEngine:
    """Dispatch one planned step through an agent session, safely.

    Args:
        session: The controller-initiated session the command travels over.
        journal: Durable claim/settlement log; the only thing that survives
            controller death.
        lease_sink: The write-ahead lease store (ADR-0005). Read on every
            resume, written when the agent hands back a lease — the controller
            is the single writer (ADR-0007).
        controller_id: Who is dispatching. Recorded on every claim so a
            post-mortem can name the owner of an epoch.
        clock: Time source, injected so expiry and ordering are reproducible.
        verifier: Command verification (plan 19). **Optional, and additive**: with
            no verifier bound the engine behaves exactly as Phase 2 did, and a
            caller that means to verify asserts
            :attr:`FabricEngine.verification_enabled` rather than discovering it.
        evidence: Where decisions are sealed. Optional for the same reason; see
            :class:`FabricEvidenceRecorder`.

    The instance keeps no dispatch state. Every decision below is recomputed
    from ``journal`` and ``lease_sink`` on each call, so constructing a second
    engine over the same durable objects *is* a controller failover.
    """

    def __init__(
        self,
        *,
        session: FabricSession,
        journal: FabricJournal,
        lease_sink: LeaseSink,
        controller_id: str,
        clock: Callable[[], datetime] = utc_now,
        verifier: FabricCommandVerifierPort | None = None,
        evidence: FabricEvidenceRecorder | None = None,
    ) -> None:
        self._session = session
        self._journal = journal
        self._sink = lease_sink
        self._controller_id = controller_id
        self._clock = clock
        self._verifier = verifier
        self._evidence = evidence

    @property
    def verification_enabled(self) -> bool:
        """Whether a verifier is bound, so a caller can assert rather than assume."""
        return self._verifier is not None

    @property
    def verification_algorithm(self) -> str:
        """The algorithm the bound verifier actually uses, or ``""`` when unbound.

        Fail-closed in spirit: naming an algorithm when none is bound would be
        the kind of claim this codebase keeps refusing to make.
        """
        return "" if self._verifier is None else self._verifier.algorithm

    @property
    def evidence_enabled(self) -> bool:
        """Whether decisions are being sealed into a chain."""
        return self._evidence is not None

    # -- projections (read-only; safe to call from a recovering controller) ------

    def claims(self, run_id: str, step_id: str | None = None) -> tuple[DispatchClaim, ...]:
        """Every claim recorded for ``run_id`` (optionally one step), in order."""
        return tuple(
            entry
            for entry in self._journal.entries(run_id, step_id)
            if isinstance(entry, DispatchClaim)
        )

    def settlements(
        self, run_id: str, step_id: str | None = None
    ) -> tuple[DispatchSettlement, ...]:
        """Every settlement recorded for ``run_id`` (optionally one step)."""
        return tuple(
            entry
            for entry in self._journal.entries(run_id, step_id)
            if isinstance(entry, DispatchSettlement)
        )

    def served_fence(self, run_id: str, step_id: str) -> FencingToken | None:
        """The highest fence claimed for ``(run_id, step_id)``, or ``None``.

        This *is* the ownership record. It survives controller death because it
        is derived from the journal, and a new controller reading it is the only
        thing that can tell a deposed owner from the current one.
        """
        fences = [claim.command.fencing_token for claim in self.claims(run_id, step_id)]
        if not fences:
            return None
        return max(fences, key=lambda fence: fence.epoch)

    def nonce_ledger(self, run_id: str, step_id: str) -> NonceLedger:
        """Nonces already spent for ``(run_id, step_id)``."""
        return NonceLedger(
            consumed=frozenset(claim.command.nonce for claim in self.claims(run_id, step_id))
        )

    def open_claims(self, run_id: str, step_id: str | None = None) -> tuple[DispatchClaim, ...]:
        """Claims with no settlement: the crash window, in envelope form."""
        settled = {entry.command_id for entry in self.settlements(run_id)}
        return tuple(
            claim
            for claim in self.claims(run_id, step_id)
            if claim.command.command_id not in settled
        )

    def unreconciled_leases(self, run_id: str) -> tuple[FaultLease, ...]:
        """Live leases in the sink that no settlement points at.

        A controller that died between receiving a lease and settling it leaves
        exactly this. The lease is the only durable evidence that the effect
        happened, so it is what a resumed controller must reconcile first.
        """
        recorded = {
            entry.lease_id for entry in self.settlements(run_id) if entry.lease_id is not None
        }
        return tuple(
            lease
            for lease in self._sink.active_leases()
            if lease.run_id == run_id and lease.id not in recorded
        )

    def unrecovered_steps(self, run_id: str) -> tuple[str, ...]:
        """Steps of ``run_id`` whose recorded lease is not yet safe-terminal.

        A resumed controller compensates these before it re-dispatches; the
        answer is derived from the sink, so it is the same on a cold start as it
        was before the controller died.
        """
        step_of_lease = {
            entry.lease_id: entry.step_id
            for entry in self.settlements(run_id)
            if entry.lease_id is not None
        }
        return tuple(
            sorted(
                {
                    step_of_lease[lease.id]
                    for lease in self._sink.active_leases()
                    if lease.run_id == run_id and lease.id in step_of_lease
                }
            )
        )

    # -- dispatch ----------------------------------------------------------------

    def dispatch(self, request: DispatchRequest) -> DispatchResult:
        """Dispatch one step, or refuse it with a named code.

        Order is deliberate and cheapest-first-per-class:

        1. the envelope's signature claim, then its scope (both are about the
           envelope being internally consistent);
        2. the frozen plan digest, then the fence — a command from a deposed
           owner must not be able to spend effort, let alone a nonce;
        3. reservations — a step that cannot have the lock does not act;
        4. the nonce (single-use, per envelope), then duplicate effect at this
           epoch, then an unresolved prior claim of the same key;
        5. **verification** — plan 19's real check over the envelope's bytes.
           Last, and that placement is a decision: every check above can only
           *refuse*, never act, so an unauthenticated command cannot make any of
           them spend anything on its way to the verifier. Putting verification
           earlier would mean a command refused for a deposed fence had already
           burned its nonce in plan 19's ledger, and a legitimate retry of that
           same intent could never be minted.
        6. the claim is appended — *now* the nonce is spent and the fence served
           — and only then does the provider hear about the step.

        Raises:
            FabricCommandRefused: With :data:`FABRIC_UNDERSIGNED`,
                :data:`FABRIC_PLAN_MISMATCH`, :data:`FABRIC_STALE_FENCE`,
                :data:`FABRIC_RESERVATION_EXPIRED`,
                :data:`FABRIC_RESOURCE_CONFLICT`, ``FABRIC_COMMAND_UNVERIFIED``,
                ``FABRIC_DUPLICATE_DISPATCH``, ``FABRIC_INFLIGHT_UNRESOLVED``,
                or :data:`FABRIC_REPLAYED_NONCE`. Nothing was dispatched in any
                of those cases.
            InvariantViolationError: When the envelope and the step disagree on
                scope — a controller that minted an inconsistent command is a
                bug, and it fails loudly rather than being normalised away.
        """
        command = request.command
        now = self._clock()
        try:
            verification = self._preflight(request, now=now)
        except FabricCommandRefused as exc:
            # A refusal is evidence too: the plan's Phase 4 acceptance asks for
            # it by name, and a refusal nobody recorded is a refusal the next
            # controller cannot tell from a command that never arrived.
            self._record_refusal(command, exc)
            raise

        claim = DispatchClaim(command=command, controller_id=self._controller_id, claimed_at=now)
        self._journal.append(claim)
        self._record_claim(claim, verification)
        recorded = self._recorded_outcome(command)
        if recorded is not None:
            return self._settle(
                command,
                outcome=recorded.outcome,
                target_outcome=recorded.target_outcome,
                detail=f"idempotent retry of '{recorded.command_id}': {recorded.detail}",
                lease_id=recorded.lease_id,
                retried=True,
            )
        normalisation, refusal_code, lease = self._invoke(request)
        return self._settle(
            command,
            outcome=normalisation.outcome,
            target_outcome=normalisation.target_outcome,
            detail=normalisation.detail,
            refusal_code=refusal_code,
            lease_id=lease.id if lease is not None else None,
        )

    def _preflight(self, request: DispatchRequest, *, now: datetime) -> VerifiedDispatch | None:
        """Every check that must pass before the step may act, in order.

        Returns the verification record, or ``None`` when no verifier is bound.
        The served fence is *not* returned even though it is read here: it is
        the journal's projection, and handing it back would invite a caller to
        cache it. ``_verify`` is given it directly, so both the fence check and
        the verifier compare against the same value.

        Raises:
            FabricCommandRefused: Naming the first check that refused.
            InvariantViolationError: On an envelope/step scope disagreement.
        """
        step, command = request.step, request.command
        self._require_signed(command)
        self._require_scope(step, command)
        assert_plan_digest_matches(command, current_plan_digest=request.current_plan_digest)

        served = self.served_fence(command.run_id, step.step_id)
        if served is not None:
            assert_fence_current(command, served_fence=served)
        self._require_reservations(request, now=now)
        # Used as the decision function so the code, message and remediation are
        # the domain's; the claim appended by ``dispatch`` is what spends the nonce.
        self.nonce_ledger(command.run_id, step.step_id).accept(command)
        self._require_single_effect(request)
        if self._has_open_claim(command):
            raise FabricCommandRefused(
                FABRIC_INFLIGHT_UNRESOLVED,
                f"command '{command.command_id}' re-dispatches key "
                f"'{command.idempotency_key}' while an earlier claim of that key is unsettled",
                details={"command_id": command.command_id, "step_id": step.step_id},
                remediation="reconcile the open claim (settle_claim) after recovering any "
                "lease it created; an in-flight effect is never retried into a second one",
            )
        return self._verify(request, served_fence=served, now=now)

    def settle_claim(
        self,
        run_id: str,
        step_id: str,
        *,
        outcome: StepOutcome,
        detail: str = "",
        target_outcome: TargetOutcome | None = None,
    ) -> DispatchSettlement:
        """Close the newest unsettled claim for ``(run_id, step_id)``.

        The reconciliation half of the crash window: a resumed controller that
        has dealt with the lease (or proven there is none) records what the claim
        became, so the step can be dispatched again under a fresh fence. A
        ``FAILED`` settlement must name why it failed, exactly like an observed
        one — a controller that did not witness the effect states its conclusion
        in ``detail`` rather than defaulting a reason it did not learn.

        Raises:
            InvariantViolationError: When there is nothing open to settle, which
                means the caller is reasoning about a claim that is already
                resolved, or when the stated outcome and reason disagree.
        """
        open_claims = self.open_claims(run_id, step_id)
        if not open_claims:
            raise InvariantViolationError(
                "fabric_no_open_claim",
                f"no unsettled claim for step '{step_id}' of run '{run_id}'",
            )
        settlement = DispatchSettlement(
            run_id=run_id,
            step_id=step_id,
            command_id=open_claims[-1].command.command_id,
            outcome=outcome,
            target_outcome=_agreeing_reason(outcome, target_outcome),
            detail=detail or f"settled by {self._controller_id} without a provider call",
            settled_at=self._clock(),
        )
        self._journal.append(settlement)
        self._record_settlement(settlement, result=None)
        return settlement

    # -- internals ----------------------------------------------------------------

    def _verify(
        self,
        request: DispatchRequest,
        *,
        served_fence: FencingToken | None,
        now: datetime,
    ) -> VerifiedDispatch | None:
        """Verify the envelope with plan 19's verifier, or refuse it by name.

        Returns ``None`` when no verifier is bound — the additive Phase 2
        behaviour, unchanged.

        Raises:
            FabricCommandRefused: With the narrowest code among the checks that
                failed (:data:`FABRIC_UNDERSIGNED` for a signature that does not
                verify, and so on), or :data:`FABRIC_COMMAND_UNVERIFIED` with the
                failing checks named. A
                :class:`~mayhem.infra.agent_identity_verifier.SignaturePortUnavailableError`
                also lands here and is refused as unverifiable: nothing was
                checked, and "nothing was checked" is never "checked and passed".
        """
        if self._verifier is None:
            return None
        try:
            verified = self._verifier.verify(
                request.command,
                expected_plan_digest=request.current_plan_digest,
                served_fence=served_fence,
                now=now,
            )
        except CommandRefusedError as exc:
            raise translate_verification_refusal(exc) from exc
        except SignaturePortUnavailableError as exc:
            raise FabricCommandRefused(
                FABRIC_COMMAND_UNVERIFIED,
                f"command '{request.command.command_id}' was not checked: {exc.reason}",
                details={
                    "command_id": request.command.command_id,
                    "failed_checks": [VerificationCheck.SIGNATURE.value],
                    "algorithm": exc.algorithm,
                },
                remediation=_REFUSED_REMEDIATION,
            ) from exc
        return VerifiedDispatch.of(verified)

    def _record_claim(
        self, claim: DispatchClaim, verification: VerifiedDispatch | None
    ) -> None:
        """Seal a landed claim. Never raises into the dispatch path silently."""
        if self._evidence is not None:
            self._evidence.dispatch_recorded(claim, verification=verification)

    def _record_settlement(
        self, settlement: DispatchSettlement, *, result: DispatchResult | None
    ) -> None:
        """Seal a landed settlement, with the dispatch reading when there is one."""
        if self._evidence is not None:
            self._evidence.settlement_recorded(settlement, result=result)

    def _record_refusal(self, command: FabricCommand, exc: FabricCommandRefused) -> None:
        """Seal a refusal.

        Failures here are the recorder's problem and are never allowed to mask the
        refusal that actually happened: a broken evidence sink must not turn a
        clean, named ``FABRIC_STALE_FENCE`` into an ``AttributeError``.
        """
        if self._evidence is None:
            return
        try:
            self._evidence.refusal_recorded(command, code=exc.code, reason=str(exc))
        except Exception:
            # The refusal is the fact; a broken evidence sink is a separate
            # problem and must not replace it.
            return

    def _require_signed(self, command: FabricCommand) -> None:
        """Refuse a command whose signature claim is empty.

        Still unreachable in-process by construction (Phase 1: no field on the
        envelope has a default, so an unsigned command cannot be built), and still
        kept rather than deleted — but its role changed in Phase 4. It is now the
        *first* of two raise sites for :data:`FABRIC_UNDERSIGNED`, and the cheap
        one: it reads a claim the envelope already made. The expensive one is
        :meth:`_verify`, which asks plan 19 whether the signature actually proves
        anything, and
        :func:`mayhem.controller.fabric_evidence.decode_wire_command`, which is
        where an untrusted frame that fails the envelope's own constraints lands.

        Checking the empty case first and the cryptographic case second is
        deliberate: a blank signature should not cost a key lookup, and a
        forged one should never be reported as "blank".
        """
        if not command.is_signed:
            raise FabricCommandRefused(
                FABRIC_UNDERSIGNED,
                f"command '{command.command_id}' carries no signature",
                details={"command_id": command.command_id, "run_id": command.run_id},
                remediation="a fabric command carries a signature over signing_payload() "
                "produced by the agent's current credential",
            )

    def _require_scope(self, step: StepSpec, command: FabricCommand) -> None:
        """The envelope must name the step it is being dispatched against.

        Checked because the two are minted by different code paths (planner and
        command builder) and a mismatch is a controller bug — not a provider
        outcome, and therefore not something to normalise into a step result.
        """
        if command.step_id != step.step_id or command.fencing_token.step_id != step.step_id:
            raise InvariantViolationError(
                "fabric_command_scope",
                f"command '{command.command_id}' names step '{command.step_id}' (fence for "
                f"'{command.fencing_token.step_id}') but is dispatched against "
                f"'{step.step_id}'",
            )
        if command.fencing_token.run_id != command.run_id:
            raise InvariantViolationError(
                "fabric_command_scope",
                f"command '{command.command_id}' carries a fence for run "
                f"'{command.fencing_token.run_id}' while claiming run '{command.run_id}'",
            )

    def _require_reservations(self, request: DispatchRequest, *, now: datetime) -> None:
        """Refuse a dispatch whose locks are lapsed, foreign, or contended.

        A reservation is taken *under* a fence, and a successor mints a strictly
        newer one. A lock the new owner presents against its own older fence is
        therefore the deposed owner's lock, not an inherited one: taking it over
        silently is how two owners end up believing they hold the same resource.
        The remediation is to re-reserve under the current fence.
        """
        held: list[Reservation] = [*request.held_by_others, *request.reservations]
        for reservation in request.reservations:
            if reservation.is_expired(now):
                raise FabricCommandRefused(
                    FABRIC_RESERVATION_EXPIRED,
                    f"reservation on '{reservation.resource_id}' expired at "
                    f"{reservation.expires_at.isoformat()}",
                    details={"resource_id": reservation.resource_id, "run_id": reservation.run_id},
                    remediation="re-reserve under a current fencing token instead of dispatching",
                )
            if not reservation.is_authorised_by(request.command.fencing_token):
                raise FabricCommandRefused(
                    FABRIC_RESOURCE_CONFLICT,
                    f"reservation on '{reservation.resource_id}' is held under fence "
                    f"{reservation.fencing_token.epoch} for holder '{reservation.holder}'; the "
                    f"presented fence is epoch {request.command.fencing_token.epoch}",
                    details={"resource_id": reservation.resource_id, "run_id": reservation.run_id},
                    remediation="a deposed owner's lock is not inherited; re-reserve under the "
                    "current fencing token",
                )
            assert_reservation_available(
                reservation,
                held=[other for other in held if other is not reservation],
                now=now,
            )

    def _require_single_effect(self, request: DispatchRequest) -> None:
        """One effect per ``(step, epoch)``.

        Epochs are the ownership unit, so two effects at the same epoch are two
        owners of one step by another route. A *retry* (same key) is allowed
        because it is the same effect, and it is settled from the recorded
        outcome rather than dispatched again.
        """
        command = request.command
        epoch = command.fencing_token.epoch
        for claim in self.claims(command.run_id, command.step_id):
            if (
                claim.command.fencing_token.epoch == epoch
                and claim.command.idempotency_key != command.idempotency_key
            ):
                raise FabricCommandRefused(
                    FABRIC_DUPLICATE_DISPATCH,
                    f"step '{command.step_id}' already has an effect claimed at epoch {epoch} "
                    f"under key '{claim.command.idempotency_key}'",
                    details={
                        "command_id": command.command_id,
                        "step_id": command.step_id,
                        "epoch": epoch,
                    },
                    remediation=_REMEDIATION_RETRY,
                )

    def _claim_ids_for_key(self, command: FabricCommand) -> frozenset[str]:
        """Command ids of every claim ever made under this idempotency key.

        The key is the effect's identity: a retry reuses it, so every claim that
        carries it describes the *same* effect however many envelopes it took.
        """
        return frozenset(
            claim.command.command_id
            for claim in self.claims(command.run_id, command.step_id)
            if claim.command.idempotency_key == command.idempotency_key
        )

    def _recorded_outcome(self, command: FabricCommand) -> DispatchSettlement | None:
        """The settlement of an earlier claim with the same idempotency key."""
        keys = self._claim_ids_for_key(command)
        for entry in self.settlements(command.run_id, command.step_id):
            if entry.command_id in keys:
                return entry
        return None

    def _has_open_claim(self, command: FabricCommand) -> bool:
        """True when an earlier claim with this idempotency key never settled."""
        keys = self._claim_ids_for_key(command)
        return any(
            claim.command.command_id in keys
            for claim in self.open_claims(command.run_id, command.step_id)
        )

    def _invoke(
        self, request: DispatchRequest
    ) -> tuple[ProviderNormalisation, str | None, FaultLease | None]:
        """Hand the command to the session and normalise whatever comes back.

        Every failure mode a session can have is a *result*, not an escape: a
        protocol refusal keeps its code, a transport exception becomes a failure
        to apply, and a lease that arrived is persisted before it is reported.
        """
        try:
            raw = self._session.dispatch(request.command)
        except FabricCommandRefused as exc:
            return _normalise_refusal(exc), exc.code, None
        except Exception as exc:  # a provider fault is a step outcome, not an engine bug
            normalisation = ProviderNormalisation(
                StepOutcome.FAILED,
                TargetOutcome.FAILED_TO_APPLY,
                f"failed to apply: {type(exc).__name__}: {exc}",
            )
            return normalisation, None, None
        if raw.lease is not None:
            # The controller is the single writer (ADR-0007): the agent hands the
            # lease back, the sink persists it before anything is reported.
            self._sink.save(raw.lease)
        return (
            normalise_provider_result(raw, expected_target=request.expected_target),
            None,
            raw.lease,
        )

    def _settle(
        self,
        command: FabricCommand,
        *,
        outcome: StepOutcome,
        target_outcome: TargetOutcome | None,
        detail: str,
        refusal_code: str | None = None,
        lease_id: str | None = None,
        retried: bool = False,
    ) -> DispatchResult:
        """Append the settlement and return the step's reading of the dispatch."""
        settlement = DispatchSettlement(
            run_id=command.run_id,
            step_id=command.step_id,
            command_id=command.command_id,
            outcome=outcome,
            target_outcome=_agreeing_reason(outcome, target_outcome),
            detail=detail,
            lease_id=lease_id,
            settled_at=self._clock(),
        )
        self._journal.append(settlement)
        reading = DispatchResult(
            run_id=command.run_id,
            step_id=command.step_id,
            command_id=command.command_id,
            epoch=command.fencing_token.epoch,
            outcome=outcome,
            target_outcome=settlement.target_outcome,
            detail=detail,
            refusal_code=refusal_code,
            retried=retried,
            lease_id=settlement.lease_id,
        )
        self._record_settlement(settlement, result=reading)
        return reading
