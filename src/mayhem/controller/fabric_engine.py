"""Distributed dispatch engine: fencing, idempotent retries, error normalisation.

Plan ``docs/v1.1.0/03_EXECUTION_FABRIC.md``, Phase 2. Phase 1 gave the fabric
its *words* (:mod:`mayhem.domain.fabric`); this module is the machinery that
drives them. It is a **dispatch layer**, not a second run engine: the run shape
is still ``RunEngine.execute``'s (intent -> gate -> open run -> grouped steps ->
recover -> verdict -> close, :mod:`mayhem.controller.executor`) and nothing here
reorders it. What this module adds is the one thing the run engine cannot
express — *who* is allowed to act on a step right now, and what to believe when
they come back.

Five properties, in the order they are checked on every dispatch:

1. **Signature claims are honoured as claims, not proofs.**
   :data:`FABRIC_UNDERSIGNED` is wired (:meth:`FabricEngine._require_signed`)
   even though the Phase 1 envelope makes it unreachable in-process: a command
   with a blank or absent signature cannot be *constructed*. The check is the
   seam the future wire path of plan 19 (mTLS, identities, trust roots) decodes
   into, and it is deliberately a named code rather than a comment, so the wire
   receiver does not have to invent a spelling. Verification itself is **not**
   implemented and is not in scope for this phase.
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

The journal itself is a :class:`FabricJournal` protocol here; the controller
binds a durable implementation in the same store as the lease sink. No SQLite
schema ships in this phase (see the module's known limits in the plan ledger).
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

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.agents.sinks import LeaseSink

#: Raised when a second *effect* is claimed for one step at one epoch. The domain
#: owns the wire-facing vocabulary; this code is dispatch-layer state, so it
#: lives here rather than being smuggled into :mod:`mayhem.domain.fabric`.
FABRIC_DUPLICATE_DISPATCH = "fabric_duplicate_dispatch"

#: Raised when a command arrives for a claim that was never settled. A prior
#: owner may have died mid-dispatch, so whether the effect happened is unknown —
#: and an unknown effect is never retried into a *second* effect.
FABRIC_INFLIGHT_UNRESOLVED = "fabric_inflight_unresolved"

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
    """

    def append(self, entry: JournalEntry) -> None: ...

    def entries(self, run_id: str, step_id: str | None = None) -> tuple[JournalEntry, ...]: ...


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
    ) -> None:
        self._session = session
        self._journal = journal
        self._sink = lease_sink
        self._controller_id = controller_id
        self._clock = clock

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
        5. the claim is appended — *now* the nonce is spent and the fence served
           — and only then does the provider hear about the step.

        Raises:
            FabricCommandRefused: With :data:`FABRIC_UNDERSIGNED`,
                :data:`FABRIC_PLAN_MISMATCH`, :data:`FABRIC_STALE_FENCE`,
                :data:`FABRIC_RESERVATION_EXPIRED`,
                :data:`FABRIC_RESOURCE_CONFLICT`,
                ``FABRIC_DUPLICATE_DISPATCH``, ``FABRIC_INFLIGHT_UNRESOLVED``,
                or :data:`FABRIC_REPLAYED_NONCE`. Nothing was dispatched in any
                of those cases.
            InvariantViolationError: When the envelope and the step disagree on
                scope — a controller that minted an inconsistent command is a
                bug, and it fails loudly rather than being normalised away.
        """
        step, command = request.step, request.command
        now = self._clock()
        self._require_signed(command)
        self._require_scope(step, command)
        assert_plan_digest_matches(command, current_plan_digest=request.current_plan_digest)

        served = self.served_fence(command.run_id, step.step_id)
        if served is not None:
            assert_fence_current(command, served_fence=served)
        self._require_reservations(request, now=now)
        # Used as the decision function so the code, message and remediation are
        # the domain's; the claim appended below is what spends the nonce.
        self.nonce_ledger(command.run_id, step.step_id).accept(command)
        self._require_single_effect(request)
        recorded = self._recorded_outcome(command)
        if self._has_open_claim(command):
            raise FabricCommandRefused(
                FABRIC_INFLIGHT_UNRESOLVED,
                f"command '{command.command_id}' re-dispatches key "
                f"'{command.idempotency_key}' while an earlier claim of that key is unsettled",
                details={"command_id": command.command_id, "step_id": step.step_id},
                remediation="reconcile the open claim (settle_claim) after recovering any "
                "lease it created; an in-flight effect is never retried into a second one",
            )

        self._journal.append(
            DispatchClaim(command=command, controller_id=self._controller_id, claimed_at=now)
        )
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
        return settlement

    # -- internals ----------------------------------------------------------------

    def _require_signed(self, command: FabricCommand) -> None:
        """Refuse a command whose signature claim is empty.

        Unreachable in-process by construction (Phase 1: no field on the envelope
        has a default, so an unsigned command cannot be built), which is exactly
        why the check is kept rather than deleted: it is the decision function
        the plan-19 wire receiver calls when a decoded frame fails the envelope's
        own signature constraints. Verification — proving the signature against a
        key and a trust root — is *not* implemented in this phase.
        """
        if not command.is_signed:
            raise FabricCommandRefused(
                FABRIC_UNDERSIGNED,
                f"command '{command.command_id}' carries no signature",
                details={"command_id": command.command_id, "run_id": command.run_id},
                remediation="mTLS identities and trust roots arrive with plan 19; until then a "
                "signature is a claim, not a proof",
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
        return DispatchResult(
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
