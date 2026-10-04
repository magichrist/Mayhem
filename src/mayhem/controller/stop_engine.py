"""Distributed stop execution — the engine that acts on a :class:`StopCommand`
(docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md, Phase 2).

Phase 1 (:mod:`mayhem.domain.stop`) gave the stop path a vocabulary and a pure
ladder and no call site: the words existed, nothing walked them. This module is
the call site. It takes a command, walks :data:`~mayhem.domain.stop.STOP_FLOW`
in order, and seals a record that says what was done, what was found, and — when
it could not finish — which stage it stalled at.

Five commitments shape the code.

**The ladder is walked, not reimplemented.** Stage *order*, *which stages are
owed*, and *whether a stage may be recorded as done* all come from
``domain.stop`` (:func:`~mayhem.domain.stop.mandatory_stages`,
:class:`~mayhem.domain.stop.StopEscalation`). This module contributes exactly one
rule of its own, in :meth:`StopEngine._resume`: the completed stages a caller
hands in must be a **prefix** of what the ladder owes. A stop that resumes by
skipping ``COMPENSATE_ACTIVE`` is refused, not silently repaired, because a
skipped undo is a mutation nobody accounted for.

**Nothing is cached in controller memory.** Every question this engine asks
about a run — is it still injecting, which leases exist, what state is each in
— is re-read from the lease sink on every call. That is what makes the
controller-loss path work: a fresh engine, holding nothing but the sink, a
dispatch surface, and a ledger, can finish a stop the dead controller started.
The run's lease sink is the rendezvous; the process is not.

**Existing undo contracts are reused, never re-derived.** Compensation goes
through :class:`mayhem.controller.recovery.RecoveryService`, which drives the
janitor over the write-ahead undo ops and verify probes each lease already
carries (:mod:`mayhem.domain.leases`). Verification goes through
:func:`mayhem.domain.leases.assert_all_recovered`, the run-completion gate. The
engine never inspects ``undo_ops`` to decide what to run, and never re-implements
a lease transition it can delegate.

**A stage that cannot complete is reported, not skipped.** Every stage handler
runs inside the walk; an exception ends the walk at that stage, records it in
:attr:`StopRecord.stalled_at` with the reason in
:attr:`StopRecord.stall_reason`, and keeps whatever partial evidence the stage
had already emitted. The attempt is then written to the ledger **unsealed** — a
stop that could not reach the agent must still leave a trace, and the trace must
name where it stopped. It is deliberately *not* sealed, because a seal claims
every mandatory stage ran.

**The postflight is computed, never authored.** A caller cannot pass in a
verdict. :func:`postflight_report` derives its checks from the recovery execution
result, the reconciliation and residue findings, and the run-completion gate;
``PostflightReport`` then recomputes the verdict from those checks. A residue
finding is a ``FAIL`` check, so the verdict is ``DIRTY`` by construction — a
stopped run can never close clean with an open residue obligation. ``UNKNOWN`` is
the fail-closed third state and belongs to the two cases where nothing was
established: a stop that stalled before it reached ``SEAL`` produces no report at
all, and observations that have aged past their TTL no longer prove anything.

Evidence references are structured and never empty. ``lease/<id>`` cites a lease,
``residue/<kind>/<target>`` cites a finding, ``run/<id>/<stage>`` cites a
stage-level observation that had no per-subject item, and
``postflight/<id>/<digest>`` cites the sealed report. A ``PASS`` with nothing
behind it is refused by ``PostflightCheck`` before it reaches this module; and a
stage cannot be recorded as done at all unless it left at least one
:class:`StageReceipt`, because "recorded as done" has to mean "left a trace"
rather than "the loop moved on".

The two controller-loss paths are both here and both are reached through
:meth:`StopEngine.execute_for_lost_controller`, which derives the run state from
the sink, builds the ``CONTROLLER_LOST`` command, and executes it:

* a **promoted standby** keeps the controller path — recovery through the undo
  contracts — and seals evidence naming ``controller_lost``;
* with **no controller at all**, the agent's own watchdog is the last resort.
  That is :data:`CompensationPath.AGENT_WATCHDOG`: the engine asks an
  :class:`AgentCompensator` to compensate the run's outstanding leases and marks
  each settled one ``EXPIRED`` with ``release_mechanism="watchdog"`` — the
  terminal state :mod:`mayhem.domain.leases` already reserves for "agent
  self-compensated". A lease the watchdog could not undo stays outstanding, and
  the postflight says so.

:meth:`StopEngine.execute` is ``async`` only because the watchdog path is: the
agent compensates through its executor off the event loop
(:meth:`mayhem.agents.watchdog.AgentWatchdog.sweep`). The controller path awaits
nothing.

Phase 3 owns the surface (one command, one button, the emergency role for an
environment-wide stop) and Phase 4 binds :class:`SealedStop` into the sealed
chain. :class:`StopLedger` is the seam they bind: it is a required collaborator,
so a stop can never be silently dropped for want of somewhere to record it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.attestation import AttestedEvent, AttestedTimestamp
from mayhem.domain.cancellation import CancellationLevel
from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.leases import LeaseState, assert_all_recovered
from mayhem.domain.stop import (
    STOP_FLOW,
    CheckStatus,
    ObservedValue,
    PostflightCheck,
    PostflightReport,
    PostflightVerdict,
    RunState,
    StopCommand,
    StopEscalation,
    StopReason,
    StopScope,
    StopSignal,
    StopStage,
    StopTrigger,
    mandatory_stages,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.agents.sinks import LeaseSink
    from mayhem.controller.recovery import RecoveryExecutionResult, RecoveryService
    from mayhem.domain.leases import FaultLease
    from mayhem.domain.stop_conditions import Firing

__all__ = [
    "EVENT_STOP_EXECUTED",
    "EVENT_STOP_POSTFLIGHT",
    "FREEZE_LATENCY_BOUND_S",
    "STOP_CHAIN_KEY_SUFFIX",
    "STOP_MECHANISM",
    "AgentCompensationOutcome",
    "AgentCompensator",
    "ClaimLedger",
    "Compensated",
    "CompensationPath",
    "DispatchFreezer",
    "OpenClaim",
    "Residue",
    "ResidueScanner",
    "SealedStop",
    "StageReceipt",
    "StopEngine",
    "StopExecution",
    "StopLedger",
    "claim_ref",
    "command_for_firing",
    "freeze_latency",
    "lease_ref",
    "leases_for_run",
    "observed_values_for",
    "postflight_ref",
    "postflight_report",
    "residue_ref",
    "run_state_from_sink",
    "stage_ref",
    "stop_chain_events",
    "stop_chain_key",
    "stop_evidence_payload",
    "stop_manifest_id",
    "stop_postflight_payload",
    "trigger_for_firing",
]


STOP_MECHANISM = "stop"
"""``release_mechanism`` for a lease this engine settled itself. Deliberately not
one of the four values :class:`mayhem.domain.leases.FaultLease` documents
(``normal|watchdog|janitor|manual``): filing an engine-driven release as
``manual`` would hide, from every reader of the lease row, that no human pressed
anything."""


# -- evidence references ------------------------------------------------------------


def lease_ref(lease_id: str) -> str:
    """Evidence reference for one lease."""
    return f"lease/{lease_id}"


def stage_ref(run_id: str, stage: StopStage) -> str:
    """Evidence reference for a stage-level observation with no per-subject item.

    Cited by a receipt for a stage that looked at the whole run and found nothing
    to name — a residue scan that came back empty, a verify gate over a run
    holding no leases. It is the weakest reference in the vocabulary and it says
    so: the evidence is the observation that ran, not a thing that was inspected.
    """
    return f"run/{run_id}/{stage.value}"


def residue_ref(kind: str, target: str) -> str:
    """Evidence reference for one residue finding."""
    return f"residue/{kind}/{target}"


def postflight_ref(run_id: str, report_digest: str) -> str:
    """Evidence reference for a sealed postflight report, by its digest."""
    return f"postflight/{run_id}/{report_digest}"


def claim_ref(command_id: str) -> str:
    """Evidence reference for one dispatch claim that was never settled."""
    return f"claim/{command_id}"


#: The plan's "freeze within seconds", as a number this codebase will fail on.
#:
#: Chosen for what the freeze actually is: one call to the
#: :class:`DispatchFreezer`, which on the shipped surface is a fence-epoch mint
#: against the local store. There is no network hop in it, so a bound in the
#: seconds is not generous — it is a bound that would notice a freeze which
#: started reaching for something remote or waiting on a lock it does not hold.
#:
#: It is a bound on *mayhem's* freeze, not on the environment's reaction: how
#: long a paused queue takes to drain, or a frozen sidecar to notice, is not
#: measured here and cannot be, from inside the process that asked.
FREEZE_LATENCY_BOUND_S = 5.0


def freeze_latency(
    execution: StopExecution, *, bound_s: float = FREEZE_LATENCY_BOUND_S
) -> tuple[float | None, bool]:
    """``(measured_seconds, within_bound)`` for one stop.

    The fail-closed third state is carried rather than collapsed: ``(None, False)``
    for a stop whose walk never reached ``FREEZE``, because "the freeze was not
    measured" is not "the freeze was instant", and a caller that treats an
    absent measurement as a passing one would report a bound it never checked.

    The check is ``measured <= bound`` and nothing else. No margin, no
    rounding, no tolerance: a bound with slack in it is a bound nobody reads.
    """
    measured = execution.freeze_latency_s
    if measured is None:
        return None, False
    return measured, measured <= bound_s


# -- records ------------------------------------------------------------------------


class Residue(BaseModel):
    """Something the undo missed, as one thing found.

    Named rather than counted: a residue with no ``target`` could not be chased,
    and two findings of the same kind on the same target are one finding however
    many probes saw it.
    """

    model_config = ConfigDict(frozen=True)

    kind: str
    target: str
    detail: str = ""

    @field_validator("kind", "target")
    @classmethod
    def _nonblank(cls, value: str) -> str:
        if not value.strip():
            msg = "a residue must name what was found; got a blank field"
            raise InvariantViolationError("residue_field_not_blank", msg)
        if value != value.strip():
            msg = f"residue field must be trimmed; got {value!r}"
            raise InvariantViolationError("residue_field_trimmed", msg)
        return value

    @property
    def evidence_ref(self) -> str:
        return residue_ref(self.kind, self.target)

    def describe(self) -> str:
        suffix = f": {self.detail}" if self.detail else ""
        return f"{self.kind}@{self.target}{suffix}"


class StageReceipt(BaseModel):
    """One stage's evidence: what ran, and what it can be cited for.

    A stage may emit several receipts (one per lease, one per residue) and falls
    back to a stage-level receipt when it had no per-subject item. Every
    completed stage owes at least one — that is what makes "recorded as done"
    mean "left a trace" rather than "the loop moved on".
    """

    model_config = ConfigDict(frozen=True)

    stage: StopStage
    evidence_ref: str
    detail: str = ""
    observed_at: datetime = Field(default_factory=utc_now)

    @field_validator("evidence_ref")
    @classmethod
    def _ref_nonblank(cls, value: str) -> str:
        if not value.strip():
            msg = "a stage receipt must cite a non-blank evidence reference"
            raise InvariantViolationError("stage_receipt_requires_evidence_ref", msg)
        if value != value.strip():
            msg = f"stage receipt evidence reference must be trimmed; got {value!r}"
            raise InvariantViolationError("stage_receipt_ref_trimmed", msg)
        return value

    @field_validator("observed_at")
    @classmethod
    def _observed_at_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            msg = f"stage receipt observed_at must be tz-aware; got naive {value!r}"
            raise InvariantViolationError("stage_receipt_observed_at_aware", msg)
        return value

    def describe(self) -> str:
        return f"{self.stage.value} -> {self.evidence_ref}"


class StopRecord(BaseModel):
    """One attempt at one stop: what was owed, what ran, where it stopped.

    The completed stages are constrained to be a **prefix** of
    :func:`~mayhem.domain.stop.mandatory_stages` for ``(state, level)``, and
    every completed stage owes at least one :class:`StageReceipt`. A stalled
    stage may also hold the partial receipts it emitted before failing — losing
    those would lose the only record of which leases *were* settled before the
    engine reached the one that could not be.
    """

    model_config = ConfigDict(frozen=True)

    command: StopCommand
    state: RunState
    level: CancellationLevel
    compensation: CompensationPath
    started_at: datetime
    finished_at: datetime
    completed_stages: tuple[StopStage, ...] = ()
    carried_stages: tuple[StopStage, ...] = ()
    """Stages a *previous* attempt completed, whose receipts live on that
    attempt's record in the ledger. Without this the "a completed stage owes a
    receipt" rule would make a legitimate resume impossible — and the fix must
    not be to weaken the rule, which is why the inherited stages are named
    rather than assumed."""
    stalled_at: StopStage | None = None
    stall_reason: str = ""
    receipts: tuple[StageReceipt, ...] = ()
    report_digest: str = ""
    """Digest of the sealed postflight, or empty when nothing was sealed."""

    @field_validator("started_at", "finished_at")
    @classmethod
    def _timestamps_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            msg = f"stop record timestamp must be tz-aware; got naive {value!r}"
            raise InvariantViolationError("stop_record_timestamp_aware", msg)
        return value

    @model_validator(mode="after")
    def _check_walk(self) -> StopRecord:
        owed = mandatory_stages(self.state, self.level)
        completed = tuple(StopStage(s) for s in self.completed_stages)
        carried = tuple(StopStage(s) for s in self.carried_stages)
        if len(completed) > len(owed) or completed != owed[: len(completed)]:
            msg = (
                f"stop record for run state {self.state.value} at {self.level} owes "
                f"{[s.value for s in owed]}; recorded {[s.value for s in completed]} is "
                "not a prefix of it"
            )
            raise InvariantViolationError("stop_record_stage_prefix", msg)
        if not set(carried) <= set(completed):
            msg = (
                f"carried stages {[s.value for s in carried]} are not all in the completed "
                f"walk {[s.value for s in completed]}"
            )
            raise InvariantViolationError("stop_record_carried_not_completed", msg)
        if self.stalled_at is not None:
            stalled = StopStage(self.stalled_at)
            if stalled not in owed[len(completed) :]:
                msg = (
                    f"stop record stalls at {stalled.value}, which is not the next stage "
                    f"owed after {[s.value for s in completed]}"
                )
                raise InvariantViolationError("stop_record_stall_not_next_owed", msg)
            if not self.stall_reason.strip():
                msg = "a stalled stop must name why it stalled"
                raise InvariantViolationError("stop_record_stall_reason_required", msg)
        elif self.stall_reason.strip():
            msg = "a stop that did not stall cannot carry a stall reason"
            raise InvariantViolationError("stop_record_stall_reason_unexpected", msg)
        allowed = set(completed) | ({self.stalled_at} if self.stalled_at is not None else set())
        unowed = {r.stage for r in self.receipts} - allowed
        if unowed:
            named = sorted(stage.value for stage in unowed)
            msg = f"stop record holds receipts for stages it did not run: {named}"
            raise InvariantViolationError("stop_record_receipt_for_unrun_stage", msg)
        for stage in completed:
            if stage in carried:
                continue  # evidenced by the earlier attempt's record
            if not any(r.stage is stage for r in self.receipts):
                msg = f"stop record marks {stage.value} done with no evidence receipt"
                raise InvariantViolationError("stop_record_stage_requires_receipt", msg)
        order = [STOP_FLOW.index(r.stage) for r in self.receipts]
        if order != sorted(order):
            msg = "stop record receipts are out of stop-flow order"
            raise InvariantViolationError("stop_record_receipts_out_of_order", msg)
        return self

    # -- projections ---------------------------------------------------------

    @property
    def reason(self) -> StopReason:
        return self.command.reason

    @property
    def sealed(self) -> bool:
        """True when the walk reached ``SEAL`` and stalled nowhere."""
        return self.stalled_at is None and StopStage.SEAL in self.completed_stages

    @property
    def outstanding(self) -> tuple[StopStage, ...]:
        """Stages the ladder still owed for this attempt.

        A stage the engine stalled *on* is included: it was attempted, not
        finished, and an operator reading the record needs to see it as work left
        undone rather than work done badly.
        """
        owed = mandatory_stages(self.state, self.level)
        done = set(self.completed_stages)
        return tuple(stage for stage in owed if stage not in done)

    def receipts_for(self, stage: StopStage) -> tuple[StageReceipt, ...]:
        return tuple(r for r in self.receipts if r.stage is StopStage(stage))


class SealedStop(BaseModel):
    """A stop that reached ``SEAL``: the record, the report, and their binding.

    ``report_digest`` is recomputed from ``report`` and compared, never taken on
    trust from the caller — the same reason ``PostflightReport.verdict`` is
    derived on every read. A seal whose digest disagrees with its report is
    refused rather than filed, because a sealed record naming one set of
    evidence while carrying another is worse than no record at all.
    """

    model_config = ConfigDict(frozen=True)

    record: StopRecord
    report: PostflightReport
    report_digest: str
    sealed_at: datetime

    @field_validator("sealed_at")
    @classmethod
    def _sealed_at_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            msg = f"sealed stop sealed_at must be tz-aware; got naive {value!r}"
            raise InvariantViolationError("sealed_stop_sealed_at_aware", msg)
        return value

    @model_validator(mode="after")
    def _check_evidence(self) -> SealedStop:
        if not self.record.sealed:
            stalled = self.record.stalled_at
            msg = (
                f"a stop that stalled at {stalled.value if stalled else 'an unknown stage'} is "
                "recorded, not sealed: sealing claims every mandatory stage ran"
            )
            raise InvariantViolationError("stop_seal_requires_complete_walk", msg)
        if not self.record.receipts:
            msg = "a stop with no evidence is unsealable"
            raise InvariantViolationError("stop_seal_requires_evidence", msg)
        digest = self.report.report_digest
        if digest != self.report_digest:
            msg = (
                f"sealed stop digest {self.report_digest!r} does not match its report "
                f"({digest!r})"
            )
            raise InvariantViolationError("stop_seal_digest_mismatch", msg)
        return self

    @property
    def verdict(self) -> PostflightVerdict:
        return self.report.verdict(self.sealed_at)

    @property
    def recovery_verified(self) -> bool:
        return self.report.recovery_verified(self.sealed_at)


# -- execution result ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StopExecution:
    """What one stop attempt produced.

    ``sealed`` is ``None`` for a stop that stalled — that is the difference
    between "we know what happened" and "we know what happened and finished".
    ``verdict`` is ``UNKNOWN`` without a seal: nothing was established, and
    unchecked is not clean.

    ``freeze_latency_s`` is the *measured* seconds from entering ``execute`` to
    the ``FREEZE`` stage leaving a receipt, and ``None`` when the walk never got
    there. It is the plan's "freeze within seconds" acceptance as a number rather
    than a claim: measured on a monotonic clock, never on the injected
    ``now`` (which is a *record* of when the stop was issued, and reading it back
    would report exactly 0.0 for a freeze that took a minute). It measures this
    process, so it bounds what mayhem can do and says nothing about how fast the
    system it froze reacted — see :func:`freeze_latency`.
    """

    record: StopRecord
    sealed: SealedStop | None = None
    freeze_latency_s: float | None = None

    @property
    def run_id(self) -> str:
        return self.record.command.run_id

    @property
    def reason(self) -> StopReason:
        return self.record.reason

    @property
    def stalled_at(self) -> StopStage | None:
        return self.record.stalled_at

    @property
    def report(self) -> PostflightReport | None:
        return None if self.sealed is None else self.sealed.report

    @property
    def verdict(self) -> PostflightVerdict:
        if self.sealed is None:
            return PostflightVerdict.UNKNOWN
        return self.sealed.verdict

    @property
    def recovered(self) -> bool:
        return self.sealed is not None and self.sealed.recovery_verified

    def describe(self) -> str:
        if self.sealed is not None:
            where = "sealed"
        else:
            stalled = self.record.stalled_at
            where = f"stalled at {stalled.value if stalled else 'an unknown stage'}"
        return (
            f"run {self.run_id} stop {self.record.command.id} "
            f"reason={self.reason.value} verdict={self.verdict.value} {where}"
        )


# -- compensation paths -------------------------------------------------------------


class CompensationPath(StrEnum):
    """Who held the undo contract while the run was stopped.

    The two paths differ only in *who*, and the choice is recorded on the stop
    record because "the agent cleaned up after itself" and "the controller drove
    the janitor" are different operational stories to read back at 3am.
    """

    CONTROLLER_RECOVERY = "controller_recovery"
    AGENT_WATCHDOG = "agent_watchdog"


class AgentCompensationOutcome(StrEnum):
    """What the agent-side watchdog made of one lease.

    ``UNKNOWN`` is the fail-closed third state: the watchdog did not hold the
    lease, so nothing compensated it. Reading that as ``EXPIRED`` would claim a
    self-compensation nobody performed.
    """

    EXPIRED = "expired"
    DIRTY = "dirty"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Compensated:
    """One lease's agent-side compensation outcome."""

    lease_id: str
    outcome: AgentCompensationOutcome
    detail: str = ""


# -- collaborator seams -------------------------------------------------------------


class DispatchFreezer(Protocol):
    """The fabric surface that stops new actions being dispatched for a run.

    Deliberately narrow: one call, one evidence reference. Whatever the 03
    fabric needs to fence a run's dispatch — a fencing token, a dispatch epoch, a
    receipt id — it returns as that reference, and the engine files it as the
    ``FREEZE`` receipt. Raising is how "the fabric could not be reached" is said;
    the engine records the stall rather than inventing a freeze.
    """

    def freeze(self, run_id: str) -> str: ...


class ClaimLedger(Protocol):
    """Plan 03's dispatch journal, read as claims that were never settled.

    The crash window, in the only form this engine can honestly act on. A claim
    is an *intent*: mayhem asked the fabric to do something under a fence epoch.
    A settlement is the observation of what that became. A claim with neither a
    settlement nor a lease in the sink is the case the reconcile stage exists for
    — mayhem dispatched, mayhem cannot prove the effect happened, and mayhem
    cannot prove it did not.

    **A reader, deliberately, and not a settler.** Settling a claim means
    asserting what the effect became, and only the lane that dispatches may make
    that assertion: it is the statement that makes a crashed step safely
    re-dispatchable under a fresh fence, and a stop has no business writing it.
    So this engine reports an open claim as a residue finding — which makes the
    postflight ``DIRTY`` and the run unclosable-clean — and leaves closing it to
    the reconciler that owns the dispatch.

    Raising is how "the journal could not be read" is said, and the walk then
    records the stall rather than asserting a clean reconcile.
    """

    def open_claims(self, run_id: str) -> tuple[OpenClaim, ...]: ...


class OpenClaim(BaseModel):
    """One dispatch claim with no settlement.

    Deliberately only what the residue finding has to cite: which command, which
    step, and under which fence epoch. A stop is not the right place to read a
    command's payload.
    """

    model_config = ConfigDict(frozen=True)

    command_id: str
    step_id: str = ""
    epoch: int = 0

    @property
    def evidence_ref(self) -> str:
        return claim_ref(self.command_id)


class ResidueScanner(Protocol):
    """Looks for what the undo missed, beyond the lease states.

    The lease states are the engine's own evidence; a scanner is the *other*
    witness — a qdisc still on an interface whose lease reads ``RELEASED``, an
    orphaned network namespace, a probe that still answers. Its absence is not
    evidence of absence, so an empty result is cited as :func:`stage_ref`, not
    as silence.
    """

    def scan(self, run_id: str) -> tuple[Residue, ...]: ...


class WatchdogLike(Protocol):
    """The surface an agent-side compensator drives
    :class:`mayhem.agents.watchdog.AgentWatchdog` through.

    Declared structurally so the controller layer takes no import-time dependency
    on the agent package, and so the real ``AgentWatchdog`` satisfies it without
    inheriting from anything here (the test file assigns one to this type, which
    is the cheapest available check that it still does).
    """

    def snapshot(self) -> list[dict[str, Any]]: ...

    def register(
        self,
        *,
        lease_id: str,
        lease: Any,
        executor: Any,
        ttl_seconds: float,
        now_epoch_s: float | None = None,
        task_id: str | None = None,
    ) -> float: ...

    async def sweep(self, *, now_epoch_s: float | None = None) -> list[str]: ...

    def final_state(self, lease_id: str) -> str | None: ...


class AgentCompensator(Protocol):
    """The agent's own last-resort compensation, asked per run."""

    async def compensate(self, leases: tuple[FaultLease, ...]) -> tuple[Compensated, ...]: ...


class StopLedger(Protocol):
    """Where stop attempts and seals are recorded.

    Required, not optional: an emergency stop whose record went nowhere is the
    failure this whole module exists to prevent. Phase 3 binds it to the
    operator surface, Phase 4 to the sealed chain.
    """

    def record_attempt(self, record: StopRecord) -> None: ...

    def record_seal(self, sealed: SealedStop) -> None: ...

    def attempts(self, run_id: str) -> tuple[StopRecord, ...]: ...

    def seal(self, run_id: str) -> SealedStop | None: ...


# -- postflight ---------------------------------------------------------------------


def postflight_report(
    *,
    run_id: str,
    stop: StopTrigger,
    leases: tuple[FaultLease, ...],
    findings: tuple[Residue, ...],
    recovery: RecoveryExecutionResult | None = None,
    now: datetime | None = None,
) -> PostflightReport:
    """Compute the postflight mirror of a stop from what the stop observed.

    Three checks, each from a different witness:

    ``recovery:leases_recovered``
        from the recovery execution result — what the compensation pass
        reported. Absent when no recovery pass ran (the agent-watchdog path, or
        a stop that stalled first), because "no output" is not "clean".
    ``residue:<kind>:<target>``
        one ``FAIL`` per finding, plus a passing ``residue:scan`` citing the
        scan itself when it found nothing.
    ``verify:run_completion_gate``
        :func:`~mayhem.domain.leases.assert_all_recovered` over the leases as
        the sink reports them *now* — the independent check that does not trust
        the pass that just ran.

    A finding makes the report ``DIRTY`` by construction. The ``UNKNOWN`` verdict
    belongs to the two cases where nothing was established rather than to this
    function: a stop that stalled before it could reach ``SEAL`` produces no
    report at all, and a report whose observations have aged past their TTL is no
    longer evidence of anything. ``PostflightReport.verdict`` owns both.
    """
    moment = now if now is not None else utc_now()
    if moment.tzinfo is None:
        msg = f"postflight generation time must be tz-aware; got naive {moment!r}"
        raise InvariantViolationError("postflight_generated_at_aware", msg)
    checks: list[PostflightCheck] = []

    if recovery is not None:
        reported = sorted({*recovery.recovered, *recovery.expired, *recovery.dirty})
        unsettled = [lid for lid in reported if not _settled(leases, lid)]
        dirty = sorted(set(recovery.dirty))
        failing = sorted({*unsettled, *dirty})
        checks.append(
            PostflightCheck(
                name="recovery:leases_recovered",
                status=CheckStatus.FAIL if failing else CheckStatus.PASS,
                evidence_refs=tuple(lease_ref(lid) for lid in reported)
                or (stage_ref(run_id, StopStage.COMPENSATE_ACTIVE),),
                detail=(
                    f"recovery state={recovery.state.value}; "
                    f"unsettled={unsettled or 'none'}; dirty={dirty or 'none'}"
                ),
                observed_at=moment,
            )
        )

    unique: dict[str, Residue] = {}
    for finding in findings:
        unique.setdefault(finding.evidence_ref, finding)
    for finding in unique.values():
        checks.append(
            PostflightCheck(
                name=f"residue:{finding.kind}:{finding.target}",
                status=CheckStatus.FAIL,
                evidence_refs=(finding.evidence_ref,),
                detail=finding.describe(),
                observed_at=moment,
            )
        )
    if not unique:
        checks.append(
            PostflightCheck(
                name="residue:scan",
                status=CheckStatus.PASS,
                evidence_refs=(stage_ref(run_id, StopStage.RESIDUE_SCAN),),
                detail="residue scan returned no findings",
                observed_at=moment,
            )
        )

    offenders = sorted(lease.id for lease in leases if not lease.is_safe_terminal)
    checks.append(
        PostflightCheck(
            name="verify:run_completion_gate",
            status=CheckStatus.FAIL if offenders else CheckStatus.PASS,
            evidence_refs=tuple(lease_ref(lid) for lid in offenders)
            or tuple(lease_ref(lease.id) for lease in sorted(leases, key=lambda item: item.id))
            or (stage_ref(run_id, StopStage.VERIFY),),
            detail=(
                f"assert_all_recovered: {len(offenders)} non-safe-terminal lease(s)"
                + (f" ({', '.join(offenders)})" if offenders else "")
            ),
            observed_at=moment,
        )
    )

    return PostflightReport(
        run_id=run_id,
        stop=stop,
        checks=tuple(checks),
        generated_at=moment,
    )


def _settled(leases: tuple[FaultLease, ...], lease_id: str) -> bool:
    return any(lease.id == lease_id and lease.is_safe_terminal for lease in leases)


# -- condition-fired reasons --------------------------------------------------------


def observed_values_for(firing: Firing) -> tuple[ObservedValue, ...]:
    """Project a firing's cited samples into the stop trigger's evidence.

    Each sample is named ``<metric>@<recorded-at>`` so two samples of the same
    metric in one firing stay distinct — ``StopTrigger`` refuses a repeated
    observed-value name, and two readings of the same metric at different
    instants are two pieces of evidence, not one repeated name.
    """
    values: list[ObservedValue] = []
    for sample in firing.samples:
        if sample.value is None:  # pragma: no cover - Firing refuses an unavailable sample
            msg = f"firing for {firing.condition_name!r} cites a sample with no value"
            raise InvariantViolationError("stop_sample_without_value", msg)
        values.append(
            ObservedValue(
                name=f"{sample.metric}@{sample.at_epoch_s:g}",
                value=f"{sample.value:g}",
                unit=sample.observation.unit,
            )
        )
    return tuple(values)


def trigger_for_firing(firing: Firing) -> StopTrigger:
    """The ``CONDITION_TRIPPED`` trigger a firing produces.

    ``Firing`` is the only producer of this reason: it is the only type that
    cannot exist without cited samples, and those samples are carried into the
    trigger, so a sealed stop names the readings that stopped the run.
    """
    return StopTrigger.for_signal(
        StopSignal.CONDITION_TRIPPED,
        condition_id=firing.condition_name,
        observed_values=observed_values_for(firing),
        detail=firing.note or f"condition fired at {firing.fired_at_epoch_s:g}s",
    )


def command_for_firing(
    firing: Firing,
    *,
    command_id: str,
    run_id: str,
    principal: str,
    now: datetime | None = None,
) -> StopCommand:
    """A run-scoped stop command for a fired condition."""
    return StopCommand(
        id=command_id,
        scope=StopScope.RUN,
        run_id=run_id,
        principal=principal,
        trigger=trigger_for_firing(firing),
        issued_at=now if now is not None else utc_now(),
    )


# -- sink helpers -------------------------------------------------------------------


def leases_for_run(sink: LeaseSink, run_id: str) -> tuple[FaultLease, ...]:
    """Every lease the sink holds for a run, read now.

    Deliberately a function and not a cache. The engine asks this question again
    after every stage, because the answer is the only thing that survives a
    controller restart.
    """
    return tuple(lease for lease in _all_leases(sink) if lease.run_id == run_id)


def _all_leases(sink: LeaseSink) -> tuple[FaultLease, ...]:
    # ``all_leases`` is not on the LeaseSink protocol but both production sinks
    # have it; without it the engine can only see unsettled leases, which is the
    # safe direction to be blind in.
    reader: Callable[[], tuple[FaultLease, ...]] | None = getattr(sink, "all_leases", None)
    if reader is not None:
        return reader()
    return sink.active_leases()


def run_state_from_sink(sink: LeaseSink, run_id: str) -> RunState:
    """The run state a controller that has lost its memory can still prove.

    An outstanding lease proves the run may still be injecting; the absence of one
    proves nothing was left injected, which is what ``PENDING`` means to the
    ladder. It deliberately cannot return ``FINISHED`` — a sink cannot tell a
    completed run from a running one that happens to hold nothing right now, and
    guessing ``FINISHED`` would silently drop owed stages. A caller that knows
    the run's terminal status passes ``state=`` instead, and a terminal state is
    refused.
    """
    if any(not lease.is_safe_terminal for lease in leases_for_run(sink, run_id)):
        return RunState.RUNNING
    return RunState.PENDING


# -- the engine ---------------------------------------------------------------------


@dataclass(slots=True)
class _Walk:
    """Mutable scratch for one stop walk. Discarded when the walk returns."""

    run_id: str
    command: StopCommand
    compensation: CompensationPath
    now: datetime
    receipts: list[StageReceipt] = field(default_factory=list)
    findings: list[Residue] = field(default_factory=list)
    recovery: RecoveryExecutionResult | None = None
    report: PostflightReport | None = None
    freeze_latency_s: float | None = None
    """Measured seconds from taking the command to the ``FREEZE`` receipt.

    ``None`` until the freeze stage leaves one, which is what a stop that
    stalled at (or before) ``FREEZE`` reports: no measurement is not a fast one.
    """


class StopEngine:
    """Executes a :class:`StopCommand` against the run it names."""

    def __init__(
        self,
        *,
        sink: LeaseSink,
        recovery: RecoveryService,
        dispatch: DispatchFreezer,
        ledger: StopLedger,
        residue: ResidueScanner | None = None,
        compensator: AgentCompensator | None = None,
        artifact_dir: str | None = None,
        claims: ClaimLedger | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sink = sink
        self._recovery = recovery
        self._dispatch = dispatch
        self._ledger = ledger
        self._residue = residue
        self._compensator = compensator
        self._artifact_dir = artifact_dir
        # Plan 13's claim ledger, read-only. Optional and inert without it; see
        # :class:`ClaimLedger` for why it is a reader and not a settler.
        self._claims = claims
        # Monotonic, not the injected wall clock: the freeze latency is an
        # elapsed-time measurement, and a clock a test can pin is exactly the
        # clock that would make the measurement meaningless. Injectable so a
        # test can drive it, never a source of the number a caller is shown.
        self._monotonic = monotonic

    # -- entry points ---------------------------------------------------------

    async def execute(
        self,
        command: StopCommand,
        *,
        state: RunState | None = None,
        level: CancellationLevel = CancellationLevel.KILL,
        compensation: CompensationPath = CompensationPath.CONTROLLER_RECOVERY,
        completed: tuple[StopStage, ...] = (),
        now: datetime | None = None,
    ) -> StopExecution:
        """Walk the ladder for *command* and record the attempt.

        Args:
            command: the stop to execute. Must be run-scoped — an
                environment-wide command names no run to act on, and fanning one
                out is the caller's job, not a guess this engine makes.
            state: the run state to walk for. Derived from the sink when
                omitted, which is what a controller that lost its memory has to
                work with.
            level: how hard to stop. Defaults to ``KILL``, which owes the whole
                flow: a residue scan and a verify gate are exactly the stages a
                stop must not skip.
            compensation: which side held the undo contract.
            completed: stages a previous attempt already finished. Must be a
                prefix of what the ladder owes — a resume that skips a stage is
                refused rather than repaired.
            now: the instant the stop began; defaults to the wall clock.

        Raises:
            InvariantViolationError: For an environment-scoped command, a stale
                command, a terminal run state, or a ``completed`` that is not a
                prefix of the owed flow.
        """
        moment = now if now is not None else utc_now()
        if command.is_environment_wide:
            msg = (
                f"stop command {command.id} is environment-wide; this engine executes one run "
                "at a time and will not guess which: expand the scope upstream"
            )
            raise InvariantViolationError("stop_engine_requires_run_scope", msg)
        if command.is_stale(moment):
            msg = (
                f"stop command {command.id} expired at {command.expires_at.isoformat()}; it "
                "would act on a world that has since changed"
            )
            raise InvariantViolationError("stop_command_stale", msg)
        run_state = state if state is not None else run_state_from_sink(self._sink, command.run_id)
        if run_state.is_terminal:
            msg = (
                f"stop command {command.id} targets run {command.run_id}, which is "
                f"{run_state.value}; there is nothing to escalate"
            )
            raise InvariantViolationError("stop_for_terminal_run", msg)
        escalation = self._resume(run_state, level, completed)

        walk = _Walk(
            run_id=command.run_id,
            command=command,
            compensation=compensation,
            now=moment,
        )
        # Taken once, before the walk starts: the freeze latency is measured from
        # the moment mayhem took the command, not from the moment the walk began.
        entered_at = self._monotonic()
        stalled: StopStage | None = None
        stall_reason = ""
        while (stage := escalation.current) is not None:
            try:
                await self._run_stage(stage, walk)
            except Exception as exc:
                # Keep whatever the stage already evidenced: which leases were
                # settled before the one that could not be is the part an operator
                # needs in order to act at all.
                stalled = stage
                stall_reason = f"{stage.value}: {type(exc).__name__}: {exc}"
                break
            if stage is StopStage.FREEZE:
                walk.freeze_latency_s = self._monotonic() - entered_at
            escalation = escalation.advance(stage)

        report = walk.report
        record = StopRecord(
            command=command,
            state=run_state,
            level=level,
            compensation=compensation,
            started_at=moment,
            finished_at=utc_now(),
            completed_stages=escalation.done,
            carried_stages=tuple(StopStage(s) for s in completed),
            stalled_at=stalled,
            stall_reason=stall_reason,
            receipts=tuple(walk.receipts),
            report_digest=report.report_digest if report is not None else "",
        )
        self._ledger.record_attempt(record)
        if stalled is not None or report is None:
            return StopExecution(record=record, freeze_latency_s=walk.freeze_latency_s)
        sealed = SealedStop(
            record=record,
            report=report,
            report_digest=report.report_digest,
            sealed_at=moment,
        )
        self._ledger.record_seal(sealed)
        return StopExecution(
            record=record, sealed=sealed, freeze_latency_s=walk.freeze_latency_s
        )

    async def execute_for_lost_controller(
        self,
        run_id: str,
        *,
        command_id: str,
        principal: str = "mayhem:controller-loss",
        level: CancellationLevel = CancellationLevel.KILL,
        compensation: CompensationPath = CompensationPath.CONTROLLER_RECOVERY,
        now: datetime | None = None,
    ) -> StopExecution:
        """Execute a stop for a run whose controller is gone.

        The reason is ``controller_lost`` and the run state is derived from the
        sink, so this works on a process that shares nothing with the dead one
        but the sink. Pass ``compensation=CompensationPath.AGENT_WATCHDOG`` when
        there is no controller to promote — see :class:`AgentCompensator`.
        """
        command = StopCommand(
            id=command_id,
            scope=StopScope.RUN,
            run_id=run_id,
            principal=principal,
            trigger=StopTrigger.for_signal(
                StopSignal.CONTROLLER_LOST, detail=f"controller for run {run_id} is gone"
            ),
            issued_at=now if now is not None else utc_now(),
        )
        return await self.execute(
            command,
            state=run_state_from_sink(self._sink, run_id),
            level=level,
            compensation=compensation,
            now=now,
        )

    # -- the walk ------------------------------------------------------------

    def _resume(
        self, state: RunState, level: CancellationLevel, completed: tuple[StopStage, ...]
    ) -> StopEscalation:
        """The escalation to resume at, refusing a skip.

        Two refusals, deliberately distinct: a stage the ladder does not owe at
        all (``stop_stage_not_owed``) is a caller naming the wrong game, while an
        owed stage handed over out of order (``stop_stage_skip_refused``) is a
        caller skipping work. Both are mistakes; the difference is which message
        an operator sees at 3am.
        """
        owed = mandatory_stages(state, level)
        done = tuple(StopStage(s) for s in completed)
        for stage in done:
            if stage not in owed:
                msg = (
                    f"stage {stage.value} is not owed at {level} for run state "
                    f"{state.value}; owed: {[s.value for s in owed]}"
                )
                raise InvariantViolationError("stop_stage_not_owed", msg)
        if done != owed[: len(done)]:
            skipped = [stage.value for stage in owed[len(done) :]]
            msg = f"cannot resume with {[s.value for s in done]}: that skips {skipped}"
            raise InvariantViolationError("stop_stage_skip_refused", msg)
        return StopEscalation(state=state, level=level, done=done)

    async def _run_stage(self, stage: StopStage, walk: _Walk) -> None:
        """Dispatch one stage. A ``match`` over the closed enum, so a member added
        to :class:`StopStage` without a handler here is a loud ``TypeError`` at the
        first stop rather than a silently skipped stage."""
        match StopStage(stage):
            case StopStage.FREEZE:
                self._stage_freeze(walk)
            case StopStage.CANCEL_PENDING:
                self._stage_cancel_pending(walk)
            case StopStage.COMPENSATE_ACTIVE:
                await self._stage_compensate(walk)
            case StopStage.RECONCILE:
                self._stage_reconcile(walk)
            case StopStage.RESIDUE_SCAN:
                self._stage_residue_scan(walk)
            case StopStage.VERIFY:
                self._stage_verify(walk)
            case StopStage.SEAL:
                self._stage_seal(walk)

    # -- stages --------------------------------------------------------------

    def _stage_freeze(self, walk: _Walk) -> None:
        ref = self._dispatch.freeze(walk.run_id)
        if not isinstance(ref, str) or not ref.strip():
            msg = (
                f"dispatch freeze for run {walk.run_id} produced no evidence reference; a "
                "freeze that cannot be cited is a freeze that did not happen"
            )
            raise InvariantViolationError("stop_freeze_requires_evidence", msg)
        walk.receipts.append(
            StageReceipt(
                stage=StopStage.FREEZE,
                evidence_ref=ref,
                detail=f"dispatch frozen for run {walk.run_id}",
                observed_at=walk.now,
            )
        )

    def _stage_cancel_pending(self, walk: _Walk) -> None:
        cancelled: list[str] = []
        for lease in leases_for_run(self._sink, walk.run_id):
            if lease.state is not LeaseState.PENDING:
                continue
            # Never injected, so there is nothing to undo: the same terminal the
            # janitor reaches for a pending lease past its deadline, reached here
            # because a stop arrived first.
            self._sink.save(
                lease.transition(
                    LeaseState.EXPIRED,
                    mechanism=STOP_MECHANISM,
                    now=walk.now,
                    escalation_notes=(
                        f"cancelled by stop {walk.command.id} before injection; never injected"
                    ),
                )
            )
            cancelled.append(lease.id)
        for lease_id in cancelled:
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.CANCEL_PENDING,
                    evidence_ref=lease_ref(lease_id),
                    detail=f"lease {lease_id} cancelled before injection; never injected",
                    observed_at=walk.now,
                )
            )
        if not cancelled:
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.CANCEL_PENDING,
                    evidence_ref=stage_ref(walk.run_id, StopStage.CANCEL_PENDING),
                    detail="no pending leases to cancel",
                    observed_at=walk.now,
                )
            )

    async def _stage_compensate(self, walk: _Walk) -> None:
        if walk.compensation is CompensationPath.AGENT_WATCHDOG:
            await self._compensate_agent_side(walk)
            return
        plan = self._recovery.plan((walk.run_id,))
        result = self._recovery.execute(
            plan,
            artifact_dir=self._artifact_dir,
            now_epoch_s=self._compensation_horizon(walk),
        )
        walk.recovery = result
        dirty = set(result.dirty)
        touched = (*result.recovered, *result.expired, *result.dirty)
        for lease_id in touched:
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.COMPENSATE_ACTIVE,
                    evidence_ref=lease_ref(lease_id),
                    detail=(
                        f"recovery state={result.state.value}; mechanism=janitor; outcome="
                        f"{'dirty' if lease_id in dirty else 'settled'}"
                    ),
                    observed_at=walk.now,
                )
            )
        if not touched:
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.COMPENSATE_ACTIVE,
                    evidence_ref=stage_ref(walk.run_id, StopStage.COMPENSATE_ACTIVE),
                    detail="no active leases to compensate",
                    observed_at=walk.now,
                )
            )

    async def _compensate_agent_side(self, walk: _Walk) -> None:
        """Compensate through the agent, and record what the agent reports.

        The controller stays the single writer (ADR-0007): it does not perform the
        undo, it files the outcome the agent's own watchdog reported. A lease the
        agent never held becomes a residue rather than an expiry — reading "I did
        not compensate that" as "compensated" would file a self-compensation
        nobody performed.
        """
        if self._compensator is None:
            msg = (
                "agent-watchdog compensation was requested but no compensator is bound; "
                "without the agent there is nobody to undo the fault"
            )
            raise InvariantViolationError("stop_watchdog_unbound", msg)
        outstanding = tuple(
            lease for lease in leases_for_run(self._sink, walk.run_id) if not lease.is_safe_terminal
        )
        outcomes = await self._compensator.compensate(outstanding)
        reported = {outcome.lease_id for outcome in outcomes}
        for outcome in outcomes:
            lease = self._sink.load(outcome.lease_id)
            settled = (
                outcome.outcome is AgentCompensationOutcome.EXPIRED
                and lease is not None
                and not lease.is_safe_terminal
            )
            if settled and lease is not None:
                self._sink.save(
                    lease.transition(
                        LeaseState.EXPIRED,
                        mechanism="watchdog",
                        now=walk.now,
                        escalation_notes=(
                            f"agent watchdog self-compensated on stop {walk.command.id}"
                        ),
                    )
                )
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.COMPENSATE_ACTIVE,
                    evidence_ref=lease_ref(outcome.lease_id),
                    detail=(
                        f"agent watchdog outcome={outcome.outcome.value}"
                        + (f"; {outcome.detail}" if outcome.detail else "")
                    ),
                    observed_at=walk.now,
                )
            )
        for lease in outstanding:
            if lease.id not in reported:
                walk.findings.append(
                    Residue(
                        kind="lease_not_compensated",
                        target=lease.id,
                        detail=(
                            f"lease {lease.id} is {lease.state.value} and no agent-side "
                            "compensation was reported for it"
                        ),
                    )
                )
        if not outcomes:
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.COMPENSATE_ACTIVE,
                    evidence_ref=stage_ref(walk.run_id, StopStage.COMPENSATE_ACTIVE),
                    detail="agent watchdog held no lease for this run",
                    observed_at=walk.now,
                )
            )

    def _stage_reconcile(self, walk: _Walk) -> None:
        """Compare intent against observation, lease by lease.

        The intent is the recovery plan's view (which leases the run holds and
        what undo contract each carries); the observation is a fresh read of the
        sink. Both are re-derived here rather than remembered, because the whole
        point of the stage is to catch the case where they disagree. The
        ``RecoveryService`` used for the plan is a pure reader over the sink, so
        this stage works on a controller that holds no memory at all.
        """
        plan = self._recovery.plan((walk.run_id,))
        planned = {lease.id for lease in plan.leases}
        for intended in plan.leases:
            current = self._sink.load(intended.id)
            if current is None:
                walk.findings.append(
                    Residue(
                        kind="lease_missing",
                        target=intended.id,
                        detail=(
                            f"stop planned lease {intended.id} (state {intended.state}) but the "
                            "sink no longer holds it"
                        ),
                    )
                )
                continue
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.RECONCILE,
                    evidence_ref=lease_ref(intended.id),
                    detail=(
                        f"intent={intended.state}/{intended.recovery.value} "
                        f"observed={current.state.value}"
                    ),
                    observed_at=walk.now,
                )
            )
        for lease in leases_for_run(self._sink, walk.run_id):
            if lease.id not in planned:
                walk.findings.append(
                    Residue(
                        kind="lease_unplanned",
                        target=lease.id,
                        detail=(
                            f"run {walk.run_id} holds lease {lease.id} ({lease.state.value}) "
                            "that the recovery plan did not name"
                        ),
                    )
                )
        if not plan.leases:
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.RECONCILE,
                    evidence_ref=stage_ref(walk.run_id, StopStage.RECONCILE),
                    detail="recovery plan named no lease for this run",
                    observed_at=walk.now,
                )
            )
        self._reconcile_claims(walk)

    def _reconcile_claims(self, walk: _Walk) -> None:
        """Compare dispatch intent against observation, claim by claim.

        The lease half of :meth:`_stage_reconcile` only sees work that reached
        the write-ahead ledger. A claim the fabric took and never settled is
        intent with no observation anywhere: no lease row to compensate, no
        recovery plan naming it, nothing for the lease-side reconcile to notice.
        With a :class:`ClaimLedger` bound, each of those becomes a
        ``claim_unsettled`` residue finding — which makes the postflight
        ``DIRTY`` and the run unclosable-clean, because an effect mayhem cannot
        account for is not an effect mayhem proved absent.

        Without one bound the stage is unchanged and says nothing about claims:
        mayhem holds no journal, and "no witness" is not "nothing outstanding".
        """
        if self._claims is None:
            return
        observed = {lease.id for lease in leases_for_run(self._sink, walk.run_id)}
        for claim in self._claims.open_claims(walk.run_id):
            walk.findings.append(
                Residue(
                    kind="claim_unsettled",
                    target=claim.command_id,
                    detail=(
                        f"dispatch claim {claim.command_id}"
                        + (f" for step {claim.step_id}" if claim.step_id else "")
                        + (f" under epoch {claim.epoch}" if claim.epoch else "")
                        + " was never settled and owns no lease in the sink: mayhem cannot "
                        "prove whether the effect happened, and cannot prove it did not"
                    ),
                )
            )
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.RECONCILE,
                    evidence_ref=claim.evidence_ref,
                    detail=(
                        f"claim {claim.command_id} reconciled against "
                        f"{len(observed)} lease(s) held by run {walk.run_id}"
                    ),
                    observed_at=walk.now,
                )
            )

    def _stage_residue_scan(self, walk: _Walk) -> None:
        """Look for what the undo missed, beyond the lease states.

        With a scanner bound that is the scanner's word — the other witness. With
        none bound the engine falls back to the only thing it can see for itself:
        a lease the compensation pass did not settle.
        """
        if self._residue is not None:
            found: tuple[Residue, ...] = tuple(self._residue.scan(walk.run_id))
        else:
            found = tuple(
                Residue(
                    kind="lease_unsettled",
                    target=lease.id,
                    detail=f"lease {lease.id} is {lease.state.value} after compensation",
                )
                for lease in leases_for_run(self._sink, walk.run_id)
                if not lease.is_safe_terminal
            )
        for finding in found:
            walk.findings.append(finding)
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.RESIDUE_SCAN,
                    evidence_ref=finding.evidence_ref,
                    detail=finding.describe(),
                    observed_at=walk.now,
                )
            )
        if not found:
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.RESIDUE_SCAN,
                    evidence_ref=stage_ref(walk.run_id, StopStage.RESIDUE_SCAN),
                    detail="residue scan found nothing",
                    observed_at=walk.now,
                )
            )

    def _stage_verify(self, walk: _Walk) -> None:
        """Assert the run could now complete, through the existing gate.

        :func:`~mayhem.domain.leases.assert_all_recovered` is the run-completion
        invariant, so this stage asks that question rather than inventing a
        second one. A refusal is a finding, not a stall: the verification ran,
        and its answer was no.
        """
        leases = list(leases_for_run(self._sink, walk.run_id))
        try:
            assert_all_recovered(leases)
        except InvariantViolationError as exc:
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.VERIFY,
                    evidence_ref=stage_ref(walk.run_id, StopStage.VERIFY),
                    detail=f"run-completion gate refused the run: {exc}",
                    observed_at=walk.now,
                )
            )
            walk.findings.extend(
                Residue(
                    kind="lease_not_recovered",
                    target=lease.id,
                    detail=f"lease {lease.id} is {lease.state.value}",
                )
                for lease in leases
                if not lease.is_safe_terminal
            )
            return
        for lease in sorted(leases, key=lambda item: item.id):
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.VERIFY,
                    evidence_ref=lease_ref(lease.id),
                    detail=f"assert_all_recovered: {lease.id} is {lease.state.value}",
                    observed_at=walk.now,
                )
            )
        if not leases:
            walk.receipts.append(
                StageReceipt(
                    stage=StopStage.VERIFY,
                    evidence_ref=stage_ref(walk.run_id, StopStage.VERIFY),
                    detail="assert_all_recovered: run holds no lease",
                    observed_at=walk.now,
                )
            )

    def _stage_seal(self, walk: _Walk) -> None:
        """Compute the postflight from what the walk observed, then cite it.

        Nothing is authored here: the checks come from the recovery result, the
        findings and the run-completion gate, and the verdict is
        :class:`~mayhem.domain.stop.PostflightReport`'s to recompute.
        """
        report = postflight_report(
            run_id=walk.run_id,
            stop=walk.command.trigger,
            leases=leases_for_run(self._sink, walk.run_id),
            findings=tuple(walk.findings),
            recovery=walk.recovery,
            now=walk.now,
        )
        walk.receipts.append(
            StageReceipt(
                stage=StopStage.SEAL,
                evidence_ref=postflight_ref(walk.run_id, report.report_digest),
                detail=(
                    f"verdict={report.verdict(walk.now).value}; "
                    f"reason={walk.command.reason.value}"
                ),
                observed_at=walk.now,
            )
        )
        walk.report = report

    def _compensation_horizon(self, walk: _Walk) -> float:
        """The instant to sweep at: past every outstanding lease's own deadline.

        The janitor's rule is "past its deadline a fault is unattended", and the
        recovery pass reuses that rule unchanged. An emergency stop asserts the
        deadline has arrived for everything the run still holds, rather than
        editing the TTL policy the janitor enforces.
        """
        deadlines = [
            lease.created_at.timestamp() + float(lease.ttl_seconds)
            for lease in leases_for_run(self._sink, walk.run_id)
        ]
        return max(deadlines, default=walk.now.timestamp()) + 1.0


# =============================================================================
# Phase 4 — the stop, sealed into plan 12's attested chain
# =============================================================================
#
# The ledger above is this module's own operator record. It is not evidence in
# plan 12's sense: it is a mutable table anyone with the database can edit, and
# nothing in it verifies. Phase 4 puts the same four facts into a chain whose
# every link is a SHA-256 over canonical bytes:
#
# * the **stop reason** — which of the six ``StopReason`` members, with the
#   command id, principal, scope, level, and the trigger's detail;
# * the **per-action compensation outcomes** — each lease the compensation pass
#   settled or could not, by id and evidence reference;
# * the **residue scan results** — every finding, by kind, target, and reference;
# * the **postflight verdict** — ``CLEAN``/``DIRTY``/``UNKNOWN`` as the report
#   itself recomputes it, plus the report's digest.
#
# Four properties this half holds, and each is what makes the chain worth
# reading rather than decorative:
#
# 1. **A stalled stop seals too.** :func:`stop_chain_events` emits one event for
#    a stop that never sealed, with ``sealed=false`` and ``verdict=UNKNOWN``.
#    Sealing is a claim that a chain is *complete as a record of what happened*,
#    not that everything went well; a stop that stalled is exactly the thing a
#    reader most needs on the chain, and withholding it would make an unsealed
#    attempt indistinguishable from an attempt that never happened.
# 2. **The verdict is read, never authored.** It is
#    :attr:`StopExecution.verdict`, which is
#    :meth:`~mayhem.domain.stop.PostflightReport.verdict` recomputed from the
#    report's own checks. A caller cannot pass a verdict in, because the payload
#    builder takes a :class:`StopExecution` and nothing else.
# 3. **An empty stop seals nothing.** :func:`stop_chain_events` returns ``()`` for
#    an execution with no record — and a chain of zero events is a chain that
#    proves nothing while looking like one that does.
# 4. **The events are unsealed on the way out.** They are sealed by
#    ``seal_events`` in the writer, so a reader can tell built from written.

#: ``AttestedEvent.event_kind`` for the stop itself: what was asked, and what the
#: ladder did with it.
EVENT_STOP_EXECUTED = "stop.executed"

#: ``AttestedEvent.event_kind`` for the postflight: the per-lease compensation
#: outcomes, the residue findings, and the verdict they produce.
EVENT_STOP_POSTFLIGHT = "stop.postflight"

#: Namespaces the stop chain so it cannot collide with another lane's chain for
#: the same run. ``attestation_chains.run_id`` is a key, not a foreign key, so
#: two lanes sealing the same run must not share a row.
STOP_CHAIN_KEY_SUFFIX = ":stop"


def stop_chain_key(run_id: str) -> str:
    """The ``attestation_chains`` key the stop chain is written under."""
    return f"{run_id}{STOP_CHAIN_KEY_SUFFIX}"


def stop_manifest_id(run_id: str) -> str:
    """The ``attestation_manifests`` id covering the stop chain."""
    return stop_chain_key(run_id)


def stop_evidence_payload(execution: StopExecution) -> dict[str, Any]:
    """Everything about one stop that belongs in evidence, as canonical scalars.

    A pure projection of a :class:`StopExecution` — no store, no clock, no
    re-derivation. Every list is sorted so the same stop seals the same bytes
    twice, and every field is either a scalar or a list of them, because this is
    what gets hashed and a dict-of-dicts would be hashed by a rule nobody could
    later re-state by hand.

    ``verdict`` is included as the enum's *value* alongside the report's digest,
    not instead of them: the digest is what proves *which* report produced the
    verdict, and the value is what a reader reads.
    """
    record = execution.record
    command = record.command
    sealed = execution.sealed
    report = sealed.report if sealed is not None else None
    residue_checks = (
        []
        if report is None
        else [
            {
                "name": check.name,
                "status": check.status.value,
                "evidence_refs": sorted(check.evidence_refs),
                "detail": check.detail,
            }
            for check in report.checks
            if check.name.startswith("residue:")
        ]
    )
    recovery_check = None
    if report is not None:
        recovery_check = next(
            (check for check in report.checks if check.name == "recovery:leases_recovered"), None
        )
    return {
        "run_id": execution.run_id,
        "command_id": command.id,
        "scope": command.scope.value,
        "principal": command.principal,
        "reason": record.reason.value,
        "reason_detail": command.trigger.detail,
        "condition_id": command.trigger.condition_id,
        "level": record.level.value,
        "state": record.state.value,
        "compensation_path": record.compensation.value,
        "sealed": sealed is not None,
        "completed_stages": [stage.value for stage in record.completed_stages],
        "carried_stages": [stage.value for stage in record.carried_stages],
        "outstanding_stages": [stage.value for stage in record.outstanding],
        "stalled_at": "" if record.stalled_at is None else record.stalled_at.value,
        "stall_reason": record.stall_reason,
        "receipts": [
            {
                "stage": receipt.stage.value,
                "evidence_ref": receipt.evidence_ref,
                "detail": receipt.detail,
                "observed_at": receipt.observed_at.isoformat(),
            }
            for receipt in record.receipts
        ],
        # Per-action compensation outcomes: one entry per lease the recovery pass
        # had an opinion about, cited by the same reference the postflight cites.
        "compensated_leases": (
            []
            if recovery_check is None
            else sorted(recovery_check.evidence_refs)
        ),
        "compensation_detail": "" if recovery_check is None else recovery_check.detail,
        "residue_checks": residue_checks,
        "verdict": execution.verdict.value,
        "recovery_verified": execution.recovered,
        "report_digest": sealed.report_digest if sealed is not None else "",
        "evidence_ref": (
            postflight_ref(execution.run_id, sealed.report_digest)
            if sealed is not None
            else stage_ref(execution.run_id, StopStage.SEAL)
        ),
        "freeze_latency_s": execution.freeze_latency_s,
    }


def stop_chain_events(
    execution: StopExecution, *, recorded_at: AttestedTimestamp
) -> tuple[AttestedEvent, ...]:
    """The unsealed chain events for one stop, in order (pure).

    One ``stop.executed`` event and one ``stop.postflight`` event. The second is
    emitted for a stalled stop as well, with the postflight fields empty and the
    verdict ``UNKNOWN`` — the record of "this stop did not get far enough to
    produce a postflight" belongs in the chain, because its absence is
    indistinguishable from never having tried.

    Returns ``()`` for an execution with no record, so a caller can seal
    unconditionally and write no empty chain.
    """
    if not execution.record.command.id:
        return ()
    run_id = execution.run_id
    executed = AttestedEvent(
        event_id=f"{run_id}:stop:{execution.record.command.id}",
        event_kind=EVENT_STOP_EXECUTED,
        run_id=run_id,
        sequence=0,
        payload=stop_evidence_payload(execution),
        recorded_at=recorded_at,
    )
    postflight = AttestedEvent(
        event_id=f"{run_id}:stop-postflight:{execution.record.command.id}",
        event_kind=EVENT_STOP_POSTFLIGHT,
        run_id=run_id,
        sequence=1,
        payload=stop_postflight_payload(execution),
        recorded_at=recorded_at,
    )
    return (executed, postflight)


def stop_postflight_payload(execution: StopExecution) -> dict[str, Any]:
    """The postflight half on its own: verdict, obligations, and the report digest.

    Separate from :func:`stop_evidence_payload` because the postflight is the part
    a reader opens a stop to find, and burying it inside a larger event would make
    it quotable only by parsing something else.
    """
    payload = stop_evidence_payload(execution)
    return {
        key: payload[key]
        for key in (
            "run_id",
            "command_id",
            "reason",
            "sealed",
            "compensated_leases",
            "residue_checks",
            "verdict",
            "recovery_verified",
            "report_digest",
            "evidence_ref",
        )
    }
