"""Distributed stop execution — the engine that acts a command (plan 10, Phase 2).

The engine's own claims are small and each has a test that would fail if the
claim were dropped:

* the walk is the Phase 1 ladder, in order, and a resume that skips a stage is
  refused rather than repaired;
* a stop that cannot reach the agent is still *recorded*, names the stage it
  stalled at, and is not sealed;
* the controller-loss path works from the lease sink alone — the drill deletes
  the first controller object outright before a second one finishes the stop and
  seals ``controller_lost``;
* with no controller at all, the agent's own ``AgentWatchdog`` compensates
  through the real undo contract, and the lease ends ``EXPIRED`` with
  ``release_mechanism="watchdog"``;
* a fired ``Condition`` reaches the sealed reason with its cited samples intact;
* the postflight is computed from the recovery output, and a residue finding
  keeps the run dirty;
* a stop for a finished run is rejected, and an environment-wide command that
  names a run is unrepresentable.

Timestamps are injected everywhere, so nothing here depends on the wall clock.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mayhem.agents.executors import ProcPauseExecutor, StepOutcome
from mayhem.agents.sinks import InMemoryLeaseSink
from mayhem.agents.watchdog import AgentWatchdog
from mayhem.controller.recovery import (
    RecoveryExecutionResult,
    RecoveryPlan,
    RecoveryService,
    RecoveryState,
)
from mayhem.controller.stop_engine import (
    AgentCompensationOutcome,
    AgentCompensator,
    Compensated,
    CompensationPath,
    Residue,
    SealedStop,
    StageReceipt,
    StopEngine,
    StopRecord,
    WatchdogLike,
    command_for_firing,
    lease_ref,
    leases_for_run,
    observed_values_for,
    postflight_ref,
    postflight_report,
    residue_ref,
    run_state_from_sink,
    stage_ref,
    trigger_for_firing,
)
from mayhem.domain.cancellation import CancellationLevel
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.observations import ObservationResult
from mayhem.domain.steady_state import AbsoluteExpect
from mayhem.domain.stop import (
    STOP_FLOW,
    ObservedValue,
    PostflightVerdict,
    RunState,
    StopCommand,
    StopReason,
    StopScope,
    StopStage,
    StopTrigger,
)
from mayhem.domain.stop_conditions import Condition, Sample, Threshold

MOMENT = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
RUN_ID = "run-1"

# -- fakes ---------------------------------------------------------------------------


class FrozenDispatch:
    """A dispatch surface that fences and hands back a receipt, or refuses to."""

    def __init__(self, ref: str | None = "dispatch/run-1/epoch-7") -> None:
        self._ref = ref
        self.calls: list[str] = []
        self.raise_with: Exception | None = None

    def freeze(self, run_id: str) -> str:
        self.calls.append(run_id)
        if self.raise_with is not None:
            raise self.raise_with
        assert self._ref is not None
        return self._ref


@dataclass
class MemoryLedger:
    """The durable stop record store, stood in for by a list."""

    attempts_made: list[StopRecord] = field(default_factory=list)
    seals_made: list[SealedStop] = field(default_factory=list)

    def record_attempt(self, record: StopRecord) -> None:
        self.attempts_made.append(record)

    def record_seal(self, sealed: SealedStop) -> None:
        self.seals_made.append(sealed)

    def attempts(self, run_id: str) -> tuple[StopRecord, ...]:
        return tuple(r for r in self.attempts_made if r.command.run_id == run_id)

    def seal(self, run_id: str) -> SealedStop | None:
        return self.seals_made[-1] if self.seals_made else None


class BrokenRecovery:
    """A recovery pass that cannot run — the controller died mid-compensation."""

    def plan(self, *args: Any, **kwargs: Any) -> RecoveryPlan:
        return RecoveryPlan(run_ids=(RUN_ID,), target_profiles=(), state=RecoveryState.NOT_NEEDED)

    def execute(self, *args: Any, **kwargs: Any) -> RecoveryExecutionResult:
        msg = "controller process gone; no recovery pass can run"
        raise RuntimeError(msg)


class ScriptedResidue:
    def __init__(self, findings: tuple[Residue, ...]) -> None:
        self._findings = findings
        self.calls: list[str] = []

    def scan(self, run_id: str) -> tuple[Residue, ...]:
        self.calls.append(run_id)
        return self._findings


class UndoTrackingExecutor(ProcPauseExecutor):
    """The real proc executor's shape, with an undo that only records."""

    def __init__(self, *, ok: bool = True) -> None:
        super().__init__()
        self.undo_calls: list[FaultLease] = []
        self._ok = ok

    def undo(self, lease: FaultLease) -> StepOutcome:
        self.undo_calls.append(lease)
        return StepOutcome("undo", self._ok, f"undone={lease.id}")


@dataclass
class WatchdogCompensator:
    """Drives the *real* :class:`AgentWatchdog` as the agent-side last resort."""

    watchdog: WatchdogLike
    executor: UndoTrackingExecutor
    now_epoch_s: float = 1_000.0

    async def compensate(self, leases: tuple[FaultLease, ...]) -> tuple[Compensated, ...]:
        for lease in leases:
            self.watchdog.register(
                lease_id=lease.id,
                lease=lease,
                executor=self.executor,
                ttl_seconds=0.0,
                now_epoch_s=self.now_epoch_s - 1.0,
            )
        await self.watchdog.sweep(now_epoch_s=self.now_epoch_s)
        outcomes: list[Compensated] = []
        for lease in leases:
            state = self.watchdog.final_state(lease.id)
            if state is None:
                outcome = AgentCompensationOutcome.UNKNOWN
            elif state == "expired":
                outcome = AgentCompensationOutcome.EXPIRED
            else:
                outcome = AgentCompensationOutcome.DIRTY
            outcomes.append(
                Compensated(lease_id=lease.id, outcome=outcome, detail=f"watchdog={state}")
            )
        return tuple(outcomes)


# -- fixtures -----------------------------------------------------------------------


def make_lease(
    lease_id: str = "l-1",
    *,
    run_id: str = RUN_ID,
    state: LeaseState = LeaseState.ACTIVE,
    ttl: float = 3600.0,
    age_s: float = 30.0,
) -> FaultLease:
    """A lease with the write-ahead undo contract every real lease carries."""
    lease = FaultLease(
        id=lease_id,
        run_id=run_id,
        fault_id="proc.pause",
        owner_agent="agent-1",
        targets=frozenset({"api"}),
        undo_ops=(UndoOp(op="signal", args={"target": "api"}),),
        verify_probes=(VerifyProbe(probe="exec", args={"cmd": "true"}),),
        ttl_seconds=ttl,
        state=LeaseState.PENDING,
        created_at=MOMENT - timedelta(seconds=age_s),
    )
    if state is LeaseState.PENDING:
        return lease
    return lease.transition(LeaseState.ACTIVE, now=MOMENT - timedelta(seconds=age_s - 1))


def build_engine(
    sink: InMemoryLeaseSink,
    *,
    dispatch: FrozenDispatch | None = None,
    ledger: MemoryLedger | None = None,
    recovery: object | None = None,
    residue: ScriptedResidue | None = None,
    compensator: AgentCompensator | None = None,
) -> tuple[StopEngine, MemoryLedger, FrozenDispatch]:
    chosen_ledger = ledger if ledger is not None else MemoryLedger()
    chosen_dispatch = dispatch if dispatch is not None else FrozenDispatch()
    engine = StopEngine(
        sink=sink,
        recovery=recovery if recovery is not None else RecoveryService(sink),  # type: ignore[arg-type]
        dispatch=chosen_dispatch,
        ledger=chosen_ledger,
        residue=residue,
        compensator=compensator,
    )
    return engine, chosen_ledger, chosen_dispatch


def operator_command(**kwargs: Any) -> StopCommand:
    payload: dict[str, Any] = {
        "id": "sc-1",
        "scope": StopScope.RUN,
        "run_id": RUN_ID,
        "principal": "operator:ana",
        "trigger": StopTrigger(reason=StopReason.HUMAN, detail="operator pressed stop"),
        "issued_at": MOMENT,
    }
    payload.update(kwargs)
    return StopCommand.model_validate(payload)


def condition_command(**kwargs: Any) -> StopCommand:
    payload: dict[str, Any] = {
        "id": "sc-2",
        "scope": StopScope.RUN,
        "run_id": RUN_ID,
        "principal": "detector:slo",
        "trigger": StopTrigger(
            reason=StopReason.CONDITION_FIRED, condition_id="api.latency", detail="fired"
        ),
        "issued_at": MOMENT,
    }
    payload.update(kwargs)
    return StopCommand.model_validate(payload)


# -- the full walk -------------------------------------------------------------------


class TestFullWalk:
    @pytest.mark.asyncio
    async def test_walks_every_stage_of_the_flow_in_order(self) -> None:
        """The KILL-level walk on a RUNNING run is the plan's flow, verbatim."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease("l-1"))
        sink.save(make_lease("l-2"))
        engine, ledger, _ = build_engine(sink)

        result = await engine.execute(operator_command(), now=MOMENT)

        assert result.record.completed_stages == STOP_FLOW
        assert result.stalled_at is None
        assert result.record.outstanding == ()
        assert result.record.sealed
        assert [r.stage for r in result.record.receipts] == sorted(
            (r.stage for r in result.record.receipts), key=STOP_FLOW.index
        )
        assert len(ledger.seals_made) == 1
        assert ledger.seal(RUN_ID) is result.sealed

    @pytest.mark.asyncio
    async def test_freeze_reaches_the_dispatch_surface_before_anything_else(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, dispatch = build_engine(sink, dispatch=FrozenDispatch(ref="fabric/fence-42"))

        result = await engine.execute(operator_command(), now=MOMENT)

        assert dispatch.calls == [RUN_ID]
        assert [r.evidence_ref for r in result.record.receipts_for(StopStage.FREEZE)] == [
            "fabric/fence-42"
        ]

    @pytest.mark.asyncio
    async def test_pending_leases_are_cancelled_and_never_compensated(self) -> None:
        """A lease that was never injected has nothing to undo; it is expired."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease("l-pending", state=LeaseState.PENDING))
        sink.save(make_lease("l-active"))
        engine, _, _ = build_engine(sink)

        await engine.execute(operator_command(), now=MOMENT)

        cancelled = sink.load("l-pending")
        assert cancelled is not None
        assert cancelled.state is LeaseState.EXPIRED
        assert cancelled.release_mechanism == "stop"
        assert "never injected" in str(cancelled.escalation_notes)
        assert cancelled.released_at == MOMENT
        # ... and the active one went through the janitor, not the stop's own path.
        active = sink.load("l-active")
        assert active is not None
        assert active.state is LeaseState.RELEASED
        assert active.release_mechanism == "janitor"

    @pytest.mark.asyncio
    async def test_every_completed_stage_leaves_an_evidence_receipt(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)

        result = await engine.execute(operator_command(), now=MOMENT)

        for stage in result.record.completed_stages:
            receipts = result.record.receipts_for(stage)
            assert receipts, f"{stage.value} completed with no receipt"
            assert all(r.evidence_ref.strip() for r in receipts)

    @pytest.mark.asyncio
    async def test_stages_with_nothing_to_name_cite_the_stage_itself(self) -> None:
        """The weakest reference is explicit, not silent."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)

        result = await engine.execute(operator_command(), now=MOMENT)

        residue_receipt = result.record.receipts_for(StopStage.RESIDUE_SCAN)
        assert [r.evidence_ref for r in residue_receipt] == [
            stage_ref(RUN_ID, StopStage.RESIDUE_SCAN)
        ]

    @pytest.mark.asyncio
    async def test_a_pending_run_walks_only_what_it_owes(self) -> None:
        """A run holding nothing walks freeze -> cancel_pending -> seal, and seals."""
        sink = InMemoryLeaseSink()
        engine, _, _ = build_engine(sink)

        result = await engine.execute(operator_command(), state=RunState.PENDING, now=MOMENT)

        assert result.record.completed_stages == (
            StopStage.FREEZE,
            StopStage.CANCEL_PENDING,
            StopStage.SEAL,
        )
        assert result.sealed is not None
        assert result.verdict is PostflightVerdict.CLEAN

    @pytest.mark.asyncio
    async def test_a_clean_run_state_from_the_sink_is_pending_not_running(self) -> None:
        sink = InMemoryLeaseSink()
        assert run_state_from_sink(sink, RUN_ID) is RunState.PENDING
        sink.save(make_lease())
        assert run_state_from_sink(sink, RUN_ID) is RunState.RUNNING
        assert leases_for_run(sink, RUN_ID) == (sink.load("l-1"),)


# -- stage skipping ------------------------------------------------------------------


class TestStageSkippingRefused:
    @pytest.mark.asyncio
    async def test_resuming_past_a_mandatory_stage_is_refused(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, ledger, _ = build_engine(sink)

        with pytest.raises(InvariantViolationError) as refusal:
            await engine.execute(
                operator_command(),
                completed=(StopStage.FREEZE, StopStage.COMPENSATE_ACTIVE),
                now=MOMENT,
            )

        assert refusal.value.rule == "stop_stage_skip_refused"
        assert ledger.attempts_made == []

    @pytest.mark.asyncio
    async def test_resuming_at_seal_alone_is_refused(self) -> None:
        """ "Already sealed" is the most tempting lie, so it is named explicitly."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)

        with pytest.raises(InvariantViolationError) as refusal:
            await engine.execute(operator_command(), completed=(StopStage.SEAL,), now=MOMENT)

        assert refusal.value.rule == "stop_stage_skip_refused"
        assert "compensate_active" in str(refusal.value)

    @pytest.mark.asyncio
    async def test_resuming_with_a_stage_the_ladder_does_not_owe_is_refused(self) -> None:
        sink = InMemoryLeaseSink()
        engine, _, _ = build_engine(sink)

        with pytest.raises(InvariantViolationError) as refusal:
            await engine.execute(
                operator_command(),
                state=RunState.PENDING,
                completed=(StopStage.COMPENSATE_ACTIVE,),
                now=MOMENT,
            )

        assert refusal.value.rule == "stop_stage_not_owed"

    @pytest.mark.asyncio
    async def test_a_genuine_prefix_resume_completes_the_rest(self) -> None:
        """The refusal above is about skipping, not about resuming."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)

        result = await engine.execute(
            operator_command(),
            completed=(StopStage.FREEZE, StopStage.CANCEL_PENDING),
            now=MOMENT,
        )

        assert result.record.completed_stages == STOP_FLOW
        # The inherited stages are named as carried, and no receipt is invented
        # for them: their evidence lives on the earlier attempt's record.
        assert result.record.carried_stages == (StopStage.FREEZE, StopStage.CANCEL_PENDING)
        assert result.record.receipts_for(StopStage.FREEZE) == ()
        assert result.sealed is not None

    def test_a_record_whose_stages_are_not_a_prefix_is_refused(self) -> None:
        payload = {
            "command": operator_command(),
            "state": RunState.RUNNING,
            "level": CancellationLevel.KILL,
            "compensation": CompensationPath.CONTROLLER_RECOVERY,
            "started_at": MOMENT,
            "finished_at": MOMENT,
            "completed_stages": (StopStage.CANCEL_PENDING, StopStage.SEAL),
            "receipts": (
                StageReceipt(stage=StopStage.CANCEL_PENDING, evidence_ref=lease_ref("l-1")),
                StageReceipt(stage=StopStage.SEAL, evidence_ref="postflight/run-1/d"),
            ),
        }
        with pytest.raises(InvariantViolationError) as refusal:
            StopRecord.model_validate(payload)
        assert refusal.value.rule == "stop_record_stage_prefix"

    def test_a_record_cannot_mark_a_stage_done_without_evidence(self) -> None:
        """A resume that skips a stage is refused; so is one that fakes one."""
        payload = {
            "command": operator_command(),
            "state": RunState.RUNNING,
            "level": CancellationLevel.KILL,
            "compensation": CompensationPath.CONTROLLER_RECOVERY,
            "started_at": MOMENT,
            "finished_at": MOMENT,
            "completed_stages": (StopStage.FREEZE,),
            "receipts": (),
        }
        with pytest.raises(InvariantViolationError) as refusal:
            StopRecord.model_validate(payload)
        assert refusal.value.rule == "stop_record_stage_requires_receipt"

    def test_carried_stages_must_be_stages_the_walk_actually_completed(self) -> None:
        """Inherited evidence is named, never assumed."""
        payload = {
            "command": operator_command(),
            "state": RunState.PENDING,
            "level": CancellationLevel.GRACE,
            "compensation": CompensationPath.CONTROLLER_RECOVERY,
            "started_at": MOMENT,
            "finished_at": MOMENT,
            "completed_stages": (StopStage.FREEZE,),
            "carried_stages": (StopStage.CANCEL_PENDING,),
            "receipts": (),
        }
        with pytest.raises(InvariantViolationError) as refusal:
            StopRecord.model_validate(payload)
        assert refusal.value.rule == "stop_record_carried_not_completed"


# -- a stage that cannot complete ----------------------------------------------------


class TestStalledStops:
    @pytest.mark.asyncio
    async def test_a_stage_that_cannot_complete_is_reported_not_skipped(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        dispatch = FrozenDispatch()
        dispatch.raise_with = RuntimeError("fabric unreachable")
        engine, ledger, _ = build_engine(sink, dispatch=dispatch)

        result = await engine.execute(operator_command(), now=MOMENT)

        assert result.stalled_at is StopStage.FREEZE
        assert result.record.completed_stages == ()
        assert "fabric unreachable" in result.record.stall_reason
        assert result.record.outstanding == STOP_FLOW
        assert result.sealed is None
        assert result.verdict is PostflightVerdict.UNKNOWN
        assert len(ledger.attempts_made) == 1
        assert ledger.seals_made == []

    @pytest.mark.asyncio
    async def test_the_stall_names_the_stage_it_stalled_at(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink, recovery=BrokenRecovery())

        result = await engine.execute(operator_command(), now=MOMENT)

        assert result.stalled_at is StopStage.COMPENSATE_ACTIVE
        assert result.record.stall_reason.startswith("compensate_active: RuntimeError")
        assert result.record.completed_stages == (StopStage.FREEZE, StopStage.CANCEL_PENDING)
        assert result.record.outstanding == (
            StopStage.COMPENSATE_ACTIVE,
            StopStage.RECONCILE,
            StopStage.RESIDUE_SCAN,
            StopStage.VERIFY,
            StopStage.SEAL,
        )

    @pytest.mark.asyncio
    async def test_evidence_emitted_before_a_stall_is_kept(self) -> None:
        """Which leases were settled is the part an operator can act on."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease("l-1"))
        sink.save(make_lease("l-2"))
        engine, _, _ = build_engine(sink, recovery=BrokenRecovery())

        result = await engine.execute(operator_command(), now=MOMENT)

        # Freeze and cancel_pending both completed; compensation is what failed.
        assert [r.stage for r in result.record.receipts] == [
            StopStage.FREEZE,
            StopStage.CANCEL_PENDING,
        ]
        assert result.stalled_at is StopStage.COMPENSATE_ACTIVE

    @pytest.mark.asyncio
    async def test_a_freeze_with_no_evidence_reference_stalls_the_stop(self) -> None:
        """A freeze that cannot be cited is a freeze that did not happen."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink, dispatch=FrozenDispatch(ref="   "))

        result = await engine.execute(operator_command(), now=MOMENT)

        assert result.stalled_at is StopStage.FREEZE
        assert "stop_freeze_requires_evidence" in result.record.stall_reason

    def test_a_stalled_record_cannot_be_sealed(self) -> None:
        """Sealing claims every mandatory stage ran; a stall refutes that."""
        stalled = StopRecord(
            command=operator_command(),
            state=RunState.PENDING,
            level=CancellationLevel.GRACE,
            compensation=CompensationPath.CONTROLLER_RECOVERY,
            started_at=MOMENT,
            finished_at=MOMENT,
            completed_stages=(StopStage.FREEZE,),
            stalled_at=StopStage.CANCEL_PENDING,
            stall_reason="cancel_pending: RuntimeError: sink write failed",
            receipts=(StageReceipt(stage=StopStage.FREEZE, evidence_ref="dispatch/run-1/epoch-7"),),
        )
        report = postflight_report(
            run_id=RUN_ID, stop=stalled.command.trigger, leases=(), findings=(), now=MOMENT
        )
        with pytest.raises(InvariantViolationError) as refusal:
            SealedStop(
                record=stalled,
                report=report,
                report_digest=report.report_digest,
                sealed_at=MOMENT,
            )
        assert refusal.value.rule == "stop_seal_requires_complete_walk"

    def test_a_seal_whose_digest_disagrees_with_its_report_is_refused(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease("l-1"))
        ledger = MemoryLedger()
        engine, _, _ = build_engine(sink, ledger=ledger)
        result = asyncio.run(engine.execute(operator_command(), now=MOMENT))
        assert result.sealed is not None
        with pytest.raises(InvariantViolationError) as refusal:
            SealedStop(
                record=result.record,
                report=result.sealed.report,
                report_digest="0" * 64,
                sealed_at=MOMENT,
            )
        assert refusal.value.rule == "stop_seal_digest_mismatch"


# -- controller loss -----------------------------------------------------------------


class TestControllerKillDrill:
    @pytest.mark.asyncio
    async def test_controller_killed_mid_fault_still_seals_controller_lost(self) -> None:
        """The drill: the controller dies mid-compensation and a fresh one finishes.

        The first controller is *deleted*, not just ignored: nothing it held in
        memory is available afterwards, and the run still stops and seals. The
        lease sink is the whole rendezvous.
        """
        sink = InMemoryLeaseSink()
        sink.save(make_lease("l-1"))
        ledger = MemoryLedger()

        # Controller A: freezes, then dies trying to compensate.
        controller_a, _, _ = build_engine(sink, ledger=ledger, recovery=BrokenRecovery())
        first = await controller_a.execute(operator_command(), now=MOMENT)
        assert first.stalled_at is StopStage.COMPENSATE_ACTIVE
        del controller_a

        # Controller B: a new object, same sink, same ledger, no shared memory.
        controller_b, _, _ = build_engine(sink, ledger=ledger)
        sealed = await controller_b.execute_for_lost_controller(
            RUN_ID, command_id="sc-standby", now=MOMENT
        )

        assert sealed.sealed is not None
        assert sealed.reason is StopReason.CONTROLLER_LOST
        assert sealed.stalled_at is None
        assert sealed.record.compensation is CompensationPath.CONTROLLER_RECOVERY
        assert sealed.verdict is PostflightVerdict.CLEAN
        assert sealed.recovered
        lease = sink.load("l-1")
        assert lease is not None and lease.is_safe_terminal
        # The dead controller's stalled attempt is still on file: nothing lost.
        assert [r.stalled_at for r in ledger.attempts(RUN_ID)] == [
            StopStage.COMPENSATE_ACTIVE,
            None,
        ]
        assert ledger.seal(RUN_ID) is sealed.sealed

    @pytest.mark.asyncio
    async def test_the_stopped_run_reads_as_nothing_outstanding_afterwards(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)

        await engine.execute_for_lost_controller(RUN_ID, command_id="sc-1", now=MOMENT)

        assert run_state_from_sink(sink, RUN_ID) is RunState.PENDING
        assert leases_for_run(sink, RUN_ID)[0].is_safe_terminal

    @pytest.mark.asyncio
    async def test_the_sealed_reason_names_controller_lost_in_the_report_too(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)

        result = await engine.execute_for_lost_controller(RUN_ID, command_id="sc-1", now=MOMENT)

        assert result.sealed is not None
        assert result.sealed.report.stop_reason is StopReason.CONTROLLER_LOST
        assert result.sealed.report.stop.describe() == "controller_lost"


class TestWatchdogFallback:
    @pytest.mark.asyncio
    async def test_agent_watchdog_compensates_when_no_controller_exists(self) -> None:
        """The last resort: the agent undoes its own fault through its watchdog."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease("l-1"))
        executor = UndoTrackingExecutor()
        watchdog: WatchdogLike = AgentWatchdog()
        compensator: AgentCompensator = WatchdogCompensator(watchdog=watchdog, executor=executor)
        engine, _, _ = build_engine(sink, compensator=compensator)

        result = await engine.execute_for_lost_controller(
            RUN_ID,
            command_id="sc-watchdog",
            compensation=CompensationPath.AGENT_WATCHDOG,
            now=MOMENT,
        )

        # The real undo contract ran: the executor was asked to undo this lease.
        assert [lease.id for lease in executor.undo_calls] == ["l-1"]
        lease = sink.load("l-1")
        assert lease is not None
        assert lease.state is LeaseState.EXPIRED
        assert lease.release_mechanism == "watchdog"
        assert result.record.compensation is CompensationPath.AGENT_WATCHDOG
        assert result.reason is StopReason.CONTROLLER_LOST
        assert result.verdict is PostflightVerdict.CLEAN
        assert result.sealed is not None and result.sealed.recovery_verified

    @pytest.mark.asyncio
    async def test_a_watchdog_that_cannot_undo_leaves_the_run_dirty(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease("l-1"))
        compensator: AgentCompensator = WatchdogCompensator(
            watchdog=AgentWatchdog(), executor=UndoTrackingExecutor(ok=False)
        )
        engine, _, _ = build_engine(sink, compensator=compensator)

        result = await engine.execute_for_lost_controller(
            RUN_ID,
            command_id="sc-watchdog",
            compensation=CompensationPath.AGENT_WATCHDOG,
            now=MOMENT,
        )

        lease = sink.load("l-1")
        assert lease is not None and lease.state is LeaseState.ACTIVE
        assert result.verdict is PostflightVerdict.DIRTY
        assert not result.recovered
        assert result.sealed is not None
        failed = {c.name for c in result.sealed.report.failed_checks}
        assert "verify:run_completion_gate" in failed
        assert "residue:lease_not_recovered:l-1" in failed

    @pytest.mark.asyncio
    async def test_a_lease_the_watchdog_never_held_is_a_residue_not_a_claim(self) -> None:
        """Reading "unknown" as compensated would claim an undo nobody performed."""

        class ForgetfulCompensator:
            async def compensate(self, leases: tuple[FaultLease, ...]) -> tuple[Compensated, ...]:
                return ()

        sink = InMemoryLeaseSink()
        sink.save(make_lease("l-1"))
        engine, _, _ = build_engine(sink, compensator=ForgetfulCompensator())

        result = await engine.execute_for_lost_controller(
            RUN_ID,
            command_id="sc-watchdog",
            compensation=CompensationPath.AGENT_WATCHDOG,
            now=MOMENT,
        )

        assert sink.load("l-1").state is LeaseState.ACTIVE  # type: ignore[union-attr]
        assert result.verdict is PostflightVerdict.DIRTY
        assert result.sealed is not None
        assert result.sealed.report.check("residue:lease_not_compensated:l-1") is not None

    @pytest.mark.asyncio
    async def test_asking_for_the_watchdog_path_with_no_watchdog_stalls_the_stage(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)

        result = await engine.execute_for_lost_controller(
            RUN_ID,
            command_id="sc-watchdog",
            compensation=CompensationPath.AGENT_WATCHDOG,
            now=MOMENT,
        )

        assert result.stalled_at is StopStage.COMPENSATE_ACTIVE
        assert "stop_watchdog_unbound" in result.record.stall_reason
        assert result.sealed is None


# -- condition-fired reasons ---------------------------------------------------------


def fired_condition_result() -> Any:
    """A real condition, evaluated over real samples, that really fires.

    ``for_samples=2`` makes the firing cite *two* readings of the same metric, so
    the sample->observation projection is exercised where it is hardest: one
    metric name, two instants.
    """
    condition = Condition.metric(
        "latency_ms",
        Threshold(expect=AbsoluteExpect(lte=250.0)),
        name="api.latency",
        for_samples=2,
    )
    samples = [
        Sample(ObservationResult(metric="latency_ms", value=value, unit="ms", window_s=10.0), at)
        for at, value in ((0.0, 100.0), (1.0, 400.0), (2.0, 450.0))
    ]
    return condition.evaluate(samples, now_epoch_s=2.0)


class TestConditionFiredReason:
    def test_a_firing_becomes_a_condition_fired_trigger_citing_its_samples(self) -> None:
        firing = fired_condition_result().to_firing()

        trigger = trigger_for_firing(firing)

        assert trigger.reason is StopReason.CONDITION_FIRED
        assert trigger.condition_id == "api.latency"
        assert [v.name for v in trigger.observed_values] == ["latency_ms@1", "latency_ms@2"]
        assert [v.value for v in trigger.observed_values] == ["400", "450"]
        assert trigger.observed_values[1].unit == "ms"
        # The cited readings are the firing's own samples, not a re-read.
        assert [s.value for s in firing.samples] == [400.0, 450.0]

    def test_two_readings_of_one_metric_stay_two_observations(self) -> None:
        """The sample *is* the evidence, so it cannot be collapsed by name."""
        firing = fired_condition_result().to_firing()

        trigger = trigger_for_firing(firing)

        assert len(trigger.observed_values) == firing.sample_count == 2
        assert len({v.name for v in trigger.observed_values}) == 2

    def test_a_command_for_a_firing_carries_the_whole_chain(self) -> None:
        firing = fired_condition_result().to_firing()

        command = command_for_firing(
            firing, command_id="sc-fired", run_id=RUN_ID, principal="detector:slo", now=MOMENT
        )

        assert command.reason is StopReason.CONDITION_FIRED
        assert command.trigger.condition_id == "api.latency"
        assert command.issued_at == MOMENT

    @pytest.mark.asyncio
    async def test_the_cited_samples_reach_the_sealed_reason(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)
        command = command_for_firing(
            fired_condition_result().to_firing(),
            command_id="sc-fired",
            run_id=RUN_ID,
            principal="detector:slo",
            now=MOMENT,
        )

        result = await engine.execute(command, now=MOMENT)

        assert result.sealed is not None
        report = result.sealed.report
        assert report.stop_reason is StopReason.CONDITION_FIRED
        assert report.stop.condition_id == "api.latency"
        assert [v.name for v in report.stop.observed_values] == ["latency_ms@1", "latency_ms@2"]
        assert [v.value for v in report.stop.observed_values] == ["400", "450"]
        assert "condition_fired:api.latency" in report.stop.describe()

    @pytest.mark.asyncio
    async def test_the_firing_is_the_only_route_to_this_reason(self) -> None:
        """A hand-written condition id with no cited samples never reaches a seal."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)

        result = await engine.execute(condition_command(), now=MOMENT)

        assert result.sealed is not None
        assert result.sealed.report.stop.observed_values == ()
        assert result.sealed.report.stop.describe() == "condition_fired:api.latency"


# -- postflight ---------------------------------------------------------------------


def released_lease(lease_id: str = "l-1") -> FaultLease:
    lease = make_lease(lease_id)
    assert lease.state is LeaseState.ACTIVE
    return lease.transition(LeaseState.RELEASING, now=MOMENT).transition(
        LeaseState.RELEASED, mechanism="janitor", now=MOMENT
    )


def recovery_result(
    *, recovered: tuple[str, ...], dirty: tuple[str, ...] = ()
) -> RecoveryExecutionResult:
    state = RecoveryState.DIRTY if dirty else RecoveryState.RECOVERED
    return RecoveryExecutionResult(state=state, run_ids=(RUN_ID,), recovered=recovered, dirty=dirty)


class TestPostflightIsComputed:
    def test_a_settled_run_with_no_findings_is_clean(self) -> None:
        report = postflight_report(
            run_id=RUN_ID,
            stop=operator_command().trigger,
            leases=(released_lease(),),
            findings=(),
            recovery=recovery_result(recovered=("l-1",)),
            now=MOMENT,
        )

        assert report.verdict(MOMENT) is PostflightVerdict.CLEAN
        assert report.recovery_verified(MOMENT)
        assert [c.name for c in report.checks] == [
            "recovery:leases_recovered",
            "residue:scan",
            "verify:run_completion_gate",
        ]

    def test_a_residue_finding_keeps_the_run_dirty(self) -> None:
        """The Phase 5 acceptance rule, enforced by construction."""
        report = postflight_report(
            run_id=RUN_ID,
            stop=operator_command().trigger,
            leases=(released_lease(),),
            findings=(Residue(kind="qdisc_present", target="api.eth0"),),
            recovery=recovery_result(recovered=("l-1",)),
            now=MOMENT,
        )

        assert report.verdict(MOMENT) is PostflightVerdict.DIRTY
        assert not report.recovery_verified(MOMENT)
        finding = report.check("residue:qdisc_present:api.eth0")
        assert finding is not None
        assert finding.evidence_refs == ("residue/qdisc_present/api.eth0",)

    def test_an_unsettled_lease_fails_the_run_completion_gate(self) -> None:
        report = postflight_report(
            run_id=RUN_ID,
            stop=operator_command().trigger,
            leases=(make_lease("l-open"),),
            findings=(),
            recovery=recovery_result(recovered=()),
            now=MOMENT,
        )

        assert report.verdict(MOMENT) is PostflightVerdict.DIRTY
        gate = report.check("verify:run_completion_gate")
        assert gate is not None
        assert gate.evidence_refs == (lease_ref("l-open"),)

    def test_a_lease_the_recovery_pass_reports_but_never_settled_is_dirty(self) -> None:
        """The recovery output is evidence, not a promise the report repeats."""
        report = postflight_report(
            run_id=RUN_ID,
            stop=operator_command().trigger,
            leases=(make_lease("l-open"),),
            findings=(),
            recovery=recovery_result(recovered=("l-open",)),
            now=MOMENT,
        )

        assert report.verdict(MOMENT) is PostflightVerdict.DIRTY

    def test_evidence_that_has_aged_out_is_unknown_not_clean(self) -> None:
        report = postflight_report(
            run_id=RUN_ID,
            stop=operator_command().trigger,
            leases=(released_lease(),),
            findings=(),
            recovery=recovery_result(recovered=("l-1",)),
            now=MOMENT,
        )

        assert report.verdict(MOMENT) is PostflightVerdict.CLEAN
        assert report.verdict(MOMENT + timedelta(days=1)) is PostflightVerdict.UNKNOWN

    def test_the_same_finding_from_two_probes_is_one_finding(self) -> None:
        report = postflight_report(
            run_id=RUN_ID,
            stop=operator_command().trigger,
            leases=(released_lease(),),
            findings=(
                Residue(kind="qdisc_present", target="api.eth0", detail="first probe"),
                Residue(kind="qdisc_present", target="api.eth0", detail="second probe"),
            ),
            now=MOMENT,
        )

        assert [c.name for c in report.checks if c.name.startswith("residue:qdisc")] == [
            "residue:qdisc_present:api.eth0"
        ]
        assert report.verdict(MOMENT) is PostflightVerdict.DIRTY

    def test_no_recovery_pass_means_no_recovery_check_not_a_clean_one(self) -> None:
        report = postflight_report(
            run_id=RUN_ID,
            stop=operator_command().trigger,
            leases=(released_lease(),),
            findings=(),
            now=MOMENT,
        )

        assert [c.name for c in report.checks] == ["residue:scan", "verify:run_completion_gate"]

    def test_a_generation_time_must_be_aware(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            postflight_report(
                run_id=RUN_ID,
                stop=operator_command().trigger,
                leases=(),
                findings=(),
                now=datetime(2026, 9, 30, 12, 0),  # noqa: DTZ001
            )
        assert refusal.value.rule == "postflight_generated_at_aware"

    @pytest.mark.asyncio
    async def test_a_stalled_stop_has_no_postflight_and_no_verdict_of_recovery(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink, recovery=BrokenRecovery())

        result = await engine.execute(operator_command(), now=MOMENT)

        assert result.report is None
        assert result.verdict is PostflightVerdict.UNKNOWN
        assert not result.recovered

    @pytest.mark.asyncio
    async def test_residue_found_after_a_clean_undo_still_dirties_the_run(self) -> None:
        """The lease can read RELEASED while the qdisc is still on the wire."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        scanner = ScriptedResidue(
            (Residue(kind="qdisc_present", target="api.eth0", detail="tc qdisc still attached"),)
        )
        engine, _, _ = build_engine(sink, residue=scanner)

        result = await engine.execute(operator_command(), now=MOMENT)

        assert scanner.calls == [RUN_ID]
        lease = sink.load("l-1")
        assert lease is not None and lease.state is LeaseState.RELEASED
        assert result.verdict is PostflightVerdict.DIRTY
        assert result.sealed is not None
        assert result.sealed.report.check("residue:qdisc_present:api.eth0") is not None


# -- negative controls ---------------------------------------------------------------


class TestNegativeControls:
    @pytest.mark.parametrize("state", [RunState.FINISHED, RunState.STOPPED])
    @pytest.mark.asyncio
    async def test_a_stop_for_a_finished_run_is_rejected(self, state: RunState) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, ledger, dispatch = build_engine(sink)

        with pytest.raises(InvariantViolationError) as refusal:
            await engine.execute(operator_command(), state=state, now=MOMENT)

        assert refusal.value.rule == "stop_for_terminal_run"
        # Refused before anything was touched.
        assert dispatch.calls == []
        assert ledger.attempts_made == []
        assert sink.load("l-1").state is LeaseState.ACTIVE  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_a_derived_state_cannot_see_a_run_the_sink_calls_finished(self) -> None:
        """The documented limit of the controller-loss path, asserted not hidden.

        Once every lease is settled the sink can no longer distinguish "stopped"
        from "never injected", so ``run_state_from_sink`` returns ``PENDING`` and
        a controller-loss stop for an already-stopped run walks the short flow
        instead of refusing. The caller that *knows* the run is stopped passes
        ``state=``, and that is refused.
        """
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)
        await engine.execute(operator_command(), now=MOMENT)

        assert run_state_from_sink(sink, RUN_ID) is RunState.PENDING
        with pytest.raises(InvariantViolationError) as refusal:
            await engine.execute(
                operator_command(id="sc-again"), state=RunState.STOPPED, now=MOMENT
            )
        assert refusal.value.rule == "stop_for_terminal_run"

    def test_an_environment_wide_stop_cannot_name_a_run(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            StopCommand.model_validate(
                {
                    "id": "sc-env",
                    "scope": StopScope.ENVIRONMENT,
                    "environment": "prod-eu-west",
                    "run_id": RUN_ID,
                    "principal": "operator:ana",
                    "trigger": StopTrigger(reason=StopReason.HUMAN),
                    "issued_at": MOMENT,
                }
            )
        assert refusal.value.rule == "environment_scope_has_no_run_id"

    @pytest.mark.asyncio
    async def test_the_engine_refuses_an_environment_wide_command(self) -> None:
        sink = InMemoryLeaseSink()
        engine, ledger, _ = build_engine(sink)
        environment_wide = StopCommand(
            id="sc-env",
            scope=StopScope.ENVIRONMENT,
            environment="prod-eu-west",
            principal="operator:ana",
            trigger=StopTrigger(reason=StopReason.HUMAN),
            issued_at=MOMENT,
        )

        with pytest.raises(InvariantViolationError) as refusal:
            await engine.execute(environment_wide, now=MOMENT)

        assert refusal.value.rule == "stop_engine_requires_run_scope"
        assert ledger.attempts_made == []

    @pytest.mark.asyncio
    async def test_a_stop_with_no_evidence_is_unsealable(self) -> None:
        """The record refuses to call a stage done with no receipt behind it."""
        payload = {
            "command": operator_command(),
            "state": RunState.PENDING,
            "level": CancellationLevel.GRACE,
            "compensation": CompensationPath.CONTROLLER_RECOVERY,
            "started_at": MOMENT,
            "finished_at": MOMENT,
            "completed_stages": (StopStage.FREEZE, StopStage.CANCEL_PENDING, StopStage.SEAL),
            "receipts": (),
        }
        with pytest.raises(InvariantViolationError) as refusal:
            StopRecord.model_validate(payload)
        assert refusal.value.rule == "stop_record_stage_requires_receipt"

    def test_a_seal_over_a_record_with_no_receipts_is_refused(self) -> None:
        """Defence in depth: a no-evidence stop is refused before it can seal.

        The record's own validator fires first (pydantic re-validates the nested
        model), which is the point: the seal rule is the second line, not the
        only one.
        """
        bare = StopRecord.model_construct(
            command=operator_command(),
            state=RunState.PENDING,
            level=CancellationLevel.GRACE,
            compensation=CompensationPath.CONTROLLER_RECOVERY,
            started_at=MOMENT,
            finished_at=MOMENT,
            completed_stages=(StopStage.FREEZE, StopStage.CANCEL_PENDING, StopStage.SEAL),
            receipts=(),
        )
        report = postflight_report(
            run_id=RUN_ID, stop=bare.command.trigger, leases=(), findings=(), now=MOMENT
        )
        with pytest.raises(InvariantViolationError) as refusal:
            SealedStop(
                record=bare, report=report, report_digest=report.report_digest, sealed_at=MOMENT
            )
        assert refusal.value.rule == "stop_record_stage_requires_receipt"
        assert not bare.sealed or bare.receipts == ()

    @pytest.mark.asyncio
    async def test_a_stale_command_is_refused(self) -> None:
        """A stale emergency stop acts on a world that has since changed."""
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, ledger, dispatch = build_engine(sink)

        with pytest.raises(InvariantViolationError) as refusal:
            await engine.execute(
                operator_command(ttl_seconds=60.0), now=MOMENT + timedelta(hours=1)
            )

        assert refusal.value.rule == "stop_command_stale"
        assert dispatch.calls == []
        assert ledger.attempts_made == []

    def test_a_receipt_must_cite_something(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            StageReceipt(stage=StopStage.FREEZE, evidence_ref="  ")
        assert refusal.value.rule == "stage_receipt_requires_evidence_ref"

    def test_a_receipt_must_be_observed_at_an_aware_instant(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            StageReceipt(
                stage=StopStage.FREEZE,
                evidence_ref="dispatch/run-1/e",
                observed_at=datetime(2026, 9, 30, 12, 0),  # noqa: DTZ001
            )
        assert refusal.value.rule == "stage_receipt_observed_at_aware"

    def test_a_residue_must_name_what_was_found(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Residue(kind="qdisc_present", target="  ")
        assert refusal.value.rule == "residue_field_not_blank"

    def test_a_record_that_did_not_stall_cannot_carry_a_stall_reason(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            StopRecord(
                command=operator_command(),
                state=RunState.PENDING,
                level=CancellationLevel.GRACE,
                compensation=CompensationPath.CONTROLLER_RECOVERY,
                started_at=MOMENT,
                finished_at=MOMENT,
                completed_stages=(StopStage.FREEZE,),
                stall_reason="something went wrong somewhere",
                receipts=(StageReceipt(stage=StopStage.FREEZE, evidence_ref="dispatch/run-1/e"),),
            )
        assert refusal.value.rule == "stop_record_stall_reason_unexpected"

    def test_the_ledger_is_a_seam_the_engine_cannot_do_without(self) -> None:
        """The engine is handed a ledger object, not a global.

        Two engines over one sink but two ledgers record into two different
        places — the record store is a collaborator, so a caller cannot lose a
        stop by forgetting to configure one.
        """
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, ledger, _ = build_engine(sink)
        assert isinstance(engine, StopEngine)

        other = MemoryLedger()
        other_engine, _, _ = build_engine(sink, ledger=other)
        asyncio.run(other_engine.execute(operator_command(), now=MOMENT))

        assert ledger.attempts_made == []
        assert len(other.attempts_made) == 1
        assert other.seal(RUN_ID) is not None


# -- the surface stays honest --------------------------------------------------------


class TestEngineReporting:
    def test_the_evidence_reference_vocabulary_is_prefixed_by_what_it_cites(self) -> None:
        """The shapes are pinned: a receipt says what it points at."""
        assert lease_ref("l-1") == "lease/l-1"
        assert stage_ref(RUN_ID, StopStage.RESIDUE_SCAN) == "run/run-1/residue_scan"
        assert residue_ref("qdisc_present", "api.eth0") == "residue/qdisc_present/api.eth0"
        assert postflight_ref(RUN_ID, "abc") == "postflight/run-1/abc"
        assert Residue(kind="qdisc_present", target="api.eth0").evidence_ref == (
            "residue/qdisc_present/api.eth0"
        )

    def test_a_sink_without_all_leases_is_read_through_active_leases(self) -> None:
        """A bare LeaseSink still works; it just cannot see settled leases."""

        class MinimalSink:
            def __init__(self, leases: tuple[FaultLease, ...]) -> None:
                self._leases = leases

            def save(self, lease: FaultLease) -> None:
                pass

            def load(self, lease_id: str) -> FaultLease | None:
                return next((x for x in self._leases if x.id == lease_id), None)

            def active_leases(self) -> tuple[FaultLease, ...]:
                return tuple(x for x in self._leases if not x.is_safe_terminal)

            def next_sequence(self) -> int:
                return 0

        active = make_lease("l-1")
        settled = released_lease("l-2")
        sink = MinimalSink((active, settled))

        assert leases_for_run(sink, RUN_ID) == (active,)
        assert run_state_from_sink(sink, RUN_ID) is RunState.RUNNING

    def test_observed_values_carry_the_sample_unit_and_instant(self) -> None:
        firing = fired_condition_result().to_firing()

        values = observed_values_for(firing)

        assert [v.describe() for v in values] == ["latency_ms@1=400ms", "latency_ms@2=450ms"]

    @pytest.mark.asyncio
    async def test_a_sealed_stop_describes_its_reason_and_verdict(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink)

        result = await engine.execute(operator_command(), now=MOMENT)

        assert result.describe() == (f"run {RUN_ID} stop sc-1 reason=human verdict=clean sealed")

    @pytest.mark.asyncio
    async def test_a_stalled_stop_describes_where_it_stopped(self) -> None:
        sink = InMemoryLeaseSink()
        sink.save(make_lease())
        engine, _, _ = build_engine(sink, recovery=BrokenRecovery())

        result = await engine.execute(operator_command(), now=MOMENT)

        assert "verdict=unknown" in result.describe()
        assert "stalled at compensate_active" in result.describe()

    def test_a_stale_receipt_would_not_pass_the_postflight_ttl_by_accident(self) -> None:
        """The report is reproducible from itself, then ages honestly."""
        report = postflight_report(
            run_id=RUN_ID,
            stop=operator_command().trigger,
            leases=(released_lease(),),
            findings=(),
            now=MOMENT,
        )
        assert (
            report.report_digest
            == postflight_report(
                run_id=RUN_ID,
                stop=operator_command().trigger,
                leases=(released_lease(),),
                findings=(),
                now=MOMENT,
            ).report_digest
        )
        assert report.verdict(MOMENT) is PostflightVerdict.CLEAN
        assert report.verdict(MOMENT + timedelta(hours=1)) is PostflightVerdict.UNKNOWN
        assert ObservedValue(name="x", value="1").describe() == "x=1"
