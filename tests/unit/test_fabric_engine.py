"""Tests for the distributed dispatch engine (v1.1.0 plan 03, Phase 2).

Phase 1's acceptance was a *type* property, so its tests are negative controls
on construction. This phase's acceptance is a *behaviour* property — "controller
failover cannot produce two owners executing the same step" — so these tests are
negative controls on dispatch: a deposed owner, a replayed envelope, a superseded
plan, a second effect at one epoch, and a provider that reports success about an
object the plan never named must each be refused or normalised, loudly, with
nothing reaching a provider.

The controller-kill drill is the load-bearing one and it is a drill, not a
docstring: a dispatch is made, the engine object is *deleted*, a brand-new engine
is constructed over the same durable rows and the same lease sink, and the
assertions are about what the newcomer can see and what it must refuse. A fresh
:class:`FabricEngine` is correct on a cold start precisely because the engine
holds no dispatch state of its own.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from mayhem.agents.lease_client import LeaseClient
from mayhem.agents.sinks import InMemoryLeaseSink
from mayhem.controller.fabric_engine import (
    FABRIC_DUPLICATE_DISPATCH,
    FABRIC_INFLIGHT_UNRESOLVED,
    DispatchClaim,
    DispatchRequest,
    DispatchResult,
    DispatchSettlement,
    FabricEngine,
    ProviderResult,
    normalise_provider_result,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.fabric import (
    FABRIC_PLAN_MISMATCH,
    FABRIC_PROTOCOL_VERSION,
    FABRIC_REPLAYED_NONCE,
    FABRIC_RESERVATION_EXPIRED,
    FABRIC_RESOURCE_CONFLICT,
    FABRIC_STALE_FENCE,
    FABRIC_UNDERSIGNED,
    CommandBodyRef,
    FabricCommand,
    FabricCommandRefused,
    FabricCommandType,
    FencingToken,
    Reservation,
    StepSemantics,
    StepSpec,
)
from mayhem.domain.leases import (
    FaultLease,
    LeaseState,
    UndoOp,
    VerifyProbe,
    assert_all_recovered,
)
from mayhem.domain.outcomes import StepOutcome, TargetOutcome

if TYPE_CHECKING:
    from mayhem.controller.fabric_engine import JournalEntry

RUN_ID = "r-fabric-2"
STEP_ID = "s-1"
PLAN_DIGEST = "a" * 64
SUPERSEDED_PLAN_DIGEST = "b" * 64
BODY_DIGEST = "c" * 64
SIGNATURE = "sig" * 8
TARGET = "pod/web-0"
OTHER_TARGET = "pod/web-1"

NOW = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
LATER = NOW + timedelta(seconds=30)


class ControllerKilled(BaseException):
    """Stands in for the controller process dying mid-dispatch.

    A ``BaseException`` on purpose: the engine normalises ``Exception`` into a
    step outcome, and a process that is being killed must not be catchable there.
    """


class _Clock:
    def __init__(self, moment: datetime = NOW) -> None:
        self.moment = moment

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment = self.moment + timedelta(seconds=seconds)


class DurableLog:
    """The rows a real SQLite-backed journal would keep.

    Shared by every controller generation in a drill, and never held by an
    engine: this object is the durable store, not controller memory.
    """

    def __init__(self) -> None:
        self.rows: list[JournalEntry] = []


class RecordingJournal:
    """In-memory :class:`~mayhem.controller.fabric_engine.FabricJournal` fake.

    Args:
        log: The durable rows to append to.
        crash_on_settlement: 1-based index of the settlement append that kills the
            controller (0 disables it). A kill happens *before* the row lands,
            which is exactly what a process death mid-append looks like.
    """

    def __init__(self, log: DurableLog, *, crash_on_settlement: int = 0) -> None:
        self._log = log
        self._crash_on = crash_on_settlement
        self._settlements = 0

    def append(self, entry: JournalEntry) -> None:
        if isinstance(entry, DispatchSettlement):
            self._settlements += 1
            if self._settlements == self._crash_on:
                raise ControllerKilled("controller died while settling a dispatch")
        self._log.rows.append(entry)

    def entries(self, run_id: str, step_id: str | None = None) -> tuple[JournalEntry, ...]:
        return tuple(
            row
            for row in self._log.rows
            if row.run_id == run_id and (step_id is None or row.step_id == step_id)
        )


class RecordingSession:
    """A controller-initiated session that replays a scripted provider.

    ``calls`` is the evidence for every idempotency claim: an assertion that a
    retry did not re-run the provider is an assertion about this list.
    """

    def __init__(self, *results: ProviderResult | BaseException) -> None:
        self._queue: list[ProviderResult | BaseException] = list(results)
        self.calls: list[FabricCommand] = []

    def dispatch(self, command: FabricCommand) -> ProviderResult:
        self.calls.append(command)
        if not self._queue:
            raise AssertionError(f"provider was dispatched unexpectedly: {command.command_id}")
        nxt = self._queue.pop(0)
        if isinstance(nxt, BaseException):
            raise nxt
        return nxt


def _nonce(index: int) -> str:
    return f"{index:032x}"


def _fence(epoch: int = 1, *, holder: str = "agent-1", step_id: str = STEP_ID) -> FencingToken:
    return FencingToken(
        run_id=RUN_ID,
        step_id=step_id,
        holder=holder,
        epoch=epoch,
        issued_at=NOW,
        supersedes_epoch=epoch - 1 if epoch > 1 else None,
    )


def _body(ref: str = "blob-1", digest: str = BODY_DIGEST) -> CommandBodyRef:
    return CommandBodyRef(
        command_type=FabricCommandType.INJECT,
        body_digest=digest,
        body_ref=ref,
    )


def _command(
    *,
    epoch: int = 1,
    nonce: int = 1,
    key: str = "idem-1",
    command_id: str = "fc-1",
    plan_digest: str = PLAN_DIGEST,
    step_id: str = STEP_ID,
    holder: str = "agent-1",
) -> FabricCommand:
    return FabricCommand(
        protocol=FABRIC_PROTOCOL_VERSION,
        command_id=command_id,
        run_id=RUN_ID,
        step_id=step_id,
        agent_id="agent-1",
        plan_digest=plan_digest,
        nonce=_nonce(nonce),
        idempotency_key=key,
        fencing_token=_fence(epoch, holder=holder, step_id=step_id),
        command=_body(),
        issued_at=NOW,
        signing_key_id="key-1",
        signature=SIGNATURE,
    )


def _step(step_id: str = STEP_ID) -> StepSpec:
    return StepSpec(step_id=step_id, semantic=StepSemantics.SERIAL, issued_at=NOW)


def _request(
    command: FabricCommand | None = None, **overrides: object
) -> DispatchRequest:
    envelope = command if command is not None else _command()
    fields: dict[str, object] = {
        "step": _step(envelope.step_id),
        "command": envelope,
        "current_plan_digest": PLAN_DIGEST,
        "expected_target": TARGET,
    }
    fields.update(overrides)
    return DispatchRequest.model_validate(fields)


def _lease(
    lease_id: str = "l-1",
    *,
    run_id: str = RUN_ID,
    owner: str = "agent-1",
    state: LeaseState = LeaseState.PENDING,
) -> FaultLease:
    return FaultLease(
        id=lease_id,
        run_id=run_id,
        fault_id="net.latency",
        owner_agent=owner,
        targets=frozenset({TARGET}),
        undo_ops=(UndoOp(op="tc.qdisc_add", args={"if": "eth0"}),),
        verify_probes=(VerifyProbe(probe="tc.qdisc_absent", args={"if": "eth0"}),),
        state=state,
        created_at=NOW,
    )


def _reservation(
    *,
    resource: str = "node/worker-3",
    epoch: int = 1,
    step_id: str = STEP_ID,
    holder: str = "agent-1",
    ttl_seconds: float = 120.0,
    acquired_at: datetime = NOW,
) -> Reservation:
    return Reservation(
        resource_id=resource,
        run_id=RUN_ID,
        step_id=step_id,
        holder=holder,
        fencing_token=_fence(epoch, holder=holder, step_id=step_id),
        ttl_seconds=ttl_seconds,
        acquired_at=acquired_at,
    )


def _engine(
    session: RecordingSession,
    journal: RecordingJournal,
    sink: InMemoryLeaseSink,
    *,
    controller_id: str = "ctl-a",
    clock: _Clock | None = None,
) -> FabricEngine:
    return FabricEngine(
        session=session,
        journal=journal,
        lease_sink=sink,
        controller_id=controller_id,
        clock=clock or _Clock(),
    )


def _applied(lease: FaultLease | None = None, *, target: str | None = TARGET) -> ProviderResult:
    return ProviderResult(ok=True, detail="qdisc added", target_ref=target, lease=lease)


def _served_epoch(engine: FabricEngine, step_id: str = STEP_ID) -> int:
    """The ownership record as a plain number (asserting a fence exists)."""
    fence = engine.served_fence(RUN_ID, step_id)
    assert fence is not None, f"step '{step_id}' has never been claimed"
    return fence.epoch


def _served_fence(engine: FabricEngine, step_id: str = STEP_ID) -> FencingToken:
    fence = engine.served_fence(RUN_ID, step_id)
    assert fence is not None, f"step '{step_id}' has never been claimed"
    return fence


# --- fencing ------------------------------------------------------------------


class TestFencing:
    def test_first_dispatch_is_served_and_serves_its_fence(self) -> None:
        journal = RecordingJournal(DurableLog())
        sink = InMemoryLeaseSink()
        session = RecordingSession(_applied())
        engine = _engine(session, journal, sink)

        result = engine.dispatch(_request())

        assert result.ok is True
        assert result.epoch == 1
        assert _served_epoch(engine) == 1
        assert [claim.controller_id for claim in engine.claims(RUN_ID)] == ["ctl-a"]

    def test_deposed_owner_is_refused_by_name_and_never_reaches_the_provider(self) -> None:
        log = DurableLog()
        journal = RecordingJournal(log)
        sink = InMemoryLeaseSink()
        successor_session = RecordingSession(_applied())
        successor = _engine(successor_session, journal, sink, controller_id="ctl-b")
        # ctl-b takes the step over at epoch 2 …
        successor.dispatch(_request(_command(epoch=2, nonce=1, key="idem-b", command_id="fc-b")))

        # … so ctl-a's late epoch-1 command is a deposed owner.
        session_a = RecordingSession(_applied())
        engine_a = _engine(session_a, RecordingJournal(log), sink, controller_id="ctl-a")
        with pytest.raises(FabricCommandRefused) as excinfo:
            engine_a.dispatch(_request(_command(epoch=1, nonce=2, key="idem-a", command_id="fc-a")))

        assert excinfo.value.code == FABRIC_STALE_FENCE
        assert excinfo.value.details["step_id"] == STEP_ID
        assert session_a.calls == []
        assert len(successor_session.calls) == 1  # only the successor's own dispatch

    def test_two_owners_cannot_both_dispatch_the_same_step(self) -> None:
        journal = RecordingJournal(DurableLog())
        sink = InMemoryLeaseSink()
        first = RecordingSession(_applied())
        _engine(first, journal, sink, controller_id="ctl-a").dispatch(_request())

        second_session = RecordingSession(_applied())
        second = _engine(second_session, journal, sink, controller_id="ctl-b")
        with pytest.raises(FabricCommandRefused) as excinfo:
            second.dispatch(_request(_command(nonce=2, key="idem-2", command_id="fc-2")))

        assert excinfo.value.code == FABRIC_DUPLICATE_DISPATCH
        assert excinfo.value.details["epoch"] == 1
        assert second_session.calls == []

    def test_a_new_owner_succeeds_under_a_newer_epoch(self) -> None:
        journal = RecordingJournal(DurableLog())
        sink = InMemoryLeaseSink()
        _engine(RecordingSession(_applied()), journal, sink).dispatch(_request())

        session_b = RecordingSession(_applied())
        engine_b = _engine(session_b, journal, sink, controller_id="ctl-b")
        result = engine_b.dispatch(
            _request(_command(epoch=2, nonce=2, key="idem-2", command_id="fc-2"))
        )

        assert result.ok is True
        assert result.epoch == 2
        assert len(session_b.calls) == 1
        assert _served_epoch(engine_b) == 2

    def test_epochs_advance_monotonically_across_successive_owners(self) -> None:
        journal = RecordingJournal(DurableLog())
        sink = InMemoryLeaseSink()
        served: list[int] = []
        fence = _fence(1)
        for generation in range(1, 4):
            # The only supported way to grow an epoch is next_fence, so a
            # succession in the test is the same operation a failover performs.
            if generation > 1:
                fence = fence.next_fence(holder=f"agent-{generation}")
            engine = _engine(
                RecordingSession(_applied()),
                journal,
                sink,
                controller_id=f"ctl-{generation}",
            )
            engine.dispatch(
                _request(
                    _command(
                        epoch=generation,
                        nonce=generation,
                        key=f"idem-{generation}",
                        command_id=f"fc-{generation}",
                        holder=f"agent-{generation}",
                    )
                )
            )
            served.append(_served_epoch(engine))

        assert served == [1, 2, 3]
        # Every claim in the log is at or after the one before it, and the
        # owners are distinct — the log is the ownership record.
        claims = engine.claims(RUN_ID)
        epochs = [claim.command.fencing_token.epoch for claim in claims]
        assert epochs == sorted(epochs) == [1, 2, 3]
        assert [claim.controller_id for claim in claims] == ["ctl-1", "ctl-2", "ctl-3"]

    def test_an_older_epoch_arriving_late_is_refused_after_a_newer_claim(self) -> None:
        log = DurableLog()
        journal = RecordingJournal(log)
        sink = InMemoryLeaseSink()
        _engine(RecordingSession(_applied()), journal, sink).dispatch(_request())
        _engine(
            RecordingSession(_applied()),
            journal,
            sink,
            controller_id="ctl-b",
        ).dispatch(_request(_command(epoch=2, nonce=2, key="idem-2", command_id="fc-2")))

        # Epoch 1 was never seen by the previous owner, and must still lose.
        late = _engine(RecordingSession(_applied()), journal, sink, controller_id="ctl-c")
        with pytest.raises(FabricCommandRefused) as excinfo:
            late.dispatch(_request(_command(nonce=3, key="idem-3", command_id="fc-3")))

        assert excinfo.value.code == FABRIC_STALE_FENCE

    def test_a_fence_for_another_step_does_not_own_this_one(self) -> None:
        journal = RecordingJournal(DurableLog())
        engine = _engine(RecordingSession(_applied()), journal, InMemoryLeaseSink())
        # s-1 is served at epoch 9 …
        engine.dispatch(_request(_command(epoch=9, nonce=9, key="idem-9", command_id="fc-9")))
        # … which must not authorise a claim on s-2, whose own scope is separate.
        other = _command(epoch=1, nonce=10, key="idem-10", command_id="fc-10", step_id="s-2")
        assert other.fencing_token.step_id == "s-2"
        result = engine.dispatch(_request(other))
        assert result.step_id == "s-2"
        assert _served_epoch(engine, "s-2") == 1
        assert _served_epoch(engine) == 9

    def test_a_command_naming_another_step_is_an_invariant_violation(self) -> None:
        engine = _engine(
            RecordingSession(_applied()), RecordingJournal(DurableLog()), InMemoryLeaseSink()
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.dispatch(_request(_command(), step=_step("s-2")))
        assert excinfo.value.rule == "fabric_command_scope"


# --- idempotent retries --------------------------------------------------------


class TestIdempotentRetries:
    def test_retry_with_the_same_key_and_a_fresh_nonce_serves_the_recorded_outcome(self) -> None:
        journal = RecordingJournal(DurableLog())
        sink = InMemoryLeaseSink()
        session = RecordingSession(_applied(lease=_lease("l-1")))
        engine = _engine(session, journal, sink)

        first = engine.dispatch(_request())
        retry = engine.dispatch(
            _request(_command(nonce=2, key="idem-1", command_id="fc-retry"))
        )

        assert retry.retried is True
        assert retry.outcome is first.outcome is StepOutcome.COMPLETED
        assert retry.command_id == "fc-retry"
        # The whole point: a retry is not a second effect.
        assert len(session.calls) == 1
        # …and it reports the effect that already happened, lease included.
        assert retry.lease_id == "l-1"
        assert len(engine.settlements(RUN_ID, STEP_ID)) == 2

    def test_a_retry_spends_its_own_fresh_nonce(self) -> None:
        journal = RecordingJournal(DurableLog())
        engine = _engine(
            RecordingSession(_applied(), _applied()),
            journal,
            InMemoryLeaseSink(),
        )
        engine.dispatch(_request())
        engine.dispatch(_request(_command(nonce=2, command_id="fc-2")))

        ledger = engine.nonce_ledger(RUN_ID, STEP_ID)
        assert ledger.knows(_nonce(1))
        assert ledger.knows(_nonce(2))

    def test_a_replayed_nonce_is_refused_even_under_a_new_command_id(self) -> None:
        journal = RecordingJournal(DurableLog())
        session = RecordingSession(_applied())
        engine = _engine(session, journal, InMemoryLeaseSink())
        engine.dispatch(_request())

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(_command(nonce=1, command_id="fc-laundered")))

        assert excinfo.value.code == FABRIC_REPLAYED_NONCE
        assert len(session.calls) == 1

    def test_a_replayed_nonce_is_refused_even_when_its_key_already_settled(self) -> None:
        journal = RecordingJournal(DurableLog())
        engine = _engine(RecordingSession(_applied()), journal, InMemoryLeaseSink())
        engine.dispatch(_request())

        # Same key (a legitimate retry shape) but the nonce is spent: the replay
        # guard runs before the idempotency short-circuit, so a replay can never
        # launder itself into a free ride.
        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(_command(nonce=1, command_id="fc-2")))

        assert excinfo.value.code == FABRIC_REPLAYED_NONCE
        assert len(engine.claims(RUN_ID, STEP_ID)) == 1

    def test_a_different_key_at_the_same_epoch_is_a_duplicate_not_a_retry(self) -> None:
        journal = RecordingJournal(DurableLog())
        engine = _engine(RecordingSession(_applied()), journal, InMemoryLeaseSink())
        engine.dispatch(_request())

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(_command(nonce=2, key="idem-2", command_id="fc-2")))

        assert excinfo.value.code == FABRIC_DUPLICATE_DISPATCH

    def test_an_unsettled_claim_blocks_a_second_effect_of_the_same_key(self) -> None:
        log = DurableLog()
        dying = RecordingJournal(log, crash_on_settlement=1)
        sink = InMemoryLeaseSink()
        session = RecordingSession(_applied(lease=_lease("l-1")))
        with pytest.raises(ControllerKilled):
            _engine(session, dying, sink).dispatch(_request())

        resumed_session = RecordingSession(_applied())
        resumed = _engine(resumed_session, RecordingJournal(log), sink, controller_id="ctl-b")
        with pytest.raises(FabricCommandRefused) as excinfo:
            resumed.dispatch(_request(_command(nonce=2, command_id="fc-2")))

        assert excinfo.value.code == FABRIC_INFLIGHT_UNRESOLVED
        assert resumed_session.calls == []

    def test_settle_claim_closes_the_window_and_a_retry_then_serves_the_record(self) -> None:
        log = DurableLog()
        with pytest.raises(ControllerKilled):
            _engine(
                RecordingSession(_applied(lease=_lease("l-1"))),
                RecordingJournal(log, crash_on_settlement=1),
                InMemoryLeaseSink(),
            ).dispatch(_request())

        sink = InMemoryLeaseSink()
        # A cold-start controller: new object, new journal handle, same rows.
        resumed = _engine(RecordingSession(), RecordingJournal(log), sink, controller_id="ctl-b")
        settlement = resumed.settle_claim(
            RUN_ID,
            STEP_ID,
            outcome=StepOutcome.FAILED,
            target_outcome=TargetOutcome.FAILED_TO_APPLY,
            detail="compensated after the crash",
        )
        assert settlement.command_id == "fc-1"
        assert resumed.open_claims(RUN_ID, STEP_ID) == ()

        session = RecordingSession()
        retry = _engine(session, RecordingJournal(log), sink, controller_id="ctl-b").dispatch(
            _request(_command(nonce=2, command_id="fc-2"))
        )
        assert retry.retried is True
        assert retry.outcome is StepOutcome.FAILED
        assert retry.detail.endswith("compensated after the crash")
        assert session.calls == []

    def test_settling_a_claim_that_is_not_open_is_an_invariant_violation(self) -> None:
        engine = _engine(
            RecordingSession(_applied()), RecordingJournal(DurableLog()), InMemoryLeaseSink()
        )
        engine.dispatch(_request())
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.settle_claim(RUN_ID, STEP_ID, outcome=StepOutcome.FAILED)
        assert excinfo.value.rule == "fabric_no_open_claim"


# --- provider-error normalisation ---------------------------------------------


_NORMALISATION_MATRIX: tuple[tuple[ProviderResult, StepOutcome, TargetOutcome | None], ...] = (
    # ok, target as planned
    (ProviderResult(ok=True, detail="applied", target_ref=TARGET), StepOutcome.COMPLETED, None),
    # ok, but the object the provider touched is not the object the plan named
    (
        ProviderResult(ok=True, detail="applied", target_ref=OTHER_TARGET),
        StepOutcome.TARGET_DRIFT,
        TargetOutcome.TARGET_DRIFT,
    ),
    # the target is simply gone
    (
        ProviderResult(ok=False, error_code="no_such_container", detail="container vanished"),
        StepOutcome.TARGET_DRIFT,
        TargetOutcome.TARGET_DRIFT,
    ),
    (
        ProviderResult(ok=False, error_code="pod_replaced", detail="uid changed"),
        StepOutcome.TARGET_DRIFT,
        TargetOutcome.TARGET_DRIFT,
    ),
    # contention on a present target
    (
        ProviderResult(ok=False, error_code="container_busy", detail="another op in flight"),
        StepOutcome.FAILED,
        TargetOutcome.RESOURCE_CONFLICT,
    ),
    # capability/permission/mutation failure on a present target
    (
        ProviderResult(ok=False, error_code="permission_denied", detail="needs NET_ADMIN"),
        StepOutcome.FAILED,
        TargetOutcome.FAILED_TO_APPLY,
    ),
    # an unrecognised code is a failure to apply, not an invented category
    (
        ProviderResult(ok=False, detail="something broke"),
        StepOutcome.FAILED,
        TargetOutcome.FAILED_TO_APPLY,
    ),
    # drift outranks a conflicting code: a moved target is drift either way
    (
        ProviderResult(
            ok=False, error_code="container_busy", target_ref=OTHER_TARGET, detail="busy elsewhere"
        ),
        StepOutcome.TARGET_DRIFT,
        TargetOutcome.TARGET_DRIFT,
    ),
)


class TestErrorNormalisation:
    @pytest.mark.parametrize(
        ("result", "outcome", "reason"),
        _NORMALISATION_MATRIX,
        ids=[
            f"{r.ok}-{r.error_code or r.target_ref or 'bare'}"
            for r, _, _ in _NORMALISATION_MATRIX
        ],
    )
    def test_matrix(
        self,
        result: ProviderResult,
        outcome: StepOutcome,
        reason: TargetOutcome | None,
    ) -> None:
        normalisation = normalise_provider_result(result, expected_target=TARGET)
        assert normalisation.outcome is outcome
        assert normalisation.target_outcome is reason

    def test_a_provider_reporting_ok_while_the_target_moved_is_drift_not_pass(self) -> None:
        session = RecordingSession(
            ProviderResult(ok=True, detail="injected", target_ref=OTHER_TARGET)
        )
        engine = _engine(session, RecordingJournal(DurableLog()), InMemoryLeaseSink())

        result = engine.dispatch(_request())

        assert result.ok is False
        assert result.is_drift is True
        assert result.outcome is StepOutcome.TARGET_DRIFT
        assert result.target_outcome is TargetOutcome.TARGET_DRIFT
        assert "mismatched, not failed" in result.detail

    def test_a_step_without_a_planned_target_cannot_drift_on_mismatch(self) -> None:
        # expected_target=None means "no identity to compare", which is a
        # declared limitation, not a silent pass: the error codes still apply.
        result = normalise_provider_result(
            ProviderResult(ok=True, target_ref=OTHER_TARGET), expected_target=None
        )
        assert result.outcome is StepOutcome.COMPLETED

    def test_an_agent_side_fence_refusal_normalises_to_contention(self) -> None:
        refusal = FabricCommandRefused(
            FABRIC_STALE_FENCE, "fence 3 already served", details={"step_id": STEP_ID}
        )
        engine = _engine(
            RecordingSession(refusal), RecordingJournal(DurableLog()), InMemoryLeaseSink()
        )

        result = engine.dispatch(_request())

        assert result.ok is False
        assert result.target_outcome is TargetOutcome.RESOURCE_CONFLICT
        assert result.refusal_code == FABRIC_STALE_FENCE
        assert FABRIC_STALE_FENCE in result.detail

    def test_a_transport_exception_is_failed_to_apply_not_a_crash(self) -> None:
        engine = _engine(
            RecordingSession(TimeoutError("session died")),
            RecordingJournal(DurableLog()),
            InMemoryLeaseSink(),
        )
        result = engine.dispatch(_request())
        assert result.outcome is StepOutcome.FAILED
        assert result.target_outcome is TargetOutcome.FAILED_TO_APPLY
        assert "TimeoutError" in result.detail

    def test_a_killed_controller_is_not_catchable(self) -> None:
        engine = _engine(
            RecordingSession(ControllerKilled()),
            RecordingJournal(DurableLog()),
            InMemoryLeaseSink(),
        )
        with pytest.raises(ControllerKilled):
            engine.dispatch(_request())

    def test_the_lease_the_agent_created_is_persisted_through_the_sink(self) -> None:
        sink = InMemoryLeaseSink()
        engine = _engine(
            RecordingSession(_applied(lease=_lease("l-7"))),
            RecordingJournal(DurableLog()),
            sink,
        )
        result = engine.dispatch(_request())
        assert result.lease_id == "l-7"
        assert sink.load("l-7") is not None
        assert engine.unrecovered_steps(RUN_ID) == (STEP_ID,)


# --- reservations ---------------------------------------------------------------


class TestReservations:
    def test_a_step_without_reservations_dispatches(self) -> None:
        engine = _engine(
            RecordingSession(_applied()), RecordingJournal(DurableLog()), InMemoryLeaseSink()
        )
        assert engine.dispatch(_request()).ok is True

    def test_a_reservation_taken_under_the_presented_fence_is_accepted(self) -> None:
        engine = _engine(
            RecordingSession(_applied()), RecordingJournal(DurableLog()), InMemoryLeaseSink()
        )
        result = engine.dispatch(
            _request(
                reservations=(
                    _reservation(epoch=2),
                    _reservation(resource="svc/checkout", epoch=2),
                )
            )
        )
        assert result.ok is True

    def test_an_expired_reservation_is_refused_before_dispatch(self) -> None:
        session = RecordingSession(_applied())
        engine = _engine(
            session, RecordingJournal(DurableLog()), InMemoryLeaseSink(), clock=_Clock(LATER)
        )
        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(reservations=(_reservation(ttl_seconds=1.0),)))
        assert excinfo.value.code == FABRIC_RESERVATION_EXPIRED
        assert session.calls == []

    def test_a_deposed_owners_lock_is_not_inherited_by_its_successor(self) -> None:
        journal = RecordingJournal(DurableLog())
        sink = InMemoryLeaseSink()
        _engine(RecordingSession(_applied()), journal, sink).dispatch(
            _request(reservations=(_reservation(epoch=1),))
        )

        # The lock was taken under epoch 1. The successor presents epoch 2, so the
        # lock is the deposed owner's, not an inherited one: re-reserve, do not
        # silently take over a resource a dead owner may still be mutating.
        successor = _engine(RecordingSession(_applied()), journal, sink, controller_id="ctl-b")
        with pytest.raises(FabricCommandRefused) as excinfo:
            successor.dispatch(
                _request(
                    _command(epoch=2, nonce=2, key="idem-2", command_id="fc-2"),
                    reservations=(_reservation(epoch=1),),
                )
            )
        assert excinfo.value.code == FABRIC_RESOURCE_CONFLICT
        assert "deposed owner's lock is not inherited" in excinfo.value.remediation

    def test_contention_with_another_runs_lock_is_refused(self) -> None:
        session = RecordingSession(_applied())
        engine = _engine(session, RecordingJournal(DurableLog()), InMemoryLeaseSink())
        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(
                _request(
                    reservations=(_reservation(epoch=1, step_id=STEP_ID),),
                    held_by_others=(
                        _reservation(epoch=1, step_id="s-9", holder="agent-9"),
                    ),
                )
            )
        assert excinfo.value.code == FABRIC_RESOURCE_CONFLICT
        assert "s-9" in str(excinfo.value)
        assert session.calls == []

    def test_locks_on_different_resources_do_not_contend(self) -> None:
        engine = _engine(
            RecordingSession(_applied()), RecordingJournal(DurableLog()), InMemoryLeaseSink()
        )
        result = engine.dispatch(
            _request(
                reservations=(_reservation(resource="node/worker-3"),),
                held_by_others=(_reservation(resource="svc/checkout", step_id="s-9"),),
            )
        )
        assert result.ok is True

    def test_the_same_step_holding_its_own_lock_is_not_contention(self) -> None:
        engine = _engine(
            RecordingSession(_applied()), RecordingJournal(DurableLog()), InMemoryLeaseSink()
        )
        result = engine.dispatch(_request(reservations=(_reservation(), _reservation())))
        assert result.ok is True


# --- plan binding, signature seam, outcome coherence ----------------------------


class TestPlanBinding:
    def test_a_command_bound_to_a_superseded_plan_is_refused(self) -> None:
        session = RecordingSession(_applied())
        engine = _engine(session, RecordingJournal(DurableLog()), InMemoryLeaseSink())
        command = _command(plan_digest=SUPERSEDED_PLAN_DIGEST)

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(command))

        assert excinfo.value.code == FABRIC_PLAN_MISMATCH
        assert session.calls == []
        assert engine.claims(RUN_ID, STEP_ID) == ()

    def test_a_command_bound_to_the_current_plan_dispatches(self) -> None:
        engine = _engine(
            RecordingSession(_applied()), RecordingJournal(DurableLog()), InMemoryLeaseSink()
        )
        assert engine.dispatch(_request()).ok is True


class TestUndersignedSeam:
    def test_the_refusal_code_is_published_for_the_wire_path(self) -> None:
        assert FABRIC_UNDERSIGNED == "fabric_undersigned"

    def test_an_unsigned_envelope_cannot_reach_the_guard_in_process(self) -> None:
        # The guard exists and is wired, but the Phase 1 envelope has no defaulted
        # field, so there is no construction path that reaches it in-process. It
        # stays for the plan-19 wire receiver, which decodes untrusted frames.
        with pytest.raises(ValidationError):
            FabricCommand.model_validate(
                {
                    **_command().model_dump(mode="json"),
                    "signature": "   ",
                }
            )
        assert _command().is_signed is True


class TestOutcomeCoherence:
    def _result(self, **overrides: object) -> DispatchResult:
        fields: dict[str, object] = {
            "run_id": RUN_ID,
            "step_id": STEP_ID,
            "command_id": "fc-1",
            "epoch": 1,
            "outcome": StepOutcome.COMPLETED,
        }
        fields.update(overrides)
        return DispatchResult.model_validate(fields)

    def test_a_completed_step_carries_no_reason(self) -> None:
        assert self._result().ok is True
        with pytest.raises(InvariantViolationError):
            self._result(target_outcome=TargetOutcome.FAILED_TO_APPLY)

    def test_a_failed_step_must_name_a_reason(self) -> None:
        with pytest.raises(InvariantViolationError):
            self._result(outcome=StepOutcome.FAILED)
        assert (
            self._result(
                outcome=StepOutcome.FAILED, target_outcome=TargetOutcome.RESOURCE_CONFLICT
            ).ok
            is False
        )

    def test_a_failed_settlement_must_name_its_reason(self) -> None:
        # The engine never guesses a reason, not even for a claim it reconciles
        # on a controller's behalf: an unnamed failure is how a drift or a
        # contention gets written up as a plain failure.
        log = DurableLog()
        with pytest.raises(ControllerKilled):
            _engine(
                RecordingSession(_applied()),
                RecordingJournal(log, crash_on_settlement=1),
                InMemoryLeaseSink(),
            ).dispatch(_request())
        engine = _engine(RecordingSession(), RecordingJournal(log), InMemoryLeaseSink())
        with pytest.raises(InvariantViolationError):
            engine.settle_claim(RUN_ID, STEP_ID, outcome=StepOutcome.FAILED)

    def test_the_drift_reason_is_derived_by_the_engine_not_the_caller(self) -> None:
        # A drifted step's reason has one reading, so the caller never has to
        # spell it out — and the model still refuses an incoherent pair.
        engine = _engine(
            RecordingSession(
                ProviderResult(ok=False, error_code="pod_replaced", detail="uid changed")
            ),
            RecordingJournal(DurableLog()),
            InMemoryLeaseSink(),
        )
        result = engine.dispatch(_request())
        assert result.is_drift is True
        assert result.target_outcome is TargetOutcome.TARGET_DRIFT
        with pytest.raises(InvariantViolationError):
            self._result(
                outcome=StepOutcome.TARGET_DRIFT, target_outcome=TargetOutcome.FAILED_TO_APPLY
            )

    def test_a_settlement_must_agree_with_its_lead_outcome(self) -> None:
        with pytest.raises(InvariantViolationError):
            DispatchSettlement(
                run_id=RUN_ID,
                step_id=STEP_ID,
                command_id="fc-1",
                outcome=StepOutcome.TARGET_DRIFT,
                target_outcome=TargetOutcome.FAILED_TO_APPLY,
                settled_at=NOW,
            )

    def test_a_claim_must_carry_the_whole_envelope(self) -> None:
        # The journal stores the command, not a projection of it, so it cannot
        # disagree with the envelope it is a record of.
        claim = DispatchClaim(
            command=_command(), controller_id="ctl-a", claimed_at=NOW
        )
        assert claim.command.nonce == _nonce(1)
        assert claim.phase.value == "claimed"

    def test_a_naive_timestamp_is_refused(self) -> None:
        naive = NOW.replace(tzinfo=None)  # a claim with no usable clock is unrecoverable
        with pytest.raises(InvariantViolationError):
            DispatchClaim(command=_command(), controller_id="ctl-a", claimed_at=naive)


# --- crash safety: kill the controller, resume from the durable rendezvous ------


class TestControllerKillAndResume:
    def test_a_resumed_controller_rebuilds_ownership_from_the_durable_log(self) -> None:
        log = DurableLog()
        sink = InMemoryLeaseSink()
        session_a = RecordingSession(_applied(lease=_lease("l-1", state=LeaseState.ACTIVE)))
        engine_a = _engine(session_a, RecordingJournal(log), sink, controller_id="ctl-a")
        first = engine_a.dispatch(_request())
        assert first.ok is True

        # ---- controller A is killed here. Nothing is handed to a successor:
        # the object is dropped and only the durable rows + the sink remain.
        del engine_a, session_a

        session_b = RecordingSession(_applied())
        engine_b = _engine(session_b, RecordingJournal(log), sink, controller_id="ctl-b")

        # What the newcomer knows, all of it derived from durable state:
        assert _served_epoch(engine_b) == 1
        assert engine_b.nonce_ledger(RUN_ID, STEP_ID).knows(_nonce(1))
        assert engine_b.unrecovered_steps(RUN_ID) == (STEP_ID,)
        assert engine_b.unreconciled_leases(RUN_ID) == ()  # the settlement recorded it
        assert [claim.controller_id for claim in engine_b.claims(RUN_ID)] == ["ctl-a"]
        # Exactly one lease exists for the step: the dead owner produced one
        # effect, and nothing has produced a second.
        assert [lease.id for lease in sink.active_leases()] == ["l-1"]

        # Before the step may be dispatched again, the lease the dead controller
        # left behind is compensated through the real state machine, and the
        # recovery guarantee holds.
        client = LeaseClient(sink, agent_id="agent-1")
        client.mark_orphaned("l-1", notes="controller ctl-a did not come back")
        client.mark_releasing("l-1")
        released = client.confirm_release("l-1", mechanism="watchdog")
        assert released.state is LeaseState.RELEASED
        assert_all_recovered(list(sink.all_leases()))
        assert engine_b.unrecovered_steps(RUN_ID) == ()

        # The successor takes the step over under a strictly newer fence.
        fence = _served_fence(engine_b).next_fence(holder="agent-2", now=LATER)
        handover = _command(epoch=fence.epoch, nonce=3, key="idem-b1", command_id="fc-b1")
        handover = handover.model_copy(update={"fencing_token": fence})
        session_b2 = RecordingSession(_applied(lease=_lease("l-2", owner="agent-2")))
        resumed = _engine(session_b2, RecordingJournal(log), sink, controller_id="ctl-b")
        result = resumed.dispatch(_request(handover))

        assert result.ok is True
        assert result.epoch == 2
        assert len(session_b2.calls) == 1
        assert _served_epoch(resumed) == 2
        # One owner, one lease at a time: the recovered lease is safe-terminal
        # and the new effect is the only live one.
        assert [lease.id for lease in sink.active_leases()] == ["l-2"]

        # …and now that the step is owned at epoch 2, the deposed owner's late
        # command is refused by name, with no provider touched on the way out.
        late_session = RecordingSession(_applied())
        late = _engine(late_session, RecordingJournal(log), sink, controller_id="ctl-a")
        with pytest.raises(FabricCommandRefused) as excinfo:
            late.dispatch(_request(_command(nonce=4, key="idem-a2", command_id="fc-a2")))
        assert excinfo.value.code == FABRIC_STALE_FENCE
        assert excinfo.value.details["step_id"] == STEP_ID
        assert late_session.calls == []
        # A replay of the dead owner's *own* key does not slip through either.
        with pytest.raises(FabricCommandRefused) as excinfo:
            late.dispatch(_request(_command(nonce=5, command_id="fc-a3")))
        assert excinfo.value.code == FABRIC_STALE_FENCE
        assert late_session.calls == []

    def test_a_crash_between_the_lease_and_the_settlement_is_visible_on_resume(self) -> None:
        log = DurableLog()
        sink = InMemoryLeaseSink()
        dying = RecordingSession(_applied(lease=_lease("l-1", state=LeaseState.ACTIVE)))
        with pytest.raises(ControllerKilled):
            _engine(dying, RecordingJournal(log, crash_on_settlement=1), sink).dispatch(_request())

        # Durable state after the kill: the claim landed, the lease landed, the
        # settlement did not. That pair is the crash signature.
        engine_b = _engine(RecordingSession(), RecordingJournal(log), sink, controller_id="ctl-b")
        assert [claim.command.command_id for claim in engine_b.open_claims(RUN_ID)] == ["fc-1"]
        assert [lease.id for lease in engine_b.unreconciled_leases(RUN_ID)] == ["l-1"]
        assert engine_b.unrecovered_steps(RUN_ID) == ()  # the settlement never named the step

        # An effect that may already have happened is not dispatched again …
        session = RecordingSession(_applied())
        with pytest.raises(FabricCommandRefused) as excinfo:
            _engine(session, RecordingJournal(log), sink, controller_id="ctl-b").dispatch(
                _request(_command(nonce=2, command_id="fc-2"))
            )
        assert excinfo.value.code == FABRIC_INFLIGHT_UNRESOLVED
        assert session.calls == []

        # … it is reconciled instead: recover the lease, close the claim, and the
        # recovery guarantee holds before anything new is dispatched.
        client = LeaseClient(sink, agent_id="agent-1")
        client.mark_orphaned("l-1", notes="settled after crash")
        client.mark_releasing("l-1")
        client.confirm_release("l-1", mechanism="watchdog")
        assert_all_recovered(list(sink.all_leases()))

        engine_b.settle_claim(
            RUN_ID,
            STEP_ID,
            outcome=StepOutcome.FAILED,
            target_outcome=TargetOutcome.FAILED_TO_APPLY,
            detail="undone during recovery",
        )
        assert engine_b.open_claims(RUN_ID) == ()
        assert engine_b.unreconciled_leases(RUN_ID) == ()

        fence = _fence(1).next_fence(holder="agent-2", now=LATER)
        retry_session = RecordingSession(_applied(lease=_lease("l-2", owner="agent-2")))
        result = _engine(
            retry_session, RecordingJournal(log), sink, controller_id="ctl-b"
        ).dispatch(
            _request(
                _command(epoch=2, nonce=3, key="idem-b1", command_id="fc-b1").model_copy(
                    update={"fencing_token": fence}
                )
            )
        )
        assert result.ok is True
        assert result.epoch == 2
        assert len(retry_session.calls) == 1
        assert [lease.id for lease in sink.active_leases()] == ["l-2"]

    def test_a_fresh_engine_needs_no_controller_memory_to_read_the_lease_sink(self) -> None:
        log = DurableLog()
        sink = InMemoryLeaseSink()
        _engine(
            RecordingSession(_applied(lease=_lease("l-1", state=LeaseState.ACTIVE))),
            RecordingJournal(log),
            sink,
        ).dispatch(_request())

        # A reader that has dispatched nothing at all still sees the live lease.
        observer = _engine(RecordingSession(), RecordingJournal(log), sink, controller_id="ctl-z")
        assert observer.unrecovered_steps(RUN_ID) == (STEP_ID,)
        assert sink.load("l-1").state is LeaseState.ACTIVE  # type: ignore[union-attr]

    def test_projection_helpers_read_the_log_not_an_engine_cache(self) -> None:
        log = DurableLog()
        sink = InMemoryLeaseSink()
        first = _engine(RecordingSession(_applied()), RecordingJournal(log), sink)
        first.dispatch(_request())
        before = (
            first.claims(RUN_ID),
            first.settlements(RUN_ID),
            first.open_claims(RUN_ID),
            first.served_fence(RUN_ID, STEP_ID),
        )

        second = _engine(RecordingSession(), RecordingJournal(log), sink, controller_id="ctl-b")
        after = (
            second.claims(RUN_ID),
            second.settlements(RUN_ID),
            second.open_claims(RUN_ID),
            second.served_fence(RUN_ID, STEP_ID),
        )
        assert before == after
