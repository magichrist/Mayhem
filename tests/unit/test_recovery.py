"""Tests for recovery state machine and audit trail (ADR-0016)."""

import json
from datetime import timedelta

import pytest

from mayhem.agents.sinks import InMemoryLeaseSink
from mayhem.controller.recovery import (
    RecoveryAuditLog,
    RecoveryService,
    RecoveryState,
    RecoveryStateMachine,
    RecoveryStatus,
    RecoveryTransition,
)
from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.leases import FaultLease, LeaseState


class TestRecoveryStatus:
    def test_all_values(self) -> None:
        assert set(RecoveryStatus) == {
            RecoveryStatus.IDLE,
            RecoveryStatus.RECOVERING,
            RecoveryStatus.VERIFIED,
            RecoveryStatus.DIRTY,
        }


class TestRecoveryAuditLog:
    def test_empty_log(self) -> None:
        log = RecoveryAuditLog()
        assert log.current_status("res-1") == RecoveryStatus.IDLE
        assert log.for_resource("res-1") == []

    def test_record_and_read(self) -> None:
        log = RecoveryAuditLog()
        t = RecoveryTransition(
            resource_id="res-1",
            from_status=RecoveryStatus.IDLE,
            to_status=RecoveryStatus.RECOVERING,
            reason="start",
        )
        log.record(t)
        assert log.current_status("res-1") == RecoveryStatus.RECOVERING
        assert len(log.for_resource("res-1")) == 1

    def test_sequential_transitions(self) -> None:
        log = RecoveryAuditLog()
        log.record(
            RecoveryTransition(
                resource_id="r1",
                from_status=RecoveryStatus.IDLE,
                to_status=RecoveryStatus.RECOVERING,
                reason="start",
            )
        )
        log.record(
            RecoveryTransition(
                resource_id="r1",
                from_status=RecoveryStatus.RECOVERING,
                to_status=RecoveryStatus.VERIFIED,
                reason="done",
            )
        )
        assert log.current_status("r1") == RecoveryStatus.VERIFIED

    def test_isolation_between_resources(self) -> None:
        log = RecoveryAuditLog()
        log.record(
            RecoveryTransition(
                resource_id="r1",
                from_status=RecoveryStatus.IDLE,
                to_status=RecoveryStatus.RECOVERING,
                reason="start",
            )
        )
        assert log.current_status("r2") == RecoveryStatus.IDLE


class TestRecoveryStateMachine:
    def test_happy_path_idle_to_verified(self) -> None:
        sm = RecoveryStateMachine(RecoveryAuditLog())
        t1 = sm.start_recovery("r1")
        assert t1.from_status == RecoveryStatus.IDLE
        assert t1.to_status == RecoveryStatus.RECOVERING
        t2 = sm.mark_verified("r1")
        assert t2.to_status == RecoveryStatus.VERIFIED
        assert sm._audit.current_status("r1") == RecoveryStatus.VERIFIED

    def test_dirty_on_failure(self) -> None:
        sm = RecoveryStateMachine(RecoveryAuditLog())
        sm.start_recovery("r1")
        t = sm.mark_dirty("r1", reason="undo command failed")
        assert t.to_status == RecoveryStatus.DIRTY

    def test_retry_from_dirty(self) -> None:
        sm = RecoveryStateMachine(RecoveryAuditLog())
        sm.start_recovery("r1")
        sm.mark_dirty("r1")
        assert sm.can_retry("r1") is True
        t = sm.start_recovery("r1", reason="retry 1")
        assert t.attempt == 2
        assert t.from_status == RecoveryStatus.DIRTY

    def test_cannot_retry_after_max(self) -> None:
        sm = RecoveryStateMachine(RecoveryAuditLog())
        for _ in range(RecoveryStateMachine.MAX_RETRIES):
            sm.start_recovery("r1")
            sm.mark_dirty("r1")
        assert sm.can_retry("r1") is False

    def test_invalid_transition_rejected(self) -> None:
        sm = RecoveryStateMachine(RecoveryAuditLog())
        with pytest.raises(InvariantViolationError, match="recovery_invalid_transition"):
            sm.mark_verified("r1")  # can't verify without recovering first

    def test_invalid_transition_idle_to_verified(self) -> None:
        sm = RecoveryStateMachine(RecoveryAuditLog())
        with pytest.raises(InvariantViolationError, match="recovery_invalid_transition"):
            # IDLE → VERIFIED is not allowed (must go through RECOVERING)
            sm.mark_verified("r1")

    def test_cannot_transition_from_terminal(self) -> None:
        sm = RecoveryStateMachine(RecoveryAuditLog())
        sm.start_recovery("r1")
        sm.mark_verified("r1")
        with pytest.raises(InvariantViolationError, match="recovery_invalid_transition"):
            sm.start_recovery("r1")

    def test_attempt_counter_increments(self) -> None:
        sm = RecoveryStateMachine(RecoveryAuditLog())
        t1 = sm.start_recovery("r1")
        assert t1.attempt == 1
        sm.mark_dirty("r1")
        t2 = sm.start_recovery("r1")
        assert t2.attempt == 2
        sm.mark_dirty("r1")
        t3 = sm.start_recovery("r1")
        assert t3.attempt == 3

    def test_audit_trail_complete(self) -> None:
        log = RecoveryAuditLog()
        sm = RecoveryStateMachine(log)
        sm.start_recovery("r1")
        sm.mark_verified("r1")
        history = log.for_resource("r1")
        assert len(history) == 2
        assert history[0].to_status == RecoveryStatus.RECOVERING
        assert history[1].to_status == RecoveryStatus.VERIFIED

    def test_dirty_retry_verified_path(self) -> None:
        sm = RecoveryStateMachine(RecoveryAuditLog())
        sm.start_recovery("r1")
        sm.mark_dirty("r1", reason="first attempt failed")
        sm.start_recovery("r1", reason="retry")
        sm.mark_verified("r1", reason="retry succeeded")
        assert sm._audit.current_status("r1") == RecoveryStatus.VERIFIED
        assert len(sm._audit.for_resource("r1")) == 4


def _recovery_lease(
    lease_id: str,
    run_id: str,
    state: LeaseState,
    *,
    age_seconds: float = 0,
) -> FaultLease:
    return FaultLease.model_validate(
        {
            "id": lease_id,
            "run_id": run_id,
            "fault_id": "proc.pause",
            "owner_agent": "agent-1",
            "targets": ["api"],
            "undo_ops": ({"op": "signal", "args": {"target": "api"}},),
            "verify_probes": (
                {"probe": "exec", "args": {"cmd": ["true"]}, "expect_present": True},
            ),
            "ttl_seconds": 60,
            "state": state,
            "created_at": utc_now() - timedelta(seconds=age_seconds),
            "escalation_notes": "manual action required" if state is LeaseState.DIRTY else None,
        }
    )


def test_recovery_lifecycle_states_are_explicit():
    assert {state.value for state in RecoveryState} == {
        "not_needed",
        "pending",
        "running",
        "recovered",
        "dirty",
        "escalated",
        "abandoned",
    }


def test_recovery_plan_is_side_effect_free_and_explicit():
    sink = InMemoryLeaseSink()
    sink.save(_recovery_lease("l-active", "run-1", LeaseState.ACTIVE))
    service = RecoveryService(sink, run_liveness=lambda run_id: False)
    plan = service.plan(("run-1",), target_profiles=("prod",))
    assert plan.run_ids == ("run-1",)
    assert plan.target_profiles == ("prod",)
    assert plan.state is RecoveryState.PENDING
    assert plan.leases[0].owner == "agent-1"
    assert plan.leases[0].expires_at
    assert plan.leases[0].compensation
    assert plan.leases[0].verification_probes
    assert sink.load("l-active").state is LeaseState.ACTIVE


def test_recovery_status_covers_active_dirty_escalated_and_abandoned():
    sink = InMemoryLeaseSink()
    sink.save(_recovery_lease("l-live", "run-live", LeaseState.ACTIVE))
    sink.save(_recovery_lease("l-dirty", "run-dirty", LeaseState.DIRTY))
    sink.save(
        _recovery_lease("l-escalated", "run-escalated", LeaseState.DIRTY).model_copy(
            update={"escalation_notes": "escalated to operator"}
        )
    )
    abandoned = (
        _recovery_lease("l-expired", "run-abandoned", LeaseState.ACTIVE)
        .transition(LeaseState.ORPHANED)
        .transition(LeaseState.RELEASING)
        .transition(LeaseState.DIRTY, escalation_notes="compensation failed")
        .transition(LeaseState.EXPIRED)
    )
    sink.save(abandoned)
    service = RecoveryService(sink, run_liveness=lambda run_id: run_id == "run-live")
    assert service.status(("run-live",)).state is RecoveryState.PENDING
    assert service.status(("run-dirty",)).state is RecoveryState.DIRTY
    assert service.status(("run-escalated",)).state is RecoveryState.ESCALATED
    assert service.status(("run-abandoned",)).state is RecoveryState.ABANDONED
    assert service.status(("missing",)).state is RecoveryState.NOT_NEEDED


def test_recovery_execute_is_idempotent_and_writes_dirty_handoff(tmp_path):
    sink = InMemoryLeaseSink()
    sink.save(_recovery_lease("l-active", "run-1", LeaseState.ACTIVE))
    sink.save(_recovery_lease("l-dirty", "run-1", LeaseState.DIRTY))
    service = RecoveryService(sink, run_liveness=lambda run_id: False)
    result = service.execute(
        service.plan(("run-1",)),
        artifact_dir=tmp_path,
        now_epoch_s=utc_now().timestamp() + 120,
    )
    assert result.recovered == ("l-active",)
    assert result.handoff_path is not None
    assert json.loads(result.handoff_path.read_text())["run_ids"] == ["run-1"]
    again = service.execute(service.plan(("run-1",)), artifact_dir=tmp_path)
    assert again.recovered == ()
    assert sink.load("l-dirty").state is LeaseState.DIRTY
