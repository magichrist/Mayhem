"""Tests for recovery state machine and audit trail (ADR-0016)."""

import pytest

from mayhem.controller.recovery import (
    RecoveryAuditLog,
    RecoveryStatus,
    RecoveryStateMachine,
    RecoveryTransition,
)
from mayhem.domain.errors import InvariantViolationError


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
        log.record(RecoveryTransition(
            resource_id="r1",
            from_status=RecoveryStatus.IDLE,
            to_status=RecoveryStatus.RECOVERING,
            reason="start",
        ))
        log.record(RecoveryTransition(
            resource_id="r1",
            from_status=RecoveryStatus.RECOVERING,
            to_status=RecoveryStatus.VERIFIED,
            reason="done",
        ))
        assert log.current_status("r1") == RecoveryStatus.VERIFIED

    def test_isolation_between_resources(self) -> None:
        log = RecoveryAuditLog()
        log.record(RecoveryTransition(
            resource_id="r1",
            from_status=RecoveryStatus.IDLE,
            to_status=RecoveryStatus.RECOVERING,
            reason="start",
        ))
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
