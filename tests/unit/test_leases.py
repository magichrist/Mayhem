"""Lease state machine: transitions, invariants, run-completion gate."""

from datetime import UTC, datetime, timedelta

import pytest

from mayhem.domain.errors import (
    InvalidTransitionError,
    InvariantViolationError,
)
from mayhem.domain.leases import (
    FaultLease,
    LeaseState,
    UndoOp,
    VerifyProbe,
    assert_all_recovered,
)

_NOW = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)


def _lease(state: LeaseState = LeaseState.PENDING, **overrides: object) -> FaultLease:
    defaults: dict[str, object] = {
        "id": "l-abc",
        "run_id": "r-1",
        "fault_id": "net.latency",
        "owner_agent": "ag-1",
        "targets": frozenset({"n-api"}),
        "undo_ops": (UndoOp(op="tc.del_qdisc", args={"dev": "eth0"}),),
        "verify_probes": (VerifyProbe(probe="tc.qdisc_absent", args={"dev": "eth0"}),),
        "state": state,
    }
    defaults.update(overrides)
    return FaultLease.model_validate(defaults)


class TestTransitions:
    def test_happy_path(self) -> None:
        lease = _lease(created_at=_NOW - timedelta(seconds=1))
        active = lease.transition(LeaseState.ACTIVE, now=_NOW)
        assert active.injected_at == _NOW
        releasing = active.transition(LeaseState.RELEASING, mechanism="normal")
        released = releasing.transition(LeaseState.RELEASED, now=_NOW + timedelta(seconds=5))
        assert released.state is LeaseState.RELEASED
        assert released.is_safe_terminal
        assert released.release_mechanism == "normal"

    def test_pending_cannot_skip_to_releasing(self) -> None:
        with pytest.raises(InvalidTransitionError):
            _lease().transition(LeaseState.RELEASING)

    def test_active_can_orphan_and_janitor_reclaims(self) -> None:
        orphaned = _lease().transition(LeaseState.ACTIVE).transition(LeaseState.ORPHANED)
        releasing = orphaned.transition(LeaseState.RELEASING, mechanism="janitor")
        assert releasing.transition(LeaseState.RELEASED).is_safe_terminal

    def test_watchdog_expiry_is_terminal(self) -> None:
        expired = (
            _lease()
            .transition(LeaseState.ACTIVE)
            .transition(LeaseState.EXPIRED, mechanism="watchdog")
        )
        assert expired.is_terminal
        assert expired.is_safe_terminal
        with pytest.raises(InvalidTransitionError):
            expired.transition(LeaseState.RELEASING)

    def test_dirty_requires_escalation_notes(self) -> None:
        releasing = _lease().transition(LeaseState.ACTIVE).transition(LeaseState.RELEASING)
        with pytest.raises(InvariantViolationError, match="dirty_requires_escalation_notes"):
            releasing.transition(LeaseState.DIRTY)
        dirty = releasing.transition(
            LeaseState.DIRTY, escalation_notes="iptables chain still present on bm-1"
        )
        assert dirty.is_terminal
        assert not dirty.is_safe_terminal


class TestInvariants:
    def test_active_without_undo_refused(self) -> None:
        with pytest.raises(InvariantViolationError, match="undo_required_before_active"):
            _lease(undo_ops=()).transition(LeaseState.ACTIVE)

    def test_id_prefix_enforced(self) -> None:
        with pytest.raises(InvariantViolationError, match="lease_id_prefix"):
            _lease(id="bad-id")

    def test_time_ordering(self) -> None:
        later = _NOW + timedelta(seconds=10)
        with pytest.raises(InvariantViolationError, match="lease_time_ordering"):
            _lease(created_at=later).transition(LeaseState.ACTIVE, now=_NOW)


class TestRunCompletionGate:
    def test_assert_all_recovered_passes_on_safe_terminals(self) -> None:
        released = (
            _lease()
            .transition(LeaseState.ACTIVE)
            .transition(LeaseState.RELEASING)
            .transition(LeaseState.RELEASED)
        )
        expired = _lease(id="l-def").transition(LeaseState.ACTIVE).transition(LeaseState.EXPIRED)
        assert_all_recovered([released, expired])

    def test_assert_all_recovered_fails_loudly(self) -> None:
        active = _lease().transition(LeaseState.ACTIVE)
        with pytest.raises(InvariantViolationError, match="l-abc:active"):
            assert_all_recovered([active])
