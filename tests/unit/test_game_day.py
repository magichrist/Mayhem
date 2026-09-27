"""v0.9.0 expansion task 17: game-day sessions."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from mayhem.domain.game_day import (
    ApprovalGate,
    FreezeWindow,
    GameDayError,
    GameDaySession,
    OperatorAcknowledgement,
    SessionState,
    check_approval,
    complete,
    pause,
    start,
)

WINDOW = FreezeWindow(starts_at="2026-09-26T00:00:00Z", ends_at="2026-09-27T00:00:00Z")
INSIDE = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)
OUTSIDE = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


def _session(**overrides) -> GameDaySession:
    payload = {
        "id": "gd-1",
        "name": "quarterly",
        "window": WINDOW,
        "gate": ApprovalGate(required_approvers=1),
    }
    payload.update(overrides)
    return GameDaySession(**payload)  # type: ignore[arg-type]


def _approved(actor: str = "sre@example") -> GameDaySession:
    return _session().with_approval(OperatorAcknowledgement(actor=actor))


# ── approval ─────────────────────────────────────────────────────────────────
def test_missing_approval_refuses_to_start() -> None:
    with pytest.raises(GameDayError, match="needs 1 approval"):
        start(_session(), now=INSIDE)


def test_one_approval_is_enough_for_a_non_critical_session() -> None:
    session = start(_approved(), now=INSIDE)
    assert session.state is SessionState.RUNNING


def test_two_approvers_are_required_when_configured() -> None:
    session = _session(gate=ApprovalGate(required_approvers=2))
    with pytest.raises(GameDayError, match="needs 2 approval"):
        start(session, now=INSIDE)
    two = session.with_approval(OperatorAcknowledgement(actor="a")).with_approval(
        OperatorAcknowledgement(actor="b")
    )
    assert start(two, now=INSIDE).state is SessionState.RUNNING


def test_duplicate_actor_does_not_count_twice() -> None:
    session = _session(gate=ApprovalGate(required_approvers=2))
    twice = session.with_approval(OperatorAcknowledgement(actor="a")).with_approval(
        OperatorAcknowledgement(actor="a")
    )
    with pytest.raises(GameDayError, match="needs 2 approval"):
        start(twice, now=INSIDE)


# ── freeze window ────────────────────────────────────────────────────────────
def test_expired_freeze_window_refuses_to_start() -> None:
    with pytest.raises(GameDayError, match="outside its freeze window"):
        start(_approved(), now=OUTSIDE)


def test_session_without_a_window_has_no_time_limit() -> None:
    session = _session(window=None)
    assert start(session.with_approval(OperatorAcknowledgement(actor="a")), now=OUTSIDE).state is (
        SessionState.RUNNING
    )


# ── critical faults / dual control ───────────────────────────────────────────
def test_critical_fault_requires_dual_control() -> None:
    session = _session(
        critical_faults=("fs.disk_fill",),
        gate=ApprovalGate(required_approvers=1, dual_control_for_critical=True),
    )
    one = session.with_approval(OperatorAcknowledgement(actor="sre@example"))
    with pytest.raises(GameDayError, match="dual control"):
        start(one, now=INSIDE)
    two = one.with_approval(OperatorAcknowledgement(actor="em@example"))
    assert start(two, now=INSIDE).state is SessionState.RUNNING


def test_dual_control_can_be_disabled_explicitly() -> None:
    session = _session(
        critical_faults=("fs.disk_fill",),
        gate=ApprovalGate(required_approvers=1, dual_control_for_critical=False),
    )
    approved = session.with_approval(OperatorAcknowledgement(actor="sre@example"))
    assert start(approved, now=INSIDE).state is SessionState.RUNNING


# ── pause / complete ─────────────────────────────────────────────────────────
def test_operator_pause_stops_a_running_session() -> None:
    running = start(_approved(), now=INSIDE)
    paused = pause(running, OperatorAcknowledgement(actor="operator@example"))
    assert paused.state is SessionState.PAUSED
    assert paused.transition(SessionState.RUNNING).state is SessionState.RUNNING


def test_pause_requires_a_running_session() -> None:
    with pytest.raises(GameDayError, match="cannot pause"):
        pause(_approved(), OperatorAcknowledgement(actor="operator@example"))


def test_pause_must_name_the_operator() -> None:
    running = start(_approved(), now=INSIDE)
    with pytest.raises(GameDayError, match="name the operator"):
        pause(running, OperatorAcknowledgement(actor=""))


def test_completion_requires_an_evidence_bundle() -> None:
    running = start(_approved(), now=INSIDE)
    with pytest.raises(GameDayError, match="evidence bundle"):
        complete(running, "")
    done = complete(running, "bundle-abc")
    assert done.state is SessionState.COMPLETED
    assert done.evidence_bundle == "bundle-abc"


def test_completed_session_is_terminal() -> None:
    running = start(_approved(), now=INSIDE)
    done = complete(running, "bundle-abc")
    with pytest.raises(GameDayError):
        done.transition(SessionState.RUNNING)


# ── state machine ────────────────────────────────────────────────────────────
def test_invalid_transitions_are_refused() -> None:
    with pytest.raises(GameDayError, match="cannot move"):
        _approved().transition(SessionState.COMPLETED)


def test_session_dict_is_json_serializable() -> None:
    payload = start(_approved(), now=INSIDE).to_dict()
    assert json.loads(json.dumps(payload))["state"] == "running"
    assert payload["gate"]["approved_by"] == ["sre@example"]
    assert payload["window"]["starts_at"] == "2026-09-26T00:00:00Z"


def test_check_approval_returns_the_gate_when_satisfied() -> None:
    gate = check_approval(_approved(), now=INSIDE)
    assert gate.approved_by == ("sre@example",)


def test_session_state_is_persisted_separately_from_campaign_state(tmp_path) -> None:
    from mayhem.infra.game_day_repository import GameDayRepository
    from mayhem.infra.store import Store

    store = Store.open_migrated(tmp_path / "gd.db")
    try:
        repo = GameDayRepository(store)
        repo.save(start(_approved(), now=INSIDE))
        tables = {
            str(dict(row)["name"])
            for row in store.query("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "game_day_sessions" in tables
        assert repo.load("gd-1").state is SessionState.RUNNING
    finally:
        store.close()
