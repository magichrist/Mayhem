"""Controlled game-day sessions (v0.9.0 expansion task 17).

A game day is a *human* activity: a change window, a named approver, an
operator who can pause, and an evidence bundle at the end. This module holds
the session state and the approval rules. It deliberately has no second
approval model — every gate here resolves to the same
:class:`~mayhem.domain.execution_intent.ExecutionIntent` used by `mayhem run`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

GAME_DAY_SCHEMA_VERSION = "1.0"

PLANNED = "planned"
AWAITING_APPROVAL = "awaiting_approval"
APPROVED = "approved"
RUNNING = "running"
PAUSED = "paused"
COMPLETED = "completed"
ABORTED = "aborted"

SESSION_STATES: tuple[str, ...] = (
    PLANNED,
    AWAITING_APPROVAL,
    APPROVED,
    RUNNING,
    PAUSED,
    COMPLETED,
    ABORTED,
)

_TRANSITIONS: dict[str, frozenset[str]] = {
    PLANNED: frozenset({AWAITING_APPROVAL, ABORTED}),
    AWAITING_APPROVAL: frozenset({APPROVED, ABORTED}),
    APPROVED: frozenset({RUNNING, ABORTED}),
    RUNNING: frozenset({PAUSED, COMPLETED, ABORTED}),
    PAUSED: frozenset({RUNNING, ABORTED}),
    COMPLETED: frozenset(),
    ABORTED: frozenset(),
}


class GameDayError(ValueError):
    """Refusal from a game-day gate; the message says what would unblock it."""


class SessionState(StrEnum):
    PLANNED = PLANNED
    AWAITING_APPROVAL = AWAITING_APPROVAL
    APPROVED = APPROVED
    RUNNING = RUNNING
    PAUSED = PAUSED
    COMPLETED = COMPLETED
    ABORTED = ABORTED


class FreezeWindow(BaseModel):
    """The change window a game day is allowed to run inside."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    starts_at: str
    ends_at: str

    def contains(self, now: datetime) -> bool:
        return _parse(self.starts_at) <= now <= _parse(self.ends_at)

    def to_dict(self) -> dict[str, Any]:
        return {"starts_at": self.starts_at, "ends_at": self.ends_at}


class OperatorAcknowledgement(BaseModel):
    """A named human accepting responsibility for one decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    actor: str
    role: str = "operator"
    reason: str = ""
    at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ApprovalGate(BaseModel):
    """Who must approve, and whether one approver is enough."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    required_approvers: int = 1
    approvers: tuple[OperatorAcknowledgement, ...] = ()
    critical_faults: tuple[str, ...] = ()
    dual_control_for_critical: bool = True

    @property
    def approved_by(self) -> tuple[str, ...]:
        return tuple(approver.actor for approver in self.approvers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "required_approvers": self.required_approvers,
            "approvers": [approver.to_dict() for approver in self.approvers],
            "approved_by": list(self.approved_by),
            "critical_faults": list(self.critical_faults),
            "dual_control_for_critical": self.dual_control_for_critical,
        }


class GameDaySession(BaseModel):
    """Persisted separately from campaign state, as the plan requires."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    name: str = ""
    state: SessionState = SessionState.PLANNED
    window: FreezeWindow | None = None
    gate: ApprovalGate = Field(default_factory=ApprovalGate)
    plan_id: str = ""
    campaign_id: str = ""
    critical_faults: tuple[str, ...] = ()
    evidence_bundle: str = ""
    created_at: str = ""
    updated_at: str = ""
    notes: str = ""
    schema_version: str = GAME_DAY_SCHEMA_VERSION

    def transition(self, new_state: SessionState, *, at: str = "") -> GameDaySession:
        if new_state.value not in _TRANSITIONS[self.state.value]:
            raise GameDayError(
                f"cannot move game-day session from {self.state.value!r} to {new_state.value!r}"
            )
        return self.model_copy(update={"state": new_state, "updated_at": at or self.updated_at})

    def with_approval(self, acknowledgement: OperatorAcknowledgement) -> GameDaySession:
        return self.model_copy(
            update={
                "gate": self.gate.model_copy(
                    update={"approvers": (*self.gate.approvers, acknowledgement)}
                )
            }
        )

    def to_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["state"] = self.state.value
        payload["gate"] = self.gate.to_dict()
        payload["window"] = self.window.to_dict() if self.window else None
        return payload


def check_approval(session: GameDaySession, *, now: datetime | None = None) -> ApprovalGate:
    """Return the gate when the session may start, else raise with the reason."""
    moment = now or datetime.now(UTC)
    if session.window is not None and not session.window.contains(moment):
        raise GameDayError(
            f"game day {session.id!r} is outside its freeze window "
            f"({session.window.starts_at} → {session.window.ends_at})"
        )
    approvers = {approver.actor for approver in session.gate.approvers}
    if len(approvers) < session.gate.required_approvers:
        raise GameDayError(
            f"game day {session.id!r} needs {session.gate.required_approvers} approval(s); "
            f"have {len(approvers)}"
        )
    if session.gate.dual_control_for_critical and session.critical_faults:
        if len(approvers) < 2:
            raise GameDayError(
                f"game day {session.id!r} schedules critical fault(s) "
                f"{list(session.critical_faults)} and requires dual control: two distinct approvers"
            )
    return session.gate


def start(session: GameDaySession, *, now: datetime | None = None) -> GameDaySession:
    """Approve-checked transition into ``running``. Reuses ExecutionIntent gates."""
    if session.state is SessionState.PLANNED:
        session = session.transition(SessionState.AWAITING_APPROVAL)
    if session.state is SessionState.AWAITING_APPROVAL:
        check_approval(session, now=now)
        session = session.transition(SessionState.APPROVED)
    return session.transition(SessionState.RUNNING)


def pause(
    session: GameDaySession, operator: OperatorAcknowledgement, *, at: str = ""
) -> GameDaySession:
    """Operator pause; only meaningful while running."""
    if session.state is not SessionState.RUNNING:
        raise GameDayError(f"cannot pause a session in {session.state.value!r}")
    if not operator.actor:
        raise GameDayError("an operator pause must name the operator")
    return session.transition(SessionState.PAUSED, at=at)


def complete(session: GameDaySession, evidence_bundle: str, *, at: str = "") -> GameDaySession:
    """Finish the session with its evidence bundle recorded."""
    if session.state not in {SessionState.RUNNING, SessionState.PAUSED}:
        raise GameDayError(f"cannot complete a session in {session.state.value!r}")
    if not evidence_bundle:
        raise GameDayError("a completed game day must record its evidence bundle")
    return session.model_copy(
        update={
            "state": SessionState.COMPLETED,
            "evidence_bundle": evidence_bundle,
            "updated_at": at,
        }
    )


def _parse(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
