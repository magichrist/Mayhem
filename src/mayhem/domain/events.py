"""Typed event union flowing through the observation hub.

Events are append-only facts. Agents emit them over their channel; the
controller persists them (SQLite) and mirrors them into the run journal.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from mayhem.domain.common import utc_now


class EventKind(StrEnum):
    RUN_STARTED = "run.started"
    RUN_COMPLETED = "run.completed"
    RUN_FAILED = "run.failed"
    RUN_ABORT_REQUESTED = "run.abort_requested"
    RUN_ABORTED = "run.aborted"
    STEP_STARTED = "step.started"
    STEP_FINISHED = "step.finished"
    STEP_SKIPPED = "step.skipped"
    FAULT_INJECTED = "fault.injected"
    FAULT_OBSERVED = "fault.observed"
    FAULT_RECOVERED = "fault.recovered"
    FAULT_FAILED = "fault.failed"
    TOOL_EXECUTED = "tool.executed"
    CHECK_EVALUATED = "check.evaluated"
    LEASE_STATE_CHANGED = "lease.state_changed"
    AGENT_STATE_CHANGED = "agent.state_changed"
    DRIFT_REPORTED = "drift.reported"
    SAFETY_REFUSED = "safety.refused"
    MANIAC_DECISION = "maniac.decision"


class Event(BaseModel):
    """Base envelope; concrete events add typed payloads via ``detail``."""

    model_config = ConfigDict(frozen=True)

    kind: EventKind
    run_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    created_at_epoch_s: float = Field(default_factory=lambda: utc_now().timestamp())

    def render_line(self) -> str:
        """Single-line journal rendering; structured enough to grep."""
        parts = [f"{self.kind.value}"]
        if self.run_id:
            parts.append(f"run={self.run_id}")
        parts.extend(f"{k}={v}" for k, v in sorted(self.detail.items()))
        return " ".join(parts)


EventStream: TypeAdapter[list[Event]] = TypeAdapter(list[Event])
