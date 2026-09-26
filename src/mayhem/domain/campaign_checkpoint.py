"""Durable campaign checkpoints and deterministic resume planning.

A campaign is long-running, so the process holding it can disappear between two
experiments. A checkpoint records *where* each experiment got to, and the resume
planner decides what may run next. Two rules matter most:

* a verified experiment is never re-run without an explicit retry intent; and
* a checkpoint whose environment fingerprint is stale is reported, not silently
  resumed, because the target may no longer be the one that was verified.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

CHECKPOINT_SCHEMA_VERSION = "1.0"

#: States a checkpoint may hold, per the ADR this task implements.
PENDING = "pending"
RUNNING = "running"
VERIFIED = "verified"
COMPENSATING = "compensating"
COMPENSATED = "compensated"
RETRYABLE = "retryable"
BLOCKED = "blocked"
COMPLETED = "completed"
ABORTED = "aborted"

CHECKPOINT_STATES: tuple[str, ...] = (
    PENDING,
    RUNNING,
    VERIFIED,
    COMPENSATING,
    COMPENSATED,
    RETRYABLE,
    BLOCKED,
    COMPLETED,
    ABORTED,
)

#: States that mean "this experiment already did its work".
TERMINAL_STATES: frozenset[str] = frozenset({VERIFIED, COMPLETED, COMPENSATED})
#: States that mean "work is in flight; a resume must not start it again".
IN_FLIGHT_STATES: frozenset[str] = frozenset({RUNNING, COMPENSATING})


class CheckpointState(StrEnum):
    PENDING = PENDING
    RUNNING = RUNNING
    VERIFIED = VERIFIED
    COMPENSATING = COMPENSATING
    COMPENSATED = COMPENSATED
    RETRYABLE = RETRYABLE
    BLOCKED = BLOCKED
    COMPLETED = COMPLETED
    ABORTED = ABORTED


class CampaignCheckpoint(BaseModel):
    """One experiment's durable position inside a campaign."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    experiment_id: str
    state: CheckpointState = CheckpointState.PENDING
    lease_id: str = ""
    attempt: int = 0
    fingerprint: str = ""
    resume_safe: bool = True
    updated_at: str = ""
    detail: str = ""
    schema_version: str = CHECKPOINT_SCHEMA_VERSION

    @property
    def key(self) -> str:
        return f"{self.campaign_id}:{self.experiment_id}"

    @property
    def terminal(self) -> bool:
        return self.state.value in TERMINAL_STATES

    @property
    def in_flight(self) -> bool:
        return self.state.value in IN_FLIGHT_STATES

    def with_state(
        self,
        state: CheckpointState,
        *,
        attempt: int | None = None,
        lease_id: str | None = None,
        detail: str | None = None,
        resume_safe: bool | None = None,
        updated_at: str | None = None,
    ) -> CampaignCheckpoint:
        return self.model_copy(
            update={
                "state": state,
                "attempt": self.attempt if attempt is None else attempt,
                "lease_id": self.lease_id if lease_id is None else lease_id,
                "detail": self.detail if detail is None else detail,
                "resume_safe": self.resume_safe if resume_safe is None else resume_safe,
                "updated_at": self.updated_at if updated_at is None else updated_at,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["state"] = self.state.value
        payload["key"] = self.key
        payload["terminal"] = self.terminal
        return payload


class ResumePlan(BaseModel):
    """What a resume would do — computed before anything runs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    resume: tuple[str, ...] = ()
    skip_verified: tuple[str, ...] = ()
    blocked: tuple[str, ...] = ()
    in_flight: tuple[str, ...] = ()
    stale: tuple[str, ...] = ()
    exhausted: tuple[str, ...] = ()
    fingerprint: str = ""
    schema_version: str = CHECKPOINT_SCHEMA_VERSION

    @property
    def safe(self) -> bool:
        """A plan is safe when nothing in flight and nothing stale blocks it."""
        return not self.in_flight and not self.stale and not self.exhausted

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "fingerprint": self.fingerprint,
            "safe": self.safe,
            "resume": list(self.resume),
            "skip_verified": list(self.skip_verified),
            "blocked": list(self.blocked),
            "in_flight": list(self.in_flight),
            "stale": list(self.stale),
            "exhausted": list(self.exhausted),
        }


def plan_resume(
    checkpoints: tuple[CampaignCheckpoint, ...],
    campaign_id: str,
    *,
    pending_experiments: tuple[str, ...] = (),
    retry_verified: bool = False,
    max_attempts: int = 3,
    current_fingerprint: str = "",
) -> ResumePlan:
    """Decide, deterministically, which experiments a resume may run.

    ``retry_verified`` is the explicit retry intent: without it, a verified
    experiment is skipped rather than repeated.
    """
    by_id = {checkpoint.experiment_id: checkpoint for checkpoint in checkpoints}
    resume: list[str] = []
    skip_verified: list[str] = []
    blocked: list[str] = []
    in_flight: list[str] = []
    stale: list[str] = []
    exhausted: list[str] = []

    for experiment_id in pending_experiments:
        checkpoint = by_id.get(experiment_id)
        if checkpoint is None:
            resume.append(experiment_id)
            continue
        if checkpoint.state is CheckpointState.ABORTED:
            blocked.append(experiment_id)
            continue
        if checkpoint.state is CheckpointState.BLOCKED:
            blocked.append(experiment_id)
            continue
        if checkpoint.in_flight:
            in_flight.append(experiment_id)
            continue
        if checkpoint.terminal and not retry_verified:
            skip_verified.append(experiment_id)
            continue
        if (
            current_fingerprint
            and checkpoint.fingerprint
            and checkpoint.fingerprint != current_fingerprint
        ):
            stale.append(experiment_id)
            continue
        if checkpoint.attempt >= max_attempts:
            exhausted.append(experiment_id)
            continue
        if not checkpoint.resume_safe:
            blocked.append(experiment_id)
            continue
        resume.append(experiment_id)

    return ResumePlan(
        campaign_id=campaign_id,
        resume=tuple(resume),
        skip_verified=tuple(skip_verified),
        blocked=tuple(blocked),
        in_flight=tuple(in_flight),
        stale=tuple(stale),
        exhausted=tuple(exhausted),
        fingerprint=current_fingerprint,
    )
