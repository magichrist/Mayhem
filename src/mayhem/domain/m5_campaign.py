"""M5 campaign semantics (ADR-M5-4, M5 Phase 5.4).

A campaign is a *goal + bounds*: a target set, a coverage target or stop
condition, an execution budget (blast-radius bound), a ``mode``
(``supervised`` | ``autonomous``), an optional deadline, and a per-campaign
risk ceiling. A campaign produces many Run/Outcome pairs and completes when the
stop condition is reached, the budget is exhausted, or the deadline passes.

This is a distinct model from the ADR-0022 ``Campaign`` used by the scheduler;
ADR-M5-4 campaigns are the intelligence-loop container.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mayhem.domain.risks import RiskLevel


class CampaignMode(StrEnum):
    SUPERVISED = "supervised"  # human approves each drill (default)
    AUTONOMOUS = "autonomous"  # auto-run within bounds, explicit opt-in


class CampaignState(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"
    ABORTED = "aborted"


class StopReason(StrEnum):
    COVERAGE_REACHED = "coverage_reached"
    BUDGET_EXHAUSTED = "budget_exhausted"
    DEADLINE_PASSED = "deadline_passed"
    STOP_CONDITION = "stop_condition"
    RESOURCE_CONFLICT = "resource_conflict"  # hard bound-abort; never executed
    NOT_STARTED = "not_started"


class ApproveDecision(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass(frozen=True)
class CampaignLogEntry:
    """One recorded decision in a campaign's approve/deny trail."""

    candidate_id: str
    decision: ApproveDecision
    rationale: str = ""
    run_id: str | None = None
    outcome_id: str | None = None


@dataclass(frozen=True)
class M5Campaign:
    """Goal + bounds for one intelligence-loop campaign (ADR-M5-4)."""

    id: str
    name: str
    targets: tuple[str, ...] = ()
    coverage_target: int = 1  # distinct cells to cover
    max_runs: int = 100  # blast-radius budget = max executed runs
    mode: CampaignMode = CampaignMode.SUPERVISED
    risk_ceiling: RiskLevel = RiskLevel.HIGH
    deadline_epoch_s: float | None = None
    stop_condition: str = ""  # free-form durable note; caller enforces it

    def with_defaults(self, **kwargs: Any) -> M5Campaign:
        """Return a copy with overridden bounds (immutable-equivalent helper)."""
        return M5Campaign(**{**self.__dict__, **kwargs})


@dataclass
class CampaignProgress:
    """Live counters of one campaign iteration."""

    runs_executed: int = 0
    cells_covered: int = 0
    candidates_rejected: int = 0
    candidates_pending_approval: int = 0
    candidates_denied: int = 0
    candidates_aborted: int = 0
    log: list[CampaignLogEntry] = field(default_factory=list)

    def snapshot(self) -> dict[str, int]:
        return {
            "runs_executed": self.runs_executed,
            "cells_covered": self.cells_covered,
            "candidates_rejected": self.candidates_rejected,
            "candidates_pending_approval": self.candidates_pending_approval,
            "candidates_denied": self.candidates_denied,
            "candidates_aborted": self.candidates_aborted,
        }

    def record(
        self,
        candidate_id: str,
        decision: ApproveDecision,
        *,
        rationale: str = "",
        run_id: str | None = None,
        outcome_id: str | None = None,
    ) -> None:
        """Append one decision to the approve/deny trail."""
        self.log.append(
            CampaignLogEntry(
                candidate_id=candidate_id,
                decision=decision,
                rationale=rationale,
                run_id=run_id,
                outcome_id=outcome_id,
            )
        )
