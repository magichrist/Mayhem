"""Campaign model — orchestrating multiple experiments (ADR-0022).

A ``Campaign`` groups multiple experiments under a single scheduling and
execution umbrella, with start/stop times, concurrency limits, and a
policy for what happens when an experiment fails.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mayhem.domain.common import Duration
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.risks import RiskLevel


class CampaignStatus(StrEnum):
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    APPROVED = "approved"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"
    ARCHIVED = "archived"


_CAMPAIGN_TRANSITIONS: dict[CampaignStatus, frozenset[CampaignStatus]] = {
    CampaignStatus.DRAFT: frozenset({CampaignStatus.APPROVED, CampaignStatus.ABORTED}),
    CampaignStatus.APPROVED: frozenset({CampaignStatus.RUNNING, CampaignStatus.ABORTED}),
    CampaignStatus.SCHEDULED: frozenset({CampaignStatus.RUNNING, CampaignStatus.ABORTED}),
    CampaignStatus.RUNNING: frozenset(
        {CampaignStatus.PAUSED, CampaignStatus.COMPLETED, CampaignStatus.ABORTED}
    ),
    CampaignStatus.PAUSED: frozenset({CampaignStatus.RUNNING, CampaignStatus.ABORTED}),
    CampaignStatus.COMPLETED: frozenset({CampaignStatus.ARCHIVED}),
    CampaignStatus.ABORTED: frozenset({CampaignStatus.ARCHIVED}),
    CampaignStatus.ARCHIVED: frozenset(),
}


def can_transition(current: CampaignStatus | str, new: CampaignStatus | str) -> bool:
    current_value = current if isinstance(current, CampaignStatus) else CampaignStatus(current)
    new_value = new if isinstance(new, CampaignStatus) else CampaignStatus(new)
    return new_value in _CAMPAIGN_TRANSITIONS[current_value]


def transition_campaign(
    current: CampaignStatus | str,
    new: CampaignStatus | str,
    *,
    legacy_start: bool = False,
) -> CampaignStatus:
    current_value = current if isinstance(current, CampaignStatus) else CampaignStatus(current)
    new_value = new if isinstance(new, CampaignStatus) else CampaignStatus(new)
    if not can_transition(current_value, new_value) and not (
        legacy_start
        and current_value is CampaignStatus.DRAFT
        and new_value is CampaignStatus.RUNNING
    ):
        raise ValueError(f"invalid campaign transition {current_value.value} -> {new_value.value}")
    return new_value


class ExperimentOnFailure(StrEnum):
    """What happens when an experiment in a campaign fails."""

    ABORT_CAMPAIGN = "abort_campaign"
    SKIP_AND_CONTINUE = "skip_and_continue"
    RETRY_THEN_ABORT = "retry_then_abort"


class CampaignExperiment(BaseModel):
    """A single experiment entry within a campaign.

    References an experiment spec by name or ID. The actual spec is resolved
    at scheduling time.
    """

    model_config = ConfigDict(frozen=True)

    experiment_ref: str  # name or ID of the experiment
    priority: int = Field(default=0, ge=0)  # higher = runs first
    delay_seconds: Duration = 0.0  # delay after previous experiment completes
    weight: float = 1.0  # for weighted random selection


class CampaignWindow(BaseModel):
    """Time window for campaign execution."""

    model_config = ConfigDict(frozen=True)

    start_epoch_s: float | None = None
    end_epoch_s: float | None = None
    max_duration_s: Duration = 3600.0  # hard stop
    cooldown_between_experiments_s: Duration = 5.0


class CampaignPolicy(BaseModel):
    """Execution policies for a campaign."""

    model_config = ConfigDict(frozen=True)

    on_experiment_failure: ExperimentOnFailure = ExperimentOnFailure.ABORT_CAMPAIGN
    max_concurrent_experiments: int = Field(default=1, ge=1)
    max_risk_level: RiskLevel | None = None  # risk ceiling for all experiments
    total_budget_usd: float | None = None  # cost ceiling (future use)
    require_approval_above: RiskLevel | None = RiskLevel.HIGH


class Campaign(BaseModel):
    """A campaign is a named, schedulable collection of experiments."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    description: str = ""
    status: CampaignStatus = CampaignStatus.DRAFT
    experiments: tuple[CampaignExperiment, ...] = ()
    window: CampaignWindow = Field(default_factory=CampaignWindow)
    policy: CampaignPolicy = Field(default_factory=CampaignPolicy)
    labels: dict[str, str] = Field(default_factory=dict)
    target_profiles: tuple[str, ...] = ()
    engine_policy: str = ""
    budget: int = Field(default=0, ge=0)
    deadline_epoch_s: float | None = None
    stop_conditions: tuple[str, ...] = ()
    execution_manifest: dict[str, object] = Field(default_factory=dict)
    recovery_status: str = "none"

    @field_validator("experiments")
    @classmethod
    def _non_empty_experiments(
        cls, value: tuple[CampaignExperiment, ...]
    ) -> tuple[CampaignExperiment, ...]:
        if not value:
            raise InvariantViolationError(
                "campaign_requires_experiments",
                "a campaign must have at least one experiment",
            )
        return value

    def sorted_experiments(self) -> tuple[CampaignExperiment, ...]:
        """Experiments ordered by priority (descending)."""
        return tuple(sorted(self.experiments, key=lambda e: e.priority, reverse=True))

    def total_weight(self) -> float:
        """Sum of all experiment weights."""
        return sum(e.weight for e in self.experiments)


class CampaignSchedule(BaseModel):
    """A scheduled campaign with execution metadata."""

    model_config = ConfigDict(frozen=True)

    campaign: Campaign
    scheduled_epoch_s: float | None = None
    last_run_epoch_s: float | None = None
    run_count: int = 0
    next_experiment_idx: int = 0
