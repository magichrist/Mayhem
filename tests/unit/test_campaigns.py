"""Tests for campaign model (ADR-0022)."""

import pytest

from mayhem.domain.campaigns import (
    Campaign,
    CampaignExperiment,
    CampaignPolicy,
    CampaignSchedule,
    CampaignStatus,
    ExperimentOnFailure,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.risks import RiskLevel


class TestCampaignStatus:
    def test_all_values(self) -> None:
        assert set(CampaignStatus) == {
            CampaignStatus.DRAFT,
            CampaignStatus.SCHEDULED,
            CampaignStatus.RUNNING,
            CampaignStatus.PAUSED,
            CampaignStatus.COMPLETED,
            CampaignStatus.ABORTED,
        }


class TestCampaign:
    def test_empty_experiments_rejected(self) -> None:
        with pytest.raises(InvariantViolationError, match="campaign_requires_experiments"):
            Campaign(id="c1", name="test", experiments=())

    def test_sorted_experiments(self) -> None:
        c = Campaign(
            id="c1",
            name="test",
            experiments=(
                CampaignExperiment(experiment_ref="low", priority=1),
                CampaignExperiment(experiment_ref="high", priority=10),
                CampaignExperiment(experiment_ref="mid", priority=5),
            ),
        )
        sorted_exp = c.sorted_experiments()
        assert sorted_exp[0].experiment_ref == "high"
        assert sorted_exp[1].experiment_ref == "mid"
        assert sorted_exp[2].experiment_ref == "low"

    def test_total_weight(self) -> None:
        c = Campaign(
            id="c1",
            name="test",
            experiments=(
                CampaignExperiment(experiment_ref="a", weight=1.0),
                CampaignExperiment(experiment_ref="b", weight=2.5),
            ),
        )
        assert c.total_weight() == 3.5

    def test_default_status_is_draft(self) -> None:
        c = Campaign(id="c1", name="test", experiments=(CampaignExperiment(experiment_ref="a"),))
        assert c.status == CampaignStatus.DRAFT

    def test_json_round_trip(self) -> None:
        c = Campaign(
            id="c1",
            name="smoke-test",
            description="Quick smoke test",
            experiments=(
                CampaignExperiment(experiment_ref="exp1", priority=5, delay_seconds=10),
                CampaignExperiment(experiment_ref="exp2", priority=1),
            ),
            policy=CampaignPolicy(
                on_experiment_failure=ExperimentOnFailure.SKIP_AND_CONTINUE,
                max_concurrent_experiments=2,
                max_risk_level=RiskLevel.MEDIUM,
            ),
            labels={"env": "staging"},
        )
        restored = Campaign.model_validate(c.model_dump(mode="json"))
        assert restored == c


class TestCampaignSchedule:
    def test_defaults(self) -> None:
        c = Campaign(id="c1", name="test", experiments=(CampaignExperiment(experiment_ref="a"),))
        sched = CampaignSchedule(campaign=c)
        assert sched.run_count == 0
        assert sched.next_experiment_idx == 0
        assert sched.last_run_epoch_s is None
