"""Risk ladder ordering invariants."""

import pytest

from tgondi.domain.risks import EnvironmentClass, RiskLevel


def test_ladder_is_totally_ordered() -> None:
    ranks = [level.rank for level in RiskLevel]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        (RiskLevel.LOW, RiskLevel.MEDIUM),
        (RiskLevel.MEDIUM, RiskLevel.HIGH),
        (RiskLevel.HIGH, RiskLevel.CRITICAL),
        (RiskLevel.LOW, RiskLevel.CRITICAL),
    ],
)
def test_at_least_and_exceeds(lower: RiskLevel, higher: RiskLevel) -> None:
    assert higher.at_least(lower)
    assert lower.at_least(higher) or higher.at_least(lower)
    assert not lower.exceeds(higher)
    assert higher.exceeds(lower)
    assert higher.next_higher().at_least(higher)


def test_next_higher_climbs_to_critical() -> None:
    level = RiskLevel.LOW
    seen = [level]
    for _ in range(3):
        level = level.next_higher()
        seen.append(level)
    assert seen[-1] is RiskLevel.CRITICAL
    assert RiskLevel.CRITICAL.next_higher() is RiskLevel.CRITICAL


def test_production_flag() -> None:
    assert EnvironmentClass.PRODUCTION.is_production
    assert not EnvironmentClass.STAGING.is_production
