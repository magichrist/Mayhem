"""Risk ladder and environment classification (ADR-0012).

The ladder is *ordered* so gates can compare; enforcement lives in the safety
engine, but the ordering itself is a domain fact.
"""

from __future__ import annotations

from enum import StrEnum


class RiskLevel(StrEnum):
    """Ordered severity ladder: low < medium < high < critical."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    def at_least(self, other: RiskLevel) -> bool:
        """True when this level is greater than or equal to ``other``."""
        return self.rank >= other.rank

    def exceeds(self, ceiling: RiskLevel) -> bool:
        """True when this level is strictly above the policy ceiling."""
        return self.rank > ceiling.rank

    def next_higher(self) -> RiskLevel:
        """One step up the ladder; critical returns itself."""
        return _NEXT_HIGHER[self]


_RANKS: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

_NEXT_HIGHER: dict[RiskLevel, RiskLevel] = {
    RiskLevel.LOW: RiskLevel.MEDIUM,
    RiskLevel.MEDIUM: RiskLevel.HIGH,
    RiskLevel.HIGH: RiskLevel.CRITICAL,
    RiskLevel.CRITICAL: RiskLevel.CRITICAL,
}


class EnvironmentClass(StrEnum):
    """Deployment class driving safety defaults (ADR-0012 §3)."""

    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def is_production(self) -> bool:
        return self is EnvironmentClass.PRODUCTION
