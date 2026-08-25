"""Load generation strategy models (ADR-0021).

Defines load patterns that the controller can orchestrate during chaos
experiments — ramping, steady, burst, and spike profiles with configurable
concurrency, duration, and ramp phases.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.common import Duration


class LoadPattern(StrEnum):
    """Named load patterns for experiment orchestration."""

    CONSTANT = "constant"  # fixed rate for the entire duration
    RAMP_UP = "ramp_up"  # linearly increase from min to max
    RAMP_DOWN = "ramp_down"  # linearly decrease from max to min
    BURST = "burst"  # short high-intensity burst
    SPIKE = "spike"  # sudden jump then return
    STEP = "step"  # step function: low → high → low


class LoadPhase(BaseModel):
    """One phase in a multi-phase load profile."""

    model_config = ConfigDict(frozen=True)

    pattern: LoadPattern
    vus: int = Field(ge=1, default=1)  # virtual users / concurrency
    rps: int | None = Field(default=None, ge=1)  # requests per second (alternative to VUs)
    duration: Duration = 10.0
    ramp_seconds: Duration = 0.0  # ramp time for RAMP_UP/RAMP_DOWN
    target_vus: int | None = Field(default=None, ge=1)  # endpoint for ramp patterns
    target_rps: int | None = Field(default=None, ge=1)


class LoadStrategy(BaseModel):
    """A complete load generation strategy: one or more phases.

    Phases execute sequentially. The total experiment duration is the sum
    of all phase durations. Between phases, there is no pause (zero-load gap
    is explicit via a phase with vus=1, duration=gap).
    """

    model_config = ConfigDict(frozen=True)

    name: str = ""
    phases: tuple[LoadPhase, ...] = (LoadPhase(pattern=LoadPattern.CONSTANT),)
    endpoint: str = ""  # target URL or service
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: Duration = 10.0

    def total_duration(self) -> float:
        """Sum of all phase durations in seconds."""
        return sum(p.duration for p in self.phases)

    def max_concurrency(self) -> int:
        """Peak VUs across all phases."""
        return max(p.vus for p in self.phases)

    @classmethod
    def constant_profile(cls, vus: int, duration: Duration) -> LoadStrategy:
        """Shorthand: single constant-rate phase."""
        return cls(
            phases=(LoadPhase(pattern=LoadPattern.CONSTANT, vus=vus, duration=duration),)
        )

    @classmethod
    def ramp_profile(
        cls, start_vus: int, end_vus: int, duration: Duration
    ) -> LoadStrategy:
        """Shorthand: single ramp-up phase."""
        return cls(
            phases=(
                LoadPhase(
                    pattern=LoadPattern.RAMP_UP,
                    vus=start_vus,
                    target_vus=end_vus,
                    duration=duration,
                    ramp_seconds=duration,
                ),
            )
        )


class FuzzStrategy(BaseModel):
    """Configuration for protocol fuzzing during an experiment."""

    model_config = ConfigDict(frozen=True)

    target_field: str = ""  # which field to mutate (empty = all)
    mutations_per_request: int = Field(default=1, ge=1)
    max_requests: int = Field(default=100, ge=1)
    timeout: Duration = 30.0
    seed: int | None = None  # deterministic fuzzing
    dictionary: tuple[str, ...] = ()  # custom mutation dictionary
