"""Observation engine — structured event log for experiment runs (ADR-0020).

An ``Observation`` is a timestamped, typed event that occurred during an
experiment — fault injected, probe measured, recovery attempted, threshold
breached, etc. The ``ObservationLog`` is an append-only, in-memory store
that can be serialized to JSON for persistence or display.

Observations are the raw material that the evaluation system consumes.
They are never mutated after creation.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.common import utc_now


class ObservationKind(StrEnum):
    """Categories of observations that can occur during an experiment."""

    FAULT_INJECTED = "fault.injected"
    FAULT_UNDONE = "fault.undone"
    PROBE_MEASURED = "probe.measured"
    THRESHOLD_BREACHED = "threshold.breached"
    RECOVERY_ATTEMPTED = "recovery.attempted"
    RECOVERY_SUCCEEDED = "recovery.succeeded"
    RECOVERY_FAILED = "recovery.failed"
    STEP_STARTED = "step.started"
    STEP_COMPLETED = "step.completed"
    STEP_FAILED = "step.failed"
    ANOMALY_DETECTED = "anomaly.detected"


class Observation(BaseModel):
    """A single immutable observation event."""

    model_config = ConfigDict(frozen=True)

    kind: ObservationKind
    run_id: str
    timestamp: str = Field(default_factory=lambda: utc_now().isoformat())
    source: str = ""  # e.g. "executor", "janitor", "probe_runner"
    data: dict[str, Any] = Field(default_factory=dict)


class ObservationLog:
    """Append-only observation log with query helpers.

    The log lives in memory for the duration of a run. Periodic snapshots
    can be flushed to SQLite or JSON for durability.
    """

    def __init__(self) -> None:
        self._observations: list[Observation] = []

    def record(self, observation: Observation) -> None:
        """Append an observation to the log."""
        self._observations.append(observation)

    def emit(
        self,
        kind: ObservationKind,
        run_id: str,
        *,
        source: str = "",
        **data: Any,
    ) -> None:
        """Shorthand: create and record in one call."""
        self.record(
            Observation(kind=kind, run_id=run_id, source=source, data=data)
        )

    @property
    def observations(self) -> tuple[Observation, ...]:
        return tuple(self._observations)

    def for_run(self, run_id: str) -> tuple[Observation, ...]:
        """All observations for a specific run."""
        return tuple(o for o in self._observations if o.run_id == run_id)

    def for_kind(
        self, kind: ObservationKind, *, run_id: str | None = None
    ) -> tuple[Observation, ...]:
        """All observations of a given kind, optionally filtered by run."""
        result = (o for o in self._observations if o.kind == kind)
        if run_id is not None:
            result = (o for o in result if o.run_id == run_id)
        return tuple(result)

    def anomalies_for_run(self, run_id: str) -> tuple[Observation, ...]:
        """All anomaly observations for a run."""
        return self.for_kind(ObservationKind.ANOMALY_DETECTED, run_id=run_id)

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        """Serialize all observations to JSON-compatible dicts."""
        return tuple(o.model_dump(mode="json") for o in self._observations)

    def __len__(self) -> int:
        return len(self._observations)
