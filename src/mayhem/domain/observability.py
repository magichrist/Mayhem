"""Declarative observability/metrics source DSL (ADR-M4-4 §22).

An ``observability`` section on a drill spec collects *evidence* into the
outcome record — the values an evaluator later needs — without driving the
run's own verdict. Every source is:

- **named** (``source_id``) so observations can be cross-referenced,
- **bounded** (per-source ``timeout`` and an overall ``total_timeout``), and
- **best-effort** (a failing source is recorded as a skip note, never fatal).

Source kinds: container logs tail, container inspect, an external probe
(HTTP/exec/TCP/process/metric/file — the same closed union as checks) and a
Prometheus text-format metrics scrape.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.checks import Probe
from mayhem.domain.common import Duration, parse_duration
from mayhem.domain.errors import SchemaValidationError


def duration_seconds(value: object) -> float:
    """Coerce a ``Duration`` to seconds, tolerating un-validated string defaults.

    Pydantic v2 returns a class-level string default (e.g. ``"10s"``) *without*
    running the duration validators, so naive ``float()`` calls would raise.
    """
    if isinstance(value, str):
        return parse_duration(value)
    if isinstance(value, (int, float)):
        return float(value)
    raise TypeError(f"cannot interpret {value!r} as a duration")


class ObservabilitySourceKind(StrEnum):
    """Kinds of observability evidences a drill can collect (ADR-M4-4)."""

    LOGS = "logs"
    INSPECTION = "inspection"
    PROBE = "probe"
    METRICS = "metrics"


class LogsSource(BaseModel):
    """Container log tail (Docker/Podman ``logs``) captured as evidence."""

    model_config = ConfigDict(frozen=True)

    kind: Literal[ObservabilitySourceKind.LOGS] = ObservabilitySourceKind.LOGS
    source_id: str
    container: str  # container name from the drill's containers:
    tail: int = Field(default=100, ge=1, le=10_000)  # bounded tail, never unbounded
    since: str = ""  # optional engine `--since` filter; empty = latest tail
    timeout: Duration = 10.0


class InspectionSource(BaseModel):
    """Container runtime inspect JSON captured as key/value evidence."""

    model_config = ConfigDict(frozen=True)

    kind: Literal[ObservabilitySourceKind.INSPECTION] = ObservabilitySourceKind.INSPECTION
    source_id: str
    container: str
    timeout: Duration = 10.0


class ProbeSource(BaseModel):
    """An external probe observed on a cadence inside the run window."""

    model_config = ConfigDict(frozen=True)

    kind: Literal[ObservabilitySourceKind.PROBE] = ObservabilitySourceKind.PROBE
    source_id: str
    probe: Probe
    cadence: Duration = 0.0  # >0 polls repeatedly; 0 = collect once
    timeout: Duration = 10.0


class MetricsSource(BaseModel):
    """Prometheus text-format scrape of one metric, sampled on a cadence."""

    model_config = ConfigDict(frozen=True)

    kind: Literal[ObservabilitySourceKind.METRICS] = ObservabilitySourceKind.METRICS
    source_id: str
    endpoint: str  # e.g. http://127.0.0.1:9100/metrics
    metric: str  # Prometheus metric name to resolve to a sample value
    cadence: Duration = 0.0
    timeout: Duration = 10.0


ObservabilitySource = Annotated[
    LogsSource | InspectionSource | ProbeSource | MetricsSource,
    Field(discriminator="kind"),
]


class ObservabilityConfig(BaseModel):
    """One bounding ``observability`` section on a drill spec."""

    model_config = ConfigDict(frozen=True)

    sources: tuple[ObservabilitySource, ...] = ()
    cadence: Duration = 5.0  # default polling cadence where cadence > 0
    total_timeout: Duration = 30.0  # hard bound across the whole pass

    @model_validator(mode="after")
    def _bounds_hold(self) -> ObservabilityConfig:
        total = duration_seconds(self.total_timeout)
        default_cadence = duration_seconds(self.cadence)
        if total <= 0:
            raise SchemaValidationError("total_timeout", "must be > 0")
        if default_cadence < 0:
            raise SchemaValidationError("cadence", "must be >= 0")
        visited: set[str] = set()
        for source in self.sources:
            if source.source_id in visited:
                raise SchemaValidationError(
                    "sources",
                    f"duplicate source_id {source.source_id!r}",
                )
            visited.add(source.source_id)
            if duration_seconds(source.timeout) > total:
                raise SchemaValidationError(
                    f"sources[{source.source_id}]",
                    f"timeout {duration_seconds(source.timeout)}s exceeds total_timeout {total}s",
                )
            cadence = getattr(source, "cadence", "0s")
            if duration_seconds(cadence) > 0 and duration_seconds(cadence) > total:
                raise SchemaValidationError(
                    f"sources[{source.source_id}]",
                    f"cadence {duration_seconds(cadence)}s exceeds total_timeout {total}s; "
                    "no sampling window remains",
                )
        return self

    @property
    def empty(self) -> bool:
        return not self.sources
