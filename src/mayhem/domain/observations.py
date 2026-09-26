"""Provider-neutral observation + SLO criterion contracts (v0.9.0 task 13).

An observation is *what a provider measured*; a criterion is *what Mayhem
judged against it*. Keeping the two apart is what lets an HTTP check today and
a Prometheus or Loki query tomorrow satisfy the same evidence contract without
changing the success logic.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

OBSERVATION_SCHEMA_VERSION = "1.0"

PROVENANCE_LOCAL = "local"
PROVENANCE_HTTP = "http"
PROVENANCE_PROMETHEUS = "prometheus"
PROVENANCE_LOKI = "loki"
PROVENANCE_PROCESS = "process"


class CriterionKind(StrEnum):
    """Supported SLO criteria, each with explicit units and failure semantics."""

    LATENCY = "latency"
    ERROR_BUDGET = "error_budget"
    RECOVERY_TIME = "recovery_time"
    SATURATION = "saturation"
    ABSENCE = "absence"


class CriterionOperator(StrEnum):
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"
    EQ = "eq"


class ObservationStatus(StrEnum):
    OK = "ok"
    MISSING = "missing"
    ERROR = "error"
    REDACTED = "redacted"


@dataclass(frozen=True, slots=True)
class ObservationQuery:
    """What to measure, in provider-neutral terms."""

    metric: str
    window_s: float = 60.0
    unit: str = "ms"
    target: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    aggregation: str = "avg"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ObservationResult:
    """One measurement plus where it came from.

    ``value is None`` with ``status=MISSING`` is the honest answer when a
    provider could not measure; it never silently becomes ``0.0``.
    """

    metric: str
    value: float | None
    unit: str
    window_s: float
    status: ObservationStatus = ObservationStatus.OK
    provenance: str = PROVENANCE_LOCAL
    source: str = ""
    detail: str = ""

    @property
    def available(self) -> bool:
        return self.status is ObservationStatus.OK and self.value is not None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        payload["available"] = self.available
        return payload


@dataclass(frozen=True, slots=True)
class SloCriterion:
    """A threshold judgement over an observation."""

    kind: CriterionKind
    metric: str
    operator: CriterionOperator
    threshold: float
    unit: str = "ms"
    window_s: float = 60.0
    name: str = ""

    @property
    def criterion_id(self) -> str:
        return self.name or f"{self.kind.value}:{self.metric}"

    def evaluate(self, observation: ObservationResult) -> CriterionOutcome:
        """Missing observations fail loudly instead of passing by accident."""
        if not observation.available:
            return CriterionOutcome(
                criterion_id=self.criterion_id,
                kind=self.kind,
                passed=False,
                reason=f"observation unavailable ({observation.status.value})",
                observed=None,
                threshold=self.threshold,
                unit=self.unit,
            )
        assert observation.value is not None
        value = observation.value
        passed = {
            CriterionOperator.LT: value < self.threshold,
            CriterionOperator.LTE: value <= self.threshold,
            CriterionOperator.GT: value > self.threshold,
            CriterionOperator.GTE: value >= self.threshold,
            CriterionOperator.EQ: value == self.threshold,
        }[self.operator]
        return CriterionOutcome(
            criterion_id=self.criterion_id,
            kind=self.kind,
            passed=passed,
            reason="" if passed else f"{value}{self.unit} violates {self.operator.value} {self.threshold}{self.unit}",
            observed=value,
            threshold=self.threshold,
            unit=self.unit,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["kind"] = self.kind.value
        payload["operator"] = self.operator.value
        payload["criterion_id"] = self.criterion_id
        return payload


@dataclass(frozen=True, slots=True)
class CriterionOutcome:
    criterion_id: str
    kind: CriterionKind
    passed: bool
    reason: str
    observed: float | None
    threshold: float
    unit: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["kind"] = self.kind.value
        return payload


@runtime_checkable
class ObservationProvider(Protocol):
    """The only contract a provider must satisfy — HTTP today, Prometheus later."""

    name: str

    def observe(self, query: ObservationQuery) -> ObservationResult:  # pragma: no cover - protocol
        ...


def collect(
    provider: ObservationProvider, queries: tuple[ObservationQuery, ...]
) -> tuple[ObservationResult, ...]:
    """Collect every query, converting a provider crash into an error result."""
    results: list[ObservationResult] = []
    for query in queries:
        try:
            result = provider.observe(query)
        except Exception as exc:  # a broken provider must not look like a pass
            results.append(
                ObservationResult(
                    metric=query.metric,
                    value=None,
                    unit=query.unit,
                    window_s=query.window_s,
                    status=ObservationStatus.ERROR,
                    provenance=getattr(provider, "name", PROVENANCE_LOCAL),
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )
            continue
        results.append(result)
    return tuple(results)


def evaluate_all(
    criteria: tuple[SloCriterion, ...], observations: tuple[ObservationResult, ...]
) -> tuple[CriterionOutcome, ...]:
    """Evaluate criteria against observations, matching on metric name."""
    by_metric = {observation.metric: observation for observation in observations}
    return tuple(
        criterion.evaluate(
            by_metric.get(
                criterion.metric,
                ObservationResult(
                    metric=criterion.metric,
                    value=None,
                    unit=criterion.unit,
                    window_s=criterion.window_s,
                    status=ObservationStatus.MISSING,
                    provenance=PROVENANCE_LOCAL,
                    detail="no provider returned this metric",
                ),
            )
        )
        for criterion in criteria
    )


def provenance_summary(observations: tuple[ObservationResult, ...]) -> dict[str, Any]:
    """Evidence-friendly provenance record: counts only, never raw payloads."""
    return {
        "schema_version": OBSERVATION_SCHEMA_VERSION,
        "count": len(observations),
        "available": sum(1 for observation in observations if observation.available),
        "missing": sum(1 for observation in observations if not observation.available),
        "sources": sorted({observation.provenance for observation in observations if observation.provenance}),
    }
