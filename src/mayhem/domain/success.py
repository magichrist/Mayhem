"""Machine-evaluable success criteria over recorded observations (ADR-M4-3 §18).

Success is an objective, machine-evaluable predicate over recorded
observations — never a human eyeball. Criteria are typed assertions
(status / latency / metric / count / boolean) evaluated by the engine over
the observation rows a drill recorded; a drill's success/failure verdict is
derived from them.

Evaluating a criterion against a *missing* observation is **false** — absence
of evidence is not success — and it never raises.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

if TYPE_CHECKING:
    from collections.abc import Mapping


class ObservationKind(StrEnum):
    """The scalar type an observation row records."""

    STATUS = "status"  # integer status (HTTP/exit code)
    LATENCY = "latency_ms"  # milliseconds, float
    METRIC = "metric"  # arbitrary numeric sample
    COUNT = "count"  # integer count
    BOOLEAN = "boolean"  # boolean outcome


class Observation(BaseModel):
    """One recorded observation row for a named ``source_id`` (step/check id)."""

    model_config = ConfigDict(frozen=True)

    source_id: str
    kind: ObservationKind
    value: float | int | bool | str
    detail: str = ""

    @model_validator(mode="after")
    def _kind_matches_value(self) -> Observation:
        if isinstance(self.value, str):
            return self
        if self.kind is ObservationKind.BOOLEAN:
            if not isinstance(self.value, bool):
                raise ValueError("boolean observation must carry a bool value")
        elif isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
            raise ValueError(f"{self.kind.value} observation must carry a numeric value")
        return self


def observations_for_step(
    source_id: str,
    *,
    ok: bool,
    measured: Mapping[str, object] | None = None,
    detail: str = "",
) -> tuple[Observation, ...]:
    """Normalise a step's outcome + measured extras into observation rows.

    The primary row (bare ``source_id``) records the boolean step outcome;
    each measured scalar is recorded under ``<source_id>.<name>`` so a status
    criterion can address ``step.status`` and a latency criterion
    ``step.latency_ms`` from the same step.
    """
    rows: list[Observation] = [
        Observation(source_id=source_id, kind=ObservationKind.BOOLEAN, value=ok, detail=detail)
    ]
    for name, raw in (measured or {}).items():
        if isinstance(raw, bool):
            rows.append(
                Observation(
                    source_id=f"{source_id}.{name}",
                    kind=ObservationKind.BOOLEAN,
                    value=raw,
                    detail=detail,
                )
            )
        elif isinstance(raw, int):
            kind = ObservationKind.COUNT if not name.endswith("status") else ObservationKind.STATUS
            rows.append(
                Observation(source_id=f"{source_id}.{name}", kind=kind, value=raw, detail=detail)
            )
        elif isinstance(raw, float):
            kind = (
                ObservationKind.LATENCY
                if name.endswith(("ms", "latency", "latency_ms"))
                else ObservationKind.METRIC
            )
            rows.append(
                Observation(source_id=f"{source_id}.{name}", kind=kind, value=raw, detail=detail)
            )
    return tuple(rows)


class CriterionType(StrEnum):
    """Kinds of machine-evaluable assertions (ADR-M4-3)."""

    STATUS = "status"  # measured status equals an expected value
    LATENCY = "latency"  # measured latency (ms) below a bound
    METRIC = "metric"  # numeric metric within bounds
    COUNT = "count"  # recorded count at least a minimum
    BOOLEAN = "boolean"  # recorded outcome equals a boolean


class StatusCriterion(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[CriterionType.STATUS] = CriterionType.STATUS
    source_id: str  # observation source, e.g. "check-0000-0.status"
    expected: int


class LatencyCriterion(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[CriterionType.LATENCY] = CriterionType.LATENCY
    source_id: str  # observation source, e.g. "check-0000-0.latency_ms"
    lt_ms: float = Field(gt=0)


class MetricCriterion(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[CriterionType.METRIC] = CriterionType.METRIC
    source_id: str
    gt: float | None = None  # exclusive lower bound
    lt: float | None = None  # exclusive upper bound

    @model_validator(mode="after")
    def _has_bound(self) -> MetricCriterion:
        if self.gt is None and self.lt is None:
            raise ValueError("metric criterion requires gt and/or lt")
        return self


class CountCriterion(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[CriterionType.COUNT] = CriterionType.COUNT
    source_id: str
    gte: int = 1  # inclusive minimum


class BooleanCriterion(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[CriterionType.BOOLEAN] = CriterionType.BOOLEAN
    source_id: str  # the bare step id — its primary boolean outcome
    value: bool = True


Criterion = Annotated[
    StatusCriterion | LatencyCriterion | MetricCriterion | CountCriterion | BooleanCriterion,
    Field(discriminator="type"),
]
_criterion_adapter: TypeAdapter[Criterion] = TypeAdapter(Criterion)


def parse_criterion(data: object) -> Criterion:
    """Parse untyped criterion data into the closed union."""
    return _criterion_adapter.validate_python(data)


class SuccessCriteria(BaseModel):
    """Typed assertions a drill must satisfy to succeed (ADR-M4-3)."""

    model_config = ConfigDict(frozen=True)

    criteria: tuple[Criterion, ...] = ()
    require_all: bool = True

    @property
    def empty(self) -> bool:
        return not self.criteria


class CriterionResult(BaseModel):
    """Evaluation of a single criterion against the recorded observations."""

    model_config = ConfigDict(frozen=True)

    type: CriterionType
    source_id: str
    satisfied: bool
    detail: str = ""

    def summary(self) -> str:
        mark = "PASS" if self.satisfied else "FAIL"
        return f"{self.type.value}:{self.source_id} {mark} ({self.detail})"


class CriteriaEvaluation(BaseModel):
    """Deterministic evaluation of a drill's success criteria."""

    model_config = ConfigDict(frozen=True)

    results: tuple[CriterionResult, ...] = ()
    all_satisfied: bool = True

    @property
    def empty(self) -> bool:
        return not self.results

    def summary_md(self) -> str:
        headline = (
            "**success criteria**: ALL PASS"
            if self.all_satisfied
            else "**success criteria**: FAILED"
        )
        lines = [headline]
        for result in self.results:
            mark = "PASS" if result.satisfied else "FAIL"
            lines.append(f"- [{mark}] {result.summary()}")
        return "\n".join(lines)


def _coerce(observation: Observation, kind: CriterionType) -> float | int | bool | None:  # noqa: PLR0911, PLR0912
    """Coerce an observation to a criterion's numeric/boolean domain.

    Returns None when the recorded kind is not coercible to the criterion's
    kind (e.g. a boolean step outcome asked for a latency bound).
    """
    if kind in (CriterionType.STATUS, CriterionType.COUNT):
        if observation.kind is ObservationKind.BOOLEAN:
            return None
        raw = observation.value
        if isinstance(raw, str):
            try:
                return int(raw)
            except ValueError:
                return None
        return int(raw) if isinstance(raw, (int, float)) and not isinstance(raw, bool) else None
    if kind is CriterionType.LATENCY or kind is CriterionType.METRIC:
        if observation.kind is ObservationKind.BOOLEAN:
            return None
        raw = observation.value
        if isinstance(raw, str):
            try:
                return float(raw)
            except ValueError:
                return None
        return float(raw) if isinstance(raw, (int, float)) and not isinstance(raw, bool) else None
    assert kind is CriterionType.BOOLEAN  # closed enum: last member
    raw = observation.value
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in ("1", "true", "yes", "y"):
            return True
        if normalized in ("0", "false", "no", "n"):
            return False
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return raw in (1, 1.0)
    return None


def _evaluate_one(criterion: Criterion, observations: Mapping[str, Observation]) -> CriterionResult:
    source_id = criterion.source_id
    observation = observations.get(source_id)
    if observation is None:
        return CriterionResult(
            type=criterion.type,
            source_id=source_id,
            satisfied=False,
            detail="no observation recorded",
        )
    value = _coerce(observation, criterion.type)
    if value is None:
        return CriterionResult(
            type=criterion.type,
            source_id=source_id,
            satisfied=False,
            detail=f"recorded kind {observation.kind.value} not comparable",
        )
    if isinstance(criterion, StatusCriterion):
        matched = value == criterion.expected
        detail = f"status={value} expected={criterion.expected}"
    elif isinstance(criterion, LatencyCriterion):
        matched = float(value) < criterion.lt_ms
        detail = f"latency={value}ms bound=<{criterion.lt_ms}ms"
    elif isinstance(criterion, MetricCriterion):
        lower_ok = criterion.gt is None or float(value) > criterion.gt
        upper_ok = criterion.lt is None or float(value) < criterion.lt
        matched = lower_ok and upper_ok
        detail = (
            f"metric={value}"
            + (f" bound=>{criterion.gt}" if criterion.gt is not None else "")
            + (f" bound=<{criterion.lt}" if criterion.lt is not None else "")
        )
    elif isinstance(criterion, CountCriterion):
        matched = int(value) >= criterion.gte
        detail = f"count={value} required>={criterion.gte}"
    elif isinstance(criterion, BooleanCriterion):
        matched = bool(value) is criterion.value
        detail = f"outcome={value} required={criterion.value}"
    else:  # pragma: no cover - closed union
        raise AssertionError(f"unhandled criterion {type(criterion).__name__}")
    return CriterionResult(
        type=criterion.type,
        source_id=source_id,
        satisfied=matched,
        detail=detail,
    )


def evaluate_criteria(
    criteria: SuccessCriteria | None,
    observations: Mapping[str, Observation],
) -> CriteriaEvaluation:
    """Evaluate success criteria over recorded observations (deterministic).

    Missing or incomparable observations evaluate to false; an absent/empty
    criteria block is satisfied (the caller decides whether any verdict is
    derived at all).
    """
    if criteria is None or criteria.empty:
        return CriteriaEvaluation()
    results = tuple(_evaluate_one(criterion, observations) for criterion in criteria.criteria)
    if criteria.require_all:
        all_satisfied = all(r.satisfied for r in results)
    else:
        all_satisfied = any(r.satisfied for r in results)
    return CriteriaEvaluation(results=results, all_satisfied=all_satisfied)
