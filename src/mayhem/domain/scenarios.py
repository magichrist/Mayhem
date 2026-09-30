"""Scenario variables and conditional steps (v0.9.0 expansion task 14).

A scenario is *data*: typed variables, time windows, and conditional steps that
are resolved at compile time. Compilation is pure and deterministic — the same
variables and seed always produce the same plan — and the original scenario
source is preserved so evidence can show what the operator actually wrote.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from datetime import time as dtime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

if TYPE_CHECKING:
    from collections.abc import Callable

SCENARIO_SCHEMA_VERSION = "1.0"


class VariableType(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    DURATION = "duration"
    ENUM = "enum"


class ConditionOperator(StrEnum):
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER = "gt"
    GREATER_EQUAL = "gte"
    LESS = "lt"
    LESS_EQUAL = "lte"
    IN = "in"
    CONTAINS = "contains"


class ScenarioError(ValueError):
    """Raised when a scenario cannot compile; the message names the variable."""


class ScenarioVariable(BaseModel):
    """One declared variable with an explicit type and optional constraint."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    type: VariableType = VariableType.STRING
    default: Any = None
    required: bool = False
    choices: tuple[Any, ...] = ()
    minimum: float | None = None
    maximum: float | None = None
    pattern: str = ""
    description: str = ""

    @model_validator(mode="after")
    def _check(self) -> ScenarioVariable:
        if self.type is VariableType.ENUM and not self.choices:
            raise ValueError(f"variable {self.name!r} is an enum with no choices")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError(f"variable {self.name!r} has minimum above maximum")
        return self


def _membership(actual: Any, expected: Any) -> bool:
    return actual in (expected or ())


def _contains(actual: Any, expected: Any) -> bool:
    return expected in (actual or ())


# One entry per operator, so `evaluate` stays a single lookup and an explicit
# "unsupported" refusal. Membership is lenient about the empty case: a missing
# container reads as an empty one, which never matches.
_OPERATORS: dict[ConditionOperator, Callable[[Any, Any], bool]] = {
    ConditionOperator.EQUALS: lambda actual, expected: bool(actual == expected),
    ConditionOperator.NOT_EQUALS: lambda actual, expected: bool(actual != expected),
    ConditionOperator.GREATER: lambda actual, expected: bool(float(actual) > float(expected)),
    ConditionOperator.GREATER_EQUAL: lambda actual, expected: bool(
        float(actual) >= float(expected)
    ),
    ConditionOperator.LESS: lambda actual, expected: bool(float(actual) < float(expected)),
    ConditionOperator.LESS_EQUAL: lambda actual, expected: bool(float(actual) <= float(expected)),
    ConditionOperator.IN: _membership,
    ConditionOperator.CONTAINS: _contains,
}


class Condition(BaseModel):
    """A guard over one variable; all conditions in a step must hold."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    variable: str
    operator: ConditionOperator = ConditionOperator.EQUALS
    value: Any = None

    def evaluate(self, resolved: dict[str, Any]) -> bool:
        if self.variable not in resolved:
            raise ScenarioError(f"condition references unknown variable {self.variable!r}")
        compare = _OPERATORS.get(self.operator)
        if compare is None:
            raise ScenarioError(f"unsupported operator {self.operator!r}")
        return compare(resolved[self.variable], self.value)


class TimeWindow(BaseModel):
    """An optional wall-clock window a scenario step is allowed to run in."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    start: str = "00:00"
    end: str = "23:59"

    @model_validator(mode="after")
    def _check(self) -> TimeWindow:
        for label, value in (("start", self.start), ("end", self.end)):
            try:
                dtime.fromisoformat(value)
            except ValueError as exc:
                raise ValueError(f"window {label} is not a HH:MM time: {value!r}") from exc
        return self

    def contains(self, moment: datetime) -> bool:
        current = moment.timetz().replace(tzinfo=None)
        start = dtime.fromisoformat(self.start)
        end = dtime.fromisoformat(self.end)
        if start <= end:
            return start <= current <= end
        # Window wraps midnight, e.g. 22:00-02:00.
        return current >= start or current <= end


class ConditionalStep(BaseModel):
    """A named step that compiles only when its conditions hold."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    when: tuple[Condition, ...] = ()
    action: dict[str, Any] = Field(default_factory=dict)
    window: TimeWindow | None = None
    else_action: dict[str, Any] | None = None

    def enabled(self, resolved: dict[str, Any], now: datetime | None = None) -> bool:
        if self.window is not None and now is not None and not self.window.contains(now):
            return False
        return all(condition.evaluate(resolved) for condition in self.when)


class Scenario(BaseModel):
    """A complete, still-uncompiled scenario."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    variables: tuple[ScenarioVariable, ...] = ()
    steps: tuple[ConditionalStep, ...] = ()
    schema_version: str = SCENARIO_SCHEMA_VERSION

    @model_validator(mode="after")
    def _check(self) -> Scenario:
        names = [variable.name for variable in self.variables]
        duplicates = {name for name in names if names.count(name) > 1}
        if duplicates:
            raise ValueError(f"duplicate scenario variables: {sorted(duplicates)}")
        step_ids = [step.id for step in self.steps]
        duplicate_steps = {sid for sid in step_ids if step_ids.count(sid) > 1}
        if duplicate_steps:
            raise ValueError(f"duplicate scenario steps: {sorted(duplicate_steps)}")
        declared = set(names)
        for step in self.steps:
            for condition in step.when:
                if condition.variable not in declared:
                    raise ScenarioError(
                        f"step {step.id!r} conditions on undeclared variable {condition.variable!r}"
                    )
        return self

    def variable_names(self) -> tuple[str, ...]:
        return tuple(variable.name for variable in self.variables)


@dataclass(frozen=True, slots=True)
class CompiledScenario:
    """The resolved result: values in, ordered steps out, source preserved."""

    scenario_name: str
    values: dict[str, Any]
    steps: tuple[dict[str, Any], ...] = ()
    skipped: tuple[str, ...] = ()
    source: dict[str, Any] = field(default_factory=dict)
    seed: int | None = None
    schema_version: str = SCENARIO_SCHEMA_VERSION

    @property
    def digest(self) -> str:
        """Deterministic identity: same variables + seed ⇒ same digest."""
        payload = {
            "scenario_name": self.scenario_name,
            "values": self.values,
            "steps": list(self.steps),
            "skipped": list(self.skipped),
            "seed": self.seed,
            "schema_version": self.schema_version,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scenario_name": self.scenario_name,
            "values": dict(self.values),
            "steps": list(self.steps),
            "skipped": list(self.skipped),
            "seed": self.seed,
            "digest": self.digest,
            "source": dict(self.source),
        }


#: Duration suffixes are matched longest-first so ``ms`` is never read as ``s``.
_MILLIS_PER_SECOND = 1000.0
_SECONDS_PER_MINUTE = 60.0
_DURATION_SUFFIXES: tuple[tuple[str, Callable[[str], float]], ...] = (
    ("ms", lambda text: float(text[:-2]) / _MILLIS_PER_SECOND),
    ("s", lambda text: float(text[:-1])),
    ("m", lambda text: float(text[:-1]) * _SECONDS_PER_MINUTE),
)

_BOOLEAN_TRUE = frozenset({"true", "yes", "1"})
_BOOLEAN_FALSE = frozenset({"false", "no", "0"})


def _coerce_string(variable: ScenarioVariable, value: Any) -> Any:
    return str(value)


def _coerce_integer(variable: ScenarioVariable, value: Any) -> Any:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ScenarioError(f"variable {variable.name!r} is not an integer: {value!r}") from exc


def _coerce_number(variable: ScenarioVariable, value: Any) -> Any:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ScenarioError(f"variable {variable.name!r} is not a number: {value!r}") from exc


def _coerce_boolean(variable: ScenarioVariable, value: Any) -> Any:
    if isinstance(value, bool):
        return value
    lowered = str(value).strip().lower()
    if lowered in _BOOLEAN_TRUE:
        return True
    if lowered in _BOOLEAN_FALSE:
        return False
    raise ScenarioError(f"variable {variable.name!r} is not a boolean: {value!r}")


def _coerce_duration(variable: ScenarioVariable, value: Any) -> Any:
    text = str(value).strip()
    try:
        for suffix, convert in _DURATION_SUFFIXES:
            if text.endswith(suffix):
                return convert(text)
        return float(text)
    except ValueError as exc:
        raise ScenarioError(f"variable {variable.name!r} is not a duration: {value!r}") from exc


def _coerce_enum(variable: ScenarioVariable, value: Any) -> Any:
    if value not in variable.choices:
        raise ScenarioError(
            f"variable {variable.name!r} must be one of {list(variable.choices)}, got {value!r}"
        )
    return value


_COERCERS: dict[VariableType, Callable[[ScenarioVariable, Any], Any]] = {
    VariableType.STRING: _coerce_string,
    VariableType.INTEGER: _coerce_integer,
    VariableType.NUMBER: _coerce_number,
    VariableType.BOOLEAN: _coerce_boolean,
    VariableType.DURATION: _coerce_duration,
    VariableType.ENUM: _coerce_enum,
}


def _coerce(variable: ScenarioVariable, value: Any) -> Any:
    coerce = _COERCERS.get(variable.type)
    if coerce is None:
        return value
    return coerce(variable, value)


def _check_constraints(variable: ScenarioVariable, value: Any) -> None:
    if variable.type in {VariableType.INTEGER, VariableType.NUMBER, VariableType.DURATION}:
        if variable.minimum is not None and float(value) < variable.minimum:
            raise ScenarioError(
                f"variable {variable.name!r} value {value} is below minimum {variable.minimum}"
            )
        if variable.maximum is not None and float(value) > variable.maximum:
            raise ScenarioError(
                f"variable {variable.name!r} value {value} is above maximum {variable.maximum}"
            )
    if variable.pattern and isinstance(value, str) and not re.search(variable.pattern, value):
        raise ScenarioError(
            f"variable {variable.name!r} value {value!r} does not match {variable.pattern!r}"
        )


def resolve_variables(scenario: Scenario, supplied: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge supplied values with defaults, then validate every constraint."""
    provided = dict(supplied or {})
    unknown = sorted(set(provided) - set(scenario.variable_names()))
    if unknown:
        raise ScenarioError(f"unknown scenario variables: {unknown}")
    resolved: dict[str, Any] = {}
    for variable in scenario.variables:
        if variable.name in provided:
            raw = provided[variable.name]
        elif variable.default is not None:
            raw = variable.default
        elif variable.required:
            raise ScenarioError(f"missing required scenario variable {variable.name!r}")
        else:
            continue
        value = _coerce(variable, raw)
        _check_constraints(variable, value)
        resolved[variable.name] = value
    return resolved


def compile_scenario(
    scenario: Scenario,
    supplied: dict[str, Any] | None = None,
    *,
    seed: int | None = None,
    now: datetime | None = None,
) -> CompiledScenario:
    """Compile a scenario into ordered steps. Pure and deterministic."""
    resolved = resolve_variables(scenario, supplied)
    moment = now or datetime.now(UTC)
    steps: list[dict[str, Any]] = []
    skipped: list[str] = []
    for step in scenario.steps:
        if step.enabled(resolved, moment):
            steps.append({"id": step.id, "action": dict(step.action), "variables": dict(resolved)})
        else:
            skipped.append(step.id)
            if step.else_action is not None:
                steps.append(
                    {
                        "id": f"{step.id}:else",
                        "action": dict(step.else_action),
                        "variables": dict(resolved),
                    }
                )
    return CompiledScenario(
        scenario_name=scenario.name,
        values=resolved,
        steps=tuple(steps),
        skipped=tuple(skipped),
        source=scenario.model_dump(mode="json"),
        seed=seed,
    )


def load_scenario(payload: dict[str, Any]) -> Scenario:
    """Parse a scenario document, reporting validation errors as ScenarioError."""
    try:
        return Scenario.model_validate(payload)
    except ValidationError as exc:
        raise ScenarioError(f"invalid scenario: {exc.errors()[0]['msg']}") from exc
    except ScenarioError:
        raise
