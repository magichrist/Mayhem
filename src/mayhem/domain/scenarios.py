"""Scenario variables and conditional steps (v0.9.0 expansion task 14), and the
plan 21 scenario library (gap 49).

A scenario is *data*: typed variables, time windows, and conditional steps that
are resolved at compile time. Compilation is pure and deterministic — the same
variables and seed always produce the same plan — and the original scenario
source is preserved so evidence can show what the operator actually wrote.

Two vocabularies live here, and they answer different questions.

The first (task 14, unchanged) is the **operator script**: a conditional
program over variables, compiled to an ordered list of actions. It says *what an
operator does*.

The second (plan 21, added below) is the **scenario library**: versioned
templates over :mod:`mayhem.domain.advisor`'s vocabulary — a hypothesis, a
timeline, stop conditions, and a recovery expectation. It says *what a whole
failure looks like over time*. A library entry is not a script and not a fault
list; it is a claim, and a claim that only lists faults has not claimed anything,
so every field that makes it a claim is required (see
:class:`ScenarioTemplate`). The library exists because a resilience backlog
written as "add a DNS failure test" produces experiments that pass and a system
that still fails.

The two never call each other. An instantiation is a *proposal function* over a
:class:`~mayhem.domain.advisor.Finding`, which is the exact signature
:func:`mayhem.domain.advisor.recommendations_for` takes, so a scenario enters
the advisor through the same door as any other proposal and is compiled, gated,
and sealed by the same road. There is no scenario-only planner.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from datetime import time as dtime
from enum import StrEnum
from itertools import pairwise
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from mayhem.domain.advisor import ExperimentCandidate
from mayhem.domain.coverage import CoverageCell
from mayhem.domain.experiments import DrillContainer, DrillFault, DrillSpec, ExecutionStep
from mayhem.domain.hashing import digest

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.domain.advisor import Finding

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


# =========================================================================== #
# Plan 21 — the scenario library (gap 49)                                   #
# =========================================================================== #

#: The schema version of a *library template*. Separate from
#: :data:`SCENARIO_SCHEMA_VERSION` because these are different documents: that
#: one is an operator script, this one is a versioned claim about a failure
#: mode. A template carries its version in two places — ``schema_version`` (the
#: shape) and ``version`` (the claim) — and an instantiation records both, so a
#: reader can tell "the format changed" from "the scenario changed".
SCENARIO_TEMPLATE_SCHEMA_VERSION = "1.0"

#: The version shape every library entry must declare. Enforced by
#: :class:`ScenarioTemplate` rather than documented, because
#: :meth:`ScenarioLibrary.latest` sorts lexically: without a rule, a template
#: authored as ``1.10`` would sort below ``1.9`` and ``latest`` would quietly hand
#: back the older claim.
_TEMPLATE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


class TimelineStep(BaseModel):
    """One moment in a scenario: a fault, how long it lasts, and what to look at.

    ``expects`` is required and is the reason this is not a fault list. A step
    that names a fault and nothing else is a wish; a step that names a fault
    *and what an observer should see while it is in place* is a falsifiable
    moment in a timeline. The template author has to write that sentence, which
    is the only place the "what would convince us this is real" question gets
    asked before the run rather than after it.

    ``at_s`` is the offset from the start of the scenario. Ordering is checked
    on the template, so a timeline that reads backwards is a refusal rather than
    an experiment that silently runs its faults in the wrong order.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    at_s: float = Field(ge=0.0)
    fault_id: str
    duration_s: float = Field(gt=0.0)
    expects: str

    @model_validator(mode="after")
    def _check(self) -> TimelineStep:
        if not self.fault_id.strip():
            raise ScenarioError(
                "a timeline step must name the fault it injects: an unnamed fault is "
                "not a moment in a scenario"
            )
        if not self.expects.strip():
            raise ScenarioError(
                f"timeline step at {self.at_s:g}s names fault {self.fault_id!r} but says "
                "nothing about what should be observed while it is in place: a fault "
                "with no expectation is a fault list"
            )
        return self


class RecoveryPlan(BaseModel):
    """What recovery means for this scenario, and how anybody would know.

    Three required sentences, and the third is the one that usually goes
    missing: ``verified_by`` names the observation that shows the system came
    back. "Restore service" is an intention; "the readiness probe returns 200 for
    three consecutive intervals with no lease outstanding" is a check, and only
    the second can end a scenario.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    expects: str
    compensation: str
    verified_by: str

    @model_validator(mode="after")
    def _check(self) -> RecoveryPlan:
        for name, value in (
            ("expects", self.expects),
            ("compensation", self.compensation),
            ("verified_by", self.verified_by),
        ):
            if not value.strip():
                raise ScenarioError(
                    f"a recovery plan must state {name}: recovery that names no "
                    "expected end state, no undo, or no way of knowing it happened is "
                    "not a recovery plan"
                )
        return self


class ScenarioTemplate(BaseModel):
    """A versioned claim about how a whole failure looks over time (gap 49).

    Plan 21's sentence — "each scenario is hypothesis plus timeline plus stop
    conditions plus recovery, never just a fault list" — is enforced by the
    constructor rather than by review: ``hypothesis``, ``timeline``,
    ``stop_conditions`` and ``recovery`` are required and non-empty, so the one
    thing this type cannot express is a fault list. Everything else is optional
    detail about a claim that is already complete.

    ``version`` is part of the identity, and the instantiation records it, so a
    scenario that was revised keeps its history instead of silently changing the
    meaning of a report that cites ``scenario:dns-failure@1.0.0``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    template_id: str
    version: str
    title: str
    hypothesis: str
    timeline: tuple[TimelineStep, ...]
    stop_conditions: tuple[str, ...]
    recovery: RecoveryPlan
    blast_scope: str = ""
    schema_version: str = SCENARIO_TEMPLATE_SCHEMA_VERSION

    @model_validator(mode="after")
    def _check(self) -> ScenarioTemplate:
        for name, value in (
            ("template_id", self.template_id),
            ("version", self.version),
            ("title", self.title),
            ("hypothesis", self.hypothesis),
        ):
            if not value.strip():
                raise ScenarioError(
                    f"a scenario template must state {name}: an unnamed scenario cannot "
                    "be cited by a report, versioned, or told apart from the next one"
                )
        if not _TEMPLATE_VERSION_RE.fullmatch(self.version):
            raise ScenarioError(
                f"scenario template version {self.version!r} is not N.N.N: "
                ":meth:`ScenarioLibrary.latest` picks a version by sorting, and a scheme "
                "that does not sort correctly would hand back the older claim without "
                "saying so"
            )
        if not self.timeline:
            raise ScenarioError(
                f"scenario {self.ref!r} declares an empty timeline: a scenario with no "
                "ordered moments is a fault list"
            )
        offsets = [step.at_s for step in self.timeline]
        if any(later < earlier for earlier, later in pairwise(offsets)):
            raise ScenarioError(
                f"scenario {self.ref!r} declares offsets {offsets}, which run backwards: "
                "a timeline that reads backwards is an experiment that injects its "
                "faults in the wrong order"
            )
        if not self.stop_conditions:
            raise ScenarioError(
                f"scenario {self.ref!r} declares no stop conditions: a scenario nobody "
                "can stop is a scenario nobody can safely run"
            )
        for index, condition in enumerate(self.stop_conditions):
            if not condition.strip():
                raise ScenarioError(
                    f"scenario {self.ref!r} stop condition {index} is blank: the rule "
                    "about when to stop is not present when it reads as one"
                )
        return self

    @property
    def ref(self) -> str:
        """``template_id@version`` — the citation form a report uses."""
        return f"{self.template_id}@{self.version}"

    @property
    def fault_ids(self) -> tuple[str, ...]:
        """The timeline's faults, in timeline order."""
        return tuple(step.fault_id for step in self.timeline)

    @property
    def duration_s(self) -> float:
        """How long the whole timeline runs for, last fault included."""
        return max(step.at_s + step.duration_s for step in self.timeline)

    @property
    def digest(self) -> str:
        """Deterministic identity of this template at this version."""
        return digest(self.to_dict())

    def probes(self) -> tuple[str, ...]:
        """One probe per timeline moment, naming the fault and what to watch.

        These are *suggested* probes in the advisor's vocabulary — they travel on
        an :class:`~mayhem.domain.advisor.ExperimentCandidate`, and plan 11 makes
        them binding downstream. The advisor suggests; the policy gate decides.
        """
        return tuple(
            f"{step.fault_id}@{step.at_s:g}s (expect: {step.expects})"
            for step in self.timeline
        )

    def instantiate(
        self,
        *,
        target: str,
        execution_context: str,
        parameter_band: str,
    ) -> ScenarioInstantiation:
        """Bind this template to one declared coverage cell. Pure, and total.

        Every argument is required and there is no default for any of them, for
        the same reason :class:`~mayhem.domain.advisor.CoverageLandscape` requires
        its identifier: a scenario instantiated with an implied execution context
        or band lands in a cell nobody can look up, which is the one thing a
        coverage claim must not do.

        Nothing is read from a clock, and no fault parameter is invented — each
        fault keeps the value
        :mod:`mayhem.domain.catalog`'s own ``params_schema`` default, because
        that default is the catalog's decision and a scenario template's whole
        claim is about the *shape* of a failure, not about a number nobody
        measured.
        """
        for name, value in (
            ("target", target),
            ("execution_context", execution_context),
            ("parameter_band", parameter_band),
        ):
            if not value.strip():
                raise ScenarioError(
                    f"scenario {self.ref!r} cannot be instantiated without {name}: a "
                    "scenario with an implied target dimension occupies a cell that "
                    "nobody can look up"
                )
        return ScenarioInstantiation(
            template_id=self.template_id,
            template_version=self.version,
            schema_version=self.schema_version,
            target=target,
            execution_context=execution_context,
            parameter_band=parameter_band,
            hypothesis=self.hypothesis,
            timeline=self.timeline,
            stop_conditions=(
                *self.stop_conditions,
                f"abort once the declared timeline has run for {self.duration_s:g}s",
                f"do not call the scenario recovered until: {self.recovery.verified_by}",
            ),
            recovery=self.recovery,
            blast_scope=self.blast_scope,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ScenarioInstantiation(BaseModel):
    """A template bound to one cell, ready to be proposed to the advisor.

    This is the whole of what a scenario library hands the engine. It carries no
    approval, no weighting, and no execution authority — the same absence of
    vocabulary as
    :class:`~mayhem.domain.advisor.UntrustedRecommendationDraft`, and for the
    same reason: the author of a scenario is not the approver of one.

    The three methods are the whole surface:

    * :meth:`cell` — the coverage cell this scenario occupies;
    * :meth:`propose` — a function of a
      :class:`~mayhem.domain.advisor.Finding`, which is precisely what
      :func:`mayhem.domain.advisor.recommendations_for` injects, so a scenario
      reaches the engine by the ordinary door;
    * :meth:`drill_spec` — the ordinary
      :class:`~mayhem.domain.experiments.DrillSpec`, which is precisely what
      ``plan_drill`` compiles for an authored plan.

    There is deliberately no fourth method. A scenario cannot compile itself,
    cannot schedule itself, and cannot reach a runtime.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    template_id: str
    template_version: str
    schema_version: str
    target: str
    execution_context: str
    parameter_band: str
    hypothesis: str
    timeline: tuple[TimelineStep, ...]
    stop_conditions: tuple[str, ...]
    recovery: RecoveryPlan
    blast_scope: str = ""

    @model_validator(mode="after")
    def _check(self) -> ScenarioInstantiation:
        for name, value in (
            ("template_id", self.template_id),
            ("template_version", self.template_version),
            ("target", self.target),
            ("execution_context", self.execution_context),
            ("parameter_band", self.parameter_band),
            ("hypothesis", self.hypothesis),
        ):
            if not value.strip():
                raise ScenarioError(f"a scenario instantiation must state {name}")
        if not self.timeline:
            raise ScenarioError(
                f"scenario {self.ref!r} carries an empty timeline: an instantiated "
                "scenario with no moments is a fault list"
            )
        if not self.stop_conditions:
            raise ScenarioError(
                f"scenario {self.ref!r} carries no stop conditions: an instantiated "
                "scenario nobody can stop is not instantiated safely"
            )
        return self

    @property
    def ref(self) -> str:
        """``template_id@version`` — travels onto every artifact derived here."""
        return f"{self.template_id}@{self.template_version}"

    @property
    def duration_s(self) -> float:
        return max(step.at_s + step.duration_s for step in self.timeline)

    @property
    def fault_ids(self) -> tuple[str, ...]:
        return tuple(step.fault_id for step in self.timeline)

    @property
    def digest(self) -> str:
        """Identity of this instantiation: template, version, cell, and timeline."""
        return digest(self.to_dict())

    @property
    def cell(self) -> CoverageCell:
        """The coverage cell the scenario occupies."""
        return CoverageCell(
            target=self.target,
            fault_kind=self.timeline[0].fault_id,
            execution_context=self.execution_context,
            parameter_band=self.parameter_band,
        )

    def probes(self) -> tuple[str, ...]:
        return tuple(
            f"{step.fault_id}@{step.at_s:g}s (expect: {step.expects})"
            for step in self.timeline
        )

    def propose(self, finding: Finding) -> ExperimentCandidate:
        """Propose this scenario against one finding.

        Typed exactly as the ``propose`` argument of
        :func:`mayhem.domain.advisor.recommendations_for`, so passing
        ``instantiation.propose`` there is not a special case — it is the
        injection point. The resulting draft is untrusted, unweighted, and
        unapproved in exactly the way any other generated candidate is, and the
        recommendation it compiles into is always ``generated``.

        The finding is used only to name the experiment, so the candidate stays
        traceable to the gap it was proposed for. The hypothesis is the
        template's, unedited: it is the claim being made, and a paraphrase would
        be a claim nobody reviewed.
        """
        return ExperimentCandidate(
            experiment_id=f"exp:scenario:{self.ref}:{finding.finding_id}",
            hypothesis=self.hypothesis,
            suggested_probes=self.probes(),
            stop_conditions=self.stop_conditions,
        )

    def drill_spec(self) -> DrillSpec:
        """The ordinary drill spec, for ``plan_drill`` and nothing else.

        Deliberately the same
        :class:`~mayhem.domain.experiments.DrillSpec` shape
        :meth:`mayhem.controller.advisor_service.AdvisorService.submit` builds for
        any recommendation: one container, the timeline's faults in declared
        order, one sequential execution step, and the container's own ``on_failure``
        and ``recovery`` defaults left to inherit — because a scenario template
        that overrode a fault's failure policy would be asserting something about
        residue handling that nobody verified.

        One honest limitation, stated rather than hidden: the planner has no
        staggered-injection step, so the timeline's ``at_s`` offsets do **not**
        become extra executions here. They travel as data on
        :attr:`timeline` — and therefore into the instantiation digest, the
        candidate's probes, and any evidence sealed from them. Turning an offset
        into a second injection would be a fabrication about what ran.
        """
        container = DrillContainer(
            faults=tuple(
                DrillFault(
                    fault=step.fault_id,
                    duration=f"{step.duration_s:g}s",
                )
                for step in self.timeline
            ),
        )
        return DrillSpec(
            kind="drill",
            name=f"advisor:scenario:{self.ref}",
            hypothesis=self.hypothesis,
            containers={self.target: container},
            execution=(ExecutionStep(sequential=(self.target,)),),
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ScenarioLibrary(BaseModel):
    """A named set of versioned templates, and the only way to look one up.

    A library may hold several versions of one ``template_id`` — that is the
    point of versioning — but never two entries with the same ``(template_id,
    version)``, because a lookup that returns one of two would make a report's
    citation depend on iteration order.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    templates: tuple[ScenarioTemplate, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> ScenarioLibrary:
        if not self.name.strip():
            raise ScenarioError("a scenario library must be named")
        refs = [template.ref for template in self.templates]
        duplicates = sorted({ref for ref in refs if refs.count(ref) > 1})
        if duplicates:
            raise ScenarioError(
                f"scenario library {self.name!r} holds {duplicates} twice: a template "
                "cited by id and version must resolve to one entry, or a report's "
                "citation depends on iteration order"
            )
        return self

    def get(self, template_id: str, version: str) -> ScenarioTemplate | None:
        """The template at that exact version, or ``None``."""
        return next(
            (t for t in self.templates if t.template_id == template_id and t.version == version),
            None,
        )

    def latest(self, template_id: str) -> ScenarioTemplate | None:
        """The highest ``version`` string for a template id, or ``None``.

        Sorted lexically, not semantically: the versions in this library are
        ``1.0.0``-shaped by the validator below, so lexical and numeric order
        agree, and a version scheme nobody validated cannot silently reorder a
        library.
        """
        candidates = [t for t in self.templates if t.template_id == template_id]
        return max(candidates, key=lambda t: t.version) if candidates else None

    def ids(self) -> tuple[str, ...]:
        """Every distinct template id, sorted."""
        return tuple(sorted({t.template_id for t in self.templates}))

    def refs(self) -> tuple[str, ...]:
        """Every ``id@version``, sorted."""
        return tuple(sorted(t.ref for t in self.templates))


def _template(**kwargs: Any) -> ScenarioTemplate:
    """One shipped entry. A thin wrapper so the data reads as a list of scenarios."""
    return ScenarioTemplate(**kwargs)


#: The plan 21 library: the eight multi-fault scenarios the plan names, each a
#: hypothesis plus timeline plus stop conditions plus recovery. DATA — a value
#: the advisor may propose, never a program that runs. Every fault id here is one
#: :mod:`mayhem.domain.catalog` actually defines, so an instantiated template
#: compiles through ``plan_drill`` like any other plan.
SCENARIO_TEMPLATES: tuple[ScenarioTemplate, ...] = (
    _template(
        template_id="regional-outage",
        version="1.0.0",
        title="Regional outage",
        hypothesis=(
            "losing an entire region's endpoints degrades checkout in the other regions "
            "before any local budget notices"
        ),
        blast_scope="one availability zone; every service that fans out to it",
        timeline=(
            TimelineStep(
                at_s=0.0,
                fault_id="node.service_stop",
                duration_s=60.0,
                expects="the region's endpoints stop answering and callers are re-routed",
            ),
            TimelineStep(
                at_s=5.0,
                fault_id="net.partition",
                duration_s=60.0,
                expects="cross-region calls hang rather than fail fast, and retry counts climb",
            ),
            TimelineStep(
                at_s=30.0,
                fault_id="dependency.timeout",
                duration_s=30.0,
                expects="the first dependency circuit opens on timeout rather than on error rate",
            ),
        ),
        stop_conditions=(
            "abort if any surviving region's error rate exceeds 2% for 30s",
            "abort if the region has not rejoined within 120s",
        ),
        recovery=RecoveryPlan(
            expects="every region's endpoints answer again and latency is at baseline",
            compensation="rejoin the isolated node and clear the injected partition rules",
            verified_by="the readiness probe returns 200 for three consecutive intervals",
        ),
    ),
    _template(
        template_id="cache-outage",
        version="1.0.0",
        title="Cache outage",
        hypothesis=(
            "a cache that stops answering turns a hot read path into a full database read, "
            "and the database is the thing that falls over next"
        ),
        blast_scope="one cache service and the services that read through it",
        timeline=(
            TimelineStep(
                at_s=0.0,
                fault_id="dependency.circuit_open",
                duration_s=120.0,
                expects="every cache read misses and the origin takes the whole read volume",
            ),
            TimelineStep(
                at_s=10.0,
                fault_id="db.slow_query",
                duration_s=60.0,
                expects="query latency rises on exactly the statements the cache was hiding",
            ),
            TimelineStep(
                at_s=45.0,
                fault_id="dependency.circuit_open",
                duration_s=30.0,
                expects="the origin's own dependency trips, so the fallback has nowhere to go",
            ),
        ),
        stop_conditions=(
            "abort if database p99 query latency exceeds 3x baseline for 30s",
            "abort if the origin's connection pool reports any refused connection",
        ),
        recovery=RecoveryPlan(
            expects="cache hit rate returns to baseline and origin read volume falls back",
            compensation="close the injected circuits and restart the evicted pool consumers",
            verified_by="cache hit rate is observed at baseline over a full interval",
        ),
    ),
    _template(
        template_id="dns-failure",
        version="1.0.0",
        title="DNS failure",
        hypothesis=(
            "name resolution failing looks like a slow application until the pools it feeds "
            "run dry"
        ),
        blast_scope="the resolver and every client that resolves through it",
        timeline=(
            TimelineStep(
                at_s=0.0,
                fault_id="dns.servfail",
                duration_s=90.0,
                expects="resolutions start failing after the first cache TTL expires",
            ),
            TimelineStep(
                at_s=5.0,
                fault_id="dependency.timeout",
                duration_s=60.0,
                expects="connection pools drain while resolvers are being retried",
            ),
            TimelineStep(
                at_s=20.0,
                fault_id="dns.resolve_delay",
                duration_s=45.0,
                expects="the surviving cached names resolve slowly, spreading the failure unevenly",
            ),
        ),
        stop_conditions=(
            "abort if the connection pool's available count reaches zero",
            "abort if resolution failure rate exceeds 50% for 20s",
        ),
        recovery=RecoveryPlan(
            expects="resolution succeeds again and the pools refill without an application restart",
            compensation="restore the resolver configuration the injector replaced",
            verified_by="a resolution probe from every zone returns an answer three times in a row",
        ),
    ),
    _template(
        template_id="payment-degradation",
        version="1.0.0",
        title="Payment degradation",
        hypothesis=(
            "a payment provider that accepts connections and then stops responding holds "
            "requests open rather than returning errors, so the queue grows silently"
        ),
        blast_scope="the payment path only",
        timeline=(
            TimelineStep(
                at_s=0.0,
                fault_id="dependency.timeout",
                duration_s=90.0,
                expects="in-flight payment requests stop completing but are not refused",
            ),
            TimelineStep(
                at_s=10.0,
                fault_id="app.response_5xx",
                duration_s=60.0,
                expects="the retries the client library issues surface as 5xx on the checkout path",
            ),
            TimelineStep(
                at_s=40.0,
                fault_id="dependency.circuit_open",
                duration_s=30.0,
                expects="the circuit opens and orders are declined instead of queued",
            ),
        ),
        stop_conditions=(
            "abort if the pending-order queue grows for more than 60s",
            "abort if any order is recorded as captured without a provider confirmation",
        ),
        recovery=RecoveryPlan(
            expects="pending orders drain and no order is left in an indeterminate state",
            compensation="re-drive the held orders and reconcile against the provider's ledger",
            verified_by="the pending-order gauge returns to zero and reconciliation reports no gap",
        ),
    ),
    _template(
        template_id="network-partition",
        version="1.0.0",
        title="Network partition",
        hypothesis=(
            "a one-way partition is worse than an outage, because both sides believe they "
            "can still reach the other"
        ),
        blast_scope="one dependency pair, in one direction",
        timeline=(
            TimelineStep(
                at_s=0.0,
                fault_id="net.partition",
                duration_s=60.0,
                expects="requests from the caller hang with no error on either side",
            ),
            TimelineStep(
                at_s=15.0,
                fault_id="dependency.flap",
                duration_s=45.0,
                expects="the caller's retries flap the connection rather than failing it cleanly",
            ),
        ),
        stop_conditions=(
            "abort if in-flight requests on the partitioned path exceed 50% of the total",
            "abort if any lease remains held after the partition is lifted",
        ),
        recovery=RecoveryPlan(
            expects="both sides see each other again and no request is still in flight",
            compensation="remove the injected partition rules on both sides",
            verified_by="a probe across the partition returns in under its baseline p99",
        ),
    ),
    _template(
        template_id="pod-churn",
        version="1.0.0",
        title="Pod churn",
        hypothesis=(
            "pods that are killed and restarted faster than their readiness gate accounts "
            "for leave the service with fewer ready replicas than its own policy allows"
        ),
        blast_scope="one workload's replicas",
        timeline=(
            TimelineStep(
                at_s=0.0,
                fault_id="container.kill",
                duration_s=30.0,
                expects="a replica disappears and the service's ready count falls",
            ),
            TimelineStep(
                at_s=5.0,
                fault_id="container.restart",
                duration_s=30.0,
                expects="the replacement comes back but is not ready yet",
            ),
            TimelineStep(
                at_s=10.0,
                fault_id="process.crash_loop",
                duration_s=30.0,
                expects="the replacement crashes on readiness, so the warm-up never settles",
            ),
        ),
        stop_conditions=(
            "abort if ready replicas fall below the workload's declared minimum",
            "abort if any request is refused rather than queued during the churn",
        ),
        recovery=RecoveryPlan(
            expects="ready replicas return to the declared count and latency returns to baseline",
            compensation="remove the churn policy and let the scheduler settle",
            verified_by="the ready-replica gauge holds at its declared minimum for two minutes",
        ),
    ),
    _template(
        template_id="certificate-expiry",
        version="1.0.0",
        title="Certificate expiry",
        hypothesis=(
            "an expired certificate fails closed, and a client that does not rotate is the "
            "thing that stays down"
        ),
        blast_scope="every client of the expired certificate",
        timeline=(
            TimelineStep(
                at_s=0.0,
                fault_id="tls.certificate_expired",
                duration_s=90.0,
                expects="TLS handshakes start failing with a verification error",
            ),
            TimelineStep(
                at_s=10.0,
                fault_id="tls.handshake_failure",
                duration_s=60.0,
                expects="clients that retry without reloading the certificate keep failing",
            ),
        ),
        stop_conditions=(
            "abort if any health check reports a TLS verification failure for more than 30s",
            "abort if the error rate on the affected endpoint exceeds 5%",
        ),
        recovery=RecoveryPlan(
            expects="a renewed certificate is loaded and handshakes succeed without a restart",
            compensation="restore the certificate bundle the injector replaced",
            verified_by="a handshake probe from every client succeeds and reports the new expiry",
        ),
    ),
    _template(
        template_id="traffic-spike",
        version="1.0.0",
        title="Traffic spike",
        hypothesis=(
            "a load step applied on top of normal traffic finds the limit that a load test "
            "on an idle system never reaches"
        ),
        blast_scope="one ingress and the services behind it",
        timeline=(
            TimelineStep(
                at_s=0.0,
                fault_id="load.spike",
                duration_s=180.0,
                expects="request rate rises above the declared steady state",
            ),
            TimelineStep(
                at_s=20.0,
                fault_id="db.slow_query",
                duration_s=90.0,
                expects="the slowest statements are the ones that stop keeping up first",
            ),
            TimelineStep(
                at_s=60.0,
                fault_id="cpu.throttle",
                duration_s=60.0,
                expects="the throttled tier shows queueing rather than saturation",
            ),
        ),
        stop_conditions=(
            "abort if the load generator's own error rate exceeds 1%",
            "abort if p99 latency exceeds 5x the declared steady-state budget",
        ),
        recovery=RecoveryPlan(
            expects="traffic returns to the declared steady state and latency follows it down",
            compensation="stop the injected load and remove the throttling rules",
            verified_by="request rate and p99 latency are both at steady state for two intervals",
        ),
    ),
)


def scenario_library(name: str = "plan-21-resilience") -> ScenarioLibrary:
    """The shipped library, by name."""
    return ScenarioLibrary(name=name, templates=SCENARIO_TEMPLATES)
