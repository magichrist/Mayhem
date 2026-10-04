"""The probe *sweep*: the plan's lifecycle, walked in order, collecting and
evaluating continuously (docs/v1.1.0/11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md,
Phase 2, collector half).

:mod:`mayhem.controller.probe_service` knows how to ask one port once and how to
evaluate one condition over what was recorded. Nothing there *runs*: it has no
opinion about when to collect, in what order the six lifecycle stages arrive, or
what a run should do when half its probes are silent. That is this module.

**Why this is a new module rather than a widening of
:mod:`mayhem.controller.observability_collector`.** The plan's Phase 2 says
"extend ``controller/observability_collector.py`` with new source kinds". That
file is a shared surface that roughly twenty concurrent lanes are editing, its
best-effort rule is about *declared observability sources* on a run row, and this
work item does not own it. So the rule is extended **additively and beside it**:
:class:`ProbeSweep` is that collector's discipline (bounded, best-effort, a
failing source records a failed collection and the pass continues) applied to the
probe lifecycle, and it composes :class:`~mayhem.controller.probe_service.ProbeService`
rather than reimplementing any of it. The "new source kinds" half of the phase is
Phase 3's work and lives in
:mod:`mayhem.controller.probe_integrations`; what lands here is the sweep.

The load-bearing property
-------------------------

**A stop condition fires on observed evidence or it does not fire.** Two
mechanisms enforce that here, and both are about the difference between *we saw
a breach* and *we ran out of time looking*:

* :class:`ProbeSweepOutcome` carries either a
  :class:`~mayhem.domain.stop_conditions.Firing` — which the domain already
  makes unconstructible without cited samples — or nothing. There is no code path
  from a timeout, an expired window, or a silent port to a
  :class:`~mayhem.domain.stop.StopCommand`.
* A sweep that ends blind ends in :attr:`ProbeSweepOutcome.blocked` with a
  :class:`SweepBlock`, which is a *different type from a firing*. It says "this
  run watched nothing and may not report a verdict", and it deliberately has no
  ``to_firing`` — the distinction between "the condition fired" and "mayhem could
  not read the condition" is exactly the distinction a single stop-reason string
  would erase.

What a sweep never does
-----------------------

* **It never reads a clock.** ``run`` takes ``at_epoch_s`` for every step from
  the caller. A stop that fired "whenever it happened to" is not reproducible, and
  the whole point of a citable firing is that it can be replayed.
* **It never invents a cadence tick.** A step is collected when its definition
  declares its stage, and a definition that declares no cadence for the stage is
  collected once. Steps that were *scheduled but produced no reading* are recorded
  as :attr:`SweepStep.skipped` with a reason, never as a reading.
* **It does not stop a run for a probe it could not read**, under the default
  policy. A dead probe is a fact about mayhem's wiring, and stopping a run because
  mayhem's connector is down would convert a mayhem outage into a system
  verdict. :data:`UnavailablePolicy.STOP_ON_UNAVAILABLE` exists for the operator
  who wants the opposite, and even then the outcome is a :class:`SweepBlock`, not
  a firing — see the ``note`` on :class:`SweepBlock`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from mayhem.controller.probe_service import (
    ProbeCoverage,
    ProbeReading,
    ProbeService,
    command_for,
    metric_name_for,
)
from mayhem.domain.probes import LifecycleStage
from mayhem.domain.stop import StopCommand

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from mayhem.domain.probes import ProbeDefinition
    from mayhem.domain.stop_conditions import Condition, ConditionResult, Firing

__all__ = [
    "LIFECYCLE_ORDER",
    "STEP_SKIPPED_NOT_DECLARED",
    "STEP_SKIPPED_NOT_GRADED",
    "STEP_SKIPPED_STAGE_ENDED",
    "ProbeSweep",
    "ProbeSweepOutcome",
    "SweepBlock",
    "SweepRefusalError",
    "SweepStep",
    "SweepStepStatus",
    "UnavailablePolicy",
    "leaf_metrics",
    "metric_names_for",
]


class SweepRefusalError(Exception):
    """A sweep cannot be built as asked. Public so a test can assert on it by name.

    A private type rather than :class:`~mayhem.domain.errors.InvariantViolationError`
    on purpose: this is a *caller* mistake in constructing a sweep, not a violated
    domain invariant about probes or conditions, and the two should not share an
    exception class that a caller catches broadly to mean "the domain said no".
    """


#: The plan's six lifecycle stages, in the order a run walks them. Spelled out
#: here rather than derived from
#: :class:`~mayhem.domain.probes.LifecycleStage`'s iteration order, because the
#: walk order is a claim about a run's shape and the enum's declaration order is
#: a claim about vocabulary.
LIFECYCLE_ORDER: tuple[LifecycleStage, ...] = (
    LifecycleStage.PRE_BASELINE,
    LifecycleStage.WARM_UP,
    LifecycleStage.DURING_FAULT,
    LifecycleStage.CONTINUOUS,
    LifecycleStage.AFTER_RECOVERY,
    LifecycleStage.FINAL_VERIFICATION,
)

#: Reasons a scheduled step produced no reading. Each is a fact about mayhem's
#: own behaviour, which is why none of them is a value and none of them may be
#: rendered as a measurement.
STEP_SKIPPED_NOT_DECLARED = "probe does not declare this lifecycle stage"
STEP_SKIPPED_NOT_GRADED = "probe's lifecycle stages were all settled stages"
STEP_SKIPPED_STAGE_ENDED = "the sweep reached the end of the run"


class UnavailablePolicy(StrEnum):
    """What a sweep does about probes it could not read.

    ``CONTINUE`` is the default and the only one that can produce a verdict from
    a partial sweep — with the coverage named, because a partial sweep that does
    not name its gaps is the defect. ``STOP_ON_UNAVAILABLE`` blocks the run's
    *verdict* rather than stopping it, for the reason in the module docstring:
    mayhem's connector being down is not a statement about the system under test.
    """

    CONTINUE = "continue"
    STOP_ON_UNAVAILABLE = "stop-on-unavailable"


class SweepStepStatus(StrEnum):
    """What one (stage, definition) step of the sweep produced."""

    GRADED = "graded"
    """A usable, non-settling reading — this one may support a verdict."""

    SETTLING = "settling"
    """A reading taken in a budgeted settling window: recorded, not gradable."""

    UNAVAILABLE = "unavailable"
    """No reading: unbound port, raising port, ``None``, valueless, wrong shape."""

    SKIPPED = "skipped"
    """Never asked, with the reason named in :attr:`SweepStep.note`."""


@dataclass(frozen=True, slots=True)
class SweepStep:
    """One step of the sweep, and what came of it.

    A step exists whether or not it produced a reading, so "the sweep did not
    look" is a recorded fact rather than an absence inferred from a short list.
    """

    stage: LifecycleStage
    probe_id: str
    family: str
    status: SweepStepStatus
    at_epoch_s: float
    note: str = ""
    reading: ProbeReading | None = None

    @property
    def graded(self) -> bool:
        return self.status is SweepStepStatus.GRADED

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage.value,
            "probe_id": self.probe_id,
            "family": self.family,
            "status": self.status.value,
            "at_epoch_s": self.at_epoch_s,
            "note": self.note,
            "reading": None if self.reading is None else self.reading.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class SweepBlock:
    """A sweep that may not support a verdict, and why.

    **Not a firing, and deliberately unable to become one.** A firing cites
    samples that say a bound was broken; a block says mayhem has no samples to
    cite. Collapsing them would let a run report "stopped because a condition
    fired" when the truth is "stopped because mayhem could not read anything",
    which is the precise confusion this whole module keeps apart.

    ``policy`` is carried so an operator reading a blocked sweep can tell which
    of the two policies blocked it: under
    :data:`UnavailablePolicy.CONTINUE` the sweep ran to the end and its coverage
    is simply blind; under :data:`UnavailablePolicy.STOP_ON_UNAVAILABLE` the sweep
    stopped early on purpose.
    """

    reason: str
    unobserved: tuple[str, ...]
    policy: UnavailablePolicy
    at_epoch_s: float
    coverage: ProbeCoverage

    @property
    def blind(self) -> bool:
        return self.coverage.blind

    def describe(self) -> str:
        names = ", ".join(self.unobserved) or "(none named)"
        return (
            f"{self.reason}; {len(self.unobserved)} probe(s) produced no usable "
            f"reading ({names}). This is a finding about mayhem's wiring, not about "
            "the system under test, and it may not be reported as a healthy run."
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "reason": self.reason,
            "unobserved": list(self.unobserved),
            "policy": self.policy.value,
            "at_epoch_s": self.at_epoch_s,
            "blind": self.blind,
            "coverage": self.coverage.to_dict(),
            "summary": self.describe(),
        }


@dataclass(frozen=True, slots=True)
class ProbeSweepOutcome:
    """Everything one sweep concluded: its steps, its coverage, its firings.

    :attr:`stop_command` is ``None`` unless a condition fired **on cited samples**
    — it is produced by :func:`~mayhem.controller.probe_service.command_for`, from
    a :class:`~mayhem.domain.stop_conditions.Firing`, which the domain refuses to
    construct without them. So the absence of a stop command is never evidence
    that nothing went wrong; it is the answer to "did a condition fire on
    evidence", and :attr:`coverage` is the answer to "was there anything to fire
    on".
    """

    steps: tuple[SweepStep, ...]
    readings: tuple[ProbeReading, ...]
    coverage: ProbeCoverage
    results: tuple[ConditionResult, ...] = ()
    firings: tuple[Firing, ...] = ()
    stop_command: StopCommand | None = None
    block: SweepBlock | None = None
    unresolved: tuple[str, ...] = ()
    """Conditions that could never be evaluated because nothing recorded their metric.

    Distinct from a ``CLEAR`` result and from a firing, and carrying neither. A
    condition whose probe produced no reading is *not evaluable*, and a sweep that
    reported it as clear would be reporting the absence of a check as a passing
    check. It is also not a crash: a probe is often collected in a later stage than
    the one the condition is first evaluated at, so "no samples yet" is a normal
    intermediate state. See :meth:`ProbeSweep.__post_init__` for the distinction
    this draws against a *typo* in a metric name, which is refused loudly.
    """

    @property
    def verdict_bearing(self) -> bool:
        """May a verdict be rendered from this sweep at all?

        False when the sweep is blocked *or* blind, and never True on the
        strength of an absence: a sweep with zero readings and no block is
        blocked, because zero readings is the definition of having looked at
        nothing.
        """
        if self.block is not None or self.unresolved:
            return False
        return self.coverage.verdict_bearing

    @property
    def stopped(self) -> bool:
        """Did a condition fire a stop command?"""
        return self.stop_command is not None

    def describe(self) -> str:
        if self.block is not None:
            return self.block.describe()
        if self.unresolved:
            return (
                f"unevaluable: {len(self.unresolved)} condition(s) could not be "
                f"evaluated because nothing recorded their metric "
                f"({', '.join(self.unresolved)}); an unevaluable condition is neither a "
                "clear one nor a fired one"
            )
        if self.stopped:
            assert self.stop_command is not None
            return (
                f"stopped by condition {self.stop_command.trigger.condition_id!r} "
                f"on {len(self.firings)} firing(s) citing recorded samples"
            )
        return f"sweep completed; {self.coverage.describe()}"

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict_bearing": self.verdict_bearing,
            "stopped": self.stopped,
            "coverage": self.coverage.to_dict(),
            "results": [result.to_dict() for result in self.results],
            "firings": [firing.to_dict() for firing in self.firings],
            "stop_command": (
                None if self.stop_command is None else self.stop_command.model_dump(mode="json")
            ),
            "block": None if self.block is None else self.block.to_dict(),
            "unresolved": list(self.unresolved),
            "steps": [step.to_dict() for step in self.steps],
            "summary": self.describe(),
        }


@dataclass(frozen=True, slots=True)
class ProbeSweep:
    """Runs the lifecycle once, collecting at each stage and evaluating after.

    * ``service`` supplies the bound definitions and the ports;
    * ``conditions`` are evaluated after **every** stage, over the readings
      recorded so far in this sweep — continuous evaluation, so a breach at
      ``t=3`` is caught at ``t=3`` and not at the end of a nominal ``t=30``;
    * ``stages`` defaults to :data:`LIFECYCLE_ORDER`, and a caller walking a
      shorter run narrows it rather than getting gaps silently filled;
    * ``policy`` says what an unreadable probe does to the sweep.

    **``now_epoch_s`` and the stage times are supplied, never read.** The
    ``stage_times`` mapping must name a time for every stage in ``stages``; a
    missing one is refused at construction rather than defaulted, for the reason
    :class:`~mayhem.controller.preflight_gate.PreflightInputs` has no default for
    ``now``.
    """

    service: ProbeService
    conditions: tuple[Condition, ...] = ()
    stages: tuple[LifecycleStage, ...] = LIFECYCLE_ORDER
    stage_times: Mapping[LifecycleStage, float] = field(default_factory=dict)
    policy: UnavailablePolicy = UnavailablePolicy.CONTINUE
    baselines: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "stage_times", dict(self.stage_times))
        if not self.stages:
            raise SweepRefusalError(
                "a sweep with no stages collects nothing and evaluates nothing, which "
                "would be reported as a completed run with nothing behind it. Name the "
                "stages it walks."
            )
        missing = [stage for stage in self.stages if stage not in self.stage_times]
        if missing:
            raise SweepRefusalError(
                "the sweep needs a time for every stage it walks: no time was supplied "
                f"for {', '.join(stage.value for stage in missing)}. A sweep that "
                "invented one would produce firings that could not be replayed."
            )
        producible = set(metric_names_for(self.service.definitions))
        unresolvable = sorted(
            {
                metric
                for condition in self.conditions
                for metric in leaf_metrics(condition)
                if metric not in producible
            }
        )
        if unresolvable:
            # A typo in a metric name is a stop condition that can never fire, and
            # the domain refuses it as ``stop_conditions.unknown_metric``. The sweep
            # refuses it *here*, before collecting anything, because a condition that
            # can never be evaluated is a defect in the plan rather than a fact about
            # this run's coverage — and the two need different words.
            raise SweepRefusalError(
                f"condition(s) read metric(s) {', '.join(unresolvable)}, which no probe "
                "in this catalogue produces. A condition reading a metric no probe "
                "declares can never be evaluated, so it can never fire; the probe it "
                "meant is either not bound to this plan or is spelt differently."
            )

    def run(
        self,
        *,
        run_id: str = "",
        principal: str = "",
        command_id: str = "",
        last_fired_epoch_s: float | None = None,
    ) -> ProbeSweepOutcome:
        """Walk the stages, collecting and evaluating. Never raises from a port.

        ``run_id``/``principal``/``command_id`` are only used if a condition fires;
        a sweep that never fires never builds a command, so an operator cannot
        be handed a stop they did not ask about.

        ``last_fired_epoch_s`` threads plan 10's cooldown across sweeps, so a
        condition that fired cannot be re-fired by the next sweep inside its own
        cooldown. Passing ``None`` on the first sweep is correct and means "no
        prior firing".
        """
        readings: list[ProbeReading] = []
        steps: list[SweepStep] = []
        results: list[ConditionResult] = []
        firings: list[Firing] = []
        blocked: SweepBlock | None = None
        stop_command: StopCommand | None = None
        fired_at: float | None = last_fired_epoch_s
        # Conditions whose metric nothing has produced. A probe is frequently
        # collected in a later stage than the condition is first evaluated at, so
        # this is an ordinary intermediate state — recorded, never graded, and
        # reported on the outcome so it cannot read as "clear".
        unevaluable: set[str] = set()

        for stage in self.stages:
            at_epoch_s = self.stage_times[stage]
            stage_readings = self.service.collect_stage(stage, at_epoch_s=at_epoch_s)
            readings.extend(stage_readings)
            steps.extend(_steps_for(stage, stage_readings, self.service.definitions, at_epoch_s))

            for condition in self.conditions:
                if not _has_samples(condition, readings):
                    unevaluable.add(condition.describe_name())
                    continue
                result = ProbeService.evaluate(
                    condition,
                    tuple(readings),
                    now_epoch_s=at_epoch_s,
                    last_fired_epoch_s=fired_at,
                    baselines=self.baselines or None,
                )
                unevaluable.discard(condition.describe_name())
                results.append(result)
                if result.fired:
                    firing = result.to_firing()
                    firings.append(firing)
                    fired_at = result.fired_at_epoch_s
                    if stop_command is None and run_id and principal and command_id:
                        issued = command_for(
                            firing,
                            command_id=command_id,
                            run_id=run_id,
                            principal=principal,
                        )
                        # ``command_for`` is plan 10's function and is typed
                        # loosely on purpose (see its docstring); the narrow
                        # claim is asserted here rather than assumed.
                        assert isinstance(issued, StopCommand)
                        stop_command = issued

            blocked = self._maybe_block(readings, at_epoch_s=at_epoch_s)
            if blocked is not None and self.policy is UnavailablePolicy.STOP_ON_UNAVAILABLE:
                break

        coverage = ProbeCoverage.of(readings)
        if blocked is None and coverage.blind:
            blocked = SweepBlock(
                reason="the sweep produced no usable reading",
                unobserved=coverage.unobserved,
                policy=self.policy,
                at_epoch_s=max(self.stage_times[stage] for stage in self.stages),
                coverage=coverage,
            )
        return ProbeSweepOutcome(
            steps=tuple(steps),
            readings=tuple(readings),
            coverage=coverage,
            results=tuple(results),
            firings=tuple(firings),
            stop_command=stop_command,
            block=blocked,
            unresolved=tuple(sorted(unevaluable)),
        )

    def _maybe_block(
        self, readings: Sequence[ProbeReading], *, at_epoch_s: float
    ) -> SweepBlock | None:
        """The block this policy implies for the readings so far, or ``None``."""
        if self.policy is UnavailablePolicy.CONTINUE:
            return None
        coverage = ProbeCoverage.of(readings)
        if not coverage.unobserved:
            return None
        return SweepBlock(
            reason=(
                f"policy {self.policy.value!r}: a probe this run depends on produced no "
                "usable reading, and mayhem reports that rather than grading around it"
            ),
            unobserved=coverage.unobserved,
            policy=self.policy,
            at_epoch_s=at_epoch_s,
            coverage=coverage,
        )


def leaf_metrics(condition: Condition) -> tuple[str, ...]:
    """Every metric name a condition tree reads, in tree order.

    Walks :attr:`Condition.operands` rather than pattern-matching node kinds, so a
    node kind added to the domain later is walked by this function for free instead
    of silently contributing no metrics — which would make every condition
    referencing it look like a typo.
    """
    if condition.reference is not None:
        return (condition.reference.metric,)
    names: list[str] = []
    for operand in condition.operands:
        names.extend(leaf_metrics(operand))
    return tuple(names)


def _has_samples(condition: Condition, readings: Sequence[ProbeReading]) -> bool:
    """Whether every metric this condition reads already has a recorded sample.

    The pre-check that keeps :meth:`ProbeSweep.run` from raising
    ``stop_conditions.unknown_metric`` on the first stage of a sweep. It asks
    *"has anything been recorded for this metric yet?"*, not *"is it available?"* —
    the domain decides the second question, and this one exists only to avoid
    asking it about a metric that has never appeared.
    """
    recorded = {
        reading.observation.metric for reading in readings if reading.observation is not None
    }
    return all(metric in recorded for metric in leaf_metrics(condition))


def _steps_for(
    stage: LifecycleStage,
    readings: Sequence[ProbeReading],
    definitions: Sequence[ProbeDefinition],
    at_epoch_s: float,
) -> list[SweepStep]:
    """One :class:`SweepStep` per definition, whether or not it produced a reading.

    Every definition gets a step. A probe that declares no membership in this
    stage is recorded as ``skipped`` with the reason named — which is how
    "lifecycle membership is a fact about the catalogue rather than a silent
    judgement" survives into the record.
    """
    by_id = {reading.probe_id: reading for reading in readings}
    steps: list[SweepStep] = []
    for definition in definitions:
        reading = by_id.get(definition.id)
        if reading is None:
            reason = (
                STEP_SKIPPED_NOT_GRADED
                if not set(definition.stages) - _SETTLING
                else STEP_SKIPPED_NOT_DECLARED
            )
            steps.append(
                SweepStep(
                    stage=stage,
                    probe_id=definition.id,
                    family=definition.family.value,
                    status=SweepStepStatus.SKIPPED,
                    at_epoch_s=at_epoch_s,
                    note=reason,
                )
            )
            continue
        if reading.in_settling_stage:
            status, note = SweepStepStatus.SETTLING, STEP_SKIPPED_NOT_GRADED
        elif not reading.available:
            status, note = SweepStepStatus.UNAVAILABLE, reading.note
        else:
            status, note = SweepStepStatus.GRADED, reading.note
        steps.append(
            SweepStep(
                stage=stage,
                probe_id=definition.id,
                family=definition.family.value,
                status=status,
                at_epoch_s=at_epoch_s,
                note=note,
                reading=reading,
            )
        )
    return steps


#: The two budgeted settling stages, read from the definition's own vocabulary.
_SETTLING = frozenset(
    {
        LifecycleStage.WARM_UP,
        LifecycleStage.AFTER_RECOVERY,
    }
)


def metric_names_for(
    definitions: Sequence[ProbeDefinition],
) -> tuple[str, ...]:
    """The metric names a condition may reference for ``definitions``.

    Exposed so an author can be told what is referenceable, rather than
    discovering it by watching a condition fail to resolve. The names come from
    :func:`~mayhem.controller.probe_service.metric_name_for`, which is the same
    function that produced them, so a condition and a probe cannot disagree about
    what name a reading arrives under.
    """
    return tuple(metric_name_for(definition) for definition in definitions)
