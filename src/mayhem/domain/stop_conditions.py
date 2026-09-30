"""Stop conditions: what may interrupt a run, and the samples that prove it did.

Plan 10 owns the teeth — the machinery that actually halts a run. This module
owns the definitions those teeth act on, and it owns exactly one opinion about
how a condition may stop a run: **it must be able to name the samples behind
it.** A stop with no cited samples is a defect, not a warning, because a report
that says "the run was stopped" and cannot say *why* is indistinguishable from a
run that stopped for an unrelated reason, a bug, or nothing at all. That is the
same failure this codebase already names twice — "the probe never fired" and
"the fault did nothing" sharing one boolean — so :class:`Firing` refuses to be
constructed without citations rather than logging a warning at the boundary.

Four controls separate *breaching* from *firing*, and the distinction is the
whole design:

``hysteresis``
    A dead band around the bound. A value inside it neither breaches nor clears,
    it **holds the previous state**. This is what stops a signal hovering on a
    threshold from flapping the stop path, and it is why equality at the bound
    is not a verdict: with a band of zero the exact comparison runs instead, so
    ``lte`` still fires on equality and ``lt`` still does not.
``for_samples``
    How many *consecutive* breaching samples are required. One spike is noise;
    three in a row is a trend.
``debounce``
    How long a breach must persist. The clock starts at the first sample of the
    qualifying run, not at the moment of evaluation, so a slow evaluator cannot
    make a breach look fresher than it is.
``cooldown``
    A lockout after a firing. Pure and stateless: the caller injects the last
    recorded firing time, so evaluation stays a function of its arguments.
``max_duration``
    A bound on how long the condition may be watched. A stop condition that can
    never fire is a no-op wearing a stop's name — so the window closes, and the
    condition reports ``expired`` rather than watching forever in silence.

Three commitments run through the code below.

**The verdict core is extended, never forked.** :func:`holds` and
:func:`breaches` delegate to :func:`mayhem.domain.steady_state.within_absolute`,
:func:`~mayhem.domain.steady_state.within_relative` and
:func:`~mayhem.domain.steady_state.delta_pct`, and :class:`Threshold` embeds
steady-state's own :class:`AbsoluteExpect` / :class:`Tolerance` /
:class:`Baseline` and :mod:`mayhem.domain.observations`' own
:class:`SloCriterion` rather than restating their semantics. :meth:`Threshold.assertion`
projects any tolerance onto the existing
:class:`~mayhem.domain.steady_state.Assertion` so the steady-state evaluator
still produces the one canonical
:class:`~mayhem.domain.steady_state.Verdict` — this module adds no verdict of
its own and no boolean that could disagree with it.

**Evaluation is over recorded observations only.** :meth:`Condition.evaluate`
reads a :class:`Sample` (a recorded :class:`ObservationResult` plus the instant
it was recorded) and performs no IO, opens nothing, and **never reads a clock**:
time is injected as ``now_epoch_s`` and the previous firing as
``last_fired_epoch_s``. Two evaluations over the same samples and the same
injected time are the same answer, forever.

**An unknown reference is refused, not resolved to "clear".** A metric name that
appears nowhere in the recorded samples raises. The tempting alternative — treat
it as healthy — is exactly the defect this feature exists to remove: a typo in a
metric name is a stop condition that can never fire, and reporting it as calm is
the most confident wrong answer the tool can give. :meth:`Condition.validate_references`
is the authoring-time twin of that refusal.

Status propagation for composite nodes is explicit, because "the conjunction did
not fire" is not one thing:

======================  ==================================================
node                    status when it does not fire
======================  ==================================================
``all``                 any child ``expired`` wins, then ``suppressed``,
                        ``unmeasured``, ``pending``, else ``clear``
``any``                 ``pending`` if any branch is still pending, else
                        ``clear`` — with the non-``clear`` branches named in
                        the note, because "no branch fired" is the contract
======================  ==================================================

``any`` reporting ``clear`` on an unobserved branch is intentional and is not a
pass: the contract of an ``any`` node is "fire when any branch fires", and a
branch with no evidence did not fire. The note says which branches were blind,
and the engine can refuse to treat an unmeasured ``any`` as a clean bill of
health.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.common import Duration
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.observations import (
    CriterionOperator,
    ObservationResult,
    SloCriterion,
)
from mayhem.domain.steady_state import (
    AbsoluteExpect,
    Assertion,
    AssertionVerb,
    Tolerance,
    delta_pct,
    within_absolute,
    within_relative,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

__all__ = [
    "Condition",
    "ConditionResult",
    "ConditionStatus",
    "FiresWhen",
    "Firing",
    "MetricReference",
    "NodeKind",
    "Sample",
    "Threshold",
    "ToleranceKind",
]


# -- vocabulary ---------------------------------------------------------------------


class ToleranceKind(StrEnum):
    """The comparison a :class:`Threshold` performs.

    These four are *mechanisms*, not a re-labelling of the eight tolerance
    types plan 11 enumerates. Each delegates to a function that already exists —
    steady-state's band and baseline maths, or an SLO criterion's operator table
    — rather than defining a second comparison for the same idea:

    ===================  =======================================================
    mechanism            plan 11 tolerance types it carries
    ===================  =======================================================
    ``absolute``         absolute, range, boolean
    ``ratio``            ratio (a multiple of a captured baseline)
    ``percentage``       percentage (a bound on the relative change)
    ``operator``         percentile, time-to-recovery, and any scalar bound
                         already expressed as an SLO criterion
    ===================  =======================================================

    ``categorical`` is deliberately absent. There is no categorical value on
    :class:`~mayhem.domain.observations.ObservationResult` to compare, and
    inventing one here would fork the observation contract that every provider
    already satisfies. It lands with the probe catalogue in Phase 3, where a
    source that can carry one exists.
    """

    ABSOLUTE = "absolute"
    RATIO = "ratio"
    PERCENTAGE = "percentage"
    OPERATOR = "operator"


class FiresWhen(StrEnum):
    """Which side of the threshold is the stop.

    ``BROKEN`` is the safety default: the condition fires when the declared
    bound stops holding ("latency above 250 ms"). ``MET`` turns the same
    declaration into a completion signal ("recovery confirmed, latency back
    under 250 ms"). Hysteresis inverts with it, because a dead band has to mean
    the same thing on both sides of the flip.
    """

    BROKEN = "broken"
    MET = "met"


class NodeKind(StrEnum):
    """The three shapes a condition node can take.

    ``AND``/``OR`` precedence is *structural, not syntactic*: every node
    declares its own operator, so ``all(a, any(b, c))`` and ``any(all(a, b),
    c)`` are different trees by construction and there is no precedence rule for
    an evaluator to get wrong. That is deliberate — a precedence rule nobody
    remembers is a precedence bug.
    """

    ALL = "all"
    ANY = "any"
    METRIC = "metric"


class ConditionStatus(StrEnum):
    """Why a condition did or did not fire.

    ``PENDING`` exists so a breaching-but-not-yet-qualifying condition never
    reads as calm: the engine can see the run building and say so, instead of
    holding its tongue until the third sample arrives. ``EXPIRED`` exists so a
    condition that can never fire says *that*, rather than watching a window
    forever in silence.
    """

    FIRED = "fired"
    CLEAR = "clear"
    PENDING = "pending"
    UNMEASURED = "unmeasured"
    EXPIRED = "expired"
    SUPPRESSED = "suppressed"


class _SampleState(StrEnum):
    """Tri-state of one recorded value under a dead band."""

    BREACH = "breach"
    CLEAR = "clear"
    HOLD = "hold"


# -- recorded samples ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Sample:
    """One recorded observation plus the instant it was recorded.

    ``ObservationResult`` already carries the value, the unit, the status and
    the provenance — and no time. Stop conditions need the time for debounce,
    cooldown and the observation window, so this wraps rather than restates: the
    original observation is kept intact and still reaches an
    :class:`SloCriterion` unchanged.

    ``available`` deliberately mirrors
    :attr:`ObservationResult.available`. A stop condition that treated a missing
    sample as ``0.0`` would fire on the absence of evidence, which is how a
    probe that never ran gets reported as a breach.
    """

    observation: ObservationResult
    at_epoch_s: float

    def __post_init__(self) -> None:
        if not isinstance(self.observation, ObservationResult):
            raise InvariantViolationError(
                "stop_conditions.sample_not_an_observation",
                f"Sample was handed a {type(self.observation).__name__} where an "
                "ObservationResult was expected: a sample is a recorded observation "
                "plus its recording time, not a bare number",
            )
        if not isfinite(self.at_epoch_s):
            raise InvariantViolationError(
                "stop_conditions.sample_time_not_finite",
                f"Sample for {self.observation.metric!r} carries a non-finite "
                f"recording time ({self.at_epoch_s!r}): a sample that cannot be "
                "placed on a timeline cannot satisfy debounce, cooldown or the "
                "observation window",
            )

    @classmethod
    def from_observation(cls, observation: ObservationResult, at_epoch_s: float) -> Sample:
        return cls(observation=observation, at_epoch_s=at_epoch_s)

    @property
    def metric(self) -> str:
        return self.observation.metric

    @property
    def value(self) -> float | None:
        return self.observation.value

    @property
    def available(self) -> bool:
        return self.observation.available

    @property
    def source(self) -> str:
        return self.observation.source

    def to_dict(self) -> dict[str, object]:
        payload = self.observation.to_dict()
        payload["at_epoch_s"] = self.at_epoch_s
        return payload


# -- tolerances (an extension of the verdict core, never a fork) --------------------


class Threshold(BaseModel):
    """One declared bound, evaluated by a function that already exists.

    ``kind`` selects the payload and the comparison:

    * ``absolute`` — an :class:`AbsoluteExpect` band, compared by
      :func:`within_absolute`.
    * ``ratio`` — a :class:`Tolerance` against a captured baseline, compared by
      :func:`within_relative`. The baseline is relative *deviation*, never
      magnitude, so a signed signal that inverted completely cannot pass.
    * ``percentage`` — a bound on ``|delta_pct|`` from a baseline, reusing the
      steady-state change maths rather than restating it.
    * ``operator`` — a whole :class:`SloCriterion`, whose own operator table is
      the comparison. Percentile bounds and time-to-recovery land here rather
      than as a new kind.

    ``baseline`` is the author's captured reference; an evaluation may override
    it per metric (Phase 2 owns the capture window). A threshold whose kind
    needs a baseline and has none is **unmeasurable, not healthy**:
    :meth:`holds` returns ``False``, and a ``fires_when=MET`` threshold reads
    as not-yet-met rather than satisfied.
    """

    model_config = ConfigDict(frozen=True)

    kind: ToleranceKind = ToleranceKind.ABSOLUTE
    fires_when: FiresWhen = FiresWhen.BROKEN
    expect: AbsoluteExpect | None = None
    tolerance: Tolerance | None = None
    criterion: SloCriterion | None = None
    percent: float | None = Field(default=None, ge=0.0)
    baseline: float | None = None

    @model_validator(mode="after")
    def _one_mechanism(self) -> Threshold:
        """Exactly the payload its ``kind`` uses, and no other."""
        payloads: dict[ToleranceKind, tuple[str, object | None]] = {
            ToleranceKind.ABSOLUTE: ("expect", self.expect),
            ToleranceKind.RATIO: ("tolerance", self.tolerance),
            ToleranceKind.PERCENTAGE: ("percent", self.percent),
            ToleranceKind.OPERATOR: ("criterion", self.criterion),
        }
        name, value = payloads[self.kind]
        if value is None:
            raise InvariantViolationError(
                "stop_conditions.threshold_payload_missing",
                f"threshold of kind {self.kind.value!r} declares no {name}: that "
                f"kind compares with {name}, and without it there is nothing to "
                "compare against",
            )
        for other, (other_name, other_value) in payloads.items():
            if other is not self.kind and other_value is not None:
                raise InvariantViolationError(
                    "stop_conditions.threshold_payload_mixed",
                    f"threshold of kind {self.kind.value!r} also declares {other_name}: "
                    "a threshold compares by exactly one mechanism; two bounds "
                    "authored in one threshold are two thresholds nobody can grade",
                )
        return self

    @model_validator(mode="after")
    def _baseline_only_where_it_means_something(self) -> Threshold:
        relative_kinds = (ToleranceKind.RATIO, ToleranceKind.PERCENTAGE)
        if self.baseline is not None and self.kind not in relative_kinds:
            raise InvariantViolationError(
                "stop_conditions.baseline_on_absolute_bound",
                f"threshold of kind {self.kind.value!r} declares a baseline: only a "
                "ratio or percentage bound is judged against one. An absolute band "
                "or an operator criterion is its own reference, and a baseline "
                "attached to it would be read as controlling and ignored",
            )
        return self

    @property
    def supports_hysteresis(self) -> bool:
        """Can a dead band be expressed around this threshold?

        A ratio tolerance has no fixed numeric bound until a baseline is
        captured, and an ``absolute`` band that declares both ends has no single
        governing bound to sit either side of. Both are refused rather than
        approximated.
        """
        if self.kind is ToleranceKind.RATIO:
            return False
        if self.kind is ToleranceKind.ABSOLUTE and self.expect is not None:
            declared = (
                (self.expect.eq is not None)
                + (self.expect.lte is not None)
                + (self.expect.gte is not None)
            )
            return declared <= 1
        return True

    def governing_bound(self) -> tuple[CriterionOperator, float] | None:
        """The single bound a dead band is measured from, in the breach direction.

        ``lte`` bounds from above so its breach direction is ``gt``; ``gte``
        bounds from below so its breach direction is ``lt``. ``eq`` bounds from
        both sides and keeps its own operator.
        """
        if self.kind is ToleranceKind.ABSOLUTE and self.expect is not None:
            return _expect_bound(self.expect)
        if self.kind is ToleranceKind.OPERATOR and self.criterion is not None:
            return (self.criterion.operator, self.criterion.threshold)
        if self.kind is ToleranceKind.PERCENTAGE and self.percent is not None:
            return (CriterionOperator.EQ, self.percent)
        return None

    def resolved_baseline(self, override: float | None) -> float | None:
        """The baseline in force: the evaluation's override, else the authored one."""
        return override if override is not None else self.baseline

    def holds(self, sample: Sample, *, baseline: float | None = None) -> bool:
        """Does this recorded sample satisfy the declared bound?

        Delegation, not reimplementation: every branch calls the steady-state or
        SLO function that already owns the comparison. An unavailable sample
        never holds — a probe that returned ``None`` satisfied nothing, and
        quietly treating it as a pass is the "no-effect" confusion in a new
        coat.
        """
        value = sample.value
        if value is None or not isfinite(value):
            return False
        if self.kind is ToleranceKind.ABSOLUTE and self.expect is not None:
            return within_absolute(value, self.expect)
        if self.kind is ToleranceKind.RATIO and self.tolerance is not None:
            return within_relative(self.resolved_baseline(baseline), value, self.tolerance)
        if self.kind is ToleranceKind.PERCENTAGE and self.percent is not None:
            base = self.resolved_baseline(baseline)
            change = delta_pct(base, value) if base is not None else None
            return change is not None and abs(change) <= self.percent
        if self.criterion is not None:
            return self.criterion.evaluate(sample.observation).passed
        return False

    def breaches(self, sample: Sample, *, baseline: float | None = None) -> bool:
        """The value on the firing side of the declared bound."""
        holding = self.holds(sample, baseline=baseline)
        return holding if self.fires_when is FiresWhen.MET else not holding

    def sample_state(
        self,
        sample: Sample,
        *,
        baseline: float | None = None,
        band: float = 0.0,
    ) -> _SampleState:
        """Tri-state one value: breaching, clear, or inside the dead band.

        With ``band == 0`` the exact comparison decides, so a strict operator
        still refuses to fire on equality. With a band, the value must sit a
        full band *beyond* the bound to confirm a breach and a full band *back
        inside* to confirm a clear; anything between holds the previous state,
        which is what stops a hovering signal from flapping the stop path.
        """
        exact = self.breaches(sample, baseline=baseline)
        value = sample.value
        if band <= 0.0 or value is None or not isfinite(value):
            return _SampleState.BREACH if exact else _SampleState.CLEAR
        bound = self.governing_bound()
        if bound is None:
            return _SampleState.BREACH if exact else _SampleState.CLEAR
        operator, limit = bound
        magnitude = value
        if self.kind is ToleranceKind.PERCENTAGE:
            base = self.resolved_baseline(baseline)
            change = delta_pct(base, value) if base is not None else None
            if change is None:
                # An unmeasurable change has no distance from the bound, so there
                # is no band to place it in. Fall back to the exact reading.
                return _SampleState.BREACH if exact else _SampleState.CLEAR
            magnitude = abs(change)
        state = _band_state(magnitude, limit, operator, band)
        if self.fires_when is FiresWhen.MET:
            state = _invert(state)
        return state

    def assertion(self, name: str, verb: AssertionVerb = AssertionVerb.DEGRADED) -> Assertion:
        """Project this tolerance onto steady-state's own assertion record.

        This is the seam that keeps the verdict core single: a threshold authored
        for a stop condition and a steady-state signal authored for a verdict
        end up as the *same* :class:`Assertion`, so
        :func:`~mayhem.domain.steady_state.classify` produces the one canonical
        :class:`~mayhem.domain.steady_state.Verdict` either way. Nothing here
        decides a verdict, and nothing here can disagree with ``classify``.
        """
        if self.kind is ToleranceKind.ABSOLUTE:
            return Assertion(verb=verb, name=name, expect=self.expect)
        if self.kind is ToleranceKind.RATIO:
            return Assertion(verb=verb, name=name, tolerance=self.tolerance)
        if self.kind is ToleranceKind.PERCENTAGE and self.percent is not None:
            # A percentage bound on a relative change is an absolute band on the
            # signed change, expressed in the vocabulary classify() already reads.
            return Assertion(
                verb=verb,
                name=name,
                expect=AbsoluteExpect(lte=self.percent, gte=-self.percent),
            )
        if self.criterion is not None:
            return Assertion(verb=verb, name=name, expect=_expect_from_operator(self.criterion))
        raise InvariantViolationError(
            "stop_conditions.threshold_unprojectable",
            f"threshold {name!r} of kind {self.kind.value!r} has no steady-state "
            "projection: a stop condition can express a bound the verdict core "
            "cannot read, which would mean two different answers to one question",
        )


def _expect_from_operator(criterion: SloCriterion) -> AbsoluteExpect:
    """Render an SLO operator as the equivalent steady-state band."""
    match criterion.operator:
        case CriterionOperator.LT | CriterionOperator.LTE:
            return AbsoluteExpect(lte=criterion.threshold)
        case CriterionOperator.GT | CriterionOperator.GTE:
            return AbsoluteExpect(gte=criterion.threshold)
        case CriterionOperator.EQ:
            return AbsoluteExpect(eq=criterion.threshold)
    raise InvariantViolationError(  # pragma: no cover - the enum is closed
        "stop_conditions.unknown_operator",
        f"criterion operator {criterion.operator!r} has no steady-state projection",
    )


def _expect_bound(expect: AbsoluteExpect) -> tuple[CriterionOperator, float] | None:
    """The single bound an absolute band is governed by, in the breach direction.

    ``AbsoluteExpect`` is a conjunction, so a band may name up to three bounds —
    but a dead band has to sit on one side of *one* number. A two-sided band
    refuses hysteresis (see :attr:`Threshold.supports_hysteresis`); which of the
    remaining bounds governs is fixed here so the answer is at least predictable.
    """
    if expect.eq is not None:
        return (CriterionOperator.EQ, expect.eq)
    if expect.lte is not None:
        return (CriterionOperator.GT, expect.lte)
    if expect.gte is not None:
        return (CriterionOperator.LT, expect.gte)
    return None


def _band_state(
    value: float, limit: float, operator: CriterionOperator, band: float
) -> _SampleState:
    """Schmitt-trigger reading of one value against a bound plus a dead band.

    The breach side is inclusive and the clear side is exclusive, so a value
    sitting exactly on the confirmation edge confirms the breach rather than
    wedging in the hold band forever.
    """
    if operator is CriterionOperator.EQ:
        return _SampleState.BREACH if abs(value - limit) > band else _SampleState.CLEAR
    above = operator in (CriterionOperator.GT, CriterionOperator.GTE)
    signed = value - limit if above else limit - value
    if signed >= band:
        return _SampleState.BREACH
    if signed > -band:
        return _SampleState.HOLD
    return _SampleState.CLEAR


def _invert(state: _SampleState) -> _SampleState:
    """Mirror a tri-state for a ``fires_when=MET`` threshold."""
    match state:
        case _SampleState.BREACH:
            return _SampleState.CLEAR
        case _SampleState.CLEAR:
            return _SampleState.BREACH
        case _SampleState.HOLD:
            return _SampleState.HOLD


# -- references ---------------------------------------------------------------------


class MetricReference(BaseModel):
    """Which recorded metric a leaf condition reads.

    Named by metric, optionally narrowed by ``source_id`` — the ``source`` field
    the observation already carries, so two sources exporting the same metric
    name stay distinguishable. An empty ``source_id`` matches any source,
    because a metric with one producer does not need to name it twice.
    """

    model_config = ConfigDict(frozen=True)

    metric: str = Field(min_length=1)
    source_id: str = ""

    def describe(self) -> str:
        return self.metric if not self.source_id else f"{self.metric}@{self.source_id}"


# -- the condition tree -------------------------------------------------------------


class Condition(BaseModel):
    """One node of a stop-condition expression tree.

    Three kinds, one type, so a nested condition is a plain value that can be
    stored, compared, sealed into an artifact and shipped to another process
    without a bespoke walker per node shape. Build trees with :meth:`all`,
    :meth:`any` and :meth:`metric`, which also carry the leaf-only controls into
    the right place instead of letting a caller set them on a node that cannot
    honour them.

    Controls are per-node, not per-tree: ``cooldown`` and ``max_duration`` mean
    something on a composite, ``for_samples`` / ``debounce`` / ``hysteresis``
    only mean something against a stream of values, so setting them on an
    ``all`` / ``any`` node is refused with a message naming the node — not
    accepted and quietly ignored, which is how a debounce becomes a comment.
    """

    model_config = ConfigDict(frozen=True)

    name: str = ""
    kind: NodeKind = NodeKind.METRIC
    operands: tuple[Condition, ...] = ()
    reference: MetricReference | None = None
    threshold: Threshold | None = None
    hysteresis: float | None = Field(default=None, ge=0.0, lt=1.0)
    hysteresis_absolute: float | None = Field(default=None, ge=0.0)
    for_samples: int = Field(default=1, ge=1)
    debounce: Duration = 0.0
    cooldown: Duration = 0.0
    max_duration: Duration | None = None

    @classmethod
    def all(
        cls,
        *operands: Condition,
        name: str = "",
        cooldown: Duration = 0.0,
        max_duration: Duration | None = None,
    ) -> Condition:
        """Every operand must fire."""
        return cls(
            name=name,
            kind=NodeKind.ALL,
            operands=operands,
            cooldown=cooldown,
            max_duration=max_duration,
        )

    @classmethod
    def any(
        cls,
        *operands: Condition,
        name: str = "",
        cooldown: Duration = 0.0,
        max_duration: Duration | None = None,
    ) -> Condition:
        """Any operand firing fires the node."""
        return cls(
            name=name,
            kind=NodeKind.ANY,
            operands=operands,
            cooldown=cooldown,
            max_duration=max_duration,
        )

    @classmethod
    def metric(
        cls,
        metric_name: str,
        threshold: Threshold,
        *,
        source_id: str = "",
        name: str = "",
        hysteresis: float | None = None,
        hysteresis_absolute: float | None = None,
        for_samples: int = 1,
        debounce: Duration = 0.0,
        cooldown: Duration = 0.0,
        max_duration: Duration | None = None,
    ) -> Condition:
        """A leaf: one recorded metric against one threshold."""
        return cls(
            name=name,
            kind=NodeKind.METRIC,
            reference=MetricReference(metric=metric_name, source_id=source_id),
            threshold=threshold,
            hysteresis=hysteresis,
            hysteresis_absolute=hysteresis_absolute,
            for_samples=for_samples,
            debounce=debounce,
            cooldown=cooldown,
            max_duration=max_duration,
        )

    # -- shape invariants ------------------------------------------------------------

    @model_validator(mode="after")
    def _shape_matches_kind(self) -> Condition:
        if self.kind is NodeKind.METRIC:
            if self.reference is None or self.threshold is None:
                missing = (
                    "a threshold"
                    if self.reference is not None
                    else "neither a reference nor a threshold"
                )
                raise InvariantViolationError(
                    "stop_conditions.leaf_without_threshold",
                    f"condition {self.describe_name()!r} is a metric leaf but "
                    f"declares {missing}: a leaf that compares nothing would fire "
                    "on every sample and cite none of them as a reason",
                )
            if self.operands:
                raise InvariantViolationError(
                    "stop_conditions.leaf_with_operands",
                    f"condition {self.describe_name()!r} is a metric leaf but also "
                    f"declares {len(self.operands)} operand(s): a node is either a "
                    "comparison or a combination of them, never both",
                )
            return self
        if not self.operands:
            raise InvariantViolationError(
                "stop_conditions.composite_without_operands",
                f"condition {self.describe_name()!r} is an {self.kind.value} node "
                "with no operands: an empty conjunction is vacuously true and an "
                "empty disjunction is vacuously false, and neither is a stop",
            )
        if self.reference is not None or self.threshold is not None:
            raise InvariantViolationError(
                "stop_conditions.composite_with_threshold",
                f"condition {self.describe_name()!r} is an {self.kind.value} node but "
                "also declares a reference or threshold: a combination has no bound "
                "of its own",
            )
        return self

    @model_validator(mode="after")
    def _value_controls_stay_on_leaves(self) -> Condition:
        """Refuse leaf-only controls on a composite rather than ignore them."""
        if self.kind is NodeKind.METRIC:
            return self
        offenders = []
        if self.hysteresis is not None:
            offenders.append("hysteresis")
        if self.hysteresis_absolute is not None:
            offenders.append("hysteresis_absolute")
        if self.for_samples != 1:
            offenders.append(f"for_samples={self.for_samples}")
        if float(self.debounce) > 0.0:
            offenders.append(f"debounce={self.debounce}")
        if offenders:
            raise InvariantViolationError(
                "stop_conditions.composite_holds_value_controls",
                f"condition {self.describe_name()!r} is an {self.kind.value} node but "
                f"declares {', '.join(offenders)}: these count or time a *stream of "
                "values*, which only a metric leaf has. Accepted here they would "
                "read as a control and do nothing. Put the control on the leaf, or "
                "use cooldown/max_duration, which a composite does honour",
            )
        return self

    @model_validator(mode="after")
    def _hysteresis_is_expressible(self) -> Condition:
        if self.kind is not NodeKind.METRIC or self.threshold is None:
            return self
        if self.hysteresis is None and self.hysteresis_absolute is None:
            return self
        if self.threshold.supports_hysteresis:
            return self
        raise InvariantViolationError(
            "stop_conditions.hysteresis_not_expressible",
            f"condition {self.describe_name()!r} declares hysteresis against a "
            f"{self.threshold.kind.value} threshold: a ratio tolerance has no "
            "numeric bound until a baseline is captured, and a band that declares "
            "both ends has no single governing bound to sit either side of. "
            "Declare one bound, or express the margin in the bound itself",
        )

    # -- introspection ---------------------------------------------------------------

    def describe_name(self) -> str:
        if self.name:
            return self.name
        if self.reference is not None:
            return self.reference.describe()
        return f"{self.kind.value} node"

    @property
    def metrics(self) -> tuple[str, ...]:
        """Every metric this tree reads, in declaration order, deduplicated."""
        seen: list[str] = []
        for reference in self.references():
            if reference.metric not in seen:
                seen.append(reference.metric)
        return tuple(seen)

    def references(self) -> tuple[MetricReference, ...]:
        """Every leaf reference in this tree, depth-first, in declaration order."""
        if self.kind is NodeKind.METRIC:
            return (self.reference,) if self.reference is not None else ()
        found: list[MetricReference] = []
        for operand in self.operands:
            found.extend(operand.references())
        return tuple(found)

    def validate_references(self, available: Iterable[str]) -> None:
        """Authoring-time check that every leaf reads a metric that exists.

        The same refusal :meth:`evaluate` makes at runtime, available before a
        run starts: a metric name that resolves to nothing becomes a stop
        condition that can never fire, and "never fired" is the answer a report
        would otherwise present as calm.
        """
        declared = set(available)
        for reference in self.references():
            if reference.metric not in declared:
                raise InvariantViolationError(
                    "stop_conditions.unknown_metric",
                    f"condition {self.describe_name()!r} reads metric "
                    f"{reference.describe()!r}, which no recorded observation "
                    f"provides (available: {sorted(declared)}). A reference that "
                    "resolves to nothing is a stop that can never fire",
                )

    # -- evaluation ------------------------------------------------------------------

    def band(self) -> float:
        """The dead band in the metric's own units: relative plus absolute.

        ``hysteresis`` is a fraction of the governing bound's magnitude, which
        is what makes one authored band work across metrics on different
        scales (a 5% band on a 250 ms bound is 12.5 ms, the same 5% on a 0.02
        error rate is 0.001). ``hysteresis_absolute`` covers bounds at or near
        zero, where a relative fraction is degenerate.
        """
        absolute = self.hysteresis_absolute or 0.0
        if self.threshold is None:
            return absolute
        bound = self.threshold.governing_bound()
        magnitude = abs(bound[1]) if bound is not None else 0.0
        return absolute + magnitude * (self.hysteresis or 0.0)

    def evaluate(
        self,
        samples: Sequence[Sample],
        *,
        now_epoch_s: float,
        last_fired_epoch_s: float | None = None,
        baselines: Mapping[str, float] | None = None,
        path: str = "",
    ) -> ConditionResult:
        """Evaluate this tree over *recorded* samples. Pure: no IO, no clock.

        ``now_epoch_s`` is injected rather than read: evaluating the same
        recorded samples twice must give the same answer, and an evaluator that
        asked the wall clock could not promise that. Samples recorded after
        ``now_epoch_s`` are outside the evaluated window and are ignored, so a
        live buffer can be handed over safely.

        ``baselines`` overrides each leaf's authored baseline by metric name —
        the seam Phase 2 uses to hand in what its baseline window captured.

        **Cost is O(branches x samples) per call**, because statelessness is
        bought by replaying the recorded series. That is the right trade at
        this layer: a wrong incremental state machine is the exact failure this
        feature exists to prevent, and the caller can always hand over a short
        tail. Phase 2's engine, which evaluates on a cadence for the length of a
        run, is where an incremental form belongs — not here.

        Raises:
            InvariantViolationError: A leaf reads a metric that no recorded
                sample provides. Refused rather than reported as clear.
        """
        if self.kind is not NodeKind.METRIC:
            return self._evaluate_composite(
                samples,
                now_epoch_s=now_epoch_s,
                last_fired_epoch_s=last_fired_epoch_s,
                baselines=baselines,
                path=path,
            )
        assert self.reference is not None  # guaranteed by _shape_matches_kind
        assert self.threshold is not None
        index = _index_by_metric(samples, now_epoch_s=now_epoch_s)
        series = self._resolve(index)
        if not series:
            raise InvariantViolationError(
                "stop_conditions.unknown_metric",
                f"condition {self.describe_name()!r} reads metric "
                f"{self.reference.describe()!r}, which no recorded sample provides: "
                "an unresolvable reference is refused, not reported as clear — a "
                "typo in a metric name is a stop condition that can never fire",
            )
        available = tuple(sample for sample in series if sample.available)
        window_start = available[0].at_epoch_s if available else series[0].at_epoch_s
        if not available:
            return _gate(
                self,
                qualifying=None,
                otherwise=ConditionStatus.UNMEASURED,
                window_start=window_start,
                now_epoch_s=now_epoch_s,
                last_fired_epoch_s=last_fired_epoch_s,
                note=(
                    f"metric {self.reference.describe()!r} has {len(series)} recorded "
                    "sample(s) and none of them is available: nothing was measured, "
                    "so nothing can be said about the bound"
                ),
            )
        baseline = None if baselines is None else baselines.get(self.reference.metric)
        band = self.band()
        run: list[Sample] = []
        for sample in available:
            state = self.threshold.sample_state(sample, baseline=baseline, band=band)
            if state is _SampleState.BREACH:
                run.append(sample)
            elif state is _SampleState.CLEAR:
                run.clear()
        qualifying = _qualifying(
            run,
            for_samples=self.for_samples,
            debounce_s=float(self.debounce),
            now_epoch_s=now_epoch_s,
            window_start=window_start,
            max_duration_s=None if self.max_duration is None else float(self.max_duration),
        )
        if qualifying is None:
            return _gate(
                self,
                qualifying=None,
                otherwise=ConditionStatus.PENDING if run else ConditionStatus.CLEAR,
                window_start=window_start,
                now_epoch_s=now_epoch_s,
                last_fired_epoch_s=last_fired_epoch_s,
                note=_leaf_note(self, run, now_epoch_s=now_epoch_s),
            )
        return _gate(
            self,
            qualifying=qualifying,
            otherwise=ConditionStatus.CLEAR,
            window_start=window_start,
            now_epoch_s=now_epoch_s,
            last_fired_epoch_s=last_fired_epoch_s,
        )

    def _evaluate_composite(
        self,
        samples: Sequence[Sample],
        *,
        now_epoch_s: float,
        last_fired_epoch_s: float | None,
        baselines: Mapping[str, float] | None,
        path: str,
    ) -> ConditionResult:
        """Combine children. Citations follow from what actually fired."""
        results: list[tuple[Condition, ConditionResult]] = []
        for index, operand in enumerate(self.operands):
            step = f"{self.kind.value}[{index}]"
            results.append(
                (
                    operand,
                    operand.evaluate(
                        samples,
                        now_epoch_s=now_epoch_s,
                        last_fired_epoch_s=last_fired_epoch_s,
                        baselines=baselines,
                        path=f"{path}/{step}" if path else step,
                    ),
                )
            )
        statuses = {result.status for _, result in results}
        # The composite is watched for as long as its *earliest* branch has
        # evidence: a node whose window is shorter than a branch's would expire
        # while a branch that started watching earlier is still live.
        starts = [r.window_start_epoch_s for _, r in results if r.window_start_epoch_s is not None]
        window_start = min(starts) if starts else None
        if self.kind is NodeKind.ALL:
            if statuses == {ConditionStatus.FIRED}:
                return _gate(
                    self,
                    qualifying=_Qualification(
                        start_at=min(
                            r.fired_at_epoch_s
                            for _, r in results
                            if r.fired_at_epoch_s is not None
                        ),
                        samples=_dedupe(sample for _, r in results for sample in r.samples),
                    ),
                    otherwise=ConditionStatus.CLEAR,
                    window_start=window_start,
                    now_epoch_s=now_epoch_s,
                    last_fired_epoch_s=last_fired_epoch_s,
                    note="every branch fired",
                    path=path,
                )
            otherwise = _and_status(results)
        else:
            fired = next((r for _, r in results if r.status is ConditionStatus.FIRED), None)
            if fired is not None:
                # Cite the first firing branch only. Every sample in it genuinely
                # contributed; adding a second branch's samples would inflate
                # the evidence behind a claim the tree did not need.
                return _gate(
                    self,
                    qualifying=_Qualification(
                        start_at=fired.fired_at_epoch_s or now_epoch_s,
                        samples=fired.samples,
                    ),
                    otherwise=ConditionStatus.CLEAR,
                    window_start=window_start,
                    now_epoch_s=now_epoch_s,
                    last_fired_epoch_s=last_fired_epoch_s,
                    note=f"{fired.condition_name} fired",
                    path=path,
                )
            otherwise = _any_status(results)
        return _gate(
            self,
            qualifying=None,
            otherwise=otherwise,
            window_start=window_start,
            now_epoch_s=now_epoch_s,
            last_fired_epoch_s=last_fired_epoch_s,
            note=_composite_note(self, results),
            path=path,
        )

    def _resolve(self, index: Mapping[str, tuple[Sample, ...]]) -> tuple[Sample, ...]:
        """The recorded series for this leaf's reference, oldest first."""
        assert self.reference is not None
        series = index.get(self.reference.metric, ())
        if self.reference.source_id:
            series = tuple(
                sample for sample in series if sample.source == self.reference.source_id
            )
        return tuple(sorted(series, key=lambda sample: sample.at_epoch_s))


Condition.model_rebuild()


# -- evaluation internals -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Qualification:
    """A breaching run that cleared every gate, and the samples that cleared it."""

    start_at: float
    samples: tuple[Sample, ...]


def _index_by_metric(
    samples: Sequence[Sample], *, now_epoch_s: float
) -> dict[str, tuple[Sample, ...]]:
    """Group recorded samples by metric, dropping anything past ``now``.

    Silently dropping rather than raising: a caller streaming from a live
    collector hands over its whole buffer, and the tail is not evidence about a
    moment the evaluation is not yet at.
    """
    index: dict[str, list[Sample]] = {}
    for sample in samples:
        if sample.at_epoch_s > now_epoch_s:
            continue
        index.setdefault(sample.metric, []).append(sample)
    return {metric: tuple(series) for metric, series in index.items()}


def _qualifying(
    run: Sequence[Sample],
    *,
    for_samples: int,
    debounce_s: float,
    now_epoch_s: float,
    window_start: float,
    max_duration_s: float | None,
) -> _Qualification | None:
    """Does the current breaching run clear ``for_samples``, debounce, expiry?

    Debounce is measured from the first breaching sample to the evaluation
    instant, not to the last sample: a run with no clear sample behind it has
    been breaching up to now, and measuring to the last sample would let a
    sparse collector reset the clock on every gap. The run must also *start*
    inside the observation window — a breach first seen after ``max_duration``
    had elapsed cannot stop the run it was written to bound, and reporting it
    would let a condition that had already been given up on take the process
    down.
    """
    if len(run) < for_samples:
        return None
    start = run[0].at_epoch_s
    if max_duration_s is not None and start > window_start + max_duration_s:
        return None
    if now_epoch_s - start < debounce_s:
        return None
    return _Qualification(start_at=start, samples=tuple(run))


def _gate(
    condition: Condition,
    *,
    qualifying: _Qualification | None,
    otherwise: ConditionStatus,
    window_start: float | None,
    now_epoch_s: float,
    last_fired_epoch_s: float | None,
    note: str = "",
    path: str = "",
) -> ConditionResult:
    """Apply cooldown and expiry around a qualification, in that order.

    Cooldown first: a condition that fired a moment ago and is still breaching
    is ``suppressed``, not ``expired`` and not ``fired`` again — and both of
    those would be lies about the same run.
    """
    cooldown_s = float(condition.cooldown)
    max_duration_s = None if condition.max_duration is None else float(condition.max_duration)
    suppressed = (
        cooldown_s > 0.0
        and last_fired_epoch_s is not None
        and now_epoch_s - last_fired_epoch_s < cooldown_s
    )
    if suppressed:
        status = ConditionStatus.SUPPRESSED if qualifying is not None else otherwise
        detail = (
            f"fired {now_epoch_s - last_fired_epoch_s:.3f}s ago and may not fire again "
            f"for {cooldown_s:.3f}s"
            if last_fired_epoch_s is not None
            else "within cooldown"
        )
        return ConditionResult(
            condition_name=condition.describe_name(),
            status=status,
            samples=qualifying.samples if qualifying is not None else (),
            fired_at_epoch_s=None,
            window_start_epoch_s=window_start,
            note=f"suppressed by cooldown: {detail}",
            path=path,
        )
    if qualifying is not None:
        return ConditionResult(
            condition_name=condition.describe_name(),
            status=ConditionStatus.FIRED,
            samples=qualifying.samples,
            fired_at_epoch_s=now_epoch_s,
            window_start_epoch_s=window_start,
            note=note,
            path=path,
        )
    if (
        max_duration_s is not None
        and window_start is not None
        and now_epoch_s - window_start >= max_duration_s
    ):
        return ConditionResult(
            condition_name=condition.describe_name(),
            status=ConditionStatus.EXPIRED,
            samples=(),
            fired_at_epoch_s=None,
            window_start_epoch_s=window_start,
            note=(
                f"watched for {now_epoch_s - window_start:.3f}s of a permitted "
                f"{max_duration_s:.3f}s without qualifying: a stop condition that "
                "cannot fire is a no-op, and saying so beats watching in silence"
            ),
            path=path,
        )
    return ConditionResult(
        condition_name=condition.describe_name(),
        status=otherwise,
        samples=(),
        fired_at_epoch_s=None,
        window_start_epoch_s=window_start,
        note=note,
        path=path,
    )


def _dedupe(samples: Iterable[Sample]) -> tuple[Sample, ...]:
    """Distinct samples in first-seen order, so a shared boundary cites once."""
    seen: list[Sample] = []
    for sample in samples:
        if sample not in seen:
            seen.append(sample)
    return tuple(seen)


def _leaf_note(condition: Condition, run: Sequence[Sample], *, now_epoch_s: float) -> str:
    """Say why a breaching-but-unqualified run has not fired yet."""
    if not run:
        return "not breaching"
    if len(run) < condition.for_samples:
        return f"breaching on {len(run)} of {condition.for_samples} required consecutive sample(s)"
    held = now_epoch_s - run[0].at_epoch_s
    return (
        f"breaching for {held:.3f}s of the {float(condition.debounce):.3f}s this "
        "condition requires"
    )


def _and_status(results: Sequence[tuple[Condition, ConditionResult]]) -> ConditionStatus:
    """Worst status wins when a conjunction has not fired."""
    statuses = {result.status for _, result in results}
    for status in (
        ConditionStatus.EXPIRED,
        ConditionStatus.SUPPRESSED,
        ConditionStatus.UNMEASURED,
        ConditionStatus.PENDING,
    ):
        if status in statuses:
            return status
    return ConditionStatus.CLEAR


def _any_status(results: Sequence[tuple[Condition, ConditionResult]]) -> ConditionStatus:
    """A disjunction that has not fired is pending, else clear."""
    statuses = {result.status for _, result in results}
    if ConditionStatus.PENDING in statuses:
        return ConditionStatus.PENDING
    return ConditionStatus.CLEAR


def _composite_note(
    condition: Condition, results: Sequence[tuple[Condition, ConditionResult]]
) -> str:
    """Name every branch and its status, so "clear" is never mistaken for health.

    A composite that has not fired reports *why* per branch rather than a bare
    status: "clear" on a conjunction whose branches are ``fired`` and ``clear``
    is technically true and completely useless to whoever reads the run.
    """
    parts = [
        f"{operand.describe_name()}={result.status.value}" for operand, result in results
    ]
    lead = (
        "not every branch fired" if condition.kind is NodeKind.ALL else "no branch fired"
    )
    return f"{lead}: " + ", ".join(parts)


# -- results ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConditionResult:
    """What evaluating one condition concluded, and on which samples.

    The ``fired``/``samples`` pairing is enforced here as well as on
    :class:`Firing`: a result that fired without citations is not
    constructible, so the defect cannot reach a report by way of the evaluator
    either.
    """

    condition_name: str
    status: ConditionStatus
    samples: tuple[Sample, ...] = ()
    fired_at_epoch_s: float | None = None
    window_start_epoch_s: float | None = None
    note: str = ""
    path: str = ""

    def __post_init__(self) -> None:
        if self.status is ConditionStatus.FIRED:
            if not self.samples:
                raise InvariantViolationError(
                    "stop_conditions.firing_without_citations",
                    f"condition {self.condition_name!r} fired with no cited samples: "
                    "a stop that cannot name the evidence behind it cannot be "
                    "reviewed, replayed or defended",
                )
            if self.fired_at_epoch_s is None:
                raise InvariantViolationError(
                    "stop_conditions.firing_without_timestamp",
                    f"condition {self.condition_name!r} fired without a timestamp: the "
                    "moment a run was stopped is part of what it must explain",
                )

    @property
    def fired(self) -> bool:
        return self.status is ConditionStatus.FIRED

    @property
    def sample_count(self) -> int:
        return len(self.samples)

    def to_firing(self) -> Firing:
        """Promote a fired result to a citable :class:`Firing`.

        Raises:
            InvariantViolationError: This result did not fire. There is no
                "firing" to promote, and manufacturing one here is how an
                uncited stop gets into a report.
        """
        if not self.fired:
            raise InvariantViolationError(
                "stop_conditions.not_fired",
                f"condition {self.condition_name!r} is {self.status.value}, not "
                "fired: there is no firing to record",
            )
        # __post_init__ already refuses to construct a fired result without a
        # timestamp; the assertion states that invariant to the type checker.
        assert self.fired_at_epoch_s is not None
        return Firing(
            condition_name=self.condition_name,
            path=self.path,
            samples=self.samples,
            fired_at_epoch_s=self.fired_at_epoch_s,
            note=self.note,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "condition": self.condition_name,
            "path": self.path,
            "status": self.status.value,
            "fired": self.fired,
            "fired_at_epoch_s": self.fired_at_epoch_s,
            "window_start_epoch_s": self.window_start_epoch_s,
            "sample_count": len(self.samples),
            "samples": [sample.to_dict() for sample in self.samples],
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class Firing:
    """A stop, and the recorded samples that justify it.

    The only way to get one is from a result that actually fired, and the only
    way to build one directly is with at least one cited sample — so
    ``Firing(samples=())`` is a type error rather than a silent lie. Each cited
    sample must itself be available: citing a ``missing`` observation as proof
    of a breach is the same defect one layer down.
    """

    condition_name: str
    samples: tuple[Sample, ...]
    fired_at_epoch_s: float
    path: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        if not self.samples:
            raise InvariantViolationError(
                "stop_conditions.firing_without_citations",
                f"firing for condition {self.condition_name!r} cites no samples: a "
                "stop with no evidence behind it is a defect, not a warning — it is "
                "indistinguishable from a run that stopped for an unrelated reason",
            )
        unmeasured = [sample for sample in self.samples if not sample.available]
        if unmeasured:
            raise InvariantViolationError(
                "stop_conditions.firing_cites_unavailable_sample",
                f"firing for condition {self.condition_name!r} cites "
                f"{len(unmeasured)} unavailable sample(s) "
                f"(first: {unmeasured[0].metric!r}={unmeasured[0].observation.status.value}): "
                "a sample that was never measured cannot justify a stop",
            )
        if not isfinite(self.fired_at_epoch_s):
            raise InvariantViolationError(
                "stop_conditions.firing_time_not_finite",
                f"firing for condition {self.condition_name!r} carries a non-finite "
                f"timestamp ({self.fired_at_epoch_s!r})",
            )

    @property
    def sample_count(self) -> int:
        return len(self.samples)

    def cites(self, sample: Sample) -> bool:
        """Is this exact recorded sample part of the evidence for the stop?"""
        return sample in self.samples

    def to_dict(self) -> dict[str, object]:
        return {
            "condition": self.condition_name,
            "path": self.path,
            "fired_at_epoch_s": self.fired_at_epoch_s,
            "sample_count": self.sample_count,
            "samples": [sample.to_dict() for sample in self.samples],
            "note": self.note,
        }
