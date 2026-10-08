"""Quantitative resilience characterisation: the arithmetic behind the graded
verdict (docs/v1.1.0/15_RESILIENCE_ANALYTICS_ADAPTIVE.md, Phase 1).

This module **extends** :mod:`mayhem.domain.steady_state`; it never replaces
it. Steady state already owns the authored vocabulary (``expect`` vs
``tolerance``), the graded :class:`~mayhem.domain.steady_state.Verdict`, and
the baseline reduction, and it already refuses to grade a signal whose baseline
is short or non-finite. Everything here is built *on top of* those two
commitments, and where a statistic already exists it is imported rather than
re-derived, so there is exactly one definition of "the percentile of this
series" (:func:`sample_baseline`) and exactly one definition of "moved by
percent" (:func:`delta_pct`) in the whole domain.

**Why anything is here at all.** Plan 15's verdict example is *"p99 moved 5.2%
with overlapping 95% CI — NO MATERIAL EFFECT"*. The graded verdict in steady
state can say *whether* a signal moved against a declared bound; it cannot say
how much of the move is the fault and how much is the noise floor of the
system under test. Five samples is not a baseline — the same plan says that
three pages earlier — and a fifth sample does not help. So this module adds
the two numbers that were missing: a **confidence interval** per distribution,
and an **effect size** for the difference between two of them.

**No material effect is a first-class outcome.** :class:`EffectOutcome` has a
member for it. A comparison that cannot separate signal from noise reports
``NO_MATERIAL_EFFECT``, not a pass on one number and a failure on another —
which is the whole point of moving from binary chaos testing toward
characterisation. Note what that outcome does *not* mean: it means this run
could not distinguish the change from the noise, not that the system is fine.

**Two decisions are separated deliberately.** The *statistical* question ("is
the difference distinguishable from noise?") is answered by the confidence
interval on the difference of means, which is the only one of the two that can
say no. The *perceptual* question ("do the two series' intervals sit on top of
each other?") is answered by :meth:`ConfidenceInterval.overlaps` and is
reported alongside, because the plan's own wording is about overlap. The two
are not interchangeable — with series of very different sizes the intervals can
be disjoint while the difference is not distinguishable, and the overlap can
sit comfortably across a difference that is — so the outcome is decided by the
difference CI and the overlap is reported beside it. Both numbers are in
:meth:`Comparison.to_dict` and neither is hidden.

**Insufficient data is not scored.** :class:`SamplePolicy` is the same
refusal steady state makes, in the same voice: a comparison below the floor
returns ``INSUFFICIENT_DATA`` with no effect size, no interval, and no verdict
phrase that could be quoted as a finding. So is a comparison whose two series
are both constant — no spread means no interval, and "no material effect"
inferred from two identical readings is a coincidence wearing a conclusion.

Everything below is pure: it reads recorded samples and returns values. It
performs no IO, captures nothing, renders nothing, and consults no clock.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from math import isfinite, sqrt
from statistics import NormalDist, fmean, median, stdev
from typing import TYPE_CHECKING

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.steady_state import delta_pct, sample_baseline

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "BELOW_MATERIALITY_NOTE",
    "CI_METHOD",
    "COHENS_D_LARGE",
    "COHENS_D_MEDIUM",
    "COHENS_D_SMALL",
    "DEFAULT_LEVEL",
    "DEFAULT_PERCENTILES",
    "INSUFFICIENT_SAMPLES_NOTE",
    "MIN_COMPARABLE_SAMPLES",
    "NO_EFFECT_NOTE",
    "NO_SPREAD_NOTE",
    "Comparison",
    "ConfidenceInterval",
    "DistributionSummary",
    "EffectOutcome",
    "EffectSize",
    "ObservationPhase",
    "SamplePolicy",
    "SegmentedSamples",
    "Sufficiency",
    "WindowPlan",
    "cohens_d",
    "compare",
    "mean_confidence_interval",
    "summarize",
]

MIN_COMPARABLE_SAMPLES = 5
"""The floor for grading a comparison, matching ``CaptureSpec.samples``.

Five is the smallest number of samples from which a spread can be estimated at
all, and it is the same floor steady state already refuses to grade below. Two
distributions may each carry more; neither may carry fewer.
"""

DEFAULT_LEVEL = 0.95
DEFAULT_PERCENTILES: tuple[float, ...] = (50.0, 90.0, 95.0, 99.0)
CI_METHOD = "normal-approximation"

COHENS_D_SMALL = 0.2
COHENS_D_MEDIUM = 0.5
COHENS_D_LARGE = 0.8

_NORMAL = NormalDist()

INSUFFICIENT_SAMPLES_NOTE = (
    "compared on {baseline_samples} baseline / {window_samples} window samples against a "
    "required minimum of {min_baseline}/{min_window}: too few samples to separate the "
    "change from the noise floor, so this is reported, not scored"
)
NO_EFFECT_NOTE = (
    "the 95% confidence interval on the difference of means contains zero: the movement "
    "cannot be separated from the run-to-run spread of the system under test. This does "
    "not mean the signal did not move"
)
BELOW_MATERIALITY_NOTE = (
    "statistically distinguishable, but the movement is below the declared materiality "
    "floor of {floor}%: a difference nobody would act on is not a material effect"
)
NO_SPREAD_NOTE = (
    "every recorded sample in both windows is identical, so there is no spread to "
    "estimate a difference interval from. A capture with no variation at all is a "
    "stuck probe, not a steady system, and reporting 'no material effect' from it would "
    "be a coincidence dressed as a conclusion"
)


# -- confidence intervals -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConfidenceInterval:
    """An interval on one statistic, with the level and method that produced it.

    :meth:`contains` is the test that decides whether a difference is
    distinguishable from noise; :meth:`overlaps` is the plainer observation
    about how wide two intervals sit relative to each other, and it carries no
    such authority. :class:`Comparison` decides on the first and reports the
    second beside it.
    """

    level: float
    low: float
    high: float
    center: float
    method: str = CI_METHOD
    samples: int = 0

    @property
    def half_width(self) -> float:
        return (self.high - self.low) / 2.0

    @property
    def width(self) -> float:
        return self.high - self.low

    def contains(self, value: float) -> bool:
        """True when ``value`` lies inside the interval, bounds included."""
        return isfinite(value) and self.low <= value <= self.high

    def overlaps(self, other: ConfidenceInterval) -> bool:
        """True when the two intervals share at least one value.

        Touching intervals count as overlapping: a difference of exactly one
        combined half-width puts both bounds on the same number, and rounding
        in a reported figure must not turn that into a clean separation.

        Overlap is **not** a significance test and does not imply one. Two wide
        intervals on series of very different sizes can overlap while the
        difference between them is firmly distinguishable, and two tight
        intervals on the *same* number of samples cannot overlap while the
        difference is real — neither reading travels in the other direction
        either. :class:`Comparison` therefore decides its outcome on the interval
        of the difference and reports the overlap beside it, never instead of it.
        """
        return self.low <= other.high and other.low <= self.high

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def mean_confidence_interval(
    values: Sequence[float], *, level: float = DEFAULT_LEVEL
) -> ConfidenceInterval | None:
    """The ``level`` interval around the mean of ``values``.

    Normal approximation: ``mean ± z * s / sqrt(n)``. It is the textbook
    estimator, it is stdlib-only (``statistics.NormalDist``), and it is exact
    enough at the sample sizes this tool captures — the alternative, a
    bootstrap, would need a seeded RNG to stay deterministic and would not be
    better at n < 30, which is the regime every honest capture here lives in.
    The method name travels on the interval so a report can say how it was
    produced rather than implying more than it should.

    ``None`` for fewer than two samples: a spread cannot be estimated from one
    number, and ``0.0`` would be a claim of perfect knowledge.
    """
    finite = [v for v in values if isfinite(v)]
    if len(finite) < 2:
        return None
    centre = fmean(finite)
    spread = stdev(finite)
    half = _NORMAL.inv_cdf(0.5 + level / 2.0) * spread / sqrt(len(finite))
    return ConfidenceInterval(
        level=level,
        low=centre - half,
        high=centre + half,
        center=centre,
        method=CI_METHOD,
        samples=len(finite),
    )


def difference_confidence_interval(
    baseline: Sequence[float], window: Sequence[float], *, level: float = DEFAULT_LEVEL
) -> ConfidenceInterval | None:
    """The ``level`` interval around ``mean(window) - mean(baseline)``.

    This is the statistic the verdict is decided on. ``None`` when either
    series has fewer than two samples, for the same reason as
    :func:`mean_confidence_interval`.
    """
    base = [v for v in baseline if isfinite(v)]
    test = [v for v in window if isfinite(v)]
    if len(base) < 2 or len(test) < 2:
        return None
    shift = fmean(test) - fmean(base)
    pooled = pooled_stdev(base, test)
    if pooled is None:
        return None
    half = _NORMAL.inv_cdf(0.5 + level / 2.0) * pooled * sqrt(1.0 / len(base) + 1.0 / len(test))
    return ConfidenceInterval(
        level=level,
        low=shift - half,
        high=shift + half,
        center=shift,
        method=CI_METHOD,
        samples=len(base) + len(test),
    )


def pooled_stdev(baseline: Sequence[float], window: Sequence[float]) -> float | None:
    """The pooled within-series spread, or ``None`` when it cannot be formed.

    ``None`` — never ``0.0`` and never a divide-by-zero — when either series
    has a single sample, or when both are constant and the pooled spread is
    exactly zero. A zero spread is not "no effect", it is "no measurable
    variation", and the effect size derived from it is undefined rather than
    infinite.
    """
    base = [v for v in baseline if isfinite(v)]
    test = [v for v in window if isfinite(v)]
    if len(base) < 2 or len(test) < 2:
        return None
    degrees = len(base) + len(test) - 2
    variance = ((len(base) - 1) * stdev(base) ** 2 + (len(test) - 1) * stdev(test) ** 2) / degrees
    pooled = sqrt(variance)
    return pooled if isfinite(pooled) and pooled > 0.0 else None


# -- effect size ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EffectSize:
    """Cohen's *d*: the shift measured in units of the pooled spread.

    Signed, so a fall is a negative *d*. ``magnitude`` is the conventional
    small/medium/large reading and is reported as a *description of the number*,
    never as a pass or a fail — the thresholds are Cohen's conventions, not a
    verdict anyone approved for this system.
    """

    value: float
    baseline_samples: int
    window_samples: int
    kind: str = "cohens-d"

    @property
    def magnitude(self) -> str:
        size = abs(self.value)
        if size < COHENS_D_SMALL:
            return "negligible"
        if size < COHENS_D_MEDIUM:
            return "small"
        if size < COHENS_D_LARGE:
            return "medium"
        return "large"

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["magnitude"] = self.magnitude
        return payload


def cohens_d(baseline: Sequence[float], window: Sequence[float]) -> EffectSize | None:
    """Cohen's *d* between two sample series, or ``None`` when undefined.

    ``None`` rather than a number whenever the pooled spread is zero or
    unestimable. A constant baseline and a constant window do not have a small
    effect size, they have no effect size, and ``0/0`` reported as ``inf`` is
    how a report ends up claiming certainty.
    """
    base = [v for v in baseline if isfinite(v)]
    test = [v for v in window if isfinite(v)]
    pooled = pooled_stdev(base, test)
    if pooled is None:
        return None
    return EffectSize(
        value=(fmean(test) - fmean(base)) / pooled,
        baseline_samples=len(base),
        window_samples=len(test),
    )


# -- distributions --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DistributionSummary:
    """One sample series reduced to the numbers a report can quote.

    ``mean_ci`` is ``None`` when fewer than two finite samples were captured,
    for the same reason :func:`mean_confidence_interval` is. Non-finite
    samples (``nan`` from a probe that returned nothing) are dropped and
    counted in ``dropped`` rather than quietly poisoning the mean — a dropped
    sample is a fact about the capture, and the count says so.
    """

    count: int
    minimum: float
    maximum: float
    mean: float
    median: float
    stdev: float
    percentiles: dict[float, float]
    mean_ci: ConfidenceInterval | None
    dropped: int = 0

    def percentile(self, point: float) -> float | None:
        """The nearest-rank percentile, or ``None`` when it was not requested."""
        return self.percentiles.get(point)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "count": self.count,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "mean": self.mean,
            "median": self.median,
            "stdev": self.stdev,
            "mean_ci": None if self.mean_ci is None else self.mean_ci.to_dict(),
            "dropped": self.dropped,
            "percentiles": {str(key): value for key, value in sorted(self.percentiles.items())},
        }
        return payload


def summarize(
    values: Sequence[float],
    *,
    percentiles: Sequence[float] = DEFAULT_PERCENTILES,
    level: float = DEFAULT_LEVEL,
) -> DistributionSummary | None:
    """Reduce a recorded series to a :class:`DistributionSummary`.

    ``None`` when nothing finite was recorded — the same refusal
    :func:`sample_baseline` makes. Percentiles come from
    :func:`sample_baseline` (nearest rank over the finite samples) so that the
    percentile this module reports and the baseline steady state captured can
    never disagree by a rounding rule.
    """
    if not 0.0 < level < 1.0:
        raise InvariantViolationError(
            "analytics.confidence_level_out_of_range",
            f"confidence level must be strictly between 0 and 1, got {level}: a level "
            "outside that range produces an interval that is not an interval",
        )
    finite = sorted(v for v in values if isfinite(v))
    if not finite:
        return None
    resolved: dict[float, float] = {}
    for point in percentiles:
        if not 0.0 < point <= 100.0:
            raise InvariantViolationError(
                "analytics.percentile_out_of_range",
                f"percentile must be in (0, 100], got {point}",
            )
        reduced = sample_baseline(finite, percentile=point)
        if reduced is not None:
            resolved[point] = reduced.value
    return DistributionSummary(
        count=len(finite),
        minimum=finite[0],
        maximum=finite[-1],
        mean=fmean(finite),
        median=median(finite),
        stdev=stdev(finite) if len(finite) > 1 else 0.0,
        percentiles=resolved,
        mean_ci=mean_confidence_interval(finite, level=level),
        dropped=len(values) - len(finite),
    )


# -- warm-up and cooldown -------------------------------------------------------------


class ObservationPhase(StrEnum):
    """Which part of a run a recorded sample belongs to.

    The three phases are ordered and non-overlapping. Warm-up is the settling
    period after a fault lands, cooldown the settling period after it is
    removed, and neither belongs in the window a comparison reads.
    """

    WARMUP = "warmup"
    MEASURED = "measured"
    COOLDOWN = "cooldown"


@dataclass(frozen=True, slots=True)
class WindowPlan:
    """How many samples each phase gets out of one recorded run.

    ``measured >= 1`` is required: a window that measures nothing is a run that
    reported nothing, which is a different failure and is refused at
    construction rather than discovered downstream as an empty comparison.
    """

    warmup: int = 0
    measured: int = MIN_COMPARABLE_SAMPLES
    cooldown: int = 0

    def __post_init__(self) -> None:
        for name in ("warmup", "measured", "cooldown"):
            value = getattr(self, name)
            if value < 0:
                raise InvariantViolationError(
                    "analytics.window_sample_negative",
                    f"{name}={value}: a phase cannot be given a negative number of samples",
                )
        if self.measured < 1:
            raise InvariantViolationError(
                "analytics.window_measures_nothing",
                "a window plan must measure at least one sample: a run that measures "
                "nothing would report 'no material effect' having observed nothing",
            )

    @property
    def total(self) -> int:
        return self.warmup + self.measured + self.cooldown

    def split(self, values: Sequence[float]) -> SegmentedSamples:
        """Assign a recorded series to the three phases, in order.

        Samples the plan did not account for are counted in ``dropped`` and
        samples the plan asked for but the run did not supply are counted in
        ``missing``. Both are surfaced rather than discarded: a window that
        quietly loses half its samples is how a comparison ends up graded on
        three values it was told it would have fifty of.
        """
        warmup = tuple(values[: self.warmup])
        measured = tuple(values[self.warmup : self.warmup + self.measured])
        cooldown = tuple(values[self.warmup + self.measured : self.total])
        return SegmentedSamples(
            warmup=warmup,
            measured=measured,
            cooldown=cooldown,
            plan=self,
            dropped=max(0, len(values) - self.total),
            missing=(self.warmup - len(warmup))
            + (self.measured - len(measured))
            + (self.cooldown - len(cooldown)),
        )


@dataclass(frozen=True, slots=True)
class SegmentedSamples:
    """One recorded series, split by phase."""

    warmup: tuple[float, ...]
    measured: tuple[float, ...]
    cooldown: tuple[float, ...]
    plan: WindowPlan
    dropped: int = 0
    missing: int = 0

    @property
    def complete(self) -> bool:
        """True when the run supplied every sample the plan asked for."""
        return self.dropped == 0 and self.missing == 0

    def values(self, phase: ObservationPhase) -> tuple[float, ...]:
        """The samples recorded for one phase."""
        return {
            ObservationPhase.WARMUP: self.warmup,
            ObservationPhase.MEASURED: self.measured,
            ObservationPhase.COOLDOWN: self.cooldown,
        }[phase]

    def to_dict(self) -> dict[str, object]:
        return {
            "plan": {
                "warmup": self.plan.warmup,
                "measured": self.plan.measured,
                "cooldown": self.plan.cooldown,
            },
            "warmup": list(self.warmup),
            "measured": list(self.measured),
            "cooldown": list(self.cooldown),
            "dropped": self.dropped,
            "missing": self.missing,
            "complete": self.complete,
        }


# -- sample sufficiency ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Sufficiency:
    """Whether a comparison had enough samples to be scored at all."""

    required_baseline: int
    required_window: int
    baseline_samples: int
    window_samples: int
    sufficient: bool
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SamplePolicy:
    """The floor a comparison must clear before it is scored.

    Separated from :class:`mayhem.domain.steady_state.CaptureSpec` on purpose:
    that model is *authored input* (how many pre-fault samples to take), this
    one is the *grading floor* applied to two series at once. They default to
    the same number and can be set apart when a capture is deliberately
    asymmetric.
    """

    min_baseline: int = MIN_COMPARABLE_SAMPLES
    min_window: int = MIN_COMPARABLE_SAMPLES

    def __post_init__(self) -> None:
        for name in ("min_baseline", "min_window"):
            value = getattr(self, name)
            if value < 1:
                raise InvariantViolationError(
                    "analytics.sample_floor_below_one",
                    f"{name}={value}: a floor below one sample grades a number nobody measured",
                )

    def check(self, baseline_samples: int, window_samples: int) -> Sufficiency:
        """Judge two sample counts against this floor."""
        sufficient = baseline_samples >= self.min_baseline and window_samples >= self.min_window
        reason = (
            ""
            if sufficient
            else INSUFFICIENT_SAMPLES_NOTE.format(
                baseline_samples=baseline_samples,
                window_samples=window_samples,
                min_baseline=self.min_baseline,
                min_window=self.min_window,
            )
        )
        return Sufficiency(
            required_baseline=self.min_baseline,
            required_window=self.min_window,
            baseline_samples=baseline_samples,
            window_samples=window_samples,
            sufficient=sufficient,
            reason=reason,
        )


# -- comparison -----------------------------------------------------------------------


class EffectOutcome(StrEnum):
    """What a baseline-vs-window comparison concluded.

    ``INSUFFICIENT_DATA`` comes first on purpose and is not a flavour of
    "no effect": the comparison was never run. ``NO_MATERIAL_EFFECT`` is a
    real conclusion — the difference could not be separated from the noise —
    and it is the outcome plan 15 asks a verdict to be able to say.
    """

    INSUFFICIENT_DATA = "insufficient-data"
    NO_MATERIAL_EFFECT = "no-material-effect"
    MATERIAL_RISE = "material-rise"
    MATERIAL_FALL = "material-fall"


@dataclass(frozen=True, slots=True)
class Comparison:
    """One baseline-vs-window comparison, carrying everything that decided it.

    Every numeric field is optional because the honest answer is sometimes "no
    number to quote". When the comparison was refused — below the
    :class:`SamplePolicy` floor, or with no measurable spread — the effect size
    and every interval are ``None``, not zero and not a fabricated default, and
    :attr:`outcome` is ``INSUFFICIENT_DATA``, which makes :attr:`graded` false.
    A caller that checks only ``outcome`` cannot read a score out of an
    unscored comparison, which is what keeps "we could not tell" from decaying
    into "it was fine". (Where a measurement exists it is still quoted: the
    point movement of the compared percentile is a fact about the capture,
    whereas the interval and the effect size are inferences, and the two are
    not treated alike.)
    """

    name: str
    percentile: float
    sufficiency: Sufficiency
    outcome: EffectOutcome
    baseline: DistributionSummary | None = None
    window: DistributionSummary | None = None
    baseline_point: float | None = None
    window_point: float | None = None
    point_delta_pct: float | None = None
    baseline_ci: ConfidenceInterval | None = None
    window_ci: ConfidenceInterval | None = None
    difference_ci: ConfidenceInterval | None = None
    effect_size: EffectSize | None = None
    intervals_overlap: bool | None = None
    materiality_pct: float | None = None
    level: float = DEFAULT_LEVEL
    note: str = ""

    @property
    def sufficient(self) -> bool:
        return self.sufficiency.sufficient

    @property
    def graded(self) -> bool:
        """True when the comparison was scored rather than refused.

        Two things refuse it: too few samples to satisfy the floor, and a
        capture with no measurable spread at all (see :data:`NO_SPREAD_NOTE`).
        Both report ``INSUFFICIENT_DATA``, so a caller reading only
        :attr:`outcome` cannot tell a scored result from an unscored one.
        """
        return self.outcome is not EffectOutcome.INSUFFICIENT_DATA

    @property
    def material(self) -> bool:
        """True only for a scored comparison that separated from the noise."""
        return self.outcome in (EffectOutcome.MATERIAL_RISE, EffectOutcome.MATERIAL_FALL)

    @property
    def statistic(self) -> str:
        """The statistic this comparison names, e.g. ``p99``."""
        return f"p{self.percentile:g}"

    @property
    def verdict_phrase(self) -> str:
        """The sentence a report quotes — plan 15's example, produced by code.

        *"p99 moved 5.2% with overlapping 95% CI — NO MATERIAL EFFECT"*. The
        clause names whichever interval fact supports the outcome that was
        actually reached, so the sentence and the verdict cannot disagree:
        overlap is quoted when the per-series intervals overlap, and the
        difference interval is named explicitly when the overlap does not
        describe the decision.
        """
        if self.outcome is EffectOutcome.INSUFFICIENT_DATA:
            if not self.sufficient:
                return (
                    f"{self.statistic} compared on {self.sufficiency.baseline_samples} "
                    f"baseline / {self.sufficiency.window_samples} window samples — "
                    "NOT GRADED"
                )
            return f"{self.statistic} — NOT GRADED: {self.note}"
        if self.point_delta_pct is None:
            moved = (
                f"{self.statistic} moved from {self.baseline_point} to {self.window_point} "
                "with no relative scale"
            )
        else:
            moved = f"{self.statistic} moved {self.point_delta_pct:.1f}%"
        level = f"{self.level * 100:g}%"
        if self.outcome is EffectOutcome.NO_MATERIAL_EFFECT:
            ci_clause = (
                f"overlapping {level} CI"
                if self.intervals_overlap
                else f"a {level} CI on the difference containing zero"
            )
        elif self.intervals_overlap:
            ci_clause = f"overlapping per-series {level} CIs, difference CI excluding zero"
        else:
            ci_clause = f"disjoint {level} CI"
        label = self.outcome.value.replace("-", " ").upper()
        return f"{moved} with {ci_clause} — {label}"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "percentile": self.percentile,
            "statistic": self.statistic,
            "outcome": self.outcome.value,
            "sufficient": self.sufficient,
            "graded": self.graded,
            "material": self.material,
            "sufficiency": self.sufficiency.to_dict(),
            "baseline": None if self.baseline is None else self.baseline.to_dict(),
            "window": None if self.window is None else self.window.to_dict(),
            "baseline_point": self.baseline_point,
            "window_point": self.window_point,
            "point_delta_pct": self.point_delta_pct,
            "baseline_ci": None if self.baseline_ci is None else self.baseline_ci.to_dict(),
            "window_ci": None if self.window_ci is None else self.window_ci.to_dict(),
            "difference_ci": None if self.difference_ci is None else self.difference_ci.to_dict(),
            "effect_size": None if self.effect_size is None else self.effect_size.to_dict(),
            "intervals_overlap": self.intervals_overlap,
            "materiality_pct": self.materiality_pct,
            "level": self.level,
            "note": self.note,
            "verdict_phrase": self.verdict_phrase,
        }


def compare(
    baseline_values: Sequence[float],
    window_values: Sequence[float],
    *,
    name: str,
    percentile: float = 99.0,
    policy: SamplePolicy | None = None,
    level: float = DEFAULT_LEVEL,
    materiality_pct: float | None = None,
) -> Comparison:
    """Compare a recorded baseline series against a recorded window series.

    Pure, and it decides the outcome in this order:

    1. **Sufficiency first.** Below the :class:`SamplePolicy` floor the result
       is ``INSUFFICIENT_DATA`` with no effect size, no interval and no
       movement figure. Nothing downstream can read a score out of it.
    2. **Then the difference interval.** A ``level`` interval whose span
       contains zero is ``NO_MATERIAL_EFFECT``. This is the decision test; the
       per-series interval overlap is reported beside it and never overrides
       it. A difference interval that cannot be estimated at all — both series
       constant, no spread — is also ``INSUFFICIENT_DATA``, never
       ``NO_MATERIAL_EFFECT``.
    3. **Then the materiality floor**, when one is declared. A difference the
       interval can separate but which moves the quoted statistic by less than
       ``materiality_pct`` is reported ``NO_MATERIAL_EFFECT`` with the reason
       attached: a difference nobody would act on is not a material effect, and
       the note says which of the two rules produced the answer.
    4. Otherwise the sign of the shift decides ``MATERIAL_RISE`` or
       ``MATERIAL_FALL``.

    ``percentile`` names the statistic the reported movement is quoted on
    (plan 15's example is p99); the interval and effect size are always
    computed on the means, because that is what the interval test is valid
    for. Both numbers are in the result.
    """
    floor = SamplePolicy() if policy is None else policy
    baseline = summarize(baseline_values, level=level)
    window = summarize(window_values, level=level)
    base_count = 0 if baseline is None else baseline.count
    window_count = 0 if window is None else window.count
    sufficiency = floor.check(base_count, window_count)

    base_point = baseline.percentile(percentile) if baseline is not None else None
    window_point = window.percentile(percentile) if window is not None else None

    if not sufficiency.sufficient or baseline is None or window is None:
        # The second disjunct is unreachable — a floor of one sample or more
        # means both series produced a summary — but it is tested rather than
        # asserted, so the refusal still holds under ``python -O``.
        return Comparison(
            name=name,
            percentile=percentile,
            sufficiency=sufficiency,
            outcome=EffectOutcome.INSUFFICIENT_DATA,
            baseline=baseline,
            window=window,
            materiality_pct=materiality_pct,
            level=level,
            note=sufficiency.reason or NO_SPREAD_NOTE,
        )

    baseline_ci = baseline.mean_ci
    window_ci = window.mean_ci
    difference_ci = difference_confidence_interval(baseline_values, window_values, level=level)
    effect = cohens_d(baseline_values, window_values)
    overlap = None if baseline_ci is None or window_ci is None else baseline_ci.overlaps(window_ci)
    # The sign is taken from the shift in the metric's own units. A percentage of
    # a percentage is not a direction.
    shift = 0.0 if difference_ci is None else difference_ci.center
    floor_units = _materiality_floor(base_point, materiality_pct)

    if difference_ci is None:
        outcome = EffectOutcome.INSUFFICIENT_DATA
        note = NO_SPREAD_NOTE
    elif difference_ci.contains(0.0):
        outcome = EffectOutcome.NO_MATERIAL_EFFECT
        note = NO_EFFECT_NOTE
    elif materiality_pct is not None and abs(shift) < floor_units:
        outcome = EffectOutcome.NO_MATERIAL_EFFECT
        note = BELOW_MATERIALITY_NOTE.format(floor=materiality_pct)
    else:
        outcome = EffectOutcome.MATERIAL_RISE if shift > 0 else EffectOutcome.MATERIAL_FALL
        note = ""

    return Comparison(
        name=name,
        percentile=percentile,
        sufficiency=sufficiency,
        outcome=outcome,
        baseline=baseline,
        window=window,
        baseline_point=base_point,
        window_point=window_point,
        point_delta_pct=None
        if base_point is None or window_point is None
        else delta_pct(base_point, window_point),
        baseline_ci=baseline_ci,
        window_ci=window_ci,
        difference_ci=difference_ci,
        effect_size=effect,
        intervals_overlap=overlap,
        materiality_pct=materiality_pct,
        level=level,
        note=note,
    )


def _materiality_floor(baseline_point: float | None, materiality_pct: float | None) -> float:
    """The absolute movement a ``materiality_pct`` floor demands.

    ``inf`` when no floor was declared or the baseline is unquotable, which
    makes the floor unreachable and leaves the interval test in sole control —
    the honest behaviour when there is nothing to compare against.
    """
    if materiality_pct is None or baseline_point is None:
        return float("inf")
    return abs(baseline_point) * materiality_pct / 100.0
