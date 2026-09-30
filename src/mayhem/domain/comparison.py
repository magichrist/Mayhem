"""Run equivalence and the resilience delta report (plan 22, gap 102).

Two runs of the same experiment are only *comparable* when everything except
the thing under test is pinned identically. This module makes that a predicate
over the pin vector rather than a convention in a dashboard:

    experiment, environment, plan, policy, catalog, agent and runtime versions,
    and the journey program pin when the run was a journey probe.

``release`` is deliberately **not** part of that vector. The release is the axis
the comparison is *about* — the new release is the whole reason there are two
runs — so treating it as a fixed dimension would make every comparison
incomparable with itself. Every other axis is fixed, because a latency delta
between a v2.4 run with policy 7 and a v2.5 run with policy 8 measures the
policy change too, and reporting that as a resilience regression is how a
regression signal becomes noise that people learn to ignore.

Three outcomes are refusals, and each is a first-class value rather than an
absence:

* :data:`ComparisonOutcome.INCOMPARABLE` — the pins differ. The report is
  returned with **no deltas at all** and a reason naming every differing axis.
  A refused comparison is not scored, not zeroed, and not reported as "no
  change": scoring it would produce a number about a comparison nobody made.
* :data:`ComparisonOutcome.INSUFFICIENT_DATA` — the runs are equivalent, but
  at least one declared metric could not be measured on one of them (absent,
  non-finite, or fewer samples than the metric requires). This is an explicit
  outcome and it is never an implied pass. :attr:`DeltaReport.improved` and
  :attr:`DeltaReport.regressed` are both ``False`` for it, and a report that
  says "insufficient" is saying the only true thing.
* :data:`ComparisonOutcome.IMPROVED` / ``REGRESSED`` / ``UNCHANGED`` — the
  runs were compared and the answer is graded, against each metric's declared
  tolerance.

**Precedence, stated because it is a judgement call.** A *proven* regression
outranks a missing metric: if three metrics are unmeasurable and the fourth
moved the wrong way past its tolerance, the honest report is "regressed", not
"insufficient" — the missing measurements do not un-ring the bell that did
ring. Only when no regression is proven does insufficient data win over a pass,
because an unmeasured metric must never be the reason a comparison reads well.

A regression finding can only be *opened* from a graded regression, and every
run it cites carries a run id and a sha256 evidence digest, validated on the
pin. So "a regression finding without two cited runs" is not a rule the code
enforces politely; it is a value that cannot be constructed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING, Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.journeys import JourneyPin
from mayhem.domain.steady_state import delta_pct

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "COMPARISON_SCHEMA_VERSION",
    "EQUIVALENCE_FIELDS",
    "RELEASE_FIELD",
    "ComparisonMetric",
    "ComparisonOutcome",
    "DeltaReport",
    "MetricDelta",
    "MetricKind",
    "RegressionFinding",
    "RunPin",
    "RunReport",
    "RunSample",
    "compare",
    "equivalent_pins",
]

COMPARISON_SCHEMA_VERSION: Final[str] = "1.0"

#: The axes that must match for two runs to be comparable. Order is the order
#: :attr:`RunPin.differences_from` reports them in, so the reason a comparison
#: was refused reads in a stable, reviewable order.
EQUIVALENCE_FIELDS: Final[tuple[str, ...]] = (
    "experiment",
    "environment",
    "plan_version",
    "policy_version",
    "catalog_version",
    "agent_version",
    "runtime_version",
    "journey",
)

#: The axis a comparison is *about*. It is recorded, reported, and deliberately
#: excluded from :data:`EQUIVALENCE_FIELDS`: two runs of the same release across
#: two different run ids are a legitimate repeat, and two runs of two different
#: releases are the comparison this whole module exists for.
RELEASE_FIELD: Final[str] = "release"

#: SHA-256 hex, the same shape ``mayhem.domain.fabric.PlanDigest`` uses. A run
#: citation is an evidence citation, so the two vocabularies for "a digest" are
#: deliberately identical rather than merely similar.
EvidenceDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

INSUFFICIENT_MISSING = "no measurement of {metric} on run {run_id}"
INSUFFICIENT_SAMPLES = "{metric} on run {run_id} has {got} samples, {need} required"
INSUFFICIENT_UNMEASURED = "{metric} on run {run_id} was not measured"
INSUFFICIENT_UNMEASURABLE = "{metric} on run {run_id} carries a non-finite value"
UNDEFINED_RELATIVE = (
    "relative change is undefined for {metric}: the baseline is zero, so the move "
    "is judged against the tolerance only when it is exactly zero"
)


class ComparisonOutcome(StrEnum):
    """What a comparison of two runs concluded.

    Every member is a conclusion. There is no ``UNKNOWN`` and no ``None``: a
    comparison that could not be made says :data:`INCOMPARABLE`, and one that
    could be made but not measured says :data:`INSUFFICIENT_DATA`. An absent
    comparison is the one thing a reader must never have to guess at.
    """

    IMPROVED = "improved"
    REGRESSED = "regressed"
    UNCHANGED = "unchanged"
    INSUFFICIENT_DATA = "insufficient_data"
    INCOMPARABLE = "incomparable"


class MetricKind(StrEnum):
    """What kind of quantity a compared metric is.

    The kind fixes the default reading direction, because "did it get worse" is
    not the same question for each: more latency is worse, more errors are
    worse, a longer recovery is worse. A :data:`BUSINESS` metric has no default
    — more ``orders_per_minute`` is better, more ``queue_lag`` is worse — so a
    business metric must say which, rather than have the tool guess.
    """

    LATENCY = "latency"
    ERROR_RATE = "error_rate"
    RECOVERY = "recovery"
    BUSINESS = "business"


#: Kinds whose deterioration is an increase. A business metric is absent on
#: purpose: see :class:`MetricKind`.
_HIGHER_IS_WORSE_BY_DEFAULT: Final[frozenset[MetricKind]] = frozenset(
    {MetricKind.LATENCY, MetricKind.ERROR_RATE, MetricKind.RECOVERY}
)

_SCORED_OUTCOMES: Final[frozenset[ComparisonOutcome]] = frozenset(
    {
        ComparisonOutcome.IMPROVED,
        ComparisonOutcome.REGRESSED,
        ComparisonOutcome.UNCHANGED,
    }
)


class ComparisonMetric(BaseModel):
    """One declared metric a comparison grades, and the tolerance it allows.

    ``tolerance_pct`` is what absorbs noise — draw-to-draw variance between
    nightly runs, jitter in a probe. A move inside the tolerance is reported as
    a move and is *not* called a regression, because a tool that calls every
    wobble a regression gets muted, and a muted regression tool catches nothing.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_.-]*$")
    kind: MetricKind
    unit: str = Field(default="ms", min_length=1, max_length=32)
    tolerance_pct: float = 5.0
    required_samples: int = Field(default=1, ge=1)
    higher_is_worse: bool | None = None

    @model_validator(mode="after")
    def _business_metric_states_its_direction(self) -> ComparisonMetric:
        """A business metric must declare which direction is bad.

        The tool cannot infer it, and inferring it is the one inference that
        would silently invert a business verdict: a KPI graded with the wrong
        direction reports a collapse in throughput as an improvement, and reads
        as a pass.
        """
        if self.kind is MetricKind.BUSINESS and self.higher_is_worse is None:
            raise InvariantViolationError(
                "comparison.business_metric_undecidable",
                f"business metric {self.name!r} does not declare higher_is_worse: "
                "more orders_per_minute is better and more queue_lag is worse, and "
                "guessing here is how a throughput collapse is reported as an "
                "improvement",
            )
        return self

    @model_validator(mode="after")
    def _tolerance_is_a_real_percentage(self) -> ComparisonMetric:
        """A tolerance is a finite, non-negative percentage or it is not one.

        ``nan`` compares false against every bound and ``inf`` absorbs every
        movement, so a tolerance of either makes the whole comparison
        meaningless while still looking like a configured threshold. The bound
        is checked here rather than by a field constraint so that a negative
        one produces the same explanation as the other two.
        """
        if not isfinite(self.tolerance_pct) or self.tolerance_pct < 0.0:
            raise InvariantViolationError(
                "comparison.tolerance_not_finite",
                f"tolerance for {self.name!r} must be a finite percentage >= 0, got "
                f"{self.tolerance_pct!r}: nan and inf are arithmetic accidents, and a "
                "negative tolerance would call every move a regression",
            )
        return self

    @property
    def worse_direction(self) -> bool:
        """Resolved: does a larger value of this metric mean worse?"""
        if self.higher_is_worse is not None:
            return self.higher_is_worse
        return self.kind in _HIGHER_IS_WORSE_BY_DEFAULT

    def to_dict(self) -> dict[str, object]:
        payload = self.model_dump(mode="json")
        payload["worse_direction"] = self.worse_direction
        return payload


class RunPin(BaseModel):
    """The pinned identity of one run, and the only thing a comparison may judge.

    ``run_id`` and ``evidence_digest`` are required and the digest must be
    sha256 hex, so a run that cannot be cited cannot be pinned. That is what
    makes a two-run citation structural rather than a convention the reporter is
    trusted to honour.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = COMPARISON_SCHEMA_VERSION
    run_id: str = Field(min_length=1, max_length=128)
    experiment: str = Field(min_length=1, max_length=128)
    release: str = Field(min_length=1, max_length=64)
    environment: str = Field(min_length=1, max_length=64)
    plan_version: str = Field(min_length=1, max_length=64)
    policy_version: str = Field(min_length=1, max_length=64)
    catalog_version: str = Field(min_length=1, max_length=64)
    agent_version: str = Field(min_length=1, max_length=64)
    runtime_version: str = Field(min_length=1, max_length=64)
    evidence_digest: EvidenceDigest
    journey: JourneyPin | None = None
    seed: int | None = None

    @model_validator(mode="after")
    def _known_schema(self) -> RunPin:
        if self.schema_version != COMPARISON_SCHEMA_VERSION:
            raise InvariantViolationError(
                "comparison.unsupported_schema",
                f"unsupported run-pin schema {self.schema_version!r}: this build "
                f"reads {COMPARISON_SCHEMA_VERSION!r} only",
            )
        return self

    @property
    def label(self) -> str:
        """``experiment@release#run_id`` — what a report line should quote."""
        return f"{self.experiment}@{self.release}#{self.run_id}"

    @property
    def equivalence_key(self) -> tuple[str, ...]:
        """The pinned vector that must match, in :data:`EQUIVALENCE_FIELDS` order."""
        return (
            self.experiment,
            self.environment,
            self.plan_version,
            self.policy_version,
            self.catalog_version,
            self.agent_version,
            self.runtime_version,
            "" if self.journey is None else self.journey.label,
        )

    def differences_from(self, other: RunPin) -> tuple[str, ...]:
        """Names of the pinned axes on which this pin and ``other`` disagree.

        Named rather than merely counted so a refusal says *which* axis moved —
        "policy_version" is a question an operator can answer, "2 differences"
        is not.
        """
        return tuple(
            name
            for name, mine, theirs in zip(
                EQUIVALENCE_FIELDS, self.equivalence_key, other.equivalence_key, strict=True
            )
            if mine != theirs
        )

    def release_differences(self, other: RunPin) -> tuple[str, ...]:
        """The axis the comparison is about — reported, never a reason to refuse."""
        return () if self.release == other.release else (RELEASE_FIELD,)

    def to_dict(self) -> dict[str, object]:
        payload = self.model_dump(mode="json")
        payload["label"] = self.label
        return payload


def equivalent_pins(baseline: RunPin, candidate: RunPin) -> bool:
    """True when two runs are comparable at all.

    Same experiment, same environment, same plan/policy/catalog/agent/runtime
    versions, same journey pin. The release is excluded on purpose — see
    :data:`RELEASE_FIELD`.
    """
    return not baseline.differences_from(candidate)


class RunSample(BaseModel):
    """One run's measured value for one metric, and how much stood behind it.

    ``value is None`` and a ``samples`` count below the metric's requirement are
    both representable on purpose: a metric nobody managed to measure is
    something the domain must be able to *say*, not something it refuses to
    record and then silently score as zero.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_.-]*$")
    value: float | None = None
    samples: int = Field(default=0, ge=0)
    unit: str = Field(default="ms", min_length=1, max_length=32)

    def usable(self, required_samples: int) -> bool:
        """True when this sample can carry a graded judgement."""
        if self.value is None or self.value != self.value:
            return False
        if self.value in (float("inf"), float("-inf")):
            return False
        return self.samples >= required_samples

    def unusable_reason(self, required_samples: int, *, run_id: str) -> str:
        """Why this sample cannot carry a judgement, as a citable sentence.

        Three different absences, three different sentences: a metric the run
        never reported, a metric it reported too few times, and a metric whose
        reported value is ``nan``/``inf``. "Not measured" and "measured as
        nothing" are not the same claim, and a report that conflates them
        invites the reader to treat a broken probe as a healthy system.
        """
        if self.value is None:
            return INSUFFICIENT_UNMEASURED.format(metric=self.metric, run_id=run_id)
        if self.value != self.value or self.value in (float("inf"), float("-inf")):
            return INSUFFICIENT_UNMEASURABLE.format(metric=self.metric, run_id=run_id)
        if self.samples < required_samples:
            return INSUFFICIENT_SAMPLES.format(
                metric=self.metric, run_id=run_id, got=self.samples, need=required_samples
            )
        return INSUFFICIENT_UNMEASURED.format(metric=self.metric, run_id=run_id)

    def to_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class RunReport(BaseModel):
    """Everything one run measured that a comparison is allowed to read.

    A run report is a projection, not the evidence store: it holds the values
    and the sample counts behind them. It is pinned (:class:`RunPin`), so it
    always travels with the two identifiers a finding needs to cite.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    pin: RunPin
    metrics: tuple[RunSample, ...] = ()

    @model_validator(mode="after")
    def _metric_names_unique(self) -> RunReport:
        seen: set[str] = set()
        for sample in self.metrics:
            if sample.metric in seen:
                raise InvariantViolationError(
                    "comparison.duplicate_metric_sample",
                    f"run {self.pin.run_id} reports {sample.metric!r} twice: a metric "
                    "has one value per run, and two values make the delta arbitrary",
                )
            seen.add(sample.metric)
        return self

    def sample(self, metric: str) -> RunSample | None:
        return next((s for s in self.metrics if s.metric == metric), None)

    def to_dict(self) -> dict[str, object]:
        return {
            "pin": self.pin.to_dict(),
            "metrics": [sample.to_dict() for sample in self.metrics],
        }


@dataclass(frozen=True, slots=True)
class MetricDelta:
    """One metric's movement between two equivalent runs.

    ``worse`` and ``improved`` are tri-state on purpose: ``None`` means the
    movement could not be established (unmeasured, non-finite, under-sampled),
    which is materially different from ``False`` — "did not get worse" and
    "we could not tell" are not the same finding, and collapsing them is how a
    missing measurement turns into a pass.
    """

    metric: str
    kind: MetricKind
    unit: str
    baseline: float | None
    candidate: float | None
    delta: float | None
    delta_pct: float | None
    worse: bool | None
    improved: bool | None
    within_tolerance: bool
    tolerance_pct: float
    required_samples: int
    reason: str = ""

    @property
    def graded(self) -> bool:
        """True when a direction could be established at all."""
        return self.worse is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "metric": self.metric,
            "kind": self.kind.value,
            "unit": self.unit,
            "baseline": self.baseline,
            "candidate": self.candidate,
            "delta": self.delta,
            "delta_pct": self.delta_pct,
            "worse": self.worse,
            "improved": self.improved,
            "within_tolerance": self.within_tolerance,
            "tolerance_pct": self.tolerance_pct,
            "required_samples": self.required_samples,
            "graded": self.graded,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class DeltaReport:
    """The graded answer to "did resilience change between these two runs".

    Carries both pins — a report that does not say which two runs it compared
    is a report nobody can re-derive, and re-deriving it is the only way to
    check a regression call. Construction enforces the two rules that make the
    report trustworthy:

    * an :data:`ComparisonOutcome.INCOMPARABLE` report carries **no deltas**.
      A refused comparison is not scored, so there is nothing for it to carry;
    * every report cites **two distinct runs**, so "compared one run to itself"
      is a value that cannot be built.
    """

    outcome: ComparisonOutcome
    baseline: RunPin
    candidate: RunPin
    deltas: tuple[MetricDelta, ...] = ()
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.baseline.run_id == self.candidate.run_id:
            raise InvariantViolationError(
                "comparison.same_run",
                f"run {self.baseline.run_id!r} cannot be compared with itself: a "
                "delta between two identical runs is zero by construction and says "
                "nothing about resilience",
            )
        if self.outcome is ComparisonOutcome.INCOMPARABLE and self.deltas:
            raise InvariantViolationError(
                "comparison.scored_while_incomparable",
                "an incomparable report must carry no deltas: a comparison across "
                "different pins is refused, not scored",
            )
        if self.outcome in _SCORED_OUTCOMES and not self.deltas:
            raise InvariantViolationError(
                "comparison.graded_without_metrics",
                f"a {self.outcome.value} report must carry at least one metric "
                "delta: a graded verdict with nothing graded is a pass by absence",
            )

    # -- derived facts ------------------------------------------------------

    @property
    def scored(self) -> bool:
        """True when the two runs were actually compared and graded."""
        return self.outcome in _SCORED_OUTCOMES

    @property
    def improved(self) -> bool:
        """True only for a graded improvement — never for insufficient data."""
        return self.outcome is ComparisonOutcome.IMPROVED

    @property
    def regressed(self) -> bool:
        return self.outcome is ComparisonOutcome.REGRESSED

    @property
    def cited_runs(self) -> tuple[str, str]:
        """The two run ids this report compares. Always two, always distinct."""
        return (self.baseline.run_id, self.candidate.run_id)

    @property
    def regressions(self) -> tuple[MetricDelta, ...]:
        return tuple(delta for delta in self.deltas if delta.worse is True)

    @property
    def ungraded(self) -> tuple[MetricDelta, ...]:
        return tuple(delta for delta in self.deltas if not delta.graded)

    def delta_for(self, metric: str) -> MetricDelta | None:
        return next((d for d in self.deltas if d.metric == metric), None)

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "scored": self.scored,
            "cited_runs": list(self.cited_runs),
            "baseline": self.baseline.to_dict(),
            "candidate": self.candidate.to_dict(),
            "deltas": [delta.to_dict() for delta in self.deltas],
            "reasons": list(self.reasons),
        }


def compare(
    baseline: RunReport,
    candidate: RunReport,
    metrics: Sequence[ComparisonMetric] = (),
) -> DeltaReport:
    """Compare two runs of the same experiment and return the graded answer.

    Pure: it reads only the two reports and the declared metrics, and it never
    guesses. The decision order is the one stated in the module docstring —
    refuse, then look for a proven regression, then refuse for missing data,
    then call it improved or unchanged.
    """
    if baseline.pin.run_id == candidate.pin.run_id:
        raise InvariantViolationError(
            "comparison.same_run",
            f"run {baseline.pin.run_id!r} cannot be compared with itself",
        )
    differences = baseline.pin.differences_from(candidate.pin)
    if differences:
        return DeltaReport(
            outcome=ComparisonOutcome.INCOMPARABLE,
            baseline=baseline.pin,
            candidate=candidate.pin,
            reasons=(
                "runs are not comparable: "
                + ", ".join(differences)
                + (" differ" if len(differences) > 1 else " differs"),
            ),
        )
    declared = tuple(metrics)
    if not declared:
        return DeltaReport(
            outcome=ComparisonOutcome.INSUFFICIENT_DATA,
            baseline=baseline.pin,
            candidate=candidate.pin,
            reasons=(
                "no metrics were declared for this comparison: two equivalent runs "
                "with nothing to compare is not a pass",
            ),
        )

    deltas = tuple(_delta(metric, baseline, candidate) for metric in declared)
    ungraded = tuple(delta for delta in deltas if not delta.graded)
    if any(delta.worse for delta in deltas):
        return DeltaReport(
            outcome=ComparisonOutcome.REGRESSED,
            baseline=baseline.pin,
            candidate=candidate.pin,
            deltas=deltas,
            reasons=tuple(_regression_reason(delta) for delta in deltas if delta.worse),
        )
    if ungraded:
        return DeltaReport(
            outcome=ComparisonOutcome.INSUFFICIENT_DATA,
            baseline=baseline.pin,
            candidate=candidate.pin,
            deltas=deltas,
            reasons=tuple(delta.reason for delta in ungraded),
        )
    if any(delta.improved for delta in deltas):
        return DeltaReport(
            outcome=ComparisonOutcome.IMPROVED,
            baseline=baseline.pin,
            candidate=candidate.pin,
            deltas=deltas,
        )
    return DeltaReport(
        outcome=ComparisonOutcome.UNCHANGED,
        baseline=baseline.pin,
        candidate=candidate.pin,
        deltas=deltas,
    )


def _delta(metric: ComparisonMetric, baseline: RunReport, candidate: RunReport) -> MetricDelta:
    """Grade one declared metric across two equivalent runs."""
    name = metric.name
    base = baseline.sample(name)
    cand = candidate.sample(name)
    missing = _unusable(name, metric, base, baseline) or _unusable(name, metric, cand, candidate)
    if missing is not None:
        return MetricDelta(
            metric=name,
            kind=metric.kind,
            unit=metric.unit,
            baseline=None if base is None else base.value,
            candidate=None if cand is None else cand.value,
            delta=None,
            delta_pct=None,
            worse=None,
            improved=None,
            within_tolerance=False,
            tolerance_pct=metric.tolerance_pct,
            required_samples=metric.required_samples,
            reason=missing,
        )
    assert base is not None and base.value is not None
    assert cand is not None and cand.value is not None
    delta = cand.value - base.value
    percent = delta_pct(base.value, cand.value)
    if percent is None:
        # A zero (or non-finite) baseline leaves the relative bound undefined.
        # The only measurement "within tolerance" of a zero baseline is the
        # baseline itself, so anything else counts as a move out of tolerance.
        within = delta == 0.0
        reason = UNDEFINED_RELATIVE.format(metric=name)
    else:
        within = abs(percent) <= metric.tolerance_pct
        reason = ""
    moved_worse = delta > 0.0 if metric.worse_direction else delta < 0.0
    return MetricDelta(
        metric=name,
        kind=metric.kind,
        unit=metric.unit,
        baseline=base.value,
        candidate=cand.value,
        delta=delta,
        delta_pct=percent,
        worse=moved_worse and not within,
        improved=not moved_worse and not within,
        within_tolerance=within,
        tolerance_pct=metric.tolerance_pct,
        required_samples=metric.required_samples,
        reason=reason,
    )


def _regression_reason(delta: MetricDelta) -> str:
    """One citable sentence per regressed metric, naming the bound it passed."""
    move = (
        f"{delta.delta_pct:+.1f}%"
        if delta.delta_pct is not None
        else f"{delta.delta:+.1f}{delta.unit}"
    )
    qualifier = f" ({delta.reason})" if delta.reason else ""
    return (
        f"{delta.metric} moved {move} from {delta.baseline}{delta.unit} to "
        f"{delta.candidate}{delta.unit}, past its {delta.tolerance_pct}% tolerance"
        f"{qualifier}"
    )


def _unusable(
    name: str,
    metric: ComparisonMetric,
    sample: RunSample | None,
    report: RunReport,
) -> str | None:
    """Why this run cannot grade ``name``, or ``None`` when it can."""
    if sample is None:
        return INSUFFICIENT_MISSING.format(metric=name, run_id=report.pin.run_id)
    if not sample.usable(metric.required_samples):
        return sample.unusable_reason(metric.required_samples, run_id=report.pin.run_id)
    return None


@dataclass(frozen=True, slots=True)
class RegressionFinding:
    """A resilience regression, opened from a graded comparison of two runs.

    Only a :data:`ComparisonOutcome.REGRESSED` report can be opened into one, and
    the report necessarily cites two distinct runs with evidence digests, so a
    finding without two cited runs is unrepresentable rather than merely
    discouraged. A finding also states *why* in prose: a delta table tells a
    reader that latency moved, and only a sentence tells them whether that
    matters.
    """

    finding_id: str
    report: DeltaReport
    summary: str

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise InvariantViolationError(
                "comparison.finding_unnamed", "a regression finding must have an id"
            )
        if not self.summary.strip():
            raise InvariantViolationError(
                "comparison.finding_unexplained",
                f"finding {self.finding_id!r} has no summary: a delta table shows that "
                "something moved, and only a sentence says whether it matters",
            )
        if self.report.outcome is not ComparisonOutcome.REGRESSED:
            raise InvariantViolationError(
                "comparison.finding_without_regression",
                f"finding {self.finding_id!r} was opened from a "
                f"{self.report.outcome.value} comparison: a finding is a regression, "
                "and anything else raised as one is a false alarm the triage queue then "
                "has to disprove",
            )

    @classmethod
    def open(
        cls,
        finding_id: str,
        baseline: RunReport,
        candidate: RunReport,
        metrics: Sequence[ComparisonMetric],
        summary: str,
    ) -> RegressionFinding:
        """Compare two runs and open a finding — refusing anything but a regression."""
        return cls(
            finding_id=finding_id,
            report=compare(baseline, candidate, metrics),
            summary=summary,
        )

    @property
    def baseline_run(self) -> str:
        return self.report.baseline.run_id

    @property
    def candidate_run(self) -> str:
        return self.report.candidate.run_id

    @property
    def cited_runs(self) -> tuple[str, str]:
        return self.report.cited_runs

    @property
    def regressed_metrics(self) -> tuple[str, ...]:
        return tuple(delta.metric for delta in self.report.regressions)

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "summary": self.summary,
            "cited_runs": list(self.cited_runs),
            "regressed_metrics": list(self.regressed_metrics),
            "report": self.report.to_dict(),
        }
