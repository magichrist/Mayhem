"""Resource budgets, estimate-vs-actual comparison, and benchmark descriptors.

Plan 23 Phase 1. This module is the *vocabulary* for gap 68: cost and
consumption get governed the way damage already is, rather than merely
measured after the fact.

**What this is not.** :mod:`mayhem.domain.quota` already owns *damage*
accounting — damage-seconds, weighted by risk and reversibility, charged per
fault step against a per-target ledger. Those numbers stay in ``quota.py``,
they stay in seconds, and nothing here reads or writes them. A run that
impairs a target for 300 seconds and a run that burns 300 CPU-seconds are
*different* facts with different units, different scopes (damage is per target,
compute is per team or per experiment), and different consequences, and a
single combined "budget" would let one dimension's slack quietly pay for
another's overspend. So the two ledgers are separate types that never merge,
and :class:`ResourceBudget` deliberately carries no ``_s`` damage field.

What this module does own:

- :class:`ResourceDimension` — the eight dimensions the plan names (CPU,
  memory, network, storage, cloud spend, API calls, target count, concurrent
  experiments), each with the unit its numbers are counted in.
- :class:`ResourceBudget` — a limit over one dimension, within one window,
  charged against one scope.
- :class:`BudgetConsumption` — a reading measured *against* that limit, with
  headroom, utilisation, and the refusal text naming the breaching dimension.
- :func:`compare_estimate` — a pre-execution estimate and the continuous
  actual, compared as two comparable records rather than merged into one.
- :class:`BenchmarkSpec` — enough of a benchmark's workload to reproduce the
  run exactly, plus a publish path that refuses a spec whose declared measured
  outputs do not arrive.

**No clock, anywhere.** Every function that needs to know what time it is
takes ``now`` (or an explicit ``anchor``) as an argument. There is no
``utc_now()`` fallback in any evaluation path, so a decision is a function of
(inputs, now) alone and a replay from evidence cannot drift. That is the same
discipline :func:`mayhem.domain.policy.evaluate_bundle` follows, and the same
reason Phase 4 can promise a replay reproduces a decision.

**An unmeasured claim is unrepresentable.** Scale claims in plan 23 ship with
measured numbers "or stay unclaimed". :class:`ScaleClaim` may be *authored*
unmeasured (someone is allowed to say "we intend to test 10,000 targets"), but
:func:`ScaleClaim.render` refuses to produce the only type a dashboard
consumes, and :class:`ScaleClaimView` itself rejects an empty measurement set.
There is no code path that yields a renderable claim without a
:class:`PublishedBenchmark` behind it.

Everything here is pure: no IO, no store, no runtime, no clock. This is a
domain module and is held to the layer's import contract.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from math import floor, isfinite
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "DECLARED_CONCURRENCY_TARGETS",
    "DECLARED_SCALE_TARGETS",
    "RESOURCE_PRECISION",
    "RULE_CLAIM_SCALE_MISMATCH",
    "RULE_DIGEST_MISMATCH",
    "RULE_EMPTY_MEASUREMENT",
    "RULE_ESTIMATE_EXCEEDED",
    "RULE_FRACTIONAL_COUNT",
    "RULE_LIMIT_EXCEEDED",
    "RULE_MEASURED_OUTPUTS_REQUIRED",
    "RULE_NEGATIVE_LIMIT",
    "RULE_NEGATIVE_MEASUREMENT",
    "RULE_NON_FINITE",
    "RULE_NON_MONOTONIC_CONSUMPTION",
    "RULE_NON_POSITIVE_WINDOW",
    "RULE_OUTPUT_MISSING",
    "RULE_OUTPUT_UNDECLARED",
    "RULE_SCALE_UNMEASURED",
    "RULE_SHAPE_CONCURRENCY",
    "RULE_SHAPE_EXCEEDS_SCALE",
    "RULE_SUBJECT_MISMATCH",
    "RULE_UNMEASURED_ESTIMATE_BASIS",
    "RULE_UNSUPPORTED_SCALE",
    "RULE_WINDOW_ORDER",
    "BenchmarkMetric",
    "BenchmarkSpec",
    "BudgetComparison",
    "BudgetConsumption",
    "BudgetWindow",
    "ConsumptionSample",
    "Measurement",
    "PublishedBenchmark",
    "RenderedMeasurement",
    "ResourceBudget",
    "ResourceDimension",
    "ResourceEstimate",
    "ResourceScope",
    "ResourceSeries",
    "ScaleClaim",
    "ScaleClaimView",
    "TargetScale",
    "WorkloadItem",
    "WorkloadShape",
    "budget_window_for",
    "compare_estimate",
    "is_counted_dimension",
    "unit_for",
]

# Rounding applied to every accumulated resource figure so a replay cannot drift
# on the last binary digit of a repeated addition. Six places is far below any
# budget a human authors and far above the noise floor of float arithmetic.
RESOURCE_PRECISION: int = 6

# -- rule ids (stable; an evidence record names these) --------------------------
#: Resource-budget refusals over cpu-seconds, request counts, bytes, and the
#: like. The hierarchical *damage* budget is a different ledger with its own
#: namespace (``mayhem.domain.policy.BudgetNode``); where the two would collide
#: the damage side is the qualified one — see
#: ``budget.damage_negative_limit`` in that module, which is why this id keeps
#: the bare name.
RULE_NEGATIVE_LIMIT = "budget.negative_limit"
RULE_NON_POSITIVE_WINDOW = "budget.non_positive_window"
RULE_NEGATIVE_MEASUREMENT = "budget.negative_measurement"
RULE_NON_FINITE = "budget.non_finite"
RULE_FRACTIONAL_COUNT = "budget.fractional_count"
RULE_NON_MONOTONIC_CONSUMPTION = "budget.consumption_not_monotonic"
RULE_SUBJECT_MISMATCH = "budget.subject_mismatch"
RULE_WINDOW_ORDER = "budget.window_order"
RULE_LIMIT_EXCEEDED = "budget.limit_exceeded"
RULE_ESTIMATE_EXCEEDED = "budget.estimate_exceeded"
RULE_UNMEASURED_ESTIMATE_BASIS = "budget.estimate_basis_required"

RULE_SHAPE_CONCURRENCY = "benchmark.shape_concurrency"
RULE_SHAPE_EXCEEDS_SCALE = "benchmark.shape_exceeds_scale"
RULE_EMPTY_MEASUREMENT = "benchmark.empty_measurement"
RULE_MEASURED_OUTPUTS_REQUIRED = "benchmark.no_measured_outputs"
RULE_OUTPUT_MISSING = "benchmark.output_missing"
RULE_OUTPUT_UNDECLARED = "benchmark.output_undeclared"
RULE_DIGEST_MISMATCH = "benchmark.spec_digest_mismatch"

RULE_UNSUPPORTED_SCALE = "scale.unsupported_target_count"
RULE_SCALE_UNMEASURED = "scale.unmeasured_claim"
RULE_CLAIM_SCALE_MISMATCH = "scale.claim_scale_mismatch"


# -- dimensions ----------------------------------------------------------------


class ResourceDimension(StrEnum):
    """The dimensions gap 68 asks to govern, one member per named cost.

    A *dimension* is not a *policy dimension* (see
    :class:`mayhem.domain.policy.PolicyDimension`) and not a damage budget.
    These eight are the things a run consumes that are not the target's time:
    compute, bytes, and count. Adding a member here is a claim that the system
    meters that dimension, so a dimension nobody measures should not exist yet.
    """

    CPU = "cpu"
    MEMORY = "memory"
    NETWORK = "network"
    STORAGE = "storage"
    CLOUD_SPEND = "cloud_spend"
    API_CALLS = "api_calls"
    TARGET_COUNT = "target_count"
    CONCURRENT_EXPERIMENTS = "concurrent_experiments"


_UNIT_BY_DIMENSION: dict[ResourceDimension, str] = {
    ResourceDimension.CPU: "core_seconds",
    ResourceDimension.MEMORY: "mebibyte_seconds",
    ResourceDimension.NETWORK: "egress_bytes",
    ResourceDimension.STORAGE: "bytes",
    ResourceDimension.CLOUD_SPEND: "currency_micros",
    ResourceDimension.API_CALLS: "calls",
    ResourceDimension.TARGET_COUNT: "targets",
    ResourceDimension.CONCURRENT_EXPERIMENTS: "runs",
}
"""The unit each dimension's numbers are counted in.

Units differ on purpose. ``core_seconds`` is a *time-integrated* quantity and
must never be compared against a raw ``targets`` count, so every comparison in
this module is between two readings of the *same* dimension and every refusal
text renders the unit it is talking about.
"""

_COUNTED_DIMENSIONS: frozenset[ResourceDimension] = frozenset(
    {
        ResourceDimension.API_CALLS,
        ResourceDimension.TARGET_COUNT,
        ResourceDimension.CONCURRENT_EXPERIMENTS,
    }
)
"""Dimensions whose quantity is indivisible.

A limit of 10.5 API calls is a unit error, not a tighter budget, so counted
dimensions reject fractional limits and readings outright rather than rounding
them into a number the author never wrote.
"""


def unit_for(dimension: ResourceDimension) -> str:
    """The unit ``dimension`` is counted in."""
    return _UNIT_BY_DIMENSION[dimension]


def is_counted_dimension(dimension: ResourceDimension) -> bool:
    """True when ``dimension`` counts things and cannot hold a fraction."""
    return dimension in _COUNTED_DIMENSIONS


# -- scopes --------------------------------------------------------------------


class ResourceScope(StrEnum):
    """What a resource budget is spent *against*.

    Deliberately not :class:`mayhem.domain.policy.BudgetScope`: that one is a
    five-level damage tree (team → environment → service → experiment → fault)
    of accumulated *damage seconds*, walked with ``BudgetNode``. This is a
    four-level containment relation over *consumption*, where the levels below
    environment (a single experiment, a single run) are the ones that actually
    own a CPU or API-call limit. Reusing the damage hierarchy would put
    ``FAULT`` in a CPU budget's vocabulary, which is a category error.
    """

    ORGANISATION = "organisation"
    ENVIRONMENT = "environment"
    EXPERIMENT = "experiment"
    RUN = "run"


_RESOURCE_SCOPE_ORDER: dict[ResourceScope, int] = {
    ResourceScope.ORGANISATION: 0,
    ResourceScope.ENVIRONMENT: 1,
    ResourceScope.EXPERIMENT: 2,
    ResourceScope.RUN: 3,
}
"""Width of the containment relation, so a scope knows what it can contain."""

_SCOPE_CONTAINS: dict[ResourceScope, frozenset[ResourceScope]] = {
    ResourceScope.ORGANISATION: frozenset(ResourceScope),
    ResourceScope.ENVIRONMENT: frozenset(
        {ResourceScope.ENVIRONMENT, ResourceScope.EXPERIMENT, ResourceScope.RUN}
    ),
    ResourceScope.EXPERIMENT: frozenset({ResourceScope.EXPERIMENT, ResourceScope.RUN}),
    ResourceScope.RUN: frozenset({ResourceScope.RUN}),
}
"""Which scopes a budget at one scope may govern. An organisation-wide CPU
limit bounds an experiment's CPU limit; a run limit bounds nothing."""


def scope_contains(outer: ResourceScope, inner: ResourceScope) -> bool:
    """True when a budget at ``outer`` governs consumption at ``inner``."""
    return inner in _SCOPE_CONTAINS[outer]


def _round(value: float) -> float:
    """Round to the module's replay-stable precision."""
    return round(value, RESOURCE_PRECISION)


def _require_finite(value: float, *, subject: str) -> float:
    if not isfinite(value):
        msg = f"{subject} must be a finite number, got {value!r}"
        raise InvariantViolationError(RULE_NON_FINITE, msg)
    return float(value)


def _require_utc(moment: datetime, *, subject: str) -> datetime:
    """Reject a naive datetime and normalise the rest to UTC.

    Window arithmetic adds :class:`~datetime.timedelta` to whatever it is given,
    which is wall-clock arithmetic; doing it in UTC keeps the bucketing correct
    across a DST transition instead of drifting by an hour twice a year.
    """
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        msg = f"{subject} must be timezone-aware, got naive {moment!r}"
        raise InvariantViolationError(RULE_WINDOW_ORDER, msg)
    return moment.astimezone(UTC)


def _require_count_value(value: float, *, dimension: ResourceDimension, subject: str) -> float:
    if is_counted_dimension(dimension) and not value.is_integer():
        msg = (
            f"{subject} for {dimension.value} counts whole things and cannot be "
            f"fractional, got {value!r}"
        )
        raise InvariantViolationError(RULE_FRACTIONAL_COUNT, msg)
    return value


# -- windows -------------------------------------------------------------------


class BudgetWindow(BaseModel):
    """A half-open consumption window ``[start, end)``.

    Half-open is the whole point. ``[start, end)`` partitions the timeline with
    no gap and no overlap, so a reading taken exactly on a boundary belongs to
    exactly one window and a re-read of the same boundary cannot double-count
    it. A closed interval would do neither, and a boundary error in a budget
    ledger is a budget that is silently wrong by one window.
    """

    model_config = ConfigDict(frozen=True)

    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _check_order(self) -> BudgetWindow:
        start = _require_utc(self.start, subject="budget window start")
        end = _require_utc(self.end, subject="budget window end")
        if end <= start:
            msg = (
                f"budget window ends ({end.isoformat()}) at or before it starts "
                f"({start.isoformat()})"
            )
            raise InvariantViolationError(RULE_WINDOW_ORDER, msg)
        return self

    @property
    def seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    def contains(self, at: datetime) -> bool:
        """True when ``at`` falls in this window; the end is excluded."""
        moment = _require_utc(at, subject="window membership probe")
        return self.start <= moment < self.end

    def describe(self) -> str:
        return f"[{self.start.isoformat()}, {self.end.isoformat()})"


def budget_window_for(*, at: datetime, window_s: float, anchor: datetime) -> BudgetWindow:
    """The window of length ``window_s`` containing ``at``, on a fixed grid.

    The grid is anchored on ``anchor`` rather than on the epoch so a caller
    controls where the windows fall: an anchor of "midnight UTC" gives calendar
    windows, an anchor of "the moment the run started" gives a run-relative
    budget. Either way the boundaries are a pure function of (at, window_s,
    anchor) — two processes asked for the same window get the same one.
    """
    _require_finite(window_s, subject="budget window length")
    if window_s <= 0.0:
        msg = f"budget window length must be positive, got {window_s!r}"
        raise InvariantViolationError(RULE_NON_POSITIVE_WINDOW, msg)
    moment = _require_utc(at, subject="window membership probe")
    origin = _require_utc(anchor, subject="budget window anchor")
    index = floor((moment - origin).total_seconds() / window_s)
    start = origin + timedelta(seconds=index * window_s)
    return BudgetWindow(start=start, end=start + timedelta(seconds=window_s))


# -- budgets -------------------------------------------------------------------


class ResourceBudget(BaseModel):
    """An authored limit on one dimension, over one window, at one scope.

    Frozen: :meth:`measure` and the series in this module read a budget, never
    write one. Changing an in-flight budget therefore produces a *different*
    budget rather than retroactively forgiving consumption, which is the same
    probe-then-commit shape ``DamageQuota.unrestricted()`` and
    ``BudgetNode.post_charge`` use.
    """

    model_config = ConfigDict(frozen=True)

    dimension: ResourceDimension
    scope: ResourceScope
    scope_key: str = Field(min_length=1)
    limit: float
    window_s: float
    description: str = ""

    @field_validator("scope_key")
    @classmethod
    def _check_scope_key(cls, value: str) -> str:
        if not value.strip():
            msg = f"resource budget scope key is blank: {value!r}"
            raise InvariantViolationError(RULE_SUBJECT_MISMATCH, msg)
        return value

    @field_validator("limit", "window_s")
    @classmethod
    def _check_finite(cls, value: float) -> float:
        return _require_finite(value, subject="resource budget limit or window")

    @model_validator(mode="after")
    def _check_budget(self) -> ResourceBudget:
        if self.limit <= 0.0:
            msg = (
                f"{self.dimension.value} budget for {self.scope.value}/"
                f"{self.scope_key!r} has a non-positive limit {self.limit!r}; "
                "a budget nobody can spend is a typo, not a setting"
            )
            raise InvariantViolationError(RULE_NEGATIVE_LIMIT, msg)
        if self.window_s <= 0.0:
            msg = (
                f"{self.dimension.value} budget for {self.scope.value}/"
                f"{self.scope_key!r} has a non-positive window {self.window_s!r} seconds"
            )
            raise InvariantViolationError(RULE_NON_POSITIVE_WINDOW, msg)
        _require_count_value(self.limit, dimension=self.dimension, subject="budget limit")
        return self

    # -- reads ----------------------------------------------------------------
    @property
    def unit(self) -> str:
        return _UNIT_BY_DIMENSION[self.dimension]

    @property
    def counted(self) -> bool:
        return is_counted_dimension(self.dimension)

    @property
    def subject(self) -> tuple[ResourceDimension, ResourceScope, str]:
        """The (dimension, scope, key) triple every record must agree on."""
        return (self.dimension, self.scope, self.scope_key)

    def describes(self, other: ResourceBudget) -> bool:
        """True when ``other`` is charged against the same subject as this one."""
        return self.subject == other.subject

    def governs(self, scope: ResourceScope) -> bool:
        """True when a budget at this scope governs consumption at ``scope``."""
        return scope_contains(self.scope, scope)

    def window_ending_at(self, now: datetime) -> BudgetWindow:
        """The window of this budget's length ending at ``now``."""
        moment = _require_utc(now, subject="budget window anchor")
        return BudgetWindow(start=moment - timedelta(seconds=self.window_s), end=moment)

    def window_for(self, at: datetime, *, anchor: datetime) -> BudgetWindow:
        """The window of this budget's length containing ``at``, on the grid."""
        return budget_window_for(at=at, window_s=self.window_s, anchor=anchor)

    # -- measurement ----------------------------------------------------------
    def measure(self, measured: float, window: BudgetWindow | None = None) -> BudgetConsumption:
        """Judge a cumulative reading against this budget.

        The reading is recorded first and judged second, so the record is a fact
        about what the run consumed, not a fact about what it was allowed to
        consume. A run that already went over still gets its true number back.
        """
        _require_finite(measured, subject=f"{self.dimension.value} measurement")
        if measured < 0.0:
            msg = (
                f"{self.dimension.value} measurement for {self.scope.value}/"
                f"{self.scope_key!r} is negative ({measured!r}); consumption does not un-happen"
            )
            raise InvariantViolationError(RULE_NEGATIVE_MEASUREMENT, msg)
        _require_count_value(measured, dimension=self.dimension, subject="measurement")
        return BudgetConsumption(
            dimension=self.dimension,
            scope=self.scope,
            scope_key=self.scope_key,
            window=window,
            measured=_round(measured),
            limit=self.limit,
        )

    def describe(self) -> str:
        window = f"{_format_window(self.window_s)}"
        return (
            f"{self.dimension.value} {self.unit} at {self.scope.value}/{self.scope_key} "
            f"<= {self.limit:g} per {window}"
        )


def _format_window(seconds: float) -> str:
    if seconds % 3600.0 == 0.0 and seconds >= 3600.0:
        return f"{seconds / 3600.0:g}h"
    if seconds % 60.0 == 0.0 and seconds >= 60.0:
        return f"{seconds / 60.0:g}m"
    return f"{seconds:g}s"


class BudgetConsumption(BaseModel):
    """A cumulative reading of one dimension, measured *against* a limit.

    Headroom and utilisation are derived from the numbers rather than stored,
    so they cannot disagree with the reading they describe. The refusal text
    (:attr:`rule_id`, :attr:`reason`, :attr:`remediation`) is derived too, and
    names the breaching dimension — plan 23 Phase 4 requires a refusal to say
    *which* budget broke, not merely that one did.
    """

    model_config = ConfigDict(frozen=True)

    dimension: ResourceDimension
    scope: ResourceScope
    scope_key: str
    measured: float
    limit: float
    window: BudgetWindow | None = None

    # -- arithmetic -----------------------------------------------------------
    @property
    def unit(self) -> str:
        return _UNIT_BY_DIMENSION[self.dimension]

    @property
    def headroom(self) -> float:
        """Budget left after the reading; negative once the limit is passed."""
        return _round(self.limit - self.measured)

    @property
    def utilisation(self) -> float:
        """Reading as a fraction of the limit. 0.0 when the limit is infinite."""
        if not isfinite(self.limit) or self.limit == 0.0:
            return 0.0
        return _round(self.measured / self.limit)

    @property
    def overage(self) -> float:
        """How far past the limit the reading went; 0.0 while within budget."""
        return _round(max(0.0, self.measured - self.limit))

    @property
    def exhausted(self) -> bool:
        """Exactly at the limit is spent, not over: a budget may be used up."""
        return self.measured >= self.limit

    @property
    def exceeded(self) -> bool:
        return self.measured > self.limit

    @property
    def within_budget(self) -> bool:
        return not self.exceeded

    # -- refusal --------------------------------------------------------------
    @property
    def rule_id(self) -> str:
        return RULE_LIMIT_EXCEEDED if self.exceeded else ""

    @property
    def reason(self) -> str:
        if not self.exceeded:
            return ""
        window = f" in window {self.window.describe()}" if self.window is not None else ""
        return (
            f"resource budget: {self.dimension.value} consumption "
            f"{self.measured:g} {self.unit} on {self.scope.value}/{self.scope_key}"
            f"{window} exceeds the limit {self.limit:g} by {self.overage:g} "
            f"[{RULE_LIMIT_EXCEEDED}]"
        )

    @property
    def remediation(self) -> str:
        if not self.exceeded:
            return ""
        period = ""
        if self.window is not None:
            period = f" per {_format_window(self.window.seconds)}"
        return (
            f"reduce {self.dimension.value} consumption, narrow the run's scope, or raise "
            f"the {self.dimension.value} budget for {self.scope.value}/{self.scope_key} "
            f"(currently {self.limit:g} {self.unit}{period})"
        )

    def inputs(self) -> dict[str, object]:
        """The machine-readable half of a refusal, for an evidence record."""
        return {
            "dimension": self.dimension.value,
            "unit": self.unit,
            "scope": self.scope.value,
            "scope_key": self.scope_key,
            "measured": self.measured,
            "limit": self.limit,
            "headroom": self.headroom,
            "utilisation": self.utilisation,
            "window_start": self.window.start.isoformat() if self.window is not None else None,
            "window_end": self.window.end.isoformat() if self.window is not None else None,
        }

    def describe(self) -> str:
        window = self.window.describe() if self.window is not None else "no window"
        return (
            f"{self.dimension.value} {self.measured:g}/{self.limit:g} {self.unit} "
            f"[{self.scope.value}/{self.scope_key}, {window}] "
            f"headroom {self.headroom:g}"
        )


# -- metering ------------------------------------------------------------------


class ConsumptionSample(BaseModel):
    """One cumulative meter reading: "by this moment, this dimension stands at N".

    Cumulative, not incremental, on purpose. The invariant that makes the
    series auditable is then a plain non-decreasing check — a reading that goes
    *down* means the meter was reset, the series was spliced, or two processes
    are posting into one ledger, and each of those is a bug worth refusing
    rather than a reading to average away.
    """

    model_config = ConfigDict(frozen=True)

    dimension: ResourceDimension
    measured: float
    at: datetime
    note: str = ""

    @field_validator("measured")
    @classmethod
    def _check_measured(cls, value: float) -> float:
        return _require_finite(value, subject="consumption sample reading")

    @model_validator(mode="after")
    def _check_sample(self) -> ConsumptionSample:
        _require_utc(self.at, subject="consumption sample timestamp")
        if self.measured < 0.0:
            msg = f"{self.dimension.value} sample reading is negative ({self.measured!r})"
            raise InvariantViolationError(RULE_NEGATIVE_MEASUREMENT, msg)
        _require_count_value(self.measured, dimension=self.dimension, subject="sample reading")
        return self

    def describe(self) -> str:
        return f"{self.dimension.value}={self.measured:g} at {self.at.isoformat()}"


class ResourceSeries(BaseModel):
    """An immutable run of cumulative readings for one budget's subject.

    :meth:`post` returns a *new* series, so a candidate reading can be probed
    against a live ledger without spending it. The series holds the budget it
    meters (rather than a limit of its own) precisely so a reading can never be
    judged against a different limit than the one it was collected under.
    """

    model_config = ConfigDict(frozen=True)

    budget: ResourceBudget
    samples: tuple[ConsumptionSample, ...] = ()

    @classmethod
    def for_budget(cls, budget: ResourceBudget) -> ResourceSeries:
        """An empty series for ``budget``."""
        return cls(budget=budget)

    # -- reads ----------------------------------------------------------------
    @property
    def dimension(self) -> ResourceDimension:
        return self.budget.dimension

    @property
    def scope(self) -> ResourceScope:
        return self.budget.scope

    @property
    def scope_key(self) -> str:
        return self.budget.scope_key

    @property
    def latest(self) -> ConsumptionSample | None:
        return self.samples[-1] if self.samples else None

    @property
    def cumulative(self) -> float:
        """The most recent reading, or 0.0 for an empty series."""
        last = self.latest
        return 0.0 if last is None else last.measured

    @property
    def length(self) -> int:
        return len(self.samples)

    # -- writes ---------------------------------------------------------------
    def post(self, sample: ConsumptionSample) -> ResourceSeries:
        """Append a cumulative reading, returning the extended series.

        Raises:
            InvariantViolationError: If the reading is for another dimension or
                is lower than the last one recorded (a non-monotonic series).
        """
        if sample.dimension is not self.budget.dimension:
            msg = (
                f"cannot post a {sample.dimension.value} reading into a "
                f"{self.budget.dimension.value} series"
            )
            raise InvariantViolationError(RULE_SUBJECT_MISMATCH, msg)
        previous = self.cumulative
        if sample.measured < previous:
            msg = (
                f"{self.budget.dimension.value} consumption for "
                f"{self.budget.scope.value}/{self.budget.scope_key} went down: "
                f"{sample.measured:g} after {previous:g}; cumulative readings are "
                "monotonic"
            )
            raise InvariantViolationError(RULE_NON_MONOTONIC_CONSUMPTION, msg)
        return self.model_copy(update={"samples": (*self.samples, sample)})

    def posted(self, samples: Iterable[ConsumptionSample]) -> ResourceSeries:
        """Append several readings in order, returning the extended series."""
        series = self
        for sample in samples:
            series = series.post(sample)
        return series

    # -- readings -------------------------------------------------------------
    def samples_in(self, window: BudgetWindow) -> tuple[ConsumptionSample, ...]:
        """The readings taken inside ``window``."""
        return tuple(sample for sample in self.samples if window.contains(sample.at))

    def measured_at(self, window: BudgetWindow) -> float:
        """The last reading taken strictly before ``window.end``.

        Carry-forward, because the reading is cumulative: the meter last said
        this much, and nothing observed before the window closed contradicts it.
        A reading taken exactly at ``window.end`` is excluded — that reading
        belongs to the next window by the half-open rule, and counting it in
        both would double-charge the boundary.
        """
        readings = [sample.measured for sample in self.samples if sample.at < window.end]
        return readings[-1] if readings else 0.0

    def consumption(self, window: BudgetWindow) -> BudgetConsumption:
        """This series judged over ``window`` against its budget."""
        return self.budget.measure(self.measured_at(window), window)


# -- estimate vs actual --------------------------------------------------------


class ResourceEstimate(BaseModel):
    """What a run is expected to consume, before it runs.

    ``basis`` is mandatory. An estimate with no stated basis — no shape, no
    prior measurement, no plan — cannot be compared against an actual in any
    meaningful way, and refusing to author one is cheaper than discovering
    afterwards that the "estimate" was a guess the comparison treated as data.
    """

    model_config = ConfigDict(frozen=True)

    dimension: ResourceDimension
    scope: ResourceScope
    scope_key: str
    expected: float
    basis: str = Field(min_length=1)

    @field_validator("expected")
    @classmethod
    def _check_expected(cls, value: float) -> float:
        return _require_finite(value, subject="resource estimate")

    @model_validator(mode="after")
    def _check_estimate(self) -> ResourceEstimate:
        if self.expected < 0.0:
            msg = f"resource estimate for {self.dimension.value} is negative ({self.expected!r})"
            raise InvariantViolationError(RULE_NEGATIVE_MEASUREMENT, msg)
        if not self.basis.strip():
            msg = (
                f"resource estimate for {self.dimension.value} on "
                f"{self.scope.value}/{self.scope_key} names no basis"
            )
            raise InvariantViolationError(RULE_UNMEASURED_ESTIMATE_BASIS, msg)
        _require_count_value(self.expected, dimension=self.dimension, subject="resource estimate")
        return self

    @property
    def unit(self) -> str:
        return _UNIT_BY_DIMENSION[self.dimension]

    @property
    def subject(self) -> tuple[ResourceDimension, ResourceScope, str]:
        return (self.dimension, self.scope, self.scope_key)

    def describe(self) -> str:
        return (
            f"{self.dimension.value} expected {self.expected:g} {self.unit} at "
            f"{self.scope.value}/{self.scope_key} (basis: {self.basis})"
        )


class BudgetComparison(BaseModel):
    """A pre-execution estimate and a continuous actual, side by side.

    Kept as two numbers and a delta rather than collapsed into a single
    "efficiency" figure: the estimate is a prediction and the actual is a
    measurement, and a comparison that loses the distinction cannot answer the
    question it exists for ("was the run more expensive than we said it would
    be?"). Whether a given delta is *acceptable* is a policy question that
    belongs to a tolerance, not a fact about the arithmetic, so this record
    reports and does not judge.
    """

    model_config = ConfigDict(frozen=True)

    dimension: ResourceDimension
    scope: ResourceScope
    scope_key: str
    estimate: float
    actual: float
    limit: float
    basis: str = ""
    window: BudgetWindow | None = None

    @property
    def unit(self) -> str:
        return _UNIT_BY_DIMENSION[self.dimension]

    @property
    def delta(self) -> float:
        """Actual minus estimate. Positive means the run cost more than predicted."""
        return _round(self.actual - self.estimate)

    @property
    def ratio(self) -> float | None:
        """Actual as a multiple of the estimate, or ``None`` at a zero estimate."""
        if self.estimate == 0.0:
            return None
        return _round(self.actual / self.estimate)

    @property
    def over_estimate(self) -> bool:
        return self.actual > self.estimate

    @property
    def headroom(self) -> float:
        return _round(self.limit - self.actual)

    @property
    def within_limit(self) -> bool:
        return self.actual <= self.limit

    @property
    def rule_id(self) -> str:
        return RULE_ESTIMATE_EXCEEDED if self.over_estimate else ""

    @property
    def reason(self) -> str:
        if not self.over_estimate:
            return ""
        detail = ""
        if not self.within_limit:
            detail = f"; it also exceeds the budget limit {self.limit:g}"
        ratio = self.ratio
        rendered = f" ({ratio:g}x the estimate)" if ratio is not None else ""
        return (
            f"resource estimate exceeded: {self.dimension.value} consumed "
            f"{self.actual:g} {self.unit} against an estimate of {self.estimate:g}"
            f"{rendered} on {self.scope.value}/{self.scope_key}{detail} "
            f"[{RULE_ESTIMATE_EXCEEDED}]"
        )

    def inputs(self) -> dict[str, object]:
        return {
            "dimension": self.dimension.value,
            "unit": self.unit,
            "scope": self.scope.value,
            "scope_key": self.scope_key,
            "estimate": self.estimate,
            "actual": self.actual,
            "delta": self.delta,
            "ratio": self.ratio,
            "limit": self.limit,
            "within_limit": self.within_limit,
            "window_start": self.window.start.isoformat() if self.window is not None else None,
            "window_end": self.window.end.isoformat() if self.window is not None else None,
        }

    def describe(self) -> str:
        return (
            f"{self.dimension.value} estimated {self.estimate:g} {self.unit}, "
            f"actual {self.actual:g} (delta {self.delta:+g})"
        )


def compare_estimate(
    budget: ResourceBudget,
    estimate: ResourceEstimate,
    consumption: BudgetConsumption,
) -> BudgetComparison:
    """Compare a pre-execution estimate with the continuous actual for it.

    All three records must describe the same (dimension, scope, key), and the
    consumption must have been measured against this budget's limit. A
    mismatch raises rather than comparing apples to oranges — a CPU actual
    against an API-call estimate would produce a confident nonsense ratio.

    Pure: nothing here reads a clock, and ``consumption`` carries the window it
    was measured over, so the comparison is reproducible from its inputs.
    """
    if estimate.subject != budget.subject:
        msg = (
            f"resource estimate is for {estimate.dimension.value}/"
            f"{estimate.scope.value}/{estimate.scope_key} but the budget is "
            f"{budget.dimension.value}/{budget.scope.value}/{budget.scope_key}"
        )
        raise InvariantViolationError(RULE_SUBJECT_MISMATCH, msg)
    if (
        consumption.dimension,
        consumption.scope,
        consumption.scope_key,
        consumption.limit,
    ) != (*budget.subject, budget.limit):
        msg = (
            f"consumption record {consumption.dimension.value}/"
            f"{consumption.scope.value}/{consumption.scope_key} at limit "
            f"{consumption.limit:g} does not belong to budget {budget.describe()}"
        )
        raise InvariantViolationError(RULE_SUBJECT_MISMATCH, msg)
    return BudgetComparison(
        dimension=budget.dimension,
        scope=budget.scope,
        scope_key=budget.scope_key,
        estimate=estimate.expected,
        actual=consumption.measured,
        limit=budget.limit,
        basis=estimate.basis,
        window=consumption.window,
    )


# -- benchmarks ----------------------------------------------------------------

#: The scale ranges plan 23 declares as claimable. Only these are representable:
#: a number outside this set is not a range anyone planned to characterize, and
#: inventing one on a dashboard is how a projection turns into a claim.
DECLARED_SCALE_TARGETS: frozenset[int] = frozenset({10, 100, 1_000, 10_000, 100_000})

#: Concurrent-run ranges the plan names, "where architecture permits". Recorded
#: for reference and reporting; not enforced on a spec, because whether a range
#: is permitted is a property of the runtime the spec will run against.
DECLARED_CONCURRENCY_TARGETS: frozenset[int] = frozenset({10, 100, 1_000})


class BenchmarkMetric(StrEnum):
    """The benchmarks plan 23 names, one member per line of its list."""

    PLAN_COMPILATION_LATENCY = "plan_compilation_latency"
    TARGET_DISCOVERY_LATENCY = "target_discovery_latency"
    POLICY_EVALUATION_LATENCY = "policy_evaluation_latency"
    CONTROLLER_THROUGHPUT = "controller_throughput"
    AGENT_COMMAND_LATENCY = "agent_command_latency"
    EVIDENCE_THROUGHPUT = "evidence_throughput"
    DATABASE_GROWTH = "database_growth"
    PROBE_OVERHEAD = "probe_overhead"
    NETWORK_OVERHEAD = "network_overhead"


class TargetScale(BaseModel):
    """A claimable scale point: how many targets, how many runs at once.

    ``targets`` must be one of :data:`DECLARED_SCALE_TARGETS`. That constraint
    is the domain-level half of "each range ships with its measured numbers or
    stays unclaimed": a scale outside the declared ranges has no published
    methodology behind it and no comparison to be made against, so it is not a
    scale this system can speak about.

    ``concurrent_runs`` is bounded only by ``targets`` (you cannot run ten
    experiments over three targets) and deliberately *not* range-checked: plan
    23 qualifies the concurrency ranges with "where architecture permits".
    """

    model_config = ConfigDict(frozen=True)

    targets: int = Field(ge=1)
    concurrent_runs: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _check_scale(self) -> TargetScale:
        if self.targets not in DECLARED_SCALE_TARGETS:
            msg = (
                f"target scale {self.targets} is not one of the declared ranges "
                f"{sorted(DECLARED_SCALE_TARGETS)}; an unmeasured scale claim is "
                "unrepresentable"
            )
            raise InvariantViolationError(RULE_UNSUPPORTED_SCALE, msg)
        if self.concurrent_runs > self.targets:
            msg = (
                f"target scale {self.targets} cannot run {self.concurrent_runs} "
                "concurrent experiments"
            )
            raise InvariantViolationError(RULE_SHAPE_CONCURRENCY, msg)
        return self

    def describe(self) -> str:
        return f"{self.targets} targets / {self.concurrent_runs} concurrent run(s)"


class WorkloadShape(BaseModel):
    """The shape of the generated workload, in pure numbers.

    Nothing here is random and nothing here reads a clock: the same shape always
    produces the same workload, in the same order, with the same identifiers.
    That is what makes "reproduces its workload exactly from its spec"
    checkable rather than aspirational — the harness in Phase 2 replays
    :meth:`workload` and gets byte-identical work items.
    """

    model_config = ConfigDict(frozen=True)

    iterations: int = Field(ge=1)
    targets: int = Field(ge=1)
    concurrency: int = Field(default=1, ge=1)
    faults_per_run: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _check_shape(self) -> WorkloadShape:
        if self.concurrency > self.targets:
            msg = (
                f"workload concurrency {self.concurrency} exceeds its target count "
                f"{self.targets}; a worker needs a target"
            )
            raise InvariantViolationError(RULE_SHAPE_CONCURRENCY, msg)
        return self

    @property
    def item_count(self) -> int:
        return self.targets * self.iterations

    def workload(self) -> tuple[WorkloadItem, ...]:
        """The work items, deterministically ordered target-major.

        Ordering is target-major (every iteration of target 0, then target 1)
        rather than iteration-major so that a workload truncated at any prefix
        still covers targets uniformly — the property a scale soak depends on
        when it has to stop early.
        """
        items: list[WorkloadItem] = []
        for target_index in range(self.targets):
            for iteration in range(self.iterations):
                items.append(
                    WorkloadItem(
                        index=len(items),
                        target_index=target_index,
                        iteration=iteration,
                        worker=target_index % self.concurrency,
                    )
                )
        return tuple(items)

    def describe(self) -> str:
        return (
            f"{self.targets} targets x {self.iterations} iteration(s) at concurrency "
            f"{self.concurrency}, {self.faults_per_run} fault(s) per run"
        )


class WorkloadItem(BaseModel):
    """One unit of generated benchmark work; identified by its position."""

    model_config = ConfigDict(frozen=True)

    index: int = Field(ge=0)
    target_index: int = Field(ge=0)
    iteration: int = Field(ge=0)
    worker: int = Field(ge=0)

    @property
    def item_id(self) -> str:
        """Stable identifier: same position in the workload, same id, forever."""
        return f"t{self.target_index:05d}:i{self.iteration:05d}:w{self.worker:03d}"

    def describe(self) -> str:
        return f"{self.item_id} (#{self.index})"


class BenchmarkSpec(BaseModel):
    """Everything needed to reproduce one benchmark run, and nothing that varies.

    The spec is the *methodology attached to a number*: the metric, the
    workload shape, the scale it claims, and the measured outputs it promises
    to produce. :meth:`publish` is where the promise is checked — a spec whose
    declared outputs do not all arrive cannot be published, which is the
    negative control for "a benchmark report without its methodology and raw
    outputs attached".

    Digest-addressed like :class:`mayhem.domain.policy.PolicyBundle`: once
    pinned, the spec refuses to exist in a form whose content has drifted, so a
    published number, its evidence record, and a later replay all name the same
    spec by value.
    """

    model_config = ConfigDict(frozen=True)

    spec_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    metric: BenchmarkMetric
    shape: WorkloadShape
    scale: TargetScale
    measured_outputs: tuple[str, ...] = ()
    methodology: str = ""
    spec_digest: str | None = None

    @field_validator("measured_outputs")
    @classmethod
    def _check_outputs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        for name in value:
            stripped = name.strip()
            if not stripped:
                msg = "benchmark spec declares a blank measured output name"
                raise InvariantViolationError(RULE_EMPTY_MEASUREMENT, msg)
            if stripped in cleaned:
                msg = f"benchmark spec declares measured output {stripped!r} twice"
                raise InvariantViolationError(RULE_EMPTY_MEASUREMENT, msg)
            cleaned.append(stripped)
        return tuple(cleaned)

    @model_validator(mode="after")
    def _check_spec(self) -> BenchmarkSpec:
        if self.shape.targets > self.scale.targets:
            msg = (
                f"benchmark spec {self.spec_id} generates {self.shape.targets} targets "
                f"but claims scale {self.scale.describe()}"
            )
            raise InvariantViolationError(RULE_SHAPE_EXCEEDS_SCALE, msg)
        if self.spec_digest is not None and self.spec_digest != self.compute_digest():
            msg = (
                f"benchmark spec {self.spec_id} carries digest {self.spec_digest} "
                f"but its content hashes to {self.compute_digest()}"
            )
            raise InvariantViolationError(RULE_DIGEST_MISMATCH, msg)
        return self

    # -- digest ---------------------------------------------------------------
    def compute_digest(self) -> str:
        """Canonical digest of the spec's content, excluding the pin itself."""
        payload = {
            key: value
            for key, value in self.model_dump(mode="json").items()
            if key != "spec_digest"
        }
        return digest(payload)

    def is_pinned(self) -> bool:
        return self.spec_digest is not None

    def pin(self) -> BenchmarkSpec:
        """A copy carrying ``spec_digest`` set to its own content digest."""
        return self.model_copy(update={"spec_digest": self.compute_digest()})

    def verify_pin(self) -> bool:
        """True when a pinned spec still matches its pin (unpinned: True).

        Raises:
            InvariantViolationError: If a pinned spec's content has drifted.
        """
        if self.spec_digest is None:
            return True
        if self.spec_digest != self.compute_digest():
            msg = f"benchmark spec {self.spec_id} no longer matches its pin"
            raise InvariantViolationError(RULE_DIGEST_MISMATCH, msg)
        return True

    # -- workload -------------------------------------------------------------
    def workload(self) -> tuple[WorkloadItem, ...]:
        """The exact work this spec describes."""
        return self.shape.workload()

    @property
    def declared_outputs(self) -> tuple[str, ...]:
        return self.measured_outputs

    # -- publish --------------------------------------------------------------
    def publish(self, measurements: Iterable[Measurement], *, now: datetime) -> PublishedBenchmark:
        """Bind this spec to the outputs a run actually produced.

        ``now`` is an argument rather than a default ``utc_now()`` call: the
        publish path is the first thing a published report will be timestamped
        with, and a clock the caller did not pass is the ambient behaviour the
        rest of this module exists to avoid.

        Raises:
            InvariantViolationError: If the spec declares no measured outputs,
                or the readings do not match the declaration exactly — missing an
                output the spec promised, or reporting one it never promised.
        """
        readings = tuple(measurements)
        if not self.measured_outputs or not readings:
            msg = (
                f"benchmark spec {self.spec_id} declares no measured outputs; a "
                "benchmark that measures nothing cannot be published"
            )
            raise InvariantViolationError(RULE_MEASURED_OUTPUTS_REQUIRED, msg)
        observed = {reading.name for reading in readings}
        promised = set(self.measured_outputs)
        missing = sorted(promised - observed)
        if missing:
            msg = (
                f"benchmark spec {self.spec_id} promised measured output(s) "
                f"{missing} that the run did not report"
            )
            raise InvariantViolationError(RULE_OUTPUT_MISSING, msg)
        undeclared = sorted(observed - promised)
        if undeclared:
            msg = (
                f"benchmark run reported undeclared measured output(s) {undeclared}; "
                f"spec {self.spec_id} declared {sorted(promised)}"
            )
            raise InvariantViolationError(RULE_OUTPUT_UNDECLARED, msg)
        return PublishedBenchmark(
            spec_id=self.spec_id,
            spec_digest=self.compute_digest(),
            metric=self.metric,
            scale=self.scale,
            methodology=self.methodology,
            measurements=tuple(sorted(readings, key=lambda reading: reading.name)),
            published_at=_require_utc(now, subject="benchmark publication time"),
        )

    def describe(self) -> str:
        return (
            f"{self.spec_id} [{self.metric.value}] {self.shape.describe()} at "
            f"{self.scale.describe()}; outputs {list(self.measured_outputs)}"
        )


class Measurement(BaseModel):
    """One measured output of a benchmark run, with the sample count behind it."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    value: float
    unit: str = Field(min_length=1)
    samples: int = Field(default=1, ge=1)

    @field_validator("name", "unit")
    @classmethod
    def _check_text(cls, value: str) -> str:
        if not value.strip():
            msg = f"measurement field is blank: {value!r}"
            raise InvariantViolationError(RULE_EMPTY_MEASUREMENT, msg)
        return value

    @field_validator("value")
    @classmethod
    def _check_value(cls, value: float) -> float:
        return _require_finite(value, subject="benchmark measurement value")

    def describe(self) -> str:
        return f"{self.name}={self.value:g} {self.unit} (n={self.samples})"


class PublishedBenchmark(BaseModel):
    """A benchmark spec bound to the outputs it produced, at a stated time.

    This is the object a report renders and an evidence record cites: it names
    the spec *by digest*, so the published number and the methodology that
    produced it cannot drift apart — re-running the spec with an edited shape
    yields a different digest and therefore a different published object.
    """

    model_config = ConfigDict(frozen=True)

    spec_id: str
    spec_digest: str
    metric: BenchmarkMetric
    scale: TargetScale
    methodology: str = ""
    measurements: tuple[Measurement, ...]
    published_at: datetime

    @model_validator(mode="after")
    def _check_published(self) -> PublishedBenchmark:
        if not self.measurements:
            msg = f"published benchmark {self.spec_id} carries no measurements"
            raise InvariantViolationError(RULE_MEASURED_OUTPUTS_REQUIRED, msg)
        names = [reading.name for reading in self.measurements]
        if len(set(names)) != len(names):
            msg = f"published benchmark {self.spec_id} reports an output twice: {names}"
            raise InvariantViolationError(RULE_EMPTY_MEASUREMENT, msg)
        _require_utc(self.published_at, subject="benchmark publication time")
        return self

    @property
    def measurement_names(self) -> tuple[str, ...]:
        return tuple(reading.name for reading in self.measurements)

    def measurement(self, name: str) -> Measurement | None:
        """The reading for ``name``, or ``None`` when it was not measured."""
        for reading in self.measurements:
            if reading.name == name:
                return reading
        return None

    def report_digest(self) -> str:
        """Canonical digest of the published record, for evidence pinning."""
        return digest(self.model_dump(mode="json"))

    def describe(self) -> str:
        return f"{self.spec_id} [{self.metric.value}] at {self.scale.describe()}: " + ", ".join(
            reading.describe() for reading in self.measurements
        )


class ScaleClaim(BaseModel):
    """A claim that Mayhem behaves at some scale — measured, or explicitly not.

    Authoring one without a :class:`PublishedBenchmark` is allowed: that is how
    "we intend to characterize 10,000 targets" is recorded. *Rendering* one is
    not — :meth:`render` is the only path to :class:`ScaleClaimView`, and the
    view refuses to exist without measurements behind it.
    """

    model_config = ConfigDict(frozen=True)

    scale: TargetScale
    benchmark: PublishedBenchmark | None = None

    @model_validator(mode="after")
    def _check_claim(self) -> ScaleClaim:
        if self.benchmark is not None and self.benchmark.scale != self.scale:
            msg = (
                f"scale claim for {self.scale.describe()} cites benchmark "
                f"{self.benchmark.spec_id} measured at {self.benchmark.scale.describe()}"
            )
            raise InvariantViolationError(RULE_CLAIM_SCALE_MISMATCH, msg)
        return self

    @property
    def measured(self) -> bool:
        """True only when a benchmark for exactly this scale is attached."""
        return self.benchmark is not None

    def render(self) -> ScaleClaimView:
        """The renderable form of this claim.

        Raises:
            InvariantViolationError: If the claim carries no measured benchmark.
        """
        if self.benchmark is None:
            msg = (
                f"scale claim {self.scale.describe()} is unmeasured; a scale ships "
                "with its measured numbers or stays unclaimed"
            )
            raise InvariantViolationError(RULE_SCALE_UNMEASURED, msg)
        return ScaleClaimView(
            scale=self.scale,
            spec_id=self.benchmark.spec_id,
            spec_digest=self.benchmark.spec_digest,
            metric=self.benchmark.metric,
            published_at=self.benchmark.published_at,
            lines=tuple(
                RenderedMeasurement(
                    name=reading.name,
                    value=reading.value,
                    unit=reading.unit,
                    samples=reading.samples,
                )
                for reading in self.benchmark.measurements
            ),
        )

    def describe(self) -> str:
        state = self.benchmark.spec_id if self.benchmark is not None else "unmeasured"
        return f"{self.scale.describe()} — {state}"


class RenderedMeasurement(BaseModel):
    """One line of a published scale claim."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    value: float
    unit: str = Field(min_length=1)
    samples: int = Field(default=1, ge=1)


class ScaleClaimView(BaseModel):
    """The only shape a dashboard may render for a scale claim.

    Its validator is the structural half of the negative control: even a
    hand-constructed view must carry at least one measurement, so there is no
    way to obtain a renderable claim that has no numbers behind it — not by
    leaving the benchmark unset, and not by constructing the view directly.
    """

    model_config = ConfigDict(frozen=True)

    scale: TargetScale
    spec_id: str = Field(min_length=1)
    spec_digest: str = Field(min_length=1)
    metric: BenchmarkMetric
    published_at: datetime
    lines: tuple[RenderedMeasurement, ...]

    @model_validator(mode="after")
    def _check_view(self) -> ScaleClaimView:
        if not self.lines:
            msg = (
                f"scale claim view for {self.scale.describe()} has no measurements; "
                "an unmeasured claim is unrepresentable"
            )
            raise InvariantViolationError(RULE_SCALE_UNMEASURED, msg)
        _require_utc(self.published_at, subject="published scale claim time")
        return self

    def describe(self) -> str:
        return f"{self.scale.describe()} [{self.metric.value}, {self.spec_id}]: " + ", ".join(
            f"{line.name}={line.value:g} {line.unit}" for line in self.lines
        )
