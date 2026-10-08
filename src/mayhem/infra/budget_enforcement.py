"""Plan 23 Phase 3 — resource budgets in the run path, and the metering ledger.

Phase 2 built the engine (:mod:`mayhem.infra.metering`) and, in
:class:`~mayhem.infra.metering.ResourceBudgetEnforcer`'s own docstring, wrote
down the two call sites it could not reach itself. This module owns them:

1. **Admission, before mutation.** :class:`RunBudgetGuard.admit` is the seam the
   controller's execution entry point consults beside ``validate_plan`` — after
   the plan-time gates and *before* the run row is opened, which is the last
   moment at which a refusal still prevents *every* mutation rather than some.
   It raises :class:`~mayhem.infra.metering.BudgetAdmissionRefused`.
2. **Continuity, during the run.** :meth:`RunBudgetGuard.observe_step` is the
   per-step hook the executor calls once a step's reading exists. It raises
   :class:`~mayhem.infra.metering.PauseForReview` on a breach, so the run stops
   being authorized to continue instead of being silently truncated or silently
   allowed to finish.

**A third thing this module exists to prevent.** Phase 2 metered six seams over
three of the eight dimensions in :class:`~mayhem.domain.budgets.ResourceDimension`
(CPU, STORAGE, API_CALLS) plus the cloud cost ceiling elsewhere, and left four
dimensions carrying budgets with *no meter behind them*. A budget with no meter
is a promise nothing keeps, and a meter that reads zero is worse than no meter
at all — it reads as compliance. So this module carries an explicit
**metering ledger** (:data:`DIMENSION_LEDGER`) that classifies every dimension:

- :attr:`MeterCoverage.EXACT` — counted at a real seam in the dimension's own
  unit (STORAGE bytes, API_CALLS calls, TARGET_COUNT targets,
  CONCURRENT_EXPERIMENTS runs).
- :attr:`MeterCoverage.DERIVED` — integrated from a real instantaneous reading
  over elapsed time, in the dimension's own unit (MEMORY's mebibyte_seconds, from
  the resident set).
- :attr:`MeterCoverage.DECLARED` — counted only where a call site already knows
  the number, and **unmeasured elsewhere** (NETWORK egress bytes: a portable
  userspace read does not exist).
- :attr:`MeterCoverage.EXTERNAL` — metered by another gate, deliberately not
  charged twice here (CLOUD_SPEND, owned by
  :func:`mayhem.domain.cloud.check_cost_ceiling`).
- :attr:`MeterCoverage.UNMEASURED` — not observable from userspace in the unit
  the dimension declares (CPU's core_seconds). Reported unmeasured; never
  approximated from a number in another unit, because that is the unit
  conflation :mod:`mayhem.domain.budgets` exists to forbid.

A dimension that reports no reading is **unmeasured, never zero**. That is
enforced structurally: :meth:`RunBudgetGuard.read` returns ``None`` unless the
seam has actually produced at least one reading, and an unmeasured dimension
never refuses a run — refusing on consumption nobody measured would invent the
very number the refusal is about.

**Two ledgers, still.** Nothing here imports
:mod:`mayhem.domain.quota`, :mod:`mayhem.domain.policy`, or
:mod:`mayhem.controller.safety`. A resource budget is a different dimension set
from a damage budget (CPU-seconds vs damage-seconds, per-team vs per-target), so
the two never enforce each other's refusals; they are two ledgers one run
consults at one moment. :class:`RunBudgetGuard` holds a
:class:`~mayhem.infra.metering.ResourceBudgetEnforcer` and nothing else, which
is what makes that structural rather than a promise.

**A pause is a state, and a state needs a decision.** Once a breach pauses the
run, further observation raises :class:`BudgetPauseUnreviewed` until somebody
records a :class:`BudgetReview` naming the breaching dimension and a rationale.
A paused run therefore cannot resume itself — "we noticed we were over budget and
carried on" is not a state this class can represent.

**No ambient clock.** Every method that needs to know *when* takes ``now`` as an
argument, exactly as :mod:`mayhem.infra.metering` does, and the concurrency
count is a length of a live set rather than a clock reading. A replay from
evidence reproduces the decisions.

**One caveat this module does not paper over.** A per-run reading charged to a
budget at ``ORGANISATION`` or ``ENVIRONMENT`` scope is *this run's
contribution*, not the aggregate: aggregating across runs needs a ledger shared
by those runs, which is a store question this lane does not own. The
observation says so in its :attr:`StepObservation.reason` rather than pretending
a single run's number is the scope's total.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from mayhem.domain.budgets import ResourceDimension, unit_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.infra.metering import (
    RULE_METER_CONTRACT,
    AdmissionDecision,
    BudgetAdmissionRefused,
    ContinuityDecision,
    PauseForReview,
    ResourceBudgetEnforcer,
    RunMeter,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping, Sequence
    from datetime import datetime

    from mayhem.domain.budgets import ResourceBudget, ResourceEstimate

__all__ = [
    "DIMENSION_LEDGER",
    "RULE_PAUSE_UNREVIEWED",
    "RULE_REVIEW_REQUIRED",
    "RULE_UNIT_CONFLATION",
    "BudgetPauseUnreviewed",
    "BudgetReview",
    "ConcurrentRunReservations",
    "DimensionLedger",
    "DimensionReading",
    "MeterCoverage",
    "ReviewDecision",
    "RunBudgetGuard",
    "budget_pause_boundary",
    "coverage_for",
    "ledger_for",
    "ledger_rows",
    "metered_dimensions",
    "unmeasured_dimensions",
]

# -- rule ids ------------------------------------------------------------------
# Disjoint from every rule id in domain/budgets.py, domain/quota.py,
# domain/policy.py, and infra/metering.py's own namespace, so a record naming one
# of these is unambiguously about *this* wiring rather than about a budget
# refusal that some other gate produced.

RULE_PAUSE_UNREVIEWED = "budget.pause_unreviewed"
RULE_REVIEW_REQUIRED = "budget.review_required"
RULE_UNIT_CONFLATION = "budget.unit_conflation"


# -- the metering ledger --------------------------------------------------------


class MeterCoverage(StrEnum):
    """How honestly this system can measure a dimension, stated up front.

    The point of the enum is that "metered" is not a boolean. A dimension counted
    in its own unit at a real seam, a dimension integrated from a real reading,
    a dimension counted only where a caller already knows the number, a dimension
    another gate owns, and a dimension nobody can see are five different
    situations, and collapsing them into "metered" / "not metered" is how a
    budget with no meter behind it ends up looking enforced.
    """

    EXACT = "exact"
    """Counted in the dimension's own unit at a real seam."""

    DERIVED = "derived"
    """Integrated from a real instantaneous reading over elapsed time."""

    DECLARED = "declared"
    """Counted where a call site already knows the number; unmeasured elsewhere."""

    EXTERNAL = "external"
    """Metered by another gate; deliberately not charged a second time here."""

    UNMEASURED = "unmeasured"
    """Not observable from userspace in the declared unit. Reported, never faked."""


@dataclass(frozen=True, slots=True)
class DimensionLedger:
    """What this system does about one dimension, and why that is the honest answer.

    ``rationale`` is the load-bearing field: it is what makes an unmeasured
    dimension a *decision* rather than an omission, and it is reused verbatim as
    the reason text on a :class:`StepObservation` whose reading is absent, so a
    report says the same thing the code believes.
    """

    dimension: ResourceDimension
    coverage: MeterCoverage
    seam: str
    """The meter seam that reads this dimension; empty when nothing does."""
    method: str
    """One line naming *how* the reading is obtained."""
    rationale: str

    @property
    def measured(self) -> bool:
        """True when some seam in this system can produce a number."""
        return self.coverage is not MeterCoverage.UNMEASURED

    def absence_reason(self) -> str:
        """The text a report renders for a dimension with no reading."""
        return (
            f"{self.dimension.value} is not measured by this run "
            f"[{self.coverage.value}]: {self.rationale}"
        )

    def inputs(self) -> dict[str, object]:
        return {
            "dimension": self.dimension.value,
            "coverage": self.coverage.value,
            "seam": self.seam,
            "method": self.method,
            "measured": self.measured,
        }

    def describe(self) -> str:
        state = self.coverage.value if self.measured else "NOT MEASURED"
        where = f" at seam {self.seam}" if self.seam else ""
        return f"{self.dimension.value}: {state}{where} via {self.method}. {self.rationale}"


DIMENSION_LEDGER: Mapping[ResourceDimension, DimensionLedger] = {
    ResourceDimension.CPU: DimensionLedger(
        dimension=ResourceDimension.CPU,
        coverage=MeterCoverage.UNMEASURED,
        seam="",
        method="none from userspace",
        rationale=(
            "the dimension is declared in core_seconds, which is per-core "
            "accounting (a cgroup's cpu.stat, a container runtime's stats); "
            "userspace can observe elapsed wall-clock, which is a different "
            "quantity in a different unit, and charging it to a core_seconds "
            "budget would conflate units. Reported unmeasured rather than "
            "approximated."
        ),
    ),
    ResourceDimension.MEMORY: DimensionLedger(
        dimension=ResourceDimension.MEMORY,
        coverage=MeterCoverage.DERIVED,
        seam="memory_resident",
        method="resident-set reading integrated over the injected monotonic clock",
        rationale=(
            "a resident set is readable from userspace, and integrating it over "
            "elapsed time yields the mebibyte_seconds the dimension declares. It "
            "is an upper bound on memory actually touched — a resident page that "
            "was never read still counts for the whole interval."
        ),
    ),
    ResourceDimension.NETWORK: DimensionLedger(
        dimension=ResourceDimension.NETWORK,
        coverage=MeterCoverage.DECLARED,
        seam="network_egress",
        method="explicit egress counter, supplied by the call site that knows the size",
        rationale=(
            "total egress bytes are accounted by the kernel and have no portable "
            "userspace read; a counter that claims to know them would be a "
            "fabrication. Only transfers whose size the calling code already "
            "knows (a payload it sent, a response body it received) are counted, "
            "and the dimension reads unmeasured anywhere else."
        ),
    ),
    ResourceDimension.STORAGE: DimensionLedger(
        dimension=ResourceDimension.STORAGE,
        coverage=MeterCoverage.EXACT,
        seam="store_growth",
        method="cumulative store-growth byte counter",
        rationale=(
            "store growth is what the run left behind (rows, indexes, WAL) and is "
            "counted in bytes, the dimension's own unit. Evidence bytes are a "
            "subset of store growth and are deliberately not added again: "
            "charging both would double-count one write."
        ),
    ),
    ResourceDimension.CLOUD_SPEND: DimensionLedger(
        dimension=ResourceDimension.CLOUD_SPEND,
        coverage=MeterCoverage.EXTERNAL,
        seam="cloud.cost_estimate",
        method="mayhem.domain.cloud.check_cost_ceiling",
        rationale=(
            "currency is metered by the cloud cost gate, which checks an action's "
            "estimate against a ceiling before the action runs. RunBudgetGuard "
            "does not charge it: a second meter over the same spend would be a "
            "double charge against a different limit, which is exactly how one "
            "dimension's slack pays for another's overspend."
        ),
    ),
    ResourceDimension.API_CALLS: DimensionLedger(
        dimension=ResourceDimension.API_CALLS,
        coverage=MeterCoverage.EXACT,
        seam="api_calls",
        method="cumulative call counter; whole numbers only",
        rationale=(
            "an API call is indivisible, so the counter takes an int and refuses "
            "a fractional or negative count rather than rounding a number no "
            "caller wrote."
        ),
    ),
    ResourceDimension.TARGET_COUNT: DimensionLedger(
        dimension=ResourceDimension.TARGET_COUNT,
        coverage=MeterCoverage.EXACT,
        seam="targets",
        method="cumulative target counter, incremented as targets are touched",
        rationale=(
            "targets are counted as the run touches them, so the reading is the "
            "blast radius actually reached rather than the plan's intent — which "
            "is the number a target-count budget exists to bound."
        ),
    ),
    ResourceDimension.CONCURRENT_EXPERIMENTS: DimensionLedger(
        dimension=ResourceDimension.CONCURRENT_EXPERIMENTS,
        coverage=MeterCoverage.EXACT,
        seam="run_reservations",
        method="length of the live run-reservation set for the budget's scope key",
        rationale=(
            "concurrency is a property of the live reservation set, not of a "
            "run's own bookkeeping, so it is read from the set itself. A "
            "reservation set tracking a different scope key than the budget "
            "governs is not a reading of zero; it is no reading at all."
        ),
    ),
}
"""Every dimension, classified. Exhaustive on purpose: adding a dimension to
:class:`~mayhem.domain.budgets.ResourceDimension` without a row here is a
budget with no statement of how it is metered, which is the gap this closes."""


def ledger_for(dimension: ResourceDimension) -> DimensionLedger:
    """The ledger entry for ``dimension``."""
    return DIMENSION_LEDGER[dimension]


def coverage_for(dimension: ResourceDimension) -> MeterCoverage:
    """How this system measures ``dimension``."""
    return DIMENSION_LEDGER[dimension].coverage


def metered_dimensions() -> frozenset[ResourceDimension]:
    """Dimensions with a seam that can produce a reading."""
    return frozenset(d for d, entry in DIMENSION_LEDGER.items() if entry.measured)


def unmeasured_dimensions() -> frozenset[ResourceDimension]:
    """Dimensions this system cannot honestly read, in its declared unit."""
    return frozenset(d for d, entry in DIMENSION_LEDGER.items() if not entry.measured)


def ledger_rows() -> tuple[tuple[str, str, str, str], ...]:
    """The ledger as printable rows — dimension, coverage, seam, rationale.

    The shape a Phase 4 budget-configuration view renders. Plain tuples so the
    caller decides its own formatting; returning a table from here would make
    this module a CLI.
    """
    return tuple(
        (entry.dimension.value, entry.coverage.value, entry.seam, entry.rationale)
        for entry in sorted(DIMENSION_LEDGER.values(), key=lambda e: e.dimension.value)
    )


# -- concurrency ----------------------------------------------------------------


class ConcurrentRunReservations:
    """The live set of run reservations ``CONCURRENT_EXPERIMENTS`` is read from.

    One instance per scope key, so a per-team cap counts that team's live runs and
    never another's. A run reserves itself on entry and releases on exit; the
    reading is :meth:`count`, a length — not a clock reading, not an estimate of
    what the scheduler might start next.

    Insertion-ordered, so a report of who is live is deterministic.
    """

    def __init__(self, scope_key: str, *, run_ids: Iterable[str] = ()) -> None:
        if not scope_key.strip():
            msg = f"reservation set names no scope key: {scope_key!r}"
            raise InvariantViolationError(RULE_METER_CONTRACT, msg)
        self.scope_key = scope_key
        self._live: dict[str, None] = dict.fromkeys(run_ids)

    def reserve(self, run_id: str) -> float:
        """Mark ``run_id`` live; returns the resulting concurrent-run count."""
        if not run_id.strip():
            msg = "run reservation names no run id"
            raise InvariantViolationError(RULE_METER_CONTRACT, msg)
        self._live[run_id] = None
        return self.count()

    def release(self, run_id: str) -> float:
        """Mark ``run_id`` no longer live; returns the resulting count."""
        self._live.pop(run_id, None)
        return self.count()

    def count(self) -> float:
        """How many runs are live in this set right now."""
        return float(len(self._live))

    @property
    def live_run_ids(self) -> tuple[str, ...]:
        """The live run ids, in reservation order."""
        return tuple(self._live)

    def __contains__(self, run_id: object) -> bool:
        return run_id in self._live

    def __len__(self) -> int:
        return len(self._live)


# -- reviews --------------------------------------------------------------------


class ReviewDecision(StrEnum):
    """What a human decided about a paused run."""

    RESUME = "resume"
    """Accept the overspend and let the run continue past it."""

    RAISE_LIMIT = "raise_limit"
    """Author a new, larger budget. The existing one is unchanged and still breached."""

    STOP = "stop"
    """End the run here. Nothing may continue, reviewed or not."""


@dataclass(frozen=True, slots=True)
class BudgetReview:
    """The decision that a pause requires before the run may continue.

    ``rationale`` is mandatory and must be non-blank: "reviewed" without a reason
    is the same as not reviewed, with a timestamp on it.
    """

    dimension: ResourceDimension
    decision: ReviewDecision
    rationale: str
    at: datetime
    run_id: str = ""
    decided_by: str = ""

    def __post_init__(self) -> None:
        if not self.rationale.strip():
            msg = "a budget review must state a rationale"
            raise InvariantViolationError(RULE_REVIEW_REQUIRED, msg)
        if self.at.tzinfo is None or self.at.tzinfo.utcoffset(self.at) is None:
            msg = f"budget review timestamp must be timezone-aware, got naive {self.at!r}"
            raise InvariantViolationError(RULE_METER_CONTRACT, msg)

    def inputs(self) -> dict[str, object]:
        return {
            "dimension": self.dimension.value,
            "decision": self.decision.value,
            "rationale": self.rationale,
            "run_id": self.run_id,
            "decided_by": self.decided_by,
            "at": self.at.isoformat(),
        }

    def describe(self) -> str:
        who = f" by {self.decided_by}" if self.decided_by else ""
        return f"{self.decision.value} after a {self.dimension.value} breach{who}: {self.rationale}"


class BudgetPauseUnreviewed(Exception):  # noqa: N818 — a pause is not an error, it is a state
    """The run is paused for review and no decision has been recorded yet.

    Raised by :meth:`RunBudgetGuard.observe_step` before it will observe another
    step. It is the enforcement half of "a paused run cannot resume without a
    decision": without it, a paused run could simply keep being observed, and the
    breach that paused it would become a note nobody read.

    ``breach`` is ``None`` only when a review already decided the run stops; the
    stop *is* the decision, so there is nothing left to wait for and nothing to
    resume into.
    """

    def __init__(self, breach: PauseForReview | None, *, observed: int, stopped: bool) -> None:
        self.breach = breach
        self.observed = observed
        self.stopped = stopped
        subject = breach.dimension.value if breach is not None else "a resource budget"
        consequence = (
            "a review decided this run stops here; nothing further may be observed"
            if stopped
            else f"record a BudgetReview before continuing [{RULE_PAUSE_UNREVIEWED}]"
        )
        where = f" at seam {breach.seam!r}" if breach is not None else ""
        super().__init__(
            f"{subject} paused this run{where} after {observed} observation(s); {consequence}"
        )

    def inputs(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "observed": self.observed,
            "stopped": self.stopped,
            "rule_id": RULE_PAUSE_UNREVIEWED,
        }
        if self.breach is not None:
            payload.update(self.breach.inputs())
        return payload


# -- readings -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DimensionReading:
    """One dimension's reading for this step, or its honest absence.

    ``value is None`` means **unmeasured**. It never means zero. A caller that
    wants a number must handle the absence, and the absence carries the ledger's
    :meth:`DimensionLedger.absence_reason` so a report can explain itself.
    """

    dimension: ResourceDimension
    coverage: MeterCoverage
    value: float | None
    unit: str
    source: str = ""
    reason: str = ""

    @property
    def measured(self) -> bool:
        return self.value is not None

    def inputs(self) -> dict[str, object]:
        return {
            "dimension": self.dimension.value,
            "coverage": self.coverage.value,
            "value": self.value,
            "unit": self.unit,
            "source": self.source,
            "measured": self.measured,
        }

    def describe(self) -> str:
        if self.value is None:
            return self.reason
        return f"{self.dimension.value}={self.value:g} {self.unit} via {self.source}"


@dataclass(frozen=True, slots=True)
class StepObservation:
    """What one dimension's budget said about one step.

    ``decision`` is ``None`` when there was no reading to judge — an unmeasured
    dimension is never a breach, because refusing a run over consumption nobody
    measured would invent the number the refusal is about. ``budget`` is ``None``
    for a ledger-level read that no budget governs.
    """

    dimension: ResourceDimension
    coverage: MeterCoverage
    measured: float | None
    unit: str
    seam: str
    budget: ResourceBudget | None = None
    decision: ContinuityDecision | None = None
    reason: str = ""

    @property
    def is_measured(self) -> bool:
        return self.measured is not None

    @property
    def within_budget(self) -> bool:
        """True when a reading was judged and did not breach."""
        if self.decision is None:
            return self.measured is None
        return self.decision.continue_running

    def inputs(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "dimension": self.dimension.value,
            "coverage": self.coverage.value,
            "measured": self.measured,
            "unit": self.unit,
            "seam": self.seam,
            "reason": self.reason,
        }
        if self.budget is not None:
            payload["limit"] = self.budget.limit
            payload["scope"] = self.budget.scope.value
            payload["scope_key"] = self.budget.scope_key
        if self.decision is not None:
            payload.update(self.decision.inputs())
        return payload

    def describe(self) -> str:
        if not self.is_measured:
            return self.reason
        if self.decision is None:
            return f"{self.dimension.value}={self.measured:g} {self.unit} (no budget governs)"
        return self.decision.describe()


# -- the guard ------------------------------------------------------------------


@dataclass
class RunBudgetGuard:
    """One run's resource budgets, its meter, and the two call sites.

    Holds a :class:`~mayhem.infra.metering.ResourceBudgetEnforcer` and a
    :class:`~mayhem.infra.metering.RunMeter` and nothing else from a budget's
    world. That is the whole reason the two ledgers cannot cross: this class has
    no reference to a damage ledger, a damage budget node, or the safety gate, so
    it *cannot* enforce a damage refusal even by accident.

    Construct one per run and hand it to
    :meth:`mayhem.controller.executor.RunEngine.with_budget_guard`. With no guard
    attached the executor behaves exactly as before — there is no global
    singleton, no environment read, and no default that could change a run
    someone did not intend to budget.
    """

    enforcer: ResourceBudgetEnforcer
    meter: RunMeter | None = None
    reservations: ConcurrentRunReservations | None = None
    estimates: tuple[ResourceEstimate, ...] = ()
    """The pre-execution estimates admission judges, supplied by the caller.

    On the guard rather than on :meth:`admit` because the admission call site is
    inside ``RunEngine.execute``, which has no estimates of its own to pass: an
    ``ExecutionPlan`` carries none, and deriving them there would mean inventing
    the basis :class:`~mayhem.domain.budgets.ResourceEstimate` demands. Empty is a
    legitimate configuration and reports itself as
    :attr:`admission_is_vacuous`."""
    observations: list[StepObservation] = field(default_factory=list)
    """Every per-dimension observation, in order, for a post-run report."""
    reviews: list[BudgetReview] = field(default_factory=list)
    """Every recorded decision, in order."""
    admission: AdmissionDecision | None = None
    """The admission verdict, or ``None`` when :meth:`admit` was never called."""
    breach: PauseForReview | None = None
    """The breach that paused the run, once one has."""

    # -- ledger ---------------------------------------------------------------
    @property
    def dimensions(self) -> tuple[ResourceDimension, ...]:
        """The dimensions this guard's budgets govern, deduplicated and ordered."""
        return tuple(sorted({b.dimension for b in self.enforcer.budgets}, key=lambda d: d.value))

    @property
    def paused(self) -> bool:
        """True once a breach paused the run."""
        return self.breach is not None

    @property
    def stopped(self) -> bool:
        """True once a review decided the run stops here."""
        return any(review.decision is ReviewDecision.STOP for review in self.reviews)

    @property
    def admission_is_vacuous(self) -> bool:
        """True when admission was granted with no estimate checked against a limit.

        Distinguishes "admitted because nothing breached" from "admitted because
        nothing was checked" — the second is a policy gap wearing the same face
        as the first, and a caller that wants to know whether admission *means*
        anything must ask.
        """
        return self.admission is not None and self.admission.estimates_compared == 0

    # -- readings -------------------------------------------------------------
    def read(
        self,
        dimension: ResourceDimension,
        *,
        scope_key: str = "",
    ) -> DimensionReading:
        """This run's reading for ``dimension``, or its honest absence.

        ``scope_key`` matters for exactly one dimension:
        :attr:`~mayhem.domain.budgets.ResourceDimension.CONCURRENT_EXPERIMENTS`
        is read from a reservation set belonging to a scope key, and a set that
        tracks a different scope is not a reading of zero — it is no reading.

        Raises:
            InvariantViolationError: With :data:`RULE_UNIT_CONFLATION` if the
                meter's own last reading at the seam carries a unit other than
                the dimension's. Conflating bytes with targets would produce a
                confident nonsense budget, so the mismatch is refused instead.
        """
        entry = ledger_for(dimension)
        unit = unit_for(dimension)
        if entry.coverage is MeterCoverage.UNMEASURED:
            return DimensionReading(
                dimension, entry.coverage, None, unit, entry.method, entry.absence_reason()
            )
        if entry.coverage is MeterCoverage.EXTERNAL:
            return DimensionReading(
                dimension,
                entry.coverage,
                None,
                unit,
                entry.seam,
                f"{dimension.value} is metered by {entry.seam}, not by this run; "
                "it is deliberately not charged a second time here",
            )
        if dimension is ResourceDimension.CONCURRENT_EXPERIMENTS:
            return self._read_reservations(entry, scope_key=scope_key, unit=unit)
        return self._read_meter(entry, unit=unit)

    def _read_reservations(
        self, entry: DimensionLedger, *, scope_key: str, unit: str
    ) -> DimensionReading:
        """The concurrent-run reading, or why there is none."""
        reservations = self.reservations
        if reservations is None:
            return DimensionReading(
                dimension=entry.dimension,
                coverage=entry.coverage,
                value=None,
                unit=unit,
                source=entry.method,
                reason=(
                    f"{entry.dimension.value} is not measured by this run: no live "
                    "reservation set is attached to the guard"
                ),
            )
        if scope_key and reservations.scope_key != scope_key:
            return DimensionReading(
                dimension=entry.dimension,
                coverage=entry.coverage,
                value=None,
                unit=unit,
                source=entry.method,
                reason=(
                    f"{entry.dimension.value} is not measured for scope {scope_key!r}: "
                    f"the attached reservation set tracks {reservations.scope_key!r}"
                ),
            )
        return DimensionReading(
            dimension=entry.dimension,
            coverage=entry.coverage,
            value=reservations.count(),
            unit=unit,
            source=f"{entry.seam}({reservations.scope_key})",
        )

    def _read_meter(self, entry: DimensionLedger, *, unit: str) -> DimensionReading:
        """The metered reading, or why there is none yet.

        The ``readings_for(seam)`` test is the structural half of "unmeasured,
        never zero": before the seam has produced a single reading this run has
        consumed nothing *that anyone observed*, and reporting ``0.0`` would be a
        claim the meter cannot support. Once the seam has been exercised, ``0.0``
        is a real zero — the run genuinely incremented nothing.
        """
        meter = self.meter
        if meter is None:
            return DimensionReading(
                dimension=entry.dimension,
                coverage=entry.coverage,
                value=None,
                unit=unit,
                source=entry.method,
                reason=(
                    f"{entry.dimension.value} is not measured by this run: no meter "
                    "is attached to the guard"
                ),
            )
        readings = meter.readings_for(entry.seam)
        if not readings:
            return DimensionReading(
                dimension=entry.dimension,
                coverage=entry.coverage,
                value=None,
                unit=unit,
                source=entry.method,
                reason=(
                    f"{entry.dimension.value} is not measured yet: the meter has "
                    f"taken no reading at seam {entry.seam!r}"
                ),
            )
        observed_unit = readings[-1].unit
        if observed_unit != unit:
            msg = (
                f"meter seam {entry.seam!r} reports in {observed_unit!r} but "
                f"{entry.dimension.value} is budgeted in {unit!r}; refusing to "
                f"conflate the two [{RULE_UNIT_CONFLATION}]"
            )
            raise InvariantViolationError(RULE_UNIT_CONFLATION, msg)
        value = self._meter_value(meter, entry.dimension)
        if value is None:
            return DimensionReading(
                dimension=entry.dimension,
                coverage=entry.coverage,
                value=None,
                unit=unit,
                source=entry.method,
                reason=(
                    f"{entry.dimension.value} is not measured by this run: seam "
                    f"{entry.seam!r} has no reading mapped to it"
                ),
            )
        note = ""
        if value == 0.0:
            note = "no consumption observed at this seam"
        return DimensionReading(
            dimension=entry.dimension,
            coverage=entry.coverage,
            value=value,
            unit=unit,
            source=entry.seam,
            reason=note,
        )

    @staticmethod
    def _meter_value(meter: RunMeter, dimension: ResourceDimension) -> float | None:
        """The cumulative total the meter holds for ``dimension``.

        ``None`` for a dimension this system reads some other way, so a caller
        that adds a dimension to the ledger without adding it here gets an
        *unmeasured* reading rather than a silent zero.
        """
        if dimension is ResourceDimension.STORAGE:
            return meter.total_store_growth_bytes
        if dimension is ResourceDimension.API_CALLS:
            return meter.total_api_calls
        if dimension is ResourceDimension.NETWORK:
            return meter.total_network_bytes
        if dimension is ResourceDimension.TARGET_COUNT:
            return meter.total_targets
        if dimension is ResourceDimension.MEMORY:
            return meter.memory_resident_mib_seconds
        return None

    # -- admission ------------------------------------------------------------
    def admit(
        self,
        estimates: Sequence[ResourceEstimate] | None = None,
        *,
        now: datetime,
    ) -> AdmissionDecision:
        """Refuse a run whose estimate breaches a budget, before any mutation.

        ``estimates`` defaults to the ones this guard was configured with; pass a
        sequence explicitly to judge a different set. Deriving them here would be
        inventing a basis (and :class:`~mayhem.domain.budgets.ResourceEstimate`
        demands one), and inventing a limit for an unbudgeted dimension is a
        policy decision this module does not get to make. With no estimates the
        run is admitted and :attr:`admission_is_vacuous` says so.

        Raises:
            BudgetAdmissionRefused: When an estimate breaches a limit. The message
                names the dimension, the number, the limit, and the overage.
        """
        judged = self.estimates if estimates is None else tuple(estimates)
        try:
            decision = self.enforcer.admit(judged, now=now)
        except BudgetAdmissionRefused as refusal:
            # Recorded before it propagates: a refusal nobody can read afterwards
            # is indistinguishable from a crash, and the decision carries the
            # dimension and the numbers.
            self.admission = refusal.decision
            raise
        self.admission = decision
        return decision

    # -- continuity -----------------------------------------------------------
    def observe_step(self, *, now: datetime, seam: str) -> tuple[StepObservation, ...]:
        """Judge every governed budget against this step's readings; pause on a breach.

        The per-step hook. Called after a step's reading exists, never before,
        because a reading that does not exist yet cannot breach anything and a
        check placed earlier would only ever see the previous step's number.

        Raises:
            BudgetPauseUnreviewed: If a previous breach has no recorded review, or
                a review decided the run stops.
            PauseForReview: On a breach, naming the dimension and the numbers. The
                run is neither silently continued nor silently truncated.
        """
        if self.stopped or (self.paused and not self._resumed):
            raise BudgetPauseUnreviewed(
                self.breach,
                observed=len(self.observations),
                stopped=self.stopped,
            )

        results: list[StepObservation] = []
        for budget in _distinct_budgets(self.enforcer.budgets):
            reading = self.read(budget.dimension, scope_key=budget.scope_key)
            value = reading.value
            if value is None:
                observation = StepObservation(
                    dimension=budget.dimension,
                    coverage=reading.coverage,
                    measured=None,
                    unit=reading.unit,
                    seam=seam,
                    budget=budget,
                    decision=None,
                    reason=reading.reason,
                )
                results.append(observation)
                self.observations.append(observation)
                continue
            note = reading.reason
            if budget.scope is not self.enforcer.scope:
                note = (
                    f"{note + '; ' if note else ''}this is this run's contribution "
                    f"against a {budget.scope.value}-scope budget, not the scope's "
                    "aggregate"
                )
            try:
                decision = self.enforcer.observe(budget, value, now=now, seam=seam)
            except PauseForReview as pause:
                self.breach = pause
                raise
            observation = StepObservation(
                dimension=budget.dimension,
                coverage=reading.coverage,
                measured=value,
                unit=reading.unit,
                seam=seam,
                budget=budget,
                decision=decision,
                reason=note or decision.describe(),
            )
            results.append(observation)
            self.observations.append(observation)
        return tuple(results)

    # -- review ---------------------------------------------------------------
    @property
    def _resumed(self) -> bool:
        """True when a review has authorized continuing past the current breach."""
        if self.breach is None:
            return False
        return any(
            review.decision is ReviewDecision.RESUME and review.dimension is self.breach.dimension
            for review in self.reviews
        )

    def record_review(self, review: BudgetReview) -> BudgetReview:
        """Record the decision a pause is waiting for.

        Raises:
            InvariantViolationError: With :data:`RULE_REVIEW_REQUIRED` when the
                review does not name the dimension that actually breached. A
                review of the wrong dimension is not a review of this pause.
        """
        if self.breach is not None and review.dimension is not self.breach.dimension:
            msg = (
                f"a review of {review.dimension.value} does not answer a "
                f"{self.breach.dimension.value} breach [{RULE_REVIEW_REQUIRED}]"
            )
            raise InvariantViolationError(RULE_REVIEW_REQUIRED, msg)
        self.reviews.append(review)
        return review

    # -- reporting ------------------------------------------------------------
    def ledger(self) -> tuple[DimensionLedger, ...]:
        """The full eight-dimension ledger, in dimension order."""
        return tuple(DIMENSION_LEDGER[dimension] for dimension in self.dimensions)

    def unmeasured(self) -> tuple[ResourceDimension, ...]:
        """Governed dimensions this run has no reading for."""
        measured = {obs.dimension for obs in self.observations if obs.is_measured}
        return tuple(d for d in self.dimensions if d not in measured)

    def observations_for(self, dimension: ResourceDimension) -> tuple[StepObservation, ...]:
        """Every observation of ``dimension``, in order."""
        return tuple(obs for obs in self.observations if obs.dimension is dimension)

    def inputs(self) -> dict[str, object]:
        return {
            "run_id": self.enforcer.run_id,
            "dimensions": [d.value for d in self.dimensions],
            "observations": len(self.observations),
            "paused": self.paused,
            "unmeasured": [d.value for d in self.unmeasured()],
        }


def _distinct_budgets(budgets: Sequence[ResourceBudget]) -> tuple[ResourceBudget, ...]:
    """The budgets, deduplicated by subject, in a stable order.

    Two equal budgets in one run meter into one ledger (see
    :meth:`~mayhem.infra.metering.ResourceBudgetEnforcer.series_for`); observing
    both would post the same reading twice into that one series and the second
    post would be judged against the first reading's already-committed total.
    """
    seen: dict[tuple[ResourceDimension, str, str], ResourceBudget] = {}
    for budget in budgets:
        seen.setdefault(budget.subject, budget)
    return tuple(seen[key] for key in sorted(seen))


@contextmanager
def budget_pause_boundary(guard: RunBudgetGuard) -> Iterator[None]:
    """Turn a :class:`PauseForReview` from the step loop into a run *status*.

    The executor wraps its fault loop in this so a breach ends the run in the
    ordinary way — the run row is still closed, still recovered, still reported —
    rather than unwinding past all of that with an exception in flight and leaving
    the leases the paused step had acquired dirty and unrecorded.

    Yields control to the caller. A breach is captured on the guard
    (:attr:`RunBudgetGuard.breach`) and swallowed here; nothing else is caught, so
    every other failure keeps propagating exactly as before.
    """
    try:
        yield
    except PauseForReview as pause:
        guard.breach = pause
