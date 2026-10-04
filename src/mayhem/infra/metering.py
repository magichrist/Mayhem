"""Plan 23 Phase 2 — metering at the real seams, and resource-budget enforcement.

Plan 23 Phase 1 put the *vocabulary* for gap 68 in
:mod:`mayhem.domain.budgets`: eight
:class:`~mayhem.domain.budgets.ResourceDimension` members, half-open
:class:`~mayhem.domain.budgets.BudgetWindow`s, cumulative
:class:`~mayhem.domain.budgets.ResourceSeries` ledgers, and a
:class:`~mayhem.domain.budgets.BenchmarkSpec` whose ``publish`` refuses a spec
whose declared measured outputs do not arrive. All of it is pure and clockless.

This module is the other half: the *engine* seam. It does two jobs, and neither
of them is "compute a number that could have been computed by hand".

**Job one — meter where the work already happens.** Six real seams, named in the
plan rather than invented here: plan-compilation timing
(:meth:`RunMeter.time_plan_compilation`), topology-discovery timing
(:meth:`RunMeter.time_discovery`), policy-evaluation timing
(:meth:`RunMeter.time_policy_evaluation`), per-command agent latency over the
fabric protocol (:meth:`RunMeter.time_agent_command`), evidence bytes per run
(:meth:`RunMeter.add_evidence_bytes`), and store growth per run
(:meth:`RunMeter.add_store_growth_bytes`). Five of the six are context managers
or counter adds that record a :class:`MeterReading` — a plain frozen dataclass —
and return control immediately. Nothing here shells out, opens a socket, writes
to the store, or waits on a queue: a meter that could block would be a meter
that made the control plane slower in order to describe it, which is the
opposite of what plan 23 is for.

**Job two — enforce the budget, not just report it.** This is gap 68's actual
ask, and it is why the module lives in ``infra`` rather than being folded into
the domain: enforcement has to be *called from somewhere*, and that somewhere is
a call site. Two checks, deliberately distinct:

- :func:`admission_check` / :meth:`ResourceBudgetEnforcer.admit` — before any
  mutation. A pre-execution
  :class:`~mayhem.domain.budgets.ResourceEstimate` is compared against each
  budget that governs the run's scope, and a run whose estimate already exceeds
  a limit is refused.
- :func:`continuity_check` / :meth:`ResourceBudgetEnforcer.observe` — during
  execution. Each cumulative reading is judged against the ledger's series, and
  a breach raises :class:`PauseForReview`: the run *stops being authorized to
  continue*. It is not silently truncated and not allowed to finish.

Both refusals name the breaching dimension and the numbers, because the text is
the domain's own :attr:`~mayhem.domain.budgets.BudgetConsumption.reason` rather
than a fresh string that could drift from it.

**The two ledgers are not the same ledger.** :mod:`mayhem.domain.quota` charges
*damage seconds* against a per-target ledger
(:class:`~mayhem.domain.quota.DamageLedger`), and
:class:`~mayhem.domain.policy.BudgetNode` is the hierarchical damage budget.
Nothing in this module reads either, and every rule id here is disjoint from
theirs. A CPU-second is not a damage-second; conflating them would let one
dimension's slack pay for another's overspend, which is the exact mistake
``domain/budgets.py``'s module docstring exists to prevent.

**A metering failure is never a run failure.** Every sink call is wrapped: a
broken exporter loses exactly one reading, records the failure in
:attr:`RunMeter.failures`, and the instrumented code never learns about it. This
is the discipline :func:`mayhem.domain.observations.collect` states as "a broken
provider must not look like a pass" — and here, must not *stop* a pass either.
The one deliberate exception is
:class:`MeterContractError`, raised only by :func:`strict_reading`, which a
*benchmark harness* opts into when it is about to publish a number.

**No ambient clock in a decision.** Timing seams read their duration from an
injected ``clock`` (defaulting to :func:`time.perf_counter`, a monotonic
source), and every function that needs to know *when* takes ``now`` as an
argument. :func:`now_utc` exists only so the default is greppable; no decision
path calls it, and a replay from evidence therefore reproduces the numbers —
the property ``domain/budgets.py`` holds and this module does not give back.

**Publication discipline.** :func:`publish_benchmark` closes the one gap
Phase 1's ``BenchmarkSpec.publish`` deliberately leaves open: a spec may declare
its outputs perfectly and still ship a number with no statement of *how* it was
measured. The gate refuses a blank methodology before delegating, and
:func:`render_scale_claim` is the only path to a renderable
:class:`~mayhem.domain.budgets.ScaleClaimView`, so "authorable unmeasured,
not renderable" stays true end to end.
"""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from math import isfinite
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from mayhem.domain.budgets import (
    RULE_ESTIMATE_EXCEEDED,
    RULE_LIMIT_EXCEEDED,
    BudgetComparison,
    BudgetConsumption,
    ConsumptionSample,
    ResourceBudget,
    ResourceDimension,
    ResourceEstimate,
    ResourceScope,
    ResourceSeries,
    compare_estimate,
    unit_for,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import sha256_hex
from mayhem.infra.secret_resolver import require_clean_artifact, require_persistable_document

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Sequence
    from typing import Any

    from mayhem.domain.budgets import (
        BenchmarkSpec,
        Measurement,
        PublishedBenchmark,
        ScaleClaim,
        ScaleClaimView,
    )

__all__ = [
    "CONTINUITY_PAUSE",
    "EVIDENCE_BYTES",
    "MEMORY_RESIDENT_SEAM",
    "NEGATIVE_CONTROL_RULES",
    "NETWORK_EGRESS_SEAM",
    "RULE_BUDGET_NOT_GOVERNED",
    "RULE_ESTIMATE_UNMEASURED",
    "RULE_METER_CONTRACT",
    "RULE_METER_SINK_FAILED",
    "RULE_METHODOLOGY_REQUIRED",
    "RULE_RECORD_NOT_BOUND",
    "STORE_GROWTH_BYTES",
    "TARGET_COUNT_SEAM",
    "AdmissionDecision",
    "BenchmarkEvidence",
    "BudgetAdmissionRefused",
    "ContinuityDecision",
    "MeterContractError",
    "MeterReading",
    "MeterSeriesEvidence",
    "MeterSink",
    "PauseForReview",
    "ResourceBudgetEnforcer",
    "RunMeter",
    "admission_check",
    "build_run_meter",
    "continuity_check",
    "now_utc",
    "publish_benchmark",
    "render_scale_claim",
    "seal_benchmark_record",
    "seal_meter_series",
    "strict_reading",
]

# -- rule ids ------------------------------------------------------------------
# Disjoint from every rule id in domain/budgets.py, domain/quota.py, and
# domain/policy.py. An evidence record naming ``meter.*`` is unambiguously about
# metering; one naming ``budget.limit_exceeded`` is unambiguously about a
# *resource* budget rather than a damage budget.

RULE_METER_SINK_FAILED = "meter.sink_failed"
RULE_METER_CONTRACT = "meter.contract_violation"
RULE_ESTIMATE_UNMEASURED = "meter.estimate_unmeasured"
RULE_BUDGET_NOT_GOVERNED = "meter.budget_not_governed"
RULE_METHODOLOGY_REQUIRED = "benchmark.methodology_required"
RULE_RECORD_NOT_BOUND = "benchmark.record_not_bound"

CONTINUITY_PAUSE = "budget.continuity_pause"
"""The action a pause carries: the run stops being authorized to continue."""

EVIDENCE_BYTES = "evidence_bytes"
STORE_GROWTH_BYTES = "store_growth_bytes"

MEMORY_RESIDENT_SEAM = "memory_resident"
"""The seam the MEMORY dimension reads: an integrated resident-set reading.

Added in Phase 3. The dimension is declared in ``mebibyte_seconds``, so the seam
integrates a resident set over elapsed time rather than reporting an
instantaneous size; see :meth:`RunMeter.sample_memory`.
"""

NETWORK_EGRESS_SEAM = "network_egress"
"""The seam the NETWORK dimension reads: bytes a call site already knows it moved.

Added in Phase 3, and deliberately *declared* rather than intercepted — see
:data:`mayhem.infra.budget_enforcement.DIMENSION_LEDGER`.
"""

TARGET_COUNT_SEAM = "targets"
"""The seam the TARGET_COUNT dimension reads: a whole-number target counter."""

NEGATIVE_CONTROL_RULES: dict[str, str] = {
    "negative_limit": "budget.negative_limit",
    "non_monotonic_series": "budget.consumption_not_monotonic",
    "no_methodology": RULE_METHODOLOGY_REQUIRED,
    "unmeasured_render": "scale.unmeasured_claim",
    "sink_failure": RULE_METER_SINK_FAILED,
}
"""The five negative controls Phase 2 must demonstrate, as data.

Kept here so the tests assert the *rule ids* rather than re-typing strings, and
so a reviewer can see at a glance which refusals this module is claiming. Four
are enforced by :mod:`mayhem.domain.budgets` and exercised here through it;
``sink_failure`` is enforced here.
"""


class MeterContractError(InvariantViolationError):
    """A meter reading violated its own contract.

    Raised only by :func:`strict_reading` and by the counter seams on a
    negative or fractional count. Deliberately *not* raised on the failure path
    of a sink, and never from inside a timing context manager's ``finally``: a
    harness asking for a number it will publish wants the raise, and a control
    plane asking for a number it will merely report does not.
    """

    def __init__(self, message: str) -> None:
        super().__init__(RULE_METER_CONTRACT, message)


# -- readings ------------------------------------------------------------------


@runtime_checkable
class MeterSink(Protocol):
    """Where a reading goes. The smallest surface that is still useful.

    A sink may raise. Every call into it from :class:`RunMeter` is guarded, and a
    raise is recorded in :attr:`RunMeter.failures` — never propagated — so a slow
    or broken exporter cannot take a run down with it.
    """

    def record(self, reading: MeterReading) -> None:
        """Accept one reading. May raise; the meter will not notice."""


@dataclass(frozen=True, slots=True)
class MeterReading:
    """One measured fact at one seam, in the unit that seam is counted in.

    A ``cumulative`` reading carries the running total for the run, so the last
    one wins and the series is monotonic by construction; a ``delta`` reading
    carries this event's increment alone. :attr:`kind` says which, so a consumer
    summing deltas does not accidentally sum a running total and report a
    quadratic.
    """

    seam: str
    kind: str
    value: float
    unit: str
    run_id: str = ""
    at: datetime | None = None
    note: str = ""

    def __post_init__(self) -> None:
        if not self.seam.strip():
            msg = "meter reading names no seam"
            raise InvariantViolationError(RULE_METER_CONTRACT, msg)
        if not self.unit.strip():
            msg = f"meter reading on seam {self.seam!r} names no unit"
            raise InvariantViolationError(RULE_METER_CONTRACT, msg)
        if self.at is not None and (
            self.at.tzinfo is None or self.at.tzinfo.utcoffset(self.at) is None
        ):
            msg = f"meter reading timestamp must be timezone-aware, got naive {self.at!r}"
            raise InvariantViolationError(RULE_METER_CONTRACT, msg)

    @property
    def is_cumulative(self) -> bool:
        """True when :attr:`value` is this run's running total, not an increment."""
        return self.kind == "cumulative"

    def describe(self) -> str:
        stamp = f" at {self.at.isoformat()}" if self.at is not None else ""
        return f"{self.seam}[{self.kind}]={self.value:g} {self.unit}{stamp}"


# -- decisions -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """The pre-execution verdict: may this run start at all?

    ``estimates_compared`` is the number of (budget, estimate) pairs actually
    checked, so a caller can tell "admitted because nothing breached" from
    "admitted because no estimate applied to any governed budget" — the second
    is a policy gap wearing the same face as the first, and saying so is the
    whole value of the count.
    """

    refused: bool
    estimates_compared: int = 0
    consumption: BudgetConsumption | None = None
    rule_id: str = ""
    reason: str = ""
    remediation: str = ""

    @property
    def allowed(self) -> bool:
        return not self.refused

    def inputs(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "refused": self.refused,
            "estimates_compared": self.estimates_compared,
        }
        if self.consumption is not None:
            payload.update(self.consumption.inputs())
        return payload

    def describe(self) -> str:
        return self.reason or ("admitted" if self.allowed else "refused")


@dataclass(frozen=True, slots=True)
class ContinuityDecision:
    """The mid-execution verdict for one reading.

    ``paused`` means the caller must stop the run and surface
    :class:`PauseForReview`. ``exhausted`` preserves the domain's own
    distinction — exactly at the limit is *spent*, not *over* — rather than
    collapsing it into "breached".
    """

    paused: bool
    exhausted: bool = False
    consumption: BudgetConsumption | None = None
    rule_id: str = ""
    reason: str = ""
    remediation: str = ""

    @property
    def continue_running(self) -> bool:
        return not self.paused

    def inputs(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "paused": self.paused,
            "exhausted": self.exhausted,
        }
        if self.consumption is not None:
            payload.update(self.consumption.inputs())
        return payload

    def describe(self) -> str:
        return self.reason or ("continue" if not self.paused else "paused")


class PauseForReview(Exception):  # noqa: N818 — a pause is not an error, it is a state
    """A mid-execution breach: the run is no longer authorized to continue.

    Not a :class:`~mayhem.domain.errors.DomainError`, because it is not a
    decision about whether the run may *start* — it is the loss of that
    authorization partway through. Keeping the two apart is what stops
    "admitted" from quietly meaning "admitted to finish".

    Attributes:
        consumption: The reading that breached, carrying the dimension, the
            measured number, the limit, and the overage.
        seam: Which instrumented seam observed it.
    """

    def __init__(self, consumption: BudgetConsumption, *, seam: str = "") -> None:
        self.consumption = consumption
        self.seam = seam
        super().__init__(consumption.reason)

    @property
    def dimension(self) -> ResourceDimension:
        return self.consumption.dimension

    def inputs(self) -> dict[str, object]:
        return {"seam": self.seam, **self.consumption.inputs()}


class BudgetAdmissionRefused(InvariantViolationError):  # noqa: N818 — public API
    """A run was refused at admission for exceeding a resource budget.

    Subclasses :class:`~mayhem.domain.errors.InvariantViolationError` so it
    travels through the same evidence path as every other refusal, and carries
    the whole :class:`AdmissionDecision` for a caller that wants the numbers
    rather than the prose.
    """

    def __init__(self, decision: AdmissionDecision) -> None:
        self.decision = decision
        super().__init__(decision.rule_id or RULE_ESTIMATE_EXCEEDED, decision.reason)


# -- checks --------------------------------------------------------------------


def _same_subject(left: ResourceEstimate, right: ResourceBudget) -> bool:
    return (
        left.dimension is right.dimension
        and left.scope is right.scope
        and left.scope_key == right.scope_key
    )


def admission_check(
    *,
    budgets: Sequence[ResourceBudget],
    estimates: Sequence[ResourceEstimate],
    scope: ResourceScope,
    now: datetime,
    anchor: datetime,
) -> AdmissionDecision:
    """Judge a pre-execution estimate set against the budgets that govern ``scope``.

    Two things are checked, and both matter:

    1. **Estimate against limit.** Every budget that ``governs(scope)`` is paired
       with the estimate naming the same subject, and the estimate's ``expected``
       is measured against the limit over the window containing ``now``. A run
       that *would* go over is refused here: catching it after the first thousand
       targets were touched is not a refusal, it is a bill.
    2. **Governance.** An estimate no budget governs is *reported* rather than
       refused (``rule_id`` = :data:`RULE_BUDGET_NOT_GOVERNED`). Inventing a
       limit for an unbudgeted dimension is a policy decision this function must
       not make on its own; silently accepting one would make an unmetered run
       look like a governed one, which is the confusion plan 23 exists to remove.

    The refusal text is the domain's :attr:`BudgetConsumption.reason`, so it
    names the breaching dimension, the measured number, the limit, and the
    overage in the same wording every other budget refusal uses.
    """
    governed = tuple(budget for budget in budgets if budget.governs(scope))
    compared = 0
    for budget in governed:
        for estimate in (e for e in estimates if _same_subject(e, budget)):
            compared += 1
            window = budget.window_for(now, anchor=anchor)
            consumption = budget.measure(estimate.expected, window)
            if consumption.exceeded:
                return AdmissionDecision(
                    refused=True,
                    estimates_compared=compared,
                    consumption=consumption,
                    rule_id=RULE_ESTIMATE_EXCEEDED,
                    reason=consumption.reason,
                    remediation=consumption.remediation,
                )
    ungoverned = sorted(
        f"{e.dimension.value}/{e.scope.value}/{e.scope_key}"
        for e in estimates
        if not any(_same_subject(e, budget) for budget in governed)
    )
    if ungoverned:
        detail = ", ".join(ungoverned)
        return AdmissionDecision(
            refused=False,
            estimates_compared=compared,
            rule_id=RULE_BUDGET_NOT_GOVERNED,
            reason=(
                f"no resource budget governs {detail}; the run is admitted but its "
                f"consumption is ungoverned [{RULE_BUDGET_NOT_GOVERNED}]"
            ),
            remediation=(
                f"author a ResourceBudget for {detail} so the estimate is checked "
                "against a limit rather than ignored"
            ),
        )
    return AdmissionDecision(
        refused=False,
        estimates_compared=compared,
        reason=f"admission: {compared} resource estimate(s) within budget",
    )


def continuity_check(
    *,
    budget: ResourceBudget,
    series: ResourceSeries,
    now: datetime,
    anchor: datetime,
) -> ContinuityDecision:
    """Judge one cumulative reading against its budget, continuously.

    The window is the one containing ``now`` on the grid anchored at ``anchor``,
    so the reading is charged to exactly one window even if the caller re-checks
    at a boundary. The half-open rule lives in :mod:`mayhem.domain.budgets` and
    is not reimplemented here.

    A reading *at* the limit returns ``paused=False, exhausted=True``: a budget
    may be used up exactly, which is the domain's distinction and is preserved
    rather than folded into "over".
    """
    window = budget.window_for(now, anchor=anchor)
    consumption = series.consumption(window)
    if consumption.exceeded:
        return ContinuityDecision(
            paused=True,
            exhausted=True,
            consumption=consumption,
            rule_id=RULE_LIMIT_EXCEEDED,
            reason=consumption.reason,
            remediation=consumption.remediation,
        )
    if consumption.exhausted:
        return ContinuityDecision(
            paused=False,
            exhausted=True,
            consumption=consumption,
            reason=(
                f"{consumption.dimension.value} budget exactly spent: "
                f"{consumption.measured:g}/{consumption.limit:g} {consumption.unit}"
            ),
        )
    return ContinuityDecision(paused=False, consumption=consumption)


def strict_reading(reading: MeterReading, *, expect_kind: str = "") -> MeterReading:
    """Return ``reading``, or raise :class:`MeterContractError`.

    The opt-in strict accessor, for a call site about to publish a number. An
    instrumented seam never calls this — it records instead — so a benchmark
    harness that promised a cumulative reading and received a delta hears about
    it, while a control plane that merely reports keeps going.
    """
    if reading.value < 0.0 or not isfinite(reading.value):
        msg = f"meter reading on seam {reading.seam!r} carries {reading.value!r}"
        raise MeterContractError(msg)
    if expect_kind and reading.kind != expect_kind:
        msg = (
            f"meter reading on seam {reading.seam!r} is a {reading.kind!r} reading, "
            f"not the {expect_kind!r} one this call site promised"
        )
        raise MeterContractError(msg)
    return reading


def _reject_bad_count(n_bytes: float, *, subject: str) -> None:
    """Refuse a negative, NaN, or infinite count before it reaches a reading.

    ``isfinite`` rather than ``x != x``: the NaN test is a truthiness trick that
    reads as a typo to the next person, and the rule the domain already applies
    to every resource measurement is worth applying here by name.
    """
    if n_bytes < 0.0 or not isfinite(n_bytes):
        msg = f"{subject} must be a finite non-negative number, got {n_bytes!r}"
        raise InvariantViolationError(RULE_METER_CONTRACT, msg)


def _require_whole_count(n_items: int, *, subject: str) -> None:
    """Refuse a count that is not a non-negative whole number.

    ``bool`` is excluded explicitly because ``isinstance(True, int)`` is true in
    Python: a ``count_api_calls(True)`` that silently charged one call would be a
    bug that reads as a passing test.
    """
    if isinstance(n_items, bool) or not isinstance(n_items, int) or n_items < 0:
        msg = f"{subject} must be a non-negative whole number, got {n_items!r}"
        raise InvariantViolationError(RULE_METER_CONTRACT, msg)


# -- publication gate ----------------------------------------------------------


def publish_benchmark(
    spec: BenchmarkSpec,
    measurements: Iterable[Measurement],
    *,
    now: datetime,
) -> PublishedBenchmark:
    """Publish a benchmark only with its methodology attached and its outputs reported.

    Two gates, in this order, because the second is meaningless without the
    first: :meth:`BenchmarkSpec.publish` refuses a spec that declares no measured
    outputs or whose promised outputs never arrived, and this refuses a spec that
    says nothing about *how* it measured. A number with no methodology attached
    is the failure mode plan 23 Phase 5 names, and it is cheaper to refuse at
    publish time than to un-publish afterwards.

    Raises:
        InvariantViolationError: With :data:`RULE_METHODOLOGY_REQUIRED` when the
            spec's methodology is blank, or whatever rule id the domain's
            ``publish`` raises when the declared outputs do not arrive.
    """
    if not spec.methodology.strip():
        msg = (
            f"benchmark spec {spec.spec_id} declares no methodology; a published "
            "number without the method that produced it is not publishable"
        )
        raise InvariantViolationError(RULE_METHODOLOGY_REQUIRED, msg)
    return spec.publish(measurements, now=now)


def render_scale_claim(claim: ScaleClaim) -> ScaleClaimView:
    """The only path from a scale claim to a renderable claim view.

    A thin, deliberate delegation to :meth:`ScaleClaim.render`, which refuses an
    unmeasured claim. Exposing it here means the "authorable unmeasured, not
    renderable" property has exactly one door, and Phase 3's dashboard reads
    through that door rather than reaching into the claim itself.
    """
    return claim.render()


# -- the evidence boundary (Phase 4) -------------------------------------------


def _canonical(document: Any) -> str:
    """A stable serialisation, so a record's digest covers exactly its content."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True, slots=True)
class BenchmarkEvidence:
    """A published benchmark cleared for persistence and bound to its spec.

    Two things make this *evidence* rather than a number somebody wrote down.
    First, ``record_digest`` is a sha256 over the canonical record, so a reader
    can tell whether the artifact they are looking at is the one that was
    cleared. Second, ``spec_digest`` is carried forward from the spec that
    produced it, so a published number names the spec that generated it — which
    is what makes two releases comparable at all (plan 22 owns the comparison).
    """

    spec_id: str
    spec_digest: str
    metric: str
    scale: str
    methodology: str
    published_at: datetime
    measurements: tuple[Measurement, ...]
    record_digest: str

    def describe(self) -> str:
        return (
            f"{self.spec_id} @ {self.scale} — {self.metric}, "
            f"{len(self.measurements)} measurement(s), record {self.record_digest[:12]}"
        )


@dataclass(frozen=True, slots=True)
class MeterSeriesEvidence:
    """A run's metering readings cleared for persistence, in one digest."""

    scope_key: str
    readings: tuple[MeterReading, ...]
    record_digest: str
    dropped: tuple[str, ...] = ()

    def describe(self) -> str:
        return (
            f"{self.scope_key} — {len(self.readings)} reading(s), record {self.record_digest[:12]}"
        )


def _require_bound_digest(document: dict[str, Any], *, artifact: str) -> str:
    """Run both boundary gates over a record and return its canonical digest.

    The order is the one plan 29 Phase 4 established: the *grade* rule first (a
    field classified ``secret`` may not be persisted here at all), then the
    *byte* rule (a resolved credential's bytes may not be present even under a
    field name nobody graded). Running them in the other order would let a
    properly-named secret field past whenever no guard happened to be active.
    """
    require_persistable_document(document, artifact=artifact)
    payload = _canonical(document)
    require_clean_artifact(payload, artifact=artifact)
    return sha256_hex(payload)


def seal_benchmark_record(
    benchmark: PublishedBenchmark,
    *,
    spec: BenchmarkSpec,
) -> BenchmarkEvidence:
    """Clear a published benchmark for persistence and bind it to its spec.

    This is the Phase 4 write path for benchmarks: the only way a published
    number becomes a stored artifact. It is deliberately *not* an
    :class:`~mayhem.infra.evidence.EvidenceEnvelope` — a benchmark is not a run,
    has no plan, no blast radius and no verdict, and forcing it into that shape
    would have it assert fields it does not have. What it gets instead is the
    two gates every evidence write path in this codebase gets, plus a digest.

    ``spec`` is a required argument rather than an optional convenience. A
    published benchmark *claims* a ``spec_digest``; comparing that claim against
    the spec it was supposedly produced from is the only way to catch a record
    bound to the wrong spec, and a check that compares the claim with itself
    cannot fail and is not a check.

    Raises:
        InvariantViolationError: With :data:`RULE_RECORD_NOT_BOUND` when the
            benchmark's ``spec_digest`` is not the one ``spec`` computes; or from
            the boundary gates — a field graded ``secret``, or a resolved
            credential's bytes, anywhere in the record. Nothing is written and no
            digest is returned.
    """
    expected = spec.compute_digest()
    if benchmark.spec_digest != expected:
        msg = (
            f"benchmark {benchmark.spec_id} claims spec digest "
            f"{benchmark.spec_digest!r}, but the spec it was produced from "
            f"computes {expected!r}; a record bound to the wrong spec cannot be "
            "compared across releases, which is the only reason to seal one"
        )
        raise InvariantViolationError(RULE_RECORD_NOT_BOUND, msg)
    document = benchmark.model_dump(mode="json")
    digest = _require_bound_digest(document, artifact="benchmark_record")
    return BenchmarkEvidence(
        spec_id=benchmark.spec_id,
        spec_digest=benchmark.spec_digest,
        metric=benchmark.metric,
        scale=benchmark.scale.describe(),
        methodology=benchmark.methodology,
        published_at=benchmark.published_at,
        measurements=tuple(benchmark.measurements),
        record_digest=digest,
    )


def seal_meter_series(
    readings: Iterable[MeterReading],
    *,
    scope_key: str,
) -> MeterSeriesEvidence:
    """Clear a run's metering series for persistence and digest it as one record.

    ``scope_key`` is required rather than optional: a metering ledger with no
    scope cannot be attributed to anything, and an unattributable cost number is
    the one thing a resource budget must not be built on.
    """
    if not scope_key.strip():
        msg = (
            "a meter series must name the scope it belongs to; an unattributed "
            "cost number is not evidence"
        )
        raise InvariantViolationError(RULE_METER_CONTRACT, msg)
    collected = tuple(readings)
    document = {
        "scope_key": scope_key,
        "readings": [
            {
                "seam": reading.seam,
                "unit": reading.unit,
                "value": reading.value,
                "kind": reading.kind,
                "run_id": reading.run_id,
                "at": reading.at.isoformat() if reading.at is not None else None,
                "note": reading.note,
            }
            for reading in collected
        ],
    }
    digest = _require_bound_digest(document, artifact="meter_series")
    return MeterSeriesEvidence(scope_key=scope_key, readings=collected, record_digest=digest)


# -- the meter -----------------------------------------------------------------


@dataclass
class RunMeter:
    """The per-run meter: six instrumented seams and one sink per reading.

    Cheap by construction. Every seam is a context manager or a numeric add; the
    only allocation per reading is one frozen :class:`MeterReading` and, if a
    sink is configured, one guarded call. No IO happens here — persisting
    readings is the caller's and Phase 3's problem, deliberately, because a meter
    that wrote to the store would make its own growth part of the growth it
    reports.

    Non-blocking by construction. ``clock`` defaults to
    :func:`time.perf_counter`, which is monotonic and cheap; a caller that wants
    reproducibility injects a fixed sequence instead.

    Failure-transparent by construction. Every sink call is wrapped: a sink that
    raises loses exactly one reading, appends to :attr:`failures`, and the
    instrumented code proceeds untouched.
    """

    run_id: str = ""
    clock: Callable[[], float] = time.perf_counter
    sink: MeterSink | None = None
    timings: dict[str, float] = field(default_factory=dict)
    """Cumulative seconds per seam, keyed by seam name."""
    totals: dict[str, float] = field(default_factory=dict)
    """Cumulative counts and bytes per seam, keyed by seam name."""
    readings: list[MeterReading] = field(default_factory=list)
    failures: list[tuple[str, str]] = field(default_factory=list)
    """Every swallowed sink failure as ``(seam, detail)``, in order."""
    _plan_compilations: list[float] = field(default_factory=list)
    _discoveries: list[float] = field(default_factory=list)
    _policy_evaluations: list[float] = field(default_factory=list)
    _commands: dict[str, list[float]] = field(default_factory=dict)
    # -- Phase 3 state: the four dimensions Phase 2 left budgeted but unmetered.
    # ``_resident_mib``/``_resident_at``/``_resident_seen`` integrate the resident
    # set over the injected clock into mebibyte_seconds; the rest are plain
    # cumulative counters. All default, so a Phase 2 construction is unaffected.
    _resident_mib: float = 0.0
    _resident_at: float = 0.0
    _resident_seen: bool = False
    _resident_samples: int = 0

    # -- internals ------------------------------------------------------------
    def _emit(
        self,
        *,
        seam: str,
        kind: str,
        value: float,
        unit: str,
        now: datetime | None = None,
        note: str = "",
    ) -> MeterReading:
        """Build a reading, keep it, hand it to the sink, and never raise.

        The guard covers the sink only. A malformed reading is a bug in the
        *call site*, and swallowing it would turn a bug into silence — so it is
        refused by :class:`MeterReading` itself, before this method is entered.
        """
        reading = MeterReading(
            seam=seam,
            kind=kind,
            value=value,
            unit=unit,
            run_id=self.run_id,
            at=now,
            note=note,
        )
        self.readings.append(reading)
        if self.sink is not None:
            try:
                self.sink.record(reading)
            except Exception as exc:  # a broken sink must not stop a run
                self.failures.append((seam, f"{type(exc).__name__}: {exc}"))
        return reading

    def _record_timing(
        self,
        *,
        seam: str,
        log: list[float],
        timings_key: str,
        start: float,
        now: datetime | None,
    ) -> float:
        """Read the clock, record one elapsed duration, and return it.

        The shared tail of the four timing seams. Two decisions live here:

        * ``finally`` at every call site, so a block that raises is still timed.
          A failed plan compilation that reported zero latency would read as
          "instant" on a dashboard, which is a false claim rather than a missing
          one — and a plan that always fails would look infinitely fast.
        * ``max(0.0, ...)``, so a clock that went backwards (an injected test
          clock, a platform quirk) yields ``0.0`` rather than a negative duration
          that would poison every mean downstream.

        ``start`` is passed in rather than stashed on ``self`` so nesting two
        timing seams — a discovery inside a compilation, which is exactly what
        the controller does — cannot have the inner seam's start clobber the
        outer seam's.
        """
        elapsed = max(0.0, self.clock() - start)
        log.append(elapsed)
        self.timings[timings_key] = self.timings.get(timings_key, 0.0) + elapsed
        self._emit(seam=seam, kind="delta", value=elapsed, unit="seconds", now=now)
        return elapsed

    # -- seam 1: plan compilation --------------------------------------------
    @contextmanager
    def time_plan_compilation(self, *, now: datetime | None = None) -> Iterator[None]:
        """Time one plan compilation, in seconds.

        The seam is :func:`mayhem.controller.planner.plan_drill`. This module
        does not call it: a context manager cannot own a call whose signature it
        does not control, and wrapping the *callee* rather than the caller is
        what keeps the seam optional — a call site that does not time compilation
        simply has no reading for it, which is honest, whereas a wrapper that
        guessed at arguments would be a second planner.
        """
        start = self.clock()
        try:
            yield
        finally:
            self._record_timing(
                seam="plan_compilation",
                log=self._plan_compilations,
                timings_key="plan_compilation_s",
                start=start,
                now=now,
            )

    # -- seam 2: topology discovery ------------------------------------------
    @contextmanager
    def time_discovery(self, *, now: datetime | None = None) -> Iterator[None]:
        """Time one topology-discovery pass, in seconds.

        The seam is ``mayhem.topology.service.TopologyService.discover``, which
        fans out across providers and is therefore the latency a controller waits
        on before it can plan anything.
        """
        start = self.clock()
        try:
            yield
        finally:
            self._record_timing(
                seam="discovery",
                log=self._discoveries,
                timings_key="discovery_s",
                start=start,
                now=now,
            )

    # -- seam 3: policy evaluation -------------------------------------------
    @contextmanager
    def time_policy_evaluation(self, *, now: datetime | None = None) -> Iterator[None]:
        """Time one policy-bundle evaluation, in seconds.

        The seam is :func:`mayhem.domain.policy.evaluate_bundle`, which runs per
        fault step and is therefore multiplied by plan length — the reason it
        gets its own seam rather than being folded into compilation.
        """
        start = self.clock()
        try:
            yield
        finally:
            self._record_timing(
                seam="policy_evaluation",
                log=self._policy_evaluations,
                timings_key="policy_evaluation_s",
                start=start,
                now=now,
            )

    # -- seam 4: per-command agent latency -----------------------------------
    @contextmanager
    def time_agent_command(self, command: str, *, now: datetime | None = None) -> Iterator[None]:
        """Time one agent command over the fabric protocol, in seconds.

        Keyed by ``command`` so the reading is *per-command* rather than one
        blended average across every method: an average over a 30-second
        ``sleep`` and a 2-millisecond ``ping`` describes neither, and plan 23
        asks for agent command latency as a per-command fact.
        """
        start = self.clock()
        try:
            yield
        finally:
            self._record_timing(
                seam=f"agent_command:{command}",
                log=self._commands.setdefault(command, []),
                timings_key=f"agent_command:{command}",
                start=start,
                now=now,
            )

    # -- seam 5: evidence bytes per run --------------------------------------
    def add_evidence_bytes(self, n_bytes: float, *, now: datetime | None = None) -> MeterReading:
        """Record ``n_bytes`` of evidence written this run; returns the running total.

        A delta on its face and a cumulative reading in substance: the emitted
        reading carries the total evidence bytes this run has produced, which is
        what a benchmark's evidence-throughput output wants *and* what a storage
        budget must be charged against (budgets are cumulative; see
        :class:`~mayhem.domain.budgets.ResourceSeries`).
        """
        _reject_bad_count(n_bytes, subject="evidence byte count")
        running = self.totals.get(EVIDENCE_BYTES, 0.0) + n_bytes
        self.totals[EVIDENCE_BYTES] = running
        return self._emit(
            seam="evidence",
            kind="cumulative",
            value=running,
            unit="bytes",
            now=now,
        )

    # -- seam 6: store growth per run ----------------------------------------
    def add_store_growth_bytes(
        self, n_bytes: float, *, now: datetime | None = None
    ) -> MeterReading:
        """Record ``n_bytes`` this run grew the store by; returns the running total.

        The ``database_growth`` metric's seam. Kept distinct from
        :meth:`add_evidence_bytes` because the two answer different questions:
        evidence is what the run *produced*, store growth is what it *left
        behind* (indexes, WAL, replication lag), and the second is routinely
        larger than the first.
        """
        _reject_bad_count(n_bytes, subject="store growth")
        running = self.totals.get(STORE_GROWTH_BYTES, 0.0) + n_bytes
        self.totals[STORE_GROWTH_BYTES] = running
        return self._emit(
            seam="store_growth",
            kind="cumulative",
            value=running,
            unit="bytes",
            now=now,
        )

    def count_api_calls(self, n_calls: int = 1, *, now: datetime | None = None) -> MeterReading:
        """Record ``n_calls`` API calls; returns the running total.

        The ``api_calls`` dimension's meter, and the one gap-68 dimension that is
        indivisible — so this takes an ``int`` and refuses a negative or
        fractional count outright rather than rounding a number the caller never
        wrote.
        """
        _require_whole_count(n_calls, subject="api call count")
        running = self.totals.get("api_calls", 0.0) + float(n_calls)
        self.totals["api_calls"] = running
        return self._emit(
            seam="api_calls",
            kind="cumulative",
            value=running,
            unit=unit_for(ResourceDimension.API_CALLS),
            now=now,
        )

    # -- Phase 3 seams: the four dimensions Phase 2 left unmetered -----------
    def sample_memory(self, rss_mib: float, *, now: datetime | None = None) -> MeterReading:
        """Record a resident-set reading; returns the running mebibyte_seconds integral.

        The ``memory`` dimension's meter, and the only *derived* one: the
        dimension is declared in ``mebibyte_seconds``, which is a size integrated
        over time, so a single instantaneous RSS number is not a reading of it.
        Each sample closes the interval since the previous one at the *previous*
        sample's resident size (the left rectangle rule — an honest upper bound,
        since a page resident but untouched still counts for the interval).

        The interval comes from the injected ``clock``, never from ``now``: an
        elapsed duration is a measurement, not a timestamp, and the two would
        disagree the moment a clock were adjusted mid-run. ``max(0.0, ...)``
        because a clock that went backwards yields zero elapsed rather than a
        negative integral that would poison every total downstream.

        The first sample establishes the baseline and contributes nothing, so it
        legitimately reads ``0.0`` — there is no interval to integrate yet, and a
        caller that samples once and never again gets a memory reading that stays
        at zero, which is why
        :meth:`mayhem.infra.budget_enforcement.RunBudgetGuard.read` refuses to
        report *no* reading as zero rather than the reverse.
        """
        _reject_bad_count(rss_mib, subject="resident set size in mebibytes")
        tick = self.clock()
        accumulated = 0.0
        if self._resident_seen:
            accumulated = self._resident_mib * max(0.0, tick - self._resident_at)
        else:
            self._resident_seen = True
        self._resident_at = tick
        self._resident_mib = rss_mib
        self._resident_samples += 1
        running = self.totals.get(MEMORY_RESIDENT_SEAM, 0.0) + accumulated
        self.totals[MEMORY_RESIDENT_SEAM] = running
        return self._emit(
            seam=MEMORY_RESIDENT_SEAM,
            kind="cumulative",
            value=running,
            unit=unit_for(ResourceDimension.MEMORY),
            now=now,
            note=f"resident={rss_mib:g}MiB sample={self._resident_samples}",
        )

    def add_network_bytes(self, n_bytes: float, *, now: datetime | None = None) -> MeterReading:
        """Record ``n_bytes`` of egress this call site knows it moved.

        The ``network`` dimension's meter, and the deliberately *declared* one.
        Total egress is kernel-accounted and has no portable userspace read, so
        the only honest counter is one fed by the code that already knows the
        size: a payload it sent, a response body it received. Anything not
        reported here is not zero — it is unmeasured, and
        :data:`mayhem.infra.budget_enforcement.DIMENSION_LEDGER` says so.
        """
        _reject_bad_count(n_bytes, subject="network egress byte count")
        running = self.totals.get(NETWORK_EGRESS_SEAM, 0.0) + n_bytes
        self.totals[NETWORK_EGRESS_SEAM] = running
        return self._emit(
            seam=NETWORK_EGRESS_SEAM,
            kind="cumulative",
            value=running,
            unit=unit_for(ResourceDimension.NETWORK),
            now=now,
        )

    def add_targets(self, n_targets: int = 1, *, now: datetime | None = None) -> MeterReading:
        """Record ``n_targets`` targets touched; returns the running total.

        The ``target_count`` dimension's meter. Counted as the run *touches*
        targets rather than as the plan intends to, because a target-count budget
        exists to bound the blast radius actually reached — a plan that names ten
        targets and reaches three has consumed three.

        Indivisible like :meth:`count_api_calls`, and refused on the same terms.
        """
        _require_whole_count(n_targets, subject="target count")
        running = self.totals.get(TARGET_COUNT_SEAM, 0.0) + float(n_targets)
        self.totals[TARGET_COUNT_SEAM] = running
        return self._emit(
            seam=TARGET_COUNT_SEAM,
            kind="cumulative",
            value=running,
            unit=unit_for(ResourceDimension.TARGET_COUNT),
            now=now,
        )

    # -- reads ----------------------------------------------------------------
    @property
    def total_evidence_bytes(self) -> float:
        return self.totals.get(EVIDENCE_BYTES, 0.0)

    @property
    def total_store_growth_bytes(self) -> float:
        return self.totals.get(STORE_GROWTH_BYTES, 0.0)

    @property
    def total_api_calls(self) -> float:
        return self.totals.get("api_calls", 0.0)

    @property
    def total_network_bytes(self) -> float:
        """Declared egress bytes this run reported; unmeasured elsewhere, not zero."""
        return self.totals.get(NETWORK_EGRESS_SEAM, 0.0)

    @property
    def total_targets(self) -> float:
        """Targets touched so far this run."""
        return self.totals.get(TARGET_COUNT_SEAM, 0.0)

    @property
    def memory_resident_mib_seconds(self) -> float:
        """The resident-set integral so far, in mebibyte_seconds."""
        return self.totals.get(MEMORY_RESIDENT_SEAM, 0.0)

    @property
    def memory_sample_count(self) -> int:
        """How many resident-set samples have been taken.

        ``1`` means the baseline was established and no interval has closed yet —
        which is why the integral is ``0.0`` and why a caller must not read that
        as "this run used no memory".
        """
        return self._resident_samples

    @property
    def plan_compilation_latencies(self) -> tuple[float, ...]:
        return tuple(self._plan_compilations)

    @property
    def discovery_latencies(self) -> tuple[float, ...]:
        return tuple(self._discoveries)

    @property
    def policy_evaluation_latencies(self) -> tuple[float, ...]:
        return tuple(self._policy_evaluations)

    def agent_command_latency(self, command: str) -> tuple[float, ...]:
        """Every recorded latency for one command, in observation order."""
        return tuple(self._commands.get(command, ()))

    def readings_for(self, seam: str) -> tuple[MeterReading, ...]:
        """Every reading taken at ``seam``, in order."""
        return tuple(reading for reading in self.readings if reading.seam == seam)

    def latency_means(self) -> dict[str, float]:
        """Mean latency per seam, keyed the same way :attr:`timings` is.

        The shape Phase 3's benchmark report consumes. A mean rather than a
        percentile because the percentiles are a reporting decision the
        :class:`~mayhem.domain.budgets.BenchmarkSpec` declares, not something
        this meter should pick on its own.
        """
        report: dict[str, float] = {}
        for seam, samples in (
            ("plan_compilation", self._plan_compilations),
            ("discovery", self._discoveries),
            ("policy_evaluation", self._policy_evaluations),
        ):
            if samples:
                report[f"{seam}_s"] = sum(samples) / len(samples)
        for command, samples in self._commands.items():
            report[f"agent_command:{command}_s"] = sum(samples) / len(samples)
        return dict(sorted(report.items()))


# -- the enforcer object --------------------------------------------------------


class ResourceBudgetEnforcer:
    """Binds one run's budgets to one run's meter, and refuses or pauses.

    This is the surface Phase 3/4 wires, and the integration point is two calls
    in the run lifecycle. **Neither of them is inside ``safety.py``**, which this
    lane does not touch:

    1. **Admission** — before the executor opens a run, beside the existing
       ``validate_plan`` call. Call :meth:`admit` with the plan's estimates; it
       raises :class:`BudgetAdmissionRefused` when the plan would breach and
       returns the decision otherwise. The owner is the controller's execution
       entry point (``cli/execution.py`` constructs the run; the executor
       validates the plan), because that is the last moment at which a refusal
       still prevents *all* mutation rather than merely some.
    2. **Continuity** — inside the fault loop, right after each step's meter
       reading is posted. Call :meth:`observe`; it raises :class:`PauseForReview`
       on a breach. The owner is the executor's per-step hook, next to where
       ``check_blast_radius`` is consulted, so a pause is raised in the same place
       a damage refusal would be and a caller already catching one sees the shape.

    The constraint that shapes both: **this module never imports
    ``controller.safety``, and ``safety.py`` never imports this module.** A
    resource budget is a different dimension set from a damage budget
    (CPU-seconds vs damage-seconds, per-team vs per-target), and merging them
    would let either enforce the other's refusals. They stay parallel ledgers
    that one run consults at one moment.
    """

    def __init__(
        self,
        *,
        budgets: Sequence[ResourceBudget],
        scope: ResourceScope,
        anchor: datetime,
        run_id: str = "",
    ) -> None:
        if anchor.tzinfo is None or anchor.tzinfo.utcoffset(anchor) is None:
            msg = f"resource budget anchor must be timezone-aware, got naive {anchor!r}"
            raise InvariantViolationError(RULE_METER_CONTRACT, msg)
        self._budgets = tuple(budgets)
        self._scope = scope
        self._anchor = anchor
        self.run_id = run_id
        self._series: dict[tuple[ResourceDimension, str], ResourceSeries] = {}
        self._paused_for = ""

    @property
    def budgets(self) -> tuple[ResourceBudget, ...]:
        return self._budgets

    @property
    def scope(self) -> ResourceScope:
        return self._scope

    @property
    def anchor(self) -> datetime:
        return self._anchor

    @property
    def paused(self) -> bool:
        """True once a breach paused the run; sticky, because a resume is a decision."""
        return bool(self._paused_for)

    @property
    def paused_for(self) -> str:
        """The seam that caused the pause; empty while the run may continue."""
        return self._paused_for

    # -- admission ------------------------------------------------------------
    def admit(self, estimates: Sequence[ResourceEstimate], *, now: datetime) -> AdmissionDecision:
        """Refuse a run whose estimate breaches a budget governing this scope.

        Raises:
            BudgetAdmissionRefused: When the estimate would exceed a limit. The
                message is the domain's :attr:`BudgetConsumption.reason`, so it
                names the breaching dimension, the number, the limit, and the
                overage.
        """
        decision = admission_check(
            budgets=self._budgets,
            estimates=estimates,
            scope=self._scope,
            now=now,
            anchor=self._anchor,
        )
        if decision.refused:
            raise BudgetAdmissionRefused(decision)
        return decision

    # -- continuity -----------------------------------------------------------
    def series_for(self, budget: ResourceBudget) -> ResourceSeries:
        """The cumulative ledger for ``budget``, created empty on first use.

        Keyed by ``(dimension, scope_key)`` rather than by object identity, so
        two equal budgets in one run share one ledger: a per-object key would let
        duplicate limits meter into two series and neither would see the other's
        consumption.
        """
        key = (budget.dimension, budget.scope_key)
        existing = self._series.get(key)
        if existing is None:
            existing = ResourceSeries.for_budget(budget)
            self._series[key] = existing
        return existing

    def post(
        self,
        budget: ResourceBudget,
        measured: float,
        *,
        now: datetime,
        note: str = "",
    ) -> ResourceSeries:
        """Post a cumulative reading onto the enforcer's ledger for ``budget``.

        Stores the extended series before returning it, so a caller that goes on
        to breach the budget still has the reading that got it there. Monotonicity
        is delegated to :meth:`ResourceSeries.post`, which *raises* on a reading
        that went down — and that raise is not the "metering must never break a
        run" exception, because a meter that went backwards is a bug whose only
        safe response is to stop. Swallowing it would let a buggy meter report a
        run as within budget forever.
        """
        key = (budget.dimension, budget.scope_key)
        current = self._series.get(key)
        if current is None:
            current = ResourceSeries.for_budget(budget)
        extended = current.post(
            ConsumptionSample(
                dimension=budget.dimension,
                measured=measured,
                at=now,
                note=note,
            )
        )
        self._series[key] = extended
        return extended

    def observe(
        self,
        budget: ResourceBudget,
        measured: float,
        *,
        now: datetime,
        seam: str = "",
    ) -> ContinuityDecision:
        """Post a reading, re-check continuously, and pause on a breach.

        Raises:
            PauseForReview: When the reading breaches the budget. The run is
                neither silently continued nor silently truncated: the caller
                must stop it and surface the breach.
        """
        series = self.post(budget, measured, now=now, note=seam)
        decision = continuity_check(
            budget=budget,
            series=series,
            now=now,
            anchor=self._anchor,
        )
        if decision.paused and decision.consumption is not None:
            self._paused_for = seam
            raise PauseForReview(decision.consumption, seam=seam)
        return decision

    def comparison(
        self,
        budget: ResourceBudget,
        estimate: ResourceEstimate,
        *,
        now: datetime,
    ) -> BudgetComparison:
        """Compare this run's stored actual against a stored estimate, for reporting."""
        window = budget.window_for(now, anchor=self._anchor)
        return compare_estimate(budget, estimate, self.series_for(budget).consumption(window))


# -- small constructors --------------------------------------------------------


def build_run_meter(
    *,
    run_id: str,
    clock: Callable[[], float] | None = None,
    sink: MeterSink | None = None,
) -> RunMeter:
    """Build a meter with an optional injected clock; tests inject a sequence."""
    return RunMeter(
        run_id=run_id,
        clock=time.perf_counter if clock is None else clock,
        sink=sink,
    )


def now_utc() -> datetime:
    """The default ``now`` for a caller that has none — the *only* clock read here.

    Present and named so the absence of ambient time in every decision path is a
    greppable fact rather than a property of where a call happened to land.
    Nothing in :func:`admission_check` or :func:`continuity_check` calls it; a
    caller that wants reproducibility passes its own ``now``.
    """
    return datetime.now(UTC)
