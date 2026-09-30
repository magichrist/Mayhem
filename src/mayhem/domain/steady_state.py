"""The steady-state hypothesis: tolerances, graded verdicts, and the maths.

Chaos Mesh's ``StatusCheck`` stops at a boolean; Litmus's probes stop at a
boolean. Neither can say *"latency rose 18%, inside the 20% band"*, because
neither has a tolerance field — there is no place in their models to write
"18%" next to "20%" and have anything compare them. This module is that
place. It is the vocabulary (``expect`` vs ``tolerance``), the graded verdict,
and the arithmetic that decides between them. It performs no IO, captures
nothing, and renders nothing.

Two design commitments run through everything below:

**A signal is judged against one basis, never two.** ``expect`` is an absolute
band someone typed; ``tolerance`` is a bound relative to a baseline the tool
captured itself. They answer different questions, and setting both is
rejected rather than merged — a merged bound would silently pick a winner and
make the assertion weaker or tighter than its author believes.

**Insufficient data is a verdict, not a number.** Plan 03's own risk section
warns that *"5 samples is not a baseline … getting this wrong makes the tool
confidently wrong, which is worse than no tool."* So :func:`classify` refuses
to grade a signal whose baseline is missing or shorter than
``capture.samples``: it returns ``verdict=None`` and says so. It never
fabricates a baseline, and it never substitutes ``inf`` for a zero one.

``no-effect`` is first-class in :class:`Verdict` for the same reason. Both CNCF
projects cannot distinguish "the fault did nothing" from "the probe never
fired", and a boolean hides that difference behind a pass. Keeping it visible
is the reason this feature exists.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from math import ceil, isfinite
from typing import TYPE_CHECKING

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from mayhem.domain.capabilities import Identifier
from mayhem.domain.common import Duration
from mayhem.domain.errors import InvariantViolationError

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "BEYOND_TOLERANCE_NOTE",
    "INSUFFICIENT_BASELINE",
    "NON_FINITE_BASELINE",
    "NOT_RECOVERED_NOTE",
    "NO_EFFECT_NOTE",
    "SAFETY_MOVED_NOTE",
    "UNCHANGED_EPSILON",
    "AbsoluteExpect",
    "Assertion",
    "AssertionResult",
    "AssertionVerb",
    "Baseline",
    "CaptureSpec",
    "Phase",
    "PhaseAssertion",
    "PhaseChecks",
    "Severity",
    "SignalResult",
    "SteadyStateSignal",
    "SteadyStateSpec",
    "Tolerance",
    "Verdict",
    "classify",
    "degradation_limit",
    "delta_pct",
    "sample_baseline",
    "within_absolute",
    "within_relative",
]

# -- vocabulary ---------------------------------------------------------------------


class Phase(StrEnum):
    """When an assertion is evaluated.

    The values are exactly ``pre`` / ``during`` / ``post`` so they satisfy the
    ``CHECK (phase IN ('pre','during','post'))`` constraint on the
    ``steady_state_evaluations`` table (``infra/migrations.py``). A verdict
    written by an evaluator lands in that column with no translation step, and
    a fourth spelling cannot be introduced by accident.

    The spec surface also accepts ``before`` as an alias for ``pre`` and
    ``after`` for ``post``, because plan 03's example YAML writes ``after:``.
    The alias is an input convenience only: what serializes, and what the
    table stores, is ``post``.
    """

    PRE = "pre"
    DURING = "during"
    POST = "post"


class Severity(StrEnum):
    """How loudly a failing signal reports itself."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class AssertionVerb(StrEnum):
    """The three things a phase can say about a signal.

    ``UNCHANGED`` is a *safety* statement: the fault must not move it at all.
    ``DEGRADED`` is the hypothesis: the signal must move, by a bounded amount.
    ``RECOVERED`` is the proof: after undo, the signal must return within
    tolerance of the captured baseline rather than merely "be present again".
    """

    UNCHANGED = "unchanged"
    DEGRADED = "degraded"
    RECOVERED = "recovered"


class Verdict(StrEnum):
    """The graded answer replacing ``success.criteria``'s boolean.

    ``NO_EFFECT`` is deliberately a first-class member: neither Chaos Mesh nor
    Litmus can tell "the fault had no impact" from "the probe never fired",
    because both collapse to the same boolean. mayhem can tell, because it
    holds both the baseline and the perturbation window — so that difference
    gets its own verdict rather than being hidden behind a pass.
    """

    AS_HYPOTHESISED = "as-hypothesised"
    DEGRADED_WITHIN_TOLERANCE = "degraded-within-tolerance"
    DEGRADED_BEYOND_TOLERANCE = "degraded-beyond-tolerance"
    NO_EFFECT = "no-effect"
    NOT_RECOVERED = "not-recovered"


UNCHANGED_EPSILON = 1e-9
"""Relative slack used to decide "this measurement did not move".

A float comparison of ``baseline`` against itself is not exact after an
aggregation step, so exact equality would report spurious movement. 1e-9
relative is far below any measurement noise worth grading and far above
float64 representation error.
"""

SAFETY_MOVED_NOTE = "safety signal moved; the target degraded beyond the fault under test"
NO_EFFECT_NOTE = (
    "the fault did not move this signal; a fault with no impact and a probe "
    "that never fired look identical from here"
)
BEYOND_TOLERANCE_NOTE = "the signal moved further than the declared tolerance allows"
NOT_RECOVERED_NOTE = "chaos residue: the signal did not return to its captured baseline"
INSUFFICIENT_BASELINE = (
    "insufficient baseline for {name}: {got} of {need} samples. Five samples is not a "
    "baseline — this is reported, not graded"
)
NON_FINITE_BASELINE = (
    "baseline for {name} is not a finite measurement ({value}). A probe that returned "
    "nan or inf captured nothing, and grading against nothing is how the tool gets "
    "confidently wrong — this is reported, not graded"
)


# -- authored spec models ------------------------------------------------------------


class CaptureSpec(BaseModel):
    """How many pre-fault samples to take, and over what window.

    ``samples`` is a *floor for grading*, not a suggestion: a run that
    captured fewer samples than this has no baseline and
    :func:`classify` will refuse to produce a verdict from it.
    """

    model_config = ConfigDict(frozen=True)

    samples: int = Field(default=5, ge=1)
    window: Duration = "10s"


class AbsoluteExpect(BaseModel):
    """An authored steady-state band, in the metric's own units.

    Every declared bound must hold — inside a single band the bounds are
    *narrowing* the window (``gte`` 10 and ``lte`` 250 is a range), so they
    are a conjunction. That is the opposite of :class:`Tolerance`, whose
    members are alternative allowances for one judgement.
    """

    model_config = ConfigDict(frozen=True)

    lte: float | None = None
    gte: float | None = None
    eq: float | None = None

    @model_validator(mode="after")
    def _declares_a_bound(self) -> AbsoluteExpect:
        if self.lte is None and self.gte is None and self.eq is None:
            raise InvariantViolationError(
                "steady_state.expect_empty",
                "expect declares none of lte, gte or eq: an empty band would "
                "accept every measurement, which is a no-op wearing a bound's name",
            )
        return self


class Tolerance(BaseModel):
    """How far a captured baseline may be exceeded.

    ``at_most`` is an absolute ceiling (percentage points for a rate, ms for a
    latency) and ``at_most_relative`` is a multiple of the baseline. Either
    one passing is enough — see :func:`within_relative`.
    """

    model_config = ConfigDict(frozen=True)

    at_most: float | None = Field(default=None, ge=0.0)
    at_most_relative: float | None = None

    @field_validator("at_most_relative")
    @classmethod
    def _relative_floor_is_one(cls, value: float | None) -> float | None:
        """Reject ``at_most_relative < 1.0`` and say why.

        A multiplier below 1.0 asserts the signal must *improve* during an
        injected fault. That is never a valid expectation for a fault, and
        admitting it would let a typo (``0.95`` for ``95``) silently invert an
        assertion into something that fails on a healthy system.
        """
        if value is not None and value < 1.0:
            raise InvariantViolationError(
                "steady_state.tolerance_relative_below_one",
                "at_most_relative must be >= 1.0: a multiplier below 1.0 would "
                "require the signal to improve while the fault is active, which is "
                "never a valid fault expectation",
            )
        return value

    @model_validator(mode="after")
    def _declares_a_bound(self) -> Tolerance:
        if self.at_most is None and self.at_most_relative is None:
            raise InvariantViolationError(
                "steady_state.tolerance_empty",
                "tolerance declares neither at_most nor at_most_relative: an empty "
                "tolerance would accept every measurement",
            )
        return self


class SteadyStateSignal(BaseModel):
    """One named metric a drill watches, and the basis it is judged on."""

    model_config = ConfigDict(frozen=True)

    name: Identifier
    source_id: str
    metric: str
    expect: AbsoluteExpect | None = None
    tolerance: Tolerance | None = None
    baseline_window: Duration | None = None
    severity: Severity = Severity.WARNING

    @model_validator(mode="after")
    def _one_basis_only(self) -> SteadyStateSignal:
        """``expect`` and ``tolerance`` are mutually exclusive per signal.

        A signal is judged either against a band someone typed in or against
        the baseline the tool captured. Both at once would have to pick a
        winner, and whichever it picked would not be the one the author
        believed they wrote.
        """
        if self.expect is not None and self.tolerance is not None:
            raise InvariantViolationError(
                "steady_state.signal_mixes_bases",
                f"signal {self.name!r} sets both expect and tolerance: judge a "
                "signal against an absolute band (expect) or against its captured "
                "baseline (tolerance), never both",
            )
        return self

    @model_validator(mode="after")
    def _baseline_window_needs_tolerance(self) -> SteadyStateSignal:
        """``baseline_window`` is a per-signal override of ``capture.window``.

        It only has meaning for a signal judged against its baseline; on an
        absolutely-bounded signal it would be decoration that reads like a
        control.
        """
        if self.baseline_window is not None and self.tolerance is None:
            raise InvariantViolationError(
                "steady_state.baseline_window_without_tolerance",
                f"signal {self.name!r} sets baseline_window without tolerance: "
                "baseline_window overrides capture.window for a signal judged "
                "against its captured baseline, and means nothing without one",
            )
        return self


class PhaseChecks(BaseModel):
    """The verbs asserted in one phase, and the bound ``degraded`` may reach.

    ``within`` binds to ``assert_degraded`` only: it is how far past the
    signal's reference value the perturbation may go. The other two verbs are
    graded against the signal's own basis and have nothing to scale.
    """

    model_config = ConfigDict(frozen=True)

    assert_unchanged: tuple[Identifier, ...] = ()
    assert_degraded: tuple[Identifier, ...] = ()
    assert_recovered: tuple[Identifier, ...] = ()
    within: float | None = Field(default=None, gt=0.0)

    @model_validator(mode="after")
    def _within_binds_degraded(self) -> PhaseChecks:
        if self.within is not None and not self.assert_degraded:
            raise InvariantViolationError(
                "steady_state.within_without_degraded",
                "within applies to assert_degraded only, and this phase declares "
                "no assert_degraded signals for it to bound",
            )
        return self

    @model_validator(mode="after")
    def _asserts_something(self) -> PhaseChecks:
        if not (self.assert_unchanged or self.assert_degraded or self.assert_recovered):
            raise InvariantViolationError(
                "steady_state.phase_asserts_nothing",
                "a phase entry asserts nothing: declare at least one of "
                "assert_unchanged, assert_degraded or assert_recovered",
            )
        return self


class PhaseAssertion(BaseModel):
    """One phase's worth of checks — exactly one of ``pre``/``during``/``post``."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    pre: PhaseChecks | None = Field(default=None, validation_alias=AliasChoices("pre", "before"))
    during: PhaseChecks | None = None
    post: PhaseChecks | None = Field(default=None, validation_alias=AliasChoices("post", "after"))

    @model_validator(mode="after")
    def _exactly_one_phase(self) -> PhaseAssertion:
        declared = [phase.value for phase, checks in self.checks() if checks is not None]
        if len(declared) > 1:
            raise InvariantViolationError(
                "steady_state.phase_has_multiple_keys",
                f"a phase entry declares more than one of {declared}: split it into "
                "one entry per phase",
            )
        if not declared:
            raise InvariantViolationError(
                "steady_state.phase_missing",
                "a phase entry declares no phase: expected exactly one of pre, during or post",
            )
        return self

    def checks(self) -> tuple[tuple[Phase, PhaseChecks | None], ...]:
        return ((Phase.PRE, self.pre), (Phase.DURING, self.during), (Phase.POST, self.post))


class SteadyStateSpec(BaseModel):
    """The authored ``steady_state:`` block: capture, signals, and phases."""

    model_config = ConfigDict(frozen=True)

    capture: CaptureSpec = Field(default_factory=CaptureSpec)
    signals: tuple[SteadyStateSignal, ...] = ()
    phases: tuple[PhaseAssertion, ...] = ()

    @model_validator(mode="after")
    def _signal_names_unique(self) -> SteadyStateSpec:
        seen: set[str] = set()
        for signal in self.signals:
            if signal.name in seen:
                raise InvariantViolationError(
                    "steady_state.duplicate_signal",
                    f"signal name {signal.name!r} is declared more than once: "
                    "signal names address exactly one measurement and must be unique "
                    "within the block",
                )
            seen.add(signal.name)
        return self

    @model_validator(mode="after")
    def _phase_signals_declared(self) -> SteadyStateSpec:
        """A phase may only reference a declared signal.

        An undeclared name is a typo, and a typo that resolves to a silent
        no-op is the worst possible failure for an assertion block: the drill
        would report "steady state held" having checked nothing.
        """
        declared = {signal.name for signal in self.signals}
        for assertion in self.phases:
            for _, checks in assertion.checks():
                if checks is None:
                    continue
                for verb, names in (
                    (AssertionVerb.UNCHANGED, checks.assert_unchanged),
                    (AssertionVerb.DEGRADED, checks.assert_degraded),
                    (AssertionVerb.RECOVERED, checks.assert_recovered),
                ):
                    for name in names:
                        if name not in declared:
                            raise InvariantViolationError(
                                "steady_state.undeclared_signal",
                                f"phase asserts {verb.value} on signal {name!r}, which "
                                f"is not declared in signals (declared: "
                                f"{sorted(declared)})",
                            )
        return self

    @model_validator(mode="after")
    def _not_a_no_op(self) -> SteadyStateSpec:
        if not self.signals and not self.phases:
            raise InvariantViolationError(
                "steady_state.empty_block",
                "steady_state declares neither signals nor phases: an empty block "
                "would read as 'steady state checked out clean' having checked nothing",
            )
        return self

    @property
    def empty(self) -> bool:
        return not self.signals and not self.phases

    def signal(self, name: str) -> SteadyStateSignal | None:
        for signal in self.signals:
            if signal.name == name:
                return signal
        return None


# -- result types --------------------------------------------------------------------
#
# Frozen slotted dataclasses with ``to_dict()``, matching
# ``mayhem.domain.observations`` — the other criterion/outcome pair in the
# domain — rather than the pydantic models used for *authored* input. Result
# types live here, not on the wire.


@dataclass(frozen=True, slots=True)
class Baseline:
    """A captured pre-fault measurement and how many samples produced it.

    ``samples`` below ``capture.samples`` is representable on purpose: an
    under-sampled baseline is something the domain must be able to *say*,
    not something it refuses to construct.
    """

    value: float
    samples: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Assertion:
    """A resolved judgement: one verb, applied to one declared signal.

    Produced by :meth:`for_signal` from an authored
    :class:`SteadyStateSignal` plus the phase's ``within``, so that
    :func:`classify` never has to re-read the spec.
    """

    verb: AssertionVerb
    name: str
    expect: AbsoluteExpect | None = None
    tolerance: Tolerance | None = None
    within: float | None = None
    required_samples: int = 1
    severity: Severity = Severity.WARNING

    @classmethod
    def for_signal(
        cls,
        signal: SteadyStateSignal,
        verb: AssertionVerb,
        *,
        required_samples: int = 1,
        within: float | None = None,
    ) -> Assertion:
        return cls(
            verb=verb,
            name=signal.name,
            expect=signal.expect,
            tolerance=signal.tolerance,
            within=within,
            required_samples=required_samples,
            severity=signal.severity,
        )

    @property
    def reference_value(self) -> float | None:
        """The value ``within`` scales — the authored bound, else the baseline."""
        if self.expect is not None and self.expect.lte is not None:
            return self.expect.lte
        return None

    def to_dict(self) -> dict[str, object]:
        # NOT dataclasses.asdict(self): `expect` and `tolerance` are pydantic
        # models, and asdict() leaves them as model objects rather than
        # recursing into them. The result typed as dict[str, object] did not
        # actually contain JSON-safe values, and json.dumps() raised
        # "Object of type Tolerance is not JSON serializable" at the evidence
        # bundle boundary — the one place a steady-state assertion must never
        # fail to serialise. Each nested model serialises itself.
        return {
            "verb": self.verb.value,
            "severity": self.severity.value,
            "name": self.name,
            "within": self.within,
            "required_samples": self.required_samples,
            "expect": None if self.expect is None else self.expect.model_dump(),
            "tolerance": None if self.tolerance is None else self.tolerance.model_dump(),
        }


@dataclass(frozen=True, slots=True)
class SignalResult:
    """Per-signal detail behind a verdict.

    Numeric fields are ``| None`` because the honest answer is sometimes
    "there is no number to quote". A missing baseline is recorded as missing
    rather than as ``0.0``, which would read as a measurement.
    """

    name: str
    asserted: AssertionVerb
    baseline: float | None
    during: float | None
    after: float | None
    delta_pct: float | None
    limit: float | None
    within: float | None
    passed: bool
    note: str = ""
    severity: Severity = Severity.WARNING

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["asserted"] = self.asserted.value
        payload["severity"] = self.severity.value
        # The plan's JSON calls this field `pass`, which is a Python keyword.
        payload["pass"] = payload.pop("passed")
        return payload


@dataclass(frozen=True, slots=True)
class AssertionResult:
    """The graded outcome of one assertion.

    ``verdict is None`` means the assertion was *not graded* — the baseline
    was missing or under-sampled. ``sufficient`` distinguishes that from a
    graded failure, and ``passed`` is false for both: an ungraded assertion
    never counts as a pass.
    """

    verdict: Verdict | None
    signals: tuple[SignalResult, ...] = ()
    sufficient: bool = True
    note: str = ""

    @property
    def passed(self) -> bool:
        return self.verdict is not None and self.sufficient and all(s.passed for s in self.signals)

    @property
    def graded(self) -> bool:
        return self.verdict is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.value if self.verdict is not None else None,
            "sufficient": self.sufficient,
            "passed": self.passed,
            "note": self.note,
            "signals": [signal.to_dict() for signal in self.signals],
        }


# -- pure maths ----------------------------------------------------------------------


def delta_pct(baseline: float, during: float) -> float | None:
    """Relative change from ``baseline`` to ``during``, in percent.

    Returns ``None`` — never ``inf``, never a raise — when the change is
    *undefined*. Two cases:

    * ``baseline == 0.0``. There is no scale to divide by. ``inf`` is the
      arithmetically honest answer and it is useless: ``inf`` is not valid
      JSON in a strict parser, it compares ``True`` against every bound, and a
      report can quote it while a reader cannot interpret it. ``None`` forces
      the caller down the absolute path (see :func:`within_relative`, where a
      zero baseline makes the *relative* bound unsatisfiable rather than
      infinite) or to say the signal was not measurable.
    * a non-finite input. Same reasoning: ``inf`` must not reach a
      hash-chained evidence bundle.

    A **negative baseline is legal** — a signed metric, a temperature delta, a
    queue-depth change — and is divided through by its *magnitude*, so the
    sign of the result always reads as "moved up" (+) or "moved down" (-) on
    the raw scale: ``-10 → -20`` is ``-100.0`` (further from zero) and
    ``-10 → -5`` is ``+50.0`` (closer to zero). Dividing by the *signed*
    baseline would flip the second reading — the reading a "did it get worse"
    check actually cares about.
    """
    if not isfinite(baseline) or not isfinite(during):
        return None
    if baseline == 0.0:
        return None
    change = (during - baseline) / abs(baseline) * 100.0
    # A denormal baseline can overflow the division itself (1e-300 → 1e18 is
    # -inf, not 4e320). An unrepresentable change is refused on the same terms
    # as an undefined one: a report can quote ``None``, and it can quote it
    # honestly.
    return change if isfinite(change) else None


def within_absolute(measured: float, expect: AbsoluteExpect) -> bool:
    """True when ``measured`` satisfies **every** bound ``expect`` declares.

    The conjunction is deliberate and is the opposite of
    :func:`within_relative`: inside one band, ``gte`` and ``lte`` *narrow* the
    window, so all of them must hold. An unmeasurable measurement fails rather
    than passing by accident.
    """
    if not isfinite(measured):
        return False
    if expect.eq is not None and measured != expect.eq:
        return False
    if expect.lte is not None and measured > expect.lte:
        return False
    if expect.gte is not None and measured < expect.gte:
        return False
    return expect.eq is not None or expect.lte is not None or expect.gte is not None


def within_relative(baseline: float | None, measured: float, tolerance: Tolerance | None) -> bool:
    """True when ``measured`` satisfies **either** declared relative bound.

    ``at_most`` and ``at_most_relative`` are *alternative allowances for one
    judgement*, so the test is a disjunction: a value that clears ``at_most``
    but blows through ``at_most_relative`` — or the reverse — still passes.
    Reading this as a conjunction would silently tighten every assertion
    authored with both bounds, which is how a tolerance band quietly turns
    into a no-op that fails healthy systems.

    **A relative bound measures deviation from the baseline, not magnitude.**
    The test is therefore ``|measured - baseline| <= |baseline| *
    at_most_relative`` — never ``|measured| <= ...``. Comparing magnitudes
    instead throws away the direction of the move, and a signed metric that
    inverted completely (``+100 → -100``) has the *same* magnitude as the
    healthy value: it sailed through a 1.5x band and was graded
    ``as-hypothesised``, the worst outcome there is reported as the best one,
    while the very same run's ``delta_pct`` correctly read ``-200.0 %``.
    Deviation is symmetric about the baseline by construction, which is
    exactly the governing invariant: a value on the opposite side of the
    baseline satisfies the bound if and only if the equal-sized move in the
    same direction would. :func:`delta_pct` divides by ``abs(baseline)`` for
    the same reason and stays consistent with it.

    A ``baseline`` of ``0.0`` or ``None`` makes the *relative* bound
    unsatisfiable rather than infinite: ``0 * 1.5 == 0`` leaves exactly one
    measurement within zero of a zero baseline, namely zero itself. That is
    the intended outcome — a signal with no measurable baseline is judged by
    its absolute band or not at all.

    An absent tolerance, or a non-finite measurement, is ``False``. An
    undeclared bound cannot assert anything.
    """
    if tolerance is None or not isfinite(measured):
        return False
    if tolerance.at_most is not None and measured <= tolerance.at_most:
        return True
    if tolerance.at_most_relative is None or baseline is None or not isfinite(baseline):
        return False
    return abs(measured - baseline) <= abs(baseline) * tolerance.at_most_relative


def degradation_limit(baseline: float, assertion: Assertion) -> float | None:
    """The measured value at which ``assert_degraded`` stops holding.

    ``within`` is a multiplier on the signal's **reference value**: the
    authored ``expect.lte`` bound for an absolutely-bounded signal, or the
    captured baseline for a relatively-bounded one. So ``within: 2.0`` on
    ``expect: {lte: 250}`` permits 500 ms of degradation, and ``within: 2.0``
    on a 10-unit baseline permits 20. ``None`` when no reference resolves, in
    which case the caller falls back to the signal's own basis.
    """
    if assertion.within is None:
        return None
    reference = assertion.reference_value
    if reference is not None:
        return abs(reference) * assertion.within
    if assertion.tolerance is not None and isfinite(baseline):
        return abs(baseline) * assertion.within
    return None


def sample_baseline(values: Sequence[float], *, percentile: float = 100.0) -> Baseline | None:
    """Reduce a captured pre-fault series to a :class:`Baseline`.

    Nearest-rank percentile over the finite samples. The default is the
    **maximum**, not the mean: plan 03's risk section says *"5 samples is not a
    baseline … needs a percentile, not a mean"*, and a mean is exactly the
    statistic that hides the one bad sample a fault exists to expose.
    ``percentile=50.0`` gives the median for a signal whose wobble is noise
    rather than signal. Non-finite samples are dropped, and an empty series
    returns ``None`` — which classifies as *insufficient* rather than as a
    fabricated ``0.0``.
    """
    finite = sorted(v for v in values if isfinite(v))
    if not finite:
        return None
    rank = min(len(finite), max(1, ceil(percentile / 100.0 * len(finite))))
    return Baseline(value=finite[rank - 1], samples=len(finite))


def classify(measured: float, baseline: Baseline | None, assertion: Assertion) -> AssertionResult:
    """Grade one measured value against one assertion. Pure; never guesses.

    **Insufficient data is refused, not guessed.** When ``baseline`` is
    ``None`` or carries fewer samples than ``assertion.required_samples`` (the
    spec's ``capture.samples``), the result carries ``verdict=None`` and
    ``sufficient=False``: no number is invented and no verdict is asserted.
    This applies to *every* verb, including an absolutely-bounded signal,
    because without a captured baseline a report cannot distinguish "the
    probe never fired" from "the fault did nothing" — the confusion this
    whole module exists to remove. :func:`within_absolute` remains available
    for callers that genuinely only want the authored band. A ``Baseline``
    whose ``value`` is ``nan`` or ``inf`` is refused the same way and with the
    same verdict: a probe that returned ``nan`` captured nothing, and a
    ``nan`` in the result is a number an evidence bundle cannot be asked to
    interpret.

    **A malformed ``baseline`` is rejected, not coerced.** ``baseline`` is a
    :class:`Baseline` or ``None``, and nothing else: it is rejected with an
    :class:`InvariantViolationError` *at this boundary* rather than being
    allowed to fail three frames deeper on ``baseline.samples``. A bare float
    is deliberately **not** accepted as a one-sample baseline, because a float
    carries no provenance — it may be a single sample, a mean, a sum or a
    max — and inventing ``samples=1`` would assert it was a single sample.
    Plan 03's risk section names that statistic by name: *"5 samples is not a
    baseline … needs a percentile, not a mean"*. Silently degrading to
    ``verdict=None`` instead would be worse still: a caller that passed a
    mean would read "insufficient baseline" when the real fault is that it
    passed the wrong type, and the drill would ship with a check that never
    ran. Loud, typed, and at the call site is the only honest option; build a
    :class:`Baseline` with :func:`sample_baseline` and the problem disappears.

    The mapping:

    ==========================  ==========================================
    verb                        verdict
    ==========================  ==========================================
    ``assert_unchanged``, held  ``as-hypothesised``
    ``assert_unchanged``, moved ``degraded-beyond-tolerance``
    ``assert_degraded``, moved and bounded  ``degraded-within-tolerance``
    ``assert_degraded``, moved and past     ``degraded-beyond-tolerance``
    ``assert_degraded``, unmoved            ``no-effect``
    ``assert_recovered``, back              ``as-hypothesised``
    ``assert_recovered``, not back          ``not-recovered``
    ==========================  ==========================================

    ``assert_unchanged`` is graded on *movement*, not on the signal's
    tolerance: those bounds say how bad degradation may get, not how much
    drift a safety signal is allowed. A 4x rise in an error rate is a
    ``degraded-beyond-tolerance`` even when it sits under ``at_most``,
    because a safety signal that moved is a finding, not a pass.
    """
    checked = _checked_baseline(baseline)
    name = assertion.name
    is_post = assertion.verb is AssertionVerb.RECOVERED
    # A baseline the tool cannot quote is not a baseline. nan/inf captured
    # nothing, so it is refused on the same terms as a missing one rather
    # than graded against — and never echoed into a result.
    usable = checked if checked is not None and isfinite(checked.value) else None
    if usable is None or usable.samples < assertion.required_samples:
        if usable is not None:
            note = INSUFFICIENT_BASELINE.format(
                name=name,
                got=usable.samples,
                need=assertion.required_samples,
            )
        elif checked is not None:
            note = NON_FINITE_BASELINE.format(name=name, value=checked.value)
        else:
            note = INSUFFICIENT_BASELINE.format(
                name=name,
                got=0,
                need=assertion.required_samples,
            )
        signal = SignalResult(
            name=name,
            asserted=assertion.verb,
            baseline=None if usable is None else usable.value,
            during=None if is_post else measured,
            after=measured if is_post else None,
            delta_pct=None,
            limit=None,
            within=assertion.within,
            passed=False,
            note=note,
            severity=assertion.severity,
        )
        return AssertionResult(verdict=None, signals=(signal,), sufficient=False, note=note)

    value = usable.value
    moved = _moved(value, measured)
    limit = degradation_limit(value, assertion)

    if assertion.verb is AssertionVerb.UNCHANGED:
        passed = not moved
        verdict = Verdict.AS_HYPOTHESISED if passed else Verdict.DEGRADED_BEYOND_TOLERANCE
        note = "" if passed else SAFETY_MOVED_NOTE
    elif assertion.verb is AssertionVerb.DEGRADED:
        if not moved:
            passed = False
            verdict = Verdict.NO_EFFECT
            note = NO_EFFECT_NOTE
        else:
            passed = _degraded_within(value, measured, limit, assertion)
            verdict = (
                Verdict.DEGRADED_WITHIN_TOLERANCE if passed else Verdict.DEGRADED_BEYOND_TOLERANCE
            )
            note = "" if passed else BEYOND_TOLERANCE_NOTE
    else:
        passed = _recovered(value, measured, assertion)
        verdict = Verdict.AS_HYPOTHESISED if passed else Verdict.NOT_RECOVERED
        note = "" if passed else NOT_RECOVERED_NOTE

    signal = SignalResult(
        name=name,
        asserted=assertion.verb,
        baseline=value,
        during=None if is_post else measured,
        after=measured if is_post else None,
        delta_pct=delta_pct(value, measured),
        limit=limit,
        within=assertion.within,
        passed=passed,
        note=note,
        severity=assertion.severity,
    )
    return AssertionResult(verdict=verdict, signals=(signal,))


def _checked_baseline(baseline: object) -> Baseline | None:
    """Narrow the ``classify`` boundary, rejecting what is not a Baseline.

    Takes ``object`` rather than ``Baseline | None`` on purpose: the parameter
    is the one place a Python caller gets no help from a type checker, so the
    runtime check is the whole defence. ``None`` means "not captured" and
    passes through to the insufficient-data path; anything else that is not a
    :class:`Baseline` is a caller bug and is named as one.
    """
    if baseline is None or isinstance(baseline, Baseline):
        return baseline
    raise InvariantViolationError(
        "steady_state.baseline_not_captured",
        f"classify was handed a {type(baseline).__name__} where a Baseline was "
        "expected: a bare number carries no sample count and cannot be graded. "
        "Build one with sample_baseline(values), or pass None to grade as "
        "insufficient rather than invented",
    )


def _moved(baseline: float, measured: float) -> bool:
    """Did the measurement move? An unmeasurable input counts as moved."""
    if not isfinite(baseline) or not isfinite(measured):
        return True
    return abs(measured - baseline) > abs(baseline) * UNCHANGED_EPSILON


def _degraded_within(
    baseline: float, measured: float, limit: float | None, assertion: Assertion
) -> bool:
    """Did the perturbation stay inside the bound ``degraded`` allows?

    A resolved ``within`` limit *replaces* the signal's own band rather than
    compounding with it: ``within: 2.0`` on ``expect: {lte: 250}`` is
    "degrade up to 500", not "degrade up to 250 and also up to 500".
    """
    if limit is not None:
        return _within_ceiling(baseline, measured, limit, assertion)
    if assertion.expect is not None:
        return within_absolute(measured, assertion.expect)
    if assertion.tolerance is not None:
        return within_relative(baseline, measured, assertion.tolerance)
    return True


def _within_ceiling(baseline: float, measured: float, limit: float, assertion: Assertion) -> bool:
    """The ``within`` magnitude ceiling, applied without the sign blind spot.

    ``within`` scales the *magnitude* of the signal's reference value, so
    :func:`degradation_limit` yields a magnitude ceiling. A magnitude ceiling
    on a signed value has to say which side of zero it bounds, and the answer
    is the reference's own side: a ``+100`` baseline with ``within: 2.0`` gives
    the window ``[0, 200]``, not ``[-200, 200]``. Mirroring the window about
    zero let a full sign inversion pass as *within tolerance* — the same
    blindness :func:`within_relative` had, reached through the other door.

    The reference anchors the direction; the baseline is the fallback for a
    relatively-bounded signal, whose reference is the baseline by construction.
    A non-finite measurement or limit fails rather than passing by accident.
    """
    if not isfinite(measured) or not isfinite(limit):
        return False
    if abs(measured) > limit:
        return False
    reference = assertion.reference_value
    anchor = baseline if reference is None else reference
    if anchor >= 0.0:
        return measured >= 0.0
    return measured <= 0.0


def _recovered(baseline: float, measured: float, assertion: Assertion) -> bool:
    """Did the signal come back to its captured baseline?

    Recovery is judged by whichever basis the signal declares, and only by
    exact non-movement when it declares neither.
    """
    if assertion.tolerance is not None:
        return within_relative(baseline, measured, assertion.tolerance)
    if assertion.expect is not None:
        return within_absolute(measured, assertion.expect)
    return not _moved(baseline, measured)
