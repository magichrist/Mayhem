"""The steady-state evaluator: capture a baseline, then grade three phases.

``domain/steady_state`` is the vocabulary and the arithmetic. This module is the
part that *does* something: it takes the readings a run produces, reduces them
to a :class:`~mayhem.domain.steady_state.Baseline`, drives
:func:`~mayhem.domain.steady_state.classify` across the plan's ``pre`` /
``during`` / ``post`` phases, persists the graded outcome, and cross-checks the
result against the impact gate. It adds no tolerance arithmetic of its own —
every bound, every epsilon and every verdict decision belongs to the domain, and
this module's job is to refuse to grade rather than to grade loosely.

**The capture loop reuses the observability collector; it does not reimplement
it.** ``capture_baselines`` calls
:func:`mayhem.controller.observability_collector.collect_observability` — the
same function the executor already calls, already honouring each source's
``cadence``, each source's ``timeout`` and the config's ``total_timeout`` — and
repeats that pass until every declared signal has ``capture.samples`` readings
or the authored ``capture.window`` is spent. The deadline is checked between
passes, never by sleeping past it: the collector owns the sleeping, because it
is the layer that knows a source's cadence. Nothing here opens a socket.

**A reading that is not a finite number is never graded.** The domain refuses an
unusable *baseline*; this module refuses an unusable *measurement*, and returns
``verdict=None`` with the reason. Both refusals exist for one reason: an
ungraded assertion must never read as a pass, and ``nan`` graded as
``degraded-beyond-tolerance`` would be exactly that — a fabricated verdict
about a probe that returned nothing.

**The bundle is the last gate.** :meth:`SteadyStateReport.bundle_payload` is
built from the typed result, never from raw provider data, and every numeric
slot is either a finite float or an explicit ``null`` carrying a ``note`` that
says why. ``json.dumps(..., allow_nan=False)`` is the proof: it raises on
``inf`` and ``nan``, so a payload that serialises under it cannot contain one.
That is the property plan 03's ``delta_pct`` returning ``None`` for a zero
baseline exists to protect — ``inf`` is not valid JSON for a strict parser and
a reader cannot be asked to interpret it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING, Any

from mayhem.controller.observability_collector import SourceCollection, collect_observability
from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.observability import duration_seconds
from mayhem.domain.observations import (
    PROVENANCE_HTTP,
    PROVENANCE_LOCAL,
    PROVENANCE_LOKI,
    PROVENANCE_PROMETHEUS,
)
from mayhem.domain.steady_state import (
    UNCHANGED_EPSILON,
    Assertion,
    AssertionResult,
    AssertionVerb,
    Baseline,
    Phase,
    PhaseChecks,
    SignalResult,
    SteadyStateSignal,
    SteadyStateSpec,
    Verdict,
    classify,
    sample_baseline,
)
from mayhem.observability.metrics import Measurement, coerce_finite, derive_log_metric

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from mayhem.domain.observability import ObservabilityConfig
    from mayhem.infra.store import Store

__all__ = [
    "NON_FINITE_READING",
    "BaselineCapture",
    "BaselineUnavailableError",
    "GateAgreement",
    "GateFinding",
    "ImpactCrossCheck",
    "PhaseEvaluation",
    "SteadyStateEvaluationRepository",
    "SteadyStateReport",
    "StoredEvaluation",
    "assert_bundle_safe",
    "baseline_from_run",
    "capture_baselines",
    "cross_check_gate",
    "evaluate_phase",
    "evaluate_run",
]


NON_FINITE_READING = (
    "measurement for {name} is not a finite number ({value!r}). A probe that returned "
    "nan or inf measured nothing, and grading a verdict about nothing is how the tool "
    "gets confidently wrong — this is reported, not graded"
)
MISSING_READING = (
    "no reading captured for {name}: the source could not produce a number, which is "
    "not the same as a reading of zero"
)


class BaselineUnavailableError(RuntimeError):
    """``--baseline-from`` named a run with no retrievable steady-state baseline."""


# -- capture -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BaselineCapture:
    """The pre-injection baselines, and the readings that produced them.

    ``readings`` is kept, not discarded: a baseline with nothing behind it cannot
    be re-derived, re-checked, or diffed against a later run, and the whole point
    of step 6 (``--baseline-from``) is comparing two captures.
    """

    baselines: dict[str, Baseline | None]
    readings: dict[str, tuple[float, ...]] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)
    source_id: str = ""

    @property
    def sufficient(self) -> bool:
        """True when every declared signal produced a gradeable baseline.

        A capture is sufficient when no signal is missing *and* no signal
        is under-sampled. Under-sampling is not a soft warning: plan 03 says
        five samples is not a baseline, and a tool that quietly grades on two
        is a tool that is confidently wrong.
        """
        return all(b is not None for b in self.baselines.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "baselines": {
                name: (None if b is None else b.to_dict()) for name, b in self.baselines.items()
            },
            "samples": {name: len(values) for name, values in self.readings.items()},
            "notes": dict(self.notes),
            "source_id": self.source_id,
        }


def _collection_index(
    collections: Sequence[SourceCollection],
) -> dict[str, SourceCollection]:
    """``source_id`` → collection, first occurrence wins.

    A duplicate ``source_id`` is not an error here: the observability config
    already rejects duplicates at validation time, and a caller that assembled
    collections by hand has not necessarily run that validator. Taking the first
    and recording nothing is the least surprising reading.
    """
    index: dict[str, SourceCollection] = {}
    for collection in collections:
        index.setdefault(collection.source_id, collection)
    return index


#: The provenance a collected source implies, reusing the constants the
#: connectors already publish. ``SourceCollection`` does not carry one, so a
#: reading lifted from it would otherwise be stamped ``local`` — claiming a
#: local measurement for something scraped out of Prometheus or Loki.
_KIND_PROVENANCE: dict[str, str] = {
    "metrics": PROVENANCE_PROMETHEUS,
    "logs": PROVENANCE_LOKI,
    "probe": PROVENANCE_HTTP,
}


def readings_for(
    signal: SteadyStateSignal, collection: SourceCollection | None
) -> tuple[Measurement, ...]:
    """The series of readings one declared signal can take from one collection.

    Each collected sample becomes its own :class:`Measurement` so the baseline
    is a *series* reduced by percentile, not one number handed down from a
    transport. A sample that is not a finite number is kept as an unavailable
    reading rather than dropped silently: ``sample_baseline`` drops non-finite
    samples itself, and the note it produces is more useful than a gap.
    """
    if collection is None or collection.source_id != signal.source_id:
        return (
            Measurement(
                name=str(signal.name),
                value=None,
                source=signal.source_id,
                detail=(
                    f"no collection for source_id {signal.source_id!r}"
                    if collection is None
                    else f"collection is for source_id {collection.source_id!r}, "
                    f"signal declared {signal.source_id!r}"
                ),
            ),
        )
    kind = str(collection.kind)
    out: list[Measurement] = []
    for sample in collection.samples:
        raw = sample.value
        text = raw if isinstance(raw, str) else ""
        if kind == "metrics":
            value = coerce_finite(raw)
            detail = "" if value is not None else f"sample {raw!r} is not a finite number"
        elif kind == "logs":
            value = coerce_finite(derive_log_metric(signal.metric, text))
            detail = (
                ""
                if value is not None
                else f"metric {signal.metric!r} has no derivation over a log tail"
            )
        else:
            value = None
            detail = (
                f"source kind {kind!r} yields no numeric reading for metric "
                f"{signal.metric!r}: probes and inspect output are not quantities"
            )
        out.append(
            Measurement(
                name=str(signal.name),
                value=value,
                provenance=_KIND_PROVENANCE.get(kind, PROVENANCE_LOCAL),
                source=collection.source_id,
                detail=detail,
                at=sample.at,
            )
        )
    if not out:
        out.append(
            Measurement(
                name=str(signal.name),
                value=None,
                source=collection.source_id,
                detail=collection.note or "collection produced no samples",
            )
        )
    return tuple(out)


def capture_baselines(
    spec: SteadyStateSpec,
    *,
    config: ObservabilityConfig,
    engine: str = "podman",
    collector: Callable[..., tuple[SourceCollection, ...]] = collect_observability,
    percentile: float = 100.0,
) -> BaselineCapture:
    """Capture ``capture.samples`` pre-injection readings per declared signal.

    The loop is a *pass* loop over the existing collector, not a sampling loop
    of its own:

    * each pass calls ``collector(config, engine=engine)``, which already
      applies every source's ``cadence``, its ``timeout``, and the config's
      ``total_timeout`` — so the cadence the author declared is the cadence
      that runs, and this module never invents a polling rate;
    * readings accumulate per signal until each has ``capture.samples`` of
      them, or until ``capture.window`` seconds have elapsed since the first
      pass. The deadline is checked *between* passes, so a slow source delays
      the run by at most one pass rather than being cut off mid-read;
    * reduction is :func:`sample_baseline` at ``percentile`` — a percentile, not
      a mean, per plan 03's own risk note.

    ``percentile`` defaults to the maximum, the domain's deliberate default: a
    mean is the statistic that hides the one bad sample a fault exists to
    expose.

    A signal with no source in ``config`` yields ``Baseline(value=..., samples=0)``
    only if it got readings; with no readings at all it is ``None``, which the
    domain grades as *insufficient* rather than as a fabricated ``0.0``.
    """
    want = spec.capture.samples
    window_s = duration_seconds(spec.capture.window)
    readings: dict[str, list[float]] = {str(s.name): [] for s in spec.signals}
    started = utc_now().timestamp()
    passed = False

    # One pass always runs, even under an exhausted window. `capture.samples`
    # says how many readings a *gradeable* baseline needs; it does not say the
    # tool may decline to look at all. A zero-length window therefore yields an
    # under-sampled capture — reported as insufficient — rather than an empty
    # one, which is a weaker and less informative failure.
    while True:
        if all(len(values) >= want for values in readings.values()):
            break
        if passed and utc_now().timestamp() - started >= window_s:
            break
        index = _collection_index(collector(config, engine=engine))
        passed = True
        for signal in spec.signals:
            for measurement in readings_for(signal, index.get(signal.source_id)):
                if measurement.value is not None:
                    readings[str(signal.name)].append(measurement.value)

    baselines: dict[str, Baseline | None] = {}
    notes: dict[str, str] = {}
    for signal in spec.signals:
        values = readings[str(signal.name)]
        baseline = sample_baseline(values, percentile=percentile)
        baselines[str(signal.name)] = baseline
        if len(values) < want:
            notes[str(signal.name)] = (
                f"captured {len(values)} of {want} declared samples within "
                f"{window_s:g}s: the baseline below is not gradeable"
            )
    return BaselineCapture(
        baselines=baselines,
        readings={name: tuple(values) for name, values in readings.items()},
        notes=notes,
    )


def baseline_from_run(
    store: Store,
    run_id: str,
    signal_names: Sequence[str],
) -> dict[str, Baseline]:
    """Reuse a previous healthy run's ``pre``-phase baselines (plan step 6).

    Reads the ``steady_state_evaluations`` rows the previous run wrote — no new
    storage, because the table already exists and already stores the captured
    baseline on every row. A ``pre``-phase row is preferred when the run
    declared one, because ``pre`` is the phase that means "before anything was
    injected"; any other phase's row for the same signal carries the *same*
    captured baseline, so a run whose spec asserts nothing pre-fault is still a
    usable reference. Requiring a ``pre`` row would silently exclude those runs,
    which is the majority of them.

    :raises BaselineUnavailableError: when *any* named signal has no retrievable
        baseline. Partial reuse is refused rather than half-applied: a baseline
        set missing one signal would grade that signal as insufficient while
        the others grade normally, and the resulting report would look like a
        mixed-provenance reference — which is exactly the "confidently wrong"
        outcome the whole tolerance model exists to prevent.
    """
    repository = SteadyStateEvaluationRepository(store)
    by_signal: dict[str, list[StoredEvaluation]] = {}
    for row in repository.load(run_id):
        by_signal.setdefault(row.check_id, []).append(row)

    out: dict[str, Baseline] = {}
    missing: list[str] = []
    for name in signal_names:
        rows = by_signal.get(name) or []
        rows.sort(key=lambda r: r.phase is not Phase.PRE)
        baseline = next((r.baseline for r in rows if r.baseline is not None), None)
        if baseline is None:
            missing.append(name)
            continue
        out[name] = baseline
    if missing:
        raise BaselineUnavailableError(
            f"run {run_id!r} has no retrievable steady-state baseline for "
            f"{missing}: its pre-phase evaluations are absent or carry no baseline. "
            "A previous run only becomes a reference once it has captured one"
        )
    return out


# -- evaluation ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PhaseEvaluation:
    """One graded assertion: one verb, one signal, one phase.

    ``verdict is None`` means the assertion was **not graded** — a missing or
    non-finite reading, or a baseline that never reached ``capture.samples``.
    ``passed`` is false for that case too: an ungraded assertion is never a pass.
    """

    phase: Phase
    check_id: str
    verb: AssertionVerb
    result: AssertionResult
    assertion: Assertion
    reading: float | None = None

    @property
    def verdict(self) -> Verdict | None:
        return self.result.verdict

    @property
    def passed(self) -> bool:
        return self.result.passed

    @property
    def graded(self) -> bool:
        return self.result.graded

    @property
    def signal(self) -> SignalResult:
        return self.result.signals[0]

    def unexplained_nulls(self) -> tuple[str, ...]:
        """Numeric slots that are ``None`` for no stated reason.

        ``after`` is ``None`` on a ``during``-phase assertion and ``during`` is
        ``None`` on a ``post``-phase one: those are *inapplicable*, not absent,
        and saying otherwise would force a note onto every healthy result. What
        must never happen is an applicable slot being ``None`` with nothing to
        explain it — an unexplained null in an evidence bundle is
        indistinguishable from a number somebody forgot to fill in.

        ``delta_pct`` is exempt when the baseline is zero: there the ``None`` is
        the answer, and :func:`mayhem.domain.steady_state.delta_pct`'s
        docstring is the note. Grading it as an unexplained absence would force
        the one case the domain handles correctly to look like a bug.
        """
        signal = self.signal
        out: list[str] = []
        if signal.baseline is None and not signal.note:
            out.append("baseline")
        if self.reading is None and not signal.note:
            out.append("reading")
        if signal.delta_pct is None and signal.baseline not in (None, 0.0) and not signal.note:
            out.append("delta_pct")
        return tuple(out)

    def to_dict(self) -> dict[str, Any]:
        payload = self.result.to_dict()
        payload["phase"] = self.phase.value
        payload["check_id"] = self.check_id
        payload["verb"] = self.verb.value
        payload["assertion"] = _assertion_payload(self.assertion)
        payload["reading"] = self.reading
        return payload


def _ungraded(
    *,
    phase: Phase,
    verb: AssertionVerb,
    name: str,
    assertion: Assertion,
    reading: float | None,
    note: str,
) -> PhaseEvaluation:
    """Build the verdict-``None`` result for an assertion that cannot be graded.

    Reproduces the shape :func:`classify` returns for insufficient data, and
    is used for the one case the domain does not cover: a *measurement* that is
    missing or non-finite while the baseline is fine.
    """
    result = AssertionResult(
        verdict=None,
        signals=(
            SignalResult(
                name=name,
                asserted=verb,
                baseline=None,
                during=reading if verb is not AssertionVerb.RECOVERED else None,
                after=reading,
                delta_pct=None,
                limit=None,
                within=assertion.within,
                passed=False,
                note=note,
                severity=assertion.severity,
            ),
        ),
        sufficient=False,
        note=note,
    )
    return PhaseEvaluation(
        phase=phase,
        check_id=name,
        verb=verb,
        result=result,
        assertion=assertion,
        reading=reading,
    )


def _assertion_payload(assertion: Assertion) -> dict[str, Any]:
    """The assertion's expectation, as plain JSON types.

    ``Assertion.to_dict()`` goes through :func:`dataclasses.asdict`, which
    leaves a pydantic field *as the model object* — ``expect`` and ``tolerance``
    are pydantic models, so the result is not serialisable and
    ``json.dumps(..., allow_nan=False)`` raises on it. That method is the
    domain's to fix and this module does not touch it; the bundle needs the
    expectation in a writable shape today, so the projection is built here from
    the same fields, flattening the two pydantic members explicitly.
    """
    return {
        "verb": assertion.verb.value,
        "name": assertion.name,
        "expect": None if assertion.expect is None else assertion.expect.model_dump(mode="json"),
        "tolerance": None
        if assertion.tolerance is None
        else assertion.tolerance.model_dump(mode="json"),
        "within": assertion.within,
        "required_samples": assertion.required_samples,
        "severity": assertion.severity.value,
    }


def evaluate_phase(
    spec: SteadyStateSpec,
    phase: Phase,
    readings: Mapping[str, float | None],
    *,
    baselines: Mapping[str, Baseline | None],
) -> tuple[PhaseEvaluation, ...]:
    """Grade every assertion declared for one phase.

    ``readings`` is ``signal name → measured value``. A value that is absent,
    ``None``, ``nan`` or ``inf`` is **not graded**: the reading is refused with
    a reason rather than handed to :func:`classify`, which would grade a
    non-finite measurement as ``degraded-beyond-tolerance`` and invent a verdict
    about a probe that returned nothing.

    Every other case goes straight to the domain: this function builds the
    :class:`Assertion` from the authored signal and the phase's ``within``, and
    lets :func:`classify` decide. It computes no bounds of its own.
    """
    required = spec.capture.samples
    out: list[PhaseEvaluation] = []
    for assertion_spec in spec.phases:
        for declared_phase, checks in assertion_spec.checks():
            if checks is None or declared_phase is not phase:
                continue
            out.extend(
                _grade_checks(spec, phase, checks, readings, baselines=baselines, required=required)
            )
    return tuple(out)


def _grade_checks(
    spec: SteadyStateSpec,
    phase: Phase,
    checks: PhaseChecks,
    readings: Mapping[str, float | None],
    *,
    baselines: Mapping[str, Baseline | None],
    required: int,
) -> list[PhaseEvaluation]:
    out: list[PhaseEvaluation] = []
    groups: tuple[tuple[AssertionVerb, tuple[str, ...]], ...] = (
        (AssertionVerb.UNCHANGED, tuple(checks.assert_unchanged)),
        (AssertionVerb.DEGRADED, tuple(checks.assert_degraded)),
        (AssertionVerb.RECOVERED, tuple(checks.assert_recovered)),
    )
    for verb, names in groups:
        for name in names:
            signal = spec.signal(name)
            if signal is None:  # pragma: no cover - the spec validator rejects this
                raise InvariantViolationError(
                    "steady_state.undeclared_signal",
                    f"phase {phase.value} asserts {verb.value} on {name!r}, which is not "
                    "declared in signals",
                )
            assertion = Assertion.for_signal(
                signal,
                verb,
                required_samples=required,
                within=checks.within,
            )
            raw = readings.get(name)
            if raw is None:
                out.append(
                    _ungraded(
                        phase=phase,
                        verb=verb,
                        name=name,
                        assertion=assertion,
                        reading=None,
                        note=MISSING_READING.format(name=name),
                    )
                )
                continue
            measured = coerce_finite(raw)
            if measured is None:
                out.append(
                    _ungraded(
                        phase=phase,
                        verb=verb,
                        name=name,
                        assertion=assertion,
                        reading=None,
                        note=NON_FINITE_READING.format(name=name, value=raw),
                    )
                )
                continue
            result = classify(measured, baselines.get(name), assertion)
            out.append(
                PhaseEvaluation(
                    phase=phase,
                    check_id=name,
                    verb=verb,
                    result=result,
                    assertion=assertion,
                    reading=measured,
                )
            )
    return out


#: Verdict precedence when a run produced more than one graded assertion.
#:
#: ``not-recovered`` outranks everything because chaos residue is a property of
#: the run, not of one signal. ``no-effect`` outranks
#: ``degraded-beyond-tolerance`` because both fail, but "the fault did nothing"
#: invalidates the drill while "a safety signal moved" is a finding *about the
#: target* — the first means the experiment proved nothing and the second means
#: it proved something alarming. Neither is a pass, so the ordering between them
#: never changes an outcome; it only decides which finding the report leads with.
_VERDICT_RANK: dict[Verdict, int] = {
    Verdict.AS_HYPOTHESISED: 1,
    Verdict.DEGRADED_WITHIN_TOLERANCE: 2,
    Verdict.DEGRADED_BEYOND_TOLERANCE: 3,
    Verdict.NO_EFFECT: 4,
    Verdict.NOT_RECOVERED: 5,
}


def aggregate_verdict(evaluations: Sequence[PhaseEvaluation]) -> Verdict | None:
    """Collapse every graded assertion into the run's one verdict.

    ``None`` when nothing was graded — every assertion insufficient. That is
    distinct from ``as-hypothesised``: a run where nothing could be measured
    has not shown the steady state held, it has shown nothing.
    """
    graded = [e.verdict for e in evaluations if e.verdict is not None]
    if not graded:
        return None
    return max(graded, key=lambda verdict: _VERDICT_RANK[verdict])


@dataclass(frozen=True, slots=True)
class SteadyStateReport:
    """Everything one run's steady-state block produced."""

    run_id: str
    capture: BaselineCapture
    evaluations: tuple[PhaseEvaluation, ...] = ()
    cross_check: ImpactCrossCheck | None = None
    baseline_from: str = ""

    @property
    def verdict(self) -> Verdict | None:
        return aggregate_verdict(self.evaluations)

    @property
    def passed(self) -> bool:
        """True when every graded assertion held.

        Deliberately **not** "the verdict is ``as-hypothesised``". Those are
        different questions: the verdict describes what the fault did, and
        ``degraded-within-tolerance`` is the *correct* description of a fault
        that moved a signal by a bounded amount. Gating the run on it would
        report a healthy, bounded, fully-recovered drill as a failure — which
        would make the tool refuse to grade the one case it exists to grade.

        The failures that do block a run each set ``passed=False`` on their own
        assertion: ``no-effect`` because the fault proved nothing, and
        ``not-recovered`` / ``degraded-beyond-tolerance`` because a bound was
        broken. An ungraded assertion is false too, so a run that could not
        measure anything never passes.
        """
        if self.verdict is None or not self.evaluations:
            return False
        return all(e.passed for e in self.evaluations)

    @property
    def recovered(self) -> bool:
        """Did every ``assert_recovered`` signal come back to its baseline?"""
        recovery = [e for e in self.evaluations if e.verb is AssertionVerb.RECOVERED]
        return bool(recovery) and all(e.passed for e in recovery)

    @property
    def max_recovery_delta_pct(self) -> float | None:
        """Largest absolute recovery delta, or ``None`` when nothing was graded.

        ``None`` — not ``0.0`` — because a recovery report that cannot be
        measured has no maximum, and a zero would read as "it came back
        exactly", which is a claim this tool cannot make.
        """
        deltas = [
            abs(s.delta_pct)
            for e in self.evaluations
            if e.verb is AssertionVerb.RECOVERED
            for s in e.result.signals
            if s.delta_pct is not None
        ]
        return max(deltas) if deltas else None

    def by_phase(self, phase: Phase) -> tuple[PhaseEvaluation, ...]:
        return tuple(e for e in self.evaluations if e.phase is phase)

    def ungraded(self) -> tuple[PhaseEvaluation, ...]:
        return tuple(e for e in self.evaluations if not e.graded)

    def findings(self) -> tuple[PhaseEvaluation, ...]:
        return tuple(e for e in self.evaluations if e.graded and not e.passed)

    def bundle_payload(self) -> dict[str, Any]:
        """The bundle-safe projection.

        Every numeric field is either a finite float or ``None``. A ``None``
        carries the ``note`` explaining the absence, because an unexplained
        null in an evidence bundle is indistinguishable from a number somebody
        forgot to fill in.

        This is safe to serialise with ``allow_nan=False``: see
        :func:`assert_bundle_safe`, and the test that proves a zero baseline
        does not smuggle an ``inf`` into the payload.
        """
        unexplained = [
            f"{e.phase.value}/{e.verb.value}/{e.check_id}:{slot}"
            for e in self.evaluations
            for slot in e.unexplained_nulls()
        ]
        if unexplained:
            raise InvariantViolationError(
                "steady_state.unexplained_null",
                f"steady-state payload has numeric slots that are null with no reason "
                f"given: {unexplained}. An unexplained null in a bundle cannot be told "
                "apart from a measurement nobody took",
            )
        return {
            "schema_version": "1.0",
            "run_id": self.run_id,
            "baseline_from": self.baseline_from,
            "verdict": None if self.verdict is None else self.verdict.value,
            "graded": self.verdict is not None,
            "passed": self.passed,
            "recovered": self.recovered,
            "max_recovery_delta_pct": self.max_recovery_delta_pct,
            "capture": self.capture.to_dict(),
            "evaluations": [e.to_dict() for e in self.evaluations],
            "ungraded": [e.check_id for e in self.ungraded()],
            "findings": [
                {
                    "phase": e.phase.value,
                    "check_id": e.check_id,
                    "verdict": None if e.verdict is None else e.verdict.value,
                    "note": e.signal.note,
                }
                for e in self.findings()
            ],
            "impact_cross_check": (
                None if self.cross_check is None else self.cross_check.to_dict()
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        return self.bundle_payload()


def assert_bundle_safe(payload: Any) -> None:
    """Refuse a payload that could not be read by a strict JSON parser.

    ``json.dumps(..., allow_nan=False)`` raises ``ValueError`` on ``inf`` and
    ``nan`` — the two literals ``json.dumps`` will otherwise happily emit as
    bare ``Infinity`` and ``NaN`` tokens, which are not valid JSON and which a
    reader of a hash-chained bundle has no way to interpret.

    This is the *last* gate before a verdict is written or bundled, and it is
    deliberately a raise rather than a coercion: a payload that cannot be
    serialised strictly is a bug in the payload, and silently replacing a
    number with a placeholder is how a bundle starts lying.
    """
    try:
        json.dumps(payload, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise InvariantViolationError(
            "steady_state.bundle_not_json_safe",
            f"steady-state payload is not strictly serialisable: {exc}. A number a "
            "strict parser cannot read must never enter a hash-chained evidence "
            "bundle — the fix is upstream, not a coercion here",
        ) from exc


def evaluate_run(
    spec: SteadyStateSpec,
    *,
    run_id: str,
    capture: BaselineCapture,
    during: Mapping[str, float | None] | None = None,
    post: Mapping[str, float | None] | None = None,
    pre: Mapping[str, float | None] | None = None,
    baseline_from: str = "",
    bypasses: Mapping[tuple[str, str], str] | None = None,
) -> SteadyStateReport:
    """Grade a whole run's steady-state block across all three phases.

    ``pre`` readings default to each signal's own captured baseline value: that
    is the only reading that exists before injection, and a ``pre``
    ``assert_unchanged`` that trivially holds against itself is still worth
    running — it is how a drill catches a target that was *already* outside its
    steady state before mayhem touched it.

    ``bypasses`` is the impact gate's own output
    (:func:`mayhem.agents.impact.bypass_from_verdicts`). When supplied, the
    ``during`` result is cross-checked against it (see :func:`cross_check_gate`).
    """
    baselines = capture.baselines
    pre_readings: dict[str, float | None] = dict(pre or {})
    for name, baseline in baselines.items():
        pre_readings.setdefault(name, None if baseline is None else baseline.value)

    evaluations = [
        *evaluate_phase(spec, Phase.PRE, pre_readings, baselines=baselines),
        *evaluate_phase(spec, Phase.DURING, dict(during or {}), baselines=baselines),
        *evaluate_phase(spec, Phase.POST, dict(post or {}), baselines=baselines),
    ]
    report = SteadyStateReport(
        run_id=run_id,
        capture=capture,
        evaluations=tuple(evaluations),
        baseline_from=baseline_from,
    )
    if bypasses:
        return replace_cross_check(report, cross_check_gate(bypasses, report.evaluations))
    return report


def replace_cross_check(
    report: SteadyStateReport, cross_check: ImpactCrossCheck
) -> SteadyStateReport:
    return SteadyStateReport(
        run_id=report.run_id,
        capture=report.capture,
        evaluations=report.evaluations,
        cross_check=cross_check,
        baseline_from=report.baseline_from,
    )


# -- step 5: the impact-gate cross-check ---------------------------------------------


class GateAgreement(StrEnum):
    """How the impact gate's verdict compares with what was observed.

    ``UNVERIFIED`` is a real third answer, not a courtesy: a drill that asserts
    no ``degraded`` signal, or one whose baseline never reached
    ``capture.samples``, cannot confirm *or* contradict the gate. Reporting
    those as "confirmed" would manufacture a self-check that never ran.
    """

    CONFIRMED = "confirmed"
    CONTRADICTED = "contradicted"
    UNVERIFIED = "unverified"


@dataclass(frozen=True, slots=True)
class GateFinding:
    """One bypassed fault, checked against what the run actually measured."""

    fault_id: str
    container: str
    agreement: GateAgreement
    reason: str
    signals: tuple[str, ...] = ()
    deltas_pct: dict[str, float | None] = field(default_factory=dict)

    @property
    def contradicted(self) -> bool:
        return self.agreement is GateAgreement.CONTRADICTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "fault_id": self.fault_id,
            "container": self.container,
            "agreement": self.agreement.value,
            "reason": self.reason,
            "signals": list(self.signals),
            "deltas_pct": dict(self.deltas_pct),
        }

    def loud_line(self) -> str:
        """The operator-facing line. A contradiction leads with the word CONTRADICTED.

        The gate's own claim is "this fault cannot perturb this container, so I
        skipped it". A baseline that then shows the signal moved means the gate
        is wrong. That is a bug in mayhem, not a note in a report nobody reads,
        so it is surfaced with a marker rather than folded into a summary.
        """
        if self.agreement is GateAgreement.CONTRADICTED:
            moved = ", ".join(
                f"{name} {self.deltas_pct.get(name):+.1f}%"
                for name in self.signals
                if self.deltas_pct.get(name) is not None
            )
            return (
                f"IMPACT GATE CONTRADICTED: {self.fault_id} on {self.container} was "
                f"bypassed as inert ({self.reason}) but the signal moved during the "
                f"fault [{moved or 'delta unquantifiable'}]. The gate's inert verdict is "
                "wrong and the bypass was unsound"
            )
        if self.agreement is GateAgreement.CONFIRMED:
            return (
                f"impact gate confirmed: {self.fault_id} on {self.container} bypassed as "
                f"inert ({self.reason}) and no asserted signal moved"
            )
        return (
            f"impact gate unverified: {self.fault_id} on {self.container} bypassed as "
            f"inert ({self.reason}) but this drill asserts no measurable degraded signal, "
            "so the bypass can be neither confirmed nor contradicted"
        )


@dataclass(frozen=True, slots=True)
class ImpactCrossCheck:
    """Every bypassed fault, checked against the run's own ``during`` result."""

    findings: tuple[GateFinding, ...] = ()

    @property
    def ok(self) -> bool:
        """True when the gate is not contradicted.

        A run with nothing to check is ``ok`` — vacuously true is the right
        answer, and distinct from ``confirmed``.
        """
        return not self.contradicted

    @property
    def contradicted(self) -> tuple[GateFinding, ...]:
        return tuple(f for f in self.findings if f.contradicted)

    @property
    def confirmed(self) -> tuple[GateFinding, ...]:
        return tuple(f for f in self.findings if f.agreement is GateAgreement.CONFIRMED)

    @property
    def unverified(self) -> tuple[GateFinding, ...]:
        return tuple(f for f in self.findings if f.agreement is GateAgreement.UNVERIFIED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checked": len(self.findings),
            "confirmed": [f.fault_id for f in self.confirmed],
            "contradicted": [f.to_dict() for f in self.contradicted],
            "unverified": [f.fault_id for f in self.unverified],
        }

    def loud_lines(self) -> tuple[str, ...]:
        return tuple(f.loud_line() for f in self.contradicted)


def _moved(baseline: float | None, measured: float | None) -> bool:
    """Did a graded signal move, using the domain's published epsilon?

    ``UNCHANGED_EPSILON`` is the domain's own statement of what "did not move"
    means; re-deriving it here would let the cross-check disagree with
    ``classify`` about the same pair of numbers, which is how a run reports
    "confirmed" and "moved" in the same breath.
    """
    if baseline is None or measured is None:
        return False
    if not isfinite(baseline) or not isfinite(measured):
        return True
    return abs(measured - baseline) > abs(baseline) * UNCHANGED_EPSILON


def cross_check_gate(
    bypasses: Mapping[tuple[str, str], str],
    evaluations: Sequence[PhaseEvaluation],
    *,
    phase: Phase = Phase.DURING,
) -> ImpactCrossCheck:
    """Check the impact gate's bypasses against what the run measured.

    ``bypasses`` is exactly what
    :func:`mayhem.agents.impact.bypass_from_verdicts` returns —
    ``{(fault_id, container): reason}`` for every fault the gate *proved* inert
    and therefore skipped. The gate's claim is currently only printed.

    With a baseline it becomes checkable, and this is the check:

    * gate says inert, no asserted signal moved ⇒ **confirmed**. The bypass was
      right, and now that is evidence rather than inference.
    * gate says inert, an asserted signal moved ⇒ **contradicted**. Either the
      gate is wrong about this fault, or the fault moved something the drill
      did not attribute to it. Both are findings about mayhem, and both are
      reported at ``GateFinding.loud_line`` with the leading word
      ``IMPACT GATE CONTRADICTED``.
    * gate says inert, nothing was measurable ⇒ **unverified**. The honest
      third answer; never reported as confirmed.

    The comparison is made against the ``assert_degraded`` signals only, since
    those are the fault's own hypothesis. A *safety* signal
    (``assert_unchanged``) moving while a fault is bypassed means something the
    fault did not do moved, which is a different question and is not what the
    gate claimed.
    """
    degraded = [
        e for e in evaluations if e.phase is phase and e.verb is AssertionVerb.DEGRADED and e.graded
    ]
    findings: list[GateFinding] = []
    for (fault_id, container), reason in sorted(bypasses.items()):
        moved = [e for e in degraded if _moved(e.signal.baseline, e.signal.during)]
        if not degraded:
            findings.append(
                GateFinding(
                    fault_id=fault_id,
                    container=container,
                    agreement=GateAgreement.UNVERIFIED,
                    reason=reason,
                )
            )
        elif moved:
            findings.append(
                GateFinding(
                    fault_id=fault_id,
                    container=container,
                    agreement=GateAgreement.CONTRADICTED,
                    reason=reason,
                    signals=tuple(e.check_id for e in moved),
                    deltas_pct={e.check_id: e.signal.delta_pct for e in moved},
                )
            )
        else:
            findings.append(
                GateFinding(
                    fault_id=fault_id,
                    container=container,
                    agreement=GateAgreement.CONFIRMED,
                    reason=reason,
                    signals=tuple(e.check_id for e in degraded),
                    deltas_pct={e.check_id: e.signal.delta_pct for e in degraded},
                )
            )
    return ImpactCrossCheck(findings=tuple(findings))


# -- persistence ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StoredEvaluation:
    """One row of ``steady_state_evaluations``, read back.

    ``phase`` is a :class:`~mayhem.domain.steady_state.Phase`, whose values are
    exactly ``pre``/``during``/``post`` so that a round-tripped phase satisfies
    the table's own ``CHECK`` constraint without translation.
    """

    check_id: str
    phase: Phase
    passed: bool
    measured: dict[str, Any]
    expectation: dict[str, Any]
    evaluated_at: str = ""

    @property
    def verb(self) -> AssertionVerb:
        return AssertionVerb(str(self.expectation.get("verb", AssertionVerb.DEGRADED.value)))

    @property
    def baseline(self) -> Baseline | None:
        """The baseline this evaluation was graded against, if it recorded one."""
        raw = self.measured.get("baseline")
        if not isinstance(raw, dict):
            return None
        value = coerce_finite(raw.get("value"))
        samples = raw.get("samples")
        if value is None or not isinstance(samples, int):
            return None
        return Baseline(value=value, samples=samples)

    @property
    def verdict(self) -> Verdict | None:
        raw = self.expectation.get("verdict")
        if raw is None:
            return None
        try:
            return Verdict(str(raw))
        except ValueError:
            return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "phase": self.phase.value,
            "passed": self.passed,
            "measured": dict(self.measured),
            "expectation": dict(self.expectation),
            "evaluated_at": self.evaluated_at,
        }


class SteadyStateEvaluationRepository:
    """Writes graded evaluations into the existing ``steady_state_evaluations`` table.

    The schema already exists (``infra/migrations.py``, with
    ``CHECK (phase IN ('pre','during','post'))``) and nothing wrote it. No
    migration is added: ``measured_json`` carries the reading and the baseline
    it was graded against, ``expectation_json`` carries the assertion and the
    verdict, and ``Phase``'s values satisfy the constraint by construction.

    Every payload passes :func:`assert_bundle_safe` before it is written, so a
    non-finite number can never be *stored*, let alone bundled later.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def save(self, report: SteadyStateReport) -> int:
        """Persist every evaluation on ``report``. Returns the row count."""
        rows = 0
        evaluated_at = utc_now().isoformat()
        with self._store.write() as conn:
            for evaluation in report.evaluations:
                measured = {
                    "reading": evaluation.reading,
                    "baseline": _baseline_of(report.capture, evaluation.check_id),
                    "result": evaluation.signal.to_dict(),
                }
                expectation = {
                    "verb": evaluation.verb.value,
                    "assertion": _assertion_payload(evaluation.assertion),
                    "verdict": None if evaluation.verdict is None else evaluation.verdict.value,
                    "sufficient": evaluation.result.sufficient,
                    "passed": evaluation.passed,
                    "note": evaluation.result.note,
                }
                assert_bundle_safe(measured)
                assert_bundle_safe(expectation)
                conn.execute(
                    "INSERT OR REPLACE INTO steady_state_evaluations "
                    "(id, run_id, check_id, phase, passed, measured_json, "
                    "expectation_json, evaluated_at) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        f"{report.run_id}:{evaluation.phase.value}:{evaluation.verb.value}"
                        f":{evaluation.check_id}",
                        report.run_id,
                        evaluation.check_id,
                        evaluation.phase.value,
                        1 if evaluation.passed else 0,
                        json.dumps(measured, sort_keys=True),
                        json.dumps(expectation, sort_keys=True),
                        evaluated_at,
                    ),
                )
                rows += 1
        return rows

    def load(self, run_id: str) -> tuple[StoredEvaluation, ...]:
        """Read a run's evaluations back, in insertion order."""
        rows = self._store.query(
            "SELECT check_id, phase, passed, measured_json, expectation_json, evaluated_at "
            "FROM steady_state_evaluations WHERE run_id = ? ORDER BY rowid",
            (run_id,),
        )
        out: list[StoredEvaluation] = []
        for row in rows:
            record = dict(row)
            try:
                measured = json.loads(str(record.get("measured_json") or "{}"))
                expectation = json.loads(str(record.get("expectation_json") or "{}"))
            except ValueError:
                continue
            if not isinstance(measured, dict) or not isinstance(expectation, dict):
                continue
            try:
                phase = Phase(str(record.get("phase")))
            except ValueError:
                continue
            out.append(
                StoredEvaluation(
                    check_id=str(record.get("check_id") or ""),
                    phase=phase,
                    passed=bool(record.get("passed")),
                    measured=measured,
                    expectation=expectation,
                    evaluated_at=str(record.get("evaluated_at") or ""),
                )
            )
        return tuple(out)


def _baseline_of(capture: BaselineCapture, check_id: str) -> dict[str, Any] | None:
    """The *captured* baseline behind one evaluation, or ``None`` when there is none.

    Taken from the capture rather than recomputed, and the sample count comes
    with it. That count is load-bearing: ``--baseline-from`` restores this row
    and grades the next run against it, and a baseline restored with the
    *required* count rather than the *captured* one would grade as sufficient
    on two samples that were never sufficient. A non-finite captured value is
    refused here exactly as it is at capture time.
    """
    baseline = capture.baselines.get(check_id)
    if baseline is None:
        return None
    value = coerce_finite(baseline.value)
    if value is None:
        return None
    return {"value": value, "samples": baseline.samples}
