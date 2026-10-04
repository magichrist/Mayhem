"""The probe *engine*: best-effort collection, and continuous stop-condition
evaluation over what was actually recorded
(docs/v1.1.0/11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md, Phase 2).

Phase 1 (:mod:`mayhem.domain.probes` and :mod:`mayhem.domain.stop_conditions`)
wrote down what a probe *is* and what a firing *must cite*. Nothing ran either.
This module runs them: it binds a plan to a catalogue, collects through injected
ports, turns readings into the domain's own
:class:`~mayhem.domain.stop_conditions.Sample`, evaluates stop conditions over
the recorded stream, and hands a fired condition to plan 10's stop path through
the function plan 10 already wrote for exactly that.

It adds no comparison, no tolerance arithmetic and no verdict of its own. Every
question about "is this value within its bound" is answered by
:meth:`mayhem.domain.stop_conditions.Condition.evaluate`, and every question
about "what does a firing cause" is answered by
:func:`mayhem.controller.stop_engine.command_for_firing`. This module's whole
contribution is the question neither of those can answer: **was there anything
to evaluate at all**, said plainly when there was not.

The load-bearing property
-------------------------

**A probe that could not be asked is ``UNAVAILABLE``, and ``UNAVAILABLE`` is
never evidence of health.** This is the same rule
:mod:`mayhem.controller.preflight_gate` states for its five ports — an unbound
port, a port that raises, a port that answers ``None``, and a port that answers
in the wrong shape are one finding, not four — and it is enforced here by the
same three-part structure:

* :class:`ProbePorts` holds injected :class:`ProbeReadingPort` values keyed by
  :class:`~mayhem.domain.probes.ProbeFamily`, and *absent* means *no way to ask*.
  There is intentionally no "no ports configured, assume healthy" default:
  **that default is the bug this module exists to remove.**
* :func:`reading_status` reduces every way a port can fail to answer to
  :data:`ProbeAvailability.UNAVAILABLE`, and :func:`refuses_probe` returns
  ``True`` for everything that is not
  :data:`~mayhem.controller.probe_service.ProbeAvailability.AVAILABLE`. The rule
  lives in exactly one expression, so a third availability cannot be added
  without that function being forced to decide about it.
* :class:`ProbeCoverage` then answers the question an operator actually asks —
  *may this run's observations support a verdict?* — and its
  :attr:`~ProbeCoverage.observations_usable` is ``False`` when no graded probe
  produced any available reading at all. A probe whose collection failed
  throughout cannot support a passing verdict, because there is no observation
  behind the claim.

Why "unavailable" and not "unhealthy"
-------------------------------------

The two words are different findings and are kept apart on purpose.
``UNAVAILABLE`` says *mayhem has no witness* — a wiring problem, an unbound port,
a collector that threw. It is not a statement about the system under test. A
Redis family with no bound port says nothing whatsoever about whether Redis is
fine; it says mayhem declined to look. :class:`ProbeReading` carries the two
apart (``availability`` versus ``observation``), so a report cannot render "the
Redis probe found nothing wrong" from a port that was never bound.

Collection never raises
-----------------------

Every collection path returns a :class:`ProbeReading`; none propagates an
exception. This is the existing collector's rule
(:mod:`mayhem.controller.observability_collector` — *evidence gathering must
never break the drill*) extended to the plan's lifecycle, and the failure is
**recorded**, not swallowed: a failed collection produces an ``UNAVAILABLE``
reading carrying the reason, which is what lets Phase 4 seal "the run watched
nothing" as a fact rather than inferring it later from an absent verdict.

Two things this module deliberately does **not** do
--------------------------------------------------

* **It does not read a clock.** ``at_epoch_s`` is passed in on every call, for
  the reason :class:`~mayhem.controller.preflight_gate.PreflightInputs` has no
  default for ``now``: a verdict whose content depends on when it was computed
  must make the moment a chosen input, or a test cannot pin it. The engine is
  deterministic given the same ports and the same arguments.
* **It does not turn a window that ran out into an answer.** A stop condition
  watched past ``max_duration`` reports
  :attr:`~mayhem.domain.stop_conditions.ConditionStatus.EXPIRED` from the
  domain, and this module surfaces that verbatim rather than translating it into
  either a firing or a clean bill of health. **A timeout means "we did not
  look", and it is never reported as "we looked and saw nothing."**
  :meth:`ProbeService.evaluate` returns the domain's result unchanged;
  :class:`ProbeCoverage` is the only thing here that may say anything about the
  system, and only when something was observed.

Adding the plan's third-party signal connectors is Phase 3's work and does not
belong here: this module speaks to :class:`~mayhem.domain.probes.ProbeFamily`,
not to any vendor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.observations import ObservationResult
from mayhem.domain.probe_evidence import ReadingView
from mayhem.domain.probes import (
    LifecycleStage,
    ProbeCatalog,
    ProbeDefinition,
    ProbeFamily,
    ProbePlan,
)
from mayhem.domain.stop_conditions import Condition, ConditionResult, Firing, Sample

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

__all__ = [
    "RULE_COVERAGE_INCOMPLETE",
    "RULE_PORT_SHAPE",
    "RULE_READING_AVAILABILITY",
    "RULE_READING_EVIDENCE_REF",
    "ProbeAvailability",
    "ProbeCoverage",
    "ProbeObservation",
    "ProbePorts",
    "ProbeReading",
    "ProbeReadingPort",
    "ProbeService",
    "as_observation_result",
    "command_for",
    "is_measurement",
    "metric_name_for",
    "reading_status",
    "reading_view",
    "refuses_port_shape",
    "refuses_probe",
]


# =============================================================================
# Availability: the word that keeps "mayhem did not look" apart from "fine"
# =============================================================================


class ProbeAvailability(StrEnum):
    """What one collection attempt came back with. Two members and no more."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


def refuses_probe(availability: ProbeAvailability) -> bool:
    """True for every availability that may not support a verdict. Total over the enum.

    Written ``is not AVAILABLE`` rather than as a membership test, so an
    unrecognised availability arriving from a port refuses rather than passes by
    omission — the same reasoning as
    :func:`mayhem.controller.preflight_gate.refuses_gate`, and for the same
    reason: the rule *no witness means no certificate* must not be a default
    somebody can widen.
    """
    return availability is not ProbeAvailability.AVAILABLE


# =============================================================================
# Ports: the systems mayhem cannot answer for
# =============================================================================


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    """One port's answer, in the only shape a port is allowed to answer in.

    Uniform on purpose, for the reason
    :class:`~mayhem.controller.preflight_gate.PortObservation` is: if each port
    returned its own type, *the port did not answer* would become
    indistinguishable from *the port answered with an empty result*, and that
    distinction is the safety property. A Prometheus connector answering ``0``
    has certified a measurement of zero; a Prometheus connector that could not be
    reached has certified nothing at all.

    ``value=None`` is a refusal by the port, not a measurement of nothing: it
    becomes :data:`ProbeAvailability.UNAVAILABLE`. Every field is required except
    ``detail``, and a blank one is refused at construction for the reason a blank
    ``evidence_ref`` is refused in the preflight gate — a reading that cannot say
    where it came from is not evidence.
    """

    value: float | None
    unit: str
    provenance: str
    evidence_ref: str
    detail: str = ""

    def __post_init__(self) -> None:
        for name, value in (
            ("unit", self.unit),
            ("provenance", self.provenance),
            ("evidence_ref", self.evidence_ref),
        ):
            if not value.strip():
                raise InvariantViolationError(
                    RULE_READING_EVIDENCE_REF,
                    f"a probe observation carries a blank {name}: a reading that "
                    "cannot say where it came from is not a reading, and a blank "
                    "field here would be indistinguishable from a port that said "
                    "nothing at all",
                )


@runtime_checkable
class ProbeReadingPort(Protocol):
    """The one contract a probe collector must satisfy.

    Deliberately family-agnostic. Eighteen probe families do not mean eighteen
    port protocols: a port is handed a :class:`~mayhem.domain.probes.ProbeDefinition`
    and answers with a :class:`ProbeObservation` about whatever that definition
    points at. Splitting this per family would rebuild the probe hierarchy
    :mod:`mayhem.domain.probes` exists to avoid, one layer up.

    ``name`` is a read-only property rather than a settable attribute because two
    of the implementations in this codebase compute it
    (:class:`mayhem.controller.probe_integrations.ConnectorProbePort` derives it
    from the connector and the client), and a protocol that demanded a setter
    would force the derived name to be restated — which is how a port's reported
    name and the port it actually is drift apart.
    """

    @property
    def name(self) -> str:  # pragma: no cover
        """How this port names itself in the note of an ``UNAVAILABLE`` reading."""
        ...

    def observe(self, definition: ProbeDefinition) -> ProbeObservation | None:  # pragma: no cover
        """One reading for ``definition``, or ``None`` for *I cannot say*."""
        ...


@dataclass(frozen=True, slots=True)
class ProbePorts:
    """Which probe families mayhem has a way to ask.

    Absent means *unavailable*, which refuses. The mapping is keyed by
    :class:`~mayhem.domain.probes.ProbeFamily` rather than by attribute name
    because the families are the plan's own vocabulary and the set is open as
    the catalogue grows.
    """

    ports: Mapping[ProbeFamily, ProbeReadingPort] = field(default_factory=dict)

    def for_family(self, family: ProbeFamily) -> ProbeReadingPort | None:
        """The port for ``family``, or ``None`` when mayhem has no way to ask."""
        return self.ports.get(family)

    def bound(self) -> tuple[ProbeFamily, ...]:
        """The families this configuration can actually read, in catalogue order."""
        return tuple(family for family in ProbeFamily if family in self.ports)

    def unbound(self, required: Iterable[ProbeFamily]) -> tuple[ProbeFamily, ...]:
        """The families in ``required`` with no port, in the family's own order.

        The reporting half of the port discipline: an operator asking *what could
        this run not see?* gets the answer as a list of family names, in the
        plan's own vocabulary, rather than by discovering it later from an absent
        verdict.
        """
        wanted = set(required)
        return tuple(
            family for family in ProbeFamily if family in wanted and family not in self.ports
        )


def refuses_port_shape(answer: object) -> bool:
    """Is this not a :class:`ProbeObservation`?

    A single predicate for the one rule, consulted by both layers that enforce
    it: :func:`reading_status` turns a wrong shape into ``UNAVAILABLE`` (the
    engine's no-raise contract), and :func:`as_observation_result` raises the
    named rule if anything ever hands it one anyway. Stated once so the two
    cannot drift, and named rather than inlined so the refusal is assertable
    from a test rather than only observable by breaking a port.

    **Total over ``object``**, not over :class:`ProbeObservation`, because the
    thing being judged is precisely the possibility that a port answered with
    something else.
    """
    return not isinstance(answer, ProbeObservation)


def is_measurement(value: float | None) -> bool:
    """Is this a finite number, i.e. a measurement at all?

    ``nan`` is not ``None``, so a ``value is not None`` check would sail it
    through as a reading and every comparison against it would be a comparison
    against nothing. Consulting one predicate from both :func:`reading_status`
    and :func:`as_observation_result` keeps the refusal in one place.
    """
    return value is not None and isfinite(value)


def reading_status(
    observation: ProbeObservation | None,
    *,
    error: BaseException | None = None,
) -> tuple[ProbeAvailability, str]:
    """The availability a port answer implies — a pure function of its two arguments.

    Six ways to have no answer, and exactly one way to have one:

    * ``error is not None`` — the port raised.
    * ``observation is None`` — the port declined to answer.
    * the answer is not a :class:`ProbeObservation` — a broken adapter.
    * ``observation.value is None`` — an answer carrying no value, which is a
      refusal to measure rather than a measurement.
    * the value is not finite — ``nan`` or ``inf``, which measured nothing.
    * otherwise — the port measured, and :data:`ProbeAvailability.AVAILABLE` is
      the only answer this function gives.

    Returns the availability **and** the reason it applies, so an ``UNAVAILABLE``
    reading names which silence it was rather than reporting one undifferentiated
    one. **Six silences, one availability**, and no sixth member of
    :class:`ProbeAvailability` — because the whole point of the enum having two
    members is that the *reasons* multiply while the *answer* does not.
    """
    # ``error`` is checked before the ``None`` answer, in the same order as
    # :func:`mayhem.controller.preflight_gate.port_status`, so a raising port is
    # named as a raising port rather than flattened into the generic "no
    # observation" — the reader learns which silence it was.
    if error is not None:
        return (
            ProbeAvailability.UNAVAILABLE,
            f"port raised {type(error).__name__}: mayhem could not read this probe",
        )
    if observation is None:
        return (
            ProbeAvailability.UNAVAILABLE,
            "port returned no observation: mayhem has no witness for this probe",
        )
    if refuses_port_shape(observation):
        return (
            ProbeAvailability.UNAVAILABLE,
            f"port answered with a {type(observation).__name__}, not a ProbeObservation: "
            "mayhem has one shape for a port's answer, so a broken adapter is reported as "
            "a broken adapter rather than read as an outage of the thing it watches",
        )
    if observation.value is None:
        return (
            ProbeAvailability.UNAVAILABLE,
            f"port answered with no value ({observation.detail or observation.evidence_ref}): "
            "a connector that could not resolve the measurement is not a measurement of zero",
        )
    if not is_measurement(observation.value):
        return (
            ProbeAvailability.UNAVAILABLE,
            f"port answered with {observation.value!r}, which is not a finite number: a "
            "collector that returned nan or inf measured nothing, and this is recorded as "
            "an absence rather than graded",
        )
    return (ProbeAvailability.AVAILABLE, observation.detail)


# =============================================================================
# Readings: what one collection attempt produced
# =============================================================================


@dataclass(frozen=True, slots=True)
class ProbeReading:
    """One collection attempt: its verdict, and the observation behind it.

    **An ``UNAVAILABLE`` reading carries no observation, and an ``AVAILABLE``
    one carries nothing else.** Both directions are refused at construction, so
    the two cannot drift into a record that claims availability while holding no
    witness — which is precisely the shape that renders as *healthy* in a report.

    ``definition_stages`` is carried rather than looked up, so
    :attr:`supports_verdict` answers from the *definition that was collected*
    rather than from whatever catalogue happens to be current when the reading is
    graded. The excluded stages are
    :attr:`~mayhem.domain.probes.LifecycleStage.WARM_UP` and
    :attr:`~mayhem.domain.probes.LifecycleStage.AFTER_RECOVERY` — the two
    budgeted settling windows — spelled here because
    :func:`mayhem.domain.probes.graded_stages` takes a definition and this is a
    reading; the *set* is the domain's, not a second policy.
    """

    probe_id: str
    family: ProbeFamily
    stage: LifecycleStage
    at_epoch_s: float
    availability: ProbeAvailability
    definition_stages: tuple[LifecycleStage, ...]
    observation: ObservationResult | None = None
    note: str = ""
    evidence_ref: str = ""

    def __post_init__(self) -> None:
        if not self.probe_id.strip():
            raise InvariantViolationError(
                RULE_READING_EVIDENCE_REF,
                "a probe reading carries a blank probe id: a reading that cannot be "
                "named cannot be reported",
            )
        if not isfinite(self.at_epoch_s):
            raise InvariantViolationError(
                RULE_READING_AVAILABILITY,
                f"probe reading for {self.probe_id!r} has a non-finite recording time "
                f"({self.at_epoch_s!r}): a sample that cannot be placed on a timeline "
                "cannot satisfy debounce, cooldown or the observation window",
            )
        available = self.availability is ProbeAvailability.AVAILABLE
        if available and self.observation is None:
            raise InvariantViolationError(
                RULE_READING_AVAILABILITY,
                f"probe {self.probe_id!r} is available but carries no observation: an "
                "available reading with no witness behind it is the one shape that reads "
                "as healthy in a report",
            )
        if not available and self.observation is not None:
            raise InvariantViolationError(
                RULE_READING_AVAILABILITY,
                f"probe {self.probe_id!r} is unavailable but carries an observation: an "
                "unavailable reading that still holds a value would be graded against "
                "evidence mayhem has already said it does not have",
            )

    @property
    def available(self) -> bool:
        return self.availability is ProbeAvailability.AVAILABLE

    @property
    def refuses(self) -> bool:
        """Whether this reading, on its own, may not support a verdict."""
        return refuses_probe(self.availability)

    @property
    def in_settling_stage(self) -> bool:
        """Was this reading taken in a budgeted settling window?"""
        return self.stage in SETTLING_STAGES

    @property
    def supports_verdict(self) -> bool:
        """May this reading be graded?

        No if it is unavailable, and no if it was taken in a settling stage.
        Excluding warm-up is not a criticism of the reading: those windows exist
        so noise is *budgeted* rather than discovered mid-verdict, and grading
        them is the failure the plan names.
        """
        return self.available and not self.in_settling_stage

    def to_dict(self) -> dict[str, object]:
        return {
            "probe_id": self.probe_id,
            "family": self.family.value,
            "stage": self.stage.value,
            "at_epoch_s": self.at_epoch_s,
            "availability": self.availability.value,
            "supports_verdict": self.supports_verdict,
            "evidence_ref": self.evidence_ref,
            "note": self.note,
            "observation": None if self.observation is None else self.observation.to_dict(),
        }


#: The two budgeted settling stages, from the plan's own lifecycle.
SETTLING_STAGES: tuple[LifecycleStage, ...] = (
    LifecycleStage.WARM_UP,
    LifecycleStage.AFTER_RECOVERY,
)


def metric_name_for(definition: ProbeDefinition) -> str:
    """The metric name a condition reads to see this probe's readings.

    The probe's own id, and nothing else. Making it derivable rather than
    authored is what stops a condition and a probe from disagreeing about what
    name a reading arrives under — a disagreement whose symptom is a stop
    condition that resolves to nothing and therefore never fires.
    """
    return definition.id


def reading_view(reading: ProbeReading) -> ReadingView:
    """Project a reading onto the domain's evidence view.

    This is the whole of the controller's contribution to Phase 4's evidence
    path, and it exists because :mod:`mayhem.domain.probe_evidence` cannot import
    this module: the controller layer is above the domain, and the layering
    contract forbids the dependency in the other direction. So the domain declares
    :class:`~mayhem.domain.probe_evidence.ReadingView` — the read-only surface it
    needs, in plain strings and numbers — and this function is the one place the
    enum-flavoured reading becomes that JSON-safe shape.

    An unavailable reading projects to a view with ``value=None`` and empty
    ``unit``/``provenance``, and **still projects**: the row must exist, because
    "mayhem could not ask" and "mayhem never asked" are different facts and only
    the first of them has a note attached.
    """
    observation = reading.observation
    return ReadingView(
        probe_id=reading.probe_id,
        family=reading.family.value,
        stage=reading.stage.value,
        availability=reading.availability.value,
        at_epoch_s=reading.at_epoch_s,
        value=None if observation is None else observation.value,
        unit="" if observation is None else observation.unit,
        provenance="" if observation is None else observation.provenance,
        evidence_ref=reading.evidence_ref,
        note=reading.note,
    )


# =============================================================================
# The engine
# =============================================================================


@dataclass(frozen=True, slots=True)
class ProbeService:
    """Binds a plan to a catalogue and collects through the bound ports.

    **Construction *is* the drift check.** :attr:`definitions` is
    :meth:`mayhem.domain.probes.ProbePlan.bind` against the catalogue, computed
    in ``__post_init__``, so a service cannot exist over an unpinned probe, a
    version that moved, or a definition edited in place while still claiming its
    old version. Three refusals, all raised before anything is collected.
    """

    catalogue: ProbeCatalog
    plan: ProbePlan
    ports: ProbePorts = field(default_factory=ProbePorts)

    def __post_init__(self) -> None:
        object.__setattr__(self, "definitions", self.plan.bind(self.catalogue))

    definitions: tuple[ProbeDefinition, ...] = ()

    # -- collection ---------------------------------------------------------------

    def collect(
        self,
        definition: ProbeDefinition,
        *,
        stage: LifecycleStage,
        at_epoch_s: float,
    ) -> ProbeReading:
        """Ask the port for one reading of ``definition``. Never raises.

        Every failure mode — unbound port, raising port, ``None`` answer, answer
        with no value, answer in the wrong shape, answer in the wrong unit — comes
        back as an ``UNAVAILABLE`` reading naming which one it was. The
        alternative, a propagated exception, is the one thing a stop path must
        never do: it would either kill a run or be swallowed by a caller, and in
        both cases the run continues with one fewer witness and no record that it
        lost one.

        A unit mismatch is treated as unavailability rather than as a failure, and
        is **not** converted: :meth:`mayhem.domain.probes.ProbeDefinition.check_reading`
        refuses it because comparing 250 against 0.25 produces a confident number
        about nothing. Mayhem did read a number; it just was not a measurement of
        this probe.
        """
        port = self.ports.for_family(definition.family)
        stages = definition.stages
        if port is None:
            return _unavailable(
                definition,
                stage=stage,
                at_epoch_s=at_epoch_s,
                stages=stages,
                note=(
                    f"no port is bound for the {definition.family.value} family: mayhem "
                    f"has no way to ask about probe {definition.id!r}, and declining to "
                    "look is not a finding about it"
                ),
                evidence_ref=f"probe/{definition.id}/unbound",
            )
        try:
            answered = port.observe(definition)
            error: BaseException | None = None
        except Exception as exc:  # a broken collector must never look like a reading
            answered, error = None, exc
        availability, reason = reading_status(answered, error=error)
        if availability is ProbeAvailability.UNAVAILABLE or answered is None:
            return _unavailable(
                definition,
                stage=stage,
                at_epoch_s=at_epoch_s,
                stages=stages,
                note=f"{reason} (port {getattr(port, 'name', 'unnamed')!r})",
                evidence_ref=f"probe/{definition.id}/unavailable",
            )
        measured = as_observation_result(answered, metric=definition.id)
        try:
            definition.check_reading(measured)
        except InvariantViolationError as exc:
            return _unavailable(
                definition,
                stage=stage,
                at_epoch_s=at_epoch_s,
                stages=stages,
                note=f"{exc.rule}: {_reason_of(exc)}",
                evidence_ref=f"probe/{definition.id}/unit-mismatch",
            )
        return ProbeReading(
            probe_id=definition.id,
            family=definition.family,
            stage=stage,
            at_epoch_s=at_epoch_s,
            availability=ProbeAvailability.AVAILABLE,
            definition_stages=stages,
            observation=measured,
            note=reason,
            evidence_ref=measured.source,
        )

    def collect_stage(
        self,
        stage: LifecycleStage,
        *,
        at_epoch_s: float,
    ) -> tuple[ProbeReading, ...]:
        """Collect one reading of every bound definition that declares ``stage``.

        A definition that does not declare ``stage`` is *not* collected. Lifecycle
        membership is the definition's own claim about where it runs, and
        honouring it here is what makes "not collected in this stage" a fact
        about the catalogue rather than a judgement this method makes silently.
        """
        return tuple(
            self.collect(definition, stage=stage, at_epoch_s=at_epoch_s)
            for definition in self.definitions
            if stage in definition.stages
        )

    def unbound_families(self) -> tuple[ProbeFamily, ...]:
        """The bound definitions' families this service has no port for."""
        return self.ports.unbound(definition.family for definition in self.definitions)

    # -- evaluation ---------------------------------------------------------------

    @staticmethod
    def samples(readings: Iterable[ProbeReading]) -> tuple[Sample, ...]:
        """The samples these readings contribute, in reading order.

        **Unavailable readings contribute nothing, and that is not a silent
        drop.** A missing observation is exactly what the domain's ``UNMEASURED``
        status exists to describe, so the reading is preserved at the coverage
        layer and its absence reaches the evaluator as *no sample for that
        metric* — which :meth:`~mayhem.domain.stop_conditions.Condition.evaluate`
        refuses rather than grades. What must never happen is the opposite: an
        unavailable reading materialising as a sample with ``value=0.0``.
        """
        return tuple(
            Sample.from_observation(reading.observation, reading.at_epoch_s)
            for reading in readings
            if reading.available and reading.observation is not None
        )

    @staticmethod
    def evaluate(
        condition: Condition,
        readings: Sequence[ProbeReading],
        *,
        now_epoch_s: float,
        last_fired_epoch_s: float | None = None,
        baselines: Mapping[str, float] | None = None,
    ) -> ConditionResult:
        """Evaluate ``condition`` over recorded readings. A pure delegation.

        The only judgement this method adds is which readings are *eligible*:
        unavailable ones never become samples, so the domain sees an absent
        metric rather than a corrupt one. The condition, its thresholds, its
        hysteresis, its debounce and its cooldown are all the domain's, read
        unchanged — this engine cannot disagree with
        :mod:`mayhem.domain.stop_conditions` about any value, because it
        computes nothing about values.
        """
        return condition.evaluate(
            ProbeService.samples(readings),
            now_epoch_s=now_epoch_s,
            last_fired_epoch_s=last_fired_epoch_s,
            baselines=baselines,
        )

    @staticmethod
    def coverage(readings: Sequence[ProbeReading]) -> ProbeCoverage:
        """What these readings do and do not establish about the system."""
        return ProbeCoverage.of(readings)


def command_for(
    firing: Firing,
    *,
    command_id: str,
    run_id: str,
    principal: str,
) -> object:
    """The stop command a fired condition produces, via plan 10's own function.

    A delegation, not a construction: plan 10 owns what a firing *causes*, and
    re-deriving the trigger here would be the second place in the codebase that
    answers "what does a stop condition stop".

    Imported lazily and typed as ``object`` because the return type belongs to
    :mod:`mayhem.domain.stop`; callers that need it should read plan 10's
    signature rather than this wrapper's annotation.

    The local import is deliberate: ``stop_engine`` imports back into the
    controller layer's own modules, and a module-level import here would make
    this one part of that cycle.
    """
    from mayhem.controller.stop_engine import (  # noqa: PLC0415 - see docstring
        command_for_firing,
    )

    return command_for_firing(firing, command_id=command_id, run_id=run_id, principal=principal)


# =============================================================================
# Coverage: may these observations support a verdict?
# =============================================================================


@dataclass(frozen=True, slots=True)
class ProbeCoverage:
    """Which probes produced evidence, which produced none, and what that means.

    This answers the question a run report cannot answer for itself: *did
    anything actually get observed?* Without it, "the run completed and no stop
    condition fired" is indistinguishable from "the run completed and no stop
    condition had a reading to fire on".

    Three states, and the third is the point:

    ====================  =========================================================
    state                 meaning
    ====================  =========================================================
    ``complete``          every graded probe produced at least one available,
                          non-settling reading
    ``partial``           some did and some did not — the run may report what it
                          saw and **must** name what it did not
    ``blind``             no graded probe produced any such reading — the run
                          watched nothing, and nothing here is a finding about
                          the system
    ====================  =========================================================
    """

    observations_usable: bool
    observed: tuple[str, ...]
    unobserved: tuple[str, ...]
    settling_only: tuple[str, ...]
    failed_collections: tuple[tuple[str, str], ...]

    @classmethod
    def of(cls, readings: Sequence[ProbeReading]) -> ProbeCoverage:
        """Reduce readings to what they establish. Pure, total, never raises.

        A probe whose only readings came from a settling window counts as
        **unobserved**, not observed: it ran, it was recorded, and it is not
        allowed to say anything yet. Counting it as observed would be the exact
        confusion this module is about — a probe that cannot speak being counted
        as though it had.
        """
        usable: dict[str, ProbeReading] = {}
        # Two reasons a probe may have produced nothing usable, kept apart
        # because they are different findings: mayhem *could not ask* is a
        # wiring problem, mayhem *was not allowed to grade yet* is the lifecycle
        # working as designed.
        failed: dict[str, str] = {}
        settling_only: dict[str, str] = {}
        for reading in readings:
            if not reading.available:
                failed.setdefault(reading.probe_id, reading.note)
            elif reading.in_settling_stage:
                settling_only.setdefault(
                    reading.probe_id,
                    f"only recorded in settling stage(s) {reading.stage.value}",
                )
            else:
                usable.setdefault(reading.probe_id, reading)
        # A probe that has a usable reading is observed even if an earlier
        # attempt failed: one success answers the question the failed one could
        # not, and recording both would invent a coverage gap that is not there.
        unobserved = {**failed, **settling_only}
        for probe_id in usable:
            unobserved.pop(probe_id, None)
            failed.pop(probe_id, None)
            settling_only.pop(probe_id, None)
        return cls(
            observations_usable=bool(usable),
            observed=tuple(sorted(usable)),
            unobserved=tuple(sorted(unobserved)),
            settling_only=tuple(sorted(settling_only)),
            failed_collections=tuple(sorted(failed.items())),
        )

    @property
    def complete(self) -> bool:
        """Did every probe that was asked produce usable evidence?"""
        return self.observations_usable and not self.unobserved

    @property
    def blind(self) -> bool:
        """True when nothing usable was observed at all.

        The state in which *every* answer this module could give is a statement
        about mayhem rather than about the system, and which must never be
        reported as a pass.
        """
        return not self.observations_usable

    @property
    def verdict_bearing(self) -> bool:
        """May a verdict be rendered from these readings at all?

        The same question as :attr:`observations_usable`, spelled for the place
        that asks it. There is no code path in this module that turns a blind
        coverage into one.
        """
        return self.observations_usable

    def describe(self) -> str:
        if self.blind:
            failures = "; ".join(
                f"{probe_id}: {note}" for probe_id, note in self.failed_collections
            )
            return (
                "blind: no graded probe produced a usable reading, so mayhem observed "
                "nothing — which is a statement about mayhem, not about the system"
                + (f" ({failures})" if failures else "")
            )
        if self.unobserved:
            return (
                f"partial: {len(self.observed)} probe(s) observed, "
                f"{len(self.unobserved)} produced no usable reading "
                f"({', '.join(self.unobserved)}); those names are findings about mayhem's "
                "wiring, not about the system"
            )
        return f"complete: {len(self.observed)} probe(s) observed"

    def to_dict(self) -> dict[str, object]:
        return {
            "complete": self.complete,
            "blind": self.blind,
            "observations_usable": self.observations_usable,
            "observed": list(self.observed),
            "unobserved": list(self.unobserved),
            "settling_only": list(self.settling_only),
            "failed_collections": [
                {"probe_id": probe_id, "note": note} for probe_id, note in self.failed_collections
            ],
            "summary": self.describe(),
        }


# =============================================================================
# Internals
# =============================================================================

RULE_READING_AVAILABILITY = "probes.reading_availability_mismatch"
RULE_READING_EVIDENCE_REF = "probes.reading_field_blank"
RULE_PORT_SHAPE = "probes.port_answered_in_the_wrong_shape"
RULE_UNBOUND_FAMILY = "probes.port_unbound"
RULE_COVERAGE_INCOMPLETE = "probes.coverage_cannot_support_a_verdict"


def _unavailable(
    definition: ProbeDefinition,
    *,
    stage: LifecycleStage,
    at_epoch_s: float,
    stages: tuple[LifecycleStage, ...],
    note: str,
    evidence_ref: str,
) -> ProbeReading:
    """The one ``UNAVAILABLE`` reading shape. Every refusal path comes through here."""
    return ProbeReading(
        probe_id=definition.id,
        family=definition.family,
        stage=stage,
        at_epoch_s=at_epoch_s,
        availability=ProbeAvailability.UNAVAILABLE,
        definition_stages=stages,
        observation=None,
        note=note,
        evidence_ref=evidence_ref,
    )


def as_observation_result(observation: object, *, metric: str) -> ObservationResult:
    """Project a :class:`ProbeObservation` onto the domain's observation record.

    Two things happen here and neither is optional. The value is checked to be a
    finite float — a port that answered ``nan`` or ``inf`` measured nothing, and
    grading against nothing is how this codebase gets confidently wrong. And the
    metric name is taken from the **definition's** id rather than from the port,
    so a connector that prefers its own label cannot defeat a condition that
    names the probe.

    **This is the loud half of the refusal, and it is public for that reason.**
    :func:`reading_status` reduces a wrong-shaped or non-finite answer to
    ``UNAVAILABLE`` before anything reaches here, because :meth:`ProbeService.collect`
    never raises. This function is the backstop beneath it: if anything ever
    routes an answer around :func:`reading_status`, *the shape was wrong* and
    *the value was not a measurement* are refused by name at this layer too,
    rather than reaching the evaluator. Both refusals are stated here rather than
    at the one layer that happened to notice first, which is the only way
    "refuse at every layer" means anything.
    """
    if refuses_port_shape(observation):
        raise InvariantViolationError(
            RULE_PORT_SHAPE,
            f"a probe port answered with a {type(observation).__name__}, not a "
            "ProbeObservation: mayhem has one shape for a port's answer so that "
            "'the port said nothing' and 'the port answered with nothing' cannot be "
            "confused, and a second shape reintroduces exactly that confusion",
        )
    # The refusal above is exactly this claim; stated so the type checker sees it
    # too, because a predicate that narrows on its *refusal* is the one thing a
    # reader should never have to infer.
    assert isinstance(observation, ProbeObservation)
    value = observation.value
    if value is not None and not isfinite(value):
        raise InvariantViolationError(
            RULE_READING_AVAILABILITY,
            f"probe observation for {metric!r} is {value!r}, which is not a finite "
            "number: a collector that returned nan or inf measured nothing, and this "
            "is reported rather than graded",
        )
    return ObservationResult(
        metric=metric,
        value=value,
        unit=observation.unit,
        window_s=0.0,
        provenance=observation.provenance,
        source=observation.evidence_ref,
        detail=observation.detail,
    )


def _reason_of(exc: InvariantViolationError) -> str:
    """The message of an ``InvariantViolationError`` without its ``[rule]`` prefix."""
    text = exc.args[0] if exc.args else str(exc)
    return text.split("] ", 1)[-1] if text.startswith("[") else text
