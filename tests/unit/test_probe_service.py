"""Plan 11 Phase 2 — the probe engine: collection that cannot lie, and a stop
that fires on observed evidence.

Phase 1 proved a probe definition is *located* and a firing *cites* its
samples. Phase 2 is the part that runs, and its acceptance criterion is "a
breached condition stops a run before nominal fault duration". So this suite is
organised around the three ways that criterion could be met dishonestly, plus
the one way it must fail:

1. **"We did not look" must never read as "everything is fine".** Four ways to
   have no answer — an unbound port, a port that raises, a port answering
   ``None``, a port answering with no value — and every one of them must land as
   :data:`ProbeAvailability.UNAVAILABLE` with a reason, must contribute **no**
   sample, and must leave the coverage unable to support a verdict. The
   load-bearing assertion is on
   :attr:`ProbeCoverage.observations_usable`, not on the absence of an exception.
2. **A stop must fire on evidence, and stop firing on nothing.** The condition
   evaluator is a delegation, so the suite proves the *plumbing*: a breach
   recorded at ``t=3`` inside a nominal 30 s fault produces a
   :class:`Firing` citing that reading, and the resulting stop command reaches
   plan 10's :func:`~mayhem.controller.stop_engine.trigger_for_firing` output
   shape. The negative half: no available reading means **no firing**, not a
   firing on absence.
3. **Lifecycle membership and noise budgets survive the crossing.** A probe in
   ``warm-up`` is collected by :meth:`ProbeService.collect_stage` and excluded
   from grading, and a probe whose only readings were settling counts as
   *unobserved* rather than as a probe that saw nothing wrong.
4. **Drift is refused before anything is collected**, in all three directions
   Phase 1 defined, and the engine refuses a unit mismatch rather than
   converting it.
5. **The negative controls**, each asserting a *named* refusal: an unbound port,
   a raising port, a ``None`` answer, a valueless answer, a wrong-shaped answer,
   a non-finite value, a unit mismatch, and an unpinned / drifted probe.

One test in this file is about something this environment cannot do: the
plan's acceptance criterion says *live-cell*. :class:`TestLiveCellAcceptance`
runs the criterion against an **in-process fault cell** — a nominal-duration
window driven by an injected clock and injected ports — and says in its own
docstring that it is not a live Kubernetes cell. Nothing in this repository can
inject a fault into a live cluster from a unit test, so claiming that would be
the same over-claim this module is written to prevent.

Timestamps are injected everywhere; nothing here reads a wall clock to decide
anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

from mayhem.controller.probe_service import (
    ProbeAvailability,
    ProbeCoverage,
    ProbeObservation,
    ProbePorts,
    ProbeReading,
    ProbeReadingPort,
    ProbeService,
    as_observation_result,
    command_for,
    is_measurement,
    metric_name_for,
    reading_status,
    refuses_port_shape,
    refuses_probe,
)
from mayhem.domain.checks import HttpProbe
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.observations import ObservationStatus
from mayhem.domain.probes import (
    LifecycleStage,
    ProbeCatalog,
    ProbeDefinition,
    ProbeFamily,
    ProbePin,
    ProbePlan,
)
from mayhem.domain.steady_state import AbsoluteExpect
from mayhem.domain.stop import StopReason
from mayhem.domain.stop_conditions import (
    Condition,
    ConditionStatus,
    FiresWhen,
    Sample,
    Threshold,
)

if TYPE_CHECKING:
    from mayhem.domain.stop_conditions import Firing

# -- ports -------------------------------------------------------------------------


@dataclass
class FakePort:
    """A port that answers however the test needs it to answer.

    Four behaviours the suite needs and no more: measure, decline (``None``),
    answer with no value, and raise. Keeping them on one fake rather than four
    is deliberate — the point is that the *engine* tells them apart, not that
    the test can tell them apart.
    """

    name: str
    value: float | None = 100.0
    unit: str = "ms"
    provenance: str = "fake"
    behaviour: str = "measure"

    def observe(self, definition: ProbeDefinition) -> ProbeObservation | None:
        if self.behaviour == "decline":
            return None
        if self.behaviour == "raise":
            raise TimeoutError(f"port {self.name} timed out")
        return ProbeObservation(
            value=self.value,
            unit=self.unit,
            provenance=self.provenance,
            evidence_ref=f"fake://{self.name}/{definition.id}",
            detail=self.behaviour,
        )


class WrongShapedPort:
    """A port that answers with something that is not a ``ProbeObservation``.

    The fifth way to have no answer, and the one that only a *type* check can
    catch: a duck-typed object, a dict, a bare float. Refusing it by shape is
    what keeps "the port answered in some other shape" from being read as "the
    port said nothing", which would make a broken adapter look like an outage.
    """

    name = "wrong-shape"

    def observe(self, definition: ProbeDefinition) -> object:
        return {"value": 12.0, "unit": "ms"}


# -- definitions -------------------------------------------------------------------


def _http(
    probe_id: str = "http.api",
    *,
    version: str = "1.0",
    stages: tuple[LifecycleStage, ...] = (LifecycleStage.DURING_FAULT,),
    cadence: float = 5.0,
    unit: str = "ms",
    warmup: float = 0.0,
    endpoint: str = "https://api.internal/latency",
) -> ProbeDefinition:
    return ProbeDefinition(
        id=probe_id,
        family=ProbeFamily.HTTP,
        version=version,
        unit=unit,
        endpoint=endpoint,
        stages=stages,
        cadence=cadence,
        warmup=warmup,
    )


def _tcp(probe_id: str = "tcp.db") -> ProbeDefinition:
    return ProbeDefinition(
        id=probe_id,
        family=ProbeFamily.TCP,
        version="1.0",
        unit="ms",
        endpoint="db.internal:5432",
        stages=(LifecycleStage.DURING_FAULT,),
        cadence=5.0,
    )


def _service(
    *definitions: ProbeDefinition,
    ports: ProbePorts | None = None,
) -> ProbeService:
    catalogue = ProbeCatalog(definitions=definitions)
    return ProbeService(
        catalogue=catalogue,
        plan=ProbePlan(pins=tuple(ProbePin.of(definition) for definition in definitions)),
        ports=ports or ProbePorts(),
    )


def _bound(*families: tuple[ProbeFamily, ProbeReadingPort]) -> ProbePorts:
    return ProbePorts(ports=dict(families))


# -- availability ------------------------------------------------------------------


class TestUnavailableIsNotHealthy:
    """The load-bearing property, in the four ways a port can be silent."""

    def test_refuses_probe_is_true_for_everything_that_is_not_available(self) -> None:
        assert refuses_probe(ProbeAvailability.UNAVAILABLE) is True
        assert refuses_probe(ProbeAvailability.AVAILABLE) is False

    def test_a_bound_port_measures(self) -> None:
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=42.0))),
        )

        reading = service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)

        assert reading.available
        assert reading.observation is not None
        assert reading.observation.value == 42.0
        assert reading.supports_verdict

    def test_an_unbound_port_is_unavailable_and_says_so(self) -> None:
        service = _service(_http())  # no ports at all

        reading = service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)

        assert reading.availability is ProbeAvailability.UNAVAILABLE
        assert reading.refuses
        assert "no port is bound" in reading.note
        assert reading.evidence_ref == "probe/http.api/unbound"

    def test_a_port_that_raises_is_unavailable_not_an_exception(self) -> None:
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", behaviour="raise"))),
        )

        reading = service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)

        assert reading.availability is ProbeAvailability.UNAVAILABLE
        assert "TimeoutError" in reading.note, reading.note

    def test_a_port_answering_none_is_unavailable(self) -> None:
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", behaviour="decline"))),
        )

        reading = service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)

        assert reading.availability is ProbeAvailability.UNAVAILABLE
        assert "no observation" in reading.note

    def test_a_port_answering_with_no_value_is_unavailable_not_zero(self) -> None:
        """The load-bearing one: a missing reading must not become ``0.0``."""
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=None))),
        )

        reading = service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)

        assert reading.availability is ProbeAvailability.UNAVAILABLE
        assert "not a measurement of zero" in reading.note
        assert service.samples([reading]) == ()

    def test_a_port_answered_in_the_wrong_shape_is_refused_at_every_layer(self) -> None:
        """A wrong shape is refused twice: quietly at the boundary, loudly beneath it.

        **The root cause this test was corrected for.** It used to assert that
        ``collect`` *raises*. ``collect`` does not raise, and that is not an
        accident of this implementation — "evidence gathering must never break
        the drill" is the existing collector's rule, and a propagated exception
        here would either kill a run or be swallowed by a caller, leaving the
        run one witness short with no record of it. So the refusal has two
        layers and the test asserts both:

        * :func:`reading_status` reduces a wrong shape to ``UNAVAILABLE`` with
          the shape named, which is what ``collect`` returns;
        * :func:`as_observation_result` — the backstop beneath it — raises
          ``probes.port_answered_in_the_wrong_shape`` by name if anything ever
          routes an answer around :func:`reading_status`.

        Asserting only the raise would have left the actual behaviour untested;
        asserting only the ``UNAVAILABLE`` would leave the backstop untested.
        """
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, WrongShapedPort())),
        )

        reading = service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)

        # Layer one: the engine's no-raise contract, and the reason named.
        assert reading.availability is ProbeAvailability.UNAVAILABLE
        assert "not a ProbeObservation" in reading.note
        assert reading.evidence_ref == "probe/http.api/unavailable"
        assert service.samples([reading]) == ()
        assert ProbeCoverage.of([reading]).blind

        # Layer two: the loud refusal, by rule id rather than by message text.
        assert refuses_port_shape({"value": 12.0, "unit": "ms"}) is True
        with pytest.raises(InvariantViolationError) as caught:
            as_observation_result({"value": 12.0, "unit": "ms"}, metric="http.api")

        assert caught.value.rule == "probes.port_answered_in_the_wrong_shape"

    @pytest.mark.parametrize(
        ("observation", "error", "expected_fragment"),
        [
            (None, None, "no observation"),
            (None, RuntimeError("boom"), "RuntimeError"),
            (
                ProbeObservation(value=None, unit="ms", provenance="p", evidence_ref="p://1"),
                None,
                "no value",
            ),
            (
                ProbeObservation(value=1.0, unit="ms", provenance="p", evidence_ref="p://1"),
                None,
                "",
            ),
        ],
    )
    def test_reading_status_names_which_silence_it_was(
        self,
        observation: ProbeObservation | None,
        error: BaseException | None,
        expected_fragment: str,
    ) -> None:
        availability, reason = reading_status(observation, error=error)

        assert isinstance(availability, ProbeAvailability)
        assert expected_fragment in reason

    def test_a_non_finite_value_is_refused_rather_than_graded(self) -> None:
        """``nan`` measured nothing, so it is recorded as an absence — twice refused.

        The same two layers as the wrong-shape case above, for the same reason:
        ``collect`` returns an ``UNAVAILABLE`` reading naming the non-finite
        value, and :func:`as_observation_result` raises if the value ever reaches
        it without passing :func:`is_measurement`. The predicate is the single
        statement of "this is a measurement", and both layers consult it — which
        is what stops ``nan`` (not ``None``, so a naive presence check sails it
        through) from being graded against a threshold.
        """
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=float("nan")))),
        )

        reading = service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)

        assert reading.availability is ProbeAvailability.UNAVAILABLE
        assert reading.refuses
        assert "not a finite number" in reading.note
        assert service.samples([reading]) == ()
        assert ProbeCoverage.of([reading]).blind

        assert is_measurement(float("nan")) is False
        assert is_measurement(float("inf")) is False
        assert is_measurement(None) is False
        assert is_measurement(0.0) is True
        notan = ProbeObservation(
            value=float("nan"), unit="ms", provenance="fake", evidence_ref="fake://api/nan"
        )
        with pytest.raises(InvariantViolationError) as caught:
            as_observation_result(notan, metric="http.api")

        assert "not a finite number" in str(caught.value)


# -- coverage ----------------------------------------------------------------------


class TestCoverageAnswersDidAnythingGetObserved:
    def test_no_readings_at_all_is_blind(self) -> None:
        coverage = ProbeCoverage.of(())

        assert coverage.blind
        assert coverage.observations_usable is False
        assert coverage.verdict_bearing is False
        assert "blind" in coverage.describe()

    def test_a_probe_whose_collection_never_succeeded_is_unobserved(self) -> None:
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", behaviour="decline"))),
        )

        readings = service.collect_stage(LifecycleStage.DURING_FAULT, at_epoch_s=1.0)
        coverage = ProbeCoverage.of(readings)

        assert coverage.blind
        assert coverage.observed == ()
        assert coverage.unobserved == ("http.api",)
        assert coverage.failed_collections[0][0] == "http.api"

    def test_one_successful_probe_and_one_dead_one_is_partial(self) -> None:
        service = _service(
            _http(),
            _tcp(),
            ports=_bound(
                (ProbeFamily.HTTP, FakePort("api", value=10.0)),
                (ProbeFamily.TCP, FakePort("db", behaviour="raise")),
            ),
        )

        coverage = ProbeCoverage.of(
            service.collect_stage(LifecycleStage.DURING_FAULT, at_epoch_s=1.0)
        )

        assert coverage.observations_usable
        assert not coverage.blind
        assert coverage.observed == ("http.api",)
        assert coverage.unobserved == ("tcp.db",)
        assert not coverage.complete
        assert "partial" in coverage.describe()

    def test_a_probe_that_succeeded_once_after_failing_is_observed(self) -> None:
        """One success answers the question an earlier failure could not."""
        good = FakePort("api", value=5.0)
        bad = FakePort("api", behaviour="decline")
        service = _service(_http(), ports=_bound((ProbeFamily.HTTP, bad)))

        first = service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)
        service_with_good = _service(_http(), ports=_bound((ProbeFamily.HTTP, good)))
        second = service_with_good.collect(
            _http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=2.0
        )
        coverage = ProbeCoverage.of([first, second])

        assert coverage.observed == ("http.api",)
        assert coverage.unobserved == ()
        assert coverage.failed_collections == ()

    def test_coverage_to_dict_carries_the_summary_not_just_the_flags(self) -> None:
        payload = ProbeCoverage.of(()).to_dict()

        assert payload["blind"] is True
        assert "a statement about mayhem, not about the system" in str(payload["summary"])

    def test_a_blank_probe_id_on_a_reading_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            ProbeReading(
                probe_id="  ",
                family=ProbeFamily.HTTP,
                stage=LifecycleStage.DURING_FAULT,
                at_epoch_s=0.0,
                availability=ProbeAvailability.UNAVAILABLE,
                definition_stages=(LifecycleStage.DURING_FAULT,),
            )

        assert "blank probe id" in str(caught.value)


class TestReadingCannotClaimWhatItDoesNotHave:
    """The two directions of the availability/observation pairing."""

    def test_available_without_an_observation_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            ProbeReading(
                probe_id="http.api",
                family=ProbeFamily.HTTP,
                stage=LifecycleStage.DURING_FAULT,
                at_epoch_s=0.0,
                availability=ProbeAvailability.AVAILABLE,
                definition_stages=(LifecycleStage.DURING_FAULT,),
                observation=None,
            )

        assert caught.value.rule == "probes.reading_availability_mismatch"
        assert "reads as healthy" in str(caught.value)

    def test_unavailable_carrying_an_observation_is_refused(self) -> None:
        witness = _available_reading()
        assert witness.observation is not None
        with pytest.raises(InvariantViolationError) as caught:
            ProbeReading(
                probe_id="http.api",
                family=ProbeFamily.HTTP,
                stage=LifecycleStage.DURING_FAULT,
                at_epoch_s=0.0,
                availability=ProbeAvailability.UNAVAILABLE,
                definition_stages=(LifecycleStage.DURING_FAULT,),
                observation=witness.observation,
            )

        assert caught.value.rule == "probes.reading_availability_mismatch"
        assert "already said it does not have" in str(caught.value)

    def test_a_non_finite_recording_time_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            ProbeReading(
                probe_id="http.api",
                family=ProbeFamily.HTTP,
                stage=LifecycleStage.DURING_FAULT,
                at_epoch_s=float("inf"),
                availability=ProbeAvailability.UNAVAILABLE,
                definition_stages=(LifecycleStage.DURING_FAULT,),
            )

        assert "non-finite recording time" in str(caught.value)


def _available_reading() -> ProbeReading:
    service = _service(
        _http(),
        ports=_bound((ProbeFamily.HTTP, FakePort("api", value=7.0))),
    )
    return service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)


# -- lifecycle ---------------------------------------------------------------------


class TestLifecycleAndNoiseBudgetsSurviveTheCrossing:
    def test_collect_stage_only_touches_definitions_that_declare_the_stage(self) -> None:
        warming = _http(
            "http.warm",
            stages=(LifecycleStage.WARM_UP,),
            warmup=10.0,
        )
        faulting = _http("http.fault")
        service = _service(
            warming,
            faulting,
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=10.0))),
        )

        readings = service.collect_stage(LifecycleStage.DURING_FAULT, at_epoch_s=1.0)

        assert [reading.probe_id for reading in readings] == ["http.fault"]

    def test_a_warm_up_reading_is_recorded_but_may_not_support_a_verdict(self) -> None:
        warming = _http("http.warm", stages=(LifecycleStage.WARM_UP,), warmup=10.0)
        service = _service(warming, ports=_bound((ProbeFamily.HTTP, FakePort("api", value=900.0))))

        reading = service.collect(warming, stage=LifecycleStage.WARM_UP, at_epoch_s=1.0)

        assert reading.available
        assert not reading.supports_verdict
        assert reading.in_settling_stage

    def test_a_probe_whose_only_readings_were_settling_counts_as_unobserved(self) -> None:
        warming = _http("http.warm", stages=(LifecycleStage.WARM_UP,), warmup=10.0)
        service = _service(warming, ports=_bound((ProbeFamily.HTTP, FakePort("api", value=900.0))))

        readings = service.collect_stage(LifecycleStage.WARM_UP, at_epoch_s=1.0)
        coverage = ProbeCoverage.of(readings)

        assert coverage.blind
        assert coverage.unobserved == ("http.warm",)
        assert coverage.settling_only == ("http.warm",)

    def test_an_after_recovery_reading_is_also_settling(self) -> None:
        cooling = ProbeDefinition(
            id="http.cool",
            family=ProbeFamily.HTTP,
            version="1.0",
            unit="ms",
            endpoint="https://api.internal/latency",
            stages=(LifecycleStage.AFTER_RECOVERY,),
            cadence=5.0,
            cooldown=15.0,
        )
        service = _service(cooling, ports=_bound((ProbeFamily.HTTP, FakePort("api", value=5.0))))

        reading = service.collect(cooling, stage=LifecycleStage.AFTER_RECOVERY, at_epoch_s=1.0)

        assert reading.in_settling_stage
        assert not reading.supports_verdict


# -- units -------------------------------------------------------------------------


class TestUnitsAreRefusedNotConverted:
    def test_a_unit_mismatch_becomes_unavailable(self) -> None:
        service = _service(
            _http(unit="ms"),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=0.25, unit="s"))),
        )

        reading = service.collect(
            _http(unit="ms"), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )

        assert reading.availability is ProbeAvailability.UNAVAILABLE
        assert reading.evidence_ref == "probe/http.api/unit-mismatch"
        assert "probes.probe_reading_unit_mismatch" in reading.note

    def test_the_same_unit_in_a_different_case_is_fine(self) -> None:
        service = _service(
            _http(unit="ms"),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=1.0, unit="MS"))),
        )

        reading = service.collect(
            _http(unit="ms"), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )

        assert reading.available


# -- drift -------------------------------------------------------------------------


class TestDriftIsRefusedBeforeAnythingIsCollected:
    def test_an_unpinned_probe_is_refused(self) -> None:
        catalogue = ProbeCatalog(definitions=(_http(),))

        with pytest.raises(InvariantViolationError) as caught:
            ProbeService(
                catalogue=catalogue,
                plan=ProbePlan(pins=(ProbePin.of(_tcp()),)),
                ports=ProbePorts(),
            )

        assert caught.value.rule == "probes.unpinned_probe"

    def test_a_version_move_is_refused(self) -> None:
        catalogue = ProbeCatalog(definitions=(_http(version="2.0"),))

        with pytest.raises(InvariantViolationError) as caught:
            ProbeService(
                catalogue=catalogue,
                plan=ProbePlan(pins=(ProbePin.of(_http(version="1.0")),)),
                ports=ProbePorts(),
            )

        assert caught.value.rule == "probes.probe_version_drift"

    def test_an_in_place_edit_keeping_the_version_is_refused(self) -> None:
        """The drift a version-only pin reports as healthy."""
        pinned = _http(version="1.0")
        edited = _http(version="1.0", endpoint="https://api.internal/other")
        catalogue = ProbeCatalog(definitions=(edited,))

        with pytest.raises(InvariantViolationError) as caught:
            ProbeService(
                catalogue=catalogue,
                plan=ProbePlan(pins=(ProbePin.of(pinned),)),
                ports=ProbePorts(),
            )

        assert caught.value.rule == "probes.probe_definition_drift"

    def test_drift_is_refused_before_any_port_is_asked(self) -> None:
        """Construction is the drift check, so a drifted plan never collects."""
        exploding = _ExplodingPort()
        catalogue = ProbeCatalog(definitions=(_http(version="2.0"),))

        with pytest.raises(InvariantViolationError):
            ProbeService(
                catalogue=catalogue,
                plan=ProbePlan(pins=(ProbePin.of(_http(version="1.0")),)),
                ports=_bound((ProbeFamily.HTTP, exploding)),
            )

        assert exploding.calls == 0


class _ExplodingPort:
    name = "exploding"

    def __init__(self) -> None:
        self.calls = 0

    def observe(self, definition: ProbeDefinition) -> ProbeObservation:
        self.calls += 1
        raise AssertionError("a drifted plan must not reach a port")


# -- stop conditions ---------------------------------------------------------------


def _breach_condition() -> Condition:
    return Condition.metric(
        metric_name_for(_http()),
        Threshold(
            fires_when=FiresWhen.BROKEN,
            expect=AbsoluteExpect(lte=250.0),
        ),
        for_samples=2,
        name="latency-ceiling",
    )


class TestStopConditionsFireOnEvidenceOnly:
    def test_a_breach_fires_and_cites_the_readings_that_caused_it(self) -> None:
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=400.0))),
        )
        readings = [
            service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=at)
            for at in (1.0, 2.0, 3.0)
        ]

        result = ProbeService.evaluate(_breach_condition(), readings, now_epoch_s=3.0)

        assert result.status is ConditionStatus.FIRED
        # Three consecutive breaching readings, and ``for_samples=2`` is a floor
        # rather than a cap: the run cites every sample that built it, because a
        # stop that discarded evidence it had would be the defect the citations
        # exist to prevent.
        assert result.sample_count == 3
        firing = result.to_firing()
        assert firing.condition_name == "latency-ceiling"
        assert all(sample.value == 400.0 for sample in firing.samples)
        assert ProbeService.samples(readings)[0] in firing.samples

    def test_no_reading_means_no_firing_never_a_firing_on_absence(self) -> None:
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", behaviour="decline"))),
        )
        readings = service.collect_stage(LifecycleStage.DURING_FAULT, at_epoch_s=1.0)

        # The metric is absent from the recorded stream entirely, which the
        # domain *refuses* rather than grading. That refusal is the whole point:
        # a stop condition that resolved to nothing is a typo or a dead probe,
        # and reporting it as clear is the most confident wrong answer available.
        assert service.samples(readings) == ()
        with pytest.raises(InvariantViolationError) as caught:
            ProbeService.evaluate(_breach_condition(), readings, now_epoch_s=10.0)

        assert caught.value.rule == "stop_conditions.unknown_metric"

    def test_an_available_reading_below_the_bound_does_not_fire(self) -> None:
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=10.0))),
        )
        readings = [
            service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=at)
            for at in (1.0, 2.0, 3.0)
        ]

        result = ProbeService.evaluate(_breach_condition(), readings, now_epoch_s=3.0)

        assert result.status is ConditionStatus.CLEAR

    def test_an_expired_window_is_reported_expired_not_fired(self) -> None:
        """A window that ran out is not a firing, and not a clean bill of health.

        ``fires_when=MET`` with a bound the readings never reach: the condition
        can never qualify, so after ``max_duration`` the domain reports
        ``EXPIRED`` and cites nothing. This is the plan's *timeout means we did
        not look* clause, exercised.
        """
        condition = Condition.metric(
            metric_name_for(_http()),
            Threshold(
                fires_when=FiresWhen.MET,
                expect=AbsoluteExpect(lte=1.0),
            ),
            max_duration=2.0,
            name="recovery-window",
        )
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=10.0))),
        )
        readings = [
            service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=at)
            for at in (1.0, 2.0)
        ]

        result = ProbeService.evaluate(condition, readings, now_epoch_s=99.0)

        assert result.status is ConditionStatus.EXPIRED
        assert result.samples == ()
        with pytest.raises(InvariantViolationError):
            result.to_firing()

    def test_a_firing_reaches_plan_tens_stop_path_unchanged(self) -> None:
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=400.0))),
        )
        readings = [
            service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=at)
            for at in (1.0, 2.0)
        ]
        firing: Firing = ProbeService.evaluate(
            _breach_condition(), readings, now_epoch_s=2.0
        ).to_firing()

        command = command_for(
            firing,
            command_id="cmd-1",
            run_id="r-drill-a1b2c3d4",
            principal="u-ana",
        )

        assert command.trigger.reason is StopReason.CONDITION_FIRED
        assert command.trigger.is_condition_fired
        assert command.trigger.condition_id == "latency-ceiling"
        assert command.scope.value == "run"
        assert len(command.trigger.observed_values) == 2

    def test_unavailable_readings_contribute_no_samples(self) -> None:
        good = _available_reading()
        bad = ProbeReading(
            probe_id="tcp.db",
            family=ProbeFamily.TCP,
            stage=LifecycleStage.DURING_FAULT,
            at_epoch_s=1.0,
            availability=ProbeAvailability.UNAVAILABLE,
            definition_stages=(LifecycleStage.DURING_FAULT,),
            note="no port is bound for the tcp family",
            evidence_ref="probe/tcp.db/unbound",
        )

        samples = ProbeService.samples([good, bad])

        assert len(samples) == 1
        assert samples[0].metric == "http.api"


# -- the acceptance criterion ------------------------------------------------------


#: The plan's Phase 2 acceptance criterion, verbatim: "a breached condition
#: stops a run before nominal fault duration in live-cell tests". Kept as a named
#: constant so the honest answer to "is the criterion met?" is a readable one
#: rather than a class name that implies a claim the file does not make.
LIVE_CELL_ACCEPTANCE = "a breached condition stops a run before nominal fault duration"


class TestTheAcceptanceDecisionIsOursAndTheLiveCellIsNot:
    """The plan's criterion, split into the half this environment can run and
    the half it cannot — with the second half asserted as *unavailable*.

    **Conversion, recorded rather than hidden.** This class used to be named
    ``TestLiveCellAcceptance`` and asserted a stop at ``t=3`` against a nominal
    ``t=30``. Nothing about that assertion was wrong — but the *name* claimed a
    live cell, and there is no live cell: a unit test cannot inject a fault into
    a Kubernetes cluster, and the ports it used were fakes. A test whose name
    asserts a capability its body does not exercise is the same defect this
    module exists to prevent, one level up, so the class was renamed and the
    unavailable half given its own test rather than a docstring footnote.

    So the criterion is answered in two halves, both executable:

    * :meth:`test_a_breach_at_t3_produces_a_stop_command_naming_its_evidence`
      — the **decision**: given readings recorded at ``t=1..3`` and a breach at
      ``t=3``, the engine fires, cites the breaching samples, and hands plan 10
      a stop command whose reason is ``CONDITION_FIRED`` and whose
      ``observed_values`` are the cited readings. It fires at ``t=3``, before the
      nominal ``t=30``. Every input is a fake; the *arithmetic and the refusal to
      fire on anything else* are real.
    * :meth:`test_the_live_cell_path_is_named_unavailable_not_assumed_healthy`
      — the **witness**: the harness a live cell needs is a ``kubernetes``-family
      probe port, and this environment binds none. So the live path is
      ``UNAVAILABLE`` by the same rule as everything else in this module, it
      refuses, and it may not be counted as evidence that the criterion holds.

    What is therefore **not** claimed anywhere in this file: that a real fault,
    a real cell and a real cluster produce readings the condition reads. That
    needs a runtime this environment does not have, and
    :meth:`test_the_live_cell_path_is_named_unavailable_not_assumed_healthy` is
    the test that says so out loud.
    """

    NOMINAL_FAULT_S = 30.0

    def test_a_breach_at_t3_produces_a_stop_command_naming_its_evidence(self) -> None:
        breach_at = 3.0
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=400.0))),
        )
        readings = [
            service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=at)
            for at in (1.0, 2.0, 3.0)
        ]

        result = ProbeService.evaluate(_breach_condition(), readings, now_epoch_s=breach_at)
        assert result.status is ConditionStatus.FIRED

        fired_at = result.fired_at_epoch_s
        assert fired_at == breach_at
        assert fired_at is not None
        assert fired_at < self.NOMINAL_FAULT_S

        command = command_for(
            result.to_firing(),
            command_id="cmd-stop",
            run_id="r-cell-0000",
            principal="u-ana",
        )
        assert command.trigger.reason is StopReason.CONDITION_FIRED
        assert command.trigger.condition_id == "latency-ceiling"
        # The stop names the readings that caused it, which is the whole claim:
        # a stop that stopped "on a condition" with nothing behind it would
        # satisfy the same assertion on `reason` alone.
        # The stop names the readings that caused it, by metric and instant, which
        # is the whole claim: a stop that said only "on a condition" would satisfy
        # the `reason` assertion above with no evidence behind it at all.
        assert [observed.name for observed in command.trigger.observed_values] == [
            "http.api@1",
            "http.api@2",
            "http.api@3",
        ]
        assert {observed.value for observed in command.trigger.observed_values} == {"400"}

    def test_the_live_cell_path_is_named_unavailable_not_assumed_healthy(self) -> None:
        """The half this environment cannot run, asserted as UNAVAILABLE.

        A live cell is a ``kubernetes``-family probe against a real cluster, so
        its harness is a :class:`~mayhem.controller.probe_service.ProbeReadingPort`
        for that family. This environment binds none — so the correct report is
        :data:`ProbeAvailability.UNAVAILABLE`, which
        :func:`~mayhem.controller.probe_service.refuses_probe` turns into a
        refusal. The negative half of the same test asserts the reason it cannot
        be quietly upgraded: with that one port bound, coverage for the family
        flips to observed, and it takes a *reading* to do it. The capability is
        real, and it is not on.
        """
        ports = ProbePorts()

        assert ports.for_family(ProbeFamily.KUBERNETES) is None
        assert ports.unbound((ProbeFamily.KUBERNETES,)) == (ProbeFamily.KUBERNETES,)
        assert refuses_probe(ProbeAvailability.UNAVAILABLE) is True

        cell = _service(
            ProbeDefinition(
                id="k8s.cell",
                family=ProbeFamily.KUBERNETES,
                version="1.0",
                unit="count",
                target="cell/drills",
                query="kube_pod_status_ready",
                stages=(LifecycleStage.DURING_FAULT,),
                cadence=5.0,
            ),
            ports=ports,
        )

        reading = cell.collect(
            cell.definitions[0], stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )
        coverage = ProbeCoverage.of([reading])

        assert reading.availability is ProbeAvailability.UNAVAILABLE
        assert "no port is bound" in reading.note
        assert coverage.blind
        assert coverage.verdict_bearing is False

        # And with the harness actually bound, coverage flips — by the reading,
        # not by the declaration. The live cell's absence is a fact about wiring.
        bound = _service(
            cell.definitions[0],
            ports=_bound((ProbeFamily.KUBERNETES, FakePort("cell", value=6.0, unit="count"))),
        )
        bound_reading = bound.collect(
            cell.definitions[0], stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )

        assert bound_reading.available
        assert ProbeCoverage.of([bound_reading]).observed == ("k8s.cell",)

    def test_a_run_whose_probes_never_answered_produces_no_stop_and_no_verdict(self) -> None:
        """The negative half: silence cannot stop a run, and cannot bless one."""
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", behaviour="raise"))),
        )
        readings = [
            service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=at)
            for at in (1.0, 2.0, 3.0)
        ]
        coverage = ProbeCoverage.of(readings)

        assert coverage.blind
        assert coverage.verdict_bearing is False
        assert service.samples(readings) == ()
        with pytest.raises(InvariantViolationError):
            ProbeService.evaluate(_breach_condition(), readings, now_epoch_s=3.0)


# -- reporting ---------------------------------------------------------------------


class TestPortsReportWhatTheyCannotSee:
    def test_unbound_lists_the_families_in_the_catalogue_order(self) -> None:
        service = _service(
            _http(),
            _tcp(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api"))),
        )

        assert service.unbound_families() == (ProbeFamily.TCP,)

    def test_ports_bound_lists_only_what_can_be_asked(self) -> None:
        ports = _bound((ProbeFamily.HTTP, FakePort("api")))

        assert ports.bound() == (ProbeFamily.HTTP,)
        assert ports.unbound((ProbeFamily.HTTP, ProbeFamily.TCP)) == (ProbeFamily.TCP,)

    def test_a_carrier_and_a_definition_must_agree_about_the_url(self) -> None:
        """Phase 1's cross-check still applies at the engine's boundary."""
        with pytest.raises(InvariantViolationError) as caught:
            ProbeDefinition(
                id="http.api",
                family=ProbeFamily.HTTP,
                version="1.0",
                unit="ms",
                endpoint="https://api.internal/latency",
                stages=(LifecycleStage.DURING_FAULT,),
                cadence=5.0,
                carrier=HttpProbe(url="https://other.internal/latency"),
            )

        assert caught.value.rule == "probes.probe_carrier_locator_conflict"


class TestSampleArityIsTheEnginesNotTheDomains:
    def test_a_reading_becomes_a_sample_carrying_its_own_provenance(self) -> None:
        service = _service(
            _http(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=3.0, provenance="prom"))),
        )

        sample: Sample = ProbeService.samples(
            [service.collect(_http(), stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)]
        )[0]

        assert sample.observation.provenance == "prom"
        assert sample.observation.source == "fake://api/http.api"
        assert sample.available
        assert sample.to_dict()["at_epoch_s"] == 1.0


class TestUnavailableStatusIsNeverSilentlyHealthy:
    def test_an_observation_status_other_than_ok_does_not_become_available(self) -> None:
        """A port that reports ``MISSING`` is a port that has no measurement."""
        from mayhem.domain.observations import ObservationResult

        result = ObservationResult(
            metric="http.api",
            value=None,
            unit="ms",
            window_s=0.0,
            status=ObservationStatus.MISSING,
        )

        assert result.available is False
        # And the engine's own availability is a property of the *port answer*,
        # never of the reading's status field, so a connector cannot smuggle a
        # "missing" observation in as though it were a measurement.
        assert refuses_probe(ProbeAvailability.UNAVAILABLE)
