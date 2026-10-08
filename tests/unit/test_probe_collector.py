"""Plan 11 Phase 2, collector half — the sweep that walks the lifecycle and never
invents an answer.

:mod:`mayhem.controller.probe_service` proves a port can be asked once and that an
unaskable probe is ``UNAVAILABLE``. :mod:`mayhem.controller.probe_collector` is the
part that *runs*: it walks the six lifecycle stages in order, collects at each,
evaluates the stop conditions over what has been recorded so far, and decides what
the run is allowed to conclude.

The suite is organised around the five ways that could go dishonestly:

1. **A stop fires on evidence, at the moment the evidence arrived.** A breach
   qualified at ``t=3`` inside a nominal ``t=30`` produces a firing citing the
   breaching samples and a stop command naming them.
2. **Silence produces no stop and no verdict.** Every way a port can fail ends in a
   blind or partial
   :class:`~mayhem.controller.probe_service.ProbeCoverage`, and in *neither* case is
   there a stop command. The load-bearing assertion is that
   ``outcome.stop_command is None`` **and** the coverage is not verdict-bearing.
3. **A block is not a firing, and cannot become one.** This is the distinction the
   whole module exists to keep, so it is asserted structurally: a sweep that
   blocked on an unaskable probe has no ``firings``, and the block exposes no
   ``to_firing``.
4. **A timeout is not a clean bill of health.** An ``EXPIRED`` window is reported as
   ``EXPIRED``, produces no firing, and the sweep's own description never claims the
   condition was satisfied.
5. **Negative controls**, each of which breaks the property it guards and is shown
   to fail: an empty ``stages`` tuple, a missing stage time, a closed vocabulary,
   a drifted plan, a wrong-shaped answer, and determinism.

Every timestamp is injected. Nothing here reads a wall clock to decide anything.

A note on the settling stages, because it is easy to get wrong
----------------------------------------------------------------

:meth:`~mayhem.controller.probe_service.ProbeService.samples` contributes an
*available* reading to the evaluator regardless of the stage it was taken in. That
is deliberate and is why the breach below is qualified at ``t=3`` rather than
``t=2``: the ``warm-up`` reading at ``t=1`` is recorded and *is* a sample, so the
first two consecutive breaching samples are ``t=2`` and ``t=3``. Settling stages
are excluded from *grading a verdict* and from *coverage*, not from the stop
signal — a latency breach during warm-up is still a latency breach, and hiding it
until the settling window closed would be the noise-discovered-mid-verdict failure
the plan names. Both halves are asserted below so the distinction cannot rot.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from mayhem.controller.probe_collector import (
    LIFECYCLE_ORDER,
    STEP_SKIPPED_NOT_DECLARED,
    ProbeSweep,
    ProbeSweepOutcome,
    SweepRefusalError,
    SweepStep,
    SweepStepStatus,
    UnavailablePolicy,
    metric_names_for,
)
from mayhem.controller.probe_service import (
    ProbeAvailability,
    ProbeCoverage,
    ProbeObservation,
    ProbePorts,
    ProbeReadingPort,
    ProbeService,
)
from mayhem.domain.errors import InvariantViolationError
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
    Threshold,
)

#: The nominal fault duration the plan's acceptance criterion is measured against.
NOMINAL_FAULT_S = 30.0


# -- fakes ---------------------------------------------------------------------------


@dataclass
class FakePort:
    """A port that answers however the test needs it to answer.

    ``value`` may be a callable taking the *call number* so one port can breach
    part-way through a sweep — which is what "the breach arrived at ``t=2``" needs
    — and the four terminal behaviours (measure, decline, raise, wrong shape) are
    what the silence tests need.
    """

    name: str
    value: object = 100.0
    unit: str = "ms"
    provenance: str = "fake"
    behaviour: str = "measure"
    calls: int = 0

    def observe(self, definition: ProbeDefinition) -> ProbeObservation | None:
        self.calls += 1
        if self.behaviour == "decline":
            return None
        if self.behaviour == "raise":
            raise TimeoutError(f"port {self.name} timed out")
        if self.behaviour == "wrong-shape":
            return {"value": 1.0}
        value = self.value(self.calls) if callable(self.value) else self.value
        return ProbeObservation(
            value=value,
            unit=self.unit,
            provenance=self.provenance,
            evidence_ref=f"fake://{self.name}/{definition.id}",
            detail=self.behaviour,
        )


class ExplodingPort:
    """A port that records how often it was asked and always fails."""

    name = "exploding"

    def __init__(self) -> None:
        self.calls = 0

    def observe(self, definition: ProbeDefinition) -> object:
        self.calls += 1
        raise AssertionError("a drifted plan must not reach a port")


def _http(
    probe_id: str = "http.api",
    *,
    version: str = "1.0",
    stages: tuple[LifecycleStage, ...] = (
        LifecycleStage.PRE_BASELINE,
        LifecycleStage.WARM_UP,
        LifecycleStage.DURING_FAULT,
        LifecycleStage.FINAL_VERIFICATION,
    ),
    warmup: float = 5.0,
    unit: str = "ms",
) -> ProbeDefinition:
    return ProbeDefinition(
        id=probe_id,
        family=ProbeFamily.HTTP,
        version=version,
        unit=unit,
        endpoint="https://api.internal/latency",
        stages=stages,
        cadence=1.0,
        warmup=warmup,
    )


def _tcp(probe_id: str = "tcp.db") -> ProbeDefinition:
    return ProbeDefinition(
        id=probe_id,
        family=ProbeFamily.TCP,
        version="1.0",
        unit="ms",
        endpoint="db.internal:5432",
        stages=(LifecycleStage.PRE_BASELINE, LifecycleStage.DURING_FAULT),
        cadence=1.0,
    )


def _service(*definitions: ProbeDefinition, ports: ProbePorts | None = None) -> ProbeService:
    return ProbeService(
        catalogue=ProbeCatalog(definitions=definitions),
        plan=ProbePlan(pins=tuple(ProbePin.of(definition) for definition in definitions)),
        ports=ports or ProbePorts(),
    )


def _bound(*families: tuple[ProbeFamily, ProbeReadingPort]) -> ProbePorts:
    return ProbePorts(ports=dict(families))


#: The four stages :func:`_http` declares, walked at ``t=0..3``. Explicit rather
#: than a slice of :data:`LIFECYCLE_ORDER` because ``continuous`` and
#: ``after-recovery`` sit between ``during-fault`` and ``final-verification`` in the
#: full order, so a slice would give the fourth reading ``t=5`` and every assertion
#: about "at ``t=3``" would be quietly wrong.
WALKED: tuple[LifecycleStage, ...] = (
    LifecycleStage.PRE_BASELINE,
    LifecycleStage.WARM_UP,
    LifecycleStage.DURING_FAULT,
    LifecycleStage.FINAL_VERIFICATION,
)

WALKED_TIMES: dict[LifecycleStage, float] = {
    LifecycleStage.PRE_BASELINE: 0.0,
    LifecycleStage.WARM_UP: 1.0,
    LifecycleStage.DURING_FAULT: 2.0,
    LifecycleStage.FINAL_VERIFICATION: 3.0,
}


def _stage_times(**overrides: float) -> dict[LifecycleStage, float]:
    """A time for every stage in :data:`LIFECYCLE_ORDER`, overridable per test."""
    times = {stage: float(index) for index, stage in enumerate(LIFECYCLE_ORDER)}
    for stage, value in overrides.items():
        times[LifecycleStage(stage)] = value
    return times


def _breach(threshold_ms: float = 250.0, *, for_samples: int = 2, name: str = "latency"):
    return Condition.metric(
        "http.api",
        Threshold(fires_when=FiresWhen.BROKEN, expect=AbsoluteExpect(lte=threshold_ms)),
        for_samples=for_samples,
        name=name,
    )


def _healthy_sweep(*, value: float = 10.0, conditions=()) -> ProbeSweep:
    return ProbeSweep(
        service=_service(_http(), ports=_bound((ProbeFamily.HTTP, FakePort("api", value=value)))),
        conditions=tuple(conditions),
        stages=WALKED,
        stage_times=dict(WALKED_TIMES),
    )


# -- 1. a stop fires on evidence, when the evidence arrived ---------------------------


class TestTheStopFiresAtTheEvidenceNotAtTheEnd:
    """The phase's acceptance criterion, minus the part no unit test can reach."""

    def test_a_breach_qualified_at_t3_stops_the_run_before_the_nominal_fault_ends(
        self,
    ) -> None:
        """The port breaches from the third call; the firing lands at ``t=3``.

        Four stages are walked at ``t=0..3`` (pre-baseline, warm-up, during-fault,
        final-verification). The port answers ``10`` for the first two calls and
        ``400`` for the last two, so the two consecutive breaching samples are
        ``t=2`` and ``t=3`` and the condition qualifies at ``t=3`` — well inside the
        nominal ``t=30``. The command names both cited readings, so the stop cannot
        be mistaken for a stop on nothing.

        ``mayhem probe`` and ``mayhem stop`` are the surfaces; this is the decision
        they carry.
        """
        port = FakePort("api", value=lambda call: 400.0 if call >= 3 else 10.0)
        sweep = ProbeSweep(
            service=_service(_http(), ports=_bound((ProbeFamily.HTTP, port))),
            conditions=(_breach(),),
            stages=WALKED,
            stage_times=dict(WALKED_TIMES),
        )

        outcome = sweep.run(run_id="r-drill-a1b2c3d4", principal="u-ana", command_id="cmd-stop")

        assert outcome.block is None
        assert len(outcome.firings) == 1
        firing = outcome.firings[0]
        assert firing.fired_at_epoch_s == 3.0
        assert firing.fired_at_epoch_s < NOMINAL_FAULT_S
        assert [sample.at_epoch_s for sample in firing.samples] == [2.0, 3.0]
        assert all(sample.value == 400.0 for sample in firing.samples)

        assert outcome.stopped
        command = outcome.stop_command
        assert command is not None
        assert command.trigger.reason is StopReason.CONDITION_FIRED
        assert command.trigger.condition_id == "latency"
        assert [observed.name for observed in command.trigger.observed_values] == [
            "http.api@2",
            "http.api@3",
        ]
        assert {observed.value for observed in command.trigger.observed_values} == {"400"}

    def test_a_warm_up_reading_is_a_sample_so_a_breach_is_not_hidden_by_settling(
        self,
    ) -> None:
        """Settling stages are excluded from *grading*, not from the stop signal.

        The port breaches from call 2 — i.e. from ``warm-up`` at ``t=1``. With
        ``for_samples=2`` the condition qualifies at ``t=2`` on the basis of the
        ``warm-up`` reading. If settling readings were dropped from the sample
        stream this would qualify at ``t=3`` instead, which is exactly the
        "noise discovered mid-verdict" window the warm-up budget exists to prevent.
        """
        port = FakePort("api", value=lambda call: 400.0 if call >= 2 else 10.0)
        sweep = ProbeSweep(
            service=_service(_http(), ports=_bound((ProbeFamily.HTTP, port))),
            conditions=(_breach(),),
            stages=WALKED,
            stage_times=dict(WALKED_TIMES),
        )

        outcome = sweep.run(run_id="r-x", principal="u-ana", command_id="cmd-x")

        assert outcome.firings[0].fired_at_epoch_s == 2.0
        assert outcome.firings[0].samples[0].at_epoch_s == 1.0
        # The warm-up *step* is recorded as settling, so it is excluded from
        # grading — while its reading still qualified the stop above. Both halves
        # of the distinction, asserted together.
        warming = [
            step
            for step in outcome.steps
            if step.stage is LifecycleStage.WARM_UP and step.probe_id == "http.api"
        ]
        assert len(warming) == 1
        assert warming[0].status is SweepStepStatus.SETTLING
        # And the probe is still observed overall, because later stages produced
        # gradable readings — which is why `settling_only` is empty here.
        assert outcome.coverage.settling_only == ()
        assert outcome.coverage.observed == ("http.api",)

    def test_a_clean_sweep_produces_no_firing_and_no_stop(self) -> None:
        outcome = _healthy_sweep(conditions=(_breach(),)).run()

        assert not outcome.firings
        assert outcome.stop_command is None
        assert outcome.stopped is False
        assert outcome.verdict_bearing
        assert outcome.coverage.observed == ("http.api",)

    def test_the_sweep_evaluates_after_every_stage_not_once_at_the_end(self) -> None:
        """Continuous evaluation is observable in the number of results recorded."""
        outcome = _healthy_sweep(conditions=(_breach(),)).run()

        assert len(outcome.results) == len(WALKED)
        assert all(result.status is ConditionStatus.CLEAR for result in outcome.results)

    def test_a_cooldown_threads_across_sweeps_so_a_stop_cannot_be_re_fired(self) -> None:
        """Two sweeps, one firing: the second is inside the cooldown and is clear.

        Plan 10's stop path owns the effect; the *eligibility* is the domain's, and
        this proves the engine threads ``last_fired_epoch_s`` rather than resetting
        it per sweep — a sweep that forgot would produce a second stop command for
        the same condition moments after the first.
        """
        condition = _breach(for_samples=2, name="latency").model_copy(update={"cooldown": 60.0})
        port = FakePort("api", value=400.0)
        service = _service(_http(), ports=_bound((ProbeFamily.HTTP, port)))
        times = _stage_times()

        first = ProbeSweep(service=service, conditions=(condition,), stage_times=times).run(
            run_id="r-x", principal="u-ana", command_id="cmd-1"
        )
        assert first.firings

        second = ProbeSweep(service=service, conditions=(condition,), stage_times=times).run(
            run_id="r-x",
            principal="u-ana",
            command_id="cmd-2",
            last_fired_epoch_s=first.firings[0].fired_at_epoch_s,
        )

        assert second.firings == ()
        assert second.stop_command is None
        # Without threading it, the same sweep would fire again.
        assert (
            ProbeSweep(service=service, conditions=(condition,), stage_times=times)
            .run(run_id="r-x", principal="u-ana", command_id="cmd-3")
            .firings
        )


# -- 2. silence produces no stop and no verdict ---------------------------------------


class TestSilenceProducesNoStopAndNoVerdict:
    """The load-bearing property, in the ways a sweep can hear nothing."""

    @pytest.mark.parametrize(
        ("behaviour", "fragment"),
        [("decline", "no observation"), ("raise", "TimeoutError")],
    )
    def test_a_dead_port_blocks_the_sweep_and_issues_no_command(
        self, behaviour: str, fragment: str
    ) -> None:
        service = _service(
            _http(), ports=_bound((ProbeFamily.HTTP, FakePort("api", behaviour=behaviour)))
        )
        sweep = ProbeSweep(
            service=service,
            conditions=(_breach(),),
            stages=WALKED,
            stage_times=dict(WALKED_TIMES),
        )

        outcome = sweep.run(run_id="r-x", principal="u-ana", command_id="cmd-x")

        assert outcome.stop_command is None
        assert outcome.stopped is False
        assert outcome.firings == ()
        assert outcome.verdict_bearing is False
        assert outcome.coverage.blind
        assert outcome.block is not None
        assert outcome.block.blind
        assert fragment in " ".join(step.note for step in outcome.steps)

    def test_an_unbound_family_blocks_the_sweep(self) -> None:
        service = _service(_http())  # no ports at all
        sweep = ProbeSweep(
            service=service,
            conditions=(_breach(),),
            stages=WALKED,
            stage_times=dict(WALKED_TIMES),
        )

        outcome = sweep.run()

        assert outcome.stop_command is None
        assert outcome.block is not None
        assert outcome.block.unobserved == ("http.api",)
        assert "no port is bound" in " ".join(step.note for step in outcome.steps)

    def test_a_partially_bound_sweep_is_partial_and_names_what_it_missed(self) -> None:
        service = _service(
            _http(),
            _tcp(),
            ports=_bound(
                (ProbeFamily.HTTP, FakePort("api", value=10.0)),
                (ProbeFamily.TCP, FakePort("db", behaviour="raise")),
            ),
        )

        outcome = ProbeSweep(
            service=service,
            conditions=(_breach(),),
            stages=WALKED,
            stage_times=dict(WALKED_TIMES),
        ).run()

        assert outcome.coverage.observed == ("http.api",)
        assert outcome.coverage.unobserved == ("tcp.db",)
        assert outcome.coverage.observations_usable
        assert not outcome.coverage.complete
        # Partial coverage still carries a verdict — with the gap named.
        assert outcome.verdict_bearing
        assert "tcp.db" in outcome.coverage.describe()
        assert outcome.block is None

    def test_a_sweep_that_only_collected_in_settling_stages_is_blind(self) -> None:
        """Warm-up readings exist, are recorded, and may not support a verdict."""
        warming = ProbeDefinition(
            id="http.warm",
            family=ProbeFamily.HTTP,
            version="1.0",
            unit="ms",
            endpoint="https://api.internal/latency",
            stages=(LifecycleStage.WARM_UP,),
            cadence=1.0,
            warmup=5.0,
        )
        service = _service(warming, ports=_bound((ProbeFamily.HTTP, FakePort("api", value=10.0))))

        outcome = ProbeSweep(service=service, stages=WALKED, stage_times=dict(WALKED_TIMES)).run()

        assert outcome.coverage.blind
        assert outcome.coverage.settling_only == ("http.warm",)
        assert outcome.verdict_bearing is False
        assert outcome.block is not None
        warming = [
            step
            for step in outcome.steps
            if step.stage is LifecycleStage.WARM_UP and step.probe_id == "http.warm"
        ]
        assert len(warming) == 1
        assert warming[0].status is SweepStepStatus.SETTLING
        assert warming[0].status is not SweepStepStatus.GRADED
        # The other three stages record the same probe as skipped-with-a-reason
        # rather than omitting it, so "we did not look there" is on the record.
        skipped = {step.stage for step in outcome.steps if step.status is SweepStepStatus.SKIPPED}
        assert skipped == set(WALKED) - {LifecycleStage.WARM_UP}

    def test_a_block_describes_itself_as_mayhems_finding_not_the_systems(self) -> None:
        service = _service(_http())
        outcome = ProbeSweep(service=service, stages=WALKED, stage_times=dict(WALKED_TIMES)).run()

        assert outcome.block is not None
        summary = outcome.describe()
        assert "mayhem" in summary.lower()
        assert "may not be reported as a healthy run" in summary
        payload = outcome.to_dict()
        assert payload["verdict_bearing"] is False
        assert payload["stop_command"] is None
        assert payload["block"]["summary"] == summary


# -- 3. a block is not a firing ------------------------------------------------------


class TestABlockIsNotAFiring:
    """The distinction this module exists to keep, asserted structurally."""

    def test_a_block_exposes_no_way_to_promote_itself_to_a_firing(self) -> None:
        """Not "we did not look today" — there is no promotion path at all.

        :class:`~mayhem.domain.stop_conditions.Firing` is the only type a stop
        command can be built from, and it refuses to be constructed without cited
        samples. A block has no samples, so it must not offer the method. The
        assertion is ``not hasattr``: a method added later would have to be handed a
        non-empty sample list to do anything, and this test would say so.
        """
        service = _service(_http())
        outcome = ProbeSweep(service=service, stages=WALKED, stage_times=dict(WALKED_TIMES)).run()

        block = outcome.block
        assert block is not None
        assert not hasattr(block, "to_firing")
        assert not hasattr(block, "samples")
        assert outcome.firings == ()
        assert outcome.stop_command is None

    def test_a_sweep_with_no_command_identity_issues_no_command(self) -> None:
        """The engine needs a run, a principal and a command id to issue a stop.

        Omitting them is the caller's way of saying "evaluate, do not stop", and
        the sweep honours it by producing the firing and *not* the command — rather
        than inventing a principal.
        """
        sweep = ProbeSweep(
            service=_service(_http(), ports=_bound((ProbeFamily.HTTP, FakePort("api", 400.0)))),
            conditions=(_breach(),),
            stages=WALKED,
            stage_times=dict(WALKED_TIMES),
        )

        outcome = sweep.run()

        assert outcome.firings
        assert outcome.stop_command is None
        assert outcome.stopped is False

    def test_the_unavailable_policy_blocks_but_still_does_not_invent_a_firing(self) -> None:
        service = _service(
            _http(),
            _tcp(),
            ports=_bound((ProbeFamily.HTTP, FakePort("api", value=10.0))),
        )
        sweep = ProbeSweep(
            service=service,
            conditions=(_breach(),),
            stages=WALKED,
            stage_times=dict(WALKED_TIMES),
            policy=UnavailablePolicy.STOP_ON_UNAVAILABLE,
        )

        outcome = sweep.run()

        # tcp.db has no port, so the sweep blocked — on coverage, not on a
        # condition, and the wording has to say which.
        assert outcome.block is not None
        assert "policy 'stop-on-unavailable'" in outcome.block.reason
        assert outcome.block.policy is UnavailablePolicy.STOP_ON_UNAVAILABLE
        assert outcome.firings == ()
        assert outcome.stop_command is None
        assert outcome.verdict_bearing is False


# -- 4. a timeout is not health ------------------------------------------------------


class TestATimeoutIsNotACleanBillOfHealth:
    def test_an_expired_window_is_reported_expired_and_fires_nothing(self) -> None:
        condition = Condition.metric(
            "http.api",
            Threshold(fires_when=FiresWhen.MET, expect=AbsoluteExpect(lte=1.0)),
            max_duration=2.0,
            name="recovery",
        )
        sweep = ProbeSweep(
            service=_service(
                _http(), ports=_bound((ProbeFamily.HTTP, FakePort("api", value=10.0)))
            ),
            conditions=(condition,),
            stages=WALKED,
            stage_times=dict(WALKED_TIMES),
        )

        outcome = sweep.run()

        statuses = {result.status for result in outcome.results}
        assert ConditionStatus.EXPIRED in statuses
        assert outcome.firings == ()
        assert outcome.stop_command is None
        # The summary must not claim the condition was satisfied or satisfied-by-time.
        assert "recovery" not in outcome.describe()
        for result in outcome.results:
            if result.status is ConditionStatus.EXPIRED:
                assert result.samples == ()

    def test_a_condition_resolving_to_no_metric_is_refused_not_reported_clear(self) -> None:
        """A typo in a metric name is the most confident wrong answer available.

        The sweep's own coverage says the run was blind, but the *condition* is a
        separate question and it refuses rather than reporting clear.
        """
        service = _service(
            _http(), ports=_bound((ProbeFamily.HTTP, FakePort("api", behaviour="decline")))
        )
        sweep = ProbeSweep(
            service=service,
            conditions=(_breach(),),
            stages=WALKED,
            stage_times=dict(WALKED_TIMES),
            policy=UnavailablePolicy.STOP_ON_UNAVAILABLE,
        )

        outcome = sweep.run()

        assert outcome.verdict_bearing is False
        with pytest.raises(InvariantViolationError) as caught:
            ProbeService.evaluate(_breach(), outcome.readings, now_epoch_s=0.0)

        assert caught.value.rule == "stop_conditions.unknown_metric"


# -- 5. lifecycle records ------------------------------------------------------------


class TestEveryStepIsRecordedWhetherOrNotItAnswered:
    def test_a_probe_that_does_not_declare_a_stage_is_recorded_as_skipped(self) -> None:
        """Lifecycle membership is a fact about the catalogue, not a silent filter."""
        sweep = ProbeSweep(
            service=_service(
                _http(),
                _tcp(),
                ports=_bound(
                    (ProbeFamily.HTTP, FakePort("api", value=10.0)),
                    (ProbeFamily.TCP, FakePort("db", value=3.0)),
                ),
            ),
            stages=(LifecycleStage.FINAL_VERIFICATION,),
            stage_times={LifecycleStage.FINAL_VERIFICATION: 9.0},
        )

        outcome = sweep.run()

        by_id = {step.probe_id: step for step in outcome.steps}
        assert by_id["http.api"].status is SweepStepStatus.GRADED
        assert by_id["tcp.db"].status is SweepStepStatus.SKIPPED
        assert by_id["tcp.db"].note == STEP_SKIPPED_NOT_DECLARED

    def test_a_sweep_step_carries_the_reading_it_produced(self) -> None:
        sweep = ProbeSweep(
            service=_service(
                _http(), ports=_bound((ProbeFamily.HTTP, FakePort("api", value=10.0)))
            ),
            stages=(LifecycleStage.DURING_FAULT,),
            stage_times={LifecycleStage.DURING_FAULT: 4.0},
        )

        outcome = sweep.run()

        graded = [step for step in outcome.steps if step.graded]
        assert len(graded) == 1
        assert graded[0].reading is not None
        assert graded[0].reading.observation.value == 10.0
        assert graded[0].at_epoch_s == 4.0
        assert graded[0].family == "http"
        assert graded[0].to_dict()["reading"]["availability"] == "available"

    def test_metric_names_for_is_the_set_a_condition_may_reference(self) -> None:
        """Derived from the engine's own function, so the two cannot disagree."""
        service = _service(_http(), _tcp())

        assert metric_names_for(service.definitions) == ("http.api", "tcp.db")


# -- negative controls ---------------------------------------------------------------


class TestTheSweepRefusalsAreRealGates:
    """Each negative control *breaks* a property and shows the guard fires."""

    def test_a_sweep_with_no_stages_is_refused_rather_than_passing_vacuously(self) -> None:
        """The property: a sweep that walks nothing observes nothing.

        **The control:** with the emptiness check removed this sweep would run,
        collect nothing, produce zero results, and report ``verdict_bearing`` from a
        coverage of nothing — a clean bill of health produced by checking nothing.
        That is the same defect the preflight gate calls out as a vacuous gate, so
        it is refused at construction here too. The exception type is named, not
        ``Exception``: a private exception asserted broadly would be a tautology.
        """
        with pytest.raises(SweepRefusalError) as caught:
            ProbeSweep(service=_service(_http()), stages=(), stage_times={})

        assert "no stages" in str(caught.value)
        assert "reported as a completed run with nothing behind it" in str(caught.value)

    def test_a_missing_stage_time_is_refused_rather_than_defaulted(self) -> None:
        """A defaulted stage time would produce a firing nobody could replay."""
        with pytest.raises(SweepRefusalError) as caught:
            ProbeSweep(
                service=_service(_http()),
                stages=(LifecycleStage.DURING_FAULT, LifecycleStage.FINAL_VERIFICATION),
                stage_times={LifecycleStage.DURING_FAULT: 1.0},
            )

        assert "a time for every stage" in str(caught.value)
        assert "final-verification" in str(caught.value)
        assert "replayed" in str(caught.value)

    def test_a_sweep_never_reads_a_clock(self) -> None:
        """Structural, not behavioural: the sweep has no clock parameter at all.

        If a future change added ``now_fn=`` the dataclass would gain a parameter
        and this fails. It is the cheapest available guard against a sweep that
        becomes irreproducible by accident.
        """
        fields = set(ProbeSweep.__dataclass_fields__)

        assert fields == {
            "service",
            "conditions",
            "stages",
            "stage_times",
            "policy",
            "baselines",
        }
        assert not any("now" in name or "clock" in name for name in fields)

    def test_an_unknown_lifecycle_stage_cannot_be_walked(self) -> None:
        """The stage vocabulary is closed, so a typo cannot become a silent no-op."""
        with pytest.raises(ValueError):
            LifecycleStage("during-faultt")

    def test_a_drifted_plan_never_reaches_a_port(self) -> None:
        """Re-proved at the sweep level: the drift check is construction."""
        exploding = ExplodingPort()

        with pytest.raises(InvariantViolationError):
            ProbeSweep(
                service=ProbeService(
                    catalogue=ProbeCatalog(definitions=(_http(version="2.0"),)),
                    plan=ProbePlan(pins=(ProbePin.of(_http(version="1.0")),)),
                    ports=_bound((ProbeFamily.HTTP, exploding)),
                ),
                stage_times=_stage_times(),
            )

        assert exploding.calls == 0

    def test_a_wrong_shaped_answer_is_unavailable_and_never_graded(self) -> None:
        """The engine's availability word, read through the sweep's own status."""
        sweep = ProbeSweep(
            service=_service(
                _http(), ports=_bound((ProbeFamily.HTTP, FakePort("api", behaviour="wrong-shape")))
            ),
            stages=WALKED,
            stage_times=dict(WALKED_TIMES),
        )

        outcome = sweep.run()

        statuses = {step.status for step in outcome.steps}
        assert SweepStepStatus.UNAVAILABLE in statuses
        assert SweepStepStatus.GRADED not in statuses
        assert outcome.verdict_bearing is False

    def test_the_sweep_is_a_function_of_its_inputs(self) -> None:
        """Determinism, so a stop can be replayed from the same inputs."""
        sweep = _healthy_sweep(conditions=(_breach(),))

        assert sweep.run().to_dict() == sweep.run().to_dict()

    def test_availability_comes_from_the_engine_and_not_from_the_sweep(self) -> None:
        """The sweep has no availability vocabulary of its own, by construction."""
        assert ProbeAvailability.AVAILABLE.value == "available"
        assert ProbeAvailability.UNAVAILABLE.value == "unavailable"
        assert not hasattr(ProbeSweepOutcome, "available")
        assert not hasattr(SweepStep, "availability")
        # And it is the engine's function that decides, not the sweep's own copy.
        assert ProbeCoverage.of(()).blind is True
