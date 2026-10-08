"""Probe definitions: the eighteen families, the lifecycle, the pins.

Plan 11 asks for probe definitions as *data* — "endpoints, queries, sampling
cadence, lifecycle membership" — and the risk in that sentence is not writing
too little but writing a second probe hierarchy alongside the one in
:mod:`mayhem.domain.checks`. These tests are therefore organised around five
questions:

1. **Do the eighteen families exist as data, and is each one *located*?** Every
   family in the plan is constructible, and every family refuses a definition
   that cannot say what it points at or asks. A probe with no endpoint and no
   query is a probe that resolves to nothing, and a probe that resolves to
   nothing reports calm.
2. **Does the definition extend the existing vocabulary rather than fork it?**
   The carrier must be a member of the closed ``Probe`` union, and the right
   one for the family; a definition and its carrier must not disagree about
   where they point; the source kind must be one that exists.
3. **Is lifecycle membership real, and is noise budgeted?** The six stages anchor
   to the three ``Phase`` values the verdict core grades in. Claiming
   ``warm-up`` without a ``warmup`` budget — or declaring a budget with no
   settling stage — is refused in both directions, because either alone either
   does nothing or discovers its noise mid-verdict.
4. **Can a plan pin a probe, and is drift caught?** Version *and* fingerprint,
   so both a version bump and an in-place edit are caught; the second is the
   one a version-only pin reports as healthy.
5. **Are the failures loud?** A reading in the wrong unit is refused rather
   than converted, and a probe that asks for a categorical reading is refused
   because ``ObservationResult`` has nowhere to put one — with a guard test
   that fails the moment somebody adds the field, so the refusal cannot rot
   into a lie.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mayhem.domain.checks import (
    ExecProbe,
    FileProbe,
    HttpProbe,
    MetricProbe,
    ProbeType,
    ProcessProbe,
    TcpProbe,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.leases import VerifyProbe
from mayhem.domain.observability import ObservabilitySourceKind
from mayhem.domain.observations import ObservationResult, ObservationStatus
from mayhem.domain.probes import (
    CATEGORICAL_REFUSAL_CODE,
    LOCATOR_FIELDS,
    SUPPORTED_TOLERANCE_KINDS,
    LifecycleStage,
    ProbeCatalog,
    ProbeDefinition,
    ProbeFamily,
    ProbePin,
    ProbePlan,
    ProbeValueKind,
    graded_stages,
    stage_phase,
)
from mayhem.domain.steady_state import Phase
from mayhem.domain.stop_conditions import ToleranceKind

# -- fixtures -----------------------------------------------------------------------

#: The eighteen families plan 11 lists, each with the locator that makes it that
#: family and a plausible unit. Spelled out per family rather than generated:
#: the point of the test is that every one of these *is* expressible as data.
_LOCATORS: dict[ProbeFamily, dict[str, object]] = {
    ProbeFamily.HTTP: {"endpoint": "https://api.internal/healthz"},
    ProbeFamily.TCP: {"endpoint": "api.internal:8443"},
    ProbeFamily.UDP: {"endpoint": "dns.internal:53"},
    ProbeFamily.DNS: {"query": "api.internal", "endpoint": "10.0.0.2:53"},
    ProbeFamily.GRPC: {"endpoint": "grpc://mesh.internal:9000"},
    ProbeFamily.SQL: {"query": "SELECT count(*) FROM orders", "endpoint": "pg://db/app"},
    ProbeFamily.REDIS: {"query": "PING", "endpoint": "redis://cache:6379"},
    ProbeFamily.KAFKA: {"query": "__consumer_offsets", "endpoint": "kafka-1:9092"},
    ProbeFamily.RABBITMQ: {"query": "queue.payments", "endpoint": "amqp://rmq:5672"},
    ProbeFamily.NATS: {"query": "orders.received", "endpoint": "nats://bus:4222"},
    ProbeFamily.PROCESS: {"target": "nginx"},
    ProbeFamily.FILE: {"path": "/var/run/app/ready"},
    ProbeFamily.COMMAND: {"command": ("pg_isready", "-h", "db.internal")},
    ProbeFamily.PROMETHEUS: {
        "endpoint": "http://prom.internal:9090/metrics",
        "query": "http_request_duration_seconds_count",
    },
    ProbeFamily.OPENTELEMETRY: {"query": "service.name=checkout"},
    ProbeFamily.LOGS: {"query": '{app="checkout"} |= "error"'},
    ProbeFamily.TRACES: {"query": "service.name=checkout AND status=error"},
    ProbeFamily.KUBERNETES: {"target": "deployment/api", "query": "status.readyReplicas"},
    ProbeFamily.SYNTHETIC: {"steps": ("POST /cart", "POST /checkout", "GET /order")},
}

_UNITS: dict[ProbeFamily, str] = {
    ProbeFamily.HTTP: "ms",
    ProbeFamily.TCP: "ms",
    ProbeFamily.UDP: "ms",
    ProbeFamily.DNS: "ms",
    ProbeFamily.GRPC: "ms",
    ProbeFamily.SQL: "count",
    ProbeFamily.REDIS: "ms",
    ProbeFamily.KAFKA: "count",
    ProbeFamily.RABBITMQ: "count",
    ProbeFamily.NATS: "count",
    ProbeFamily.PROCESS: "count",
    ProbeFamily.FILE: "count",
    ProbeFamily.COMMAND: "count",
    ProbeFamily.PROMETHEUS: "s",
    ProbeFamily.OPENTELEMETRY: "ms",
    ProbeFamily.LOGS: "count",
    ProbeFamily.TRACES: "count",
    ProbeFamily.KUBERNETES: "count",
    ProbeFamily.SYNTHETIC: "ms",
}

ALL_FAMILIES = tuple(ProbeFamily)

#: The locators each family accepts as *its own*, restated independently of the
#: module's table so the contract is asserted rather than exercised. A family
#: with two entries accepts either one; every other family accepts exactly one.
ACCEPTED_LOCATORS: dict[ProbeFamily, tuple[str, ...]] = {
    ProbeFamily.HTTP: ("endpoint",),
    ProbeFamily.TCP: ("endpoint",),
    ProbeFamily.UDP: ("endpoint",),
    ProbeFamily.DNS: ("query",),
    ProbeFamily.GRPC: ("endpoint",),
    ProbeFamily.SQL: ("query",),
    ProbeFamily.REDIS: ("query",),
    ProbeFamily.KAFKA: ("query",),
    ProbeFamily.RABBITMQ: ("query",),
    ProbeFamily.NATS: ("query",),
    ProbeFamily.PROCESS: ("target",),
    ProbeFamily.FILE: ("path",),
    ProbeFamily.COMMAND: ("command",),
    ProbeFamily.PROMETHEUS: ("query",),
    ProbeFamily.OPENTELEMETRY: ("query",),
    ProbeFamily.LOGS: ("query",),
    ProbeFamily.TRACES: ("query",),
    # A Kubernetes state probe is located either by the object it reads
    # (``deployment/api``) or by the field it selects (``status.readyReplicas``),
    # so either alone is a complete locator. The only family where that is true.
    ProbeFamily.KUBERNETES: ("target", "query"),
    ProbeFamily.SYNTHETIC: ("steps",),
}


def _expected_locator(family: ProbeFamily, field: str) -> str:
    value = _LOCATORS[family][field]
    return " ".join(value) if isinstance(value, tuple) else str(value)


#: A carrier per carried family, agreeing with that family's locators.
_CARRIERS: dict[ProbeFamily, Any] = {
    ProbeFamily.HTTP: lambda: HttpProbe(url="https://api.internal/healthz"),
    ProbeFamily.TCP: lambda: TcpProbe(host="api.internal", port=8443),
    ProbeFamily.PROCESS: lambda: ProcessProbe(name="nginx"),
    ProbeFamily.FILE: lambda: FileProbe(path="/var/run/app/ready"),
    ProbeFamily.COMMAND: lambda: ExecProbe(cmd=("pg_isready", "-h", "db.internal")),
    ProbeFamily.PROMETHEUS: lambda: MetricProbe(
        endpoint="http://prom.internal:9090/metrics",
        query="http_request_duration_seconds_count",
    ),
}

#: The families the closed ``Probe`` union has a member for. Spelled out here
#: on purpose: the complement is the interesting half, and deriving it from the
#: module's own table would make the test agree with whatever that table says.
CARRIED_FAMILIES = (
    ProbeFamily.HTTP,
    ProbeFamily.TCP,
    ProbeFamily.PROCESS,
    ProbeFamily.FILE,
    ProbeFamily.COMMAND,
    ProbeFamily.PROMETHEUS,
)
CARRIERLESS_FAMILIES = tuple(f for f in ALL_FAMILIES if f not in CARRIED_FAMILIES)


def _definition(family: ProbeFamily, **overrides: Any) -> ProbeDefinition:
    """A valid definition for ``family``, with ``overrides`` applied on top."""
    payload: dict[str, Any] = {
        "id": f"{family.value}.probe",
        "family": family,
        "version": "1.0",
        "unit": _UNITS[family],
        "stages": (LifecycleStage.PRE_BASELINE,),
        **_LOCATORS[family],
    }
    payload.update(overrides)
    return ProbeDefinition(**payload)


def _http(**overrides: Any) -> ProbeDefinition:
    overrides.setdefault("id", "http.health")
    return _definition(ProbeFamily.HTTP, **overrides)


def _blank_locators() -> dict[str, Any]:
    """Every locator emptied — the state no family may be constructed from."""
    return {field: () if field in ("command", "steps") else "   " for field in LOCATOR_FIELDS}


def _reading(
    unit: str = "ms",
    metric: str = "http.health",
    value: float | None = 120.0,
    status: ObservationStatus = ObservationStatus.OK,
) -> ObservationResult:
    return ObservationResult(
        metric=metric,
        value=value,
        unit=unit,
        window_s=10.0,
        status=status,
    )


def _catalogue() -> ProbeCatalog:
    return ProbeCatalog(definitions=tuple(_definition(f) for f in ALL_FAMILIES))


# -- 1. per-family definitions ------------------------------------------------------


class TestProbeFamilies:
    def test_the_plans_eighteen_families_all_exist(self) -> None:
        assert {family.value for family in ProbeFamily} == {
            "http",
            "tcp",
            "udp",
            "dns",
            "grpc",
            "sql",
            "redis",
            "kafka",
            "rabbitmq",
            "nats",
            "process",
            "file",
            "command",
            "prometheus",
            "opentelemetry",
            "logs",
            "traces",
            "kubernetes",
            "synthetic",
        }
        assert len(ProbeFamily) == 19  # see the comment above

    @pytest.mark.parametrize("family", ALL_FAMILIES)
    def test_every_family_is_expressible_as_data(self, family: ProbeFamily) -> None:
        definition = _definition(family)
        assert definition.family is family
        assert definition.unit == _UNITS[family]
        assert definition.locator
        assert definition.version == "1.0"

    @pytest.mark.parametrize("family", ALL_FAMILIES)
    def test_every_family_refuses_a_definition_with_no_locator(self, family: ProbeFamily) -> None:
        """The negative control: nothing to point at, nothing to ask, no probe."""
        with pytest.raises(InvariantViolationError) as refused:
            _definition(family, **_blank_locators())
        assert refused.value.rule == "probes.probe_without_locator"
        assert "resolves to nothing" in str(refused.value)

    @pytest.mark.parametrize("family", ALL_FAMILIES)
    def test_whitespace_is_not_a_locator(self, family: ProbeFamily) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _definition(family, **dict(_blank_locators()))
        assert refused.value.rule == "probes.probe_without_locator"

    @pytest.mark.parametrize("family", ALL_FAMILIES)
    def test_each_family_accepts_only_its_own_locators(self, family: ProbeFamily) -> None:
        """Pins the required-locator table, not merely its existence.

        Blanking every locator at once only proves the table has *a* required
        field. Blanking just this family's own locator(s) while keeping every
        other one — including a plausible-looking address — proves which field
        it is, so swapping ``dns``'s ``query`` for ``endpoint`` in the module
        fails here instead of passing quietly.
        """
        accepted = ACCEPTED_LOCATORS[family]
        refused_payload = dict(_blank_locators())
        for field, value in _LOCATORS[family].items():
            if field not in accepted:
                refused_payload[field] = value
        with pytest.raises(InvariantViolationError) as refused:
            _definition(family, **refused_payload)
        assert refused.value.rule == "probes.probe_without_locator"

    @pytest.mark.parametrize("family", ALL_FAMILIES)
    def test_each_accepted_locator_is_complete_on_its_own(self, family: ProbeFamily) -> None:
        """The other direction: any one accepted locator is enough, alone."""
        accepted = ACCEPTED_LOCATORS[family]
        for kept in accepted:
            payload = dict(_blank_locators())
            for field, value in _LOCATORS[family].items():
                if field in accepted and field != kept:
                    continue  # blank the family's *other* accepted locators
                payload[field] = value
            definition = _definition(family, **payload)
            assert definition.locator == _expected_locator(family, kept)

    def test_a_question_shaped_family_will_not_accept_an_address_as_a_substitute(self) -> None:
        """A DNS probe pointed at a resolver with no name to resolve is TCP."""
        with pytest.raises(InvariantViolationError) as refused:
            ProbeDefinition(
                id="dns.reachable",
                family=ProbeFamily.DNS,
                version="1.0",
                unit="ms",
                endpoint="10.0.0.2:53",
                stages=(LifecycleStage.PRE_BASELINE,),
            )
        assert refused.value.rule == "probes.probe_without_locator"

    def test_http_requires_an_absolute_url(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _http(endpoint="/healthz")
        assert refused.value.rule == "probes.http_endpoint_not_absolute"
        assert _http(endpoint="http://api.internal/healthz").family is ProbeFamily.HTTP

    def test_unit_must_be_declared(self) -> None:
        with pytest.raises(ValidationError):
            _http(unit="")  # type: ignore[call-overload]
        with pytest.raises(InvariantViolationError) as refused:
            _http(unit="   ")
        assert refused.value.rule == "probes.probe_unit_blank"

    def test_a_synthetic_transaction_is_a_list_of_steps(self) -> None:
        definition = _definition(ProbeFamily.SYNTHETIC)
        assert definition.steps == ("POST /cart", "POST /checkout", "GET /order")
        assert definition.locator == "POST /cart POST /checkout GET /order"

    def test_a_command_probe_is_argv_not_a_string(self) -> None:
        definition = _definition(ProbeFamily.COMMAND)
        assert definition.command == ("pg_isready", "-h", "db.internal")
        assert definition.locator == "pg_isready -h db.internal"

    def test_planned_samples_reflects_window_over_cadence(self) -> None:
        assert _http(cadence=5.0, window=30.0).planned_samples == 6
        assert _http(cadence=5.0, window=3.0).planned_samples == 1
        assert _http(cadence=0.0, window=300.0).planned_samples == 1


# -- 2. extending the existing vocabulary --------------------------------------------


class TestVocabularyIsExtendedNotForked:
    def test_a_definition_may_carry_an_existing_probe_as_its_carrier(self) -> None:
        definition = _http(carrier=HttpProbe(url="https://api.internal/healthz"))
        assert definition.carrier_type is ProbeType.HTTP
        assert definition.carrier is not None
        assert definition.carrier.type is ProbeType.HTTP

    def test_a_carrier_of_the_wrong_kind_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _http(carrier=TcpProbe(host="api.internal", port=8443))
        assert refused.value.rule == "probes.probe_carrier_mismatch"

    def test_a_definition_and_its_carrier_must_agree_where_they_point(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _http(carrier=HttpProbe(url="https://other.internal/healthz"))
        assert refused.value.rule == "probes.probe_carrier_locator_conflict"

    def test_an_omitted_locator_is_left_to_the_carrier(self) -> None:
        definition = _definition(
            ProbeFamily.PROMETHEUS,
            endpoint="",
            carrier=MetricProbe(endpoint="", query="http_request_duration_seconds_count"),
        )
        assert definition.carrier is not None
        assert definition.locator == "http_request_duration_seconds_count"

    @pytest.mark.parametrize("family", CARRIED_FAMILIES)
    def test_a_carried_family_names_its_probe_type(self, family: ProbeFamily) -> None:
        definition = _definition(family, carrier=_CARRIERS[family]())
        assert definition.carrier is not None
        assert definition.carrier_type is definition.carrier.type

    def test_the_tcp_carrier_locals_are_deliberately_not_parsed_here(self) -> None:
        """A stated gap, so a reader does not mistake it for an oversight.

        A ``TcpProbe`` carries ``host`` + ``port`` where the definition carries
        one address string. Comparing them needs a parsing rule for the address,
        and inventing one here would decide what ``api.internal:8443`` means
        without the collector that has to dial it. The engine is the only place
        that knows.
        """
        definition = _definition(
            ProbeFamily.TCP,
            carrier=TcpProbe(host="somewhere.else", port=1),
        )
        assert definition.carrier is not None

    @pytest.mark.parametrize("family", CARRIERLESS_FAMILIES)
    def test_a_family_with_no_probe_in_the_union_carries_none(self, family: ProbeFamily) -> None:
        """A SQL probe is not an ExecProbe with a statement in it."""
        definition = _definition(family)
        assert definition.carrier is None
        assert definition.carrier_type is None
        with pytest.raises(InvariantViolationError) as refused:
            _definition(family, carrier=ExecProbe(cmd=("sh", "-c", "true")))
        assert refused.value.rule == "probes.probe_carrier_unsupported"
        assert "second probe hierarchy" in str(refused.value)

    def test_a_definition_may_name_the_lease_vocabularys_verify_probe(self) -> None:
        definition = _http(
            verify=VerifyProbe(probe="exec", args={"cmd": ["systemctl", "is-active", "nginx"]})
        )
        assert definition.verify is not None
        assert definition.verify.probe == "exec"

    @pytest.mark.parametrize(
        ("family", "expected"),
        (
            (ProbeFamily.HTTP, ObservabilitySourceKind.PROBE),
            (ProbeFamily.COMMAND, ObservabilitySourceKind.PROBE),
            (ProbeFamily.PROMETHEUS, ObservabilitySourceKind.METRICS),
            (ProbeFamily.LOGS, ObservabilitySourceKind.LOGS),
        ),
    )
    def test_source_kind_matches_the_existing_collectors(
        self, family: ProbeFamily, expected: ObservabilitySourceKind
    ) -> None:
        assert _definition(family).expected_source_kind is expected
        assert _definition(family, source_kind=expected).source_kind is expected

    def test_a_source_kind_the_family_does_not_use_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _definition(ProbeFamily.PROMETHEUS, source_kind=ObservabilitySourceKind.LOGS)
        assert refused.value.rule == "probes.probe_source_kind_mismatch"

    def test_a_source_kind_that_does_not_exist_for_the_family_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _definition(ProbeFamily.TRACES, source_kind=ObservabilitySourceKind.PROBE)
        assert refused.value.rule == "probes.probe_source_kind_unsupported"

    def test_probe_constructs_the_mayhem_process_and_file_probes_unaffected(self) -> None:
        """The closed union this module extends is still the one in checks."""
        process = _definition(ProbeFamily.PROCESS, carrier=ProcessProbe(name="nginx"))
        file_probe = _definition(ProbeFamily.FILE, carrier=FileProbe(path="/var/run/app/ready"))
        assert process.carrier is not None
        assert process.carrier.type is ProbeType.PROCESS
        assert file_probe.carrier is not None
        assert file_probe.carrier.type is ProbeType.FILE


# -- 3. lifecycle membership --------------------------------------------------------


class TestLifecycle:
    def test_the_six_plan_stages_anchor_to_the_three_existing_phases(self) -> None:
        assert {stage.value for stage in LifecycleStage} == {
            "pre-baseline",
            "warm-up",
            "during-fault",
            "continuous",
            "after-recovery",
            "final-verification",
        }
        mapping = {stage: stage_phase(stage) for stage in LifecycleStage}
        assert all(isinstance(phase, Phase) for phase in mapping.values())
        assert set(mapping.values()) == {Phase.PRE, Phase.DURING, Phase.POST}
        assert mapping[LifecycleStage.PRE_BASELINE] is Phase.PRE
        assert mapping[LifecycleStage.DURING_FAULT] is Phase.DURING
        assert mapping[LifecycleStage.FINAL_VERIFICATION] is Phase.POST

    def test_phases_are_derived_from_stages_in_phase_order(self) -> None:
        definition = _http(
            stages=(
                LifecycleStage.FINAL_VERIFICATION,
                LifecycleStage.DURING_FAULT,
                LifecycleStage.PRE_BASELINE,
            )
        )
        assert definition.phases == (Phase.PRE, Phase.DURING, Phase.POST)
        assert definition.stages_in_phase(Phase.DURING) == (LifecycleStage.DURING_FAULT,)

    def test_a_probe_with_no_lifecycle_stage_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _http(stages=())
        assert refused.value.rule == "probes.probe_without_stage"
        assert "baseline of the perturbation" in str(refused.value)

    def test_a_repeated_stage_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _http(stages=(LifecycleStage.DURING_FAULT, LifecycleStage.DURING_FAULT))
        assert refused.value.rule == "probes.probe_duplicate_stage"

    def test_warm_up_requires_a_declared_budget(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _http(stages=(LifecycleStage.WARM_UP,))
        assert refused.value.rule == "probes.probe_noise_budget_missing"
        budgeted = _http(stages=(LifecycleStage.WARM_UP,), warmup=30.0)
        assert float(budgeted.warmup) == 30.0

    def test_after_recovery_requires_a_cooldown(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _http(stages=(LifecycleStage.AFTER_RECOVERY,))
        assert refused.value.rule == "probes.probe_noise_budget_missing"
        assert float(_http(stages=(LifecycleStage.AFTER_RECOVERY,), cooldown=45.0).cooldown) == 45.0

    def test_a_budget_with_no_settling_stage_is_refused(self) -> None:
        """A number that never affects a reading reads as a control."""
        with pytest.raises(InvariantViolationError) as warmup:
            _http(stages=(LifecycleStage.DURING_FAULT,), warmup=30.0)
        assert warmup.value.rule == "probes.probe_noise_budget_unclaimed"
        with pytest.raises(InvariantViolationError) as cooldown:
            _http(stages=(LifecycleStage.DURING_FAULT,), cooldown=30.0)
        assert cooldown.value.rule == "probes.probe_noise_budget_unclaimed"

    def test_settling_stages_are_recorded_but_never_graded(self) -> None:
        definition = _http(
            stages=(
                LifecycleStage.PRE_BASELINE,
                LifecycleStage.WARM_UP,
                LifecycleStage.DURING_FAULT,
                LifecycleStage.AFTER_RECOVERY,
                LifecycleStage.FINAL_VERIFICATION,
            ),
            warmup=20.0,
            cooldown=60.0,
        )
        assert definition.excluded_stages == (
            LifecycleStage.WARM_UP,
            LifecycleStage.AFTER_RECOVERY,
        )
        assert definition.graded_stages == (
            LifecycleStage.PRE_BASELINE,
            LifecycleStage.DURING_FAULT,
            LifecycleStage.FINAL_VERIFICATION,
        )
        assert graded_stages(definition) == definition.graded_stages

    def test_continuous_must_claim_both_ends_of_the_run(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _http(stages=(LifecycleStage.CONTINUOUS,))
        assert refused.value.rule == "probes.probe_continuous_not_spanning"
        spanning = _http(
            stages=(
                LifecycleStage.PRE_BASELINE,
                LifecycleStage.CONTINUOUS,
                LifecycleStage.FINAL_VERIFICATION,
            )
        )
        assert spanning.phases == (Phase.PRE, Phase.DURING, Phase.POST)

    def test_a_repeating_stage_refuses_a_cadence_of_zero(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _http(stages=(LifecycleStage.DURING_FAULT,), cadence=0.0)
        assert refused.value.rule == "probes.probe_cadence_conflicts_with_stages"
        assert "spike reported as a plateau" in str(refused.value)

    def test_a_one_shot_stage_may_collect_once(self) -> None:
        definition = _http(stages=(LifecycleStage.FINAL_VERIFICATION,), cadence=0.0)
        assert float(definition.cadence) == 0.0
        assert definition.planned_samples == 1

    def test_a_catalogue_selects_by_family_stage_and_phase(self) -> None:
        catalogue = _catalogue()
        assert catalogue.select(family=ProbeFamily.HTTP) == (_definition(ProbeFamily.HTTP),)
        assert len(catalogue.select(stage=LifecycleStage.PRE_BASELINE)) == len(ALL_FAMILIES)
        assert len(catalogue.select(phase=Phase.POST)) == 0
        assert catalogue.select(family=ProbeFamily.SQL, phase=Phase.PRE) != ()


# -- 4. version pinning -------------------------------------------------------------


class TestVersionPinning:
    def test_a_version_is_required_and_must_be_dotted(self) -> None:
        with pytest.raises(ValidationError):
            _http(version="")  # type: ignore[call-overload]
        with pytest.raises(ValidationError):
            _http(version="v1")  # type: ignore[call-overload]
        with pytest.raises(ValidationError):
            _http(version="1")  # type: ignore[call-overload]
        assert _http(version="1.4.2").version == "1.4.2"

    def test_a_pin_carries_id_version_and_fingerprint(self) -> None:
        definition = _http()
        pin = ProbePin.of(definition)
        assert pin.id == definition.id
        assert pin.version == definition.version
        assert pin.fingerprint == definition.fingerprint
        assert pin.describe == "http.health@1.0"

    def test_a_pin_may_not_be_satisfied_by_a_version_alone(self) -> None:
        with pytest.raises(ValidationError):
            ProbePin(id="http.health", version="1.0", fingerprint="not-a-digest")  # type: ignore[arg-type]
        with pytest.raises(ValidationError):
            ProbePin(id="http.health", version="1.0", fingerprint="a" * 63)  # type: ignore[arg-type]

    def test_a_plan_binds_every_pin_in_pin_order(self) -> None:
        catalogue = _catalogue()
        plan = ProbePlan(
            pins=(
                ProbePin.of(_definition(ProbeFamily.HTTP)),
                ProbePin.of(_definition(ProbeFamily.SQL)),
            )
        )
        assert plan.bind(catalogue) == (
            _definition(ProbeFamily.HTTP),
            _definition(ProbeFamily.SQL),
        )
        plan.assert_resolvable(catalogue)

    def test_a_catalogue_can_pin_itself_into_a_plan(self) -> None:
        catalogue = _catalogue()
        plan = catalogue.plan()
        assert len(plan.pins) == len(ALL_FAMILIES)
        assert plan.assert_resolvable(catalogue) is None

    def test_an_empty_plan_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            ProbePlan(pins=())
        assert refused.value.rule == "probes.empty_plan"
        assert "watched the whole system" in str(refused.value)

    def test_two_pins_for_one_probe_are_refused(self) -> None:
        pin = ProbePin.of(_http())
        with pytest.raises(InvariantViolationError) as refused:
            ProbePlan(pins=(pin, pin))
        assert refused.value.rule == "probes.duplicate_pin"

    def test_two_definitions_for_one_id_are_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            ProbeCatalog(definitions=(_http(), _http()))
        assert refused.value.rule == "probes.duplicate_probe_id"

    def test_the_fingerprint_ignores_prose_but_nothing_else(self) -> None:
        definition = _http()
        reworded = _http(description="A much friendlier description of the same probe.")
        moved = _http(endpoint="https://api.internal/readyz")
        assert reworded.fingerprint == definition.fingerprint
        assert moved.fingerprint != definition.fingerprint

    def test_the_fingerprint_covers_the_schedule_and_the_lifecycle(self) -> None:
        definition = _http()
        assert _http(cadence=2.0).fingerprint != definition.fingerprint
        restaged = _http(stages=(LifecycleStage.FINAL_VERIFICATION,))
        assert restaged.fingerprint != definition.fingerprint
        assert _http(unit="s").fingerprint != definition.fingerprint

    def test_a_probe_the_catalogue_does_not_have_is_unpinned(self) -> None:
        plan = ProbePlan(pins=(ProbePin(id="absent.probe", version="1.0", fingerprint="0" * 64),))
        with pytest.raises(InvariantViolationError) as refused:
            plan.bind(_catalogue())
        assert refused.value.rule == "probes.unpinned_probe"
        assert "would run without it" in str(refused.value)

    def test_a_version_that_moved_since_the_plan_is_refused(self) -> None:
        pinned = _http()
        plan = ProbePlan(pins=(ProbePin.of(pinned),))
        moved = _http(version="1.1", endpoint=pinned.endpoint)
        with pytest.raises(InvariantViolationError) as refused:
            plan.bind(ProbeCatalog(definitions=(moved,)))
        assert refused.value.rule == "probes.probe_version_drift"
        assert "1.0" in str(refused.value) and "1.1" in str(refused.value)

    def test_a_definition_edited_without_a_version_bump_is_refused(self) -> None:
        """The drift a version-only pin would happily call healthy."""
        pinned = _http()
        plan = ProbePlan(pins=(ProbePin.of(pinned),))
        edited = pinned.model_copy(update={"endpoint": "https://api.internal/readyz"})
        assert edited.version == pinned.version
        with pytest.raises(InvariantViolationError) as refused:
            plan.bind(ProbeCatalog(definitions=(edited,)))
        assert refused.value.rule == "probes.probe_definition_drift"
        assert "without a version bump" in str(refused.value)

    def test_a_plan_reports_which_probe_it_does_not_authorise(self) -> None:
        plan = ProbePlan(pins=(ProbePin.of(_http()),))
        assert plan.pin_for("http.health") is not None
        assert plan.pin_for("sql.probe") is None
        assert plan.covers(_http()) is True
        assert plan.covers(_http(version="1.1")) is False
        assert plan.covers(_definition(ProbeFamily.SQL)) is False

    def test_an_unknown_probe_id_is_refused_rather_than_returning_none(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _catalogue().get("absent.probe")
        assert refused.value.rule == "probes.unknown_probe"


# -- 5. units and the categorical refusal --------------------------------------------


class TestUnits:
    def test_a_reading_in_the_declared_unit_is_accepted(self) -> None:
        definition = _http(unit="ms")
        assert definition.unit_matches(_reading(unit="ms")) is True
        assert definition.check_reading(_reading(unit="ms")) is None

    def test_a_reading_in_another_unit_is_refused_and_not_converted(self) -> None:
        definition = _http(unit="ms")
        reading = _reading(unit="s", value=0.25)  # the same measurement, honestly labelled
        assert definition.unit_matches(reading) is False
        with pytest.raises(InvariantViolationError) as refused:
            definition.check_reading(reading)
        assert refused.value.rule == "probes.probe_reading_unit_mismatch"
        assert "never both" in str(refused.value)

    def test_unit_identity_tolerates_case_and_whitespace_only(self) -> None:
        definition = _http(unit="ms")
        assert definition.unit_matches(_reading(unit=" MS ")) is True
        assert definition.unit_matches(_reading(unit="milliseconds")) is False

    def test_a_missing_reading_is_not_a_unit_problem(self) -> None:
        """Availability is stop_conditions' business, not this module's."""
        definition = _http(unit="ms")
        missing = _reading(status=ObservationStatus.MISSING, value=None)
        assert definition.check_reading(missing) is None

    def test_every_family_declares_the_unit_its_reading_must_be_in(self) -> None:
        for family in ALL_FAMILIES:
            definition = _definition(family)
            assert definition.unit.strip()
            with pytest.raises(InvariantViolationError):
                definition.check_reading(_reading(unit="furlongs"))


class TestCategoricalIsRefusedDeliberately:
    def test_a_categorical_probe_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            _http(value_kind=ProbeValueKind.CATEGORICAL)
        assert refused.value.rule == CATEGORICAL_REFUSAL_CODE
        assert "carries no label" in str(refused.value)
        assert "adding the tolerance without the value" in str(refused.value)

    def test_a_numeric_probe_is_the_default(self) -> None:
        assert _http().value_kind is ProbeValueKind.NUMERIC
        assert ProbeValueKind.CATEGORICAL.value == "categorical"

    def test_the_refusals_precondition_still_holds(self) -> None:
        """The guard on the guard.

        ``probes.categorical_unsupported`` is only honest while the observation
        contract cannot carry a categorical value. The moment somebody adds one
        to :class:`ObservationResult`, this test fails and the refusal has to be
        lifted in the same commit — rather than the two drifting apart until the
        module refuses something it claims cannot exist.
        """
        fields = set(ObservationResult.__dataclass_fields__)
        assert not (fields & {"label", "category", "state", "value_text", "text"}), (
            "ObservationResult now carries a non-numeric field: the categorical "
            "refusal in domain/probes.py must be lifted in this commit, not left "
            f"behind. New fields: {sorted(fields)}"
        )
        assert ObservationResult.__dataclass_fields__["value"].type in (
            "float | None",
            "Optional[float]",
        )

    def test_no_categorical_tolerance_mechanism_exists_either(self) -> None:
        assert not hasattr(ToleranceKind, "CATEGORICAL")
        assert "categorical" not in {kind.value for kind in ToleranceKind}
        assert frozenset(ToleranceKind) == SUPPORTED_TOLERANCE_KINDS
        assert CATEGORICAL_REFUSAL_CODE.startswith("probes.")


# -- end-to-end ---------------------------------------------------------------------


class TestCatalogueEndToEnd:
    def test_every_family_pins_binds_and_selects(self) -> None:
        catalogue = _catalogue()
        plan = catalogue.plan()
        bound = plan.bind(catalogue)
        assert [definition.family for definition in bound] == list(ALL_FAMILIES)
        assert len(catalogue.select(phase=Phase.PRE)) == len(ALL_FAMILIES)
        assert (
            catalogue.select(family=ProbeFamily.SYNTHETIC, stage=LifecycleStage.DURING_FAULT) == ()
        )

    def test_a_catalogue_of_the_whole_lifecycle_round_trips(self) -> None:
        definitions = (
            _http(
                id="http.baseline",
                stages=(LifecycleStage.PRE_BASELINE,),
                cadence=5.0,
                window=30.0,
            ),
            _http(
                id="http.settling",
                stages=(LifecycleStage.WARM_UP, LifecycleStage.AFTER_RECOVERY),
                warmup=20.0,
                cooldown=45.0,
            ),
            _http(
                id="http.continuous",
                stages=(
                    LifecycleStage.PRE_BASELINE,
                    LifecycleStage.CONTINUOUS,
                    LifecycleStage.FINAL_VERIFICATION,
                ),
            ),
        )
        catalogue = ProbeCatalog(definitions=definitions)
        plan = catalogue.plan()
        assert plan.bind(catalogue) == definitions
        assert catalogue.select(stage=LifecycleStage.FINAL_VERIFICATION) == (definitions[2],)
        assert definitions[1].graded_stages == ()

    def test_definitions_serialise_for_an_artifact(self) -> None:
        payload = _http(
            carrier=HttpProbe(url="https://api.internal/healthz"),
            stages=(LifecycleStage.PRE_BASELINE,),
        ).model_dump(mode="json")
        assert payload["family"] == "http"
        assert payload["version"] == "1.0"
        assert payload["cadence"] == "5s"
        assert payload["carrier"]["type"] == "http"
        assert (
            ProbeDefinition.model_validate(payload).fingerprint
            == _http(
                carrier=HttpProbe(url="https://api.internal/healthz"),
                stages=(LifecycleStage.PRE_BASELINE,),
            ).fingerprint
        )
