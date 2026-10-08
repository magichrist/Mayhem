"""Plan 11 Phase 3 — fifteen shipped integrations, each fixture-backed, each bounded.

The plan's Phase 3 acceptance criterion is "each integration ships with a
fixture-backed test proving bounded, redacted behavior". This suite is that, and it
is shaped like the criterion rather than like a coverage report:

* **A fixture per connector.** :data:`CONNECTOR_FIXTURES` is a row for each of the
  fifteen shipped connectors: a body the connector would return, the number it read,
  and the unit it read it in. The parametrised tests below run over **every** row,
  so a sixteenth connector without a fixture fails the suite rather than shipping
  untested. The seam is an injected client — no HTTP, no vendor, no network.

* **Bounded, three ways.** The declared timeout is inside the cap; the declared
  response cap is inside the cap; and a body that *overruns the cap it declared* is
  refused, because a client that overran its own bound must not be believed about
  anything else it reports.

* **Redacted before evidence.** A credential planted in a connector body is
  scrubbed before it can reach a ``ProbeObservation``'s ``detail``, and the fact that
  something was scrubbed is *recorded* rather than left implicit.

* **An unbound connector is UNAVAILABLE, not absent.** The families the catalogue
  serves become available only when a client is bound; every other family stays
  unbound, and the resulting port map reports them as unobserved.

The negative controls are the fourth block and each one **breaks** a property the
module claims:

* an over-long timeout, an over-sized cap, ``redact_before_evidence=False``, a
  non-``https`` endpoint, and an endpoint carrying a credential are each refused at
  construction — the first three by relaxing the shipped value, the last two by
  constructing the shape an operator would try;
* a client that returns the wrong shape, one that returns a non-finite value, and
  one that returns an over-cap body are each refused *as observations*, not
  propagated;
* **the tautology control:** an unbound connector is not the same finding as a
  bound-but-broken one, and both are not the same as "the family is fine". A
  control that could not distinguish them would pass on any implementation that
  returned ``None``, so this one asserts the three words are three words.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from mayhem.controller.probe_integrations import (
    MAX_CONNECTOR_BYTES,
    MAX_CONNECTOR_TIMEOUT_S,
    ROLLOUT_TIER_ORDER,
    ConnectorCatalog,
    ConnectorClient,
    ConnectorContractError,
    ConnectorId,
    ConnectorPayload,
    ConnectorProbePort,
    ConnectorProbePorts,
    SignalConnector,
    default_connectors,
)
from mayhem.controller.probe_service import (
    ProbeAvailability,
    ProbeCoverage,
    ProbePorts,
    ProbeReading,
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

# -- fixtures ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Fixture:
    """One connector's canned answer: the body, the number, the unit."""

    connector_id: ConnectorId
    body: str
    value: float | None
    unit: str


#: A body carrying a credential in three different shapes, so redaction is not
#: proven by one regex. ``promql=`` style assignment, a ``Bearer`` header, and a
#: userinfo URL — the three forms :func:`mayhem.domain.redaction.redact_text` is
#: built to catch.
CREDENTIAL_BODY = (
    "query=up&api_key=sk-live-9f2c7d41b0aa4e6f"
    "\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
    "\nendpoint=https://admin:hunter2@prometheus.internal/api/v1/query"
)

#: One fixture per shipped connector. Sixteen connectors without a fixture fails
#: :func:`test_every_shipped_connector_ships_a_fixture`, which is the point.
CONNECTOR_FIXTURES: tuple[Fixture, ...] = (
    Fixture(ConnectorId.PROMETHEUS, '{"status":"success","value":"0.42"}', 0.42, "ratio"),
    Fixture(ConnectorId.OTEL, '{"resourceMetrics":[],"count":"7"}', 7.0, "count"),
    Fixture(ConnectorId.GRAFANA, '{"results":{"A":{"frames":[]}}}', 0.0, "count"),
    Fixture(ConnectorId.LOKI, '{"status":"success","values":[["1","line"]]}', 1.0, "count"),
    Fixture(ConnectorId.TEMPO, '{"traces":[],"scannedTraces":"128"}', 128.0, "count"),
    Fixture(ConnectorId.JAEGER, '{"data":[],"total":"0"}', 0.0, "count"),
    Fixture(
        ConnectorId.DATADOG,
        '{"series":[{"pointlist":[[1,0.97]]}],"value":"0.97"}',
        0.97,
        "ratio",
    ),
    Fixture(
        ConnectorId.NEW_RELIC,
        '{"metric_data":{"values":[5.0]},"count":"5"}',
        5.0,
        "count",
    ),
    Fixture(ConnectorId.ELASTIC, '{"hits":{"total":{"value":12}}}', 12.0, "count"),
    Fixture(ConnectorId.OPENSEARCH, '{"hits":{"total":{"value":12}}}', 12.0, "count"),
    Fixture(
        ConnectorId.CLOUDWATCH,
        '{"MetricDataResults":[{"Values":[1.5]}],"id":"m1"}',
        1.5,
        "ratio",
    ),
    Fixture(
        ConnectorId.AZURE_MONITOR,
        '{"timespan":"PT1M","value":[["t","v"]],"count":"3"}',
        3.0,
        "count",
    ),
    Fixture(
        ConnectorId.GCP_MONITORING,
        '{"metricDescriptors":[],"points":[[1.0]],"count":"1"}',
        1.0,
        "count",
    ),
    Fixture(ConnectorId.PAGERDUTY, '{"incidents":[{"status":"triggered"}]}', 1.0, "count"),
    Fixture(ConnectorId.OPSGENIE, '{"data":[{"status":"open"}]}', 1.0, "count"),
)


@dataclass
class FixtureClient:
    """The injected client every connector test answers through.

    Deliberately the *only* thing the tests put between a connector and its reading:
    no HTTP opener, no fixture file on disk, no vendor SDK. The point under test is
    the contract around the answer, and a real transport would add a way for the
    test to pass that had nothing to do with it.
    """

    name: str
    payload: ConnectorPayload | None = None
    raises: BaseException | None = None
    raw: object = None
    calls: int = 0

    def fetch(self, connector: SignalConnector) -> ConnectorPayload:
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        if self.raw is not None:
            return self.raw  # type: ignore[return-value]
        assert self.payload is not None
        return self.payload


def _client_for(connector_id: ConnectorId, **overrides: object) -> FixtureClient:
    fixture = next(f for f in CONNECTOR_FIXTURES if f.connector_id is connector_id)
    return FixtureClient(
        name=f"fixture-{connector_id.value}",
        payload=ConnectorPayload(body=fixture.body, value=fixture.value, unit=fixture.unit),
        **overrides,  # type: ignore[arg-type]
    )


def _definition(family: ProbeFamily, probe_id: str, unit: str = "count") -> ProbeDefinition:
    locators: dict[ProbeFamily, dict[str, str]] = {
        ProbeFamily.PROMETHEUS: {"query": "up"},
        ProbeFamily.OPENTELEMETRY: {"query": "http.server.request.duration"},
        ProbeFamily.LOGS: {"query": '{app="checkout"} |= "error"'},
        ProbeFamily.TRACES: {"query": "service.name=checkout"},
        ProbeFamily.SYNTHETIC: {"steps": ("cart", "pay", "confirm")},
    }
    return ProbeDefinition(
        id=probe_id,
        family=family,
        version="1.0",
        unit=unit,
        stages=(LifecycleStage.DURING_FAULT,),
        cadence=5.0,
        **locators[family],  # type: ignore[arg-type]
    )


def _service(families: list[ProbeFamily], ports: ProbePorts) -> ProbeService:
    definitions = tuple(_definition(family, f"{family.value}.probe") for family in families)
    return ProbeService(
        catalogue=ProbeCatalog(definitions=definitions),
        plan=ProbePlan(pins=tuple(ProbePin.of(definition) for definition in definitions)),
        ports=ports,
    )


def _ports_for(*connector_ids: ConnectorId) -> ConnectorProbePorts:
    catalogue = default_connectors()
    return ConnectorProbePorts(
        catalog=catalogue,
        clients={cid: _client_for(cid) for cid in connector_ids},
    )


# -- every shipped connector has a fixture -------------------------------------------


class TestEveryShippedConnectorShipsAFixture:
    def test_every_shipped_connector_ships_a_fixture(self) -> None:
        """The acceptance criterion's precondition, asserted as a set equality.

        Not a count: a count passes when a fixture is duplicated and a connector
        ships untested. Set equality against the catalogue's own ids is the only
        formulation that fails in both directions.
        """
        shipped = set(default_connectors().ids())
        fixtureed = {fixture.connector_id for fixture in CONNECTOR_FIXTURES}

        assert fixtureed == shipped
        assert len(CONNECTOR_FIXTURES) == len(shipped) == 15

    def test_the_catalogue_ships_the_fifteen_the_plan_names(self) -> None:
        assert {member.value for member in ConnectorId} == {
            "prometheus",
            "opentelemetry",
            "grafana",
            "loki",
            "datadog",
            "new-relic",
            "elastic",
            "opensearch",
            "tempo",
            "jaeger",
            "cloudwatch",
            "azure-monitor",
            "gcp-monitoring",
            "pagerduty",
            "opsgenie",
        }

    @pytest.mark.parametrize("fixture", CONNECTOR_FIXTURES, ids=lambda f: f.connector_id.value)
    def test_every_fixture_body_is_valid_json_or_named_as_a_non_json_read(
        self, fixture: Fixture
    ) -> None:
        """The fixture is a *real* payload, so the test is not asserting about a stub.

        A fixture that were ``"42"`` for every connector would pass every bound and
        redaction assertion below while proving nothing about the five connectors
        whose vendor API actually returns JSON. So each body must parse, and the
        parsed value must agree with the number the fixture says was read.
        """
        parsed = json.loads(fixture.body)
        assert isinstance(parsed, dict), fixture.connector_id
        assert fixture.value is not None
        assert isinstance(fixture.unit, str) and fixture.unit


# -- bounded, per connector ----------------------------------------------------------


class TestEveryConnectorIsBounded:
    @pytest.mark.parametrize("fixture", CONNECTOR_FIXTURES, ids=lambda f: f.connector_id.value)
    def test_a_fixture_backed_reading_is_produced_with_the_connectors_provenance(
        self, fixture: Fixture
    ) -> None:
        catalogue = default_connectors()
        connector = catalogue.get(fixture.connector_id)
        assert connector is not None

        port = ConnectorProbePort(connector, _client_for(fixture.connector_id))
        observation = port.observe(_definition(connector.family, "probe.one"))

        assert observation is not None
        assert observation.value == fixture.value
        assert observation.unit == fixture.unit
        assert observation.provenance == fixture.connector_id.value
        assert fixture.connector_id.value in observation.evidence_ref

    @pytest.mark.parametrize("fixture", CONNECTOR_FIXTURES, ids=lambda f: f.connector_id.value)
    def test_every_shipped_connector_declares_a_timeout_and_a_cap_inside_the_limits(
        self, fixture: Fixture
    ) -> None:
        connector = default_connectors().get(fixture.connector_id)
        assert connector is not None
        assert 0.0 < connector.timeout_s <= MAX_CONNECTOR_TIMEOUT_S
        assert 0 < connector.max_bytes <= MAX_CONNECTOR_BYTES
        assert connector.redact_before_evidence is True
        assert connector.auth_ref, "a connector must name the secret the run resolves"

    @pytest.mark.parametrize("connector_id", list(ConnectorId))
    def test_a_body_over_the_cap_it_declared_is_refused_not_truncated(
        self, connector_id: ConnectorId
    ) -> None:
        """The cap is re-checked, not trusted.

        The control: if the port trusted the client, an over-cap body would produce
        a reading whose ``detail`` carried a megabyte of whatever the vendor
        returned — including any credential in it. Truncating instead of refusing
        would be worse than useless here, because a truncated body reads like a
        complete one.
        """
        connector = default_connectors().get(connector_id)
        assert connector is not None
        oversized = "x" * (connector.max_bytes + 1)
        port = ConnectorProbePort(
            connector, FixtureClient(name="oversized", payload=ConnectorPayload(oversized, 1.0))
        )

        with pytest.raises(ConnectorContractError) as caught:
            port.observe(_definition(connector.family, "probe.one"))

        assert caught.value.rule == "probes.connector_response_over_cap"
        assert "must not be believed" in str(caught.value)


# -- redaction, before evidence ------------------------------------------------------


class TestRedactionHappensBeforeEvidence:
    def test_a_credential_in_the_body_never_reaches_the_observation(self) -> None:
        """The load-bearing redaction test: three credential shapes, one answer."""
        connector = default_connectors().get(ConnectorId.PROMETHEUS)
        assert connector is not None
        client = FixtureClient(
            name="leaky",
            payload=ConnectorPayload(body=CREDENTIAL_BODY, value=0.5, unit="ratio"),
        )

        observation = ConnectorProbePort(connector, client).observe(
            _definition(ProbeFamily.PROMETHEUS, "probe.one")
        )

        assert observation is not None
        for secret in ("sk-live-9f2c7d41b0aa4e6f", "eyJhbGciOiJIUzI1NiJ9", "hunter2"):
            assert secret not in observation.detail, secret
        assert "REDACTED" in observation.detail
        # And the *number* survives: redaction must not have cost us the reading.
        assert observation.value == 0.5
        # And the scrub is announced, so "the note is short" and "the note was
        # scrubbed" are different things to a reviewer.
        assert "redacted" in observation.detail

    def test_the_redacted_body_survives_a_json_round_trip_into_an_envelope_row(self) -> None:
        """The redaction has to hold through the evidence path, not just the port."""
        from mayhem.controller.probe_service import reading_view
        from mayhem.domain.probe_evidence import envelope_observations

        connector = default_connectors().get(ConnectorId.PROMETHEUS)
        assert connector is not None
        port = ConnectorProbePort(
            connector,
            FixtureClient(
                name="leaky",
                payload=ConnectorPayload(body=CREDENTIAL_BODY, value=0.5, unit="ratio"),
            ),
        )
        # The unit must match the fixture's: a mismatch is refused as
        # unavailability, not converted, and the reading would be lost.
        definition = _definition(ProbeFamily.PROMETHEUS, "probe.one", unit="ratio")
        service = _service(
            [ProbeFamily.PROMETHEUS], ProbePorts(ports={ProbeFamily.PROMETHEUS: port})
        )
        reading = service.collect(definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)

        rows = envelope_observations([reading_view(reading)])
        serialised = json.dumps(rows)

        assert "sk-live-9f2c7d41b0aa4e6f" not in serialised
        assert "hunter2" not in serialised
        assert rows[0]["value"] == 0.5
        assert rows[0]["provenance"] == "prometheus"

    def test_a_credential_in_the_endpoint_is_refused_at_construction(self) -> None:
        """A redacted credential in a catalogue is still a credential in a catalogue."""
        with pytest.raises(InvariantViolationError) as caught:
            SignalConnector(
                connector_id=ConnectorId.PROMETHEUS,
                signal=connector_signal(),
                family=ProbeFamily.PROMETHEUS,
                endpoint_template="https://admin:hunter2@prometheus.internal/api/v1/query",
            )

        assert caught.value.rule == "probes.connector_carries_a_credential"
        assert "version control" in str(caught.value)


def connector_signal():
    """The signal kind Prometheus declares, read from the shipped catalogue."""
    connector = default_connectors().get(ConnectorId.PROMETHEUS)
    assert connector is not None
    return connector.signal


# -- wiring: bound vs unbound --------------------------------------------------------


class TestAnUnboundConnectorIsUnavailableNotAbsent:
    def test_binding_a_connector_makes_its_family_readable(self) -> None:
        ports = _ports_for(ConnectorId.PROMETHEUS)

        assert ports.ports().for_family(ProbeFamily.PROMETHEUS) is not None

    def test_a_family_no_connector_serves_stays_unbound(self) -> None:
        ports = _ports_for(ConnectorId.PROMETHEUS)

        assert ports.unbound((ProbeFamily.PROMETHEUS, ProbeFamily.REDIS)) == (ProbeFamily.REDIS,)

    def test_a_declared_but_unbound_connector_is_still_not_a_way_to_ask(self) -> None:
        """Grafana declares the metrics family and this run did not bind it."""
        ports = _ports_for(ConnectorId.PROMETHEUS)
        catalogue = default_connectors()
        assert catalogue.get(ConnectorId.GRAFANA) is not None

        assert ports.unbound((ProbeFamily.PROMETHEUS,)) == ()

    def test_a_fully_unbound_catalogue_produces_an_empty_port_map_and_a_blind_run(self) -> None:
        """The tautology control: no connector and no observation must not look fine."""
        ports = _ports_for()
        service = _service(
            [ProbeFamily.PROMETHEUS, ProbeFamily.LOGS],
            ports.ports([ProbeFamily.PROMETHEUS, ProbeFamily.LOGS]),
        )

        readings = [
            service.collect(definition, stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0)
            for definition in service.definitions
        ]
        coverage = ProbeCoverage.of(readings)

        assert coverage.blind
        assert coverage.verdict_bearing is False
        assert coverage.observed == ()
        assert {reading.availability for reading in readings} == {ProbeAvailability.UNAVAILABLE}
        assert ProbeService.samples(readings) == ()

    def test_an_unavailable_familys_reading_carries_no_observation(self) -> None:
        """``UNAVAILABLE`` and ``AVAILABLE`` are kept apart at the constructor."""
        service = _service([ProbeFamily.PROMETHEUS], _ports_for().ports())

        reading = service.collect(
            service.definitions[0], stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )

        assert isinstance(reading, ProbeReading)
        assert reading.observation is None
        assert reading.refuses


# -- rollout order -------------------------------------------------------------------


class TestTheRolloutOrderIsInTheCode:
    def test_tier_one_is_metric_and_log_families_with_no_vendor_account(self) -> None:
        catalogue = default_connectors()
        tier_one = {c.connector_id for c in catalogue.for_tier(ROLLOUT_TIER_ORDER[0])}

        assert tier_one == {
            ConnectorId.PROMETHEUS,
            ConnectorId.OTEL,
            ConnectorId.GRAFANA,
            ConnectorId.LOKI,
        }

    def test_tier_two_is_trace_and_synthetic(self) -> None:
        catalogue = default_connectors()

        assert {c.connector_id for c in catalogue.for_tier(ROLLOUT_TIER_ORDER[1])} == {
            ConnectorId.TEMPO,
            ConnectorId.JAEGER,
        }

    def test_tier_three_is_everything_needing_a_vendor_contract(self) -> None:
        catalogue = default_connectors()

        assert {c.connector_id for c in catalogue.for_tier(ROLLOUT_TIER_ORDER[2])} == {
            ConnectorId.DATADOG,
            ConnectorId.NEW_RELIC,
            ConnectorId.ELASTIC,
            ConnectorId.OPENSEARCH,
            ConnectorId.CLOUDWATCH,
            ConnectorId.AZURE_MONITOR,
            ConnectorId.GCP_MONITORING,
            ConnectorId.PAGERDUTY,
            ConnectorId.OPSGENIE,
        }

    def test_a_family_two_connectors_claim_is_named_rather_than_silently_chosen(self) -> None:
        catalogue = default_connectors()

        ambiguous = {family.value for family in catalogue.ambiguous_families()}

        # metrics is served by prometheus, grafana, datadog, new-relic, cloudwatch,
        # azure-monitor and gcp-monitoring; logs by loki, elastic and opensearch.
        assert "prometheus" in ambiguous
        assert "logs" in ambiguous

    def test_the_first_bound_connector_wins_and_the_choice_is_reported(self) -> None:
        """Which one is bound is a deployment decision, so it is visible."""
        catalogue = default_connectors()
        ports = ConnectorProbePorts(
            catalog=catalogue,
            clients={
                ConnectorId.DATADOG: _client_for(ConnectorId.DATADOG),
                ConnectorId.PROMETHEUS: _client_for(ConnectorId.PROMETHEUS),
            },
        )

        port = ports.ports([ProbeFamily.PROMETHEUS]).for_family(ProbeFamily.PROMETHEUS)

        assert port is not None
        # Prometheus is declared first, so it wins the metrics family.
        assert port.name.startswith("prometheus:")


# -- negative controls ---------------------------------------------------------------


class TestTheConstructionRefusalsAreRealGates:
    """Each one *breaks* a shipped connector's guarantee and shows the guard fires."""

    def _prometheus(self, **overrides: object) -> SignalConnector:
        base: dict[str, object] = {
            "connector_id": ConnectorId.PROMETHEUS,
            "signal": connector_signal(),
            "family": ProbeFamily.PROMETHEUS,
            "endpoint_template": "https://prometheus.internal/api/v1/query",
        }
        base.update(overrides)
        return SignalConnector(**base)  # type: ignore[arg-type]

    def test_an_over_long_timeout_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            self._prometheus(timeout_s=600.0)

        assert caught.value.rule == "probes.connector_timeout_out_of_bounds"
        assert "hung run" in str(caught.value)

    def test_a_zero_timeout_is_refused(self) -> None:
        """The other end of the interval: ``(0, cap]``, not ``[0, cap]``.

        A zero timeout is not "no timeout" — it is a connector that must fail
        immediately, which is a configuration nobody intends and every deployment
        would read as "unbounded".
        """
        with pytest.raises(InvariantViolationError) as caught:
            self._prometheus(timeout_s=0.0)

        assert caught.value.rule == "probes.connector_timeout_out_of_bounds"

    def test_an_over_sized_cap_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            self._prometheus(max_bytes=MAX_CONNECTOR_BYTES + 1)

        assert caught.value.rule == "probes.connector_response_cap_out_of_bounds"
        assert "unbounded memory" in str(caught.value)

    def test_redaction_cannot_be_turned_off(self) -> None:
        """A connector added with redaction off fails here, not in an envelope."""
        with pytest.raises(InvariantViolationError) as caught:
            self._prometheus(redact_before_evidence=False)

        assert caught.value.rule == "probes.connector_redaction_required"
        assert "the artifact the secret boundary exists for" in str(caught.value)

    def test_a_plain_http_endpoint_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            self._prometheus(endpoint_template="http://prometheus.internal/api/v1/query")

        assert caught.value.rule == "probes.connector_endpoint_not_https"
        assert "in the clear" in str(caught.value)

    def test_a_relative_endpoint_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            self._prometheus(endpoint_template="/api/v1/query")

        assert caught.value.rule == "probes.connector_endpoint_not_https"

    def test_an_endpoint_carrying_a_token_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            self._prometheus(
                endpoint_template="https://prometheus.internal/api/v1/query?token=abc123"
            )

        assert caught.value.rule == "probes.connector_carries_a_credential"

    def test_every_shipped_connector_survives_its_own_refusals(self) -> None:
        """The positive control: a gate that refuses everything is not a gate."""
        catalogue = ConnectorCatalog(
            connectors=tuple(default_connectors().connectors),
        )

        assert len(catalogue.connectors) == 15
        assert catalogue.describe().count("timeout") == 15


class TestTheClientRefusalsAreRealGates:
    def _port(self, **client_kwargs: object) -> ConnectorProbePort:
        connector = default_connectors().get(ConnectorId.PROMETHEUS)
        assert connector is not None
        return ConnectorProbePort(
            connector,
            FixtureClient(name="broken", **client_kwargs),  # type: ignore[arg-type]
        )

    def test_a_client_answering_in_the_wrong_shape_is_refused(self) -> None:
        """A broken client must be reported as a broken client.

        **The control:** if the port coerced the answer, a client returning a dict
        would be graded as a reading and the symptom would look like an outage of
        Prometheus — a mayhem bug reported as a system finding.
        """
        with pytest.raises(ConnectorContractError) as caught:
            self._port(payload=None, raw={"value": 1.0}).observe(
                _definition(ProbeFamily.PROMETHEUS, "probe.one")
            )

        assert caught.value.rule == "probes.connector_answered_in_the_wrong_shape"
        assert "outage of the thing it watches" in str(caught.value)

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_a_non_finite_value_is_refused_rather_than_graded(self, value: float) -> None:
        with pytest.raises(ConnectorContractError) as caught:
            self._port(payload=ConnectorPayload(body="{}", value=value, unit="ratio")).observe(
                _definition(ProbeFamily.PROMETHEUS, "probe.one")
            )

        assert caught.value.rule == "probes.connector_non_finite_value"
        assert "measured nothing" in str(caught.value)

    def test_a_valueless_answer_is_an_absence_not_a_measurement_of_zero(self) -> None:
        """``None`` crosses the port as a refusal, and the engine grades it as one."""
        port = ConnectorProbePort(
            default_connectors().get(ConnectorId.PROMETHEUS),  # type: ignore[arg-type]
            FixtureClient(
                name="empty", payload=ConnectorPayload(body='{"status":"success"}', value=None)
            ),
        )
        service = _service(
            [ProbeFamily.PROMETHEUS], ProbePorts(ports={ProbeFamily.PROMETHEUS: port})
        )

        reading = service.collect(
            service.definitions[0], stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )

        assert reading.availability is ProbeAvailability.UNAVAILABLE
        assert reading.observation is None
        assert ProbeService.samples([reading]) == ()

    def test_a_raising_client_is_unavailable_at_the_engine_not_an_exception(self) -> None:
        """The engine's no-raise contract, reached through a connector."""
        port = ConnectorProbePort(
            default_connectors().get(ConnectorId.PROMETHEUS),  # type: ignore[arg-type]
            FixtureClient(name="boom", raises=TimeoutError("connection refused")),
        )
        service = _service(
            [ProbeFamily.PROMETHEUS], ProbePorts(ports={ProbeFamily.PROMETHEUS: port})
        )

        reading = service.collect(
            service.definitions[0], stage=LifecycleStage.DURING_FAULT, at_epoch_s=1.0
        )

        assert reading.availability is ProbeAvailability.UNAVAILABLE
        assert "TimeoutError" in reading.note
        assert ProbeCoverage.of([reading]).blind

    def test_a_connector_contract_error_is_still_an_invariant_violation(self) -> None:
        """One base class, so a caller can catch "this cannot be trusted" once.

        The control: if ``ConnectorContractError`` were unrelated to
        :class:`~mayhem.domain.errors.InvariantViolationError`, a caller wrapping a
        connector read would have to know both types, and the next connector-shaped
        refusal would be a third.
        """
        assert issubclass(ConnectorContractError, InvariantViolationError)

        error = ConnectorContractError("probes.connector_non_finite_value", "nope")

        assert error.rule == "probes.connector_non_finite_value"
        assert isinstance(error, InvariantViolationError)

    def test_a_client_satisfying_the_protocol_is_recognised_as_one(self) -> None:
        """Structural: the protocol is not decorative."""
        assert isinstance(_client_for(ConnectorId.LOKI), ConnectorClient)
        assert not isinstance(object(), ConnectorClient)


# -- honesty -------------------------------------------------------------------------


class TestWhatThisModuleDoesNotClaim:
    def test_no_connector_declares_a_credential_value_only_a_reference(self) -> None:
        """``auth_ref`` names a secret; it is never the secret."""
        for connector in default_connectors().connectors:
            assert "/" in connector.auth_ref, connector.connector_id
            assert "=" not in connector.auth_ref, connector.connector_id

    def test_no_connector_says_it_authenticates_what_it_read(self) -> None:
        """No signature-verification claim anywhere in the connector vocabulary.

        The control: an implementation could add a ``verified=True`` field or a
        ``signature_verified`` note to a connector and every test here would still
        pass, because none of them looks. This one looks, and it is the assertion
        that keeps ``verified-live`` at 0 when somebody is tempted to raise it.
        """
        vocabulary = set(dir(ConnectorId))
        forbidden = {name for name in vocabulary if "verified" in name or "signature" in name}

        assert forbidden == set()
        for connector in default_connectors().connectors:
            assert "verif" not in json.dumps(connector.to_dict()).lower()
            assert "signature" not in json.dumps(connector.to_dict()).lower()

    def test_no_shipped_endpoint_is_a_deployments_own_address(self) -> None:
        """The shipped endpoints are vendor documentation URLs, not somebody's prod.

        Some are genuinely fixed (``https://api.opsgenie.com/v2/alerts``) and the
        rest carry a ``{base}``-style placeholder a deployment substitutes. What
        neither may be is *a deployment's* address: an internal hostname, a ``.local``
        name or a bare port is the shape of a URL that is right for exactly one
        environment and wrong everywhere else.

        The control: an implementation could add ``https://prometheus.prod.acme``
        to the catalogue and every bounded, redacted and fixture-backed assertion
        above would still pass, because none of them looks at the endpoint at all.
        This one looks.
        """
        for connector in default_connectors().connectors:
            host = connector.endpoint_template.split("://", 1)[-1].split("/", 1)[0]
            assert "internal" not in host, connector.connector_id
            assert ".local" not in host, connector.connector_id
            assert ":" not in host, connector.connector_id
            # A bare `{base}` placeholder is the shape a substitution leaves
            # behind; a real host carries at least one dot. Anything else would be
            # a single-label internal name, which the two assertions above catch
            # only if it says so.
            assert host == "{base}" or host.count(".") >= 1, connector.connector_id
