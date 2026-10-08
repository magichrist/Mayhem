"""Plan 11 Phase 3, surface half — ``mayhem probe``, the authoring surface.

The five sub-commands are pure functions of their flags over shipped data, and the
suite is about the two properties that make such a surface honest rather than
decorative:

* **``uncover`` is the surface that refuses to let silence read as health.** It
  names the families a run cannot see, distinguishes the two reasons it cannot see
  them (no shipped connector at all versus a declared connector nobody bound), and
  prints the word ``UNAVAILABLE`` — read from
  :func:`mayhem.controller.probe_service.refuses_probe`, the same function the
  engine uses, so the CLI and a run report cannot disagree about the word.
* **The catalogue never implies coverage it does not have.** A family with no
  shipped connector is rendered ``declared-only`` and is listed under
  ``declared_only``, which is the whole reason the command can be trusted.

**The group is deliberately not registered** in
:data:`mayhem.cli.command_registry.COMMANDS`, which this work item does not own, so
the suite invokes it directly through ``CliRunner`` — the same shape
``tests/unit/test_stop_surface.py`` uses for the same reason.

Negative controls, each breaking a property the surface claims:

* the locator table the surface documents is asserted to agree with the domain's
  own :func:`mayhem.domain.probes.required_locator`, so a flag cannot describe a
  requirement the domain does not have;
* an unpinned probe, a warm-up with no budget, a relative http endpoint and a
  malformed id each exit with ``ExitCode.VALIDATION_ERROR`` and name the rule,
  rather than printing a traceback;
* an unknown lifecycle stage, probe family or connector id is a *usage* error, not
  a silent no-op;
* the ``categorical`` tolerance is absent from the rendered reference, and the
  absence is stated rather than implied;
* nothing in the surface reaches a network, a store or a cluster — asserted
  structurally, by the absence of the modules the imports would need.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.output import current_format
from mayhem.cli.probe_cmd import (
    TOLERANCE_REFERENCE,
    build_condition,
    build_definition,
    catalogue_payload,
    connectors_payload,
    family_rows,
    locators_for,
    probe,
    tolerances_payload,
    uncover_payload,
)
from mayhem.controller.probe_integrations import ConnectorId, default_connectors
from mayhem.controller.probe_service import ProbeAvailability, refuses_probe
from mayhem.domain.observations import CriterionOperator
from mayhem.domain.probes import (
    LifecycleStage,
    ProbeFamily,
    required_locator,
)
from mayhem.domain.stop_conditions import FiresWhen

if TYPE_CHECKING:
    from collections.abc import Sequence


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _invoke(runner: CliRunner, args: Sequence[str]):
    return runner.invoke(probe, list(args))


# -- the group resolves ---------------------------------------------------------------


class TestEveryDocumentedInvocationResolves:
    def test_the_group_lists_its_sub_commands(self, runner: CliRunner) -> None:
        result = _invoke(runner, ["--help"])

        assert result.exit_code == 0
        for command in ("build", "catalogue", "condition", "connectors", "tolerances", "uncover"):
            assert command in result.output

    @pytest.mark.parametrize(
        "args",
        [
            ["catalogue"],
            ["connectors"],
            ["tolerances"],
            ["uncover", "--families", "prometheus"],
            [
                "build",
                "--id",
                "http.api",
                "--family",
                "http",
                "--locator",
                "https://a/b",
                "--unit",
                "ms",
                "--stages",
                "during-fault",
            ],
            ["condition", "--metric", "http.api", "--op", "lte", "--value", "250"],
        ],
    )
    def test_each_documented_invocation_succeeds(self, runner: CliRunner, args: list[str]) -> None:
        result = _invoke(runner, args)

        assert result.exit_code == ExitCode.SUCCESS, result.output

    # -- registration ------------------------------------------------------
    #
    # ``test_the_group_is_not_registered_yet`` stood here and asserted that
    # ``"probe"`` was absent from ``register_commands`` — a reminder the lane
    # owed the tree a registration. The probe group is registered now (and
    # documented in the README command table), so per that test's own docstring
    # it is deleted rather than flipped: whoever registered it deleted it, and
    # the plan's ledger and the live tree agree.


# -- the catalogue --------------------------------------------------------------------


class TestTheCatalogueNeverImpliesCoverageItDoesNotHave:
    def test_every_family_is_listed_one_row_each(self) -> None:
        """The count is derived, not asserted as a literal.

        The plan's prose sentence ("HTTP/HTTPS, TCP/UDP, DNS, gRPC, SQL, Redis,
        Kafka/RabbitMQ/NATS, process, file, command, Prometheus metrics,
        OpenTelemetry, logs, traces, Kubernetes state, synthetic") is sixteen
        comma-separated items that expand to **nineteen** families once the compound
        ones are split, which is what :class:`ProbeFamily` carries. Asserting a
        literal here would either fail forever or be quietly edited to match the
        code. Asserting against the enum makes the catalogue complete by
        construction, and the prose discrepancy is recorded in the plan's ledger.
        """
        rows = family_rows()

        assert len(rows) == len(list(ProbeFamily)) == 19
        assert {row["family"] for row in rows} == {family.value for family in ProbeFamily}

    def test_a_family_with_no_shipped_connector_is_declared_only(self) -> None:
        payload = catalogue_payload()

        # Redis, SQL, Kafka, gRPC, Kubernetes and the transport families ship no
        # read path, and the catalogue says so rather than implying one.
        for family in ("redis", "sql", "kafka", "grpc", "kubernetes", "tcp", "dns"):
            assert family in payload["declared_only"], family
            assert family not in payload["served"], family

    def test_a_served_family_names_the_connectors_that_serve_it(self) -> None:
        rows = {row["family"]: row for row in family_rows()}

        assert rows["prometheus"]["served"] is True
        assert "prometheus" in rows["prometheus"]["connectors"]
        assert rows["redis"]["connectors"] == []

    def test_the_catalogue_names_the_families_shipped_integrations_can_read(self) -> None:
        payload = catalogue_payload()

        assert set(payload["served"]) == {
            "prometheus",
            "opentelemetry",
            "logs",
            "traces",
            "synthetic",
        }

    def test_the_catalogue_prints_the_unavailable_word_in_its_note(self, runner: CliRunner) -> None:
        result = _invoke(runner, ["catalogue"])

        assert result.exit_code == 0
        assert "declared-only" in result.output
        assert "UNAVAILABLE is not evidence of health" in result.output

    def test_the_documented_locator_table_agrees_with_the_domain(self) -> None:
        """The negative control for the flag documentation.

        **The control:** if the surface carried its own copy of the family's required
        locator and the domain changed its own, every other test here would still
        pass while ``--locator`` silently produced a definition the domain refuses.
        The comparison is over the domain's own accessor, not a second literal.
        """
        for family in ProbeFamily:
            assert locators_for(family) == required_locator(family), family

    def test_kubernetes_names_both_of_its_locators_rather_than_picking_one(self) -> None:
        assert locators_for(ProbeFamily.KUBERNETES) == ("target", "query")


# -- uncover: the load-bearing sub-command ---------------------------------------------


class TestUncoverRefusesToLetSilenceReadAsHealth:
    def test_a_family_with_no_shipped_connector_is_unavailable(self) -> None:
        payload = uncover_payload([ProbeFamily.REDIS])

        row = payload["families"][0]
        assert row["availability"] == ProbeAvailability.UNAVAILABLE.value
        assert row["refuses"] is True
        assert row["unavailable_reason"] == "no shipped connector serves this family"

    def test_a_declared_but_unbound_connector_is_a_different_finding(self) -> None:
        """Two reasons to see nothing, and they are different repairs.

        Redis needs a connector written; logs needs somebody to bind the one that
        exists. Reporting both as "unavailable" would send the second to write code
        that already exists.
        """
        payload = uncover_payload([ProbeFamily.LOGS, ProbeFamily.REDIS])

        by_family = {row["family"]: row for row in payload["families"]}
        assert by_family["logs"]["unavailable_reason"] == "connector declared but not bound"
        assert by_family["redis"]["unavailable_reason"] == "no shipped connector serves this family"
        assert by_family["logs"]["declared_connectors"] == ["loki", "elastic", "opensearch"]
        assert by_family["redis"]["declared_connectors"] == []

    def test_a_bound_connector_is_available_and_names_itself(self) -> None:
        payload = uncover_payload([ProbeFamily.PROMETHEUS], bound=[ConnectorId.PROMETHEUS])

        row = payload["families"][0]
        assert row["availability"] == ProbeAvailability.AVAILABLE.value
        assert row["refuses"] is False
        assert row["unavailable_reason"] is None
        assert row["bound_connectors"] == ["prometheus"]

    def test_an_unavailable_family_makes_the_whole_report_unusable_for_a_verdict(
        self,
    ) -> None:
        payload = uncover_payload(
            [ProbeFamily.PROMETHEUS, ProbeFamily.REDIS], bound=[ConnectorId.PROMETHEUS]
        )

        assert payload["unavailable"] == ["redis"]
        assert payload["verdict_bearing"] is False
        assert "statement about mayhem's wiring and not about the system" in payload["summary"]

    def test_every_unavailable_row_refuses_through_the_engines_own_function(self) -> None:
        """The word is read from :func:`refuses_probe`, not restated in the surface."""
        payload = uncover_payload([ProbeFamily.PROMETHEUS, ProbeFamily.LOGS])

        for row in payload["families"]:
            availability = ProbeAvailability(row["availability"])
            assert row["refuses"] is refuses_probe(availability), row["family"]

    def test_the_command_prints_unavailable_and_says_it_may_not_report_a_pass(
        self, runner: CliRunner
    ) -> None:
        result = _invoke(
            runner, ["uncover", "--families", "prometheus,redis", "--bound", "prometheus"]
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "UNAVAILABLE" in result.output
        assert "no shipped connector serves this family" in result.output
        assert "may not report a passing verdict" in result.output
        assert "not about the system under test" in result.output

    def test_a_fully_available_report_says_so_and_warns_about_nothing(
        self, runner: CliRunner
    ) -> None:
        result = _invoke(runner, ["uncover", "--families", "prometheus", "--bound", "prometheus"])

        assert "available" in result.output
        assert "may not report a passing verdict" not in result.output

    def test_an_unknown_family_is_a_usage_error_naming_the_choices(self, runner: CliRunner) -> None:
        result = _invoke(runner, ["uncover", "--families", "prometheus,mysql"])

        assert result.exit_code != ExitCode.SUCCESS
        assert "mysql" in str(result.exception)

    def test_an_unknown_connector_id_is_a_usage_error_naming_the_choices(
        self, runner: CliRunner
    ) -> None:
        result = _invoke(runner, ["uncover", "--families", "prometheus", "--bound", "dynatrace"])

        assert result.exit_code != ExitCode.SUCCESS
        assert "dynatrace" in str(result.exception)


# -- connectors and rollout -------------------------------------------------------------


class TestTheConnectorCatalogueAndItsRollout:
    def test_fifteen_connectors_are_shipped_with_their_bounds(self) -> None:
        payload = connectors_payload()

        assert len(payload["connectors"]) == 15
        assert payload["bounds"]["max_timeout_s"] == 5.0
        assert payload["bounds"]["max_bytes"] == 256 * 1024
        assert payload["bounds"]["redaction_required"] is True

    def test_the_rollout_order_is_metric_log_then_trace_then_third_party(self) -> None:
        payload = connectors_payload()
        tiers = {row["tier"]: row["connectors"] for row in payload["rollout"]}

        assert set(tiers["tier-1-metric-and-log"]) == {
            "prometheus",
            "opentelemetry",
            "grafana",
            "loki",
        }
        assert set(tiers["tier-2-trace-and-synthetic"]) == {"tempo", "jaeger"}
        assert "datadog" in tiers["tier-3-third-party"]
        assert "pagerduty" in tiers["tier-3-third-party"]

    def test_the_ambiguous_metric_families_are_named_on_the_command(
        self, runner: CliRunner
    ) -> None:
        result = _invoke(runner, ["connectors"])

        assert "more than one shipped connector" in result.output
        assert "prometheus" in result.output

    def test_every_connector_row_states_its_bounds_and_its_auth_reference(self) -> None:
        for row in connectors_payload()["connectors"]:
            assert row["timeout_s"] > 0
            assert row["max_bytes"] > 0
            assert row["redact_before_evidence"] is True
            assert row["auth_ref"], row["connector_id"]


# -- tolerances ------------------------------------------------------------------------


class TestTheToleranceReferenceStatesItsAbsence:
    def test_the_four_mechanisms_are_listed_with_what_each_carries(self) -> None:
        payload = tolerances_payload()

        assert {row["kind"] for row in payload["tolerances"]} == {
            "absolute",
            "ratio",
            "percentage",
            "operator",
        }
        assert len(TOLERANCE_REFERENCE) == 4

    def test_a_relative_bound_is_declared_as_needing_a_baseline(self) -> None:
        """An unmeasurable bound must not read as a passing one."""
        payload = {row["kind"]: row for row in tolerances_payload()["tolerances"]}

        assert payload["ratio"]["baseline"] == "required"
        assert payload["percentage"]["baseline"] == "required"
        assert payload["absolute"]["baseline"] == "no"

    def test_the_categorical_absence_is_stated_not_implied(self) -> None:
        payload = tolerances_payload()

        assert payload["absent"]["kind"] == "categorical"
        assert payload["absent"]["refusal"] == "probes.categorical_unsupported"
        assert "float | None" in payload["absent"]["reason"]
        assert "categorical" not in {row["kind"] for row in payload["tolerances"]}

    def test_the_command_prints_the_absence_rather_than_omitting_it(
        self, runner: CliRunner
    ) -> None:
        result = _invoke(runner, ["tolerances"])

        assert "categorical: ABSENT by decision." in result.output
        assert "no label, enum or string field" in result.output

    def test_the_reference_matches_the_domain_vocabulary_it_documents(self) -> None:
        """The control for a reference that can drift from what exists."""
        from mayhem.domain.stop_conditions import ToleranceKind

        assert {row["kind"] for row in TOLERANCE_REFERENCE} == {
            kind.value for kind in ToleranceKind
        }


# -- build ------------------------------------------------------------------------------


class TestBuildingAProbeDefinition:
    def test_a_built_definition_carries_the_pin_a_plan_must_copy(self) -> None:
        payload = build_definition(
            probe_id="http.api",
            family=ProbeFamily.HTTP,
            unit="ms",
            locator="https://api.internal/latency",
            stages=(LifecycleStage.DURING_FAULT,),
            cadence=5.0,
        )

        assert payload["definition"]["id"] == "http.api"
        assert payload["pin"]["id"] == "http.api"
        assert len(payload["pin"]["fingerprint"]) == 64
        assert payload["pin_summary"] == "http.api@1.0"
        assert payload["graded_stages"] == ["during-fault"]

    def test_a_warm_up_probe_declares_which_of_its_stages_are_settling(self) -> None:
        payload = build_definition(
            probe_id="http.warm",
            family=ProbeFamily.HTTP,
            unit="ms",
            locator="https://api.internal/latency",
            stages=(LifecycleStage.WARM_UP, LifecycleStage.DURING_FAULT),
            warmup=10.0,
        )

        assert payload["excluded_stages"] == ["warm-up"]
        assert payload["graded_stages"] == ["during-fault"]

    def test_a_synthetic_stages_locator_is_split_into_steps(self) -> None:
        payload = build_definition(
            probe_id="synth.checkout",
            family=ProbeFamily.SYNTHETIC,
            unit="count",
            locator="cart > pay > confirm",
            stages=(LifecycleStage.DURING_FAULT,),
        )

        assert payload["definition"]["steps"] == ["cart", "pay", "confirm"]

    def test_a_missing_locator_is_refused_naming_the_familys_own_field(self) -> None:
        with pytest.raises(Exception) as caught:
            build_definition(
                probe_id="redis.cache",
                family=ProbeFamily.REDIS,
                unit="count",
                locator="",
            )

        assert "query" in str(caught.value)
        assert "resolves to nothing" in str(caught.value)

    def test_a_warm_up_stage_with_no_budget_is_refused_by_the_domain(self) -> None:
        with pytest.raises(Exception) as caught:
            build_definition(
                probe_id="http.warm",
                family=ProbeFamily.HTTP,
                unit="ms",
                locator="https://api.internal/latency",
                stages=(LifecycleStage.WARM_UP,),
                warmup=0.0,
            )

        assert "probes.probe_noise_budget_missing" in str(caught.value)

    def test_the_command_renders_a_refusal_as_a_refusal_not_a_traceback(
        self, runner: CliRunner
    ) -> None:
        """The control for "the tool is broken" versus "I caught that"."""
        result = _invoke(
            runner,
            [
                "build",
                "--id",
                "http.warm",
                "--family",
                "http",
                "--locator",
                "https://api.internal/latency",
                "--unit",
                "ms",
                "--stages",
                "warm-up",
            ],
        )

        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "error:" in result.output
        assert "probes.probe_noise_budget_missing" in result.output
        assert "nothing was collected and nothing was graded" in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)

    def test_a_malformed_id_is_a_refusal_rather_than_a_pydantic_traceback(
        self, runner: CliRunner
    ) -> None:
        result = _invoke(
            runner,
            [
                "build",
                "--id",
                "P",
                "--family",
                "http",
                "--locator",
                "https://api.internal/latency",
                "--unit",
                "ms",
            ],
        )

        assert result.exit_code == ExitCode.VALIDATION_ERROR
        assert "id:" in result.output
        assert "Traceback" not in result.output

    def test_an_unknown_stage_is_a_usage_error_naming_the_choices(self, runner: CliRunner) -> None:
        result = _invoke(
            runner,
            [
                "build",
                "--id",
                "http.api",
                "--family",
                "http",
                "--locator",
                "https://api.internal/latency",
                "--unit",
                "ms",
                "--stages",
                "during-faultt",
            ],
        )

        assert result.exit_code != ExitCode.SUCCESS
        assert "during-faultt" in str(result.exception)


# -- condition authoring -----------------------------------------------------------------


class TestAuthoringACondition:
    def test_a_condition_is_built_from_the_domain_own_threshold(self) -> None:
        payload = build_condition(
            metric="http.api",
            op=CriterionOperator.LTE,
            value=250.0,
            for_samples=2,
            debounce=1.5,
        )

        condition = payload["condition"]
        assert condition["reference"]["metric"] == "http.api"
        assert condition["threshold"]["expect"]["lte"] == 250.0
        assert condition["for_samples"] == 2
        # Duration is an annotated *string* in this codebase ("1.5s"), not a float;
        # asserting the float would pass only on an implementation that dropped the
        # unit, which is the thing the type exists to prevent.
        assert condition["debounce"] == "1.5s"
        assert "for 2 consecutive sample(s)" in payload["summary"]
        assert "debounced 1.5s" in payload["summary"]

    @pytest.mark.parametrize(
        ("op", "field"),
        [
            (CriterionOperator.LTE, "lte"),
            (CriterionOperator.GTE, "gte"),
            (CriterionOperator.EQ, "eq"),
        ],
    )
    def test_each_operator_maps_to_its_own_expect_field(
        self, op: CriterionOperator, field: str
    ) -> None:
        payload = build_condition(metric="m.metric", op=op, value=1.0)

        assert payload["condition"]["threshold"]["expect"][field] == 1.0

    def test_the_two_hysteresis_forms_stay_separate_flags(self) -> None:
        """A dead band's *size* is the author's decision, not the surface's."""
        fraction = build_condition(
            metric="m.metric", op=CriterionOperator.LTE, value=100.0, hysteresis=0.2
        )
        absolute = build_condition(
            metric="m.metric",
            op=CriterionOperator.LTE,
            value=100.0,
            hysteresis_absolute=5.0,
        )

        assert fraction["condition"]["hysteresis"] == 0.2
        assert fraction["condition"]["hysteresis_absolute"] is None
        assert absolute["condition"]["hysteresis_absolute"] == 5.0
        assert absolute["condition"]["hysteresis"] is None
        assert "hysteresis 20%" in fraction["summary"]
        assert "dead band 5" in absolute["summary"]

    @pytest.mark.parametrize("op", [CriterionOperator.LT, CriterionOperator.GT])
    def test_an_operator_with_no_absolute_bound_is_refused(self, op: CriterionOperator) -> None:
        """``lt``/``gt`` have no ``AbsoluteExpect`` field of their own.

        Percentile and time-to-recovery bounds belong in an ``SloCriterion`` — the
        ``operator`` tolerance kind — so a surface that accepted ``lt`` here would
        either guess a field or silently drop the comparison.
        """
        with pytest.raises(Exception) as caught:
            build_condition(metric="m.metric", op=op, value=1.0)

        assert "no absolute bound" in str(caught.value)
        assert "time-to-recovery" in str(caught.value)

    def test_a_fires_when_met_condition_may_be_authored_for_a_recovery_window(self) -> None:
        payload = build_condition(
            metric="http.api",
            op=CriterionOperator.LTE,
            value=100.0,
            fires_when=FiresWhen.MET,
            max_duration=30.0,
        )

        assert payload["condition"]["threshold"]["fires_when"] == "met"
        assert "window 30s" in payload["summary"]

    def test_the_command_states_that_a_firing_must_cite_its_samples(
        self, runner: CliRunner
    ) -> None:
        result = _invoke(
            runner, ["condition", "--metric", "http.api", "--op", "lte", "--value", "250"]
        )

        assert result.exit_code == 0
        assert "cites the samples that produced it" in result.output
        assert "resolving to nothing is refused" in result.output


# -- machine output and honesty ----------------------------------------------------------


class TestTheSurfaceReachesNothingAndClaimsNothing:
    def test_the_surface_has_no_transport_and_no_store(self) -> None:
        """Structural: the modules an IO-capable surface would import are absent.

        The control: an implementation could add a ``--run`` flag that read the store
        or a ``--endpoint`` that fetched, and every behaviour test here would still
        pass while the surface stopped being honest about what it had verified. This
        reads the module's own namespace instead.
        """
        from mayhem.cli import probe_cmd

        forbidden = {"urllib", "socket", "sqlite3", "httpx", "requests", "asyncio", "Store"}
        namespace = set(dir(probe_cmd))

        assert forbidden & namespace == set()
        assert not any("http" in name and "client" in name for name in namespace)

    def test_the_payload_functions_are_json_serialisable(self) -> None:
        """A surface whose JSON mode emits a ``PosixPath`` is a surface with a bug."""
        for payload in (
            catalogue_payload(),
            connectors_payload(),
            tolerances_payload(),
            uncover_payload([ProbeFamily.PROMETHEUS]),
        ):
            assert json.loads(json.dumps(payload)) == payload

    def test_the_locator_table_is_delegated_to_the_domain_not_copied(self) -> None:
        """A surface that documented a *different* requirement would be lying."""
        assert locators_for(ProbeFamily.HTTP) == required_locator(ProbeFamily.HTTP)

    def test_the_catalogue_hard_codes_no_family_names(self) -> None:
        """The catalogue is derived from the enum, so a nineteenth family appears."""
        payload = catalogue_payload()

        assert len(payload["families"]) == len(list(ProbeFamily))
        assert len(payload["lifecycle"]) == len(list(LifecycleStage))

    def test_nothing_in_the_payloads_claims_authentication_or_liveness(self) -> None:
        """The control for ``verified-live`` staying at 0.

        An implementation could add a ``verified`` key to a connector row or a
        ``liveness`` key to the catalogue and every behavioural test here would
        still pass. These are the two words that would mean "we proved this against
        a real system", and they must not appear.
        """
        serialised = json.dumps(
            {
                "catalogue": catalogue_payload(),
                "connectors": connectors_payload(),
                "tolerances": tolerances_payload(),
                "uncover": uncover_payload([ProbeFamily.PROMETHEUS]),
            }
        ).lower()

        for word in ("verified", "signature", "live-cell", "verified-live"):
            assert word not in serialised, word

    def test_the_machine_format_hook_is_available_to_every_sub_command(
        self, runner: CliRunner
    ) -> None:
        """``echo_machine`` is called by all six; a new one must do the same."""
        from mayhem.cli import probe_cmd

        source = probe_cmd.__file__
        assert source is not None
        text = Path(source).read_text(encoding="utf-8")
        # One call site per sub-command; a seventh command added without one would
        # render text where the caller asked for JSON.
        assert text.count("echo_machine(") == 6
        # And the global format is what it reads, so `--format json` works for free.
        assert current_format("text") in {"text", "json", "yaml"}


class TestTheAbsentConnectorCatalogueIsNotMistakenForCoverage:
    def test_default_connectors_is_the_only_catalogue_the_surface_defaults_to(self) -> None:
        """One shipped catalogue, so two surfaces cannot disagree about coverage."""
        assert len(default_connectors().connectors) == 15
        assert len(catalogue_payload()["families"]) == len(list(ProbeFamily))

    def test_the_unavailable_reason_strings_are_exactly_three(self) -> None:
        """Every row must name its reason, so no row can render as a bare flag."""
        reasons: set[str] = set()
        for family in ProbeFamily:
            for bound in ((), (ConnectorId.PROMETHEUS,)):
                payload = uncover_payload([family], bound=bound)
                reason = payload["families"][0]["unavailable_reason"]
                if reason is not None:
                    reasons.add(reason)
                else:
                    reasons.add("<available>")

        assert reasons == {
            "<available>",
            "no shipped connector serves this family",
            "connector declared but not bound",
        }
