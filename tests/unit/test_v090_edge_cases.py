"""Edge-case unit tests for the v0.9.0 code (task 1 of this pass).

These cover the branches the per-feature suites leave untested: coercion
failures, malformed connector payloads, and the refusal paths that only fire
when something is already wrong. Coverage-driven, not invented.
"""

from __future__ import annotations

import io
import json
import urllib.error
from types import SimpleNamespace

import pytest


# ── scenarios: coercion and constraint branches ──────────────────────────────
def test_number_variable_rejects_non_numeric() -> None:
    from mayhem.domain.scenarios import Scenario, ScenarioError, resolve_variables

    scenario = Scenario.model_validate(
        {"name": "s", "variables": [{"name": "n", "type": "number"}], "steps": []}
    )
    with pytest.raises(ScenarioError, match="is not a number"):
        resolve_variables(scenario, {"n": "lots"})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(True, True), ("yes", True), ("1", True), ("false", False), ("no", False), ("0", False)],
)
def test_boolean_variable_accepts_common_spellings(raw: object, expected: bool) -> None:
    from mayhem.domain.scenarios import Scenario, resolve_variables

    scenario = Scenario.model_validate(
        {"name": "s", "variables": [{"name": "b", "type": "boolean"}], "steps": []}
    )
    assert resolve_variables(scenario, {"b": raw})["b"] is expected


def test_boolean_variable_rejects_nonsense() -> None:
    from mayhem.domain.scenarios import Scenario, ScenarioError, resolve_variables

    scenario = Scenario.model_validate(
        {"name": "s", "variables": [{"name": "b", "type": "boolean"}], "steps": []}
    )
    with pytest.raises(ScenarioError, match="is not a boolean"):
        resolve_variables(scenario, {"b": "maybe"})


def test_duration_variable_rejects_nonsense() -> None:
    from mayhem.domain.scenarios import Scenario, ScenarioError, resolve_variables

    scenario = Scenario.model_validate(
        {"name": "s", "variables": [{"name": "d", "type": "duration"}], "steps": []}
    )
    with pytest.raises(ScenarioError, match="is not a duration"):
        resolve_variables(scenario, {"d": "soon"})


def test_optional_variable_without_a_default_is_skipped() -> None:
    from mayhem.domain.scenarios import Scenario, resolve_variables

    scenario = Scenario.model_validate(
        {"name": "s", "variables": [{"name": "maybe", "required": False}], "steps": []}
    )
    assert resolve_variables(scenario, {}) == {}


def test_condition_on_an_undeclared_variable_at_evaluation_time() -> None:
    from mayhem.domain.scenarios import Condition, ScenarioError

    with pytest.raises(ScenarioError, match="unknown variable"):
        Condition(variable="ghost", value=1).evaluate({"other": 1})


def test_condition_with_an_unsupported_operator_is_refused() -> None:
    """A value smuggled past validation is refused at evaluation, not ignored."""
    from mayhem.domain.scenarios import Condition, ScenarioError

    condition = Condition.model_construct(variable="n", operator="teleport", value=1)
    with pytest.raises(ScenarioError, match="unsupported operator"):
        condition.evaluate({"n": 1})


def test_pattern_constraint_rejects_a_non_string_value_gracefully() -> None:
    from mayhem.domain.scenarios import Scenario, resolve_variables

    scenario = Scenario.model_validate(
        {
            "name": "s",
            "variables": [{"name": "n", "type": "integer", "pattern": "^1"}],
            "steps": [],
        }
    )
    # A pattern only applies to strings; an integer passes rather than erroring.
    assert resolve_variables(scenario, {"n": 2})["n"] == 2


def test_load_scenario_reraises_a_scenario_error_unchanged() -> None:
    from mayhem.domain.scenarios import ScenarioError, load_scenario

    with pytest.raises(ScenarioError) as excinfo:
        load_scenario({"name": "s", "variables": [{"name": "a", "type": "enum"}], "steps": []})
    assert "invalid scenario" in str(excinfo.value)


def test_compiled_digest_property_is_stable() -> None:
    from mayhem.domain.scenarios import Scenario, compile_scenario

    compiled = compile_scenario(Scenario.model_validate({"name": "s"}), {})
    assert compiled.digest == compiled.digest
    assert len(compiled.digest) == 64


# ── observation providers: the success and HTTP-error paths ──────────────────
class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def status(self) -> int:
        return 200


def test_http_provider_measures_latency(monkeypatch) -> None:
    from mayhem.domain.observations import ObservationQuery
    from mayhem.providers.observation import HttpObservationProvider

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout=None: _Response(b"ok"),
    )
    result = HttpObservationProvider().observe(
        ObservationQuery(metric="http.latency", target="http://svc/healthz")
    )
    assert result.available is True
    assert result.value is not None and result.value >= 0.0
    assert result.unit == "ms"
    assert result.provenance == "http"


def test_http_provider_reports_a_status_metric(monkeypatch) -> None:
    from mayhem.domain.observations import ObservationQuery
    from mayhem.providers.observation import HttpObservationProvider

    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout=None: _Response(b"ok"))
    result = HttpObservationProvider().observe(
        ObservationQuery(metric="http.status", target="http://svc/healthz", unit="code")
    )
    assert result.value == 200.0
    assert result.unit == "code"


def test_http_provider_reports_an_http_error_code(monkeypatch) -> None:
    from mayhem.domain.observations import ObservationQuery
    from mayhem.providers.observation import HttpObservationProvider

    def raise_http_error(request: object, timeout: float | None = None) -> object:
        raise urllib.error.HTTPError(
            "http://svc",
            503,
            "Service Unavailable",
            {},
            None,  # type: ignore[arg-type]
        )

    monkeypatch.setattr("urllib.request.urlopen", raise_http_error)
    result = HttpObservationProvider().observe(
        ObservationQuery(metric="http.latency", target="http://svc/healthz")
    )
    assert result.available is True
    assert result.value == 503.0
    assert "503" in result.detail


def test_process_provider_without_an_injected_runner() -> None:
    """The default path shells out for real; it must be bounded and numeric."""
    from mayhem.domain.observations import ObservationQuery
    from mayhem.providers.observation import ProcessObservationProvider

    result = ProcessObservationProvider().observe(ObservationQuery(metric="procs", target="echo 7"))
    assert result.value == 7.0
    assert result.provenance == "process"


def test_process_provider_reports_a_runner_crash_as_error() -> None:
    from mayhem.domain.observations import ObservationQuery
    from mayhem.providers.observation import ProcessObservationProvider

    def explode(argv: list[str]) -> object:
        raise OSError("no such command")

    result = ProcessObservationProvider(runner=explode).observe(
        ObservationQuery(metric="m", target="nope")
    )
    assert result.status.value == "error"
    assert result.available is False


def test_process_provider_without_a_command_is_missing() -> None:
    from mayhem.domain.observations import ObservationQuery
    from mayhem.providers.observation import ProcessObservationProvider

    result = ProcessObservationProvider().observe(ObservationQuery(metric="m"))
    assert result.status.value == "missing"
    assert "no command" in result.detail


def test_process_provider_tolerates_a_result_object_without_returncode() -> None:
    from mayhem.domain.observations import ObservationQuery
    from mayhem.providers.observation import ProcessObservationProvider

    provider = ProcessObservationProvider(runner=lambda argv: SimpleNamespace(stdout="3\n"))
    assert provider.observe(ObservationQuery(metric="m", target="x")).value == 3.0


def test_query_to_dict_includes_every_field() -> None:
    from mayhem.domain.observations import ObservationQuery

    query = ObservationQuery(metric="m", window_s=30.0, unit="s", target="t", labels={"a": "b"})
    assert query.to_dict() == {
        "metric": "m",
        "window_s": 30.0,
        "unit": "s",
        "target": "t",
        "labels": {"a": "b"},
        "aggregation": "avg",
    }


# ── prometheus edge payloads ─────────────────────────────────────────────────
def _opener(payload: object) -> object:
    body = json.dumps(payload).encode()

    def opener(request: object, timeout: float | None = None) -> _Response:
        return _Response(body)

    return opener


def test_prometheus_query_includes_an_explicit_time() -> None:
    from mayhem.observability.prometheus import MetricQuery, PrometheusConnector

    seen: list[str] = []

    def opener(request: object, timeout: float | None = None) -> _Response:
        seen.append(getattr(request, "full_url", ""))
        return _Response(json.dumps({"status": "success", "data": {"result": []}}).encode())

    PrometheusConnector("http://prom:9090", opener=opener).query(
        MetricQuery(promql="up", time="2026-01-01T00:00:00Z")
    )
    assert "time=" in seen[0]


def test_prometheus_uses_the_promql_label_when_present() -> None:
    from mayhem.domain.observations import ObservationQuery
    from mayhem.observability.prometheus import PrometheusConnector

    seen: list[str] = []

    def opener(request: object, timeout: float | None = None) -> _Response:
        seen.append(getattr(request, "full_url", ""))
        return _Response(
            json.dumps({"status": "success", "data": {"result": [{"value": [1, "1.5"]}]}}).encode()
        )

    PrometheusConnector("http://prom:9090", opener=opener).observe(
        ObservationQuery(metric="m", labels={"promql": "rate(errors[5m])"})
    )
    assert "rate" in seen[0]


def test_prometheus_non_numeric_sample_is_missing_not_zero() -> None:
    from mayhem.observability.prometheus import MetricQuery, PrometheusConnector

    payload = {"status": "success", "data": {"result": [{"value": [1, "NaN-ish"]}]}}
    connector = PrometheusConnector("http://prom:9090", opener=_opener(payload))
    assert connector.query(MetricQuery(promql="up")) is None


def test_prometheus_result_without_a_value_is_missing() -> None:
    from mayhem.observability.prometheus import MetricQuery, PrometheusConnector

    payload = {"status": "success", "data": {"result": [{"metric": {}}]}}
    connector = PrometheusConnector("http://prom:9090", opener=_opener(payload))
    assert connector.query(MetricQuery(promql="up")) is None


def test_prometheus_non_dict_result_entry_is_ignored() -> None:
    from mayhem.observability.prometheus import MetricQuery, PrometheusConnector

    payload = {"status": "success", "data": {"result": ["nonsense"]}}
    connector = PrometheusConnector("http://prom:9090", opener=_opener(payload))
    assert connector.query(MetricQuery(promql="up")) is None


def test_prometheus_missing_data_block_raises() -> None:
    from mayhem.observability.base import ConnectorError
    from mayhem.observability.prometheus import MetricQuery, PrometheusConnector

    connector = PrometheusConnector("http://prom:9090", opener=_opener({"status": "success"}))
    with pytest.raises(ConnectorError, match="no data block"):
        connector.query(MetricQuery(promql="up"))


def test_metric_query_to_dict() -> None:
    from mayhem.observability.prometheus import MetricQuery

    query = MetricQuery(promql="up", time="t0", step_s=15.0, labels={"job": "mayhem"})
    assert query.to_dict() == {
        "promql": "up",
        "time": "t0",
        "step_s": 15.0,
        "labels": {"job": "mayhem"},
    }


# ── loki edge payloads ───────────────────────────────────────────────────────
def test_loki_skips_malformed_streams_and_entries() -> None:
    from mayhem.observability.loki import LogQuery, LokiConnector

    payload = {
        "status": "success",
        "data": {
            "result": [
                "not-a-stream",
                {"stream": {}, "values": "not-a-list"},
                {"stream": {}, "values": [["1", "good"], "not-a-pair", ["2"]]},
            ]
        },
    }
    connector = LokiConnector("http://loki:3100", opener=_opener(payload))
    assert connector.query_lines(LogQuery(selector='{app="x"}')) == ("good",)


def test_loki_query_sends_start_and_end() -> None:
    from mayhem.observability.loki import LogQuery, LokiConnector

    seen: list[str] = []

    def opener(request: object, timeout: float | None = None) -> _Response:
        seen.append(getattr(request, "full_url", ""))
        return _Response(json.dumps({"status": "success", "data": {"result": []}}).encode())

    LokiConnector("http://loki:3100", opener=opener).query_lines(
        LogQuery(selector='{app="x"}', start="t0", end="t1", limit=5)
    )
    assert "start=t0" in seen[0]
    assert "end=t1" in seen[0]
    assert "limit=5" in seen[0]


def test_log_query_to_dict() -> None:
    from mayhem.observability.loki import LogQuery

    query = LogQuery(selector='{app="x"}', start="t0", end="t1", limit=7, labels={"a": "b"})
    assert query.to_dict() == {
        "selector": '{app="x"}',
        "start": "t0",
        "end": "t1",
        "limit": 7,
        "labels": {"a": "b"},
    }


# ── connector transport errors ───────────────────────────────────────────────
def test_http_error_status_becomes_a_connector_error() -> None:
    from mayhem.observability.base import ConnectorError, fetch_json

    def opener(request: object, timeout: float | None = None) -> object:
        raise urllib.error.HTTPError(
            "http://x",
            502,
            "Bad Gateway",
            {},
            None,  # type: ignore[arg-type]
        )

    with pytest.raises(ConnectorError, match="HTTP 502"):
        fetch_json("http://x", opener=opener)


# ── domain model edge lines ──────────────────────────────────────────────────
def test_coverage_node_with_an_unknown_maturity_band() -> None:
    from mayhem.domain.coverage_graph import CoverageNode

    node = CoverageNode(
        service="s",
        fault_family="net",
        fault_kind="net.x",
        failure_domain="d",
        target_type="container",
        engine="docker",
        maturity="who-knows",
        evidence_status="verified",
    )
    assert node.maturity_band == "unknown"


def test_observation_result_dict_exposes_availability() -> None:
    from mayhem.domain.observations import ObservationResult, ObservationStatus

    ok = ObservationResult("m", 1.0, "ms", 60.0)
    missing = ObservationResult("m", None, "ms", 60.0, status=ObservationStatus.MISSING)
    assert ok.to_dict()["available"] is True
    assert missing.to_dict()["available"] is False
    assert ok.to_dict()["status"] == "ok"


def test_pack_fault_to_dict_sorts_permissions() -> None:
    from mayhem.domain.provider import ProviderPermission
    from mayhem.providers.pack import PackFault

    fault = PackFault(
        id="p.fault",
        compensation="undo",
        permissions=(ProviderPermission.SUBPROCESS, ProviderPermission.NETWORK),
    )
    assert fault.to_dict()["permissions"] == ["network", "subprocess"]


def test_game_day_cannot_be_completed_before_it_runs() -> None:
    from mayhem.domain.game_day import GameDayError, GameDaySession, complete

    with pytest.raises(GameDayError, match="cannot complete"):
        complete(GameDaySession(id="gd-1"), "bundle-abc")


def test_bundle_with_optional_artifacts_uses_every_slot() -> None:
    from mayhem.domain.evidence_bundle import build_bundle

    bundle = build_bundle(
        evidence={"run_id": "r", "redaction_metrics": {"policy_version": "1"}},
        replay={"run_id": "r"},
        capabilities={"capabilities": []},
        observations={"count": 0},
    )
    assert set(bundle.artifacts) == {
        "evidence.json",
        "replay.json",
        "capabilities.json",
        "observations.json",
    }


def test_bundle_without_an_evidence_artifact_is_refused() -> None:
    from mayhem.domain.evidence_bundle import BundleManifest, EvidenceBundle, verify_bundle

    bundle = EvidenceBundle(
        manifest=BundleManifest(artifacts=(), root_digest="", redaction_policy=""),
        artifacts={},
    )
    result = verify_bundle(bundle)
    assert result.valid is False
    assert any("no evidence.json" in error for error in result.errors)


def test_bundle_with_a_non_dict_evidence_artifact_is_refused() -> None:
    from mayhem.domain.evidence_bundle import BundleManifest, EvidenceBundle, verify_bundle

    bundle = EvidenceBundle(
        manifest=BundleManifest(artifacts=(), root_digest="", redaction_policy=""),
        artifacts={"evidence.json": ["not", "a", "dict"]},
    )
    result = verify_bundle(bundle)
    assert result.valid is False
    assert any("no evidence.json" in error for error in result.errors)


def test_coverage_node_maturity_bands() -> None:
    from mayhem.domain.coverage_graph import CoverageNode

    def _node(maturity: str) -> CoverageNode:
        return CoverageNode(
            service="s",
            fault_family="net",
            fault_kind="net.x",
            failure_domain="d",
            target_type="container",
            engine="docker",
            maturity=maturity,
            evidence_status="none",
        )

    assert _node("stable").maturity_band == "mature"
    assert _node("verified-live").maturity_band == "mature"
    assert _node("verified-unit").maturity_band == "provisional"
    assert _node("experimental").maturity_band == "provisional"
    assert _node("mystery").maturity_band == "unknown"


def test_bundle_manifest_without_a_redaction_policy_is_refused() -> None:
    from mayhem.domain.evidence_bundle import build_bundle, verify_bundle

    bundle = build_bundle(evidence={"run_id": "r", "redaction_metrics": {"policy_version": "1"}})
    # Strip the policy the builder derived from the evidence marker.
    stripped = type(bundle)(
        manifest=type(bundle.manifest)(
            artifacts=bundle.manifest.artifacts,
            root_digest=bundle.manifest.root_digest,
            redaction_policy="",
        ),
        artifacts=bundle.artifacts,
    )
    result = verify_bundle(stripped)
    assert result.valid is False
    assert any("no redaction policy version" in error for error in result.errors)


def test_unknown_variable_type_is_passed_through_unchanged() -> None:
    """A type outside the vocabulary is a validation error, not a silent pass."""
    from mayhem.domain.scenarios import ScenarioError, load_scenario

    with pytest.raises(ScenarioError):
        load_scenario({"name": "s", "variables": [{"name": "v", "type": "matrix"}]})


def test_load_scenario_propagates_a_scenario_error_unchanged() -> None:
    """A ScenarioError raised while parsing is re-raised, not re-wrapped."""
    from mayhem.domain.scenarios import ScenarioError, load_scenario

    payload = {
        "name": "s",
        "variables": [],
        "steps": [{"id": "a", "when": [{"variable": "ghost", "operator": "eq", "value": 1}]}],
    }
    with pytest.raises(ScenarioError):
        load_scenario(payload)


# ── the documented YAML must actually compile ────────────────────────────────
def test_drill_spec_accepts_the_documented_slo_block() -> None:
    from mayhem.domain.experiments import DrillSpec

    spec = DrillSpec.model_validate(
        {
            "kind": "drill",
            "name": "checkout-slo",
            "containers": {"checkout": {"faults": [{"fault": "cpu.saturate", "duration": "1s"}]}},
            "execution": [{"sequential": ["checkout"]}],
            "slo": [
                {
                    "metric": "http.latency",
                    "kind": "latency",
                    "operator": "lte",
                    "threshold": 250,
                    "unit": "ms",
                    "window_s": 30,
                }
            ],
        }
    )
    assert spec.slo[0]["metric"] == "http.latency"


def test_planner_carries_spec_slo_into_the_plan() -> None:
    from tests.conftest import build_compose_runtime_graph

    from mayhem.controller.planner import plan_drill
    from mayhem.domain.experiments import DrillSpec

    spec = DrillSpec.model_validate(
        {
            "kind": "drill",
            "name": "checkout-slo",
            "containers": {
                "testcase-api": {"faults": [{"fault": "cpu.saturate", "duration": "1s"}]}
            },
            "execution": [{"sequential": ["testcase-api"]}],
            "slo": [{"metric": "http.latency", "kind": "latency", "threshold": 250}],
        }
    )
    plan = plan_drill(
        "r-slo-1",
        spec,
        build_compose_runtime_graph(),
        config_snapshot_id="cs",
        topology_snapshot_id="ts",
        environment_fingerprint="f",
        engine="fake",
    )
    assert plan.slo[0]["metric"] == "http.latency"
    assert plan.slo[0]["threshold"] == 250
