"""Scenario compile → plan identity → replay (task 14)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from mayhem.domain.scenarios import Scenario, compile_scenario

DOCUMENT = {
    "name": "checkout-degradation",
    "variables": [
        {"name": "duration", "type": "duration", "default": "30s"},
        {"name": "concurrency", "type": "integer", "default": 5, "minimum": 1, "maximum": 50},
        {"name": "mode", "type": "enum", "choices": ["smoke", "full"], "default": "smoke"},
    ],
    "steps": [
        {"id": "baseline", "action": {"type": "check_http", "url": "http://checkout/healthz"}},
        {
            "id": "degrade",
            "when": [{"variable": "mode", "operator": "eq", "value": "full"}],
            "action": {"type": "start_load", "concurrency": 50},
            "else_action": {"type": "start_load", "concurrency": 1},
        },
    ],
}


def _scenario() -> Scenario:
    return Scenario.model_validate(DOCUMENT)


def _write(tmp_path, payload: dict, name: str = "scenario.json"):
    path = tmp_path / name
    path.write_text(json.dumps(payload))
    return path


def test_same_variables_and_seed_reproduce_the_same_plan(tmp_path) -> None:
    scenario = _scenario()
    first = compile_scenario(scenario, {"concurrency": 12, "mode": "full"}, seed=99)
    second = compile_scenario(scenario, {"concurrency": 12, "mode": "full"}, seed=99)
    assert first.digest == second.digest
    assert [step["id"] for step in first.steps] == [step["id"] for step in second.steps]
    assert first.values == second.values


def test_replay_from_the_recorded_source_reproduces_the_plan() -> None:
    """The compiled plan keeps its source, so a replay needs no extra inputs."""
    compiled = compile_scenario(_scenario(), {"concurrency": 7, "mode": "smoke"}, seed=3)
    replayed = compile_scenario(
        Scenario.model_validate(compiled.source), compiled.values, seed=compiled.seed
    )
    assert replayed.digest == compiled.digest


def test_different_values_produce_a_different_plan_identity() -> None:
    scenario = _scenario()
    assert (
        compile_scenario(scenario, {"concurrency": 1}).digest
        != compile_scenario(scenario, {"concurrency": 2}).digest
    )


def test_cli_compose_is_plan_only(tmp_path) -> None:
    from mayhem.cli.experiment import compose

    path = _write(tmp_path, DOCUMENT)
    result = CliRunner().invoke(compose, [str(path), "--set", "mode=full", "--seed", "5"])
    assert result.exit_code == 0, result.output
    assert "plan only — nothing was executed" in result.output
    assert "mode = full" in result.output


def test_cli_compose_json_carries_the_digest(tmp_path) -> None:
    from mayhem.cli.experiment import compose

    path = _write(tmp_path, DOCUMENT)
    result = CliRunner().invoke(compose, [str(path), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["digest"]
    assert payload["source"]["name"] == "checkout-degradation"


def test_cli_compose_rejects_a_bad_assignment(tmp_path) -> None:
    from mayhem.cli.experiment import compose

    path = _write(tmp_path, DOCUMENT)
    result = CliRunner().invoke(compose, [str(path), "--set", "mode"])
    assert result.exit_code == 2


def test_cli_compose_reports_a_missing_required_variable(tmp_path) -> None:
    from mayhem.cli.experiment import compose

    payload = dict(DOCUMENT)
    payload["variables"] = [{"name": "token", "type": "string", "required": True}]
    payload["steps"] = []
    path = _write(tmp_path, payload)
    result = CliRunner().invoke(compose, [str(path)])
    assert result.exit_code != 0
    assert "missing required" in result.output


def test_cli_validate_scenario_accepts_and_rejects(tmp_path) -> None:
    from mayhem.cli.experiment import validate_scenario as check_scenario

    good = _write(tmp_path, DOCUMENT)
    assert CliRunner().invoke(check_scenario, [str(good), "--json"]).exit_code == 0

    bad_payload = dict(DOCUMENT)
    bad_payload["steps"] = [
        {"id": "s", "when": [{"variable": "ghost", "operator": "eq", "value": 1}]}
    ]
    bad = _write(tmp_path, bad_payload, "bad.json")
    result = CliRunner().invoke(check_scenario, [str(bad), "--json"])
    assert result.exit_code == 1
    assert json.loads(result.output)["valid"] is False


def test_compose_never_builds_a_run_engine(tmp_path, monkeypatch) -> None:
    """The plan-only guarantee is structural: no engine, no lease, no mutation."""
    from mayhem.cli import experiment as experiment_mod

    def explode(*args: object, **kwargs: object) -> object:
        raise AssertionError("compose must not build an execution engine")

    monkeypatch.setattr("mayhem.controller.executor.RunEngine", explode)
    path = _write(tmp_path, DOCUMENT)
    result = CliRunner().invoke(experiment_mod.compose, [str(path), "--json"])
    assert result.exit_code == 0, result.output
