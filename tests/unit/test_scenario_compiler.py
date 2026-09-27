"""v0.9.0 expansion task 14: scenario compiler."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from mayhem.domain.scenarios import (
    Condition,
    ConditionalStep,
    ConditionOperator,
    Scenario,
    ScenarioError,
    ScenarioVariable,
    TimeWindow,
    VariableType,
    compile_scenario,
    load_scenario,
    resolve_variables,
)


def _scenario(**overrides) -> Scenario:
    payload = {
        "name": "peak-traffic",
        "variables": [
            {"name": "duration", "type": "duration", "default": "30s"},
            {"name": "concurrency", "type": "integer", "default": 10, "minimum": 1, "maximum": 100},
            {"name": "mode", "type": "enum", "choices": ["smoke", "full"], "default": "smoke"},
        ],
        "steps": [
            {
                "id": "warmup",
                "action": {"type": "wait", "duration": 5},
            },
            {
                "id": "load",
                "when": [{"variable": "mode", "operator": "eq", "value": "full"}],
                "action": {"type": "start_load", "concurrency": 50},
                "else_action": {"type": "start_load", "concurrency": 1},
            },
        ],
    }
    payload.update(overrides)
    return Scenario.model_validate(payload)


# ── variables ────────────────────────────────────────────────────────────────
def test_defaults_are_used_when_nothing_is_supplied() -> None:
    resolved = resolve_variables(_scenario(), {})
    assert resolved == {"duration": 30.0, "concurrency": 10, "mode": "smoke"}


def test_supplied_values_override_defaults() -> None:
    resolved = resolve_variables(_scenario(), {"concurrency": "42"})
    assert resolved["concurrency"] == 42


def test_typed_coercion_rejects_bad_values() -> None:
    with pytest.raises(ScenarioError, match="not an integer"):
        resolve_variables(_scenario(), {"concurrency": "many"})


def test_duration_units_normalise_to_seconds() -> None:
    scenario = _scenario()
    assert resolve_variables(scenario, {"duration": "500ms"})["duration"] == 0.5
    assert resolve_variables(scenario, {"duration": "2m"})["duration"] == 120.0
    assert resolve_variables(scenario, {"duration": "45"})["duration"] == 45.0


def test_typed_constraints_are_enforced() -> None:
    with pytest.raises(ScenarioError, match="above maximum"):
        resolve_variables(_scenario(), {"concurrency": 1000})
    with pytest.raises(ScenarioError, match="below minimum"):
        resolve_variables(_scenario(), {"concurrency": 0})


def test_enum_choices_are_enforced() -> None:
    with pytest.raises(ScenarioError, match="must be one of"):
        resolve_variables(_scenario(), {"mode": "extreme"})


def test_missing_required_variable_is_refused() -> None:
    scenario = _scenario(
        variables=[{"name": "token", "type": "string", "required": True}],
        steps=[],
    )
    with pytest.raises(ScenarioError, match="missing required"):
        resolve_variables(scenario, {})


def test_unknown_supplied_variable_is_refused() -> None:
    with pytest.raises(ScenarioError, match="unknown scenario variables"):
        resolve_variables(_scenario(), {"nope": 1})


def test_pattern_constraint_is_enforced() -> None:
    scenario = _scenario(
        variables=[{"name": "run", "type": "string", "pattern": "^[a-z]+$"}],
        steps=[],
    )
    assert resolve_variables(scenario, {"run": "abc"})["run"] == "abc"
    with pytest.raises(ScenarioError, match="does not match"):
        resolve_variables(scenario, {"run": "ABC1"})


def test_enum_variable_without_choices_is_rejected() -> None:
    with pytest.raises(Exception):
        ScenarioVariable(name="x", type=VariableType.ENUM)


def test_minimum_above_maximum_is_rejected() -> None:
    with pytest.raises(Exception):
        ScenarioVariable(name="x", type=VariableType.INTEGER, minimum=10, maximum=1)


# ── time windows ─────────────────────────────────────────────────────────────
def test_time_window_contains_moment() -> None:
    window = TimeWindow(start="09:00", end="17:00")
    assert window.contains(datetime(2026, 1, 1, 12, 0, tzinfo=UTC)) is True
    assert window.contains(datetime(2026, 1, 1, 18, 0, tzinfo=UTC)) is False


def test_time_window_wrapping_midnight() -> None:
    window = TimeWindow(start="22:00", end="02:00")
    assert window.contains(datetime(2026, 1, 1, 23, 0, tzinfo=UTC)) is True
    assert window.contains(datetime(2026, 1, 1, 1, 0, tzinfo=UTC)) is True
    assert window.contains(datetime(2026, 1, 1, 12, 0, tzinfo=UTC)) is False


def test_invalid_window_time_is_rejected() -> None:
    with pytest.raises(Exception):
        TimeWindow(start="25:00", end="26:00")


def test_step_outside_its_window_is_skipped() -> None:
    scenario = Scenario.model_validate(
        {
            "name": "nightly",
            "variables": [],
            "steps": [
                {
                    "id": "night",
                    "window": {"start": "22:00", "end": "02:00"},
                    "action": {"type": "wait"},
                }
            ],
        }
    )
    inside = compile_scenario(scenario, now=datetime(2026, 1, 1, 23, 0, tzinfo=UTC))
    outside = compile_scenario(scenario, now=datetime(2026, 1, 1, 12, 0, tzinfo=UTC))
    assert len(inside.steps) == 1
    assert outside.steps == ()
    assert outside.skipped == ("night",)


# ── conditional steps ────────────────────────────────────────────────────────
def test_condition_branches_select_the_right_action() -> None:
    smoke = compile_scenario(_scenario(), {"mode": "smoke"})
    full = compile_scenario(_scenario(), {"mode": "full"})
    assert smoke.steps[-1]["id"] == "load:else"
    assert smoke.steps[-1]["action"]["concurrency"] == 1
    assert full.steps[-1]["id"] == "load"
    assert full.steps[-1]["action"]["concurrency"] == 50
    assert smoke.skipped == ("load",)
    assert full.skipped == ()


def test_all_conditions_must_hold() -> None:
    step = ConditionalStep(
        id="s",
        when=(
            Condition(variable="a", operator=ConditionOperator.GREATER, value=1),
            Condition(variable="b", operator=ConditionOperator.EQUALS, value="yes"),
        ),
    )
    assert step.enabled({"a": 2, "b": "yes"}) is True
    assert step.enabled({"a": 2, "b": "no"}) is False


def test_numeric_condition_operators() -> None:
    for operator, threshold, expected in (
        (ConditionOperator.GREATER, 4, True),
        (ConditionOperator.GREATER_EQUAL, 5, True),
        (ConditionOperator.LESS, 5, False),
        (ConditionOperator.LESS_EQUAL, 5, True),
        (ConditionOperator.NOT_EQUALS, 5, False),
    ):
        condition = Condition(variable="n", operator=operator, value=threshold)
        assert condition.evaluate({"n": 5}) is expected


def test_in_and_contains_operators() -> None:
    assert Condition(variable="l", operator=ConditionOperator.IN, value=["a"]).evaluate({"l": "a"})
    assert not Condition(variable="l", operator=ConditionOperator.IN, value=["b"]).evaluate(
        {"l": "a"}
    )
    assert Condition(variable="s", operator=ConditionOperator.CONTAINS, value="err").evaluate(
        {"s": "an error occurred"}
    )


def test_condition_on_undeclared_variable_is_refused_at_compile() -> None:
    # Pydantic wraps validator errors; ``load_scenario`` is the surface that
    # reports them as a ScenarioError.
    with pytest.raises(ScenarioError, match="invalid scenario"):
        load_scenario(
            {
                "name": "bad",
                "variables": [],
                "steps": [
                    {"id": "s", "when": [{"variable": "ghost", "operator": "eq", "value": 1}]}
                ],
            }
        )


def test_duplicate_variables_and_steps_are_rejected() -> None:
    with pytest.raises(Exception, match="duplicate scenario variables"):
        Scenario.model_validate(
            {"name": "x", "variables": [{"name": "a"}, {"name": "a"}], "steps": []}
        )
    with pytest.raises(Exception, match="duplicate scenario steps"):
        Scenario.model_validate(
            {
                "name": "x",
                "variables": [],
                "steps": [{"id": "s", "action": {}}, {"id": "s", "action": {}}],
            }
        )


# ── determinism and evidence ─────────────────────────────────────────────────
def test_compilation_is_deterministic_for_the_same_variables_and_seed() -> None:
    scenario = _scenario()
    first = compile_scenario(scenario, {"concurrency": 25}, seed=7)
    second = compile_scenario(scenario, {"concurrency": 25}, seed=7)
    assert first.digest == second.digest
    assert first.to_dict() == second.to_dict()


def test_a_different_seed_changes_the_digest() -> None:
    scenario = _scenario()
    assert (
        compile_scenario(scenario, {}, seed=1).digest
        != compile_scenario(scenario, {}, seed=2).digest
    )


def test_compiled_plan_preserves_the_scenario_source() -> None:
    compiled = compile_scenario(_scenario(), {})
    assert compiled.source["name"] == "peak-traffic"
    assert compiled.to_dict()["source"]["variables"][0]["name"] == "duration"


def test_compiled_dict_is_json_serializable() -> None:
    payload = compile_scenario(_scenario(), {}).to_dict()
    assert json.loads(json.dumps(payload, default=str))["digest"]


def test_load_scenario_reports_validation_errors() -> None:
    with pytest.raises(ScenarioError, match="invalid scenario"):
        load_scenario({"name": "x", "variables": [{"name": "a", "type": "nope"}]})
