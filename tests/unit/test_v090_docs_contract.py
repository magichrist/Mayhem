"""The documented YAML must actually work (v0.9.0 docs contract).

A spec doc that drifts from the schema is a lie the reader pays for, so the
examples in `docs/drill-spec.md` are loaded and compiled here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC_DOC = ROOT / "docs" / "drill-spec.md"


def _yaml_blocks() -> list[str]:
    text = SPEC_DOC.read_text(encoding="utf-8")
    return re.findall(r"```yaml\n(.*?)```", text, re.DOTALL)


def test_the_doc_has_yaml_examples() -> None:
    assert len(_yaml_blocks()) >= 5


def test_every_documented_drill_yaml_parses() -> None:
    from mayhem.domain.experiments import DrillSpec

    parsed = 0
    for block in _yaml_blocks():
        payload = yaml.safe_load(block)
        if not isinstance(payload, dict) or payload.get("kind") != "drill":
            continue
        # Examples that are deliberately invalid are marked in a comment.
        if "INVALID" in block or payload.get("name") in {"invalid-example"}:
            continue
        DrillSpec.model_validate(payload)
        parsed += 1
    assert parsed >= 1, "no complete drill example in the doc parsed"


def test_the_documented_slo_example_matches_the_slo_schema() -> None:
    from mayhem.domain.experiments import DrillSpec

    for block in _yaml_blocks():
        payload = yaml.safe_load(block)
        if not isinstance(payload, dict) or "slo" not in payload:
            continue
        spec = DrillSpec.model_validate(payload)
        assert spec.slo, "documented slo block produced no criteria"
        for criterion in spec.slo:
            assert criterion["metric"]
            assert criterion["kind"] in {
                "latency",
                "error_budget",
                "recovery_time",
                "saturation",
                "absence",
            }
            assert criterion["operator"] in {"lt", "lte", "gt", "gte", "eq"}
            assert isinstance(criterion["threshold"], (int, float))
            assert criterion["unit"]
            assert criterion["window_s"] > 0
        return
    pytest.fail("no slo example found in docs/drill-spec.md")


def test_the_documented_scenario_example_compiles() -> None:
    from mayhem.domain.scenarios import Scenario, compile_scenario

    for block in _yaml_blocks():
        payload = yaml.safe_load(block)
        if not isinstance(payload, dict) or "steps" not in payload:
            continue
        if "variables" not in payload and "name" not in payload:
            continue
        if "kind" in payload:  # that is a drill spec, not a scenario
            continue
        scenario = Scenario.model_validate(payload)
        compiled = compile_scenario(scenario, {}, seed=7)
        assert compiled.digest
        assert compiled.source["name"] == scenario.name
        return
    pytest.fail("no scenario example found in docs/drill-spec.md")


def test_documented_condition_operators_all_exist() -> None:
    from mayhem.domain.scenarios import ConditionOperator

    documented = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "contains"}
    implemented = {operator.value for operator in ConditionOperator}
    assert documented <= implemented


def test_documented_durations_normalise_to_seconds() -> None:
    from mayhem.domain.scenarios import Scenario, resolve_variables

    scenario = Scenario.model_validate(
        {"name": "d", "variables": [{"name": "d", "type": "duration"}]}
    )
    assert resolve_variables(scenario, {"d": "500ms"})["d"] == 0.5
    assert resolve_variables(scenario, {"d": "2m"})["d"] == 120.0


def test_documented_time_window_format_is_accepted() -> None:
    from mayhem.domain.scenarios import TimeWindow

    midnight_wrap = TimeWindow(start="22:00", end="02:00")
    assert midnight_wrap.contains(
        __import__("datetime").datetime(2026, 1, 1, 23, 0, tzinfo=__import__("datetime").UTC)
    )


def test_readme_documents_every_new_command_group() -> None:
    from mayhem.cli.command_registry import COMMAND_SPECS

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    v090_groups = {"game-day", "bundle"}
    for spec in COMMAND_SPECS:
        if spec.name in v090_groups:
            assert f"mayhem {spec.name}" in readme, f"{spec.name} missing from README"


def test_drill_spec_documents_the_slo_field_that_exists() -> None:
    from mayhem.domain.experiments import DrillSpec

    doc = SPEC_DOC.read_text(encoding="utf-8")
    for field in DrillSpec.model_fields:
        if field in {"slo"}:
            assert f"`{field}`" in doc, f"drill spec doc omits the {field} field"
