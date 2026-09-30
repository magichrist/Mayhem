from __future__ import annotations

import json
from pathlib import Path

import pytest

from mayhem.cli.app import main
from mayhem.domain.catalog import all_definitions, definition_for
from mayhem.controller import catalog_report

ROOT = Path(__file__).resolve().parents[2]


def test_capability_status_keeps_dimensions_separate(monkeypatch: pytest.MonkeyPatch) -> None:
    definition = definition_for("proc.pause")
    monkeypatch.setattr(catalog_report, "_engine_available", lambda engine: True)
    status = catalog_report.capability_status(definition, "docker")
    assert status.fault_id == "proc.pause"
    assert status.engine == "docker"
    assert status.registered is True
    assert status.available is True
    assert status.target_supported is True
    assert status.unit_verified is True
    assert status.live_verified is False
    assert status.compensation_complete is True
    assert status.supported is True
    assert status.blocked_reason == ""


def test_catalog_only_status_explains_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    definition = next(item for item in all_definitions() if item.catalog_only)
    monkeypatch.setattr(catalog_report, "_engine_available", lambda engine: True)
    status = catalog_report.capability_status(definition, "docker")
    assert status.supported is False
    assert status.blocked_reason


def test_unavailable_runtime_and_missing_compensation_are_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition = definition_for("proc.pause")
    monkeypatch.setattr(catalog_report, "_engine_available", lambda engine: False)
    monkeypatch.setattr(catalog_report, "template_for", lambda fault_id: None)
    status = catalog_report.capability_status(definition, "docker")
    assert status.available is False
    assert status.compensation_complete is False
    assert status.blocked_reason == "compensation contract is not registered"
    assert status.supported is False


def test_capability_dashboard_supports_json_and_explain(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["discover", "capabilities", "--format", "json", "--engine", "docker"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "1.0"
    assert payload["engine"] == "docker"
    assert payload["capabilities"]
    assert {"fault_id", "engine", "supported", "blocked_reason"} <= set(payload["capabilities"][0])

    assert main(["discover", "capabilities", "--explain", "proc.pause"]) == 0
    explain = capsys.readouterr().out
    assert "proc.pause" in explain
    assert "docker" in explain


def test_capability_dashboard_yaml_is_machine_readable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    import yaml

    assert main(["discover", "capabilities", "--format", "yaml", "--engine", "podman"]) == 0
    payload = yaml.safe_load(capsys.readouterr().out)
    assert payload["engine"] == "podman"
    assert payload["capabilities"]


def test_capability_dashboard_human_output_contains_reasons(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["discover", "capabilities", "--engine", "docker"]) == 0
    output = capsys.readouterr().out
    assert "supported=" in output
    assert "reason=" in output
    assert "live=false" in output
