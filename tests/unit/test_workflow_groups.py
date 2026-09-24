from __future__ import annotations

import json

from click.testing import CliRunner

from mayhem.cli.app import app


def test_workflow_groups_expose_expected_views() -> None:
    expected = {
        "discover": {"topology", "faults", "capabilities", "engines"},
        "prepare": {"config", "validate", "dependencies", "check", "plan"},
        "inspect": {"runs", "run", "coverage", "history", "expert", "next", "leases"},
        "extend": {"faults", "capabilities", "dependencies"},
    }
    for group_name, command_names in expected.items():
        result = CliRunner().invoke(app, [group_name, "--help"])
        assert result.exit_code == 0
        for command_name in command_names:
            assert command_name in result.output


def test_discover_engines_has_stable_json_shape() -> None:
    result = CliRunner().invoke(app, ["discover", "engines"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert {engine["name"] for engine in payload["engines"]} == {
        "docker",
        "podman",
        "kubernetes",
    }
    assert "note" in payload


def test_command_map_is_available() -> None:
    result = CliRunner().invoke(app, ["commands", "show", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert any(row["command"] == "discover" for row in payload)
    assert all("workflow" in row for row in payload)


def test_workflow_aliases_delegate_to_legacy_commands() -> None:
    for args in (["discover", "topology", "--help"], ["prepare", "plan", "--help"]):
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 0
