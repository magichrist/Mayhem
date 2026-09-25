from __future__ import annotations

import json

from click.testing import CliRunner

from mayhem.cli.app import app

ACTIVE_COMMANDS = {
    "campaign",
    "commands",
    "discover",
    "doctor",
    "experiment",
    "extend",
    "init",
    "inspect",
    "janitor",
    "maniac",
    "prepare",
    "recover",
    "run",
    "verify",
}
REMOVED_COMMANDS = {
    "cfg",
    "config",
    "coverage",
    "dependency",
    "expert",
    "explore",
    "history",
    "next",
    "plan",
    "status",
    "toolkit",
    "topology",
    "validate",
}


def test_cli_surface_contains_only_active_commands() -> None:
    assert set(app.commands) == ACTIVE_COMMANDS
    assert not ACTIVE_COMMANDS & REMOVED_COMMANDS


def test_removed_commands_are_not_dispatchable() -> None:
    for name in REMOVED_COMMANDS:
        result = CliRunner().invoke(app, [name, "--help"])
        assert result.exit_code == 2, name


def test_command_map_contains_only_active_commands() -> None:
    result = CliRunner().invoke(app, ["commands", "show", "--json"])

    assert result.exit_code == 0
    rows = json.loads(result.output)
    assert {row["command"] for row in rows} == ACTIVE_COMMANDS
    assert all("deprecated" not in row for row in rows)
    assert all("replacement" not in row for row in rows)
