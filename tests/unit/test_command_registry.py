from __future__ import annotations

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.command_registry import COMMAND_HELP, COMMAND_SPECS


def test_registry_covers_current_commands() -> None:
    registry_names = {spec.name for spec in COMMAND_SPECS}
    assert registry_names == set(app.commands)
    for spec in COMMAND_SPECS:
        assert spec.name in app.commands


def test_registry_declares_workflow_and_mutation_metadata() -> None:
    workflows = {spec.workflow for spec in COMMAND_SPECS}
    assert workflows <= {"discover", "prepare", "experiment", "run", "inspect", "recover", "extend"}
    assert any(spec.mutating for spec in COMMAND_SPECS)


def test_every_visible_command_has_help_text() -> None:
    for name in app.list_commands(None):
        assert app.commands[name].get_short_help_str(limit=100)
        assert name in COMMAND_HELP


def test_removed_aliases_are_not_listed_or_dispatchable() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("cfg", "v", "config", "validate"):
        assert f"\n  {name} " not in result.output
        assert app.commands.get(name) is None
