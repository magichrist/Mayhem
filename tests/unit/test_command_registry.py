from __future__ import annotations

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.command_registry import COMMAND_HELP, COMMAND_SPECS

# COMMAND_SPECS covers the 40 active root commands. Namespaces (10) and the
# ``config`` compatibility alias are registered separately and are not part of
# COMMAND_SPECS or COMMAND_HELP.


def test_registry_covers_current_commands() -> None:
    registry_names = {spec.name for spec in COMMAND_SPECS}
    # app.commands = 40 active commands + 10 namespaces + ``config`` alias.
    # COMMAND_SPECS only covers the 40 active commands.
    assert registry_names == set(app.commands) - {
        "workspace",
        "environment",
        "drill",
        "runs",
        "orchestration",
        "governance",
        "evidence",
        "platform",
        "extensions",
        "developer",
        "config",
    }
    for spec in COMMAND_SPECS:
        assert spec.name in app.commands


def test_registry_declares_workflow_and_mutation_metadata() -> None:
    workflows = {spec.workflow for spec in COMMAND_SPECS}
    assert workflows <= {"discover", "prepare", "experiment", "run", "inspect", "recover", "extend"}
    assert any(spec.mutating for spec in COMMAND_SPECS)


def test_every_visible_command_has_help_text() -> None:
    registry_names = {spec.name for spec in COMMAND_SPECS}
    for name in app.list_commands(None):
        assert app.commands[name].get_short_help_str(limit=100)
        if name in registry_names:
            assert name in COMMAND_HELP


def test_removed_aliases_are_not_listed_or_dispatchable() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("cfg", "v", "validate"):
        assert f"\n  {name} " not in result.output
        assert app.commands.get(name) is None
