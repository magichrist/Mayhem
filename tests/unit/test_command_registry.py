from __future__ import annotations

from mayhem.cli.app import app
from mayhem.cli.command_registry import COMMAND_SPECS


def test_registry_covers_current_commands() -> None:
    registry_names = {spec.name for spec in COMMAND_SPECS}
    alias_names = {alias for spec in COMMAND_SPECS for alias in spec.aliases}
    assert registry_names == set(app.commands) - alias_names
    for spec in COMMAND_SPECS:
        assert spec.name in app.commands
        for alias in spec.aliases:
            assert app.commands[alias] is app.commands[spec.name]


def test_registry_declares_workflow_and_mutation_metadata() -> None:
    workflows = {spec.workflow for spec in COMMAND_SPECS}
    assert workflows <= {"discover", "prepare", "experiment", "run", "inspect", "recover", "extend"}
    assert any(spec.mutating for spec in COMMAND_SPECS)
    assert all(spec.help_group for spec in COMMAND_SPECS)
