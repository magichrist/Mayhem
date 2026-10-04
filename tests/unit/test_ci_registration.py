"""``mayhem ci`` is registered on the live CLI tree (plan 16 Phase 3).

``tests/unit/test_ci_surface_cli.py`` proved the surface *works* by driving
``mayhem.cli.ci_cmd.ci`` directly, and said in its own module docstring that a
refusal only the registration can undo is not yet a refusal a person can hit.
That debt is paid here: the group is on the application tree, ``mayhem ci
--help`` resolves, and the four subcommands a pipeline calls are reachable by
name.

What is asserted is the registration itself — reachability and inventory
agreement — not the fail-closed behaviour, which is the other file's subject and
is not duplicated here. The published metadata is asserted too, because
``mayhem commands show`` reports it: a reviewer reads ``workflow``,
``help_group`` and ``mutating`` before running anything, so those three fields
are a contract with whoever reads the command map.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.ci_cmd import ci
from mayhem.cli.command_registry import COMMAND_HELP, COMMAND_SPECS

SUBCOMMANDS = ("check", "status", "summary", "workflow")


def _run(*args: str) -> Any:
    return CliRunner().invoke(app, list(args), catch_exceptions=False)


def test_ci_group_resolves_on_the_live_tree() -> None:
    result = _run("ci", "--help")
    assert result.exit_code == 0
    assert f"Usage: {app.name} ci [OPTIONS] COMMAND [ARGS]..." in result.output
    assert COMMAND_HELP["ci"] in result.output
    for name in SUBCOMMANDS:
        assert name in result.output


def test_registered_group_is_the_one_under_test() -> None:
    """The live command must be the object the direct-CliRunner suite drives.

    Two names would both satisfy ``mayhem ci --help`` while testing different
    code, so identity — not just presence — is what this pins.
    """
    assert app.commands["ci"] is ci


@pytest.mark.parametrize("name", SUBCOMMANDS)
def test_every_ci_subcommand_parses_help_through_the_tree(name: str) -> None:
    result = _run("ci", name, "--help")
    assert result.exit_code == 0
    assert f"Usage: {app.name} ci {name} [OPTIONS]" in result.output
    assert "Options:" in result.output


def test_registry_help_and_command_map_agree_on_ci() -> None:
    spec = next(spec for spec in COMMAND_SPECS if spec.name == "ci")
    assert (spec.workflow, spec.help_group, spec.mutating) == ("run", "experiments", False)
    assert app.commands["ci"].help == COMMAND_HELP["ci"]
    assert set(app.commands["ci"].commands) == set(SUBCOMMANDS)


def test_ci_appears_in_the_published_command_map() -> None:
    result = _run("commands", "show", "--json")
    assert result.exit_code == 0
    row = next(row for row in json.loads(result.output) if row["command"] == "ci")
    assert row["workflow"] == "run"
    assert row["help_group"] == "experiments"
    assert row["mutating"] is False
