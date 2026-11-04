"""Tests that namespace help shows its commands and leaf help shows parameters.

Covers Task 16 of the Mayhem CLI reorganization plan:
https://github.com/.../docs/superpowers/plans/2026-11-04-mayhem-cli-reorganization.md
"""

from __future__ import annotations

from click.testing import CliRunner

from mayhem.cli.app import app

NAMESPACE_COMMANDS = [
    ("workspace", ["init", "doctor", "config", "support", "upgrade"]),
    ("environment", ["discover", "boundary", "advisor", "probe"]),
    ("drill", ["prepare", "experiment", "run", "maniac", "risk-preview"]),
    ("runs", ["inspect", "stop", "extend", "recover", "janitor"]),
    ("orchestration", ["campaign", "schedule", "game-day"]),
    ("governance", ["policy", "secrets", "certify"]),
    ("evidence", ["bundle", "verify", "prove"]),
    ("platform", ["agent", "ci", "cloud", "ha", "enterprise"]),
    ("extensions", ["pack", "marketplace", "sandbox"]),
    ("developer", ["api", "lowlevel", "commands", "completion"]),
]


def test_namespace_help_shows_its_commands() -> None:
    """Each namespace's ``--help`` lists the commands belonging to that namespace."""
    runner = CliRunner()
    for ns, expected_cmds in NAMESPACE_COMMANDS:
        result = runner.invoke(app, [ns, "--help"])
        assert result.exit_code == 0, f"namespace {ns} help failed: {result.output}"
        output = result.output
        for cmd in expected_cmds:
            assert cmd in output, f"command {cmd!r} missing from {ns} help"


def test_leaf_help_shows_full_parameters() -> None:
    """Leaf help under a new path shows the existing parameter reference."""
    runner = CliRunner()
    result = runner.invoke(app, ["drill", "run", "--help"])
    assert result.exit_code == 0
    output = result.output
    assert "--execute" in output, "run command missing --execute option"
    assert "--compose" in output, "run command missing --compose option"
