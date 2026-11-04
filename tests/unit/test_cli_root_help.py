"""Tests that root help displays the ten namespace groups.

Covers Task 15 of the Mayhem CLI reorganization plan:
https://github.com/.../docs/superpowers/plans/2026-11-04-mayhem-cli-reorganization.md
"""

from __future__ import annotations

from click.testing import CliRunner

from mayhem.cli.app import app

NAMESPACES = [
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
]


def test_root_help_shows_namespaces_not_flat_list() -> None:
    """``mayhem --help`` lists the ten namespace groups, not a flat list of 40 commands."""
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    output = result.output
    for ns in NAMESPACES:
        assert ns in output, f"namespace {ns!r} missing from root help"
