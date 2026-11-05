"""Tests that every old root command path resolves to the same handler
as its new namespace path (compatibility alias contract).

Covers Task 14 of the Mayhem CLI reorganization plan:
https://github.com/.../docs/superpowers/plans/2026-11-04-mayhem-cli-reorganization.md
"""

from __future__ import annotations

import click
from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.command_registry import OLD_TO_NEW_PATH


def _resolve(ctx: click.Context, path: str) -> click.Command:
    """Walk a space-separated path through the Click tree, returning the final command."""
    target: click.Command | click.Group = app
    for part in path.split():
        target = target.get_command(ctx, part)
        assert target is not None, f"path {path!r} does not resolve at {part!r}"
        ctx = click.Context(target)
    return target


def test_every_old_path_resolves_to_same_handler_as_new_path() -> None:
    """Each old path resolves to the same Click handler object as its new path."""
    ctx = click.Context(app)
    for old_path, new_path in OLD_TO_NEW_PATH.items():
        old_cmd = _resolve(ctx, old_path)
        new_cmd = _resolve(ctx, new_path)
        assert old_cmd is not None, f"old path {old_path!r} missing"
        assert new_cmd is not None, f"new path {new_path!r} missing"
        assert old_cmd.callback == new_cmd.callback, (
            f"handler mismatch: {old_path!r} -> {new_path!r}"
        )


def test_old_path_invocation_equals_new_path_invocation() -> None:
    """Invoking --help through old and new paths produces equivalent exit codes."""
    runner = CliRunner()
    for old_path, new_path in OLD_TO_NEW_PATH.items():
        old_result = runner.invoke(app, [*old_path.split(), "--help"])
        new_result = runner.invoke(app, [*new_path.split(), "--help"])
        assert old_result.exit_code == new_result.exit_code, (
            f"exit code mismatch: {old_path!r} vs {new_path!r}"
        )
