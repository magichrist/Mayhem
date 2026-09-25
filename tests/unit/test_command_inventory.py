from __future__ import annotations

from mayhem.cli.app import app
from mayhem.cli.exit_codes import ExitCode

ALLOWLIST_COMMANDS: frozenset[str] = frozenset(
    {
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
)

ALLOWLIST_TOP_LEVEL = ALLOWLIST_COMMANDS

ALLOWLIST_EXIT_CODES: frozenset[str] = frozenset(
    {
        "SUCCESS",
        "GENERAL_FAILURE",
        "USAGE_ERROR",
        "CONFIG_ERROR",
        "VALIDATION_ERROR",
        "SAFETY_REFUSAL",
        "EXPERIMENT_FAILURE",
        "RECOVERY_FAILURE",
        "AGENT_ERROR",
        "TOOLKIT_ERROR",
        "AMBIGUOUS_COMMAND",
    }
)


def test_top_level_commands_match_allowlist() -> None:
    actual = frozenset(app.commands.keys())
    assert actual == ALLOWLIST_TOP_LEVEL, (
        "top-level command set drifted from the active surface. "
        f"missing={sorted(ALLOWLIST_TOP_LEVEL - actual)} "
        f"extra={sorted(actual - ALLOWLIST_TOP_LEVEL)}"
    )


def test_no_exit_code_renamed_or_removed() -> None:
    actual_names = frozenset(ExitCode.__members__.keys())
    assert actual_names >= ALLOWLIST_EXIT_CODES
    assert not actual_names - ALLOWLIST_EXIT_CODES
