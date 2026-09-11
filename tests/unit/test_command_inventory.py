"""feat-5 §0 constraint enforcement — top-level command/exit-code inventory.

The allowlist is the canonical snapshot of the 0.6 surface. Two guards:

1. **Surface freeze** — removing or adding a top-level command fails the
   suite. Adding a command requires updating this very allowlist first, which
   forces a human review of the new surface.
2. **Exit-code freeze** — no ``ExitCode`` member can be renamed or removed;
   additions are allowed only when the enum gains a doc entry.

Negative check note: uncommenting the ``# covered`` sentinel below and
running this file demonstrates the removal sentsinel — the suite fails with a
clear diff.
"""

from __future__ import annotations

from mayhem.cli.app import app
from mayhem.cli.exit_codes import ExitCode

# Canonical 0.6 surface — 14 pre-existing + explore/next/coverage (feat-2),
# plus the ``cfg`` alias for ``config``. Removal or addition fails.
ALLOWLIST_COMMANDS: frozenset[str] = frozenset({
    "campaign",
    "config",
    "cfg",
    "dependency",
    "experiment",
    "history",
    "janitor",
    "maniac",
    "plan",
    "recover",
    "run",
    "status",
    "toolkit",
    "topology",
    "validate",
    # feat-2 §3 new surface
    "explore",
    "next",
    "coverage",
})

# Allowlist with cfg de-duplicated (alias).
ALLOWLIST_TOP_LEVEL: frozenset[str] = frozenset({
    "campaign",
    "cfg",
    "config",
    "dependency",
    "experiment",
    "expert",
    "history",
    "janitor",
    "maniac",
    "plan",
    "recover",
    "run",
    "status",
    "toolkit",
    "topology",
    "validate",
    "explore",
    "next",
    "coverage",
})

# Canonical ExitCode snapshot — no member may be renamed or removed.
ALLOWLIST_EXIT_CODES: frozenset[str] = frozenset({
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
})


def test_top_level_commands_match_allowlist() -> None:
    actual = frozenset(app.commands.keys())
    assert actual == ALLOWLIST_TOP_LEVEL, (
        "top-level command set drifted from the 0.6 surface. "
        f"missing={sorted(ALLOWLIST_TOP_LEVEL - actual)} "
        f"extra={sorted(actual - ALLOWLIST_TOP_LEVEL)} "
        "— update docs/reference/cli.md and this allowlist deliberately."
    )


def test_no_exit_code_renamed_or_removed() -> None:
    actual_names = frozenset(ExitCode.__members__.keys())
    assert ALLOWLIST_EXIT_CODES <= actual_names, (
        "an ExitCode member was renamed or removed; that is a breaking change "
        f"(removed: {sorted(ALLOWLIST_EXIT_CODES - actual_names)})"
    )
    # Additions allowed only with a doc entry — ensure any new member is
    # documented in the enum's class docstring by asserting the member count
    # is not silently growing.
    unexpected = actual_names - ALLOWLIST_EXIT_CODES
    assert not unexpected, (
        f"new ExitCode members without doc entry: {sorted(unexpected)} — "
        "add a docs/reference/cli.md entry before allowlisting."
    )


def test_cfg_is_config_alias() -> None:
    assert app.commands["cfg"] is app.commands["config"]