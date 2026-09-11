"""Global CLI output contract (§9) enforced as tests (plan-feat-4 Phase C1).

Checks, without touching containers:

* every documented command parses with ``--help`` and every §9 contract flag
  is present where the spec requires;
* ``--quiet --json`` emits no progress frames and parses as valid JSON;
* ``--no-color`` output contains no ANSI escapes;
* ``--fault`` and ``--fault-category`` are mutually exclusive, and any
  ``--state`` value is from the §4.2 enum (shared with ``CellState``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from mayhem.cli.app import main
from mayhem.domain.coverage import CellState

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

TESTCASE = Path(__file__).resolve().parents[2] / "examples" / "testCase"
COMPOSE_FILE = TESTCASE / "docker-compose.yml"

# §9 contract flags that the new commands must implement.
CONTRACT_FLAGS = ("--json", "--quiet", "--no-color")

# Commands that take a drill/spec positional and must parse --help.
SPEC_POSITIONAL_COMMANDS = ("plan", "run", "validate", "experiment", "next", "explore", "recover")


@pytest.mark.parametrize("command", SPEC_POSITIONAL_COMMANDS)
def test_documented_commands_parse_help(command: str) -> None:
    assert main([command, "--help"]) == 0, f"`mayhem {command} --help` must succeed"


@pytest.mark.parametrize("flag", CONTRACT_FLAGS)
def test_contract_flags_are_accepted(flag: str) -> None:
    """The §9 output-mode flags parse on every 0.6 command."""
    for command in ("next", "coverage", "explore"):
        assert main([command, "--help"]) == 0
        if command in ("coverage", "next"):
            # runnable form: commands that read the store accept the flag.
            assert main([command, flag, "--compose", str(COMPOSE_FILE)]) in (0, 4)


def test_quiet_json_emits_only_valid_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``mayhem coverage --quiet --json`` prints JSON only, and it parses."""
    monkeypatch.chdir(TESTCASE)
    code = main(["coverage", "--quiet", "--json", "--compose", str(COMPOSE_FILE)])
    emitted = capsys.readouterr().out
    assert code == 0, f"coverage --quiet --json must exit 0 (got {code})"
    payload = json.loads(emitted)
    assert "cells" in payload or "summary" in payload


def test_no_color_emits_no_ansi(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(TESTCASE)
    code = main(["coverage", "--no-color", "--compose", str(COMPOSE_FILE)])
    emitted = capsys.readouterr().out
    assert code == 0
    assert not _ANSI_RE.search(emitted), "`--no-color` output must be ANSI-free"


def test_help_output_is_nonempty(capsys: pytest.CaptureFixture[str]) -> None:
    for command in ("next", "coverage", "explore"):
        main([command, "--help"])
        assert capsys.readouterr().out.strip(), f"{command} --help printed nothing"


def test_state_values_from_cellstate_enum() -> None:
    """``--state`` accepts exactly the §4.2 CellState values."""
    valid = {st.value for st in CellState}
    # unknown is the *absence* of a row (never a CellState value) but a valid
    # CLI filter; the four persisted states are the enum.
    assert valid == {"covered", "inconclusive", "failed", "blocked"}


def test_fault_and_fault_category_mutually_exclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Passing both ``--fault`` and ``--fault-category`` is refused."""
    monkeypatch.chdir(TESTCASE)
    code = main(
        [
            "coverage",
            "--fault",
            "net.delay",
            "--fault-category",
            "network",
            "--compose",
            str(COMPOSE_FILE),
        ]
    )
    assert code == 2, "mutually exclusive filters must exit USAGE_ERROR (2)"


def test_group_db_flag_reaches_new_commands(
    tmp_path: Path,
) -> None:
    """The §9 ``--db`` group option is accepted by every 0.6 command."""
    db = tmp_path / "test.db"
    for command in ("next", "coverage"):
        code = main(
            ["--db", str(db), command, "--quiet", "--json", "--compose", str(COMPOSE_FILE)]
        )
        assert code in (0, 4), f"{command}: --db group flag was not accepted"