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

COMMAND_PATHS = (
    ("prepare", "plan"),
    ("prepare", "validate"),
    ("run",),
    ("experiment",),
    ("inspect", "coverage"),
    ("inspect", "next"),
    ("experiment", "explore"),
    ("recover",),
)


@pytest.mark.parametrize("command_path", COMMAND_PATHS)
def test_documented_commands_parse_help(command_path: tuple[str, ...]) -> None:
    assert main([*command_path, "--help"]) == 0


@pytest.mark.parametrize("flag", ("--json", "--quiet", "--no-color"))
def test_contract_flags_are_accepted(flag: str) -> None:
    for command_path in (("inspect", "coverage"), ("inspect", "next")):
        assert main([*command_path, "--help"]) == 0
        assert main([*command_path, flag, "--compose", str(COMPOSE_FILE)]) in (0, 4)


def test_quiet_json_emits_only_valid_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(TESTCASE)
    code = main(["inspect", "coverage", "--quiet", "--json", "--compose", str(COMPOSE_FILE)])
    emitted = capsys.readouterr().out
    assert code == 0
    payload = json.loads(emitted)
    assert "cells" in payload or "summary" in payload


def test_no_color_emits_no_ansi(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(TESTCASE)
    code = main(["inspect", "coverage", "--no-color", "--compose", str(COMPOSE_FILE)])
    emitted = capsys.readouterr().out
    assert code == 0
    assert not _ANSI_RE.search(emitted)


def test_help_output_is_nonempty(capsys: pytest.CaptureFixture[str]) -> None:
    for command_path in COMMAND_PATHS:
        main([*command_path, "--help"])
        assert capsys.readouterr().out.strip(), f"{' '.join(command_path)} printed nothing"


def test_state_values_from_cellstate_enum() -> None:
    valid = {state.value for state in CellState}
    assert valid == {
        "unknown",
        "planned",
        "executed",
        "passed",
        "inconclusive",
        "failed",
        "blocked",
        "skipped",
    }


def test_fault_and_fault_category_mutually_exclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(TESTCASE)
    code = main(
        [
            "inspect",
            "coverage",
            "--fault",
            "net.delay",
            "--fault-category",
            "network",
            "--compose",
            str(COMPOSE_FILE),
        ]
    )
    assert code == 2


def test_group_db_flag_reaches_new_commands(tmp_path: Path) -> None:
    db = tmp_path / "test.db"
    for command_path in (("inspect", "next"), ("inspect", "coverage")):
        code = main(
            [
                "--db",
                str(db),
                *command_path,
                "--quiet",
                "--json",
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert code in (0, 4)
