"""``mayhem completion SHELL`` — the printed script must actually complete.

These tests assert two separate things, because a script that merely *prints*
is worthless:

1. the generated script is syntactically valid for its shell (`bash -n` / `zsh -n`); and
2. the completion machinery it delegates to really resolves the live command
   tree, so `mayhem ga` completes to `game-day` and `mayhem inspect re` completes
   to `replay` and `residual`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.completion import COMPLETE_VAR, PROG_NAME, SUPPORTED_SHELLS

SHELLS = list(SUPPORTED_SHELLS)


def _script(shell: str) -> str:
    result = CliRunner().invoke(app, ["completion", shell])
    assert result.exit_code == 0, result.output
    return result.output


# ── the command surface ──────────────────────────────────────────────────────
def test_completion_is_a_registered_root_command() -> None:
    from mayhem.cli.command_registry import COMMAND_SPECS

    assert "completion" in {spec.name for spec in COMMAND_SPECS}
    assert "completion" in app.commands


def test_completion_appears_in_root_help() -> None:
    out = CliRunner().invoke(app, ["--help"]).output
    assert "completion" in out


@pytest.mark.parametrize("shell", SHELLS)
def test_each_supported_shell_prints_a_script(shell: str) -> None:
    body = _script(shell)
    assert body.strip()
    assert PROG_NAME in body
    assert COMPLETE_VAR in body


def test_shell_argument_is_optional() -> None:
    """`mayhem completion` with no argument defaults to bash."""
    assert _script("bash") == CliRunner().invoke(app, ["completion"]).output


@pytest.mark.parametrize("shell", ["tcsh", "powershell", "nushell"])
def test_unsupported_shell_is_rejected(shell: str) -> None:
    result = CliRunner().invoke(app, ["completion", shell])
    assert result.exit_code == 2


def test_shell_choice_is_case_insensitive() -> None:
    assert _script("BASH") == _script("bash")


# ── the scripts are syntactically valid ──────────────────────────────────────
@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_generated_script_parses_in_its_shell(shell: str, tmp_path) -> None:
    binary = shutil.which(shell)
    if binary is None:  # pragma: no cover - depends on the host
        pytest.skip(f"{shell} is not installed")
    path = tmp_path / ("mayhem.bash" if shell == "bash" else "_mayhem")
    path.write_text(_script(shell))
    result = subprocess.run([binary, "-n", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_scripts_are_free_of_prose() -> None:
    """The printed script is something you source, not something you read."""
    for shell in SHELLS:
        for line in _script(shell).splitlines():
            assert not line.startswith("#") or line.startswith("#compdef "), (shell, line)


def test_zsh_keeps_its_compdef_directive() -> None:
    """`#compdef` is how zsh binds the file to the command; it is not commentary."""
    assert _script("zsh").splitlines()[0] == "#compdef mayhem"


def test_bash_44_requirement_is_documented() -> None:
    """macOS ships bash 3.2, where this cannot work; the docs must say so."""
    from mayhem.cli import completion as module

    readme = (Path(__file__).resolve().parents[2] / "README.md").read_text()
    assert "4.4" in readme
    assert "4.4" in (module.__doc__ or "")


# ── the scripts actually complete ────────────────────────────────────────────
#: The env var each shell sets to ask Click for candidates, not source code.
COMPLETION_MODE = {"bash": "bash_complete", "zsh": "zsh_complete"}


def _complete(shell: str, words: list[str]) -> list[str]:
    """Run the completion protocol the shell itself runs, and read candidates."""
    line = " ".join(words)
    env = {
        **os.environ,
        "_MAYHEM_COMPLETE": COMPLETION_MODE[shell],
        "COMP_WORDS": line,
        "COMP_CWORD": str(len(words) - 1),
        "COMP_LINE": line,
        "COMP_POINT": str(len(line)),
    }
    result = subprocess.run([PROG_NAME], capture_output=True, text=True, env=env, check=False)
    return [row for row in result.stdout.splitlines() if row.strip()]


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_root_prefix_completes_to_a_real_command(shell: str) -> None:
    if shutil.which(shell) is None:  # pragma: no cover - depends on the host
        pytest.skip(f"{shell} is not installed")
    candidates = _complete(shell, [PROG_NAME, "ga"])
    assert any("game-day" in candidate for candidate in candidates), candidates


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_subcommand_prefix_completes_inside_a_group(shell: str) -> None:
    if shutil.which(shell) is None:  # pragma: no cover - depends on the host
        pytest.skip(f"{shell} is not installed")
    candidates = _complete(shell, [PROG_NAME, "inspect", "re"])
    assert any("replay" in candidate for candidate in candidates), candidates
    assert any("residual" in candidate for candidate in candidates), candidates


def test_completion_offers_the_v090_command_groups() -> None:
    if shutil.which("bash") is None:  # pragma: no cover - depends on the host
        pytest.skip("bash is not installed")
    candidates = " ".join(_complete("bash", [PROG_NAME, ""]))
    for group in ("game-day", "bundle", "campaign", "inspect", "run"):
        assert group in candidates


def test_completion_never_suggests_a_removed_command() -> None:
    if shutil.which("bash") is None:  # pragma: no cover - depends on the host
        pytest.skip("bash is not installed")
    candidates = " ".join(_complete("bash", [PROG_NAME, ""]))
    for removed in ("topology", "toolkit", "coverage", "expert"):
        assert removed not in candidates
