"""``mayhem completion SHELL`` — print a shell completion script.

Click already owns the completion machinery (argument parsing, prefix
resolution, option completion), so this command does not reimplement any of it:
it prints the small source script Click documents for the requested shell. The
generated file therefore cannot drift from the installed program.

    mayhem completion bash >> ~/.bashrc
    mayhem completion zsh  > "${fpath[1]}/_mayhem"
    mayhem completion fish > ~/.config/fish/completions/mayhem.fish

Requires bash >= 4.4 (macOS ships 3.2); use zsh or fish there.
"""

from __future__ import annotations

import click

#: The executable users type. Keep in sync with ``[project.scripts]``.
PROG_NAME = "mayhem"

SUPPORTED_SHELLS: tuple[str, ...] = ("bash", "zsh", "fish")

#: ``complete_var`` Click derives from the program name: ``_<PROG>_COMPLETE``.
COMPLETE_VAR = f"_{PROG_NAME.upper()}_COMPLETE"

_SCRIPTS = {
    "bash": f"""\
if [[ -z "${{{COMPLETE_VAR}:-}}" ]]; then
    eval "$({COMPLETE_VAR}=bash_source {PROG_NAME})"
fi

complete -F _{PROG_NAME} {PROG_NAME}
""",
    "zsh": f"""\
#compdef {PROG_NAME}

if [[ -z "${{{COMPLETE_VAR}:-}}" ]]; then
    eval "$({COMPLETE_VAR}=zsh_source {PROG_NAME})"
fi

compdef _{PROG_NAME} {PROG_NAME}
""",
    "fish": f"""\
if test -z "${{{COMPLETE_VAR}}}"
    set -x {COMPLETE_VAR} fish_source
    {PROG_NAME} | source
    set -e {COMPLETE_VAR}
end

complete --no-files --command {PROG_NAME}
""",
}


@click.command("completion")
@click.argument(
    "shell",
    type=click.Choice(SUPPORTED_SHELLS, case_sensitive=False),
    required=False,
    default="bash",
)
def completion(shell: str) -> None:
    """Print the completion script for SHELL (bash, zsh, or fish).

    Nothing is installed and nothing is executed: the script is written to
    stdout so you decide where it goes.
    """
    click.echo(_SCRIPTS[shell.lower()], nl=False)
