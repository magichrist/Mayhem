"""``mayhem completion SHELL`` — print a shell completion script.

This prints Click's own completion script for the requested shell, verbatim from
:meth:`click.shell_completion.ShellComplete.source`. That is deliberate:
hand-rolled wrappers are how you end up binding a function name that does not
exist (``compdef _mayhem`` instead of ``compdef _mayhem_completion``), which
parses fine under ``zsh -n`` and then silently completes nothing.

The scripts are self-contained, so you decide where they go:

    mayhem completion bash >> ~/.bashrc
    mayhem completion zsh  > "${fpath[1]}/_mayhem"
    mayhem completion fish > ~/.config/fish/completions/mayhem.fish

Completion is dynamic: the shell asks the installed ``mayhem`` for candidates,
so the list always matches the commands that build actually has.
"""

from __future__ import annotations

import click
from click.shell_completion import BashComplete, FishComplete, ShellComplete, ZshComplete

#: The executable users type. Keep in sync with ``[project.scripts]``.
PROG_NAME = "mayhem"

SUPPORTED_SHELLS: tuple[str, ...] = ("bash", "zsh", "fish")

#: ``complete_var`` Click derives from the program name: ``_<PROG>_COMPLETE``.
COMPLETE_VAR = f"_{PROG_NAME.upper()}_COMPLETE"

_COMPLETERS = {
    "bash": BashComplete,
    "zsh": ZshComplete,
    "fish": FishComplete,
}


def _app() -> click.Command:
    # Imported lazily: app -> command_registry -> completion, so a module-level
    # import here would be circular.
    from mayhem.cli.app import app

    return app


def _source(completer: ShellComplete) -> str:
    """Render the script, tolerating a host bash too old to run it.

    ``BashComplete.source`` refuses to emit when the *local* bash is < 4.4
    (macOS ships 3.2). The script itself is version-agnostic — it is the
    running bash that must be new enough — so a warning plus the script is more
    useful than a refusal.
    """
    try:
        return completer.source()
    except RuntimeError as exc:
        click.echo(f"warning: {exc}", err=True)
        return ShellComplete.source(completer)


@click.command("completion")
@click.argument(
    "shell",
    type=click.Choice(SUPPORTED_SHELLS, case_sensitive=False),
    required=False,
    default="bash",
)
def completion(shell: str) -> None:
    """Print the completion script for SHELL (bash, zsh, or fish).

    Writes to stdout only: nothing is installed, no file is touched, and
    nothing is executed.
    """
    completer = _COMPLETERS[shell.lower()](_app(), {}, PROG_NAME, COMPLETE_VAR)
    click.echo(_source(completer), nl=False)
