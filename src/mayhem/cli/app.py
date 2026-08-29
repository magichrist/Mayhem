"""Root CLI assembly and top-level error -> exit-code mapping.

The tree is registered here; every group is a :class:`PrefixGroup`, so unique
prefix resolution works at every level. ``main()`` is the single place where
mayhem exceptions become documented exit codes — handlers raise typed domain
errors and never format exit codes themselves.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import click

from mayhem.cli import style
from mayhem.cli.campaign import campaign
from mayhem.cli.config_cmd import config
from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.experiment import experiment
from mayhem.cli.lifecycle import history, janitor, plan, recover, run, status, validate
from mayhem.cli.resolver import PREFIX_HELP, CommandResolutionError, PrefixGroup
from mayhem.cli.toolkit import toolkit
from mayhem.cli.topology import topology
from mayhem.controller.planner import PlanningError
from mayhem.controller.safety import SafetyRefusedError
from mayhem.domain.errors import (
    DomainError,
    InvariantViolationError,
    SchemaValidationError,
    TargetResolutionError,
)
from mayhem.toolkit.tool_runner import ToolError

if TYPE_CHECKING:
    from collections.abc import Sequence


_STATE: dict[str, str] = {"debug": "", "engine": ""}


@click.group(
    cls=PrefixGroup,
    epilog=PREFIX_HELP,
    help="mayhem — safe-by-construction chaos experiments.",
    no_args_is_help=True,
)
@click.option("--db", default=None, help="SQLite database path [default: mayhem.db].")
@click.option("--config", "config_path", default=None, help="Path to mayhem.yaml.")
@click.option("--profile", default=None, help="Configuration profile name.")
@click.option("--allow-critical", is_flag=True, help="Acknowledge critical-risk faults.")
@click.option(
    "--skip-gate",
    is_flag=True,
    help="Run even when the impact gate proved some faults inert.",
)
@click.option(
    "--podman", "podman", is_flag=True, default=False, help="Use Podman instead of Docker."
)
@click.option("--debug", is_flag=True, help="Re-raise errors instead of rendering them.")
@click.pass_context
def app(
    ctx: click.Context,
    db: str | None,
    config_path: str | None,
    profile: str | None,
    allow_critical: bool,
    skip_gate: bool,
    podman: bool,
    debug: bool,
) -> None:
    _STATE["debug"] = "1" if debug else ""
    _STATE["engine"] = "podman" if podman else ""
    _STATE["gate"] = "0" if skip_gate else "1"
    ctx.obj = CliContext(
        db=db or "mayhem.db",
        config=config_path,
        profile=profile,
        allow_critical=allow_critical,
        debug=debug,
    )


for _cmd in (validate, plan, run, status, history, recover, janitor):
    app.add_command(_cmd)
for _group in (experiment, topology, toolkit, config, campaign):
    app.add_command(_group)
app.add_command(config, "cfg")


def _fail(message: str, code: int) -> int:
    click.echo(f"{style.danger('error:')} {message}", err=True)
    return code


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch argv and map every failure mode onto a documented exit code."""
    try:
        app.main(
            args=list(argv) if argv is not None else sys.argv[1:],
            prog_name="mayhem",
            standalone_mode=False,
            windows_expand_args=False,
        )
    except CommandResolutionError as exc:
        code = ExitCode.USAGE_ERROR if not exc.candidates else ExitCode.AMBIGUOUS_COMMAND
        return _fail(str(exc), int(code))
    except click.UsageError as exc:
        exc.show()
        return int(ExitCode.USAGE_ERROR)
    except click.exceptions.Exit as exc:
        return int(exc.exit_code)
    except click.exceptions.Abort:
        return _fail("aborted.", int(ExitCode.GENERAL_FAILURE))
    except SafetyRefusedError as exc:
        return _fail(f"safety refused: {exc}", int(ExitCode.SAFETY_REFUSAL))
    except SchemaValidationError as exc:
        code = (
            ExitCode.CONFIG_ERROR
            if getattr(exc, "subject", "") == "config"
            else ExitCode.VALIDATION_ERROR
        )
        return _fail(str(exc), int(code))
    except (
        InvariantViolationError,
        PlanningError,
        TargetResolutionError,
        FileNotFoundError,
    ) as exc:
        return _fail(str(exc), int(ExitCode.VALIDATION_ERROR))
    except ToolError as exc:
        return _fail(str(exc), int(ExitCode.TOOLKIT_ERROR))
    except DomainError as exc:
        return _fail(str(exc), int(ExitCode.GENERAL_FAILURE))
    except Exception as exc:  # last-resort boundary; see exit-code contract
        if _STATE["debug"]:
            raise
        return _fail(f"{type(exc).__name__}: {exc}", int(ExitCode.GENERAL_FAILURE))
    return int(ExitCode.SUCCESS)


if __name__ == "__main__":
    raise SystemExit(main())
