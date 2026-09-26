from __future__ import annotations

import os
import sys
import traceback
from typing import TYPE_CHECKING

import click

from mayhem.cli import style
from mayhem.cli.command_registry import register_commands
from mayhem.cli.context import CliContext
from mayhem.cli.errors import MayhemCliError, map_exception_to_error
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import PREFIX_HELP, CommandResolutionError, PrefixGroup
from mayhem.controller.planner import PlanningError
from mayhem.controller.safety import SafetyRefusedError
from mayhem.domain.errors import (
    DomainError,
    InvariantViolationError,
    SchemaValidationError,
    TargetDriftError,
    TargetResolutionError,
)
from mayhem.domain.execution_intent import IMPLICIT_EXECUTION_ENV
from mayhem.domain.maniac import ManiacError
from mayhem.toolkit.tool_runner import ToolError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


def mayhem_version() -> str:
    """Installed version, or a source-checkout marker when not installed.

    ``mayhem --version`` must work from a wheel *and* from a plain source
    checkout, so a missing distribution is reported rather than raised.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("mayhem-cli")
    except PackageNotFoundError:
        return "0.0.0+source"


def _print_version(ctx: click.Context, _param: object, value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"mayhem {mayhem_version()}")
    ctx.exit(0)


_STATE: dict[str, str] = {
    "debug": "",
    "engine": "",
    "target": "",
    "gate": "1",
    "format": "text",
    "no_color": "",
}


@click.group(
    cls=PrefixGroup,
    epilog=PREFIX_HELP,
    help="mayhem — safe-by-construction chaos experiments.",
    no_args_is_help=True,
)
@click.option(
    "--version",
    "show_version",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_print_version,
    help="Show the installed Mayhem version and exit.",
)
@click.option("--db", default=None, help="SQLite database path [default: mayhem.db].")
@click.option("--config", "config_path", default=None, help="Path to mayhem.yaml.")
@click.option("--profile", default=None, help="Configuration profile name.")
@click.option("--policy", default=None, help="Named policy profile (strict, permissive, etc.).")
@click.option("--dry-run", is_flag=True, help="Evaluate policy without mutating.")
@click.option("--allow-critical", is_flag=True, help="Acknowledge critical-risk faults.")
@click.option(
    "--skip-gate",
    is_flag=True,
    help="Run even when the impact gate proved some faults inert.",
)
@click.option(
    "-p",
    "--podman",
    "podman",
    is_flag=True,
    default=False,
    help="Use Podman instead of Docker.",
)
@click.option(
    "-k",
    "--kubernetes",
    "kubernetes",
    is_flag=True,
    default=False,
    help="Use Kubernetes instead of Docker/Podman (kubeconfig-driven discovery).",
)
@click.option("-d", "--debug", is_flag=True, help="Re-raise errors instead of rendering them.")
@click.option("--target", default=None, help="Target profile name.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "yaml"], case_sensitive=False),
    default=None,
    help="Output format: text (default), json, or yaml. Preserves --json compatibility.",
)
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output.")
@click.pass_context
def app(
    ctx: click.Context,
    db: str | None,
    config_path: str | None,
    profile: str | None,
    policy: str | None,
    dry_run: bool,
    allow_critical: bool,
    skip_gate: bool,
    podman: bool,
    kubernetes: bool,
    debug: bool,
    target: str | None,
    output_format: str | None,
    no_color: bool,
) -> None:
    if podman and kubernetes:
        raise click.UsageError("--podman and --kubernetes are mutually exclusive")
    _STATE["debug"] = "1" if debug else ""
    _STATE["engine"] = "podman" if podman else ("kubernetes" if kubernetes else "")
    _STATE["gate"] = "0" if skip_gate else "1"
    _STATE["target"] = target or ""
    _STATE["policy"] = policy or ""
    _STATE["dry_run"] = "1" if dry_run else ""
    _STATE["format"] = output_format.lower() if output_format else "text"
    _STATE["no_color"] = "1" if no_color else ""
    if no_color:
        os.environ["NO_COLOR"] = "1"
    ctx.obj = CliContext(
        db=db or "mayhem.db",
        config=config_path,
        profile=profile,
        policy=policy,
        allow_critical=allow_critical,
        debug=debug,
        target=target,
        dry_run=dry_run,
    )


register_commands(app)


def _fail(message: str, code: int) -> int:
    click.echo(f"{style.danger('error:')} {message}", err=True)
    return code


def implicit_execution_allowed(environ: Mapping[str, str] | None = None) -> bool:
    """True when the documented ``MAYHEM_ALLOW_IMPLICIT_EXECUTION=1`` is set.

    This is the *only* place the environment is consulted for the
    execution-intent contract. The domain layer
    (:mod:`mayhem.domain.execution_intent`) stays pure and receives the answer
    as ``allow_implicit``; the application layer — this module — reads the
    switch and passes it down, so every mutating surface sees one policy and a
    domain test can never depend on the ambient environment.
    """
    env = os.environ if environ is None else environ
    return str(env.get(IMPLICIT_EXECUTION_ENV, "")).strip() == "1"


def _is_refusal(code: str) -> bool:
    """True for codes that read as a gate refusing an act, not a bad input.

    ``safety_refusal`` and the three v0.9.0 execution-intent codes all mean
    "mayhem understood the request and declined to act"; they are rendered
    with the same framing so scripts grepping for one see the other.
    """
    return code in {
        "safety_refusal",
        "execution_intent_required",
        "approval_expired",
        "execution_intent_mismatch",
    }


def _fail_error(err: MayhemCliError) -> int:
    debug = bool(_STATE.get("debug"))
    fmt = _STATE.get("format", "text")
    as_json = fmt == "json"
    if as_json:
        click.echo(err.to_json(), err=True)
    else:
        if _is_refusal(err.code):
            click.echo(
                f"{style.danger('error:')} safety refused: {err.message} [{err.code}]", err=True
            )
        else:
            click.echo(f"{style.danger('error:')} [{err.code}] {err.message}", err=True)
        if err.remediation:
            click.echo(f"  remediation: {err.remediation}", err=True)
        if err.details:
            for k in sorted(err.details.keys()):
                click.echo(f"  {k}: {err.details[k]}", err=True)
        if err.evidence_ref:
            click.echo(f"  evidence_ref: {err.evidence_ref}", err=True)
    if debug:
        tb = traceback.format_exc()
        if tb and "NoneType: None" not in tb:
            click.echo(tb.strip(), err=True)
    return int(err.exit_code)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    rv: int | None = None
    try:
        rv = app.main(
            args=args,
            prog_name="mayhem",
            standalone_mode=False,
            windows_expand_args=False,
        )
    except MayhemCliError as exc:
        return _fail_error(exc)
    except CommandResolutionError as exc:
        err = map_exception_to_error(exc)
        return _fail_error(err)
    except click.UsageError as exc:
        mapped = map_exception_to_error(exc)
        if _STATE.get("format") == "json":
            click.echo(mapped.to_json(), err=True)
            if _STATE.get("debug"):
                tb = traceback.format_exc()
                if tb and "NoneType: None" not in tb:
                    click.echo(tb.strip(), err=True)
            return int(mapped.exit_code)
        exc.show()
        if _STATE.get("debug"):
            tb = traceback.format_exc()
            if tb and "NoneType: None" not in tb:
                click.echo(tb.strip(), err=True)
        return int(ExitCode.USAGE_ERROR)
    except click.exceptions.Exit as exc:
        return int(exc.exit_code)
    except click.exceptions.Abort:
        return _fail("aborted.", int(ExitCode.GENERAL_FAILURE))
    except SafetyRefusedError as exc:
        err = map_exception_to_error(exc)
        return _fail_error(err)
    except SchemaValidationError as exc:
        err = map_exception_to_error(exc)
        return _fail_error(err)
    except (
        InvariantViolationError,
        ManiacError,
        PlanningError,
        TargetResolutionError,
        TargetDriftError,
        FileNotFoundError,
    ) as exc:
        err = map_exception_to_error(exc)
        return _fail_error(err)
    except ToolError as exc:
        err = map_exception_to_error(exc)
        return _fail_error(err)
    except DomainError as exc:
        err = map_exception_to_error(exc)
        return _fail_error(err)
    except Exception as exc:
        if _STATE.get("debug"):
            raise
        err = map_exception_to_error(exc)
        return _fail_error(err)
    return int(ExitCode.SUCCESS) if rv is None else int(rv)


if __name__ == "__main__":
    raise SystemExit(main())
