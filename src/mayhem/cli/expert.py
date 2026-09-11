"""``mayhem expert`` — diagnostic expert system command.

Runs config probes, analyzes failed runs, and suggests next actions.

Shape::

    mayhem expert [--compose PATH] [--run RUN_ID] [--json] [--quiet] [--no-color]
                  [--db PATH] [--profile NAME]
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import click

from mayhem.cli import style
from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.services import build_graph, open_store


def _compose_option[F: Callable[..., object]](fn: F) -> F:
    return click.option(
        "-c",
        "--compose",
        type=str,
        default=None,
        help="docker-compose.yaml blueprint (auto-detected in cwd if omitted).",
    )(fn)


def _graph_from(ctx: click.Context, compose: str | None) -> tuple:
    from mayhem.cli.topology import _resolve_compose

    resolved = _resolve_compose(compose)
    try:
        return build_graph(resolved), resolved
    except ValueError as exc:
        raise click.UsageError(str(exc), ctx=ctx) from None


def _probe_compose(compose_path: str | None) -> dict[str, Any]:
    """Probe docker-compose file validity."""
    from pathlib import Path

    result: dict[str, Any] = {"status": "ok", "checks": []}

    if compose_path:
        path = Path(compose_path)
        if not path.exists():
            result["status"] = "error"
            result["checks"].append(
                {
                    "name": "compose_file_exists",
                    "status": "error",
                    "detail": f"file not found: {compose_path}",
                }
            )
            return result
        try:
            import yaml

            with open(path) as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                result["status"] = "error"
                result["checks"].append(
                    {
                        "name": "compose_file_valid",
                        "status": "error",
                        "detail": "not a valid YAML mapping",
                    }
                )
                return result
            result["checks"].append(
                {
                    "name": "compose_file_valid",
                    "status": "ok",
                    "detail": f"parsed successfully, {len(data.get('services', {}))} services",
                }
            )
        except Exception as exc:
            result["status"] = "error"
            result["checks"].append(
                {
                    "name": "compose_file_valid",
                    "status": "error",
                    "detail": str(exc),
                }
            )
    else:
        result["checks"].append(
            {
                "name": "compose_file_provided",
                "status": "warning",
                "detail": "no compose file specified, using auto-detection",
            }
        )

    return result


def _probe_config(config_path: str | None, profile: str | None) -> dict[str, Any]:
    """Probe mayhem.yaml configuration validity."""
    result: dict[str, Any] = {"status": "ok", "checks": []}

    if config_path:
        from pathlib import Path

        path = Path(config_path)
        if not path.exists():
            result["status"] = "error"
            result["checks"].append(
                {
                    "name": "config_file_exists",
                    "status": "error",
                    "detail": f"file not found: {config_path}",
                }
            )
            return result
        try:
            import warnings as _warnings

            from mayhem.config import SpecFileUsedAsConfig, load_config

            with _warnings.catch_warnings(record=True) as caught:
                _warnings.simplefilter("always")
                _cfg, sources = load_config(config_path=config_path, profile=profile)
            spec_warning = next(
                (w for w in caught if issubclass(w.category, SpecFileUsedAsConfig)), None
            )
            if spec_warning is not None:
                result["status"] = "warning"
                result["checks"].append(
                    {
                        "name": "config_valid",
                        "status": "warning",
                        "detail": str(spec_warning.message),
                    }
                )
            elif any(source == "file(spec)" for source in sources.values()):
                result["checks"].append(
                    {
                        "name": "config_valid",
                        "status": "ok",
                        "detail": (
                            "configuration loaded from the drill spec's embedded "
                            "`config:` section (mayhem.yaml doubles as the config file)"
                        ),
                    }
                )
            else:
                result["checks"].append(
                    {
                        "name": "config_valid",
                        "status": "ok",
                        "detail": "configuration loaded and validated successfully",
                    }
                )
        except Exception as exc:
            result["status"] = "error"
            result["checks"].append(
                {
                    "name": "config_valid",
                    "status": "error",
                    "detail": str(exc),
                }
            )
    else:
        result["checks"].append(
            {
                "name": "config_provided",
                "status": "warning",
                "detail": "no config file specified, using defaults",
            }
        )

    return result


def _probe_docker() -> dict[str, Any]:
    """Probe Docker/Podman availability."""
    import shutil
    import subprocess

    result: dict[str, Any] = {"status": "ok", "checks": []}

    for cmd in ("docker", "podman"):
        path = shutil.which(cmd)
        if path:
            try:
                proc = subprocess.run(
                    [cmd, "info", "--format", "{{.ServerVersion}}"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode == 0:
                    version = proc.stdout.strip()
                    result["checks"].append(
                        {
                            "name": f"{cmd}_available",
                            "status": "ok",
                            "detail": f"{cmd} {version} available at {path}",
                        }
                    )
                else:
                    result["checks"].append(
                        {
                            "name": f"{cmd}_available",
                            "status": "warning",
                            "detail": f"{cmd} found but not running: {proc.stderr.strip()[:100]}",
                        }
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                result["checks"].append(
                    {
                        "name": f"{cmd}_available",
                        "status": "warning",
                        "detail": f"{cmd} found but unresponsive",
                    }
                )
        else:
            result["checks"].append(
                {
                    "name": f"{cmd}_available",
                    "status": "info",
                    "detail": f"{cmd} not found in PATH",
                }
            )

    if not any(c["status"] == "ok" for c in result["checks"]):
        result["status"] = "error"

    return result


def _analyze_recent_failures(
    db: str,
    limit: int = 5,
) -> dict[str, Any]:
    """Analyze recent failed runs for root-cause patterns."""
    result: dict[str, Any] = {"status": "ok", "checks": [], "failures": []}

    store = open_store(db)
    try:
        rows = store.query(
            "SELECT id, experiment_name, status, verdict, started_at, ended_at "
            "FROM m5_runs WHERE status IN ('failed', 'aborted') "
            "ORDER BY ended_at DESC LIMIT ?",
            (limit,),
        )

        if not rows:
            result["checks"].append(
                {
                    "name": "recent_failures",
                    "status": "ok",
                    "detail": "no recent failures found",
                }
            )
            return result

        result["checks"].append(
            {
                "name": "recent_failures",
                "status": "warning",
                "detail": f"found {len(rows)} recent failures",
            }
        )

        for row in rows:
            failure_info: dict[str, Any] = {
                "run_id": row["id"],
                "experiment": row["experiment_name"],
                "status": row["status"],
                "verdict": row["verdict"],
            }

            # Analyze coverage for this run
            coverage_rows = store.query(
                "SELECT target, fault_kind, state FROM m5_coverage "
                "WHERE run_id = ? AND state IN ('failed', 'inconclusive')",
                (row["id"],),
            )
            if coverage_rows:
                failure_info["failed_cells"] = [
                    {
                        "target": cr["target"],
                        "fault_kind": cr["fault_kind"],
                        "state": cr["state"],
                    }
                    for cr in coverage_rows
                ]

            result["failures"].append(failure_info)

    finally:
        store.close()

    return result


def _render_expert_json(
    compose_probe: dict[str, Any],
    config_probe: dict[str, Any],
    docker_probe: dict[str, Any],
    failures: dict[str, Any],
) -> str:
    """Render expert output as JSON."""
    return json.dumps(
        {
            "probes": {
                "compose": compose_probe,
                "config": config_probe,
                "docker": docker_probe,
            },
            "analysis": failures,
        },
        indent=2,
    )


def _render_expert_human(
    compose_probe: dict[str, Any],
    config_probe: dict[str, Any],
    docker_probe: dict[str, Any],
    failures: dict[str, Any],
) -> str:
    """Render expert output as human-readable text."""
    lines = ["# Expert Diagnosis", ""]

    # Probes section
    lines.append("## Configuration Probes")
    for name, probe in [
        ("Compose", compose_probe),
        ("Config", config_probe),
        ("Docker", docker_probe),
    ]:
        status_char = (
            style.ok("✓")
            if probe["status"] == "ok"
            else style.warn("⚠")
            if probe["status"] == "warning"
            else style.danger("✗")
        )
        lines.append(f"\n### {name} [{status_char}]")
        for check in probe.get("checks", []):
            check_status = (
                style.ok("ok")
                if check["status"] == "ok"
                else style.warn("warn")
                if check["status"] == "warning"
                else style.danger("error")
                if check["status"] == "error"
                else style.info("info")
            )
            lines.append(f"  - [{check_status}] {check['name']}: {check['detail']}")

    # Failures section
    if failures.get("failures"):
        lines.append("\n## Recent Failures")
        for failure in failures["failures"]:
            lines.append(f"\n### Run {failure['run_id']}")
            lines.append(f"  - experiment: {failure['experiment']}")
            lines.append(f"  - status: {failure['status']}")
            lines.append(f"  - verdict: {failure['verdict']}")
            if failure.get("failed_cells"):
                lines.append("  - failed cells:")
                for cell in failure["failed_cells"]:
                    lines.append(f"    - {cell['target']}/{cell['fault_kind']} ({cell['state']})")

    # Recommendations
    lines.append("\n## Recommendations")
    has_errors = any(p["status"] == "error" for p in [compose_probe, config_probe, docker_probe])
    has_warnings = any(
        p["status"] == "warning" for p in [compose_probe, config_probe, docker_probe]
    )

    if has_errors:
        lines.append(f"  - {style.danger('Fix the errors above before running experiments')}")
    if has_warnings:
        lines.append(f"  - {style.warn('Review warnings — some checks did not pass')}")
    if failures.get("failures"):
        lines.append(
            f"  - {style.info('Consider running `mayhem next` to find the best next cell')}"
        )
    if not has_errors and not has_warnings and not failures.get("failures"):
        lines.append(f"  - {style.ok('All checks passed — ready to run experiments')}")

    return "\n".join(lines)


@click.command("expert")
@_compose_option
@click.option("--run", "run_id", default=None, help="Analyze a specific run ID.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress human output.")
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output.")
@click.pass_context
def expert_cmd(
    ctx: click.Context,
    compose: str | None,
    run_id: str | None,
    as_json: bool,
    quiet: bool,
    no_color: bool,
) -> None:
    """Run diagnostic probes and analyze recent failures.

    Checks compose file validity, configuration, Docker availability,
    and analyzes recent failed runs to suggest next actions.
    """
    ctx_obj: CliContext = ctx.obj

    if no_color:
        import os

        os.environ["NO_COLOR"] = "1"

    # Run probes
    compose_probe = _probe_compose(compose)
    config_probe = _probe_config(ctx_obj.config, ctx_obj.profile)
    docker_probe = _probe_docker()

    # Analyze failures
    if run_id:
        failures: dict[str, Any] = {"status": "ok", "checks": [], "failures": []}
        store = open_store(ctx_obj.db)
        try:
            row = store.query(
                "SELECT id, experiment_name, status, verdict FROM m5_runs WHERE id = ?",
                (run_id,),
            )
            if row:
                failures["failures"] = [
                    {
                        "run_id": row[0]["id"],
                        "experiment": row[0]["experiment_name"],
                        "status": row[0]["status"],
                        "verdict": row[0]["verdict"],
                    }
                ]
            else:
                failures["checks"].append(
                    {
                        "name": "run_exists",
                        "status": "error",
                        "detail": f"run not found: {run_id}",
                    }
                )
                compose_probe["status"] = "error"
        finally:
            store.close()
    else:
        failures = _analyze_recent_failures(ctx_obj.db)

    if as_json:
        click.echo(_render_expert_json(compose_probe, config_probe, docker_probe, failures))
    elif not quiet:
        click.echo(_render_expert_human(compose_probe, config_probe, docker_probe, failures))

    # Exit with error if any probe failed
    overall_status = "ok"
    for probe in [compose_probe, config_probe, docker_probe, failures]:
        if probe.get("status") == "error":
            overall_status = "error"
            break
    if overall_status == "error":
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
