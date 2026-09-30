from __future__ import annotations

import json

import click

from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.infra.diagnostics import (
    DiagnosticCategory,
    DiagnosticRecord,
    DiagnosticSeverity,
    run_diagnostics,
)


def _render_human(records: list[DiagnosticRecord]) -> None:
    for rec in records:
        prefix = rec.severity.value.upper()
        line = f"[{prefix}] {rec.category.value}/{rec.id}: {rec.message}"
        if rec.severity in (DiagnosticSeverity.error, DiagnosticSeverity.warning):
            click.echo(line)
            if rec.remediation:
                click.echo(f"  remediation: {rec.remediation}")
        else:
            click.echo(line)
    errs = sum(1 for r in records if r.severity == DiagnosticSeverity.error)
    warns = sum(1 for r in records if r.severity == DiagnosticSeverity.warning)
    click.echo(f"doctor: {errs} error(s), {warns} warning(s), {len(records)} total")


@click.command("doctor")
@click.option("--json", "as_json", is_flag=True, help="Emit diagnostics as JSON.")
@click.option("--quiet", is_flag=True, help="Suppress output; exit code signals errors.")
@click.option(
    "--category",
    "category",
    type=click.Choice([c.value for c in DiagnosticCategory]),
    default=None,
    help="Filter to one category.",
)
@click.pass_context
def doctor_cmd(
    ctx: click.Context,
    as_json: bool,
    quiet: bool,
    category: str | None,
) -> None:
    obj = ctx.obj
    assert isinstance(obj, CliContext)
    compose = None
    try:
        from mayhem.cli.topology import _resolve_compose

        compose = _resolve_compose(None)
    except Exception:
        compose = None
    records = run_diagnostics(
        config_path=obj.config,
        profile=obj.profile,
        policy=obj.policy,
        target=obj.target,
        db_path=obj.db,
        compose_path=compose,
        spec_path=obj.config,
    )
    if category is not None:
        records = [r for r in records if r.category.value == category]
    if as_json:
        from mayhem.cli.app import _STATE
        from mayhem.controller.catalog_report import build_capability_report

        payload = {
            "diagnostics": [r.model_dump(mode="json") for r in records],
            "summary": {
                "total": len(records),
                "errors": sum(1 for r in records if r.severity == DiagnosticSeverity.error),
                "warnings": sum(1 for r in records if r.severity == DiagnosticSeverity.warning),
                "infos": sum(1 for r in records if r.severity == DiagnosticSeverity.info),
            },
            "capabilities": build_capability_report(engine=_STATE.get("engine") or None),
        }
        click.echo(json.dumps(payload, indent=2))
    elif not quiet:
        _render_human(records)
    has_error = any(r.severity == DiagnosticSeverity.error for r in records)
    if has_error:
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
