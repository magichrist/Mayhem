from __future__ import annotations

import copy
import json
from pathlib import Path

import click

from mayhem.cli.context import CliContext
from mayhem.cli.coverage_cmd import coverage_cmd
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.expert import expert_cmd
from mayhem.cli.lifecycle import history, status
from mayhem.cli.next_cmd import next_cmd
from mayhem.cli.services import open_store, run_detail, run_journal
from mayhem.infra.diagnostics import (
    DiagnosticSeverity,
    lease_projection,
    run_diagnostics,
    structured_diagnostics,
    to_json_diagnostics,
)
from mayhem.infra.evidence import load_evidence
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.report import (
    ReportArtifactPolicy,
    compare_reports,
    render_report_html,
    render_report_json,
    render_report_markdown,
    report_id_for_run,
    write_report_artifacts,
)


def _clone(command: click.Command, name: str) -> click.Command:
    cloned = copy.copy(command)
    cloned.name = name
    return cloned


@click.group("inspect", help="Inspect runs, coverage, leases, reports, and diagnostics.")
def inspect() -> None:
    pass


@inspect.command("doctor")
@click.option("--json", "as_json", is_flag=True, help="Emit structured diagnostics as JSON.")
@click.option("--quiet", is_flag=True, help="Suppress output; exit code signals errors.")
@click.pass_context
def inspect_doctor(ctx: click.Context, as_json: bool, quiet: bool) -> None:
    obj = ctx.obj
    assert isinstance(obj, CliContext)
    records = run_diagnostics(
        config_path=obj.config,
        profile=obj.profile,
        policy=obj.policy,
        target=obj.target,
        db_path=obj.db,
        compose_path=None,
        spec_path=obj.config,
    )
    diagnostics = structured_diagnostics(records)
    if as_json:
        click.echo(
            json.dumps(
                {
                    "diagnostics": to_json_diagnostics(diagnostics),
                    "summary": {
                        "total": len(diagnostics),
                        "errors": sum(
                            item.severity is DiagnosticSeverity.error for item in diagnostics
                        ),
                        "warnings": sum(
                            item.severity is DiagnosticSeverity.warning for item in diagnostics
                        ),
                    },
                },
                indent=2,
            )
        )
    elif not quiet:
        for item in diagnostics:
            click.echo(
                f"[{item.status.value.upper()}] {item.check_id}: {item.message} "
                f"evidence={json.dumps(item.evidence, sort_keys=True)}"
            )
    if any(item.severity is DiagnosticSeverity.error for item in diagnostics):
        ctx.exit(int(ExitCode.VALIDATION_ERROR))


@inspect.command("run")
@click.argument("run_id")
@click.option(
    "--report",
    "report_format",
    type=click.Choice(["markdown", "json", "html"]),
    default=None,
)
@click.option("--artifact-dir", type=click.Path(), default=None)
@click.option("--retention-days", type=click.IntRange(1, 3650), default=30, show_default=True)
@click.option("--max-reports", type=click.IntRange(1, 10000), default=100, show_default=True)
@click.option("--compare", "compare_run_id", default=None, help="Compare with another run id.")
@click.pass_context
def inspect_run(
    ctx: click.Context,
    run_id: str,
    report_format: str | None,
    artifact_dir: str | None,
    retention_days: int,
    max_reports: int,
    compare_run_id: str | None,
) -> None:
    obj = ctx.obj
    assert isinstance(obj, CliContext)
    store = open_store(obj.db)
    try:
        row = run_detail(store, run_id)
        if row is None:
            raise click.UsageError(f"no such run: {run_id}", ctx=ctx)
        envelope = load_evidence(store, run_id)
        payload: dict[str, object] = {
            "report_id": report_id_for_run(run_id),
            "run": row,
            "journal": run_journal(store, run_id),
            "evidence": envelope.model_dump(mode="json") if envelope is not None else None,
        }
        if compare_run_id is not None:
            other = load_evidence(store, compare_run_id)
            if other is None:
                raise click.UsageError(
                    f"no evidence envelope for comparison run: {compare_run_id}", ctx=ctx
                )
            payload["comparison"] = (
                compare_reports(other, envelope) if envelope is not None else None
            )
        if report_format is not None and envelope is not None:
            renderer = {
                "markdown": render_report_markdown,
                "json": render_report_json,
                "html": render_report_html,
            }[report_format]
            rendered = renderer(envelope)
            if artifact_dir is not None:
                paths = write_report_artifacts(
                    envelope,
                    policy=ReportArtifactPolicy(
                        artifact_dir=Path(artifact_dir),
                        retention_days=retention_days,
                        max_reports=max_reports,
                    ),
                    formats=(report_format,),
                )
                payload["artifacts"] = {key: str(path) for key, path in paths.items()}
            else:
                click.echo(rendered)
                return
    finally:
        store.close()
    click.echo(json.dumps(payload, indent=2, default=str))


@inspect.command("leases")
@click.option("--run", "run_id", default=None, help="Only leases related to this run id.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def inspect_leases(ctx: click.Context, run_id: str | None, as_json: bool) -> None:
    obj = ctx.obj
    assert isinstance(obj, CliContext)
    store = open_store(obj.db)
    try:
        leases = SQLiteLeaseSink(store).all_leases()
        selected = [lease for lease in leases if run_id is None or lease.run_id == run_id]
        projections = [lease_projection(lease) for lease in selected]
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps({"leases": projections}, indent=2))
        return
    for item in projections:
        click.echo(
            f"{item['id']} owner={item['owner']} ttl={item['ttl_seconds']}s "
            f"target={','.join(item['target'])} fault={item['fault']} "
            f"state={item['state']} recovery={item['recovery']}"
        )


inspect.add_command(_clone(status, "runs"))
inspect.add_command(_clone(history, "history"))
inspect.add_command(_clone(coverage_cmd, "coverage"))
inspect.add_command(_clone(expert_cmd, "expert"))
inspect.add_command(_clone(next_cmd, "next"))
