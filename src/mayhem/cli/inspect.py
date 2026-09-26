from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Literal, cast

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


@click.group("replay", help="Export and validate replay capsules.")
def replay_group() -> None:
    """Replay capsule surfaces."""


@replay_group.command("export")
@click.argument("run_id")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option(
    "--out",
    type=click.Path(),
    default=None,
    help="Write the capsule to this file instead of stdout.",
)
@click.pass_context
def replay_export(ctx: click.Context, run_id: str, as_json: bool, out: str | None) -> None:
    """Export the stored replay capsule for a run, or capture it if missing."""
    from mayhem.infra.replay_repository import ReplayRepository, build_capsule

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    store = open_store(obj.db)
    try:
        repo = ReplayRepository(store)
        capsule = repo.load(run_id) or build_capsule(store, run_id)
        if capsule is None:
            click.echo(f"no run or capsule recorded for {run_id}", err=True)
            raise SystemExit(1)
        repo.save(capsule)
    finally:
        store.close()
    payload = capsule.model_dump(mode="json")
    if out:
        with open(out, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        click.echo(f"wrote {out} (digest {capsule.digest()[:12]})")
        return
    if as_json or not sys.stdout.isatty():
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    click.echo(f"run: {capsule.run_id}")
    click.echo(f"schema: {capsule.schema_version}")
    click.echo(f"digest: {capsule.digest()}")
    click.echo(f"engine: {capsule.runtime.get('engine', '') or '-'}")
    click.echo(f"fingerprints: {json.dumps(capsule.fingerprints, sort_keys=True)}")


@replay_group.command("validate")
@click.argument("run_id")
@click.option(
    "--mode",
    type=click.Choice(["validate", "dry_run"]),
    default="validate",
    show_default=True,
)
@click.option(
    "--current-fingerprint",
    default=None,
    help="Environment fingerprint to compare against the recorded one.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def replay_validate(
    ctx: click.Context,
    run_id: str,
    mode: str,
    current_fingerprint: str | None,
    as_json: bool,
) -> None:
    """Validate a stored replay capsule without mutating anything."""
    from mayhem.domain.replay import validate_replay_capsule
    from mayhem.infra.replay_repository import ReplayRepository, build_capsule

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    store = open_store(obj.db)
    try:
        capsule = ReplayRepository(store).load(run_id) or build_capsule(store, run_id)
    finally:
        store.close()
    if capsule is None:
        click.echo(f"no run or capsule recorded for {run_id}", err=True)
        raise SystemExit(1)
    result = validate_replay_capsule(
        capsule,
        mode=cast("Literal['validate', 'dry_run']", mode),
        current_fingerprint=current_fingerprint,
    )
    if as_json:
        click.echo(
            json.dumps(
                {
                    "run_id": capsule.run_id,
                    "valid": result.valid,
                    "errors": list(result.errors),
                    "warnings": list(result.warnings),
                    "plan_hash": result.plan_hash,
                },
                indent=2,
            )
        )
    else:
        click.echo(f"run: {capsule.run_id}")
        click.echo(f"valid: {str(result.valid).lower()}")
        click.echo(f"plan hash: {result.plan_hash}")
        for error in result.errors:
            click.echo(f"error: {error}")
        for warning in result.warnings:
            click.echo(f"warning: {warning}")
    if not result.valid:
        raise SystemExit(1)


@inspect.command("residual")
@click.argument("run_id")
@click.option(
    "--expect",
    "expected",
    multiple=True,
    metavar="SIGNAL=VALUE",
    help="Baseline signal to compare against (repeatable).",
)
@click.option(
    "--observed",
    "observed",
    multiple=True,
    metavar="SIGNAL=VALUE",
    help="Post-recovery signal to compare (repeatable).",
)
@click.option("--tolerance", type=float, default=0.0, show_default=True, help="Allowed drift.")
@click.option(
    "--accept",
    "acceptances",
    multiple=True,
    metavar="SIGNAL=WHO:REASON",
    help="Explicitly accept a residual deviation for one signal.",
)
@click.option(
    "--from-observations",
    is_flag=True,
    help="Use the evidence envelope's own observation values.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def inspect_residual(
    ctx: click.Context,
    run_id: str,
    expected: tuple[str, ...],
    observed: tuple[str, ...],
    tolerance: float,
    acceptances: tuple[str, ...],
    from_observations: bool,
    as_json: bool,
) -> None:
    """Report residual impact for a run: did the system come back?"""
    from mayhem.domain.residual_impact import (
        ImpactAcceptance,
        ImpactSnapshot,
        assess_residual_impact,
    )

    def _parse(pairs: tuple[str, ...]) -> dict[str, float]:
        values: dict[str, float] = {}
        for pair in pairs:
            if "=" not in pair:
                raise click.UsageError(f"expected SIGNAL=VALUE, got {pair!r}")
            signal, _, raw = pair.partition("=")
            try:
                values[signal.strip()] = float(raw)
            except ValueError as exc:
                raise click.UsageError(f"signal {signal!r} is not numeric: {raw!r}") from exc
        return values

    before_values = _parse(expected)
    after_values = _parse(observed)
    detail = ""
    if from_observations:
        obj = ctx.obj
        assert isinstance(obj, CliContext)
        store = open_store(obj.db)
        try:
            envelope = load_evidence(store, run_id)
        finally:
            store.close()
        if envelope is None:
            click.echo(f"no evidence recorded for {run_id}", err=True)
            raise SystemExit(1)
        for observation in envelope.observations:
            metric = str(observation.get("metric") or "")
            value = observation.get("value")
            if metric and isinstance(value, (int, float)):
                before_values.setdefault(metric, float(value))
                after_values.setdefault(metric, float(value))
        detail = "signals read from the evidence envelope"

    acceptance_models: list[ImpactAcceptance] = []
    for item in acceptances:
        if "=" not in item:
            raise click.UsageError(f"expected SIGNAL=WHO:REASON, got {item!r}")
        signal, _, rest = item.partition("=")
        who, _, reason = rest.partition(":")
        if not who or not reason:
            raise click.UsageError(f"acceptance needs WHO and REASON, got {item!r}")
        acceptance_models.append(
            ImpactAcceptance(signal=signal.strip(), accepted_by=who, reason=reason)
        )

    assessment = assess_residual_impact(
        ImpactSnapshot(label="before", values=before_values, source="cli"),
        ImpactSnapshot(label="after", values=after_values, source="cli"),
        tolerance=tolerance,
        acceptances=tuple(acceptance_models),
    )
    payload = assessment.to_dict()
    if detail:
        payload["detail"] = detail
    from mayhem.cli.output import echo_machine

    if not echo_machine(payload, as_json=as_json):
        click.echo(f"residual impact: {assessment.status}")
        for violation in assessment.violations:
            marker = "tolerated" if violation.tolerated else "VIOLATION"
            click.echo(
                f"  {marker:<10} {violation.signal}: expected {violation.expected}, "
                f"observed {violation.observed} (delta {violation.delta})"
            )
            if violation.acceptance:
                click.echo(
                    f"             accepted by {violation.acceptance.accepted_by}: "
                    f"{violation.acceptance.reason}"
                )


inspect.add_command(replay_group)

@inspect.command("graph")
@click.option("--service", default=None, help="Only nodes for this service.")
@click.option("--engine", default=None, help="Only nodes for this engine.")
@click.option(
    "--evidence-status",
    default=None,
    type=click.Choice(["verified", "attempted", "blocked", "none"]),
    help="Only nodes with this evidence status.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option(
    "--record",
    is_flag=True,
    help="Record the current coverage table into the graph before reporting.",
)
@click.pass_context
def inspect_graph(
    ctx: click.Context,
    service: str | None,
    engine: str | None,
    evidence_status: str | None,
    as_json: bool,
    record: bool,
) -> None:
    """Read-only resilience coverage graph."""
    from mayhem.domain.coverage_graph import build_graph
    from mayhem.infra.coverage_repository import CoverageGraphRepository

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    store = open_store(obj.db)
    try:
        repo = CoverageGraphRepository(store)
        if record:
            graph = build_graph(repo.records_from_coverage())
            repo.record_nodes(graph.nodes)
        graph = repo.graph(service=service, engine=engine, evidence_status=evidence_status)
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    if echo_machine(graph.to_dict(), as_json=as_json):
        return
    summary = graph.summary()
    click.echo(
        f"coverage graph: {summary['nodes']} nodes, {summary['services']} services, "
        f"{summary['verified']} verified, {summary['blocked']} blocked"
    )
    for node in graph.nodes:
        click.echo(
            f"  {node.service:<24} {node.fault_family:<16} {node.engine:<12} "
            f"{node.evidence_status:<10} maturity={node.maturity}"
        )
        for edge in graph.edges:
            if edge.source == node.service and edge.target == node.fault_family:
                click.echo(f"    -> {edge.target} ({edge.evidence_status}, {edge.weight} attempt(s))")


@inspect.command("coverage-diff")
@click.argument("baseline")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option(
    "--save",
    is_flag=True,
    help="Save the current graph as this baseline instead of diffing against it.",
)
@click.pass_context
def inspect_coverage_diff(ctx: click.Context, baseline: str, as_json: bool, save: bool) -> None:
    """Diff the recorded coverage graph against a named baseline."""
    from mayhem.infra.coverage_repository import CoverageGraphRepository

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    store = open_store(obj.db)
    try:
        repo = CoverageGraphRepository(store)
        if save:
            graph = repo.graph()
            repo.save_baseline(baseline, graph)
            payload = {"baseline": baseline, "saved": graph.summary()}
        else:
            delta = repo.delta(baseline)
            if delta is None:
                click.echo(f"unknown baseline: {baseline}", err=True)
                click.echo(f"known baselines: {', '.join(repo.baseline_names()) or '-'}", err=True)
                raise SystemExit(1)
            payload = {"baseline": baseline, **delta.to_dict()}
    finally:
        store.close()
    from mayhem.cli.output import echo_machine

    if echo_machine(payload, as_json=as_json):
        return
    for key, value in payload.items():
        click.echo(f"{key}: {value}")


inspect.add_command(_clone(status, "runs"))
inspect.add_command(_clone(history, "history"))
inspect.add_command(_clone(coverage_cmd, "coverage"))
inspect.add_command(_clone(expert_cmd, "expert"))
inspect.add_command(_clone(next_cmd, "next"))
