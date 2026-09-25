"""CLI commands for campaigns (ADR-0023)."""

from __future__ import annotations

import json
from datetime import UTC
from typing import TYPE_CHECKING

import click

from mayhem.cli import style
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.cli.services import (
    build_graph,
    engine_for,
    open_store,
    plan_from_spec,
    prepare,
    run_campaign_sequence,
)
from mayhem.domain.campaigns import CampaignStatus, transition_campaign
from mayhem.domain.m5_campaign import CampaignExecutionManifest, CampaignManifestEntry

if TYPE_CHECKING:
    from click import Context

    from mayhem.controller.executor import RunResult


def _ctx(ctx: Context):
    from mayhem.cli.context import CliContext

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    return obj


def _db_status(status: CampaignStatus) -> str:
    if status is CampaignStatus.APPROVED:
        return "scheduled"
    if status is CampaignStatus.ARCHIVED:
        return "completed"
    return status.value


def _campaign_status(value: str) -> CampaignStatus:
    if value == "scheduled":
        return CampaignStatus.APPROVED
    return CampaignStatus(value)


def _transition_row(
    store,
    campaign_id: str,
    new_status: CampaignStatus,
    *,
    legacy_start: bool = False,
) -> dict:
    rows = store.query("SELECT status FROM campaigns WHERE id = ?", (campaign_id,))
    if not rows:
        raise FileNotFoundError(f"campaign not found: {campaign_id}")
    current = _campaign_status(rows[0]["status"])
    next_status = transition_campaign(current, new_status, legacy_start=legacy_start)
    from datetime import datetime

    now = datetime.now(UTC).isoformat()
    with store.write() as conn:
        conn.execute(
            "UPDATE campaigns SET status = ?, updated_at = ? WHERE id = ?",
            (_db_status(next_status), now, campaign_id),
        )
    return dict(store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))[0])


campaign = make_group("campaign", "Create, list, and inspect chaos campaigns.")


@campaign.command("list")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def list_campaigns(ctx: Context, db_opt: str | None, as_json: bool) -> None:
    """List all campaigns."""
    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query("SELECT id, name, status, created_at FROM campaigns ORDER BY created_at")
        if as_json:
            click.echo(json.dumps([dict(r) for r in rows], indent=2))
        else:
            if not rows:
                click.echo("No campaigns.")
                return
            for row in rows:
                click.echo(f"{row['id']:<32} {row['name']:<24} {style.state(row['status'])}")
    finally:
        store.close()


@campaign.command("create")
@click.argument("name")
@click.option("--description", "-d", default="", help="Campaign description.")
@click.option("--hypothesis", "-h", default=None, help="Campaign hypothesis.")
@click.option(
    "--target-profile",
    "target_profiles",
    multiple=True,
    help="Target profile to include.",
)
@click.option("--engine-policy", default="", help="Engine policy for the campaign.")
@click.option("--budget", type=int, default=0, help="Maximum campaign runs.")
@click.option("--deadline", type=float, default=None, help="Campaign deadline as epoch seconds.")
@click.option("--stop-condition", "stop_conditions", multiple=True, help="Campaign stop condition.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def create_campaign(
    ctx: Context,
    name: str,
    description: str,
    hypothesis: str | None,
    target_profiles: tuple[str, ...],
    engine_policy: str,
    budget: int,
    deadline: float | None,
    stop_conditions: tuple[str, ...],
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Create a new campaign in draft status."""
    import uuid
    from datetime import datetime

    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        campaign_id = f"camp-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()
        with store.write() as conn:
            labels = {
                "hypothesis": hypothesis or "",
                "target_profiles": list(target_profiles),
                "engine_policy": engine_policy,
                "budget": budget,
                "deadline_epoch_s": deadline,
                "stop_conditions": list(stop_conditions),
            }
            conn.execute(
                "INSERT INTO campaigns ("
                "id, name, description, status, labels_json, created_at, updated_at)"
                " VALUES (?, ?, ?, 'draft', ?, ?, ?)",
                (campaign_id, name, description, json.dumps(labels), now, now),
            )
        if as_json:
            row = store.query(
                "SELECT id, name, description, status, created_at, updated_at"
                " FROM campaigns WHERE id = ?",
                (campaign_id,),
            )
            click.echo(json.dumps(dict(row[0]), indent=2))
        else:
            click.echo(style.ok(f"Campaign '{campaign_id}' created successfully."))
    finally:
        store.close()


@campaign.command("show")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def show_campaign(ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool) -> None:
    """Show campaign details."""
    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            click.echo(f"{style.danger('error:')} Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        runs = [
            dict(r)
            for r in store.query(
                "SELECT run_id, data_json, timestamp FROM observations"
                " WHERE source = ? AND kind = 'campaign_run' ORDER BY timestamp",
                (campaign_id,),
            )
        ]
        if as_json:
            for key in ("experiments_json", "window_json", "policy_json", "labels_json"):
                if row.get(key):
                    row[key] = json.loads(row[key])
            parsed_runs = []
            for r in runs:
                spec = json.loads(r["data_json"]).get("spec", "")
                parsed_runs.append(
                    {"spec_path": spec, "run_id": r["run_id"], "timestamp": r["timestamp"]}
                )
            row["runs"] = parsed_runs
            click.echo(json.dumps(row, indent=2))
        else:
            click.echo(f"Campaign: {row['name']} ({row['id']})")
            click.echo(f"  Status: {style.state(row['status'])}")
            if row.get("description"):
                click.echo(f"  Description: {row['description']}")
            click.echo(f"  Created: {row['created_at']}")
            if runs:
                click.echo("  Runs:")
                for r in runs:
                    spec = json.loads(r["data_json"]).get("spec", "?")
                    click.echo(f"    - {spec} -> {r['run_id']} ({r['timestamp']})")
    finally:
        store.close()


@campaign.command("status")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.pass_context
def campaign_status(ctx: Context, campaign_id: str, db_opt: str | None) -> None:
    """Show the status of a campaign."""
    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query("SELECT id, name, status FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            click.echo(f"{style.danger('error:')} Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        click.echo(f"{row['id']} {row['name']} {style.state(row['status'])}")
    finally:
        store.close()


@campaign.command("delete")
@click.argument("campaign_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def delete_campaign(
    ctx: Context, campaign_id: str, yes: bool, db_opt: str | None, as_json: bool
) -> None:
    """Delete a campaign (only drafts)."""
    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query("SELECT id, name, status FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            click.echo(f"{style.danger('error:')} Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        if row["status"] != "draft":
            click.echo(
                f"Cannot delete campaign in '{row['status']}' status (must be 'draft').",
                err=True,
            )
            raise click.UsageError(f"cannot delete campaign in '{row['status']}' status")
        if not yes:
            click.confirm(f"Delete campaign '{row['name']}' ({campaign_id})?", abort=True)
        with store.write() as conn:
            conn.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))
        if as_json:
            click.echo(json.dumps({"deleted": campaign_id}))
        else:
            click.echo(style.ok(f"Campaign '{campaign_id}' deleted."))
    finally:
        store.close()


@campaign.command("approve")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def approve_campaign(ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool) -> None:
    """Approve a draft campaign."""
    store = open_store(db_opt or _ctx(ctx).db)
    try:
        row = _transition_row(store, campaign_id, CampaignStatus.APPROVED)
        if as_json:
            click.echo(json.dumps(dict(row), indent=2, sort_keys=True))
        else:
            click.echo(style.ok(f"Campaign '{campaign_id}' approved."))
    finally:
        store.close()


@campaign.command("pause")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def pause_campaign(ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool) -> None:
    """Persistently pause a running campaign."""
    store = open_store(db_opt or _ctx(ctx).db)
    try:
        row = _transition_row(store, campaign_id, CampaignStatus.PAUSED)
        if as_json:
            click.echo(json.dumps(dict(row), indent=2, sort_keys=True))
        else:
            click.echo(style.ok(f"Campaign '{campaign_id}' paused."))
    finally:
        store.close()


@campaign.command("resume")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def resume_campaign(ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool) -> None:
    """Resume a paused campaign and report recovery status."""
    store = open_store(db_opt or _ctx(ctx).db)
    try:
        rows = store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        current = _campaign_status(rows[0]["status"])
        if current is CampaignStatus.PAUSED:
            row = _transition_row(store, campaign_id, CampaignStatus.RUNNING)
        elif current is CampaignStatus.RUNNING:
            row = dict(rows[0])
        else:
            raise click.UsageError(f"cannot resume campaign in '{current.value}' status")
        store.save_observation(
            "campaign_resume",
            source=campaign_id,
            data={"recovery_status": "resumed", "campaign_id": campaign_id},
        )
        if as_json:
            payload = dict(row)
            payload["recovery_status"] = "resumed"
            click.echo(json.dumps(payload, indent=2, sort_keys=True))
        else:
            click.echo(style.ok(f"Campaign '{campaign_id}' resumed (recovery: ready)."))
    finally:
        store.close()


@campaign.command("plan")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def plan_campaign(ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool) -> None:
    """Build a side-effect-free campaign execution manifest."""
    store = open_store(db_opt or _ctx(ctx).db)
    try:
        rows = store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        labels = json.loads(row.get("labels_json") or "{}")
        experiments = json.loads(row.get("experiments_json") or "[]")
        manifest = CampaignExecutionManifest(
            campaign_id=campaign_id,
            entries=tuple(
                CampaignManifestEntry(
                    candidate_id=spec,
                    target=labels.get("target_profiles", [""])[0]
                    if labels.get("target_profiles")
                    else "",
                    fault="",
                )
                for spec in experiments
            ),
            engine_policy=labels.get("engine_policy", ""),
            target_profiles=tuple(labels.get("target_profiles", [])),
            budget=labels.get("budget") or None,
            deadline_epoch_s=labels.get("deadline_epoch_s"),
            stop_conditions=tuple(labels.get("stop_conditions", [])),
        )
        if as_json:
            click.echo(
                json.dumps(
                    {"dry_run": True, **manifest.to_dict()},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            click.echo(f"Campaign {campaign_id} execution plan ({len(manifest.entries)} cells).")
            for entry in manifest.entries:
                click.echo(f"  {entry.candidate_id} -> planned")
    finally:
        store.close()


@campaign.command("start")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def start_campaign(ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool) -> None:
    """Start a draft or approved campaign (legacy draft start is preserved)."""
    store = open_store(db_opt or _ctx(ctx).db)
    try:
        rows = store.query("SELECT status FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            click.echo(f"{style.danger('error:')} Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        current = _campaign_status(rows[0]["status"])
        if current not in (CampaignStatus.DRAFT, CampaignStatus.APPROVED):
            raise click.UsageError(f"cannot start campaign in '{current.value}' status")
        row = _transition_row(
            store,
            campaign_id,
            CampaignStatus.RUNNING,
            legacy_start=current is CampaignStatus.DRAFT,
        )
        if as_json:
            for key in ("experiments_json", "window_json", "policy_json", "labels_json"):
                if row.get(key):
                    row[key] = json.loads(row[key])
            click.echo(json.dumps(row, indent=2, sort_keys=True))
        else:
            click.echo(style.ok(f"Campaign '{campaign_id}' started."))
    finally:
        store.close()


@campaign.command("archive")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def archive_campaign(ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool) -> None:
    """Archive a completed or aborted campaign; legacy storage remains completed."""
    store = open_store(db_opt or _ctx(ctx).db)
    try:
        rows = store.query("SELECT status FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        current = _campaign_status(rows[0]["status"])
        if current is CampaignStatus.RUNNING:
            from datetime import datetime

            now = datetime.now(UTC).isoformat()
            with store.write() as conn:
                conn.execute(
                    "UPDATE campaigns SET status = 'completed', updated_at = ? WHERE id = ?",
                    (now, campaign_id),
                )
            row = dict(store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))[0])
            row["lifecycle_status"] = CampaignStatus.ARCHIVED.value
        else:
            row = _transition_row(store, campaign_id, CampaignStatus.ARCHIVED)
        if as_json:
            for key in ("experiments_json", "window_json", "policy_json", "labels_json"):
                if row.get(key):
                    row[key] = json.loads(row[key])
            row["lifecycle_status"] = CampaignStatus.ARCHIVED.value
            click.echo(json.dumps(row, indent=2, sort_keys=True))
        else:
            click.echo(style.ok(f"Campaign '{campaign_id}' archived."))
    finally:
        store.close()


@campaign.command("abort")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.pass_context
def abort_campaign(ctx: Context, campaign_id: str, db_opt: str | None) -> None:
    """Abort an active campaign (set status to 'aborted')."""
    store = open_store(db_opt or _ctx(ctx).db)
    try:
        _transition_row(store, campaign_id, CampaignStatus.ABORTED)
        click.echo(style.ok(f"Campaign '{campaign_id}' aborted."))
    finally:
        store.close()


@campaign.command("add-experiment")
@click.argument("campaign_id")
@click.argument("experiment_path", type=click.Path(exists=True))
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def add_experiment(
    ctx: Context,
    campaign_id: str,
    experiment_path: str,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Add an experiment spec file to a campaign."""
    from datetime import datetime

    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            click.echo(f"{style.danger('error:')} Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        experiments = json.loads(row.get("experiments_json") or "[]")
        experiments.append(experiment_path)
        now = datetime.now(UTC).isoformat()
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET experiments_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(experiments), now, campaign_id),
            )
        if as_json:
            click.echo(
                json.dumps({"campaign_id": campaign_id, "experiments": experiments}, indent=2)
            )
        else:
            click.echo(style.ok(f"Added experiment to campaign '{campaign_id}'."))
    finally:
        store.close()


def _resolve_engine_from_state() -> str:
    from mayhem.cli.app import _STATE
    from mayhem.cli.topology import _resolve_engine

    return _resolve_engine(str(_STATE.get("engine", ""))) or "podman"


def _record_campaign_resume(store, campaign_id: str, status: str) -> None:
    if status == "paused":
        store.save_observation(
            "campaign_resume",
            source=campaign_id,
            data={"recovery_status": "resumed", "campaign_id": campaign_id},
        )


@campaign.command("run")
@click.argument("campaign_id")
@click.option("--compose", "-c", type=str, default=None, help="Compose file path.")
@click.option("--no-gate", is_flag=True, help="Skip the impact gate for this run.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def run_campaign(
    ctx: Context,
    campaign_id: str,
    compose: str | None,
    no_gate: bool,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Execute a campaign's experiments sequentially (ADR-0023).

    Each experiment spec is compiled and executed against the compose
    topology. The campaign's policy_json failure policy and window_json
    deadline/cooldown are honored; per-experiment results are recorded in the
    observations table.
    """
    from datetime import datetime

    from mayhem.cli.lifecycle import _gate_bypasses, _gate_enabled, _graph_from

    obj = _ctx(ctx)
    db = db_opt or obj.db
    store = open_store(db)
    try:
        rows = store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            click.echo(f"{style.danger('error:')} Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        experiments = json.loads(row.get("experiments_json") or "[]")
        if not experiments:
            click.echo(
                f"{style.danger('error:')} Campaign has no experiments; add one with"
                " `mayhem campaign add-experiment`.",
                err=True,
            )
            raise click.UsageError("campaign has no experiments", ctx=ctx)
        if row["status"] not in ("draft", "scheduled", "running", "paused"):
            click.echo(
                "Cannot run campaign in "
                f"'{row['status']}' status (must be draft/scheduled/running/paused).",
                err=True,
            )
            raise click.UsageError(f"cannot run campaign in '{row['status']}' status")

        graph, resolved_compose = _graph_from(ctx, compose)
        engine_name = _resolve_engine_from_state()
        gate = _gate_enabled() and not no_gate

        _record_campaign_resume(store, campaign_id, row["status"])
        now = datetime.now(UTC).isoformat()
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET status = 'running', updated_at = ? WHERE id = ?",
                (now, campaign_id),
            )

        def _run_one(spec_path: str) -> RunResult:
            from mayhem.cli.lifecycle import _debug_progress

            prepared = prepare(
                config_path=obj.config,
                profile=obj.profile,
                allow_critical=obj.allow_critical,
                store=store,
                graph=graph,
                compose=resolved_compose,
                spec_path=spec_path,
            )
            compiled = plan_from_spec(spec_path, graph, prepared=prepared, engine=engine_name)
            bypass: dict[tuple[str, str], str] = {}
            if gate:
                bypass = _gate_bypasses(engine_name, compiled.plan, graph)
            eng = engine_for(
                store,
                engine_name,
                live_graph=lambda: build_graph(resolved_compose),
                on_event=_debug_progress() if obj.debug else None,
                bypass=bypass,
                recovery_grace=prepared.recovery_grace,
            )
            return eng.execute(compiled.plan)

        outcome = run_campaign_sequence(
            campaign_id=campaign_id,
            experiments=experiments,
            policy=json.loads(row.get("policy_json") or "{}"),
            window=json.loads(row.get("window_json") or "{}"),
            store=store,
            run_one=_run_one,
        )

        final_status = "completed" if outcome.status == "completed" else "aborted"
        now = datetime.now(UTC).isoformat()
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET status = ?, updated_at = ? WHERE id = ?",
                (final_status, now, campaign_id),
            )

        if as_json:
            click.echo(
                json.dumps(
                    {
                        "campaign_id": campaign_id,
                        "status": outcome.status,
                        "runs": [
                            {
                                "spec_path": e.spec_path,
                                "run_id": e.run_id,
                                "status": e.status,
                            }
                            for e in outcome.runs
                        ],
                    },
                    indent=2,
                )
            )
        else:
            for entry in outcome.runs:
                mark = style.ok("ok") if entry.status == "completed" else style.danger("FAIL")
                click.echo(f"  [{mark}] {entry.spec_path} -> {entry.run_id} ({entry.status})")
            click.echo(
                f"Campaign {style.cyan(campaign_id)} finished with status"
                f" {style.state(outcome.status)}."
            )

        if outcome.status != "completed":
            ctx.exit(int(ExitCode.EXPERIMENT_FAILURE))
    finally:
        store.close()
