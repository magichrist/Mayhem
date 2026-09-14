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

if TYPE_CHECKING:
    from click import Context

    from mayhem.controller.executor import RunResult


def _ctx(ctx: Context):
    from mayhem.cli.context import CliContext

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    return obj


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
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def create_campaign(
    ctx: Context,
    name: str,
    description: str,
    hypothesis: str | None,
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
            conn.execute(
                "INSERT INTO campaigns (id, name, description, status, created_at, updated_at)"
                " VALUES (?, ?, ?, 'draft', ?, ?)",
                (campaign_id, name, description, now, now),
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


@campaign.command("start")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def start_campaign(ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool) -> None:
    """Start a draft campaign (set status to 'running')."""
    from datetime import datetime

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
                f"Cannot start campaign in '{row['status']}' status (must be 'draft').",
                err=True,
            )
            raise click.UsageError(f"cannot start campaign in '{row['status']}' status")
        now = datetime.now(UTC).isoformat()
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET status = 'running', updated_at = ? WHERE id = ?",
                (now, campaign_id),
            )
        if as_json:
            rows2 = store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
            r = dict(rows2[0])
            for key in ("experiments_json", "window_json", "policy_json", "labels_json"):
                if r.get(key):
                    r[key] = json.loads(r[key])
            click.echo(json.dumps(r, indent=2))
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
    """Archive a campaign (set status to 'completed')."""
    from datetime import datetime

    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query("SELECT id, name, status FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            click.echo(f"{style.danger('error:')} Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        now = datetime.now(UTC).isoformat()
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET status = 'completed', updated_at = ? WHERE id = ?",
                (now, campaign_id),
            )
        if as_json:
            rows2 = store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
            r = dict(rows2[0])
            for key in ("experiments_json", "window_json", "policy_json", "labels_json"):
                if r.get(key):
                    r[key] = json.loads(r[key])
            click.echo(json.dumps(r, indent=2))
        else:
            click.echo(style.ok(f"Campaign '{campaign_id}' archived."))
    finally:
        store.close()


@campaign.command("abort")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.pass_context
def abort_campaign(ctx: Context, campaign_id: str, db_opt: str | None) -> None:
    """Abort a draft campaign (set status to 'aborted')."""
    from datetime import datetime

    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query("SELECT id, name, status FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            click.echo(f"{style.danger('error:')} Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        now = datetime.now(UTC).isoformat()
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET status = 'aborted', updated_at = ? WHERE id = ?",
                (now, campaign_id),
            )
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
