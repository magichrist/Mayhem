"""CLI commands for campaigns (ADR-0023)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import click

from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.cli.services import open_store

if TYPE_CHECKING:
    from click import Context


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
        rows = store.query(
            "SELECT id, name, status, created_at FROM campaigns ORDER BY created_at"
        )
        if as_json:
            click.echo(json.dumps([dict(r) for r in rows], indent=2))
        else:
            if not rows:
                click.echo("No campaigns.")
                return
            for row in rows:
                click.echo(f"{row['id']:<32} {row['name']:<24} {row['status']}")
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
    ctx: Context, name: str, description: str, hypothesis: str | None, db_opt: str | None, as_json: bool
) -> None:
    """Create a new campaign in draft status."""
    import uuid
    from datetime import datetime, timezone

    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        campaign_id = f"camp-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
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
            click.echo(f"Campaign '{campaign_id}' created successfully.")
    finally:
        store.close()


@campaign.command("show")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def show_campaign(
    ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool
) -> None:
    """Show campaign details."""
    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            click.echo(f"Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        if as_json:
            for key in ("experiments_json", "window_json", "policy_json", "labels_json"):
                if row.get(key):
                    row[key] = json.loads(row[key])
            click.echo(json.dumps(row, indent=2))
        else:
            click.echo(f"Campaign: {row['name']} ({row['id']})")
            click.echo(f"  Status: {row['status']}")
            if row.get("description"):
                click.echo(f"  Description: {row['description']}")
            click.echo(f"  Created: {row['created_at']}")
    finally:
        store.close()


@campaign.command("status")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.pass_context
def campaign_status(
    ctx: Context, campaign_id: str, db_opt: str | None
) -> None:
    """Show the status of a campaign."""
    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query(
            "SELECT id, name, status FROM campaigns WHERE id = ?", (campaign_id,)
        )
        if not rows:
            click.echo(f"Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        click.echo(f"{row['id']} {row['name']} {row['status']}")
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
        rows = store.query(
            "SELECT id, name, status FROM campaigns WHERE id = ?", (campaign_id,)
        )
        if not rows:
            click.echo(f"Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        if row["status"] != "draft":
            click.echo(
                f"Cannot delete campaign in '{row['status']}' status (must be 'draft').",
                err=True,
            )
            raise click.UsageError(f"cannot delete campaign in '{row['status']}' status")
        if not yes:
            click.confirm(
                f"Delete campaign '{row['name']}' ({campaign_id})?", abort=True
            )
        with store.write() as conn:
            conn.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))
        if as_json:
            click.echo(json.dumps({"deleted": campaign_id}))
        else:
            click.echo(f"Campaign '{campaign_id}' deleted.")
    finally:
        store.close()


@campaign.command("start")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def start_campaign(
    ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool
) -> None:
    """Start a draft campaign (set status to 'active')."""
    from datetime import datetime, timezone

    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query(
            "SELECT id, name, status FROM campaigns WHERE id = ?", (campaign_id,)
        )
        if not rows:
            click.echo(f"Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        if row["status"] != "draft":
            click.echo(
                f"Cannot start campaign in '{row['status']}' status (must be 'draft').",
                err=True,
            )
            raise click.UsageError(f"cannot start campaign in '{row['status']}' status")
        now = datetime.now(timezone.utc).isoformat()
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET status = 'active', updated_at = ? WHERE id = ?",
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
            click.echo(f"Campaign '{campaign_id}' started.")
    finally:
        store.close()


@campaign.command("archive")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def archive_campaign(
    ctx: Context, campaign_id: str, db_opt: str | None, as_json: bool
) -> None:
    """Archive a campaign (set status to 'archived')."""
    from datetime import datetime, timezone

    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query(
            "SELECT id, name, status FROM campaigns WHERE id = ?", (campaign_id,)
        )
        if not rows:
            click.echo(f"Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        now = datetime.now(timezone.utc).isoformat()
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET status = 'archived', updated_at = ? WHERE id = ?",
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
            click.echo(f"Campaign '{campaign_id}' archived.")
    finally:
        store.close()


@campaign.command("abort")
@click.argument("campaign_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.pass_context
def abort_campaign(
    ctx: Context, campaign_id: str, db_opt: str | None
) -> None:
    """Abort a draft campaign (set status to 'aborted')."""
    from datetime import datetime, timezone

    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query(
            "SELECT id, name, status FROM campaigns WHERE id = ?", (campaign_id,)
        )
        if not rows:
            click.echo(f"Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        now = datetime.now(timezone.utc).isoformat()
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET status = 'aborted', updated_at = ? WHERE id = ?",
                (now, campaign_id),
            )
        click.echo(f"Campaign '{campaign_id}' aborted.")
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
    from datetime import datetime, timezone

    db = db_opt or _ctx(ctx).db
    store = open_store(db)
    try:
        rows = store.query("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        if not rows:
            click.echo(f"Campaign {campaign_id!r} not found.", err=True)
            raise FileNotFoundError(f"campaign not found: {campaign_id}")
        row = dict(rows[0])
        experiments = json.loads(row.get("experiments_json") or "[]")
        experiments.append(experiment_path)
        now = datetime.now(timezone.utc).isoformat()
        store.query(
            "UPDATE campaigns SET experiments_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(experiments), now, campaign_id),
        )
        if as_json:
            click.echo(json.dumps({"campaign_id": campaign_id, "experiments": experiments}, indent=2))
        else:
            click.echo(f"Added experiment to campaign '{campaign_id}'.")
    finally:
        store.close()
