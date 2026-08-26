"""CLI commands for campaigns (ADR-0023)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import click

from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.services import open_store

if TYPE_CHECKING:
    from click import Context


def _ctx(ctx: Context):
    from mayhem.cli.context import CliContext

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    return obj


@click.group()
def campaign() -> None:
    """Chaos campaign management."""
    pass


@campaign.command("list")
@click.pass_context
def list_campaigns(ctx: Context) -> None:
    """List all campaigns."""
    store = open_store(_ctx(ctx).db)
    try:
        with store.write() as conn:
            rows = conn.execute(
                "SELECT id, name, status, created_at FROM campaigns ORDER BY created_at DESC"
            ).fetchall()
    except Exception as exc:
        click.echo(f"Error listing campaigns: {exc}", err=True)
        ctx.exit(int(ExitCode.GENERAL_FAILURE))
        return
    if not rows:
        click.echo("No campaigns found.")
        return
    click.echo(f"{'ID':<20} {'Name':<30} {'Status':<12} {'Created'}")
    click.echo("-" * 80)
    for row in rows:
        click.echo(f"{row['id']:<20} {row['name']:<30} {row['status']:<12} {row['created_at']}")


@campaign.command("show")
@click.argument("campaign_id")
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.pass_context
def show_campaign(ctx: Context, campaign_id: str, as_json: bool) -> None:
    """Show details of a campaign."""
    store = open_store(_ctx(ctx).db)
    try:
        with store.write() as conn:
            row = conn.execute(
                "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
            ).fetchone()
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(int(ExitCode.GENERAL_FAILURE))
        return
    if row is None:
        click.echo(f"Campaign {campaign_id!r} not found.", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
        return
    if as_json:
        data = dict(row)
        for key in ("experiments_json", "window_json", "policy_json", "labels_json"):
            if data.get(key):
                data[key] = json.loads(data[key])
        click.echo(json.dumps(data, indent=2, default=str))
        return
    click.echo(f"Campaign: {row['name']}")
    click.echo(f"  ID:          {row['id']}")
    click.echo(f"  Status:      {row['status']}")
    click.echo(f"  Description: {row['description'] or '(none)'}")
    click.echo(f"  Created:     {row['created_at']}")
    click.echo(f"  Updated:     {row['updated_at']}")
    experiments = json.loads(row["experiments_json"]) if row["experiments_json"] else []
    if experiments:
        click.echo(f"  Experiments ({len(experiments)}):")
        for exp in experiments:
            ref = exp.get("experiment_ref", "?")
            priority = exp.get("priority", 0)
            click.echo(f"    - {ref} (priority={priority})")
    else:
        click.echo("  Experiments: (none)")


@campaign.command("create")
@click.argument("name")
@click.option("--description", "-d", default="", help="Campaign description.")
@click.option("--hypothesis", "-h", "hyp", default="", help="Campaign hypothesis.")
@click.option("--json-file", "-f", type=click.Path(exists=True), help="JSON file with campaign config.")
@click.pass_context
def create_campaign(ctx: Context, name: str, description: str, hyp: str, json_file: str | None) -> None:
    """Create a new campaign."""
    store = open_store(_ctx(ctx).db)

    import uuid
    from datetime import datetime, timezone

    campaign_id = f"camp-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    if json_file:
        with open(json_file) as f:
            config = json.load(f)
    else:
        config = {}

    try:
        with store.write() as conn:
            conn.execute(
                """INSERT INTO campaigns
                   (id, name, description, status, experiments_json, window_json,
                    policy_json, labels_json, created_at, updated_at)
                   VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?)""",
                (
                    campaign_id,
                    name,
                    description or hyp or config.get("description", ""),
                    json.dumps(config.get("experiments", [])),
                    json.dumps(config.get("window", {})),
                    json.dumps(config.get("policy", {})),
                    json.dumps(config.get("labels", {})),
                    now,
                    now,
                ),
            )
    except Exception as exc:
        click.echo(f"Error creating campaign: {exc}", err=True)
        ctx.exit(int(ExitCode.GENERAL_FAILURE))
        return
    click.echo(f"Campaign {campaign_id!r} created successfully.")


@campaign.command("delete")
@click.argument("campaign_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.pass_context
def delete_campaign(ctx: Context, campaign_id: str, yes: bool) -> None:
    """Delete a campaign (draft or completed only)."""
    store = open_store(_ctx(ctx).db)
    try:
        with store.write() as conn:
            row = conn.execute(
                "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
            ).fetchone()
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(int(ExitCode.GENERAL_FAILURE))
        return
    if row is None:
        click.echo(f"Campaign {campaign_id!r} not found.", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
        return
    if row["status"] not in ("draft", "completed", "aborted"):
        click.echo(
            f"Cannot delete campaign in status {row['status']!r}. "
            "Only draft/completed/aborted campaigns can be deleted.",
            err=True,
        )
        ctx.exit(int(ExitCode.SAFETY_REFUSED))
        return
    if not yes:
        click.confirm(f"Delete campaign {campaign_id!r}?", abort=True)
    try:
        with store.write() as conn:
            conn.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))
    except Exception as exc:
        click.echo(f"Error deleting campaign: {exc}", err=True)
        ctx.exit(int(ExitCode.GENERAL_FAILURE))
        return
    click.echo(f"Campaign {campaign_id!r} deleted.")


@campaign.command("start")
@click.argument("campaign_id")
@click.pass_context
def start_campaign(ctx: Context, campaign_id: str) -> None:
    """Start a draft campaign."""
    store = open_store(_ctx(ctx).db)
    try:
        with store.write() as conn:
            row = conn.execute(
                "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
            ).fetchone()
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(int(ExitCode.GENERAL_FAILURE))
        return
    if row is None:
        click.echo(f"Campaign {campaign_id!r} not found.", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
        return
    if row["status"] != "draft":
        click.echo(f"Cannot start campaign in status {row['status']!r}.", err=True)
        ctx.exit(int(ExitCode.SAFETY_REFUSED))
        return
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    try:
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET status = 'running', updated_at = ? WHERE id = ?",
                (now, campaign_id),
            )
    except Exception as exc:
        click.echo(f"Error starting campaign: {exc}", err=True)
        ctx.exit(int(ExitCode.GENERAL_FAILURE))
        return
    click.echo(f"Campaign {campaign_id!r} started.")


@campaign.command("status")
@click.argument("campaign_id")
@click.pass_context
def campaign_status(ctx: Context, campaign_id: str) -> None:
    """Show status of a campaign."""
    store = open_store(_ctx(ctx).db)
    try:
        with store.write() as conn:
            row = conn.execute(
                "SELECT id, name, status FROM campaigns WHERE id = ?", (campaign_id,)
            ).fetchone()
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(int(ExitCode.GENERAL_FAILURE))
        return
    if row is None:
        click.echo(f"Campaign {campaign_id!r} not found.", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
        return
    click.echo(f"{row['id']}  {row['status']:<12}  {row['name']}")


@campaign.command("abort")
@click.argument("campaign_id")
@click.pass_context
def abort_campaign(ctx: Context, campaign_id: str) -> None:
    """Abort a running campaign."""
    store = open_store(_ctx(ctx).db)
    try:
        with store.write() as conn:
            row = conn.execute(
                "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
            ).fetchone()
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(int(ExitCode.GENERAL_FAILURE))
        return
    if row is None:
        click.echo(f"Campaign {campaign_id!r} not found.", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
        return
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    try:
        with store.write() as conn:
            conn.execute(
                "UPDATE campaigns SET status = 'aborted', updated_at = ? WHERE id = ?",
                (now, campaign_id),
            )
    except Exception as exc:
        click.echo(f"Error aborting campaign: {exc}", err=True)
        ctx.exit(int(ExitCode.GENERAL_FAILURE))
        return
    click.echo(f"Campaign {campaign_id!r} aborted.")
