"""``config`` group: show and validate layered configuration."""

from __future__ import annotations

import json

import click

from mayhem.cli import style
from mayhem.cli.resolver import make_group
from mayhem.cli.services import effective_config

config = make_group("config", "Inspect the effective layered mayhem configuration.")


def _sanitize_payload(payload: dict[str, object]) -> dict[str, object]:
    from mayhem.domain.policy import sanitize_for_logging

    return sanitize_for_logging(payload)


@config.command("show")
@click.option("--json", "as_json", is_flag=True, help="Emit resolved config as JSON.")
@click.pass_context
def show(ctx: click.Context, as_json: bool) -> None:
    from mayhem.cli.context import CliContext

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    cfg, sources = effective_config(obj.config, obj.profile, obj.policy)
    sanitized = _sanitize_payload(cfg.model_dump(mode="json", by_alias=True))
    if as_json:
        payload = {"config": sanitized, "sources": sources}
        click.echo(json.dumps(payload, indent=2))
        return
    import yaml

    click.echo(yaml.safe_dump(sanitized, sort_keys=False))
    click.echo("# sources:")
    for layer, origin in sources.items():
        click.echo(f"#   {layer}: {origin}")


@config.command("explain")
@click.option("--json", "as_json", is_flag=True, help="Emit explanation as JSON.")
@click.pass_context
def explain(ctx: click.Context, as_json: bool) -> None:
    from mayhem.cli.context import CliContext
    from mayhem.config import explain_config

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    cfg, sources = effective_config(obj.config, obj.profile, obj.policy)
    rows = explain_config(cfg, sources)
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    for row in rows:
        safe = "mutable" if row["safe_for_mutation"] else "immutable"
        click.echo(f"{row['field']}: {row['value']} (source={row['source']}, {safe})")


@config.command("validate")
@click.pass_context
def validate(ctx: click.Context) -> None:
    from mayhem.cli.context import CliContext

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    _cfg, sources = effective_config(obj.config, obj.profile, obj.policy)
    click.echo(style.ok(f"configuration valid ({len(sources)} layer(s))"))
