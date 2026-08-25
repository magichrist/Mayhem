"""``config`` group: show and validate layered configuration."""

from __future__ import annotations

import json

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.services import effective_config
from mayhem.domain.errors import SchemaValidationError

config = make_group("config", "Inspect the effective layered mayhem configuration.")


@config.command("show")
@click.option("--json", "as_json", is_flag=True, help="Emit resolved config as JSON.")
@click.pass_context
def show(ctx: click.Context, as_json: bool) -> None:
    """Print the effective configuration after all layers are merged."""
    from mayhem.cli.context import CliContext

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    cfg, sources = effective_config(obj.config, obj.profile)
    if as_json:
        payload = {"config": cfg.model_dump(mode="json"), "sources": sources}
        click.echo(json.dumps(payload, indent=2))
        return
    import yaml

    click.echo(yaml.safe_dump(cfg.model_dump(mode="json"), sort_keys=False))
    click.echo("# sources:")
    for layer, origin in sources.items():
        click.echo(f"#   {layer}: {origin}")


@config.command("validate")
@click.pass_context
def validate(ctx: click.Context) -> None:
    """Load every configuration layer; refuse unknown keys or versions."""
    from mayhem.cli.context import CliContext

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    try:
        _cfg, sources = effective_config(obj.config, obj.profile)
    except SchemaValidationError as exc:
        raise click.ClickException(f"invalid configuration: {exc}") from exc
    click.echo(f"configuration valid ({len(sources)} layer(s))")
