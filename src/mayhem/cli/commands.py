from __future__ import annotations

import json

import click

from mayhem.cli.resolver import make_group

commands = make_group("commands", "Inspect the command migration map.")


@commands.command("show")
@click.option("--json", "as_json", is_flag=True, help="Emit the command map as JSON.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "yaml"], case_sensitive=False),
    default=None,
    help="Output format: text, json, or yaml.",
)
def show(as_json: bool, output_format: str | None) -> None:
    from mayhem.cli.command_registry import COMMAND_SPECS

    fmt = (output_format or ("json" if as_json else "text")).lower()
    rows = [
        {
            "command": spec.name,
            "workflow": spec.workflow,
            "help_group": spec.help_group,
            "mutating": spec.mutating,
            "sample_invocation": (
                f"mayhem {spec.name} --help"
                if spec.name in {"discover", "prepare", "inspect", "extend"}
                else f"mayhem {spec.name}"
            ),
        }
        for spec in COMMAND_SPECS
    ]
    if fmt == "json":
        click.echo(json.dumps(rows, indent=2, sort_keys=True))
        return
    if fmt == "yaml":
        import yaml

        click.echo(yaml.safe_dump(rows, sort_keys=True, allow_unicode=True))
        return
    for row in rows:
        click.echo(f"{row['command']} [{row['workflow']}] sample: {row['sample_invocation']}")
