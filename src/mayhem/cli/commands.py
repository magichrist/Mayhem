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
    rows = []
    for spec in COMMAND_SPECS:
        sample = f"mayhem {spec.replacement}" if spec.replacement else f"mayhem {spec.name}"
        if spec.workflow in ("discover", "prepare", "inspect", "extend") and spec.name in (
            "discover",
            "prepare",
            "inspect",
            "extend",
        ):
            sample = f"mayhem {spec.name} --help"
        rows.append(
            {
                "command": spec.name,
                "workflow": spec.workflow,
                "aliases": list(spec.aliases),
                "replacement": spec.replacement,
                "deprecated": bool(spec.deprecated),
                "deprecated_since": spec.deprecated_since,
                "deprecation_reason": spec.deprecation_reason,
                "removal": spec.removal,
                "sample_invocation": sample,
            }
        )
    if fmt == "json":
        click.echo(json.dumps(rows, indent=2, sort_keys=True))
        return
    if fmt == "yaml":
        import yaml

        click.echo(yaml.safe_dump(rows, sort_keys=True, allow_unicode=True))
        return
    for row in rows:
        replacement = f" -> {row['replacement']}" if row["replacement"] else ""
        aliases = f" aliases={','.join(row['aliases'])}" if row["aliases"] else ""
        depre = ""
        if row["deprecated"]:
            depre = f" deprecated since {row['deprecated_since']}"
            if row["removal"]:
                depre += f" removal {row['removal']}"
        sample = f" sample: {row['sample_invocation']}"
        click.echo(f"{row['command']} [{row['workflow']}]{aliases}{replacement}{depre}{sample}")
