"""``experiment`` group: inspect and validate experiment specs."""

from __future__ import annotations

import click

from mayhem.cli.lifecycle import validate as _validate_handler
from mayhem.cli.resolver import make_group

experiment = make_group("experiment", "Inspect and validate authored experiments.")


@experiment.command("show")
@click.argument("experiment", type=click.Path())
def show(experiment: str) -> None:
    """Print the parsed drill spec as JSON."""
    from mayhem.spec import load_drill

    loaded = load_drill(experiment)
    click.echo(loaded.model_dump_json(indent=2))


# Same handler object, registered under the group: zero behavioral drift.
experiment.add_command(_validate_handler, name="validate")
