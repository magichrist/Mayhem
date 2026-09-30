"""``experiment`` group: inspect and validate experiment specs."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import click

from mayhem.cli.explore import explore
from mayhem.cli.lifecycle import validate as _validate_handler
from mayhem.cli.resolver import make_group

if TYPE_CHECKING:
    from mayhem.domain.scenarios import Scenario

experiment = make_group("experiment", "Inspect and validate authored experiments.")


@experiment.command("show")
@click.argument("experiment", type=click.Path())
def show(experiment: str) -> None:
    """Print the parsed drill spec as JSON."""
    from mayhem.spec import load_drill

    loaded = load_drill(experiment)
    click.echo(loaded.model_dump_json(indent=2))


def _load_scenario(path: str) -> Scenario:
    import json

    from mayhem.domain.scenarios import load_scenario

    if path.endswith((".yaml", ".yml")):
        text = Path(path).read_text(encoding="utf-8")
        import yaml

        payload = yaml.safe_load(text)
    else:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return load_scenario(payload or {})


@experiment.command("compose")
@click.argument("scenario", type=click.Path(exists=True))
@click.option(
    "--set",
    "assignments",
    multiple=True,
    metavar="NAME=VALUE",
    help="Supply a scenario variable (repeatable).",
)
@click.option("--seed", type=int, default=None, help="Seed recorded with the compiled plan.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def compose(scenario: str, assignments: tuple[str, ...], seed: int | None, as_json: bool) -> None:
    """Compile a scenario into a plan. Plan-only: this never executes anything."""
    from mayhem.domain.scenarios import ScenarioError, compile_scenario

    supplied: dict[str, str] = {}
    for assignment in assignments:
        if "=" not in assignment:
            raise click.UsageError(f"--set expects NAME=VALUE, got {assignment!r}")
        name, _, value = assignment.partition("=")
        supplied[name.strip()] = value.strip()
    try:
        compiled = compile_scenario(_load_scenario(scenario), supplied, seed=seed)
    except ScenarioError as exc:
        raise click.ClickException(str(exc)) from exc
    from mayhem.cli.output import echo_machine

    payload = compiled.to_dict()
    if echo_machine(payload, as_json=as_json):
        return
    click.echo(f"scenario: {compiled.scenario_name}")
    click.echo(f"digest: {compiled.digest}")
    for name, value in sorted(compiled.values.items()):
        click.echo(f"  {name} = {value}")
    for step in compiled.steps:
        click.echo(f"  step {step['id']}: {json_dumps(step['action'])}")
    for skipped in compiled.skipped:
        click.echo(f"  skipped {skipped}")
    click.echo("plan only — nothing was executed")


@experiment.command("check-scenario")
@click.argument("scenario", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def validate_scenario(scenario: str, as_json: bool) -> None:
    """Validate a scenario document without compiling or executing it."""
    from mayhem.domain.scenarios import ScenarioError, resolve_variables

    try:
        parsed = _load_scenario(scenario)
        defaults = resolve_variables(parsed, {})
    except ScenarioError as exc:
        from mayhem.cli.output import echo_machine

        if not echo_machine({"valid": False, "error": str(exc)}, as_json=as_json):
            click.echo(f"invalid: {exc}")
        raise SystemExit(1) from exc
    variables = list(parsed.variable_names())
    payload = {
        "valid": True,
        "name": parsed.name,
        "schema_version": parsed.schema_version,
        "variables": variables,
        "defaults": defaults,
        "steps": [step.id for step in parsed.steps],
    }
    from mayhem.cli.output import echo_machine

    if echo_machine(payload, as_json=as_json):
        return
    click.echo(f"valid: {parsed.name}")
    click.echo(f"variables: {', '.join(variables) or '-'}")
    click.echo(f"steps: {len(parsed.steps)}")


def json_dumps(payload: object) -> str:
    import json

    return json.dumps(payload, indent=2, sort_keys=True, default=str)


# Same handler object, registered under the group: zero behavioral drift.
experiment.add_command(_validate_handler, name="validate")
experiment.add_command(explore, name="explore")
