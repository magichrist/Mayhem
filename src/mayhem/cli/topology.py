"""``topology`` group: discovery and drift."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import click

from mayhem.cli.resolver import make_group

if TYPE_CHECKING:
    from mayhem.cli.context import CliContext

topology = make_group("topology", "Discover and inspect target-system topology.")

_COMPOSE_CANDIDATES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


@topology.command("discover")
@click.option(
    "--compose",
    "compose_path",
    default=None,
    help="Compose file, directory containing one, or omit to auto-detect in cwd.",
)
@click.pass_context
def discover(ctx: click.Context, compose_path: str | None) -> None:
    """Run the topology provider pipeline and print graph + drift JSON."""
    from mayhem.cli.app import _STATE
    from mayhem.topology.providers.adapter_registry import best_effort as runtime_best_effort
    from mayhem.topology.providers.compose import ComposeFileProvider
    from mayhem.topology.service import TopologyService

    resolved = _resolve_compose(compose_path)
    engine = _resolve_engine(str(_STATE.get("engine", "")))

    providers: list = []

    # Compose blueprint — scoped runtime match.
    if resolved is not None:
        compose_provider = ComposeFileProvider(resolved)
        runtime_provider = runtime_best_effort(engine)
        if runtime_provider is not None:
            runtime_provider.filter_by_compose(
                compose_provider.project_name,
                compose_provider.service_names,
            )
        providers = [p for p in (compose_provider, runtime_provider) if p is not None]
    else:
        # No compose file — fall back to mayhem.yml target.containers,
        # or discover all running containers.
        from mayhem.config import load_config

        cli_ctx: CliContext | None = ctx.obj
        try:
            config, _sources = load_config(
                config_path=cli_ctx.config if cli_ctx else None,
                profile=cli_ctx.profile if cli_ctx else None,
            )
        except (OSError, ValueError):
            config = None

        target_names: list[str] = []
        if config is not None:
            target_names = list(config.target.containers)

        runtime_provider = runtime_best_effort(engine)
        if runtime_provider is not None and target_names:
            runtime_provider.filter_by_names(target_names)

        providers = [p for p in (runtime_provider,) if p is not None]

    if not providers:
        raise click.ClickException(
            "No docker-compose file found and no target containers "
            "configured. Pass --compose <path> or add target.containers "
            "to mayhem.yaml."
        )

    result = TopologyService().discover(providers)
    click.echo(
        json.dumps(
            {
                "graph": result.graph.model_dump(mode="json"),
                "drift": result.drift_report,
            },
            indent=2,
        )
    )


def _resolve_compose(explicit: str | None) -> str | None:
    """Resolve the compose file from user input.

    Accepts three forms:
      * ``None`` or empty — auto-detect in the current working directory.
      * A **directory** path — search for compose candidates inside it.
      * A **file** path  — use it directly (returns ``None`` if missing).
    """
    if not explicit:
        return _find_compose_in(Path.cwd())

    target = Path(explicit)
    if target.is_dir():
        return _find_compose_in(target)
    if target.is_file():
        return str(target)
    return None


def _find_compose_in(directory: Path) -> str | None:
    """Return the first matching compose file in *directory*, or ``None``."""
    for name in _COMPOSE_CANDIDATES:
        path = directory / name
        if path.is_file():
            return str(path)
    return None


def _resolve_engine(flag_value: str) -> str | None:
    """Turn the CLI flag value into an explicit engine, or None for auto-detect."""
    if flag_value in ("docker", "podman"):
        return flag_value
    return None
