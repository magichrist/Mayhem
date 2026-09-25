from __future__ import annotations

from pathlib import Path

import click
import yaml

from mayhem.cli.context import CliContext


def _compose_service_names(compose_path: Path) -> list[str]:
    try:
        data = yaml.safe_load(compose_path.read_text()) or {}
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    services = data.get("services")
    if not isinstance(services, dict):
        return []
    return sorted(services.keys())


def _build_starter_yaml(
    *,
    engine: str,
    compose: str | None,
    has_k8s: bool,
) -> str:
    doc: dict[str, object] = {"apiVersion": "mayhem/v1", "runtime": engine}
    if compose:
        doc["target"] = {"containers": []}
    if has_k8s:
        doc["kubernetes"] = {"context": None, "namespace": None}
    doc["policy"] = {"risk_ceiling": "medium"}
    doc["storage"] = {"path": "mayhem.db", "artifacts_dir": ".mayhem/artifacts"}
    doc["blast_radius"] = {"max_services_pct": 50.0, "max_hosts": 2}
    doc["log_level"] = "INFO"
    return yaml.safe_dump(doc, sort_keys=False)


def _build_starter_drill(compose_path: Path | None) -> str:
    containers: dict[str, object]
    if compose_path is not None:
        names = _compose_service_names(compose_path)
        if names:
            first = names[0]
            containers = {
                first: {"faults": [{"fault": "cpu.saturate", "percent": 50, "duration": "10s"}]}
            }  # noqa: E501
        else:
            containers = {
                "example": {"faults": [{"fault": "cpu.saturate", "percent": 50, "duration": "10s"}]}
            }  # noqa: E501
    else:
        containers = {
            "example": {"faults": [{"fault": "cpu.saturate", "percent": 50, "duration": "10s"}]}
        }  # noqa: E501
    doc: dict[str, object] = {
        "apiVersion": "mayhem/v1",
        "kind": "drill",
        "name": "starter-drill",
        "hypothesis": "starter drill verifies the stack recovers",
        "config": {"risk_ceiling": "medium", "max_faults": 1, "timeout": "5m"},
        "containers": containers,
        "execution": [{"sequential": list(containers.keys())}],
    }
    return yaml.safe_dump(doc, sort_keys=False)


@click.command("init")
@click.option("--non-interactive", is_flag=True, help="Do not prompt; use inferred defaults.")
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=str),
    default=None,
    help="Output config path [default: mayhem.yaml].",
)  # noqa: E501
@click.option("--force", is_flag=True, help="Overwrite existing files.")
@click.pass_context
def init_cmd(
    ctx: click.Context, non_interactive: bool, output_path: str | None, force: bool
) -> None:  # noqa: E501
    from mayhem.infra.project_detection import detect_project

    obj = ctx.obj
    assert isinstance(obj, CliContext)
    base = Path.cwd()
    detection = detect_project(base)
    out = Path(output_path) if output_path else base / "mayhem.yaml"
    drill_out = base / "drill.starter.yaml"
    if out.exists() and not force:
        raise click.ClickException(f"refusing to overwrite {out}; use --force to overwrite")
    compose_file = str(detection.compose_files[0]) if detection.has_compose else None
    engine = detection.explicit_engine or "docker"
    if detection.has_k8s_manifest and not detection.has_compose:
        engine = "kubernetes"
    if not non_interactive and detection.explicit_engine is None:
        if detection.has_compose and detection.has_k8s_manifest:
            choice = click.prompt(
                "select engine",
                type=click.Choice(["docker", "podman", "kubernetes"]),
                default=engine,
                show_default=True,
            )  # noqa: E501
            engine = choice
        elif detection.has_k8s_manifest and not detection.has_compose:
            engine = click.prompt(
                "select engine",
                type=click.Choice(["docker", "podman", "kubernetes"]),
                default="kubernetes",
                show_default=True,
            )  # noqa: E501
        elif not detection.has_compose and not detection.has_k8s_manifest:
            engine = click.prompt(
                "select engine",
                type=click.Choice(["docker", "podman", "kubernetes"]),
                default="docker",
                show_default=True,
            )  # noqa: E501
    yaml_text = _build_starter_yaml(
        engine=engine, compose=compose_file, has_k8s=detection.has_k8s_manifest
    )  # noqa: E501
    out.write_text(yaml_text)
    if not drill_out.exists() or force:
        drill_path = detection.compose_files[0] if detection.has_compose else None
        drill_text = _build_starter_drill(drill_path)
        drill_out.write_text(drill_text)
        click.echo(f"created {drill_out}")
    click.echo(f"created {out} (engine={engine})")
    if compose_file:
        click.echo(f"detected compose: {compose_file}")
    if detection.has_k8s_manifest:
        click.echo(f"detected k8s manifests: {', '.join(str(p) for p in detection.k8s_manifests)}")
    click.echo("next: mayhem doctor")
    click.echo("validate: mayhem validate --help")
    click.echo(f"run: mayhem validate {drill_out}")
