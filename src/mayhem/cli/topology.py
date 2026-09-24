"""``topology`` group: discovery and drift."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

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
@click.option(
    "--runtime",
    "runtime",
    type=click.Choice(["docker", "podman", "kubernetes"], case_sensitive=False),
    default=None,
    help="Discovery engine. Overrides the global --podman flag. Default: auto.",
)
@click.option(
    "--context",
    "kube_context",
    default=None,
    help="kubeconfig context to use (kubernetes discovery).",
)
@click.option(
    "--namespace",
    "kube_namespace",
    default=None,
    help="Scope discovery to one namespace (kubernetes discovery).",
)
@click.option(
    "--target",
    "kube_target",
    default=None,
    help="Target profile supplying Kubernetes context and namespace.",
)
@click.option(
    "--mode",
    "k8s_mode",
    type=click.Choice(["manifest", "live", "dry-run"], case_sensitive=False),
    default=None,
    help="Kubernetes engine mode: manifest (offline), live (cluster), dry-run (no cluster).",
)
@click.option(
    "--manifest",
    "k8s_manifest",
    default=None,
    help="Kubernetes manifest file for offline inspection (manifest mode).",
)
@click.pass_context
def discover(  # noqa: PLR0912, PLR0915
    ctx: click.Context,
    compose_path: str | None,
    runtime: str | None,
    kube_context: str | None,
    kube_namespace: str | None,
    kube_target: str | None,
    k8s_mode: str | None,
    k8s_manifest: str | None,
) -> None:
    """Run the topology provider pipeline and print graph + drift JSON."""
    from mayhem.cli.app import _STATE
    from mayhem.topology.providers.adapter_registry import best_effort as runtime_best_effort
    from mayhem.topology.providers.compose import ComposeFileProvider
    from mayhem.topology.service import TopologyService

    resolved = _resolve_compose(compose_path)
    if runtime is None:
        runtime = _resolve_engine(str(_STATE.get("engine", "")))
    if runtime is None:
        try:
            from mayhem.domain.runtime_adapter import resolve_engine_selection

            sel = resolve_engine_selection(None)
            runtime = sel.name
        except Exception as exc:
            from mayhem.domain.errors import InvariantViolationError

            if isinstance(exc, InvariantViolationError) and getattr(exc, "rule", "") in (
                "engine_ambiguous",
                "engine_unavailable",
            ):
                raise click.ClickException(
                    f"{exc} — remediation: pass --runtime docker or --runtime podman"
                ) from None
            runtime = None
    engine = runtime

    providers: list[Any] = []
    k8s_discovery: dict[str, object] | None = None

    if engine == "kubernetes":
        from mayhem.agents.k8s_resolve import K8sEngineMode, resolve_k8s_target_context
        from mayhem.domain.target_profiles import load_profiles_from_mayhem_yaml

        selected_target = kube_target
        if selected_target is None and ctx.obj is not None:
            selected_target = getattr(ctx.obj, "target", None)
        profiles = load_profiles_from_mayhem_yaml(
            getattr(ctx.obj, "config", None) if ctx.obj is not None else None
        )
        profile = profiles.get(selected_target) if selected_target is not None else None
        if selected_target is None and len(profiles) > 1:
            raise click.ClickException(
                "multiple Kubernetes target profiles; pass --target NAME or use explicit context/namespace"
            )
        if profile is not None and profile.engine != "kubernetes":
            raise click.ClickException(
                f"target profile {selected_target!r} uses engine {profile.engine!r}, not kubernetes"
            )
        resolved_ctx = resolve_k8s_target_context(
            profile_context=profile.context if profile is not None else None,
            explicit_context=kube_context,
            profile_namespace=profile.namespace if profile is not None else None,
            explicit_namespace=kube_namespace,
            profile_workload_selector=profile.workload_selector if profile is not None else None,
            profile_capability_policy=profile.capability_policy if profile is not None else None,
            target_profile=selected_target,
            mode=k8s_mode,
        )
        effective_mode = resolved_ctx.mode
        if effective_mode in (K8sEngineMode.MANIFEST, K8sEngineMode.DRY_RUN):
            from mayhem.topology.providers.k8s_manifest import KubernetesManifestProvider

            manifest_path = k8s_manifest or compose_path
            if manifest_path is None:
                raise click.ClickException(
                    f"Kubernetes {effective_mode.value} mode requires --manifest PATH"
                )
            provider = KubernetesManifestProvider(manifest_path)
            if not provider.manifest_inspection_available():
                raise click.ClickException(
                    f"manifest inspection unavailable: {manifest_path}; provide a Kubernetes manifest"
                )
            k8s_discovery = {
                "mode": effective_mode.value,
                "manifest_inspection": True,
                "live_readiness": False,
                "sdk_available": None,
                "client_available": False,
                "context": resolved_ctx.context,
                "namespace": resolved_ctx.namespace,
                "healthy": False,
                "note": "manifest inspection succeeded; live execution was not probed",
            }
            providers = [provider]
        else:
            from mayhem.topology.providers.kubernetes import (
                KUBERNETES_IMPORT_ERROR,
                KUBERNETES_INSTALL_HINT,
                KubernetesProvider,
            )

            if KUBERNETES_IMPORT_ERROR is not None:
                raise click.ClickException(
                    "Kubernetes live discovery is unavailable: missing SDK. "
                    + KUBERNETES_INSTALL_HINT
                )
            provider_kwargs: dict[str, object] = {
                "context": resolved_ctx.context,
                "namespace": resolved_ctx.namespace,
            }
            if resolved_ctx.workload_selector is not None:
                provider_kwargs["workload_selector"] = resolved_ctx.workload_selector
            provider = KubernetesProvider("kubernetes", **provider_kwargs)
            readiness = (
                provider.live_readiness_available()
                if hasattr(provider, "live_readiness_available")
                else provider.is_available()
            )
            if not readiness:
                details = (
                    provider.readiness_details() if hasattr(provider, "readiness_details") else {}
                )
                detail = str(details.get("error") or "cluster is not reachable")
                raise click.ClickException(
                    f"Kubernetes live discovery is not ready (not reachable): {detail}; "
                    "check --context/--namespace and kubeconfig"
                )
            k8s_discovery = {
                "mode": effective_mode.value,
                "manifest_inspection": False,
                "live_readiness": True,
                "sdk_available": True,
                "client_available": True,
                "context": resolved_ctx.context,
                "namespace": resolved_ctx.namespace,
                "healthy": True,
                "note": "live discovery succeeded; execution capabilities remain separately gated",
            }
            providers = [provider]

    # Compose blueprint — scoped runtime match (docker/podman only).
    elif resolved is not None:
        compose_provider = ComposeFileProvider(resolved)
        runtime_provider = runtime_best_effort(engine)
        if runtime_provider is not None:
            runtime_provider.filter_by_compose(
                compose_provider.project_name,
                compose_provider.service_names,
            )
        providers = [p for p in (compose_provider, runtime_provider) if p is not None]

    else:
        # No compose file — fall back to mayhem.yaml target.containers,
        # or discover all running containers.
        from mayhem.config import load_config
        from mayhem.domain.errors import SchemaValidationError

        cli_ctx: CliContext | None = ctx.obj
        try:
            config, _sources = load_config(
                config_path=cli_ctx.config if cli_ctx else None,
                profile=cli_ctx.profile if cli_ctx else None,
            )
        except (OSError, ValueError, SchemaValidationError):
            config = None

        target_names: list[str] = []
        if config is not None:
            target_names = list(config.target.containers)

        runtime_provider = runtime_best_effort(engine)
        if runtime_provider is not None and target_names:
            runtime_provider.filter_by_names(target_names)

        providers = [p for p in (runtime_provider,) if p is not None]

    if not providers:
        eng = engine or "docker"
        if eng == "podman":
            remediation = "podman: install podman and podman-compose, "
            remediation += "then pass --compose <path> or add target.containers to mayhem.yaml"
        elif eng == "docker":
            remediation = "docker: install docker and docker compose plugin, "
            remediation += "then pass --compose <path> or add target.containers to mayhem.yaml"
        else:
            remediation = "pass --compose <path> or add target.containers to mayhem.yaml"
        raise click.ClickException(
            f"No docker-compose file found and no target containers configured. {remediation}"
        )

    result = TopologyService().discover(providers)
    engine_version = None
    topology_fingerprint = None
    try:
        from mayhem.domain.runtime_adapter import describe_engine, topology_fingerprint_for_engine

        if engine:
            try:
                desc = describe_engine(engine)
                engine_version = desc.version
            except Exception:
                pass
            if engine_version is None:
                try:
                    from mayhem.domain.runtime_adapter import detect_available_engines

                    for cand in detect_available_engines():
                        if cand.name == engine:
                            engine_version = cand.version
                            break
                except Exception:
                    pass
            try:
                topology_fingerprint = topology_fingerprint_for_engine(engine, result.graph)
            except Exception:
                topology_fingerprint = None
    except Exception:
        pass
    payload: dict[str, object] = {
        "graph": result.graph.model_dump(mode="json"),
        "drift": result.drift_report,
    }
    if engine:
        payload["engine"] = engine
    if k8s_discovery is not None:
        payload["kubernetes"] = k8s_discovery
    if engine_version:
        payload["engine_version"] = engine_version
    if topology_fingerprint:
        payload["topology_fingerprint"] = topology_fingerprint
    click.echo(json.dumps(payload, indent=2))


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
    if flag_value in ("docker", "podman", "kubernetes"):
        return flag_value
    return None
