"""``mayhem sandbox`` — plan 20 Phase 3: the sandbox lifecycle as CLI verbs.

Three verbs over the Phase 2 engine (:mod:`mayhem.controller.sandbox_service`),
and deliberately a thin surface:

``mayhem sandbox up``
    Provision the built-in test environment (frontend, API, database, cache,
    queue, observability) through :class:`SandboxProvisioner` with the CLI's
    own container-runtime runner. A refusal names its rule id, the runtime's
    own stderr, and whether the rollback worked — the surface adds no second
    policy and no second sequence.

``mayhem sandbox down``
    Tear the stack down through the same runner. A failed teardown is
    *reported*, never raised: teardown runs precisely when something has
    already gone wrong, so replacing a useful failure message with an
    exception about the cleanup is the wrong trade.

``mayhem sandbox status``
    Render what the sandbox is without touching a runtime: the blueprint's
    services, the registry hosts pulling would reach, and (when the compose
    document exists on disk) the topology the compose provider reads back.
    Status never provisions, never pulls, never starts anything — it reads
    the document the provisioner wrote.

What this surface does not do:

* It never shells out by itself. The only thing that touches a container
  runtime is :class:`SubprocessSandboxRunner`, injected into the
  provisioner, and the unit suite replaces it with a recording fake — no
  live docker in tests, fakes only.
* It is not a policy-free zone. Image egress is resolved through the
  declared network policy before the first command, and a denied host
  refuses with the cause named and no stack created.
* The compose document is written by :func:`render_compose_document` from
  the blueprint (the ``--dir`` directory holds it), so the sandbox the
  CLI provisions is the sandbox the topology provider can read back.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import click

from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.controller.sandbox_service import (
    COMPOSE_FILENAME,
    CommandOutcome,
    SandboxProvisioner,
    SandboxRefusedError,
    SandboxRequest,
    blueprint_registry_hosts,
    blueprint_services,
    render_compose_document,
    sandbox_topology,
)
from mayhem.domain.deployment import (
    SANDBOX_DEPLOYMENT_MODEL,
    DeploymentModel,
    NetworkPolicy,
    deployment_profile,
)

sandbox = make_group(
    "sandbox",
    "Provision and inspect the built-in test environment.",
)

__all__ = ["SubprocessSandboxRunner", "build_policy", "provisioner_for", "sandbox"]


class SubprocessSandboxRunner:
    """The container-runtime runner the CLI injects into the provisioner.

    The only implementation of
    :class:`~mayhem.controller.sandbox_service.SandboxRunner` that reaches
    a real runtime. It runs the argv it is handed, captures the output, and
    never raises — a command's failure is a :class:`CommandOutcome` the
    provisioner turns into a named refusal, not an exception here.
    """

    def __init__(self, *, timeout_s: float = 300.0) -> None:
        self.timeout_s = timeout_s

    def run(self, argv: Any) -> CommandOutcome:
        recorded = tuple(str(part) for part in argv)
        try:
            done = subprocess.run(
                list(recorded),
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_s,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return CommandOutcome(argv=recorded, returncode=1, stderr=f"runtime unavailable: {exc}")
        return CommandOutcome(
            argv=recorded,
            returncode=done.returncode,
            stdout=done.stdout or "",
            stderr=done.stderr or "",
        )


def build_policy(
    *,
    http_proxy: str,
    https_proxy: str,
    ca_bundle: str,
    allowlist: tuple[str, ...],
    enforce_allowlist: bool,
    air_gapped: bool,
) -> NetworkPolicy:
    """The declared network policy from relay/proxy configuration flags.

    Flag-shaped on purpose: relay and proxy configuration is the Phase 3
    acceptance UX, and every external call the sandbox makes (image pulls)
    honors it or fails closed with the cause named.
    """
    return NetworkPolicy(
        http_proxy=http_proxy,
        https_proxy=https_proxy,
        custom_ca_bundle=ca_bundle,
        air_gapped=air_gapped,
        outbound_allowlist=frozenset(allowlist),
        allowlist_enforced=enforce_allowlist or bool(allowlist),
    )


def provisioner_for(runner: Any) -> SandboxProvisioner:
    """The provisioner the CLI verbs share: default blueprint, injected runner."""
    return SandboxProvisioner(runner=runner)


def _policy_options(fn: Any) -> Any:
    """The relay/proxy configuration UX, shared by every verb that provisions."""
    for decorator in reversed(
        (
            click.option(
                "--http-proxy",
                default="",
                help="HTTP proxy for image pulls (empty means direct).",
            ),
            click.option(
                "--https-proxy",
                default="",
                help="HTTPS proxy for image pulls (empty means direct).",
            ),
            click.option(
                "--ca-bundle",
                default="",
                help="Custom CA bundle path the runtime trusts.",
            ),
            click.option(
                "--allow-host",
                "allowlist",
                multiple=True,
                help="Outbound host the policy permits; repeatable.",
            ),
            click.option(
                "--enforce-allowlist",
                is_flag=True,
                default=False,
                help="Refuse image hosts the allowlist does not name.",
            ),
            click.option(
                "--air-gapped",
                is_flag=True,
                default=False,
                help="Refuse all image egress; provision from pre-pulled images.",
            ),
        )
    ):
        fn = decorator(fn)
    return fn


def _echo(payload: dict[str, Any], as_json: bool) -> bool:
    from mayhem.cli.output import echo_machine

    return echo_machine(payload, as_json=as_json)


def _refuse(ctx: click.Context, exc: SandboxRefusedError) -> None:
    click.echo(f"refused [{exc.rule}]: {exc}", err=True)
    ctx.exit(int(ExitCode.SAFETY_REFUSAL))


@sandbox.command("up")
@click.option("--name", default="mayhem-sandbox", help="Compose project name.")
@click.option(
    "--dir",
    "directory",
    default=".",
    help="Directory holding the rendered compose document.",
)
@click.option(
    "--model",
    type=click.Choice([model.value for model in DeploymentModel]),
    default=None,
    help="Deployment model the sandbox provisions under (default: local).",
)
@_policy_options
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def up_cmd(
    ctx: click.Context,
    name: str,
    directory: str,
    model: str | None,
    http_proxy: str,
    https_proxy: str,
    ca_bundle: str,
    allowlist: tuple[str, ...],
    enforce_allowlist: bool,
    air_gapped: bool,
    as_json: bool,
) -> None:
    """Provision the built-in test environment. Refuses cleanly when it cannot."""
    policy = build_policy(
        http_proxy=http_proxy,
        https_proxy=https_proxy,
        ca_bundle=ca_bundle,
        allowlist=allowlist,
        enforce_allowlist=enforce_allowlist,
        air_gapped=air_gapped,
    )
    provisioner = provisioner_for(SubprocessSandboxRunner())
    try:
        environment = provisioner.provision(
            SandboxRequest(
                name=name,
                directory=Path(directory),
                policy=policy,
                model=DeploymentModel(model) if model else SANDBOX_DEPLOYMENT_MODEL,
            )
        )
    except SandboxRefusedError as exc:
        _refuse(ctx, exc)
        return
    payload: dict[str, Any] = {
        "name": environment.name,
        "ready": environment.ready,
        "compose_path": str(environment.compose_path),
        "services": list(environment.blueprint_services),
        "components": [component.value for component in environment.components],
        "deployment_model": environment.deployment_model.value,
        "deployment_note": deployment_profile(SANDBOX_DEPLOYMENT_MODEL).summary,
        "registry_egress": [
            {"host": host, "rule": rule} for host, rule in environment.registry_egress
        ],
        "commands": [command.command for command in environment.commands],
    }
    if _echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    click.echo(environment.describe())
    ctx.exit(int(ExitCode.SUCCESS))


@sandbox.command("down")
@click.option("--name", default="mayhem-sandbox", help="Compose project name.")
@click.option(
    "--dir",
    "directory",
    default=".",
    help="Directory holding the rendered compose document.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def down_cmd(ctx: click.Context, name: str, directory: str, as_json: bool) -> None:
    """Tear the sandbox stack down. A failed teardown is reported, not raised."""
    from mayhem.domain.deployment import SANDBOX_DEPLOYMENT_MODEL

    compose_path = Path(directory) / COMPOSE_FILENAME
    provisioner = provisioner_for(SubprocessSandboxRunner())
    # Teardown needs an environment record to name the compose document; the
    # record is reconstructed from the blueprint rather than re-provisioned,
    # so `down` never pulls, validates, or starts anything.
    from mayhem.controller.sandbox_service import SandboxEnvironment
    from mayhem.domain.deployment import SANDBOX_COMPONENTS

    environment = SandboxEnvironment(
        name=name,
        directory=Path(directory),
        compose_path=compose_path,
        blueprint_services=blueprint_services(),
        components=SANDBOX_COMPONENTS,
        deployment_model=SANDBOX_DEPLOYMENT_MODEL,
        registry_egress=(),
        attempts=(),
        commands=(),
        ca=provisioner.guard_for(SandboxRequest(name=name, directory=Path(directory))).ca,
    )
    teardown = provisioner.teardown(environment)
    payload: dict[str, Any] = {
        "name": teardown.name,
        "removed": teardown.removed,
        "command": teardown.outcome.command,
        "refusal": teardown.refusal,
    }
    if _echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS if teardown.removed else ExitCode.RECOVERY_FAILURE))
    if teardown.removed:
        click.echo(f"sandbox {name!r} removed with `{teardown.outcome.command}`")
        ctx.exit(int(ExitCode.SUCCESS))
    click.echo(f"teardown incomplete: {teardown.refusal}", err=True)
    ctx.exit(int(ExitCode.RECOVERY_FAILURE))


@sandbox.command("status")
@click.option("--name", default="mayhem-sandbox", help="Compose project name.")
@click.option(
    "--dir",
    "directory",
    default=".",
    help="Directory holding the rendered compose document.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def status_cmd(ctx: click.Context, name: str, directory: str, as_json: bool) -> None:
    """Describe the sandbox without touching a runtime: blueprint, registries, topology."""
    compose_path = Path(directory) / COMPOSE_FILENAME
    services = list(blueprint_services())
    hosts = list(blueprint_registry_hosts())
    node_ids: list[str] = []
    discoverable = False
    if compose_path.is_file():
        try:
            graph = sandbox_topology(compose_path)
            node_ids = [node.id for node in graph.nodes]
            discoverable = True
        except Exception:
            discoverable = False
    payload: dict[str, Any] = {
        "name": name,
        "compose_path": str(compose_path),
        "compose_present": compose_path.is_file(),
        "compose_discoverable": discoverable,
        "services": services,
        "registry_hosts": hosts,
        "node_ids": node_ids,
        "document_preview": render_compose_document(project_name=name),
    }
    if _echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    click.echo(f"sandbox {name!r} at {compose_path}")
    click.echo(f"  compose document: {'present' if compose_path.is_file() else 'absent'}")
    click.echo(f"  services: {', '.join(services)}")
    click.echo(f"  registry hosts: {', '.join(hosts)}")
    if node_ids:
        click.echo(f"  topology nodes: {', '.join(node_ids)}")
    ctx.exit(int(ExitCode.SUCCESS))
