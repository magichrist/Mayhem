"""``mayhem upgrade`` — plan 20 Phase 3: upgrade channels as a read-only surface.

Two verbs over the Phase-4-drafted engine
(:mod:`mayhem.controller.upgrade_channels`), and deliberately a thin one:

``mayhem upgrade channels``
    List the three cadences (stable, extended, rapid) with what each means,
    how often it moves, and whether an air-gapped site may follow it. Pure
    data; nothing is decided here.

``mayhem upgrade check --channel NAME --current X --target Y``
    Answer whether the move ``current → target`` on ``channel`` is
    admissible, through :func:`validate_upgrade`. A downgrade is refused by
    name, an unparseable version is refused by name, and an air-gapped
    install following ``rapid`` is refused by name. Staying on the same
    version is admissible: a no-op upgrade is idempotent, not wrong.

Read-only twice over: no verb here moves an install, pins a version, or
touches a package manager — the installer reads the answer, this surface
only decides whether the declared move is admissible. A refused move exits
with the safety-refusal code, because "mayhem understood the request and
declined to act" is what that code means.
"""

from __future__ import annotations

from typing import Any

import click

from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.controller.upgrade_channels import (
    UPGRADE_CHANNELS,
    UpgradeChannel,
    upgrade_channel,
    validate_upgrade,
)
from mayhem.domain.deployment import DeploymentModel

upgrade = make_group(
    "upgrade",
    "List upgrade channels and check whether a move is allowed.",
)

__all__ = ["upgrade"]


def _echo(payload: dict[str, Any], as_json: bool) -> bool:
    from mayhem.cli.output import echo_machine

    return echo_machine(payload, as_json=as_json)


@upgrade.command("channels")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def channels_cmd(ctx: click.Context, as_json: bool) -> None:
    """List the release cadences an install may follow."""
    payload: dict[str, Any] = {
        "channels": [
            {
                "channel": descriptor.channel.value,
                "summary": descriptor.summary,
                "cadence": descriptor.cadence,
                "requires_egress": descriptor.requires_egress,
                "supports_air_gapped": descriptor.supports_air_gapped,
            }
            for descriptor in UPGRADE_CHANNELS
        ],
    }
    if _echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    for descriptor in UPGRADE_CHANNELS:
        click.echo(f"{descriptor.channel.value}: {descriptor.summary} ({descriptor.cadence})")
        click.echo(
            f"  air-gapped: {'yes' if descriptor.supports_air_gapped else 'no — offline bundles only'}"
        )
    ctx.exit(int(ExitCode.SUCCESS))


@upgrade.command("check")
@click.option(
    "--channel",
    required=True,
    type=click.Choice([channel.value for channel in UpgradeChannel]),
    help="The cadence the install follows.",
)
@click.option("--current", required=True, help="Installed version (dotted numeric).")
@click.option("--target", required=True, help="Candidate version (dotted numeric).")
@click.option(
    "--model",
    type=click.Choice([model.value for model in DeploymentModel]),
    default=None,
    help="Deployment model refusing egress-dependent channels when air-gapped.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def check_cmd(
    ctx: click.Context,
    channel: str,
    current: str,
    target: str,
    model: str | None,
    as_json: bool,
) -> None:
    """Check whether current → target on channel is admissible. Moves nothing."""
    deployment = DeploymentModel(model) if model else None
    refusal = validate_upgrade(channel, current, target, model=deployment)
    descriptor = upgrade_channel(channel)
    payload: dict[str, Any] = {
        "channel": descriptor.channel.value,
        "current": current,
        "target": target,
        "deployment_model": deployment.value if deployment else None,
        "admissible": not refusal,
        "refusal": refusal,
        "supports_air_gapped": descriptor.supports_air_gapped,
    }
    if refusal:
        if _echo(payload, as_json):
            ctx.exit(int(ExitCode.SAFETY_REFUSAL))
        click.echo(f"refused: {refusal}", err=True)
        ctx.exit(int(ExitCode.SAFETY_REFUSAL))
    if _echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    click.echo(f"{current} → {target} on {descriptor.channel.value}: admissible")
    ctx.exit(int(ExitCode.SUCCESS))
