from __future__ import annotations

import copy
import json

import click

from mayhem.cli.config_cmd import config
from mayhem.cli.dependency import dependency
from mayhem.cli.extend import providers
from mayhem.cli.inspect import inspect
from mayhem.cli.lifecycle import plan, validate
from mayhem.cli.resolver import make_group
from mayhem.cli.toolkit import toolkit
from mayhem.cli.topology import topology

__all__ = ["inspect"]


def _clone(command: click.Command, name: str) -> click.Command:
    cloned = copy.copy(command)
    cloned.name = name
    return cloned


discover = make_group("discover", "Discover targets, engines, and capabilities.")
discover.add_command(_clone(topology.commands["discover"], "topology"))
discover.add_command(_clone(toolkit.commands["faults"], "faults"))
discover.add_command(_clone(toolkit.commands["list"], "capabilities"))


@discover.command("engines")
def engines() -> None:
    from mayhem.domain.runtime_adapter import detect_available_engines

    detected = detect_available_engines()
    engines_payload = []
    for desc in detected:
        sel = (
            "--podman"
            if desc.name == "podman"
            else "--podman=false"
            if desc.name == "docker"
            else "--kubernetes"
        )
        engines_payload.append(
            {
                "name": desc.name,
                "selection": sel,
                "binary": desc.binary,
                "binary_available": bool(desc.binary_available),
                "version": desc.version,
                "compose_supported": bool(desc.compose_supported),
                "signals": list(desc.signals),
                "network_capabilities": sorted(desc.network_capabilities),
                "storage_capabilities": sorted(desc.storage_capabilities),
            }
        )
    for name in ("docker", "podman", "kubernetes"):
        if not any(e["name"] == name for e in engines_payload):
            sel = (
                "--kubernetes"
                if name == "kubernetes"
                else "--podman"
                if name == "podman"
                else "--podman=false"
            )
            engines_payload.append(
                {
                    "name": name,
                    "selection": sel,
                    "binary": name,
                    "binary_available": False,
                    "version": None,
                    "compose_supported": True,
                    "signals": ["SIGSTOP", "SIGCONT", "SIGTERM", "SIGKILL"],
                    "network_capabilities": [],
                    "storage_capabilities": [],
                }
            )
    click.echo(
        json.dumps(
            {
                "engines": sorted(engines_payload, key=lambda x: x["name"]),
                "note": (
                    "Availability reflects binary on PATH; ambiguity refusal "
                    "requires explicit --runtime when multiple engines available."
                ),
            },
            indent=2,
        )
    )


prepare = make_group("prepare", "Prepare configuration, dependencies, and executable plans.")
prepare_config = copy.copy(config)
prepare_config.name = "config"
prepare.add_command(prepare_config)
prepare.add_command(validate, name="validate")
prepare_dependencies = copy.copy(dependency)
prepare_dependencies.name = "dependencies"
prepare.add_command(prepare_dependencies)
prepare.add_command(_clone(dependency.commands["check"], "check"))
prepare.add_command(_clone(plan, "plan"))

extend = make_group("extend", "Inspect and extend faults, capabilities, and dependencies.")
extend.add_command(_clone(toolkit.commands["faults"], "faults"))
extend.add_command(_clone(toolkit.commands["list"], "capabilities"))
extend.add_command(_clone(dependency.commands["check"], "dependencies"))
extend.add_command(providers)
