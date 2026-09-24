from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CommandSpec:
    name: str
    workflow: str
    aliases: tuple[str, ...] = ()
    help_group: str = "general"
    mutating: bool = False
    replacement: str | None = None
    deprecated: bool = False
    deprecated_since: str = ""
    deprecation_reason: str = ""
    removal: str = ""


def _deprecated(
    name: str,
    workflow: str,
    *,
    help_group: str,
    replacement: str,
    aliases: tuple[str, ...] = (),
    mutating: bool = False,
) -> CommandSpec:
    return CommandSpec(
        name=name,
        workflow=workflow,
        aliases=aliases,
        help_group=help_group,
        mutating=mutating,
        replacement=replacement,
        deprecated=True,
        deprecated_since="0.6.0",
        deprecation_reason="workflow grouping",
        removal="0.8.0",
    )


COMMAND_SPECS: tuple[CommandSpec, ...] = (
    _deprecated(
        "validate",
        "experiment",
        help_group="experiments",
        aliases=("v",),
        replacement="prepare validate",
    ),
    _deprecated(
        "plan",
        "prepare",
        help_group="experiments",
        replacement="prepare plan",
    ),
    CommandSpec("run", "run", mutating=True),
    CommandSpec("maniac", "run", mutating=True),
    _deprecated(
        "status",
        "inspect",
        help_group="inspect",
        replacement="inspect runs",
    ),
    _deprecated(
        "history",
        "inspect",
        help_group="inspect",
        replacement="inspect run",
    ),
    CommandSpec("recover", "recover", mutating=True),
    CommandSpec("janitor", "recover", mutating=True),
    _deprecated(
        "dependency",
        "prepare",
        help_group="preparation",
        mutating=True,
        replacement="prepare dependencies",
    ),
    _deprecated(
        "explore",
        "run",
        help_group="experiments",
        mutating=True,
        replacement="inspect next",
    ),
    _deprecated(
        "next",
        "inspect",
        help_group="inspect",
        replacement="inspect next",
    ),
    _deprecated(
        "coverage",
        "inspect",
        help_group="inspect",
        replacement="inspect coverage",
    ),
    _deprecated(
        "expert",
        "inspect",
        help_group="inspect",
        replacement="inspect expert",
    ),
    CommandSpec("experiment", "experiment", help_group="experiments"),
    _deprecated(
        "topology",
        "discover",
        help_group="discovery",
        replacement="discover topology",
    ),
    _deprecated(
        "toolkit",
        "extend",
        help_group="extension",
        replacement="discover faults / discover capabilities",
    ),
    _deprecated(
        "config",
        "prepare",
        aliases=("cfg",),
        help_group="preparation",
        replacement="prepare config",
    ),
    CommandSpec("campaign", "run", help_group="experiments", mutating=True),
    CommandSpec("discover", "discover", help_group="discovery"),
    CommandSpec("prepare", "prepare", help_group="preparation"),
    CommandSpec("inspect", "inspect", help_group="inspect"),
    CommandSpec("extend", "extend", help_group="extension"),
    CommandSpec("commands", "inspect", help_group="inspect"),
    CommandSpec("init", "prepare", help_group="preparation"),
    CommandSpec("doctor", "inspect", help_group="inspect"),
    CommandSpec("verify", "inspect", help_group="inspect"),
)


def register_legacy_commands(app: Any) -> None:
    from mayhem.cli.campaign import campaign
    from mayhem.cli.commands import commands
    from mayhem.cli.config_cmd import config
    from mayhem.cli.coverage_cmd import coverage_cmd
    from mayhem.cli.dependency import dependency
    from mayhem.cli.doctor import doctor_cmd
    from mayhem.cli.experiment import experiment
    from mayhem.cli.expert import expert_cmd
    from mayhem.cli.explore import explore
    from mayhem.cli.init import init_cmd
    from mayhem.cli.lifecycle import (
        history,
        janitor,
        maniac,
        plan,
        recover,
        run,
        status,
        validate,
        verify,
    )
    from mayhem.cli.next_cmd import next_cmd
    from mayhem.cli.toolkit import toolkit
    from mayhem.cli.topology import topology
    from mayhem.cli.workflows import discover, extend, inspect, prepare

    commands = {
        "validate": validate,
        "plan": plan,
        "run": run,
        "maniac": maniac,
        "status": status,
        "history": history,
        "recover": recover,
        "janitor": janitor,
        "dependency": dependency,
        "explore": explore,
        "next": next_cmd,
        "coverage": coverage_cmd,
        "commands": commands,
        "expert": expert_cmd,
        "experiment": experiment,
        "topology": topology,
        "toolkit": toolkit,
        "config": config,
        "campaign": campaign,
        "discover": discover,
        "prepare": prepare,
        "inspect": inspect,
        "extend": extend,
        "init": init_cmd,
        "doctor": doctor_cmd,
        "verify": verify,
    }
    for spec in COMMAND_SPECS:
        app.add_command(commands[spec.name])
        for alias in spec.aliases:
            app.add_command(commands[spec.name], alias)
