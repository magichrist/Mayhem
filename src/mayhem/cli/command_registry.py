from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CommandSpec:
    name: str
    workflow: str
    help_group: str = "general"
    mutating: bool = False


COMMAND_HELP: dict[str, str] = {
    "campaign": "Create, inspect, and run chaos campaigns.",
    "commands": "Show the command migration map.",
    "completion": "Generate a shell completion script for this Mayhem build.",
    "discover": "Discover targets, engines, and capabilities.",
    "doctor": "Check configuration, database, engines, and permissions.",
    "experiment": "Inspect and validate authored experiment specs.",
    "extend": "Extend fault and capability coverage safely.",
    "game-day": "Plan and run controlled game-day sessions.",
    "init": "Detect the project and create a safe starting configuration.",
    "inspect": "Inspect runs, coverage, leases, reports, and diagnostics.",
    "pack": "Validate and load third-party fault packs.",
    "janitor": "Preview or execute stale lease cleanup.",
    "maniac": "Run randomized fault injection from a drill.",
    "prepare": "Prepare configuration, dependencies, and plans.",
    "recover": "Plan or execute recovery for a run.",
    "run": "Compile, approve, execute, and record a drill.",
    "verify": "Verify a recorded evidence envelope without mutation.",
    "bundle": "Build and verify portable evidence bundles.",
}


COMMAND_SPECS: tuple[CommandSpec, ...] = (
    CommandSpec("campaign", "run", help_group="experiments", mutating=True),
    CommandSpec("commands", "inspect", help_group="inspect"),
    CommandSpec("completion", "inspect", help_group="inspect"),
    CommandSpec("discover", "discover", help_group="discovery"),
    CommandSpec("doctor", "inspect", help_group="inspect"),
    CommandSpec("experiment", "experiment", help_group="experiments"),
    CommandSpec("extend", "extend", help_group="extension"),
    CommandSpec("game-day", "run", help_group="experiments", mutating=True),
    CommandSpec("init", "prepare", help_group="preparation"),
    CommandSpec("inspect", "inspect", help_group="inspect"),
    CommandSpec("janitor", "recover", help_group="recover", mutating=True),
    # `pack` is read-only in 1.0: `validate` and `load` both touch no
    # campaign, plan, or database, and load registers in-process only. A pack
    # fault is catalog-only, so loading a pack never mutates a target.
    CommandSpec("pack", "extend", help_group="extension"),
    CommandSpec("maniac", "run", help_group="experiments", mutating=True),
    CommandSpec("prepare", "prepare", help_group="preparation"),
    CommandSpec("recover", "recover", help_group="recover", mutating=True),
    CommandSpec("run", "run", help_group="run", mutating=True),
    CommandSpec("verify", "inspect", help_group="inspect"),
    CommandSpec("bundle", "inspect", help_group="inspect"),
)


def register_commands(app: Any) -> None:
    from mayhem.cli.campaign import campaign
    from mayhem.cli.commands import commands
    from mayhem.cli.completion import completion
    from mayhem.cli.doctor import doctor_cmd
    from mayhem.cli.experiment import experiment
    from mayhem.cli.game_day import game_day
    from mayhem.cli.init import init_cmd
    from mayhem.cli.lifecycle import janitor, maniac, recover, run, verify
    from mayhem.cli.pack import pack
    from mayhem.cli.verify_bundle import bundle_cmd
    from mayhem.cli.workflows import discover, extend, inspect, prepare

    command_map = {
        "campaign": campaign,
        "commands": commands,
        "completion": completion,
        "discover": discover,
        "doctor": doctor_cmd,
        "experiment": experiment,
        "game-day": game_day,
        "extend": extend,
        "init": init_cmd,
        "inspect": inspect,
        "janitor": janitor,
        "maniac": maniac,
        "pack": pack,
        "prepare": prepare,
        "recover": recover,
        "run": run,
        "verify": verify,
        "bundle": bundle_cmd,
    }
    for spec in COMMAND_SPECS:
        command = command_map[spec.name]
        command.help = COMMAND_HELP[spec.name]
        app.add_command(command)
