"""``runs`` namespace: run inspection, lifecycle control and recovery."""

from __future__ import annotations

from mayhem.cli.inspect import inspect as inspect_cmd
from mayhem.cli.lifecycle import janitor, recover
from mayhem.cli.resolver import make_group
from mayhem.cli.stop_cmd import stop
from mayhem.cli.workflows import extend as extend_cmd

runs = make_group(
    "runs",
    "Inspect, control and recover runs.",
)

# `inspect` is itself a group; carry over all its existing subcommands intact.
inspect_cmd.name = "inspect"
runs.add_command(inspect_cmd)

runs.add_command(stop)
runs.add_command(extend_cmd, name="extend")
runs.add_command(recover)
runs.add_command(janitor)
