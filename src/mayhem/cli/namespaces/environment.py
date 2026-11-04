"""``environment`` namespace: discovery, topology, capabilities, diagnostics."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.workflows import discover
from mayhem.cli.boundary_report_cmd import boundary
from mayhem.cli.advisor_cmd import advisor
from mayhem.cli.probe_cmd import probe


environment = make_group(
    "environment",
    "Discover topology, faults, capabilities and diagnostics.",
)

# `discover` is itself a group; its existing subcommands are carried over intact.
discover.name = "discover"
environment.add_command(discover)

environment.add_command(boundary)
environment.add_command(advisor)
environment.add_command(probe)
