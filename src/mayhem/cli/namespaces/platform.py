"""``platform`` namespace: agents, CI, cloud, HA, enterprise operations."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.agent_cmd import agent
from mayhem.cli.ci_cmd import ci
from mayhem.cli.cloud_cmd import cloud
from mayhem.cli.failover_cmd import ha
from mayhem.cli.enterprise_cmd import enterprise


platform = make_group(
    "platform",
    "Manage agents and platform integrations.",
)

platform.add_command(agent)
platform.add_command(ci)
platform.add_command(cloud)
platform.add_command(ha)
platform.add_command(enterprise)
