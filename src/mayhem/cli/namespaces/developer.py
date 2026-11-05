"""``developer`` namespace: API, low-level, command registry, shell completion."""

from __future__ import annotations

from mayhem.cli.api_cmd import api
from mayhem.cli.commands import commands
from mayhem.cli.completion import completion
from mayhem.cli.lowlevel_cmd import lowlevel
from mayhem.cli.resolver import make_group

developer = make_group(
    "developer",
    "API, low-level, command registry and shell completion tools.",
)

developer.add_command(api)
developer.add_command(lowlevel)
developer.add_command(commands)
developer.add_command(completion)
