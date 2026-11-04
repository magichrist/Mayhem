"""``workspace`` namespace: project setup, environment checks, support, upgrades."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.init import init_cmd
from mayhem.cli.doctor import doctor_cmd
from mayhem.cli.config_cmd import config
from mayhem.cli.support_bundle_cmd import support_bundle
from mayhem.cli.upgrade_cmd import upgrade


workspace = make_group(
    "workspace",
    "Initialize projects and manage the local installation.",
)

# Re-register existing command handlers under the workspace namespace.
# `init` and `doctor` are top-level commands under workspace.
workspace.add_command(init_cmd)
workspace.add_command(doctor_cmd)
workspace.add_command(upgrade)

# `config` is itself a group with `show` and `validate` subcommands.
config.name = "config"
workspace.add_command(config)

# `support` is a group with `bundle` subcommand.
support = make_group(
    "support",
    "Build and collect support bundles.",
)
support.add_command(support_bundle, name="bundle")
workspace.add_command(support)
