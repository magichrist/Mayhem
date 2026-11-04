"""Mayhem CLI command namespaces.

This package holds the ten namespace PrefixGroups that reorganize the
flat 40-command root CLI into domain-based groups:

    workspace, environment, drill, runs, orchestration, governance,
    evidence, platform, extensions, developer.

Each namespace module defines its own PrefixGroup and registers its
commands. Existing command handlers are imported from their current
modules and registered under the new path once; root-level compatibility
aliases point to the same handler objects.
"""

from mayhem.cli.namespaces.developer import developer as developer
from mayhem.cli.namespaces.drill import drill as drill
from mayhem.cli.namespaces.environment import environment as environment
from mayhem.cli.namespaces.evidence import evidence as evidence
from mayhem.cli.namespaces.extensions import extensions as extensions
from mayhem.cli.namespaces.governance import governance as governance
from mayhem.cli.namespaces.orchestration import orchestration as orchestration
from mayhem.cli.namespaces.platform import platform as platform
from mayhem.cli.namespaces.runs import runs as runs
from mayhem.cli.namespaces.workspace import workspace as workspace

__all__ = [
    "workspace",
    "environment",
    "drill",
    "runs",
    "orchestration",
    "governance",
    "evidence",
    "platform",
    "extensions",
    "developer",
]
