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
