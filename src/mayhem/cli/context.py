"""Shared CLI context object.

Global options live once on the root group and travel through
``ctx.obj`` as an immutable :class:`CliContext`. Subcommands never re-declare
them and never reach into module-level globals — this object is the only
channel for user intent, which keeps the handlers testable and makes a future
REST/UI layer trivial to add (construct a CliContext programmatically).
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_DB = ".mayhem/mayhem.db"


@dataclass(frozen=True, slots=True)
class CliContext:
    db: str = DEFAULT_DB
    config: str | None = None
    profile: str | None = None
    policy: str | None = None
    allow_critical: bool = False
    debug: bool = False
    target: str | None = None
    dry_run: bool = False
