"""General command-tree prefix resolution (the "unique prefix" contract).

Every group in the mayhem CLI is a :class:`PrefixGroup`, so abbreviation works
at *every* level of the tree, not just the root: ``mayhem e s`` resolves to
``experiment show`` because ``s`` is unambiguous inside ``experiment``.

Resolution rules, applied per level:

1. exact name wins;
2. otherwise collect all commands whose names start with the given prefix;
3. exactly one candidate -> resolved;
4. zero candidates -> usage error with close-match suggestions;
5. multiple candidates -> educational ambiguity error listing every match.

Prefix resolution happens strictly before any callback runs, so a shorthand
invocation can never bypass validation or safety gates — it dispatches to the
identical handler object.
"""

from __future__ import annotations

import difflib
from typing import Any

import click

PREFIX_HELP = (
    "Commands may be abbreviated to any unique prefix at every level of this "
    "tree (e.g. 'mayhem run' or 'mayhem man'). Exact names and "
    "'--help' always work."
)


class CommandResolutionError(click.UsageError):
    """A command token could not resolve to exactly one command."""

    def __init__(self, token: str, candidates: tuple[str, ...]) -> None:
        self.token = token
        self.candidates = candidates
        super().__init__(self._render(), ctx=None)

    def _render(self) -> str:
        if not self.candidates:
            difflib.get_close_matches(self.token, [], n=1)
            return f"No command matches {self.token!r}."
        lines = "\n".join(f"  - {name}" for name in self.candidates)
        return (
            f"Command prefix {self.token!r} is ambiguous; it matches "
            f"{len(self.candidates)} commands:\n{lines}\n"
            "Use a longer prefix to select one of them."
        )


class PrefixGroup(click.Group):
    """A Click Group whose subcommands resolve by unique prefix."""

    # Click's Group signature is keyword-heavy and open-ended; `Any` is the
    # documented way to forward it in a subclass. `object` here was a lie that
    # cost nine downstream arg-type errors at the super() call.
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.hidden_commands: set[str] = set()

    def hide_command(self, name: str) -> None:
        self.hidden_commands.add(name)

    def list_commands(self, ctx: click.Context) -> list[str]:
        return sorted(name for name in self.commands if name not in self.hidden_commands)

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        exact = super().get_command(ctx, cmd_name)
        if exact is not None:
            return exact
        candidates = sorted(name for name in self.list_commands(ctx) if name.startswith(cmd_name))
        if len(candidates) == 1:
            return super().get_command(ctx, candidates[0])
        if not candidates:
            raise CommandResolutionError(cmd_name, ())
        raise CommandResolutionError(cmd_name, tuple(candidates))


def make_group(name: str, help_text: str, **attrs: object) -> PrefixGroup:
    """Factory so nested groups inherit prefix resolution automatically."""
    attrs.setdefault("help", help_text)
    attrs.setdefault("epilog", PREFIX_HELP)
    return PrefixGroup(name=name, **attrs)
