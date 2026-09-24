from __future__ import annotations

from dataclasses import dataclass

import click


@dataclass(frozen=True, slots=True)
class DeprecationInfo:
    name: str
    since: str
    replacement: str
    reason: str
    aliases: tuple[str, ...] = ()
    removal: str = ""


DEPRECATIONS: dict[str, DeprecationInfo] = {
    "validate": DeprecationInfo(
        name="validate",
        since="0.6.0",
        replacement="prepare validate",
        reason="workflow grouping",
        aliases=("v",),
        removal="0.8.0",
    ),
    "plan": DeprecationInfo(
        name="plan",
        since="0.6.0",
        replacement="prepare plan",
        reason="workflow grouping",
        removal="0.8.0",
    ),
    "dependency": DeprecationInfo(
        name="dependency",
        since="0.6.0",
        replacement="prepare dependencies or extend dependencies",
        reason="workflow grouping",
        removal="0.8.0",
    ),
    "topology": DeprecationInfo(
        name="topology",
        since="0.6.0",
        replacement="discover topology",
        reason="workflow grouping",
        removal="0.8.0",
    ),
    "toolkit": DeprecationInfo(
        name="toolkit",
        since="0.6.0",
        replacement="discover faults / discover capabilities / extend",
        reason="workflow grouping",
        removal="0.8.0",
    ),
    "config": DeprecationInfo(
        name="config",
        since="0.6.0",
        replacement="prepare config",
        reason="workflow grouping",
        aliases=("cfg",),
        removal="0.8.0",
    ),
    "status": DeprecationInfo(
        name="status",
        since="0.6.0",
        replacement="inspect runs",
        reason="workflow grouping",
        removal="0.8.0",
    ),
    "history": DeprecationInfo(
        name="history",
        since="0.6.0",
        replacement="inspect run",
        reason="workflow grouping",
        removal="0.8.0",
    ),
    "coverage": DeprecationInfo(
        name="coverage",
        since="0.6.0",
        replacement="inspect coverage",
        reason="workflow grouping",
        removal="0.8.0",
    ),
    "next": DeprecationInfo(
        name="next",
        since="0.6.0",
        replacement="inspect next",
        reason="workflow grouping",
        removal="0.8.0",
    ),
    "expert": DeprecationInfo(
        name="expert",
        since="0.6.0",
        replacement="inspect expert",
        reason="workflow grouping",
        removal="0.8.0",
    ),
    "explore": DeprecationInfo(
        name="explore",
        since="0.6.0",
        replacement="inspect next / prepare plan + run",
        reason="workflow grouping",
        removal="0.8.0",
    ),
}


ALIAS_TO_CANONICAL: dict[str, str] = {
    "v": "validate",
    "cfg": "config",
}


def warn_deprecated(command: str) -> None:
    canonical = ALIAS_TO_CANONICAL.get(command, command)
    info = DEPRECATIONS.get(canonical)
    if info is None and command in ALIAS_TO_CANONICAL:
        target = ALIAS_TO_CANONICAL[command]
        info = DEPRECATIONS.get(target)
        if info is not None:
            msg = (
                f"warning: alias '{command}' is deprecated since "
                f"{info.since}; use '{info.replacement}'"
            )
            click.echo(msg, err=True)
            return
    if info is None:
        return
    if command in info.aliases:
        msg = (
            f"warning: alias '{command}' is deprecated since "
            f"{info.since}; use '{info.replacement}'"
        )
        click.echo(msg, err=True)
    else:
        msg = (
            f"warning: command '{command}' is deprecated since "
            f"{info.since}; use '{info.replacement}'"
        )
        click.echo(msg, err=True)


def deprecation_for(command: str) -> DeprecationInfo | None:
    if command in ALIAS_TO_CANONICAL:
        return DEPRECATIONS.get(ALIAS_TO_CANONICAL[command])
    return DEPRECATIONS.get(command)


def all_deprecations() -> list[DeprecationInfo]:
    return sorted(DEPRECATIONS.values(), key=lambda d: d.name)


def sample_invocation(info: DeprecationInfo) -> str:
    return f"mayhem {info.replacement}"
