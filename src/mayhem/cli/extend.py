from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import click

from mayhem.cli.resolver import make_group
from mayhem.domain.provider import ProviderError, ProviderPermission
from mayhem.providers.loader import ProviderLoader

if TYPE_CHECKING:
    from mayhem.providers.loader import ProviderLoadReport

providers = make_group("providers", "Inspect and explicitly load provider extensions.")
_PERMISSION_VALUES = tuple(permission.value for permission in ProviderPermission)

#: Help text for the one flag that turns a refusal off.
#:
#: **Without this flag there is no way to load a provider that declares any
#: permission.** The loader denies by default — see
#: :data:`~mayhem.providers.loader.DEFAULT_REQUIRE_SANDBOX_ENFORCEMENT` — because
#: this build applies no seccomp filter, AppArmor profile, SELinux label or
#: container, so a provider declaring a permission runs unconfined. That decision
#: is right and it stands. What was missing is not the refusal but the other half
#: of it: the refusal text tells the operator to "load it without sandbox
#: enforcement", and before this flag there was no such command to type. Deny by
#: default is a posture; deny with no escape hatch is a lockout, and an operator
#: who cannot load the provider at all will reach for the environment variable or
#: the patch instead of a documented flag.
#:
#: So the opt-out exists, and it is deliberately *loud* rather than convenient:
#:
#: * **Explicit only.** No inference, no auto-downgrade, no "the provider looks
#:   harmless" heuristic. ``--allow-permission`` grants a *permission*;
#:   ``--allow-unsandboxed`` gives up a *mechanism*, and it takes a second,
#:   differently-named flag to say so.
#: * **Not silent.** The loader records every admission, and one made under this
#:   flag is sealed as ``ACKNOWLEDGED_NO_BACKEND`` with the profile's unapplied
#:   mechanism list, so "we ran it unconfined" is a fact in the evidence chain
#:   rather than an absence anyone has to notice.
#: * **Not free.** It does not make the provider safe, make the permission
#:   granted, or make mayhem confine anything. It removes the refusal and only
#:   the refusal. ``--allow-permission`` is still required for whatever the
#:   declaration asks for, and a provider declaring a permission nobody granted
#:   is still refused for that reason.
#:
#: The name follows the ``--allow-*`` family this surface already uses for
#: decisions that admit something the default refuses (``--allow-permission``,
#: ``--allow-development-only`` in ``mayhem pack``), rather than the ``--no-*``
#: spelling used for cosmetic switches: this is a trust decision and the command
#: line should read as one.
_UNSANDBOXED_HELP = (
    "Load the provider with sandbox enforcement DISABLED. Without this flag, a "
    "provider that declares any permission is refused "
    "(provider_sandbox_mechanism_unapplied), because this mayhem build applies no "
    "confinement mechanism at all — no seccomp, AppArmor, SELinux or container — so "
    "it would run unconfined. This flag does not grant the declared permission "
    "(--allow-permission still does that), does not make the provider safe, and "
    "does not confine anything: it removes that one refusal, and the unconfined "
    "admission is recorded in the evidence chain as ACKNOWLEDGED_NO_BACKEND."
)


def _report(
    report: ProviderLoadReport,
    *,
    as_json: bool,
) -> None:
    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return
    for provider in report.providers:
        click.echo(
            f"{provider.provider_id:<24} {provider.status:<8} "
            f"version={(provider.metadata or {}).get('version', '?')} source={provider.source}"
        )
        # Permissions are printed for every inspection, including the
        # metadata-only one: an operator has to be able to see what a
        # third-party provider asks for *before* any of its implementation
        # code is loaded, and the default posture — a declaration that asks
        # for nothing — is only visible if the empty case prints too.
        permissions = (provider.metadata or {}).get("permissions")
        if isinstance(permissions, list):
            names = ", ".join(str(name) for name in permissions) or "none (default posture)"
            click.echo(f"  permissions: {names}")
        if provider.error is not None:
            click.echo(f"  {provider.error.code}: {provider.error.message}")
    click.echo(f"loaded={len(report.loaded)} failures={len(report.failures)}")


def _load_report(
    *,
    catalog: Path | None,
    entry_points: tuple[str, ...],
    allowed_permissions: tuple[str, ...],
    load_implementations: bool,
    allow_unsandboxed: bool,
) -> ProviderLoadReport:
    if catalog is not None and entry_points:
        raise click.UsageError("choose either --catalog or --entry-point")
    loader = ProviderLoader(
        allowed_permissions=frozenset(ProviderPermission(value) for value in allowed_permissions),
        require_sandbox_enforcement=not allow_unsandboxed,
    )
    if catalog is not None:
        if load_implementations:
            return loader.load_catalog(catalog)
        return loader.inspect_catalog(catalog)
    if load_implementations:
        return loader.load_entry_points(entry_points)
    return loader.inspect_entry_points(entry_points)


def _invoke(
    *,
    catalog: Path | None,
    entry_points: tuple[str, ...],
    allowed_permissions: tuple[str, ...],
    as_json: bool,
    load_implementations: bool,
    allow_unsandboxed: bool,
) -> None:
    try:
        report = _load_report(
            catalog=catalog,
            entry_points=entry_points,
            allowed_permissions=allowed_permissions,
            load_implementations=load_implementations,
            allow_unsandboxed=allow_unsandboxed,
        )
    except (ProviderError, OSError, ValueError) as exc:
        click.echo(f"provider rejected: {exc}", err=True)
        raise click.ClickException(str(exc)) from exc
    _report(report, as_json=as_json)
    if report.failures:
        raise click.ClickException("one or more providers failed to load")


def _source_options(function: click.decorators.FC) -> click.decorators.FC:
    function = click.option(
        "--catalog",
        type=click.Path(path_type=Path, exists=True, dir_okay=False),
        default=None,
        help="Explicit provider catalog to inspect.",
    )(function)
    return click.option(
        "--entry-point",
        "entry_points",
        multiple=True,
        help="Explicit provider id to inspect; repeatable.",
    )(function)


def _trust_options(function: click.decorators.FC) -> click.decorators.FC:
    """The two options that decide what a third party is allowed to reach for.

    Both grant, so they belong together and neither implies the other:
    ``--allow-permission`` hands a provider a declared capability, and
    ``--allow-unsandboxed`` stops mayhem refusing on a mechanism this build does
    not have. One without the other is still a refusal — for a different reason —
    which is the point of keeping them as two named flags rather than one
    "trust this provider" switch.
    """
    function = click.option(
        "--allow-permission",
        "allowed_permissions",
        multiple=True,
        type=click.Choice(_PERMISSION_VALUES),
        help="Permission granted for implementation loading; repeatable.",
    )(function)
    return click.option(
        "--allow-unsandboxed",
        "allow_unsandboxed",
        is_flag=True,
        default=False,
        help=_UNSANDBOXED_HELP,
    )(function)


def _json_option(function: click.decorators.FC) -> click.decorators.FC:
    return click.option(
        "--json",
        "as_json",
        is_flag=True,
        help="Emit machine-readable output.",
    )(function)


@providers.command("inspect")
@_source_options
@_trust_options
@_json_option
def inspect_providers(
    catalog: Path | None,
    entry_points: tuple[str, ...],
    allowed_permissions: tuple[str, ...],
    allow_unsandboxed: bool,
    as_json: bool,
) -> None:
    """Validate provider metadata without loading implementation code."""
    _invoke(
        catalog=catalog,
        entry_points=entry_points,
        allowed_permissions=allowed_permissions,
        as_json=as_json,
        load_implementations=False,
        allow_unsandboxed=allow_unsandboxed,
    )


@providers.command("load")
@_source_options
@_trust_options
@_json_option
def load_providers(
    catalog: Path | None,
    entry_points: tuple[str, ...],
    allowed_permissions: tuple[str, ...],
    allow_unsandboxed: bool,
    as_json: bool,
) -> None:
    """Load explicitly selected providers after metadata and permission checks."""
    _invoke(
        catalog=catalog,
        entry_points=entry_points,
        allowed_permissions=allowed_permissions,
        as_json=as_json,
        load_implementations=True,
        allow_unsandboxed=allow_unsandboxed,
    )
