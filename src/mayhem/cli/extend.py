from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import click

from mayhem.cli.resolver import make_group
from mayhem.domain.provider import ProviderPermission
from mayhem.providers.loader import ProviderError, ProviderLoader

if TYPE_CHECKING:
    from mayhem.providers.loader import ProviderLoadReport

providers = make_group("providers", "Inspect and explicitly load provider extensions.")
_PERMISSION_VALUES = tuple(permission.value for permission in ProviderPermission)


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
            f"version={provider.metadata.get('version', '?')} source={provider.source}"
        )
        if provider.error is not None:
            click.echo(f"  {provider.error.code}: {provider.error.message}")
    click.echo(f"loaded={len(report.loaded)} failures={len(report.failures)}")


def _load_report(
    *,
    catalog: Path | None,
    entry_points: tuple[str, ...],
    allowed_permissions: tuple[str, ...],
    load_implementations: bool,
) -> ProviderLoadReport:
    if catalog is not None and entry_points:
        raise click.UsageError("choose either --catalog or --entry-point")
    loader = ProviderLoader(
        allowed_permissions=frozenset(ProviderPermission(value) for value in allowed_permissions)
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
) -> None:
    try:
        report = _load_report(
            catalog=catalog,
            entry_points=entry_points,
            allowed_permissions=allowed_permissions,
            load_implementations=load_implementations,
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


def _permission_option(function: click.decorators.FC) -> click.decorators.FC:
    return click.option(
        "--allow-permission",
        "allowed_permissions",
        multiple=True,
        type=click.Choice(_PERMISSION_VALUES),
        help="Permission granted for implementation loading; repeatable.",
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
@_permission_option
@_json_option
def inspect_providers(
    catalog: Path | None,
    entry_points: tuple[str, ...],
    allowed_permissions: tuple[str, ...],
    as_json: bool,
) -> None:
    """Validate provider metadata without loading implementation code."""
    _invoke(
        catalog=catalog,
        entry_points=entry_points,
        allowed_permissions=allowed_permissions,
        as_json=as_json,
        load_implementations=False,
    )


@providers.command("load")
@_source_options
@_permission_option
@_json_option
def load_providers(
    catalog: Path | None,
    entry_points: tuple[str, ...],
    allowed_permissions: tuple[str, ...],
    as_json: bool,
) -> None:
    """Load explicitly selected providers after metadata and permission checks."""
    _invoke(
        catalog=catalog,
        entry_points=entry_points,
        allowed_permissions=allowed_permissions,
        as_json=as_json,
        load_implementations=True,
    )
