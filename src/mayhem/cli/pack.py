"""``mayhem pack`` — is this third-party fault pack trustworthy?

Plan 05 step 1: verify and report, install nothing. The command's whole value
is that it is *honest* about what it established, so every rendering of a
verdict carries the same two-axis statement the loader makes:

* the sha256 content digest was (or was not) checked — **integrity**;
* the pack signature was **not** checked, because the pack format declares no
  key, no algorithm, and no trust store — so a signer name is a *claim*.

A refusal exits nonzero with a message naming what to change. There is
deliberately no ``--insecure`` flag: a build that cannot verify a signature has
no business offering to skip that check, because there is nothing to skip.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import click

from mayhem.cli import style
from mayhem.cli.resolver import make_group
from mayhem.providers.loader import PackLoader, builtin_fault_ids
from mayhem.providers.pack import DEVELOPMENT_ONLY_FLAG

if TYPE_CHECKING:
    from mayhem.providers.loader import LoadedPack

pack = make_group(
    "pack",
    "Validate and load third-party fault packs. Reports what was verified and "
    "refuses what was not.",
)


def _granted(permissions: tuple[str, ...]) -> tuple[str, ...]:
    """Resolve ``--allow-permission`` into provider permission names."""
    from mayhem.domain.provider import ProviderPermission

    return tuple(ProviderPermission(name).value for name in permissions)


def _build_loader(
    path: Path,
    *,
    allow_development_only: bool,
    permissions: tuple[str, ...],
) -> PackLoader:
    """A loader whose grants are pinned to the pack's own provider id.

    The id is only knowable from the document, so it is read first. A
    permission the caller named is granted to *that* provider and no other, so
    ``--allow-permission`` on one pack never widens another pack's grant.
    """
    from mayhem.providers.loader import read_pack_document
    from mayhem.providers.permissions import ProviderPermissionSet

    loader = PackLoader(allow_development_only=allow_development_only)
    names = _granted(permissions)
    if not names:
        return loader
    document, _file_digest = read_pack_document(path)
    provider_id = str(document.get("manifest", {}).get("provider_id", ""))
    if provider_id:
        loader.grant(provider_id, ProviderPermissionSet.from_names(provider_id, names))
    return loader


def _load_or_exit(
    path: Path,
    *,
    allow_development_only: bool,
    permissions: tuple[str, ...],
    expected_digest: str,
    require_grant: bool = True,
) -> LoadedPack:
    """Load a pack, turning a refusal into a stable CLI failure.

    A refusal is the *expected* outcome for an untrusted pack, so it is a
    nonzero exit with a readable reason — never a traceback, and never a
    success line.
    """
    from mayhem.providers.pack import PackValidationError
    from mayhem.providers.permissions import SandboxRefusal

    try:
        loader = _build_loader(
            path, allow_development_only=allow_development_only, permissions=permissions
        )
        if require_grant:
            return loader.load_file(path, expected_digest=expected_digest)
        return loader.validate_file(path, expected_digest=expected_digest)
    except (PackValidationError, SandboxRefusal) as exc:
        raise click.ClickException(str(exc)) from exc


def _assurance_lines(loaded: LoadedPack) -> list[str]:
    """The verdict, phrased so no reader can mistake integrity for provenance."""
    assurance = loaded.assurance
    signature = (
        f"NOT VERIFIED (pack claims signer {assurance.signer_claimed!r})"
        if assurance.signature_present
        else "ABSENT (pack is unsigned)"
    )
    digest_note = "yes" if assurance.digest_verified else "no (pack declares no digest)"
    return [
        f"pack            {assurance.provider_id}",
        f"digest          {assurance.digest}",
        f"  verified      {digest_note}",
        f"signature       {signature}",
        f"assurance       {assurance.assurance}",
        f"development     {'yes' if assurance.development_only else 'no'}",
        f"faults          {len(loaded.pack.faults)} contributed, all catalog-only",
        "                (mayhem 1.0 does not plan or execute pack faults)",
        "",
        f"NOTE: {assurance.notice}",
    ]


def _emit(loaded: LoadedPack, *, as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps(loaded.to_dict(), indent=2, sort_keys=True))
        return
    for line in _assurance_lines(loaded):
        click.echo(style.warn(line) if line.startswith("NOTE:") else f"  {line}")


def _trust_options(function: click.decorators.FC) -> click.decorators.FC:
    """The two options every pack verb shares, applied outermost-last."""
    function = click.option(
        "--allow-permission",
        "permissions",
        multiple=True,
        help="Permission granted to this pack's provider; repeatable.",
    )(function)
    return click.option(
        "--allow-development-only",
        is_flag=True,
        default=False,
        help=(
            f"Load an unsigned or development-only pack ({DEVELOPMENT_ONLY_FLAG}). "
            "Grants no signature verification, of which there is none."
        ),
    )(function)


def _shared_options(function: click.decorators.FC) -> click.decorators.FC:
    function = _trust_options(function)
    function = click.option(
        "--expect-digest",
        "expected_digest",
        default="",
        help="Refuse unless the pack content digests to exactly this sha256 hex.",
    )(function)
    return click.option("--json", "as_json", is_flag=True, help="Emit machine-readable output.")(
        function
    )


@pack.command("validate")
@click.argument("path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@_shared_options
def validate_pack(
    path: Path,
    expected_digest: str,
    allow_development_only: bool,
    permissions: tuple[str, ...],
    as_json: bool,
) -> None:
    """Verify a fault pack and report what was and was not established.

    Installs nothing and registers nothing. Use this to decide whether you
    trust a pack before ``mayhem pack load`` touches the provider registry.

    This asks whether the pack is *sound*, which is a read-only question and
    needs no permission grant: every structural, digest, shadowing, and safety
    check is applied. The permission grant is a separate question, asked by
    ``mayhem pack load``.
    """
    _emit(
        _load_or_exit(
            path,
            allow_development_only=allow_development_only,
            permissions=permissions,
            expected_digest=expected_digest,
            require_grant=False,
        ),
        as_json=as_json,
    )


@pack.command("load")
@click.argument("path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--list",
    "as_list",
    is_flag=True,
    help="List the fault ids the pack contributes instead of loading it.",
)
@_shared_options
def load_pack(
    path: Path,
    as_list: bool,
    expected_digest: str,
    allow_development_only: bool,
    permissions: tuple[str, ...],
    as_json: bool,
) -> None:
    """Verify a pack, then register it and list the faults it contributes.

    Registration is in-process and touches no campaign, plan, or database: each
    pack fault becomes a catalog-only entry that the planner refuses with a
    reason. Loading a pack is not approval to inject its faults.
    """
    from mayhem.providers.builtin import create_builtin_registry
    from mayhem.providers.pack import PackValidationError
    from mayhem.providers.permissions import SandboxRefusal

    loaded = _load_or_exit(
        path,
        allow_development_only=allow_development_only,
        permissions=permissions,
        expected_digest=expected_digest,
    )
    registry = create_builtin_registry()
    try:
        loader = _build_loader(
            path, allow_development_only=allow_development_only, permissions=permissions
        )
        loader.register(loaded, registry, reserved_fault_ids=builtin_fault_ids())
    except (PackValidationError, SandboxRefusal) as exc:
        raise click.ClickException(str(exc)) from exc

    payload = {
        **loaded.to_dict(),
        "registry": {
            "provider_ids": sorted(registry.ids()),
            "pack_provider_id": loaded.pack.manifest.provider_id,
            "registered": loaded.pack.manifest.provider_id in registry.ids(),
            "contributed_fault_ids": sorted(d.id for d in loaded.definitions),
        },
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    _emit(loaded, as_json=False)
    if as_list:
        for definition in loaded.definitions:
            click.echo(f"  {definition.id}  risk={definition.risk.value}")
        return
    click.echo(style.ok(f"registered {loaded.pack.manifest.provider_id!r}"))
    for definition in loaded.definitions:
        click.echo(f"  {definition.id}  catalog-only: {definition.refusal_reason}")
