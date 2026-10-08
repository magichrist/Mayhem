"""``mayhem marketplace`` — plan 18 Phase 3: search, inspect, and install catalog artifacts.

The surface over the Phase 2 engine (:mod:`mayhem.infra.marketplace_store`),
and deliberately a thin one:

* ``mayhem marketplace list`` / ``search`` — read-only rows over
  :meth:`~mayhem.infra.marketplace_store.MarketplaceRegistry.listing`. A
  private registry is listed through the same call with its own id, because
  federation is distribution, not standing.
* ``mayhem marketplace inspect`` — read-only detail for one pinned version via
  :meth:`~mayhem.infra.marketplace_store.MarketplaceRegistry.resolve`: the
  declared permissions **before** install, the certification states the label
  is derived from, the cells that evidence covers, and every reason the
  artifact may not back a new approval. It never calls ``verify_bytes`` —
  that method *records* a digest verdict, so it is a write, and an inspect
  that wrote would not be read-only.
* ``mayhem marketplace install`` — the one mutating verb, straight through to
  :meth:`~mayhem.infra.marketplace_store.MarketplaceRegistry.install`, which
  is where the gates live (pin digest, observed bytes, deprecation,
  revocation, supply-chain record). This command adds no second policy.

Two honesty properties, both structural rather than promised:

* Every rendering of a trust class travels with
  :data:`~mayhem.domain.marketplace.SIGNATURE_TRUST_NOTICE` in the same
  breath — the class word is never printed without the qualification beside
  it, in text and in JSON.
* Permissions shown are the artifact's *declared* set
  (``sorted(p.value for p in artifact.permissions)``, the plan-17 provider
  vocabulary), reported exactly as stored. A declared permission is not a
  grant, and install does not grant one: the grant lives with the provider
  loader, and nothing here writes it.
* ``--digest`` (what the caller intends to install) and ``--observed-digest``
  (the sha256 of the bytes actually in hand) are separate required options on
  purpose. Collapsing them is how "we checked the digest" becomes a claim
  about a file nobody hashed — the engine keeps them apart, so this surface
  does too. Hash the bytes first (e.g. ``sha256sum``), then install.

What this surface does not do: no signature is checked, anywhere.
``signature_verification_implemented`` is ``False`` in text and JSON alike,
and a compatibility *verdict* needs a cell this command does not invent —
inspect reports the cells the evidence was made on instead, and install
checks compatibility only when its caller supplies a cell.
"""

from __future__ import annotations

import json
from typing import Any

import click

from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.domain.marketplace import SIGNATURE_TRUST_NOTICE

marketplace = make_group(
    "marketplace",
    "Search, inspect, and install catalog artifacts.",
)


def _ctx(ctx: click.Context) -> CliContext:
    obj = ctx.obj
    return obj if isinstance(obj, CliContext) else CliContext()


def _registry(ctx: click.Context, db_opt: str | None) -> tuple[Any, Any]:
    """The store and the registry over it. The caller closes the store."""
    from mayhem.cli.services import open_store
    from mayhem.infra.marketplace_store import MarketplaceRegistry, MarketplaceStore
    from mayhem.providers.loader import ProviderLoader

    store = open_store(db_opt or _ctx(ctx).db)
    return store, MarketplaceRegistry(store=MarketplaceStore(store), loader=ProviderLoader())


def _echo(payload: dict[str, Any], as_json: bool) -> bool:
    from mayhem.cli.output import echo_machine

    return echo_machine(payload, as_json=as_json)


def _fail(ctx: click.Context, message: str, code: ExitCode = ExitCode.GENERAL_FAILURE) -> None:
    click.echo(f"error: {message}", err=True)
    ctx.exit(int(code))


def _refusal(ctx: click.Context, exc: Exception, payload: dict[str, Any] | None) -> None:
    """A refusal is a readable reason plus the evidence, never a traceback."""
    from mayhem.cli.output import echo_machine
    from mayhem.domain.marketplace import TrustLabelError
    from mayhem.infra.marketplace_store import MarketplaceError

    if isinstance(exc, (MarketplaceError, TrustLabelError)):
        code = getattr(exc, "code", "marketplace.refused")
        message = f"refused [{code}]: {exc}"
        if payload is not None and echo_machine(payload, as_json=True):
            ctx.exit(int(ExitCode.SAFETY_REFUSAL))
        click.echo(message, err=True)
        if payload is not None:
            click.echo(json.dumps(payload, indent=2, sort_keys=True), err=True)
        ctx.exit(int(ExitCode.SAFETY_REFUSAL))
    raise exc


def _row_lines(entry: Any) -> list[str]:
    """One listing row: the class word with its meaning in the same breath."""
    artifact = entry.artifact
    label = entry.label
    permissions = ", ".join(sorted(p.value for p in artifact.permissions)) or "none declared"
    states = ", ".join(sorted({str(state) for state in label.certified_states})) or "-"
    faults = ", ".join(label.certified_fault_ids) or "-"
    return [
        f"{artifact.ref}  digest {artifact.digest[:12]}  registry {artifact.registry.registry_id}",
        f"  class       {label.artifact_class.value}: {label.meaning()}",
        f"  permissions (declared, not granted): {permissions}",
        f"  certified   states [{states}] faults [{faults}]",
        f"  deprecated  {'yes' if artifact.is_deprecated else 'no'}"
        + (f" ({artifact.deprecation.reason})" if artifact.deprecation else ""),
        f"  NOTE: {SIGNATURE_TRUST_NOTICE}",
    ]


def _filtered_listing(registry: Any, *, query: str, registry_id: str) -> tuple[Any, ...]:
    entries: tuple[Any, ...] = registry.listing(registry_id=registry_id)
    if query:
        lowered = query.lower()
        entries = tuple(
            entry
            for entry in entries
            if lowered in entry.artifact.artifact_id.lower()
            or lowered in entry.artifact.version.lower()
        )
    return entries


def _render_listing(
    ctx: click.Context,
    entries: tuple[Any, ...],
    *,
    query: str,
    registry_id: str,
    as_json: bool,
) -> None:
    payload: dict[str, Any] = {
        "query": query,
        "registry_id": registry_id,
        "count": len(entries),
        "entries": [entry.to_dict() for entry in entries],
        "signature_verification_implemented": False,
        "notice": SIGNATURE_TRUST_NOTICE,
    }
    if _echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    if not entries:
        click.echo("no catalog artifacts match.")
        click.echo(f"NOTE: {SIGNATURE_TRUST_NOTICE}")
        ctx.exit(int(ExitCode.SUCCESS))
    for entry in entries:
        for line in _row_lines(entry):
            click.echo(line)
        click.echo("")
    ctx.exit(int(ExitCode.SUCCESS))


@marketplace.command("list")
@click.option(
    "--registry-id",
    "registry_id",
    default="",
    help="Only rows published to this registry (private registries use the same call).",
)
@click.option(
    "--query",
    default="",
    help="Substring filter over artifact id and version.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def list_cmd(
    ctx: click.Context,
    registry_id: str,
    query: str,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """List catalog artifacts with the label each one's records support."""
    from mayhem.infra.marketplace_store import MarketplaceError

    store, registry = _registry(ctx, db_opt)
    try:
        entries = _filtered_listing(registry, query=query, registry_id=registry_id)
    except MarketplaceError as exc:
        _fail(ctx, str(exc), ExitCode.VALIDATION_ERROR)
    finally:
        store.close()
    _render_listing(ctx, entries, query=query, registry_id=registry_id, as_json=as_json)


@marketplace.command("search")
@click.argument("query")
@click.option(
    "--registry-id",
    "registry_id",
    default="",
    help="Only rows published to this registry (private registries use the same call).",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def search_cmd(
    ctx: click.Context,
    query: str,
    registry_id: str,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Search the catalog: a substring over artifact id and version.

    Read-only. Each row carries the derived class with its meaning, the
    declared permissions, and the certification states — the same facts
    ``inspect`` shows one at a time.
    """
    from mayhem.infra.marketplace_store import MarketplaceError

    store, registry = _registry(ctx, db_opt)
    try:
        entries = _filtered_listing(registry, query=query, registry_id=registry_id)
    except MarketplaceError as exc:
        _fail(ctx, str(exc), ExitCode.VALIDATION_ERROR)
    finally:
        store.close()
    _render_listing(ctx, entries, query=query, registry_id=registry_id, as_json=as_json)


@marketplace.command("inspect")
@click.argument("artifact_id")
@click.option("--version", required=True, help="Exact version; pins never float.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def inspect_cmd(
    ctx: click.Context,
    artifact_id: str,
    version: str,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Show everything the catalog knows before an install: permissions,
    certification states, compatibility evidence, and approval refusals.

    Read-only: resolves the pin and derives the label, and records nothing.
    """
    from mayhem.infra.marketplace_store import MarketplaceError

    store, registry = _registry(ctx, db_opt)
    try:
        pin = registry.resolve(artifact_id, version=version)
        artifact = pin.artifact
        label = pin.label
        refusals = registry.approval_gate(artifact)
        blocking = registry.store.blocking(artifact, now=label.evaluated_at)
        pending = registry.store.pending(artifact, now=label.evaluated_at)
        supply_chain = pin.supply_chain
        federation = registry.federation()
    except MarketplaceError as exc:
        store.close()
        _fail(ctx, str(exc), ExitCode.VALIDATION_ERROR)
    store.close()

    permissions = sorted(p.value for p in artifact.permissions)
    evidence = [
        {
            "fault_id": cert.record.fault_id,
            "state": cert.record.state.value,
            "cell": cert.record.cell.label,
            "cell_fingerprint": cert.record.cell.fingerprint,
            "expires_at": cert.record.expires_at.isoformat(),
        }
        for cert in label.certifications
    ]
    payload: dict[str, Any] = {
        "artifact_id": artifact.artifact_id,
        "version": artifact.version,
        "digest": artifact.digest,
        "registry_id": artifact.registry.registry_id,
        "registry_scope": artifact.registry.scope.value,
        "federated": (
            federation.contains(artifact.registry.registry_id) if federation is not None else False
        ),
        "federation_size": len(federation.registry_ids) if federation is not None else 0,
        "artifact_class": label.artifact_class.value,
        "meaning": label.meaning(),
        "declared_permissions": permissions,
        "permissions_note": (
            "declared by the artifact, not granted by mayhem; install grants nothing"
        ),
        "certified_fault_ids": list(label.certified_fault_ids),
        "certification_evidence": evidence,
        "may_display_certified_state": label.may_display_certified_state,
        "compatibility_note": (
            "a compatibility verdict needs the runtime cell it is made against, which this "
            "command does not invent; the cells above are the runtimes the evidence was made "
            "on, and install checks compatibility when its caller supplies a cell"
        ),
        "approval_refusals": list(refusals),
        "blocking_revocations": [rev.revocation_id for rev in blocking],
        "pending_revocations": [rev.revocation_id for rev in pending],
        "deprecated": artifact.is_deprecated,
        "deprecation_reason": artifact.deprecation.reason if artifact.deprecation else "",
        "publisher": {
            "publisher_id": artifact.publisher.publisher_id,
            "display_name": artifact.publisher.display_name,
            "notice": artifact.publisher.notice,
        },
        "license_id": artifact.license_id,
        "changelog_ref": artifact.changelog_ref,
        "dependencies": [
            {
                "name": dep.name,
                "constraint": dep.constraint,
                "digest": dep.digest,
                "pinned": dep.pinned,
            }
            for dep in artifact.dependencies
        ],
        "supply_chain": (
            {
                "verification_state": supply_chain.verification_state.value,
                "sbom": (
                    {
                        "format": supply_chain.sbom.format,
                        "digest": supply_chain.sbom.digest,
                    }
                    if supply_chain.sbom is not None
                    else None
                ),
                "release_count": len(supply_chain.release_history),
            }
            if supply_chain is not None
            else None
        ),
        "installed": pin.installed,
        "signature_verification_implemented": False,
        "notice": SIGNATURE_TRUST_NOTICE,
    }
    if _echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    click.echo(f"{artifact.ref}  digest {artifact.digest}")
    click.echo(f"  registry    {artifact.registry.registry_id} ({artifact.registry.scope.value})")
    click.echo(f"  class       {label.artifact_class.value}: {label.meaning()}")
    click.echo(
        "  permissions (declared, not granted): " + (", ".join(permissions) or "none declared")
    )
    if evidence:
        click.echo("  certification evidence (one row per current record for these bytes):")
        for row in evidence:
            click.echo(
                f"    fault {row['fault_id']} state {row['state']} on {row['cell']} "
                f"until {row['expires_at']}"
            )
    else:
        click.echo("  certification evidence: none current for these bytes")
    covered = ", ".join(sorted({row["cell"] for row in evidence}))
    click.echo(
        "  compatibility: no verdict without a runtime cell; evidence covers "
        + (covered if covered else "no cells")
    )
    if refusals:
        click.echo("  approval refusals (this artifact may not back a new approval):")
        for refusal in refusals:
            click.echo(f"    - {refusal}")
    else:
        click.echo("  approval refusals: none")
    if blocking:
        for rev in blocking:
            click.echo(f"  revoked: {rev.revocation_id} ({rev.reason.value}) — {rev.detail}")
    if pending:
        for rev in pending:
            click.echo(
                f"  revocation announced, not yet in force: {rev.revocation_id} "
                f"(in force at {rev.propagation_deadline.isoformat()})"
            )
    if artifact.is_deprecated and artifact.deprecation is not None:
        click.echo(
            f"  deprecated: {artifact.deprecation.reason} "
            f"(replaced by {artifact.deprecation.replaced_by})"
        )
    click.echo(f"  publisher: {artifact.publisher.publisher_id} — {artifact.publisher.notice}")
    click.echo(f"  NOTE: {SIGNATURE_TRUST_NOTICE}")
    ctx.exit(int(ExitCode.SUCCESS))


@marketplace.command("install")
@click.argument("artifact_id")
@click.option("--version", required=True, help="Exact version; pins never float.")
@click.option(
    "--digest",
    required=True,
    help="The digest the caller intends to install (the pin's bytes).",
)
@click.option(
    "--observed-digest",
    required=True,
    help="sha256 of the bytes actually in hand (hash first, e.g. sha256sum).",
)
@click.option(
    "--provider-id",
    required=True,
    help="Provider id whose registration will execute these bytes.",
)
@click.option(
    "--principal",
    default="",
    help="Identity recorded in the privileged-action log; a declaration, not authentication.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def install_cmd(
    ctx: click.Context,
    artifact_id: str,
    version: str,
    digest: str,
    observed_digest: str,
    provider_id: str,
    principal: str,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Install one artifact version: pin exact bytes after the gates pass.

    The gates live in the registry, in order: the pin digest must be the
    published one, the observed bytes must hash to it, the version must not
    be deprecated, and no revocation may be in force. Any refusal names its
    record and exits nonzero; a refused install is sealed as a refusal, not
    as evidence.
    """
    from mayhem.infra.marketplace_store import MarketplaceError

    store, registry = _registry(ctx, db_opt)
    try:
        resolved = registry.install(
            artifact_id,
            version=version,
            digest=digest,
            provider_id=provider_id,
            observed_digest=observed_digest,
            principal=principal,
        )
    except MarketplaceError as exc:
        store.close()
        _refusal(
            ctx,
            exc,
            {
                "artifact_id": artifact_id,
                "version": version,
                "requested_digest": digest,
                "observed_digest": observed_digest,
                "provider_id": provider_id,
                "refusal_code": exc.code,
                "refusal_message": str(exc),
                "signature_verification_implemented": False,
                "notice": SIGNATURE_TRUST_NOTICE,
            },
        )
    store.close()
    artifact = resolved.artifact
    permissions = sorted(p.value for p in artifact.permissions)
    payload: dict[str, Any] = {
        **resolved.to_dict(),
        "declared_permissions": permissions,
        "provider_id": provider_id,
        "integrity_verified": True,
        "signature_verification_implemented": False,
    }
    if _echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    click.echo(f"installed {artifact.ref}#{artifact.digest[:12]} for provider {provider_id!r}")
    click.echo(f"  class       {resolved.artifact_class.value}: {resolved.label.meaning()}")
    click.echo(
        "  permissions (declared, not granted): " + (", ".join(permissions) or "none declared")
    )
    click.echo("  integrity   observed bytes hash to the published digest")
    click.echo(f"  NOTE: {SIGNATURE_TRUST_NOTICE}")
    ctx.exit(int(ExitCode.SUCCESS))
