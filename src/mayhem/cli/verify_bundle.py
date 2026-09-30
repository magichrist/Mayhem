"""``mayhem bundle build|show|verify PATH`` — portable evidence bundles.

``verify`` deliberately touches no database, no cluster, and no runtime: it
reads a bundle directory and re-derives every hash from the bytes on disk.

``build`` is the one verb that does read the local store. It exists because the
group advertised "Build and verify" while offering only ``show`` and
``verify`` — mayhem shipped a verifier for bundles it could not produce, and
advertised the producer in its own ``--help``. Evidence bundles are the
feature mayhem differentiates on; an unproducible bundle is a dead feature
with a working parser in front of it.
"""

from __future__ import annotations

import click

from mayhem.cli.context import CliContext
from mayhem.cli.resolver import make_group


def _ctx(ctx: click.Context) -> CliContext:
    obj = ctx.obj
    return obj if isinstance(obj, CliContext) else CliContext()


bundle_cmd = make_group("bundle", "Build and verify portable evidence bundles.")


@bundle_cmd.command("verify")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def verify(path: str, as_json: bool) -> None:
    """Verify a bundle's schema, hashes, chain order, signature, and redaction."""
    from mayhem.domain.evidence_bundle import BundleVerificationError, verify_bundle
    from mayhem.infra.evidence_bundle_io import load_bundle

    try:
        bundle = load_bundle(path)
    except BundleVerificationError as exc:
        from mayhem.cli.output import echo_machine

        if not echo_machine({"valid": False, "errors": [str(exc)]}, as_json=as_json):
            click.echo(f"unreadable bundle: {exc}", err=True)
        raise SystemExit(1) from exc

    from mayhem.cli.output import echo_machine

    result = verify_bundle(bundle)
    if not echo_machine(result.to_dict(), as_json=as_json):
        click.echo(
            f"bundle valid: {str(result.valid).lower()} "
            f"(signed={str(result.signed).lower()}, "
            f"artifacts={result.artifacts_checked}, "
            f"root {result.root_digest[:12]})"
        )
        for error in result.errors:
            click.echo(f"  error: {error}", err=True)
        for warning in result.warnings:
            click.echo(f"  warning: {warning}", err=True)
    if not result.valid:
        raise SystemExit(1)


@bundle_cmd.command("show")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def show(path: str, as_json: bool) -> None:
    """Print a bundle's manifest without verifying it."""
    from mayhem.domain.evidence_bundle import BundleVerificationError
    from mayhem.infra.evidence_bundle_io import load_bundle

    try:
        bundle = load_bundle(path)
    except BundleVerificationError as exc:
        click.echo(f"unreadable bundle: {exc}", err=True)
        raise SystemExit(1) from exc
    from mayhem.cli.output import echo_machine

    if echo_machine(bundle.manifest.to_dict(), as_json=as_json):
        return
    click.echo(
        f"bundle schema {bundle.manifest.schema_version}, root {bundle.manifest.root_digest[:12]}"
    )
    for artifact in bundle.manifest.artifacts:
        click.echo(f"  {artifact['name']:<22} {artifact['digest'][:12]}")


@bundle_cmd.command("build")
@click.argument("run_id")
@click.option("--out", "out", required=True, type=click.Path(), help="Bundle directory to write.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def build(ctx: click.Context, run_id: str, out: str, db_opt: str | None, as_json: bool) -> None:
    """Assemble a portable, hash-chained evidence bundle for a recorded run.

    Reads the local store only. The bundle is self-contained afterwards:
    `mayhem bundle verify` needs nothing but the directory.
    """
    from mayhem.cli.services import open_store
    from mayhem.domain.evidence_bundle import build_bundle
    from mayhem.infra.evidence import load_evidence
    from mayhem.infra.evidence_bundle_io import write_bundle

    # Same resolution as every other store-backed command: an explicit --db,
    # else the context's configured database.
    store = open_store(db_opt or _ctx(ctx).db)
    envelope = load_evidence(store, run_id)
    if envelope is None:
        click.echo(
            f"no evidence envelope recorded for run {run_id!r}; "
            "a bundle can only be built from a run that has one",
            err=True,
        )
        raise SystemExit(1) from None

    replay: dict[str, object] | None = None
    try:
        from mayhem.infra.replay_repository import ReplayRepository

        capsule = ReplayRepository(store).load(run_id)
        replay = None if capsule is None else capsule.model_dump(mode="json")
    except Exception:  # a missing capsule narrows the bundle, it does not fail it
        replay = None

    bundle = build_bundle(
        evidence=envelope.model_dump(mode="json"),
        replay=replay,
        previous_root="",
    )
    target = write_bundle(bundle, out)

    from mayhem.cli.output import echo_machine

    manifest = bundle.manifest
    if not echo_machine(
        {"run_id": run_id, "path": str(target), "root_digest": manifest.root_digest},
        as_json=as_json,
    ):
        click.echo(f"wrote {target} (root {manifest.root_digest[:12]})")
        click.echo(f"verify with: mayhem bundle verify {target}")
