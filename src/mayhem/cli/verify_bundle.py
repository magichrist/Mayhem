"""``mayhem bundle verify PATH`` — offline evidence bundle verification.

This command deliberately touches no database, no cluster, and no runtime: it
reads a bundle directory and re-derives every hash from the bytes on disk.
"""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group

bundle_cmd = make_group("bundle", "Build and verify portable evidence bundles.")


@bundle_cmd.command("verify")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def verify(path: str, as_json: bool) -> None:
    """Verify a bundle's schema, hashes, chain order, signature, and redaction."""
    from mayhem.domain.evidence_bundle import BundleVerificationError, load_bundle, verify_bundle

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
    from mayhem.domain.evidence_bundle import BundleVerificationError, load_bundle

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
