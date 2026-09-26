"""``mayhem verify bundle PATH`` — offline evidence bundle verification.

This command deliberately touches no database, no cluster, and no runtime: it
reads a bundle directory and re-derives every hash from the bytes on disk.
"""

from __future__ import annotations

import json

import click

from mayhem.cli.resolver import make_group

verify_bundle_cmd = make_group(
    "verify-bundle", "Verify a portable evidence bundle offline."
)


@verify_bundle_cmd.command("check")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def check(path: str, as_json: bool) -> None:
    """Verify a bundle's schema, hashes, chain order, signature, and redaction."""
    from mayhem.domain.evidence_bundle import BundleVerificationError, load_bundle, verify_bundle

    try:
        bundle = load_bundle(path)
    except BundleVerificationError as exc:
        if as_json:
            click.echo(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2))
        else:
            click.echo(f"unreadable bundle: {exc}", err=True)
        raise SystemExit(1) from exc

    result = verify_bundle(bundle)
    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
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


@verify_bundle_cmd.command("show")
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
    if as_json:
        click.echo(json.dumps(bundle.manifest.to_dict(), indent=2, sort_keys=True))
        return
    click.echo(f"bundle schema {bundle.manifest.schema_version}, root {bundle.manifest.root_digest[:12]}")
    for artifact in bundle.manifest.artifacts:
        click.echo(f"  {artifact['name']:<22} {artifact['digest'][:12]}")
