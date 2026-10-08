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

from pathlib import Path
from typing import TYPE_CHECKING

import click

from mayhem.cli.context import CliContext
from mayhem.cli.resolver import make_group

if TYPE_CHECKING:
    # Typing-only: the import stays out of module scope so ``bundle --help`` does
    # no signing work at all. Construction is still lazy, inside ``_key_store``.
    from mayhem.infra.evidence_signing import LocalKeyStore


def _ctx(ctx: click.Context) -> CliContext:
    obj = ctx.obj
    return obj if isinstance(obj, CliContext) else CliContext()


def _key_store(key_dir: str | None) -> LocalKeyStore:
    """The local key store, at ``key_dir`` or the default ``~/.mayhem/keys``.

    Constructed here rather than at module scope so a bare ``bundle --help``
    does no signing-module import work at all, and so listing the group never
    creates a key directory as a side effect. The annotation is satisfied by the
    ``TYPE_CHECKING`` import at the top of the module.
    """
    from mayhem.infra.evidence_signing import LocalKeyStore

    return LocalKeyStore(Path(key_dir) if key_dir else None)


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


# --------------------------------------------------------------------------- #
# Signing                                                                      #
#                                                                           #
# Plan 12 Phase 3: these extend the existing `bundle` group rather than minting #
# a parallel command tree. Key management and signing live here because a key  #
# is evidence custody, and a key created by an untracked command is a key     #
# nobody knows to rotate.                                                     #
# --------------------------------------------------------------------------- #


@bundle_cmd.command("keygen")
@click.argument("key_id")
@click.option(
    "--rotate",
    "rotate",
    is_flag=True,
    help="Replace an existing key's bytes under the same key id.",
)
@click.option("--key-dir", "key_dir", default=None, help="Key directory (default ~/.mayhem/keys).")
@click.option("--note", "note", default="", help="Free-text note stored beside the key.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def keygen(key_id: str, rotate: bool, key_dir: str | None, note: str, as_json: bool) -> None:
    """Create a local signing key with owner-only permissions.

    Refuses to overwrite an existing key id unless ``--rotate`` is given.
    ``create_key`` alone truncates the file in place, so without this guard a
    re-run or a typo would silently destroy the key that every existing
    signature was made with -- and those signatures would then fail to verify
    for a reason that looks like tampering.

    ``--rotate`` keeps the key *id* and replaces the bytes. Existing signatures
    keep verifying against an archived trust root holding the old fingerprint,
    while new ones use the new key; a deployment verifying with only the new key
    reports the old signatures as untrusted, which is the point of rotating.
    """
    from mayhem.cli.output import echo_machine
    from mayhem.infra.evidence_signing import SigningError

    keys = _key_store(key_dir)
    exists = key_id in keys.list_keys()
    if exists and not rotate:
        message = (
            f"key {key_id!r} already exists; refusing to overwrite it because "
            "create_key truncates in place and every signature already made with "
            "this key would stop verifying. Pass --rotate to replace the bytes "
            "deliberately."
        )
        payload = {"created": False, "key_id": key_id, "errors": [message]}
        if not echo_machine(payload, as_json=as_json):
            click.echo(message, err=True)
        raise SystemExit(1)

    try:
        key = keys.rotate_key(key_id, note=note) if rotate else keys.create_key(key_id, note=note)
    except SigningError as exc:
        if not echo_machine(
            {"created": False, "key_id": key_id, "errors": [str(exc)]}, as_json=as_json
        ):
            click.echo(f"refused to write key {key_id!r}: {exc}", err=True)
        raise SystemExit(1) from exc

    # ``create_key``/``rotate_key`` validate the key id as an identifier before
    # writing, so joining here cannot produce a path outside the key directory.
    path = keys.directory / f"{key.key_id}.key"
    payload = {
        "created": not rotate,
        "rotated": rotate,
        "key_id": key.key_id,
        "algorithm": str(key.algorithm),
        "path": str(path),
        # The fingerprint is deliberately absent: an HMAC fingerprint is
        # sha256(secret), so printing one hands a third party an offline
        # dictionary-attack target. The key is identified by its id only.
        "note": note,
    }
    if not echo_machine(payload, as_json=as_json):
        verb = "rotated" if rotate else "created"
        click.echo(f"{verb} key {key.key_id} ({key.algorithm}) at {path}")
        click.echo("permissions are owner-only (0600); the secret is never printed or logged")


@bundle_cmd.command("keys")
@click.option("--key-dir", "key_dir", default=None, help="Key directory (default ~/.mayhem/keys).")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def list_keys(key_dir: str | None, as_json: bool) -> None:
    """List local signing key ids. Never prints key material or fingerprints."""
    from mayhem.cli.output import echo_machine

    keys = _key_store(key_dir).list_keys()
    if not echo_machine({"keys": list(keys), "count": len(keys)}, as_json=as_json):
        if not keys:
            click.echo("no local keys; create one with mayhem bundle keygen KEY_ID")
            return
        for key_id in keys:
            click.echo(f"  {key_id}")


@bundle_cmd.command("sign")
@click.argument("manifest_id")
@click.option("--key", "key_id", required=True, help="Signing key id.")
@click.option(
    "--trust-root",
    "trust_root_id",
    required=True,
    help="Trust root the signature is made under. A signature naming no trust root proves nothing.",
)
@click.option(
    "--algorithm",
    "algorithm",
    default="hmac-sha256",
    help="Signing algorithm. Only hmac-sha256 is implemented; others are refused, not downgraded.",
)
@click.option("--key-dir", "key_dir", default=None, help="Key directory (default ~/.mayhem/keys).")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def sign(
    ctx: click.Context,
    manifest_id: str,
    key_id: str,
    trust_root_id: str,
    algorithm: str,
    key_dir: str | None,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Sign a sealed manifest and record the signature.

    Signs an *already sealed* manifest. Signing a manifest that was never sealed
    would mint a signature over evidence the database never committed, so an
    unknown manifest id is refused rather than signed.
    """
    from mayhem.cli.output import echo_machine
    from mayhem.cli.services import open_store
    from mayhem.infra.evidence_signing import (
        KeyStoreBackedVerifier,
        SignatureAlgorithm,
        SignatureRepository,
        SigningError,
        build_trust_store,
        signer_for,
    )

    keys = _key_store(key_dir)
    store = open_store(db_opt or _ctx(ctx).db)
    repo = SignatureRepository(store)

    try:
        # ``signer_for`` loads the key itself, so this also surfaces a missing or
        # world-readable key as a refusal rather than a traceback.
        signer = signer_for(
            keys,
            key_id,
            trust_root_id=trust_root_id,
            algorithm=SignatureAlgorithm(algorithm),
        )
    except (SigningError, ValueError) as exc:
        refusal = {"signed": False, "manifest_id": manifest_id, "errors": [str(exc)]}
        if not echo_machine(refusal, as_json=as_json):
            click.echo(f"refused to sign: {exc}", err=True)
        raise SystemExit(1) from exc

    verifier = KeyStoreBackedVerifier(
        keys, build_trust_store(keys, trust_root_id=trust_root_id, key_ids=[key_id])
    )
    try:
        signature = repo.sign_manifest(manifest_id, signer, verifier=verifier)
    except (SigningError, KeyError) as exc:
        refusal = {"signed": False, "manifest_id": manifest_id, "errors": [str(exc)]}
        if not echo_machine(refusal, as_json=as_json):
            click.echo(f"refused to sign: {exc}", err=True)
        raise SystemExit(1) from exc

    trusted = verifier.trust_root_for(signature) is not None
    payload = {
        "signed": True,
        "manifest_id": manifest_id,
        "key_id": signature.key_id,
        "algorithm": str(signature.algorithm),
        "trust_root_id": signature.trust_root_id,
        "trusted": trusted,
        "signed_digest": signature.signed_digest,
        "signed_at": signature.signed_at,
    }
    if not echo_machine(payload, as_json=as_json):
        click.echo(
            f"signed {manifest_id} with key {signature.key_id} under trust root {trust_root_id}"
        )
        click.echo(f"trusted by this deployment: {str(trusted).lower()}")
        if not trusted:
            click.echo(
                "  note: the signature is valid but this deployment's trust store does not "
                "vouch for the key; it is recorded as signed-but-untrusted, not as verified",
                err=True,
            )


@bundle_cmd.command("signatures")
@click.argument("manifest_id")
@click.option("--key-dir", "key_dir", default=None, help="Key directory (default ~/.mayhem/keys).")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def signatures(
    ctx: click.Context, manifest_id: str, key_dir: str | None, db_opt: str | None, as_json: bool
) -> None:
    """Verify a recorded signature offline and report both verdicts separately.

    ``verified`` means the bytes match; ``trusted`` means this deployment's trust
    store vouches for the key. A signature can be one without the other — for
    instance made by a key since rotated out — and collapsing them into a single
    boolean would hide exactly the case an auditor needs to see.
    """
    from mayhem.cli.output import echo_machine
    from mayhem.cli.services import open_store
    from mayhem.infra.evidence_signing import (
        KeyMaterialError,
        KeyStoreBackedVerifier,
        SignatureRepository,
        SigningError,
        TrustRoot,
        build_trust_store,
    )

    keys = _key_store(key_dir)
    store = open_store(db_opt or _ctx(ctx).db)
    repo = SignatureRepository(store)

    try:
        manifest = repo.require_manifest(manifest_id)
    except (SigningError, KeyError) as exc:
        if not echo_machine({"manifest_id": manifest_id, "errors": [str(exc)]}, as_json=as_json):
            click.echo(f"cannot verify {manifest_id!r}: {exc}", err=True)
        raise SystemExit(1) from exc

    signature = repo.load_signature(manifest_id)
    # The trust store is derived from this deployment's own keys, under the trust
    # root the signature names. It cannot be left empty: ``verify_signature``
    # refuses to reach a verdict without one ("no trust store: nothing vouches
    # for any key") and would report every sound signature as unverified.
    store_warnings: list[str] = []
    trust_store: tuple[TrustRoot, ...] = ()
    if signature is not None and signature.signed:
        try:
            trust_store = build_trust_store(keys, trust_root_id=signature.trust_root_id)
        except KeyMaterialError as exc:
            # An unreadable or wrongly-permissioned key file must be reported as
            # an unverifiable trust store, not raised as a traceback: it is a
            # fact about the deployment's custody, and the operator needs to read
            # it next to the signature it prevents from verifying.
            store_warnings.append(str(exc))
    verifier = KeyStoreBackedVerifier(keys, trust_store)
    try:
        verdict = verifier.verify_signature(signature, manifest)
    except SigningError as exc:
        if not echo_machine({"manifest_id": manifest_id, "errors": [str(exc)]}, as_json=as_json):
            click.echo(f"cannot verify {manifest_id!r}: {exc}", err=True)
        raise SystemExit(1) from exc

    payload = verdict.to_dict()
    # Fold in what the trust-store construction itself refused. Dropping it
    # would make a wrongly-permissioned key file look like a clean "untrusted"
    # verdict, which is precisely the custody failure an operator must see.
    if store_warnings:
        payload["warnings"] = [*payload.get("warnings", []), *store_warnings]
    if not echo_machine(payload, as_json=as_json):
        click.echo(
            f"{manifest_id}: verified={str(verdict.verified).lower()} "
            f"trusted={str(verdict.trusted).lower()} "
            f"algorithm={verdict.algorithm} key={verdict.key_id or '-'}"
        )
        for error in verdict.errors:
            click.echo(f"  error: {error}", err=True)
        for warning in (*verdict.warnings, *store_warnings):
            click.echo(f"  warning: {warning}", err=True)

    # Exit non-zero only when the bytes did not verify. An untrusted-but-valid
    # signature is a fact to report, not a failure to hide behind an exit code.
    if not verdict.verified:
        raise SystemExit(1)
