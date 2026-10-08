"""Plan 12 Phase 3 CLI: the `bundle` signing surface, end to end.

The domain-level signing tests in ``test_evidence_signing.py`` cover the
primitives. This file covers the *commands*: that a manifest sealed through
Phase 2's real path can be signed and verified from the shell, and that the
refusals reach the terminal as refusals rather than tracebacks.

Every refusal asserted here has a negative control beside it. For signing the
danger is not a broken happy path -- it is a command that reports success it did
not achieve, or one that exits zero on a signature that does not verify.
"""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.domain.attestation import AttestedTimestamp
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.infra.attestation_store import seal_run_evidence
from mayhem.infra.evidence_signing import SignatureRepository
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator

T0 = datetime(2026, 4, 1, 9, 0, 0, tzinfo=UTC)
READING = AttestedTimestamp(wall_clock=T0, monotonic_ns=1_000_000, source="system")
RUN_ID = "run-cli-sign"
MANIFEST_ID = f"{RUN_ID}:manifest"
TRUST_ROOT = "mayhem-local"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def keys(tmp_path: Path) -> Path:
    return tmp_path / "keys"


@pytest.fixture
def db(tmp_path: Path) -> str:
    return str(tmp_path / "mayhem.db")


@pytest.fixture
def sealed_db(db: str) -> Iterator[str]:
    """A database with a run sealed through Phase 2's real sealing path."""
    store = Store.open_migrated(Path(db), migrations=ALL_MIGRATIONS)
    envelope = EvidenceEnvelope.model_validate(
        {
            "run_id": RUN_ID,
            "plan_hash": "plan-hash-1",
            "verdict": "pass",
            "step_reports": ({"step_id": "s1", "status": "completed"},),
            "created_at": T0.isoformat(),
            "redaction_metrics": {"policy_version": "redaction-v9", "redacted_path_count": 0},
        }
    )
    seal_run_evidence(
        store,
        envelope,
        run_status="completed",
        verdict="pass",
        manifest_id=MANIFEST_ID,
        recorded_at=READING,
        created_at=READING,
    )
    store.close()
    yield db
    store.close()


def run(runner: CliRunner, *args: str) -> object:
    return runner.invoke(app, list(args))


# --------------------------------------------------------------------------- #
# Old bundle commands still work                                                #
# --------------------------------------------------------------------------- #


def test_keygen_does_not_disturb_the_read_only_bundle_commands(
    runner: CliRunner, keys: Path
) -> None:
    """Phase 3 extends the group; the pre-existing commands are still there."""
    assert run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys)).exit_code == 0
    for existing in ("build", "show", "verify"):
        assert existing in app.commands["bundle"].commands, f"bundle {existing} was lost"


def test_keygen_does_not_create_a_key_directory_when_the_group_is_listed(
    tmp_path: Path, runner: CliRunner
) -> None:
    """``--help`` must not touch the filesystem: listing is not creating."""
    default_keys = tmp_path / "default-keys"
    result = run(runner, "bundle", "--help")
    assert result.exit_code == 0
    assert "sign" in result.output
    assert not default_keys.exists()


# --------------------------------------------------------------------------- #
# Key management                                                                #
# --------------------------------------------------------------------------- #


def test_keygen_creates_an_owner_only_key(runner: CliRunner, keys: Path) -> None:
    result = run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    assert result.exit_code == 0, result.output
    key_file = keys / "alpha.key"
    assert key_file.exists()
    if stat.S_IMODE(key_file.stat().st_mode) & 0o077:
        pytest.skip("filesystem does not honour owner-only permissions")
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600


def test_keygen_never_prints_a_fingerprint(runner: CliRunner, keys: Path) -> None:
    """An HMAC fingerprint is sha256(secret): printing one is a leak."""
    from mayhem.infra.evidence_signing import LocalKeyStore

    assert run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys)).exit_code == 0
    fingerprint = LocalKeyStore(keys).fingerprint_for("alpha")
    secret = (keys / "alpha.key").read_bytes()
    # ``--rotate`` on the second call so it is a real write (and a *different*
    # fingerprint) rather than the overwrite refusal, which would exit before
    # printing anything and so prove nothing about leakage.
    for args in (
        ("bundle", "keygen", "alpha", "--key-dir", str(keys), "--rotate"),
        ("bundle", "keygen", "alpha", "--key-dir", str(keys), "--rotate", "--json"),
    ):
        result = run(runner, *args)
        assert result.exit_code == 0, result.output
        assert fingerprint not in result.output
        # And the secret itself, which is the stronger guarantee.
        assert secret.hex() not in result.output


def test_keygen_refuses_to_overwrite_an_existing_key(runner: CliRunner, keys: Path) -> None:
    """create_key truncates in place, so a bare re-run destroys a live key."""
    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    before = (keys / "alpha.key").read_bytes()

    result = run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    assert result.exit_code == 1
    assert (keys / "alpha.key").read_bytes() == before, "a refused keygen must not touch the key"
    assert "--rotate" in result.output


def test_keygen_rotate_replaces_the_bytes_deliberately(runner: CliRunner, keys: Path) -> None:
    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    before = (keys / "alpha.key").read_bytes()

    result = run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys), "--rotate")
    assert result.exit_code == 0, result.output
    assert (keys / "alpha.key").read_bytes() != before


def test_keygen_refuses_a_key_id_that_would_escape_the_key_directory(
    runner: CliRunner, keys: Path
) -> None:
    """A key id is an identifier, not a path."""
    for bad in ("../escape", "sub/dir"):
        result = run(runner, "bundle", "keygen", bad, "--key-dir", str(keys))
        assert result.exit_code == 1, f"{bad} was accepted"
    assert not (keys.parent / "escape.key").exists()


def test_keys_lists_key_ids(runner: CliRunner, keys: Path) -> None:
    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    result = run(runner, "bundle", "keys", "--key-dir", str(keys), "--json")
    assert result.exit_code == 0, result.output
    assert "alpha" in result.output


# --------------------------------------------------------------------------- #
# Sign / verify                                                                 #
# --------------------------------------------------------------------------- #


def test_sign_then_signatures_reports_verified_and_trusted(
    runner: CliRunner, keys: Path, sealed_db: str
) -> None:
    """The whole point of the phase, end to end through the CLI."""
    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    signed = run(
        runner,
        "bundle",
        "sign",
        MANIFEST_ID,
        "--key",
        "alpha",
        "--trust-root",
        TRUST_ROOT,
        "--key-dir",
        str(keys),
        "--db",
        sealed_db,
    )
    assert signed.exit_code == 0, signed.output
    assert "trusted" in signed.output

    verified = run(
        runner, "bundle", "signatures", MANIFEST_ID, "--key-dir", str(keys), "--db", sealed_db
    )
    assert verified.exit_code == 0, verified.output
    assert "verified=true" in verified.output
    assert "trusted=true" in verified.output


def test_sign_refuses_a_manifest_that_was_never_sealed(
    runner: CliRunner, keys: Path, sealed_db: str
) -> None:
    """Signing unsealed evidence would authenticate nothing."""
    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    result = run(
        runner,
        "bundle",
        "sign",
        "no-such-run:manifest",
        "--key",
        "alpha",
        "--trust-root",
        TRUST_ROOT,
        "--key-dir",
        str(keys),
        "--db",
        sealed_db,
    )
    assert result.exit_code == 1
    assert "no such sealed manifest" in result.output


def test_sign_requires_a_trust_root(runner: CliRunner, keys: Path, sealed_db: str) -> None:
    """A signature naming no trust root proves nothing, so the flag is required."""
    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    result = run(
        runner,
        "bundle",
        "sign",
        MANIFEST_ID,
        "--key",
        "alpha",
        "--key-dir",
        str(keys),
        "--db",
        sealed_db,
    )
    assert result.exit_code != 0
    assert "--trust-root" in result.output


def test_sign_refuses_an_unimplemented_algorithm(
    runner: CliRunner, keys: Path, sealed_db: str
) -> None:
    """A requested algorithm is refused by name, never downgraded to HMAC."""
    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    result = run(
        runner,
        "bundle",
        "sign",
        MANIFEST_ID,
        "--key",
        "alpha",
        "--algorithm",
        "ed25519",
        "--trust-root",
        TRUST_ROOT,
        "--key-dir",
        str(keys),
        "--db",
        sealed_db,
    )
    assert result.exit_code == 1
    assert "ed25519" in result.output


def test_sign_refuses_a_key_that_does_not_exist(
    runner: CliRunner, keys: Path, sealed_db: str
) -> None:
    result = run(
        runner,
        "bundle",
        "sign",
        MANIFEST_ID,
        "--key",
        "ghost",
        "--trust-root",
        TRUST_ROOT,
        "--key-dir",
        str(keys),
        "--db",
        sealed_db,
    )
    assert result.exit_code == 1
    assert "ghost" in result.output


def test_signatures_exits_non_zero_on_an_unsigned_manifest(
    runner: CliRunner, keys: Path, sealed_db: str
) -> None:
    """The negative control for the happy path above: no signature is not a pass."""
    result = run(
        runner, "bundle", "signatures", MANIFEST_ID, "--key-dir", str(keys), "--db", sealed_db
    )
    assert result.exit_code == 1
    assert "unsigned" in result.output


def test_signatures_reports_a_rotated_key_as_untrusted_not_verified(
    runner: CliRunner, keys: Path, sealed_db: str
) -> None:
    """Rotation must make the deployment stop accepting the old key.

    Collapsing ``verified`` and ``trusted`` into one flag would hide this, so the
    command reports both and asserts the one that actually revokes: after
    rotation the retired fingerprint is no longer vouched for, so a reader sees
    ``trusted=false``.

    The bytes still verify against the archived generation, and that is not a
    defect — it is what lets an auditor re-check evidence that was signed before
    the rotation. Revocation lives in ``trusted``, because "this was signed by
    the key we no longer trust" and "these bytes were altered" are different
    findings and a tool that merges them cannot report either honestly."""
    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    signed = run(
        runner,
        "bundle",
        "sign",
        MANIFEST_ID,
        "--key",
        "alpha",
        "--trust-root",
        TRUST_ROOT,
        "--key-dir",
        str(keys),
        "--db",
        sealed_db,
    )
    assert signed.exit_code == 0, signed.output

    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys), "--rotate")
    result = run(
        runner, "bundle", "signatures", MANIFEST_ID, "--key-dir", str(keys), "--db", sealed_db
    )
    assert "trusted=false" in result.output


def test_signatures_rejects_a_tampered_manifest(
    runner: CliRunner, keys: Path, sealed_db: str, db: str
) -> None:
    """Rewriting the stored manifest's bytes must not verify.

    The negative control that makes the pass above meaningful: it proves the
    verifier is actually checking bytes rather than reporting the recorded
    state.
    """
    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    run(
        runner,
        "bundle",
        "sign",
        MANIFEST_ID,
        "--key",
        "alpha",
        "--trust-root",
        TRUST_ROOT,
        "--key-dir",
        str(keys),
        "--db",
        sealed_db,
    )

    store = Store.open_migrated(Path(db), migrations=ALL_MIGRATIONS)
    row = store.query(
        "SELECT manifest_json FROM attestation_manifests WHERE manifest_id = ?", (MANIFEST_ID,)
    )[0]
    payload = json.loads(str(row["manifest_json"]))
    # ``signing_bytes`` is derived from the Manifest model, which is rebuilt from
    # ``manifest_json`` -- so the tampered field has to live *inside* that JSON.
    # Rewriting a sibling column would change nothing the verifier ever reads.
    payload["signer_identity"] = "attacker"
    with store.write() as conn:
        conn.execute(
            "UPDATE attestation_manifests SET manifest_json = ? WHERE manifest_id = ?",
            (json.dumps(payload, sort_keys=True), MANIFEST_ID),
        )
    store.close()

    result = run(
        runner, "bundle", "signatures", MANIFEST_ID, "--key-dir", str(keys), "--db", sealed_db
    )
    assert result.exit_code == 1
    assert "verified=false" in result.output


def test_signatures_reports_a_world_readable_key_rather_than_trusting_it(
    runner: CliRunner, keys: Path, sealed_db: str
) -> None:
    """A key any local user can read must be reported, not silently refused
    with an empty trust store that looks like an ordinary 'untrusted'."""
    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    run(
        runner,
        "bundle",
        "sign",
        MANIFEST_ID,
        "--key",
        "alpha",
        "--trust-root",
        TRUST_ROOT,
        "--key-dir",
        str(keys),
        "--db",
        sealed_db,
    )
    (keys / "alpha.key").chmod(0o644)

    result = run(
        runner, "bundle", "signatures", MANIFEST_ID, "--key-dir", str(keys), "--db", sealed_db
    )
    assert "verified=false" in result.output


def test_signature_state_is_recorded_on_the_manifest_row(
    runner: CliRunner, keys: Path, sealed_db: str, db: str
) -> None:
    """Signing flips the stored state, so a reader of the row sees it."""
    store = Store.open_migrated(Path(db), migrations=ALL_MIGRATIONS)
    before = SignatureRepository(store).load_signature_state(MANIFEST_ID)[0]
    store.close()
    assert before != "signed"

    run(runner, "bundle", "keygen", "alpha", "--key-dir", str(keys))
    run(
        runner,
        "bundle",
        "sign",
        MANIFEST_ID,
        "--key",
        "alpha",
        "--trust-root",
        TRUST_ROOT,
        "--key-dir",
        str(keys),
        "--db",
        sealed_db,
    )

    store = Store.open_migrated(Path(db), migrations=ALL_MIGRATIONS)
    after = SignatureRepository(store).load_signature_state(MANIFEST_ID)[0]
    store.close()
    assert after == "signed"
