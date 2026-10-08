"""The evidence boundary: a secret-classified value reaches no artifact.

Plan 29 Phase 4 states the acceptance criterion as a byte-scan over a sealed
bundle, and Phase 2 owns the enforcement. The tests below drive the *real*
pipeline — resolve a credential, build an evidence envelope, persist it, write
the report artifacts, hash-chain a bundle, seal it to disk — and then scan every
byte of every file for the resolved value.

The case that matters most is the one name-based redaction cannot catch. A value
written under ``detail``, or embedded in a provider's captured stderr, survives
``redact``: that function triggers on how a field is *called*. The byte scan
triggers on the bytes themselves, which is the only signal that survives a value
planted somewhere nobody predicted. So the first test in this file *proves the
gap exists* before the later tests prove the guard closes it — otherwise the
guard's green result would be indistinguishable from a guard that never fires.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.domain.evidence_bundle import build_bundle
from mayhem.domain.redaction import redact
from mayhem.domain.secrets import (
    REFUSAL_SECRET_FIELD_PERSISTED,
    CredentialRef,
    CredentialScope,
    ScopeKind,
    SecretGrant,
    SecretProvider,
)
from mayhem.infra.evidence import (
    build_evidence,
    render_report,
    write_evidence,
    write_evidence_file,
)
from mayhem.infra.evidence_bundle_io import write_bundle
from mayhem.infra.secret_resolver import (
    REFUSAL_SECRET_BYTES_IN_ARTIFACT,
    FilesystemFixtureProvider,
    SecretGrantRepository,
    SecretLeakGuard,
    SecretResolver,
    StaticGrantSource,
    require_clean_bundle,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
ALICE = "svc:alice"
PROD = "prod-eu"
RUN_ID = "r-secrets-1"

#: Long and unguessable, so a match cannot be a coincidence of a short needle.
SECRET_VALUE = "vault-value-9f3c-4b71-do-not-persist"


@pytest.fixture
def secret_tree(tmp_path: Path) -> Path:
    root = tmp_path / "secrets"
    (root / SecretProvider.VAULT.value).mkdir(parents=True, exist_ok=True)
    (root / SecretProvider.VAULT.value / "prod__database").write_text(SECRET_VALUE, "utf-8")
    return root


def grant(*, scopes: tuple[str, ...] = ()) -> SecretGrant:
    return SecretGrant(
        principal=ALICE,
        credential_pattern="vault:prod/*",
        environments=(PROD,),
        scopes=scopes,
        expires_at=NOW + timedelta(seconds=3600),
        issued_at=NOW,
    )


def step_ref(step: str = "inject-db") -> CredentialRef:
    return CredentialRef(
        provider=SecretProvider.VAULT,
        secret="prod/database",
        purpose="inject the fault's database credential",
        scope=CredentialScope(kind=ScopeKind.STEP, ref=step),
    )


class SecretsBearingRun:
    """A run that resolved a credential, with every artifact it produced.

    The run records *metadata* about the resolution — provider, canonical key,
    purpose, scope — which is what the plan says evidence may carry, and never
    the value. The value is reachable only inside the ``with`` block that spends
    it, and this helper exits that block before it builds anything.
    """

    def __init__(self, tree: Path, *, guard: SecretLeakGuard) -> None:
        self.guard = guard
        self.resolver = SecretResolver(
            providers={SecretProvider.VAULT: FilesystemFixtureProvider(tree)},
            grant_source=StaticGrantSource((grant(),)),
            clock=lambda: NOW,
            guard=guard,
        )
        self.value_used = False

    def execute(self) -> None:
        """Resolve and spend the credential, recording only its receipt."""
        secret = self.resolver.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        )
        with secret.use() as value:
            self.value_used = value == SECRET_VALUE
        secret.zero()

    @property
    def receipts(self) -> list[dict[str, object]]:
        return [receipt.to_dict() for receipt in self.resolver.receipts]

    def envelope(self) -> EvidenceEnvelope:
        """Build an envelope the way the engine would after the run."""
        return build_evidence(
            run_id=RUN_ID,
            plan=None,
            target_profile="local",
            engine="",
            safety_decisions=("impact gate: approved",),
            step_reports=(
                {
                    "step_id": "inject-db",
                    "status": "completed",
                    "credentials_resolved": self.receipts,
                    "detail": "postgres connection reset applied to db-1",
                },
            ),
            lease_timeline=(),
            observations=({"kind": "fault", "target": "db-1", "outcome": "applied"},),
            verdict="pass",
            recovery_state="recovered",
            remediation=(),
        )


# --- The gap: name-based redaction is not sufficient ----------------------------


class TestNameRedactionIsNotPolicy:
    def test_a_value_under_an_innocuous_field_name_survives_redact(self) -> None:
        """The premise of the byte scan, asserted rather than assumed."""
        result = redact({"detail": f"connected with {SECRET_VALUE} to db-1"})
        assert SECRET_VALUE in str(result.value)
        assert result.removed_paths == ()

    def test_the_byte_scan_catches_what_redact_misses(self) -> None:
        guard = SecretLeakGuard()
        guard.register_value(SECRET_VALUE)
        document = {"detail": f"connected with {SECRET_VALUE} to db-1"}
        with pytest.raises(InvariantViolationError) as excinfo:
            guard.require_clean_document(document, artifact="step_report")
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert SECRET_VALUE not in str(excinfo.value)


# --- The byte-scan over a sealed bundle -----------------------------------------


class TestSealedBundleByteScan:
    def test_a_secrets_bearing_run_seals_a_bundle_with_zero_credential_bytes(
        self, tmp_path: Path, secret_tree: Path
    ) -> None:
        guard = SecretLeakGuard()
        run = SecretsBearingRun(secret_tree, guard=guard)
        run.execute()
        assert run.value_used, "the run must actually have held the value"

        # The evidence boundary, applied before anything is persisted.
        guard.require_clean_envelope(run.envelope(), artifact="evidence")

        bundle_dir = tmp_path / "bundle"
        write_evidence_file(run.envelope(), bundle_dir)
        bundle = build_bundle(
            evidence=run.envelope().model_dump(mode="json"),
            replay={"steps": run.receipts},
            created_at=NOW.isoformat(),
        )
        write_bundle(bundle, bundle_dir)

        scanned = require_clean_bundle(bundle_dir, guard)
        assert scanned, "the scan must have read at least the bundle files"
        assert any(name.endswith("manifest.json") for name in scanned)
        assert any(name.endswith("evidence.json") for name in scanned)
        assert any(name.endswith("replay.json") for name in scanned)

        # Independent of the guard: read the bytes and search them directly.
        for path in sorted(bundle_dir.rglob("*")):
            if path.is_file():
                assert SECRET_VALUE.encode() not in path.read_bytes(), path

    def test_the_bundle_still_verifies_after_the_scan(self, secret_tree: Path) -> None:
        """Scanning must not be the only thing the bundle satisfies."""
        from mayhem.domain.evidence_bundle import verify_bundle

        guard = SecretLeakGuard()
        run = SecretsBearingRun(secret_tree, guard=guard)
        run.execute()
        bundle = build_bundle(
            evidence=run.envelope().model_dump(mode="json"),
            replay={"steps": run.receipts},
            created_at=NOW.isoformat(),
        )
        assert verify_bundle(bundle).valid

    def test_a_planted_value_in_a_bundle_artifact_is_caught(
        self, tmp_path: Path, secret_tree: Path
    ) -> None:
        """Negative control: the scan is not vacuously green."""
        guard = SecretLeakGuard()
        run = SecretsBearingRun(secret_tree, guard=guard)
        run.execute()
        envelope = run.envelope()
        planted = envelope.model_copy(
            update={
                "step_reports": (
                    {
                        "step_id": "inject-db",
                        "detail": f"provider stderr: FATAL: password={SECRET_VALUE}",
                    },
                )
            }
        )
        bundle_dir = tmp_path / "planted"
        write_bundle(
            build_bundle(evidence=planted.model_dump(mode="json"), created_at=NOW.isoformat()),
            bundle_dir,
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            require_clean_bundle(bundle_dir, guard)
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert "evidence.json" in str(excinfo.value)


# --- Envelope and report boundaries --------------------------------------------


class TestEnvelopeAndReport:
    def test_a_secret_classified_envelope_field_is_refused(self) -> None:
        guard = SecretLeakGuard()
        envelope = EvidenceEnvelope(
            run_id=RUN_ID,
            plan_hash="h",
            # ``resolved_credentials`` is graded SECRET in Phase 1's
            # ``EVIDENCE_FIELD_CLASSIFICATIONS``, and the walk is recursive, so a
            # secret-shaped key nested inside a step report is caught too.
            step_reports=({"id": "inject-db", "resolved_credentials": {"db": SECRET_VALUE}},),
            verdict="pass",
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            guard.require_clean_envelope(envelope)
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        assert "resolved_credentials" in str(excinfo.value)

    def test_a_gated_envelope_is_persistable(self, tmp_path: Path, secret_tree: Path) -> None:
        guard = SecretLeakGuard()
        run = SecretsBearingRun(secret_tree, guard=guard)
        run.execute()
        envelope = run.envelope()
        guard.require_clean_envelope(envelope)

        store = Store.open_migrated(tmp_path / "mayhem.db")
        write_evidence(store, envelope)
        loaded = store.query(
            "SELECT envelope_json FROM evidence_envelopes WHERE run_id = ?", (RUN_ID,)
        )
        assert len(loaded) == 1
        raw = str(loaded[0]["envelope_json"])
        assert SECRET_VALUE not in raw
        store.close()

    def test_the_rendered_report_carries_no_credential_bytes(
        self, tmp_path: Path, secret_tree: Path
    ) -> None:
        guard = SecretLeakGuard()
        run = SecretsBearingRun(secret_tree, guard=guard)
        run.execute()
        report = render_report(run.envelope())
        assert SECRET_VALUE not in report
        guard.require_clean_bytes(report, artifact="report")

    def test_a_log_line_carrying_a_value_is_caught(self, secret_tree: Path) -> None:
        """The log surface: the guard is what notices, not the formatter."""
        guard = SecretLeakGuard()
        run = SecretsBearingRun(secret_tree, guard=guard)
        run.execute()
        log_line = f"event=step_completed step=inject-db detail=resolved {SECRET_VALUE}"
        with pytest.raises(InvariantViolationError) as excinfo:
            guard.require_clean_bytes(log_line, artifact="log")
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert SECRET_VALUE not in str(excinfo.value)


# --- The store boundary --------------------------------------------------------


class TestStoreBoundary:
    def test_a_store_row_cannot_be_written_with_a_secret_classified_value(
        self, tmp_path: Path, secret_tree: Path
    ) -> None:
        """Impossible by construction, then proven.

        ``EvidenceEnvelope`` accepts a ``dict[str, Any]`` payload, so the type
        alone does not stop a secret-classified key. The gate does, and the gate
        runs before the write — so the store never receives the row at all.
        """
        guard = SecretLeakGuard()
        run = SecretsBearingRun(secret_tree, guard=guard)
        run.execute()
        poisoned = run.envelope().model_copy(
            update={"observations": ({"credential_values": {"db": SECRET_VALUE}},)}
        )
        store = Store.open_migrated(tmp_path / "mayhem.db")
        with pytest.raises(InvariantViolationError) as excinfo:
            guard.require_clean_envelope(poisoned)
            write_evidence(store, poisoned)
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        # Stronger than "zero rows": the table is not even created. The refusal
        # happened before ``write_evidence`` was reached, so there is nothing to
        # count.
        tables = {
            str(row["name"])
            for row in store.query("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "evidence_envelopes" not in tables
        store.close()

    def test_the_grant_table_cannot_hold_a_value(self, tmp_path: Path) -> None:
        """The schema is the guarantee, not a convention.

        ``secret_grants`` exists to record permissions. Proving there is no
        column a value could occupy is stronger than proving the writer is
        careful, because it also covers the writer nobody wrote.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        repository = SecretGrantRepository(store)
        repository.save(grant(scopes=("step:inject-db",)))
        columns = {str(row["name"]) for row in store.query("PRAGMA table_info(secret_grants)")}
        assert columns == {
            "principal",
            "credential_pattern",
            "environments_json",
            "scopes_json",
            "expires_at",
            "issued_at",
        }
        assert not any(
            token in name
            for name in columns
            for token in ("value", "secret_value", "credential_value", "password")
        )
        store.close()

    def test_a_direct_sql_insert_of_a_value_has_no_column_to_use(self, tmp_path: Path) -> None:
        """The negative control on the schema itself."""
        store = Store.open_migrated(tmp_path / "mayhem.db")
        columns = {str(row["name"]) for row in store.query("PRAGMA table_info(secret_grants)")}
        with pytest.raises(sqlite3.OperationalError):
            with store.write() as conn:
                conn.execute(
                    "INSERT INTO secret_grants (principal, credential_pattern, secret_value) "
                    "VALUES (?,?,?)",
                    (ALICE, "vault:prod/*", SECRET_VALUE),
                )
        assert "secret_value" not in columns
        store.close()

    def test_the_value_is_absent_from_the_store_file_after_a_full_run(
        self, tmp_path: Path, secret_tree: Path
    ) -> None:
        guard = SecretLeakGuard()
        run = SecretsBearingRun(secret_tree, guard=guard)
        run.execute()
        envelope = run.envelope()
        guard.require_clean_envelope(envelope)
        store = Store.open_migrated(tmp_path / "mayhem.db")
        write_evidence(store, envelope)
        repository = SecretGrantRepository(store)
        repository.save(grant(scopes=("step:inject-db",)))
        store.close()
        assert SECRET_VALUE.encode() not in (tmp_path / "mayhem.db").read_bytes()


# --- Guard mechanics -----------------------------------------------------------


class TestGuardMechanics:
    def test_needles_shorter_than_the_minimum_are_not_searched(self) -> None:
        guard = SecretLeakGuard(minimum_length=8)
        guard.register_value("abc")
        assert guard.scan_bytes("an abc here") == ()
        guard.register_value("a-longer-needle")
        assert guard.scan_bytes("an a-longer-needle here") != ()

    def test_multiple_occurrences_are_all_reported(self) -> None:
        guard = SecretLeakGuard()
        guard.register_value(SECRET_VALUE)
        hits = guard.scan_bytes(f"{SECRET_VALUE} and {SECRET_VALUE}")
        assert len(hits) == 2
        assert {hit.offset for hit in hits} == {0, len(SECRET_VALUE) + 5}

    def test_hit_reports_a_digest_not_a_value(self) -> None:
        guard = SecretLeakGuard()
        guard.register_value(SECRET_VALUE)
        hit = guard.scan_bytes(SECRET_VALUE)[0]
        assert SECRET_VALUE not in hit.describe()
        assert len(hit.needle_digest) == 64

    def test_scan_bytes_accepts_text_and_bytes_alike(self) -> None:
        guard = SecretLeakGuard()
        guard.register_value(SECRET_VALUE)
        assert guard.scan_bytes(SECRET_VALUE) == guard.scan_bytes(SECRET_VALUE.encode())

    def test_release_is_idempotent_and_then_finds_nothing(self) -> None:
        guard = SecretLeakGuard()
        guard.register_value(SECRET_VALUE)
        guard.release()
        guard.release()
        assert guard.scan_bytes(SECRET_VALUE) == ()

    def test_guard_registration_from_a_resolved_secret_uses_live_bytes(
        self, secret_tree: Path
    ) -> None:
        guard = SecretLeakGuard()
        resolver = SecretResolver(
            providers={SecretProvider.VAULT: FilesystemFixtureProvider(secret_tree)},
            grant_source=StaticGrantSource((grant(),)),
            clock=lambda: NOW,
            guard=guard,
        )
        secret = resolver.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        )
        assert guard.needle_count == 1
        with secret.use():
            assert guard.scan_bytes(SECRET_VALUE) != ()
        assert secret.is_spent

    def test_require_clean_document_reads_nested_structures(self) -> None:
        guard = SecretLeakGuard()
        guard.register_value(SECRET_VALUE)
        document = {"steps": [{"detail": f"used {SECRET_VALUE}"}]}
        with pytest.raises(InvariantViolationError):
            guard.require_clean_document(document, artifact="envelope")

    def test_an_ungraded_field_defaults_to_sensitive_not_secret(self) -> None:
        """Phase 1's fail-closed default, observed through the guard."""
        guard = SecretLeakGuard()
        # ``detail`` is ungraded, so it is SENSITIVE and therefore persistable —
        # which is exactly why the byte scan has to exist alongside the grading.
        guard.require_clean_document({"detail": "no credential here"}, artifact="envelope")

    def test_serialising_a_receipt_is_safe(self, secret_tree: Path) -> None:
        guard = SecretLeakGuard()
        run = SecretsBearingRun(secret_tree, guard=guard)
        run.execute()
        rendered = json.dumps(run.receipts)
        guard.require_clean_bytes(rendered, artifact="receipts")
        assert SECRET_VALUE not in rendered
