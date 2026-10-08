"""The sealed half of the per-run development-only marker (plan 29 Phase 3).

Phase 3 requires the explicit per-run marker to be *sealed into evidence*. What
the resolver already did was the in-memory half: refuse a development-only
provider without ``allow_development_only=True`` and record a
``ResolutionReceipt`` per resolution. A receipt that lives only in
``SecretResolver.receipts`` dies with the process, so a run that resolved a
development-only credential left no evidence it did. What is asserted here:

* **The marker is metadata, never a value.** ``development_marker()`` carries
  the run-wide flag plus the development-only receipts' own ``to_dict`` —
  provider, canonical key, purpose, scope, principal, environment, grant
  pattern, timestamps — and a byte-scan with the real value as the needle finds
  nothing in it. The scan is two-sided: the same needle planted in a document
  *is* found, so the clean result is the scanner working, not the scanner idle.
* **The seal is the existing seal path.** ``seal_secret_development_marker``
  writes through ``AttestationRepository`` under its own chain key, both
  verifications must pass before anything is written, and the round trip
  (seal → load → re-verify) is exact. Nothing to seal seals nothing (``None``,
  not an empty row), and an unsealed run loads as absent and verifies as
  invalid — never as silently unmarked.
* **The run-close wiring seals and renders read-only.**
  ``_write_evidence_after_run`` takes the marker, seals it before the envelope
  persists, and renders only a remediation note — no value, no mutation of the
  marker. ``None`` (no resolver involved) seals and renders nothing.
* **The grant UI is a second projection, not a second answer.**
  ``secret_grant_explain_payload`` builds the CLI's own ``GrantExplanation``
  and returns the CLI's own ``explain_payload`` of it; CLI ``--json`` and the
  API payload are asserted byte-identical for a permitted and a denied
  question. The principal stays a declared string in both.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.lifecycle import _write_evidence_after_run
from mayhem.cli.secrets_cmd import build_grant_explanation, explain_payload
from mayhem.controller.api_service import secret_grant_explain_payload
from mayhem.controller.secret_evidence import (
    EVENT_SECRET_DEVELOPMENT_MARKED,
    load_secret_development_marker,
    seal_secret_development_marker,
    secret_chain_key,
    secret_manifest_id,
    verify_secret_development_chain,
)
from mayhem.domain.secrets import (
    CredentialRef,
    CredentialScope,
    ScopeKind,
    SecretGrant,
    SecretProvider,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.secret_resolver import (
    EnvironmentSecretProvider,
    SecretLeakGuard,
    SecretResolver,
    StaticGrantSource,
    development_marker_is_sealable,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
ALICE = "svc:alice"
PROD = "prod-eu"
DEV_VALUE = "dev-only-value-7c2e-do-not-persist"
DEV_VARIABLE = "MAYHEM_TEST_DEV_SECRET"


def _grant(
    *,
    principal: str = ALICE,
    pattern: str = "environment:*",
    environments: tuple[str, ...] = (PROD,),
    scopes: tuple[str, ...] = (),
    expires_in: float = 3600.0,
) -> SecretGrant:
    return SecretGrant(
        principal=principal,
        credential_pattern=pattern,
        environments=environments,
        scopes=scopes,
        expires_at=NOW + timedelta(seconds=expires_in),
        issued_at=NOW,
    )


def _env_ref(variable: str = DEV_VARIABLE) -> CredentialRef:
    return CredentialRef(
        provider=SecretProvider.ENVIRONMENT,
        secret=variable,
        purpose="seed the checkout rows before the fault",
        scope=CredentialScope(kind=ScopeKind.STEP, ref="inject-db"),
    )


def _resolver(**kwargs: Any) -> SecretResolver:
    return SecretResolver(
        providers={
            SecretProvider.ENVIRONMENT: EnvironmentSecretProvider({DEV_VARIABLE: DEV_VALUE})
        },
        grant_source=StaticGrantSource((_grant(),)),
        clock=lambda: NOW,
        **kwargs,  # type: ignore[arg-type]
    )


def _resolve_dev(resolver: SecretResolver) -> None:
    """Resolve one development-only credential and spend it immediately."""
    with resolver.resolve(_env_ref(), principal=ALICE, environment=PROD, step_id="inject-db").use():
        pass


def _open_store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


# --- The marker is metadata ---------------------------------------------------


class TestTheMarkerIsMetadata:
    def test_the_flag_is_carried(self) -> None:
        marker = _resolver(allow_development_only=True).development_marker()

        assert marker["allow_development_only"] is True

    def test_the_flag_defaults_off(self) -> None:
        marker = _resolver().development_marker()

        assert marker["allow_development_only"] is False

    def test_a_development_resolution_is_carried_with_its_provider(self) -> None:
        resolver = _resolver(allow_development_only=True)
        _resolve_dev(resolver)
        marker = resolver.development_marker()

        assert marker["development_only_providers"] == ["environment"]
        (receipt,) = marker["development_only_receipts"]
        assert receipt["provider"] == "environment"
        assert receipt["canonical_key"] == f"environment:{DEV_VARIABLE}"
        assert receipt["principal"] == ALICE

    def test_a_non_development_resolution_is_counted_not_carried(self) -> None:
        from mayhem.infra.secret_resolver import CallableSecretProvider

        vault_resolver = SecretResolver(
            providers={
                SecretProvider.VAULT: CallableSecretProvider(
                    SecretProvider.VAULT, lambda _request: b"vault-bytes"
                )
            },
            grant_source=StaticGrantSource(
                (_grant(pattern="vault:prod/*"),),
            ),
            clock=lambda: NOW,
        )
        with vault_resolver.resolve(
            CredentialRef(
                provider=SecretProvider.VAULT,
                secret="prod/database",
                purpose="seed the checkout rows before the fault",
                scope=CredentialScope(kind=ScopeKind.STEP, ref="inject-db"),
            ),
            principal=ALICE,
            environment=PROD,
            step_id="inject-db",
        ).use():
            pass
        marker = vault_resolver.development_marker()

        assert marker["receipt_count"] == 1
        assert marker["development_only_receipts"] == []
        assert marker["development_only_providers"] == []

    def test_the_marker_carries_zero_credential_bytes(self) -> None:
        resolver = _resolver(allow_development_only=True)
        _resolve_dev(resolver)
        marker = resolver.development_marker()

        guard = SecretLeakGuard()
        guard.register_value(DEV_VALUE)
        assert guard.needle_count == 1
        # Raises when the value appears; returns quietly when it does not.
        guard.require_clean_bytes(
            json.dumps(marker, sort_keys=True, default=str), artifact="marker"
        )
        assert DEV_VALUE not in json.dumps(marker, sort_keys=True, default=str)

    def test_the_scan_bites_on_a_planted_value(self) -> None:
        """Two-sided: a clean scan must be the scanner working, not idle."""
        guard = SecretLeakGuard()
        guard.register_value(DEV_VALUE)

        with pytest.raises(Exception, match="credential bytes"):
            guard.require_clean_bytes(json.dumps({"note": DEV_VALUE}), artifact="control")

    def test_an_untouched_resolver_marks_nothing_sealable(self) -> None:
        assert development_marker_is_sealable(_resolver().development_marker()) is False

    def test_the_flag_alone_is_sealable(self) -> None:
        marker = _resolver(allow_development_only=True).development_marker()

        assert development_marker_is_sealable(marker) is True

    def test_a_development_receipt_alone_is_sealable(self) -> None:
        resolver = _resolver(allow_development_only=True)
        _resolve_dev(resolver)

        assert development_marker_is_sealable(resolver.development_marker()) is True


# --- The seal round trip ------------------------------------------------------


class TestTheSealRoundTrip:
    def test_seal_load_and_reverify_are_exact(self, tmp_path: Path) -> None:
        resolver = _resolver(allow_development_only=True)
        _resolve_dev(resolver)
        marker = resolver.development_marker()
        store = _open_store(tmp_path)
        try:
            sealed = seal_secret_development_marker(store, "r-1", marker)
            assert sealed is not None
            assert sealed.valid
            assert sealed.events[0].event_kind == EVENT_SECRET_DEVELOPMENT_MARKED
            assert sealed.events[0].run_id == "r-1"

            reloaded = load_secret_development_marker(store, "r-1")
            assert reloaded is not None
            assert reloaded.valid
            assert reloaded.marker == sealed.marker
            assert reloaded.marker["allow_development_only"] is True
            assert reloaded.marker["development_only_providers"] == ["environment"]
            assert verify_secret_development_chain(store, "r-1").valid
        finally:
            store.close()

    def test_the_sealed_bytes_carry_zero_credential_bytes(self, tmp_path: Path) -> None:
        resolver = _resolver(allow_development_only=True)
        _resolve_dev(resolver)
        store = _open_store(tmp_path)
        try:
            sealed = seal_secret_development_marker(store, "r-1", resolver.development_marker())
            assert sealed is not None
            chain_json = json.dumps(
                [event.model_dump(mode="json") for event in sealed.events],
                sort_keys=True,
                default=str,
            )
            guard = SecretLeakGuard()
            guard.register_value(DEV_VALUE)
            guard.require_clean_bytes(chain_json, artifact="secret-development-chain")
            assert DEV_VALUE not in chain_json
        finally:
            store.close()

    def test_the_flag_alone_seals_one_event_with_no_receipts(self, tmp_path: Path) -> None:
        marker = _resolver(allow_development_only=True).development_marker()
        store = _open_store(tmp_path)
        try:
            sealed = seal_secret_development_marker(store, "r-1", marker)

            assert sealed is not None
            assert sealed.marker["development_only_receipts"] == []
            assert sealed.marker["receipt_count"] == 0
        finally:
            store.close()

    def test_nothing_to_seal_writes_no_row(self, tmp_path: Path) -> None:
        store = _open_store(tmp_path)
        try:
            assert (
                seal_secret_development_marker(store, "r-1", _resolver().development_marker())
                is None
            )
            assert load_secret_development_marker(store, "r-1") is None
            assert secret_chain_key("r-1") == "r-1:secret-development"
            assert secret_manifest_id("r-1") == "r-1:secret-development"
        finally:
            store.close()

    def test_an_unsealed_run_is_absent_not_unmarked(self, tmp_path: Path) -> None:
        store = _open_store(tmp_path)
        try:
            assert load_secret_development_marker(store, "r-never") is None
            verification = verify_secret_development_chain(store, "r-never")
            assert verification.valid is False
        finally:
            store.close()

    def test_the_marker_chain_does_not_claim_the_run_chain_key(self, tmp_path: Path) -> None:
        """Namespacing is load-bearing: the run's own chain key stays free."""
        assert secret_chain_key("r-1") != "r-1"


# --- The run-close wiring -----------------------------------------------------


def _preflight() -> Any:
    return SimpleNamespace(
        plan=None,
        plan_id="r-1",
        target_profile="dev",
        safety_decisions=("allow",),
        environment_fingerprint="env-1",
        target_identity="dev/api",
        blast_radius={"services": 1},
        compensation_status="verified",
        k8s_target_scope="dev",
        k8s_context="",
        k8s_namespace="",
        k8s_capability_verdict="allowed",
        k8s_wait_strategy="",
        k8s_recovery_guidance="",
    )


def _result() -> Any:
    return SimpleNamespace(
        run_id="r-1",
        steps=(SimpleNamespace(step_id="s1", ok=True, detail="ok", status="ok"),),
        observability=(),
        verdict="passed",
        status="completed",
        dirty_leases=(),
    )


class TestTheRunCloseWiring:
    def test_a_marker_is_sealed_and_rendered_as_a_note(self, tmp_path: Path) -> None:
        resolver = _resolver(allow_development_only=True)
        _resolve_dev(resolver)
        store = _open_store(tmp_path)
        try:
            envelope = _write_evidence_after_run(
                store=store,
                preflight=_preflight(),
                result=_result(),
                engine="podman",
                evidence_dir=None,
                secret_development_marker=resolver.development_marker(),
            )

            assert envelope is not None
            assert any(
                "development-only credential marker sealed" in item for item in envelope.remediation
            )
            assert DEV_VALUE not in json.dumps(envelope.to_dict(), default=str)
            sealed = load_secret_development_marker(store, "r-1")
            assert sealed is not None
            assert sealed.valid
            assert sealed.marker["development_only_providers"] == ["environment"]
        finally:
            store.close()

    def test_no_marker_seals_and_renders_nothing(self, tmp_path: Path) -> None:
        store = _open_store(tmp_path)
        try:
            envelope = _write_evidence_after_run(
                store=store,
                preflight=_preflight(),
                result=_result(),
                engine="podman",
                evidence_dir=None,
            )

            assert envelope is not None
            assert not any(
                "development-only credential marker" in item for item in envelope.remediation
            )
            assert load_secret_development_marker(store, "r-1") is None
        finally:
            store.close()


# --- The grant UI as a second projection --------------------------------------


def _question_grants() -> tuple[SecretGrant, ...]:
    return (
        SecretGrant(
            principal=ALICE,
            credential_pattern="vault:prod/*",
            environments=(PROD,),
            scopes=("step:inject",),
            expires_at=NOW + timedelta(days=7),
            issued_at=NOW,
        ),
    )


def _question_ref() -> CredentialRef:
    return CredentialRef(
        provider=SecretProvider.VAULT,
        secret="prod/database",
        purpose="seed the checkout rows before the fault",
        scope=CredentialScope(kind=ScopeKind.STEP, ref="inject"),
    )


class TestTheGrantProjectionIsOneViewModel:
    def test_the_api_payload_is_the_cli_payload(self) -> None:
        grants = _question_grants()
        reference = _question_ref()

        expected = explain_payload(
            build_grant_explanation(grants, reference, principal=ALICE, environment=PROD, now=NOW)
        )
        actual = secret_grant_explain_payload(
            grants, reference, principal=ALICE, environment=PROD, now=NOW
        )

        assert actual == expected
        assert actual["permitted"] is True
        assert actual["answered_by"] == "vault:prod/*"

    def test_the_denied_case_matches_too(self) -> None:
        grants = _question_grants()
        reference = _question_ref()

        expected = explain_payload(
            build_grant_explanation(
                grants, reference, principal=ALICE, environment="staging", now=NOW
            )
        )
        actual = secret_grant_explain_payload(
            grants, reference, principal=ALICE, environment="staging", now=NOW
        )

        assert actual == expected
        assert actual["permitted"] is False

    def test_the_cli_json_matches_the_api_payload(self, tmp_path: Path) -> None:
        db = str(tmp_path / "grants.db")
        granted = CliRunner().invoke(
            app,
            [
                "secrets",
                "grant",
                "--principal",
                ALICE,
                "--pattern",
                "vault:prod/*",
                "--environment",
                PROD,
                "--scope",
                "step:inject",
                "--expires-in",
                "7",
                "--db",
                db,
            ],
            catch_exceptions=False,
        )
        assert granted.exit_code == int(ExitCode.SUCCESS)

        store = Store.open_migrated(db, migrations=ALL_MIGRATIONS)
        try:
            from mayhem.infra.secret_resolver import SecretGrantRepository

            grants = SecretGrantRepository(store).grants_for(ALICE)
        finally:
            store.close()

        cli_result = CliRunner().invoke(
            app,
            [
                "secrets",
                "explain",
                "--principal",
                ALICE,
                "--pattern",
                "vault:prod/database",
                "--environment",
                PROD,
                "--scope",
                "step:inject",
                "--db",
                db,
                "--json",
            ],
        )
        cli_payload = cast("dict[str, Any]", json.loads(cli_result.output))
        # The CLI stamps expiries from its own clock; the question it answers is
        # the same one, so compare everything but the minted timestamps.
        api_payload = secret_grant_explain_payload(
            grants, _question_ref(), principal=ALICE, environment=PROD
        )
        for key in ("question", "grants_considered", "answered_by", "permitted", "note"):
            assert cli_payload[key] == api_payload[key]
        assert [entry["clauses"] for entry in cli_payload["considered"]] == [
            entry["clauses"] for entry in api_payload["considered"]
        ]

    def test_the_principal_stays_a_declared_string(self) -> None:
        payload = secret_grant_explain_payload(
            _question_grants(),
            _question_ref(),
            principal=ALICE,
            environment=PROD,
            now=NOW,
        )

        assert payload["question"]["principal"] == ALICE
        assert "authenticated" not in json.dumps(payload)
