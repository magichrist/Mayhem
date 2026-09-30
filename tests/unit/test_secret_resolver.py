"""Phase 2 secret resolution engine: grants, scope, lifetime, and zeroing.

``docs/v1.1.0/29_SECRETS_MANAGEMENT.md`` Phase 2 acceptance is "memory-lifetime
tests; cross-step leakage tests refused", so the matrix below is organised
around the four claims the engine makes rather than around its classes:

* the grant matrix — every Phase 1 refusal code still arrives, now through the
  engine, at resolution time rather than at authoring time;
* short-lived credentials — a fetch that overruns its window is refused, and
  the window rides on the request so an adapter can assert on it;
* zero-after-use — the buffer is genuinely overwritten and a second read is a
  refusal, not an empty string;
* cross-step refusal — a step-N credential is unreachable from step N+1 unless a
  separate reference and grant say otherwise.

Plus the negative controls the plan asks for: a revoked grant mid-run fences the
next step, a literal in a spec refuses before anything executes, and the
``secret_grants`` table has no column a value could occupy.
"""

from __future__ import annotations

import json
import pickle
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.secrets import (
    REFUSAL_ENVIRONMENT_OUT_OF_SCOPE,
    REFUSAL_GRANT_EXPIRED,
    REFUSAL_LITERAL_SECRET,
    REFUSAL_NO_GRANT,
    REFUSAL_PATTERN_MISMATCH,
    REFUSAL_PRINCIPAL_MISMATCH,
    REFUSAL_SCOPE_NOT_GRANTED,
    CredentialRef,
    CredentialScope,
    ScopeKind,
    SecretGrant,
    SecretProvider,
)
from mayhem.infra.secret_resolver import (
    REFUSAL_CREDENTIAL_EXPIRED,
    REFUSAL_DEVELOPMENT_PROVIDER,
    REFUSAL_PROVIDER_UNAVAILABLE,
    REFUSAL_SCOPE_HANDOFF,
    REFUSAL_SECRET_VALUE_SPENT,
    CallableSecretProvider,
    EnvironmentSecretProvider,
    FilesystemFixtureProvider,
    GrantSourcePort,
    ProviderRequest,
    ResolvedSecret,
    SecretGrantRepository,
    SecretLeakGuard,
    SecretProviderPort,
    SecretResolver,
    SecretResolverPort,
    StaticGrantSource,
    StoredGrantSource,
    default_providers,
    require_no_literal_spec,
    scan_spec_for_literals,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
ALICE = "svc:alice"
BOB = "svc:bob"
PROD = "prod-eu"
SECRET_VALUE = "vault-value-9f3c-do-not-persist"


# --- Helpers -------------------------------------------------------------------


class Clock:
    """A clock the test moves, so expiry is deterministic rather than timed."""

    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


def grant(
    *,
    principal: str = ALICE,
    pattern: str = "vault:prod/*",
    environments: tuple[str, ...] = (PROD,),
    scopes: tuple[str, ...] = (),
    expires_in: float = 3600.0,
) -> SecretGrant:
    """A grant valid from :data:`NOW` for ``expires_in`` seconds."""
    return SecretGrant(
        principal=principal,
        credential_pattern=pattern,
        environments=environments,
        scopes=scopes,
        expires_at=NOW + timedelta(seconds=expires_in),
        issued_at=NOW,
    )


def step_ref(step: str, *, secret: str = "prod/database") -> CredentialRef:
    return CredentialRef(
        provider=SecretProvider.VAULT,
        secret=secret,
        purpose="inject the fault's database credential",
        scope=CredentialScope(kind=ScopeKind.STEP, ref=step),
    )


def run_ref(run_id: str = "r-1", *, secret: str = "prod/database") -> CredentialRef:
    return CredentialRef(
        provider=SecretProvider.VAULT,
        secret=secret,
        purpose="read the pre-injection baseline",
        scope=CredentialScope(kind=ScopeKind.RUN, ref=run_id),
    )


def env_ref(variable: str = "MAYHEM_TEST_DB_PASSWORD") -> CredentialRef:
    return CredentialRef(
        provider=SecretProvider.ENVIRONMENT,
        secret=variable,
        purpose="inject the fault's database credential",
        scope=CredentialScope(kind=ScopeKind.STEP, ref="inject-db"),
    )


def provider_request(reference: CredentialRef, *, ttl: int = 60) -> ProviderRequest:
    return ProviderRequest(
        reference=reference,
        principal=ALICE,
        environment=PROD,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=ttl),
    )


@pytest.fixture
def secret_tree(tmp_path: Path) -> Path:
    """A filesystem-backed provider tree, so no test needs a live Vault."""
    root = tmp_path / "secrets"
    (root / SecretProvider.VAULT.value).mkdir(parents=True, exist_ok=True)
    (root / SecretProvider.VAULT.value / "prod__database").write_text(
        SECRET_VALUE, encoding="utf-8"
    )
    return root


def fixture_resolver(
    tree: Path,
    grants: tuple[SecretGrant, ...],
    *,
    clock: Clock | None = None,
    **kwargs: object,
) -> SecretResolver:
    return SecretResolver(
        providers={SecretProvider.VAULT: FilesystemFixtureProvider(tree)},
        grant_source=StaticGrantSource(grants),
        clock=clock or Clock(),
        **kwargs,  # type: ignore[arg-type]
    )


def callable_resolver(
    fetch: object,
    grants: tuple[SecretGrant, ...],
    *,
    provider: SecretProvider = SecretProvider.VAULT,
    clock: Clock | None = None,
    **kwargs: object,
) -> SecretResolver:
    return SecretResolver(
        providers={provider: CallableSecretProvider(provider, fetch)},  # type: ignore[arg-type]
        grant_source=StaticGrantSource(grants),
        clock=clock or Clock(),
        **kwargs,  # type: ignore[arg-type]
    )


def refusal_code(exc: BaseException) -> str:
    """The stable code from a refusal.

    ``InvariantViolationError`` carries it as ``rule`` (``ResolutionError`` calls
    the same field ``code``). Callers assert on the code, never on message text.
    """
    assert isinstance(exc, InvariantViolationError)
    return exc.rule


# --- The grant matrix ----------------------------------------------------------


class TestGrantMatrix:
    """Every Phase 1 refusal still arrives, now through the engine."""

    def test_granted_reference_resolves_and_yields_the_value(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(),))
        secret = engine.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        )
        with secret.use() as value:
            assert value == SECRET_VALUE

    def test_wrong_principal_is_refused_before_any_fetch(self) -> None:
        fetched: list[ProviderRequest] = []

        def spy(request: ProviderRequest) -> bytes:
            fetched.append(request)
            return SECRET_VALUE.encode()

        engine = callable_resolver(spy, (grant(principal=ALICE),))
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(
                step_ref("inject-db"), principal=BOB, environment=PROD, step_id="inject-db"
            )
        assert refusal_code(excinfo.value) == REFUSAL_PRINCIPAL_MISMATCH
        assert fetched == [], "a refused reference must never reach a provider"

    def test_wrong_environment_is_refused(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(environments=(PROD,)),))
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(
                step_ref("inject-db"), principal=ALICE, environment="staging", step_id="inject-db"
            )
        assert refusal_code(excinfo.value) == REFUSAL_ENVIRONMENT_OUT_OF_SCOPE

    def test_pattern_mismatch_is_refused(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(pattern="vault:other/*"),))
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(
                step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
            )
        assert refusal_code(excinfo.value) == REFUSAL_PATTERN_MISMATCH

    def test_expired_grant_is_refused(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(expires_in=-1.0),))
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(
                step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
            )
        assert refusal_code(excinfo.value) == REFUSAL_GRANT_EXPIRED

    def test_scope_not_granted_is_refused_by_the_grant(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(scopes=("step:other",)),))
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(
                step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
            )
        assert refusal_code(excinfo.value) == REFUSAL_SCOPE_NOT_GRANTED

    def test_no_grants_at_all_is_refused(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, ())
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(
                step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
            )
        assert refusal_code(excinfo.value) == REFUSAL_NO_GRANT

    def test_unregistered_provider_is_refused_rather_than_faked(self) -> None:
        engine = SecretResolver(
            providers={}, grant_source=StaticGrantSource((grant(),)), clock=Clock()
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(
                step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
            )
        assert refusal_code(excinfo.value) == REFUSAL_PROVIDER_UNAVAILABLE

    def test_development_only_provider_requires_the_marker(self) -> None:
        engine = SecretResolver(
            providers=default_providers({"MAYHEM_TEST_DB_PASSWORD": SECRET_VALUE}),
            grant_source=StaticGrantSource(
                (grant(pattern="environment:MAYHEM_TEST_DB_PASSWORD"),)
            ),
            clock=Clock(),
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(
                env_ref(), principal=ALICE, environment=PROD, step_id="inject-db"
            )
        assert refusal_code(excinfo.value) == REFUSAL_DEVELOPMENT_PROVIDER

    def test_development_only_provider_resolves_with_the_marker(self) -> None:
        engine = SecretResolver(
            providers=default_providers({"MAYHEM_TEST_DB_PASSWORD": SECRET_VALUE}),
            grant_source=StaticGrantSource(
                (grant(pattern="environment:MAYHEM_TEST_DB_PASSWORD"),)
            ),
            clock=Clock(),
            allow_development_only=True,
        )
        secret = engine.resolve(
            env_ref(), principal=ALICE, environment=PROD, step_id="inject-db"
        )
        with secret.use() as value:
            assert value == SECRET_VALUE


# --- Short-lived credentials ---------------------------------------------------


class TestShortLivedCredentials:
    def test_provider_receives_a_bounded_window(self) -> None:
        seen: list[ProviderRequest] = []

        def spy(request: ProviderRequest) -> bytes:
            seen.append(request)
            return SECRET_VALUE.encode()

        engine = callable_resolver(spy, (grant(),), credential_ttl_seconds=300)
        engine.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        )
        assert len(seen) == 1
        request = seen[0]
        assert request.issued_at == NOW
        assert request.expires_at == NOW + timedelta(seconds=300)
        assert request.seconds_remaining(NOW) == 300
        assert not request.is_expired(NOW)

    def test_fetch_overrunning_the_window_is_refused(self) -> None:
        clock = Clock()

        def slow(request: ProviderRequest) -> bytes:
            clock.advance(400)
            return SECRET_VALUE.encode()

        engine = callable_resolver(
            slow, (grant(),), clock=clock, credential_ttl_seconds=300
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(
                step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
            )
        assert refusal_code(excinfo.value) == REFUSAL_CREDENTIAL_EXPIRED
        assert engine.receipts == (), "a refused fetch records no receipt"

    def test_default_window_is_one_oidc_token_lifetime(self) -> None:
        seen: list[ProviderRequest] = []

        def spy(request: ProviderRequest) -> bytes:
            seen.append(request)
            return b"x"

        engine = callable_resolver(spy, (grant(),))
        engine.resolve(run_ref(), principal=ALICE, environment=PROD, step_id="any-step")
        assert seen[0].seconds_remaining(NOW) == 900


# --- Memory lifetime -----------------------------------------------------------


class TestZeroAfterUse:
    def test_use_yields_the_value_then_zeroes_the_buffer(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(),))
        secret = engine.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        )
        with secret.use() as value:
            assert value == SECRET_VALUE
            # Still intact inside the block: the value exists only here.
            assert secret.residual_nonzero_bytes() == len(SECRET_VALUE)
        assert secret.is_spent
        assert secret.residual_nonzero_bytes() == 0

    def test_a_second_use_is_refused_not_empty(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(),))
        secret = engine.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        )
        with secret.use():
            pass
        with pytest.raises(InvariantViolationError) as excinfo:
            with secret.use():
                pass
        assert refusal_code(excinfo.value) == REFUSAL_SECRET_VALUE_SPENT

    def test_zero_after_use_happens_even_when_the_block_raises(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(),))
        secret = engine.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        )
        with pytest.raises(RuntimeError, match="blew up"):
            with secret.use():
                raise RuntimeError("blew up")
        assert secret.is_spent

    def test_repr_str_and_format_never_carry_the_value(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(),))
        secret = engine.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        )
        for rendered in (repr(secret), str(secret), f"{secret}", format(secret)):
            assert SECRET_VALUE not in rendered
        assert "vault:prod/database" in repr(secret)

    def test_a_resolved_secret_cannot_be_pickled(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(),))
        secret = engine.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        )
        with pytest.raises(TypeError):
            pickle.dumps(secret)

    def test_resolver_records_metadata_but_never_a_value(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(),))
        with engine.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        ).use():
            pass
        assert len(engine.receipts) == 1
        rendered = json.dumps([receipt.to_dict() for receipt in engine.receipts])
        assert SECRET_VALUE not in rendered
        receipt = engine.receipts[0]
        assert receipt.canonical_key == "vault:prod/database"
        assert receipt.grant_pattern == "vault:prod/*"
        assert receipt.scope_token == "step:inject-db"

    def test_guard_needles_are_zeroed_on_release(self) -> None:
        guard = SecretLeakGuard()
        guard.register_value(SECRET_VALUE)
        assert guard.scan_bytes(SECRET_VALUE) != ()
        guard.release()
        assert guard.released
        assert guard.scan_bytes(SECRET_VALUE) == ()


# --- Cross-step leakage --------------------------------------------------------


class TestCrossStepScope:
    def test_step_scoped_value_is_refused_from_the_next_step(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(),))
        reference = step_ref("inject-db")
        with engine.resolve(
            reference, principal=ALICE, environment=PROD, step_id="inject-db"
        ).use() as value:
            assert value == SECRET_VALUE
        # Step N+1 asks for the same reference object.
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(reference, principal=ALICE, environment=PROD, step_id="cleanup-db")
        assert refusal_code(excinfo.value) == REFUSAL_SCOPE_HANDOFF

    def test_a_separate_reference_and_grant_unlocks_the_next_step(self, secret_tree: Path) -> None:
        engine = fixture_resolver(
            secret_tree,
            (grant(scopes=("step:inject-db",)), grant(scopes=("step:cleanup-db",))),
        )
        with engine.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        ).use():
            pass
        with engine.resolve(
            step_ref("cleanup-db"), principal=ALICE, environment=PROD, step_id="cleanup-db"
        ).use() as value:
            assert value == SECRET_VALUE

    def test_run_scoped_value_reaches_every_step(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(),))
        reference = run_ref("r-1")
        for step in ("inject-db", "cleanup-db", "verify-db"):
            with engine.resolve(
                reference, principal=ALICE, environment=PROD, step_id=step
            ).use() as value:
                assert value == SECRET_VALUE

    def test_run_scoped_reference_is_bound_to_its_own_run(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(scopes=("run:r-1",)),))
        with pytest.raises(InvariantViolationError) as excinfo:
            engine.resolve(
                run_ref("r-2"), principal=ALICE, environment=PROD, step_id="inject-db"
            )
        assert refusal_code(excinfo.value) == REFUSAL_SCOPE_NOT_GRANTED


# --- Revocation fences the step ------------------------------------------------


class TestRevocationFence:
    def test_revoked_grant_fences_the_next_step_mid_run(
        self, tmp_path: Path, secret_tree: Path
    ) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        repository = SecretGrantRepository(store)
        repository.save(grant(scopes=("step:inject-db", "step:cleanup-db")))
        engine = SecretResolver(
            providers={SecretProvider.VAULT: FilesystemFixtureProvider(secret_tree)},
            grant_source=StoredGrantSource(repository),
            clock=Clock(),
        )
        with engine.resolve(
            step_ref("inject-db"), principal=ALICE, environment=PROD, step_id="inject-db"
        ).use():
            pass

        # Revoked while the run is still going.
        assert repository.revoke(ALICE, "vault:prod/*") == 1

        with pytest.raises(InvariantViolationError):
            engine.resolve(
                step_ref("cleanup-db"), principal=ALICE, environment=PROD, step_id="cleanup-db"
            )
        store.close()

    def test_grants_round_trip_through_the_store(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        repository = SecretGrantRepository(store)
        original = grant(scopes=("step:inject-db",))
        repository.save(original)
        loaded = repository.grants_for(ALICE)
        assert len(loaded) == 1
        assert loaded[0].credential_pattern == original.credential_pattern
        assert loaded[0].scopes == original.scopes
        assert loaded[0].environments == original.environments
        assert loaded[0].expires_at == original.expires_at
        assert loaded[0].issued_at == original.issued_at
        store.close()

    def test_the_grant_table_has_no_column_a_value_could_occupy(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        rows = store.query("PRAGMA table_info(secret_grants)")
        columns = {str(row["name"]) for row in rows}
        assert columns == {
            "principal",
            "credential_pattern",
            "environments_json",
            "scopes_json",
            "expires_at",
            "issued_at",
        }
        store.close()

    def test_persisted_grant_bytes_never_contain_a_value(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        repository = SecretGrantRepository(store)
        repository.save(grant())
        store.close()
        # Reopen the file as bytes: the value cannot be in it because no code
        # path was given one to write.
        assert SECRET_VALUE.encode() not in (tmp_path / "mayhem.db").read_bytes()


# --- Literal-in-spec refusal (negative control) --------------------------------


class TestLiteralSpecRefusal:
    def test_a_literal_password_in_a_spec_refuses_before_execution(self) -> None:
        spec = {
            "apiVersion": "mayhem/v1",
            "steps": [
                {
                    "id": "inject-db",
                    "with": {
                        "host": "db-1",
                        "password": "hunter2-literal-value",
                        "credentialRef": {"provider": "vault", "secret": "prod/db"},
                    },
                }
            ],
        }
        assert scan_spec_for_literals(spec) == ("$.steps[0].with.password",)
        with pytest.raises(InvariantViolationError) as excinfo:
            require_no_literal_spec(spec)
        assert refusal_code(excinfo.value) == REFUSAL_LITERAL_SECRET
        assert "spec.steps[0].with.password" in str(excinfo.value)

    def test_a_reference_shaped_spec_passes_the_literal_scan(self) -> None:
        spec = {
            "steps": [
                {
                    "with": {
                        "credentialRef": {"provider": "vault", "secret": "prod/db"},
                        "secret_path": "vault://prod/db",
                    }
                }
            ]
        }
        assert scan_spec_for_literals(spec) == ()
        require_no_literal_spec(spec)


# --- Port conformance ----------------------------------------------------------


class TestPorts:
    def test_every_adapter_satisfies_the_provider_port(self) -> None:
        adapters: list[object] = [
            FilesystemFixtureProvider("/nonexistent"),
            EnvironmentSecretProvider({}),
            CallableSecretProvider(SecretProvider.AWS_SECRETS_MANAGER, lambda r: b""),
        ]
        assert all(isinstance(adapter, SecretProviderPort) for adapter in adapters)

    def test_resolver_and_grant_sources_satisfy_their_ports(self, secret_tree: Path) -> None:
        engine = fixture_resolver(secret_tree, (grant(),))
        assert isinstance(engine, SecretResolverPort)
        assert isinstance(StaticGrantSource((grant(),)), GrantSourcePort)

    def test_environment_provider_refuses_a_path_shaped_name(self) -> None:
        provider = EnvironmentSecretProvider({"MAYHEM_X": "v"})
        with pytest.raises(InvariantViolationError) as excinfo:
            provider.fetch(provider_request(env_ref("prod/database")))
        assert refusal_code(excinfo.value) == REFUSAL_PROVIDER_UNAVAILABLE

    def test_environment_provider_refuses_an_empty_value(self) -> None:
        provider = EnvironmentSecretProvider({"MAYHEM_X": ""})
        with pytest.raises(InvariantViolationError) as excinfo:
            provider.fetch(provider_request(env_ref("MAYHEM_X")))
        assert refusal_code(excinfo.value) == REFUSAL_PROVIDER_UNAVAILABLE

    def test_version_pinned_reference_reads_the_pinned_file(self, tmp_path: Path) -> None:
        root = tmp_path / "secrets"
        (root / "vault").mkdir(parents=True, exist_ok=True)
        (root / "vault" / "prod__database.v2").write_text("pinned-value", encoding="utf-8")
        provider = FilesystemFixtureProvider(root)
        reference = CredentialRef(
            provider=SecretProvider.VAULT,
            secret="prod/database",
            purpose="replay against the pinned version",
            scope=CredentialScope(kind=ScopeKind.RUN, ref="r-1"),
            version="v2",
        )
        assert provider.fetch(provider_request(reference)) == b"pinned-value"

    def test_resolved_secret_constructed_directly_zeroes_on_zero(self) -> None:
        secret = ResolvedSecret.from_bytes(
            SECRET_VALUE.encode(),
            canonical_key="vault:prod/db",
            scope_token="run:r-1",
            purpose="p",
        )
        live = secret.residual_nonzero_bytes()
        secret.zero()
        assert live == len(SECRET_VALUE)
        assert secret.is_spent
        assert secret.residual_nonzero_bytes() == 0
        # Idempotent: zeroing a spent value is not an error.
        secret.zero()
        assert secret.residual_nonzero_bytes() == 0
