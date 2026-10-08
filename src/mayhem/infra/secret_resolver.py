"""Late secret resolution with least privilege (plan 29 Phase 2).

Phase 1 (``mayhem.domain.secrets``) decided whether a reference *may* be
resolved. It could not fetch anything: every type in it is pure, and the domain
layer carries a hard zero-IO contract (``[tool.importlinter]`` forbids
``os``, ``pathlib``, ``sqlite3`` and ``subprocess`` under ``mayhem.domain``).
This module is the other half — the fetch, the grant check that authorises it,
and the memory discipline that keeps the value from outliving its step.

Four properties, and this module exists to hold all four at once:

* **Late.** Nothing here is called at authoring time. A ``CredentialRef`` is
  inert until a step asks for it, which is what makes the grant decision
  answerable: the principal, environment, and scope are all known at that
  moment.
* **Least privilege.** :meth:`SecretResolver.resolve` re-checks the whole grant
  (principal, environment, pattern, scope, expiry) on *every* call against a
  live grant source, so a revocation that lands mid-run fences the next step
  instead of being observed only at the start. The check itself is
  :func:`mayhem.domain.secrets.require_reference` — the engine adds no
  authorization vocabulary of its own, it only decides *when* to ask.
* **Narrow scope.** ``resolve`` takes the ``step_id`` being executed. A
  step-scoped reference resolves only in the step it names, so a value obtained
  in step N is structurally unreachable in step N+1. Running it there requires a
  separate reference carrying its own grant — which is the plan's "unless
  separately granted", expressed as a parameter rather than as a cache
  invalidation rule nobody remembers to call.
* **Memory-only.** A value arrives as ``bytes`` into a :class:`bytearray` this
  module owns, is handed out through :meth:`ResolvedSecret.use` for exactly one
  lexical block, and is overwritten with zeroes on the way out. It is never
  written to the store, never placed in an envelope, never logged.

**No provider SDK, on purpose.** The declared dependency set for this project
is exactly pydantic, typer, click, pyyaml, structlog, kubernetes, and plan 29
Phase 2 does not get to widen it. So every cloud provider is a *seam*, not an
implementation: :class:`SecretProviderPort` is a one-method protocol and
:class:`CallableSecretProvider` wraps whatever callable the deployment
injects. Two providers are real here, because they need no library:

* :class:`EnvironmentSecretProvider` — reads the process environment, and is
  development-only by construction. The resolver refuses it unless the caller
  passes ``allow_development_only=True``, so a local convenience cannot become
  a production path by omission.
* :class:`FilesystemFixtureProvider` — reads values from a directory tree, so
  unit tests exercise the resolver end to end with no network and no SDK. The
  plan's "provider-adapter tests against fixtures".

The grant *records* persist (migration ``M0022_SECRET_GRANTS``) and the values
never do: the table has no column a value could occupy, and
:class:`SecretGrantRepository` is the only writer.

The other half of the phase is the evidence boundary, and it lives here too
because it is the same problem seen from the output side. :class:`SecretLeakGuard`
scans artifact *bytes* for values the run actually resolved. Name-based
redaction cannot be the primary defence — it triggers on how a field is
*called*, so a value written under ``detail`` or embedded in a provider's stderr
survives it — which is exactly why ``redact`` is backup and not policy.

## Phase 4: why the guard cannot be skipped

A guard that a caller may decline to call is documentation. So from Phase 4 the
boundary is not "call :meth:`SecretLeakGuard.require_clean_envelope` before you
write" — it is **two rules with no opt-out parameter**, reachable from a single
module and invoked by the write paths themselves:

* **The grade rule is stateless.** :func:`require_persistable_document` calls
  :meth:`FieldClassifications.require_persistable` on every document it is
  handed, always, whether or not a run ever resolved anything. It needs no
  registry, no configuration and no run state, so there is nothing a caller can
  leave unset to switch it off.
* **The byte rule is ambient.** A :class:`SecretLeakGuard` made active by
  :func:`guard_evidence_writes` is consulted by *every* artifact write in the
  process, including from threads the caller did not spawn on the guard's
  thread. The registry is a lock-guarded set rather than a
  :class:`~contextvars.ContextVar` precisely because a security gate should fail
  closed in a worker thread, not silently fall back to "no needles registered".

The registry is the *only* optional part, and it is optional in the safe
direction: no active guard means no resolved value exists for the run to leak,
because a value can only enter the process through :meth:`SecretResolver.resolve`
and that is what registers the needles.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.evidence import require_persistable_envelope
from mayhem.domain.secrets import (
    DEVELOPMENT_ONLY_PROVIDERS,
    EVIDENCE_FIELD_CLASSIFICATIONS,
    CredentialRef,
    FieldClassifications,
    ScopeKind,
    SecretGrant,
    SecretProvider,
    find_literal_credentials,
    require_no_literal_credentials,
    require_reference,
)
from mayhem.domain.secrets import (
    REFUSAL_DEVELOPMENT_PROVIDER as _DOMAIN_DEVELOPMENT_PROVIDER_REFUSAL,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Mapping

    from mayhem.domain.evidence import EvidenceEnvelope
    from mayhem.infra.store import Store

# --- Refusal codes (Phase 2 additions) ----------------------------------------
# Phase 1 owns the grant-dimension codes in ``domain.secrets``. These are the
# codes the *engine* can produce, and all of them are about the fetch rather
# than about permission.

#: No adapter is registered for the reference's provider in this build.
REFUSAL_PROVIDER_UNAVAILABLE = "secret.provider_unavailable"
#: A development-only provider was used without the explicit per-run marker.
#: Re-exported rather than re-spelled: Phase 3 gives the *authoring* refusal
#: the same code (a spec naming a development-only provider without its marker),
#: and two spellings of one rule is how an operator ends up grepping for a
#: string that only one of them uses.
REFUSAL_DEVELOPMENT_PROVIDER = _DOMAIN_DEVELOPMENT_PROVIDER_REFUSAL
#: The short-lived credential window elapsed while the provider was fetching.
REFUSAL_CREDENTIAL_EXPIRED = "secret.provider_credential_expired"
#: A resolved value was used again after it had been zeroed.
REFUSAL_SECRET_VALUE_SPENT = "secret.resolved_value_already_spent"
#: Credential bytes were found in an artifact bound for a reviewer.
REFUSAL_SECRET_BYTES_IN_ARTIFACT = "secret.credential_bytes_in_artifact"
#: A step-scoped credential was asked for from a different step.
REFUSAL_SCOPE_HANDOFF = "secret.resolver_scope_handoff"

#: How long a provider credential stays usable after it is minted. Workload
#: identity exchanges return tokens with minutes, not hours; the default is one
#: OIDC access-token lifetime, and a fetch that overruns it is refused rather
#: than allowed to finish holding a credential nobody can revoke.
DEFAULT_CREDENTIAL_TTL_SECONDS = 900

#: Needle lengths below this are refused by the byte scan: a one- or two-byte
#: "secret" matches everything, so scanning for it is not a check.
MINIMUM_SCANNABLE_SECRET_BYTES = 4


def _zero(buffer: bytearray) -> None:
    """Overwrite ``buffer`` in place with NUL bytes.

    In place, because assigning a fresh object would leave the old one alive
    until the collector runs — which is precisely the lifetime this module
    exists to shorten.
    """
    buffer[:] = bytes(len(buffer))


# --- The provider seam ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    """One provider call: what to fetch, under whose identity, until when.

    ``expires_at`` is the short-lived window. An adapter that needs a bearer
    token mints one inside it; an adapter that exchanges a workload identity
    asserts on it. Nothing in the request carries a value.
    """

    reference: CredentialRef
    principal: str
    environment: str
    issued_at: datetime
    expires_at: datetime

    def seconds_remaining(self, now: datetime) -> float:
        return (self.expires_at - now).total_seconds()

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at <= now


@runtime_checkable
class SecretProviderPort(Protocol):
    """The one method every provider adapter implements.

    A port rather than a base class on purpose: a Vault adapter, a Kubernetes
    adapter, and a fixture adapter share no code beyond this signature, and the
    resolver never needs to know which one it holds.
    """

    def fetch(self, request: ProviderRequest) -> bytes:
        """Return the raw secret bytes, or raise.

        Raises:
            InvariantViolationError: When the value cannot be fetched. The code
                names the reason; the message must never name the value.
        """
        ...


class CallableSecretProvider:
    """Adapts an injected callable to :class:`SecretProviderPort`.

    This is where a real deployment plugs in: ``CallableSecretProvider(
    SecretProvider.VAULT, lambda req: hvac_client.read(req.reference.secret)
    )``. Mayhem ships no client, so this adapter is what "supports Vault"
    honestly means in a build with no Vault dependency.
    """

    def __init__(self, provider: SecretProvider, fetch: Callable[[ProviderRequest], bytes]) -> None:
        self._provider = provider
        self._fetch = fetch

    @property
    def provider(self) -> SecretProvider:
        return self._provider

    def fetch(self, request: ProviderRequest) -> bytes:
        return self._fetch(request)


class EnvironmentSecretProvider:
    """Reads a value from the process environment. Development-only.

    The reference's ``secret`` is the variable name. The provider refuses a name
    that is not a plain environment identifier, so a path-shaped secret cannot
    quietly become a path lookup, and it refuses empty values rather than
    resolving them — an empty secret that looks resolved is worse than a missing
    one, because it fails at the target instead of here.
    """

    _IDENTIFIER = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")

    def __init__(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        provider: SecretProvider = SecretProvider.ENVIRONMENT,
    ) -> None:
        self._environ = environ
        self._provider = provider

    @property
    def provider(self) -> SecretProvider:
        return self._provider

    def fetch(self, request: ProviderRequest) -> bytes:
        name = request.reference.secret
        if not name or name[0].isdigit() or not set(name) <= self._IDENTIFIER:
            raise InvariantViolationError(
                REFUSAL_PROVIDER_UNAVAILABLE,
                f"environment provider: {name!r} is not a plain environment variable "
                "name; author a reference whose secret is the variable name",
            )
        value = os.environ.get(name) if self._environ is None else self._environ.get(name)
        if value is None or value == "":
            raise InvariantViolationError(
                REFUSAL_PROVIDER_UNAVAILABLE,
                f"environment provider: variable {name!r} is unset or empty",
            )
        return value.encode()


class FilesystemFixtureProvider:
    """Reads values from a directory tree. Test fixtures only.

    Layout is ``<root>/<provider>/<secret>`` with ``/`` in ``secret`` mapped to
    ``__``, plus a ``.<version>`` suffix when the reference pins a version. It
    exists so unit tests exercise the resolver end to end with no network and no
    SDK.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        provider: SecretProvider = SecretProvider.VAULT,
    ) -> None:
        self._root = Path(root)
        self._provider = provider

    @property
    def provider(self) -> SecretProvider:
        return self._provider

    def fetch(self, request: ProviderRequest) -> bytes:
        reference = request.reference
        name = reference.secret.replace("/", "__")
        if reference.version:
            name = f"{name}.{reference.version}"
        target = self._root / self._provider.value / name
        try:
            return target.read_bytes()
        except OSError as exc:
            raise InvariantViolationError(
                REFUSAL_PROVIDER_UNAVAILABLE,
                f"fixture provider: {reference.canonical_key!r} is absent at {target}",
            ) from exc


def default_providers(
    environ: Mapping[str, str] | None = None,
) -> dict[SecretProvider, SecretProviderPort]:
    """The providers that need no third-party client.

    Only the development-only environment provider. Every other provider in the
    plan's vocabulary is a seam with no implementation in this build, and
    pretending otherwise would mean shipping an SDK.
    """
    provider = EnvironmentSecretProvider(environ)
    return {provider.provider: provider}


# --- Resolved value ------------------------------------------------------------


class ResolvedSecret:
    """A credential value in memory: spendable once, then zeroed.

    Holds a :class:`bytearray` rather than a ``str`` because a ``str`` cannot be
    overwritten — the most a string-valued design can promise is "we drop our
    reference", which is a claim about garbage collection, not about custody.
    :meth:`use` yields the decoded text for one lexical block and zeroes on the
    way out, including when the block raises.

    The value is not reachable through ``repr``, ``str``, ``format``, or
    ``pickle``: :meth:`use` is the only exit, which is the whole enforcement
    story for "values live in memory only".
    """

    __slots__ = ("_buffer", "_canonical_key", "_purpose", "_scope_token", "_spent")

    def __init__(
        self,
        buffer: bytearray,
        *,
        canonical_key: str,
        scope_token: str,
        purpose: str,
    ) -> None:
        self._buffer = buffer
        self._canonical_key = canonical_key
        self._scope_token = scope_token
        self._purpose = purpose
        self._spent = False

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        canonical_key: str,
        scope_token: str,
        purpose: str,
    ) -> ResolvedSecret:
        """Adopt a freshly fetched value.

        ``raw`` is copied so the caller's buffer can be dropped immediately
        after the call returns, leaving exactly one owner of the bytes.
        """
        return cls(
            bytearray(raw),
            canonical_key=canonical_key,
            scope_token=scope_token,
            purpose=purpose,
        )

    @property
    def is_spent(self) -> bool:
        """True once the value has been zeroed."""
        return self._spent

    @property
    def canonical_key(self) -> str:
        return self._canonical_key

    @property
    def scope_token(self) -> str:
        return self._scope_token

    @property
    def purpose(self) -> str:
        return self._purpose

    def copy_bytes(self) -> bytes:
        """A snapshot of the value, for a caller that must own its own buffer.

        Intended for :class:`SecretLeakGuard`, which needs the bytes in order to
        recognise them later and keeps them in a buffer it zeroes itself.
        """
        if self._spent:
            raise InvariantViolationError(
                REFUSAL_SECRET_VALUE_SPENT,
                f"{self._canonical_key}: resolved value was already spent and zeroed",
            )
        return bytes(self._buffer)

    def zero(self) -> None:
        """Overwrite the value. Idempotent."""
        if not self._spent:
            _zero(self._buffer)
            self._spent = True

    def residual_nonzero_bytes(self) -> int:
        """How many bytes of the buffer are still non-zero.

        Exposed so custody is *checkable* rather than merely asserted: a caller
        (or a test) can prove the buffer was overwritten instead of trusting
        that it was. Zero once spent; the full length before.
        """
        return sum(1 for byte in self._buffer if byte)

    @contextmanager
    def use(self) -> Iterator[str]:
        """Yield the value once, then zero it — even if the block raises.

        Raises:
            InvariantViolationError: With :data:`REFUSAL_SECRET_VALUE_SPENT`
                when the value was already spent. Re-reading a zeroed credential
                is the failure this makes loud, rather than returning ``""``.
        """
        if self._spent:
            raise InvariantViolationError(
                REFUSAL_SECRET_VALUE_SPENT,
                f"{self._canonical_key}: resolved value was already spent and zeroed",
            )
        try:
            yield self._buffer.decode()
        finally:
            self.zero()

    def __repr__(self) -> str:
        state = "spent" if self._spent else "live"
        return f"<ResolvedSecret {self._canonical_key} scope={self._scope_token} {state}>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return self.__repr__()

    def __reduce__(self) -> tuple[Any, ...]:
        raise TypeError("ResolvedSecret is not serializable: a secret value cannot leave memory")


@dataclass(frozen=True, slots=True)
class ResolutionReceipt:
    """What may be recorded about a resolution. Never the value.

    A receipt answers "did this run hold this credential, for what purpose,
    under whose identity, and was it in time" — which is what a reviewer and a
    rotation runbook need, and which is fully expressible without the value.
    """

    provider: SecretProvider
    canonical_key: str
    purpose: str
    scope_token: str
    principal: str
    environment: str
    grant_pattern: str
    resolved_at: datetime
    credential_expires_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe metadata, safe to place in evidence: no value is present."""
        return {
            "provider": self.provider.value,
            "canonical_key": self.canonical_key,
            "purpose": self.purpose,
            "scope_token": self.scope_token,
            "principal": self.principal,
            "environment": self.environment,
            "grant_pattern": self.grant_pattern,
            "resolved_at": self.resolved_at.isoformat(),
            "credential_expires_at": self.credential_expires_at.isoformat(),
        }


# --- Grant sources -------------------------------------------------------------


@runtime_checkable
class GrantSourcePort(Protocol):
    """A live set of grants, re-read on every resolution.

    Live rather than captured at construction, because that is what makes a
    mid-run revocation bite: the grant is consulted again when step N+1 asks,
    not once when the run started.
    """

    def current(self) -> tuple[SecretGrant, ...]: ...


class StaticGrantSource:
    """An in-memory grant set. The default for tests and single-process runs."""

    def __init__(self, grants: Iterable[SecretGrant] = ()) -> None:
        self._grants = tuple(grants)

    def current(self) -> tuple[SecretGrant, ...]:
        return self._grants


class SecretGrantRepository:
    """Persistence for grant *records*. There is deliberately no value column.

    The table is the audit of who was allowed to resolve what, and until when,
    read back at resolution time so a revocation can be enforced by the same
    query that recorded it.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def save(self, grant: SecretGrant) -> None:
        """Insert or replace one grant record.

        Gated like every other store write: the schema has no column a value
        could occupy, but the *contents* of a column are still caller-supplied
        strings, and ``environments=("vault-value-9f3c-...",)`` is a refusal this
        module can make cheaply. Without the gate the guarantee would be "no
        column exists" plus "nobody thought of that", which is one of the two.
        """
        issued = grant.issued_at.isoformat() if grant.issued_at else ""
        require_persistable_document(
            {
                "secret_grants": {
                    "principal": grant.principal,
                    "credential_pattern": grant.credential_pattern,
                    "environments_json": json.dumps(list(grant.environments)),
                    "scopes_json": json.dumps(list(grant.scopes)),
                    "expires_at": grant.expires_at.isoformat(),
                    "issued_at": issued,
                }
            },
            artifact="store:secret_grants",
        )
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO secret_grants "
                "(principal, credential_pattern, environments_json, scopes_json, "
                "expires_at, issued_at) VALUES (?,?,?,?,?,?)",
                (
                    grant.principal,
                    grant.credential_pattern,
                    json.dumps(list(grant.environments)),
                    json.dumps(list(grant.scopes)),
                    grant.expires_at.isoformat(),
                    issued,
                ),
            )

    def load_all(self) -> tuple[SecretGrant, ...]:
        """Every persisted grant, expired ones included.

        Expiry is deliberately not filtered here: an expired grant is still
        evidence that a permission once existed, and the access decision belongs
        to the domain predicate with an explicit clock rather than to a WHERE
        clause nobody can audit.
        """
        rows = self._store.query(
            "SELECT principal, credential_pattern, environments_json, scopes_json, "
            "expires_at, issued_at FROM secret_grants ORDER BY principal, credential_pattern"
        )
        return tuple(
            SecretGrant(
                principal=str(row["principal"]),
                credential_pattern=str(row["credential_pattern"]),
                environments=tuple(json.loads(str(row["environments_json"]))),
                scopes=tuple(json.loads(str(row["scopes_json"]))),
                expires_at=datetime.fromisoformat(str(row["expires_at"])),
                issued_at=(
                    datetime.fromisoformat(str(row["issued_at"])) if str(row["issued_at"]) else None
                ),
            )
            for row in rows
        )

    def grants_for(self, principal: str) -> tuple[SecretGrant, ...]:
        return tuple(grant for grant in self.load_all() if grant.principal == principal)

    def revoke(self, principal: str, credential_pattern: str) -> int:
        """Delete matching grant records; returns the number of rows removed.

        Revocation is a delete, not a flag. A grant with no end date would be a
        standing permission, which the domain model refuses to express, so the
        honest revocation removes the record and leaves the prior resolution
        receipts as the standing evidence that the permission existed.
        """
        with self._store.write() as conn:
            cursor = conn.execute(
                "DELETE FROM secret_grants WHERE principal = ? AND credential_pattern = ?",
                (principal, credential_pattern),
            )
        return int(cursor.rowcount or 0)


class StoredGrantSource:
    """Reads grants from the store on every resolution.

    This is the revocation fence: a :meth:`SecretGrantRepository.revoke` is
    visible to the next :meth:`current`, because nothing is cached.
    """

    def __init__(self, repository: SecretGrantRepository) -> None:
        self._repository = repository

    def current(self) -> tuple[SecretGrant, ...]:
        return self._repository.load_all()


# --- The resolver --------------------------------------------------------------


@runtime_checkable
class SecretResolverPort(Protocol):
    """The engine seam a step depends on, so no step imports a provider."""

    def resolve(
        self,
        reference: CredentialRef,
        *,
        principal: str,
        environment: str,
        step_id: str,
        now: datetime | None = None,
    ) -> ResolvedSecret:
        """Fetch a granted reference for the step about to execute."""
        ...


class SecretResolver:
    """Late resolution under policy, one step at a time.

    Deliberately thin. It decides *when* to ask
    :func:`mayhem.domain.secrets.require_reference`, insists the scope matches
    the step being executed, bounds the provider credential's lifetime, and owns
    the bytes afterwards. It adds no authorization vocabulary of its own.
    """

    def __init__(
        self,
        *,
        providers: Mapping[SecretProvider, SecretProviderPort] | None = None,
        grant_source: GrantSourcePort | None = None,
        clock: Callable[[], datetime] = utc_now,
        credential_ttl_seconds: int = DEFAULT_CREDENTIAL_TTL_SECONDS,
        allow_development_only: bool = False,
        guard: SecretLeakGuard | None = None,
    ) -> None:
        self._providers: dict[SecretProvider, SecretProviderPort] = dict(providers or {})
        self._grant_source: GrantSourcePort = grant_source or StaticGrantSource()
        self._clock = clock
        self._credential_ttl = timedelta(seconds=credential_ttl_seconds)
        self._allow_development_only = allow_development_only
        self._guard = guard
        self._receipts: list[ResolutionReceipt] = []

    @property
    def receipts(self) -> tuple[ResolutionReceipt, ...]:
        """Metadata for every resolution so far. Never a value."""
        return tuple(self._receipts)

    def development_marker(self) -> dict[str, Any]:
        """The per-run development-only marker as sealable metadata. Read-only.

        Plan 29 Phase 3 requires the explicit per-run marker to be *sealed into
        evidence*, not just held in memory: a run that resolved a development-only
        credential left its :class:`ResolutionReceipt`\\ s in
        :attr:`receipts` only, which die with the process. This is the payload
        :mod:`mayhem.controller.secret_evidence` seals — the run-wide flag plus
        the development-only receipts' own :meth:`ResolutionReceipt.to_dict`
        (provider, canonical key, purpose, scope, principal, environment, grant
        pattern, timestamps), which is already evidence-safe because it never
        carries a value. Non-development receipts are counted, not carried: the
        marker is about the development-only path, and the full receipt set stays
        queryable on the resolver for the run's lifetime.
        """
        dev_only = tuple(
            receipt for receipt in self._receipts if receipt.provider in DEVELOPMENT_ONLY_PROVIDERS
        )
        return {
            "allow_development_only": self._allow_development_only,
            "development_only_providers": sorted({receipt.provider.value for receipt in dev_only}),
            "development_only_receipts": [receipt.to_dict() for receipt in dev_only],
            "receipt_count": len(self._receipts),
        }

    def register_provider(self, provider: SecretProvider, adapter: SecretProviderPort) -> None:
        self._providers[provider] = adapter

    def resolve(
        self,
        reference: CredentialRef,
        *,
        principal: str,
        environment: str,
        step_id: str,
        now: datetime | None = None,
    ) -> ResolvedSecret:
        """Resolve a reference for the step about to run, or refuse.

        The ordering is policy, not convenience: nothing is fetched until the
        grant is proven, so a refusal never leaves a value in memory to clean up.

        Raises:
            InvariantViolationError: With the most specific refusal code — a
                grant-dimension code from ``domain.secrets`` when no grant
                authorises the reference; :data:`REFUSAL_SCOPE_HANDOFF` when a
                step-scoped reference is asked for from a different step;
                :data:`REFUSAL_DEVELOPMENT_PROVIDER` when a development-only
                provider is used without the marker;
                :data:`REFUSAL_PROVIDER_UNAVAILABLE` when no adapter is
                registered or the value is absent; and
                :data:`REFUSAL_CREDENTIAL_EXPIRED` when the fetch overran its
                short-lived credential window.
        """
        moment = self._clock() if now is None else now
        grants = tuple(self._grant_source.current())
        grant = require_reference(
            reference,
            grants,
            principal=principal,
            environment=environment,
            now=moment,
            field="credentialRef",
        )
        if reference.scope.kind is ScopeKind.STEP and reference.scope.ref != step_id:
            raise InvariantViolationError(
                REFUSAL_SCOPE_HANDOFF,
                f"credentialRef: reference is bound to step {reference.scope.ref!r} and "
                f"cannot be resolved while step {step_id!r} executes; author a separate "
                "reference and grant for that step",
            )
        if reference.is_development_only() and not self._allow_development_only:
            raise InvariantViolationError(
                REFUSAL_DEVELOPMENT_PROVIDER,
                f"credentialRef: provider {reference.provider.value!r} is development-only "
                "and requires an explicit per-run marker before it may be resolved",
            )
        adapter = self._providers.get(reference.provider)
        if adapter is None:
            raise InvariantViolationError(
                REFUSAL_PROVIDER_UNAVAILABLE,
                f"credentialRef: no adapter registered for provider "
                f"{reference.provider.value!r}; register one before resolving",
            )
        request = ProviderRequest(
            reference=reference,
            principal=principal,
            environment=environment,
            issued_at=moment,
            expires_at=moment + self._credential_ttl,
        )
        raw = adapter.fetch(request)
        finished = self._clock()
        if finished > request.expires_at:
            raise InvariantViolationError(
                REFUSAL_CREDENTIAL_EXPIRED,
                f"credentialRef: the provider credential for "
                f"{reference.canonical_key!r} expired mid-fetch (window "
                f"{int(self._credential_ttl.total_seconds())}s); refusing the value",
            )
        secret = ResolvedSecret.from_bytes(
            raw,
            canonical_key=reference.canonical_key,
            scope_token=reference.scope_token,
            purpose=reference.purpose,
        )
        del raw
        self._receipts.append(
            ResolutionReceipt(
                provider=reference.provider,
                canonical_key=reference.canonical_key,
                purpose=reference.purpose,
                scope_token=reference.scope_token,
                principal=principal,
                environment=environment,
                grant_pattern=grant.credential_pattern,
                resolved_at=finished,
                credential_expires_at=request.expires_at,
            )
        )
        if self._guard is not None:
            self._guard.register(secret)
        return secret


def development_marker_is_sealable(marker: Mapping[str, Any]) -> bool:
    """True when a development marker says anything worth sealing.

    A resolver that never set the per-run flag and resolved nothing
    development-only produces an all-default marker; sealing that would write a
    row that proves nothing, which is noise a later reader has to rule out.
    Anything else — the flag set, or at least one development-only receipt —
    is a fact about the run worth attesting.
    """
    return bool(marker.get("allow_development_only")) or bool(
        marker.get("development_only_receipts")
    )


# --- Authoring-time gates ------------------------------------------------------


def scan_spec_for_literals(spec: Mapping[str, Any]) -> tuple[str, ...]:
    """Literal-credential paths in a spec, before anything is executed.

    Delegates to the domain's name-based scanner rather than reimplementing it,
    so "what counts as a literal" has exactly one answer in the codebase.
    """
    return find_literal_credentials(spec)


def require_no_literal_spec(spec: Mapping[str, Any], *, field_name: str = "spec") -> None:
    """Refuse a spec carrying a literal credential.

    Raises:
        InvariantViolationError: With
            ``mayhem.domain.secrets.REFUSAL_LITERAL_SECRET`` and every offending
            path named.
    """
    require_no_literal_credentials(spec, path=field_name)


# --- Evidence boundary: the byte-scan guard ------------------------------------


@dataclass(frozen=True, slots=True)
class SecretByteHit:
    """One credential value found in an artifact. Reports a digest, not a value."""

    artifact: str
    offset: int
    needle_index: int
    needle_digest: str

    def describe(self) -> str:
        return (
            f"{self.artifact}: credential bytes at offset {self.offset} "
            f"(value sha256 {self.needle_digest[:12]}, needle #{self.needle_index})"
        )


class SecretLeakGuard:
    """Scans artifact bytes for values this run actually resolved.

    The needle set comes from :class:`ResolvedSecret` at resolution time, so
    the scan needs no vocabulary, no schema, and no guess about where a value
    might have been planted — which is the property name-based redaction cannot
    offer. Needles live in memory, are zeroed by :meth:`release`, and the guard
    refuses needles too short to be a meaningful search.
    """

    def __init__(self, *, minimum_length: int = MINIMUM_SCANNABLE_SECRET_BYTES) -> None:
        self._needles: list[bytearray] = []
        self._digests: list[str] = []
        self._minimum_length = minimum_length
        self._released = False

    def register(self, secret: ResolvedSecret) -> None:
        """Track a resolved value's bytes."""
        raw = secret.copy_bytes()
        self._needles.append(bytearray(raw))
        self._digests.append(hashlib.sha256(raw).hexdigest())

    def register_value(self, value: str | bytes) -> int:
        """Track bytes known directly. Returns the needle index.

        For fixtures and tests, where the "value" never passed through a
        resolver but must still be provably absent from an artifact.
        """
        raw = value.encode() if isinstance(value, str) else bytes(value)
        self._needles.append(bytearray(raw))
        self._digests.append(hashlib.sha256(raw).hexdigest())
        return len(self._needles) - 1

    @property
    def needle_count(self) -> int:
        return len(self._needles)

    @property
    def released(self) -> bool:
        return self._released

    def release(self) -> None:
        """Zero every needle. Idempotent."""
        for needle in self._needles:
            _zero(needle)
        self._released = True

    def scan_bytes(
        self, payload: bytes | str, *, artifact: str = "<memory>"
    ) -> tuple[SecretByteHit, ...]:
        """Every (artifact, offset, needle) where a tracked value appears."""
        raw = payload.encode() if isinstance(payload, str) else bytes(payload)
        hits: list[SecretByteHit] = []
        for index, needle in enumerate(self._needles):
            if len(needle) < self._minimum_length:
                continue
            pattern = bytes(needle)
            start = raw.find(pattern)
            while start != -1:
                hits.append(
                    SecretByteHit(
                        artifact=artifact,
                        offset=start,
                        needle_index=index,
                        needle_digest=self._digests[index],
                    )
                )
                start = raw.find(pattern, start + 1)
        return tuple(hits)

    def require_clean_bytes(self, payload: bytes | str, *, artifact: str) -> None:
        """Raise when a tracked value appears in ``payload``.

        Raises:
            InvariantViolationError: With
                :data:`REFUSAL_SECRET_BYTES_IN_ARTIFACT`, naming the artifact
                and the offsets. The message reports a sha256 prefix, never the
                value — an exception carrying the secret would carry it into
                every log that captured the traceback.
        """
        hits = self.scan_bytes(payload, artifact=artifact)
        if not hits:
            return
        detail = "; ".join(hit.describe() for hit in hits[:5])
        more = "" if len(hits) <= 5 else f" (+{len(hits) - 5} more)"
        raise InvariantViolationError(
            REFUSAL_SECRET_BYTES_IN_ARTIFACT,
            f"{artifact}: resolved credential value(s) present in artifact bytes: {detail}{more}",
        )

    def require_clean_document(
        self,
        document: Any,
        *,
        artifact: str,
        classifications: FieldClassifications = EVIDENCE_FIELD_CLASSIFICATIONS,
    ) -> None:
        """Grade-gate then byte-scan a JSON-shaped document.

        Both checks, in this order: the grade gate is the cheap refusal with the
        better message, and the byte scan is the one that catches a value planted
        under a field name nobody graded.
        """
        classifications.require_persistable(document, path=artifact)
        self.require_clean_bytes(
            json.dumps(document, sort_keys=True, default=str), artifact=artifact
        )

    def require_clean_envelope(
        self, envelope: EvidenceEnvelope, *, artifact: str = "envelope"
    ) -> None:
        """Gate an evidence envelope on both rules before it is sealed."""
        self.require_clean_document(envelope.model_dump(mode="json"), artifact=artifact)

    def require_clean_tree(self, directory: str | Path, *, artifact: str = "") -> tuple[str, ...]:
        """Byte-scan every file under ``directory``; returns the names scanned.

        A sealed bundle is a directory of files, so "scan the bundle" is "scan
        the tree". Enumerating the directory rather than naming the files we
        expect is what keeps the check honest when an artifact is added later.
        """
        base = Path(directory)
        scanned: list[str] = []
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            label = f"{artifact}:{path.relative_to(base).as_posix()}" if artifact else path.name
            self.require_clean_bytes(path.read_bytes(), artifact=label)
            scanned.append(label)
        return tuple(scanned)


def require_clean_bundle(bundle_directory: str | Path, guard: SecretLeakGuard) -> tuple[str, ...]:
    """Scan a sealed bundle directory for credential bytes.

    The plan's Phase 4 acceptance criterion as a function: a bundle produced by
    a secrets-bearing run contains zero credential bytes. Raises rather than
    returning a verdict, because every caller of this is a gate, not a report.
    """
    return guard.require_clean_tree(bundle_directory, artifact="bundle")


# --- Phase 4: the ambient enforcement boundary ---------------------------------
#
# The write paths in ``infra.evidence``, ``infra.report`` and
# ``infra.evidence_bundle_io`` do not take a guard argument and do not read
# configuration: they call the four functions below. That is the whole
# enforcement story, and it is worth stating plainly why it is shaped this way.
#
# A caller-supplied guard is skippable — the caller holds the guard, so the
# caller decides whether to pass it, and every new call site repeats the
# decision. An ambient registry inverts that: the guard is *registered by the
# thing that resolved the value*, and the write path consults it whether or not
# anybody thought to mention it. The grade rule needs no registration at all, so
# even a run that never resolves a credential still cannot persist a field
# graded ``secret``.

# The registry is process-wide rather than a :class:`~contextvars.ContextVar`
# because a fault executed on a worker thread writes its evidence from that
# thread, and a guard scoped to the resolving thread would not be consulted
# there. Failing closed — scanning too much — is the correct bias for a leak
# gate, so the set is shared and lock-guarded rather than thread-local.
_ACTIVE_GUARDS: list[SecretLeakGuard] = []
_ACTIVE_LOCK = threading.RLock()


@contextmanager
def guard_evidence_writes(guard: SecretLeakGuard) -> Iterator[SecretLeakGuard]:
    """Make ``guard`` apply to every evidence write in this process.

    Intended use is ``with``::

        with guard_evidence_writes(guard):
            envelope = build_evidence(...)

    The needles themselves are zeroed by :meth:`SecretLeakGuard.release`; this
    scope only decides *when* the guard is consulted.
    """
    with _ACTIVE_LOCK:
        if guard not in _ACTIVE_GUARDS:
            _ACTIVE_GUARDS.append(guard)
    try:
        yield guard
    finally:
        # Unconditional, including when the block raises: a registry entry left
        # behind is process-global state that outlives the run that created it.
        with _ACTIVE_LOCK:
            if guard in _ACTIVE_GUARDS:
                _ACTIVE_GUARDS.remove(guard)


def active_guards() -> tuple[SecretLeakGuard, ...]:
    """Every guard currently applying to evidence writes, in registration order."""
    with _ACTIVE_LOCK:
        return tuple(_ACTIVE_GUARDS)


def require_clean_artifact(payload: bytes | str, *, artifact: str) -> None:
    """Refuse ``payload`` when any active guard's needle appears in it.

    The byte rule on its own, for surfaces that are already strings or bytes —
    a rendered report file, a bundle file's contents, a log line.

    Raises:
        InvariantViolationError: With
            :data:`REFUSAL_SECRET_BYTES_IN_ARTIFACT`, naming the artifact and the
            offsets. Never the value.
    """
    for guard in active_guards():
        guard.require_clean_bytes(payload, artifact=artifact)


def require_persistable_document(document: Any, *, artifact: str) -> None:
    """The gate every evidence write path calls. Two rules, no opt-out.

    The grade rule runs first and unconditionally: a field name graded ``secret``
    is refused whatever produced it, whether or not this run resolved anything.
    The byte rule runs second and only for guards that are active, because it is
    the only one that needs run state.

    Splitting them this way is deliberate. A single "check the guard" call would
    be vacuous with no guard registered; a single name-based check would miss a
    value planted under ``detail``. Keeping both means the cheap structural rule
    is always on and the expensive value rule is on whenever there is a value to
    look for.

    Raises:
        InvariantViolationError: With
            ``mayhem.domain.secrets.REFUSAL_SECRET_FIELD_PERSISTED`` when a field
            is graded ``secret``, or :data:`REFUSAL_SECRET_BYTES_IN_ARTIFACT` when
            a resolved value is present in the serialised document.
    """
    EVIDENCE_FIELD_CLASSIFICATIONS.require_persistable(document, path=artifact)
    guards = active_guards()
    if not guards:
        return
    serialised = json.dumps(document, sort_keys=True, default=str)
    for guard in guards:
        guard.require_clean_bytes(serialised, artifact=artifact)


def require_envelope_boundary(envelope: EvidenceEnvelope, *, artifact: str = "evidence") -> None:
    """The envelope write gate: grade the fields, then scan the exact bytes.

    The bytes scanned are the ones that reach disk — pydantic's own JSON — not
    a re-serialisation of a dict, because a gate that scans a different rendering
    than the writer emits is a gate on the wrong artifact.

    Raises:
        InvariantViolationError: With
            ``mayhem.domain.secrets.REFUSAL_SECRET_FIELD_PERSISTED`` or
            :data:`REFUSAL_SECRET_BYTES_IN_ARTIFACT`.
    """
    require_persistable_envelope(envelope, artifact=artifact)
    require_clean_artifact(envelope.model_dump_json(), artifact=artifact)


def require_clean_log_line(line: str, *, event: str) -> None:
    """The log boundary: refuse a log line carrying a resolved value.

    Name-based redaction is not consulted here and must not be: ``redact`` fires
    on how a field is named, so it cannot see a value a caller interpolated into
    a message it composed. This gate is the one that can.

    Raises:
        InvariantViolationError: With :data:`REFUSAL_SECRET_BYTES_IN_ARTIFACT`.
    """
    require_clean_artifact(line, artifact=f"log:{event}")
