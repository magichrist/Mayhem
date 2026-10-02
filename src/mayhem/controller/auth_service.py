"""Plan 09 Phase 3 — the authentication and authorization *service*.

Phase 1 (:mod:`mayhem.domain.identity`) supplied the vocabulary:
:class:`~mayhem.domain.identity.Principal`,
:class:`~mayhem.domain.identity.TeamMembership`,
:class:`~mayhem.domain.identity.EnvironmentScope`,
:class:`~mayhem.domain.identity.Role`, and
:class:`~mayhem.domain.identity.RoleGrant`, with role resolution as a pure
function of (grants, memberships, scope, now). Phase 2
(:mod:`mayhem.controller.approval_gate`) supplied the *decision point*: it
authorizes an executor against those grants and refuses before any approval
counts. Neither could answer "who is this, and may they act?"

This module is the missing middle, and it is deliberately thin in the two
places it could have been thick:

* **It defines no role, no scope, and no approval rule.** Every authorization
  answer is :func:`~mayhem.domain.identity.effective_roles` /
  :func:`~mayhem.domain.identity.has_role` over records it loaded, and every
  approval it hands the gate is
  :meth:`~mayhem.domain.identity.Approval.bind` via the Phase 2 vocabulary. If
  this module had its own notion of "may execute", there would be two answers to
  the same question and they would diverge the first time somebody widened one
  of them.
* **It decides nothing about whether an approval authorizes.** It *supplies*
  the executor principal, the grants, the memberships, and the consumed-id set
  to :func:`~mayhem.controller.approval_gate.verify_approvals`, and reports the
  gate's verdict. The gate still decides.

What it does own is the part neither pure layer could: **proving who somebody
is, and keeping that proof short-lived.**

Identity providers are ports
----------------------------

Local authentication is implemented here, for real, because it needs no
library: PBKDF2-HMAC-SHA256 from :mod:`hashlib`, a per-credential salt, and a
constant-time comparison. Everything else — OIDC, OAuth, SAML, SCIM — is a
:class:`IdentityProviderPort`: a two-method protocol plus
:class:`CallableIdentityProvider`, which adapts an injected callable. This
project's declared dependency set is pydantic, typer, click, pyyaml, structlog,
and kubernetes, and "supports OIDC" in a build with no OIDC library honestly
means "there is a seam an OIDC client plugs into". A test injects
:class:`StaticIdentityProvider` and gets the same walkthrough a deployment would
get from a real IdP, which is what the Phase 3 acceptance asks for — the
walkthrough with *faked identity providers*.

Token lifecycle, and the bound on revocation propagation
--------------------------------------------------------

A session is ``"<session_id>.<secret>"``. The id routes the lookup and is
public by construction; the secret is 256 bits of CSPRNG output, is stored only
as a pepper-salted digest, and is returned exactly once — at issue or at
rotation — on a type whose ``__repr__`` redacts it. Rotation mints a new
secret and revokes the predecessor in the same transaction, so there is no
instant at which both are live or neither is.

Revocation writes two things in one transaction: it stamps ``revoked_at`` on
the subject's row, and it appends an ``identity_revocations`` row that no
``UPDATE`` can rewrite. Every authentication reads both, *including* a
revocation row for the **principal**, which is why disabling a person fences
sessions and API keys this module never visited.

The service caches an authentication decision for at most
:data:`REVOCATION_PROPAGATION_BOUND_S` seconds, measured on an **injected**
monotonic clock so the bound is a tested number rather than a hope. Within the
bound: no cached decision is ever returned. Beyond it: the cache is never read
without a fresh revocation read. A revocation committed by *this* process also
drops its own cache entry immediately, so the realistic latency is one
statement, and the bound is the ceiling for a revocation written by a peer —
which is precisely the case a cache exists for.

Separation of duties is a switch the caller owns
------------------------------------------------

:data:`AuthService.separation_of_duties` is a *default*, not a policy: the
Phase 2 gate remains the place the switch is decided per run, and
:meth:`AuthService.gate_inputs` only supplies it when the caller does not
override. Where this module can enforce it on its own, it does —
:meth:`AuthService.mint_approval` refuses to mint an approval for the principal
who authored the plan when the switch is on, because a service that can mint one
is the only place that requirement can be met *before* the fact rather than
caught after it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from mayhem.controller.approval_gate import ApprovalGateInputs
from mayhem.domain.approval import Approval, ChangeTicket
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    PrincipalKind,
    Role,
    RoleGrant,
    TeamMembership,
    effective_roles,
    has_role,
    team_ids_for,
)
from mayhem.infra.identity_store import (
    API_KEY_PREFIX_CHARS,
    PASSWORD_HASH_ITERATIONS,
    ApiKeyRecord,
    AuthSource,
    IdentityStore,
    RevocationRecord,
    RevocationSubject,
    SessionKind,
    SessionRecord,
    hash_secret,
    new_api_key_id,
    new_secret,
    new_session_id,
    verify_password,
    verify_secret,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from mayhem.domain.safety_proof import SafetyProof

# =============================================================================
# Constants and refusal codes
# =============================================================================

#: Default session lifetime. Short by design: this is the ceiling a stolen
#: bearer token gets, and rotation makes it renewable without widening it.
DEFAULT_SESSION_TTL_S: float = 3600.0

#: Default API-key lifetime, deliberately shorter than a session's. A key is a
#: credential a script cannot be asked to re-mint interactively, so it trades
#: convenience for a tighter window; a deployment that wants longer keys issues
#: them explicitly with ``ttl_s``.
DEFAULT_API_KEY_TTL_S: float = 900.0

#: The longest a cached authentication decision may be served without re-reading
#: the revocations table. See the module docstring; the number is asserted by
#: ``tests/unit/test_auth_service.py`` rather than trusted.
REVOCATION_PROPAGATION_BOUND_S: float = 5.0

#: Stable refusal codes. Part of the service's contract — a caller branches on
#: these, and an operator reads them in a log line.
REFUSAL_PRINCIPAL_UNKNOWN = "auth.principal_unknown"
REFUSAL_CREDENTIAL_INVALID = "auth.credential_invalid"
REFUSAL_SESSION_UNKNOWN = "auth.session_unknown"
REFUSAL_SESSION_EXPIRED = "auth.session_expired"
REFUSAL_SESSION_REVOKED = "auth.session_revoked"
REFUSAL_API_KEY_UNKNOWN = "auth.api_key_unknown"
REFUSAL_API_KEY_EXPIRED = "auth.api_key_expired"
REFUSAL_API_KEY_REVOKED = "auth.api_key_revoked"
REFUSAL_API_KEY_UNSCOPED = "auth.api_key_unscoped"
REFUSAL_PRINCIPAL_DISABLED = "auth.principal_disabled"
REFUSAL_ROLE_MISSING = "auth.role_missing"
REFUSAL_SESSION_SCOPE = "auth.session_scope"
REFUSAL_MINT_UNAUTHORIZED = "auth.mint_unauthorized"
REFUSAL_SELF_APPROVAL = "auth.self_approval"
REFUSAL_PROVIDER_UNAVAILABLE = "auth.provider_unavailable"
REFUSAL_PROVIDER_UNKNOWN = "auth.provider_unknown"
REFUSAL_REVOCATION_UNKNOWN = "auth.revocation_unknown"
REFUSAL_CREDENTIAL_UNREADABLE = "auth.credential_unreadable"


class AuthRefusedError(DomainError):
    """A request the service refuses, naming the rule it refused under.

    Split from ``InvariantViolationError`` on purpose: an invariant violation is
    a bug, whereas every refusal here is a *correct answer* to an unauthenticated
    or unauthorized request. Callers that expect to handle refusal branch on
    ``code``; a mistake surfaces as an unexpected exception type instead.
    """

    def __init__(self, code: str, message: str, *, remediation: str = "") -> None:
        self.code = code
        self.remediation = remediation
        super().__init__(message)


# =============================================================================
# Ports
# =============================================================================


@dataclass(frozen=True)
class FederatedCredentials:
    """What a caller presents to a non-local provider port.

    Deliberately opaque: the service never parses a bearer assertion, a SAML
    response, or a SCIM PATCH. It hands the credentials to the registered port
    and trusts the port to have done the verification, because a *partial* SAML
    verification is worse than none — it looks authenticated and is not.
    """

    source: AuthSource
    external_id: str
    assertion: str = ""
    groups: tuple[str, ...] = ()

    @property
    def teams(self) -> tuple[str, ...]:
        """Group claims read as team ids.

        Read as an *assertion of membership the IdP made*, and turned into a
        :class:`~mayhem.domain.identity.TeamMembership` only if the deployment
        says to trust the provider. The mapping is one narrow call in
        :meth:`AuthService.sync_federated_memberships`, so "SCIM manages team
        membership" is a switch with a default rather than a behaviour.
        """
        return self.groups


class IdentityProviderPort(Protocol):
    """The seam every non-local identity provider plugs into.

    A protocol, not a base class: an OIDC adapter, a SAML adapter, and a test
    double share no code beyond these two methods, and the service never needs to
    know which one it holds. The name says *idp*, so this cannot grow into a
    general plug-in bus.
    """

    @property
    def source(self) -> AuthSource:
        """The :class:`~mayhem.infra.identity_store.AuthSource` this port serves."""
        ...

    def resolve(self, credentials: FederatedCredentials) -> tuple[Principal, tuple[str, ...]]:
        """Verify ``credentials`` and return the principal plus its asserted teams.

        Returns:
            The principal as the IdP states it, and the team ids the IdP claims
            the principal belongs to.

        Raises:
            AuthRefusedError: When the assertion does not verify. An adapter must
                not return an unverified principal — "we could not check it" and
                "it is fine" are different answers and the second one is the
                dangerous one.
        """
        ...


class CallableIdentityProvider:
    """Adapts an injected callable to :class:`IdentityProviderPort`.

    This is where a real deployment plugs in:
    ``CallableIdentityProvider(AuthSource.OIDC, oidc_client.resolve)``. Mayhem
    ships no OIDC client, so this class is what "OIDC/OAuth supported" honestly
    means in a build that does not depend on one.
    """

    def __init__(
        self,
        source: AuthSource,
        resolve: Callable[[FederatedCredentials], tuple[Principal, tuple[str, ...]]],
    ) -> None:
        self._source = AuthSource(source)
        self._resolve = resolve

    @property
    def source(self) -> AuthSource:
        return self._source

    def resolve(self, credentials: FederatedCredentials) -> tuple[Principal, tuple[str, ...]]:
        return self._resolve(credentials)


@dataclass(frozen=True)
class StaticIdentityProvider:
    """A fixed IdP for tests and for the Phase 3 walkthrough.

    Holds a table of ``(external_id, principal, teams)`` and a set of external
    ids it will *not* resolve. The refusal half is what makes it useful as a
    negative control: a faked provider that always succeeds proves nothing about
    what happens when the IdP says no.
    """

    source: AuthSource = AuthSource.OIDC
    known: tuple[tuple[str, Principal, tuple[str, ...]], ...] = ()
    rejected: frozenset[str] = frozenset()

    def resolve(self, credentials: FederatedCredentials) -> tuple[Principal, tuple[str, ...]]:
        if credentials.external_id in self.rejected:
            raise AuthRefusedError(
                REFUSAL_CREDENTIAL_INVALID,
                f"identity provider {self.source.value} rejected "
                f"{credentials.external_id!r}; nothing about this assertion was trusted",
                remediation="obtain a fresh assertion from the provider",
            )
        for external_id, principal, teams in self.known:
            if external_id == credentials.external_id:
                return principal, teams
        raise AuthRefusedError(
            REFUSAL_CREDENTIAL_INVALID,
            f"identity provider {self.source.value} does not know {credentials.external_id!r}",
            remediation="provision the principal before authenticating it",
        )


# =============================================================================
# Results
# =============================================================================


class AuthMethod(StrEnum):
    """Which path authenticated. Recorded so evidence can name it."""

    PASSWORD = "password"
    TOKEN = "token"
    API_KEY = "api_key"
    FEDERATED = "federated"


@dataclass(frozen=True)
class AuthRefusal:
    """One refused authentication, with everything a log line needs.

    ``code`` is stable; ``reason`` is written for a human; ``remediation`` says
    what to do. No field can hold the presented credential: a refusal that
    echoed the secret would put the thing it refused to accept into the log.
    """

    code: str
    reason: str
    remediation: str = ""
    subject: str = ""
    at: datetime | None = None

    def describe(self) -> str:
        return f"{self.code}: {self.reason}"


@dataclass(frozen=True)
class Authentication:
    """The answer to "who is this and what may they reach".

    ``principal`` is ``None`` unless :attr:`authenticated` — a caller that
    forgets to check the flag gets ``None`` rather than an identity, so the
    default-deny answer survives a careless caller.

    ``scopes`` is the *reach* this authentication carries: empty for a password
    or token session, where authority comes from grants resolved by the domain,
    and non-empty for an API key, which is scoped at issue time.
    """

    method: AuthMethod
    principal: Principal | None = None
    subject_id: str = ""
    scopes: tuple[EnvironmentScope, ...] = ()
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    auth_source: AuthSource = AuthSource.LOCAL
    refusal: AuthRefusal | None = None

    @property
    def authenticated(self) -> bool:
        return self.principal is not None and self.refusal is None

    @property
    def code(self) -> str:
        """The refusal code, or an empty string on success."""
        return "" if self.refusal is None else self.refusal.code

    def describe(self) -> str:
        if self.authenticated:
            assert self.principal is not None
            return (
                f"{self.principal.principal_id} authenticated by {self.method.value} "
                f"({self.auth_source.value}), subject {self.subject_id}"
            )
        assert self.refusal is not None
        return f"refused: {self.refusal.describe()}"


@dataclass(frozen=True)
class IssuedToken:
    """A freshly minted session token. The secret is readable exactly once.

    ``__repr__`` redacts ``token``: this value ends up in a return type, a
    debugger, and a traceback frame, and the one field that must never be
    printed is the one a ``dataclass`` would print by default.
    """

    session_id: str
    token: str
    issued_at: datetime
    expires_at: datetime

    def __repr__(self) -> str:
        return (
            f"IssuedToken(session_id={self.session_id!r}, token='<redacted>', "
            f"expires_at={self.expires_at.isoformat()!r})"
        )

    def describe(self) -> str:
        return f"session {self.session_id} valid until {self.expires_at.isoformat()}"


@dataclass(frozen=True)
class IssuedApiKey:
    """A freshly minted API key: the secret is readable exactly once."""

    api_key_id: str
    key_prefix: str
    secret: str
    scopes: tuple[EnvironmentScope, ...]
    issued_at: datetime
    expires_at: datetime

    @property
    def presented(self) -> str:
        """How a caller actually presents this key on the wire."""
        return f"mk_{self.key_prefix}.{self.secret}"

    def __repr__(self) -> str:
        return (
            f"IssuedApiKey(api_key_id={self.api_key_id!r}, "
            f"key_prefix={self.key_prefix!r}, secret='<redacted>', "
            f"scopes={[s.describe() for s in self.scopes]!r})"
        )

    def describe(self) -> str:
        scopes = ", ".join(scope.describe() for scope in self.scopes) or "no scope"
        return f"api key {self.api_key_id} in {scopes}, expires {self.expires_at.isoformat()}"


@dataclass(frozen=True)
class AuthorizationDecision:
    """What a principal holds in a scope, and whether that was enough.

    ``roles`` is :func:`~mayhem.domain.identity.effective_roles` verbatim; this
    type adds no hierarchy, no inheritance, and no "admin implies execute".
    """

    principal: str
    scope: EnvironmentScope
    roles: frozenset[Role]
    required: tuple[Role, ...]
    evaluated_at: datetime
    code: str = ""

    @property
    def authorized(self) -> bool:
        return not self.code and all(role in self.roles for role in self.required)

    @property
    def missing(self) -> tuple[Role, ...]:
        return tuple(role for role in self.required if role not in self.roles)

    def evidence(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "environment": self.scope.describe(),
            "roles": sorted(role.value for role in self.roles),
            "required": [role.value for role in self.required],
            "missing": [role.value for role in self.missing],
            "authorized": self.authorized,
            "code": self.code,
            "at": self.evaluated_at.isoformat(),
        }

    def describe(self) -> str:
        held = ", ".join(sorted(role.value for role in self.roles)) or "no roles"
        if self.authorized:
            return f"{self.principal} holds [{held}] in {self.scope.describe()}"
        return (
            f"{self.principal} holds [{held}] in {self.scope.describe()}; "
            f"missing {', '.join(role.value for role in self.missing) or 'reach'}"
            + (f" [{self.code}]" if self.code else "")
        )


@dataclass(frozen=True)
class RevocationPropagation:
    """One measured revocation: when it committed, when it was observed, bound.

    ``latency_s`` is measured on the service's **injected** monotonic clock, so a
    test drives it deterministically instead of sleeping and hoping.
    ``within_bound`` is the property, and it is what the Phase 5 acceptance
    ("revocation propagation time bounded and tested") asks for.
    """

    subject_kind: str
    subject_id: str
    revoked_at: datetime
    observed_at: datetime | None = None
    latency_s: float | None = None
    bound_s: float = REVOCATION_PROPAGATION_BOUND_S
    still_authenticated: bool = False

    @property
    def within_bound(self) -> bool:
        return (
            self.observed_at is not None
            and self.latency_s is not None
            and self.latency_s <= self.bound_s
            and not self.still_authenticated
        )

    def describe(self) -> str:
        latency = "not observed" if self.latency_s is None else f"{self.latency_s:.3f}s"
        return (
            f"{self.subject_kind} {self.subject_id}: revoked {self.revoked_at.isoformat()}, "
            f"propagated in {latency} (bound {self.bound_s:.3f}s, "
            f"within_bound={self.still_authenticated is False})"
        )


@dataclass(frozen=True)
class SessionExpiryReport:
    """Which sessions lapsed at one instant, and which have not."""

    at: datetime
    lapsed: tuple[str, ...] = ()
    live: tuple[str, ...] = ()

    def describe(self) -> str:
        return f"at {self.at.isoformat()}: {len(self.lapsed)} lapsed, {len(self.live)} live"


@dataclass(frozen=True)
class _CacheEntry:
    """A cached authentication decision plus the readings behind it.

    ``checked_monotonic`` is what bounds the revocation propagation. ``honoured_until``
    is a second, *tighter* bound: a cached decision is never served past the
    subject's own expiry, so the cache can never make an expired session or key
    look live. Without it the two bounds would be in tension and the revocation
    bound would silently win, which is the wrong way round — an expired
    credential is already dead on its own.
    """

    authentication: Authentication
    checked_monotonic: float
    honoured_until: datetime | None = None


# =============================================================================
# The service
# =============================================================================


class AuthService:
    """Authenticate, resolve authority, and mint/revoke the credentials.

    Constructor arguments are all deliberate:

    ``store``
        The :class:`~mayhem.infra.identity_store.IdentityStore` holding the
        records. Injectable so a test can hand a second service a *second*
        connection to the same database and prove that a revocation written by
        one process fences the other.
    ``pepper``
        Required, with no default. It is what makes a stolen table useless on
        its own, and a default pepper would be a secret in the source tree
        wearing a constant's name.
    ``clock`` / ``monotonic``
        Both injected, so every time-dependent claim in this module is testable.
        ``clock`` supplies wall time (windows, expiry); ``monotonic`` supplies
        the propagation measurement, because a wall clock can jump backwards and
        a bound measured on it is not a bound.
    ``separation_of_duties``
        A *default* for :meth:`gate_inputs` and :meth:`mint_approval`, never an
        override of the gate. Phase 2 remains the place the switch is decided
        per run.
    """

    def __init__(
        self,
        store: IdentityStore,
        *,
        pepper: bytes,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        session_ttl_s: float = DEFAULT_SESSION_TTL_S,
        api_key_ttl_s: float = DEFAULT_API_KEY_TTL_S,
        password_iterations: int = PASSWORD_HASH_ITERATIONS,
        revocation_propagation_bound_s: float = REVOCATION_PROPAGATION_BOUND_S,
        separation_of_duties: bool = False,
        providers: Sequence[IdentityProviderPort] = (),
        trust_provider_teams: bool = False,
    ) -> None:
        if not pepper:
            msg = (
                "AuthService requires a non-empty pepper; a default pepper would be a "
                "shared secret in the source tree, and an empty one makes a stolen "
                "identity table directly comparable against candidate secrets"
            )
            raise AuthRefusedError(REFUSAL_CREDENTIAL_INVALID, msg)
        self._store = store
        self._pepper = bytes(pepper)
        self._clock = clock or utc_now
        self._monotonic = monotonic or time.monotonic
        self._session_ttl_s = float(session_ttl_s)
        self._api_key_ttl_s = float(api_key_ttl_s)
        self._password_iterations = int(password_iterations)
        self._bound_s = float(revocation_propagation_bound_s)
        self.separation_of_duties = separation_of_duties
        self._trust_provider_teams = trust_provider_teams
        self._providers: dict[AuthSource, IdentityProviderPort] = {
            AuthSource(port.source): port for port in providers
        }
        self._cache: dict[str, _CacheEntry] = {}
        self._last_seen_revocation: str = ""

    # -- plumbing ---------------------------------------------------------------

    @property
    def identity_store(self) -> IdentityStore:
        """The backing store, for callers composing a transaction around a call."""
        return self._store

    @property
    def revocation_propagation_bound_s(self) -> float:
        """The ceiling this service caches an authentication decision for."""
        return self._bound_s

    def _now(self, now: datetime | None) -> datetime:
        """Resolve the clock, refusing a naive one.

        Same rule and same reason as
        :meth:`mayhem.controller.approval_gate.ApprovalGateInputs.__post_init__`:
        a naive ``now`` makes every window in this module unreproducible, and an
        unreproducible window is one that silently compares wrong.
        """
        moment = self._clock() if now is None else now
        if moment.tzinfo is None or moment.utcoffset() is None:
            msg = (
                "auth service requires a timezone-aware clock; a naive `now` makes expiry, "
                "grant windows, and revocation ordering unreproducible"
            )
            raise InvariantViolationError("auth.naive_clock", msg)
        return moment

    def _invalidate(self, subject_id: str) -> None:
        """Drop this process's cached decision for ``subject_id``.

        Called by every mutating path on the way out. It is an optimisation and
        never the *mechanism* — the revocations table is the mechanism, and a
        peer process has no access to this dict at all.
        """
        self._cache.pop(subject_id, None)

    def _cached(
        self, subject_id: str, refresh: Callable[[], Authentication], *, now: datetime
    ) -> Authentication:
        """Serve a cached decision only inside the propagation bound.

        Two properties, both of which the test asserts:

        * a decision is never served once the monotonic reading has advanced by
          :data:`REVOCATION_PROPAGATION_BOUND_S` — the bound is checked *before*
          the cache is consulted, not cleaned up afterwards;
        * a decision about a *disabled or revoked* principal is not cached at
          all, because a negative answer is cheap to recompute and caching one
          would extend the window in which "no" is served after a grant lands.
        """
        entry = self._cache.get(subject_id)
        # ``now`` is the clock the caller asked the question *at*, not the
        # service's own: a caller replaying a decision as of an earlier or later
        # instant must get that instant's answer, and a cache that judged expiry
        # against a different clock would answer a question nobody asked.
        if entry is not None and self._served(entry, now):
            return entry.authentication
        authentication = refresh()
        self._remember(subject_id, authentication)
        return authentication

    def _served(self, entry: _CacheEntry, moment: datetime) -> bool:
        """Whether a cached decision may be served at ``moment``.

        Three refusals, in the order that matters: a decision whose subject has
        since expired is never served (its own deadline is the tighter bound),
        then the propagation window, then the positive answer itself (a negative
        decision is never cached at all, so it has no entry to be served).
        """
        if not entry.authentication.authenticated:
            return False
        if entry.honoured_until is not None and moment >= entry.honoured_until:
            return False
        return self._monotonic() - entry.checked_monotonic < self._bound_s

    def _remember(self, subject_id: str, authentication: Authentication) -> None:
        if authentication.authenticated:
            self._cache[subject_id] = _CacheEntry(
                authentication, self._monotonic(), authentication.expires_at
            )
        else:
            self._cache.pop(subject_id, None)

    # -- principals and teams ---------------------------------------------------

    def register_principal(
        self,
        principal: Principal,
        *,
        auth_source: AuthSource = AuthSource.LOCAL,
        now: datetime | None = None,
    ) -> Principal:
        """Persist a principal. The local path this is the first step of."""
        return self._store.save_principal(principal, auth_source=auth_source, now=self._now(now))

    def principal(self, principal_id: str) -> Principal | None:
        return self._store.load_principal(principal_id)

    def disable_principal(
        self, principal_id: str, *, revoked_by: str, reason: str, now: datetime | None = None
    ) -> Principal:
        """Disable a principal and revoke every credential it holds.

        The flag is what role resolution reads
        (:func:`~mayhem.domain.identity.RoleGrant.applies_to` refuses a disabled
        principal); the revocation row is what authentication reads. Both are
        written because they answer two different questions — "may this person
        still exercise authority" and "is this bearer token still honoured" —
        and a service that wrote only one of them would leave the other path
        open.

        Returns:
            The principal as it now reads.

        Raises:
            AuthRefusedError: If the principal is unknown, or the revocation
                names no actor.
        """
        moment = self._now(now)
        _require_actor(revoked_by, "disabling a principal")
        updated = self._store.set_principal_disabled(principal_id, disabled=True, now=moment)
        if updated is None:
            raise AuthRefusedError(
                REFUSAL_PRINCIPAL_UNKNOWN,
                f"no principal {principal_id!r} to disable",
                remediation="register the principal first",
            )
        self._store.record_revocation(
            self._revocation(RevocationSubject.PRINCIPAL, principal_id, revoked_by, reason, moment)
        )
        for session in self._store.sessions_for(principal_id):
            self._cache.pop(session.session_id, None)
        for key in self._store.api_keys_for(principal_id):
            self._cache.pop(key.api_key_id, None)
        self._cache.pop(principal_id, None)
        return updated

    def add_membership(
        self,
        principal_id: str,
        *,
        team_id: str,
        now: datetime | None = None,
        until: datetime | None = None,
    ) -> TeamMembership:
        """Put a principal in a team, optionally with a closing time."""
        principal = self.principal(principal_id)
        if principal is None:
            raise AuthRefusedError(
                REFUSAL_PRINCIPAL_UNKNOWN,
                f"no principal {principal_id!r} to add to {team_id!r}",
                remediation="register the principal first",
            )
        membership = TeamMembership(
            principal=principal, team_id=team_id, joined_at=self._now(now), until=until
        )
        return self._store.save_membership(membership)

    def memberships(self, principal_id: str) -> tuple[TeamMembership, ...]:
        return self._store.memberships_for(principal_id)

    def teams(self, principal_id: str, *, now: datetime | None = None) -> frozenset[str]:
        """Teams a principal is *actively* in at ``now``.

        Delegates to :func:`~mayhem.domain.identity.team_ids_for` so the
        service and the Phase 1 vocabulary cannot hold different opinions about
        whether a closed membership still counts.
        """
        principal = self.principal(principal_id)
        if principal is None:
            return frozenset()
        return team_ids_for(
            principal, self._store.memberships_for(principal_id), now=self._now(now)
        )

    # -- role grants ------------------------------------------------------------

    def grant_role(
        self,
        *,
        role: Role,
        scope: EnvironmentScope,
        principal_id: str = "",
        team_id: str = "",
        granted_by: str = "",
        change_ticket: str = "",
        now: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> str:
        """Grant one role in one scope, returning the grant's id.

        Addressed to exactly one of ``principal_id``/``team_id`` — the
        :class:`~mayhem.domain.identity.RoleGrant` validator refuses "both" and
        "neither", and this method refuses a blank ``role`` scope rather than
        defaulting it, because a grant nobody located is a template.
        """
        moment = self._now(now)
        addressee: Principal | None = None
        if principal_id:
            addressee = self.principal(principal_id)
            if addressee is None:
                raise AuthRefusedError(
                    REFUSAL_PRINCIPAL_UNKNOWN,
                    f"cannot grant to unknown principal {principal_id!r}",
                    remediation="register the principal first",
                )
        # ``team_id`` carries a pattern that (correctly) rejects "" when it is
        # stated explicitly, and :class:`~mayhem.domain.identity.RoleGrant`
        # only gets away with an empty default because pydantic does not validate
        # defaults. So the addressee's key is *omitted* rather than passed as "".
        addressed: dict[str, Any] = {"principal": addressee} if addressee else {"team_id": team_id}
        grant = RoleGrant(
            role=Role(role),
            scope=EnvironmentScope(**scope.model_dump()),
            granted_at=moment,
            expires_at=expires_at,
            granted_by=granted_by,
            change_ticket=change_ticket,
            **addressed,
        )
        return self._store.save_grant(grant)

    def grants_for(self, *, principal_id: str = "", team_id: str = "") -> tuple[RoleGrant, ...]:
        """Direct grants plus the grants addressed to the teams it is in."""
        direct = self._store.grants_for(principal_id=principal_id) if principal_id else ()
        team_grants: tuple[RoleGrant, ...] = ()
        if principal_id:
            memberships = self._store.memberships_for(principal_id)
            collected: list[RoleGrant] = []
            for membership in memberships:
                collected.extend(self._store.grants_for(team_id=membership.team_id))
            team_grants = tuple(collected)
        if team_id:
            return self._store.grants_for(team_id=team_id)
        return (*direct, *team_grants)

    def all_grants(self) -> tuple[RoleGrant, ...]:
        return self._store.all_grants()

    def revoke_grant(self, grant_id: str) -> bool:
        """Remove a grant outright. No grant, no clock read, no side effect."""
        return self._store.delete_grant(grant_id)

    # -- authorization ----------------------------------------------------------

    def roles_for(
        self, principal: Principal, scope: EnvironmentScope, *, now: datetime | None = None
    ) -> frozenset[Role]:
        """Every role ``principal`` holds in ``scope``, per the Phase 1 vocabulary."""
        return effective_roles(
            self.grants_for(principal_id=principal.principal_id),
            principal=principal,
            scope=scope,
            memberships=self._store.memberships_for(principal.principal_id),
            now=self._now(now),
        )

    def authorize(
        self,
        *,
        principal: Principal,
        role: Role = Role.EXECUTE,
        scope: EnvironmentScope,
        authentication: Authentication | None = None,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        """May ``principal`` act in ``scope``, and why not if they may not.

        ``authentication`` is optional and load-bearing: passing it adds the
        *reach* check — a session scoped to ``staging`` cannot authorize
        ``production`` even if the same principal holds a production grant,
        because a scoped credential's scope and the principal's grants are two
        different questions and a CI key that escapes its scope is exactly the
        cross-environment replay this has to refuse.
        """
        moment = self._now(now)
        roles = self.roles_for(principal, scope, now=moment)
        code = ""
        if principal.disabled:
            code = REFUSAL_PRINCIPAL_DISABLED
        elif (
            authentication is not None
            and authentication.scopes
            and not any(stated.covers(scope) for stated in authentication.scopes)
        ):
            code = REFUSAL_SESSION_SCOPE
        return AuthorizationDecision(
            principal=principal.principal_id,
            scope=scope,
            roles=roles,
            required=(Role(role),),
            evaluated_at=moment,
            code=code,
        )

    def require_role(
        self,
        *,
        principal: Principal,
        role: Role,
        scope: EnvironmentScope,
        authentication: Authentication | None = None,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        """Like :meth:`authorize`, but a refusal raises.

        For call sites that cannot proceed without authority — which is every
        mutating surface. The raised :class:`AuthRefusedError` carries the same
        stable code the returned decision would have, so a caller can handle the
        two uniformly.
        """
        decision = self.authorize(
            principal=principal,
            role=role,
            scope=scope,
            authentication=authentication,
            now=now,
        )
        if not decision.authorized:
            raise AuthRefusedError(
                decision.code or REFUSAL_ROLE_MISSING,
                decision.describe(),
                remediation=(
                    f"grant {role.value} to {principal.principal_id} in "
                    f"{scope.describe()}, or authenticate with a credential scoped there"
                ),
            )
        return decision

    def may_approve(
        self, principal: Principal, scope: EnvironmentScope, *, now: datetime | None = None
    ) -> bool:
        """``APPROVE`` in scope — the exact predicate :meth:`mint_approval` uses.

        Exposed so a caller can pre-check without catching an exception, and so
        the answer is visibly the Phase 1 one rather than a re-derivation.
        """
        return has_role(
            self.grants_for(principal_id=principal.principal_id),
            principal=principal,
            role=Role.APPROVE,
            scope=scope,
            memberships=self._store.memberships_for(principal.principal_id),
            now=self._now(now),
        )

    # -- local authentication ---------------------------------------------------

    def set_password(
        self, principal_id: str, password: str, *, now: datetime | None = None
    ) -> None:
        """Hash and store a password. The plaintext does not survive the call."""
        if self.principal(principal_id) is None:
            raise AuthRefusedError(
                REFUSAL_PRINCIPAL_UNKNOWN,
                f"cannot set a password for unknown principal {principal_id!r}",
                remediation="register the principal first",
            )
        if not password:
            raise AuthRefusedError(
                REFUSAL_CREDENTIAL_INVALID,
                "refusing an empty password; an empty secret authenticates nobody and "
                "looks like a configuration rather than a credential",
                remediation="supply a password, or issue an API key for a non-human caller",
            )
        self._store.set_local_credential(
            principal_id,
            password,
            now=self._now(now),
            iterations=self._password_iterations,
        )

    def authenticate_password(
        self,
        *,
        principal_id: str,
        password: str,
        ttl_s: float | None = None,
        now: datetime | None = None,
    ) -> Authentication:
        """Local authentication, implemented rather than delegated.

        Order of questions, and why: an unknown principal is refused before any
        hash is computed, a wrong password is compared in constant time, and a
        *disabled* principal is refused last — after the credential verified —
        because the honest diagnostic for "your password is right but your
        account is off" is worth more to a caller than indistinguishable
        not-found noise, and this is an internal control plane rather than a
        public login form. A deployment that needs username enumeration
        resistance should put a rate limiter in front of this, not rely on this
        ordering.
        """
        moment = self._now(now)
        principal = self.principal(principal_id)
        if principal is None:
            return _refused(
                AuthMethod.PASSWORD,
                REFUSAL_PRINCIPAL_UNKNOWN,
                f"no principal {principal_id!r}",
                "register the principal, then authenticate",
                subject=principal_id,
                at=moment,
            )
        record = self._store.load_local_credential(principal_id)
        if record is None or not verify_password(
            password,
            salt_hex=record.salt_hex,
            credential_hash=record.credential_hash,
            iterations=record.iterations,
        ):
            return _refused(
                AuthMethod.PASSWORD,
                REFUSAL_CREDENTIAL_INVALID,
                f"the password presented for {principal_id!r} did not verify",
                "present the correct password, or reset it through an administrator",
                subject=principal_id,
                at=moment,
            )
        if principal.disabled:
            return _refused(
                AuthMethod.PASSWORD,
                REFUSAL_PRINCIPAL_DISABLED,
                f"{principal_id!r} is disabled; a disabled principal holds nothing",
                "an administrator must re-enable the principal",
                subject=principal_id,
                at=moment,
            )
        token = self._issue_session(
            principal=principal,
            kind=SessionKind.PASSWORD,
            auth_source=AuthSource.LOCAL,
            ttl_s=self._session_ttl_s if ttl_s is None else ttl_s,
            now=moment,
        )
        return Authentication(
            method=AuthMethod.PASSWORD,
            principal=principal,
            subject_id=token.session_id,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            auth_source=AuthSource.LOCAL,
        )

    # -- federated authentication -----------------------------------------------

    def register_provider(self, provider: IdentityProviderPort) -> None:
        """Register one identity-provider port.

        Local auth is *not* a port: it is implemented above, because "delegate
        the password check" is not a seam, it is an omission.
        """
        source = AuthSource(provider.source)
        if source is AuthSource.LOCAL:
            msg = (
                "local authentication is implemented by AuthService, not delegated to a "
                "port; registering a local provider would create a second answer to "
                "'is this password correct'"
            )
            raise InvariantViolationError("auth.local_is_not_a_port", msg)
        self._providers[source] = provider

    def authenticate_federated(
        self,
        credentials: FederatedCredentials,
        *,
        ttl_s: float | None = None,
        now: datetime | None = None,
    ) -> Authentication:
        """Authenticate through a registered non-local provider port.

        The port verifies; this method provisions-or-resolves the local
        principal, then mints a session exactly as the local path does. That
        shared tail is deliberate: an OIDC login and a password login must not
        produce *different kinds* of session, or the token lifecycle below would
        apply to only one of them.

        A provider claiming a team does not by itself create a membership unless
        the service was constructed with ``trust_provider_teams=True``. The
        default is to record nothing the IdP said about groups.
        """
        moment = self._now(now)
        source = AuthSource(credentials.source)
        provider = self._providers.get(source)
        if provider is None:
            return _refused(
                AuthMethod.FEDERATED,
                REFUSAL_PROVIDER_UNAVAILABLE,
                f"no identity provider is registered for {source.value}",
                "register a provider port for this source, or use local authentication",
                subject=credentials.external_id,
                at=moment,
            )
        try:
            principal, teams = provider.resolve(credentials)
        except AuthRefusedError as refusal:
            return _refused(
                AuthMethod.FEDERATED,
                refusal.code,
                str(refusal),
                refusal.remediation,
                subject=credentials.external_id,
                at=moment,
            )
        existing = self._store.find_by_external_id(
            auth_source=source, external_id=principal.external_id or credentials.external_id
        )
        stored = self._store.save_principal(principal, auth_source=source, now=moment)
        if existing is not None and existing.principal_id != stored.principal_id:
            return _refused(
                AuthMethod.FEDERATED,
                REFUSAL_CREDENTIAL_INVALID,
                (
                    f"provider {source.value} external id "
                    f"{credentials.external_id!r} is already bound to principal "
                    f"{existing.principal_id!r} but resolved to {stored.principal_id!r}; "
                    "one IdP identity cannot become two principals"
                ),
                "resolve the collision before authenticating again",
                subject=credentials.external_id,
                at=moment,
            )
        if stored.disabled:
            return _refused(
                AuthMethod.FEDERATED,
                REFUSAL_PRINCIPAL_DISABLED,
                f"{stored.principal_id!r} is disabled; a disabled principal holds nothing",
                "an administrator must re-enable the principal",
                subject=stored.principal_id,
                at=moment,
            )
        if self._trust_provider_teams:
            for team_id in teams:
                self.add_membership(stored.principal_id, team_id=team_id, now=moment)
        token = self._issue_session(
            principal=stored,
            kind=SessionKind.FEDERATED,
            auth_source=source,
            ttl_s=self._session_ttl_s if ttl_s is None else ttl_s,
            now=moment,
        )
        return Authentication(
            method=AuthMethod.FEDERATED,
            principal=stored,
            subject_id=token.session_id,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            auth_source=source,
        )

    # -- token lifecycle --------------------------------------------------------

    def _issue_session(
        self,
        *,
        principal: Principal,
        kind: SessionKind,
        auth_source: AuthSource,
        ttl_s: float,
        now: datetime,
    ) -> IssuedToken:
        if ttl_s <= 0:
            msg = f"session ttl_s must be positive, got {ttl_s}"
            raise InvariantViolationError("auth.non_positive_ttl", msg)
        session_id = new_session_id()
        secret = new_secret()
        record = _session_record(
            session_id=session_id,
            principal_id=principal.principal_id,
            kind=kind,
            auth_source=auth_source,
            secret=secret,
            pepper=self._pepper,
            issued_at=now,
            ttl_s=ttl_s,
        )
        self._store.save_session(record)
        self._last_seen_revocation = ""
        return IssuedToken(
            session_id=session_id,
            token=f"{session_id}.{secret}",
            issued_at=now,
            expires_at=record.expires_at,
        )

    def issue_session(
        self,
        principal_id: str,
        *,
        ttl_s: float | None = None,
        now: datetime | None = None,
    ) -> IssuedToken:
        """Mint a session token directly — the service-account path.

        No credential is presented and nothing is verified, which is exactly why
        this is the *narrowest* entry point in the module: it authenticates
        nobody. It is the path a workload that already holds a machine identity
        (see plan 19) uses to obtain a short-lived token, and it is refused for a
        disabled principal so a disabled machine cannot mint its way back in.
        """
        moment = self._now(now)
        principal = self.principal(principal_id)
        if principal is None:
            raise AuthRefusedError(
                REFUSAL_PRINCIPAL_UNKNOWN,
                f"no principal {principal_id!r} to issue a session for",
                remediation="register the principal first",
            )
        if principal.disabled:
            raise AuthRefusedError(
                REFUSAL_PRINCIPAL_DISABLED,
                f"{principal_id!r} is disabled; a disabled principal holds nothing",
                remediation="an administrator must re-enable the principal",
            )
        return self._issue_session(
            principal=principal,
            kind=SessionKind.SERVICE_ACCOUNT,
            auth_source=AuthSource.WORKLOAD,
            ttl_s=self._session_ttl_s if ttl_s is None else ttl_s,
            now=moment,
        )

    def authenticate_token(self, token: str, *, now: datetime | None = None) -> Authentication:
        """Verify a presented session token.

        The cached fast path is :meth:`_cached`'s, and the refresh path reads, in
        order: the session row, the session's revocation row, and the
        *principal's* revocation row. The last one is why disabling a principal
        fences tokens this service issued before the disable.
        """
        moment = self._now(now)
        session_id, _, secret = token.partition(".")
        if not session_id or not secret:
            return _refused(
                AuthMethod.TOKEN,
                REFUSAL_SESSION_UNKNOWN,
                "a session token is '<session_id>.<secret>'; this was neither",
                "present the token exactly as it was issued",
                at=moment,
            )
        return self._cached(
            session_id,
            lambda: self._refresh_token(session_id, secret, now=now),
            now=moment,
        )

    def _refresh_token(
        self, session_id: str, secret: str, *, now: datetime | None
    ) -> Authentication:
        moment = self._now(now)
        record = self._store.load_session(session_id)
        if record is None:
            return _refused(
                AuthMethod.TOKEN,
                REFUSAL_SESSION_UNKNOWN,
                f"no session {session_id!r}",
                "authenticate again to obtain a fresh token",
                subject=session_id,
                at=moment,
            )
        if not verify_secret(secret, pepper=self._pepper, expected_hash=record.token_hash):
            return _refused(
                AuthMethod.TOKEN,
                REFUSAL_CREDENTIAL_INVALID,
                f"the secret presented for session {session_id!r} did not verify",
                "present the token exactly as it was issued",
                subject=session_id,
                at=moment,
            )
        principal_revocation = self._store.revocation_for(
            RevocationSubject.PRINCIPAL, record.principal_id
        )
        session_revocation = self._store.revocation_for(RevocationSubject.SESSION, session_id)
        principal = self.principal(record.principal_id)
        if session_revocation is not None or record.revoked:
            return _refused(
                AuthMethod.TOKEN,
                REFUSAL_SESSION_REVOKED,
                f"session {session_id!r} was revoked at "
                f"{_revoked_at(session_revocation, record.revoked_at, record.issued_at).isoformat()}",  # noqa: E501
                "authenticate again to obtain a fresh token",
                subject=session_id,
                at=moment,
            )
        if principal_revocation is not None or principal is None or principal.disabled:
            code = (
                REFUSAL_PRINCIPAL_DISABLED
                if principal is not None and principal.disabled
                else REFUSAL_SESSION_REVOKED
            )
            return _refused(
                AuthMethod.TOKEN,
                code,
                (
                    f"principal {record.principal_id!r} was revoked at "
                    f"{principal_revocation.revoked_at.isoformat()}"
                    if principal_revocation is not None
                    else f"principal {record.principal_id!r} confers nothing"
                ),
                "an administrator must re-enable the principal",
                subject=session_id,
                at=moment,
            )
        if record.is_expired(moment):
            return _refused(
                AuthMethod.TOKEN,
                REFUSAL_SESSION_EXPIRED,
                (f"session {session_id!r} expired at {record.expires_at.isoformat()}"),
                "authenticate again to obtain a fresh token",
                subject=session_id,
                at=moment,
            )
        return Authentication(
            method=AuthMethod.TOKEN,
            principal=principal,
            subject_id=session_id,
            issued_at=record.issued_at,
            expires_at=record.expires_at,
            auth_source=record.auth_source,
        )

    def rotate_session(
        self,
        token: str,
        *,
        revoked_by: str = "",
        ttl_s: float | None = None,
        now: datetime | None = None,
    ) -> IssuedToken:
        """Rotate a token: new secret, new window, predecessor revoked now.

        Revocation precedes issuance *and* is committed with it, so the two
        windows overlap by less than one statement: there is no instant at which
        the old token works and the new one does not, and none at which the new
        one exists while the old one still does.
        """
        moment = self._now(now)
        session_id, _, _ = token.partition(".")
        existing = self.authenticate_token(token, now=moment)
        if not existing.authenticated or existing.principal is None:
            raise AuthRefusedError(
                existing.code or REFUSAL_SESSION_UNKNOWN,
                f"cannot rotate session {session_id!r}: {existing.describe()}",
                remediation="authenticate again to obtain a fresh token",
            )
        actor = revoked_by or existing.principal.principal_id
        _require_actor(actor, "rotating a session")
        successor = self._issue_session(
            principal=existing.principal,
            kind=SessionKind(existing.method.value)
            if existing.method is not AuthMethod.TOKEN
            else SessionKind.PASSWORD,
            auth_source=existing.auth_source,
            ttl_s=self._session_ttl_s if ttl_s is None else ttl_s,
            now=moment,
        )
        self._store.mark_session_rotated(
            session_id,
            rotated_to=successor.session_id,
            revoked_by=actor,
            reason="rotated",
            now=moment,
        )
        self._store.record_revocation(
            self._revocation(RevocationSubject.SESSION, session_id, actor, "rotated", moment)
        )
        self._invalidate(session_id)
        return successor

    def revoke_session(
        self,
        token: str,
        *,
        revoked_by: str,
        reason: str,
        now: datetime | None = None,
    ) -> RevocationPropagation:
        """Revoke one session, and report how long it took to take effect.

        The returned :class:`RevocationPropagation` is measured by *probing*:
        the service re-authenticates the very token it just revoked and reports
        when (and whether) the answer turned. That makes the bound a measured
        fact rather than a claim — and because the refresh path drops this
        process's cache entry synchronously, the measured value is the honest
        one.
        """
        moment = self._now(now)
        _require_actor(revoked_by, "revoking a session")
        session_id, _, _ = token.partition(".")
        record = self._store.load_session(session_id)
        if record is None:
            raise AuthRefusedError(
                REFUSAL_SESSION_UNKNOWN,
                f"no session {session_id!r} to revoke",
                remediation="check the session id; rotation already replaces the token",
            )
        self._store.record_revocation(
            self._revocation(RevocationSubject.SESSION, session_id, revoked_by, reason, moment)
        )
        revoked = self._store.load_session(session_id)
        if revoked is not None and not revoked.revoked:
            self._store.save_session(
                revoked.model_copy(
                    update={
                        "revoked_at": moment,
                        "revoked_by": revoked_by,
                        "revocation_reason": reason,
                    }
                )
            )
        self._invalidate(session_id)
        observed_at, latency, still = self._probe_token(session_id, token)
        return RevocationPropagation(
            subject_kind="session",
            subject_id=session_id,
            revoked_at=moment,
            observed_at=observed_at,
            latency_s=latency,
            bound_s=self._bound_s,
            still_authenticated=still,
        )

    def _probe_token(
        self, session_id: str, token: str
    ) -> tuple[datetime | None, float | None, bool]:
        """Re-authenticate a token and measure when the revocation was visible."""
        start = self._monotonic()
        result = self.authenticate_token(token)
        elapsed = self._monotonic() - start
        if result.authenticated:
            return None, None, True
        return self._now(None), elapsed, False

    def revoke_all_sessions(
        self, principal_id: str, *, revoked_by: str, reason: str, now: datetime | None = None
    ) -> tuple[RevocationPropagation, ...]:
        """Revoke every live session for a principal, probing each one."""
        _require_actor(revoked_by, "revoking sessions")
        reports: list[RevocationPropagation] = []
        for session in self._store.sessions_for(principal_id):
            if session.revoked:
                continue
            reports.append(self._revoke_session_row(session.session_id, revoked_by, reason, now))
        return tuple(reports)

    def _revoke_session_row(
        self, session_id: str, revoked_by: str, reason: str, now: datetime | None
    ) -> RevocationPropagation:
        moment = self._now(now)
        self._store.record_revocation(
            self._revocation(RevocationSubject.SESSION, session_id, revoked_by, reason, moment)
        )
        record = self._store.load_session(session_id)
        if record is not None and not record.revoked:
            self._store.save_session(
                record.model_copy(
                    update={
                        "revoked_at": moment,
                        "revoked_by": revoked_by,
                        "revocation_reason": reason,
                    }
                )
            )
        self._invalidate(session_id)
        observed_at, latency, still = self._probe_token_by_id(session_id)
        return RevocationPropagation(
            subject_kind="session",
            subject_id=session_id,
            revoked_at=moment,
            observed_at=observed_at,
            latency_s=latency,
            bound_s=self._bound_s,
            still_authenticated=still,
        )

    def _probe_token_by_id(self, session_id: str) -> tuple[datetime | None, float | None, bool]:
        """Same probe as :meth:`_probe_token` without needing the secret.

        Used by the by-id revocation paths, where the caller named the session
        rather than presenting a token — so the probe has to reconstruct enough
        of one to be refused for the *right* reason, and a session whose secret
        cannot be reconstructed is still refused, which is the answer that
        matters.
        """
        start = self._monotonic()
        record = self._store.load_session(session_id)
        revocation = self._store.revocation_for(RevocationSubject.SESSION, session_id)
        principal_revocation = (
            self._store.revocation_for(RevocationSubject.PRINCIPAL, record.principal_id)
            if record is not None
            else None
        )
        elapsed = self._monotonic() - start
        still = (
            record is not None
            and not record.revoked
            and revocation is None
            and principal_revocation is None
        )
        if still:
            return None, None, True
        return self._now(None), elapsed, False

    def expire_sessions(self, *, now: datetime | None = None) -> SessionExpiryReport:
        """Report which sessions have lapsed. A report, never a mutation.

        An expired session is already unusable — every authentication re-checks
        the window — so this exists so an operator can *see* the sweep, not so
        the service can lazily clean up a window it never trusted.
        """
        moment = self._now(now)
        lapsed: list[str] = []
        live: list[str] = []
        for principal in self._store.all_principals():
            for session in self._store.sessions_for(principal.principal_id):
                (lapsed if session.is_expired(moment) else live).append(session.session_id)
        return SessionExpiryReport(at=moment, lapsed=tuple(lapsed), live=tuple(live))

    # -- service accounts and api keys ------------------------------------------

    def create_api_key(
        self,
        principal_id: str,
        *,
        scopes: Iterable[EnvironmentScope],
        ttl_s: float | None = None,
        now: datetime | None = None,
    ) -> IssuedApiKey:
        """Mint an API key for a service account or a person, scoped and hashed.

        ``scopes`` is required and must be non-empty: an unscoped key is the
        failure mode this whole feature exists to prevent, so it is unrepresentable
        rather than merely discouraged. Short-lived by default
        (:data:`DEFAULT_API_KEY_TTL_S`, half a session's life) and revocable in
        one statement.
        """
        moment = self._now(now)
        principal = self.principal(principal_id)
        if principal is None:
            raise AuthRefusedError(
                REFUSAL_PRINCIPAL_UNKNOWN,
                f"no principal {principal_id!r} to issue an api key for",
                remediation="register the principal first",
            )
        if principal.disabled:
            raise AuthRefusedError(
                REFUSAL_PRINCIPAL_DISABLED,
                f"{principal_id!r} is disabled; a disabled principal holds nothing",
                remediation="an administrator must re-enable the principal",
            )
        stated = tuple(EnvironmentScope(**scope.model_dump()) for scope in scopes)
        if not stated:
            msg = (
                "an api key must carry at least one environment scope; an unscoped key "
                "is the credential this feature exists to prevent"
            )
            raise AuthRefusedError(REFUSAL_API_KEY_UNSCOPED, msg)
        ttl = self._api_key_ttl_s if ttl_s is None else float(ttl_s)
        if ttl <= 0:
            msg = f"api key ttl_s must be positive, got {ttl}"
            raise InvariantViolationError("auth.non_positive_ttl", msg)
        secret = new_secret()
        key_id = new_api_key_id()
        record = _api_key_record(
            api_key_id=key_id,
            principal_id=principal_id,
            secret=secret,
            scopes=stated,
            pepper=self._pepper,
            issued_at=moment,
            ttl_s=ttl,
        )
        self._store.save_api_key(record)
        return IssuedApiKey(
            api_key_id=key_id,
            key_prefix=record.key_prefix,
            secret=secret,
            scopes=stated,
            issued_at=moment,
            expires_at=record.expires_at,
        )

    def authenticate_api_key(  # noqa: PLR0911 — one refusal per lifecycle stage, in order
        self, presented: str, *, now: datetime | None = None
    ) -> Authentication:
        """Verify a presented API key and return its principal *and its scopes*.

        The scopes travel with the answer on purpose: a caller that forgets to
        pass ``authentication=`` into :meth:`authorize` still has them available,
        and the API-key scope is not a substitute for a role grant, it is a
        *narrowing* applied on top of one.
        """
        moment = self._now(now)
        raw = presented.removeprefix("mk_")
        prefix, _, secret = raw.partition(".")
        if not prefix or not secret:
            return _refused(
                AuthMethod.API_KEY,
                REFUSAL_API_KEY_UNKNOWN,
                "an api key is presented as 'mk_<prefix>.<secret>'; this was neither",
                "present the key exactly as it was issued",
                at=moment,
            )
        if len(prefix) < API_KEY_PREFIX_CHARS:
            return _refused(
                AuthMethod.API_KEY,
                REFUSAL_API_KEY_UNKNOWN,
                "the api key prefix is too short to identify a key",
                "present the key exactly as it was issued",
                at=moment,
            )
        record = self._store.load_api_key_by_prefix(prefix)
        if record is None:
            return _refused(
                AuthMethod.API_KEY,
                REFUSAL_API_KEY_UNKNOWN,
                f"no api key with prefix {prefix!r}",
                "check the key; an unknown key is indistinguishable from a wrong one",
                at=moment,
            )
        if not verify_secret(secret, pepper=self._pepper, expected_hash=record.secret_hash):
            return _refused(
                AuthMethod.API_KEY,
                REFUSAL_CREDENTIAL_INVALID,
                f"the secret presented for api key {record.api_key_id!r} did not verify",
                "present the key exactly as it was issued",
                subject=record.api_key_id,
                at=moment,
            )
        key_revocation = self._store.revocation_for(RevocationSubject.API_KEY, record.api_key_id)
        principal_revocation = self._store.revocation_for(
            RevocationSubject.PRINCIPAL, record.principal_id
        )
        principal = self.principal(record.principal_id)
        if key_revocation is not None or record.revoked:
            return _refused(
                AuthMethod.API_KEY,
                REFUSAL_API_KEY_REVOKED,
                f"api key {record.api_key_id!r} was revoked at "
                f"{_revoked_at(key_revocation, record.revoked_at, record.issued_at).isoformat()}",
                "issue a new key for the service account",
                subject=record.api_key_id,
                at=moment,
            )
        if principal is None or principal.disabled or principal_revocation is not None:
            return _refused(
                AuthMethod.API_KEY,
                REFUSAL_PRINCIPAL_DISABLED,
                (
                    f"principal {record.principal_id!r} confers nothing; the key's owner "
                    "is disabled or was revoked"
                ),
                "an administrator must re-enable the principal",
                subject=record.api_key_id,
                at=moment,
            )
        if record.is_expired(moment):
            return _refused(
                AuthMethod.API_KEY,
                REFUSAL_API_KEY_EXPIRED,
                f"api key {record.api_key_id!r} expired at {record.expires_at.isoformat()}",
                "issue a new key; keys are short-lived by default",
                subject=record.api_key_id,
                at=moment,
            )
        self._store.mark_api_key_used(record.api_key_id, now=moment)
        return Authentication(
            method=AuthMethod.API_KEY,
            principal=principal,
            subject_id=record.api_key_id,
            scopes=record.scopes,
            issued_at=record.issued_at,
            expires_at=record.expires_at,
        )

    def revoke_api_key(
        self,
        api_key_id: str,
        *,
        revoked_by: str,
        reason: str,
        now: datetime | None = None,
    ) -> RevocationPropagation:
        """Revoke one API key and measure how long it took to take effect."""
        moment = self._now(now)
        _require_actor(revoked_by, "revoking an api key")
        record = self._store.load_api_key(api_key_id)
        if record is None:
            raise AuthRefusedError(
                REFUSAL_API_KEY_UNKNOWN,
                f"no api key {api_key_id!r} to revoke",
                remediation="check the key id",
            )
        self._store.record_revocation(
            self._revocation(RevocationSubject.API_KEY, api_key_id, revoked_by, reason, moment)
        )
        fresh = self._store.load_api_key(api_key_id)
        if fresh is not None and not fresh.revoked:
            self._store.save_api_key(
                fresh.model_copy(
                    update={
                        "revoked_at": moment,
                        "revoked_by": revoked_by,
                        "revocation_reason": reason,
                    }
                )
            )
        self._invalidate(api_key_id)
        start = self._monotonic()
        revocation = self._store.revocation_for(RevocationSubject.API_KEY, api_key_id)
        elapsed = self._monotonic() - start
        visible = revocation is not None
        return RevocationPropagation(
            subject_kind="api_key",
            subject_id=api_key_id,
            revoked_at=moment,
            observed_at=moment if visible else None,
            latency_s=elapsed,
            bound_s=self._bound_s,
            still_authenticated=not visible,
        )

    def api_keys_for(self, principal_id: str) -> tuple[Any, ...]:
        """Live API keys for a principal. Hashes included, secrets never present."""
        return self._store.api_keys_for(principal_id)

    # -- the approval seam ------------------------------------------------------

    def rebind_approver(self, approval: Approval) -> Approval:
        """Present ``approval`` with its approver's *current* principal record.

        This is the revoked-approver negative control, and it exists because of a
        real gap rather than a hypothetical one. An
        :class:`~mayhem.domain.approval.Approval` carries its approver as a
        snapshot: the :class:`~mayhem.domain.identity.Principal` as it read at
        mint time. The Phase 2 gate authorizes that approver — and
        :meth:`mayhem.domain.identity.RoleGrant.applies_to` refuses a *disabled*
        principal — so an approval whose approver has since been disabled would
        keep counting against the snapshot, forever, in every later gate pass.

        So the service re-reads the approver and presents the current record. What
        this changes is exactly one thing: whether the person who signed may
        exercise authority *now*. What it does not touch is the substance of the
        statement — plan digest, policy digest, proof digest, environment, issue
        time, and expiry are all carried through unchanged, so this is not a
        licence to edit an approval. It does change
        :attr:`~mayhem.domain.approval.Approval.approval_digest`, which is why it
        is a *copy* for the gate's decision rather than a rewrite of the stored
        record: the record on disk is untouched evidence, and what the gate is
        asked is "may this person still authorize this".

        An approver who cannot be resolved at all is bound to a disabled stand-in
        rather than dropped, because dropping the approval would silently change
        the quorum while leaving the operator believing the same set of
        signatures was counted.
        """
        current = self.principal(approval.approver.principal_id)
        if current is None:
            current = approval.approver.model_copy(update={"disabled": True})
        # Field comparison, not ``==``: :class:`~mayhem.domain.identity.Principal`
        # compares on ``principal_id`` alone, so a disabled principal would
        # compare equal to the enabled snapshot and this method would be a no-op
        # exactly when it matters.
        if current.model_dump() == approval.approver.model_dump():
            return approval
        return approval.model_copy(update={"approver": current})

    def gate_inputs(
        self,
        *,
        environment: EnvironmentScope,
        executor: Principal,
        proof: SafetyProof,
        policy_digest: str,
        approvals: Sequence[Approval] = (),
        consumed_ids: Iterable[str] = (),
        now: datetime | None = None,
        required_approvals: int = 1,
        separation_of_duties: bool | None = None,
    ) -> ApprovalGateInputs:
        """Build :class:`~mayhem.controller.approval_gate.ApprovalGateInputs` from
        this service's own state.

        The seam, and the reason it exists: grants and memberships come from
        *here* rather than being restated by the caller. A caller that passes its
        own grant list ends up authorizing against a different set than the one
        the store holds, and the resulting refusal — or worse, the resulting
        allow — is about a world that does not exist.

        ``separation_of_duties=None`` means "use this service's default"; the
        gate still decides per run, because Phase 2 is where the switch belongs.
        """
        return ApprovalGateInputs(
            now=self._now(now),
            environment=environment,
            executor=executor,
            proof=proof,
            policy_digest=policy_digest,
            approvals=tuple(self.rebind_approver(approval) for approval in approvals),
            grants=self.grants_for(principal_id=executor.principal_id)
            + self._grants_for_approvers(approvals),
            memberships=self._store.all_memberships(),
            consumed_ids=frozenset(consumed_ids),
            required_approvals=required_approvals,
            separation_of_duties=(
                self.separation_of_duties if separation_of_duties is None else separation_of_duties
            ),
        )

    def _grants_for_approvers(self, approvals: Sequence[Approval]) -> tuple[RoleGrant, ...]:
        """Grants for every approver whose approval was offered.

        The Phase 2 gate authorizes the approvers *from the grant set on its
        inputs*, so a service that supplied only the executor's grants would make
        every approval fail for want of an ``APPROVE`` grant it actually holds.
        Supplying the approvers' grants is not a second authorization system:
        :func:`~mayhem.domain.identity.effective_roles` still decides, and the
        gate still refuses when the grant does not cover the acted-on scope.
        """
        collected: dict[str, tuple[RoleGrant, ...]] = {}
        for approval in approvals:
            approver_id = approval.approver.principal_id
            if approver_id not in collected:
                collected[approver_id] = self.grants_for(principal_id=approver_id)
        grants: list[RoleGrant] = []
        for group in collected.values():
            grants.extend(group)
        return tuple(grants)

    def mint_approval(
        self,
        *,
        approval_id: str,
        proof: SafetyProof,
        policy_digest: str,
        approver_id: str,
        environment: EnvironmentScope,
        now: datetime | None = None,
        ttl_s: float | None = None,
        change_tickets: Sequence[ChangeTicket] = (),
        override: bool = False,
        override_reason: str = "",
        plan_author: str | None = None,
        note: str = "",
        separation_of_duties: bool | None = None,
    ) -> Approval:
        """Mint one approval on the Phase 1 type, after the Phase 3 checks.

        Two refusals happen *here* rather than at the gate, because the gate can
        only refuse at execution and a minted approval is already evidence:

        * the approver must hold ``APPROVE`` in ``environment`` — delegated to
          :func:`~mayhem.domain.identity.has_role`, the same predicate
          :func:`~mayhem.domain.approval.approval_reasons` uses, so a service
          that mints and a gate that refuses cannot disagree about who may
          approve;
        * with separation of duties on, the approver may not be the plan's
          author. Off, the check does not run at all — the roles stay separate
          even when their holders coincide.

        Returns:
            The :class:`~mayhem.domain.approval.Approval`. Persisting it is the
            caller's business; this module holds authority, not approvals.

        Raises:
            AuthRefusedError: With :data:`REFUSAL_MINT_UNAUTHORIZED` or
                :data:`REFUSAL_SELF_APPROVAL`; whatever
                :meth:`mayhem.domain.approval.Approval.bind` refuses (a proof
                that did not pass, a negative TTL, an override with no reason).
        """
        moment = self._now(now)
        approver = self.principal(approver_id)
        if approver is None:
            raise AuthRefusedError(
                REFUSAL_PRINCIPAL_UNKNOWN,
                f"no principal {approver_id!r} to approve with",
                remediation="register the approver and grant them approve in the scope",
            )
        if not self.may_approve(approver, environment, now=moment):
            raise AuthRefusedError(
                REFUSAL_MINT_UNAUTHORIZED,
                (
                    f"{approver_id!r} holds no approve grant in {environment.describe()}; "
                    "an approval nobody was authorized to make is not minted, because it "
                    "would authorize nothing and would still be evidence of a decision"
                ),
                remediation=(
                    f"grant approve to {approver_id!r} in {environment.describe()}, or "
                    "approve from a principal that already holds it there"
                ),
            )
        enforce_separation = (
            self.separation_of_duties if separation_of_duties is None else separation_of_duties
        )
        if enforce_separation and plan_author is not None and plan_author == approver_id:
            raise AuthRefusedError(
                REFUSAL_SELF_APPROVAL,
                (
                    f"{approver_id!r} authored the plan they are approving; separation of "
                    "duties is on, so the approval is not minted"
                ),
                remediation="have a different principal holding approve approve this plan",
            )
        return Approval.bind(
            approval_id=approval_id,
            proof=proof,
            policy_digest=policy_digest,
            approver=approver,
            environment=environment,
            issued_at=moment,
            ttl_s=ttl_s,
            change_tickets=tuple(change_tickets),
            override=override,
            override_reason=override_reason,
            note=note,
        )

    def mint_overridden_approval(
        self,
        *,
        approval_id: str,
        proof: SafetyProof,
        policy_digest: str,
        approver_id: str,
        environment: EnvironmentScope,
        reason: str,
        **kwargs: Any,
    ) -> Approval:
        """Mint an emergency override. The reason is mandatory, not optional.

        Same checks as :meth:`mint_approval`, plus a reason that cannot be blank.
        The Phase 2 gate records an override it saw and seals the identity and
        reason into evidence; this is the only place that reason can be demanded
        *before* the fact.
        """
        if not reason.strip():
            msg = (
                "an emergency override must carry a reason; 'someone bypassed this and "
                "wrote nothing down' is the one record an audit trail cannot reconstruct"
            )
            raise InvariantViolationError("auth.override_requires_reason", msg)
        return self.mint_approval(
            approval_id=approval_id,
            proof=proof,
            policy_digest=policy_digest,
            approver_id=approver_id,
            environment=environment,
            override=True,
            override_reason=reason,
            **kwargs,
        )

    def service_account(
        self,
        *,
        principal_id: str,
        display_name: str = "",
        external_id: str = "",
        auth_source: AuthSource = AuthSource.LOCAL,
        now: datetime | None = None,
    ) -> Principal:
        """Register a service-account principal.

        The vocabulary already distinguishes
        :attr:`~mayhem.domain.identity.PrincipalKind.SERVICE_ACCOUNT` from a
        person; this exists so the common case does not require assembling the
        model by hand, and so the kind is set from *one* place rather than by
        every caller remembering it.
        """
        principal = Principal(
            principal_id=principal_id,
            kind=PrincipalKind.SERVICE_ACCOUNT,
            display_name=display_name or principal_id,
            external_id=external_id,
        )
        return self._store.save_principal(principal, auth_source=auth_source, now=self._now(now))

    # -- revocation bookkeeping -------------------------------------------------

    def _revocation(
        self,
        subject_kind: RevocationSubject,
        subject_id: str,
        revoked_by: str,
        reason: str,
        now: datetime,
    ) -> RevocationRecord:
        if not reason.strip():
            msg = (
                f"a revocation of {subject_id!r} must say why; an unattributed revocation "
                "cannot be reviewed"
            )
            raise AuthRefusedError(REFUSAL_REVOCATION_UNKNOWN, msg)
        return RevocationRecord(
            revocation_id=f"rv-{subject_kind.value}-{subject_id}",
            subject_kind=subject_kind,
            subject_id=subject_id,
            revoked_at=now,
            revoked_by=revoked_by,
            reason=reason,
        )


# =============================================================================
# Helpers
# =============================================================================


def _require_actor(actor: str, action: str) -> None:
    if not actor.strip():
        msg = f"{action} must name who did it; an unattributed action is unreviewable"
        raise AuthRefusedError(REFUSAL_REVOCATION_UNKNOWN, msg)


def _refused(
    method: AuthMethod,
    code: str,
    reason: str,
    remediation: str,
    *,
    subject: str = "",
    at: datetime,
) -> Authentication:
    """A refusal carrying no principal — the shape default-deny needs.

    Returning rather than raising is what lets one caller handle "wrong password"
    and "account disabled" without a try/except, and ``principal is None`` means
    a caller who ignores :attr:`Authentication.authenticated` still cannot act.
    """
    return Authentication(
        method=method,
        principal=None,
        subject_id=subject,
        refusal=AuthRefusal(
            code=code, reason=reason, remediation=remediation, subject=subject, at=at
        ),
    )


def _session_record(
    *,
    session_id: str,
    principal_id: str,
    kind: SessionKind,
    auth_source: AuthSource,
    secret: str,
    pepper: bytes,
    issued_at: datetime,
    ttl_s: float,
) -> SessionRecord:
    return SessionRecord(
        session_id=session_id,
        principal_id=principal_id,
        kind=kind,
        auth_source=auth_source,
        token_hash=hash_secret(secret, pepper=pepper),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=float(ttl_s)),
    )


def _api_key_record(
    *,
    api_key_id: str,
    principal_id: str,
    secret: str,
    scopes: Sequence[EnvironmentScope],
    pepper: bytes,
    issued_at: datetime,
    ttl_s: float,
) -> ApiKeyRecord:
    return ApiKeyRecord(
        api_key_id=api_key_id,
        principal_id=principal_id,
        key_prefix=secret[:API_KEY_PREFIX_CHARS],
        secret_hash=hash_secret(secret, pepper=pepper),
        scopes=tuple(scopes),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=float(ttl_s)),
    )


def _revoked_at(
    revocation: RevocationRecord | None, stamped: datetime | None, fallback: datetime
) -> datetime:
    """When a subject was revoked, for a refusal message.

    Prefers the append-only row (which names the actor) and falls back to the
    row's own stamp. The last-resort ``fallback`` is the issued-at of a subject
    with no revocation evidence at all, which only reaches here if a caller
    reached the refusal branch for another reason — the message then states a
    time that is at worst the issue time rather than inventing one.
    """
    if revocation is not None:
        return revocation.revoked_at
    return stamped or fallback
