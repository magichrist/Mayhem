"""Persistence for principals, memberships, grants, sessions, and API keys.

Plan 09 Phase 3's service half. Phase 1 (:mod:`mayhem.domain.identity`) decided
*what* a principal, a role grant, and an environment scope are, as pure types.
Phase 2 (:mod:`mayhem.controller.approval_gate`) decided *whether an approval
authorizes*, as a pure function over those types plus an injected clock. Neither
could store anything, and this module is the IO half they need.

Four properties this module exists to hold, each of which is a *schema* property
rather than a code convention:

**No credential material is stored, ever.** Local passwords are PBKDF2-HMAC-SHA256
with a per-credential salt; session secrets and API-key secrets are
pepper-salted SHA-256 over 256 bits of :func:`secrets.token_urlsafe` entropy.
:data:`CREDENTIAL_HASH_ALGORITHM` and
:data:`PEPPERED_SECRET_ALGORITHM` are the only two algorithm names the
``CHECK`` constraints accept, and :meth:`IdentityStore.credential_material`
returns every credential-bearing column value so a test can assert a plaintext
appears in none of them. A deployment that loses the store still cannot
authenticate anybody: the pepper is injected by the caller and is not here.

**A revocation is an append-only row, not an edit.** ``identity_revocations``
carries a ``BEFORE UPDATE`` / ``BEFORE DELETE`` trigger pair that RAISEs, so a
revocation cannot be un-written even by a direct SQL writer. The service writes
the revocation row *and* stamps ``revoked_at`` on the session/API-key row in the
same transaction — the stamp is the cheap read path, the row is the reason the
cheap read path cannot go stale (see the propagation note below).

**Propagation is a read, not a cache invalidation.** Every authentication reads
the revocations table for the session, the API key, *and* the principal. A
principal disabled by another process therefore fences its own sessions even
though nobody updated those rows. The service caches that read for a bounded
window (:data:`~mayhem.controller.auth_service.REVOCATION_PROPAGATION_BOUND_S`)
and the bound is asserted by a test rather than asserted here.

**Roles are the Phase 1 vocabulary, stored verbatim.** ``identity_role_grants``
keeps ``role`` and ``scope_key`` in exactly the spelling
:mod:`mayhem.domain.identity` uses, and ``grant_json`` holds the whole record so
a reconstruction cannot need a second field-mapping table. This module never
decides whether a grant applies — :func:`mayhem.domain.identity.effective_roles`
does, with an explicit clock.

Deliberately absent: password reset tokens, TOTP/MFA secrets, OAuth client
registrations, SAML metadata, and SCIM sync state. Those are secrets whose
*format* belongs to a provider library this project does not depend on; they are
Phase 6 surfaces with their own tables. What exists here is enough for the
walkthrough — authenticate, resolve authority, mint and revoke — and the
``CHECK`` constraints refuse to become a place where an unhashed credential can
be smuggled in under a column name that looks harmless.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.common import iso_utc
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import canonical_json, digest
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    PrincipalKind,
    RoleGrant,
    TeamMembership,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from mayhem.infra.store import Store

# =============================================================================
# Constants
# =============================================================================

#: The only password-hash algorithm this store accepts. A row naming anything
#: else is refused by a CHECK constraint, because "which KDF" is exactly the
#: field an operator relaxes by accident and a reader then trusts.
CREDENTIAL_HASH_ALGORITHM = "pbkdf2_sha256"

#: The only high-entropy-secret algorithm. These are not passwords: the secret
#: is 256 bits of CSPRNG output, so a single-pass peppered SHA-256 is the right
#: cost — deliberately *not* PBKDF2, which would make every token verification
#: pay a password-strength cost for a value that cannot be brute-forced.
PEPPERED_SECRET_ALGORITHM = "sha256_peppered"

#: PBKDF2 work factor for a *password*. Overridable on :meth:`IdentityStore.set_local_credential`
#: so a test suite is not a benchmark; the default is the posture.
PASSWORD_HASH_ITERATIONS = 200_000

#: Salt width in bytes (32 → 64 hex characters, which is what the CHECK pins).
SALT_BYTES = 32

#: Bytes of entropy in a session secret or an API-key secret.
SECRET_BYTES = 32

#: How many leading characters of a key's secret are stored as a *lookup* prefix.
#: The prefix is public by construction — it is how a presented key is routed to
#: one row — so it must be long enough to be collision-resistant at the expected
#: key count and is deliberately not a verification input.
API_KEY_PREFIX_CHARS = 12

#: Session-id alphabet: unambiguous hex, so an id copied out of a log line and
#: pasted back in cannot differ by an ``l``/``1`` or ``0``/``O`` reading.
SESSION_ID_CHARS = 16


# =============================================================================
# Vocabulary
# =============================================================================


class AuthSource(StrEnum):
    """Which path established this principal's identity.

    A vocabulary rather than a hierarchy, matching
    :class:`~mayhem.domain.identity.PrincipalKind`: ``LOCAL`` is not a lesser
    ``OIDC``, it is the first of the three the rollout order names. The values
    are exactly the strings the ``identity_principals.auth_source`` CHECK
    accepts.
    """

    LOCAL = "local"
    OIDC = "oidc"
    OAUTH = "oauth"
    SAML = "saml"
    SCIM = "scim"
    WORKLOAD = "workload"


class SessionKind(StrEnum):
    """What a session was minted from. Pinned by the ``identity_sessions.kind`` CHECK."""

    PASSWORD = "password"
    FEDERATED = "federated"
    SERVICE_ACCOUNT = "service_account"


class RevocationSubject(StrEnum):
    """What a revocation row is about. Pinned by the ``subject_kind`` CHECK.

    ``PRINCIPAL`` is the load-bearing one: disabling a person writes *this* row,
    so every session and API key they hold stops being honoured without
    anybody having to walk their children.
    """

    SESSION = "session"
    API_KEY = "api_key"
    PRINCIPAL = "principal"


class LocalCredentialRecord(BaseModel):
    """One principal's stored password verifier. Never the password.

    ``credential_hash`` and ``salt_hex`` are the whole record. There is no field
    a plaintext could occupy, which is why the "no plaintext at rest" property
    is a schema fact here and not merely a promise in the writer.
    """

    model_config = ConfigDict(frozen=True)

    principal_id: str
    algorithm: str = CREDENTIAL_HASH_ALGORITHM
    iterations: int = Field(gt=0)
    salt_hex: str = Field(min_length=64, max_length=64)
    credential_hash: str = Field(min_length=64, max_length=64)
    updated_at: datetime

    @model_validator(mode="after")
    def _hash_is_hex(self) -> LocalCredentialRecord:
        for name in ("salt_hex", "credential_hash"):
            value = getattr(self, name)
            if any(char not in "0123456789abcdef" for char in value):
                msg = f"local credential {name} must be lowercase hex, got {value!r}"
                raise InvariantViolationError("identity.credential_not_hex", msg)
        return self


class SessionRecord(BaseModel):
    """One issued session. The token secret is a hash; ``session_id`` is public.

    A presented token is ``"<session_id>.<secret>"``: the id routes the lookup
    and the secret proves it. Storing the id separately is what lets a
    revocation name the thing it revokes without ever putting the bearer value
    in a table.
    """

    model_config = ConfigDict(frozen=True)

    session_id: str
    principal_id: str
    kind: SessionKind = SessionKind.PASSWORD
    auth_source: AuthSource = AuthSource.LOCAL
    token_hash: str = Field(min_length=64, max_length=64)
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_by: str = ""
    revocation_reason: str = ""
    rotated_from: str = ""
    rotated_to: str = ""
    rotated_at: datetime | None = None

    @model_validator(mode="after")
    def _check_window(self) -> SessionRecord:
        if self.expires_at <= self.issued_at:
            msg = (
                f"session {self.session_id} expires ({self.expires_at.isoformat()}) at or "
                f"before it was issued ({self.issued_at.isoformat()})"
            )
            raise InvariantViolationError("identity.session_window", msg)
        if self.revoked_at is not None and not self.revoked_by.strip():
            msg = f"session {self.session_id} is revoked but names no revoker"
            raise InvariantViolationError("identity.revocation_needs_actor", msg)
        if self.revoked_at is not None and self.revoked_at < self.issued_at:
            msg = f"session {self.session_id} is revoked before it was issued"
            raise InvariantViolationError("identity.revocation_time_order", msg)
        return self

    def is_expired(self, now: datetime) -> bool:
        """True at and after ``expires_at`` — same boundary as every other window."""
        return now >= self.expires_at

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None


class ApiKeyRecord(BaseModel):
    """One API key. Only its hash, its public prefix, and its scopes are stored."""

    model_config = ConfigDict(frozen=True)

    api_key_id: str
    principal_id: str
    key_prefix: str = Field(min_length=API_KEY_PREFIX_CHARS)
    secret_hash: str = Field(min_length=64, max_length=64)
    scopes: tuple[EnvironmentScope, ...] = ()
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_by: str = ""
    revocation_reason: str = ""
    last_used_at: datetime | None = None

    @model_validator(mode="after")
    def _check_window(self) -> ApiKeyRecord:
        if self.expires_at <= self.issued_at:
            msg = (
                f"api key {self.api_key_id} expires ({self.expires_at.isoformat()}) at or "
                f"before it was issued ({self.issued_at.isoformat()})"
            )
            raise InvariantViolationError("identity.api_key_window", msg)
        if self.revoked_at is not None and not self.revoked_by.strip():
            msg = f"api key {self.api_key_id} is revoked but names no revoker"
            raise InvariantViolationError("identity.revocation_needs_actor", msg)
        return self

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None

    def covers(self, scope: EnvironmentScope) -> bool:
        """True when one of this key's scopes reaches ``scope``.

        A key with *no* scope is a key nobody scoped, and an unscoped key is
        refused everywhere rather than treated as org-wide: "short-lived,
        scoped, revocable" is the whole property, and the permissive reading of
        a missing scope is how a CI key ends up holding production authority.
        """
        return any(stated.covers(scope) for stated in self.scopes)


class RevocationRecord(BaseModel):
    """An append-only statement that a subject stopped being usable."""

    model_config = ConfigDict(frozen=True)

    revocation_id: str
    subject_kind: RevocationSubject
    subject_id: str
    revoked_at: datetime
    revoked_by: str = Field(min_length=1)
    reason: str = Field(min_length=1)


# =============================================================================
# Credential primitives (stdlib only — no hashing dependency is added)
# =============================================================================


def new_secret() -> str:
    """A URL-safe secret with :data:`SECRET_BYTES` bytes of CSPRNG entropy."""
    return secrets.token_urlsafe(SECRET_BYTES)


def new_session_id() -> str:
    """A public session id. Unguessable, but *not* the bearer value."""
    return f"s-{secrets.token_hex(SESSION_ID_CHARS // 2)}"


def new_api_key_id() -> str:
    return f"ak-{secrets.token_hex(8)}"


def hash_password(
    password: str,
    *,
    salt_hex: str | None = None,
    iterations: int = PASSWORD_HASH_ITERATIONS,
) -> tuple[str, str]:
    """PBKDF2-HMAC-SHA256 a password; return ``(salt_hex, hash_hex)``.

    The salt is per-credential and returned so the caller can store it beside
    the hash — which is the only reason two principals with the same password
    do not produce the same row.
    """
    if iterations < 1:
        msg = f"password hash iterations must be positive, got {iterations}"
        raise InvariantViolationError("identity.negative_iterations", msg)
    salt = secrets.token_bytes(SALT_BYTES) if salt_hex is None else bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return salt.hex(), derived.hex()


def verify_password(
    password: str,
    *,
    salt_hex: str,
    credential_hash: str,
    iterations: int,
) -> bool:
    """Constant-time check of a password against a stored verifier."""
    _, candidate = hash_password(password, salt_hex=salt_hex, iterations=iterations)
    return hmac.compare_digest(candidate, credential_hash)


def hash_secret(secret: str, *, pepper: bytes) -> str:
    """Pepper-salted SHA-256 of a high-entropy secret.

    The pepper is a deployment secret the caller injects and this module never
    stores, so a stolen database alone cannot be compared against a candidate
    without it. Length-independent by construction of SHA-256, which is what
    makes it appropriate for a fixed-width 256-bit input.
    """
    return hashlib.sha256(pepper + b"\x00" + secret.encode("utf-8")).hexdigest()


def verify_secret(secret: str, *, pepper: bytes, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret, pepper=pepper), expected_hash)


# =============================================================================
# The store
# =============================================================================


class IdentityStore:
    """SQLite persistence for the identity tables added by ``M0030_IDENTITY``.

    One write per call, each in a single ``Store.write()`` transaction
    (ADR-0007), so a revocation that stamps a session and writes its
    append-only row either lands whole or not at all. A revocation split across
    two transactions is a window in which a revoked session still reads as live,
    and that window is the one thing this phase must not have.

    Reads are deliberately *narrow*: :meth:`load_session` and
    :meth:`load_api_key` return the record and nothing else, so a caller cannot
    reach a hash it does not need. :meth:`credential_material` exists so a test
    can make the no-plaintext claim about the *schema* rather than about one
    writer's discipline.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    @property
    def store(self) -> Store:
        """The underlying store, for callers that compose transactions."""
        return self._store

    # -- principals ------------------------------------------------------------

    def save_principal(
        self, principal: Principal, *, auth_source: AuthSource, now: datetime
    ) -> Principal:
        """Insert or replace one principal row.

        ``INSERT OR REPLACE`` is right here and nowhere else in this module:
        a principal's *identity* is its id, and its profile columns are
        descriptive (the same rule
        :class:`~mayhem.domain.identity.Principal` states for the type). Note
        what replace does *not* touch: ``disabled`` is rewritten from the
        passed record, so a caller that reloads a principal and saves it is
        writing back the disabled flag it read — which is why
        :meth:`set_principal_disabled` exists as a separate statement rather
        than as "load, flip, save".
        """
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO identity_principals (principal_id, kind, display_name, "
                "email, external_id, auth_source, disabled, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    principal.principal_id,
                    principal.kind.value,
                    principal.display_name,
                    principal.email,
                    principal.external_id,
                    AuthSource(auth_source).value,
                    int(principal.disabled),
                    iso_utc(now),
                    iso_utc(now),
                ),
            )
        return principal

    def load_principal(self, principal_id: str) -> Principal | None:
        rows = self._store.query(
            "SELECT principal_id, kind, display_name, email, external_id, disabled "
            "FROM identity_principals WHERE principal_id = ?",
            (principal_id,),
        )
        return _principal_from_row(rows[0]) if rows else None

    def find_by_external_id(self, *, auth_source: AuthSource, external_id: str) -> Principal | None:
        """Resolve the provider's own id to a local principal.

        The lookup an OIDC/SAML/SCIM port needs, and the reason
        :attr:`~mayhem.domain.identity.Principal.external_id` exists: a
        re-issued local id must not lose the link back to the IdP record.
        """
        rows = self._store.query(
            "SELECT principal_id, kind, display_name, email, external_id, disabled "
            "FROM identity_principals WHERE auth_source = ? AND external_id = ?",
            (AuthSource(auth_source).value, external_id),
        )
        return _principal_from_row(rows[0]) if rows else None

    def all_principals(self) -> tuple[Principal, ...]:
        rows = self._store.query(
            "SELECT principal_id, kind, display_name, email, external_id, disabled "
            "FROM identity_principals ORDER BY principal_id"
        )
        return tuple(_principal_from_row(row) for row in rows)

    def set_principal_disabled(
        self, principal_id: str, *, disabled: bool, now: datetime
    ) -> Principal | None:
        """Flip the disabled flag without a load/modify/save round trip."""
        with self._store.write() as conn:
            cursor = conn.execute(
                "UPDATE identity_principals SET disabled = ?, updated_at = ? "
                "WHERE principal_id = ?",
                (int(disabled), iso_utc(now), principal_id),
            )
        if cursor.rowcount == 0:
            return None
        return self.load_principal(principal_id)

    # -- local credentials ------------------------------------------------------

    def set_local_credential(
        self,
        principal_id: str,
        password: str,
        *,
        now: datetime,
        iterations: int = PASSWORD_HASH_ITERATIONS,
    ) -> LocalCredentialRecord:
        """Hash and store a password. The plaintext is not retained anywhere."""
        salt_hex, credential_hash = hash_password(password, iterations=iterations)
        record = LocalCredentialRecord(
            principal_id=principal_id,
            algorithm=CREDENTIAL_HASH_ALGORITHM,
            iterations=iterations,
            salt_hex=salt_hex,
            credential_hash=credential_hash,
            updated_at=now,
        )
        self._write_credential(record)
        return record

    def _write_credential(self, record: LocalCredentialRecord) -> None:
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO identity_local_credentials (principal_id, algorithm, "
                "iterations, salt_hex, credential_hash, updated_at) VALUES (?,?,?,?,?,?)",
                (
                    record.principal_id,
                    record.algorithm,
                    record.iterations,
                    record.salt_hex,
                    record.credential_hash,
                    iso_utc(record.updated_at),
                ),
            )

    def load_local_credential(self, principal_id: str) -> LocalCredentialRecord | None:
        rows = self._store.query(
            "SELECT principal_id, algorithm, iterations, salt_hex, credential_hash, updated_at "
            "FROM identity_local_credentials WHERE principal_id = ?",
            (principal_id,),
        )
        if not rows:
            return None
        row = rows[0]
        return LocalCredentialRecord(
            principal_id=str(row["principal_id"]),
            algorithm=str(row["algorithm"]),
            iterations=int(row["iterations"]),
            salt_hex=str(row["salt_hex"]),
            credential_hash=str(row["credential_hash"]),
            updated_at=datetime.fromisoformat(str(row["updated_at"])),
        )

    # -- memberships ------------------------------------------------------------

    def save_membership(self, membership: TeamMembership) -> TeamMembership:
        """Insert or replace one ``(principal, team)`` membership and its window.

        One row per pair is deliberate: a membership is a *current* fact with a
        closing time, not a history. ``until`` is how it is made revocable
        without deletion (:meth:`~mayhem.domain.identity.TeamMembership.is_active`
        is the reader), so the row that ends a membership is the row that
        existed before it — which is what keeps "who was in this team last
        quarter" answerable from the audit stream rather than from here.
        """
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO identity_memberships (principal_id, team_id, joined_at, "
                "until_at) VALUES (?,?,?,?)",
                (
                    membership.principal.principal_id,
                    membership.team_id,
                    iso_utc(membership.joined_at),
                    None if membership.until is None else iso_utc(membership.until),
                ),
            )
        return membership

    def memberships_for(self, principal_id: str) -> tuple[TeamMembership, ...]:
        principal = self.load_principal(principal_id)
        if principal is None:
            return ()
        return self._memberships("WHERE m.principal_id = ?", (principal_id,), principal)

    def all_memberships(self) -> tuple[TeamMembership, ...]:
        return self._memberships("", ())

    def _memberships(
        self, where: str, params: Sequence[object], principal: Principal | None = None
    ) -> tuple[TeamMembership, ...]:
        sql = (
            "SELECT m.principal_id, m.team_id, m.joined_at, m.until_at "
            "FROM identity_memberships m "
            "LEFT JOIN identity_principals p ON p.principal_id = m.principal_id "
            f"{where} ORDER BY m.principal_id, m.team_id"
        )
        resolved: list[TeamMembership] = []
        for row in self._store.query(sql, tuple(params)):
            member = principal or self.load_principal(str(row["principal_id"]))
            if member is None:
                # A membership row whose principal row is gone cannot be read as
                # a membership: TeamMembership carries the Principal itself, and
                # inventing one would grant a team role to a subject that does
                # not exist.
                continue
            until = row["until_at"]
            resolved.append(
                TeamMembership(
                    principal=member,
                    team_id=str(row["team_id"]),
                    joined_at=datetime.fromisoformat(str(row["joined_at"])),
                    until=None if until is None else datetime.fromisoformat(str(until)),
                )
            )
        return tuple(resolved)

    # -- role grants ------------------------------------------------------------

    def save_grant(self, grant: RoleGrant) -> str:
        """Persist one grant; return its deterministic ``grant_id``.

        The id is a digest of the grant's own identifying fields rather than a
        counter, so writing the same grant twice is idempotent — which matters
        because a grant is a *fact* about authority, not an event, and an event
        log would let the same authority be granted twice and look like two
        separate decisions.
        """
        grant_id = _grant_id(grant)
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO identity_role_grants (grant_id, role, scope_key, "
                "addressee_kind, addressee_id, granted_at, expires_at, granted_by, "
                "change_ticket, grant_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    grant_id,
                    grant.role.value,
                    grant.scope.key(),
                    "team" if grant.principal is None else "principal",
                    grant.addressee,
                    iso_utc(grant.granted_at),
                    None if grant.expires_at is None else iso_utc(grant.expires_at),
                    grant.granted_by,
                    grant.change_ticket,
                    canonical_json(_grant_payload(grant)),
                ),
            )
        return grant_id

    def grants_for(self, *, principal_id: str = "", team_id: str = "") -> tuple[RoleGrant, ...]:
        """Grants addressed to one principal or one team.

        Called twice per authorization (the principal's grants and the
        memberships' teams' grants) rather than once over "everything for this
        person", because the Phase 1 vocabulary
        (:func:`~mayhem.domain.identity.effective_roles`) unions direct and team
        grants itself. Resolving team membership in SQL would be a second rule
        for the same question, and two rules for "is this person in that team"
        eventually disagree.
        """
        if bool(principal_id) == bool(team_id):
            msg = "grants_for needs exactly one of principal_id or team_id"
            raise InvariantViolationError("identity.grant_addressee_ambiguous", msg)
        # The column names are fixed strings chosen from a two-valued enum, never
        # interpolated caller text — the value is always bound as a parameter.
        kind = "principal" if principal_id else "team"
        value = principal_id or team_id
        rows = self._store.query(
            "SELECT grant_json FROM identity_role_grants "
            "WHERE addressee_kind = ? AND addressee_id = ? "
            "ORDER BY role, scope_key, granted_at",
            (kind, value),
        )
        return tuple(RoleGrant.model_validate(json.loads(str(row["grant_json"]))) for row in rows)

    def all_grants(self) -> tuple[RoleGrant, ...]:
        rows = self._store.query(
            "SELECT grant_json FROM identity_role_grants ORDER BY role, scope_key, granted_at"
        )
        return tuple(RoleGrant.model_validate(json.loads(str(row["grant_json"]))) for row in rows)

    def delete_grant(self, grant_id: str) -> bool:
        """Remove one grant by id. Returns whether a row was removed.

        Deletion is offered *beside* the window-based expiry rather than
        instead of it: a grant with an ``expires_at`` stops applying through
        :func:`~mayhem.domain.identity.RoleGrant.is_active` and stays on record,
        and an operator who genuinely wants the row gone (a test fixture, a
        mistaken grant for a wrong person) can remove it. The audit stream is
        what preserves history; this table is current authority.
        """
        with self._store.write() as conn:
            cursor = conn.execute(
                "DELETE FROM identity_role_grants WHERE grant_id = ?", (grant_id,)
            )
        return cursor.rowcount > 0

    # -- sessions ---------------------------------------------------------------

    def save_session(self, record: SessionRecord) -> None:
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO identity_sessions (session_id, principal_id, kind, "
                "auth_source, token_hash, issued_at, expires_at, revoked_at, revoked_by, "
                "revocation_reason, rotated_from, rotated_to, rotated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.session_id,
                    record.principal_id,
                    record.kind.value,
                    record.auth_source.value,
                    record.token_hash,
                    iso_utc(record.issued_at),
                    iso_utc(record.expires_at),
                    None if record.revoked_at is None else iso_utc(record.revoked_at),
                    record.revoked_by,
                    record.revocation_reason,
                    record.rotated_from,
                    record.rotated_to,
                    None if record.rotated_at is None else iso_utc(record.rotated_at),
                ),
            )

    def load_session(self, session_id: str) -> SessionRecord | None:
        rows = self._store.query(
            "SELECT session_id, principal_id, kind, auth_source, token_hash, issued_at, "
            "expires_at, revoked_at, revoked_by, revocation_reason, rotated_from, rotated_to, "
            "rotated_at FROM identity_sessions WHERE session_id = ?",
            (session_id,),
        )
        return _session_from_row(rows[0]) if rows else None

    def sessions_for(self, principal_id: str) -> tuple[SessionRecord, ...]:
        rows = self._store.query(
            "SELECT session_id, principal_id, kind, auth_source, token_hash, issued_at, "
            "expires_at, revoked_at, revoked_by, revocation_reason, rotated_from, rotated_to, "
            "rotated_at FROM identity_sessions WHERE principal_id = ? ORDER BY issued_at",
            (principal_id,),
        )
        return tuple(_session_from_row(row) for row in rows)

    def mark_session_rotated(
        self,
        session_id: str,
        *,
        rotated_to: str,
        revoked_by: str,
        reason: str,
        now: datetime,
    ) -> None:
        """Stamp rotation bookkeeping and revoke the predecessor.

        Rotation is revoke-then-issue, and this is the revoke half: the old
        token stops being honoured at the same instant the new one starts. The
        ``rotated_to`` link is what makes "the token that was rotated" answerable
        without keeping the old hash.
        """
        with self._store.write() as conn:
            conn.execute(
                "UPDATE identity_sessions SET revoked_at = ?, revoked_by = ?, "
                "revocation_reason = ?, rotated_to = ?, rotated_at = ? WHERE session_id = ?",
                (iso_utc(now), revoked_by, reason, rotated_to, iso_utc(now), session_id),
            )

    # -- api keys ---------------------------------------------------------------

    def save_api_key(self, record: ApiKeyRecord) -> None:
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO identity_api_keys (api_key_id, principal_id, key_prefix, "
                "secret_hash, scopes_json, issued_at, expires_at, revoked_at, revoked_by, "
                "revocation_reason, last_used_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.api_key_id,
                    record.principal_id,
                    record.key_prefix,
                    record.secret_hash,
                    json.dumps([scope.model_dump(mode="json") for scope in record.scopes]),
                    iso_utc(record.issued_at),
                    iso_utc(record.expires_at),
                    None if record.revoked_at is None else iso_utc(record.revoked_at),
                    record.revoked_by,
                    record.revocation_reason,
                    None if record.last_used_at is None else iso_utc(record.last_used_at),
                ),
            )

    def load_api_key(self, api_key_id: str) -> ApiKeyRecord | None:
        rows = self._store.query(
            "SELECT api_key_id, principal_id, key_prefix, secret_hash, scopes_json, issued_at, "
            "expires_at, revoked_at, revoked_by, revocation_reason, last_used_at "
            "FROM identity_api_keys WHERE api_key_id = ?",
            (api_key_id,),
        )
        return _api_key_from_row(rows[0]) if rows else None

    def load_api_key_by_prefix(self, key_prefix: str) -> ApiKeyRecord | None:
        """Route a presented key to its single row.

        The prefix is not a credential: it selects the candidate row, and the
        secret half is still verified against that row's hash. A wrong prefix
        therefore fails as *unknown key* rather than as a bad secret, which is
        the same information either way and one less place where a comparison
        short-circuits.
        """
        rows = self._store.query(
            "SELECT api_key_id, principal_id, key_prefix, secret_hash, scopes_json, issued_at, "
            "expires_at, revoked_at, revoked_by, revocation_reason, last_used_at "
            "FROM identity_api_keys WHERE key_prefix = ?",
            (key_prefix,),
        )
        return _api_key_from_row(rows[0]) if rows else None

    def api_keys_for(self, principal_id: str) -> tuple[ApiKeyRecord, ...]:
        rows = self._store.query(
            "SELECT api_key_id, principal_id, key_prefix, secret_hash, scopes_json, issued_at, "
            "expires_at, revoked_at, revoked_by, revocation_reason, last_used_at "
            "FROM identity_api_keys WHERE principal_id = ? ORDER BY issued_at",
            (principal_id,),
        )
        return tuple(_api_key_from_row(row) for row in rows)

    def mark_api_key_used(self, api_key_id: str, *, now: datetime) -> None:
        with self._store.write() as conn:
            conn.execute(
                "UPDATE identity_api_keys SET last_used_at = ? WHERE api_key_id = ?",
                (iso_utc(now), api_key_id),
            )

    # -- revocations ------------------------------------------------------------

    def record_revocation(self, record: RevocationRecord) -> RevocationRecord:
        """Append one revocation. Never an update — the triggers enforce it.

        ``INSERT OR IGNORE`` on ``(subject_kind, subject_id)`` makes a second
        revocation of the same subject a no-op: the first one stands with its
        original revoker and reason, so "who revoked this and when" cannot be
        silently rewritten by a later, weaker record.
        """
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO identity_revocations (revocation_id, subject_kind, "
                "subject_id, revoked_at, revoked_by, reason) VALUES (?,?,?,?,?,?)",
                (
                    record.revocation_id,
                    record.subject_kind.value,
                    record.subject_id,
                    iso_utc(record.revoked_at),
                    record.revoked_by,
                    record.reason,
                ),
            )
        return record

    def revocation_for(
        self, subject_kind: RevocationSubject, subject_id: str
    ) -> RevocationRecord | None:
        rows = self._store.query(
            "SELECT revocation_id, subject_kind, subject_id, revoked_at, revoked_by, reason "
            "FROM identity_revocations WHERE subject_kind = ? AND subject_id = ?",
            (RevocationSubject(subject_kind).value, subject_id),
        )
        return _revocation_from_row(rows[0]) if rows else None

    def revocations(self) -> tuple[RevocationRecord, ...]:
        rows = self._store.query(
            "SELECT revocation_id, subject_kind, subject_id, revoked_at, revoked_by, reason "
            "FROM identity_revocations ORDER BY revoked_at, subject_id"
        )
        return tuple(_revocation_from_row(row) for row in rows)

    def expired_sessions(self, now: datetime) -> tuple[SessionRecord, ...]:
        """Sessions whose window closed at ``now``.

        A report, not a mutation — the same choice
        :meth:`mayhem.controller.approval_gate.ApprovalLedger.expire` makes. An
        expired session is already unusable because every read re-checks the
        window; the sweep exists so an operator can *see* what needs cleaning
        up rather than discovering it from a growing table.
        """
        rows = self._store.query(
            "SELECT session_id, principal_id, kind, auth_source, token_hash, issued_at, "
            "expires_at, revoked_at, revoked_by, revocation_reason, rotated_from, rotated_to, "
            "rotated_at FROM identity_sessions WHERE expires_at <= ? "
            "AND revoked_at IS NULL ORDER BY expires_at",
            (iso_utc(now),),
        )
        return tuple(_session_from_row(row) for row in rows)

    # -- the no-plaintext claim --------------------------------------------------

    def credential_material(self) -> Mapping[str, Mapping[str, tuple[str, ...]]]:
        """Every credential-bearing column value, by table and column.

        Exists so the "a credential is never readable back out of the store"
        property is a statement about the *schema* rather than about one
        writer's discipline: a test can assert a plaintext appears in none of
        these values, and a future column added to one of these tables shows up
        in the very object the assertion walks.
        """
        selectors: Mapping[str, tuple[str, ...]] = {
            "identity_local_credentials": ("salt_hex", "credential_hash"),
            "identity_sessions": ("token_hash", "session_id", "revocation_reason"),
            "identity_api_keys": ("secret_hash", "key_prefix", "revocation_reason"),
        }
        material: dict[str, dict[str, tuple[str, ...]]] = {}
        for table, columns in selectors.items():
            column_list = ", ".join(columns)
            material[table] = {
                column: tuple(
                    str(row[column])
                    for row in self._store.query(f"SELECT {column_list} FROM {table}")
                )
                for column in columns
            }
        return material


# =============================================================================
# Row reconstruction
# =============================================================================


def _principal_from_row(row: Any) -> Principal:
    return Principal(
        principal_id=str(row["principal_id"]),
        kind=PrincipalKind(str(row["kind"])),
        display_name=str(row["display_name"]),
        email=str(row["email"]),
        external_id=str(row["external_id"]),
        disabled=bool(row["disabled"]),
    )


def _session_from_row(row: Any) -> SessionRecord:
    revoked_at = row["revoked_at"]
    rotated_at = row["rotated_at"]
    return SessionRecord(
        session_id=str(row["session_id"]),
        principal_id=str(row["principal_id"]),
        kind=SessionKind(str(row["kind"])),
        auth_source=AuthSource(str(row["auth_source"])),
        token_hash=str(row["token_hash"]),
        issued_at=datetime.fromisoformat(str(row["issued_at"])),
        expires_at=datetime.fromisoformat(str(row["expires_at"])),
        revoked_at=None if revoked_at is None else datetime.fromisoformat(str(revoked_at)),
        revoked_by=str(row["revoked_by"]),
        revocation_reason=str(row["revocation_reason"]),
        rotated_from=str(row["rotated_from"]),
        rotated_to=str(row["rotated_to"]),
        rotated_at=None if rotated_at is None else datetime.fromisoformat(str(rotated_at)),
    )


def _api_key_from_row(row: Any) -> ApiKeyRecord:
    revoked_at = row["revoked_at"]
    last_used = row["last_used_at"]
    return ApiKeyRecord(
        api_key_id=str(row["api_key_id"]),
        principal_id=str(row["principal_id"]),
        key_prefix=str(row["key_prefix"]),
        secret_hash=str(row["secret_hash"]),
        scopes=tuple(
            EnvironmentScope.model_validate(entry) for entry in json.loads(str(row["scopes_json"]))
        ),
        issued_at=datetime.fromisoformat(str(row["issued_at"])),
        expires_at=datetime.fromisoformat(str(row["expires_at"])),
        revoked_at=None if revoked_at is None else datetime.fromisoformat(str(revoked_at)),
        revoked_by=str(row["revoked_by"]),
        revocation_reason=str(row["revocation_reason"]),
        last_used_at=None if last_used is None else datetime.fromisoformat(str(last_used)),
    )


def _revocation_from_row(row: Any) -> RevocationRecord:
    return RevocationRecord(
        revocation_id=str(row["revocation_id"]),
        subject_kind=RevocationSubject(str(row["subject_kind"])),
        subject_id=str(row["subject_id"]),
        revoked_at=datetime.fromisoformat(str(row["revoked_at"])),
        revoked_by=str(row["revoked_by"]),
        reason=str(row["reason"]),
    )


def _grant_payload(grant: RoleGrant) -> dict[str, Any]:
    """The grant exactly as the domain states it, for lossless round-trip.

    Serialized through the model's own JSON form rather than a hand-written
    field map, so a field added to :class:`~mayhem.domain.identity.RoleGrant`
    is stored by default instead of being silently dropped by a mapping that
    predates it.

    One field needs surgery: ``team_id`` carries an id pattern that rejects
    ``""`` whenever it is *stated*, and ``model_dump`` always states it — the
    empty string only survives on a freshly constructed grant because pydantic
    does not validate defaults. So a principal-addressed grant is stored with the
    key omitted rather than empty, which is what makes the round trip
    re-validatable. This is the one place where storage has to know something
    about the domain model's asymmetry, and it is written down here rather than
    discovered later as an unreadable grant row.
    """
    payload = grant.model_dump(mode="json")
    if grant.principal is not None:
        payload.pop("team_id", None)
    return payload


def _grant_id(grant: RoleGrant) -> str:
    payload = _grant_payload(grant)
    identifying = {
        key: payload.get(key) for key in ("role", "scope", "principal", "team_id", "granted_at")
    }
    return f"g-{digest(identifying)[:32]}"


def scope_from_json(raw: str) -> EnvironmentScope:
    """Rebuild a scope from its stored JSON. Kept next to the writer."""
    return EnvironmentScope.model_validate(json.loads(raw))


def scopes_to_json(scopes: Iterable[EnvironmentScope]) -> str:
    return json.dumps([scope.model_dump(mode="json") for scope in scopes])
