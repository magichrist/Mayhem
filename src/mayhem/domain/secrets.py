"""Secrets domain: references, grants, and data classification.

v1.1.0 plan 29 Phase 1 (``docs/v1.1.0/29_SECRETS_MANAGEMENT.md``). This
module is the *type* half of secrets management, nothing else: a chaos
experiment needs credentials, and the way it gets them is by naming a
credential late — under policy, at execution time, inside the narrowest
scope that needs the value — never by writing the value into a spec, a plan,
a log, or an evidence bundle.

Three concepts live here, all pure and all free of IO:

* :class:`CredentialRef` — *where* a secret is (provider + path + optional
  version pin) and *what it is for* (a purpose string bound to either the run
  scope or one step's scope). A reference carries no value; that is the whole
  point of the type.
* :class:`SecretGrant` — *who* may resolve *which* reference pattern, in
  *which* environments, under *which* scope, until *when*. A reference with no
  matching grant is invalid, and that is stated once, here, as a pure
  predicate rather than at three call sites.
* :class:`DataClassification` plus :class:`FieldClassifications` — how an
  evidence field is graded, so "secrets never enter evidence" becomes a rule
  over declared grades rather than a hope about redaction.

Phase 2 (the engine) builds on these types; it does not change them. The
domain layer rule (``[tool.importlinter]`` contract "Domain layer has zero IO
and no upward imports") holds: no provider SDK, no environment reads, no
ambient environment variables. Resolution happens elsewhere and under these
rules.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from itertools import pairwise

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.policy import _SECRET_KEYS

# --- Stable refusal codes -----------------------------------------------------
# Part of the domain's contract with the surfaces that surface these refusals.
# Names, not messages, are what callers branch on.

#: No grant in the set authorizes this reference for this principal/scope.
REFUSAL_NO_GRANT = "secret.reference_without_grant"
#: A matching grant exists but its own expiry has passed.
REFUSAL_GRANT_EXPIRED = "secret.grant_expired"
#: The grant belongs to a different principal.
REFUSAL_PRINCIPAL_MISMATCH = "secret.grant_principal_mismatch"
#: The grant does not cover this environment.
REFUSAL_ENVIRONMENT_OUT_OF_SCOPE = "secret.grant_environment_out_of_scope"
#: The grant does not cover the reference's scope token (e.g. a step-scoped
#: credential reaching a step it was never granted for).
REFUSAL_SCOPE_NOT_GRANTED = "secret.grant_scope_not_granted"
#: The grant's credential pattern does not match the reference.
REFUSAL_PATTERN_MISMATCH = "secret.grant_pattern_mismatch"
#: A literal credential value was found where a reference is required.
REFUSAL_LITERAL_SECRET = "secret.literal_where_reference_required"
#: An evidence field graded ``secret`` would be persisted.
REFUSAL_SECRET_FIELD_PERSISTED = "secret.secret_classified_field_present"


# --- Providers ----------------------------------------------------------------


class SecretProvider(StrEnum):
    """Where a :class:`CredentialRef` points.

    The plan's provider list, as a closed vocabulary. A provider this build
    cannot honor is a validation error at authoring time, not a runtime
    surprise during a fault injection.
    """

    VAULT = "vault"
    AWS_SECRETS_MANAGER = "aws_secrets_manager"
    GCP_SECRET_MANAGER = "gcp_secret_manager"
    AZURE_KEY_VAULT = "azure_key_vault"
    KUBERNETES = "kubernetes"
    OIDC = "oidc"
    #: Development-only: scoped environment injection, never a production path.
    ENVIRONMENT = "environment"


#: Providers that only exist to make local development possible. The plan asks
#: for a loud marker wherever they appear; Phase 1 states the marker (this set,
#: and :func:`is_development_only`), Phase 3 wires it into authoring.
DEVELOPMENT_ONLY_PROVIDERS: frozenset[SecretProvider] = frozenset(
    {SecretProvider.ENVIRONMENT}
)


def is_development_only(provider: SecretProvider | str) -> bool:
    """True for providers that are development-only and must be marked loudly."""
    try:
        resolved = SecretProvider(provider)
    except ValueError:
        return False
    return resolved in DEVELOPMENT_ONLY_PROVIDERS


# --- Scopes -------------------------------------------------------------------

#: Prefix of the opaque token a grant lists in ``scopes``. Also what
#: :attr:`CredentialScope.token` produces, so the two compare directly.
SCOPE_TOKEN_SEPARATOR = ":"


class ScopeKind(StrEnum):
    """How wide a credential's purpose binding is.

    ``RUN`` binds a credential to the whole run; ``STEP`` binds it to one
    step. A step-scoped credential is the narrower grant and the default
    expectation (plan 29 Phase 2: "a credential resolved for step N is
    unavailable to step N+1 unless separately granted").
    """

    RUN = "run"
    STEP = "step"


class CredentialScope(BaseModel):
    """The scope a credential's purpose is bound to.

    Attributes:
        kind: ``run`` or ``step``.
        ref: The run id or the step id, depending on ``kind``. Never a name
            a user can retype into a different scope; it is the identity the
            grant compares against.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ScopeKind
    ref: str = Field(min_length=1)

    @field_validator("ref")
    @classmethod
    def _reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("scope ref must be non-empty")
        return value

    @property
    def token(self) -> str:
        """The opaque string a grant lists in :attr:`SecretGrant.scopes`."""
        return f"{self.kind.value}{SCOPE_TOKEN_SEPARATOR}{self.ref}"


# --- Credential references ----------------------------------------------------


class CredentialRef(BaseModel):
    """A late-bound reference to one secret. Carries no secret value.

    Attributes:
        provider: Which provider holds the secret.
        secret: The provider-specific path (``prod/database``,
            ``projects/p/secrets/db``), not a value.
        version: Optional version pin. When present, resolution asks for this
            exact version so a run is reproducible against a rotated secret.
        purpose: Why this credential is needed, in the author's words. Part of
            the binding, not documentation: it is what a reviewer reads when
            asking "why does this step hold this credential?".
        scope: The run or step this purpose is bound to.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: SecretProvider
    secret: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    scope: CredentialScope
    version: str | None = None

    @field_validator("secret", "purpose", "version")
    @classmethod
    def _reject_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("must be non-empty when provided")
        return value

    @property
    def canonical_key(self) -> str:
        """``provider:path`` — what :attr:`SecretGrant.credential_pattern` matches.

        The version pin is deliberately *not* part of the key: a grant answers
        "may this principal resolve this secret", which does not change when
        the secret rotates to a new version.
        """
        return f"{self.provider.value}{SCOPE_TOKEN_SEPARATOR}{self.secret}"

    @property
    def scope_token(self) -> str:
        """Shortcut for ``self.scope.token`` — the scope a grant must cover."""
        return self.scope.token

    def is_development_only(self) -> bool:
        """True when this reference points at a development-only provider."""
        return is_development_only(self.provider)


# --- Grants -------------------------------------------------------------------


class SecretGrant(BaseModel):
    """Permission for one principal to resolve a credential pattern, bounded.

    A grant is a whole, self-contained permission. It says *who*, *what
    shape of secret*, *where*, *how wide*, and *until when* — and a reference
    that no grant answers for is invalid, not merely undocumented.

    Attributes:
        principal: The identity the permission is issued to.
        credential_pattern: A glob over :attr:`CredentialRef.canonical_key`,
            e.g. ``vault:prod/*``. Narrow patterns are better; a bare ``*``
            is legal but grants the whole provider namespace.
        environments: Environment names covered, as globs so ``prod-*`` works.
            Required and non-empty: an unbounded environment scope is a grant
            with no boundary, so the type refuses to express one.
        scopes: Scope tokens covered (``step:inject-db``, ``run:r-1``), also
            globs. Empty means "any scope within the covered environments" —
            the one deliberate convenience in this type, and the one worth
            noticing in review.
        expires_at: When the grant lapses. Required: a grant with no deadline
            is a standing permission, and this model does not mint those.
        issued_at: When the grant was issued, for evidence and rotation
            bookkeeping. Values, never, are what evidence carries.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    principal: str = Field(min_length=1)
    credential_pattern: str = Field(min_length=1)
    environments: tuple[str, ...] = Field(min_length=1)
    expires_at: datetime
    scopes: tuple[str, ...] = ()
    issued_at: datetime | None = None

    @field_validator("principal", "credential_pattern")
    @classmethod
    def _reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must be non-empty")
        return value

    @field_validator("environments", "scopes")
    @classmethod
    def _reject_blank_entries(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not entry.strip() for entry in value):
            raise ValueError("entries must be non-empty")
        return value

    @field_validator("expires_at")
    @classmethod
    def _reject_naive(cls, value: datetime) -> datetime:
        # DTZ discipline (ruff DTZ): a naive deadline compares against nothing
        # and reads as "already expired" on some hosts and "never" on others.
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return value

    def is_expired(self, now: datetime | None = None) -> bool:
        """True once the grant's own deadline has passed."""
        return self.expires_at <= (utc_now() if now is None else now)

    def covers_principal(self, principal: str) -> bool:
        """True when the grant was issued to this exact principal."""
        return self.principal == principal

    def covers_environment(self, environment: str) -> bool:
        """True when any covered environment glob matches ``environment``."""
        return any(fnmatchcase(environment, pattern) for pattern in self.environments)

    def covers_scope(self, scope_token: str) -> bool:
        """True when the grant covers this scope token.

        An empty :attr:`scopes` covers every scope inside the grant's
        environments. Otherwise a glob must match the token.
        """
        if not self.scopes:
            return True
        return any(fnmatchcase(scope_token, pattern) for pattern in self.scopes)

    def covers_reference(self, reference: CredentialRef) -> bool:
        """True when the grant's pattern matches this reference's key."""
        return fnmatchcase(reference.canonical_key, self.credential_pattern)

    def is_live(self, now: datetime | None = None) -> bool:
        """True when the grant has not lapsed."""
        return not self.is_expired(now)


# --- Grant validation predicates ----------------------------------------------


def grant_refusals(
    grant: SecretGrant,
    reference: CredentialRef,
    *,
    principal: str,
    environment: str,
    now: datetime | None = None,
) -> tuple[str, ...]:
    """Reasons *this* grant cannot authorize *this* reference, as codes.

    Every failing dimension is reported, not just the first, so an operator
    asking "why was this refused?" gets the whole answer. An empty tuple
    means this grant authorizes the reference. Whether *any* grant does is
    :func:`reference_is_granted`'s question.
    """
    refusals: list[str] = []
    if not grant.covers_principal(principal):
        refusals.append(REFUSAL_PRINCIPAL_MISMATCH)
    if not grant.covers_environment(environment):
        refusals.append(REFUSAL_ENVIRONMENT_OUT_OF_SCOPE)
    if not grant.covers_reference(reference):
        refusals.append(REFUSAL_PATTERN_MISMATCH)
    if not grant.covers_scope(reference.scope_token):
        refusals.append(REFUSAL_SCOPE_NOT_GRANTED)
    if grant.is_expired(now):
        refusals.append(REFUSAL_GRANT_EXPIRED)
    return tuple(refusals)


def find_grant(
    reference: CredentialRef,
    grants: Iterable[SecretGrant],
    *,
    principal: str,
    environment: str,
    now: datetime | None = None,
) -> SecretGrant | None:
    """The first grant that authorizes ``reference``, or ``None``.

    Deterministic: grants are consulted in the order given, and the caller
    owns that order. The domain never sorts a caller's permission set.
    """
    for grant in grants:
        if not grant_refusals(
            grant, reference, principal=principal, environment=environment, now=now
        ):
            return grant
    return None


def reference_is_granted(
    reference: CredentialRef,
    grants: Iterable[SecretGrant],
    *,
    principal: str,
    environment: str,
    now: datetime | None = None,
) -> bool:
    """True when some grant authorizes this reference. A bare reference is invalid.

    The single rule the whole grant model exists to express: naming a
    credential is not permission to resolve it.
    """
    return (
        find_grant(
            reference, grants, principal=principal, environment=environment, now=now
        )
        is not None
    )


def validate_reference(
    reference: CredentialRef,
    grants: Iterable[SecretGrant],
    *,
    principal: str,
    environment: str,
    now: datetime | None = None,
    field: str = "credentialRef",
) -> tuple[str, ...]:
    """Refusal codes for an ungranted reference; empty means authorized.

    When nothing authorizes the reference, the reported codes come from the
    *closest* grant — the one that matched the most dimensions — so the
    refusal says "right secret, wrong environment" instead of a bare "no
    grant", which would send an operator hunting for the wrong thing.
    """
    grant_list = tuple(grants)
    if find_grant(
        reference, grant_list, principal=principal, environment=environment, now=now
    ):
        return ()
    best: tuple[str, ...] = ()
    for grant in grant_list:
        refusals = grant_refusals(
            grant, reference, principal=principal, environment=environment, now=now
        )
        if len(refusals) < len(best) or not best:
            best = refusals
    if not best:
        return (REFUSAL_NO_GRANT,)
    return best


def require_reference(
    reference: CredentialRef,
    grants: Iterable[SecretGrant],
    *,
    principal: str,
    environment: str,
    now: datetime | None = None,
    field: str = "credentialRef",
) -> SecretGrant:
    """The grant that authorizes ``reference``, or raise with the field named.

    Raises:
        InvariantViolationError: With the most specific refusal code available
            and ``field`` in the message, because the acceptance criterion is
            that every refusal names the offending field.
    """
    grant_list = tuple(grants)
    grant = find_grant(
        reference, grant_list, principal=principal, environment=environment, now=now
    )
    if grant is not None:
        return grant
    codes = validate_reference(
        reference,
        grant_list,
        principal=principal,
        environment=environment,
        now=now,
        field=field,
    )
    raise InvariantViolationError(
        codes[0],
        f"{field}: credential reference {reference.canonical_key!r} "
        f"(purpose {reference.purpose!r}, scope {reference.scope_token!r}) is not "
        f"granted to principal {principal!r} in environment {environment!r} "
        f"[{', '.join(codes)}]",
    )


# --- Literal-credential detection ---------------------------------------------


#: Keys under which a *reference* is authored (plan 29 reference shape).
REFERENCE_SHAPED_KEYS: frozenset[str] = frozenset(
    {"credentialref", "credential_ref", "credentials"}
)

#: The keys of a reference-shaped mapping.
_REFERENCE_MAP_KEYS: frozenset[str] = frozenset({"provider", "secret"})

#: Suffixes that mark a key as *naming* a credential rather than carrying
#: one — a pointer, not a value. ``secret_path``, ``credential_ref``,
#: ``api_key_name``: flagging those would make the vocabulary unusable,
#: because the plan's own reference shape is a credential named by its path.
_CREDENTIAL_POINTER_SUFFIXES: tuple[str, ...] = (
    "_path",
    "_ref",
    "_reference",
    "_name",
    "_id",
    "_file",
    "_uri",
    "_url",
    "_location",
    "_pattern",
    "_kind",
    "_type",
)

#: Whole-word fragments that make a key credential-bearing, matched per token
#: (see :func:`_name_tokens`) rather than as a bare substring so
#: ``secret_path`` is not a ``secret`` and ``tokenize`` is not a ``token``.
_CREDENTIAL_TOKENS: frozenset[str] = frozenset(
    {
        "apikey",
        "credential",
        "credentials",
        "kubeconfig",
        "passphrase",
        "passwd",
        "password",
        "secret",
        "secrets",
        "token",
        "tokens",
    }
)

#: Two adjacent tokens that together name a credential.
_CREDENTIAL_TOKEN_PAIRS: frozenset[tuple[str, str]] = frozenset(
    {
        ("access", "key"),
        ("api", "key"),
        ("private", "key"),
        ("secret", "key"),
    }
)

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NAME_SEPARATORS = re.compile(r"[^a-z0-9]+")


def _name_tokens(name: str) -> tuple[str, ...]:
    """Split a field name into lowercase tokens across camelCase and separators.

    ``dbPassword`` -> ``("db", "password")``; ``registry_token`` ->
    ``("registry", "token")``; ``apiKey`` -> ``("api", "key")``.
    """
    spaced = _CAMEL_BOUNDARY.sub("_", name).lower()
    return tuple(token for token in _NAME_SEPARATORS.split(spaced) if token)


def is_credential_field_name(name: str) -> bool:
    """True when a mapping key looks like it carries a credential *value*.

    Shares :data:`mayhem.domain.policy._SECRET_KEYS` with the redaction
    boundary so "looks like a credential" means the same thing in both
    places, then widens to token- and pair-level matches (``dbPassword``,
    ``registry_token``, ``api_key``).

    Pointer-shaped keys (``secret_path``, ``credential_ref``) are excluded on
    purpose: they name where a credential lives, and a rule that flagged
    them would flag every well-formed reference in the plan's own shape.
    """
    lowered = name.lower()
    if lowered.endswith(_CREDENTIAL_POINTER_SUFFIXES):
        return False
    if lowered in _SECRET_KEYS:
        return True
    tokens = _name_tokens(name)
    if any(token in _CREDENTIAL_TOKENS for token in tokens):
        return True
    return any(pair in _CREDENTIAL_TOKEN_PAIRS for pair in pairwise(tokens))


def is_reference_value(value: object) -> bool:
    """True when a value is a reference rather than a credential.

    Three accepted shapes: a :class:`CredentialRef`, a mapping carrying both
    ``provider`` and ``secret`` (the plan's YAML shape), or a
    ``secret://provider/path`` string.
    """
    if isinstance(value, CredentialRef):
        return True
    if isinstance(value, Mapping):
        return {str(key).lower() for key in value} >= _REFERENCE_MAP_KEYS
    if isinstance(value, str):
        return value.startswith("secret://")
    return False


def is_literal_credential(field: str, value: object) -> bool:
    """True when ``field`` is credential-named and ``value`` is a literal.

    A literal is any present, non-empty value that is not a reference. The
    check is deliberately blind to *which* value it is: a short placeholder
    and a real password are refused the same way, because the domain cannot
    tell a placeholder from a leak.
    """
    if not is_credential_field_name(field):
        return False
    if is_reference_value(value):
        return False
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return not (isinstance(value, (Mapping, list, tuple, set)) and not value)


def find_literal_credentials(document: object, *, path: str = "$") -> tuple[str, ...]:
    """Paths of every literal credential in ``document``, depth-first.

    Reference-shaped mappings are terminal: their ``secret`` key names a
    *path*, not a value, and descending into one would flag every well-formed
    reference as a literal. That skip is the reason this walk cannot simply
    delegate to :func:`mayhem.domain.redaction.redact`.
    """
    found: list[str] = []
    if isinstance(document, Mapping):
        for key, value in document.items():
            name = str(key)
            child = f"{path}.{name}"
            if is_reference_value(value):
                continue
            if is_literal_credential(name, value):
                found.append(child)
                continue
            found.extend(find_literal_credentials(value, path=child))
        return tuple(found)
    if isinstance(document, (list, tuple)):
        for index, item in enumerate(document):
            found.extend(find_literal_credentials(item, path=f"{path}[{index}]"))
    return tuple(found)


def has_literal_credential(document: object, *, path: str = "$") -> bool:
    """True when ``document`` carries any literal credential."""
    return bool(find_literal_credentials(document, path=path))


def require_no_literal_credentials(document: object, *, path: str = "$") -> None:
    """Raise when ``document`` carries a literal credential, naming each field.

    Raises:
        InvariantViolationError: With :data:`REFUSAL_LITERAL_SECRET` and every
            offending path in the message.
    """
    found = find_literal_credentials(document, path=path)
    if not found:
        return
    raise InvariantViolationError(
        REFUSAL_LITERAL_SECRET,
        f"{path}: literal credential value(s) where a reference is required: "
        f"{', '.join(found)}; author a credentialRef instead",
    )


# --- Data classification ------------------------------------------------------


class DataClassification(StrEnum):
    """How sensitive a field is. Ordered from least to most restricted.

    ``SECRET`` fields are the ones secrets management governs end to end:
    they must never be persisted into an artifact, a store row, a report, or
    a log line. ``SENSITIVE`` may be persisted only under a policy that says
    so. ``INTERNAL`` is the default grade for operational detail, and
    ``PUBLIC`` is what may be published as-is.
    """

    SECRET = "secret"
    SENSITIVE = "sensitive"
    INTERNAL = "internal"
    PUBLIC = "public"


#: Ascending restrictiveness. Index in this tuple *is* the rank.
CLASSIFICATION_ORDER: tuple[DataClassification, ...] = (
    DataClassification.PUBLIC,
    DataClassification.INTERNAL,
    DataClassification.SENSITIVE,
    DataClassification.SECRET,
)


def classification_rank(classification: DataClassification | str) -> int:
    """Position in :data:`CLASSIFICATION_ORDER`; higher means more restricted."""
    return CLASSIFICATION_ORDER.index(DataClassification(classification))


def most_restrictive(
    classifications: Iterable[DataClassification | str],
) -> DataClassification | None:
    """The most restricted grade in ``classifications``, or ``None`` if empty."""
    resolved = [DataClassification(item) for item in classifications]
    if not resolved:
        return None
    return max(resolved, key=classification_rank)


def must_not_persist(classification: DataClassification | str) -> bool:
    """True when a field of this grade may never be written to an artifact.

    Only ``secret`` is absolute. ``sensitive`` is a policy question, and
    answering it here would put a policy decision inside a value type.
    """
    return DataClassification(classification) is DataClassification.SECRET


class FieldClassifications(BaseModel):
    """A field-name -> grade map for one artifact surface.

    The point is declaration, not inference: an evidence field that nobody
    graded cannot be caught by a rule that only reads grades, so an ungraded
    field grades as :attr:`DEFAULT_CLASSIFICATION` and therefore still needs a
    decision.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fields: dict[str, DataClassification] = Field(default_factory=dict)

    def classification_for(self, field: str) -> DataClassification:
        """The declared grade for ``field``, else the default grade."""
        return self.fields.get(field, DEFAULT_CLASSIFICATION)

    def must_not_persist(self, field: str) -> bool:
        """True when ``field`` is graded ``secret``."""
        return must_not_persist(self.classification_for(field))

    def highest(self) -> DataClassification | None:
        """The most restricted grade declared here, or ``None`` when empty."""
        return most_restrictive(self.fields.values())

    def forbidden_fields(self) -> tuple[str, ...]:
        """Names of the fields that may never be persisted, sorted."""
        return tuple(
            sorted(name for name, grade in self.fields.items() if must_not_persist(grade))
        )

    def find_forbidden(self, document: object, *, path: str = "$") -> tuple[str, ...]:
        """Paths in ``document`` whose field name is graded ``secret``.

        Name-based, on purpose: it is the same signal the redaction boundary
        uses, so the two agree on which fields are credential-bearing instead
        of disagreeing at the envelope.
        """
        found: list[str] = []
        if isinstance(document, Mapping):
            for key, value in document.items():
                name = str(key)
                child = f"{path}.{name}"
                if self.must_not_persist(name):
                    found.append(child)
                    continue
                found.extend(self.find_forbidden(value, path=child))
            return tuple(found)
        if isinstance(document, (list, tuple)):
            for index, item in enumerate(document):
                found.extend(self.find_forbidden(item, path=f"{path}[{index}]"))
        return tuple(found)

    def require_persistable(self, document: object, *, path: str = "$") -> None:
        """Raise when ``document`` contains a field graded ``secret``.

        Raises:
            InvariantViolationError: With :data:`REFUSAL_SECRET_FIELD_PERSISTED`
                and every offending path named.
        """
        found = self.find_forbidden(document, path=path)
        if not found:
            return
        raise InvariantViolationError(
            REFUSAL_SECRET_FIELD_PERSISTED,
            f"{path}: field(s) graded 'secret' must never be persisted: "
            f"{', '.join(found)}",
        )


#: The grade an ungraded field gets. ``sensitive`` rather than ``internal``:
#: an artifact field nobody thought about is treated as more private than one
#: somebody did think about.
DEFAULT_CLASSIFICATION = DataClassification.SENSITIVE

#: Grading for the evidence surface (``mayhem.domain.evidence``). Baseline, not
#: a complete inventory — Phase 4 extends it as the envelope grows, and
#: anything absent grades as :data:`DEFAULT_CLASSIFICATION`.
EVIDENCE_FIELD_CLASSIFICATIONS = FieldClassifications(
    fields={
        "run_id": DataClassification.INTERNAL,
        "plan_hash": DataClassification.INTERNAL,
        "verdict": DataClassification.INTERNAL,
        "step_reports": DataClassification.SENSITIVE,
        "observations": DataClassification.SENSITIVE,
        "credential_values": DataClassification.SECRET,
        "resolved_credentials": DataClassification.SECRET,
        "secret_value": DataClassification.SECRET,
    }
)
