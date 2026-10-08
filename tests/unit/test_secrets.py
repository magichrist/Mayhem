"""Phase 1 secrets domain: grant validity, reference validation, classification.

``docs/v1.1.0/29_SECRETS_MANAGEMENT.md`` Phase 1 acceptance is "validation
tests pin every refusal with the offending field named", so the matrix below
is deliberately exhaustive over the grant dimensions — principal,
environment, scope, pattern, expiry — and every refusal asserts on the stable
code rather than on message text.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.secrets import (
    CLASSIFICATION_ORDER,
    DEFAULT_CLASSIFICATION,
    EVIDENCE_FIELD_CLASSIFICATIONS,
    REFUSAL_ENVIRONMENT_OUT_OF_SCOPE,
    REFUSAL_GRANT_EXPIRED,
    REFUSAL_LITERAL_SECRET,
    REFUSAL_NO_GRANT,
    REFUSAL_PATTERN_MISMATCH,
    REFUSAL_PRINCIPAL_MISMATCH,
    REFUSAL_SCOPE_NOT_GRANTED,
    REFUSAL_SECRET_FIELD_PERSISTED,
    CredentialRef,
    CredentialScope,
    DataClassification,
    FieldClassifications,
    ScopeKind,
    SecretGrant,
    SecretProvider,
    classification_rank,
    find_grant,
    find_literal_credentials,
    grant_refusals,
    has_literal_credential,
    is_credential_field_name,
    is_development_only,
    is_literal_credential,
    is_reference_value,
    most_restrictive,
    must_not_persist,
    reference_is_granted,
    require_no_literal_credentials,
    require_reference,
    validate_reference,
)

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
ALICE = "svc:alice"
BOB = "svc:bob"

#: Run scopes reused by the shape-validation cases below.
_RUN: dict[str, str] = {"kind": "run", "ref": "r"}
_EMPTY_RUN: dict[str, str] = {"kind": "run", "ref": ""}


def _ref(
    *,
    provider: SecretProvider = SecretProvider.VAULT,
    secret: str = "prod/database",
    purpose: str = "database chaos step needs credentials",
    kind: ScopeKind = ScopeKind.STEP,
    scope_ref: str = "step-1",
    version: str | None = None,
) -> CredentialRef:
    return CredentialRef(
        provider=provider,
        secret=secret,
        purpose=purpose,
        scope=CredentialScope(kind=kind, ref=scope_ref),
        version=version,
    )


def _grant(
    *,
    principal: str = ALICE,
    credential_pattern: str = "vault:prod/*",
    environments: tuple[str, ...] = ("prod",),
    expires_in: timedelta = timedelta(hours=1),
    scopes: tuple[str, ...] = (),
    issued_at: datetime | None = None,
) -> SecretGrant:
    return SecretGrant(
        principal=principal,
        credential_pattern=credential_pattern,
        environments=environments,
        expires_at=NOW + expires_in,
        scopes=scopes,
        issued_at=issued_at,
    )


class TestCredentialRefShape:
    def test_canonical_key_is_provider_and_path(self) -> None:
        assert _ref().canonical_key == "vault:prod/database"

    def test_canonical_key_excludes_version_pin(self) -> None:
        # A grant answers "may this principal resolve this secret"; rotating
        # the secret to a new version must not silently un-grant it.
        assert _ref(version="7").canonical_key == "vault:prod/database"

    def test_step_and_run_scope_tokens_are_distinct(self) -> None:
        assert _ref(kind=ScopeKind.STEP, scope_ref="step-1").scope_token == "step:step-1"
        assert _ref(kind=ScopeKind.RUN, scope_ref="run-9").scope_token == "run:run-9"

    def test_version_pin_is_optional(self) -> None:
        assert _ref().version is None

    @pytest.mark.parametrize(
        "field",
        [
            {"provider": "vault", "secret": "  ", "purpose": "p", "scope": _RUN},
            {"provider": "vault", "secret": "s", "purpose": "", "scope": _RUN},
            {"provider": "vault", "secret": "s", "purpose": "p", "scope": _EMPTY_RUN},
            {"provider": "vault", "secret": "s", "purpose": "p", "scope": _RUN, "version": " "},
        ],
    )
    def test_blank_required_fields_are_refused(self, field: dict[str, object]) -> None:
        with pytest.raises(ValueError):
            CredentialRef.model_validate(field)

    def test_unknown_provider_is_refused(self) -> None:
        with pytest.raises(ValueError):
            _ref(provider="keepass")  # type: ignore[arg-type]

    def test_extra_keys_are_refused(self) -> None:
        with pytest.raises(ValueError):
            CredentialRef.model_validate(
                {
                    "provider": "vault",
                    "secret": "prod/database",
                    "purpose": "p",
                    "scope": {"kind": "run", "ref": "r"},
                    "value": "hunter2",
                }
            )

    def test_models_are_frozen(self) -> None:
        ref = _ref()
        with pytest.raises(ValueError):
            ref.secret = "prod/other"  # type: ignore[misc]


class TestProviderVocabulary:
    def test_development_only_provider_is_marked(self) -> None:
        assert is_development_only(SecretProvider.ENVIRONMENT)
        assert is_development_only("environment")

    @pytest.mark.parametrize(
        "provider",
        [SecretProvider.VAULT, SecretProvider.OIDC, SecretProvider.KUBERNETES],
    )
    def test_real_providers_are_not_development_only(self, provider: SecretProvider) -> None:
        assert not is_development_only(provider)

    def test_reference_reports_its_own_development_marker(self) -> None:
        assert _ref(provider=SecretProvider.ENVIRONMENT).is_development_only()
        assert not _ref().is_development_only()


class TestGrantValidityMatrix:
    """Right/wrong principal, in/out of environment, live/expired grant."""

    def test_right_principal_in_scope_live_grant_is_authorized(self) -> None:
        ref = _ref()
        grant = _grant()
        assert grant_refusals(grant, ref, principal=ALICE, environment="prod", now=NOW) == ()
        assert reference_is_granted(ref, [grant], principal=ALICE, environment="prod", now=NOW)

    def test_wrong_principal_is_refused(self) -> None:
        refusals = grant_refusals(
            _grant(principal=ALICE),
            _ref(),
            principal=BOB,
            environment="prod",
            now=NOW,
        )
        assert REFUSAL_PRINCIPAL_MISMATCH in refusals
        assert not reference_is_granted(
            _ref(), [_grant(principal=ALICE)], principal=BOB, environment="prod", now=NOW
        )

    def test_environment_out_of_scope_is_refused(self) -> None:
        refusals = grant_refusals(
            _grant(environments=("prod",)),
            _ref(),
            principal=ALICE,
            environment="staging",
            now=NOW,
        )
        assert REFUSAL_ENVIRONMENT_OUT_OF_SCOPE in refusals

    def test_environment_glob_covers(self) -> None:
        grant = _grant(environments=("prod-*",))
        assert grant.covers_environment("prod-eu")
        assert not grant.covers_environment("staging")

    def test_expired_grant_is_refused(self) -> None:
        grant = _grant(expires_in=timedelta(seconds=-1))
        assert grant.is_expired(NOW)
        assert REFUSAL_GRANT_EXPIRED in grant_refusals(
            grant, _ref(), principal=ALICE, environment="prod", now=NOW
        )

    def test_grant_live_until_its_instant(self) -> None:
        grant = _grant(expires_in=timedelta(hours=1))
        assert not grant.is_expired(NOW + timedelta(minutes=59))
        assert grant.is_expired(NOW + timedelta(hours=1))

    def test_credential_pattern_mismatch_is_refused(self) -> None:
        refusals = grant_refusals(
            _grant(credential_pattern="vault:staging/*"),
            _ref(),
            principal=ALICE,
            environment="prod",
            now=NOW,
        )
        assert REFUSAL_PATTERN_MISMATCH in refusals

    def test_every_dimension_reports_at_once(self) -> None:
        refusals = grant_refusals(
            _grant(principal=ALICE, environments=("prod",), expires_in=timedelta(seconds=-1)),
            _ref(secret="other/database"),
            principal=BOB,
            environment="staging",
            now=NOW,
        )
        assert set(refusals) == {
            REFUSAL_PRINCIPAL_MISMATCH,
            REFUSAL_ENVIRONMENT_OUT_OF_SCOPE,
            REFUSAL_PATTERN_MISMATCH,
            REFUSAL_GRANT_EXPIRED,
        }

    def test_environment_scope_is_required(self) -> None:
        with pytest.raises(ValueError):
            SecretGrant(
                principal=ALICE,
                credential_pattern="vault:prod/*",
                environments=(),
                expires_at=NOW,
            )

    def test_expiry_is_required(self) -> None:
        # A grant with no deadline is a standing permission; the type refuses
        # to express one.
        with pytest.raises(ValueError):
            SecretGrant.model_validate(
                {
                    "principal": ALICE,
                    "credential_pattern": "vault:prod/*",
                    "environments": ["prod"],
                }
            )

    def test_naive_expiry_is_refused(self) -> None:
        with pytest.raises(ValueError):
            SecretGrant(
                principal=ALICE,
                credential_pattern="vault:prod/*",
                environments=("prod",),
                expires_at=datetime(2026, 9, 30, 13, 0),  # noqa: DTZ001
            )

    def test_grant_is_frozen(self) -> None:
        grant = _grant()
        with pytest.raises(ValueError):
            grant.principal = BOB  # type: ignore[misc]


class TestGrantScope:
    def test_empty_scopes_covers_every_scope_in_scope(self) -> None:
        grant = _grant(scopes=())
        assert grant.covers_scope("step:step-1")
        assert grant.covers_scope("run:run-9")

    def test_listed_scope_is_covered(self) -> None:
        grant = _grant(scopes=("step:step-1",))
        assert grant.covers_scope("step:step-1")
        assert not grant.covers_scope("step:step-2")

    def test_scope_glob_covers(self) -> None:
        grant = _grant(scopes=("step:*",))
        assert grant.covers_scope("step:step-2")
        assert not grant.covers_scope("run:run-2")

    def test_scope_mismatch_is_refused(self) -> None:
        refusals = grant_refusals(
            _grant(scopes=("step:step-1",)),
            _ref(scope_ref="step-2"),
            principal=ALICE,
            environment="prod",
            now=NOW,
        )
        assert REFUSAL_SCOPE_NOT_GRANTED in refusals


class TestReferenceValidation:
    def test_reference_without_a_grant_is_invalid(self) -> None:
        ref = _ref()
        assert not reference_is_granted(ref, [], principal=ALICE, environment="prod", now=NOW)
        assert validate_reference(ref, [], principal=ALICE, environment="prod", now=NOW) == (
            REFUSAL_NO_GRANT,
        )

    def test_naming_a_credential_is_not_permission(self) -> None:
        assert find_grant(_ref(), [], principal=ALICE, environment="prod", now=NOW) is None

    def test_validation_returns_empty_when_authorized(self) -> None:
        ref = _ref()
        grant = _grant()
        assert validate_reference(ref, [grant], principal=ALICE, environment="prod", now=NOW) == ()

    def test_validation_reports_the_closest_grants_reason(self) -> None:
        # Right secret, right principal, wrong environment: the refusal must
        # say so rather than a bare "no grant".
        refusals = validate_reference(
            _ref(),
            [_grant(environments=("staging",))],
            principal=ALICE,
            environment="prod",
            now=NOW,
        )
        assert refusals == (REFUSAL_ENVIRONMENT_OUT_OF_SCOPE,)

    def test_require_reference_returns_the_authorizing_grant(self) -> None:
        grant = _grant()
        found = require_reference(_ref(), [grant], principal=ALICE, environment="prod", now=NOW)
        assert found is grant

    def test_require_reference_names_the_offending_field(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            require_reference(
                _ref(),
                [],
                principal=ALICE,
                environment="prod",
                now=NOW,
                field="steps[2].credentialRef",
            )
        message = str(excinfo.value)
        assert "steps[2].credentialRef" in message
        assert "vault:prod/database" in message
        assert "step:step-1" in message
        assert excinfo.value.rule == REFUSAL_NO_GRANT

    def test_cross_step_reuse_without_a_separate_grant_is_refused(self) -> None:
        # Negative control: step-2 asking for a step-1-scoped credential.
        grant = _grant(scopes=("step:step-1",))
        reuse = _ref(scope_ref="step-2")
        assert not reference_is_granted(
            reuse, [grant], principal=ALICE, environment="prod", now=NOW
        )
        assert REFUSAL_SCOPE_NOT_GRANTED in validate_reference(
            reuse, [grant], principal=ALICE, environment="prod", now=NOW
        )

    def test_a_separate_grant_does_allow_cross_step_use(self) -> None:
        grants = [_grant(scopes=("step:step-1",)), _grant(scopes=("step:step-2",))]
        assert reference_is_granted(
            _ref(scope_ref="step-2"), grants, principal=ALICE, environment="prod", now=NOW
        )

    def test_run_scoped_reference_needs_a_run_scoped_grant(self) -> None:
        ref = _ref(kind=ScopeKind.RUN, scope_ref="run-9")
        assert not reference_is_granted(
            ref, [_grant(scopes=("step:*",))], principal=ALICE, environment="prod", now=NOW
        )
        assert reference_is_granted(
            ref, [_grant(scopes=("run:run-9",))], principal=ALICE, environment="prod", now=NOW
        )

    def test_grant_consultation_order_is_the_callers(self) -> None:
        first = _grant(principal=BOB)
        second = _grant(principal=ALICE)
        assert (
            find_grant(_ref(), [first, second], principal=ALICE, environment="prod", now=NOW)
            is second
        )


class TestLiteralCredentialDetection:
    @pytest.mark.parametrize(
        "name",
        [
            "password",
            "passwd",
            "token",
            "api_key",
            "apiKey",
            "secret",
            "registry_token",
            "dbPassword",
        ],
    )
    def test_credential_named_keys_are_recognised(self, name: str) -> None:
        assert is_credential_field_name(name)

    @pytest.mark.parametrize("name", ["provider", "secret_path", "purpose", "verdict"])
    def test_ordinary_keys_are_not_credential_named(self, name: str) -> None:
        # ``secret_path`` names a path, never a value; over-broad matching on
        # it would flag every well-formed reference.
        assert not is_credential_field_name(name)

    def test_literal_password_value_is_flagged(self) -> None:
        assert is_literal_credential("password", "hunter2")
        assert has_literal_credential({"password": "hunter2"})

    def test_reference_value_is_not_a_literal(self) -> None:
        assert not is_literal_credential(
            "credentialRef", {"provider": "vault", "secret": "prod/database"}
        )

    def test_reference_shapes_are_recognised(self) -> None:
        assert is_reference_value(_ref())
        assert is_reference_value({"provider": "vault", "secret": "prod/db"})
        assert is_reference_value("secret://vault/prod/db")
        assert not is_reference_value({"provider": "vault"})

    def test_absent_or_empty_values_are_not_literals(self) -> None:
        assert not is_literal_credential("password", None)
        assert not is_literal_credential("password", "")
        assert not is_literal_credential("password", "   ")
        assert not is_literal_credential("password", {})

    def test_walk_finds_nested_literals_with_paths(self) -> None:
        document = {
            "kind": "drill",
            "steps": [
                {"id": "s1", "credentialRef": {"provider": "vault", "secret": "prod/db"}},
                {"id": "s2", "token": "abc123"},
            ],
        }
        assert find_literal_credentials(document) == ("$.steps[1].token",)

    def test_a_well_formed_reference_document_is_clean(self) -> None:
        document = {
            "kind": "drill",
            "steps": [{"id": "s1", "credentialRef": {"provider": "vault", "secret": "prod/db"}}],
        }
        assert find_literal_credentials(document) == ()
        assert not has_literal_credential(document)

    def test_walk_descends_into_mappings_and_lists(self) -> None:
        document = {"a": [{"b": {"password": "p", "c": [{"api_key": "k"}]}}]}
        assert find_literal_credentials(document) == ("$.a[0].b.password", "$.a[0].b.c[0].api_key")

    def test_typed_reference_object_inside_a_document_is_clean(self) -> None:
        assert find_literal_credentials({"credentialRef": _ref()}) == ()

    def test_require_no_literal_credentials_names_every_field(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            require_no_literal_credentials({"password": "p", "steps": [{"token": "t"}]})
        message = str(excinfo.value)
        assert excinfo.value.rule == REFUSAL_LITERAL_SECRET
        assert "$.password" in message
        assert "$.steps[0].token" in message

    def test_require_no_literal_credentials_passes_a_clean_document(self) -> None:
        require_no_literal_credentials(
            {"credentialRef": {"provider": "vault", "secret": "prod/db"}}
        )


class TestDataClassification:
    def test_grades_are_the_documented_four(self) -> None:
        assert {grade.value for grade in DataClassification} == {
            "secret",
            "sensitive",
            "internal",
            "public",
        }

    def test_order_is_ascending_restrictiveness(self) -> None:
        assert CLASSIFICATION_ORDER == (
            DataClassification.PUBLIC,
            DataClassification.INTERNAL,
            DataClassification.SENSITIVE,
            DataClassification.SECRET,
        )

    def test_rank_is_monotonic(self) -> None:
        ranks = [classification_rank(grade) for grade in CLASSIFICATION_ORDER]
        assert ranks == sorted(ranks)
        assert classification_rank(DataClassification.PUBLIC) < classification_rank(
            DataClassification.SECRET
        )

    def test_most_restrictive_picks_the_tightest_grade(self) -> None:
        assert (
            most_restrictive(
                [DataClassification.PUBLIC, DataClassification.SECRET, DataClassification.INTERNAL]
            )
            is DataClassification.SECRET
        )

    def test_most_restrictive_of_nothing_is_nothing(self) -> None:
        assert most_restrictive([]) is None

    def test_only_secret_must_never_persist(self) -> None:
        assert must_not_persist(DataClassification.SECRET)
        for grade in (
            DataClassification.SENSITIVE,
            DataClassification.INTERNAL,
            DataClassification.PUBLIC,
        ):
            assert not must_not_persist(grade)


class TestFieldClassifications:
    def test_ungraded_field_gets_the_fail_closed_default(self) -> None:
        assert FieldClassifications().classification_for("anything") == DEFAULT_CLASSIFICATION
        assert DEFAULT_CLASSIFICATION is DataClassification.SENSITIVE

    def test_declared_grade_wins(self) -> None:
        grades = FieldClassifications(fields={"verdict": DataClassification.PUBLIC})
        assert grades.classification_for("verdict") is DataClassification.PUBLIC

    def test_highest_reports_the_tightest_declared_grade(self) -> None:
        grades = FieldClassifications(
            fields={
                "verdict": DataClassification.INTERNAL,
                "observations": DataClassification.SENSITIVE,
            }
        )
        assert grades.highest() is DataClassification.SENSITIVE

    def test_forbidden_fields_lists_only_secret(self) -> None:
        grades = FieldClassifications(
            fields={
                "verdict": DataClassification.INTERNAL,
                "resolved_credentials": DataClassification.SECRET,
                "secret_value": DataClassification.SECRET,
            }
        )
        assert grades.forbidden_fields() == ("resolved_credentials", "secret_value")

    def test_find_forbidden_walks_nested_paths(self) -> None:
        grades = FieldClassifications(fields={"credential_value": DataClassification.SECRET})
        document = {"steps": [{"ok": 1}, {"credential_value": "x"}]}
        assert grades.find_forbidden(document) == ("$.steps[1].credential_value",)

    def test_find_forbidden_descends_into_graded_free_subtrees(self) -> None:
        document = {"observations": [{"resolved_credentials": "s3cr3t"}]}
        assert EVIDENCE_FIELD_CLASSIFICATIONS.find_forbidden(document) == (
            "$.observations[0].resolved_credentials",
        )

    def test_require_persistable_names_every_forbidden_field(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            EVIDENCE_FIELD_CLASSIFICATIONS.require_persistable(
                {"verdict": "ok", "resolved_credentials": {"db": "x"}}
            )
        message = str(excinfo.value)
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        assert "$.resolved_credentials" in message
        assert "$.verdict" not in message

    def test_require_persistable_passes_a_clean_envelope(self) -> None:
        EVIDENCE_FIELD_CLASSIFICATIONS.require_persistable(
            {"run_id": "r1", "verdict": "ok", "observations": [{"name": "latency"}]}
        )

    def test_evidence_grades_sensitive_fields_and_defaults_the_rest(self) -> None:
        grades = EVIDENCE_FIELD_CLASSIFICATIONS
        assert grades.classification_for("run_id") is DataClassification.INTERNAL
        assert grades.classification_for("observations") is DataClassification.SENSITIVE
        assert grades.classification_for("credential_values") is DataClassification.SECRET
        # Ungraded evidence fields default to sensitive, not public.
        assert grades.classification_for("some_new_field") is DataClassification.SENSITIVE
