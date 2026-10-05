"""``credentialRef:`` in a drill spec — the syntax Phase 3 kept promising.

Plan 29 wrote down the reference shape in the first screenful of the document
and never gave a spec a field to put it in::

    credentialRef:
      provider: vault
      secret: prod/database

``DrillSpec`` had no such key, so an author who followed the plan's own example
had their block silently ignored, and the phase's acceptance sentence — "a
literal where a reference is required fails spec validation with the field
named" — had nothing to fail against and no declared alternative to point at.
What is asserted here, each from both sides:

* **A reference validates and a literal does not, at the spec door.** Not at
  the run, not in a unit test of the scanner: ``parse_drill`` is where every
  authored spec enters the domain (``load_drill``, the API planner's file path,
  the boundary report's), so this is the narrowest place the refusal can hold.
* **The refusal names the field and never the value.** A message that echoed the
  credential would move the secret into the terminal, the log, and the CI
  transcript; the paths are what an author needs and the paths are what is
  rendered.
* **A spec without a reference dumps byte-identically to one from before the
  field existed.** The default is ``None`` and every digest path excludes none,
  so no existing run's hash, replay or plan diff moves. A new field that
  silently changed every digest would be a worse outcome than no field.
* **A development-only provider needs an explicit marker, at authoring time as
  well as at resolution time**, under one refusal code shared by both halves.
  Authoring is where the marker has to be visible: a spec is a document anyone
  can commit, and a marker only a run could set would let a committed file
  wave through a rule about what a run may do.
* **The block is closed.** A typo inside it is refused rather than dropped —
  ``extra="forbid"`` — because a reference that lost its ``secret`` on the way
  in is a credential nobody granted and nobody can audit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from mayhem.cli.app import app
from mayhem.cli.exit_codes import ExitCode
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import DrillSpec
from mayhem.domain.secrets import (
    REFUSAL_DEVELOPMENT_PROVIDER,
    CredentialRef,
    CredentialScope,
    ScopeKind,
    SecretProvider,
    SpecCredentialRef,
    find_literal_credentials,
)
from mayhem.spec import parse_drill

_SPEC: dict[str, Any] = {
    "kind": "drill",
    "name": "checkout",
    "containers": {"api": {"faults": [{"fault": "proc.pause", "duration": "10s"}]}},
    "execution": [{"wait": "5s"}],
}

_LEAK_VALUE = "hunter2hunter2"


def _spec(**overrides: Any) -> dict[str, Any]:
    return {**_SPEC, **overrides}


def _block(**overrides: Any) -> dict[str, Any]:
    block: dict[str, Any] = {
        "provider": "vault",
        "secret": "prod/database",
        "purpose": "seed the checkout rows before the fault",
    }
    block.update(overrides)
    return block


def _write(tmp_path: Path, document: dict[str, Any], name: str = "mayhem.yaml") -> Path:
    import yaml

    path = tmp_path / name
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


# --- The block parses ---------------------------------------------------------


class TestTheBlockParses:
    def test_a_reference_block_parses_into_the_spec(self) -> None:
        spec = parse_drill(_spec(credentialRef=_block()))
        assert len(spec.credential_refs) == 1
        reference = spec.credential_refs[0]
        assert reference.provider is SecretProvider.VAULT
        assert reference.secret == "prod/database"
        assert reference.purpose == "seed the checkout rows before the fault"
        assert reference.canonical_key == "vault:prod/database"

    def test_the_plan_s_own_field_names_are_the_ones_that_parse(self) -> None:
        # The plan's example names exactly provider and secret. `purpose` is
        # required on top of them, which is a deliberate strengthening rather
        # than a divergence: the purpose binding is what a reviewer reads when
        # asking why a step holds a credential, so defaulting it to "" would
        # make every reference equally unexplained.
        assert set(_block()) >= {"provider", "secret", "purpose"}
        assert parse_drill(_spec(credentialRef=_block())).credential_refs

    def test_the_snake_case_field_name_also_parses(self) -> None:
        spec = parse_drill(_spec(credential_ref=_block()))
        assert spec.credential_refs[0].canonical_key == "vault:prod/database"

    def test_the_list_form_is_accepted_because_one_was_a_shape_not_a_limit(self) -> None:
        spec = parse_drill(
            _spec(
                credentialRef=[
                    _block(),
                    _block(secret="prod/redis", purpose="flush the cart cache"),
                ]
            )
        )
        assert [ref.secret for ref in spec.credential_refs] == ["prod/database", "prod/redis"]

    def test_a_spec_with_no_block_has_no_references(self) -> None:
        assert parse_drill(_spec()).credential_refs == ()

    def test_an_empty_block_is_refused_rather_than_read_as_no_references(self) -> None:
        with pytest.raises(SchemaValidationError):
            parse_drill(_spec(credentialRef={}))

    def test_an_unknown_key_inside_the_block_is_refused(self) -> None:
        with pytest.raises(SchemaValidationError):
            parse_drill(_spec(credentialRef=_block(secrett="prod/database")))

    def test_a_blank_purpose_is_refused(self) -> None:
        with pytest.raises(SchemaValidationError):
            parse_drill(_spec(credentialRef=_block(purpose="   ")))

    def test_the_version_pin_survives_parsing(self) -> None:
        spec = parse_drill(_spec(credentialRef=_block(version="v7")))
        assert spec.credential_refs[0].version == "v7"


# --- Nothing else moved -------------------------------------------------------


class TestNothingElseMoved:
    def test_a_spec_without_a_reference_dumps_exactly_as_before(self) -> None:
        # Every digest path (canonical_json, plan_diff, evidence) excludes none,
        # so a new field that defaulted to `()` would have re-hashed every
        # existing run. `None` is what keeps this byte-identical.
        dumped = parse_drill(_spec()).model_dump(exclude_none=True)
        assert "credential_ref" not in dumped

    def test_a_spec_with_a_reference_dumps_it(self) -> None:
        # The other half of the property: a reference that was authored has to
        # survive into the parsed model, or the parser would be discarding the
        # thing this phase exists to record.
        dumped = parse_drill(_spec(credentialRef=_block())).model_dump(exclude_none=True)
        assert dumped["credential_ref"] == (
            {
                "provider": SecretProvider.VAULT,
                "secret": "prod/database",
                "purpose": "seed the checkout rows before the fault",
                "allow_development_only": False,
            },
        )

    def test_the_two_dumps_differ_only_by_the_reference(self) -> None:
        without = parse_drill(_spec()).model_dump(exclude_none=True)
        with_ref = parse_drill(_spec(credentialRef=_block())).model_dump(exclude_none=True)
        assert set(with_ref) - set(without) == {"credential_ref"}


# --- The development-only marker ----------------------------------------------


class TestDevelopmentOnlyNeedsAMarker:
    def test_a_development_only_provider_without_the_marker_is_refused(self) -> None:
        with pytest.raises(SchemaValidationError) as excinfo:
            parse_drill(_spec(credentialRef=_block(provider="environment", secret="PGPASS")))
        assert REFUSAL_DEVELOPMENT_PROVIDER in str(excinfo.value)
        assert "environment:PGPASS" in str(excinfo.value)

    def test_the_refusal_says_what_would_have_been_accepted(self) -> None:
        with pytest.raises(SchemaValidationError) as excinfo:
            parse_drill(_spec(credentialRef=_block(provider="environment", secret="PGPASS")))
        assert "allow_development_only" in str(excinfo.value)

    def test_the_same_provider_with_the_marker_is_accepted(self) -> None:
        spec = parse_drill(
            _spec(
                credentialRef=_block(
                    provider="environment", secret="PGPASS", allow_development_only=True
                )
            )
        )
        assert spec.credential_refs[0].is_development_only()

    def test_a_real_provider_needs_no_marker(self) -> None:
        spec = parse_drill(_spec(credentialRef=_block(provider="kubernetes")))
        assert not spec.credential_refs[0].is_development_only()

    def test_authoring_and_resolution_share_one_refusal_code(self) -> None:
        # Two spellings of one rule is how an operator ends up grepping for a
        # string only one half uses, and the two halves of this rule are the
        # same rule: a development-only provider needs an explicit marker.
        from mayhem.infra import secret_resolver

        assert secret_resolver.REFUSAL_DEVELOPMENT_PROVIDER == REFUSAL_DEVELOPMENT_PROVIDER

    def test_the_engine_does_not_re_spell_the_code(self) -> None:
        # Equality alone is not enough: an engine module that re-spelled the
        # literal would compare equal forever and drift the first time either
        # side changed. One definition, one import.
        from mayhem.infra import secret_resolver

        source = Path(secret_resolver.__file__).read_text(encoding="utf-8")
        assert f'"{REFUSAL_DEVELOPMENT_PROVIDER}"' not in source


# --- Binding at run start -----------------------------------------------------


class TestBinding:
    def test_binding_attaches_the_scope_the_run_supplies(self) -> None:
        reference = parse_drill(_spec(credentialRef=_block())).credential_refs[0]
        bound = reference.bind(CredentialScope(kind=ScopeKind.RUN, ref="r-1"))
        assert isinstance(bound, CredentialRef)
        assert bound.scope_token == "run:r-1"
        assert bound.canonical_key == reference.canonical_key
        assert bound.purpose == reference.purpose

    def test_binding_keeps_the_version_pin(self) -> None:
        reference = parse_drill(_spec(credentialRef=_block(version="v7"))).credential_refs[0]
        bound = reference.bind(CredentialScope(kind=ScopeKind.RUN, ref="r-1"))
        assert bound.version == "v7"

    def test_a_step_scope_may_be_authored_explicitly(self) -> None:
        reference = parse_drill(
            _spec(credentialRef=_block(scope={"kind": "step", "ref": "inject-db"}))
        ).credential_refs[0]
        assert reference.scope is not None
        assert reference.scope_token == "step:inject-db"

    def test_binding_refuses_to_rebind_a_scope_the_spec_named(self) -> None:
        # The run does not get to quietly widen what the spec scoped. A rebind
        # that succeeded would make the granted scope and the authored scope
        # two different things with only the grant's name surviving.
        reference = parse_drill(
            _spec(credentialRef=_block(scope={"kind": "step", "ref": "inject-db"}))
        ).credential_refs[0]
        with pytest.raises(ValueError, match="already names scope"):
            reference.bind(CredentialScope(kind=ScopeKind.RUN, ref="r-1"))


# --- The literal gate at the spec door ----------------------------------------


class TestTheLiteralGate:
    def test_a_literal_password_fails_spec_validation_naming_the_field(self) -> None:
        with pytest.raises(SchemaValidationError) as excinfo:
            parse_drill(_spec(config={"env": {"DB_PASSWORD": _LEAK_VALUE}}))
        message = str(excinfo.value)
        assert "config.env.DB_PASSWORD" in message
        assert "secret.literal_where_reference_required" in message

    def test_the_refusal_never_contains_the_value(self) -> None:
        with pytest.raises(SchemaValidationError) as excinfo:
            parse_drill(_spec(config={"env": {"DB_PASSWORD": _LEAK_VALUE}}))
        assert _LEAK_VALUE not in str(excinfo.value)

    def test_a_token_field_is_refused_too(self) -> None:
        with pytest.raises(SchemaValidationError) as excinfo:
            parse_drill(_spec(config={"env": {"REGISTRY_TOKEN": _LEAK_VALUE}}))
        assert "config.env.REGISTRY_TOKEN" in str(excinfo.value)

    def test_the_reference_is_the_accepted_alternative_in_the_same_field(self) -> None:
        # Same field position, same document, opposite verdict: this is what
        # "author a credentialRef instead" in the refusal message promises.
        parse_drill(_spec(credentialRef=_block()))

    def test_a_list_of_references_is_not_a_literal(self) -> None:
        parse_drill(_spec(credentialRef=[_block(), _block(secret="prod/redis", purpose="cache")]))

    def test_a_list_mixing_a_reference_with_a_literal_is_still_refused(self) -> None:
        with pytest.raises(SchemaValidationError) as excinfo:
            parse_drill(
                _spec(
                    credentialRef=[
                        _block(),
                        {"provider": "vault", "secret": "x", "password": _LEAK_VALUE},
                    ]
                )
            )
        assert _LEAK_VALUE not in str(excinfo.value)

    def test_the_gate_and_the_domain_scanner_never_disagree(self) -> None:
        # The loader delegates rather than reimplementing, so "what counts as a
        # literal" has one answer. Compared over a spread of documents rather
        # than one, because a delegation that only agreed on the easy case
        # would still be a second implementation.
        documents = [
            _spec(),
            _spec(credentialRef=_block()),
            _spec(credentialRef=[_block()]),
            _spec(config={"env": {"DB_PASSWORD": _LEAK_VALUE}}),
            _spec(config={"env": {"DB_PASSWORD": "secret://vault/prod/database"}}),
            _spec(config={"env": {"password": ""}}),
            _spec(config={"env": {"password": None}}),
            _spec(containers={"api": {"faults": [], "secret_path": "prod/db"}}),
        ]
        for document in documents:
            literals = find_literal_credentials(document)
            refused = False
            try:
                parse_drill(document)
            except SchemaValidationError as exc:
                refused = "secret.literal_where_reference_required" in str(exc)
            assert refused == bool(literals), document


# --- The surface --------------------------------------------------------------


class TestTheSurface:
    def test_show_renders_the_reference_and_no_value(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _spec(credentialRef=_block()))
        result = CliRunner().invoke(app, ["experiment", "show", str(path)])
        assert result.exit_code == ExitCode.SUCCESS
        assert '"secret": "prod/database"' in result.output
        assert "seed the checkout rows before the fault" in result.output

    def test_show_refuses_a_literal_and_never_prints_the_value(self, tmp_path: Path) -> None:
        # `CliRunner` does not run the app's own error handler, so the refusal
        # arrives as the raise rather than as a rendered line. The rendering —
        # exit 4, the field path, the remediation — is what an author reads, so
        # it is driven through the real CLI in /tmp/drive_credential_refs.py.
        path = _write(tmp_path, _spec(config={"env": {"DB_PASSWORD": _LEAK_VALUE}}))
        result = CliRunner().invoke(app, ["experiment", "show", str(path)])
        assert isinstance(result.exception, SchemaValidationError)
        assert "config.env.DB_PASSWORD" in str(result.exception)
        assert _LEAK_VALUE not in str(result.exception)

    def test_a_spec_with_a_reference_still_loads_through_the_model_directly(self) -> None:
        # Not only through `parse_drill`: the API planner validates a raw body
        # straight onto the model, so the block has to survive that door too.
        spec = DrillSpec.model_validate(_spec(credentialRef=_block()))
        assert spec.credential_refs[0].canonical_key == "vault:prod/database"


class TestTheModelIsClosed:
    def test_the_block_rejects_a_field_it_does_not_declare(self) -> None:
        with pytest.raises(ValidationError, match="secrett"):
            SpecCredentialRef.model_validate(_block(secrett="prod/database"))

    def test_the_block_requires_a_provider(self) -> None:
        with pytest.raises(ValidationError, match="provider"):
            SpecCredentialRef.model_validate({"secret": "prod/database", "purpose": "p"})
