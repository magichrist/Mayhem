"""``mayhem secrets``: grant administration, and the literal-secret refusal.

Plan 29 Phase 3 named a surface that did not exist: a grant could be written by a
test and read by the resolver, and no command issued or revoked one. A permission
nobody can grant or withdraw is a fixture, not a permission model.

What is asserted here, each from both sides:

* **Every bound on a grant is required, not defaulted.** Environments, pattern,
  principal and an expiry are all mandatory, because the domain refuses to mint
  a grant with an unbounded environment or no deadline. A zero or negative
  ``--expires-in`` is refused here rather than clamped, so the operator learns
  what they asked for.
* **Revocation is by the pair the resolver looks a grant up by**, and revoking
  nothing is an error. A revocation that quietly withdrew nothing would leave an
  operator believing a permission was gone.
* **``explain`` is the acceptance criterion made operable**: it names which grant
  answers and which of its five clauses matched, and denies when none does. The
  denial names the clause that failed, which is the difference between a
  permission you can audit and one you can only observe.
* **A literal credential in an authored scenario is refused at the intake** —
  ``mayhem experiment check-scenario`` is the first production caller of
  ``require_no_literal_spec``, so the gate Phase 4 recorded as callerless is now
  on a real path, and the refusal happens before anything is compiled.

Nothing here handles a value: the surface stores and prints patterns and declared
principals only.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pytest
from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.exit_codes import ExitCode

if TYPE_CHECKING:
    from pathlib import Path

LEAKY_SCENARIO = """name: leaky
variables: {}
steps:
  - id: inject
    fault: net.latency
    duration: 1
    env:
      DB_PASSWORD: hunter2hunter2
"""


def _run(*args: str) -> Any:
    return CliRunner().invoke(app, list(args), catch_exceptions=False)


def _run_soft(*args: str) -> Any:
    """Let the app render its own refusals.

    ``require_no_literal_spec`` raises ``InvariantViolationError``, which the app
    turns into an exit code and a remediation line. The tests about the literal
    gate are about what an author is shown, so they go through the handler rather
    than asserting the raise; the domain's own tests cover the raise.
    """
    return CliRunner().invoke(app, list(args))


def _payload(result: Any) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(result.output))


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "grants.db")


def _granted(tmp_path: Path, *options: str) -> str:
    db = _db(tmp_path)
    result = _run(
        "secrets",
        "grant",
        "--principal",
        "sre-oncall",
        "--pattern",
        "vault:prod/*",
        "--environment",
        "prod-*",
        "--scope",
        "step:inject",
        "--expires-in",
        "7",
        "--db",
        db,
        *options,
    )
    assert result.exit_code == int(ExitCode.SUCCESS), result.output
    return db


class TestTheSurfaceIsReachable:
    def test_the_group_renders_help(self) -> None:
        result = _run("secrets", "--help")

        assert result.exit_code == 0
        for verb in ("grant", "revoke", "list", "explain"):
            assert verb in result.output

    def test_an_empty_table_says_so(self, tmp_path: Path) -> None:
        result = _run("secrets", "list", "--db", _db(tmp_path))

        assert result.exit_code == 0
        assert "no credential grant is outstanding" in result.output


class TestIssuingAndWithdrawing:
    def test_a_grant_records_who_what_where_and_until_when(self, tmp_path: Path) -> None:
        db = _granted(tmp_path)
        row = _payload(_run("secrets", "list", "--db", db, "--json"))["grants"][0]

        assert row["principal"] == "sre-oncall"
        assert row["credential_pattern"] == "vault:prod/*"
        assert row["environments"] == ["prod-*"]
        assert row["scopes"] == ["step:inject"]
        assert row["expires_at"]

    def test_the_principal_is_recorded_as_declared_and_not_authenticated(
        self, tmp_path: Path
    ) -> None:
        """Nothing in this surface proves who typed it; the payload says so."""
        db = _granted(tmp_path)
        payload = _payload(_run("secrets", "list", "--db", db, "--json"))

        assert "declared" in payload["note"]

    def test_a_zero_expiry_is_refused_rather_than_clamped(self, tmp_path: Path) -> None:
        result = _run(
            "secrets",
            "grant",
            "--principal",
            "x",
            "--pattern",
            "vault:*",
            "--environment",
            "prod",
            "--expires-in",
            "0",
            "--db",
            _db(tmp_path),
        )

        assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
        assert "standing permission" in result.output

    def test_a_negative_expiry_is_refused_too(self, tmp_path: Path) -> None:
        result = _run(
            "secrets",
            "grant",
            "--principal",
            "x",
            "--pattern",
            "vault:*",
            "--environment",
            "prod",
            "--expires-in",
            "-3",
            "--db",
            _db(tmp_path),
        )

        assert result.exit_code != int(ExitCode.SUCCESS)

    def test_a_missing_environment_is_refused_by_the_type(self, tmp_path: Path) -> None:
        result = _run(
            "secrets",
            "grant",
            "--principal",
            "x",
            "--pattern",
            "vault:*",
            "--expires-in",
            "3",
            "--db",
            _db(tmp_path),
        )

        assert result.exit_code != int(ExitCode.SUCCESS)

    def test_revoking_the_pair_removes_the_grant(self, tmp_path: Path) -> None:
        db = _granted(tmp_path)

        result = _run(
            "secrets",
            "revoke",
            "--principal",
            "sre-oncall",
            "--pattern",
            "vault:prod/*",
            "--db",
            db,
        )

        assert result.exit_code == int(ExitCode.SUCCESS)
        assert "no credential grant is outstanding" in _run("secrets", "list", "--db", db).output

    def test_revoking_nothing_is_an_error(self, tmp_path: Path) -> None:
        """A revocation that withdrew nothing must not read as one that did."""
        db = _granted(tmp_path)

        result = _run(
            "secrets", "revoke", "--principal", "nobody", "--pattern", "vault:*", "--db", db
        )

        assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
        assert "Nothing was withdrawn" in result.output

    def test_revoking_one_principal_leaves_another_alone(self, tmp_path: Path) -> None:
        db = _granted(tmp_path)
        _run(
            "secrets",
            "grant",
            "--principal",
            "other",
            "--pattern",
            "vault:prod/db",
            "--environment",
            "prod",
            "--expires-in",
            "1",
            "--db",
            db,
        )

        _run(
            "secrets",
            "revoke",
            "--principal",
            "sre-oncall",
            "--pattern",
            "vault:prod/*",
            "--db",
            db,
        )

        remaining = _payload(_run("secrets", "list", "--db", db, "--json"))["grants"]
        assert [row["principal"] for row in remaining] == ["other"]


class TestEffectivePermissionExplanation:
    def _explain_on(self, db: str, **overrides: str) -> Any:
        """Ask the question against a database the caller already owns."""
        options = {
            "--principal": "sre-oncall",
            "--pattern": "vault:prod/database",
            "--environment": "prod-eu",
            "--scope": "step:inject",
            "--db": db,
            "--json": "",
        }
        options.update(overrides)
        args = ["secrets", "explain"]
        for flag, value in options.items():
            args.append(flag)
            if value:
                args.append(value)
        return _run(*args)

    def _explain(self, tmp_path: Path, **overrides: str) -> Any:
        return self._explain_on(_granted(tmp_path), **overrides)

    def test_a_covered_question_is_permitted_and_names_the_grant(self, tmp_path: Path) -> None:
        payload = _payload(self._explain(tmp_path))

        assert payload["permitted"] is True
        assert payload["answered_by"] == "vault:prod/*"

    def test_every_clause_is_reported_not_just_the_answer(self, tmp_path: Path) -> None:
        payload = _payload(self._explain(tmp_path))

        assert sorted(payload["considered"][0]["clauses"]) == [
            "environment",
            "pattern",
            "principal",
            "scope",
            "unexpired",
        ]

    def test_the_wrong_environment_denies_and_names_the_clause(self, tmp_path: Path) -> None:
        payload = _payload(self._explain(tmp_path, **{"--environment": "staging"}))

        assert payload["permitted"] is False
        failed = [name for name, ok in payload["considered"][0]["clauses"].items() if not ok]
        assert failed == ["environment"]

    def test_the_wrong_scope_denies(self, tmp_path: Path) -> None:
        payload = _payload(self._explain(tmp_path, **{"--scope": "step:other"}))

        assert payload["permitted"] is False

    def test_an_unknown_principal_denies_and_consults_nothing(self, tmp_path: Path) -> None:
        payload = _payload(self._explain(tmp_path, **{"--principal": "stranger"}))

        assert payload["permitted"] is False
        assert payload["grants_considered"] == 0

    def test_an_expired_grant_denies(self, tmp_path: Path) -> None:
        from mayhem.infra.migrations import ALL_MIGRATIONS
        from mayhem.infra.secret_resolver import SecretGrantRepository
        from mayhem.infra.store import Store

        db = _granted(tmp_path)
        store = Store.open_migrated(db, migrations=ALL_MIGRATIONS)
        try:
            repository = SecretGrantRepository(store)
            live = repository.load_all()[0]
            repository.save(
                live.model_copy(update={"expires_at": live.issued_at or live.expires_at})
            )
        finally:
            store.close()

        payload = _payload(self._explain_on(db))

        assert payload["permitted"] is False
        assert payload["considered"][0]["clauses"]["unexpired"] is False

    def test_the_denial_exits_non_zero_so_it_can_gate_a_run(self, tmp_path: Path) -> None:
        db = _granted(tmp_path)
        result = _run(
            "secrets",
            "explain",
            "--principal",
            "sre-oncall",
            "--pattern",
            "vault:prod/database",
            "--environment",
            "staging",
            "--db",
            db,
        )

        assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
        assert "did not match" in result.output

    def test_the_permitted_case_exits_zero(self, tmp_path: Path) -> None:
        db = _granted(tmp_path)
        result = _run(
            "secrets",
            "explain",
            "--principal",
            "sre-oncall",
            "--pattern",
            "vault:prod/database",
            "--environment",
            "prod-eu",
            "--scope",
            "step:inject",
            "--db",
            db,
        )

        assert result.exit_code == int(ExitCode.SUCCESS)
        assert result.output.startswith("PERMITTED")


class TestLiteralSecretsAreRefusedAtTheIntake:
    """``require_no_literal_spec`` finally has the production caller it lacked.

    The rendered refusal — exit code and remediation — belongs to
    ``mayhem.cli.app.main``, which ``CliRunner`` does not run. These tests assert
    the contract underneath it instead: the named rule, the offending field
    path, and the guarantee that the value itself never appears.
    """

    @staticmethod
    def _leaky(tmp_path: Path) -> str:
        path = tmp_path / "leaky.yaml"
        path.write_text(LEAKY_SCENARIO, encoding="utf-8")
        return str(path)

    def test_a_scenario_carrying_a_literal_is_refused(self, tmp_path: Path) -> None:
        from mayhem.domain.errors import InvariantViolationError
        from mayhem.domain.secrets import REFUSAL_LITERAL_SECRET

        with pytest.raises(InvariantViolationError) as refusal:
            _run("experiment", "check-scenario", self._leaky(tmp_path))

        assert refusal.value.rule == REFUSAL_LITERAL_SECRET
        assert "credentialRef" in str(refusal.value)

    def test_the_refusal_names_the_field_and_never_the_value(self, tmp_path: Path) -> None:
        from mayhem.domain.errors import InvariantViolationError

        with pytest.raises(InvariantViolationError) as refusal:
            _run("experiment", "check-scenario", self._leaky(tmp_path))

        message = str(refusal.value)
        assert "DB_PASSWORD" in message
        assert "hunter2hunter2" not in message

    def test_a_scenario_with_no_literal_still_compiles(self, tmp_path: Path) -> None:
        """Two-sided: a gate that refused every scenario would pass the tests above."""
        path = tmp_path / "clean.yaml"
        path.write_text(
            "name: clean\nvariables: {}\nsteps:\n"
            "  - id: inject\n    fault: net.latency\n    duration: 1\n"
            "    env:\n      LOG_LEVEL: info\n",
            encoding="utf-8",
        )

        result = _run("experiment", "check-scenario", str(path))

        assert "literal credential" not in result.output
