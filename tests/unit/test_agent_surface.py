"""Plan 03 Phase 3 — the enrollment surface, driven through the live Click tree.

Phase 3's acceptance is two claims: a third-party provider installs without
core changes and its permissions are visible pre-execution (the provider half
is asserted in this file's ``TestProviderPermissionsAreVisible``), and agent
enrollment has a surface carrying the refusals an operator's wrong belief
deserves. This suite drives ``mayhem agent`` through ``app`` — the registered
tree, not the group object — because a command nobody can reach would pass a
group-level test while being undispatchable, which is exactly the debt plan 07
and plan 21 each paid for.

The three refusals the surface must give, each asserted from the side that
matters:

* enrolling over an existing id is refused, and the *existing record is
  untouched* (a successful overwrite would reset ``version`` to 1 and launder
  revocation history);
* revoking twice is refused, and the first revoker stays on the record;
* a state the verifier would refuse is refused by ``show`` with the same
  verdict, read through the domain's own ``refusals_at`` rather than a second
  implementation of expiry.

And the honesty the ledger carries: no verb generates, reads, or stores key
material — enrollment writes identity, and the payload says so in a field
rather than leaving it to prose.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.services import open_store
from mayhem.domain.agent_identity import AgentCredential, AgentIdentity
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.infra.agent_identity_store import AgentIdentityRepository


def _run(*args: str) -> Any:
    result = CliRunner().invoke(app, list(args), catch_exceptions=False)
    assert isinstance(result.exit_code, int)
    return result


def _json(result: Any) -> dict[str, Any]:
    return json.loads(result.output)


def _enroll(db: str, agent_id: str, **overrides: str) -> object:
    args = [
        "agent",
        "enroll",
        "--agent-id",
        agent_id,
        "--controller-id",
        overrides.get("controller_id", "controller-1"),
        "--principal",
        overrides.get("principal", "sa-agent-1"),
        "--environment",
        overrides.get("environment", "staging"),
        "--db",
        db,
        "--json",
    ]
    if "ttl_seconds" in overrides:
        args.extend(["--ttl-seconds", overrides["ttl_seconds"]])
    if "principal_kind" in overrides:
        args.extend(["--principal-kind", overrides["principal_kind"]])
    return _run(*args)


def _repo(db: str) -> AgentIdentityRepository:
    return AgentIdentityRepository(open_store(db))


def _seed(db: str, agent_id: str, *, issued: datetime, expires: datetime) -> AgentIdentity:
    """Write an identity straight through the repository, bypassing the surface."""
    identity = AgentIdentity(
        agent_id=agent_id,
        controller_id="controller-1",
        principal=Principal(principal_id="sa-agent-1", kind=PrincipalKind.WORKLOAD),
        scope=EnvironmentScope(environment="staging"),
        credential=AgentCredential(
            credential_id=f"cred-{agent_id}",
            agent_id=agent_id,
            issued_at=issued,
            expires_at=expires,
        ),
    )
    _repo(db).save(identity)
    return identity


# -- enroll -------------------------------------------------------------------------


def test_enroll_writes_a_usable_identity_and_no_key_material(tmp_path) -> None:
    db = str(tmp_path / "mayhem.db")
    result = _enroll(db, "agent-1")
    assert result.exit_code == int(ExitCode.SUCCESS)
    payload = _json(result)
    assert payload["agent_id"] == "agent-1"
    assert payload["state"] == "usable"
    assert payload["revoked"] is False
    assert payload["credential_id"].startswith("cred-agent-1")
    # The honesty, in a field rather than in prose: nothing was minted.
    assert payload["key_material"] == "none"
    assert "no key material" in payload["note"]

    # The record the verifier would read is the one the surface wrote.
    stored = _repo(db).load("agent-1")
    assert stored is not None
    assert stored.principal.principal_id == "sa-agent-1"
    assert stored.scope.environment == "staging"
    assert stored.version == 1


def test_enroll_refuses_an_already_enrolled_agent_and_leaves_the_record_untouched(
    tmp_path,
) -> None:
    db = str(tmp_path / "mayhem.db")
    first = _enroll(db, "agent-1")
    assert first.exit_code == int(ExitCode.SUCCESS)
    before = _repo(db).load("agent-1")
    assert before is not None

    second = _enroll(db, "agent-1")
    assert second.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "already enrolled" in second.output
    assert "reset its version" in second.output

    after = _repo(db).load("agent-1")
    assert after is not None
    # Not overwritten: same version, same credential. An overwrite would have
    # reset version to 1 and replaced the window.
    assert after.version == before.version
    assert after.credential.credential_id == before.credential.credential_id


def test_enroll_refuses_a_malformed_agent_id(tmp_path) -> None:
    db = str(tmp_path / "mayhem.db")
    result = _enroll(db, "not a valid id!")
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
    assert _repo(db).load("not a valid id!") is None


def test_enroll_refuses_a_non_positive_ttl(tmp_path) -> None:
    """An eternal or negative credential window is unrepresentable, not defaulted."""
    db = str(tmp_path / "mayhem.db")
    result = _enroll(db, "agent-1", ttl_seconds="0")
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
    assert "window" in result.output or "expires" in result.output
    assert _repo(db).load("agent-1") is None


# -- list ---------------------------------------------------------------------------


def test_list_reports_every_enrolled_agent(tmp_path) -> None:
    db = str(tmp_path / "mayhem.db")
    _enroll(db, "agent-b")
    _enroll(db, "agent-a")
    result = _run("agent", "list", "--db", db, "--json")
    assert result.exit_code == int(ExitCode.SUCCESS)
    payload = _json(result)
    assert payload["count"] == 2
    # Ordered by agent id, so two runs of the same store render the same rows.
    assert [row["agent_id"] for row in payload["agents"]] == ["agent-a", "agent-b"]
    assert all(row["state"] == "usable" for row in payload["agents"])


def test_list_on_an_empty_store_points_at_enroll(tmp_path) -> None:
    db = str(tmp_path / "mayhem.db")
    result = _run("agent", "list", "--db", db)
    assert "mayhem agent enroll" in result.output


def test_list_flags_an_expired_identity_as_unusable_with_its_refusal(tmp_path) -> None:
    now = datetime.now(UTC)
    db = str(tmp_path / "mayhem.db")
    _seed(db, "agent-old", issued=now - timedelta(hours=3), expires=now - timedelta(hours=1))
    result = _run("agent", "list", "--db", db, "--json")
    payload = _json(result)
    (row,) = payload["agents"]
    assert row["agent_id"] == "agent-old"
    assert row["state"] == "unusable"
    assert "expired" in row["refusals"]
    assert row["needs_rotation"] is False


# -- show ---------------------------------------------------------------------------


def test_show_exits_zero_for_a_usable_identity(tmp_path) -> None:
    db = str(tmp_path / "mayhem.db")
    _enroll(db, "agent-1")
    result = _run("agent", "show", "agent-1", "--db", db, "--json")
    assert result.exit_code == int(ExitCode.SUCCESS)
    payload = _json(result)
    assert payload["state"] == "usable"
    assert payload["refusals"] == []


def test_show_exits_nonzero_when_the_identity_may_not_authenticate(tmp_path) -> None:
    now = datetime.now(UTC)
    db = str(tmp_path / "mayhem.db")
    _seed(db, "agent-old", issued=now - timedelta(hours=3), expires=now - timedelta(hours=1))
    result = _run("agent", "show", "agent-old", "--db", db, "--json")
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    payload = _json(result)
    assert payload["state"] == "unusable"
    assert "expired" in payload["refusals"]


def test_show_agrees_with_the_domain_predicates(tmp_path) -> None:
    """The surface must read the question the verifier reads, not a cheaper one."""
    now = datetime.now(UTC)
    db = str(tmp_path / "mayhem.db")
    _seed(db, "agent-fresh", issued=now - timedelta(minutes=1), expires=now + timedelta(hours=1))
    _seed(db, "agent-old", issued=now - timedelta(hours=3), expires=now - timedelta(hours=1))

    for agent_id in ("agent-fresh", "agent-old"):
        result = _run("agent", "show", agent_id, "--db", db, "--json")
        payload = _json(result)
        stored = _repo(db).load(agent_id)
        assert stored is not None
        usable = stored.is_usable_at(now=datetime.now(UTC))
        assert (payload["state"] == "unusable") is (not usable), agent_id
        assert result.exit_code == (
            int(ExitCode.SUCCESS) if usable else int(ExitCode.SAFETY_REFUSAL)
        ), agent_id


def test_show_refuses_an_unknown_agent_rather_than_rendering_nothing(tmp_path) -> None:
    db = str(tmp_path / "mayhem.db")
    result = _run("agent", "show", "agent-ghost", "--db", db)
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
    assert "not enrolled" in result.output
    assert "mayhem agent enroll" in result.output


# -- revoke -------------------------------------------------------------------------


def test_revoke_pulls_the_identity_and_show_then_refuses(tmp_path) -> None:
    db = str(tmp_path / "mayhem.db")
    _enroll(db, "agent-1")
    result = _run(
        "agent",
        "revoke",
        "--agent-id",
        "agent-1",
        "--reason",
        "compromised",
        "--by",
        "operator-1",
        "--note",
        "host reimaged",
        "--db",
        db,
        "--json",
    )
    assert result.exit_code == int(ExitCode.SUCCESS)
    payload = _json(result)
    assert payload["revoked"] is True
    assert payload["state"] == "unusable"
    assert any("compromised" in entry for entry in payload["revocations"])

    shown = _run("agent", "show", "agent-1", "--db", db, "--json")
    assert shown.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert _json(shown)["revoked"] is True


def test_a_second_revoke_is_refused_and_records_nothing(tmp_path) -> None:
    """The first revocation wins: a second reason must not erase the first actor."""
    db = str(tmp_path / "mayhem.db")
    _enroll(db, "agent-1")
    _run(
        "agent",
        "revoke",
        "--agent-id",
        "agent-1",
        "--reason",
        "compromised",
        "--by",
        "operator-1",
        "--db",
        db,
    )
    second = _run(
        "agent",
        "revoke",
        "--agent-id",
        "agent-1",
        "--reason",
        "decommissioned",
        "--by",
        "operator-2",
        "--db",
        db,
    )
    assert second.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "first one wins" in second.output

    stored = _repo(db).load("agent-1")
    assert stored is not None
    assert len(stored.revocations) == 1
    assert stored.revocations[0].reason.value == "compromised"
    assert stored.revocations[0].revoked_by == "operator-1"


def test_revoke_refuses_an_unenrolled_agent(tmp_path) -> None:
    db = str(tmp_path / "mayhem.db")
    result = _run(
        "agent",
        "revoke",
        "--agent-id",
        "agent-ghost",
        "--reason",
        "compromised",
        "--by",
        "operator-1",
        "--db",
        db,
    )
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
    assert "not enrolled" in result.output


def test_revoke_requires_a_non_blank_actor(tmp_path) -> None:
    """A revocation with no revoker is the one provenance an audit cannot rebuild."""
    db = str(tmp_path / "mayhem.db")
    _enroll(db, "agent-1")
    result = _run(
        "agent",
        "revoke",
        "--agent-id",
        "agent-1",
        "--reason",
        "compromised",
        "--by",
        "   ",
        "--db",
        db,
    )
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
    assert "revoker" in result.output or "--by" in result.output
    stored = _repo(db).load("agent-1")
    assert stored is not None
    assert stored.revoked is False


# -- registration (the inventory suites own the exact sets; this pins the wiring) ---


def test_the_group_is_registered_on_the_live_app() -> None:
    from mayhem.cli.command_registry import COMMAND_HELP, COMMAND_SPECS

    assert "agent" in app.commands
    assert set(app.commands["agent"].commands) == {"enroll", "list", "show", "revoke"}
    assert COMMAND_HELP["agent"] in (app.commands["agent"].help or "")
    spec = next(spec for spec in COMMAND_SPECS if spec.name == "agent")
    assert spec.mutating is True  # enroll inserts; revoke appends and bumps


# -- provider permissions visible pre-execution (Phase 3's other clause) -----------


def _write_catalog(path: Path, permissions: list[str]) -> None:
    """A third-party catalog whose single provider declares ``permissions``.

    Same document shape ``tests/unit/test_cli_extend.py`` writes: a metadata
    half the inspector reads *without loading any implementation code*, and an
    import target that does not exist — inspection still succeeds, which is
    what makes "visible pre-execution" a testable claim rather than a hope.
    """
    path.write_text(
        json.dumps(
            {
                "apiVersion": "mayhem.provider-catalog/v1",
                "providers": [
                    {
                        "metadata": {
                            "apiVersion": "mayhem.provider/v1",
                            "providerId": "acme.injector",
                            "name": "Acme Injector",
                            "version": "1.0.0",
                            "description": "A third-party provider.",
                            "permissions": permissions,
                            "capabilities": [
                                {"id": "target.discovery", "summary": "Resolve targets."}
                            ],
                            "targetLocators": [
                                {
                                    "id": "acme.target",
                                    "kind": "test_object",
                                    "selectorSchema": {"name": "string"},
                                    "requiredPermissions": [],
                                }
                            ],
                            "evidenceSchema": {
                                "name": "acme-evidence",
                                "version": "1.0",
                                "fields": ("target",),
                            },
                        },
                        "implementation": {
                            "kind": "import",
                            "target": "tests.missing_provider:Missing",
                            "factory": False,
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


class TestProviderPermissionsAreVisible:
    """The acceptance clause: what a provider asks for, before it is loaded."""

    def test_inspect_prints_the_declared_permissions_without_loading_code(
        self, tmp_path: Path
    ) -> None:
        catalog = tmp_path / "catalog.json"
        _write_catalog(catalog, ["target:read"])
        result = _run("extend", "providers", "inspect", "--catalog", str(catalog))
        assert result.exit_code == int(ExitCode.SUCCESS)
        # The metadata-only path loads no implementation code — the import
        # target above does not exist, and inspection still succeeds — while
        # the permission line renders, because that is what "visible
        # pre-execution" means.
        assert "permissions: target:read" in result.output
        assert "acme.injector" in result.output

    def test_inspect_json_carries_the_permission_names(self, tmp_path: Path) -> None:
        catalog = tmp_path / "catalog.json"
        _write_catalog(catalog, ["target:read", "network"])
        result = _run("extend", "providers", "inspect", "--catalog", str(catalog), "--json")
        assert result.exit_code == int(ExitCode.SUCCESS)
        payload = _json(result)
        assert payload["providers"], "the inspection reported no providers at all"
        (provider,) = payload["providers"]
        assert provider["provider_id"] == "acme.injector"
        assert provider["status"] == "ready"
        # Inspection never loads: nothing in `loaded` came from this run.
        assert payload["loaded"] == []
        # The serializer sorts permission names, so two runs render alike.
        assert (provider.get("metadata") or {}).get("permissions") == [
            "network",
            "target:read",
        ]

    def test_the_default_posture_is_rendered_as_nothing_asked(self, tmp_path: Path) -> None:
        """A declaration that asks for nothing must print, not vanish."""
        catalog = tmp_path / "catalog.json"
        _write_catalog(catalog, [])
        result = _run("extend", "providers", "inspect", "--catalog", str(catalog))
        assert result.exit_code == int(ExitCode.SUCCESS)
        assert "permissions: none (default posture)" in result.output
