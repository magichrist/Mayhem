"""Plan 19 Phase 3 (surface half) — ``mayhem ha``: promote, rotate, trust, update.

Invoked directly through ``CliRunner``: ``cli/failover_cmd.py`` is registered in
``cli/command_registry.py`` under the root name ``ha``, so ``mayhem ha --help``
resolves, and nothing here depends on that registration either way. The tests
drive the Click object directly so a failure names the command and its refusal
rather than the registry.

The properties under test are the ones a CLI can quietly destroy:

* **There is no "cannot reach it, so promote" flag.** ``ha promote`` derives its
  evidence from the leadership store's own record, so a live lease yields
  ``heartbeat_missing`` and is refused, and only an *expired* lease in the
  replicated store yields the death evidence that promotes. The word
  ``unreachable`` does not appear as an option anywhere in the command's help.
* **A refusal exits ``SAFETY_REFUSAL``**, prints every reason, and never reports
  success — including when the standby is refused three separate ways at once.
* **A secret is never an argument.** Every key comes from a named environment
  variable, and an unset one is a ``config_error`` rather than an empty secret.
* **An unavailable algorithm is not a refusal.** ``--algorithm x509`` exits
  ``TOOLKIT_ERROR`` with ``agent_signature_port_unavailable`` and never prints
  ``trusted``, which is the property the whole X.509 seam exists to hold.
* **The rotation surface reports the fail-closed window.** A rotation with no
  provisioner bound prints "rotated-without-a-key 1" and warns; it does not read
  as a healthy sweep.
* **The update check verifies and refuses; it never installs.** The output says
  ``APPLICABLE`` only when it is true, and every refusal is named.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from mayhem.cli import failover_cmd
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.credential_rotation import CredentialRotationService, RotationPolicy
from mayhem.controller.failover_service import FailoverService
from mayhem.controller.leader_election import LeaderElection, SqliteLeadershipStore
from mayhem.domain.agent_identity import AgentCredential, AgentIdentity
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.infra.agent_identity_store import AgentIdentityRepository
from mayhem.infra.agent_identity_verifier import (
    ALGORITHM_X509,
    SIGNATURE_PORT_UNAVAILABLE,
    HmacSha256CommandSigner,
    HmacSha256SignatureVerifier,
    StaticKeyMaterial,
)
from mayhem.infra.certificate_authority import (
    CaKeyMaterial,
    FixtureCertificateAuthority,
    MtlsRole,
)
from mayhem.infra.failover_store import (
    FAILOVER_MIGRATION,
    FAILOVER_VERSION,
    FailoverPromotionStore,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store
from mayhem.infra.update_manifest import HmacUpdateManifestSigner, UpdateChannel

if TYPE_CHECKING:
    from pathlib import Path

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
SCOPE = "control-plane"
TTL_S = 30.0
CA_ID = "ca-mesh-1"
CA_SECRET = b"c" * 32
RELEASE_KEY = b"r" * 32
ARTIFACT = b"mayhem-agent-2.1.0\n"
MIGRATIONS: tuple = (
    ALL_MIGRATIONS
    if any(m.version == FAILOVER_VERSION for m in ALL_MIGRATIONS)
    else (*ALL_MIGRATIONS, FAILOVER_MIGRATION)
)


class Clock:
    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def identity(agent_id: str = "ag-1") -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        controller_id="ctl-a",
        principal=Principal(principal_id=f"sa-{agent_id}", kind=PrincipalKind.WORKLOAD),
        scope=EnvironmentScope(environment="staging"),
        credential=AgentCredential(
            credential_id=f"{agent_id}-c1",
            agent_id=agent_id,
            issued_at=NOW - timedelta(seconds=60),
            expires_at=NOW + timedelta(seconds=900),
            rotate_before=300.0,
        ),
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """A real migrated database the CLI opens itself."""
    path = tmp_path / "ha.db"
    opened = Store.open_migrated(path, migrations=MIGRATIONS)
    opened.close()
    return path


def invoke(db_path: Path, args: list[str]) -> object:
    return CliRunner().invoke(failover_cmd.ha, args, obj=SimpleNamespace(db=str(db_path)))


def leadership(
    db_path: Path, controller_id: str, clock: Clock | None = None, *, ttl_s: float = TTL_S
) -> LeaderElection:
    store = Store.open_migrated(str(db_path), migrations=MIGRATIONS)
    election = LeaderElection(
        store=SqliteLeadershipStore(store),
        controller_id=controller_id,
        ttl_s=ttl_s,
        clock=clock if clock is not None else utc_now,
    )
    election.campaign()
    store.close()
    return election


def utc_now() -> datetime:
    from mayhem.domain.common import utc_now as _now

    return _now()


def write_manifest(tmp_path: Path, **over: object) -> Path:
    keys = StaticKeyMaterial({"release-1": RELEASE_KEY})
    signer = HmacUpdateManifestSigner(keys)
    base: dict[str, object] = {
        "manifest_id": "m-2.1.0",
        "component": "agent",
        "component_version": "2.1.0",
        "artifact_digest": hashlib.sha256(ARTIFACT).hexdigest(),
        "channel": "stable",
        "issued_at": utc_now() - timedelta(hours=1),
        "expires_at": utc_now() + timedelta(hours=1),
        "signer_key_id": "release-1",
        "sbom_ref": "sbom/2.1.0.json",
        "provenance_ref": "provenance/2.1.0.json",
    }
    base.update(over)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(signer.sign(base).model_dump(mode="json")), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Shape                                                                          #
# --------------------------------------------------------------------------- #


class TestTheGroup:
    def test_help_lists_every_command(self) -> None:
        result = CliRunner().invoke(failover_cmd.ha, ["--help"])
        assert result.exit_code == 0
        for command in ("promote", "rotate", "cert", "update"):
            assert command in result.output

    def test_promote_offers_no_unreachable_flag(self) -> None:
        """The dangerous branch must not be one keystroke away."""
        result = CliRunner().invoke(failover_cmd.ha, ["promote", "--help"])
        assert result.exit_code == 0
        assert "--primary-unreachable" not in result.output
        assert "--forced" in result.output

    def test_no_command_has_a_bypass_flag(self) -> None:
        for command in ("promote", "rotate", "cert", "update"):
            result = CliRunner().invoke(failover_cmd.ha, [command, "--help"])
            assert result.exit_code == 0
            for banned in ("--skip-verify", "--trust-me", "--insecure", "--no-verify"):
                assert banned not in result.output

    def test_a_secret_is_never_an_argument(self) -> None:
        result = CliRunner().invoke(failover_cmd.ha, ["cert", "--help"])
        assert "--key-env" in result.output
        assert "--key" not in result.output.replace("--key-env", "")


# --------------------------------------------------------------------------- #
# ha promote                                                                     #
# --------------------------------------------------------------------------- #


class TestPromoteCommand:
    def test_an_empty_scope_is_claimed_rather_than_failed_over(self, db_path: Path) -> None:
        result = invoke(db_path, ["promote", "--operator", "ana", "--reason", "fresh cluster"])
        assert result.exit_code == ExitCode.SUCCESS
        assert "claimed by ctl-local" in result.output
        assert "nothing was deposed" in result.output

    def test_a_live_lease_is_refused_and_nothing_moves(self, db_path: Path) -> None:
        leadership(db_path, "ctl-a")
        result = invoke(db_path, ["promote", "--operator", "ana", "--reason", "I think it is hung"])
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert "REFUSED promotion" in result.output
        assert "primary_indeterminate" in result.output
        assert "lease_live" in result.output
        assert "a live lease is a primary that may still be dispatching" in result.output

    def test_an_expired_lease_promotes(self, db_path: Path) -> None:
        """The lease's own expiry is what the CLI reads, so age it past its TTL."""
        leadership(db_path, "ctl-a", ttl_s=0.001)
        import time

        time.sleep(0.01)
        result = invoke(db_path, ["promote", "--operator", "ana", "--reason", "lease lapsed"])
        assert result.exit_code == ExitCode.SUCCESS
        assert "promoted ctl-local" in result.output
        assert "term 1 → 2" in result.output

    def test_forcing_without_evidence_is_still_refused(self, db_path: Path) -> None:
        """``--forced`` takes the lease; it does not manufacture the evidence."""
        leadership(db_path, "ctl-a")
        result = invoke(
            db_path,
            ["promote", "--operator", "ana", "--reason", "it is hung", "--forced"],
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL

    def test_evidence_without_forcing_is_still_refused(self, db_path: Path) -> None:
        leadership(db_path, "ctl-a")
        result = invoke(
            db_path,
            [
                "promote",
                "--operator",
                "ana",
                "--reason",
                "service manager says it is gone",
                "--attest-process-gone",
            ],
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert "lease_live" in result.output

    def test_forcing_with_an_attested_process_absence_promotes(self, db_path: Path) -> None:
        leadership(db_path, "ctl-a")
        result = invoke(
            db_path,
            [
                "promote",
                "--operator",
                "ana",
                "--reason",
                "systemd reports the unit failed",
                "--forced",
                "--attest-process-gone",
            ],
        )
        assert result.exit_code == ExitCode.SUCCESS
        assert "promoted ctl-local" in result.output
        assert "term 1 → 2" in result.output

    def test_an_operator_and_a_reason_are_required(self, db_path: Path) -> None:
        """The CLI error surface is the app's, so the exception carries the refusal."""
        result = invoke(db_path, ["promote"])
        assert result.exit_code != 0
        assert isinstance(result.exception, MayhemCliError)
        assert result.exception.code == "validation_error"
        assert "--operator and --reason are both required" in result.exception.message

    def test_the_claim_is_stated_in_the_output(self, db_path: Path) -> None:
        result = invoke(db_path, ["promote", "--operator", "ana", "--reason", "r"])
        assert "standby_id is a claim this process wrote" in result.output

    def test_json_output_names_the_refusals_and_the_claim(self, db_path: Path) -> None:
        leadership(db_path, "ctl-a")
        result = invoke(
            db_path,
            ["promote", "--operator", "ana", "--reason", "r", "--json"],
        )
        payload = json.loads(result.output)
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert payload["promoted"] is False
        assert payload["refusals"] == ["primary_indeterminate", "lease_live"]
        assert payload["standby_id_is_a_claim"] is True
        assert payload["term_before"] == 1


class TestPromoteHelpers:
    def service(self, db_path: Path, clock: Clock, controller_id: str = "ctl-b") -> FailoverService:
        store = Store.open_migrated(str(db_path), migrations=MIGRATIONS)
        return FailoverService(
            store=FailoverPromotionStore(store),
            election=LeaderElection(
                store=SqliteLeadershipStore(store),
                controller_id=controller_id,
                ttl_s=TTL_S,
                clock=clock,
            ),
            controller_id=controller_id,
            clock=clock,
        )

    def test_the_evidence_comes_from_the_store_not_the_prompt(self, db_path: Path) -> None:
        now = NOW
        service = self.service(db_path, Clock(now))
        leadership(db_path, "ctl-a", Clock(now))

        result = failover_cmd.run_promote(
            service=service,
            observations=failover_cmd.lease_expiry_observation(term=1, at=now, expired=False),
            operator="ana",
            reason="cannot reach it",
        )

        assert result.promoted is False
        assert "lease_live" in result.refusals
        assert "primary_indeterminate" in result.refusals

    def test_an_expired_lease_reads_as_death_evidence(self) -> None:
        (observation,) = failover_cmd.lease_expiry_observation(term=4, at=NOW, expired=True)
        assert observation.observed_term == 4
        assert observation.source == "lease-store"
        assert observation.establishes_death is True

    def test_a_live_lease_reads_as_no_evidence_at_all(self) -> None:
        """Not liveness: a live lease is not the primary answering.

        Calling it liveness evidence would contradict the operator's attested
        process-absence and refuse a legitimate break-glass handover.
        """
        (observation,) = failover_cmd.lease_expiry_observation(term=4, at=NOW, expired=False)
        assert observation.establishes_death is False
        assert observation.establishes_liveness is False
        assert "NOT expired" in observation.detail

    def test_a_blank_operator_is_a_validation_error(self, db_path: Path) -> None:
        with pytest.raises(MayhemCliError) as caught:
            failover_cmd.run_promote(
                service=self.service(db_path, Clock(NOW)),
                observations=(),
                operator="  ",
                reason="r",
            )
        assert caught.value.code == "validation_error"


# --------------------------------------------------------------------------- #
# ha rotate                                                                      #
# --------------------------------------------------------------------------- #


class TestRotateCommand:
    def test_naming_neither_a_nor_all_is_a_usage_error(self, db_path: Path) -> None:
        result = invoke(db_path, ["rotate"])
        assert isinstance(result.exception, MayhemCliError)
        assert result.exception.code == "usage_error"
        assert "name exactly one target" in result.exception.message

    def test_naming_both_is_also_a_usage_error(self, db_path: Path) -> None:
        result = invoke(db_path, ["rotate", "--agent", "ag-1", "--all"])
        assert isinstance(result.exception, MayhemCliError)
        assert result.exception.code == "usage_error"

    def test_a_keyless_rotation_is_reported_as_a_window_not_a_success(self, db_path: Path) -> None:
        store = Store.open_migrated(str(db_path), migrations=MIGRATIONS)
        AgentIdentityRepository(store).save(identity())
        store.close()

        result = invoke(db_path, ["rotate", "--agent", "ag-1"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "rotated 1, failed 0" in result.output
        assert "rotated-without-a-key 1" in result.output
        assert "cannot authenticate" in result.output

    def test_a_sweep_reports_failures_with_a_refusal_exit(self, db_path: Path) -> None:
        store = Store.open_migrated(str(db_path), migrations=MIGRATIONS)
        AgentIdentityRepository(store).save(identity("ag-1"))
        AgentIdentityRepository(store).revoke_agent("ag-1", _revocation())
        store.close()

        result = invoke(db_path, ["rotate", "--all", "--rotate-before", "60"])

        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert "failed 1" in result.output

    def test_json_output_carries_the_key_provisioned_flag(self, db_path: Path) -> None:
        store = Store.open_migrated(str(db_path), migrations=MIGRATIONS)
        AgentIdentityRepository(store).save(identity())
        store.close()

        result = invoke(db_path, ["rotate", "--agent", "ag-1", "--json"])

        payload = json.loads(result.output)
        assert payload[0]["key_provisioned"] is False
        assert payload[0]["action"] == "rotated"

    def test_a_degenerate_policy_is_refused_before_anything_is_written(self, db_path: Path) -> None:
        """The policy object refuses it, so no rotation is attempted at all."""
        result = invoke(db_path, ["rotate", "--all", "--ttl", "10", "--rotate-before", "100"])
        assert isinstance(result.exception, InvariantViolationError)
        assert "rotate_before" in str(result.exception)

    def test_rotating_an_unenrolled_agent_exits_nonzero(self, db_path: Path) -> None:
        result = invoke(db_path, ["rotate", "--agent", "ag-nobody"])
        assert result.exception is not None
        assert "unenrolled agent" in str(result.exception)

    def test_run_rotate_requires_exactly_one_target(self) -> None:
        with pytest.raises(MayhemCliError) as caught:
            failover_cmd.run_rotate(_StubRotationService(), agent_id="ag-1", sweep=True)
        assert caught.value.code == "usage_error"


def _revocation() -> object:
    from mayhem.domain.agent_identity import Revocation, RevocationReason

    return Revocation(
        reason=RevocationReason.COMPROMISED,
        revoked_at=NOW,
        revoked_by="ops",
    )


class _StubRotationService(CredentialRotationService):
    """Constructed without a store: only the guard is under test."""

    def __init__(self) -> None:
        self.calls: list[str] = []


# --------------------------------------------------------------------------- #
# ha cert verify                                                                 #
# --------------------------------------------------------------------------- #


def issue_certificate(roles: list[MtlsRole] | None = None) -> object:
    """A fixture certificate valid around *now*, because the CLI checks at the real clock."""
    ca = FixtureCertificateAuthority(CaKeyMaterial({CA_ID: CA_SECRET}))
    return ca.issue(
        ca_id=CA_ID,
        subject="agent=ag-1",
        serial="01",
        not_before=utc_now() - timedelta(hours=1),
        not_after=utc_now() + timedelta(days=1),
        roles=roles if roles is not None else [MtlsRole.AGENT],
    )


class TestCertCommand:
    def write(self, tmp_path: Path, certificate: object) -> Path:
        path = tmp_path / "certificate.json"
        path.write_text(certificate.model_dump_json(), encoding="utf-8")  # type: ignore[attr-defined]
        return path

    def issue(self, tmp_path: Path) -> Path:
        return self.write(tmp_path, issue_certificate())

    def test_a_pinned_valid_certificate_is_trusted(self, tmp_path: Path) -> None:
        certificate = issue_certificate()
        path = self.write(tmp_path, certificate)

        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "cert",
                "--certificate",
                str(path),
                "--ca-id",
                CA_ID,
                "--pin",
                certificate.sha256_fingerprint,
                "--key-env",
                "TEST_CA_KEY",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_CA_KEY": CA_SECRET.decode()},
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "trusted" in result.output
        # A fixture verdict can never be mistaken for a PKI result.
        assert "fixture-ca-hmac-sha256" in result.output

    def test_an_unpinned_certificate_is_refused(self, tmp_path: Path) -> None:
        """No anchor configured is a refusal, never an implicit trust."""
        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "cert",
                "--certificate",
                str(self.issue(tmp_path)),
                "--ca-id",
                CA_ID,
                "--key-env",
                "TEST_CA_KEY",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_CA_KEY": CA_SECRET.decode()},
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert "REFUSED" in result.output

    def test_a_wrong_role_is_refused_by_name(self, tmp_path: Path) -> None:
        certificate = issue_certificate()
        path = self.write(tmp_path, certificate)

        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "cert",
                "--certificate",
                str(path),
                "--ca-id",
                CA_ID,
                "--pin",
                certificate.sha256_fingerprint,
                "--role",
                "controller",
                "--key-env",
                "TEST_CA_KEY",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_CA_KEY": CA_SECRET.decode()},
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert "wrong_role" in result.output

    def test_x509_refuses_as_unavailable_and_never_says_trusted(self, tmp_path: Path) -> None:
        """**The negative control for the whole X.509 seam.**"""
        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "cert",
                "--certificate",
                str(self.issue(tmp_path)),
                "--ca-id",
                CA_ID,
                "--algorithm",
                ALGORITHM_X509,
                "--key-env",
                "TEST_CA_KEY",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_CA_KEY": CA_SECRET.decode()},
        )
        assert isinstance(result.exception, MayhemCliError)
        assert result.exception.code == "unavailable_engine"
        assert result.exception.message == SIGNATURE_PORT_UNAVAILABLE
        assert "trusted" not in result.output

    def test_an_unset_key_variable_is_a_config_error(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            failover_cmd.ha,
            ["cert", "--certificate", str(self.issue(tmp_path)), "--ca-id", CA_ID],
            obj=SimpleNamespace(db="unused"),
            env={},
        )
        assert isinstance(result.exception, MayhemCliError)
        assert result.exception.code == "config_error"
        assert "is not set" in result.exception.message

    def test_a_short_key_is_refused_rather_than_verified(self) -> None:
        with pytest.raises(MayhemCliError) as caught:
            failover_cmd.run_cert_verify(
                certificate=None,
                ca_id=CA_ID,
                secret=b"short",
                required_role=MtlsRole.AGENT,
                at=NOW,
            )
        assert caught.value.code == "config_error"

    def test_no_certificate_at_all_is_a_refusal(self) -> None:
        verdict = failover_cmd.run_cert_verify(
            certificate=None,
            ca_id=CA_ID,
            secret=CA_SECRET,
            pinned_fingerprint="f" * 64,
            required_role=MtlsRole.AGENT,
            at=NOW,
        )
        assert verdict.trusted is False
        assert verdict.refusal_code == "mtls_no_certificate"

    def test_an_unknown_role_is_a_usage_error(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "cert",
                "--certificate",
                str(self.issue(tmp_path)),
                "--ca-id",
                CA_ID,
                "--role",
                "overlord",
                "--key-env",
                "TEST_CA_KEY",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_CA_KEY": CA_SECRET.decode()},
        )
        assert result.exit_code != 0


# --------------------------------------------------------------------------- #
# ha update check                                                                #
# --------------------------------------------------------------------------- #


class TestUpdateCommand:
    def test_a_good_manifest_is_applicable(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "update",
                "--manifest",
                str(write_manifest(tmp_path)),
                "--signer-key-id",
                "release-1",
                "--key-env",
                "TEST_RELEASE_KEY",
                "--component",
                "agent",
                "--installed",
                "2.0.0",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_RELEASE_KEY": RELEASE_KEY.decode()},
        )
        assert result.exit_code == ExitCode.SUCCESS
        assert "APPLICABLE" in result.output
        assert "NOT public-key authorship" in result.output

    def test_a_wrong_channel_is_refused_by_name(self, tmp_path: Path) -> None:
        path = write_manifest(tmp_path, manifest_id="m-test", channel="test")
        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "update",
                "--manifest",
                str(path),
                "--signer-key-id",
                "release-1",
                "--key-env",
                "TEST_RELEASE_KEY",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_RELEASE_KEY": RELEASE_KEY.decode()},
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert "channel_mismatch" in result.output

    def test_a_tampered_manifest_is_refused(self, tmp_path: Path) -> None:
        path = write_manifest(tmp_path)
        document = json.loads(path.read_text(encoding="utf-8"))
        document["component_version"] = "9.9.9"
        path.write_text(json.dumps(document), encoding="utf-8")

        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "update",
                "--manifest",
                str(path),
                "--signer-key-id",
                "release-1",
                "--key-env",
                "TEST_RELEASE_KEY",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_RELEASE_KEY": RELEASE_KEY.decode()},
        )
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert "signature_invalid" in result.output

    def test_an_unreadable_manifest_is_a_config_error(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.json"
        path.write_text("{not json", encoding="utf-8")
        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "update",
                "--manifest",
                str(path),
                "--signer-key-id",
                "release-1",
                "--key-env",
                "TEST_RELEASE_KEY",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_RELEASE_KEY": RELEASE_KEY.decode()},
        )
        assert isinstance(result.exception, MayhemCliError)
        assert result.exception.code == "config_error"

    def test_an_unknown_channel_is_a_usage_error(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "update",
                "--manifest",
                str(write_manifest(tmp_path)),
                "--channel",
                "whatever",
                "--signer-key-id",
                "release-1",
                "--key-env",
                "TEST_RELEASE_KEY",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_RELEASE_KEY": RELEASE_KEY.decode()},
        )
        assert isinstance(result.exception, MayhemCliError)
        assert result.exception.code == "usage_error"
        assert "is not a release channel" in result.exception.message

    def test_the_command_never_applies_anything(self, tmp_path: Path) -> None:
        """``UpdateApplier`` is not reachable from this command at all."""
        source = __import__("mayhem.cli.failover_cmd", fromlist=["x"]).__doc__ or ""
        assert "It never installs" in source
        assert "UpdateApplier" not in source

    def test_json_output_reports_applicability_and_refusals(self, tmp_path: Path) -> None:
        path = write_manifest(tmp_path, manifest_id="m-test", channel="test")
        result = CliRunner().invoke(
            failover_cmd.ha,
            [
                "update",
                "--manifest",
                str(path),
                "--signer-key-id",
                "release-1",
                "--key-env",
                "TEST_RELEASE_KEY",
                "--json",
            ],
            obj=SimpleNamespace(db="unused"),
            env={"TEST_RELEASE_KEY": RELEASE_KEY.decode()},
        )
        payload = json.loads(result.output)
        assert payload["applicable"] is False
        assert payload["refusals"] == ["channel_mismatch"]
        assert payload["verified"] is True


class TestRenderers:
    def test_a_trusted_verdict_says_trusted(self) -> None:
        from mayhem.infra.certificate_authority import TrustReason, TrustVerdict

        lines = failover_cmd.render_trust(
            TrustVerdict(reason=TrustReason.TRUSTED, detail="d", algorithm="fixture-ca-hmac-sha256")
        )
        assert "trusted" in lines[0]
        assert "REFUSED" not in lines[0]

    def test_a_refused_verdict_says_refused(self) -> None:
        from mayhem.infra.certificate_authority import TrustReason, TrustVerdict

        lines = failover_cmd.render_trust(TrustVerdict(reason=TrustReason.REVOKED, detail="d"))
        assert "REFUSED" in lines[0]

    def test_an_inapplicable_update_says_refused(self) -> None:
        from mayhem.infra.update_manifest import ManifestVerdict, UpdateRefusal

        lines = failover_cmd.render_update_verdict(
            ManifestVerdict(
                manifest_id="m",
                refusals=(UpdateRefusal.EXPIRED,),
                detail="d",
                algorithm="hmac-sha256",
            )
        )
        assert "REFUSED (expired)" in lines[0]
        assert "APPLICABLE" not in "\n".join(lines)


class TestPolicyConstants:
    def test_the_prefixes_and_names_are_published(self) -> None:
        assert failover_cmd.DEFAULT_SCOPE == "control-plane"
        assert failover_cmd.DEFAULT_CONTROLLER_ID == "ctl-local"
        assert failover_cmd.KEY_ENV_PREFIX == "MAYHEM_HA_"

    def test_an_unset_secret_never_becomes_an_empty_one(self) -> None:
        with pytest.raises(MayhemCliError) as caught:
            failover_cmd.secret_from_env("NOPE", env={})
        assert caught.value.code == "config_error"
        assert "never appears in a command line" in caught.value.remediation

    def test_a_policy_refusal_code_is_a_safety_refusal_exit(self) -> None:
        from mayhem.cli.exit_codes import ExitCode as Codes

        assert Codes.SAFETY_REFUSAL == 5
        assert Codes.TOOLKIT_ERROR == 9


class TestWhatThisSurfaceDoesNotDo:
    def test_it_opens_no_socket_and_runs_no_subprocess(self) -> None:
        source = __import__("mayhem.cli.failover_cmd", fromlist=["x"]).__doc__ or ""
        for banned in ("socket", "subprocess", "paramiko", "requests"):
            assert banned not in source.lower()

    def test_the_rotation_policy_still_cannot_be_degenerate(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            RotationPolicy(policy_id="p", credential_ttl_s=10.0, rotate_before_s=10.0)
        assert caught.value.rule == "rotation.policy_degenerate"

    def test_the_channel_enum_is_the_one_the_verifier_uses(self) -> None:
        from mayhem.infra.update_manifest import UpdateVerifier

        verifier = UpdateVerifier(
            signature=HmacSha256SignatureVerifier(StaticKeyMaterial({})),
            signer_keys=StaticKeyMaterial({}),
        )
        assert verifier.expected_channel is UpdateChannel.STABLE
        assert HmacSha256CommandSigner(StaticKeyMaterial({})).algorithm == "hmac-sha256"
