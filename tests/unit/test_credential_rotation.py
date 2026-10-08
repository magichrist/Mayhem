"""Plan 19 Phase 3 — policy-level credential rotation, and what a rotation does
*not* do.

Phase 2's ledger recorded the gap this closes: ``rotate_before`` and
``rotation_grace`` lived on each credential, so two agents could carry different
discipline. :class:`RotationPolicy` is the one deployment-wide answer, and this
file is what proves the sweep applies it honestly.

The properties under test:

* **Due-ness is derived from the policy and the window, never from a flag.** A
  fresh credential is not due; one inside ``rotate_before_s`` of expiry is; a
  revoked identity is due *and* cannot rotate (it must be re-enrolled), and the
  verdict says so.
* **A rotation that cannot reach its store refuses rather than reporting
  success.** The load-bearing negative control: :meth:`rotate` on an unenrolled
  agent raises, a sweep converts a policy refusal into a ``FAILED`` outcome, a
  **closed** store raises out of the sweep rather than being swallowed into a
  success, and no outcome claims ``ROTATED`` in any of those cases.
  ``sweep_summary`` counts ``failed`` and ``without_key`` separately, because a
  summary that reported only ``rotated`` would render a sweep that broke every
  agent as a healthy one.
* **A rotation without key custody is a fail-closed window, and says so.**
  ``key_provisioned`` is ``False`` with no provisioner bound and also ``False``
  when a bound provisioner returns nothing, and the consequence is proved against
  the real :class:`~mayhem.infra.agent_identity_verifier.AgentCommandVerifier`:
  immediately after a rotation the *old* key is refused (the identity no longer
  names it) and the *new* one verifies nothing (no key resolves for it). A
  rotation whose overlap let the old key keep working would not have rotated
  anything.
* **Revocation goes through the append-only ledger**, and the sweep is per-agent:
  one agent's refusal does not stop the other ninety-nine from rotating.
* A degenerate policy — one that makes every credential overdue the moment it is
  issued — is refused at construction, so a deployment cannot configure itself
  into a sweep that rotates forever.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.controller.credential_rotation import (
    DEFAULT_POLICY_LEAD_S,
    DEFAULT_POLICY_TTL_S,
    CredentialRotationService,
    RotationAction,
    RotationPolicy,
    RotationVerdict,
    credential_window,
    sweep_summary,
)
from mayhem.domain.agent_identity import (
    AgentCredential,
    AgentIdentity,
    CertificateRef,
    Revocation,
    RevocationReason,
    TrustAnchorRef,
)
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.fabric import (
    FABRIC_PROTOCOL_VERSION,
    CommandBodyRef,
    FabricCommand,
    FabricCommandType,
    FencingToken,
)
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.infra.agent_identity_store import AgentIdentityRepository
from mayhem.infra.agent_identity_verifier import (
    AgentCommandVerifier,
    CommandRefusedError,
    HmacSha256CommandSigner,
    HmacSha256SignatureVerifier,
    StaticKeyMaterial,
    VerificationCheck,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
TTL_S = 900.0
LEAD_S = 300.0
SECRET = b"s" * 32
FINGERPRINT = "f" * 64
PLAN_DIGEST = "a" * 64
NONCE = "0123456789abcdef0123456789abcdef"
RUN_ID = "r-1"
STEP_ID = "s-1"


class Clock:
    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def identity(
    agent_id: str = "ag-1", *, ttl_s: float = TTL_S, issued_at: datetime | None = None
) -> AgentIdentity:
    issued = NOW - timedelta(seconds=60) if issued_at is None else issued_at
    return AgentIdentity(
        agent_id=agent_id,
        controller_id="ctl-a",
        principal=Principal(principal_id=f"sa-{agent_id}", kind=PrincipalKind.WORKLOAD),
        scope=EnvironmentScope(environment="staging"),
        credential=AgentCredential(
            credential_id=f"{agent_id}-c1",
            agent_id=agent_id,
            issued_at=issued,
            expires_at=issued + timedelta(seconds=ttl_s),
            rotate_before=LEAD_S,
        ),
        certificate=CertificateRef(
            subject=f"agent={agent_id}",
            issuer="ca-mesh-1",
            serial="01",
            sha256_fingerprint=FINGERPRINT,
            not_before=NOW - timedelta(hours=1),
            not_after=NOW + timedelta(days=1),
        ),
        trust_anchors=(
            TrustAnchorRef(ca_id="ca-mesh-1", subject="ca-mesh-1", sha256_fingerprint=FINGERPRINT),
        ),
    )


class Provisioner:
    """A bound key custodian. Returns ``None`` for a credential it cannot serve."""

    def __init__(self, *, serves: set[str] | None = None) -> None:
        self.serves = serves
        self.asked: list[tuple[str, str]] = []

    def provision(self, *, agent_id: str, credential_id: str) -> str | None:
        self.asked.append((agent_id, credential_id))
        if self.serves is not None and credential_id not in self.serves:
            return None
        return f"key::{credential_id}"


@pytest.fixture
def store() -> Iterator[Store]:
    opened = Store.open_migrated(":memory:", migrations=ALL_MIGRATIONS)
    yield opened
    opened.close()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def identities(store: Store) -> AgentIdentityRepository:
    return AgentIdentityRepository(store)


def policy(**over: object) -> RotationPolicy:
    fields: dict[str, object] = {
        "policy_id": "p-strict",
        "credential_ttl_s": TTL_S,
        "rotate_before_s": LEAD_S,
    }
    fields.update(over)
    return RotationPolicy.model_validate(fields)


def service(
    identities: AgentIdentityRepository,
    clock: Clock,
    *,
    provisioner: Provisioner | None = None,
    **policy_fields: object,
) -> CredentialRotationService:
    return CredentialRotationService(
        identities=identities,
        policy=policy(**policy_fields),
        provisioner=provisioner,
        clock=clock,
    )


def command(signing_key_id: str, *, nonce: str) -> FabricCommand:
    return FabricCommand(
        protocol=FABRIC_PROTOCOL_VERSION,
        command_id=f"fc-{signing_key_id}",
        run_id=RUN_ID,
        step_id=STEP_ID,
        agent_id="ag-1",
        plan_digest=PLAN_DIGEST,
        nonce=nonce,
        idempotency_key=f"idem-{signing_key_id}",
        fencing_token=FencingToken(
            run_id=RUN_ID, step_id=STEP_ID, holder="ctl-a", epoch=1, issued_at=NOW
        ),
        command=CommandBodyRef(
            command_type=FabricCommandType.PREPARE, body_digest="b" * 64, body_ref="body-1"
        ),
        issued_at=NOW.isoformat(),
        signing_key_id=signing_key_id,
        signature="A" * 64,
    )


def unsigned_fields(envelope: FabricCommand) -> dict[str, object]:
    return dict(envelope.model_dump(mode="json", exclude={"signature"}))


# --------------------------------------------------------------------------- #
# The policy                                                                     #
# --------------------------------------------------------------------------- #


class TestRotationPolicy:
    def test_the_due_and_overdue_instants_are_derived_from_the_window(self) -> None:
        expires = NOW + timedelta(seconds=TTL_S)
        assert policy().due_at(expires, NOW) == expires - timedelta(seconds=LEAD_S)
        assert policy().overdue_at(expires) == expires

    def test_a_degenerate_policy_is_refused_at_construction(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            policy(rotate_before_s=TTL_S)
        assert caught.value.rule == "rotation.policy_degenerate"

    def test_the_defaults_are_stated_on_the_module(self) -> None:
        assert DEFAULT_POLICY_TTL_S == TTL_S
        assert DEFAULT_POLICY_LEAD_S == LEAD_S
        assert "due" in policy().describe()

    def test_the_credentials_own_window_is_still_readable_for_comparison(self) -> None:
        """The disagreement this policy object was introduced to remove stays visible."""
        window = credential_window(identity().credential)
        assert window.due_at == window.expires_at - timedelta(seconds=LEAD_S)
        assert window.is_open(NOW) is True
        assert window.is_due(window.due_at) is True


# --------------------------------------------------------------------------- #
# The survey                                                                     #
# --------------------------------------------------------------------------- #


class TestTheSurvey:
    def test_a_fresh_credential_is_not_due(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        (verdict,) = service(identities, clock).survey()
        assert verdict.due is False
        assert verdict.overdue is False
        assert "not due" in verdict.describe()
        assert verdict.generation == 1

    def test_a_credential_inside_the_lead_time_is_due(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        (verdict,) = service(identities, clock).survey(at=clock.advance(TTL_S - LEAD_S + 1))
        assert verdict.due is True
        assert verdict.overdue is False

    def test_an_expired_credential_is_overdue(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        (verdict,) = service(identities, clock).survey(at=clock.advance(TTL_S + 1))
        assert verdict.due is True
        assert verdict.overdue is True

    def test_a_revoked_identity_is_due_and_says_it_can_never_rotate(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        identities.revoke_agent(
            "ag-1",
            Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by="ops"),
        )
        (verdict,) = service(identities, clock).survey()
        assert verdict.due is True
        assert "can never rotate and must be re-enrolled" in verdict.reason

    def test_the_survey_is_ordered_by_agent_id(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        for agent in ("ag-3", "ag-1", "ag-2"):
            identities.save(identity(agent))
        assert [v.agent_id for v in service(identities, clock).survey()] == [
            "ag-1",
            "ag-2",
            "ag-3",
        ]

    def test_an_empty_store_surveys_to_nothing(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        svc = service(identities, clock)
        assert svc.survey() == ()
        assert svc.due_agents() == ()


# --------------------------------------------------------------------------- #
# Rotating                                                                       #
# --------------------------------------------------------------------------- #


class TestRotate:
    def test_a_rotation_issues_a_strictly_newer_credential(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        outcome = service(identities, clock).rotate("ag-1", at=NOW)

        assert outcome.rotated is True
        assert outcome.from_credential == "ag-1-c1"
        assert outcome.to_credential == "ag-1-c2"
        assert outcome.generation == 2
        reloaded = identities.load("ag-1")
        assert reloaded is not None
        assert reloaded.credential.credential_id == "ag-1-c2"
        assert reloaded.credential.rotation_state.value == "current"

    def test_the_successor_credential_id_can_be_named(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        outcome = service(identities, clock).rotate("ag-1", credential_id="ag-1-spring", at=NOW)
        assert outcome.to_credential == "ag-1-spring"

    def test_a_rotation_without_custody_reports_no_key(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        svc = service(identities, clock)

        outcome = svc.rotate("ag-1", at=NOW)

        assert svc.provisions_keys is False
        assert outcome.key_provisioned is False
        assert "cannot authenticate until one is" in outcome.describe()

    def test_a_bound_provisioner_that_returns_nothing_is_not_a_success(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        provisioner = Provisioner(serves=set())

        outcome = service(identities, clock, provisioner=provisioner).rotate("ag-1", at=NOW)

        assert provisioner.asked == [("ag-1", "ag-1-c2")]
        assert outcome.key_provisioned is False
        assert "returned no key" in outcome.detail

    def test_a_bound_provisioner_that_serves_reports_the_key(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        outcome = service(identities, clock, provisioner=Provisioner()).rotate("ag-1", at=NOW)
        assert outcome.key_provisioned is True
        assert "key::ag-1-c2" in outcome.detail

    def test_rotating_an_unenrolled_agent_raises(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        with pytest.raises(DomainError) as caught:
            service(identities, clock).rotate("ag-nobody", at=NOW)
        assert "unenrolled agent" in str(caught.value)


class TestTheFailClosedWindow:
    """The consequence of a keyless rotation, proved against the real verifier."""

    @staticmethod
    def _verifier(store: Store, *key_ids: str) -> AgentCommandVerifier:
        """A verifier whose key port resolves only ``key_ids``."""
        return AgentCommandVerifier(
            identities=AgentIdentityRepository(store),
            signature=HmacSha256SignatureVerifier(
                StaticKeyMaterial(dict.fromkeys(key_ids, SECRET))
            ),
            nonces=None,
        )

    def test_the_old_key_stops_working_and_the_new_one_has_no_key_yet(
        self, store: Store, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        # The key port knows the *old* credential only: no provisioner ran.
        verifier = self._verifier(store, "ag-1-c1")
        signer = HmacSha256CommandSigner(StaticKeyMaterial({"ag-1-c1": SECRET}))
        before = signer.sign_fields(  # type: ignore[arg-type]
            unsigned_fields(command("ag-1-c1", nonce=NONCE))
        )
        assert (
            verifier.verify(before, expected_plan_digest=PLAN_DIGEST, now=NOW).command.nonce
            == NONCE
        )

        service(identities, clock).rotate("ag-1", at=NOW)

        with pytest.raises(CommandRefusedError) as caught:
            verifier.verify(before, expected_plan_digest=PLAN_DIGEST, now=NOW)
        assert VerificationCheck.KEY_BINDING in caught.value.failed

        # Somebody holding a key for the new credential signs honestly: it still
        # verifies nothing, because no key resolves for it at this end.
        holder = HmacSha256CommandSigner(StaticKeyMaterial({"ag-1-c2": SECRET}))
        after = holder.sign_fields(  # type: ignore[arg-type]
            unsigned_fields(command("ag-1-c2", nonce="f" * 32))
        )
        with pytest.raises(CommandRefusedError) as caught:
            verifier.verify(after, expected_plan_digest=PLAN_DIGEST, now=NOW)
        assert VerificationCheck.SIGNATURE in caught.value.failed

    def test_a_provisioned_key_makes_the_new_credential_usable(
        self, store: Store, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        """The other half of the story: with custody bound, the window closes."""
        identities.save(identity())
        service(identities, clock, provisioner=Provisioner()).rotate("ag-1", at=NOW)
        signer = HmacSha256CommandSigner(StaticKeyMaterial({"ag-1-c2": SECRET}))

        signed = signer.sign_fields(  # type: ignore[arg-type]
            unsigned_fields(command("ag-1-c2", nonce="e" * 32))
        )

        verified = self._verifier(store, "ag-1-c2").verify(
            signed, expected_plan_digest=PLAN_DIGEST, now=NOW
        )
        assert verified.command.signing_key_id == "ag-1-c2"


# --------------------------------------------------------------------------- #
# The sweep                                                                      #
# --------------------------------------------------------------------------- #


class TestTheSweep:
    def test_it_rotates_every_due_agent(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity("ag-1"))
        identities.save(identity("ag-2"))

        outcomes = service(identities, clock).rotate_due(at=clock.advance(TTL_S - LEAD_S + 1))

        assert [o.agent_id for o in outcomes] == ["ag-1", "ag-2"]
        assert all(o.rotated for o in outcomes)
        reloaded = identities.load("ag-1")
        assert reloaded is not None
        assert reloaded.credential.credential_id == "ag-1-c2"

    def test_nothing_is_due_before_the_lead_time(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        assert service(identities, clock).rotate_due(at=NOW) == ()

    def test_a_limit_bounds_the_sweep(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        for agent in ("ag-1", "ag-2", "ag-3"):
            identities.save(identity(agent))
        at = clock.advance(TTL_S - LEAD_S + 1)
        assert len(service(identities, clock).rotate_due(at=at, limit=2)) == 2
        assert service(identities, clock).rotate_due(at=at, limit=0) == ()

    def test_one_agents_refusal_does_not_stop_the_sweep(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        """A revoked identity must not prevent the other credentials from rotating."""
        identities.save(identity("ag-1"))
        identities.save(identity("ag-2"))
        identities.revoke_agent(
            "ag-1",
            Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by="ops"),
        )

        outcomes = service(identities, clock).rotate_due(at=clock.advance(TTL_S + 1))

        by_agent = {outcome.agent_id: outcome for outcome in outcomes}
        assert by_agent["ag-1"].failed is True
        assert "rotation refused" in by_agent["ag-1"].detail
        assert by_agent["ag-2"].rotated is True

    def test_a_sweep_that_cannot_reach_its_store_does_not_report_success(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        """**The negative control.**

        A closed store raises out of the sweep rather than being converted into an
        outcome, because the sweep only converts *policy* refusals
        (``DomainError``) into ``FAILED``. An IO failure reaching the caller is the
        honest shape: mayhem does not know whether anything was rotated, and the
        only honest report is that the sweep did not complete.
        """
        identities.save(identity())
        identities._store.close()

        with pytest.raises(sqlite3.ProgrammingError):
            service(identities, clock).rotate_due(at=clock.advance(TTL_S + 1))

    def test_the_summary_counts_failures_and_keyless_rotations_separately(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity("ag-1"))
        identities.save(identity("ag-2"))
        identities.revoke_agent(
            "ag-1",
            Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by="ops"),
        )
        provisioner = Provisioner(serves={"ag-2-c2"})

        outcomes = service(identities, clock, provisioner=provisioner).rotate_due(
            at=clock.advance(TTL_S + 1)
        )

        assert sweep_summary(outcomes) == {
            "agents": 2,
            "rotated": 1,
            "revoked": 0,
            "failed": 1,
            "skipped": 0,
            "without_key": 0,
        }

    def test_a_sweep_with_no_custody_counts_every_rotation_as_keyless(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity("ag-1"))
        outcomes = service(identities, clock).rotate_due(at=clock.advance(TTL_S + 1))
        assert sweep_summary(outcomes)["without_key"] == 1


# --------------------------------------------------------------------------- #
# Revocation                                                                     #
# --------------------------------------------------------------------------- #


class TestRevocation:
    def test_it_uses_the_append_only_ledger_and_leaves_one_row(
        self, store: Store, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())

        outcome = service(identities, clock).revoke(
            "ag-1", reason=RevocationReason.COMPROMISED, revoked_by="ops", at=NOW
        )

        assert outcome.action is RotationAction.REVOKED
        # The key note is a statement about rotation, so a revocation does not
        # claim the agent is waiting for a provisioner to fix it.
        assert "NO signing key provisioned" not in outcome.describe()
        assert len(store.query("SELECT scope FROM agent_credential_revocations")) == 1
        reloaded = identities.load("ag-1")
        assert reloaded is not None
        assert reloaded.revoked is True

    def test_revoking_an_unenrolled_agent_raises(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        with pytest.raises(DomainError):
            service(identities, clock).revoke(
                "ag-nobody", reason=RevocationReason.COMPROMISED, revoked_by="ops", at=NOW
            )

    def test_a_revoked_identity_cannot_be_rotated_back(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        identities.revoke_agent(
            "ag-1",
            Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by="ops"),
        )
        with pytest.raises((DomainError, InvariantViolationError)):
            service(identities, clock).rotate("ag-1", at=clock.advance(1))


class TestServiceShape:
    def test_it_holds_no_state_so_a_second_service_agrees(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity())
        first = service(identities, clock)
        second = service(identities, clock)
        assert first.survey() == second.survey()
        assert first.policy.policy_id == second.policy.policy_id

    def test_a_verdict_can_be_asked_for_one_identity(
        self, identities: AgentIdentityRepository, clock: Clock
    ) -> None:
        identities.save(identity("ag-1"))
        verdict = service(identities, clock).verdict_for(identity("ag-2"))
        assert isinstance(verdict, RotationVerdict)
        assert verdict.agent_id == "ag-2"
        assert verdict.due is False
