"""Plan 19 Phase 3 — promoting a standby, the durable record of it, and the drills
that prove a deposed holder loses.

This file is the plan's highest-consequence operation under test, against a real
migrated SQLite database and two :class:`~mayhem.controller.leader_election.
LeaderElection` objects over it — which is what a failover actually is: the
second object is a second controller, not a method call on the first.

The property under test, in one sentence: **a standby is promoted only when a
durable record says the primary is gone, and the instant the promotion lands, the
previous holder stops authorising anything.**

Concretely, each with its negative control:

* :meth:`FailoverService.promote_if_dead` **refuses** on the canonical partition
  observations (``PROBE_UNREACHABLE``, ``HEARTBEAT_MISSING``,
  ``STALE_READ_REPLICA``, ``NO_EVIDENCE``) and the stored term does not move. The
  refusal is still recorded, because "we saw the partition and did not promote"
  is the record an incident review needs. *Cannot determine liveness* must never
  mean *promote*.
* An expired leadership lease in the replicated store **does** promote, and the
  new term is strictly greater — a takeover that does not move the term forward
  is unrepresentable in the domain and unpromotable here.
* A **live** foreign lease is refused (``LEASE_LIVE``) unless the operator forced
  it. When forced, the term still strictly increases, so the deposed leader is
  refused by :meth:`LeaderElection.require_leader` *immediately*, and a deposed
  leader that tries to dispatch is refused before the dispatcher is ever called.
  An unexpired lease is not authority.
* A promotion decided against term *N* is refused with ``TERM_MOVED`` once the
  store is at *N+1*; a controller that already holds the scope is refused with
  ``ALREADY_LEADER`` rather than promoting itself twice.
* The store keeps refusals as well as successes: several refusals in one scope
  are all storable (they share ``new_term = 0``, and an unconditional unique
  index would have made the second collide with the first), a second promotion
  into the *same* term is a loud ``PromotionDuplicateError``, and a row edited
  behind the model's back refuses itself on read.
* A **replayed** command — captured bytes presented again after the promotion — is
  refused by plan 19's own :class:`AgentCommandVerifier`, and a command refused
  for a deposed fence can still be re-minted because verification is the last
  check and spends no nonce on the way to a refusal.

The migration reservation is asserted rather than assumed: these tables exist
here only where a caller splices ``FAILOVER_MIGRATION`` in, and the test says so
out loud.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.controller.failover_service import DEFAULT_SCOPE, FailoverService, new_promotion_id
from mayhem.controller.leader_election import (
    DEFAULT_LEADERSHIP_SCOPE,
    LEADER_NOT_CURRENT,
    LeaderElection,
    LeaderNotCurrentError,
    SqliteLeadershipStore,
    StepAlreadyDispatchedError,
)
from mayhem.domain.agent_identity import (
    AgentCredential,
    AgentIdentity,
    CertificateRef,
    Revocation,
    RevocationReason,
    TrustAnchorRef,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.fabric import (
    FABRIC_PROTOCOL_VERSION,
    CommandBodyRef,
    FabricCommand,
    FabricCommandType,
    FencingToken,
)
from mayhem.domain.failover import (
    LivenessEvidenceKind,
    LivenessObservation,
    PromotionRefusal,
    PromotionRefusedError,
    assess_primary,
)
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.infra.agent_identity_store import AgentIdentityRepository
from mayhem.infra.agent_identity_verifier import (
    FABRIC_REPLAYED_NONCE,
    AgentCommandVerifier,
    CommandRefusedError,
    HmacSha256CommandSigner,
    HmacSha256SignatureVerifier,
    SqliteNonceLedger,
    StaticKeyMaterial,
    VerificationCheck,
)
from mayhem.infra.failover_store import (
    DOWN_SQL,
    FAILOVER_MIGRATION,
    FAILOVER_VERSION,
    MIGRATION_SQL,
    PROMOTIONS_TABLE,
    STANDBYS_TABLE,
    FailoverPromotionStore,
    PromotionDuplicateError,
    PromotionIntegrityError,
    PromotionRecord,
    StandbyRecord,
    reserved_versions,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
SCOPE = DEFAULT_LEADERSHIP_SCOPE
TTL_S = 60.0
RUN_ID = "r-1"
STEP_ID = "s-1"
PLAN_DIGEST = "a" * 64
NONCE = "0123456789abcdef0123456789abcdef"
CREDENTIAL = "cr-ag-1"
AGENT = "ag-1"
SECRET = b"s" * 32
FINGERPRINT = "f" * 64

#: The chain these tests migrate through. ``FAILOVER_MIGRATION`` is defined in
#: :mod:`mayhem.infra.failover_store` and is **not** in
#: :data:`mayhem.infra.migrations.ALL_MIGRATIONS` — see
#: :meth:`TestTheMigrationReservation.test_the_promotion_tables_are_a_reserved_migration`.
#: When the registering lane adds it, this tuple stops splicing and every fixture
#: below migrates through the production chain, with no test edited.
MIGRATIONS: tuple = (
    ALL_MIGRATIONS
    if any(m.version == FAILOVER_VERSION for m in ALL_MIGRATIONS)
    else (*ALL_MIGRATIONS, FAILOVER_MIGRATION)
)


class Clock:
    """A hand-advanced clock, so lease expiry and terms are exact."""

    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def fence(*, epoch: int = 1, holder: str = "ctl-a") -> FencingToken:
    return FencingToken(
        run_id=RUN_ID, step_id=STEP_ID, holder=holder, epoch=epoch, issued_at=NOW
    )


def command(*, command_id: str = "fc-1", token: FencingToken) -> FabricCommand:
    return FabricCommand(
        protocol=FABRIC_PROTOCOL_VERSION,
        command_id=command_id,
        run_id=RUN_ID,
        step_id=STEP_ID,
        agent_id=AGENT,
        plan_digest=PLAN_DIGEST,
        nonce=NONCE,
        idempotency_key=f"idem-{command_id}",
        fencing_token=token,
        command=CommandBodyRef(
            command_type=FabricCommandType.PREPARE, body_digest="b" * 64, body_ref="body-1"
        ),
        issued_at=NOW.isoformat(),
        signing_key_id=CREDENTIAL,
        signature="A" * 64,
    )


class Recorder:
    """Stands in for the controller-initiated agent session.

    "The dispatcher was not called" is then an assertion about observed behaviour
    rather than about an exception having been raised.
    """

    def __init__(self) -> None:
        self.seen: list[str] = []

    def __call__(self, envelope: FabricCommand) -> str:
        self.seen.append(envelope.command_id)
        return f"dispatched:{envelope.command_id}"


def observation(
    kind: LivenessEvidenceKind, *, term: int, at: datetime, source: str = "test"
) -> LivenessObservation:
    return LivenessObservation(
        kind=kind,
        observed_term=term,
        observed_at=at,
        source=source,
        detail=f"{kind.value} at term {term}",
    )


# --------------------------------------------------------------------------- #
# Fixtures                                                                       #
# --------------------------------------------------------------------------- #


@pytest.fixture
def store() -> Iterator[Store]:
    opened = Store.open_migrated(":memory:", migrations=MIGRATIONS)
    yield opened
    opened.close()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def promotions(store: Store) -> FailoverPromotionStore:
    return FailoverPromotionStore(store)


def election(store: Store, controller_id: str, clock: Clock) -> LeaderElection:
    return LeaderElection(
        store=SqliteLeadershipStore(store), controller_id=controller_id, ttl_s=TTL_S, clock=clock
    )


def service(
    store: Store, promotions: FailoverPromotionStore, controller_id: str, clock: Clock
) -> FailoverService:
    return FailoverService(
        store=promotions,
        election=election(store, controller_id, clock),
        controller_id=controller_id,
        clock=clock,
    )


@pytest.fixture
def primary(store: Store, clock: Clock) -> LeaderElection:
    """``ctl-a``: campaigns immediately and holds a live lease."""
    election(store, "ctl-a", clock).campaign(now=NOW)
    return election(store, "ctl-a", clock)


@pytest.fixture
def standby(store: Store, clock: Clock, promotions: FailoverPromotionStore) -> FailoverService:
    """``ctl-b``: a registered standby that is not the leader."""
    promotions.register_standby("ctl-b", scope=SCOPE, observed_term=1, at=NOW)
    return service(store, promotions, "ctl-b", clock)


def enrol(store: Store) -> None:
    AgentIdentityRepository(store).save(
        AgentIdentity(
            agent_id=AGENT,
            controller_id="ctl-a",
            principal=Principal(principal_id="sa-ag-1", kind=PrincipalKind.WORKLOAD),
            scope=EnvironmentScope(environment="staging"),
            credential=AgentCredential(
                credential_id=CREDENTIAL,
                agent_id=AGENT,
                issued_at=NOW - timedelta(seconds=60),
                expires_at=NOW + timedelta(seconds=900),
                rotate_before=300.0,
            ),
            certificate=CertificateRef(
                subject=f"agent={AGENT}",
                issuer="ca-mesh-1",
                serial="01",
                sha256_fingerprint=FINGERPRINT,
                not_before=NOW - timedelta(hours=1),
                not_after=NOW + timedelta(hours=1),
            ),
            trust_anchors=(
                TrustAnchorRef(
                    ca_id="ca-mesh-1", subject="ca-mesh-1", sha256_fingerprint=FINGERPRINT
                ),
            ),
        )
    )


# --------------------------------------------------------------------------- #
# The migration reservation, stated out loud                                     #
# --------------------------------------------------------------------------- #


class TestTheMigrationReservation:
    def test_the_promotion_tables_are_a_reserved_migration(self) -> None:
        """A literal, on purpose: the honesty of this file depends on it.

        ``FAILOVER_MIGRATION`` (version 36) is defined beside the row models and
        is *not* in ``ALL_MIGRATIONS`` until the registering lane adds it. Until
        then a real deployment has no ``control_plane_promotions`` table and every
        promotion write fails at the first real persist — the same gap plan 03
        recorded for its own journal. Versions 34 and 35 are reserved by
        concurrent lanes, which is why this one takes 36 rather than renumbering
        anything shipped.
        """
        registered = {m.version for m in ALL_MIGRATIONS}
        assert FAILOVER_VERSION == 36
        assert max(registered) < FAILOVER_VERSION
        assert reserved_versions() == (FAILOVER_VERSION,)
        if FAILOVER_VERSION not in registered:
            assert MIGRATIONS[-1] is FAILOVER_MIGRATION

    def test_the_ddl_and_the_down_ddl_are_both_declared(self) -> None:
        assert len(MIGRATION_SQL) == 5
        assert len(DOWN_SQL) == 5
        assert any(STANDBYS_TABLE in statement for statement in MIGRATION_SQL)
        assert any(PROMOTIONS_TABLE in statement for statement in MIGRATION_SQL)

    def test_the_tables_migrate_up_and_roll_back(self, store: Store) -> None:
        def tables() -> set[str]:
            return {
                str(row["name"])
                for row in store.query("SELECT name FROM sqlite_master WHERE type = 'table'")
            }

        assert {STANDBYS_TABLE, PROMOTIONS_TABLE} <= tables()
        head = store.schema_version
        assert head == FAILOVER_VERSION
        store.migrate_down(FAILOVER_VERSION - 1, migrations=MIGRATIONS)
        assert STANDBYS_TABLE not in tables()
        assert PROMOTIONS_TABLE not in tables()
        store.migrate(migrations=MIGRATIONS)
        assert store.schema_version == head


# --------------------------------------------------------------------------- #
# Promotion: what is refused                                                     #
# --------------------------------------------------------------------------- #


class TestPromoteRefuses:
    @pytest.mark.parametrize(
        "kind",
        [
            LivenessEvidenceKind.PROBE_UNREACHABLE,
            LivenessEvidenceKind.HEARTBEAT_MISSING,
            LivenessEvidenceKind.STALE_READ_REPLICA,
            LivenessEvidenceKind.NO_EVIDENCE,
        ],
    )
    def test_cannot_determine_liveness_never_promotes(
        self,
        store: Store,
        clock: Clock,
        promotions: FailoverPromotionStore,
        kind: LivenessEvidenceKind,
    ) -> None:
        """**The negative control this plan exists for.**

        Four ways of not knowing whether the primary is alive, each of which a
        failover implementation is tempted to read as "dead". None moves the term,
        and each is recorded as a refusal.
        """
        election(store, "ctl-a", clock).campaign(now=NOW)
        standby = service(store, promotions, "ctl-b", clock)

        decision = standby.promote_if_dead(
            [observation(kind, term=1, at=NOW)], operator="ops", reason="primary unreachable"
        )

        assert decision.promoted is False
        assert decision.new_term is None
        recorded = standby.last_decision()
        assert recorded is not None
        assert recorded.status == "refused"
        assert recorded.new_term == 0
        lease = SqliteLeadershipStore(store).load_lease(SCOPE)
        assert lease is not None
        assert lease.leader_id == "ctl-a"
        assert lease.term == 1

    def test_a_live_lease_is_refused_even_with_perfect_death_evidence(
        self, standby: FailoverService, primary: LeaderElection
    ) -> None:
        """Lease state is a second, independent gate: evidence alone is not enough."""
        decision = standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=NOW)],
            operator="ops",
            reason="the watchdog says the lease expired",
        )

        assert decision.promoted is False
        assert PromotionRefusal.LEASE_LIVE in decision.refusals
        assert "forc" in decision.describe()

    def test_a_request_decided_against_an_old_term_is_refused(
        self, store: Store, clock: Clock, standby: FailoverService
    ) -> None:
        """Somebody promoted while this request was in flight; its evidence is stale."""
        election(store, "ctl-a", clock).campaign(now=NOW)
        assessment = standby.assess(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=NOW)],
            expected_term=1,
            now=NOW,
        )
        request = standby.request(assessment, operator="ops", reason="lease expired")
        election(store, "ctl-c", clock).campaign(force=True, now=NOW)

        decision = standby.promote(request, at=NOW)

        assert decision.promoted is False
        assert PromotionRefusal.TERM_MOVED in decision.refusals

    def test_a_controller_that_already_holds_the_scope_is_refused(
        self,
        store: Store,
        clock: Clock,
        promotions: FailoverPromotionStore,
        primary: LeaderElection,
    ) -> None:
        """Promoting yourself is a second owner, not a takeover."""
        incumbent = service(store, promotions, "ctl-a", clock)
        assessment = incumbent.assess(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=NOW)],
            expected_term=1,
            now=NOW,
        )

        decision = incumbent.promote(
            incumbent.request(assessment, operator="ops", reason="re-campaigning"), at=NOW
        )

        assert decision.promoted is False
        assert PromotionRefusal.ALREADY_LEADER in decision.refusals

    def test_promote_or_raise_carries_the_decision_on_the_exception(
        self, standby: FailoverService
    ) -> None:
        with pytest.raises(PromotionRefusedError) as caught:
            standby.promote_or_raise(
                standby.request(
                    standby.assess(
                        [observation(LivenessEvidenceKind.PROBE_UNREACHABLE, term=1, at=NOW)],
                        expected_term=1,
                        now=NOW,
                    ),
                    operator="ops",
                    reason="cannot reach it",
                ),
                at=NOW,
            )
        assert caught.value.decision.promoted is False
        assert caught.value.decision.new_term is None

    def test_an_assessment_for_another_term_is_a_programming_error_not_a_refusal(
        self, standby: FailoverService
    ) -> None:
        assessment = standby.assess([], expected_term=7, now=NOW)
        with pytest.raises(InvariantViolationError) as caught:
            standby.promote(
                standby.request(assessment, operator="ops", reason="why", expected_term=1), at=NOW
            )
        assert caught.value.rule == "promotion.term_mismatch"


# --------------------------------------------------------------------------- #
# Promotion: what is allowed                                                     #
# --------------------------------------------------------------------------- #


class TestPromoteProceeds:
    def test_an_expired_lease_in_the_store_promotes_and_advances_the_term(
        self, store: Store, clock: Clock, standby: FailoverService
    ) -> None:
        """The only "the primary is gone" that does not depend on reaching it."""
        election(store, "ctl-a", clock).campaign(now=NOW)
        later = clock.advance(TTL_S + 1)

        decision = standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=later)],
            operator="ops",
            reason="lease for term 1 lapsed in the replicated store",
        )

        assert decision.promoted is True
        assert decision.new_term == 2
        lease = SqliteLeadershipStore(store).load_lease(SCOPE)
        assert lease is not None
        assert (lease.leader_id, lease.term) == ("ctl-b", 2)

    def test_a_cold_start_is_a_campaign_not_a_promotion(
        self, store: Store, clock: Clock, promotions: FailoverPromotionStore
    ) -> None:
        """Nothing holds the scope, so there is no failover to perform.

        Refused by name rather than handled quietly, because the two acts write
        different records: a campaign writes a lease, and a promotion writes a
        record naming the leader it deposed — a cluster whose first controller
        wrote the latter would be claiming a deposed leader it never had.
        """
        standby = service(store, promotions, "ctl-b", clock)

        decision = standby.promote_if_dead(
            [observation(LivenessEvidenceKind.NO_EVIDENCE, term=1, at=NOW)],
            operator="ops",
            reason="first controller in a fresh cluster",
        )

        assert decision.promoted is False
        assert PromotionRefusal.NO_LEADER in decision.refusals
        assert "campaigns rather than promotes" in decision.detail
        assert SqliteLeadershipStore(store).load_lease(SCOPE) is None
        record = promotions.last_promotion(SCOPE)
        assert record is not None
        assert record.status == "refused"

    def test_an_operator_forced_takeover_of_a_live_lease_still_moves_the_term(
        self, store: Store, clock: Clock, promotions: FailoverPromotionStore
    ) -> None:
        """Break-glass is safe *because* of the term, not in spite of it."""
        election(store, "ctl-a", clock).campaign(now=NOW)
        standby = service(store, promotions, "ctl-b", clock)

        decision = standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=NOW)],
            operator="ops",
            reason="the primary is hung and its lease is long",
            forced=True,
        )

        assert decision.promoted is True
        assert decision.new_term == 2
        record = standby.last_decision()
        assert record is not None
        assert record.forced is True
        assert "UNDER --force" in record.describe()

    def test_a_promotion_is_recorded_with_the_evidence_and_the_operator(
        self, store: Store, clock: Clock, promotions: FailoverPromotionStore
    ) -> None:
        election(store, "ctl-a", clock).campaign(now=NOW)
        standby = service(store, promotions, "ctl-b", clock)
        later = clock.advance(TTL_S + 1)

        standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=later)],
            operator="ana",
            reason="lease lapsed",
        )

        record = standby.last_decision()
        assert record is not None
        assert record.status == "promoted"
        assert record.operator == "ana"
        assert record.new_term == 2
        assert record.deposed_leader_id == "ctl-a"
        assert record.evidence["status"] == "dead"
        assert record.describes_itself()


# --------------------------------------------------------------------------- #
# Fencing: a deposed holder always loses                                         #
# --------------------------------------------------------------------------- #


class TestTheDeposedHolderLoses:
    def test_the_deposed_leader_cannot_dispatch(
        self, store: Store, clock: Clock, promotions: FailoverPromotionStore
    ) -> None:
        """A partition can leave a deposed leader inside its own TTL. Expiry is not authority."""
        primary = election(store, "ctl-a", clock)
        lease_a = primary.campaign(now=NOW)
        standby = service(store, promotions, "ctl-b", clock)
        later = clock.advance(TTL_S + 1)
        standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=later)],
            operator="ops",
            reason="lease lapsed",
        )
        successor = election(store, "ctl-b", clock)
        lease_b = successor.current()
        assert lease_b is not None
        recorder = Recorder()
        token_b = successor.fence_for(
            lease_b, run_id=RUN_ID, step_id=STEP_ID, holder="ctl-b", now=later
        )
        successor.dispatch(lease_b, command(command_id="fc-b", token=token_b), recorder, now=later)

        # ctl-a comes back believing it still holds term 1.
        with pytest.raises(LeaderNotCurrentError) as caught:
            primary.require_leader(lease_a, now=later)
        assert caught.value.code == LEADER_NOT_CURRENT

        with pytest.raises(LeaderNotCurrentError):
            primary.dispatch(
                lease_a, command(command_id="fc-a", token=fence()), recorder, now=later
            )
        assert recorder.seen == ["fc-b"]

    def test_a_deposed_leader_spends_no_epoch_and_cannot_double_dispatch_the_step(
        self, store: Store, clock: Clock, promotions: FailoverPromotionStore
    ) -> None:
        primary = election(store, "ctl-a", clock)
        primary.campaign(now=NOW)
        standby = service(store, promotions, "ctl-b", clock)
        later = clock.advance(TTL_S + 1)
        standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=later)],
            operator="ops",
            reason="lease lapsed",
        )
        successor = election(store, "ctl-b", clock)
        lease_b = successor.current()
        assert lease_b is not None
        recorder = Recorder()
        token_b = successor.fence_for(
            lease_b, run_id=RUN_ID, step_id=STEP_ID, holder="ctl-b", now=later
        )
        assert token_b.epoch == 1
        # The mint is recorded; the deposed leader never spent an epoch on it.
        minted_only = successor.dispatched_step(RUN_ID, STEP_ID)
        assert minted_only is not None
        assert minted_only.dispatched is False

        successor.dispatch(lease_b, command(command_id="fc-b", token=token_b), recorder, now=later)
        with pytest.raises(StepAlreadyDispatchedError):
            successor.dispatch(
                lease_b, command(command_id="fc-b2", token=token_b), recorder, now=later
            )
        assert recorder.seen == ["fc-b"]

    def test_a_second_promotion_into_one_term_is_refused_by_the_database(
        self, store: Store, clock: Clock, promotions: FailoverPromotionStore
    ) -> None:
        """Two controllers believing they took term 2 *is* the split brain."""
        election(store, "ctl-a", clock).campaign(now=NOW)
        standby = service(store, promotions, "ctl-b", clock)
        later = clock.advance(TTL_S + 1)
        standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=later)],
            operator="ops",
            reason="lease lapsed",
        )
        imposter = PromotionRecord(
            promotion_id=new_promotion_id(),
            scope=SCOPE,
            standby_id="ctl-c",
            deposed_leader_id="ctl-b",
            deposed_term=1,
            new_term=2,
            operator="mallory",
            reason="I am sure the store is mine",
            status="promoted",
            promoted_at=later,
        ).stamped()

        with pytest.raises(PromotionDuplicateError) as caught:
            promotions.record_promotion(imposter, at=later)
        assert caught.value.rule == PromotionDuplicateError.RULE_SCOPE_TERM


# --------------------------------------------------------------------------- #
# Replay: a captured command comes back                                          #
# --------------------------------------------------------------------------- #


def command_fields(*, command_id: str, token: FencingToken) -> dict[str, object]:
    return {
        "protocol": FABRIC_PROTOCOL_VERSION,
        "command_id": command_id,
        "run_id": RUN_ID,
        "step_id": STEP_ID,
        "agent_id": AGENT,
        "plan_digest": PLAN_DIGEST,
        "nonce": NONCE,
        "idempotency_key": f"idem-{command_id}",
        "fencing_token": token.model_dump(mode="json"),
        "command": CommandBodyRef(
            command_type=FabricCommandType.PREPARE, body_digest="b" * 64, body_ref="body-1"
        ).model_dump(mode="json"),
        "issued_at": NOW.isoformat(),
        "signing_key_id": CREDENTIAL,
    }


def verifier_for(store: Store) -> AgentCommandVerifier:
    keys = StaticKeyMaterial({CREDENTIAL: SECRET})
    return AgentCommandVerifier(
        identities=AgentIdentityRepository(store),
        signature=HmacSha256SignatureVerifier(keys),
        nonces=SqliteNonceLedger(store),
    )


def signer_for(store: Store) -> HmacSha256CommandSigner:
    return HmacSha256CommandSigner(StaticKeyMaterial({CREDENTIAL: SECRET}))


class TestReplayAcrossAFailover:
    def test_a_captured_command_re_injected_is_refused_by_name(
        self, store: Store, clock: Clock, promotions: FailoverPromotionStore
    ) -> None:
        """Captured bytes, presented again after the primary is gone, must not act twice."""
        enrol(store)
        verifier = verifier_for(store)
        election(store, "ctl-a", clock).campaign(now=NOW)
        standby = service(store, promotions, "ctl-b", clock)
        later = clock.advance(TTL_S + 1)
        standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=later)],
            operator="ops",
            reason="lease lapsed",
        )

        captured = signer_for(store).sign_fields(  # type: ignore[arg-type]
            command_fields(command_id="fc-captured", token=fence())
        )
        assert (
            verifier.verify(
                captured, expected_plan_digest=PLAN_DIGEST, now=later
            ).command.command_id
            == "fc-captured"
        )

        with pytest.raises(CommandRefusedError) as caught:
            verifier.verify(captured, expected_plan_digest=PLAN_DIGEST, now=later)
        assert VerificationCheck.NONCE_FRESHNESS in caught.value.failed
        replayed = [
            outcome
            for outcome in caught.value.outcomes
            if outcome.check is VerificationCheck.NONCE_FRESHNESS
        ]
        assert replayed and FABRIC_REPLAYED_NONCE in replayed[0].detail

    def test_a_command_refused_for_a_deposed_fence_can_still_be_re_minted(
        self, store: Store, clock: Clock
    ) -> None:
        """Verification is the last preflight check, so a refusal costs no nonce."""
        enrol(store)
        verifier = verifier_for(store)
        signer = signer_for(store)
        served = fence().next_fence(holder="ctl-b", now=clock.advance(10))
        stale = signer.sign_fields(command_fields(command_id="fc-retry", token=fence()))  # type: ignore[arg-type]

        with pytest.raises(CommandRefusedError) as caught:
            verifier.verify(
                stale, expected_plan_digest=PLAN_DIGEST, served_fence=served, now=clock()
            )
        assert VerificationCheck.FENCE in caught.value.failed

        reminted = signer.sign_fields(  # type: ignore[arg-type]
            command_fields(command_id="fc-retry-2", token=served)
        )
        assert (
            verifier.verify(
                reminted, expected_plan_digest=PLAN_DIGEST, served_fence=served, now=clock()
            ).command.nonce
            == NONCE
        )


# --------------------------------------------------------------------------- #
# The durable record                                                             #
# --------------------------------------------------------------------------- #


class TestPromotionStore:
    def test_registration_is_idempotent_and_keeps_the_join_time(
        self, promotions: FailoverPromotionStore
    ) -> None:
        first = promotions.register_standby("ctl-b", scope=SCOPE, at=NOW)
        later = NOW + timedelta(hours=1)
        second = promotions.register_standby(
            "ctl-b", scope=SCOPE, observed_term=4, advertised_version="1.1.0", at=later
        )
        assert second.registered_at == first.registered_at
        assert second.updated_at == later
        assert second.observed_term == 4
        assert second.observed is True
        assert len(promotions.standbys(SCOPE)) == 1
        assert promotions.standby("ctl-b") is not None
        assert promotions.standby("nobody") is None
        assert len(promotions.standbys()) == 1

    def test_a_standby_that_never_reported_a_term_is_not_observed(
        self, promotions: FailoverPromotionStore
    ) -> None:
        record = promotions.register_standby("ctl-c", scope=SCOPE, at=NOW)
        assert record.observed is False
        assert "claim, not an authentication" in record.describe()

    def test_a_standby_row_edited_behind_the_model_refuses_itself(
        self, store: Store, promotions: FailoverPromotionStore
    ) -> None:
        promotions.register_standby("ctl-b", scope=SCOPE, observed_term=1, at=NOW)
        with store.write() as conn:
            conn.execute(f"UPDATE {STANDBYS_TABLE} SET observed_term = 99")

        with pytest.raises(InvariantViolationError) as caught:
            promotions.standbys(SCOPE)
        assert caught.value.rule == PromotionIntegrityError.RULE_DIGEST

    def test_refusals_accumulate_rather_than_colliding(
        self,
        store: Store,
        clock: Clock,
        standby: FailoverService,
        promotions: FailoverPromotionStore,
    ) -> None:
        """Refused rows share ``new_term = 0``; they must all be storable.

        An unconditional unique index on ``(scope, new_term)`` made the *second*
        refusal in a scope fail as a split brain, which is exactly backwards:
        refusals are the record an incident review needs.
        """
        for index in range(3):
            standby.promote_if_dead(
                [observation(LivenessEvidenceKind.PROBE_UNREACHABLE, term=1, at=NOW)],
                operator=f"ops-{index}",
                reason=f"attempt {index}",
            )
        records = promotions.promotions(SCOPE)
        assert len(records) == 3
        assert all(record.status == "refused" for record in records)
        assert standby.history() == records

    def test_the_history_is_readable_in_both_directions(
        self, store: Store, clock: Clock, promotions: FailoverPromotionStore
    ) -> None:
        election(store, "ctl-a", clock).campaign(now=NOW)
        standby = service(store, promotions, "ctl-b", clock)
        standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PROBE_UNREACHABLE, term=1, at=NOW)],
            operator="ops",
            reason="first attempt",
        )
        later = clock.advance(TTL_S + 1)
        standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=later)],
            operator="ops",
            reason="lease lapsed",
        )
        records = promotions.promotions(SCOPE)
        assert [record.status for record in records] == ["refused", "promoted"]
        assert promotions.last_promotion(SCOPE) is not None
        assert promotions.last_promotion("other-scope") is None
        assert promotions.promotions("other-scope") == ()
        assert len(promotions.promotions()) == 2

    def test_re_recording_one_decision_is_not_a_second_event(
        self, promotions: FailoverPromotionStore
    ) -> None:
        record = PromotionRecord(
            promotion_id=new_promotion_id(),
            scope=SCOPE,
            standby_id="ctl-b",
            deposed_leader_id="ctl-a",
            deposed_term=1,
            new_term=2,
            operator="ops",
            reason="lease lapsed",
            status="promoted",
            promoted_at=NOW,
        )
        first = promotions.record_promotion(record, at=NOW)
        second = promotions.record_promotion(record, at=NOW)
        assert first.promotion_id == second.promotion_id
        assert len(promotions.promotions(SCOPE)) == 1
        assert promotions.promotion(first.promotion_id) is not None

    def test_the_domain_rule_is_repeated_in_the_schema(self, store: Store) -> None:
        """A refused row cannot name a term, and a promoted one must advance it."""
        insert = (
            f"INSERT INTO {PROMOTIONS_TABLE} (promotion_id, scope, standby_id, "
            "deposed_leader_id, deposed_term, new_term, operator, reason, forced, status, "
            "refusals_json, evidence_json, document_digest, promoted_at) "
            "VALUES (?, 's', 'ctl-b', 'ctl-a', 1, ?, 'ops', 'why', 0, ?, '[]', '{}', "
            f"'{FINGERPRINT}', '{NOW.isoformat()}')"
        )
        with store.write() as conn:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(insert, ("x", 2, "refused"))
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(insert, ("y", 1, "promoted"))
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(insert, ("z", 2, "promoting"))

    def test_a_row_cannot_claim_promoted_with_no_operator(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            PromotionRecord(
                promotion_id=new_promotion_id(),
                scope=SCOPE,
                standby_id="ctl-b",
                deposed_leader_id="ctl-a",
                deposed_term=1,
                new_term=2,
                operator="  ",
                reason="why",
                status="promoted",
                promoted_at=NOW,
            )
        assert caught.value.rule == PromotionIntegrityError.RULE_DOCUMENT_SHAPE

    def test_a_status_the_domain_cannot_produce_is_unstorable(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            PromotionRecord(
                promotion_id=new_promotion_id(),
                scope=SCOPE,
                standby_id="ctl-b",
                reason="why",
                status="pending",
                promoted_at=NOW,
            )
        assert caught.value.rule == PromotionIntegrityError.RULE_DOCUMENT_SHAPE

    def test_an_unstamped_record_describes_itself_as_unverified(self) -> None:
        record = PromotionRecord(
            promotion_id=new_promotion_id(), scope=SCOPE, standby_id="ctl-b", reason="why"
        )
        assert record.describes_itself() is False
        assert record.stamped().describes_itself() is True
        assert StandbyRecord(standby_id="ctl-b", scope=SCOPE).stamped().describes_itself() is True

    def test_a_stored_row_keeps_the_excluded_evidence_too(
        self,
        store: Store,
        clock: Clock,
        standby: FailoverService,
        promotions: FailoverPromotionStore,
    ) -> None:
        """A refusal's evidence is mostly what did *not* count."""
        standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=99, at=NOW)],
            operator="ops",
            reason="evidence from another term",
        )
        record = promotions.last_promotion(SCOPE)
        assert record is not None
        assert record.evidence["excluded"]
        assert "not the term being decided" in record.evidence["excluded"][0]["reason"]

    def test_an_unregisterable_standby_id_is_refused(
        self, promotions: FailoverPromotionStore
    ) -> None:
        with pytest.raises(ValueError):
            promotions.register_standby("not a valid id!", scope=SCOPE, at=NOW)


class TestServiceShape:
    def test_the_default_scope_is_the_leadership_scope(self) -> None:
        assert DEFAULT_SCOPE == DEFAULT_LEADERSHIP_SCOPE

    def test_a_second_service_over_one_store_is_a_second_controller(
        self, store: Store, clock: Clock, promotions: FailoverPromotionStore
    ) -> None:
        """Nothing is held in memory, so a restarted controller is immediately correct."""
        election(store, "ctl-a", clock).campaign(now=NOW)
        service(store, promotions, "ctl-b", clock).promote_if_dead(
            [observation(LivenessEvidenceKind.PROBE_UNREACHABLE, term=1, at=NOW)],
            operator="ops",
            reason="cannot reach it",
        )
        restarted = service(store, promotions, "ctl-b", clock)
        assert restarted.last_decision() is not None
        assert restarted.scope == SCOPE
        assert restarted.controller_id == "ctl-b"
        assert restarted.freshness_bound_s > 0

    def test_a_freshness_bound_configured_on_the_service_is_applied(
        self, store: Store, promotions: FailoverPromotionStore
    ) -> None:
        clock = Clock()
        tight = FailoverService(
            store=promotions,
            election=election(store, "ctl-b", clock),
            controller_id="ctl-b",
            clock=clock,
            freshness_bound_s=5.0,
        )
        stale = observation(
            LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=NOW - timedelta(seconds=20)
        )
        assert tight.assess([stale], expected_term=1, now=NOW).promotable is False
        assert (
            tight.assess([stale], expected_term=1, now=NOW, freshness_bound_s=30.0).promotable
            is True
        )

    def test_the_assessment_is_pure_and_repeatable(
        self, store: Store, promotions: FailoverPromotionStore
    ) -> None:
        clock = Clock()
        svc = FailoverService(
            store=promotions,
            election=election(store, "ctl-b", clock),
            controller_id="ctl-b",
            clock=clock,
        )
        observations = [observation(LivenessEvidenceKind.NO_EVIDENCE, term=1, at=NOW)]
        assert svc.assess(observations, expected_term=1, now=NOW) == svc.assess(
            observations, expected_term=1, now=NOW
        )
        assert assess_primary(observations, expected_term=1, now=NOW).promotable is False

    def test_a_promotion_id_is_greppable_and_unique(self) -> None:
        assert new_promotion_id().startswith("p19-")
        assert new_promotion_id() != new_promotion_id()


class TestWhatIsNotAProperty:
    def test_a_revoked_agent_credential_does_not_gate_a_promotion(
        self, store: Store, clock: Clock, promotions: FailoverPromotionStore
    ) -> None:
        """Recording *who* the standby claims to be is not a gate; the evidence is.

        Asserted because it is a tempting shortcut: "the agent's credential is
        revoked, so refuse" would be a check with no rule behind it — this build
        has no revocation-checking protocol on the promotion path, and pretending
        otherwise would be a check that cannot fail for the right reason.
        """
        enrol(store)
        AgentIdentityRepository(store).revoke_agent(
            AGENT,
            Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by="ops"),
        )
        election(store, "ctl-a", clock).campaign(now=NOW)
        standby = service(store, promotions, "ctl-b", clock)
        later = clock.advance(TTL_S + 1)

        decision = standby.promote_if_dead(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1, at=later)],
            operator="ops",
            reason="lease lapsed",
        )
        assert decision.promoted is True
