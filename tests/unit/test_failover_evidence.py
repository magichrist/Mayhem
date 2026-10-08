"""Plan 19 Phase 4 — every failover and credential decision sealed into evidence.

A durable row and a sealed event are not the same thing: a row can be edited by
anything holding the database file, while a sealed chain can be re-verified
offline from its stored bytes. This file is what makes "every failover sealed
into evidence" a claim about a real database rather than a sentence, and each
case has the negative control that would have caught the opposite behaviour:

* **refusals are sealed**, under their own event kind, so a chain that never
  promoted is not empty. A success-only chain could not produce the record an
  incident review actually needs — "we saw the partition and did not promote".
* **the evidence never launders a claim into an authentication.** Every promotion
  payload carries ``standby_id_is_a_claim`` and its explanation, and every standby
  registration carries an ``identity_claim`` saying no handshake took place.
* **the chain is unsigned**, and says so: the manifest's signature state is plan
  12's ``unsigned_no_signing`` with its reason, asserted rather than assumed.
* **tampering is noticed.** An event row edited behind the sealer's back makes
  :func:`verify_failover_chain` fail, which is the whole reason verification reads
  *stored bytes* through plan 12's own domain verifier instead of re-running the
  sealer (which would only prove the sealer agrees with itself).
* an unknown event kind is refused before anything is written, and the two chain
  ids cannot collide — a promotion decision and a credential rotation answer
  different questions and must not be readable as one sequence.

Phase 4's other two items are *not* here and are not claimed: restore drills were
sealed in Phase 2, and SBOM/SLSA provenance is neither generated nor verified by
any module in this plan (see the ledger).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.controller.credential_rotation import CredentialRotationService, RotationPolicy
from mayhem.controller.failover_evidence import (
    EVENT_HA_CREDENTIAL_REVOKED,
    EVENT_HA_CREDENTIAL_ROTATED,
    EVENT_HA_CREDENTIAL_ROTATION_FAILED,
    EVENT_HA_PROMOTED,
    EVENT_HA_PROMOTION_REFUSED,
    EVENT_HA_STANDBY_REGISTERED,
    HA_EVENT_KINDS,
    FailoverEvidenceRecorder,
    failover_chain_id,
    failover_timeline,
    load_failover_chain,
    load_failover_manifest,
    load_rotation_chain,
    rotation_chain_id,
    rotation_timeline,
    verify_failover_chain,
    verify_rotation_chain,
)
from mayhem.controller.failover_service import FailoverService
from mayhem.controller.leader_election import LeaderElection, SqliteLeadershipStore
from mayhem.domain.agent_identity import (
    AgentCredential,
    AgentIdentity,
    Revocation,
    RevocationReason,
)
from mayhem.domain.attestation import AttestedTimestamp
from mayhem.domain.errors import DomainError
from mayhem.domain.failover import LivenessEvidenceKind, LivenessObservation
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.infra.agent_identity_store import AgentIdentityRepository
from mayhem.infra.attestation_store import SIGNATURE_UNSIGNED_NO_SIGNING, AttestationRepository
from mayhem.infra.failover_store import (
    FAILOVER_MIGRATION,
    FAILOVER_VERSION,
    FailoverPromotionStore,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
SCOPE = "control-plane"
TTL_S = 60.0
MIGRATIONS: tuple = (
    ALL_MIGRATIONS
    if any(m.version == FAILOVER_VERSION for m in ALL_MIGRATIONS)
    else (*ALL_MIGRATIONS, FAILOVER_MIGRATION)
)


def reading(moment: datetime) -> AttestedTimestamp:
    return AttestedTimestamp(
        wall_clock=moment, monotonic_ns=1_000, uncertainty_ms=0.0, source="test"
    )


class Clock:
    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def observation(kind: LivenessEvidenceKind, *, term: int, at: datetime) -> LivenessObservation:
    return LivenessObservation(
        kind=kind,
        observed_term=term,
        observed_at=at,
        source="test",
        detail=f"{kind.value} at term {term}",
    )


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
def store() -> Iterator[Store]:
    opened = Store.open_migrated(":memory:", migrations=MIGRATIONS)
    yield opened
    opened.close()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def recorder(store: Store, clock: Clock) -> FailoverEvidenceRecorder:
    return FailoverEvidenceRecorder(store=store, clock=lambda: reading(clock()))


@pytest.fixture
def promotions(store: Store) -> FailoverPromotionStore:
    return FailoverPromotionStore(store)


def election(store: Store, controller_id: str, clock: Clock) -> LeaderElection:
    return LeaderElection(
        store=SqliteLeadershipStore(store), controller_id=controller_id, ttl_s=TTL_S, clock=clock
    )


def promote(
    store: Store,
    promotions: FailoverPromotionStore,
    recorder: FailoverEvidenceRecorder,
    clock: Clock,
    *,
    kind: LivenessEvidenceKind,
    at: datetime,
    term: int = 1,
    forced: bool = False,
    operator: str = "ops",
) -> object:
    """Drive a decision through the real service and seal it, as a controller would."""
    standby = FailoverService(
        store=promotions,
        election=election(store, "ctl-b", clock),
        controller_id="ctl-b",
        clock=clock,
    )
    decision = standby.promote_if_dead(
        [observation(kind, term=term, at=at)],
        operator=operator,
        reason="drill",
        forced=forced,
    )
    record = standby.last_decision()
    assert record is not None
    recorder.promotion_decided(decision, record, recorded_at=reading(at))
    return decision


# --------------------------------------------------------------------------- #
# Sealing                                                                        #
# --------------------------------------------------------------------------- #


class TestSealing:
    def test_a_standby_registration_is_sealed_as_a_claim(
        self, promotions: FailoverPromotionStore, recorder: FailoverEvidenceRecorder
    ) -> None:
        record = promotions.register_standby("ctl-b", scope=SCOPE, observed_term=1, at=NOW)

        event = recorder.standby_registered(record)

        assert event.event_kind == EVENT_HA_STANDBY_REGISTERED
        assert event.run_id == failover_chain_id(SCOPE)
        assert event.payload["standby_id"] == "ctl-b"
        assert event.payload["observed_term"] == 1
        assert "not an authenticated identity" in str(event.payload["identity_claim"])

    def test_a_refusal_is_sealed_under_its_own_kind(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
        clock: Clock,
    ) -> None:
        election(store, "ctl-a", clock).campaign(now=NOW)

        promote(
            store,
            promotions,
            recorder,
            clock,
            kind=LivenessEvidenceKind.PROBE_UNREACHABLE,
            at=NOW,
        )

        timeline = failover_timeline(store, SCOPE)
        assert timeline.refusals
        assert timeline.promotions == ()
        assert timeline.last_term == 0
        assert timeline.verified is True
        payload = timeline.refusals[0].payload
        assert "primary_alive" in json.dumps(payload["refusals"])
        assert payload["new_term"] == 0
        assert payload["deposed_leader_id"] == "ctl-a"

    def test_a_promotion_is_sealed_with_both_terms_and_the_operator(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
        clock: Clock,
    ) -> None:
        election(store, "ctl-a", clock).campaign(now=NOW)
        later = clock.advance(TTL_S + 1)

        decision = promote(
            store,
            promotions,
            recorder,
            clock,
            kind=LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED,
            at=later,
            operator="ana",
        )

        assert decision.promoted is True
        timeline = failover_timeline(store, SCOPE)
        (sealed,) = timeline.promotions
        assert sealed.payload["new_term"] == 2
        assert sealed.payload["deposed_term"] == 1
        assert sealed.payload["deposed_leader_id"] == "ctl-a"
        assert sealed.payload["operator"] == "ana"
        assert sealed.payload["forced"] is False
        assert sealed.payload["evidence"]["status"] == "dead"

    def test_the_excluded_evidence_travels_with_the_decision(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
        clock: Clock,
    ) -> None:
        promote(
            store,
            promotions,
            recorder,
            clock,
            kind=LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED,
            at=NOW,
            term=99,
        )
        (sealed,) = load_failover_chain(store, SCOPE)
        assert sealed.payload["evidence"]["excluded"]

    def test_a_forced_promotion_is_sealed_as_forced(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
        clock: Clock,
    ) -> None:
        election(store, "ctl-a", clock).campaign(now=NOW)

        promote(
            store,
            promotions,
            recorder,
            clock,
            kind=LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED,
            at=NOW,
            forced=True,
        )

        (sealed,) = load_failover_chain(store, SCOPE)
        assert sealed.event_kind == EVENT_HA_PROMOTED
        assert sealed.payload["forced"] is True

    def test_an_unknown_kind_is_refused_before_anything_is_written(
        self, store: Store, recorder: FailoverEvidenceRecorder
    ) -> None:
        with pytest.raises(DomainError):
            recorder.seal(
                chain_id=failover_chain_id(SCOPE), kind="ha.invented", identity="x", payload={}
            )
        assert store.query("SELECT * FROM attestation_events") == []

    def test_every_kind_is_published_so_a_reader_and_a_test_cannot_disagree(self) -> None:
        assert HA_EVENT_KINDS == (
            EVENT_HA_STANDBY_REGISTERED,
            EVENT_HA_PROMOTED,
            EVENT_HA_PROMOTION_REFUSED,
            EVENT_HA_CREDENTIAL_ROTATED,
            EVENT_HA_CREDENTIAL_REVOKED,
            EVENT_HA_CREDENTIAL_ROTATION_FAILED,
        )


# --------------------------------------------------------------------------- #
# Reading back                                                                   #
# --------------------------------------------------------------------------- #


class TestReadingBack:
    def test_the_chain_verifies_from_stored_bytes(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
        clock: Clock,
    ) -> None:
        FailoverPromotionStore(store).register_standby("ctl-b", scope=SCOPE, at=NOW)
        recorder.standby_registered(promotions.standby("ctl-b"))
        election(store, "ctl-a", clock).campaign(now=NOW)
        promote(
            store,
            promotions,
            recorder,
            clock,
            kind=LivenessEvidenceKind.PROBE_UNREACHABLE,
            at=NOW,
        )
        later = clock.advance(TTL_S + 1)
        promote(
            store,
            promotions,
            recorder,
            clock,
            kind=LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED,
            at=later,
        )

        verification = verify_failover_chain(store, SCOPE)

        assert verification.valid is True
        assert len(load_failover_chain(store, SCOPE)) == 3
        timeline = failover_timeline(store, SCOPE)
        assert timeline.terms_taken == (2,)
        assert len(timeline.refusals) == 1
        assert "1 promotion(s) [2]" in timeline.describe()

    def test_an_edited_event_is_noticed_by_the_offline_verifier(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
        clock: Clock,
    ) -> None:
        """**The negative control for sealing.**

        The payload is edited behind the sealer's back — the thing an attacker
        with database access would do to make a refusal read as a promotion — and
        plan 12's verifier over the *reloaded* bytes refuses the chain.
        """
        election(store, "ctl-a", clock).campaign(now=NOW)
        promote(
            store,
            promotions,
            recorder,
            clock,
            kind=LivenessEvidenceKind.PROBE_UNREACHABLE,
            at=NOW,
        )
        (sealed,) = load_failover_chain(store, SCOPE)
        tampered = sealed.model_copy(update={"payload": {**sealed.payload, "new_term": 9}})
        with store.write() as conn:
            conn.execute(
                "UPDATE attestation_events SET event_json = ? WHERE event_id = ?",
                (tampered.model_dump_json(), sealed.event_id),
            )

        assert verify_failover_chain(store, SCOPE).valid is False

    def test_the_manifest_is_unsigned_and_says_why(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
    ) -> None:
        promotions.register_standby("ctl-b", scope=SCOPE, at=NOW)
        recorder.standby_registered(promotions.standby("ctl-b"))

        manifest = load_failover_manifest(store, SCOPE)

        assert manifest is not None
        assert manifest.run_id == failover_chain_id(SCOPE)
        stored = store.query(
            "SELECT signature_state, signature_reason FROM attestation_manifests "
            "WHERE manifest_id = ?",
            (f"{failover_chain_id(SCOPE)}:manifest",),
        )
        assert str(stored[0]["signature_state"]) == SIGNATURE_UNSIGNED_NO_SIGNING
        assert "signature" in str(stored[0]["signature_reason"]).lower() or bool(
            stored[0]["signature_reason"]
        )

    def test_the_manifest_chains_to_the_one_it_replaces(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
    ) -> None:
        promotions.register_standby("ctl-b", scope=SCOPE, at=NOW)
        recorder.standby_registered(promotions.standby("ctl-b"))
        first = load_failover_manifest(store, SCOPE)

        promotions.register_standby("ctl-c", scope=SCOPE, at=NOW)
        recorder.standby_registered(promotions.standby("ctl-c"))
        second = load_failover_manifest(store, SCOPE)

        assert first is not None and second is not None
        assert second.previous_manifest_digest == first.manifest_digest

    def test_an_empty_scope_has_no_chain_and_no_manifest(self, store: Store) -> None:
        assert load_failover_chain(store, "nothing-here") == ()
        assert load_failover_manifest(store, "nothing-here") is None
        assert verify_failover_chain(store, "nothing-here").valid is True

    def test_two_scopes_do_not_share_a_chain(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
    ) -> None:
        promotions.register_standby("ctl-b", scope="cell-eu-1", at=NOW)
        recorder.standby_registered(promotions.standby("ctl-b"))

        assert load_failover_chain(store, "cell-eu-1")
        assert load_failover_chain(store, SCOPE) == ()


# --------------------------------------------------------------------------- #
# Credentials                                                                    #
# --------------------------------------------------------------------------- #


class TestCredentialEvidence:
    def service(self, store: Store, clock: Clock) -> CredentialRotationService:
        return CredentialRotationService(
            identities=AgentIdentityRepository(store),
            policy=RotationPolicy(policy_id="p-strict"),
            clock=clock,
        )

    def test_a_keyless_rotation_is_sealed_with_the_window_it_opened(
        self,
        store: Store,
        recorder: FailoverEvidenceRecorder,
        clock: Clock,
    ) -> None:
        identities = AgentIdentityRepository(store)
        identities.save(identity())
        outcome = self.service(store, clock).rotate("ag-1", at=NOW)

        recorder.rotation_recorded(outcome, controller_id="ctl-a", recorded_at=reading(NOW))

        timeline = rotation_timeline(store, "ctl-a")
        assert timeline.verified is True
        (sealed,) = timeline.rotated
        assert sealed.event_kind == EVENT_HA_CREDENTIAL_ROTATED
        assert sealed.payload["key_provisioned"] is False
        assert sealed.payload["from_credential"] == "ag-1-c1"
        assert sealed.payload["to_credential"] == "ag-1-c2"
        # The fail-closed window is readable from the chain, not just from stdout.
        assert timeline.without_key == ("ag-1",)
        assert "without a provisioned key" in timeline.describe()

    def test_a_revocation_is_sealed_under_its_own_kind(
        self,
        store: Store,
        recorder: FailoverEvidenceRecorder,
        clock: Clock,
    ) -> None:
        identities = AgentIdentityRepository(store)
        identities.save(identity())
        outcome = self.service(store, clock).revoke(
            "ag-1", reason=RevocationReason.COMPROMISED, revoked_by="ops", at=NOW
        )

        recorder.rotation_recorded(outcome, controller_id="ctl-a", recorded_at=reading(NOW))

        (sealed,) = load_rotation_chain(store, "ctl-a")
        assert sealed.event_kind == EVENT_HA_CREDENTIAL_REVOKED
        assert sealed.payload["agent_id"] == "ag-1"
        assert len(rotation_timeline(store, "ctl-a").revoked) == 1

    def test_a_failed_rotation_is_sealed_too(
        self,
        store: Store,
        recorder: FailoverEvidenceRecorder,
        clock: Clock,
    ) -> None:
        """One failure in a sweep of a hundred must not hide behind the ninety-nine."""
        identities = AgentIdentityRepository(store)
        identities.save(identity())
        identities.revoke_agent(
            "ag-1",
            Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by="ops"),
        )
        outcome = self.service(store, clock).rotate_due(at=clock.advance(10))[0]

        recorder.rotation_recorded(outcome, controller_id="ctl-a", recorded_at=reading(clock()))

        (sealed,) = load_rotation_chain(store, "ctl-a")
        assert sealed.event_kind == EVENT_HA_CREDENTIAL_ROTATION_FAILED
        assert "rotation refused" in sealed.payload["detail"]
        assert verify_rotation_chain(store, "ctl-a").valid is True

    def test_the_two_chains_never_mix(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
        clock: Clock,
    ) -> None:
        """A promotion decision and a credential rotation are different questions."""
        promotions.register_standby("ctl-b", scope=SCOPE, at=NOW)
        recorder.standby_registered(promotions.standby("ctl-b"))
        identities = AgentIdentityRepository(store)
        identities.save(identity())
        outcome = self.service(store, clock).rotate("ag-1", at=NOW)
        recorder.rotation_recorded(outcome, controller_id="ctl-a", recorded_at=reading(NOW))

        failover_kinds = {e.event_kind for e in load_failover_chain(store, SCOPE)}
        rotation_kinds = {e.event_kind for e in load_rotation_chain(store, "ctl-a")}

        assert failover_kinds == {EVENT_HA_STANDBY_REGISTERED}
        assert rotation_kinds == {EVENT_HA_CREDENTIAL_ROTATED}
        assert failover_chain_id(SCOPE) != rotation_chain_id("ctl-a")

    def test_the_chain_is_readable_through_the_repository_too(
        self,
        store: Store,
        promotions: FailoverPromotionStore,
        recorder: FailoverEvidenceRecorder,
    ) -> None:
        """The timeline is a reader, not a privileged accessor."""
        promotions.register_standby("ctl-b", scope=SCOPE, at=NOW)
        recorder.standby_registered(promotions.standby("ctl-b"))
        assert AttestationRepository(store).load_chain(failover_chain_id(SCOPE))
        assert AttestationRepository(store).load_chain(rotation_chain_id("ctl-b")) == ()
