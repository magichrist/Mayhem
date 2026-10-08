"""Plan 19 Phase 3 — the cluster membership view: a projection that refuses to
reassure, and a composition root that wires the plan together.

The view is the read side of plan 19: leadership lease, standby roster, enrolled
identities, recovery posture, and the most recent promotion decision, projected
into one immutable value. It holds no lock and changes nothing — rendering it
cannot promote a standby, spend a fence, or rotate a credential — and the tests
assert that by calling :meth:`ClusterOperations.members` and then reading the
store to show nothing moved.

The three places it refuses to reassure are the point of the file:

* **Leadership.** ``single_dispatcher`` is a statement that one leader is
  *recorded* and nothing contradicts it, not that one leader is *running*: the
  printed caveat says so verbatim, because this build ships no quorum and no
  partition detection.
* **Recovery.** ``backup_trusted`` is ``False`` for any datastore with no
  verified restore drill, and the RPO/RTO verdicts are printed verbatim from
  Phase 1's comparison — "not demonstrated" rather than a number nobody measured.
* **Agents.** ``credential_state`` is a five-valued enum, not a boolean, and
  ``unknown_key`` is reachable: with no key port bound, or after a rotation that
  provisioned nothing, the agent renders as unhealthy rather than as healthy.

And the one thing it must never invent: a datastore with no stated objective
produces **no** recovery row at all, so an operator never reads "0 snapshots"
about a system nobody backed up and mistakes it for a finding.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.controller.cluster_ops import (
    NO_EVIDENCE_VERDICT,
    ClusterMembershipView,
    ClusterOperations,
    CredentialState,
    LeadershipVerdict,
    RecoveryView,
)
from mayhem.controller.credential_rotation import RotationPolicy
from mayhem.controller.leader_election import LeaderElection, SqliteLeadershipStore
from mayhem.domain.agent_identity import (
    AgentCredential,
    AgentIdentity,
    CertificateRef,
    Revocation,
    RevocationReason,
    TrustAnchorRef,
)
from mayhem.domain.backup import RecoveryObjective, SnapshotKind
from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.failover import LivenessEvidenceKind, LivenessObservation
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.infra.agent_identity_store import AgentIdentityRepository, BackupRepository
from mayhem.infra.agent_identity_verifier import StaticKeyMaterial
from mayhem.infra.backup_engine import (
    BackupEngine,
    InMemoryObjectStore,
    SqliteSnapshotSource,
)
from mayhem.infra.failover_store import (
    FAILOVER_MIGRATION,
    FAILOVER_VERSION,
    FailoverPromotionStore,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
DATASTORE = "mayhem-sqlite"
TTL_S = 60.0
FINGERPRINT = "f" * 64
MIGRATIONS: tuple = (
    ALL_MIGRATIONS
    if any(m.version == FAILOVER_VERSION for m in ALL_MIGRATIONS)
    else (*ALL_MIGRATIONS, FAILOVER_MIGRATION)
)


def identity(
    agent_id: str = "ag-1", *, expires_at: datetime | None = None, with_anchors: bool = True
) -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        controller_id="ctl-a",
        principal=Principal(principal_id=f"sa-{agent_id}", kind=PrincipalKind.WORKLOAD),
        scope=EnvironmentScope(environment="staging"),
        credential=AgentCredential(
            credential_id=f"cr-{agent_id}",
            agent_id=agent_id,
            issued_at=NOW - timedelta(seconds=60),
            expires_at=NOW + timedelta(seconds=900) if expires_at is None else expires_at,
            rotate_before=300.0,
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
            (
                TrustAnchorRef(
                    ca_id="ca-mesh-1", subject="ca-mesh-1", sha256_fingerprint=FINGERPRINT
                ),
            )
            if with_anchors
            else ()
        ),
    )


class Clock:
    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


@pytest.fixture
def store() -> Iterator[Store]:
    opened = Store.open_migrated(":memory:", migrations=MIGRATIONS)
    yield opened
    opened.close()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def source_db(tmp_path: Path) -> Path:
    """A real on-disk SQLite database worth snapshotting."""
    path = tmp_path / "source.db"
    controller = Store.open_migrated(path, migrations=MIGRATIONS)
    AgentIdentityRepository(controller).save(identity("ag-1"))
    controller.close()
    return path


@pytest.fixture
def backups(store: Store, source_db: Path, clock: Clock) -> BackupEngine:
    return BackupEngine(
        store=store,
        object_store=InMemoryObjectStore(),
        source=SqliteSnapshotSource(source_db, observed_tables=("agent_identities",)),
        clock=clock,
    )


def operations(
    store: Store,
    backups: BackupEngine,
    clock: Clock,
    *,
    keys: StaticKeyMaterial | None = None,
    controller_id: str = "ctl-a",
) -> ClusterOperations:
    return ClusterOperations(
        store=store,
        controller_id=controller_id,
        election=LeaderElection(
            store=SqliteLeadershipStore(store),
            controller_id=controller_id,
            ttl_s=TTL_S,
            clock=clock,
        ),
        policy=RotationPolicy(policy_id="p-strict"),
        backups=backups,
        keys=keys,
    )


# --------------------------------------------------------------------------- #
# The projection                                                                 #
# --------------------------------------------------------------------------- #


class TestRenderingChangesNothing:
    def test_taking_a_view_writes_nothing(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        AgentIdentityRepository(store).save(identity())
        FailoverPromotionStore(store).register_standby("ctl-b", scope="control-plane", at=NOW)

        view = operations(store, backups, clock).members(at=NOW)

        assert isinstance(view, ClusterMembershipView)
        assert store.query("SELECT * FROM control_plane_leaders") == []
        assert len(store.query("SELECT * FROM agent_identities")) == 1
        assert len(store.query("SELECT * FROM control_plane_promotions")) == 0

    def test_two_views_a_second_apart_differ_when_the_store_does(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        ops = operations(store, backups, clock)
        before = ops.members(at=NOW)
        ops.failover._election.campaign(now=NOW)
        after = ops.members(at=NOW)
        assert before.has_leader is False
        assert after.has_leader is True
        assert after.leader_term == 1

    def test_a_naive_instant_is_refused(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            operations(store, backups, clock).members(
                at=datetime(2026, 3, 1, 12, 0)  # noqa: DTZ001 - naive on purpose
            )
        assert caught.value.rule == "cluster.time_aware"

    def test_the_caveat_is_printed_on_every_view(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        view = operations(store, backups, clock).members(at=NOW)
        assert view.caveat == ClusterOperations.CAVEAT
        assert "no quorum" in view.caveat.lower()
        assert "bounds the damage" in view.caveat
        assert view.caveat in view.describe()


# --------------------------------------------------------------------------- #
# Leadership                                                                     #
# --------------------------------------------------------------------------- #


class TestLeadershipProjection:
    def test_no_lease_reads_as_no_leader_not_as_healthy(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        view = operations(store, backups, clock).members(at=NOW)
        assert view.leadership_verdict is LeadershipVerdict.NO_LEADER
        assert view.has_leader is False
        assert "nothing dispatches" in view.describe()

    def test_a_live_lease_reads_as_a_single_dispatcher(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        ops = operations(store, backups, clock)
        ops.failover._election.campaign(now=NOW)
        view = ops.members(at=NOW)
        assert view.leadership_verdict is LeadershipVerdict.SINGLE_DISPATCHER
        assert view.leader_id == "ctl-a"
        assert view.lease_expires_at == NOW + timedelta(seconds=TTL_S)
        leaders = [c for c in view.controllers if c.role == "leader"]
        assert len(leaders) == 1
        assert "still live" in leaders[0].detail

    def test_an_expired_lease_reads_as_expired(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        ops = operations(store, backups, clock)
        ops.failover._election.campaign(now=NOW)
        view = ops.members(at=clock.advance(TTL_S + 1))
        assert view.leadership_verdict is LeadershipVerdict.LEASE_EXPIRED
        leader = next(c for c in view.controllers if c.role == "leader")
        assert "EXPIRED" in leader.detail

    def test_a_standby_never_observed_in_sync_is_surfaced(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        FailoverPromotionStore(store).register_standby("ctl-b", scope="control-plane", at=NOW)
        ops = operations(store, backups, clock)
        ops.failover._election.campaign(now=NOW)

        view = ops.members(at=NOW)

        assert view.leadership_verdict is LeadershipVerdict.STANDBY_NOT_OBSERVED
        standby = next(c for c in view.controllers if c.role == "standby")
        assert "never observed in sync" in standby.detail
        assert "says nothing about its readiness" in standby.detail

    def test_an_observed_standby_does_not_lower_the_verdict(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        FailoverPromotionStore(store).register_standby(
            "ctl-b", scope="control-plane", observed_term=1, at=NOW
        )
        ops = operations(store, backups, clock)
        ops.failover._election.campaign(now=NOW)
        assert ops.members(at=NOW).leadership_verdict is LeadershipVerdict.SINGLE_DISPATCHER


# --------------------------------------------------------------------------- #
# Agents                                                                         #
# --------------------------------------------------------------------------- #


class TestAgentProjection:
    def test_an_agent_with_no_key_port_bound_reads_as_unknown_key(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        """An unasked question rendered as a pass is the defect this refuses."""
        AgentIdentityRepository(store).save(identity())
        view = operations(store, backups, clock).members(at=NOW)
        (agent,) = view.agents
        assert agent.credential_state is CredentialState.UNKNOWN_KEY
        assert agent.healthy is False
        assert [a.agent_id for a in view.unhealthy_agents] == ["ag-1"]

    def test_a_resolvable_key_makes_the_agent_current(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        AgentIdentityRepository(store).save(identity())
        view = operations(
            store, backups, clock, keys=StaticKeyMaterial({"cr-ag-1": b"k" * 32})
        ).members(at=NOW)
        (agent,) = view.agents
        assert agent.credential_state is CredentialState.CURRENT
        assert agent.healthy is True
        assert agent.pin_reason == "pinned"

    def test_an_agent_with_no_anchor_prints_the_refusal_verbatim(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        AgentIdentityRepository(store).save(identity(with_anchors=False))
        view = operations(
            store, backups, clock, keys=StaticKeyMaterial({"cr-ag-1": b"k" * 32})
        ).members(at=NOW)
        (agent,) = view.agents
        assert agent.pin_reason == "no_anchors"
        assert "pin no_anchors" in agent.describe()

    def test_an_expired_credential_reads_as_expired(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        AgentIdentityRepository(store).save(identity(expires_at=NOW + timedelta(seconds=60)))
        view = operations(
            store, backups, clock, keys=StaticKeyMaterial({"cr-ag-1": b"k" * 32})
        ).members(at=clock.advance(120))
        (agent,) = view.agents
        assert agent.credential_state is CredentialState.EXPIRED
        assert agent.healthy is False

    def test_a_revoked_identity_reads_as_revoked(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        identities = AgentIdentityRepository(store)
        identities.save(identity())
        identities.revoke_agent(
            "ag-1",
            Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by="ops"),
        )
        view = operations(
            store, backups, clock, keys=StaticKeyMaterial({"cr-ag-1": b"k" * 32})
        ).members(at=NOW)
        assert view.agents[0].credential_state is CredentialState.REVOKED

    def test_a_credential_inside_the_lead_time_reads_as_due_but_not_unhealthy(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        AgentIdentityRepository(store).save(identity())
        view = operations(
            store, backups, clock, keys=StaticKeyMaterial({"cr-ag-1": b"k" * 32})
        ).members(at=clock.advance(700))
        (agent,) = view.agents
        assert agent.credential_state is CredentialState.ROTATION_DUE
        assert agent.healthy is True
        assert view.unhealthy_agents == ()
        assert "rotation is due at" in agent.rotation_reason

    def test_the_agents_are_ordered_and_counted(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        identities = AgentIdentityRepository(store)
        for agent in ("ag-3", "ag-1", "ag-2"):
            identities.save(identity(agent))
        view = operations(store, backups, clock).members(at=NOW)
        assert [a.agent_id for a in view.agents] == ["ag-1", "ag-2", "ag-3"]
        assert view.agent_count == 3


# --------------------------------------------------------------------------- #
# Recovery                                                                       #
# --------------------------------------------------------------------------- #


class TestRecoveryProjection:
    def test_no_stated_objective_produces_no_recovery_row(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        """A view that invented a datastore would print "0 snapshots" for a system
        nobody backs up, which reads like a finding rather than a missing config."""
        view = operations(store, backups, clock).members(at=NOW)
        assert view.recovery == ()

    def test_a_stated_objective_with_no_drill_reads_not_demonstrated(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        BackupRepository(store).save_objective(
            RecoveryObjective(
                datastore=DATASTORE,
                rpo_seconds=300.0,
                rto_seconds=900.0,
                stated_by="ops",
                stated_at=NOW,
            )
        )
        view = operations(store, backups, clock).members(at=NOW)

        (entry,) = view.recovery
        assert isinstance(entry, RecoveryView)
        assert entry.snapshots == 0
        assert entry.backup_trusted is False
        assert "not demonstrated" in entry.rpo_verdict
        assert "not demonstrated" in entry.rto_verdict
        assert "backup trusted=False" in entry.describe()

    def test_a_snapshot_without_a_drill_is_still_untrusted(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        """A backup nobody has ever restored is not a backup."""
        backups.snapshot_now(snapshot_id="snap-1", datastore=DATASTORE, kind=SnapshotKind.FULL)
        BackupRepository(store).save_objective(
            RecoveryObjective(
                datastore=DATASTORE,
                rpo_seconds=300.0,
                rto_seconds=900.0,
                stated_by="ops",
                stated_at=NOW,
            )
        )
        view = operations(store, backups, clock).members(at=NOW)

        (entry,) = view.recovery
        assert entry.snapshots == 1
        assert entry.last_snapshot_at == NOW
        assert entry.backup_trusted is False

    def test_the_no_evidence_string_is_one_shared_constant(self) -> None:
        assert NO_EVIDENCE_VERDICT.startswith("not demonstrated")
        assert "no restore drill has been recorded" in NO_EVIDENCE_VERDICT


# --------------------------------------------------------------------------- #
# The composition root                                                           #
# --------------------------------------------------------------------------- #


class TestCompositionRoot:
    def test_it_publishes_the_collaborators_it_was_built_from(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        ops = operations(store, backups, clock, controller_id="ctl-b")
        assert ops.scope == "control-plane"
        assert ops.controller_id == "ctl-b"
        assert ops.backups is backups
        assert ops.identities is not None
        assert ops.promotions is not None
        assert ops.failover.controller_id == "ctl-b"
        assert ops.rotation.policy.policy_id == "p-strict"

    def test_the_scope_can_be_narrowed(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        ops = ClusterOperations(
            store=store,
            controller_id="ctl-a",
            election=LeaderElection(
                store=SqliteLeadershipStore(store),
                controller_id="ctl-a",
                scope="cell-eu-1",
                clock=clock,
            ),
            policy=RotationPolicy(policy_id="p"),
            backups=backups,
        )
        assert ops.scope == "cell-eu-1"
        assert ops.members(at=NOW).scope == "cell-eu-1"

    def test_the_last_promotion_decision_is_surfaced_verbatim(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        ops = operations(store, backups, clock, controller_id="ctl-b")
        FailoverPromotionStore(store).register_standby("ctl-b", scope="control-plane", at=NOW)
        ops.failover.promote_if_dead(
            [
                LivenessObservation(
                    kind=LivenessEvidenceKind.PROBE_UNREACHABLE,
                    observed_term=1,
                    observed_at=NOW,
                    source="watchdog",
                    detail="cannot reach ctl-a",
                )
            ],
            operator="ops",
            reason="primary unreachable",
        )
        view = ops.members(at=NOW)
        assert "REFUSED" in view.last_promotion_note
        assert "the scope did not move" in view.last_promotion_note

    def test_with_no_decision_the_note_is_empty(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        view = operations(store, backups, clock).members(at=NOW)
        assert view.last_promotion_note == ""
        assert "last promotion" not in view.describe()

    def test_a_dashboard_cannot_promote_a_standby(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        """The split between reading the cluster and changing it, asserted."""
        FailoverPromotionStore(store).register_standby("ctl-b", scope="control-plane", at=NOW)
        ops = operations(store, backups, clock, controller_id="ctl-b")

        for _ in range(3):
            ops.members(at=NOW)

        assert store.query("SELECT * FROM control_plane_promotions") == []
        assert store.query("SELECT * FROM control_plane_leaders") == []


class TestHonestDefaults:
    def test_the_clock_defaults_to_the_real_one_and_the_view_stamps_utc_now(self) -> None:
        view = ClusterMembershipView(scope="control-plane", caveat=ClusterOperations.CAVEAT)
        assert view.as_of.tzinfo is not None
        assert abs((view.as_of - utc_now()).total_seconds()) < 60

    def test_a_naive_view_stamp_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            ClusterMembershipView(
                scope="control-plane",
                as_of=datetime(2026, 3, 1, 12, 0),  # noqa: DTZ001 - naive on purpose
                caveat=ClusterOperations.CAVEAT,
            )
        assert caught.value.rule == "cluster.time_aware"

    def test_every_credential_state_exists_and_only_two_are_healthy(self) -> None:
        healthy = {CredentialState.CURRENT, CredentialState.ROTATION_DUE}
        assert {state for state in CredentialState if state not in healthy} == {
            CredentialState.EXPIRED,
            CredentialState.REVOKED,
            CredentialState.UNKNOWN_KEY,
        }
        assert len(CredentialState) == 5

    def test_the_store_is_the_only_source_so_a_view_needs_no_cache_invalidation(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        identities = AgentIdentityRepository(store)
        ops = operations(store, backups, clock)
        assert ops.members(at=NOW).agents == ()
        identities.save(identity())
        assert len(ops.members(at=NOW).agents) == 1
        with store.write() as conn:
            conn.execute("DELETE FROM agent_identities")
        assert ops.members(at=NOW).agents == ()

    def test_no_sqlite_error_escapes_from_the_view(
        self, store: Store, backups: BackupEngine, clock: Clock
    ) -> None:
        """A missing table is a deployment problem, not a stack trace to a dashboard."""
        store.close()
        with pytest.raises(sqlite3.ProgrammingError):
            operations(store, backups, clock).members(at=NOW)
