"""Tests for leader election with fencing (plan 19 Phase 2).

The phase's acceptance is a leader-kill drill. This file *is* that drill, run
against a real SQLite store with two ``LeaderElection`` objects over it — which is
exactly the shape of a failover: the second object is a second controller, not a
method call on the first.

The three properties under test, and the negative controls for each:

1. **Only one leader owns a scope.** :meth:`LeaderElection.campaign` refuses a
   second claimer while the first lease is live
   (``LeadershipRefusedError`` / :data:`LEADERSHIP_TAKEN`).
2. **A deposed leader cannot dispatch.** The successor bumps the term, and the
   deposed lease's term no longer matches the stored one — so
   :meth:`LeaderElection.dispatch` refuses *before* the dispatcher is called, even
   though the deposed lease has not expired yet. That last part is the point: an
   unexpired lease is not authority.
3. **A new leader cannot double-dispatch a step.** Its fence is strictly newer
   (:meth:`~mayhem.domain.fabric.FencingToken.next_fence`), and the store refuses a
   second command at an epoch that is already spent
   (``StepAlreadyDispatchedError``).

Also pinned: the same ``command_id`` re-recorded is *not* a second effect (an
idempotent retry is one envelope), and ``FencingToken`` is used from
:mod:`mayhem.domain.fabric` rather than a second fence type being introduced here.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.controller.leader_election import (
    DEFAULT_LEADERSHIP_SCOPE,
    LEADER_NOT_CURRENT,
    LEADERSHIP_TAKEN,
    STEP_ALREADY_DISPATCHED,
    DispatchedStep,
    LeaderElection,
    LeaderLease,
    LeaderNotCurrentError,
    LeadershipRefusedError,
    SqliteLeadershipStore,
    StepAlreadyDispatchedError,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.fabric import (
    FABRIC_PROTOCOL_VERSION,
    CommandBodyRef,
    FabricCommand,
    FabricCommandType,
    FencingToken,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
RUN_ID = "r-1"
STEP_ID = "s-1"
TTL_S = 30.0

#: The version of ``M0032_HA_DR``. A literal on purpose: the reversibility drill
#: below is a claim about *that* migration, so the migration it targets is pinned
#: while the length of the chain it sits in is not. See the test's docstring.
HA_DR_VERSION = 32


class Clock:
    """A hand-advanced clock, so expiry and terms are reproducible."""

    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def fence(*, epoch: int = 1, holder: str = "ctl-a", step_id: str = STEP_ID) -> FencingToken:
    return FencingToken(
        run_id=RUN_ID, step_id=step_id, holder=holder, epoch=epoch, issued_at=NOW
    )


def command(
    *,
    command_id: str = "fc-1",
    token: FencingToken | None = None,
    step_id: str = STEP_ID,
    nonce: str | None = None,
) -> FabricCommand:
    return FabricCommand(
        protocol=FABRIC_PROTOCOL_VERSION,
        command_id=command_id,
        run_id=RUN_ID,
        step_id=step_id,
        agent_id="ag-1",
        plan_digest="a" * 64,
        nonce=nonce or f"{abs(hash(command_id)):032x}"[:32],
        idempotency_key=f"idem-{command_id}",
        fencing_token=token if token is not None else fence(step_id=step_id),
        command=CommandBodyRef(
            command_type=FabricCommandType.PREPARE, body_digest="b" * 64, body_ref="body-1"
        ),
        issued_at=NOW,
        signing_key_id="cr-1",
        signature="A" * 64,
    )


class Recorder:
    """Stands in for the controller-initiated agent session.

    Records every command it is handed, so "the dispatcher was not called" is an
    assertion about observed behaviour rather than about an exception.
    """

    def __init__(self) -> None:
        self.seen: list[str] = []

    def __call__(self, envelope: FabricCommand) -> str:
        self.seen.append(envelope.command_id)
        return f"dispatched:{envelope.command_id}"


@pytest.fixture
def store() -> Store:
    return Store.open_migrated(":memory:")


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def leadership(store: Store, clock: Clock) -> SqliteLeadershipStore:
    return SqliteLeadershipStore(store)


def controller(
    store: SqliteLeadershipStore, controller_id: str, clock: Clock, *, ttl_s: float = TTL_S
) -> LeaderElection:
    return LeaderElection(
        store=store, controller_id=controller_id, ttl_s=ttl_s, clock=clock
    )


# --------------------------------------------------------------------------- #
# Campaign: one leader per scope                                               #
# --------------------------------------------------------------------------- #


def test_first_claimant_wins_term_one(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    lease = controller(leadership, "ctl-a", clock).campaign()

    assert lease.term == 1
    assert lease.leader_id == "ctl-a"
    assert lease.scope == DEFAULT_LEADERSHIP_SCOPE
    assert lease.remaining_s(clock()) == pytest.approx(TTL_S)


def test_second_claimant_is_refused_while_the_lease_is_live(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """NEGATIVE CONTROL: two leaders cannot both own a run."""
    controller(leadership, "ctl-a", clock).campaign()

    with pytest.raises(LeadershipRefusedError) as refused:
        controller(leadership, "ctl-b", clock).campaign()

    assert refused.value.code == LEADERSHIP_TAKEN
    assert refused.value.leader_id == "ctl-a"
    assert refused.value.term == 1


def test_an_expired_lease_is_claimable_and_bumps_the_term(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """The failover case: the first controller's lease lapses, the second takes over."""
    first = controller(leadership, "ctl-a", clock).campaign()
    clock.advance(TTL_S + 1.0)

    second = controller(leadership, "ctl-b", clock).campaign()

    assert second.leader_id == "ctl-b"
    assert second.term == first.term + 1
    # The old lease is readable for an incident review, and still says who held it.
    assert leadership.load_lease(DEFAULT_LEADERSHIP_SCOPE).leader_id == "ctl-b"


def test_re_campaigning_after_own_expiry_yields_a_strictly_newer_term(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    first = controller(leadership, "ctl-a", clock).campaign()
    clock.advance(TTL_S + 1.0)

    again = controller(leadership, "ctl-a", clock).campaign()

    assert again.term == first.term + 1


def test_scopes_are_independent(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    controller(leadership, "ctl-a", clock).campaign()
    other = LeaderElection(
        store=leadership, controller_id="ctl-b", scope="cell-a", clock=clock
    )

    assert other.campaign().leader_id == "ctl-b"


def test_a_non_positive_ttl_is_refused_at_construction(leadership: SqliteLeadershipStore) -> None:
    with pytest.raises(InvariantViolationError, match="ttl"):
        LeaderElection(store=leadership, controller_id="ctl-a", ttl_s=0.0)


def test_an_anonymous_leader_is_refused_at_construction(leadership: SqliteLeadershipStore) -> None:
    """A leader nobody can name cannot be deposed by name."""
    with pytest.raises(InvariantViolationError, match="controller_id"):
        LeaderElection(store=leadership, controller_id="  ")


# --------------------------------------------------------------------------- #
# require_leader: the term is the fence                                         #
# --------------------------------------------------------------------------- #


def test_the_current_lease_authorises(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    lease = controller(leadership, "ctl-a", clock).campaign()
    engine = controller(leadership, "ctl-a", clock)

    assert engine.is_leader(lease)
    assert engine.require_leader(lease) == lease


def test_an_expired_lease_does_not_authorise(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """NEGATIVE CONTROL: an unexpired-by-others lease that has expired stops here."""
    lease = controller(leadership, "ctl-a", clock).campaign()
    clock.advance(TTL_S + 1.0)

    with pytest.raises(LeaderNotCurrentError) as refused:
        controller(leadership, "ctl-a", clock).require_leader(lease)

    assert refused.value.code == LEADER_NOT_CURRENT
    assert "expired" in str(refused.value)


def test_a_deposed_lease_is_refused_even_before_it_expires(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """**The load-bearing negative control.**

    ``ctl-a`` holds a 600-second lease and only 1 second has elapsed, yet it may not
    act: ``ctl-b`` forced the handover and bumped the term. Expiry alone would not
    produce this — a hung or partitioned controller can sit comfortably inside its
    own lease for the whole TTL, and "my lease has not expired" is not authority. The
    term is what makes the forced handover safe.
    """
    deposed = controller(leadership, "ctl-a", clock, ttl_s=600.0).campaign()
    clock.advance(1.0)
    successor = controller(leadership, "ctl-b", clock).campaign(force=True)

    assert successor.term == deposed.term + 1
    assert deposed.is_expired_at(clock()) is False  # still nominally live

    engine_a = controller(leadership, "ctl-a", clock)
    assert engine_a.is_leader(deposed) is False
    with pytest.raises(LeaderNotCurrentError) as refused:
        engine_a.require_leader(deposed)

    assert refused.value.code == LEADER_NOT_CURRENT
    assert f"term {deposed.term}" in str(refused.value)
    assert "ctl-b" in str(refused.value)


def test_a_deposed_leader_cannot_dispatch_even_with_an_unexpired_lease(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """The same property, at the door: the dispatcher is never reached."""
    deposed = controller(leadership, "ctl-a", clock, ttl_s=600.0).campaign()
    clock.advance(1.0)
    controller(leadership, "ctl-b", clock).campaign(force=True)
    recorder = Recorder()

    with pytest.raises(LeaderNotCurrentError):
        controller(leadership, "ctl-a", clock).dispatch(
            deposed, command(), recorder
        )

    assert recorder.seen == []
    # The epoch was not spent either, so the successor owns an untouched step.
    assert leadership.load_step(RUN_ID, STEP_ID) is None


def test_an_unclaimed_scope_authorises_nobody(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    invented = LeaderLease(
        scope=DEFAULT_LEADERSHIP_SCOPE,
        term=7,
        leader_id="ctl-ghost",
        acquired_at=NOW,
        expires_at=NOW + timedelta(seconds=TTL_S),
    )
    with pytest.raises(LeaderNotCurrentError, match="no leader is recorded"):
        controller(leadership, "ctl-a", clock).require_leader(invented)


# --------------------------------------------------------------------------- #
# Fences: strictly newer, never reused                                          #
# --------------------------------------------------------------------------- #


def test_first_fence_for_a_step_is_epoch_one(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    lease = controller(leadership, "ctl-a", clock).campaign()
    minted = controller(leadership, "ctl-a", clock).fence_for(
        lease, run_id=RUN_ID, step_id=STEP_ID, holder="ctl-a"
    )

    assert minted.epoch == 1
    assert leadership.load_step(RUN_ID, STEP_ID).fence.epoch == 1


def test_each_fence_is_strictly_newer_than_the_last(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """A new leader cannot reuse the deposed leader's epoch. Reuse is double dispatch."""
    lease = controller(leadership, "ctl-a", clock).campaign()
    engine = controller(leadership, "ctl-a", clock)
    first = engine.fence_for(lease, run_id=RUN_ID, step_id=STEP_ID, holder="ctl-a")
    second = engine.fence_for(lease, run_id=RUN_ID, step_id=STEP_ID, holder="ctl-a")

    assert second.is_after(first)
    assert second.epoch == first.epoch + 1
    assert second.supersedes_epoch == first.epoch


def test_a_deposed_leader_cannot_mint_a_fence(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    deposed = controller(leadership, "ctl-a", clock).campaign()
    clock.advance(TTL_S + 1.0)
    controller(leadership, "ctl-b", clock).campaign()

    with pytest.raises(LeaderNotCurrentError):
        controller(leadership, "ctl-a", clock).fence_for(
            deposed, run_id=RUN_ID, step_id=STEP_ID, holder="ctl-a"
        )


def test_fences_are_per_step(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """One step's epoch says nothing about another's — that is plan 03's scope rule."""
    lease = controller(leadership, "ctl-a", clock).campaign()
    engine = controller(leadership, "ctl-a", clock)
    engine.fence_for(lease, run_id=RUN_ID, step_id=STEP_ID, holder="ctl-a")
    other = engine.fence_for(lease, run_id=RUN_ID, step_id="s-2", holder="ctl-a")

    assert other.epoch == 1
    assert leadership.load_step(RUN_ID, "s-2").fence.step_id == "s-2"


def test_recording_a_minted_fence_reports_it_as_undispatched(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    lease = controller(leadership, "ctl-a", clock).campaign()
    engine = controller(leadership, "ctl-a", clock)
    engine.fence_for(lease, run_id=RUN_ID, step_id=STEP_ID, holder="ctl-a")

    recorded = engine.dispatched_step(RUN_ID, STEP_ID)
    assert isinstance(recorded, DispatchedStep)
    assert recorded.dispatched is False
    assert "not yet dispatched" in recorded.describe()


# --------------------------------------------------------------------------- #
# Dispatch: the only door, and no second effect                                 #
# --------------------------------------------------------------------------- #


def test_the_leader_dispatches_and_the_epoch_is_recorded(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    lease = controller(leadership, "ctl-a", clock).campaign()
    recorder = Recorder()

    result = controller(leadership, "ctl-a", clock).dispatch(lease, command(), recorder)

    assert result == "dispatched:fc-1"
    assert recorder.seen == ["fc-1"]
    recorded = leadership.load_step(RUN_ID, STEP_ID)
    assert recorded is not None
    assert recorded.dispatched is True
    assert recorded.command_id == "fc-1"


def test_a_second_command_at_the_same_epoch_is_refused(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """NEGATIVE CONTROL: one step, one epoch, one effect.

    Two *different* commands at one epoch is two owners of one step by another
    route. The second is refused before the dispatcher is reached.
    """
    lease = controller(leadership, "ctl-a", clock).campaign()
    engine = controller(leadership, "ctl-a", clock)
    recorder = Recorder()
    engine.dispatch(lease, command(command_id="fc-1"), recorder)

    with pytest.raises(StepAlreadyDispatchedError) as refused:
        engine.dispatch(lease, command(command_id="fc-2"), recorder)

    assert refused.value.code == STEP_ALREADY_DISPATCHED
    assert refused.value.epoch == 1
    assert refused.value.dispatched_command_id == "fc-1"
    assert recorder.seen == ["fc-1"]  # the second never reached the provider


def test_an_older_epoch_is_refused_even_under_a_live_lease(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """A replay of the pre-takeover envelope is refused by the fence, not the term."""
    lease = controller(leadership, "ctl-a", clock).campaign()
    engine = controller(leadership, "ctl-a", clock)
    recorder = Recorder()
    engine.dispatch(lease, command(command_id="fc-1", token=fence(epoch=1)), recorder)

    with pytest.raises(StepAlreadyDispatchedError):
        engine.dispatch(
            lease, command(command_id="fc-old", token=fence(epoch=1, holder="ctl-a")), recorder
        )

    assert recorder.seen == ["fc-1"]


def test_re_recording_the_same_command_is_not_a_second_effect(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """An idempotent retry is one envelope reaching the provider twice, not two effects.

    The same ``command_id`` at the same epoch is accepted as a re-record. A retry is
    the *same* effect however many times it is attempted; what must never happen is a
    **different** effect at an epoch that is already spent.
    """
    lease = controller(leadership, "ctl-a", clock).campaign()
    engine = controller(leadership, "ctl-a", clock)
    recorder = Recorder()
    engine.dispatch(lease, command(command_id="fc-1"), recorder)

    engine.dispatch(lease, command(command_id="fc-1"), recorder)

    assert recorder.seen == ["fc-1", "fc-1"]
    assert leadership.load_step(RUN_ID, STEP_ID).command_id == "fc-1"


def test_a_new_epoch_may_dispatch_again(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    lease = controller(leadership, "ctl-a", clock).campaign()
    engine = controller(leadership, "ctl-a", clock)
    recorder = Recorder()
    engine.dispatch(lease, command(command_id="fc-1", token=fence(epoch=1)), recorder)

    engine.dispatch(
        lease,
        command(command_id="fc-2", token=fence(epoch=2), nonce="1" * 32),
        recorder,
    )

    assert recorder.seen == ["fc-1", "fc-2"]


# --------------------------------------------------------------------------- #
# The failover drill the phase's acceptance asks for                            #
# --------------------------------------------------------------------------- #


def test_leader_kill_drill_forces_a_handover_and_cannot_double_dispatch(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """**The end-to-end drill: leader killed mid-step, successor takes over.**

    Sequence, all against one store:

    1. ``ctl-a`` campaigns and dispatches step ``s-1`` at epoch 1. The provider heard
       about it.
    2. ``ctl-a`` is killed. Its lease is still nominally live for 600s — exactly the
       situation that makes expiry-only mutual exclusion useless.
    3. ``ctl-b`` forces the handover, which bumps the term.
    4. ``ctl-a`` comes back (a paused process, a partition that healed) and tries to
       dispatch at epoch 1 again: refused on **leadership**, dispatcher untouched.
    5. ``ctl-b`` mints its fence. It is epoch 2 — strictly newer — so it cannot
       re-present epoch 1.
    6. ``ctl-b`` dispatches. One step, two epochs, one effect each.
    """
    recorder = Recorder()
    controller_a = controller(leadership, "ctl-a", clock, ttl_s=600.0)
    controller_b = controller(leadership, "ctl-b", clock)

    lease_a = controller_a.campaign()
    assert lease_a.term == 1
    controller_a.dispatch(lease_a, command(command_id="fc-1", token=fence(epoch=1)), recorder)
    assert recorder.seen == ["fc-1"]

    # (2)/(3) the leader is killed; the successor forces the handover 1s later.
    clock.advance(1.0)
    lease_b = controller_b.campaign(force=True)
    assert lease_b.term == 2
    assert lease_b.leader_id == "ctl-b"

    # (4) the deposed leader returns and tries to re-dispatch the same envelope.
    with pytest.raises(LeaderNotCurrentError) as refused:
        controller_a.dispatch(lease_a, command(command_id="fc-1b", token=fence(epoch=1)), recorder)
    assert refused.value.code == LEADER_NOT_CURRENT
    assert recorder.seen == ["fc-1"]

    # (5) the successor cannot reuse the old epoch.
    token_b = controller_b.fence_for(
        lease_b, run_id=RUN_ID, step_id=STEP_ID, holder="ctl-b"
    )
    assert token_b.epoch == 2
    assert token_b.holder == "ctl-b"
    with pytest.raises(StepAlreadyDispatchedError):
        controller_b.dispatch(
            lease_b, command(command_id="fc-dup", token=fence(epoch=1)), recorder
        )

    # (6) the successor dispatches under its own, newer fence.
    result = controller_b.dispatch(
        lease_b, command(command_id="fc-2", token=token_b, nonce="2" * 32), recorder
    )
    assert result == "dispatched:fc-2"
    assert recorder.seen == ["fc-1", "fc-2"]
    assert leadership.load_step(RUN_ID, STEP_ID).command_id == "fc-2"


def test_the_handover_record_is_readable_after_the_fact(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """An incident review can name the current leader and the epoch a step reached."""
    controller(leadership, "ctl-a", clock, ttl_s=600.0).campaign()
    clock.advance(1.0)
    controller(leadership, "ctl-b", clock).campaign(force=True)

    current = leadership.load_lease(DEFAULT_LEADERSHIP_SCOPE)
    assert current is not None
    assert (current.leader_id, current.term) == ("ctl-b", 2)
    assert "ctl-b" in current.describe()
    assert leadership.load_step(RUN_ID, STEP_ID) is None


def test_a_restarted_election_instance_is_immediately_correct(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    """A new ``LeaderElection`` over the same store holds no memory of its predecessor."""
    first = controller(leadership, "ctl-a", clock)
    lease = first.campaign()
    clock.advance(1.0)
    controller(leadership, "ctl-b", clock).campaign(force=True)

    # Same controller_id, brand-new object: still deposed, because the *store* moved.
    restarted = controller(leadership, "ctl-a", clock)
    assert restarted.is_leader(lease) is False


def test_a_lease_round_trips_through_a_dict(
    store: Store, clock: Clock, leadership: SqliteLeadershipStore
) -> None:
    lease = controller(leadership, "ctl-a", clock).campaign()
    record = leadership.load_lease(lease.scope)

    assert record is not None
    assert record.to_dict()["leader_id"] == "ctl-a"
    assert record.remaining_s(record.acquired_at) == pytest.approx(TTL_S)


# --------------------------------------------------------------------------- #
# Persistence: the migration is reversible                                       #
# --------------------------------------------------------------------------- #


def test_m0032_is_reversible_and_reapplies_cleanly(tmp_path: Path) -> None:
    """NEGATIVE CONTROL: ``M0032_HA_DR`` ships a down path and a re-apply is clean.

    The additive-schema gate already asserts that a down path *exists*; this asserts
    it *works* and that the election's tables come back, because a down path that
    raises would leave an operator with no way back to a baseline.

    Head-relative on purpose. The subject is migration **32 specifically** — that
    *this* migration reverses, and that its tables come back — not "the chain
    happens to be 32 long". So the literals below identify 32 and its baseline,
    and everything that depends on *how far* the chain has grown is derived:

    * the chain head is read from the database rather than pinned, so registering
      34 does not turn a true statement into a false one;
    * the rollback target is ``HA_DR_VERSION - 1``, so it is "undo the election
      and its successors" regardless of how many successors exist;
    * ``reversed_ids`` is asserted as "contains 0032, and ends with 0032" rather
      than as an exact list, because ``migrate_down`` reverses in strictly
      descending version order — so the lowest migration above the baseline is
      reversed *last*, and "last is 0032" is precisely the claim that 32 was
      reversed. That is *stronger* than the old ``== ["0032_ha_dr"]``, which was
      only ever true while 32 was the head, and would have gone quietly stale the
      next time anything was appended after it.

    Rewriting ``== 32`` as ``== 33`` would have been the tempting one-line change
    and is exactly the pin that breaks again on registration of 34.
    """
    path = tmp_path / "ha-dr.db"
    store = Store.open_migrated(path)
    by_version = {m.version: m for m in ALL_MIGRATIONS}
    ha_dr = by_version[HA_DR_VERSION]
    assert ha_dr.migration_id == "0032_ha_dr"  # the literal subject of this test
    head = store.schema_version
    assert head is not None and head >= HA_DR_VERSION, (
        "0032 must actually be applied to this database, or the drill below "
        "proves nothing about it"
    )

    engine = LeaderElection(
        store=SqliteLeadershipStore(store), controller_id="ctl-a", ttl_s=30.0
    )
    engine.campaign(now=NOW)

    reversed_ids = store.migrate_down(HA_DR_VERSION - 1)
    assert ha_dr.migration_id in reversed_ids
    assert reversed_ids[-1] == ha_dr.migration_id
    assert store.schema_version == HA_DR_VERSION - 1
    tables = {
        str(row["name"])
        for row in store.query("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "control_plane_leaders" not in tables

    reapplied = store.migrate()
    assert ha_dr.migration_id in reapplied
    assert store.schema_version == head
    tables = {
        str(row["name"])
        for row in store.query("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"control_plane_leaders", "control_plane_step_fences"} <= tables
    # The leadership row went with the table, so a re-claim starts from term 1 again.
    reclaimed = LeaderElection(
        store=SqliteLeadershipStore(store), controller_id="ctl-b", ttl_s=30.0
    ).campaign(now=NOW)
    assert reclaimed.term == 1
    store.close()
