"""Leader election over the replicated store, with fencing on every dispatch.

Plan ``docs/v1.1.0/19_HA_DR_SECURITY.md`` Phase 2 -- "leader election over the
replicated store with fencing so only the leader dispatches". Acceptance for the
phase names leader-kill drills; the property this module makes unrepresentable is
the one a leader-kill drill is trying to observe: **a deposed leader cannot
dispatch, and a new leader cannot double-dispatch a step.**

The model, stated once so nobody has to reconstruct it
-------------------------------------------------------

Leadership is a **lease with a monotonic term**, persisted in the same store every
controller reads (ADR-0007: the controller is the single writer).

* :meth:`LeaderElection.campaign` is a compare-and-set in one transaction. A
  scope with no record, an expired record, or *our own* record may be claimed, and
  claiming bumps ``term``. A live foreign lease is refused
  (:class:`LeadershipRefusedError`) -- mutual exclusion by lease, which is the
  primitive a real election needs, and which is honest about what it is rather than
  pretending to be a Raft vote.
* The **term is the fence for leadership itself**. :meth:`require_leader` compares
  the caller's ``term`` against the stored one, so a lease that was valid a moment
  ago stops authorising the instant a successor claims. Expiry alone would not do
  this: a partition can leave a deposed leader's clock inside its own lease
  indefinitely, and "my lease has not expired" is not authority.
* :meth:`LeaderElection.fence_for` mints the fence a dispatch will carry, and it
  is **strictly newer** than any epoch already dispatched for that step
  (:meth:`~mayhem.domain.fabric.FencingToken.next_fence` is the only way to grow
  one). A new leader therefore cannot reuse the old epoch, which is the
  no-double-dispatch mechanism from the takeover side.
* :meth:`LeaderElection.dispatch` is the only door to a provider. It checks
  leadership, then the step fence, then records ``(epoch, command_id)``
  atomically, then calls the injected dispatcher. Recording before dispatching is
  what makes a crash mid-dispatch leave a claim rather than a hole.

**``FencingToken`` is used verbatim from :mod:`mayhem.domain.fabric` and is not
re-defined, wrapped into a second type, or re-ordered here.** Phase 1 of plan 19
stated the rule at length: two orderings over one ``(run_id, step_id)`` is the
split-brain the fence exists to prevent. This module adds *leadership* terms, which
order leadership scopes -- a different scope, deliberately, because a controller
can be leader of the control plane and still be fenced out of one step.

What this module does NOT do
----------------------------

* **It does not replace :class:`~mayhem.controller.fabric_engine.FabricEngine`.**
  That engine owns the claim/settlement journal, idempotent retries and provider
  normalisation; this module owns *who may start one at all*. A controller wires
  them in that order and this file does not touch the engine.
* **It does not open a socket, dial an agent, or hold a session.** Agents never
  listen (ADR-0003, :mod:`mayhem.agents.transports`); the dispatcher callable is
  injected and is whatever controller-initiated session the caller already has.
* **It does not detect a partition or a clock problem.** A controller that cannot
  reach the store simply cannot claim, expire, or record -- and every one of those
  is required before a dispatch, so losing the store stops dispatch. What is *not*
  implemented is lease renewal under contention, membership change, or a
  quorum: a store that is reachable but partitioned in two is out of scope, and
  the term mechanism bounds the damage rather than preventing it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Protocol

from mayhem.domain.common import iso_utc, utc_now
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.fabric import FabricCommand, FencingToken

if TYPE_CHECKING:
    import sqlite3
    from collections.abc import Callable, Mapping

    from mayhem.infra.store import Store

#: Stable refusal code: somebody else's live lease holds the scope.
LEADERSHIP_TAKEN = "leadership_taken"
#: Stable refusal code: the caller's lease is deposed, expired, or somebody else's.
LEADER_NOT_CURRENT = "leader_not_current"
#: Stable refusal code: a second effect was already claimed for this step at this
#: epoch, or the epoch is older than the one already dispatched.
STEP_ALREADY_DISPATCHED = "step_already_dispatched"

#: The leadership scope used when a caller does not name one. One control plane,
#: one leader, unless an operator deliberately partitions by name.
DEFAULT_LEADERSHIP_SCOPE = "control-plane"

#: Default lease lifetime. Long enough that a normal GC pause does not trigger a
#: failover, short enough that a crashed leader is replaced promptly. Not a
#: tuned number: it is an argument with a default, and an operator who needs a
#: different one configures it.
DEFAULT_LEADER_TTL_S = 30.0

_REMEDIATION_LEADERSHIP = (
    "campaign for leadership first; only the leader holding the current, unexpired "
    "term may dispatch"
)
_REMEDIATION_STEP = (
    "mint a strictly newer fence with next_fence() and re-dispatch; a step that was "
    "already dispatched at this epoch does not take a second effect"
)


class LeadershipError(DomainError):
    """Leader election refused an operation. Nothing was dispatched."""


class LeadershipRefusedError(LeadershipError):
    """The scope is held by another leader whose lease has not expired."""

    def __init__(self, scope: str, leader_id: str, term: int, expires_at: datetime) -> None:
        self.code = LEADERSHIP_TAKEN
        self.scope = scope
        self.leader_id = leader_id
        self.term = term
        self.expires_at = expires_at
        super().__init__(
            f"{LEADERSHIP_TAKEN}: scope {scope!r} is held by {leader_id!r} at term {term} "
            f"until {expires_at.isoformat()}"
        )
        self.remediation = _REMEDIATION_LEADERSHIP


class LeaderNotCurrentError(LeadershipError):
    """The presented lease is not the current authority for its scope."""

    def __init__(self, scope: str, leader_id: str, term: int, detail: str) -> None:
        self.code = LEADER_NOT_CURRENT
        self.scope = scope
        self.leader_id = leader_id
        self.term = term
        super().__init__(
            f"{LEADER_NOT_CURRENT}: {leader_id!r} presents term {term} for scope "
            f"{scope!r} but is not the current leader: {detail}"
        )
        self.remediation = _REMEDIATION_LEADERSHIP


class StepAlreadyDispatchedError(LeadershipError):
    """A second effect was claimed for this step at an epoch that may not repeat.

    Two distinguishable situations share this code because they share the remedy, and
    the message says which it is: the epoch was *spent* by a command, or it was
    *minted* for a dispatch that has not happened yet. "already dispatched ''" would
    be a lie in the second case, and an operator chasing a lost command needs to know
    which one they are looking at.
    """

    def __init__(
        self,
        run_id: str,
        step_id: str,
        epoch: int,
        dispatched_command_id: str,
        *,
        minted_only: bool = False,
    ) -> None:
        self.code = STEP_ALREADY_DISPATCHED
        self.run_id = run_id
        self.step_id = step_id
        self.epoch = epoch
        self.dispatched_command_id = dispatched_command_id
        self.minted_only = minted_only
        state = (
            "holds a minted, not-yet-dispatched fence"
            if minted_only
            else f"already dispatched {dispatched_command_id!r}"
        )
        super().__init__(
            f"{STEP_ALREADY_DISPATCHED}: step {run_id}/{step_id} {state} at epoch {epoch}; "
            "a second effect at that epoch would be a second owner"
        )
        self.remediation = _REMEDIATION_STEP


# --------------------------------------------------------------------------- #
# Records                                                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LeaderLease:
    """Proof that a controller held a leadership scope, at a term.

    A statement about a *term*, not a session. It stays readable after the lease
    has expired (an incident review needs to know who held what when), and
    :meth:`LeaderElection.require_leader` is what decides whether it still
    authorises anything. There is no ``valid`` flag on this dataclass for the same
    reason :class:`~mayhem.domain.agent_identity.CredentialGrant` has none: the
    check is re-run at the moment of use.

    Attributes:
        scope: Leadership scope (``control-plane`` by default).
        term: Monotonic, 1-based, strictly increasing per scope.
        leader_id: The controller that claimed it.
        acquired_at: When the claim was recorded (tz-aware).
        expires_at: Lease expiry (tz-aware).
    """

    scope: str
    term: int
    leader_id: str
    acquired_at: datetime
    expires_at: datetime

    def is_expired_at(self, moment: datetime) -> bool:
        """At-and-after expiry, matching every other deadline in the system."""
        return moment >= self.expires_at

    def remaining_s(self, moment: datetime) -> float:
        return max(0.0, (self.expires_at - moment).total_seconds())

    def to_dict(self) -> dict[str, object]:
        return {
            "scope": self.scope,
            "term": self.term,
            "leader_id": self.leader_id,
            "acquired_at": iso_utc(self.acquired_at),
            "expires_at": iso_utc(self.expires_at),
        }

    @classmethod
    def from_row(cls, row: Mapping[str, object] | sqlite3.Row) -> LeaderLease:
        """Rebuild from a ``control_plane_leaders`` row."""
        record: dict[str, object] = dict(row)
        return cls(
            scope=str(record["scope"]),
            term=int(str(record["term"])),
            leader_id=str(record["leader_id"]),
            acquired_at=datetime.fromisoformat(str(record["acquired_at"])),
            expires_at=datetime.fromisoformat(str(record["expires_at"])),
        )

    def describe(self) -> str:
        return (
            f"{self.leader_id} holds {self.scope!r} at term {self.term} "
            f"[{self.acquired_at.isoformat()} → {self.expires_at.isoformat()}]"
        )


@dataclass(frozen=True, slots=True)
class DispatchedStep:
    """What a step's fence slot currently records.

    Attributes:
        fence: The highest fence dispatched for the step.
        command_id: The command that spent that epoch; ``""`` when the slot holds a
            minted fence that has not been dispatched yet.
        dispatched_at: When the epoch was spent; ``None`` while unminted-only.
    """

    fence: FencingToken
    command_id: str = ""
    dispatched_at: datetime | None = None

    @property
    def dispatched(self) -> bool:
        return bool(self.command_id)

    def describe(self) -> str:
        spent = self.command_id or "not yet dispatched"
        return (
            f"{self.fence.run_id}/{self.fence.step_id} at epoch {self.fence.epoch} "
            f"held by {self.fence.holder}: {spent}"
        )


# --------------------------------------------------------------------------- #
# The store port and its SQLite binding                                        #
# --------------------------------------------------------------------------- #


class LeadershipStore(Protocol):
    """Durable leadership and step-fence state.

    A port so the election rule can be exercised against a fake and so a
    non-SQLite replicated store (plan 08) can be bound without touching the rule.
    Every method must be atomic with respect to the others -- the election's
    mutual exclusion is entirely this object's transactional guarantee.
    """

    def load_lease(self, scope: str) -> LeaderLease | None: ...

    def claim(self, lease: LeaderLease, *, force: bool = False) -> LeaderLease:
        """Compare-and-set: refuse unless the scope is claimable at ``lease.term - 1``."""
        ...

    def load_step(self, run_id: str, step_id: str) -> DispatchedStep | None: ...

    def record_mint(self, run_id: str, step_id: str, fence: FencingToken) -> DispatchedStep: ...

    def record_dispatch(self, command: FabricCommand, *, at: datetime) -> DispatchedStep: ...


class SqliteLeadershipStore:
    """:class:`LeadershipStore` over ``M0032_HA_DR``.

    ``Store.write`` is the single-writer transaction boundary and is serialized by
    the store's lock (ADR-0007), so each method below is a genuine
    read-modify-write with no interleaving.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def load_lease(self, scope: str) -> LeaderLease | None:
        rows = self._store.query("SELECT * FROM control_plane_leaders WHERE scope = ?", (scope,))
        return LeaderLease.from_row(rows[0]) if rows else None

    def claim(self, lease: LeaderLease, *, force: bool = False) -> LeaderLease:
        """Insert or replace the scope's lease, refusing a stale compare-and-set.

        Args:
            lease: The lease to install.
            force: Overwrite a live foreign lease. The stored term must still be
                strictly below ``lease.term``, so forcing can never move the term
                backwards.

        Raises:
            LeadershipRefusedError: If a *different* leader's unexpired lease is
                present and ``force`` is false, or if the stored term is already at
                or beyond ``lease.term`` -- which means somebody else claimed while
                we were deciding.
        """
        with self._store.write() as conn:
            rows = conn.execute(
                "SELECT * FROM control_plane_leaders WHERE scope = ?", (lease.scope,)
            ).fetchall()
            if rows:
                current = LeaderLease.from_row(rows[0])
                live = not current.is_expired_at(lease.acquired_at)
                if live and current.leader_id != lease.leader_id and not force:
                    raise LeadershipRefusedError(
                        current.scope, current.leader_id, current.term, current.expires_at
                    )
                if current.term >= lease.term:
                    # Somebody else claimed while we were deciding. Refuse rather
                    # than overwrite: the term is the fence, so a lost compare-and-set
                    # is a lost election, not a retryable write.
                    raise LeadershipRefusedError(
                        current.scope,
                        current.leader_id,
                        current.term,
                        current.expires_at,
                    )
            conn.execute(
                "INSERT OR REPLACE INTO control_plane_leaders "
                "(scope, term, leader_id, acquired_at, expires_at, updated_at) "
                "VALUES (?,?,?,?,?,?)",
                (
                    lease.scope,
                    lease.term,
                    lease.leader_id,
                    iso_utc(lease.acquired_at),
                    iso_utc(lease.expires_at),
                    iso_utc(lease.acquired_at),
                ),
            )
        return lease

    def load_step(self, run_id: str, step_id: str) -> DispatchedStep | None:
        rows = self._store.query(
            "SELECT * FROM control_plane_step_fences WHERE run_id = ? AND step_id = ?",
            (run_id, step_id),
        )
        if not rows:
            return None
        record = dict(rows[0])
        dispatched_at = str(record["dispatched_at"]) or ""
        return DispatchedStep(
            fence=FencingToken.model_validate_json(str(record["fence_json"])),
            command_id=str(record["dispatched_command_id"]),
            dispatched_at=datetime.fromisoformat(dispatched_at) if dispatched_at else None,
        )

    def record_mint(self, run_id: str, step_id: str, fence: FencingToken) -> DispatchedStep:
        """Remember a minted (not yet dispatched) fence.

        Raises:
            InvariantViolationError: If the fence does not belong to this step, or
                if it is not strictly newer than the recorded epoch -- a record that
                went backwards would let an old owner look current.
        """
        if (fence.run_id, fence.step_id) != (run_id, step_id):
            msg = (
                f"fence for {fence.run_id}/{fence.step_id} cannot be recorded against "
                f"{run_id}/{step_id}"
            )
            raise InvariantViolationError("leadership.fence_scope", msg)
        with self._store.write() as conn:
            current = self.load_step(run_id, step_id)
            if current is not None and not fence.is_after(current.fence):
                msg = (
                    f"refusing to record fence epoch {fence.epoch} for {run_id}/{step_id}: "
                    f"the recorded epoch is {current.fence.epoch}"
                )
                raise InvariantViolationError("leadership.fence_not_newer", msg)
            conn.execute(
                "INSERT OR REPLACE INTO control_plane_step_fences "
                "(run_id, step_id, epoch, holder, issued_at, dispatched_command_id, "
                " dispatched_at, fence_json) VALUES (?,?,?,?,?,'','',?)",
                (
                    run_id,
                    step_id,
                    fence.epoch,
                    fence.holder,
                    iso_utc(fence.issued_at),
                    fence.model_dump_json(),
                ),
            )
        return DispatchedStep(fence=fence)

    def record_dispatch(self, command: FabricCommand, *, at: datetime) -> DispatchedStep:
        """Spend this step's epoch for ``command``.

        Raises:
            StepAlreadyDispatchedError: If the epoch is already spent by a *different*
                command. The same ``command_id`` is accepted as an idempotent
                re-record: a retry of one envelope is one effect, and a second
                *command* at one epoch is two.
        """
        fence = command.fencing_token
        with self._store.write() as conn:
            current = self.load_step(command.run_id, command.step_id)
            if current is not None:
                if current.command_id == command.command_id:
                    # The same envelope recorded twice is one effect, not two.
                    return current
                # Epoch arithmetic rather than ``is_after`` alone, because the slot
                # may hold a fence that was *minted* for exactly this epoch and not
                # yet dispatched. ``is_after`` is strictly-newer and would refuse the
                # very dispatch the mint was made for.
                if fence.epoch <= current.fence.epoch and not (
                    fence.epoch == current.fence.epoch and not current.dispatched
                ):
                    raise StepAlreadyDispatchedError(
                        command.run_id,
                        command.step_id,
                        current.fence.epoch,
                        current.command_id,
                        minted_only=not current.dispatched,
                    )
            conn.execute(
                "INSERT OR REPLACE INTO control_plane_step_fences "
                "(run_id, step_id, epoch, holder, issued_at, dispatched_command_id, "
                " dispatched_at, fence_json) VALUES (?,?,?,?,?,?,?,?)",
                (
                    command.run_id,
                    command.step_id,
                    fence.epoch,
                    fence.holder,
                    iso_utc(fence.issued_at),
                    command.command_id,
                    iso_utc(at),
                    fence.model_dump_json(),
                ),
            )
        return DispatchedStep(fence=fence, command_id=command.command_id, dispatched_at=at)


# --------------------------------------------------------------------------- #
# The election                                                                 #
# --------------------------------------------------------------------------- #


class LeaderElection:
    """Claim leadership, mint fences, and be the only door to a dispatch.

    Args:
        store: Durable leadership/step-fence state. Two ``LeaderElection`` objects
            over the same store are two controllers, which is exactly what the
            tests use to produce a deposed leader.
        controller_id: Who is claiming.
        ttl_s: Lease lifetime.
        scope: Leadership scope; ``control-plane`` by default.
        clock: Injected, so expiry and term changes are reproducible.

    Holds no dispatch state. Every decision is recomputed from ``store``, so
    constructing a second instance over the same store *is* a controller failover
    and it is immediately correct because there was nothing in the first one to
    lose.
    """

    def __init__(
        self,
        *,
        store: LeadershipStore,
        controller_id: str,
        ttl_s: float = DEFAULT_LEADER_TTL_S,
        scope: str = DEFAULT_LEADERSHIP_SCOPE,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if ttl_s <= 0:
            msg = f"leader lease ttl must be positive, got {ttl_s}"
            raise InvariantViolationError("leadership.ttl", msg)
        if not controller_id.strip():
            msg = "a leader must have an id; an anonymous leader cannot be deposed by name"
            raise InvariantViolationError("leadership.controller_id", msg)
        self._store = store
        self._controller_id = controller_id
        self._ttl_s = float(ttl_s)
        self._scope = scope
        self._clock = clock

    @property
    def controller_id(self) -> str:
        return self._controller_id

    @property
    def scope(self) -> str:
        return self._scope

    # -- projections ----------------------------------------------------------
    def current(self) -> LeaderLease | None:
        """The stored lease for the scope, expired or not."""
        return self._store.load_lease(self._scope)

    def is_leader(self, lease: LeaderLease, *, now: datetime | None = None) -> bool:
        """True when ``lease`` is still the current authority at ``now``.

        Three conditions, all necessary: it is *our* id, it is the *stored* term
        (so a successor has deposed us), and it has not *expired*.
        """
        moment = self._clock() if now is None else now
        stored = self._store.load_lease(lease.scope)
        if stored is None:
            return False
        return (
            stored.leader_id == lease.leader_id
            and stored.term == lease.term
            and not lease.is_expired_at(moment)
        )

    def require_leader(self, lease: LeaderLease, *, now: datetime | None = None) -> LeaderLease:
        """Return the stored lease, or refuse.

        Raises:
            LeaderNotCurrentError: If the scope has no record (we never claimed, or
                it was deleted), if another leader holds it, if the stored term has
                moved past ours (we were deposed), or if our own lease expired.
                Each is named in the message, because "you are not the leader" is
                not a useful incident report.
        """
        moment = self._clock() if now is None else now
        stored = self._store.load_lease(lease.scope)
        if stored is None:
            raise LeaderNotCurrentError(
                lease.scope,
                lease.leader_id,
                lease.term,
                "no leader is recorded for this scope",
            )
        if stored.term != lease.term:
            raise LeaderNotCurrentError(
                lease.scope,
                lease.leader_id,
                lease.term,
                f"the scope is at term {stored.term} held by {stored.leader_id}",
            )
        if stored.leader_id != lease.leader_id:
            raise LeaderNotCurrentError(
                lease.scope,
                lease.leader_id,
                lease.term,
                f"term {stored.term} is held by {stored.leader_id}",
            )
        if lease.is_expired_at(moment):
            raise LeaderNotCurrentError(
                lease.scope,
                lease.leader_id,
                lease.term,
                f"the lease expired at {lease.expires_at.isoformat()}",
            )
        return stored

    # -- campaign -------------------------------------------------------------
    def campaign(self, *, force: bool = False, now: datetime | None = None) -> LeaderLease:
        """Claim (or re-claim) leadership, returning the lease we now hold.

        A live foreign lease is refused with :class:`LeadershipRefusedError` -- two
        leaders cannot both own the scope, and the loser is told who won rather than
        being told "try again". An expired or absent lease is claimable, and an
        owner re-campaigning (after its own expiry) gets a strictly higher term, so
        its old lease cannot come back to life.

        Args:
            force: Claim **even though another leader's lease has not expired.**
                This is the operator's break-glass path for a controller that is
                hung (a long lease would otherwise keep a dead leader in charge for
                its whole TTL), and it is safe *because* of the term rather than in
                spite of it: forcing bumps the term, and from that instant the
                forced-out leader's lease no longer matches the stored one, so
                :meth:`require_leader` refuses its dispatch immediately. Without the
                term there would be nothing to make a forced handover safe, and this
                argument would not exist.

            now: Injected instant, so a handover is reproducible in a drill.

        Raises:
            LeadershipRefusedError: If a live foreign lease is present and ``force``
                is false, or if the stored term is already at or beyond the term this
                claim would take -- i.e. somebody else claimed while we were
                deciding.
        """
        moment = self._clock() if now is None else now
        stored = self._store.load_lease(self._scope)
        next_term = 1 if stored is None else stored.term + 1
        lease = LeaderLease(
            scope=self._scope,
            term=next_term,
            leader_id=self._controller_id,
            acquired_at=moment,
            expires_at=moment + timedelta(seconds=self._ttl_s),
        )
        return self._store.claim(lease, force=force)

    # Note on what is deliberately absent: there is no ``resign`` and no
    # ``renew``. ``campaign()`` *is* renewal -- an owner re-campaigning after its
    # own expiry gets a strictly higher term, which is what makes the old lease
    # unusable -- and a hand-written ``resign`` would need a store operation whose
    # only use is to let a controller bump the term without dispatching anything.
    # A half-implemented handover path is a worse thing to leave in a safety
    # module than an absent one.

    # -- fences ---------------------------------------------------------------
    def dispatched_step(self, run_id: str, step_id: str) -> DispatchedStep | None:
        """What is recorded for one step's fence slot, or ``None``."""
        return self._store.load_step(run_id, step_id)

    def fence_for(
        self,
        lease: LeaderLease,
        *,
        run_id: str,
        step_id: str,
        holder: str,
        now: datetime | None = None,
    ) -> FencingToken:
        """Mint the fence the next dispatch of ``(run_id, step_id)`` will carry.

        Strictly newer than anything already recorded for the step, via
        :meth:`~mayhem.domain.fabric.FencingToken.next_fence`. That is the
        no-double-dispatch mechanism from the takeover side: a new leader physically
        cannot present the deposed leader's epoch, so even a buggy or hostile
        successor cannot re-run an effect under the old owner's fence.

        Raises:
            LeaderNotCurrentError: If the caller does not hold current leadership.
            InvariantViolationError: If the recorded epoch is already at or beyond
                one this call would mint.
        """
        moment = self._clock() if now is None else now
        self.require_leader(lease, now=moment)
        recorded = self._store.load_step(run_id, step_id)
        fence = (
            recorded.fence.next_fence(holder=holder, now=moment)
            if recorded is not None
            else FencingToken.issue(run_id=run_id, step_id=step_id, holder=holder, now=moment)
        )
        self._store.record_mint(run_id, step_id, fence)
        return fence

    # -- the only door to a provider -------------------------------------------
    def dispatch(
        self,
        lease: LeaderLease,
        command: FabricCommand,
        dispatcher: Callable[[FabricCommand], object],
        *,
        now: datetime | None = None,
    ) -> object:
        """Dispatch ``command`` if and only if we are still the leader.

        Order is the point, and each step is a precondition for the next:

        1. :meth:`require_leader` -- a deposed or expired lease stops here, before
           the provider is touched and before the epoch is spent.
        2. ``record_dispatch`` -- the epoch is spent and the command id recorded in
           one transaction, so a second effect at this epoch by a *different*
           command is refused (:class:`StepAlreadyDispatchedError`). Recording
           before dispatching is deliberate: a crash after the record leaves a claim
           that says "this epoch was spent", which is recoverable; a crash before it
           leaves nothing, which is not.
        3. ``dispatcher(command)`` -- the injected controller-initiated session.

        The dispatcher is a callable, not a transport, and this module opens no
        socket: agents never listen (ADR-0003), so the caller supplies the session it
        already has.

        Raises:
            LeaderNotCurrentError: If we are not the current leader.
            StepAlreadyDispatchedError: If the step already took an effect at this
                epoch.
        """
        moment = self._clock() if now is None else now
        self.require_leader(lease, now=moment)
        self._store.record_dispatch(command, at=moment)
        return dispatcher(command)
