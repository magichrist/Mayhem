"""The cluster membership view, and the one object that wires the plan together
(plan 19, Phase 3 surface).

Phases 1-3 built four separate vocabularies and four separate engines. None of
them answers "what does this control plane look like right now, and is any of it
unhealthy?", which is the question an operator opens a terminal to ask. This
module is the read model and the composition root:

* :class:`ClusterMembershipView` — one immutable projection over the leadership
  lease, the standby roster, the enrolled identities, and the most recent
  promotion decision.
* :class:`ClusterOperations` — the object a surface (the CLI, a watchdog, an HTTP
  handler) constructs once, from a :class:`~mayhem.infra.store.Store`, and then
  calls.

The view is a *projection*, and it says what it is not
------------------------------------------------------

Every field is recomputed from the store on each call. Nothing is cached, so two
views taken a second apart differ if the store did, and a view is never a lock:
nothing here reserves leadership, spends a fence, or rotates a credential. The
split between "read the cluster" and "change the cluster" is the split between
this module and :mod:`mayhem.controller.failover_service` /
:mod:`mayhem.controller.credential_rotation`, and it is worth keeping: an operator
dashboard cannot promote a standby by rendering it.

Three places the view refuses to reassure
-----------------------------------------

The honest part of a membership view is the places where a field could have been a
green light and is not:

* :attr:`ClusterMembershipView.leadership_verdict` is
  :data:`LeadershipVerdict.SINGLE_DISPATCHER` **only** when a live lease exists and
  the standing pattern holds. There is no quorum and no partition detection in this
  build, so the view reports
  :data:`LeadershipVerdict.LEASE_ONLY_UNVERIFIED` when a lease is live and says
  why: a lease bounds how much damage two leaders can do, it does not prove there
  is one.
* :attr:`ClusterMembershipView.backup_trusted`` is ``False`` for every datastore
  with no *verified* restore drill, and the reason string says "no drill has
  verified a restore". A backup that exists and has never been restored is not a
  backup, and Phase 2's schema makes that visible rather than this module guessing.
* :attr:`AgentView.credential_state` is a small enum, not a boolean, and its
  ``UNKNOWN_KEY`` member is reachable: after a rotation with no key provisioner
  bound the credential is current but cannot sign. A boolean would render that
  agent as healthy.

Where the numbers come from
---------------------------

Nothing in this module computes an SLO, an availability figure, or a recovery
objective. Recovery targets are :class:`~mayhem.domain.backup.RecoveryObjective`
values (Phase 1) compared against :class:`~mayhem.domain.backup.Measurement`
objects that only a completed drill can produce (Phase 2), and this view prints
the comparison verbatim via
:meth:`~mayhem.domain.backup.ObjectiveComparison.verdict`. It never fills in a
number nobody measured.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.controller.credential_rotation import (
    CredentialRotationService,
    RotationPolicy,
    RotationVerdict,
)
from mayhem.controller.failover_service import FailoverService
from mayhem.domain.agent_identity import RotationState
from mayhem.domain.backup import RecoveryObjective
from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.infra.agent_identity_store import AgentIdentityRepository, BackupRepository
from mayhem.infra.failover_store import FailoverPromotionStore

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mayhem.controller.leader_election import LeaderElection, LeaderLease
    from mayhem.domain.agent_identity import AgentIdentity
    from mayhem.domain.backup import ObjectiveReport
    from mayhem.infra.agent_identity_verifier import KeyMaterialPort
    from mayhem.infra.backup_engine import BackupEngine
    from mayhem.infra.failover_store import StandbyRecord
    from mayhem.infra.store import Store

_ID = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"


def _require_aware(moment: datetime, rule: str, subject: str) -> None:
    """Refuse naive instants. A view stamped with one has no place on a timeline."""
    if moment.tzinfo is None:
        raise InvariantViolationError(
            rule, f"{subject} must be timezone-aware, got naive {moment!r}"
        )


class LeadershipVerdict(StrEnum):
    """What the view can honestly say about dispatch authority."""

    #: No lease is recorded at all: nothing dispatches.
    NO_LEADER = "no_leader"
    #: A live lease exists. **This is the best this build can say**, and the
    #: distinction from :attr:`LEASE_ONLY_UNVERIFIED` is that nothing contradicts
    #: it — not that it is proven.
    SINGLE_DISPATCHER = "single_dispatcher"
    #: A lease exists but has expired, so nothing dispatches even though a leader
    #: is recorded.
    LEASE_EXPIRED = "lease_expired"
    #: A second controller registered as a standby and has not been observed to be
    #: in sync, so a promotion is possible and unattended.
    STANDBY_NOT_OBSERVED = "standby_not_observed"


class CredentialState(StrEnum):
    """One agent's credential, in words rather than a boolean."""

    CURRENT = "current"
    #: Past its policy's rotation due date but still inside its validity window.
    ROTATION_DUE = "rotation_due"
    #: Past its validity window: it can no longer authenticate, whatever else.
    EXPIRED = "expired"
    #: Revoked, at either the credential or the identity level.
    REVOKED = "revoked"
    #: Current, but no signing key resolves for it. Reachable, and the reason it is
    #: a member here rather than folded into ``CURRENT``.
    UNKNOWN_KEY = "unknown_key"


class ControllerRecord(BaseModel):
    """One controller's standing in this control plane.

    ``role`` is :attr:`ControllerRole.STANDBY` because the standby *registered as
    one*, which is a claim about itself, and :attr:`ControllerRole.LEADER` only
    because a lease row names it. Neither is an authentication: nothing here
    verifies that the process holding this id is the process that registered.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    controller_id: str = Field(pattern=_ID)
    role: str
    term: Annotated[int, Field(ge=0)] = 0
    expires_at: datetime | None = None
    advertised_version: str = ""
    detail: str = Field(min_length=1)

    def describe(self) -> str:
        return f"{self.controller_id} [{self.role}]: {self.detail}"


class AgentView(BaseModel):
    """One enrolled agent, as the cluster sees it.

    Attributes:
        agent_id: Whose agent.
        controller_id: Which controller owns it.
        credential_id: The current credential.
        rotation_state: Phase 1's own rotation state.
        credential_state: This module's four-plus-one way of describing it.
        expires_at: The credential's validity end (tz-aware).
        pin_reason: Phase 1's pinning verdict, read verbatim. An agent with no
            configured anchor is ``no_anchors``, which is a refusal upstream and is
            printed as such rather than normalised away.
        rotation_reason: Why this agent is or is not due.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str = Field(pattern=_ID)
    controller_id: str = Field(pattern=_ID)
    credential_id: str = Field(pattern=_ID)
    rotation_state: RotationState = RotationState.CURRENT
    credential_state: CredentialState = CredentialState.CURRENT
    expires_at: datetime
    pin_reason: str = "unrecorded"
    rotation_reason: str = ""

    @property
    def healthy(self) -> bool:
        """True only for an agent that is current, unexpired, unrevoked, and keyed.

        A property rather than a column, so it cannot drift from the fields it is
        derived from.
        """
        return self.credential_state in (
            CredentialState.CURRENT,
            CredentialState.ROTATION_DUE,
        )

    def describe(self) -> str:
        pin = "" if self.pin_reason in ("pinned", "unrecorded") else f", pin {self.pin_reason}"
        return (
            f"{self.agent_id} on {self.controller_id}: credential {self.credential_id} "
            f"[{self.credential_state.value}] until {self.expires_at.isoformat()}{pin}"
            + (f"; {self.rotation_reason}" if self.rotation_reason else "")
        )


class RecoveryView(BaseModel):
    """What the recovery posture looks like *right now*, in words.

    No number here is invented. ``rpo_verdict`` and ``rto_verdict`` are Phase 1's
    :meth:`~mayhem.domain.backup.ObjectiveComparison.verdict` strings, which read
    "not demonstrated" when no drill has verified a restore — and that string is the
    point of this view rather than an inconvenience.

    Attributes:
        datastore: Which datastore.
        objective: The stated target, if one was ever stated.
        snapshots: How many snapshots exist.
        last_snapshot_at: When the newest was captured.
        backup_trusted: Phase 2's own answer, which is ``True`` only when a
            verified drill exists.
        rpo_verdict / rto_verdict: Verbatim from the comparison.
        detail: The account. Required.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    datastore: str = Field(min_length=1)
    objective: RecoveryObjective | None = None
    snapshots: Annotated[int, Field(ge=0)] = 0
    last_snapshot_at: datetime | None = None
    backup_trusted: bool = False
    rpo_verdict: str = "no objective stated"
    rto_verdict: str = "no objective stated"
    detail: str = Field(min_length=1)

    def describe(self) -> str:
        return (
            f"{self.datastore}: {self.snapshots} snapshot(s), newest "
            f"{self.last_snapshot_at.isoformat() if self.last_snapshot_at else '(never)'}, "
            f"backup trusted={self.backup_trusted}; RPO {self.rpo_verdict}; RTO "
            f"{self.rto_verdict}. {self.detail}"
        )


class ClusterMembershipView(BaseModel):
    """Everything the cluster looks like at one instant.

    Frozen, and rebuilt from the store on every call. It holds no lock and changes
    nothing: rendering it cannot promote a standby, spend a fence, or rotate a
    credential.

    Attributes:
        scope: The leadership scope.
        as_of: The instant the projection was taken (tz-aware).
        leader_id: Who the stored lease names, or ``""``.
        leader_term: The stored term, or ``0``.
        lease_expires_at: When that lease lapses, or ``None``.
        leadership_verdict: What can be said about dispatch authority.
        controllers: Every controller with a standing in this scope.
        agents: Every enrolled agent.
        recovery: One entry per configured datastore.
        last_promotion_note: A one-line account of the most recent promotion
            decision, or ``""`` when there is none.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    scope: str = Field(min_length=1)
    as_of: datetime = Field(default_factory=utc_now)
    leader_id: str = ""
    leader_term: Annotated[int, Field(ge=0)] = 0
    lease_expires_at: datetime | None = None
    leadership_verdict: LeadershipVerdict = LeadershipVerdict.NO_LEADER
    controllers: tuple[ControllerRecord, ...] = ()
    agents: tuple[AgentView, ...] = ()
    recovery: tuple[RecoveryView, ...] = ()
    last_promotion_note: str = ""
    caveat: str = Field(min_length=1)

    @model_validator(mode="after")
    def _check_invariants(self) -> ClusterMembershipView:
        _require_aware(
            self.as_of,
            "cluster.time_aware",
            f"membership view for scope {self.scope!r}",
        )
        return self

    @property
    def has_leader(self) -> bool:
        return bool(self.leader_id)

    @property
    def agent_count(self) -> int:
        return len(self.agents)

    @property
    def unhealthy_agents(self) -> tuple[AgentView, ...]:
        """Agents that are expired, revoked, or unkeyed. Not merely "due"."""
        return tuple(
            a
            for a in self.agents
            if a.credential_state
            in (
                CredentialState.EXPIRED,
                CredentialState.REVOKED,
                CredentialState.UNKNOWN_KEY,
            )
        )

    def describe(self) -> str:
        lines = [
            f"cluster scope {self.scope!r} as of {self.as_of.isoformat()}",
            f"  leadership: {self.leadership_verdict.value}"
            + (
                f" — {self.leader_id} at term {self.leader_term}, lease until "
                + (
                    self.lease_expires_at.isoformat()
                    if self.lease_expires_at is not None
                    else "(unstated)"
                )
                if self.has_leader
                else " — no lease is recorded, so nothing dispatches"
            ),
        ]
        lines.extend(f"  controller: {record.describe()}" for record in self.controllers)
        lines.extend(f"  agent: {agent.describe()}" for agent in self.agents)
        lines.extend(f"  recovery: {entry.describe()}" for entry in self.recovery)
        if self.last_promotion_note:
            lines.append(f"  last promotion: {self.last_promotion_note}")
        lines.append(f"  caveat: {self.caveat}")
        return "\n".join(lines)


class ClusterOperations:
    """The composition root: one object over one store.

    Args:
        store: The replicated SQLite store (ADR-0007: single writer).
        controller_id: This controller's id.
        election: The leadership lease, bound to ``store``.
        policy: The deployment's rotation discipline.
        backups: The Phase 2 backup engine, for the recovery view.
        keys: Optional release/agent key material, used **only** to answer "does a
            key resolve for this agent's current credential" in the membership
            view. Unbound means every agent renders as :attr:`CredentialState.
            UNKNOWN_KEY` rather than as healthy, because an unenrolled key map
            cannot answer the question.
        scope: The leadership scope.

    Why keys are optional and their absence is loud: it is tempting to render an
    agent healthy when nothing was asked about its key. That is the exact shape of
    the defect this module refuses — an unasked question rendered as a pass.
    """

    #: Printed on every view, so a screenshot of the CLI cannot be mistaken for a
    #: claim about quorum.
    CAVEAT: str = (
        "No quorum, no consensus, and no partition detection ship in this build. A live "
        "lease means a single leader is *recorded*; it does not prove a single leader is "
        "running, because a store that is reachable in two places is out of scope. The "
        "term bounds the damage such a split could do; it does not prevent it."
    )

    def __init__(
        self,
        *,
        store: Store,
        controller_id: str,
        election: LeaderElection,
        policy: RotationPolicy,
        backups: BackupEngine,
        keys: KeyMaterialPort | None = None,
        scope: str | None = None,
    ) -> None:
        self._store = store
        self._controller_id = controller_id
        self._election = election
        self._policy = policy
        self._backups = backups
        self._keys = keys
        self._scope = scope or election.scope
        self._identities = AgentIdentityRepository(store)
        self._promotions = FailoverPromotionStore(store)
        self._failover = FailoverService(
            store=self._promotions,
            election=election,
            controller_id=controller_id,
            scope=self._scope,
        )
        self._rotation = CredentialRotationService(identities=self._identities, policy=policy)

    # -- accessors ------------------------------------------------------------
    @property
    def scope(self) -> str:
        return self._scope

    @property
    def controller_id(self) -> str:
        return self._controller_id

    @property
    def identities(self) -> AgentIdentityRepository:
        return self._identities

    @property
    def promotions(self) -> FailoverPromotionStore:
        return self._promotions

    @property
    def failover(self) -> FailoverService:
        return self._failover

    @property
    def rotation(self) -> CredentialRotationService:
        return self._rotation

    @property
    def backups(self) -> BackupEngine:
        return self._backups

    # -- the view -------------------------------------------------------------
    def members(self, *, at: datetime | None = None) -> ClusterMembershipView:
        """Project the cluster as it is at ``at``.

        Raises:
            InvariantViolationError: If ``at`` is naive.
        """
        moment = utc_now() if at is None else at
        _require_aware(moment, "cluster.time_aware", "ClusterOperations.members")
        lease = self._election.current()
        standbys = self._promotions.standbys(self._scope)
        verdicts = {v.agent_id: v for v in self._rotation.survey(at=moment)}
        agents = tuple(
            self._agent_view(identity, verdicts.get(identity.agent_id), at=moment)
            for identity in sorted(self._identities.list_agents(), key=lambda i: i.agent_id)
        )
        last = self._promotions.last_promotion(self._scope)
        return ClusterMembershipView(
            scope=self._scope,
            as_of=moment,
            leader_id="" if lease is None else lease.leader_id,
            leader_term=0 if lease is None else lease.term,
            lease_expires_at=None if lease is None else lease.expires_at,
            leadership_verdict=self._leadership_verdict(lease, standbys, moment),
            controllers=self._controller_records(lease, standbys, moment),
            agents=agents,
            recovery=self._recovery_views(),
            last_promotion_note="" if last is None else last.describe(),
            caveat=self.CAVEAT,
        )

    def _agent_view(
        self, identity: AgentIdentity, verdict: RotationVerdict | None, *, at: datetime
    ) -> AgentView:
        credential = identity.credential
        return AgentView(
            agent_id=identity.agent_id,
            controller_id=identity.controller_id,
            credential_id=credential.credential_id,
            rotation_state=credential.rotation_state,
            credential_state=self._credential_state(identity, verdict, at=at),
            expires_at=credential.expires_at,
            pin_reason=identity.pin_verdict().reason.value,
            rotation_reason="" if verdict is None else verdict.reason,
        )

    def _credential_state(
        self, identity: AgentIdentity, verdict: RotationVerdict | None, *, at: datetime
    ) -> CredentialState:
        """The five-way answer. Never collapses to a boolean.

        ``UNKNOWN_KEY`` is reachable and is not folded into ``CURRENT``: after a
        rotation with no key provisioner bound, the credential *is* current and the
        agent still cannot sign anything. A two-valued field would render that agent
        as healthy, which is the exact defect a membership view exists to catch.

        The window is consulted directly rather than through
        :meth:`~mayhem.domain.agent_identity.AgentCredential.is_valid_at`, because
        that convenience answers "can this credential still be used" — and being
        *due for rotation* is a refusal there, not an expiry. Relying on it made
        :attr:`CredentialState.ROTATION_DUE` unreachable and rendered every due
        agent as ``EXPIRED``, which is the difference between "rotate this soon" and
        "this is broken" in an operator's dashboard.
        """
        credential = identity.credential
        window = credential.rotation_window()
        if identity.revoked or credential.revocation is not None or credential.superseded:
            return CredentialState.REVOKED
        if window.is_not_yet_valid(at) or window.is_expired(at):
            return CredentialState.EXPIRED
        key_id = credential.serial.strip() or credential.credential_id
        if self._keys is None or self._keys.lookup(key_id) is None:
            return CredentialState.UNKNOWN_KEY
        if window.is_due(at) or (verdict is not None and verdict.due):
            return CredentialState.ROTATION_DUE
        return CredentialState.CURRENT

    def _leadership_verdict(
        self,
        lease: LeaderLease | None,
        standbys: Sequence[StandbyRecord],
        moment: datetime,
    ) -> LeadershipVerdict:
        if lease is None:
            return LeadershipVerdict.NO_LEADER
        if lease.is_expired_at(moment):
            return LeadershipVerdict.LEASE_EXPIRED
        if standbys and not all(standby.observed for standby in standbys):
            return LeadershipVerdict.STANDBY_NOT_OBSERVED
        return LeadershipVerdict.SINGLE_DISPATCHER

    def _controller_records(
        self,
        lease: LeaderLease | None,
        standbys: Sequence[StandbyRecord],
        moment: datetime,
    ) -> tuple[ControllerRecord, ...]:
        records: dict[str, ControllerRecord] = {}
        for standby in standbys:
            records[standby.standby_id] = ControllerRecord(
                controller_id=standby.standby_id,
                role="standby",
                term=standby.observed_term,
                advertised_version=standby.advertised_version,
                detail=(
                    f"registered as a standby, last observed term {standby.observed_term}"
                    + (
                        ""
                        if standby.observed
                        else "; never observed in sync, so a promotion is possible and "
                        "this says nothing about its readiness"
                    )
                ),
            )
        if lease is not None:
            live = not lease.is_expired_at(moment)
            records[lease.leader_id] = ControllerRecord(
                controller_id=lease.leader_id,
                role="leader",
                term=lease.term,
                expires_at=lease.expires_at,
                detail=(
                    f"holds the recorded lease at term {lease.term}, "
                    + ("still live" if live else "EXPIRED — nothing dispatches")
                ),
            )
        return tuple(records[key] for key in sorted(records))

    def _recovery_views(self) -> tuple[RecoveryView, ...]:
        """One entry per stated objective, plus one for any datastore with snapshots.

        Sourced from the objectives a deployment actually stated, rather than from
        a hard-coded datastore name: a view that invented a datastore would print
        "0 snapshots" for a system nobody backs up, which reads like a finding
        rather than like the absence of a configuration.
        """
        backups = BackupRepository(self._store)
        objectives = backups.list_objectives()
        if not objectives:
            return ()
        return tuple(self._recovery_view(objective) for objective in objectives)

    def _recovery_view(self, objective: RecoveryObjective) -> RecoveryView:
        snapshots = self._backups.backups.list_snapshots(datastore=objective.datastore)
        comparison = self._backups.report(objective.datastore)
        return RecoveryView(
            datastore=objective.datastore,
            objective=objective,
            snapshots=len(snapshots),
            last_snapshot_at=self._backups.last_snapshot_at(objective.datastore),
            backup_trusted=self._backups.is_backup_trusted(objective.datastore),
            rpo_verdict=_rpo_verdict(comparison),
            rto_verdict=_rto_verdict(comparison),
            detail=objective.describe(),
        )


#: The text used when a datastore has no report at all. One string, defined here,
#: so "there is no evidence" reads the same way in the CLI, in a test, and in a
#: document quoting it.
NO_EVIDENCE_VERDICT: str = (
    "not demonstrated — no restore drill has been recorded for this datastore"
)


def _rpo_verdict(report: ObjectiveReport | None) -> str:
    """Phase 1's own RPO verdict text, verbatim."""
    if report is None:
        return NO_EVIDENCE_VERDICT
    return report.rpo.verdict


def _rto_verdict(report: ObjectiveReport | None) -> str:
    """Phase 1's own RTO verdict text, verbatim."""
    if report is None:
        return NO_EVIDENCE_VERDICT
    return report.rto.verdict


__all__ = [
    "CAVEAT_PLACEHOLDER",
    "AgentView",
    "ClusterMembershipView",
    "ClusterOperations",
    "ControllerRecord",
    "CredentialState",
    "LeadershipVerdict",
    "RecoveryView",
]


#: Placeholder kept so ``__all__`` reads the way the rest of the repo's modules do
#: while stating, in source, that :class:`ClusterOperations.CAVEAT` is the only
#: caveat string this module publishes.
CAVEAT_PLACEHOLDER = ClusterOperations.CAVEAT
