"""Promote a standby, or refuse to (plan 19, Phase 3 engine surface).

Phases 1 and 2 built the vocabulary (:mod:`mayhem.domain.failover`), the
leadership lease (:mod:`mayhem.controller.leader_election`), the promotion record
(:mod:`mayhem.infra.failover_store`), and the mTLS trust decision
(:mod:`mayhem.infra.certificate_authority`). This module is the one function a
person or a watchdog calls, and its whole job is to make the ordering of those
things unskippable.

The ordering, and why it is this ordering
-----------------------------------------

:meth:`FailoverService.promote` does exactly five things, in this order, and each
step is a precondition for the next:

1. **The evidence and the request agree about the term.**
   :func:`~mayhem.domain.failover.assert_assessment_consistent` — evidence about
   term 3 cannot decide term 4.
2. **The evidence establishes that the primary is gone.**
   :func:`~mayhem.domain.failover.require_promotable`, which is *pure*. It runs
   before the store is read, which is the point: there is no window in which the
   system has observed the leadership state and then promoted on an assessment
   that does not support it. "Could not determine whether the primary is alive"
   therefore cannot reach :meth:`~mayhem.controller.leader_election.LeaderElection.campaign`,
   which is the only call that can move the term.
3. **The stored term has not moved.** A request decided against term *N* is
   refused if the store is now at *N+1* — somebody promoted while this request was
   in flight, and the evidence that justified the request says nothing about the
   term that now exists.
4. **The lease is either expired or explicitly forced.** A live foreign lease is
   refused with :data:`~mayhem.domain.failover.PromotionRefusal.LEASE_LIVE` unless
   the request set ``forced``, which is the operator break-glass path and is
   recorded as such. When it is forced, the term still strictly increases, so the
   deposed leader loses its authority the instant the campaign lands — which is
   the property that makes forcing safe *because of* the term rather than in spite
   of it.
5. **The decision is recorded, promoted or refused.** Both outcomes go to
   :class:`~mayhem.infra.failover_store.FailoverPromotionStore`, because
   "we observed the partition and did not promote" is the record an incident
   review needs and a success-only table could not produce.

Refusals are *returned*, not raised, and they are recorded
------------------------------------------------------------

:meth:`promote` returns a :class:`~mayhem.domain.failover.PromotionDecision` on
both paths. That is not politeness: the CLI wants to print the refusals, the
watchdog wants to log them and keep waiting, and a caller that wants the raise has
:meth:`promote_or_raise`. What is *not* available is a caller that ignores a
refusal and dispatches anyway, because the only thing that can move the term is
:meth:`~mayhem.controller.leader_election.LeaderElection.campaign` and it is not
reachable from here after a refusal.

Honesty about who the standby is
--------------------------------

``standby_id`` is recorded as a **claim**. This module verifies the *evidence*, not
the identity of the controller presenting it: there is no handshake, and a caller
that wanted an authenticated promotion would have to run
:meth:`~mayhem.infra.certificate_authority.MtlsTrustService.controller_capable`
itself and pass the resulting certificate in — which is not wired here, so it is
stated rather than implied. What a promotion record proves is that *this process,
holding the store, wrote this row*, not that a particular controller at a
particular address did.

Deliberately absent
-------------------

* **No ``resign``.** A hand-written handover path with a half-implemented store
  operation is worse than none, the same reasoning
  :class:`~mayhem.controller.leader_election.LeaderElection` records.
* **No cold start.** With no lease recorded there is nothing to depose, and a
  promotion must strictly increase a term — so :meth:`promote` refuses with
  :data:`~mayhem.domain.failover.PromotionRefusal.NO_LEADER` and says that
  claiming an empty scope is a *campaign*
  (:meth:`~mayhem.controller.leader_election.LeaderElection.campaign`), which
  writes a lease and no promotion record.
* **No health check, no heartbeat, no quorum.** The evidence is supplied by the
  caller. That is the right seam: the sources of liveness evidence are
  deployment-specific (a service manager, a lease store, a replica), and a policy
  that guessed among them would be a policy nobody could audit.
* **No socket.** Agents never listen (ADR-0003) and this module opens nothing.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from mayhem.domain.common import utc_now
from mayhem.domain.failover import (
    DEFAULT_FRESHNESS_BOUND_S,
    LivenessAssessment,
    LivenessObservation,
    PromotionDecision,
    PromotionOutcome,
    PromotionRefusal,
    PromotionRefusedError,
    PromotionRequest,
    assert_assessment_consistent,
    assess_primary,
    decision_from_campaign,
    order_promotion_refusals,
    require_promotable,
)
from mayhem.infra.failover_store import (
    FailoverPromotionStore,
    PromotionRecord,
    assessment_document,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence
    from datetime import datetime

    from mayhem.controller.leader_election import LeaderElection, LeaderLease

#: The default leadership scope, read from the election module rather than
#: re-spelled so the two cannot disagree about what "the control plane" is.
DEFAULT_SCOPE = "control-plane"


def new_promotion_id() -> str:
    """A fresh promotion id. ``p19-`` prefixed so it is greppable in a store dump."""
    return f"p19-{uuid.uuid4().hex[:16]}"


class FailoverService:
    """Decide, record, and perform a standby promotion.

    Args:
        store: The durable promotion/standby record.
        election: The leadership lease. Reused verbatim; **this module introduces
            no second notion of leadership and no second fencing scheme**. The
            term the election bumps is the fence for the scope.
        controller_id: This controller's id.
        scope: The leadership scope.
        clock: Injected, so a drill reproduces.
        freshness_bound_s: Default bound applied when a caller does not state one.

    Holds no state. Every decision is recomputed from the store, so constructing a
    second service over the same store *is* a second controller and it is
    immediately correct because there was nothing in the first one to lose.
    """

    def __init__(
        self,
        *,
        store: FailoverPromotionStore,
        election: LeaderElection,
        controller_id: str,
        scope: str = DEFAULT_SCOPE,
        clock: Callable[[], datetime] = utc_now,
        freshness_bound_s: float = DEFAULT_FRESHNESS_BOUND_S,
    ) -> None:
        self._store = store
        self._election = election
        self._controller_id = controller_id
        self._scope = scope
        self._clock = clock
        self._freshness_bound_s = float(freshness_bound_s)

    @property
    def controller_id(self) -> str:
        return self._controller_id

    @property
    def scope(self) -> str:
        return self._scope

    @property
    def freshness_bound_s(self) -> float:
        return self._freshness_bound_s

    # -- requests -------------------------------------------------------------
    def assess(
        self,
        observations: Iterable[LivenessObservation],
        *,
        expected_term: int,
        now: datetime | None = None,
        freshness_bound_s: float | None = None,
    ) -> LivenessAssessment:
        """Build the assessment a request would carry. Pure.

        A thin, named wrapper over
        :func:`~mayhem.domain.failover.assess_primary` so the bound this service
        was configured with is applied consistently and so a caller assembling a
        request by hand is visibly doing the same thing.
        """
        return assess_primary(
            observations,
            expected_term=expected_term,
            now=now,
            freshness_bound_s=(
                self._freshness_bound_s if freshness_bound_s is None else freshness_bound_s
            ),
        )

    def request(
        self,
        assessment: LivenessAssessment,
        *,
        operator: str,
        reason: str,
        forced: bool = False,
        expected_term: int | None = None,
        at: datetime | None = None,
    ) -> PromotionRequest:
        """Build a :class:`PromotionRequest` for this standby and ``assessment``.

        Constructible with an insufficient assessment on purpose — a refusal has to
        be recordable — but it *does* reject an assessment assembled for a
        different term than the request names, because that is a programming error
        rather than a policy outcome.
        """
        moment = self._clock() if at is None else at
        term = assessment.expected_term if expected_term is None else expected_term
        assert_assessment_consistent(assessment, request_term=term)
        return PromotionRequest(
            scope=self._scope,
            standby_id=self._controller_id,
            expected_term=term,
            assessment=assessment,
            forced=forced,
            operator=operator.strip(),
            reason=reason.strip(),
            requested_at=moment,
        )

    # -- the operation --------------------------------------------------------
    def promote(
        self,
        request: PromotionRequest,
        *,
        at: datetime | None = None,
    ) -> PromotionDecision:
        """Promote, or return a refusal naming every reason. **Nothing else moves.**

        Returns:
            A :class:`PromotionDecision`. ``decision.promoted`` is the only way to
            learn whether the scope moved; there is no "assume yes" default.
        """
        moment = self._clock() if at is None else at
        assert_assessment_consistent(request.assessment, request_term=request.expected_term)

        refusals = list(request.refusals())
        lease = self._election.current()
        refusals.extend(self._state_refusals(request, lease, moment=moment))
        if refusals:
            ordered = order_promotion_refusals(refusals)
            decision = PromotionDecision(
                request=request,
                outcome=PromotionOutcome.REFUSED,
                refusals=ordered,
                detail=self._refusal_detail(request, lease, ordered),
                decided_at=moment,
            )
            self._store.record_promotion(self._record(request, decision, lease))
            return decision

        # Step 2's `require_promotable` is unreachable-as-a-raise here, because the
        # refusals above already carry every reason it would have raised. Called
        # anyway so that the invariant "no campaign without a passing assessment"
        # is enforced by the domain function rather than by this module's reading of
        # it, and so a future change to `refusals()` cannot quietly open a path.
        require_promotable(request)

        claimed = self._election.campaign(force=request.forced, now=moment)
        decision = decision_from_campaign(request, new_term=claimed.term, decided_at=moment)
        self._store.record_promotion(self._record(request, decision, lease))
        return decision

    def promote_or_raise(
        self, request: PromotionRequest, *, at: datetime | None = None
    ) -> PromotionDecision:
        """:meth:`promote`, or raise on a refusal.

        Raises:
            PromotionRefusedError: Carrying
                :attr:`~mayhem.domain.failover.PromotionRefusedError.decision`, so a
                caller that only wants the exception still has the record.
        """
        decision = self.promote(request, at=at)
        if not decision.promoted:
            raise PromotionRefusedError(decision)
        return decision

    def promote_if_dead(
        self,
        observations: Iterable[LivenessObservation],
        *,
        operator: str,
        reason: str,
        forced: bool = False,
        now: datetime | None = None,
        freshness_bound_s: float | None = None,
    ) -> PromotionDecision:
        """Assess, request, promote — the whole path in one call.

        Convenience, not a shortcut past anything: it calls
        :meth:`~mayhem.domain.failover.assess_primary`, then :meth:`request`, then
        :meth:`promote`, in that order. The tests use it for the drill, and the
        three-step form is available when a caller wants to inspect the assessment
        first.
        """
        moment = self._clock() if now is None else now
        lease = self._election.current()
        term = 1 if lease is None else lease.term
        assessment = self.assess(
            observations,
            expected_term=term,
            now=moment,
            freshness_bound_s=freshness_bound_s,
        )
        request = self.request(
            assessment, operator=operator, reason=reason, forced=forced, at=moment
        )
        return self.promote(request, at=moment)

    # -- refusals -------------------------------------------------------------
    def _state_refusals(
        self,
        request: PromotionRequest,
        lease: LeaderLease | None,
        *,
        moment: datetime,
    ) -> tuple[PromotionRefusal, ...]:
        """The refusals that need the store, which the pure request cannot know.

        Split out so the ordering of :meth:`promote` is legible: the pure check
        runs first, and only then is anything read.
        """
        refusals: list[PromotionRefusal] = []
        if lease is None:
            # No lease at all. This is not a failover — nothing was deposed, and a
            # first controller claiming an empty scope is a *campaign*. Refusing by
            # name also keeps the structural invariant intact: a promotion must
            # strictly increase a term, and with nothing stored there is no term to
            # increase, so any decision produced here would have to lie about it.
            return (PromotionRefusal.NO_LEADER,)
        if lease.term != request.expected_term:
            refusals.append(PromotionRefusal.TERM_MOVED)
        if lease.leader_id == self._controller_id and lease.term == request.expected_term:
            refusals.append(PromotionRefusal.ALREADY_LEADER)
        if not lease.is_expired_at(moment) and not request.forced:
            refusals.append(PromotionRefusal.LEASE_LIVE)
        return tuple(refusals)

    def _refusal_detail(
        self,
        request: PromotionRequest,
        lease: LeaderLease | None,
        refusals: Sequence[PromotionRefusal],
    ) -> str:
        """The account a reader gets. Names the store state, not just the rule."""
        parts = [
            f"{request.standby_id} asked for scope {request.scope!r} at term "
            f"{request.expected_term}; the store holds "
            + (
                "no leader at all"
                if lease is None
                else f"term {lease.term} held by {lease.leader_id} until "
                f"{lease.expires_at.isoformat()}"
            )
        ]
        parts.append(f"refused for: {', '.join(reason.value for reason in refusals)}")
        if PromotionRefusal.LEASE_LIVE in refusals:
            parts.append(
                "a live lease is a primary that may still be dispatching; pass forced=True "
                "only when an operator has decided it is hung, and note that forcing still "
                "strictly increases the term, so the deposed leader loses authority at once"
            )
        if PromotionRefusal.TERM_MOVED in refusals:
            parts.append(
                "the term moved while this request was in flight, so its evidence describes "
                "a scope that no longer exists; re-assess against the current term"
            )
        if PromotionRefusal.NO_LEADER in refusals:
            parts.append(
                "nothing holds this scope, so there is no failover to perform: the first "
                "controller in a cluster campaigns rather than promotes, and campaign() "
                "writes a leadership lease without claiming a deposed leader it never had"
            )
        return " | ".join(parts)

    def _record(
        self,
        request: PromotionRequest,
        decision: PromotionDecision,
        lease: LeaderLease | None,
    ) -> PromotionRecord:
        """The durable row for ``decision``, promoted or refused."""
        return PromotionRecord(
            promotion_id=new_promotion_id(),
            scope=request.scope,
            standby_id=request.standby_id,
            deposed_leader_id="" if lease is None else lease.leader_id,
            deposed_term=0 if lease is None else lease.term,
            new_term=decision.new_term or 0,
            operator=request.operator,
            reason=request.reason,
            forced=request.forced,
            status=decision.outcome.value,
            refusals=tuple(reason.value for reason in decision.refusals),
            evidence=assessment_document(request.assessment),
            promoted_at=decision.decided_at,
        )

    # -- reads ----------------------------------------------------------------
    def current_lease(self) -> LeaderLease | None:
        """The stored leadership lease for this scope, expired or not.

        The seam a surface reads to build its own evidence: a caller that wants to
        decide for itself what the store says has one named accessor rather than a
        private attribute, and the value it returns is the store's record.
        """
        return self._election.current()

    def campaign(self, *, at: datetime | None = None) -> LeaderLease:
        """Claim the scope outright. **Not a failover.**

        Claiming an empty scope is a different act from taking one over, and it is
        exposed separately for exactly that reason: a caller that wants "become the
        leader" can say so, and a caller that wants "take over from this primary"
        cannot reach this by accident. :meth:`promote` deliberately refuses with
        :data:`~mayhem.domain.failover.PromotionRefusal.NO_LEADER` instead of
        calling it.
        """
        moment = self._clock() if at is None else at
        return self._election.campaign(now=moment)

    def last_decision(self) -> PromotionRecord | None:
        """The most recent promotion record for this scope, promoted or refused."""
        return self._store.last_promotion(self._scope)

    def history(self) -> tuple[PromotionRecord, ...]:
        """Every recorded decision for this scope, oldest first."""
        return self._store.promotions(self._scope)
