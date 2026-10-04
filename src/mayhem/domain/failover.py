"""Failover vocabulary: what counts as evidence that a primary is gone.

Plan ``docs/v1.1.0/19_HA_DR_SECURITY.md``, Phase 3. Phases 1 and 2 built the
identity model (:mod:`mayhem.domain.agent_identity`), the command verifier, the
leadership lease (:mod:`mayhem.controller.leader_election`), and the backup
engine. None of them answers the question this module exists for.

The question
------------

Promoting a standby is the **highest-consequence operation in this system**. A
dispatcher that doubles up produces two injections into the same environment; a
dispatcher that vanishes mid-step leaves a run with an open effect. Between those
two failures, losing availability for thirty seconds is the cheap one. So the
default answer to "should the standby take over?" has to be *no*, and the bar for
*yes* has to be evidence rather than a timeout.

The dangerous sentence is **"could not determine whether the primary is alive"**.
Every failover implementation eventually grows one of two branches, and the
difference between them is the whole safety story:

* wrong -- ``if we cannot reach the primary, promote``  -> a network partition
  becomes a split brain, and the primary is usually still running and still
  dispatching;
* right -- ``if we cannot reach the primary, wait``     -> the lease expires on
  its own and the decision is made from a *fact in the replicated store* rather
  than from an observer's inability to hear anything.

This module makes the second branch the only one that is constructible. There are
exactly three statuses -- :attr:`PrimaryStatus.ALIVE`, :attr:`PrimaryStatus.DEAD`,
and :attr:`PrimaryStatus.INDETERMINATE` -- and only ``DEAD`` may promote. An
``INDETERMINATE`` is a refusal with a name, not a default that a caller is
expected to interpret.

Three-valued on purpose
-----------------------

:attr:`PrimaryStatus` is not a boolean and it is not an enum with a "probably
dead" member that happens to sort last. It is three-valued because the interesting
case is the third one, and a two-valued type pushes the third case into a
caller's head, where it is exactly as likely to be read as "false" as as "true".
:attr:`LivenessAssessment.promotable` is ``status is DEAD`` -- never ``not alive``
-- so a future member added to the enum defaults to *not* promoting.

Which observations can establish death
--------------------------------------

The table is data (:data:`DEATH_EVIDENCE`) rather than a chain of ``if``s, and it
is deliberately small. Two kinds can establish that a primary is gone:

* :attr:`LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED` -- the leadership lease for
  the term in question is present in the replicated store and is *past its
  expiry*. That is a fact about a durable record, which is why it is the strong
  signal: it does not depend on anybody being able to reach anything.
* :attr:`LivenessEvidenceKind.PRIMARY_PROCESS_GONE` -- an out-of-process witness
  (a service manager, a PID namespace, a container runtime) positively reports the
  process as absent. Positive absence is rare and worth honouring.

Everything else is :attr:`LivenessAssessment.status` ``INDETERMINATE``:

* :attr:`LivenessEvidenceKind.HEARTBEAT_MISSING` -- no heartbeat is an absence of
  a signal, not a signal of absence. A paused process, a full disk, and a dead
  process are indistinguishable from the reader's side.
* :attr:`LivenessEvidenceKind.PROBE_UNREACHABLE` -- the definition of a partition.
  This is the observation that must *never* mean "promote".
* :attr:`LivenessEvidenceKind.STALE_READ_REPLICA` -- a replica that has not caught
  up cannot decide anything at all, including that the primary is dead. This kind
  exists so that "my replica is behind" is a first-class, refusable finding rather
  than a gap in somebody's log parsing.

Admissibility, and why stale evidence is excluded rather than trusted
---------------------------------------------------------------------

Every observation names the *term* it was taken against and the instant it was
taken. :func:`assess_primary` admits an observation only when both are current:
an observation of term 3 says nothing about term 4 (the primary may have been
restarted and re-elected), and an observation from an hour ago is a statement about
the past. Excluded observations are **returned** with the reason, so
:attr:`LivenessAssessment.excluded` is the audit trail of what somebody thought
they knew and why it did not count. Dropping them would make an assessment
indistinguishable from an assessment that was never offered the evidence.

What this module deliberately does not do
-----------------------------------------

* **No quorum, no consensus, no membership.** The leadership lease plus a
  monotonic term (Phase 2) is what mutual exclusion rests on here. A store that is
  reachable but partitioned in two is out of scope; the term bounds the damage,
  it does not prevent it.
* **No fencing of its own.** Ownership is a term, and the fence a promoted
  controller mints for a step is plan 03's :class:`~mayhem.domain.fabric.
  FencingToken`. **There is no second fencing scheme in this module** -- the
  failover vocabulary is about *deciding to promote*, and the monotonic epoch that
  makes a stale holder lose is the one from ``domain/fabric.py``.
* **No transport, no clock read, no IO.** Callers pass ``now``. The domain layer
  imports nothing upward per the layering contract, and this module imports no
  ``asyncio``, ``socket``, ``sqlite3``, or ``os``.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError, InvariantViolationError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

_ID = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"

_IDENT = Annotated[str, StringConstraints(pattern=_ID)]
_TERM = Annotated[int, Field(ge=1)]

#: Stable refusal code for a promotion that did not happen. Every reason below
#: shares it, because an operator's first question is "did the standby take over?"
#: and not "why not?" -- but :attr:`PromotionDecision.refusal` always names which
#: of the reasons it was.
PROMOTION_REFUSED = "failover_promotion_refused"

#: Stable refusal code for the specific case this module exists to make
#: impossible-by-default: the evidence did not establish that the primary is gone.
PRIMARY_INDETERMINATE = "failover_primary_indeterminate"

#: Stable refusal code for a promotion request that names no operator.
NO_OPERATOR = "failover_no_operator"

_REMEDIATION_INDETERMINATE: Final[str] = (
    "wait for the primary's leadership lease to expire in the replicated store, or "
    "obtain a positive process-absence observation; a partition, a missing "
    "heartbeat, or a stale replica is never grounds for promotion"
)
_REMEDIATION_NO_OPERATOR: Final[str] = (
    "name the operator performing the promotion; a takeover with nobody accountable "
    "is the one nobody can audit afterwards"
)


def _require_aware(moment: datetime, rule: str, subject: str) -> None:
    """Refuse naive datetimes. A naive observation has no place on a timeline."""
    if moment.tzinfo is None:
        raise InvariantViolationError(
            rule, f"{subject} must be timezone-aware, got naive {moment!r}"
        )


# --------------------------------------------------------------------------- #
# Evidence                                                                      #
# --------------------------------------------------------------------------- #


class LivenessEvidenceKind(StrEnum):
    """One thing somebody observed about the primary.

    The split is the safety property, so the names are chosen for what they
    *establish*, not for where they came from:

    * :attr:`PRIMARY_LEASE_EXPIRED` -- a durable record says the term is over.
    * :attr:`PRIMARY_PROCESS_GONE` -- an out-of-process witness says the process
      is absent.
    * the remaining three are all *absences of a signal* and establish nothing.
    """

    #: The leadership lease for the observed term is past its expiry in the
    #: replicated store. A durable fact, and the only kind a partitioned reader
    #: can still evaluate honestly if its replica is current.
    PRIMARY_LEASE_EXPIRED = "primary_lease_expired"
    #: An out-of-process witness positively reports the process as absent.
    PRIMARY_PROCESS_GONE = "primary_process_gone"
    #: No heartbeat arrived inside its interval. Silence, not death.
    HEARTBEAT_MISSING = "heartbeat_missing"
    #: The primary could not be reached. Indistinguishable from a partition.
    PROBE_UNREACHABLE = "probe_unreachable"
    #: The replica this reader read is behind. It cannot decide anything.
    STALE_READ_REPLICA = "stale_read_replica"
    #: Somebody asked. The empty answer, so "no evidence gathered" is a record
    #: rather than a missing row.
    NO_EVIDENCE = "no_evidence"


#: The kinds that can establish that a primary is **gone**. Authored as data
#: rather than a chain of ``if``s so that adding a kind is a visible edit to one
#: line that a reviewer can argue with, instead of a new branch somewhere in a
#: decision function.
DEATH_EVIDENCE: Final[frozenset[LivenessEvidenceKind]] = frozenset(
    {
        LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED,
        LivenessEvidenceKind.PRIMARY_PROCESS_GONE,
    }
)

#: The kinds that establish the primary is **still there**. One admissible
#: observation from this set vetoes a promotion no matter how much death evidence
#: accompanies it; the contradiction is itself the finding.
LIVENESS_EVIDENCE: Final[frozenset[LivenessEvidenceKind]] = frozenset(
    {
        LivenessEvidenceKind.HEARTBEAT_MISSING,
        LivenessEvidenceKind.PROBE_UNREACHABLE,
    }
)


class LivenessObservation(BaseModel):
    """One observation, with the two facts that make it admissible or not.

    ``observed_term`` and ``observed_at`` are **required**. An observation that
    does not say which term it was taken against, or when, cannot be checked
    against anything, and an uncheckable observation is the thing that gets
    promoted on. Refusing to construct one is the enforcement; the alternative --
    defaulting either field -- is how a stale fact becomes a current one.

    Attributes:
        kind: What was observed.
        observed_term: The leadership term the observation was taken against.
        observed_at: When it was taken (tz-aware).
        source: Who observed it (``lease-store``, ``systemd``, …). Recorded for
            the reader, never trusted: a source is a label, not a warrant.
        detail: Free text the observer attached. Required to be non-empty so a
            row cannot be a bare enum with no account of itself.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: LivenessEvidenceKind
    observed_term: _TERM
    observed_at: datetime
    source: str = Field(min_length=1)
    detail: str = Field(min_length=1)

    @model_validator(mode="after")
    def _check_invariants(self) -> LivenessObservation:
        _require_aware(self.observed_at, "liveness.time_aware", f"observation {self.kind.value}")
        return self

    @property
    def establishes_death(self) -> bool:
        """True when this kind can on its own establish that the primary is gone."""
        return self.kind in DEATH_EVIDENCE

    @property
    def establishes_liveness(self) -> bool:
        """True when this kind is positive evidence the primary is still there."""
        return self.kind in LIVENESS_EVIDENCE

    def age_at(self, now: datetime) -> timedelta:
        """How old this observation is at ``now``. Negative if it is from the future."""
        return now - self.observed_at

    def is_admissible_at(self, now: datetime, *, expected_term: int) -> bool:
        """True when this observation may be counted toward a decision.

        Two conditions, both necessary: it was taken against the term being
        decided, and it is inside the caller's freshness bound. See
        :func:`assess_primary` for why the second one is a refusal rather than a
        discount.
        """
        return self.observed_term == expected_term and self.observed_at <= now

    def describe(self) -> str:
        return (
            f"{self.kind.value} of term {self.observed_term} at "
            f"{self.observed_at.isoformat()} from {self.source}: {self.detail}"
        )


class ExcludedObservation(BaseModel):
    """An observation that was offered and not counted, and why.

    Returned rather than discarded. An assessment that silently dropped stale
    evidence would read identically to one that never saw it, which is precisely
    the shape of a bad post-mortem.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation: LivenessObservation
    reason: str = Field(min_length=1)

    def describe(self) -> str:
        return f"excluded {self.observation.kind.value}: {self.reason}"


class PrimaryStatus(StrEnum):
    """What the evidence establishes about the primary. Three-valued, on purpose.

    :attr:`INDETERMINATE` is a first-class member rather than a boolean's
    double negative so that a caller cannot read "not alive" as "dead" without
    having to name the third case.
    """

    ALIVE = "alive"
    DEAD = "dead"
    INDETERMINATE = "indeterminate"


class AssessmentReason(StrEnum):
    """Why the assessment came out the way it did."""

    #: An admissible death-evidence observation and no liveness evidence.
    DEATH_ESTABLISHED = "death_established"
    #: An admissible liveness observation vetoed the promotion.
    LIVENESS_OBSERVED = "liveness_observed"
    #: Death evidence and liveness evidence were both admissible.
    CONTRADICTORY = "contradictory"
    #: Nothing was offered at all.
    NO_EVIDENCE = "no_evidence"
    #: What was offered was all of the non-establishing kinds.
    WEAK_EVIDENCE_ONLY = "weak_evidence_only"
    #: Everything offered was inadmissible (wrong term, or too old).
    NOTHING_ADMISSIBLE = "nothing_admissible"


class LivenessAssessment(BaseModel):
    """The verdict over a set of observations, with the working shown.

    Constructed only by :func:`assess_primary`. The two collections are both kept
    so a reader can see *what counted* and *what did not*, which is the difference
    between a decision and a vibe.

    Attributes:
        expected_term: The leadership term the decision is about.
        status: The three-valued verdict.
        reason: Why.
        admitted: Observations that counted.
        excluded: Observations that were offered and not counted, each with a
            reason.
        assessed_at: The instant the verdict was computed at (tz-aware).
        freshness_bound_s: The maximum observation age this verdict accepted.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    expected_term: _TERM
    status: PrimaryStatus
    reason: AssessmentReason
    admitted: tuple[LivenessObservation, ...] = ()
    excluded: tuple[ExcludedObservation, ...] = ()
    assessed_at: datetime = Field(default_factory=utc_now)
    freshness_bound_s: Annotated[float, Field(gt=0)] = 30.0

    @model_validator(mode="after")
    def _check_invariants(self) -> LivenessAssessment:
        _require_aware(self.assessed_at, "liveness.time_aware", "liveness assessment")
        if (
            self.status is PrimaryStatus.DEAD
            and self.reason is not AssessmentReason.DEATH_ESTABLISHED
        ):
            msg = (
                f"an assessment claims the primary is DEAD for reason {self.reason.value!r}; "
                "only death_established can say that"
            )
            raise InvariantViolationError("liveness.dead_without_evidence", msg)
        return self

    @property
    def promotable(self) -> bool:
        """True **only** for ``DEAD``.

        Written as an identity test rather than ``not alive`` on purpose: a fourth
        member added to :class:`PrimaryStatus` in future defaults to *not*
        promoting, which is the direction that is safe to be wrong in.
        """
        return self.status is PrimaryStatus.DEAD

    @property
    def indeterminate(self) -> bool:
        """True when the evidence did not establish either answer."""
        return self.status is PrimaryStatus.INDETERMINATE

    def death_observations(self) -> tuple[LivenessObservation, ...]:
        """The admitted observations that established death."""
        return tuple(o for o in self.admitted if o.establishes_death)

    def describe(self) -> str:
        parts = [
            f"primary of term {self.expected_term}: {self.status.value} ({self.reason.value})",
            f"{len(self.admitted)} admitted, {len(self.excluded)} excluded, "
            f"freshness bound {self.freshness_bound_s:g}s",
        ]
        parts.extend(f"  admitted: {observation.describe()}" for observation in self.admitted)
        parts.extend(f"  excluded: {entry.describe()}" for entry in self.excluded)
        return "\n".join(parts)


#: Default freshness bound. Long enough that one clock tick does not invalidate a
#: decision, short enough that an observation from before a restart cannot decide
#: anything afterwards. A caller may tighten it; there is deliberately no way to
#: pass ``None`` meaning "no bound", because an unbounded observation is the same
#: defect as an inadmissible one.
DEFAULT_FRESHNESS_BOUND_S: Final[float] = 30.0


def assess_primary(
    observations: Iterable[LivenessObservation],
    *,
    expected_term: int,
    now: datetime | None = None,
    freshness_bound_s: float = DEFAULT_FRESHNESS_BOUND_S,
) -> LivenessAssessment:
    """Decide what ``observations`` establish about the primary at ``expected_term``.

    The rule, in full:

    1. An observation is **admissible** only if it names ``expected_term`` and is
       not in the future. Everything else lands in
       :attr:`LivenessAssessment.excluded` with a reason.
    2. Of the admissible, an observation older than ``freshness_bound_s`` is
       excluded as stale.
    3. ``DEAD`` requires **at least one** admissible observation from
       :data:`DEATH_EVIDENCE` **and no** admissible observation from
       :data:`LIVENESS_EVIDENCE`. The conjunction is the point: a single
       "the primary answered" observation vetoes the promotion, because a
       contradiction about whether a primary is alive is a reason to wait.
    4. Otherwise, an admissible liveness observation is ``ALIVE`` and anything
       else is ``INDETERMINATE``.

    Args:
        observations: What was offered. Duplicates are kept -- counting the same
            observation twice proves nothing either way, and silently collapsing
            them would hide that somebody only had one data point.
        expected_term: The leadership term being decided.
        now: Injected instant, so a drill reproduces.
        freshness_bound_s: Maximum admissible observation age.

    Returns:
        A :class:`LivenessAssessment`. There is no other success shape, so
        "the primary is dead" cannot be a field somebody sets.
    """
    moment = utc_now() if now is None else now
    _require_aware(moment, "liveness.time_aware", "assess_primary")
    if expected_term < 1:
        msg = f"expected_term is 1-based, got {expected_term}"
        raise InvariantViolationError("liveness.term_floor", msg)
    if freshness_bound_s <= 0:
        msg = f"freshness_bound_s must be positive, got {freshness_bound_s}"
        raise InvariantViolationError("liveness.freshness_floor", msg)
    bound = timedelta(seconds=freshness_bound_s)

    admitted: list[LivenessObservation] = []
    excluded: list[ExcludedObservation] = []
    for observation in observations:
        if observation.observed_term != expected_term:
            excluded.append(
                ExcludedObservation(
                    observation=observation,
                    reason=(
                        f"observed term {observation.observed_term} is not the term being "
                        f"decided ({expected_term}); a fact about a previous term says "
                        "nothing about this one"
                    ),
                )
            )
            continue
        if observation.observed_at > moment:
            excluded.append(
                ExcludedObservation(
                    observation=observation,
                    reason=(
                        f"observed_at {observation.observed_at.isoformat()} is after the "
                        f"decision instant {moment.isoformat()}"
                    ),
                )
            )
            continue
        age = observation.age_at(moment)
        if age > bound:
            excluded.append(
                ExcludedObservation(
                    observation=observation,
                    reason=(
                        f"observed {age.total_seconds():g}s ago, past the freshness bound "
                        f"of {freshness_bound_s:g}s"
                    ),
                )
            )
            continue
        admitted.append(observation)

    death = [o for o in admitted if o.establishes_death]
    alive = [o for o in admitted if o.establishes_liveness]

    if not admitted:
        status, reason = PrimaryStatus.INDETERMINATE, AssessmentReason.NOTHING_ADMISSIBLE
    elif death and alive:
        status, reason = PrimaryStatus.INDETERMINATE, AssessmentReason.CONTRADICTORY
    elif death:
        status, reason = PrimaryStatus.DEAD, AssessmentReason.DEATH_ESTABLISHED
    elif alive:
        status, reason = PrimaryStatus.ALIVE, AssessmentReason.LIVENESS_OBSERVED
    else:
        # Admissible, but every kind was one of the non-establishing ones
        # (STALE_READ_REPLICA / NO_EVIDENCE). This is the branch a partition
        # lands in, and it is a refusal by construction.
        status, reason = PrimaryStatus.INDETERMINATE, AssessmentReason.WEAK_EVIDENCE_ONLY

    return LivenessAssessment(
        expected_term=expected_term,
        status=status,
        reason=reason,
        admitted=tuple(admitted),
        excluded=tuple(excluded),
        assessed_at=moment,
        freshness_bound_s=freshness_bound_s,
    )


# --------------------------------------------------------------------------- #
# The promotion request and its decision                                         #
# --------------------------------------------------------------------------- #


class PromotionRefusal(StrEnum):
    """Every way a promotion did not happen.

    One enumeration in a canonical order (:data:`PROMOTION_REFUSAL_ORDER`), the
    pattern ``domain/approval.py`` set, so a refusal reports *every* reason rather
    than the first and a log line reads the same way every time.
    """

    #: No evidence established the primary is gone.
    PRIMARY_INDETERMINATE = "primary_indeterminate"
    #: Admissible evidence says the primary is still there.
    PRIMARY_ALIVE = "primary_alive"
    #: Death evidence and liveness evidence were both admissible.
    CONTRADICTORY_EVIDENCE = "contradictory_evidence"
    #: Nothing admissible was offered at all.
    NO_ADMISSIBLE_EVIDENCE = "no_admissible_evidence"
    #: The caller is already the leader for this scope; promoting again is a
    #: second owner, not a takeover.
    ALREADY_LEADER = "already_leader"
    #: The leadership store's term has moved past the term the request was decided
    #: against. Somebody promoted while this request was in flight, and the
    #: evidence that justified *this* request says nothing about the term that now
    #: exists.
    TERM_MOVED = "term_moved"
    #: The stored lease has not expired and the request did not ask to force it.
    #: This is the operator break-glass decision, and it is refused rather than
    #: taken silently: a "probably hung" primary is a guess, and a guess that takes
    #: a live leader's scope is a split brain.
    LEASE_LIVE = "lease_live"
    #: **There is no lease to take over.** A first controller in a fresh cluster
    #: *campaigns*; it does not fail over. Refused by name rather than quietly
    #: handled, because the two acts produce different records — a campaign
    #: writes a leadership lease and nothing else, while a promotion writes a
    #: promotion record naming who was deposed, and a cluster whose first
    #: controller wrote the latter would claim a deposed leader it never had.
    NO_LEADER = "no_leader"
    #: The request names no operator.
    NO_OPERATOR = "no_operator"


#: Canonical reporting order. Authored, and asserted equal to
#: :class:`PromotionRefusal`'s declaration order by the unit tests, so the enum
#: and this tuple cannot drift apart quietly.
PROMOTION_REFUSAL_ORDER: Final[tuple[PromotionRefusal, ...]] = tuple(PromotionRefusal)


def order_promotion_refusals(reasons: Iterable[PromotionRefusal]) -> tuple[PromotionRefusal, ...]:
    """De-duplicate and canonically order a refusal set."""
    present = set(reasons)
    return tuple(reason for reason in PROMOTION_REFUSAL_ORDER if reason in present)


class PromotionRequest(BaseModel):
    """A standby asks to take the leadership scope.

    **Constructible with bad evidence on purpose.** A refusal has to be
    *recordable* -- plan 19 Phase 4 seals refused failovers into the same evidence
    chain as successful ones -- so this type does not refuse to exist. What it
    does is refuse to exist *incompletely*: ``assessment``, ``operator``,
    ``reason``, and ``expected_term`` are all required, and there is no way to
    mint a request that forgot to gather evidence.

    ``forced`` records that the caller intends to take the scope from a lease that
    has **not** expired. That is the operator break-glass path and it is a
    different act from promoting a dead primary's scope, so it is a distinct
    field rather than something inferred later from a lease's expiry.

    Attributes:
        scope: The leadership scope being taken (``control-plane`` by default).
        standby_id: The standby asking. Recorded as a **claim**: nothing here
            proves who ``standby_id`` is, and the record must not imply otherwise.
        expected_term: The term the standby believes is current.
        assessment: What the evidence established.
        forced: Take the scope from a live lease.
        operator: Who is performing the promotion. Required.
        reason: Why, in the operator's words. Required.
        requested_at: When the request was made (tz-aware).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    scope: str = Field(min_length=1)
    standby_id: _IDENT
    expected_term: _TERM
    assessment: LivenessAssessment
    forced: bool = False
    operator: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    requested_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> PromotionRequest:
        _require_aware(
            self.requested_at, "promotion.time_aware", f"promotion request by {self.standby_id}"
        )
        return self

    def refusals(self) -> tuple[PromotionRefusal, ...]:
        """Every reason this request may not proceed, canonically ordered.

        Pure. It reads the request and the assessment and knows nothing about the
        store, which is what makes it testable on its own and what keeps
        "promote when liveness is unknown" out of reach of a caller who only has
        a :class:`LivenessAssessment`.
        """
        reasons: set[PromotionRefusal] = set()
        if not self.operator.strip():
            reasons.add(PromotionRefusal.NO_OPERATOR)
        status = self.assessment.status
        if status is PrimaryStatus.DEAD:
            pass
        elif status is PrimaryStatus.ALIVE:
            reasons.add(PromotionRefusal.PRIMARY_ALIVE)
        elif self.assessment.reason is AssessmentReason.NOTHING_ADMISSIBLE:
            reasons.add(PromotionRefusal.NO_ADMISSIBLE_EVIDENCE)
        elif self.assessment.reason is AssessmentReason.CONTRADICTORY:
            reasons.add(PromotionRefusal.CONTRADICTORY_EVIDENCE)
        else:
            reasons.add(PromotionRefusal.PRIMARY_INDETERMINATE)
        return order_promotion_refusals(reasons)

    @property
    def admissible(self) -> bool:
        """True when this request clears every refusal above."""
        return not self.refusals()

    def describe(self) -> str:
        forced = " (forced: taking a live lease)" if self.forced else ""
        return (
            f"{self.standby_id} asks for scope {self.scope!r} at term "
            f"{self.expected_term}{forced} as {self.operator}: {self.reason}\n"
            + self.assessment.describe()
        )


class PromotionOutcome(StrEnum):
    """How a promotion ended. ``PROMOTED`` is the only member that took a scope."""

    PROMOTED = "promoted"
    REFUSED = "refused"


class PromotionDecision(BaseModel):
    """What the failover engine decided, and on what grounds.

    The validator is the load-bearing part: :attr:`promoted` is an identity test
    against :attr:`outcome`, and ``new_term`` is **required and strictly greater
    than the requested term** when the outcome is ``PROMOTED`` while being
    ``None`` otherwise. So the one number that says "this standby now holds the
    scope" cannot exist on a refusal, and cannot exist on a promotion that did not
    move the term forward. A promotion that does not strictly increase the term is
    not a takeover -- it is a second owner, which is the failure this whole module
    exists to make unrepresentable.

    Attributes:
        request: The request decided.
        outcome: Whether the scope moved.
        refusals: Every reason it did not, canonically ordered. Empty iff
            ``outcome is PROMOTED``.
        new_term: The term the scope now holds; ``None`` on a refusal.
        decided_at: When the decision was made (tz-aware).
        detail: The account a reader gets. Required to be non-empty on both paths,
            because a decision with no narrative is not an auditable one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    request: PromotionRequest
    outcome: PromotionOutcome
    refusals: tuple[PromotionRefusal, ...] = ()
    new_term: _TERM | None = None
    decided_at: datetime = Field(default_factory=utc_now)
    detail: str = Field(min_length=1)

    @model_validator(mode="after")
    def _check_invariants(self) -> PromotionDecision:
        _require_aware(self.decided_at, "promotion.time_aware", "promotion decision")
        if self.outcome is PromotionOutcome.PROMOTED:
            if self.refusals:
                msg = (
                    "a promotion decision cannot be PROMOTED and carry refusals "
                    f"{[r.value for r in self.refusals]}"
                )
                raise InvariantViolationError("promotion.promoted_with_refusals", msg)
            if self.new_term is None:
                msg = "a PROMOTED decision must name the term the scope now holds"
                raise InvariantViolationError("promotion.missing_new_term", msg)
            if self.new_term <= self.request.expected_term:
                msg = (
                    f"a takeover must strictly increase the term; promoting to "
                    f"{self.new_term} at requested term {self.request.expected_term} would "
                    "leave the previous holder's lease matching the stored one"
                )
                raise InvariantViolationError("promotion.term_not_advanced", msg)
        elif self.new_term is not None:
            msg = (
                f"a REFUSED promotion cannot name a term (got {self.new_term}); the scope "
                "did not move and a reader must not be able to think it did"
            )
            raise InvariantViolationError("promotion.refused_with_term", msg)
        return self

    @property
    def promoted(self) -> bool:
        return self.outcome is PromotionOutcome.PROMOTED

    @property
    def indeterminate(self) -> bool:
        """True when the refusal was "the evidence did not establish death"."""
        return PromotionRefusal.PRIMARY_INDETERMINATE in self.refusals or (
            PromotionRefusal.NO_ADMISSIBLE_EVIDENCE in self.refusals
            or PromotionRefusal.CONTRADICTORY_EVIDENCE in self.refusals
        )

    def describe(self) -> str:
        if self.promoted:
            return (
                f"PROMOTED {self.request.standby_id} onto scope {self.request.scope!r} at term "
                f"{self.new_term} by {self.request.operator}: {self.detail}"
            )
        names = ", ".join(reason.value for reason in self.refusals) or "unspecified"
        return (
            f"REFUSED promotion of {self.request.standby_id} onto scope "
            f"{self.request.scope!r} ({names}): {self.detail}"
        )


class PromotionRefusedError(DomainError):
    """A promotion was refused. **The scope did not move.**"""

    def __init__(
        self,
        decision: PromotionDecision,
        *,
        remediation: str = _REMEDIATION_INDETERMINATE,
    ) -> None:
        self.code = (
            PRIMARY_INDETERMINATE if decision.indeterminate else PROMOTION_REFUSED
        )
        self.decision = decision
        self.refusals = decision.refusals
        self.remediation = remediation
        super().__init__(f"{self.code}: {decision.describe()}")


def require_promotable(request: PromotionRequest) -> None:
    """Refuse ``request`` unless its evidence establishes that the primary is gone.

    The one function a caller must call before it touches the store. Pure, so it
    can be called *first* -- there is no window in which the store has been read
    or written and the refusal has not already been decided.

    Raises:
        PromotionRefusedError: With :attr:`~PromotionRefusedError.refusals`
            naming every reason, in :data:`PROMOTION_REFUSAL_ORDER`.
    """
    refusals = request.refusals()
    if refusals:
        raise PromotionRefusedError(
            PromotionDecision(
                request=request,
                outcome=PromotionOutcome.REFUSED,
                refusals=refusals,
                detail=(
                    "no promotion: "
                    + "; ".join(
                        reason.value for reason in refusals
                    )
                ),
            )
        )


def decision_from_campaign(
    request: PromotionRequest,
    *,
    new_term: int,
    decided_at: datetime | None = None,
) -> PromotionDecision:
    """Build the ``PROMOTED`` decision once the store has actually moved the term.

    Args:
        request: The request that was admitted.
        new_term: The term the leadership store recorded. Validated against
            ``request.expected_term`` by :class:`PromotionDecision`, so a store
            that returned the old term produces a refusal-shaped failure rather
            than a promotion that did not take.
        decided_at: Injected instant.

    Raises:
        InvariantViolationError: If the store did not strictly advance the term.
    """
    moment = utc_now() if decided_at is None else decided_at
    return PromotionDecision(
        request=request,
        outcome=PromotionOutcome.PROMOTED,
        new_term=new_term,
        decided_at=moment,
        detail=(
            f"leadership store moved scope {request.scope!r} to term {new_term} for "
            f"{request.standby_id}"
            + ("; took the scope from a live lease under --force" if request.forced else "")
        ),
    )


def assert_assessment_consistent(assessment: LivenessAssessment, *, request_term: int) -> None:
    """Refuse an assessment assembled for a different term than the request names.

    The two are separate values because they are gathered separately (an assessment
    over observations, a request over an operator's intent), and a mismatch is
    exactly the bug this catches: promoting on term 3's evidence while asking for
    term 4.

    Raises:
        InvariantViolationError: With rule ``promotion.term_mismatch``.
    """
    if assessment.expected_term != request_term:
        msg = (
            f"the assessment was computed for term {assessment.expected_term} but the "
            f"request names term {request_term}; evidence about one term cannot decide "
            "another"
        )
        raise InvariantViolationError("promotion.term_mismatch", msg)


def observations_for_term(
    observations: Sequence[LivenessObservation],
    *,
    expected_term: int,
) -> tuple[LivenessObservation, ...]:
    """The observations that name ``expected_term``, in the order given.

    A convenience for the drill: it makes the "wrong term" negative control a
    one-liner without having to re-derive the filter that
    :func:`assess_primary` applies with reasons attached.
    """
    return tuple(o for o in observations if o.observed_term == expected_term)
