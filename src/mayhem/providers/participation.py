"""Does a provider action participate like a native action? — plan 17 Phase 4.

The acceptance criterion Phase 1 wrote down, quoted exactly:

    *Provider actions participate in admission, blast accounting, damage quota,
    leases, and evidence exactly like native actions* … *provider faults enter the
01 certification pipeline with their provider version pinned in the matrix cell.*

Phases 1 and 2 built the first two words of that sentence — admission and
evidence — and Phase 4's loader half sealed every activity. This module is the
other three, and it is honest about the difference between **participating** and
**being wired in**:

* **Damage quota and blast accounting — landed, and it really is the same
  ledger.** :func:`charge_provider_blast` calls
  :meth:`~mayhem.domain.quota.DamageLedger.charge`. Not a preview, not a second
  arithmetic, not a preview quote copied out of it: the *same* call a native step
  makes, so a provider step and a native step cannot disagree about what a run
  costs. What it refuses with is likewise the ledger's own
  ``damage_quota.budget`` / ``damage_quota.per_fault_ceiling`` rule ids, which
  :data:`~mayhem.controller.safety_proof.OBLIGATION_FOR_RULE` already owns — so
  a provider action that blows the quota compiles into an existing proof line
  rather than a new unmapped one.

  The one thing that is *not* the same, and is said out loud on every charge: a
  provider fault id is not in the fault catalog, so
  :func:`~mayhem.domain.quota.damage_weight` prices it at
  :data:`~mayhem.domain.quota.UNRESOLVED_FAULT_WEIGHT` — the top rung of both
  ladders. That is the fail-safe direction (an unpriced fault can never be the
  cheap one) but it is also *unresolved*, so
  :attr:`BlastCharge.weight_source` reports
  ``unresolved_conservative`` rather than letting a reader assume a catalog
  price was found. Pricing a provider fault is a catalog decision plan 05 owns;
  this module does not invent one.

* **Leases — landed, and it is the real lease.** :func:`lease_for_provider_action`
  builds an ordinary
  :class:`~mayhem.domain.leases.FaultLease`, which means the real state machine
  and the real invariants apply: no mutation becomes ``ACTIVE`` without
  write-ahead undo ops, no release begins without verify probes, and
  :func:`~mayhem.domain.leases.assert_all_recovered` is the same run-completion
  invariant. The refusal that matters is
  :data:`RULE_PROVIDER_LEASE_UNDO_ABSENT`, and it is refused **here** rather than
  discovered later because the *declaration cannot supply the undo*: a
  :class:`~mayhem.domain.provider.FaultDeclaration` says ``reversible=True`` —
  that compensation exists — and it has no field for the operations that perform
  it. Those arrive from the provider's own runtime at lease time. A mutating
  provider action with no undo ops is refused, not admitted, because a
  mutation without write-ahead undo is the exact defect ADR-0005 exists to
  prevent, and a provider must not be the one actor allowed to skip it.

* **Certification — landed as a refusal, because the cell cannot be pinned.**
  :func:`certification_blockers` **calls** the plan-01 code and reports what it
  answers. Today it answers two refusals, both real and both reproducible:
  :class:`~mayhem.domain.certification.MatrixCell` is ``extra="forbid"`` with no
  field for a provider version, so a provider version cannot be frozen into the
  cell's identity and therefore cannot be invalidated when the provider moves;
  and :class:`~mayhem.domain.certification.CertificationRecord` refuses a
  provider fault id outright, because ``fault_id`` is validated against
  ``FaultCategory`` prefixes and a third-party provider does not get one.
  :func:`ensure_certification_pin` refuses on both counts rather than minting a
  certification claim that would not be checkable.

What is deliberately *not* here
------------------------------
* **No execution wiring.** Nothing in this module is called by a run today. The
  charge has to be made from ``controller/cell_runner.py`` /
  ``controller/safety.py`` and the lease has to be persisted by the executor
  (``controller/executor.py``, plan 03); both are owned by other lanes and are
  named precisely in the plan's STATUS. A participation module that nobody calls
  is a *decision*, not a mechanism — the same split
  :mod:`mayhem.domain.lowlevel_admission` makes, and for the same reason.
* **No ``MatrixCell`` field, and no ``FaultCategory`` prefix.** Both live in
  plan 01's files. Adding them here would be editing another plan's contract
  silently; :func:`certification_blockers` states the change instead.
* **No signature field, and no signature check.** See
  :data:`mayhem.providers.sdk.SDK_UNVERIFIED_NOTICE`; this module carries the
  same notice on every record for the same reason. ``ProviderVersionPin.version``
  is the *author's declared version string* — a claim in a declaration — and
  nothing here verifies who wrote it.
* **No ``BOUNDARY_CALL_SITES`` row is owed.** This module performs no IO and
  persists nothing: the charge mutates an in-memory
  :class:`~mayhem.domain.quota.DamageLedger` the caller owns, and the lease is a
  frozen value the caller's own store writes. A writer is added by the lane that
  owns the write path, which is the rule the boundary table exists to enforce.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from mayhem.domain.certification import CertificationRecord, MatrixCell
from mayhem.domain.common import utc_now
from mayhem.domain.leases import (
    FaultLease,
    LeaseState,
    UndoOp,
    VerifyProbe,
    assert_all_recovered,
)
from mayhem.domain.provider import (
    FaultDeclaration,
    ProviderError,
    ProviderMetadata,
    ProviderMutation,
)
from mayhem.domain.quota import (
    UNRESOLVED_FAULT_WEIGHT,
    DamageLedger,
    DamageQuota,
    QuotaCharge,
    is_catalog_fault,
)

if TYPE_CHECKING:
    from datetime import datetime

    from mayhem.domain.common import Duration

__all__ = [
    "PROVIDER_PARTICIPATION_NOTICE",
    "RULE_PROVIDER_BLAST_UNCHARGED",
    "RULE_PROVIDER_CELL_UNPINNED",
    "RULE_PROVIDER_FAULT_UNDECLARED",
    "RULE_PROVIDER_LEASE_UNDO_ABSENT",
    "RULE_PROVIDER_QUOTA_EXCEEDED",
    "BlastCharge",
    "CellPinStatus",
    "CertificationBlocker",
    "CertificationRecordRefusalError",
    "LeaseRequirement",
    "ProviderAction",
    "ProviderLeaseRequest",
    "ProviderParticipationError",
    "ProviderVersionPin",
    "WeightSource",
    "assert_provider_action_recovered",
    "certification_blockers",
    "charge_provider_blast",
    "ensure_blast_within_quota",
    "ensure_certification_pin",
    "lease_for_provider_action",
    "lease_requirement",
    "participate",
    "pin_verdict",
    "serve_provider_action",
    "weight_source_for",
]


#: The sentence every value this module produces carries.
#:
#: A module constant rather than a docstring for the reason
#: :data:`mayhem.providers.sandbox.SANDBOX_NOT_ENFORCED_NOTICE` and
#: :data:`mayhem.domain.lowlevel_report.LOWLEVEL_NOT_ATTACHED_NOTICE` are both
#: module constants: a surface that renders a participation decision must be able
#: to render the caveat next to it without having to remember the wording.
#:
#: It says two separate things, and both are load-bearing. The first is that the
#: participation is computed **here** rather than performed by the run, so a
#: rendered participation report is a decision a caller made and not an
#: observation of an executed step. The second is that a provider version is a
#: declared string: no signature is checked anywhere on this path.
PROVIDER_PARTICIPATION_NOTICE: Final[str] = (
    "mayhem computes what a provider action would charge to the damage quota, which lease "
    "it would take, and which matrix cell would have to pin its provider version. Nothing "
    "here executes an action, and no signature is checked on any of them: a provider version "
    "is the string its author declared, and mayhem.providers.pack."
    "SIGNATURE_VERIFICATION_IMPLEMENTED is False in this build."
)


#: Refusal ids this module can raise.
#:
#: Two of the five are *re-exports in spirit only* — ``provider.quota_exceeded``
#: deliberately restates the ledger's own ``damage_quota.*`` rule ids rather than
#: inventing its own, because a provider step that blows the quota must compile
#: into the same proof line a native step does. The three genuinely new ids need
#: ``OBLIGATION_FOR_RULE`` and ``RULE_CHECK`` rows from their owners; the exact
#: mapping requested is written in the plan's STATUS.
RULE_PROVIDER_QUOTA_EXCEEDED: Final[str] = "provider.quota_exceeded"
RULE_PROVIDER_FAULT_UNDECLARED: Final[str] = "provider.fault_undeclared"
RULE_PROVIDER_LEASE_UNDO_ABSENT: Final[str] = "provider.lease_undo_absent"
RULE_PROVIDER_BLAST_UNCHARGED: Final[str] = "provider.blast_uncharged"
RULE_PROVIDER_CELL_UNPINNED: Final[str] = "provider.certification_cell_unpinned"


class ProviderParticipationError(ProviderError):
    """A provider action that cannot participate the way a native one does.

    A :class:`~mayhem.domain.provider.ProviderError` so it carries a ``code`` a
    caller can branch on and lands in the same ``except`` as the loader's own
    refusals. Deliberately **not** an
    :class:`~mayhem.domain.errors.InvariantViolationError`: those mean mayhem is
    internally inconsistent, while every refusal here is about a declaration or
    a caller, which is the ordinary business of a gate.
    """


# =============================================================================
# The action
# =============================================================================


@dataclass(frozen=True, slots=True)
class ProviderAction:
    """One provider-initiated action, described well enough to be charged.

    Deliberately a plain value with no reference to a loader, a registry or a
    store. Participation is arithmetic and invariants, and keeping this free of
    mayhem's object graph is what lets the whole module be tested without a
    database, an engine, or a loaded provider.

    ``node_ids`` is required and non-empty. A damage charge with no target is a
    charge against nothing, and a lease with no target is a promise about
    nothing — both are refused here rather than being made to look meaningful by
    a default.
    """

    provider_id: str
    fault_id: str
    run_id: str
    owner_agent: str
    node_ids: tuple[str, ...]
    duration_s: float
    operation_id: str = ""

    def __post_init__(self) -> None:
        for field_name in ("provider_id", "fault_id", "run_id", "owner_agent"):
            if not str(getattr(self, field_name)).strip():
                msg = f"a provider action must name its {field_name}"
                raise ProviderParticipationError(
                    RULE_PROVIDER_FAULT_UNDECLARED, msg
                )
        if not self.node_ids:
            msg = (
                f"provider action {self.operation_id or self.fault_id!r} targets nothing; "
                "a blast charge with no node and a lease with no target are both promises "
                "about nothing"
            )
            raise ProviderParticipationError(RULE_PROVIDER_FAULT_UNDECLARED, msg)
        if self.duration_s <= 0.0:
            msg = (
                f"provider action {self.fault_id!r} has duration_s={self.duration_s!r}; a "
                "charge of zero or less is not a charge, and a zero-duration mutation is "
                "not a mutation"
            )
            raise ProviderParticipationError(RULE_PROVIDER_FAULT_UNDECLARED, msg)

    @property
    def subject(self) -> str:
        """What a refusal names: the operation id when there is one, else the fault."""
        return self.operation_id or self.fault_id


# =============================================================================
# Blast accounting and the damage quota
# =============================================================================


class WeightSource(StrEnum):
    """Where a damage weight came from, and how much that is worth.

    Two members and no more, because a reader of a charge has exactly two
    questions: was this fault priced by the catalog, and if not what happened
    instead. Collapsing them into "the weight" is how a conservative fallback
    ends up quoted in a report as though it were a catalog price.
    """

    #: The catalog holds a definition for this fault id, so the weight was read
    #: from the same :class:`~mayhem.domain.faults.FaultDefinition` every other
    #: fault is priced by.
    CATALOG = "catalog"

    #: The catalog cannot resolve the fault id, so
    #: :func:`~mayhem.domain.quota.damage_weight` returned
    #: :data:`~mayhem.domain.quota.UNRESOLVED_FAULT_WEIGHT` — the top rung of both
    #: ladders, deliberately, so an unpriced fault is never the cheap one. Every
    #: provider fault lands here today, because a third-party fault id is not in
    #: mayhem's catalog and inventing one is plan 05's decision, not this
    #: module's.
    UNRESOLVED_CONSERVATIVE = "unresolved_conservative"


def weight_source_for(fault_id: str) -> WeightSource:
    """Whether *fault_id*'s damage weight came from the catalog or the fallback."""
    return (
        WeightSource.CATALOG if is_catalog_fault(fault_id) else WeightSource.UNRESOLVED_CONSERVATIVE
    )


@dataclass(frozen=True, slots=True)
class BlastCharge:
    """One provider action's charge to the damage quota, and its provenance.

    :attr:`charge` is the ledger's own
    :class:`~mayhem.domain.quota.QuotaCharge`, held rather than copied into new
    fields. Re-expressing its numbers would be a second implementation of
    ``DamageLedger.charge``'s arithmetic, and the two could then disagree — which
    is precisely the failure the "delegate, do not re-implement" rule exists to
    prevent. The additions are exactly the two things the ledger cannot know:
    which provider acted, and where the weight came from.
    """

    provider_id: str
    charge: QuotaCharge
    weight_source: WeightSource
    notice: str = PROVIDER_PARTICIPATION_NOTICE

    @property
    def weight(self) -> float:
        return self.charge.weight

    @property
    def exceeded(self) -> bool:
        return self.charge.exceeded

    @property
    def rule_id(self) -> str:
        """The rule that refused, or ``""`` when within budget.

        Deliberately the ledger's id (``damage_quota.budget`` /
        ``damage_quota.per_fault_ceiling``) and not a provider-flavoured one: the
        same breach must compile to the same proof line whoever performed it, or
        ``OBLIGATION_FOR_RULE`` grows a second row for one physical limit.
        """
        return self.charge.rule_id

    @property
    def priced_by_catalog(self) -> bool:
        return self.weight_source is WeightSource.CATALOG

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "fault_id": self.charge.fault_id,
            "weight": self.charge.weight,
            "weight_source": self.weight_source.value,
            "priced_by_catalog": self.priced_by_catalog,
            "unresolved_fault_weight": UNRESOLVED_FAULT_WEIGHT,
            "per_node_damage_s": round(self.charge.per_node_s, 3),
            "step_damage_s": round(self.charge.step_damage_s, 3),
            "plan_total_damage_s": round(self.charge.total_s, 3),
            "worst_node": self.charge.worst_node,
            "worst_node_s": round(self.charge.worst_node_s, 3),
            "limit_s": self.charge.limit_s,
            "exceeded": self.exceeded,
            "rule_id": self.rule_id,
            "reason": self.charge.reason,
            "remediation": self.charge.remediation,
            "notice": self.notice,
        }


def charge_provider_blast(
    ledger: DamageLedger,
    action: ProviderAction,
    quota: DamageQuota,
) -> BlastCharge:
    """Charge *action* to *ledger* and judge it against *quota*.

    One call, the same call. ``ledger`` is mutated — a ledger is a record of what
    a plan *does*, not of what it was allowed to do — and the returned
    :class:`~mayhem.domain.quota.QuotaCharge` is the ledger's own verdict, so
    :func:`~mayhem.controller.safety.check_blast_radius` and this function cannot
    disagree about what a provider step costs. That is what "participates exactly
    like a native action" has to mean if it is to mean anything.

    Raises:
        ProviderParticipationError: Only for a *malformed* action, which
            :class:`ProviderAction` already refuses at construction. A quota
            breach is **returned**, not raised, because the ledger judges after
            it charges and the caller is the thing that decides what to do about
            an exceeded charge — exactly as it does for a native step. Use
            :func:`ensure_blast_within_quota` to turn a breach into a refusal.
    """
    charge = ledger.charge(
        fault_id=action.fault_id,
        duration_s=action.duration_s,
        node_ids=action.node_ids,
        quota=quota,
    )
    return BlastCharge(
        provider_id=action.provider_id,
        charge=charge,
        weight_source=weight_source_for(action.fault_id),
    )


def ensure_blast_within_quota(
    ledger: DamageLedger,
    action: ProviderAction,
    quota: DamageQuota,
) -> BlastCharge:
    """Charge the action, and refuse it when the quota is breached.

    The refusing half of :func:`charge_provider_blast`, split out so the two
    answers stay distinguishable at a call site: a caller that wants to *report*
    charges and reads :attr:`BlastCharge.exceeded`, while a caller that wants to
    *gate* calls this and lets the exception be the decision.

    Note the ordering the ledger itself documents: the charge has already been
    made when this raises. A refused provider action is still on the ledger,
    because a run that attempted it did the damage — rolling the number back
    would make the ledger disagree with the world.

    Raises:
        ProviderParticipationError: With code
            :data:`~mayhem.domain.quota.RULE_BUDGET` or
            :data:`~mayhem.domain.quota.RULE_PER_FAULT_CEILING` — the ledger's
            own ids, carried through unchanged.
    """
    blast = charge_provider_blast(ledger, action, quota)
    if not blast.exceeded:
        return blast
    raise ProviderParticipationError(
        blast.rule_id or RULE_PROVIDER_QUOTA_EXCEEDED,
        f"{blast.charge.reason} — charged by provider {action.provider_id!r} fault "
        f"{action.fault_id!r} at weight {blast.charge.weight:g} "
        f"({blast.weight_source.value}) over {len(action.node_ids)} node(s). "
        f"{blast.charge.remediation}",
    )


# =============================================================================
# Leases
# =============================================================================


class LeaseRequirement(StrEnum):
    """Whether a provider fault must take a lease before it runs.

    A closed vocabulary, so "does this need a lease?" has one answer per shape
    rather than a boolean a caller has to interpret. ``NOT_REQUIRED`` is not
    "we did not check" — it is the decision, and it is a decision because a
    read-only fault changes nothing and therefore has nothing to compensate.
    """

    #: The declared fault is read-only: it mutates nothing, so a lease would be
    #: a recovery record for an action with no recovery to perform.
    NOT_REQUIRED = "not_required"

    #: The declared fault is mutating: it must take a lease carrying write-ahead
    #: undo ops before it becomes ``ACTIVE``, exactly as a native mutation does.
    REQUIRED = "required"


@dataclass(frozen=True, slots=True)
class ProviderLeaseRequest:
    """What a provider action brings to the point where a lease is taken.

    ``undo_ops`` and ``verify_probes`` come from the *provider's runtime*, not
    from its declaration, and that asymmetry is the whole point of
    :data:`RULE_PROVIDER_LEASE_UNDO_ABSENT`. A
    :class:`~mayhem.domain.provider.FaultDeclaration` can say ``reversible=True``
    — that a compensation path exists — and has no field describing the
    operations that perform it. So a declaration that says "compensable" without
    a runtime that supplies undo cannot reach ``ACTIVE``, and this request is
    where the gap becomes an explicit refusal instead of a lease that is silently
    under-specified.

    Both operations are required before ``ACTIVE``, not one: ``FaultLease`` will
    not serve a mutation whose recovery cannot be both *performed* (undo) and
    *observed* (probes). Supplying undo alone is refused by
    :func:`serve_provider_action` with ``verify_required_before_release``, which
    is the native lease's own refusal and not one invented here.
    """

    action: ProviderAction
    undo_ops: tuple[UndoOp, ...] = ()
    verify_probes: tuple[VerifyProbe, ...] = ()
    lease_id: str = ""
    ttl_seconds: Duration = 120.0
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        for undo in self.undo_ops:
            if not undo.op.strip():
                msg = "a provider lease's undo op must name an operation"
                raise ProviderParticipationError(RULE_PROVIDER_LEASE_UNDO_ABSENT, msg)
        for probe in self.verify_probes:
            if not probe.probe.strip():
                msg = "a provider lease's verify probe must name a probe"
                raise ProviderParticipationError(RULE_PROVIDER_LEASE_UNDO_ABSENT, msg)
        if float(self.ttl_seconds) <= 0.0:
            msg = (
                f"a provider lease with ttl_seconds={self.ttl_seconds!r} expires before it "
                "is created; a watchdog that fires instantly cannot watch anything"
            )
            raise ProviderParticipationError(RULE_PROVIDER_LEASE_UNDO_ABSENT, msg)


def _declared_fault(metadata: ProviderMetadata, fault_id: str) -> FaultDeclaration:
    """The fault declaration for *fault_id*, or refuse.

    Refusing rather than defaulting is the whole contract: participation is read
    off the *declaration*, so a fault the provider never declared has no declared
    mutation character, no declared compensation, and therefore no place in the
    lease or the certification matrix. A caller that wants participation for an
    undeclared fault has a declaration bug, and this names it.
    """
    declaration = metadata.fault_declaration.get(fault_id)
    if declaration is None:
        raise ProviderParticipationError(
            RULE_PROVIDER_FAULT_UNDECLARED,
            f"provider {metadata.provider_id!r} declares "
            f"{len(metadata.declared_fault_ids)} fault(s), none of them {fault_id!r}; "
            "mayhem will not charge, lease or certify an action for a fault the "
            "declaration does not contain",
        )
    return declaration


def lease_requirement(metadata: ProviderMetadata, fault_id: str) -> LeaseRequirement:
    """Whether *fault_id* must take a lease before it runs.

    Read off :attr:`~mayhem.domain.provider.FaultDeclaration.mutation`, which the
    declaration validator already ties to ``target:mutate``: a fault that says it
    mutates must require the mutation permission, and a read-only fault cannot
    require action permissions. So this is not a heuristic over permissions — it
    is the same mutation flag the pack loader and the sandbox profile read.
    """
    declaration = _declared_fault(metadata, fault_id)
    mutating = declaration.mutation is ProviderMutation.MUTATING
    return LeaseRequirement.REQUIRED if mutating else LeaseRequirement.NOT_REQUIRED


def lease_for_provider_action(
    metadata: ProviderMetadata,
    request: ProviderLeaseRequest,
) -> FaultLease:
    """The :class:`~mayhem.domain.leases.FaultLease` a provider action takes.

    An ordinary lease, built by the ordinary constructor, so **the same
    invariants a native action lives under are the invariants this one lives
    under** — there is no ``ProviderLease`` type that could be more permissive:

    * ``FaultLease`` refuses ``ACTIVE`` without ``undo_ops``;
    * ``FaultLease`` refuses ``RELEASING`` without ``verify_probes``;
    * ``transition`` re-validates, so a ``model_copy`` cannot smuggle a state
      past them;
    * ``assert_all_recovered`` is the run-completion invariant and it does not
      care who holds the lease.

    :func:`serve_provider_action` walks the full lifecycle so those are
    *exercised* by this module's own tests rather than merely cited here.

    Raises:
        ProviderParticipationError: With code
            :data:`RULE_PROVIDER_LEASE_UNDO_ABSENT` when the action mutates and
            the request carries no undo ops. That refusal is this module's own
            rather than ``FaultLease``'s, because ``FaultLease`` only refuses on
            the ``ACTIVE`` transition — and a lease that can be *created* without
            undo is an open lease sitting in whatever store the caller writes,
            which is where the window would be.
    """
    action = request.action
    declaration = _declared_fault(metadata, action.fault_id)
    if declaration.mutation is not ProviderMutation.MUTATING:
        msg = (
            f"provider fault {action.fault_id!r} is declared read-only, so it takes no "
            "lease; a recovery record for an action with no recovery to perform would be "
            "an object that looks like a guarantee and protects nothing"
        )
        raise ProviderParticipationError(RULE_PROVIDER_FAULT_UNDECLARED, msg)
    if not request.undo_ops:
        msg = (
            f"provider {metadata.provider_id!r} fault {action.fault_id!r} is declared "
            "mutating and would run without write-ahead undo ops. The declaration says "
            "that a compensation path exists — FaultDeclaration.reversible is "
            f"{declaration.reversible!r} — but a declaration carries no field for the "
            "operations that perform it, so mayhem cannot take the lease for it. Refusing "
            "rather than admitting a mutation whose compensation cannot be written down "
            "first."
        )
        raise ProviderParticipationError(RULE_PROVIDER_LEASE_UNDO_ABSENT, msg)
    return FaultLease(
        id=request.lease_id or f"l-{action.run_id}-{action.fault_id}".replace(".", "-"),
        run_id=action.run_id,
        fault_id=action.fault_id,
        owner_agent=action.owner_agent,
        targets=frozenset(action.node_ids),
        undo_ops=tuple(request.undo_ops),
        verify_probes=tuple(request.verify_probes),
        ttl_seconds=float(request.ttl_seconds),
        created_at=request.created_at or utc_now(),
    )


def serve_provider_action(
    metadata: ProviderMetadata,
    request: ProviderLeaseRequest,
) -> FaultLease:
    """Take the lease and advance it to ``ACTIVE``.

    The whole point of Phase 4's lease half, in one call: a provider mutation
    goes through ``PENDING -> ACTIVE`` exactly as a native one does, so the
    ``undo_required_before_active`` invariant is *enforced* rather than
    asserted-in-prose, and the epoch / ``injected_at`` / ``served_at`` bookkeeping
    that a watchdog reads is populated by the same transition function.

    Returns the ``ACTIVE`` lease. Compensation is the caller's, through
    ``lease.transition(LeaseState.RELEASING, ...)`` — which is where the verify
    probes are finally required, and is deliberately not automated here so that
    nothing in this module can release a provider's mutation without the caller's
    own compensation code running.
    """
    lease = lease_for_provider_action(metadata, request)
    return lease.transition(LeaseState.ACTIVE)


def assert_provider_action_recovered(lease: FaultLease) -> None:
    """:func:`~mayhem.domain.leases.assert_all_recovered` for one provider lease.

    Named rather than re-implemented: the run-completion invariant says *all*
    leases, and a provider lease is one, so the check is the shared one called
    with a single-element list rather than a provider-flavoured re-reading of
    "is this terminal and safe".
    """
    assert_all_recovered([lease])


# =============================================================================
# Certification: the matrix cell, and the pin it cannot carry
# =============================================================================


@dataclass(frozen=True, slots=True)
class ProviderVersionPin:
    """The provider identity a matrix cell must freeze alongside the engine.

    Plan 17's own words: *provider faults enter the 01 certification pipeline
    with their provider version pinned in the matrix cell*. So the pin is not
    decoration beside the cell — it is part of what identifies the cell, and
    :func:`pin_verdict` refuses when the cell cannot hold it.

    :attr:`version` is the **string the author declared in the declaration**, a
    claim. Nothing in this module verifies who wrote it, because
    ``mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED`` is ``False``:
    a pinned version is what lets mayhem notice that the *artifact* moved, and it
    is not evidence that the *author* is who they say they are.
    """

    provider_id: str
    version: str
    fault_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.provider_id.strip():
            msg = "a provider version pin must name the provider it pins"
            raise ProviderParticipationError(RULE_PROVIDER_CELL_UNPINNED, msg)
        if not self.version.strip():
            msg = (
                f"provider {self.provider_id!r} is pinned at version {self.version!r}; an "
                "unreadable version cannot be compared against a later one, so a pin with "
                "one is a pin that cannot be invalidated"
            )
            raise ProviderParticipationError(RULE_PROVIDER_CELL_UNPINNED, msg)


class CellPinStatus(StrEnum):
    """Whether a matrix cell can carry a provider version pin."""

    #: The cell holds a provider version field and it matches the pin.
    PINNED = "pinned"

    #: The cell holds a provider version field and it *differs* from the pin: the
    #: provider moved and every certification against that cell is now about a
    #: build that no longer exists.
    VERSION_MOVED = "version_moved"

    #: The cell has no field for a provider version at all. Today this is every
    #: cell, on every core, because :class:`MatrixCell` is ``extra="forbid"``.
    CELL_CANNOT_CARRY_PIN = "cell_cannot_carry_pin"


@dataclass(frozen=True, slots=True)
class CellPinVerdict:
    """What the pin check found, and what a refusal would have to change."""

    status: CellPinStatus
    cell_label: str
    cell_fingerprint: str
    pin: ProviderVersionPin
    detail: str
    notice: str = PROVIDER_PARTICIPATION_NOTICE

    @property
    def pinned(self) -> bool:
        return self.status is CellPinStatus.PINNED

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "cell": self.cell_label,
            "cell_fingerprint": self.cell_fingerprint,
            "provider_id": self.pin.provider_id,
            "pinned_version": self.pin.version,
            "detail": self.detail,
            "notice": self.notice,
        }


#: The field name a ``MatrixCell`` would have to carry for a provider pin to be
#: part of the cell's identity.
#:
#: Named as a constant, and looked up in ``MatrixCell.model_fields`` at read
#: time rather than hard-coded into a branch, so the verdict below changes from
#: ``cell_cannot_carry_pin`` to ``pinned`` the moment plan 01 adds it — with no
#: edit here, and with the test that pins today's answer failing loudly in the
#: meantime.
CANDIDATE_CELL_PIN_FIELD: Final[str] = "provider_version"


def pin_verdict(cell: MatrixCell, pin: ProviderVersionPin) -> CellPinVerdict:
    """Can *cell* carry *pin*, and does the version still match?

    A pure read of two values. It never constructs a cell, never edits one, and
    never falls back to a default pin: a cell that cannot hold the version is
    reported as exactly that, because "the pin was dropped" and "the pin was
    checked" must not look alike.
    """
    # ``type(cell)``, not ``MatrixCell``: the check is "does *this* cell carry a
    # provider version", and a subclass that adds the field is exactly the shape
    # plan 01's change would produce. Reading the base class would make the
    # verdict immune to the very fix it is waiting for.
    fields = type(cell).model_fields
    if CANDIDATE_CELL_PIN_FIELD not in fields:
        return CellPinVerdict(
            status=CellPinStatus.CELL_CANNOT_CARRY_PIN,
            cell_label=cell.label,
            cell_fingerprint=cell.fingerprint,
            pin=pin,
            detail=(
                f"MatrixCell is extra='forbid' and has no {CANDIDATE_CELL_PIN_FIELD!r} "
                f"field, so provider {pin.provider_id!r} at {pin.version!r} cannot be "
                f"pinned into the cell {cell.label!r}. Until that field exists, a "
                "certification recorded against this cell cannot be invalidated when the "
                "provider moves."
            ),
        )
    recorded = getattr(cell, CANDIDATE_CELL_PIN_FIELD, None)
    if recorded == pin.version:
        return CellPinVerdict(
            status=CellPinStatus.PINNED,
            cell_label=cell.label,
            cell_fingerprint=cell.fingerprint,
            pin=pin,
            detail=(
                f"cell {cell.label!r} pins provider {pin.provider_id!r} at "
                f"{pin.version!r}, the version under test"
            ),
        )
    return CellPinVerdict(
        status=CellPinStatus.VERSION_MOVED,
        cell_label=cell.label,
        cell_fingerprint=cell.fingerprint,
        pin=pin,
        detail=(
            f"cell {cell.label!r} pins provider {pin.provider_id!r} at "
            f"{recorded!r} but the action under test is {pin.version!r}; a certification "
            "recorded against that cell is about a build that is no longer the one running"
        ),
    )


def ensure_certification_pin(cell: MatrixCell, pin: ProviderVersionPin) -> CellPinVerdict:
    """:func:`pin_verdict`, refusing anything that is not ``PINNED``.

    Raises:
        ProviderParticipationError: With code
            :data:`RULE_PROVIDER_CELL_UNPINNED`, carrying the verdict's detail so
            the refusal names the missing field and the version that could not be
            recorded.
    """
    verdict = pin_verdict(cell, pin)
    if verdict.pinned:
        return verdict
    raise ProviderParticipationError(RULE_PROVIDER_CELL_UNPINNED, verdict.detail)


@dataclass(frozen=True, slots=True)
class CertificationBlocker:
    """One reproducible reason a provider fault cannot enter the 01 pipeline.

    Each one is *observed*, not asserted: :func:`certification_blockers` calls
    plan 01's own code and records what it raised. A blocker written as prose
    ages; a blocker produced by the code that refuses cannot drift from the
    refusal it describes.
    """

    subject: str
    rule: str
    detail: str
    change_required: str

    def to_dict(self) -> dict[str, object]:
        return {
            "subject": self.subject,
            "rule": self.rule,
            "detail": self.detail,
            "change_required": self.change_required,
        }


def certification_blockers(
    metadata: ProviderMetadata,
    cell: MatrixCell,
) -> tuple[CertificationBlocker, ...]:
    """Every way a provider fault cannot be certified on *cell* today.

    Calls the plan-01 code rather than reasoning about it, so the answer is
    current the moment plan 01 lands a change. Two blockers are expected in this
    build and both are reported:

    1. **The cell cannot hold the pin.** ``MatrixCell`` is ``extra="forbid"``
       with no ``provider_version`` field, so there is nowhere for
       :func:`pin_verdict` to find the version.
    2. **The record cannot name the fault.**
       :class:`~mayhem.domain.certification.CertificationRecord` validates
       ``fault_id`` against ``FaultCategory`` prefixes, so a provider's own
       fault id is refused before any other certification invariant is reached.

    The change each one needs is stated in
    :attr:`CertificationBlocker.change_required` rather than applied, because
    both files belong to plan 01 and a silent edit to another plan's contract is
    how two plans end up disagreeing about what a matrix cell is.
    """
    blockers: list[CertificationBlocker] = []
    pin = ProviderVersionPin(
        provider_id=metadata.provider_id,
        version=metadata.version,
        fault_ids=tuple(sorted(metadata.declared_fault_ids)),
    )
    verdict = pin_verdict(cell, pin)
    if not verdict.pinned:
        blockers.append(
            CertificationBlocker(
                subject=f"MatrixCell.{CANDIDATE_CELL_PIN_FIELD}",
                rule=verdict.status.value,
                detail=verdict.detail,
                change_required=(
                    "mayhem.domain.certification.MatrixCell: add "
                    f"{CANDIDATE_CELL_PIN_FIELD!r}: str | None = None, include it in "
                    ".fingerprint so a moved provider invalidates the cell, and "
                    "include it in .label so a report says which provider it was "
                    "recorded against"
                ),
            )
        )
    for fault_id in sorted(metadata.declared_fault_ids):
        try:
            _certification_probe(fault_id, cell, pin)
        except CertificationRecordRefusalError as refusal:
            blockers.append(
                CertificationBlocker(
                    subject=f"CertificationRecord.fault_id[{fault_id}]",
                    rule=refusal.rule,
                    detail=str(refusal),
                    change_required=(
                        "mayhem.domain.certification.CertificationRecord._plausible_fault_id: "
                        "accept a provider fault id — either a provider-scoped branch of "
                        "the id rule that requires the id to belong to the provider named "
                        "in the cell's provider_version pin, or a registered provider "
                        "fault prefix in domain.faults.FaultCategory. A blanket relaxation "
                        "of the id shape would be the wrong fix: it would let any string "
                        "be certified."
                    ),
                )
            )
            break
    return tuple(blockers)


class CertificationRecordRefusalError(Exception):
    """What plan 01 answered when asked to certify a provider fault.

    A local exception rather than catching and string-matching plan 01's own
    error types: this module must not grow an import-time dependency on which
    exception class a field validator raises, and the *message* is what an
    operator reads anyway.
    """

    def __init__(self, rule: str, detail: str) -> None:
        self.rule = rule
        super().__init__(detail)


def _certification_probe(
    fault_id: str,
    cell: MatrixCell,
    pin: ProviderVersionPin,
) -> None:
    """Try to build the certification record plan 01 would need. Raise on refusal.

    Constructing the record is the cheapest honest probe available: it runs the
    real field validators, so a refusal recorded here is the same refusal a real
    certification run would hit, with the same message. A probe that *succeeds*
    is not a certification — it is evidence that the shape is constructible — and
    the return value is ``None`` because there is nothing to hand back.
    """
    moment = utc_now()
    try:
        CertificationRecord(
            fault_id=fault_id,
            cell=cell,
            injector_version=pin.version,
            expires_at=moment + timedelta(days=30),
        )
    except Exception as exc:
        # Every exception plan 01's validators can raise is in scope: which class
        # a pydantic field validator raises is not this module's contract to pin,
        # and the message is what an operator reads either way.
        raise CertificationRecordRefusalError(type(exc).__name__, str(exc)) from exc


# =============================================================================
# One report
# =============================================================================


@dataclass(frozen=True, slots=True)
class ProviderParticipation:
    """What one provider action would owe the rest of mayhem's safety pipeline.

    Aggregated because the failure this module exists to prevent is a *reader*
    seeing "admitted", "sealed" and "within quota" as three separate renderings
    and concluding the action was fully accounted for. They are not the same
    claim, so they are one value with one verdict.

    :attr:`lease_taken` and :attr:`cell_pinned` are ``None`` when the
    corresponding surface does not apply, and that ``None`` is distinguished from
    ``False`` on purpose: "no lease was needed" and "a lease was needed and was
    not taken" are different findings and must not render alike.
    """

    action: ProviderAction
    blast: BlastCharge
    lease_required: LeaseRequirement
    lease: FaultLease | None
    cell_pin: CellPinVerdict | None
    blockers: tuple[CertificationBlocker, ...] = ()
    charged: bool = True
    notice: str = PROVIDER_PARTICIPATION_NOTICE

    @property
    def within_quota(self) -> bool:
        return not self.blast.exceeded

    @property
    def lease_outstanding(self) -> bool:
        """Whether a lease was needed and the action does not end recovered.

        ``False`` for a read-only action — not because the lease is recovered but
        because none was required, and the two are reported by
        :attr:`lease_required` rather than collapsed here.
        """
        if self.lease is None:
            return self.lease_required is LeaseRequirement.REQUIRED
        return not self.lease.is_safe_terminal

    @property
    def cell_pinned_or_not_required(self) -> bool:
        return self.cell_pin is None or self.cell_pin.pinned

    @property
    def fully_accounted(self) -> bool:
        """Whether every surface that applies is satisfied.

        ``False`` is the honest answer whenever a blocker exists, and it is the
        answer a caller should act on: the action is sealed and charged but not
        certifiable, and calling that "accounted for" is the gap Phase 4's ledger
        recorded.
        """
        return self.within_quota and not self.lease_outstanding and self.cell_pinned_or_not_required

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.action.provider_id,
            "fault_id": self.action.fault_id,
            "run_id": self.action.run_id,
            "nodes": list(self.action.node_ids),
            "duration_s": self.action.duration_s,
            "charged": self.charged,
            "blast": self.blast.to_dict(),
            "within_quota": self.within_quota,
            "lease_required": self.lease_required.value,
            "lease_id": self.lease.id if self.lease is not None else None,
            "lease_state": self.lease.state.value if self.lease is not None else None,
            "lease_outstanding": self.lease_outstanding,
            "cell_pin": self.cell_pin.to_dict() if self.cell_pin is not None else None,
            "cell_pinned": self.cell_pinned_or_not_required,
            "certification_blockers": [blocker.to_dict() for blocker in self.blockers],
            "fully_accounted": self.fully_accounted,
            "notice": self.notice,
        }


def participate(
    metadata: ProviderMetadata,
    action: ProviderAction,
    quota: DamageQuota,
    *,
    ledger: DamageLedger | None = None,
    lease_request: ProviderLeaseRequest | None = None,
    cell: MatrixCell | None = None,
    charged: bool = True,
) -> ProviderParticipation:
    """Run every participation surface for one provider action and aggregate.

    The order is fixed and it is the order the failure matters in: **charge
    first**, then lease, then pin. A provider action that blows the quota has
    already done the damage, so it is on the ledger whatever the later surfaces
    say; and a caller that only reads :attr:`ProviderParticipation.within_quota`
    cannot get a clean answer about a run that spent more than it was allowed.

    ``lease_request`` is optional and its absence is *not* treated as "no lease
    was needed": the requirement is read from the declaration either way, so a
    mutating fault with no request reports ``lease_outstanding=True``. Omitting
    the request is therefore a louder finding than passing an empty one, not a
    quieter one — which is the right way round.

    ``cell`` is optional for the same reason: no cell means no pin check ran, so
    :attr:`ProviderParticipation.cell_pin` is ``None`` and
    :attr:`ProviderParticipation.cell_pinned_or_not_required` is ``True`` — the
    one place this module reports an unchecked axis as satisfied, and it does so
    only because ``None`` is visibly distinct from a verdict.
    """
    charged_ledger = ledger if ledger is not None else DamageLedger()
    blast = charge_provider_blast(charged_ledger, action, quota)
    requirement = lease_requirement(metadata, action.fault_id)
    lease: FaultLease | None = None
    if lease_request is not None:
        lease = lease_for_provider_action(metadata, lease_request)
    elif requirement is LeaseRequirement.REQUIRED:
        # Reported as outstanding, not raised: the caller asked what participation
        # looks like, not for permission to proceed, and a report that cannot say
        # "this is not yet accounted for" is not worth having.
        lease = None
    verdict: CellPinVerdict | None = None
    blockers: tuple[CertificationBlocker, ...] = ()
    if cell is not None:
        pin = ProviderVersionPin(
            provider_id=metadata.provider_id,
            version=metadata.version,
            fault_ids=tuple(sorted(metadata.declared_fault_ids)),
        )
        verdict = pin_verdict(cell, pin)
        blockers = certification_blockers(metadata, cell)
    return ProviderParticipation(
        action=action,
        blast=blast,
        lease_required=requirement,
        lease=lease,
        cell_pin=verdict,
        blockers=blockers,
        charged=charged,
    )
