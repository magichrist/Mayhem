"""The analysis service, the causal-chain model, and the adaptive runner — Phase 2
of docs/v1.1.0/15_RESILIENCE_ANALYTICS_ADAPTIVE.md.

Phase 1 built the *arithmetic* (:mod:`mayhem.domain.analytics`) and the *search
policy* (:mod:`mayhem.domain.search`). This module is the part that does
something with them: it turns recorded runs into **boundaries, recovery curves,
minimal failure cases, and traced causal chains**, and it walks a
:class:`~mayhem.domain.search.SearchPolicy` forward as a sequence of admitted,
budgeted, approved micro-plans.

Five commitments shape everything below. Each is a construction-time or
signature-time rule rather than a review habit, and each has a test that fails if
it stops being true.

**A causal claim that cannot cite its evidence is withheld, not softened.** Gap
53's chain is *fault → target → dependency → metric change → customer impact*:
five nodes, four links. Each link carries its own citations — the trial that was
executed, the metric comparison that was graded, the SLO criterion that failed,
and the topology edges that actually exist between the nodes. A :class:`CausalStep`
with no support **cannot be constructed** (:data:`RULE_HOP_UNSUPPORTED`), and the
dependency hop additionally refuses to exist without a real edge
(:data:`RULE_HOP_WITHOUT_EDGE`). So an unciteable chain is not a chain with a
weaker confidence — it is a :class:`WithheldClaim` naming the hop that failed and
why, sitting beside the claims that survived. Citations are sha256 digests of the
records they point at (:data:`RULE_CITATION_NOT_A_DIGEST`), so a citation cannot
be typed in by hand: change the trial and the citation the chain names no longer
matches the trial it claims to come from.

**Boundary and recovery come from the verdict core, not from new arithmetic.**
The verdict, the baseline reduction, the relative-tolerance test, and the
comparison are all imported from :mod:`mayhem.domain.steady_state` and
:mod:`mayhem.domain.analytics`. This module adds the *report shapes* — a bracket
with an explicit confidence statement, a per-sample recovery curve — and refuses
to invent a statistic the domain has not already defined. In particular a
boundary's confidence is the movement of the *metric* at the boundary, labelled
as such; it is never presented as a confidence interval on the boundary value,
because nothing here estimates one.

**Every search step is approved, admitted, and budgeted before it runs.** The
adaptive runner's loop is plan → approve → compile → admit → budget-check →
charge → execute → record, and that order is not interchangeable. Approval comes
before compilation on purpose: the gate is never asked about a plan nobody
authorised, and a step refused for want of an approval costs nothing to refuse. The planner
already refuses a step it cannot pay for
(:func:`mayhem.domain.search.plan_next_step`); the runner re-checks against its
own running budget anyway, because a search that discovers the budget was
exhausted somewhere other than the planner must still stop *with the findings it
already has*. Budget exhaustion is a stop that keeps the boundary
(:class:`AdaptiveRun`), never a search that quietly continues.

**A generated candidate cannot carry execution authority.** Gap 25 is enforced
with types, not with a comment. :func:`compile_candidate` takes the *raw mapping*
an advisor produced — not a trusted object — refuses any payload carrying an
authority field at any depth (:data:`RULE_DRAFT_CARRIES_AUTHORITY`), validates
the step against the policy it would run under, and returns a ``generated``
:class:`~mayhem.domain.search.SearchPlan` through
:meth:`~mayhem.domain.search.UntrustedSearchDraft.compile`, a type with nowhere to
put an approval. The runner rebuilds every step's plan *with* the token the
reviewer returned (:func:`_approve_step`), and that reconstruction is where a
generated origin is refused (:data:`RULE_STEP_NOT_APPROVED` carries the domain's
own :data:`~mayhem.domain.search.RULE_GENERATED_CANNOT_BE_APPROVED` or
:data:`~mayhem.domain.search.RULE_APPROVAL_MISMATCH` refusal in its reason) — a
reviewer who meant well and approved the candidate anyway gets a stop, not an
execution. A draft that fails compilation never reaches policy evaluation because
the refusal happens in the compiler, upstream of every gate.

**Progressive stages are plan-level constructs, not ad-hoc reruns.**
:func:`compile_stages` reads *one* compiled
:class:`~mayhem.domain.experiments.ExecutionPlan` and emits one :class:`Stage`
per rung, each carrying that experiment's identity, its own narrow target set,
and its own narrowed plan — so "the 5% stage" is a fact about one experiment
rather than a second experiment that happens to look similar. Every stage declares
the SLO criteria that gate it, and promotion requires them to pass
(:func:`promote_to`). An unhealthy stage stops the ladder; a stage with no
recorded observation is *not* healthy, because "could not see it" and "nothing
is wrong" are different answers and only one of them may promote a canary.

Phase 4 — safety and evidence integration
-----------------------------------------

Phase 2 computed these reports and left three things open. All three are closed
below, and each closing is a construction rule rather than a review habit.

**The runner's own budget check is live, not decorative.** Phase 2's
:func:`step_affordable` could only be reached by handing the runner a budget the
planner did not see, and the ordinary wiring made that impossible. It is now a
documented parameter: ``planner_budget`` lets a caller hand
:func:`~mayhem.domain.search.plan_next_step` one budget while the runner spends
another (:attr:`AdaptiveRun.divergence` names the two and the step they
disagreed on). That is the case the check exists for — a ledger drained by a
concurrent step, a search resumed against a smaller allocation, a caller that
declared its full allowance up front — and it is reachable only by asking for
it, so a divergence is a decision somebody made rather than a coincidence. The
evidence is in the step itself: :class:`~mayhem.domain.search.SearchStep` records
``budget_remaining`` as the *planner's* reading, so a divergence is visible in
the sealed history and not merely in prose here.

**Analytics evidence is sealed, and an unsupported claim is withheld.** Every
report type carries its own support — the trial digests behind a boundary
(:attr:`BoundaryReport.trial_digests`), the sample digest behind a recovery curve
(:attr:`RecoveryCurve.samples_digest`), the tried cases behind a minimal failure
case (:attr:`MinimalFailureCase.case_digests`), and the observation citations
plus topology edges behind a causal chain. :func:`analytics_evidence` turns those
into :class:`AnalyticsClaim` values and :func:`seal_analytics_evidence` seals
them through :mod:`mayhem.infra.attestation_store` — the same sealer, the same
verifier, the same evidence boundary, no second chain format. A claim with no
support cannot be *constructed* (:data:`RULE_EVIDENCE_UNSUPPORTED`), and a
report with no support becomes a :class:`WithheldEvidence` beside the claims that
survived: the answer to "what did the search establish" is never a guess.
:func:`require_sealed_claim` is the gate a decision path calls, and an unsealed
report cannot cross it (:data:`RULE_EVIDENCE_NOT_SEALED`).

**A boundary search is a privileged action, so it is an audit entry.** The runner
builds a :class:`SearchRecord` naming the policy digest, the origin, the
approvers, and the escalating ladder it walked, and hands it to whatever recorder
the caller wired; :func:`record_boundary_search` writes it to
:mod:`mayhem.infra.audit_stream` as
:data:`mayhem.infra.audit_stream.KIND_RESILIENCE_BOUNDARY_SEARCHED`. The stream is
the cross-run log that already exists, so an operator can see who
searched a boundary and under what authorization without a second logger.
:func:`require_recorded_search` is the fail-closed counterpart: a search with no
entry in the stream is refused (:data:`RULE_SEARCH_NOT_RECORDED`).

None of this widens the AI boundary. :data:`AUTHORITY_FIELDS` and
:func:`_authority_keys` are unchanged and remain the single authority scan plan
21's advisor service imports — this phase reuses them and forks neither. Neither
:class:`AnalyticsClaim` nor :class:`SearchRecord` has a field an approval could
travel in, so evidence cannot become an authority channel.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import pairwise
from math import ceil, isfinite
from typing import TYPE_CHECKING

from mayhem.domain.analytics import Comparison, SamplePolicy, compare
from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    RetentionClass,
    build_manifest,
    chain_root,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest
from mayhem.domain.observations import ObservationResult, ObservationStatus
from mayhem.domain.prediction import (
    DEPENDENCY_EDGE_KINDS,
    customer_facing_node_ids,
    graph_identity,
    plan_identity,
)
from mayhem.domain.search import (
    Approval,
    BudgetKind,
    BudgetReference,
    SafetyBudget,
    SearchDecision,
    SearchHistory,
    SearchOrigin,
    SearchPhase,
    SearchPlan,
    SearchPolicy,
    SearchStep,
    StopReason,
    Trial,
    UntrustedSearchDraft,
    plan_next_step,
)
from mayhem.domain.steady_state import (
    Assertion,
    AssertionVerb,
    Verdict,
    classify,
    delta_pct,
    sample_baseline,
    within_relative,
)
from mayhem.domain.topology import EdgeKind
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationError,
    AttestationRepository,
)

#: Re-exported, not declared: this kind belongs to the audit stream's ``KIND_*``
#: table. See the note above :data:`KIND_RESILIENCE_BOUNDARY_SEARCHED`.
from mayhem.infra.audit_stream import (
    KIND_RESILIENCE_BOUNDARY_SEARCHED,
    AuditEntry,
)

if TYPE_CHECKING:
    from mayhem.domain.attestation import (
        ChainVerification,
        Manifest,
        ManifestVerification,
    )
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.observations import CriterionOutcome, SloCriterion
    from mayhem.domain.steady_state import Baseline, Tolerance
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.audit_stream import AuditStream
    from mayhem.infra.store import Store

__all__ = [
    "ANALYTICS_CHAIN_PREFIX",
    "AUTHORITY_FIELDS",
    "CANARY_LADDER",
    "CHAIN_EVENT_ANALYTICS_CLAIM",
    "CHAIN_EVENT_ANALYTICS_RECORDED",
    "CHAIN_EVENT_ANALYTICS_SEALED",
    "CHAIN_EVENT_ANALYTICS_WITHHELD",
    "KIND_RESILIENCE_BOUNDARY_SEARCHED",
    "MAX_CERTIFIABLE_COMPONENTS",
    "RULE_ADMISSION_REFUSED",
    "RULE_CAUSAL_NOT_CUSTOMER_FACING",
    "RULE_CAUSAL_NO_IMPACT",
    "RULE_CAUSAL_TARGET_NOT_IN_GRAPH",
    "RULE_CITATION_NOT_A_DIGEST",
    "RULE_DRAFT_BUDGET_REFERENCE_MISMATCH",
    "RULE_DRAFT_CARRIES_AUTHORITY",
    "RULE_DRAFT_STEP_COST_MISMATCH",
    "RULE_DRAFT_UNKNOWN_FIELD",
    "RULE_DRAFT_VALUE_OUT_OF_LADDER",
    "RULE_EVIDENCE_NOT_SEALED",
    "RULE_EVIDENCE_UNSUPPORTED",
    "RULE_HOP_UNSUPPORTED",
    "RULE_HOP_WITHOUT_EDGE",
    "RULE_LADDER_NOT_INCREASING",
    "RULE_NO_TARGETS",
    "RULE_PLANNER_BUDGET_DIVERGED",
    "RULE_SEARCH_NOT_RECORDED",
    "RULE_STAGE_NOT_HEALTHY",
    "RULE_STAGE_NO_CRITERIA",
    "RULE_STEP_NOT_APPROVED",
    "RULE_STEP_UNAFFORDABLE",
    "AdaptiveRun",
    "AnalyticsClaim",
    "AnalyticsEvidence",
    "AnalyticsEvidenceVerdict",
    "AnalyticsSeal",
    "BoundaryReport",
    "BudgetDivergence",
    "CausalAnalysis",
    "CausalChain",
    "CausalClaimRequest",
    "CausalHop",
    "CausalStep",
    "CitationKind",
    "ClaimKind",
    "CustomerImpactCheck",
    "EdgeCitation",
    "FailureCase",
    "MetricChange",
    "MinimalFailureCase",
    "ObservationCitation",
    "Promotion",
    "RecoveryCurve",
    "RecoveryPoint",
    "ResilienceAnalysis",
    "SearchRecord",
    "SearchStepTrace",
    "Stage",
    "StageOutcome",
    "StepAdmission",
    "StepOutcome",
    "WithheldClaim",
    "WithheldEvidence",
    "adaptive_run",
    "analytics_chain_id",
    "analytics_evidence",
    "analytics_manifest_id",
    "analyze_run",
    "boundary_claim",
    "boundary_decision_support",
    "boundary_report",
    "causal_chains",
    "compile_candidate",
    "compile_stages",
    "dependency_path",
    "evaluate_stage",
    "minimal_failure_case",
    "promote_to",
    "record_boundary_search",
    "recovery_curve",
    "require_recorded_search",
    "require_sealed_claim",
    "run_progressive",
    "seal_analytics_evidence",
    "search_policy_digest",
    "stage_ladder",
    "step_affordable",
    "verify_analytics_evidence",
]

# -- rule ids -----------------------------------------------------------------------------


RULE_CITATION_NOT_A_DIGEST = "analytics.citation_not_a_digest"
RULE_HOP_UNSUPPORTED = "analytics.causal_hop_unsupported"
RULE_HOP_WITHOUT_EDGE = "analytics.causal_hop_without_edge"
RULE_CAUSAL_TARGET_NOT_IN_GRAPH = "analytics.causal_target_not_in_graph"
RULE_CAUSAL_NOT_CUSTOMER_FACING = "analytics.causal_impact_not_customer_facing"
RULE_CAUSAL_NO_IMPACT = "analytics.causal_no_customer_impact"
RULE_DRAFT_CARRIES_AUTHORITY = "analytics.draft_carries_authority"
RULE_DRAFT_UNKNOWN_FIELD = "analytics.draft_unknown_field"
RULE_DRAFT_BUDGET_REFERENCE_MISMATCH = "analytics.draft_budget_reference_mismatch"
RULE_DRAFT_STEP_COST_MISMATCH = "analytics.draft_step_cost_mismatch"
RULE_DRAFT_VALUE_OUT_OF_LADDER = "analytics.draft_value_out_of_ladder"
RULE_STEP_NOT_APPROVED = "analytics.step_not_approved"
RULE_ADMISSION_REFUSED = "analytics.admission_refused"
RULE_STEP_UNAFFORDABLE = "analytics.step_unaffordable"
RULE_NO_TARGETS = "analytics.no_targets"
RULE_LADDER_NOT_INCREASING = "analytics.ladder_not_increasing"
RULE_STAGE_NO_CRITERIA = "analytics.stage_declares_no_criteria"
RULE_STAGE_NOT_HEALTHY = "analytics.stage_not_healthy"
#: Phase 4. The runner spent a budget the planner did not see
#: (:attr:`AdaptiveRun.divergence`), and the runner's own per-step check is what
#: caught it. Named so an operator reading an admission record can tell "the gate
#: said no" from "the ledger and the plan disagreed".
RULE_PLANNER_BUDGET_DIVERGED = "analytics.planner_budget_diverged"
#: Phase 4. A claim with no observation and no topology edge behind it. Phase 2
#: raised the same law for a causal hop
#: (:data:`RULE_HOP_UNSUPPORTED`); this is the whole-analysis form, because a
#: boundary, a curve, or a minimal case rests on records too.
RULE_EVIDENCE_UNSUPPORTED = "analytics.evidence_unsupported"
#: Phase 4. A decision asked a report to back it and that report is not in a
#: verified attestation chain.
RULE_EVIDENCE_NOT_SEALED = "analytics.evidence_not_sealed"
#: Phase 4. A search ran and the cross-run audit stream holds no entry for it.
RULE_SEARCH_NOT_RECORDED = "analytics.search_not_recorded"

#: The synthetic run id an analytics chain hangs off, for the reason
#: :mod:`mayhem.controller.certification_evidence` names its own: plan 12's
#: verifier defines a chain as starting at genesis for one ``run_id``, so an
#: analysis that spans several runs cannot hang off any one of them. The subject
#: run id travels in the payload instead.
ANALYTICS_CHAIN_PREFIX = "analytics.claim-chain"

#: Event kinds on that chain, in chain order.
CHAIN_EVENT_ANALYTICS_RECORDED = "analytics.recorded"
CHAIN_EVENT_ANALYTICS_CLAIM = "analytics.claim"
CHAIN_EVENT_ANALYTICS_WITHHELD = "analytics.claim.withheld"
CHAIN_EVENT_ANALYTICS_SEALED = "analytics.sealed"

#: The audit-stream action a resilience-boundary search is recorded under.
#:
#: Re-exported, not declared: the kind is a member of
#: :mod:`mayhem.infra.audit_stream`'s closed ``KIND_*`` table, which this phase did
#: not own — the local definition that used to sit here has moved to that module,
#: and the name stays in this namespace so existing callers of
#: ``mayhem.controller.analytics_service.KIND_RESILIENCE_BOUNDARY_SEARCHED`` keep
#: resolving (it remains in ``__all__``). The *string* is unchanged: it is the
#: event kind the entry carries, exactly as for every other action in the stream.
#: ``tests/unit/test_audit_kind_ownership.py`` fails if this module defines it again.

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

NO_CITATION_NOTE = (
    "this hop cites nothing, so the chain stops here rather than asserting a link it "
    "cannot show"
)
UNRESOLVED_BOUNDARY_NOTE = (
    "the bracket is wider than the declared resolution: the boundary is reported as a "
    "bracket, not as a number, and the confidence statement describes the metric "
    "movement at the boundary rather than an interval on the boundary itself"
)
NO_METRIC_MOVEMENT_NOTE = (
    "the metric comparison at this dependency is not a graded material change: a chain "
    "cannot say a metric changed when the comparison says it could not be separated "
    "from the noise"
)
NO_SUPPORT_NOTE = (
    "this report rests on no observation and no topology edge, so it is withheld rather "
    "than sealed: 'the search found nothing' is a finding, and 'the search ran nothing' "
    "is not one"
)


# =======================================================================================
# Causal chains (gap 53)
# =======================================================================================


class CitationKind(StrEnum):
    """What a citation points at.

    ``TRIAL`` is the executed search step, ``METRIC`` a graded
    :class:`~mayhem.domain.analytics.Comparison`, and ``SLO`` a criterion evaluated
    over one observation. All three are records that exist; none is a place a
    hand-written string can go, because every citation is the sha256 digest of the
    record it names.
    """

    TRIAL = "trial"
    METRIC = "metric"
    SLO = "slo"


@dataclass(frozen=True, slots=True)
class ObservationCitation:
    """A digest of the record that supports a hop.

    The digest is verified at construction (:data:`RULE_CITATION_NOT_A_DIGEST`),
    which is what makes "cites the observations" a property of the value rather
    than an intention: a citation is either the hash of a record somebody can
    produce, or it is not a citation.
    """

    kind: CitationKind
    ref: str
    detail: str = ""

    def __post_init__(self) -> None:
        if _SHA256_HEX.fullmatch(self.ref) is None:
            raise InvariantViolationError(
                RULE_CITATION_NOT_A_DIGEST,
                f"a citation must be the sha256 digest of the record it names, got "
                f"{self.ref!r}: a typed-in reference is not evidence",
            )

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind.value, "ref": self.ref, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class EdgeCitation:
    """A topology edge, named in full.

    Both endpoints and the edge kind travel, because "somewhere downstream" is not
    a citation: a reader has to be able to look the edge up in the same graph
    snapshot the chain was computed over.
    """

    src: str
    dst: str
    kind: EdgeKind
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.src or not self.dst:
            raise InvariantViolationError(
                RULE_HOP_WITHOUT_EDGE,
                "an edge citation must name both endpoints: an edge with a missing "
                "endpoint cannot be found in the graph it claims to come from",
            )

    def key(self) -> str:
        return f"{self.kind.value}:{self.src}->{self.dst}"

    def to_dict(self) -> dict[str, object]:
        return {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind.value,
            "detail": self.detail,
            "edge": self.key(),
        }


class CausalHop(StrEnum):
    """The four links of gap 53's chain."""

    FAULT_TO_TARGET = "fault->target"
    TARGET_TO_DEPENDENCY = "target->dependency"
    DEPENDENCY_TO_METRIC = "dependency->metric"
    METRIC_TO_CUSTOMER = "metric->customer"


@dataclass(frozen=True, slots=True)
class CausalStep:
    """One link, and everything it rests on.

    A hop with no citation cannot be constructed at all, and the dependency hop
    additionally requires a real edge — a chain may not say "the dependency is
    somewhere downstream" on the strength of a metric moving.
    """

    hop: CausalHop
    src: str
    dst: str
    observations: tuple[ObservationCitation, ...] = ()
    edges: tuple[EdgeCitation, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        if not self.src or not self.dst:
            raise InvariantViolationError(
                RULE_HOP_UNSUPPORTED,
                f"hop {self.hop.value} has a missing endpoint: a link between nothing "
                "and something is not a link",
            )
        if not self.observations and not self.edges:
            raise InvariantViolationError(
                RULE_HOP_UNSUPPORTED,
                f"hop {self.hop.value} ({self.src} -> {self.dst}) cites neither an "
                f"observation nor a topology edge: {NO_CITATION_NOTE}",
            )
        if self.hop is CausalHop.TARGET_TO_DEPENDENCY and not self.edges:
            raise InvariantViolationError(
                RULE_HOP_WITHOUT_EDGE,
                f"hop {self.hop.value} ({self.src} -> {self.dst}) cites no topology "
                "edge: the dependency link is a claim about the graph, so it must name "
                "the edge that makes it true",
            )

    @property
    def citations(self) -> tuple[ObservationCitation | EdgeCitation, ...]:
        return (*self.observations, *self.edges)

    def to_dict(self) -> dict[str, object]:
        return {
            "hop": self.hop.value,
            "src": self.src,
            "dst": self.dst,
            "observations": [o.to_dict() for o in self.observations],
            "edges": [e.to_dict() for e in self.edges],
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class CausalChain:
    """A fully cited fault → target → dependency → metric → customer chain."""

    fault_id: str
    hops: tuple[CausalStep, ...]

    def __post_init__(self) -> None:
        if not self.fault_id:
            raise InvariantViolationError(
                RULE_HOP_UNSUPPORTED,
                "a causal chain must name the fault it starts from",
            )
        present = tuple(hop.hop for hop in self.hops)
        if present != tuple(CausalHop):
            missing = [hop.value for hop in CausalHop if hop not in present]
            raise InvariantViolationError(
                RULE_HOP_UNSUPPORTED,
                f"a causal chain carries every hop in order or none at all; missing "
                f"{missing}",
            )

    @property
    def target_id(self) -> str:
        return self.hops[0].dst

    @property
    def dependency_id(self) -> str:
        return self.hops[1].dst

    @property
    def metric(self) -> str:
        return self.hops[2].dst

    @property
    def customer_node_id(self) -> str:
        return self.hops[3].dst

    @property
    def edges(self) -> tuple[EdgeCitation, ...]:
        return tuple(edge for hop in self.hops for edge in hop.edges)

    @property
    def observations(self) -> tuple[ObservationCitation, ...]:
        return tuple(cite for hop in self.hops for cite in hop.observations)

    def citation_counts(self) -> tuple[int, int]:
        """``(edge citations, observation citations)`` — reported, never summed."""
        return (len(self.edges), len(self.observations))

    def to_dict(self) -> dict[str, object]:
        edges, observations = self.citation_counts()
        return {
            "fault_id": self.fault_id,
            "target_id": self.target_id,
            "dependency_id": self.dependency_id,
            "metric": self.metric,
            "customer_node_id": self.customer_node_id,
            "hops": [hop.to_dict() for hop in self.hops],
            "edge_citations": edges,
            "observation_citations": observations,
        }


@dataclass(frozen=True, slots=True)
class WithheldClaim:
    """A chain that could not be cited, and the hop that stopped it.

    Withholding is the default, so a reader can count how many candidate chains
    were dropped and why. A run that produced no evidence at all produces a
    ``withheld`` list and an empty ``claims`` list — visibly a different report
    from one that produced a chain.
    """

    fault_id: str
    hop: CausalHop
    rule_id: str
    reason: str
    target_id: str = ""
    dependency_id: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "fault_id": self.fault_id,
            "target_id": self.target_id,
            "dependency_id": self.dependency_id,
            "hop": self.hop.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class CausalAnalysis:
    """What could be traced, and what had to be withheld."""

    graph_digest: str
    claims: tuple[CausalChain, ...] = ()
    withheld: tuple[WithheldClaim, ...] = ()

    @property
    def complete(self) -> bool:
        return bool(self.claims)

    def to_dict(self) -> dict[str, object]:
        return {
            "graph_digest": self.graph_digest,
            "claims": [claim.to_dict() for claim in self.claims],
            "withheld": [claim.to_dict() for claim in self.withheld],
            "complete": self.complete,
        }


@dataclass(frozen=True, slots=True)
class MetricChange:
    """A graded metric movement attributed to one node on the dependency path.

    The attribution is the caller's claim and this module's job is to grade it: an
    ungraded or non-material comparison is a *missing* metric change, not a weak
    one (:data:`RULE_HOP_UNSUPPORTED`).
    """

    node_id: str
    comparison: Comparison

    @property
    def moved(self) -> bool:
        return self.comparison.graded and self.comparison.material

    def citation(self) -> ObservationCitation:
        return ObservationCitation(
            kind=CitationKind.METRIC,
            ref=digest(self.comparison.to_dict()),
            detail=(
                f"{self.comparison.name} @ {self.comparison.statistic}: "
                f"{self.comparison.verdict_phrase}"
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {"node_id": self.node_id, "comparison": self.comparison.to_dict()}


@dataclass(frozen=True, slots=True)
class CustomerImpactCheck:
    """One SLO criterion over one observation of a customer-facing node.

    An impact is a *failed* criterion. A criterion that passed is not evidence of
    impact and never becomes a hop, which is why :attr:`impacted` is checked before
    the citation is built rather than after.
    """

    node_id: str
    criterion: SloCriterion
    observation: ObservationResult

    @property
    def outcome(self) -> CriterionOutcome:
        return self.criterion.evaluate(self.observation)

    @property
    def impacted(self) -> bool:
        return not self.outcome.passed

    def citation(self) -> ObservationCitation:
        return ObservationCitation(
            kind=CitationKind.SLO,
            ref=digest(
                {
                    "criterion": self.criterion.to_dict(),
                    "observation": self.observation.to_dict(),
                }
            ),
            detail=f"{self.outcome.criterion_id}: {self.outcome.reason or 'passed'}",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "criterion": self.criterion.to_dict(),
            "observation": self.observation.to_dict(),
            "outcome": self.outcome.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class CausalClaimRequest:
    """A candidate chain, as one observer believes it after a run.

    Every field here is an *assertion to be checked*. Nothing in this module trusts
    it: the trial must have been executed, the dependency must be reachable by real
    edges, the metric must be a graded material change, and the impact must be a
    failed criterion on a customer-facing node. Whatever fails is reported as a
    :class:`WithheldClaim`.
    """

    fault_id: str
    target_ids: tuple[str, ...]
    dependency_ids: tuple[str, ...]
    trial: Trial
    metric_changes: tuple[MetricChange, ...]
    customer_impacts: tuple[CustomerImpactCheck, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "fault_id": self.fault_id,
            "target_ids": list(self.target_ids),
            "dependency_ids": list(self.dependency_ids),
            "trial": self.trial.to_dict(),
            "metric_changes": [m.to_dict() for m in self.metric_changes],
            "customer_impacts": [c.to_dict() for c in self.customer_impacts],
        }


def causal_chains(graph: TopologyGraph, request: CausalClaimRequest) -> CausalAnalysis:
    """Trace every candidate chain in ``request`` against ``graph``.

    Deterministic and read-only: for each ``(target, dependency)`` pair in sorted
    order the four hops are built in order, and the first hop that cannot cite its
    evidence withholds the whole chain. Pairs are considered in sorted order so the
    same inputs always yield the same ``claims`` and the same ``withheld`` list.

    Withholding rules, in the order they are checked per pair:

    * the target is not in the graph snapshot
      (:data:`RULE_CAUSAL_TARGET_NOT_IN_GRAPH`) — a claim may not implicate a node
      nobody observed;
    * no dependency path exists in the graph (:data:`RULE_HOP_WITHOUT_EDGE`);
    * the dependency has no graded material metric change
      (:data:`RULE_HOP_UNSUPPORTED`);
    * no failed SLO criterion on a customer-facing node is reachable
      (:data:`RULE_CAUSAL_NO_IMPACT`), or the impacted node is not customer facing
      (:data:`RULE_CAUSAL_NOT_CUSTOMER_FACING`).
    """
    claims: list[CausalChain] = []
    withheld: list[WithheldClaim] = []
    trial_citation = ObservationCitation(
        kind=CitationKind.TRIAL,
        ref=digest(request.trial.to_dict()),
        detail=(
            f"trial {request.trial.step.index} at value {request.trial.step.value:g} "
            f"({request.trial.step.phase.value}) breached={request.trial.breached}"
        ),
    )
    changes = {change.node_id: change for change in request.metric_changes}
    impacts = {check.node_id: check for check in request.customer_impacts}
    facing = customer_facing_node_ids(graph)

    for target_id in sorted(request.target_ids):
        if graph.by_id(target_id) is None:
            withheld.append(
                WithheldClaim(
                    fault_id=request.fault_id,
                    hop=CausalHop.FAULT_TO_TARGET,
                    rule_id=RULE_CAUSAL_TARGET_NOT_IN_GRAPH,
                    reason=(
                        f"target {target_id!r} is not in the graph snapshot: a chain may "
                        "not implicate a node that was never observed"
                    ),
                    target_id=target_id,
                )
            )
            continue
        for dependency_id in sorted(request.dependency_ids):
            path = dependency_path(graph, target_id, dependency_id)
            if not path:
                withheld.append(
                    WithheldClaim(
                        fault_id=request.fault_id,
                        hop=CausalHop.TARGET_TO_DEPENDENCY,
                        rule_id=RULE_HOP_WITHOUT_EDGE,
                        reason=(
                            f"no dependency path from {target_id!r} to {dependency_id!r} "
                            f"in the graph snapshot over {sorted(DEPENDENCY_EDGE_KINDS)}"
                        ),
                        target_id=target_id,
                        dependency_id=dependency_id,
                    )
                )
                continue
            change = changes.get(dependency_id)
            if change is None or not change.moved:
                withheld.append(
                    WithheldClaim(
                        fault_id=request.fault_id,
                        hop=CausalHop.DEPENDENCY_TO_METRIC,
                        rule_id=RULE_HOP_UNSUPPORTED,
                        reason=NO_METRIC_MOVEMENT_NOTE,
                        target_id=target_id,
                        dependency_id=dependency_id,
                    )
                )
                continue
            impact_node = _impact_node(graph, target_id, impacts, facing)
            if impact_node is None:
                observed = sorted(impacts)
                not_facing = [node for node in observed if node not in facing]
                only_not_facing = bool(not_facing) and len(not_facing) == len(observed)
                withheld.append(
                    WithheldClaim(
                        fault_id=request.fault_id,
                        hop=CausalHop.METRIC_TO_CUSTOMER,
                        rule_id=(
                            RULE_CAUSAL_NOT_CUSTOMER_FACING
                            if only_not_facing
                            else RULE_CAUSAL_NO_IMPACT
                        ),
                        reason=(
                            "the only observed impact is on a node that is not customer "
                            f"facing ({observed} expose no port), so it is not a "
                            "customer impact"
                            if only_not_facing
                            else (
                                "no failed SLO criterion on a customer-facing node "
                                "reachable from the fault: there is no recorded customer "
                                "impact to cite"
                            )
                        ),
                        target_id=target_id,
                        dependency_id=dependency_id,
                    )
                )
                continue
            impact = impacts[impact_node]
            impact_path = dependency_path(graph, target_id, impact_node) or path
            claims.append(
                CausalChain(
                    fault_id=request.fault_id,
                    hops=(
                        CausalStep(
                            hop=CausalHop.FAULT_TO_TARGET,
                            src=request.fault_id,
                            dst=target_id,
                            observations=(trial_citation,),
                        ),
                        CausalStep(
                            hop=CausalHop.TARGET_TO_DEPENDENCY,
                            src=target_id,
                            dst=dependency_id,
                            edges=tuple(
                                EdgeCitation(src=edge.src, dst=edge.dst, kind=edge.kind)
                                for edge in path
                            ),
                        ),
                        CausalStep(
                            hop=CausalHop.DEPENDENCY_TO_METRIC,
                            src=dependency_id,
                            dst=change.comparison.name,
                            observations=(change.citation(),),
                        ),
                        CausalStep(
                            hop=CausalHop.METRIC_TO_CUSTOMER,
                            src=change.comparison.name,
                            dst=impact_node,
                            observations=(impact.citation(),),
                            edges=tuple(
                                EdgeCitation(src=edge.src, dst=edge.dst, kind=edge.kind)
                                for edge in impact_path
                            ),
                            note=impact.outcome.reason,
                        ),
                    ),
                )
            )
    return CausalAnalysis(
        graph_digest=graph_identity(graph),
        claims=tuple(claims),
        withheld=tuple(withheld),
    )


def dependency_path(graph: TopologyGraph, src: str, dst: str) -> tuple[EdgeCitation, ...]:
    """The shortest dependency path from ``src`` to ``dst``, as edge citations.

    Empty when there is no such path — including when ``src == dst``, because a
    node depending on itself is not a dependency and citing it would make every
    self-contained target look like it had downstream damage. Breadth-first, so the
    answer is a shortest path and therefore deterministic.
    """
    if src == dst or graph.by_id(src) is None or graph.by_id(dst) is None:
        return ()
    adjacency: dict[str, list[tuple[str, EdgeKind]]] = {}
    for edge in graph.edges:
        if edge.kind.value in DEPENDENCY_EDGE_KINDS:
            adjacency.setdefault(edge.src, []).append((edge.dst, edge.kind))
    frontier = [src]
    came_from: dict[str, tuple[str, EdgeKind]] = {}
    seen = {src}
    while frontier:
        current = frontier.pop(0)
        for neighbour, kind in sorted(adjacency.get(current, [])):
            if neighbour in seen:
                continue
            seen.add(neighbour)
            came_from[neighbour] = (current, kind)
            if neighbour == dst:
                path: list[EdgeCitation] = []
                cursor = dst
                while cursor != src:
                    parent, edge_kind = came_from[cursor]
                    path.append(EdgeCitation(src=parent, dst=cursor, kind=edge_kind))
                    cursor = parent
                return tuple(reversed(path))
            frontier.append(neighbour)
    return ()


def _impact_node(
    graph: TopologyGraph,
    target_id: str,
    impacts: Mapping[str, CustomerImpactCheck],
    facing: frozenset[str],
) -> str | None:
    """The customer-facing node whose SLO actually failed and is reachable.

    Sorted for determinism. A node whose criterion passed is not an impact, and a
    node reachable only through edges that are not dependency edges is not a path
    this claim can cite.
    """
    for node_id in sorted(impacts):
        check = impacts[node_id]
        if node_id not in facing or not check.impacted:
            continue
        # The target is the customer-facing service in the common case, and a node
        # is trivially reachable from itself: refusing that would withhold every
        # chain whose door and its dependency are the same request path.
        if node_id == target_id or dependency_path(graph, target_id, node_id):
            return node_id
    return None


# =======================================================================================
# Boundary (plan 15 "Outputs": tolerance boundary with confidence)
# =======================================================================================


@dataclass(frozen=True, slots=True)
class BoundaryReport:
    """Where the tolerance boundary lies, and how confident that statement is.

    ``boundary`` is the smallest impairment known to breach and ``bracket_low`` is
    the largest value known to clear below it, so the boundary lies in
    ``(bracket_low, boundary]``. ``resolved`` says whether that bracket is narrower
    than the policy's declared resolution — when it is not, :attr:`tolerance_statement`
    says so in words rather than quoting the midpoint.

    The confidence statement describes the *metric* at the boundary value, taken
    from the comparison recorded there. It is deliberately not an interval on the
    boundary: nothing in this repository estimates one, and inventing a confidence
    band on the boundary value is precisely the overclaim plan 15 §Docs exists to
    prevent.
    """

    policy_name: str
    boundary: float | None
    bracket_low: float
    bracket_high: float | None
    resolved: bool
    resolution: float
    trials: int
    highest_tried: float | None = None
    boundary_comparison: Comparison | None = None
    note: str = ""
    insufficient_trials: tuple[int, ...] = ()
    trial_digests: tuple[str, ...] = ()
    """The sha256 digest of every trial the bracket was read from, in order.

    The report's own support (Phase 4). A boundary is a statement about the trials
    that were executed, so the report carries the digests of those trials rather
    than leaving a reader to re-derive them from a history that may since have
    been redacted — and an empty tuple is what makes ``boundary is None`` over
    zero trials *withheld* rather than sealed as a finding.
    """

    @property
    def tolerance_statement(self) -> str:
        """The sentence a boundary report quotes."""
        if self.boundary is None:
            reached = "none" if self.highest_tried is None else f"{self.highest_tried:g}"
            return (
                f"no impairment in this search crossed the declared tolerance "
                f"(highest tried {reached} across {self.trials} trials)"
            )
        if not self.resolved:
            return (
                f"tolerates impairment up to {self.bracket_low:g} (highest value known "
                f"to clear); boundary lies in ({self.bracket_low:g}, {self.boundary:g}] "
                f"over {self.trials} trials — NOT RESOLVED to a declared resolution of "
                f"{self.resolution:g}"
            )
        return (
            f"tolerates impairment up to {self.bracket_low:g}; boundary at "
            f"{self.boundary:g} within the declared resolution {self.resolution:g}"
        )

    @property
    def confidence_statement(self) -> str:
        """What is known about the metric at the boundary — never about the boundary."""
        comparison = self.boundary_comparison
        if self.boundary is None or comparison is None:
            return (
                "no comparison was recorded at a boundary value, so this search reports "
                "a ladder with no graded evidence about the metric at its edge"
            )
        effect = comparison.effect_size
        effect_clause = (
            "" if effect is None else f" (Cohen's d {effect.value:.2f}, {effect.magnitude})"
        )
        return (
            f"at the boundary {self.boundary:g} the metric read: "
            f"{comparison.verdict_phrase}{effect_clause}. This describes the metric's "
            "movement at that impairment, not an interval on the boundary value itself"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_name": self.policy_name,
            "boundary": self.boundary,
            "bracket_low": self.bracket_low,
            "bracket_high": self.bracket_high,
            "resolved": self.resolved,
            "resolution": self.resolution,
            "trials": self.trials,
            "highest_tried": self.highest_tried,
            "insufficient_trials": list(self.insufficient_trials),
            "boundary_comparison": (
                None
                if self.boundary_comparison is None
                else self.boundary_comparison.to_dict()
            ),
            "tolerance_statement": self.tolerance_statement,
            "confidence_statement": self.confidence_statement,
            "note": self.note,
            "trial_digests": list(self.trial_digests),
        }


def boundary_report(
    policy: SearchPolicy,
    history: SearchHistory,
    comparisons: Mapping[int, Comparison] | None = None,
) -> BoundaryReport:
    """Reduce a walked search to a boundary bracket with a confidence statement.

    ``comparisons`` is keyed by ``SearchStep.index`` — the graded comparison from
    each trial's own window. A boundary trial with no comparison yields a report
    whose :attr:`BoundaryReport.confidence_statement` says exactly that, which is
    the honest report when the capture could not be graded: the bracket still
    stands, because the search recorded a breach, but nothing is claimed about the
    metric there.

    Trials whose measurement was insufficient are counted and named, never folded
    into the boundary: a search that stopped on an unmeasurable trial has a bracket
    from the trials before it and a note about the one it could not use.

    The bracket itself is *not* recomputed here — :attr:`SearchHistory.boundary`
    and :attr:`SearchHistory.bracket_low` are the one definition of it, and this
    function reads them. Re-deriving them over the same trials in a second place
    would give the runner and a later re-analysis two chances to disagree about
    where the boundary is, and only one of them would be in the sealed evidence.
    What this adds is the report shape and the trial digests behind it.
    """
    trials = history.trials
    boundary = history.boundary
    bracket_low = history.bracket_low
    highest = trials[-1].step.value if trials else None
    insufficient = tuple(trial.step.index for trial in trials if not trial.sufficient)
    note = ""
    if boundary is not None and (boundary - bracket_low) > policy.resolution:
        note = UNRESOLVED_BOUNDARY_NOTE
    elif boundary is None:
        note = (
            "the ladder ended without a breach, so this report states how far the "
            "search went and not where the boundary is"
        )
    boundary_comparison = None
    if comparisons is not None and boundary is not None:
        index = next(
            (
                trial.step.index
                for trial in trials
                if trial.breached and trial.step.value == boundary
            ),
            None,
        )
        if index is not None:
            boundary_comparison = comparisons.get(index)
    return BoundaryReport(
        policy_name=policy.name,
        boundary=boundary,
        bracket_low=bracket_low,
        bracket_high=boundary,
        resolved=boundary is not None and (boundary - bracket_low) <= policy.resolution,
        resolution=policy.resolution,
        trials=len(trials),
        highest_tried=highest,
        boundary_comparison=boundary_comparison,
        note=note,
        insufficient_trials=insufficient,
        trial_digests=tuple(digest(trial.to_dict()) for trial in trials),
    )


# =======================================================================================
# Recovery curves
# =======================================================================================


@dataclass(frozen=True, slots=True)
class RecoveryPoint:
    """One post-fault sample and how far it sat from the captured baseline."""

    index: int
    value: float
    deviation_pct: float | None
    within_tolerance: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "value": self.value,
            "deviation_pct": self.deviation_pct,
            "within_tolerance": self.within_tolerance,
        }


@dataclass(frozen=True, slots=True)
class RecoveryCurve:
    """How a signal came back after the fault was removed.

    Graded by :func:`mayhem.domain.steady_state.classify` under ``assert_recovered``,
    on the same baseline the degradation was measured against — so "recovered" here
    means the signal returned to *its captured baseline within the declared
    tolerance*, not merely that it exists again. ``recovered_at_index`` is the first
    post-fault sample inside tolerance; ``residual_pct`` is where the last one
    landed.
    """

    name: str
    baseline: Baseline | None
    points: tuple[RecoveryPoint, ...]
    recovered: bool
    recovered_at_index: int | None
    residual_pct: float | None
    verdict: Verdict | None
    graded: bool
    comparison: Comparison | None = None
    note: str = ""
    samples_digest: str = ""
    """The sha256 digest of the raw baseline and cooldown samples (Phase 4).

    The curve's own support: the baseline capture and the post-fault samples it was
    computed from. Taken over the *inputs*, not over this curve, so a curve whose
    samples were re-read differently is a different piece of evidence rather than
    the same one quoted again. Empty when no post-fault sample exists at all — which
    is the case :func:`analytics_evidence` withholds, because a curve with no
    samples is not a recovery and is not evidence of one.
    """

    @property
    def curve(self) -> tuple[float, ...]:
        return tuple(point.value for point in self.points)

    @property
    def statement(self) -> str:
        if self.baseline is None:
            return f"{self.name}: no baseline captured, so recovery was not measured"
        if not self.points:
            return (
                f"{self.name}: no post-fault samples recorded, so recovery was not "
                "observed"
            )
        if not self.graded:
            return f"{self.name}: {self.note}"
        status = "RECOVERED" if self.recovered else "NOT RECOVERED"
        where = (
            "immediately"
            if self.recovered_at_index == 0
            else f"at sample {self.recovered_at_index}"
        )
        residual = (
            "residual 0.0%" if self.residual_pct is None else f"residual {self.residual_pct:+.1f}%"
        )
        return (
            f"{self.name}: returned to its captured baseline ({where}) over "
            f"{len(self.points)} post-fault samples, {residual} — {status}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "baseline": None if self.baseline is None else self.baseline.to_dict(),
            "points": [point.to_dict() for point in self.points],
            "recovered": self.recovered,
            "recovered_at_index": self.recovered_at_index,
            "residual_pct": self.residual_pct,
            "verdict": None if self.verdict is None else self.verdict.value,
            "graded": self.graded,
            "comparison": None if self.comparison is None else self.comparison.to_dict(),
            "statement": self.statement,
            "note": self.note,
            "samples_digest": self.samples_digest,
        }


def _samples_digest(
    baseline_values: Sequence[float], cooldown_values: Sequence[float]
) -> str:
    """The digest of one signal's raw capture, or ``""`` when there is nothing.

    Empty is the honest answer for a curve with no post-fault samples: there is no
    capture to cite, and citing the empty list would mint a digest that a reader
    could later match against any other empty capture.
    """
    if not cooldown_values:
        return ""
    return digest(
        {
            "baseline": [float(value) for value in baseline_values],
            "cooldown": [float(value) for value in cooldown_values],
        }
    )


def recovery_curve(
    *,
    name: str,
    baseline_values: Sequence[float],
    cooldown_values: Sequence[float],
    tolerance: Tolerance,
    percentile: float = 99.0,
    sample_policy: SamplePolicy | None = None,
    materiality_pct: float | None = None,
) -> RecoveryCurve:
    """Extract one signal's recovery curve from its post-fault samples.

    ``baseline_values`` is the pre-fault capture and ``cooldown_values`` the samples
    taken after the fault was removed (the ``cooldown`` phase of
    :class:`mayhem.domain.analytics.WindowPlan`, or simply "after"). Sufficiency is
    judged by :class:`~mayhem.domain.analytics.SamplePolicy` before anything is
    measured, and an under-sampled or missing baseline yields an ungraded curve with
    the reason attached — the same refusal :func:`mayhem.domain.steady_state.classify`
    makes, in the same voice.
    """
    floor = SamplePolicy() if sample_policy is None else sample_policy
    baseline = sample_baseline(baseline_values, percentile=percentile)
    samples = _samples_digest(baseline_values, cooldown_values)
    if not cooldown_values:
        # Checked before sufficiency, and deliberately: "no post-fault samples at
        # all" is a different failure from "fewer post-fault samples than the
        # floor", and the first is the one a residue scan has to find.
        return RecoveryCurve(
            name=name,
            baseline=baseline,
            points=(),
            recovered=False,
            recovered_at_index=None,
            residual_pct=None,
            verdict=None,
            graded=False,
            note=(
                "no post-fault samples were recorded: an empty recovery curve is not a "
                "recovery, and reporting one as clean would be the residue this tool "
                "exists to surface"
            ),
            samples_digest=samples,
        )
    base_count = 0 if baseline is None else baseline.samples
    sufficiency = floor.check(base_count, len(cooldown_values))
    if not sufficiency.sufficient or baseline is None:
        return RecoveryCurve(
            name=name,
            baseline=baseline,
            points=(),
            recovered=False,
            recovered_at_index=None,
            residual_pct=None,
            verdict=None,
            graded=False,
            note=sufficiency.reason,
            samples_digest=samples,
        )
    points = tuple(
        RecoveryPoint(
            index=index,
            value=value,
            deviation_pct=delta_pct(baseline.value, value),
            within_tolerance=within_relative(baseline.value, value, tolerance),
        )
        for index, value in enumerate(cooldown_values)
    )
    assertion = Assertion(
        verb=AssertionVerb.RECOVERED,
        name=name,
        tolerance=tolerance,
        required_samples=base_count,
    )
    result = classify(points[-1].value, baseline, assertion)
    recovered_at = next((point.index for point in points if point.within_tolerance), None)
    return RecoveryCurve(
        name=name,
        baseline=baseline,
        points=points,
        recovered=bool(result.passed),
        recovered_at_index=recovered_at,
        residual_pct=points[-1].deviation_pct,
        verdict=result.verdict,
        graded=result.graded,
        comparison=compare(
            baseline_values,
            cooldown_values,
            name=name,
            percentile=percentile,
            policy=floor,
            materiality_pct=materiality_pct,
        ),
        note=result.note,
        samples_digest=samples,
    )


# =======================================================================================
# Minimal failure cases (counterexample minimization)
# =======================================================================================

MAX_CERTIFIABLE_COMPONENTS = 8
"""Above this many components, minimality is reported but not certified.

Enumerating proper subsets is ``2**n - 2`` per candidate. Eight components is 254
subsets — already more than a reader will check — so a larger case reports the
smallest *tried* reproduction and says plainly that it is not certified minimal,
rather than spending CPU to assert something nobody can verify.
"""


@dataclass(frozen=True, slots=True)
class FailureCase:
    """One tried fault/target combination and whether it reproduced."""

    fault_ids: tuple[str, ...]
    target_ids: tuple[str, ...]
    reproduced: bool
    value: float | None = None
    combination: str = ""
    sufficient: bool = True

    @property
    def components(self) -> tuple[str, ...]:
        """Canonical component labels — the unit minimization shrinks."""
        return (
            *(f"fault:{fault_id}" for fault_id in sorted(self.fault_ids)),
            *(f"target:{target_id}" for target_id in sorted(self.target_ids)),
        )

    @property
    def size(self) -> int:
        return len(self.components)

    def key(self) -> str:
        return "+".join(self.components)

    def to_dict(self) -> dict[str, object]:
        return {
            "fault_ids": list(self.fault_ids),
            "target_ids": list(self.target_ids),
            "reproduced": self.reproduced,
            "sufficient": self.sufficient,
            "value": self.value,
            "combination": self.combination,
            "key": self.key(),
        }


@dataclass(frozen=True, slots=True)
class MinimalFailureCase:
    """The smallest tried reproduction, and whether minimality is certified.

    ``minimal`` is ``True`` only when every proper subset of the chosen case was
    itself tried and did not reproduce. A search that found a two-component
    reproduction without trying the one-component versions has found the *smallest
    tried* case, and this type says so instead of implying the search proved there
    is nothing smaller.
    """

    case: FailureCase | None
    size: int
    minimal: bool
    considered: int
    note: str = ""
    case_digests: tuple[str, ...] = ()
    """The sha256 digest of every *measurable* tried case the reduction read (Phase 4).

    Including the cases that did **not** reproduce, because minimality is a claim
    about the subsets that were tried and cleared — a minimal case with no record of
    the clearances behind it is an assertion. Empty when no measurable case was
    offered, which is what makes "nothing reproduced over nothing tried" withheld
    rather than sealed as a finding.
    """

    @property
    def found(self) -> bool:
        return self.case is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "case": None if self.case is None else self.case.to_dict(),
            "size": self.size,
            "minimal": self.minimal,
            "found": self.found,
            "considered": self.considered,
            "note": self.note,
            "case_digests": list(self.case_digests),
        }


def minimal_failure_case(cases: Sequence[FailureCase]) -> MinimalFailureCase:
    """Minimize a set of tried combinations down to the smallest reproduction.

    Deterministic: reproductions are ranked by component count, then by the
    canonical component key, and the winner is the first. An insufficient measurement
    is never counted as a reproduction *or* as a clearance — it is skipped, so an
    unmeasurable trial cannot masquerade as evidence that a subset does not
    reproduce.

    Minimality is certified by checking every non-empty proper subset of the winner
    against the tried set: each must be present and must have failed to reproduce. A
    subset that was never tried blocks certification and is named in the note.
    """
    usable = [case for case in cases if case.sufficient]
    # Ordered by the canonical key, not by the caller's order, so the support a
    # reader gets is the same whichever order the cases arrived in.
    digests = tuple(digest(case.to_dict()) for case in sorted(usable, key=lambda c: c.key()))
    reproductions = sorted(
        (case for case in usable if case.reproduced),
        key=lambda case: (case.size, case.key()),
    )
    if not reproductions:
        return MinimalFailureCase(
            case=None,
            size=0,
            minimal=False,
            considered=len(usable),
            note=(
                f"no tried combination reproduced the failure across {len(usable)} "
                "measurable case(s): there is no minimal failure case to report, and "
                "the absence is the finding"
            ),
            case_digests=digests,
        )
    winner = reproductions[0]
    if winner.size > MAX_CERTIFIABLE_COMPONENTS:
        return MinimalFailureCase(
            case=winner,
            size=winner.size,
            minimal=False,
            considered=len(usable),
            note=(
                f"{winner.size} components exceeds the {MAX_CERTIFIABLE_COMPONENTS}-"
                "component certification ceiling, so this is the smallest tried "
                "reproduction and not a certified minimal case"
            ),
            case_digests=digests,
        )
    tried = {case.key(): case for case in usable}
    untested: list[str] = []
    for subset in _proper_subsets(winner.components):
        # A subset with no fault perturbs nothing, so it cannot have reproduced and
        # cannot be "tried" — requiring it would make minimality uncertifiable for
        # every real case, which is worse than saying nothing about it.
        if not any(component.startswith("fault:") for component in subset):
            continue
        observed = tried.get("+".join(subset))
        if observed is None or observed.reproduced:
            untested.append("+".join(subset))
    if untested:
        return MinimalFailureCase(
            case=winner,
            size=winner.size,
            minimal=False,
            considered=len(usable),
            note=(
                "smallest tried reproduction, not certified minimal: "
                f"{len(untested)} proper subset(s) were never tried or also reproduced "
                f"(first: {sorted(untested)[0]})"
            ),
            case_digests=digests,
        )
    return MinimalFailureCase(
        case=winner,
        size=winner.size,
        minimal=True,
        considered=len(usable),
        note=(
            "every fault-bearing proper subset was tried and did not reproduce"
        ),
        case_digests=digests,
    )


def _proper_subsets(components: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    """Every non-empty proper subset, in a deterministic order."""
    found: list[tuple[str, ...]] = []
    for mask in range(1, (1 << len(components)) - 1):
        subset = tuple(
            component for index, component in enumerate(components) if mask >> index & 1
        )
        found.append(subset)
    return tuple(found)


# =======================================================================================
# Sealed analytics evidence (Phase 4)
# =======================================================================================


class ClaimKind(StrEnum):
    """What one sealed claim is about."""

    BOUNDARY = "boundary"
    RECOVERY = "recovery"
    MINIMAL_FAILURE_CASE = "minimal-failure-case"
    CAUSAL_CHAIN = "causal-chain"


@dataclass(frozen=True, slots=True)
class AnalyticsClaim:
    """One analytics finding, the digest that fixes it, and what it rests on.

    Three refusals, all at construction, because a claim is a value that travels
    into sealed bytes and a value that cannot hold a lie is cheaper to audit than a
    reviewer:

    * no subject (:data:`RULE_EVIDENCE_UNSUPPORTED`);
    * a ``claim_digest`` that is not a sha256 hex digest
      (:data:`RULE_CITATION_NOT_A_DIGEST` — the same law every other citation in
      this module obeys, applied to the claim itself rather than to its support);
    * no support at all (:data:`RULE_EVIDENCE_UNSUPPORTED`).

    ``support`` reuses the citation types Phase 2 already defined rather than
    inventing a third: an :class:`ObservationCitation` names a record by digest, an
    :class:`EdgeCitation` names a topology edge in full. A causal chain's own
    citations are already values of those two types, so sealing one is a projection
    rather than a translation.
    """

    kind: ClaimKind
    subject: str
    claim_digest: str
    support: tuple[ObservationCitation | EdgeCitation, ...]
    statement: str = ""
    detail: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.subject.strip():
            raise InvariantViolationError(
                RULE_EVIDENCE_UNSUPPORTED,
                f"a {self.kind.value} claim must name what it is about",
            )
        if _SHA256_HEX.fullmatch(self.claim_digest) is None:
            raise InvariantViolationError(
                RULE_CITATION_NOT_A_DIGEST,
                f"a claim digest must be the sha256 of the report it claims to describe, "
                f"got {self.claim_digest!r}",
            )
        if not self.support:
            raise InvariantViolationError(
                RULE_EVIDENCE_UNSUPPORTED,
                f"the {self.kind.value} claim about {self.subject!r} cites neither an "
                f"observation nor a topology edge: {NO_SUPPORT_NOTE}",
            )

    @property
    def observations(self) -> tuple[ObservationCitation, ...]:
        return tuple(c for c in self.support if isinstance(c, ObservationCitation))

    @property
    def edges(self) -> tuple[EdgeCitation, ...]:
        return tuple(c for c in self.support if isinstance(c, EdgeCitation))

    @property
    def support_refs(self) -> tuple[str, ...]:
        """Every support reference, in the order the claim cites them.

        Digests for observations, ``kind:src->dst`` keys for edges — so one tuple
        answers "what was this computed from" without the reader having to know
        which kind of citation each entry is.
        """
        return tuple(
            citation.ref if isinstance(citation, ObservationCitation) else citation.key()
            for citation in self.support
        )

    def payload(self) -> dict[str, object]:
        """The attested body: the claim, its statement, and its support."""
        return {
            "kind": self.kind.value,
            "subject": self.subject,
            "claim_digest": self.claim_digest,
            "statement": self.statement,
            "support": [citation.to_dict() for citation in self.support],
            "support_refs": list(self.support_refs),
            "detail": dict(sorted(self.detail.items())),
        }

    def to_dict(self) -> dict[str, object]:
        return self.payload()


@dataclass(frozen=True, slots=True)
class WithheldEvidence:
    """A report that could not be sealed because it rested on nothing.

    The Phase 4 sibling of :class:`WithheldClaim`: that one is a causal chain that
    stopped at a hop, this is a boundary or a curve or a minimal case that has no
    observation behind it at all. Both are reported rather than dropped, because a
    reader who counts the claims also has to be able to count what did not survive.
    """

    kind: ClaimKind
    subject: str
    rule_id: str
    reason: str

    def payload(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "subject": self.subject,
            "rule_id": self.rule_id,
            "reason": self.reason,
        }

    def to_dict(self) -> dict[str, object]:
        return self.payload()


@dataclass(frozen=True, slots=True)
class AnalyticsEvidence:
    """What one analysis supports, and what it had to withhold."""

    run_id: str
    claims: tuple[AnalyticsClaim, ...] = ()
    withheld: tuple[WithheldEvidence, ...] = ()

    @property
    def complete(self) -> bool:
        """Every report in the analysis became a claim — no section was withheld."""
        return not self.withheld

    @property
    def claim_digests(self) -> tuple[str, ...]:
        return tuple(claim.claim_digest for claim in self.claims)

    def claim_for(self, claim_digest: str) -> AnalyticsClaim | None:
        return next(
            (claim for claim in self.claims if claim.claim_digest == claim_digest), None
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "claims": [claim.to_dict() for claim in self.claims],
            "withheld": [claim.to_dict() for claim in self.withheld],
            "claim_digests": list(self.claim_digests),
            "complete": self.complete,
        }


def boundary_claim(report: BoundaryReport) -> AnalyticsClaim | WithheldEvidence:
    """The boundary report as a claim, or the reason it cannot be one.

    The support is every trial the bracket was read from
    (:attr:`BoundaryReport.trial_digests`), in order. A report over no trials at all
    is withheld: "no impairment crossed the tolerance" over an empty history is not
    a finding about the system's tolerance, it is a statement that nobody ran
    anything, and sealing it would let a search that executed zero steps produce a
    signed boundary of ``None``.
    """
    support = tuple(
        ObservationCitation(
            kind=CitationKind.TRIAL,
            ref=ref,
            detail=f"trial {index}",
        )
        for index, ref in enumerate(report.trial_digests)
    )
    if not support:
        return WithheldEvidence(
            kind=ClaimKind.BOUNDARY,
            subject=report.policy_name,
            rule_id=RULE_EVIDENCE_UNSUPPORTED,
            reason=(
                f"the search executed no trial at all, so this report rests on nothing: "
                f"{NO_SUPPORT_NOTE}"
            ),
        )
    return AnalyticsClaim(
        kind=ClaimKind.BOUNDARY,
        subject=report.policy_name,
        claim_digest=digest(report.to_dict()),
        support=support,
        statement=report.tolerance_statement,
        detail={
            "boundary": report.boundary,
            "bracket_low": report.bracket_low,
            "bracket_high": report.bracket_high,
            "resolved": report.resolved,
            "resolution": report.resolution,
            "trials": report.trials,
            "highest_tried": report.highest_tried,
            "insufficient_trials": list(report.insufficient_trials),
            "confidence_statement": report.confidence_statement,
        },
    )


def _recovery_claim(curve: RecoveryCurve) -> AnalyticsClaim | WithheldEvidence:
    """One recovery curve as a claim, or withheld when there were no samples.

    ``graded`` travels in the detail rather than deciding the claim: a curve that
    could not be separated from noise is still a record of what was measured, and
    sealing it with ``graded: false`` keeps it out of the set of findings while
    leaving it in the evidence. Only the absence of samples withholds it.
    """
    if not curve.samples_digest:
        return WithheldEvidence(
            kind=ClaimKind.RECOVERY,
            subject=curve.name,
            rule_id=RULE_EVIDENCE_UNSUPPORTED,
            reason=(
                f"no post-fault sample was recorded for {curve.name!r}: {NO_SUPPORT_NOTE}"
            ),
        )
    return AnalyticsClaim(
        kind=ClaimKind.RECOVERY,
        subject=curve.name,
        claim_digest=digest(curve.to_dict()),
        support=(
            ObservationCitation(
                kind=CitationKind.METRIC,
                ref=curve.samples_digest,
                detail=f"{curve.name}: baseline and cooldown samples",
            ),
        ),
        statement=curve.statement,
        detail={
            "graded": curve.graded,
            "recovered": curve.recovered,
            "recovered_at_index": curve.recovered_at_index,
            "residual_pct": curve.residual_pct,
            "samples": len(curve.points),
            "verdict": None if curve.verdict is None else curve.verdict.value,
        },
    )


def _minimal_claim(case: MinimalFailureCase) -> AnalyticsClaim | WithheldEvidence:
    """One minimal-failure-case reduction as a claim, or withheld.

    The support is every measurable case that was tried — reproductions *and*
    clearances — because minimality is a claim about the subsets that were tried
    and did not reproduce. ``minimal`` travels in the detail so a reader can tell a
    certified minimal case from the smallest *tried* one without re-deriving the
    subset walk.
    """
    if not case.case_digests:
        return WithheldEvidence(
            kind=ClaimKind.MINIMAL_FAILURE_CASE,
            subject=case.case.key() if case.case is not None else "(none)",
            rule_id=RULE_EVIDENCE_UNSUPPORTED,
            reason=(
                f"no measurable fault/target combination was tried, so the reduction "
                f"rests on nothing: {NO_SUPPORT_NOTE}"
            ),
        )
    return AnalyticsClaim(
        kind=ClaimKind.MINIMAL_FAILURE_CASE,
        subject=case.case.key() if case.case is not None else "(none-reproduced)",
        claim_digest=digest(case.to_dict()),
        support=tuple(
            ObservationCitation(
                kind=CitationKind.TRIAL,
                ref=ref,
                detail=f"tried case {index}",
            )
            for index, ref in enumerate(case.case_digests)
        ),
        statement=case.note,
        detail={
            "found": case.found,
            "size": case.size,
            "minimal": case.minimal,
            "considered": case.considered,
            "combination": None if case.case is None else case.case.key(),
        },
    )


def _chain_claim(chain: CausalChain) -> AnalyticsClaim | WithheldEvidence:
    """One causal chain as a claim, citing the records and the edges behind it.

    The chain's own citations, unchanged: every observation it was built over and
    every topology edge it traversed. A chain cannot be sealed with fewer citations
    than it already carries, and a chain that carries none cannot be built at all
    (Phase 2), so this branch exists to name the failure rather than to search for
    support.
    """
    support: tuple[ObservationCitation | EdgeCitation, ...] = (
        *chain.observations,
        *chain.edges,
    )
    if not support:
        return WithheldEvidence(
            kind=ClaimKind.CAUSAL_CHAIN,
            subject=chain.fault_id,
            rule_id=RULE_EVIDENCE_UNSUPPORTED,
            reason=(
                f"the chain from fault {chain.fault_id!r} cites neither an observation "
                f"nor a topology edge: {NO_SUPPORT_NOTE}"
            ),
        )
    return AnalyticsClaim(
        kind=ClaimKind.CAUSAL_CHAIN,
        subject=chain.fault_id,
        claim_digest=digest(chain.to_dict()),
        support=support,
        statement=(
            f"{chain.fault_id} → {chain.target_id} → {chain.dependency_id} → "
            f"{chain.metric} → {chain.customer_node_id}"
        ),
        detail={
            "target_id": chain.target_id,
            "dependency_id": chain.dependency_id,
            "metric": chain.metric,
            "customer_node_id": chain.customer_node_id,
            "hops": [hop.hop.value for hop in chain.hops],
            "edge_citations": len(chain.edges),
            "observation_citations": len(chain.observations),
        },
    )


def analytics_evidence(analysis: ResilienceAnalysis, *, run_id: str = "") -> AnalyticsEvidence:
    """Derive the claims one analysis supports, and withhold what it does not.

    Pure and deterministic, and the *only* place a report becomes a claim: a
    boundary, every recovery curve, the minimal failure case, and every causal
    chain, in that order. Sections absent from the analysis produce nothing at all —
    ``minimal_case is None`` is not a withheld claim, it is a section nobody ran,
    which :class:`ResilienceAnalysis`'s own notes already say.

    A report that is present but unsupported becomes a :class:`WithheldEvidence`
    rather than a claim with an empty support list, so ``len(claims) +
    len(withheld)`` is the number of sections the analysis actually produced — plus
    one entry per causal chain the analysis itself withheld, whose rule id is the
    causal rule that stopped it.
    """
    claims: list[AnalyticsClaim] = []
    withheld: list[WithheldEvidence] = []
    sections: list[AnalyticsClaim | WithheldEvidence] = [boundary_claim(analysis.boundary)]
    sections.extend(_recovery_claim(curve) for curve in analysis.recovery)
    if analysis.minimal_case is not None:
        sections.append(_minimal_claim(analysis.minimal_case))
    if analysis.causal is not None:
        sections.extend(_chain_claim(claim) for claim in analysis.causal.claims)
        # The causal analysis's own withholdings are sealed too, carrying their own
        # rule ids. A chain that stopped at a hop is a finding about the graph as
        # much as a chain that completed is a finding about the incident, and a
        # sealed record that listed only the completed chains would read as "nothing
        # else was considered".
        withheld.extend(
            WithheldEvidence(
                kind=ClaimKind.CAUSAL_CHAIN,
                subject=f"{claim.fault_id}:{claim.hop.value}",
                rule_id=claim.rule_id,
                reason=(
                    f"the chain from fault {claim.fault_id!r} to "
                    f"{claim.target_id or '(no target)'} was withheld at hop "
                    f"{claim.hop.value}: {claim.reason}"
                ),
            )
            for claim in analysis.causal.withheld
        )
    for section in sections:
        if isinstance(section, WithheldEvidence):
            withheld.append(section)
        else:
            claims.append(section)
    return AnalyticsEvidence(run_id=run_id, claims=tuple(claims), withheld=tuple(withheld))


def analytics_chain_id(run_id: str) -> str:
    """The synthetic run id one analysis's chain hangs off.

    The subject run id travels in the payload instead, for the reason
    :mod:`mayhem.controller.certification_evidence` names its own: plan 12's
    verifier requires one ``run_id`` per chain, and an analysis spans whatever runs
    produced its trials.
    """
    return f"{ANALYTICS_CHAIN_PREFIX}:{run_id}"


def analytics_manifest_id(run_id: str) -> str:
    """The manifest id for ``run_id``'s analytics chain."""
    return f"{analytics_chain_id(run_id)}:manifest"


def _reading(recorded_at: AttestedTimestamp | None) -> AttestedTimestamp:
    """The caller's reading, or a wall-clock + monotonic pair.

    The monotonic half comes from :func:`time.monotonic_ns` rather than the wall
    clock, so a host whose clock steps mid-analysis still orders these events
    correctly — the same clock policy :mod:`mayhem.infra.attestation_store` and
    :mod:`mayhem.infra.audit_stream` both use, so a run event and an analytics
    event taken together are ordered by one rule.
    """
    if recorded_at is not None:
        return recorded_at
    return AttestedTimestamp(
        wall_clock=utc_now(),
        monotonic_ns=time.monotonic_ns(),
        uncertainty_ms=0.0,
        source="system",
    )


def analytics_evidence_events(
    evidence: AnalyticsEvidence,
    *,
    recorded_at: AttestedTimestamp,
) -> tuple[AttestedEvent, ...]:
    """The events one analysis seals, in chain order (pure).

    Always three or more: what was analysed (:data:`CHAIN_EVENT_ANALYTICS_RECORDED`),
    then one :data:`CHAIN_EVENT_ANALYTICS_CLAIM` per supported report and one
    :data:`CHAIN_EVENT_ANALYTICS_WITHHELD` per unsupported one, then the seal that
    closes the chain. Withholding is sealed too: a reader who reloads the chain sees
    what was *not* claimed and why, which is the difference between "the search
    found nothing" and "the search established nothing".

    Event ids carry the claim's digest, so re-sealing a *different* analysis for the
    same run cannot collide with this one's ids, and the chain verifier would catch
    a genuine collision rather than silently dropping a claim.
    """
    chain_id = analytics_chain_id(evidence.run_id)
    events: list[AttestedEvent] = [
        AttestedEvent(
            event_id=f"{chain_id}:recorded",
            event_kind=CHAIN_EVENT_ANALYTICS_RECORDED,
            run_id=chain_id,
            sequence=0,
            payload={
                "run_id": evidence.run_id,
                "claims": len(evidence.claims),
                "withheld": len(evidence.withheld),
                "claim_digests": list(evidence.claim_digests),
                "complete": evidence.complete,
            },
            recorded_at=recorded_at,
        )
    ]
    for claim in evidence.claims:
        events.append(
            AttestedEvent(
                event_id=f"{chain_id}:claim:{claim.claim_digest[:16]}",
                event_kind=CHAIN_EVENT_ANALYTICS_CLAIM,
                run_id=chain_id,
                sequence=len(events),
                payload=claim.payload(),
                recorded_at=recorded_at,
            )
        )
    for index, withheld in enumerate(evidence.withheld):
        events.append(
            AttestedEvent(
                event_id=f"{chain_id}:withheld:{index}",
                event_kind=CHAIN_EVENT_ANALYTICS_WITHHELD,
                run_id=chain_id,
                sequence=len(events),
                payload=withheld.payload(),
                recorded_at=recorded_at,
            )
        )
    events.append(
        AttestedEvent(
            event_id=f"{chain_id}:sealed",
            event_kind=CHAIN_EVENT_ANALYTICS_SEALED,
            run_id=chain_id,
            sequence=len(events),
            payload={
                "run_id": evidence.run_id,
                "claims": len(evidence.claims),
                "withheld": len(evidence.withheld),
            },
            recorded_at=recorded_at,
        )
    )
    return tuple(events)


@dataclass(frozen=True, slots=True)
class AnalyticsSeal:
    """What sealing an analysis produced, plus the verdicts that prove it."""

    run_id: str
    chain_id: str
    manifest_id: str
    evidence: AnalyticsEvidence
    events: tuple[AttestedEvent, ...]
    manifest: Manifest
    chain_verification: ChainVerification
    manifest_verification: ManifestVerification
    signature_state: str
    signature_reason: str

    @property
    def chain_root(self) -> str:
        """The root the manifest commits to."""
        return chain_root(self.events)

    @property
    def verified(self) -> bool:
        """Both the chain and its manifest verified.

        The only thing that makes a claim *back* a decision. An unsealed analysis
        verifies nothing, and :func:`require_sealed_claim` reads this rather than
        trusting the caller's word that it sealed it.
        """
        return self.chain_verification.valid and self.manifest_verification.valid

    @property
    def signed(self) -> bool:
        """Always ``False``. Integrity is sealed; authorship is not claimed."""
        return False

    @property
    def claims(self) -> tuple[AnalyticsClaim, ...]:
        return self.evidence.claims

    @property
    def withheld(self) -> tuple[WithheldEvidence, ...]:
        return self.evidence.withheld

    def describe(self) -> str:
        return (
            f"{self.run_id}: {len(self.claims)} claim(s), {len(self.withheld)} withheld, "
            f"sealed as {self.manifest_id} (root {self.chain_root[:12]}…, "
            f"{len(self.events)} event(s), {'verified' if self.verified else 'UNVERIFIED'}, "
            f"{self.signature_state})"
        )


def seal_analytics_evidence(
    store: Store,
    analysis: ResilienceAnalysis,
    *,
    run_id: str,
    recorded_at: AttestedTimestamp | None = None,
    retention_class: RetentionClass = RetentionClass.HOT,
) -> AnalyticsSeal:
    """Seal one analysis's evidence into a persisted chain and manifest.

    Delegates every part of the sealing to plan 12's machinery: this function decides
    *what* is attested and nothing else. :func:`~mayhem.domain.attestation.seal_events`
    and :func:`~mayhem.domain.attestation.build_manifest` do the hashing,
    :meth:`~mayhem.infra.attestation_store.AttestationRepository` does the
    persistence and the evidence-boundary gate, and both verdicts are checked
    **before** anything is written — so an analysis that does not hold leaves no row
    behind to be mistaken for evidence.

    The unsigned state and the reason for it are carried on the returned seal and are
    the plan 12 strings, imported rather than restated: this module attests
    integrity, and nothing here may read as though it attests authorship.

    Args:
        store: The migrated store.
        analysis: The analysis whose sections become claims.
        run_id: The run this analysis describes. Travels in the payload; the chain
            itself hangs off :func:`analytics_chain_id`.
        recorded_at: The reading to stamp the events with (tests inject one).
        retention_class: The class the retention ladder will enforce.

    Returns:
        The sealed chain, its manifest, the claims and withholdings, and both
        verification verdicts.

    Raises:
        AttestationError: If the derived chain or the manifest fails verification.
            Nothing is written.
        InvariantViolationError: From the evidence boundary inside the plan 12
            writers, if a derived document carries a secret-classified field or a
            value this run resolved.
    """
    if not run_id.strip():
        raise InvariantViolationError(
            RULE_EVIDENCE_UNSUPPORTED,
            "sealing analytics evidence needs the run id it describes: a chain nobody "
            "can attribute to a run is not evidence about one",
        )
    evidence = analytics_evidence(analysis, run_id=run_id)
    reading = _reading(recorded_at)
    events = seal_events(analytics_evidence_events(evidence, recorded_at=reading))
    chain_id = analytics_chain_id(run_id)
    manifest = build_manifest(
        events,
        manifest_id=analytics_manifest_id(run_id),
        run_id=chain_id,
        signer_identity="",
        trust_root_ref="",
        retention_class=retention_class,
        created_at=reading,
        previous_manifest_digest=GENESIS_DIGEST,
    )
    chain_verification = verify_chain(events)
    if not chain_verification.valid:
        raise AttestationError(
            f"refusing to seal an invalid analytics chain for run {run_id!r}: "
            f"{'; '.join(chain_verification.errors)}"
        )
    manifest_verification = verify_manifest(manifest, events)
    if not manifest_verification.valid:
        raise AttestationError(
            f"refusing to seal an invalid analytics manifest for run {run_id!r}: "
            f"{'; '.join(manifest_verification.errors)}"
        )
    repository = AttestationRepository(store)
    repository.save_chain(chain_id, events, sealed_at=reading.wall_clock)
    repository.save_manifest(manifest)
    return AnalyticsSeal(
        run_id=run_id,
        chain_id=chain_id,
        manifest_id=manifest.manifest_id,
        evidence=evidence,
        events=events,
        manifest=manifest,
        chain_verification=chain_verification,
        manifest_verification=manifest_verification,
        signature_state=SIGNATURE_UNSIGNED_NO_SIGNING,
        signature_reason=UNSIGNED_REASON_NO_SIGNING,
    )


@dataclass(frozen=True, slots=True)
class AnalyticsEvidenceVerdict:
    """What a reloaded analytics chain says, from its stored bytes alone."""

    run_id: str
    chain_id: str
    present: bool
    verified: bool
    claims: tuple[AnalyticsClaim, ...] = ()
    withheld: tuple[WithheldEvidence, ...] = ()
    errors: tuple[str, ...] = ()

    def backing(self, claim_digest: str) -> str | None:
        """The digest of the claim with that digest, or ``None`` if absent.

        ``None`` means *not in a verified chain*, which is what a decision path must
        treat as a refusal: the report may be perfectly true and still be unusable
        as evidence, because nothing sealed it.
        """
        if not (self.present and self.verified):
            return None
        claim = next(
            (claim for claim in self.claims if claim.claim_digest == claim_digest), None
        )
        return None if claim is None else claim.claim_digest

    def describe(self) -> str:
        if not self.present:
            return f"{self.run_id}: no analytics chain stored"
        if not self.verified:
            return f"{self.run_id}: analytics chain does NOT verify — {'; '.join(self.errors)}"
        return (
            f"{self.run_id}: {len(self.claims)} claim(s), {len(self.withheld)} withheld, "
            "chain verified"
        )


def verify_analytics_evidence(store: Store, run_id: str) -> AnalyticsEvidenceVerdict:
    """Reload a run's analytics chain and re-verify it with plan 12's own verifier.

    The persisted counterpart of :func:`analytics_evidence_events`: a report that a
    caller still holds in memory proves nothing months later, and this is what turns
    it back into evidence — or reports that it no longer is. Both the chain and the
    manifest are re-verified, and the claims are rebuilt from the stored payloads
    rather than from the caller's objects, so a claim only comes back if its own
    bytes carry it.

    A run with no stored chain reports ``present=False`` and the absence named,
    rather than an empty claim list a reader could mistake for "nothing was claimed".
    """
    chain_id = analytics_chain_id(run_id)
    repository = AttestationRepository(store)
    events = repository.load_chain(chain_id)
    if not events:
        return AnalyticsEvidenceVerdict(
            run_id=run_id,
            chain_id=chain_id,
            present=False,
            verified=False,
            errors=(f"no analytics chain stored for run {run_id!r}",),
        )
    verification = repository.verify_run_chain(chain_id)
    errors = list(verification.errors)
    try:
        manifest = repository.load_manifest(analytics_manifest_id(run_id))
    except KeyError:  # pragma: no cover -- load_manifest returns None, not KeyError
        manifest = None
    if manifest is None:
        errors.append(
            f"the chain for run {run_id!r} is stored but carries no manifest, so nothing "
            "commits to it"
        )
    else:
        manifest_verification = verify_manifest(manifest, events)
        errors.extend(manifest_verification.errors)
    claims: list[AnalyticsClaim] = []
    withheld: list[WithheldEvidence] = []
    for event in events:
        if event.event_kind == CHAIN_EVENT_ANALYTICS_CLAIM:
            claims.append(_claim_from_payload(event.payload))
        elif event.event_kind == CHAIN_EVENT_ANALYTICS_WITHHELD:
            withheld.append(_withheld_from_payload(event.payload))
    return AnalyticsEvidenceVerdict(
        run_id=run_id,
        chain_id=chain_id,
        present=True,
        verified=not errors,
        claims=tuple(claims),
        withheld=tuple(withheld),
        errors=tuple(errors),
    )


def _claim_from_payload(payload: Mapping[str, object]) -> AnalyticsClaim:
    """Rebuild a claim from its attested bytes.

    The support is rebuilt as citations, so a claim that comes back from storage
    carries the same digests and edge keys it was sealed with — and a payload whose
    support is empty cannot be rebuilt, because :class:`AnalyticsClaim` refuses it
    (again). That is deliberate: a stored payload that lost its support makes
    :func:`verify_analytics_evidence` raise rather than hand back a claim with
    nothing behind it.
    """
    support: list[ObservationCitation | EdgeCitation] = []
    raw_support = payload.get("support", ())
    for raw in raw_support if isinstance(raw_support, Sequence) else ():
        if not isinstance(raw, Mapping):
            continue
        kind = str(raw.get("kind", ""))
        if "edge" in raw and kind not in {item.value for item in CitationKind}:
            support.append(
                EdgeCitation(
                    src=str(raw.get("src", "")),
                    dst=str(raw.get("dst", "")),
                    kind=_edge_kind(raw),
                    detail=str(raw.get("detail", "")),
                )
            )
            continue
        support.append(
            ObservationCitation(
                kind=CitationKind(kind),
                ref=str(raw.get("ref", "")),
                detail=str(raw.get("detail", "")),
            )
        )
    detail = payload.get("detail")
    return AnalyticsClaim(
        kind=ClaimKind(str(payload.get("kind", ""))),
        subject=str(payload.get("subject", "")),
        claim_digest=str(payload.get("claim_digest", "")),
        support=tuple(support),
        statement=str(payload.get("statement", "")),
        detail=detail if isinstance(detail, Mapping) else {},
    )


def _edge_kind(raw: Mapping[str, object]) -> EdgeKind:
    """Rebuild an edge citation's kind from its attested ``edge`` key.

    The key is ``kind:src->dst``, so the kind is its first segment. Falls back to
    the plain ``kind`` field a payload written by an older shape would carry, and
    raises on anything else — a citation whose kind cannot be rebuilt is a payload
    that is not the shape this module sealed.
    """
    prefix = str(raw.get("edge", "")).split(":", 1)[0]
    return EdgeKind(prefix or str(raw.get("kind", "")))


def _withheld_from_payload(payload: Mapping[str, object]) -> WithheldEvidence:
    return WithheldEvidence(
        kind=ClaimKind(str(payload.get("kind", ""))),
        subject=str(payload.get("subject", "")),
        rule_id=str(payload.get("rule_id", "")),
        reason=str(payload.get("reason", "")),
    )


def require_sealed_claim(seal: AnalyticsSeal | None, claim: AnalyticsClaim) -> str:
    """The claim's digest, if a **verified** chain sealed it. Otherwise a refusal.

    This is the gate a decision path calls. Three refusals, all
    :data:`RULE_EVIDENCE_NOT_SEALED`, because an unsealed report cannot back a
    decision and the three ways that happens are different:

    * ``seal is None`` — nobody sealed this analysis at all;
    * the chain does not verify — the bytes are there but the integrity check failed;
    * the claim is absent from the chain — the seal covers something else.

    What it does *not* do is re-grade the claim. The claim was built by the function
    that owns its kind, and a second opinion here would be a second definition of
    what a boundary or a chain is. This gate asks one question — is this exact
    finding in sealed, verified bytes — and answers it from the chain.
    """
    if seal is None:
        raise InvariantViolationError(
            RULE_EVIDENCE_NOT_SEALED,
            f"the {claim.kind.value} claim about {claim.subject!r} is not sealed: no "
            "analytics evidence was sealed for this analysis, and an unsealed report "
            "cannot back a decision",
        )
    if not seal.verified:
        errors = (*seal.chain_verification.errors, *seal.manifest_verification.errors)
        raise InvariantViolationError(
            RULE_EVIDENCE_NOT_SEALED,
            f"the analytics chain for run {seal.run_id!r} does not verify "
            f"({'; '.join(errors)}): the {claim.kind.value} claim about "
            f"{claim.subject!r} cannot back a decision",
        )
    if seal.evidence.claim_for(claim.claim_digest) is None:
        raise InvariantViolationError(
            RULE_EVIDENCE_NOT_SEALED,
            f"the {claim.kind.value} claim about {claim.subject!r} (digest "
            f"{claim.claim_digest[:12]}…) is not in the chain sealed for run "
            f"{seal.run_id!r}, which carries {len(seal.claims)} other claim(s): a report "
            "someone else sealed does not evidence this one",
        )
    return claim.claim_digest


def boundary_decision_support(seal: AnalyticsSeal | None, report: BoundaryReport) -> str:
    """The sealed digest of a boundary report, for a decision that reads it.

    The boundary is the claim most likely to be quoted out of context, so it gets
    the named entry point rather than making every caller assemble a claim first.
    :func:`boundary_claim` derives the claim from the report and
    :func:`require_sealed_claim` refuses it if this report's bytes are not the ones
    that were sealed — including the case where the report was *edited* after the
    seal, because the edit changes the digest the chain recorded.
    """
    claim = boundary_claim(report)
    if isinstance(claim, WithheldEvidence):
        raise InvariantViolationError(
            RULE_EVIDENCE_NOT_SEALED,
            f"the boundary report about {claim.subject!r} rests on no trial and cannot "
            f"back a decision: {claim.reason}",
        )
    return require_sealed_claim(seal, claim)


# =======================================================================================
# The AI boundary (gap 25) — compilation of an untrusted candidate
# =======================================================================================

AUTHORITY_FIELDS = frozenset(
    {"approval", "approved_by", "authority", "plan_digest", "authorization", "token"}
)
"""Keys an advisor payload may never contain, at any depth.

Checked over the top level and over each nested mapping, because the obvious
attack is a nested one: ``{"step": {...}, "approval": {...}}`` is refused at the
top level and ``{"step": {...}, "meta": {"approved_by": "sre"}}`` is refused inside
``meta``. A payload is data from an untrusted producer until compilation says
otherwise, and the first thing compilation checks is that it is not trying to *be*
an approval.
"""

_ALLOWED_CANDIDATE_FIELDS = frozenset({"step", "rationale"})


def compile_candidate(
    payload: Mapping[str, object],
    policy: SearchPolicy,
) -> SearchPlan:
    """Compile an advisor's raw candidate payload into an untrusted plan.

    ``payload`` is the *raw mapping* an advisor produced, not a trusted object — that
    is the whole reason this function exists and takes ``Mapping[str, object]``
    rather than a model. Every refusal happens here, upstream of admission, policy
    evaluation, and the runner, so a draft that fails compilation never reaches a
    gate.

    Refusals, in order:

    * an authority field at any depth (:data:`RULE_DRAFT_CARRIES_AUTHORITY`) — the
      negative control: a draft with an embedded approval token is rejected, because
      the AI may not supply its own authority;
    * an unknown top-level field (:data:`RULE_DRAFT_UNKNOWN_FIELD`);
    * a step whose budget reference is not the policy's
      (:data:`RULE_DRAFT_BUDGET_REFERENCE_MISMATCH`) — charging a candidate to an
      unrelated ledger is a wiring bug, not a candidate;
    * a step cost that disagrees with the policy's
      (:data:`RULE_DRAFT_STEP_COST_MISMATCH`);
    * a field of the wrong type, or a non-finite number at all
      (:data:`RULE_DRAFT_UNKNOWN_FIELD`) — ``nan`` is refused there, which is
      earlier and more precise than refusing it as an out-of-ladder value;
    * a value outside the policy's ladder (:data:`RULE_DRAFT_VALUE_OUT_OF_LADDER`).

    The returned plan is ``generated`` and carries no approval, because the only way
    to build one is :meth:`~mayhem.domain.search.UntrustedSearchDraft.compile` and
    that type has nowhere to put a token.
    """
    unknown = sorted(set(payload) - _ALLOWED_CANDIDATE_FIELDS)
    authority = sorted(_authority_keys(payload))
    if authority:
        raise InvariantViolationError(
            RULE_DRAFT_CARRIES_AUTHORITY,
            f"candidate payload carries authority field(s) {authority}: an AI-drafted "
            "candidate reaches exactly as far as the gates and the approval an authored "
            "one would, and it cannot supply its own. It must be reviewed as one",
        )
    if unknown:
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate payload declares unknown field(s) {unknown}; allowed fields are "
            f"{sorted(_ALLOWED_CANDIDATE_FIELDS)}",
        )
    raw_step = payload.get("step")
    if not isinstance(raw_step, Mapping):
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            "candidate payload carries no 'step' mapping to compile",
        )
    step = _compile_step(raw_step, policy)
    rationale = payload.get("rationale", "")
    if not isinstance(rationale, str):
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate rationale must be a string, got {type(rationale).__name__}",
        )
    return UntrustedSearchDraft(step=step, rationale=rationale).compile()


def _budget_reference(raw: object) -> BudgetReference:
    """Rebuild a :class:`BudgetReference` from an untrusted mapping."""
    if not isinstance(raw, Mapping):
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate budget_ref must be a mapping, got {type(raw).__name__}",
        )
    unknown = sorted(set(raw) - {"kind", "label"})
    if unknown:
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate budget_ref declares unknown field(s) {unknown}",
        )
    try:
        return BudgetReference(
            kind=BudgetKind(_exact_str(raw.get("kind"), "budget_ref.kind")),
            label=_exact_str(raw.get("label", ""), "budget_ref.label"),
        )
    except (TypeError, ValueError) as exc:
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate budget_ref could not be compiled: {exc}",
        ) from exc


def _exact_int(raw: object, field: str) -> int:
    """An int that is really an int — ``True`` is not an index."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate step field {field!r} must be an integer, got {raw!r}",
        )
    return raw


def _exact_float(raw: object, field: str) -> float:
    """A finite float. ``nan`` and ``inf`` are refused, not propagated."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate step field {field!r} must be a number, got {raw!r}",
        )
    value = float(raw)
    if not isfinite(value):
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate step field {field!r} must be finite, got {value!r}",
        )
    return value


def _exact_str(raw: object, field: str) -> str:
    if not isinstance(raw, str):
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate step field {field!r} must be a string, got {type(raw).__name__}",
        )
    return raw


def _authority_keys(payload: Mapping[str, object], prefix: str = "") -> set[str]:
    """Every authority key in a payload, at any depth."""
    found: set[str] = set()
    for key, value in payload.items():
        name = f"{prefix}{key}"
        if str(key).lower() in AUTHORITY_FIELDS:
            found.add(name)
        if isinstance(value, Mapping):
            found |= _authority_keys(value, prefix=f"{name}.")
    return found


_STEP_FIELDS = frozenset(
    {
        "index",
        "value",
        "phase",
        "combination",
        "budget_remaining",
        "budget_ref",
        "expected_cost",
    }
)


def _compile_step(raw: Mapping[str, object], policy: SearchPolicy) -> SearchStep:
    """Turn a raw step mapping into a validated :class:`SearchStep`.

    Every field is coerced explicitly rather than trusted, because the payload is
    untrusted: a missing field, a wrong type, or an unrecognised extra field is a
    refusal (:data:`RULE_DRAFT_UNKNOWN_FIELD`) rather than a default. The budget
    reference is rebuilt from its parts so the comparison below is between two
    :class:`~mayhem.domain.search.BudgetReference` values rather than between a
    model and a dictionary.
    """
    unknown = sorted(set(raw) - _STEP_FIELDS)
    missing = sorted(_STEP_FIELDS - {"budget_remaining", "expected_cost"} - set(raw))
    if unknown or missing:
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate step declares unknown field(s) {unknown} and is missing "
            f"{missing}; a step is {sorted(_STEP_FIELDS)}",
        )
    reference = _budget_reference(raw["budget_ref"])
    try:
        step = SearchStep(
            index=_exact_int(raw["index"], "index"),
            value=_exact_float(raw["value"], "value"),
            phase=SearchPhase(_exact_str(raw["phase"], "phase")),
            combination=_exact_str(raw["combination"], "combination"),
            budget_remaining=_exact_float(
                raw.get("budget_remaining", 0.0), "budget_remaining"
            ),
            budget_ref=reference,
            expected_cost=_exact_float(
                raw.get("expected_cost", policy.step_cost), "expected_cost"
            ),
        )
    except (TypeError, ValueError) as exc:
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate step could not be compiled: {exc}",
        ) from exc
    if not step.combination:
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            "candidate step names no fault/target combination: an unlabelled step "
            "cannot be counted against the combination budget",
        )
    if step.budget_ref != policy.budget_ref:
        raise InvariantViolationError(
            RULE_DRAFT_BUDGET_REFERENCE_MISMATCH,
            f"candidate step draws on {step.budget_ref.to_dict()} but the policy "
            f"{policy.name!r} draws on {policy.budget_ref.to_dict()}",
        )
    if step.expected_cost != policy.step_cost:
        raise InvariantViolationError(
            RULE_DRAFT_STEP_COST_MISMATCH,
            f"candidate step declares cost {step.expected_cost} against a policy step "
            f"cost of {policy.step_cost}: a candidate may not reprice the search",
        )
    ceiling = policy.start + policy.step * max(0, policy.max_steps - 1)
    if step.index < 0:
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"candidate step index {step.index} is negative: a step address cannot be "
            "before the first one",
        )
    if not isfinite(step.value) or not 0.0 < step.value <= ceiling:
        raise InvariantViolationError(
            RULE_DRAFT_VALUE_OUT_OF_LADDER,
            f"candidate value {step.value!r} is outside the ladder this policy can walk "
            f"({policy.start:g} .. {ceiling:g} in steps of {policy.step:g})",
        )
    return step


# =======================================================================================
# The adaptive runner
# =======================================================================================


@dataclass(frozen=True, slots=True)
class StepOutcome:
    """What one executed micro-plan showed.

    ``sufficient`` defaults to ``True`` and means the trial's measurement could be
    graded. Setting it ``False`` hands the search back to
    :func:`mayhem.domain.search.plan_next_step`, which stops with
    ``INSUFFICIENT_MEASUREMENT`` rather than re-proposing the same value — an
    unmeasurable trial must not be recorded as a clearance.
    """

    breached: bool
    sufficient: bool = True
    comparison: Comparison | None = None
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "breached": self.breached,
            "sufficient": self.sufficient,
            "comparison": None if self.comparison is None else self.comparison.to_dict(),
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class StepAdmission:
    """The admission trail for one step: approved, admitted, and what it cost.

    Every field is present whether the step ran or not, because a search that halted
    on a refusal is exactly the run whose audit trail matters most.
    ``budget_remaining`` is the runner's own running total *after* the charge, and
    ``charged`` is ``0.0`` for a step that was refused before execution — a refused
    step costs nothing and says so.
    """

    index: int
    value: float
    origin: SearchOrigin
    approved_by: str
    plan_digest: str
    admitted: bool
    charged: float
    budget_remaining: float
    stop_reason: StopReason | None = None
    rule_id: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "value": self.value,
            "origin": self.origin.value,
            "approved_by": self.approved_by,
            "plan_digest": self.plan_digest,
            "admitted": self.admitted,
            "charged": self.charged,
            "budget_remaining": self.budget_remaining,
            "stop_reason": None if self.stop_reason is None else self.stop_reason.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class BudgetDivergence:
    """The planner planned against a budget the runner was not spending.

    Phase 4's answer to Phase 2's open note. :attr:`planner_remaining` is what
    :func:`~mayhem.domain.search.plan_next_step` saw and stamped into
    :attr:`~mayhem.domain.search.SearchStep.budget_remaining`;
    :attr:`runner_remaining` is what the runner could actually pay with. They differ
    because the caller passed a ``planner_budget`` that is not the runner's running
    total — and once they differ, the runner's own per-step check is no longer
    redundant with the planner's, because the planner is answering a different
    question.

    ``stopped`` says whether the divergence is what ended the search. When it is
    ``False`` the two budgets happened to agree on every step that was taken, and
    the record exists only to say the caller asked for a planner budget at all.
    """

    step_index: int
    step_value: float
    planner_remaining: float
    runner_remaining: float
    stopped: bool
    rule_id: str = RULE_PLANNER_BUDGET_DIVERGED
    reason: str = ""

    @property
    def shortfall(self) -> float:
        """How much of the step's cost the runner could not cover, at least."""
        return max(0.0, self.planner_remaining - self.runner_remaining)

    def to_dict(self) -> dict[str, object]:
        return {
            "step_index": self.step_index,
            "step_value": self.step_value,
            "planner_remaining": self.planner_remaining,
            "runner_remaining": self.runner_remaining,
            "shortfall": self.shortfall,
            "stopped": self.stopped,
            "rule_id": self.rule_id,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class AdaptiveRun:
    """The result of walking a search policy forward.

    ``history``, ``boundary``, and ``report`` survive every stop — including
    :data:`~mayhem.domain.search.StopReason.NO_REMAINING_BUDGET` and an admission
    refusal. That is the acceptance criterion: a search that halts reports the
    boundary it established, it does not throw the findings away with the run.

    ``record`` is always present (Phase 4): a boundary search perturbs a system in
    escalating steps, so the run is a privileged action and describes itself even
    when nobody wired a recorder to it. ``recorded`` says whether a recorder actually
    took it — see :func:`record_boundary_search` for the one that writes it to the
    cross-run audit stream, and :func:`require_recorded_search` for the gate that
    refuses a search the stream cannot show.
    """

    policy_name: str
    stop: StopReason
    stop_note: str
    history: SearchHistory
    boundary: float | None
    report: BoundaryReport
    record: SearchRecord
    admissions: tuple[StepAdmission, ...] = ()
    divergence: BudgetDivergence | None = None
    budget_remaining: float = 0.0
    executed: int = 0
    recorded: bool = False

    @property
    def stopped_on_budget(self) -> bool:
        return self.stop is StopReason.NO_REMAINING_BUDGET

    @property
    def findings_preserved(self) -> bool:
        """True when a halt still carries what the search established."""
        return self.boundary is not None or self.history.steps_used > 0

    @property
    def stops_on_divergent_budget(self) -> bool:
        """The runner's own per-step check stopped this run, not the planner's."""
        return self.divergence is not None and self.divergence.stopped

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_name": self.policy_name,
            "stop": self.stop.value,
            "stop_note": self.stop_note,
            "boundary": self.boundary,
            "budget_remaining": self.budget_remaining,
            "executed": self.executed,
            "stopped_on_budget": self.stopped_on_budget,
            "stops_on_divergent_budget": self.stops_on_divergent_budget,
            "findings_preserved": self.findings_preserved,
            "recorded": self.recorded,
            "record": self.record.to_dict(),
            "divergence": None if self.divergence is None else self.divergence.to_dict(),
            "history": self.history.to_dict(),
            "report": self.report.to_dict(),
            "admissions": [admission.to_dict() for admission in self.admissions],
        }


def adaptive_run(
    policy: SearchPolicy,
    *,
    budget: SafetyBudget,
    compile_step: Callable[[SearchStep], ExecutionPlan],
    admit: Callable[[ExecutionPlan], None],
    execute: Callable[[ExecutionPlan, SearchStep], StepOutcome],
    approve: Callable[[SearchPlan], Approval | None],
    origin: SearchOrigin = SearchOrigin.AUTHORED,
    history: SearchHistory | None = None,
    combination: str = "default",
    planner_budget: SafetyBudget | None = None,
    search_record: Callable[[SearchRecord], None] | None = None,
) -> AdaptiveRun:
    """Walk ``policy`` forward as a sequence of approved, admitted, budgeted steps.

    The per-step order is the safety order and is not interchangeable: plan → approve
    → compile → admit → budget → execute → record. :func:`_walk` is where it lives
    and documents each step; this function composes the walk, builds the audit
    record, and returns the run.

    ``history`` may be supplied to resume a search walked in an earlier call; the
    boundary found so far is then carried into the report rather than rediscovered.

    ``planner_budget`` is Phase 4's deliberate API change, and the reason
    :func:`step_affordable` is live rather than decorative. **It is the budget the
    planner plans against; ``budget`` is the budget the runner spends.** By default
    they are the same value and the two checks cannot disagree. Pass a
    ``planner_budget`` and the runner is deliberately planning against a number it
    is not spending — which is exactly the situation the per-step check exists for:

    * a damage ledger drained by a concurrent step or another run, after the caller
      read its remaining allowance;
    * a resumed search handed the full original allowance while the runner carries
      only what the earlier call left;
    * a caller that wants the *policy* (how far it would search if it could) decided
      without the *ledger* (how far it may), so the report says "the ladder would
      have gone this far" and the run says "it stopped here".

    The default is deliberately the safe one: a divergence requires a caller to ask
    for it, so a run that never asked cannot quietly plan against a budget it does
    not have. A ``planner_budget`` drawn on another ledger is refused by
    :func:`~mayhem.domain.search.plan_next_step` on the first iteration — before any
    step is approved, compiled, or admitted — with the domain's own
    ``search.budget_reference_mismatch``; there is deliberately no second check here,
    for the reason :func:`_approve_step` gives about its own authority checks.

    Either way the divergence is *recorded*, not merely possible:
    :class:`~mayhem.domain.search.SearchStep` stamps ``budget_remaining`` from
    whatever the planner saw, so it lands in the sealed trial history, and
    :attr:`AdaptiveRun.divergence` names both numbers and the step they disagreed on.

    ``search_record`` is handed the run's :class:`SearchRecord` exactly once, on
    every path including a refusal, and its return value is ignored. Wire
    :func:`record_boundary_search` to it to put the search in the cross-run audit
    stream. An exception from the recorder **propagates** rather than being
    swallowed: a search nobody can find afterwards is not a result, and the same
    reasoning :func:`mayhem.infra.audit_stream.seal_run_evidence_at_run_close` gives
    for a seal whose audit entry could not be written. The run is on
    :attr:`AdaptiveRun.record` either way, so a caller that prefers to record it
    afterwards can.
    """
    walked = _walk(
        policy,
        budget=budget,
        planner_budget=planner_budget,
        history=history,
        combination=combination,
        origin=origin,
        compile_step=compile_step,
        admit=admit,
        execute=execute,
        approve=approve,
    )
    record = search_record_of(
        policy,
        history=walked.history,
        admissions=walked.admissions,
        stop=walked.stop,
        stop_note=walked.stop_note,
        budget_remaining=walked.remaining.remaining,
        origin=origin,
        divergence=walked.divergence,
    )
    if search_record is not None:
        search_record(record)
    return AdaptiveRun(
        policy_name=policy.name,
        stop=walked.stop,
        stop_note=walked.stop_note,
        history=walked.history,
        boundary=walked.history.boundary,
        report=boundary_report(policy, walked.history),
        record=record,
        admissions=tuple(walked.admissions),
        divergence=walked.divergence,
        budget_remaining=walked.remaining.remaining,
        executed=sum(1 for admission in walked.admissions if admission.admitted),
        recorded=search_record is not None,
    )


@dataclass(slots=True)
class _Walk:
    """The mutable state of one walk, so the loop and its caller can share it.

    A plain mutable holder rather than a return tuple: six values come back out of
    the loop and three of them are read again by the caller, and unpacking seven
    positional values at every return path is how a field silently gets crossed.
    """

    history: SearchHistory
    remaining: SafetyBudget
    admissions: list[StepAdmission] = field(default_factory=list)
    divergence: BudgetDivergence | None = None
    stop: StopReason = StopReason.LADDER_EXHAUSTED
    stop_note: str = ""
    exhausted_guard: bool = False


def _walk(
    policy: SearchPolicy,
    *,
    budget: SafetyBudget,
    compile_step: Callable[[SearchStep], ExecutionPlan],
    admit: Callable[[ExecutionPlan], None],
    execute: Callable[[ExecutionPlan, SearchStep], StepOutcome],
    approve: Callable[[SearchPlan], Approval | None],
    origin: SearchOrigin,
    history: SearchHistory | None,
    combination: str,
    planner_budget: SafetyBudget | None,
) -> _Walk:
    """The search loop itself, in the safety order, stopping at the first refusal.

    One iteration, in this order and no other:

    1. **Plan.** :func:`~mayhem.domain.search.plan_next_step` — pure, and the first
       thing that can stop the search (combinations spent, no budget, unmeasurable
       last trial, steps exhausted, bracket resolved). It is handed ``planner_budget``
       when the caller supplied one, and the runner's running total otherwise.
    2. **Approve.** ``approve`` is asked for a token bound to *this* plan's digest.
       ``None`` stops the walk with :data:`RULE_STEP_NOT_APPROVED`, and a
       ``generated`` plan cannot produce a token at all, because
       :class:`~mayhem.domain.search.SearchPlan` refuses to be constructed with an
       approval on a generated origin. This is before compilation on purpose: a
       step refused for want of an approval should not cost a compile.
    3. **Compile.** ``compile_step`` turns the abstract step into a frozen
       :class:`~mayhem.domain.experiments.ExecutionPlan`.
    4. **Admit.** ``admit`` is the real gate — ``validate_plan`` in production — and
       a refusal stops the walk with the rule id it refused on.
    5. **Budget.** :func:`step_affordable` re-checks the runner's own running budget
       before charging. With no ``planner_budget`` this is redundant with step 1 by
       construction; with one it is the only line of defence, because the planner is
       answering about a different number. A refusal stops with
       ``NO_REMAINING_BUDGET``, keeps the findings, and is recorded as
       :data:`RULE_PLANNER_BUDGET_DIVERGED` rather than the plain
       :data:`RULE_STEP_UNAFFORDABLE` — the two are different failures and an
       operator reading the admission record has to be able to tell them apart.
    6. **Execute and record.** The outcome becomes a :class:`Trial`, and the budget is
       charged.

    A ``guard``-length ``for``/``else`` bounds the loop: a search that neither
    proceeds nor stops would otherwise hang, and ``exhausted_guard`` says the guard
    is what ended it rather than the policy.
    """
    walked = _Walk(
        history=SearchHistory() if history is None else history,
        remaining=budget,
    )
    admissions = walked.admissions
    guard = policy.max_steps * 4 + 8
    for _ in range(guard):
        planned_against = (
            walked.remaining if planner_budget is None else planner_budget
        )
        decision: SearchDecision = plan_next_step(
            policy, walked.history, budget=planned_against, combination=combination
        )
        if not decision.proceed:
            walked.stop = decision.stop if decision.stop is not None else StopReason.MAX_STEPS
            walked.stop_note = decision.note
            break
        step = decision.step
        if step is None:  # unreachable while `proceed` holds; tested rather than asserted
            walked.stop = StopReason.MAX_STEPS
            walked.stop_note = "the planner returned a proceeding decision with no step"
            break
        approval = _approve_step(approve, step, origin=origin)
        if isinstance(approval, str):
            admissions.append(
                _refused(
                    step,
                    origin=origin,
                    approved_by="",
                    plan_digest="",
                    remaining=walked.remaining,
                    rule_id=RULE_STEP_NOT_APPROVED,
                    reason=approval,
                )
            )
            walked.stop = StopReason.NO_FURTHER_VALUE
            walked.stop_note = approval
            break
        plan = approval
        micro_plan = compile_step(step)
        try:
            admit(micro_plan)
        except InvariantViolationError as exc:
            admissions.append(
                _refused(
                    step,
                    origin=plan.origin,
                    approved_by=_approver_of(plan),
                    plan_digest=plan.plan_digest,
                    remaining=walked.remaining,
                    rule_id=str(getattr(exc, "rule", RULE_ADMISSION_REFUSED)),
                    reason=str(exc),
                )
            )
            walked.stop = StopReason.NO_FURTHER_VALUE
            walked.stop_note = (
                f"admission refused the micro-plan for step {step.index} at value "
                f"{step.value:g}: {exc}"
            )
            break
        unaffordable = step_affordable(walked.remaining, step)
        if unaffordable:
            walked.divergence = _divergence(
                step, remaining=walked.remaining, reason=unaffordable, stopped=True
            )
            admissions.append(
                _refused(
                    step,
                    origin=plan.origin,
                    approved_by=_approver_of(plan),
                    plan_digest=plan.plan_digest,
                    remaining=walked.remaining,
                    rule_id=(
                        RULE_STEP_UNAFFORDABLE
                        if walked.divergence is None
                        else RULE_PLANNER_BUDGET_DIVERGED
                    ),
                    reason=unaffordable,
                    stop_reason=StopReason.NO_REMAINING_BUDGET,
                )
            )
            walked.stop = StopReason.NO_REMAINING_BUDGET
            walked.stop_note = _unaffordable_note(step, walked.divergence)
            break
        if walked.divergence is None:
            # Recorded even when it costs nothing this time: a caller that asked for
            # a planner budget should be able to see from the run that it did.
            walked.divergence = _divergence(
                step,
                remaining=walked.remaining,
                reason=(
                    f"the planner planned step {step.index} against "
                    f"{step.budget_remaining} of {step.budget_ref.kind.value} while the "
                    f"runner had {walked.remaining.remaining} to spend"
                ),
                stopped=False,
            )
        charged = walked.remaining.charge(step.expected_cost)
        outcome = execute(micro_plan, step)
        admissions.append(
            StepAdmission(
                index=step.index,
                value=step.value,
                origin=plan.origin,
                approved_by=_approver_of(plan),
                plan_digest=plan.plan_digest,
                admitted=True,
                charged=step.expected_cost,
                budget_remaining=charged.remaining,
            )
        )
        walked.history = walked.history.record(
            step, breached=outcome.breached, sufficient=outcome.sufficient
        )
        walked.remaining = charged
    else:
        walked.stop = StopReason.MAX_STEPS
        walked.stop_note = (
            f"the runner hit its own guard after {guard} iterations without the search "
            "reporting a stop"
        )
        walked.exhausted_guard = True
    return walked


def _divergence(
    step: SearchStep,
    *,
    remaining: SafetyBudget,
    reason: str,
    stopped: bool,
) -> BudgetDivergence | None:
    """The divergence record for this step, or ``None`` when there is none.

    ``None`` in the ordinary wiring, and that is the point: with no
    ``planner_budget`` the planner and the runner read the same number, so the
    runner's second check is unreachable and there is nothing to record. Returning
    ``None`` rather than a zero record keeps "no divergence" and "a divergence of
    zero" from being the same value in :attr:`AdaptiveRun.divergence`.
    """
    if step.budget_remaining == remaining.remaining:
        return None
    return BudgetDivergence(
        step_index=step.index,
        step_value=step.value,
        planner_remaining=step.budget_remaining,
        runner_remaining=remaining.remaining,
        stopped=stopped,
        reason=reason,
    )


def _refused(
    step: SearchStep,
    *,
    origin: SearchOrigin,
    approved_by: str,
    plan_digest: str,
    remaining: SafetyBudget,
    rule_id: str,
    reason: str,
    stop_reason: StopReason | None = None,
) -> StepAdmission:
    """The admission record for a step that did not run.

    One constructor for every refusal in the loop, so a refused step always costs
    ``0.0``, always carries the runner's *own* ``budget_remaining`` (not the
    planner's reading of it), and always names the rule it was refused on. A search
    that halted on a refusal is exactly the run whose audit trail matters most, and
    four hand-written literals are four chances for one of them to forget a field.
    """
    return StepAdmission(
        index=step.index,
        value=step.value,
        origin=origin,
        approved_by=approved_by,
        plan_digest=plan_digest,
        admitted=False,
        charged=0.0,
        budget_remaining=remaining.remaining,
        stop_reason=stop_reason,
        rule_id=rule_id,
        reason=reason,
    )


def _unaffordable_note(
    step: SearchStep, divergence: BudgetDivergence | None
) -> str:
    """The stop note for a step the runner could not pay for.

    Names the two budgets when they disagreed, because "the remaining budget no
    longer covers a step" is a different story from "the planner thought 100 was
    left and the runner had 0.5" and an operator needs to know which one happened.
    """
    if divergence is None:
        return (
            "the remaining budget no longer covers a step; search halts with the "
            "findings so far"
        )
    return (
        f"the remaining budget no longer covers a step; the planner was working from "
        f"{divergence.planner_remaining} of {step.budget_ref.kind.value} and the runner "
        f"had {divergence.runner_remaining} to spend ({RULE_PLANNER_BUDGET_DIVERGED}); "
        "search halts with the findings so far"
    )


def step_affordable(budget: SafetyBudget, step: SearchStep) -> str:
    """Why this step cannot be charged, or ``""`` when it can.

    The runner's own per-step budget check, as a pure predicate. **The runner never
    charges a step this says it cannot pay for, whatever the planner decided.**

    In the ordinary wiring it is redundant with
    :func:`~mayhem.domain.search.plan_next_step` by construction: the runner hands
    the planner its running budget, so the planner refuses first and the two can
    never disagree. It is reachable when ``adaptive_run`` is given a
    ``planner_budget`` different from the budget it spends — a ledger drained by a
    concurrent step, a resumed search carrying less than the caller declared, a
    caller separating "how far the policy would search" from "how far it may" — and
    a runner that trusted the planner there would execute a step it cannot pay for.
    :attr:`AdaptiveRun.divergence` is the record of that case, and the refusal it
    carries is why this check is live rather than decorative.

    Returns the refusal message rather than a boolean so the stop note names the
    numbers the decision was made on, and the admission record carries it.
    """
    if budget.allows(step.expected_cost):
        return ""
    return (
        f"runner budget has {budget.remaining} of {budget.reference.kind.value} left, "
        f"which does not cover a step costing {step.expected_cost}: search halts with "
        "the findings so far"
    )


def _approver_of(plan: SearchPlan) -> str:
    """Who approved this plan, or ``""`` when nothing did."""
    return "" if plan.approval is None else plan.approval.approved_by


def _approve_step(
    approve: Callable[[SearchPlan], Approval | None],
    step: SearchStep,
    *,
    origin: SearchOrigin,
) -> SearchPlan | str:
    """The approved plan for one step, or the reason there is not one.

    The plan handed to ``approve`` carries no approval, so the approver binds to the
    digest of the step it actually read — and the returned plan is rebuilt *with*
    that token, which is where the AI boundary bites. A ``generated`` origin cannot
    produce an approved plan at all: constructing a ``generated``
    :class:`~mayhem.domain.search.SearchPlan` *with* an approval raises
    :data:`~mayhem.domain.search.RULE_GENERATED_CANNOT_BE_APPROVED`, and a token that
    does not match the plan digest raises
    :data:`~mayhem.domain.search.RULE_APPROVAL_MISMATCH`. Both are returned as a
    reason rather than raised, so the run stops with a trail instead of a
    traceback.

    There is no separate authority check here, and there should not be: the two
    constructor refusals above are exhaustive. A plan that carries a valid token has
    ``authority is APPROVED`` by the definition of
    :attr:`~mayhem.domain.search.SearchPlan.authority`, so a second predicate over it
    would be unreachable code standing in for a guarantee the type already makes.
    :attr:`SearchPlan.authority` is what the admission record reads — through
    :func:`_approver_of` — and it reads the approval, not a flag somebody could set.
    """
    candidate = SearchPlan(step=step, origin=origin)
    try:
        token = approve(candidate)
    except InvariantViolationError as exc:
        return f"step {step.index} at value {step.value:g} cannot be approved: {exc}"
    if token is None:
        return (
            f"step {step.index} at value {step.value:g} has no approval token: an "
            "unapproved micro-plan is not executed, whatever the search would have "
            "liked to do next"
        )
    try:
        approved = SearchPlan(step=step, origin=origin, approval=token)
    except InvariantViolationError as exc:
        return (
            f"step {step.index} at value {step.value:g} was offered an approval that "
            f"does not bind to it: {exc}"
        )
    return approved


# =======================================================================================
# The search as a privileged action (Phase 4) — the audit record
# =======================================================================================


def search_policy_digest(policy: SearchPolicy) -> str:
    """The digest an approval or an audit entry binds a search policy by.

    Over :meth:`SearchPolicy.to_dict`, the policy's own canonical form — so the same
    policy always hashes to the same value and any change to the ladder, the budget
    reference, the step cost, or the resolution changes it. This is the one place a
    search policy is named by digest; :func:`record_boundary_search` puts it in the
    stream's ``policy_digest`` column and an approval may name it as the artifact it
    authorised.
    """
    return digest(policy.to_dict())


@dataclass(frozen=True, slots=True)
class SearchStepTrace:
    """One rung of the ladder, as the audit stream records it.

    ``planned_against`` is the *planner's* reading of the budget at that moment, not
    the runner's, because it is the number the step was decided on. Keeping the two
    distinguishable here is what lets a later reader tell an ordinary ladder from one
    that was walked against a budget the runner did not have.
    """

    index: int
    value: float
    phase: SearchPhase
    combination: str
    breached: bool
    sufficient: bool
    charged: float
    approved_by: str
    planned_against: float
    admitted: bool
    rule_id: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "value": self.value,
            "phase": self.phase.value,
            "combination": self.combination,
            "breached": self.breached,
            "sufficient": self.sufficient,
            "charged": self.charged,
            "approved_by": self.approved_by,
            "planned_against": self.planned_against,
            "admitted": self.admitted,
            "rule_id": self.rule_id,
        }


@dataclass(frozen=True, slots=True)
class SearchRecord:
    """One boundary search, as the thing an operator can later read back.

    A resilience-boundary search perturbs a system in escalating steps until it finds
    where the system stops tolerating anything. That is a privileged act with a
    budget attached, so it is recorded in the cross-run audit stream that already
    exists — not in a log of this module's own.

    What it deliberately does **not** carry is any authority. There is no field an
    approval could travel in: ``approved_by`` names who signed the individual steps
    that were admitted (it is a read-back of
    :attr:`StepAdmission.approved_by``, which is itself derived from a token that
    bound to a plan digest), and it grants nothing. A ``generated`` origin is
    recorded as ``generated``, so a search whose candidates came from an advisor is
    visible as one in the stream — the AI boundary is unchanged by being logged.
    """

    policy_name: str
    policy_digest: str
    run_id: str
    origin: SearchOrigin
    strategy: str
    ladder: tuple[SearchStepTrace, ...]
    boundary: float | None
    bracket_low: float
    stop: StopReason
    stop_note: str
    budget_remaining: float
    executed: int
    divergence: BudgetDivergence | None = None

    @property
    def approved_by(self) -> tuple[str, ...]:
        """Every distinct approver whose token admitted a step, in order."""
        return tuple(
            dict.fromkeys(
                trace.approved_by for trace in self.ladder if trace.admitted and trace.approved_by
            )
        )

    @property
    def perturbations(self) -> tuple[float, ...]:
        """The impairment values actually charged — what the system was asked to absorb."""
        return tuple(trace.value for trace in self.ladder if trace.admitted)

    @property
    def decision_digest(self) -> str:
        """The digest of this record's own bytes.

        The identity :func:`record_boundary_search` writes into the stream's
        ``decision_digest`` and :func:`require_recorded_search` looks for, so a
        search cannot be shown to be recorded by pointing at a *different* search's
        entry. Taken over :meth:`payload` — not over :meth:`to_dict`, which includes
        this digest — for the reason :class:`~mayhem.domain.attestation.AttestedEvent`
        takes its digest over its *other* fields.
        """
        return digest(self.payload())

    def payload(self) -> dict[str, object]:
        """The attested body. Names, digests, and the ladder — never a copy of a plan."""
        return {
            "policy_name": self.policy_name,
            "policy_digest": self.policy_digest,
            "run_id": self.run_id,
            "origin": self.origin.value,
            "strategy": self.strategy,
            "boundary": self.boundary,
            "bracket_low": self.bracket_low,
            "stop": self.stop.value,
            "stop_note": self.stop_note,
            "budget_remaining": self.budget_remaining,
            "executed": self.executed,
            "approved_by": list(self.approved_by),
            "ladder": [trace.to_dict() for trace in self.ladder],
            "divergence": None if self.divergence is None else self.divergence.to_dict(),
        }

    def to_dict(self) -> dict[str, object]:
        payload = self.payload()
        payload["decision_digest"] = self.decision_digest
        return payload


def search_record_of(
    policy: SearchPolicy,
    *,
    history: SearchHistory,
    admissions: Sequence[StepAdmission],
    stop: StopReason,
    stop_note: str,
    budget_remaining: float,
    origin: SearchOrigin = SearchOrigin.AUTHORED,
    divergence: BudgetDivergence | None = None,
    run_id: str = "",
) -> SearchRecord:
    """Build the audit record for one walked search (pure).

    Every trial contributes a rung, and every admission record is matched onto it by
    index — so a rung records both *what was tried* (the trial) and *who allowed it*
    (the admission), and a step that was refused before execution still appears with
    its ``rule_id`` and ``admitted: false``. A ladder that hides its refusals is not
    the record of a search that perturbs a system.

    ``run_id`` is empty when the caller has not told the runner which run this
    belongs to; :func:`record_boundary_search` requires one, because an audit entry
    whose subject is unnamed cannot answer "what was done to this run".
    """
    by_index = {admission.index: admission for admission in admissions}
    ladder = tuple(
        SearchStepTrace(
            index=trial.step.index,
            value=trial.step.value,
            phase=trial.step.phase,
            combination=trial.step.combination,
            breached=trial.breached,
            sufficient=trial.sufficient,
            charged=(
                by_index[trial.step.index].charged
                if trial.step.index in by_index
                else trial.step.expected_cost
            ),
            approved_by=(
                by_index[trial.step.index].approved_by if trial.step.index in by_index else ""
            ),
            planned_against=trial.step.budget_remaining,
            admitted=bool(
                trial.step.index in by_index and by_index[trial.step.index].admitted
            ),
            rule_id=by_index[trial.step.index].rule_id if trial.step.index in by_index else "",
        )
        for trial in history.trials
    )
    return SearchRecord(
        policy_name=policy.name,
        policy_digest=search_policy_digest(policy),
        run_id=run_id,
        origin=origin,
        strategy=policy.strategy.value,
        ladder=ladder,
        boundary=history.boundary,
        bracket_low=history.bracket_low,
        stop=stop,
        stop_note=stop_note,
        budget_remaining=budget_remaining,
        executed=sum(1 for trace in ladder if trace.admitted),
        divergence=divergence,
    )


def record_boundary_search(
    audit: AuditStream,
    record: SearchRecord,
    *,
    principal: str,
    run_id: str = "",
    approval_digest: str = "",
    detail: Mapping[str, object] | None = None,
    recorded_at: AttestedTimestamp | None = None,
) -> AttestedEvent:
    """Append one boundary search to the cross-run audit stream.

    The one call that makes an adaptive run findable. A resilience-boundary search is
    a privileged action with a budget attached, so it goes into
    :mod:`mayhem.infra.audit_stream` — the append-only, integrity-chained, cross-run
    log this repository already has — under
    :data:`KIND_RESILIENCE_BOUNDARY_SEARCHED`. There is no second logger here and no
    search-specific table: the entry is a
    :class:`~mayhem.infra.audit_stream.AuditEntry`, verified by the same
    :func:`~mayhem.domain.attestation.verify_chain` as every other entry.

    What the entry carries, and why each is there:

    * ``principal`` — who ran the search. A *recorded claim*, not an authenticated
      identity: nothing in this repository signs, and the audit module says so in its
      own docstring.
    * ``policy_digest`` — :func:`search_policy_digest`, so the entry names the ladder,
      the budget reference, and the step cost that were authorised rather than
      asserting "a search happened".
    * ``approval_digest`` — the artifact that authorised it, when the caller has one
      (the approvals are also readable per rung from ``ladder[*].approved_by``).
    * ``decision_digest`` — :attr:`SearchRecord.decision_digest` over the run's own
      bytes, which is what :func:`require_recorded_search` matches on.
    * ``detail`` — the escalating ladder: what impairment was applied at each step,
      whether it breached, and whether it was admitted. A boundary search that
      perturbed a system in twenty steps and left no record of the nineteen that
      cleared is not auditable, and the ladder is the whole point of the action.

    Args:
        audit: The stream to append to.
        record: The run's record, from :attr:`AdaptiveRun.record`.
        principal: Who is running the search.
        run_id: The run this search belongs to. Required in practice — an entry with
            no subject cannot answer "what was done to this run" — and it defaults to
            ``record.run_id`` so a caller who passed it to ``adaptive_run`` does not
            repeat it.
        approval_digest: Digest of whatever authorized the search, if anything.
        detail: Caller-supplied extras, merged under ``detail.search``.
        recorded_at: The reading to stamp the entry with (tests inject one).

    Returns:
        The sealed :class:`~mayhem.domain.attestation.AttestedEvent` that was
        appended.

    Raises:
        InvariantViolationError: If no run id is available. A boundary search with no
            named subject is refused rather than recorded unattributed.
        AuditStreamAppendError: If the append was refused. The stream is unchanged,
            and the error propagates so the caller is never told a search was
            recorded when it was not.
    """
    subject = run_id or record.run_id
    if not subject.strip():
        raise InvariantViolationError(
            RULE_SEARCH_NOT_RECORDED,
            "recording a boundary search needs the run it perturbed: an audit entry "
            "with no subject cannot answer what was done to a run",
        )
    payload: dict[str, object] = {
        "search": record.payload(),
        "perturbations": list(record.perturbations),
    }
    if detail:
        payload.update(dict(detail))
    return audit.record(
        AuditEntry(
            principal=principal,
            action=KIND_RESILIENCE_BOUNDARY_SEARCHED,
            target=f"{subject}:{record.policy_name}",
            subject_run_id=subject,
            policy_digest=record.policy_digest,
            approval_digest=approval_digest,
            decision_digest=record.decision_digest,
            detail=payload,
        ),
        recorded_at=recorded_at,
    )


def require_recorded_search(audit: AuditStream, record: SearchRecord) -> str:
    """This search's decision digest, if the audit stream holds its entry.

    The fail-closed counterpart of :func:`record_boundary_search`: a search that
    perturbed a system and left no entry behind is refused
    (:data:`RULE_SEARCH_NOT_RECORDED`). Matching is on
    :attr:`SearchRecord.decision_digest` — the run's own bytes — rather than on a
    policy name or a run id, so a different search under the same policy does not
    stand in for this one.

    The stream is **not** re-verified here. This gate answers "is the entry there",
    which is the question a decision path has; :meth:`AuditStream.verify` answers
    "do the stored bytes still hash and link", and an operator runs that on the
    stream. Re-verifying an append-only log on every lookup would make this a second
    verification path with its own rules, which is the duplication the audit module
    exists to avoid.
    """
    for entry in audit.load():
        if entry.event_kind != KIND_RESILIENCE_BOUNDARY_SEARCHED:
            continue
        if str(entry.payload.get("decision_digest", "")) == record.decision_digest:
            return record.decision_digest
    raise InvariantViolationError(
        RULE_SEARCH_NOT_RECORDED,
        f"the boundary search {record.policy_name!r} on run {record.run_id or '(unnamed)'!r} "
        "is not in the audit stream: a search that perturbs a system in escalating steps "
        "has to be recorded before anything it found can be acted on",
    )


# =======================================================================================
# Progressive delivery (gaps 90, 91)
# =======================================================================================

CANARY_LADDER: tuple[float, ...] = (5.0, 10.0, 25.0, 50.0)
"""The percentages a canary ladder walks, after the single-target stage.

Plan 15's ``single target → 5% → 10% → 25% → 50%``. Percentages are computed with
:func:`math.ceil` against the experiment's own target count and never exceed it, so
a four-target experiment gets 1/1/1/2 rather than fractions of a target that does
not exist.
"""


def stage_ladder(target_count: int, ladder: Sequence[float] = CANARY_LADDER) -> tuple[int, ...]:
    """Target counts for each rung: the single-target stage, then one per share.

    ``(1, 1, 1, 2, 2)`` for four targets — one single-target stage followed by four
    canary stages. Refuses an empty target set (:data:`RULE_NO_TARGETS`) because a
    canary over nothing would promote on the strength of no evidence, and refuses a
    ladder that narrows (:data:`RULE_LADDER_NOT_INCREASING`).
    """
    if target_count < 1:
        raise InvariantViolationError(
            RULE_NO_TARGETS,
            f"a progressive ladder needs at least one target, got {target_count}",
        )
    counts = [1]
    for share in ladder:
        width = min(target_count, max(1, ceil(share / 100.0 * target_count)))
        counts.append(width)
    for previous, current in pairwise(counts):
        if current < previous:
            raise InvariantViolationError(
                RULE_LADDER_NOT_INCREASING,
                f"stage ladder must not narrow: {previous} targets followed by {current}",
            )
    return tuple(counts)


@dataclass(frozen=True, slots=True)
class Stage:
    """One rung of the ladder, compiled from one experiment.

    ``experiment_digest`` is the identity of the single
    :class:`~mayhem.domain.experiments.ExecutionPlan` every stage was compiled from,
    and ``plan`` is this stage's own frozen plan with its targets narrowed to the
    rung's width. The stage therefore *is* a plan-level construct of that
    experiment: two stages cannot be silently swapped for stages of a different
    experiment without the digest changing, and every stage can be admitted by the
    same gate that admits the whole plan.
    """

    index: int
    name: str
    share_pct: float | None
    targets: tuple[str, ...]
    slo_criteria: tuple[SloCriterion, ...]
    plan: ExecutionPlan
    experiment_digest: str

    def __post_init__(self) -> None:
        if not self.targets:
            raise InvariantViolationError(
                RULE_NO_TARGETS,
                f"stage {self.name!r} narrows to no targets: a stage with nothing to "
                "fault cannot produce evidence and must not be promoted through",
            )
        if not self.slo_criteria:
            raise InvariantViolationError(
                RULE_STAGE_NO_CRITERIA,
                f"stage {self.name!r} declares no SLO criteria: a stage that gates on "
                "nothing promotes unconditionally, which is a canary with no canary in it",
            )

    @property
    def single_target(self) -> bool:
        return self.share_pct is None

    @property
    def plan_digest(self) -> str:
        """Identity of this stage's plan.

        Content-addressed, so two stages that narrow to the same targets — which a
        small experiment does, since ``ceil(5% of 4)`` and ``ceil(10% of 4)`` are
        both one node — legitimately share a plan. :attr:`stage_digest` is the
        stage's own identity, which does not.
        """
        return plan_identity(self.plan)

    @property
    def stage_digest(self) -> str:
        """Identity of *this rung*: its name, share, width, and plan.

        Distinct across every stage of a ladder even when two rungs narrow to the
        same nodes, so an approval or an evidence citation may bind to a stage
        rather than to whichever stage happened to compile that plan first.
        """
        return digest(
            {
                "index": self.index,
                "name": self.name,
                "share_pct": self.share_pct,
                "targets": list(self.targets),
                "slo_criteria": [criterion.to_dict() for criterion in self.slo_criteria],
                "plan": self.plan_digest,
                "experiment": self.experiment_digest,
            }
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "name": self.name,
            "share_pct": self.share_pct,
            "targets": list(self.targets),
            "slo_criteria": [c.to_dict() for c in self.slo_criteria],
            "plan_digest": self.plan_digest,
            "stage_digest": self.stage_digest,
            "experiment_digest": self.experiment_digest,
            "single_target": self.single_target,
        }


def compile_stages(
    experiment: ExecutionPlan,
    criteria: Sequence[SloCriterion] | None = None,
    *,
    ladder: Sequence[float] = CANARY_LADDER,
    name: str = "canary",
) -> tuple[Stage, ...]:
    """Compile one experiment into its progressive stages.

    The target set is read from the experiment's own fault steps — the nodes the plan
    already resolved — and each stage takes the first ``n`` of them in sorted order,
    so the ladder is reproducible from the plan alone. Every stage carries the same
    ``criteria``; pass ``None`` and every stage declares none, which :class:`Stage`
    refuses, because a gate nobody declared is a gate that always passes.

    The first stage is the single-target stage (``share_pct is None``) and the rest
    follow ``ladder``. :func:`stage_ladder` refuses a ladder that narrows.
    """
    gates = tuple(criteria or ())
    targets = sorted(
        {
            node_id
            for step in experiment.steps
            if step.fault is not None
            for resolved in step.fault.targets
            for node_id in resolved.node_ids
        }
    )
    if not targets:
        raise InvariantViolationError(
            RULE_NO_TARGETS,
            f"experiment {experiment.run_id!r} resolves no fault targets, so it has no "
            "progressive ladder to compile",
        )
    counts = stage_ladder(len(targets), ladder)
    shares: list[float | None] = [None, *ladder]
    digest_of_experiment = plan_identity(experiment)
    stages: list[Stage] = []
    for index, (count, share) in enumerate(zip(counts, shares, strict=True)):
        stage_name = "single" if share is None else f"{name}-{share:g}"
        stages.append(
            Stage(
                index=index,
                name=stage_name,
                share_pct=share,
                targets=tuple(targets[:count]),
                slo_criteria=gates,
                plan=_narrow_plan(experiment, targets[:count]),
                experiment_digest=digest_of_experiment,
            )
        )
    return tuple(stages)


def _narrow_plan(experiment: ExecutionPlan, targets: Sequence[str]) -> ExecutionPlan:
    """The same experiment with every fault step narrowed to ``targets``.

    Fault steps whose resolved targets fall entirely outside the stage's width are
    dropped, and the remaining steps keep their ids, sequences, compensation
    contract, and stop policy. What changes is only *which nodes this stage
    touches*, which is the entire difference between the 5% stage and the 25% stage.
    """
    keep = frozenset(targets)
    steps = []
    for step in experiment.steps:
        if step.fault is None:
            steps.append(step)
            continue
        narrowed = tuple(
            resolved.model_copy(update={"node_ids": resolved.node_ids & keep})
            for resolved in step.fault.targets
            if resolved.node_ids & keep
        )
        if not narrowed:
            continue
        steps.append(
            step.model_copy(
                update={"fault": step.fault.model_copy(update={"targets": narrowed})}
            )
        )
    return experiment.model_copy(update={"steps": tuple(steps)})


@dataclass(frozen=True, slots=True)
class StageOutcome:
    """What one stage's SLO criteria said.

    ``healthy`` is true only when **every** declared criterion was evaluated and
    passed. A criterion with no observation evaluates as failed — the same refusal
    :meth:`mayhem.domain.observations.SloCriterion.evaluate` makes for an
    unavailable measurement — so "we could not see it" never promotes a canary.
    """

    stage: Stage
    outcomes: tuple[CriterionOutcome, ...] = ()
    note: str = ""

    @property
    def healthy(self) -> bool:
        return bool(self.outcomes) and all(outcome.passed for outcome in self.outcomes)

    @property
    def breaches(self) -> tuple[CriterionOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if not outcome.passed)

    @property
    def evaluated(self) -> tuple[str, ...]:
        return tuple(outcome.criterion_id for outcome in self.outcomes)

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage.to_dict(),
            "healthy": self.healthy,
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
            "breaches": [outcome.to_dict() for outcome in self.breaches],
            "note": self.note,
        }


def evaluate_stage(
    stage: Stage,
    observations: Mapping[str, ObservationResult],
) -> StageOutcome:
    """Grade one stage against its own declared criteria.

    Every declared criterion produces an outcome, including one with no observation:
    :meth:`~mayhem.domain.observations.SloCriterion.evaluate` fails an unavailable
    measurement loudly rather than passing it by accident. The resulting
    :class:`StageOutcome` is therefore never "healthy" by omission.
    """
    outcomes = tuple(
        criterion.evaluate(observations[criterion.metric])
        if criterion.metric in observations
        else criterion.evaluate(_missing(criterion))
        for criterion in stage.slo_criteria
    )
    note = ""
    if not any(criterion.metric in observations for criterion in stage.slo_criteria):
        note = (
            "no observation was supplied for any of this stage's criteria: an unobserved "
            "stage is not a healthy stage"
        )
    return StageOutcome(stage=stage, outcomes=outcomes, note=note)


def _missing(criterion: SloCriterion) -> ObservationResult:
    """An unavailable observation for a criterion nothing measured."""
    return ObservationResult(
        metric=criterion.metric,
        value=None,
        unit=criterion.unit,
        window_s=criterion.window_s,
        status=ObservationStatus.MISSING,
        detail=f"stage criterion {criterion.criterion_id!r} produced no observation for "
        f"{criterion.metric!r}",
    )


@dataclass(frozen=True, slots=True)
class Promotion:
    """The decision to advance the ladder, or the reason it stopped.

    ``promoted`` and ``stopped`` are mutually exclusive by construction, and a
    promotion always names the stage it is promoting *to* — a healthy last stage has
    nothing to promote to and is reported as a completion, not as a promotion into
    nowhere.
    """

    outcome: StageOutcome
    promoted: bool
    stopped: bool
    next_stage: Stage | None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.promoted and self.stopped:
            raise InvariantViolationError(
                RULE_STAGE_NOT_HEALTHY,
                "a stage decision is either a promotion or a stop",
            )
        if self.promoted and self.next_stage is None:
            raise InvariantViolationError(
                RULE_STAGE_NOT_HEALTHY,
                "a promotion must name the stage it promotes to",
            )
        if self.stopped and self.next_stage is not None:
            raise InvariantViolationError(
                RULE_STAGE_NOT_HEALTHY,
                "a stopped ladder has no next stage: naming one would imply the experiment "
                "continued after a breach",
            )

    @property
    def complete(self) -> bool:
        """The ladder finished healthy — neither a promotion nor a stop."""
        return self.outcome.healthy and not self.promoted and not self.stopped

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.to_dict(),
            "promoted": self.promoted,
            "stopped": self.stopped,
            "complete": self.complete,
            "next_stage": None if self.next_stage is None else self.next_stage.to_dict(),
            "reason": self.reason,
        }


def promote_to(stages: Sequence[Stage], outcome: StageOutcome) -> Promotion:
    """Advance or stop, based on one stage's health.

    Three outcomes, never two:

    * unhealthy — :attr:`Promotion.stopped`, naming every failing criterion. An
      automatic stop on breach, and one that happens before the next stage is even
      named;
    * healthy with a stage to advance to — :attr:`Promotion.promoted`;
    * healthy at the top of the ladder — :attr:`Promotion.complete`, which is neither
      a promotion nor a stop: the experiment finished its ladder.
    """
    index = outcome.stage.index
    following = stages[index + 1] if index + 1 < len(stages) else None
    if not outcome.healthy:
        breaches = outcome.breaches
        named = (
            ", ".join(
                f"{breach.criterion_id} ({breach.reason or 'failed'})" for breach in breaches
            )
            or "no criterion was evaluated"
        )
        return Promotion(
            outcome=outcome,
            promoted=False,
            stopped=True,
            next_stage=None,
            reason=(
                f"stage {outcome.stage.name!r} is not healthy, so the ladder stops here: "
                f"{named}"
            ),
        )
    if following is None:
        return Promotion(
            outcome=outcome,
            promoted=False,
            stopped=False,
            next_stage=None,
            reason=(
                f"stage {outcome.stage.name!r} is healthy and is the top of the ladder: the "
                "experiment finished without a breach"
            ),
        )
    return Promotion(
        outcome=outcome,
        promoted=True,
        stopped=False,
        next_stage=following,
        reason=(
            f"stage {outcome.stage.name!r} is healthy on {len(outcome.outcomes)} "
            f"criteria; promoting to {following.name!r}"
        ),
    )


def run_progressive(
    stages: Sequence[Stage],
    observe: Callable[[Stage], Mapping[str, ObservationResult]],
) -> tuple[Promotion, ...]:
    """Walk the ladder, stopping at the first stage that is not healthy.

    Stages are observed one at a time and no stage after a stop is ever observed — an
    automatic stop has to mean the experiment stopped, not that the runner recorded a
    few more rows. Returns one :class:`Promotion` per stage actually reached.
    """
    decisions: list[Promotion] = []
    for stage in stages:
        decision = promote_to(stages, evaluate_stage(stage, observe(stage)))
        decisions.append(decision)
        if decision.stopped:
            break
    return tuple(decisions)


# =======================================================================================
# The aggregate report
# =======================================================================================


@dataclass(frozen=True, slots=True)
class ResilienceAnalysis:
    """Everything one analysis produced, in one reportable value."""

    boundary: BoundaryReport
    recovery: tuple[RecoveryCurve, ...] = ()
    minimal_case: MinimalFailureCase | None = None
    causal: CausalAnalysis | None = None
    stages: tuple[StageOutcome, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "boundary": self.boundary.to_dict(),
            "recovery": [curve.to_dict() for curve in self.recovery],
            "minimal_case": None if self.minimal_case is None else self.minimal_case.to_dict(),
            "causal": None if self.causal is None else self.causal.to_dict(),
            "stages": [stage.to_dict() for stage in self.stages],
            "notes": list(self.notes),
        }


def analyze_run(
    policy: SearchPolicy,
    history: SearchHistory,
    *,
    comparisons: Mapping[int, Comparison] | None = None,
    recovery: Sequence[RecoveryCurve] = (),
    failure_cases: Sequence[FailureCase] = (),
    causal: Sequence[CausalAnalysis] = (),
    stages: Sequence[StageOutcome] = (),
) -> ResilienceAnalysis:
    """Assemble the outputs plan 15 names into one reportable value.

    Deliberately thin: the boundary, the curves, the minimal case, and the causal
    analysis are each computed by the function that owns them, and this one only
    collects them so a caller has a single value to serialise into an evidence
    bundle. Absent sections are ``None`` or empty — never a default that reads as a
    clean result — and each absence carries a note saying what it means.
    """
    notes: list[str] = []
    if not causal:
        notes.append(
            "no causal analysis was supplied: absence of a chain here is not evidence "
            "that no chain exists"
        )
    if not recovery:
        notes.append("no recovery curve was supplied: recovery is unreported, not clean")
    return ResilienceAnalysis(
        boundary=boundary_report(policy, history, comparisons),
        recovery=tuple(recovery),
        minimal_case=minimal_failure_case(failure_cases) if failure_cases else None,
        causal=causal[0] if causal else None,
        stages=tuple(stages),
        notes=tuple(notes),
    )
