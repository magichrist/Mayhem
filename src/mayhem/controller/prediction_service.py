"""Plan 14 Phase 2 — the prediction service, and the simulate path that cannot mutate.

Phase 1 (:mod:`mayhem.domain.prediction`) computed a prediction. Nothing called
it, and a pure function nobody calls is a library, not a control. This module is
the call site: it assembles the inputs a real run would have — the budgets the
gate enforces, the plan-14 ceilings from configuration, a rate card, the policy
facts — evaluates the *real* gate alongside the prediction, and returns both.

Four properties carry the phase, and each is negative: what this module must
refuse to do.

**The preview can never be calmer than the gate.** :func:`simulate_plan` does not
merely compute a prediction; it runs ``controller.safety.validate_plan`` on a
throwaway context and carries the gate's own refusal set out next to the
prediction, checked with
:func:`~mayhem.domain.prediction.is_never_permissive`. The check is *split*, and
the split is the load-bearing part. The gate refuses on the **first** breach, so
its refusal set is a single rule, and on a real plan it is frequently one this
preview has no vocabulary for at all — a config-policy denylist, an
environment-fingerprint mismatch, a capability gate, ``k8s.unsupported``. Those
are reported as :attr:`GateAgreement.unmodelled` and make the report unusable for
approval, because a preview that cannot speak to the rule which killed a plan may
not back an approval of it. A refusal from a rule the prediction *does* model and
did *not* flag is a genuine defect, and it raises
:data:`RULE_PREDICTION_CALMER_THAN_GATE` rather than returning a preview that
would have told an approver "fine" while the gate refused.

**Simulate is inert by construction, and proves it.**
:func:`PredictionService.simulate_plan` evaluates through
:meth:`PredictionService.detached`, a copy of the service holding no mutation
backend at all. It also accepts whatever backend the caller holds and never
routes a call through it, and reports :attr:`MutationProof.calls` — the
*observed* length of that :class:`~mayhem.controller.policy_gate.MutationSink`
after the call, read off a real object. The predicate tested is the policy_gate
one: a sink is accepted and never written. So a simulate is not a code path that
is careful; it is a code path with no call site for the thing that mutates, and
the evidence is a length, not a promise.

**Ceilings are reported, and the debt is named.** Plan 14 §"Controls" lists a
protected-service list, a maximum dependency depth, a maximum customer-facing
services, and a maximum percentage. Phase 1 modelled them; this phase consumes
them, as :class:`CeilingVerdict` records — one per dimension, configured or not,
with the observed value beside the limit, and :attr:`CeilingVerdict.enforced_by_gate`
false, because ``validate_plan`` does not evaluate them. They are *not* added to
``controller/safety.py`` here: that gate is wired into by the executor and several
later phases, and the honest statement is that these ceilings are Phase 4's
admission wiring, not Phase 2's.
:data:`PENDING_ADMISSION_WIRING` names each rule, the dimension it belongs to,
and the exact work Phase 4 owes — as data, so a surface can render the debt and a
test can assert it is still owed.

**An unpriced estimate is disclosed, never invented.** There is no price table in
this repository. The service therefore builds a
:class:`~mayhem.domain.prediction.CostRateCard` with a rate of ``0.0`` unless
configuration supplies one, and the resulting :attr:`CostDisclosure.status` is
``"unpriced"`` with the *measured* affected-node-seconds beside it. ``total_usd``
of ``0.0`` on an unpriced estimate is the absence of a number, not a price of
nothing.

Two boundaries this module will not cross. It calls exactly one gate function —
the plan-time one — and only on a cloned context, the way
:func:`controller.preflight._probe_context` clones rather than pollutes the
caller's decision log; a preview that appended its own probe decisions to the
safety record a real run is judged by would be a preview that edited the evidence.
And a report is a *prediction*, not a preflight: :meth:`SimulateReport.as_preflight`
raises, because a preview that could be promoted into a preflight would let the
two artifacts be confused at exactly the moment somebody is deciding to run
something.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import TYPE_CHECKING, NoReturn

from mayhem.controller.policy_gate import (
    MutationSink,
    capability_requirements_for,
    derive_facts,
)
from mayhem.controller.safety import (
    SafetyRefusedError,
    simulate_plan_policy,
    validate_plan,
)
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.policy import PolicyDimension, PolicyFacts
from mayhem.domain.prediction import (
    KNOWN_RULE_IDS,
    RULE_MAX_AFFECTED_NODES,
    RULE_MAX_AFFECTED_PCT,
    RULE_MAX_CUSTOMER_FACING_SERVICES,
    RULE_MAX_DEPENDENCY_DEPTH,
    RULE_PROTECTED_NODE,
    BlastCeilings,
    CostRateCard,
    approval_refusal_reason,
    customer_facing_node_ids,
    is_never_permissive,
    predict_impact,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mayhem.controller.policy_gate import PolicyGateResult
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.decisions import SafetyDecision
    from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan
    from mayhem.domain.prediction import CostEstimate, ImpactPrediction
    from mayhem.domain.quota import DamageQuota
    from mayhem.domain.runtime_adapter import CapabilityRequirements
    from mayhem.domain.topology import TopologyGraph

# -- names ------------------------------------------------------------------------

#: What a report from this module *is*. Deliberately not ``"preflight"``: the
#: preflight artifact is :class:`mayhem.domain.preflight.Preflight`, built by
#: ``controller.preflight.build_preflight`` off the real gate, and a report that
#: could be called one would let a preview stand in for it.
PREDICTION_ARTIFACT = "prediction"

RULE_PREDICTION_CALMER_THAN_GATE = "prediction.calmer_than_gate"
RULE_PREVIEW_NOT_PREFLIGHT = "prediction.preview_not_preflight"

#: Rule id naming the admission-wiring debt, for a surface that renders it.
RULE_PENDING_ADMISSION_WIRING = "prediction.ceiling_admission_pending"

#: The evidence a real run of a predicted plan is expected to produce, mirroring
#: ``controller.preflight.build_preflight``'s list. ``prediction`` is second
#: because Phase 4 seals the prediction with the plan; until it does, this names
#: what the run *should* end up carrying, not what any envelope holds today.
SIMULATE_EXPECTED_EVIDENCE: tuple[str, ...] = (
    "plan",
    "prediction",
    "safety_decisions",
    "step_reports",
    "lease_timeline",
    "observations",
    "verdict",
    "recovery_state",
)


# -- refusals ---------------------------------------------------------------------


class PredictionDisagreementError(InvariantViolationError):
    """The prediction came out calmer than the real gate.

    Raised instead of returned. A prediction that under-reports a rule the gate
    refused would show an approver a clean preview for a plan that cannot run,
    which is the single failure this module exists to make impossible; a returned
    report would let it travel.
    """


class PreviewNotPreflightError(InvariantViolationError):
    """Someone tried to promote a prediction preview into a preflight artifact.

    A preflight is evaluated against live state and carries the real gate's
    decision; a preview is computed over a snapshot and carries a prediction. The
    two are not interchangeable, and there is no condition under which a preview
    becomes one.
    """


# -- the admission-wiring debt -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class CeilingWiring:
    """One plan-14 ceiling, and what ``validate_plan`` still owes for it."""

    rule_id: str
    dimension: str
    owes: str


#: The Phase 4 admission wiring this phase deliberately does *not* do.
#:
#: Kept as data rather than prose so a surface can render the debt and a test can
#: assert it is still owed: the moment one of these rule ids starts appearing in a
#: real gate refusal, its entry is stale and this phase's own suite says so.
PENDING_ADMISSION_WIRING: tuple[CeilingWiring, ...] = (
    CeilingWiring(
        rule_id=RULE_PROTECTED_NODE,
        dimension="protected service list",
        owes=(
            "validate_plan must refuse a fault whose resolved targets intersect the "
            "protected node list, before the per-step admission loop, recording "
            f"{RULE_PROTECTED_NODE} on the safety context"
        ),
    ),
    CeilingWiring(
        rule_id=RULE_MAX_DEPENDENCY_DEPTH,
        dimension="maximum dependency depth",
        owes=(
            "validate_plan must measure dependents-closure depth per fault step and "
            f"refuse past the ceiling, recording {RULE_MAX_DEPENDENCY_DEPTH}"
        ),
    ),
    CeilingWiring(
        rule_id=RULE_MAX_CUSTOMER_FACING_SERVICES,
        dimension="maximum customer-facing services",
        owes=(
            "validate_plan must count exposed-port service nodes inside the affected "
            f"set per step and refuse past the ceiling, recording "
            f"{RULE_MAX_CUSTOMER_FACING_SERVICES}"
        ),
    ),
    CeilingWiring(
        rule_id=RULE_MAX_AFFECTED_PCT,
        dimension="maximum percentage",
        owes=(
            "validate_plan must compare the affected-node share of the graph per step "
            f"and refuse past the ceiling, recording {RULE_MAX_AFFECTED_PCT}"
        ),
    ),
    CeilingWiring(
        rule_id=RULE_MAX_AFFECTED_NODES,
        dimension="blast-radius ceiling",
        owes=(
            "validate_plan must cap the raw affected-node count per step, recording "
            f"{RULE_MAX_AFFECTED_NODES}"
        ),
    ),
)

WIRING_GAP_NOTE = (
    "plan 14 ceilings are reported by this preview and enforced by nobody: "
    + "; ".join(f"{w.rule_id} ({w.dimension})" for w in PENDING_ADMISSION_WIRING)
    + f" are admission wiring plan 14 Phase 4 still owes to controller.safety "
    f"[{RULE_PENDING_ADMISSION_WIRING}]"
)

_PENDING_RULE_IDS: frozenset[str] = frozenset(w.rule_id for w in PENDING_ADMISSION_WIRING)


def is_enforced_by_gate(rule_id: str) -> bool:
    """Whether admission is expected to evaluate ``rule_id``.

    Derived from :data:`PENDING_ADMISSION_WIRING` rather than hardcoded per
    dimension, so the table and the records cannot disagree: Phase 4's job is to
    delete a row here, and the ``enforced_by_gate`` field on every ceiling flips
    with it instead of continuing to claim the rule is unenforced after it is.

    The converse assumption is that a rule id *absent* from the table is the
    gate's to enforce — which is what makes the table's completeness load-bearing.
    That is the right default for the five plan-14 controls, whose whole job is to
    end up in admission; a reader who adds a rule here for a ceiling the gate
    should never see would have to say so in the table rather than by exception.
    """
    return rule_id not in _PENDING_RULE_IDS


# -- configuration ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PredictionConfig:
    """Everything the service reads from configuration.

    ``ceilings`` and ``rate_card`` are the plan-14 inputs, and both are Phase 1
    domain values passed through untouched so this module never becomes a second
    place where a limit is authored. ``observed`` fills only the policy dimensions
    no derivation can reach — team, schedule, maintenance window, cloud cost,
    approval level — and is merged *under* the service's own derivations, so a
    supplied value can never talk a preview into a different target set or fault
    family than the plan actually carries.
    """

    ceilings: BlastCeilings = field(default_factory=BlastCeilings)
    rate_card: CostRateCard = field(default_factory=CostRateCard)
    observed: Mapping[PolicyDimension, tuple[str, ...]] = field(default_factory=dict)


# -- the report's parts -----------------------------------------------------------


class CeilingName(StrEnum):
    """Plan 14 §"Controls" dimensions, as admission dimensions.

    One member per ceiling, including the protected list, so a reader asking
    "which of these did the preview actually check?" gets an exhaustive answer
    rather than the subset that happened to fire.
    """

    PROTECTED_SERVICES = "protected_services"
    MAX_DEPENDENCY_DEPTH = "max_dependency_depth"
    MAX_CUSTOMER_FACING_SERVICES = "max_customer_facing_services"
    MAX_AFFECTED_PCT = "max_affected_pct"
    BLAST_RADIUS_CEILING = "blast_radius_ceiling"


@dataclass(frozen=True, slots=True)
class CeilingVerdict:
    """One ceiling: what it is, what was measured, and whether it is enforced.

    ``observed`` is ``None`` rather than ``0.0`` when nothing could be measured
    (an empty graph has no percentage to divide by), so an unmeasurable dimension
    is never rendered as a passing one. ``configured`` says whether a *limit*
    applies at all: an unconfigured ceiling is unchecked, which is not the same as
    satisfied. ``enforced_by_gate`` is false for all five today and is the field a
    reader — or a Phase 4 reviewer — checks first; it is derived from
    :data:`PENDING_ADMISSION_WIRING` (see :func:`is_enforced_by_gate`), so
    removing a row there flips it rather than leaving a stale claim behind.
    """

    dimension: CeilingName
    rule_id: str
    configured: bool
    limit: float | None
    observed: float | None
    unit: str
    breached: bool
    enforced_by_gate: bool
    detail: str


@dataclass(frozen=True, slots=True)
class GateAgreement:
    """The real gate's refusals beside the prediction's, compared one-directionally.

    ``modelled`` is the part of the gate's refusal set the prediction can speak
    about: rule ids in :data:`~mayhem.domain.prediction.KNOWN_RULE_IDS`.
    ``unmodelled`` is the rest — refusals from rules this preview does not
    evaluate at all.

    The split is what makes the invariant checkable rather than vacuous. Folding
    unmodelled refusals into the comparison would make ``agrees`` false for every
    correctly-scoped preview, and the check would be noise nobody could act on.

    Neither half may be dropped, and each is refused differently:

    * a ``modelled`` refusal the prediction did not flag makes :attr:`agrees`
      false, and :func:`PredictionService.simulate_plan` raises rather than return
      a report;
    * an ``unmodelled`` refusal leaves ``agrees`` true but makes the report
      unusable for approval, because a preview that cannot speak to the rule that
      blocked the plan may not back an approval of it.
    """

    gate_refused: frozenset[str]
    modelled: frozenset[str]
    unmodelled: frozenset[str]
    flagged: frozenset[str]
    agrees: bool
    reason: str

    def describe(self) -> str:
        if not self.agrees:
            return self.reason
        if self.unmodelled:
            return f"gate refused {sorted(self.unmodelled)}, which this preview does not model"
        if not self.gate_refused:
            return f"gate admitted; prediction flagged {sorted(self.flagged) or 'nothing'}"
        return f"gate refused {sorted(self.gate_refused)}; prediction flagged it too"


@dataclass(frozen=True, slots=True)
class CostDisclosure:
    """What the blast is expected to cost, or the explicit statement that nobody priced it.

    ``status`` is ``"priced"`` or ``"unpriced"`` — a word, not a zero. On an
    unpriced estimate ``total_usd`` is ``0.0`` because there is no number, and
    ``affected_node_seconds`` is real: it is measured, so a caller holding its own
    rate can price the same blast without re-deriving anything.

    One caveat the caller must not lose: the node-seconds come from the walk, which
    counts the plan's target ids whether or not the graph holds them. Over a
    missing target or an empty topology that figure is therefore non-zero without
    being a measurement of anything, which is why the trust question is answered
    separately by :attr:`SimulateReport.approval_refusal` and not here.
    """

    status: str
    currency: str
    basis: str
    affected_node_seconds: float
    total_usd: float
    note: str

    @property
    def priced(self) -> bool:
        return self.status == "priced"


@dataclass(frozen=True, slots=True)
class MutationProof:
    """What the simulate path can state about mutation: nothing was performed.

    ``backend_attached`` is false because :func:`PredictionService.simulate_plan`
    evaluates through :meth:`PredictionService.detached`. ``calls`` and
    ``calls_detail`` are read *after* the call off whatever
    :class:`~mayhem.controller.policy_gate.MutationSink` the caller held, so the
    evidence is a length rather than a promise.
    """

    backend_attached: bool
    calls: int
    calls_detail: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class PredictionReview:
    """Whether a stored prediction may still back an approval, and why not.

    The Phase 4 question: a prediction sealed with a plan is only meaningful while
    the graph and plan it described still are.
    :meth:`PredictionService.review` answers that by re-deriving identities, so a
    preview stored before a topology change cannot be re-read as current.
    """

    usable_for_approval: bool
    reason: str
    graph_identity: str
    plan_identity: str


@dataclass(frozen=True, slots=True)
class SimulateReport:
    """Everything a simulate established, and nothing it did not.

    The prediction, the real gate's own refusals beside it, the plan-14 ceilings
    as admission dimensions, the fact set, the policy verdict, the capability
    requirements, the cost disclosure, and the mutation proof. What this report
    does *not* contain is authority: nothing here approves a plan, and
    :attr:`approval_refusal` is the single field that says whether the preview may
    be shown to someone deciding to approve.
    """

    artifact: str
    prediction: ImpactPrediction
    agreement: GateAgreement
    dimensions: tuple[CeilingVerdict, ...]
    cost: CostDisclosure
    facts: PolicyFacts
    facts_complete: bool
    policy: PolicyGateResult | None
    capabilities: CapabilityRequirements
    gate_decisions: tuple[SafetyDecision, ...]
    expected_evidence: tuple[str, ...]
    #: The plan's target selection, in full — including ids the topology does not
    #: hold, which are named in
    #: :attr:`~mayhem.domain.prediction.ImpactPrediction.unresolved_target_ids`
    #: and are excluded from the affected set, the fan-out, and the observed
    #: TARGET fact. This is "what the plan asked for", not "what was measured", so
    #: hiding an unresolvable id here would hide the operator's own mistake.
    targets: tuple[str, ...]
    mutation: MutationProof
    approval_refusal: str
    wiring_gaps: tuple[CeilingWiring, ...]
    notes: tuple[str, ...] = ()

    @property
    def usable_for_approval(self) -> bool:
        """True only when the numbers are current and were measured against something.

        Deliberately *not* "no violated rules": a preview full of flagged rules is
        exactly what an approver needs. This asks whether the preview is a
        *complete* measurement — a current graph, no unresolved target, a walk that
        reached the end, and nothing the gate refused that this preview cannot
        speak to. Note that a gate refusal makes it false in practice, through the
        truncated walk, not through the refusal itself; a plan the gate admits and
        the preview measures to the end is the case this is true for.
        """
        return not self.approval_refusal

    @property
    def admitted_by_gate(self) -> bool:
        """True when ``validate_plan`` raised nothing on the probed context."""
        return not self.agreement.gate_refused

    @property
    def unmodelled_refusals(self) -> frozenset[str]:
        """Gate refusals this preview has no rule for — never silently dropped."""
        return self.agreement.unmodelled

    @property
    def configured_dimensions(self) -> tuple[CeilingVerdict, ...]:
        """Only the ceilings a limit was actually configured for."""
        return tuple(dimension for dimension in self.dimensions if dimension.configured)

    def breached_dimensions(self) -> tuple[CeilingVerdict, ...]:
        """Only the ceilings that fired, for a surface that leads with them."""
        return tuple(dimension for dimension in self.dimensions if dimension.breached)

    def dimension(self, name: CeilingName) -> CeilingVerdict:
        """The verdict for one named dimension.

        A lookup that raises rather than returning ``None``: the five dimensions
        are a closed set (:class:`CeilingName`), so a miss is a caller's typo and
        silently answering about a different dimension is the failure mode a
        dict-and-``if not found`` shape invites.
        """
        for verdict in self.dimensions:
            if verdict.dimension is name:
                return verdict
        msg = f"no verdict for ceiling dimension {name.value!r}"
        raise InvariantViolationError(RULE_PENDING_ADMISSION_WIRING, msg)

    def as_preflight(self) -> NoReturn:
        """Refuse, always: a prediction is not a preflight and cannot become one.

        A preflight is ``controller.preflight.Preflight`` — built by
        ``build_preflight`` off the real gate, against live state, carrying the
        gate's own decision. This report is computed over a snapshot and carries a
        prediction. Promoting one into the other would let a preview stand in for
        the artifact an operator reads to decide a run is safe, so there is no
        condition under which this returns.
        """
        raise PreviewNotPreflightError(
            RULE_PREVIEW_NOT_PREFLIGHT,
            f"a {PREDICTION_ARTIFACT} is not a preflight: it is computed over a "
            f"topology snapshot and carries a prediction, while a preflight is built "
            f"by controller.preflight.build_preflight off the real gate against live "
            f"state; plan 14 Phase 3 renders this preview alongside the preflight, "
            f"never instead of it",
        )

    def describe(self) -> str:
        """One-screen summary. A summary, never the whole report."""
        breached = self.breached_dimensions()
        lines = [
            f"{self.artifact}: {len(self.prediction.affected_node_ids)} node(s) affected, "
            f"fan-out depth {self.prediction.fan_out.max_depth}",
            f"gate: {'admitted' if self.admitted_by_gate else 'refused'} — "
            f"{self.agreement.describe()}",
            "ceilings breached: "
            + (
                ", ".join(f"{d.rule_id} ({d.observed:g}/{d.limit:g})" for d in breached)
                if breached
                else "none"
            ),
            f"cost: {self.cost.status} — {self.cost.note}",
            f"mutation: {self.mutation.calls} call(s), backend "
            f"{'attached' if self.mutation.backend_attached else 'detached'}",
        ]
        if self.approval_refusal:
            lines.append(f"not usable for approval: {self.approval_refusal}")
        return "\n".join(lines)


# -- assembly helpers -------------------------------------------------------------


def _probe_context(ctx: SafetyContext) -> SafetyContext:
    """A clone of ``ctx`` with fresh decision and warning lists.

    ``validate_plan`` records a decision on every call. Running it against the
    caller's context would append this preview's gate decisions to the safety
    record the real run is judged by — the same reason
    :func:`controller.preflight._probe_context` and the safety-proof probe clone
    rather than write. The *limits* are the caller's own, never a lifted copy: a
    probe through an unlimited budget could report passing numbers for a cap the
    real gate refuses, which is precisely the never-calmer failure this module
    exists to prevent.
    """
    return replace(ctx, decisions=[], warnings=[])


def _rule_of(exc: DomainError) -> str:
    """The rule id a non-``SafetyRefusedError`` domain failure is named by."""
    if isinstance(exc, InvariantViolationError):
        return exc.rule
    return type(exc).__name__


def _gate_verdict(
    plan: ExecutionPlan, graph: TopologyGraph, ctx: SafetyContext
) -> tuple[frozenset[str], tuple[SafetyDecision, ...]]:
    """Rule ids the *real* gate refuses, plus the decisions it recorded.

    ``validate_plan`` raises on the first breach, so this is the gate's own
    answer, not a re-derivation of it: a plan refused at step 2 yields the rule
    step 2 broke. A non-``SafetyRefusedError`` domain failure (a policy bundle
    with a drifted pin, a cyclic bundle, an unresolvable selector) is captured the
    same way rather than allowed to escape as an exception the caller cannot
    interpret — a refusal the preview cannot see is not a plan it may describe as
    admissible.
    """
    probe = _probe_context(ctx)
    try:
        validate_plan(plan, graph, probe)
    except SafetyRefusedError as exc:
        rule_id = exc.decision.rule_id if exc.decision is not None else exc.reason_code
        return frozenset({rule_id}), tuple(probe.decisions)
    except DomainError as exc:
        return frozenset({_rule_of(exc)}), tuple(probe.decisions)
    return frozenset(), tuple(probe.decisions)


def _agreement(prediction: ImpactPrediction, gate_refused: frozenset[str]) -> GateAgreement:
    """Compare the gate's refusals with the prediction, splitting what it can model."""
    modelled = gate_refused.intersection(KNOWN_RULE_IDS)
    unmodelled = gate_refused - KNOWN_RULE_IDS
    agrees = is_never_permissive(prediction, modelled)
    reason = ""
    if not agrees:
        missing = sorted(modelled - prediction.rule_ids)
        reason = (
            f"prediction did not flag rule(s) {missing} that the real gate refused as "
            f"{sorted(modelled)}; a preview must never be calmer than the gate"
        )
    return GateAgreement(
        gate_refused=gate_refused,
        modelled=modelled,
        unmodelled=unmodelled,
        flagged=prediction.rule_ids,
        agrees=agrees,
        reason=reason,
    )


def _cost_disclosure(estimate: CostEstimate) -> CostDisclosure:
    """State the estimate, or state plainly that nobody priced it.

    The unpriced branch is the one that matters: ``total_usd == 0.0`` on its own
    reads as "this blast is free", and the disclosure has to be a word.
    ``affected_node_seconds`` travels with it because it *is* measured — a caller
    with a real rate can price the same blast without re-deriving anything.
    """
    if estimate.priced:
        return CostDisclosure(
            status="priced",
            currency=estimate.currency,
            basis=estimate.basis,
            affected_node_seconds=estimate.affected_node_seconds,
            total_usd=estimate.total_usd,
            note=(
                f"priced at {estimate.total_usd:g} {estimate.currency} from "
                f"{estimate.affected_node_seconds:g} affected-node-seconds "
                f"(basis: {estimate.basis})"
            ),
        )
    return CostDisclosure(
        status="unpriced",
        currency=estimate.currency,
        basis=estimate.basis,
        affected_node_seconds=estimate.affected_node_seconds,
        total_usd=estimate.total_usd,
        note=(
            "UNPRICED: this repository holds no price table, so no dollar figure is "
            "claimed and the zero is the absence of a number. The blast is "
            f"{estimate.affected_node_seconds:g} affected-node-seconds, which is "
            f"measured and can be priced by any caller holding a rate "
            f"(basis: {estimate.basis})"
        ),
    )


def _as_float(value: int | float | None) -> float | None:
    """``None`` stays ``None``; a configured number is reported as a float."""
    return None if value is None else float(value)


def _targeted_ids(prediction: ImpactPrediction) -> tuple[str, ...]:
    """Every node the plan's fault steps target, sorted and deduplicated."""
    return tuple(sorted({node_id for step in prediction.steps for node_id in step.target_ids}))


def _ceilings(
    prediction: ImpactPrediction,
    graph: TopologyGraph,
    ceilings: BlastCeilings,
) -> tuple[CeilingVerdict, ...]:
    """Evaluate every plan-14 control, configured or not, as an admission dimension.

    All five are always present. A ceiling nobody configured is reported as
    unchecked with its observed value attached rather than omitted, because "we did
    not check this" and "this passed" must never render identically. And
    ``enforced_by_gate`` comes from :func:`is_enforced_by_gate`, which reads the
    wiring table: the gate evaluates none of these rules today, and the record says
    so per dimension rather than leaving a reader to infer enforcement from the fact
    that a number appeared.
    """
    targets = _targeted_ids(prediction)
    protected_hit = tuple(sorted(ceilings.protected_node_ids.intersection(targets)))
    customer_facing = customer_facing_node_ids(graph)
    facing_hit = tuple(sorted(customer_facing.intersection(prediction.affected_node_ids)))
    worst_nodes = max((step.node_count for step in prediction.steps), default=0)
    node_total = len(graph.nodes)
    worst_pct = (worst_nodes / node_total * 100.0) if node_total else None
    depth = prediction.fan_out.max_depth
    breached = prediction.rule_ids

    def verdict(
        name: CeilingName,
        rule_id: str,
        *,
        configured: bool,
        limit: float | None,
        observed: float | None,
        unit: str,
        detail: str,
    ) -> CeilingVerdict:
        return CeilingVerdict(
            dimension=name,
            rule_id=rule_id,
            configured=configured,
            limit=limit,
            observed=observed,
            unit=unit,
            breached=rule_id in breached,
            enforced_by_gate=is_enforced_by_gate(rule_id),
            detail=detail,
        )

    return (
        verdict(
            CeilingName.PROTECTED_SERVICES,
            RULE_PROTECTED_NODE,
            configured=bool(ceilings.protected_node_ids),
            limit=0.0 if ceilings.protected_node_ids else None,
            observed=float(len(protected_hit)),
            unit="protected_nodes",
            detail=(
                f"targets intersect the protected list: {list(protected_hit)}"
                if protected_hit
                else "no protected node is targeted"
            ),
        ),
        verdict(
            CeilingName.MAX_DEPENDENCY_DEPTH,
            RULE_MAX_DEPENDENCY_DEPTH,
            configured=ceilings.max_dependency_depth is not None,
            limit=_as_float(ceilings.max_dependency_depth),
            observed=float(depth),
            unit="hops",
            detail=f"damage reaches {depth} dependency hop(s) from the targets",
        ),
        verdict(
            CeilingName.MAX_CUSTOMER_FACING_SERVICES,
            RULE_MAX_CUSTOMER_FACING_SERVICES,
            configured=ceilings.max_customer_facing_services is not None,
            limit=_as_float(ceilings.max_customer_facing_services),
            observed=float(len(facing_hit)),
            unit="services",
            detail=(
                f"customer-facing services affected: {list(facing_hit)}"
                if facing_hit
                else "no customer-facing service is affected"
            ),
        ),
        verdict(
            CeilingName.MAX_AFFECTED_PCT,
            RULE_MAX_AFFECTED_PCT,
            configured=ceilings.max_affected_pct is not None,
            limit=ceilings.max_affected_pct,
            observed=round(worst_pct, 3) if worst_pct is not None else None,
            unit="percent_of_nodes",
            detail=(
                f"worst step affects {worst_nodes} of {node_total} nodes"
                if worst_pct is not None
                else "graph carried no nodes, so no percentage is measurable"
            ),
        ),
        verdict(
            CeilingName.BLAST_RADIUS_CEILING,
            RULE_MAX_AFFECTED_NODES,
            configured=ceilings.max_affected_nodes is not None,
            limit=_as_float(ceilings.max_affected_nodes),
            observed=float(worst_nodes),
            unit="nodes",
            detail=f"worst step affects {worst_nodes} node(s)",
        ),
    )


def _policy_verdict(
    plan: ExecutionPlan, ctx: SafetyContext
) -> tuple[PolicyGateResult | None, str]:
    """The plan-07 policy verdict, read through its own simulation entry point.

    :func:`controller.safety.simulate_plan_policy` is ``simulate_gate`` with
    ``simulated=True``, so this is the verdict admission reaches rather than a
    preview of it. A bundle that cannot be evaluated at all (a drifted pin, a
    missing parent) is returned as a note instead of an exception: the real gate
    refuses such a plan, and that refusal is already carried in
    :attr:`GateAgreement` — raising here would lose the prediction that explains
    why the plan is refused.
    """
    try:
        return simulate_plan_policy(plan, ctx), ""
    except DomainError as exc:
        return None, f"policy bundle could not be evaluated: {exc}"


def _facts(
    plan: ExecutionPlan,
    prediction: ImpactPrediction,
    graph: TopologyGraph,
    ctx: SafetyContext,
    config: PredictionConfig,
) -> tuple[PolicyFacts, bool, str]:
    """The observed facts behind this preview, and whether they are the gate's own.

    With a policy bundle configured this is
    :func:`controller.policy_gate.derive_facts` — the gate's *own* derivation, not
    a second one — so the facts shown beside a policy verdict are the facts that
    verdict was reached from, and ``complete`` is true.

    Without a bundle there is nothing to derive against, so the service reports
    only what it observed itself: the configured dimensions, the environment, and
    the graph-resident targets the prediction actually resolved. ``complete`` is
    false and the note says so, because a fact set missing the bundle-derived
    dimensions is not a bundle evaluation and must not be rendered as one. An
    unresolvable target id is excluded from the TARGET dimension: a fact set may
    not claim a node was targeted when the topology never held it.
    """
    if ctx.policy_gate is not None:
        return (
            derive_facts(plan, ctx.policy_gate, environment=ctx.environment),
            True,
            "policy facts derived by controller.policy_gate.derive_facts from the gate's "
            "own inputs, so the facts beside a policy verdict are the ones it used",
        )
    values: dict[PolicyDimension, tuple[str, ...]] = {
        dimension: tuple(supplied) for dimension, supplied in config.observed.items()
    }
    if ctx.environment is not None:
        values[PolicyDimension.ENVIRONMENT] = (ctx.environment,)
    resident = frozenset(node.id for node in graph.nodes)
    targets = tuple(sorted(set(_targeted_ids(prediction)).intersection(resident)))
    if targets:
        values[PolicyDimension.TARGET] = targets
    return (
        PolicyFacts(values=values),
        False,
        "no policy bundle configured, so these are the prediction's own observations and "
        "not a bundle evaluation: fault family, risk, capability, concurrency, and damage "
        "budget are unobserved",
    )


def _approval_refusal(
    report: SimulateReport, *, plan: ExecutionPlan, graph: TopologyGraph
) -> str:
    """Every named reason this preview may not back an approval, as one sentence.

    Ordered so the most fundamental comes first: an unmeasured or stale prediction
    is refused before a half-modelled one, because each earlier reason makes the
    later ones moot. Returns ``""`` only when the preview is current, measured,
    complete, and nothing the gate refused is a rule this preview cannot speak to.

    Note what is deliberately *not* a reason here: the gate refusing a rule this
    preview modelled, and a breached ceiling. Those are the preview's findings, not
    its disqualifications — refusing to *show* an approver a breach is the failure
    this whole module exists to prevent. (A modelled refusal does make the report
    unusable in practice, but through Phase 1's truncation disclosure rather than
    through this function: the walk stops where the gate stops, so the tail went
    unmeasured, and that is a statement about coverage.) The absence of a policy
    bundle is likewise not a reason: it is a configuration fact the operator
    already knows, and requiring a bundle to show a preview would make the field
    useless on every default installation — a run is approval-gated whether or not
    a bundle exists (see ``controller.approval_gate``), so showing a preview is not
    standing in for an approval. :attr:`SimulateReport.facts_complete` discloses
    that gap instead.
    """
    unmeasured = approval_refusal_reason(report.prediction, graph=graph, plan=plan)
    if unmeasured:
        return unmeasured
    if report.agreement.unmodelled:
        return (
            f"the real gate refused {sorted(report.agreement.unmodelled)}, which this "
            f"preview does not model, so it cannot speak to the rule that blocks this plan"
        )
    return ""


# -- the service ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PredictionService:
    """Assembles a prediction from live topology plus configuration.

    The service holds the live ``graph`` because a prediction is a statement about
    *this* topology: assembling one per call would let a caller evaluate a plan
    against one snapshot and the next against another while both were described as
    "the prediction". ``backend`` is the mutation backend a real run would hold;
    the service never routes a call through it, and :func:`simulate_plan` evaluates
    through :meth:`detached` — a copy with ``backend=None`` — so the simulate path
    has no backend to write through even when a caller hands one in.
    """

    graph: TopologyGraph
    config: PredictionConfig = PredictionConfig()
    backend: MutationSink | None = None

    def with_config(self, config: PredictionConfig) -> PredictionService:
        """The same live topology under different configuration."""
        return replace(self, config=config)

    def detached(self) -> PredictionService:
        """This service with the mutation backend removed.

        The simulate path runs on this copy. It is the "backend detached" half of
        the purity claim: the object that evaluates the plan holds no backend
        reference at all, so no forgotten call site could have written through one.
        """
        return replace(self, backend=None)

    def budgets(self, ctx: SafetyContext) -> tuple[BlastRadiusBudget, DamageQuota]:
        """The exact limits the gate enforces, read off the same context.

        ``ctx.damage_quota`` and *not* ``ctx.budget.damage_quota``: the gate
        charges the context's quota, and the field on the budget is only the
        default for a context that has none. Reading the wrong one would let the
        preview evaluate a different limit than admission does — the exact
        disagreement this module exists to prevent.
        """
        return ctx.budget, ctx.damage_quota

    def predict(self, plan: ExecutionPlan, ctx: SafetyContext) -> ImpactPrediction:
        """The Phase 1 pure function, fed the gate's own limits.

        Delegated rather than reimplemented, so the preview's arithmetic is the
        domain's by construction and a change there cannot leave this call site
        behind.
        """
        budget, quota = self.budgets(ctx)
        return predict_impact(
            self.graph,
            plan,
            budget=budget,
            quota=quota,
            ceilings=self.config.ceilings,
            rate_card=self.config.rate_card,
        )

    def simulate_plan(self, plan: ExecutionPlan, ctx: SafetyContext) -> SimulateReport:
        """Evaluate a frozen plan against live topology, mutating nothing.

        ``mayhem simulate`` semantics for plan 14 gaps 62/72: target selection,
        blast radius, expected changes, capabilities, policy result, cost
        estimate, expected evidence — and zero mutation by construction.

        Purity is structural, in three layers, each of them checkable:

        1. this method evaluates through :meth:`detached`, so the service doing
           the work holds no mutation backend;
        2. the only gate function called is the plan-time one, on a cloned context
           (:func:`_probe_context`), so the caller's safety record is untouched — a
           preview must not append its own probe decisions to the log a real run is
           judged by;
        3. the caller's ``backend``, if any, is read afterwards and its length
           reported in :attr:`SimulateReport.mutation` — a measurement taken off a
           real object, not a promise in a docstring.

        Raises :class:`PredictionDisagreementError` if the prediction comes out
        calmer than the real gate. Everything else is reported, including the
        reasons that make a preview unusable for approval.
        """
        service = self.detached()
        prediction = service.predict(plan, ctx)
        gate_refused, gate_decisions = _gate_verdict(plan, service.graph, ctx)
        agreement = _agreement(prediction, gate_refused)
        if not agreement.agrees:
            raise PredictionDisagreementError(RULE_PREDICTION_CALMER_THAN_GATE, agreement.reason)

        policy, policy_note = _policy_verdict(plan, ctx)
        facts, facts_complete, facts_note = _facts(
            plan, prediction, service.graph, ctx, service.config
        )
        notes = [facts_note, WIRING_GAP_NOTE]
        if policy_note:
            notes.append(policy_note)
        notes.extend(prediction.notes)

        report = SimulateReport(
            artifact=PREDICTION_ARTIFACT,
            prediction=prediction,
            agreement=agreement,
            dimensions=_ceilings(prediction, service.graph, service.config.ceilings),
            cost=_cost_disclosure(prediction.cost),
            facts=facts,
            facts_complete=facts_complete,
            policy=policy,
            capabilities=capability_requirements_for(plan),
            gate_decisions=gate_decisions,
            expected_evidence=SIMULATE_EXPECTED_EVIDENCE,
            targets=_targeted_ids(prediction),
            mutation=MutationProof(
                backend_attached=False,
                calls=len(self.backend) if self.backend is not None else 0,
                calls_detail=self.backend.calls if self.backend is not None else (),
            ),
            approval_refusal="",  # replaced once every reason is known
            wiring_gaps=PENDING_ADMISSION_WIRING,
            notes=tuple(notes),
        )
        return replace(
            report, approval_refusal=_approval_refusal(report, plan=plan, graph=service.graph)
        )

    def review(
        self,
        prediction: ImpactPrediction,
        *,
        plan: ExecutionPlan | None = None,
        graph: TopologyGraph | None = None,
    ) -> PredictionReview:
        """Whether a stored prediction may still back an approval.

        The Phase 4 question, answered by re-deriving identities rather than by
        trusting a timestamp: a prediction sealed with a plan describes that plan
        on that graph, and a topology change since then makes every number in it a
        description of the past. The reason is the Phase 1 one — an empty basis, an
        unresolved target, a stale identity, or a truncated walk — checked against
        the service's live graph and the caller's plan.

        This method touches nothing: no gate runs, no context is cloned, and no
        mutation backend is reachable from it.
        """
        live_graph = graph if graph is not None else self.graph
        reason = approval_refusal_reason(prediction, graph=live_graph, plan=plan)
        return PredictionReview(
            usable_for_approval=not reason,
            reason=reason,
            graph_identity=prediction.graph_identity,
            plan_identity=prediction.plan_identity,
        )
