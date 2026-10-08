"""Plan 14 — the prediction service, and the simulate path that cannot mutate.

Phase 1 (:mod:`mayhem.domain.prediction`) computed a prediction. Phase 2, this
module's first half, was the call site: it assembles the inputs a real run would
have — the budgets the gate enforces, the plan-14 ceilings from configuration, a
rate card, the policy facts — evaluates the *real* gate alongside the
prediction, and returns both. Phase 4, this module's second half, makes the
prediction something a run can be *scored against*: it closes the admission-wiring
debt Phase 2 declared, names the agreement state Phase 2 left emergent, and seals
the prediction with the plan so post-run analysis can say whether the forecast
was right.

Four properties carry the prediction phase, and each is negative: what this
module must refuse to do.

**The preview can never be calmer than the gate.** :func:`simulate_plan` does not
merely compute a prediction; it runs ``controller.safety.validate_plan`` on a
throwaway context and carries the gate's own refusal set out next to the
prediction. The check is *split*, and the split is the load-bearing part. The gate
refuses on the **first** breach, so its refusal set is a single rule, and on a
real plan it is frequently one this preview has no vocabulary for at all — a
config-policy denylist, an environment-fingerprint mismatch, a capability gate,
``k8s.unsupported``.

Phase 2 carried that split as two sets and let the consequences fall out of them,
which left the report's usability emergent: a reader had to know that *some*
refusals disqualified a preview and others did not, from a boolean computed
elsewhere. Phase 4 replaces the emergent split with an explicit, named state —
:class:`AgreementState` — so the rule is stated once and tested directly:

* :attr:`AgreementState.AGREES` — the gate admitted, or refused only rules this
  preview models *and* flagged. :attr:`GateAgreement.agrees` is true and the
  report may back an approval.
* :attr:`AgreementState.UNMODELLED` — the gate refused on at least one rule this
  preview has no vocabulary for. ``agrees`` stays true, because nothing modelled
  was missed, but the report is **unusable for approval**: a preview that cannot
  speak to the rule which killed a plan may not back an approval of it. This is
  now a state a test asserts, not an inference a reader has to make.
* :attr:`AgreementState.DISAGREES` — a refusal from a rule the prediction *does*
  model and did *not* flag. This is a genuine defect, and it raises
  :data:`RULE_PREDICTION_CALMER_THAN_GATE` rather than returning a preview that
  would have told an approver "fine" while the gate refused. The state is still
  recorded on the exception's behalf so a caller reading a trace can see it.

**Simulate is inert by construction, and proves it.**
:func:`PredictionService.simulate_plan` evaluates through
:meth:`PredictionService.detached`, a copy of the service holding no mutation
backend at all. It also accepts whatever backend the caller holds and never
routes a call through it, and reports :attr:`MutationProof.calls` — the
*observed* length of that :class:`~mayhem.domain.policy_gate.MutationSink`
after the call, read off a real object. The predicate tested is the policy_gate
one: a sink is accepted and never written. So a simulate is not a code path that
is careful; it is a code path with no call site for the thing that mutates, and
the evidence is a length, not a promise.

**An unpriced estimate is disclosed, never invented.** There is no price table in
this repository. The service therefore builds a
:class:`~mayhem.domain.prediction.CostRateCard` with a rate of ``0.0`` unless
configuration supplies one, and the resulting :attr:`CostDisclosure.status` is
``"unpriced"`` with the *measured* affected-node-seconds beside it. ``total_usd``
of ``0.0`` on an unpriced estimate is the absence of a number, not a price of
nothing.

Three boundaries this module will not cross. It calls exactly one gate function —
the plan-time one — and only on a cloned context, the way
:func:`controller.preflight._probe_context` clones rather than pollutes the
caller's decision log; a preview that appended its own probe decisions to the
safety record a real run is judged by would be a preview that edited the evidence.
And a report is a *prediction*, not a preflight: :meth:`SimulateReport.as_preflight`
raises, because a preview that could be promoted into a preflight would let the
two artifacts be confused at exactly the moment somebody is deciding to run
something.

Phase 4: enforcement, sealing, and accuracy
-------------------------------------------

**The five ceilings are enforced by the real gate, and the debt table is empty.**
Phase 2 named this work in :data:`PENDING_ADMISSION_WIRING` and reported every
ceiling with :attr:`CeilingVerdict.enforced_by_gate` false. Phase 4 does it:
``SafetyContext.blast_ceilings`` carries the limits, and
:func:`controller.safety.check_blast_radius` refuses
``blast_radius.protected_node``, ``…max_dependency_depth``,
``…max_customer_facing_services``, ``…max_affected_pct`` and
``…max_affected_nodes`` on the same step
:func:`mayhem.domain.prediction.predict_impact` flags them on. The wiring table is
now empty, which is not an absence but the assertion: :func:`is_enforced_by_gate`
reads it, so an emptied table is what every ceiling record follows, and a rule id
someone later adds to the gate without wiring it here is a row that has to be
deleted on purpose.

**The prediction is sealed with the plan, and an uncited one cannot be.**
:func:`seal_prediction` commits a prediction into plan 12's existing hash-chained
attestation machinery — the same domain functions, the same M0023 tables, the same
unsigned-manifest honesty gate and offline verifier
:mod:`mayhem.controller.proof_sealing` uses — under its own scope, so the
prediction's chain and the run-close chain cannot overwrite one another. Two
negative rules make the seal mean something:

* :func:`seal_prediction` refuses a blank ``evidence_ref``. A sealed prediction
  that names nothing it was computed from is a number with no provenance, and
  "we predicted this" must never be the whole of the record.
* :func:`verify_sealed_prediction` re-verifies the chain and the manifest off
  stored bytes and hands back the reconstructed :class:`ImpactPrediction`, so the
  thing post-run analysis reads is the object that was sealed rather than a
  summary of it.

**A blast that outgrew its prediction opens a finding.** Plan 14 §Phase 4's
acceptance criterion is "a run whose actual blast exceeded prediction opens a
finding, not a silent pass", and :func:`score_prediction_accuracy` is that
finding: it names the affected ids the prediction did not forecast and refuses to
call the forecast accurate while any exist. The opposite direction is a *finding
about the forecast*, not about the run — a preview that over-estimated is the
conservative failure this whole module is built around, so it is recorded and
labelled, never silently treated as a match.

Two boundaries this second half will not cross either. Sealing writes to the
store; it never computes anything, so the sealed bytes are the prediction's own
and a reload is an equality check rather than a re-derivation. And the seal is
not authority: it says *this exact prediction existed before the run*, not that
the run was allowed.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Any, NoReturn

from mayhem.controller.safety import (
    SafetyRefusedError,
    simulate_plan_policy,
    validate_plan,
)
from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    RetentionClass,
    build_manifest,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.hashing import digest as digest_of
from mayhem.domain.policy import PolicyDimension, PolicyFacts
from mayhem.domain.policy_gate import (
    MutationSink,
    capability_requirements_for,
    derive_facts,
)
from mayhem.domain.prediction import (
    KNOWN_RULE_IDS,
    RULE_MAX_AFFECTED_NODES,
    RULE_MAX_AFFECTED_PCT,
    RULE_MAX_CUSTOMER_FACING_SERVICES,
    RULE_MAX_DEPENDENCY_DEPTH,
    RULE_PROTECTED_NODE,
    BlastCeilings,
    CostEstimate,
    CostRateCard,
    DependencyFanOut,
    ImpactPrediction,
    NodeDepth,
    PredictionBasis,
    ReplicaGroupLoss,
    ReplicaLoss,
    StepCost,
    StepImpact,
    ViolatedRule,
    approval_refusal_reason,
    customer_facing_node_ids,
    is_never_permissive,
    predict_impact,
)
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationError,
    AttestationRepository,
    SigningNotImplementedError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.attestation import (
        AttestedTimestamp,
        ChainVerification,
        Manifest,
        ManifestVerification,
    )
    from mayhem.domain.decisions import SafetyDecision
    from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan
    from mayhem.domain.policy_gate import PolicyGateResult
    from mayhem.domain.quota import DamageQuota
    from mayhem.domain.runtime_adapter import CapabilityRequirements
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.store import Store

# -- names ------------------------------------------------------------------------

#: What a report from this module *is*. Deliberately not ``"preflight"``: the
#: preflight artifact is :class:`mayhem.domain.preflight.Preflight`, built by
#: ``controller.preflight.build_preflight`` off the real gate, and a report that
#: could be called one would let a preview stand in for it.
PREDICTION_ARTIFACT = "prediction"

RULE_PREDICTION_CALMER_THAN_GATE = "prediction.calmer_than_gate"
RULE_PREVIEW_NOT_PREFLIGHT = "prediction.preview_not_preflight"

#: Rule id for the explicit :attr:`AgreementState.UNMODELLED` state, for a surface
#: that renders the debt as a finding rather than as a boolean. The state is what
#: makes a preview unusable for approval; this names it in the gate's own idiom.
RULE_PREDICTION_UNMODELLED_GATE_REFUSAL = "prediction.unmodelled_gate_refusal"

#: Rule id for the accuracy finding a post-run analysis opens when the blast it
#: observed outgrew the sealed prediction. Plan 14 §Phase 4's acceptance
#: criterion, as a name something can be searched for.
RULE_PREDICTION_BLAST_EXCEEDED = "prediction.blast_exceeded"

#: Rule id for a seal refused because the prediction cites no evidence. See
#: :func:`seal_prediction`.
RULE_PREDICTION_NOT_CITED = "prediction.not_cited"

#: Rule id for a seal refused because the preview payload it was handed is not
#: a readable presentation structure. See :func:`prediction_seal_event`.
RULE_PREDICTION_PREVIEW_UNREADABLE = "prediction.preview_unreadable"

#: The seal-event payload key carrying the stored preview. See
#: :func:`prediction_seal_event` for why the preview travels inside the
#: prediction's own seal rather than in a second chain.
PREVIEW_PAYLOAD_KEY = "preview_payload"

#: Rule id naming the admission-wiring debt, for a surface that renders it.
RULE_PENDING_ADMISSION_WIRING = "prediction.ceiling_admission_pending"

#: The evidence a real run of a predicted plan is expected to produce, mirroring
#: ``controller.preflight.build_preflight``'s list. ``prediction`` is second
#: because the prediction is sealed with the plan (see :func:`seal_prediction`),
#: so post-run analysis can score the forecast rather than having nothing to
#: compare the run against.
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
    """One plan-14 ceiling, and what ``validate_plan`` still owes for it.

    Kept after Phase 4 emptied the table below, because
    :attr:`SimulateReport.wiring_gaps` is typed against it and because the shape
    is the module's own statement about what "unwired" means: a rule id, the
    dimension it belongs to, and the exact work owed. Phase 4's job was to
    *delete* the rows rather than fill an ``enforced`` flag, so this type is
    empty of instances today and populated the moment somebody adds a sixth
    ceiling the gate does not evaluate.
    """

    rule_id: str
    dimension: str
    owes: str


#: The ceilings ``controller.safety.validate_plan`` does **not** evaluate.
#:
#: Empty, and that emptiness is the assertion. Phase 2 populated this with the
#: five plan-14 §"Controls" rules and refused to add them to
#: ``controller/safety.py``, because the honest statement was that they were
#: admission wiring Phase 4 still owed. Phase 4 wired them: the five rule ids now
#: come out of :func:`controller.safety.check_blast_radius` on the same step
#: :func:`mayhem.domain.prediction.predict_impact` flags them on, and each row
#: was deleted deliberately rather than flipped.
#:
#: Kept as data rather than removed so :func:`is_enforced_by_gate` still *derives*
#: every :attr:`CeilingVerdict.enforced_by_gate` from one place. A reader cannot
#: tell from the table being empty that the derivation still holds — that is what
#: ``tests/unit/test_prediction_evidence.py`` asserts.
PENDING_ADMISSION_WIRING: tuple[CeilingWiring, ...] = ()

#: The five plan-14 §"Controls" ceilings, all of which admission now enforces.
#:
#: Named here rather than derived from :data:`PENDING_ADMISSION_WIRING`'s
#: complement, because "every rule id the gate can emit" is not a finite set a
#: module can hold. This is the finite set *this preview* reports dimensions for,
#: and asserting it against the five the gate actually refuses is what keeps
#: :func:`is_enforced_by_gate` from being an unchecked default.
ENFORCED_CEILING_RULE_IDS: frozenset[str] = frozenset(
    {
        RULE_PROTECTED_NODE,
        RULE_MAX_DEPENDENCY_DEPTH,
        RULE_MAX_CUSTOMER_FACING_SERVICES,
        RULE_MAX_AFFECTED_PCT,
        RULE_MAX_AFFECTED_NODES,
    }
)

ADMISSION_WIRING_NOTE = (
    "plan 14 ceilings are enforced by controller.safety.check_blast_radius, "
    f"refusing on {sorted(ENFORCED_CEILING_RULE_IDS)} on the same step the preview "
    f"flags them; nothing is pending admission wiring "
    f"[{RULE_PENDING_ADMISSION_WIRING}]"
)

_PENDING_RULE_IDS: frozenset[str] = frozenset(w.rule_id for w in PENDING_ADMISSION_WIRING)


def is_enforced_by_gate(rule_id: str) -> bool:
    """Whether admission is expected to evaluate ``rule_id``.

    Derived from :data:`PENDING_ADMISSION_WIRING` rather than hardcoded per
    dimension, so the table and the records cannot disagree: Phase 4's job was to
    delete a row here, and the ``enforced_by_gate`` field on every ceiling flipped
    with it instead of continuing to claim the rule is unenforced after it was.
    Phase 4 did delete all five, so all five report ``True``.

    The converse assumption is that a rule id *absent* from the table is the
    gate's to enforce — which is what makes the table's completeness
    load-bearing. That is the right default for the five plan-14 controls, whose
    whole job is to end up in admission; a reader who adds a rule here for a
    ceiling the gate should never see would have to say so in the table rather
    than by exception. Because the table is now empty, that default is currently
    unfalsifiable from the table alone — which is why
    :data:`ENFORCED_CEILING_RULE_IDS` exists and why the ceilings suite asserts
    the derivation against the gate's *own* refusals rather than against this
    function's return value.
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
    satisfied.

    ``enforced_by_gate`` is the field a reader checks first, and it is true for
    all five as of Phase 4. It is *derived* from
    :data:`PENDING_ADMISSION_WIRING` (see :func:`is_enforced_by_gate`) rather than
    set here, so emptying that table flipped every record at once instead of
    leaving five stale claims behind. The derivation alone would be an unchecked
    default — an absent rule id reads as "the gate's" — so the ceilings suite
    asserts it against the rule ids the real gate actually refuses.
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


class AgreementState(StrEnum):
    """Where a preview stands against the real gate's refusal.

    Phase 2 computed the two halves of the split and let the report's usability
    fall out of a boolean in a different function. Phase 4 states the rule in one
    place, as a named state, because "some refusals disqualify a preview and
    others do not" is a rule a reader has to be told rather than one they should
    have to reconstruct.

    The three members are ordered by how much has gone wrong, and the ordering is
    the whole point:

    * :attr:`AGREES` — the gate admitted, or refused only rules this preview
      models and flagged. :attr:`GateAgreement.agrees` is true and the report may
      back an approval. Note this is *not* "no violated rules": a preview full of
      flagged rules is exactly what an approver needs.
    * :attr:`UNMODELLED` — "the gate found something this preview cannot speak
      to". Nothing modelled was missed, so ``agrees`` stays true; but the report
      is **unusable for approval**, because a preview that cannot speak to the
      rule which blocked a plan may not back an approval of it.
    * :attr:`DISAGREES` — a refusal from a modelled rule the prediction did not
      flag. A defect, not a state a caller handles:
      :func:`PredictionService.simulate_plan` raises
      :class:`PredictionDisagreementError` instead of returning a report.

    The split exists rather than a single comparison because the gate refuses on
    the **first** breach: its refusal set is one rule, and on a real plan that is
    usually a config-policy denylist, an environment-fingerprint mismatch, or a
    capability gate — rules this preview has no vocabulary for at all. Folding
    those into :func:`~mayhem.domain.prediction.is_never_permissive` would make
    ``agrees`` false for every correctly-scoped preview, and the check would be
    noise nobody could act on.
    """

    AGREES = "agrees"
    UNMODELLED = "unmodelled"
    DISAGREES = "disagrees"

    @property
    def usable_for_approval(self) -> bool:
        """Whether a report in this state may back somebody's approval.

        ``False`` for :attr:`UNMODELLED`, which is the whole reason the state
        exists. :attr:`DISAGREES` never reaches a report — it raises — but it is
        ``False`` here too rather than being a state a caller could mistake for
        a live one.
        """
        return self is AgreementState.AGREES


@dataclass(frozen=True, slots=True)
class GateAgreement:
    """The real gate's refusals beside the prediction's, compared one-directionally.

    ``modelled`` is the part of the gate's refusal set the prediction can speak
    about: rule ids in :data:`~mayhem.domain.prediction.KNOWN_RULE_IDS`.
    ``unmodelled`` is the rest — refusals from rules this preview does not
    evaluate at all.

    Neither half may be dropped, and each is refused differently. :attr:`state` is
    where that decision lives, so it is stated once rather than inferred from
    ``agrees`` and the presence of ``unmodelled`` at every call site:

    * a ``modelled`` refusal the prediction did not flag makes :attr:`state`
      :attr:`AgreementState.DISAGREES`, and
      :func:`PredictionService.simulate_plan` raises rather than return a report;
    * an ``unmodelled`` refusal leaves :attr:`agrees` true and makes the state
      :attr:`AgreementState.UNMODELLED`, which is not usable for approval, because
      a preview that cannot speak to the rule that blocked the plan may not back
      an approval of it.
    """

    gate_refused: frozenset[str]
    modelled: frozenset[str]
    unmodelled: frozenset[str]
    flagged: frozenset[str]
    agrees: bool
    reason: str
    #: Which of the three :class:`AgreementState` members this comparison landed
    #: in. Required rather than defaulted, and checked by :meth:`__post_init__`
    #: against the fields above it. A default would be a lie waiting to be
    #: written: any caller who forgot to state it would get ``AGREES`` beside
    #: ``agrees=False``, and the record would claim the preview was calmer than
    #: the gate while the booleans said the opposite. Making it required means the
    #: omission is a ``TypeError`` at construction rather than a wrong answer at
    #: approval time.
    state: AgreementState

    def __post_init__(self) -> None:
        """Refuse a ``state`` that contradicts :attr:`agrees` or the two sets.

        Phase 4's complaint about the split being emergent is that the rule lived
        outside the record, in a function three call sites away. Giving the record
        a state without this check would move the problem rather than close it: a
        caller could build ``state=UNMODELLED`` beside ``agrees=False`` and the
        report would read "unmodelled" to a surface that never had an unmodelled
        refusal. The two are derived from the same facts, so this insists they are
        derived from the same facts.
        """
        implied = _agreement_state(self.modelled, self.unmodelled, self.agrees)
        if self.state is not implied:
            raise InvariantViolationError(
                RULE_PREDICTION_CALMER_THAN_GATE,
                f"gate agreement claims state {self.state.value!r} while its own sets "
                f"imply {implied.value!r} (modelled={sorted(self.modelled)}, "
                f"unmodelled={sorted(self.unmodelled)}, agrees={self.agrees})",
            )

    @property
    def usable_for_approval(self) -> bool:
        """Whether this agreement, on its own, lets a report back an approval.

        Only about the agreement. A report may still be unusable for a completely
        different reason — a stale prediction, an unresolved target, a walk that
        stopped early — which is what :meth:`SimulateReport.usable_for_approval`
        answers.
        """
        return self.state.usable_for_approval

    def describe(self) -> str:
        if self.state is AgreementState.DISAGREES:
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
    :class:`~mayhem.domain.policy_gate.MutationSink` the caller held, so the
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

    @property
    def agreement_state(self) -> AgreementState:
        """The named agreement state, so a surface need not infer one."""
        return self.agreement.state

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
            f"{self.agreement.describe()} [agreement: {self.agreement.state.value}]",
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
    plan: ExecutionPlan,
    graph: TopologyGraph,
    ctx: SafetyContext,
    *,
    ceilings: BlastCeilings,
) -> tuple[frozenset[str], tuple[SafetyDecision, ...]]:
    """Rule ids the *real* gate refuses, plus the decisions it recorded.

    ``validate_plan`` raises on the first breach, so this is the gate's own
    answer, not a re-derivation of it: a plan refused at step 2 yields the rule
    step 2 broke. A non-``SafetyRefusedError`` domain failure (a policy bundle
    with a drifted pin, a cyclic bundle, an unresolvable selector) is captured the
    same way rather than allowed to escape as an exception the caller cannot
    interpret — a refusal the preview cannot see is not a plan it may describe as
    admissible.

    ``ceilings`` is the *same* set :meth:`PredictionService.predict` used, carried
    in and written onto the probe context. That is the whole point of the
    parameter: since Phase 4 the ceilings are not decoration, ``validate_plan``
    enforces them, so a probe run without them would evaluate a plan under limits
    admission does not hold and report an "admitted" verdict for a plan the real
    gate refuses. The preview would then be calmer than the gate in the one
    direction this module exists to prevent.
    """
    probe = replace(_probe_context(ctx), blast_ceilings=ceilings)
    try:
        validate_plan(plan, graph, probe)
    except SafetyRefusedError as exc:
        rule_id = exc.decision.rule_id if exc.decision is not None else exc.reason_code
        return frozenset({rule_id}), tuple(probe.decisions)
    except DomainError as exc:
        return frozenset({_rule_of(exc)}), tuple(probe.decisions)
    return frozenset(), tuple(probe.decisions)


def _agreement_state(
    modelled: frozenset[str], unmodelled: frozenset[str], agrees: bool
) -> AgreementState:
    """Which :class:`AgreementState` three facts imply. One place, so there is one rule.

    Order matters and is the rule itself: a *disagreement* outranks an
    *unmodelled* refusal, because a modelled rule the prediction missed is a
    defect in the prediction while an unmodelled refusal is a limit of its
    vocabulary. A preview that is both unmodelled and disagreeing is disagreeing,
    and :func:`PredictionService.simulate_plan` raises before the weaker fact can
    be read as an excuse.
    """
    if not agrees:
        return AgreementState.DISAGREES
    if unmodelled:
        return AgreementState.UNMODELLED
    return AgreementState.AGREES


def _agreement(prediction: ImpactPrediction, gate_refused: frozenset[str]) -> GateAgreement:
    """Compare the gate's refusals with the prediction, and name where it landed."""
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
        state=_agreement_state(modelled, unmodelled, agrees),
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
    (now empty) wiring table, so every dimension reports the gate evaluates it
    rather than leaving a reader to infer enforcement from the fact that a number
    appeared. A breach here is now a statement about the *real* gate: the same rule
    id came out of ``validate_plan`` on the same step, or it would have raised.
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


def _policy_verdict(plan: ExecutionPlan, ctx: SafetyContext) -> tuple[PolicyGateResult | None, str]:
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


def _approval_refusal(report: SimulateReport, *, plan: ExecutionPlan, graph: TopologyGraph) -> str:
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

    The one *agreement* reason here is :attr:`AgreementState.UNMODELLED`, and it is
    reached through the state rather than by asking whether a set is non-empty.
    Phase 2's split was emergent — this function read ``.unmodelled`` and the
    disqualification was a side effect — so the rule existed only in the shape of
    the data. Naming it makes the rule the thing a test asserts.
    """
    unmeasured = approval_refusal_reason(report.prediction, graph=graph, plan=plan)
    if unmeasured:
        return unmeasured
    if report.agreement.state is AgreementState.UNMODELLED:
        # Stated through the named state, not re-derived from ``.unmodelled`` being
        # non-empty. Same answer, but a reader of this function can see that the
        # disqualification is a *state of the agreement* — which is testable — and
        # not an inference about a set.
        return (
            f"{RULE_PREDICTION_UNMODELLED_GATE_REFUSAL}: the real gate refused "
            f"{sorted(report.agreement.unmodelled)}, which this preview does not model, "
            f"so it cannot speak to the rule that blocks this plan"
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

    def ceilings(self, ctx: SafetyContext) -> BlastCeilings:
        """The plan-14 ceilings admission will actually enforce, read off ``ctx``.

        Since Phase 4 these are not decoration: ``validate_plan`` refuses on them.
        That makes *which* set of ceilings matters for the first time, and it is
        the same disagreement :meth:`budgets` already guards against in the other
        direction. The context wins over :attr:`config` when it carries any,
        because the context is what admission holds — a preview built from
        ``config.ceilings`` while the gate enforces ``ctx.blast_ceilings`` would
        be checking a plan against limits the gate does not have.

        The merge is *per-field* rather than all-or-nothing, and that is the
        subtle part. A caller who configures the service and the context
        independently should get the union of what each named, not one silently
        replacing the other: taking the context wholesale would silently drop a
        ceiling the operator configured on the service, and taking the config
        wholesale would silently drop one they configured on the context. So each
        of the five dimensions is taken from the context when it names one and
        from the service otherwise.

        When the context names none — the ordinary case for a caller that only
        configured the preview — this returns :attr:`config`'s set unchanged, so
        Phase 2's behaviour is preserved exactly.
        """
        configured = self.config.ceilings
        enforced = ctx.blast_ceilings
        if enforced is None:
            return configured
        return BlastCeilings(
            max_affected_nodes=(
                enforced.max_affected_nodes
                if enforced.max_affected_nodes is not None
                else configured.max_affected_nodes
            ),
            max_dependency_depth=(
                enforced.max_dependency_depth
                if enforced.max_dependency_depth is not None
                else configured.max_dependency_depth
            ),
            max_customer_facing_services=(
                enforced.max_customer_facing_services
                if enforced.max_customer_facing_services is not None
                else configured.max_customer_facing_services
            ),
            max_affected_pct=(
                enforced.max_affected_pct
                if enforced.max_affected_pct is not None
                else configured.max_affected_pct
            ),
            protected_node_ids=(
                enforced.protected_node_ids
                if enforced.protected_node_ids
                else configured.protected_node_ids
            ),
        )

    def predict(self, plan: ExecutionPlan, ctx: SafetyContext) -> ImpactPrediction:
        """The Phase 1 pure function, fed the gate's own limits.

        Delegated rather than reimplemented, so the preview's arithmetic is the
        domain's by construction and a change there cannot leave this call site
        behind. The ceilings come from :meth:`ceilings` rather than straight off
        the config, for the reason that method documents.
        """
        budget, quota = self.budgets(ctx)
        return predict_impact(
            self.graph,
            plan,
            budget=budget,
            quota=quota,
            ceilings=self.ceilings(ctx),
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

        Since Phase 4 there is a fourth thing to keep true, and it is the one
        that made the ceilings enforceable at all: the preview and the gate probe
        are evaluated under *the same* ceilings (see :meth:`ceilings`). A preview
        that checked a plan against limits the gate does not hold would be calmer
        than the gate by construction.

        Raises :class:`PredictionDisagreementError` if the prediction comes out
        calmer than the real gate. Everything else is reported, including the
        reasons that make a preview unusable for approval.
        """
        service = self.detached()
        # One ceilings set, read once, used by all three consumers: the prediction,
        # the gate probe, and the reported dimensions. Reading it three times would
        # be three chances for the gate and the preview to be evaluated under
        # different limits, which is the never-calmer failure in its most basic
        # form.
        effective_ceilings = service.ceilings(ctx)
        prediction = service.predict(plan, ctx)
        gate_refused, gate_decisions = _gate_verdict(
            plan, service.graph, ctx, ceilings=effective_ceilings
        )
        agreement = _agreement(prediction, gate_refused)
        # The only state that raises. DISAGREES means the prediction missed a rule
        # the gate refused on, and a returned report would let a clean preview
        # travel for a plan that cannot run. UNMODELLED is returned: it is a
        # limit of the preview's vocabulary, not a defect in it, and it is
        # carried as the named state that makes the report unusable for approval.
        if agreement.state is AgreementState.DISAGREES:
            raise PredictionDisagreementError(RULE_PREDICTION_CALMER_THAN_GATE, agreement.reason)

        policy, policy_note = _policy_verdict(plan, ctx)
        facts, facts_complete, facts_note = _facts(
            plan, prediction, service.graph, ctx, service.config
        )
        notes = [facts_note, ADMISSION_WIRING_NOTE]
        if policy_note:
            notes.append(policy_note)
        notes.extend(prediction.notes)

        report = SimulateReport(
            artifact=PREDICTION_ARTIFACT,
            prediction=prediction,
            agreement=agreement,
            dimensions=_ceilings(prediction, service.graph, effective_ceilings),
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


# -- Phase 4: sealing the prediction with the plan --------------------------------


class PredictionSealingError(InvariantViolationError):
    """A prediction could not be sealed, read back, or cited.

    An :class:`~mayhem.domain.errors.InvariantViolationError` rather than a bare
    ``DomainError`` so every refusal here carries a ``rule`` a caller can branch
    on and a test can assert — the same treatment
    :data:`RULE_PREDICTION_CALMER_THAN_GATE` gets. The alternative, a rule name
    buried in a message, is what makes a family of refusals impossible to tell
    apart programmatically.
    """


#: The event kind a sealed prediction contributes to its chain.
#:
#: Named here rather than imported, for the reason
#: :mod:`mayhem.controller.proof_sealing` names its own: ``attestation_store``
#: owns the *run-close* event kinds, and the prediction's is a different fact at
#: a different moment in the run. Inventing it inside that module would make that
#: module the owner of a chain it never builds.
EVENT_PREDICTION_SEALED = "prediction.sealed"

#: The attestation scope a prediction seal is stored under, derived from the run.
#:
#: A chain is keyed by this string in ``attestation_chains.run_id`` — a primary
#: key — so the prediction's chain, the run's proof seal (``:proof``), and the
#: run-close chain are keyed differently and cannot overwrite one another. That
#: is the whole reason for a suffix rather than reusing the run id: plan 12's
#: verifier defines a chain as starting at genesis, so a second chain cannot be
#: hung off the first.
PREDICTION_ATTESTATION_SCOPE = ":prediction"


def prediction_scope(run_id: str) -> str:
    """The attestation scope ``run_id``'s prediction seal is stored under.

    Raises:
        InvariantViolationError: If ``run_id`` is blank. A scope is a primary key
            and part of every event id in the chain; an empty one would key an
            entire chain to nothing.
    """
    if not run_id.strip():
        msg = "a prediction seal needs a non-blank run id to name its attestation scope"
        raise InvariantViolationError("prediction_sealing.blank_run_id", msg)
    return f"{run_id}{PREDICTION_ATTESTATION_SCOPE}"


@dataclass(frozen=True, slots=True)
class SealedPrediction:
    """A prediction sealed into plan 12's chain, plus the verdicts proving it.

    ``evidence_ref`` is the citation: whatever ran before this and produced the
    prediction — a preflight digest, a safety-proof digest, a simulate-report
    digest. It is *required*, not optional, because a sealed prediction that
    names nothing it was computed from is a number with no provenance, and
    "we predicted this" is not the whole of a record an auditor has to act on.
    :func:`seal_prediction` refuses a blank one.

    The seal attests integrity, never authorship: :attr:`signed` is always
    ``False`` and :attr:`signature_reason` says why, because plan 12 Phase 2
    mints no signature bytes and naming a signer would turn "integrity
    verified" into "authorship verified".
    """

    run_id: str
    scope: str
    prediction: ImpactPrediction
    prediction_digest: str
    evidence_ref: str
    events: tuple[AttestedEvent, ...]
    manifest: Manifest
    signature_state: str
    signature_reason: str
    chain_verification: ChainVerification
    manifest_verification: ManifestVerification
    #: The preview presentation structure sealed alongside the prediction, as
    #: stored — ``None`` when the seal was made without one. What a UI renders
    #: is this payload, not a re-derivation, so post-run analysis reads what an
    #: approver was actually shown.
    preview_payload: dict[str, Any] | None = None

    @property
    def signed(self) -> bool:
        """Always False — plan 12 Phase 2 signs nothing."""
        return self.manifest.signed

    @property
    def manifest_digest(self) -> str:
        """What a later manifest (the run-close seal) chains to."""
        return self.manifest.manifest_digest

    @property
    def chain_root(self) -> str:
        """The root the manifest commits to."""
        return self.events[-1].chain_link if self.events else GENESIS_DIGEST


@dataclass(frozen=True, slots=True)
class PredictionAccuracy:
    """How a sealed prediction compared to what the run actually did.

    ``unpredicted_node_ids`` is the whole finding. A node inside the observed
    blast that the prediction never named is a node the preview was *calmer*
    about than reality — the one direction this whole module exists to prevent,
    discovered after the fact. Any of them means
    :attr:`understated` is true and the run opens a finding under
    :data:`RULE_PREDICTION_BLAST_EXCEEDED` rather than passing silently.

    The opposite direction is named too, and deliberately is *not* a finding about
    the run: ``overstated_node_ids`` is a preview that over-estimated, which is
    the conservative failure this module is built around. It is reported so an
    analyst can see a forecast that was pessimistic rather than discovering it by
    comparing numbers later, but it never opens a finding and never makes
    :attr:`holds` false.

    ``accuracy_pct`` is the share of the observed blast the prediction named, and
    is ``None`` when the observation is empty — an unmeasurable ratio is not
    ``0.0``, because ``0.0`` would read as "the prediction was right about
    nothing", which is a different claim.
    """

    plan_identity: str
    evidence_ref: str
    predicted_node_ids: tuple[str, ...]
    actual_node_ids: tuple[str, ...]
    unpredicted_node_ids: tuple[str, ...]
    overstated_node_ids: tuple[str, ...]
    predicted_fan_out_depth: int
    actual_fan_out_depth: int | None
    accuracy_pct: float | None
    finding: str

    @property
    def understated(self) -> bool:
        """Whether the run's blast reached nodes the prediction did not name."""
        return bool(self.unpredicted_node_ids)

    @property
    def holds(self) -> bool:
        """Whether the forecast was safe to rely on. The opposite of a finding."""
        return not self.understated

    def describe(self) -> str:
        if self.understated:
            return (
                f"prediction understated the blast by {len(self.unpredicted_node_ids)} "
                f"node(s) {list(self.unpredicted_node_ids)} [{RULE_PREDICTION_BLAST_EXCEEDED}]: "
                f"{self.finding}"
            )
        if self.overstated_node_ids:
            return (
                f"prediction held: named all {len(self.actual_node_ids)} observed "
                f"node(s), over-estimating {len(self.overstated_node_ids)} "
                f"{list(self.overstated_node_ids)}"
            )
        return (
            f"prediction held exactly: {len(self.actual_node_ids)} observed node(s), all predicted"
        )


def score_prediction_accuracy(
    sealed: SealedPrediction | LoadedPrediction,
    *,
    actual_node_ids: Sequence[str],
    actual_fan_out_depth: int | None = None,
) -> PredictionAccuracy:
    """Compare a sealed prediction against what a run actually did.

    Plan 14 §Phase 4's acceptance criterion, as a function: "a run whose actual
    blast exceeded prediction opens a finding, not a silent pass".

    "Exceeded" is read as a *set* question, not a count question, and that is the
    load-bearing choice. A run that reached six nodes where the prediction named
    five is not thereby safe: the sixth is a node nobody told an approver about.
    So any observed id the prediction did not name opens the finding, and the ids
    are named — a reader can go and look at the sixth node rather than re-derive
    it from a count.

    Args:
        sealed: Either the record :func:`seal_prediction` returned or the one
            :func:`verify_sealed_prediction` read back off stored bytes, since both
            carry the two fields this reads — the prediction and the citation.
            Accepting both is deliberate rather than convenient: the seal-time
            record is in-process and a caller could score it, but the *legitimate*
            caller is a post-run analysis hours later holding only what it can
            reload, and a signature that accepted only the first would force that
            analysis to either fabricate a seal-time record or skip the check.
        actual_node_ids: What the run actually affected.
        actual_fan_out_depth: How far the damage actually propagated, when the
            caller measured it. ``None`` — the default — means "not measured", and
            the record says so rather than defaulting to the predicted depth,
            which would make an unmeasured run look accurate.

    Returns:
        A :class:`PredictionAccuracy`. Never raises: an inaccuracy is a finding
        to report, not an error. A *caller* that refuses to act on a finding is
        the caller's business.
    """
    predicted = tuple(sealed.prediction.affected_node_ids)
    observed = tuple(sorted(set(actual_node_ids)))
    predicted_set = frozenset(predicted)
    observed_set = frozenset(observed)
    named = predicted_set.intersection(observed_set)
    unpredicted = tuple(sorted(observed_set - predicted_set))
    overstated = tuple(sorted(predicted_set - observed_set))
    accuracy = round(len(named) / len(observed_set) * 100.0, 3) if observed_set else None
    finding = ""
    if unpredicted:
        finding = (
            f"the run affected {len(observed)} node(s) but the prediction named only "
            f"{len(named)} of them; {list(unpredicted)} were not in the forecast"
        )
    return PredictionAccuracy(
        plan_identity=sealed.prediction.plan_identity,
        evidence_ref=sealed.evidence_ref,
        predicted_node_ids=predicted,
        actual_node_ids=observed,
        unpredicted_node_ids=unpredicted,
        overstated_node_ids=overstated,
        predicted_fan_out_depth=sealed.prediction.fan_out.max_depth,
        actual_fan_out_depth=actual_fan_out_depth,
        accuracy_pct=accuracy,
        finding=finding,
    )


def prediction_seal_event(
    prediction: ImpactPrediction,
    *,
    run_id: str,
    recorded_at: AttestedTimestamp,
    evidence_ref: str,
    preview_payload: Mapping[str, Any] | None = None,
) -> AttestedEvent:
    """The one event a prediction seal contributes.

    Pure, and *referencing* rather than re-deriving: the payload carries the
    prediction in full (so it reloads byte-identically), plus the citation and
    the digest. The full body is deliberate and is the one place this module
    stores an artifact rather than a pointer to it — a post-run scoring pass has
    to be able to reconstruct the *prediction*, and a digest alone would leave it
    needing the prediction to still exist somewhere.

    ``preview_payload`` is the presentation structure sealed alongside the
    prediction — the ``RiskPreviewView`` payload a UI renders, built by the
    surface that showed it and handed here as data. It travels inside this same
    event rather than in a second chain because the acceptance criterion is
    "preview output stored *with the plan*": one seal, one scope, one manifest
    to verify. This module never builds it — it has no view-model to build it
    from — so an unreadable one is refused here, at the boundary, rather than
    written as a row nobody can render. ``None`` means the seal was made without
    one, and the key is then omitted rather than stored as null, so seals made
    before the preview existed read back unchanged.

    Raises:
        PredictionSealingError: If ``evidence_ref`` is blank. Refused here rather
            than at write time so the same check guards every path that produces
            an event.
        PredictionSealingError: If ``preview_payload`` is present but is not a
            readable presentation structure (not a dict, no schema version, or
            not JSON-serialisable).
    """
    if not evidence_ref.strip():
        raise PredictionSealingError(
            RULE_PREDICTION_NOT_CITED,
            f"refusing to build a prediction seal event for run {run_id!r}: "
            f"evidence_ref is blank, so the prediction would be sealed with nothing "
            f"naming what it was computed from. A prediction that cites no evidence "
            f"cannot back a decision, and an uncited one in the chain cannot be "
            f"read back as a forecast anybody stood behind",
        )
    sealed_preview = _normalise_preview(preview_payload, run_id=run_id)
    event_payload: dict[str, Any] = {
        "prediction_digest": digest_of(_prediction_payload(prediction)),
        "evidence_ref": evidence_ref,
        "run_id": run_id,
        "plan_identity": prediction.plan_identity,
        "graph_identity": prediction.graph_identity,
        "schema_version": prediction.schema_version,
        "predicted_node_ids": list(prediction.affected_node_ids),
        "predicted_fan_out_depth": prediction.fan_out.max_depth,
        "prediction": _prediction_payload(prediction),
    }
    if sealed_preview is not None:
        event_payload[PREVIEW_PAYLOAD_KEY] = sealed_preview
    return AttestedEvent(
        event_id=f"{prediction_scope(run_id)}:sealed",
        event_kind=EVENT_PREDICTION_SEALED,
        run_id=prediction_scope(run_id),
        sequence=0,
        payload=event_payload,
        recorded_at=recorded_at,
    )


def seal_prediction(
    store: Store,
    prediction: ImpactPrediction,
    *,
    run_id: str,
    recorded_at: AttestedTimestamp,
    evidence_ref: str,
    retention_class: RetentionClass | None = None,
    manifest_id: str = "",
    previous_manifest_digest: str = GENESIS_DIGEST,
    signer: object | None = None,
    preview_payload: Mapping[str, Any] | None = None,
) -> SealedPrediction:
    """Seal a prediction with its plan, pre-execution, into plan 12's chain machinery.

    The seam the run path calls between "the preview was shown" and the first
    fault step runs. Every stage is plan 12's and
    :mod:`mayhem.controller.proof_sealing`'s: :func:`~mayhem.domain.attestation.seal_events`
    wires the links, :func:`~mayhem.domain.attestation.build_manifest` commits to
    the event digest, the two verifiers check both before anything is written, and
    :class:`~mayhem.infra.attestation_store.AttestationRepository` persists into
    the same M0023 tables. Nothing is re-hashed here and no table is created —
    a bespoke ``predictions`` table would be a second thing an auditor would have
    to trust.

    Args:
        store: The migrated store.
        prediction: The prediction to seal. Any prediction is sealed, including
            one that flagged breaches and one whose walk truncated: a sealed
            inaccurate forecast is a true and useful record, and refusing it would
            lose the artifact that
            :func:`score_prediction_accuracy` later needs.
        run_id: The run the prediction belongs to.
        recorded_at: The reading to stamp the event with (tests inject one).
        evidence_ref: What the prediction was computed from — a preflight or
            safety-proof digest. **Required and non-blank.**
        retention_class: Defaults to ``HOT``, matching the run-close seal.
        manifest_id: Defaults to ``<run_id>:prediction:manifest``.
        previous_manifest_digest: The manifest this seal chains to; pass the
            prior run's digest to link runs, or the proof seal's.
        signer: The Phase 6 signing seam. There is no implementation, and naming
            one is refused for the reason
            :func:`~mayhem.infra.attestation_store.seal_run_evidence` refuses it.
        preview_payload: The presentation structure sealed alongside the
            prediction — the ``RiskPreviewView`` payload a surface renders,
            built by that surface and handed here as data. Sealing writes to the
            store; it never computes anything, so the stored bytes are the
            surface's own and a reload is an equality check rather than a
            re-derivation. ``None`` seals the prediction alone, exactly as
            before. A read-only preview command must not own a write path, so
            this parameter is how the half of plan 14's acceptance criterion
            that says "stored with the plan" is met without giving one to it:
            the seal-time caller passes what was shown, and the store holds it.

    Raises:
        PredictionSealingError: If ``evidence_ref`` is blank. Nothing is written.
        PredictionSealingError: If ``preview_payload`` is present but unreadable.
            Nothing is written.
        SigningNotImplementedError: If a signer is supplied.
        InvariantViolationError: If ``run_id`` is blank.
        AttestationError: If the derived chain or manifest fails verification, in
            which case nothing is written.
    """
    if signer is not None:
        raise SigningNotImplementedError(
            "plan 12 Phase 2 mints no signature bytes: no key material, KMS/HSM "
            "custody or Sigstore integration exists, so naming a signer would claim "
            "an authentication that was never performed. The manifest is written "
            f"unsigned and the reason is stored: {UNSIGNED_REASON_NO_SIGNING}"
        )
    scope = prediction_scope(run_id)
    # Raised before anything is built, so a blank citation costs no work.
    events = seal_events(
        [
            prediction_seal_event(
                prediction,
                run_id=run_id,
                recorded_at=recorded_at,
                evidence_ref=evidence_ref,
                preview_payload=preview_payload,
            )
        ]
    )
    manifest = build_manifest(
        events,
        manifest_id=manifest_id or f"{run_id}:prediction:manifest",
        run_id=scope,
        signer_identity="",
        trust_root_ref="",
        retention_class=(retention_class if retention_class is not None else RetentionClass.HOT),
        created_at=recorded_at,
        previous_manifest_digest=previous_manifest_digest,
    )
    chain_verification = verify_chain(events)
    if not chain_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid prediction chain for run {run_id!r}: "
            f"{'; '.join(chain_verification.errors)}"
        )
    manifest_verification = verify_manifest(manifest, events)
    if not manifest_verification.valid:
        raise AttestationError(
            f"refusing to persist an invalid prediction manifest for run {run_id!r}: "
            f"{'; '.join(manifest_verification.errors)}"
        )
    repository = AttestationRepository(store)
    repository.save_chain(scope, events, sealed_at=recorded_at.wall_clock)
    repository.save_manifest(manifest)
    stored_preview = events[0].payload.get(PREVIEW_PAYLOAD_KEY)
    return SealedPrediction(
        run_id=run_id,
        scope=scope,
        prediction=prediction,
        prediction_digest=digest_of(_prediction_payload(prediction)),
        evidence_ref=evidence_ref,
        events=events,
        manifest=manifest,
        signature_state=SIGNATURE_UNSIGNED_NO_SIGNING,
        signature_reason=UNSIGNED_REASON_NO_SIGNING,
        chain_verification=chain_verification,
        manifest_verification=manifest_verification,
        # Read off the built event rather than normalised a second time, so the
        # record carries the stored bytes themselves — a second normalisation
        # could only agree by coincidence.
        preview_payload=dict(stored_preview) if stored_preview is not None else None,
    )


@dataclass(frozen=True, slots=True)
class LoadedPrediction:
    """A sealed prediction read back off stored bytes, with its citation.

    What :func:`verify_sealed_prediction` hands a post-run scoring pass. It is the
    reconstructed :class:`~mayhem.domain.prediction.ImpactPrediction` itself, not
    a summary: scoring has to compare against the numbers that were sealed, or
    it is scoring against something else. :attr:`prediction_digest` and
    :attr:`evidence_ref` are re-read from the stored payload rather than taken on
    trust, and the chain and manifest are both re-verified from their own bytes
    before this record is constructed.
    """

    run_id: str
    scope: str
    prediction: ImpactPrediction
    prediction_digest: str
    evidence_ref: str
    #: The preview presentation structure read back off stored bytes, or ``None``
    #: when the seal was made without one. It is the payload a UI renders, not a
    #: re-derivation of it — which is what makes "rendered identically in CLI and
    #: UI" a property of stored bytes rather than of two renderers agreeing today.
    preview_payload: dict[str, Any] | None = None


def verify_sealed_prediction(store: Store, run_id: str) -> tuple[LoadedPrediction | None, str]:
    """Reload a run's sealed prediction and re-verify it, or say why it cannot be read.

    Returns ``(record, "")`` on success and ``(None, reason)`` otherwise — a
    named reason, never a bare ``None``, because the caller is a post-run analysis
    deciding whether it has a forecast to score against at all.

    Five things are checked, in that order, and each has its own failure shape:

    1. a chain exists under the prediction's scope, and a
       :data:`EVENT_PREDICTION_SEALED` event is in it;
    2. the stored chain verifies with the domain verifier and its stored root
       matches the recomputed one — the same check
       :meth:`~mayhem.infra.attestation_store.AttestationRepository.verify_run_chain`
       makes, so a row edited to name a different root than its events produce is
       rejected;
    3. the stored manifest verifies against the reloaded events;
    4. the payload reconstructs into an
       :class:`~mayhem.domain.prediction.ImpactPrediction` whose digest matches the
       one recorded at seal time — which is what catches an event body edited to
       name a prediction it no longer carries.
    5. the sealed preview payload, when the seal carries one, is a readable
       presentation structure — a dict with a schema version — so a UI is never
       handed bytes no renderer can claim to read. A seal made without one reads
       back as ``None``, not as an error, because seals predate the preview.

    A record whose ``evidence_ref`` is blank is not returned: a prediction that
    cites no evidence cannot back a decision, and handing one to
    :func:`score_prediction_accuracy` would let it be scored as though it could.

    The checks are split into helpers purely so each refusal is one ``return``.
    That is a readability trade, and it is worth it here because this function's
    entire value is the *reasons* — a caller that gets a bare ``None`` cannot tell
    an unsealed run from a tampered one.
    """
    repository = AttestationRepository(store)
    scope = prediction_scope(run_id)
    events = repository.load_chain(scope)
    seal = next((e for e in events if e.event_kind == EVENT_PREDICTION_SEALED), None)
    if seal is None:
        # One message for both "nothing stored" and "stored, but not a prediction
        # seal": from the caller's side those are the same situation — there is
        # no forecast here — and distinguishing them would be a distinction the
        # post-run analysis cannot act on differently.
        return None, (
            f"no {EVENT_PREDICTION_SEALED} event stored for run {run_id!r} (scope {scope!r})"
        )
    chain_verification = repository.verify_run_chain(scope)
    if not chain_verification.valid:
        return None, (
            f"the prediction chain for run {run_id!r} does not verify: "
            f"{'; '.join(chain_verification.errors)}"
        )
    manifest_error = _verify_prediction_manifest(repository, run_id, events)
    if manifest_error:
        return None, manifest_error
    body_error, loaded = _reconstruct_seal(seal, run_id=run_id, scope=scope)
    if body_error:
        return None, body_error
    return loaded, ""


def _reconstruct_seal(
    seal: AttestedEvent, *, run_id: str, scope: str
) -> tuple[str, LoadedPrediction | None]:
    """The seal's payload turned back into a :class:`LoadedPrediction`, or why not.

    Four refusals live here: a body this module cannot read field by field, a
    body whose digest does not match the one recorded beside it, a body that
    cites no evidence, and a preview payload that cannot be rendered. The last
    three are what catch an edited row — a chain whose links still verify can
    still carry a payload that was swapped after the fact, and a hash chain only
    guarantees that the *bytes were not edited*, never that the bytes are the
    right ones.

    Returns ``(reason, None)`` on refusal, ``("", record)`` on success.
    """
    body_error, prediction = _reload_prediction_body(seal.payload)
    if body_error:
        return body_error, None
    digest = digest_of(_prediction_payload(prediction))
    recorded = str(seal.payload.get("prediction_digest", ""))
    if digest != recorded:
        return (
            f"the sealed prediction for run {run_id!r} does not match its own digest: "
            f"recomputed {digest[:12]}, event records {recorded[:12]}",
            None,
        )
    evidence_error, evidence_ref = _cited_evidence(seal.payload, run_id)
    if evidence_error:
        return evidence_error, None
    preview_error, preview = _sealed_preview(seal.payload, run_id)
    if preview_error:
        return preview_error, None
    return (
        "",
        LoadedPrediction(
            run_id=run_id,
            scope=scope,
            prediction=prediction,
            prediction_digest=digest,
            evidence_ref=evidence_ref,
            preview_payload=preview,
        ),
    )


def _normalise_preview(preview: Mapping[str, Any] | None, *, run_id: str) -> dict[str, Any] | None:
    """A preview payload as storable bytes, or why it cannot be stored.

    ``None`` stays ``None`` — a seal made without a preview is legitimate, and
    the key is omitted rather than stored as null because a null where a
    structure belongs reads as "there was nothing to show", which is a different
    claim from "this seal predates the preview". Anything present must be a dict
    carrying a ``schema_version`` string: without a version a reader cannot tell
    which presentation contract the bytes were written under, and a version it
    cannot name is a row nobody can render. The JSON round trip both proves
    serialisability and normalises what the store will return — tuples become
    lists, ints that JSON cannot distinguish stay comparable — so what
    :func:`verify_sealed_prediction` hands back compares equal to what was
    sealed rather than to something that merely resembles it.

    Raises:
        PredictionSealingError: If ``preview`` is present but unreadable.
    """
    if preview is None:
        return None
    if not isinstance(preview, dict):
        raise PredictionSealingError(
            RULE_PREDICTION_PREVIEW_UNREADABLE,
            f"refusing to seal a preview payload for run {run_id!r}: it is "
            f"{type(preview).__name__}, not a presentation structure, so nothing "
            f"stored under {PREVIEW_PAYLOAD_KEY!r} could be rendered back",
        )
    version = preview.get("schema_version")
    if not isinstance(version, str) or not version.strip():
        raise PredictionSealingError(
            RULE_PREDICTION_PREVIEW_UNREADABLE,
            f"refusing to seal a preview payload for run {run_id!r} with no schema "
            f"version: a stored preview nobody can version is a stored preview "
            f"nobody can render",
        )
    try:
        round_tripped: dict[str, Any] | None = json.loads(json.dumps(preview))
        return round_tripped
    except (TypeError, ValueError) as exc:
        raise PredictionSealingError(
            RULE_PREDICTION_PREVIEW_UNREADABLE,
            f"refusing to seal a preview payload for run {run_id!r} that is not "
            f"JSON-serialisable ({exc}): a seal that cannot be read back is not a seal",
        ) from exc


def _sealed_preview(
    payload: Mapping[str, object], run_id: str
) -> tuple[str, dict[str, Any] | None]:
    """The seal's preview payload, or the reason it cannot back a rendering.

    Absent (or explicitly null, which old seals never write but a hand-edited
    row could carry) means the seal was made without one, and reads back as
    ``None`` rather than as an error — seals predate the preview and must keep
    reading. Present but unreadable is a refusal, for the same reason a digest
    mismatch is: the chain proves the bytes were not edited, never that the
    bytes are the right ones, and a preview that reloads with its version
    missing would render under a contract nobody named.

    Returns ``(reason, None)`` on refusal, ``("", preview)`` on success.
    """
    if PREVIEW_PAYLOAD_KEY not in payload:
        return "", None
    raw = payload.get(PREVIEW_PAYLOAD_KEY)
    if raw is None:
        return "", None
    if not isinstance(raw, dict):
        return (
            f"the sealed preview for run {run_id!r} is {type(raw).__name__}, not a "
            f"presentation structure, so it cannot be rendered",
            None,
        )
    version = raw.get("schema_version")
    if not isinstance(version, str) or not version.strip():
        return (
            f"the sealed preview for run {run_id!r} carries no schema version, so no "
            f"renderer can claim to read it",
            None,
        )
    return "", dict(raw)


def _cited_evidence(payload: Mapping[str, object], run_id: str) -> tuple[str, str]:
    """The seal's ``evidence_ref``, or the reason it cannot back a decision.

    A prediction that cites nothing it was computed from is a number with no
    provenance, so this is a refusal rather than an empty string handed on. It is
    checked here rather than in :func:`seal_prediction` alone because a row can
    be edited after the fact, and the whole point of reading a seal back is that
    what comes out is what went in.

    Returns ``("", evidence_ref)`` on success.
    """
    evidence_ref = str(payload.get("evidence_ref", ""))
    if evidence_ref.strip():
        return "", evidence_ref
    return (
        f"the sealed prediction for run {run_id!r} cites no evidence, so it cannot "
        f"back a decision: re-seal it with the digest of whatever produced it "
        f"(a preflight, a safety proof, a simulate report)",
        "",
    )


def _verify_prediction_manifest(
    repository: AttestationRepository, run_id: str, events: Sequence[AttestedEvent]
) -> str:
    """Re-verify the prediction's stored manifest against the reloaded chain.

    ``""`` when it verifies; the reason when it does not. Split out of
    :func:`verify_sealed_prediction` so that function's refusal paths are one
    ``return`` each and stay readable.

    The manifest id is *derived* rather than read off the event payload: it is
    ``<run_id>:prediction:manifest`` by construction (see :func:`seal_prediction`),
    and trusting a caller-writable payload key to name the manifest to verify
    would let a hand-edited row redirect the check at a manifest that does verify.
    """
    manifest_id = f"{run_id}:prediction:manifest"
    manifest = repository.load_manifest(manifest_id)
    if manifest is None:
        return f"no manifest {manifest_id!r} stored for run {run_id!r}'s prediction seal"
    verification = verify_manifest(manifest, events)
    if verification.valid:
        return ""
    return (
        f"the prediction manifest for run {run_id!r} does not verify: "
        f"{'; '.join(verification.errors)}"
    )


def _reload_prediction_body(payload: Mapping[str, object]) -> tuple[str, ImpactPrediction]:
    """Reconstruct the sealed prediction, or say why the body is unreadable.

    The digest check happens in the caller, *after* this returns: reconstructing
    and then hashing is what makes the digest check meaningful, because a payload
    edited to name a prediction it no longer carries reconstructs to something
    whose digest no longer matches.

    A body that is not an object, or one this module cannot read field by field,
    is a refusal rather than a default. A prediction that reloads with a field
    silently filled in is a prediction that would score a run against numbers it
    never made — the one failure a sealed forecast cannot have.
    """
    raw = payload.get("prediction")
    if not isinstance(raw, dict):
        return (
            f"the {EVENT_PREDICTION_SEALED} event carries no prediction body, so there "
            f"is nothing to reload",
            _EMPTY_PREDICTION,
        )
    try:
        return "", _prediction_from_payload(raw)
    except PredictionSealingError as exc:
        return str(exc), _EMPTY_PREDICTION


#: The value :func:`_reload_prediction_body` returns alongside a failure reason, so
#: the caller has a well-typed value it must not use. Never handed out: every
#: path that returns one also returns a non-empty reason, and the reason is what
#: the caller checks first.
_EMPTY_PREDICTION: ImpactPrediction = ImpactPrediction(
    plan_identity="",
    graph_identity="",
    basis=PredictionBasis.EMPTY_GRAPH,
)


# -- the prediction's own bytes ----------------------------------------------------


def _prediction_payload(prediction: ImpactPrediction) -> dict[str, Any]:
    """A prediction as JSON-native data, field for field.

    :func:`dataclasses.asdict` over the frozen tree is what keeps this total —
    there is no field a caller can add to
    :class:`~mayhem.domain.prediction.ImpactPrediction` that this drops, because
    the walk is over the dataclass rather than over a hand-written list. The
    ``json`` round trip then normalises what ``asdict`` leaves alone: tuples
    become lists and the :class:`~mayhem.domain.prediction.PredictionBasis` member
    becomes its string value, which is the form the chain actually stores.

    The return type is ``dict[str, Any]`` rather than ``dict[str, object]``
    because the value is *untrusted* JSON on the way back in, and typing it as
    ``object`` would push a cast or a ``type: ignore`` into every one of the ~60
    field reads in :func:`_prediction_from_payload`. The runtime checks live in
    :func:`_body` and :func:`_list_of`, which is where an unknown shape is
    actually caught; the annotations here are a convenience for the decoder, not
    the safety mechanism.

    The round trip also *normalises numbers*, and that is load-bearing rather
    than incidental. A prediction whose per-step costs are empty has
    ``affected_node_seconds == 0`` (an ``int``, from summing nothing) while the
    same prediction after a reload has ``0.0`` (a ``float``, from the field's own
    annotation). The two are equal under ``==``, so a reload-equality check passes
    — but :func:`mayhem.domain.hashing.digest` is over *canonical bytes*, and
    ``0`` and ``0.0`` serialise differently. Without this normalisation the
    digest taken at seal time and the one recomputed on read back would differ
    for a prediction that never changed, and every sealed forecast would be
    unreadable.
    """
    payload: dict[str, Any] = json.loads(json.dumps(asdict(prediction), default=str))
    normalised: dict[str, Any] = _normalise_numbers(payload)
    return normalised


def _normalise_numbers(value: Any) -> Any:
    # (typed ``Any`` in, ``Any`` out — this is a recursive walk over untrusted
    # JSON, so the annotations below are documentation of the shapes handled, not
    # a claim the caller may rely on.)
    """Every number in a sealed body becomes a ``float``, recursively.

    Applied to the payload rather than to the decode side because it has to be
    the *encoder* that decides: the digest is taken over the encoded bytes, so
    normalising there means the recorded digest and the recomputed one are taken
    over the same normalisation by construction. Doing it only on the way out
    would leave the seal-time digest over ``0`` and the read-back digest over
    ``0.0``, which is the bug this function exists to prevent.

    ``bool`` is excluded because ``bool`` is a subclass of ``int`` and
    ``True`` must not become ``1.0`` — ``capacity_known`` and ``targeted`` are
    real booleans whose meaning a score depends on.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return float(value)
    if isinstance(value, dict):
        return {key: _normalise_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalise_numbers(item) for item in value]
    return value


def _prediction_from_payload(payload: dict[str, Any]) -> ImpactPrediction:
    """Rebuild a prediction from what :func:`_prediction_payload` produced.

    Explicit rather than reflective, for two reasons a reviewer should weigh
    rather than take on trust: an ``asdict``-shaped dict has lost the type
    information a generic decoder would need to pick the right constructor, and a
    *silent* key mismatch is worse here than anywhere else in this module — a
    prediction that reloads with one field defaulted is a prediction that scores
    a run against numbers it never made. So every field is read by name, each
    nested object is shape-checked by :func:`_body`, and anything unexpected is a
    refusal.

    Raises:
        PredictionSealingError: If the body is not shaped like a prediction, or a
            field it must carry is absent or the wrong type.
    """
    fan_out = _body(payload, "fan_out")
    replica = _body(payload, "replica_loss")
    cost = _body(payload, "cost")
    truncated = payload["truncated_at_step"]
    try:
        return ImpactPrediction(
            plan_identity=str(payload["plan_identity"]),
            graph_identity=str(payload["graph_identity"]),
            basis=PredictionBasis(str(payload["basis"])),
            steps=tuple(
                StepImpact(
                    step_id=str(step["step_id"]),
                    step_index=int(step["step_index"]),
                    fault_id=str(step["fault_id"]),
                    target_ids=_strings(step, "target_ids"),
                    affected_ids=_strings(step, "affected_ids"),
                    services_hit=int(step["services_hit"]),
                    services_total=int(step["services_total"]),
                    services_pct=float(step["services_pct"]),
                    hosts_hit=int(step["hosts_hit"]),
                    duration_s=float(step["duration_s"]),
                    node_count=int(step["node_count"]),
                    damage_s=float(step["damage_s"]),
                )
                for step in _list_of(payload, "steps")
            ),
            affected_node_ids=_strings(payload, "affected_node_ids"),
            unresolved_target_ids=_strings(payload, "unresolved_target_ids"),
            fan_out=DependencyFanOut(
                nodes=tuple(
                    NodeDepth(
                        node_id=str(node["node_id"]),
                        kind=str(node["kind"]),
                        depth=int(node["depth"]),
                        targeted=bool(node["targeted"]),
                    )
                    for node in _list_of(fan_out, "nodes")
                ),
                max_depth=int(fan_out["max_depth"]),
            ),
            replica_loss=ReplicaLoss(
                groups=tuple(
                    ReplicaGroupLoss(
                        group_id=str(group["group_id"]),
                        members=_strings(group, "members"),
                        lost=_strings(group, "lost"),
                    )
                    for group in _list_of(replica, "groups")
                ),
                measured=bool(replica["measured"]),
            ),
            expected_capacity_change_pct=float(payload["expected_capacity_change_pct"]),
            capacity_known=bool(payload["capacity_known"]),
            violated_rules=tuple(
                ViolatedRule(
                    rule_id=str(rule["rule_id"]),
                    step_id=str(rule["step_id"]),
                    step_index=int(rule["step_index"]),
                    fault_id=str(rule["fault_id"]),
                    observed=None if rule["observed"] is None else float(rule["observed"]),
                    limit=None if rule["limit"] is None else float(rule["limit"]),
                    unit=str(rule["unit"]),
                    detail=str(rule["detail"]),
                    observed_ids=_strings(rule, "observed_ids"),
                    remediation=str(rule["remediation"]),
                )
                for rule in _list_of(payload, "violated_rules")
            ),
            cost=CostEstimate(
                currency=str(cost["currency"]),
                priced=bool(cost["priced"]),
                basis=str(cost["basis"]),
                affected_node_seconds=float(cost["affected_node_seconds"]),
                total_usd=float(cost["total_usd"]),
                per_step=tuple(
                    StepCost(
                        step_id=str(step["step_id"]),
                        fault_id=str(step["fault_id"]),
                        affected_nodes=int(step["affected_nodes"]),
                        duration_s=float(step["duration_s"]),
                        affected_node_seconds=float(step["affected_node_seconds"]),
                        usd=float(step["usd"]),
                    )
                    for step in _list_of(cost, "per_step")
                ),
            ),
            truncated_at_step=None if truncated is None else int(truncated),
            notes=_strings(payload, "notes"),
            schema_version=str(payload["schema_version"]),
        )
    except PredictionSealingError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PredictionSealingError(
            "prediction_sealing.unreadable_payload",
            f"the sealed prediction body is not a readable {ImpactPrediction.__name__}: {exc}",
        ) from exc


def _body(payload: dict[str, Any], key: str) -> dict[str, Any]:
    """One nested object of a sealed prediction body, shape-checked.

    ``asdict`` produces ``{"nodes": [...], "max_depth": 3}`` where
    :class:`~mayhem.domain.prediction.DependencyFanOut` wants two arguments, so a
    nested object has to be pulled apart explicitly rather than splatted. This is
    the one place that pull-apart is checked, so a body hand-edited to put a list
    where an object belongs is a refusal rather than an ``AttributeError`` three
    frames deeper.
    """
    value = payload.get(key)
    if not isinstance(value, dict):
        raise PredictionSealingError(
            "prediction_sealing.unreadable_payload",
            f"sealed prediction field {key!r} is {type(value).__name__}, not an object",
        )
    return value


def _list_of(payload: dict[str, Any], key: str) -> list[Any]:
    """One list-shaped field of a sealed prediction body, shape-checked.

    A ``str`` is deliberately *not* accepted as a list: ``"abc"`` is a
    ``Sequence``, and letting one through would turn a mangled body into a
    three-element tuple of single characters rather than an error.
    """
    value = payload.get(key)
    if not isinstance(value, list):
        raise PredictionSealingError(
            "prediction_sealing.unreadable_payload",
            f"sealed prediction field {key!r} is {type(value).__name__}, not a list",
        )
    return value


def _strings(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    """One tuple-of-strings field, shape-checked, as a tuple.

    Every id list on a prediction round-trips through ``json`` as a list, and
    every one of them is read back as a tuple: a caller comparing
    ``prediction.affected_node_ids == (...)`` must not fail because the reload
    produced a list.
    """
    return tuple(str(item) for item in _list_of(payload, key))
