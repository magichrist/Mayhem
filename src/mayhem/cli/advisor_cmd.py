"""``mayhem advisor`` — the reliability advisor's surface: a dashboard, an
incident-to-experiment flow, and the scenario library browser
(docs/v1.1.0/21_RELIABILITY_ADVISOR.md, Phase 3).

Phases 1-2 proved the arithmetic (:mod:`mayhem.domain.advisor`) and the engine
(:mod:`mayhem.controller.advisor_service`), and Phase 4 proved the boundary. None
of it is reachable by a person. This module is the button — and most of its
length is not the buttons.

## The view-model layer is the guarantee, not the callback

Plan 21's Phase 3 acceptance is *a recommendation without a traceable rationale
cannot render, tested at the view-model layer*. So there is a view-model layer:
pure dataclasses in this module that take engine output and return something a
renderer — this module's text renderer today, plan 08's UI tomorrow — can print
without re-deriving anything or re-deciding anything. :func:`ranked_views` is
where the refusal lives, and it refuses *before* it builds a view: an
untraceable recommendation raises
:data:`RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE` naming every recommendation it
declined and why. A Click callback cannot weaken that by being edited, by being
skipped, or by a future UI that never calls it — because a UI that wants a
recommendation has to ask this layer for one, and there is no other way to get
one. The callback's only job is to *report* the refusal.

Two properties are enforced here rather than documented, and both are refusals:

* **advisory is not authorization.** Every view type inherits
  :class:`_AdvisoryStanding`, whose :attr:`~_AdvisoryStanding.standing`,
  :attr:`~_AdvisoryStanding.grants_approval` and
  :attr:`~_AdvisoryStanding.grants_authorization` are *properties returning
  literals* read from nothing. They cannot be passed ``True``, because there is
  no field to pass them into. And a recommendation that already carries an
  approval is refused outright (:data:`RULE_VIEW_RECOMMENDATION_CARRIES_APPROVAL`),
  the same refusal :meth:`AdvisoryClaim.from_recommendation` makes and for the
  same reason: an approval is its own record, attested by the gate that verified
  it, and an advisory surface that displayed one would be a second place that
  appeared to make decisions.
* **an unknown authorization is never an authorized one.**
  :class:`SubmissionView` carries all three of
  :class:`~mayhem.controller.advisor_service.SubmissionAuthorization`'s states as
  :attr:`SubmissionView.authorization_state`, verbatim, and adds
  :attr:`SubmissionView.surface_grants_authorization` — a second, literal
  ``False``, reading *this surface's own* grant rather than the gate's verdict.
  The two cannot be confused because they are named differently and one of them
  is a constant. Nothing here collapses ``requirements_only`` and
  ``gate_refused``, and nothing here turns either of them into a grant.

## Priority is derived here and nowhere else

There is no priority parameter anywhere in this module. :func:`ranked_views`
receives a :class:`~mayhem.domain.advisor.PriorityCriteria` declaration and the
recommendations themselves, and computes each score as
``recommendation.priority.total`` — the weighted mean, recomputed on every read.
:func:`advisor_dashboard` goes one step earlier and does the ranking itself, via
:func:`mayhem.domain.advisor.rank_drafts`, so the order is the domain's ordering
and not a ``sorted()`` written next to the renderer. A caller cannot supply a
weight: the declaration is part of the sealed inputs document, every criterion in
it must carry the customer question it answers (the domain refuses one that does
not), and :func:`ranked_views` refuses any recommendation weighed against a
*different* declaration (:data:`RULE_VIEW_CRITERIA_MISMATCH`) rather than
rendering a score under a weighting the reader is not looking at.

## One compilation core, not two

``advisor replay`` stops at the candidate. ``advisor submit`` and
``advisor scenario instantiate`` both go through
:meth:`~mayhem.controller.advisor_service.AdvisorService.submit` /
:func:`~mayhem.controller.advisor_service.submit_scenario`, which are the same
private core — so a candidate from an incident and a candidate from a scenario
reach the planner, the proof compiler, and the policy gate by one route, and a
second path would have to be written on purpose to exist.

**There is no ``approve`` command and no ``--approve``/``--force`` flag.**
Naming the surface cannot approve anything, and a flag that could would be the
one thing that undoes Phase 4. What the flow produces is a candidate at the gate
with :attr:`SubmissionView.surface_grants_authorization` reading ``False``.

## Where the inputs come from, and what the surface refuses to invent

The advisor correlates sealed facts. A CLI cannot read a live incident feed, a
deployment record, or a coverage landscape without being handed them, so this
surface takes one **inputs document** (``--inputs``) and builds the five read
ports over it — no database is opened, no engine is contacted, and no clock is
read. Every field is validated and every unknown field is refused
(:data:`RULE_INPUT_UNKNOWN_FIELD`) rather than ignored, so a document cannot
smuggle a key past the boundary by naming it something nothing looks at.

Two consequences worth stating rather than hiding:

* **The surface refuses an incident it cannot trace.** A capture pinned to a
  snapshot other than the one the document declares is refused by name
  (:data:`RULE_VIEW_REPLAY_NOT_PINNED`), and so is a replay whose own pin
  disagrees with the snapshot the engine read — there is no default candidate
  behind either refusal.
* **The safety context is fixed and there is no flag to change it.** The advisor
  read sealed inputs; it has no policy bundle, no approval gate, and no runtime
  adapter to ask. A caller could be handed flags that loosen the blast-radius
  caps and call them "configuration", so there are none. What the submission
  honestly reports is therefore :data:`POLICY_STATE_NO_BUNDLE`,
  ``requirements_only``, and a ``VOID`` proof whose reason names the capability
  line the advisor had no witness for. Loosening any of that is a change made in
  :mod:`mayhem.controller.safety`, where a reviewer can see it.

## Nothing here maps an advisor artifact onto a proof obligation

Phase 4 recorded this gap and this surface hits it rather than papering over it:
:mod:`mayhem.controller.safety_proof` owns the proof-obligation mapping and no
obligation names an advisory claim, so a submission's proof says nothing about
whether the recommendation was sound. The view therefore renders
:attr:`SubmissionView.proof_verdict` and :attr:`SubmissionView.proof_void_reason`
verbatim and never paraphrases either into "the recommendation was validated".
Inventing an obligation here would be inventing the mapping the owner of that
vocabulary has to write.

Invocations that resolve against this command::

    mayhem advisor --help
    mayhem advisor dashboard --inputs advisor.json
    mayhem advisor replay --inputs advisor.json --incident inc-1 --fault-id net.latency \\
        --context container --band default --bind seconds=duration --bind jitter_ms=p99:ms
    mayhem advisor submit --inputs advisor.json --incident inc-1 --fault-id net.latency \\
        --context container --band default --bind seconds=duration --bind jitter_ms=p99:ms \\
        --run-id r-advisor-1 --config-snapshot cfg-1 --fingerprint <64 hex>
    mayhem advisor scenario list
    mayhem advisor scenario show dns-failure@1.0.0
    mayhem advisor scenario instantiate regional-outage@1.0.0 --inputs advisor.json \\
        --target checkout --context container --band default \\
        --run-id r-scenario-1 --config-snapshot cfg-1 --fingerprint <64 hex>
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from math import isfinite
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import click

from mayhem.cli import style
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.output import echo_machine
from mayhem.controller.advisor_service import ADVISORY_STANDING, submit_scenario
from mayhem.domain.advisor import (
    SEALED_DIGEST_PATTERN,
    CriterionReading,
    ExperimentCandidate,
    is_certified_evidence,
    rank_drafts,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.scenarios import scenario_library

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from mayhem.controller.advisor_service import (
        AdvisorAnalysis,
        AdvisorService,
        AdvisorSubmission,
        IncidentReplay,
        SealedCell,
    )
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.advisor import (
        CitedFact,
        Finding,
        PriorityCriteria,
        Recommendation,
        UntrustedRecommendationDraft,
    )
    from mayhem.domain.coverage import CellState, CoverageCell
    from mayhem.domain.scenarios import (
        ScenarioInstantiation,
        ScenarioLibrary,
        ScenarioTemplate,
        TimelineStep,
    )
    from mayhem.domain.topology import TopologyGraph

__all__ = [
    "ADVISORY_CAP_MAX_CONCURRENT_FAULTS",
    "ADVISORY_CAP_MAX_DURATION_PER_FAULT_S",
    "ADVISORY_CAP_MAX_HOSTS",
    "ADVISORY_CAP_MAX_SERVICES_PCT",
    "ADVISORY_FINGERPRINT_ENV",
    "DRAFT_TRUST",
    "POLICY_STATE_ALLOWED",
    "POLICY_STATE_NO_BUNDLE",
    "POLICY_STATE_REFUSED",
    "RULE_INPUT_INCOMPLETE",
    "RULE_INPUT_UNKNOWN_FIELD",
    "RULE_VIEW_CRITERIA_MISMATCH",
    "RULE_VIEW_READING_BLANK",
    "RULE_VIEW_RECOMMENDATION_CARRIES_APPROVAL",
    "RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE",
    "RULE_VIEW_REPLAY_NOT_PINNED",
    "RULE_VIEW_REPLAY_UNTRACED",
    "RULE_VIEW_SCENARIO_CELL_NOT_A_GAP",
    "SURFACE_SUBMITS_THROUGH",
    "AdvisorDashboard",
    "AdvisorInputs",
    "AdvisorViewRefused",
    "DeclaredReading",
    "DeclaredWeight",
    "DraftView",
    "ParameterView",
    "RankedRecommendation",
    "RecoveryView",
    "ReplayView",
    "ScenarioInstantiationView",
    "ScenarioView",
    "SubmissionView",
    "SuppressedView",
    "TimelineView",
    "TracedCriterion",
    "TracedFact",
    "advisor",
    "advisor_dashboard",
    "advisor_safety_context",
    "advisor_service_for",
    "carries_sealed_evidence",
    "parse_binding",
    "propose_candidate",
    "ranked_views",
    "render_dashboard",
    "render_replay",
    "render_scenario",
    "render_submission",
    "scenario",
    "scenario_instantiation_view",
    "scenario_submission",
    "scenario_view",
    "scenario_views",
    "submission_view",
]

# =============================================================================
# Rule ids
# =============================================================================

#: A recommendation whose rationale cannot be checked against the declared
#: criteria it was ranked by. Raised by the view-model layer, before a view
#: exists, so there is no partial view a renderer could print instead.
RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE = "advisor_view.recommendation_not_renderable"

#: A recommendation that already carries an approval. This surface is advisory;
#: an approval is its own record and is not re-displayed here.
RULE_VIEW_RECOMMENDATION_CARRIES_APPROVAL = "advisor_view.recommendation_carries_an_approval"

#: A recommendation weighed against a *different* declared criteria than the one
#: being rendered against, or a reading for a criterion nobody declared.
RULE_VIEW_CRITERIA_MISMATCH = "advisor_view.criteria_declaration_mismatch"

#: A replay whose topology pin is not the snapshot the engine read, or the
#: snapshot the incident itself was observed against.
RULE_VIEW_REPLAY_NOT_PINNED = "advisor_view.replay_not_pinned_to_its_snapshot"

#: A replay parameter with no incident fact behind it.
RULE_VIEW_REPLAY_UNTRACED = "advisor_view.replay_parameter_without_a_trace"

#: A scenario bound to a cell the analysed landscape does not report as a gap.
RULE_VIEW_SCENARIO_CELL_NOT_A_GAP = "advisor_view.scenario_cell_is_not_a_declared_gap"

#: A declared reading with no criterion name, no evidence sentence, or a value
#: outside the normalised interval every reading is drawn from.
RULE_VIEW_READING_BLANK = "advisor_view.declared_reading_is_not_traceable"

#: The inputs document declared a field this surface does not read.
RULE_INPUT_UNKNOWN_FIELD = "advisor_view.input_unknown_field"

#: The inputs document omitted a field this surface cannot default.
RULE_INPUT_INCOMPLETE = "advisor_view.input_incomplete"

#: The trust label every draft renders under. A constant, on purpose: the only
#: value an untrusted draft can be rendered as is the one that says it is
#: untrusted.
DRAFT_TRUST: Final[str] = "untrusted"

#: Where every candidate this surface produces goes next, named in the rendered
#: output so a reader can grep for the road rather than trust it.
SURFACE_SUBMITS_THROUGH: Final[str] = "mayhem.controller.advisor_service.submit"

#: The three answers the policy gate can give. Named, because ``None`` from the
#: simulator means "the context carried no bundle" and a boolean would have to
#: render that as a pass.
POLICY_STATE_ALLOWED: Final[str] = "allowed"
POLICY_STATE_REFUSED: Final[str] = "refused"
POLICY_STATE_NO_BUNDLE: Final[str] = "no_bundle_configured"


# =============================================================================
# The safety context this surface builds — and does not let a caller change
# =============================================================================

#: Blast-radius ceilings for the submissions this surface compiles. Fixed, and
#: stated here rather than taken from a flag: a caller handed ``--max-hosts``
#: would be handed the gate that is supposed to be checking them. They are
#: deliberately generous, because the honest limits on this path are the policy
#: bundle and the runtime, and this surface has neither.
ADVISORY_CAP_MAX_SERVICES_PCT: Final[float] = 50.0
ADVISORY_CAP_MAX_HOSTS: Final[int] = 8
ADVISORY_CAP_MAX_CONCURRENT_FAULTS: Final[int] = 4
ADVISORY_CAP_MAX_DURATION_PER_FAULT_S: Final[float] = 300.0

#: Environment variable naming the environment fingerprint, so a fingerprint does
#: not have to sit on a command line next to a run id.
ADVISORY_FINGERPRINT_ENV: Final[str] = "MAYHEM_ENVIRONMENT_FINGERPRINT"

#: The environment fingerprint is compared by shape everywhere in the tree.
_FINGERPRINT_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

#: The sealed-evidence digest shape, restated here rather than imported as a
#: compiled pattern so the two rules (a citation and a rendered claim) are
#: checked against the same expression plan 12 uses.
_SEALED_DIGEST_RE: Final[re.Pattern[str]] = re.compile(SEALED_DIGEST_PATTERN)


# =============================================================================
# The refusal type every view-model rule raises
# =============================================================================


class AdvisorViewRefused(InvariantViolationError):  # noqa: N818 — domain refusal vocabulary
    """A refusal raised by the view-model layer, before any view exists.

    A subclass of :class:`~mayhem.domain.errors.InvariantViolationError` so the
    CLI's existing error mapping carries the rule id, and so a caller that only
    knows the domain's vocabulary still catches it. The Click callback turns one
    of these into a ``safety_refusal`` envelope — it *reports* the refusal, and
    reporting it is the callback's only job.
    """


# =============================================================================
# The standing every advisory view carries
# =============================================================================


class _AdvisoryStanding:
    """``advisory``, and the two grants this surface can never make.

    Properties, not fields. A field would be a value a caller could set to
    ``True`` at construction, and "no input can make this say otherwise" is the
    whole claim — the same reason
    :attr:`~mayhem.controller.advisor_service.AdvisorySeal.grants_authorization`
    is a literal. Every view type below inherits this, so a new view cannot
    forget the vocabulary.
    """

    @property
    def standing(self) -> str:
        """Always :data:`ADVISORY_STANDING`. Read from nothing."""
        return ADVISORY_STANDING

    @property
    def grants_approval(self) -> bool:
        """Always ``False``. This surface approves nothing and cannot be asked to."""
        return False

    @property
    def grants_authorization(self) -> bool:
        """Always ``False``. Reading this, not the plan-09 gate's verdict.

        The gate's own verdict travels on
        :attr:`SubmissionView.authorization_state`, named differently and
        separately, so the two can never be read as one claim.
        """
        return False


# =============================================================================
# Small traced value types
# =============================================================================


@dataclass(frozen=True, slots=True)
class TracedFact:
    """One cited fact, named for the reader: what kind, which reference, what it says."""

    kind: str
    ref: str
    detail: str

    @classmethod
    def of(cls, fact: CitedFact) -> TracedFact:
        return cls(kind=fact.kind.value, ref=fact.ref, detail=fact.detail)

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "ref": self.ref, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class DeclaredWeight:
    """One declared customer criterion: its weight and the question it answers.

    Carries no reading. A declaration is what the customer agreed to; a reading
    is what one finding scored against it, and the two are rendered separately
    so a reader cannot mistake an agreed weighting for a score.
    """

    name: str
    weight: float
    question: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "weight": self.weight, "question": self.question}


@dataclass(frozen=True, slots=True)
class TracedCriterion:
    """One declared criterion, this finding's reading of it, and the fact behind it."""

    name: str
    weight: float
    question: str
    value: float
    contribution: float
    evidence: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "weight": self.weight,
            "question": self.question,
            "value": self.value,
            "contribution": self.contribution,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class DeclaredReading:
    """A customer's reading of one *gap*, against one declared criterion.

    Carries a criterion *name*, never a weight and never an index: the weighting
    is the declaration's business, and this surface has no way to express an
    opinion about how much a criterion is worth.
    """

    criterion: str
    value: float
    evidence: str

    def __post_init__(self) -> None:
        for name, text in (("criterion", self.criterion), ("evidence", self.evidence)):
            if not text.strip():
                raise AdvisorViewRefused(
                    RULE_VIEW_READING_BLANK,
                    f"a declared reading states no {name}: a score with no criterion is "
                    "not a score, and a score with no fact behind it is the opaque "
                    "ranking plan 21 exists to prevent",
                )
        if not isfinite(self.value) or not 0.0 <= self.value <= 1.0:
            raise AdvisorViewRefused(
                RULE_VIEW_READING_BLANK,
                f"a declared reading for {self.criterion!r} is {self.value!r}, which is "
                "outside the normalised [0, 1] interval every reading is drawn from",
            )

    def to_dict(self) -> dict[str, object]:
        return {"criterion": self.criterion, "value": self.value, "evidence": self.evidence}


@dataclass(frozen=True, slots=True)
class SuppressedView:
    """One declared cell the engine looked at and declined, with its reason by name."""

    cell_key: str
    reason: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"cell_key": self.cell_key, "reason": self.reason, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class DraftView(_AdvisoryStanding):
    """An untrusted draft, rendered as untrusted.

    There is no field here an approval could travel in, and that is not an
    omission: :class:`~mayhem.domain.advisor.UntrustedRecommendationDraft` has no
    approval field either, and the two were built to match. :attr:`trust` is a
    property reading :data:`DRAFT_TRUST`, so there is exactly one value an
    untrusted draft can render as.
    """

    recommendation_id: str
    finding_id: str
    failure_mode: str
    cell_key: str
    hypothesis: str
    rationale: str
    suggested_probes: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    cited_facts: tuple[TracedFact, ...]

    @property
    def trust(self) -> str:
        """Always :data:`DRAFT_TRUST`."""
        return DRAFT_TRUST

    @property
    def authority(self) -> str:
        """Always ``none``. A draft has reached no gate, so it holds no standing."""
        return "none"

    def to_dict(self) -> dict[str, object]:
        return {
            "recommendation_id": self.recommendation_id,
            "trust": self.trust,
            "authority": self.authority,
            "standing": self.standing,
            "grants_approval": self.grants_approval,
            "grants_authorization": self.grants_authorization,
            "finding_id": self.finding_id,
            "failure_mode": self.failure_mode,
            "cell_key": self.cell_key,
            "hypothesis": self.hypothesis,
            "rationale": self.rationale,
            "suggested_probes": list(self.suggested_probes),
            "stop_conditions": list(self.stop_conditions),
            "cited_facts": [fact.to_dict() for fact in self.cited_facts],
        }


@dataclass(frozen=True, slots=True)
class RankedRecommendation(_AdvisoryStanding):
    """One recommendation, ranked by the declared criteria, with its whole trace.

    :attr:`priority_total` is the weighted mean, computed on read from the
    declared readings — there is no field to store a score in, and this view type
    has no way to accept one either.
    """

    position: int
    recommendation_id: str
    experiment_id: str
    origin: str
    authority: str
    failure_mode: str
    cell_key: str
    cell_ref: str
    cell_state: str
    landscape_id: str
    topology_node_ids: tuple[str, ...]
    graph_identity: str
    criteria_name: str
    declared_criteria: tuple[TracedCriterion, ...]
    priority_total: float
    weighted_sum: float
    total_weight: float
    rationale: str
    hypothesis: str
    suggested_probes: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    cited_facts: tuple[TracedFact, ...]
    submits_through: str

    def to_dict(self) -> dict[str, object]:
        return {
            "position": self.position,
            "recommendation_id": self.recommendation_id,
            "experiment_id": self.experiment_id,
            "origin": self.origin,
            "authority": self.authority,
            "standing": self.standing,
            "grants_approval": self.grants_approval,
            "grants_authorization": self.grants_authorization,
            "failure_mode": self.failure_mode,
            "cell_key": self.cell_key,
            "cell_ref": self.cell_ref,
            "cell_state": self.cell_state,
            "landscape_id": self.landscape_id,
            "topology_node_ids": list(self.topology_node_ids),
            "graph_identity": self.graph_identity,
            "criteria_name": self.criteria_name,
            "declared_criteria": [criterion.to_dict() for criterion in self.declared_criteria],
            "priority_total": self.priority_total,
            "weighted_sum": self.weighted_sum,
            "total_weight": self.total_weight,
            "rationale": self.rationale,
            "hypothesis": self.hypothesis,
            "suggested_probes": list(self.suggested_probes),
            "stop_conditions": list(self.stop_conditions),
            "cited_facts": [fact.to_dict() for fact in self.cited_facts],
            "submits_through": self.submits_through,
        }


# =============================================================================
# The dashboard
# =============================================================================


@dataclass(frozen=True, slots=True)
class AdvisorDashboard(_AdvisoryStanding):
    """Findings ranked by the declared criteria, their traces, and what was declined.

    ``ranked`` is in the domain's own order (``-total``, then id) because
    :func:`advisor_dashboard` ranks through :func:`rank_drafts`. ``suppressed``
    is the honesty half: the gap between the declared landscape and the findings
    is a list a reader can check, not an arithmetic difference.
    """

    artifact: str
    landscape_id: str
    criteria_name: str
    declared_criteria: tuple[DeclaredWeight, ...]
    topology_snapshot_id: str
    graph_identity: str
    ranked: tuple[RankedRecommendation, ...]
    drafts: tuple[DraftView, ...]
    suppressed: tuple[SuppressedView, ...]
    mutation_backend_attached: bool
    mutation_calls: int
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact": self.artifact,
            "standing": self.standing,
            "grants_approval": self.grants_approval,
            "grants_authorization": self.grants_authorization,
            "landscape_id": self.landscape_id,
            "criteria_name": self.criteria_name,
            "declared_criteria": [criterion.to_dict() for criterion in self.declared_criteria],
            "topology_snapshot_id": self.topology_snapshot_id,
            "graph_identity": self.graph_identity,
            "ranked": [row.to_dict() for row in self.ranked],
            "drafts": [draft.to_dict() for draft in self.drafts],
            "suppressed": [row.to_dict() for row in self.suppressed],
            "mutation": {
                "backend_attached": self.mutation_backend_attached,
                "calls": self.mutation_calls,
            },
            "notes": list(self.notes),
        }


def _traced_criteria(recommendation: Recommendation) -> tuple[TracedCriterion, ...]:
    """The declared criteria, each with this recommendation's reading and its fact."""
    return tuple(
        TracedCriterion(
            name=reading.criterion.name,
            weight=reading.criterion.weight,
            question=reading.criterion.question,
            value=reading.value,
            contribution=reading.contribution,
            evidence=reading.evidence,
        )
        for reading in recommendation.priority.readings
    )


def _readable_cell(cell: CoverageCell) -> str:
    """The cell's four declared dimensions, spelled out for a reader.

    ``cell.key`` is the four parts joined by the unit separator, which is exact
    and unreadable. Both are rendered — the readable one first, because a human
    reading a dashboard wants to know which failure mode on which service, and
    the key because that is what the domain, the citations, and every artifact
    downstream use.
    """
    return (
        f"{cell.target} / {cell.fault_kind} @ {cell.execution_context}"
        f":{cell.parameter_band}"
    )


def _declared_weights(criteria: PriorityCriteria) -> tuple[DeclaredWeight, ...]:
    return tuple(
        DeclaredWeight(name=c.name, weight=c.weight, question=c.question) for c in criteria.criteria
    )


def carries_sealed_evidence(subject: object) -> bool:
    """True when ``subject`` carries the sealed evidence digest a verifier accepts.

    Two halves on purpose. The first is
    :func:`mayhem.domain.advisor.is_certified_evidence`, the predicate Phase 1
    wrote and Phase 4 made structural — it is ``False`` for every type in the
    advisor's vocabulary, which is the argument. The second half is a check on
    the *serialised* form, because a serialisation is what a report or a UI
    would carry forward, and a digest-shaped value under an ``evidence_digest``
    key there would be a claim of certified evidence this surface has no standing
    to repeat — whether it arrived as a field, a mapping, or a nested payload.

    Both halves are cheap, and the second is the one a future type would trip
    first.
    """
    if is_certified_evidence(subject):
        return True
    payload = subject.to_dict() if hasattr(subject, "to_dict") else subject
    return _carries_digest(payload)


def _carries_digest(payload: object) -> bool:
    """True when any mapping in ``payload`` holds a digest-shaped ``evidence_digest``."""
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if (
                key == "evidence_digest"
                and isinstance(value, str)
                and _SEALED_DIGEST_RE.match(value)
            ):
                return True
            if _carries_digest(value):
                return True
        return False
    if isinstance(payload, (list, tuple)):
        return any(_carries_digest(item) for item in payload)
    return False


def ranked_views(
    recommendations: Iterable[Recommendation], criteria: PriorityCriteria
) -> tuple[RankedRecommendation, ...]:
    """Rank these recommendations against *this* declaration, or refuse all of them.

    **This function is the Phase 3 acceptance criterion.** A recommendation whose
    rationale does not name every criterion it was weighed against is not
    rendered, not shortened, and not rendered with a warning — there is no partial
    view here to print. Every unrenderable recommendation is named in the one
    refusal, so a reader learns the whole problem rather than its first third.

    Four refusals, all checked before anything is built:

    1. a recommendation that already carries an approval
       (:data:`RULE_VIEW_RECOMMENDATION_CARRIES_APPROVAL`) — an advisory surface
       does not display decisions;
    2. a recommendation whose rationale cannot be traced against the declared
       criteria (:data:`RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE`);
    3. a recommendation that would render as a sealed run
       (:data:`RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE`) — correlation is not a
       run, and this would be the last place the distinction was still visible;
    4. a recommendation weighed against a different declaration
       (:data:`RULE_VIEW_CRITERIA_MISMATCH`) — rendering its score under this
       weighting would show a number the reader is not looking at.

    The score is :attr:`~mayhem.domain.advisor.Recommendation.total`, the derived
    weighted mean; nothing here accepts one. The order is ``(-total,
    recommendation_id)`` — the domain's own ordering, restated once so a tie
    cannot render as "whoever sorted first".
    """
    rows = tuple(recommendations)
    carrying_approval = tuple(r.recommendation_id for r in rows if r.approval is not None)
    if carrying_approval:
        raise AdvisorViewRefused(
            RULE_VIEW_RECOMMENDATION_CARRIES_APPROVAL,
            f"recommendation(s) {list(carrying_approval)} carry an approval. An approval is "
            "its own record, attested by the gate that verified it and bound by digest to "
            "the recommendation a human read. The advisor surface is advisory: it "
            "correlates cited facts and shows what they add up to, and it does not "
            "display or re-attest a decision",
        )
    unrenderable = tuple(
        (r.recommendation_id, r.render_refusal_reason()) for r in rows if r.render_refusal_reason()
    )
    if unrenderable:
        detail = "; ".join(f"{rid}: {reason}" for rid, reason in unrenderable)
        raise AdvisorViewRefused(
            RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE,
            f"{len(unrenderable)} of {len(rows)} recommendation(s) may not be rendered — "
            f"{detail}. A recommendation whose rationale cannot be checked against the "
            "declared criteria it was ranked by is not shown in a shortened form either: a "
            "partial render is how an untraceable recommendation reaches a screen",
        )
    sealed = tuple(
        r.recommendation_id
        for r in rows
        if carries_sealed_evidence(r)
        or carries_sealed_evidence(r.candidate)
        or carries_sealed_evidence(r.finding)
        or carries_sealed_evidence(r.to_dict())
    )
    if sealed:
        raise AdvisorViewRefused(
            RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE,
            f"recommendation(s) {list(sealed)} carry a sealed evidence digest and would "
            "render as a run. The advisor correlates facts and has no verdict: correlation "
            "is not a run, and this surface may not present one as the other",
        )
    mismatched = tuple(
        r.recommendation_id
        for r in rows
        if r.priority.criteria_name != criteria.name
        or r.priority.criteria_names != criteria.names
        or r.priority.total_weight != criteria.total_weight
    )
    if mismatched:
        raise AdvisorViewRefused(
            RULE_VIEW_CRITERIA_MISMATCH,
            f"recommendation(s) {list(mismatched)} were weighed against a different criteria "
            f"declaration than {criteria.name!r} declares ({criteria.names} at total weight "
            f"{criteria.total_weight:g}): a priority is a function of the declared weights, so "
            "rendering one under a weighting the reader is not looking at would show a number "
            "that is not the weighting anybody agreed to",
        )
    ordered = sorted(rows, key=lambda r: (-r.total, r.recommendation_id))
    return tuple(
        RankedRecommendation(
            position=position,
            recommendation_id=r.recommendation_id,
            experiment_id=r.candidate.experiment_id,
            origin=r.origin.value,
            authority=r.authority.value,
            failure_mode=r.finding.failure_mode,
            cell_key=r.finding.cell_key,
            cell_ref=_readable_cell(r.finding.cell),
            cell_state=r.finding.cell_state.value,
            landscape_id=r.finding.landscape.landscape_id,
            topology_node_ids=r.finding.topology_node_ids,
            graph_identity=r.finding.graph_identity,
            criteria_name=r.priority.criteria_name,
            declared_criteria=_traced_criteria(r),
            priority_total=r.total,
            weighted_sum=r.priority.weighted_sum,
            total_weight=r.priority.total_weight,
            rationale=r.rationale,
            hypothesis=r.candidate.hypothesis,
            suggested_probes=r.candidate.suggested_probes,
            stop_conditions=r.candidate.stop_conditions,
            cited_facts=tuple(TracedFact.of(fact) for fact in r.cited_facts),
            submits_through=SURFACE_SUBMITS_THROUGH,
        )
        for position, r in enumerate(ordered, start=1)
    )


def advisor_dashboard(
    analysis: AdvisorAnalysis,
    criteria: PriorityCriteria,
    readings: Mapping[str, Sequence[DeclaredReading]],
) -> AdvisorDashboard:
    """The dashboard: ranked recommendations with traces, plus what was declined.

    The ranking is the domain's. :func:`mayhem.domain.advisor.rank_drafts` is
    called *here* rather than by the caller, so the order a reader sees is the
    order plan 21 declared and not a ``sorted()`` written next to a renderer.

    ``readings`` is keyed by **coverage cell key**, not by finding id. The finding
    id is a digest of the cell key, so a customer reading a *gap* cannot be asked
    to know a hash; mapping gap to finding is this function's job, and it does it
    by looking the cell up in the analysis.

    Three refusals, all by name, none caught and continued:

    * a cell key in the document that no finding matched
      (:data:`RULE_VIEW_CRITERIA_MISMATCH`) — a reading about a gap that no
      longer exists is a stale key, and drift between a document and a landscape
      is not a rendering preference;
    * a reading naming a criterion nobody declared
      (:data:`RULE_VIEW_CRITERIA_MISMATCH`);
    * everything :func:`ranked_views` refuses, which is where the render
      acceptance lives.
    """
    declared: dict[str, dict[str, CriterionReading]] = {}
    for finding in analysis.findings:
        declared[finding.cell_key] = _readings_for(
            criteria, readings.get(finding.cell_key, ())
        )
    orphans = sorted(set(readings) - set(declared))
    if orphans:
        raise AdvisorViewRefused(
            RULE_VIEW_CRITERIA_MISMATCH,
            f"the inputs document holds criterion readings for cell(s) {orphans}, which are "
            f"not gaps in landscape {analysis.landscape_id!r}: a reading about a gap that no "
            "longer exists is either a stale key or evidence about nothing, and neither may "
            "be ranked",
        )
    # ``rank_drafts`` is keyed by *finding id*; the document is keyed by coverage
    # cell, and the mapping between them is this module's job. Translated once,
    # here, so the domain's one-to-one check is done against exactly the findings
    # it is ranking.
    by_finding = {
        draft.finding.finding_id: declared[draft.finding.cell_key]
        for draft in analysis.drafts
    }
    ranked = ranked_views(rank_drafts(analysis.drafts, criteria, by_finding), criteria)
    return AdvisorDashboard(
        artifact=analysis.artifact,
        landscape_id=analysis.landscape_id,
        criteria_name=criteria.name,
        declared_criteria=_declared_weights(criteria),
        topology_snapshot_id=analysis.topology_snapshot_id,
        graph_identity=analysis.graph_identity,
        ranked=ranked,
        drafts=tuple(_draft_view(draft) for draft in analysis.drafts),
        suppressed=tuple(
            SuppressedView(cell_key=row.cell_key, reason=row.reason.value, detail=row.detail)
            for row in analysis.suppressed
        ),
        mutation_backend_attached=analysis.purity.backend_attached,
        mutation_calls=analysis.purity.calls,
        notes=analysis.notes,
    )


def _readings_for(
    criteria: PriorityCriteria, declared: Sequence[DeclaredReading]
) -> dict[str, CriterionReading]:
    """Turn declared readings into the domain's, refusing an undeclared criterion.

    The lookup goes through the declaration rather than through the reading, so a
    criterion name nobody declared cannot be weighed — and the resulting
    :class:`~mayhem.domain.advisor.CriterionReading` carries the *declared*
    weight, not one this module could have invented.
    """
    readings: dict[str, CriterionReading] = {}
    for entry in declared:
        criterion = criteria.criterion(entry.criterion)
        if criterion is None:
            raise AdvisorViewRefused(
                RULE_VIEW_CRITERIA_MISMATCH,
                f"a declared reading names criterion {entry.criterion!r}, which declaration "
                f"{criteria.name!r} does not declare {criteria.names}: a weight that was not "
                "declared cannot be weighed, because nobody agreed to it",
            )
        readings[entry.criterion] = CriterionReading(
            criterion=criterion, value=entry.value, evidence=entry.evidence
        )
    return readings


def _draft_view(draft: UntrustedRecommendationDraft) -> DraftView:
    return DraftView(
        recommendation_id=draft.recommendation_id,
        finding_id=draft.finding.finding_id,
        failure_mode=draft.finding.failure_mode,
        cell_key=draft.finding.cell_key,
        hypothesis=draft.candidate.hypothesis,
        rationale=draft.rationale,
        suggested_probes=draft.candidate.suggested_probes,
        stop_conditions=draft.candidate.stop_conditions,
        cited_facts=tuple(TracedFact.of(fact) for fact in draft.finding.cited_facts),
    )


# =============================================================================
# The replay view — incident in, candidate out
# =============================================================================


@dataclass(frozen=True, slots=True)
class ParameterView:
    """One generated parameter, its value, and the incident fact it came from."""

    parameter: str
    value: float
    unit: str
    source: str
    incident_id: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "parameter": self.parameter,
            "value": self.value,
            "unit": self.unit,
            "source": self.source,
            "incident_id": self.incident_id,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ReplayView(_AdvisoryStanding):
    """An incident capture compiled into a candidate, pinned and traced.

    :attr:`next_gate` is the honest sentence about what happens next: the
    candidate is a plan with nothing authorised, and a person is what stands
    between it and a runtime.
    """

    incident_id: str
    service: str
    dependency: str
    failure_signature: str
    topology_snapshot_id: str
    graph_identity: str
    cell_key: str
    finding_id: str
    fault_id: str
    duration_s: float
    hypothesis: str
    suggested_probes: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    parameters: tuple[ParameterView, ...]
    cited_facts: tuple[TracedFact, ...]
    replay_digest: str
    next_gate: str

    @property
    def authority(self) -> str:
        """Always ``none``. A replayed candidate has reached no gate yet."""
        return "none"

    def to_dict(self) -> dict[str, object]:
        return {
            "standing": self.standing,
            "grants_approval": self.grants_approval,
            "grants_authorization": self.grants_authorization,
            "authority": self.authority,
            "incident_id": self.incident_id,
            "service": self.service,
            "dependency": self.dependency,
            "failure_signature": self.failure_signature,
            "topology_snapshot_id": self.topology_snapshot_id,
            "graph_identity": self.graph_identity,
            "cell_key": self.cell_key,
            "finding_id": self.finding_id,
            "fault_id": self.fault_id,
            "duration_s": self.duration_s,
            "hypothesis": self.hypothesis,
            "suggested_probes": list(self.suggested_probes),
            "stop_conditions": list(self.stop_conditions),
            "parameters": [parameter.to_dict() for parameter in self.parameters],
            "cited_facts": [fact.to_dict() for fact in self.cited_facts],
            "replay_digest": self.replay_digest,
            "next_gate": self.next_gate,
        }


def replay_view(replay: IncidentReplay, *, topology_snapshot_id: str) -> ReplayView:
    """The candidate a replay produced, or a refusal naming what could not be traced.

    ``topology_snapshot_id`` is the snapshot the engine's topology port reported,
    passed in rather than read off the replay, and the pin is checked against
    **both** the replay and the capture it came from. That is what makes "pinned"
    mean something at the view: the view cannot assume the engine ran the check,
    and a hand-assembled artifact handed to this function is refused rather than
    rendered.

    Two refusals, both by name, neither with a default behind it:

    * a pin that is not the snapshot the engine read
      (:data:`RULE_VIEW_REPLAY_NOT_PINNED`) — replaying an incident against a
      different graph reproduces a different incident;
    * a parameter with no incident fact behind it
      (:data:`RULE_VIEW_REPLAY_UNTRACED`) — a generated parameter whose origin
      cannot be named is an invented one.

    An incident that cannot be traced to its snapshot therefore yields **no**
    candidate: not a candidate with defaults, and not a candidate with an
    untraced parameter.
    """
    if replay.topology_snapshot_id != topology_snapshot_id:
        raise AdvisorViewRefused(
            RULE_VIEW_REPLAY_NOT_PINNED,
            f"replay of {replay.incident.incident_id!r} is pinned to snapshot "
            f"{replay.topology_snapshot_id!r} but the engine read "
            f"{topology_snapshot_id!r}: replaying an incident against a different graph "
            "reproduces a different incident, which is the one thing replay exists to "
            "prevent. No candidate was compiled in its place",
        )
    if replay.incident.topology_snapshot_id != topology_snapshot_id:
        raise AdvisorViewRefused(
            RULE_VIEW_REPLAY_NOT_PINNED,
            f"incident {replay.incident.incident_id!r} was observed against snapshot "
            f"{replay.incident.topology_snapshot_id!r}, and the engine read "
            f"{topology_snapshot_id!r}: there is no candidate to show, because the one "
            "this would render reproduces a different incident",
        )
    untraced = tuple(
        trace.parameter for trace in replay.parameters if not trace.source.strip()
    )
    if untraced:
        raise AdvisorViewRefused(
            RULE_VIEW_REPLAY_UNTRACED,
            f"replay of {replay.incident.incident_id!r} carries parameter(s) "
            f"{list(untraced)} with no incident fact behind them: a generated parameter "
            "whose origin cannot be named is an invented one, and a replay of nothing is "
            "not rendered as a candidate",
        )
    return ReplayView(
        incident_id=replay.incident.incident_id,
        service=replay.incident.service,
        dependency=replay.incident.dependency,
        failure_signature=replay.incident.failure_signature,
        topology_snapshot_id=replay.topology_snapshot_id,
        graph_identity=replay.graph_identity,
        cell_key=replay.cell.key,
        finding_id=replay.finding.finding_id,
        fault_id=replay.fault_id,
        duration_s=replay.duration_s,
        hypothesis=replay.candidate.hypothesis,
        suggested_probes=replay.candidate.suggested_probes,
        stop_conditions=replay.candidate.stop_conditions,
        parameters=tuple(
            ParameterView(
                parameter=trace.parameter,
                value=trace.value,
                unit=trace.unit,
                source=trace.source,
                incident_id=trace.incident_id,
                detail=trace.detail,
            )
            for trace in replay.parameters
        ),
        cited_facts=tuple(TracedFact.of(fact) for fact in replay.finding.cited_facts),
        replay_digest=replay.replay_digest,
        next_gate=(
            "a person, through the ordinary approval chain: this surface has no approval "
            "path, and 'advisor submit' only compiles and gates the candidate"
        ),
    )


# =============================================================================
# The submission view — what the shared core produced
# =============================================================================


@dataclass(frozen=True, slots=True)
class SubmissionView(_AdvisoryStanding):
    """One candidate taken through the shared compile → proof → policy path.

    Four separate fields, because four separate questions are being asked and
    collapsing any two of them is how an advisory surface starts lying:

    * :attr:`authorization_state` — what the ``required_approvals`` line
      established, verbatim from
      :class:`~mayhem.controller.advisor_service.SubmissionAuthorization`. All
      three states render, and neither non-granting state may be read as the
      third.
    * :attr:`surface_grants_authorization` — what *this surface* granted. A
      property reading ``False``, so it is not derived from the gate's verdict and
      cannot become ``True`` when the gate says something else.
    * :attr:`policy_state` — :data:`POLICY_STATE_ALLOWED`,
      :data:`POLICY_STATE_REFUSED`, or :data:`POLICY_STATE_NO_BUNDLE`. The third
      is not a pass and is not rendered as one.
    * :attr:`refusing_gates` — the rule ids the safety gate refused, by name. A
      candidate refused downstream names the gate that refused it rather than
      being reported as merely "not admitted".
    """

    via: str
    recommendation_id: str
    experiment_id: str
    origin: str
    criteria_name: str
    priority_total: float
    plan_digest: str
    plan_step_count: int
    plan_topology_snapshot_id: str
    proof_verdict: str
    proof_void_reason: str
    admitted_by_gate: bool
    refusing_gates: tuple[str, ...]
    compiler_refusals: tuple[str, ...]
    policy_state: str
    authorization_state: str
    cited_facts: tuple[TracedFact, ...]
    mutation_backend_attached: bool
    mutation_calls: int

    @property
    def surface_grants_authorization(self) -> bool:
        """Always ``False``. This surface granted nothing, whatever the gate said.

        Distinct from :attr:`authorization_state` on purpose: the state is the
        plan-09 gate's own verdict and may read ``gate_authorized`` when a caller
        configured a gate; this field is the advisor surface's own standing, and a
        literal is the only thing it can honestly be.
        """
        return False

    @property
    def authority(self) -> str:
        """Always ``none``. Read from nothing; see :attr:`grants_approval`."""
        return "none"

    def to_dict(self) -> dict[str, object]:
        return {
            "via": self.via,
            "standing": self.standing,
            "grants_approval": self.grants_approval,
            "grants_authorization": self.grants_authorization,
            "surface_grants_authorization": self.surface_grants_authorization,
            "authority": self.authority,
            "recommendation_id": self.recommendation_id,
            "experiment_id": self.experiment_id,
            "origin": self.origin,
            "criteria_name": self.criteria_name,
            "priority_total": self.priority_total,
            "plan_digest": self.plan_digest,
            "plan_step_count": self.plan_step_count,
            "plan_topology_snapshot_id": self.plan_topology_snapshot_id,
            "proof_verdict": self.proof_verdict,
            "proof_void_reason": self.proof_void_reason,
            "admitted_by_gate": self.admitted_by_gate,
            "refusing_gates": list(self.refusing_gates),
            "compiler_refusals": list(self.compiler_refusals),
            "policy_state": self.policy_state,
            "authorization_state": self.authorization_state,
            "cited_facts": [fact.to_dict() for fact in self.cited_facts],
            "mutation": {
                "backend_attached": self.mutation_backend_attached,
                "calls": self.mutation_calls,
            },
        }


def submission_view(
    submission: AdvisorSubmission, *, via: str = "advisor_replay"
) -> SubmissionView:
    """What the shared core produced, in vocabulary that cannot be over-read.

    A recommendation that already carries an approval is refused here for the
    same reason :func:`ranked_views` refuses one: this is an advisory surface,
    and a decision is not something it renders.

    Nothing here paraphrases the proof verdict. :attr:`proof_void_reason` is
    carried verbatim and is frequently the honest answer — with no runtime
    adapter the capability line is unestablished and the proof is ``VOID``, which
    says the advisor had no witness for what the cluster can do. That is a fact
    about the advisor's inputs, not about the soundness of the recommendation.
    """
    if submission.recommendation.approval is not None:
        raise AdvisorViewRefused(
            RULE_VIEW_RECOMMENDATION_CARRIES_APPROVAL,
            f"recommendation {submission.recommendation.recommendation_id!r} carries an "
            "approval and was about to be rendered as an advisory submission: an approval "
            "is its own record, attested by the gate that verified it, and this surface "
            "reports gate verdicts rather than making them",
        )
    return SubmissionView(
        via=via,
        recommendation_id=submission.recommendation.recommendation_id,
        experiment_id=submission.recommendation.candidate.experiment_id,
        origin=submission.recommendation.origin.value,
        criteria_name=submission.recommendation.priority.criteria_name,
        priority_total=submission.recommendation.total,
        plan_digest=submission.plan_digest,
        plan_step_count=len(submission.plan.steps),
        plan_topology_snapshot_id=submission.plan.topology_snapshot_id,
        proof_verdict=submission.proof_verdict,
        proof_void_reason=submission.compilation.void_reason,
        admitted_by_gate=submission.admitted_by_gate,
        refusing_gates=tuple(submission.compilation.gate_refusals),
        compiler_refusals=tuple(submission.compilation.compiler_refusals),
        policy_state=_policy_state(submission),
        authorization_state=submission.authorization.value,
        cited_facts=tuple(TracedFact.of(fact) for fact in submission.recommendation.cited_facts),
        mutation_backend_attached=submission.purity.backend_attached,
        mutation_calls=submission.purity.calls,
    )


def _policy_state(submission: AdvisorSubmission) -> str:
    if submission.policy is None:
        return POLICY_STATE_NO_BUNDLE
    return POLICY_STATE_ALLOWED if submission.policy.allowed else POLICY_STATE_REFUSED


def scenario_submission(
    service: AdvisorService,
    instantiation: ScenarioInstantiation,
    recommendation: Recommendation,
    ctx: SafetyContext,
    *,
    run_id: str,
    config_snapshot_id: str,
    environment_fingerprint: str,
) -> SubmissionView:
    """A scenario's own door: :func:`submit_scenario`, in advisory view clothing.

    Thin on purpose. The binding check that keeps this from being a side channel
    — the compiled plan must carry the recommendation's own hypothesis
    (:data:`~mayhem.controller.advisor_service.RULE_SUBMISSION_SPEC_NOT_BOUND`)
    — lives in the engine, and a scenario whose hypothesis does not match the
    recommendation it is submitted against is refused there, by name, before the
    planner runs. This function exists so the Click callback has one call site and
    so that refusal is reachable and testable from the surface.
    """
    submission = submit_scenario(
        service,
        instantiation,
        recommendation,
        ctx,
        run_id=run_id,
        config_snapshot_id=config_snapshot_id,
        environment_fingerprint=environment_fingerprint,
    )
    return submission_view(submission, via="advisor_scenario")


# =============================================================================
# The scenario library browser
# =============================================================================


@dataclass(frozen=True, slots=True)
class TimelineView:
    """One moment in a scenario: the fault, how long, and what should be observed."""

    at_s: float
    fault_id: str
    duration_s: float
    expects: str

    @classmethod
    def of(cls, step: TimelineStep) -> TimelineView:
        return cls(
            at_s=step.at_s,
            fault_id=step.fault_id,
            duration_s=step.duration_s,
            expects=step.expects,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "at_s": self.at_s,
            "fault_id": self.fault_id,
            "duration_s": self.duration_s,
            "expects": self.expects,
        }


@dataclass(frozen=True, slots=True)
class RecoveryView:
    """What recovery means for a scenario, and how anybody would know it happened."""

    expects: str
    compensation: str
    verified_by: str

    def to_dict(self) -> dict[str, str]:
        return {
            "expects": self.expects,
            "compensation": self.compensation,
            "verified_by": self.verified_by,
        }


@dataclass(frozen=True, slots=True)
class ScenarioView(_AdvisoryStanding):
    """A library template, browsable.

    Every field a claim needs is here — hypothesis, timeline, stop conditions,
    recovery — because :class:`~mayhem.domain.scenarios.ScenarioTemplate` cannot
    be constructed without them. What it deliberately does not carry is anything
    about authority: browsing a scenario is reading a claim about a failure mode,
    and reading it grants nothing.
    """

    ref: str
    template_id: str
    version: str
    title: str
    hypothesis: str
    blast_scope: str
    duration_s: float
    fault_ids: tuple[str, ...]
    timeline: tuple[TimelineView, ...]
    stop_conditions: tuple[str, ...]
    recovery: RecoveryView
    submits_through: str

    @property
    def authority(self) -> str:
        """Always ``none``. A template is a claim, not a decision."""
        return "none"

    def to_dict(self) -> dict[str, object]:
        return {
            "ref": self.ref,
            "standing": self.standing,
            "grants_approval": self.grants_approval,
            "grants_authorization": self.grants_authorization,
            "authority": self.authority,
            "template_id": self.template_id,
            "version": self.version,
            "title": self.title,
            "hypothesis": self.hypothesis,
            "blast_scope": self.blast_scope,
            "duration_s": self.duration_s,
            "fault_ids": list(self.fault_ids),
            "timeline": [step.to_dict() for step in self.timeline],
            "stop_conditions": list(self.stop_conditions),
            "recovery": self.recovery.to_dict(),
            "submits_through": self.submits_through,
        }


@dataclass(frozen=True, slots=True)
class ScenarioInstantiationView(_AdvisoryStanding):
    """A template bound to one declared coverage cell.

    Rendered *before* anything is compiled, and labelled with what it will go
    through. It carries no approval, no weight, and no execution field, matching
    :class:`~mayhem.domain.scenarios.ScenarioInstantiation` exactly — the view
    adds no vocabulary the type does not have.
    """

    ref: str
    target: str
    execution_context: str
    parameter_band: str
    cell_key: str
    hypothesis: str
    duration_s: float
    fault_ids: tuple[str, ...]
    timeline: tuple[TimelineView, ...]
    stop_conditions: tuple[str, ...]
    recovery: RecoveryView
    digest: str
    submits_through: str

    @property
    def authority(self) -> str:
        """Always ``none``."""
        return "none"

    def to_dict(self) -> dict[str, object]:
        return {
            "ref": self.ref,
            "standing": self.standing,
            "grants_approval": self.grants_approval,
            "grants_authorization": self.grants_authorization,
            "authority": self.authority,
            "target": self.target,
            "execution_context": self.execution_context,
            "parameter_band": self.parameter_band,
            "cell_key": self.cell_key,
            "hypothesis": self.hypothesis,
            "duration_s": self.duration_s,
            "fault_ids": list(self.fault_ids),
            "timeline": [step.to_dict() for step in self.timeline],
            "stop_conditions": list(self.stop_conditions),
            "recovery": self.recovery.to_dict(),
            "digest": self.digest,
            "submits_through": self.submits_through,
        }


def scenario_view(template: ScenarioTemplate) -> ScenarioView:
    """One library template, in view-model shape. Pure."""
    return ScenarioView(
        ref=template.ref,
        template_id=template.template_id,
        version=template.version,
        title=template.title,
        hypothesis=template.hypothesis,
        blast_scope=template.blast_scope,
        duration_s=template.duration_s,
        fault_ids=template.fault_ids,
        timeline=tuple(TimelineView.of(step) for step in template.timeline),
        stop_conditions=template.stop_conditions,
        recovery=RecoveryView(
            expects=template.recovery.expects,
            compensation=template.recovery.compensation,
            verified_by=template.recovery.verified_by,
        ),
        submits_through="mayhem.controller.advisor_service.submit_scenario",
    )


def scenario_views(templates: Sequence[ScenarioTemplate]) -> tuple[ScenarioView, ...]:
    """The library, sorted by citation ref, so the listing is a stable value."""
    return tuple(scenario_view(t) for t in sorted(templates, key=lambda t: t.ref))


def scenario_instantiation_view(instantiation: ScenarioInstantiation) -> ScenarioInstantiationView:
    """One instantiation, in view-model shape. Pure, and before any compilation."""
    return ScenarioInstantiationView(
        ref=instantiation.ref,
        target=instantiation.target,
        execution_context=instantiation.execution_context,
        parameter_band=instantiation.parameter_band,
        cell_key=instantiation.cell.key,
        hypothesis=instantiation.hypothesis,
        duration_s=instantiation.duration_s,
        fault_ids=instantiation.fault_ids,
        timeline=tuple(TimelineView.of(step) for step in instantiation.timeline),
        stop_conditions=instantiation.stop_conditions,
        recovery=RecoveryView(
            expects=instantiation.recovery.expects,
            compensation=instantiation.recovery.compensation,
            verified_by=instantiation.recovery.verified_by,
        ),
        digest=instantiation.digest,
        submits_through="mayhem.controller.advisor_service.submit_scenario",
    )


# =============================================================================
# The sealed inputs document
# =============================================================================

#: Every key the inputs document may declare. Everything else is refused rather
#: than ignored, so a document cannot smuggle a field past the boundary by naming
#: it something nothing looks at. There is no ``approval``, no ``execute``, and
#: no ``weight`` anywhere outside a criteria *declaration* row.
ALLOWED_INPUT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "landscape_id",
        "criteria",
        "readings",
        "topology",
        "cells",
        "incidents",
        "deployments",
        "established",
    }
)

_ALLOWED_CRITERIA_BLOCK: Final[frozenset[str]] = frozenset({"name", "criteria"})
_ALLOWED_CRITERIA_ROW: Final[frozenset[str]] = frozenset({"name", "weight", "question"})
_ALLOWED_READING_ROW: Final[frozenset[str]] = frozenset({"criterion", "value", "evidence"})
#: The cell's four declared dimensions, stated separately from its coverage
#: state. The cell key itself is *derived* from these four by
#: :class:`~mayhem.domain.coverage.CoverageCell` and never written by a caller —
#: it joins its parts with the unit separator, which is not a character anybody
#: can type into a JSON document, so a document that asked for it by hand would
#: be asking for a key one keystroke away from being wrong.
_ALLOWED_CELL_IDENTITY: Final[frozenset[str]] = frozenset(
    {"target", "fault_kind", "execution_context", "parameter_band"}
)
_ALLOWED_CELL_ROW: Final[frozenset[str]] = _ALLOWED_CELL_IDENTITY | {"state"}
_ALLOWED_READINGS_ROW: Final[frozenset[str]] = _ALLOWED_CELL_IDENTITY | {"readings"}
_ALLOWED_TOPOLOGY_BLOCK: Final[frozenset[str]] = frozenset({"snapshot_id", "graph"})
_ALLOWED_ESTABLISHED_ROW: Final[frozenset[str]] = frozenset(
    {"cell_key", "evidence_digest", "run_label"}
)


def _refuse_unknown(document: Mapping[str, Any], allowed: frozenset[str], *, where: str) -> None:
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise AdvisorViewRefused(
            RULE_INPUT_UNKNOWN_FIELD,
            f"{where} declares unknown field(s) {unknown}; allowed fields are {sorted(allowed)}. "
            "An unread field is not a field nobody cares about — it is a field whose meaning "
            "this surface would have to guess, and guessing is how an approval would arrive "
            "through a door nobody checked",
        )


def _require(document: Mapping[str, Any], field_name: str, *, where: str) -> Any:
    if field_name not in document:
        raise AdvisorViewRefused(
            RULE_INPUT_INCOMPLETE,
            f"{where} declares no {field_name!r}: every field this surface reads is required "
            "and none of them has a default, because a default here would be mayhem inventing "
            "a fact about a system it has not read",
        )
    return document[field_name]


@dataclass(frozen=True, slots=True)
class AdvisorInputs:
    """One parsed inputs document: the sealed facts this surface can read.

    Validation happens once, at :meth:`from_document`, so nothing downstream has
    to ask whether a field was there. Every value is a *declared* fact: the
    coverage landscape, the topology snapshot and its graph, the incident
    captures, the deployment record, the sealed cells already established, the
    customer's criteria declaration, and the readings against it.
    """

    landscape_id: str
    criteria: PriorityCriteria
    readings: Mapping[str, tuple[DeclaredReading, ...]]
    topology_snapshot_id: str
    graph: TopologyGraph
    cells: tuple[CoverageCell, ...]
    states: Mapping[str, CellState]
    incidents: Mapping[str, Any]
    deployments: Mapping[str, str]
    established: tuple[SealedCell, ...]

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> AdvisorInputs:
        """Parse and validate a document, refusing anything unexpected by name."""
        from mayhem.controller.advisor_service import SealedCell as _SealedCell
        from mayhem.domain.advisor import CustomerCriterion as _Criterion
        from mayhem.domain.advisor import IncidentFacts as _Incident
        from mayhem.domain.advisor import PriorityCriteria as _Criteria
        from mayhem.domain.coverage import CellState as _State
        from mayhem.domain.coverage import CoverageCell as _Cell
        from mayhem.domain.topology import TopologyGraph as _Graph

        _refuse_unknown(document, ALLOWED_INPUT_FIELDS, where="the inputs document")

        criteria_doc = _require(document, "criteria", where="the inputs document")
        _refuse_unknown(criteria_doc, _ALLOWED_CRITERIA_BLOCK, where="the criteria declaration")
        criteria_rows = _require(criteria_doc, "criteria", where="the criteria declaration")
        if not isinstance(criteria_rows, list) or not criteria_rows:
            raise AdvisorViewRefused(
                RULE_INPUT_INCOMPLETE,
                "the criteria declaration lists no criteria: a priority computed against "
                "nothing is not a low priority, it is a ranking with no basis, and every "
                "candidate would tie at the top of it",
            )
        declared: list[_Criterion] = []
        for row in criteria_rows:
            _refuse_unknown(row, _ALLOWED_CRITERIA_ROW, where="a criteria declaration row")
            declared.append(
                _Criterion(
                    name=str(_require(row, "name", where="a criteria declaration row")),
                    weight=float(_require(row, "weight", where="a criteria declaration row")),
                    question=str(_require(row, "question", where="a criteria declaration row")),
                )
            )
        criteria = _Criteria(
            name=str(_require(criteria_doc, "name", where="the criteria declaration")),
            criteria=tuple(declared),
        )

        topology_doc = _require(document, "topology", where="the inputs document")
        _refuse_unknown(topology_doc, _ALLOWED_TOPOLOGY_BLOCK, where="the topology block")
        topology_snapshot_id = str(
            _require(topology_doc, "snapshot_id", where="the topology block")
        )
        graph = _Graph.model_validate(_require(topology_doc, "graph", where="the topology block"))

        cells: list[_Cell] = []
        states: dict[str, _State] = {}
        for row in _require(document, "cells", where="the inputs document"):
            _refuse_unknown(row, _ALLOWED_CELL_ROW, where="a coverage cell row")
            cell = _Cell(
                target=str(_require(row, "target", where="a coverage cell row")),
                fault_kind=str(_require(row, "fault_kind", where="a coverage cell row")),
                execution_context=str(
                    _require(row, "execution_context", where="a coverage cell row")
                ),
                parameter_band=str(_require(row, "parameter_band", where="a coverage cell row")),
            )
            states[cell.key] = _State(
                str(_require(row, "state", where="a coverage cell row"))
            )
            cells.append(cell)

        incidents: dict[str, _Incident] = {}
        for row in _require(document, "incidents", where="the inputs document"):
            capture = _Incident.normalise(
                incident_id=str(_require(row, "incident_id", where="an incident row")),
                service=str(_require(row, "service", where="an incident row")),
                failure_signature=str(
                    _require(row, "failure_signature", where="an incident row")
                ),
                dependency=str(_require(row, "dependency", where="an incident row")),
                topology_snapshot_id=str(
                    _require(row, "topology_snapshot_id", where="an incident row")
                ),
                duration_s=float(_require(row, "duration_s", where="an incident row")),
                percentiles=_require(row, "percentiles", where="an incident row"),
                versions=_require(row, "versions", where="an incident row"),
                started_at=str(row.get("started_at", "")),
                ended_at=str(row.get("ended_at", "")),
            )
            if capture.incident_id in incidents:
                raise AdvisorViewRefused(
                    RULE_INPUT_INCOMPLETE,
                    f"the inputs document declares incident {capture.incident_id!r} twice: a "
                    "capture cited by an id has to resolve to one set of facts, or a replay's "
                    "source depends on which row was read last",
                )
            incidents[capture.incident_id] = capture

        deployments = {
            str(component): str(version)
            for component, version in dict(
                _require(document, "deployments", where="the inputs document")
            ).items()
        }
        established = tuple(
            _SealedCell(
                cell_key=str(_require(row, "cell_key", where="a sealed cell row")),
                evidence_digest=str(
                    _require(row, "evidence_digest", where="a sealed cell row")
                ),
                run_label=str(_require(row, "run_label", where="a sealed cell row")),
            )
            for row in _require(document, "established", where="the inputs document")
        )

        readings: dict[str, tuple[DeclaredReading, ...]] = {}
        for row in _require(document, "readings", where="the inputs document"):
            _refuse_unknown(row, _ALLOWED_READINGS_ROW, where="a readings row")
            cell = _Cell(
                target=str(_require(row, "target", where="a readings row")),
                fault_kind=str(_require(row, "fault_kind", where="a readings row")),
                execution_context=str(
                    _require(row, "execution_context", where="a readings row")
                ),
                parameter_band=str(_require(row, "parameter_band", where="a readings row")),
            )
            if cell.key in readings:
                raise AdvisorViewRefused(
                    RULE_INPUT_INCOMPLETE,
                    f"the inputs document holds two readings rows for cell {cell.key!r}: a "
                    "gap has one customer's reading of it, and a second row would make the "
                    "ranking depend on which one was read last",
                )
            parsed: list[DeclaredReading] = []
            for entry in _require(row, "readings", where="a readings row"):
                _refuse_unknown(entry, _ALLOWED_READING_ROW, where="a criterion reading row")
                parsed.append(
                    DeclaredReading(
                        criterion=str(
                            _require(entry, "criterion", where="a criterion reading row")
                        ),
                        value=float(_require(entry, "value", where="a criterion reading row")),
                        evidence=str(_require(entry, "evidence", where="a criterion reading row")),
                    )
                )
            readings[cell.key] = tuple(parsed)

        return cls(
            landscape_id=str(_require(document, "landscape_id", where="the inputs document")),
            criteria=criteria,
            readings=readings,
            topology_snapshot_id=topology_snapshot_id,
            graph=graph,
            cells=tuple(cells),
            states=states,
            incidents=incidents,
            deployments=deployments,
            established=established,
        )

    @classmethod
    def from_path(cls, path: Path) -> AdvisorInputs:
        """Read and parse a document, or refuse a path that is not one."""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise MayhemCliError(
                code="validation_error",
                message=f"cannot read the inputs document at {path}: {exc}",
                details={"inputs": str(path)},
                remediation="pass --inputs with a readable JSON document",
            ) from None
        except json.JSONDecodeError as exc:
            raise MayhemCliError(
                code="validation_error",
                message=f"the inputs document at {path} is not valid JSON: {exc}",
                details={"inputs": str(path)},
                remediation="fix the document's JSON syntax",
            ) from None
        if not isinstance(raw, dict):
            raise MayhemCliError(
                code="validation_error",
                message=f"the inputs document at {path} must be a JSON object",
                details={"inputs": str(path)},
                remediation="the document declares named fields; a bare value cannot",
            )
        return cls.from_document(raw)


# =============================================================================
# The five read ports, over the document and nothing else
# =============================================================================


@dataclass(frozen=True, slots=True)
class _DocumentTopology:
    """The topology port, over the document's snapshot. Two reads and no others."""

    inputs: AdvisorInputs

    def topology(self) -> TopologyGraph:
        return self.inputs.graph

    def snapshot_id(self) -> str:
        return self.inputs.topology_snapshot_id


@dataclass(frozen=True, slots=True)
class _DocumentCoverage:
    """The coverage port, over the document's declared landscape."""

    inputs: AdvisorInputs

    def landscape_id(self) -> str:
        return self.inputs.landscape_id

    def cells(self) -> tuple[CoverageCell, ...]:
        return self.inputs.cells

    def states(self) -> Mapping[str, CellState]:
        return self.inputs.states


@dataclass(frozen=True, slots=True)
class _DocumentIncidents:
    """The incident port, over the document's normalised captures."""

    inputs: AdvisorInputs

    def captures(self) -> tuple[Any, ...]:
        return tuple(self.inputs.incidents[key] for key in sorted(self.inputs.incidents))


@dataclass(frozen=True, slots=True)
class _DocumentDeployments:
    """The deployment port: what the document says is running, per component."""

    inputs: AdvisorInputs

    def releases(self) -> Mapping[str, str]:
        return self.inputs.deployments


@dataclass(frozen=True, slots=True)
class _DocumentEvidence:
    """The evidence port, over the cells a sealed run already established."""

    inputs: AdvisorInputs

    def established(self) -> tuple[SealedCell, ...]:
        return self.inputs.established


def advisor_service_for(inputs: AdvisorInputs, *, sink: Any | None = None) -> AdvisorService:
    """An :class:`~mayhem.controller.advisor_service.AdvisorService` over a document.

    No database, no engine, no clock. ``sink`` is the caller's own
    :class:`~mayhem.domain.policy_gate.MutationSink`, handed in only to be
    *read* afterwards: the engine evaluates through
    :meth:`~mayhem.controller.advisor_service.AdvisorService.detached`, so a
    pre-loaded sink whose length does not change is the evidence that viewing
    mutated nothing.
    """
    from mayhem.controller.advisor_service import AdvisorService

    return AdvisorService(
        topology=_DocumentTopology(inputs),
        coverage=_DocumentCoverage(inputs),
        incidents=_DocumentIncidents(inputs),
        deployments=_DocumentDeployments(inputs),
        evidence=_DocumentEvidence(inputs),
        sink=sink,
    )


def advisor_safety_context(*, fingerprint: str = "") -> SafetyContext:
    """The one safety context this surface builds, from fixed stated limits.

    No policy bundle, no approval gate, no runtime adapter — not as omissions but
    as statements. The advisor read sealed inputs and has no live runtime to ask
    what the cluster can do, so the capability line is unestablished and the proof
    says ``VOID`` naming it; it holds no policy bundle, so the policy state is
    :data:`POLICY_STATE_NO_BUNDLE` rather than "allowed"; and it holds no approval
    gate, so the authorization state is
    :data:`~mayhem.controller.advisor_service.SubmissionAuthorization.REQUIREMENTS_ONLY`.

    The blast-radius ceilings are module constants rather than options for the
    reason stated above them: a caller handed a flag for the ceiling would be
    handed the gate that is supposed to be checking it.

    ``fingerprint`` is the caller's declared environment fingerprint, and it is
    passed *twice* by the commands that use this — once here and once to
    ``plan_drill`` — so the two agree. The advisor does not measure the
    environment and does not invent one: it binds the value the caller declared to
    both sides of the fingerprint gate. An empty fingerprint (the default) is
    honest for a caller who has measured nothing, and the fingerprint gate will
    then refuse any plan carrying one, which is the correct answer rather than a
    surface-level workaround.
    """
    from mayhem.config import PolicyCfg
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.experiments import BlastRadiusBudget

    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(
            max_services_pct=ADVISORY_CAP_MAX_SERVICES_PCT,
            max_hosts=ADVISORY_CAP_MAX_HOSTS,
            max_concurrent_faults=ADVISORY_CAP_MAX_CONCURRENT_FAULTS,
            max_duration_per_fault_s=ADVISORY_CAP_MAX_DURATION_PER_FAULT_S,
            forbidden_fault_pairs=frozenset(),
        ),
        fingerprint=fingerprint,
    )


def propose_candidate(finding: Finding) -> ExperimentCandidate:
    """This surface's proposal function: a proposal, deterministically derived.

    No model is consulted, and nothing is invented about the *system* — the
    candidate names the fault and the target the finding already cited, plus stop
    conditions read off the same coverage state. It is what
    :func:`mayhem.domain.advisor.recommendations_for` injects, and its output is
    an :class:`~mayhem.domain.advisor.UntrustedRecommendationDraft` whatever it
    says.
    """
    return ExperimentCandidate(
        experiment_id=f"exp:gap:{finding.finding_id}",
        hypothesis=(
            f"breaking {finding.cell.fault_kind} on {finding.cell.target} would show what "
            f"coverage cell {finding.cell.key!r} is {finding.cell_state.value} about"
        ),
        suggested_probes=(f"{finding.cell.fault_kind}@{finding.cell.target}",),
        stop_conditions=(
            f"abort if {finding.cell.target} stops answering entirely",
            f"abort if the {finding.cell.execution_context} context still holds a lease "
            f"after the {finding.cell.parameter_band} band",
        ),
    )


# =============================================================================
# Building the engine's own inputs from the document
# =============================================================================


def _analyse(inputs: AdvisorInputs, *, sink: Any | None = None) -> AdvisorAnalysis:
    """Run the engine over the document, through its ordinary ``analyse`` entry point."""

    def weight(finding: Finding) -> Mapping[str, CriterionReading]:
        return _readings_for(inputs.criteria, inputs.readings.get(finding.cell_key, ()))

    return advisor_service_for(inputs, sink=sink).analyse(
        propose_candidate, inputs.criteria, weight
    )


def _recommendation_for(
    inputs: AdvisorInputs,
    finding: Finding,
    *,
    propose: Callable[[Finding], ExperimentCandidate] = propose_candidate,
) -> Recommendation:
    """A ranked, unapproved recommendation for one finding, or a named refusal.

    Built through the domain's own two pure functions, so the recommendation the
    gate sees is exactly the one the dashboard shows — same declaration, same
    readings, same ranking — and through :func:`ranked_views`, so the render
    refusal still applies to a candidate on its way to a gate.

    ``propose`` is the ordinary injection point
    :func:`mayhem.domain.advisor.recommendations_for` takes, and a scenario
    arrives through it like anything else:
    :meth:`~mayhem.domain.scenarios.ScenarioInstantiation.propose` is a function
    of one finding with that exact signature, so binding a scenario is not a
    special case — it is the same door, and there is no scenario-only planner.

    There is no approval parameter and no ``origin`` parameter. That is not an
    omission: :meth:`UntrustedRecommendationDraft.compile` returns a ``generated``
    recommendation with no approval, and :class:`Recommendation` refuses an
    approval on a ``generated`` origin, so this function cannot produce anything
    else.
    """
    from mayhem.domain.advisor import recommendations_for

    draft = recommendations_for(
        (finding,),
        inputs.criteria,
        {finding.finding_id: _declared_readings(inputs, finding)},
        propose=propose,
    )[0]
    ranked = ranked_views(_rank_one(draft, inputs), inputs.criteria)
    if not ranked:
        raise AdvisorViewRefused(
            RULE_VIEW_RECOMMENDATION_NOT_RENDERABLE,
            f"recommendation for {finding.cell_key!r} produced nothing to submit",
        )
    return draft.compile(
        inputs.criteria,
        _readings_for(inputs.criteria, inputs.readings.get(finding.cell_key, ())),
    )


def _declared_readings(inputs: AdvisorInputs, finding: Finding) -> dict[str, CriterionReading]:
    """The customer's readings for one gap, or a refusal naming what is missing."""
    return _readings_for(inputs.criteria, inputs.readings.get(finding.cell_key, ()))


def _rank_one(
    draft: UntrustedRecommendationDraft, inputs: AdvisorInputs
) -> Sequence[Recommendation]:
    return rank_drafts(
        (draft,),
        inputs.criteria,
        {draft.finding.finding_id: _declared_readings(inputs, draft.finding)},
    )


def _finding_for_cell(analysis: AdvisorAnalysis, cell_key: str, *, what: str) -> Finding:
    """The analysed finding for a cell, or a refusal naming the cell that is not a gap."""
    finding = next((f for f in analysis.findings if f.cell.key == cell_key), None)
    if finding is None:
        # Why it is absent matters, so the suppressed list is read rather than
        # summarised: "covered", "established by sealed evidence", and "anchored
        # to no topology" are three different findings about this cell.
        declined = tuple(
            f"{row.cell_key} ({row.reason.value}: {row.detail})"
            for row in analysis.suppressed
            if row.cell_key == cell_key
        )
        raise AdvisorViewRefused(
            RULE_VIEW_SCENARIO_CELL_NOT_A_GAP,
            f"{what} occupies cell {cell_key!r}, which is not a gap in landscape "
            f"{analysis.landscape_id!r} (declined: {list(declined) or 'not declared at all'}). "
            "A scenario bound to a covered cell has no coverage claim to make, and one bound "
            "to a cell the landscape does not declare lands nowhere a reader can look up",
        )
    return finding


# =============================================================================
# Replay request assembly from command-line arguments
# =============================================================================

#: ``PARAM=duration`` for a duration binding, ``PARAM=LABEL:UNIT`` for a
#: percentile. One grammar, parsed once, so a typo is a usage error rather than a
#: silently unbound parameter.
_BINDING_RE: Final[re.Pattern[str]] = re.compile(r"^(?P<param>[^\s=]+)=(?P<rest>.+)$")


def parse_binding(spec: str) -> Any:
    """``param=duration`` or ``param=label:unit`` into a ``ParameterBinding``.

    The two spellings are the two sources
    :class:`~mayhem.controller.advisor_service.ParameterSource` can reach, and
    refusing a third keeps "every generated parameter traces to an incident fact" a
    property of the vocabulary rather than of a parser being careful.
    """
    from mayhem.controller.advisor_service import ParameterBinding, ParameterSource

    match = _BINDING_RE.match(spec.strip())
    if match is None:
        raise click.UsageError(
            f"--bind {spec!r} is not PARAM=SOURCE. Use PARAM=duration for the incident's own "
            "duration, or PARAM=LABEL:UNIT for one observed percentile, e.g. "
            "--bind jitter_ms=p99:ms"
        )
    parameter = match.group("param").strip()
    rest = match.group("rest").strip()
    if rest == "duration":
        return ParameterBinding(parameter, ParameterSource.DURATION)
    label, _, unit = rest.partition(":")
    if not label.strip() or not unit.strip():
        raise click.UsageError(
            f"--bind {spec!r} binds a percentile but names no unit. A unit the binding does "
            "not state is a unit the compiler would have to guess, and a guessed unit turns a "
            "replay into a different experiment"
        )
    return ParameterBinding(parameter, ParameterSource.PERCENTILE, label=label, unit=unit)


# =============================================================================
# Renderers — every one prints a view-model value and re-derives nothing
# =============================================================================


def _standing_line(view: _AdvisoryStanding) -> str:
    return (
        f"standing: {view.standing}   grants_approval: {str(view.grants_approval).lower()}   "
        f"grants_authorization: {str(view.grants_authorization).lower()}"
    )


def render_dashboard(dashboard: AdvisorDashboard) -> tuple[str, ...]:
    """The dashboard, as text. Prints a view; decides nothing."""
    lines = [
        style.cyan(f"{dashboard.artifact} — landscape {dashboard.landscape_id!r}"),
        f"  topology snapshot: {dashboard.topology_snapshot_id!r}   graph: "
        f"{dashboard.graph_identity[:12]}…",
        f"  {_standing_line(dashboard)}",
        style.cyan(f"declared criteria ({dashboard.criteria_name!r})"),
    ]
    for declared in dashboard.declared_criteria:
        lines.append(f"  - {declared.name} weight {declared.weight:g} — {declared.question}")
    lines.append(
        style.cyan(
            f"ranked recommendations ({len(dashboard.ranked)}) — order is the weighted mean "
            "of the declared criteria, derived on read"
        )
    )
    for row in dashboard.ranked:
        lines.append(
            f"  {row.position}. {row.recommendation_id} ({row.experiment_id}) priority "
            f"{row.priority_total:.3f}  [{row.origin} / authority {row.authority}]"
        )
        lines.append(f"     failure mode: {row.failure_mode}")
        lines.append(
            f"     cell: {row.cell_ref} — {row.cell_state} in {row.landscape_id!r}"
        )
        lines.append(f"     topology: {list(row.topology_node_ids)}")
        lines.append(f"     hypothesis: {row.hypothesis}")
        for traced in row.declared_criteria:
            lines.append(
                f"     criterion {traced.name}: {traced.value:.2f} x "
                f"{traced.weight:g} = {traced.contribution:.3f} ({traced.evidence})"
            )
        lines.append(f"     rationale: {row.rationale}")
        lines.append("     cites:")
        lines.extend(
            f"       - {fact.kind}: {fact.ref} — {fact.detail}" for fact in row.cited_facts
        )
        lines.append(f"     next: {row.submits_through}")
    lines.append(style.cyan(f"untrusted drafts ({len(dashboard.drafts)})"))
    for draft in dashboard.drafts:
        lines.append(
            f"  - {draft.recommendation_id} [{draft.trust}, authority {draft.authority}] "
            f"{draft.hypothesis}"
        )
    lines.append(style.cyan(f"declined cells ({len(dashboard.suppressed)})"))
    for declined in dashboard.suppressed:
        lines.append(
            f"  - {declined.cell_key.replace(chr(31), '/')}: {declined.reason} — "
            f"{declined.detail}"
        )
    lines.append(
        f"mutation: {dashboard.mutation_calls} call(s), backend "
        f"{'attached' if dashboard.mutation_backend_attached else 'detached'} — reading is not "
        "writing"
    )
    lines.extend(f"note: {note}" for note in dashboard.notes)
    return tuple(lines)


def render_replay(view: ReplayView) -> tuple[str, ...]:
    """A replayed candidate, as text. Prints a view; decides nothing."""
    lines = [
        style.cyan(f"incident {view.incident_id} → candidate {view.fault_id}"),
        f"  service: {view.service}   dependency: {view.dependency}",
        f"  signature: {view.failure_signature}",
        f"  pinned to snapshot: {view.topology_snapshot_id!r}   graph: "
        f"{view.graph_identity[:12]}…",
        f"  cell: {view.cell_key}   finding: {view.finding_id}",
        f"  hypothesis: {view.hypothesis}",
        f"  duration: {view.duration_s:g}s",
        f"  {_standing_line(view)}   authority: {view.authority}",
        style.cyan("parameters, each traced to an incident fact"),
    ]
    for parameter in view.parameters:
        lines.append(
            f"  - {parameter.parameter} = {parameter.value:g}{parameter.unit} ← "
            f"{parameter.source} ({parameter.incident_id})"
        )
    lines.append("cites:")
    lines.extend(f"  - {fact.kind}: {fact.ref} — {fact.detail}" for fact in view.cited_facts)
    lines.append(f"replay digest: {view.replay_digest}")
    lines.append(f"next gate: {view.next_gate}")
    return tuple(lines)


def render_submission(view: SubmissionView) -> tuple[str, ...]:
    """A submitted candidate, as text.

    The authorization line states the gate's own state and this surface's own grant
    as two separate facts, in that order, so no reader has to guess which is which.
    """
    return (
        style.cyan(f"{view.via}: {view.recommendation_id} ({view.experiment_id})"),
        f"  origin: {view.origin}   {_standing_line(view)}   authority: {view.authority}",
        f"  criteria: {view.criteria_name!r} → weighted mean {view.priority_total:.3f} "
        "(derived on read)",
        f"  plan: {view.plan_digest[:12]}… ({view.plan_step_count} step(s), topology snapshot "
        f"{view.plan_topology_snapshot_id!r})",
        f"  proof: {view.proof_verdict}"
        + (f" — {view.proof_void_reason}" if view.proof_void_reason else ""),
        "  gate: "
        + ("admitted" if view.admitted_by_gate else f"refused {list(view.refusing_gates)}"),
        f"  policy: {view.policy_state}",
        f"  authorization state: {view.authorization_state} — reported by the "
        "required_approvals line, not granted here",
        f"  surface grants authorization: {str(view.surface_grants_authorization).lower()}",
        f"  mutation: {view.mutation_calls} call(s), backend "
        f"{'attached' if view.mutation_backend_attached else 'detached'}",
        "  next gate: a person, through the ordinary approval chain",
    )


def render_scenario(view: ScenarioView | ScenarioInstantiationView) -> tuple[str, ...]:
    """A library template or an instantiation, as text.

    The header names the template's title for a browsed template and its bound
    cell for an instantiation, because an instantiation does not carry a title:
    it carries the cell it occupies, and that is what distinguishes one from
    another.
    """
    heading = (
        f"{view.ref} — {view.title}"
        if isinstance(view, ScenarioView)
        else f"{view.ref} instantiated for {view.target}"
    )
    lines = [
        style.cyan(heading),
        f"  hypothesis: {view.hypothesis}",
        f"  {_standing_line(view)}   authority: {view.authority}",
        f"  duration: {view.duration_s:g}s   faults: {list(view.fault_ids)}",
        style.cyan("timeline"),
    ]
    for step in view.timeline:
        lines.append(f"  t+{step.at_s:g}s {step.fault_id} for {step.duration_s:g}s")
        lines.append(f"       expect: {step.expects}")
    lines.append(style.cyan("stop conditions"))
    lines.extend(f"  - {condition}" for condition in view.stop_conditions)
    lines.append(style.cyan("recovery"))
    lines.append(f"  expects: {view.recovery.expects}")
    lines.append(f"  compensation: {view.recovery.compensation}")
    lines.append(f"  verified by: {view.recovery.verified_by}")
    if isinstance(view, ScenarioInstantiationView):
        lines.append(f"cell: {view.cell_key}")
        lines.append(f"digest: {view.digest}")
        lines.append("nothing compiled: no plan exists yet for this cell")
    lines.append(f"next: {view.submits_through}")
    return tuple(lines)


# =============================================================================
# CLI plumbing shared by the commands
# =============================================================================


def _call(thunk: Any) -> Any:
    """Run a view-model or engine step, turning a named refusal into an envelope.

    The only place a refusal crosses from ``InvariantViolationError`` to a CLI
    envelope. Everything above it raises named rules; this reports them. The rule
    id goes into ``details`` so a machine reader gets the name the plan spells
    rather than a paraphrase invented here, and so a future UI rendering the same
    refusal gets the same fields this does.
    """
    try:
        return thunk()
    except InvariantViolationError as exc:
        raise MayhemCliError(
            code="safety_refusal",
            message=str(exc),
            details={"rule": exc.rule},
            remediation=(
                "an advisor view is refused rather than degraded: the finding, criterion, "
                "topology pin, or gate it names has to be satisfied first"
            ),
        ) from None


#: Shared Click declarations, so ``advisor replay`` and ``advisor submit`` cannot
#: drift apart on what a replay needs. Built once at import from
#: :func:`click.option`, whose factory is typed, and composed here rather than
#: applied as bare ``click.Option`` instances so the decorators keep their type.
def _compose[F: Callable[..., Any]](
    *decorators: Callable[[F], F],
) -> Callable[[F], F]:
    """Fold several Click decorators into one, preserving the decorated function's type.

    A factory rather than bare ``click.Option`` instances as decorators, because
    Click's parameter objects are not callable in its own type stubs and a chain
    of them would leave every command untyped.
    """

    def decorate(fn: F) -> F:
        for one in reversed(decorators):
            fn = one(fn)
        return fn

    return decorate


_INPUTS_OPTION = _compose(
    click.option(
        "--inputs",
        "inputs_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        required=True,
        metavar="FILE",
        help="The sealed inputs document: coverage landscape, topology snapshot, incident "
        "captures, deployment record, and the declared customer criteria with the readings "
        "against them. No database is read.",
    )
)

_REPLAY_OPTIONS = _compose(
    click.option(
        "--incident",
        "incident_id",
        required=True,
        metavar="ID",
        help="The capture to replay.",
    ),
    click.option(
        "--fault-id",
        "fault_id",
        required=True,
        metavar="FAULT",
        help="The catalog fault to inject. Declared, never derived: choosing which fault to "
        "inject is a judgement that belongs to whoever reads the incident.",
    ),
    click.option(
        "--context",
        "execution_context",
        required=True,
        metavar="CTX",
        help="The coverage cell's execution context.",
    ),
    click.option(
        "--band",
        "parameter_band",
        required=True,
        metavar="BAND",
        help="The coverage cell's parameter band.",
    ),
    click.option(
        "--bind",
        "bindings",
        multiple=True,
        metavar="SPEC",
        help="Bind a fault parameter to an incident fact: PARAM=duration, or PARAM=LABEL:UNIT "
        "for one observed percentile. Repeatable, and required at least once — a replay whose "
        "every value came from a catalog default reproduces nothing.",
    ),
)

_RUN_OPTIONS = _compose(
    click.option(
        "--run-id",
        "run_id",
        metavar="ID",
        help="The run id the candidate compiles under. Required unless --preview: a plan with "
        "no run id is not a plan.",
    ),
    click.option(
        "--config-snapshot",
        "config_snapshot_id",
        metavar="ID",
        help="The configuration snapshot the candidate compiles against. Required unless "
        "--preview.",
    ),
    click.option(
        "--fingerprint",
        "fingerprint",
        default="",
        metavar="HEX",
        help="The environment fingerprint (64 hex characters), or "
        f"${ADVISORY_FINGERPRINT_ENV}.",
    ),
)

_JSON_OPTION = _compose(
    click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit a JSON projection instead of the text rendering.",
    )
)

_SCENARIO_CELL_OPTIONS = _compose(
    click.option(
        "--target",
        "target",
        required=True,
        metavar="TARGET",
        help="The cell's target.",
    ),
    click.option(
        "--context",
        "execution_context",
        required=True,
        metavar="CTX",
        help="The cell's execution context.",
    ),
    click.option(
        "--band",
        "parameter_band",
        required=True,
        metavar="BAND",
        help="The cell's band.",
    ),
)


def _echo(lines: Iterable[str]) -> None:
    for line in lines:
        click.echo(line)


def _bindings_from(specs: Sequence[str]) -> tuple[Any, ...]:
    parsed = tuple(parse_binding(spec) for spec in specs)
    if not parsed:
        raise click.UsageError(
            "--bind is required at least once: a replay that binds no parameter to an incident "
            "fact compiles a fault whose every value came from the catalog's defaults, which "
            "is a different experiment wearing this incident's name"
        )
    return parsed


def _replay_request(
    fault_id: str, execution_context: str, parameter_band: str, specs: Sequence[str]
) -> Any:
    from mayhem.controller.advisor_service import ReplayRequest

    return ReplayRequest(
        fault_id=fault_id,
        execution_context=execution_context,
        parameter_band=parameter_band,
        bindings=_bindings_from(specs),
    )


def _require_run_arguments(run_id: str, config_snapshot_id: str) -> None:
    """Refuse a submission with no run id or no configuration snapshot.

    Checked here rather than by ``required=True`` so ``advisor scenario
    instantiate --preview`` can be a real, complete command that compiles nothing:
    a preview that had to name a run it would never compile under would be
    asking for a fact it has no use for.
    """
    missing = [
        flag
        for flag, value in (("--run-id", run_id), ("--config-snapshot", config_snapshot_id))
        if not value.strip()
    ]
    if missing:
        raise click.UsageError(
            f"{' and '.join(missing)} required: a candidate that reaches the planner has to "
            "say which run it belongs to and which configuration it was planned against, and "
            "neither has a default this surface may invent. Drop --preview to compile "
            "nothing instead"
        )


def _fingerprint(explicit: str) -> str:
    candidate = (explicit or os.environ.get(ADVISORY_FINGERPRINT_ENV, "")).strip()
    if not _FINGERPRINT_RE.match(candidate):
        raise click.UsageError(
            f"--fingerprint must be 64 hex characters (or set ${ADVISORY_FINGERPRINT_ENV}); got "
            f"{candidate!r}. An environment fingerprint is a binding to what was measured, and "
            "a value nobody measured is not one"
        )
    return candidate


def _incident(inputs: AdvisorInputs, incident_id: str) -> Any:
    capture = inputs.incidents.get(incident_id)
    if capture is None:
        raise MayhemCliError(
            code="validation_error",
            message=(
                f"the inputs document declares no incident {incident_id!r}; it declares "
                f"{sorted(inputs.incidents)}. An incident the advisor cannot read cannot be "
                "replayed, and there is no default incident to replay instead"
            ),
            details={
                "incident_id": incident_id,
                "declared": ",".join(sorted(inputs.incidents)),
            },
            remediation="add the capture to the inputs document, or name one it declares",
        )
    return capture


def _scenario_ref(library: ScenarioLibrary, ref: str) -> ScenarioTemplate:
    """A template by ``id@version``, or by id at its highest version.

    A ref with no version resolves to :meth:`ScenarioLibrary.latest`, which is a
    resolved answer rather than a silent one: the rendered view carries the
    version it resolved to, so a report citing the scenario can name it.
    """
    template_id, _, version = ref.partition("@")
    template = (
        library.get(template_id, version) if version else library.latest(template_id)
    )
    if template is None:
        raise MayhemCliError(
            code="validation_error",
            message=(
                f"the scenario library declares no {ref!r}; it declares {list(library.refs())}"
            ),
            details={"ref": ref, "declared": ",".join(library.refs())},
            remediation="pick one of the declared id@version citations",
        )
    return template


# =============================================================================
# The commands
# =============================================================================


@click.group("advisor", help="Recommend experiments from sealed facts; replay incidents.")
def advisor() -> None:
    """Reliability advisor: findings ranked by declared criteria, replay, scenarios.

    Everything here is **advisory**. It correlates sealed facts and shows what
    they add up to. It approves nothing, authorises nothing, certifies nothing,
    and executes nothing — and there is no ``--approve`` and no ``--force``, so
    there is no flag here that could make it look as though it did.

    A candidate is compiled, proven, and gated by exactly the path an authored
    plan takes (:mod:`mayhem.controller.advisor_service`), and what comes back is
    a plan at a gate with nothing granted. The next step belongs to a person.
    """


@advisor.command("dashboard", help="Findings ranked by the declared criteria, with traces.")
@_INPUTS_OPTION
@click.option(
    "--limit",
    "limit",
    default=0,
    metavar="N",
    help="Show at most N ranked recommendations; 0 (the default) shows all of them. The full "
    "ranking is computed either way — this truncates the rendering, not the arithmetic.",
)
@_JSON_OPTION
def dashboard(inputs_path: Path, limit: int, as_json: bool) -> None:
    """Rank the declared landscape's gaps by the customer's declared criteria.

    The order is the weighted mean of the declared criteria, derived on read and
    stored nowhere; the criteria themselves — name, weight, and the customer
    question each answers — travel with every row. A recommendation whose
    rationale cannot be checked against those criteria is **not rendered at
    all**: this command fails with a named refusal rather than showing it with a
    warning, and the refusal happens in the view-model layer so a future UI
    inherits the guarantee instead of reimplementing it.
    """
    inputs = _call(lambda: AdvisorInputs.from_path(inputs_path))
    dashboard_view = _call(
        lambda: advisor_dashboard(_analyse(inputs), inputs.criteria, inputs.readings)
    )
    rows = dashboard_view.ranked if limit <= 0 else dashboard_view.ranked[:limit]
    payload = replace(dashboard_view, ranked=tuple(rows)).to_dict()
    if echo_machine(payload, as_json=as_json):
        return
    _echo(render_dashboard(replace(dashboard_view, ranked=tuple(rows))))


@advisor.command("replay", help="Turn one incident capture into a traced candidate.")
@_INPUTS_OPTION
@_REPLAY_OPTIONS
@_JSON_OPTION
def replay(
    inputs_path: Path,
    incident_id: str,
    fault_id: str,
    execution_context: str,
    parameter_band: str,
    bindings: Sequence[str],
    as_json: bool,
) -> None:
    """Compile one incident into a candidate, pinned to the snapshot it failed on.

    Every parameter the advisor generates carries the incident fact it came from,
    and a binding the capture cannot satisfy is a refusal rather than a default.
    This command stops at the candidate: it does not compile a plan, prove
    anything, or reach a gate. ``advisor submit`` is the next step, and a person is
    the step after that.
    """
    inputs = _call(lambda: AdvisorInputs.from_path(inputs_path))
    capture = _incident(inputs, incident_id)
    engine = advisor_service_for(inputs)
    request = _replay_request(fault_id, execution_context, parameter_band, bindings)
    compiled = _call(lambda: engine.replay(request, capture, engine.landscape()))
    view = _call(
        lambda: replay_view(compiled, topology_snapshot_id=inputs.topology_snapshot_id)
    )
    if echo_machine(view.to_dict(), as_json=as_json):
        return
    _echo(render_replay(view))


@advisor.command(
    "submit", help="Take a replayed candidate through the shared compile/gate path."
)
@_INPUTS_OPTION
@_REPLAY_OPTIONS
@_RUN_OPTIONS
@_JSON_OPTION
def submit(
    inputs_path: Path,
    incident_id: str,
    fault_id: str,
    execution_context: str,
    parameter_band: str,
    bindings: Sequence[str],
    run_id: str,
    config_snapshot_id: str,
    fingerprint: str,
    as_json: bool,
) -> None:
    """Compile, prove, and gate a replayed candidate — the road an authored plan takes.

    This is the *same* private core :meth:`AdvisorService.submit` uses, reached
    with no branch on origin, so a candidate from an incident and one a person
    wrote are compiled by the same planner, the same proof compiler, and the same
    policy gate. A candidate that will not compile is refused before either of
    those runs.

    It approves nothing and executes nothing. ``authorization_state`` says what the
    ``required_approvals`` line established; ``surface_grants_authorization`` is a
    constant ``False``, and a reader who wants to know what this command did can
    look at that one.

    The submitted candidate needs a declared reading for the cell it replays,
    because a :class:`~mayhem.domain.advisor.Recommendation` always carries a
    priority and a priority is always a function of the declared criteria. A cell
    with no reading is refused by name rather than given a default score.
    """
    inputs = _call(lambda: AdvisorInputs.from_path(inputs_path))
    capture = _incident(inputs, incident_id)
    engine = advisor_service_for(inputs)
    request = _replay_request(fault_id, execution_context, parameter_band, bindings)
    _require_run_arguments(run_id or "", config_snapshot_id or "")
    environment_fingerprint = _fingerprint(fingerprint)
    compiled = _call(lambda: engine.replay(request, capture, engine.landscape()))
    recommendation = _call(lambda: _recommendation_for(inputs, compiled.finding))
    view = _call(
        lambda: submission_view(
            engine.submit(
                recommendation,
                advisor_safety_context(fingerprint=environment_fingerprint),
                fault_id=compiled.fault_id,
                target=capture.service,
                duration_s=compiled.duration_s,
                parameters=compiled.parameter_values,
                run_id=run_id or "",
                config_snapshot_id=config_snapshot_id or "",
                environment_fingerprint=environment_fingerprint,
                traces=compiled.parameters,
            )
        )
    )
    if echo_machine(view.to_dict(), as_json=as_json):
        return
    _echo(render_submission(view))


# -- the scenario library browser ------------------------------------------------


@advisor.group("scenario", help="Browse the scenario library and instantiate a template.")
def scenario() -> None:
    """Browse versioned multi-fault scenarios, and bind one to a declared cell.

    A library entry is a claim about how a whole failure looks over time:
    hypothesis, timeline, stop conditions, and recovery. Browsing one reads the
    claim and grants nothing.
    """


@scenario.command("list", help="Every scenario template in the library, by citation.")
@_JSON_OPTION
def scenario_list(as_json: bool) -> None:
    """List the library. Reading the list changes nothing and decides nothing."""
    library = scenario_library()
    views = scenario_views(library.templates)
    payload = {
        "standing": ADVISORY_STANDING,
        "grants_approval": False,
        "grants_authorization": False,
        "library": library.name,
        "templates": [view.to_dict() for view in views],
    }
    if echo_machine(payload, as_json=as_json):
        return
    lines = [
        style.cyan(f"scenario library {library.name!r} ({len(views)})"),
        *(
            f"  {view.ref} — {view.title} ({view.duration_s:g}s, "
            f"{len(view.timeline)} moment(s), faults {list(view.fault_ids)})"
            for view in views
        ),
        f"standing: {ADVISORY_STANDING}   grants_approval: false   "
        "grants_authorization: false",
    ]
    _echo(lines)


@scenario.command("show", help="One scenario template in full.")
@click.argument("ref", metavar="ID@VERSION")
@_JSON_OPTION
def scenario_show(ref: str, as_json: bool) -> None:
    """Show one template: its hypothesis, timeline, stop conditions, and recovery."""
    view = scenario_view(_scenario_ref(scenario_library(), ref))
    if echo_machine(view.to_dict(), as_json=as_json):
        return
    _echo(render_scenario(view))


@scenario.command("instantiate", help="Bind a template to a declared gap cell.")
@click.argument("ref", metavar="ID@VERSION")
@_INPUTS_OPTION
@_SCENARIO_CELL_OPTIONS
@click.option(
    "--preview",
    "preview",
    is_flag=True,
    default=False,
    help="Bind the template and stop: no plan is compiled and no gate is consulted.",
)
@_RUN_OPTIONS
@_JSON_OPTION
def scenario_instantiate(
    ref: str,
    inputs_path: Path,
    target: str,
    execution_context: str,
    parameter_band: str,
    preview: bool,
    run_id: str,
    config_snapshot_id: str,
    fingerprint: str,
    as_json: bool,
) -> None:
    """Bind a scenario to a gap this advisor found, and take it through the shared core.

    The cell has to be a gap in the inputs document's landscape. A scenario bound
    to a covered cell is refused by name, because a scenario bound to nowhere is a
    fault list and a fault list does not have a coverage claim to make.

    ``--preview`` stops after the binding. Without it, the instantiation goes
    through :func:`mayhem.controller.advisor_service.submit_scenario` — the same
    private core ``advisor submit`` reaches — after checking that the compiled
    plan would carry this template's own hypothesis.
    """
    inputs = _call(lambda: AdvisorInputs.from_path(inputs_path))
    template = _scenario_ref(scenario_library(), ref)
    engine = advisor_service_for(inputs)
    instantiation = _call(
        lambda: template.instantiate(
            target=target,
            execution_context=execution_context,
            parameter_band=parameter_band,
        )
    )
    view = scenario_instantiation_view(instantiation)
    if preview:
        if echo_machine(view.to_dict(), as_json=as_json):
            return
        _echo(render_scenario(view))
        return
    _require_run_arguments(run_id or "", config_snapshot_id or "")
    environment_fingerprint = _fingerprint(fingerprint)
    analysis = _call(lambda: _analyse(inputs))
    finding = _call(
        lambda: _finding_for_cell(
            analysis, instantiation.cell.key, what=f"scenario {instantiation.ref!r}"
        )
    )
    recommendation = _call(
        lambda: _recommendation_for(inputs, finding, propose=instantiation.propose)
    )
    submission = _call(
        lambda: scenario_submission(
            engine,
            instantiation,
            recommendation,
            advisor_safety_context(fingerprint=environment_fingerprint),
            run_id=run_id or "",
            config_snapshot_id=config_snapshot_id or "",
            environment_fingerprint=environment_fingerprint,
        )
    )
    if echo_machine(submission.to_dict(), as_json=as_json):
        return
    _echo(render_scenario(view))
    click.echo("")
    _echo(render_submission(submission))
