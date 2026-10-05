"""Plan 21 Phases 2 and 4 — the advisor engine: analysis over sealed inputs, the
incident-replay compiler, and the safety/evidence integration.

Phase 1 (:mod:`mayhem.domain.advisor`) is the arithmetic: a :class:`Finding` is
the absence of a fact pointed at, a priority is the weighted mean of *declared*
criteria, and :class:`~mayhem.domain.advisor.UntrustedRecommendationDraft` is the
machine's output type with nowhere to put an approval. This module is the call
site. It reads sealed inputs, correlates them, and returns the same types Phase 1
defines — so nothing here can produce an artifact Phase 1 has not already made
impossible.

## Read-only by construction, not by policy

The engine holds five injected read ports (:class:`TopologyPort`,
:class:`CoveragePort`, :class:`IncidentPort`, :class:`DeploymentPort`,
:class:`EvidencePort`). Every one is a :class:`typing.Protocol` with read methods
and nothing else, so the engine holds no statement handle, no catalog writer, no
lease client, and no agent sink. There is no code path from a
:class:`Finding` to a mutation, and no object on this class to route one through.

The purity claim is then *measured*, the way
:mod:`mayhem.controller.prediction_service` measures it rather than promising it:
every method here evaluates through :meth:`AdvisorService.detached` — a copy of
the service with its :class:`~mayhem.domain.policy_gate.MutationSink`
removed — and then reports :attr:`AdvisorAnalysis.purity` by reading
:func:`len` off whatever sink the *caller* held. A caller that pre-loads the sink
with a recorded call and still sees zero calls afterwards has evidence, which is
what makes ``calls == 0`` a measurement rather than a constant. The reuse is
deliberate: :class:`~mayhem.controller.prediction_service.MutationProof` already
states exactly this, and two shapes for "nothing was mutated" is one more place
for the two to disagree.

**Phase 4 holds that line, and the sealing below is how.** Every write this
module can perform — :func:`seal_advisory_claim`,
:func:`record_replay_compilation`, :func:`record_advisory_seal` — is a
*module-level* function that takes a store or an audit stream the caller supplies,
exactly as
:func:`~mayhem.controller.certification_evidence.seal_certification_evidence`
does. Not one of them is a method on :class:`AdvisorService`, and the service's
field set is unchanged from Phase 2. A caller who wants advisor output sealed must
hold a :class:`~mayhem.infra.store.Store` themselves and pass it in; the analysis
context still cannot obtain one, so it still cannot write. That is the structural
claim, and tests/unit/test_advisor_evidence.py asserts it against the dataclass
fields rather than taking a docstring's word for it.

## Every generated parameter traces to an incident fact

The replay compiler (:meth:`AdvisorService.replay`) never fills in a parameter.
Each parameter is a :class:`ParameterBinding` naming the *incident fact* it must
come from, and a binding the incident cannot satisfy is a refusal, not a default:

* a percentile label the capture never observed — ``RULE_REPLAY_PARAMETER_UNTRACEABLE``;
* a percentile observed with ``samples == 0`` (``ObservedPercentile.usable`` is
  false) — the same rule, because an observation with nothing behind it cannot
  carry a judgement;
* an observation whose unit is not the unit the binding declared —
  ``RULE_REPLAY_UNIT_MISMATCH``, because a latency in milliseconds silently
  feeding a parameter counted in seconds is the arithmetic that makes a replay
  reproduce a *different* incident;
* a replay pinned to a topology snapshot that is not the one the engine read, or
  against component versions the deployment record has since superseded —
  ``RULE_REPLAY_TOPOLOGY_PIN_MISMATCH`` and ``RULE_REPLAY_VERSION_SUPERSEDED``.
  These are the two refusals that make "pinned" mean anything: replay is not
  "run something similar later".

What the engine does *not* do is default. A fault parameter nobody bound is left
to the catalog's own declared default, because that default is the catalog's
decision and not this engine's invention — and a parameter the engine *does*
generate always arrives with a :class:`ParameterTrace` naming its incident fact,
so a generated parameter with no trace is not constructible.

## Generated candidates take the same road as authored ones

:meth:`AdvisorService.submit` is the only door a recommendation leaves through,
and it does not branch on origin. For an ``authored`` recommendation and a
``generated`` one it runs the identical sequence against the identical functions:
``plan_drill`` (:mod:`mayhem.controller.planner`) to compile the frozen
:class:`~mayhem.domain.experiments.ExecutionPlan`, then
:func:`~mayhem.controller.safety_proof.compile_safety_evidence` for the proof,
then :func:`~mayhem.controller.safety.simulate_plan_policy` for the policy
verdict. There is no "advisor fast path", and the refusal order is the load-
bearing part: a candidate that will not compile raises *out of* the compile
stage, so the proof compiler and the policy gate are never reached. That is the
claim tests/unit/test_advisor_service.py asserts by counting calls to both.

:func:`submit_scenario` is that same door with the *fault set* supplied instead of
derived, because a scenario library template (gap 49,
:mod:`mayhem.domain.scenarios`) is a multi-fault timeline and one ``fault_id``
cannot express it. It calls the same private core, so the compile → proof →
policy sequence, the refusal order, and the origin-blindness are one
implementation rather than two that agree today. What it adds is a binding check
(:data:`RULE_SUBMISSION_SPEC_NOT_BOUND`): the plan it compiles must carry the
recommendation's own hypothesis, so supplying a spec cannot smuggle in a plan that
says something other than the recommendation a human read. An instantiation is
otherwise indistinguishable downstream from an authored one, which is the point.

## ``required_approvals`` is a requirement, not a grant — and that is the answer

Phase 2 left a question open: the proof's ``required_approvals`` line reports
``PASS`` with the detail "No intent presented at compile time", and should
:meth:`AdvisorService.submit` refuse that? **No, and the ``PASS`` is the honest
state.** The line's subject is the *requirements* — which approval levels are
required, which critical faults need an explicit acknowledgement, and the rule
that any approval must bind this plan digest — and its own detail says the grant
is bound later, against the proof digest. ``PASS`` there means "the requirements
are established and nothing has been authorised", which is exactly what an advisor
submission should report.

Refusing it would be wrong three times over. The advisor must never present an
execution intent (that is this plan's critical invariant), so ``intent is None``
is the *only* branch an advisor submission can reach; refusing it would make
:meth:`submit` unusable and would create pressure to attach an intent in order to
satisfy a line — weakening the boundary to please a status. And reporting it as a
refusal would assert something false: there is no intent to fail
``require_execution_intent``, which raises ``INTENT_REQUIRED`` at execution time,
where the decision actually belongs.

What would not be honest is leaving a bare ``PASS`` for a reader to
misunderstand. So :attr:`AdvisorSubmission.authorization` names the three states
that line can be in, read off two structural facts — whether ``ctx.approval_gate``
was configured at all, and the line's own status — rather than from reading its
prose, and :attr:`AdvisorSubmission.authorized` is ``True`` only when the plan-09
approval gate actually authorised this plan. For every advisor submission it is
``False``, and that is a field on the type rather than a sentence a reader has to
notice.

## Sealing is advisory, and the distinction is structural

A recommendation is a claim a human will act on, so it belongs in the sealed chain
beside the facts it cites — but sealing it must not hand it authority it does not
have. How that is guaranteed here is by *what the types can carry*, not by a
sentence in a payload:

* :class:`AdvisoryClaim` has no ``approval``, ``approved_by``, ``intent``,
  ``run_id``, ``policy_decision`` or ``approval_state`` field, and its
  constructor refuses a recommendation that already carries an approval
  (:data:`RULE_ADVISORY_SEAL_CARRIES_APPROVAL`) — so a sealed advisory artifact
  can never be a decision, and a decision can never be re-attested here;
* :class:`AdvisorySeal` deliberately has **no** ``evidence_digest`` attribute, so
  :func:`mayhem.domain.advisor.is_certified_evidence` is ``False`` for it. That
  existing predicate *is* the test: advisor output is correlated facts, has no
  verdict, and can never be presented as a sealed run;
* :attr:`AdvisorySeal.grants_authorization` is the literal ``False``. It reads
  nothing, so no input can change it;
* an :class:`AdvisorySeal` cannot be dressed up as a
  :class:`~mayhem.infra.attestation_store.RunAuthorization` — the two types share
  no constructor — and its chain id is namespaced ``advisory:…``, so a verifier
  walking attestation chains for runs never meets one;
* :func:`seal_advisory_claim` verifies the chain and the manifest *before* opening
  a transaction, and refuses a recommendation whose rationale does not name the
  criteria it was ranked by (:data:`RULE_ADVISORY_SEAL_UNTRACEABLE`): a claim
  nobody can check is not a claim that belongs in the chain of record.

Every chain member's payload repeats ``standing: advisory`` and
``grants_approval: false`` as data, so an operator reading the persisted JSON is
told the standing rather than left to infer it from the absence of a field.

## Replay and sealing are privileged actions, and the audit stream says so

An incident being turned into an experiment is exactly the kind of thing an auditor
wants to see, so :func:`record_replay_compilation` appends one
:class:`~mayhem.infra.audit_stream.AuditEntry` under
:data:`KIND_ADVISORY_REPLAY_COMPILED`, carrying the incident, the cell, the
topology pin, and every parameter with the incident fact it came from.
:func:`record_advisory_seal` does the same for the seal. Both leave
``approval_digest`` and ``policy_digest`` **empty**, and that emptiness is the
point: nothing the advisor records carries a digest of an approval it did not
receive.

The draft boundary itself is Plan 15's, reused rather than reimplemented:
:func:`~mayhem.controller.analytics_service.compile_candidate` already scans a
raw advisor payload for an authority field at any depth
(:data:`~mayhem.controller.analytics_service.AUTHORITY_FIELDS`), and that is the
scan this module calls via
:func:`~mayhem.controller.analytics_service.authority_keys`. A second scanner
would be a second answer to "which keys mean authority", and the two would drift.

## What this module refuses to be

It does not understand the system. It correlates cited facts: a coverage cell in a
gap state, the topology that cell's failure would travel through, an incident
that names the same dependency, a version pin that has not moved. Every claim it
makes is a citation, and
:func:`~mayhem.domain.advisor.is_certified_evidence` is false for every artifact
it emits — correlation is not a run, has no verdict, and can never be sealed.
The evidence it *reads* through :class:`EvidencePort` is sealed and is used only
to *withhold* work (a cell sealed evidence already established is not an
uncovered failure mode), never to decorate a finding with someone else's digest.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, replace
from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING, Final, Protocol

from mayhem.controller.analytics_service import AUTHORITY_FIELDS
from mayhem.controller.analytics_service import _authority_keys as authority_keys
from mayhem.controller.planner import PlanningError, plan_drill
from mayhem.controller.prediction_service import MutationProof
from mayhem.controller.safety import SafetyContext, simulate_plan_policy
from mayhem.controller.safety_proof import SafetyCompilation, compile_safety_evidence
from mayhem.domain.advisor import (
    GAP_STATES,
    AdvisorAuthority,
    CitedFact,
    CoverageLandscape,
    CriterionReading,
    ExperimentCandidate,
    Finding,
    IncidentFacts,
    PriorityCriteria,
    Recommendation,
    RecommendationOrigin,
    UntrustedRecommendationDraft,
    is_certified_evidence,
    rank_drafts,
    recommendations_for,
)
from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    ChainVerification,
    Manifest,
    ManifestVerification,
    RetentionClass,
    build_manifest,
    chain_root,
    seal_events,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.common import utc_now
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import DrillContainer, DrillFault, DrillSpec, ExecutionStep
from mayhem.domain.hashing import digest, sha256_hex
from mayhem.domain.prediction import graph_identity as compute_graph_identity
from mayhem.domain.safety_proof import ObligationStatus
from mayhem.infra.attestation_store import AttestationError, AttestationRepository
from mayhem.infra.audit_stream import AuditEntry, AuditStream

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.policy_gate import MutationSink, PolicyGateResult
    from mayhem.domain.runtime_adapter import RuntimeAdapter
    from mayhem.domain.scenarios import ScenarioInstantiation
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.store import Store

__all__ = [
    "ADVISORY_CHAIN_PREFIX",
    "ADVISORY_STANDING",
    "ADVISOR_ARTIFACT",
    "APPROVAL_GATE_BLINE",
    "AUTHORITY_FIELDS",
    "EXECUTION_INTENT_BLINE",
    "KIND_ADVISORY_CLAIM_SEALED",
    "KIND_ADVISORY_REPLAY_COMPILED",
    "POLICY_GATE_BLINE",
    "RULE_ADVISORY_SEAL_CARRIES_APPROVAL",
    "RULE_ADVISORY_SEAL_UNTRACEABLE",
    "RULE_DRAFT_CARRIES_AUTHORITY",
    "RULE_DRAFT_UNKNOWN_FIELD",
    "RULE_NO_DECLARED_BINDINGS",
    "RULE_REPLAY_INCOMPLETE",
    "RULE_REPLAY_NO_USABLE_OBSERVATION",
    "RULE_REPLAY_PARAMETER_UNTRACEABLE",
    "RULE_REPLAY_TOPOLOGY_PIN_MISMATCH",
    "RULE_REPLAY_UNIT_MISMATCH",
    "RULE_REPLAY_VERSION_SUPERSEDED",
    "RULE_SUBMISSION_SPEC_NOT_BOUND",
    "RULE_SUBMISSION_UNTRACEABLE_PARAMETER",
    "RULE_SUBMISSION_WILL_NOT_COMPILE",
    "AdvisorAnalysis",
    "AdvisorService",
    "AdvisorSubmission",
    "AdvisoryClaim",
    "AdvisorySeal",
    "CoveragePort",
    "DeploymentPort",
    "EvidencePort",
    "IncidentPort",
    "IncidentReplay",
    "ParameterBinding",
    "ParameterSource",
    "ParameterTrace",
    "ReplayRequest",
    "SealedCell",
    "SubmissionAuthorization",
    "SuppressReason",
    "SuppressedCell",
    "TopologyPort",
    "advisory_chain_id",
    "advisory_events",
    "authority_keys",
    "build_draft_payload",
    "read_draft_payload",
    "record_advisory_seal",
    "record_replay_compilation",
    "seal_advisory_claim",
    "submit_scenario",
]

# -- names ------------------------------------------------------------------------

#: What an :class:`AdvisorAnalysis` *is*. Deliberately not ``"plan"`` and not
#: ``"run"``: nothing here may be executed, and an artifact that could be spelled
#: like one would be one call site away from being handed to a runner.
ADVISOR_ARTIFACT = "advisor_analysis"

RULE_DRAFT_UNKNOWN_FIELD = "advisor.draft_unknown_field"
RULE_DRAFT_CARRIES_AUTHORITY = "advisor.draft_carries_authority"

RULE_NO_DECLARED_BINDINGS = "advisor.replay_declares_no_parameter_bindings"
RULE_REPLAY_INCOMPLETE = "advisor.replay_incomplete"
RULE_REPLAY_PARAMETER_UNTRACEABLE = "advisor.replay_parameter_untraceable"
RULE_REPLAY_UNIT_MISMATCH = "advisor.replay_unit_mismatch"
RULE_REPLAY_NO_USABLE_OBSERVATION = "advisor.replay_has_no_usable_observation"
RULE_REPLAY_TOPOLOGY_PIN_MISMATCH = "advisor.replay_topology_pin_mismatch"
RULE_REPLAY_VERSION_SUPERSEDED = "advisor.replay_version_superseded"

RULE_SUBMISSION_WILL_NOT_COMPILE = "advisor.submission_will_not_compile"
RULE_SUBMISSION_UNTRACEABLE_PARAMETER = "advisor.submission_parameter_untraceable"
RULE_SUBMISSION_SPEC_NOT_BOUND = "advisor.submission_spec_not_bound_to_recommendation"

RULE_ADVISORY_SEAL_UNTRACEABLE = "advisor.seal_requires_traceable_citations"
RULE_ADVISORY_SEAL_CARRIES_APPROVAL = "advisor.seal_refuses_to_carry_an_approval"

#: The namespace an advisory chain hangs off. Plan 12's law is one chain per run
#: starting at genesis, so an advisory claim is given a chain identity of its own
#: rather than hung off a run that does not exist — and the prefix keeps a
#: verifier walking attestation chains for runs from meeting one.
ADVISORY_CHAIN_PREFIX: Final[str] = "advisory"

#: The one standing a sealed advisory artifact may claim, written into every
#: chain member's payload so an operator reading persisted JSON is told it rather
#: than left to infer it from an absent field. There is no second member of this
#: enumeration and no parameter that changes it, which is what makes "advisory,
#: not authorization" a property of the artifact rather than a sentence about it.
ADVISORY_STANDING: Final[str] = "advisory"

#: The chain members, in chain order. Named here rather than spelled inline so a
#: grep finds every advisory event kind at once.
CHAIN_EVENT_ADVISORY_RECORDED: Final[str] = "advisory.recorded"
CHAIN_EVENT_ADVISORY_SEALED: Final[str] = "advisory.sealed"

#: Audit-stream action kinds. These are *this module's* vocabulary additions:
#: ``mayhem.infra.audit_stream`` owns the stream and the closed list of kinds its
#: own writers use, and its ``action`` column is deliberately free text, so an
#: advisor action is declared here — in the module that performs it — instead of
#: by editing a file this plan does not own. A reviewer adding a kind should add
#: it here, next to the write that uses it.
KIND_ADVISORY_REPLAY_COMPILED: Final[str] = "audit.advisory.incident_replayed"
KIND_ADVISORY_CLAIM_SEALED: Final[str] = "audit.advisory.claim_sealed"

#: The gates that can produce the ``required_approvals`` line, named exactly as
#: ``mayhem.controller.safety_proof`` names them in ``_Line.gates``.
#:
#: :func:`_authorization_state` does **not** read these — it reads
#: ``ctx.approval_gate`` and the line's status, which are both values rather than
#: rule ids. They are named here for a reader who wants the full set, and
#: :data:`EXECUTION_INTENT_BLINE` in particular is named for what is *deliberately
#: absent*: this module never passes an ``ExecutionIntent`` to the proof compiler,
#: so no advisor submission can be in that state and there is no enum member for it.
POLICY_GATE_BLINE: Final[str] = "controller.policy_gate.required_approvals"
APPROVAL_GATE_BLINE: Final[str] = "controller.approval_gate.verify_approvals"
EXECUTION_INTENT_BLINE: Final[str] = "domain.execution_intent.require_execution_intent"

#: The obligation Phase 2's author could not interpret. Named here so the answer
#: lives in code rather than only in a status note.
REQUIRED_APPROVALS_OBLIGATION: Final[str] = "required_approvals"

#: The fields a raw advisor payload may declare. Everything else is refused
#: before it is read, so a payload cannot smuggle a field past the boundary by
#: burying it under a name nothing looks at. There is no ``approval``, no
#: ``weight``, no ``criteria`` and no ``execute``: the same absence of vocabulary
#: the draft type has.
ALLOWED_DRAFT_FIELDS: frozenset[str] = frozenset(
    {"recommendation_id", "finding_id", "rationale", "hypothesis", "probes", "stop_conditions"}
)


# -- sealed inputs, read through ports only --------------------------------------


class TopologyPort(Protocol):
    """The sealed topology: the graph, and the id of the snapshot it came from.

    Two methods, both reads. The snapshot id is a *separate* read on purpose —
    the graph itself carries no identity, so a replay that claimed to be pinned
    to a snapshot would have to take the engine's word for which one it is.
    """

    def topology(self) -> TopologyGraph: ...

    def snapshot_id(self) -> str: ...


class CoveragePort(Protocol):
    """Sealed coverage facts: the declared landscape and the state of each cell."""

    def landscape_id(self) -> str: ...

    def cells(self) -> tuple[CoverageCell, ...]: ...

    def states(self) -> Mapping[str, CellState]: ...


class IncidentPort(Protocol):
    """Normalised incident captures. Already normalised: the port hands back
    :class:`~mayhem.domain.advisor.IncidentFacts` values, not raw reports."""

    def captures(self) -> tuple[IncidentFacts, ...]: ...


class DeploymentPort(Protocol):
    """What is deployed now, per component."""

    def releases(self) -> Mapping[str, str]: ...


class EvidencePort(Protocol):
    """Sealed evidence somebody else produced.

    Only ever read to *withhold* work. A cell a sealed run already established
    is not an uncovered failure mode, and the engine's answer to that is to
    suppress the finding and name the digest that suppressed it.
    """

    def established(self) -> tuple[SealedCell, ...]: ...


@dataclass(frozen=True, slots=True)
class SealedCell:
    """One coverage cell a sealed run established, and the evidence that says so.

    This type carries an ``evidence_digest`` field on purpose: it is the shape
    :func:`~mayhem.domain.advisor.is_certified_evidence` recognises, so the port's
    own records are certified evidence and the artifacts this module emits are
    not. The distinction is then a predicate over real objects rather than a
    comment about which class is trusted.
    """

    cell_key: str
    evidence_digest: str
    run_label: str

    def __post_init__(self) -> None:
        if not self.cell_key.strip() or not self.run_label.strip():
            raise InvariantViolationError(
                RULE_REPLAY_INCOMPLETE,
                f"sealed evidence {self.to_dict()!r} must name both the cell it "
                "established and the run that established it",
            )
        if not is_certified_evidence(self):
            raise InvariantViolationError(
                RULE_REPLAY_INCOMPLETE,
                f"sealed evidence for cell {self.cell_key!r} cites "
                f"{self.evidence_digest!r}, which is not a sealed sha256 digest: a "
                "record that cannot be verified is a claim about a run that never "
                "sealed anything",
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "cell_key": self.cell_key,
            "evidence_digest": self.evidence_digest,
            "run_label": self.run_label,
        }


# -- findings the engine will not emit --------------------------------------------


class SuppressReason(StrEnum):
    """Why a declared cell produced no finding.

    Named rather than counted, because "we looked at N cells" is exactly the
    number a reader cannot check. Every cell the engine declines is enumerated
    with its reason, so the gap between the landscape and the findings is a list
    somebody can read rather than an arithmetic difference.
    """

    #: The cell's state is not a gap state. ``PASSED`` is coverage, ``FAILED`` is
    #: a graded regression (:mod:`mayhem.domain.comparison` owns that), and
    #: ``EXECUTED`` is a run in flight — none is an uncovered failure mode.
    NOT_A_GAP_STATE = "not_a_gap_state"
    #: Sealed evidence already established the cell.
    ESTABLISHED_BY_SEALED_EVIDENCE = "established_by_sealed_evidence"
    #: The cell's target is in no node of the sealed topology, so a finding could
    #: not cite the topology the failure would travel through.
    TARGET_NOT_IN_TOPOLOGY = "target_not_in_topology"


@dataclass(frozen=True, slots=True)
class SuppressedCell:
    """One declared cell the engine looked at and did not turn into a finding."""

    cell_key: str
    reason: SuppressReason
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"cell_key": self.cell_key, "reason": self.reason.value, "detail": self.detail}


# -- incident replay ---------------------------------------------------------------


class ParameterSource(StrEnum):
    """Which incident fact a fault parameter is bound to.

    An enumeration rather than a free-text path, because "traceable to an incident
    fact" has to be checkable by the type: a binding can only name a fact this
    vocabulary can reach, and the compiler refuses one that reaches nothing.
    """

    #: ``incident.duration_s`` — how long the incident lasted.
    DURATION = "duration"
    #: ``incident.percentile(label)`` — one observed percentile.
    PERCENTILE = "percentile"


@dataclass(frozen=True, slots=True)
class ParameterBinding:
    """One fault parameter, and the incident fact it must be read from.

    ``unit`` is required for a percentile binding and refused on mismatch
    (:data:`RULE_REPLAY_UNIT_MISMATCH`). That is the binding's whole value: a
    latency observed in milliseconds cannot quietly become a count in seconds,
    because a replay that mistranslates its own evidence reproduces a different
    incident while looking like a faithful one.

    ``label`` is required for :data:`ParameterSource.PERCENTILE` and must be
    absent for :data:`ParameterSource.DURATION`, so a binding names exactly one
    fact and cannot be read two ways.
    """

    parameter: str
    source: ParameterSource
    label: str = ""
    unit: str = ""

    def __post_init__(self) -> None:
        if not self.parameter.strip():
            raise InvariantViolationError(
                RULE_REPLAY_PARAMETER_UNTRACEABLE,
                "a parameter binding must name the fault parameter it feeds: an "
                "unbound parameter cannot be traced to anything",
            )
        wants_label = self.source is ParameterSource.PERCENTILE
        if wants_label and not self.label.strip():
            raise InvariantViolationError(
                RULE_REPLAY_PARAMETER_UNTRACEABLE,
                f"parameter binding {self.parameter!r} is bound to "
                f"{self.source.value!r} but names no percentile label: which "
                "observation should supply it",
            )
        if wants_label and not self.unit.strip():
            raise InvariantViolationError(
                RULE_REPLAY_UNIT_MISMATCH,
                f"parameter binding {self.parameter!r} must declare the unit it "
                f"expects from percentile {self.label!r}: a unit the binding does not "
                "state is a unit the compiler has to guess, and a guessed unit turns a "
                "replay into a different experiment",
            )
        if not wants_label and self.label.strip():
            raise InvariantViolationError(
                RULE_REPLAY_PARAMETER_UNTRACEABLE,
                f"parameter binding {self.parameter!r} is bound to "
                f"{self.source.value!r}, which names its own fact, but also carries "
                f"label {self.label!r}: a binding must read exactly one fact",
            )

    @property
    def fact(self) -> str:
        """The incident fact this binding reads, in the reader's own notation."""
        if self.source is ParameterSource.DURATION:
            return "incident.duration_s"
        return f'incident.percentile("{self.label}")'


@dataclass(frozen=True, slots=True)
class ParameterTrace:
    """One generated parameter, the value it carries, and the fact it came from.

    ``source`` is required and non-blank, which is what makes "every generated
    parameter traces to an incident fact" a constructor rule rather than a review
    habit: a trace with no source cannot be built, so a parameter the engine
    generated cannot be held by anything that has not said where it came from.
    """

    parameter: str
    value: float
    unit: str
    source: str
    incident_id: str
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.parameter.strip():
            raise InvariantViolationError(
                RULE_REPLAY_PARAMETER_UNTRACEABLE,
                "a parameter trace must name the parameter it accounts for",
            )
        if not self.source.strip():
            raise InvariantViolationError(
                RULE_REPLAY_PARAMETER_UNTRACEABLE,
                f"parameter {self.parameter!r} carries no source fact: a generated "
                "parameter whose origin cannot be named is an invented one, and the "
                "whole rule of this compiler is that it invents none",
            )
        if not self.incident_id.strip():
            raise InvariantViolationError(
                RULE_REPLAY_PARAMETER_UNTRACEABLE,
                f"parameter {self.parameter!r} cites source {self.source!r} but names "
                "no incident: a trace to nowhere is not a trace",
            )
        if not isfinite(self.value):
            raise InvariantViolationError(
                RULE_REPLAY_PARAMETER_UNTRACEABLE,
                f"parameter {self.parameter!r} reads {self.value!r} off {self.source!r}: "
                "nan and inf are arithmetic accidents, and a replay carrying one is a "
                "replay of nothing",
            )

    @property
    def scaled(self) -> float:
        """The value in seconds, for the parameters whose unit is a duration.

        Named rather than implicit, so the unit conversion is one line a reader
        can check instead of a multiplication hiding inside a comprehension.
        """
        return self.value / 1000.0 if self.unit == "ms" else self.value

    def to_dict(self) -> dict[str, object]:
        return {
            "parameter": self.parameter,
            "value": self.value,
            "unit": self.unit,
            "source": self.source,
            "incident_id": self.incident_id,
            "detail": self.detail,
        }


# -- the authorization state a submission is in ---------------------------------


class SubmissionAuthorization(StrEnum):
    """What the ``required_approvals`` line actually established.

    Three states, and the enumeration exists because the one question Phase 2
    could not answer was whether ``PASS`` on that line meant the plan was
    approved. It does not, and this is the vocabulary that says so without anybody
    having to re-read the line's detail string.

    :data:`REQUIREMENTS_ONLY` is the advisor's own state and the answer to the
    open question: the requirements are established, the plan digest any approval
    must bind is named, and *nothing has been authorised*. A ``PASS`` there is
    correct, because the line's subject is the requirements.

    The other two are readings of the plan-09 approval gate's own verdict — a
    decision this module can report because a caller put a gate in the context,
    and can never make because it holds no gate itself. There is deliberately no
    "intent verified" member: :meth:`AdvisorService.submit` never passes an
    ``ExecutionIntent`` to the proof compiler, so the state is unreachable from
    here and naming it would be vocabulary for something this path cannot do.
    """

    #: Requirements established, no approval gate configured, no intent presented.
    #: The advisor's state, and the honest answer to "was this approved?" — no.
    REQUIREMENTS_ONLY = "requirements_only"
    #: A caller configured ``ctx.approval_gate``, it ran, and it authorised this
    #: plan. The advisor only reports it.
    GATE_AUTHORIZED = "gate_authorized"
    #: The approval gate ran and refused this plan.
    GATE_REFUSED = "gate_refused"


def _authorization_state(
    ctx: SafetyContext, compilation: SafetyCompilation
) -> SubmissionAuthorization:
    """Read the approval state off the inputs, not off the line's prose.

    Two structural facts decide it, and only these two:

    * ``ctx.approval_gate is None`` — the context knows nothing about approvals,
      so nothing could have been authorised by one. That is the advisor's own
      situation, and it is why :data:`SubmissionAuthorization.REQUIREMENTS_ONLY`
      is the honest answer to a ``PASS`` on that line rather than a defect.
    * the line's own status — :mod:`mayhem.controller.safety_proof` returns
      ``FAIL`` exactly when the plan-09 gate refused, so a non-``PASS`` line with
      a gate configured is a refusal and not an ambiguity.

    Note what is *not* consulted: the line's ``detail`` string. A verdict derived
    from prose a different module composes is a verdict that breaks when somebody
    improves the sentence, and the sentence is the one part of a proof no test
    should be parsing.
    """
    line = compilation.proof.obligation(REQUIRED_APPROVALS_OBLIGATION)
    if ctx.approval_gate is None:
        return SubmissionAuthorization.REQUIREMENTS_ONLY
    if line is None or line.status is ObligationStatus.FAIL:
        return SubmissionAuthorization.GATE_REFUSED
    return SubmissionAuthorization.GATE_AUTHORIZED


@dataclass(frozen=True, slots=True)
class ReplayRequest:
    """What a caller declares about a replay before the compiler reads anything.

    Every field is required. ``fault_id`` is *declared*, never derived — the
    engine correlates facts, and choosing which fault to inject is a judgement
    that belongs to whoever reads the incident, not to a function that has seen
    four string fields. ``execution_context`` and ``parameter_band`` are the other
    two halves of the coverage cell's identity, and they are required for the
    same reason the domain requires them: a cell missing a dimension is not a cell
    anybody can look up.

    ``bindings`` must be non-empty. A replay with no bound parameter would compile
    a fault whose every value came from the catalog's defaults, which is a
    different experiment wearing the incident's name
    (:data:`RULE_NO_DECLARED_BINDINGS`).
    """

    fault_id: str
    execution_context: str
    parameter_band: str
    bindings: tuple[ParameterBinding, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("fault_id", self.fault_id),
            ("execution_context", self.execution_context),
            ("parameter_band", self.parameter_band),
        ):
            if not value.strip():
                raise InvariantViolationError(
                    RULE_REPLAY_INCOMPLETE,
                    f"a replay request must declare {name}: a replay with no "
                    f"{name} is a fault somebody hoped for rather than one the "
                    "incident actually showed",
                )
        if not self.bindings:
            raise InvariantViolationError(
                RULE_NO_DECLARED_BINDINGS,
                f"replay of {self.fault_id!r} binds no parameter to an incident fact: "
                "every value would then come from a catalog default, which reproduces "
                "the fault's shape and none of the incident",
            )
        names = [binding.parameter for binding in self.bindings]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise InvariantViolationError(
                RULE_REPLAY_INCOMPLETE,
                f"replay request binds {duplicates} twice: two facts feeding one "
                "parameter is an arithmetic accident, not a decision",
            )

    @property
    def facts_cited(self) -> tuple[str, ...]:
        """The incident facts this request reads, in declaration order."""
        return tuple(binding.fact for binding in self.bindings)


@dataclass(frozen=True, slots=True)
class IncidentReplay:
    """An incident capture compiled into a reproducible candidate.

    Four things travel together and none of them can be dropped: the capture it
    came from, the cell it replays, the finding that cell is uncovered under, and
    the candidate with its parameter traces. A replay with a candidate but no
    traces is not constructible, because
    :meth:`AdvisorService.replay` always builds the two together and
    :meth:`__post_init__` refuses a candidate whose parameters are not exactly
    the traced ones.

    ``topology_snapshot_id`` is pinned and checked twice — against the request's
    incident and against the topology the engine actually read. That is the whole
    meaning of "reproducible" here: the same graph, the same versions, the same
    numbers.
    """

    incident: IncidentFacts
    fault_id: str
    cell: CoverageCell
    finding: Finding
    candidate: ExperimentCandidate
    parameters: tuple[ParameterTrace, ...]
    duration_s: float
    topology_snapshot_id: str
    graph_identity: str

    def __post_init__(self) -> None:
        if not self.parameters:
            raise InvariantViolationError(
                RULE_NO_DECLARED_BINDINGS,
                f"replay of {self.incident.incident_id!r} carries no traced parameter: a "
                "reproducible candidate is one whose every value can be named",
            )
        traced = {trace.parameter: trace for trace in self.parameters}
        if len(traced) != len(self.parameters):
            raise InvariantViolationError(
                RULE_REPLAY_PARAMETER_UNTRACEABLE,
                f"replay of {self.incident.incident_id!r} traces the same parameter "
                "twice",
            )
        if self.cell.key != self.finding.cell.key:
            raise InvariantViolationError(
                RULE_REPLAY_INCOMPLETE,
                f"replay of {self.incident.incident_id!r} replays cell "
                f"{self.cell.key!r} but its finding cites {self.finding.cell_key!r}: "
                "the cell and the gap it was read from are one fact, not two",
            )
        if self.topology_snapshot_id != self.incident.topology_snapshot_id:
            raise InvariantViolationError(
                RULE_REPLAY_TOPOLOGY_PIN_MISMATCH,
                f"replay of {self.incident.incident_id!r} is pinned to snapshot "
                f"{self.incident.topology_snapshot_id!r} but was compiled against "
                f"{self.topology_snapshot_id!r}: replaying an incident against a "
                "different graph reproduces a different incident",
            )
        if self.duration_s != self.incident.duration_s:
            raise InvariantViolationError(
                RULE_REPLAY_INCOMPLETE,
                f"replay of {self.incident.incident_id!r} runs for {self.duration_s!r}s "
                f"but the incident lasted {self.incident.duration_s!r}s: the stop "
                "condition of a replay is the duration of the thing it replays",
            )

    @property
    def parameter_values(self) -> dict[str, float]:
        """The traced values, ready to hand to :meth:`AdvisorService.submit`."""
        return {trace.parameter: trace.value for trace in self.parameters}

    @property
    def replay_digest(self) -> str:
        """Identity of this replay: the capture, the cell, and every value.

        Excludes nothing, so two replays of one incident that disagree on any
        parameter are different values rather than the same one described twice.
        """
        return digest(
            {
                "incident": self.incident.to_dict(),
                "fault_id": self.fault_id,
                "cell_key": self.cell.key,
                "topology_snapshot_id": self.topology_snapshot_id,
                "graph_identity": self.graph_identity,
                "duration_s": self.duration_s,
                "parameters": [trace.to_dict() for trace in self.parameters],
            }
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "incident_id": self.incident.incident_id,
            "fault_id": self.fault_id,
            "cell_key": self.cell.key,
            "topology_snapshot_id": self.topology_snapshot_id,
            "graph_identity": self.graph_identity,
            "duration_s": self.duration_s,
            "parameters": [trace.to_dict() for trace in self.parameters],
            "candidate": self.candidate.to_dict(),
            "finding": self.finding.to_dict(),
            "replay_digest": self.replay_digest,
        }


# -- the analysis and its submission ------------------------------------------------


@dataclass(frozen=True, slots=True)
class AdvisorAnalysis:
    """Everything the engine read, what it concluded, and what it declined.

    ``findings`` and ``drafts`` are the answer; ``suppressed`` is the honesty
    half. A report that listed only the findings would be indistinguishable from
    one that had looked at three cells, so every declared cell that produced no
    finding is here with a named reason.

    :attr:`purity` is read off the caller's own mutation sink *after* the work
    (see :meth:`AdvisorService.detached`), so it is a measurement.
    """

    artifact: str
    landscape_id: str
    graph_identity: str
    topology_snapshot_id: str
    findings: tuple[Finding, ...]
    drafts: tuple[UntrustedRecommendationDraft, ...]
    suppressed: tuple[SuppressedCell, ...]
    purity: MutationProof
    notes: tuple[str, ...] = ()

    def rank(
        self, criteria: PriorityCriteria, readings: Mapping[str, Mapping[str, CriterionReading]]
    ) -> tuple[Recommendation, ...]:
        """Compile and order these drafts against the *declared* weighting.

        Delegated to :func:`mayhem.domain.advisor.rank_drafts`, so the ordering
        and the one-to-one reading check are the domain's and not this module's.
        """
        return rank_drafts(self.drafts, criteria, readings)

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.finding_id == finding_id), None)

    def suppressed_for(self, reason: SuppressReason) -> tuple[SuppressedCell, ...]:
        return tuple(cell for cell in self.suppressed if cell.reason is reason)

    def describe(self) -> str:
        lines = [
            f"{self.artifact}: {len(self.findings)} finding(s) over "
            f"{len(self.suppressed) + len(self.findings)} declared cell(s) in "
            f"landscape {self.landscape_id!r}",
            f"topology: snapshot {self.topology_snapshot_id!r}, "
            f"identity {self.graph_identity[:12]}…",
            f"mutation: {self.purity.calls} call(s), backend "
            f"{'attached' if self.purity.backend_attached else 'detached'}",
        ]
        if self.suppressed:
            by_reason: dict[str, int] = {}
            for cell in self.suppressed:
                by_reason[cell.reason.value] = by_reason.get(cell.reason.value, 0) + 1
            lines.append(
                "suppressed: "
                + ", ".join(f"{reason} x{n}" for reason, n in sorted(by_reason.items()))
            )
        lines.extend(f"note: {note}" for note in self.notes)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact": self.artifact,
            "landscape_id": self.landscape_id,
            "graph_identity": self.graph_identity,
            "topology_snapshot_id": self.topology_snapshot_id,
            "findings": [f.to_dict() for f in self.findings],
            "drafts": [d.to_dict() for d in self.drafts],
            "suppressed": [s.to_dict() for s in self.suppressed],
            "mutation": {
                "backend_attached": self.purity.backend_attached,
                "calls": self.purity.calls,
                "calls_detail": [list(call) for call in self.purity.calls_detail],
            },
            "notes": list(self.notes),
        }


@dataclass(frozen=True, slots=True)
class AdvisorSubmission:
    """A recommendation that has travelled the full compile -> proof -> policy path.

    Carries all three artifacts rather than a verdict, because the point of the
    exercise is that they are the *same* three an authored recommendation gets:
    a frozen plan with its digest, a compiled proof with the rule-level trail
    that produced it, and the policy gate's own verdict. Nothing here approves
    anything — the recommendation it carries still has
    :attr:`~mayhem.domain.advisor.Recommendation.authority` equal to ``none`` for
    a generated origin, and the plan is a plan, not a run.
    """

    recommendation: Recommendation
    plan: ExecutionPlan
    plan_digest: str
    compilation: SafetyCompilation
    policy: PolicyGateResult | None
    purity: MutationProof
    #: What the ``required_approvals`` line established, read off the inputs
    #: (:func:`_authorization_state`) rather than off the line's prose. Carried as
    #: a field rather than re-derived on each read so it states what was true at
    #: the moment the proof was compiled.
    authorization: SubmissionAuthorization = SubmissionAuthorization.REQUIREMENTS_ONLY

    @property
    def proof_verdict(self) -> str:
        return self.compilation.proof.verdict.value

    @property
    def admitted_by_gate(self) -> bool:
        """True when the authoritative gate refused nothing on this plan."""
        return not self.compilation.gate_refusals

    @property
    def policy_allowed(self) -> bool:
        """True when a bundle exists and allowed the plan; ``None`` is not allowed.

        ``None`` means the context carried no policy bundle, which is a different
        answer from "allowed" and must not be rendered as a pass.
        """
        return self.policy is not None and self.policy.allowed

    @property
    def authorized(self) -> bool:
        """Whether some *other* system authorised this plan. Never the advisor's own.

        ``True`` requires :data:`SubmissionAuthorization.GATE_AUTHORIZED`, which
        requires a caller to have configured ``ctx.approval_gate`` — a handle this
        module holds no reference to at all. For an advisor submission it is
        therefore ``False``, which is the answer to Phase 2's open question: the
        ``required_approvals`` ``PASS`` is honest and needs no refusal, because
        nothing downstream may read it as a grant.
        """
        return self.authorization is SubmissionAuthorization.GATE_AUTHORIZED

    @property
    def authorization_detail(self) -> str:
        """The line's own words, for a reader who wants them — never the state."""
        line = self.compilation.proof.obligation(REQUIRED_APPROVALS_OBLIGATION)
        return "" if line is None else line.detail

    def describe(self) -> str:
        lines = [
            f"{self.recommendation.recommendation_id} "
            f"({self.recommendation.candidate.experiment_id})",
            f"  origin: {self.recommendation.origin.value}   "
            f"authority: {self.recommendation.authority.value}",
            f"  plan: {self.plan_digest[:12]}… ({len(self.plan.steps)} step(s))",
            f"  proof: {self.proof_verdict}"
            + (f" — {self.compilation.void_reason}" if self.compilation.void_reason else ""),
            f"  gate: {'admitted' if self.admitted_by_gate else 'refused'} "
            f"{list(self.compilation.gate_refusals)}",
            "  policy: "
            + (
                ("allowed" if self.policy.allowed else "refused")
                if self.policy is not None
                else "no bundle configured"
            ),
            f"  authorization: {self.authorization.value} "
            f"({'authorized' if self.authorized else 'nothing granted'})",
            f"  mutation: {self.purity.calls} call(s), backend "
            f"{'attached' if self.purity.backend_attached else 'detached'}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "recommendation": self.recommendation.to_dict(),
            "plan_digest": self.plan_digest,
            "proof_verdict": self.proof_verdict,
            "gate_refusals": list(self.compilation.gate_refusals),
            "compiler_refusals": list(self.compilation.compiler_refusals),
            "void_reason": self.compilation.void_reason,
            "policy_allowed": self.policy_allowed,
            "admitted_by_gate": self.admitted_by_gate,
            "authorization": self.authorization.value,
            "authorized": self.authorized,
            "mutation": {
                "backend_attached": self.purity.backend_attached,
                "calls": self.purity.calls,
                "calls_detail": [list(call) for call in self.purity.calls_detail],
            },
        }


# -- the service -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AdvisorService:
    """The advisor engine: five sealed read ports and nothing that can mutate.

    Every field is either a read port or the :class:`MutationSink` a real run
    would hold — which this service never routes a call through; it *reads* it,
    once, after the work, to report :attr:`MutationProof.calls`. There is no
    statement handle, no lease client, no agent sink and no executor on this
    class, so "analysis code must never acquire execution authority" is a
    property of the signature rather than a rule somebody has to remember.
    """

    topology: TopologyPort
    coverage: CoveragePort
    incidents: IncidentPort
    deployments: DeploymentPort
    evidence: EvidencePort
    sink: MutationSink | None = None

    # -- the purity pattern ------------------------------------------------------

    def detached(self) -> AdvisorService:
        """This service with its mutation sink removed.

        The analysis and the submission both evaluate through this copy. It is
        the "backend detached" half of the purity claim: the object doing the
        work holds no sink at all, so no forgotten call site could have written
        through one. The *caller's* sink is then read afterwards and its length
        reported, which is what turns "nothing was mutated" from a promise into a
        measurement.
        """
        return replace(self, sink=None)

    def _proof(self) -> MutationProof:
        """The observed length of the caller's sink — read, never written."""
        return MutationProof(
            backend_attached=False,
            calls=len(self.sink) if self.sink is not None else 0,
            calls_detail=self.sink.calls if self.sink is not None else (),
        )

    # -- reading the sealed inputs -------------------------------------------------

    def graph(self) -> TopologyGraph:
        return self.topology.topology()

    def graph_identity(self) -> str:
        """The sealed graph's identity, from :mod:`mayhem.domain.prediction`.

        Delegated rather than re-derived: the digest admission and the digest a
        replay is pinned to must be the same function's, or "the graph changed"
        means two different things depending on who asks.
        """
        return compute_graph_identity(self.graph())

    def landscape(self) -> CoverageLandscape:
        """The declared coverage landscape, read through the coverage port."""
        return CoverageLandscape(
            landscape_id=self.coverage.landscape_id(), cells=tuple(self.coverage.cells())
        )

    def replayable(self) -> tuple[IncidentFacts, ...]:
        """Every normalised capture on the incident port, in id order.

        Sorted so the same port contents always produce the same analysis order,
        and so a diff between two runs does not fire on arrival order.
        """
        return tuple(sorted(self.incidents.captures(), key=lambda c: c.incident_id))

    # -- the analysis --------------------------------------------------------------

    def analyse(
        self,
        propose: Callable[[Finding], ExperimentCandidate],
        criteria: PriorityCriteria,
        weight: Callable[[Finding], Mapping[str, CriterionReading]],
    ) -> AdvisorAnalysis:
        """Correlate the sealed inputs into findings and untrusted drafts.

        The order of the checks is the argument:

        1. a cell whose state is not a gap state is never a finding — that
           refusal belongs to :data:`mayhem.domain.advisor.GAP_STATES` and to
           :mod:`mayhem.domain.comparison` for the failed case, and re-deciding
           it here would give one event two owners;
        2. a cell sealed evidence has already established is not uncovered,
           whatever its coverage state says;
        3. a cell whose target is in no node of the sealed topology cannot cite
           the topology its failure would travel through, so it cannot be a
           :class:`Finding` at all;
        4. what survives is a finding, and every finding gets a draft through
           :func:`mayhem.domain.advisor.recommendations_for` — which returns
           drafts and nothing else, and requires a complete reading for every
           finding before it proposes anything.

        ``weight`` is a *callable* rather than a map keyed by finding id, and
        that is the point: the finding ids are an output of this method, so a
        caller could not have written them down beforehand without first running
        the very analysis being asked for. It is also what makes a finding the
        reader cannot weigh a refusal rather than a silent drop —
        :func:`mayhem.domain.advisor.recommendations_for` is handed exactly one
        reading-map per finding this method produced, so an incomplete map is
        caught by ``Priority.from_readings`` upstream of any proposal.

        Every input is read through its port, and the whole method evaluates
        through :meth:`detached`.
        """
        service = self.detached()
        landscape = service.landscape()
        graph = service.graph()
        identity = service.graph_identity()
        snapshot_id = service.topology.snapshot_id()
        if not snapshot_id.strip():
            raise InvariantViolationError(
                RULE_REPLAY_TOPOLOGY_PIN_MISMATCH,
                "the topology port reports no snapshot id: without one every finding "
                "would be pinned to a graph nobody can name, and a gap nobody can "
                "place is a gap nobody can close",
            )
        states = dict(service.coverage.states())
        established = {record.cell_key: record for record in service.evidence.established()}
        resident = frozenset(node.id for node in graph.nodes)
        captures = service.replayable()

        notes: list[str] = []
        if established:
            notes.append(
                f"{len(established)} cell(s) suppressed because sealed evidence "
                f"already established them: {sorted(established)}"
            )

        findings: list[Finding] = []
        suppressed: list[SuppressedCell] = []
        for cell in sorted(landscape.cells, key=lambda c: c.key):
            state = states.get(cell.key)
            if state is None or state not in GAP_STATES:
                suppressed.append(
                    SuppressedCell(
                        cell_key=cell.key,
                        reason=SuppressReason.NOT_A_GAP_STATE,
                        detail=(
                            f"coverage records {getattr(state, 'value', 'no state')} for "
                            "this cell, and nothing about a run in flight or a graded "
                            "regression makes it an uncovered failure mode"
                        ),
                    )
                )
                continue
            sealed = established.get(cell.key)
            if sealed is not None:
                suppressed.append(
                    SuppressedCell(
                        cell_key=cell.key,
                        reason=SuppressReason.ESTABLISHED_BY_SEALED_EVIDENCE,
                        detail=(
                            f"{sealed.run_label} established this cell "
                            f"(evidence {sealed.evidence_digest[:12]}…): a cell a sealed "
                            "run already exercised is not an uncovered failure mode, and "
                            "the engine does not re-report what evidence already settled"
                        ),
                    )
                )
                continue
            if cell.target not in resident:
                suppressed.append(
                    SuppressedCell(
                        cell_key=cell.key,
                        reason=SuppressReason.TARGET_NOT_IN_TOPOLOGY,
                        detail=(
                            f"target {cell.target!r} is in no node of the sealed "
                            f"topology (snapshot {snapshot_id!r}): a finding has to cite "
                            "the nodes its failure would travel through, and this cell "
                            "has none to cite"
                        ),
                    )
                )
                continue
            findings.append(
                _finding_for(
                    cell,
                    state,
                    landscape,
                    identity,
                    snapshot_id=snapshot_id,
                    captures=captures,
                )
            )

        ordered = tuple(findings)
        drafts = recommendations_for(
            ordered,
            criteria,
            {f.finding_id: dict(weight(f)) for f in ordered},
            propose=propose,
        )
        return AdvisorAnalysis(
            artifact=ADVISOR_ARTIFACT,
            landscape_id=landscape.landscape_id,
            graph_identity=identity,
            topology_snapshot_id=snapshot_id,
            findings=ordered,
            drafts=drafts,
            suppressed=tuple(suppressed),
            purity=self._proof(),
            notes=tuple(notes),
        )

    # -- incident replay ------------------------------------------------------------

    def replay(
        self, request: ReplayRequest, incident: IncidentFacts, landscape: CoverageLandscape
    ) -> IncidentReplay:
        """Compile one incident capture into a candidate, pinned and traced.

        Refusals, in the order they are checked, and every one of them is a
        refusal rather than a substitution:

        * the capture's topology pin is not the snapshot this engine read
          (:data:`RULE_REPLAY_TOPOLOGY_PIN_MISMATCH`) — a replay against a
          different graph reproduces a different incident;
        * a component's pinned version has been superseded by the deployment
          record (:data:`RULE_REPLAY_VERSION_SUPERSEDED`) — for the same reason,
          one version later;
        * the capture has no *usable* observed percentile
          (:data:`RULE_REPLAY_NO_USABLE_OBSERVATION`) — a replay whose stop
          condition cannot be built on an observation is a replay that cannot
          stop;
        * a binding whose incident fact does not exist
          (:data:`RULE_REPLAY_PARAMETER_UNTRACEABLE`) or whose unit disagrees
          (:data:`RULE_REPLAY_UNIT_MISMATCH`).

        Nothing here is defaulted. A fault parameter the request did not bind is
        left to the catalog's own declared default, which is the catalog's
        decision; every parameter this compiler *generates* arrives with a
        :class:`ParameterTrace`.
        """
        service = self.detached()
        snapshot_id = service.topology.snapshot_id()
        identity = service.graph_identity()
        if incident.topology_snapshot_id != snapshot_id:
            raise InvariantViolationError(
                RULE_REPLAY_TOPOLOGY_PIN_MISMATCH,
                f"incident {incident.incident_id!r} was observed against topology "
                f"snapshot {incident.topology_snapshot_id!r}, and this engine read "
                f"{snapshot_id!r}: replaying it against a different graph reproduces a "
                "different incident, which is the one thing replay exists to prevent",
            )
        _require_versions_current(incident, service.deployments.releases())

        usable = tuple(p for p in incident.percentiles if p.usable)
        if not usable:
            raise InvariantViolationError(
                RULE_REPLAY_NO_USABLE_OBSERVATION,
                f"incident {incident.incident_id!r} observed "
                f"{[f'{p.label} ({p.samples} samples)' for p in incident.percentiles]} "
                "and no observation stands behind anything: a replay whose parameters "
                "and stop conditions cannot be read off a measurement is a guess with an "
                "incident's name on it",
            )

        parameters = tuple(
            _trace_for(incident, binding) for binding in request.bindings
        )
        cell = _cell_for(incident, request)
        finding = _finding_for(
            cell,
            _gap_state_for(incident),
            landscape,
            identity,
            snapshot_id=snapshot_id,
            captures=(incident,),
        )
        candidate = _replay_candidate(incident, request, parameters, finding)
        return IncidentReplay(
            incident=incident,
            fault_id=request.fault_id,
            cell=cell,
            finding=finding,
            candidate=candidate,
            parameters=parameters,
            duration_s=incident.duration_s,
            topology_snapshot_id=incident.topology_snapshot_id,
            graph_identity=identity,
        )

    # -- the one door out ------------------------------------------------------------

    def submit(
        self,
        recommendation: Recommendation,
        ctx: SafetyContext,
        *,
        fault_id: str,
        target: str,
        duration_s: float,
        parameters: Mapping[str, object],
        run_id: str,
        config_snapshot_id: str,
        environment_fingerprint: str,
        traces: Sequence[ParameterTrace] | None = None,
        adapter: RuntimeAdapter | None = None,
    ) -> AdvisorSubmission:
        """Take one recommendation through compile -> proof -> policy.

        Identical for both origins, and deliberately not parameterised on origin
        at all: there is no ``generated=`` branch anywhere below this line, so an
        AI-drafted recommendation reaches the planner, the proof compiler, and
        the policy gate exactly as an authored one does and acquires nothing on
        the way.

        The order is the guarantee. ``plan_drill`` compiles the frozen
        :class:`~mayhem.domain.experiments.ExecutionPlan`, and a candidate that
        will not compile raises *here* — as
        :data:`RULE_SUBMISSION_WILL_NOT_COMPILE` — which is upstream of both the
        proof compiler and the policy gate, so a draft nobody can run never gets
        a safety case or a policy verdict either. Then
        :func:`~mayhem.controller.safety_proof.compile_safety_evidence` runs the
        real gates and assembles the proof, and
        :func:`~mayhem.controller.safety.simulate_plan_policy` produces the
        verdict.

        ``traces`` is what ties a *generated* parameter set back to the incident
        facts behind it: supply it and every entry must correspond exactly to a
        submitted parameter (:data:`RULE_SUBMISSION_UNTRACEABLE_PARAMETER`).

        ``adapter`` is forwarded to the proof compiler unchanged. Left ``None`` —
        the default — the ``capability_requirements`` line is unestablished and
        the proof comes out ``VOID`` saying so, which is the honest answer: the
        advisor read sealed inputs and has no live runtime to ask what the
        cluster can do. Supplying an adapter is a statement about the runtime,
        not about the incident, so it is the caller's to make and not this
        method's to assume.

    A ``PASS`` on the proof's ``required_approvals`` line is *not* a refusal here,
    and Phase 4 decided that deliberately: see
    :attr:`AdvisorSubmission.authorization` for the four states that line can be
    in and why the advisor's is always :data:`SubmissionAuthorization.REQUIREMENTS_ONLY`.
        """
        service = self.detached()
        _require_traced(parameters, traces)
        fault_params: dict[str, object] = {"fault": fault_id, "duration": f"{duration_s}s"}
        fault_params.update(dict(parameters))
        spec = _submission_spec(recommendation, target, fault_params)
        return service._run_submission(
            recommendation,
            ctx,
            spec,
            run_id=run_id,
            config_snapshot_id=config_snapshot_id,
            environment_fingerprint=environment_fingerprint,
            adapter=adapter,
        )

    def _run_submission(
        self,
        recommendation: Recommendation,
        ctx: SafetyContext,
        spec: DrillSpec,
        *,
        run_id: str,
        config_snapshot_id: str,
        environment_fingerprint: str,
        adapter: RuntimeAdapter | None,
    ) -> AdvisorSubmission:
        """Compile one spec and take it through proof and policy. One implementation.

        Every path out of this module goes through here, which is what makes "a
        generated candidate faces the identical gates an authored one does" one
        piece of code rather than two that happen to agree today. The refusal
        order lives here and is load-bearing: ``plan_drill`` raises here,
        upstream of the proof compiler and the policy gate, so a spec that will
        not compile never receives a safety case or a policy verdict either.
        """
        graph = self.graph()
        snapshot_id = self.topology.snapshot_id()
        try:
            plan = plan_drill(
                run_id,
                spec,
                graph,
                config_snapshot_id=config_snapshot_id,
                topology_snapshot_id=snapshot_id,
                environment_fingerprint=environment_fingerprint,
            )
        except (PlanningError, LookupError) as exc:
            raise InvariantViolationError(
                RULE_SUBMISSION_WILL_NOT_COMPILE,
                f"recommendation {recommendation.recommendation_id!r} does not compile: "
                f"{exc}. A candidate that cannot be compiled is refused here, before the "
                "proof compiler and the policy gate, so it never receives a safety case "
                "or a policy verdict",
            ) from None

        compilation = compile_safety_evidence(plan, graph, ctx, adapter=adapter)
        policy = simulate_plan_policy(plan, ctx)
        return AdvisorSubmission(
            recommendation=recommendation,
            plan=plan,
            plan_digest=compilation.plan_digest,
            compilation=compilation,
            policy=policy,
            purity=self._proof(),
            authorization=_authorization_state(ctx, compilation),
        )


# -- assembly helpers ---------------------------------------------------------------


def _require_versions_current(incident: IncidentFacts, releases: Mapping[str, str]) -> None:
    """Refuse a replay whose pinned versions the deployment record has moved past.

    Only components the deployment record actually names are checked. An absent
    component is not evidence that nothing moved — it is the absence of evidence,
    and the incident's own pins are then the only version statement there is,
    which is exactly what the pin is for.
    """
    moved = tuple(
        (pin.component, pin.version, releases[pin.component])
        for pin in incident.versions
        if pin.component in releases and releases[pin.component] != pin.version
    )
    if moved:
        detail = ", ".join(f"{c}: incident pinned {p}, deployed {d}" for c, p, d in moved)
        raise InvariantViolationError(
            RULE_REPLAY_VERSION_SUPERSEDED,
            f"incident {incident.incident_id!r} cannot be replayed as-is — {detail}. A "
            "replay runs against whatever happens to be deployed, which is the one thing "
            "replay exists to avoid",
        )


def _trace_for(incident: IncidentFacts, binding: ParameterBinding) -> ParameterTrace:
    """One traced parameter, or a refusal. Never a default.

    This is the heart of the traceability rule and it has three refusals, all of
    them the same shape: the binding names an incident fact, and where the fact
    is absent or does not measure what the parameter claims, the compiler says so
    instead of substituting the catalog's value. Substituting would produce a
    candidate that compiles, passes every gate, and reproduces nothing.
    """
    if binding.source is ParameterSource.DURATION:
        return ParameterTrace(
            parameter=binding.parameter,
            value=incident.duration_s,
            unit="s",
            source=binding.fact,
            incident_id=incident.incident_id,
            detail=(
                f"incident {incident.incident_id!r} lasted "
                f"{incident.duration_s:g}s from {incident.started_at or 'an unrecorded start'} "
                f"to {incident.ended_at or 'an unrecorded end'}"
            ),
        )
    observed = incident.percentile(binding.label)
    if observed is None:
        raise InvariantViolationError(
            RULE_REPLAY_PARAMETER_UNTRACEABLE,
            f"parameter {binding.parameter!r} is bound to percentile "
            f"{binding.label!r}, which incident {incident.incident_id!r} never observed "
            f"(it observed {sorted(p.label for p in incident.percentiles)}): there is no "
            "fact here to read, and the catalog's default is not a substitute for the "
            "incident's own measurement",
        )
    if not observed.usable:
        raise InvariantViolationError(
            RULE_REPLAY_PARAMETER_UNTRACEABLE,
            f"parameter {binding.parameter!r} is bound to percentile "
            f"{binding.label!r}, which incident {incident.incident_id!r} observed "
            f"{observed.samples} time(s): an observation with nothing behind it cannot "
            "carry a parameter, and defaulting here would dress an absence up as a "
            "measurement",
        )
    if observed.unit != binding.unit:
        raise InvariantViolationError(
            RULE_REPLAY_UNIT_MISMATCH,
            f"parameter {binding.parameter!r} is bound to percentile "
            f"{binding.label!r} in {binding.unit!r}, but incident "
            f"{incident.incident_id!r} observed it in {observed.unit!r}: a replay that "
            "translates its own evidence silently reproduces a different incident",
        )
    return ParameterTrace(
        parameter=binding.parameter,
        value=observed.value,
        unit=observed.unit,
        source=binding.fact,
        incident_id=incident.incident_id,
        detail=(
            f"{observed.metric} {observed.label} read {observed.value:g}{observed.unit} "
            f"over {observed.samples} sample(s) during {incident.incident_id!r}"
        ),
    )


def _gap_state_for(incident: IncidentFacts) -> CellState:
    """The gap state a replay's finding is read from.

    :data:`mayhem.domain.advisor.CellState.UNKNOWN` and nothing else: the
    incident is the evidence that nobody has tested this, so the state is "not
    established" by construction. Choosing anything stronger would claim the
    coverage record says something it does not.
    """
    return CellState.UNKNOWN


def _cell_for(incident: IncidentFacts, request: ReplayRequest) -> CoverageCell:
    """The coverage cell a replay occupies: the incident's service, the declared fault.

    Both halves are facts rather than choices — ``service`` is the incident's own
    and ``fault_id`` is declared in the request — and the two structural
    dimensions come from the request rather than from a default, because a cell
    with an implied execution context or band is a cell nobody can look up.
    """
    return CoverageCell(
        target=incident.service,
        fault_kind=request.fault_id,
        execution_context=request.execution_context,
        parameter_band=request.parameter_band,
    )


def _replay_candidate(
    incident: IncidentFacts,
    request: ReplayRequest,
    parameters: tuple[ParameterTrace, ...],
    finding: Finding,
) -> ExperimentCandidate:
    """The candidate a replay produces, every field traced to the capture.

    Four things, and all four are in plan 15's list of what a model may do —
    summarise, generate a candidate plan, explain evidence, suggest probes:

    * ``experiment_id`` names the incident it replays;
    * ``hypothesis`` restates the incident's own failure signature on its own
      service, so the sentence a reviewer reads is the incident's, not a
      paraphrase that could have drifted;
    * ``suggested_probes`` names the declared fault on the incident's dependency;
    * ``stop_conditions`` are built from the incident's duration and from every
      usable percentile it observed, so the rule about when to stop comes from
      the same capture as the parameters.

    No approval, no weight, no execution field — the candidate type has none, and
    the draft that will carry it has none either.
    """
    stops = tuple(
        f"abort if observed {p.metric} {p.label} exceeds {p.value:g}{p.unit}"
        for p in incident.percentiles
        if p.usable
    )
    stops = (
        *stops,
        f"abort if the incident's own {incident.duration_s:g}s duration is exceeded",
    )
    return ExperimentCandidate(
        experiment_id=f"exp:replay:{incident.incident_id}",
        hypothesis=(
            f"replay of {incident.incident_id}: {incident.failure_signature} on "
            f"{incident.service} via {incident.dependency}"
        ),
        suggested_probes=(f"{request.fault_id}@{incident.dependency}",),
        stop_conditions=stops,
    )


def _finding_for(
    cell: CoverageCell,
    state: CellState,
    landscape: CoverageLandscape,
    identity: str,
    *,
    snapshot_id: str,
    captures: Sequence[IncidentFacts],
) -> Finding:
    """One finding for one gap cell: the facts, cited, and a corroborating incident.

    The topology nodes are ``(cell.target, dependency)`` for any capture whose
    service matches the cell's target — so the dependency is cited when there is
    one, and the target alone is cited when there is not. The incident is a
    *corroborating* fact, not the basis: a gap with no incident behind it is still
    a gap, and :class:`~mayhem.domain.advisor.Finding` says so.
    """
    matching = tuple(c for c in captures if c.service == cell.target)
    primary = matching[0] if matching else None
    # ``dict.fromkeys`` is the dedup: two captures of the same service are one
    # node cited once, not a repeated citation that reads like two hops.
    cited = (cell.target, primary.dependency) if primary is not None else (cell.target,)
    nodes = tuple(dict.fromkeys(node_id for node_id in cited if node_id.strip()))
    # The id is a digest of the cell key rather than the key itself: a cell key
    # joins its four parts with the unit separator, which is unreadable in an id
    # that ends up in a recommendation id, a trace line, and a log.
    return Finding(
        finding_id=f"finding:{sha256_hex(cell.key)[:12]}",
        failure_mode=f"{cell.fault_kind} on {cell.target}",
        summary=(
            f"{cell.fault_kind} on {cell.target} is {state.value} in coverage cell "
            f"{cell.key!r}: nothing has established how {cell.target} behaves when "
            f"{cell.fault_kind} happens, and the failure would travel through "
            f"{list(nodes)}"
        ),
        cell=cell,
        cell_state=state,
        landscape=landscape,
        topology_node_ids=nodes,
        graph_identity=identity,
        incident=primary,
    )


def _require_traced(
    parameters: Mapping[str, object], traces: Sequence[ParameterTrace] | None
) -> None:
    """Refuse a generated parameter set that is not exactly its incident traces.

    A caller that generated the parameters has to say where each came from. This
    is checked against the *submitted* mapping rather than trusted, so a trace
    cannot be supplied for one value while a different, untraced value travels
    under its name — which is the shape an invented parameter would take.
    """
    if traces is None:
        return
    submitted = {str(name): value for name, value in parameters.items()}
    traced = {trace.parameter: trace for trace in traces}
    untraced = sorted(set(submitted) - set(traced))
    if untraced:
        raise InvariantViolationError(
            RULE_SUBMISSION_UNTRACEABLE_PARAMETER,
            f"generated parameter(s) {untraced} arrive with no trace to an incident "
            f"fact (traced: {sorted(traced)}): a generated parameter with no origin is "
            "an invented one, and it is refused before the plan is compiled",
        )
    mismatched = sorted(
        f"{name}={submitted[name]!r} but traced {traced[name].value!r}"
        for name in traced
        if name in submitted and float(submitted[name]) != traced[name].value  # type: ignore[arg-type]
    )
    if mismatched:
        raise InvariantViolationError(
            RULE_SUBMISSION_UNTRACEABLE_PARAMETER,
            f"generated parameter(s) disagree with their trace: {mismatched}: a trace "
            "that names one value while a different one is submitted is not a trace",
        )


def _submission_spec(
    recommendation: Recommendation, target: str, fault_params: Mapping[str, object]
) -> DrillSpec:
    """The :class:`~mayhem.domain.experiments.DrillSpec` a recommendation compiles through.

    Deliberately the ordinary drill spec — one container, one declared fault, one
    sequential execution step — so a generated recommendation is planned by
    ``plan_drill`` with the same rules, the same compensation contract, and the
    same frozen-plan invariants an authored one is. The hypothesis travels from
    the recommendation, which means the plan a reviewer reads carries the same
    sentence the draft did.
    """
    container = DrillContainer(
        faults=(DrillFault.model_validate(dict(fault_params)),),
    )
    return DrillSpec(
        kind="drill",
        name=f"advisor:{recommendation.recommendation_id}",
        hypothesis=recommendation.candidate.hypothesis,
        containers={target: container},
        execution=(ExecutionStep(sequential=(target,)),),
    )


def build_draft_payload(
    *, recommendation_id: str, finding_id: str, rationale: str, hypothesis: str
) -> dict[str, object]:
    """An untrusted draft payload in the shape the boundary accepts.

    Exists so a caller assembling advisor output from a model's JSON has one
    spelling of it, and so :func:`mayhem.controller.analytics_service.authority_keys`
    — the reused scan — has something real to run against. The payload is *data*:
    it is refused here if it carries an authority field at any depth, before any
    part of it is read.
    """
    payload: dict[str, object] = {
        "recommendation_id": recommendation_id,
        "finding_id": finding_id,
        "rationale": rationale,
        "hypothesis": hypothesis,
        "probes": [],
        "stop_conditions": [],
    }
    return payload


def read_draft_payload(
    payload: Mapping[str, object],
) -> tuple[str, str, str]:
    """Read an untrusted draft payload, refusing anything that oversteps.

    Two refusals, and the order is the boundary: the authority scan runs
    *first*, over the whole payload at every depth, before any field is read.
    That ordering is the difference between "the payload was rejected for trying
    to be an approval" and "the payload happened to be rejected for a typo on the
    way past its approval token".

    The scan itself is
    :func:`mayhem.controller.analytics_service.authority_keys` — plan 15's, over
    :data:`mayhem.controller.analytics_service.AUTHORITY_FIELDS`. It is imported
    rather than reimplemented because two lists of "keys that mean authority" is
    two answers, and the answers would drift the first time somebody added a key
    to one of them.
    """
    authority = sorted(authority_keys(payload))
    if authority:
        raise InvariantViolationError(
            RULE_DRAFT_CARRIES_AUTHORITY,
            f"advisor payload carries authority field(s) {authority}: an AI-drafted "
            "candidate reaches exactly as far through compilation, policy and approval "
            "as an authored one would, and it cannot supply its own. It must be reviewed "
            "as one",
        )
    unknown = sorted(set(payload) - ALLOWED_DRAFT_FIELDS)
    if unknown:
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"advisor payload declares unknown field(s) {unknown}; allowed fields are "
            f"{sorted(ALLOWED_DRAFT_FIELDS)}",
        )
    return (
        _payload_str(payload, "recommendation_id"),
        _payload_str(payload, "rationale"),
        _payload_str(payload, "hypothesis"),
    )


def _payload_str(payload: Mapping[str, object], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise InvariantViolationError(
            RULE_DRAFT_UNKNOWN_FIELD,
            f"advisor payload field {field_name!r} must be a non-blank string, got "
            f"{value!r}",
        )
    return value


# -- Phase 4: the scenario library's way in --------------------------------------


def submit_scenario(
    service: AdvisorService,
    instantiation: ScenarioInstantiation,
    recommendation: Recommendation,
    ctx: SafetyContext,
    *,
    run_id: str,
    config_snapshot_id: str,
    environment_fingerprint: str,
    adapter: RuntimeAdapter | None = None,
) -> AdvisorSubmission:
    """Take a scenario-instantiated recommendation down the same road as any other.

    A scenario library template (gap 49,
    :mod:`mayhem.domain.scenarios`) is a *multi-fault timeline*, and
    :meth:`AdvisorService.submit` takes one ``fault_id`` because that is what a
    candidate names. Rather than add a second compile path for multi-fault specs,
    this takes the instantiation's own
    :meth:`~mayhem.domain.scenarios.ScenarioInstantiation.drill_spec` and hands it
    to the same private core — so the compile → proof → policy sequence, the
    refusal order, and the origin-blindness are one implementation.

    The binding check is what keeps this from being a side channel. The spec must
    carry ``recommendation.candidate.hypothesis``, which is the sentence the
    draft's :meth:`~mayhem.domain.advisor.UntrustedRecommendationDraft.compile`
    produced *from the template's* hypothesis. A caller who swaps in a plan of
    their own is refused with :data:`RULE_SUBMISSION_SPEC_NOT_BOUND` before the
    planner runs, so supplying a spec cannot put a plan in front of a reviewer
    that does not say what the recommendation said.

    Everything else follows from the road being shared: the returned submission
    is an :class:`AdvisorSubmission` whose recommendation is ``generated`` and
    unapproved, whose authorization is
    :data:`SubmissionAuthorization.REQUIREMENTS_ONLY`, and whose proof and policy
    artefacts were produced by the same two functions an authored recommendation
    gets. A scenario is not a privileged kind of plan; it is a plan.
    """
    if instantiation.hypothesis != recommendation.candidate.hypothesis:
        raise InvariantViolationError(
            RULE_SUBMISSION_SPEC_NOT_BOUND,
            f"scenario {instantiation.ref!r} proposes hypothesis "
            f"{instantiation.hypothesis[:60]!r}… but recommendation "
            f"{recommendation.recommendation_id!r} carries "
            f"{recommendation.candidate.hypothesis[:60]!r}…: the plan that gets compiled "
            "must say what the recommendation a human read says. Supplying a spec cannot "
            "put a different experiment in front of a reviewer",
        )
    service = service.detached()
    return service._run_submission(
        recommendation,
        ctx,
        instantiation.drill_spec(),
        run_id=run_id,
        config_snapshot_id=config_snapshot_id,
        environment_fingerprint=environment_fingerprint,
        adapter=adapter,
    )


# -- Phase 4: advisory claims and their seal -------------------------------------


@dataclass(frozen=True, slots=True)
class AdvisoryClaim:
    """One advisor claim, reduced to what can be attested about it.

    This is the type that makes "advisory, not authorization" structural, and the
    absence is the mechanism. There is no ``approval`` field, no ``approved_by``,
    no ``intent``, no ``run_id``, no ``policy_decision`` and no ``approval_state``;
    :meth:`from_recommendation` refuses a recommendation that already carries an
    approval (:data:`RULE_ADVISORY_SEAL_CARRIES_APPROVAL`), so an approval can
    never be laundered into the sealed chain by sealing the recommendation that
    holds it.

    :attr:`authority` is therefore always :attr:`AdvisorAuthority.NONE`, and the
    constructor checks it rather than trusting the caller — a claim whose authority
    reads ``approved`` is refused, because a type that can hold one is a type that
    will eventually hold one.

    What the claim *does* carry is the whole citation set: the finding's facts, the
    criteria readings it was ranked by, the graph identity it was read against, and
    — when it came from a submission — the plan digest, proof verdict, policy
    outcome and authorization state. Those are facts *about the claim*, not powers
    it holds.
    """

    recommendation_id: str
    recommendation_digest: str
    origin: RecommendationOrigin
    authority: AdvisorAuthority
    finding_id: str
    cell_key: str
    graph_identity: str
    cited_facts: tuple[CitedFact, ...]
    criteria_name: str
    criteria: tuple[str, ...]
    priority_total: float
    plan_digest: str = ""
    proof_verdict: str = ""
    policy_allowed: bool | None = None
    authorization: SubmissionAuthorization = SubmissionAuthorization.REQUIREMENTS_ONLY

    def __post_init__(self) -> None:
        if self.authority is not AdvisorAuthority.NONE:
            raise InvariantViolationError(
                RULE_ADVISORY_SEAL_CARRIES_APPROVAL,
                f"advisory claim {self.recommendation_id!r} carries authority "
                f"{self.authority.value!r}: a sealed advisory artifact stands only as a "
                "claim about cited facts. An approval is bound by digest to the exact "
                "recommendation a human read and is recorded by the approval gate's own "
                "chain; sealing it here would re-attest a decision this module has no "
                "standing to make",
            )
        if not self.recommendation_id.strip() or not self.finding_id.strip():
            raise InvariantViolationError(
                RULE_ADVISORY_SEAL_UNTRACEABLE,
                f"advisory claim {self.recommendation_id!r} must name both the "
                "recommendation and the finding it rests on",
            )
        if not _SEALED_DIGEST_RE.fullmatch(self.recommendation_digest):
            raise InvariantViolationError(
                RULE_ADVISORY_SEAL_UNTRACEABLE,
                f"advisory claim {self.recommendation_id!r} carries digest "
                f"{self.recommendation_digest!r}, which is not a sealed sha256 digest: a "
                "claim in the chain of record has to be addressable by something that "
                "names its own bytes",
            )
        if not self.cited_facts:
            raise InvariantViolationError(
                RULE_ADVISORY_SEAL_UNTRACEABLE,
                f"advisory claim {self.recommendation_id!r} cites no facts: a correlation "
                "with nothing behind it is an opinion, and opinions do not belong in a "
                "chain that a verifier will later be asked to trust",
            )
        blank = tuple(fact.ref for fact in self.cited_facts if not fact.ref.strip())
        if blank:
            raise InvariantViolationError(
                RULE_ADVISORY_SEAL_UNTRACEABLE,
                f"advisory claim {self.recommendation_id!r} cites blank reference(s) "
                f"{list(blank)}: a citation nobody can look up is not a citation",
            )
        if not isfinite(self.priority_total):
            raise InvariantViolationError(
                RULE_ADVISORY_SEAL_UNTRACEABLE,
                f"advisory claim {self.recommendation_id!r} carries priority "
                f"{self.priority_total!r}: nan is an arithmetic accident, not a ranking",
            )

    @classmethod
    def from_recommendation(cls, recommendation: Recommendation) -> AdvisoryClaim:
        """The claim a recommendation makes, with its citations and nothing else.

        Refuses a recommendation whose rationale does not name the criteria it was
        ranked by — the same check :meth:`Recommendation.render` makes, for the
        same reason. A reader-facing view drops an untraceable recommendation; the
        chain of record must not accept one either, because the difference is that
        the chain is what somebody reads *later*, with no analyst in the room.
        """
        if recommendation.approval is not None:
            raise InvariantViolationError(
                RULE_ADVISORY_SEAL_CARRIES_APPROVAL,
                f"recommendation {recommendation.recommendation_id!r} already carries an "
                f"approval from {recommendation.approval.approved_by!r}: an approval is "
                "its own record, attested by the gate that verified it. Sealing the "
                "recommendation that holds one here would produce a second artifact "
                "asserting a decision the advisor did not make",
            )
        reason = recommendation.render_refusal_reason()
        if reason:
            raise InvariantViolationError(
                RULE_ADVISORY_SEAL_UNTRACEABLE,
                f"{reason}. An untraceable recommendation may be stored, but it does not "
                "belong in the sealed chain: the chain is read later and cold, with no "
                "analyst in the room to notice the omission",
            )
        return cls(
            recommendation_id=recommendation.recommendation_id,
            recommendation_digest=recommendation.recommendation_digest,
            origin=recommendation.origin,
            authority=recommendation.authority,
            finding_id=recommendation.finding.finding_id,
            cell_key=recommendation.finding.cell_key,
            graph_identity=recommendation.finding.graph_identity,
            cited_facts=recommendation.cited_facts,
            criteria_name=recommendation.priority.criteria_name,
            criteria=recommendation.priority.criteria_names,
            priority_total=recommendation.total,
        )

    @classmethod
    def from_submission(cls, submission: AdvisorSubmission) -> AdvisoryClaim:
        """The claim plus the three artifacts the road produced for it.

        Superset of :meth:`from_recommendation`, and the one worth sealing when
        there is a submission: the plan digest an approval must bind, the proof's
        verdict, the policy outcome, and the
        :attr:`AdvisorSubmission.authorization` state are all facts about the claim
        and none of them is authority. The authorization state travels *as data*
        precisely so a later reader can see "requirements only" without having to
        reconstruct it.
        """
        return replace(
            cls.from_recommendation(submission.recommendation),
            plan_digest=submission.plan_digest,
            proof_verdict=submission.proof_verdict,
            policy_allowed=submission.policy_allowed,
            authorization=submission.authorization,
        )

    @property
    def standing(self) -> str:
        """Always :data:`ADVISORY_STANDING`. A property, not a field, on purpose."""
        return ADVISORY_STANDING

    def payload(self) -> dict[str, object]:
        """The attested body: names and digests, plus every fact it cites.

        ``grants_approval`` and ``grants_authorization`` are literal ``False`` in
        the persisted bytes. They are not a promise — the types already forbid it —
        but they are what an operator reading this JSON without the code needs in
        order not to have to infer it from an absent field.
        """
        return {
            "standing": ADVISORY_STANDING,
            "grants_approval": False,
            "grants_authorization": False,
            "recommendation_id": self.recommendation_id,
            "recommendation_digest": self.recommendation_digest,
            "origin": self.origin.value,
            "authority": self.authority.value,
            "finding_id": self.finding_id,
            "cell_key": self.cell_key,
            "graph_identity": self.graph_identity,
            "criteria_name": self.criteria_name,
            "criteria": list(self.criteria),
            "priority_total": self.priority_total,
            "cited_facts": [fact.to_dict() for fact in self.cited_facts],
            "plan_digest": self.plan_digest,
            "proof_verdict": self.proof_verdict,
            "policy_allowed": self.policy_allowed,
            "authorization": self.authorization.value,
        }

    def to_dict(self) -> dict[str, object]:
        return self.payload()


@dataclass(frozen=True, slots=True)
class AdvisorySeal:
    """What sealing an advisory claim produced, plus both verification verdicts.

    :attr:`grants_authorization` is the literal ``False`` and reads nothing, so no
    input can change it. :attr:`verified` is *integrity*, the same question
    :func:`~mayhem.domain.attestation.verify_chain` answers for a run's chain and
    no more: it says the bytes are unaltered and in order, not that the claim is
    true and not that anybody approved it.

    Note what this type does **not** have: no ``evidence_digest`` attribute, which
    is why :func:`~mayhem.domain.advisor.is_certified_evidence` is ``False`` for
    it, and no ``run_id``, so it can never be presented as a run's sealed evidence.
    Both absences are the design, and tests/unit/test_advisor_evidence.py asserts
    them rather than trusting this sentence.
    """

    chain_id: str
    manifest_id: str
    events: tuple[AttestedEvent, ...]
    manifest: Manifest
    chain_verification: ChainVerification
    manifest_verification: ManifestVerification
    claim: AdvisoryClaim

    @property
    def chain_root(self) -> str:
        """The root the manifest commits to."""
        return chain_root(self.events)

    @property
    def verified(self) -> bool:
        """Chain integrity and manifest coverage. Not truth, and not approval."""
        return self.chain_verification.valid and self.manifest_verification.valid

    @property
    def grants_authorization(self) -> bool:
        """Always ``False``. Literal, derived from nothing, on purpose.

        A sealed advisory claim is a record that a recommendation was generated
        from cited facts. It approves nothing, authorises nothing, and grants no
        execution intent — and because this property takes no input, there is no
        value a caller could pass, store, or replay to make it say otherwise.
        """
        return False

    @property
    def standing(self) -> str:
        """Always :data:`ADVISORY_STANDING`."""
        return ADVISORY_STANDING

    def describe(self) -> str:
        return (
            f"advisory claim {self.claim.recommendation_id!r} sealed as {self.manifest_id} "
            f"(root {self.chain_root[:12]}…, {len(self.events)} event(s), standing "
            f"{self.standing}, grants_authorization={self.grants_authorization}, "
            f"{'verified' if self.verified else 'UNVERIFIED'})"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "standing": self.standing,
            "grants_approval": False,
            "grants_authorization": self.grants_authorization,
            "chain_id": self.chain_id,
            "manifest_id": self.manifest_id,
            "chain_root": self.chain_root,
            "verified": self.verified,
            "claim": self.claim.to_dict(),
        }


#: The sha256 shape an advisory digest must have. Same regex
#: ``mayhem.domain.advisor`` uses for a sealed-evidence citation, restated here as
#: a module constant because this module is the one that refuses on it.
_SEALED_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def advisory_chain_id(recommendation_digest: str) -> str:
    """The chain an advisory claim hangs off: ``advisory:<digest prefix>``.

    Derived from the *claim's own* digest rather than from its id, so two claims
    about the same recommendation with different content are two chains, and one
    claim re-derived from the same bytes is the same chain. Plan 12's law is one
    chain per identity starting at genesis, and this gives an advisory claim an
    identity of its own — it has no run.
    """
    if not _SEALED_DIGEST_RE.fullmatch(recommendation_digest):
        raise InvariantViolationError(
            RULE_ADVISORY_SEAL_UNTRACEABLE,
            f"advisory chain id needs a sealed sha256 digest, got {recommendation_digest!r}",
        )
    return f"{ADVISORY_CHAIN_PREFIX}:{recommendation_digest[:16]}"


def advisory_claim_payload(claim: AdvisoryClaim) -> dict[str, object]:
    """The attested body of an advisory claim. One function, so tests can call it."""
    return claim.payload()


def advisory_events(
    claim: AdvisoryClaim, *, recorded_at: AttestedTimestamp
) -> tuple[AttestedEvent, ...]:
    """The events one advisory claim seals, in chain order (pure).

    Two members, and the second is what makes the standing legible from the chain
    alone. The first records the claim with every fact it cites; the second closes
    the chain and repeats ``standing: advisory`` with
    ``grants_authorization: false``, so a reader who has the manifest but has not
    read the first payload still learns what it is.

    The events *reference* the recommendation by digest rather than embedding it,
    the same rule :mod:`mayhem.infra.attestation_store` follows for a run's
    envelope. This chain cannot become a second copy of an advisor artifact, and
    the fact that it cannot be is what keeps it from being mistaken for one.
    """
    chain_id = advisory_chain_id(claim.recommendation_digest)
    return (
        AttestedEvent(
            event_id=f"{chain_id}:recorded",
            event_kind=CHAIN_EVENT_ADVISORY_RECORDED,
            run_id=chain_id,
            sequence=0,
            payload=advisory_claim_payload(claim),
            recorded_at=recorded_at,
        ),
        AttestedEvent(
            event_id=f"{chain_id}:sealed",
            event_kind=CHAIN_EVENT_ADVISORY_SEALED,
            run_id=chain_id,
            sequence=1,
            payload={
                "standing": ADVISORY_STANDING,
                "grants_approval": False,
                "grants_authorization": False,
                "recommendation_digest": claim.recommendation_digest,
                "claims_before": 1,
            },
            recorded_at=recorded_at,
        ),
    )


def _seal_reading(recorded_at: AttestedTimestamp | None) -> AttestedTimestamp:
    """The caller's reading, or a fresh wall-clock + monotonic pair.

    Same construction :mod:`mayhem.infra.attestation_store` and
    :mod:`mayhem.infra.audit_stream` use, so one clock policy covers plan 12 and
    plan 21: an advisory event and a run event taken together are ordered by the
    same rule.
    """
    if recorded_at is not None:
        return recorded_at
    return AttestedTimestamp(
        wall_clock=utc_now(),
        monotonic_ns=time.monotonic_ns(),
        uncertainty_ms=0.0,
        source="system",
    )


def seal_advisory_claim(
    store: Store,
    claim: AdvisoryClaim,
    *,
    recorded_at: AttestedTimestamp | None = None,
    retention_class: RetentionClass = RetentionClass.HOT,
) -> AdvisorySeal:
    """Seal one advisory claim into a persisted chain and manifest.

    Delegates every part of the sealing to the machinery that already exists —
    :func:`~mayhem.domain.attestation.seal_events`,
    :func:`~mayhem.domain.attestation.build_manifest`,
    :func:`~mayhem.domain.attestation.verify_chain`,
    :func:`~mayhem.domain.attestation.verify_manifest`, and
    :class:`~mayhem.infra.attestation_store.AttestationRepository`. This function
    decides *what* is attested and nothing else; there is no second sealer here,
    for the same reason
    :func:`mayhem.controller.certification_evidence.seal_certification_evidence`
    is not one.

    The chain and the manifest are verified **before** anything is written, so a
    chain that does not hold leaves no row behind to be mistaken for a sealed
    claim. That ordering is the difference between "the seal failed" and "there is
    a chain that looks sealed and is not".

    The ``store`` is a *parameter*, not a field on :class:`AdvisorService`. That
    is the boundary: this function writes, the engine cannot, and the engine is
    the thing a caller holds while reading sealed inputs. ``HOT`` is the default
    retention class because an advisory claim is meant to be re-derivable — the
    facts it cites are the durable part — and keeping the correlation forever
    would outlast the reason it was made.

    Raises:
        AttestationError: If the derived chain or manifest fails verification.
            Nothing is written.
        InvariantViolationError: From the evidence boundary inside the plan 12
            writers, if the derived document carries a secret-classified field.
            Nothing is written.
    """
    reading = _seal_reading(recorded_at)
    events = seal_events(advisory_events(claim, recorded_at=reading))
    chain_id = advisory_chain_id(claim.recommendation_digest)
    manifest = build_manifest(
        events,
        manifest_id=f"{chain_id}:manifest",
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
            f"refusing to seal an invalid advisory chain for "
            f"{claim.recommendation_id!r}: {'; '.join(chain_verification.errors)}"
        )
    manifest_verification = verify_manifest(manifest, events)
    if not manifest_verification.valid:
        raise AttestationError(
            f"refusing to seal an invalid advisory manifest for "
            f"{claim.recommendation_id!r}: {'; '.join(manifest_verification.errors)}"
        )

    repository = AttestationRepository(store)
    repository.save_chain(chain_id, events, sealed_at=reading.wall_clock)
    repository.save_manifest(manifest)
    return AdvisorySeal(
        chain_id=chain_id,
        manifest_id=manifest.manifest_id,
        events=events,
        manifest=manifest,
        chain_verification=chain_verification,
        manifest_verification=manifest_verification,
        claim=claim,
    )


# -- Phase 4: the audit stream ------------------------------------------------------


def record_replay_compilation(
    stream: AuditStream,
    replay: IncidentReplay,
    *,
    principal: str,
    subject_run_id: str = "",
    recorded_at: AttestedTimestamp | None = None,
) -> AttestedEvent:
    """Append the privileged action of turning an incident into an experiment.

    An incident-replay compilation is the exact thing an auditor wants to see:
    somebody took a production failure, decided it was worth reproducing, and
    built an experiment out of it. Before Phase 4 the answer lived only in the
    caller's logs, if anywhere.

    ``decision_digest`` carries :attr:`IncidentReplay.replay_digest`, so the entry
    names the *value* that was compiled — the capture, the cell, the topology pin
    and every parameter together. ``target`` is the incident, not the coverage
    cell: a cell key joins its four parts with the unit separator, which the
    ``audit_entries`` CHECK constraints refuse as a column value, and the incident
    is the thing the compilation was *of*. The cell travels in ``detail`` where a
    key is allowed.

    ``approval_digest`` and ``policy_digest`` are left **empty on purpose**: no
    approval exists and no policy decision was consulted, and writing anything
    into either column would be a claim that the advisor holds authority it does
    not. ``principal`` is the identity the writer *recorded*; the stream is
    unsigned, so that is a claim and
    :class:`~mayhem.infra.audit_stream.AuditEntry` says so.
    """
    return stream.record(
        AuditEntry(
            principal=principal,
            action=KIND_ADVISORY_REPLAY_COMPILED,
            target=replay.incident.incident_id,
            subject_run_id=subject_run_id,
            decision_digest=replay.replay_digest,
            detail={
                "incident_id": replay.incident.incident_id,
                "cell_key": replay.cell.key,
                "service": replay.incident.service,
                "dependency": replay.incident.dependency,
                "fault_id": replay.fault_id,
                "topology_snapshot_id": replay.topology_snapshot_id,
                "graph_identity": replay.graph_identity,
                "duration_s": replay.duration_s,
                "parameters": [
                    {"parameter": t.parameter, "source": t.source, "unit": t.unit}
                    for t in replay.parameters
                ],
                "standing": ADVISORY_STANDING,
            },
        ),
        recorded_at=recorded_at,
    )


def record_advisory_seal(
    stream: AuditStream,
    seal: AdvisorySeal,
    *,
    principal: str,
    recorded_at: AttestedTimestamp | None = None,
) -> AttestedEvent:
    """Append the privileged action of sealing an advisory claim.

    The companion to :func:`record_replay_compilation`, and the same reasoning:
    sealing puts bytes into the chain of record, so it is an action an operator
    should be able to find. ``decision_digest`` is the chain root — the identity
    of exactly what was sealed — and again ``approval_digest`` is empty, because
    :attr:`AdvisorySeal.grants_authorization` is ``False`` and a log row claiming
    otherwise would be the same overclaim the seal itself refuses to make.
    """
    return stream.record(
        AuditEntry(
            principal=principal,
            action=KIND_ADVISORY_CLAIM_SEALED,
            target=seal.claim.recommendation_id,
            decision_digest=seal.chain_root,
            detail={
                "chain_id": seal.chain_id,
                "manifest_id": seal.manifest_id,
                "recommendation_digest": seal.claim.recommendation_digest,
                "finding_id": seal.claim.finding_id,
                "cell_key": seal.claim.cell_key,
                "standing": seal.standing,
                "grants_approval": False,
                "grants_authorization": seal.grants_authorization,
            },
        ),
        recorded_at=recorded_at,
    )
