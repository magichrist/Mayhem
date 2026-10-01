"""Plan 21 Phase 2 — the advisor engine: analysis over sealed inputs, and the
incident-replay compiler.

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
the service with its :class:`~mayhem.controller.policy_gate.MutationSink`
removed — and then reports :attr:`AdvisorAnalysis.purity` by reading
:func:`len` off whatever sink the *caller* held. A caller that pre-loads the sink
with a recorded call and still sees zero calls afterwards has evidence, which is
what makes ``calls == 0`` a measurement rather than a constant. The reuse is
deliberate: :class:`~mayhem.controller.prediction_service.MutationProof` already
states exactly this, and two shapes for "nothing was mutated" is one more place
for the two to disagree.

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

from dataclasses import dataclass, replace
from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING, Protocol

from mayhem.controller.analytics_service import AUTHORITY_FIELDS
from mayhem.controller.analytics_service import _authority_keys as authority_keys
from mayhem.controller.planner import PlanningError, plan_drill
from mayhem.controller.prediction_service import MutationProof
from mayhem.controller.safety import SafetyContext, simulate_plan_policy
from mayhem.controller.safety_proof import SafetyCompilation, compile_safety_evidence
from mayhem.domain.advisor import (
    GAP_STATES,
    CoverageLandscape,
    CriterionReading,
    ExperimentCandidate,
    Finding,
    IncidentFacts,
    PriorityCriteria,
    Recommendation,
    UntrustedRecommendationDraft,
    is_certified_evidence,
    rank_drafts,
    recommendations_for,
)
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import DrillContainer, DrillFault, DrillSpec, ExecutionStep
from mayhem.domain.hashing import digest, sha256_hex
from mayhem.domain.prediction import graph_identity as compute_graph_identity

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from mayhem.controller.policy_gate import MutationSink, PolicyGateResult
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.runtime_adapter import RuntimeAdapter
    from mayhem.domain.topology import TopologyGraph

__all__ = [
    "ADVISOR_ARTIFACT",
    "AUTHORITY_FIELDS",
    "RULE_DRAFT_CARRIES_AUTHORITY",
    "RULE_DRAFT_UNKNOWN_FIELD",
    "RULE_NO_DECLARED_BINDINGS",
    "RULE_REPLAY_INCOMPLETE",
    "RULE_REPLAY_NO_USABLE_OBSERVATION",
    "RULE_REPLAY_PARAMETER_UNTRACEABLE",
    "RULE_REPLAY_TOPOLOGY_PIN_MISMATCH",
    "RULE_REPLAY_UNIT_MISMATCH",
    "RULE_REPLAY_VERSION_SUPERSEDED",
    "RULE_SUBMISSION_UNTRACEABLE_PARAMETER",
    "RULE_SUBMISSION_WILL_NOT_COMPILE",
    "AdvisorAnalysis",
    "AdvisorService",
    "AdvisorSubmission",
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
    "SuppressReason",
    "SuppressedCell",
    "TopologyPort",
    "authority_keys",
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
        """
        service = self.detached()
        _require_traced(parameters, traces)
        graph = service.graph()
        snapshot_id = service.topology.snapshot_id()
        fault_params: dict[str, object] = {"fault": fault_id, "duration": f"{duration_s}s"}
        fault_params.update(dict(parameters))
        spec = _submission_spec(recommendation, target, fault_params)
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
