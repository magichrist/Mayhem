"""Uncovered failure modes, candidate experiments, and normalised incident facts
(docs/v1.1.0/21_RELIABILITY_ADVISOR.md, Phase 1).

The advisor *correlates sealed facts*. It does not understand the system, it
does not observe it, and it never touches it. Everything in this module is a
pure function of facts somebody else sealed: a coverage cell's state, a
topology snapshot's identity, a customer's declared weighting, an incident
report. There is no clock, no IO, no randomness, so the same facts always yield
the same findings, the same priority, and the same recommendation — which is
what makes a recommendation re-derivable rather than merely plausible.

**A finding is the absence of a fact, pointed at.** Plan 21's first output is an
*uncovered failure mode*, and an uncovered failure mode is not a thing you can
assert: it is the joint of a coverage cell in a gap state (:class:`Finding.cell`,
:class:`Finding.cell_state`, checked against the :class:`CoverageLandscape` the
cell came from) and the topology that the failure would travel through
(:attr:`Finding.topology_node_ids`, :attr:`Finding.graph_identity`).
All of those are required constructor arguments with no defaults, so "a finding
with no coverage cell" and "a finding with no topology" are not values this
module can produce — they are ``TypeError``s. :attr:`Finding.cited_facts` then
enumerates exactly those citations, so a reader is handed the facts instead of a
summary of them. A cell whose state is :data:`CellState.PASSED` is refused
outright (it is covered, so nothing is uncovered), and so is
:data:`CellState.FAILED` — an observed and graded failure is a *regression*,
which :mod:`mayhem.domain.comparison` already raises as a ``RegressionFinding``
from two cited runs. Two vocabularies for one event is how a triage queue ends up
disproving its own findings.

**Priority is arithmetic over declared weights, or it is nothing.** There is no
score field anywhere in this module. :class:`Priority` holds one
:class:`CriterionReading` per *declared* :class:`CustomerCriterion` — each
carrying its weight, its value in ``[0, 1]``, and the fact that value was read
from — and :attr:`Priority.total` is the weighted mean, computed on read. A
caller cannot hand this module a number and call it a priority, cannot drop the
criterion it scored badly, and cannot raise a weight to win an argument: a
weight is a *declared* customer criterion carrying the customer question it
answers, so "the model thinks this is important" has no spelling.
:class:`Priority.from_readings` refuses a reading for a criterion nobody
declared, a criterion with no reading at all, and an empty declaration.

**A recommendation that cannot show its work does not render.**
:attr:`Recommendation.render_refusal_reason` names the declared criteria the
rationale fails to mention, and :meth:`Recommendation.render` raises on it. The
gap between "the rationale is a sentence" and "the rationale is checkable
against the declared criteria" is the gap an opaque ranking lives in.

**Traceability is a construction rule, not a review habit.** A recommendation
carries its :class:`Finding` by value, and the finding carries its cell and its
topology by value, so the citation chain is part of the type. The two pure
functions :func:`recommendations_for` and :func:`rank_drafts` require an exact
one-to-one correspondence between the findings they are given and the readings
supplied for them: drop a finding and its recommendation is not produced, and
drop a finding while leaving its readings behind and the call is *refused*
rather than quietly dropping work on the floor. Remove the facts and the
recommendation does not survive, which is plan 21's acceptance criterion stated
as a property of the code.

**The AI boundary is a type, and it is enforced twice.** Plan 15's rule —
"advisor output is untrusted drafts through standard compilation" — is
implemented the way :mod:`mayhem.domain.search` implements the same rule for
generated search plans: :class:`UntrustedRecommendationDraft` is the machine's
output type and it has **no approval field at all** (not one defaulted to
``None``), no weight field, and no execution field, so a generated candidate
cannot be *composed* into an approved recommendation; the only thing it can
become is a ``generated`` :class:`Recommendation` via :meth:`compile`, and that
type refuses to be constructed with an approval on a ``generated`` origin.
:meth:`UntrustedRecommendationDraft.compile` also *requires* the declared
criteria and the readings as arguments, so the weighting is never the draft's to
supply — the AI may summarise, generate candidate plans, explain evidence and
suggest probes, and those are exactly the four things the draft type has
fields for. Authority is a property of the recommendation, never of the caller
that produced it.

**Advisor output is not evidence.** :func:`is_certified_evidence` is the
structural half of that statement: it recognises the sealed sha256 evidence
digest that :mod:`mayhem.domain.comparison` and
:mod:`mayhem.domain.certification` treat as the mark of certified evidence, and
none of the types here has such a field — not on a finding, not on a
recommendation, not on a draft. A recommendation that cites five facts is
therefore five facts *correlated*, and the correlation is not a run, has no
verdict, and can never be sealed. Blast radius is likewise not recomputed here:
"likely affected dependencies" is
:class:`mayhem.domain.prediction.ImpactPrediction`'s job, so a candidate
*cites* that prediction by digest rather than re-deriving a weaker copy of it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, field_validator

from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

__all__ = [
    "RULE_APPROVAL_MISMATCH",
    "RULE_APPROVAL_WITHOUT_AN_APPROVER",
    "RULE_CANDIDATE_INCOMPLETE",
    "RULE_CRITERIA_HAVE_NO_WEIGHT",
    "RULE_CRITERION_NOT_DECLARED",
    "RULE_CRITERION_NOT_READ",
    "RULE_CRITERION_VALUE_OUT_OF_RANGE",
    "RULE_CRITERION_WITHOUT_EVIDENCE",
    "RULE_CRITERION_WITHOUT_QUESTION",
    "RULE_DUPLICATE_CRITERION",
    "RULE_FINDING_CELL_IS_NOT_A_GAP",
    "RULE_FINDING_CELL_NOT_IN_LANDSCAPE",
    "RULE_FINDING_NOT_READ",
    "RULE_FINDING_UNEXPLAINED",
    "RULE_FINDING_UNNAMED",
    "RULE_FINDING_WITHOUT_TOPOLOGY",
    "RULE_GENERATED_CANNOT_BE_APPROVED",
    "RULE_INCIDENT_DURATION_INVALID",
    "RULE_INCIDENT_WITHOUT_IDENTITY",
    "RULE_INCIDENT_WITHOUT_OBSERVATION",
    "RULE_INCIDENT_WITHOUT_TOPOLOGY_PIN",
    "RULE_INCIDENT_WITHOUT_VERSION_PINS",
    "RULE_LANDSCAPE_DUPLICATE_CELL",
    "RULE_LANDSCAPE_EMPTY",
    "RULE_LANDSCAPE_UNIDENTIFIED",
    "RULE_NO_DECLARED_CRITERIA",
    "RULE_OBSERVED_VALUE_NOT_FINITE",
    "RULE_PREDICTION_DIGEST_INVALID",
    "RULE_READING_FOR_UNKNOWN_FINDING",
    "RULE_RECOMMENDATION_RATIONALE_NOT_TRACEABLE",
    "RULE_RECOMMENDATION_UNNAMED",
    "AdvisorAuthority",
    "Approval",
    "CitedFact",
    "CitedFactKind",
    "CoverageLandscape",
    "CriterionReading",
    "CustomerCriterion",
    "ExperimentCandidate",
    "Finding",
    "IncidentFacts",
    "ObservedPercentile",
    "Priority",
    "PriorityCriteria",
    "Recommendation",
    "RecommendationOrigin",
    "UntrustedRecommendationDraft",
    "VersionPin",
    "is_certified_evidence",
    "rank_drafts",
    "recommendations_for",
]

# -- rule ids ----------------------------------------------------------------------


RULE_FINDING_UNNAMED = "advisor.finding_unnamed"
RULE_FINDING_UNEXPLAINED = "advisor.finding_unexplained"
RULE_FINDING_CELL_IS_NOT_A_GAP = "advisor.finding_cell_is_not_a_gap"
RULE_FINDING_WITHOUT_TOPOLOGY = "advisor.finding_without_topology"
RULE_FINDING_CELL_NOT_IN_LANDSCAPE = "advisor.finding_cell_not_in_landscape"
RULE_LANDSCAPE_UNIDENTIFIED = "advisor.landscape_unidentified"
RULE_LANDSCAPE_EMPTY = "advisor.landscape_empty"
RULE_LANDSCAPE_DUPLICATE_CELL = "advisor.landscape_duplicate_cell"
RULE_FINDING_NOT_READ = "advisor.finding_not_read"
RULE_READING_FOR_UNKNOWN_FINDING = "advisor.reading_for_unknown_finding"
RULE_NO_DECLARED_CRITERIA = "advisor.no_declared_criteria"
RULE_DUPLICATE_CRITERION = "advisor.duplicate_criterion"
RULE_CRITERIA_HAVE_NO_WEIGHT = "advisor.criteria_have_no_weight"
RULE_CRITERION_WITHOUT_QUESTION = "advisor.criterion_without_question"
RULE_CRITERION_WITHOUT_EVIDENCE = "advisor.criterion_without_evidence"
RULE_CRITERION_VALUE_OUT_OF_RANGE = "advisor.criterion_value_out_of_range"
RULE_CRITERION_NOT_READ = "advisor.criterion_not_read"
RULE_CRITERION_NOT_DECLARED = "advisor.criterion_not_declared"
RULE_CANDIDATE_INCOMPLETE = "advisor.candidate_incomplete"
RULE_PREDICTION_DIGEST_INVALID = "advisor.prediction_digest_invalid"
RULE_RECOMMENDATION_UNNAMED = "advisor.recommendation_unnamed"
RULE_RECOMMENDATION_RATIONALE_NOT_TRACEABLE = "advisor.recommendation_rationale_not_traceable"
RULE_GENERATED_CANNOT_BE_APPROVED = "advisor.generated_recommendation_cannot_be_approved"
RULE_APPROVAL_MISMATCH = "advisor.approval_does_not_match_recommendation"
RULE_APPROVAL_WITHOUT_AN_APPROVER = "advisor.approval_without_an_approver"
RULE_INCIDENT_WITHOUT_IDENTITY = "advisor.incident_without_identity"
RULE_INCIDENT_WITHOUT_TOPOLOGY_PIN = "advisor.incident_without_topology_pin"
RULE_INCIDENT_WITHOUT_OBSERVATION = "advisor.incident_without_observation"
RULE_INCIDENT_WITHOUT_VERSION_PINS = "advisor.incident_without_version_pins"
RULE_INCIDENT_DURATION_INVALID = "advisor.incident_duration_invalid"
RULE_OBSERVED_VALUE_NOT_FINITE = "advisor.observed_value_not_finite"

#: The shape a sealed evidence digest has, deliberately identical to
#: ``mayhem.domain.comparison.EvidenceDigest`` and
#: ``mayhem.domain.certification.BUNDLE_DIGEST_RE``. :func:`is_certified_evidence`
#: matches on it, and no type in this module carries a field of that shape —
#: which is the whole of the "advisor output is not evidence" argument.
SEALED_DIGEST_PATTERN: Final[str] = r"^[0-9a-f]{64}$"

_SEALED_DIGEST_RE: Final[re.Pattern[str]] = re.compile(SEALED_DIGEST_PATTERN)


# -- vocabulary --------------------------------------------------------------------


class CitedFactKind(StrEnum):
    """What sort of fact a citation points at.

    Named rather than free text because a reader tracing a recommendation needs
    to know *which kind* of artefact to go and read, and "some evidence" is not
    an answer.
    """

    COVERAGE_CELL = "coverage_cell"
    TOPOLOGY_NODE = "topology_node"
    TOPOLOGY_SNAPSHOT = "topology_snapshot"
    INCIDENT = "incident"
    FINDING = "finding"
    CRITERION_READING = "criterion_reading"


class RecommendationOrigin(StrEnum):
    """Who wrote the recommendation. Decides authority; nothing else does."""

    AUTHORED = "authored"
    GENERATED = "generated"


class AdvisorAuthority(StrEnum):
    """What a recommendation is allowed to do next."""

    NONE = "none"
    APPROVED = "approved"


#: The cell states that mean *nothing has been established about this failure
#: mode*. Anything else is refused as a gap: ``PASSED`` is coverage,
#: ``FAILED`` is a graded regression (:mod:`mayhem.domain.comparison` owns that
#: vocabulary), and ``EXECUTED`` is a run that has not concluded yet, so calling
#: it a gap would report an in-flight experiment as a resilience hole.
GAP_STATES: Final[frozenset[CellState]] = frozenset(
    {
        CellState.UNKNOWN,
        CellState.PLANNED,
        CellState.BLOCKED,
        CellState.SKIPPED,
        CellState.INCONCLUSIVE,
    }
)


# -- citations --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CitedFact:
    """One fact a finding or recommendation rests on, named for the reader.

    ``ref`` is an identifier the reader can look up (a coverage cell key, a node
    id, a graph digest, a criterion name); ``detail`` is the sentence saying what
    that fact contributes, so the citation is not just a pointer into a database
    nobody was given.
    """

    kind: CitedFactKind
    ref: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind.value, "ref": self.ref, "detail": self.detail}


# -- findings ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CoverageLandscape:
    """The declared set of cells a finding is allowed to cite — and nothing else.

    A :class:`~mayhem.domain.coverage.CoverageCell` is a four-part *value*, so on
    its own one can always be typed, including a cell that exists in no landscape
    at all. That is why a finding carries the landscape it was read against: it is
    what makes "a finding citing a cell that does not exist" a refusal rather than
    a plausible-looking key nobody can look up, and it is the same discipline
    :mod:`mayhem.domain.prediction` applies to a target id the graph does not
    contain.

    The landscape must be non-empty and duplicate-free. A duplicate key means two
    rows claim one cell's state, so which of them the gap was read from would be
    arbitrary.
    """

    landscape_id: str
    cells: tuple[CoverageCell, ...] = ()

    def __post_init__(self) -> None:
        if not self.landscape_id.strip():
            raise InvariantViolationError(
                RULE_LANDSCAPE_UNIDENTIFIED,
                "a coverage landscape must be identified: 'the landscape' is not a "
                "declaration anybody can re-read the gap against",
            )
        if not self.cells:
            raise InvariantViolationError(
                RULE_LANDSCAPE_EMPTY,
                f"coverage landscape {self.landscape_id!r} declares no cells: a finding "
                "cannot cite a cell out of a landscape with nothing in it, and an empty "
                "landscape makes every absence look like a gap",
            )
        keys = [c.key for c in self.cells]
        duplicates = sorted({key for key in keys if keys.count(key) > 1})
        if duplicates:
            raise InvariantViolationError(
                RULE_LANDSCAPE_DUPLICATE_CELL,
                f"coverage landscape {self.landscape_id!r} declares {len(duplicates)} "
                f"cell(s) twice ({duplicates}): two rows claiming one cell's state makes "
                "the state the gap was read from arbitrary",
            )

    @property
    def keys(self) -> frozenset[str]:
        return frozenset(c.key for c in self.cells)

    def __contains__(self, other: object) -> bool:
        return isinstance(other, CoverageCell) and other.key in self.keys

    def to_dict(self) -> dict[str, object]:
        return {"landscape_id": self.landscape_id, "cells": sorted(self.keys)}


@dataclass(frozen=True, slots=True)
class Finding:
    """An uncovered failure mode, pointed at the facts that make it uncovered.

    The required arguments after the prose are the finding: the
    :class:`~mayhem.domain.coverage.CoverageCell` whose state says nothing has
    been established, that state, the :class:`CoverageLandscape` the cell was
    read against, the topology nodes the failure would travel through, and the
    identity of the topology snapshot. None of them has a default, so a finding
    without its facts cannot be constructed — the enforcement is the constructor
    signature, not a validator a caller could satisfy with ``None``.

    ``incident`` is optional and is a *corroborating* fact, not the basis: an
    incident report that names this failure mode makes the gap urgent, and a gap
    with no incident behind it is still a gap.
    """

    finding_id: str
    failure_mode: str
    summary: str
    cell: CoverageCell
    cell_state: CellState
    landscape: CoverageLandscape
    topology_node_ids: tuple[str, ...]
    graph_identity: str
    incident: IncidentFacts | None = None

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise InvariantViolationError(
                RULE_FINDING_UNNAMED,
                "a finding must have an id: an unnamed finding cannot be cited by a "
                "recommendation, tracked to a closure, or told apart from the next one",
            )
        if not self.failure_mode.strip() or not self.summary.strip():
            raise InvariantViolationError(
                RULE_FINDING_UNEXPLAINED,
                f"finding {self.finding_id!r} must state both the failure mode and a "
                "summary: a coverage cell in a gap state is a fact, and only a sentence "
                "says which failure it leaves untested",
            )
        if self.cell.key not in self.landscape.keys:
            raise InvariantViolationError(
                RULE_FINDING_CELL_NOT_IN_LANDSCAPE,
                f"finding {self.finding_id!r} cites cell {self.cell.key!r}, which is not "
                f"in coverage landscape {self.landscape.landscape_id!r}: a cell that "
                "exists in no landscape is not a coverage fact, and a gap read off a cell "
                "nobody has declared is a finding about nowhere",
            )
        if self.cell_state not in GAP_STATES:
            raise InvariantViolationError(
                RULE_FINDING_CELL_IS_NOT_A_GAP,
                f"cell {self.cell.key!r} is {self.cell_state.value!r}, not one of "
                f"{sorted(state.value for state in GAP_STATES)}: a passed cell is "
                "covered, a failed cell is a graded regression (raise it as a "
                "comparison finding, which cites two runs), and an executed cell is a "
                "run that has not concluded — none of them is an uncovered failure mode",
            )
        if not self.topology_node_ids or not self.graph_identity.strip():
            raise InvariantViolationError(
                RULE_FINDING_WITHOUT_TOPOLOGY,
                f"finding {self.finding_id!r} must name the topology nodes the failure "
                "would travel through and the snapshot it was read against: a gap with "
                "no topology is a gap nobody can size, target, or close",
            )
        if any(not node_id.strip() for node_id in self.topology_node_ids):
            raise InvariantViolationError(
                RULE_FINDING_WITHOUT_TOPOLOGY,
                f"finding {self.finding_id!r} carries a blank topology node id: an "
                "unnamed node is not a place the failure would travel through",
            )

    @property
    def cell_key(self) -> str:
        """The coverage cell this finding is about."""
        return self.cell.key

    @property
    def cited_facts(self) -> tuple[CitedFact, ...]:
        """Every fact this finding rests on, in the order a reader should read them."""
        return (
            CitedFact(
                kind=CitedFactKind.COVERAGE_CELL,
                ref=self.cell.key,
                detail=(
                    f"{self.failure_mode} is {self.cell_state.value} on this cell of "
                    f"landscape {self.landscape.landscape_id!r}, which is why the failure "
                    "mode is uncovered"
                ),
            ),
            CitedFact(
                kind=CitedFactKind.TOPOLOGY_SNAPSHOT,
                ref=self.graph_identity,
                detail="topology snapshot the gap was read against",
            ),
            *(
                CitedFact(
                    kind=CitedFactKind.TOPOLOGY_NODE,
                    ref=node_id,
                    detail="node the failure would travel through",
                )
                for node_id in self.topology_node_ids
            ),
            *(
                ()
                if self.incident is None
                else (
                    CitedFact(
                        kind=CitedFactKind.INCIDENT,
                        ref=self.incident.incident_id,
                        detail=(
                            f"{self.incident.failure_signature} observed on "
                            f"{self.incident.service}"
                        ),
                    ),
                )
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "failure_mode": self.failure_mode,
            "summary": self.summary,
            "cell_key": self.cell.key,
            "cell_state": self.cell_state.value,
            "landscape_id": self.landscape.landscape_id,
            "topology_node_ids": list(self.topology_node_ids),
            "graph_identity": self.graph_identity,
            "incident_id": None if self.incident is None else self.incident.incident_id,
            "cited_facts": [fact.to_dict() for fact in self.cited_facts],
        }


# -- incident facts ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ObservedPercentile:
    """One observed percentile of one metric during an incident.

    ``samples`` may be zero on purpose: "we observed a p99 and we observed it
    once" is a fact the domain must be able to *say*, and refusing it would
    leave the alternative being a silently zeroed value that reads like a
    healthy system. :attr:`usable` is what a consumer checks.
    """

    label: str
    metric: str
    value: float
    unit: str = "ms"
    samples: int = 0

    def __post_init__(self) -> None:
        if not self.label.strip() or not self.metric.strip() or not self.unit.strip():
            raise InvariantViolationError(
                RULE_INCIDENT_WITHOUT_IDENTITY,
                "an observed percentile must name its label, metric and unit: "
                "'a number was observed' is not a measurement anybody can reproduce",
            )
        if not isfinite(self.value):
            raise InvariantViolationError(
                RULE_OBSERVED_VALUE_NOT_FINITE,
                f"observed {self.metric} {self.label} is {self.value!r}: nan and inf are "
                "arithmetic accidents, and a captured incident that carries one cannot be "
                "replayed because there is nothing to replay",
            )
        if self.samples < 0:
            raise InvariantViolationError(
                RULE_INCIDENT_DURATION_INVALID,
                f"observed {self.metric} {self.label} claims {self.samples} samples: a "
                "negative count is not a measurement of anything",
            )

    @property
    def usable(self) -> bool:
        """True when this observation can carry a judgement."""
        return self.samples > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "metric": self.metric,
            "value": self.value,
            "unit": self.unit,
            "samples": self.samples,
            "usable": self.usable,
        }


@dataclass(frozen=True, slots=True)
class VersionPin:
    """One component's version at the time of an incident.

    Pinned rather than described, because "on the latest release" is the version
    that has stopped existing by the time anybody reads the incident report.
    """

    component: str
    version: str

    def __post_init__(self) -> None:
        if not self.component.strip() or not self.version.strip():
            raise InvariantViolationError(
                RULE_INCIDENT_WITHOUT_VERSION_PINS,
                f"version pin {self.to_dict()!r} must name both a component and a "
                "version: an incident that cannot say what was running cannot be "
                "reproduced",
            )

    def to_dict(self) -> dict[str, str]:
        return {"component": self.component, "version": self.version}


@dataclass(frozen=True, slots=True)
class IncidentFacts:
    """A normalised incident capture: what broke, where, how badly, and on what.

    "Normalised" means two things and both are load-bearing. The *canonical
    order* is fixed — percentiles by label, versions by component — so two
    captures of the same incident assembled in different orders are the same
    value and compare equal; a diff that fires on key order is a diff nobody
    reads. And the *shape* is fixed: service, failure signature, dependency,
    observed percentiles, timing, version pins, and the topology snapshot the
    incident was observed against. An incident with no observed percentile or no
    version pin is refused rather than stored empty, because a capture missing
    the measurements cannot become a reproducible experiment candidate later
    (plan 21, "incident replay") and storing it empty would defer the refusal to
    the point where somebody is trying to reproduce a failure.

    :attr:`topology_snapshot_id` is the pin that makes replay meaningful: the
    experiment candidate derived from this incident is compiled against *this*
    topology, not against whatever the graph looks like when the replay is
    finally run.
    """

    incident_id: str
    service: str
    failure_signature: str
    dependency: str
    topology_snapshot_id: str
    duration_s: float
    percentiles: tuple[ObservedPercentile, ...]
    versions: tuple[VersionPin, ...]
    started_at: str = ""
    ended_at: str = ""

    def __post_init__(self) -> None:
        for name, value in (
            ("incident_id", self.incident_id),
            ("service", self.service),
            ("failure_signature", self.failure_signature),
            ("dependency", self.dependency),
        ):
            if not value.strip():
                raise InvariantViolationError(
                    RULE_INCIDENT_WITHOUT_IDENTITY,
                    f"incident is missing {name}: an incident that does not name its "
                    "service, its dependency, or the signature it produced cannot be "
                    "matched to a topology or replayed",
                )
        if not self.topology_snapshot_id.strip():
            raise InvariantViolationError(
                RULE_INCIDENT_WITHOUT_TOPOLOGY_PIN,
                f"incident {self.incident_id!r} carries no topology snapshot: replaying "
                "it against a different graph than the one that failed reproduces a "
                "different incident",
            )
        if not self.percentiles:
            raise InvariantViolationError(
                RULE_INCIDENT_WITHOUT_OBSERVATION,
                f"incident {self.incident_id!r} carries no observed percentile: an "
                "incident with no measurement is an anecdote, and converting an anecdote "
                "into an experiment candidate is how an untested belief gets run "
                "against a live system",
            )
        if not self.versions:
            raise InvariantViolationError(
                RULE_INCIDENT_WITHOUT_VERSION_PINS,
                f"incident {self.incident_id!r} pins no component versions: the "
                "candidate derived from it would be replayed against whatever happens "
                "to be deployed, which is the one thing replay exists to avoid",
            )
        if not isfinite(self.duration_s) or self.duration_s < 0.0:
            raise InvariantViolationError(
                RULE_INCIDENT_DURATION_INVALID,
                f"incident {self.incident_id!r} claims a duration of {self.duration_s!r}: "
                "a negative or non-finite duration is not a timing, and a replay whose "
                "stop condition is built on it is a replay that cannot stop",
            )

    @classmethod
    def normalise(
        cls,
        *,
        incident_id: str,
        service: str,
        failure_signature: str,
        dependency: str,
        topology_snapshot_id: str,
        duration_s: float,
        percentiles: Mapping[str, Mapping[str, object]] | None = None,
        versions: Mapping[str, str] | None = None,
        started_at: str = "",
        ended_at: str = "",
    ) -> IncidentFacts:
        """Assemble a capture from loose inputs, canonically ordered.

        ``percentiles`` is keyed by label so a duplicate cannot be expressed at
        all, and each entry supplies ``metric``/``value``/``unit``/``samples``.
        ``versions`` is keyed by component for the same reason. Both are sorted
        here, which is the whole of the canonicalisation: everything else is
        validated by the constructor.
        """
        observed = tuple(
            ObservedPercentile(
                label=label,
                metric=str(entry["metric"]),
                value=_as_float(entry.get("value"), label=label, metric=str(entry["metric"])),
                unit=str(entry.get("unit", "ms")),
                samples=_as_int(entry.get("samples", 0), label=label),
            )
            for label, entry in sorted((percentiles or {}).items())
        )
        pins = tuple(
            VersionPin(component=component, version=str(version))
            for component, version in sorted((versions or {}).items())
        )
        return cls(
            incident_id=incident_id,
            service=service,
            failure_signature=failure_signature,
            dependency=dependency,
            topology_snapshot_id=topology_snapshot_id,
            duration_s=duration_s,
            percentiles=observed,
            versions=pins,
            started_at=started_at,
            ended_at=ended_at,
        )

    def percentile(self, label: str) -> ObservedPercentile | None:
        """The observation for one label, or ``None`` if it was not observed."""
        return next((p for p in self.percentiles if p.label == label), None)

    def version(self, component: str) -> str | None:
        """The pinned version of one component, or ``None`` if it was not pinned."""
        pin = next((v for v in self.versions if v.component == component), None)
        return None if pin is None else pin.version

    def to_dict(self) -> dict[str, object]:
        return {
            "incident_id": self.incident_id,
            "service": self.service,
            "failure_signature": self.failure_signature,
            "dependency": self.dependency,
            "topology_snapshot_id": self.topology_snapshot_id,
            "duration_s": self.duration_s,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "percentiles": [p.to_dict() for p in self.percentiles],
            "versions": [v.to_dict() for v in self.versions],
        }


# -- declared criteria and priority ------------------------------------------------


@dataclass(frozen=True, slots=True)
class CustomerCriterion:
    """One criterion the customer declared, with the weight and the question.

    ``question`` is required to be non-blank. A weighting knob that does not say
    which customer question it answers is exactly the opaque ranking plan 21
    forbids: "customer_impact" with no stated question could mean revenue, or
    could mean the on-call pager, and the two order a resilience backlog
    differently.
    """

    name: str
    weight: float
    question: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise InvariantViolationError(
                RULE_CRITERION_NOT_DECLARED,
                "a declared criterion must have a name: an unnamed weighting knob "
                "cannot be cited by the rationale that used it",
            )
        if not isfinite(self.weight) or self.weight < 0.0:
            raise InvariantViolationError(
                RULE_CRITERIA_HAVE_NO_WEIGHT,
                f"criterion {self.name!r} carries weight {self.weight!r}: weights must be "
                "finite and non-negative, and nan/inf is how a declared criterion turns "
                "into an unbounded one",
            )
        if not self.question.strip():
            raise InvariantViolationError(
                RULE_CRITERION_WITHOUT_QUESTION,
                f"criterion {self.name!r} does not state the customer question it "
                "answers: a weight nobody can restate as a question is an opaque "
                "ranking, which is the thing the declared criteria exist to prevent",
            )

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "weight": self.weight, "question": self.question}


@dataclass(frozen=True, slots=True)
class PriorityCriteria:
    """A named declaration of the criteria a priority is computed against.

    ``criteria`` is a required, non-empty, duplicate-free tuple with a positive
    total weight. Those three refusals are the statement that priority is a pure
    function of *declared* weights: no criteria means there is no function, one
    criterion twice means the weighting is ambiguous, and a zero total weight
    means the weighted mean has no denominator.
    """

    name: str
    criteria: tuple[CustomerCriterion, ...]

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise InvariantViolationError(
                RULE_NO_DECLARED_CRITERIA,
                "a criteria declaration must be named: 'the priority' is not a "
                "declaration anybody can review or change",
            )
        if not self.criteria:
            raise InvariantViolationError(
                RULE_NO_DECLARED_CRITERIA,
                f"criteria declaration {self.name!r} is empty: a priority computed "
                "against no declared criteria is not a low priority, it is a ranking "
                "with no basis, and every candidate would tie at the top of it",
            )
        names = [criterion.name for criterion in self.criteria]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise InvariantViolationError(
                RULE_DUPLICATE_CRITERION,
                f"criteria declaration {self.name!r} declares {duplicates} twice: a "
                "criterion declared twice is weighted twice by arithmetic and read once "
                "by a human, which is how a weighting stops meaning what it says",
            )
        if sum(criterion.weight for criterion in self.criteria) <= 0.0:
            raise InvariantViolationError(
                RULE_CRITERIA_HAVE_NO_WEIGHT,
                f"criteria declaration {self.name!r} has zero total weight: the weighted "
                "mean it feeds has no denominator, and dividing by it would make the "
                "priority read as a number rather than as nothing",
            )

    @property
    def names(self) -> tuple[str, ...]:
        """The declared criterion names, in declaration order."""
        return tuple(criterion.name for criterion in self.criteria)

    @property
    def total_weight(self) -> float:
        return sum(criterion.weight for criterion in self.criteria)

    def criterion(self, name: str) -> CustomerCriterion | None:
        """The declared criterion with this name, or ``None``."""
        return next((c for c in self.criteria if c.name == name), None)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "criteria": [criterion.to_dict() for criterion in self.criteria],
            "total_weight": self.total_weight,
        }


@dataclass(frozen=True, slots=True)
class CriterionReading:
    """One declared criterion, the value read from a cited fact, and that fact.

    The value is a normalised ``[0, 1]`` reading, not a raw measurement: two
    criteria in different units cannot be added, and normalising them here is
    what lets the weighted mean mean something. ``evidence`` is required, and it
    is the sentence that makes the reading checkable — a reading of ``0.9`` on
    "customer impact" with no fact behind it is the opaque ranking with an extra
    step.
    """

    criterion: CustomerCriterion
    value: float
    evidence: str

    def __post_init__(self) -> None:
        if not isfinite(self.value) or not 0.0 <= self.value <= 1.0:
            raise InvariantViolationError(
                RULE_CRITERION_VALUE_OUT_OF_RANGE,
                f"reading {self.value!r} for criterion {self.criterion.name!r} is outside "
                "[0, 1]: a normalised reading that is nan, infinite, or past the unit "
                "interval cannot be weighted against anything",
            )
        if not self.evidence.strip():
            raise InvariantViolationError(
                RULE_CRITERION_WITHOUT_EVIDENCE,
                f"reading for criterion {self.criterion.name!r} cites no evidence: a "
                "score that does not say which fact produced it is the one thing an "
                "opaque ranking is made of",
            )

    @property
    def contribution(self) -> float:
        """``weight x value`` — this reading's share of the weighted sum."""
        return self.criterion.weight * self.value

    def to_dict(self) -> dict[str, object]:
        return {
            "criterion": self.criterion.to_dict(),
            "value": self.value,
            "evidence": self.evidence,
            "contribution": self.contribution,
        }


@dataclass(frozen=True, slots=True)
class Priority:
    """A score that is a pure function of the declared weights — stored nowhere.

    There is deliberately no ``total`` field: :attr:`total` is computed from the
    readings on every access, so a caller cannot construct a priority, inject a
    score, or carry a number across a change of weights. The same
    :class:`CriterionReading` tuple against a different declared weight yields a
    different total, which is what "a pure function of declared weights" means
    and what a stored score could not demonstrate.

    Every declared criterion has exactly one reading here. A criterion the
    author could quietly drop is a criterion they could always lose points on,
    so the invariant is enforced rather than documented.
    """

    criteria_name: str
    readings: tuple[CriterionReading, ...]

    def __post_init__(self) -> None:
        if not self.criteria_name.strip():
            raise InvariantViolationError(
                RULE_NO_DECLARED_CRITERIA,
                "a priority must name the criteria declaration it was computed "
                "against: a score without a declaration behind it is an opaque ranking",
            )
        if not self.readings:
            raise InvariantViolationError(
                RULE_NO_DECLARED_CRITERIA,
                f"priority against {self.criteria_name!r} carries no readings: with no "
                "declared criterion there is nothing to weigh, and reporting a rank "
                "anyway is how every candidate ends up tied for first",
            )
        names = [reading.criterion.name for reading in self.readings]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise InvariantViolationError(
                RULE_DUPLICATE_CRITERION,
                f"priority against {self.criteria_name!r} weighs {duplicates} more than "
                "once: arithmetic would count the duplicate twice, so the number would "
                "not be the weighting anybody declared",
            )
        if sum(reading.criterion.weight for reading in self.readings) <= 0.0:
            raise InvariantViolationError(
                RULE_CRITERIA_HAVE_NO_WEIGHT,
                f"priority against {self.criteria_name!r} has zero total weight: the "
                "weighted mean has no denominator, and a priority of zero would read as "
                "'nobody cares' when the truth is 'nothing was declared'",
            )

    @classmethod
    def from_readings(
        cls,
        criteria: PriorityCriteria,
        readings: Mapping[str, CriterionReading],
    ) -> Priority:
        """Weigh a complete set of readings against a declaration.

        Refuses a reading for a criterion nobody declared (a weight invented at
        the last moment) and a declared criterion with no reading at all (a
        criterion quietly dropped because it scored badly). Both are the
        arithmetic an opaque ranking needs and cannot survive.
        """
        declared = set(criteria.names)
        undeclared = sorted(set(readings) - declared)
        if undeclared:
            raise InvariantViolationError(
                RULE_CRITERION_NOT_DECLARED,
                f"readings supplied for {undeclared}, which criteria declaration "
                f"{criteria.name!r} does not declare: a weight that was not declared "
                "cannot be weighed, because nobody agreed to it",
            )
        unread = sorted(declared - set(readings))
        if unread:
            raise InvariantViolationError(
                RULE_CRITERION_NOT_READ,
                f"criteria declaration {criteria.name!r} declares {unread} with no "
                "reading: a criterion the author can drop is a criterion they can always "
                "lose points on, so the priority would not be the declared weighting",
            )
        return cls(
            criteria_name=criteria.name,
            readings=tuple(
                readings[name]
                for name in criteria.names
                if name in readings  # narrowed by the completeness check above
            ),
        )

    @property
    def weighted_sum(self) -> float:
        """``sum(weight x value)`` across the readings."""
        return sum(reading.contribution for reading in self.readings)

    @property
    def total_weight(self) -> float:
        return sum(reading.criterion.weight for reading in self.readings)

    @property
    def total(self) -> float:
        """The weighted mean — the only number a priority produces, and it is derived."""
        return self.weighted_sum / self.total_weight

    @property
    def criteria_names(self) -> tuple[str, ...]:
        return tuple(reading.criterion.name for reading in self.readings)

    def reading(self, name: str) -> CriterionReading | None:
        return next((r for r in self.readings if r.criterion.name == name), None)

    @property
    def rationale(self) -> str:
        """The arithmetic, in words: every criterion, its weight, and its fact.

        Generated rather than supplied, which is why it can never omit a
        criterion — the criterion list *is* the text.
        """
        parts = ", ".join(
            f"{reading.criterion.name} {reading.value:.2f} x {reading.criterion.weight:g} "
            f"({reading.evidence})"
            for reading in self.readings
        )
        return (
            f"weighted {self.total:.3f} against {len(self.readings)} declared "
            f"{'criterion' if len(self.readings) == 1 else 'criteria'} of "
            f"{self.criteria_name!r}: {parts}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "criteria_name": self.criteria_name,
            "criteria": list(self.criteria_names),
            "total": self.total,
            "weighted_sum": self.weighted_sum,
            "total_weight": self.total_weight,
            "rationale": self.rationale,
            "readings": [reading.to_dict() for reading in self.readings],
        }


# -- candidates, recommendations, and the AI boundary ------------------------------


@dataclass(frozen=True, slots=True)
class ExperimentCandidate:
    """A proposed experiment: an id, a hypothesis, and the probes to try.

    ``suggested_probes`` and ``stop_conditions`` are what plan 15 calls "suggested
    probes" and what plan 11 makes binding downstream — a candidate that names
    a probe with no stop condition is a suggestion to break something with no
    rule about when to stop, so both are carried together and neither is
    authority.

    ``impact_prediction_digest`` is a *citation* of
    :class:`mayhem.domain.prediction.ImpactPrediction`, never a re-derivation.
    Likely affected dependencies are that module's job; recomputing a weaker
    version of the gate's own arithmetic here would be the one change most likely
    to drift from the gate that actually refuses.
    """

    experiment_id: str
    hypothesis: str
    suggested_probes: tuple[str, ...] = ()
    stop_conditions: tuple[str, ...] = ()
    impact_prediction_digest: str = ""

    def __post_init__(self) -> None:
        if not self.experiment_id.strip() or not self.hypothesis.strip():
            raise InvariantViolationError(
                RULE_CANDIDATE_INCOMPLETE,
                "a candidate experiment needs both an id and a hypothesis: an id with no "
                "hypothesis is a fault to run, and a hypothesis with no id is a belief "
                "nobody can re-run or refute",
            )
        if self.impact_prediction_digest and not _is_sealed_digest(self.impact_prediction_digest):
            raise InvariantViolationError(
                RULE_PREDICTION_DIGEST_INVALID,
                f"impact prediction digest {self.impact_prediction_digest!r} is not a "
                "sealed sha256 digest: a citation that is not verifiable is a claim in a "
                "field that looks like a citation",
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "experiment_id": self.experiment_id,
            "hypothesis": self.hypothesis,
            "suggested_probes": list(self.suggested_probes),
            "stop_conditions": list(self.stop_conditions),
            "impact_prediction_digest": self.impact_prediction_digest,
        }


class Approval(BaseModel):
    """A human approval bound to one exact recommendation by digest.

    Binding by digest rather than by identity is what makes the binding
    meaningful: change the finding, the candidate, the weights, or the rationale
    after approval and the digest no longer matches, so the approval cannot
    travel across a change nobody re-read. ``approved_by`` must be non-blank for
    the same reason :class:`mayhem.domain.search.Approval` requires it — an
    unattributed decision is not a decision anybody made.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    approved_by: str
    recommendation_digest: str

    @field_validator("approved_by")
    @classmethod
    def _named_approver(cls, value: str) -> str:
        if not value.strip():
            raise InvariantViolationError(
                RULE_APPROVAL_WITHOUT_AN_APPROVER,
                "an approval must name who gave it: an unnamed approver is how an "
                "unattributed decision acquires authority",
            )
        return value

    @field_validator("recommendation_digest")
    @classmethod
    def _sealed_digest(cls, value: str) -> str:
        if not _is_sealed_digest(value):
            raise InvariantViolationError(
                RULE_APPROVAL_MISMATCH,
                f"approval names {value!r}, which is not a sealed sha256 digest: an "
                "approval that cannot be matched to a recommendation is a signature on "
                "a blank page",
            )
        return value

    def to_dict(self) -> dict[str, str]:
        return {"approved_by": self.approved_by}


@dataclass(frozen=True, slots=True)
class Recommendation:
    """A candidate experiment, its finding, and a priority that names its basis.

    One type, two origins, and the origin alone decides authority — the same
    discipline as :class:`mayhem.domain.search.SearchPlan`. A ``generated``
    recommendation cannot be *constructed* with an approval, and an approval
    whose digest does not match this recommendation is refused, so an approval
    binds to the recommendation a human actually read rather than to whatever
    happens to sit in the object later.

    ``rationale`` is prose and is allowed to be the AI's, which is why it is not
    trusted to be checkable by itself: :meth:`render_refusal_reason` requires it
    to mention every declared criterion the priority was computed against.
    """

    recommendation_id: str
    finding: Finding
    candidate: ExperimentCandidate
    priority: Priority
    rationale: str
    origin: RecommendationOrigin = RecommendationOrigin.AUTHORED
    approval: Approval | None = None

    def __post_init__(self) -> None:
        if not self.recommendation_id.strip():
            raise InvariantViolationError(
                RULE_RECOMMENDATION_UNNAMED,
                "a recommendation must have an id: an unnamed recommendation cannot be "
                "approved by digest, ranked, or closed",
            )
        if not self.rationale.strip():
            raise InvariantViolationError(
                RULE_RECOMMENDATION_RATIONALE_NOT_TRACEABLE,
                f"recommendation {self.recommendation_id!r} has no rationale: a priority "
                "number tells a reader where something sits in a list and not why it "
                "should be looked at",
            )
        if self.approval is None:
            return
        if self.origin is not RecommendationOrigin.AUTHORED:
            raise InvariantViolationError(
                RULE_GENERATED_CANNOT_BE_APPROVED,
                "a generated candidate cannot carry an approval: an AI-drafted "
                "recommendation reaches exactly as far through compilation, policy and "
                "impact as an authored one would, and it cannot supply its own. It must "
                "be reviewed as one",
            )
        if self.approval.recommendation_digest != self.recommendation_digest:
            raise InvariantViolationError(
                RULE_APPROVAL_MISMATCH,
                f"approval names digest {self.approval.recommendation_digest[:12]}… but "
                f"this recommendation hashes to {self.recommendation_digest[:12]}…: an "
                "approval binds to the recommendation that was read, not to the one that "
                "happens to sit here now",
            )

    @property
    def total(self) -> float:
        """The derived priority score. Never a stored field — see :class:`Priority`."""
        return self.priority.total

    @property
    def authority(self) -> AdvisorAuthority:
        return AdvisorAuthority.NONE if self.approval is None else AdvisorAuthority.APPROVED

    @property
    def recommendation_digest(self) -> str:
        """The digest an approval must name to bind to this recommendation.

        Deliberately excludes :attr:`approval` itself, so an approval can be
        computed over a recommendation it is then attached to.
        """
        return digest(
            {
                "recommendation_id": self.recommendation_id,
                "origin": self.origin.value,
                "rationale": self.rationale,
                "finding": self.finding.to_dict(),
                "candidate": self.candidate.to_dict(),
                "priority": self.priority.to_dict(),
            }
        )

    @property
    def cited_facts(self) -> tuple[CitedFact, ...]:
        """Every fact this recommendation rests on, findings and weights included."""
        return (
            CitedFact(
                kind=CitedFactKind.FINDING,
                ref=self.finding.finding_id,
                detail=self.finding.summary,
            ),
            *self.finding.cited_facts,
            *(
                CitedFact(
                    kind=CitedFactKind.CRITERION_READING,
                    ref=reading.criterion.name,
                    detail=(
                        f"{reading.value:.2f} x {reading.criterion.weight:g} from "
                        f"{reading.evidence}"
                    ),
                )
                for reading in self.priority.readings
            ),
        )

    def render_refusal_reason(self) -> str:
        """Why this recommendation may not be rendered for a reader, or ``""`` if it may.

        Named reasons, never a bare ``False``: a view that silently drops an
        untraceable recommendation has turned a governance rule into a rendering
        preference.

        :meth:`to_dict` is the lossless serialisation and is deliberately *not*
        gated — it exists so a recommendation can be stored and re-read. Every
        reader-facing view goes through this or :meth:`render`.
        """
        if not self.rationale.strip():
            return (
                f"recommendation {self.recommendation_id!r} has no rationale, so there "
                "is nothing for a reader to check"
            )
        missing = tuple(
            name for name in self.priority.criteria_names if name not in self.rationale
        )
        if missing:
            return (
                f"recommendation {self.recommendation_id!r} is weighted against "
                f"{self.priority.criteria_name!r} but its rationale never mentions "
                f"{list(missing)}: a rationale that omits a declared criterion cannot be "
                "checked against the weighting that ordered it"
            )
        return ""

    def render(self) -> str:
        """The reader-facing view: the recommendation, its arithmetic, its citations.

        Refuses rather than degrades. A recommendation whose rationale does not
        name the criteria it was ranked by is not shown in a shortened form
        either — a partial render is how an untraceable recommendation reaches a
        screen anyway.
        """
        reason = self.render_refusal_reason()
        if reason:
            raise InvariantViolationError(RULE_RECOMMENDATION_RATIONALE_NOT_TRACEABLE, reason)
        lines = [
            f"{self.recommendation_id} ({self.candidate.experiment_id})",
            f"  origin: {self.origin.value}   authority: {self.authority.value}",
            f"  hypothesis: {self.candidate.hypothesis}",
            f"  priority: {self.priority.rationale}",
            f"  rationale: {self.rationale}",
        ]
        if self.candidate.suggested_probes:
            lines.append(f"  suggested probes: {list(self.candidate.suggested_probes)}")
        if self.candidate.stop_conditions:
            lines.append(f"  suggested stop conditions: {list(self.candidate.stop_conditions)}")
        lines.append("  cites:")
        lines.extend(
            f"    - {fact.kind.value}: {fact.ref} — {fact.detail}"
            for fact in self.cited_facts
        )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "recommendation_id": self.recommendation_id,
            "origin": self.origin.value,
            "authority": self.authority.value,
            "recommendation_digest": self.recommendation_digest,
            "approval": None
            if self.approval is None
            else {"approved_by": self.approval.approved_by},
            "rationale": self.rationale,
            "finding": self.finding.to_dict(),
            "candidate": self.candidate.to_dict(),
            "priority": self.priority.to_dict(),
            "cited_facts": [fact.to_dict() for fact in self.cited_facts],
        }


class UntrustedRecommendationDraft(BaseModel):
    """An advisor-generated candidate: the same body, with nowhere to put a token.

    The four things plan 21 lets AI do are the four things this type has fields
    for — summarise (``rationale``), generate a candidate plan
    (:class:`ExperimentCandidate`), explain evidence (the :class:`Finding` it
    cites, whose :attr:`Finding.cited_facts` are the explanation), and suggest
    probes (:attr:`ExperimentCandidate.suggested_probes`).

    What it does **not** have is the important part:

    * no ``approval`` field — not one defaulted to ``None``, no field at all — so
      a generated candidate cannot be *composed* into an approved
      recommendation. It is frozen too, so nothing can be attached afterwards.
    * no weight, criteria, or priority field. The weighting is *declared* by the
      customer, and :meth:`compile` takes it as an argument, so a draft cannot
      supply — or quietly renegotiate — its own ranking.
    * no execution, dispatch, or intent field of any kind. The draft compiles
      into a :class:`Recommendation`, which travels the same compilation, policy,
      impact, and approval gates an authored recommendation does (plans 15/16),
      and which refuses to carry an approval on a ``generated`` origin.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    recommendation_id: str
    finding: Finding
    candidate: ExperimentCandidate
    rationale: str = ""

    @field_validator("rationale")
    @classmethod
    def _draft_says_something(cls, value: str) -> str:
        if not value.strip():
            raise InvariantViolationError(
                RULE_RECOMMENDATION_RATIONALE_NOT_TRACEABLE,
                "a draft must carry a rationale: a candidate nobody can read the reason "
                "for is a proposal, and a proposal that reaches a human inbox is an "
                "unreviewed plan",
            )
        return value

    def compile(
        self,
        criteria: PriorityCriteria,
        readings: Mapping[str, CriterionReading],
    ) -> Recommendation:
        """The draft as a recommendation — same type as an authored one, zero authority.

        ``criteria`` and ``readings`` are required arguments with no defaults, so
        a draft cannot be compiled into a ranked recommendation by anyone who has
        not been handed the declared weighting and a reading for every declared
        criterion. ``readings`` is keyed by criterion name — this is one draft's
        weighing, not the whole landscape's, so :func:`rank_drafts` selects the
        finding's map before calling. The returned recommendation is always
        ``generated`` and always unapproved: :class:`Recommendation` refuses both
        otherwise.
        """
        priority = Priority.from_readings(criteria, readings)
        return Recommendation(
            recommendation_id=self.recommendation_id,
            finding=self.finding,
            candidate=self.candidate,
            priority=priority,
            # The draft explains; the declared criteria weigh. Both are in the
            # rationale, which is what lets :meth:`Recommendation.render` show it.
            rationale=f"{self.rationale} (priority: {priority.rationale})",
            origin=RecommendationOrigin.GENERATED,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "recommendation_id": self.recommendation_id,
            "rationale": self.rationale,
            "finding": self.finding.to_dict(),
            "candidate": self.candidate.to_dict(),
            "cited_facts": [fact.to_dict() for fact in self.finding.cited_facts],
        }


# -- the two pure functions the plan's traceability acceptance needs --------------


def _require_readings_match_findings(
    finding_ids: Sequence[str],
    readings: Mapping[str, Mapping[str, CriterionReading]],
) -> None:
    """Refuse a reading set that is not exactly one reading-map per finding.

    Two refusals, both about a finding silently losing its place. A finding with
    no readings is a gap the advisor cannot weigh, and *not* producing a
    recommendation for it would be a silent drop — so it is refused. A reading
    map whose finding is not present is a stale or misspelled key, and dropping
    it would hide a wiring bug behind a shorter list.
    """
    present = set(finding_ids)
    unread = sorted(present - set(readings))
    if unread:
        raise InvariantViolationError(
            RULE_FINDING_NOT_READ,
            f"finding(s) {unread} carry no criterion readings: a finding the advisor "
            "cannot weigh against the declared criteria is either not ready to be "
            "recommended or is being dropped without saying so, and both readings of "
            "that are wrong",
        )
    orphan = sorted(set(readings) - present)
    if orphan:
        raise InvariantViolationError(
            RULE_READING_FOR_UNKNOWN_FINDING,
            f"criterion readings supplied for {orphan}, which are not findings in this "
            "call: a reading whose finding is gone is either a stale key or evidence "
            "about a gap that no longer exists",
        )


def recommendations_for(
    findings: Sequence[Finding],
    criteria: PriorityCriteria,
    readings: Mapping[str, Mapping[str, CriterionReading]],
    *,
    propose: Callable[[Finding], ExperimentCandidate],
) -> tuple[UntrustedRecommendationDraft, ...]:
    """Draft one candidate experiment per finding. Pure, and drafts only.

    This is the machine path, and it can only return
    :class:`UntrustedRecommendationDraft` — so nothing that comes out of an
    analysis (human-run or AI-run) can acquire authority by being generated. The
    weighting is not computed here either: it is supplied as ``readings`` against
    the ``criteria`` the customer declared, which is what keeps priority a pure
    function of declared weights rather than a by-product of the analysis.

    ``propose`` is an injected, side-effect-free function of one finding, so the
    same findings and readings always yield the same drafts. Returns drafts in
    ``finding_id`` order; ranking happens in :func:`rank_drafts`, once the
    declared weighting has been applied.
    """
    _require_readings_match_findings([f.finding_id for f in findings], readings)
    ordered = sorted(findings, key=lambda f: f.finding_id)
    # Weight every criterion against every finding before proposing anything, so
    # a finding that cannot be weighed is refused here rather than at compile
    # time in a later phase — and so a proposal is never generated for work that
    # was going to be rejected anyway.
    for f in ordered:
        Priority.from_readings(criteria, readings[f.finding_id])
    drafts = []
    for f in ordered:
        candidate = propose(f)
        drafts.append(
            UntrustedRecommendationDraft(
                recommendation_id=f"rec:{f.finding_id}",
                finding=f,
                candidate=candidate,
                rationale=candidate.hypothesis,
            )
        )
    return tuple(drafts)


def rank_drafts(
    drafts: Sequence[UntrustedRecommendationDraft],
    criteria: PriorityCriteria,
    readings: Mapping[str, Mapping[str, CriterionReading]],
) -> tuple[Recommendation, ...]:
    """Compile drafts into recommendations and order them by declared priority.

    Every compiled recommendation is ``generated`` and unapproved — that is not
    a policy decision made here, it is the only thing
    :meth:`UntrustedRecommendationDraft.compile` can produce. The ordering is
    ``(-total, recommendation_id)``: descending by the weighted mean, ties broken
    by id, so a tie never renders as "whoever the sort happened to put first" and
    the same inputs always produce the same list.
    """
    _require_readings_match_findings(
        [draft.finding.finding_id for draft in drafts], readings
    )
    compiled = [
        draft.compile(criteria, readings[draft.finding.finding_id]) for draft in drafts
    ]
    return tuple(sorted(compiled, key=lambda r: (-r.total, r.recommendation_id)))


def _as_float(value: object, *, label: str, metric: str) -> float:
    """A number out of a loose capture, or a refusal.

    ``normalise`` is the one boundary in this module that takes untyped input, so
    it is where a string that merely looks like a number gets refused. Coercing
    it instead would produce an incident capture whose reported latency nobody
    can go back and check.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvariantViolationError(
            RULE_OBSERVED_VALUE_NOT_FINITE,
            f"observed {metric} {label} is {value!r}, which is not a number: an incident "
            "capture is normalised, not guessed at",
        )
    return float(value)


def _as_int(value: object, *, label: str) -> int:
    """A sample count out of a loose capture, or a refusal."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvariantViolationError(
            RULE_INCIDENT_DURATION_INVALID,
            f"observed {label} claims {value!r} samples, which is not a count: a "
            "capture that cannot say how much stood behind an observation cannot be "
            "replayed",
        )
    return value


def _is_sealed_digest(value: str) -> bool:
    """True when ``value`` has the shape of a sealed sha256 evidence digest."""
    return _SEALED_DIGEST_RE.match(value) is not None


def is_certified_evidence(claim: object) -> bool:
    """True only for a value carrying the sealed evidence digest a verifier accepts.

    The shape checked is the same sha256 digest
    :mod:`mayhem.domain.comparison` and :mod:`mayhem.domain.certification` treat
    as the mark of sealed evidence. No type in this module has a field of that
    shape — not a :class:`Finding`, not a :class:`Recommendation`, not an
    :class:`UntrustedRecommendationDraft` — so a verifier that asks this question
    rejects advisor output by construction rather than by policy text.

    A recommendation that cites five sealed facts is still five facts
    *correlated*: correlation is not a run, has no verdict, and can never be
    sealed.
    """
    sealed = getattr(claim, "evidence_digest", None)
    return isinstance(sealed, str) and _is_sealed_digest(sealed)
