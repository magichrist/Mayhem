"""CI/CD and change-link vocabulary: the words a pipeline decision is made of
(docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md, Phase 1).

Phase 1 is vocabulary and pure predicates. Nothing here dispatches a check,
posts a commit status, talks to a forge, evaluates a policy, or reads a clock
implicitly — it defines the words the engine (Phase 2) and the surfaces
(Phase 3) will use, and the rules that make a decision unrepresentable unless
it is honest.

Three types carry the contract, and each one closes a way a pipeline decision
can be forged:

* :class:`PipelineVerdict` — pass/fail for one pipeline, carrying the change it
  is about, the checks it rests on, the run it cites, and its evidence
  references. ``evidence_refs`` is **required and non-empty**, so a verdict with
  no evidence link is not a value that can be built; a ``PASS`` is additionally
  refused over any check that did not pass, so "one check failed and the
  pipeline is green" cannot be constructed either. The verdict is not trusted:
  :func:`gates_release` recomputes whether it may open a release from the
  checks, the pins, and the plan the merge actually landed, and names every
  reason it may not.
* :class:`ChangeLink` — the link from a pipeline decision back to the change
  system: change ticket, incident id, deployment id, the git SHA, and the
  plan/policy/catalog/agent/runtime version pins in :class:`PipelinePins`. A
  link that names no ticket, no incident, and no deployment is refused: a change
  nobody filed is not a change that can be attributed. The pins are a *separate*
  type and are deliberately allowed to be blank, because a link is recorded
  before the run happens — but :attr:`PipelinePins.complete` is what
  :func:`gates_release` reads, so an unpinned run cannot back a release
  decision. That is the whole point of separating them: making the pins
  un-constructible would also make the *refusal* untestable, and a rule nobody
  can exercise is a rule nobody should rely on.
* :class:`PRCheck` — one check: name, scope, outcome, coverage delta against
  :class:`mayhem.domain.coverage.CoverageCell`, and a structured
  :class:`CheckFinding` when it fails. The fail-closed rule is here: a check
  that could not reach the control plane (:data:`ControlPlaneReach.UNREACHABLE`)
  is refused at construction with any outcome other than
  :data:`CheckOutcome.UNKNOWN`, and a ``PASS`` is refused without evidence
  refs. ``UNKNOWN`` is a real outcome, and it is not a soft pass — it blocks,
  because a check that could not ask the question has not answered it.

Comparability is a pure predicate over pins, delegated rather than
re-derived: :func:`comparable_across_release` is
:func:`mayhem.domain.comparison.equivalent_pins`, the same rule plan 22 landed,
including its deliberate exclusion of the release axis. Re-deriving it here
would be a second answer to "are these two runs comparable" and the two would
drift.

Invalidation on plan change (:class:`PlanApproval`, :class:`PlanMerge`) is the
negative control from Phase 5, made a type: approvals are bound to the digest of
the plan that was checked, so a merge that lands a *different* plan invalidates
all of them — not just the ones whose digest happens to match, because an
approval given against a plan nobody ran is an approval of a different thing.

.. note::
   Nothing reads any of this yet. Phase 2 is the engine that evaluates checks
   and decides release gates, and Phase 3 is the surface that renders them;
   until one of those calls it, this module is vocabulary with no call site.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Final, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from mayhem.domain.common import utc_now
from mayhem.domain.comparison import RunPin, equivalent_pins
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.decisions import DecisionRef
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import canonical_json, sha256_hex

__all__ = [
    "CONTROL_PLANE_UNREACHABLE",
    "PIPELINE_SCHEMA_VERSION",
    "REQUIRED_PINS",
    "ChangeLink",
    "CheckFinding",
    "CheckOutcome",
    "CheckScope",
    "ControlPlaneReach",
    "CoverageDelta",
    "FindingSeverity",
    "PRCheck",
    "PipelineOutcome",
    "PipelinePins",
    "PipelineVerdict",
    "PlanApproval",
    "PlanDigest",
    "PlanMerge",
    "blocking_reasons",
    "comparable_across_release",
    "gates_release",
]

PIPELINE_SCHEMA_VERSION: Final[str] = "1.0"

#: The version axes a run must pin before it can back a release-gate decision.
#: Same five axes, in the same order, as the tail of
#: :data:`mayhem.domain.comparison.EQUIVALENCE_FIELDS` — a pipeline decision is a
#: comparison decision, and the two must not be able to disagree about which
#: axes matter.
REQUIRED_PINS: Final[tuple[str, ...]] = (
    "plan_version",
    "policy_version",
    "catalog_version",
    "agent_version",
    "runtime_version",
)

#: SHA-256 hex, the shape :data:`mayhem.domain.fabric.PlanDigest` and
#: :data:`mayhem.domain.comparison.EvidenceDigest` already use. Written out
#: again here so a plan digest means one thing in every module that pins a plan,
#: without pipeline.py importing a module that pins command frames.
PlanDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

#: A git object name: 7 hex characters is the shortest GitHub will resolve, 40
#: is a full sha1. Anything else is a ref name or a typo, and neither is a
#: commit a reviewer can look at.
_GIT_SHA_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{7,40}$")

#: The one sentence every unreachable-check refusal has to be able to make.
CONTROL_PLANE_UNREACHABLE: Final[str] = (
    "the control plane was unreachable, so no outcome was established: a check "
    "that could not ask the question reports unknown, never pass"
)


class CheckScope(StrEnum):
    """What a check actually checked.

    A closed vocabulary, no ``OTHER`` member: a check whose scope cannot be
    named is a check nobody can tell whether to gate on, and a scope that can be
    spelled at a call site will eventually be spelled as free text.
    """

    SYNTAX = "syntax"
    TARGET = "target"
    SAFETY_POLICY = "safety_policy"
    BLAST_RADIUS = "blast_radius"
    DAMAGE_BUDGET = "damage_budget"
    FAULT_COMPATIBILITY = "fault_compatibility"
    COVERAGE = "coverage"
    RESILIENCE = "resilience"


class CheckOutcome(StrEnum):
    """What one check concluded.

    ``UNKNOWN`` is the fail-closed third state, not an absence: it means the
    check did not establish an answer, and it blocks exactly as a failure
    blocks. A pipeline that renders unknown as a warning is a pipeline that
    renders "the API was down" as "everything is fine".
    """

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class ControlPlaneReach(StrEnum):
    """Whether the check got to ask the control plane anything at all."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"


class FindingSeverity(StrEnum):
    """How much a finding costs the pipeline.

    A ``WARNING`` finding is admissible on a passing check — that is how the
    coverage gaps of Phase 3 ("checkout has no experiment covering PostgreSQL
    failure") get reported without failing a PR over a known gap. An ``ERROR``
    finding is not: it is admissible only on a failing check.
    """

    WARNING = "warning"
    ERROR = "error"


class PipelineOutcome(StrEnum):
    """The pipeline's answer. Two members, both load-bearing.

    There is no ``UNKNOWN`` pipeline outcome, and that is deliberate. A pipeline
    that could not establish its answer is not a third answer — it is a failed
    gate, and :func:`gates_release` names the check that would not conclude.
    Collapsing it here would make "we don't know" a place a caller could go
    looking for a pass.
    """

    PASS = "pass"
    FAIL = "fail"


def _require_nonblank(value: str, rule: str, subject: str) -> str:
    """Non-empty, non-whitespace text or a typed refusal."""
    if not value or not value.strip():
        raise InvariantViolationError(rule, f"{subject} must not be blank")
    return value


def _require_aware(value: datetime | None, rule: str, subject: str) -> datetime | None:
    """Timezone-aware datetime or a typed refusal (DTZ discipline)."""
    if value is None:
        return None
    if value.tzinfo is None:
        raise InvariantViolationError(rule, f"{subject} must be timezone-aware, not naive")
    return value


def _check_refs(refs: tuple[str, ...], subject: str) -> tuple[str, ...]:
    """Strip, refuse blanks and repeats, and return the cleaned references."""
    cleaned = [ref.strip() for ref in refs]
    if any(not ref for ref in cleaned):
        raise InvariantViolationError("pipeline_blank_evidence_ref", f"{subject} has a blank ref")
    if len(set(cleaned)) != len(cleaned):
        raise InvariantViolationError("pipeline_duplicate_evidence_ref", f"{subject} repeats a ref")
    return tuple(cleaned)


class PipelinePins(BaseModel):
    """The version pins a pipeline decision is attributable to.

    Every axis may be blank — a :class:`ChangeLink` is written when the change
    is filed, long before a run pins a plan version — but a blank axis is only
    ever *reportable*, never gateable: :attr:`complete` is the predicate
    :func:`gates_release` requires, and :attr:`missing` is what the refusal
    names. The axes are the same five, in the same order, that
    :class:`mayhem.domain.comparison.RunPin` requires outright, so a pin that
    passes this check cannot fail plan 22's.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_version: str = ""
    policy_version: str = ""
    catalog_version: str = ""
    agent_version: str = ""
    runtime_version: str = ""

    def axis(self, name: str) -> str:
        """One pinned value by axis name; ``""`` when unpinned or unknown."""
        if name not in REQUIRED_PINS:
            raise InvariantViolationError(
                "pipeline.unknown_pin_axis",
                f"{name!r} is not a pipeline pin axis: the axes are "
                + ", ".join(REQUIRED_PINS),
            )
        return str(getattr(self, name))

    @property
    def values(self) -> tuple[str, ...]:
        """The pin vector in :data:`REQUIRED_PINS` order."""
        return tuple(self.axis(name) for name in REQUIRED_PINS)

    @property
    def missing(self) -> tuple[str, ...]:
        """The unpinned axes, in :data:`REQUIRED_PINS` order.

        Named rather than counted: "policy_version" is a question an operator
        can answer, "2 missing" is not.
        """
        return tuple(
            name
            for name, value in zip(REQUIRED_PINS, self.values, strict=True)
            if not value
        )

    @property
    def complete(self) -> bool:
        """True when every required axis is pinned — the release-gate predicate."""
        return not self.missing

    def differences_from(self, other: PipelinePins) -> tuple[str, ...]:
        """Axes on which this pin and ``other`` disagree, both ways included."""
        return tuple(
            name
            for name, mine, theirs in zip(REQUIRED_PINS, self.values, other.values, strict=True)
            if mine != theirs
        )

    @classmethod
    def from_run(cls, pin: RunPin) -> PipelinePins:
        """The pins a run actually carried, as a pipeline link records them."""
        return cls(
            plan_version=pin.plan_version,
            policy_version=pin.policy_version,
            catalog_version=pin.catalog_version,
            agent_version=pin.agent_version,
            runtime_version=pin.runtime_version,
        )

    def matches_run(self, pin: RunPin) -> bool:
        """True when this link's pins agree with the run it is linked to.

        A link pinned to policy 8 that cites a run under policy 7 attributes the
        decision to a policy the run never saw, so a release gate reads the
        disagreement as blocking rather than cosmetic.
        """
        return not self.differences_from(PipelinePins.from_run(pin))

    def to_dict(self) -> dict[str, object]:
        payload = self.model_dump(mode="json")
        payload["complete"] = self.complete
        payload["missing"] = list(self.missing)
        return payload


class CheckFinding(BaseModel):
    """A structured finding — the thing a failing check actually found.

    A delta table tells a reader that something moved and only a sentence tells
    them whether it matters, so a failed check carries prose plus a stable
    ``code`` and an optional coverage ``cell`` to point at.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str = Field(min_length=2, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$")
    message: str = Field(min_length=1, max_length=2000)
    remediation: str = Field(default="", max_length=2000)
    severity: FindingSeverity = FindingSeverity.ERROR
    cell: CoverageCell | None = None

    @property
    def blocks(self) -> bool:
        """True when this finding is an error rather than a warning."""
        return self.severity is FindingSeverity.ERROR

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "message": self.message,
            "remediation": self.remediation,
            "severity": self.severity.value,
            "cell": None if self.cell is None else self.cell.key,
            "blocks": self.blocks,
        }


class CoverageDelta(BaseModel):
    """How one :class:`CoverageCell` moved between a baseline and a candidate.

    The four properties are the four honest readings of a coverage report, and
    they are deliberately not collapsed into a signed number: a cell that became
    covered and a cell that stopped being covered both "changed", and only the
    second one is bad news.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    cell: CoverageCell
    before: CellState
    after: CellState
    note: str = ""

    @model_validator(mode="after")
    def _is_a_delta(self) -> Self:
        if self.before is self.after:
            raise InvariantViolationError(
                "pipeline.coverage_delta_without_change",
                f"coverage cell {self.cell.key!r} is reported at {self.after.value!r} on "
                f"both sides: a delta that is not a change is a mistake in the "
                "report, and leaving it in is how a moved cell gets read as settled",
            )
        return self

    @property
    def newly_covered(self) -> bool:
        return self.after is CellState.PASSED and self.before is not CellState.PASSED

    @property
    def lost(self) -> bool:
        """Coverage this delta removed. A regression, not a change."""
        return self.before is CellState.PASSED and self.after is not CellState.PASSED

    @property
    def settled(self) -> bool:
        """Neither gained nor lost — inconclusive, skipped, or blocked."""
        return not self.newly_covered and not self.lost

    def to_dict(self) -> dict[str, object]:
        return {
            "cell": self.cell.key,
            "before": self.before.value,
            "after": self.after.value,
            "newly_covered": self.newly_covered,
            "lost": self.lost,
            "note": self.note,
        }


class PRCheck(BaseModel):
    """One check in a pull request or a release gate, and what it found.

    Three refusals make the interesting cases unrepresentable:

    * an **unreachable control plane** may only report
      :data:`CheckOutcome.UNKNOWN`, and must say why. It may not report pass —
      the check never ran — and it may not report fail either, because a failure
      is a fact about the world and an unreachable plane is a fact about the
      network. Reporting fail there manufactures an incident out of a DNS
      timeout.
    * a **pass without evidence** is refused: a check that claims to have passed
      with nothing behind it is a malformed claim, not a weak one.
    * a **fail without a finding** is refused: an uncited failure is a verdict
      with no content, and the triage queue cannot act on it.

    A pass *may* carry a warning-level finding — that is how a coverage gap is
    surfaced on a PR that passes. It may not carry an error-level one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = PIPELINE_SCHEMA_VERSION
    name: str = Field(min_length=1, max_length=128)
    scope: CheckScope
    outcome: CheckOutcome
    control_plane: ControlPlaneReach = ControlPlaneReach.REACHABLE
    evidence_refs: tuple[str, ...] = ()
    finding: CheckFinding | None = None
    coverage_deltas: tuple[CoverageDelta, ...] = ()
    detail: str = ""
    observed_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        if self.schema_version != PIPELINE_SCHEMA_VERSION:
            raise InvariantViolationError(
                "pipeline.unsupported_schema",
                f"unsupported PR-check schema {self.schema_version!r}: this build "
                f"reads {PIPELINE_SCHEMA_VERSION!r} only",
            )
        _require_nonblank(self.name, "pipeline_check_name_not_blank", "PR check name")
        _require_aware(self.observed_at, "pipeline_check_observed_at_aware", "PR check observed_at")
        _check_refs(self.evidence_refs, f"PR check {self.name!r}")

        if self.control_plane is ControlPlaneReach.UNREACHABLE:
            if self.outcome is not CheckOutcome.UNKNOWN:
                raise InvariantViolationError(
                    "pipeline.unreachable_check_concluded",
                    f"PR check {self.name!r} reports {self.outcome.value!r} with an "
                    f"unreachable control plane: {CONTROL_PLANE_UNREACHABLE}",
                )
            _require_nonblank(
                self.detail,
                "pipeline.unknown_check_unexplained",
                f"PR check {self.name!r} reported unknown without saying why",
            )

        if self.outcome is CheckOutcome.PASS:
            if not self.evidence_refs:
                raise InvariantViolationError(
                    "pipeline.pass_without_evidence",
                    f"PR check {self.name!r} is a pass with no evidence reference: a "
                    "verdict nobody can re-derive is a decoration, not a check",
                )
            if self.finding is not None and self.finding.blocks:
                raise InvariantViolationError(
                    "pipeline.pass_carrying_error",
                    f"PR check {self.name!r} is a pass while carrying the error finding "
                    f"{self.finding.code!r}: the outcome and the finding disagree, and "
                    "only one of them is true",
                )

        if self.outcome is CheckOutcome.FAIL and self.finding is None:
            raise InvariantViolationError(
                "pipeline.fail_without_finding",
                f"PR check {self.name!r} is a fail with no finding: a failure with no "
                "statement of what was found cannot be triaged, fixed, or disproved",
            )

        cells = [delta.cell.key for delta in self.coverage_deltas]
        if len(set(cells)) != len(cells):
            raise InvariantViolationError(
                "pipeline.duplicate_coverage_delta",
                f"PR check {self.name!r} reports the same coverage cell twice: a cell has "
                "one before and one after, and two pairs make the move ambiguous",
            )
        return self

    @property
    def is_pass(self) -> bool:
        return self.outcome is CheckOutcome.PASS

    @property
    def conclusive(self) -> bool:
        """True only when the check established an answer."""
        return self.outcome is not CheckOutcome.UNKNOWN

    @property
    def blocking(self) -> bool:
        """True when this check stops the pipeline — including when unknown."""
        return not self.is_pass

    @property
    def newly_covered(self) -> tuple[CoverageDelta, ...]:
        return tuple(delta for delta in self.coverage_deltas if delta.newly_covered)

    @property
    def lost_coverage(self) -> tuple[CoverageDelta, ...]:
        return tuple(delta for delta in self.coverage_deltas if delta.lost)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "scope": self.scope.value,
            "outcome": self.outcome.value,
            "control_plane": self.control_plane.value,
            "blocking": self.blocking,
            "evidence_refs": list(self.evidence_refs),
            "finding": None if self.finding is None else self.finding.to_dict(),
            "coverage_deltas": [delta.to_dict() for delta in self.coverage_deltas],
            "detail": self.detail,
            "observed_at": self.observed_at.isoformat(),
        }


class ChangeLink(BaseModel):
    """The link from a pipeline decision back to the change system.

    Carries what a reviewer needs to go and look (ticket, incident, deployment,
    commit) and the :class:`PipelinePins` the decision is attributable to. At
    least one of the three change-system identifiers is required: a link with a
    SHA and nothing else is a commit, not a change anyone filed.

    The pins are allowed to be blank. That is not leniency — it is what makes
    the release-gate refusal testable, and :func:`gates_release` treats an
    unpinned link as blocking.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    git_sha: str = Field(min_length=7, max_length=40, pattern=r"^[0-9a-f]{7,40}$")
    change_ticket: str = Field(default="", max_length=128)
    incident_id: str = Field(default="", max_length=128)
    deployment_id: str = Field(default="", max_length=128)
    pins: PipelinePins = Field(default_factory=PipelinePins)
    linked_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _links_something(self) -> Self:
        _require_aware(self.linked_at, "pipeline_linked_at_aware", "change link linked_at")
        if not any((self.change_ticket, self.incident_id, self.deployment_id)):
            raise InvariantViolationError(
                "pipeline.unattributable_change",
                f"change link for {self.git_sha} names no change ticket, incident, or "
                "deployment: a decision nobody filed cannot be traced back to the "
                "work that justified it",
            )
        return self

    @property
    def references(self) -> tuple[str, ...]:
        """``kind:id`` for every change-system id present, stable order."""
        return tuple(
            f"{kind}:{value}"
            for kind, value in (
                ("ticket", self.change_ticket),
                ("incident", self.incident_id),
                ("deployment", self.deployment_id),
            )
            if value
        )

    @property
    def attributable(self) -> bool:
        """True when the link names a change system and pins every version axis.

        This is the cheap answer; :func:`gates_release` is the one that also
        looks at the checks, the run, and the merge.
        """
        return bool(self.references) and self.pins.complete

    def to_dict(self) -> dict[str, object]:
        return {
            "git_sha": self.git_sha,
            "references": list(self.references),
            "pins": self.pins.to_dict(),
            "attributable": self.attributable,
            "linked_at": self.linked_at.isoformat(),
        }


class PipelineVerdict(BaseModel):
    """The pipeline's answer, with the evidence it rests on.

    ``evidence_refs`` is required and non-empty, which is what makes "a verdict
    with no evidence link" unrepresentable rather than discouraged. The
    ``outcome`` is stored but never *trusted*: construction refuses a ``PASS``
    over any check that did not pass, and :func:`gates_release` recomputes the
    whole decision from the checks, the pins, the cited run, and the plan the
    merge landed — naming each blocking reason rather than returning a bare
    ``False``.

    A verdict may cite no run (:attr:`cited_run` is optional) because a
    pull-request check has no run behind it. That verdict is perfectly valid as
    a PR verdict and can never open a release: :func:`gates_release` requires a
    pinned, agreeing run.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = PIPELINE_SCHEMA_VERSION
    outcome: PipelineOutcome
    change: ChangeLink
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    checks: tuple[PRCheck, ...] = ()
    cited_run: RunPin | None = None
    decision_refs: tuple[DecisionRef, ...] = ()
    reasons: tuple[str, ...] = ()
    decided_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        if self.schema_version != PIPELINE_SCHEMA_VERSION:
            raise InvariantViolationError(
                "pipeline.unsupported_schema",
                f"unsupported pipeline-verdict schema {self.schema_version!r}: "
                f"this build reads {PIPELINE_SCHEMA_VERSION!r} only",
            )
        _require_aware(self.decided_at, "pipeline_decided_at_aware", "verdict decided_at")
        _check_refs(self.evidence_refs, "pipeline verdict")

        names = [check.name for check in self.checks]
        if len(set(names)) != len(names):
            repeated = sorted({name for name in names if names.count(name) > 1})
            raise InvariantViolationError(
                "pipeline.duplicate_check_name",
                f"pipeline verdict repeats a check name: {repeated}",
            )

        blocking = [check for check in self.checks if check.blocking]
        if self.outcome is PipelineOutcome.PASS and blocking:
            listed = ", ".join(f"{c.name}={c.outcome.value}" for c in blocking)
            raise InvariantViolationError(
                "pipeline.pass_over_blocking_check",
                f"pipeline verdict is a pass while {listed}: the verdict is not allowed "
                "to disagree with the checks it cites",
            )
        if self.outcome is PipelineOutcome.PASS and not self.checks:
            raise InvariantViolationError(
                "pipeline.pass_without_checks",
                "pipeline verdict is a pass with no checks: a pipeline that checked "
                "nothing has established nothing",
            )
        if self.outcome is PipelineOutcome.FAIL and not self.reasons:
            raise InvariantViolationError(
                "pipeline.fail_without_reason",
                "pipeline verdict is a fail with no reason: a gate that closed must say "
                "what closed it",
            )
        if any(not reason.strip() for reason in self.reasons):
            raise InvariantViolationError(
                "pipeline.blank_reason", "pipeline verdict carries a blank reason"
            )
        return self

    # -- catalogue ------------------------------------------------------------

    @classmethod
    def decide(
        cls,
        change: ChangeLink,
        checks: tuple[PRCheck, ...],
        *,
        evidence_refs: tuple[str, ...] = (),
        cited_run: RunPin | None = None,
        decision_refs: tuple[DecisionRef, ...] = (),
        reasons: tuple[str, ...] = (),
        decided_at: datetime | None = None,
    ) -> PipelineVerdict:
        """Grade checks into a verdict.

        The grade is not a parameter: any check that did not pass — including
        one that reported :data:`CheckOutcome.UNKNOWN` — fails the pipeline, and
        the failing checks are named in the reasons. ``evidence_refs`` defaults
        to the union of the checks' own references, so a verdict assembled from
        real checks cannot accidentally arrive without evidence.
        """
        if not checks and not any(check.blocking for check in checks):
            raise InvariantViolationError(
                "pipeline.verdict_without_checks",
                f"a verdict for {change.git_sha} was asked to grade zero checks: with "
                "nothing checked there is no answer, and UNKNOWN is not an outcome of "
                "this vocabulary",
            )
        blocking = [check for check in checks if check.blocking]
        cited = evidence_refs or tuple(
            dict.fromkeys(ref for check in checks for ref in check.evidence_refs)
        )
        if not cited:
            # Not a placeholder and not a default: a fabricated reference is an
            # evidence link that leads nowhere, and a link that leads nowhere is
            # worse than a missing one because it reads as cited.
            raise InvariantViolationError(
                "pipeline.verdict_without_evidence",
                f"a verdict for {change.git_sha} has no evidence reference: the checks "
                "carry none and none was supplied, and inventing one would produce a "
                "verdict that looks cited and is not",
            )
        graded = reasons or tuple(
            f"{check.name} reported {check.outcome.value}"
            + (f": {check.detail}" if check.detail else "")
            for check in blocking
        )
        fields: dict[str, Any] = {} if decided_at is None else {"decided_at": decided_at}
        return cls(
            outcome=PipelineOutcome.FAIL if blocking else PipelineOutcome.PASS,
            change=change,
            evidence_refs=cited,
            checks=checks,
            cited_run=cited_run,
            decision_refs=decision_refs,
            reasons=graded,
            **fields,
        )

    def check(self, name: str) -> PRCheck | None:
        """The named check, or ``None``."""
        return next((check for check in self.checks if check.name == name), None)

    @property
    def blocking_checks(self) -> tuple[PRCheck, ...]:
        return tuple(check for check in self.checks if check.blocking)

    @property
    def unknown_checks(self) -> tuple[PRCheck, ...]:
        """Checks that could not reach an answer — blocking, not a soft pass."""
        return tuple(
            check for check in self.checks if check.outcome is CheckOutcome.UNKNOWN
        )

    @property
    def resilient(self) -> bool:
        """True only when a resilience check ran and passed.

        "No resilience check" and "resilience check passed" are different facts,
        and collapsing them is how a release gate reads well on the strength of
        a check nobody ran.
        """
        return any(
            check.scope is CheckScope.RESILIENCE and check.is_pass for check in self.checks
        )

    def verdict_digest(self) -> str:
        """Canonical digest of the whole decision, for sealing into evidence."""
        return sha256_hex(canonical_json(self.model_dump(mode="json")))

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "resilient": self.resilient,
            "change": self.change.to_dict(),
            "cited_run": None if self.cited_run is None else self.cited_run.label,
            "evidence_refs": list(self.evidence_refs),
            "checks": [check.to_dict() for check in self.checks],
            "decision_refs": [ref.summary() for ref in self.decision_refs],
            "reasons": list(self.reasons),
            "decided_at": self.decided_at.isoformat(),
        }


class PlanApproval(BaseModel):
    """One approval, bound to the digest of the plan that was checked.

    Bound rather than free: an approval whose digest is empty approves nothing,
    so the plan it was read against can always be named. That is the property
    :class:`PlanMerge` needs to decide that a merge invalidated it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    approver: str = Field(min_length=1, max_length=128)
    plan_digest: PlanDigest
    approved_at: datetime = Field(default_factory=utc_now)
    note: str = ""

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_nonblank(self.approver, "pipeline_approver_not_blank", "plan approval approver")
        _require_aware(self.approved_at, "pipeline_approved_at_aware", "plan approval approved_at")
        return self

    def to_dict(self) -> dict[str, object]:
        return {
            "approver": self.approver,
            "plan_digest": self.plan_digest,
            "approved_at": self.approved_at.isoformat(),
            "note": self.note,
        }


class PlanMerge(BaseModel):
    """The plan digest that was checked against the one that actually merged.

    The negative control from Phase 5 as a type. When the two digests differ,
    **every** prior approval is invalidated — not merely the ones whose digest
    happens to match, because an approval granted against a plan nobody ran is
    an approval of a different thing, whatever digest it carries.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    checked_plan_digest: PlanDigest
    merged_plan_digest: PlanDigest
    approvals: tuple[PlanApproval, ...] = ()
    merged_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(self.merged_at, "pipeline_merged_at_aware", "plan merge merged_at")
        return self

    @property
    def changed(self) -> bool:
        """True when the merged plan is not the plan that was checked."""
        return self.checked_plan_digest != self.merged_plan_digest

    @property
    def invalidated(self) -> tuple[PlanApproval, ...]:
        """The approvals this merge took away, in the order they were granted."""
        if self.changed:
            return self.approvals
        return tuple(
            approval
            for approval in self.approvals
            if approval.plan_digest != self.merged_plan_digest
        )

    @property
    def surviving(self) -> tuple[PlanApproval, ...]:
        """The approvals that still bind the plan that merged."""
        gone = {id(approval) for approval in self.invalidated}
        return tuple(approval for approval in self.approvals if id(approval) not in gone)

    @property
    def approvals_stand(self) -> bool:
        """True only when the plan did not move and every approval still binds."""
        return not self.invalidated

    @property
    def invalidation_reason(self) -> str:
        """The citable sentence, empty when nothing was invalidated."""
        if not self.invalidated:
            return ""
        if self.changed:
            return (
                f"the merged plan digest {self.merged_plan_digest[:12]}… is not the "
                f"checked digest {self.checked_plan_digest[:12]}…, so "
                f"{len(self.invalidated)} prior approval(s) are invalidated: an approval "
                "given against a plan nobody ran approves nothing"
            )
        return (
            f"{len(self.invalidated)} approval(s) were granted against a plan other than "
            f"the merged digest {self.merged_plan_digest[:12]}…"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "checked_plan_digest": self.checked_plan_digest,
            "merged_plan_digest": self.merged_plan_digest,
            "changed": self.changed,
            "approvals": [approval.to_dict() for approval in self.approvals],
            "invalidated": [a.approver for a in self.invalidated],
            "surviving": [a.approver for a in self.surviving],
            "invalidation_reason": self.invalidation_reason,
            "merged_at": self.merged_at.isoformat(),
        }


def comparable_across_release(baseline: RunPin, candidate: RunPin) -> bool:
    """True when two runs may be compared across a release boundary.

    A pure delegation to :func:`mayhem.domain.comparison.equivalent_pins`:
    same experiment, same environment, same plan/policy/catalog/agent/runtime
    versions, same journey pin — and the release deliberately *excluded*, since
    the release is the axis the comparison is about. It exists here as a named
    predicate so a pipeline reader can ask the pipeline question; the answer
    comes from plan 22 so the two cannot drift.
    """
    return equivalent_pins(baseline, candidate)


def gates_release(
    verdict: PipelineVerdict,
    merge: PlanMerge | None = None,
) -> bool:
    """True only when this verdict may open a release. Recomputed, never trusted.

    Blocking reasons, in the order they are checked:

    * the verdict is a fail;
    * a check reported fail **or unknown** — unknown blocks, because a check
      that could not ask the question has not answered it;
    * no run is cited, so nothing was measured;
    * the change link leaves a required version axis unpinned;
    * the link's pins disagree with the run it cites;
    * a merge is supplied and it invalidated the plan's approvals.
    """
    return not blocking_reasons(verdict, merge)


def blocking_reasons(
    verdict: PipelineVerdict,
    merge: PlanMerge | None = None,
) -> tuple[str, ...]:
    """Everything standing between this verdict and a release, in check order.

    Returned as sentences rather than a boolean so a refused gate can say which
    check would not conclude, which axis was unpinned, and which approval lapsed
    — the difference between a gate an operator can act on and a red X. The
    link/run disagreement is reported only once the link is *complete*: an
    incomplete link has already named every blank axis, and naming each of them
    again as a disagreement would say the same sentence five times over.
    """
    reasons: list[str] = []

    if verdict.outcome is PipelineOutcome.FAIL:
        reasons.extend(verdict.reasons or ("the pipeline verdict is a fail",))
    for check in verdict.blocking_checks:
        reasons.append(
            f"check {check.name!r} ({check.scope.value}) reported {check.outcome.value}"
            + (f": {check.detail}" if check.detail else "")
        )
    if verdict.cited_run is None:
        reasons.append(
            "no run is cited, and a run that cannot be cited cannot back a "
            "release-gate decision"
        )
    missing = verdict.change.pins.missing
    if missing:
        reasons.append(
            "the change link leaves "
            + ", ".join(missing)
            + " unpinned, and a run missing a required pin cannot back a "
            "release-gate decision"
        )
    if verdict.cited_run is not None and not missing:
        # Only reported once the link is complete. An incomplete link already
        # names every blank axis, and re-reporting each of them as a
        # disagreement with the run would say the same thing five more times.
        disagreements = verdict.change.pins.differences_from(
            PipelinePins.from_run(verdict.cited_run)
        )
        if disagreements:
            reasons.append(
                "the change link pins "
                + ", ".join(disagreements)
                + " differently from the cited run, so the decision is attributed to "
                "versions the run never saw"
            )
    if merge is not None and not merge.approvals_stand:
        reasons.append(merge.invalidation_reason)
    return tuple(dict.fromkeys(reasons))
