"""``mayhem boundary`` — resilience boundary reports, minimal-failure-case
reports, and candidate review (docs/v1.1.0/15_RESILIENCE_ANALYTICS_ADAPTIVE.md,
Phase 3).

Phases 1-2 put the arithmetic in :mod:`mayhem.domain.analytics` and
:mod:`mayhem.domain.search` and the engine in
:mod:`mayhem.controller.analytics_service`; Phase 4 sealed every report that
engine produces and refused a draft that carries its own authority. None of that
is reachable by a person. This module is the surface, and it is two commands::

    mayhem boundary report  --search SEARCH.json [--signal NAME]
    mayhem boundary review  --candidate CANDIDATE.json --policy POLICY.json \\
                            --spec DRILL.yaml --graph GRAPH.json

Eight commitments shape it.

**The view-model layer is the guarantee, not the callback.** As in
:mod:`mayhem.cli.advisor_cmd`, the renderable values are pure dataclasses built
here, and the Click callbacks only *report* a refusal. A refusal somebody has to
remember to run is not a refusal, and a future UI that wants a boundary report
has to ask this layer for one.

Every document this surface reads is validated field by field and its unknown
fields are refused by name — the search document, the policy, and the topology
graph here, and the **candidate** by
:func:`~mayhem.controller.analytics_service.compile_candidate`, which owns both
that document's field discipline and its authority scan. A key nothing reads is a
place a value can hide, and a document mayhem does not fully understand may not be
the document it reads.

**Nothing here computes a statistic.** ``boundary report`` reads a document of
*recorded observations* — the ladder and the sample series captured at each rung
— and hands them to :func:`~mayhem.domain.analytics.compare`,
:func:`~mayhem.controller.analytics_service.boundary_report`,
:func:`~mayhem.controller.analytics_service.minimal_failure_case`, and
:func:`~mayhem.controller.analytics_service.analytics_evidence`. The boundary is
read from :attr:`~mayhem.domain.search.SearchHistory.boundary`, never re-derived;
the bracket is the engine's; sufficiency is
:class:`~mayhem.domain.analytics.SamplePolicy`'s; warm-up and cooldown are
:class:`~mayhem.domain.analytics.WindowPlan`'s. A document that already carried a
*finished* boundary would let this surface print back a number it did not
compute, which is why the input format is the raw one.

**A boundary whose confidence is insufficient does not render as a tolerance.**
That is this module's load-bearing honesty rule, and it is a refusal in the view
layer rather than a phrasing choice in a renderer. :func:`_tolerates` is the only
thing that can emit the word ``tolerates``, and it emits it only when the report
has a boundary, that boundary sits inside the bracket the engine reported, *and*
the comparison recorded there was sufficient and graded. Anything else returns
the domain's own reason and the renderer prints a withholding naming it.

**Unsupported is rendered, never omitted.** Every report goes through
:func:`~mayhem.controller.analytics_service.analytics_evidence`, and the
withholdings come back beside the claims. A report whose sections were all
withheld renders as a list of refusals, which is a different document from a
report that ran no sections at all and is not allowed to look like one.

**"Indistinguishable downstream of compilation" is one function, not a
comparison.** :func:`_gate` compiles a
:class:`~mayhem.domain.experiments.DrillSpec` with
:func:`~mayhem.controller.planner.plan_drill`, proves it with
:func:`~mayhem.controller.safety_proof.compile_safety_evidence`, and reads the
policy verdict with :func:`~mayhem.controller.safety.simulate_plan_policy`.
**It has no origin parameter.** The authored arm and the generated arm both call
it, so a generated candidate cannot reach a different compiler, a different
proof, or a different policy verdict than an authored one — not because a test
checked that it did, but because there is no second implementation to reach. The
candidate itself is compiled by
:func:`~mayhem.controller.analytics_service.compile_candidate` into the *same*
:class:`~mayhem.domain.search.SearchPlan` an authored proposal uses, with
``origin=generated`` and nowhere to put an approval.

**The surface grants nothing, and one word says so.** Every view reports
``authority: none``, which is
:attr:`~mayhem.domain.search.SearchPlan.authority`'s own value. This module has
no ``grants_approval`` / ``grants_authorization`` boolean to render: a surface
that can print ``false`` beside a word can grow a branch that prints ``true``
beside it, and the absence of the field is stronger than the value. For the same
reason the rendered gate transcript is *rule ids* and not the gates' prose.

**The blast-radius ceilings are module constants, not flags.** A caller handed a
flag for the ceiling is handed the gate that is supposed to be checking it, which
is the argument :func:`mayhem.cli.advisor_cmd.advisor_safety_context` makes and
the reason this surface repeats it. ``--deny-fault`` exists because it can only
*tighten*. There is no ``--force``, no ``--approve``, no ``--skip-gate``, and
neither command opens a database.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import click

from mayhem.cli import style
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.output import echo_machine
from mayhem.controller.analytics_service import (
    AUTHORITY_FIELDS,
    AnalyticsClaim,
    ClaimKind,
    FailureCase,
    WithheldEvidence,
    analytics_evidence,
    analyze_run,
    boundary_claim,
    boundary_report,
    compile_candidate,
    search_record_of,
)
from mayhem.controller.planner import plan_drill
from mayhem.controller.safety import SafetyContext, simulate_plan_policy
from mayhem.controller.safety_proof import compile_safety_evidence
from mayhem.domain.analytics import (
    DEFAULT_PERCENTILES,
    MIN_COMPARABLE_SAMPLES,
    Comparison,
    SamplePolicy,
    SegmentedSamples,
    Sufficiency,
    WindowPlan,
    compare,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import DrillContainer, DrillFault, DrillSpec
from mayhem.domain.hashing import digest
from mayhem.domain.search import (
    SearchHistory,
    SearchOrigin,
    SearchPhase,
    SearchPlan,
    SearchPolicy,
    SearchStep,
    StopReason,
    Trial,
)

if TYPE_CHECKING:
    from mayhem.controller.analytics_service import BoundaryReport
    from mayhem.controller.safety_proof import SafetyCompilation
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.policy_gate import PolicyGateResult
    from mayhem.domain.topology import TopologyGraph

__all__ = [
    "AUTHORITY_FIELD_KEYS",
    "AUTHORITY_NONE",
    "GATE_PATH",
    "POLICY_STATE_NO_BUNDLE",
    "REVIEW_CAP_MAX_CONCURRENT_FAULTS",
    "REVIEW_CAP_MAX_DURATION_PER_FAULT_S",
    "REVIEW_CAP_MAX_HOSTS",
    "REVIEW_CAP_MAX_SERVICES_PCT",
    "REVIEW_CLOSES_EVIDENCE",
    "RULE_REPORT_SIGNAL_UNKNOWN",
    "RULE_REPORT_UNKNOWN_FIELD",
    "RULE_REPORT_VALUE_UNKNOWN",
    "RULE_REVIEW_UNKNOWN_FIELD",
    "RULE_REVIEW_WILL_NOT_COMPILE",
    "SURFACE_VIA",
    "BoundaryReportView",
    "BoundaryViewRefused",
    "CandidateReviewView",
    "MinimalCaseView",
    "ReviewArmView",
    "SearchDocument",
    "SignalBoundaryView",
    "SignalDocument",
    "TrialRow",
    "boundary",
    "boundary_report_view",
    "boundary_review_safety_context",
    "candidate_review_view",
    "plan_shape_digest",
    "render_boundary_report",
    "render_candidate_review",
    "search_document",
]

# =============================================================================
# Vocabulary this module owns
# =============================================================================

SURFACE_VIA: Final[str] = "mayhem.boundary.review"
"""The one door a candidate review goes through, named so a rendered view can say it."""

AUTHORITY_NONE: Final[str] = "none"
"""What every view here reports. :attr:`SearchPlan.authority`'s own value for a plan
nobody approved, quoted rather than paraphrased so a reader who greps for it
lands on the type that decides it."""

REVIEW_CLOSES_EVIDENCE: Final[str] = "no"
"""Always ``"no"``. This surface seals nothing and reads no seal."""

POLICY_STATE_NO_BUNDLE: Final[str] = "no_bundle_configured"
"""What the policy state renders as when the context carries no bundle. Not a pass."""

GATE_PATH: Final[tuple[str, ...]] = (
    "controller.planner.plan_drill",
    "controller.safety_proof.compile_safety_evidence",
    "controller.safety.simulate_plan_policy",
)
"""The gates every candidate reaches, in order.

A declaration, not a description: :func:`_gate` is written to call exactly these
three in exactly this order, this tuple is what a rendered view prints, and it is
what the test suite compares between the authored arm and the generated one. A
gate added to :func:`_gate` without being added here is a gate a reader is not
told about.

Three, and not four, because approval is not a gate this surface can reach: it
holds no :class:`~mayhem.controller.approval_gate.ApprovalGateInputs`, so the
plan-09 gate is **not evaluated** and the proof's ``required_approvals`` line
says so. "Not evaluated" is not "passed", and the rendered view prints that
line's own state rather than a word this module chose.
"""

AUTHORITY_FIELD_KEYS: Final[tuple[str, ...]] = tuple(sorted(AUTHORITY_FIELDS))
"""A projection of :data:`~mayhem.controller.analytics_service.AUTHORITY_FIELDS`.

Sorted from the domain's own frozenset rather than re-spelled, so it cannot
drift from the scan. It is here so a rendered view and a test can *name* what a
draft would have had to smuggle. It is **not** a second authority scan:
:func:`~mayhem.controller.analytics_service.compile_candidate` stays the one
place a payload is scanned, and this module never scans for itself — a second
scan would be a second definition of what an authority field is.
"""

REVIEW_CAP_MAX_SERVICES_PCT: Final[float] = 50.0
REVIEW_CAP_MAX_HOSTS: Final[int] = 8
REVIEW_CAP_MAX_CONCURRENT_FAULTS: Final[int] = 4
REVIEW_CAP_MAX_DURATION_PER_FAULT_S: Final[float] = 300.0
"""The blast-radius ceilings this surface evaluates against.

Module constants for the reason stated above. They are the same numbers
:func:`mayhem.cli.advisor_cmd.advisor_safety_context` uses, so two advisory
surfaces cannot disagree about what they will tolerate.
"""

RULE_REPORT_UNKNOWN_FIELD = "boundary_report.unknown_field"
RULE_REPORT_VALUE_UNKNOWN = "boundary_report.value_unknown"
RULE_REPORT_SIGNAL_UNKNOWN = "boundary_report.signal_unknown"
RULE_REVIEW_UNKNOWN_FIELD = "boundary_review.unknown_field"
RULE_REVIEW_WILL_NOT_COMPILE = "boundary_review.candidate_will_not_compile"

_ALLOWED_REPORT_FIELDS: Final[frozenset[str]] = frozenset(
    {"run_id", "policy", "trials", "signals", "failure_cases"}
)
_ALLOWED_POLICY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "strategy",
        "start",
        "step",
        "stop_on_breach",
        "minimization",
        "combination_budget",
        "budget_ref",
        "step_cost",
        "max_steps",
        "resolution",
        "name",
    }
)
_ALLOWED_TRIAL_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "index",
        "value",
        "phase",
        "combination",
        "budget_remaining",
        "expected_cost",
        "breached",
        "sufficient",
    }
)
_ALLOWED_SIGNAL_FIELDS: Final[frozenset[str]] = frozenset(
    {"name", "unit", "percentile", "materiality_pct", "window", "captures"}
)
_ALLOWED_CAPTURE_FIELDS: Final[frozenset[str]] = frozenset({"index", "baseline", "window"})
_ALLOWED_WINDOW_FIELDS: Final[frozenset[str]] = frozenset({"warmup", "measured", "cooldown"})
_ALLOWED_CASE_FIELDS: Final[frozenset[str]] = frozenset(
    {"fault_ids", "target_ids", "reproduced", "value", "combination", "sufficient"}
)
#: No ``_ALLOWED_CANDIDATE_FIELDS`` here on purpose. The candidate document's field
#: discipline *and* its authority scan are both
#: :func:`~mayhem.controller.analytics_service.compile_candidate`'s, and it checks
#: authority first; a second refusal on this surface would shadow
#: ``analytics.draft_carries_authority`` — the more specific answer to the same
#: document — with a rule that says only "I did not expect that key".


class BoundaryViewRefused(InvariantViolationError):  # noqa: N818 — domain refusal vocabulary
    """A document or a rendering refused, with a stable rule id."""


# =============================================================================
# Reading a document: every field validated, every unknown field refused
# =============================================================================


def _refuse_unknown(
    document: Mapping[str, Any], allowed: frozenset[str], *, where: str, rule: str
) -> None:
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise BoundaryViewRefused(
            rule,
            f"{where} declares unknown field(s) {unknown}; allowed fields are {sorted(allowed)}. "
            "A key nothing reads is a place a value can hide, and a document mayhem does not "
            "fully understand may not be the document it reads",
        )


def _block(value: object, *, where: str, rule: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BoundaryViewRefused(
            rule, f"{where} must be a mapping, got {type(value).__name__}"
        )
    return value


def _rows(value: object, *, where: str, rule: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise BoundaryViewRefused(
            rule, f"{where} must be a list, got {type(value).__name__}"
        )
    return [
        _block(item, where=f"{where}[{index}]", rule=rule) for index, item in enumerate(value)
    ]


def _number(value: object, *, where: str, rule: str = RULE_REPORT_VALUE_UNKNOWN) -> float:
    """A finite number, or a refusal naming the field.

    ``None``, ``""``, ``"unknown"``, ``True``, ``nan`` and ``inf`` all land here.
    The rule this exists for is that **an unknown value is refused rather than
    defaulted to a number**: a blank boundary rung rendered as ``0`` would be
    indistinguishable from a measured zero, and a report that cannot say which
    impairment it is talking about must say so rather than pick one.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BoundaryViewRefused(
            rule,
            f"{where} must be a number, got {value!r}: an unknown value is refused rather "
            "than defaulted, because a boundary nobody measured is not a boundary of zero",
        )
    resolved = float(value)
    if not isfinite(resolved):
        raise BoundaryViewRefused(
            rule,
            f"{where} must be finite, got {resolved!r}: an infinite ladder never terminates "
            "and an infinite boundary is not a number",
        )
    return resolved


def _integer(value: object, *, where: str, rule: str = RULE_REPORT_VALUE_UNKNOWN) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BoundaryViewRefused(
            rule,
            f"{where} must be an integer, got {value!r}: a count this surface reports is read "
            "as written, never rounded into one",
        )
    return value


def _boolean(value: object, *, where: str, rule: str = RULE_REPORT_VALUE_UNKNOWN) -> bool:
    if not isinstance(value, bool):
        raise BoundaryViewRefused(
            rule,
            f"{where} must be true or false, got {value!r}: a breach is either recorded or it "
            "was not, and there is no third reading",
        )
    return value


def _text(value: object, *, where: str, rule: str = RULE_REPORT_VALUE_UNKNOWN) -> str:
    if not isinstance(value, str):
        raise BoundaryViewRefused(
            rule, f"{where} must be a string, got {type(value).__name__}"
        )
    if not value.strip():
        raise BoundaryViewRefused(
            rule,
            f"{where} is blank: a field with nothing in it is not a value this surface may "
            "substitute a default for",
        )
    return value


def _samples(
    value: object, *, where: str, rule: str = RULE_REPORT_VALUE_UNKNOWN
) -> tuple[float, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise BoundaryViewRefused(
            rule, f"{where} must be a list of samples, got {type(value).__name__}"
        )
    return tuple(
        _number(item, where=f"{where}[{index}]", rule=rule) for index, item in enumerate(value)
    )


def _read_json(path: Path, *, what: str, rule: str) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MayhemCliError(
            code="validation_error",
            message=f"the {what} file {str(path)!r} could not be read: {exc}",
            details={"path": str(path), "rule": rule},
            remediation="check the path and its permissions",
        ) from None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MayhemCliError(
            code="validation_error",
            message=f"the {what} file {str(path)!r} is not valid JSON: {exc}",
            details={"path": str(path), "rule": rule},
            remediation=f"a {what} document is JSON; mayhem will not guess at it",
        ) from None


def _policy_fields(raw: Mapping[str, Any], *, rule: str) -> Mapping[str, Any]:
    _refuse_unknown(raw, _ALLOWED_POLICY_FIELDS, where="the policy", rule=rule)
    if "budget_ref" not in raw:
        raise BoundaryViewRefused(
            rule,
            "the policy declares no budget_ref: a ladder with no budget is a sweep, and mayhem "
            "will not render one as a boundary search",
        )
    return raw


def _policy_block(document: Mapping[str, Any], *, rule: str) -> Mapping[str, Any]:
    return _policy_fields(
        _block(document.get("policy", {}), where="the policy", rule=rule), rule=rule
    )


# =============================================================================
# The search document — recorded observations, never a finished report
# =============================================================================


@dataclass(frozen=True, slots=True)
class TrialRow:
    """One rung of the recorded ladder."""

    index: int
    value: float
    phase: str
    combination: str
    budget_remaining: float
    expected_cost: float
    breached: bool
    sufficient: bool


@dataclass(frozen=True, slots=True)
class SignalDocument:
    """One declared metric and the samples recorded for it at each rung."""

    name: str
    unit: str
    percentile: float
    materiality_pct: float | None
    window_plan: WindowPlan
    captures: tuple[tuple[int, tuple[float, ...], tuple[float, ...]], ...]
    """``(trial index, baseline samples, during-fault samples)`` per rung."""

    @property
    def statistic(self) -> str:
        return f"p{self.percentile:g}"


@dataclass(frozen=True, slots=True)
class SearchDocument:
    """A boundary search as it was *recorded*: a policy, its ladder, its samples.

    Deliberately the raw shape. Every field here is something a run observed or
    an operator declared, and none of them is a boundary — the boundary is the
    engine's answer to this document, not a field in it.
    """

    run_id: str
    policy: SearchPolicy
    trials: tuple[TrialRow, ...]
    signals: tuple[SignalDocument, ...]
    failure_cases: tuple[FailureCase, ...]

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> SearchDocument:
        _refuse_unknown(
            document, _ALLOWED_REPORT_FIELDS, where="the search document",
            rule=RULE_REPORT_UNKNOWN_FIELD,
        )
        policy = SearchPolicy.model_validate(
            _policy_block(document, rule=RULE_REPORT_UNKNOWN_FIELD)
        )
        trials = tuple(
            _trial_row(raw, policy, index)
            for index, raw in enumerate(
                _rows(document.get("trials", []), where="search document trials",
                      rule=RULE_REPORT_UNKNOWN_FIELD)
            )
        )
        if not trials:
            raise BoundaryViewRefused(
                RULE_REPORT_UNKNOWN_FIELD,
                "the search document declares no trial: a report over zero trials says nothing "
                "about what a system tolerates, and mayhem renders that as a withholding "
                "rather than as a boundary of zero. Record the ladder that was walked, or "
                "point --search at a document that has it",
            )
        return cls(
            run_id=_text(document.get("run_id", ""), where="search document run_id"),
            policy=policy,
            trials=trials,
            signals=tuple(
                _signal_document(raw, index)
                for index, raw in enumerate(
                    _rows(document.get("signals", []), where="search document signals",
                          rule=RULE_REPORT_UNKNOWN_FIELD)
                )
            ),
            failure_cases=tuple(
                _failure_case(raw, index)
                for index, raw in enumerate(
                    _rows(document.get("failure_cases", []),
                          where="search document failure_cases",
                          rule=RULE_REPORT_UNKNOWN_FIELD)
                )
            ),
        )

    @classmethod
    def from_path(cls, path: Path) -> SearchDocument:
        return cls.from_document(
            _block(
                _read_json(path, what="search", rule=RULE_REPORT_UNKNOWN_FIELD),
                where="the search document",
                rule=RULE_REPORT_UNKNOWN_FIELD,
            )
        )


def _trial_row(raw: Mapping[str, Any], policy: SearchPolicy, position: int) -> TrialRow:
    where = f"search document trials[{position}]"
    _refuse_unknown(raw, _ALLOWED_TRIAL_FIELDS, where=where, rule=RULE_REPORT_UNKNOWN_FIELD)
    return TrialRow(
        index=_integer(raw.get("index", position), where=f"{where}.index"),
        value=_number(raw.get("value"), where=f"{where}.value"),
        phase=_text(raw.get("phase", "escalation"), where=f"{where}.phase"),
        combination=_text(raw.get("combination", "default"), where=f"{where}.combination"),
        budget_remaining=_number(
            raw.get("budget_remaining", policy.step_cost), where=f"{where}.budget_remaining"
        ),
        expected_cost=_number(
            raw.get("expected_cost", policy.step_cost), where=f"{where}.expected_cost"
        ),
        breached=_boolean(raw.get("breached", False), where=f"{where}.breached"),
        sufficient=_boolean(raw.get("sufficient", True), where=f"{where}.sufficient"),
    )


def _signal_document(raw: Mapping[str, Any], position: int) -> SignalDocument:
    where = f"search document signals[{position}]"
    _refuse_unknown(raw, _ALLOWED_SIGNAL_FIELDS, where=where, rule=RULE_REPORT_UNKNOWN_FIELD)
    window_raw = _block(raw.get("window", {}), where=f"{where}.window",
                        rule=RULE_REPORT_UNKNOWN_FIELD)
    _refuse_unknown(window_raw, _ALLOWED_WINDOW_FIELDS, where=f"{where}.window",
                    rule=RULE_REPORT_UNKNOWN_FIELD)
    materiality = raw.get("materiality_pct")
    return SignalDocument(
        name=_text(raw.get("name"), where=f"{where}.name"),
        unit=_text(raw.get("unit", "unitless"), where=f"{where}.unit"),
        percentile=_number(
            raw.get("percentile", max(DEFAULT_PERCENTILES)), where=f"{where}.percentile"
        ),
        materiality_pct=(
            None if materiality is None else _number(materiality, where=f"{where}.materiality_pct")
        ),
        window_plan=WindowPlan(
            warmup=_integer(window_raw.get("warmup", 0), where=f"{where}.window.warmup"),
            measured=_integer(
                window_raw.get("measured", MIN_COMPARABLE_SAMPLES),
                where=f"{where}.window.measured",
            ),
            cooldown=_integer(
                window_raw.get("cooldown", 0), where=f"{where}.window.cooldown"
            ),
        ),
        captures=tuple(
            _capture(item, where, index)
            for index, item in enumerate(
                _rows(raw.get("captures", []), where=f"{where}.captures",
                      rule=RULE_REPORT_UNKNOWN_FIELD)
            )
        ),
    )


def _capture(
    raw: Mapping[str, Any], where: str, position: int
) -> tuple[int, tuple[float, ...], tuple[float, ...]]:
    at = f"{where}.captures[{position}]"
    _refuse_unknown(raw, _ALLOWED_CAPTURE_FIELDS, where=at, rule=RULE_REPORT_UNKNOWN_FIELD)
    return (
        _integer(raw.get("index", position), where=f"{at}.index"),
        _samples(raw.get("baseline", []), where=f"{at}.baseline"),
        _samples(raw.get("window", []), where=f"{at}.window"),
    )


def _failure_case(raw: Mapping[str, Any], position: int) -> FailureCase:
    where = f"search document failure_cases[{position}]"
    _refuse_unknown(raw, _ALLOWED_CASE_FIELDS, where=where, rule=RULE_REPORT_UNKNOWN_FIELD)
    value = raw.get("value")
    return FailureCase(
        fault_ids=tuple(
            _text(item, where=f"{where}.fault_ids[{index}]")
            for index, item in enumerate(raw.get("fault_ids", []))
        ),
        target_ids=tuple(
            _text(item, where=f"{where}.target_ids[{index}]")
            for index, item in enumerate(raw.get("target_ids", []))
        ),
        reproduced=_boolean(raw.get("reproduced", False), where=f"{where}.reproduced"),
        value=None if value is None else _number(value, where=f"{where}.value"),
        combination=_text(raw.get("combination", f"case-{position}"), where=f"{where}.combination"),
        sufficient=_boolean(raw.get("sufficient", True), where=f"{where}.sufficient"),
    )


# =============================================================================
# Rebuilding the engine's inputs out of the document
# =============================================================================


def _step_for(row: TrialRow, policy: SearchPolicy) -> SearchStep:
    return SearchStep(
        index=row.index,
        value=row.value,
        phase=SearchPhase(row.phase),
        combination=row.combination,
        budget_remaining=row.budget_remaining,
        budget_ref=policy.budget_ref,
        expected_cost=row.expected_cost,
    )


def _recorded_history(document: SearchDocument) -> SearchHistory:
    """The ladder exactly as the search recorded it — the engine's own type."""
    return SearchHistory(
        trials=tuple(
            Trial(
                step=_step_for(row, document.policy),
                breached=row.breached,
                sufficient=row.sufficient,
            )
            for row in document.trials
        )
    )


def _signal_ladder(
    document: SearchDocument, signal: SignalDocument
) -> tuple[SearchHistory, dict[int, Comparison], dict[int, SegmentedSamples]]:
    """One metric's own ladder, its comparisons, and its phase splits.

    A rung *breached for this metric* when its own comparison was graded and
    material, and *measurable* when the comparison was sufficient — both read off
    the domain, neither from a threshold written here. A rung with no capture at
    all is recorded as unmeasurable, so it can never be counted as a clearance:
    that is what stops "mayhem did not look" from decaying into "mayhem looked and
    it was fine".
    """
    by_index = {index: (baseline, window) for index, baseline, window in signal.captures}
    comparisons: dict[int, Comparison] = {}
    segments: dict[int, SegmentedSamples] = {}
    trials: list[Trial] = []
    for row in document.trials:
        step = _step_for(row, document.policy)
        captured = by_index.get(row.index)
        if captured is None:
            trials.append(Trial(step=step, breached=False, sufficient=False))
            continue
        baseline, window = captured
        result = compare(
            baseline,
            signal.window_plan.split(window).measured,
            name=signal.name,
            percentile=signal.percentile,
            policy=SamplePolicy(),
            materiality_pct=signal.materiality_pct,
        )
        comparisons[row.index] = result
        segments[row.index] = signal.window_plan.split(window)
        trials.append(
            Trial(
                step=step,
                breached=bool(result.graded and result.material),
                sufficient=bool(result.sufficient),
            )
        )
    return SearchHistory(trials=tuple(trials)), comparisons, segments


def _boundary_trial_index(history: SearchHistory, boundary: float | None) -> int | None:
    """Which recorded rung the boundary's own comparison belongs to.

    A *read* of the history the engine already read, using the engine's own
    selection — the first breaching trial at the boundary value. It computes no
    boundary and no bracket; :attr:`SearchHistory.boundary` remains the single
    definition and this only says which rung of that history the quote came from.
    """
    if boundary is None:
        return None
    return next(
        (
            trial.step.index
            for trial in history.trials
            if trial.breached and trial.step.value == boundary
        ),
        None,
    )


def _stop_of(history: SearchHistory) -> StopReason:
    """Why the recorded ladder ended, in the domain's own vocabulary."""
    return StopReason.BREACH_FOUND if history.boundary is not None else StopReason.LADDER_EXHAUSTED


# =============================================================================
# The report view
# =============================================================================


def _refusal_reason(comparison: Comparison | None) -> str:
    if comparison is None:
        return (
            "no comparison was recorded at a boundary value, so this search reports a ladder "
            "with no graded evidence about the metric at its edge"
        )
    sufficiency: Sufficiency | None = comparison.sufficiency
    if not comparison.sufficient and sufficiency is not None and sufficiency.reason:
        return sufficiency.reason
    return comparison.note or "the comparison at the boundary was not graded"


def _tolerates(
    report: BoundaryReport,
    comparison: Comparison | None,
    signal: str,
    statistic: str,
    unit: str,
) -> tuple[bool, str]:
    """Whether this boundary may be printed as a tolerance — and the line if so.

    The single place the word ``tolerates`` can reach a reader, and a function
    rather than a template for exactly that reason. The numbers and the
    ``NOT RESOLVED`` wording come from the engine's own
    :attr:`BoundaryReport.tolerance_statement` — this surface does not restate a
    boundary in its own vocabulary — and what is appended names the metric the
    reading is on. The appended unit is the *metric's* unit and the sentence says
    so: the ladder's value is an impairment, and a metric's unit printed beside an
    impairment number would be a unit read that was never measured.

    The word may only appear when the report has a boundary, that boundary sits
    inside the bracket the engine reported, *and* the comparison recorded there
    was sufficient and graded. Anything else returns ``(False, reason)`` and the
    renderer prints a withholding naming the domain's own reason.
    """
    if report.boundary is None:
        unmeasured = (
            f" {len(report.insufficient_trials)} of its {report.trials} rung(s) could not be "
            "graded, so a breach may have been recorded with no separable measurement behind it"
            if report.insufficient_trials
            else ""
        )
        return False, (
            "the ladder never crossed the declared tolerance, so there is no boundary to "
            f"quote:{unmeasured}. This search establishes nothing about the limit the system "
            "was held to, and a number invented for it would be one mayhem never measured"
        )
    if comparison is None or not comparison.sufficient or not comparison.graded:
        return False, _refusal_reason(comparison)
    label = f"{signal} {statistic} {unit}".replace("  ", " ").strip()
    return True, f"{report.tolerance_statement} — read on {label}"


def _bracket_line(report: BoundaryReport) -> str:
    high = "none" if report.boundary is None else f"{report.boundary:g}"
    return f"({report.bracket_low:g}, {high}]"


def _phase_line(signal: SignalDocument, segment: SegmentedSamples | None) -> str:
    plan = signal.window_plan
    if segment is None:
        return (
            f"warmup {plan.warmup} / measured {plan.measured} / cooldown {plan.cooldown} "
            "(no capture recorded at the boundary rung)"
        )
    tail = "" if segment.complete else " — the capture did not supply the declared window"
    return (
        f"warmup {len(segment.warmup)} / measured {len(segment.measured)} / "
        f"cooldown {len(segment.cooldown)}; dropped {segment.dropped}, "
        f"missing {segment.missing}{tail}"
    )


@dataclass(frozen=True, slots=True)
class SignalBoundaryView:
    """One declared metric's boundary: the tolerance, the confidence, the support.

    ``reportable`` is computed once, in :func:`boundary_report_view`, and never in
    a renderer — so a future UI inherits the rule rather than reimplementing it.
    """

    signal: str
    unit: str
    statistic: str
    reportable: bool
    tolerance: str
    confidence: str
    refusal: str
    bracket: str
    resolved: bool
    resolution: float
    trials: int
    insufficient_trials: tuple[int, ...]
    graded_verdict: str
    effect_size: str
    window_phases: str
    support_refs: tuple[str, ...]
    withheld_rule: str
    withheld_reason: str

    @property
    def withheld(self) -> bool:
        return bool(self.withheld_rule)

    def to_dict(self) -> dict[str, object]:
        return {
            "signal": self.signal,
            "unit": self.unit,
            "statistic": self.statistic,
            "reportable": self.reportable,
            "tolerance": self.tolerance,
            "confidence": self.confidence,
            "refusal": self.refusal,
            "bracket": self.bracket,
            "resolved": self.resolved,
            "resolution": self.resolution,
            "trials": self.trials,
            "insufficient_trials": list(self.insufficient_trials),
            "graded_verdict": self.graded_verdict,
            "effect_size": self.effect_size,
            "window_phases": self.window_phases,
            "support_refs": list(self.support_refs),
            "withheld": self.withheld,
            "withheld_rule": self.withheld_rule,
            "withheld_reason": self.withheld_reason,
        }


@dataclass(frozen=True, slots=True)
class MinimalCaseView:
    """The smallest tried reproduction, and whether minimality is certified."""

    found: bool
    size: int
    minimal: bool
    considered: int
    combination: str
    note: str
    support_refs: tuple[str, ...]
    withheld_rule: str
    withheld_reason: str

    @property
    def withheld(self) -> bool:
        return bool(self.withheld_rule)

    def to_dict(self) -> dict[str, object]:
        return {
            "found": self.found,
            "size": self.size,
            "minimal": self.minimal,
            "considered": self.considered,
            "combination": self.combination,
            "note": self.note,
            "support_refs": list(self.support_refs),
            "withheld": self.withheld,
            "withheld_rule": self.withheld_rule,
            "withheld_reason": self.withheld_reason,
        }


@dataclass(frozen=True, slots=True)
class BoundaryReportView:
    """Everything one recorded search produced, renderable without re-deriving it."""

    run_id: str
    policy_name: str
    strategy: str
    origin: str
    recorded_note: str
    recorded_bracket: str
    recorded_trials: int
    recorded_resolved: bool
    stop_reason: str
    budget_remaining: float
    signals: tuple[SignalBoundaryView, ...]
    minimal_case: MinimalCaseView | None
    evidence_complete: bool
    notes: tuple[str, ...]

    @property
    def authority(self) -> str:
        """Always :data:`AUTHORITY_NONE`. This surface granted nothing."""
        return AUTHORITY_NONE

    @property
    def withholdings(self) -> tuple[SignalBoundaryView | MinimalCaseView, ...]:
        rows: list[SignalBoundaryView | MinimalCaseView] = [
            signal for signal in self.signals if signal.withheld
        ]
        if self.minimal_case is not None and self.minimal_case.withheld:
            rows.append(self.minimal_case)
        return tuple(rows)

    @property
    def reportable_signals(self) -> tuple[SignalBoundaryView, ...]:
        return tuple(signal for signal in self.signals if signal.reportable)

    def to_dict(self) -> dict[str, object]:
        return {
            "via": SURFACE_VIA,
            "authority": self.authority,
            "closes_evidence": REVIEW_CLOSES_EVIDENCE,
            "run_id": self.run_id,
            "policy_name": self.policy_name,
            "strategy": self.strategy,
            "origin": self.origin,
            "recorded_note": self.recorded_note,
            "recorded_bracket": self.recorded_bracket,
            "recorded_trials": self.recorded_trials,
            "recorded_resolved": self.recorded_resolved,
            "stop_reason": self.stop_reason,
            "budget_remaining": self.budget_remaining,
            "signals": [signal.to_dict() for signal in self.signals],
            "minimal_case": None if self.minimal_case is None else self.minimal_case.to_dict(),
            "withholdings": [row.to_dict() for row in self.withholdings],
            "evidence_complete": self.evidence_complete,
            "notes": list(self.notes),
        }


def _signal_view(
    signal: SignalDocument,
    report: BoundaryReport,
    comparison: Comparison | None,
    segment: SegmentedSamples | None,
    claim: AnalyticsClaim | WithheldEvidence,
) -> SignalBoundaryView:
    reportable, line = _tolerates(report, comparison, signal.name, signal.statistic, signal.unit)
    effect = ""
    if comparison is not None and comparison.effect_size is not None:
        effect = (
            f"{comparison.statistic} on a {comparison.level * 100:g}% interval; Cohen's d "
            f"{comparison.effect_size.value:.2f} ({comparison.effect_size.magnitude})"
        )
    return SignalBoundaryView(
        signal=signal.name,
        unit=signal.unit,
        statistic=signal.statistic,
        reportable=reportable,
        tolerance=line,
        confidence=report.confidence_statement,
        refusal="" if reportable else line,
        bracket=_bracket_line(report),
        resolved=report.resolved,
        resolution=report.resolution,
        trials=report.trials,
        insufficient_trials=report.insufficient_trials,
        graded_verdict="" if comparison is None else comparison.verdict_phrase,
        effect_size=effect,
        window_phases=_phase_line(signal, segment),
        support_refs=claim.support_refs if isinstance(claim, AnalyticsClaim) else (),
        withheld_rule=claim.rule_id if isinstance(claim, WithheldEvidence) else "",
        withheld_reason=claim.reason if isinstance(claim, WithheldEvidence) else "",
    )


def _minimal_view(case: Any, evidence: Any) -> MinimalCaseView:
    claim = next(
        (
            item
            for item in (*evidence.claims, *evidence.withheld)
            if item.kind is ClaimKind.MINIMAL_FAILURE_CASE
        ),
        None,
    )
    return MinimalCaseView(
        found=case.found,
        size=case.size,
        minimal=case.minimal,
        considered=case.considered,
        combination="" if case.case is None else case.case.key(),
        note=case.note,
        support_refs=claim.support_refs if isinstance(claim, AnalyticsClaim) else (),
        withheld_rule=claim.rule_id if isinstance(claim, WithheldEvidence) else "",
        withheld_reason=claim.reason if isinstance(claim, WithheldEvidence) else "",
    )


def boundary_report_view(
    document: SearchDocument, *, only_signal: str = ""
) -> BoundaryReportView:
    """Turn a recorded search into the report a reader is allowed to see.

    Every number here is the engine's. A metric's boundary is
    :func:`~mayhem.controller.analytics_service.boundary_report` over *that
    metric's own* ladder — the same rungs, with the breach flag read off that
    metric's own comparison — so "the service tolerates latency ≤ X, loss ≤ Y" is
    two reports from one function rather than two spellings of one number. The
    ladder the search actually walked is reported beside them and is never used as
    either metric's tolerance.

    ``only_signal`` narrows the rendering to one declared metric and **refuses** an
    undeclared one: a report about a metric nobody recorded is not a report about
    that metric with an empty result.
    """
    if only_signal and only_signal not in {signal.name for signal in document.signals}:
        raise BoundaryViewRefused(
            RULE_REPORT_SIGNAL_UNKNOWN,
            f"the search document declares no signal {only_signal!r}; it declares "
            f"{[signal.name for signal in document.signals]}. A report about a metric that "
            "was not recorded is not a report about that metric with an empty result",
        )
    selected = tuple(
        signal
        for signal in document.signals
        if not only_signal or signal.name == only_signal
    )
    recorded_history = _recorded_history(document)
    recorded = boundary_report(document.policy, recorded_history)
    record = search_record_of(
        document.policy,
        history=recorded_history,
        admissions=(),
        stop=_stop_of(recorded_history),
        stop_note=(
            "the recorded ladder ended without a breach"
            if recorded.boundary is None
            else "the recorded ladder recorded a breach"
        ),
        budget_remaining=document.trials[-1].budget_remaining,
    )
    signals: list[SignalBoundaryView] = []
    for signal in selected:
        history, comparisons, segments = _signal_ladder(document, signal)
        report = boundary_report(document.policy, history, comparisons)
        index = _boundary_trial_index(history, report.boundary)
        comparison = comparisons.get(index) if index is not None else None
        segment = segments.get(index) if index is not None else None
        signals.append(
            _signal_view(signal, report, comparison, segment, boundary_claim(report))
        )
    analysis = analyze_run(
        document.policy,
        recorded_history,
        recovery=(),
        failure_cases=document.failure_cases,
    )
    evidence = analytics_evidence(analysis, run_id=document.run_id)
    return BoundaryReportView(
        run_id=document.run_id,
        policy_name=document.policy.name,
        strategy=document.policy.strategy.value,
        origin=record.origin.value,
        recorded_note=recorded.note,
        recorded_bracket=_bracket_line(recorded),
        recorded_trials=recorded.trials,
        recorded_resolved=recorded.resolved,
        stop_reason=record.stop.value,
        budget_remaining=record.budget_remaining,
        signals=tuple(signals),
        minimal_case=None if analysis.minimal_case is None else _minimal_view(
            analysis.minimal_case, evidence
        ),
        evidence_complete=evidence.complete,
        notes=analysis.notes,
    )


def search_document(path: Path) -> SearchDocument:
    """Read a search document. The only place the file format is interpreted."""
    return SearchDocument.from_path(path)


# =============================================================================
# Candidate review — one gate core, reached by both origins
# =============================================================================


def boundary_review_safety_context(
    *, fingerprint: str = "", deny_faults: frozenset[str] = frozenset()
) -> SafetyContext:
    """The one safety context candidate review evaluates against.

    No policy bundle, no plan-09 gate, no runtime adapter — as statements rather
    than omissions. With no bundle the policy state renders as
    :data:`POLICY_STATE_NO_BUNDLE` and not as "allowed"; with no adapter the
    capability line of the proof is unestablished and the proof comes out ``VOID``
    naming it, which is the honest answer for a surface with no runtime to ask;
    with no plan-09 gate the ``required_approvals`` line reports requirements and
    nothing more.

    The ceilings are the module constants, for the reason they are constants
    everywhere else on this surface. ``deny_faults`` exists because it can only
    *tighten* — a caller may narrow what may be reviewed and may never widen it.
    """
    from mayhem.config import PolicyCfg
    from mayhem.domain.experiments import BlastRadiusBudget

    return SafetyContext(
        policy=PolicyCfg(deny_faults=deny_faults),
        budget=BlastRadiusBudget(
            max_services_pct=REVIEW_CAP_MAX_SERVICES_PCT,
            max_hosts=REVIEW_CAP_MAX_HOSTS,
            max_concurrent_faults=REVIEW_CAP_MAX_CONCURRENT_FAULTS,
            max_duration_per_fault_s=REVIEW_CAP_MAX_DURATION_PER_FAULT_S,
            forbidden_fault_pairs=frozenset(),
        ),
        fingerprint=fingerprint,
    )


def _gate(
    spec: DrillSpec,
    *,
    run_id: str,
    graph: TopologyGraph,
    ctx: SafetyContext,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    environment_fingerprint: str,
    subject: str,
) -> tuple[ExecutionPlan, SafetyCompilation, PolicyGateResult | None]:
    """Compile one drill, prove it, and read its policy verdict.

    **This function has no origin parameter, and that is the acceptance
    criterion.** The authored arm and the generated arm both call it, so a
    generated candidate cannot reach a different compiler, a different proof, or
    a different policy verdict than an authored one — not because a test checked
    that it did, but because there is no second implementation for it to reach.

    The order is the safety order and is not interchangeable: ``plan_drill``
    raises here, upstream of the proof compiler and the policy gate, so a
    candidate that will not compile never receives a safety case or a policy
    verdict either. That refusal is re-raised as
    :data:`RULE_REVIEW_WILL_NOT_COMPILE` with ``subject`` naming the arm, so a
    reader is told *which* plan would not compile rather than being handed a
    planner sentence with no owner.
    """
    from mayhem.controller.planner import PlanningError

    try:
        plan = plan_drill(
            run_id,
            spec,
            graph,
            config_snapshot_id=config_snapshot_id,
            topology_snapshot_id=topology_snapshot_id,
            environment_fingerprint=environment_fingerprint,
        )
    except (PlanningError, LookupError) as exc:
        raise BoundaryViewRefused(
            RULE_REVIEW_WILL_NOT_COMPILE,
            f"the {subject} plan does not compile: {exc}. A candidate that cannot be "
            "compiled is refused here, before the proof compiler and the policy gate, so it "
            "never receives a safety case or a policy verdict either",
        ) from None
    compilation = compile_safety_evidence(plan, graph, ctx)
    policy = simulate_plan_policy(plan, ctx)
    return plan, compilation, policy


def _micro_spec(template: DrillSpec, step: SearchStep) -> DrillSpec:
    """The authored drill at one rung of the ladder.

    The candidate chooses *when* and *how hard*; the authored drill says *what*.
    Every fault's duration becomes ``step.value`` seconds and the fault ids,
    containers and execution blocks are the authored ones untouched — so a
    generated candidate cannot widen the blast radius by naming a fault the
    authored drill does not contain, and the plan it compiles is the authored
    plan at a different intensity rather than a plan of its own.

    Refused when the template declares no container: there would be nothing to
    narrow, and substituting a fault here would be inventing the very thing this
    surface exists to keep a candidate from doing.
    """
    containers = template.containers or {}
    if not containers:
        raise BoundaryViewRefused(
            RULE_REVIEW_WILL_NOT_COMPILE,
            "the authored drill declares no containers, so there is no experiment for a "
            "candidate to propose a rung of: a candidate may choose when and how hard, "
            "never what",
        )
    narrowed = {
        name: DrillContainer(
            faults=tuple(
                DrillFault(
                    fault=fault.fault,
                    duration=step.value,
                    on_failure=fault.on_failure,
                    recovery=fault.recovery,
                    targets=fault.targets,
                    network_path=fault.network_path,
                )
                for fault in container.faults
            )
        )
        for name, container in containers.items()
    }
    return template.model_copy(update={"containers": narrowed})


@dataclass(frozen=True, slots=True)
class ReviewArmView:
    """What one origin's plan got out of :func:`_gate`.

    ``gates_reached`` is :data:`GATE_PATH`, which is what :func:`_gate` calls; it
    is carried on the view so a reader and a test can compare the two arms
    without re-deriving it.
    """

    label: str
    origin: str
    trust: str
    plan_digest: str
    plan_shape_digest: str
    plan_type: str
    plan_steps: int
    proof_verdict: str
    proof_void_reason: str
    admitted_by_gate: bool
    refusing_gates: tuple[str, ...]
    compiler_refusals: tuple[str, ...]
    policy_state: str
    approval_line_state: str
    gates_reached: tuple[str, ...] = GATE_PATH

    @property
    def authority(self) -> str:
        """Always :data:`AUTHORITY_NONE`, read from nothing.

        This surface holds no plan-09 gate, so nothing could have been granted
        through it, and :func:`~mayhem.controller.analytics_service.compile_candidate`
        returns a plan that cannot be constructed with an approval at all.
        """
        return AUTHORITY_NONE

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "origin": self.origin,
            "trust": self.trust,
            "authority": self.authority,
            "plan_digest": self.plan_digest,
            "plan_shape_digest": self.plan_shape_digest,
            "plan_type": self.plan_type,
            "plan_steps": self.plan_steps,
            "proof_verdict": self.proof_verdict,
            "proof_void_reason": self.proof_void_reason,
            "admitted_by_gate": self.admitted_by_gate,
            "refusing_gates": list(self.refusing_gates),
            "compiler_refusals": list(self.compiler_refusals),
            "policy_state": self.policy_state,
            "approval_line_state": self.approval_line_state,
            "gates_reached": list(self.gates_reached),
        }


@dataclass(frozen=True, slots=True)
class CandidateReviewView:
    """A generated candidate reviewed beside the authored plan it perturbs."""

    via: str
    run_id: str
    policy_name: str
    candidate_rationale: str
    candidate_index: int
    candidate_value: float
    candidate_combination: str
    candidate_plan_digest: str
    authored: ReviewArmView
    generated: ReviewArmView
    safety_decisions_recorded: int
    safety_warnings_recorded: int

    @property
    def authority(self) -> str:
        return AUTHORITY_NONE

    @property
    def same_gates(self) -> bool:
        """The acceptance criterion, first half: the same gates, in the same order."""
        return self.authored.gates_reached == self.generated.gates_reached

    @property
    def same_verdict(self) -> bool:
        """The same gate verdict on both plans."""
        return (self.authored.admitted_by_gate, self.authored.refusing_gates) == (
            self.generated.admitted_by_gate,
            self.generated.refusing_gates,
        )

    @property
    def identical_plan(self) -> bool:
        """Same type, same shape digest: downstream of :func:`_gate` the two are one plan.

        ``True`` whenever a generated candidate proposes the rung the authored
        drill already encodes, and it is the strongest statement the acceptance
        criterion allows — not "the report reads the same" but "the two compiles
        differ in nothing". The comparison is on :func:`plan_shape_digest` rather
        than on the compiler's own digest, because ``plan_drill`` mints a fresh
        execution-group id on every call and so no two independent compiles are
        ever byte-identical; see that function for why holding that one identifier
        out is the strongest claim two compiles can support.
        """
        return (
            self.authored.plan_type == self.generated.plan_type
            and self.authored.plan_shape_digest == self.generated.plan_shape_digest
        )

    @property
    def indistinguishable(self) -> bool:
        return self.same_gates and self.authored.plan_type == self.generated.plan_type

    def to_dict(self) -> dict[str, object]:
        return {
            "via": self.via,
            "authority": self.authority,
            "closes_evidence": REVIEW_CLOSES_EVIDENCE,
            "run_id": self.run_id,
            "policy_name": self.policy_name,
            "candidate": {
                "origin": self.generated.origin,
                "trust": self.generated.trust,
                "authority": self.generated.authority,
                "rationale": self.candidate_rationale,
                "step_index": self.candidate_index,
                "step_value": self.candidate_value,
                "combination": self.candidate_combination,
                "plan_digest": self.candidate_plan_digest,
            },
            "authored": self.authored.to_dict(),
            "generated": self.generated.to_dict(),
            "acceptance": {
                "same_gates": self.same_gates,
                "same_gate_verdict": self.same_verdict,
                "same_plan_type": self.authored.plan_type == self.generated.plan_type,
                "identical_plan": self.identical_plan,
                "indistinguishable": self.indistinguishable,
            },
            "mutation": {
                "safety_decisions_recorded": self.safety_decisions_recorded,
                "safety_warnings_recorded": self.safety_warnings_recorded,
            },
        }


def plan_shape_digest(plan: ExecutionPlan) -> str:
    """The plan's digest with the planner's per-call execution-group id held out.

    :func:`~mayhem.controller.planner.plan_drill` mints a fresh
    ``execution_group_id`` on every call, so **no** two independent compiles of the
    same spec are byte-identical — not an authored one and itself either. Holding
    that one per-call identifier constant is what makes "the same plan" a
    checkable statement across two separate compiles, and it is the strongest one
    available: any other difference, including an origin stamped anywhere on the
    plan, still moves this digest.
    """
    payload = plan.model_dump(mode="json")
    for step in payload.get("steps", []):
        if isinstance(step, dict):
            step.pop("execution_group_id", None)
    return digest(payload)


def _arm_view(
    label: str,
    origin: SearchOrigin,
    plan: ExecutionPlan,
    compilation: SafetyCompilation,
    policy: PolicyGateResult | None,
) -> ReviewArmView:
    from mayhem.domain.safety_proof import ObligationName, ObligationStatus

    line = compilation.proof.obligation(ObligationName.REQUIRED_APPROVALS.value)
    if line is None:
        approval_state = "not_evaluated"
    elif line.status is ObligationStatus.PASS:
        approval_state = "requirements_only"
    else:
        approval_state = "refused"
    return ReviewArmView(
        label=label,
        origin=origin.value,
        trust="authored" if origin is SearchOrigin.AUTHORED else "untrusted",
        plan_digest=compilation.plan_digest,
        plan_shape_digest=plan_shape_digest(plan),
        plan_type=type(plan).__name__,
        plan_steps=len(plan.steps),
        proof_verdict=compilation.proof.verdict.value,
        proof_void_reason=compilation.void_reason,
        admitted_by_gate=not compilation.gate_refusals,
        refusing_gates=tuple(compilation.gate_refusals),
        compiler_refusals=tuple(compilation.compiler_refusals),
        policy_state=(
            POLICY_STATE_NO_BUNDLE
            if policy is None
            else ("allowed" if policy.allowed else "refused")
        ),
        approval_line_state=approval_state,
    )


def candidate_review_view(
    *,
    candidate: Mapping[str, Any],
    policy: SearchPolicy,
    spec: DrillSpec,
    graph: TopologyGraph,
    ctx: SafetyContext,
    run_id: str = "r-boundary-review",
    config_snapshot_id: str = "review",
    topology_snapshot_id: str = "review",
    environment_fingerprint: str = "",
) -> CandidateReviewView:
    """Review a generated candidate beside the authored plan it perturbs.

    Three steps, in this order:

    1. **Compile the draft.**
       :func:`~mayhem.controller.analytics_service.compile_candidate` turns the
       raw payload into a :class:`~mayhem.domain.search.SearchPlan` with
       ``origin=generated`` and no approval. It is the *only* authority scan on
       this path, so a draft carrying a token is refused there, by name, before
       anything below runs.
    2. **Derive the micro-drill.** :func:`_micro_spec` narrows the authored drill
       to the rung the candidate proposed.
    3. **Gate both arms through :func:`_gate`.** One function, no origin branch.

    The mutation evidence is the caller's own safety context:
    :func:`~mayhem.controller.safety_proof.compile_safety_evidence` runs every
    probe against a clone, so a review that ran the real gates leaves
    ``ctx.decisions`` empty — and the view *reports* the length rather than
    asserting it.
    """
    # No unknown-field refusal here: `compile_candidate` owns the candidate's
    # field discipline *and* its authority scan, and it checks authority first. A
    # second refusal on this surface would shadow `analytics.draft_carries_authority`
    # with a rule that says only "I did not expect that key" — which is a weaker
    # answer to the same document, and one that would let the two drift apart.
    plan: SearchPlan = compile_candidate(candidate, policy)
    micro = _micro_spec(spec, plan.step)
    authored_plan, authored_compilation, authored_policy = _gate(
        spec,
        run_id=run_id,
        graph=graph,
        ctx=ctx,
        config_snapshot_id=config_snapshot_id,
        topology_snapshot_id=topology_snapshot_id,
        environment_fingerprint=environment_fingerprint,
        subject="authored",
    )
    generated_plan, generated_compilation, generated_policy = _gate(
        micro,
        run_id=run_id,
        graph=graph,
        ctx=ctx,
        config_snapshot_id=config_snapshot_id,
        topology_snapshot_id=topology_snapshot_id,
        environment_fingerprint=environment_fingerprint,
        subject="generated candidate",
    )
    return CandidateReviewView(
        via=SURFACE_VIA,
        run_id=run_id,
        policy_name=policy.name,
        candidate_rationale=plan.rationale,
        candidate_index=plan.step.index,
        candidate_value=plan.step.value,
        candidate_combination=plan.step.combination,
        candidate_plan_digest=generated_compilation.plan_digest,
        authored=_arm_view(
            "authored", SearchOrigin.AUTHORED, authored_plan, authored_compilation, authored_policy
        ),
        generated=_arm_view(
            "generated", SearchOrigin.GENERATED, generated_plan, generated_compilation,
            generated_policy,
        ),
        safety_decisions_recorded=len(ctx.decisions),
        safety_warnings_recorded=len(ctx.warnings),
    )


def review_document(path: Path) -> Mapping[str, Any]:
    """Read the untrusted candidate payload."""
    return _block(
        _read_json(path, what="candidate", rule=RULE_REVIEW_UNKNOWN_FIELD),
        where="the candidate document",
        rule=RULE_REVIEW_UNKNOWN_FIELD,
    )


# =============================================================================
# Renderers — every one prints a view and re-derives nothing
# =============================================================================


def render_boundary_report(view: BoundaryReportView) -> tuple[str, ...]:
    """A boundary report, as text.

    The tolerance lines come from :func:`_tolerates` and nowhere else, and the
    withholding section is printed whatever it holds — including when it holds
    every signal, which is the case where a reader most needs to be told the
    search established nothing.
    """
    lines = [
        style.cyan(f"boundary report — run {view.run_id} · policy {view.policy_name!r}"),
        f"  strategy: {view.strategy}   origin: {view.origin}   stop: {view.stop_reason}   "
        f"budget remaining: {view.budget_remaining:g}",
        f"  recorded ladder: {view.recorded_trials} trial(s), bracket {view.recorded_bracket}, "
        f"resolved: {str(view.recorded_resolved).lower()}",
        f"  recorded note: {view.recorded_note or '(none)'}",
    ]
    for signal in view.signals:
        unit = f" {signal.unit}"
        lines.append(style.cyan(f"signal {signal.signal} ({signal.statistic}{unit})"))
        lines.append(
            f"  tolerance: {signal.tolerance}"
            if signal.reportable
            else f"  tolerance: WITHHELD — {signal.refusal}"
        )
        lines.append(f"  confidence: {signal.confidence}")
        if signal.graded_verdict:
            lines.append(f"  at the boundary: {signal.graded_verdict}")
        if signal.effect_size:
            lines.append(f"  effect: {signal.effect_size}")
        lines.append(f"  bracket: {signal.bracket}   resolved: {str(signal.resolved).lower()}")
        lines.append(f"  window: {signal.window_phases}")
        if signal.insufficient_trials:
            lines.append(
                f"  insufficient rungs: {list(signal.insufficient_trials)} — an unmeasurable "
                "trial is not a clearance and is not counted as one"
            )
        lines.append(f"  support: {len(signal.support_refs)} citation(s) behind this report")
        if signal.withheld:
            lines.append(
                style.warn(f"  withheld [{signal.withheld_rule}]: {signal.withheld_reason}")
            )
    lines.append(style.cyan("minimal failure case"))
    case = view.minimal_case
    if case is None:
        lines.append(
            "  not run: the search document declares no fault/target combination. Absence here "
            "is not evidence that no minimal case exists"
        )
    else:
        if not case.found:
            lines.append(f"  found: no — {case.note}")
        else:
            lines.append(
                f"  found: {case.combination} ({case.size} component(s)); minimal: "
                f"{'certified' if case.minimal else 'NOT CERTIFIED — smallest tried'}"
            )
            lines.append(f"  considered: {case.considered} measurable case(s)")
            lines.append(f"  note: {case.note}")
        lines.append(f"  support: {len(case.support_refs)} citation(s)")
        if case.withheld:
            lines.append(
                style.warn(f"  withheld [{case.withheld_rule}]: {case.withheld_reason}")
            )
    if view.withholdings:
        lines.append(
            style.warn(
                f"withheld sections ({len(view.withholdings)}) — nothing was omitted from "
                "this report"
            )
        )
        for row in view.withholdings:
            lines.append(f"  - [{row.withheld_rule}] {row.withheld_reason}")
    lines.append(f"evidence complete: {str(view.evidence_complete).lower()}")
    lines.extend(f"note: {note}" for note in view.notes)
    lines.append(
        f"this command reports: authority {view.authority}; no target perturbed, no run "
        f"recorded, no evidence sealed (closes_evidence: {REVIEW_CLOSES_EVIDENCE})"
    )
    return tuple(lines)


def _arm_block(label: str, arm: ReviewArmView) -> str:
    verdict = "refused" if arm.refusing_gates else "admitted"
    rules = f" {list(arm.refusing_gates)}" if arm.refusing_gates else ""
    void = f" — {arm.proof_void_reason}" if arm.proof_void_reason else ""
    return (
        f"  {label} plan: {arm.plan_type} {arm.plan_digest[:12]}… ({arm.plan_steps} step(s))\n"
        f"  proof: {arm.proof_verdict}{void}\n"
        f"  gate: {verdict}{rules}\n"
        f"  policy: {arm.policy_state}\n"
        f"  required_approvals line: {arm.approval_line_state} (requirements, not a grant)"
    )


def render_candidate_review(view: CandidateReviewView) -> tuple[str, ...]:
    """A candidate review, as text.

    The gate transcript is *rule ids* rather than the gates' prose, so the two
    arms can be compared line for line and so no sentence composed elsewhere in
    this repository can be read here as a verdict about this candidate.
    """
    generated = view.generated
    authored = view.authored
    lines = [
        style.cyan(f"candidate review — policy {view.policy_name!r} · run {view.run_id}"),
        f"  via: {view.via}   authority: {view.authority}   closes evidence: "
        f"{REVIEW_CLOSES_EVIDENCE}",
        style.cyan("generated candidate"),
        f"  origin: {generated.origin}   trust: {generated.trust}   authority: "
        f"{generated.authority}",
        f"  rung: step {view.candidate_index} at {view.candidate_value:g} "
        f"(combination {view.candidate_combination!r})",
        f"  rationale: {view.candidate_rationale or '(none stated)'}",
        f"  compiled: {generated.plan_type} {generated.plan_digest[:12]}… "
        f"({generated.plan_steps} step(s))",
        style.cyan("gates reached — the same for both origins"),
    ]
    for index, gate in enumerate(generated.gates_reached, start=1):
        lines.append(f"  {index}. {gate}")
    lines.append(
        f"  identical to the authored plan: {str(view.same_gates).lower()}   same gate "
        f"verdict: {str(view.same_verdict).lower()}"
    )
    lines.append(_arm_block("generated", generated))
    lines.append(style.cyan("authored plan (the reference this candidate perturbs)"))
    lines.append(
        f"  origin: {authored.origin}   trust: {authored.trust}   authority: {authored.authority}"
    )
    lines.append(_arm_block("authored", authored))
    lines.append(style.cyan("acceptance"))
    lines.append(
        "  indistinguishable downstream of compilation: "
        f"{str(view.indistinguishable).lower()} (same type {authored.plan_type}, same gates "
        f"{list(generated.gates_reached)})"
    )
    lines.append(
        f"  identical compiled plan: {str(view.identical_plan).lower()}"
        + (
            ""
            if view.identical_plan
            else " — the candidate proposes a rung the authored drill does not already encode, "
            "so the two plans differ in their numbers and not in their type or their gates"
        )
    )
    lines.append(
        f"mutation: {view.safety_decisions_recorded} safety decision(s) and "
        f"{view.safety_warnings_recorded} warning(s) recorded on this review's own context; "
        "no store opened, no executor attached, nothing sealed"
    )
    lines.append("next: a person, through the ordinary approval chain")
    return tuple(lines)


# =============================================================================
# The commands
# =============================================================================


def _call(thunk: Callable[[], Any]) -> Any:
    """The one place a refusal crosses from the domain into a CLI envelope."""
    try:
        return thunk()
    except InvariantViolationError as exc:
        raise MayhemCliError(
            code="safety_refusal",
            message=str(exc),
            details={"rule": exc.rule},
            remediation=(
                "a boundary report and a candidate review are refused rather than degraded: "
                "the rung, the sample, the gate, or the authority the refusal names has to "
                "be satisfied first"
            ),
        ) from None


def _echo(lines: Sequence[str]) -> None:
    for line in lines:
        click.echo(line)


@click.group("boundary", help="Report a resilience boundary; review a generated candidate.")
def boundary() -> None:
    """Resilience boundaries, minimal failure cases, and candidate review.

    Everything here is **read + decide**. It reports what a recorded search
    established and what an untrusted candidate faces, and it perturbs nothing: no
    store is opened, no executor is attached, and no evidence is sealed.

    There is no ``--force``, no ``--approve``, and no flag that loosens a
    blast-radius ceiling — a caller handed the ceiling is handed the gate that is
    supposed to be checking it. A candidate that would fail a gate is refused by
    that gate, and the refusal names it.
    """


@boundary.command("report", help="Render a recorded search as a boundary report.")
@click.option(
    "--search",
    "search_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    metavar="FILE",
    help="A JSON document of the recorded ladder and the sample series captured at each rung.",
)
@click.option(
    "--signal",
    "only_signal",
    default="",
    metavar="NAME",
    help="Render only this declared metric. An undeclared name is refused rather than "
    "rendered as an empty result.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the JSON projection instead of text.")
def report(search_path: Path, only_signal: str, as_json: bool) -> None:
    """Render one recorded search: the tolerance, the confidence, and the support.

    The document is read as **observations**, never as a finished report: the
    ladder and its sample series go to the analytics engine, which owns the
    boundary, the bracket, the sufficiency floor and the warm-up/cooldown split. A
    boundary whose measurement at its edge was insufficient or ungraded renders as
    a withholding that names the reason — it never renders as a tolerance — and a
    section with no support is printed as a withholding rather than dropped.
    """
    document = _call(lambda: search_document(search_path))
    view = _call(lambda: boundary_report_view(document, only_signal=only_signal))
    if echo_machine(view.to_dict(), as_json=as_json):
        return
    _echo(render_boundary_report(view))


@boundary.command("review", help="Review a generated candidate beside the authored plan.")
@click.option(
    "--candidate",
    "candidate_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    metavar="FILE",
    help="The advisor's raw candidate payload: {step, rationale}. Untrusted, and scanned by "
    "the analytics domain's one authority check and by nothing else.",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    metavar="FILE",
    help="The authored search policy the candidate is compiled against. Deliberately not "
    "read from the candidate: a draft that declared its own ladder would be declaring its "
    "own budget.",
)
@click.option(
    "--spec",
    "spec_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    metavar="FILE",
    help="The authored drill (YAML or JSON) the candidate perturbs. The candidate chooses "
    "when and how hard; the fault, the target and the execution blocks are these.",
)
@click.option(
    "--graph",
    "graph_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    metavar="FILE",
    help="A serialized topology graph — the environment both plans are compiled and gated "
    "against.",
)
@click.option(
    "--run-id",
    default="r-boundary-review",
    show_default=True,
    metavar="ID",
    help="Run id both plans compile under, so their digests are comparable.",
)
@click.option(
    "--config-snapshot-id",
    default="review",
    show_default=True,
    metavar="ID",
    help="Config snapshot id stamped on both plans.",
)
@click.option(
    "--topology-snapshot-id",
    default="review",
    show_default=True,
    metavar="ID",
    help="Topology snapshot id stamped on both plans.",
)
@click.option(
    "--fingerprint",
    default="",
    metavar="HEX",
    help="Environment fingerprint, applied to both the plan and the safety context. Empty "
    "by default: this surface has no environment to measure, and the two plans are "
    "compared with each other rather than admitted against a live one.",
)
@click.option(
    "--deny-fault",
    "deny_faults",
    multiple=True,
    metavar="FAULT_ID",
    help="Refuse a review of this fault id. Repeatable. Tightens the config-policy half "
    "only — there is no flag here that widens anything.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the JSON projection instead of text.")
def review(
    candidate_path: Path,
    policy_path: Path,
    spec_path: Path,
    graph_path: Path,
    run_id: str,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    fingerprint: str,
    deny_faults: tuple[str, ...],
    as_json: bool,
) -> None:
    """Compile a generated candidate, then gate it exactly as an authored plan.

    The candidate is compiled by the analytics domain into the **same**
    ``SearchPlan`` an authored proposal uses, with ``origin=generated`` and nowhere
    to put an approval. The surface derives the micro-drill it proposes and hands
    that, together with the authored drill, to one gate core —
    ``plan_drill`` → ``compile_safety_evidence`` → ``simulate_plan_policy`` — that
    has no origin parameter. Downstream of it the two plans are the same type
    carrying the same gates, and when the candidate proposes the rung the authored
    drill already encodes the two compiled plans are byte-identical.

    A candidate carrying an approval token is refused before any of that, by the
    domain's single authority scan. A candidate that will not compile never
    receives a safety case or a policy verdict. And this command grants nothing:
    the view reports ``authority: none`` and the next step belongs to a person.
    """
    from mayhem.domain.topology import TopologyGraph
    from mayhem.spec import parse_drill

    candidate = _call(lambda: review_document(candidate_path))
    policy_document = _call(
        lambda: _block(
            _read_json(policy_path, what="policy", rule=RULE_REVIEW_UNKNOWN_FIELD),
            where="the policy document",
            rule=RULE_REVIEW_UNKNOWN_FIELD,
        )
    )
    _call(lambda: _policy_fields(policy_document, rule=RULE_REVIEW_UNKNOWN_FIELD))
    policy = SearchPolicy.model_validate(policy_document)
    spec = _call(lambda: parse_drill(_spec_body(spec_path)))
    graph = _call(
        lambda: TopologyGraph.model_validate(
            _read_json(graph_path, what="graph", rule=RULE_REVIEW_UNKNOWN_FIELD)
        )
    )
    ctx = boundary_review_safety_context(
        fingerprint=fingerprint, deny_faults=frozenset(deny_faults)
    )
    view = _call(
        lambda: candidate_review_view(
            candidate=candidate,
            policy=policy,
            spec=spec,
            graph=graph,
            ctx=ctx,
            run_id=run_id,
            config_snapshot_id=config_snapshot_id,
            topology_snapshot_id=topology_snapshot_id,
            environment_fingerprint=fingerprint,
        )
    )
    if echo_machine(view.to_dict(), as_json=as_json):
        return
    _echo(render_candidate_review(view))


def _spec_body(path: Path) -> Any:
    import yaml

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MayhemCliError(
            code="validation_error",
            message=f"the drill spec {str(path)!r} could not be read: {exc}",
            details={"path": str(path)},
            remediation="check the path and its permissions",
        ) from None
    if path.suffix.lower() == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise MayhemCliError(
                code="validation_error",
                message=f"the drill spec {str(path)!r} is not valid JSON: {exc}",
                details={"path": str(path)},
                remediation="a drill spec is YAML (or JSON); mayhem will not guess at it",
            ) from None
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise MayhemCliError(
            code="validation_error",
            message=f"the drill spec {str(path)!r} is not valid YAML: {exc}",
            details={"path": str(path)},
            remediation="a drill spec is YAML (or JSON); mayhem will not guess at it",
        ) from None
