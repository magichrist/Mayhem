"""CI/CD pipeline decisions: pin completeness, evidence, fail-closed checks (plan 16).

Why this file exists
--------------------
Plan 16 turns Mayhem into a developer workflow, and the failure modes of that
surface are all *silent* ones. A PR check that could not reach the control plane
renders as a green tick nobody investigates; a release gate that reads an
unpinned run looks exactly like one that read a pinned one; a plan that changed
between review and merge keeps the approvals it was refused. None of these make
a sound, and each is a decision made from an absence.

So the tests are grouped as:

* **pin completeness.** The five required axes, what "missing" names, and the
  central acceptance criterion of Phase 1 — a run missing any required pin
  cannot back a release-gate decision. Verified through
  :func:`~mayhem.domain.pipeline.gates_release`, because a rule nobody can
  exercise is a rule nobody should rely on.
* **verdicts carry evidence.** A verdict with no evidence reference is not
  constructible; a pass over a check that did not pass is not constructible
  either; and the gate re-derives its answer rather than reading the stored
  ``outcome``.
* **UNKNOWN, never PASS.** The fail-closed rule, from both sides: an unreachable
  control plane may only report unknown, and an unknown check blocks the
  pipeline instead of being downgraded to a warning.
* **coverage deltas.** The four honest readings of a coverage report — newly
  covered, lost, settled, and the case that is not a delta at all.
* **invalidation on plan change.** A merge that lands a different plan than the
  one that was checked takes back every approval, not just the mismatched ones.
* **the negative controls.** The three forgeries the phase has to refuse: a
  failing resilience verdict that fails the pipeline, an unpinned run that
  cannot gate a release, and a check reporting pass with no evidence.
* **comparability.** The pipeline's "same experiment, new release" predicate,
  checked against plan 22's axis list rather than a second copy of it.

The last test re-states the domain law locally: this module may not import the
toolkit, agents, controller, infra, or the IO modules. ``pyproject.toml``'s
import-linter contract enforces the same thing in CI, but that check needs an
extra dependency, so the guard also lives here.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import ValidationError

import mayhem.domain.pipeline as pipeline_module
from mayhem.domain.comparison import EQUIVALENCE_FIELDS, RunPin
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.decisions import DECISION_M4_3_SUCCESS_CRITERIA, DecisionRef
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.pipeline import (
    REQUIRED_PINS,
    ChangeLink,
    CheckFinding,
    CheckOutcome,
    CheckScope,
    ControlPlaneReach,
    CoverageDelta,
    FindingSeverity,
    PipelineOutcome,
    PipelinePins,
    PipelineVerdict,
    PlanApproval,
    PlanMerge,
    PRCheck,
    blocking_reasons,
    comparable_across_release,
    gates_release,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

# ── fixtures ────────────────────────────────────────────────────────────────────

CHECKED_AT = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
MERGED_AT = datetime(2026, 9, 30, 13, 0, tzinfo=UTC)


def naive_moment(hour: int = 12) -> datetime:
    """A deliberately naive datetime — the input every tz-discipline check refuses."""
    return datetime(2026, 9, 30, hour, 0)  # noqa: DTZ001


#: Two digests standing in for "the plan that was checked" and "the plan that
#: actually merged". Never equal unless a test says so.
CHECKED_DIGEST = "a" * 64
MERGED_DIGEST = "b" * 64

#: The run's sealed evidence digest. A run that cannot be cited cannot be pinned.
RUN_DIGEST = "0" * 64

CHECKOUT_POSTGRES = CoverageCell(
    target="checkout",
    fault_kind="postgres_failure",
    execution_context="container",
    parameter_band="default",
)
PAYMENT_TIMEOUT = CoverageCell(
    target="payment",
    fault_kind="http_timeout",
    execution_context="kubernetes",
    parameter_band="default",
)


def _pin(**overrides: Any) -> RunPin:
    """A fully pinned v2.5 run; override any axis, including the release."""
    fields: dict[str, Any] = {
        "run_id": "run-v25-0001",
        "experiment": "checkout-resilience",
        "release": "v2.5",
        "environment": "staging",
        "plan_version": "plan-7",
        "policy_version": "policy-7",
        "catalog_version": "catalog-2026.09",
        "agent_version": "agent-2.0.0",
        "runtime_version": "runtime-2.1.0",
        "evidence_digest": RUN_DIGEST,
    }
    fields.update(overrides)
    return RunPin(**fields)


def _link(**overrides: Any) -> ChangeLink:
    """A change link that agrees with :func:`_pin` on every axis."""
    fields: dict[str, Any] = {
        "git_sha": "a1b2c3d",
        "change_ticket": "CH-1421",
        "pins": PipelinePins.from_run(_pin()),
        "linked_at": CHECKED_AT,
    }
    fields.update(overrides)
    return ChangeLink(**fields)


def _passing_check(**overrides: Any) -> PRCheck:
    fields: dict[str, Any] = {
        "name": "resilience",
        "scope": CheckScope.RESILIENCE,
        "outcome": CheckOutcome.PASS,
        "evidence_refs": ("bundle:sha-abc",),
        "observed_at": CHECKED_AT,
    }
    fields.update(overrides)
    return PRCheck(**fields)


def _syntax_check(**overrides: Any) -> PRCheck:
    fields: dict[str, Any] = {
        "name": "syntax",
        "scope": CheckScope.SYNTAX,
        "outcome": CheckOutcome.PASS,
        "evidence_refs": ("validate:stdout",),
        "observed_at": CHECKED_AT,
    }
    fields.update(overrides)
    return PRCheck(**fields)


def _failure(
    code: str = "coverage.gap",
    *,
    severity: FindingSeverity = FindingSeverity.ERROR,
) -> CheckFinding:
    return CheckFinding(
        code=code,
        message="checkout has no experiment covering PostgreSQL failure",
        remediation="add a postgres drill to the checkout experiment",
        severity=severity,
        cell=CHECKOUT_POSTGRES,
    )


def _unreachable_check(**overrides: Any) -> PRCheck:
    fields: dict[str, Any] = {
        "name": "policy",
        "scope": CheckScope.SAFETY_POLICY,
        "outcome": CheckOutcome.UNKNOWN,
        "control_plane": ControlPlaneReach.UNREACHABLE,
        "detail": "control plane at mayhem.internal:8443 did not answer in 30s",
        "observed_at": CHECKED_AT,
    }
    fields.update(overrides)
    return PRCheck(**fields)


def _failing_check(**overrides: Any) -> PRCheck:
    fields: dict[str, Any] = {
        "name": "blast-radius",
        "scope": CheckScope.BLAST_RADIUS,
        "outcome": CheckOutcome.FAIL,
        "finding": _failure("blast.radius_exceeded"),
        "evidence_refs": ("proof:sha-def",),
        "detail": "requested 4 services, ceiling is 2",
        "observed_at": CHECKED_AT,
    }
    fields.update(overrides)
    return PRCheck(**fields)


def _passing_verdict(**overrides: Any) -> PipelineVerdict:
    """A green release-gate verdict: two passing checks, a pinned run, a link."""
    fields: dict[str, Any] = {
        "outcome": PipelineOutcome.PASS,
        "change": _link(),
        "checks": (_syntax_check(), _passing_check()),
        "evidence_refs": ("validate:stdout", "bundle:sha-abc"),
        "cited_run": _pin(),
        "decision_refs": (DECISION_M4_3_SUCCESS_CRITERIA,),
        "decided_at": CHECKED_AT,
    }
    fields.update(overrides)
    return PipelineVerdict(**fields)


def _all_pins(**overrides: Any) -> dict[str, str]:
    pins: dict[str, str] = {axis: f"{axis}-v1" for axis in REQUIRED_PINS}
    pins.update(overrides)
    return pins


def _delta(cell: CoverageCell, before: CellState, after: CellState) -> CoverageDelta:
    return CoverageDelta(cell=cell, before=before, after=after)


# ── pin completeness (Phase 1's acceptance criterion) ──────────────────────────


def test_the_required_pins_are_the_last_five_axes_plan_22_compares_on() -> None:
    """A pipeline decision is a comparison decision; the two must not disagree."""
    assert EQUIVALENCE_FIELDS[2:7] == REQUIRED_PINS
    assert REQUIRED_PINS == (
        "plan_version",
        "policy_version",
        "catalog_version",
        "agent_version",
        "runtime_version",
    )


def test_a_fully_pinned_link_is_attributable() -> None:
    link = _link()
    assert link.pins.complete
    assert not link.pins.missing
    assert link.attributable


def test_missing_names_the_axes_rather_than_counting_them() -> None:
    """'policy_version' is a question an operator can answer; '2 missing' is not."""
    pins = PipelinePins(plan_version="plan-7")
    assert pins.missing == ("policy_version", "catalog_version", "agent_version", "runtime_version")
    assert not pins.complete
    # Report order is the declaration order, so a refusal reads stably.
    assert pins.missing == tuple(axis for axis in REQUIRED_PINS if axis not in {"plan_version"})


def test_an_unpinned_run_cannot_gate_a_release() -> None:
    """Phase 1's acceptance criterion, read through the gate that enforces it."""
    unpinned = _link(pins=PipelinePins())
    verdict = _passing_verdict(change=unpinned)

    assert not gates_release(verdict)
    reasons = blocking_reasons(verdict)
    assert len(reasons) == 1
    assert "cannot back a release-gate decision" in reasons[0]
    for axis in REQUIRED_PINS:
        assert axis in reasons[0]


@pytest.mark.parametrize("blanked", REQUIRED_PINS)
def test_a_run_missing_any_single_required_pin_cannot_gate_a_release(blanked: str) -> None:
    """'Any' is tested one axis at a time — a rule that only bites on all five at
    once is not a rule about 'any'."""
    fields = _all_pins()
    fields[blanked] = ""
    verdict = _passing_verdict(change=_link(pins=PipelinePins(**fields)))

    assert not gates_release(verdict)
    assert PipelinePins(**fields).missing == (blanked,)
    assert f"{blanked} unpinned" in blocking_reasons(verdict)[0]


def test_a_link_pins_differently_from_the_run_it_cites_blocks_the_gate() -> None:
    """A link pinned to policy 8 that cites a policy-7 run attributes the
    decision to a policy the run never saw."""
    verdict = _passing_verdict(
        change=_link(pins=PipelinePins.from_run(_pin(policy_version="policy-8")))
    )

    assert not gates_release(verdict)
    assert "policy_version" in blocking_reasons(verdict)[0]


def test_an_incomplete_link_reports_the_blanks_once_rather_than_twice() -> None:
    """Each blank axis is named once. The disagreement check is suppressed while
    the link is incomplete, so a refusal does not say the same sentence five
    times."""
    verdict = _passing_verdict(change=_link(pins=PipelinePins()))

    assert len(blocking_reasons(verdict)) == 1


def test_pins_taken_from_a_run_agree_with_that_run() -> None:
    pin = _pin(plan_version="plan-9", policy_version="policy-3")
    assert PipelinePins.from_run(pin).matches_run(pin)
    assert not PipelinePins.from_run(pin).matches_run(_pin())


def test_pins_difference_names_the_axes_that_moved() -> None:
    left = PipelinePins.from_run(_pin())
    right = PipelinePins.from_run(_pin(agent_version="agent-3.0.0"))
    assert left.differences_from(right) == ("agent_version",)
    assert right.differences_from(left) == ("agent_version",)
    assert left.differences_from(left) == ()


def test_an_unknown_pin_axis_is_refused_rather_than_reported_blank() -> None:
    """Returning '' for a typo'd axis would let a misspelled pin look unpinned
    rather than wrong."""
    with pytest.raises(InvariantViolationError) as excinfo:
        _link().pins.axis("planversion")

    assert excinfo.value.rule == "pipeline.unknown_pin_axis"


# ── a verdict carries its evidence ──────────────────────────────────────────────


def test_a_verdict_with_no_evidence_link_is_refused() -> None:
    with pytest.raises(ValidationError):
        PipelineVerdict(
            outcome=PipelineOutcome.PASS,
            change=_link(),
            checks=(_syntax_check(),),
            evidence_refs=(),
            cited_run=_pin(),
        )


@pytest.mark.parametrize("refs", [("",), ("bundle:a", " "), ("bundle:a", "bundle:a")])
def test_a_verdict_with_a_blank_or_repeated_evidence_ref_is_refused(
    refs: Sequence[str],
) -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _passing_verdict(evidence_refs=tuple(refs))

    assert excinfo.value.rule in {"pipeline_blank_evidence_ref", "pipeline_duplicate_evidence_ref"}


def test_a_verdict_says_which_run_and_which_change_it_is_about() -> None:
    verdict = _passing_verdict()
    payload: dict[str, Any] = verdict.to_dict()

    assert payload["outcome"] == "pass"
    assert payload["cited_run"] == "checkout-resilience@v2.5#run-v25-0001"
    assert payload["change"]["references"] == ["ticket:CH-1421"]
    assert payload["decision_refs"] == [DECISION_M4_3_SUCCESS_CRITERIA.summary()]


def test_a_verdict_digest_covers_the_checks_and_the_evidence() -> None:
    """Phase 4 seals this; keeping it a property of the frozen model means the
    digest cannot drift from the decision beside it."""
    verdict = _passing_verdict()
    same = _passing_verdict(decided_at=CHECKED_AT)
    other = _passing_verdict(checks=(_syntax_check(),))

    assert verdict.verdict_digest() == same.verdict_digest()
    assert verdict.verdict_digest() != other.verdict_digest()
    assert len(verdict.verdict_digest()) == 64


def test_a_pass_over_a_check_that_did_not_pass_is_refused_at_construction() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _passing_verdict(checks=(_syntax_check(), _unreachable_check()))

    assert excinfo.value.rule == "pipeline.pass_over_blocking_check"


def test_a_pass_with_no_checks_is_refused() -> None:
    """A pipeline that checked nothing has established nothing."""
    with pytest.raises(InvariantViolationError) as excinfo:
        _passing_verdict(checks=())

    assert excinfo.value.rule == "pipeline.pass_without_checks"


def test_a_fail_with_no_reason_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        PipelineVerdict(
            outcome=PipelineOutcome.FAIL,
            change=_link(),
            checks=(_failing_check(),),
            evidence_refs=("proof:sha-def",),
            reasons=(),
        )

    assert excinfo.value.rule == "pipeline.fail_without_reason"


def test_a_verdict_repeating_a_check_name_is_refused() -> None:
    """Two results for one check make the verdict un-derivable."""
    with pytest.raises(InvariantViolationError) as excinfo:
        _passing_verdict(checks=(_syntax_check(), _syntax_check(scope=CheckScope.TARGET)))

    assert excinfo.value.rule == "pipeline.duplicate_check_name"


def test_a_naive_decision_timestamp_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _passing_verdict(decided_at=naive_moment())

    assert excinfo.value.rule == "pipeline_decided_at_aware"


@pytest.mark.parametrize("bad", ["2.0", "mayhem/1", ""])
def test_an_unsupported_verdict_or_check_schema_is_refused(bad: str) -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _passing_verdict(schema_version=bad)
    assert excinfo.value.rule == "pipeline.unsupported_schema"

    with pytest.raises(InvariantViolationError) as checkinfo:
        _syntax_check(schema_version=bad)
    assert checkinfo.value.rule == "pipeline.unsupported_schema"


# ── UNKNOWN, never PASS (fail-closed) ───────────────────────────────────────────


def test_a_check_that_cannot_reach_the_control_plane_reports_unknown() -> None:
    check = _unreachable_check()

    assert check.outcome is CheckOutcome.UNKNOWN
    assert not check.conclusive
    assert check.blocking


@pytest.mark.parametrize("outcome", [CheckOutcome.PASS, CheckOutcome.FAIL])
def test_an_unreachable_check_may_not_conclude_at_all(outcome: CheckOutcome) -> None:
    """Not pass — it never ran. Not fail either: a failure is a fact about the
    world, and an unreachable plane is a fact about the network. Reporting fail
    manufactures an incident out of a DNS timeout."""
    with pytest.raises(InvariantViolationError) as excinfo:
        _unreachable_check(outcome=outcome)

    assert excinfo.value.rule == "pipeline.unreachable_check_concluded"
    assert "unknown, never pass" in str(excinfo.value)


def test_an_unreachable_check_must_say_why() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _unreachable_check(detail="   ")

    assert excinfo.value.rule == "pipeline.unknown_check_unexplained"


def test_an_unknown_check_fails_the_pipeline_rather_than_warning_about_it() -> None:
    verdict = PipelineVerdict.decide(
        _link(), (_syntax_check(), _unreachable_check()), cited_run=_pin(), decided_at=CHECKED_AT
    )

    assert verdict.outcome is PipelineOutcome.FAIL
    assert not gates_release(verdict)
    assert verdict.unknown_checks == (_unreachable_check(),)
    assert verdict.reasons == (
        "policy reported unknown: control plane at mayhem.internal:8443 did not answer in 30s",
    )
    assert verdict.check("policy") is not None
    assert verdict.check("nope") is None


def test_an_unreachable_check_may_carry_a_warning_finding() -> None:
    """A finding on an unknown check records what was observed, not what was
    concluded. It is admissible; the check still reports unknown and still
    blocks. The rule that a *fail* needs a finding does not extend to a check
    that found nothing and reached nothing."""
    check = _unreachable_check(
        finding=_failure("policy.unreachable", severity=FindingSeverity.WARNING)
    )

    assert check.outcome is CheckOutcome.UNKNOWN
    assert check.finding is not None
    assert not check.finding.blocks
    assert check.blocking


# ── coverage deltas ─────────────────────────────────────────────────────────────


def test_a_delta_is_the_move_of_one_coverage_cell() -> None:
    gained = _delta(CHECKOUT_POSTGRES, CellState.PLANNED, CellState.PASSED)
    assert gained.cell.key == CHECKOUT_POSTGRES.key
    assert gained.newly_covered
    assert not gained.lost
    assert gained.settled is False


def test_coverage_lost_is_a_regression_and_says_so() -> None:
    lost = _delta(CHECKOUT_POSTGRES, CellState.PASSED, CellState.FAILED)
    assert lost.lost
    assert not lost.newly_covered
    assert lost.settled is False


def test_a_move_between_two_uncovered_states_is_settled_not_covered() -> None:
    """'planned → blocked' changed, and reporting it as coverage would be a lie
    in the direction that flatters."""
    settled = _delta(PAYMENT_TIMEOUT, CellState.PLANNED, CellState.BLOCKED)
    assert settled.settled
    assert not settled.newly_covered
    assert not settled.lost


def test_a_delta_that_is_not_a_change_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _delta(CHECKOUT_POSTGRES, CellState.PASSED, CellState.PASSED)

    assert excinfo.value.rule == "pipeline.coverage_delta_without_change"


def test_a_check_reports_its_coverage_gains_and_losses_separately() -> None:
    check = _syntax_check(
        scope=CheckScope.COVERAGE,
        coverage_deltas=(
            _delta(CHECKOUT_POSTGRES, CellState.PLANNED, CellState.PASSED),
            _delta(PAYMENT_TIMEOUT, CellState.PASSED, CellState.FAILED),
        ),
    )

    assert [d.cell.key for d in check.newly_covered] == [CHECKOUT_POSTGRES.key]
    assert [d.cell.key for d in check.lost_coverage] == [PAYMENT_TIMEOUT.key]


def test_a_check_reports_one_before_and_after_per_cell() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _syntax_check(
            scope=CheckScope.COVERAGE,
            coverage_deltas=(
                _delta(CHECKOUT_POSTGRES, CellState.PLANNED, CellState.PASSED),
                _delta(CHECKOUT_POSTGRES, CellState.PASSED, CellState.FAILED),
            ),
        )

    assert excinfo.value.rule == "pipeline.duplicate_coverage_delta"


def test_a_coverage_gap_may_ride_on_a_passing_check_as_a_warning() -> None:
    """Phase 3's 'checkout has no experiment covering PostgreSQL failure' is
    reportable without failing the PR: a known gap is not a new failure."""
    check = _passing_check(
        scope=CheckScope.COVERAGE,
        finding=_failure("coverage.gap", severity=FindingSeverity.WARNING),
    )

    assert check.is_pass
    assert check.finding is not None
    assert not check.finding.blocks
    assert check.finding.cell == CHECKOUT_POSTGRES


def test_a_passing_check_may_not_carry_an_error_finding() -> None:
    """The outcome and the finding disagree, and only one of them is true."""
    with pytest.raises(InvariantViolationError) as excinfo:
        _passing_check(finding=_failure("blast.radius_exceeded"))

    assert excinfo.value.rule == "pipeline.pass_carrying_error"


# ── change links ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("ident", "expected"),
    [
        ({"change_ticket": "CH-1"}, "ticket:CH-1"),
        ({"incident_id": "INC-9"}, "incident:INC-9"),
        ({"deployment_id": "dpl-77"}, "deployment:dpl-77"),
    ],
)
def test_any_one_change_system_satisfies_the_link(ident: dict[str, str], expected: str) -> None:
    link = ChangeLink(
        git_sha="a1b2c3d",
        linked_at=CHECKED_AT,
        pins=PipelinePins.from_run(_pin()),
        **ident,
    )

    assert link.references == (expected,)
    assert link.attributable


def test_a_link_cites_every_change_system_it_carries() -> None:
    link = _link(incident_id="INC-9", deployment_id="dpl-77")

    assert link.references == ("ticket:CH-1421", "incident:INC-9", "deployment:dpl-77")


def test_a_link_naming_no_ticket_incident_or_deployment_is_refused() -> None:
    """A decision nobody filed cannot be traced back to the work that justified it."""
    with pytest.raises(InvariantViolationError) as excinfo:
        ChangeLink(git_sha="a1b2c3d", linked_at=CHECKED_AT)

    assert excinfo.value.rule == "pipeline.unattributable_change"


@pytest.mark.parametrize("sha", ["a1b2c3", "A1B2C3D", "zzz", "a" * 41])
def test_a_link_requires_a_resolvable_git_sha(sha: str) -> None:
    with pytest.raises(ValidationError):
        ChangeLink(git_sha=sha, change_ticket="CH-1", linked_at=CHECKED_AT)


def test_a_link_is_serialised_with_its_references_and_pin_state() -> None:
    payload: dict[str, Any] = _link().to_dict()

    assert payload["git_sha"] == "a1b2c3d"
    assert payload["attributable"] is True
    assert payload["pins"]["complete"] is True
    assert payload["pins"]["missing"] == []


# ── invalidation on plan change (Phase 5's negative control) ────────────────────


def _approval(approver: str, digest: str = CHECKED_DIGEST) -> PlanApproval:
    return PlanApproval(approver=approver, plan_digest=digest, approved_at=CHECKED_AT)


def _merge(merged: str, approvals: tuple[PlanApproval, ...]) -> PlanMerge:
    return PlanMerge(
        checked_plan_digest=CHECKED_DIGEST,
        merged_plan_digest=merged,
        approvals=approvals,
        merged_at=MERGED_AT,
    )


def test_a_merged_plan_that_differs_from_the_checked_one_invalidates_every_approval() -> None:
    """Including the approvals whose digest happens to match: an approval given
    against a plan nobody ran approves nothing, whatever digest it carries."""
    merge = _merge(MERGED_DIGEST, (_approval("ana"), _approval("bo")))

    assert merge.changed
    assert merge.approvals_stand is False
    assert merge.invalidated == merge.approvals
    assert merge.surviving == ()


def test_an_unchanged_plan_keeps_every_approval_that_binds_it() -> None:
    merge = _merge(CHECKED_DIGEST, (_approval("ana"), _approval("bo")))

    assert not merge.changed
    assert merge.approvals_stand
    assert merge.invalidated == ()
    assert merge.surviving == merge.approvals
    assert merge.invalidation_reason == ""


def test_an_approval_for_a_different_plan_is_invalidated_even_without_a_change() -> None:
    """A merge can land the checked digest and still carry an approval that was
    granted against some other plan entirely."""
    other_digest = "c" * 64
    merge = _merge(CHECKED_DIGEST, (_approval("ana"), _approval("cy", other_digest)))

    assert not merge.changed
    assert merge.approvals_stand is False
    assert [a.approver for a in merge.invalidated] == ["cy"]
    assert [a.approver for a in merge.surviving] == ["ana"]


def test_an_invalidation_states_the_plan_that_moved_and_how_many_approvals_it_cost() -> None:
    merge = _merge(MERGED_DIGEST, (_approval("ana"),))
    reason = merge.invalidation_reason

    assert MERGED_DIGEST[:12] in reason
    assert CHECKED_DIGEST[:12] in reason
    assert "1 prior approval" in reason
    assert "approves nothing" in reason


def test_an_invalidated_approval_blocks_the_release_gate() -> None:
    verdict = _passing_verdict()
    assert gates_release(verdict)

    merge = _merge(MERGED_DIGEST, (_approval("ana"),))
    assert not gates_release(verdict, merge)
    assert "approves nothing" in blocking_reasons(verdict, merge)[0]


def test_an_approval_must_name_its_approver_and_carry_a_sha256_plan_digest() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        PlanApproval(approver="  ", plan_digest=CHECKED_DIGEST)
    assert excinfo.value.rule == "pipeline_approver_not_blank"

    with pytest.raises(ValidationError):
        PlanApproval(approver="ana", plan_digest="not-a-digest")


def test_a_merge_with_a_naive_timestamp_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        PlanMerge(
            checked_plan_digest=CHECKED_DIGEST,
            merged_plan_digest=MERGED_DIGEST,
            merged_at=naive_moment(13),
        )

    assert excinfo.value.rule == "pipeline_merged_at_aware"


# ── the gate, recomputed rather than read ───────────────────────────────────────


def test_a_fully_pinned_passing_verdict_gates_the_release() -> None:
    verdict = _passing_verdict()

    assert gates_release(verdict)
    assert blocking_reasons(verdict) == ()
    assert verdict.resilient


def test_the_gate_recomputes_rather_than_reading_the_stored_outcome() -> None:
    """A green verdict with no run cited still refuses: nothing was measured."""
    verdict = _passing_verdict(cited_run=None)

    assert verdict.outcome is PipelineOutcome.PASS
    assert not gates_release(verdict)
    assert "no run is cited" in blocking_reasons(verdict)[0]


def test_a_verdict_without_a_resilience_check_is_valid_but_not_resilient() -> None:
    """'No resilience check' and 'resilience check passed' are different facts."""
    verdict = _passing_verdict(checks=(_syntax_check(),))

    assert verdict.resilient is False
    assert verdict.outcome is PipelineOutcome.PASS
    assert gates_release(verdict)


def test_a_referenced_decision_survives_serialisation() -> None:
    ref = DecisionRef(decision_id="ADR-M4-4", decided_on="2026-09-05", title="Observability")
    verdict = _passing_verdict(decision_refs=(ref,))

    assert verdict.to_dict()["decision_refs"] == ["ADR-M4-4 2026-09-05 (Observability)"]


# ── the negative controls the plan names ────────────────────────────────────────


def test_a_failing_resilience_verdict_fails_the_pipeline() -> None:
    """Plan 16 Phase 2's acceptance criterion, decided by Phase 1's types."""
    verdict = PipelineVerdict.decide(
        _link(),
        (_syntax_check(), _failing_check(name="resilience", scope=CheckScope.RESILIENCE)),
        cited_run=_pin(),
        decided_at=CHECKED_AT,
    )

    assert verdict.outcome is PipelineOutcome.FAIL
    assert not verdict.resilient
    assert not gates_release(verdict)
    assert verdict.reasons == ("resilience reported fail: requested 4 services, ceiling is 2",)


def test_a_run_whose_own_pins_are_blank_cannot_even_be_cited() -> None:
    """The run side of the same criterion, one layer down: :class:`RunPin`
    requires every axis outright, so the only way to reach an unattributable run
    is a link that never agreed with it in the first place."""
    with pytest.raises(ValidationError):
        _pin(plan_version="")
    with pytest.raises(ValidationError):
        _pin(policy_version="")

    verdict = _passing_verdict(change=_link(pins=PipelinePins()))
    assert not gates_release(verdict)
    assert "cannot back a release-gate decision" in blocking_reasons(verdict)[0]


def test_a_check_reporting_pass_with_no_evidence_is_rejected() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _passing_check(evidence_refs=())

    assert excinfo.value.rule == "pipeline.pass_without_evidence"
    assert "decoration" in str(excinfo.value)


def test_a_failing_check_with_no_finding_is_rejected() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _failing_check(finding=None)

    assert excinfo.value.rule == "pipeline.fail_without_finding"


def test_a_grade_over_zero_checks_is_refused_rather_than_defaulted_to_pass() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        PipelineVerdict.decide(_link(), (), cited_run=_pin())

    assert excinfo.value.rule == "pipeline.verdict_without_checks"


def test_deciding_takes_the_evidence_from_the_checks_when_none_is_given() -> None:
    """A verdict assembled from real checks cannot arrive without evidence."""
    verdict = PipelineVerdict.decide(
        _link(), (_syntax_check(), _passing_check()), cited_run=_pin(), decided_at=CHECKED_AT
    )

    assert verdict.evidence_refs == ("validate:stdout", "bundle:sha-abc")


def test_grading_refuses_to_invent_an_evidence_reference() -> None:
    """The evidence-less case is a refusal, not a placeholder. A fabricated
    reference leads nowhere, and a link that leads nowhere is worse than a
    missing one because it reads as cited."""
    evidence_free = _unreachable_check()

    with pytest.raises(InvariantViolationError) as excinfo:
        PipelineVerdict.decide(_link(), (evidence_free,), cited_run=_pin())

    assert excinfo.value.rule == "pipeline.verdict_without_evidence"
    assert "looks cited and is not" in str(excinfo.value)


# ── comparability, delegated to plan 22 ─────────────────────────────────────────


def test_the_same_experiment_on_a_new_release_is_comparable() -> None:
    baseline = _pin(run_id="run-v24-0001", release="v2.4")
    candidate = _pin()

    assert comparable_across_release(baseline, candidate)
    assert baseline.release_differences(candidate) == ("release",)


@pytest.mark.parametrize(
    "axis",
    [
        "experiment",
        "environment",
        "plan_version",
        "policy_version",
        "catalog_version",
        "agent_version",
        "runtime_version",
    ],
)
def test_two_runs_differing_on_any_other_axis_are_not_comparable(axis: str) -> None:
    baseline = _pin(run_id="run-v24-0001", release="v2.4")
    candidate = _pin(release="v2.5", **{axis: f"other-{axis}"})

    assert not comparable_across_release(baseline, candidate)
    assert axis in candidate.differences_from(baseline)


# ── time is injected, never read ────────────────────────────────────────────────


def test_a_check_observed_far_in_the_past_is_still_a_valid_pass() -> None:
    """Nothing in this module ages an observation out. Staleness is Phase 4's
    evidence-seal concern; inventing a TTL here would make a verdict's
    reproducibility depend on when it was asked."""
    old = _passing_check(observed_at=CHECKED_AT - timedelta(days=400))
    verdict = _passing_verdict(checks=(old,))

    assert verdict.outcome is PipelineOutcome.PASS
    assert gates_release(verdict)
    with pytest.raises(InvariantViolationError) as excinfo:
        _passing_check(observed_at=naive_moment())
    assert excinfo.value.rule == "pipeline_check_observed_at_aware"


# ── the domain law, restated where the module lives ─────────────────────────────

_FORBIDDEN_STDLIB = frozenset({"asyncio", "socket", "subprocess", "sqlite3", "pathlib", "os"})
_FORBIDDEN_LAYERS = ("mayhem.toolkit", "mayhem.agents", "mayhem.controller", "mayhem.infra")


def test_pipeline_imports_nothing_the_domain_may_not_import() -> None:
    source = open(pipeline_module.__file__, encoding="utf-8").read()  # noqa: SIM115, PTH123
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
    assert not imported & _FORBIDDEN_STDLIB
    assert not [name for name in sorted(imported) if name.startswith(_FORBIDDEN_LAYERS)]
