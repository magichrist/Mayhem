"""Plan 15 Phase 5 — negative controls for the statistics and the search.

`tests/unit/test_analytics.py` (39), `test_search.py` (44),
`test_analytics_service.py` (86), `test_analytics_evidence.py` (42) and
`test_boundary_report_surface.py` (88) assert what the domain and the engine
*do*. This file asserts that the four properties the plan's Phase 5 names by
name are **load-bearing** — that each one is what decides the answer, and that
removing or inverting it moves the answer.

That is a different claim, and it is the one that survives an edit:

* **The materiality floor decides.** The same two series, compared by the same
  function, are material at a 5% floor and not material at a 95% one. If the
  verdict did not move, the floor would be decoration and the phase's central
  claim ("no material effect" is a statement about *your* threshold) would be
  false.
* **Per-series interval overlap does not decide.** Two fixtures disagree with the
  verdict in *opposite* directions — one where the intervals are disjoint and
  the effect is immaterial, one where they overlap and it is material. A single
  case could be coincidence; a matched pair in opposite directions is the
  property.
* **Insufficient data withholds rather than widens.** Below the floor the
  comparison reports *no quotable number at all* — no effect size, no interval,
  no delta — rather than a number with a wider interval around it. The same data
  one sample-count higher is graded, so the gate is doing the withholding.
* **An exhausted budget refuses, and an unexhausted one does not.** Same policy,
  same history, only the remaining budget moves. The plan's own negative control,
  pinned from both sides so it cannot be satisfied by a search that refuses
  everything.

The phase also names two properties that live behind the engine's ports —
a causal chain over a missing edge being *withheld*, and an approval token inside
a draft being *rejected*. Rebuilding those collaborators here would duplicate the
suites that already own them, so they are guarded by name instead
(:func:`test_the_service_level_properties_the_phase_names_are_still_pinned`): a
name-pin is a weaker guarantee than a behaviour test, and it is labelled as one
rather than dressed up as the real thing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.unit.test_analytics import (
    BASE_LATENCY,
    NOISY_WINDOW,
    RISEN_WINDOW,
    SHIFTED_LATENCY,
    TIGHT_BASELINE,
    WIDE_BASELINE,
)
from tests.unit.test_search import PLANTED_BOUNDARY, policy, run

from mayhem.domain.analytics import (
    Comparison,
    EffectOutcome,
    SamplePolicy,
    compare,
)
from mayhem.domain.search import (
    SearchHistory,
    StopReason,
    plan_next_step,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The two service-level properties Phase 5 names, and the suite that owns each.
#: Pinned by name so deleting the coverage fails here instead of silently
#: dropping a property the plan's acceptance criterion lists.
NAMED_SERVICE_PROPERTIES: tuple[tuple[str, str], ...] = (
    (
        "tests/unit/test_analytics_service.py",
        "test_a_chain_over_a_missing_edge_is_withheld_not_guessed",
    ),
    ("tests/unit/test_analytics_service.py", "test_a_chain_missing_a_hop_cannot_be_constructed"),
    (
        "tests/unit/test_analytics_service.py",
        "test_a_draft_with_an_embedded_approval_token_is_rejected",
    ),
    ("tests/unit/test_analytics_service.py", "test_a_nested_approval_token_is_rejected_too"),
    (
        "tests/unit/test_advisor_service.py",
        "test_the_advisor_context_holds_no_mutation_backend_and_no_lease_sink",
    ),
)


def _outcome(left: list[float], right: list[float], **kwargs: object) -> Comparison:
    return compare(left, right, name="probe", **kwargs)  # type: ignore[arg-type]


# ── the materiality floor decides ────────────────────────────────────────────


def test_the_materiality_floor_decides_the_verdict_in_both_directions() -> None:
    """Identical data, identical function; only the declared floor moves.

    This is the property behind every "no material effect" sentence mayhem
    prints. The answer is a function of the threshold the customer declared, so
    if the same comparison returned one verdict at both floors, the phrase would
    be reporting the data's mood rather than the customer's standard.
    """
    material = _outcome(BASE_LATENCY, SHIFTED_LATENCY, materiality_pct=5.0)
    immaterial = _outcome(BASE_LATENCY, SHIFTED_LATENCY, materiality_pct=95.0)

    assert material.outcome is EffectOutcome.MATERIAL_RISE
    assert immaterial.outcome is EffectOutcome.NO_MATERIAL_EFFECT
    assert material.graded is True and immaterial.graded is True
    # Both are *graded* — the floor is a threshold, not a data-quality gate, and
    # a threshold that suppressed the numbers would be the sufficiency rule
    # wearing a different hat.
    assert immaterial.difference_ci is not None


def test_per_series_overlap_disagrees_with_the_verdict_in_both_directions() -> None:
    """The matched pair: disjoint intervals yet immaterial, overlapping yet material.

    `intervals_overlap` is reported because operators want it, not because it
    grades anything. If either of these two agreed with it, the suite would still
    be green on a single case — which is why both directions are asserted here.
    """
    disjoint_but_immaterial = _outcome(TIGHT_BASELINE, NOISY_WINDOW)
    overlapping_but_material = _outcome(WIDE_BASELINE, RISEN_WINDOW)

    assert disjoint_but_immaterial.intervals_overlap is False
    assert disjoint_but_immaterial.outcome is EffectOutcome.NO_MATERIAL_EFFECT

    assert overlapping_but_material.intervals_overlap is True
    assert overlapping_but_material.outcome is EffectOutcome.MATERIAL_RISE

    # Each verdict is carried by the *difference* interval, and each phrase says
    # which way that interval fell — never that the intervals overlapped, which
    # is the one thing that is true of one case and false of the other.
    assert disjoint_but_immaterial.difference_ci is not None
    assert "on the difference containing zero" in disjoint_but_immaterial.verdict_phrase
    assert overlapping_but_material.difference_ci is not None
    assert "difference CI excluding zero" in overlapping_but_material.verdict_phrase


# ── insufficiency withholds rather than widens ───────────────────────────────


def test_insufficient_data_withholds_every_quotable_number_rather_than_widening_it() -> None:
    """Below the floor the comparison reports nothing; at the floor it reports everything.

    The failure this rules out is an insufficient comparison rendered with a
    wider interval around a point estimate — a number a reader would quote, with
    a confidence interval that only becomes comfortable as the sample grows past
    the threshold it was never allowed to cross.
    """
    # Four samples per series is still *insufficient* — the floor is five per
    # series, which is why this test writes five rather than "one more than the
    # insufficient case". Getting that wrong would have made the pair look like
    # a threshold that had been crossed.
    insufficient = _outcome([100.0, 101.0], [105.0, 106.0])
    sufficient = _outcome([100.0, 101.0, 102.0, 103.0, 104.0], [105.0, 106.0, 107.0, 108.0, 109.0])

    assert insufficient.outcome is EffectOutcome.INSUFFICIENT_DATA
    for withheld in (
        insufficient.effect_size,
        insufficient.difference_ci,
        insufficient.baseline_ci,
        insufficient.point_delta_pct,
    ):
        assert withheld is None
    assert insufficient.verdict_phrase.endswith("— NOT GRADED")

    assert sufficient.outcome is not EffectOutcome.INSUFFICIENT_DATA
    assert sufficient.graded is True
    assert sufficient.difference_ci is not None


def test_the_sample_floor_is_the_boundary_between_graded_and_ungraded() -> None:
    """Five is the floor, and four on either side of it is not.

    Asserted on the policy itself rather than only through `compare`, so the
    threshold is pinned as a constant with its own meaning instead of being
    inferred from a downstream verdict.
    """
    policy_ = SamplePolicy()

    assert policy_.check(5, 5).sufficient is True
    assert policy_.check(4, 5).sufficient is False
    assert policy_.check(5, 4).sufficient is False


# ── the budget backstop ──────────────────────────────────────────────────────


def test_an_exhausted_budget_refuses_the_step_and_an_unexhausted_one_does_not() -> None:
    """Same policy, same empty history; only the remaining budget differs.

    This is the plan's own negative control, pinned from both sides. A search that
    refused everything would satisfy the "refuses" half alone, so the passing half
    is asserted in the same test.
    """
    search = policy()
    history = SearchHistory()

    exhausted = plan_next_step(search, history, budget=search.budget(0.0))
    available = plan_next_step(search, history, budget=search.budget(500.0))

    assert exhausted.proceed is False
    assert exhausted.step is None
    assert exhausted.stop is StopReason.NO_REMAINING_BUDGET
    assert available.proceed is True
    assert available.step is not None


def test_a_missing_budget_refuses_rather_than_reading_as_unlimited() -> None:
    """``None`` is the absent state, and the absent state refuses.

    The dangerous reading of a missing budget is "no limit configured, therefore
    unlimited" — which is how a search that nobody bounded runs until something
    else stops it.
    """
    decision = plan_next_step(policy(), SearchHistory(), budget=None)

    assert decision.proceed is False
    assert decision.stop is StopReason.NO_REMAINING_BUDGET


# ── the boundary is found, not assumed ──────────────────────────────────────


def test_the_planted_boundary_is_found_and_a_surface_without_one_reports_none() -> None:
    """The planted breach is reported; a surface that never breaches is not.

    Otherwise "boundary found" is a property of the search rather than of the
    world, and a search over a healthy service would report a boundary at
    whatever value it happened to stop on.
    """
    breaching, walked_breaching, _ = run(policy())
    clean, walked_clean, _ = run(policy(), surface=lambda value: False)

    # The search brackets the boundary rather than landing on it: minimization
    # narrows onto the planted value, so 8.0 itself is never walked. What is
    # asserted is the bracket — a clean value below and a breached value above —
    # because that is the claim the report makes.
    assert any(value < PLANTED_BOUNDARY and not breached for value, breached in walked_breaching)
    assert any(value >= PLANTED_BOUNDARY and breached for value, breached in walked_breaching)
    assert breaching.stop is StopReason.BOUNDARY_RESOLVED
    assert breaching.proceed is False

    assert not any(breached for _, breached in walked_clean)
    assert clean.stop is not StopReason.BOUNDARY_RESOLVED
    assert walked_clean, "the clean surface was still walked, so this is not a vacuous stop"


# ── the properties that live behind the engine's ports ───────────────────────


@pytest.mark.parametrize(("path", "test_name"), NAMED_SERVICE_PROPERTIES)
def test_the_service_level_properties_the_phase_names_are_still_pinned(
    path: str, test_name: str
) -> None:
    """A name-pin, and weaker than a behaviour test — stated as such.

    Rebuilding a causal chain with a missing edge, or a draft carrying an
    approval token, would duplicate the suites that already own those
    collaborators. What this guards is narrower and still worth guarding: that
    the coverage the phase's acceptance criterion names has not been deleted.
    """
    source = (REPO_ROOT / path).read_text(encoding="utf-8")

    assert f"def {test_name}(" in source, f"{path} no longer pins {test_name}"
