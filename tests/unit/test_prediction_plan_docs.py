"""Plan 14 Phase 6 — the honesty gate over the plan document.

Same shape as `test_lowlevel_doc_honesty.py`, `test_advisor_plan_docs.py` and
`test_analytics_plan_docs.py`, and for the same reason: the phase's acceptance
criterion is a claim *about prose* — "no doc calls a prediction a guarantee" — so
writing the sentence does not discharge it.

This plan is also the one where the ledger must **not** be inflated. Phase 3 is
`INCOMPLETE` for stated reasons of ownership, so `Overall: 5 of 6` is the correct
summary and `6 of 6` would be the flattering lie. The gate therefore checks that
the summary agrees with the `DONE` lines *and* that a plan carrying an
`INCOMPLETE` phase does not claim to be finished:

* one ledger line per phase, and ``Overall:`` equal to the number of ``DONE``
  lines;
* Phase 3 is still ``INCOMPLETE`` and is *named* as the unfinished one — a gate
  that only checked arithmetic would pass a document that quietly promoted itself
  to complete;
* the two Phase 6 guides are present by name;
* the guarantee claim is absent, and each checker bites against a mutated copy.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/14_TOPOLOGY_BLAST_RADIUS.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")

REQUIRED_SECTIONS: Final[tuple[str, ...]] = (
    "## Prediction interpretation guide",
    "## Simulate vs. preflight",
    "## Rollout order",
)

#: Claims this plan must never make. The document's own *denials* — "is an
#: expectation, never an outcome", "guarantee-shaped claims belong to plan 22" —
#: must not match these.
FORBIDDEN_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (r"\bprediction is a guarantee\b", "a prediction is an expectation over a read graph"),
    (r"\bguarantees? (?:the )?blast radius\b", "the blast radius is predicted, not guaranteed"),
    (r"\bthe prediction will (?:always|never) be accurate\b", "accuracy is unmeasured"),
    (r"\bunchecked\b[^.]{0,40}\bmeans? (?:safe|fine|passed)\b", "unchecked means not checked"),
)


def ledger_lines(document: str) -> dict[str, str]:
    lines: dict[str, str] = {}
    in_status = False
    for raw in document.split("\n"):
        stripped = raw.strip()
        if stripped.startswith("## STATUS"):
            in_status = True
            continue
        if in_status and stripped.startswith("## ") and stripped != "## STATUS":
            in_status = False
        if not in_status:
            continue
        match = re.match(r"^- (Phase \d)(.*?):\s*(DONE|INCOMPLETE|not started|partially)", stripped)
        if match:
            lines[match.group(1)] = stripped
    return lines


def done_phase_count(document: str) -> int:
    return sum(1 for line in ledger_lines(document).values() if ": DONE" in line)


def incomplete_phases(document: str) -> list[str]:
    return [phase for phase, line in ledger_lines(document).items() if ": INCOMPLETE" in line]


def claimed_overall(document: str) -> tuple[int, int] | None:
    match = re.search(r"^Overall:\s*(\d+)\s+of\s+(\d+)", document, re.MULTILINE)
    return (int(match.group(1)), int(match.group(2))) if match else None


def missing_sections(document: str) -> list[str]:
    return [heading for heading in REQUIRED_SECTIONS if heading not in document]


def forbidden_claims_found(document: str) -> list[str]:
    return [
        reason
        for pattern, reason in FORBIDDEN_CLAIMS
        if re.search(pattern, document, re.IGNORECASE)
    ]


def inflates_its_own_completion(document: str) -> bool:
    """True when the summary claims more done phases than the ledger records as done.

    Counted against ``: DONE`` lines *only*. An ``INCOMPLETE`` phase is a real
    phase in the ledger, so a document that promoted one to ``DONE`` to make its
    own arithmetic agree would pass a count-everything check; this one does not.
    """
    overall = claimed_overall(document)
    if overall is None:
        return False
    claimed_done, _total = overall
    return claimed_done > done_phase_count(document)


# ── the ledger ───────────────────────────────────────────────────────────────


def test_the_ledger_carries_one_line_per_phase() -> None:
    assert sorted(ledger_lines(PLAN)) == [f"Phase {n}" for n in range(1, 7)]


def test_the_overall_count_equals_the_number_of_done_lines() -> None:
    overall = claimed_overall(PLAN)

    assert overall is not None
    done, total = overall
    assert done == done_phase_count(PLAN)
    assert total == len(ledger_lines(PLAN))


def test_phase_three_is_still_named_as_the_unfinished_one() -> None:
    """The reason this plan is 5 of 6, asserted so it cannot be quietly promoted."""
    assert incomplete_phases(PLAN) == ["Phase 3"]
    overall = claimed_overall(PLAN)
    assert overall is not None
    assert overall[0] < overall[1]


def test_the_document_does_not_inflate_its_own_completion() -> None:
    assert inflates_its_own_completion(PLAN) is False


# ── the Phase 6 deliverables ─────────────────────────────────────────────────


def test_the_two_guides_and_the_rollout_order_are_in_the_document() -> None:
    assert missing_sections(PLAN) == []


def test_the_interpretation_guide_states_its_three_load_bearing_claims() -> None:
    for required in (
        "was **not checked**",
        "marks a prediction **stale**",
        "about **targets**, not blast radius",
        "omits `currency` and `total` **entirely**",
    ):
        assert required in PLAN, f"the guide must state {required!r}"


# ── the claims the document must not make ─────────────────────────────────────


def test_the_document_makes_no_literal_false_claim() -> None:
    assert forbidden_claims_found(PLAN) == []


# ── negative controls ────────────────────────────────────────────────────────

_MUTATIONS: Final[tuple[tuple[str, Callable[[str], str], Callable[[str], object]], ...]] = (
    (
        "a done phase demoted",
        lambda d: d.replace(": DONE", ": not started", 1),
        done_phase_count,
    ),
    (
        "the Overall count inflated to complete",
        lambda d: d.replace("Overall: 5 of 6", "Overall: 6 of 6", 1),
        inflates_its_own_completion,
    ),
    (
        "the interpretation guide removed",
        lambda d: d.replace("## Prediction interpretation guide", "## Removed", 1),
        lambda d: len(missing_sections(d)),
    ),
    (
        "the document calling a prediction a guarantee",
        lambda d: d + "\nThe prediction is a guarantee of the blast radius.\n",
        lambda d: len(forbidden_claims_found(d)),
    ),
    (
        "Phase 3 silently promoted to done",
        lambda d: d.replace(": INCOMPLETE", ": DONE", 1),
        incomplete_phases,
    ),
)


def _run_negative_controls() -> None:
    for name, mutate, checker in _MUTATIONS:
        baseline = checker(PLAN)
        mutated = mutate(PLAN)
        assert mutated != PLAN, f"{name}: the mutation must change the document"
        assert checker(mutated) != baseline, f"{name}: the checker did not bite"


def test_each_checker_notices_its_own_mutation() -> None:
    _run_negative_controls()
