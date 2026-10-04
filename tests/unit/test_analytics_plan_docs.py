"""Plan 15 Phase 6 — the honesty gate over the plan document.

The other two plans with a prose gate (`test_lowlevel_doc_honesty.py`,
`test_advisor_plan_docs.py`) share this shape, and the reason is the same in all
three: a ledger and a summary are only useful if they agree with each other and
with the code, and prose is the one artifact nothing else checks.

This plan's acceptance criterion is a claim *about prose* — "no doc presents a
boundary as a guarantee across releases (that claim belongs to 22)" — so it
cannot be discharged by writing the sentence. It is discharged by a gate that
reads the document and refuses the claim if it appears:

* the per-phase ledger carries one line per phase and the ``Overall:`` count
  equals the number of ``DONE`` lines;
* the three Phase 6 guides are present by name;
* four literal claims are absent, the load-bearing one being any sentence calling
  a boundary a guarantee across releases — the exact over-claim this plan hands
  to plan 22, and the one an operator would most want to believe;
* the search's own stop-reason vocabulary is quoted in the reading guide, so a
  new ``StopReason`` that the guide does not mention fails here rather than
  reaching a reader who was told the list was complete.

Each checker is proven to bite against a mutated copy of the document.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

from mayhem.domain.search import StopReason

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/15_RESILIENCE_ANALYTICS_ADAPTIVE.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")

#: The Phase 6 deliverables, by the heading each one must carry.
REQUIRED_SECTIONS: Final[tuple[str, ...]] = (
    "## Statistics interpretation guide",
    "## Boundary-report reading guide",
    "## Advisor methodology doc",
    "## Rollout order",
)

#: The claims this plan must never make. Narrow and literal by design: a prose
#: gate cannot judge intent, so it judges the smallest set of literal claims that
#: would each be a distinct lie. The document's own *denials* — "is not a
#: guarantee across releases", "does not make it" — must not match these.
FORBIDDEN_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (
        r"\bboundary is a guarantee across releases\b",
        "that claim belongs to plan 22",
    ),
    (
        r"\bguarantees? (?:safety|tolerance) across (?:releases|versions)\b",
        "that claim belongs to plan 22",
    ),
    (
        r"\bno material effect\b[^.]{0,60}\bmeans nothing happened\b",
        "no material effect is a threshold statement, not an absence",
    ),
    (
        r"\binsufficient data\b[^.]{0,40}\bmeans? (?:low|less) confidence\b",
        "insufficient data withholds every quotable number",
    ),
)


# ── the checkers, as functions, so the negative controls can attack them ──────


def ledger_lines(document: str) -> dict[str, str]:
    """``phase label -> its STATUS line``, parsed from the ledger."""
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


def claimed_overall(document: str) -> tuple[int, int] | None:
    match = re.search(r"^Overall:\s*(\d+)\s+of\s+(\d+)", document, re.MULTILINE)
    return (int(match.group(1)), int(match.group(2))) if match else None


def missing_sections(document: str) -> list[str]:
    return [heading for heading in REQUIRED_SECTIONS if heading not in document]


def forbidden_claims_found(document: str) -> list[str]:
    found: list[str] = []
    for pattern, reason in FORBIDDEN_CLAIMS:
        if re.search(pattern, document, re.IGNORECASE):
            found.append(reason)
    return found


def unmentioned_stop_reasons(document: str) -> list[str]:
    """``StopReason`` members the reading guide does not name.

    The guide tells the reader the list is complete, so a new member that nobody
    documented is a silent gap in a document that claims not to have any.
    """
    return [member.value for member in StopReason if member.value not in document]


# ── the ledger ───────────────────────────────────────────────────────────────


def test_the_ledger_carries_one_line_per_phase() -> None:
    assert sorted(ledger_lines(PLAN)) == [f"Phase {n}" for n in range(1, 7)]


def test_the_overall_count_equals_the_number_of_done_lines() -> None:
    overall = claimed_overall(PLAN)

    assert overall is not None, "the STATUS block must carry an Overall: line"
    done, total = overall
    assert (done, total) == (done_phase_count(PLAN), len(ledger_lines(PLAN)))
    assert done == total


# ── the Phase 6 deliverables ─────────────────────────────────────────────────


def test_the_three_guides_and_the_rollout_order_are_in_the_document() -> None:
    assert missing_sections(PLAN) == []


def test_the_reading_guide_documents_every_stop_reason() -> None:
    assert unmentioned_stop_reasons(PLAN) == []


def test_the_interpretation_guide_states_what_no_material_effect_is_not() -> None:
    """The guide's own denials, so a future edit cannot quietly drop them."""
    for required in (
        "statement about the *declared threshold*",
        'is not "no effect"',
        "follows the *difference* interval, never the overlap",
        "no answer",
    ):
        assert required in PLAN, f"the guide must state {required!r}"


# ── the claims the document must not make ─────────────────────────────────────


def test_the_document_makes_no_literal_false_claim() -> None:
    assert forbidden_claims_found(PLAN) == []


def test_the_document_does_not_hold_a_boundary_as_a_release_guarantee() -> None:
    """The phase's own acceptance criterion, asserted as a checker."""
    assert forbidden_claims_found(PLAN) == []


def _demote_the_first_done_phase(document: str) -> str:
    """Flip the first ``DONE`` ledger line to ``not started``.

    Derived from the document rather than from a hardcoded phase label, because a
    label copied into a test is a second place for the ledger to be wrong — and
    this mutation would then silently stop mutating anything.
    """
    for raw in document.split("\n"):
        if raw.startswith("- Phase ") and ": DONE" in raw:
            return document.replace(": DONE", ": not started", 1)
    raise AssertionError("the document has no DONE ledger line to demote")


# ── negative controls: each checker must bite ────────────────────────────────

_MUTATIONS: Final[tuple[tuple[str, Callable[[str], str], Callable[[str], object]], ...]] = (
    (
        "a done phase demoted",
        _demote_the_first_done_phase,
        done_phase_count,
    ),
    (
        "the Overall count inflated",
        lambda d: d.replace("Overall: 6 of 6", "Overall: 7 of 6", 1),
        claimed_overall,
    ),
    (
        "the reading guide removed",
        lambda d: d.replace("## Boundary-report reading guide", "## Removed", 1),
        lambda d: len(missing_sections(d)),
    ),
    (
        "the document calling a boundary a release guarantee",
        lambda d: d + "\nThe boundary is a guarantee across releases.\n",
        lambda d: len(forbidden_claims_found(d)),
    ),
    (
        "a stop reason removed from the guide",
        lambda d: d.replace("`boundary-resolved`", "`removed-reason`", 1),
        unmentioned_stop_reasons,
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
