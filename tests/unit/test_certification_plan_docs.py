"""Plan 01 Phase 6 — the honesty gate over the runtime-certification document.

Plan 01's ledger is the longest in the package and the most careful, which makes
it the easiest place for drift: a claim that was true when it was written sits
there next to code that has since moved. So this gate checks the three things that
drift.

* **The ledger against itself.** One line per phase, ``Overall:`` equal to the
  ``DONE`` count, and exactly one phase open — Phase 5. That last part matters
  more than it looks: this document has an "Overall" line that reads
  ``5 of 6`` while deliberately *not* counting Phase 5, and a reader who only
  reads the headline could easily think six phases were done.
* **The Phase 6 deliverables are present by name**, and the sentences the phase
  depends on are still there — in particular that the tiered rollout has no
  schedule, which is the honest half of that section.
* **The gates and tests the ledger names exist.** The Phase 5 and Phase 6 lines
  cite specific test names as evidence; a citation to a test that was renamed or
  deleted is the same class of lie as a stale count, and it is checkable. This is
  the check that makes the ledger trustworthy rather than merely detailed.

It also refuses the overclaims this plan is most likely to acquire: a document
that starts describing a cell as certified, or that credits the programme with a
schedule it does not have.

Each checker is proven to bite against a mutated copy of the document.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/01_RUNTIME_CERTIFICATION.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")

#: The Phase 6 deliverables, by the heading each one must carry.
REQUIRED_SECTIONS: Final[tuple[str, ...]] = (
    "## Fault-catalog reliability matrix",
    "## Public compatibility matrix",
    "## Tiered rollout",
    "## Rollout order",
)

#: Short, line-break-independent fragments of the reasoning the phase rests on.
#: Reflowing the prose must not be able to satisfy or break the gate; only
#: deleting the reasoning should.
REQUIRED_SENTENCES: Final[tuple[str, ...]] = (
    "the honest zero is a zero",
    "unreached",
    "the first two tiers have no schedule",
    "derived from the record store",
    "**catalog fault id**",
    "fresh database is **0**",
)

#: Claims this plan must never make. The document's own denials — "the honest
#: zero", "have no schedule" — must not match these.
FORBIDDEN_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (
        r"\bcell[s]? (?:is|are|has been|have been) certified\b",
        "no live cell has been certified",
    ),
    (
        r"\bcertification (?:runs|scheduled|schedules) nightly\b",
        "the sweep runs on demand; nothing calls it on a clock",
    ),
    (
        r"\bregression blocking is wired\b",
        "regression blocking is asserted in a test, not in a pipeline",
    ),
    (
        r"\bany fault is `?verified-live`?\b",
        "verified-live requires a recorded live run; there is none",
    ),
)

#: The open phase. Named so the count cannot quietly reach six while Phase 5 is
#: still advanced-but-not-done.
OPEN_PHASE: Final[str] = "Phase 5"

#: Test names the ledger cites as evidence, paired with the file they live in.
#: Kept as data rather than prose so a rename fails here instead of quietly
#: invalidating a sentence in the ledger.
CITED_TESTS: Final[tuple[tuple[str, str], ...]] = (
    ("tests/unit/test_certification_nightly.py", "test_a_lapsed_claim_is_aged_by_the_clock"),
    (
        "tests/unit/test_certification_badge_honesty.py",
        "test_the_record_store_produces_no_live_certification",
    ),
    (
        "tests/unit/test_certification_gate_arming.py",
        "test_the_cli_matrix_reports_zero_on_a_fresh_database",
    ),
    ("tests/unit/test_readme_honesty.py", "test_no_document_describes_fault_packs_as_signed"),
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
        match = re.match(
            r"^- (Phase \d)(.*?):\s*(DONE|INCOMPLETE|not started|partially|\*\*)", stripped
        )
        if match:
            lines[match.group(1)] = stripped
    return lines


def done_phase_count(document: str) -> int:
    return sum(1 for line in ledger_lines(document).values() if ": DONE" in line)


def claimed_overall(document: str) -> tuple[int, int] | None:
    match = re.search(r"^Overall:\s*(\d+)\s+of\s+(\d+)", document, re.MULTILINE)
    return (int(match.group(1)), int(match.group(2))) if match else None


def open_phases(document: str) -> list[str]:
    return [phase for phase, line in sorted(ledger_lines(document).items()) if ": DONE" not in line]


def missing_sections(document: str) -> list[str]:
    return [heading for heading in REQUIRED_SECTIONS if heading not in document]


def missing_sentences(document: str) -> list[str]:
    return [sentence for sentence in REQUIRED_SENTENCES if sentence not in document]


#: Words that turn a match into a denial. Checked over the whole sentence, not
#: the match: this document says "**No live cell has been certified.**" and "no
#: cell is certified yet", and a fixed-width lookbehind cannot see either.
NEGATIONS: Final[tuple[str, ...]] = (
    "no ",
    "not ",
    "never",
    "nothing",
    "must stay",
    "must remain",
    "the first",
    "once a promotion",
    "until a real",
    "when the first",
)


def _sentence_around(text: str, start: int) -> str:
    """The sentence containing ``start``: the nearest sentence boundary behind it."""
    preceding = text[:start]
    for mark in (". ", ".\n", "? ", "! ", "; ", ", and ", ", but "):
        index = preceding.rfind(mark)
        if index != -1:
            preceding = preceding[index + len(mark) :]
    return preceding.lower()


def forbidden_claims_found(document: str) -> list[str]:
    found: list[str] = []
    for pattern, reason in FORBIDDEN_CLAIMS:
        for match in re.finditer(pattern, document, re.IGNORECASE):
            if any(word in _sentence_around(document, match.start()) for word in NEGATIONS):
                continue
            found.append(f"{reason}: ...{document[max(0, match.start() - 60) : match.end()]!r}")
    return found


def dangling_citations() -> list[str]:
    """Cited tests that no longer exist.

    The ledger cites test names as its evidence. A citation to a test that was
    renamed or deleted is a stale claim of exactly the kind this plan's own gate
    exists to catch elsewhere, and it is mechanically checkable.
    """
    missing: list[str] = []
    for relative, name in CITED_TESTS:
        path = REPO_ROOT / relative
        if not path.exists():
            missing.append(f"{relative} does not exist")
        elif name not in path.read_text(encoding="utf-8"):
            missing.append(f"{relative} does not define {name}")
    return missing


# ── the ledger ───────────────────────────────────────────────────────────────


def test_the_ledger_carries_one_line_per_phase() -> None:
    assert sorted(ledger_lines(PLAN)) == [f"Phase {n}" for n in range(1, 7)]


def test_the_overall_count_equals_the_number_of_done_lines() -> None:
    overall = claimed_overall(PLAN)

    assert overall is not None, "the STATUS block must carry an Overall: line"
    assert overall == (done_phase_count(PLAN), len(ledger_lines(PLAN)))


def test_exactly_one_phase_is_open_and_the_ledger_names_it() -> None:
    """``5 of 6`` is only honest beside an explicit "and this is the one"."""
    assert open_phases(PLAN) == [OPEN_PHASE]


# ── the Phase 6 deliverables ─────────────────────────────────────────────────


def test_the_four_sections_are_in_the_document() -> None:
    assert missing_sections(PLAN) == []


def test_the_sections_keep_their_own_denials() -> None:
    """The honest half of each section, so an edit cannot reduce it to a promise."""
    assert missing_sentences(PLAN) == []


def test_every_test_the_ledger_cites_as_evidence_still_exists() -> None:
    assert dangling_citations() == []


# ── the claims the document must not make ─────────────────────────────────────


def test_the_document_makes_no_literal_false_claim() -> None:
    assert forbidden_claims_found(PLAN) == []


def test_the_document_does_not_claim_a_certified_cell_or_a_schedule() -> None:
    """The phase's own honesty risk: the programme acquiring credit it has not earned."""
    assert forbidden_claims_found(PLAN) == []


# ── negative controls: each checker must bite ────────────────────────────────

_MUTATIONS: Final[tuple[tuple[str, Callable[[str], str], Callable[[str], object]], ...]] = (
    (
        "the Overall count inflated to six",
        lambda d: d.replace("Overall: 5 of 6", "Overall: 6 of 6", 1),
        claimed_overall,
    ),
    (
        "Phase 5 silently marked done",
        lambda d: re.sub(
            r"^- Phase 5: \*\*substantially advanced",
            "- Phase 5: DONE",
            d,
            count=1,
            flags=re.MULTILINE,
        ),
        open_phases,
    ),
    (
        "the tiered rollout section removed",
        lambda d: d.replace("## Tiered rollout", "## Removed", 1),
        lambda d: len(missing_sections(d)),
    ),
    (
        "the no-schedule denial dropped",
        lambda d: d.replace(
            "the first two tiers have no schedule", "the first two tiers run nightly"
        ),
        lambda d: len(missing_sentences(d)) + len(forbidden_claims_found(d)),
    ),
    (
        "the unreached verdict dropped from the matrix section",
        lambda d: d.replace("unreached", "pending"),
        lambda d: len(missing_sentences(d)),
    ),
    (
        "a cell claimed certified",
        lambda d: d + "\nThe docker 24.04 cell is certified.\n",
        lambda d: len(forbidden_claims_found(d)),
    ),
    (
        "regression blocking claimed as wired",
        lambda d: d + "\nRegression blocking is wired into the pipeline.\n",
        lambda d: len(forbidden_claims_found(d)),
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
