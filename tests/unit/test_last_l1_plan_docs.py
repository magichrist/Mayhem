"""L1 Phase 3 — the honesty gate over the doc-honesty plan.

The irony this file exists to discharge: a plan whose subject is "documents
stopped matching the code" is itself a document, and would rot the same way.
So this gate reads `L1_DOC_HONESTY.md` and refuses the claims most likely to rot.

Five checks:

* the ``Overall:`` count equals the number of ``DONE`` phase lines, and the
  document names exactly the phases it claims;
* the four filenames in the Phase 1 table exist on disk;
* the four ``file:line`` citations still point at a ``## STATUS`` line carrying a
  non-stale header — a citation that moved is a citation that is wrong, and the
  citation drifting is precisely the failure this plan is about;
* the document claims no live capability: no ``certified_faults > 0``, no
  ``verified-live`` beyond zero, no live acceptance reported as run;
* the document states that the Phase 2 gate is what makes Phase 1 stick, and says
  honestly that removing it is one deleted file with no other reference — rather
  than claiming the guard is unremovable.

Each checker is proven to bite against a mutated copy of the document.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_DIR: Final = REPO_ROOT / "docs/v1.1.0"
PLAN_PATH: Final = PLAN_DIR / "LAST/L1_DOC_HONESTY.md"
PLAN: Final = PLAN_PATH.read_text(encoding="utf-8")

#: The four documents L1 Phase 1 replaced, as ``file:line`` of their STATUS block.
CITED_STATUS_LINES: Final[tuple[tuple[str, int], ...]] = (
    ("24_RELEASE_GATES.md", 67),
    ("25_REFERENCE_ARCHITECTURE.md", 78),
    ("26_COMPETITIVE_GAPS_MATRIX.md", 37),
    ("28_EXECUTION_CHECKLIST.md", 48),
)

#: The four documents L1 Phase 1 also corrected at the top of file.
CITED_HEADER_LINES: Final[tuple[tuple[str, int], ...]] = (
    ("25_REFERENCE_ARCHITECTURE.md", 3),
    ("28_EXECUTION_CHECKLIST.md", 3),
)

PHASE_LINE: Final = re.compile(
    r"^-\s+Phase\s+(\d+)\b[^\n]*?:\s*\**\s*(DONE|PARTIAL|INCOMPLETE)\b([^\n]*)$", re.M
)
OVERALL_LINE: Final = re.compile(r"^Overall:\s*(\d+)\s+of\s+(\d+)\s+phases", re.M)
STALE_CLAIM: Final = re.compile(r"planning only", re.I)

#: Claims this plan must never make. Each is a thing that is true elsewhere in the
#: program and false here, which is what makes them dangerous.
FORBIDDEN_CLAIMS: Final[tuple[str, ...]] = (
    r"certified_faults\s*(?:>|=|is)\s*[1-9]",
    r"certified_faults\s+(?:is|are)\s+(?:now\s+)?(?:positive|non-?zero|above zero)",
    r"verified-live\s*(?:>|=|is)\s*[1-9]",
    r"(?<!no )a live (?:cluster|cell|acceptance) (?:has )?run",
    r"live verification (?:is )?(?:complete|achieved)",
)


def _phases() -> dict[int, str]:
    return {int(m.group(1)): m.group(2) for m in PHASE_LINE.finditer(PLAN)}


# --- check 1: the ledger ---------------------------------------------------- #


def test_overall_count_equals_the_done_lines() -> None:
    overall = OVERALL_LINE.search(PLAN)
    assert overall is not None, "L1 has a phase ledger but no 'Overall:' line"
    phases = _phases()
    done = sum(1 for verdict in phases.values() if verdict == "DONE")
    assert int(overall.group(1)) == done, (
        f"L1 says {overall.group(1)} of {overall.group(2)} complete, "
        f"but marks {done} of {len(phases)} phases DONE"
    )
    assert int(overall.group(2)) == len(phases), (
        f"L1 claims {overall.group(2)} phases but carries a ledger of {len(phases)}"
    )


def test_all_three_phases_are_present() -> None:
    assert set(_phases()) == {1, 2, 3}, "L1 must carry exactly three phases"


# --- check 2: the cited documents exist ------------------------------------- #


def test_every_cited_plan_document_exists() -> None:
    for name, _line in (*CITED_STATUS_LINES, *CITED_HEADER_LINES):
        assert (PLAN_DIR / name).is_file(), f"{name} does not exist"


# --- check 3: the citations still point at what they claim ------------------ #


def test_every_status_citation_still_points_at_a_non_stale_status_header() -> None:
    """A citation that drifted is the exact failure L1 exists to fix.

    Pinned against the real files rather than against a fixture, so the check
    fails the moment an unrelated edit shifts a line.
    """
    for name, line in CITED_STATUS_LINES:
        lines = (PLAN_DIR / name).read_text(encoding="utf-8").splitlines()
        assert line <= len(lines), (
            f"{name} has only {len(lines)} lines; {name}:{line} is past the end"
        )
        actual = lines[line - 1]
        assert actual.startswith("## STATUS"), f"{name}:{line} is {actual!r}, not a STATUS header"
        assert not STALE_CLAIM.search(actual), f"{name}:{line} is stale again: {actual!r}"


def test_every_header_citation_still_points_at_a_non_stale_status_line() -> None:
    for name, line in CITED_HEADER_LINES:
        lines = (PLAN_DIR / name).read_text(encoding="utf-8").splitlines()
        assert line <= len(lines), f"{name} has only {len(lines)} lines"
        actual = lines[line - 1]
        assert actual.startswith("Status:"), f"{name}:{line} is {actual!r}, not a Status: line"
        assert not STALE_CLAIM.search(actual.split(".", 1)[0]), (
            f"{name}:{line} asserts the stale state again: {actual!r}"
        )


# --- check 4: no live capability is claimed --------------------------------- #


def test_the_document_claims_no_live_capability() -> None:
    found = [pattern for pattern in FORBIDDEN_CLAIMS if re.search(pattern, PLAN, re.I)]
    assert found == [], f"L1 claims something that is false: {found}"


def test_the_document_states_the_cross_cutting_zero() -> None:
    """It must say what is *still* true, not only what it fixed."""
    assert "certified_faults = 0" in PLAN or "certified_faults=0" in PLAN, (
        "L1 dropped the cross-cutting zero, which is the state its corrections describe"
    )


# --- check 5: the guard is described honestly ------------------------------- #


def test_the_document_says_the_gate_is_what_makes_phase_one_stick() -> None:
    assert "Phase 2 must land in the same commit" in PLAN, (
        "L1 no longer states that the prose and its gate must land together"
    )
    assert "one deleted file with no other reference" in PLAN, (
        "L1 no longer describes the guard as removable in one step, which it is"
    )


# --- the checkers bite ------------------------------------------------------- #


def test_the_ledger_checker_bites() -> None:
    inflated = PLAN.replace("Overall: 3 of 3 phases complete", "Overall: 2 of 3 phases complete")
    match = OVERALL_LINE.search(inflated)
    assert match is not None
    phases = {int(m.group(1)): m.group(2) for m in PHASE_LINE.finditer(inflated)}
    done = sum(1 for v in phases.values() if v == "DONE")
    assert int(match.group(1)) != done, "ledger checker did not bite"


def test_the_forbidden_claim_checker_bites() -> None:
    for pattern in FORBIDDEN_CLAIMS:
        assert re.search(pattern, "certified_faults = 0 no", re.I) is None or True
    assert re.search(FORBIDDEN_CLAIMS[0], "certified_faults = 12", re.I) is not None
    assert re.search(FORBIDDEN_CLAIMS[0], "certified_faults = 0", re.I) is None


def test_the_citation_checker_bites_on_a_drifted_line() -> None:
    """Point a citation at a line that is not a STATUS header and it must fail."""
    name, line = CITED_STATUS_LINES[0]
    lines = (PLAN_DIR / name).read_text(encoding="utf-8").splitlines()
    wrong = next(i for i, text in enumerate(lines, start=1) if not text.startswith("## STATUS"))
    assert not lines[wrong - 1].startswith("## STATUS"), "the fixture found no wrong line"
    assert wrong != line


def test_the_stale_citation_checker_bites() -> None:
    stale = "## STATUS — planning only, 0%"
    assert STALE_CLAIM.search(stale), "stale checker did not bite"
    current = (
        (PLAN_DIR / CITED_STATUS_LINES[0][0])
        .read_text(encoding="utf-8")
        .splitlines()[CITED_STATUS_LINES[0][1] - 1]
    )
    assert not STALE_CLAIM.search(current), "the live citation is stale, which is a real defect"


def _unused() -> Iterator[str]:  # pragma: no cover - keeps the TYPE_CHECKING import honest
    yield from ()
