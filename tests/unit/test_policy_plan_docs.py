"""Plan 07's ledger, its example block, and the dimensions it names.

Three things drift in a plan document, and each is checkable:

* **The ledger against itself.** One line per phase, ``Overall:`` equal to the
  ``DONE`` count. The count is the sentence a reader skims to, so it has to be
  derived rather than remembered.
* **The citations.** The ledger names test files and modules as its evidence. A
  citation to something that no longer exists is the same class of lie as a
  stale count.
* **The dimensions.** Phase 6's acceptance is "no doc describes a policy
  dimension the evaluator does not enforce", and the cheap half of that is
  checkable today: every dimension this document names must be a member of
  ``PolicyDimension``. The expensive half — that the evaluator reads it — is the
  gate's own job, not a document's, and is not claimed here.

The **DENY example** is plan 07 Phase 3's acceptance criterion and it is checked
where the engine is in reach, in ``tests/unit/test_policy_surface.py::Test
TheDocumentedExampleIsTheEngines``: this file asserts the block is *present* and
four lines long, that suite asserts it is byte-identical to what the engine
renders. Splitting them this way keeps one owner for "what the engine says" and
one for "what the document says", and neither can quietly change alone.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from mayhem.domain.policy import PolicyDimension

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN = (REPO_ROOT / "docs/v1.1.0/07_POLICY_SAFETY_ENGINE.md").read_text(encoding="utf-8")

#: The block the phase promises is the engine's, verbatim.
EXAMPLE_HEAD: Final[str] = "```text\nDENY\n"
EXAMPLE_LINES: Final[int] = 4

#: Files the ledger cites as evidence. Data, not prose, so a rename fails here.
CITED_PATHS: Final[tuple[str, ...]] = (
    "src/mayhem/controller/policy_authoring.py",
    "src/mayhem/controller/policy_gate.py",
    "src/mayhem/infra/policy_store.py",
    "src/mayhem/cli/policy_cmd.py",
    "tests/unit/test_policy_surface.py",
    "tests/unit/test_policy_bundle.py",
    "tests/unit/test_policy_explain.py",
)

#: The heading whose body is a list of dimensions. Every phrase in it must map to
#: a real ``PolicyDimension``; that is plan 07 Phase 6's acceptance criterion
#: ("no doc describes a policy dimension the evaluator does not enforce") in the
#: one part that is checkable from the document side.
DIMENSIONS_HEADING: Final[str] = "## Policy dimensions"


def documented_dimension_phrases(document: str) -> list[str]:
    """The phrases the document's own dimension list is made of."""
    match = re.search(
        rf"^{re.escape(DIMENSIONS_HEADING)}\n(.*?)(?=^## )", document, re.S | re.MULTILINE
    )
    if match is None:
        return []
    body = match.group(1).strip().rstrip(".")
    return [
        phrase.strip() for line in body.splitlines() for phrase in line.split(",") if phrase.strip()
    ]


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
        match = re.match(r"^- (Phase \d)(.*?):\s*(DONE|\*\*|not started|partially)", stripped)
        if match:
            lines[match.group(1)] = stripped
    return lines


def done_count(document: str) -> int:
    return sum(1 for line in ledger_lines(document).values() if ": DONE" in line)


def claimed_overall(document: str) -> tuple[int, int] | None:
    match = re.search(r"^Overall: (\d+) of (\d+)", document, re.MULTILINE)
    return (int(match.group(1)), int(match.group(2))) if match else None


def example_block(document: str) -> list[str]:
    """The ``DENY`` example, as lines. Empty when the block is gone."""
    match = re.search(r"```text\n(.*?)```", document, re.S)
    return match.group(1).splitlines() if match else []


def dangling_citations(document: str) -> list[str]:
    """Every ``src/`` or ``tests/`` path the document names that is not there."""
    named = set(re.findall(r"`((?:src/mayhem|tests/unit)/[A-Za-z0-9_./-]+\.py)`", document))
    return sorted(path for path in named if not (REPO_ROOT / path).is_file())


def unknown_dimensions(document: str) -> list[str]:
    """Dimensions this document lists that ``PolicyDimension`` does not have.

    Read out of the document rather than a list kept here, because the earlier
    version compared a hardcoded phrase list against the enum and so could only
    ever confirm itself: every phrase in it was real by construction, and an
    invented dimension added to the document was invisible. "deployment/incident
    state" is two members written as one phrase, so a slash is read as a
    conjunction rather than as part of a name.
    """
    invented: set[str] = set()
    for phrase in documented_dimension_phrases(document):
        parts = [part.strip() for part in re.split(r"[/&]", phrase) if part.strip()]
        for part in parts:
            key = part.lower().replace(" ", "_")
            if not any(key in dim.value for dim in PolicyDimension):
                invented.add(part)
    return sorted(invented)


class TestTheLedger:
    def test_one_line_per_phase(self) -> None:
        assert sorted(ledger_lines(PLAN)) == [f"Phase {n}" for n in range(1, 7)]

    def test_the_overall_count_equals_the_done_lines(self) -> None:
        assert claimed_overall(PLAN) == (done_count(PLAN), 6)

    def test_the_count_finder_works_on_the_real_document(self) -> None:
        """Otherwise the equality above would hold at zero and zero."""
        assert done_count(PLAN) >= 4


class TestTheCitations:
    def test_every_cited_path_exists(self) -> None:
        assert dangling_citations(PLAN) == []

    def test_the_citation_checker_finds_its_work(self) -> None:
        """Otherwise it passes on a document that cites nothing."""
        assert dangling_citations(PLAN + "\n`src/mayhem/controller/not_a_module.py`\n") == [
            "src/mayhem/controller/not_a_module.py"
        ]

    def test_and_the_files_the_ledger_names_as_evidence_are_present(self) -> None:
        for relative in CITED_PATHS:
            assert (REPO_ROOT / relative).is_file(), relative


class TestTheExampleBlock:
    def test_it_is_present_and_four_lines(self) -> None:
        block = example_block(PLAN)

        assert block, "the plan must keep its Example result"
        assert len(block) == EXAMPLE_LINES
        assert block[0] == "DENY"

    def test_its_lines_are_labelled_the_way_the_engine_labelled_them(self) -> None:
        block = example_block(PLAN)

        assert [line.split(":")[0] for line in block] == [
            "DENY",
            "Reason",
            "Required",
            "Plan digest",
        ]

    def test_the_verbatim_check_lives_where_the_engine_is(self) -> None:
        """Two owners, so neither can change alone: this shape, that suite the words."""
        surface = (REPO_ROOT / "tests/unit/test_policy_surface.py").read_text(encoding="utf-8")

        assert "class TestTheDocumentedExampleIsTheEngines" in surface


class TestTheDimensionsAreReal:
    def test_the_document_invents_no_dimension(self) -> None:
        assert unknown_dimensions(PLAN) == []

    def test_the_document_really_lists_its_dimensions(self) -> None:
        """Otherwise the checker below is scanning an empty section."""
        assert len(documented_dimension_phrases(PLAN)) >= 10

    def test_the_checker_notices_an_invented_one(self) -> None:
        mutated = PLAN.replace("cloud cost", "quantum entanglement")

        assert "quantum entanglement" in unknown_dimensions(mutated)

    def test_and_a_real_dimension_is_not_flagged(self) -> None:
        """Two-sided, so the mutation above cannot pass by flagging everything."""
        assert unknown_dimensions(PLAN.replace("cloud cost", "damage budget")) == []

    def test_and_removing_the_section_empties_the_list(self) -> None:
        assert documented_dimension_phrases(PLAN.replace(DIMENSIONS_HEADING, "## Other")) == []


class TestTheCheckersBite:
    """Each checker, against a mutated copy. A check that cannot fail is not one."""

    def test_the_ledger_checker_catches_an_inflated_count(self) -> None:
        inflated = re.sub(r"^Overall: \d+ of 6", "Overall: 6 of 6", PLAN, count=1, flags=re.M)

        assert inflated != PLAN
        assert claimed_overall(inflated) != (done_count(inflated), 6)

    def test_the_ledger_checker_catches_a_missing_phase_line(self) -> None:
        stripped = re.sub(r"^- Phase 6[^\n]*\n", "", PLAN, count=1, flags=re.MULTILINE)

        assert sorted(ledger_lines(stripped)) != [f"Phase {n}" for n in range(1, 7)]

    def test_the_example_checker_catches_a_deleted_block(self) -> None:
        assert example_block(PLAN.replace("```text\nDENY", "```text\nALLOW"))[0] == "ALLOW"

    def test_and_the_document_still_carries_the_deny_block(self) -> None:
        assert PLAN.startswith(EXAMPLE_HEAD) or EXAMPLE_HEAD in PLAN
