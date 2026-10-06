"""Plan 22 Phase 6 — the honesty gate over the coverage-and-regression document.

The phase's acceptance is *"no dashboard shows a coverage percentage without
defining its denominator on the same screen"* — an acceptance about rendering,
held where the renderers live in `test_coverage_matrix.py` and
`test_coverage_service.py`. This file is the document half of the phase: it
parses `docs/v1.1.0/22_RESILIENCE_COVERAGE_REGRESSION.md` and holds it to the
code, the way `test_fabric_plan_docs.py` holds the fabric plan to the fabric.

* **The ledger against itself.** ``Overall:`` equals the number of ``DONE``
  lines; a summary that disagrees with its own ledger is the ledger lying.
* **Every refusal code the document quotes is real.** A rule id an operator is
  told to triage from must be one the source can raise.
* **The methodology's five load-bearing claims stay written down.** Cited
  evidence only, no catalog member, blocked cells out of the denominator,
  never-run cells in it, empty cell renders untested.
* **The rollout tiers stay in their recorded order**, and the forbidden false
  claims stay out — a document that grows a guarantee its code disclaims is
  the same lie a dashboard would tell.
* **Every checker bites.** Each checker is run against a mutated copy of the
  document and must fail there; a checker that cannot fail is decoration, and
  the negative controls prove the gate rather than the prose.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from mayhem.domain.coverage import CellState
from mayhem.infra import coverage_service as cs

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/22_RESILIENCE_COVERAGE_REGRESSION.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")

#: The three rollout tiers, in the order the plan records.
ROLLOUT_TIERS: Final[tuple[str, ...]] = (
    "Service×fault cells first",  # noqa: RUF001 — the document's own character
    "Journeys and business metrics second",
    "Continuous comparison third",
)

#: Fragments the phase's reasoning rests on. Reflowing the prose must not be
#: able to satisfy or break the gate; only deleting the reasoning should.
REQUIRED_SENTENCES: Final[tuple[str, ...]] = (
    "Only cited evidence counts",
    "percentage without its denominator",
    "never-run cells stay in it",
    "Every step asserts something",
    "Authoring proves nothing",
    "A finding is two runs and a sentence",
    "insufficient_data",
    "`insufficient_data` is\nan outcome, never a pass",
)

#: Claims this document must never make. Its own subject — coverage counted
#: from cited evidence, never from catalog presence — must not grow the
#: opposite claims.
FORBIDDEN_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (
        r"\bcatalog presence (?:counts|is counted)(?:\s+as\s+coverage)?\b",
        "catalog presence never counts as coverage",
    ),
    (
        r"\bauth(?:or)?(?:ing|ored)? a journey (?:proves|counts as)(?:\s+coverage)?\b",
        "authoring a journey proves nothing; only executed evidence moves a cell",
    ),
    (
        r"\ba refused comparison (?:is|reads as) (?:a )?pass\b",
        "a refused comparison is never scored, and never a pass",
    ),
    (
        r"\bthe release gate (?:has|has a|gained a) production caller\b",
        "no production caller passes open_findings to release_gate yet",
    ),
)


def _real_rule_ids() -> set[str]:
    """Every rule id the plan-22 surface can actually raise.

    Two sources: the ``RULE_*`` constants the modules declare, and the string
    literals the service raises inline — a refusal does not have to be a named
    constant to be real, and a document quoting a literal the source raises is
    quoting something an operator can actually hit.
    """
    ids: set[str] = set()
    for name, value in vars(cs).items():
        if name.startswith("RULE_") and isinstance(value, str):
            ids.update({name, value})
    source = (REPO_ROOT / "src/mayhem/infra/coverage_service.py").read_text(encoding="utf-8")
    ids.update(re.findall(r'"(comparison_service\.[a-z_]+)"', source))
    from mayhem.domain import comparison, journeys

    for module in (comparison, journeys):
        for name, value in vars(module).items():
            if (
                name.isupper()
                and isinstance(value, str)
                and re.fullmatch(r"[a-z_]+\.[a-z_]+", value)
            ):
                ids.add(value)
    return ids


def _real_states() -> set[str]:
    return {member.value for member in CellState}


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


def missing_sentences(document: str) -> list[str]:
    return [sentence for sentence in REQUIRED_SENTENCES if sentence not in document]


def forbidden_claims_found(document: str) -> list[str]:
    return [
        reason
        for pattern, reason in FORBIDDEN_CLAIMS
        if re.search(pattern, document, re.IGNORECASE)
    ]


def unquoted_rule_ids(document: str) -> list[str]:
    """Rule-id-shaped backticked ids the document quotes that no module defines.

    Test filenames share the dotted shape and are not rule ids; the ledger
    quotes them as files, and the regex excludes them by name rather than by
    exempting the match.
    """
    quoted = set(re.findall(r"`([a-z]+(?:_[a-z]+)+\.[a-z_]+)`", document))
    quoted -= {name for name in quoted if name.startswith("test_")}
    return sorted(code for code in quoted if code not in _real_rule_ids())


def unknown_cell_states_quoted(document: str) -> list[str]:
    """Backticked state-shaped words the Phase 6 guides quote that the vocabulary lacks.

    Scoped to the guides (everything from the methodology section on) rather
    than the whole document: the ledger legitimately quotes method names such
    as ``set_certification_state``, which share the ``_state`` suffix and are
    not states. An invented *state* in the guides is the lie this checker
    exists for — a guide that invents a state the accounting never records.
    """
    _head, separator, rest = document.partition("## Coverage methodology")
    if not separator:
        return ["the guides section is missing"]
    guides = rest.partition("## STATUS")[0]
    quoted = set(re.findall(r"`([a-z_]+)`", guides))
    real = _real_states() | {
        "insufficient_data",
        "unknown",
        "regressed",
        "unchanged",
        "improved",
        "incomparable",
        "run_id",
    }
    return sorted(
        word
        for word in quoted
        if word not in real
        and (word in {"passed_by_absence", "covered_by_catalog"} or word.endswith("_state"))
    )


def rollout_tiers_out_of_order(document: str) -> bool:
    """True unless all three tiers appear, in the recorded order."""
    try:
        section = document[document.index("## Rollout order") :]
        positions = [section.index(tier) for tier in ROLLOUT_TIERS]
    except ValueError:
        return True
    return positions != sorted(positions)


# ── the tests ─────────────────────────────────────────────────────────────────


def test_the_ledger_carries_one_line_per_phase() -> None:
    assert sorted(ledger_lines(PLAN)) == [f"Phase {n}" for n in range(1, 7)]


def test_the_overall_count_equals_the_number_of_done_lines() -> None:
    overall = claimed_overall(PLAN)
    assert overall is not None, "the STATUS block must carry an Overall: line"
    done = done_phase_count(PLAN)
    assert overall[0] == done, (
        f"Overall claims {overall[0]} but {done} ledger lines say DONE — the count "
        "this repository's ledgers exist to refuse"
    )
    assert overall[1] == 6


def test_the_document_keeps_its_own_reasoning() -> None:
    assert missing_sentences(PLAN) == []


def test_the_document_makes_no_literal_false_claim() -> None:
    assert forbidden_claims_found(PLAN) == []


def test_every_rule_id_the_document_quotes_is_real() -> None:
    assert unquoted_rule_ids(PLAN) == []


def test_every_state_the_document_quotes_is_real() -> None:
    assert unknown_cell_states_quoted(PLAN) == []


def test_the_rollout_tiers_stay_in_order() -> None:
    assert not rollout_tiers_out_of_order(PLAN)


def test_the_denominator_rule_is_stated_where_the_renderers_are_tested() -> None:
    """The acceptance's other half lives with the renderers, not only in prose."""
    from pathlib import Path as _Path

    matrix_test = _Path(__file__).resolve().parents[1] / "unit/test_coverage_matrix.py"
    text = matrix_test.read_text(encoding="utf-8")
    assert "denominator" in text


# ── negative controls: every checker must bite ────────────────────────────────

_MUTATIONS: Final[tuple[tuple[str, Callable[[str], str], Callable[[str], object]], ...]] = (
    (
        "the Overall count walked back to five",
        lambda d: d.replace("Overall: 6 of 6", "Overall: 5 of 6", 1),
        lambda d: claimed_overall(d)[0] == done_phase_count(d),
    ),
    (
        "Phase 6 reopened in prose while its ledger line says DONE",
        lambda d: re.sub(
            r"^- Phase 6 \(docs, honesty gates, rollout\): DONE",
            "- Phase 6 (docs, honesty gates, rollout): INCOMPLETE",
            d,
            count=1,
            flags=re.MULTILINE,
        ),
        lambda d: done_phase_count(d) == 6,
    ),
    (
        "a fabricated rule id is quoted",
        # Well-shaped on purpose: an id outside the dotted-underscore regex
        # would fall out of the quoted set and the mutation would test nothing.
        lambda d: d.replace(
            "`comparison_service.finding_cites_unrecorded_run`",
            "`comparison_service.finding_cites_ghost_run`",
            1,
        ),
        lambda d: unquoted_rule_ids(d) == [],
    ),
    (
        "the methodology's first claim is deleted",
        lambda d: d.replace("Only cited evidence counts", "Evidence counts", 1),
        lambda d: missing_sentences(d) == [],
    ),
    (
        "a forbidden claim is introduced",
        lambda d: d.replace(
            "## Rollout order", "Catalog presence counts as coverage.\n\n## Rollout order", 1
        ),
        lambda d: forbidden_claims_found(d) == [],
    ),
    (
        "a rollout tier is dropped",
        lambda d: d.replace("Continuous comparison third", "Continuous comparison last", 1),
        lambda d: not rollout_tiers_out_of_order(d),
    ),
    (
        "an invented cell state is quoted",
        lambda d: d.replace("`unknown`", "`covered_by_catalog`", 1),
        lambda d: unknown_cell_states_quoted(d) == [],
    ),
)


@pytest.mark.parametrize("name, mutate, holds", _MUTATIONS, ids=[m[0] for m in _MUTATIONS])
def test_each_checker_notices_its_own_mutation(
    name: str, mutate: Callable[[str], str], holds: Callable[[str], object]
) -> None:
    mutated = mutate(PLAN)
    assert mutated != PLAN, f"the mutation {name!r} changed nothing"
    assert not holds(mutated), f"the checker behind {name!r} did not bite"


def test_the_clean_document_passes_every_checker() -> None:
    assert claimed_overall(PLAN)[0] == done_phase_count(PLAN)
    assert missing_sentences(PLAN) == []
    assert forbidden_claims_found(PLAN) == []
    assert unquoted_rule_ids(PLAN) == []
    assert unknown_cell_states_quoted(PLAN) == []
    assert not rollout_tiers_out_of_order(PLAN)
