"""Plan 21 Phase 6 — the honesty gate over the plan document.

Phases 1 to 5 built the model, the engine, the surface, the boundary and the
tests. This file gates the *document*, and it exists because this pass already
found two claims in it that the code had made false.

**Why prose needs a gate here.** Most of a plan's ledger is checkable by opening
the code. This plan had two claims that were not: that the ``advisor`` group was
unreachable. It *was*, once; an integration pass registered it, and the document
kept saying otherwise in two separate places. Both were wrong in the flattering
direction for the reader — one understated a shipped surface — and neither would
have been caught by a test that only counted phases. A document that calls a
reachable surface unreachable is the same defect as one that calls an unreachable
surface reachable: the reader is misled about what they can type.

So the document is parsed, not trusted:

* the per-phase ledger has one line per phase, and the ``Overall:`` count equals
  the number of ``DONE`` lines — **a summary disagreeing with its own ledger is
  the defect this file exists to catch**;
* the Phase 6 deliverables are present by name: the methodology guide, the replay
  guide, the scenario authoring guide, and the rollout order;
* eight literal claims this plan must never make are absent;
* ``advisor`` is resolved through the **live Click tree**, and the document may
  not describe it as unregistered or absent — a claim checked against the code
  rather than against the prose.

Negative controls, at the end: a copy of the document is mutated so that each
property breaks, and the checker is asserted to notice — so a checker that passes
vacuously is distinguishable from one that bites.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/21_RELIABILITY_ADVISOR.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")

#: The Phase 6 deliverables, by the heading each one must carry.
REQUIRED_SECTIONS: Final[tuple[str, ...]] = (
    "## Advisor methodology",
    "## Incident replay guide",
    "## Scenario authoring guide",
    "## Rollout order",
)

#: The claims this plan must never make. Deliberately narrow and literal: a prose
#: gate cannot judge intent, so it judges the smallest set of literal claims that
#: would each be a distinct lie. The surrounding prose carries the reasoning a
#: regex cannot, and every one of these is written so that the document's own
#: denials ("carries no approval", "grants nothing") do not match it.
FORBIDDEN_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (r"\badvisor (?:approves|authorises|authorizes|executes)\b", "the advisor grants nothing"),
    (r"\bgrants? (?:approval|authorization|authorisation)\b", "a seal grants nothing"),
    (
        r"\brecommendations? (?:are|is) (?:approved|certified|authorized|authorised)\b",
        "a recommendation is advisory and grants nothing",
    ),
    (r"\b(?:approval|authorisation|authorization) is not required\b", "approval is mandatory"),
    (r"\bwithout (?:human |any )?approval\b", "approval is mandatory at every step"),
    (
        r"\bdirectly (?:executes|dispatches|runs) (?:a|the) (?:candidate|plan|draft)\b",
        "a candidate takes the ordinary door",
    ),
    (r"\bthe advisor (?:runs|dispatches) experiments?\b", "the advisor is read-only"),
    (
        r"\bverified[- ]live (?:was|is) (?:achieved|promoted|reached|granted)\b",
        "nothing in this plan is verified-live",
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
    """How many ledger lines claim the phase is done."""
    return sum(1 for line in ledger_lines(document).values() if ": DONE" in line)


def claimed_overall(document: str) -> tuple[int, int] | None:
    """The ``Overall: X of Y`` pair, or ``None`` when the summary is absent."""
    match = re.search(r"^Overall:\s*(\d+)\s+of\s+(\d+)", document, re.MULTILINE)
    return (int(match.group(1)), int(match.group(2))) if match else None


def missing_sections(document: str) -> list[str]:
    """Required Phase 6 headings the document does not carry."""
    return [heading for heading in REQUIRED_SECTIONS if heading not in document]


def forbidden_claims_found(document: str) -> list[str]:
    """The reasons a literal false claim appears in the document."""
    found: list[str] = []
    for pattern, reason in FORBIDDEN_CLAIMS:
        if re.search(pattern, document, re.IGNORECASE):
            found.append(reason)
    return found


def unreachable_claims_found(document: str) -> list[str]:
    """Ways the document can call a registered command group absent."""
    return [
        reason
        for pattern, reason in (
            (r"\badvisor\b[^.]{0,80}\bis not registered\b", "advisor is registered"),
            (r"`advisor` is absent", "advisor is registered"),
            (r"\bmayhem advisor\b[^.]{0,80}\bdoes not resolve\b", "mayhem advisor resolves"),
        )
        if re.search(pattern, document, re.IGNORECASE)
    ]


# ── the ledger ───────────────────────────────────────────────────────────────


def test_the_ledger_carries_one_line_per_phase() -> None:
    assert sorted(ledger_lines(PLAN)) == [f"Phase {n}" for n in range(1, 7)]


def test_the_overall_count_equals_the_number_of_done_lines() -> None:
    """A summary disagreeing with its own ledger is the defect this file exists for."""
    overall = claimed_overall(PLAN)

    assert overall is not None, "the STATUS block must carry an Overall: line"
    done, total = overall
    assert (done, total) == (done_phase_count(PLAN), len(ledger_lines(PLAN)))
    assert done == total, "plan 21 is complete: a phase is still outstanding"


# ── the Phase 6 deliverables ─────────────────────────────────────────────────


def test_the_three_guides_and_the_rollout_order_are_in_the_document() -> None:
    assert missing_sections(PLAN) == []


def test_the_guides_state_what_they_do_not_grant() -> None:
    """The honesty half of each guide: what a reader must not take from it."""
    for required in (
        "carries no approval",
        "no authorisation",
        "human approval mandatory",
        "is not an incident to replay",
        "proves *integrity*",
        "never *authorship*",
    ):
        assert required in PLAN, f"the guides must state {required!r}"


# ── the claims the document must not make ─────────────────────────────────────


@pytest.mark.parametrize(("claim", "reason"), FORBIDDEN_CLAIMS, ids=lambda p: p[:38])
def test_the_document_makes_no_literal_false_claim(claim: str, reason: str) -> None:
    assert reason not in forbidden_claims_found(PLAN)


def test_the_document_does_not_call_a_registered_surface_unreachable() -> None:
    assert unreachable_claims_found(PLAN) == []


def test_the_advisor_group_really_is_reachable() -> None:
    """So the check above is not vacuous: the claim it guards is currently false.

    Resolved through the live Click tree rather than by reading the registry, so
    a registration that exists in a table but never reaches the app would fail
    here instead of satisfying the prose.
    """
    from click.testing import CliRunner

    from mayhem.cli.app import app

    result = CliRunner().invoke(app, ["advisor", "--help"])

    assert result.exit_code == 0, result.output
    for leaf in ("dashboard", "replay", "submit", "scenario"):
        assert leaf in result.output


# ── negative controls: each checker must bite ────────────────────────────────

_MUTATIONS: Final[tuple[tuple[str, Callable[[str], object], Callable[[str], object]], ...]] = (
    (
        "a done phase demoted to not started",
        lambda d: d.replace("- Phase 4 (safety/evidence): DONE", "- Phase 4: not started", 1),
        done_phase_count,
    ),
    (
        "the Overall count inflated",
        lambda d: d.replace("Overall: 6 of 6", "Overall: 7 of 6", 1),
        claimed_overall,
    ),
    (
        "the replay guide removed",
        lambda d: d.replace("## Incident replay guide", "## Removed", 1),
        lambda d: len(missing_sections(d)),
    ),
    (
        "the document claiming the advisor approves",
        lambda d: d + "\nThe advisor approves the candidate it ranks highest.\n",
        lambda d: len(forbidden_claims_found(d)),
    ),
    (
        "the document claiming the group is unregistered",
        lambda d: d + "\nNote: `advisor` is absent from the registry today.\n",
        lambda d: len(unreachable_claims_found(d)),
    ),
)


@pytest.mark.parametrize(
    ("mutation", "checker", "baseline"),
    [(mutation, checker, checker(PLAN)) for _, mutation, checker in _MUTATIONS],
    ids=[name for name, _, _ in _MUTATIONS],
)
def test_each_checker_notices_its_own_mutation(
    mutation: Callable[[str], str], checker: Callable[[str], object], baseline: object
) -> None:
    mutated = mutation(PLAN)

    assert mutated != PLAN, "the mutation must actually change the document"
    assert checker(mutated) != baseline
