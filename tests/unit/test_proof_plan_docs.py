"""Plan 30 Phase 6 — the honesty gate over the safety-proof document.

The other prose gates in this repository (`test_lowlevel_doc_honesty.py`,
`test_advisor_plan_docs.py`, `test_analytics_plan_docs.py`,
`test_prediction_plan_docs.py`) share one shape, and this plan needs it more
than most. A safety proof is an artifact whose entire value is that a reader can
tell what it *does* establish, so a plan document that overstates it is worse than
no document: it converts a record that checks ran into a warranty.

Phase 6's acceptance criterion is a claim *about prose*, which writing the
sentence cannot discharge. It is discharged by a gate that reads the document and
refuses the claim:

* the per-phase ledger carries one line per phase and the ``Overall:`` count
  equals the number of ``DONE`` lines;
* no phase is still unfinished while the plan claims to be complete — a gate
  that only checked arithmetic would pass a document that quietly demoted a
  finished phase while keeping its count, so ``Overall: 6 of 6`` is asserted
  exactly, and inflating it is the flattering lie;
* the four Phase 6 deliverables are present by name;
* every ``ObligationName``, ``ResiduePredicate`` and ``ProofVerdict`` value is
  named in the document, so a vocabulary the code adds cannot leave the guides
  silently behind — the guides claim completeness, and this is what makes that
  claim checkable;
* the three prose counts the guides assert ("Three verdicts", "Six predicates",
  "nine required obligation names") equal the corresponding enum lengths, so the
  numbers a reader relies on are not allowed to drift from the code;
* the document states that signature verification is *not* implemented, and the
  constant it names is `False` in this build;
* the open phase ledger is empty and the summary says exactly ``6 of 6`` —
  Phase 3 was the last open one and has since landed, so ``Overall: 6 of 6``
  is the correct summary and naming an open phase would now be the stale claim;
* five literal claims are absent, the load-bearing one being that the proof is a
  guarantee, and the document's own *denials* must not match them.

Each checker is proven to bite against a mutated copy of the document.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

from mayhem.domain.safety_proof import ObligationName, ProofVerdict, ResiduePredicate
from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/30_SAFETY_PROOF.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")

#: The Phase 6 deliverables, by the heading each one must carry.
REQUIRED_SECTIONS: Final[tuple[str, ...]] = (
    "## Proof-reading guide",
    "## Residue-obligation catalogue",
    "## Rollout order",
    "## What a proof does not claim",
)

#: Claims this plan must never make. Narrow and literal by design: a prose gate
#: cannot judge intent, so it judges the smallest set of literal claims that
#: would each be a distinct lie. The document's own *denials* — "a record that
#: checks ran", "not a certificate", "never authorship" — must not match these.
FORBIDDEN_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (
        r"\bthe proof is a guarantee\b",
        "a proof is a record that checks ran",
    ),
    (
        r"\bguarantees? (?:that )?the (?:plan|system|target|run) (?:is|are) safe\b",
        "a proof covers the checks mayhem knows how to perform",
    ),
    (
        r"\bPASS means? the (?:plan|run|system|target) (?:is|are) safe\b",
        "PASS is a claim about the lines, for one plan digest",
    ),
    (
        r"\bVOID means? the (?:plan|run) failed\b",
        "VOID means the evidence no longer applies; FAIL means a check said no",
    ),
    (
        r"\bproves? authorship\b",
        "signatures are not verified in this build, so a seal proves integrity only",
    ),
)

#: Prose counts the guides assert, keyed by the phrase that carries them. Each is
#: checked against the length of the enum it describes, so the number a reader
#: relies on cannot drift away from the code.
COUNT_PHRASES: Final[dict[str, tuple[re.Pattern[str], int]]] = {
    "verdicts": (re.compile(r"\bThree\s+verdicts\b"), len(tuple(ProofVerdict))),
    "predicates": (re.compile(r"\bSix\s+predicates\b"), len(tuple(ResiduePredicate))),
    "obligations": (
        re.compile(r"\bnine\s+required\s+obligation\s+names\b"),
        len(tuple(ObligationName)),
    ),
}

# Sentences the guides depend on, so an edit cannot quietly drop the reasoning.
REQUIRED_DENIALS: Final[tuple[str, ...]] = (
    "a **record that checks ran**",
    "not a certificate",
    "`PASS` means every",
    "A proof proves the plan satisfied every check Mayhem knows how to perform",
    "demonstrates **integrity**",
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
        # ``PARTIAL`` is a state word like DONE and not started, so it needs its
        # own alternative: a phase where some clauses landed and others did not
        # is recorded that way, and a line the parser cannot read is a line
        # nothing can be checked against. (Plan 29's gate learned the same word
        # for the same reason.)
        match = re.match(
            r"^- (Phase \d)(.*?):\s*(DONE|PARTIAL|INCOMPLETE|not started|partially)", stripped
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
    """Ledger phases whose line is not ``DONE``."""
    return [phase for phase, line in sorted(ledger_lines(document).items()) if ": DONE" not in line]


def missing_sections(document: str) -> list[str]:
    return [heading for heading in REQUIRED_SECTIONS if heading not in document]


def forbidden_claims_found(document: str) -> list[str]:
    found: list[str] = []
    for pattern, reason in FORBIDDEN_CLAIMS:
        if re.search(pattern, document, re.IGNORECASE):
            found.append(reason)
    return found


def unmentioned(document: str, values: Iterable[str]) -> list[str]:
    """``values`` the document never names.

    The guides assert their lists are complete, so a vocabulary the code gains
    and the document does not is a silent gap in a document claiming to have
    none.
    """
    return [value for value in values if value not in document]


def mismatched_counts(document: str) -> list[str]:
    """Prose counts that disagree with the enum they describe."""
    wrong: list[str] = []
    for role, (pattern, actual) in COUNT_PHRASES.items():
        claimed = re.search(pattern, document)
        if claimed is None:
            wrong.append(f"{role}: the document does not state the count")
        else:
            numbers = {"Three": 3, "Six": 6, "nine": 9}
            spoken = numbers.get(claimed.group(0).split()[0], -1)
            if spoken != actual:
                wrong.append(f"{role}: document says {spoken}, code has {actual}")
    return wrong


def signature_claims_implemented(document: str) -> list[str]:
    """Every place the document says signature verification is implemented.

    All occurrences are inspected rather than the first one: a document that
    denies it in the guide and claims it in the ledger has still made the claim,
    and a checker that only read the first mention would pass it.
    """
    claims: list[str] = []
    for window in re.finditer(
        r"SIGNATURE_VERIFICATION_IMPLEMENTED[^.]{0,120}?\bis\b[^.]{0,20}?`?(\w+)`?",
        document,
    ):
        if window.group(1).lower() == "true":
            claims.append(window.group(0))
    return claims


def missing_denials(document: str) -> list[str]:
    return [denial for denial in REQUIRED_DENIALS if denial not in document]


# ── the ledger ───────────────────────────────────────────────────────────────


def test_the_ledger_carries_one_line_per_phase() -> None:
    assert sorted(ledger_lines(PLAN)) == [f"Phase {n}" for n in range(1, 7)]


def test_the_overall_count_equals_the_number_of_done_lines() -> None:
    overall = claimed_overall(PLAN)

    assert overall is not None, "the STATUS block must carry an Overall: line"
    done, total = overall
    assert (done, total) == (done_phase_count(PLAN), len(ledger_lines(PLAN)))


def test_no_phase_is_open_and_the_summary_says_so() -> None:
    """All six phases are DONE, and the summary says exactly that.

    This replaces ``test_exactly_one_phase_is_open_and_it_is_the_named_one``
    (and the ``unnamed_open_phase`` check beside it) rather than editing them:
    those pinned Phase 3 as the open one, and their continued presence would
    imply the plan is still 5 of 6. The promotion to DONE is recorded in the
    Phase 3 STATUS entry, which names the two projections that landed and the
    tests that assert each.
    """
    assert open_phases(PLAN) == []
    assert claimed_overall(PLAN) == (6, 6)


# ── the Phase 6 deliverables ─────────────────────────────────────────────────


def test_the_guides_and_the_rollout_order_are_in_the_document() -> None:
    assert missing_sections(PLAN) == []


def test_the_guides_name_every_verdict_obligation_and_predicate() -> None:
    assert unmentioned(PLAN, (member.value for member in ProofVerdict)) == []
    assert unmentioned(PLAN, (member.value for member in ObligationName)) == []
    assert unmentioned(PLAN, (member.value for member in ResiduePredicate)) == []


def test_the_counts_the_guides_assert_match_the_code() -> None:
    assert mismatched_counts(PLAN) == []


def test_the_guides_keep_their_own_denials() -> None:
    """The reasoning, so an edit cannot quietly reduce a guide to a slogan."""
    assert missing_denials(PLAN) == []


def test_the_document_does_not_claim_signatures_are_verified() -> None:
    assert signature_claims_implemented(PLAN) == []
    assert SIGNATURE_VERIFICATION_IMPLEMENTED is False


# ── the claims the document must not make ─────────────────────────────────────


def test_the_document_makes_no_literal_false_claim() -> None:
    assert forbidden_claims_found(PLAN) == []


def test_the_document_does_not_present_the_proof_as_a_guarantee() -> None:
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
        "the Overall count inflated past complete",
        lambda d: d.replace("Overall: 6 of 6", "Overall: 7 of 6", 1),
        claimed_overall,
    ),
    (
        "the reading guide removed",
        lambda d: d.replace("## Proof-reading guide", "## Removed", 1),
        lambda d: len(missing_sections(d)),
    ),
    (
        "a predicate dropped from the catalogue",
        lambda d: d.replace("`no_leases_held`", "`removed_predicate`", 1),
        lambda d: len(unmentioned(d, (member.value for member in ResiduePredicate))),
    ),
    (
        "the residue catalogue claiming seven predicates",
        lambda d: d.replace("Six predicates", "Seven predicates", 1),
        lambda d: len(mismatched_counts(d)),
    ),
    (
        "the document claiming signatures are verified",
        lambda d: d.replace(
            "SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`",
            "SIGNATURE_VERIFICATION_IMPLEMENTED` is `True`",
            1,
        ),
        lambda d: len(signature_claims_implemented(d)),
    ),
    (
        "a done phase silently demoted to partial",
        lambda d: d.replace(": DONE", ": PARTIAL", 1),
        open_phases,
    ),
    (
        "the document calling the proof a guarantee",
        lambda d: d + "\nThe proof is a guarantee that the target is safe.\n",
        lambda d: len(forbidden_claims_found(d)),
    ),
    (
        "a guide's own denial deleted",
        lambda d: d.replace("a **record that checks ran**", "a warranty", 1),
        lambda d: len(missing_denials(d)),
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
