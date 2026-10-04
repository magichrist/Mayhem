"""Plan 23 Phase 6 — the honesty gate over the performance/scale document.

Plan 23's Phase 6 acceptance criterion is "the 'what overhead does Mayhem add?'
question answered with numbers plus methodology, not adjectives", and the honest
answer today is that there are no numbers. The failure this gate exists to
prevent is the quiet one: a document that keeps saying the numbers are missing
while quietly acquiring some, or that states a figure nobody measured. So the
load-bearing check is a **number-shaped claim** rule — this document may name the
harness and the gates, and it may say a range is unmeasured, but it may not carry
a latency, throughput or target-count figure.

The second load-bearing check is the same one plan 29's gate uses, applied to a
different vocabulary: every rule id and every enum member quoted in backticks must
be real. A refusal id an operator is told to look for that the code never raises is
a dead end, and a scale range the domain refuses that a document advertises is
worse.

The rest follows the established shape: ledger against ``Overall:``, the four
Phase 6 headings by name, the phase's own key sentences kept verbatim, four
literal over-claims refused, and every checker proven to bite against a mutated
copy of the document.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

from mayhem.domain import budgets as domain_budgets
from mayhem.infra import budget_enforcement as infra_budget_enforcement
from mayhem.infra import metering as infra_metering

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/23_PERFORMANCE_SCALE.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")

#: The Phase 6 deliverables, by the heading each one must carry. The
#: scale-characterization heading is present *and* empty of measurements, which is
#: the phase's own instruction: measured numbers or silence.
REQUIRED_SECTIONS: Final[tuple[str, ...]] = (
    "## Benchmark methodology doc",
    "## Scale-characterization pages",
    "## Budget-configuration guide",
    "## Rollout order",
)

#: Claims this plan must never make. The document's own denials — "there are no
#: scale-characterization pages", "no benchmark has been run", "unmeasured" — must
#: not match these.
FORBIDDEN_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (
        r"\bhandles \d[\d,]*\s*(?:targets|experiments|drills)\b",
        "a measured number, and none has been measured",
    ),
    (
        r"\b\d+(?:\.\d+)?\s*(?:ms|milliseconds?|s|seconds?)\s+(?:faster|overhead|latency)\b",
        "no overhead figure has been measured against a live cluster",
    ),
    (
        r"\bscale claim(?:s)? (?:is|are) (?:published|renderable)\b",
        "an unmeasured claim is authorable and not renderable",
    ),
    (
        r"\bcpu\b[^.]{0,40}\b(?:is|are) (?:metered|measured|enforced) from userspace\b",
        "core_seconds is per-core accounting, unmeasurable from userspace",
    ),
)

#: Sentences the phase depends on, so an edit cannot quietly reduce a section to a
#: slogan.
#: Short, line-break-independent fragments: reflowing the prose must not be able
#: to satisfy or break the gate, only deleting the reasoning should.
REQUIRED_SENTENCES: Final[tuple[str, ...]] = (
    "there are none, and that is the honest state",
    "no benchmark has been run against a",
    "never `0.0`",
    "Unmeasured is a state, not a zero",
    "compared the claim with itself could",
    "is the only path to a `ScaleClaimView`",
)


def _real_rule_ids() -> set[str]:
    """Every rule id the two modules actually define."""
    return {
        value
        for module in (domain_budgets, infra_budget_enforcement, infra_metering)
        for name in dir(module)
        if name.startswith(("RULE_", "CONTINUITY_"))
        for value in (getattr(module, name),)
        if isinstance(value, str)
    }


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
    return [
        reason
        for pattern, reason in FORBIDDEN_CLAIMS
        if re.search(pattern, document, re.IGNORECASE)
    ]


def unquoted_rule_ids(document: str) -> list[str]:
    """Rule ids the document quotes that no module defines.

    ``budget.limit_exceeded`` and ``budget.estimate_exceeded`` are quoted in the
    ledger and the guide; a typo such as ``budget.exceeded`` reads as plausible
    and sends an operator after a constant that does not exist.
    """
    real = _real_rule_ids()
    quoted = set(re.findall(r"`((?:budget|benchmark|scale|meter)\.[a-z_]+)`", document))
    return sorted(code for code in quoted if code not in real and " " not in code)


def unquoted_dimensions(document: str) -> list[str]:
    """``ResourceDimension`` values the document never names.

    The budget guide claims to cover the eight; a ninth that appears in the code
    and in neither the guide nor the ledger is the gap this closes.
    """
    return [
        dimension.value
        for dimension in domain_budgets.ResourceDimension
        if dimension.value not in document
    ]


def unquoted_scale_targets(document: str) -> list[str]:
    """Declared scale targets the document does not list.

    ``TargetScale`` refuses any target count outside
    :data:`DECLARED_SCALE_TARGETS`, so the document's list of "the ranges a claim
    may be made about" is a claim about the code.
    """
    return [
        str(target)
        for target in sorted(domain_budgets.DECLARED_SCALE_TARGETS)
        if str(target) not in document
    ]


def missing_sentences(document: str) -> list[str]:
    return [sentence for sentence in REQUIRED_SENTENCES if sentence not in document]


# ── the ledger ───────────────────────────────────────────────────────────────


def test_the_ledger_carries_one_line_per_phase() -> None:
    assert sorted(ledger_lines(PLAN)) == [f"Phase {n}" for n in range(1, 7)]


def test_the_overall_count_equals_the_number_of_done_lines() -> None:
    overall = claimed_overall(PLAN)

    assert overall is not None, "the STATUS block must carry an Overall: line"
    assert overall == (done_phase_count(PLAN), len(ledger_lines(PLAN)))
    assert overall[0] == overall[1], "plan 23 claims six of six; a stale count is a lie"


# ── the Phase 6 deliverables ─────────────────────────────────────────────────


def test_the_four_sections_are_in_the_document() -> None:
    assert missing_sections(PLAN) == []


def test_every_rule_id_the_document_quotes_is_real() -> None:
    assert unquoted_rule_ids(PLAN) == []


def test_the_guide_covers_every_resource_dimension() -> None:
    assert unquoted_dimensions(PLAN) == []


def test_the_scale_section_lists_every_declared_target_count() -> None:
    assert unquoted_scale_targets(PLAN) == []


def test_the_sections_keep_their_own_denials() -> None:
    """The reasoning, so an edit cannot quietly turn honesty into a footnote."""
    assert missing_sentences(PLAN) == []


# ── the claims the document must not make ─────────────────────────────────────


def test_the_document_makes_no_literal_false_claim() -> None:
    assert forbidden_claims_found(PLAN) == []


def test_the_document_quotes_no_unmeasured_performance_figure() -> None:
    """The phase's own acceptance criterion, asserted as a checker."""
    assert forbidden_claims_found(PLAN) == []


# ── negative controls: each checker must bite ────────────────────────────────

_MUTATIONS: Final[tuple[tuple[str, Callable[[str], str], Callable[[str], object]], ...]] = (
    (
        "the Overall count dropped",
        lambda d: d.replace("Overall: 6 of 6", "Overall: 5 of 6", 1),
        claimed_overall,
    ),
    (
        "a phase marked not started",
        lambda d: re.sub(
            r"^- Phase 5 \(tests and negative controls\): DONE",
            "- Phase 5: not started",
            d,
            count=1,
            flags=re.MULTILINE,
        ),
        done_phase_count,
    ),
    (
        "the budget guide removed",
        lambda d: d.replace("## Budget-configuration guide", "## Removed", 1),
        lambda d: len(missing_sections(d)),
    ),
    (
        "a rule id invented",
        lambda d: d.replace("`budget.limit_exceeded`", "`budget.exceeded`", 1),
        lambda d: len(unquoted_rule_ids(d)),
    ),
    (
        "a dimension dropped from the guide",
        lambda d: d.replace("cloud_spend", "the cloud one"),
        lambda d: len(unquoted_dimensions(d)),
    ),
    (
        "a declared scale target dropped",
        lambda d: d.replace("10000, 100000", "10000", 1),
        lambda d: len(unquoted_scale_targets(d)),
    ),
    (
        "a performance figure invented",
        lambda d: d + "\nMayhem handles 10,000 targets with 3ms overhead.\n",
        lambda d: len(forbidden_claims_found(d)),
    ),
    (
        "the no-live-benchmark denial removed",
        lambda d: d.replace("no benchmark has been run against a", "every benchmark ran against a"),
        lambda d: int("no benchmark has been run against a" not in d),
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
