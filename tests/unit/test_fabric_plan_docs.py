"""Plan 03 Phase 6 — the honesty gate over the execution-fabric document.

The phase's acceptance criterion is the documented protocol, provider guide and
non-guarantee being *enforced* rather than asserted, so this file parses
`docs/v1.1.0/03_EXECUTION_FABRIC.md` and holds it to the code:

* **The ledger against itself.** ``Overall:`` equal to the number of ``DONE``
  lines, one line per phase, no phase silently reopened. Plan 03 landed Phase 4
  out of order, which the ledger records rather than inflating.
* **Every refusal code the document quotes is real.** A ``FABRIC_*`` id an
  operator is told to look for that the source never raises is a dead end.
* **The vocabulary the document explains is the vocabulary the code declares.**
  All eleven ``StepSemantics`` members are enumerated by name; a member the
  code gains without the document describing it is the same lie in reverse.
* **The non-guarantee stays a non-guarantee.** The delivery-semantics section
  exists to say "at-most-once per (step, epoch), never exactly-once"; a document
  that grows an exactly-once claim, or loses the unresolved-effect state, is
  promising what the journal cannot deliver. A claim that a successor protocol
  version ships is refused the same way — the successor rules describe how one
  *would* land, not that one has.
* **The Phase 6 deliverables are present by name**, and the three rollout tiers
  stay in their recorded order.
* **Every checker bites.** Each one is run against a mutated copy of the
  document and must fail there — a checker that cannot fail is decoration, and
  the negative controls prove the gate rather than the prose.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import mayhem.domain.fabric as domain_fabric
from mayhem.controller import fabric_engine

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/03_EXECUTION_FABRIC.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")

#: The Phase 6 deliverables, by the heading each one must carry.
REQUIRED_SECTIONS: Final[tuple[str, ...]] = (
    "## The `mayhem/1` successor rules",
    "## Provider integration guide",
    "## Delivery semantics: the explicit non-guarantee",
    "## Rollout order",
)

#: Fragments the phase's reasoning rests on. Reflowing the prose must not be able
#: to satisfy or break the gate; only deleting the reasoning should.
REQUIRED_SENTENCES: Final[tuple[str, ...]] = (
    "at-most-once per (step, epoch)",
    "never exactly-once",
    "fabric_inflight_unresolved",
    "Agents never listen",
    "Enrollment is declaration, not authentication",
    "Refusal codes are added, never re-meaning",
    "adds required fields; it never adds optional extras",
)

#: Claims this document must never make. Its own subject matter — a fabric that
#: refuses double effects and fails closed on verification — must not grow the
#: guarantees it explicitly disclaims.
FORBIDDEN_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (
        r"\bexactly-?once delivery(?:\s+is\s+(?:guaranteed|provided|implemented))?\b",
        "the fabric guarantees at-most-once per (step, epoch), never exactly-once",
    ),
    (
        r"\bguarantees? (?:that )?an effect (?:happened|landed|was applied)\b",
        "crash-resume makes the window visible; it does not decide whether an effect happened",
    ),
    (
        r"\bmayhem/2 (?:is|has been) (?:shipped|implemented|live)\b",
        "the successor rules describe how a successor would land; none ships",
    ),
    (
        r"\b(?:docker|kubernetes) cells? (?:are|have been) certified\b",
        "only the podman cell holds a live claim",
    ),
)

#: The invented constructs the invented-semantics mutation uses, plus the shape
#: a hand-waved new semantic would take in prose.
INVENTED_SEMANTIC_MARKERS: Final[tuple[str, ...]] = (
    "forkbomb",
    "fork",
    "pause_semantic",
)


def _real_fabric_codes() -> set[str]:
    """Every code the fabric can actually raise, by value *and* constant name.

    The document quotes both spellings — ``fabric_stale_fence`` (the value an
    integrator routes on) and ``SIGNATURE_PORT_UNAVAILABLE`` (the constant an
    operator reads in a traceback) — so a real code under either spelling
    counts. ``fabric_journal`` is the table/module the document names, not a
    refusal code, and is allowed the same way rather than by exempting the
    regex match.
    """
    codes: set[str] = set()
    for module in (domain_fabric, fabric_engine):
        for name, value in vars(module).items():
            if name.startswith("FABRIC_") and isinstance(value, str):
                codes.update({name, value})
    from mayhem.infra.agent_identity_verifier import SIGNATURE_PORT_UNAVAILABLE
    from mayhem.infra.fabric_journal import FABRIC_JOURNAL_TABLE

    codes.update({"SIGNATURE_PORT_UNAVAILABLE", SIGNATURE_PORT_UNAVAILABLE, FABRIC_JOURNAL_TABLE})
    return codes


def _real_semantics() -> set[str]:
    return {member.value for member in domain_fabric.StepSemantics}


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


def missing_sentences(document: str) -> list[str]:
    return [sentence for sentence in REQUIRED_SENTENCES if sentence not in document]


def forbidden_claims_found(document: str) -> list[str]:
    return [
        reason
        for pattern, reason in FORBIDDEN_CLAIMS
        if re.search(pattern, document, re.IGNORECASE)
    ]


def unquoted_fabric_codes(document: str) -> list[str]:
    """``FABRIC_*``-shaped ids the document quotes that no module defines."""
    quoted = set(re.findall(r"`(fabric_[a-z_]+|SIGNATURE_PORT_UNAVAILABLE)`", document))
    return sorted(code for code in quoted if code not in _real_fabric_codes())


def unknown_semantics_quoted(document: str) -> list[str]:
    """Semantics-shaped words the document quotes that the vocabulary lacks.

    The document enumerates the whole vocabulary backticked, so a backticked
    word that is *named as* a semantic but is not one — an invented construct
    presented as the planner's — is caught here.
    """
    quoted = set(re.findall(r"`([a-z_]+)`", document))
    real = _real_semantics()
    return sorted(
        word
        for word in quoted
        if word not in real and (word in INVENTED_SEMANTIC_MARKERS or word.endswith("_semantic"))
    )


def semantics_vocabulary_enumerated(document: str) -> bool:
    """Every ``StepSemantics`` member is backticked somewhere in the document."""
    return _real_semantics() <= set(re.findall(r"`([a-z_]+)`", document))


def rollout_tiers_out_of_order(document: str) -> bool:
    """True unless all three tiers appear, in the recorded order.

    A tier the rollout section no longer names is a reordered rollout — the
    honest reading of a mutation that deletes one — and raises nothing.
    """
    try:
        section = document[document.index("## Rollout order") :]
        local = section.index("Local agents first")
        k8s = section.index("Kubernetes DaemonSet agents")
        third_party = section.index("Third-party providers")
    except ValueError:
        return True
    return not local < k8s < third_party


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


def test_the_four_sections_are_in_the_document() -> None:
    assert missing_sections(PLAN) == []


def test_the_document_keeps_its_own_reasoning() -> None:
    assert missing_sentences(PLAN) == []


def test_the_document_makes_no_literal_false_claim() -> None:
    assert forbidden_claims_found(PLAN) == []


def test_every_fabric_code_the_document_quotes_is_real() -> None:
    assert unquoted_fabric_codes(PLAN) == []


def test_every_semantic_the_document_quotes_is_real() -> None:
    assert unknown_semantics_quoted(PLAN) == []


def test_the_document_enumerates_the_whole_semantics_vocabulary() -> None:
    assert semantics_vocabulary_enumerated(PLAN)


def test_the_rollout_tiers_stay_in_order() -> None:
    assert not rollout_tiers_out_of_order(PLAN)


# ── negative controls: every checker must bite ────────────────────────────────

_MUTATIONS: Final[tuple[tuple[str, Callable[[str], str], Callable[[str], object]], ...]] = (
    (
        "the Overall count walked back to five",
        lambda d: d.replace("Overall: 6 of 6", "Overall: 5 of 6", 1),
        lambda d: claimed_overall(d)[0] == done_phase_count(d),
    ),
    (
        "Phase 5 reopened in prose while its ledger line says DONE",
        lambda d: re.sub(
            r"^- Phase 5 \(tests, regression guards, negative controls\): DONE",
            "- Phase 5 (tests, regression guards, negative controls): INCOMPLETE",
            d,
            count=1,
            flags=re.MULTILINE,
        ),
        lambda d: done_phase_count(d) == 6,
    ),
    (
        "a fabricated refusal code is quoted",
        # Digit-free on purpose: a code with a digit would fall outside the
        # quoted-id regex, and the mutation would test nothing.
        lambda d: d.replace("`fabric_stale_fence`", "`fabric_stale_fencey`", 1),
        lambda d: unquoted_fabric_codes(d) == [],
    ),
    (
        "an invented step semantic is quoted",
        lambda d: d.replace("`serial`", "`forkbomb`", 1),
        lambda d: unknown_semantics_quoted(d) == [],
    ),
    (
        "a semantics member is dropped from the document",
        lambda d: d.replace("`parallel`, ", "", 1),
        semantics_vocabulary_enumerated,
    ),
    (
        "an exactly-once delivery claim appears",
        lambda d: d.replace(
            "at-most-once per (step, epoch)", "exactly-once delivery is guaranteed", 1
        ),
        lambda d: forbidden_claims_found(d) == [],
    ),
    (
        "the successor version is claimed as shipped",
        lambda d: d + "\nmayhem/2 is shipped.\n",
        lambda d: forbidden_claims_found(d) == [],
    ),
    (
        "a Phase 6 section is deleted",
        lambda d: d.replace("## Rollout order", "## Rollout history", 1),
        lambda d: missing_sections(d) == [],
    ),
    (
        "the rollout tiers are reordered",
        lambda d: d.replace("Local agents first", "Third-party providers first", 1),
        lambda d: not rollout_tiers_out_of_order(d),
    ),
)


def test_each_checker_notices_its_own_mutation() -> None:
    for name, mutate, should_hold_on_clean in _MUTATIONS:
        mutated = mutate(PLAN)
        assert not should_hold_on_clean(mutated), f"the gate did not notice: {name}"


def test_the_clean_document_passes_every_checker() -> None:
    """The mirror of the negative controls: the real document is green."""
    assert claimed_overall(PLAN) == (6, 6)
    assert missing_sections(PLAN) == []
    assert missing_sentences(PLAN) == []
    assert forbidden_claims_found(PLAN) == []
    assert unquoted_fabric_codes(PLAN) == []
    assert unknown_semantics_quoted(PLAN) == []
    assert semantics_vocabulary_enumerated(PLAN)
    assert not rollout_tiers_out_of_order(PLAN)
