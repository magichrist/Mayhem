"""L1 Phase 2 — the honesty gate over every plan-document STATUS block.

One test file for the whole directory, because the defect is directory-wide: four
documents kept a ``planning only, 0%`` status after the commit that claimed to
have removed them all, and nothing referenced those four files, so nothing
caught it. Commit ``d4201c9`` is titled *"Correct the stale 'planning only, 0%'
status blocks"*; ``git show --name-only`` on it lists four files, and four more
still carried the string.

Four checks:

* **no plan's header or STATUS block claims a bare completion percentage.**
  Scoped to the header (the first lines, before the first heading) and to the
  ``## STATUS`` section rather than to the whole document, because the whole
  document legitimately contains the phrase in two places: ``27`` and
  ``README.md`` both *report* that the stale header was corrected. A checker
  that flagged those would be flagging the correction as the defect, and a
  checker that had been "fixed" to stop flagging them would be the kind of
  checker that stops checking anything. The scope is stated here rather than
  tuned until it passes.
* **every feature plan's ``Overall:`` count equals its number of ``DONE``
  phase lines**, so a plan cannot quietly demote a finished phase while keeping
  its count, and cannot inflate the count without the lines to back it.
* **a plan that names a phase PARTIAL says why** — the line must name the live
  acceptance that has not run, not only the word.
* **a plan with a phase ledger has a STATUS block at all.**

Each checker is proven to bite against a mutated copy of the directory, so a
checker that silently stopped checking fails here too.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Non-recursive on purpose. ``LAST/`` is a package of *open* plans whose STATUS
#: blocks are honest about being unimplemented, and a directory-wide gate that
#: failed on them would be a gate that could not be run mid-plan.
PLAN_DIR: Final = REPO_ROOT / "docs/v1.1.0"

#: Plans that carry a six-phase ledger and therefore must carry ``Overall:``.
FEATURE_PLANS: Final[tuple[str, ...]] = (
    "01_RUNTIME_CERTIFICATION.md",
    "02_KUBERNETES_RUNTIME.md",
    "03_EXECUTION_FABRIC.md",
    "04_EBPF_KERNEL_IO_JVM.md",
    "05_APP_AND_DEPENDENCY_FAULTS.md",
    "06_CLOUD_PROVIDERS.md",
    "07_POLICY_SAFETY_ENGINE.md",
    "08_CONTROL_PLANE_API_UI.md",
    "09_IDENTITY_RBAC_APPROVALS.md",
    "10_EMERGENCY_STOP_PREFLIGHT.md",
    "11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md",
    "12_CRYPTOGRAPHIC_EVIDENCE.md",
    "13_SCHEDULING_CAMPAIGNS_GAMEDAYS.md",
    "14_TOPOLOGY_BLAST_RADIUS.md",
    "15_RESILIENCE_ANALYTICS_ADAPTIVE.md",
    "16_CI_GITOPS_INTEGRATIONS.md",
    "17_EXTENSION_SDK_PROVIDER_PROTOCOL.md",
    "18_MARKETPLACE_CATALOG.md",
    "19_HA_DR_SECURITY.md",
    "20_ENTERPRISE_PRODUCT_HARDENING.md",
    "21_RELIABILITY_ADVISOR.md",
    "22_RESILIENCE_COVERAGE_REGRESSION.md",
    "23_PERFORMANCE_SCALE.md",
    "29_SECRETS_MANAGEMENT.md",
    "30_SAFETY_PROOF.md",
)

#: The stale claim. Matched in the header and the STATUS block only.
STALE_CLAIM: Final = re.compile(r"planning only", re.I)

#: A bare completion percentage: "0%", "planning only, 0%", "Overall: 0%".
BARE_PERCENT: Final = re.compile(r"(?:planning only[^\n]*)?\b\d+\s*%")

STATUS_HEADER: Final = re.compile(r"^## STATUS\b[^\n]*$", re.M)

#: A phase ledger line: ``- Phase 4 (safety and evidence integration): DONE — …``.
#:
#: Three things this deliberately does *not* do, each found by running it
#: against the real documents rather than against a fixture:
#:
#: * it anchors the verdict to the label (``):\s*DONE``) rather than searching
#:   the whole line. Plan 20's Phase 4 line reads ``PARTIAL`` and then mentions
#:   "DONE" several hundred characters later in its prose; a loose ``.*DONE``
#:   counts that PARTIAL phase as done, which is exactly the flattering
#:   miscount this gate exists to prevent;
#: * the label is matched **lazily** (``[^\n]*?``) up to the colon that is
#:   actually followed by a verdict. Plan 3's label is ``Phase 3 (surface: agent
#:   enrollment and provider registration)`` — it contains its own colon, so a
#:   match that stops at the first colon silently drops the phase out of the
#:   count and reports a false alarm;
#: * it captures the phase *number*, so plan 12's extra "Phase 4 correction …
#:   DONE" line — a correction inside a phase, the pattern plans 20 and 29 both
#:   use — does not inflate the count to seven.
#:
#: Group 3 is the remainder of the line, so the "PARTIAL must say why" check
#: reads the whole sentence rather than the eight characters of the verdict.
PHASE_LINE: Final = re.compile(
    r"^-\s+Phase\s+(\d+)\b[^\n]*?:\s*\**\s*(DONE|PARTIAL|INCOMPLETE)\b([^\n]*)$", re.M
)
OVERALL_LINE: Final = re.compile(r"^Overall:\s*(\d+)\s+of\s+(\d+)\s+phases", re.M)

#: What "PARTIAL because a live acceptance has not run" has to look like.
LIVE_ACCEPTANCE: Final = re.compile(
    r"live|cluster|IdP|approver|runtime|no cell|has not run|not met|no DaemonSet",
    re.I,
)


def _plans() -> Iterator[Path]:
    yield from sorted(PLAN_DIR.glob("*.md"))


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _status_block(text: str) -> str:
    """The ``## STATUS`` section: to the next level-2 heading, or to EOF."""
    match = STATUS_HEADER.search(text)
    if match is None:
        return ""
    rest = text[match.start() :]
    nxt = re.search(r"^## (?!STATUS)", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def _header(text: str) -> str:
    """Everything before the first level-1 or level-2 heading."""
    first = re.search(r"^##\s", text, re.M)
    return text[: first.start()] if first else text


def _phases(text: str) -> dict[int, str]:
    """``{phase number: verdict}`` from the ledger, last verdict winning.

    Plan 12 carries both ``- Phase 4 …: DONE`` and ``- Phase 4 correction …:
    DONE``, so the same number appears twice; both say the same thing, and a
    disagreement between them would be a real defect that
    :func:`test_overall_count_equals_the_done_lines` reports by the arithmetic
    rather than by guessing which one to believe.
    """
    return {int(match.group(1)): match.group(2) for match in PHASE_LINE.finditer(text)}


def _status_lead(line: str) -> str:
    """The state a ``Status:`` header asserts, up to its first sentence.

    ``Status: **planning only.** Meta document: …`` asserts "planning only".
    ``Status: **implemented and closing out.** The "planning only" line this
    file used to carry was stale…`` asserts the opposite, and merely *mentions*
    the phrase while reporting the correction. Reading the whole header would
    flag that correction as the defect it corrects.
    """
    return line.split(".", 1)[0]


# --- check 1: no stale claim in a header or a STATUS block ----------------- #


def test_no_plan_header_or_status_block_claims_planning_only() -> None:
    """The exact defect commit d4201c9 claimed to have fixed everywhere.

    Scoped to the STATUS **header line** and to the leading state of a ``Status:``
    header. ``27_IMPLEMENTATION_BACKLOG.md`` mentions the phrase *inside* its
    STATUS block, in the sentence reporting that the stale header was corrected —
    flagging that would flag the correction as the defect it corrects.
    """
    offenders: list[str] = []
    for path in _plans():
        text = _read(path)
        block = _status_block(text)
        status_line = block.splitlines()[0] if block else ""
        if STALE_CLAIM.search(status_line):
            offenders.append(f"{path.name} [STATUS] {status_line.strip()!r}")
        for line in _header(text).splitlines():
            if not line.startswith("Status:"):
                continue
            lead = _status_lead(line)
            if STALE_CLAIM.search(lead):
                offenders.append(f"{path.name} [header] {lead.strip()!r}")
    assert offenders == [], "stale 'planning only' claims remain:\n  " + "\n  ".join(offenders)


def test_no_status_block_is_just_a_percentage() -> None:
    """A STATUS block must say something, not merely score itself."""
    offenders: list[str] = []
    for path in _plans():
        block = _status_block(_read(path))
        if not block:
            continue
        header_line = block.splitlines()[0]
        if BARE_PERCENT.search(header_line) and len(header_line.strip()) < 40:
            offenders.append(f"{path.name}: {header_line!r}")
    assert offenders == [], "STATUS block is a bare percentage:\n  " + "\n  ".join(offenders)


def test_a_loading_header_states_a_state() -> None:
    """Every plan that opens with ``Status:`` must state a real state, not a plan."""
    offenders: list[str] = []
    for path in _plans():
        for line in _header(_read(path)).splitlines():
            if line.startswith("Status:") and STALE_CLAIM.search(_status_lead(line)):
                offenders.append(f"{path.name}: {line.strip()!r}")
    assert offenders == [], "stale Status header:\n  " + "\n  ".join(offenders)


# --- check 2: the ledger arithmetic ---------------------------------------- #


def test_overall_count_equals_the_done_lines() -> None:
    """``Overall: N of M`` must equal the number of phases marked DONE."""
    offenders: list[str] = []
    for name in FEATURE_PLANS:
        text = _read(PLAN_DIR / name)
        overall = OVERALL_LINE.search(text)
        if overall is None:
            offenders.append(f"{name}: has a phase ledger but no 'Overall:' line")
            continue
        phases = _phases(text)
        done = sum(1 for verdict in phases.values() if verdict == "DONE")
        if int(overall.group(1)) != done:
            offenders.append(
                f"{name}: says {overall.group(1)} of {overall.group(2)} complete, "
                f"but marks {done} of {len(phases)} ledger phases DONE"
            )
    assert offenders == [], "ledger arithmetic:\n  " + "\n  ".join(offenders)


def test_a_plan_with_phase_lines_has_a_status_block() -> None:
    for path in _plans():
        text = _read(path)
        if PHASE_LINE.search(text):
            assert _status_block(text), f"{path.name} has phase lines but no ## STATUS block"


# --- check 3: PARTIAL must say why ----------------------------------------- #


def test_a_partial_phase_names_the_open_acceptance() -> None:
    """``PARTIAL`` alone is not a status; it must name what has not run."""
    offenders: list[str] = []
    for path in _plans():
        text = _read(path)
        for match in PHASE_LINE.finditer(text):
            if match.group(2) != "PARTIAL":
                continue
            line = match.group(0)
            if not LIVE_ACCEPTANCE.search(line):
                offenders.append(f"{path.name}: {line.strip()[:160]!r}")
    assert offenders == [], "PARTIAL without a named acceptance:\n  " + "\n  ".join(offenders)


# --- the checkers bite ------------------------------------------------------ #


def test_the_stale_claim_checker_bites_on_a_mutated_plan() -> None:
    """Restore the defect into a scratch copy and prove each checker catches it."""
    good = _read(PLAN_DIR / "30_SAFETY_PROOF.md")
    assert STATUS_HEADER.search(good) is not None, "the fixture plan lost its STATUS block"

    stale_block = good.replace(
        STATUS_HEADER.search(good).group(0),  # type: ignore[union-attr]
        "## STATUS — planning only, 0%",
        1,
    )
    assert STALE_CLAIM.search(_status_block(stale_block).splitlines()[0]), (
        "stale-claim checker did not bite"
    )

    stale_header = good.replace("# ", "Status: **planning only.**\n\n# ", 1)
    assert STALE_CLAIM.search(_header(stale_header)), "header checker did not bite"


def test_the_ledger_checker_bites_on_an_inflated_count() -> None:
    good = _read(PLAN_DIR / "30_SAFETY_PROOF.md")
    inflated = good.replace(
        OVERALL_LINE.search(good).group(0),  # type: ignore[union-attr]
        "Overall: 5 of 6 phases complete",
        1,
    )
    match = OVERALL_LINE.search(inflated)
    assert match is not None
    phases = _phases(inflated)
    done = sum(1 for verdict in phases.values() if verdict == "DONE")
    assert int(match.group(1)) != done, "ledger checker did not bite"


def test_a_phase_correction_does_not_inflate_the_count() -> None:
    """Plan 12's "Phase 4 correction … DONE" is not a seventh phase.

    Pinned against the real document, because the loose version of this rule
    reported plan 12 as claiming 6 of 6 while carrying 7 DONE lines — a false
    alarm that would have been silenced by deleting a true statement from a
    plan document, which is the worst possible way to make a gate pass.
    """
    text = _read(PLAN_DIR / "12_CRYPTOGRAPHIC_EVIDENCE.md")
    phases = _phases(text)
    assert max(phases) == 6, "the six-phase ledger is not six phases"
    assert len(phases) == 6, "a correction line invented a phase"
    assert sum(1 for v in phases.values() if v == "DONE") == 6


def test_a_partial_line_that_mentions_done_is_still_partial() -> None:
    """Plan 20's Phase 4 reads PARTIAL and then says "DONE" in its prose.

    A loose ``.*DONE`` search counts that phase as complete, which is the
    flattering miscount this gate exists to prevent.
    """
    line = (
        "- Phase 4 (safety and evidence integration): PARTIAL — and much is DONE, "
        "but not the live part."
    )
    match = PHASE_LINE.search(line)
    assert match is not None
    assert match.group(2) == "PARTIAL"
    assert re.search(r".*DONE", line) is not None, "the fixture lost its misleading DONE"


def test_the_partial_checker_bites_on_an_unexplained_partial() -> None:
    partial = "- Phase 4: PARTIAL — the thing is not finished."
    match = PHASE_LINE.search(partial)
    assert match is not None and match.group(2) == "PARTIAL"
    assert LIVE_ACCEPTANCE.search(partial) is None, "partial checker did not bite"
    explained = partial + " It needs a live cluster cell."
    assert LIVE_ACCEPTANCE.search(explained) is not None


def test_the_header_scope_does_not_flag_the_correction() -> None:
    """``README.md`` mentions "planning only" while reporting it was corrected.

    Reading the whole header line would flag that sentence as the defect it
    corrects. The scope is the leading state, and this pins that it works.
    """
    corrected = (
        'Status: **implemented and closing out.** The "planning only" line this file used '
        "to carry was stale."
    )
    assert STALE_CLAIM.search(corrected) is not None, "the fixture lost its mention"
    assert STALE_CLAIM.search(_status_lead(corrected)) is None, "header scope is too wide"

    stale = "Status: **planning only.** Meta document: the thing."
    assert STALE_CLAIM.search(_status_lead(stale)) is not None
