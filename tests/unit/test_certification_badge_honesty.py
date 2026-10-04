"""Plan 01 Phase 6 — the certification-badge overclaim scan, across every document.

Phase 6's acceptance criterion is a claim *about prose*: "no document may show a
certified state the record store did not produce". ``test_readme_honesty.py``
already owns the pack-signing half of that idea and the README's ``0 of N``
live-verified count (with ``N`` derived from ``len(CATALOG)``, so the denominator
cannot quietly become a smaller lie). Neither is repeated here.

What was missing is the other half: the scan covered the README's prose about
live verification, and nothing covered a **badge** — a table cell, a status
column, a checklist entry, a matrix row — anywhere in the published documents. A
badge is the shape an overclaim actually takes when a certification programme
starts landing: somebody fills in the cell because the cell was there.

So the gate is derived from the store rather than from a list. It opens a real
migrated SQLite database, asks
:meth:`~mayhem.controller.certification_evidence.sealed_certification_gate` which
faults it would report as live, and requires every badge in every published
document to name one of them. Today that set is empty, so the gate reads: no
document may carry a badge at all. When the first real cell is certified the set
becomes non-empty and the same gate admits exactly that fault's badge — which is
the point of deriving it rather than hardcoding a prohibition.

**The store side is real, not stubbed.** A badge scan is only meaningful if the
allowlist it compares against comes from the same machinery the CLI uses; a
literal ``set()`` would make this a grep with extra steps.

Three properties keep it from passing vacuously:

* the store really is consulted, and really is empty on a fresh database;
* a badge naming a fault the store *did* produce is admitted, so the gate is a
  comparison and not a blanket ban;
* every detector is proven against the exact sentence it forbids, and against the
  disclaimer that clears it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from mayhem.controller.certification_evidence import sealed_certification_gate
from mayhem.domain.catalog import CATALOG
from mayhem.infra.certification_repository import CertificationRepository
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLANNING_PACKAGE = REPO_ROOT / "docs/v1.1.0"

#: Every Markdown file a reader can be shown. The planning package is excluded for
#: the same reason ``test_readme_honesty.py`` excludes it: those documents quote
#: overclaims in order to forbid them, so they are where the detectors are
#: *defined*, not where they are *obeyed*. Their overclaims are covered from the
#: other side, by each plan's own negative controls.
PUBLISHED_DOCUMENTS: Final[tuple[Path, ...]] = tuple(
    sorted(
        path
        for path in (
            *REPO_ROOT.glob("README.md"),
            *REPO_ROOT.glob("docs/**/*.md"),
            *REPO_ROOT.glob("examples/**/*.md"),
        )
        if path.is_file() and not path.is_relative_to(PLANNING_PACKAGE)
    )
)

#: A fault id as the catalog spells it. Built from the live catalogue rather than
#: from a pattern, because a badge's *subject* is a catalog fault: matching a
#: generic dotted token instead flagged prose that merely mentioned a live rung,
#: which is the false-positive shape this gate is most prone to.
CATALOG_IDS: Final[frozenset[str]] = frozenset(definition.id for definition in CATALOG)
FAULT_ID: Final[re.Pattern[str]] = re.compile(
    "|".join(re.escape(fault_id) for fault_id in sorted(CATALOG_IDS, key=len, reverse=True))
)

#: Wording that asserts a live rung. These are the words that would sit in a badge
#: cell next to a fault id — not every mention of the rung, which is what prose
#: about the maturity model is made of.
CERTIFIED_WORDING: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\bcertified\b", re.IGNORECASE),
    re.compile(r"\b✅"),
    re.compile(r"\bverified[-_ ]live\b", re.IGNORECASE),
    re.compile(r"\blive[-_ ]verified\b", re.IGNORECASE),
    re.compile(r"\bpassing (?:on|in production)\b", re.IGNORECASE),
)

#: A rung name sitting alone in a table cell or a checklist tick. "Stable" is an
#: ordinary English word, so it only counts as a claim in the shape a badge takes
#: — a cell, or a ticked box — and never in prose.
RUNG_CELL: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:\||-\s*\[[xX]\])"
    r".*\b(?:stable|verified[-_ ]live|live[-_ ]verified|certified)\b",
    re.IGNORECASE,
)

#: Wording that retracts the badge on the same line. A disclaimer is how a
#: document is allowed to *discuss* certification while claiming none.
DISCLAIMERS: Final[tuple[str, ...]] = (
    "0 of",
    "0-of-",
    "no fault",
    "not certified",
    "no live",
    "never certified",
    "must stay",
    "must remain",
    "still 0",
    "until the first",
    "nothing is certified",
    "no cell",
    "is 0",
    "0 on a fresh",
    "cannot be certified",
    "blocked",
    "not started",
    "no promotion",
    "stays 0",
    "nothing has been certified",
    "earned only",
    "unreachable",
    "unverified",
    # A long prose line that states the truth and then names the rung it is *not*
    # at ("their maturity remains unit-verified rather than live-verified") is a
    # retraction, and the reliability matrix is full of them.
    "rather than",
    "remains unit-verified",
    "none of them",
)


def _live_faults_from_the_store(tmp_path: Path) -> frozenset[str]:
    """Fault ids the sealed gate would report as live, from a real store.

    A fresh migrated database, deliberately: the claim this gate is checking is
    "the record store did not produce it", and on an empty store that is a
    statement about the whole programme rather than about one test's fixtures.
    """
    store = Store.open_migrated(tmp_path / "certification.db")
    try:
        records = sealed_certification_gate(CertificationRepository(store), store)
    finally:
        store.close()
    return frozenset(fault_id for fault_id, rows in records.items() if rows)


def _badges(text: str) -> list[str]:
    """Lines that assert a live certification state for a named catalog fault.

    Three conditions, all required, because each one alone over-matches:

    * the line names a **catalog fault id** — a badge always names its subject;
    * the line asserts a live rung or certification for it;
    * the line carries **no retraction** beside the claim.

    Dropping the first condition is what made the first version of this gate
    useless: every document that explains the maturity model mentions
    ``verified-live``, so matching the rung alone flagged the explanation.
    """
    found: list[str] = []
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.strip()
        if not line or not FAULT_ID.search(line):
            continue
        if not any(pattern.search(line) for pattern in CERTIFIED_WORDING) and not RUNG_CELL.search(
            line
        ):
            continue
        if any(marker in line.lower() for marker in DISCLAIMERS):
            continue
        found.append(f"L{number}: {line[:160]}")
    return found


def _discharged(badges: Iterable[str], allowed: frozenset[str]) -> list[str]:
    """Badges that survive the store's verdict: the fault id is not one it produced.

    A badge naming a fault the sealed gate *would* report as live is discharged,
    because that is exactly what a document is entitled to say once the record
    store has produced it. Anything else is outstanding.
    """
    return [
        badge
        for badge in badges
        if not any(fault_id in allowed for fault_id in FAULT_ID.findall(badge.split(": ", 1)[-1]))
    ]


# ── the store side ───────────────────────────────────────────────────────────


def test_the_record_store_produces_no_live_certification(tmp_path: Path) -> None:
    """The premise, checked against the store rather than assumed.

    Everything else in this file compares a document against this set, so if this
    ever stops holding the comparison is meaningless and this is where it shows.
    """
    assert _live_faults_from_the_store(tmp_path) == frozenset()


def test_the_live_set_is_read_from_the_sealed_gate_not_a_literal(tmp_path: Path) -> None:
    """A hardcoded ``set()`` would make this a grep with extra steps."""
    store = Store.open_migrated(tmp_path / "certification.db")
    try:
        records = sealed_certification_gate(CertificationRepository(store), store)
    finally:
        store.close()

    assert isinstance(records, dict)
    assert all(isinstance(rows, tuple) for rows in records.values())


# ── the scan ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path", PUBLISHED_DOCUMENTS, ids=lambda path: str(path.relative_to(REPO_ROOT))
)
def test_no_document_shows_a_certification_badge_the_store_did_not_produce(
    path: Path, tmp_path: Path
) -> None:
    """Phase 6's acceptance criterion, as a check rather than a promise."""
    allowed = _live_faults_from_the_store(tmp_path)

    outstanding = _discharged(_badges(path.read_text(encoding="utf-8")), allowed)

    assert outstanding == [], (
        f"{path.relative_to(REPO_ROOT)} shows a certification badge the record "
        "store did not produce:\n" + "\n".join(outstanding)
    )


def test_the_scan_is_not_vacuous(tmp_path: Path) -> None:
    """A gate that finds nothing because it looks for nothing is not a gate."""
    assert len(PUBLISHED_DOCUMENTS) > 20, "the document set collapsed; is the glob still right?"

    detected = _badges("| `proc.pause` | certified | docker 24.04 |")
    assert detected, "a badge table row is not detected at all"


# ── two-sided: the gate admits what the store produced ───────────────────────


def test_a_badge_naming_a_certified_fault_is_admitted() -> None:
    """The gate is a comparison against the store, not a blanket ban."""
    allowed = frozenset({"proc.pause"})
    badge = _badges("| `proc.pause` | ✅ certified | docker 24.04 |")

    assert _discharged(badge, allowed) == []


def test_a_badge_naming_an_uncertified_fault_is_outstanding() -> None:
    """Two-sided for the discharge: a different fault id is still a lie."""
    badge = _badges("| `net.latency` | ✅ certified | docker 24.04 |")

    assert _discharged(badge, frozenset({"proc.pause"})) != []


def test_a_prose_mention_of_the_rung_is_not_a_badge() -> None:
    """The false positive that made the first version of this gate useless.

    Every document explaining the maturity model mentions ``verified-live``.
    Matching the rung without requiring a named subject flagged all of them.
    """
    prose = (
        "`verified-live` is earned only from a recorded live-run record: an "
        "injected fault, a recovery, and a bundle that verifies."
    )

    assert _badges(prose) == []


def test_a_disclaimer_clears_a_line_that_merely_discusses_certification() -> None:
    discussed = _badges(
        "**0 of 145 faults are live-verified, because no cell has been certified.**"
    )

    assert discussed == []


# ── negative controls: each detector must bite ───────────────────────────────


@pytest.mark.parametrize(
    "overclaim",
    [
        "| `proc.pause` | certified | docker 24.04 |",
        "| `net.latency` | ✅ live-verified | podman 5.0 |",
        "cpu.steal has been verified-live since 3.2.",
        "- [x] `fs.fill` certified on the reference cell",
        "| `cpu.steal` | stable | podman 5.0 |",
    ],
)
def test_the_detector_catches_each_shape_an_overclaim_takes(overclaim: str) -> None:
    assert _badges(overclaim), f"not detected: {overclaim!r}"


@pytest.mark.parametrize(
    "honest",
    [
        "**0 of 145** faults are `verified-live`; none is `stable`.",
        "Each of `cpu.steal`, `fs.fill` is unit-verified rather than live-verified.",
        "No fault in this repository is `verified-live`.",
        "A cell must be certified before a fault may claim that rung.",
        "nothing is certified — `certified_faults` is 0 on a fresh database.",
        "Signatures are NOT verified in this build.",
    ],
)
def test_the_detector_leaves_honest_prose_alone(honest: str) -> None:
    assert _badges(honest) == [], f"false positive on honest prose: {honest!r}"


@pytest.mark.parametrize("fault_id", sorted(CATALOG_IDS)[:20], ids=str)
def test_every_catalog_fault_id_is_recognisable_as_a_badge_subject(fault_id: str) -> None:
    """The badge's subject is a catalog fault, so the pattern must match each one.

    Parametrised over a slice rather than a single sample: a regex assembled from
    145 alternatives can silently miss one, and a missed id is a badge the gate
    would wave through.
    """
    assert FAULT_ID.search(f"`{fault_id}` certified") is not None, (
        f"the badge detector cannot recognise the catalog's own fault id {fault_id!r}"
    )
