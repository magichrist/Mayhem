"""The release gate that checks the release notes are honest (plan 07 §Honesty).

Why this file exists
--------------------
Five honesty gates in ``docs/v1.0.0/07-release-gates.md`` were open at 1.0.0.
Four of them are claims *about* the documentation, so a code test is the only
thing that can keep them closed: a README that hides a defect is not a
documentation bug, it is a shipping bug with a marketing surface.

This module is deliberately not a style test. Every assertion below is
*substantive* — it asks whether a claim is present and whether it is a claim at
all, rather than whether particular words appear in a particular order. A
rewording that keeps the meaning must keep passing; a rewrite that deletes the
limitation must fail.

Three properties make it trustworthy:

1. **It fails on the tree it was written against.** Every assertion was run
   before the prose was corrected; see the lane report for the before/after
   counts.
2. **It has negative controls.** The ``*_fails_when_*`` tests re-run each
   substantive check against text with the honesty passage deleted and assert
   that the check *does* complain. A check that cannot fail is decoration, and
   these prove the checks have teeth.
3. **It covers the class of drift, not the instance.** The anchor check and the
   command-parity check were added because a whole check had gone missing
   unnoticed — see the note on the stranded ``_iter_doc_invocations`` helper in
   ``test_release_contract.py``.
"""

from __future__ import annotations

import importlib.util
import re
import shlex
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

import pytest

from mayhem.domain.catalog import CATALOG

if TYPE_CHECKING:
    from collections.abc import Iterator

ROOT = Path(__file__).parents[2]
README_PATH = ROOT / "README.md"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"

#: The heading the honesty passage lives under. Kept in one place so the
#: negative controls and the checks can never drift apart.
HONESTY_HEADING = "What mayhem cannot do"

#: Every document the documentation-consistency test considers part of the
#: published surface. The anchor check runs over the same set so the two tests
#: cannot disagree about what "the docs" means.
DOCUMENTS: tuple[Path, ...] = tuple(
    sorted(
        {
            README_PATH,
            CHANGELOG_PATH,
            *ROOT.glob("docs/**/*.md"),
            *ROOT.glob("examples/**/*.md"),
        }
    )
)

#: The ``docs/v1.0.0/`` planning package, which another lane owns. It is
#: excluded from the *enforced* checks below for two different reasons, both
#: deliberate:
#:
#: 1. It names proposed commands that do not exist — ``mayhem verify-live``,
#:    ``mayhem pack trust add``, ``mayhem run --preview``. A plan that names a
#:    proposed command has not lied about the current surface.
#: 2. It still contains pack-signing overclaims this lane cannot fix. Recorded
#:    here so the exclusion is auditable rather than invisible; reported to the
#:    owning lane:
#:
#:    - ``docs/v1.0.0/README.md``
#:      "**mayhem has a signed fault-pack format and no way to load it.**" — both
#:      halves are now false. A loader exists and enforces a SHA-256 integrity
#:      digest; the format is *not* signed and cannot be.
#:    - ``docs/v1.0.0/README.md``
#:      "a signed extensibility format that exists and cannot be loaded — finish
#:      or delete"; "| [05 fault packs](05-fault-packs.md) | **0%** — the signed
#:      format still cannot be loaded by anything".
#:    - ``docs/v1.0.0/05-fault-packs.md``
#:      "# Plan 4 — the signed fault pack, finished or deleted"; "a pack is
#:      trusted because it is signed by a [trusted key]"; "| 6 | `mayhem pack
#:      list` showing every pack fault and its signer |".
#:    - ``docs/v1.0.0/06-debt-and-quality.md``
#:      "record the **pack signer** (plan 4 step 5)".
#:
#: When the owning lane corrects those lines, nothing in this file needs to
#: change: the exclusion is by path, not by content.
PLANNING_PACKAGE = ROOT / "docs" / "v1.0.0"

#: The published user-facing surface: everything a reader can be sent to, and
#: therefore everything that must not overclaim.
PUBLISHED_DOCUMENTS: tuple[Path, ...] = tuple(
    path for path in DOCUMENTS if not path.is_relative_to(PLANNING_PACKAGE)
)

#: Documents that make *current-surface* claims about commands. The planning
#: package is excluded per ``PLANNING_PACKAGE``. ``CHANGELOG.md`` is excluded
#: for the reason ``docs/README.md`` already classifies it: it is a historical
#: audit, and the whole point of a breaking-change entry is to name a command
#: invocation that no longer resolves. The current references, the README, and
#: the examples have no such licence.
CURRENT_SURFACE_DOCUMENTS: tuple[Path, ...] = tuple(
    path
    for path in PUBLISHED_DOCUMENTS
    if path not in {CHANGELOG_PATH, ROOT / "docs/new-faults"}
    and (
        path == README_PATH
        or path == ROOT / "docs/README.md"
        or path
        in {ROOT / "docs/drill-spec.md", ROOT / "docs/config.md", ROOT / "docs/compensation.md"}
        or path.is_relative_to(ROOT / "docs/fault-catalog")
        or path.is_relative_to(ROOT / "examples")
    )
)

#: The version section that must carry the 1.0.0 breaking changes.
RELEASE_SECTION = "1.0.0"

_INLINE_LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+['\"][^)]*['\"])?\s*\)")
_REFERENCE_LINK_RE = re.compile(r"^\s*\[[^\]]+\]:\s*<?([^\s>]+)>?", re.MULTILINE)
_FENCE_RE = re.compile(r"^\s*(?:```|~~~)")
_ATX_HEADING_RE = re.compile(r"^(?P<marks>#{1,6})\s+(?P<title>.*?)\s*#*\s*$")


# ── text helpers ────────────────────────────────────────────────────────────


def _readme() -> str:
    return README_PATH.read_text(encoding="utf-8")


def _changelog() -> str:
    return CHANGELOG_PATH.read_text(encoding="utf-8")


def _blocks(text: str) -> list[str]:
    """Split Markdown into maximal runs of non-blank lines.

    A paragraph, a table row, and a list item each become their own block. A
    claim and its qualifier sit on the same lines far more often than they are
    split across paragraphs, so block-level co-occurrence is the right unit for
    "does this passage actually say the thing".
    """
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.strip():
            current.append(line)
        elif current:
            blocks.append("\n".join(current))
            current = []
    if current:
        blocks.append("\n".join(current))
    return blocks


def _slug(heading: str) -> str:
    """GitHub-flavoured heading slug: strip punctuation, lowercase, dash-join."""
    text = heading.strip().replace("`", "")
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"\s+", "-", text.strip().lower())


def _section(text: str, heading: str) -> str:
    """Return the body of the level-2 section whose heading matches ``heading``.

    Matching is case- and punctuation-insensitive so a reworded heading still
    resolves.
    """
    wanted = _slug(heading)
    collected: list[str] = []
    inside = False
    for line in text.splitlines():
        match = _ATX_HEADING_RE.match(line)
        if match:
            if inside and len(match.group("marks")) <= 2:
                break
            inside = _slug(match.group("title")) == wanted
            continue
        if inside:
            collected.append(line)
    assert collected, f"no section heading matching {heading!r} was found"
    return "\n".join(collected)


def _heading_slugs(path: Path) -> set[str]:
    """Every ATX heading slug in ``path``, skipping fenced code blocks."""
    slugs: set[str] = set()
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if _FENCE_RE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        match = _ATX_HEADING_RE.match(line)
        if match:
            slugs.add(_slug(match.group("title")))
    return slugs


def _link_targets(text: str) -> tuple[str, ...]:
    return tuple(_INLINE_LINK_RE.findall(text)) + tuple(_REFERENCE_LINK_RE.findall(text))


#: A block that claims an absence. Deliberately broad: the test is asking
#: "did the author write down that this is missing", not "did they use the word
#: 'no'".
_ABSENCE = re.compile(
    r"\b(?:no|not|never|cannot|can not|does not|doesn't|without|absent|lacks|lacking|"
    r"unsupported|unavailable|zero|none|isn't|aren't|won't)\b",
    re.IGNORECASE,
)


# ── gate 1: no kernel / BPF fault injection ─────────────────────────────────


def _kernel_bpf_overclaims(text: str) -> list[str]:
    """Blocks that discuss kernel/BPF injection without recording its absence."""
    overclaims = []
    for block in _blocks(text):
        mentions_bpf = re.search(r"\bbpf\b|\bebpf\b", block, re.IGNORECASE) is not None
        mentions_kernel = re.search(r"\bkernel\b", block, re.IGNORECASE) is not None
        if mentions_bpf and mentions_kernel and not _ABSENCE.search(block):
            overclaims.append(block.splitlines()[0][:160])
    return overclaims


def test_readme_states_there_is_no_kernel_or_bpf_fault_injection() -> None:
    """Gate 1: the README must record the absence, not merely raise the topic.

    Asserted at block level so a reworded sentence still passes; deliberately
    *not* matched against one blessed phrasing.
    """
    text = _readme()
    assert re.search(r"\bbpf\b|\bebpf\b", text, re.IGNORECASE), (
        "the README never mentions BPF/eBPF; the largest functional gap against "
        "Chaos Mesh is undocumented"
    )
    assert re.search(r"\bkernel\b", text, re.IGNORECASE), (
        "the README never mentions the kernel; the injection substrate is undescribed"
    )
    overclaims = _kernel_bpf_overclaims(text)
    assert not overclaims, (
        "the README discusses kernel/BPF injection without saying it is absent:\n"
        + "\n".join(overclaims)
    )


def test_kernel_bpf_check_fails_when_the_honesty_text_is_removed() -> None:
    """Negative control: gate 1's check is load-bearing, not vacuous."""
    text = _readme()
    assert not _kernel_bpf_overclaims(text)
    without = text.replace(_section(text, HONESTY_HEADING), "")
    assert without != text, "the honesty section is empty; nothing was removed"
    assert len(_blocks(without)) < len(_blocks(text)), (
        "removing the honesty section removed no prose; the control is not exercising itself"
    )
    claiming = without + (
        "\n\n## Injection substrate\n\n"
        "Mayhem injects faults with eBPF programs and kernel primitives.\n"
    )
    assert _kernel_bpf_overclaims(claiming), (
        "a README that described the capability instead of denying it was not caught"
    )


# ── gate 2: maturity ────────────────────────────────────────────────────────


def _live_verification_silence(text: str) -> list[str]:
    """Blocks that mention ``verified-live`` without stating that it is empty."""
    zero = re.compile(
        r"\b0\s*(?:of|/|out of)\s*\d+|\b0/\d+\b|\bzero\b|\bnone\b|\bnot one\b|"
        r"\bno\b(?=\s+(?:\w+\s+){0,3}(?:fault|is|are|has|have|carry|hold))",
        re.IGNORECASE,
    )
    silent = []
    for block in _blocks(text):
        if re.search(r"verified[-\s]live", block, re.IGNORECASE) and not zero.search(block):
            silent.append(block.splitlines()[0][:160])
    return silent


def test_readme_does_not_claim_any_fault_is_live_verified() -> None:
    """Gate 2: 0 of N faults are ``verified-live`` and the README must say so.

    ``N`` is read from the live catalogue rather than written into this test. The
    denominator is the whole point of the gate — a reader has to be able to check
    a live-verified count against the real catalogue size — and a denominator
    frozen in the test would quietly become a smaller lie than the one it was
    written to catch.
    """
    text = _readme()
    silence = _live_verification_silence(text)
    assert not silence, (
        "the README mentions verified-live without stating that no fault holds "
        "it:\n" + "\n".join(silence)
    )
    total = len(CATALOG)
    assert re.search(rf"\b{total}\b", text), (
        "the README does not state the catalog size, so a reader cannot check a "
        "live-verified count against a denominator"
    )
    assert re.search(
        rf"\b0\b\W{{0,4}}\bof\b\W{{0,4}}\b{total}\b|\b{total}\b.{{0,24}}\b0\b", text
    ), f"the README does not state a 0-of-{total} live-verified count"


def _unit_verification_underclaims(text: str) -> list[str]:
    """Blocks naming ``verified-unit`` that do not say what the claim is about."""
    thin = []
    for block in _blocks(text):
        if "verified-unit" not in block:
            continue
        about_mayhems_own_code = re.search(
            r"mayhem'?s own|mayhem own|its own (?:parameter|refusal|compensation)|"
            r"parameter.{0,48}refusal|refusal.{0,48}compensation",
            block,
            re.IGNORECASE,
        )
        if about_mayhems_own_code and _ABSENCE.search(block):
            continue
        thin.append(block.splitlines()[0][:160])
    return thin


def test_readme_says_verified_unit_is_a_claim_about_mayhems_own_code() -> None:
    """Gate 2: a badge with no explanation is the failure mode, not the fix."""
    thin = _unit_verification_underclaims(_readme())
    assert not thin, (
        "the README presents verified-unit without saying it is a claim about "
        "mayhem's own parameter/refusal/compensation code and not about the "
        "fault working:\n" + "\n".join(thin)
    )


def test_maturity_checks_fail_when_the_honesty_text_is_removed() -> None:
    """Negative control: both gate-2 checks are load-bearing."""
    text = _readme()
    assert not _live_verification_silence(text)
    assert not _unit_verification_underclaims(text)
    without = text.replace(_section(text, HONESTY_HEADING), "")
    assert without != text, "the honesty section is empty; nothing was removed"
    claiming = without + (
        "\n\n## Maturity\n\nEvery fault in the catalog is `verified-unit`.\n"
        "The `verified-live` level applies to the faults we have exercised.\n"
    )
    assert _live_verification_silence(claiming), (
        "a README that used verified-live without a zero count was not caught"
    )
    assert _unit_verification_underclaims(claiming), (
        "a README that presented verified-unit without saying what it is a claim "
        "about was not caught"
    )


# ── gate 4: fault packs are not signed ──────────────────────────────────────

#: A line that names signing and packs together is only acceptable if it also
#: disclaims. The disclaims below are the ones the loader actually implements
#: (see ``providers/pack.py``: a SHA-256 digest is checked, provenance is not).
_SIGN_DISCLAIMER = re.compile(
    r"not\s+(?:be\s+|ever\s+|currently\s+)?verified|cannot\s+(?:be\s+)?verify|"
    r"unverified|no\s+(?:public\s+|signing\s+)?(?:key|key\s+id|signature|"
    r"trust\s+store|algorithm)|"
    r"not\s+checked|not\s+implemented|without\s+(?:a\s+|any\s+)?"
    r"(?:key|algorithm|trust|signature)|"
    r"claim(?:ed)?\s+of\s+authorship|unsigned|integrity[-\s]checked|provenance",
    re.IGNORECASE,
)

#: Phrasings that assert a pack *is* authenticated. Each is a direct
#: contradiction of ``SIGNATURE_VERIFICATION_IMPLEMENTED = False``.
#:
#: Public (no leading underscore) because it is not only a documents check.
#: ``mayhem.domain.marketplace.CLASS_MEANING`` states the same honesty claim in
#: *source data* rather than in prose, and the honest strings there are only
#: load-bearing if the overclaim detector is applied to them too — see
#: ``test_marketplace.py``. The pattern lives here so the two cannot drift.
SIGNATURE_OVERCLAIM = re.compile(
    r"cryptographically\s+signed|signature[-\s]?verified|verified\s+signature|"
    r"signature\s+is\s+verified|signatures\s+are\s+verified|"
    r"trusted\s+sign(?:ature|er)|signed\s+and\s+verified",
    re.IGNORECASE,
)

#: Phrasings that assert a publisher has been *authenticated*, independently of
#: the word "signature". A rewrite can dodge the pattern above by never saying
#: "signed" — "so the publisher is authenticated" claims exactly the same thing
#: the domain refuses to establish, so it is caught by name.
#:
#: Each alternative is written so the shipped honest sentences do not match. The
#: real ``CLASS_MEANING`` text says "nothing here authenticates the publisher",
#: which is a *negation*: ``authenticates?`` with no preceding negation word
#: would match it, so a negative lookbehind is required rather than a rewrite of
#: the honest prose, which must not be bent around a test.
PUBLISHER_AUTHENTICATED_OVERCLAIM = re.compile(
    r"(?<!nothing here )(?<!never )(?<!not )"
    r"(?:publisher\s+is\s+authenticated|authenticates?\s+the\s+publisher|"
    r"verif(?:y|ies|ied)\s+the\s+publisher|"
    r"trust\s+(?:is\s+)?established|no\s+certification\s+gap|"
    r"certification\s+gap\s+remains|provenance\s+(?:is\s+)?established)",
    re.IGNORECASE,
)

#: Kept as a private alias so the existing document checks below read unchanged.
_SIGNATURE_OVERCLAIM = SIGNATURE_OVERCLAIM


def honesty_overclaims(text: str) -> list[str]:
    """Every overclaim phrase in *text*, whichever gate it belongs to.

    The single entry point for "does this sentence claim more than mayhem can
    establish", shared by the document gates and by the source-data guard in
    ``test_marketplace.py``. Returns the matched phrases so a failure can name
    the sentence rather than just the file.
    """
    found = [match.group(0) for match in SIGNATURE_OVERCLAIM.finditer(text)]
    found += [match.group(0) for match in PUBLISHER_AUTHENTICATED_OVERCLAIM.finditer(text)]
    return found


def _pack_signing_overclaims(text: str) -> list[str]:
    """Blocks that tie signing to packs without carrying the disclaimer.

    Block-level, not line-level: a disclaimer routinely wraps onto the next
    line, and a checker that demands it on the same physical line would be
    checking typography rather than honesty.
    """
    overclaims = []
    for block in _blocks(text):
        if not re.search(r"sign", block, re.IGNORECASE):
            continue
        if not re.search(r"\bpacks?\b", block, re.IGNORECASE):
            continue
        if _SIGN_DISCLAIMER.search(block):
            continue
        overclaims.append(block.splitlines()[0][:160])
    return overclaims


@pytest.mark.parametrize("path", PUBLISHED_DOCUMENTS, ids=lambda path: str(path.relative_to(ROOT)))
def test_no_document_describes_fault_packs_as_signed(path: Path) -> None:
    """Gate 4: a placeholder ``signature: str`` is not a signature.

    ``pack.py`` declares a signature field with no key, no algorithm, and no
    trust store, so the loader verifies a SHA-256 *digest* and nothing else. Any
    document that calls a pack "signed" without that caveat in the same breath
    is a lie with a version number.
    """
    text = path.read_text(encoding="utf-8")
    overclaims = _pack_signing_overclaims(text)
    assert not overclaims, (
        f"{path.relative_to(ROOT)} describes fault packs with signing language and "
        f"no disclaimer:\n" + "\n".join(overclaims)
    )
    assertion = _SIGNATURE_OVERCLAIM.search(text)
    assert assertion is None, (
        f"{path.relative_to(ROOT)} asserts a verified pack signature: {assertion.group(0)!r}"
        if assertion
        else ""
    )


def test_pack_signing_check_fails_on_the_overclaim_it_exists_to_catch() -> None:
    """Negative control: gate 4 fails on the exact sentence it forbids."""
    overclaim = "| `mayhem pack` | Validate and load a signed fault pack. |"
    assert _pack_signing_overclaims(overclaim), "the overclaim was not detected"
    disclaimed = (
        "| `mayhem pack` | Load a fault pack. **Integrity-checked; signatures are "
        "NOT verified in this build.** |"
    )
    assert not _pack_signing_overclaims(disclaimed), "a disclaimer should clear the line"
    assert _SIGNATURE_OVERCLAIM.search("Packs are cryptographically signed.")
    assert _SIGNATURE_OVERCLAIM.search("Each pack ships a verified signature.")


# ── gate 3: the release notes name the breaking changes ─────────────────────


def _release_notes(version: str = RELEASE_SECTION) -> str:
    """The body of one ``## <version> - <date>`` changelog section.

    Matched on the leading semver token rather than the whole heading, so the
    ``- 2026-09-29`` suffix and the ``[unreleased]`` bracket style do not have
    to be reproduced exactly.
    """
    text = _changelog()
    collected: list[str] = []
    inside = False
    for line in text.splitlines():
        match = _ATX_HEADING_RE.match(line)
        if match and len(match.group("marks")) <= 2:
            if inside:
                break
            inside = _slug(match.group("title")).startswith(_slug(version))
            continue
        if inside:
            collected.append(line)
    assert collected, f"CHANGELOG.md has no `{version}` section"
    return "\n".join(collected)


#: Each breaking change, and the facts that must appear for a reader to act on
#: it. Named rather than inlined so a failure reports *which* fact is missing.
BREAKING_CHANGE_FACTS: dict[str, dict[str, str]] = {
    "db.slow_query now defaults to netem latency": {
        "the fault": r"\bdb\.slow_query\b",
        "the mode key": r"\bmode\b",
        "the new value": r"\blatency\b",
        "the new mechanism": r"\bnetem\b",
        "the old mechanism": r"\biptables\b",
        "the old behaviour": r"\bDROP\b",
        "the breaking label": r"breaking",
    },
    "new catalog_only refusals": {
        "the flag": r"\bcatalog_only\b",
        "that they refuse": r"\brefus(?:e|es|ed|al)\w*",
        "a count of them": r"\b(?:nine|9|thirteen|13)\b",
    },
    "mayhem p is now an ambiguous prefix": {
        "the invocation": r"mayhem p\b",
        "the error": r"ambiguous_command|\bambiguous\b",
        "a replacement": r"mayhem pre(?:p)?\b",
    },
    "forbidden_fault_pairs actually fires now": {
        "the setting": r"\bforbidden_fault_pairs\b",
        "that it refuses": r"\brefus\w+",
        "that it was inert": r"\b(?:inert|silently|never fired|decorative|did not fire|no-op)\b",
        "the plan length that exposed it": r"\b(?:three|3)\b[^.\n]{0,40}"
        r"(?:faults?|steps?|plan)|3-fault",
        "the breaking label": r"breaking",
    },
    "a cumulative damage quota": {
        "the setting": r"\bdamage_quota\b",
        "its config home": r"\bblast_radius\b",
        "that it is cumulative": r"\bcumulative\b|\btotal\b",
        "that it refuses": r"\brefus\w+",
    },
}


def _missing_facts(notes: str) -> dict[str, list[str]]:
    """Map ``change name -> facts absent from ``notes`` ``, dropping empty ones."""
    missing: dict[str, list[str]] = {}
    for change, facts in BREAKING_CHANGE_FACTS.items():
        absent = [
            name for name, pattern in facts.items() if not re.search(pattern, notes, re.IGNORECASE)
        ]
        if absent:
            missing[change] = absent
    return missing


@pytest.mark.parametrize("change", sorted(BREAKING_CHANGE_FACTS))
def test_changelog_names_each_breaking_change(change: str) -> None:
    """Gate 3: a breaking change nobody was told about is not a breaking change."""
    missing = _missing_facts(_release_notes()).get(change, [])
    assert not missing, (
        f"CHANGELOG.md {RELEASE_SECTION} does not record {change!r} — missing: "
        + ", ".join(sorted(missing))
    )


def test_changelog_records_every_breaking_change_in_one_section() -> None:
    """All five must live under the same 1.0.0 heading, not scattered."""
    missing = _missing_facts(_release_notes())
    assert not missing, "CHANGELOG.md 1.0.0 is incomplete:\n" + "\n".join(
        f"  {change}: {', '.join(sorted(facts))}" for change, facts in sorted(missing.items())
    )


def test_breaking_change_checks_fail_when_the_facts_are_deleted() -> None:
    """Negative control: all five breaking-change checks are load-bearing."""
    notes = _release_notes()
    assert not _missing_facts(notes)
    emptied = notes
    for marker in (
        "db.slow_query",
        "catalog_only",
        "mayhem p",
        "forbidden_fault_pairs",
        "damage_quota",
    ):
        assert marker in notes, f"negative-control fixture is incomplete: {marker}"
        emptied = emptied.replace(marker, "\x00")
    reported = _missing_facts(emptied)
    assert set(reported) == set(BREAKING_CHANGE_FACTS), (
        "deleting the five names did not make every breaking-change check complain"
    )


# ── gate 5: intra-document anchors resolve ──────────────────────────────────


def _dangling_anchors() -> list[str]:
    dangling: list[str] = []
    for document in DOCUMENTS:
        for target in _link_targets(document.read_text(encoding="utf-8")):
            parsed = urlsplit(target)
            if not parsed.fragment or parsed.scheme or parsed.netloc:
                continue
            if target.startswith("/"):
                destination = ROOT / unquote(parsed.fragment.lstrip("/"))
            elif not parsed.path:
                destination = document
            else:
                destination = (document.parent / unquote(parsed.path)).resolve()
                if not destination.exists() or destination.suffix != ".md":
                    continue
            if parsed.fragment.lower() not in _heading_slugs(destination):
                dangling.append(f"{document.relative_to(ROOT)} -> {target}")
    return dangling


def test_every_intra_document_anchor_resolves() -> None:
    """Gate 5: the consistency test validates link *paths*, not *fragments*.

    ``test_documentation_consistency.py`` reads ``urlsplit(target).path`` and
    skips any target whose path is empty or already ``#…``, so ``[x](#nowhere)``
    is invisible to it. A dangling anchor is exactly the defect that makes a
    reader believe a claim the document does not back.
    """
    dangling = _dangling_anchors()
    assert not dangling, "intra-document anchors do not resolve:\n" + "\n".join(dangling)


def test_anchor_check_fails_on_a_dangling_fragment() -> None:
    """Negative control: the anchor check is a real check."""
    path = ROOT / "docs" / "README.md"
    original = path.read_text(encoding="utf-8")
    try:
        path.write_text(original + "\n\n[dangling](#no-such-heading)\n", encoding="utf-8")
        assert _dangling_anchors(), "an injected dangling anchor was not detected"
    finally:
        path.write_text(original, encoding="utf-8")
    assert not _dangling_anchors(), "the injected anchor was not cleaned up"


# ── gate 5b: the command-parity check that never ran ────────────────────────


def _release_contract_module():
    """Import the sibling contract module by path.

    The helpers this test reuses (``_resolve_invocation``, the code-span
    regexes) are intact; the module's own doc-invocation generator is not
    usable, which is the defect being reported.
    """
    name = "_release_contract_under_test"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "tests/unit/test_release_contract.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _doc_invocations(text: str) -> Iterator[tuple[int, list[str]]]:
    """Yield ``(line, argv)`` for every ``mayhem …`` reference in a document.

    A deliberate re-implementation. ``test_release_contract.py`` already has
    this helper, but it cannot be called: the CLI-inventory assertions were
    concatenated into the middle of its generator body, so the first thing the
    function does on any document containing a command is raise
    ``NameError: name 'documented' is not defined``. That is why no documented
    command has ever been checked against the live Click tree.
    """
    contract = _release_contract_module()
    for match in contract.CODE_SPAN_RE.finditer(text):
        lineno = text.count("\n", 0, match.start()) + 1
        lines = match.group(0).strip("`~").splitlines()
        if lines and contract.FENCE_LANGUAGE_RE.match(lines[0].strip()) and len(lines) > 1:
            lines = lines[1:]
        for line in lines:
            for segment in re.split(r"\|\||&&|\||;", line):
                try:
                    words = shlex.split(segment.strip(), comments=True)
                except ValueError:  # pragma: no cover - unbalanced quoting
                    continue
                if words and words[0] == "mayhem":
                    yield lineno, words[1:]


def test_stranded_doc_invocation_generator_would_raise_on_first_use() -> None:
    """Pin the defect this file exists partly to report.

    The generator in ``test_release_contract.py`` yields correctly and then
    falls into an orphaned block naming ``documented``, ``executable``, and
    ``active`` — none of which is defined anywhere in that module. Because it is
    a generator the block only runs on iteration, and because nothing iterates
    it, the CLI-doc-parity check has never run. The moment anything iterates it,
    it raises instead of checking anything.
    """
    contract = _release_contract_module()
    with pytest.raises(NameError, match="documented"):
        list(contract._iter_doc_invocations("```bash\nmayhem run mayhem.yaml\n```\n"))


def test_every_documented_mayhem_command_resolves_against_the_cli() -> None:
    """The check the stranded generator was supposed to perform.

    Scoped to the documents that make current-surface claims. The
    ``docs/v1.0.0/`` planning package is excluded because it deliberately names
    proposed commands; see ``CURRENT_SURFACE_DOCUMENTS``.
    """
    contract = _release_contract_module()
    unresolved: list[str] = []
    for document in CURRENT_SURFACE_DOCUMENTS:
        text = document.read_text(encoding="utf-8")
        for lineno, argv in _doc_invocations(text):
            problems = contract._resolve_invocation(argv)
            if problems:
                unresolved.append(
                    f"{document.relative_to(ROOT)}:{lineno} "
                    f"`mayhem {' '.join(argv)}` — {problems[0]}"
                )
    assert not unresolved, (
        "documented mayhem commands that do not resolve against the live CLI:\n"
        + "\n".join(unresolved)
    )


def test_documented_cli_reference_page_cannot_silently_disappear() -> None:
    """The stranded parity check had a second casualty: its target document.

    ``CURRENT_DOCS`` in ``test_release_contract.py`` lists ``docs/reference/*.md``
    and the orphaned inventory assertion names ``docs/reference/cli.md``
    specifically. No such file exists, and ``_current_doc_paths()`` — which has no
    callers — asserts on the empty glob. So the drift class is "a documented
    reference page is missing and nothing notices". This pins both facts that
    keep the gap visible: the page is absent, and the helper that would notice is
    itself dead.
    """
    contract = _release_contract_module()
    assert not (ROOT / "docs" / "reference" / "cli.md").exists(), (
        "docs/reference/cli.md now exists: retire this absence pin and give the CLI "
        "reference its own parity test"
    )
    dead = [pattern for pattern in contract.CURRENT_DOCS if not list(ROOT.glob(pattern))]
    assert dead, (
        "every CURRENT_DOCS pattern matches a file; the drift pin is stale and the "
        "dead glob list has been repaired"
    )
    with pytest.raises(AssertionError, match="matches nothing"):
        contract._current_doc_paths()
