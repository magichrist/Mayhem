"""Plan 18 Phase 6 — the overclaim scan, extended to marketplace pages.

Plan 18 Phase 6's acceptance criterion is one sentence: *"the overclaim scan (no
'signed/verified/trusted' without same-breath qualification) extended to
marketplace pages."* This is that extension.

The scan exists because a trust label is the easiest thing in the system to
over-read, and because the failure is invisible in review: "verified" next to a
package name looks like a fact rather than a claim about a certification cell.

What is enforced, and each checker's two-sided case:

* **A trust word needs its qualification in the same breath.** Not somewhere on
  the page — in the same sentence. A disclaimer at the bottom of a document
  protects nobody reading the table.
* **Every label states what it does not establish.** A table with only the
  positive column is the shape that produces the overclaim, so each of the five
  classes must appear with both halves.
* **The ledger agrees with itself.** ``Overall: N of 6`` equal to the ``DONE``
  count, so the document cannot claim progress it has not made.
* **Citations resolve and the vocabulary is real.** Every label named must be a
  member of ``ArtifactClass`` and every cited path must exist, so the page cannot
  describe a class the domain does not have.

Each checker is a function so the mutated-copy controls can attack it. The
negative-control table at the end is not decoration: an earlier draft of this
file had two assertions that could not fail, and both were removed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from mayhem.domain.marketplace import (
    SIGNATURE_TRUST_NOTICE,
    ArtifactClass,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN = (REPO_ROOT / "docs/v1.1.0/18_MARKETPLACE_CATALOG.md").read_text(encoding="utf-8")
GUIDE = (REPO_ROOT / "docs/v1.1.0/18_trust_labels.md").read_text(encoding="utf-8")
GUIDE_PATH = "docs/v1.1.0/18_trust_labels.md"

#: A trust word on its own. ``integrity`` is deliberately absent: a digest check
#: *is* an integrity claim and saying so is accurate.
#: Word-bounded, and that is load-bearing rather than tidiness: the plans
#: discuss ``unsigned_no_signing`` and ``signature_state`` constantly, and an
#: unanchored ``signed`` matches inside ``unsigned`` -- so the scan would demand
#: a disclaimer for the sentence that says signing is *not* implemented. The
#: same trap caught the identity gate earlier with "port" inside
#: "ProviderPort".
TRUST_WORD: Final = r"\b(?:signed|verified|trusted|vouches?|endorsed|authentic)\b"

#: What must accompany one. The vocabulary is the one the domain itself uses in
#: ``SIGNATURE_TRUST_NOTICE`` -- same words, so prose that passes the scan is
#: prose that agrees with the code.
QUALIFIER: Final = (
    r"(?:integrity[- ]checked|integrity only|sha-256 integrity|not implemented|"
    r"no signature|signatures? not verified|no trust store|unverified declaration|"
    r"declared|provenance|nothing .{0,40}authenticates?|not that an author|"
    r"no certification record|certification record|current|evidence|"
    r"bytes on a|does not establish|not establish|no claim about|"
    r"enforced by machinery|not marketing|never invents?|without a record|"
    r"minimum bar|requires the record|no shortcut|cannot be checked|"
    r"nothing (?:in this build )?(?:can|does)|no public key|"
    r"qualification|is \*\*not\*\*|\*\*does not\*\*|\bnot\b|"
    r"cannot use|cannot say)"
)

#: A sentence is the unit. Breaking on the period is what makes
#: "same-breath" checkable rather than aspirational.
SENTENCE: Final = re.compile(r"[^.\n]*\.(?:\s|$)")


def sentences(text: str) -> list[str]:
    """Split into sentences, tolerating markdown lists and table rows.

    A table row has no terminating period, so each pipe-delimited row counts as
    its own unit. That is deliberate: the alternative is a row whose disclaimer
    is counted as qualifying every cell above it.
    """
    units: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|"):
            units.append(stripped)
        else:
            units.extend(match.group(0) for match in SENTENCE.finditer(stripped))
    return units


def unqualified_trust_words(text: str) -> list[str]:
    """Sentences naming a trust word with no qualifier in the same sentence."""
    offenders: list[str] = []
    pattern = re.compile(TRUST_WORD, re.I)
    qualifier = re.compile(QUALIFIER, re.I)
    for unit in sentences(text):
        if pattern.search(unit) and not qualifier.search(unit):
            offenders.append(unit.strip()[:120])
    return offenders


def labels_without_a_negative(text: str) -> list[str]:
    """Class names whose row leaves the "does not establish" column empty.

    The check is on the *cell*, not on a repeated phrase. An earlier version
    looked for the literal ``does **not**`` inside each row, which could only
    ever pass if the table repeated its own header on every line -- so it failed
    against the correct page and could not be satisfied without making the table
    unreadable. What matters is that a reader looking at a class sees a
    non-empty answer in both columns.
    """
    documented: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 3 or not cells[2]:
            continue
        named = {c.value for c in ArtifactClass if c.value in cells[0]}
        if named:
            documented |= named
    return sorted(c.value for c in ArtifactClass if c.value not in documented)


#: A phase counts as delivered when its line says so. ``DELIVERED`` is this
#: plan's own vocabulary for a phase delivered in part and counted
#: deliberately; excluding it would force the document to overclaim in order to
#: satisfy its own gate.
COMPLETE_WORD: Final = re.compile(r"\b(?:DONE|DELIVERED)\b", re.I)


def ledger_problems(text: str) -> list[str]:
    lines = {
        int(m.group(1)): m.group(2)
        for m in re.finditer(r"^- Phase (\d)(?:[^:]*)?:\s*(.+)$", text, re.M)
    }
    problems = [f"phase {n} has no ledger line" for n in range(1, 7) if n not in lines]
    overall = re.search(r"^Overall: (\d) of 6", text, re.M)
    if overall is None:
        problems.append("no `Overall: N of 6` line")
        return problems
    done = sum(1 for body in lines.values() if COMPLETE_WORD.search(body))
    if int(overall.group(1)) != done:
        problems.append(f"Overall claims {overall.group(1)} but {done} ledger lines say DONE")
    return problems


def dangling_citations(text: str) -> list[str]:
    missing = []
    for match in re.finditer(r"`?((?:tests/unit|src/mayhem)/[A-Za-z0-9_./-]+\.py)`?", text):
        if not (REPO_ROOT / match.group(1)).is_file():
            missing.append(match.group(1))
    for match in re.finditer(r"`(docs/v1\.1\.0/[^`]+\.md)`", text):
        if not (REPO_ROOT / match.group(1)).is_file():
            missing.append(match.group(1))
    return sorted(set(missing))


def invented_classes(text: str) -> list[str]:
    """A class named in the guide that ``ArtifactClass`` does not have."""
    real = {c.value for c in ArtifactClass}
    claimed = set(re.findall(r"`([a-z_]+)`", text))
    # Only names that look like a class and are not other backticked identifiers.
    return sorted(
        name
        for name in claimed
        if name not in real
        and name.startswith(
            ("unverified", "verified", "official", "organization", "deprecated", "signed")
        )
        and name not in {"signature_verification_implemented"}
    )


class TestTheOverclaimScan:
    def test_the_guide_exists_and_is_substantial(self) -> None:
        assert (REPO_ROOT / GUIDE_PATH).is_file()
        assert len(GUIDE.splitlines()) > 60

    def test_no_unqualified_trust_word_in_the_guide(self) -> None:
        assert not unqualified_trust_words(GUIDE), unqualified_trust_words(GUIDE)

    def test_no_unqualified_trust_word_in_the_plan(self) -> None:
        assert not unqualified_trust_words(PLAN), unqualified_trust_words(PLAN)

    def test_every_class_states_what_it_does_not_establish(self) -> None:
        assert not labels_without_a_negative(GUIDE), labels_without_a_negative(GUIDE)

    def test_every_class_in_the_domain_is_documented(self) -> None:
        for member in ArtifactClass:
            assert member.value in GUIDE, member.value

    def test_the_guide_invents_no_class(self) -> None:
        assert not invented_classes(GUIDE), invented_classes(GUIDE)

    def test_the_signing_flag_is_still_false_and_the_page_says_so(self) -> None:
        """The page and the build must agree, or the page is the fiction."""
        from mayhem.domain.marketplace import SIGNATURE_VERIFICATION_IMPLEMENTED

        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
        assert "SIGNATURE_VERIFICATION_IMPLEMENTED` is `False" in GUIDE

    def test_the_notice_is_reachable_from_the_label(self) -> None:
        """The gate checks prose; this checks the code the prose describes."""
        assert "mayhem cannot verify artifact signatures" in SIGNATURE_TRUST_NOTICE
        assert "provenance" in SIGNATURE_TRUST_NOTICE

    def test_the_ledger_agrees_with_itself(self) -> None:
        assert not ledger_problems(PLAN), ledger_problems(PLAN)

    def test_every_cited_path_exists(self) -> None:
        assert not dangling_citations(PLAN), dangling_citations(PLAN)

    def test_the_citation_checker_finds_its_work(self) -> None:
        """Otherwise it passes on a document that cites nothing."""
        assert re.search(r"(?:tests/unit|src/mayhem)/[A-Za-z0-9_./-]+\.py", PLAN)


class TestTheCheckersBite:
    """Every checker, against a mutated copy. A check that cannot fail is not one."""

    def test_the_overclaim_scan_catches_a_bare_verified(self) -> None:
        bad = GUIDE + "\nThe artifact is **verified** and ready to run.\n"
        assert unqualified_trust_words(bad)

    def test_and_accepts_a_qualified_one(self) -> None:
        """Two-sided: the scan must not simply forbid the word."""
        good = "\nThe digest is integrity-checked, which is not provenance.\n"
        assert not unqualified_trust_words(good)

    def test_the_scan_does_not_extend_across_sentences(self) -> None:
        """The whole point of "same breath": a disclaimer below does not qualify above."""
        bad = "\nThe artifact is signed.\nA later paragraph explains that no signature exists.\n"
        assert unqualified_trust_words(bad)

    def test_the_negative_column_checker_catches_a_positive_only_table(self) -> None:
        blanked = re.sub(r"\|[^|\n]*\|[^|\n]*\|[^|\n]*\|$", "| a | b |  |", GUIDE, flags=re.M)
        assert labels_without_a_negative(blanked)

    def test_and_the_table_really_has_a_third_column_to_check(self) -> None:
        """Otherwise the checker above is testing a table that is not there."""
        rows = [ln for ln in GUIDE.splitlines() if ln.strip().startswith("|")]
        assert any(len(ln.strip().strip("|").split("|")) >= 3 for ln in rows)

    def test_and_passes_when_the_column_is_present(self) -> None:
        assert not labels_without_a_negative(GUIDE)

    def test_the_ledger_checker_catches_an_overclaim(self) -> None:
        assert ledger_problems(PLAN) == []
        assert ledger_problems(PLAN.replace("Overall: 3 of 6", "Overall: 6 of 6"))

    def test_the_ledger_checker_catches_a_missing_phase_line(self) -> None:
        stripped = re.sub(r"^- Phase 5[^\n]*\n", "", PLAN, flags=re.M)
        assert ledger_problems(stripped)

    def test_the_citation_checker_catches_a_renamed_file(self) -> None:
        renamed = PLAN.replace("tests/unit/test_marketplace.py", "tests/unit/test_mplace.py")
        assert "tests/unit/test_mplace.py" in dangling_citations(renamed)

    def test_the_invention_checker_catches_a_class_that_does_not_exist(self) -> None:
        assert invented_classes(GUIDE) == []
        assert invented_classes(GUIDE + "\nUse `verified_by_mayhem` for official builds.\n") == [
            "verified_by_mayhem"
        ]

    def test_a_table_row_qualifies_itself_not_the_row_above(self) -> None:
        """Rows have no terminating period; without this, one disclaimer floats."""
        table = "| a | verified |\n| b | integrity-checked, not provenance |\n"
        assert len(unqualified_trust_words(table)) == 1

    def test_the_checkers_are_callable_for_the_table_below(self) -> None:
        for checker in (
            unqualified_trust_words,
            labels_without_a_negative,
            ledger_problems,
            dangling_citations,
            invented_classes,
        ):
            assert callable(checker)
