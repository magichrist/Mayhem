"""Plan 05 \u2014 the plan document checked against the code it describes.

A plan document drifts. Phases get marked done that were scoped down, numbers
appear that nothing measures, and citations name files that were renamed. This
file checks the three ways that happens here:

* **The ledger must agree with itself.** Every phase line must match the phase
  section it summarises, and ``Overall: N of 6`` must match the ledger. A plan
  claiming six of six with an open phase is the failure this exists to catch.
* **The scoping must survive.** Phases 2 and 3 were scoped down, and the 12
  genuinely-new ids are still unbuilt. A ledger line that quietly stops saying so
  is the specific dishonesty most likely to creep in, so the wording is required
  to still be present.
* **Citations must resolve.** Every ``tests/unit/*.py`` and
  ``src/mayhem/**/*.py`` path the document names must exist, and every fault id it
  names must be in the catalog or explicitly marked as absent.

Each checker is a function so the mutated-copy controls below can attack it
individually. A control that cannot fail is not a control.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mayhem.domain.catalog import CATALOG

PLAN = Path(__file__).resolve().parents[2] / "docs/v1.1.0/05_APP_AND_DEPENDENCY_FAULTS.md"

CATALOG_IDS = frozenset(definition.id for definition in CATALOG)
TEST_PATH = re.compile(r"tests/unit/[A-Za-z0-9_./-]+\.py")
SOURCE_PATH = re.compile(r"src/mayhem/[A-Za-z0-9_./-]+\.py")
LEDGER = re.compile(r"^- Phase (\d)(?:[^:]*)?:\s*(.+)$", re.M)
OVERALL = re.compile(r"^Overall: (\d) of 6", re.M)
FAULT_ID = re.compile(r"`([a-z][a-z0-9]*\.[a-z][a-z0-9_]*)`")
PREFIXES = frozenset(fault_id.split(".")[0] for fault_id in CATALOG_IDS)
#: Vocabulary marking a mention as "this id does not exist yet". ``GENUINELY-NEW``
#: is the plan's own verdict column, and the Counts paragraph names the whole
#: build list across six lines while stating the verdict once above them, so the
#: check reads the enclosing paragraph rather than the line.
NOT_YET = re.compile(
    r"\b(?:no|not|never|does not|doesn't|isn't|rather than|absent|retired|"
    r"genuinely-new|new catalog id|unbuildable|blocked|unbuilt)\b",
    re.I,
)

#: ``RULE_*`` constants are dotted strings that look exactly like fault ids.
#: ``dependency.unresolved`` is a rule, not a fault anybody can run, and the set
#: is derived from the source so it needs no maintenance.
RULE_CONSTANT = re.compile(r'^RULE_[A-Z_]+\s*(?::[^=]+)?=\s*"([^"]+)"', re.M)

REQUIRED_SECTIONS = (
    "## Phase 4 outcome \u2014 dependency fan-out accounting",
    "### What this does not claim",
    "## Phase 5 outcome \u2014 the sweep criterion, made checkable",
    "### What the survey found",
    "### Three defects the negative controls found",
    "## Phase 6 outcome \u2014 the matrix, the gate, and the rollout order",
    "### What the gate found",
    "### Rollout order",
)

REQUIRED_PHRASES = (
    # The scoping that must not erode.
    "The 12 genuinely-new ids",
    # Phase 6's acceptance criterion, restated so it can be checked.
    "no doc presents a retired id as available",
    # The rollout order the phase committed to.
    "HTTP and gRPC first",
    "messaging only after the substrate ruling lands",
)


def _text() -> str:
    return PLAN.read_text(encoding="utf-8")


def check_ledger_self_consistent(text: str) -> list[str]:
    """Every phase has a line, and ``Overall`` counts the lines that say DONE."""
    problems: list[str] = []
    lines = {int(m.group(1)): m.group(2) for m in LEDGER.finditer(text)}
    for phase in range(1, 7):
        if phase not in lines:
            problems.append(f"phase {phase} has no ledger line")
    overall = OVERALL.search(text)
    if overall is None:
        problems.append("no `Overall: N of 6` line")
        return problems
    claimed = int(overall.group(1))
    done = sum(1 for body in lines.values() if "DONE" in body)
    if claimed != done:
        problems.append(f"Overall claims {claimed} of 6 but {done} ledger lines say DONE")
    return problems


def check_required_sections(text: str) -> list[str]:
    return [name for name in REQUIRED_SECTIONS if name not in text]


def check_required_phrases(text: str) -> list[str]:
    return [phrase for phrase in REQUIRED_PHRASES if phrase not in text]


def check_citations_resolve(text: str, root: Path) -> list[str]:
    missing = []
    for match in TEST_PATH.finditer(text):
        if not (root / match.group(0)).is_file():
            missing.append(match.group(0))
    for match in SOURCE_PATH.finditer(text):
        if not (root / match.group(0)).is_file():
            missing.append(match.group(0))
    return sorted(set(missing))


def _rule_ids(root: Path) -> frozenset[str]:
    """Every ``RULE_*`` constant in ``src/`` -- dotted strings, not fault ids."""
    found: set[str] = set()
    for path in (root / "src").rglob("*.py"):
        found |= set(RULE_CONSTANT.findall(path.read_text(encoding="utf-8")))
    return frozenset(found)


def check_fault_ids(text: str, root: Path) -> list[str]:
    """Every id named must exist, be a rule id, or sit in a not-yet paragraph.

    Paragraph-scoped rather than line-scoped because the plan's Counts
    paragraph names all twelve unbuilt ids across six lines and states the
    verdict once, above them. A line-scoped check would either fail the
    document for being well-written or force the prose to repeat itself.
    """
    rules = _rule_ids(root)
    bad: list[str] = []
    for block in re.split(r"\n\s*\n", text):
        excused = bool(NOT_YET.search(block))
        for prefix, suffix in re.findall(r"`([a-z][a-z0-9]*)\.([a-z][a-z0-9_]*)`", block):
            if prefix not in PREFIXES:
                continue
            name = f"{prefix}.{suffix}"
            if name in CATALOG_IDS or name in rules:
                continue
            if excused:
                continue
            bad.append(name)
    return sorted(set(bad))


@pytest.fixture(scope="module")
def text() -> str:
    return _text()


@pytest.fixture(scope="module")
def root() -> Path:
    return PLAN.parents[2]


class TestTheDocument:
    def test_it_exists(self) -> None:
        assert PLAN.is_file(), PLAN

    def test_the_ledger_agrees_with_itself(self, text: str) -> None:
        assert not check_ledger_self_consistent(text), check_ledger_self_consistent(text)

    def test_the_required_phase_sections_are_present(self, text: str) -> None:
        assert not check_required_sections(text), check_required_sections(text)

    def test_the_required_phrases_are_present(self, text: str) -> None:
        assert not check_required_phrases(text), check_required_phrases(text)

    def test_every_cited_path_exists(self, text: str, root: Path) -> None:
        assert not check_citations_resolve(text, root), check_citations_resolve(text, root)

    def test_it_cites_a_path_at_all(self, text: str) -> None:
        """Otherwise the citation check is vacuous."""
        assert len(TEST_PATH.findall(text)) >= 3

    def test_every_fault_id_named_is_real_or_marked_absent(self, text: str, root: Path) -> None:
        bad = check_fault_ids(text, root)
        assert not bad, f"the plan names fault ids the catalog lacks: {bad}"

    def test_the_unbuilt_ids_are_still_called_unbuilt(self, text: str) -> None:
        """The single most likely way this document could start lying.

        Phases 2 and 3 were scoped down to parameter work and the audit's
        genuinely-new ids were never built. A ledger that stops saying so while
        claiming six of six would be the plan quietly claiming a product.
        """
        overall = OVERALL.search(text)
        assert overall is not None
        assert "unbuilt" in text
        assert "genuinely-new" in text


class TestTheCheckersBite:
    """Every checker, attacked against a mutated copy of the real document."""

    ROOT = PLAN.parents[2]

    def test_ledger_checker_catches_an_overclaim(self, text: str) -> None:
        assert check_ledger_self_consistent(text) == []
        assert check_ledger_self_consistent(text.replace("Overall: 6 of 6", "Overall: 7 of 6"))

    def test_ledger_checker_catches_a_phase_with_no_line(self, text: str) -> None:
        stripped = re.sub(r"^- Phase 5[^\n]*\n", "", text, flags=re.M)
        assert "no `Overall" not in " ".join(check_ledger_self_consistent(stripped))
        assert check_ledger_self_consistent(stripped)

    def test_section_checker_catches_a_removed_section(self, text: str) -> None:
        assert check_required_sections(text) == []
        assert check_required_sections(text.replace("### Rollout order", "### Later"))

    def test_phrase_checker_catches_a_dropped_scoping_note(self, text: str) -> None:
        assert check_required_phrases(text) == []
        assert check_required_phrases(text.replace("messaging only after", "messaging after"))

    def test_citation_checker_catches_a_renamed_file(self, text: str) -> None:
        assert check_citations_resolve(text, self.ROOT) == []
        stale = text.replace("tests/unit/test_dependency_fanout.py", "tests/unit/test_fanout.py")
        assert check_citations_resolve(stale, self.ROOT) == ["tests/unit/test_fanout.py"]

    def test_citation_checker_catches_a_source_path_rename(self, text: str) -> None:
        assert not check_citations_resolve(text, self.ROOT)
        stale = text.replace("src/mayhem/domain/topology.py", "src/mayhem/domain/graph.py")
        if stale == text:
            # The document cites no src/ path; use a test path it does name.
            stale = text.replace("tests/unit/test_dependency_fanout.py", "tests/unit/t_fanout.py")
        assert check_citations_resolve(stale, self.ROOT)

    def test_fault_id_checker_catches_an_invented_id(self, text: str) -> None:
        assert check_fault_ids(text, self.ROOT) == []
        invented = text + "\n\nUse `dependency.slow_first` for this.\n"
        assert check_fault_ids(invented, self.ROOT) == ["dependency.slow_first"]

    def test_fault_id_checker_allows_an_explicitly_absent_id(self, text: str) -> None:
        """Two-sided: the not-yet allowance must not be a blanket pass."""
        excused = text + "\n\nThere is no `dependency.slow_first`.\n"
        assert check_fault_ids(excused, self.ROOT) == []
        # A verdict one paragraph away does not excuse the next one, or the
        # allowance would cover the whole document after its first match.
        buried = "\n\n| row | `dependency.slow_first` | offered |\n"
        assert check_fault_ids(text + buried, self.ROOT) == ["dependency.slow_first"]

    def test_it_knows_a_rule_id_is_not_a_fault_id(self) -> None:
        """``dependency.unresolved`` is a rule; ``dependency.slow`` is not."""
        rules = _rule_ids(self.ROOT)
        assert "dependency.unresolved" in rules
        assert "dependency.slow" not in rules
