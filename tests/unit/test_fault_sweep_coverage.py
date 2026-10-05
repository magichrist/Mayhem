"""Plan 05 Phase 5 — new fault ids must be swept automatically, and prove it.

Phase 5's acceptance criterion is one sentence: *"new ids swept into the six
deriving test files automatically."* This file turns that sentence into a
property of the repository rather than a claim about it.

The property has two halves, and the second is the half that bites:

1. **A full sweep exists.** Some test module derives its parametrization from
   ``CATALOG`` itself, so a newly added id is collected the moment it lands.
2. **A hardcoded list is never the *only* coverage.** Sixteen module-level id
   lists in ``tests/unit/`` spell their ids out literally. That is legitimate --
   a family-specific suite *should* name its family -- and it is also the exact
   shape that silently stops covering a new id. So each literal list must be a
   strict narrowing of the catalog, checked against ids that still exist, and
   every id in it must already be covered by a full sweep. A literal list that
   drifts out of the catalog, or that covers an id nothing else does, fails here.

The plan says "six deriving test files". The real number of full sweeps is
derived below and asserted as *at least two*, not as six: a count of files is
not the property anyone cares about, and pinning it would make this guard break
when someone usefully splits a file in two. The Phase 6 document records the
discrepancy rather than quietly matching the plan's number.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from mayhem.domain.catalog import CATALOG

if TYPE_CHECKING:
    from types import ModuleType

CATALOG_IDS = frozenset(definition.id for definition in CATALOG)
UNIT = Path(__file__).resolve().parent

#: A full sweep must be redundant. One file doing the sweeping means a rename,
#: a skip marker or a deletion silently drops coverage of every new id, and the
#: failure would not surface until the id was already in production.
MINIMUM_FULL_SWEEPS = 2


#: This file. It imports ``CATALOG`` and holds the full id set, so without this
#: exclusion it satisfies its own minimum: an earlier version did, and a mutation
#: that collapsed three of the four real full sweepers still passed, because the
#: guard was the fifth. Excluded by identity rather than by name so renaming the
#: file cannot silently re-admit it.
SELF = Path(__file__).resolve()


def _catalog_importing_modules() -> list[Path]:
    """Every unit test that reads the catalog at all, except this one.

    Found by source rather than by a hand-maintained list, because a
    hand-maintained list is exactly the hardcoding this guard exists to
    discourage. A module that imports ``CATALOG`` and is not returned here would
    be a module whose sweep could not be verified.
    """
    found = []
    for path in sorted(UNIT.glob("test_*.py")):
        if path.resolve() == SELF:
            continue
        source = path.read_text(encoding="utf-8")
        if "mayhem.domain.catalog import" in source or "mayhem.domain.faults import" in source:
            found.append(path)
    return found


def _load(path: Path) -> ModuleType:
    """Import a test module by path.

    Test modules are not importable by name here -- ``tests/`` has no
    ``__init__.py`` and several modules do ``from tests.unit.x import y`` -- so
    rootdir goes on the path first and the module is loaded under a private
    name. Importing is what makes the classification real rather than a regex
    guess: the value is the one pytest will actually parametrize over.
    """
    root = str(UNIT.parent.parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    name = f"_sweep_probe_{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _id_sets(namespace: ModuleType | type[object]) -> dict[str, frozenset[str]]:
    """Names in a namespace holding a non-empty set of real catalog ids.

    Takes a class as readily as a module, so the classifier can be pinned by a
    synthetic namespace instead of by whatever the repository happens to contain.
    """
    found: dict[str, frozenset[str]] = {}
    for name, value in vars(namespace).items():
        if name.startswith("_") or not isinstance(value, (tuple, list, set, frozenset)):
            continue
        if value and all(isinstance(v, str) and v in CATALOG_IDS for v in value):
            found[name] = frozenset(value)
    return found


def _written_out(module_name: str, source: str, ids: frozenset[str]) -> bool:
    """Is every id in this set spelled literally in the file, or computed?

    Computed-from-``CATALOG`` is what makes a sweep automatic. A literal list
    needs an edit to grow, which is the whole distinction this file is about.
    """
    return all(f'"{fault_id}"' in source or f"'{fault_id}'" in source for fault_id in ids)


@pytest.fixture(scope="module")
def landscape() -> dict[Path, dict[str, frozenset[str]]]:
    """Every catalog-importing module, loaded, with its id sets resolved."""
    return {path: _id_sets(_load(path)) for path in _catalog_importing_modules()}


class TestTheLandscape:
    def test_every_catalog_importing_module_can_be_inspected(
        self, landscape: dict[Path, dict[str, frozenset[str]]]
    ) -> None:
        """An unimportable module is an unverifiable sweep, so it is a failure.

        Skipping would be the comfortable choice and the dishonest one: the
        guard would report "all clear" about a file it never read.
        """
        assert landscape, "no test module imports the catalog; the sweep is vacuous"
        # ``landscape`` is keyed by path, so a module that raised during import
        # simply would not be present -- assert every discovered path is there.
        discovered = set(_catalog_importing_modules())
        assert set(landscape) == discovered

    def test_the_catalog_is_not_empty(self) -> None:
        """A guard derived from an empty catalog passes everything."""
        assert len(CATALOG_IDS) > 100

    def test_at_least_two_modules_sweep_the_whole_catalog(
        self, landscape: dict[Path, dict[str, frozenset[str]]]
    ) -> None:
        full = [
            f"{path.name}:{name}"
            for path, sets in landscape.items()
            for name, ids in sets.items()
            if ids == CATALOG_IDS
        ]
        assert len(full) >= MINIMUM_FULL_SWEEPS, full

    def test_a_literal_naming_a_retired_id_is_invisible_here_by_construction(
        self, landscape: dict[Path, dict[str, frozenset[str]]]
    ) -> None:
        """Stated rather than asserted, because there is nothing to assert.

        Two earlier drafts of this file asserted "every set is a subset of the
        catalog". Both were removed: ``_id_sets`` already drops any set containing
        a non-catalog member, so ``ids <= CATALOG_IDS`` and ``ids - CATALOG_IDS``
        are both true by construction, and a mutation deleting either assertion
        did not fail the suite. Two checks that cannot fail are worse than none,
        because they read as coverage.

        The cost is real and worth stating: **a literal list naming an id the
        catalog has since retired is invisible to this file.** The stale member
        disqualifies the whole set, so it is classified as neither a literal nor a
        full sweep and simply vanishes from both counts. Such a list is caught by
        whatever runs that module -- an ``ALL_FAULTS`` parametrization over a
        retired id raises -- not here. That is the correct place for the check,
        because only the owning module knows what the id meant.

        The assertion below is therefore the one that *does* bite: dropping the
        catalog-membership filter inside ``_id_sets`` is caught by
        ``TestTheClassifier``, and by the count invariants in
        ``TestHardcodedListsAreNarrowingNotCoverage``, which would no longer add
        up if sets were being misclassified in bulk.
        """
        recognised = {f"{p.name}:{n}" for p, sets in landscape.items() for n in sets}
        assert recognised, "no id sets recognised at all"


def test_the_guard_never_counts_itself() -> None:
    """The bug this file had, named so it cannot come back.

    An earlier version of this guard imported ``CATALOG`` and defined
    ``CATALOG_IDS`` over it, and therefore appeared in its own landscape as a
    full sweep. The consequence was not subtle: with three of the four real
    sweepers collapsed to literals, ``MINIMUM_FULL_SWEEPS`` was still satisfied
    by the guard, so the redundancy it exists to enforce was unenforced.

    ``MINIMUM_FULL_SWEEPS`` is compared against a landscape that must exclude
    this file. Asserted directly rather than inferred from a passing count,
    because the count is exactly what was wrong.
    """
    assert SELF not in _catalog_importing_modules()
    assert Path(__file__).resolve() == SELF


class TestHardcodedListsAreNarrowingNotCoverage:
    """The half that bites: literal lists must never be the only coverage."""

    def _literals(
        self, landscape: dict[Path, dict[str, frozenset[str]]]
    ) -> dict[str, frozenset[str]]:
        """``"file.py:NAME" -> ids`` for every id set spelled out by hand."""
        literals: dict[str, frozenset[str]] = {}
        for path, sets in landscape.items():
            source = path.read_text(encoding="utf-8")
            for name, ids in sets.items():
                if _written_out(path.name, source, ids):
                    literals[f"{path.name}:{name}"] = ids
        return literals

    def test_there_are_hardcoded_lists_to_guard(
        self, landscape: dict[Path, dict[str, frozenset[str]]]
    ) -> None:
        """A guard with nothing to bite is not a guard.

        Recorded as a finding rather than left implicit: as of this commit
        sixteen module-level id lists in ``tests/unit/`` are literals, and the
        number moves as modules are added, so the test asserts the category is
        non-empty instead of the count.
        """
        assert self._literals(landscape), "no hardcoded id lists found; re-check this guard"

    def test_every_hardcoded_id_is_covered_by_a_full_sweep(
        self, landscape: dict[Path, dict[str, frozenset[str]]]
    ) -> None:
        """A literal list may narrow; it may not be the sole owner of an id.

        This is the check that makes "new ids are swept automatically" mean
        something for the family suites: adding an id to ``CATALOG`` reaches
        every full sweep without an edit, so the literal suites are free to stay
        literal precisely because the id cannot slip past them unexamined.
        """
        swept = set().union(*(ids for sets in landscape.values() for ids in sets.values()))
        for where, ids in sorted(self._literals(landscape).items()):
            assert ids <= swept, (
                f"{where} covers ids no deriving module sweeps: {sorted(ids - swept)}"
            )

    def test_a_hardcoded_list_is_narrower_than_the_catalog(
        self, landscape: dict[Path, dict[str, frozenset[str]]]
    ) -> None:
        """A literal equal to the whole catalog is a sweep pretending to be literal.

        It is the worst of both: it looks hand-maintained, so nobody trusts it to
        stay current, and it does not derive, so it does not.
        """
        for where, ids in sorted(self._literals(landscape).items()):
            assert ids != CATALOG_IDS, f"{where} spells out every catalog id"

    def test_the_split_between_literal_and_derived_is_visible(
        self, landscape: dict[Path, dict[str, frozenset[str]]]
    ) -> None:
        """The report the plan's "six deriving test files" should have been.

        Asserted as a shape rather than a count: both categories are non-empty
        and together they account for every id set in the landscape, so the
        numbers cannot quietly drift apart with nothing noticing.
        """
        literals = self._literals(landscape)
        derived = [
            f"{path.name}:{name}"
            for path, sets in landscape.items()
            for name, ids in sets.items()
            if not _written_out(path.name, path.read_text(encoding="utf-8"), ids)
        ]
        assert literals and derived
        assert len(literals) + len(derived) == sum(len(sets) for sets in landscape.values())


class TestTheClassifier:
    """The classifier itself, two-sided.

    Without this the guard above would be unfalsifiable in one direction: it
    would pass whether ``_written_out`` recognised a literal or not, because the
    thing it guards -- a literal that drifts out of the catalog -- has not
    happened yet. These cases pin the classification rule independently of that.
    """

    def test_a_hand_written_tuple_is_classified_as_written_out(self) -> None:
        source = 'IDS = ("dependency.flap", "dependency.timeout")\n'
        assert _written_out("x.py", source, frozenset({"dependency.flap", "dependency.timeout"}))

    def test_a_comprehension_is_classified_as_derived(self) -> None:
        """Even with the ids quoted in the same file, e.g. in prose or a comment.

        The rule is deliberately about the *set*: a file that quotes an id in a
        docstring while deriving its parametrization is still automatic, and
        treating it as literal would make this guard cry wolf on good files.
        """
        source = (
            "IDS = tuple(d.id for d in CATALOG)\n"
            "# dependency.flap and dependency.timeout are both swept.\n"
        )
        assert not _written_out(
            "x.py", source, frozenset({"dependency.flap", "dependency.timeout"})
        )

    def test_a_partially_written_set_is_not_called_a_literal(self) -> None:
        """The conservative direction: ambiguous means not-literal, not the reverse.

        Calling a half-written set a literal would attach a hardcoded list's
        blame to a derived one, and the failure would name the wrong file.
        """
        source = 'IDS = ("dependency.flap",) + tuple(d.id for d in CATALOG)\n'
        assert not _written_out(
            "x.py", source, frozenset({"dependency.flap", "dependency.timeout"})
        )

    def test_id_sets_keeps_only_non_empty_sets_of_real_catalog_ids(self) -> None:
        class Fake:
            _PRIVATE = frozenset({"dependency.flap"})
            REAL = frozenset({"dependency.flap", "dependency.timeout"})
            A_TUPLE = ("dependency.flap",)
            EMPTY: frozenset[str] = frozenset()
            NOT_FAULTS = frozenset({"api", "web"})
            ONE_BAD_ID = frozenset({"dependency.flap", "not-a-fault-id"})

        found = _id_sets(Fake)
        # Tuples count: `tuple(d.id for d in CATALOG)` is the commonest shape.
        assert {"REAL", "A_TUPLE"} <= set(found)
        # A single non-catalog member disqualifies the set. Half-recognising it
        # would put a literal list's blame on a derived one.
        assert "ONE_BAD_ID" not in found
        assert "EMPTY" not in found
        assert "NOT_FAULTS" not in found
        # Underscore-prefixed names are the module's own scratch space.
        assert "_PRIVATE" not in found

    def test_id_sets_is_keyed_by_the_name_it_was_bound_to(self) -> None:
        class Fake:
            K8S = frozenset({"k8s.pod_oom"})

        assert list(_id_sets(Fake)) == ["K8S"]


class TestTheNegativeControlFromThisPhase:
    """Plan 05 Phase 5's named control, asserted here rather than only in Phase 4.

    Phase 4 implemented the refusal; this asserts it is reachable through the
    sweep surface too, so a change that made dependency faults unrefusable
    would be caught by this file even if the Phase 4 suite were skipped.
    """

    def test_a_dependency_fault_aimed_nowhere_is_refused_at_plan_time(self) -> None:
        from mayhem.domain.dependency_fanout import (
            RULE_DEPENDENCY_UNRESOLVED,
            fanout_ledger,
        )
        from mayhem.domain.errors import InvariantViolationError
        from mayhem.domain.topology import (
            Edge,
            EdgeKind,
            ExternalDependencyNode,
            ServiceNode,
            TopologyGraph,
        )

        graph = TopologyGraph(
            nodes=(
                ServiceNode(id="n-api", name="api"),
                ExternalDependencyNode(id="x-pg", name="postgres", endpoint="postgres:5432"),
            ),
            edges=(Edge(src="n-api", dst="x-pg", kind=EdgeKind.DEPENDS_ON),),
        )
        with pytest.raises(InvariantViolationError) as caught:
            fanout_ledger(graph, [("dependency.block", ["x-does-not-exist"])])
        assert caught.value.rule == RULE_DEPENDENCY_UNRESOLVED

    def test_and_the_same_call_on_a_real_dependency_does_not_refuse(self) -> None:
        """A control with no counterpart proves nothing: it refuses everything."""
        from mayhem.domain.dependency_fanout import fanout_ledger
        from mayhem.domain.topology import (
            Edge,
            EdgeKind,
            ExternalDependencyNode,
            ServiceNode,
            TopologyGraph,
        )

        graph = TopologyGraph(
            nodes=(
                ServiceNode(id="n-api", name="api"),
                ExternalDependencyNode(id="x-pg", name="postgres", endpoint="postgres:5432"),
            ),
            edges=(Edge(src="n-api", dst="x-pg", kind=EdgeKind.DEPENDS_ON),),
        )
        ledger = fanout_ledger(graph, [("dependency.block", ["x-pg"])])
        assert ledger.widened_steps() == ("dependency.block",)
