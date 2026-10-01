"""Coverage accounting over the plan-22 dimensions, run comparison, and change triggers.

What this module is
-------------------
Plan 22 phase 2. Three engines that sit on top of things that already exist and
change none of them:

* **Dimension accounting.** Plan 22 asks for coverage over
  ``Service x Dependency x Fault x Environment x Version``, with probe class and
  certification state as *attributes* of the cell rather than part of its key.
  The cell key itself is untouched: this module projects the five dimensions
  onto the existing :class:`mayhem.domain.coverage.CoverageCell`
  (``service -> target``, ``fault -> fault_kind``, ``environment ->
  execution_context``, ``version|dependency -> parameter_band``) and keeps the
  five-state transition rules in :mod:`mayhem.infra.coverage_repository`. The
  new dimension table stores the decomposition and points at the legacy
  ``m5_coverage`` row that owns the state. There is exactly one place a cell's
  state lives, so there is nothing to drift.
* **Comparison service.** Scoring a pair of pinned runs and opening a
  regression finding with exact run and evidence references. The comparability
  rule is *not* re-derived here — see "one answer to equivalence" below.
* **Trigger engine.** Gap 104 (continuous suites: nightly, post-deploy,
  post-infra-change, post-incident) and gap 106 (a broker version, a cache
  topology, or a database upgrade auto-*suggests* the relevant fault suites).
  Suggestions are advisory data. Nothing in this module executes anything.

Coverage is evidence, never catalog presence
--------------------------------------------
The single most important claim in this file is that **a cell counts as covered
only when something citable says so**. Three mechanisms enforce it, in
increasing order of how hard they are to defeat:

1. :class:`CoverageEvidenceKind` has exactly two members, ``EXECUTED`` and
   ``CERTIFIED``. ``catalog`` is not one of them, so a catalog sighting cannot
   be passed to :meth:`CoverageDimensionRepository.record_evidence` — not
   because the function checks and refuses, but because the value does not
   exist. Declaring cells is a different call
   (:meth:`~CoverageDimensionRepository.declare`) which writes a dimension row
   and no sighting at all.
2. The migration's ``coverage_dimension_sightings`` table carries a CHECK that
   requires every ``executed``/``certified`` row to name a run and a 64-char
   lowercase-hex evidence digest (and, for ``certified``, a certification
   reference), and every ``catalog`` row to name neither. A hand-written INSERT
   that tries to launder catalog presence into coverage fails at the storage
   layer, which is the place that survives a refactor of this module.
3. :attr:`DimensionCoverage.counted` requires *both* a covering state and a
   cited sighting. So even if some other writer sets ``m5_coverage.covered`` or
   ``state='passed'`` on a cell nobody ever ran, this module refuses to count
   it, and the report renders the cell as untested.

Catalog presence is still recorded — :meth:`declare` is how you say "we have
written a checkout journey" — and it shows up in
:attr:`CoverageReport.catalog_only_count`, which is a *different* number from
untested coverage. A declared cell is untested; a declared cell that has since
been executed is tested. Neither is ever "passing by absence".

One answer to equivalence
-------------------------
:meth:`ComparisonService.score` decides comparability with
:func:`mayhem.domain.comparison.equivalent_pins` and then *cross-checks*
:meth:`mayhem.domain.comparison.compare` against that verdict, refusing to
serve a report if the two disagree. A second implementation of the equivalence
rule in this file would be a second answer to "may these two runs be compared",
and two answers is exactly how a comparison service starts reporting a latency
delta across a policy change as a resilience regression. So: one function,
called, and a guard that says so if it ever stops agreeing.

A suggestion is not an execution
--------------------------------
:class:`SuiteSuggestion` is frozen data. :class:`TriggerEngine` holds a
registry and nothing else — no runner, no executor, no gate handle. The
``suite_suggestions`` table has ``advisory`` and ``requires_approval`` columns
whose CHECK admits no value but ``1``, and — deliberately — has **no**
``run_id``, ``status``, or ``started_at`` column at all, because the schema is
where "this only ever gets suggested" has to be written down. Execution of a
suggested suite goes through the ordinary candidate gate and policy gate; this
module does not touch them and cannot bypass them because it never reaches
them.

Certification state is an attribute, and claiming it needs evidence
--------------------------------------------------------------------
``certification_state`` rides on the cell rather than in its key, so a claim
that lapses does not orphan the evidence gathered under it. Setting it to
``certified``/``expiring`` without a certification reference is refused, and
recording ``CERTIFIED`` evidence requires a ``PASSED`` state: a certification
claim is a statement that a run passed on this cell, and accepting anything
weaker would let a lapsed claim be re-earned by asserting it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Literal

from mayhem.domain import comparison as comparison_domain
from mayhem.domain.catalog import all_definitions
from mayhem.domain.certification import CertificationState
from mayhem.domain.common import utc_now
from mayhem.domain.comparison import (
    ComparisonMetric,
    ComparisonOutcome,
    DeltaReport,
    RegressionFinding,
    RunReport,
    compare,
)
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest as canonical_digest
from mayhem.domain.journeys import JourneyProgram, authored_cells
from mayhem.infra.coverage_repository import SQLiteCoverageRepository

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from mayhem.infra.store import Store

__all__ = [
    "CACHE_COMPONENT",
    "CERTIFICATION_CELL_STATES",
    "COUNTING_EVIDENCE",
    "COVERAGE_VIEWS",
    "COVERING_STATES",
    "DATABASE_COMPONENT",
    "EVIDENCE_OUTCOME_STATES",
    "KNOWN_FAULT",
    "NO_SUITE_DESCRIPTION",
    "PLAN_22_SUITES",
    "PLATFORM_DOMAIN",
    "SIGHTING_KINDS",
    "UNCERTIFIED",
    "ChangeEvent",
    "ChangeEventKind",
    "ComparisonService",
    "CoverageDimensionRepository",
    "CoverageEvidenceKind",
    "CoverageReport",
    "CoverageSighting",
    "DimensionCell",
    "DimensionCoverage",
    "FaultSuite",
    "SuggestionRepository",
    "SuiteRegistry",
    "SuiteSuggestion",
    "TriggerEngine",
]

#: The states that mean "this cell was actually exercised". ``EXECUTED`` counts
#: because the plan counts executed evidence, and ``FAILED`` counts because
#: coverage is *tested*, not *passing* — a cell that failed was tested, and
#: reporting it as uncovered would hide the failure. ``PASSED`` counts too;
#: :attr:`CoverageReport.passed_count` is the number that says how many of them
#: actually passed.
COVERING_STATES: Final[frozenset[CellState]] = frozenset(
    {
        CellState.EXECUTED,
        CellState.PASSED,
        CellState.INCONCLUSIVE,
        CellState.FAILED,
    }
)

#: States a sighting may record as the outcome of an attempt. A sighting that
#: records an attempt must record what came of it: ``planned`` is an intention,
#: ``blocked``/``skipped`` are absences, and ``unknown`` is the absence of a
#: record.
EVIDENCE_OUTCOME_STATES: Final[frozenset[CellState]] = frozenset(
    {
        CellState.EXECUTED,
        CellState.PASSED,
        CellState.INCONCLUSIVE,
        CellState.FAILED,
    }
)

#: The cell-level certification vocabulary: "never claimed", plus every state
#: :class:`mayhem.domain.certification.CertificationState` defines.
UNCERTIFIED: Final[str] = "uncertified"
CERTIFICATION_CELL_STATES: Final[tuple[str, ...]] = (
    UNCERTIFIED,
    *(state.value for state in CertificationState),
)

#: Component name for a cache dependency, used by gap 106's cache-topology rule.
CACHE_COMPONENT: Final[str] = "cache"
#: Component name for a database dependency, used by gap 106's upgrade rule.
DATABASE_COMPONENT: Final[str] = "database"
#: The catalog failure domain that means "the platform underneath the service".
PLATFORM_DOMAIN: Final[str] = "platform"

#: Every dimension part is bounded; the unit separator is banned by
#: :func:`mayhem.domain.coverage.cell_key` and by the migration's CHECK, but a
#: value that would silently merge two cells is refused here with a message that
#: names the offending axis.
_MAX_DIMENSION_PART = 128
_UNIT_SEPARATOR = "\x1f"


# ═══════════════════════════════════════════════════════════════════════════
# The extended cell key
# ═══════════════════════════════════════════════════════════════════════════


def _dimension_part(axis: str, value: str) -> str:
    """Refuse a dimension value that is empty, oversized, or would merge cells."""
    if not value:
        raise InvariantViolationError(
            "coverage_service.empty_dimension",
            f"coverage dimension {axis!r} is empty: an empty axis is a cell every "
            "cell shares, which is how a per-service report becomes one number",
        )
    if value != value.strip():
        raise InvariantViolationError(
            "coverage_service.padded_dimension",
            f"coverage dimension {axis!r} is {value!r}: leading or trailing "
            "whitespace makes one logical cell two differently-keyed cells",
        )
    if _UNIT_SEPARATOR in value:
        raise InvariantViolationError(
            "coverage_service.separator_in_dimension",
            f"coverage dimension {axis!r} contains the unit separator: the cell "
            "key joins its parts with it, so this value would silently merge two "
            "cells into one key",
        )
    if len(value) > _MAX_DIMENSION_PART:
        raise InvariantViolationError(
            "coverage_service.oversized_dimension",
            f"coverage dimension {axis!r} is {len(value)} characters; the cell key "
            f"holds {value[:32]!r}... and anything longer is not an axis, it is a "
            "paragraph quoted where a name belongs",
        )
    return value


@dataclass(frozen=True, slots=True)
class CoverageDimensions:
    """The five key dimensions plan 22 adds: service, dependency, fault, environment, version.

    They are the *key*, so two runs that differ on any of them are two cells.
    That is the point: coverage for ``checkout`` on ``v2.4`` in ``staging`` says
    nothing about ``v2.5`` in ``prod``, and a report that merged them would be
    reporting one environment's resilience as another's.

    The version belongs in the key for the same reason
    :attr:`mayhem.domain.journeys.JourneyProgram.cells` puts it in the band:
    evidence gathered under a release has to stay addressable after the next
    one lands.
    """

    service: str
    dependency: str
    fault: str
    environment: str
    version: str

    def __post_init__(self) -> None:
        for axis in ("service", "dependency", "fault", "environment", "version"):
            _dimension_part(axis, getattr(self, axis))

    @property
    def band(self) -> str:
        """The ``parameter_band`` the legacy cell key carries: version|dependency.

        Named in this order because the version is the slower-moving of the two
        and a reader scanning a band wants to see it first.
        """
        return f"{self.version}|{self.dependency}"

    def as_tuple(self) -> tuple[str, str, str, str, str]:
        return (self.service, self.dependency, self.fault, self.environment, self.version)

    @classmethod
    def from_tuple(cls, row: tuple[str, str, str, str, str]) -> CoverageDimensions:
        return cls(*row)

    def to_dict(self) -> dict[str, str]:
        return {
            "service": self.service,
            "dependency": self.dependency,
            "fault": self.fault,
            "environment": self.environment,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class DimensionCell:
    """A dimension cell: the five key axes plus the two plan-22 attributes.

    ``probe_class`` and ``certification_state`` are *attributes* rather than key
    parts, exactly as plan 22 words it. The consequence is worth stating plainly:
    a cell probed by two different probe classes is one cell, and the recorded
    ``probe_class`` is the most recent one. The full history is not lost — it is
    in :class:`CoverageSighting`, one row per cited run — but a single cell row
    cannot answer "was this ever probed as a journey", only "was it probed most
    recently as one". Phase 3's views are where that distinction earns its keep.
    """

    dimensions: CoverageDimensions
    probe_class: str = "fault.probe"
    certification_state: str = UNCERTIFIED

    def __post_init__(self) -> None:
        if not self.probe_class.strip():
            raise InvariantViolationError(
                "coverage_service.blank_probe_class",
                "a dimension cell with no probe class cannot say how it was "
                "tested, and 'how it was tested' is half of what coverage means",
            )
        if self.certification_state not in CERTIFICATION_CELL_STATES:
            raise InvariantViolationError(
                "coverage_service.unknown_certification_state",
                f"certification state {self.certification_state!r} is not one of "
                f"{list(CERTIFICATION_CELL_STATES)}",
            )

    @property
    def service(self) -> str:
        return self.dimensions.service

    @property
    def dependency(self) -> str:
        return self.dimensions.dependency

    @property
    def fault(self) -> str:
        return self.dimensions.fault

    @property
    def environment(self) -> str:
        return self.dimensions.environment

    @property
    def version(self) -> str:
        return self.dimensions.version

    @property
    def coverage_cell(self) -> CoverageCell:
        """The existing four-part cell this dimension cell projects onto.

        Reusing :class:`~mayhem.domain.coverage.CoverageCell` rather than
        inventing a second key is what keeps the five-state accounting, the
        transition rules, and every existing reader of ``m5_coverage`` working
        unchanged.
        """
        return CoverageCell(
            target=self.dimensions.service,
            fault_kind=self.dimensions.fault,
            execution_context=self.dimensions.environment,
            parameter_band=self.dimensions.band,
        )

    @property
    def cell_key(self) -> str:
        return self.coverage_cell.key

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.dimensions.to_dict(),
            "probe_class": self.probe_class,
            "certification_state": self.certification_state,
            "cell_key": self.cell_key,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Evidence: the only thing that may make a cell covered
# ═══════════════════════════════════════════════════════════════════════════


class CoverageEvidenceKind(StrEnum):
    """The two kinds of sighting that count as coverage.

    There is no ``CATALOG`` member and that is the design, not an oversight.
    :meth:`CoverageDimensionRepository.record_evidence` takes one of these, so
    "a catalog entry counted as coverage" is not a case the method handles — it
    is a value that cannot be passed to it. Catalog presence is declared through
    :meth:`CoverageDimensionRepository.declare`, which records a dimension row
    and no sighting, leaving the cell :data:`~mayhem.domain.coverage.CellState.UNKNOWN`.
    """

    EXECUTED = "executed"
    CERTIFIED = "certified"


#: Every kind a sighting row may carry, including the non-counting one. Mirrors
#: the migration's CHECK constraint so the domain and the DDL can be compared
#: in a test without importing SQLite types upward.
SIGHTING_KINDS: Final[tuple[str, ...]] = (
    CoverageEvidenceKind.EXECUTED.value,
    CoverageEvidenceKind.CERTIFIED.value,
    "catalog",
)

#: The subset of :data:`SIGHTING_KINDS` that may make a cell count as covered.
COUNTING_EVIDENCE: Final[frozenset[str]] = frozenset(kind.value for kind in CoverageEvidenceKind)


@dataclass(frozen=True, slots=True)
class CoverageSighting:
    """One sighting of a cell: what kind, on which run, with which evidence.

    ``catalog`` sightings deliberately carry no ``run_id`` and no
    ``evidence_digest`` — the field types say so rather than carrying empty
    strings that a reader has to interpret. An evidence sighting carries both,
    because a claim without a citable bundle is not a claim about anything.
    """

    kind: str
    service: str
    dependency: str
    fault: str
    environment: str
    version: str
    run_id: str = ""
    evidence_digest: str = ""
    certification_ref: str = ""
    recorded_at: str = ""

    @property
    def counts(self) -> bool:
        """True when this sighting can make its cell count as covered."""
        return self.kind in COUNTING_EVIDENCE

    @property
    def citation(self) -> str:
        """``executed:run-7#0a1b2c3d`` — the handle a report or finding quotes."""
        if not self.counts:
            return f"{self.kind}:{self.service}/{self.dimensions_band}"
        return f"{self.kind}:{self.run_id}#{self.evidence_digest[:12]}"

    @property
    def dimensions_band(self) -> str:
        return f"{self.version}|{self.dependency}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "service": self.service,
            "dependency": self.dependency,
            "fault": self.fault,
            "environment": self.environment,
            "version": self.version,
            "run_id": self.run_id,
            "evidence_digest": self.evidence_digest,
            "certification_ref": self.certification_ref,
            "recorded_at": self.recorded_at,
            "counts": self.counts,
            "citation": self.citation,
        }


@dataclass(frozen=True, slots=True)
class DimensionCoverage:
    """One dimension cell's honest coverage state, with the evidence behind it.

    ``counted`` is the whole answer to "is this cell covered", and it is a
    conjunction: a covering state *and* at least one cited executed-or-certified
    sighting. Either half alone is insufficient — a state with no evidence is a
    claim, and evidence with no state is a run whose result was never recorded.
    """

    cell: DimensionCell
    state: CellState
    evidence_kinds: frozenset[str] = frozenset()
    catalog_presence: int = 0
    last_run: str = ""
    citations: tuple[str, ...] = ()

    @property
    def counted(self) -> bool:
        """True when this cell is covered, by evidence rather than by assertion."""
        return self.state in COVERING_STATES and bool(self.evidence_kinds & COUNTING_EVIDENCE)

    @property
    def tested(self) -> bool:
        """Alias of :attr:`counted` in the vocabulary a coverage report reads in."""
        return self.counted

    @property
    def untested(self) -> bool:
        """True when the cell exists but nothing about it has been executed."""
        return not self.counted

    @property
    def passed(self) -> bool:
        return self.counted and self.state is CellState.PASSED

    @property
    def catalog_only(self) -> bool:
        """True when the cell was declared and never executed — catalog presence."""
        return self.catalog_presence > 0 and not self.evidence_kinds & COUNTING_EVIDENCE

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.cell.to_dict(),
            "state": self.state.value,
            "counted": self.counted,
            "tested": self.tested,
            "passed": self.passed,
            "catalog_only": self.catalog_only,
            "catalog_presence": self.catalog_presence,
            "evidence_kinds": sorted(self.evidence_kinds),
            "last_run": self.last_run,
            "citations": list(self.citations),
        }


#: The plan-22 coverage views. Phase 3 renders them; phase 2 computes them.
COVERAGE_VIEWS: Final[tuple[str, ...]] = (
    "service",
    "dependency",
    "fault",
    "environment",
    "version",
    "probe_class",
    "certification_state",
)


def _view_service(item: DimensionCoverage) -> str:
    return item.cell.service


def _view_dependency(item: DimensionCoverage) -> str:
    return item.cell.dependency


def _view_fault(item: DimensionCoverage) -> str:
    return item.cell.fault


def _view_environment(item: DimensionCoverage) -> str:
    return item.cell.environment


def _view_version(item: DimensionCoverage) -> str:
    return item.cell.version


def _view_probe_class(item: DimensionCoverage) -> str:
    return item.cell.probe_class


def _view_certification_state(item: DimensionCoverage) -> str:
    return item.cell.certification_state


_COVERAGE_VIEW_ACCESSORS: Final[dict[str, Callable[[DimensionCoverage], str]]] = {
    "service": _view_service,
    "dependency": _view_dependency,
    "fault": _view_fault,
    "environment": _view_environment,
    "version": _view_version,
    "probe_class": _view_probe_class,
    "certification_state": _view_certification_state,
}


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """Aggregate coverage over dimension cells, with its denominator spelled out.

    Plan 22 phase 6's acceptance is "no dashboard shows a coverage percentage
    without defining its denominator on the same screen", so the denominator is
    a named property here rather than arithmetic buried in
    :attr:`fraction`. Blocked cells are excluded from it — a cell that safety
    policy forbids running is not something the team failed to test — and the
    count is exposed so a report can show what was excluded and why.
    """

    cells: tuple[DimensionCoverage, ...] = ()

    @property
    def total_count(self) -> int:
        return len(self.cells)

    @property
    def blocked_count(self) -> int:
        return sum(1 for item in self.cells if item.state is CellState.BLOCKED)

    @property
    def denominator(self) -> int:
        """Cells a coverage percentage is measured against: everything but blocked."""
        return self.total_count - self.blocked_count

    @property
    def tested_count(self) -> int:
        return sum(1 for item in self.cells if item.counted)

    @property
    def untested_count(self) -> int:
        return sum(1 for item in self.cells if item.untested)

    @property
    def passed_count(self) -> int:
        return sum(1 for item in self.cells if item.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for item in self.cells if item.state is CellState.FAILED)

    @property
    def catalog_only_count(self) -> int:
        """Declared-but-never-executed cells — the number catalog presence produces."""
        return sum(1 for item in self.cells if item.catalog_only)

    @property
    def fraction(self) -> float:
        """Covered over :attr:`denominator`. Zero when there is nothing to measure.

        Zero rather than one for an empty report: "we have measured nothing" and
        "everything is covered" must never render as the same number, and the
        first is the truth whenever there are no cells at all.
        """
        if self.denominator == 0:
            return 0.0
        return self.tested_count / self.denominator

    def untested_cells(self) -> tuple[DimensionCell, ...]:
        return tuple(item.cell for item in self.cells if item.untested)

    def catalog_only_cells(self) -> tuple[DimensionCell, ...]:
        return tuple(item.cell for item in self.cells if item.catalog_only)

    def coverage_for(self, cell: DimensionCell) -> DimensionCoverage | None:
        return next((item for item in self.cells if item.cell.cell_key == cell.cell_key), None)

    def group_by(self, view: str) -> dict[str, CoverageReport]:
        """Split the report by one of :data:`COVERAGE_VIEWS`."""
        accessor = _COVERAGE_VIEW_ACCESSORS.get(view)
        if accessor is None:
            raise InvariantViolationError(
                "coverage_service.unknown_coverage_view",
                f"{view!r} is not a plan-22 coverage view; the vocabulary is "
                f"{list(COVERAGE_VIEWS)}",
            )
        groups: dict[str, list[DimensionCoverage]] = {}
        for item in self.cells:
            groups.setdefault(accessor(item), []).append(item)
        return {name: CoverageReport(cells=tuple(items)) for name, items in sorted(groups.items())}

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_count": self.total_count,
            "denominator": self.denominator,
            "tested_count": self.tested_count,
            "untested_count": self.untested_count,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "blocked_count": self.blocked_count,
            "catalog_only_count": self.catalog_only_count,
            "fraction": self.fraction,
            "cells": [item.to_dict() for item in self.cells],
        }


# ═══════════════════════════════════════════════════════════════════════════
# The dimension repository: an extension of the existing accounting
# ═══════════════════════════════════════════════════════════════════════════


class CoverageDimensionRepository:
    """Plan-22 dimensions over :class:`SQLiteCoverageRepository`'s five-state accounting.

    Three tables, and one of them is not new: the coverage *state* still lives
    in ``m5_coverage`` and is only ever written through
    :class:`~mayhem.infra.coverage_repository.SQLiteCoverageRepository`, so the
    transition rules in :mod:`mayhem.domain.coverage` apply to the new
    dimensions without being restated. This class owns
    ``coverage_dimension_cells`` (the decomposition and the two attributes) and
    ``coverage_dimension_sightings`` (what has actually been observed).
    """

    def __init__(self, store: Store) -> None:
        self._store = store
        self._coverage = SQLiteCoverageRepository(store)

    # -- declaration: catalog presence, and nothing more -------------------

    def declare(self, cell: DimensionCell) -> None:
        """Record that ``cell`` is a cell we *claim* to test. It stays untested.

        This is the honest reading of "we have written a checkout journey for
        this service": the cell now exists, addressed by its five dimensions, and
        its state is whatever the accounting says it is — which, until something
        runs, is :data:`~mayhem.domain.coverage.CellState.UNKNOWN`. No sighting
        is written, so :attr:`CoverageReport.catalog_only_count` can tell this
        cell apart from one that was executed.
        """
        now = utc_now().isoformat()
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT INTO coverage_dimension_cells (
                    service, dependency, fault, environment, version,
                    probe_class, certification_state, cell_key, declared_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (service, dependency, fault, environment, version)
                DO UPDATE SET probe_class = excluded.probe_class, updated_at = excluded.updated_at
                """,
                (
                    *cell.dimensions.as_tuple(),
                    cell.probe_class,
                    cell.certification_state,
                    cell.cell_key,
                    now,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO coverage_dimension_sightings (
                    service, dependency, fault, environment, version,
                    kind, run_id, evidence_digest, certification_ref, recorded_at
                ) VALUES (?, ?, ?, ?, ?, 'catalog', '', '', '', ?)
                """,
                (*cell.dimensions.as_tuple(), now),
            )

    def declare_journey(
        self,
        program: JourneyProgram,
        environment: str,
    ) -> tuple[DimensionCell, ...]:
        """Declare every cell a journey program *claims*, all of them untested.

        The journey's own projection (:attr:`JourneyProgram.cells`) carries the
        probe class in the legacy fault axis and pins the version and step in the
        band, so it lands on its own addressable cells rather than on the
        servicexdependency grid. Nothing here advances a state: authoring a
        program proves the program was authored.
        """
        declared: list[DimensionCell] = []
        for cell in authored_cells(program):
            dimension_cell = DimensionCell(
                dimensions=CoverageDimensions(
                    service=cell.target,
                    dependency="none",
                    fault=cell.fault_kind,
                    environment=environment,
                    version=program.version,
                ),
                probe_class=cell.fault_kind,
            )
            self.declare(dimension_cell)
            declared.append(dimension_cell)
        return tuple(declared)

    # -- evidence: the only way a cell becomes covered --------------------

    def record_evidence(
        self,
        cell: DimensionCell,
        kind: CoverageEvidenceKind,
        *,
        run_id: str,
        evidence_digest: str,
        state: CellState = CellState.EXECUTED,
        certification_ref: str = "",
    ) -> None:
        """Record one cited sighting and advance the cell's state through it.

        ``kind`` is a :class:`CoverageEvidenceKind`, so ``catalog`` cannot be
        passed here. Everything else is checked because the alternative is a
        sighting that claims a run nobody can find:

        * ``run_id`` must be non-empty and ``evidence_digest`` must be a
          sha256-shaped lowercase hex digest — the same shape a
          :class:`mayhem.domain.comparison.RunPin` requires, because a coverage
          claim and a comparison citation are the same kind of claim;
        * ``state`` must be one of :data:`EVIDENCE_OUTCOME_STATES`: a sighting
          that records an attempt must record what came of it;
        * ``CERTIFIED`` evidence requires a ``certification_ref`` and a
          ``PASSED`` state, and it also sets the cell's certification attribute.

        Declaring the cell first is not required (the sighting is upserted), but
        a cell with no dimension row is invisible to :meth:`cells`, so callers
        that want it reported should :meth:`declare` it.
        """
        _require_evidence_citation(run_id, evidence_digest)
        if state not in EVIDENCE_OUTCOME_STATES:
            raise InvariantViolationError(
                "coverage_service.sighting_without_outcome",
                f"sighting recorded the cell as {state.value!r}: a sighting that "
                "records an attempt must record what came of it — planned is an "
                "intention, blocked and skipped are absences, and unknown is the "
                "absence of a record",
            )
        if kind is CoverageEvidenceKind.CERTIFIED:
            if not certification_ref.strip():
                raise InvariantViolationError(
                    "coverage_service.certification_without_reference",
                    f"certified evidence on {cell.service}/{cell.dependency}/"
                    f"{cell.fault} names no certification reference: a certification "
                    "claim has to point at the claim it is renewing, or a lapsed "
                    "one can be re-earned by asserting it",
                )
            if state is not CellState.PASSED:
                raise InvariantViolationError(
                    "coverage_service.certification_without_pass",
                    f"certified evidence recorded the cell as {state.value!r}: a "
                    "certification is a claim that the fault passed on this cell, "
                    "and accepting a weaker state would let a failing cell be "
                    "certified",
                )
        self.declare(cell)
        now = utc_now().isoformat()
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO coverage_dimension_sightings (
                    service, dependency, fault, environment, version,
                    kind, run_id, evidence_digest, certification_ref, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *cell.dimensions.as_tuple(),
                    kind.value,
                    run_id,
                    evidence_digest,
                    certification_ref,
                    now,
                ),
            )
        # The state goes through the existing repository, so the five-state
        # transition rules and the legacy ``covered`` column stay authoritative.
        self._coverage.record(cell.coverage_cell, state, run_id=run_id)
        if kind is CoverageEvidenceKind.CERTIFIED:
            self._write_certification_state(
                cell, CertificationState.CERTIFIED.value, certification_ref, now=now
            )
        elif self.stored_certification_state(cell) == UNCERTIFIED:
            # The cell exists but nobody has ever claimed a certification for it.
            # Executing it is not a certification, so the attribute moves to
            # "recorded, not yet certified" and no further — a run is not a
            # claim. Read the *stored* state, never the caller's copy: a caller
            # holding a default cell must not be able to age a live claim back to
            # pending by re-recording evidence.
            self._write_certification_state(cell, CertificationState.PENDING.value, "", now=now)

    def set_certification_state(
        self,
        cell: DimensionCell,
        state: str,
        *,
        certification_ref: str = "",
    ) -> None:
        """Move the certification *attribute* without claiming new coverage.

        ``certified`` and ``expiring`` require a reference — they are claims —
        while ``pending``/``stale``/``failed``/``incompatible`` do not, because
        ageing a claim or marking it failed is a statement about the claim, not
        about the cell.
        """
        if state not in CERTIFICATION_CELL_STATES:
            raise InvariantViolationError(
                "coverage_service.unknown_certification_state",
                f"certification state {state!r} is not one of {list(CERTIFICATION_CELL_STATES)}",
            )
        claims = (CertificationState.CERTIFIED.value, CertificationState.EXPIRING.value)
        if state in claims and not certification_ref.strip():
            raise InvariantViolationError(
                "coverage_service.certification_without_reference",
                f"moving the certification attribute of {cell.service}/"
                f"{cell.dependency}/{cell.fault} to {state!r} names no certification "
                "reference: the two states that mean 'this is certified' have to "
                "say which certification",
            )
        self.declare(cell)
        self._write_certification_state(cell, state, certification_ref)

    def stored_certification_state(self, cell: DimensionCell) -> str:
        """The certification attribute as persisted, or ``uncertified`` when absent."""
        rows = self._store.query(
            "SELECT certification_state FROM coverage_dimension_cells "
            "WHERE service = ? AND dependency = ? AND fault = ? AND environment = ? "
            "AND version = ?",
            cell.dimensions.as_tuple(),
        )
        if not rows:
            return UNCERTIFIED
        return str(dict(rows[0])["certification_state"])

    def _write_certification_state(
        self,
        cell: DimensionCell,
        state: str,
        certification_ref: str,
        *,
        now: str | None = None,
    ) -> None:
        stamp = now or utc_now().isoformat()
        with self._store.write() as conn:
            conn.execute(
                """
                UPDATE coverage_dimension_cells
                SET certification_state = ?, updated_at = ?
                WHERE service = ? AND dependency = ? AND fault = ?
                  AND environment = ? AND version = ?
                """,
                (state, stamp, *cell.dimensions.as_tuple()),
            )

    # -- reads -------------------------------------------------------------

    def declared_cells(self) -> tuple[DimensionCell, ...]:
        """Every dimension cell that has been declared, in dimension order."""
        rows = self._store.query(
            "SELECT service, dependency, fault, environment, version, probe_class, "
            "certification_state FROM coverage_dimension_cells "
            "ORDER BY service, dependency, fault, environment, version"
        )
        return tuple(
            DimensionCell(
                dimensions=CoverageDimensions.from_tuple(
                    (
                        str(dict(row)["service"]),
                        str(dict(row)["dependency"]),
                        str(dict(row)["fault"]),
                        str(dict(row)["environment"]),
                        str(dict(row)["version"]),
                    )
                ),
                probe_class=str(dict(row)["probe_class"]),
                certification_state=str(dict(row)["certification_state"]),
            )
            for row in rows
        )

    def sightings(self, cell: DimensionCell) -> tuple[CoverageSighting, ...]:
        """Every sighting of ``cell``, oldest first, as citable records."""
        rows = self._store.query(
            "SELECT kind, run_id, evidence_digest, certification_ref, recorded_at "
            "FROM coverage_dimension_sightings "
            "WHERE service = ? AND dependency = ? AND fault = ? AND environment = ? "
            "AND version = ? ORDER BY recorded_at, sighting_id",
            cell.dimensions.as_tuple(),
        )
        service, dependency, fault, environment, version = cell.dimensions.as_tuple()
        return tuple(
            CoverageSighting(
                kind=str(dict(row)["kind"]),
                service=service,
                dependency=dependency,
                fault=fault,
                environment=environment,
                version=version,
                run_id=str(dict(row)["run_id"]),
                evidence_digest=str(dict(row)["evidence_digest"]),
                certification_ref=str(dict(row)["certification_ref"]),
                recorded_at=str(dict(row)["recorded_at"]),
            )
            for row in rows
        )

    def coverage(self, cell: DimensionCell) -> DimensionCoverage:
        """One cell's honest coverage: state from the accounting, count from evidence."""
        stored = next(
            (item for item in self.declared_cells() if item.cell_key == cell.cell_key), None
        )
        resolved = stored if stored is not None else cell
        state = self._coverage.cell_state(cell.coverage_cell) or CellState.UNKNOWN
        sightings = self.sightings(cell)
        counted = tuple(item for item in sightings if item.counts)
        status = self._coverage.resilience_cells((cell.coverage_cell,))
        last_run = status[0].last_run if status else ""
        return DimensionCoverage(
            cell=resolved,
            state=state,
            evidence_kinds=frozenset(item.kind for item in counted),
            catalog_presence=sum(1 for item in sightings if item.kind == "catalog"),
            last_run=last_run,
            citations=tuple(item.citation for item in counted),
        )

    def report(self, cells: Iterable[DimensionCell] | None = None) -> CoverageReport:
        """Coverage over ``cells``, or over every declared cell."""
        selected = tuple(cells) if cells is not None else self.declared_cells()
        return CoverageReport(cells=tuple(self.coverage(cell) for cell in selected))

    def certified_cells(self) -> tuple[DimensionCoverage, ...]:
        """The certification view: cells whose certification attribute is live.

        ``expiring`` is included on purpose and flagged by its state rather than
        hidden: a claim close to expiry is still a claim, and a certification
        view that silently dropped the expiring ones would report a steady state
        nobody measured.
        """
        live = frozenset({CertificationState.CERTIFIED.value, CertificationState.EXPIRING.value})
        return tuple(item for item in self.report().cells if item.cell.certification_state in live)


def _require_evidence_citation(run_id: str, evidence_digest: str) -> None:
    """Refuse a sighting that cites nothing, or cites a malformed digest."""
    if not run_id.strip():
        raise InvariantViolationError(
            "coverage_service.uncited_evidence",
            "a coverage sighting must name the run that produced it: an uncited "
            "sighting is an assertion wearing an evidence reference's clothes",
        )
    stripped = evidence_digest.strip()
    if len(stripped) != 64 or any(char not in "0123456789abcdef" for char in stripped):
        raise InvariantViolationError(
            "coverage_service.malformed_evidence_digest",
            f"evidence digest {evidence_digest!r} is not a sha256 hex digest: a "
            "coverage claim is citable, and 'trust me' is not a citation",
        )


# ═══════════════════════════════════════════════════════════════════════════
# Comparison service
# ═══════════════════════════════════════════════════════════════════════════


class ComparisonService:
    """Scores pinned run pairs and opens regression findings, with exact citations.

    A run's measurements are sealed: :meth:`record_run` refuses to overwrite a
    stored run with a different evidence digest, because a comparison that
    silently re-reads a run's numbers after the fact is a comparison nobody can
    re-derive. Re-recording the identical report is a no-op.

    The comparability rule lives in :mod:`mayhem.domain.comparison` and is
    called, never restated — see the module docstring.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    # -- run reports -------------------------------------------------------

    def record_run(self, report: RunReport) -> None:
        """Persist one run's measurements under its run id."""
        pin = report.pin
        equivalence_key = json.dumps(list(pin.equivalence_key))
        # ``RunReport.to_dict()`` is a *report* payload: it adds derived keys
        # such as the pin's label and would not validate back into a model. The
        # round-trippable serialization is ``model_dump``, and the derived facts
        # are stored as their own columns instead.
        payload = json.dumps(report.model_dump(mode="json"), sort_keys=True)
        with self._store.write() as conn:
            existing = conn.execute(
                "SELECT evidence_digest, report_json FROM comparison_runs WHERE run_id = ?",
                (pin.run_id,),
            ).fetchone()
            if existing is not None:
                row = dict(existing)
                if str(row["evidence_digest"]) == pin.evidence_digest:
                    return
                raise InvariantViolationError(
                    "comparison_service.run_resealed",
                    f"run {pin.run_id!r} is already stored against evidence "
                    f"{str(row['evidence_digest'])[:12]} and cannot be re-recorded "
                    f"against {pin.evidence_digest[:12]}: a sealed run's measurements "
                    "are the ones its evidence bundle contains, and swapping them "
                    "would make every comparison of it unre-derivable",
                )
            conn.execute(
                """
                INSERT INTO comparison_runs (
                    run_id, experiment, release, environment, equivalence_key,
                    evidence_digest, report_json, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pin.run_id,
                    pin.experiment,
                    pin.release,
                    pin.environment,
                    equivalence_key,
                    pin.evidence_digest,
                    payload,
                    utc_now().isoformat(),
                ),
            )

    def run(self, run_id: str) -> RunReport | None:
        """Load one stored run report, or ``None`` when it was never recorded."""
        rows = self._store.query(
            "SELECT report_json FROM comparison_runs WHERE run_id = ?", (run_id,)
        )
        if not rows:
            return None
        payload = json.loads(str(dict(rows[0])["report_json"]))
        return RunReport.model_validate(payload)

    def runs(self) -> tuple[str, ...]:
        """Every stored run id, in recording order."""
        rows = self._store.query("SELECT run_id FROM comparison_runs ORDER BY recorded_at")
        return tuple(str(dict(row)["run_id"]) for row in rows)

    def _require_run(self, run_id: str) -> RunReport:
        report = self.run(run_id)
        if report is None:
            raise InvariantViolationError(
                "comparison_service.unknown_run",
                f"run {run_id!r} has no stored measurements: a comparison is made "
                "between two runs this store can produce a citation for, not "
                "between two ids",
            )
        return report

    # -- scoring -----------------------------------------------------------

    def equivalent(self, baseline_run: str, candidate_run: str) -> bool:
        """Whether two stored runs may be compared at all.

        A one-line delegation to :func:`mayhem.domain.comparison.equivalent_pins`
        so that "may these two runs be compared" has exactly one answer
        everywhere in the system.
        """
        return comparison_domain.equivalent_pins(
            self._require_run(baseline_run).pin,
            self._require_run(candidate_run).pin,
        )

    def score(
        self,
        baseline: RunReport,
        candidate: RunReport,
        metrics: Sequence[ComparisonMetric],
    ) -> DeltaReport:
        """Grade one run pair, refusing anything the equivalence rule refuses.

        :func:`mayhem.domain.comparison.compare` produces the report;
        :func:`mayhem.domain.comparison.equivalent_pins` decides whether it was
        allowed to. If the two disagree the pair is refused rather than served:
        the two functions are the same rule, and a disagreement means one of them
        has drifted from the intended semantics, which is exactly the moment to
        stop rather than pick a winner.
        """
        report = compare(baseline, candidate, metrics)
        comparable = comparison_domain.equivalent_pins(baseline.pin, candidate.pin)
        refused = report.outcome is ComparisonOutcome.INCOMPARABLE
        if comparable is refused:
            raise InvariantViolationError(
                "comparison_service.equivalence_disagreement",
                f"equivalent_pins says runs {baseline.pin.run_id!r} and "
                f"{candidate.pin.run_id!r} are {'comparable' if comparable else 'not comparable'}, "
                f"but compare() returned a {report.outcome.value} report: the "
                "equivalence rule must have one answer, and two disagreeing "
                "answers is how a policy change gets reported as a resilience "
                "regression",
            )
        return report

    def compare_runs(
        self,
        baseline_run: str,
        candidate_run: str,
        metrics: Sequence[ComparisonMetric],
    ) -> DeltaReport:
        """Score two *stored* runs by id."""
        return self.score(
            self._require_run(baseline_run),
            self._require_run(candidate_run),
            metrics,
        )

    # -- findings ----------------------------------------------------------

    def open_finding(
        self,
        finding_id: str,
        baseline_run: str,
        candidate_run: str,
        metrics: Sequence[ComparisonMetric],
        summary: str,
    ) -> RegressionFinding:
        """Compare two stored runs and open a regression finding from the result.

        Only a graded regression survives: :class:`RegressionFinding` refuses any
        other outcome, and the migration's CHECK on ``regression_findings``
        admits no outcome but ``regressed``. The persisted row carries both run
        ids and both evidence digests, so the finding cites exactly what it
        compared and a reviewer can re-derive the numbers from the bundles alone.
        """
        report = self.compare_runs(baseline_run, candidate_run, metrics)
        finding = RegressionFinding(
            finding_id=finding_id,
            report=report,
            summary=summary,
        )
        self.record_finding(finding)
        return finding

    def record_finding(self, finding: RegressionFinding) -> None:
        """Persist a regression finding with its exact run and evidence references."""
        report = finding.report
        payload = json.dumps(finding.to_dict(), sort_keys=True)
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO regression_findings (
                    finding_id, experiment, baseline_release, candidate_release,
                    baseline_run, candidate_run, baseline_evidence_digest,
                    candidate_evidence_digest, outcome, regressed_metrics,
                    finding_json, opened_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.finding_id,
                    report.baseline.experiment,
                    report.baseline.release,
                    report.candidate.release,
                    report.baseline.run_id,
                    report.candidate.run_id,
                    report.baseline.evidence_digest,
                    report.candidate.evidence_digest,
                    report.outcome.value,
                    json.dumps(list(finding.regressed_metrics)),
                    payload,
                    utc_now().isoformat(),
                ),
            )

    def findings(self) -> tuple[dict[str, Any], ...]:
        """Every stored finding, oldest first, as its persisted citation fields."""
        rows = self._store.query(
            "SELECT finding_id, experiment, baseline_release, candidate_release, "
            "baseline_run, candidate_run, baseline_evidence_digest, "
            "candidate_evidence_digest, outcome, regressed_metrics, finding_json, "
            "opened_at FROM regression_findings ORDER BY opened_at, finding_id"
        )
        return tuple(dict(row) for row in rows)

    def finding(self, finding_id: str) -> dict[str, Any] | None:
        rows = self._store.query(
            "SELECT finding_id, experiment, baseline_release, candidate_release, "
            "baseline_run, candidate_run, baseline_evidence_digest, "
            "candidate_evidence_digest, outcome, regressed_metrics, finding_json, "
            "opened_at FROM regression_findings WHERE finding_id = ?",
            (finding_id,),
        )
        return dict(rows[0]) if rows else None


# ═══════════════════════════════════════════════════════════════════════════
# Trigger engine (gaps 104, 106)
# ═══════════════════════════════════════════════════════════════════════════


class ChangeEventKind(StrEnum):
    """What happened, in the vocabulary gap 104 and gap 106 name.

    The first four are gap 104's continuous-testing triggers. The last three are
    gap 106's dependency-change triggers, kept as distinct kinds rather than one
    ``dependency_change`` with a string field: a cache topology change and a
    broker version change select *different* suites, and collapsing them into one
    kind with a discriminator means the discrimination moves from the type system
    into a string comparison somebody eventually gets wrong.
    """

    NIGHTLY = "nightly"
    POST_DEPLOY = "post_deploy"
    POST_INFRA_CHANGE = "post_infra_change"
    POST_INCIDENT = "post_incident"
    DEPENDENCY_VERSION_CHANGE = "dependency_version_change"
    CACHE_TOPOLOGY_CHANGE = "cache_topology_change"
    DATABASE_UPGRADE = "database_upgrade"


#: The event kinds that must carry a version: a version change that does not name
#: a version is not a change anybody can scope suites to.
_VERSIONED_EVENTS: Final[frozenset[ChangeEventKind]] = frozenset(
    {ChangeEventKind.DEPENDENCY_VERSION_CHANGE, ChangeEventKind.DATABASE_UPGRADE}
)

#: The event kinds that must carry a failure domain. A post-incident trigger
#: scoped to nothing would re-run the whole landscape, which is the one thing
#: "continuous testing" must not mean.
_DOMAIN_SCOPED_EVENTS: Final[frozenset[ChangeEventKind]] = frozenset(
    {ChangeEventKind.POST_INCIDENT, ChangeEventKind.POST_INFRA_CHANGE}
)


@dataclass(frozen=True, slots=True)
class ChangeEvent:
    """Something that happened which should make somebody look at a fault suite.

    An event that cannot be scoped is refused rather than widened. A nightly
    window is scoped to a subject; a dependency version change is scoped to a
    version; an incident is scoped to a failure domain. The refusals are the
    point: "run everything" is the failure mode this whole engine exists to
    avoid, and the cheapest way to prevent it is to make an unscoped event
    unrepresentable.
    """

    kind: ChangeEventKind
    subject: str
    detail: str = ""
    version: str = ""
    failure_domain: str = ""
    occurred_at: str = ""
    attributes: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.subject.strip():
            raise InvariantViolationError(
                "trigger.unscoped_change_event",
                f"a {self.kind.value} event names no subject: an event that cannot "
                "say what changed cannot say which suites to look at",
            )
        if self.subject != self.subject.strip():
            raise InvariantViolationError(
                "trigger.padded_subject",
                f"change-event subject is {self.subject!r}: padded subjects silently "
                "miss a component's suites and read as 'nothing to suggest'",
            )
        if self.kind in _VERSIONED_EVENTS and not self.version.strip():
            raise InvariantViolationError(
                "trigger.version_change_without_version",
                f"a {self.kind.value} event on {self.subject!r} names no version: the "
                "suite selection for a version change is scoped to what moved, and "
                "with no version there is nothing that moved",
            )
        if self.kind in _DOMAIN_SCOPED_EVENTS and not self.failure_domain.strip():
            raise InvariantViolationError(
                "trigger.unscoped_incident",
                f"a {self.kind.value} event on {self.subject!r} names no failure "
                "domain: re-running the whole landscape is not continuous testing, "
                "it is no continuous testing",
            )

    @property
    def component(self) -> str:
        """The subject, lowercased — the component name a suite is tagged with."""
        return self.subject.lower()

    def fingerprint(self) -> str:
        """Content digest of the event, so the same event yields the same suggestion id."""
        return canonical_digest(
            {
                "kind": self.kind.value,
                "subject": self.subject,
                "detail": self.detail,
                "version": self.version,
                "failure_domain": self.failure_domain,
                "occurred_at": self.occurred_at,
                "attributes": dict(self.attributes),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "subject": self.subject,
            "detail": self.detail,
            "version": self.version,
            "failure_domain": self.failure_domain,
            "occurred_at": self.occurred_at,
            "attributes": dict(self.attributes),
            "fingerprint": self.fingerprint(),
        }


@dataclass(frozen=True, slots=True)
class FaultSuite:
    """A named, tagged group of catalog faults plus the component it exercises.

    Fault kinds are validated against the real catalog at registry construction,
    so a suite cannot name a fault that does not exist — which would otherwise
    surface as a suite that suggests a fault nothing can execute.

    ``failure_domains`` is *derived* from the catalog rather than declared, so a
    suite cannot claim to cover a platform failure while naming only network
    faults.
    """

    name: str
    description: str
    fault_kinds: tuple[str, ...]
    components: tuple[str, ...] = ()
    continuous: bool = False
    probe_class: str = "fault.probe"

    @property
    def failure_domains(self) -> frozenset[str]:
        """The catalog failure domains this suite's faults belong to."""
        definitions = {definition.id: definition for definition in all_definitions()}
        return frozenset(
            str(definition.failure_domain.value)
            for fault in self.fault_kinds
            if (definition := definitions.get(fault)) is not None
            and definition.failure_domain is not None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "fault_kinds": list(self.fault_kinds),
            "components": list(self.components),
            "continuous": self.continuous,
            "probe_class": self.probe_class,
            "failure_domains": sorted(self.failure_domains),
        }


class SuiteRegistry:
    """The suites an engine may suggest, validated against the real catalog.

    Validating at construction rather than at suggestion time is deliberate: a
    registry holding a typo is a registry whose suggestions are wrong every
    night, quietly, and the operator never learns it because the suggestion is
    well-formed.
    """

    def __init__(self, suites: Iterable[FaultSuite]) -> None:
        collected = tuple(suites)
        if not collected:
            raise InvariantViolationError(
                "trigger.empty_registry",
                "a suite registry with no suites suggests nothing for every event, "
                "which reads as 'nothing to look at' rather than 'nothing configured'",
            )
        known = {definition.id for definition in all_definitions()}
        seen: set[str] = set()
        for suite in collected:
            if not suite.name.strip():
                raise InvariantViolationError(
                    "trigger.unnamed_suite", "every fault suite must have a name"
                )
            if suite.name in seen:
                raise InvariantViolationError(
                    "trigger.duplicate_suite",
                    f"suite {suite.name!r} is registered twice: a suite name addresses "
                    "one suite, and a duplicate makes a suggestion ambiguous",
                )
            seen.add(suite.name)
            if not suite.fault_kinds:
                raise InvariantViolationError(
                    "trigger.suite_without_faults",
                    f"suite {suite.name!r} names no fault kinds: it would suggest "
                    "running nothing, dressed as a suite",
                )
            unknown = sorted(set(suite.fault_kinds) - known)
            if unknown:
                raise InvariantViolationError(
                    "trigger.unknown_fault_kind",
                    f"suite {suite.name!r} names fault kinds that are not in the "
                    f"catalog: {unknown}. A suggestion for a fault nothing can "
                    "execute is a suggestion an operator will trust and cannot run.",
                )
        self._suites = collected

    @property
    def suites(self) -> tuple[FaultSuite, ...]:
        return self._suites

    def get(self, name: str) -> FaultSuite | None:
        return next((suite for suite in self._suites if suite.name == name), None)

    def select(self, event: ChangeEvent) -> tuple[FaultSuite, ...]:
        """The suites this event selects, in registry order.

        One predicate per event kind, and each names *why*:

        * ``nightly`` — the continuous suites, and only those. A suite nobody
          opted into continuous testing does not become nightly by existing.
        * ``post_deploy`` — everything continuous (a deploy is a reason to
          re-establish the baseline) plus anything tagged with the deployed
          component, which is how a service's own dependency suites join in.
        * ``post_infra_change`` / ``post_incident`` — scoped by failure domain.
          Post-infra-change selects the platform domain, because that is what an
          infrastructure change is; post-incident selects the domain the incident
          happened in, which is the whole reason an incident trigger exists.
        * ``dependency_version_change`` — suites tagged with the dependency.
          Gap 106's first case, and the only kind where an unmatched component is
          an expected outcome rather than a bug.
        * ``cache_topology_change`` / ``database_upgrade`` — the cache and
          database component tags respectively. A topology change and a version
          change select on *what kind of thing* changed, not on its name, so
          "redis" and "valkey" and "memcached" all land on the same suites.
        """
        component = event.component
        domain = event.failure_domain.strip().lower()
        selected: list[FaultSuite] = []
        for suite in self._suites:
            if self._matches(event.kind, suite, component, domain):
                selected.append(suite)
        return tuple(selected)

    @staticmethod
    def _matches(
        kind: ChangeEventKind,
        suite: FaultSuite,
        component: str,
        domain: str,
    ) -> bool:
        tagged = component in suite.components
        domains = suite.failure_domains
        if kind is ChangeEventKind.NIGHTLY:
            matched = suite.continuous
        elif kind is ChangeEventKind.POST_DEPLOY:
            matched = suite.continuous or tagged
        elif kind is ChangeEventKind.POST_INFRA_CHANGE:
            matched = PLATFORM_DOMAIN in domains
        elif kind is ChangeEventKind.POST_INCIDENT:
            matched = domain in domains
        elif kind is ChangeEventKind.DEPENDENCY_VERSION_CHANGE:
            matched = tagged
        elif kind is ChangeEventKind.CACHE_TOPOLOGY_CHANGE:
            matched = CACHE_COMPONENT in suite.components
        else:
            # ``DATABASE_UPGRADE`` is the last member; naming it keeps the change
            # loud if a future kind is added without a rule here.
            matched = DATABASE_COMPONENT in suite.components
        return matched


#: The plan-22 reference registry. Every fault kind here is a real catalog id and
#: the registry validates that at import time, so this table cannot rot into
#: suggesting faults that stopped existing.
PLAN_22_SUITES: Final[SuiteRegistry] = SuiteRegistry(
    (
        FaultSuite(
            name="service.availability",
            description=(
                "Does the service come back? Process kill/crash-loop and upstream "
                "timeouts are the failure an availability claim is actually about."
            ),
            fault_kinds=(
                "process.kill",
                "process.crash_loop",
                "process.stop",
                "node.service_stop",
                "http.upstream_timeout",
            ),
            components=("service",),
            continuous=True,
        ),
        FaultSuite(
            name="dependency.cache",
            description=(
                "Cache dependency behaviour: a cache that evicts, flaps or starts "
                "answering slowly must not become the service's latency."
            ),
            fault_kinds=(
                "dependency.timeout",
                "dependency.flap",
                "dependency.circuit_open",
                "dependency.rate_limit",
                "net.latency",
            ),
            components=(
                CACHE_COMPONENT,
                "redis",
                "valkey",
                "memcached",
            ),
            continuous=True,
        ),
        FaultSuite(
            name="dependency.broker",
            description=(
                "Broker dependency behaviour: partition, blocked producer, consumer "
                "half-open sockets, and the rate limit that answers them."
            ),
            fault_kinds=(
                "dependency.block",
                "dependency.connection_refuse",
                "dependency.timeout",
                "dependency.rate_limit",
                "net.tcp_half_open",
            ),
            components=("broker", "kafka", "rabbitmq", "nats", "pulsar"),
            continuous=True,
        ),
        FaultSuite(
            name="dependency.database",
            description=(
                "Database dependency behaviour across an upgrade: slow queries, "
                "connection exhaustion, query errors and the write path."
            ),
            fault_kinds=(
                "db.slow_query",
                "db.connection_exhaust",
                "db.query_error",
                "dependency.timeout",
                "fs.write_delay",
            ),
            components=(
                DATABASE_COMPONENT,
                "postgres",
                "postgresql",
                "mysql",
                "mariadb",
            ),
            continuous=True,
        ),
        FaultSuite(
            name="network.edge",
            description=(
                "The network between here and the dependency: latency, loss, "
                "partition and resets, plus the DNS the connection starts with."
            ),
            fault_kinds=(
                "net.latency",
                "net.packet_loss",
                "net.partition",
                "net.connection_reset",
                "dns.timeout",
            ),
            continuous=True,
        ),
        FaultSuite(
            name="platform.node",
            description=(
                "What the platform takes away underneath a healthy service: drained "
                "nodes, lost nodes, partitioned nodes, and pods killed for memory."
            ),
            fault_kinds=(
                "k8s.node_drain",
                "k8s.node_not_ready",
                "k8s.node_network_partition",
                "k8s.pod_oom",
                "k8s.eviction_block",
            ),
            continuous=True,
        ),
        FaultSuite(
            name="journey.checkout",
            description=(
                "The synthetic checkout journey's dependencies, exercised as a "
                "customer flow rather than as components."
            ),
            fault_kinds=(
                "http.latency",
                "http.error_injection",
                "dependency.timeout",
                "http.upstream_timeout",
            ),
            components=("journey",),
            continuous=True,
            probe_class="synthetic.journey",
        ),
    )
)


@dataclass(frozen=True, slots=True)
class SuiteSuggestion:
    """Advisory data: which suites a change event points at, and why.

    Three fields are typed as :data:`~typing.Literal` ``True`` so the claim is
    structural. ``advisory`` says this is a suggestion; ``requires_approval``
    says a human must say yes; ``gates_apply`` says the ordinary policy and
    candidate gates still stand between this and a run. There is no method on
    this class that runs anything, and no runner, executor or gate handle on
    :class:`TriggerEngine`, so there is no path from a suggestion to execution
    that does not go through code this module does not contain.
    """

    suggestion_id: str
    event: ChangeEvent
    suites: tuple[FaultSuite, ...]
    rationale: str
    advisory: Literal[True] = True
    requires_approval: Literal[True] = True
    gates_apply: Literal[True] = True

    def __post_init__(self) -> None:
        if not self.suggestion_id.strip():
            raise InvariantViolationError(
                "trigger.unnamed_suggestion",
                "a suite suggestion must have an id: an uncited suggestion cannot "
                "be found again, and a suggestion nobody can find was not reviewed",
            )
        if not self.suites:
            raise InvariantViolationError(
                "trigger.empty_suggestion",
                f"suggestion {self.suggestion_id!r} suggests no suites: 'nothing to "
                "look at' and 'nothing matched' are different answers and this one "
                "is dressed as the first",
            )
        if not self.rationale.strip():
            raise InvariantViolationError(
                "trigger.unexplained_suggestion",
                f"suggestion {self.suggestion_id!r} gives no rationale: a bare list "
                "of suite names is not something an operator can disagree with",
            )

    @property
    def suite_names(self) -> tuple[str, ...]:
        return tuple(suite.name for suite in self.suites)

    @property
    def fault_kinds(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(fault for suite in self.suites for fault in suite.fault_kinds))

    def to_dict(self) -> dict[str, Any]:
        return {
            "suggestion_id": self.suggestion_id,
            "event": self.event.to_dict(),
            "suite_names": list(self.suite_names),
            "suites": [suite.to_dict() for suite in self.suites],
            "fault_kinds": list(self.fault_kinds),
            "rationale": self.rationale,
            "advisory": self.advisory,
            "requires_approval": self.requires_approval,
            "gates_apply": self.gates_apply,
        }


class TriggerEngine:
    """Maps change events to suggested fault suites. It runs nothing.

    The engine holds a registry and two pure functions. Everything about it is
    readable in one screen, which is the point: a reviewer asking "can a trigger
    start a run?" can answer by reading the class rather than by tracing a call
    graph into an executor this module does not import.
    """

    def __init__(self, registry: SuiteRegistry = PLAN_22_SUITES) -> None:
        self._registry = registry

    @property
    def registry(self) -> SuiteRegistry:
        return self._registry

    def suites_for(self, event: ChangeEvent) -> tuple[FaultSuite, ...]:
        """The suites ``event`` selects. Empty means nothing is tagged for it."""
        return self._registry.select(event)

    def suggest(self, event: ChangeEvent) -> SuiteSuggestion:
        """Produce the advisory suggestion for ``event``.

        A change event matching no suite is not an error: the component may
        simply not have suites yet, and inventing one here would mean this module
        owned the catalog. :meth:`_suggest_none` states the absence explicitly so
        a caller never has to read "no suites" as "everything is fine".
        """
        suites = self.suites_for(event)
        if not suites:
            return self._suggest_none(event)
        suggestion_id = (
            "sug-"
            + canonical_digest(
                {"event": event.fingerprint(), "suites": [suite.name for suite in suites]}
            )[:16]
        )
        scope = f" on {event.subject}" + (f" {event.version}" if event.version else "")
        rationale = (
            f"a {event.kind.value} event{scope} selects "
            f"{len(suites)} suite(s) ({', '.join(suite.name for suite in suites)}); "
            "advisory only — a human approves, the policy and candidate gates "
            "still apply, and nothing here runs"
        )
        return SuiteSuggestion(
            suggestion_id=suggestion_id,
            event=event,
            suites=suites,
            rationale=rationale,
        )

    @staticmethod
    def _suggest_none(event: ChangeEvent) -> SuiteSuggestion:
        """The explicit "nothing is tagged for this" answer.

        Still a suggestion, still advisory, still requiring approval: an event
        whose component has no suites is a coverage gap somebody should see, not
        a silently empty result.
        """
        suggestion_id = "sug-" + canonical_digest({"event": event.fingerprint(), "suites": []})[:16]
        rationale = (
            f"a {event.kind.value} event on {event.subject} matches no registered "
            "fault suite: either the component has no suites yet or the registry "
            "has drifted from the landscape. This is a coverage gap, not a clean "
            "result — advisory only, and nothing here runs."
        )
        return SuiteSuggestion(
            suggestion_id=suggestion_id,
            event=event,
            suites=(
                FaultSuite(
                    name="none.registered",
                    description=NO_SUITE_DESCRIPTION,
                    fault_kinds=(KNOWN_FAULT,),
                    continuous=False,
                ),
            ),
            rationale=rationale,
        )

    def suggestions(self, events: Iterable[ChangeEvent]) -> tuple[SuiteSuggestion, ...]:
        """One suggestion per event, in the order given."""
        return tuple(self.suggest(event) for event in events)


#: The fault kind :meth:`TriggerEngine._suggest_none` names so the "nothing is
#: tagged" answer is still structurally a suite. It is a real catalog id and it
#: is never executed: the suggestion is advisory and the suite is named
#: ``none.registered``, so a report rendering the list says "no suites" instead
#: of naming a fault an operator might think somebody was supposed to run.
KNOWN_FAULT: Final[str] = "dependency.timeout"
NO_SUITE_DESCRIPTION: Final[str] = "no fault suite is registered for this change event"


class SuggestionRepository:
    """Persistence for advisory suggestions.

    The schema is where "this only ever gets suggested" is written down:
    ``suite_suggestions`` has CHECKs admitting no value but ``1`` for
    ``advisory`` and ``requires_approval``, and — deliberately — has no
    ``run_id``, ``status``, or ``started_at`` column. There is nowhere for a
    suggestion to record that it ran, because it never does.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def record(self, suggestion: SuiteSuggestion) -> None:
        """Persist one advisory suggestion. Re-recording the same one is a no-op."""
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO suite_suggestions (
                    suggestion_id, event_kind, event_subject, event_fingerprint,
                    suites_json, fault_kinds_json, rationale, advisory,
                    requires_approval, suggested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, ?)
                """,
                (
                    suggestion.suggestion_id,
                    suggestion.event.kind.value,
                    suggestion.event.subject,
                    suggestion.event.fingerprint(),
                    json.dumps(list(suggestion.suite_names)),
                    json.dumps(list(suggestion.fault_kinds)),
                    suggestion.rationale,
                    utc_now().isoformat(),
                ),
            )

    def suggestions(self) -> tuple[dict[str, Any], ...]:
        """Every stored suggestion, oldest first."""
        rows = self._store.query(
            "SELECT suggestion_id, event_kind, event_subject, event_fingerprint, "
            "suites_json, fault_kinds_json, rationale, advisory, requires_approval, "
            "suggested_at FROM suite_suggestions ORDER BY suggested_at, suggestion_id"
        )
        return tuple(dict(row) for row in rows)

    def suggestion(self, suggestion_id: str) -> dict[str, Any] | None:
        rows = self._store.query(
            "SELECT suggestion_id, event_kind, event_subject, event_fingerprint, "
            "suites_json, fault_kinds_json, rationale, advisory, requires_approval, "
            "suggested_at FROM suite_suggestions WHERE suggestion_id = ?",
            (suggestion_id,),
        )
        return dict(rows[0]) if rows else None

    def recent(
        self,
        kind: ChangeEventKind,
        *,
        since: str,
        limit: int = 20,
    ) -> tuple[dict[str, Any], ...]:
        """Suggestions of ``kind`` recorded at or after ``since`` — the triage queue's feed.

        Read-only and advisory: the queue it feeds is a human's. Nothing here
        turns a suggestion into a run.
        """
        rows = self._store.query(
            "SELECT suggestion_id, event_kind, event_subject, event_fingerprint, "
            "suites_json, fault_kinds_json, rationale, advisory, requires_approval, "
            "suggested_at FROM suite_suggestions "
            "WHERE event_kind = ? AND suggested_at >= ? "
            "ORDER BY suggested_at DESC, suggestion_id LIMIT ?",
            (kind.value, since, limit),
        )
        return tuple(dict(row) for row in rows)
