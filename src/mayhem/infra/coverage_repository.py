"""SQLite-backed coverage accounting (ADR-M5-3, M5 Phase 5.2).

A recorded ``Outcome`` marks the run's coverage cell as *seen*. Marking the
same cell again (a re-run) is idempotent — ``INSERT OR IGNORE`` on the primary
key means re-running a cell never double-counts. Maniac can then enumerate the
``UNKNOWN`` cells of a landscape (cells not yet covered) to prioritize coverage
gain.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from mayhem.domain.coverage import (
    CoverageCell,
    CoverageRecord,
    CoverageSummary,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from mayhem.infra.store import Store


class SQLiteCoverageRepository:
    """Persists seen coverage cells over the ``m5_coverage`` table."""

    def __init__(self, store: Store) -> None:
        self._store = store

    def mark_seen(
        self,
        cell: CoverageCell,
        run_id: str,
        *,
        extra: dict[str, object] | None = None,
    ) -> None:
        """Record that ``cell`` was observed by ``run_id``.

        Idempotent per cell: re-running the same cell does not double-count;
        ``CREATE TABLE ... PRIMARY KEY`` + ``INSERT OR IGNORE`` guarantees it.
        """
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO m5_coverage (
                    cell_key, target, fault_kind, execution_context,
                    parameter_band, run_id, covered, extra_json
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    cell.key,
                    cell.target,
                    cell.fault_kind,
                    cell.execution_context,
                    cell.parameter_band,
                    run_id,
                    json.dumps(extra or {}),
                ),
            )

    def is_covered(self, cell: CoverageCell) -> bool:
        rows = self._store.query(
            "SELECT 1 FROM m5_coverage WHERE cell_key = ? AND covered = 1",
            (cell.key,),
        )
        return bool(rows)

    def covered_keys(self) -> frozenset[str]:
        rows = self._store.query("SELECT cell_key FROM m5_coverage WHERE covered = 1")
        return frozenset(r["cell_key"] for r in rows)

    def covered_records(self) -> tuple[CoverageRecord, ...]:
        rows = self._store.query(
            "SELECT target, fault_kind, execution_context, parameter_band, run_id, extra_json "
            "FROM m5_coverage WHERE covered = 1"
        )
        records: list[CoverageRecord] = []
        for r in rows:
            cell = CoverageCell(
                target=r["target"],
                fault_kind=r["fault_kind"],
                execution_context=r["execution_context"],
                parameter_band=r["parameter_band"],
            )
            records.append(
                CoverageRecord(cell=cell, run_id=r["run_id"], extra=json.loads(r["extra_json"]))
            )
        return tuple(records)

    def summary(self, landscape: Iterable[CoverageCell]) -> CoverageSummary:
        """Aggregate covered vs UNKNOWN cells over ``landscape``."""
        landscape_tuple = tuple(landscape)
        covered = self.covered_keys()
        return CoverageSummary(covered_keys=covered, total_cells=len(landscape_tuple))

    def unknown_cells(self, landscape: Iterable[CoverageCell]) -> tuple[CoverageCell, ...]:
        """Cells in ``landscape`` not yet covered, in landscape order."""
        return self.summary(landscape).unknown_cells(tuple(landscape))
