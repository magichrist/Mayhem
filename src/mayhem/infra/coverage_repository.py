"""SQLite-backed coverage accounting (ADR-M5-3, M5 Phase 5.2).

A recorded ``Outcome`` marks the run's coverage cell as *seen*. Marking the
same cell again (a re-run) is idempotent — ``INSERT OR IGNORE`` on the primary
key means re-running a cell never double-counts. Maniac can then enumerate the
``UNKNOWN`` cells of a landscape (cells not yet covered) to prioritize coverage
gain.

The M5 five-state model (feat-3 §4.2) extends the binary view: every row now
carries ``state`` (covered | inconclusive | failed | blocked) while ``covered``
keeps ``1`` iff ``state='covered'``, so Maniac/report.py read the legacy column
unchanged. ``unknown`` remains an absent row. ``record``/``record_blocked``
write states under the §4.2 transition rules; ``states``/``blocked_cells``
read them back; ``summary`` counts per state.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from mayhem.domain.catalog import all_definitions
from mayhem.domain.common import utc_now
from mayhem.domain.coverage import (
    CellFilters,
    CellState,
    CellStatusRecord,
    CoverageCell,
    CoverageRecord,
    CoverageSummary,
    ResilienceCell,
    transition,
)
from mayhem.infra.ranking import rank_resilience_cells

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from mayhem.domain.risks import RiskLevel
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
        rows = self._store.query(
            "SELECT cell_key FROM m5_coverage WHERE covered = 1 OR state = 'passed'"
        )
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
        """Aggregate covered vs unknown cells over ``landscape`` (five states)."""
        landscape_tuple = tuple(landscape)
        covered = self.covered_keys()
        state_map = self.states(landscape_tuple)
        counts: dict[CellState, int] = dict.fromkeys(CellState, 0)
        for state in state_map.values():
            counts[state] += 1
        return CoverageSummary(
            covered_keys=covered,
            total_cells=len(landscape_tuple),
            state_counts=counts,
        )

    def unknown_cells(self, landscape: Iterable[CoverageCell]) -> tuple[CoverageCell, ...]:
        """Cells in ``landscape`` not yet covered, in landscape order."""
        return self.summary(landscape).unknown_cells(tuple(landscape))

    # ── Five-state coverage API (feat-3 §4.2) ─────────────────────────

    def record(
        self,
        cell: CoverageCell,
        state: CellState,
        *,
        block_reason: str = "",
        scaffold_tier: int | None = None,
        run_id: str = "",
        verdict: dict[str, object] | None = None,
        metadata: dict[str, object] | None = None,
        target_profile: str = "",
        engine: str = "",
        service: str = "",
        failure_domain: str = "",
        risk: str = "",
        maturity: str = "",
        next_rationale: str = "",
    ) -> None:
        if state is CellState.UNKNOWN:
            return
        verdict_json = json.dumps(verdict or {}, sort_keys=True)
        extra = dict(metadata or {})
        extra.update(
            {
                key: value
                for key, value in (
                    ("target_profile", target_profile),
                    ("engine", engine),
                    ("service", service),
                    ("failure_domain", failure_domain),
                    ("risk", risk),
                    ("maturity", maturity),
                    ("next_rationale", next_rationale),
                )
                if value
            }
        )
        extra_json = json.dumps(extra, sort_keys=True)
        with self._store.write() as conn:
            existing = conn.execute(
                "SELECT state, run_id FROM m5_coverage WHERE cell_key = ?",
                (cell.key,),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO m5_coverage (
                        cell_key, target, fault_kind, execution_context,
                        parameter_band, run_id, covered, extra_json, state,
                        block_reason, scaffold_tier, updated_at, verdict_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cell.key,
                        cell.target,
                        cell.fault_kind,
                        cell.execution_context,
                        cell.parameter_band,
                        run_id,
                        1 if state is CellState.COVERED else 0,
                        extra_json,
                        state.value,
                        block_reason if state is CellState.BLOCKED else "",
                        scaffold_tier,
                        utc_now().isoformat(),
                        verdict_json,
                    ),
                )
                return
            existing_state = CellState(existing["state"])
            if existing["run_id"] == run_id:
                winner = existing_state
            else:
                winner = transition(existing_state, state)
            conn.execute(
                """
                UPDATE m5_coverage
                SET state = ?, covered = ?, run_id = ?, block_reason = ?,
                    scaffold_tier = ?, updated_at = ?, verdict_json = ?, extra_json = ?
                WHERE cell_key = ?
                """,
                (
                    winner.value,
                    1 if winner is CellState.COVERED else 0,
                    run_id,
                    block_reason if winner is CellState.BLOCKED else "",
                    scaffold_tier,
                    utc_now().isoformat(),
                    verdict_json,
                    extra_json,
                    cell.key,
                ),
            )

    def record_blocked(self, cell: CoverageCell, reason: str) -> None:
        """Record ``cell`` as ``blocked`` with a ``block_reason`` (§4.2)."""
        self.record(cell, CellState.BLOCKED, block_reason=reason)

    def cell_state(self, cell: CoverageCell) -> CellState | None:
        """Return the cell's persisted state, or None when unknown."""
        rows = self._store.query("SELECT state FROM m5_coverage WHERE cell_key = ?", (cell.key,))
        if not rows:
            return None
        return CellState(rows[0]["state"])

    def states(self, landscape: Iterable[CoverageCell]) -> dict[str, CellState]:
        """Map ``cell.key`` → state for every recorded cell in ``landscape``.

        Missing keys are ``unknown`` by convention (absent row, §4.2).
        """
        cells = tuple(landscape)
        if not cells:
            return {}
        keys = [c.key for c in cells]
        placeholders = ",".join("?" for _ in keys)
        rows = self._store.query(
            f"SELECT cell_key, state FROM m5_coverage WHERE cell_key IN ({placeholders})",
            tuple(keys),
        )
        return {r["cell_key"]: CellState(r["state"]) for r in rows}

    def blocked_cells(self, landscape: Iterable[CoverageCell]) -> tuple[CellStatusRecord, ...]:
        """Records of every ``blocked`` cell in ``landscape``, in order."""
        state_map = self.states(landscape)
        records: list[CellStatusRecord] = []
        for cell in landscape:
            if state_map.get(cell.key) is CellState.BLOCKED:
                records.append(self._status_record(cell.key))
        return tuple(records)

    def resilience_cells(
        self,
        landscape: Iterable[CoverageCell],
        filters: CellFilters | None = None,
    ) -> tuple[ResilienceCell, ...]:
        """Return enriched cells using the same rows and state vocabulary as ranking."""
        definitions = {definition.id: definition for definition in all_definitions()}
        cells = tuple(landscape)
        state_map = self.states(cells)
        result: list[ResilienceCell] = []
        for cell in cells:
            definition = definitions.get(cell.fault_kind)
            rows = self._store.query(
                "SELECT run_id, updated_at, extra_json, block_reason FROM m5_coverage"
                " WHERE cell_key = ?",
                (cell.key,),
            )
            row = rows[0] if rows else None
            extra = json.loads(row["extra_json"]) if row is not None and row["extra_json"] else {}
            state = state_map.get(cell.key, CellState.UNKNOWN)
            result.append(
                ResilienceCell(
                    target=cell.target,
                    failure_domain=str(
                        extra.get("failure_domain")
                        or (
                            definition.failure_domain.value
                            if definition and definition.failure_domain
                            else ""
                        )
                    ),
                    fault=cell.fault_kind,
                    engine=str(extra.get("engine", "")),
                    risk=str(
                        extra.get("risk")
                        or (definition.risk.value if definition else "")
                    ),
                    maturity=str(
                        extra.get("maturity")
                        or (definition.maturity.value if definition else "")
                    ),
                    state=state,
                    last_run=str(row["run_id"] if row is not None else ""),
                    next_rationale=str(
                        extra.get("next_rationale")
                        or self._rationale_for(
                            state,
                            str(row["block_reason"] if row is not None else ""),
                        )
                    ),
                    service=str(extra.get("service", cell.target)),
                    target_profile=str(extra.get("target_profile", "")),
                    execution_context=cell.execution_context,
                    parameter_band=cell.parameter_band,
                    metadata=extra,
                )
            )
        selected = filters if filters is not None else CellFilters()
        return tuple(cell for cell in result if selected.matches(cell))

    def cells(
        self,
        landscape: Iterable[CoverageCell],
        filters: CellFilters | None = None,
    ) -> tuple[ResilienceCell, ...]:
        return self.resilience_cells(landscape, filters)

    def next_cells(
        self,
        landscape: Iterable[CoverageCell],
        *,
        division_map: Mapping[str, int] | None = None,
        criticality_map: Mapping[str, float] | None = None,
        risk_map: Mapping[str, RiskLevel] | None = None,
        limit: int | None = None,
        filters: CellFilters | None = None,
    ) -> tuple[ResilienceCell, ...]:
        ranked = rank_resilience_cells(
            self.resilience_cells(landscape, filters),
            division_map=division_map or {},
            criticality_map=criticality_map or {},
            risk_map=risk_map or {},
        )
        return tuple(item.cell for item in (ranked[:limit] if limit is not None else ranked))

    @staticmethod
    def _rationale_for(state: CellState, block_reason: str) -> str:
        rationales = {
            CellState.UNKNOWN: "uncovered cell",
            CellState.PLANNED: "planned and ready to execute",
            CellState.EXECUTED: "executed; awaiting a terminal verdict",
            CellState.PASSED: "already passed",
            CellState.INCONCLUSIVE: "inconclusive evidence requires another run",
            CellState.FAILED: "failed evidence requires investigation",
            CellState.SKIPPED: "skipped; review selection and policy",
        }
        if state is CellState.BLOCKED:
            return (
                f"blocked: {block_reason}"
                if block_reason
                else "blocked by safety or feasibility"
            )
        return rationales[state]

    def recent_failures(self, limit: int = 10) -> tuple[frozenset[str], frozenset[str]]:
        """Return (failed_targets, failed_faults) from recent failed runs.

        This powers session memory in the ranking function: cells sharing a
        target or fault_kind with recently failed cells get a recall bonus.
        """
        rows = self._store.query(
            "SELECT target, fault_kind FROM m5_coverage "
            "WHERE state IN ('failed', 'inconclusive') "
            "ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        )
        targets = frozenset(r["target"] for r in rows)
        faults = frozenset(r["fault_kind"] for r in rows)
        return targets, faults

    def _status_record(self, cell_key: str) -> CellStatusRecord:
        rows = self._store.query(
            "SELECT cell_key, target, fault_kind, execution_context, parameter_band,"
            " state, block_reason, scaffold_tier, run_id, verdict_json, updated_at, extra_json"
            " FROM m5_coverage WHERE cell_key = ?",
            (cell_key,),
        )
        row = rows[0]
        return CellStatusRecord(
            cell=CoverageCell(
                target=row["target"],
                fault_kind=row["fault_kind"],
                execution_context=row["execution_context"],
                parameter_band=row["parameter_band"],
            ),
            state=CellState(row["state"]),
            block_reason=row["block_reason"],
            scaffold_tier=row["scaffold_tier"],
            run_id=row["run_id"],
            verdict=json.loads(row["verdict_json"]),
            updated_at=row["updated_at"],
            extra=json.loads(row["extra_json"]),
        )
