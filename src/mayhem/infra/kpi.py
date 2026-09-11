"""0.6 KPI compute module (§8) — pure, deterministic, store-derived.

Every function is documented with its §8 KPI id:

- ``delta-recovery``     — ``delta_timeout_seconds(results)``
- ``critical-evidence``  — ``probability_critical_evidence()``
- ``autonomy-gap``       — ``autonomy_gap()``
- ``evidence-recorded``  — ``evidence_recorded_total()``

Design contract: no clocks, no I/O inside the pure functions except where a
``now`` timestamp is passed in explicitly, so a given store snapshot always
produces the same numbers. No new tables are added: KPIs derive from existing
run / outcome / coverage rows.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

_KPI_IDS = (
    "delta-recovery",
    "critical-evidence",
    "autonomy-gap",
    "evidence-recorded",
)


def delta_timeout_seconds(results: list[dict[str, Any]]) -> float:
    """KPI ``delta-recovery`` — max wall-clock seconds of any executed run.

    ``results`` is a list of run-row dicts with a numeric ``duration_seconds``
    key (or ``None`` when the run never completed). Empty input → 0.0.
    """
    durations = [
        float(r.get("duration_seconds") or 0.0)
        for r in results
        if isinstance(r, dict)
    ]
    return max(durations) if durations else 0.0


def probability_critical_evidence(
    covered_rows: list[dict[str, Any]],
    risk_of: Any | None = None,
) -> float:
    """KPI ``critical-evidence`` — share of covered cells at critical-or-higher risk.

    ``covered_rows`` is a list of coverage-row dicts carrying a ``risk_level``
    key. When ``risk_of`` is None a row without an explicit ``risk_level`` is
    counted as non-critical. Returns 0.0..1.0 (0.0 on empty input).
    """
    if not covered_rows:
        return 0.0
    critical = 0
    for row in covered_rows:
        level = row.get("risk_level")
        if level is None and risk_of is not None:
            level = risk_of(row.get("fault_kind", ""))  # type: ignore[call-arg]
        if str(level).strip().lower() in {"critical", "catastrophic"}:
            critical += 1
    return critical / len(covered_rows)


def autonomy_gap(planned: int, executed: int) -> float:
    """KPI ``autonomy-gap`` — planned vs executed coverage of the run queue.

    Returns the fraction of the planned queue that actually executed
    (0.0..1.0, and 1.0 when nothing was planned).
    """
    if planned <= 0:
        return 1.0
    return min(1.0, executed / planned)


def evidence_recorded_total(
    observation_rows: int = 0,
    coverage_rows: int = 0,
) -> int:
    """KPI ``evidence-recorded`` — sum of observations + coverage rows."""
    return int(observation_rows) + int(coverage_rows)


# ── Store-backed helpers (the module's one concession to the real world) ────


def _query_count(conn: Any, sql: str) -> int:
    cur = conn.execute(sql)
    return int(cur.fetchone()[0])


def kpis_from_store(db: str | Path) -> dict[str, Any]:
    """Compute all four KPIs from a store at ``db``.

    Reads rows from the existing schema (``runs``, ``m5_coverage``) without
    adding tables. Kept thin so the pure functions above stay the source of
    truth.
    """
    import sqlite3

    path = Path(db)
    if not path.exists():
        raise FileNotFoundError(f"store does not exist: {path}")

    conn = sqlite3.connect(path)
    try:
        # runs table duration_seconds (best-effort; some schemas store ms)
        try:
            runs = conn.execute(
                'SELECT duration_seconds FROM runs WHERE status != \'pending\''
            )
            run_rows = [{"duration_seconds": row[0]} for row in runs]
            durations = [float(r.get("duration_seconds") or 0.0) for r in run_rows]
            delta = max(durations) if durations else 0.0
        except sqlite3.OperationalError:
            # older store without runs.duration_seconds — treat as 0
            delta = 0.0
            run_rows = []

        # covered cells with risk
        try:
            covered = conn.execute(
                'SELECT state, risk_level FROM m5_coverage '
                'WHERE state = \'covered\''
            )
            covered_rows = [{"state": r[0], "risk_level": r[1]} for r in covered]
        except sqlite3.OperationalError:
            covered_rows = []

        try:
            planned = _query_count(conn, 'SELECT COUNT(*) FROM m5_coverage')
        except sqlite3.OperationalError:
            planned = 0
        executed = len(run_rows)
        autonomy = autonomy_gap(planned, executed) if planned else 1.0

        try:
            obs_total = _query_count(conn, 'SELECT COUNT(*) FROM observations')
        except sqlite3.OperationalError:
            obs_total = 0
        evidence = evidence_recorded_total(obs_total, len(covered_rows))

        return {
            "delta-recovery": round(delta, 3),
            "critical-evidence": round(probability_critical_evidence(covered_rows), 4),
            "autonomy-gap": round(autonomy, 4),
            "evidence-recorded": evidence,
        }
    finally:
        conn.close()


def _main(argv: list[str] | None = None) -> int:
    """``python -m mayhem.infra.kpi [--db PATH]`` — self-serve one-liner."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="python -m mayhem.infra.kpi")
    parser.add_argument("--db", default="mayhem.db", help="store path (default: mayhem.db)")
    parser.add_argument("--json", action="store_true", help="emit JSON lines")
    args = parser.parse_args(argv)

    try:
        results = kpis_from_store(args.db)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for kpi_id, value in results.items():
            print(f"{kpi_id:24s} = {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())