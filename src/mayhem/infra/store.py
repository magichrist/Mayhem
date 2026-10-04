"""SQLite store: one connection, WAL, disciplined pragmas (ADR-0007).

The controller is the single writer. Agents never open this file.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from mayhem.domain.common import utc_now
from mayhem.domain.run_outcome import Outcome, RunRecord, RunStatus, RunVerdict
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.migrator import Migration, current_version, run_down_migrations, run_migrations
from mayhem.infra.secret_resolver import require_persistable_document

if TYPE_CHECKING:
    from collections.abc import Iterator

_BUSY_TIMEOUT_MS = 5_000


class Store:
    """Owns the SQLite connection and migration lifecycle."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # One connection shared across threads (parallel fault execution, ADR-0022).
        # Access is serialized by ``_lock``; WAL + busy_timeout handle cross-process writers.
        self._conn = sqlite3.connect(
            self._path, timeout=_BUSY_TIMEOUT_MS / 1000, check_same_thread=False
        )
        self._lock = threading.RLock()
        self._conn.row_factory = sqlite3.Row
        for pragma in (
            "PRAGMA journal_mode=WAL",
            f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}",
            "PRAGMA foreign_keys=ON",
            "PRAGMA synchronous=NORMAL",
        ):
            self._conn.execute(pragma)

    @classmethod
    def open_migrated(
        cls, path: Path | str, migrations: tuple[Migration, ...] = ALL_MIGRATIONS
    ) -> Store:
        store = cls(path)
        store.migrate(migrations)
        return store

    def migrate(self, migrations: tuple[Migration, ...] = ALL_MIGRATIONS) -> list[str]:
        with self._lock:
            return run_migrations(self._conn, migrations)

    def migrate_down(
        self, target_version: int, migrations: tuple[Migration, ...] = ALL_MIGRATIONS
    ) -> list[str]:
        """Roll the schema back to ``target_version`` (ADR-M4-5)."""
        with self._lock:
            return run_down_migrations(self._conn, migrations, target_version)

    @property
    def schema_version(self) -> int | None:
        with self._lock:
            return current_version(self._conn)

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """Single-writer transaction boundary; commits or rolls back atomically."""
        try:
            with self._lock, self._conn:
                yield self._conn
        except sqlite3.Error:
            raise

    def query(self, sql: str, params: tuple[object, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params))

    def close(self) -> None:
        self._conn.close()

    # ── Run / Outcome persistence (ADR-M5-1) ──────────────────────────

    def save_run_record(self, run: RunRecord) -> None:
        """Persist a RunRecord to the m5_runs table."""
        with self.write() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO m5_runs
                   (id, experiment_name, spec_json, plan_json, seed,
                    status, environment_fingerprint, config_snapshot_id,
                    started_at, ended_at, description, verdict,
                    tags_json, extra_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run.run_id,
                    run.experiment_name,
                    run.spec_json,
                    run.plan_json,
                    run.seed,
                    run.status.value,
                    run.environment_fingerprint,
                    run.config_snapshot_id,
                    run.started_at,
                    run.ended_at,
                    run.description,
                    run.verdict.value,
                    json.dumps(list(run.tags)),
                    json.dumps(run.extra),
                ),
            )

    def load_run_record(self, run_id: str) -> RunRecord | None:
        """Load a RunRecord by id, or None if absent."""
        rows = self.query("SELECT * FROM m5_runs WHERE id = ?", (run_id,))
        if not rows:
            return None
        row = rows[0]
        return RunRecord(
            run_id=row["id"],
            experiment_name=row["experiment_name"],
            spec_json=row["spec_json"],
            plan_json=row["plan_json"],
            seed=row["seed"],
            status=RunStatus(row["status"]),
            environment_fingerprint=row["environment_fingerprint"],
            config_snapshot_id=row["config_snapshot_id"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            description=row["description"],
            verdict=RunVerdict(row["verdict"]),
            tags=tuple(json.loads(row["tags_json"])),
            extra=json.loads(row["extra_json"]),
        )

    def save_outcome(self, outcome: Outcome) -> None:
        """Persist an Outcome to the m5_outcomes table."""
        with self.write() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO m5_outcomes
                   (run_id, body_json, body_hash, checks_passed, checks_failed,
                    metric_deltas_json, residual_effect, stability_signal,
                    extra_json)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    outcome.run_id,
                    outcome.body_json,
                    outcome.body_hash,
                    outcome.checks_passed,
                    outcome.checks_failed,
                    json.dumps(outcome.metric_deltas),
                    outcome.residual_effect,
                    outcome.stability_signal,
                    json.dumps(outcome.extra),
                ),
            )

    def save_observation(
        self,
        kind: str,
        *,
        run_id: str = "",
        source: str = "",
        data: dict[str, object] | None = None,
    ) -> None:
        """Persist one row to the observations table (ADR-M5 phase-gated).

        An observation is evidence by the argument that binds the audit stream:
        it is persisted, read back by the reports that make a run legible, and
        archived by the retention machinery — so plan 12's "secrets must never
        enter evidence" binds the row. ``data`` is caller-authored and
        free-form, and the callers are operator-facing: a facilitator's note on a
        game-day artifact, a scheduler tick's decisions, a stop record. Any of
        them can carry a value the run resolved, under a field name nobody
        graded, which is the surface the byte rule exists for.

        The gate runs before the transaction opens, not inside it, so a refusal
        leaves no row rather than a rolled-back one.

        Raises:
            InvariantViolationError: From the evidence boundary, if ``data``
                carries a secret-classified field or a value this run resolved.
                Nothing was written.
        """
        # The evidence boundary, before the transaction opens. Gating ``data``
        # rather than its JSON rendering because the document is what the grade
        # rule walks; the writer's ``json.dumps`` re-emits the same values, so
        # gating a different rendering than the column receives would be gating
        # the wrong artifact.
        require_persistable_document(data or {}, artifact="store:observations")
        with self.write() as conn:
            conn.execute(
                """INSERT INTO observations (kind, run_id, source, data_json, timestamp)
                   VALUES (?,?,?,?,?)""",
                (
                    kind,
                    run_id,
                    source,
                    json.dumps(data or {}),
                    utc_now().isoformat(),
                ),
            )

    def load_outcome(self, run_id: str) -> Outcome | None:
        """Load an Outcome by run_id, or None if absent."""
        rows = self.query("SELECT * FROM m5_outcomes WHERE run_id = ?", (run_id,))
        if not rows:
            return None
        row = rows[0]
        return Outcome(
            run_id=row["run_id"],
            body_json=row["body_json"],
            body_hash=row["body_hash"],
            checks_passed=row["checks_passed"],
            checks_failed=row["checks_failed"],
            metric_deltas=json.loads(row["metric_deltas_json"]),
            residual_effect=row["residual_effect"],
            stability_signal=row["stability_signal"],
            extra=json.loads(row["extra_json"]),
        )
