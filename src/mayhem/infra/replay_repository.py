from __future__ import annotations

from typing import Any

from mayhem.domain.replay import ReplayCapsule


class ReplayRepository:
    def __init__(self, store: Any) -> None:
        self._store = store

    def save(self, capsule: ReplayCapsule) -> None:
        payload = capsule.with_digests().model_dump_json()
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO replay_capsules "
                "(run_id, capsule_json, digest, created_at) VALUES (?,?,?,datetime('now'))",
                (capsule.run_id, payload, capsule.digest()),
            )

    def load(self, run_id: str) -> ReplayCapsule | None:
        rows = self._store.query("SELECT capsule_json FROM replay_capsules WHERE run_id = ?", (run_id,))
        if not rows:
            return None
        raw = rows[0]["capsule_json"]
        return ReplayCapsule.model_validate_json(raw)

    def list_run_ids(self) -> tuple[str, ...]:
        rows = self._store.query("SELECT run_id FROM replay_capsules ORDER BY created_at DESC, run_id")
        return tuple(str(row["run_id"]) for row in rows)
