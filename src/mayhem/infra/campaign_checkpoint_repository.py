"""Persistence for campaign checkpoints (v0.9.0 expansion task 15)."""

from __future__ import annotations

from mayhem.domain.campaign_checkpoint import CampaignCheckpoint, CheckpointState
from mayhem.infra.store import Store


class CampaignCheckpointRepository:
    def __init__(self, store: Store) -> None:
        self._store = store

    def save(self, checkpoint: CampaignCheckpoint, *, now: str = "") -> CampaignCheckpoint:
        stamp = now or checkpoint.updated_at or _now()
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO campaign_checkpoints (campaign_id, experiment_id, "
                "state, lease_id, attempt, fingerprint, resume_safe, detail, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    checkpoint.campaign_id,
                    checkpoint.experiment_id,
                    checkpoint.state.value,
                    checkpoint.lease_id,
                    checkpoint.attempt,
                    checkpoint.fingerprint,
                    int(checkpoint.resume_safe),
                    checkpoint.detail,
                    stamp,
                ),
            )
        return checkpoint.model_copy(update={"updated_at": stamp})

    def load(self, campaign_id: str) -> tuple[CampaignCheckpoint, ...]:
        rows = self._store.query(
            "SELECT campaign_id, experiment_id, state, lease_id, attempt, fingerprint, "
            "resume_safe, detail, updated_at FROM campaign_checkpoints "
            "WHERE campaign_id = ? ORDER BY experiment_id",
            (campaign_id,),
        )
        return tuple(
            CampaignCheckpoint(
                campaign_id=str(dict(row)["campaign_id"]),
                experiment_id=str(dict(row)["experiment_id"]),
                state=CheckpointState(str(dict(row)["state"])),
                lease_id=str(dict(row)["lease_id"]),
                attempt=int(dict(row)["attempt"]),
                fingerprint=str(dict(row)["fingerprint"]),
                resume_safe=bool(dict(row)["resume_safe"]),
                detail=str(dict(row)["detail"]),
                updated_at=str(dict(row)["updated_at"]),
            )
            for row in rows
        )

    def get(self, campaign_id: str, experiment_id: str) -> CampaignCheckpoint | None:
        for checkpoint in self.load(campaign_id):
            if checkpoint.experiment_id == experiment_id:
                return checkpoint
        return None

    def delete_campaign(self, campaign_id: str) -> int:
        with self._store.write() as conn:
            cursor = conn.execute(
                "DELETE FROM campaign_checkpoints WHERE campaign_id = ?", (campaign_id,)
            )
        return int(cursor.rowcount or 0)


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()
