from __future__ import annotations

import json
from typing import Any

from mayhem.domain.replay import ReplayCapsule


def build_capsule(
    store: Any,
    run_id: str,
    *,
    engine: str = "",
    policy: dict[str, Any] | None = None,
    target: dict[str, Any] | None = None,
    runtime: dict[str, Any] | None = None,
    versions: dict[str, str] | None = None,
) -> ReplayCapsule | None:
    """Build a replay capsule from the durable run row and evidence envelope."""
    rows = store.query(
        "SELECT spec_json, plan_json, seed, environment_fingerprint, config_snapshot_id "
        "FROM runs WHERE id = ?",
        (run_id,),
    )
    if not rows:
        return None
    row = dict(rows[0])

    def _json(raw: object) -> dict[str, Any]:
        try:
            value = json.loads(str(raw or "{}"))
        except (TypeError, ValueError):
            return {}
        return value if isinstance(value, dict) else {"value": value}

    spec = _json(row.get("spec_json"))
    plan = _json(row.get("plan_json"))
    envelope: dict[str, Any] = {}
    try:
        evidence_rows = store.query(
            "SELECT envelope_json FROM evidence_envelopes WHERE run_id = ?", (run_id,)
        )
    except Exception:
        evidence_rows = []
    if evidence_rows:
        envelope = _json(dict(evidence_rows[0])["envelope_json"])
    capsule = ReplayCapsule(
        run_id=run_id,
        spec=spec,
        plan=plan,
        policy=dict(policy or {}),
        target=dict(target or {"profile": envelope.get("target_profile") or ""}),
        runtime={"engine": engine, **dict(runtime or {})},
        versions=dict(versions or {}),
        seed=row.get("seed"),
        fingerprints={
            "environment": str(row.get("environment_fingerprint") or ""),
            "topology": str(envelope.get("topology_fingerprint") or ""),
            "config_snapshot": str(row.get("config_snapshot_id") or ""),
        },
        digests={"plan": envelope.get("plan_hash", "") if envelope else ""},
    )
    return capsule.with_digests()


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
