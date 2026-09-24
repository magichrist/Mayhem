from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from mayhem.toolkit.hashing import canonical_json


def artifact_name(run_id: str, kind: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in run_id)
    return f"{safe}__{kind}.json"


def plan_hash_from_file(path: str) -> str:
    text = Path(path).read_text()
    try:
        data = json.loads(text)
        return hashlib.sha256(canonical_json(data).encode()).hexdigest()
    except Exception:
        return hashlib.sha256(text.encode()).hexdigest()


def load_plan_file(path: str) -> dict[str, Any]:
    text = Path(path).read_text()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"raw": text}


def reject_if_stale(
    *,
    preflight_fingerprint: str,
    current_fingerprint: str,
    preflight_target: str | None,
    current_target: str | None,
    plan_hash: str | None = None,
) -> None:
    if (
        preflight_fingerprint
        and current_fingerprint
        and preflight_fingerprint != current_fingerprint
    ):
        raise ValueError(
            f"stale plan: fingerprint changed {preflight_fingerprint[:12]} -> {current_fingerprint[:12]}; re-plan"
        )
    if (
        preflight_target is not None
        and current_target is not None
        and preflight_target != current_target
    ):
        raise ValueError(
            f"stale plan: target changed {preflight_target!r} -> {current_target!r}; re-plan"
        )


def expected_evidence_display(expected: tuple[str, ...] | list[str]) -> str:
    if not expected:
        return "expected evidence: none"
    return "expected evidence: " + ", ".join(expected)


def blast_radius_display(blast: dict[str, Any]) -> str:
    if not blast:
        return "blast_radius: unknown"
    parts = []
    for key in sorted(blast.keys()):
        parts.append(f"{key}={blast[key]}")
    return "blast_radius: " + ", ".join(parts)


def compensation_display(status: str) -> str:
    if not status:
        return "compensation: unknown"
    return f"compensation: {status}"


def build_execution_intent(
    *,
    action: str,
    target_profile: str | None,
    plan_id: str,
    plan_hash: str,
    policy_decision: str,
    approval_source: str,
    fingerprint: str = "",
    engine: str = "",
) -> dict[str, Any]:
    return {
        "action": action,
        "target_profile": target_profile,
        "plan_id": plan_id,
        "plan_hash": plan_hash,
        "policy_decision": policy_decision,
        "approval_source": approval_source,
        "fingerprint": fingerprint,
        "engine": engine,
    }


def migration_warning() -> str:
    return "warning: implicit execution without --execute is deprecated; use --execute --from-plan or --execute with explicit approval"


def resolve_plan_source(
    *,
    from_plan: str | None,
    plan_id: str | None,
    db: Any = None,
) -> dict[str, Any] | None:
    if from_plan is not None:
        return load_plan_file(from_plan)
    if plan_id is not None and db is not None:
        try:
            rows = db.query("SELECT plan_json FROM runs WHERE id = ?", (plan_id,))
            if rows:
                raw = rows[0]["plan_json"] if isinstance(rows[0], dict) else rows[0][0]
                try:
                    return json.loads(raw) if isinstance(raw, str) else dict(raw)
                except Exception:
                    return {"raw": raw}
        except Exception:
            return None
    return None
