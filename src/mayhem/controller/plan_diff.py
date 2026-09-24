from __future__ import annotations

import json
from typing import Any

from mayhem.toolkit.hashing import canonical_json


def _plan_dict(plan: Any) -> dict[str, Any]:
    try:
        from mayhem.domain.experiments import ExecutionPlan

        if isinstance(plan, ExecutionPlan):
            return plan.model_dump(mode="json")
    except Exception:
        pass
    if isinstance(plan, dict):
        return dict(plan)
    if isinstance(plan, str):
        try:
            loaded = json.loads(plan)
            if isinstance(loaded, dict):
                return loaded
        except Exception:
            return {"raw": plan}
    try:
        return json.loads(json.dumps(plan, default=str))
    except Exception:
        return {"raw": str(plan)}


def diff_plans(authored: Any, last_accepted: Any) -> dict[str, Any]:
    a = _plan_dict(authored)
    b = _plan_dict(last_accepted)
    a_steps = a.get("steps", [])
    b_steps = b.get("steps", [])
    a_ids = (
        [s.get("id", str(i)) for i, s in enumerate(a_steps)] if isinstance(a_steps, list) else []
    )
    b_ids = (
        [s.get("id", str(i)) for i, s in enumerate(b_steps)] if isinstance(b_steps, list) else []
    )
    added = [x for x in a_ids if x not in b_ids]
    removed = [x for x in b_ids if x not in a_ids]
    changed_keys: list[str] = []
    for key in sorted(set(a.keys()) | set(b.keys())):
        if canonical_json(a.get(key)) != canonical_json(b.get(key)):
            changed_keys.append(key)
    equal = len(changed_keys) == 0 and added == [] and removed == []
    return {
        "added": sorted(added),
        "removed": sorted(removed),
        "changed_keys": sorted(changed_keys),
        "equal": equal,
        "authored_hash": _hash_dict(a),
        "accepted_hash": _hash_dict(b),
    }


def _hash_dict(data: dict[str, Any]) -> str:
    import hashlib

    return hashlib.sha256(canonical_json(data).encode()).hexdigest()


def compare_plan_files(authored_path: str, accepted_path: str) -> dict[str, Any]:
    import pathlib

    a_text = pathlib.Path(authored_path).read_text()
    b_text = pathlib.Path(accepted_path).read_text()
    try:
        a_json = json.loads(a_text)
    except Exception:
        a_json = {"raw": a_text}
    try:
        b_json = json.loads(b_text)
    except Exception:
        b_json = {"raw": b_text}
    return diff_plans(a_json, b_json)
