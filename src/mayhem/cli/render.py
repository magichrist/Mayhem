from __future__ import annotations

import json
from typing import Any

try:
    from mayhem.domain.preflight import Preflight
except Exception:
    Preflight = object  # type: ignore[assignment,misc]


def render_preflight_human(preflight: Any) -> str:
    lines: list[str] = []
    lines.append(
        f"target: {getattr(preflight, 'resolved_target', '') or getattr(preflight, 'target_profile', '') or '-'}"
    )
    lines.append(f"engine: {getattr(preflight, 'engine', '') or '-'}")
    lines.append(
        f"plan: {getattr(preflight, 'plan_id', '')} hash {getattr(preflight, 'plan_hash', '')[:12]}"
    )
    lines.append(f"fingerprint: {getattr(preflight, 'environment_fingerprint', '')[:12]}")
    lines.append(
        f"config: {getattr(preflight, 'config_snapshot_id', '')[:12]} topo {getattr(preflight, 'topology_snapshot_id', '')[:12]}"
    )
    blast = getattr(preflight, "blast_radius", {}) or {}
    if blast:
        lines.append(f"blast_radius: {blast}")
    comp = getattr(preflight, "compensation_status", "")
    if comp:
        lines.append(f"compensation: {comp}")
    expected = getattr(preflight, "expected_evidence", ()) or ()
    if expected:
        lines.append(f"expected_evidence: {', '.join(expected)}")
    blocked = getattr(preflight, "blocked_items", ()) or ()
    if blocked:
        lines.append("blocked:")
        for item in blocked:
            lines.append(f"  - {item}")
    warnings = getattr(preflight, "warnings", ()) or ()
    if warnings:
        lines.append("warnings:")
        for item in warnings:
            lines.append(f"  - {item}")
    safety = getattr(preflight, "safety_decisions", ()) or ()
    if safety:
        lines.append(f"safety: {'; '.join(safety)}")
    plan = getattr(preflight, "plan", None)
    if plan is not None:
        try:
            steps = getattr(plan, "steps", []) or []
            fault_ids = [
                getattr(s.fault, "fault_id", "")
                for s in steps
                if getattr(s, "fault", None) is not None
            ]
            durations = [
                float(getattr(s.fault, "duration", 0) or 0)
                for s in steps
                if getattr(s, "fault", None) is not None
            ]
            if fault_ids:
                lines.append(f"faults: {', '.join(fault_ids)}")
            if durations:
                lines.append(f"durations: {', '.join(f'{d:.1f}s' for d in durations)}")
        except Exception:
            pass
    return "\n".join(lines)


def render_preflight_json(preflight: Any) -> str:
    try:
        if hasattr(preflight, "to_dict"):
            payload = preflight.to_dict()
        else:
            payload = {
                "resolved_target": getattr(preflight, "resolved_target", None),
                "config_snapshot_id": getattr(preflight, "config_snapshot_id", ""),
                "topology_snapshot_id": getattr(preflight, "topology_snapshot_id", ""),
                "environment_fingerprint": getattr(preflight, "environment_fingerprint", ""),
                "safety_decisions": list(getattr(preflight, "safety_decisions", []) or []),
                "blocked_items": list(getattr(preflight, "blocked_items", []) or []),
                "warnings": list(getattr(preflight, "warnings", []) or []),
                "target_profile": getattr(preflight, "target_profile", None),
                "engine": getattr(preflight, "engine", ""),
                "blast_radius": dict(getattr(preflight, "blast_radius", {}) or {}),
                "compensation_status": getattr(preflight, "compensation_status", ""),
                "expected_evidence": list(getattr(preflight, "expected_evidence", []) or []),
                "plan_hash": getattr(preflight, "plan_hash", ""),
                "plan_id": getattr(preflight, "plan_id", ""),
                "target_identity": getattr(preflight, "target_identity", ""),
            }
        ordered = {k: payload[k] for k in sorted(payload.keys())}
        return json.dumps(ordered, indent=2, sort_keys=False)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def render_plan_diff(diff: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"equal: {diff.get('equal', False)}")
    if diff.get("added"):
        lines.append(f"added: {', '.join(diff['added'])}")
    if diff.get("removed"):
        lines.append(f"removed: {', '.join(diff['removed'])}")
    if diff.get("changed_keys"):
        lines.append(f"changed_keys: {', '.join(diff['changed_keys'])}")
    lines.append(f"authored_hash: {diff.get('authored_hash', '')[:12]}")
    lines.append(f"accepted_hash: {diff.get('accepted_hash', '')[:12]}")
    return "\n".join(lines)


def render_evidence_human(envelope: Any) -> str:
    try:
        data = (
            envelope.model_dump(mode="json") if hasattr(envelope, "model_dump") else dict(envelope)
        )
    except Exception:
        data = {}
    lines: list[str] = []
    lines.append(f"run: {data.get('run_id', '')}")
    lines.append(f"plan: {data.get('plan_id', '')} hash {str(data.get('plan_hash', ''))[:12]}")
    lines.append(f"target: {data.get('target_profile', '') or data.get('target_identity', '')}")
    lines.append(f"engine: {data.get('engine', '')}")
    lines.append(
        f"logical target: {data.get('logical_target', '') or '-'} "
        f"resolved target: {data.get('resolved_target', '') or '-'} "
        f"drift: {data.get('drift_status', '') or 'not recorded'}"
    )
    if data.get("k8s_context") or data.get("k8s_namespace"):
        lines.append(
            f"kubernetes: context={data.get('k8s_context', '') or '-'} "
            f"namespace={data.get('k8s_namespace', '') or '-'} "
            f"capability={data.get('k8s_capability_verdict', '') or '-'}"
        )
    if data.get("k8s_recovery_guidance"):
        lines.append(
            f"recovery: wait={data.get('k8s_wait_strategy', '') or '-'}; "
            f"guidance={data['k8s_recovery_guidance']}"
        )
    lines.append(f"verdict: {data.get('verdict', '')} recovery {data.get('recovery_state', '')}")
    if data.get("safety_decisions"):
        lines.append(f"safety: {'; '.join(data['safety_decisions'])}")
    if data.get("step_reports"):
        lines.append(f"steps: {len(data['step_reports'])}")
    if data.get("lease_timeline"):
        lines.append(f"leases: {len(data['lease_timeline'])}")
    if data.get("observations"):
        lines.append(f"observations: {len(data['observations'])}")
    if data.get("remediation"):
        lines.append(f"remediation: {'; '.join(data['remediation'])}")
    return "\n".join(lines)
