from __future__ import annotations

import json
from math import isfinite
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
        from mayhem.cli.execution import blast_radius_display

        lines.append(blast_radius_display(blast))
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
    lines.extend(_plan_lines(getattr(preflight, "plan", None)))
    # Steady state is rendered only when a report is attached, and an absent
    # report appends nothing at all — a drill with no `steady_state:` block must
    # render byte-identically to how it rendered before this feature existed.
    steady = getattr(preflight, "steady_state_report", None)
    if steady is not None:
        lines.extend(render_steady_state_human(steady))
    return "\n".join(lines)


def _plan_lines(plan: object) -> list[str]:
    """The fault summary of a compiled plan, or nothing when there is no plan."""
    if plan is None:
        return []
    try:
        steps = getattr(plan, "steps", []) or []
        fault_ids = [
            getattr(s.fault, "fault_id", "") for s in steps if getattr(s, "fault", None) is not None
        ]
        durations = [
            float(getattr(s.fault, "duration", 0) or 0)
            for s in steps
            if getattr(s, "fault", None) is not None
        ]
    except Exception:
        return []
    lines: list[str] = []
    if fault_ids:
        lines.append(f"faults: {', '.join(fault_ids)}")
    if durations:
        lines.append(f"durations: {', '.join(f'{d:.1f}s' for d in durations)}")
    return lines


def _number(value: object, unit: str = "") -> str:
    """Quote a number, or say plainly that there is none.

    Never renders ``inf`` or ``nan``: those are the two literals a reader of an
    operator report cannot interpret, and a display string is exactly the place
    where they would otherwise reach a human being unannounced.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return str(value) if value is not None else "n/a"
    number = float(value)
    if not isfinite(number):
        return "n/a"
    text = f"{number:.3f}".rstrip("0").rstrip(".")
    return f"{text}{unit}" if text else f"0{unit}"


def render_steady_state_human(report: Any) -> list[str]:
    """The steady-state block, in the preflight block's own idiom.

    One line per verdict-bearing fact, then one line per signal. The graded
    verdict leads because it replaces the boolean: an operator who reads only
    the first line still learns whether the fault did what it claimed and
    whether it left residue.
    """
    verdict = getattr(report, "verdict", None)
    lines: list[str] = []
    lines.append(f"steady_state: verdict {getattr(verdict, 'value', None) or 'not-graded'}")
    # The baseline's provenance is always on screen, never implied by its
    # absence: an unlabelled baseline is an untrustworthy baseline. A reader
    # who cannot tell whether the numbers were just measured or carried over
    # from an earlier run cannot tell whether the deltas below mean anything.
    baseline_from = getattr(report, "baseline_from", "")
    if baseline_from:
        lines.append(f"steady_state: baseline from run {baseline_from}")
    else:
        lines.append(
            f"steady_state: baseline captured fresh for run {getattr(report, 'run_id', '') or '?'}"
        )
    lines.append(
        "steady_state: recovered "
        f"{'yes' if getattr(report, 'recovered', False) else 'no'}"
        f" (max recovery delta {_number(getattr(report, 'max_recovery_delta_pct', None), '%')})"
    )
    for evaluation in getattr(report, "evaluations", ()) or ():
        signal = evaluation.signal
        measured = signal.after if signal.after is not None else signal.during
        mark = "ok" if evaluation.passed else ("UNGRADED" if not evaluation.graded else "FAIL")
        lines.append(
            f"  {evaluation.phase.value}/{evaluation.verb.value} {evaluation.check_id}: "
            f"baseline {_number(signal.baseline)} measured {_number(measured)} "
            f"delta {_number(signal.delta_pct, '%')} -> {mark}"
        )
        if signal.note:
            lines.append(f"    {signal.note}")
    ungraded = getattr(report, "ungraded", lambda: ())()
    if ungraded:
        names = ", ".join(e.check_id for e in ungraded)
        lines.append(
            f"  steady_state: {len(ungraded)} assertion(s) not graded ({names}) — "
            "an ungraded assertion is never a pass"
        )
    cross_check = getattr(report, "cross_check", None)
    if cross_check is not None:
        for loud in getattr(cross_check, "loud_lines", lambda: ())():
            lines.append(f"  {loud}")
        lines.append(
            "  steady_state: impact gate cross-check "
            f"{len(cross_check.contradicted)} contradicted, "
            f"{len(cross_check.confirmed)} confirmed, "
            f"{len(cross_check.unverified)} unverified"
        )
    return lines


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
    if data.get("action_outcomes"):
        lines.append(f"action outcomes: {'; '.join(data['action_outcomes'])}")
    residual = data.get("residual_impact") or {}
    if residual:
        lines.append(
            f"residual impact: {residual.get('status', 'unknown')} "
            f"({residual.get('untolerated_count', 0)} untolerated "
            f"of {residual.get('signals_compared', 0)} signal(s))"
        )
    metrics = data.get("redaction_metrics") or {}
    if metrics:
        lines.append(
            f"redaction: policy v{metrics.get('policy_version', '?')} "
            f"paths={metrics.get('redacted_path_count', 0)}"
        )
    return "\n".join(lines)
