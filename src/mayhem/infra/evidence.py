from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mayhem.domain.common import utc_now
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.domain.preflight import plan_hash_for
from mayhem.infra.report import report_id_for_run


def _sanitize_evidence_dict(data: dict[str, Any]) -> dict[str, Any]:
    from mayhem.domain.redaction import redact

    return dict(redact(data).value)


def build_evidence(
    *,
    run_id: str,
    plan: Any,
    target_profile: str | None,
    engine: str,
    safety_decisions: tuple[str, ...],
    step_reports: tuple[dict[str, Any], ...],
    lease_timeline: tuple[dict[str, Any], ...],
    observations: tuple[dict[str, Any], ...],
    steady_state: dict[str, Any] | None = None,
    verdict: str,
    recovery_state: str,
    remediation: tuple[str, ...],
    environment_fingerprint: str = "",
    target_identity: str = "",
    blast_radius: dict[str, Any] | None = None,
    compensation_status: str = "",
    logical_target: str = "",
    resolved_target: str = "",
    drift_status: str = "",
    k8s_context: str = "",
    k8s_namespace: str = "",
    k8s_capability_verdict: str = "",
    k8s_wait_strategy: str = "",
    k8s_recovery_guidance: str = "",
    skip_gate: bool = False,
    engine_version: str | None = None,
    topology_fingerprint: str | None = None,
    execution_intent: dict[str, Any] | None = None,
    replay_digest: str = "",
    evidence_status: str = "complete",
    action_outcomes: tuple[str, ...] = (),
    observation_provenance: dict[str, Any] | None = None,
    slo_outcomes: tuple[dict[str, Any], ...] = (),
    residual_impact: dict[str, Any] | None = None,
    emitted_spans: tuple[str, ...] = (),
) -> EvidenceEnvelope:
    phash = plan_hash_for(plan) if plan is not None else ""
    pid = getattr(plan, "run_id", run_id) if plan is not None else run_id
    from mayhem.domain.redaction import RULE_VERSION

    redaction_paths: list[str] = []

    def _redact_into(data: dict[str, Any]) -> dict[str, Any]:
        from mayhem.domain.redaction import redact

        result = redact(data)
        redaction_paths.extend(result.removed_paths)
        return dict(result.value)

    sanitized_reports = tuple(_redact_into(dict(r)) for r in step_reports)
    sanitized_leases = tuple(_redact_into(dict(r)) for r in lease_timeline)
    sanitized_obs = tuple(_redact_into(dict(r)) for r in observations)
    sanitized_blast = _redact_into(dict(blast_radius or {}))
    sanitized_steady = _redact_into(dict(steady_state or {}))
    redaction_metrics = {
        "policy_version": RULE_VERSION,
        "redacted_path_count": len(redaction_paths),
        "redacted_paths": tuple(sorted(set(redaction_paths))),
    }
    extra_verdict = verdict
    extra_remediation = list(remediation)
    if skip_gate:
        extra_remediation.append("break-glass: --skip-gate used")
        extra_verdict = verdict + " (skip-gate)" if verdict else "skip-gate"
    if engine_version is None:
        try:
            from mayhem.domain.runtime_adapter import describe_engine

            desc = describe_engine(engine) if engine else None
            engine_version = desc.version if desc else None
        except Exception:
            engine_version = None
        if engine_version is None:
            try:
                from mayhem.infra.engine_probe import detect_available_engines

                for cand in detect_available_engines():
                    if cand.name == engine:
                        engine_version = cand.version
                        break
            except Exception:
                engine_version = None
    if topology_fingerprint is None and environment_fingerprint:
        topology_fingerprint = environment_fingerprint[:16]
    return EvidenceEnvelope(
        run_id=run_id,
        plan_hash=phash,
        report_id=report_id_for_run(run_id),
        plan_id=pid,
        target_profile=target_profile,
        engine=engine,
        safety_decisions=tuple(safety_decisions),
        step_reports=sanitized_reports,
        lease_timeline=sanitized_leases,
        observations=sanitized_obs,
        verdict=extra_verdict,
        recovery_state=recovery_state,
        remediation=tuple(extra_remediation),
        environment_fingerprint=environment_fingerprint,
        target_identity=target_identity,
        blast_radius=sanitized_blast,
        compensation_status=compensation_status,
        logical_target=logical_target,
        resolved_target=resolved_target,
        drift_status=drift_status,
        k8s_context=k8s_context,
        k8s_namespace=k8s_namespace,
        k8s_capability_verdict=k8s_capability_verdict,
        k8s_wait_strategy=k8s_wait_strategy,
        k8s_recovery_guidance=k8s_recovery_guidance,
        created_at=utc_now().isoformat(),
        engine_version=engine_version,
        topology_fingerprint=topology_fingerprint,
        execution_intent=(
            None if execution_intent is None else _sanitize_evidence_dict(dict(execution_intent))
        ),
        replay_digest=replay_digest,
        evidence_status=evidence_status,
        action_outcomes=tuple(action_outcomes),
        redaction_metrics=redaction_metrics,
        observation_provenance=dict(observation_provenance or {}),
        slo_outcomes=tuple(slo_outcomes),
        residual_impact=dict(residual_impact or {}),
        emitted_spans=tuple(emitted_spans),
        steady_state=dict(sanitized_steady),
        verification_basis="live" if engine and verdict not in ("", "planned") else "unit_tested",
    )


def redact_envelope(envelope: EvidenceEnvelope) -> EvidenceEnvelope:
    """Return a sanitized copy — the last gate before bytes hit disk.

    ``build_evidence`` already redacts, but any caller can construct an
    ``EvidenceEnvelope`` directly. Enforcing the policy here means no write
    path can leak a secret, and the metrics are recomputed at the boundary so
    they describe what was actually written.
    """
    from mayhem.domain.redaction import RULE_VERSION, redact

    result = redact(envelope.model_dump(mode="json"))
    payload = dict(result.value)
    payload["redaction_metrics"] = {
        "policy_version": RULE_VERSION,
        "redacted_path_count": len(result.removed_paths),
        "redacted_paths": tuple(sorted(set(result.removed_paths))),
    }
    return EvidenceEnvelope.model_validate(payload)


def write_evidence(store: Any, envelope: EvidenceEnvelope) -> None:
    stable = redact_envelope(envelope).model_copy(
        update={"report_id": envelope.report_id or report_id_for_run(envelope.run_id)}
    )
    with store.write() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence_envelopes (run_id TEXT PRIMARY KEY, envelope_json TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT OR REPLACE INTO evidence_envelopes (run_id, envelope_json, created_at) VALUES (?, ?, ?)",
            (stable.run_id, stable.model_dump_json(), stable.created_at),
        )


def load_evidence(store: Any, run_id: str) -> EvidenceEnvelope | None:
    rows = store.query("SELECT envelope_json FROM evidence_envelopes WHERE run_id = ?", (run_id,))
    if not rows:
        return None
    raw = (
        rows[0]["envelope_json"]
        if isinstance(rows[0], dict) or hasattr(rows[0], "__getitem__")
        else rows[0][0]
    )
    try:
        data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        if not data.get("report_id"):
            data["report_id"] = report_id_for_run(str(data.get("run_id", "")))
        return EvidenceEnvelope.model_validate(data)
    except Exception:
        return None


def list_evidence(store: Any, limit: int = 20) -> list[EvidenceEnvelope]:
    rows = store.query(
        "SELECT envelope_json FROM evidence_envelopes ORDER BY created_at DESC LIMIT ?", (limit,)
    )
    out: list[EvidenceEnvelope] = []
    for row in rows:
        raw = (
            row["envelope_json"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[0]
        )
        try:
            data = json.loads(raw) if isinstance(raw, str) else dict(raw)
            if not data.get("report_id"):
                data["report_id"] = report_id_for_run(str(data.get("run_id", "")))
            out.append(EvidenceEnvelope.model_validate(data))
        except Exception:
            continue
    return out


def write_evidence_file(envelope: EvidenceEnvelope, evidence_dir: str | Path) -> Path:
    # Local so this module and mayhem.infra.report can reference each other
    # without a circular import; the dependency is one-directional at call time.
    from mayhem.infra.report import artifact_name, write_report_artifacts

    stable = redact_envelope(envelope).model_copy(
        update={"report_id": envelope.report_id or report_id_for_run(envelope.run_id)}
    )
    directory = Path(evidence_dir)
    directory.mkdir(parents=True, exist_ok=True)
    name = artifact_name(stable.run_id, "evidence")
    target = directory / name
    target.write_text(stable.model_dump_json(indent=2))
    write_report_artifacts(stable, artifact_dir=directory)
    return target


def render_report(envelope: EvidenceEnvelope) -> str:
    lines: list[str] = []
    lines.append(f"# Evidence {envelope.run_id}")
    lines.append("")
    lines.append(f"- plan: {envelope.plan_id} hash {envelope.plan_hash[:12]}")
    lines.append(f"- target: {envelope.target_profile or envelope.target_identity or '-'}")
    lines.append(f"- engine: {envelope.engine or '-'}")
    lines.append(f"- verdict: {envelope.verdict or '-'} recovery {envelope.recovery_state or '-'}")
    if envelope.safety_decisions:
        lines.append(f"- safety: {'; '.join(envelope.safety_decisions)}")
    if envelope.blast_radius:
        lines.append(f"- blast_radius: {envelope.blast_radius}")
    if envelope.compensation_status:
        lines.append(f"- compensation: {envelope.compensation_status}")
    if envelope.logical_target or envelope.resolved_target:
        lines.append(
            f"- logical target: {envelope.logical_target or '-'} "
            f"resolved target: {envelope.resolved_target or '-'} "
            f"drift: {envelope.drift_status or 'not recorded'}"
        )
    if envelope.k8s_context or envelope.k8s_namespace:
        lines.append(
            f"- kubernetes: context={envelope.k8s_context or '-'} "
            f"namespace={envelope.k8s_namespace or '-'} "
            f"verdict={envelope.k8s_capability_verdict or '-'}"
        )
    if envelope.k8s_wait_strategy or envelope.k8s_recovery_guidance:
        lines.append(
            f"- recovery: wait={envelope.k8s_wait_strategy or '-'}; "
            f"guidance={envelope.k8s_recovery_guidance or '-'}"
        )
    lines.append(
        f"- steps: {len(envelope.step_reports)} leases {len(envelope.lease_timeline)} observations {len(envelope.observations)}"
    )
    if envelope.remediation:
        lines.append(f"- remediation: {'; '.join(envelope.remediation)}")
    lines.append("")
    lines.append("## steps")
    for item in envelope.step_reports:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## leases")
    for item in envelope.lease_timeline:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## observations")
    for item in envelope.observations:
        lines.append(f"- {item}")
    return "\n".join(lines)


def verify_evidence(envelope: EvidenceEnvelope) -> dict[str, Any]:
    errors = envelope.completeness_errors()
    return {
        "run_id": envelope.run_id,
        "complete": len(errors) == 0,
        "errors": errors,
        "plan_hash": envelope.plan_hash,
        "verdict": envelope.verdict,
        "step_count": len(envelope.step_reports),
        "lease_count": len(envelope.lease_timeline),
    }
