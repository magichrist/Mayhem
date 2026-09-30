from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mayhem.infra.report import artifact_name
from mayhem.toolkit.hashing import canonical_json

#: ``artifact_name`` is re-exported here so ``mayhem.cli`` callers keep one
#: import site; the definition lives in ``mayhem.infra.report`` because
#: ``infra.evidence`` needs it too and must not reach upward into ``cli``
#: (layered-architecture contract).
__all__ = ["artifact_name", "plan_hash_from_file"]

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mayhem.controller.steady_state import SteadyStateReport
    from mayhem.domain.steady_state import SteadyStateSpec
    from mayhem.infra.store import Store


def evaluate_steady_state(
    spec: SteadyStateSpec | None,
    *,
    run_id: str,
    config: Any,
    store: Store,
    engine: str = "podman",
    baseline_from: str | None = None,
    during: Mapping[str, float | None] | None = None,
    post: Mapping[str, float | None] | None = None,
    bypasses: Mapping[tuple[str, str], str] | None = None,
    collector: Any | None = None,
) -> SteadyStateReport | None:
    """Capture the baseline, grade the three phases, persist the verdict.

    Returns ``None`` — and touches nothing — when the drill declares no
    ``steady_state:`` block. That is the compatibility guarantee, enforced at
    the entry point rather than by each caller remembering: a run without the
    block performs no capture, writes no ``steady_state_evaluations`` row, and
    renders no extra byte.

    With ``baseline_from``, the baselines come from that earlier run's
    ``pre``-phase rows instead of a fresh capture (plan step 6), and the report
    records which run it was measured against.
    """
    from mayhem.controller.steady_state import (
        BaselineCapture,
        SteadyStateEvaluationRepository,
        baseline_from_run,
        capture_baselines,
        evaluate_run,
    )

    if spec is None or spec.empty:
        return None
    baseline_from = baseline_from or ""
    if baseline_from:
        reused = baseline_from_run(
            store, baseline_from, [str(signal.name) for signal in spec.signals]
        )
        capture = BaselineCapture(baselines=dict(reused), source_id=baseline_from)
    else:
        capture = (
            capture_baselines(spec, config=config, engine=engine, collector=collector)
            if collector is not None
            else capture_baselines(spec, config=config, engine=engine)
        )
    report = evaluate_run(
        spec,
        run_id=run_id,
        capture=capture,
        during=during,
        post=post,
        baseline_from=baseline_from,
        bypasses=bypasses,
    )
    SteadyStateEvaluationRepository(store).save(report)
    return report


def steady_state_display(report: SteadyStateReport | None) -> str:
    """Rendered exactly like the preflight block: absent report, absent output."""
    if report is None:
        return ""
    from mayhem.cli.render import render_steady_state_human

    return "\n".join(render_steady_state_human(report))


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


# Rendered order matches the order the gate enforces its limits in
# (``check_blast_radius``), so the first failing limit on screen is the first
# limit the run will be refused by.
_BLAST_LIMIT_ROWS: tuple[tuple[str, str, str], ...] = (
    ("services_pct", "max_services_pct", "%"),
    ("hosts", "max_hosts", ""),
    ("concurrent_faults", "max_concurrent_faults", ""),
    ("duration_per_fault", "max_duration_per_fault_s", "s"),
)


def blast_radius_display(blast: dict[str, Any]) -> str:
    if not blast:
        return "blast_radius: unknown"
    if blast.get("status") == "unknown":
        return (
            f"blast_radius: unknown — could not compute ({blast.get('error', 'no reason given')})"
        )

    lines: list[str] = []
    for key, cap, unit in _BLAST_LIMIT_ROWS:
        if key not in blast and cap not in blast:
            continue
        value = blast.get(key, "?")
        limit = blast.get(cap, "?")
        ok = blast.get(f"{key}_ok")
        mark = "" if ok is None else (" ok" if ok else " OVER BUDGET")
        lines.append(f"  {key}={value}{unit} of {cap}={limit}{unit}{mark}")

    violations = blast.get("violations") or []
    for violation in violations:
        lines.append(
            f"  WILL REFUSE [{violation.get('rule_id', '?')}] {violation.get('reason', '')}"
        )
        if violation.get("remediation"):
            lines.append(f"    remediation: {violation['remediation']}")

    shown = {key for key, _, _ in _BLAST_LIMIT_ROWS} | {f"{a}_ok" for a, _, _ in _BLAST_LIMIT_ROWS}
    shown |= {cap for _, cap, _ in _BLAST_LIMIT_ROWS} | {"status", "violations"}
    extras = [
        f"{k}={v}"
        for k, v in sorted(blast.items())
        if k not in shown and not isinstance(v, (list, dict))
    ]
    if extras:
        lines.append("  " + ", ".join(extras))
    return "blast_radius:\n" + "\n".join(lines)


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
    """Legacy evidence-shaped intent record.

    .. deprecated:: 0.9.0
        This is the *record* of an approval as it appeared in an evidence
        envelope, not the contract that gates execution. It has no call site in
        mayhem and nothing validates against it, so it cannot refuse anything.
        The gate is :func:`mayhem.domain.execution_intent.require_execution_intent`
        over :class:`mayhem.domain.execution_intent.ExecutionIntent`; the
        run's real intent now travels on the evidence envelope as its
        ``execution_intent`` field, produced by
        :func:`mayhem.infra.evidence.build_evidence`.

        Kept importable for external callers; do not add new ones.
    """
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
    return "warning: implicit execution without --execute is unsafe; use --execute with explicit approval"


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
