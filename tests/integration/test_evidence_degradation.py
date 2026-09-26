from __future__ import annotations

from types import SimpleNamespace

from mayhem.cli.lifecycle import _write_evidence_after_run


class BrokenStore:
    def write(self):
        raise OSError("disk unavailable")

    def query(self, _sql, _params=()):
        return []


def test_evidence_persistence_failure_is_visible_and_preserves_recovery_data() -> None:
    preflight = SimpleNamespace(
        plan=None,
        plan_id="run-1",
        target_profile="dev",
        safety_decisions=("allow",),
        environment_fingerprint="env-1",
        target_identity="dev/api",
        blast_radius={"services": 1},
        compensation_status="verified",
        k8s_target_scope="dev",
        k8s_context="",
        k8s_namespace="",
        k8s_capability_verdict="allowed",
        k8s_wait_strategy="",
        k8s_recovery_guidance="",
    )
    result = SimpleNamespace(
        run_id="run-1",
        steps=(SimpleNamespace(step_id="s1", ok=False, detail="dirty", status="dirty"),),
        observability=(),
        verdict="failed",
        status="failed",
        dirty_leases=("lease-1",),
    )
    envelope = _write_evidence_after_run(
        store=BrokenStore(),
        preflight=preflight,
        result=result,
        engine="podman",
        evidence_dir=None,
    )
    assert envelope is not None
    assert envelope.evidence_status == "degraded"
    assert envelope.recovery_state == "dirty"
    assert envelope.step_reports[0]["step_id"] == "s1"
    assert any("evidence persistence failed" in item for item in envelope.remediation)
