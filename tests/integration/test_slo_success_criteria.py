"""SLO success criteria through the real evidence path (task 13)."""

from __future__ import annotations

import json

from mayhem.domain.observations import (
    CriterionKind,
    CriterionOperator,
    ObservationQuery,
    ObservationResult,
    ObservationStatus,
    SloCriterion,
    collect,
    evaluate_all,
)
from mayhem.infra.evidence import build_evidence, write_evidence, write_evidence_file
from mayhem.infra.store import Store
from mayhem.providers.observation import StaticObservationProvider


def _plan(slo: list[dict]) -> object:
    from mayhem.domain.experiments import ExecutionPlan, ExperimentKind

    return ExecutionPlan(
        run_id="slo-run",
        kind=ExperimentKind.DRILL,
        steps=(),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
        slo=tuple(slo),
    )


def test_slo_criteria_reach_the_evidence_envelope() -> None:
    from mayhem.cli.lifecycle import _observation_provider_for, _slo_from_plan

    plan = _plan(
        [
            {
                "metric": "http.latency",
                "kind": "latency",
                "operator": "lte",
                "threshold": 250.0,
                "unit": "ms",
                "window_s": 30.0,
            }
        ]
    )
    queries, criteria = _slo_from_plan(plan)
    assert len(queries) == 1
    assert isinstance(criteria[0], SloCriterion)

    provider = _observation_provider_for("kubernetes")
    assert provider is not None
    provider.set("http.latency", 100.0)  # type: ignore[attr-defined]
    observed = collect(provider, queries)
    outcomes = evaluate_all(criteria, observed)

    envelope = build_evidence(
        run_id="slo-run",
        plan=plan,
        target_profile=None,
        engine="kubernetes",
        safety_decisions=(),
        step_reports=(),
        lease_timeline=(),
        observations=(),
        verdict="pass",
        recovery_state="none",
        remediation=(),
        observation_provenance=__import__(
            "mayhem.domain.observations", fromlist=["provenance_summary"]
        ).provenance_summary(observed),
        slo_outcomes=tuple(outcome.to_dict() for outcome in outcomes),
    )
    assert envelope.observation_provenance["available"] == 1
    assert envelope.slo_outcomes[0]["passed"] is True
    assert envelope.slo_outcomes[0]["observed"] == 100.0


def test_a_failing_slo_is_recorded_as_a_failure() -> None:
    from mayhem.cli.lifecycle import _slo_from_plan

    plan = _plan(
        [{"metric": "cpu.saturation", "kind": "saturation", "operator": "lte", "threshold": 0.8, "unit": "ratio"}]
    )
    _, criteria = _slo_from_plan(plan)
    provider = StaticObservationProvider({"cpu.saturation": 0.99})
    outcomes = evaluate_all(criteria, collect(provider, (ObservationQuery(metric="cpu.saturation", unit="ratio"),)))
    assert outcomes[0].passed is False
    assert outcomes[0].kind is CriterionKind.SATURATION


def test_missing_observation_degrades_instead_of_passing() -> None:
    from mayhem.cli.lifecycle import _slo_from_plan

    plan = _plan([{"metric": "absent.metric", "kind": "latency", "operator": "lte", "threshold": 1.0}])
    _, criteria = _slo_from_plan(plan)
    outcomes = evaluate_all(criteria, ())
    assert outcomes[0].passed is False
    assert "missing" in outcomes[0].reason


def test_observation_provenance_persists_and_is_redacted(tmp_path) -> None:
    envelope = build_evidence(
        run_id="slo-redact",
        plan=None,
        target_profile=None,
        engine="kubernetes",
        safety_decisions=(),
        step_reports=({"detail": "token=ghp_leakme", "password": "hunter2-plaintext"},),
        lease_timeline=(),
        observations=(),
        verdict="pass",
        recovery_state="none",
        remediation=(),
        observation_provenance={"schema_version": "1.0", "count": 1, "available": 1},
        slo_outcomes=({"criterion_id": "m", "passed": True, "reason": "", "unit": "ms"},),
    )
    store = Store.open_migrated(tmp_path / "slo.db")
    try:
        write_evidence(store, envelope)
        rows = store.query("SELECT envelope_json FROM evidence_envelopes")
    finally:
        store.close()
    blob = json.dumps([dict(row) for row in rows])
    assert "ghp_leakme" not in blob
    assert "hunter2-plaintext" not in blob
    assert "observation_provenance" in blob
    assert "slo_outcomes" in blob


def test_evidence_file_keeps_provenance_and_drops_secrets(tmp_path) -> None:
    envelope = build_evidence(
        run_id="slo-file",
        plan=None,
        target_profile=None,
        engine="kubernetes",
        safety_decisions=(),
        step_reports=({"detail": "password=hunter2-plaintext", "registry_token": "reg-secret-xyz"},),
        lease_timeline=(),
        observations=(),
        verdict="pass",
        recovery_state="none",
        remediation=(),
        observation_provenance={"schema_version": "1.0", "count": 2, "missing": 0},
    )
    path = write_evidence_file(envelope, tmp_path / "evidence")
    blob = path.read_text()
    assert "hunter2-plaintext" not in blob
    assert "reg-secret-xyz" not in blob
    assert "observation_provenance" in blob


def test_recovery_time_criterion_reports_its_unit_and_window() -> None:
    criterion = SloCriterion(
        kind=CriterionKind.RECOVERY_TIME,
        metric="recovery.time",
        operator=CriterionOperator.LTE,
        threshold=15.0,
        unit="s",
        window_s=120.0,
        name="recover-under-15s",
    )
    observation = ObservationResult(
        metric="recovery.time", value=9.0, unit="s", window_s=120.0, status=ObservationStatus.OK
    )
    outcome = criterion.evaluate(observation)
    assert outcome.passed is True
    assert outcome.unit == "s"
    assert outcome.criterion_id == "recover-under-15s"
