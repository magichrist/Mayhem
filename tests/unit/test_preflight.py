from mayhem.controller.preflight import build_preflight
from mayhem.domain.experiments import ExecutionPlan, PlannedStep, Wait
from mayhem.domain.preflight import execution_intent_for, plan_hash_for


def _plan(run_id: str = "r-test") -> ExecutionPlan:
    from mayhem.domain.experiments import ExperimentKind

    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=(PlannedStep(id="wait-0000", seq=0, raw_action=Wait(type="wait", duration=1.0)),),
        config_snapshot_id="cfg-abc",
        topology_snapshot_id="topo-abc",
        environment_fingerprint="fp-123",
    )


def test_equivalent_plans_produce_equivalent_preflight():
    p1 = _plan("r-a")
    p2 = _plan("r-a")
    pf1 = build_preflight(
        spec_path=None,
        compose=None,
        graph=None,
        store=None,
        config_path=None,
        profile=None,
        allow_critical=False,
        target="dev",
        engine="docker",
        plan=p1,
        safety=None,
        fingerprint="fp-123",
        config_snapshot_id="cfg-abc",
        topology_snapshot_id="topo-abc",
    )
    pf2 = build_preflight(
        spec_path=None,
        compose=None,
        graph=None,
        store=None,
        config_path=None,
        profile=None,
        allow_critical=False,
        target="dev",
        engine="docker",
        plan=p2,
        safety=None,
        fingerprint="fp-123",
        config_snapshot_id="cfg-abc",
        topology_snapshot_id="topo-abc",
    )
    assert pf1.plan_hash == pf2.plan_hash
    assert pf1.to_dict()["plan_hash"] == pf2.to_dict()["plan_hash"]
    assert pf1.environment_fingerprint == pf2.environment_fingerprint


def test_preflight_contains_required_fields():
    p = _plan()
    pf = build_preflight(
        spec_path=None,
        compose=None,
        graph=None,
        store=None,
        config_path=None,
        profile=None,
        allow_critical=False,
        target="dev",
        engine="podman",
        plan=p,
        safety=None,
        fingerprint="fp-x",
        config_snapshot_id="cfg-x",
        topology_snapshot_id="topo-x",
    )
    d = pf.to_dict()
    for key in [
        "resolved_target",
        "config_snapshot_id",
        "topology_snapshot_id",
        "environment_fingerprint",
        "safety_decisions",
        "blocked_items",
        "warnings",
        "target_profile",
        "engine",
        "blast_radius",
        "compensation_status",
        "expected_evidence",
        "plan_hash",
        "plan_id",
    ]:
        assert key in d
    assert pf.engine == "podman"
    assert pf.target_profile == "dev"


def test_execution_intent_fields():
    p = _plan()
    pf = build_preflight(
        spec_path=None,
        compose=None,
        graph=None,
        store=None,
        config_path=None,
        profile=None,
        allow_critical=False,
        target="dev",
        engine="docker",
        plan=p,
        safety=None,
        fingerprint="fp-123",
        config_snapshot_id="cfg-abc",
        topology_snapshot_id="topo-abc",
    )
    intent = execution_intent_for(pf, action="run", approval_source="cli --execute")
    assert intent.action == "run"
    assert intent.plan_hash == pf.plan_hash
    assert intent.approval_source == "cli --execute"
    assert intent.target_profile == "dev"


def test_plan_hash_stable():
    p = _plan("r-stable")
    h1 = plan_hash_for(p)
    h2 = plan_hash_for(p)
    assert h1 == h2
    assert len(h1) == 64


def test_no_executor_called_while_producing_preflight(monkeypatch):
    p = _plan()
    monkeypatch.setattr(
        "mayhem.controller.executor.RunEngine",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("executor called")),
    )
    pf = build_preflight(
        spec_path=None,
        compose=None,
        graph=None,
        store=None,
        config_path=None,
        profile=None,
        allow_critical=False,
        target=None,
        engine="docker",
        plan=p,
        safety=None,
        fingerprint="fp",
        config_snapshot_id="cfg",
        topology_snapshot_id="topo",
    )
    assert pf.plan_hash
