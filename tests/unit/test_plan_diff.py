import json

from mayhem.controller.plan_diff import diff_plans
from mayhem.domain.experiments import ExecutionPlan, ExperimentKind, PlannedStep, Wait


def _plan(run_id: str, steps) -> ExecutionPlan:
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=tuple(steps),
        config_snapshot_id="cfg-1",
        topology_snapshot_id="topo-1",
        environment_fingerprint="fp-1",
    )


def test_diff_equal_plans():
    s = PlannedStep(id="wait-0000", seq=0, raw_action=Wait(type="wait", duration=1.0))
    p1 = _plan("r-1", [s])
    p2 = _plan("r-1", [s])
    diff = diff_plans(p1, p2)
    assert diff["equal"] is True
    assert diff["added"] == []
    assert diff["removed"] == []
    assert diff["changed_keys"] == []
    assert "authored_hash" in diff and "accepted_hash" in diff
    assert diff["authored_hash"] == diff["accepted_hash"]


def test_diff_detects_added_step():
    s1 = PlannedStep(id="wait-0000", seq=0, raw_action=Wait(type="wait", duration=1.0))
    s2 = PlannedStep(id="wait-0001", seq=1, raw_action=Wait(type="wait", duration=2.0))
    p1 = _plan("r-1", [s1, s2])
    p2 = _plan("r-1", [s1])
    diff = diff_plans(p1, p2)
    assert diff["equal"] is False
    assert "wait-0001" in diff["added"]


def test_diff_schema_keys_stable_ordering():
    s = PlannedStep(id="wait-0000", seq=0, raw_action=Wait(type="wait", duration=1.0))
    p1 = _plan("r-1", [s])
    p2 = _plan("r-1", [s])
    diff = diff_plans(p1, p2)
    expected_keys = ["accepted_hash", "added", "authored_hash", "changed_keys", "equal", "removed"]
    assert sorted(diff.keys()) == expected_keys


def test_diff_json_roundtrip():
    s = PlannedStep(id="wait-0000", seq=0, raw_action=Wait(type="wait", duration=1.0))
    p = _plan("r-1", [s])
    payload = json.loads(p.model_dump_json())
    diff = diff_plans(payload, payload)
    assert diff["equal"] is True
