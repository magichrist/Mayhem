"""Planner: spec -> honest frozen plan. Refusals are part of the contract."""
import random

import pytest

from mayhem.controller.planner import PlanningError, plan_deterministic, plan_random
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import (
    DeterministicExperiment,
    ExperimentMetadata,
    InjectFault,
    Parallel,
    RandomExperiment,
    SelectionPolicy,
    Step,
    Wait,
)
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import (
    NodeKind,
    ProcessNode,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ProcessNode(id="n-proc", name="api-pid", pid=4242, host_id="h1"),
            ServiceNode(id="n-svc", name="api"),
        ),
        edges=(),
    )


def _exp(*steps: Step, risk_ceiling: RiskLevel | None = None) -> DeterministicExperiment:
    from mayhem.domain.experiments import Constraints

    return DeterministicExperiment(
        metadata=ExperimentMetadata(name="proc-pause-drill"),
        constraints=Constraints(risk_ceiling=risk_ceiling),
        steps=tuple(steps),
    )


_PAUSE = Step(id="s1", action=InjectFault(fault="proc.pause", selectors=(TargetSelector(kind=NodeKind.PROCESS, expr="name=api-pid"),), duration=10.0))


class TestDeterministicPlanning:
    def test_compiles_fault_with_targets_and_undo_contract(self) -> None:
        plan = plan_deterministic(
            "r-1", _exp(_PAUSE), _graph(),
            config_snapshot_id="cfg-1", topology_snapshot_id="topo-1",
            environment_fingerprint="fp",
        )
        assert len(plan.steps) == 1
        fault = plan.steps[0].fault
        assert fault is not None and fault.fault_id == "proc.pause"
        assert fault.targets[0].node_ids == frozenset({"n-proc"})
        undo_args = [op.args for op in fault.undo_ops]
        assert {"pid": "4242"} in undo_args
        assert fault.verify_probes  # write-ahead verify present

    def test_unresolved_selector_refused(self) -> None:
        bad = Step(
            id="s1",
            action=InjectFault(
                fault="proc.pause",
                selectors=(TargetSelector(kind=NodeKind.PROCESS, expr="name=ghost"),),
                duration=10.0,
            ),
        )
        with pytest.raises(PlanningError, match="ghost"):
            plan_deterministic(
                "r-1", _exp(bad), _graph(),
                config_snapshot_id="c", topology_snapshot_id="t", environment_fingerprint="f",
            )

    def test_unknown_fault_refused_at_authoring(self) -> None:
        # The domain id-prefix law refuses unknown faults before planning sees them.
        with pytest.raises(SchemaValidationError, match="quantum"):
            Step(
                id="s1",
                action=InjectFault(
                    fault="quantum.flip",
                    selectors=(TargetSelector(kind=NodeKind.PROCESS, expr="x"),),
                    duration=10.0,
                ),
            )

    def test_wrong_node_kind_refused(self) -> None:
        bad = Step(
            id="s1",
            action=InjectFault(
                fault="container.kill",  # containers only; graph has none
                selectors=(TargetSelector(kind=NodeKind.CONTAINER, expr="name=api-pid"),),
                duration=10.0,
            ),
        )
        with pytest.raises(PlanningError, match="unresolved"):
            plan_deterministic(
                "r-1", _exp(bad), _graph(),
                config_snapshot_id="c", topology_snapshot_id="t", environment_fingerprint="f",
            )

    def test_duration_over_cap_refused(self) -> None:
        bad = Step(
            id="s1",
            action=InjectFault(
                fault="proc.pause",
                selectors=(TargetSelector(kind=NodeKind.PROCESS, expr="name=api-pid"),),
                duration=700.0,  # cap 600
            ),
        )
        with pytest.raises(PlanningError, match="exceeds cap"):
            plan_deterministic(
                "r-1", _exp(bad), _graph(),
                config_snapshot_id="c", topology_snapshot_id="t", environment_fingerprint="f",
            )

    def test_parallel_flattens_branches(self) -> None:
        wait = Step(id="w", action=Wait(duration="1s"))
        par = Step(
            id="p",
            action=Parallel(branches=((wait.action,), (_PAUSE.action,))),
        )
        plan = plan_deterministic(
            "r-1", _exp(par, wait), _graph(),
            config_snapshot_id="c", topology_snapshot_id="t", environment_fingerprint="f",
        )
        planned_faults = [s for s in plan.steps if s.fault is not None]
        assert len(planned_faults) == 1
        assert planned_faults[0].id.startswith("p.")

    def test_no_fault_plan_refused(self) -> None:
        only_wait = Step(id="w", action=Wait(duration="1s"))
        with pytest.raises(PlanningError, match="no fault injection"):
            plan_deterministic(
                "r-1", _exp(only_wait), _graph(),
                config_snapshot_id="c", topology_snapshot_id="t", environment_fingerprint="f",
            )


class TestRandomPlanning:
    def test_same_seed_same_plan(self) -> None:
        exp = RandomExperiment(
            metadata=ExperimentMetadata(name="maniac"),
            seed=7,
            selection=SelectionPolicy(count=3),
        )
        kwargs = dict(config_snapshot_id="c", topology_snapshot_id="t", environment_fingerprint="f")
        a = plan_random("r-a", exp, _graph(), rng_factory=lambda seed: random.Random(seed), **kwargs)
        b = plan_random("r-b", exp, _graph(), rng_factory=lambda seed: random.Random(seed), **kwargs)
        faults_a = [(s.fault.fault_id, sorted(n for t in s.fault.targets for n in t.node_ids)) for s in a.steps if s.fault]
        faults_b = [(s.fault.fault_id, sorted(n for t in s.fault.targets for n in t.node_ids)) for s in b.steps if s.fault]
        assert faults_a == faults_b

    def test_only_compensatable_faults_enter_lottery(self) -> None:
        exp = RandomExperiment(metadata=ExperimentMetadata(name="maniac"), seed=1)
        kwargs = dict(config_snapshot_id="c", topology_snapshot_id="t", environment_fingerprint="f")
        plan = plan_random("r-1", exp, _graph(), rng_factory=lambda seed: random.Random(seed), **kwargs)
        for step in plan.steps:
            if step.fault is not None:
                assert step.fault.undo_ops  # every chosen fault is compensatable

    def test_weights_skew_lottery(self) -> None:
        kwargs = dict(config_snapshot_id="c", topology_snapshot_id="t", environment_fingerprint="f",
                      rng_factory=lambda seed: random.Random(seed))
        weighted = RandomExperiment(
            metadata=ExperimentMetadata(name="maniac"),
            seed=3,
            selection=SelectionPolicy(count=1, weights={"proc.pause": 1000.0}),
        )
        seen = {
            p.steps[0].fault.fault_id
            for i in range(20)
            if (p := plan_random(f"w-{i}", weighted, _graph(), **kwargs)).steps[0].fault
        }
        assert "proc.pause" in seen  # heavy weight dominates the draw

    def test_audit_sink_receives_decision(self) -> None:
        captured: list[dict] = []
        exp = RandomExperiment(metadata=ExperimentMetadata(name="maniac"), seed=11,
                               selection=SelectionPolicy(count=2))
        plan_random("r-audit", exp, _graph(),
                    config_snapshot_id="c", topology_snapshot_id="t", environment_fingerprint="f",
                    audit_sink=captured.append)
        row = captured[0]
        assert row["seed"] == 11
        assert len(row["candidates"]) >= 2
        assert set(row["weights"]) == set(row["candidates"])
        state = row["rng_state"]
        assert isinstance(state[0], int) and isinstance(state[1], list)
