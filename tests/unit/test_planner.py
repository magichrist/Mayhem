"""Planner: spec -> honest frozen plan. Refusals are part of the contract.

Drill planning compiles :class:`DrillSpec` into a frozen :class:`ExecutionPlan`.
Refusals are part of the contract.
"""

import pytest

from mayhem.controller.planner import PlanningError, plan_drill
from mayhem.domain.topology import TopologyGraph

# ---------------------------------------------------------------------------
# plan_drill (ADR-0019)
# ---------------------------------------------------------------------------


def _drill_graph() -> TopologyGraph:
    from mayhem.domain.topology import ContainerNode, Edge, EdgeKind, ProcessNode, ServiceNode

    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-api",
                name="api",
                engine="podman",
                runtime_id="cid-api",
                container_name="testcase-api",
                ip_address="172.18.0.2",
                state="running",
            ),
            ServiceNode(id="svc-api", name="api-svc", container_name="testcase-api"),
            ProcessNode(
                id="proc-api",
                name="api-proc",
                pid=4242,
                host_id="h1",
                container_name="testcase-api",
            ),
        ),
        edges=(
            Edge(src="svc-api", dst="ctr-api", kind=EdgeKind.RUNS_ON),
            Edge(src="ctr-api", dst="proc-api", kind=EdgeKind.RUNS_ON),
        ),
    )


def _drill_spec(execution):
    from mayhem.domain.experiments import DrillConfig, DrillContainer, DrillFault, DrillSpec

    return DrillSpec(
        kind="drill",
        name="api-drill",
        config=DrillConfig(),
        containers={
            "testcase-api": DrillContainer(faults=(DrillFault(fault="proc.pause", duration="3s"),))
        },
        execution=execution,
    )


class TestDrillPlanning:
    def test_compiles_valid_spec(self) -> None:
        from mayhem.domain.experiments import ExecutionStep

        plan = plan_drill(
            "r-drill",
            _drill_spec((ExecutionStep(parallel=("testcase-api",)),)),
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        assert plan.kind.value == "drill"
        assert len(plan.steps) == 1
        step = plan.steps[0]
        assert step.fault is not None
        assert step.fault.fault_id == "proc.pause"
        assert step.fault.undo_ops  # write-ahead undo present
        assert step.fault.verify_probes

    def test_missing_container_name_raises(self) -> None:
        from mayhem.domain.experiments import DrillContainer, DrillFault, DrillSpec, ExecutionStep

        spec = DrillSpec(
            kind="drill",
            name="api-drill",
            containers={"ghost": DrillContainer(faults=(DrillFault(fault="proc.pause"),))},
            execution=(ExecutionStep(parallel=("ghost",)),),
        )
        with pytest.raises(PlanningError, match="not found in topology"):
            plan_drill(
                "r-drill",
                spec,
                _drill_graph(),
                config_snapshot_id="c",
                topology_snapshot_id="t",
                environment_fingerprint="f",
            )

    def test_execution_references_undefined_container_raises(self) -> None:
        from mayhem.domain.experiments import ExecutionStep

        spec = _drill_spec((ExecutionStep(parallel=("not-a-container",)),))
        with pytest.raises(PlanningError, match="not defined"):
            plan_drill(
                "r-drill",
                spec,
                _drill_graph(),
                config_snapshot_id="c",
                topology_snapshot_id="t",
                environment_fingerprint="f",
            )

    def test_parallel_block_produces_per_container_steps(self) -> None:
        from mayhem.domain.experiments import (
            DrillContainer,
            DrillFault,
            DrillSpec,
            ExecutionStep,
        )
        from mayhem.domain.topology import ContainerNode, Edge, EdgeKind, ProcessNode

        graph = TopologyGraph(
            nodes=(
                ContainerNode(
                    id="ctr-a",
                    name="a",
                    engine="podman",
                    runtime_id="a",
                    container_name="c-a",
                    state="running",
                ),
                ContainerNode(
                    id="ctr-b",
                    name="b",
                    engine="podman",
                    runtime_id="b",
                    container_name="c-b",
                    state="running",
                ),
                ProcessNode(id="proc-a", name="pa", pid=1, host_id="h", container_name="c-a"),
                ProcessNode(id="proc-b", name="pb", pid=2, host_id="h", container_name="c-b"),
            ),
            edges=(
                Edge(src="ctr-a", dst="proc-a", kind=EdgeKind.RUNS_ON),
                Edge(src="ctr-b", dst="proc-b", kind=EdgeKind.RUNS_ON),
            ),
        )
        spec = DrillSpec(
            kind="drill",
            name="two",
            containers={
                "c-a": DrillContainer(faults=(DrillFault(fault="proc.pause"),)),
                "c-b": DrillContainer(faults=(DrillFault(fault="proc.pause"),)),
            },
            execution=(ExecutionStep(parallel=("c-a", "c-b")),),
        )
        plan = plan_drill(
            "r-two",
            spec,
            graph,
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        assert len(plan.steps) == 2
        seqs = [s.seq for s in plan.steps]
        assert seqs == sorted(seqs)
        # Parallel containers in one block share the same seq for concurrent execution.
        assert len(set(seqs)) == 1
        assert all(s.fault is not None for s in plan.steps)

    def test_wait_block_produces_wait_step(self) -> None:
        from mayhem.domain.experiments import ExecutionStep

        plan = plan_drill(
            "r-wait",
            _drill_spec(
                (
                    ExecutionStep(parallel=("testcase-api",)),
                    ExecutionStep(wait="5s"),
                )
            ),
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        fault_step = plan.steps[0]
        wait_step = plan.steps[1]
        assert fault_step.fault is not None
        assert wait_step.fault is None
        assert wait_step.raw_action.type == "wait"
        assert float(wait_step.raw_action.duration) == 5.0

    def test_check_block_produces_check_http_step(self) -> None:
        from mayhem.domain.experiments import (
            CheckExpectation,
            CheckProbe,
            ExecutionStep,
        )

        plan = plan_drill(
            "r-check",
            _drill_spec(
                (
                    ExecutionStep(parallel=("testcase-api",)),
                    ExecutionStep(
                        check=(
                            CheckProbe(
                                http="http://testcase-api:8080/health",
                                expect=CheckExpectation(status=200),
                            ),
                        )
                    ),
                )
            ),
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        check_step = plan.steps[1]
        assert check_step.fault is None
        assert check_step.raw_action.type == "check_http"
        assert check_step.raw_action.url == "http://testcase-api:8080/health"
        assert check_step.raw_action.expected_status == 200

    def test_sequential_block_preserves_order(self) -> None:
        from mayhem.domain.experiments import ExecutionStep

        plan = plan_drill(
            "r-seq",
            _drill_spec((ExecutionStep(sequential=("testcase-api",)),)),
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        assert len(plan.steps) == 1
        assert plan.steps[0].fault is not None
