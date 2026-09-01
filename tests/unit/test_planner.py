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
    from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
    from mayhem.domain.topology import ContainerNode, Edge, EdgeKind, ProcessNode, ServiceNode

    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-api",
                name="api",
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="cid-api"
                ),
                runtime_metadata=RuntimeMetadata(service="api-svc", name="api"),
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

    def test_container_target_carries_planned_runtime_identity(self) -> None:
        from mayhem.domain.experiments import ExecutionStep
        from mayhem.domain.identity import RuntimeIdentity

        plan = plan_drill(
            "r-drill",
            _drill_spec((ExecutionStep(parallel=("testcase-api",)),)),
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        step = plan.steps[0]
        assert step.runtime_identity == RuntimeIdentity(
            runtime="podman", host_id="h1", runtime_id="cid-api"
        )
        assert step.fault is not None
        assert step.fault.runtime_identity == step.runtime_identity
        assert step.fault.runtime_identity.key() == "podman|h1|cid-api"

    def test_identity_is_none_when_node_has_no_container_identity(self) -> None:
        from mayhem.domain.identity import RuntimeIdentity
        from mayhem.domain.topology import ServiceNode

        from mayhem.controller.planner import _resolve_planned_identity

        # A service is a resolver key only (ADR-M1-1): it contributes no
        # RuntimeIdentity, so the planned identity for a service-only match is
        # None even though the plan succeeded.
        service = ServiceNode(
            id="svc-x",
            name="x-svc",
            container_name="x",
        )
        assert _resolve_planned_identity((service,)) is None

        # A ContainerNode (which always carries a RuntimeIdentity) is the one
        # that contributes the canonical planned identity.
        from mayhem.domain.topology import ContainerNode

        container = ContainerNode(
            id="ctr-x",
            name="x",
            engine="podman",
            runtime_identity=RuntimeIdentity(runtime="podman", host_id="h1", runtime_id="c-x"),
            container_name="x",
        )
        assert _resolve_planned_identity((service, container)) == RuntimeIdentity(
            runtime="podman", host_id="h1", runtime_id="c-x"
        )


    def test_mem_exhaust_accepts_byte_amount_dsl(self) -> None:
        from mayhem.domain.experiments import DrillContainer, DrillFault, DrillSpec, ExecutionStep

        spec = DrillSpec(
            kind="drill",
            name="mem-drill",
            containers={
                "testcase-api": DrillContainer(
                    faults=(DrillFault(fault="mem.exhaust", amount="256M", duration="10s"),)
                )
            },
            execution=(ExecutionStep(parallel=("testcase-api",)),),
        )
        plan = plan_drill(
            "r-mem",
            spec,
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        fault = plan.steps[0].fault
        assert fault is not None
        assert fault.params["amount"] == 256 * 1024 * 1024
        payload = next(op for op in fault.undo_ops if op.op == "payload.undo")
        source = str(payload.args["payload"])
        assert "amount = 268435456" in source
        assert "goal = amount if amount > 0" in source
        assert fault.verify_probes  # lease activation demands recovery evidence
        probe = fault.verify_probes[0]
        assert probe.probe == "exec"
        assert probe.args["incontainer"] is True
        assert "test ! -e" in str(probe.args["cmd"])
        assert probe.args["pid"] == "ctr-api:@live-pid"
        assert "test ! -e" in str(probe.args["cmd"])
        assert probe.args["incontainer"] is True

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

    def test_multi_fault_container_plans_all_faults_with_shared_group(self) -> None:
        from mayhem.domain.experiments import (
            DrillContainer,
            DrillFault,
            DrillSpec,
            ExecutionStep,
            GroupMode,
        )

        spec = DrillSpec(
            kind="drill",
            name="multi",
            containers={
                "testcase-api": DrillContainer(
                    faults=(
                        DrillFault(fault="proc.pause"),
                        DrillFault(fault="proc.pause"),
                        DrillFault(fault="proc.pause"),
                    )
                )
            },
            execution=(ExecutionStep(sequential=("testcase-api",)),),
        )
        plan = plan_drill(
            "r1",
            spec,
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="e",
        )
        fault_steps = [s for s in plan.steps if s.fault is not None]
        assert len(fault_steps) == 3  # no faults[0]-only regression
        group_ids = {s.execution_group_id for s in fault_steps}
        assert len(group_ids) == 1  # all members share one group
        for step in fault_steps:
            assert step.group_mode == GroupMode.SEQUENTIAL
            assert step.group_path == "/testcase-api"
            assert step.execution_group_id == next(iter(group_ids))

    def test_parallel_block_produces_per_container_steps(self) -> None:
        from mayhem.domain.experiments import (
            DrillContainer,
            DrillFault,
            DrillSpec,
            ExecutionStep,
        )
        from mayhem.domain.identity import RuntimeIdentity
        from mayhem.domain.topology import ContainerNode, Edge, EdgeKind, ProcessNode

        graph = TopologyGraph(
            nodes=(
                ContainerNode(
                    id="ctr-a",
                    name="a",
                    engine="podman",
                    runtime_identity=RuntimeIdentity(runtime="podman", host_id="h", runtime_id="a"),
                    container_name="c-a",
                    state="running",
                ),
                ContainerNode(
                    id="ctr-b",
                    name="b",
                    engine="podman",
                    runtime_identity=RuntimeIdentity(runtime="podman", host_id="h", runtime_id="b"),
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
