"""Planner: spec -> honest frozen plan. Refusals are part of the contract.

Drill planning compiles :class:`DrillSpec` into a frozen :class:`ExecutionPlan`.
Refusals are part of the contract.
"""

import json

import pytest

from mayhem.controller.planner import PlanningError, plan_drill
from mayhem.domain.experiments import DrillSpec, ExecutionStep
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
            Edge(src="ctr-api", dst="proc-api", kind=EdgeKind.RUNS_ON),
        ),
    )


def _drill_spec(execution: tuple[ExecutionStep, ...]) -> DrillSpec:
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

    def test_net_load_embeds_user_script_against_spec_dir(self, tmp_path) -> None:
        from mayhem.domain.experiments import (
            DrillConfig,
            DrillContainer,
            DrillFault,
            DrillSpec,
            ExecutionStep,
        )

        script = tmp_path / "k6" / "script.js"
        script.parent.mkdir()
        script.write_text(
            "import http from 'k6/http';\n"
            "export default function () {\n"
            '  http.get("http://10.0.0.5:8080/");\n'
            "}\n",
            encoding="utf-8",
        )
        spec = DrillSpec(
            kind="drill",
            name="load-drill",
            config=DrillConfig(),
            containers={
                "testcase-api": DrillContainer(
                    faults=(
                        DrillFault(
                            fault="net.load",
                            duration="120s",
                            users=10000,
                            script="k6/script.js",
                        ),
                    )
                )
            },
            execution=(ExecutionStep(parallel=("testcase-api",)),),
        )
        plan = plan_drill(
            "r-drill",
            spec,
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
            spec_dir=str(tmp_path),
        )
        step = plan.steps[0]
        assert step.fault is not None
        assert step.fault.fault_id == "net.load"
        assert step.fault.params["script"] == "k6/script.js"
        assert "http://10.0.0.5:8080/" in step.fault.params["script_content"]
        inject = json.loads(step.fault.undo_ops[0].args["inject_argv"])
        assert "k6 run -u 10000 -d 120s" in inject[-1]
        assert "http://10.0.0.5:8080/;" in inject[-1] or "http://10.0.0.5:8080/" in inject[-1]

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
        from mayhem.controller.planner import _resolve_planned_identity
        from mayhem.domain.identity import RuntimeIdentity
        from mayhem.domain.topology import ServiceNode

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

    def test_recovery_defaults_true_from_config(self) -> None:
        from mayhem.domain.experiments import (
            DrillContainer,
            DrillFault,
            DrillSpec,
            ExecutionStep,
        )

        spec = DrillSpec(
            kind="drill",
            name="recover-on",
            containers={
                "testcase-api": DrillContainer(
                    faults=(DrillFault(fault="proc.pause", duration="3s"),)
                )
            },
            execution=(ExecutionStep(parallel=("testcase-api",)),),
        )
        plan = plan_drill(
            "r-rec-default",
            spec,
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        assert plan.steps[0].fault is not None
        assert plan.steps[0].fault.recovery is True
        assert spec.config.recovery is True

    def test_config_recovery_false_propagates_to_plan(self) -> None:
        from mayhem.domain.experiments import (
            DrillConfig,
            DrillContainer,
            DrillFault,
            DrillSpec,
            ExecutionStep,
        )

        spec = DrillSpec(
            kind="drill",
            name="recover-off",
            config=DrillConfig(recovery=False),
            containers={
                "testcase-api": DrillContainer(
                    faults=(DrillFault(fault="proc.pause", duration="3s"),)
                )
            },
            execution=(ExecutionStep(parallel=("testcase-api",)),),
        )
        plan = plan_drill(
            "r-rec-off",
            spec,
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        fault = plan.steps[0].fault
        assert fault is not None
        assert fault.recovery is False
        assert fault.undo_ops  # write-ahead undo must still be carried

    def test_per_fault_recovery_overrides_config(self) -> None:
        from mayhem.domain.experiments import (
            DrillConfig,
            DrillContainer,
            DrillFault,
            DrillSpec,
            ExecutionStep,
        )

        spec = DrillSpec(
            kind="drill",
            name="recover-mixed",
            config=DrillConfig(recovery=False),
            containers={
                "testcase-api": DrillContainer(
                    faults=(
                        DrillFault(fault="proc.pause", duration="3s"),
                        DrillFault(fault="proc.pause", duration="3s", recovery=True),
                    )
                )
            },
            execution=(ExecutionStep(sequential=("testcase-api",)),),
        )
        plan = plan_drill(
            "r-rec-mixed",
            spec,
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        faults = [s.fault for s in plan.steps if s.fault is not None]
        assert [f.recovery for f in faults] == [False, True]

    def test_grouped_params_map_honored(self) -> None:
        from mayhem.domain.experiments import DrillContainer, DrillFault, DrillSpec, ExecutionStep

        spec = DrillSpec(
            kind="drill",
            name="grouped-params",
            containers={
                "testcase-api": DrillContainer(
                    faults=(
                        DrillFault(
                            fault="net.latency",
                            duration="10s",
                            params={"seconds": "5s", "jitter_ms": 10},
                        ),
                    )
                )
            },
            execution=(ExecutionStep(parallel=("testcase-api",)),),
        )
        plan = plan_drill(
            "r-grouped",
            spec,
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        fault = plan.steps[0].fault
        assert fault is not None
        assert fault.params["seconds"] == 5.0
        assert fault.params["jitter_ms"] == 10

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

    def test_check_spec_block_compiles_to_check_spec_step(self) -> None:
        from mayhem.domain.checks import CheckLocus, CheckSpec, FileProbe
        from mayhem.domain.experiments import ExecutionStep

        plan = plan_drill(
            "r-check-spec",
            _drill_spec(
                (
                    ExecutionStep(parallel=("testcase-api",)),
                    ExecutionStep(
                        check_spec=(
                            CheckSpec(
                                id="file-present",
                                probe=FileProbe(path="/var/run/app.pid"),
                                execution=CheckLocus.HOST,
                                target="testcase-api",
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
        assert check_step.raw_action.type == "check_spec"
        assert check_step.raw_action.check_id == "file-present"
        assert check_step.raw_action.probe.type == "file"
        assert check_step.raw_action.probe.path == "/var/run/app.pid"
        assert check_step.raw_action.execution == CheckLocus.HOST
        assert check_step.raw_action.target == "testcase-api"

    def test_check_spec_accepts_bare_locus_for_inference(self) -> None:
        from mayhem.domain.checks import CheckSpec, MetricProbe
        from mayhem.domain.experiments import ExecutionStep

        plan = plan_drill(
            "r-check-bare",
            _drill_spec(
                (
                    ExecutionStep(parallel=("testcase-api",)),
                    ExecutionStep(
                        check_spec=(
                            CheckSpec(
                                id="metric-up",
                                probe=MetricProbe(endpoint="http://svc:9090", query="up"),
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
        assert check_step.raw_action.type == "check_spec"
        assert check_step.raw_action.execution is None  # bare → executor infers locus
        assert check_step.raw_action.probe.type == "metric"

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


# ---------------------------------------------------------------------------
# restrict_plan_to_container (--ctr scoping)
# ---------------------------------------------------------------------------
def _two_container_graph() -> TopologyGraph:
    from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
    from mayhem.domain.topology import ContainerNode, Edge, EdgeKind, ProcessNode, ServiceNode

    return TopologyGraph(
        nodes=(
            ServiceNode(id="svc-api", name="api", container_name="testcase-api"),
            ProcessNode(
                id="proc-api",
                name="api-python",
                pid=4242,
                host_id="h1",
                container_name="testcase-api",
            ),
            ContainerNode(
                id="ctr-api",
                name="testcase-api",
                engine="podman",
                container_name="testcase-api",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="cid-api"
                ),
                runtime_metadata=RuntimeMetadata(service="api", name="testcase-api"),
                ip_address="172.18.0.2",
                state="running",
            ),
            ServiceNode(id="svc-web", name="web", container_name="testcase-web"),
            ProcessNode(
                id="proc-web",
                name="web-node",
                pid=4243,
                host_id="h1",
                container_name="testcase-web",
            ),
            ContainerNode(
                id="ctr-web",
                name="testcase-web",
                engine="podman",
                container_name="testcase-web",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="cid-web"
                ),
                runtime_metadata=RuntimeMetadata(service="web", name="testcase-web"),
                ip_address="172.18.0.3",
                state="running",
            ),
        ),
        edges=(
            Edge(src="svc-api", dst="ctr-api", kind=EdgeKind.RUNS_ON),
            Edge(src="svc-web", dst="ctr-web", kind=EdgeKind.RUNS_ON),
            Edge(src="ctr-web", dst="proc-web", kind=EdgeKind.RUNS_ON),
        ),
    )


def _two_container_spec() -> DrillSpec:
    from mayhem.domain.experiments import DrillConfig, DrillContainer, DrillFault, ExecutionStep

    return DrillSpec(
        kind="drill",
        name="two-ctr",
        config=DrillConfig(),
        containers={
            "testcase-api": DrillContainer(faults=(DrillFault(fault="proc.pause", duration="3s"),)),
            "testcase-web": DrillContainer(faults=(DrillFault(fault="proc.pause", duration="3s"),)),
        },
        execution=(
            ExecutionStep(wait=1.0),
            ExecutionStep(parallel=("testcase-api", "testcase-web")),
            ExecutionStep(wait=2.0),
        ),
    )


class TestRestrictPlanToContainer:
    def test_scopes_execution_to_one_container(self) -> None:
        from mayhem.controller.planner import restrict_plan_to_container

        plan = plan_drill(
            "r-two",
            _two_container_spec(),
            _two_container_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        assert sum(1 for s in plan.steps if s.fault is not None) == 2

        scoped = restrict_plan_to_container(plan, "testcase-api", _two_container_graph())
        kept_faults = [s for s in scoped.steps if s.fault is not None]
        assert len(kept_faults) == 1
        assert kept_faults[0].fault.fault_id == "proc.pause"
        # Plain waits/checks for other containers are dropped.
        assert all(s.raw_action.type != "wait" for s in scoped.steps)
        assert all(s.id.startswith("testcase-api") for s in scoped.steps)

    def test_drops_other_containers_and_keeps_timeout_shape(self) -> None:
        from mayhem.controller.planner import restrict_plan_to_container

        plan = plan_drill(
            "r-two",
            _two_container_spec(),
            _two_container_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        scoped = restrict_plan_to_container(plan, "testcase-web", _two_container_graph())
        ids = {s.id for s in scoped.steps}
        assert "testcase-api-0000" not in ids
        assert any(i.startswith("testcase-web") for i in ids)
        assert scoped.run_id == plan.run_id  # identity preserved

    def test_missing_container_is_a_planning_error(self) -> None:
        from mayhem.controller.planner import restrict_plan_to_container

        plan = plan_drill(
            "r-two",
            _two_container_spec(),
            _two_container_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        with pytest.raises(PlanningError, match="not found in topology graph"):
            restrict_plan_to_container(plan, "unrelated", _two_container_graph())

    def test_container_without_faults_is_rejected(self) -> None:
        from mayhem.controller.planner import restrict_plan_to_container
        from mayhem.domain.experiments import DrillConfig, DrillContainer, DrillFault

        graph = _two_container_graph()
        spec = DrillSpec(
            kind="drill",
            name="only-web",
            config=DrillConfig(),
            containers={
                "testcase-web": DrillContainer(
                    faults=(DrillFault(fault="proc.pause", duration="3s"),)
                ),
            },
            execution=(ExecutionStep(parallel=("testcase-web",)),),
        )
        plan = plan_drill(
            "r-web",
            spec,
            graph,
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        with pytest.raises(PlanningError, match="has no fault steps targeting"):
            restrict_plan_to_container(plan, "testcase-api", graph)


# ---------------------------------------------------------------------------
# synthesize_candidate_spec (feat-2 §A1)
# ---------------------------------------------------------------------------


class TestSynthesizeCandidateSpec:
    def test_produces_single_fault_spec(self) -> None:
        from mayhem.controller.planner import synthesize_candidate_spec
        from mayhem.domain.candidates import ExperimentCandidate

        candidate = ExperimentCandidate(
            target="testcase-api",
            fault_kinds=("net.delay",),
            params={"band": "default", "seconds": "5s"},
            execution_context="container",
            expected_effect="latency injection",
        )
        spec = synthesize_candidate_spec(candidate, "testcase-api")
        assert spec.kind == "drill"
        assert "testcase-api" in spec.containers
        container = spec.containers["testcase-api"]
        assert len(container.faults) == 1
        assert container.faults[0].fault == "net.delay"

    def test_hypothesis_from_candidate(self) -> None:
        from mayhem.controller.planner import synthesize_candidate_spec
        from mayhem.domain.candidates import ExperimentCandidate

        candidate = ExperimentCandidate(
            target="api",
            fault_kinds=("cpu.spike",),
            expected_effect="CPU saturation",
        )
        spec = synthesize_candidate_spec(candidate, "api")
        assert spec.hypothesis == "CPU saturation"

    def test_default_hypothesis_when_empty(self) -> None:
        from mayhem.controller.planner import synthesize_candidate_spec
        from mayhem.domain.candidates import ExperimentCandidate

        candidate = ExperimentCandidate(
            target="web",
            fault_kinds=("fs.fill",),
        )
        spec = synthesize_candidate_spec(candidate, "web")
        assert "fs.fill" in spec.hypothesis
        assert "web" in spec.hypothesis

    def test_plan_drill_compiles_candidate_spec(self) -> None:
        """synthesize_candidate_spec output is valid input to plan_drill."""
        from mayhem.controller.planner import synthesize_candidate_spec
        from mayhem.domain.candidates import ExperimentCandidate
        from mayhem.domain.experiments import ExecutionStep

        candidate = ExperimentCandidate(
            target="testcase-api",
            fault_kinds=("proc.pause",),
            execution_context="container",
        )
        spec = synthesize_candidate_spec(candidate, "testcase-api")
        spec = spec.model_copy(update={"execution": (ExecutionStep(parallel=("testcase-api",)),)})
        plan = plan_drill(
            "r-test",
            spec,
            _drill_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        assert plan.kind.value == "drill"
        assert len(plan.steps) == 1
        assert plan.steps[0].fault.fault_id == "proc.pause"
