"""k-plan-1 — cross-runtime ``targets:`` compilation.

DD-30678: the authored drill gains a ``targets:`` block that compiles
practically but refuses loudly at the execution-side safety gate.  These tests
pin the four decisions:

  1. schema: ``targets:`` is exactly-one-of with ``containers:``
  2. compile: containers-path drills desugar every fault onto a TargetRef;
     targets-path drills pin the authored logical target
  3. kubernetes targets compile even with no live driver, and stay
     logically pinned when the topology holds no matching pod node
  4. the existing k8s safety gate now also refuses kubernetes-runtime
     logical targets (deployment/statefulset/…) — loud at ``mayhem plan``

Selection modes beyond ``one`` parse (documented grammar) but compile-refuse
with "reserved until k-plan-4".
"""

from __future__ import annotations

from typing import Any

import pydantic
import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.planner import plan_drill
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, validate_plan
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    DrillSpec,
    ExecutionPlan,
    ExecutionStep,
    PlannedFault,
)
from mayhem.domain.identity import RuntimeIdentity, RuntimeLabel
from mayhem.domain.target import ResourceKind, SelectionMode, TargetRef
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    PodNode,
    ProcessNode,
    ServiceNode,
    TopologyGraph,
    TopologyNode,
)

# ── helpers ──────────────────────────────────────────────────────────────────


def _graph(*nodes: TopologyNode) -> TopologyGraph:
    return TopologyGraph(nodes=tuple(nodes), edges=())


def _container_graph(name: str = "checkout", cid: str = "c-checkout") -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id=cid,
                name=name,
                engine="podman",
                runtime_identity=RuntimeIdentity(runtime="docker", host_id="h1", runtime_id=cid),
                container_name=name,
            ),
            ServiceNode(id=f"svc-{name}", name=f"{name}-svc", container_name=name),
            ProcessNode(
                id=f"proc-{name}",
                name=f"{name}-proc",
                pid=4242,
                host_id="h1",
                container_name=name,
            ),
        ),
        edges=(
            Edge(src=f"svc-{name}", dst=cid, kind=EdgeKind.RUNS_ON),
            Edge(src=cid, dst=f"proc-{name}", kind=EdgeKind.RUNS_ON),
        ),
    )


def _pod_graph() -> TopologyGraph:
    return _graph(
        PodNode(
            id="pod-checkout",
            name="checkout-abc123",
            namespace="production",
            image="checkout:latest",
            state="Running",
        )
    )


def _ctx(**policy_kwargs: Any) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(**policy_kwargs),
        budget=BlastRadiusBudget(),
        fingerprint="f",
    )


def _docker_target(name: str = "checkout") -> dict[str, Any]:
    return {"runtime": "docker", "docker": {"container_name": name}}


def _kubernetes_deployment_target() -> dict[str, Any]:
    return {
        "runtime": "kubernetes",
        "kubernetes": {
            "kind": "deployment",
            "namespace": "production",
            "name": "checkout",
        },
    }


def _spec(
    target_name: str, target: dict[str, Any], *, fault_id: str = "proc.pause"
) -> dict[str, Any]:
    return {
        "kind": "drill",
        "name": "k1",
        "targets": {
            target_name: {
                **target,
                "faults": [{"fault": fault_id, "duration": "5s"}],
            },
        },
        "execution": [{"sequential": [target_name]}],
    }


def _compile(
    target_name: str,
    target: dict[str, Any],
    graph: TopologyGraph,
    *,
    fault_id: str = "proc.pause",
) -> ExecutionPlan:
    spec = DrillSpec.model_validate(_spec(target_name, target, fault_id=fault_id))
    return plan_drill(
        "r-x-1",
        spec,
        graph,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def _first_fault(plan: ExecutionPlan) -> PlannedFault:
    for step in plan.steps:
        if step.fault is not None:
            return step.fault
    raise AssertionError("plan carries no fault steps")


def _target_of(fault: PlannedFault) -> TargetRef:
    assert fault.target is not None
    return fault.target


# ── 1. schema ────────────────────────────────────────────────────────────────


class TestTargetsSchema:
    def test_docker_target_parses(self) -> None:
        spec = DrillSpec.model_validate(_spec("checkout", _docker_target()))
        assert spec.targets is not None
        assert spec.targets["checkout"].runtime == RuntimeLabel.DOCKER
        assert spec.containers is None

    def test_kubernetes_target_parses(self) -> None:
        spec = DrillSpec.model_validate(
            _spec("checkout", _kubernetes_deployment_target(), fault_id="k8s.pod_latency")
        )
        assert spec.targets is not None
        assert spec.targets["checkout"].kubernetes is not None
        assert spec.targets["checkout"].kubernetes.name == "checkout"

    def test_mixed_sources_refused(self) -> None:
        mixed = _spec("checkout", _docker_target())
        mixed["containers"] = {"api": {"faults": [{"fault": "proc.pause", "duration": "5s"}]}}
        with pytest.raises(InvariantViolationError) as exc:
            DrillSpec.model_validate(mixed)
        assert exc.value.rule == "targets.mixed_sources"

    def test_neither_source_refused_as_schema_error(self) -> None:
        # direct model_validate surfaces the pydantic error; parse_drill
        # re-wraps it as SchemaValidationError.
        with pytest.raises(pydantic.ValidationError):
            DrillSpec.model_validate({"kind": "drill", "name": "k1", "execution": [{"wait": "5s"}]})

    def test_empty_containers_still_invariant(self) -> None:
        with pytest.raises(InvariantViolationError):
            DrillSpec.model_validate(
                {
                    "kind": "drill",
                    "name": "k1",
                    "containers": {},
                    "execution": [{"sequential": ["api"]}],
                }
            )

    def test_target_requires_fault(self) -> None:
        bad = _spec("checkout", _docker_target())
        bad["targets"]["checkout"]["faults"] = []
        with pytest.raises(InvariantViolationError) as exc:
            DrillSpec.model_validate(bad)
        assert exc.value.rule == "target_requires_faults"

    def test_kubernetes_target_block_locator_mixed(self) -> None:
        bad = {
            "kind": "drill",
            "name": "k1",
            "targets": {
                "checkout": {
                    "runtime": "kubernetes",
                    "kubernetes": {
                        "kind": "deployment",
                        "namespace": "production",
                        "name": "checkout",
                    },
                    "docker": {"container_name": "checkout"},
                    "faults": [{"fault": "k8s.pod_latency", "duration": "5s"}],
                },
            },
            "execution": [{"sequential": ["checkout"]}],
        }
        with pytest.raises(InvariantViolationError) as exc:
            DrillSpec.model_validate(bad)
        assert exc.value.rule == "target.mixed_locators"

    def test_docker_target_requires_docker_block(self) -> None:
        with pytest.raises(InvariantViolationError) as exc:
            DrillSpec.model_validate(_spec("checkout", {"runtime": "docker"}))
        assert exc.value.rule == "target.runtime_mismatch"

    def test_container_kind_is_docker_scoped(self) -> None:
        bad = {
            "runtime": "kubernetes",
            "kubernetes": {"kind": "container", "namespace": "n", "name": "x"},
        }
        with pytest.raises(ValueError):
            DrillSpec.model_validate(_spec("checkout", bad))

    def test_reserved_selection_modes_schema_accepted(self) -> None:
        modes = (
            SelectionMode.ALL,
            SelectionMode.COUNT,
            SelectionMode.PERCENTAGE,
            SelectionMode.RANDOM,
        )
        for mode in modes:
            target = _docker_target()
            target["selection"] = {"mode": mode.value}
            spec = DrillSpec.model_validate(_spec("checkout", target))
            assert spec.targets is not None
            assert spec.targets["checkout"].selection is not None
            assert spec.targets["checkout"].selection.mode == mode

    def test_selection_count_conflicts_with_one(self) -> None:
        target = _docker_target()
        target["selection"] = {"mode": "one", "count": 2}
        with pytest.raises(ValueError):
            DrillSpec.model_validate(_spec("checkout", target))


# ── 2.+3. compile ────────────────────────────────────────────────────────────


class TestTargetsCompile:
    def test_containers_path_desugars_target_ref(self) -> None:
        spec = DrillSpec.model_validate(
            {
                "kind": "drill",
                "name": "legacy",
                "containers": {"checkout": {"faults": [{"fault": "proc.pause", "duration": "5s"}]}},
                "execution": [{"sequential": ["checkout"]}],
            }
        )
        plan = plan_drill(
            "r-x-1",
            spec,
            _container_graph("checkout", "c-checkout"),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        fault = _first_fault(plan)
        target = _target_of(fault)
        assert target.runtime == RuntimeLabel.DOCKER
        assert target.kind == ResourceKind.CONTAINER
        assert target.authority["container_name"] == "checkout"
        assert any(t.node_ids for t in fault.targets)

    def test_docker_target_compiles_and_pins(self) -> None:
        plan = _compile("checkout", _docker_target(), _container_graph(), fault_id="proc.pause")
        fault = _first_fault(plan)
        target = _target_of(fault)
        assert target.runtime == RuntimeLabel.DOCKER
        assert target.kind == ResourceKind.CONTAINER
        assert target.authority["container_name"] == "checkout"
        assert any(t.node_ids for t in fault.targets)
        assert fault.undo_ops

    def test_docker_target_refuses_missing_container(self) -> None:
        with pytest.raises(Exception, match="not found in topology"):
            _compile("checkout", _docker_target(), _graph())

    def test_kubernetes_target_compiles_without_driver(self) -> None:
        plan = _compile(
            "checkout",
            _kubernetes_deployment_target(),
            _graph(),
            fault_id="k8s.pod_latency",
        )
        fault = _first_fault(plan)
        assert fault.fault_id == "k8s.pod_latency"
        target = _target_of(fault)
        assert target.runtime == RuntimeLabel.KUBERNETES
        assert target.kind == ResourceKind.DEPLOYMENT
        assert fault.targets == ()

    def test_pod_target_resolves_against_graph(self) -> None:
        plan = _compile(
            "checkout",
            {
                "runtime": "kubernetes",
                "kubernetes": {
                    "kind": "pod",
                    "namespace": "production",
                    "name": "checkout-abc123",
                },
            },
            _pod_graph(),
            fault_id="k8s.pod_latency",
        )
        fault = _first_fault(plan)
        target = _target_of(fault)
        assert target.kind == ResourceKind.POD
        resolved = {node_id for t in fault.targets for node_id in t.node_ids}
        assert resolved == {"pod-checkout"}
        # the writable undo lands with the driver (k-plan-2) — no template yet

    def test_selection_modes_compile(self) -> None:
        """k-plan-4 §4.2: multi-instance selection modes parse and compile
        (SP-4.1 reserved-mode flip)."""
        cases = (
            {"mode": "one"},
            {"mode": "all"},
            {"mode": "count", "count": 1},
            {"mode": "percentage", "percentage": 50},
            {"mode": "random"},
        )
        for selection in cases:
            target = _docker_target()
            target["selection"] = selection
            plan = _compile("checkout", target, _container_graph(), fault_id="proc.pause")
            assert any(step.fault is not None for step in plan.steps)

    def test_execution_references_undefined_target_refused(self) -> None:
        spec = DrillSpec.model_validate(_spec("checkout", _docker_target()))
        spec = spec.model_copy(update={"execution": (ExecutionStep(sequential=("nope",)),)})
        with pytest.raises(Exception, match="not defined under 'targets'"):
            plan_drill(
                "r-x-1",
                spec,
                _container_graph(),
                config_snapshot_id="c",
                topology_snapshot_id="t",
                environment_fingerprint="f",
            )

    def test_queue_step_block(self) -> None:
        spec = DrillSpec.model_validate(
            {
                "kind": "drill",
                "name": "k1",
                "targets": {
                    "checkout": {
                        **_docker_target(),
                        "faults": [{"fault": "proc.pause", "duration": "5s"}],
                    },
                },
                "execution": [{"wait": "2s"}, {"sequential": ["checkout"]}],
            }
        )
        plan = plan_drill(
            "r-x-1",
            spec,
            _container_graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="f",
        )
        assert any(step.fault is not None for step in plan.steps)


# ── 4. safety gate ───────────────────────────────────────────────────────────


class TestTargetsSafetyGate:
    def test_kubernetes_logical_target_admitted_when_eligible(self) -> None:
        """ADR-M7-1 flip (SP-3.2, SP-4.1): a workload with an eligible pod is
        admitted at plan + safety time; the old unconditional ``k8s.unsupported``
        refusal applies only to unimplemented pathways."""
        _k8s_owned = _graph(
            PodNode(
                id="pod-checkout-2",
                name="checkout-abc123",
                namespace="production",
                image="checkout:latest",
                state="Running",
                owner_kind="Deployment",
                owner_name="checkout",
            )
        )
        plan = _compile(
            "checkout",
            _kubernetes_deployment_target(),
            _k8s_owned,
            fault_id="k8s.pod_latency",
        )
        validate_plan(plan, _k8s_owned, _ctx())  # no SafetyRefusedError raised

    def test_docker_target_passes_k8s_gate(self) -> None:
        plan = _compile("checkout", _docker_target(), _container_graph(), fault_id="proc.pause")
        try:
            validate_plan(plan, _container_graph(), _ctx())
        except SafetyRefusedError as exc:
            assert exc.reason_code != "k8s.unsupported"
