"""Dense container x fault matrix.

For every argv-executable fault in the catalog and every compose service of the
testCase example, the write-ahead compensation contract must (a) address the
right container and (b) compile through the real planner into exactly one fully
compensatable step. A fault that breaks one cell of the matrix breaks the whole
matrix — no skips, no favorites.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mayhem.controller.compensation import compensated
from mayhem.controller.planner import plan_drill
from mayhem.domain.catalog import CATALOG, definition_for
from mayhem.domain.experiments import (
    DrillConfig,
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
    PlannedFault,
)
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.topology import (
    ContainerNode,
    ExternalDependencyNode,
    HostNode,
    NodeKind,
    ProcessNode,
    ServiceNode,
)

TESTCASE_DIR = Path(__file__).resolve().parents[2] / "examples" / "testCase"

CONTAINERS = (
    "testcase-api",
    "testcase-web",
    "testcase-download-1",
    "testcase-download-2",
    "testcase-lb",
    "testcase-db",
)

FAULTS = tuple(
    d.id
    for d in CATALOG
    if NodeKind.POD not in d.applicable_node_kinds
    and NodeKind.K8S_NODE not in d.applicable_node_kinds
)

_RATE = {"net.bandwidth": {"rate": "10mbit"}, "dependency.rate_limit": {"rate": 100}}


def seeds_for(fault_id: str) -> dict[str, object]:
    """Valid required-param values so a bare DrillFault compiles per fault."""
    definition = definition_for(fault_id)
    seeds: dict[str, object] = {}
    for spec in definition.params_schema:
        if not spec.required:
            continue
        if fault_id in _RATE and spec.name in _RATE[fault_id]:
            seeds[spec.name] = _RATE[fault_id][spec.name]
        elif spec.type.value == "integer":
            seeds[spec.name] = 1
        elif spec.type.value == "duration":
            seeds[spec.name] = "5s"
        else:
            seeds[spec.name] = "test"
    return seeds


def nodes_for(container_name: str) -> tuple:
    """Full ground-truth subtree for one compose service."""
    node_id = f"ctr-{container_name}"
    service = ServiceNode(
        id=f"svc-{container_name}", name=container_name, container_name=container_name
    )
    container = ContainerNode(
        id=node_id,
        name=container_name,
        engine="fake",
        runtime_identity=RuntimeIdentity(runtime="fake", host_id="h1", runtime_id=node_id),
        runtime_metadata=RuntimeMetadata(service=container_name, name=container_name),
        container_name=container_name,
        state="running",
    )
    process = ProcessNode(
        id=f"{node_id}.proc",
        name=f"{container_name}-proc",
        pid=1024,
        host_id="h1",
        container_name=container_name,
    )
    host = HostNode(id="host-h1", name="h1")
    external = ExternalDependencyNode(id="ext.db", name="db", endpoint="172.18.0.9:3306")
    return (service, container, process, host, external)


def collect_strings(value: object, acc: list[str]) -> None:
    if isinstance(value, str):
        acc.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            collect_strings(v, acc)
    elif isinstance(value, (list, tuple)):
        for v in value:
            collect_strings(v, acc)


@pytest.fixture()
def runtime_graph(compose_runtime_graph):
    return compose_runtime_graph


class TestCompensatedMatrix:
    @pytest.mark.parametrize(
        ("fault_id", "container_name"),
        [(f, c) for f in FAULTS for c in CONTAINERS],
    )
    def test_undo_ops_address_the_container(self, fault_id: str, container_name: str) -> None:
        planned = PlannedFault(
            fault_id=fault_id,
            targets=(),
            duration=5.0,
            params=seeds_for(fault_id),
        )
        written = compensated(planned, nodes_for(container_name))
        assert written.undo_ops
        assert written.verify_probes
        # every undo chain must reference the container being repaired
        needles: list[str] = []
        for op in written.undo_ops:
            collect_strings(op.args, needles)
            if op.op == "payload.undo":
                marker = str(op.args.get("marker", ""))
                assert marker.endswith(f"ctr-{container_name}.pid"), marker
            if op.op == "signal.cont":
                pid = str(op.args.get("pid", ""))
                assert pid.startswith(f"ctr-{container_name}.proc"), pid
            if "cont" in op.args:
                assert op.args["cont"] == container_name
        joined = json.dumps(needles)
        assert container_name in joined or any("ctr-" + container_name in s for s in needles)

    @pytest.mark.parametrize(
        ("fault_id", "container_name"),
        [(f, c) for f in FAULTS for c in CONTAINERS],
    )
    def test_recovery_keeps_perturbation_by_default(
        self, fault_id: str, container_name: str
    ) -> None:
        written = compensated(
            PlannedFault(
                fault_id=fault_id,
                targets=(),
                duration=5.0,
                params=seeds_for(fault_id),
                recovery=True,
            ),
            nodes_for(container_name),
        )
        assert written.undo_ops


class TestPlannerMatrix:
    @pytest.mark.parametrize(
        ("fault_id", "container_name"),
        [(f, c) for f in FAULTS for c in CONTAINERS],
    )
    def test_every_fault_plans_exactly_one_compensatable_step(
        self, runtime_graph, fault_id: str, container_name: str
    ) -> None:
        spec = DrillSpec(
            kind="drill",
            name=f"{container_name}-{fault_id}",
            config=DrillConfig(),
            containers={
                container_name: DrillContainer(
                    faults=(DrillFault(fault=fault_id, duration="5s", **seeds_for(fault_id)),)
                )
            },
            execution=(ExecutionStep(parallel=(container_name,)),),
        )
        plan = plan_drill(
            "matrix-run",
            spec,
            runtime_graph,
            config_snapshot_id="cs",
            topology_snapshot_id="ts",
            environment_fingerprint="f",
            engine="fake",
            spec_dir=str(TESTCASE_DIR),
        )
        steps = [s for s in plan.steps if s.fault is not None]
        assert len(steps) == 1, f"{fault_id} on {container_name} produced {len(steps)} steps"
        step = steps[0]
        assert step.fault.fault_id == fault_id
        assert step.fault.undo_ops
        assert step.fault.verify_probes

    def test_all_catalog_faults_appear_in_the_matrix(self) -> None:
        non_k8s = {
            d.id
            for d in CATALOG
            if NodeKind.POD not in d.applicable_node_kinds
            and NodeKind.K8S_NODE not in d.applicable_node_kinds
        }
        assert set(FAULTS) == non_k8s
        assert "net.bandwidth" in FAULTS  # rate-seeded required param present
        assert "dependency.rate_limit" in FAULTS
        assert "proc.pause" in FAULTS
        assert "mem.exhaust" in FAULTS
