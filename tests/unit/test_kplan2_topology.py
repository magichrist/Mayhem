"""k-plan-2 — topology node-model extensions.

DD-30678 phase 2: the PodNode gains the stable-workload owner identity and
pod facts promised in k-plan-2 §2.3. These tests pin:
  1. new fields default so docker-era PodNode construction is untouched;
  2. a docker-era graph round-trips with byte-identical JSON (no schema churn);
  3. a fully-populated PodNode round-trips stably (owner, containers, uid,
     restart_count survive model_dump → model_validate);
  4. owner identity rides PodNode metadata — it is never the node name
     (the k-plan-1 identity contract).
"""

from __future__ import annotations

from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    PodNode,
    RuntimeIdentity,
    ServiceNode,
    TopologyGraph,
)


def _docker_graph() -> TopologyGraph:
    edge = Edge(src="svc/web", dst="ctr/web-1", kind=EdgeKind.RUNS_ON)
    return TopologyGraph(
        nodes=(
            ServiceNode(id="svc/web", name="web", image="nginx:1.25"),
            ContainerNode(
                id="ctr/web-1",
                name="web-1",
                engine="docker",
                container_name="web",
                runtime_identity=RuntimeIdentity(
                    runtime="docker", host_id="host-1", runtime_id="abc123"
                ),
            ),
        ),
        edges=(edge,),
    )


def _full_pod() -> PodNode:
    return PodNode(
        id="k8s::pod/production/checkout-867cd6dcb8-x7z9k",
        name="checkout-867cd6dcb8-x7z9k",
        namespace="production",
        node_name="ip-10-0-1-24",
        owner_kind="Deployment",
        owner_name="checkout",
        containers=("app", "sidecar"),
        pod_uid="b3e2e7e0-9be0-4d07-9e3f-19d4c4f5d001",
        restart_count=2,
        state="running",
    )


class TestPodNodeExtensions:
    def test_defaults_keep_docker_era_construction(self) -> None:
        pod = PodNode(id="p1", name="minimal")
        assert pod.owner_kind is None
        assert pod.owner_name is None
        assert pod.containers == ()
        assert pod.pod_uid is None
        assert pod.restart_count == 0

    def test_docker_graph_round_trip_bytes_identical(self) -> None:
        graph = _docker_graph()
        first = graph.model_dump(mode="json")
        revived = TopologyGraph.model_validate(first)
        assert revived.model_dump(mode="json") == first

    def test_full_pod_round_trip_stable(self) -> None:
        pod = _full_pod()
        dumped = pod.model_dump(mode="json")
        revived = PodNode.model_validate(dumped)
        assert revived.model_dump(mode="json") == dumped
        assert revived.owner_kind == "Deployment"
        assert revived.owner_name == "checkout"
        assert revived.containers == ("app", "sidecar")
        assert revived.pod_uid == "b3e2e7e0-9be0-4d07-9e3f-19d4c4f5d001"
        assert revived.restart_count == 2

    def test_owner_identity_is_metadata_not_name(self) -> None:
        pod = _full_pod()
        assert pod.owner_name != pod.name
        assert pod.owner_kind not in ("pod",)