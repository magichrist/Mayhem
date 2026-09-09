"""``--ctr`` scoping helpers: container naming, subtree lookup, subgraphs."""

import pytest

from mayhem.domain.errors import TargetResolutionError
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    HostNode,
    ProcessNode,
    ServiceNode,
    TopologyGraph,
)


def _compose_graph() -> TopologyGraph:
    """A compose-style subtree: service/container/process share ``container_name``."""
    return TopologyGraph(
        nodes=(
            ServiceNode(id="svc-api", name="api", container_name="testcase-api"),
            ContainerNode(
                id="ctr-api",
                name="testcase-api",
                engine="podman",
                container_name="testcase-api",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="cid-api"
                ),
                runtime_metadata=RuntimeMetadata(service="api", name="testcase-api"),
            ),
            ProcessNode(
                id="proc-api",
                name="api-python",
                pid=4242,
                host_id="h1",
                container_name="testcase-api",
            ),
            ServiceNode(id="svc-web", name="web", container_name="testcase-web"),
            ContainerNode(
                id="ctr-web",
                name="container-web",
                engine="podman",
                container_name="testcase-web",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="cid-web"
                ),
                runtime_metadata=RuntimeMetadata(service="web", name="container-web"),
            ),
            HostNode(id="h1", name="host-1"),
        ),
        edges=(
            Edge(src="svc-api", dst="ctr-api", kind=EdgeKind.RUNS_ON),
            Edge(src="ctr-api", dst="proc-api", kind=EdgeKind.RUNS_ON),
            Edge(src="svc-web", dst="ctr-web", kind=EdgeKind.RUNS_ON),
            Edge(src="ctr-web", dst="h1", kind=EdgeKind.RUNS_ON),
        ),
    )


class TestContainerNames:
    def test_lists_authoring_keys_and_container_names(self) -> None:
        # Authoring keys (`testcase-*`) plus the runtime container name
        # (`container-web`) are all valid ``--ctr`` values.
        assert _compose_graph().container_names() == (
            "container-web",
            "testcase-api",
            "testcase-web",
        )

    def test_empty_graph(self) -> None:
        assert TopologyGraph(nodes=(), edges=()).container_names() == ()


class TestNodeIdsForContainer:
    def test_matches_whole_subtree_by_authoring_key(self) -> None:
        assert _compose_graph().node_ids_for_container("testcase-api") == frozenset(
            {"svc-api", "ctr-api", "proc-api"}
        )

    def test_runtime_name_falls_back_to_authoring_subtree(self) -> None:
        # `container-web` is the runtime container name; its authoring key is
        # `testcase-web`, so the whole web subtree resolves.
        assert _compose_graph().node_ids_for_container("container-web") == frozenset(
            {"svc-web", "ctr-web"}
        )

    def test_miss_returns_empty_set(self) -> None:
        assert _compose_graph().node_ids_for_container("testcase-none") == frozenset()
        assert _compose_graph().node_ids_for_container("not-a-container") == frozenset()


class TestRestrictTo:
    def test_keeps_only_the_container_subtree(self) -> None:
        restricted = _compose_graph().restrict_to("testcase-api")
        assert {node.id for node in restricted.nodes} == {"svc-api", "ctr-api", "proc-api"}
        assert {edge.src for edge in restricted.edges} == {"svc-api", "ctr-api"}
        assert {edge.dst for edge in restricted.edges} == {"ctr-api", "proc-api"}

    def test_keeps_host_parents(self) -> None:
        restricted = _compose_graph().restrict_to("testcase-web")
        assert {node.id for node in restricted.nodes} == {"svc-web", "ctr-web", "h1"}
        assert {edge.src for edge in restricted.edges} == {"svc-web", "ctr-web"}

    def test_miss_is_loud(self) -> None:
        with pytest.raises(TargetResolutionError, match="testcase-none"):
            _compose_graph().restrict_to("testcase-none")

    def test_restricted_graph_stays_a_valid_topology(self) -> None:
        restricted = _compose_graph().restrict_to("testcase-web")
        # Re-validating invariants proves the cut left no dangling edges.
        TopologyGraph(nodes=restricted.nodes, edges=restricted.edges)
