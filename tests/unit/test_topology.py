"""Topology integrity, selectors, and blast-radius closure."""

import pytest

from mayhem.domain.errors import (
    InvariantViolationError,
    TargetResolutionError,
)
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    ExternalDependencyNode,
    HostNode,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-api", name="api"),
            ServiceNode(id="n-web", name="web"),
            ContainerNode(
                id="c-api",
                name="api-1",
                engine="docker",
                runtime_id="abc123",
                service_name="api",
            ),
            HostNode(id="h-bm1", name="bm-1"),
            ExternalDependencyNode(id="x-pg", name="postgres", endpoint="postgres:5432"),
        ),
        edges=(
            Edge(src="n-api", dst="c-api", kind=EdgeKind.RUNS_ON),
            Edge(src="c-api", dst="h-bm1", kind=EdgeKind.RUNS_ON),
            Edge(src="n-api", dst="x-pg", kind=EdgeKind.DEPENDS_ON),
            Edge(src="n-web", dst="n-api", kind=EdgeKind.CONNECTS_VIA),
        ),
    )


class TestIntegrity:
    def test_duplicate_node_ids_rejected(self) -> None:
        with pytest.raises(InvariantViolationError, match="topology_unique_node_ids"):
            TopologyGraph(nodes=(ServiceNode(id="dup", name="a"), ServiceNode(id="dup", name="b")))

    def test_dangling_edges_rejected(self) -> None:
        with pytest.raises(InvariantViolationError, match="dangling"):
            TopologyGraph(
                nodes=(ServiceNode(id="a", name="a"),),
                edges=(Edge(src="a", dst="ghost", kind=EdgeKind.DEPENDS_ON),),
            )

    def test_json_round_trip(self) -> None:
        graph = _graph()
        assert TopologyGraph.model_validate(graph.model_dump(mode="json")) == graph


class TestSelectors:
    @pytest.mark.parametrize(
        ("selector", "expected_name"),
        [
            (TargetSelector(kind=NodeKind.SERVICE, expr="api"), "api"),
            (TargetSelector(kind=NodeKind.CONTAINER, expr="service_name=api"), "api-1"),
            (TargetSelector(kind=NodeKind.CONTAINER, expr="engine~=dock.*"), "api-1"),
            (TargetSelector(kind=NodeKind.HOST, expr="bm-1"), "bm-1"),
        ],
    )
    def test_resolution(self, selector: TargetSelector, expected_name: str) -> None:
        found = _graph().resolve(selector)
        assert len(found) == 1
        assert found[0].name == expected_name

    def test_no_match_raises_typed_error(self) -> None:
        selector = TargetSelector(kind=NodeKind.SERVICE, expr="missing")
        with pytest.raises(TargetResolutionError):
            _graph().resolve(selector)

    def test_kind_mismatch_excludes_node(self) -> None:
        selector = TargetSelector(kind=NodeKind.HOST, expr="api")
        assert not selector.matches(ServiceNode(id="n-api", name="api"))

    def test_str_rendering(self) -> None:
        assert str(TargetSelector(kind=NodeKind.SERVICE, expr="api")) == "service:api"


class TestBlastRadiusClosure:
    def test_dependents_closure_includes_transitive(self) -> None:
        dependents = _graph().dependents_closure("x-pg")
        # web -> api -> postgres; api runs on container/host but those are RUNS_ON (excluded)
        assert "n-web" in dependents
        assert "n-api" in dependents
        assert "x-pg" not in dependents

    def test_leaf_has_empty_closure(self) -> None:
        assert _graph().dependents_closure("n-web") == frozenset()
