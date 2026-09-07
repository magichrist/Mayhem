"""Shared fixtures for the mayhem test suite (rootdir conftest).

The compose blueprint + synthetic live runtime graph is used by both the
example-spec tests and the container x fault matrix tests, and must be built
identically in both.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    ProcessNode,
    TopologyGraph,
)
from mayhem.topology.providers.compose import ComposeFileProvider

TESTCASE_DIR = Path(__file__).resolve().parents[1] / "examples" / "testCase"


def build_compose_runtime_graph() -> TopologyGraph:
    """Compose blueprint merged with a synthetic live runtime so every drill
    fault (process-addressable ones included) has a node to act on."""
    from mayhem.topology.service import _graph

    result = ComposeFileProvider(str(TESTCASE_DIR / "docker-compose.yml")).discover()
    nodes: list = list(result.nodes)
    svc_nodes = {n.id: n for n in result.nodes}
    edges = list(result.edges)
    pid = 1000
    for _node_id, svc in sorted(svc_nodes.items()):
        cname = svc.container_name
        cid = f"ctr-{cname}"
        container = ContainerNode(
            id=cid,
            name=svc.name,
            engine="fake",
            runtime_identity=RuntimeIdentity(runtime="fake", host_id="h1", runtime_id=cid),
            runtime_metadata=RuntimeMetadata(service=svc.name, name=svc.name),
            container_name=cname,
            state="running",
        )
        proc = ProcessNode(
            id=f"{cid}.proc",
            name=f"{svc.name}-proc",
            pid=pid,
            host_id="h1",
            container_name=cname,
        )
        pid += 1
        nodes.append(container)
        nodes.append(proc)
        edges.append(Edge(src=svc.id, dst=container.id, kind=EdgeKind.RUNS_ON))
        edges.append(Edge(src=container.id, dst=proc.id, kind=EdgeKind.RUNS_ON))
    return _graph(tuple(nodes), tuple(edges))


@pytest.fixture(scope="module")
def compose_runtime_graph() -> TopologyGraph:
    return build_compose_runtime_graph()
