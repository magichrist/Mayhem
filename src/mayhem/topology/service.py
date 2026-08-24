"""TopologyService — merge provider fragments into one graph + drift report."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mayhem.domain.topology import ContainerNode, Edge, NodeKind, TopologyGraph

if TYPE_CHECKING:
    from mayhem.domain.topology import TopologyNode
    from mayhem.topology.providers.base import PartialGraph, TopologyProvider


@dataclass(frozen=True)
class DiscoveryResult:
    graph: TopologyGraph
    drift_report: dict[str, object] = field(default_factory=dict)


class TopologyService:
    """Blueprint (compose) ↔ live (runtime) merge; drift is recorded, never hidden."""

    def discover(self, providers: list[TopologyProvider]) -> DiscoveryResult:
        fragments = []
        for provider in providers:
            if not provider.is_available():
                continue
            fragments.append(provider.discover())

        blueprint = next((f for f in fragments if f.source == "compose"), None)
        live = [f for f in fragments if f.source != "compose"]

        nodes: dict[str, TopologyNode] = {}
        edges: list[Edge] = []
        for fragment in fragments:
            for node in fragment.nodes:
                nodes.setdefault(node.id, node)
            edges.extend(fragment.edges)

        drift: dict[str, object] = {}
        if blueprint is not None:
            drift = self._diff(blueprint, live)
        notes = [n for f in fragments for n in f.notes]
        if notes:
            drift["notes"] = list(notes)

        graph_nodes = tuple(nodes.values())
        known_ids = set(nodes)
        safe_edges = tuple(e for e in edges if e.src in known_ids and e.dst in known_ids)
        return DiscoveryResult(
            graph=_graph(graph_nodes, safe_edges),
            drift_report=drift,
        )

    @staticmethod
    def _diff(
        blueprint: PartialGraph,
        live_fragments: list[PartialGraph],
    ) -> dict[str, object]:
        services = {n.name: n for n in blueprint.nodes if n.kind is NodeKind.SERVICE}
        live_by_service: dict[str, list[ContainerNode]] = {}
        for fragment in live_fragments:
            for node in fragment.nodes:
                if isinstance(node, ContainerNode) and node.service_name:
                    live_by_service.setdefault(node.service_name, []).append(node)

        missing_services = sorted(set(services) - set(live_by_service))
        extra_containers: list[dict[str, str]] = [
            {"name": c.name, "engine": c.engine}
            for fragment in live_fragments
            for c in fragment.nodes
            if isinstance(c, ContainerNode)
            and c.service_name
            and c.service_name not in services
        ]
        changed_images: list[dict[str, str]] = []
        for name, svc in services.items():
            expected = getattr(svc, "image", None)
            for _container in live_by_service.get(name, []):
                # engine ps does not carry image on all versions; absence ≠ drift.
                if expected is None:
                    continue
                changed_images.append({"service": name, "expected": str(expected)})

        report: dict[str, object] = {
            "missing_services": missing_services,
            "extra_containers": extra_containers,
            "image_expectations": changed_images,
        }
        return {k: v for k, v in report.items() if v}


def _graph(
    nodes: tuple[TopologyNode, ...], edges: tuple[Edge, ...]
) -> TopologyGraph:
    return TopologyGraph(nodes=nodes, edges=edges)
