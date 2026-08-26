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
    partial: bool = False
    errors: tuple[str, ...] = ()


class TopologyService:
    """Blueprint (compose) ↔ live (runtime) merge; drift is recorded, never hidden."""

    def discover(self, providers: list[TopologyProvider]) -> DiscoveryResult:
        fragments = []
        errors: list[str] = []
        for provider in providers:
            if not provider.is_available():
                errors.append(f"{provider.id}: not available")
                continue
            try:
                fragment = provider.discover()
                fragments.append(fragment)
            except Exception as exc:
                errors.append(f"{provider.id}: discovery failed: {exc}")

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
            partial=bool(errors),
            errors=tuple(errors),
        )

    @staticmethod
    def _diff(
        blueprint: PartialGraph,
        live_fragments: list[PartialGraph],
    ) -> dict[str, object]:
        services = {n.name: n for n in blueprint.nodes if n.kind is NodeKind.SERVICE}
        live_by_service: dict[str, list[ContainerNode]] = {}
        all_live_containers: list[ContainerNode] = []
        for fragment in live_fragments:
            for node in fragment.nodes:
                if isinstance(node, ContainerNode):
                    all_live_containers.append(node)
                    if node.service_name:
                        live_by_service.setdefault(node.service_name, []).append(node)

        # --- matched services ---
        matched_services: list[str] = []
        for name in sorted(set(services) & set(live_by_service)):
            matched_services.append(name)

        # --- missing services ---
        missing_services = sorted(set(services) - set(live_by_service))

        # --- extra containers (runtime containers with no matching service) ---
        extra_containers: list[dict[str, str]] = [
            {"name": c.name, "engine": c.engine, "image": str(c.image or "")}
            for c in all_live_containers
            if c.service_name and c.service_name not in services
        ]

        # --- image drift ---
        changed_images: list[dict[str, str]] = []
        for name, svc in services.items():
            expected = getattr(svc, "image", None)
            if expected is None:
                continue
            for container in live_by_service.get(name, []):
                actual = getattr(container, "image", None)
                if actual and str(expected) != str(actual):
                    changed_images.append({
                        "service": name,
                        "expected": str(expected),
                        "actual": str(actual),
                    })

        # --- state anomalies (stopped, paused, restarting) ---
        unhealthy: list[dict[str, str]] = []
        for name, containers in live_by_service.items():
            for c in containers:
                state = c.state.lower() if c.state else ""
                if state not in ("running", "up", ""):
                    unhealthy.append({"service": name, "name": c.name, "state": c.state})

        report: dict[str, object] = {
            "matched_services": matched_services,
            "missing_services": missing_services,
            "extra_containers": extra_containers,
            "changed_images": changed_images,
            "unhealthy": unhealthy,
        }
        return {k: v for k, v in report.items() if v}


def _graph(nodes: tuple[TopologyNode, ...], edges: tuple[Edge, ...]) -> TopologyGraph:
    return TopologyGraph(nodes=nodes, edges=edges)
