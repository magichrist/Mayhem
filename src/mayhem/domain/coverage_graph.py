"""Resilience coverage graph (v0.9.0 expansion task 12).

A read-only projection over the existing coverage table: nodes are
``(service, fault_kind, failure_domain, target_type, engine, maturity,
evidence_status)`` cells, and edges connect a service to the fault families it
has exercised. The graph never mutates coverage; it only reads it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

GRAPH_SCHEMA_VERSION = "1.0"

EVIDENCE_VERIFIED = "verified"
EVIDENCE_ATTEMPTED = "attempted"
EVIDENCE_BLOCKED = "blocked"
EVIDENCE_NONE = "none"

_RANK = {EVIDENCE_NONE: 0, EVIDENCE_ATTEMPTED: 1, EVIDENCE_BLOCKED: 2, EVIDENCE_VERIFIED: 3}


@dataclass(frozen=True, slots=True)
class CoverageNode:
    """One service x fault x failure-domain x target-type x engine cell."""

    service: str
    fault_family: str
    fault_kind: str
    failure_domain: str
    target_type: str
    engine: str
    maturity: str
    evidence_status: str
    attempts: int = 0
    verified: bool = False
    blocked_reason: str = ""

    @property
    def node_id(self) -> str:
        # The full fault kind, not the family: ``k8s.pod_kill`` and
        # ``k8s.pod_latency`` share a family but are distinct cells.
        return "|".join(
            (
                self.service,
                self.fault_kind or self.fault_family,
                self.failure_domain,
                self.target_type,
                self.engine,
            )
        )

    @property
    def maturity_band(self) -> str:
        if self.maturity in {"stable", "verified-live"}:
            return "mature"
        if self.maturity in {"verified-unit", "experimental"}:
            return "provisional"
        return "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "node_id": self.node_id,
            "maturity_band": self.maturity_band,
        }


@dataclass(frozen=True, slots=True)
class CoverageEdge:
    """A service → fault-family edge, annotated with the strongest evidence."""

    source: str
    target: str
    kind: str = "exercises"
    evidence_status: str = EVIDENCE_NONE
    weight: int = 0

    @property
    def edge_id(self) -> str:
        return f"{self.source}->{self.target}:{self.kind}"

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "edge_id": self.edge_id}


@dataclass(frozen=True, slots=True)
class CoverageGraph:
    nodes: tuple[CoverageNode, ...] = ()
    edges: tuple[CoverageEdge, ...] = ()
    schema_version: str = GRAPH_SCHEMA_VERSION
    filters: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "filters": list(self.filters),
            "summary": self.summary(),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }

    def summary(self) -> dict[str, int]:
        return {
            "services": len({node.service for node in self.nodes}),
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "verified": sum(1 for node in self.nodes if node.verified),
            "blocked": sum(1 for node in self.nodes if node.evidence_status == EVIDENCE_BLOCKED),
        }

    def services(self) -> tuple[str, ...]:
        return tuple(sorted({node.service for node in self.nodes}))

    def uncovered(self) -> tuple[CoverageNode, ...]:
        return tuple(node for node in self.nodes if node.evidence_status == EVIDENCE_NONE)

    def filtered(
        self,
        *,
        service: str | None = None,
        engine: str | None = None,
        evidence_status: str | None = None,
    ) -> CoverageGraph:
        nodes = list(self.nodes)
        applied: list[str] = []
        if service:
            nodes = [node for node in nodes if node.service == service]
            applied.append("service")
        if engine:
            nodes = [node for node in nodes if node.engine == engine]
            applied.append("engine")
        if evidence_status:
            nodes = [node for node in nodes if node.evidence_status == evidence_status]
            applied.append("evidence_status")
        services = {node.service for node in nodes}
        families = {node.fault_family for node in nodes}
        edges = tuple(
            edge for edge in self.edges if edge.source in services and edge.target in families
        )
        return CoverageGraph(
            nodes=tuple(nodes),
            edges=edges,
            schema_version=self.schema_version,
            filters=tuple(applied),
        )


def evidence_status_for(*, covered: bool, blocked_reason: str = "") -> str:
    """Derive the evidence status of a cell from existing coverage facts."""
    if blocked_reason:
        return EVIDENCE_BLOCKED
    if covered:
        return EVIDENCE_VERIFIED
    return EVIDENCE_NONE


@dataclass(frozen=True, slots=True)
class CoverageDelta:
    """Before/after difference between two coverage graphs."""

    before: CoverageGraph
    after: CoverageGraph
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()

    @classmethod
    def between(cls, before: CoverageGraph, after: CoverageGraph) -> CoverageDelta:
        before_nodes = {node.node_id: node for node in before.nodes}
        after_nodes = {node.node_id: node for node in after.nodes}
        return cls(
            before=before,
            after=after,
            added=tuple(sorted(set(after_nodes) - set(before_nodes))),
            removed=tuple(sorted(set(before_nodes) - set(after_nodes))),
            changed=tuple(
                sorted(
                    node_id
                    for node_id in set(before_nodes) & set(after_nodes)
                    if before_nodes[node_id].evidence_status != after_nodes[node_id].evidence_status
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "before": self.before.summary(),
            "after": self.after.summary(),
            "added": list(self.added),
            "removed": list(self.removed),
            "changed": list(self.changed),
            "net_covered": self.after.summary()["verified"] - self.before.summary()["verified"],
        }

    @property
    def improved(self) -> bool:
        return self.after.summary()["verified"] > self.before.summary()["verified"]


def build_edges(nodes: tuple[CoverageNode, ...]) -> tuple[CoverageEdge, ...]:
    """One edge per (service, fault-family) pair; strongest evidence wins."""
    best: dict[tuple[str, str], CoverageNode] = {}
    for node in nodes:
        key = (node.service, node.fault_family)
        current = best.get(key)
        if current is None or _RANK[node.evidence_status] > _RANK[current.evidence_status]:
            best[key] = node
    return tuple(
        CoverageEdge(
            source=service,
            target=family,
            evidence_status=node.evidence_status,
            weight=node.attempts,
        )
        for (service, family), node in sorted(best.items())
    )


def build_graph(
    records: Iterable[dict[str, Any]],
    *,
    service: str | None = None,
    engine: str | None = None,
    evidence_status: str | None = None,
) -> CoverageGraph:
    """Build a graph from plain coverage-record dicts (read-only input)."""
    prepared: list[dict[str, Any]] = []
    for record in records:
        item = dict(record)
        blocked = str(item.get("block_reason") or "")
        item["_blocked"] = blocked
        # A blocked cell is never counted as verified, even if an earlier run
        # covered it — blocked is the honest state.
        item["_verified"] = bool(item.get("covered")) and not blocked
        prepared.append(item)
    nodes = tuple(
        CoverageNode(
            service=str(record.get("service") or record.get("target") or "unknown"),
            fault_family=str(record.get("fault_family") or "unknown"),
            fault_kind=str(record.get("fault_kind") or record.get("fault_family") or "unknown"),
            failure_domain=str(record.get("failure_domain") or "unknown"),
            target_type=str(record.get("target_type") or "unknown"),
            engine=str(record.get("engine") or "unknown"),
            maturity=str(record.get("maturity") or "unknown"),
            evidence_status=evidence_status_for(
                covered=bool(record.get("covered")),
                blocked_reason=str(record.get("_blocked") or ""),
            ),
            attempts=int(record.get("attempts") or 0),
            verified=bool(record.get("_verified")),
            blocked_reason=str(record.get("_blocked") or ""),
        )
        for record in prepared
    )
    return CoverageGraph(nodes=nodes, edges=build_edges(nodes)).filtered(
        service=service, engine=engine, evidence_status=evidence_status
    )
