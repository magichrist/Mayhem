"""Topology model: nodes, edges, graph (ADR-0006).

Node kinds form a *closed union* — adding Kubernetes later means extending this
union deliberately (ADR-0013), never duck-typing through it. Container-runtime
specifics stay out: ``ContainerNode`` is engine-agnostic.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.networks import IPvAnyAddress

from mayhem.domain.errors import InvariantViolationError, TargetResolutionError


class NodeKind(StrEnum):
    SERVICE = "service"
    CONTAINER = "container"
    HOST = "host"
    PROCESS = "process"
    EXTERNAL_DEPENDENCY = "external_dependency"


class _NodeBase(BaseModel):
    """Common node shape; all nodes are immutable value objects."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str


class PortBinding(BaseModel):
    """A single port binding — host side and container side."""

    model_config = ConfigDict(frozen=True)

    host_port: int
    container_port: int
    host_address: str = "0.0.0.0"
    protocol: str = "tcp"  # tcp | udp


class ServiceNode(_NodeBase):
    kind: Literal[NodeKind.SERVICE] = NodeKind.SERVICE
    image: str | None = None
    exposed_ports: tuple[PortBinding, ...] = ()
    container_name: str | None = None  # compose ``name:`` field (ADR-0020)


class ContainerNode(_NodeBase):
    kind: Literal[NodeKind.CONTAINER] = NodeKind.CONTAINER
    engine: str  # "docker" | "podman" — label only, no runtime types here (ADR-0013)
    runtime_id: str
    ip_address: IPvAnyAddress | None = None
    host_id: str | None = None
    service_name: str | None = None  # com.docker.compose.service binding
    container_name: str | None = None  # stable identity from docker-compose name: field
    ports: tuple[PortBinding, ...] = ()
    state: str = "unknown"  # engine-reported lifecycle state
    image: str | None = None
    networks: tuple[str, ...] = ()


class HostNode(_NodeBase):
    kind: Literal[NodeKind.HOST] = NodeKind.HOST
    address: IPvAnyAddress | None = None
    transport: Literal["local", "ssh"] = "local"
    ssh_user: str | None = None


class ProcessNode(_NodeBase):
    kind: Literal[NodeKind.PROCESS] = NodeKind.PROCESS
    pid: int | None = None  # resolved lazily at execution time (ADR-0020)
    host_id: str
    cmdline: str = ""
    container_id: str | None = None  # short container ID if running inside a container
    container_name: str | None = None  # stable identity for PID resolution (ADR-0020)
    exe: str = ""  # executable path where discoverable
    user: str = ""  # process user where discoverable
    ppid: int | None = None  # parent PID where discoverable


class ExternalDependencyNode(_NodeBase):
    kind: Literal[NodeKind.EXTERNAL_DEPENDENCY] = NodeKind.EXTERNAL_DEPENDENCY
    endpoint: str
    protocol: str = "http"  # http | tcp | dns | ...
    inferred: bool = False  # inferred nodes are never targetable until allowlisted


TopologyNode = ServiceNode | ContainerNode | HostNode | ProcessNode | ExternalDependencyNode
"""Public union of all node kinds."""

_discriminated_nodes = Annotated[TopologyNode, Field(discriminator="kind")]


# --- Network path model (ADR-0019) ---


class NetworkSegment(BaseModel):
    """A named segment in the network topology — a subnet, VLAN, or namespace."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    cidr: str | None = None  # e.g. "10.0.1.0/24"
    node_ids: tuple[str, ...] = ()  # nodes in this segment


class NetworkPath(BaseModel):
    """A directed path between two nodes through the network.

    Captures hops, expected latency, and any intermediate infrastructure
    (load balancers, firewalls, service meshes) that could be fault targets.
    """

    model_config = ConfigDict(frozen=True)

    src_node_id: str
    dst_node_id: str
    hop_count: int = 1
    expected_latency_ms: float = 0.0
    intermediaries: tuple[str, ...] = ()  # node IDs of LBs, firewalls, etc.
    segments: tuple[str, ...] = ()  # segment IDs this path crosses
    bidirectional: bool = True


class NetworkTopology(BaseModel):
    """Collection of network segments and paths — the "network view" of the topology.

    Used by the planner to determine which network faults are applicable
    to a given source→destination path and which intermediaries can be targeted.
    """

    model_config = ConfigDict(frozen=True)

    segments: tuple[NetworkSegment, ...] = ()
    paths: tuple[NetworkPath, ...] = ()

    def paths_for_node(self, node_id: str) -> tuple[NetworkPath, ...]:
        """All paths originating from or terminating at a node."""
        return tuple(p for p in self.paths if p.src_node_id == node_id or p.dst_node_id == node_id)

    def segment_for_node(self, node_id: str) -> NetworkSegment | None:
        """Which segment contains this node, if any."""
        for seg in self.segments:
            if node_id in seg.node_ids:
                return seg
        return None

    def find_path(self, src_node_id: str, dst_node_id: str) -> NetworkPath | None:
        """Find a path between two nodes (directional)."""
        for p in self.paths:
            if p.src_node_id == src_node_id and p.dst_node_id == dst_node_id:
                return p
        return None

    def cross_segment_paths(self) -> tuple[NetworkPath, ...]:
        """Paths that cross segment boundaries — higher fault surface."""
        return tuple(p for p in self.paths if len(p.segments) > 1)


class EdgeKind(StrEnum):
    RUNS_ON = "runs_on"
    CONNECTS_VIA = "connects_via"
    DEPENDS_ON = "depends_on"
    EXPOSES = "exposes"
    CONTAINED_IN = "contained_in"
    LISTENS_ON = "listens_on"
    ATTACHED_TO = "attached_to"


class Edge(BaseModel):
    model_config = ConfigDict(frozen=True)

    src: str
    dst: str
    kind: EdgeKind
    weight: float = 1.0  # depends_on condition strength; >=1.0 means health-gated


class TargetSelector(BaseModel):
    """Declarative selector resolved against a :class:`TopologyGraph`.

    Grammar of ``expr``:
      * ``name``                      — exact node name match
      * ``key=value``                 — exact field match
      * ``key~=regex``                — regex field match
    """

    model_config = ConfigDict(frozen=True)

    kind: NodeKind
    expr: str

    def matches(self, node: TopologyNode) -> bool:
        if node.kind != self.kind:
            return False
        expr = self.expr.strip()
        if "~=" in expr:
            key, pattern = (part.strip() for part in expr.split("~=", maxsplit=1))
            value = _field_str(node, key)
            return value is not None and re.search(pattern, value) is not None
        if "=" in expr:
            key, expected = (part.strip() for part in expr.split("=", maxsplit=1))
            return _field_str(node, key) == expected
        return node.name == expr

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.expr}"


def _field_str(node: BaseModel, key: str) -> str | None:
    value = getattr(node, key, None)
    return None if value is None else str(value)


class TopologyGraph(BaseModel):
    model_config = ConfigDict(frozen=True)

    nodes: tuple[_discriminated_nodes, ...] = ()
    edges: tuple[Edge, ...] = ()

    @model_validator(mode="after")
    def _check_integrity(self) -> TopologyGraph:
        ids = [n.id for n in self.nodes]
        duplicates = {nid for nid in ids if ids.count(nid) > 1}
        if duplicates:
            raise InvariantViolationError(
                "topology_unique_node_ids", f"duplicate node ids: {sorted(duplicates)}"
            )
        known = set(ids)
        dangling = [e for e in self.edges if e.src not in known or e.dst not in known]
        if dangling:
            bad = ", ".join(f"{e.kind.value}:{e.src}->{e.dst}" for e in dangling[:5])
            raise InvariantViolationError(
                "topology_edges_reference_known_nodes", f"dangling edges: {bad}"
            )
        return self

    # -- queries ------------------------------------------------------------------
    def by_id(self, node_id: str) -> TopologyNode | None:
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def of_kind(self, kind: NodeKind) -> list[TopologyNode]:
        return [n for n in self.nodes if n.kind == kind]

    def resolve(self, selector: TargetSelector) -> tuple[TopologyNode, ...]:
        found = tuple(n for n in self.nodes if selector.matches(n))
        if not found:
            raise TargetResolutionError(str(selector), "no nodes matched")
        return found

    def connected_processes(self, node_id: str) -> tuple[ProcessNode, ...]:
        """Walk RUNS_ON edges from *node_id* to find connected ProcessNodes.

        Follows: service → container → process.  Returns every ProcessNode
        reachable within two hops of *node_id* via RUNS_ON edges.
        """
        by_id = {n.id: n for n in self.nodes}
        child_ids = [e.dst for e in self.edges if e.src == node_id and e.kind is EdgeKind.RUNS_ON]
        # One more hop: process nodes that RUNS_ON the children.
        grandchild_ids = [
            e.dst
            for cid in child_ids
            for e in self.edges
            if e.src == cid and e.kind is EdgeKind.RUNS_ON
        ]
        result: list[ProcessNode] = []
        for cid in (*child_ids, *grandchild_ids):
            node = by_id.get(cid)
            if isinstance(node, ProcessNode):
                result.append(node)
        return tuple(result)

    def dependents_closure(self, node_id: str) -> frozenset[str]:
        """All node ids that transitively depend on ``node_id`` — blast-radius input."""
        reverse: dict[str, list[str]] = {}
        for edge in self.edges:
            if edge.kind in (EdgeKind.DEPENDS_ON, EdgeKind.CONNECTS_VIA):
                reverse.setdefault(edge.dst, []).append(edge.src)
        seen: set[str] = set()
        frontier = [node_id]
        while frontier:
            current = frontier.pop()
            for upstream in reverse.get(current, []):
                if upstream != node_id and upstream not in seen:
                    seen.add(upstream)
                    frontier.append(upstream)
        return frozenset(seen)
