"""ContainerRuntimeProvider — live truth via CLI, one code path (ADR-0006).

Docker and Podman share identical ``ps --format json`` semantics; the engine
binary is the only difference. CLI wrappers, not SDKs, so both engines and a
remote context behave identically. Import of this module is confined to
``topology/providers`` per the import rule ([ADR-0013]).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from mayhem.domain.topology import ContainerNode, Edge, EdgeKind, HostNode
from mayhem.topology.providers.base import PartialGraph


def _ps(engine: str) -> list[dict[str, Any]]:
    out = subprocess.run(
        [engine, "ps", "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    rows: list[dict[str, Any]] = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue  # some engines emit concatenated JSON; tolerate partial lines
        rows.append(row)
    return rows


class ContainerRuntimeProvider:
    def __init__(self, engine: str) -> None:
        self._engine = engine

    @property
    def id(self) -> str:
        return self._engine

    @classmethod
    def best_effort(cls) -> ContainerRuntimeProvider | None:
        """Return a provider for whichever engine binary exists, else None."""
        for engine in ("docker", "podman"):
            if shutil.which(engine):
                return cls(engine)
        return None

    def is_available(self) -> bool:
        return shutil.which(self._engine) is not None

    def discover(self) -> PartialGraph:
        try:
            rows = _ps(self._engine)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return PartialGraph(source=self._engine, notes=(f"engine probe failed: {exc}",))

        nodes: list[HostNode | ContainerNode] = []
        edges: list[Edge] = []
        host_id = f"h-{self._engine}-local"
        nodes.append(HostNode(id=host_id, name=self._engine, transport="local"))
        for row in rows:
            service_name = _labels(row).get("com.docker.compose.service")
            ports = tuple(
                int(p.split(":")[1].split("/")[0])
                for p in str(row.get("Ports") or "").split(",")
                if "->" in p
            )
            node = ContainerNode(
                id=f"ctr-{str(row.get('ID') or '')[:12]}",
                name=str(row.get("Names") or row.get("Name") or ""),
                engine=self._engine,
                runtime_id=str(row.get("ID") or ""),
                service_name=service_name,
                state=str(row.get("State") or row.get("Status") or "unknown"),
                ports=ports,
                host_id=host_id,
            )
            nodes.append(node)
            edges.append(Edge(src=node.id, dst=host_id, kind=EdgeKind.RUNS_ON))
        return PartialGraph(source=self._engine, nodes=tuple(nodes), edges=tuple(edges))


def _labels(row: dict[str, Any]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for pair in str(row.get("Labels") or "").split(","):
        if "=" in pair:
            key, _, value = pair.partition("=")
            labels[key] = value
    return labels
