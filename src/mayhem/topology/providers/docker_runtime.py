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
    text = out.stdout.strip()
    if not text:
        return []

    # Podman emits a single JSON array; Docker emits one JSON object per line.
    # Try the array form first — if the whole output parses as a list, extract
    # the dicts from it.  Otherwise fall back to line-by-line (NDJSON) parsing.
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
    except (json.JSONDecodeError, ValueError):
        pass

    rows: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue  # tolerate partial/fragment lines from pretty-printed output
        if isinstance(row, dict):
            rows.append(row)
    return rows


class ContainerRuntimeProvider:
    def __init__(
        self,
        engine: str,
        *,
        filter_project: str | None = None,
        filter_services: tuple[str, ...] | None = None,
        filter_names: tuple[str, ...] | None = None,
    ) -> None:
        self._engine = engine
        self._filter_project = filter_project
        self._filter_services = filter_services
        self._filter_names = filter_names

    @property
    def id(self) -> str:
        suffix = f"+{self._filter_project}" if self._filter_project else ""
        return f"{self._engine}{suffix}"

    @classmethod
    def best_effort(cls, engine: str | None = None) -> ContainerRuntimeProvider | None:
        """Return a provider for the requested engine, or whichever is available.

        *engine* may be ``"docker"`` or ``"podman"``.  When *None*, the first
        installed engine wins (docker preferred).
        """
        if engine is not None:
            if shutil.which(engine):
                return cls(engine)
            return None
        for candidate in ("docker", "podman"):
            if shutil.which(candidate):
                return cls(candidate)
        return None

    def is_available(self) -> bool:
        return shutil.which(self._engine) is not None

    def filter_by_compose(
        self,
        project: str,
        services: tuple[str, ...] | None = None,
    ) -> None:
        """Scope this provider to containers belonging to a compose project."""
        self._filter_project = project
        self._filter_services = services

    def filter_by_names(self, names: list[str]) -> None:
        """Scope this provider to containers matching explicit names."""
        self._filter_names = tuple(names)

    def _filter_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Narrow *rows* to containers matching the active filters.

        Filters are combined with AND semantics.  When no filters are set
        (standalone runtime mode), all rows pass through.
        """
        has_any_filter = (
            self._filter_project is not None
            or self._filter_services is not None
            or self._filter_names is not None
        )
        if not has_any_filter:
            return rows

        # Name filter is a simple substring match on the container name.
        allowed_names: set[str] | None = None
        if self._filter_names is not None:
            allowed_names = {n.lower() for n in self._filter_names}

        result: list[dict[str, Any]] = []
        for row in rows:
            labels = _labels(row)
            if self._filter_project is not None:
                project = labels.get("com.docker.compose.project", "")
                if project != self._filter_project:
                    continue
            if self._filter_services is not None:
                svc = labels.get("com.docker.compose.service", "")
                if svc and svc not in self._filter_services:
                    continue
            if allowed_names is not None:
                raw_name = str(row.get("Names") or row.get("Name") or "")
                container_names = [n.strip().lower() for n in raw_name.strip("[]").split(",")]
                if not any(n in allowed_names for n in container_names):
                    continue
            result.append(row)
        return result

    def discover(self) -> PartialGraph:
        try:
            rows = _ps(self._engine)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return PartialGraph(source=self._engine, notes=(f"engine probe failed: {exc}",))

        rows = self._filter_rows(rows)

        nodes: list[HostNode | ContainerNode] = []
        edges: list[Edge] = []
        host_id = f"h-{self._engine}-local"
        nodes.append(HostNode(id=host_id, name=self._engine, transport="local"))
        for row in rows:
            service_name = _labels(row).get("com.docker.compose.service")
            ports = _parse_ports(row)
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


def _parse_ports(row: dict[str, Any]) -> tuple[int, ...]:
    """Extract exposed host ports from a container inspect row.

    Docker ``ps --format json`` emits *Ports* as a comma-separated string
    like ``"0.0.0.0:5432->5432/tcp"``.  Podman emits it as a dict keyed by
    port number (e.g. ``{"5432": []}``).  Both cases are handled.
    """
    raw = row.get("Ports")
    if isinstance(raw, dict):
        return tuple(int(p) for p in raw if str(p).isdigit())
    ports: list[int] = []
    for part in str(raw or "").split(","):
        if "->" in part:
            try:
                host_port = int(part.split(":")[1].split("/")[0])
                ports.append(host_port)
            except (IndexError, ValueError):
                continue
    return tuple(ports)


def _labels(row: dict[str, Any]) -> dict[str, str]:
    raw = row.get("Labels")
    # Podman returns Labels as a dict; Docker returns a comma-separated string.
    if isinstance(raw, dict):
        return {k: str(v) for k, v in raw.items()}
    labels: dict[str, str] = {}
    for pair in str(raw or "").split(","):
        if "=" in pair:
            key, _, value = pair.partition("=")
            labels[key] = value
    return labels
