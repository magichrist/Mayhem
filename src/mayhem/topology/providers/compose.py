"""ComposeFileProvider — docker-compose.yaml as first-class blueprint (ADR-0006).

Extracts services, images, networks, ports, healthcheck-gated ``depends_on``
(weight ≥ 2), and heuristically infers external dependencies from service env
vars. Inferred nodes are flagged and never targetable until allowlisted
([ADR-0012]).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    ExternalDependencyNode,
    NodeKind,
    ServiceNode,
)
from mayhem.topology.providers.base import PartialGraph

_URL_KEYS = re.compile(r"(DATABASE_URL|REDIS_URL|.*_URL|.*_ENDPOINT)$")
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://([^/@]+@)?(?P<host>[^/:?#]+)")


def _interpolate(value: str, env: dict[str, str]) -> str:
    """Minimal ${VAR} / ${VAR:-default} interpolation from .env."""

    def sub(match: re.Match[str]) -> str:
        expr = match.group(1)
        name, sep, default = expr.partition(":-")
        resolved = env.get(name.strip(), default if sep else "")
        return resolved

    return re.sub(r"\$\{([^}]+)\}", sub, value)


def _load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip("'\"")
    return env


def _parse_ports(raw: Any) -> tuple[int, ...]:
    ports: list[int] = []
    for item in raw or []:
        text = str(item)
        host_part = text.split(":", maxsplit=1)[0]
        if host_part.isdigit():
            ports.append(int(host_part))
    return tuple(sorted(set(ports)))


class ComposeFileProvider:
    id = "compose"

    def __init__(self, compose_path: str | Path) -> None:
        self._path = Path(compose_path)

    def is_available(self) -> bool:
        return self._path.exists()

    def discover(self) -> PartialGraph:
        document: dict[str, Any] = yaml.safe_load(self._path.read_text()) or {}
        services: dict[str, Any] = document.get("services") or {}
        env = _load_env_file(self._path.parent / ".env")

        nodes: list[Any] = []
        edges: list[Edge] = []
        notes: list[str] = []

        for name, svc in services.items():
            image = svc.get("image")
            nodes.append(
                ServiceNode(
                    id=f"svc-{name}",
                    name=name,
                    image=image,
                    exposed_ports=_parse_ports(svc.get("ports")),
                )
            )
            # EXPOSES is a self-edge carrying the declared port surface.
            for port in _parse_ports(svc.get("ports")):
                edges.append(Edge(src=f"svc-{name}", dst=f"svc-{name}", kind=EdgeKind.EXPOSES))

            depends = svc.get("depends_on") or {}
            pairs: list[tuple[str, float]] = []
            if isinstance(depends, dict):
                for dep_name, cfg in depends.items():
                    condition = (cfg or {}).get("condition", "service_started")
                    weight = 2.0 if condition == "service_healthy" else 1.0
                    pairs.append((dep_name, weight))
            elif isinstance(depends, list):
                pairs.extend((dep_name, 1.0) for dep_name in depends)
            for dep_name, weight in pairs:
                edges.append(
                    Edge(
                        src=f"svc-{name}",
                        dst=f"svc-{dep_name}",
                        kind=EdgeKind.DEPENDS_ON,
                        weight=weight,
                    )
                )

            environment = svc.get("environment") or {}
            if isinstance(environment, list):
                environment = {
                    entry.split("=", 1)[0]: entry.split("=", 1)[1]
                    for entry in environment
                    if "=" in entry
                }
            for key, raw_value in environment.items():
                value = _interpolate(str(raw_value), env)
                if not _URL_KEYS.match(key):
                    continue
                match = _URL_RE.match(value)
                if match is None:
                    continue
                host = match.group("host")
                node_id = f"ext-{host}"
                if any(getattr(n, "id", None) == node_id for n in nodes):
                    continue
                nodes.append(
                    ExternalDependencyNode(
                        id=node_id,
                        name=host,
                        endpoint=value.split("://", 1)[0] + "://" + host,
                        inferred=True,
                    )
                )
                notes.append(f"inferred external dependency {host!r} from {name}.{key}")

        known_service_ids = {n.id for n in nodes}
        kept: list[Edge] = []
        dropped_dep: list[str] = []
        for edge in edges:
            if (
                edge.kind is EdgeKind.DEPENDS_ON
                and edge.dst not in known_service_ids
            ):
                dropped_dep.append(edge.dst)
                continue
            kept.append(edge)
        if dropped_dep:
            notes.append(
                "depends_on references unknown services (dropped): "
                + ", ".join(sorted(set(dropped_dep)))
            )

        return PartialGraph(source=self.id, nodes=tuple(nodes), edges=tuple(kept),
                            notes=tuple(notes))


__all__ = ["ComposeFileProvider", "NodeKind"]
