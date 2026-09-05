"""PodmanAdapter — concrete RuntimeAdapter for the Podman engine (ADR-M3-1, ADR-M3-4).

Handles rootful and rootless Podman.  Rootless mode downgrades NETNS to
ALTERNATIVE and RESOURCE_LIMITS to UNSUPPORTED.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.runtime_adapter import (
    AdapterCapabilities,
    RuntimeAdapter,
    RuntimeCapability,
)
from mayhem.topology.providers.base import PartialGraph, TopologyProvider

# Module-level helpers from the original provider — unchanged.
from mayhem.topology.providers.docker_runtime import (
    _container_id,
    _container_name,
    _inspect_meta,
    _inspect_pid,
    _labels,
    _networks,
    _parse_ports,
    _ps,
)


def _detect_rootless(engine: str = "podman") -> bool:
    """Detect whether Podman is running rootless via ``podman info``."""
    try:
        out = subprocess.run(
            [engine, "info", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        data = json.loads(out.stdout.strip())
        host = data.get("host") or {}
        security = host.get("security") or {}
        return bool(security.get("rootless", False))
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError, ValueError):
        return False


class PodmanAdapter(RuntimeAdapter, TopologyProvider):
    """RuntimeAdapter for the local Podman engine.

    Handles both rootful and rootless modes.  Rootless detection is performed
    once at construction time and cached in the ``AdapterCapabilities``.
    """

    ENGINE = "podman"

    def __init__(
        self,
        engine: str = ENGINE,
        *,
        filter_project: str | None = None,
        filter_services: tuple[str, ...] | None = None,
        filter_names: tuple[str, ...] | None = None,
    ) -> None:
        self._engine = engine
        self._filter_project = filter_project
        self._filter_services = filter_services
        self._filter_names = filter_names
        self._rootless = _detect_rootless(engine)

    # -- identity ------------------------------------------------------------

    @property
    def id(self) -> str:
        suffix = f"+{self._filter_project}" if self._filter_project else ""
        return f"{self._engine}{suffix}"

    def is_available(self) -> bool:
        return shutil.which(self._engine) is not None

    # -- capabilities --------------------------------------------------------

    def capabilities(self) -> AdapterCapabilities:
        if self._rootless:
            # Rootless: NETNS=ALTERNATIVE, RESOURCE_LIMITS=UNSUPPORTED (ADR-M3-4)
            return AdapterCapabilities(
                engine=self._engine,
                rootless=True,
                supported=frozenset(
                    {
                        RuntimeCapability.EXEC,
                        RuntimeCapability.PID,
                        RuntimeCapability.SIGNAL,
                        RuntimeCapability.INSPECT,
                        RuntimeCapability.COMPOSE_FILTER,
                    }
                ),
                alternatives=frozenset({RuntimeCapability.NETNS}),
            )
        # Rootful: all SUPPORTED (same as docker)
        return AdapterCapabilities(
            engine=self._engine,
            rootless=False,
            supported=frozenset(RuntimeCapability),
            alternatives=frozenset(),
        )

    # -- container operations ------------------------------------------------

    def ps(self) -> list[dict[str, Any]]:
        return _ps(self._engine)

    def inspect(self, container_id: str) -> tuple[RuntimeIdentity, RuntimeMetadata | None]:
        container_name, created_at, started_at = _inspect_meta(self._engine, container_id)
        metadata = RuntimeMetadata.from_inspect(
            {
                "created_at": created_at,
                "started_at": started_at,
            },
            name=container_name,
        )
        identity = RuntimeIdentity(
            runtime=self._engine,
            host_id="host",
            runtime_id=container_id,
        )
        return identity, metadata

    def exec(self, container_id: str, cmd: list[str], *, timeout_s: float = 30) -> str:
        out = subprocess.run(
            [self._engine, "exec", container_id, *cmd],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_s,
        )
        return out.stdout

    def pid(self, container_id: str) -> int | None:
        return _inspect_pid(self._engine, container_id)

    def signal(self, container_id: str, signo: int) -> None:
        import signal as _signal

        try:
            sig = _signal.Signals(signo)
            signame = sig.name
        except (ValueError, AttributeError):
            signame = "SIGKILL"
        subprocess.run(
            [self._engine, "kill", "-s", signame, container_id],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def netns(self, container_id: str) -> str | None:
        """Return network-namespace path.

        In rootless mode this may require ``podman unshare nsenter`` — the
        caller receives ALTERNATIVE verdict and must degrade gracefully.
        """
        pid = _inspect_pid(self._engine, container_id)
        if pid is None:
            return None
        return f"/proc/{pid}/ns/net"

    # -- filtering -----------------------------------------------------------

    def filter_by_compose(
        self,
        project: str,
        services: tuple[str, ...] | None = None,
    ) -> None:
        self._filter_project = project
        self._filter_services = services

    def filter_by_names(self, names: list[str]) -> None:
        self._filter_names = tuple(names)

    # -- discovery (TopologyProvider) ----------------------------------------

    def _filter_rows(
        self,
        rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        allowed_names: set[str] | None = (
            {n.strip().lower() for n in self._filter_names} if self._filter_names else None
        )
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
                raw_name = _container_name(row)
                container_names = [n.strip().lower() for n in raw_name.strip("[]").split(",")]
                if not any(n in allowed_names for n in container_names):
                    continue
            result.append(row)
        return result

    def discover(self) -> PartialGraph:
        from mayhem.domain.topology import (
            ContainerNode,
            Edge,
            EdgeKind,
            HostNode,
        )

        try:
            rows = _ps(self._engine)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return PartialGraph(source=self._engine, notes=(str(exc),))

        rows = self._filter_rows(rows)

        nodes: list[Any] = []
        edges: list[Any] = []
        notes: list[str] = []

        host_id = f"h-{self._engine}-local"
        nodes.append(HostNode(id=host_id, name=self._engine, transport="local"))

        all_networks: set[str] = set()
        for row in rows:
            nets = row.get("Networks") or []
            if isinstance(nets, list):
                all_networks.update(nets)
        network_info = _networks(self._engine, sorted(all_networks))

        container_ips: dict[str, str] = {}
        for _net_name, net_data in network_info.items():
            for cid_key, ip_val in net_data.items():
                if cid_key != "subnet" and isinstance(ip_val, str) and "." in ip_val:
                    container_ips[cid_key] = ip_val

        for row in rows:
            labels = _labels(row)
            service_name = labels.get("com.docker.compose.service")
            ports = _parse_ports(row)
            container_id = _container_id(row)
            short_id = container_id[:12]
            ip_str = container_ips.get(short_id)
            ip_addr = None
            if ip_str:
                from pydantic.networks import IPvAnyAddress

                ip_addr = IPvAnyAddress(ip_str)

            nets = row.get("Networks") or []
            net_names = tuple(nets) if isinstance(nets, list) else ()

            container_name, created_at, started_at = _inspect_meta(self._engine, container_id)
            metadata = RuntimeMetadata.from_inspect(
                {
                    "labels": labels,
                    "created_at": created_at,
                    "started_at": started_at,
                    "image": str(row.get("Image") or ""),
                },
                name=container_name,
            )

            node = ContainerNode(
                id=f"ctr-{short_id}",
                name=_container_name(row),
                engine=self._engine,
                runtime_identity=RuntimeIdentity(
                    runtime=self._engine,
                    host_id=host_id,
                    runtime_id=container_id,
                ),
                runtime_metadata=metadata,
                state=str(row.get("State") or row.get("Status") or "unknown"),
                ports=ports,
                container_name=container_name,
                ip_address=ip_addr,
                image=str(row.get("Image") or ""),
                networks=net_names,
            )
            nodes.append(node)
            edges.append(Edge(src=node.id, dst=host_id, kind=EdgeKind.RUNS_ON))

            if service_name:
                edges.append(
                    Edge(src=node.id, dst=f"svc-{service_name}", kind=EdgeKind.CONTAINED_IN)
                )

            # Emit a ProcessNode for the container's main PID so process-addressed
            # faults (proc.pause / process.stop / process.kill) resolve a real PID
            # carried with the container's runtime address — the same contract as
            # the docker provider (ADR-0020 / ADR-M1-1).
            from mayhem.domain.topology import ProcessNode  # noqa: PLC0415

            process_name = service_name or _container_name(row)
            pid = _inspect_pid(self._engine, container_id)
            if pid is not None and process_name:
                proc_id = f"proc-{process_name}-{short_id}"
                proc_node = ProcessNode(
                    id=proc_id,
                    name=process_name,
                    pid=pid,
                    host_id=host_id,
                    cmdline=f"{self._engine} container {short_id}",
                    container_id=short_id,
                    container_name=container_name,
                )
                nodes.append(proc_node)
                edges.append(Edge(src=proc_id, dst=node.id, kind=EdgeKind.RUNS_ON))

        return PartialGraph(
            source=self._engine,
            nodes=tuple(nodes),
            edges=tuple(edges),
            notes=tuple(notes),
        )
