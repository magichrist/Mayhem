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

from pydantic.networks import IPvAnyAddress

from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    HostNode,
    PortBinding,
    ProcessNode,
)
from mayhem.topology.providers.base import PartialGraph


def _inspect_pid(engine: str, container_id: str) -> int | None:
    """Query the main PID of a running container via ``engine inspect``."""
    try:
        out = subprocess.run(
            [engine, "inspect", "--format", "{{.State.Pid}}", container_id],
            capture_output=True,
            text=True,
            timeout=5,
        )
        pid = int(out.stdout.strip())
        return pid if pid > 0 else None
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None


def _inspect_name(engine: str, container_id: str) -> str:
    """Query the canonical container name via ``engine inspect``.

    Docker returns ``/container-name``; we strip the leading ``/``.
    """
    try:
        out = subprocess.run(
            [engine, "inspect", "--format", "{{.Name}}", container_id],
            capture_output=True,
            text=True,
            timeout=5,
        )
        raw = out.stdout.strip()
        return raw.lstrip("/") if raw else ""
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return ""


def _inspect_meta(engine: str, container_id: str) -> tuple[str, str | None, str | None]:
    """Query name + lifecycle timestamps in a single inspect pass (ADR-M1-2).

    Returns ``(name, created_at, started_at)`` with the leading ``/`` stripped.
    """
    try:
        out = subprocess.run(  # noqa: PLW1510 — expected fire-and-forget inspect
            [
                engine,
                "inspect",
                "--format",
                "{{.Name}}|{{.Created}}|{{.State.StartedAt}}",
                container_id,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        raw = out.stdout.strip()
        name, _, rest = raw.partition("|")
        created, _, started = rest.partition("|")
        return (
            name.lstrip("/"),
            created or None,
            started or None,
        )
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return ("", None, None)


def _container_id(row: dict[str, Any]) -> str:
    """Extract container ID handling both Docker ('ID') and Podman ('Id') keys."""
    return str(row.get("ID") or row.get("Id") or "")


def _container_name(row: dict[str, Any]) -> str:
    """Extract a single container name handling Docker (str) and Podman (list)."""
    names = row.get("Names") or row.get("Name") or ""
    if isinstance(names, list):
        return names[0] if names else ""
    return str(names)


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
                raw_name = _container_name(row)
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

        nodes: list[HostNode | ContainerNode | ProcessNode] = []
        edges: list[Edge] = []
        notes: list[str] = []
        host_id = f"h-{self._engine}-local"
        nodes.append(HostNode(id=host_id, name=self._engine, transport="local"))

        # Discover network info for IP addresses.
        all_networks: set[str] = set()
        for row in rows:
            nets = row.get("Networks") or []
            if isinstance(nets, list):
                all_networks.update(nets)
        network_info = _networks(self._engine, sorted(all_networks))

        # Resolve container short_id → IP from network info.
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

            ip_addr = IPvAnyAddress(ip_str) if ip_str else None

            nets = row.get("Networks") or []
            net_names = tuple(nets) if isinstance(nets, list) else ()

            # Identity (ADR-M1-1) + descriptive metadata (ADR-M1-2) in one
            # inspect pass; `container_name` stays as the authored resolver key.
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

            # Container → service edge (contained_in).
            if service_name:
                edges.append(
                    Edge(src=node.id, dst=f"svc-{service_name}", kind=EdgeKind.CONTAINED_IN)
                )

            # Emit a ProcessNode for the container's main PID.
            process_name = service_name or node.name
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


def _parse_ports(row: dict[str, Any]) -> tuple[PortBinding, ...]:
    """Extract port bindings from a container ps row.

    Docker ``ps --format json`` emits *Ports* as a comma-separated string
    like ``"0.0.0.0:5432->5432/tcp"``.  Podman emits it as either a dict
    keyed by port number or a list of dicts with *host_port* keys.
    """
    raw = row.get("Ports")
    bindings: list[PortBinding] = []

    # Podman list-of-dicts: [{"host_port": 8080, "container_port": 80, ...}]
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and "host_port" in item:
                bindings.append(
                    PortBinding(
                        host_port=int(item["host_port"]),
                        container_port=int(item.get("container_port", item["host_port"])),
                        host_address=str(item.get("host_ip", "") or "0.0.0.0"),
                        protocol=str(item.get("protocol", "tcp")),
                    )
                )
        return tuple(bindings)

    # Podman dict: {"5432/tcp": []} or {"80/tcp": [{"HostPort": "8080"}]}
    if isinstance(raw, dict):
        for port_key, port_entries in raw.items():
            parts = str(port_key).split("/")
            try:
                cport = int(parts[0])
            except (ValueError, IndexError):
                continue
            proto = parts[1] if len(parts) > 1 else "tcp"
            if isinstance(port_entries, list) and port_entries:
                for entry in port_entries:
                    if isinstance(entry, dict):
                        bindings.append(
                            PortBinding(
                                host_port=int(entry.get("HostPort", cport)),
                                container_port=cport,
                                host_address=str(entry.get("HostIp", "") or "0.0.0.0"),
                                protocol=proto,
                            )
                        )
            else:
                bindings.append(PortBinding(host_port=cport, container_port=cport, protocol=proto))
        return tuple(bindings)

    # Docker string form: "0.0.0.0:5432->5432/tcp,192.168.1.5:8080->8080/tcp"
    for part in str(raw or "").split(","):
        if "->" in part:
            try:
                host_part, rest = part.split("->")
                host_addr, _, host_port_s = host_part.rpartition(":")
                cport_s, _, proto = rest.partition("/")
                bindings.append(
                    PortBinding(
                        host_port=int(host_port_s),
                        container_port=int(cport_s),
                        host_address=host_addr or "0.0.0.0",
                        protocol=proto.strip() or "tcp",
                    )
                )
            except (IndexError, ValueError):
                continue
    return tuple(bindings)


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


def _networks(engine: str, network_names: list[str]) -> dict[str, dict[str, str]]:
    """Discover network info: {network_name: {subnet, container_id: ip}}.

    Returns a mapping of network name → {subnet, container_id → ip_address}.
    """
    result: dict[str, dict[str, str]] = {}
    for net_name in network_names:
        try:
            out = subprocess.run(
                [engine, "network", "inspect", net_name, "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if out.returncode != 0:
                continue
            data = json.loads(out.stdout.strip())
            net = (
                data[0]
                if isinstance(data, list) and data
                else data
                if isinstance(data, dict)
                else {}
            )
            entry: dict[str, str] = {}
            subnets = net.get("subnets") or []
            if subnets and isinstance(subnets[0], dict):
                entry["subnet"] = subnets[0].get("subnet", "")
            containers = net.get("containers") or {}
            for cid, cdata in containers.items():
                if isinstance(cdata, dict):
                    interfaces = cdata.get("interfaces") or {}
                    for iface in interfaces.values():
                        subnets = iface.get("subnets") or []
                        if subnets and isinstance(subnets[0], dict):
                            ipnet = subnets[0].get("ipnet", "")
                            if "/" in ipnet:
                                entry[cid[:12]] = ipnet.split("/")[0]
                            break
            result[net_name] = entry
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
            continue
    return result
