"""Container resolution — get current PID and IP from container names.

Resolution is invoked at execution time, not discovery time, so the PID is
never older than the injection syscall. A single ``inspect`` per container
returns the current main PID, IP address, and state (ADR-0020).

Import of this module is confined to ``topology`` per the import rule
([ADR-0013]) — it shells out to the container engine binary.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from mayhem.domain.identity import ProcessRuntimeIdentity, RuntimeIdentity, RuntimeMetadata

__all__ = [
    "ContainerInfo",
    "resolve_all",
    "resolve_container",
    "resolve_identity",
    "resolve_ip",
    "resolve_metadata",
    "resolve_pid",
    "resolve_process_identity",
]


@dataclass(frozen=True)
class ContainerInfo:
    pid: int
    ip_address: str
    state: str  # "running", "exited", etc.


def _detect_engine() -> str:
    """Return 'podman' or 'docker', preferring podman."""
    for engine in ("podman", "docker"):
        if shutil.which(engine):
            return engine
    raise RuntimeError("neither podman nor docker found in PATH")


def _inspect(engine: str, container_name: str, fmt: str) -> str:
    """Run ``engine inspect`` with a Go template format string."""
    cmd = [engine, "inspect", "--format", fmt, container_name]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{engine} inspect timed out for {container_name}") from exc
    if result.returncode != 0:
        raise RuntimeError(f"{engine} inspect failed for {container_name}: {result.stderr.strip()}")
    return result.stdout.strip()


def _host_for_engine(engine: str) -> str:
    """Local host identity for the active engine (ADR-M1-1)."""
    return f"h-{engine}-local"


def resolve_identity(container_name: str, engine: str | None = None) -> RuntimeIdentity:
    """Resolve the live ``RuntimeIdentity`` for a named container.

    The engine reports the container's full id via ``inspect .Id``; combined with
    the engine label and the local host identity this IS the equality key
    (ADR-M1-1). Raises :class:`RuntimeError` if the container is gone.
    """
    engine = engine or _detect_engine()
    runtime_id = _inspect(engine, container_name, "{{.Id}}")
    if not runtime_id:
        raise RuntimeError(f"container {container_name} has no runtime id")
    return RuntimeIdentity(runtime=engine, host_id=_host_for_engine(engine), runtime_id=runtime_id)


def resolve_metadata(container_name: str, engine: str | None = None) -> RuntimeMetadata:
    """Resolve descriptive metadata for a named container (ADR-M1-2)."""
    engine = engine or _detect_engine()
    fmt = "{{json .Config.Labels}}|{{.Created}}|{{.State.StartedAt}}|{{.Image}}"
    raw = _inspect(engine, container_name, fmt)
    labels_part, _, rest = raw.partition("|")
    created, _, rest2 = rest.partition("|")
    started, _, image = rest2.partition("|")
    try:
        labels = json.loads(labels_part) if labels_part else {}
    except json.JSONDecodeError:
        labels = {}
    return RuntimeMetadata.from_inspect(
        {
            "labels": labels if isinstance(labels, dict) else {},
            "created_at": created or None,
            "started_at": started or None,
            "image": image or None,
        },
        name=container_name,
    )


def resolve_pid(container_name: str, engine: str | None = None) -> int:
    """Get the current host PID for a named container."""
    engine = engine or _detect_engine()
    out = _inspect(engine, container_name, "{{.State.Pid}}")
    try:
        pid = int(out)
    except ValueError as exc:
        raise RuntimeError(
            f"{engine} inspect returned non-numeric pid {out!r} for {container_name}"
        ) from exc
    if pid <= 0:
        raise RuntimeError(f"container {container_name} has no running process (pid={pid})")
    return pid


def resolve_process_identity(
    pid: int,
    host_id: str,
    container_name: str | None = None,
) -> ProcessRuntimeIdentity:
    """Resolve the live process identity for a PID (ADR-M2 Phase 2.4).

    The boot time (``/proc/<pid>/stat`` field 22 — start time in clock ticks
    since boot) is read on Linux hosts to disambiguate PID recycling. On
    platforms without a procfs the boot time is ``None`` and the identity
    degrades to a pid-only key (the PID-reuse guard then cannot distinguish a
    recycled PID, so container-addressed faults still carry their runtime id).
    """
    boot_time: int | None = None
    if sys.platform.startswith("linux"):
        stat_path = f"/proc/{pid}/stat"
        try:
            raw = Path(stat_path).read_text()
            # field 22 is starttime; fields 3.. are comm (may contain spaces in
            # parentheses), so split AFTER the closing ')' of the comm field.
            rest = raw.split(")", maxsplit=1)[1]
            fields = rest.split()
            boot_time = int(fields[19]) if len(fields) > 19 else None
        except (OSError, ValueError, IndexError):
            boot_time = None
    return ProcessRuntimeIdentity(
        host_id=host_id,
        pid=pid,
        boot_time=boot_time,
        container_name=container_name,
    )


def resolve_ip(container_name: str, engine: str | None = None) -> str:
    """Get the current IP address for a named container."""
    engine = engine or _detect_engine()
    fmt_ip = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    return _inspect(engine, container_name, fmt_ip)


def resolve_container(container_name: str, engine: str | None = None) -> ContainerInfo:
    """Resolve PID, IP, and state for a named container in one inspect pass.

    May raise :class:`RuntimeError` if the container is missing or stopped.
    """
    engine = engine or _detect_engine()
    pid = resolve_pid(container_name, engine)
    ip = resolve_ip(container_name, engine)
    state = _inspect(engine, container_name, "{{.State.Status}}")
    return ContainerInfo(pid=pid, ip_address=ip, state=state)


def resolve_all(
    container_names: tuple[str, ...], engine: str | None = None
) -> dict[str, ContainerInfo]:
    """Resolve several containers by name, returning a name → info mapping.

    Containers that fail to resolve are omitted; no exception is raised.
    """
    engine = engine or _detect_engine()
    result: dict[str, ContainerInfo] = {}
    for name in container_names:
        try:
            result[name] = resolve_container(name, engine)
        except RuntimeError:
            continue
    return result
