"""Container resolution — get current PID and IP from container names.

Resolution is invoked at execution time, not discovery time, so the PID is
never older than the injection syscall. A single ``inspect`` per container
returns the current main PID, IP address, and state (ADR-0020).

Import of this module is confined to ``topology`` per the import rule
([ADR-0013]) — it shells out to the container engine binary.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

__all__ = ["ContainerInfo", "resolve_all", "resolve_container", "resolve_ip", "resolve_pid"]


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
