# ADR-0020: Container-Name-First PID/IP Resolution

**Status:** Approved
**Date:** 2026-08-26
**Deciders:** Ali

## Context

`ProcessNode.pid` is set once during topology discovery via `_inspect_pid(engine, container_id)` using the short container hash (e.g., `c06f625c9d8d`). By execution time:

1. If a container restarted, the PID is stale
2. The short container hash itself can change on recreate
3. The PID may belong to a completely different process

This is the root cause of fault injection failures — `os.kill(stale_pid, SIGSTOP)` targets the wrong process or fails with `ProcessLookupError`.

The short container ID (`c06f625c9d8d`) is also ephemeral — it changes on every `docker-compose up`. But the `container_name:` (e.g., `testcase-api`) is stable across restarts and recreates.

## Decision

Resolve PIDs and IPs at execution time, just before injection, using the stable `container_name` — not at topology discovery time.

### Resolution Mechanism

```bash
# PID — runs immediately before the fault injection syscall
podman inspect --format '{{.State.Pid}}' testcase-api
# Fallback
docker inspect --format '{{.State.Pid}}' testcase-api

# IP address — for network faults
podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' testcase-api
# Fallback
docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' testcase-api
```

### Implementation

**New module:** `src/mayhem/topology/resolve.py`

```python
@dataclass(frozen=True)
class ContainerInfo:
    pid: int
    ip_address: str
    state: str  # "running", "exited", etc.


def resolve_pid(container_name: str, engine: str | None = None) -> int:
    """Get the current host PID for a named container."""


def resolve_ip(container_name: str, engine: str | None = None) -> str:
    """Get the current IP address for a named container."""


def resolve_container(container_name: str, engine: str | None = None) -> ContainerInfo:
    """Resolve PID + IP + state in a single inspect call."""
```

**Call site in executor:**

```python
# In RunEngine._execute_fault(), immediately before injection:
for target in resolved_targets:
    info = resolve_container(target.container_name, self._engine)
    live_targets.append(
        LiveTarget(
            node_id=target.node_id,
            pid=info.pid,  # fresh — resolved seconds ago
            ip_address=info.ip_address,
            container_name=target.container_name,
        )
    )
```

### Timing Guarantee

The PID is never older than the injection syscall. The resolve call happens in `_execute_fault()` immediately before the `os.kill(pid, SIGSTOP)` or `nsenter` invocation. If the container restarted between topology discovery and this moment, `resolve_pid()` gets the new PID. If the container is gone, `resolve_pid()` raises a clear error and the step fails cleanly.

### Domain Model Changes

- `ProcessNode.pid`: `int` → `int | None = None` (optional, resolved lazily)
- `ProcessNode.container_name`: new field `str | None = None`
- `ContainerNode.container_name`: new field `str | None = None`

### Why Not Alternatives

| Alternative | Why Rejected |
|-------------|-------------|
| Cache PID after first resolve | Still stale if container restarts |
| Watch container events for PID changes | Over-engineered for our use case |
| Use docker-compose service name directly | Compose names ≠ container names (e.g., `api` vs `testcase-api`) |
| Store PID in topology, refresh periodically | Unclear when to refresh; adds complexity |

## Consequences

- **Fresh PIDs always**: fault injection uses PIDs resolved seconds before injection
- **Container restarts tolerated**: if a container restarts between discovery and execution, the new PID is used
- **Lighter topology discovery**: no subprocess for PID during discovery — faster startup
- **Network faults work by name**: `net.partition` targets resolve IP from container name — no manual IP specification
- **Clear error on missing container**: `resolve_pid()` raises `RuntimeError` with container name — easy to debug
- **Undo/verify probes**: compensation and verification also resolve at their execution time, not plan time
