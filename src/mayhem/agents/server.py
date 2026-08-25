"""Agent-side JSON-RPC server loop over ndjson stdio (ADR-0003).

The agent never listens on sockets: the controller spawns it (locally or over
``ssh … mayhem-agent serve``) and drives the session through its stdin/stdout.
stderr is reserved for logs, never protocol frames.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import TYPE_CHECKING, Any

from mayhem.agents import protocol as rpc
from mayhem.agents.watchdog import DEFAULT_SWEEP_INTERVAL_S, AgentWatchdog
from mayhem.domain.leases import FaultLease
from mayhem.toolkit.fingerprint import interpreter_marker

if TYPE_CHECKING:
    from mayhem.agents.executors import FaultExecutor

AGENT_VERSION = "0.1.0.dev0"


class TaskRecord:
    def __init__(self, task_id: str, params: dict[str, Any]) -> None:
        self.task_id = task_id
        self.params = params
        self.state = "queued"
        self.detail = ""
        self.handle: asyncio.Task[dict[str, Any]] | None = None


class AgentServer:
    """Serves one controller session. One instance per spawned process."""

    def __init__(
        self,
        roles: tuple[str, ...],
        executors: tuple[FaultExecutor, ...] = (),
        agent_id: str | None = None,
        watchdog_interval_s: float = DEFAULT_SWEEP_INTERVAL_S,
    ) -> None:
        self.agent_id = agent_id or f"ag-{interpreter_marker()}"
        self.roles = roles
        self._executors = executors
        self._tasks: dict[str, TaskRecord] = {}
        self._task_counter = 0
        self.watchdog = AgentWatchdog(interval_s=watchdog_interval_s)

    # -- method dispatch -----------------------------------------------------

    async def handle(self, request: rpc.RpcRequest) -> rpc.RpcResponse:
        try:
            rpc._require_context(request.params)
        except rpc.ProtocolError as exc:
            return rpc.error_response(request.id, exc.code, str(exc))
        handler = {
            rpc.METHOD_HANDSHAKE: self._on_handshake,
            rpc.METHOD_CAPABILITIES_QUERY: self._on_capabilities,
            rpc.METHOD_TASK_EXECUTE: self._on_task_execute,
            rpc.METHOD_TASK_CANCEL: self._on_task_cancel,
            rpc.METHOD_TASK_STATUS: self._on_task_status,
            rpc.METHOD_HEALTH_PING: self._on_health_ping,
        }.get(request.method)
        if handler is None:
            return rpc.error_response(
                request.id,
                rpc.RpcErrorCode.METHOD_NOT_FOUND,
                f"no such method: {request.method}",
            )
        try:
            result = await handler(request.params)
        except Exception as exc:  # the wire must never see a traceback crash
            return rpc.error_response(
                request.id,
                rpc.RpcErrorCode.INTERNAL_ERROR,
                f"{type(exc).__name__}: {exc}",
            )
        return rpc.result_response(request.id, result)

    async def _on_handshake(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "protocol": rpc.PROTOCOL_VERSION,
            "agent_version": AGENT_VERSION,
            "roles": list(self.roles),
        }

    async def _on_capabilities(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "roles": list(self.roles),
            "faults": sorted({f for ex in self._executors for f in ex.capable_faults()}),
        }

    async def _on_health_ping(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "pong": True,
            "inflight": len(self._tasks),
            "owned_leases": self.watchdog.active_count(),
        }

    async def _on_task_execute(self, params: dict[str, Any]) -> dict[str, Any]:
        fault_id = params.get("fault_id")
        if not isinstance(fault_id, str) or not fault_id:
            raise ValueError("task.execute requires fault_id")
        executor = next((ex for ex in self._executors if ex.supports(fault_id)), None)
        if executor is None:
            raise LookupError(f"agent has no executor for fault {fault_id}")
        try:
            lease = (
                params["lease"]
                if isinstance(params["lease"], FaultLease)
                else FaultLease.model_validate(params["lease"])
            )
        except Exception as exc:
            raise ValueError(f"invalid lease payload: {exc}") from exc
        self._task_counter += 1
        task_id = f"t-{self._task_counter:06d}"
        record = TaskRecord(task_id, params)
        record.state = "running"
        self._tasks[task_id] = record
        phase = params.get("phase", "inject")
        try:
            outcome = (
                await asyncio.to_thread(executor.inject, lease)
                if phase == "inject"
                else await asyncio.to_thread(executor.undo, lease)
            )
        except Exception as exc:
            record.state = "failed"
            record.detail = f"{type(exc).__name__}: {exc}"
            raise
        if phase == "inject" and outcome.ok:
            self.watchdog.register(
                lease_id=str(lease.id),
                lease=lease,
                executor=executor,
                ttl_seconds=float(lease.ttl_seconds),
                task_id=task_id,
            )
        record.state = "done"
        record.detail = outcome.detail
        return {
            "task_id": task_id,
            "state": "done",
            "ok": outcome.ok,
            "detail": outcome.detail,
        }

    async def _on_task_cancel(self, params: dict[str, Any]) -> dict[str, Any]:
        task_id = params.get("task_id")
        record = self._tasks.get(task_id) if isinstance(task_id, str) else None
        if record is None:
            return {"task_id": task_id, "state": "unknown"}
        if record.handle is not None and not record.handle.done():
            record.handle.cancel()
        record.state = "cancelled"
        return {"task_id": task_id, "state": "cancelled"}

    async def _on_task_status(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("task_id")
        records = (
            [r for r in self._tasks.values() if r.task_id == requested]
            if isinstance(requested, str)
            else list(self._tasks.values())
        )
        return {
            "tasks": [
                {"task_id": r.task_id, "state": r.state, "detail": r.detail} for r in records
            ],
            "watchdog": self.watchdog.snapshot(),
            "compensated": self.watchdog.history(),
        }

    # -- io loop ---------------------------------------------------------------

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Consume requests until EOF; every line gets exactly one response."""
        while True:
            raw = await reader.readline()
            if not raw:
                break
            await self._serve_line(raw.strip(), writer)
        if not writer.is_closing():
            await writer.drain()
            writer.close()

    async def _serve_line(self, raw: bytes, writer: asyncio.StreamWriter) -> None:
        try:
            frame = rpc.decode(raw)
        except rpc.ProtocolError as exc:
            response = rpc.error_response(None, exc.code, str(exc))
            writer.write(rpc.encode(response))
            await writer.drain()
            return
        if isinstance(frame, rpc.RpcResponse):
            return  # agents do not consume responses on their own session
        if isinstance(frame, rpc.RpcNotification):
            return  # event.emit / log.emit are accepted and dropped (logged via stderr)
        response = await self.handle(frame)
        writer.write(rpc.encode(response))
        await writer.drain()


def serve_sync(roles: tuple[str, ...], executors: tuple[FaultExecutor, ...]) -> None:
    """Blocking stdio entrypoint used by ``mayhem-agent serve``.

    Prefers a fully-async session so the ADR-0005 watchdog keeps sweeping even
    while stdin is idle; falls back to per-line pumping where the platform
    cannot wrap stdio as pipes.
    """
    server = AgentServer(roles=roles, executors=executors)
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_serve_async(server))
    except NotImplementedError, ValueError:
        _serve_blocking(server, loop)
    finally:
        loop.close()


async def _serve_async(server: AgentServer) -> None:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    transport, protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(transport, protocol, None, loop)
    server.watchdog.start()
    try:
        await server.serve(reader, writer)
    finally:
        await server.watchdog.stop()


def _serve_blocking(server: AgentServer, loop: asyncio.AbstractEventLoop) -> None:
    """Per-line fallback: watchdog sweeps piggyback on request processing."""
    while True:
        raw = sys.stdin.readline()
        if not raw:
            break
        line = raw.strip()
        if not line:
            continue
        try:
            frame = rpc.decode(line.encode("utf-8"))
        except rpc.ProtocolError as exc:
            _write_frame(rpc.error_response(None, exc.code, str(exc)))
            continue
        if isinstance(frame, rpc.RpcResponse):
            continue
        if isinstance(frame, rpc.RpcNotification):
            continue  # accepted; logs/events surface on stderr
        try:
            response = loop.run_until_complete(
                asyncio.gather(server.handle(frame), server.watchdog.sweep())
            )[0]
        except Exception as exc:  # session must survive handler bugs
            response = rpc.error_response(
                frame.id,
                rpc.RpcErrorCode.INTERNAL_ERROR,
                f"{type(exc).__name__}: {exc}",
            )
        _write_frame(response)


def _write_frame(response: rpc.RpcResponse) -> None:
    sys.stdout.write(rpc.encode(response).decode("utf-8"))
    sys.stdout.flush()


def frames_from_jsonl(text: str) -> list[dict[str, Any]]:
    """Debug helper: pretty-print captured ndjson traffic (`| jq` equivalent)."""
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out
