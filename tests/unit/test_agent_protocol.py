"""Unit tests for the ndjson JSON-RPC agent protocol and server (ADR-0003)."""

from __future__ import annotations

import asyncio
import json

import pytest

from mayhem.agents import protocol as rpc
from mayhem.agents.executors import NoopExecutor, ProcPauseExecutor
from mayhem.agents.server import AgentServer
from mayhem.agents.transports import LocalStdioTransport, SSHTransport, session_for

CTX = {"run_id": "r-x", "agent_id": "ag-t"}


class TestFraming:
    def test_request_roundtrip(self) -> None:
        request = rpc.RpcRequest(id=1, method="handshake", params=dict(CTX))
        decoded = rpc.decode(rpc.encode(request))
        assert isinstance(decoded, rpc.RpcRequest)
        assert decoded.method == "handshake"
        assert decoded.params == CTX

    def test_notification_has_no_id(self) -> None:
        note = rpc.RpcNotification(method="log.emit", params={**CTX, "line": "hi"})
        raw = rpc.decode(rpc.encode(note))
        assert isinstance(raw, rpc.RpcNotification)
        assert not hasattr(raw, "id")

    def test_response_requires_result_or_error(self) -> None:
        with pytest.raises(ValueError):
            rpc.RpcResponse(id=1)

    def test_bad_json_is_parse_error(self) -> None:
        with pytest.raises(rpc.ProtocolError) as excinfo:
            rpc.decode("{nope")
        assert excinfo.value.code == rpc.RpcErrorCode.PARSE_ERROR

    def test_missing_context_rejected_at_dispatch(self) -> None:
        server = AgentServer(roles=("proc",))
        request = rpc.RpcRequest(id=7, method="health.ping", params={})
        response = asyncio.run(server.handle(request))
        assert response.error is not None
        assert response.error["code"] == int(rpc.RpcErrorCode.INVALID_PARAMS)

    def test_unknown_method(self) -> None:
        server = AgentServer(roles=("proc",))
        request = rpc.RpcRequest(id=8, method="warp.drive", params=CTX)
        response = asyncio.run(server.handle(request))
        assert response.error["code"] == int(rpc.RpcErrorCode.METHOD_NOT_FOUND)


class TestServerMethods:
    def _server(self) -> AgentServer:
        return AgentServer(roles=("proc", "fuzz"), executors=(ProcPauseExecutor(), NoopExecutor()))

    def test_handshake_reports_identity(self) -> None:
        request = rpc.RpcRequest(id=1, method="handshake", params=CTX)
        response = asyncio.run(self._server().handle(request))
        result = response.result
        assert result["roles"] == ["proc", "fuzz"]
        assert result["protocol"] == rpc.PROTOCOL_VERSION
        assert result["agent_id"].startswith("ag-")

    def test_capabilities_lists_executor_families(self) -> None:
        request = rpc.RpcRequest(id=2, method="capabilities.query", params=CTX)
        result = asyncio.run(self._server().handle(request)).result
        assert {"proc", "fuzz", "load"} <= set(result["faults"])

    def test_health_ping(self) -> None:
        request = rpc.RpcRequest(id=3, method="health.ping", params=CTX)
        assert asyncio.run(self._server().handle(request)).result["pong"] is True

    def test_task_execute_with_unknown_fault_fails_cleanly(self) -> None:
        params = {**CTX, "fault_id": "net.latency", "phase": "inject"}
        request = rpc.RpcRequest(id=4, method="task.execute", params=params)
        response = asyncio.run(self._server().handle(request))
        assert response.error is not None  # LookupError mapped to INTERNAL_ERROR envelope

    def test_task_status_empty(self) -> None:
        request = rpc.RpcRequest(id=5, method="task.status", params=CTX)
        assert asyncio.run(self._server().handle(request)).result["tasks"] == []


class TestServeLoopOverPipes:
    def test_full_session_via_memory_streams(self) -> None:
        async def scenario() -> list[dict]:
            writer = _FakeWriter()
            server = AgentServer(roles=("proc",), executors=(ProcPauseExecutor(),))
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "handshake",
                 "params": {"run_id": "r-1", "agent_id": "c"}},
                {"jsonrpc": "2.0", "method": "log.emit",
                 "params": {"run_id": "r-1", "agent_id": "c", "line": "hello"}},
                {"jsonrpc": "2.0", "id": 2, "method": "capabilities.query",
                 "params": {"run_id": "r-1", "agent_id": "c"}},
                "{not json",
            ]
            for payload in requests:
                if isinstance(payload, str):
                    await server._serve_line(payload.encode(), writer)
                else:
                    await server._serve_line(json.dumps(payload).encode(), writer)
            return [json.loads(line) for line in writer.lines]

        responses = asyncio.run(scenario())
        assert len(responses) == 3  # notification produced no frame; bad json got an error frame
        assert responses[0]["result"]["protocol"] == rpc.PROTOCOL_VERSION
        assert responses[1]["result"]["faults"] == ["proc"]
        assert responses[2]["error"]["code"] == int(rpc.RpcErrorCode.PARSE_ERROR)


class _FakeWriter:
    """Duck-typed stand-in for asyncio.StreamWriter (write/drain/close only)."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def write(self, data: bytes | bytearray | memoryview) -> None:
        for chunk in bytes(data).splitlines():
            if chunk.strip():
                self.lines.append(chunk.decode())

    async def drain(self) -> None:
        pass

    def is_closing(self) -> bool:
        return False

    def close(self) -> None:
        pass


class TestTransports:
    def test_ssh_argv_shape(self) -> None:
        transport = SSHTransport("root@host-b")
        argv = transport.argv()
        assert argv[:2] == ["ssh", "-o"]
        assert "ControlMaster=auto" in argv and "ControlPersist=600" in argv
        assert argv[-1] == "mayhem-agent serve --roles proc,fs"

    def test_session_for_factory(self) -> None:
        assert isinstance(session_for(None, ("proc",)), LocalStdioTransport)
        assert isinstance(session_for("u@h", ("proc",)), SSHTransport)
