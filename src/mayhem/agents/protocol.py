"""ndjson JSON-RPC 2.0 framing for controller↔agent communication (ADR-0003).

One JSON object per line. Requests carry an id; notifications do not.
Every params payload carries ``run_id``/``agent_id`` context for correlation —
enforced here at the frame level so no handler can forget it.
"""

from __future__ import annotations

import json
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

PROTOCOL_VERSION = "mayhem/1"


class RpcErrorCode(IntEnum):
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    TASK_FAILED = -32000  # implementation-defined server error range
    SAFETY_REFUSED = -32001


class ProtocolError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


class _Frame(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    jsonrpc: str = "2.0"

    @model_validator(mode="after")
    def _version(self) -> Any:
        if self.jsonrpc != "2.0":
            raise ValueError("jsonrpc must be '2.0'")
        return self


def _require_context(params: dict[str, Any]) -> None:
    missing = [key for key in ("run_id", "agent_id") if key not in params]
    if missing:
        raise ProtocolError(
            RpcErrorCode.INVALID_PARAMS,
            f"params missing correlation context: {', '.join(missing)}",
        )


class RpcRequest(_Frame):
    id: int | str
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class RpcNotification(_Frame):
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class RpcResponse(_Frame):
    id: int | str | None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None  # {"code": int, "message": str}

    @model_validator(mode="after")
    def _exactly_one(self) -> Any:
        if (self.result is None) == (self.error is None):
            raise ValueError("response must carry exactly one of result|error")
        return self


def encode(frame: RpcRequest | RpcNotification | RpcResponse) -> bytes:
    """Serialize one frame as a single ndjson line (newline included)."""
    return (frame.model_dump_json(exclude_none=True) + "\n").encode("utf-8")


def decode(line: str | bytes) -> RpcRequest | RpcNotification | RpcResponse:
    """Parse one ndjson line into a typed frame.

    Raises ProtocolError(PARSE_ERROR) on malformed JSON and
    ProtocolError(INVALID_REQUEST) on structurally invalid frames.
    """
    try:
        raw = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProtocolError(RpcErrorCode.PARSE_ERROR, f"bad json: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise ProtocolError(RpcErrorCode.INVALID_REQUEST, "frame must be a JSON object")
    try:
        if "method" in raw:
            if "id" in raw:
                return RpcRequest.model_validate(raw)
            return RpcNotification.model_validate(raw)
        return RpcResponse.model_validate(raw)
    except ValueError as exc:
        raise ProtocolError(RpcErrorCode.INVALID_REQUEST, str(exc)) from exc


def error_response(request_id: int | str | None, code: int, message: str) -> RpcResponse:
    return RpcResponse(id=request_id, error={"code": int(code), "message": message})


def result_response(request_id: int | str | None, result: dict[str, Any]) -> RpcResponse:
    return RpcResponse(id=request_id, result=result)


METHOD_HANDSHAKE = "handshake"
METHOD_CAPABILITIES_QUERY = "capabilities.query"
METHOD_TASK_EXECUTE = "task.execute"
METHOD_TASK_CANCEL = "task.cancel"
METHOD_TASK_STATUS = "task.status"
METHOD_LEASE_EXTEND = "lease.extend"
METHOD_HEALTH_PING = "health.ping"
NOTIFICATION_EVENT_EMIT = "event.emit"
NOTIFICATION_LOG_EMIT = "log.emit"
KNOWN_METHODS = frozenset(
    {
        METHOD_HANDSHAKE,
        METHOD_CAPABILITIES_QUERY,
        METHOD_TASK_EXECUTE,
        METHOD_TASK_CANCEL,
        METHOD_TASK_STATUS,
        METHOD_LEASE_EXTEND,
        METHOD_HEALTH_PING,
    }
)
KNOWN_NOTIFICATIONS = frozenset({NOTIFICATION_EVENT_EMIT, NOTIFICATION_LOG_EMIT})
