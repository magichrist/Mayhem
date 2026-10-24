"""Plan 02 Phase 4 — the DaemonSet agent transport, **agent side**.

Plan 03 defined the envelope; ``FabricEngine`` defined the dispatch checks;
:class:`~mayhem.controller.k8s_fabric.K8sFabricDispatcher` wired the lane and
recorded its remaining debt: *"no DaemonSet agent transport exists and no live
cell has run it"*. The verifier half is closed
(:func:`~mayhem.controller.k8s_fabric.build_k8s_verifier`); this is the
transport. The controller half of it is
:mod:`mayhem.controller.k8s_transport`.

What this module is
-------------------
The agent's end of one established, controller-initiated connection.
:func:`serve_agent_session` is the loop — the same ``AgentServer``, the same
frames, the same one-request-one-response discipline as the stdio loop, over a
connected pair instead of stdio pipes.

**The agent is still not a listener** (ADR-0003: sessions stay
controller-initiated). Nothing here accepts an inbound connection, resolves a
pod IP, or opens a socket; the DaemonSet template's ``MAYHEM_AGENT_LISTEN=false``
holds in fact as well as in spirit. A caller opens the connection however their
deployment does and hands it here.

Why this half is here and the other half is not
-----------------------------------------------
:func:`serve_agent_session` takes an
:class:`AgentSessionConnection` and returns ``None``. It has no idea what a
:class:`~mayhem.domain.fabric.FabricCommand` is, never names a
``ProviderResult``, and never mentions the controller. That is not incidental
tidiness: the layering contract in ``tests/unit/test_import_contracts.py``
forbids ``mayhem.agents`` from importing ``mayhem.controller`` at all, because
that upward edge is what would let the agent layer start depending on
orchestration. The original single module mixed both halves and broke the
contract at import time — a failure that reads as an architecture regression,
not as a missing import.

So the seam is the same seam the protocol already draws: the agent answers
requests, the controller composes them into a dispatch. The two halves meet at
:class:`AgentSessionConnection` — a ``Protocol``, so the controller's session
satisfies it structurally without importing anything back.

What stays NOT implemented
--------------------------
No cluster was contacted and no live cell has run; plan 01's cells own the phase
acceptance. The connection is one synchronous request/response pair per dispatch.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from mayhem.agents import protocol as rpc

if TYPE_CHECKING:
    from mayhem.agents.server import AgentServer

__all__ = [
    "AgentSessionConnection",
    "serve_agent_session",
]


class AgentSessionConnection(Protocol):
    """An established, controller-initiated connection to one agent's serve loop.

    The transport's only IO seam, and the only thing that dials anything: a
    caller opens the connection however their deployment does (the
    controller's port-forward to a DaemonSet pod, a sidecar socket, an
    in-process pipe for tests) and hands it here.

    Both directions are async on purpose: the real connection is an asyncio
    pair shared with the agent's own serve loop, so a write that skips
    ``drain()`` would stall the very loop reading it.
    """

    async def send(self, line: str) -> None:
        """One ndjson frame out, flushed. Raises on a broken connection."""
        ...

    async def recv(self) -> str:
        """The next ndjson frame in. Raises on a broken or closed connection."""
        ...


async def serve_agent_session(server: AgentServer, connection: AgentSessionConnection) -> None:
    """Serve the agent's JSON-RPC loop over an established connection.

    The one entry point the DaemonSet agent uses: the pod hands its own
    connected socket to :class:`~mayhem.agents.server.AgentServer` through
    this adapter, and the protocol, ordering, and one-response-per-request
    discipline are the stdio loop's (:meth:`AgentServer.serve`). The frames
    are the frames, the errors are the errors; nothing about the wire
    changes because the transport under it did.

    The watchdog runs here exactly as the stdio loop's ``_serve_async``
    runs it: started for the life of the session, stopped in ``finally`` —
    so a fault this agent injected self-compensates past TTL even while
    the connection is idle, which is the whole point of ADR-0005.

    Malformed lines are answered with an error frame rather than dropped, so
    a half-written frame produces a diagnosable reply instead of a silent
    stall. The server's exception discipline is unchanged: a handler bug
    becomes an ``INTERNAL_ERROR`` reply, and the session survives it.
    """
    server.watchdog.start()
    try:
        while True:
            line = await connection.recv()
            await _serve_one_line(server, connection, line)
    finally:
        await server.watchdog.stop()


async def _serve_one_line(
    server: AgentServer, connection: AgentSessionConnection, line: str
) -> None:
    try:
        frame = rpc.decode(line)
    except rpc.ProtocolError as exc:
        await _send_response(connection, rpc.error_response(None, exc.code, str(exc)))
        return
    if isinstance(frame, (rpc.RpcResponse, rpc.RpcNotification)):
        return  # agents do not consume responses; notifications are accepted and dropped
    response = await server.handle(frame)
    await _send_response(connection, response)


async def _send_response(connection: AgentSessionConnection, response: rpc.RpcResponse) -> None:
    await connection.send(rpc.encode(response).decode("utf-8"))
