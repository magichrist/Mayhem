"""Plan 02 Phase 4 — the DaemonSet agent transport, **controller side**.

Plan 03 defined the envelope; ``FabricEngine`` defined the dispatch checks;
:class:`~mayhem.controller.k8s_fabric.K8sFabricDispatcher` wired the lane and
recorded its remaining debt: *"no DaemonSet agent transport exists and no live
cell has run it"*. The verifier half is closed
(:func:`~mayhem.controller.k8s_fabric.build_k8s_verifier`); this is the
transport. The agent half of it is
:mod:`mayhem.agents.k8s_session`.

What this module is
-------------------
One controller-side :class:`~mayhem.controller.fabric_engine.FabricSession`.
:class:`RemoteAgentFabricSession` mints the ``task.execute`` frame from a
:class:`~mayhem.domain.fabric.FabricCommand` and reads the agent's reply back
into a :class:`~mayhem.controller.fabric_engine.ProviderResult`. Every fabric
field maps onto an existing wire field — no second protocol:

- correlation: ``run_id`` / ``agent_id`` (frame-level enforced by
  :func:`mayhem.agents.protocol._require_context`); ``step_id``, the fence,
  the plan digest, the nonce and the idempotency key travel in params;
- body: ``command.body_ref`` **is** the fault id. The agent's ``task.execute``
  handler already dispatches on ``fault_id`` over its registered executors, so
  the fabric's opaque ``body_ref`` becomes the body verbatim, and
  ``body_digest`` is the sha256 of it. One encoding.
- identity of the effect: the task id is minted from the envelope's
  ``idempotency_key``, so a retried effect (new envelope, new nonce, same key)
  lands on the same agent-side task record — the agent's answer to "did this
  effect already run?" is the same object both times.
- **the write-ahead lease travels with the command.** The controller is the
  single lease writer (ADR-0007), and :mod:`mayhem.agents.server`'s
  ``task.execute`` requires a real :class:`~mayhem.domain.leases.FaultLease`
  in params — it *validates* it, executes it, and registers it with the agent
  watchdog on success. So :func:`lease_for_command` mints the ``PENDING`` lease
  controller-side (id deterministically derived from the idempotency key, fault
  id from ``body_ref``, placement from the agent's node) and the session sends
  it over the wire; the reply comes back and the session returns that same
  lease as ``ProviderResult.lease`` so the engine executes its normal sink
  write — the write-ahead record the crash-reconciliation projection reads.

**Fail-closed body digest.** :func:`digest_body_ref` hashes the body the
session is about to send and refuses :data:`BODY_DIGEST_MISMATCH` when it does
not match the envelope's own ``body_digest``. A body that contradicts its
envelope must never reach the wire — the digest is the one field every later
reader can use to answer "these bytes were intended".

Why this half lives under ``controller`` and not ``agents``
-----------------------------------------------------------
:class:`RemoteAgentFabricSession` **is** a ``FabricSession`` and returns
``ProviderResult`` values, so it cannot live below the controller: the layering
contract in ``tests/unit/test_import_contracts.py`` forbids
``mayhem.agents`` from importing ``mayhem.controller``, and an upward edge
there is exactly the dependency that would let the agent layer start depending
on orchestration. The transport's two halves were originally one module and that
module broke the contract at import time.

The two halves meet only at
:class:`~mayhem.agents.k8s_session.AgentSessionConnection`, which is a
``Protocol``: the session satisfies it structurally, so importing it here is a
one-way ``controller -> agents`` edge, which the contract permits.

What stays NOT implemented, unchanged and honestly stated
---------------------------------------------------------
No cluster was contacted and no live cell has run (plan 01's cells own the phase
acceptance); every dispatch is one synchronous request/response over the
injected connection; and the envelope's cryptographic authorisation remains
plan 19's verifier bound at the dispatcher — this transport adds none of its
own.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from typing import TYPE_CHECKING, Any

from mayhem.agents import protocol as rpc
from mayhem.controller.fabric_engine import FABRIC_MALFORMED_ENVELOPE, ProviderResult
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.domain.leases import FaultLease, LeaseState

if TYPE_CHECKING:
    # Type positions only, so these cost nothing at import time: the session is
    # never instantiated by name here, it is duck-typed through the connection
    # Protocol, and the agent ref is only an argument annotation.
    from mayhem.agents.k8s_session import AgentSessionConnection
    from mayhem.controller.k8s_fabric import K8sAgentRef
    from mayhem.domain.fabric import FabricCommand

__all__ = [
    "AGENT_MISMATCH",
    "BODY_DIGEST_MISMATCH",
    "RemoteAgentFabricSession",
    "TransportRefusedError",
    "digest_body_ref",
    "lease_for_command",
    "task_id_for",
]

#: A reply that does not come from the envelope's own agent. Spelled into
#: ``error_code`` on the settled result; the engine's drift table reads it as
#: drift because "an effect reported under another agent's name" is the same
#: shape as "a pod was replaced under the envelope" — mismatched, not failed.
AGENT_MISMATCH = "k8s.transport.agent_mismatch"

#: Body-vs-envelope contradiction, refused in the controller before the wire.
BODY_DIGEST_MISMATCH = "k8s.transport.body_digest_mismatch"

#: The engine's own malformation code, reused for a reply this transport
#: cannot parse — a malformed reply is not a fourth refusal category.
_MALFORMED = FABRIC_MALFORMED_ENVELOPE

_TASK_ID_SALT = "mayhem-task-id"
_LEASE_ID_SALT = "mayhem-lease"

#: The reply keys this transport reads, and the only ones it accepts.
_REPLY_KEYS = ("task_id", "state", "ok", "detail")


class TransportRefusedError(DomainError):
    """A transport-level refusal, carrying the code the engine normalises on.

    The engine's ``_invoke`` turns any exception into ``failed_to_apply``,
    which would lose the diagnosis. So the session catches this error itself
    and returns it as a settled ``ProviderResult(ok=False, error_code=…)``
    (see :meth:`RemoteAgentFabricSession.dispatch`), preserving the code —
    a refusal is a settled result, not an escape.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def digest_body_ref(body_ref: str, *, body_digest: str) -> None:
    """Verify the body the session will send against the envelope's digest.

    ``body_ref`` *is* the body (the fault id). Raises
    :data:`BODY_DIGEST_MISMATCH` when the envelope's own ``body_digest``
    does not name these bytes.
    """
    computed = hashlib.sha256(body_ref.encode("utf-8")).hexdigest()
    if computed != body_digest:
        raise TransportRefusedError(
            BODY_DIGEST_MISMATCH,
            f"command body digest mismatch: envelope claims {body_digest!r}; "
            f"the body the session would send hashes to {computed!r}",
        )


def task_id_for(command: FabricCommand) -> str:
    """The task id the agent records this dispatch under.

    The envelope's ``idempotency_key`` names the *effect*; minting the
    agent-side task id from it means a retried effect lands on the same task
    record, which is what makes the agent's side of "at-most-once per
    effect" decidable rather than assumed.
    """
    salted = f"{_TASK_ID_SALT}:{command.idempotency_key}"
    return uuid.uuid5(uuid.NAMESPACE_URL, salted).hex


def lease_for_command(command: FabricCommand, agent: K8sAgentRef) -> FaultLease:
    """Mint the write-ahead lease the dispatch carries to the agent.

    The controller is the single lease writer (ADR-0007) and the agent's
    ``task.execute`` handler *requires* a real :class:`FaultLease` it can
    validate and execute against — so the session mints one here rather than
    putting a digest string in a lease slot and calling it a lease.

    Determinism: the lease id is derived from the idempotency key the way
    the task id is, so a retried effect mints the same lease id on the
    controller side too. The lease stays ``PENDING``: its state advances
    only where the recovery contract owns the transitions, never inside the
    transport.
    """
    lease_id = (
        "l-" + uuid.uuid5(uuid.NAMESPACE_URL, f"{_LEASE_ID_SALT}:{command.idempotency_key}").hex
    )[:64]
    return FaultLease(
        id=lease_id,
        run_id=command.run_id,
        fault_id=command.command.body_ref,
        owner_agent=command.agent_id,
        targets=frozenset({agent.node}),
        state=LeaseState.PENDING,
        created_at=utc_now(),
    )


def _reply_payload_from_frame(frame: rpc.RpcResponse, command: FabricCommand) -> dict[str, Any]:
    """Read the agent's reply frame into the dict this transport trusts.

    * an error frame is a refusal the agent stated — translated to
      :data:`_MALFORMED`-coded refusal, never swallowed;
    * a result frame that is not an object, or that carries unrecognised
      keys, is refused as malformed;
    * a result carrying an ``agent_id`` other than the envelope's own raises
      :data:`AGENT_MISMATCH`.
    """
    if frame.error is not None:
        code = int(frame.error.get("code", rpc.RpcErrorCode.INTERNAL_ERROR))
        raise TransportRefusedError(
            _MALFORMED,
            f"agent refused the task for command {command.command_id!r} "
            f"[jsonrpc error {code}]: {frame.error.get('message', '')}",
        )
    result = frame.result
    if not isinstance(result, dict):
        raise TransportRefusedError(
            _MALFORMED,
            f"agent reply for command {command.command_id!r} is not a result object",
        )
    unexpected = sorted(set(result) - set(_REPLY_KEYS))
    if unexpected:
        raise TransportRefusedError(
            _MALFORMED,
            f"agent reply for command {command.command_id!r} carries unrecognised "
            f"key(s) {unexpected}; the transport reads {sorted(_REPLY_KEYS)} only",
        )
    agent_id = result.get("agent_id")
    if agent_id is not None and agent_id != command.agent_id:
        raise TransportRefusedError(
            AGENT_MISMATCH,
            f"agent reply for command {command.command_id!r} names agent "
            f"{agent_id!r} but the envelope addressed {command.agent_id!r}; "
            "the effect reported belongs to another dispatch",
        )
    return result


class RemoteAgentFabricSession:
    """The fabric's :class:`~mayhem.controller.fabric_engine.FabricSession`
    over a connected agent session.

    Constructs from an injected :class:`AgentSessionConnection`; the fabric
    engine calls :meth:`dispatch` synchronously, and the session runs one
    request/response round trip per dispatch over that connection.

    The session deliberately does **not**:

    - verify signatures (plan 19's verifier at the dispatcher owns that
      check);
    - decide outcomes (:func:`~mayhem.controller.fabric_engine.normalise_provider_result`
      owns the reading; this session refuses only structurally impossible
      replies);
    - invent a fourth outcome category or a second protocol verb;
    - re-mint a lease per retry: :func:`lease_for_command` derives the id
      from the idempotency key, so a retry mints the same lease id.
    """

    def __init__(self, *, agent: K8sAgentRef, connection: AgentSessionConnection) -> None:
        self._agent = agent
        self._connection = connection

    def dispatch(self, command: FabricCommand) -> ProviderResult:
        """One envelope out, one settled :class:`ProviderResult` back.

        Transport refusals are returned as ``ok=False`` results with the
        transport's ``error_code`` spelled onto the engine's existing
        reading — :data:`AGENT_MISMATCH` reads as drift (it is drift-shaped:
        the effect reported does not belong to this dispatch), everything
        else reads as failed-to-apply — the same discipline
        :func:`~mayhem.controller.fabric_engine._normalise_refusal` gives
        agent-side fabric refusals.
        """
        try:
            return asyncio.run(self._dispatch(command))
        except TransportRefusedError as exc:
            return ProviderResult(
                ok=False,
                detail=f"transport refused: {exc.message}",
                error_code=exc.code,
                target_ref=None,
                lease=None,
            )

    async def _dispatch(self, command: FabricCommand) -> ProviderResult:
        # 1. The envelope's own integrity first: never send a body the
        #    envelope contradicts.
        digest_body_ref(command.command.body_ref, body_digest=command.command.body_digest)
        lease = lease_for_command(command, self._agent)
        request = rpc.RpcRequest(
            id=task_id_for(command),
            method=rpc.METHOD_TASK_EXECUTE,
            params={
                "run_id": command.run_id,
                "agent_id": command.agent_id,
                "step_id": command.step_id,
                "fault_id": command.command.body_ref,
                "phase": "inject",
                "lease": lease.model_dump(mode="json"),
                "fence": command.fencing_token.model_dump(mode="json"),
                "plan_digest": command.plan_digest,
                "nonce": command.nonce,
                "idempotency_key": command.idempotency_key,
            },
        )
        await self._connection.send(rpc.encode(request).decode("utf-8"))
        reply_line = await self._connection.recv()
        reply_frame = rpc.decode(reply_line)
        if isinstance(reply_frame, (rpc.RpcRequest, rpc.RpcNotification)):
            raise TransportRefusedError(
                _MALFORMED,
                f"agent answered command {command.command_id!r} with a "
                f"{type(reply_frame).__name__} frame; a session is a "
                "request/response conversation",
            )
        result = _reply_payload_from_frame(reply_frame, command)
        state = str(result.get("state") or "")
        ok = bool(result.get("ok"))
        detail = str(result.get("detail") or "")
        task_id = str(result.get("task_id") or "")
        if state == "unknown":
            # The agent cannot resolve the task this envelope names; the
            # effect this envelope believed was in flight is not the one the
            # agent has — drift-shaped, spelled onto the engine's drift
            # table the same way a replaced pod is.
            return ProviderResult(
                ok=False,
                detail=detail or "agent reported state=unknown for this task",
                error_code="pod_replaced",
                target_ref=command.agent_id,
                lease=lease,
            )
        return ProviderResult(
            ok=ok,
            detail=detail or f"task {task_id!r} state {state!r}",
            error_code=None if ok else "task_failed",
            target_ref=command.agent_id,
            lease=lease,
        )
