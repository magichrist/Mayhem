"""v1.1.0 plan 02 Phase 4 (fabric half) — k8s steps through the 03 fabric.

What is pinned, all with fakes (scripted session, in-memory journal and
lease sink — no cluster, no store):

1. **Dispatch through the fabric**: one k8s step dispatches under a lease and
   fence and settles ``COMPLETED``, with the agent-returned lease persisted
   through the sink (the controller is the single writer).
2. **Agent-loss fencing**: the lost agent's active leases are orphaned and a
   successor fence is minted; the deposed epoch can never act again
   (``fabric_stale_fence`` once the successor claims), while the successor
   redispatches under a fresh key.
3. **Startup reconciliation**: a "killed controller" (a new dispatcher over
   the same durable journal and sink) sees the open claim, the unreconciled
   lease, and the unrecovered step — and sees nothing after settling on an
   effect that created no lease.

What is *not* claimed: no verifier is bound here (the test signature is a
deterministic stub, and the module docstring says it must never reach a live
agent), no DaemonSet transport exists, and the phase acceptance
("controller-kill mid-fault recovers with evidence proving it") needs a live
cell — recorded as open debt in the plan ledger.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from mayhem.agents.sinks import InMemoryLeaseSink
from mayhem.controller.fabric_engine import (
    FABRIC_STALE_FENCE,
    FabricCommandRefused,
    ProviderResult,
)
from mayhem.controller.k8s_fabric import (
    InMemoryFabricJournal,
    K8sAgentRef,
    K8sFabricDispatcher,
    mint_k8s_command,
)
from mayhem.domain.common import utc_now
from mayhem.domain.fabric import FabricCommand, FencingToken
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.outcomes import StepOutcome

RUN_ID = "run-fabric-1"
STEP_ID = "s1"
AGENT = "agent-node-0"
SUCCESSOR = "agent-node-1"
PLAN = "ab" * 32
BODY = "cd" * 32
TARGET = "shop/checkout-00"
NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)


def _clock() -> Callable[[], datetime]:
    return lambda: NOW


def _sign(command_id: str) -> str:
    """Deterministic test stub, never a proof. Production binds plan 19's signer."""
    return hashlib.sha256(f"stub-sign:{command_id}".encode()).hexdigest()


class ScriptedSession:
    def __init__(self, *results: ProviderResult | BaseException) -> None:
        self._queue: list[ProviderResult | BaseException] = list(results)
        self.calls: list[FabricCommand] = []

    def dispatch(self, command: FabricCommand) -> ProviderResult:
        self.calls.append(command)
        if not self._queue:
            raise AssertionError(f"provider dispatched unexpectedly: {command.command_id}")
        nxt = self._queue.pop(0)
        if isinstance(nxt, BaseException):
            raise nxt
        return nxt


class Nonces:
    def __init__(self) -> None:
        self._n = 0

    def next(self) -> str:
        self._n += 1
        return f"{self._n:032x}"


def _agent(node: str = "node-0", agent_id: str = AGENT) -> K8sAgentRef:
    return K8sAgentRef(agent_id=agent_id, node=node, namespace="shop")


def _lease(lease_id: str = "l-1", *, owner: str = AGENT) -> FaultLease:
    return FaultLease(
        id=lease_id,
        run_id=RUN_ID,
        fault_id="k8s.pod_kill",
        owner_agent=owner,
        targets=frozenset({TARGET}),
        undo_ops=(UndoOp(op="k8s.exec", args={"undo": "uncordon"}),),
        verify_probes=(VerifyProbe(probe="k8s.pod_running", args={}),),
        state=LeaseState.ACTIVE,
        created_at=NOW,
    )


def _applied(lease: FaultLease | None = None) -> ProviderResult:
    return ProviderResult(ok=True, detail="pod deleted", target_ref=TARGET, lease=lease)


def _dispatcher(session: ScriptedSession, **overrides: object) -> K8sFabricDispatcher:
    fields: dict[str, object] = {
        "session": session,
        "journal": InMemoryFabricJournal(),
        "lease_sink": InMemoryLeaseSink(),
        "controller_id": "controller-1",
        "clock": _clock(),
    }
    fields.update(overrides)
    return K8sFabricDispatcher(**fields)  # type: ignore[arg-type]


def _mint(
    dispatcher: K8sFabricDispatcher,
    nonces: Nonces,
    *,
    command_id: str,
    key: str,
    epoch: int = 1,
    holder: str = AGENT,
    nonce: str | None = None,
) -> FabricCommand:
    fence = FencingToken(
        run_id=RUN_ID,
        step_id=STEP_ID,
        holder=holder,
        epoch=epoch,
        issued_at=NOW,
        supersedes_epoch=epoch - 1 if epoch > 1 else None,
    )
    return mint_k8s_command(
        run_id=RUN_ID,
        step_id=STEP_ID,
        command_id=command_id,
        agent=_agent(),
        plan_digest=PLAN,  # type: ignore[arg-type]
        nonce=nonce if nonce is not None else nonces.next(),
        idempotency_key=key,
        fence=fence,
        body_digest=BODY,
        body_ref="blob-1",
        signature=_sign(command_id),
        signing_key_id="key-1",
        issued_at=NOW,
    )


class TestFabricDispatch:
    def test_a_k8s_step_dispatches_and_settles_completed(self) -> None:
        nonces = Nonces()
        session = ScriptedSession(_applied(_lease()))
        dispatcher = _dispatcher(session)

        result = dispatcher.dispatch_step(
            _mint(dispatcher, nonces, command_id="fc-1", key="idem-1"),
            plan_digest=PLAN,  # type: ignore[arg-type]
            expected_target=TARGET,
        )

        assert result.ok
        assert result.outcome is StepOutcome.COMPLETED
        assert result.epoch == 1
        assert result.lease_id == "l-1"
        # The controller persisted the agent-returned lease (single writer).
        assert dispatcher.engine.unreconciled_leases(RUN_ID) == ()
        assert dispatcher.reconcile_on_startup(RUN_ID).open_claim_ids == ()

    def test_a_command_without_a_signature_has_no_constructor(self) -> None:
        import pytest

        with pytest.raises(TypeError):
            mint_k8s_command(  # type: ignore[call-arg]
                run_id=RUN_ID,
                step_id=STEP_ID,
                command_id="fc-x",
                agent=_agent(),
                plan_digest=PLAN,
                nonce="00" * 16,
                idempotency_key="idem-x",
                fence=FencingToken(
                    run_id=RUN_ID, step_id=STEP_ID, holder=AGENT, epoch=1, issued_at=NOW
                ),
                body_digest=BODY,
                body_ref="blob-1",
                signing_key_id="key-1",
                issued_at=NOW,
            )


class TestAgentLossFencing:
    def test_loss_orphans_leases_mints_a_successor_and_deposes_the_old_epoch(self) -> None:
        import pytest

        nonces = Nonces()
        session = ScriptedSession(_applied(_lease()), _applied(_lease("l-2")))
        dispatcher = _dispatcher(session)

        first = dispatcher.dispatch_step(
            _mint(dispatcher, nonces, command_id="fc-1", key="idem-1"),
            plan_digest=PLAN,  # type: ignore[arg-type]
            expected_target=TARGET,
        )
        assert first.ok

        outcome = dispatcher.handle_agent_loss(
            RUN_ID, STEP_ID, lost_agent=AGENT, successor_holder=SUCCESSOR, now=NOW
        )

        assert outcome.successor_fence.epoch == 2
        assert outcome.orphaned_lease_ids == ("l-1",)
        assert dispatcher._sink.load("l-1") is not None
        assert dispatcher._sink.load("l-1").state is LeaseState.ORPHANED

        # The successor claims epoch 2 under a fresh key …
        second = dispatcher.dispatch_step(
            _mint(dispatcher, nonces, command_id="fc-2", key="idem-2", epoch=2, holder=SUCCESSOR),
            plan_digest=PLAN,  # type: ignore[arg-type]
            expected_target=TARGET,
        )
        assert second.ok and second.epoch == 2

        # … and the deposed epoch can never act again.
        with pytest.raises(FabricCommandRefused) as excinfo:
            dispatcher.dispatch_step(
                _mint(dispatcher, nonces, command_id="fc-old", key="idem-old", epoch=1),
                plan_digest=PLAN,  # type: ignore[arg-type]
                expected_target=TARGET,
            )
        assert excinfo.value.code == FABRIC_STALE_FENCE
        assert session.calls[-1].command_id == "fc-2"  # the refusal never reached a provider

    def test_a_pending_lease_needs_no_fencing(self) -> None:
        session = ScriptedSession()
        dispatcher = _dispatcher(session)
        pending = FaultLease(
            id="l-9",
            run_id=RUN_ID,
            fault_id="k8s.pod_kill",
            owner_agent=AGENT,
            targets=frozenset({TARGET}),
            created_at=NOW,
        )
        dispatcher._sink.save(pending)

        outcome = dispatcher.handle_agent_loss(
            RUN_ID, STEP_ID, lost_agent=AGENT, successor_holder=SUCCESSOR, now=NOW
        )

        assert outcome.orphaned_lease_ids == ()
        assert outcome.successor_fence.epoch == 1  # nothing was ever claimed


class TestStartupReconciliation:
    def test_a_restarted_controller_sees_the_crash_window(self) -> None:
        nonces = Nonces()
        journal = InMemoryFabricJournal()
        sink = InMemoryLeaseSink()
        session = ScriptedSession(_applied(_lease()))
        dispatcher = _dispatcher(session, journal=journal, lease_sink=sink)
        dispatcher.dispatch_step(
            _mint(dispatcher, nonces, command_id="fc-1", key="idem-1"),
            plan_digest=PLAN,  # type: ignore[arg-type]
            expected_target=TARGET,
        )
        assert dispatcher.reconcile_on_startup(RUN_ID).needs_attention

        # The controller dies: a new dispatcher over the same durable objects.
        restarted = _dispatcher(ScriptedSession(), journal=journal, lease_sink=sink)
        found = restarted.reconcile_on_startup(RUN_ID)

        assert found.unrecovered_steps == (STEP_ID,)
        # The lease was settled, so it is reconciled — the step is not.
        assert found.unreconciled_lease_ids == ()
        assert found.open_claim_ids == ()

    def test_an_unsettled_claim_and_its_lease_are_both_visible(self) -> None:
        """The crash signature: a claim with no settlement, plus a live lease
        no settlement points at (the controller died between receiving the
        lease and settling it). A restarted controller sees both."""
        import pytest

        from mayhem.controller.fabric_engine import DispatchSettlement
        from mayhem.domain.outcomes import TargetOutcome

        class _CrashOnSettle:
            def __init__(self, delegate: InMemoryFabricJournal) -> None:
                self._delegate = delegate

            def append(self, entry: object) -> None:
                if isinstance(entry, DispatchSettlement):
                    raise RuntimeError("controller died while settling a dispatch")
                self._delegate.append(entry)

            def entries(self, run_id: str, step_id: str | None = None) -> tuple[object, ...]:
                return self._delegate.entries(run_id, step_id)

        journal = InMemoryFabricJournal()
        sink = InMemoryLeaseSink()
        sink.save(_lease("l-crash"))
        dispatcher = _dispatcher(
            ScriptedSession(_applied(_lease("l-crash"))),
            journal=_CrashOnSettle(journal),  # type: ignore[arg-type]
            lease_sink=sink,
        )
        nonces = Nonces()
        with pytest.raises(RuntimeError, match="died while settling"):
            dispatcher.dispatch_step(
                _mint(dispatcher, nonces, command_id="fc-1", key="idem-1"),
                plan_digest=PLAN,  # type: ignore[arg-type]
                expected_target=TARGET,
            )

        restarted = _dispatcher(ScriptedSession(), journal=journal, lease_sink=sink)
        found = restarted.reconcile_on_startup(RUN_ID)
        assert found.open_claim_ids == ("fc-1",)
        assert found.unreconciled_lease_ids == ("l-crash",)
        assert found.needs_attention is True

        # Settle the claim once the lease has been dealt with; the window closes.
        restarted.settle_reconciled(
            RUN_ID,
            STEP_ID,
            outcome=StepOutcome.FAILED,
            detail="crash reconciliation: effect unknown, compensated",
            target_outcome=TargetOutcome.FAILED_TO_APPLY,
        )
        assert restarted.reconcile_on_startup(RUN_ID).open_claim_ids == ()

    def test_a_clean_restart_needs_nothing(self) -> None:
        dispatcher = _dispatcher(ScriptedSession())
        assert dispatcher.reconcile_on_startup(RUN_ID).needs_attention is False

    def test_settle_then_redispatch_needs_nothing_open(self) -> None:
        nonces = Nonces()
        journal = InMemoryFabricJournal()
        sink = InMemoryLeaseSink()
        dispatcher = _dispatcher(
            ScriptedSession(ProviderResult(ok=True, detail="pod deleted", target_ref=TARGET)),
            journal=journal,
            lease_sink=sink,
        )
        dispatcher.dispatch_step(
            _mint(dispatcher, nonces, command_id="fc-1", key="idem-1"),
            plan_digest=PLAN,  # type: ignore[arg-type]
            expected_target=TARGET,
        )
        restarted = _dispatcher(ScriptedSession(), journal=journal, lease_sink=sink)
        found = restarted.reconcile_on_startup(RUN_ID)
        assert found.open_claim_ids == ()
        assert found.unreconciled_lease_ids == ()
        assert found.unrecovered_steps == ()
        assert found.needs_attention is False


def test_the_dispatcher_binds_no_verifier_by_default() -> None:
    """Unverified dispatch is test-only: without a verifier nothing is proven.

    This test exists so the default cannot silently become "verified".
    """
    dispatcher = _dispatcher(ScriptedSession())
    assert dispatcher.engine.verification_enabled is False
    assert dispatcher.engine.verification_algorithm == ""
    assert utc_now() is not None
