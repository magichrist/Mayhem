"""Node-agent execution through the 03 fabric (plan 02 Phase 4, fabric half).

Phase 4's evidence half (``controller/k8s_evidence.py``) records the admission
decision. This module is the other half the phase names: *executing* through
the fabric — leases, fencing, signed commands — with the lease sink as the
rendezvous a restarted controller reads.

What this module is
-------------------
A thin wiring layer over :class:`~mayhem.controller.fabric_engine.FabricEngine`.
It mints the envelope for one k8s step (:func:`mint_k8s_command`), dispatches
it through an injected agent session (:meth:`K8sFabricDispatcher.dispatch_step`),
marks a lost agent's leases so they cannot be mistaken for healthy ones
(:meth:`K8sFabricDispatcher.handle_agent_loss`), and aggregates the crash
window on restart (:meth:`K8sFabricDispatcher.reconcile_on_startup`).

What this module is not, stated as debt
---------------------------------------
* **No live agent session.** ``FabricSession`` is injected; tests use a
  scripted fake. A DaemonSet agent transport (controller-initiated dial to a
  pod IP, plan 19 mTLS) does not exist yet and is live-cluster work.
* **Verification is now bound by default, and still not X.509.**
  :func:`build_k8s_verifier` and :func:`build_k8s_signer` join plan 19 Phase 2's
  ``AgentCommandVerifier`` to the durable store, so ``signature`` is a *proof*
  rather than a claim for any caller that uses them — real HMAC-SHA256 over the
  canonical envelope, with the replay check backed by the ``agent_command_nonces``
  table. What that proves is unchanged: a holder of the shared key produced these
  bytes. It is not a public-key signature, there is no handshake, and no
  X.509 chain is validated. A caller that still passes ``verifier=None`` gets
  the signature-as-claim behaviour, which is now a deliberate choice rather than
  the default that used to apply to everyone.
* **Recovery is surfaced, not performed.** :meth:`handle_agent_loss` fences
  (successor epoch) and orphans the lost agent's *active* leases; the
  compensation itself stays with the janitor/watchdog paths that own it.
  The phase acceptance — "controller-kill mid-fault recovers with evidence
  proving it" — is therefore **not met** and needs a live cell (plan 01).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mayhem.agents.sinks import InMemoryLeaseSink
from mayhem.controller.fabric_engine import (
    DispatchRequest,
    DispatchResult,
    FabricEngine,
)
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.domain.fabric import (
    CommandBodyRef,
    FabricCommand,
    FabricCommandType,
    FencingToken,
    PlanDigest,
    StepSemantics,
    StepSpec,
)
from mayhem.domain.leases import FaultLease, LeaseState
from mayhem.infra.agent_identity_store import AgentIdentityRepository
from mayhem.infra.agent_identity_verifier import (
    AgentCommandVerifier,
    HmacSha256CommandSigner,
    HmacSha256SignatureVerifier,
    SqliteNonceLedger,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Collection
    from datetime import datetime

    from mayhem.agents.sinks import LeaseSink
    from mayhem.controller.fabric_engine import (
        DispatchSettlement,
        FabricCommandVerifierPort,
        FabricEvidenceRecorder,
        FabricJournal,
        FabricSession,
    )
    from mayhem.domain.outcomes import StepOutcome
    from mayhem.infra.agent_identity_verifier import KeyMaterialPort


@dataclass(frozen=True)
class K8sAgentRef:
    """The node agent a k8s step dispatches to: envelope identity + placement."""

    agent_id: str
    node: str
    namespace: str = "default"


@dataclass(frozen=True)
class AgentLossOutcome:
    """What losing an agent decided: the successor fence and the orphaned leases."""

    run_id: str
    step_id: str
    lost_agent: str
    successor_fence: FencingToken
    orphaned_lease_ids: tuple[str, ...]


@dataclass(frozen=True)
class StartupReconciliation:
    """The crash window a restarted controller must clear before redispatch.

    ``open_claims`` are effects whose happening is unknown; ``unreconciled``
    are live leases no settlement points at (the signature of a crash between
    receiving a lease and settling it); ``unrecovered`` are steps whose lease
    is not safe-terminal. A restarted controller settles or compensates these
    first, then mints a successor fence — never a retry into a second effect.
    """

    run_id: str
    open_claim_ids: tuple[str, ...]
    unreconciled_lease_ids: tuple[str, ...]
    unrecovered_steps: tuple[str, ...]

    @property
    def needs_attention(self) -> bool:
        """True when a restart found anything unfinished."""
        return bool(self.open_claim_ids or self.unreconciled_lease_ids or self.unrecovered_steps)


class InMemoryFabricJournal:
    """An append-only journal over a list, for tests and the k8s lane's wiring.

    Production binds
    :class:`~mayhem.controller.fabric_evidence.SqliteFabricJournal`; this one
    exists so the lane is drivable without a store. Entries are returned in
    append order, which is the only ordering the engine relies on.
    """

    def __init__(self) -> None:
        self._entries: list[object] = []

    def append(self, entry: object) -> None:
        self._entries.append(entry)

    def entries(self, run_id: str, step_id: str | None = None) -> tuple[object, ...]:
        return tuple(
            entry
            for entry in self._entries
            if getattr(entry, "run_id", None) == run_id
            and (step_id is None or getattr(entry, "step_id", None) == step_id)
        )


def mint_k8s_command(
    *,
    run_id: str,
    step_id: str,
    command_id: str,
    agent: K8sAgentRef,
    plan_digest: PlanDigest,
    nonce: str,
    idempotency_key: str,
    fence: FencingToken,
    body_digest: str,
    body_ref: str,
    signature: str,
    signing_key_id: str,
    issued_at: datetime | None = None,
) -> FabricCommand:
    """One signed-command envelope for a k8s step, addressed to a node agent.

    Every field is required — including ``signature``. There is no default
    signer here on purpose: the signature must come from the agent credential's
    real signer (plan 19), and a module-level default would be the fake
    signature every caller silently inherits.
    """
    return FabricCommand(
        protocol="mayhem/1",
        command_id=command_id,
        run_id=run_id,
        step_id=step_id,
        agent_id=agent.agent_id,
        plan_digest=plan_digest,
        nonce=nonce,
        idempotency_key=idempotency_key,
        fencing_token=fence,
        command=CommandBodyRef(
            command_type=FabricCommandType.INJECT,
            body_digest=body_digest,
            body_ref=body_ref,
        ),
        issued_at=issued_at if issued_at is not None else utc_now(),
        signing_key_id=signing_key_id,
        signature=signature,
    )


def k8s_step_spec(step_id: str, *, issued_at: datetime | None = None) -> StepSpec:
    """The planner-level step a k8s dispatch acts on: serial, exactly once."""
    return StepSpec(
        step_id=step_id,
        semantic=StepSemantics.SERIAL,
        issued_at=issued_at if issued_at is not None else utc_now(),
    )


# ── the default wiring: a real signer and a real verifier ─────────────────────
#
# Phase 4's recorded debt was, in these words: *"no verifier bound by default …
# the signature is a claim, not a proof."* That was true and it had a cause: the
# pieces existed (plan 19 Phase 2's `AgentCommandVerifier`,
# `HmacSha256CommandSigner`, `SqliteNonceLedger`, `AgentIdentityRepository`) and
# nothing joined them, so every caller had to assemble four collaborators and
# could get the order or the omissions wrong silently.
#
# The factory below is that assembly, once. It binds a verifier to the durable
# store, so the *absence* of verification now has to be requested explicitly
# instead of being what you get. It is deliberately not a module-level
# singleton: a verifier carries an identity store and a nonce ledger, and a
# process-wide one would be a second copy of durable state — exactly the
# stale-copy failure plan 19 Phase 2 refuses to allow.
#
# What is still NOT implemented, unchanged: the DaemonSet agent transport, and
# therefore any live cell. A signer and a verifier over a `Store` is real
# cryptography over real durable state, but it proves that a key holder produced
# these bytes — symmetric, not X.509, no handshake, no chain.


class K8sVerifierUnavailable(DomainError):
    """The k8s lane could not bind a verifier and refused to fake one."""


def build_k8s_verifier(
    store: Any,
    *,
    keys: KeyMaterialPort,
    controller_id: str,
    require_key_ids: Collection[str] = (),
    require_certificate: bool = True,
) -> AgentCommandVerifier:
    """Bind plan 19's verifier to a store, as the k8s lane's default.

    Args:
        store: The migrated control-plane store. Supplies both the agent
            identity/revocation repository (plan 19 Phase 1) and the durable
            nonce ledger (``agent_command_nonces``, M0032) that the replay check
            reads and writes.
        keys: Key material by ``signing_key_id``. Deliberately an injected port
            and never a file: this module must not decide where secrets live
            (that is plan 29's lane).
        controller_id: The receiving controller, so a command minted by another
            controller cannot spend this one's agents.
        require_key_ids: Key ids that **must resolve** through ``keys`` before the
            verifier is allowed to exist. Checked here, at construction, rather
            than left to fail at the first dispatch: a verifier whose keys do not
            resolve is not a working configuration, and the failure should name
            the key rather than arriving later as a signature refusal.
        require_certificate: Defaults to true. Pass false only for a deployment
            that has deliberately turned certificate recording off.

    Raises:
        K8sVerifierUnavailable: When a key id in ``require_key_ids`` does not
            resolve. Fail closed at construction, never substituted with an
            empty secret.
    """
    unresolved = sorted(key_id for key_id in require_key_ids if keys.lookup(key_id) is None)
    if unresolved:
        raise K8sVerifierUnavailable(
            f"no key material resolves for agent key id(s) {', '.join(unresolved)}; "
            f"refusing to construct a verifier that would refuse every command at "
            f"dispatch. Bind the keys, or pass verifier=None deliberately to keep the "
            f"signature-as-claim behaviour."
        )
    return AgentCommandVerifier(
        identities=AgentIdentityRepository(store),
        signature=HmacSha256SignatureVerifier(keys),
        nonces=SqliteNonceLedger(store),
        controller_id=controller_id,
        require_certificate=require_certificate,
    )


def build_k8s_signer(keys: KeyMaterialPort) -> HmacSha256CommandSigner:
    """The matching signer over the same key material.

    Paired with :func:`build_k8s_verifier` deliberately: both sides take the
    same ``keys`` port and both canonicalise through the same
    :func:`~mayhem.infra.agent_identity_verifier.signed_payload`, so "the signer
    and the verifier disagree about what was signed" is not a state this lane can
    be in.
    """
    return HmacSha256CommandSigner(keys)


class K8sFabricDispatcher:
    """Dispatch k8s steps through the 03 fabric with the lease sink behind them.

    Args:
        session: Controller-initiated agent session (injected; faked in tests).
        journal: Durable claim/settlement log. Defaults to an in-memory
            journal — adequate for unit proof, not for crash survival across
            processes (that needs the SQLite journal; named debt above).
        lease_sink: Write-ahead lease store. Defaults to an in-memory sink.
        controller_id: Who is dispatching; recorded on every claim.
        clock: Time source, injected for reproducibility.
        verifier: Plan 19's verifier when bound; ``None`` keeps the Phase-2
            behaviour (signature as claim). A dispatcher without a verifier
            must never dispatch to a live agent.
        evidence: Where decisions are sealed; optional, as on the engine.
    """

    def __init__(
        self,
        *,
        session: FabricSession,
        journal: FabricJournal | None = None,
        lease_sink: LeaseSink | None = None,
        controller_id: str,
        clock: Callable[[], datetime] = utc_now,
        verifier: FabricCommandVerifierPort | None = None,
        evidence: FabricEvidenceRecorder | None = None,
    ) -> None:
        self._engine = FabricEngine(
            session=session,
            journal=journal if journal is not None else InMemoryFabricJournal(),  # type: ignore[arg-type]
            lease_sink=lease_sink if lease_sink is not None else InMemoryLeaseSink(),
            controller_id=controller_id,
            clock=clock,
            verifier=verifier,
            evidence=evidence,
        )
        self._sink: LeaseSink = lease_sink if lease_sink is not None else InMemoryLeaseSink()
        self._controller_id = controller_id

    @property
    def engine(self) -> FabricEngine:
        """The underlying engine, for reconciliation reads in tests."""
        return self._engine

    def dispatch_step(
        self,
        command: FabricCommand,
        *,
        plan_digest: PlanDigest,
        expected_target: str | None = None,
    ) -> DispatchResult:
        """Dispatch one k8s step's envelope; refusals raise, outcomes return."""
        return self._engine.dispatch(
            DispatchRequest(
                step=k8s_step_spec(command.step_id),
                command=command,
                current_plan_digest=plan_digest,
                expected_target=expected_target,
            )
        )

    def successor_fence(
        self,
        run_id: str,
        step_id: str,
        *,
        holder: str,
        now: datetime | None = None,
    ) -> FencingToken:
        """The fence a successor controller (or a post-loss retry) dispatches under.

        Strictly newer than the highest fence ever claimed for the step, so a
        deposed owner can never act again under its old epoch. First dispatch
        mints epoch 1.
        """
        served = self._engine.served_fence(run_id, step_id)
        moment = now if now is not None else utc_now()
        if served is None:
            return FencingToken.issue(run_id=run_id, step_id=step_id, holder=holder, now=moment)
        return served.next_fence(holder=holder, now=moment)

    def handle_agent_loss(
        self,
        run_id: str,
        step_id: str,
        *,
        lost_agent: str,
        successor_holder: str,
        now: datetime | None = None,
    ) -> AgentLossOutcome:
        """Fencing policy for a lost node agent: fence first, orphan second.

        Returns the successor fence and marks the lost agent's *active* leases
        for this run as ``ORPHANED`` (saved back through the sink) so the
        janitor reclaims them instead of trusting them. ``PENDING`` leases need
        no fencing — nothing was injected under them yet. Compensation itself
        stays with the janitor/watchdog; this method surfaces, never performs.
        """
        moment = now if now is not None else utc_now()
        fence = self.successor_fence(run_id, step_id, holder=successor_holder, now=moment)
        orphaned: list[str] = []
        for lease in self._sink.active_leases():
            if lease.run_id != run_id or lease.owner_agent != lost_agent:
                continue
            if lease.state is not LeaseState.ACTIVE:
                continue
            self._sink.save(lease.transition(LeaseState.ORPHANED, now=moment))
            orphaned.append(lease.id)
        return AgentLossOutcome(
            run_id=run_id,
            step_id=step_id,
            lost_agent=lost_agent,
            successor_fence=fence,
            orphaned_lease_ids=tuple(orphaned),
        )

    def reconcile_on_startup(
        self, run_id: str, step_id: str | None = None
    ) -> StartupReconciliation:
        """Aggregate the crash window for ``run_id`` from journal + lease sink.

        A new dispatcher over the same durable journal and sink *is* a
        restarted controller: nothing here reads instance memory, so the
        answer is identical before and after the old controller died.
        """
        open_claims = self._engine.open_claims(run_id, step_id)
        unreconciled = self._engine.unreconciled_leases(run_id)
        if step_id is not None:
            unreconciled = tuple(
                lease
                for lease in unreconciled
                if _lease_step(self._engine, run_id, lease) == step_id
            )
        return StartupReconciliation(
            run_id=run_id,
            open_claim_ids=tuple(claim.command.command_id for claim in open_claims),
            unreconciled_lease_ids=tuple(lease.id for lease in unreconciled),
            unrecovered_steps=self._engine.unrecovered_steps(run_id)
            if step_id is None
            else tuple(step for step in self._engine.unrecovered_steps(run_id) if step == step_id),
        )

    def settle_reconciled(
        self,
        run_id: str,
        step_id: str,
        *,
        outcome: StepOutcome,
        detail: str = "",
        target_outcome: object = None,
    ) -> DispatchSettlement:
        """Close the newest unsettled claim after its lease has been dealt with."""
        return self._engine.settle_claim(
            run_id,
            step_id,
            outcome=outcome,
            detail=detail or f"settled by {self._controller_id} on startup reconciliation",
            target_outcome=target_outcome,  # type: ignore[arg-type]
        )


def _lease_step(engine: FabricEngine, run_id: str, lease: FaultLease) -> str | None:
    """The step whose settlement recorded ``lease``, or ``None`` when unreconciled."""
    for settlement in engine.settlements(run_id):
        if settlement.lease_id == lease.id:
            return settlement.step_id
    return None


__all__ = (
    "AgentLossOutcome",
    "InMemoryFabricJournal",
    "K8sAgentRef",
    "K8sFabricDispatcher",
    "StartupReconciliation",
    "k8s_step_spec",
    "mint_k8s_command",
)
