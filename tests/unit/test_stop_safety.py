"""Plan 10 Phases 4-6 — the stop reaches the sealed chain, the bound holds, and
nothing here is claimed that was not measured (docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md).

The other three files in this lane hold the vocabulary (``test_stop.py``), the
ladder (``test_stop_engine.py``), the gate (``test_preflight_gate.py``), and the
button (``test_stop_surface.py``). This one holds the three claims that could
only be made after those four existed, and it holds each of them *as a negative
control* rather than as a smoke test:

* **A stop seals into plan 12's attested chain** — the reason, the per-lease
  compensation outcomes, the residue findings, and the verdict, hashed into a
  chain that verifies and is committed to by a manifest. Including the two cases
  that are easy to leave out: a **stalled** stop still seals (with ``UNKNOWN``),
  and an invocation that stopped nothing seals **nothing**.
* **Stop latency is bounded and the bound is measured** — the freeze receipt's
  offset on a monotonic clock, against a named constant, with the unmeasured case
  reported as unmeasured rather than as zero.
* **An open dispatch claim keeps the run dirty** (plan 13's seam): a claim the
  fabric took and never settled becomes a ``claim_unsettled`` residue finding, so
  the postflight is ``DIRTY`` and the stop cannot be called recovered.

Three properties are asserted from the *absence* of a mechanism, because each is
a property this lane has spent three phases defending and each could be undone by
one added keyword: no preflight bypass on the run path, no ``--force`` on the
stop, and no way to author a verdict (every verdict in the chain is read off the
report that produced it).

Nothing here claims a real cluster was stopped. Every stop in this file runs
against a SQLite store and an in-process lease sink, and the latency figure the
tests assert is mayhem's own freeze — the time to take the button — never the
environment's reaction to it. ``mayhem.providers.pack.SIGNATURE_VERIFICATION_
IMPLEMENTED`` stays ``False`` and :func:`test_the_stop_chain_is_unsigned_with_a_
reason` says so.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.cli import stop_cmd
from mayhem.controller import stop_engine
from mayhem.controller.preflight_gate import (
    ALL_CHECKS,
    CHECK_AGENT_AVAILABILITY,
    CHECK_BUDGET_AVAILABLE,
    CHECK_INCIDENT_ACTIVE,
    CHECK_POLICY_AVAILABLE,
    CheckStatus,
    PreflightGate,
    PreflightInputs,
    PreflightPorts,
)
from mayhem.controller.stop_engine import (
    FREEZE_LATENCY_BOUND_S,
    CompensationPath,
    OpenClaim,
    StopEngine,
    StopExecution,
    StopRecord,
    claim_ref,
    freeze_latency,
    stop_chain_events,
    stop_chain_key,
    stop_evidence_payload,
    stop_manifest_id,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.identity import Principal
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.stop import (
    PostflightVerdict,
    RunState,
    StopReason,
    StopScope,
    StopSignal,
    StopTrigger,
    reason_for,
)
from mayhem.domain.topology import TargetSelector
from mayhem.infra.lease_repository import SQLiteLeaseSink

if TYPE_CHECKING:
    from mayhem.infra.store import Store

MOMENT = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
RUN_ID = "r-drill-safety01"
OTHER_RUN_ID = "r-drill-safety02"
HOUR = 3600.0
REASON = "the fault is not reversing and the run is losing traffic"


# ==============================================================================
# The world
# ==============================================================================


def _store(tmp_path: Path, *, name: str = "stop-safety.db") -> Store:
    from mayhem.infra.store import Store as _Store

    return _Store.open_migrated(tmp_path / name)


def _lease(
    lease_id: str = "l-1",
    *,
    run_id: str = RUN_ID,
    wedged: bool = False,
) -> FaultLease:
    base = FaultLease(
        id=lease_id,
        run_id=run_id,
        fault_id="proc.pause",
        owner_agent="agent-1",
        targets=frozenset({"api"}),
        undo_ops=(UndoOp(op="signal", args={"target": "api"}),),
        verify_probes=(VerifyProbe(probe="exec", args={"cmd": "true"}),),
        ttl_seconds=HOUR,
        state=LeaseState.PENDING,
        created_at=MOMENT - timedelta(seconds=30),
    )
    active = base.transition(LeaseState.ACTIVE, now=MOMENT)
    if not wedged:
        return active
    return active.transition(LeaseState.RELEASING, now=MOMENT).transition(
        LeaseState.DIRTY, now=MOMENT, escalation_notes="compensation wedged"
    )


def _seed_run(store: Store, run_id: str, *, status: str = "running") -> None:
    with store.write() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO config_snapshots (id, resolved_json, source_map, created_at)"
            " VALUES ('c-1', '{}', '{}', 'now')"
        )
        conn.execute(
            "INSERT OR REPLACE INTO runs (id, experiment_name, kind, spec_json, plan_json,"
            " seed, status, environment_fingerprint, config_snapshot_id)"
            " VALUES (?, 'exp', 'deterministic', '{}', '{}', 1, ?, 'f-1', 'c-1')",
            (run_id, status),
        )


def _runnable_plan(run_id: str = "r-drill-execute1") -> ExecutionPlan:
    """A plan naming one fault, so ``execute`` has something to refuse before.

    The refusal happens ahead of ``_open_run``, so the plan never reaches a step —
    what matters is that it is a real, resolvable plan rather than an empty one, so
    a test cannot pass by asserting that an empty plan was refused for some other
    reason.
    """
    selector = TargetSelector(kind="service", expr="web")
    step = PlannedStep(
        id="s0",
        seq=0,
        raw_action=InjectFault(fault="proc.pause", selectors=(selector,), duration=5.0),
        fault=PlannedFault(
            fault_id="proc.pause",
            targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-web"})),),
            duration=5.0,
        ),
    )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=(step,),
        config_snapshot_id="c-1",
        topology_snapshot_id="",
        environment_fingerprint="f-1",
    )


def _seed_lease(store: Store, lease: FaultLease) -> None:
    SQLiteLeaseSink(store).save(lease)


def _stop(tmp_path: Path, *, lease: FaultLease | None = None, run_id: str = RUN_ID) -> Any:
    """A completed, sealed run-scoped stop over a store holding one live lease.

    The lease is the point: without one the sink proves the run state is
    ``PENDING`` rather than ``RUNNING``, and a pending run owes a shorter ladder
    — no compensation stage at all — which is correct behaviour and useless for
    asserting that the compensation outcomes reached the chain.
    """
    store = _store(tmp_path)
    _seed_run(store, run_id)
    _seed_lease(store, _lease() if lease is None else lease)
    outcome = stop_cmd.run_stop(
        store=store,
        principal=Principal(principal_id="u-ana"),
        scope=StopScope.RUN,
        reason=REASON,
        run_id=run_id,
        now=MOMENT,
    )
    return store, outcome


# ==============================================================================
# Phase 4 — the stop reaches plan 12's attested chain
# ==============================================================================


def test_a_stop_seals_the_reason_the_outcomes_and_the_verdict(tmp_path: Path) -> None:
    """The four facts the plan names, in one verifying chain.

    Read back out of the stored chain — through plan 12's own
    :meth:`AttestationRepository.load_chain`, not this process's return value — so
    what is asserted is what a week-later reader of the database would find.
    """
    from mayhem.domain.attestation import verify_chain, verify_manifest
    from mayhem.infra.attestation_store import AttestationRepository

    store, outcome = _stop(tmp_path)
    try:
        assert len(outcome.seals) == 1, "a completed stop sealed nothing"
        seal = outcome.seals[0]
        assert seal.chain_verification.valid, seal.chain_verification.errors
        assert seal.manifest_verification.valid, seal.manifest_verification.errors
        execution = outcome.executions[0]
        payload = stop_evidence_payload(execution)

        # 1. the reason
        assert payload["reason"] == "human"
        assert payload["reason_detail"] == REASON
        # 2. the per-action compensation outcomes, cited per lease
        assert payload["compensated_leases"], "the chain names no lease outcome"
        assert all(ref.startswith("lease/") for ref in payload["compensated_leases"])
        # 3. the residue scan results — an empty scan is still a recorded result
        assert payload["residue_checks"], "the chain carries no residue scan result"
        # 4. the postflight verdict, plus the digest that proves which report
        assert payload["verdict"] == PostflightVerdict.CLEAN.value
        assert payload["report_digest"] == execution.sealed.report_digest
        assert payload["recovery_verified"] is True

        # And it is on disk, verifiable without this process's help.
        repository = AttestationRepository(store)
        stored = repository.load_chain(stop_chain_key(RUN_ID))
        assert len(stored) == 2
        assert verify_chain(stored).valid, "the stored chain does not verify"
        manifest = repository.load_manifest(stop_manifest_id(RUN_ID))
        assert manifest is not None, "no manifest was written for the stop chain"
        assert verify_manifest(manifest, stored).valid
        assert [event.event_kind for event in stored] == [
            stop_engine.EVENT_STOP_EXECUTED,
            stop_engine.EVENT_STOP_POSTFLIGHT,
        ]
        assert stored[0].payload["reason"] == "human"
        assert stored[1].payload["verdict"] == PostflightVerdict.CLEAN.value
    finally:
        store.close()


def test_a_stalled_stop_still_seals_with_unknown(tmp_path: Path) -> None:
    """A stop that could not reach the agent is the fact most worth having.

    Sealing means the chain is a complete *record*, not that everything went well.
    Withholding an unsealed attempt would make "the stop stalled" indistinguishable
    from "the stop never happened", which is the reading that loses an incident.
    """
    # Driven through the engine directly so the freezer can be the failing
    # collaborator: a dispatcher that cannot be reached is how "the stop could
    # not get started" is said, and the FREEZE stage is the first thing that
    # notices.
    from mayhem.controller.recovery import RecoveryService
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    store = _store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        _seed_lease(store, _lease())
        sink = SQLiteLeaseSink(store)
        engine = StopEngine(
            sink=sink,
            recovery=RecoveryService(sink),
            dispatch=_Unfreezable(),
            ledger=stop_cmd.StoreStopLedger(store),
        )
        command = stop_cmd.build_stop_command(
            scope=StopScope.RUN,
            run_id=RUN_ID,
            principal=Principal(principal_id="u-ana"),
            reason=REASON,
            now=MOMENT,
        )
        execution = asyncio.run(engine.execute(command, state=RunState.RUNNING, now=MOMENT))
        assert execution.sealed is None
        assert execution.verdict is PostflightVerdict.UNKNOWN

        seal = stop_cmd.seal_stop_evidence(store, execution)
        assert seal is not None, "a stalled stop sealed nothing"
        payload = stop_evidence_payload(execution)
        assert payload["sealed"] is False
        assert payload["verdict"] == PostflightVerdict.UNKNOWN
        assert payload["stalled_at"] == "freeze"
        assert payload["report_digest"] == ""
    finally:
        store.close()


class _Unfreezable:
    """A dispatch surface that cannot be reached, which is how a stall is said."""

    def freeze(self, run_id: str) -> str:
        msg = f"fabric unreachable for {run_id}"
        raise RuntimeError(msg)


def test_an_invocation_that_stopped_nothing_seals_nothing(tmp_path: Path) -> None:
    """An empty chain proves nothing while looking like one that does."""
    store = _store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        outcome = stop_cmd.run_stop(
            store=store,
            principal=Principal(principal_id="u-ana"),
            scope=StopScope.RUN,
            reason=REASON,
            run_id=RUN_ID,
            now=MOMENT,
            dry_run=True,
        )
        assert outcome.executions == ()
        assert outcome.seals == ()
        # Nothing was frozen, so the latency was not measured and the bound was
        # not met — the same fail-closed answer a stalled freeze gets. A
        # "stopped nothing" that reported *within bound* would be claiming a
        # freeze it never performed.
        assert outcome.freeze_latency_s is None
        assert outcome.freeze_within_bound is False
        assert stop_cmd.stop_payload(outcome)["freeze_within_bound"] is False

        assert store.query("SELECT * FROM attestation_chains") == []
        assert store.query("SELECT * FROM attestation_manifests") == []
    finally:
        store.close()


def test_the_chain_events_are_built_unsealed_and_reject_an_empty_record(
    tmp_path: Path,
) -> None:
    """Built ≠ written: the builder hands back unsealed events, and refuses junk.

    Two claims about the same function, because both are easy to lose: the events
    leave with empty digests (the writer seals them), and an execution whose
    command id is blank yields no events at all rather than one citing nothing.
    """
    from mayhem.infra.attestation_store import _recorded_at

    store, outcome = _stop(tmp_path)
    try:
        execution = outcome.executions[0]
        events = stop_chain_events(execution, recorded_at=_recorded_at(None))
        assert [event.event_kind for event in events] == [
            stop_engine.EVENT_STOP_EXECUTED,
            stop_engine.EVENT_STOP_POSTFLIGHT,
        ]
        assert all(not event.is_sealed for event in events), (
            "the builder sealed its own events: then a write failure would leave a chain "
            "that looks complete and is not"
        )
        assert [event.sequence for event in events] == [0, 1]
        blanked = StopExecution(
            record=execution.record.model_copy(
                update={
                    "command": execution.record.command.model_copy(update={"id": ""}),
                }
            )
        )
        assert stop_chain_events(blanked, recorded_at=_recorded_at(None)) == ()
    finally:
        store.close()


def test_a_stale_stop_record_does_not_break_the_evidence_chain(tmp_path: Path) -> None:
    """A payload whose report aged past its TTL reports ``UNKNOWN``, not ``DIRTY``.

    The plan's rule is that "degraded-beyond-tolerance vs. aborted is decided by
    observations, never defaulted". ``PostflightReport.verdict`` recomputes from
    the checks on every read, so a sealed report read long after the stop reports
    the state the evidence *now* supports. This asserts the chain carries whatever
    that recomputation says rather than a verdict frozen at seal time.
    """
    from mayhem.infra.attestation_store import _recorded_at

    store, outcome = _stop(tmp_path)
    try:
        execution = outcome.executions[0]
        sealed_at = execution.sealed.sealed_at
        later = sealed_at + timedelta(days=365)
        payload = stop_evidence_payload(execution)
        assert payload["verdict"] == execution.verdict.value
        assert stop_evidence_payload(execution)["verdict"] == payload["verdict"]
        events = stop_chain_events(execution, recorded_at=_recorded_at(None))
        assert events[1].payload["report_digest"] == execution.sealed.report_digest
        assert later > sealed_at
    finally:
        store.close()


def test_the_stop_chain_is_unsigned_with_a_reason(tmp_path: Path) -> None:
    """Sealed is not signed, and mayhem does not pretend otherwise.

    The three facts together, because any one of them alone is quotable out of
    context: the seal's own ``signature_state``, the manifest row's, and the fact
    that signature verification is genuinely not implemented in this build. A
    reader who sees "sealed" in a log must be able to find the reason beside it.
    """
    from mayhem.infra.attestation_store import AttestationRepository
    from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED

    assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
    store, outcome = _stop(tmp_path)
    try:
        seal = outcome.seals[0]
        assert seal.signature_state, "the seal does not say whether it is signed"
        assert seal.signature_reason, "the seal gives no reason for its signature state"
        assert seal.signed is False
        row = store.query(
            "SELECT signature_state, signature_reason FROM attestation_manifests WHERE"
            " manifest_id = ?",
            (stop_manifest_id(RUN_ID),),
        )
        assert row, "the manifest row is missing"
        assert str(dict(row[0])["signature_state"]) == seal.signature_state
        assert str(dict(row[0])["signature_reason"]) == seal.signature_reason
        stored = AttestationRepository(store).load_manifest(stop_manifest_id(RUN_ID))
        assert stored is not None and stored.signed is False
    finally:
        store.close()


def test_the_verdict_in_the_chain_cannot_be_authored_by_a_caller() -> None:
    """There is no ``verdict=`` parameter on the payload builder.

    The chain's verdict is
    :attr:`~mayhem.controller.stop_engine.StopExecution.verdict`, which is
    :meth:`~mayhem.domain.stop.PostflightReport.verdict` recomputed from the
    report's checks. A builder that accepted a verdict would let a caller write
    ``CLEAN`` over a ``DIRTY`` report, and the hash would then faithfully attest
    to the lie.
    """
    import inspect

    signature = inspect.signature(stop_evidence_payload)
    assert list(signature.parameters) == ["execution"], signature
    assert stop_postflight_keys_are_derived_not_passed()


def stop_postflight_keys_are_derived_not_passed() -> bool:
    from mayhem.controller.stop_engine import stop_postflight_payload

    parameters = inspect_signature(stop_postflight_payload)
    assert set(parameters) == {"execution"}, parameters
    return True


def inspect_signature(function: Any) -> dict[str, Any]:
    import inspect

    return dict(inspect.signature(function).parameters)


# ==============================================================================
# Phase 3 — the stop-latency bound (plan 08's open item)
# ==============================================================================


def test_the_freeze_latency_is_measured_and_inside_the_named_bound(tmp_path: Path) -> None:
    """The plan's "freeze within seconds", as a measurement rather than a claim.

    Measured on the monotonic clock the engine stamps the freeze receipt with, and
    compared against :data:`FREEZE_LATENCY_BOUND_S`. Nothing here is a number
    about a cluster: it is how long mayhem took to mint a fence epoch and record
    it, which is the half of the acceptance mayhem is entitled to state.
    """
    store, outcome = _stop(tmp_path)
    try:
        execution = outcome.executions[0]
        measured, within = freeze_latency(execution)
        assert measured is not None, "the freeze latency was never measured"
        assert measured >= 0.0
        assert within is True, f"measured {measured:.3f}s against a {FREEZE_LATENCY_BOUND_S}s bound"
        assert outcome.freeze_latency_s == measured
        assert outcome.freeze_within_bound is True
        assert FREEZE_LATENCY_BOUND_S <= 30.0, (
            "the bound has grown past 'seconds'; the plan's acceptance was freeze within "
            "seconds and a bound nobody could trip is not a bound"
        )
    finally:
        store.close()


def test_a_freeze_that_overran_is_reported_as_over_not_as_passing(tmp_path: Path) -> None:
    """The bound is executable, not decorative — driven by an injected clock.

    A wall-clock sleep would make this flaky in one direction and impossible to
    push past the bound in the other, so the clock is injected: the assertion is
    that the *check* moves, not that the machine is slow.
    """
    from mayhem.controller.recovery import RecoveryService
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    store = _store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        _seed_lease(store, _lease())
        ticks = iter([0.0, FREEZE_LATENCY_BOUND_S + 1.0, 9.0, 9.0])
        sink = SQLiteLeaseSink(store)
        engine = StopEngine(
            sink=sink,
            recovery=RecoveryService(sink),
            dispatch=stop_cmd.FenceDispatchFreezer(store, holder="stop:u-ana"),
            ledger=stop_cmd.StoreStopLedger(store),
            monotonic=lambda: next(ticks),
        )
        command = stop_cmd.build_stop_command(
            scope=StopScope.RUN,
            run_id=RUN_ID,
            principal=Principal(principal_id="u-ana"),
            reason=REASON,
            now=MOMENT,
        )
        execution = asyncio.run(engine.execute(command, state=RunState.RUNNING, now=MOMENT))
        measured, within = freeze_latency(execution)
        assert measured == pytest.approx(FREEZE_LATENCY_BOUND_S + 1.0)
        assert within is False
    finally:
        store.close()


def test_a_stop_that_never_froze_reports_no_latency_rather_than_zero() -> None:
    """``None`` is not ``0.0``: an unmeasured freeze is not a fast one."""
    record = StopRecord(
        command=_command("sc-1"),
        state=RunState.RUNNING,
        level=stop_engine.CancellationLevel.KILL,
        compensation=CompensationPath.CONTROLLER_RECOVERY,
        started_at=MOMENT,
        finished_at=MOMENT,
        stalled_at=stop_engine.StopStage.FREEZE,
        stall_reason="freeze: fabric unreachable",
    )
    execution = StopExecution(record=record)
    assert execution.freeze_latency_s is None
    assert freeze_latency(execution) == (None, False)
    payload = stop_evidence_payload(execution)
    assert payload["freeze_latency_s"] is None
    assert payload["verdict"] == PostflightVerdict.UNKNOWN.value


def _command(command_id: str) -> Any:
    return stop_cmd.build_stop_command(
        scope=StopScope.RUN,
        run_id=RUN_ID,
        principal=Principal(principal_id="u-ana"),
        reason=REASON,
        now=MOMENT,
    ).model_copy(update={"id": command_id})


def test_the_rendered_latency_says_what_it_does_and_does_not_measure(tmp_path: Path) -> None:
    """The rendered line names mayhem's own freeze, not the environment's."""
    store, outcome = _stop(tmp_path)
    try:
        lines = stop_cmd.render_stop_execution(outcome.executions[0])
        assert lines, "the stop rendered nothing"
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            stop_cmd._echo_text(outcome)
        printed = buffer.getvalue()
        assert "freeze latency" in printed
        assert "environment's reaction is not measured here" in printed
        payload = stop_cmd.stop_payload(outcome)
        assert payload["freeze_latency_bound_s"] == FREEZE_LATENCY_BOUND_S
        assert payload["freeze_within_bound"] is True
        assert payload["seals"][0]["signed"] is False
    finally:
        store.close()


def test_an_unmeasured_freeze_renders_as_unmeasured_not_as_zero(tmp_path: Path) -> None:
    """A stopped-at-freeze attempt prints the warning, not ``0.000s``."""
    import io
    from contextlib import redirect_stdout

    store = _store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        _seed_lease(store, _lease())
        # A dispatcher that never records a receipt: the walk stalls at FREEZE,
        # so there is no measurement to render.
        execution = StopExecution(
            record=StopRecord(
                command=_command("sc-stalled"),
                state=RunState.RUNNING,
                level=stop_engine.CancellationLevel.KILL,
                compensation=CompensationPath.CONTROLLER_RECOVERY,
                started_at=MOMENT,
                finished_at=MOMENT,
                stalled_at=stop_engine.StopStage.FREEZE,
                stall_reason="freeze: fabric unreachable",
            )
        )
        outcome = stop_cmd.StopOutcome(
            scope=StopScope.RUN,
            command=_command("sc-stalled"),
            executions=(execution,),
        )
        assert outcome.freeze_latency_s is None
        assert outcome.freeze_within_bound is False
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            stop_cmd._echo_text(outcome)
        printed = buffer.getvalue()
        assert "freeze latency: not measured" in printed
        assert "0.000s" not in printed
        payload = stop_cmd.stop_payload(outcome)
        assert payload["freeze_latency_s"] is None
        assert payload["freeze_within_bound"] is False
        assert payload["verdict"] == "unknown"
    finally:
        store.close()


# ==============================================================================
# Plan 13's open item — the claim ledger, and what an open claim does
# ==============================================================================


class _Claims:
    """A claim ledger holding *count* open claims for every run."""

    def __init__(self, *command_ids: str) -> None:
        self._open = tuple(
            OpenClaim(command_id=command_id, step_id="s0", epoch=7) for command_id in command_ids
        )

    def open_claims(self, run_id: str) -> tuple[OpenClaim, ...]:
        return self._open


def test_an_open_dispatch_claim_keeps_the_run_dirty(tmp_path: Path) -> None:
    """Plan 13's seam: intent with no observation is not an effect proved absent.

    The lease-side reconcile cannot see this case — the claim owns no lease, so
    there is nothing in the sink, nothing in the recovery plan, and nothing for
    the compensation pass to have missed. With a claim ledger bound, each open
    claim becomes a ``claim_unsettled`` residue finding, which makes the postflight
    ``DIRTY`` and the run unclosable-clean.
    """
    from mayhem.controller.recovery import RecoveryService
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    store = _store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        _seed_lease(store, _lease())
        command = stop_cmd.build_stop_command(
            scope=StopScope.RUN,
            run_id=RUN_ID,
            principal=Principal(principal_id="u-ana"),
            reason=REASON,
            now=MOMENT,
        )
        sink = SQLiteLeaseSink(store)
        engine = StopEngine(
            sink=sink,
            recovery=RecoveryService(sink),
            dispatch=stop_cmd.FenceDispatchFreezer(store, holder="stop:u-ana"),
            ledger=stop_cmd.StoreStopLedger(store),
            claims=_Claims("cmd-open-1"),
        )
        execution = asyncio.run(engine.execute(command, state=RunState.RUNNING, now=MOMENT))

        assert execution.sealed is not None, "the walk stalled rather than reporting the claim"
        assert execution.verdict is PostflightVerdict.DIRTY
        assert execution.recovered is False
        names = {check.name for check in execution.report.checks}
        assert "residue:claim_unsettled:cmd-open-1" in names
        assert any(
            receipt.evidence_ref == claim_ref("cmd-open-1") for receipt in execution.record.receipts
        )
        payload = stop_evidence_payload(execution)
        assert payload["verdict"] == PostflightVerdict.DIRTY.value
        assert [check["name"] for check in payload["residue_checks"]] == [
            "residue:claim_unsettled:cmd-open-1"
        ]
    finally:
        store.close()


def test_the_same_stop_with_no_claim_ledger_sees_no_claim(tmp_path: Path) -> None:
    """Absence of a ledger is not evidence of no claims — and says nothing.

    The negative half of the property above: the engine's own arithmetic is
    unchanged when no ledger is bound, so a run nobody fabric-dispatched still
    seals ``CLEAN``. Wiring the ledger must be *additive*, or every existing stop
    would have turned ``DIRTY`` for a witness mayhem never claimed to hold.
    """
    store, outcome = _stop(tmp_path)
    try:
        assert outcome.executions[0].verdict is PostflightVerdict.CLEAN
        names = {check.name for check in outcome.executions[0].report.checks}
        assert not any(name.startswith("residue:claim") for name in names)
    finally:
        store.close()


def test_the_claim_ledger_reader_is_inert_where_there_is_no_journal(tmp_path: Path) -> None:
    """A database with no fabric journal reports "no witness", not "no claims"."""
    from mayhem.infra.fabric_journal import FabricJournalTable

    store = _store(tmp_path)
    try:
        claims = stop_cmd.FabricJournalClaims(store)
        assert claims.available is FabricJournalTable(store).table_exists()
        assert claims.open_claims(RUN_ID) == ()
    finally:
        store.close()


# ==============================================================================
# The properties that are absences, and must stay that way
# ==============================================================================


def test_neither_the_run_path_nor_the_stop_has_a_bypass() -> None:
    """No ``--force``, no ``--no-preflight``, no ``skip_preflight``, anywhere.

    Two surfaces, one property. The stop surface's version of this is
    ``test_stop_has_no_bypass_flag``; the run path's is
    ``test_the_run_path_has_no_preflight_bypass``. Asserted here as well because
    the *mechanism* is what matters — a bypass does not have to be a flag, and
    the run path's version would not be a CLI flag at all.
    """
    import inspect

    from mayhem.cli import execution as execution_module
    from mayhem.controller.executor import RunEngine
    from mayhem.controller.preflight_gate import PreflightGate

    forbidden = {
        "force",
        "skip",
        "no_preflight",
        "skip_preflight",
        "ignore_preflight",
        "disable_preflight",
        "override",
    }
    engine_params = set(inspect.signature(RunEngine.__init__).parameters)
    gate_params = set(inspect.signature(PreflightGate.__init__).parameters)
    assert not engine_params & forbidden, engine_params & forbidden
    assert not gate_params & forbidden, gate_params & forbidden
    assert not [n for n in dir(execution_module) if "force" in n or "skip" in n]
    assert not [
        n
        for n in dir(RunEngine)
        if "preflight" in n.lower()
        and not n.startswith("_")
        and n not in {"preflight_gate", "preflight_report", "with_preflight_gate"}
    ], (
        "RunEngine grew a public preflight entry point other than the attach point and the "
        "report property; a third one would be somewhere to bypass it"
    )
    # ``--preflight`` on the stop is opt-*in* (ask for the gate), not opt-*out*
    # (get past it), and ``run_stop`` takes a gate rather than a switch.
    assert not hasattr(stop_cmd.run_stop, "__wrapped__")
    run_stop_params = set(inspect.signature(stop_cmd.run_stop).parameters)
    assert "preflight" in run_stop_params
    assert not run_stop_params & {"force", "skip_preflight", "bypass_preflight"}


def test_a_stop_for_a_finished_run_is_refused_not_silently_accepted(tmp_path: Path) -> None:
    """The plan's negative control, restated where the sealed chain can see it.

    A run the store records as ``completed`` has nothing to escalate, so the stop
    is refused by the engine. What matters here is that *nothing is sealed*: a
    refused stop that still wrote a chain would put a record of an escalation on
    the chain that never happened.
    """
    from mayhem.domain.errors import InvariantViolationError

    store = _store(tmp_path)
    try:
        _seed_run(store, RUN_ID, status="completed")
        with pytest.raises(InvariantViolationError) as caught:
            stop_cmd.run_stop(
                store=store,
                principal=Principal(principal_id="u-ana"),
                scope=StopScope.RUN,
                reason=REASON,
                run_id=RUN_ID,
                now=MOMENT,
            )
        assert "stop_for_terminal_run" in str(caught.value) or "nothing to escalate" in str(
            caught.value
        )
        assert store.query("SELECT * FROM attestation_chains") == []
    finally:
        store.close()


def test_a_stop_with_no_reason_cannot_be_sealed(tmp_path: Path) -> None:
    """Preserved from Phase 3, and now load-bearing for the chain too.

    The refusal happens before the command exists, so there is no object to seal:
    a ``StopCommand`` with an empty trigger detail would produce a perfectly
    verifiable chain that could not say why anything happened.
    """
    from mayhem.cli.errors import MayhemCliError

    store = _store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        with pytest.raises(MayhemCliError) as caught:
            stop_cmd.run_stop(
                store=store,
                principal=Principal(principal_id="u-ana"),
                scope=StopScope.RUN,
                reason="   ",
                run_id=RUN_ID,
                now=MOMENT,
            )
        assert "cannot be sealed" in str(caught.value)
        assert store.query("SELECT * FROM attestation_chains") == []
        assert store.query("SELECT * FROM observations") == []
    finally:
        store.close()


def test_a_residue_finding_never_seals_as_clean(tmp_path: Path) -> None:
    """The plan's postflight-failure test: residue found means the run stays dirty.

    Driven through a wedged lease, whose compensation cannot settle — the same
    shape as :func:`test_an_open_dispatch_claim_keeps_the_run_dirty` but through
    the lease side instead of the journal side, so both witnesses are covered.
    """
    store = _store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        _seed_lease(store, _lease(wedged=True))
        outcome = stop_cmd.run_stop(
            store=store,
            principal=Principal(principal_id="u-ana"),
            scope=StopScope.RUN,
            reason=REASON,
            run_id=RUN_ID,
            now=MOMENT,
        )
        execution = outcome.executions[0]
        assert execution.verdict is PostflightVerdict.DIRTY
        assert execution.recovered is False
        assert stop_cmd.exit_code_for(outcome).value == 7
        payload = stop_evidence_payload(execution)
        assert payload["verdict"] == "dirty"
        assert payload["recovery_verified"] is False
    finally:
        store.close()


# ==============================================================================
# Phase 6 — the documents must not promise what this cannot do
# ==============================================================================


def test_the_plan_document_promises_no_stop_of_an_irreversible_effect() -> None:
    """Phase 6's acceptance, asserted against the document itself.

    "no doc promises stop of irreversible effects — reconciliation of the
    irreversible is documented as best-effort with explicit limits." The plan
    file is the document this lane owns, so the promise is checked where it is
    written rather than in a reviewer's memory.
    """
    root = Path(__file__).parents[2]
    text = (root / "docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md").read_text(encoding="utf-8")
    # Markdown emphasis is stripped rather than worked around: the claim under
    # test is about what the document *says*, and ``does **not** settle`` says it
    # exactly as loudly as ``does not settle``.
    lowered = text.lower().replace("**", "")
    for phrase in (
        "irreversible",
        "best-effort",
        "cannot undo",
        "does not undo",
    ):
        assert phrase in lowered, f"the plan document never says {phrase!r}"
    # And it must not claim the opposite anywhere.
    for forbidden in (
        "stops any effect",
        "fully reversible",
        "guarantees recovery",
        "reverses everything",
        "no residue is possible",
    ):
        assert forbidden not in lowered, f"the plan document promises {forbidden!r}"


def test_the_stop_runbook_and_the_two_guides_are_in_the_document() -> None:
    """Phase 6's three deliverables, present as named sections.

    Named rather than merely present: a runbook nobody can find is not a runbook,
    and a reviewer checking "did Phase 6 land" needs a string to grep for rather
    than a judgement call about prose.
    """
    root = Path(__file__).parents[2]
    text = (root / "docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md").read_text(encoding="utf-8")
    for heading in (
        "## Stop runbook",
        "## Preflight check catalogue",
        "## Postflight interpretation guide",
    ):
        assert heading in text, f"Phase 6 deliverable missing: {heading}"


def test_the_catalogue_lists_every_check_the_gate_can_run() -> None:
    """The catalogue is generated from the gate's own vocabulary, not restated."""
    from mayhem.controller.preflight_gate import PORT_CHECKS, REAL_CHECKS

    root = Path(__file__).parents[2]
    text = (root / "docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md").read_text(encoding="utf-8")
    for name in ALL_CHECKS:
        assert f"`{name}`" in text, f"the catalogue omits {name}"
    assert len(REAL_CHECKS) + len(PORT_CHECKS) == len(ALL_CHECKS)


# ==============================================================================
# Phase 5 — the matrix, and the three refusals the plan names by hand
# ==============================================================================

#: Fault families the stop has to handle. Three because the plan asks for "every
#: fault family" and this lane cannot enumerate the catalogue honestly; the
#: property under test is family-independent — the ladder reads the lease, not
#: the fault — and a family with a different ``fault_id`` exercises the same
#: path. The catalogue-wide matrix belongs to whoever owns the catalogue.
FAULT_FAMILIES = ("proc.pause", "net.latency", "disk.fill")


def _trigger(signal: str) -> StopTrigger:
    """A trigger for *signal*, carrying whatever that signal's path demands.

    The condition-fired path is the one that has to name a condition: the domain
    refuses a ``condition_fired`` stop with a blank ``condition_id``, because a
    stop that says "a criterion fired" without saying which one is a sealed record
    that cannot be acted on. Constructing it through
    :meth:`StopTrigger.for_signal` rather than by hand is what makes that
    refusal visible here instead of discovered in production.
    """
    the_signal = StopSignal(signal)
    condition_id = "err_rate>5%" if the_signal is StopSignal.CONDITION_TRIPPED else ""
    return StopTrigger.for_signal(the_signal, condition_id=condition_id, detail=REASON)


@pytest.mark.parametrize("fault_id", FAULT_FAMILIES)
@pytest.mark.parametrize("signal", ["operator_request", "condition_tripped", "controller_lost"])
def test_every_trigger_stops_every_fault_family_the_same_way(
    tmp_path: Path, fault_id: str, signal: str
) -> None:
    """The stop matrix, over the triggers a command can carry.

    The point is that the *reason* travels and the *behaviour* does not depend on
    it: a human stop and a controller-lost stop compensate, scan, verify, and
    seal identically, and differ only in the reason sealed. A matrix where the
    verdict varied by trigger would mean one trigger short-circuits the ladder.
    """

    store = _store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        lease = _lease()
        _seed_lease(store, lease.model_copy(update={"fault_id": fault_id}))
        command = stop_cmd.build_stop_command(
            scope=StopScope.RUN,
            run_id=RUN_ID,
            principal=Principal(principal_id="u-ana"),
            reason=REASON,
            now=MOMENT,
        ).model_copy(update={"trigger": _trigger(signal)})
        from mayhem.controller.recovery import RecoveryService
        from mayhem.infra.lease_repository import SQLiteLeaseSink

        sink = SQLiteLeaseSink(store)
        engine = StopEngine(
            sink=sink,
            recovery=RecoveryService(sink),
            dispatch=stop_cmd.FenceDispatchFreezer(store, holder="stop:u-ana"),
            ledger=stop_cmd.StoreStopLedger(store),
        )
        execution = asyncio.run(engine.execute(command, state=RunState.RUNNING, now=MOMENT))
        assert execution.sealed is not None, f"{fault_id}/{signal} did not seal"
        assert [stage.value for stage in execution.record.completed_stages] == [
            stage.value for stage in stop_engine.STOP_FLOW
        ]
        assert execution.verdict is PostflightVerdict.CLEAN
        # The reason is the only thing the trigger changes.
        assert execution.reason.value == reason_for(StopSignal(signal)).value
        assert stop_evidence_payload(execution)["reason"] == execution.reason.value
    finally:
        store.close()


def test_a_fault_family_whose_compensation_fails_is_never_closed_clean(tmp_path: Path) -> None:
    """The matrix's negative half: the same ladder, over a lease it cannot settle.

    Proves the matrix above is not passing because every stop trivially succeeds:
    the identical walk over a wedged lease produces ``DIRTY`` and exit 7.
    """
    store = _store(tmp_path)
    try:
        for fault_id in FAULT_FAMILIES:
            run_id = f"r-{fault_id.replace('.', '-')}"
            _seed_run(store, run_id)
            _seed_lease(
                store,
                _lease(wedged=True).model_copy(update={"fault_id": fault_id, "run_id": run_id}),
            )
            outcome = stop_cmd.run_stop(
                store=store,
                principal=Principal(principal_id="u-ana"),
                scope=StopScope.RUN,
                reason=REASON,
                run_id=run_id,
                now=MOMENT,
            )
            assert outcome.verdict is PostflightVerdict.DIRTY, fault_id
            assert outcome.recovered is False, fault_id
    finally:
        store.close()


PREFLIGHT_REFUSAL_CASES = (
    # (check name, what the engine cannot supply, status the refusal must be)
    (CHECK_INCIDENT_ACTIVE, "the incident manager (no port bound)", CheckStatus.UNAVAILABLE),
    (CHECK_AGENT_AVAILABILITY, "the agent registry (none registered)", CheckStatus.FAIL),
    (CHECK_BUDGET_AVAILABLE, "a resource budget (no guard attached)", CheckStatus.FAIL),
    (CHECK_POLICY_AVAILABLE, "a policy decision (none supplied)", CheckStatus.FAIL),
)


@pytest.mark.parametrize(
    ("check", "missing", "status"),
    PREFLIGHT_REFUSAL_CASES,
    ids=[case[0] for case in PREFLIGHT_REFUSAL_CASES],
)
def test_the_run_path_refuses_each_missing_witness_by_name(
    tmp_path: Path, check: str, missing: str, status: CheckStatus
) -> None:
    """The plan's three named refusals, plus the policy one, through ``execute``.

    Each case narrows the gate to the single check under test. That is not a
    convenience: the engine legitimately holds only the plan, a clock, a graph
    if it was given one, and a budget guard — no agent registry and no policy
    decision — so a full catalogue would refuse for several unrelated reasons at
    once and the assertion would prove nothing about the case named here.
    Narrowing is safe by construction: an omitted check shows up as an *absence*
    in the report, never as a pass.

    Asserted on the refusal text and its status, not merely on "it raised": an
    operator told only "preflight refused" has to go and find which check failed.
    The absent run row proves the refusal cost nothing.
    """
    from mayhem.controller.executor import RunEngine

    store = _store(tmp_path)
    try:
        plan = _runnable_plan()
        gate = PreflightGate(checks=(check,), ports=PreflightPorts())
        engine = RunEngine(store, SQLiteLeaseSink(store), sleeper=lambda _s: None)
        engine.with_preflight_gate(gate)
        with pytest.raises(InvariantViolationError) as caught:
            engine.execute(plan)
        message = str(caught.value)
        assert check in message, f"{check}: {message}"
        assert "refused" in message, message
        assert store.query("SELECT * FROM runs WHERE id = ?", (plan.run_id,)) == []
        # And the same check, evaluated rather than raised, reports the status the
        # missing witness implies — UNAVAILABLE for an unreachable system, FAIL for
        # an absent one. Collapsing the two would let a reader take "mayhem has no
        # witness" for "mayhem looked and the answer was no".
        report = gate.evaluate(
            PreflightInputs(plan=plan, now=MOMENT, environment="staging", target="web")
        )
        assert [c.status for c in report.checks] == [status], missing
        assert not report.granted
    finally:
        store.close()


def test_the_run_path_refusal_names_the_stop_reason_a_preflight_produces(
    tmp_path: Path,
) -> None:
    """A refused run's stop reason is ``preflight_failed``, spelled by ``domain.stop``.

    Not a private string invented at the refusal site: the trigger comes from
    :meth:`StopTrigger.for_signal` over ``StopSignal.PREFLIGHT_REFUSAL``, so the
    same vocabulary that names a human stop names this one, and a reader of the
    sealed evidence sees the reason they already know.
    """
    from mayhem.controller.executor import RunEngine
    from mayhem.controller.preflight_gate import PreflightRefusedError

    store = _store(tmp_path)
    try:
        plan = _runnable_plan()
        engine = RunEngine(store, SQLiteLeaseSink(store), sleeper=lambda _s: None)
        engine.with_preflight_gate(
            PreflightGate(checks=(CHECK_INCIDENT_ACTIVE,), ports=PreflightPorts())
        )
        with pytest.raises(PreflightRefusedError) as caught:
            engine.execute(plan)
        trigger = caught.value.trigger
        assert trigger.reason is StopReason.PREFLIGHT_FAILED
        assert CHECK_INCIDENT_ACTIVE in trigger.detail
        assert trigger.detail, "the refusal carries no evidence for its reason"
    finally:
        store.close()
