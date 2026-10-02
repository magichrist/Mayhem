"""``mayhem stop`` — one command stops a run, and says what it did
(docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md, Phase 3, surface half).

Phase 1 (:mod:`mayhem.domain.stop`) named the words, Phase 2
(:mod:`mayhem.controller.stop_engine`) walked the ladder, and Phase 3's engine
half (:mod:`mayhem.controller.preflight_gate`) made preflight refuse. None of
those is reachable by a person. This module is the button, and it is the whole
of what Phase 3's surface half consists of: one Click command with two scopes,
one checklist renderer for preflight, one for postflight, and the two seams the
engine insists on — a :class:`~mayhem.controller.stop_engine.StopLedger` and a
:class:`~mayhem.controller.stop_engine.DispatchFreezer` — bound to the store.

Six commitments shape the code.

**One command, two scopes, no third spelling.** ``mayhem stop RUN_ID`` stops one
run; ``mayhem stop --environment ENV`` stops every run that can still be
injecting in that environment and *requires* plan 09's
``Role.EMERGENCY_STOP``. Naming the command is the approval, exactly as
``mayhem recover execute`` treats naming its sub-command — a second flag on an
emergency stop is keystrokes standing between an operator and a stopped run, and
it is not a control: the real control is the emergency role, which is checked
before anything is written. There is deliberately **no** ``--force``,
``--no-preflight``, or ``--skip-role``: each would be a bypass of a gate that
exists to refuse, and the plan names "a preflight bypass flag does not exist" as
a property to assert rather than a feature to add.

**A refusal mutates nothing, and the refusal is the interesting output.** The
authorization check, the ``--preflight`` admission, and the terminal-run check
all run *before* the engine is asked for a single stage, so a refused stop has
performed no mutation at all. ``--preflight`` is opt-in and its absence is
byte-identical to :func:`mayhem.controller.preflight_gate.admit`'s ``gate=None``
branch: no check runs, no port is called, nothing is read that the caller did not
name.

**The environment-wide scope is expanded here, not guessed by the engine.**
:meth:`mayhem.controller.stop_engine.StopEngine.execute` refuses an
environment-wide command outright — "expand the scope upstream" — because
fanning one command out over a set of runs is a decision, not a detail. This
module makes that decision explicitly and names the set it chose: the runs the
lease sink still holds unsettled work for. A run holding nothing has nothing to
escalate, so that set is exactly what an emergency stop means. The
environment-wide command itself is still recorded, so who asked is on the record
even when the fan-out finds nothing to stop.

**A residue finding must never read as clean.** The verdict rendered here is
:attr:`~mayhem.controller.stop_engine.StopExecution.verdict`, which is
:attr:`~mayhem.domain.stop.PostflightReport.verdict` recomputed on every read
and ``UNKNOWN`` for a stop that never sealed. The renderer has no "assume clean"
branch and no way to be handed a verdict: it reads the execution, and a
``DIRTY`` verdict prints its failing checks by name.

**An unreachable witness renders as unavailable, never as pass.** The preflight
checklist prints
:attr:`~mayhem.controller.preflight_gate.PreflightCheck.status` verbatim, and the
word ``PASS`` is emitted for :attr:`~mayhem.controller.preflight_gate.CheckStatus.PASS`
and for nothing else. A check whose source is an unbound, raising,
``None``-answering or wrong-shaped port is ``UNAVAILABLE`` — mayhem could not
ask, which is not an answer — and it is rendered as such with the port named.
``--preflight`` with no port witnesses bound therefore *refuses* by
construction, which is the honest reading of "a preflight that warns-and-
continues is a bug": the seven real checks answer from the run's stored plan and
topology, the five port checks cannot answer from a CLI, and a gate that cannot
see an incident manager cannot certify that no incident is open.

**The ledger is not optional here, and it is not the sealed chain.**
:class:`StoreStopLedger` writes attempts and seals to the ``observations``
table — the durable, already-migrated surface — because an emergency stop whose
record went nowhere is the failure this command exists to prevent. It also writes
the two things the engine never sees: the environment-wide ask (which the engine
refuses to execute) and the *granting* preflight checklist. A *refusing*
checklist is deliberately recorded nowhere, because that path mutates nothing.
Phase 4 binds the same records into the sealed chain; this is the operator
surface's own record, and it says so.

.. warning::

   **The preflight gate is not wired into the run path.**
   :meth:`mayhem.controller.executor.RunEngine.execute` has no ``preflight_gate``
   field and no ``with_preflight_gate`` attach point — the budget guard's
   :meth:`~mayhem.controller.executor.RunEngine.with_budget_guard` is the shape
   such a seam would take, and no equivalent exists for this gate yet. Adding it
   means editing ``controller/executor.py`` and ``cli/execution.py``, neither of
   which this work item owns, so this module does not pretend to have done it.
   What *is* true here: ``--preflight`` makes ``mayhem stop`` itself refuse
   before it mutates, naming every refusing check with its evidence reference.

Invocations that resolve against this command::

    mayhem stop --help
    mayhem stop r-drill-a1b2c3d4 --reason "operator pressed the button"
    mayhem stop --environment staging --reason "incident INC-42 open" --principal u-ana
    mayhem stop r-drill-a1b2c3d4 --reason "fault is not reversing" --preflight
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import click

from mayhem.cli import style
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.domain.stop import PostflightVerdict

if TYPE_CHECKING:
    from datetime import datetime
    from typing import Protocol

    from mayhem.controller.preflight_gate import (
        PreflightCheck,
        PreflightGate,
        PreflightInputs,
        PreflightReport,
    )
    from mayhem.controller.stop_engine import (
        SealedStop,
        StopExecution,
        StopLedger,
        StopRecord,
    )
    from mayhem.domain.cancellation import CancellationLevel
    from mayhem.domain.identity import Principal
    from mayhem.domain.stop import (
        PostflightReport,
        RunState,
        StopCommand,
        StopScope,
    )
    from mayhem.infra.store import Store

    class StopRecorder(StopLedger, Protocol):
        """A :class:`StopLedger` that can also record an unexpanded ask.

        :class:`~mayhem.controller.stop_engine.StopLedger` covers what the
        *engine* writes — attempts and seals, both for one run. This surface also
        records two things the engine never sees: the environment-wide command,
        which is never executed (the engine refuses that scope), and the
        *granting* preflight checklist, which is what an operator's ``--preflight``
        produced. Without both the fan-out and the gate would leave no trace.
        Narrowing :func:`run_stop`'s ledger parameter to this narrower protocol
        means a caller cannot pass a ledger that would drop either.
        """

        def record_command(self, command: StopCommand) -> None: ...

        def record_checklist(self, run_id: str, report: PreflightReport) -> None: ...

__all__ = [
    "DEFAULT_PRINCIPAL",
    "EMERGENCY_STOP_CHECKLIST_KIND",
    "PRINCIPAL_ENV",
    "STOP_ATTEMPT_KIND",
    "STOP_COMMAND_KIND",
    "STOP_SEAL_KIND",
    "FenceDispatchFreezer",
    "StopOutcome",
    "StopRecorder",
    "StoreStopLedger",
    "authorization_refusal",
    "build_stop_command",
    "command_id",
    "exit_code_for",
    "preflight_inputs_for",
    "render_preflight_checklist",
    "render_stop_execution",
    "require_emergency_role",
    "run_state_for",
    "run_stop",
    "stop",
    "stop_payload",
]


# =============================================================================
# Vocabulary this module owns
# =============================================================================

#: ``observations.kind`` values. Attempts and seals are what
#: :class:`~mayhem.controller.stop_engine.StopEngine` writes through its ledger
#: seam; ``stop_command`` is written by *this* module for the environment-wide
#: ask, so "who asked" survives even when the fan-out finds nothing.
STOP_ATTEMPT_KIND = "stop_attempt"
STOP_SEAL_KIND = "stop_seal"
STOP_COMMAND_KIND = "stop_command"
EMERGENCY_STOP_CHECKLIST_KIND = "stop_preflight"

#: ``runs.status`` values that mean the run reached a terminal state of its own
#: accord. A stop against one of these is refused: there is nothing to escalate,
#: and pretending otherwise would write a stop record for a run that ended
#: without one.
_TERMINAL_RUN_STATUSES: frozenset[str] = frozenset({"completed", "failed", "aborted"})

#: Column width of the rendered status word, so the checklist's evidence column
#: lines up whatever mix of statuses a gate produced.
_STATUS_WORD_WIDTH = len("UNAVAILABLE")


def command_id() -> str:
    """A fresh ``sc-<hex>`` stop-command id.

    Prefixed ``sc-`` because :class:`~mayhem.domain.stop.StopCommand` documents
    that shape and the sealed evidence cites the command by it; a reader — and a
    grep — should be able to tell a stop command from a run id at a glance.
    """
    return f"sc-{uuid.uuid4().hex[:12]}"


# =============================================================================
# The two collaborator seams the engine requires
# =============================================================================


class StoreStopLedger:
    """Where stop attempts and seals are recorded: the ``observations`` table.

    A :class:`~mayhem.controller.stop_engine.StopLedger` because the engine's
    constructor takes one as a *required* collaborator — an emergency stop whose
    record went nowhere is precisely the failure the ladder exists to prevent —
    and because :meth:`attempts` / :meth:`seal` have to be readable back for a
    second stop to recognise the first.

    ``observations`` is the durable surface already in the migration set, so this
    adds no schema and no migration. It is explicitly *not* the sealed chain:
    Phase 4 binds the stop reason, the per-action compensation outcomes, and the
    postflight verdict into the evidence envelope, and until that lands this is
    the operator surface's own record of what happened and when.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    # -- writes ---------------------------------------------------------------

    def record_attempt(self, record: StopRecord) -> None:
        self._store.save_observation(
            STOP_ATTEMPT_KIND,
            run_id=record.command.run_id,
            source=record.command.id,
            data=record.model_dump(mode="json"),
        )

    def record_seal(self, sealed: SealedStop) -> None:
        self._store.save_observation(
            STOP_SEAL_KIND,
            run_id=sealed.record.command.run_id,
            source=sealed.record.command.id,
            data=sealed.model_dump(mode="json"),
        )

    def record_command(self, command: StopCommand) -> None:
        """Record an ask that has not been expanded into runs yet.

        The environment-wide command is never executed — the engine refuses it —
        so nothing else would put it on the record, and a sealed evidence chain
        that cannot name the environment-wide command behind a fan-out cannot
        reproduce what was asked for.
        """
        self._store.save_observation(
            STOP_COMMAND_KIND,
            run_id=command.run_id,
            source=command.id,
            data=command.model_dump(mode="json"),
        )

    def record_checklist(self, run_id: str, report: PreflightReport) -> None:
        """Record the checklist that *granted* a stop, with every check's evidence.

        Only a granting checklist is written, and that is deliberate: the refusal
        path must perform zero mutations, so a refused gate leaves nothing behind
        here — its rendered checklist is in the operator's error output instead.
        A granted one is the opposite case and worth keeping, because "which
        checks cleared this stop, and what did they look at" is the question a
        week-later reader of the sealed evidence will ask.
        """
        self._store.save_observation(
            EMERGENCY_STOP_CHECKLIST_KIND,
            run_id=run_id,
            source="",
            data=report.inputs(),
        )

    # -- reads ----------------------------------------------------------------

    def attempts(self, run_id: str) -> tuple[StopRecord, ...]:
        """Every recorded attempt for *run_id*, oldest first."""
        from mayhem.controller.stop_engine import StopRecord as _Record

        return tuple(
            _Record.model_validate(json.loads(str(row["data_json"])))
            for row in self._store.query(
                "SELECT data_json FROM observations WHERE kind = ? AND run_id = ? ORDER BY id",
                (STOP_ATTEMPT_KIND, run_id),
            )
        )

    def seal(self, run_id: str) -> SealedStop | None:
        """The most recent seal for *run_id*, or ``None`` when it never sealed."""
        from mayhem.controller.stop_engine import SealedStop as _Sealed

        rows = self._store.query(
            "SELECT data_json FROM observations WHERE kind = ? AND run_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (STOP_SEAL_KIND, run_id),
        )
        return _Sealed.model_validate(json.loads(str(rows[0]["data_json"]))) if rows else None


class FenceDispatchFreezer:
    """The ``FREEZE`` stage: stop new actions being dispatched for a run.

    Minting a strictly newer fence epoch is the primitive mayhem already has
    (:class:`mayhem.infra.replication.FenceLedger`; ``repl_fences`` is
    append-only by epoch and refuses a regression). A writer that presents the
    superseded epoch afterwards fails
    :meth:`mayhem.infra.replication.FenceLedger.assert_current`, which is the
    replication writer's own check, so the freeze is a real fence rather than a
    flag somebody set.

    Stated honestly, because a freeze is only as good as its enforcement: this
    fences every consumer that *asks the ledger* whether its epoch is current. A
    controller that never consults ``repl_fences`` is not fenced by this, and no
    amount of rendering would make it so. The evidence reference is
    ``fence/<run_id>/<epoch>`` so a reader can look the epoch up rather than take
    the word "frozen" for it.

    The holder is fixed at construction because the engine's
    :class:`~mayhem.controller.stop_engine.DispatchFreezer` protocol takes only
    a ``run_id``: the freeze is attributed to the command that caused it.
    """

    def __init__(self, store: Store, *, holder: str) -> None:
        from mayhem.infra.replication import FenceLedger

        self._fences = FenceLedger(store)
        self._holder = holder

    def freeze(self, run_id: str) -> str:
        token = self._fences.mint(run_id, self._holder)
        return f"fence/{run_id}/{token.epoch}"


# =============================================================================
# Authorization: plan 09's emergency role, for the environment-wide scope only
# =============================================================================


def authorization_refusal(
    *, principal_id: str, environment: str, held: tuple[str, ...], required: str
) -> MayhemCliError:
    """The refusal an environment-wide stop without authority produces.

    A function rather than an inline construction because the refusal has to say
    the same three things everywhere it is raised — who was refused, which role
    was required, and which roles they actually hold — and an operator decides
    whether to fix a grant or to go away based on exactly those three.
    """
    roles = ", ".join(held) if held else "no roles"
    return MayhemCliError(
        code="safety_refusal",
        message=(
            f"{principal_id} may not issue an environment-wide stop in {environment!r}: "
            f"this needs the {required!r} role and the principal holds {roles}"
        ),
        details={
            "principal": principal_id,
            "environment": environment,
            "required_role": required,
            "held_roles": ",".join(held),
        },
        remediation=(
            f"grant {required} to {principal_id} in {environment!r} (mayhem's identity "
            "store), or stop the individual runs instead"
        ),
    )


def require_emergency_role(
    store: Store,
    *,
    principal: Principal,
    environment: str,
    now: datetime,
) -> tuple[str, ...]:
    """Resolve *principal*'s roles in *environment*; raise unless they may stop it.

    The one authorization decision this module makes, and it is plan 09's rather
    than this module's: the answer is
    :func:`mayhem.domain.identity.effective_roles` over
    :class:`~mayhem.domain.identity.RoleGrant` records read from the identity
    store, and the role required is ``Role.EMERGENCY_STOP`` — the same mapping
    ``mayhem.controller.check_gate.CHATOPS_REQUIRED_ROLE`` already states for a
    ChatOps ``stop``, read from there rather than restated so the two surfaces
    cannot disagree about who may stop something. Default-deny: no grants means
    no roles, so a principal nobody granted anything is refused rather than
    defaulted in.

    Returns the held roles, sorted, so a caller can render what was seen.
    """
    from mayhem.controller.check_gate import CHATOPS_REQUIRED_ROLE, ChatOpsCommand
    from mayhem.domain.identity import EnvironmentScope, Role, effective_roles
    from mayhem.infra.identity_store import IdentityStore

    required = Role(CHATOPS_REQUIRED_ROLE[ChatOpsCommand.STOP])
    identities = IdentityStore(store)
    roles = effective_roles(
        identities.all_grants(),
        principal=principal,
        scope=EnvironmentScope(environment=environment),
        memberships=identities.all_memberships(),
        now=now,
    )
    if required not in roles:
        raise authorization_refusal(
            principal_id=principal.principal_id,
            environment=environment,
            held=tuple(sorted(role.value for role in roles)),
            required=required.value,
        )
    return tuple(sorted(role.value for role in roles))


# =============================================================================
# Preflight: the checklist, and the inputs the store can honestly supply
# =============================================================================


def preflight_inputs_for(
    store: Store,
    run_id: str,
    *,
    environment: str = "",
    target: str = "",
    now: datetime,
) -> PreflightInputs | None:
    """The gate inputs the store can honestly supply for *run_id*, or ``None``.

    Two inputs are genuinely recoverable — the run's frozen
    :class:`~mayhem.domain.experiments.ExecutionPlan` from ``runs.plan_json`` and
    the topology snapshot it was compiled against from
    ``topology_snapshots.graph_json`` — and the rest are deliberately left at
    their ``None``/empty defaults. That is not an oversight to be tidied away:
    each missing input is a check that reports ``FAIL`` naming what it lacked,
    and "mayhem did not check" must not render as "mayhem checked and it was
    fine". In particular there is no preflight *preview* here, because
    :mod:`mayhem.controller.preflight` computes one and mayhem does not persist
    it — re-deriving it from a topology that may have changed since would be a
    second opinion pretending to be the first.

    ``None`` means the store holds no such run, which is a different finding from
    a run whose checks all fail, and the caller must not conflate them.
    """
    from mayhem.controller.preflight_gate import PreflightInputs
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.topology import TopologyGraph

    rows = store.query("SELECT plan_json, topology_snapshot_id FROM runs WHERE id = ?", (run_id,))
    if not rows:
        return None
    plan = ExecutionPlan.model_validate_json(str(rows[0]["plan_json"]))
    graph = None
    snapshot_id = rows[0]["topology_snapshot_id"]
    if snapshot_id:
        snapshot = store.query(
            "SELECT graph_json FROM topology_snapshots WHERE id = ?", (str(snapshot_id),)
        )
        if snapshot:
            graph = TopologyGraph.model_validate_json(str(snapshot[0]["graph_json"]))
    return PreflightInputs(
        plan=plan,
        now=now,
        graph=graph,
        environment=environment,
        target=target,
    )


def render_preflight_checklist(report: PreflightReport) -> list[str]:
    """Render every check with its own status and its own evidence reference.

    **The word ``PASS`` is emitted for :attr:`CheckStatus.PASS` and for nothing
    else.** A status is upper-cased from the enum's own value rather than chosen
    from a mapping keyed by the *expected* statuses, so a check that is not a
    pass renders as something that is not a pass. A check answered through a port
    that was unbound, raised, answered ``None``, or answered in the wrong shape
    is ``UNAVAILABLE`` and says so here with the port named — "mayhem has no
    witness" and "mayhem looked and the answer was no" are different findings,
    and an operator triaging a refused stop needs to know which one they are
    looking at.
    """
    if report.vacuous:
        headline = (
            f"preflight for run {report.run_id}: REFUSED — no check was evaluated; "
            "a gate that checked nothing cannot certify a run"
        )
    elif report.granted:
        headline = (
            f"preflight for run {report.run_id}: granted ({len(report.checks)} checks passed)"
        )
    else:
        headline = (
            f"preflight for run {report.run_id}: REFUSED "
            f"({len(report.refusing_checks)} of {len(report.checks)} checks refused)"
        )
    lines = [headline]
    for check in report.checks:
        lines.append(f"  {_check_line(check)}")
    return lines


def _check_line(check: PreflightCheck) -> str:
    word = check.status.value.upper().ljust(_STATUS_WORD_WIDTH)
    subject = f" via {check.port}" if check.port else ""
    return f"{word}  {check.name}{subject} — {check.detail} [{check.evidence_ref}]"


# =============================================================================
# Postflight: the verdict, the stages, and the residue
# =============================================================================


def _verdict_word(verdict: PostflightVerdict) -> str:
    if verdict.value == "clean":
        return style.ok("CLEAN", err=False)
    if verdict.value == "dirty":
        return style.orange("DIRTY", err=False)
    return style.warn("UNKNOWN", err=False)


def _open_residue_obligations(report: PostflightReport) -> tuple[str, ...]:
    from mayhem.controller.preflight_gate import RESIDUE_CHECK_PREFIX

    return tuple(
        c.name for c in report.checks if c.name.startswith(RESIDUE_CHECK_PREFIX) and not c.is_pass
    )


def render_stop_execution(execution: StopExecution) -> list[str]:
    """Render one stop: its reason, its stages, and its postflight verdict.

    A residue finding cannot read as clean, and it does not because of a branch
    here: the verdict printed is
    :attr:`~mayhem.controller.stop_engine.StopExecution.verdict`, which is
    :attr:`~mayhem.domain.stop.PostflightReport.verdict` recomputed from the
    report's own checks, and a residue finding is a ``FAIL`` check, so the
    verdict is ``DIRTY`` before this function sees it. The failing checks are
    then printed by name with their evidence references, so the reason for
    ``DIRTY`` is on the screen rather than implied by a word.

    A stop that never sealed prints no report at all and ``UNKNOWN``, and says
    which stage the walk could not finish: "probably recovered" is not a state,
    and a stalled walk has established nothing.
    """
    record = execution.record
    command = record.command
    lines = [
        f"stop {command.id} for run {execution.run_id} (scope {command.scope})",
        f"  principal: {command.principal}",
        f"  reason: {execution.reason.value}"
        + (f" — {command.trigger.detail}" if command.trigger.detail else ""),
        "  stages completed: "
        + (", ".join(stage.value for stage in record.completed_stages) or "none"),
        "  stages outstanding: "
        + (", ".join(stage.value for stage in record.outstanding) or "none"),
    ]
    if record.stalled_at is not None:
        lines.append(style.warn(f"  stalled at {record.stalled_at.value}: {record.stall_reason}"))
    report: PostflightReport | None = execution.report
    if report is None:
        lines.append("  postflight: none — this stop did not seal, so nothing was verified")
        lines.append(f"  postflight verdict: {_verdict_word(execution.verdict)}")
        return lines
    lines.append(f"  postflight verdict: {_verdict_word(execution.verdict)}")
    lines.append(
        "  recovery verified: "
        + (style.ok("yes", err=False) if execution.recovered else style.orange("no", err=False))
    )
    for check in report.failed_checks:
        refs = ", ".join(check.evidence_refs) or "no evidence"
        lines.append(style.orange(f"    FAIL {check.name}: {check.detail} [{refs}]", err=False))
    obligations = _open_residue_obligations(report)
    if obligations:
        lines.append(
            style.orange(
                f"    OPEN RESIDUE OBLIGATIONS ({len(obligations)}): "
                f"{', '.join(obligations)} — this run did not recover and must not be "
                "read as clean",
                err=False,
            )
        )
    return lines


# =============================================================================
# What a stop did: the value the command renders and the JSON emits
# =============================================================================


@dataclass(frozen=True, slots=True)
class StopOutcome:
    """One ``mayhem stop`` invocation, resolved.

    ``dry_run`` is carried rather than inferred from the absence of executions,
    because a preview that renders like a completed stop is the failure this
    whole command family exists to prevent, and the renderer is told.
    """

    scope: StopScope
    command: StopCommand
    target_run_ids: tuple[str, ...] = ()
    executions: tuple[StopExecution, ...] = ()
    preflight: PreflightReport | None = None
    held_roles: tuple[str, ...] = ()
    dry_run: bool = False

    @property
    def verdicts(self) -> tuple[tuple[str, str], ...]:
        """``(run_id, verdict)`` for every run this invocation stopped."""
        return tuple((execution.run_id, execution.verdict.value) for execution in self.executions)

    @property
    def recovered(self) -> bool:
        """True only when *every* stopped run sealed with a ``CLEAN`` verdict.

        False for a dry run and false for an empty tuple, deliberately: "nothing
        was stopped" and "a preview stopped nothing" must not read as
        "everything recovered". An environment-wide stop that found no
        unsettled lease is a success, and :func:`exit_code_for` says so — but
        this property is the *recovery* claim, and no recovery was verified.
        """
        if self.dry_run or not self.executions:
            return False
        return all(execution.recovered for execution in self.executions)

    @property
    def verdict(self) -> PostflightVerdict:
        """The single verdict for a whole invocation, worst-first.

        ``DIRTY`` beats ``UNKNOWN`` beats ``CLEAN``, which is
        :attr:`~mayhem.domain.stop.PostflightReport.verdict`'s precedence applied
        across runs rather than re-derived: one run that did not recover settles
        the answer for the invocation, because an operator asking "is this
        environment clean?" is answered by the worst thing in it. With nothing
        stopped the answer is ``UNKNOWN``, never ``CLEAN``.
        """
        from mayhem.domain.stop import PostflightVerdict as _Verdict

        # The domain's own precedence, read rather than re-derived: a fourth
        # verdict member has to be placed here deliberately, not fall to the
        # bottom because this tuple was not updated.
        order = (_Verdict.CLEAN, _Verdict.UNKNOWN, _Verdict.DIRTY)
        worst = max(
            (order.index(_Verdict(verdict)) for _, verdict in self.verdicts),
            default=order.index(_Verdict.UNKNOWN),
        )
        return order[worst]


def exit_code_for(outcome: StopOutcome) -> ExitCode:
    """The exit code one invocation reports.

    Three cases, deliberately distinct:

    * **dry run** → ``SUCCESS``. The promise was "mutate nothing" and the promise
      was kept; a preview that exited non-zero would train operators to ignore
      the exit code.
    * **nothing to stop** (no executions, not a preview) → ``SUCCESS``. An
      environment-wide stop that found no unsettled lease stopped everything it
      could, and that is the answer, not a failure.
    * **anything stopped** → ``RECOVERY_FAILURE`` if any run is ``DIRTY``,
      ``GENERAL_FAILURE`` if any is ``UNKNOWN``, else ``SUCCESS``. A stalled or
      unsealed stop leaves ``UNKNOWN`` precisely so it cannot exit 0, and a
      residue finding makes ``DIRTY`` precisely so it exits 7.
    """
    if outcome.dry_run or not outcome.executions:
        return ExitCode.SUCCESS
    verdicts = {verdict for _, verdict in outcome.verdicts}
    if PostflightVerdict.DIRTY.value in verdicts:
        return ExitCode.RECOVERY_FAILURE
    if PostflightVerdict.UNKNOWN.value in verdicts:
        return ExitCode.GENERAL_FAILURE
    return ExitCode.SUCCESS


def stop_payload(outcome: StopOutcome) -> dict[str, Any]:
    """The machine-readable projection, in the shape every surface emits."""

    def _execution_row(execution: StopExecution) -> dict[str, Any]:
        record = execution.record
        report = execution.report
        return {
            "run_id": execution.run_id,
            "verdict": execution.verdict.value,
            "recovered": execution.recovered,
            "sealed": execution.sealed is not None,
            "stalled_at": "" if record.stalled_at is None else record.stalled_at.value,
            "stall_reason": record.stall_reason,
            "stages_completed": [stage.value for stage in record.completed_stages],
            "stages_outstanding": [stage.value for stage in record.outstanding],
            "open_residue_obligations": (
                [] if report is None else list(_open_residue_obligations(report))
            ),
            "checks": (
                []
                if report is None
                else [
                    {
                        "name": check.name,
                        "status": check.status.value,
                        "evidence_refs": list(check.evidence_refs),
                        "detail": check.detail,
                    }
                    for check in report.checks
                ]
            ),
        }

    preflight = outcome.preflight
    return {
        "scope": outcome.scope.value,
        "command_id": outcome.command.id,
        "principal": outcome.command.principal,
        "reason": outcome.command.reason.value,
        "detail": outcome.command.trigger.detail,
        "environment": outcome.command.environment,
        "target_run_ids": list(outcome.target_run_ids),
        "held_roles": list(outcome.held_roles),
        "dry_run": outcome.dry_run,
        "recovered": outcome.recovered,
        "verdict": outcome.verdict.value,
        "exit_code": int(exit_code_for(outcome)),
        "preflight": (
            None
            if preflight is None
            else {
                "granted": preflight.granted,
                "vacuous": preflight.vacuous,
                "refusal_reason": preflight.refusal_reason,
                "checks": [
                    {
                        "name": check.name,
                        "status": check.status.value,
                        "source": check.source.value,
                        "port": check.port,
                        "evidence_ref": check.evidence_ref,
                        "detail": check.detail,
                    }
                    for check in preflight.checks
                ],
            }
        ),
        "runs": [_execution_row(execution) for execution in outcome.executions],
    }


# =============================================================================
# Building and executing the command
# =============================================================================


def build_stop_command(
    *,
    scope: StopScope,
    principal: Principal,
    reason: str,
    run_id: str = "",
    environment: str = "",
    now: datetime,
    ttl_seconds: float = 300.0,
) -> StopCommand:
    """Build the :class:`~mayhem.domain.stop.StopCommand` for this invocation.

    **A blank reason is refused here, before any object exists.** A stop with no
    stated cause produces a trigger with no detail, a sealed record that cannot
    say why it sealed, and a postflight whose ``stop`` field names only "human" —
    the one case sealed evidence most needs to explain and the one a reader
    would find blankest. The plan's negative control ("a stop command with no
    reason is unsealable") is enforced at the surface so the reason cannot reach
    the engine in the first place.

    The scope is handed to :class:`~mayhem.domain.stop.StopCommand` and never
    re-derived: an environment-wide command cannot carry a ``run_id`` and a
    run-scoped one cannot name an environment, so "stop everything except that
    one run" is unrepresentable rather than merely discouraged.
    """
    from mayhem.domain.stop import StopCommand as _Command
    from mayhem.domain.stop import StopScope as _Scope
    from mayhem.domain.stop import StopSignal, StopTrigger

    if not reason.strip():
        raise MayhemCliError(
            code="validation_error",
            message=(
                "a stop with no reason cannot be sealed: sealed evidence that cannot say "
                "why a run stopped is not evidence of anything, so pass --reason with "
                "what you are stopping it for"
            ),
            details={"subject": "stop_reason"},
            remediation="pass --reason '<why this run is being stopped>'",
        )
    resolved_scope = _Scope(scope)
    run_id = run_id or ""
    environment = environment or ""
    if resolved_scope is _Scope.RUN and not run_id.strip():
        raise MayhemCliError(
            code="validation_error",
            message="a run-scoped stop must name the run it stops",
            details={"subject": "stop_run_id"},
            remediation="pass a RUN_ID, or --environment to stop every live run",
        )
    return _Command(
        id=command_id(),
        scope=resolved_scope,
        run_id=run_id,
        environment=environment,
        principal=principal.principal_id,
        trigger=StopTrigger.for_signal(StopSignal.OPERATOR_REQUEST, detail=reason.strip()),
        issued_at=now,
        ttl_seconds=ttl_seconds,
    )


def run_state_for(
    store: Store,
    ledger: StopLedger,
    *,
    run_id: str,
) -> RunState:
    """What state of the stop ladder a run is in, as this surface can prove it.

    Two terminal states the lease sink cannot express, both answered from what
    mayhem holds instead of guessed.
    :func:`mayhem.controller.stop_engine.run_state_from_sink` derives only
    ``RUNNING`` and ``PENDING`` on purpose — a sink cannot tell a completed run
    from a running one that happens to hold nothing right now, so guessing
    ``FINISHED`` would silently drop owed stages — so a run the store records as
    ``completed``/``failed``/``aborted`` is ``FINISHED``, and a run that already
    sealed a stop is ``STOPPED``. Both are refused by the engine
    (``stop_for_terminal_run``), which is the plan's negative control: a stop
    command for a finished run is rejected, not silently accepted.

    An unknown run id is a refusal of its own, not a ``PENDING``: mayhem has no
    record of that run at all, and inventing a state for it would let a typo
    produce a sealed stop for a run that never existed.
    """
    from mayhem.controller.stop_engine import run_state_from_sink
    from mayhem.domain.stop import RunState as _State
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    rows = store.query("SELECT status FROM runs WHERE id = ?", (run_id,))
    if not rows:
        raise MayhemCliError(
            code="validation_error",
            message=(
                f"no such run {run_id!r}: mayhem has no record of it, so it cannot stop it"
            ),
            details={"run_id": run_id},
            remediation="run mayhem inspect runs to list the runs mayhem recorded",
        )
    if str(rows[0]["status"]) in _TERMINAL_RUN_STATUSES:
        return _State.FINISHED
    if ledger.seal(run_id) is not None:
        return _State.STOPPED
    return run_state_from_sink(SQLiteLeaseSink(store), run_id)


def _runs_that_can_still_inject(store: Store) -> tuple[str, ...]:
    """The runs an environment-wide stop fans out to.

    Every run the lease sink still holds unsettled work for, and nothing else.
    That set is the honest meaning of "stop this environment": a run holding no
    outstanding lease has nothing to freeze, cancel, compensate, reconcile,
    scan, or verify, and including it would mean writing a stop record for a run
    the ladder refuses anyway, once per invocation.
    """
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    sink = SQLiteLeaseSink(store)
    reader = getattr(sink, "all_leases", None)
    leases = reader() if reader is not None else sink.active_leases()
    return tuple(
        sorted({lease.run_id for lease in leases if lease.run_id and not lease.is_safe_terminal})
    )


def _stop_engine(store: Store, ledger: StopLedger, *, holder: str) -> Any:
    """The stop engine, with every required collaborator bound to this store."""
    from mayhem.controller.recovery import RecoveryService
    from mayhem.controller.stop_engine import StopEngine
    from mayhem.infra.lease_repository import SQLiteLeaseSink

    sink = SQLiteLeaseSink(store)
    return StopEngine(
        sink=sink,
        recovery=RecoveryService(sink),
        dispatch=FenceDispatchFreezer(store, holder=holder),
        ledger=ledger,
    )


def _admit_or_refuse(gate: PreflightGate, inputs: PreflightInputs) -> PreflightReport:
    """``admit`` the gate, turning a refusal into a CLI refusal with the checklist.

    The refusal carries the rendered checklist rather than only the report's
    one-line summary, because the operator who has to decide what to do next
    needs to see *which* checks refused and against what evidence. The gate's own
    :class:`~mayhem.controller.preflight_gate.PreflightRefusedError` and its
    ``PREFLIGHT_REFUSAL`` :class:`~mayhem.domain.stop.StopTrigger` are preserved
    in ``details`` so a machine reader gets the reason the plan spells rather
    than a paraphrase invented here.
    """
    from mayhem.controller.preflight_gate import PreflightRefusedError

    try:
        return gate.admit(inputs)
    except PreflightRefusedError as exc:
        checklist = "\n".join(render_preflight_checklist(exc.report))
        raise MayhemCliError(
            code="safety_refusal",
            message=(
                f"preflight refused the stop for run {exc.report.run_id}: "
                f"{len(exc.report.refusing_checks)} of {len(exc.report.checks)} checks "
                "refused. Nothing was frozen, cancelled, compensated, reconciled, "
                f"scanned, verified, or sealed.\n{checklist}"
            ),
            details={
                "rule": "preflight.refused",
                "stop_reason": exc.trigger.reason.value,
                "refusing_checks": ",".join(check.name for check in exc.refusing_checks),
                "granted": "false",
            },
            remediation=(
                "a preflight that cannot see the incident manager, the control plane, the "
                "deployment feed, the backup system, or the replication peer cannot "
                "certify the environment: bind those witnesses and ask again"
            ),
        ) from exc


def run_stop(
    *,
    store: Store,
    principal: Principal,
    scope: StopScope,
    reason: str,
    now: datetime,
    run_id: str = "",
    environment: str = "",
    level: CancellationLevel | None = None,
    preflight: PreflightGate | None = None,
    preflight_inputs: PreflightInputs | None = None,
    dry_run: bool = False,
    ledger: StopRecorder | None = None,
) -> StopOutcome:
    """Resolve, authorize, admit, and walk — in that order, and only that order.

    1. Build the command. A blank reason, or a run scope naming no run, is
       refused here.
    2. For the environment-wide scope, resolve ``Role.EMERGENCY_STOP`` over the
       identity store and refuse without authority. **Nothing has been written
       at this point.**
    3. Record nothing yet — every write happens after the dry-run return below.
    4. For a run-scoped stop with ``preflight``, call the gate's ``admit``. A
       refusal becomes a ``safety_refusal`` carrying the rendered checklist —
       and the walk never begins, so the refusal performed **zero mutations**.
       ``preflight=None`` reads nothing at all, which is the additive contract
       ``admit(gate=None)`` was built for.
    5. Return early under ``dry_run``, so a preview is write-free: not the
       environment-wide ask, not a checklist, not a lease transition.
    6. Record the environment-wide command itself (so the ask is on the record
       before the fan-out decides there was nothing to stop) and the *granting*
       preflight checklist (so "which checks cleared this stop, and what did they
       look at" survives for the sealed-evidence reader in Phase 4). A *refusing*
       checklist is recorded nowhere, because that path mutates nothing.
    7. Resolve each target run's state; the terminal ones are refused by the
       engine before any stage runs, then walk.

    ``preflight``/``preflight_inputs`` are parameters rather than options so a
    caller that *can* bind port witnesses — the only way the five port checks can
    be answered at all — reaches the same admission the CLI reaches, instead of
    re-implementing it.

    ``StopEngine.execute`` is ``async`` only because the agent-watchdog path is;
    this command takes the controller-recovery path, which awaits nothing, and
    drives it through :func:`asyncio.run` rather than reaching for an event loop
    of its own.
    """
    from mayhem.domain.cancellation import CancellationLevel as _Level
    from mayhem.domain.stop import StopScope as _Scope

    stop_scope = _Scope(scope)
    effective_level = _Level.KILL if level is None else _Level(level)
    the_ledger: StopRecorder = StoreStopLedger(store) if ledger is None else ledger

    command = build_stop_command(
        scope=stop_scope,
        run_id=run_id,
        environment=environment,
        principal=principal,
        reason=reason,
        now=now,
    )

    held_roles: tuple[str, ...] = ()
    if stop_scope is _Scope.ENVIRONMENT:
        held_roles = require_emergency_role(
            store, principal=principal, environment=command.environment, now=now
        )

    report: PreflightReport | None = None
    if preflight is not None:
        if preflight_inputs is None:
            raise MayhemCliError(
                code="safety_refusal",
                message=(
                    "a preflight gate was requested but mayhem holds no inputs to evaluate "
                    "it against; a gate with no inputs must not grant"
                ),
                details={"subject": command.run_id or command.environment},
                remediation="drop the gate, or run against a database that recorded the run",
            )
        report = _admit_or_refuse(preflight, preflight_inputs)

    targets = (command.run_id,) if stop_scope is _Scope.RUN else _runs_that_can_still_inject(store)

    # Every write this function performs is below this line, so ``dry_run=True``
    # is provably write-free rather than merely not-walking-the-ladder: not the
    # environment-wide ask, not the granting checklist, not a lease transition.
    if dry_run:
        return StopOutcome(
            scope=stop_scope,
            command=command,
            target_run_ids=targets,
            preflight=report,
            held_roles=held_roles,
            dry_run=True,
        )

    if report is not None:
        the_ledger.record_checklist(command.run_id, report)
    if stop_scope is _Scope.ENVIRONMENT:
        the_ledger.record_command(command)

    executions: list[StopExecution] = []
    for target in targets:
        state = run_state_for(store, the_ledger, run_id=target)
        run_command = command
        if stop_scope is _Scope.ENVIRONMENT:
            # The engine refuses an environment-wide command by design, so each
            # run gets its own run-scoped command — carrying the same reason, the
            # same principal, and a detail naming the environment-wide ask it
            # came from, so the sealed record reproduces the fan-out.
            run_command = build_stop_command(
                scope=_Scope.RUN,
                run_id=target,
                principal=principal,
                reason=(
                    f"{command.trigger.detail} — environment-wide stop of "
                    f"{command.environment} under command {command.id}"
                ),
                now=now,
            )
        engine = _stop_engine(store, the_ledger, holder=f"stop:{command.principal}")
        executions.append(
            asyncio.run(
                engine.execute(run_command, state=state, level=effective_level, now=now)
            )
        )

    return StopOutcome(
        scope=stop_scope,
        command=command,
        target_run_ids=targets,
        executions=tuple(executions),
        preflight=report,
        held_roles=held_roles,
    )


# =============================================================================
# The Click command
# =============================================================================

_LEVEL_CHOICES = ("grace", "term", "kill")

#: Environment variable naming the principal when ``--principal`` is omitted.
PRINCIPAL_ENV = "MAYHEM_PRINCIPAL"

#: The principal a run-scoped stop runs as when none was named. A real, non-empty
#: :class:`~mayhem.domain.identity.Principal`, because the plan gates only the
#: *environment-wide* scope behind the emergency role — and for that scope the
#: placeholder confers nothing by construction, because ``effective_roles`` over
#: an identity store with no grant for it returns the empty set. Default-deny,
#: not a special case for the anonymous spelling.
DEFAULT_PRINCIPAL = "operator"


def _principal_for(principal_id: str) -> Principal:
    from mayhem.domain.identity import Principal as _Principal

    return _Principal(principal_id=principal_id)


@click.command(
    "stop",
    params=[
        click.Argument(
            ["run_id"],
            required=False,
            metavar="[RUN_ID]",
            help="The one run to stop. Omit it, and pass --environment, to stop every "
            "live run in an environment.",
        ),
        click.Option(
            ["--environment", "environment"],
            default="",
            metavar="ENV",
            help="Environment-wide stop: every run that can still be injecting. Requires "
            "the emergency_stop role (plan 09).",
        ),
        click.Option(
            ["--principal", "principal_id"],
            default="",
            metavar="ID",
            help="Principal issuing the stop, resolved for the emergency role. Defaults "
            f"to ${PRINCIPAL_ENV}.",
        ),
        click.Option(
            ["--reason", "reason"],
            required=True,
            metavar="TEXT",
            help="Why the run is being stopped. Required: a stop with no reason cannot "
            "be sealed.",
        ),
        click.Option(
            ["--level", "level"],
            type=click.Choice(_LEVEL_CHOICES, case_sensitive=False),
            default="kill",
            show_default=True,
            help="How hard to stop. kill (the default) owes the whole ladder, including "
            "the residue scan and the verify gate.",
        ),
        click.Option(
            ["--preflight", "preflight"],
            is_flag=True,
            default=False,
            help="Run the refusing preflight gate first and render its checklist; a "
            "refusal stops nothing. The five port checks have no CLI witness, so this "
            "refuses until they are bound.",
        ),
        click.Option(
            ["--json", "as_json"],
            is_flag=True,
            default=False,
            help="Emit a JSON projection instead of the text checklist.",
        ),
    ],
)
@click.pass_context
def stop(
    ctx: click.Context,
    run_id: str,
    environment: str,
    principal_id: str,
    reason: str,
    level: str,
    preflight: bool,
    as_json: bool,
) -> None:
    """Stop one run, or every live run in an environment.

    Naming the command is the approval, as it is for ``mayhem recover execute``:
    the request to stop *is* the explicit act, and the real control on the
    environment-wide scope is the emergency role this command checks before it
    writes anything.

    A global ``--dry-run`` is honoured structurally: the walk is unreachable in
    that branch, so nothing is frozen, cancelled, compensated, reconciled,
    scanned, verified, or sealed, and the rendered outcome says ``dry-run`` so it
    can never be mistaken for a completed stop.
    """
    from mayhem.cli.services import open_store
    from mayhem.domain.cancellation import CancellationLevel
    from mayhem.domain.common import utc_now
    from mayhem.domain.stop import StopScope

    # Click hands an omitted optional argument back as None; the domain takes
    # "" for "not stated", and normalising here keeps that distinction in one
    # place rather than in every optional field.
    run_id = run_id or ""
    environment = environment or ""
    if bool(run_id) == bool(environment):
        raise click.UsageError(
            "name exactly one scope: a RUN_ID, or --environment ENV. An "
            "environment-wide command cannot carry a run id, and a run-scoped one "
            "cannot name an environment."
        )
    if preflight and environment:
        raise click.UsageError(
            "--preflight evaluates one run's gate and needs a RUN_ID; an environment "
            "has no plan to check."
        )

    scope = StopScope.RUN if run_id else StopScope.ENVIRONMENT
    now = utc_now()
    dry_run = bool(getattr(ctx.obj, "dry_run", False))
    db_path = getattr(ctx.obj, "db", "mayhem.db")

    gate: PreflightGate | None = None
    inputs: PreflightInputs | None = None
    if preflight:
        from mayhem.controller.preflight_gate import PreflightGate as _Gate

        # Nothing is bound here, and that is the honest starting position: the
        # CLI has no witness for the incident manager, the control plane, the
        # deployment feed, the backup system, or the replication peer, so those
        # five checks report UNAVAILABLE and refuse. A caller that *has* witnesses
        # calls run_stop(preflight=...) with its own PreflightGate.
        gate = _Gate()

    store = open_store(db_path)
    try:
        if inputs is None and gate is not None:
            inputs = preflight_inputs_for(store, run_id, now=now)
            if inputs is None:
                raise MayhemCliError(
                    code="validation_error",
                    message=(
                        f"--preflight was requested for run {run_id!r}, which the database "
                        "does not record. Mayhem has no plan to pre-check, and a gate with "
                        "no inputs must not grant."
                    ),
                    details={"run_id": run_id},
                    remediation="run mayhem inspect runs to list the runs mayhem recorded",
                )
        outcome = run_stop(
            store=store,
            principal=_principal_for(principal_id or _principal_from_env()),
            scope=scope,
            reason=reason,
            run_id=run_id,
            environment=environment,
            level=CancellationLevel[str(level).upper()],
            preflight=gate,
            preflight_inputs=inputs,
            dry_run=dry_run,
            now=now,
        )
    finally:
        store.close()

    if as_json:
        click.echo(json.dumps(stop_payload(outcome), indent=2, sort_keys=True, default=str))
    else:
        _echo_text(outcome)
    ctx.exit(int(exit_code_for(outcome)))


def _principal_from_env() -> str:
    return str(os.environ.get(PRINCIPAL_ENV, "") or "").strip() or DEFAULT_PRINCIPAL


def _echo_text(outcome: StopOutcome) -> None:
    command = outcome.command
    if outcome.dry_run:
        click.echo(
            style.warn(
                "dry-run: nothing was frozen, cancelled, compensated, reconciled, "
                "scanned, verified, or sealed. No run was stopped.",
                err=False,
            )
        )
    click.echo(
        f"stop {command.id} scope={outcome.scope.value} principal={command.principal} "
        f"reason={command.reason.value}"
    )
    if outcome.held_roles:
        click.echo(f"  authorized by roles: {', '.join(outcome.held_roles)}")
    if outcome.preflight is not None:
        for line in render_preflight_checklist(outcome.preflight):
            click.echo(f"  {line}")
    if not outcome.executions:
        click.echo(
            "  no run was stopped: "
            + (
                "dry-run previewed the stop without walking the ladder"
                if outcome.dry_run
                else "this environment holds no unsettled lease, so there was nothing "
                "to escalate"
            )
        )
        return
    for execution in outcome.executions:
        for line in render_stop_execution(execution):
            click.echo(line)
    click.echo(f"verdict: {_verdict_word(outcome.verdict)}")
    click.echo(
        "recovered: "
        + (style.ok("yes", err=False) if outcome.recovered else style.orange("no", err=False))
    )
