"""Plan 10 Phase 3 (surface half) — one command that stops a run, and says so.

Phase 1 (:mod:`mayhem.domain.stop`) proved the vocabulary, Phase 2
(``test_stop_engine.py``) proved the ladder walks and seals, and the engine half
of Phase 3 (``test_preflight_gate.py``) proved preflight refuses. None of those
is reachable by a person, and this suite is about the missing last link:

* **every documented invocation resolves on the live Click tree.** The surface is
  one command, not a group, and the plan's two spellings — ``mayhem stop
  RUN_ID`` and ``mayhem stop --environment ENV`` — are checked against the same
  resolver ``test_release_contract.py`` uses, so a typo in this suite fails the
  same way a typo in a document would.
* **run-scoped and environment-wide are different acts.** A run-scoped stop
  needs no role at all; an environment-wide one needs plan 09's
  ``emergency_stop`` and is refused — with *zero mutations* — without it. The
  role required is read from ``check_gate.CHATOPS_REQUIRED_ROLE`` rather than
  restated, so the CLI and ChatOps cannot disagree about who may stop something.
* **a preflight refusal stops nothing.** Asserted against the store itself:
  no observation rows, no fence row, no lease transition. A refusal that had
  already written a stop record would be a refusal that changed the world it
  refused to read.
* **an unreachable port never renders as pass.** Four ways to have no answer —
  unbound, raising, answering ``None``, answering in the wrong shape — and the
  rendered word must be ``UNAVAILABLE`` in every one, with the port named.
* **postflight rendering, in all three verdicts.** Clean, dirty, and unknown.
  The load-bearing assertion is the dirty one: a stop that left a residue must
  name that residue and must not contain the word ``CLEAN`` anywhere.
* **the negative controls**, each asserting a *named* refusal rather than "it
  raised": a finished run, an already-stopped run, an unknown run, a blank
  reason, an unauthorized environment-wide stop, and an unreachable port.

One test in this file is about something that did **not** land:
:func:`test_the_run_path_still_has_no_preflight_gate_seam` pins the absence of
the executor attach point, because a refusal a caller has to remember to ask for
is not yet a refusal in the run path, and the Phase 3 STATUS line depends on
that being true.

Timestamps are injected everywhere; nothing here reads a wall clock to decide a
verdict.
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import click
import pytest
from click.testing import CliRunner

from mayhem.cli import stop_cmd
from mayhem.cli.app import _STATE, app, main
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.check_gate import CHATOPS_REQUIRED_ROLE, ChatOpsCommand
from mayhem.controller.preflight_gate import (
    CHECK_INCIDENT_ACTIVE,
    CheckStatus,
    PortObservation,
    PreflightGate,
    PreflightInputs,
    PreflightPorts,
)
from mayhem.controller.stop_engine import (
    CompensationPath,
    StopRecord,
    stage_ref,
)
from mayhem.domain.cancellation import CancellationLevel
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.identity import EnvironmentScope, Principal, Role, RoleGrant
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.policy import PolicyDecision
from mayhem.domain.preflight import Preflight
from mayhem.domain.stop import (
    STOP_FLOW,
    PostflightVerdict,
    RunState,
    StopScope,
    StopStage,
    StopTrigger,
)
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.infra.budget_enforcement import RunBudgetGuard
from mayhem.infra.identity_store import IdentityStore
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.metering import ResourceBudgetEnforcer
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from mayhem.controller.stop_engine import SealedStop

ROOT = Path(__file__).parents[2]
MOMENT = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
"""Injected clock: every verdict below is decided against this instant."""
RUN_ID = "r-drill-a1b2c3d4"
OTHER_RUN_ID = "r-drill-ffff0000"
HOUR = 3600.0
DURATION_S = 5.0
REASON = "the injected fault is not reversing"


# ==============================================================================
# The world: a store with runs, leases, and (optionally) an emergency grant
# ==============================================================================


@pytest.fixture(autouse=True)
def _restore_cli_state():
    original = _STATE.copy()
    yield
    _STATE.clear()
    _STATE.update(original)


def _plan(run_id: str = RUN_ID, *fault_ids: str) -> ExecutionPlan:
    """A frozen plan naming one service target, or none."""
    selector = TargetSelector(kind="service", expr="web")
    steps = tuple(
        PlannedStep(
            id=f"s{seq}",
            seq=seq,
            raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=DURATION_S),
            fault=PlannedFault(
                fault_id=fault_id,
                targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-web"})),),
                duration=DURATION_S,
            ),
        )
        for seq, fault_id in enumerate(fault_ids)
    )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=steps,
        config_snapshot_id="c-1",
        topology_snapshot_id="",
        environment_fingerprint="f-1",
    )


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(ServiceNode(id="n-web", name="web"), ServiceNode(id="n-api", name="api")),
        edges=(Edge(src="n-api", dst="n-web", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
    )


def _preview(plan: ExecutionPlan) -> Preflight:
    return Preflight(
        resolved_target="web",
        config_snapshot_id="c-1",
        topology_snapshot_id="",
        environment_fingerprint="f-1",
        plan=plan,
        blocked_items=(),
        warnings=(),
        blast_radius={"status": "within_budget", "services_pct": 33.3},
    )


def _allow() -> PolicyDecision:
    return PolicyDecision(
        outcome="allow",
        bundle_id="stop-surface",
        bundle_version=1,
        matched_rules=("staging.allows",),
    )


def _budget() -> RunBudgetGuard:
    from mayhem.domain.budgets import (
        ResourceBudget,
        ResourceDimension,
        ResourceEstimate,
        ResourceScope,
    )

    enforcer = ResourceBudgetEnforcer(
        budgets=(
            ResourceBudget(
                dimension=ResourceDimension.CPU,
                scope=ResourceScope.RUN,
                scope_key=RUN_ID,
                limit=1e6,
                window_s=HOUR,
                description="stop-surface fixture",
            ),
        ),
        scope=ResourceScope.RUN,
        anchor=MOMENT,
        run_id=RUN_ID,
    )
    return RunBudgetGuard(
        enforcer=enforcer,
        estimates=(
            ResourceEstimate(
                dimension=ResourceDimension.CPU,
                scope=ResourceScope.RUN,
                scope_key=RUN_ID,
                expected=DURATION_S,
                basis="stop-surface fixture",
            ),
        ),
    )


def _agent():
    from mayhem.agents.capabilities import AgentCapabilities, AgentIdentity, CapabilityKind

    return AgentIdentity(
        agent_id="agent-1",
        capabilities=AgentCapabilities(
            allowed_faults=("proc.pause",),
            capabilities=(CapabilityKind.FAULT_INJECT, CapabilityKind.FAULT_UNDO),
        ),
    )


def granting_inputs(plan: ExecutionPlan | None = None, *, ports: PreflightPorts) -> PreflightInputs:
    """Every one of the twelve checks has a witness and every witness says yes."""
    the_plan = _plan() if plan is None else plan
    return PreflightInputs(
        plan=the_plan,
        now=MOMENT,
        preflight=_preview(the_plan),
        graph=_graph(),
        agents=(_agent(),),
        policy=_allow(),
        budget=_budget(),
        environment="staging",
        target="web",
    )


def healthy_ports() -> PreflightPorts:
    """Five ports, all bound, all answering ``healthy=True``."""

    class Healthy:
        def __init__(self, name: str) -> None:
            self._name = name

        def _answer(self, **kwargs: Any) -> PortObservation:
            return PortObservation(
                healthy=True,
                evidence_ref=f"obs/{self._name}",
                detail=f"{self._name} reachable",
            )

        cluster_ready = active_incidents = recent_deployment = _answer
        backup_state = replication_health = _answer

    return PreflightPorts(
        cluster=Healthy("cluster"),
        incident=Healthy("incident"),
        deployment=Healthy("deployment"),
        backup=Healthy("backup"),
        replication=Healthy("replication"),
    )


def _lease(
    lease_id: str = "l-1",
    *,
    run_id: str = RUN_ID,
    state: LeaseState = LeaseState.ACTIVE,
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
    if state is LeaseState.PENDING:
        return base
    if state is LeaseState.ACTIVE:
        return base.transition(LeaseState.ACTIVE, now=MOMENT)
    wedged = base.transition(LeaseState.ACTIVE, now=MOMENT)
    return wedged.transition(LeaseState.RELEASING, now=MOMENT).transition(
        LeaseState.DIRTY, now=MOMENT, escalation_notes="compensation failed; wedged"
    )


def _seed_run(
    store: Store,
    run_id: str,
    *,
    status: str = "running",
    plan: ExecutionPlan | None = None,
) -> None:
    """One ``runs`` row plus its ``config_snapshots`` dependency."""
    document = (_plan(run_id) if plan is None else plan).model_dump_json()
    with store.write() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO config_snapshots (id, resolved_json, source_map, created_at)"
            " VALUES (?, '{}', '{}', 'now')",
            ("c-1",),
        )
        conn.execute(
            "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed,"
            " status, environment_fingerprint, config_snapshot_id)"
            " VALUES (?, 'exp', 'deterministic', '{}', ?, 1, ?, 'f-1', 'c-1')",
            (run_id, document, status),
        )


def _make_store(tmp_path: Path, *, name: str = "stop.db") -> Store:
    return Store.open_migrated(tmp_path / name)


def _granted(store: Store, principal_id: str, environment: str, role: Role) -> None:
    IdentityStore(store).save_grant(
        RoleGrant(
            role=role,
            scope=EnvironmentScope(environment=environment),
            principal=Principal(principal_id=principal_id),
            granted_at=MOMENT - timedelta(days=1),
        )
    )


def _run_main(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


def _ledger_rows(store: Store, kind: str) -> list[Any]:
    return list(store.query("SELECT * FROM observations WHERE kind = ?", (kind,)))


def _fences(store: Store) -> list[Any]:
    return list(store.query("SELECT * FROM repl_fences"))


def _lease_state(store: Store, lease_id: str) -> str | None:
    rows = store.query("SELECT state FROM fault_leases WHERE id = ?", (lease_id,))
    return None if not rows else str(rows[0]["state"])


def _principal(principal_id: str = "u-ana") -> Principal:
    return Principal(principal_id=principal_id)


# ==============================================================================
# The surface exists, is one command, and every invocation resolves
# ==============================================================================


def _release_contract_module() -> Any:
    """The sibling contract module, by path — the one real resolver in the tree.

    Imported rather than re-implemented for the same reason
    ``test_readme_honesty.py`` imports it: a second prefix/arity resolver is a
    second opinion, and this suite's job is to hold the *surface* to the same
    contract a document is held to, not to invent a laxer one.
    """
    name = "_release_contract_for_stop_surface"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "tests/unit/test_release_contract.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: Every ``mayhem …`` spelling this module or the README puts forward. Each must
#: resolve on the live tree, with its options declared on the node that consumes
#: them and its minimum arity satisfied.
DOCUMENTED_INVOCATIONS: tuple[tuple[str, ...], ...] = (
    ("stop", RUN_ID, "--reason", REASON),
    ("stop", RUN_ID, "--reason", REASON, "--level", "kill"),
    ("stop", RUN_ID, "--reason", REASON, "--json"),
    ("stop", RUN_ID, "--reason", REASON, "--preflight"),
    ("stop", "--environment", "staging", "--reason", REASON),
    ("stop", "--environment", "staging", "--reason", REASON, "--principal", "u-ana"),
)


@pytest.mark.parametrize("argv", DOCUMENTED_INVOCATIONS)
def test_every_documented_stop_invocation_resolves_against_the_cli(argv: tuple[str, ...]) -> None:
    assert _release_contract_module()._resolve_invocation(list(argv)) == []


def test_stop_is_registered_under_its_own_name_and_no_prefix_shorthand() -> None:
    """``stop`` must resolve exactly: no sibling command starts with ``s``."""
    ctx = click.Context(app)
    assert app.get_command(ctx, "stop") is stop_cmd.stop
    candidates = sorted(name for name in app.commands if name.startswith("s"))
    assert candidates == ["stop"], f"stop now shares a prefix with {candidates}"


def test_stop_is_one_command_and_not_a_group() -> None:
    """The plan's acceptance is "one command/UI action stops a run".

    A group would give ``mayhem stop`` a second, differently-shaped spelling of
    the same act, and the environment-wide form could then be reached without
    the emergency-role check being obviously load-bearing.
    """
    assert isinstance(stop_cmd.stop, click.Command)
    assert not isinstance(stop_cmd.stop, click.Group)


def test_stop_help_advertises_both_scopes_and_the_required_options() -> None:
    result = CliRunner().invoke(app, ["stop", "--help"])
    assert result.exit_code == 0
    for expected in (
        "[RUN_ID]",
        "--environment",
        "--principal",
        "--reason",
        "--level",
        "--preflight",
        "--json",
    ):
        assert expected in result.output, expected
    assert "emergency_stop" in result.output


@pytest.mark.parametrize(
    "bypass",
    (
        "--force",
        "--no-preflight",
        "--skip-preflight",
        "--skip-role",
        "--unrestricted",
        "--skip-gate",
        "--bypass-role",
    ),
)
def test_stop_has_no_bypass_flag(bypass: str) -> None:
    """The plan: "a preflight bypass flag does not exist".

    Phase 6 makes this a stated property, and the surface is where it would be
    added, so it is asserted here rather than deferred. A flag that waves the
    gate through would be the one thing that undoes the whole refusal contract.
    """
    declared = {
        token
        for param in stop_cmd.stop.params
        for token in getattr(param, "opts", []) + getattr(param, "secondary_opts", [])
    }
    assert bypass not in declared


def test_stop_reason_is_required_by_the_parser() -> None:
    reasons = [p for p in stop_cmd.stop.params if p.name == "reason"]
    assert len(reasons) == 1
    assert reasons[0].required is True


# ==============================================================================
# Run-scoped vs environment-wide: different acts, one command
# ==============================================================================


def test_the_environment_wide_role_required_is_plan_09s_emergency_stop() -> None:
    """Read from the ChatOps table rather than restated here."""
    assert CHATOPS_REQUIRED_ROLE[ChatOpsCommand.STOP] is Role.EMERGENCY_STOP
    source = (ROOT / "src/mayhem/cli/stop_cmd.py").read_text(encoding="utf-8")
    assert "CHATOPS_REQUIRED_ROLE" in source, "the required role must be read, not re-spelled"


def test_run_scoped_stop_needs_no_role_at_all(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        outcome = stop_cmd.run_stop(
            store=store,
            principal=_principal(),
            scope=StopScope.RUN,
            reason=REASON,
            run_id=RUN_ID,
            now=MOMENT,
        )
        assert outcome.scope is StopScope.RUN
        assert outcome.executions[0].run_id == RUN_ID
        assert outcome.verdict is PostflightVerdict.CLEAN
    finally:
        store.close()


def test_environment_wide_stop_is_refused_without_the_emergency_role(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        with pytest.raises(MayhemCliError) as excinfo:
            stop_cmd.run_stop(
                store=store,
                principal=_principal(),
                scope=StopScope.ENVIRONMENT,
                reason=REASON,
                environment="staging",
                now=MOMENT,
            )
        refusal = excinfo.value
        assert refusal.code == "safety_refusal"
        assert "emergency_stop" in refusal.message
        assert refusal.details["required_role"] == Role.EMERGENCY_STOP.value
        # The refusal is a refusal of the *whole* invocation: nothing stopped,
        # nothing was recorded, nothing was frozen.
        assert _ledger_rows(store, stop_cmd.STOP_ATTEMPT_KIND) == []
        assert _ledger_rows(store, stop_cmd.STOP_SEAL_KIND) == []
        assert _ledger_rows(store, stop_cmd.STOP_COMMAND_KIND) == []
        assert _fences(store) == []
        assert _lease_state(store, "l-1") == LeaseState.ACTIVE.value
    finally:
        store.close()


def test_environment_wide_stop_is_allowed_with_the_emergency_role(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        _seed_run(store, OTHER_RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        # The second run holds a settled lease, so it cannot be injecting and the
        # fan-out must not touch it.
        SQLiteLeaseSink(store).save(
            _lease("l-2", run_id=OTHER_RUN_ID).transition(
                LeaseState.RELEASING, now=MOMENT
            ).transition(LeaseState.RELEASED, now=MOMENT)
        )
        _granted(store, "u-ana", "staging", Role.EMERGENCY_STOP)
        outcome = stop_cmd.run_stop(
            store=store,
            principal=_principal(),
            scope=StopScope.ENVIRONMENT,
            reason=REASON,
            environment="staging",
            now=MOMENT,
        )
        assert Role.EMERGENCY_STOP.value in outcome.held_roles
        assert outcome.target_run_ids == (RUN_ID,)
        assert [execution.run_id for execution in outcome.executions] == [RUN_ID]
        # The sealed record reproduces the fan-out: same reason, same principal,
        # and a detail naming the environment-wide ask behind it.
        detail = outcome.executions[0].record.command.trigger.detail
        assert REASON in detail
        assert "staging" in detail
        assert outcome.command.id in detail
        assert outcome.command.scope is StopScope.ENVIRONMENT
        # The ask itself is on the record, before the fan-out decided anything.
        assert len(_ledger_rows(store, stop_cmd.STOP_COMMAND_KIND)) == 1
    finally:
        store.close()


def test_an_environment_wide_stop_records_the_ask_even_with_nothing_to_stop(
    tmp_path: Path,
) -> None:
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        _granted(store, "u-ana", "staging", Role.EMERGENCY_STOP)
        outcome = stop_cmd.run_stop(
            store=store,
            principal=_principal(),
            scope=StopScope.ENVIRONMENT,
            reason=REASON,
            environment="staging",
            now=MOMENT,
        )
        assert outcome.target_run_ids == ()
        assert outcome.executions == ()
        assert len(_ledger_rows(store, stop_cmd.STOP_COMMAND_KIND)) == 1
        # Nothing was stopped, so nothing was verified: "recovered" must not be
        # read out of an invocation that ran no ladder.
        assert outcome.recovered is False
        assert int(stop_cmd.exit_code_for(outcome)) == int(ExitCode.SUCCESS)
    finally:
        store.close()


def test_an_environment_wide_command_cannot_carry_a_run_id() -> None:
    """The unrepresentable case, straight from ``domain.stop``.

    "Stop everything except that one run" is a bug with a blast radius, so the
    domain refuses the spelling outright rather than encouraging the caller to
    narrow the scope.
    """
    from mayhem.domain.stop import StopCommand, StopReason

    with pytest.raises(InvariantViolationError):
        StopCommand(
            id="sc-x",
            scope=StopScope.ENVIRONMENT,
            run_id=RUN_ID,
            environment="staging",
            principal="u-ana",
            trigger=StopTrigger(reason=StopReason.HUMAN),
            issued_at=MOMENT,
        )


def test_the_cli_refuses_an_unauthorized_environment_wide_stop(tmp_path: Path) -> None:
    db = tmp_path / "cli.db"
    store = _make_store(tmp_path, name="cli.db")
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
    finally:
        store.close()
    code, _out, err = _run_main(
        "--db", str(db), "stop", "--environment", "staging", "--reason", REASON,
        "--principal", "u-ana",
    )
    assert code == int(ExitCode.SAFETY_REFUSAL)
    assert "emergency_stop" in err


def test_the_cli_stops_an_environment_once_the_role_is_granted(tmp_path: Path) -> None:
    db = tmp_path / "cli.db"
    store = _make_store(tmp_path, name="cli.db")
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        _granted(store, "u-ana", "staging", Role.EMERGENCY_STOP)
    finally:
        store.close()
    code, out, err = _run_main(
        "--db", str(db), "stop", "--environment", "staging", "--reason", REASON,
        "--principal", "u-ana",
    )
    assert code == int(ExitCode.SUCCESS), err
    assert "authorized by roles: emergency_stop" in out
    assert RUN_ID in out
    assert "CLEAN" in out


# ==============================================================================
# Preflight: the checklist, and the refusal that stops nothing
# ==============================================================================


class _DeadPort:
    """A bound port with no answer: it raises, which is one of the four no-answers."""

    def __init__(self, name: str) -> None:
        self._name = name

    def active_incidents(self, **kwargs: Any) -> PortObservation:
        msg = f"{self._name} unreachable"
        raise TimeoutError(msg)

    cluster_ready = active_incidents
    recent_deployment = active_incidents
    backup_state = active_incidents
    replication_health = active_incidents


class _SilentPort:
    """A bound port that connects and answers ``None`` — which is not an answer."""

    def __init__(self, name: str) -> None:
        self._name = name

    def active_incidents(self, **kwargs: Any) -> None:
        return None

    cluster_ready = active_incidents
    recent_deployment = active_incidents
    backup_state = active_incidents
    replication_health = active_incidents


def test_an_unreachable_port_is_rendered_unavailable_and_never_as_pass() -> None:
    """The load-bearing rendering rule, for all four ways of having no answer.

    ``FAIL`` would at least be a fact about the environment; ``PASS`` would be a
    rubber stamp, and "the incident manager reports no open incidents" is the
    one sentence a preflight must never be able to say without having asked.
    """
    shapes = (
        PreflightPorts(),  # unbound
        PreflightPorts(incident=_DeadPort("incident")),  # raises
        PreflightPorts(incident=_SilentPort("incident")),  # answers None
        PreflightPorts(incident=SimpleNamespace(active_incidents=lambda **_: "yes")),  # wrong shape
    )
    for ports in shapes:
        plan = _plan()
        report = PreflightGate(ports=ports).evaluate(granting_inputs(plan, ports=ports))
        rendered = stop_cmd.render_preflight_checklist(report)
        incident = report.check(CHECK_INCIDENT_ACTIVE)
        assert incident is not None
        assert incident.status is CheckStatus.UNAVAILABLE, (ports, incident.status)
        assert incident.refuses is True
        # Scoped to the incident line: the seven real checks may legitimately
        # render as PASS in this same report, and the rule is about *this* check.
        line = next(row for row in rendered if incident.name in row)
        assert line.lstrip().startswith("UNAVAILABLE"), (ports, line)
        assert "PASS" not in line, (ports, line)
        # The port is named, so an operator learns which system could not be asked.
        assert incident.port == "incident"
        assert f"via {incident.port}" in line
        assert "UNAVAILABLE" in "\n".join(rendered)


def test_a_granting_preflight_renders_every_check_as_a_pass_and_allows_the_stop(
    tmp_path: Path,
) -> None:
    """The other half of the rule: a gate that is genuinely satisfied still lets
    the stop through. Without this, ``--preflight`` would be a button that only
    ever refuses, and the refusal would prove nothing about the gate."""
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        ports = healthy_ports()
        plan = _plan()
        outcome = stop_cmd.run_stop(
            store=store,
            principal=_principal(),
            scope=StopScope.RUN,
            reason=REASON,
            run_id=RUN_ID,
            preflight=PreflightGate(ports=ports),
            preflight_inputs=granting_inputs(plan, ports=ports),
            now=MOMENT,
        )
        # A granting checklist is kept with its per-check evidence, because "which
        # checks cleared this stop" is the question a later reader of the sealed
        # evidence asks. The *refused* half deliberately leaves nothing behind.
        rows = _ledger_rows(store, stop_cmd.EMERGENCY_STOP_CHECKLIST_KIND)
    finally:
        store.close()
    assert outcome.preflight is not None
    assert outcome.preflight.granted is True
    rendered = "\n".join(stop_cmd.render_preflight_checklist(outcome.preflight))
    assert "granted (12 checks passed)" in rendered
    assert "UNAVAILABLE" not in rendered
    assert outcome.verdict is PostflightVerdict.CLEAN
    assert len(rows) == 1
    recorded = json.loads(str(rows[0]["data_json"]))
    assert recorded["granted"] is True
    assert len(recorded["checks"]) == 12
    assert all(check["evidence_ref"] for check in recorded["checks"])


def test_a_preflight_refusal_prevents_every_mutation(tmp_path: Path) -> None:
    """Zero mutations, asserted against the store itself.

    A refusal that had already written a stop record, minted a fence, or moved a
    lease would have changed the world it refused to read.
    """
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        before = len(store.query("SELECT * FROM observations"))
        with pytest.raises(MayhemCliError) as excinfo:
            stop_cmd.run_stop(
                store=store,
                principal=_principal(),
                scope=StopScope.RUN,
                reason=REASON,
                run_id=RUN_ID,
                preflight=PreflightGate(),  # no ports bound: five UNAVAILABLE
                preflight_inputs=granting_inputs(_plan(), ports=PreflightPorts()),
                now=MOMENT,
            )
        refusal = excinfo.value
        assert refusal.code == "safety_refusal"
        assert refusal.details["stop_reason"] == "preflight_failed"
        assert CHECK_INCIDENT_ACTIVE in refusal.details["refusing_checks"]
        assert "UNAVAILABLE" in refusal.message
        incident_line = next(
            row for row in refusal.message.splitlines() if CHECK_INCIDENT_ACTIVE in row
        )
        assert incident_line.lstrip().startswith("UNAVAILABLE"), incident_line
        assert _lease_state(store, "l-1") == LeaseState.ACTIVE.value
        assert _fences(store) == []
        assert len(store.query("SELECT * FROM observations")) == before
        assert _ledger_rows(store, stop_cmd.STOP_ATTEMPT_KIND) == []
        assert _ledger_rows(store, stop_cmd.STOP_SEAL_KIND) == []
    finally:
        store.close()


def test_the_cli_preflight_refusal_is_a_safety_refusal_and_names_every_check(
    tmp_path: Path,
) -> None:
    db = tmp_path / "cli.db"
    store = _make_store(tmp_path, name="cli.db")
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
    finally:
        store.close()
    code, _out, err = _run_main(
        "--db", str(db), "stop", RUN_ID, "--reason", REASON, "--preflight"
    )
    assert code == int(ExitCode.SAFETY_REFUSAL)
    assert "REFUSED" in err
    assert "UNAVAILABLE" in err
    assert "Nothing was frozen, cancelled, compensated" in err
    assert "CLEAN" not in err
    # Nothing was stopped: the lease is still ACTIVE and no fence was minted.
    store = _make_store(tmp_path, name="cli.db")
    try:
        assert _lease_state(store, "l-1") == LeaseState.ACTIVE.value
        assert _fences(store) == []
    finally:
        store.close()


def test_preflight_refuses_an_environment_wide_stop_as_a_usage_error() -> None:
    """An environment has no plan, so there is nothing for the gate to judge."""
    code, _out, err = _run_main(
        "stop", "--environment", "staging", "--reason", REASON, "--preflight"
    )
    assert code == int(ExitCode.USAGE_ERROR)
    assert "needs a RUN_ID" in err


def test_the_cli_preflight_rejects_a_run_the_database_does_not_record(
    tmp_path: Path,
) -> None:
    db = tmp_path / "cli.db"
    _make_store(tmp_path, name="cli.db").close()
    code, _out, err = _run_main(
        "--db", str(db), "stop", "r-nope", "--reason", REASON, "--preflight"
    )
    assert code == int(ExitCode.VALIDATION_ERROR)
    assert "does not record" in err


# ==============================================================================
# Postflight rendering: clean, dirty, and unknown
# ==============================================================================


def test_a_clean_stop_names_the_reason_the_stages_and_the_verdict(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        outcome = stop_cmd.run_stop(
            store=store,
            principal=_principal(),
            scope=StopScope.RUN,
            reason=REASON,
            run_id=RUN_ID,
            now=MOMENT,
        )
    finally:
        store.close()
    rendered = "\n".join(stop_cmd.render_stop_execution(outcome.executions[0]))
    assert f"reason: human — {REASON}" in rendered
    assert "stages completed: " + ", ".join(stage.value for stage in STOP_FLOW) in rendered
    assert "stages outstanding: none" in rendered
    assert "postflight verdict: CLEAN" in rendered
    assert "recovery verified: yes" in rendered
    assert "FAIL" not in rendered
    assert outcome.recovered is True
    assert int(stop_cmd.exit_code_for(outcome)) == int(ExitCode.SUCCESS)


def test_a_dirty_stop_names_the_residue_and_never_reads_as_clean(tmp_path: Path) -> None:
    """The requirement that a stopped run which did not recover must never read
    as clean — asserted as the absence of the word ``CLEAN`` in the rendering,
    not merely as the presence of the word ``DIRTY``."""
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease(state=LeaseState.DIRTY))
        outcome = stop_cmd.run_stop(
            store=store,
            principal=_principal(),
            scope=StopScope.RUN,
            reason=REASON,
            run_id=RUN_ID,
            now=MOMENT,
        )
    finally:
        store.close()
    execution = outcome.executions[0]
    rendered = "\n".join(stop_cmd.render_stop_execution(execution))
    assert "CLEAN" not in rendered
    assert "postflight verdict: DIRTY" in rendered
    assert "recovery verified: no" in rendered
    assert "OPEN RESIDUE OBLIGATIONS" in rendered
    assert "must not be read as clean" in rendered
    # The failing checks are named with their evidence, not merely counted.
    assert "residue:lease_unsettled:l-1" in rendered
    assert "residue/lease_unsettled/l-1" in rendered
    assert "FAIL verify:run_completion_gate" in rendered
    assert outcome.verdict is PostflightVerdict.DIRTY
    assert outcome.recovered is False
    assert int(stop_cmd.exit_code_for(outcome)) == int(ExitCode.RECOVERY_FAILURE)

    payload = stop_cmd.stop_payload(outcome)
    assert payload["verdict"] == "dirty"
    assert payload["exit_code"] == int(ExitCode.RECOVERY_FAILURE)
    row = payload["runs"][0]
    assert row["open_residue_obligations"], "the payload must carry the open obligations"
    assert row["recovered"] is False


def test_a_stalled_stop_reads_unknown_and_names_the_stage_it_stalled_at() -> None:
    from mayhem.controller.stop_engine import StageReceipt, StopExecution

    record = StopRecord(
        command=stop_cmd.build_stop_command(
            scope=StopScope.RUN,
            run_id=RUN_ID,
            principal=_principal(),
            reason=REASON,
            now=MOMENT,
        ),
        state=RunState.RUNNING,
        level=CancellationLevel.KILL,
        compensation=CompensationPath.CONTROLLER_RECOVERY,
        started_at=MOMENT,
        finished_at=MOMENT,
        completed_stages=(StopStage.FREEZE,),
        stalled_at=StopStage.COMPENSATE_ACTIVE,
        stall_reason="compensate_active: RuntimeError: the agent cannot be reached",
        receipts=(
            StageReceipt(
                stage=StopStage.FREEZE,
                evidence_ref=f"fence/{RUN_ID}/1",
                detail="dispatch frozen",
                observed_at=MOMENT,
            ),
        ),
    )
    execution = StopExecution(record=record)
    assert execution.sealed is None
    assert execution.verdict is PostflightVerdict.UNKNOWN
    rendered = "\n".join(stop_cmd.render_stop_execution(execution))
    assert "postflight: none — this stop did not seal" in rendered
    assert "postflight verdict: UNKNOWN" in rendered
    assert "stalled at compensate_active" in rendered
    assert "the agent cannot be reached" in rendered
    assert "CLEAN" not in rendered


def test_the_worst_run_decides_the_verdict_of_a_whole_invocation() -> None:
    """One run that did not recover settles the answer for the invocation."""
    clean = SimpleNamespace(
        run_id="r-a", verdict=PostflightVerdict.CLEAN, recovered=True
    )
    dirty = SimpleNamespace(
        run_id="r-b", verdict=PostflightVerdict.DIRTY, recovered=False
    )
    outcome = stop_cmd.StopOutcome(
        scope=StopScope.ENVIRONMENT,
        command=stop_cmd.build_stop_command(
            scope=StopScope.ENVIRONMENT,
            environment="staging",
            principal=_principal(),
            reason=REASON,
            now=MOMENT,
        ),
        executions=(clean, dirty),  # type: ignore[arg-type]
    )
    assert outcome.verdict is PostflightVerdict.DIRTY
    assert outcome.recovered is False


def test_a_dry_run_never_reports_a_recovery_it_did_not_verify(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        outcome = stop_cmd.run_stop(
            store=store,
            principal=_principal(),
            scope=StopScope.RUN,
            reason=REASON,
            run_id=RUN_ID,
            dry_run=True,
            now=MOMENT,
        )
        assert outcome.dry_run is True
        assert outcome.executions == ()
        assert outcome.recovered is False
        assert outcome.verdict is PostflightVerdict.UNKNOWN
        # The preview mutated nothing, from inside the transaction as well.
        assert _lease_state(store, "l-1") == LeaseState.ACTIVE.value
        assert _fences(store) == []
        assert _ledger_rows(store, stop_cmd.STOP_ATTEMPT_KIND) == []
    finally:
        store.close()


def test_a_dry_run_environment_wide_stop_is_write_free_too(tmp_path: Path) -> None:
    """Every write in the invocation sits after the dry-run return, so a preview
    of the *broadest* scope records neither the ask nor a fence nor a lease."""
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        _granted(store, "u-ana", "staging", Role.EMERGENCY_STOP)
        outcome = stop_cmd.run_stop(
            store=store,
            principal=_principal(),
            scope=StopScope.ENVIRONMENT,
            reason=REASON,
            environment="staging",
            dry_run=True,
            now=MOMENT,
        )
        assert outcome.target_run_ids == (RUN_ID,)
        assert outcome.executions == ()
        assert _ledger_rows(store, stop_cmd.STOP_COMMAND_KIND) == []
        assert _ledger_rows(store, stop_cmd.STOP_ATTEMPT_KIND) == []
        assert _fences(store) == []
        assert _lease_state(store, "l-1") == LeaseState.ACTIVE.value
    finally:
        store.close()


def test_the_cli_dry_run_says_it_mutated_nothing(tmp_path: Path) -> None:
    db = tmp_path / "cli.db"
    store = _make_store(tmp_path, name="cli.db")
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
    finally:
        store.close()
    code, out, err = _run_main("--dry-run", "--db", str(db), "stop", RUN_ID, "--reason", REASON)
    assert code == int(ExitCode.SUCCESS), err
    assert "dry-run" in out
    assert "No run was stopped" in out
    assert "CLEAN" not in out
    store = _make_store(tmp_path, name="cli.db")
    try:
        assert _lease_state(store, "l-1") == LeaseState.ACTIVE.value
    finally:
        store.close()


# ==============================================================================
# Negative controls, each a named refusal
# ==============================================================================


def test_stopping_a_finished_run_is_rejected(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID, status="completed")
        SQLiteLeaseSink(store).save(_lease())
        with pytest.raises(InvariantViolationError) as excinfo:
            stop_cmd.run_stop(
                store=store,
                principal=_principal(),
                scope=StopScope.RUN,
                reason=REASON,
                run_id=RUN_ID,
                now=MOMENT,
            )
        assert "nothing to escalate" in str(excinfo.value)
        # Rejected, not silently accepted: the lease is untouched and nothing
        # was recorded.
        assert _lease_state(store, "l-1") == LeaseState.ACTIVE.value
        assert _ledger_rows(store, stop_cmd.STOP_ATTEMPT_KIND) == []
        assert _fences(store) == []
    finally:
        store.close()


def test_stopping_an_already_stopped_run_is_rejected(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        stop_cmd.run_stop(
            store=store,
            principal=_principal(),
            scope=StopScope.RUN,
            reason=REASON,
            run_id=RUN_ID,
            now=MOMENT,
        )
        ledger = stop_cmd.StoreStopLedger(store)
        assert ledger.seal(RUN_ID) is not None
        with pytest.raises(InvariantViolationError) as excinfo:
            stop_cmd.run_stop(
                store=store,
                principal=_principal(),
                scope=StopScope.RUN,
                reason=REASON,
                run_id=RUN_ID,
                now=MOMENT,
            )
        assert "stopped" in str(excinfo.value)
        assert "nothing to escalate" in str(excinfo.value)
        # Still one attempt on the record: the second stop added none.
        assert len(ledger.attempts(RUN_ID)) == 1
    finally:
        store.close()


def test_stopping_an_unknown_run_is_refused_before_anything_happens(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    try:
        with pytest.raises(MayhemCliError) as excinfo:
            stop_cmd.run_stop(
                store=store,
                principal=_principal(),
                scope=StopScope.RUN,
                reason=REASON,
                run_id="r-does-not-exist",
                now=MOMENT,
            )
        assert excinfo.value.code == "validation_error"
        assert "no such run" in excinfo.value.message
        assert _ledger_rows(store, stop_cmd.STOP_ATTEMPT_KIND) == []
    finally:
        store.close()


@pytest.mark.parametrize("reason", ("", "   ", "\t\n"))
def test_a_stop_with_no_reason_is_refused_as_unsealable(reason: str) -> None:
    with pytest.raises(MayhemCliError) as excinfo:
        stop_cmd.build_stop_command(
            scope=StopScope.RUN,
            run_id=RUN_ID,
            principal=_principal(),
            reason=reason,
            now=MOMENT,
        )
    refusal = excinfo.value
    assert refusal.code == "validation_error"
    assert "cannot be sealed" in refusal.message


def test_a_run_scoped_command_cannot_name_an_environment() -> None:
    with pytest.raises(InvariantViolationError):
        stop_cmd.build_stop_command(
            scope=StopScope.RUN,
            run_id=RUN_ID,
            environment="staging",
            principal=_principal(),
            reason=REASON,
            now=MOMENT,
        )


def test_the_cli_names_exactly_one_scope_or_it_is_a_usage_error() -> None:
    for argv in (
        ("stop", "--reason", REASON),
        ("stop", RUN_ID, "--environment", "staging", "--reason", REASON),
    ):
        code, _out, err = _run_main(*argv)
        assert code == int(ExitCode.USAGE_ERROR), argv
        assert "name exactly one scope" in err


def test_the_stop_record_is_written_where_a_second_stop_can_find_it(tmp_path: Path) -> None:
    """An emergency stop whose record went nowhere is the failure this prevents."""
    store = _make_store(tmp_path)
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
        stop_cmd.run_stop(
            store=store,
            principal=_principal(),
            scope=StopScope.RUN,
            reason=REASON,
            run_id=RUN_ID,
            now=MOMENT,
        )
        ledger = stop_cmd.StoreStopLedger(store)
        attempts = ledger.attempts(RUN_ID)
        assert len(attempts) == 1
        assert attempts[0].command.reason.value == "human"
        seal: SealedStop | None = ledger.seal(RUN_ID)
        assert seal is not None
        assert seal.report.stop_reason.value == "human"
        assert seal.verdict is PostflightVerdict.CLEAN
        # The freeze is a citable fence epoch, not a flag somebody set.
        freeze = attempts[0].receipts_for(StopStage.FREEZE)[0]
        assert freeze.evidence_ref.startswith(f"fence/{RUN_ID}/")
        assert _fences(store)
    finally:
        store.close()


# ==============================================================================
# What did NOT land, pinned so it cannot be quietly forgotten
# ==============================================================================


def test_the_run_path_still_has_no_preflight_gate_seam() -> None:
    """Why Phase 3 is still INCOMPLETE, asserted rather than asserted-in-prose.

    ``RunBudgetGuard`` reached the run path through one optional attach point
    (``with_budget_guard``) and one ``is not None`` block beside
    ``validate_plan``. The preflight gate has neither, so a refusal is reachable
    only by a caller who asks for one — and a refusal a caller has to remember to
    ask for is not a refusal in the run path. Binding it needs
    ``controller/executor.py`` and ``cli/execution.py``, which this work item
    does not own; the pin below is deleted by whoever adds the seam.
    """
    import inspect

    from mayhem.controller.executor import RunEngine

    assert not hasattr(RunEngine, "with_preflight_gate"), (
        "RunEngine gained a preflight-gate attach point: the Phase 3 STATUS line and this "
        "pin both have to be revisited, because the run-path wiring may now exist"
    )
    parameters = inspect.signature(RunEngine.__init__).parameters
    assert "preflight_gate" not in parameters, (
        "RunEngine now takes a preflight gate: bind it in cli/execution.py and update the "
        "Phase 3 ledger"
    )
    # And the additive contract the surface relies on is still intact: with no
    # gate, `admit` reads nothing at all.
    from mayhem.controller.preflight_gate import admit

    assert admit(None, granting_inputs(_plan(), ports=PreflightPorts())) is None


def _documented_stop_invocations() -> list[str]:
    """Every ``mayhem stop …`` invocation written in prose this lane owns."""
    sources = {
        "README.md": (ROOT / "README.md").read_text(encoding="utf-8"),
        "src/mayhem/cli/stop_cmd.py": (
            ROOT / "src/mayhem/cli/stop_cmd.py"
        ).read_text(encoding="utf-8"),
    }
    found: list[str] = []
    for _label, text in sources.items():
        for line in text.splitlines():
            if "mayhem stop" not in line:
                continue
            tail = line.split("mayhem stop", 1)[1]
            # Stop at the end of the sentence/row: a prose continuation is not
            # part of the invocation.
            argv = ("stop " + re.split(r"[.;|`]", tail.strip())[0].strip()).split()
            # `--help` is outside the release contract's stated validation
            # boundary (it documents the boundary it does not validate), so it is
            # not resolved here either — every other token is.
            found.append(" ".join(token for token in argv if token != "--help"))
    return [argv for argv in found if argv]


def test_every_stop_invocation_written_in_prose_resolves_against_the_cli() -> None:
    """Docstrings and the README row are checked against the live Click tree.

    Same resolver, same rules as ``test_readme_honesty.py`` uses for the
    documents it scans: command tokens by exact name or unique prefix, option
    tokens against the options declared on the node that consumes them, and the
    minimum arity each leaf requires. A flag documented but not declared fails
    here rather than in a user's terminal.
    """
    invocations = _documented_stop_invocations()
    assert invocations, "no stop invocation is documented at all"
    assert "stop" in invocations, "the README's CLI-surface row stopped naming the command"
    contract = _release_contract_module()
    problems = [
        (argv, contract._resolve_invocation(argv.split()))
        for argv in invocations
        if contract._resolve_invocation(argv.split())
    ]
    assert not problems, problems


def test_the_json_projection_is_valid_json_with_the_documented_keys(tmp_path: Path) -> None:
    db = tmp_path / "cli.db"
    store = _make_store(tmp_path, name="cli.db")
    try:
        _seed_run(store, RUN_ID)
        SQLiteLeaseSink(store).save(_lease())
    finally:
        store.close()
    code, out, err = _run_main("--db", str(db), "stop", RUN_ID, "--reason", REASON, "--json")
    assert code == int(ExitCode.SUCCESS), err
    payload = json.loads(out)
    assert payload["scope"] == "run"
    assert payload["reason"] == "human"
    assert payload["verdict"] == "clean"
    assert payload["exit_code"] == int(ExitCode.SUCCESS)
    assert payload["preflight"] is None
    row = payload["runs"][0]
    assert set(row) >= {
        "run_id",
        "verdict",
        "recovered",
        "sealed",
        "stages_completed",
        "open_residue_obligations",
        "checks",
    }
    assert row["stages_completed"] == [stage.value for stage in STOP_FLOW]


def test_the_stage_level_receipt_reference_helper_is_the_engines_own() -> None:
    """Evidence vocabulary is reused, not re-spelled in this module."""
    assert stage_ref(RUN_ID, StopStage.RESIDUE_SCAN) == f"run/{RUN_ID}/residue_scan"
