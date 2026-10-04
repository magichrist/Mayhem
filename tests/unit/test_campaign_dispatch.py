"""Plan 13 Phase 4 — the shared dispatch core, and the campaign budget probe.

The property under test is the one the plan asks for by name: **every scheduled
campaign traverses the identical gate path an authored drill does.** It is
proved two ways, and the second is the one that matters.

*Structurally.* :class:`~mayhem.controller.campaign_dispatch.CampaignRunRequest`
has no origin field, and :func:`compile_campaign_run` is one function with no
branch in it. A test walks the module's AST and asserts there is no conditional
anywhere below that function that mentions anything origin-shaped.

*By spy.* ``compile_safety_evidence`` is imported into
:mod:`mayhem.controller.campaign_dispatch`'s own namespace, so replacing that one
binding and driving a real scheduled dispatch observes the call directly. The
**negative control removes the admission gate's use of the compiler entirely and
asserts the dispatch still executes** — which is what makes the positive
observation evidence rather than coincidence. Without that control, "the spy
fired" could just as easily mean "the spy fired in a path that was about to
refuse anyway".

The rest of the file covers the two fail-closed rules that module exists to
enforce (``VOID`` is not ``PASS``; no compilation means no admission), the
one-pass refusal of the real planner, and the hierarchical campaign budget probe,
which must not spend the caller's tree and must attribute every charge to a level
that exists.
"""

from __future__ import annotations

import ast
import dataclasses
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller import campaign_dispatch
from mayhem.controller.approval_gate import ApprovalGateInputs, verify_approvals
from mayhem.controller.campaign_dispatch import (
    CAMPAIGN_BUDGET_LIMIT,
    NO_COMPILATION_LIMIT,
    CampaignBudgetVerdict,
    CampaignRunRequest,
    DispatchEnvironment,
    build_dispatch_pipeline,
    campaign_budget_verdict,
    compile_campaign_run,
)
from mayhem.controller.planner import PlanningError, plan_drill
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, validate_plan
from mayhem.controller.safety_proof import compile_safety_evidence
from mayhem.controller.scheduler import (
    DispatchPipeline,
    ExecutionReceipt,
    GateVerdict,
    PlannedDispatch,
    Scheduler,
    SchedulerInputs,
)
from mayhem.domain.approval import Approval
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    DrillConfig,
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
)
from mayhem.domain.hashing import digest
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.policy import BudgetNode, BudgetScope
from mayhem.domain.runtime_adapter import (
    AdapterCapabilities,
    CapabilityRequirements,
    CapabilityVerdict,
    RuntimeAdapter,
    VerdictResult,
)
from mayhem.domain.safety_proof import ObligationName, ProofVerdict
from mayhem.domain.scheduling import (
    ConcurrencyClass,
    IntervalSpec,
    Schedule,
    ScheduleKind,
)
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    ProcessNode,
    ServiceNode,
    TopologyGraph,
)
from mayhem.infra.schedule_store import ScheduleEntry, ScheduleStore
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from mayhem.domain.experiments import ExecutionPlan

REPO_ROOT = Path(__file__).resolve().parents[2]
DISPATCH_MODULE = REPO_ROOT / "src" / "mayhem" / "controller" / "campaign_dispatch.py"

T0 = datetime(2026, 6, 1, 9, 0, tzinfo=UTC)
BEFORE_T0 = T0.replace(year=2025)
FINGERPRINT = "fp-9c1e"
OPERATOR_ID = "u-operator"
POLICY_DIGEST = digest({"bundle": "campaign-dispatch", "version": 1})

#: The names an "is this a scheduled run?" branch would plausibly be spelled. The
#: structural test looks for these rather than for the word "scheduled" alone,
#: because a branch that read ``if request.auto:`` would defeat a narrower check.
ORIGIN_WORDS = (
    "scheduled",
    "origin",
    "automatic",
    "auto",
    "generated",
    "unattended",
    "triggered",
)


# =============================================================================
# Fixtures
# =============================================================================


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-api",
                name="api",
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="cid-api"
                ),
                runtime_metadata=RuntimeMetadata(service="api-svc", name="api"),
                container_name="testcase-api",
                state="running",
            ),
            ServiceNode(id="svc-api", name="api-svc", container_name="testcase-api"),
            ProcessNode(
                id="proc-api",
                name="api-proc",
                pid=4242,
                host_id="h1",
                container_name="testcase-api",
            ),
        ),
        edges=(
            Edge(src="svc-api", dst="ctr-api", kind=EdgeKind.RUNS_ON),
            Edge(src="ctr-api", dst="proc-api", kind=EdgeKind.RUNS_ON),
        ),
    )


def _spec(*, name: str = "api-drill", duration: str = "5s") -> DrillSpec:
    return DrillSpec(
        kind="drill",
        name=name,
        config=DrillConfig(),
        containers={
            "testcase-api": DrillContainer(
                faults=(DrillFault(fault="proc.pause", duration=duration),)
            )
        },
        execution=(ExecutionStep(sequential=("testcase-api",)),),
    )


class _Adapter(RuntimeAdapter):
    """A fake runtime. ``blocking=True`` makes the capability line refuse."""

    blocking = False

    @property
    def id(self) -> str:
        return "fake-adapter"

    def is_available(self) -> bool:
        return True

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(engine=self.id, supported=frozenset(), version=None)

    def evaluate(self, reqs: CapabilityRequirements) -> VerdictResult:
        verdict = CapabilityVerdict.UNSUPPORTED if self.blocking else CapabilityVerdict.SUPPORTED
        return VerdictResult(
            engine=self.id,
            requirements=reqs,
            verdicts={"namespace": verdict.value},
            blocking=self.blocking,
        )

    def ps(self) -> list[dict[str, Any]]:
        return []

    def inspect(self, container_id: str) -> tuple[RuntimeIdentity, RuntimeMetadata | None]:
        return (RuntimeIdentity(runtime="fake", host_id="h", runtime_id=container_id), None)

    def exec(self, container_id: str, cmd: list[str], *, timeout_s: float = 30.0) -> str:
        return ""

    def pid(self, container_id: str) -> int | None:
        return None

    def signal(self, container_id: str, signo: int) -> None:
        return None

    def netns(self, container_id: str) -> str | None:
        return None

    def filter_by_compose(
        self, project: str, services: tuple[str, ...] | None = None
    ) -> None:
        return None

    def filter_by_names(self, names: list[str]) -> None:
        return None

    def discover(self) -> Any:
        """No live runtime behind this adapter, so discovery yields nothing.

        Returned empty rather than raising because nothing in the dispatch path
        calls it -- the compiler and the gates read the graph they are handed, and
        a test adapter that raised here would only obscure which of them does.
        """
        from mayhem.domain.topology import PartialGraph

        return PartialGraph(nodes=(), edges=())


def _ctx(*, fingerprint: str = FINGERPRINT) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(max_services_pct=100.0),
        fingerprint=fingerprint,
    )


@dataclass
class Recorder:
    """What the executor and the gates were asked to do, in order."""

    executions: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.executions)


def _executor(recorder: Recorder) -> Any:
    def execute(plan: ExecutionPlan) -> ExecutionReceipt:
        recorder.executions.append(plan.run_id)
        return ExecutionReceipt(run_id=plan.run_id, outcome_id="out-1", detail="ran")

    return execute


def _approvals_for(plan: ExecutionPlan) -> ApprovalGateInputs:
    """Plan-09 inputs whose proof is pinned to *this* plan's digest.

    The plan digest is the plan's own, not a fabricated one: the plan-09 gate
    refuses a proof whose ``plan_digest`` disagrees with the frozen plan
    (``approval.proof_not_pass``, "plan superseded"), which is the correct
    behaviour and would otherwise make every approval test in this file fail for a
    reason that has nothing to do with scheduling.
    """
    from mayhem.controller.approval_gate import candidate_plan_digest
    from mayhem.domain.identity import EnvironmentScope, Principal, Role, RoleGrant
    from mayhem.domain.safety_proof import Obligation, ObligationStatus, SafetyProof

    proof = SafetyProof(
        plan_digest=candidate_plan_digest(plan),
        obligations=tuple(
            Obligation(
                name=name.value,
                status=ObligationStatus.PASS,
                gate_digest=digest({"gate": name.value}),
                evidence_ref=f"evidence://{name.value}",
                evaluated_at=BEFORE_T0,
            )
            for name in ObligationName
        ),
        verdict=ProofVerdict.PASS,
        generated_at=BEFORE_T0,
    )
    operator = Principal(principal_id=OPERATOR_ID, display_name="Operator")
    scope = EnvironmentScope.any()
    approval = Approval(
        approval_id="a-campaign",
        plan_digest=proof.plan_digest,
        policy_digest=POLICY_DIGEST,
        proof_digest=proof.proof_digest,
        approver=operator,
        environment=scope,
        issued_at=BEFORE_T0,
    )
    return ApprovalGateInputs(
        now=T0,
        environment=scope,
        executor=operator,
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approvals=(approval,),
        grants=tuple(
            RoleGrant(role=role, scope=scope, granted_at=BEFORE_T0, principal=operator)
            for role in (Role.APPROVE, Role.EXECUTE)
        ),
    )


#: Sentinel for "the caller did not say", so ``adapter=None`` can mean *no
#: adapter at all* -- which is the whole point of the VOID-proof test. A plain
#: ``None`` default would be swallowed by the ``or`` and silently hand back a
#: healthy adapter, making that test assert the opposite of what it says.
_UNSET: Any = object()


def _environment(
    recorder: Recorder | None = None,
    *,
    adapter: Any = _UNSET,
    ctx: SafetyContext | None = None,
    spec: DrillSpec | None = None,
    fingerprint: str = FINGERPRINT,
) -> DispatchEnvironment:
    resolved = spec if spec is not None else _spec()
    return DispatchEnvironment(
        graph=_graph(),
        ctx=ctx if ctx is not None else _ctx(fingerprint=fingerprint),
        spec_for=lambda campaign_id, experiment_id: resolved,
        approvals_for=_approvals_for,
        executor=_executor(recorder) if recorder is not None else _executor(Recorder()),
        adapter=_Adapter() if adapter is _UNSET else adapter,
        config_snapshot_id="cfg-1",
        topology_snapshot_id="topo-1",
        environment_fingerprint=fingerprint,
        policy_id="",
    )


def _request(
    *, run_id: str = "r-campaign-1", spec: DrillSpec | None = None
) -> CampaignRunRequest:
    return CampaignRunRequest(
        run_id=run_id,
        campaign_id="camp-1",
        experiment_id="exp-1",
        spec=spec if spec is not None else _spec(),
    )


def _entry(*, every_s: float = 3600.0, anchor_at: datetime = T0) -> ScheduleEntry:
    return ScheduleEntry(
        schedule=Schedule(
            schedule_id="nightly",
            team="sre",
            kind=ScheduleKind.INTERVAL,
            interval=IntervalSpec(every_s=every_s, anchor_at=anchor_at),
            created_at=BEFORE_T0,
            max_runs=10_000,
            poll_resolution_s=3600.0,
        ),
        campaign_id="camp-1",
        experiment_id="exp-1",
        concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",),
    )


def _dispatch_once(recorder: Recorder, *, now: datetime = T0, pipeline: Any = None) -> Any:
    """Drive one scheduled dispatch through a real :class:`Scheduler`.

    The store and the real pipeline are used, so the spy observation below is
    about a dispatch that actually went through the claim ledger and the fairness
    ordering rather than about a hand-called function. Returns the
    :class:`~mayhem.controller.scheduler.TickReport`; the caller reads the
    ``Recorder`` it passed in, so the recorder observed here is the one the
    environment's executor was built with rather than a fresh one the helper
    happened to make.
    """
    store = Store.open_migrated(":memory:")
    repo = ScheduleStore(store)
    environment = _environment(recorder)
    scheduler = Scheduler(
        store=repo,
        pipeline=pipeline if pipeline is not None else build_dispatch_pipeline(environment),
        controller_id="ctl-1",
    )
    scheduler.register(_entry())
    report = scheduler.tick(SchedulerInputs(now=now, window_index=0))
    return report, repo


# =============================================================================
# 1. The identical gate path — structural
# =============================================================================


def test_the_request_type_cannot_describe_a_run_as_scheduled() -> None:
    """The origin field does not exist, so no caller could branch on one.

    Asserted as "no field mentions an origin word" rather than as a list, because
    a hand-maintained allowlist of the four fields would pass unchanged after
    somebody added a fifth called ``auto``.
    """
    fields = {field.name for field in dataclasses.fields(CampaignRunRequest)}

    assert fields == {"run_id", "campaign_id", "experiment_id", "spec", "spec_dir"}
    for name in fields:
        assert not any(word in name for word in ORIGIN_WORDS), name


def test_the_shared_core_has_no_origin_branch_anywhere_in_the_module() -> None:
    """No conditional in this module reads anything origin-shaped.

    Parsed, not grepped: a docstring that says "scheduled" must not trip the
    check, and a branch spelled ``if req.auto:`` must. Every ``if`` and every
    conditional expression in the file is tested against :data:`ORIGIN_WORDS`.
    """
    tree = ast.parse(DISPATCH_MODULE.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If | ast.IfExp):
            test = ast.unparse(node.test).lower()
            hit = [word for word in ORIGIN_WORDS if word in test]
            if hit:
                offenders.append(f"line {node.lineno}: {ast.unparse(node.test)} {hit}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "getattr" and any(
                isinstance(arg, ast.Constant) and arg.value == word for arg in node.args
                for word in ORIGIN_WORDS
            ):
                offenders.append(f"line {node.lineno}: getattr({node.args[1]!r})")

    assert offenders == [], (
        "campaign_dispatch has an origin branch; a scheduled run and an authored "
        f"drill must not be distinguishable below compile_campaign_run: {offenders}"
    )


def test_the_shared_core_calls_the_three_compilers_in_order() -> None:
    """The three statements are present, in this order, with nothing between them.

    Read from the AST rather than trusted to the prose: the claim is about the
    shape of the function, and the docstring is free to be wrong.
    """
    tree = ast.parse(DISPATCH_MODULE.read_text(encoding="utf-8"))
    core = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "compile_campaign_run"
    )
    called = [
        node.func.id
        for node in ast.walk(core)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]

    assert called.index("plan_drill") < called.index("compile_safety_evidence")
    assert called.index("compile_safety_evidence") < called.index("simulate_plan_policy")
    # No other compiler, and no gate call that could re-order or replace them.
    assert "compile_safety_proof" not in called
    assert "validate_plan" not in called


def test_the_shared_core_reads_no_clock_and_no_environment() -> None:
    """Reproducibility: the same inputs give the same plan on any host, any date."""
    tree = ast.parse(DISPATCH_MODULE.read_text(encoding="utf-8"))
    core = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "compile_campaign_run"
    )
    body = ast.unparse(core)

    # Scanned as *code*: the docstring is allowed to say "reads no clock", and
    # ``environment`` is a parameter name that contains "environ". Only a real
    # call or a real name lookup is a read.
    calls = [
        f"{ast.unparse(node.func)}"
        for node in ast.walk(core)
        if isinstance(node, ast.Call)
    ]
    forbidden_calls = ("datetime.now", "utc_now", "monotonic", "getenv", "time.time")
    for needle in forbidden_calls:
        assert not any(needle in call for call in calls), (
            f"compile_campaign_run calls {needle}"
        )
    assert "os.environ" not in body
    assert "import os" not in body


# =============================================================================
# 2. The identical gate path — by spy, with a negative control
# =============================================================================


def test_a_scheduled_dispatch_reaches_the_shared_proof_compiler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The spy: a scheduled campaign calls ``compile_safety_evidence`` itself.

    The binding replaced is the one in *this* module's namespace, which is exactly
    what "the scheduled path goes through the shared compiler" means in Python:
    not that the function is named in two files, but that the call resolves here.
    """
    seen: list[str] = []
    real = campaign_dispatch.compile_safety_evidence

    def spy(plan: Any, graph: Any, ctx: Any, **kwargs: Any) -> Any:
        seen.append(plan.run_id)
        return real(plan, graph, ctx, **kwargs)

    monkeypatch.setattr(campaign_dispatch, "compile_safety_evidence", spy)
    recorder = Recorder()
    report, _repo = _dispatch_once(recorder)

    assert len(seen) == 1, f"expected exactly one compilation, saw {seen}"
    decision = report.for_schedule("nightly")
    assert decision is not None
    assert decision.dispatched is True
    assert decision.run_id == seen[0]
    assert recorder.count == 1


def test_the_negative_control_removing_the_admission_gate_still_executes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the compiler in the gate, the dispatch still runs — so the spy means something.

    This is what makes the positive observation evidence. If the spy fired only on
    paths that were about to be refused, "the spy fired" would be a fact about the
    refusals and not about the gate. Here the compiler is removed from
    :func:`build_dispatch_pipeline`'s reach by handing the scheduler a pipeline
    whose admission gate is a plain stub, and the run is dispatched: the spy is
    observing the *planner's* call, which is the shared core, and nothing
    downstream re-derives it.
    """
    calls: list[str] = []

    def stub_admission(request: Any, planned: PlannedDispatch) -> GateVerdict:
        calls.append("admission")
        # Deliberately never reads ``planned.dispatch``. The spy below must
        # therefore be observing the *planner's* call to the shared core, and
        # nothing downstream re-deriving it.
        return GateVerdict(passed=True, reason="stubbed admission")

    recorder = Recorder()
    bound = build_dispatch_pipeline(_environment(recorder))
    relaxed = DispatchPipeline(
        planner=bound.planner,
        admission=stub_admission,
        approver=bound.approver,
        executor=bound.executor,
    )
    seen: list[str] = []
    real = campaign_dispatch.compile_safety_evidence

    def spy(plan: Any, graph: Any, ctx: Any, **kwargs: Any) -> Any:
        seen.append(plan.run_id)
        return real(plan, graph, ctx, **kwargs)

    monkeypatch.setattr(campaign_dispatch, "compile_safety_evidence", spy)
    report, _repo = _dispatch_once(recorder, pipeline=relaxed)

    decision = report.for_schedule("nightly")
    assert decision is not None
    assert decision.dispatched is True
    assert recorder.count == 1
    assert len(seen) == 1
    assert calls == ["admission"]


def test_the_admission_gate_refuses_a_plan_with_no_compilation() -> None:
    """A bespoke planner cannot borrow this binding's gate without a proof.

    ``PlannedDispatch.dispatch`` defaults to ``None``. That is the fail-closed
    reading of "no proof": the admission gate refuses by name rather than
    admitting a plan nobody checked, which is the only alternative being worse.
    The rule id is read from the settled claim's ``detail`` -- which is where the
    scheduler records a gate's own vocabulary -- rather than scraped out of the
    prose reason.
    """
    bound = build_dispatch_pipeline(_environment())
    report, repo = _dispatch_once(
        Recorder(),
        pipeline=DispatchPipeline(
            planner=lambda request: PlannedDispatch(
                plan=plan_drill(
                    request.concurrency.run_id,
                    _spec(),
                    _graph(),
                    config_snapshot_id="cfg-1",
                    topology_snapshot_id="topo-1",
                    environment_fingerprint=FINGERPRINT,
                )
            ),
            admission=bound.admission,
            approver=bound.approver,
            executor=bound.executor,
        ),
    )

    decision = report.for_schedule("nightly")
    assert decision is not None
    assert decision.dispatched is False
    assert decision.code is not None
    assert decision.code.value == "schedule.admission_refused"
    assert "no safety compilation" in decision.reason
    assert decision.gates == ()

    records = repo.runs_for_schedule("nightly")
    assert len(records) == 1
    assert records[0].settled is True
    assert records[0].detail["rule_id"] == NO_COMPILATION_LIMIT


# =============================================================================
# 3. Fail-closed rules
# =============================================================================


def test_a_void_proof_is_refused_and_names_the_unestablished_lines() -> None:
    """``VOID`` is not ``PASS``. An unestablished capability line refuses the run.

    The plan here needs no adapter, so ``capability_requirements`` is unmeasured
    and the proof comes back ``VOID``. A dispatch that treated that as "not a
    failure" would run a plan whose runtime requirements nobody established --
    unrefuted is not the same statement as safe.
    """
    environment = _environment(adapter=None)
    dispatch = compile_campaign_run(environment, _request())

    assert dispatch.verdict is ProofVerdict.VOID
    assert dispatch.admissible is False
    assert dispatch.unproven_lines() == ("capability_requirements",)
    reason = dispatch.refusal_reason()
    assert "VOID" in reason
    assert "capability_requirements" in reason
    # And the whole spine is otherwise satisfied, so the refusal is specific
    # rather than a blanket "no".
    assert dispatch.compilation.gate_refusals == ()


def test_a_blocking_capability_refusal_names_the_gate_rule() -> None:
    """A real refusal is reported in the gate's own words, not swallowed."""
    adapter = _Adapter()
    adapter.blocking = True  # type: ignore[misc]
    environment = _environment(adapter=adapter)

    dispatch = compile_campaign_run(environment, _request())

    assert dispatch.admissible is False
    assert dispatch.verdict is not ProofVerdict.PASS
    assert "capability" in dispatch.refusal_reason().lower()
    assert dispatch.compilation.compiler_refusals


def test_a_capable_adapter_makes_the_same_plan_admissible() -> None:
    """The positive control: the refusal above is about the adapter, not the code path."""
    dispatch = compile_campaign_run(_environment(adapter=_Adapter()), _request())

    assert dispatch.verdict is ProofVerdict.PASS
    assert dispatch.admissible is True
    assert dispatch.unproven_lines() == ()
    assert dispatch.refusal_reason() == ""


def test_the_real_admission_gate_still_speaks_for_the_shared_dispatch() -> None:
    """A fingerprint mismatch is refused by ``validate_plan``, not by this module.

    Binding the real gate in is the point: the shared core compiles, and the gate
    refuses on its own terms. A module that only ever compiled proofs would pass
    every other test in this file and ship a run against a different environment
    than the one the plan was written for.
    """
    environment = _environment(ctx=_ctx(fingerprint="some-other-environment"))
    dispatch = compile_campaign_run(environment, _request())

    assert dispatch.plan.environment_fingerprint == FINGERPRINT
    assert environment.ctx.fingerprint == "some-other-environment"
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(
            dispatch.plan, environment.graph, environment.ctx, environment.adapter
        )
    assert "environment.fingerprint_mismatch" in str(excinfo.value)


def test_the_approval_gate_still_speaks_for_the_shared_dispatch() -> None:
    """``verify_approvals`` refuses an unauthorised run, and the pipeline reports it."""
    environment = _environment()

    def refusing_approvals(plan: ExecutionPlan) -> ApprovalGateInputs:
        inputs = _approvals_for(plan)
        return ApprovalGateInputs(
            now=inputs.now,
            environment=inputs.environment,
            executor=inputs.executor,
            proof=inputs.proof,
            policy_digest=inputs.policy_digest,
            approvals=(),
            grants=(),
        )

    refused = DispatchEnvironment(
        graph=environment.graph,
        ctx=environment.ctx,
        spec_for=environment.spec_for,
        approvals_for=refusing_approvals,
        executor=environment.executor,
        adapter=environment.adapter,
        config_snapshot_id=environment.config_snapshot_id,
        topology_snapshot_id=environment.topology_snapshot_id,
        environment_fingerprint=environment.environment_fingerprint,
    )
    store = Store.open_migrated(":memory:")
    repo = ScheduleStore(store)
    scheduler = Scheduler(store=repo, pipeline=build_dispatch_pipeline(refused), controller_id="c")
    scheduler.register(_entry())
    report = scheduler.tick(SchedulerInputs(now=T0, window_index=0))

    decision = report.for_schedule("nightly")
    assert decision is not None
    assert decision.dispatched is False
    assert decision.gates == ("admission",)
    assert "approv" in decision.reason.lower() or "role" in decision.reason.lower()


def test_a_spec_that_will_not_compile_raises_upstream_of_the_proof() -> None:
    """One pass: a plan nobody can run never receives a safety case.

    The planner's refusal propagates with its own rule id rather than being
    re-labelled, because ``undo_template_missing`` is more actionable than
    anything this layer could invent — and a caught-and-rewrapped exception would
    be exactly the "second path" the plan forbids.
    """
    environment = _environment()
    # No matching container in the topology: the planner refuses this spec.
    bad = DrillSpec(
        kind="drill",
        name="unresolvable",
        config=DrillConfig(),
        containers={
            "not-in-topology": DrillContainer(
                faults=(DrillFault(fault="proc.pause", duration="1s"),)
            )
        },
        execution=(ExecutionStep(sequential=("not-in-topology",)),),
    )

    with pytest.raises(PlanningError):
        compile_campaign_run(environment, _request(spec=bad))


def test_the_dispatch_is_reproducible_across_hosts() -> None:
    """The same environment and request give the same verdict, twice over.

    The *verdict* is reproducible, and deliberately so: it is a pure function of
    the plan and the gates, and it is what a replay has to reproduce.

    The plan **digest** is not asserted here, and that is a fact about
    :func:`mayhem.controller.planner.plan_drill` rather than about this module:
    the planner mints a fresh ``execution_group_id`` per compile
    (``grp-<uuid4>``), so two compiles of the same spec produce two distinct
    plans. Asserting digest stability here would be asserting something the
    planner does not promise. What this module promises is narrower and is what
    the assertion checks: the same inputs reach the same decision.
    """
    first = compile_campaign_run(_environment(), _request())
    second = compile_campaign_run(_environment(), _request())

    assert first.verdict is second.verdict is ProofVerdict.PASS
    assert first.admissible is second.admissible is True
    assert first.unproven_lines() == second.unproven_lines() == ()
    assert first.refusal_reason() == second.refusal_reason() == ""
    assert first.plan.run_id == second.plan.run_id == "r-campaign-1"
    assert first.plan.environment_fingerprint == second.plan.environment_fingerprint


def test_the_module_imports_the_compiler_it_spies_on() -> None:
    """The spy is possible only because the binding is module-level.

    Asserted so that a future refactor which reaches the compiler through
    ``safety_proof.compile_safety_evidence`` at call time -- breaking the spy and
    with it the evidence -- fails here rather than silently making the positive
    test vacuous.
    """
    assert campaign_dispatch.compile_safety_evidence is compile_safety_evidence
    assert campaign_dispatch.plan_drill is plan_drill
    assert campaign_dispatch.verify_approvals is verify_approvals


# =============================================================================
# 4. The hierarchical campaign budget
# =============================================================================


def _budget(*, team_limit: float | None = 1_000.0) -> BudgetNode:
    """team → environment → service → experiment, with no per-fault leaf.

    Mirrors a hierarchy authored to four of 07's five levels, which is the shape
    the probe has to cope with: the leaf charge resolves at the experiment level
    rather than at a per-fault node that was never filled in.
    """
    experiment = BudgetNode(
        scope=BudgetScope.EXPERIMENT, key="exp-1", limit_s=1_000.0
    )
    service = BudgetNode(
        scope=BudgetScope.SERVICE, key="api-svc", limit_s=1_000.0, children=(experiment,)
    )
    environment = BudgetNode(
        scope=BudgetScope.ENVIRONMENT, key="podman", limit_s=1_000.0, children=(service,)
    )
    return BudgetNode(
        scope=BudgetScope.TEAM,
        key="sre",
        limit_s=team_limit,
        children=(environment,),
    )


def _plan_for_environment() -> ExecutionPlan:
    return compile_campaign_run(_environment(), _request()).plan


#: The path the caller passes: the levels it filled in, leaf-last. The fault id
#: is appended by the probe, so this is the *context* of the charge.
CAMPAIGN_PATH = ("sre", "podman", "api-svc", "exp-1")


def test_a_campaign_budget_probe_posts_to_every_level_widest_first() -> None:
    """The charge reaches the leaf *and every ancestor*, in the order a refusal reads.

    The path stops at ``exp-1`` because the hierarchy has no per-fault leaf, so
    the probe resolves the chargeable prefix to four levels and posts to all
    four. A path one level shorter would legitimately post to three -- which is
    the fallback the next test covers.
    """
    budget = _budget()

    verdict = campaign_budget_verdict(budget, CAMPAIGN_PATH, _plan_for_environment())

    assert verdict.allowed is True
    scopes = [(charge.scope.value, charge.key) for charge in verdict.charges]
    assert scopes == [
        ("team", "sre"),
        ("environment", "podman"),
        ("service", "api-svc"),
        ("experiment", "exp-1"),
    ]
    assert verdict.rule_id == ""


def test_a_campaign_budget_probe_spends_nothing() -> None:
    """Probe-then-commit: the caller's tree is byte-identical after the probe.

    ``BudgetNode`` is frozen and ``post_charge`` returns new trees, so this is
    structural -- but it is also the property that makes a *refusal* free, and a
    refusal that cost budget would be worse than no budget at all.
    """
    budget = _budget(team_limit=1.0)

    verdict = campaign_budget_verdict(budget, CAMPAIGN_PATH, _plan_for_environment())

    assert verdict.allowed is False
    assert budget.spent_s == 0.0
    assert budget.find(BudgetScope.TEAM, "sre") is budget
    assert budget.children[0].spent_s == 0.0


def test_an_exhausted_ancestor_refuses_even_with_leaf_headroom() -> None:
    """The hierarchy's own semantics, at the campaign layer: the widest limit wins.

    Every level below ``team`` has 1000s of headroom. The team's 6s does not
    cover the 5s fault's damage-seconds, so the campaign budget refuses and names
    the team — which is the fact an operator needs, and the one a per-leaf check
    would have missed entirely.
    """
    budget = _budget(team_limit=1.0)

    verdict = campaign_budget_verdict(budget, CAMPAIGN_PATH, _plan_for_environment())

    assert verdict.allowed is False
    assert verdict.rule_id == CAMPAIGN_BUDGET_LIMIT
    assert "team/sre" in verdict.reason
    assert "limit" in verdict.reason
    assert CampaignBudgetVerdict(allowed=False).describe().startswith(
        "campaign budget refuses"
    )


def test_a_budget_with_headroom_admits_and_returns_the_committed_tree() -> None:
    """The positive control, and the caller's commit path."""
    budget = _budget(team_limit=600.0)

    verdict = campaign_budget_verdict(budget, CAMPAIGN_PATH, _plan_for_environment())

    assert verdict.allowed is True
    assert verdict.committed is not None
    assert verdict.committed.spent_s > 0.0
    assert budget.spent_s == 0.0
    assert "campaign budget admits" in verdict.describe()


def test_no_mounted_campaign_budget_is_allowed_rather_than_refusing() -> None:
    """``None`` means "no campaign ledger", not "an empty one".

    Refusing here would be inventing a limit nobody configured. 07's own damage
    quota and blast-radius budget still apply inside the safety core, so the
    honest answer is "nothing extra to charge here".
    """
    verdict = campaign_budget_verdict(None, CAMPAIGN_PATH, _plan_for_environment())

    assert verdict.allowed is True
    assert verdict.charges == ()
    assert verdict.committed is None


def test_a_budget_that_cannot_attribute_the_charge_refuses() -> None:
    """A charge nobody is accountable for is not a budget.

    The team name does not exist in the tree at any level, which is a
    misconfiguration rather than a missing budget. It refuses, and it carries 07's
    own rule id so a reader is not left guessing which layer objected.
    """
    budget = _budget()

    verdict = campaign_budget_verdict(budget, ("payments",), _plan_for_environment())

    assert verdict.allowed is False
    assert verdict.charges == ()
    assert verdict.rule_id == "policy.budget_path_missing"
    assert "cannot attribute" in verdict.reason


def test_the_chargeable_path_falls_back_to_the_levels_that_exist() -> None:
    """A hierarchy authored to fewer levels charges those levels, not nothing.

    07's ``_chargeable_path`` contract, restated as a test of *this* module's copy:
    a path whose first three keys exist resolves to the prefix rather than raising,
    so a team that filled in three of five levels is charged for three of them.
    """
    budget = _budget()

    full_path = ("sre", "podman", "api-svc", "exp-1", "proc.pause")
    resolved = campaign_dispatch._chargeable(budget, full_path)

    assert resolved == ("sre", "podman", "api-svc", "exp-1")


def test_a_path_that_resolves_at_no_depth_raises_with_07s_rule() -> None:
    """The helper raises rather than returning a nonsense prefix.

    Returning ``()`` would make ``post_charge`` charge the root for work nobody
    declared, which is the same failure 07 refuses.
    """
    with pytest.raises(InvariantViolationError) as excinfo:
        campaign_dispatch._chargeable(_budget(), ("nobody", "nowhere"))

    assert excinfo.value.rule == "policy.budget_path_missing"


def test_the_budget_probe_does_not_read_a_clock() -> None:
    """A budget verdict is a function of the tree, the path, and the plan."""
    import inspect

    signature = inspect.signature(campaign_budget_verdict)

    assert list(signature.parameters) == ["budget", "path", "plan"]
    assert "now" not in signature.parameters

