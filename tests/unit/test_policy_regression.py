"""Plan 07 Phase 5 — the regression suite the plan names, at admission.

Phase 5's acceptance is a list of *cases*: forbidden-pair regression (3+ fault
plans, the historical inertness case), quota and budget, lock contention (two
experiments, one ``postgres-primary``, the second queues with the lock owner
named), the two negative controls (an expired policy version cannot authorize
a run; a lock held by a dead run is fenced, never inherited), and simulation
covered by tests asserting no mutation occurred.

The other policy suites unit-test the pieces — the vocabulary
(``test_policy_bundle``), the gate function (``test_policy_gate``), the sealing
(``test_policy_evidence``). This suite asserts the cases the plan names the way
a run meets them: through ``validate_plan``, the real admission path, where the
policy gate runs before the per-step loop and a refusal raises
``SafetyRefusedError``. A case proven only against ``evaluate_gate`` would not
notice if admission stopped calling it.

Two groups reach beyond the other suites on purpose:

* **The budget commit path.** ``commit_budget`` is the posting half Phase 4
  recorded as missing — probe-then-post, judged after every append. When this
  phase opened, nothing in ``src/`` called it and no test in the tree named it,
  so its docstring's claims (charge-then-judge, byte-identical refusal,
  unmounted posts nothing, malformed refuses without posting) were prose. They
  are asserted here.
* **The historical inertness case through admission.** ``test_damage_quota``
  proves the old one-big-set bug fixed at ``check_blast_radius``; this suite
  proves a run carrying the same three-fault plan through ``validate_plan``
  with a policy bundle mounted is still refused.

Every input is explicit, including the clock: ``PolicyGateInputs`` has no
default for ``now`` precisely so a test cannot smuggle one in.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, validate_plan
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.policy import (
    BudgetLedgerEntry,
    BudgetNode,
    BudgetScope,
    CompatibilityCondition,
    CompatibilityEdge,
    CompatibilityVerdict,
    PolicyBundle,
    PolicyDimension,
    PolicyEffect,
    ResourceLock,
)
from mayhem.domain.policy_gate import (
    RULE_BUDGET_EXHAUSTED,
    RULE_BUNDLE_EXPIRED,
    RULE_COMPAT_CONFLICT,
    RULE_LOCK_CONTENDED,
    RULE_POLICY_CONFIG,
    MutationSink,
    PolicyGateInputs,
    check_locks,
    commit_budget,
    evaluate_gate,
    persisted_budget,
    simulate_gate,
)
from mayhem.domain.quota import DamageQuota
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
BEFORE = T0 - timedelta(hours=1)
AFTER = T0 + timedelta(hours=1)
STEP_S = 5.0

#: Where this run sits in the five-level budget hierarchy. The gate appends the
#: fault id for the leaf.
BUDGET_PATH = ("sre", "production", "web", "exp-1")

#: The plan's own historical case: a forbidden pair whose members are never
#: adjacent, so the pre-1.0.0 rule — one big set of every fault plus the new
#: one — matched nothing on a three-fault plan.
INERT_PAIR = frozenset({"net.latency", "net.packet_loss"})
INERT_PLAN = ("net.latency", "dns.servfail", "net.packet_loss")


# -- fixtures -----------------------------------------------------------------------


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-web", name="web"),
            ServiceNode(id="n-api", name="api"),
        ),
        edges=(Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
    )


def _plan(*fault_ids: str, duration: float = STEP_S, run_id: str = "run-1") -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="web")
    steps = tuple(
        PlannedStep(
            id=f"s{seq}",
            seq=seq,
            raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=duration),
            fault=PlannedFault(
                fault_id=fault_id,
                targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-web"})),),
                duration=duration,
            ),
        )
        for seq, fault_id in enumerate(fault_ids)
    )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=steps,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def _bundle(
    *rules: object,
    default: PolicyEffect = PolicyEffect.ALLOW,
    expires_at: datetime | None = None,
    edges: tuple[CompatibilityEdge, ...] = (),
) -> PolicyBundle:
    return PolicyBundle(
        bundle_id="phase5-test",
        version=1,
        rules=rules,  # type: ignore[arg-type]
        compatibility_edges=edges,
        default_effect=default,
        created_at=T0 - timedelta(days=1),
        expires_at=expires_at,
    )


def _inputs(
    bundle: PolicyBundle | None = None, *, now: datetime = T0, **kwargs: object
) -> PolicyGateInputs:
    return PolicyGateInputs(bundle=bundle or _bundle(), now=now, **kwargs)  # type: ignore[arg-type]


def _permissive() -> BlastRadiusBudget:
    """Per-step caps no plan in this file should trip, so a refusal has one cause."""
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(),
    )


def _pairing_budget(*pairs: frozenset[str]) -> BlastRadiusBudget:
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(pairs),
    )


def _ctx(
    gate: PolicyGateInputs | None = None,
    *,
    budget: BlastRadiusBudget | None = None,
    **kwargs: object,
) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=budget or _permissive(),
        fingerprint="f",
        policy_gate=gate,
        **kwargs,  # type: ignore[arg-type]
    )


def _refusal(plan: ExecutionPlan, ctx: SafetyContext):
    """Run admission and return the decision it refused with."""
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(plan, _graph(), ctx)
    decision = excinfo.value.decision
    assert decision is not None
    return decision


def _budget_tree(
    leaf_limit: float, *fault_ids: str, path: tuple[str, ...] = BUDGET_PATH
) -> BudgetNode:
    """A full five-level budget; only the per-fault leaves carry a tight limit."""
    team, environment, service, experiment = path
    leaves = tuple(
        BudgetNode(scope=BudgetScope.FAULT, key=fault_id, limit_s=leaf_limit)
        for fault_id in fault_ids
    )
    return BudgetNode(
        scope=BudgetScope.TEAM,
        key=team,
        limit_s=1e6,
        children=(
            BudgetNode(
                scope=BudgetScope.ENVIRONMENT,
                key=environment,
                limit_s=1e6,
                children=(
                    BudgetNode(
                        scope=BudgetScope.SERVICE,
                        key=service,
                        limit_s=1e6,
                        children=(
                            BudgetNode(
                                scope=BudgetScope.EXPERIMENT,
                                key=experiment,
                                limit_s=1e6,
                                children=leaves,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )


def _lock(
    *,
    lock_id: str = "exp-a-run-a-postgres-primary",
    resource: str = "postgres-primary",
    experiment_id: str = "exp-a",
    owner_run_id: str = "run-a",
    acquired_at: datetime = BEFORE,
    expires_at: datetime = AFTER,
) -> ResourceLock:
    return ResourceLock(
        lock_id=lock_id,
        resource=resource,
        experiment_id=experiment_id,
        owner_run_id=owner_run_id,
        acquired_at=acquired_at,
        expires_at=expires_at,
        reason="experiment a holds the primary",
    )


class _MemoryLedger:
    """An in-memory ``HierarchicalBudgetLedger``: append-only, read-back-able."""

    def __init__(self) -> None:
        self._entries: list[BudgetLedgerEntry] = []

    def append(self, entry: BudgetLedgerEntry) -> None:
        self._entries.append(entry)

    def entries(self) -> tuple[BudgetLedgerEntry, ...]:
        return tuple(self._entries)


# -- forbidden pairs: the historical inertness case, through admission --------------


def test_forbidden_pair_refuses_a_three_fault_plan_at_admission() -> None:
    # The pair completes on the third step with its members adjacent — the
    # shape the pre-1.0.0 rule accidentally got right on two-fault plans only.
    plan = _plan("dns.servfail", "net.latency", "net.packet_loss")
    ctx = _ctx(
        _inputs(),
        budget=_pairing_budget(INERT_PAIR),
    )
    decision = _refusal(plan, ctx)
    assert decision.rule_id == "blast_radius.forbidden_fault_pairs"
    assert decision.inputs["pair"] == ["net.latency", "net.packet_loss"]


def test_the_historical_inertness_case_is_caught_when_the_pair_is_not_adjacent() -> None:
    """The pre-1.0.0 bug: one big set of every fault, which a pair never matches.

    ``INERT_PLAN`` keeps the two forbidden members separated by a third fault,
    so the old rule — ``{'net.latency', 'dns.servfail', 'net.packet_loss'}`` —
    matched nothing and the drill ran protected in name only. The pair is
    completed on the third step and admission must refuse.
    """
    ctx = _ctx(_inputs(), budget=_pairing_budget(INERT_PAIR))
    decision = _refusal(_plan(*INERT_PLAN), ctx)
    assert decision.rule_id == "blast_radius.forbidden_fault_pairs"
    assert decision.inputs["pair"] == ["net.latency", "net.packet_loss"]


def test_whichever_member_of_the_pair_runs_second_refuses() -> None:
    """Order does not decide where the pair sits: every arrangement refuses."""
    orders = (
        ("net.latency", "dns.servfail", "net.packet_loss"),  # members 1st and 3rd
        ("net.packet_loss", "dns.servfail", "net.latency"),  # reversed
        ("net.latency", "net.packet_loss", "dns.servfail"),  # completes on step 2
    )
    for order in orders:
        ctx = _ctx(_inputs(), budget=_pairing_budget(INERT_PAIR))
        decision = _refusal(_plan(*order), ctx)
        assert decision.rule_id == "blast_radius.forbidden_fault_pairs"
        assert decision.inputs["pair"] == ["net.latency", "net.packet_loss"]


def test_a_three_fault_plan_without_the_pair_passes_admission() -> None:
    """Two-sided: a three-fault plan is not refused for a pair it does not carry."""
    ctx = _ctx(_inputs(), budget=_pairing_budget(frozenset({"proc.pause", "http.latency"})))
    validate_plan(_plan(*INERT_PLAN), _graph(), ctx)
    allowed = [d for d in ctx.decisions if d.rule_id == "blast_radius.allow"]
    assert len(allowed) == 3


def test_the_bundle_collision_graph_refuses_a_three_fault_plan_before_any_step() -> None:
    """Gap 66's graph has the same pair reading, checked before the loop runs."""
    edge = CompatibilityEdge(
        left_fault="net.latency",
        right_fault="dns.servfail",
        verdict=CompatibilityVerdict.CONFLICTING,
        reason="latency masks servfail",
    )
    ctx = _ctx(_inputs(compatibility=(edge,)))
    decision = _refusal(_plan(*INERT_PLAN), ctx)
    assert decision.rule_id == RULE_COMPAT_CONFLICT
    # Refused at plan level: no step was ever admitted, so there is no
    # per-step allow record beside the refusal.
    assert [d for d in ctx.decisions if d.rule_id == "blast_radius.allow"] == []


def test_a_conditional_pair_passes_only_when_its_condition_holds_at_admission() -> None:
    edge = CompatibilityEdge(
        left_fault="net.latency",
        right_fault="net.packet_loss",
        verdict=CompatibilityVerdict.CONDITIONALLY_SAFE,
        conditions=(
            CompatibilityCondition(dimension=PolicyDimension.ENVIRONMENT, values=("staging",)),
        ),
    )
    admitted = _ctx(_inputs(compatibility=(edge,)), environment="staging")
    validate_plan(_plan(*INERT_PLAN), _graph(), admitted)

    refused = _ctx(_inputs(compatibility=(edge,)), environment="production")
    decision = _refusal(_plan(*INERT_PLAN), refused)
    assert decision.rule_id == RULE_COMPAT_CONFLICT


# -- lock contention: two experiments, one postgres-primary -------------------------


def test_the_second_experiment_queues_behind_the_named_lock_owner() -> None:
    """Experiment A holds ``postgres-primary``; experiment B is refused, naming A."""
    # A's own run: re-entrant through its own reservation, so A is admitted.
    first = _ctx(
        _inputs(
            locks=(_lock(),),
            lock_resources=("postgres-primary",),
            experiment_id="exp-a",
            run_id="run-a",
        )
    )
    validate_plan(_plan("proc.pause"), _graph(), first)

    # B asks for the same resource while A's lock is live.
    second = _ctx(
        _inputs(
            locks=(_lock(),),
            lock_resources=("postgres-primary",),
            experiment_id="exp-b",
            run_id="run-b",
        )
    )
    decision = _refusal(_plan("proc.pause"), second)
    assert decision.rule_id == RULE_LOCK_CONTENDED
    assert decision.inputs["resource"] == "postgres-primary"
    # The owner is named in the reason *and* machine-readably, so a queue can be
    # built without parsing prose.
    assert "run-a" in decision.reason
    assert "exp-a" in decision.reason
    assert "queue behind" in decision.reason
    assert decision.inputs["holder_run_id"] == "run-a"
    assert decision.inputs["holder_experiment_id"] == "exp-a"
    assert decision.inputs["blockers"] == ["exp-a-run-a-postgres-primary"]


def test_a_dead_runs_lock_fences_nothing_and_is_never_inherited() -> None:
    """Negative control: the lock of a run whose window closed blocks nobody.

    And B is granted *its own* reservation rather than handed A's: the dead
    run's lock is still A's on the caller's lock set — fencing closed, never
    inherited.
    """
    dead = _lock(expires_at=BEFORE + timedelta(minutes=1))
    gate = _inputs(
        locks=(dead,),
        lock_resources=("postgres-primary",),
        experiment_id="exp-b",
        run_id="run-b",
    )
    # Admission is not blocked...
    validate_plan(_plan("proc.pause"), _graph(), _ctx(gate))
    # ...the verdict is a fresh grant naming B as requester...
    (verdict,) = check_locks(_plan("proc.pause"), gate)
    assert verdict.granted
    assert verdict.blockers == ()
    assert verdict.requested_by == "run-b"
    # ...and the dead lock still belongs to A: nothing was inherited.
    assert len(gate.locks) == 1
    assert gate.locks[0].owner_run_id == "run-a"
    assert gate.locks[0].experiment_id == "exp-a"


# -- quota and budget, both systems, at admission -----------------------------------


def test_the_quota_alone_refuses_at_admission() -> None:
    """One system configured and refusing is enough: the conjunction has no escape."""
    gate = _inputs(damage_quota=DamageQuota(budget_s=1.0, per_fault_ceiling_s=1e6))
    decision = _refusal(_plan("proc.pause"), _ctx(gate))
    assert decision.rule_id == "damage_quota.budget"


def test_budget_and_quota_both_refusing_reports_the_hierarchy_with_the_ride_along() -> None:
    gate = _inputs(
        budget=_budget_tree(1.0, "proc.pause"),
        budget_path=BUDGET_PATH,
        damage_quota=DamageQuota(budget_s=1.0, per_fault_ceiling_s=1e6),
    )
    decision = _refusal(_plan("proc.pause"), _ctx(gate))
    assert decision.rule_id == RULE_BUDGET_EXHAUSTED
    # The other system's verdict rides along rather than being discarded by the
    # reporting preference.
    assert decision.inputs["also_refused_by"] == "damage_quota.budget"
    assert decision.inputs["budget_rule_ids"] == [RULE_BUDGET_EXHAUSTED, "damage_quota.budget"]


def test_a_plan_within_both_budgets_passes_admission() -> None:
    gate = _inputs(
        budget=_budget_tree(1e6, "proc.pause"),
        budget_path=BUDGET_PATH,
        damage_quota=DamageQuota(budget_s=1e6, per_fault_ceiling_s=1e6),
    )
    ctx = _ctx(gate)
    validate_plan(_plan("proc.pause"), _graph(), ctx)
    assert [d for d in ctx.decisions if d.rule_id == "blast_radius.allow"]


# -- the budget commit path: probe, then post, then judge ----------------------------


def test_commit_posts_every_charge_and_the_next_run_reads_the_spend() -> None:
    """Posting is what makes "persisted across runs" a fact rather than a claim."""
    ledger = _MemoryLedger()
    tree = _budget_tree(1e6, "proc.pause")
    gate = _inputs(budget=tree, budget_path=BUDGET_PATH)

    commit = commit_budget(_plan("proc.pause"), gate, ledger)
    assert commit.posted
    assert commit.entries == 5  # team → environment → service → experiment → fault
    assert commit.refusal is None
    assert not commit.refused
    # The authored tree the caller holds is untouched; spend lives on the ledger.
    assert tree.spent_s == 0.0
    assert len(ledger.entries()) == 5

    # A second run over the same ledger reads the first run's spend.
    persisted = persisted_budget(tree, ledger)
    team = persisted.find(BudgetScope.TEAM, "sre")
    assert team is not None
    assert team.spent_s == pytest.approx(STEP_S)

    second = commit_budget(_plan("proc.pause", run_id="run-2"), gate, ledger)
    assert second.posted
    assert len(ledger.entries()) == 10
    assert {entry.run_id for entry in ledger.entries()} == {"run-1", "run-2"}
    leaf = second.tree.find(BudgetScope.FAULT, "proc.pause") if second.tree else None
    assert leaf is not None
    assert leaf.spent_s == pytest.approx(2 * STEP_S)


def test_commit_judges_after_posting_and_refuses_by_the_gates_own_rule_id() -> None:
    """Charge-then-judge: the breach is posted first, and there is no refund path."""
    ledger = _MemoryLedger()
    gate = _inputs(budget=_budget_tree(1.0, "proc.pause"), budget_path=BUDGET_PATH)
    commit = commit_budget(_plan("proc.pause"), gate, ledger)
    assert commit.refused
    assert commit.refusal is not None
    assert commit.refusal.rule_id == RULE_BUDGET_EXHAUSTED
    # The charge that breached is on the ledger — judged *after* every append.
    assert commit.posted
    assert len(ledger.entries()) == 5
    assert [charge.key for charge in commit.breached] == ["proc.pause"]
    # And the refusal reads byte-for-byte like the gate's, so one rule id means
    # one failure wherever it was reached.
    gate_result = evaluate_gate(_plan("proc.pause"), gate)
    assert gate_result.refusal is not None
    assert commit.refusal.rule_id == gate_result.refusal.rule_id
    assert commit.refusal.reason == gate_result.refusal.reason
    assert commit.refusal.remediation == gate_result.refusal.remediation
    assert commit.refusal.inputs == gate_result.refusal.inputs


def test_commit_without_a_mounted_budget_posts_nothing() -> None:
    """A limit nobody configured is not a limit: no charge, no refusal."""
    ledger = _MemoryLedger()
    commit = commit_budget(_plan("proc.pause"), _inputs(), ledger)
    assert not commit.posted
    assert commit.entries == 0
    assert commit.refusal is None
    assert commit.within_budget
    assert commit.tree is None
    assert ledger.entries() == ()
    assert commit.describe() == "budget commit posted nothing (no budget mounted)"


def test_a_malformed_budget_path_refuses_the_commit_without_posting() -> None:
    """The walk cannot say who pays, so it posts nothing rather than posting half."""
    ledger = _MemoryLedger()
    # A tree whose first level is not the one budget_path names: the walk dies
    # before it can say who pays, so nothing may be posted.
    gate = _inputs(budget=_budget_tree(1e6, "proc.pause"), budget_path=("typo",))
    commit = commit_budget(_plan("proc.pause"), gate, ledger)
    assert commit.config_defect is not None
    assert commit.refusal is not None
    assert commit.refusal.rule_id == RULE_POLICY_CONFIG
    assert not commit.posted
    assert commit.entries == 0
    assert ledger.entries() == ()


# -- negative controls ---------------------------------------------------------------


def test_an_expired_policy_version_cannot_authorize_a_run() -> None:
    """Negative control: expiry outranks every allow rule the bundle has.

    The bundle here permits everything — no deny rule, default allow — and is
    still refused, because an expired version authorizes nothing regardless of
    what its rules would have said.
    """
    expired = _bundle(default=PolicyEffect.ALLOW, expires_at=BEFORE)
    assert all(rule.effect is not PolicyEffect.DENY for rule in expired.rules)
    decision = _refusal(_plan("proc.pause"), _ctx(_inputs(expired)))
    assert decision.rule_id == RULE_BUNDLE_EXPIRED
    assert "expired" in decision.reason


def test_simulating_the_contention_scenario_mutates_nothing_and_matches_admission() -> None:
    """The phase's acceptance: simulation covered by tests asserting no mutation."""
    tree = _budget_tree(1.0, "proc.pause")
    gate = _inputs(
        budget=tree,
        budget_path=BUDGET_PATH,
        locks=(_lock(),),
        lock_resources=("postgres-primary",),
        experiment_id="exp-b",
        run_id="run-b",
    )
    plan = _plan("proc.pause")
    plan_before = plan.model_dump_json()
    locks_before = tuple(lock.model_dump_json() for lock in gate.locks)
    tree_before = tree.model_dump_json()
    sink = MutationSink()

    simulated = simulate_gate(plan, gate, sink=sink)
    # Nothing reached the mutation boundary, nothing changed bytes...
    assert len(sink) == 0
    assert sink.calls == ()
    assert plan.model_dump_json() == plan_before
    assert tuple(lock.model_dump_json() for lock in gate.locks) == locks_before
    assert tree.model_dump_json() == tree_before
    # ...a real refusal was still reached (purity is not an early return)...
    assert simulated.simulated
    assert simulated.refusal is not None
    assert simulated.refusal.rule_id == RULE_LOCK_CONTENDED
    # ...repeating the simulation reproduces it bit-for-bit, and admission
    # reaches the identical decision — a preview cannot disagree with the run.
    again = simulate_gate(plan, gate)
    admitted = evaluate_gate(plan, gate)
    assert again.decision_digest() == simulated.decision_digest()
    assert admitted.decision_digest() == simulated.decision_digest()
    assert admitted.refusal is not None
    assert admitted.refusal.reason == simulated.refusal.reason
