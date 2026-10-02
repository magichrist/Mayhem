"""v1.1.0 plan 02 phase 4 — the Kubernetes lane as evidence, not a standalone gate.

Phase 2's ledger recorded, verbatim, that *"nothing constructs a
``K8sAdmissionInput`` in production"* and that *"the executor does not yet build
``requests`` from its ``resolve_many`` output, so even a configured context would
refuse every step as unresolved."* These tests are about that gap and about the
two things that have to be true afterwards: the run journal says what the
Kubernetes lane decided, and the sealed chain can reconstruct why.

What is pinned here:

  1. **request building** — ``resolve_many``'s output becomes step-id-keyed
     admission requests, and a two-step plan against one workload does *not*
     reuse step 1's pods for step 2 (the fault-id keying bug this naming exists
     to prevent);
  2. **event emission** — one decision per step, drift only when there is drift,
     and every kind drawn from the ``EventKind`` vocabulary that already existed
     (the phase-specific set is asserted, so a later "just add a kind" edit fails
     here rather than quietly doubling the vocabulary);
  3. **the executor hook** — inert with no ``k8s_admission`` configured (the
     resolver factory is never even called), one cluster read per workload
     although the gate is asked twice, and the caller's context never mutated;
  4. **the sealing round trip** — the decision, its rule id and its observed
     numbers reload from stored bytes and re-verify;
  5. **negative controls** — a blueprint placeholder, a drift-only selection, a
     record with no pod uid, a step nothing could resolve, and an *unsealed* or
     *tampered* decision are all detected, and the refusal for an unresolvable
     step names the step.

Honesty note that every test below is written under: **no live cluster has been
accepted by this phase.** Every request here came from a fake cluster client, so
what is certified is the evidence integration, not a cluster.
"""

from __future__ import annotations

import contextlib
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.agents.k8s_resolve import K8sWorkload, ResolutionOutcome
from mayhem.config import PolicyCfg
from mayhem.controller.executor import RunEngine
from mayhem.controller.k8s_admission import (
    RULE_ADMISSION_ALLOW,
    RULE_NO_LIVE_TARGET,
    K8sAdmissionInput,
    K8sAdmissionRequest,
    namespace_protection,
)
from mayhem.controller.k8s_evidence import (
    EVENT_K8S_ADMISSION_DECIDED,
    K8S_PHASE_KINDS,
    admission_chain_key,
    admission_payload,
    drift_events,
    k8s_plan_steps,
    load_k8s_admission,
    note_from_outcomes,
    plan_phase_admission,
    resolve_admission_requests,
    run_phase_event,
    seal_k8s_admission,
    verify_k8s_admission_chain,
)
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    explain_fault_refusal,
    validate_plan,
)
from mayhem.domain.attestation import AttestedEvent, AttestedTimestamp
from mayhem.domain.errors import ResolutionError
from mayhem.domain.events import EventKind
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.k8s_adapter import KubernetesAdapter
from mayhem.domain.k8s_targets import (
    K8sExclusionKind,
    K8sSelectionCandidate,
    K8sSelector,
    K8sTargetSource,
    WorkloadFacts,
    WorkloadKind,
)
from mayhem.domain.resolution import ResolvedNodeTarget, ResolvedPodTarget
from mayhem.domain.target import ResourceKind, TargetScope
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    PodNode,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

WORKLOAD = K8sWorkload(namespace="shop", kind="deployment", name="checkout")
FAULT_ID = "k8s.pod_kill"
RUN_ID = "run-1"

#: Every ``EventKind`` this phase is allowed to emit. All of them pre-date the
#: phase: the plan's "Kubernetes events emitted per run phase" is satisfied by
#: reusing the lifecycle kinds the engine already journals plus
#: ``CHECK_EVALUATED`` / ``DRIFT_REPORTED`` / ``SAFETY_REFUSED``, all of which
#: ``domain/api.py``'s timeline already maps to a phase. If a future edit adds a
#: kind, this tuple stops covering it and this test fails — which is the point.
PHASE_EVENT_KINDS: frozenset[EventKind] = frozenset(
    {
        EventKind.RUN_STARTED,
        EventKind.STEP_STARTED,
        EventKind.FAULT_INJECTED,
        EventKind.CHECK_EVALUATED,
        EventKind.DRIFT_REPORTED,
        EventKind.SAFETY_REFUSED,
    }
)

READING = AttestedTimestamp(
    wall_clock=datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC),
    monotonic_ns=1_000_000,
    uncertainty_ms=0.5,
    source="system",
)


# ── fakes ───────────────────────────────────────────────────────────────────
class FakeResolver:
    """``resolve_many`` per scope, so a step's *own* resolution is what it gets.

    Keyed by the scope's logical id, which is what makes the step-id keying test
    meaningful: two steps with the same fault and the same workload kind but
    different scopes must receive different pods.
    """

    def __init__(self, by_logical_id: dict[str, list[tuple[str, bool]]]) -> None:
        self._by_id = by_logical_id
        self.calls: list[tuple[str, str]] = []

    @property
    def available(self) -> bool:
        """The resolver seam's availability flag, as the executor reads it."""
        return True

    def resolve_many(self, scope: TargetScope, *, pod_action: str = "") -> list[ResolutionOutcome]:
        self.calls.append((scope.logical_id, pod_action))
        pods = self._by_id.get(scope.logical_id)
        if pods is None:
            raise ResolutionError("resolution.resource_missing", f"no pods for {scope.logical_id}")
        return [
            ResolutionOutcome(
                resolved=ResolvedPodTarget(
                    namespace="shop",
                    pod=pod,
                    container="app",
                    pod_uid=f"uid-{pod}",
                    container_id=f"containerd://{pod}",
                    node=f"node-{pod}",
                ),
                drift=drift,
                note=f"resolved {pod}",
            )
            for pod, drift in pods
        ]


class FakeAdmissionClient:
    """Records every read, so a test can prove how many the plan phase spent.

    Facts are keyed by workload name; a workload the test did not name gets the
    default fact set re-pinned to the identity admission asked about, which is
    what a real client returning per-workload facts would look like.
    """

    def __init__(self, facts: WorkloadFacts | None = None) -> None:
        self.default = facts
        self.by_name: dict[str, WorkloadFacts] = {}
        self.asked: list[K8sWorkload] = []

    def workload_facts(self, workload: K8sWorkload) -> WorkloadFacts | None:
        self.asked.append(workload)
        named = self.by_name.get(workload.name)
        if named is not None:
            return named
        if self.default is None:
            return None
        return self.default.model_copy(
            update={"namespace": workload.namespace, "name": workload.name}
        )

    @property
    def reads(self) -> int:
        return len(self.asked)


class ExplodingFactory:
    """A resolver factory that fails the test if it is ever called."""

    def __call__(self) -> Any:
        raise AssertionError("the resolver factory must not be called on the inert path")


# ── builders ─────────────────────────────────────────────────────────────────
def _scope(
    name: str = "checkout",
    *,
    namespace: str = "shop",
    kind: ResourceKind = ResourceKind.DEPLOYMENT,
) -> TargetScope:
    authority: dict[str, str] = {"api_group": "apps", "namespace": namespace, "name": name}
    if kind is ResourceKind.K8S_NODE:
        authority = {"name": "node-a"}
    return TargetScope(
        logical_id=name,
        runtime=RuntimeLabel.KUBERNETES,
        kind=kind,
        authority=authority,
        container="app",
    )


def _pod_node(name: str) -> PodNode:
    return PodNode(
        id=f"k8s::shop/pod/{name}",
        name=name,
        kind=NodeKind.POD,
        state="Running",
        namespace="shop",
        owner_kind="Deployment",
        owner_name="checkout",
        node_name="node-0",
    )


def _graph(*, with_pods: bool = False) -> TopologyGraph:
    """A plan-time graph, optionally carrying the planned pod as a graph node.

    Two shapes, for the reason ``test_k8s_admission.py`` documents: with the pod
    node present, ``_check_k8s_targets`` would refuse the plan as
    ``k8s.unsupported``; without it, a plan the admission *allows* is not then
    refused for something unrelated to the admission.
    """
    pods = (_pod_node("checkout-00"),) if with_pods else ()
    edges = (
        (
            Edge(
                src="k8s::shop/Service/checkout",
                dst="checkout-00",
                kind=EdgeKind.DEPENDS_ON,
                weight=1.0,
            ),
        )
        if with_pods
        else ()
    )
    return TopologyGraph(
        nodes=(
            ServiceNode(id="k8s::shop/Service/checkout", name="checkout", kind=NodeKind.SERVICE),
            *pods,
        ),
        edges=edges,
    )


def _plan(
    *,
    steps: tuple[tuple[str, str, TargetScope], ...] = (("s1", FAULT_ID, _scope()),),
    run_id: str = RUN_ID,
) -> ExecutionPlan:
    """A plan whose steps carry ``(step_id, fault_id, scope)`` triples."""
    planned: list[PlannedStep] = []
    for index, (step_id, fault_id, scope) in enumerate(steps):
        selector = TargetSelector(kind=NodeKind.POD, expr="checkout")
        planned.append(
            PlannedStep(
                id=step_id,
                seq=index,
                raw_action=InjectFault(
                    fault=fault_id,
                    selectors=(selector,),
                    target=scope,
                    duration=5.0,
                ),
                fault=PlannedFault(
                    fault_id=fault_id,
                    targets=(
                        ResolvedTarget(
                            selector=selector,
                            node_ids=frozenset({"k8s::shop/pod/checkout-00"}),
                        ),
                    ),
                    target=scope,
                    duration=5.0,
                ),
            )
        )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DETERMINISTIC,
        steps=tuple(planned),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="fp",
    )


def _docker_plan() -> ExecutionPlan:
    """A docker-only plan: the Kubernetes hook must not resolve anything for it."""
    selector = TargetSelector(kind=NodeKind.HOST, expr="web")
    scope = TargetScope(
        logical_id="web",
        runtime=RuntimeLabel.DOCKER,
        kind=ResourceKind.CONTAINER,
        authority={"container_name": "web"},
    )
    return ExecutionPlan(
        run_id=RUN_ID,
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id="s1",
                seq=0,
                raw_action=InjectFault(
                    fault="cpu.spike", selectors=(selector,), target=scope, duration=5.0
                ),
                fault=PlannedFault(
                    fault_id="cpu.spike",
                    targets=(
                        ResolvedTarget(selector=selector, node_ids=frozenset({"docker::web"})),
                    ),
                    target=scope,
                    duration=5.0,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="fp",
    )


def _facts(**kwargs: Any) -> WorkloadFacts:
    base: dict[str, Any] = {
        "name": "checkout",
        "namespace": "shop",
        "kind": WorkloadKind.DEPLOYMENT,
        "replicas": 10,
        "ready_replicas": 10,
        "updated_replicas": 10,
        "readiness_probe": True,
        "liveness_probe": True,
        "startup_probe": True,
        "cluster_nodes_ready": 5,
        "cluster_nodes_total": 5,
    }
    base.update(kwargs)
    return WorkloadFacts(**base)


def _admission(
    client: FakeAdmissionClient,
    *,
    requests: dict[str, K8sAdmissionRequest] | None = None,
    **kwargs: Any,
) -> K8sAdmissionInput:
    return K8sAdmissionInput(
        client=client,
        authorize=namespace_protection(),
        requests=requests or {},
        **kwargs,
    )


def _ctx(admission: K8sAdmissionInput | None = None) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(max_services_pct=100.0),
        fingerprint="fp",
        k8s_admission=admission,
    )


def _open_store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


def _resolved(pod: str, *, uid: str | None = "auto") -> ResolvedPodTarget:
    return ResolvedPodTarget(
        namespace="shop",
        pod=pod,
        container="app",
        pod_uid=f"uid-{pod}" if uid == "auto" else uid,
    )


def _blueprint_candidate(name: str = "checkout-00") -> K8sSelectionCandidate:
    """An offline manifest placeholder: never live-eligible, by construction."""
    return K8sSelectionCandidate(
        name=name,
        namespace="shop",
        target=None,
        source=K8sTargetSource.BLUEPRINT,
        state="blueprint",
    )


# ── 1. request building from the resolver's output ──────────────────────────
class TestRequestBuilding:
    def test_requests_are_keyed_by_step_id_and_carry_the_resolver_targets(self) -> None:
        resolver = FakeResolver({"checkout": [("checkout-00", False)]})

        requests, notes = resolve_admission_requests(_plan(), resolver)

        assert tuple(requests) == ("s1",)
        request = requests["s1"]
        assert request.workload == WORKLOAD
        assert [t.authority_key for t in request.targets] == ["shop/checkout-00"]
        assert notes[0].resolved
        assert notes[0].authority_keys == ("shop/checkout-00",)

    def test_two_steps_of_the_same_fault_do_not_reuse_step_ones_pods(self) -> None:
        """The negative control for fault-id keying.

        Both steps carry ``k8s.pod_kill`` against the same namespace and the same
        workload kind; only the step ids and the workload names differ. A
        fault-id key would collapse them into one request and step 2 would be
        admitted against step 1's pod.
        """
        plan = _plan(
            steps=(
                ("s1", FAULT_ID, _scope("checkout")),
                ("s2", FAULT_ID, _scope("checkout-restart")),
            )
        )
        resolver = FakeResolver(
            {"checkout": [("checkout-00", False)], "checkout-restart": [("restart-00", False)]}
        )

        requests, notes = resolve_admission_requests(plan, resolver)

        assert tuple(requests) == ("s1", "s2")
        assert requests["s1"].targets[0].pod == "checkout-00"
        assert requests["s2"].targets[0].pod == "restart-00"
        assert requests["s2"].workload.name == "checkout-restart"
        assert {note.step_id for note in notes} == {"s1", "s2"}
        # The resolver was asked once per step, with that step's own scope.
        assert resolver.calls == [("checkout", "pod_kill"), ("checkout-restart", "pod_kill")]

    def test_a_step_the_resolver_cannot_resolve_produces_no_request_and_says_why(
        self,
    ) -> None:
        requests, notes = resolve_admission_requests(_plan(), FakeResolver({}))

        assert requests == {}
        (note,) = notes
        assert not note.resolved
        assert note.error_code == "resolution.resource_missing"
        assert "s1" in note.describe()

    def test_a_blueprint_placeholder_is_never_a_request_target(self) -> None:
        """Honesty invariant: an offline manifest placeholder is not a pod.

        Phase 1 buckets it and never selects it. Asserted here because this phase
        consumes those buckets: a request built from a selection that matched a
        blueprint can never carry the blueprint's "target".
        """
        live = K8sSelectionCandidate(
            name="checkout-01", namespace="shop", target=_resolved("checkout-01")
        )

        selection = K8sSelector().select([_blueprint_candidate(), live])

        assert [t.pod for t in selection.targets] == ["checkout-01"]
        kinds = {exclusion.kind for exclusion in selection.excluded}
        assert kinds == {K8sExclusionKind.BLUEPRINT}
        assert "blueprint" in selection.exclusion_summary()
        assert not _blueprint_candidate().live_eligible

    def test_a_selection_with_only_blueprints_yields_no_request_target(self) -> None:
        selection = K8sSelector().select([_blueprint_candidate()])

        assert selection.targets == ()
        assert selection.is_empty
        assert selection.reason  # an empty selection is explicit, never an all-match

    def test_k8s_plan_steps_excludes_node_scoped_and_non_kubernetes_steps(self) -> None:
        plan = _plan(
            steps=(
                ("s1", FAULT_ID, _scope()),
                ("s2", "k8s.node_drain", _scope("node-a", kind=ResourceKind.K8S_NODE)),
            )
        )

        assert tuple(step_id for step_id, _, _ in k8s_plan_steps(plan)) == ("s1",)

    def test_note_drops_a_node_resolution_instead_of_coercing_it(self) -> None:
        note = note_from_outcomes(
            "s1",
            FAULT_ID,
            WORKLOAD,
            [ResolutionOutcome(resolved=ResolvedNodeTarget(node="node-a"), note="resolved node")],
        )

        assert note.targets == ()
        assert not note.resolved


# ── 2. event emission ────────────────────────────────────────────────────────
class TestEvents:
    def test_every_emitted_kind_is_from_the_pre_existing_vocabulary(self) -> None:
        assert set(K8S_PHASE_KINDS.values()) <= PHASE_EVENT_KINDS
        assert K8S_PHASE_KINDS["admission"] is EventKind.CHECK_EVALUATED
        assert K8S_PHASE_KINDS["drift"] is EventKind.DRIFT_REPORTED
        for kind in K8S_PHASE_KINDS.values():
            assert kind in EventKind

    def test_run_phase_event_renders_and_refuses_an_unknown_phase(self) -> None:
        event = run_phase_event("plan", RUN_ID, step_id="s1", fault_id=FAULT_ID)

        assert event.kind is EventKind.CHECK_EVALUATED
        assert event.run_id == RUN_ID
        assert event.detail == {"phase": "plan", "lane": "k8s", "step": "s1", "fault": FAULT_ID}
        assert "plan" in event.render_line()
        assert "step=s1" in event.render_line()
        with pytest.raises(KeyError):
            run_phase_event("nonsense", RUN_ID)

    def test_one_decision_event_per_step_plus_one_refusal_marker(self) -> None:
        # s1 resolves two pods against a PDB floor of 9 of 10 → the PDB rule
        # refuses it. s2's workload has no PDB floor and one pod → admitted.
        client = FakeAdmissionClient(_facts(pdb_min_available=9))
        plan = _plan(steps=(("s1", FAULT_ID, _scope("checkout")), ("s2", FAULT_ID, _scope("b"))))
        resolver = FakeResolver(
            {"checkout": [("checkout-00", False), ("checkout-01", False)], "b": [("b-00", False)]}
        )
        ctx = _ctx(_admission(client))

        with pytest.raises(SafetyRefusedError):
            with plan_phase_admission(plan, ctx, lambda: resolver) as phase:
                validate_plan(plan, _graph(), phase.safety)

        events = phase.events
        kinds = [event.kind for event in events]
        # One decision per step — the *allow* included, because "why was this
        # allowed" is the question a later reader asks just as often.
        assert kinds.count(EventKind.CHECK_EVALUATED) == 2
        assert kinds.count(EventKind.SAFETY_REFUSED) == 1
        assert EventKind.DRIFT_REPORTED not in kinds  # nothing drifted
        decisions = {
            str(e.detail["step_id"]): e for e in events if e.kind is EventKind.CHECK_EVALUATED
        }
        assert decisions["s1"].detail["admitted"] is False
        assert decisions["s2"].detail["admitted"] is True
        assert decisions["s2"].detail["rule_id"] == RULE_ADMISSION_ALLOW
        refusal = next(e for e in events if e.kind is EventKind.SAFETY_REFUSED)
        assert refusal.detail["rule_id"] == "k8s.pdb_violation"
        assert refusal.detail["step_id"] == "s1"
        assert phase.denied_steps == ("s1",)

    def test_a_drifted_or_unresolved_step_emits_exactly_one_drift_event(self) -> None:
        resolved = note_from_outcomes(
            "s1",
            FAULT_ID,
            WORKLOAD,
            [
                ResolutionOutcome(resolved=_resolved("a")),
            ],
        )
        drifted = replace(resolved, step_id="s2", drift=True)
        unresolved = replace(
            resolved,
            step_id="s3",
            targets=(),
            error_code="resolution.resource_missing",
            error="no Running pod for shop/checkout",
        )

        events = drift_events(RUN_ID, [resolved, drifted, unresolved])

        # A resolved, undrifted step produces nothing: a drift report that fires
        # on every healthy step teaches a reader to ignore it.
        assert [event.detail["step"] for event in events] == ["s2", "s3"]
        assert all(event.kind is EventKind.DRIFT_REPORTED for event in events)
        assert "resolution.resource_missing" in str(events[1].detail["reason"])

    def test_the_decision_payload_names_the_rule_and_the_observed_numbers(self) -> None:
        client = FakeAdmissionClient(_facts(pdb_min_available=8, replicas=10))
        resolver = FakeResolver({"checkout": [("a", False), ("b", False), ("c", False)]})
        plan = _plan()

        with pytest.raises(SafetyRefusedError):
            with plan_phase_admission(plan, _ctx(_admission(client)), lambda: resolver) as phase:
                validate_plan(plan, _graph(), phase.safety)

        (outcome,) = phase.outcomes
        payload = admission_payload(outcome)
        assert payload["rule_id"] == "k8s.pdb_violation"
        assert payload["admitted"] is False
        assert payload["step_id"] == "s1"
        assert payload["observed"]["replicas"] == 10
        assert payload["observed"]["pdb_min_available"] == 8
        assert payload["observed"]["kill_count"] == 3
        # Every observed value survives the JSON projection: a decision record
        # that could not be serialized would be worse than a legible one.
        assert payload["verdicts"][0]["code"] == "k8s.pdb_violation"


# ── 3. the executor hook ─────────────────────────────────────────────────────
class TestPlanPhaseHook:
    def test_an_unconfigured_context_never_reaches_the_resolver(self) -> None:
        ctx = _ctx(None)
        plan = _plan()

        with plan_phase_admission(plan, ctx, ExplodingFactory()) as phase:
            assert phase.safety is ctx
            assert phase.outcomes == ()
            assert phase.notes == ()

    def test_a_docker_only_plan_never_reaches_the_resolver(self) -> None:
        ctx = _ctx(_admission(FakeAdmissionClient(_facts())))

        with plan_phase_admission(_docker_plan(), ctx, ExplodingFactory()) as phase:
            assert phase.safety is ctx
            assert phase.outcomes == ()

    def test_a_configured_context_is_never_mutated_by_the_hook(self) -> None:
        client = FakeAdmissionClient(_facts())
        resolver = FakeResolver({"checkout": [("checkout-00", False)]})
        ctx = _ctx(_admission(client))
        plan = _plan()

        with plan_phase_admission(plan, ctx, lambda: resolver) as phase:
            validate_plan(plan, _graph(), phase.safety)
            assert tuple(phase.safety.k8s_admission.requests) == ("s1",)

        # The caller's context is untouched: no resolved request was installed on
        # it, so a resolution can never leak into a later run on the same context.
        assert tuple(ctx.k8s_admission.requests) == ()

    def test_the_plan_phase_spends_one_cluster_read_per_workload(self) -> None:
        client = FakeAdmissionClient(_facts())
        resolver = FakeResolver({"checkout": [("checkout-00", False)]})
        ctx = _ctx(_admission(client))
        plan = _plan()

        with plan_phase_admission(plan, ctx, lambda: resolver) as phase:
            validate_plan(plan, _graph(), phase.safety)

        # The gate is asked twice — once here so the decision can be journaled
        # and sealed, once inside validate_plan — and reads the cluster once.
        assert client.reads == 1
        assert phase.outcomes[0].admitted
        assert phase.outcomes[0].rule_id == RULE_ADMISSION_ALLOW
        assert phase.outcomes[0].targets == ("shop/checkout-00",)

    def test_the_callers_context_keeps_the_gate_decisions(self) -> None:
        client = FakeAdmissionClient(_facts(pdb_min_available=10))
        resolver = FakeResolver({"checkout": [("checkout-00", False)]})
        ctx = _ctx(_admission(client))
        plan = _plan()

        with pytest.raises(SafetyRefusedError) as excinfo:
            with plan_phase_admission(plan, ctx, lambda: resolver) as phase:
                validate_plan(plan, _graph(), phase.safety)

        assert phase.refused
        assert isinstance(phase.refusal, SafetyRefusedError)
        # The recorded decisions live on the *caller's* context: replacing the
        # frozen context for the block must not swallow the refusal.
        assert any(d.rule_id == "k8s.pdb_violation" for d in ctx.decisions)
        assert explain_fault_refusal(excinfo.value)["rule_id"] == "k8s.pdb_violation"

    def test_the_resolved_requests_are_what_the_gate_reads(self) -> None:
        """The gap this phase exists to close, end to end.

        A configured context with *no* requests refuses every step as
        unresolved. Once the hook has run ``resolve_many``, the same plan is
        admitted against the pods the resolver actually returned.
        """
        client = FakeAdmissionClient(_facts())
        resolver = FakeResolver({"checkout": [("checkout-00", False)]})
        ctx = _ctx(_admission(client))
        plan = _plan()

        # Before: no request, so no live target.
        with pytest.raises(SafetyRefusedError) as excinfo:
            validate_plan(plan, _graph(), ctx)
        assert explain_fault_refusal(excinfo.value)["rule_id"] == RULE_NO_LIVE_TARGET

        # After: the hook's requests are what the gate sees.
        with plan_phase_admission(plan, ctx, lambda: resolver) as phase:
            validate_plan(plan, _graph(), phase.safety)
            assert phase.resolved_steps == ("s1",)
            assert phase.denied_steps == ()

    def test_a_resolver_that_is_not_available_leaves_the_gate_untouched(self) -> None:
        client = FakeAdmissionClient(_facts())
        ctx = _ctx(_admission(client))
        plan = _plan()

        with plan_phase_admission(plan, ctx, lambda: None) as phase:
            with pytest.raises(SafetyRefusedError) as excinfo:
                validate_plan(plan, _graph(), phase.safety)

        assert phase.outcomes == ()
        assert explain_fault_refusal(excinfo.value)["rule_id"] == RULE_NO_LIVE_TARGET

    def test_the_events_table_cannot_hold_a_row_before_the_run_exists(self, tmp_path: Path) -> None:
        """Why :attr:`K8sPlanPhase.events` is buffered instead of written inline.

        ``events.run_id`` references ``runs(id)`` with foreign keys enforced, and
        admission runs before ``_open_run``. If the lane journaled its own events
        at decision time this insert would fail — so the ordering is a property
        with a test behind it, not a comment a reviewer has to take on faith.
        """
        store = _open_store(tmp_path)
        with pytest.raises(sqlite3.IntegrityError):
            with store.write() as conn:
                conn.execute(
                    "INSERT INTO events (run_id, ts, kind, payload_json) VALUES (?,?,?,?)",
                    (RUN_ID, "2026-03-01T12:00:00+00:00", EventKind.CHECK_EVALUATED.value, "{}"),
                )
        store.close()

    def test_the_engine_journals_the_plan_phase_after_the_run_row_exists(
        self, tmp_path: Path
    ) -> None:
        """The end-to-end path: hook → validate_plan → ``_open_run`` → journal.

        The run itself then fails at the fault step (there is no Kubernetes
        executor registered here, and this file certifies no cluster), which is
        beside the point: what it pins is that the plan-phase decision reached
        the journal at all, and that it landed *before* ``run.started``.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        resolver = FakeResolver({"checkout": [("checkout-00", False)]})
        ctx = _ctx(_admission(FakeAdmissionClient(_facts())))
        engine = RunEngine(
            store,
            SQLiteLeaseSink(store),
            safety=ctx,
            live_graph=_graph,
            k8s_resolver=resolver,
        )

        result = engine.execute(_plan())

        assert result.run_id == RUN_ID
        rows = store.query("SELECT kind FROM events WHERE run_id = ? ORDER BY id", (RUN_ID,))
        kinds = [str(dict(row)["kind"]) for row in rows]
        assert EventKind.CHECK_EVALUATED.value in kinds
        assert kinds.index(EventKind.CHECK_EVALUATED.value) < kinds.index(
            EventKind.RUN_STARTED.value
        )
        # And the decision was sealed, so "why was this run allowed" survives the
        # run row as well as the journal.
        assert verify_k8s_admission_chain(store, RUN_ID).valid
        store.close()


# ── 4. the sealing round trip ────────────────────────────────────────────────
def _outcomes(
    *, admitted: bool, client: FakeAdmissionClient
) -> tuple[list[ResolutionOutcome], Any]:
    """Drive one plan through the hook and hand back its resolver outcomes."""
    resolver = FakeResolver(
        {"checkout": [("checkout-00", False)] if admitted else [("a", False), ("b", False)]}
    )
    ctx = _ctx(_admission(client))
    plan = _plan()
    with plan_phase_admission(plan, ctx, lambda: resolver) as phase:
        with contextlib.suppress(SafetyRefusedError):
            validate_plan(plan, _graph(), phase.safety)
    return phase.notes, phase


class TestSealing:
    def test_a_refusal_is_sealed_with_its_rule_and_numbers_and_reverifies(
        self, tmp_path: Path
    ) -> None:
        store = _open_store(tmp_path)
        # Two pods against a floor of 9 of 10: expected availability 8 < 9.
        client = FakeAdmissionClient(_facts(pdb_min_available=9, replicas=10))
        _, phase = _outcomes(admitted=False, client=client)
        (outcome,) = phase.outcomes
        assert outcome.rule_id == "k8s.pdb_violation"

        sealed = seal_k8s_admission(store, RUN_ID, phase.outcomes, recorded_at=READING)

        assert sealed is not None
        assert sealed.valid
        assert not sealed.signed
        assert sealed.signature_state == "unsigned_no_signing"
        assert "no signature bytes" in sealed.signature_reason
        assert [e.event_kind for e in sealed.events] == [EVENT_K8S_ADMISSION_DECIDED]
        reloaded = load_k8s_admission(store, RUN_ID)
        assert reloaded is not None
        assert reloaded.chain_verification.valid
        assert reloaded.manifest_verification.valid
        assert reloaded.chain_root == sealed.chain_root
        assert reloaded.decisions[0]["rule_id"] == "k8s.pdb_violation"
        assert reloaded.decisions[0]["observed"]["pdb_min_available"] == 9
        assert reloaded.decisions[0]["observed"]["kill_count"] == 2
        assert reloaded.decisions[0]["step_id"] == "s1"
        store.close()

    def test_an_allow_is_sealed_too(self, tmp_path: Path) -> None:
        store = _open_store(tmp_path)
        client = FakeAdmissionClient(_facts())
        _, phase = _outcomes(admitted=True, client=client)
        (outcome,) = phase.outcomes
        assert outcome.admitted

        sealed = seal_k8s_admission(store, RUN_ID, phase.outcomes, recorded_at=READING)

        assert sealed is not None and sealed.valid
        reloaded = load_k8s_admission(store, RUN_ID)
        assert reloaded is not None
        assert reloaded.decisions[0]["admitted"] is True
        assert reloaded.decisions[0]["rule_id"] == RULE_ADMISSION_ALLOW
        assert reloaded.decisions[0]["targets"] == ["shop/checkout-00"]
        store.close()

    def test_a_two_step_plan_seals_one_event_per_step(self, tmp_path: Path) -> None:
        store = _open_store(tmp_path)
        plan = _plan(
            steps=(("s1", FAULT_ID, _scope("checkout")), ("s2", FAULT_ID, _scope("other")))
        )
        resolver = FakeResolver(
            {"checkout": [("checkout-00", False)], "other": [("other-00", False)]}
        )
        ctx = _ctx(_admission(FakeAdmissionClient(_facts())))
        with plan_phase_admission(plan, ctx, lambda: resolver) as phase:
            validate_plan(plan, _graph(), phase.safety)

        sealed = seal_k8s_admission(store, RUN_ID, phase.outcomes, recorded_at=READING)

        assert sealed is not None
        assert [str(e.payload["step_id"]) for e in sealed.events] == ["s1", "s2"]
        assert sealed.events[1].sequence == 1
        assert sealed.events[1].previous_digest == sealed.events[0].chain_link
        store.close()

    def test_the_chain_key_does_not_collide_with_the_run_evidence_chain(
        self, tmp_path: Path
    ) -> None:
        """One chain per run — so this lane's key is namespaced, not the run id.

        ``seal_run_evidence`` writes ``attestation_chains`` under the bare run id
        at run close. If the admission decision used that key it would replace the
        evidence chain (or be replaced by it) and be lost either way.
        """
        store = _open_store(tmp_path)
        client = FakeAdmissionClient(_facts())
        _, phase = _outcomes(admitted=True, client=client)

        seal_k8s_admission(store, RUN_ID, phase.outcomes, recorded_at=READING)
        rows = store.query("SELECT run_id FROM attestation_chains")

        assert [str(dict(row)["run_id"]) for row in rows] == [admission_chain_key(RUN_ID)]
        assert admission_chain_key(RUN_ID) != RUN_ID
        # The events still name the real run, so a reloaded row says which run it
        # describes even though the chain key is namespaced.
        rows = store.query(
            "SELECT event_json FROM attestation_events WHERE run_id = ?",
            (admission_chain_key(RUN_ID),),
        )
        assert all(RUN_ID in str(dict(row)["event_json"]) for row in rows)
        store.close()

    def test_nothing_is_sealed_when_there_is_nothing_to_seal(self, tmp_path: Path) -> None:
        store = _open_store(tmp_path)

        assert seal_k8s_admission(store, RUN_ID, (), recorded_at=READING) is None
        assert store.query("SELECT COUNT(*) AS n FROM attestation_chains")[0]["n"] == 0
        store.close()

    def test_the_hook_seals_on_the_allow_path(self, tmp_path: Path) -> None:
        store = _open_store(tmp_path)
        client = FakeAdmissionClient(_facts())
        resolver = FakeResolver({"checkout": [("checkout-00", False)]})
        ctx = _ctx(_admission(client))
        plan = _plan()

        with plan_phase_admission(
            plan,
            ctx,
            lambda: resolver,
            seal=lambda outcomes: seal_k8s_admission(store, RUN_ID, outcomes, recorded_at=READING),
        ) as phase:
            validate_plan(plan, _graph(), phase.safety)

        assert phase.seal is not None
        assert phase.seal.valid
        assert verify_k8s_admission_chain(store, RUN_ID).valid
        store.close()

    def test_the_hook_seals_a_refusal_too(self, tmp_path: Path) -> None:
        store = _open_store(tmp_path)
        client = FakeAdmissionClient(_facts(pdb_min_available=9))
        resolver = FakeResolver({"checkout": [("a", False), ("b", False)]})
        ctx = _ctx(_admission(client))
        plan = _plan()

        with pytest.raises(SafetyRefusedError):
            with plan_phase_admission(
                plan,
                ctx,
                lambda: resolver,
                seal=lambda outcomes: seal_k8s_admission(
                    store, RUN_ID, outcomes, recorded_at=READING
                ),
            ) as phase:
                validate_plan(plan, _graph(), phase.safety)

        assert phase.seal is not None
        assert phase.seal.decisions[0]["rule_id"] == "k8s.pdb_violation"
        assert phase.seal.decisions[0]["admitted"] is False
        store.close()


# ── 5. negative controls ─────────────────────────────────────────────────────
class TestNegativeControls:
    def test_a_blueprint_placeholder_is_refused_for_live_admission(self) -> None:
        """The plan's own invariant, asserted through this phase's evidence path.

        A manifest blueprint never resolves, so the gate refuses the step as
        ``k8s.no_live_target`` and the refusal names the step. An offline
        blueprint can plan; it can never be a live target.
        """
        client = FakeAdmissionClient(_facts())
        ctx = _ctx(_admission(client))
        plan = _plan()

        with pytest.raises(SafetyRefusedError) as excinfo:
            with plan_phase_admission(plan, ctx, lambda: FakeResolver({})) as phase:
                validate_plan(plan, _graph(), phase.safety)

        refusal = explain_fault_refusal(excinfo.value)
        assert refusal["rule_id"] == RULE_NO_LIVE_TARGET
        assert "step s1" in refusal["reason"]
        assert phase.unresolved_steps == ("s1",)
        # The exclusion bucket is Phase 1's; what this asserts is that the
        # evidence layer reads it rather than inventing a target.
        selection = K8sSelector().select([_blueprint_candidate()])
        assert selection.excluded[0].kind is K8sExclusionKind.BLUEPRINT

    def test_a_drift_only_selection_is_refused(self) -> None:
        """A step that matched but resolved nothing is drift, never a target."""
        client = FakeAdmissionClient(_facts())
        ctx = _ctx(_admission(client))
        plan = _plan()

        with pytest.raises(SafetyRefusedError) as excinfo:
            with plan_phase_admission(plan, ctx, lambda: FakeResolver({})) as phase:
                validate_plan(plan, _graph(), phase.safety)

        assert explain_fault_refusal(excinfo.value)["rule_id"] == RULE_NO_LIVE_TARGET
        assert phase.notes[0].resolved is False
        assert "could not be resolved" in phase.notes[0].drift_reason()

    def test_a_record_with_no_pod_uid_is_refused(self) -> None:
        client = FakeAdmissionClient(_facts())
        uidless = _resolved("checkout-00", uid="")
        assert uidless.pod_uid == ""
        ctx = _ctx(
            _admission(
                client,
                requests={"s1": K8sAdmissionRequest(workload=WORKLOAD, targets=(uidless,))},
            )
        )
        plan = _plan()

        with pytest.raises(SafetyRefusedError) as excinfo:
            validate_plan(plan, _graph(), ctx)

        refusal = explain_fault_refusal(excinfo.value)
        assert refusal["rule_id"] == RULE_NO_LIVE_TARGET
        assert "pod uid" in refusal["reason"]
        assert "step s1" in refusal["reason"]

    def test_a_refusal_for_an_unresolvable_step_names_the_step(self) -> None:
        client = FakeAdmissionClient(_facts())
        ctx = _ctx(_admission(client))
        plan = _plan()

        with pytest.raises(SafetyRefusedError) as excinfo:
            with plan_phase_admission(plan, ctx, lambda: FakeResolver({})) as phase:
                validate_plan(plan, _graph(), phase.safety)

        events = phase.events
        refusal = explain_fault_refusal(excinfo.value)
        assert "s1" in refusal["reason"]
        assert "step s1" in refusal["reason"]
        assert "s1" in refusal["inputs"]  # the recorded inputs carry it too
        drift = next(e for e in events if e.kind is EventKind.DRIFT_REPORTED)
        assert drift.detail["step"] == "s1"
        assert "s1" in str(drift.detail["reason"])
        assert phase.denied_steps == ("s1",)

    def test_an_unsealed_admission_decision_is_detectable(self, tmp_path: Path) -> None:
        store = _open_store(tmp_path)

        verification = verify_k8s_admission_chain(store, RUN_ID)

        assert not verification.valid
        assert "no chain stored" in "; ".join(verification.errors)
        assert load_k8s_admission(store, RUN_ID) is None
        store.close()

    def test_a_tampered_admission_chain_does_not_verify(self, tmp_path: Path) -> None:
        """The negative control the persistence layer exists for.

        A chain whose stored *bytes* were edited behind the model's back must be
        rejected by the persisted verifier, naming what failed. A store that only
        re-verified its own in-memory objects would pass every positive test above
        and still be worthless.
        """
        store = _open_store(tmp_path)
        client = FakeAdmissionClient(_facts())
        resolver = FakeResolver({"checkout": [("checkout-00", False)]})
        ctx = _ctx(_admission(client))
        plan = _plan()
        with plan_phase_admission(plan, ctx, lambda: resolver) as phase:
            validate_plan(plan, _graph(), phase.safety)
        seal_k8s_admission(store, RUN_ID, phase.outcomes, recorded_at=READING)
        assert verify_k8s_admission_chain(store, RUN_ID).valid

        rows = store.query(
            "SELECT event_json FROM attestation_events WHERE run_id = ? ORDER BY sequence",
            (admission_chain_key(RUN_ID),),
        )
        stored = AttestedEvent.model_validate_json(str(dict(rows[0])["event_json"]))
        forged = stored.model_copy(
            update={"payload": {**dict(stored.payload), "admitted": False, "rule_id": "forged"}}
        )
        with store.write() as conn:
            conn.execute(
                "UPDATE attestation_events SET event_json = ? WHERE run_id = ? AND sequence = 0",
                (forged.model_dump_json(), admission_chain_key(RUN_ID)),
            )

        verification = verify_k8s_admission_chain(store, RUN_ID)
        assert not verification.valid
        assert any("digest mismatch" in error for error in verification.errors)
        store.close()

    def test_a_seal_failure_surfaces_on_the_allow_path(self, tmp_path: Path) -> None:
        store = _open_store(tmp_path)
        client = FakeAdmissionClient(_facts())
        resolver = FakeResolver({"checkout": [("checkout-00", False)]})
        ctx = _ctx(_admission(client))
        plan = _plan()

        def exploding_seal(outcomes: tuple[Any, ...]) -> Any:
            raise RuntimeError("store unavailable")

        with pytest.raises(RuntimeError, match="store unavailable"):
            with plan_phase_admission(plan, ctx, lambda: resolver, seal=exploding_seal) as phase:
                validate_plan(plan, _graph(), phase.safety)
        assert phase.seal_error is not None
        store.close()

    def test_a_seal_failure_does_not_mask_a_refusal(self, tmp_path: Path) -> None:
        """A refused plan stays refused, and says its sealing failed."""
        store = _open_store(tmp_path)
        client = FakeAdmissionClient(_facts(pdb_min_available=9))
        resolver = FakeResolver({"checkout": [("a", False), ("b", False)]})
        ctx = _ctx(_admission(client))
        plan = _plan()

        def exploding_seal(outcomes: tuple[Any, ...]) -> Any:
            raise RuntimeError("store unavailable")

        with pytest.raises(SafetyRefusedError):
            with plan_phase_admission(plan, ctx, lambda: resolver, seal=exploding_seal) as phase:
                validate_plan(plan, _graph(), phase.safety)
        assert phase.seal_error is not None
        assert "store unavailable" in str(phase.seal_error)
        store.close()


# ── 6. honesty invariants that must survive this phase ───────────────────────
def test_the_adapter_is_still_unavailable_so_no_live_cluster_is_claimed() -> None:
    assert KubernetesAdapter().is_available() is False
