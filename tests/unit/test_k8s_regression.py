"""v1.1.0 plan 02 Phase 5 — fake-client suites, PDB regressions, negative controls.

What is pinned, all without a cluster:

1. **PDB-denial regressions**: the plan's headline arithmetic — kill 4 of 10
   with ``minAvailable`` 8 is denied showing expected-vs-required — at the pure
   rule level and through the real gate (``admit_k8s_fault`` with a fake fact
   client), for both PDB forms.
2. **Manifest-blueprint never-live negative control**: an offline manifest
   placeholder (``state="blueprint"`` off the manifest provider, and the
   ``BLUEPRINT``-sourced candidate) is never live-eligible, never selected,
   and refused at admission as ``k8s.no_live_target`` naming the bucket.
3. **Fake-client resolution suite**: the resolver driven by a fake
   ``K8sClusterClient`` resolves the scoped workload to evidence records with
   pod uids — the same records admission consumes.

What is *not* claimed: live cells via the 01 pipeline. The phase acceptance
requires first live-cluster cells certified in 01 before any "first-class"
claim ships; those do not exist, so the phase stays PARTIAL and this file
asserts the fake half only. ``KubernetesAdapter.is_available()`` stays
``False``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mayhem.agents.k8s_resolve import (
    K8sContainerStatus,
    K8sPod,
    K8sWorkload,
    KubernetesRuntimeResolver,
)
from mayhem.config import PolicyCfg
from mayhem.controller.k8s_admission import (
    K8sAdmissionInput,
    K8sAdmissionRequest,
    admit_k8s_fault,
    namespace_protection,
)
from mayhem.controller.safety import SafetyContext
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    PlannedFault,
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
    admit_workload_fault,
    check_pdb,
)
from mayhem.domain.resolution import ResolvedPodTarget
from mayhem.domain.target import ResourceKind, TargetScope
from mayhem.domain.topology import NodeKind, PodNode, TargetSelector

FAULT_ID = "k8s.pod_kill"


def _facts(**overrides: Any) -> WorkloadFacts:
    base: dict[str, Any] = {
        "name": "checkout",
        "namespace": "shop",
        "kind": WorkloadKind.DEPLOYMENT,
        "replicas": 10,
        "ready_replicas": 10,
        "updated_replicas": 10,
        "readiness_probe": True,
        "liveness_probe": True,
        "cluster_nodes_ready": 5,
        "cluster_nodes_total": 5,
    }
    base.update(overrides)
    return WorkloadFacts(**base)


def _targets(n: int) -> tuple[ResolvedPodTarget, ...]:
    return tuple(
        ResolvedPodTarget(
            namespace="shop",
            pod=f"checkout-{i:02d}",
            container="app",
            pod_uid=f"uid-checkout-{i:02d}",
        )
        for i in range(n)
    )


class FakeAdmissionClient:
    def __init__(self, facts: WorkloadFacts) -> None:
        self._facts = facts

    def workload_facts(self, workload: K8sWorkload) -> WorkloadFacts | None:
        return self._facts.model_copy(
            update={"namespace": workload.namespace, "name": workload.name}
        )


def _scope() -> TargetScope:
    return TargetScope(
        logical_id="checkout",
        runtime=RuntimeLabel.KUBERNETES,
        kind=ResourceKind.DEPLOYMENT,
        authority={
            "api_group": "apps",
            "kind": "deployment",
            "namespace": "shop",
            "name": "checkout",
        },
        container="app",
    )


def _fault() -> PlannedFault:
    selector = TargetSelector(kind=NodeKind.POD, expr="checkout")
    return PlannedFault(
        fault_id=FAULT_ID,
        targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"k8s::shop/pod/x"})),),
        target=_scope(),
        duration=5.0,
    )


def _admission(facts: WorkloadFacts, targets: tuple[ResolvedPodTarget, ...]) -> K8sAdmissionInput:
    workload = K8sWorkload(namespace="shop", kind="deployment", name="checkout")
    return K8sAdmissionInput(
        client=FakeAdmissionClient(facts),
        authorize=namespace_protection(),
        requests={"s1": K8sAdmissionRequest(workload=workload, targets=targets)},
    )


# ── 1. PDB-denial regressions ─────────────────────────────────────────────────
class TestPdbDenial:
    def test_kill_4_of_10_with_min_available_8_denies_with_the_arithmetic(self) -> None:
        verdict = check_pdb(_facts(pdb_min_available=8), kill_count=4)

        assert not verdict.admitted
        assert verdict.code == "k8s.pdb_violation"
        assert verdict.observed == 6
        assert verdict.required == 8
        assert "replicas=10" in verdict.reason
        assert "expected availability after fault = 6" in verdict.reason
        assert "PDB requires >= 8" in verdict.reason

    def test_the_max_unavailable_form_denies_the_same_fault(self) -> None:
        verdict = check_pdb(_facts(pdb_max_unavailable=2), kill_count=4)

        assert not verdict.admitted
        assert verdict.observed == 6
        assert verdict.required == 8  # 10 - maxUnavailable 2
        assert "maxUnavailable" in verdict.reason

    def test_a_fitting_kill_is_admitted(self) -> None:
        verdict = check_pdb(_facts(pdb_min_available=8), kill_count=2)

        assert verdict.admitted
        assert verdict.observed == 8

    def test_the_aggregate_gate_names_the_pdb_rule_first(self) -> None:
        verdict = admit_workload_fault(_facts(pdb_min_available=8), kill_count=4)

        assert not verdict.admitted
        assert verdict.code == "k8s.pdb_violation"

    def test_the_real_gate_refuses_the_plan_step_with_the_rule_and_numbers(self) -> None:
        outcome = admit_k8s_fault(
            "s1", _fault(), _admission(_facts(pdb_min_available=8), _targets(4))
        )

        assert not outcome.admitted
        assert outcome.rule_id == "k8s.pdb_violation"
        assert outcome.refusal is not None
        assert outcome.refusal.observed == 6
        assert outcome.refusal.required == 8
        assert outcome.targets == tuple(t.authority_key for t in _targets(4))

    def test_the_real_gate_admits_a_fitting_step(self) -> None:
        outcome = admit_k8s_fault(
            "s1", _fault(), _admission(_facts(pdb_min_available=8), _targets(2))
        )

        assert outcome.admitted
        assert outcome.rule_id == "k8s.admission_allow"


# ── 2. manifest-blueprint never-live negative control ─────────────────────────
def _blueprint_node() -> PodNode:
    return PodNode(
        id="k8s::shop/pod/checkout-blueprint",
        name="checkout-blueprint",
        kind=NodeKind.POD,
        state="blueprint",
        namespace="shop",
        owner_kind="Deployment",
        owner_name="checkout",
        node_name="",
    )


class TestBlueprintNeverLive:
    def test_a_blueprint_pod_node_projects_to_an_ineligible_candidate(self) -> None:
        candidate = K8sSelectionCandidate.from_pod_node(_blueprint_node())

        assert candidate.source is K8sTargetSource.BLUEPRINT
        assert candidate.is_blueprint
        assert not candidate.live_eligible

    def test_a_selector_over_only_blueprints_selects_nothing_explicitly(self) -> None:
        selection = K8sSelector().select([K8sSelectionCandidate.from_pod_node(_blueprint_node())])

        assert selection.targets == ()
        assert selection.is_empty
        assert selection.reason  # explicit, never an all-match fallback
        assert selection.excluded[0].kind is K8sExclusionKind.BLUEPRINT

    def test_a_live_pod_beside_a_blueprint_selects_only_the_live_pod(self) -> None:
        live = K8sSelectionCandidate(
            name="checkout-01",
            namespace="shop",
            target=ResolvedPodTarget(
                namespace="shop", pod="checkout-01", container="app", pod_uid="uid-01"
            ),
        )
        selection = K8sSelector().select(
            [K8sSelectionCandidate.from_pod_node(_blueprint_node()), live]
        )

        assert [t.pod for t in selection.targets] == ["checkout-01"]

    def test_an_unresolved_pin_is_drift_never_a_target(self) -> None:
        pin = K8sSelectionCandidate(
            name="checkout-09", namespace="shop", source=K8sTargetSource.UNRESOLVED
        )
        selection = K8sSelector().select([pin])

        assert selection.targets == ()
        assert selection.drift[0].kind.value == "drift"


# ── 3. fake-client resolution suite ───────────────────────────────────────────
class FakeClusterClient:
    """A fake `K8sClusterClient`: three Running pods, one terminating."""

    def workload(self, workload: K8sWorkload) -> K8sWorkload | None:
        return workload

    def pods_for(self, workload: K8sWorkload) -> list[K8sPod]:
        pods = [
            K8sPod(
                uid=f"uid-{name}",
                name=name,
                namespace="shop",
                phase="Running",
                node="node-0",
                containers=(K8sContainerStatus(name="app", container_id=f"containerd://{name}"),),
            )
            for name in ("checkout-00", "checkout-01", "checkout-02")
        ]
        return [
            *pods,
            K8sPod(
                uid="uid-terminating",
                name="checkout-99",
                namespace="shop",
                phase="Running",
                node="node-0",
                deletion_timestamp="2026-03-01T12:00:00Z",
                containers=(K8sContainerStatus(name="app"),),
            ),
        ]

    def exec(self, target: ResolvedPodTarget, argv: tuple[str, ...]) -> str:
        raise AssertionError("no exec in the resolution suite")

    def node(self, name: str) -> None:
        return None

    def nodes(self) -> list:
        return []


class TestFakeClientResolution:
    def test_resolve_many_returns_evidence_with_pod_uids(self) -> None:
        resolver = KubernetesRuntimeResolver(client=FakeClusterClient())  # type: ignore[arg-type]

        outcomes = resolver.resolve_many(_scope(), pod_action="pod_kill")

        assert len(outcomes) == 1  # mode-one: the deterministic first eligible pod
        (outcome,) = outcomes
        assert outcome.resolved is not None
        assert outcome.resolved.pod_uid == "uid-checkout-00"
        assert outcome.resolved.container_id == "containerd://checkout-00"

    def test_a_terminating_pod_is_never_resolved(self) -> None:
        resolver = KubernetesRuntimeResolver(client=FakeClusterClient())  # type: ignore[arg-type]

        outcomes = resolver.resolve_many(_scope(), pod_action="pod_kill")

        assert all(o.resolved.pod != "checkout-99" for o in outcomes if o.resolved is not None)

    def test_resolved_records_feed_admission(self) -> None:
        """The resolver-to-gate seam: resolved targets become the request the
        gate consumes, and a fitting kill is admitted end to seam-end."""
        resolver = KubernetesRuntimeResolver(client=FakeClusterClient())  # type: ignore[arg-type]
        outcomes = resolver.resolve_many(_scope(), pod_action="pod_kill")
        targets = tuple(o.resolved for o in outcomes if o.resolved is not None)
        assert targets

        outcome = admit_k8s_fault("s1", _fault(), _admission(_facts(), targets))

        assert outcome.admitted
        assert outcome.targets == ("shop/checkout-00",)

    def test_an_unknown_container_is_a_named_refusal(self) -> None:
        from mayhem.domain.errors import ResolutionError

        resolver = KubernetesRuntimeResolver(client=FakeClusterClient())  # type: ignore[arg-type]
        scope = _scope().model_copy(update={"container": "sidecar"})

        try:
            resolver.resolve_many(scope, pod_action="pod_kill")
        except ResolutionError as exc:
            assert exc.code == "resolution.container_missing"
        else:  # pragma: no cover — the resolver must refuse, not guess
            raise AssertionError("expected resolution.container_missing")


def _ctx() -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(max_services_pct=100.0),
        fingerprint="fp",
    )


def test_no_live_cluster_is_claimed_by_this_phase() -> None:
    assert KubernetesAdapter().is_available() is False
    assert _ctx().k8s_admission is None  # production still configures nothing


# ── 4. Phase 6 honesty gate: the ledger cannot inflate itself ─────────────────
PLAN_DOC = Path(__file__).resolve().parents[2] / "docs" / "v1.1.0" / "02_KUBERNETES_RUNTIME.md"
DOCS_README = Path(__file__).resolve().parents[2] / "docs" / "README.md"
EXAMPLES_README = Path(__file__).resolve().parents[2] / "examples" / "k8s" / "README.md"


class TestHonestyGate:
    def test_overall_count_matches_the_done_lines(self) -> None:
        """`Overall: N of 6` must equal the number of `- Phase N: DONE` lines,
        so a phase marked PARTIAL can never be counted by accident."""
        import re

        text = PLAN_DOC.read_text(encoding="utf-8")
        done = re.findall(r"^- Phase \d+.*: DONE", text, flags=re.MULTILINE)
        (overall,) = re.findall(r"^Overall: (\d+) of 6 phases complete", text, flags=re.MULTILINE)
        assert int(overall) == len(done) > 0

    def test_the_doc_names_its_open_debt_and_no_live_acceptance(self) -> None:
        text = PLAN_DOC.read_text(encoding="utf-8").lower()
        assert "open debt register" in text
        assert "no live cluster has been accepted" in text
        assert "live cells" in text  # the live half is named, not implied

    def test_no_live_execution_row_without_certified_cells(self) -> None:
        """The phase text allows the README row only with certified cells."""
        assert "| live execution |" not in DOCS_README.read_text(encoding="utf-8").lower()

    def test_the_example_still_disclaims_live_acceptance(self) -> None:
        text = EXAMPLES_README.read_text(encoding="utf-8")
        assert "not live acceptance" in text or "not a claim" in text
