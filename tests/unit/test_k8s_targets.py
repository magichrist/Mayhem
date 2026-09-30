"""v1.1.0 plan 02 phase 1 — Kubernetes selectors and workload-safety facts.

The plan's acceptance for this phase is "property tests over selector
combinations; the PDB denial test shows expected availability vs. required".
These tests pin that, plus the honesty rules the plan inherits from the
existing Kubernetes status vocabulary (docs/README.md):

  1. selector match / miss per dimension, and percentage / random selection
     deterministic under an *injected* seed (never wall-clock, never the
     global RNG);
  2. workload-safety refusals — PDB, StatefulSet semantics, DaemonSet
     awareness, anti-affinity, topology spread, cluster health — each showing
     the observed numbers;
  3. the exact-arithmetic PDB refusal from the plan's headline example;
  4. negative controls: an unresolved target is drift, a manifest blueprint
     placeholder is never live-eligible, and a selector matching nothing is an
     explicit empty selection, never a silent all-match.
"""

from __future__ import annotations

import random
from typing import Any

import pytest

from mayhem.domain.errors import InvariantViolationError, SelectionError
from mayhem.domain.k8s_targets import (
    EMPTY_SELECTION_REASON,
    K8sAdmissionCheck,
    K8sAdmissionVerdict,
    K8sExclusionKind,
    K8sSelectionCandidate,
    K8sSelector,
    K8sTargetSource,
    TopologySpreadConstraint,
    WorkloadFacts,
    WorkloadKind,
    admit_workload_fault,
    check_anti_affinity,
    check_cluster_health,
    check_daemonset_coverage,
    check_pdb,
    check_statefulset_ordinal,
    check_topology_spread,
    evaluate_workload_admission,
)
from mayhem.domain.resolution import ResolvedPodTarget
from mayhem.domain.target import SelectionMode, SelectionSpec
from mayhem.domain.topology import PodNode


def _candidate(
    name: str,
    *,
    namespace: str = "shop",
    node: str = "node-a",
    zone: str = "us-east-1a",
    region: str = "us-east-1",
    labels: dict[str, str] | None = None,
    annotations: dict[str, str] | None = None,
    kind: WorkloadKind = WorkloadKind.DEPLOYMENT,
    workload: str = "checkout",
    state: str = "running",
    source: K8sTargetSource = K8sTargetSource.LIVE,
    with_target: bool = True,
) -> K8sSelectionCandidate:
    """A live resolved candidate — the shape the selector is meant to consume."""
    resolved = (
        ResolvedPodTarget(
            namespace=namespace,
            pod=name,
            container="app",
            pod_uid=f"uid-{name}",
            container_id=f"containerd://{name}",
            node=node,
        )
        if with_target
        else None
    )
    return K8sSelectionCandidate(
        name=name,
        namespace=namespace,
        target=resolved,
        source=source,
        state=state,
        labels=dict(labels or {}),
        annotations=dict(annotations or {}),
        workload_kind=kind,
        workload_name=workload,
        node=node,
        zone=zone,
        region=region,
    )


def _fleet(count: int, **kwargs: Any) -> tuple[K8sSelectionCandidate, ...]:
    return tuple(_candidate(f"checkout-{index:02d}", **kwargs) for index in range(count))


def _facts(**kwargs: Any) -> WorkloadFacts:
    base: dict[str, Any] = {"name": "checkout", "namespace": "shop"}
    base.update(kwargs)
    return WorkloadFacts(**base)


# ── 1. selector dimensions ──────────────────────────────────────────────────
class TestSelectorDimensions:
    def test_empty_selector_matches_every_candidate(self) -> None:
        selector = K8sSelector()
        assert all(selector.matches(c) for c in _fleet(5))

    def test_name_dimension_matches_and_misses(self) -> None:
        selector = K8sSelector(name="checkout-02")
        assert selector.matches(_candidate("checkout-02"))
        assert not selector.matches(_candidate("checkout-03"))

    def test_namespace_dimension_matches_and_misses(self) -> None:
        selector = K8sSelector(namespace="shop")
        assert selector.matches(_candidate("checkout-00"))
        assert not selector.matches(_candidate("checkout-00", namespace="billing"))

    def test_workload_kind_dimension_matches_and_misses(self) -> None:
        selector = K8sSelector(workload_kind=WorkloadKind.STATEFULSET)
        assert selector.matches(_candidate("db-0", kind=WorkloadKind.STATEFULSET))
        assert not selector.matches(_candidate("db-1", kind=WorkloadKind.DEPLOYMENT))

    def test_workload_name_dimension_matches_and_misses(self) -> None:
        selector = K8sSelector(workload_name="checkout")
        assert selector.matches(_candidate("checkout-00", workload="checkout"))
        assert not selector.matches(_candidate("cart-00", workload="cart"))

    def test_labels_use_subset_semantics(self) -> None:
        selector = K8sSelector(labels={"app": "checkout", "tier": "backend"})
        assert selector.matches(
            _candidate("checkout-00", labels={"app": "checkout", "tier": "backend", "x": "1"})
        )
        # a missing pair is a miss, an extra observed label is not
        assert not selector.matches(_candidate("checkout-00", labels={"app": "checkout"}))
        assert not selector.matches(
            _candidate("checkout-00", labels={"app": "checkout", "tier": "edge"})
        )

    def test_annotations_dimension_matches_and_misses(self) -> None:
        selector = K8sSelector(annotations={"mayhem.dev/owner": "sre"})
        assert selector.matches(
            _candidate("checkout-00", annotations={"mayhem.dev/owner": "sre"})
        )
        assert not selector.matches(
            _candidate("checkout-00", annotations={"mayhem.dev/owner": "platform"})
        )

    def test_node_dimension_matches_and_misses(self) -> None:
        selector = K8sSelector(node="node-b")
        assert selector.matches(_candidate("checkout-00", node="node-b"))
        assert not selector.matches(_candidate("checkout-00", node="node-a"))

    def test_zone_dimension_matches_and_misses(self) -> None:
        selector = K8sSelector(zones=("us-east-1b", "us-west-2a"))
        assert selector.matches(_candidate("checkout-00", zone="us-west-2a"))
        assert not selector.matches(_candidate("checkout-00", zone="us-east-1a"))

    def test_region_dimension_matches_and_misses(self) -> None:
        selector = K8sSelector(regions=("eu-west-1",))
        assert selector.matches(_candidate("checkout-00", region="eu-west-1"))
        assert not selector.matches(_candidate("checkout-00", region="us-east-1"))

    def test_dimensions_compose_as_a_conjunction(self) -> None:
        selector = K8sSelector(
            namespace="shop",
            workload_kind=WorkloadKind.DEPLOYMENT,
            labels={"app": "checkout"},
            zones=("us-east-1a",),
        )
        assert selector.matches(
            _candidate("checkout-00", labels={"app": "checkout"}, zone="us-east-1a")
        )
        assert not selector.matches(
            _candidate("checkout-00", labels={"app": "checkout"}, zone="us-west-2a")
        )

    def test_render_is_stable_and_names_every_stated_dimension(self) -> None:
        selector = K8sSelector(
            namespace="shop",
            workload_kind=WorkloadKind.DEPLOYMENT,
            workload_name="checkout",
            labels={"app": "checkout"},
            zones=("us-east-1a",),
            selection=SelectionSpec(mode=SelectionMode.PERCENTAGE, percentage=30),
        )
        rendered = selector.render()
        assert rendered == selector.render()
        for fragment in ("ns=shop", "workload=deployment/checkout", "label:app=checkout"):
            assert fragment in rendered
        assert "zone in {us-east-1a}" in rendered
        assert "selection:percentage" in rendered


class TestSelectorOrdering:
    def test_selection_is_ordered_by_namespace_name_uid(self) -> None:
        candidates = (
            _candidate("checkout-10"),
            _candidate("checkout-02"),
            _candidate("checkout-01"),
        )
        selection = K8sSelector(selection=SelectionSpec(mode=SelectionMode.ALL)).select(
            candidates
        )
        assert selection.authority_keys == (
            "shop/checkout-01",
            "shop/checkout-02",
            "shop/checkout-10",
        )

    def test_input_order_does_not_change_the_result(self) -> None:
        candidates = _fleet(6)
        forwards = K8sSelector(selection=SelectionSpec(mode=SelectionMode.ALL)).select(candidates)
        backwards = K8sSelector(selection=SelectionSpec(mode=SelectionMode.ALL)).select(
            tuple(reversed(candidates))
        )
        assert forwards.authority_keys == backwards.authority_keys


# ── 2. percentage and random selection ──────────────────────────────────────
class TestPercentageSelection:
    def test_percentage_uses_ceiling(self) -> None:
        selection = K8sSelector(
            selection=SelectionSpec(mode=SelectionMode.PERCENTAGE, percentage=25)
        ).select(_fleet(10))
        assert len(selection.targets) == 3  # ceil(2.5)

    def test_percentage_always_selects_at_least_one(self) -> None:
        selection = K8sSelector(
            selection=SelectionSpec(mode=SelectionMode.PERCENTAGE, percentage=1)
        ).select(_fleet(3))
        assert len(selection.targets) == 1

    def test_percentage_cannot_exceed_the_eligible_set(self) -> None:
        selection = K8sSelector(
            selection=SelectionSpec(mode=SelectionMode.PERCENTAGE, percentage=100)
        ).select(_fleet(4))
        assert len(selection.targets) == 4

    def test_percentage_is_deterministic(self) -> None:
        selector = K8sSelector(
            selection=SelectionSpec(mode=SelectionMode.PERCENTAGE, percentage=40)
        )
        first = selector.select(_fleet(10))
        second = selector.select(_fleet(10))
        assert first.authority_keys == second.authority_keys
        assert len(first.targets) == 4

    def test_count_selection_and_overshoot_refusal(self) -> None:
        selector = K8sSelector(selection=SelectionSpec(mode=SelectionMode.COUNT, count=3))
        assert len(selector.select(_fleet(10)).targets) == 3
        overshoot = K8sSelector(selection=SelectionSpec(mode=SelectionMode.COUNT, count=11))
        with pytest.raises(SelectionError) as excinfo:
            overshoot.select(_fleet(10))
        assert excinfo.value.code == "selection.count_exceeds_eligible"


class TestRandomSelection:
    def test_same_seed_selects_the_same_pod(self) -> None:
        selector = K8sSelector(selection=SelectionSpec(mode=SelectionMode.RANDOM))
        candidates = _fleet(10)
        first = selector.select(candidates, seed=42)
        second = selector.select(candidates, seed=42)
        assert first.authority_keys == second.authority_keys
        assert len(first.targets) == 1

    def test_seed_is_ignored_by_the_global_rng(self) -> None:
        """A wall-clock / global-RNG draw would break replay; prove we do not use one."""
        selector = K8sSelector(selection=SelectionSpec(mode=SelectionMode.RANDOM))
        candidates = _fleet(10)
        random.seed(1)
        first = selector.select(candidates, seed=7)
        random.seed(99999)
        second = selector.select(candidates, seed=7)
        random.setstate(random.Random(0).getstate())
        assert first.authority_keys == second.authority_keys
        assert first.targets[0].authority_key in {c.target.authority_key for c in candidates}

    def test_random_refuses_without_an_injected_seed(self) -> None:
        selector = K8sSelector(selection=SelectionSpec(mode=SelectionMode.RANDOM))
        with pytest.raises(SelectionError) as excinfo:
            selector.select(_fleet(5))
        assert excinfo.value.code == "selection.seed_required"
        assert "unreplayable" in str(excinfo.value)

    def test_different_seeds_can_differ_without_being_unstable(self) -> None:
        selector = K8sSelector(selection=SelectionSpec(mode=SelectionMode.RANDOM))
        candidates = _fleet(20)
        picks = {selector.select(candidates, seed=seed).authority_keys for seed in range(5)}
        assert len(picks) > 1  # the seed is actually honoured
        # each pick is stable on its own
        for seed in range(5):
            assert selector.select(candidates, seed=seed).authority_keys in picks


# ── 3. the headline PDB rule, with exact arithmetic ─────────────────────────
class TestPdbRule:
    def test_refusal_shows_the_exact_arithmetic(self) -> None:
        facts = _facts(kind=WorkloadKind.DEPLOYMENT, replicas=10, pdb_min_available=8)
        verdict = check_pdb(facts, kill_count=4)
        assert not verdict.admitted
        assert verdict.reason == (
            "replicas=10, PDB minAvailable=8, requested kill 4 → DENY, "
            "expected availability after fault = 6, PDB requires >= 8"
        )
        assert verdict.observed == 6
        assert verdict.required == 8
        assert verdict.check is K8sAdmissionCheck.PDB
        assert verdict.code == "k8s.pdb_violation"

    def test_refusal_names_the_workload_and_the_kill_count(self) -> None:
        facts = _facts(replicas=10, pdb_min_available=8)
        verdict = check_pdb(facts, kill_count=4)
        assert verdict.workload == "shop/checkout"
        assert verdict.kill_count == 4
        assert "DENY" in verdict.summary
        assert "k8s.pdb_violation" in verdict.summary

    def test_admits_exactly_at_the_boundary(self) -> None:
        facts = _facts(replicas=10, pdb_min_available=8)
        verdict = check_pdb(facts, kill_count=2)
        assert verdict.admitted
        assert verdict.observed == 8
        assert "expected availability after fault = 8, PDB requires >= 8" in verdict.reason

    def test_one_over_the_boundary_is_refused(self) -> None:
        facts = _facts(replicas=10, pdb_min_available=8)
        assert not check_pdb(facts, kill_count=3).admitted

    def test_kill_larger_than_replicas_reports_negative_availability(self) -> None:
        facts = _facts(replicas=3, pdb_min_available=1)
        verdict = check_pdb(facts, kill_count=5)
        assert not verdict.admitted
        assert "expected availability after fault = -2" in verdict.reason

    def test_max_unavailable_form_converts_to_a_floor(self) -> None:
        facts = _facts(replicas=10, pdb_max_unavailable=3)
        assert facts.pdb_required_available == 7
        verdict = check_pdb(facts, kill_count=4)
        assert not verdict.admitted
        assert "PDB maxUnavailable=7" in verdict.reason
        assert check_pdb(facts, kill_count=3).admitted

    def test_no_pdb_admits_and_says_so(self) -> None:
        verdict = check_pdb(_facts(replicas=10), kill_count=4)
        assert verdict.admitted
        assert "no PodDisruptionBudget" in verdict.reason

    def test_zero_kill_admits_even_against_a_tight_pdb(self) -> None:
        assert check_pdb(_facts(replicas=10, pdb_min_available=10), kill_count=0).admitted

    def test_non_replica_gated_kinds_are_not_pdb_gated(self) -> None:
        for kind in (WorkloadKind.JOB, WorkloadKind.POD):
            verdict = check_pdb(_facts(kind=kind, replicas=10, pdb_min_available=8), kill_count=4)
            assert verdict.admitted
            assert "not PDB-gated" in verdict.reason

    def test_both_pdb_forms_are_refused_at_construction(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _facts(replicas=10, pdb_min_available=8, pdb_max_unavailable=2)
        assert excinfo.value.rule == "k8s.pdb_forms_exclusive"


# ── 4. workload-kind semantics and the other safety rules ───────────────────
class TestStatefulSetSemantics:
    def test_two_identities_in_one_disruption_are_refused(self) -> None:
        facts = _facts(kind=WorkloadKind.STATEFULSET, replicas=3)
        verdict = check_statefulset_ordinal(facts, kill_count=2)
        assert not verdict.admitted
        assert verdict.code == "k8s.statefulset_rollout_exceeded"
        assert "replicas=3, StatefulSet rollout budget=1, requested kill 2 → DENY" in verdict.reason
        assert "expected available stable identities after fault = 1" in verdict.reason

    def test_one_identity_is_within_the_rollout_budget(self) -> None:
        facts = _facts(kind=WorkloadKind.STATEFULSET, replicas=3)
        assert check_statefulset_ordinal(facts, kill_count=1).admitted

    def test_a_wider_declared_budget_is_honoured(self) -> None:
        facts = _facts(kind=WorkloadKind.STATEFULSET, replicas=5, statefulset_rollout_budget=2)
        assert check_statefulset_ordinal(facts, kill_count=2).admitted
        assert not check_statefulset_ordinal(facts, kill_count=3).admitted

    def test_deployments_carry_no_stable_identity(self) -> None:
        verdict = check_statefulset_ordinal(
            _facts(kind=WorkloadKind.DEPLOYMENT, replicas=3), kill_count=5
        )
        assert verdict.admitted


class TestDaemonSetAwareness:
    def test_total_coverage_loss_is_refused(self) -> None:
        facts = _facts(
            kind=WorkloadKind.DAEMONSET,
            replicas=3,
            daemonset_nodes_ready=3,
            daemonset_nodes_total=3,
        )
        verdict = check_daemonset_coverage(facts, kill_count=3)
        assert not verdict.admitted
        assert verdict.code == "k8s.daemonset_coverage_lost"
        assert "replicas(healthy DaemonSet nodes)=3, requested kill 3 → DENY" in verdict.reason
        assert "expected DaemonSet coverage after fault = 0 of 3" in verdict.reason
        assert "node-bound" in verdict.reason

    def test_partial_coverage_loss_is_admitted(self) -> None:
        facts = _facts(
            kind=WorkloadKind.DAEMONSET,
            replicas=3,
            daemonset_nodes_ready=3,
            daemonset_nodes_total=3,
        )
        verdict = check_daemonset_coverage(facts, kill_count=2)
        assert verdict.admitted
        assert "expected DaemonSet coverage after fault = 1 of 3" in verdict.reason

    def test_tolerated_total_loss_is_admitted(self) -> None:
        facts = _facts(
            kind=WorkloadKind.DAEMONSET,
            replicas=2,
            daemonset_nodes_ready=2,
            daemonset_nodes_total=2,
            daemonset_tolerates_total_loss=True,
        )
        assert check_daemonset_coverage(facts, kill_count=2).admitted

    def test_deployments_are_not_node_bound(self) -> None:
        verdict = check_daemonset_coverage(
            _facts(kind=WorkloadKind.DEPLOYMENT, replicas=3), kill_count=3
        )
        assert verdict.admitted
        assert "not node-bound" in verdict.reason


class TestAntiAffinity:
    def test_required_anti_affinity_refuses_when_no_domain_is_free(self) -> None:
        facts = _facts(
            replicas=10,
            required_anti_affinity=True,
            anti_affinity_domains=3,
        )
        verdict = check_anti_affinity(facts, kill_count=1)
        assert not verdict.admitted
        assert verdict.code == "k8s.anti_affinity_no_free_domain"
        assert "required anti-affinity topology domains=3" in verdict.reason
        assert "expected free domains for replacement = 0" in verdict.reason

    def test_required_anti_affinity_admits_while_a_domain_is_free(self) -> None:
        facts = _facts(replicas=3, required_anti_affinity=True, anti_affinity_domains=6)
        verdict = check_anti_affinity(facts, kill_count=2)
        assert verdict.admitted
        assert verdict.observed == 3

    def test_preferred_anti_affinity_is_soft(self) -> None:
        facts = _facts(
            replicas=10, preferred_anti_affinity=True, anti_affinity_domains=3
        )
        verdict = check_anti_affinity(facts, kill_count=4)
        assert verdict.admitted
        assert "soft" in verdict.reason

    def test_no_anti_affinity_admits(self) -> None:
        assert check_anti_affinity(_facts(replicas=10), kill_count=4).admitted


class TestTopologySpread:
    def test_strict_spread_refuses_beyond_max_skew(self) -> None:
        facts = _facts(
            replicas=6,
            topology_spread=(
                TopologySpreadConstraint(
                    topology_key="topology.kubernetes.io/zone", max_skew=1
                ),
            ),
            topology_spread_domains=3,
        )
        # DoNotSchedule defaults to False — make the constraint strict.
        strict = facts.model_copy(
            update={
                "topology_spread": (
                    TopologySpreadConstraint(
                        topology_key="topology.kubernetes.io/zone",
                        max_skew=1,
                        do_not_schedule=True,
                    ),
                )
            }
        )
        verdict = check_topology_spread(strict, kill_count=2)
        assert not verdict.admitted
        assert verdict.code == "k8s.topology_spread_blocked"
        assert "maxSkew=1 (DoNotSchedule)" in verdict.reason
        assert "expected available replicas after fault = 4" in verdict.reason
        assert "scheduler requires maxSkew <= 1 across 3 domain(s)" in verdict.reason
        # the non-strict original is a hint and admits
        assert check_topology_spread(facts, kill_count=2).admitted

    def test_strict_spread_admits_within_max_skew(self) -> None:
        facts = _facts(
            replicas=6,
            topology_spread=(
                TopologySpreadConstraint(topology_key="zone", max_skew=2, do_not_schedule=True),
            ),
            topology_spread_domains=3,
        )
        assert check_topology_spread(facts, kill_count=2).admitted

    def test_no_constraint_admits(self) -> None:
        assert check_topology_spread(_facts(replicas=6), kill_count=5).admitted


class TestClusterHealth:
    def test_degraded_cluster_refuses_and_shows_the_counts(self) -> None:
        facts = _facts(replicas=10, cluster_nodes_ready=2, cluster_nodes_total=3)
        verdict = check_cluster_health(facts, kill_count=1)
        assert not verdict.admitted
        assert verdict.code == "k8s.cluster_degraded"
        assert "cluster nodes ready=2/3, requested kill 1 → DENY" in verdict.reason
        assert "expected healthy nodes after fault = 1" in verdict.reason

    def test_acknowledged_degradation_admits(self) -> None:
        facts = _facts(
            replicas=10,
            cluster_nodes_ready=2,
            cluster_nodes_total=3,
            cluster_degradation_acknowledged=True,
        )
        assert check_cluster_health(facts, kill_count=1).admitted

    def test_healthy_cluster_admits(self) -> None:
        facts = _facts(replicas=10, cluster_nodes_ready=3, cluster_nodes_total=3)
        verdict = check_cluster_health(facts, kill_count=2)
        assert verdict.admitted
        assert "no pre-existing degradation" in verdict.reason

    def test_unknown_cluster_size_admits(self) -> None:
        assert check_cluster_health(_facts(replicas=10), kill_count=2).admitted


class TestAggregateAdmission:
    def test_first_refusal_wins_and_is_the_most_specific_rule(self) -> None:
        facts = _facts(
            kind=WorkloadKind.STATEFULSET,
            replicas=10,
            pdb_min_available=8,
            cluster_nodes_ready=1,
            cluster_nodes_total=3,
        )
        verdict = admit_workload_fault(facts, kill_count=4)
        assert not verdict.admitted
        assert verdict.check is K8sAdmissionCheck.PDB

    def test_a_clean_workload_is_admitted(self) -> None:
        facts = _facts(replicas=10, pdb_min_available=8, cluster_nodes_ready=3)
        facts = facts.model_copy(update={"cluster_nodes_total": 3})
        verdict = admit_workload_fault(facts, kill_count=2)
        assert verdict.admitted
        assert "every workload-safety rule holds" in verdict.reason
        assert verdict.observed == 8

    def test_every_rule_is_evaluated_in_order(self) -> None:
        facts = _facts(
            kind=WorkloadKind.STATEFULSET,
            replicas=10,
            pdb_min_available=8,
            required_anti_affinity=True,
            anti_affinity_domains=3,
            topology_spread=(
                TopologySpreadConstraint(topology_key="zone", do_not_schedule=True),
            ),
            topology_spread_domains=3,
            cluster_nodes_ready=1,
            cluster_nodes_total=3,
        )
        verdicts = evaluate_workload_admission(facts, kill_count=4)
        assert [v.check for v in verdicts] == [
            K8sAdmissionCheck.PDB,
            K8sAdmissionCheck.STATEFULSET_ORDINAL,
            K8sAdmissionCheck.DAEMONSET_COVERAGE,
            K8sAdmissionCheck.ANTI_AFFINITY,
            K8sAdmissionCheck.TOPOLOGY_SPREAD,
            K8sAdmissionCheck.CLUSTER_HEALTH,
        ]
        assert not verdicts[0].admitted
        assert not verdicts[1].admitted
        assert verdicts[2].admitted  # a StatefulSet is not node-bound
        assert not verdicts[3].admitted
        assert not verdicts[4].admitted
        assert not verdicts[5].admitted

    def test_the_gate_is_pure(self) -> None:
        facts = _facts(replicas=10, pdb_min_available=8)
        first = admit_workload_fault(facts, kill_count=4)
        second = admit_workload_fault(facts, kill_count=4)
        assert first.model_dump() == second.model_dump()

    def test_verdicts_are_frozen_value_objects(self) -> None:
        verdict = K8sAdmissionVerdict.admit(K8sAdmissionCheck.PDB, note="fine")
        with pytest.raises(ValueError):
            verdict.admitted = False  # type: ignore[misc]


class TestWorkloadKindSemantics:
    @pytest.mark.parametrize(
        ("kind", "node_bound", "ordered"),
        [
            (WorkloadKind.DEPLOYMENT, False, False),
            (WorkloadKind.STATEFULSET, False, True),
            (WorkloadKind.DAEMONSET, True, False),
            (WorkloadKind.JOB, False, False),
            (WorkloadKind.POD, False, False),
        ],
    )
    def test_kind_flags(self, kind: WorkloadKind, node_bound: bool, ordered: bool) -> None:
        assert kind.node_bound is node_bound
        assert kind.ordered_identity is ordered

    def test_parse_accepts_the_api_camelcase_label(self) -> None:
        assert WorkloadKind.parse("StatefulSet") is WorkloadKind.STATEFULSET
        assert WorkloadKind.parse("DaemonSet") is WorkloadKind.DAEMONSET
        assert WorkloadKind.parse("Deployment") is WorkloadKind.DEPLOYMENT
        assert WorkloadKind.parse("statefulset") is WorkloadKind.STATEFULSET

    def test_parse_is_lenient_about_unknown_kinds(self) -> None:
        assert WorkloadKind.parse("ReplicaSet") is None
        assert WorkloadKind.parse("") is None
        assert WorkloadKind.parse(None) is None


# ── 5. negative controls ────────────────────────────────────────────────────
class TestNegativeControls:
    def test_an_unresolved_candidate_is_drift_not_a_target(self) -> None:
        candidate = K8sSelectionCandidate(
            name="checkout-00",
            namespace="shop",
            target=None,
            source=K8sTargetSource.UNRESOLVED,
        )
        assert not candidate.live_eligible
        selection = K8sSelector().select((candidate,))
        assert selection.targets == ()
        assert selection.matched == 1
        assert selection.eligible == 0
        assert selection.is_empty
        drift = selection.drift
        assert len(drift) == 1
        assert drift[0].kind is K8sExclusionKind.DRIFT
        assert "drift, not a target" in drift[0].reason

    def test_drift_never_leaks_into_targets_even_alongside_live_pods(self) -> None:
        candidates = (
            _candidate("checkout-00"),
            _candidate("checkout-01", with_target=False, source=K8sTargetSource.UNRESOLVED),
            _candidate("checkout-02"),
        )
        selection = K8sSelector(selection=SelectionSpec(mode=SelectionMode.ALL)).select(candidates)
        assert selection.authority_keys == ("shop/checkout-00", "shop/checkout-02")
        assert len(selection.drift) == 1
        assert selection.exclusion_summary() == "selected 2 of 2 eligible, 1 drift"

    def test_a_blueprint_placeholder_is_never_live_eligible(self) -> None:
        """The offline manifest graph (k8s_manifest.py) must not select live pods."""
        blueprint = PodNode(
            id="k8s::workload/shop/deployment/checkout",
            name="checkout",
            namespace="shop",
            state="blueprint",
            owner_kind="Deployment",
            owner_name="checkout",
            labels={"app": "checkout"},
        )
        candidate = K8sSelectionCandidate.from_pod_node(blueprint)
        assert candidate.source is K8sTargetSource.BLUEPRINT
        assert candidate.is_blueprint
        assert not candidate.live_eligible

        selection = K8sSelector(selection=SelectionSpec(mode=SelectionMode.ALL)).select(
            (candidate,)
        )
        assert selection.targets == ()
        assert selection.matched == 1
        assert selection.eligible == 0
        excluded = selection.excluded
        assert len(excluded) == 1
        assert excluded[0].kind is K8sExclusionKind.BLUEPRINT
        assert "manifest blueprint placeholder" in excluded[0].reason

    def test_a_blueprint_stays_ineligible_even_when_a_target_is_attached(self) -> None:
        """Defence in depth: a resolved target cannot override the blueprint state."""
        resolved = ResolvedPodTarget(namespace="shop", pod="checkout", container="app")
        candidate = K8sSelectionCandidate(
            name="checkout",
            namespace="shop",
            target=resolved,
            source=K8sTargetSource.LIVE,
            state="blueprint",
        )
        assert not candidate.live_eligible
        assert K8sSelector().select((candidate,)).targets == ()

    def test_a_selector_matching_nothing_is_an_explicit_empty_selection(self) -> None:
        candidates = _fleet(5, labels={"app": "checkout"})
        selector = K8sSelector(labels={"app": "payments"})
        selection = selector.select(candidates)
        assert selection.targets == ()
        assert selection.is_empty
        assert selection.matched == 0
        assert selection.eligible == 0
        assert selection.reason == EMPTY_SELECTION_REASON

    def test_an_empty_selection_is_never_a_silent_all_match(self) -> None:
        candidates = _fleet(5, labels={"app": "checkout"})
        selector = K8sSelector(labels={"app": "payments"})
        for spec in (
            SelectionSpec(mode=SelectionMode.ONE),
            SelectionSpec(mode=SelectionMode.ALL),
            SelectionSpec(mode=SelectionMode.COUNT, count=4),
            SelectionSpec(mode=SelectionMode.PERCENTAGE, percentage=80),
        ):
            selection = selector.model_copy(update={"selection": spec}).select(
                candidates, seed=1
            )
            assert selection.targets == ()
            assert selection.reason == EMPTY_SELECTION_REASON

    def test_selection_over_no_candidates_is_empty_not_an_error(self) -> None:
        selection = K8sSelector().select(())
        assert selection.is_empty
        assert selection.reason == EMPTY_SELECTION_REASON
        assert selection.eligible == 0

    def test_a_matching_candidate_that_is_not_live_is_reported_not_selected(self) -> None:
        """A source that is neither live nor blueprint still cannot become a target."""
        candidate = K8sSelectionCandidate(
            name="checkout-00",
            namespace="shop",
            target=None,
            source=K8sTargetSource.UNRESOLVED,
            state="terminating",
        )
        selection = K8sSelector().select((candidate,))
        assert selection.targets == ()
        assert selection.excluded[0].kind is K8sExclusionKind.DRIFT
