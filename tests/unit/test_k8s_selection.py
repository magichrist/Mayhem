"""Mode-one selection + planner eligibility gate for kubernetes targets.

Mirrors k-plan-2 §2.5: workload present ⇒ ≥1 Running, non-terminating pod,
or ``selection.*`` :class:`SelectionError` at plan time. Absent workload ⇒
logically pinned (returns None / plans fine), resolved at execution.
"""

from __future__ import annotations

import pytest

from mayhem.controller.planner import _gate_k8s_selection_eligibility
from mayhem.domain.errors import SelectionError
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.target import ResourceKind, SelectionMode, TargetScope
from mayhem.domain.target_selector import select_one
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    PodNode,
    ServiceNode,
    TopologyGraph,
)


def _pod(
    name: str,
    *,
    state: str = "Running",
    owner: str = "checkout",
    deletion_timestamp: str | None = None,
) -> PodNode:
    return PodNode(
        id=f"k8s::pod/checkout/{name}",
        name=name,
        kind=NodeKind.POD,
        state=state,
        namespace="checkout",
        owner_kind="Deployment",
        owner_name=owner,
        deletion_timestamp=deletion_timestamp,
    )


def _dep_edge(pod: PodNode) -> Edge:
    return Edge(
        src="k8s::checkout/Service/checkout",
        dst=pod.id,
        kind=EdgeKind.DEPENDS_ON,
        weight=1.0,
    )


def _graph(pods: list[PodNode]) -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            *pods,
            ServiceNode(
                id="k8s::checkout/Service/checkout",
                name="checkout",
                kind=NodeKind.SERVICE,
            ),
        ),
        edges=tuple(_dep_edge(p) for p in pods),
    )


def _scope(selection: SelectionMode | None = None) -> TargetScope:
    kwargs: dict[str, object] = {
        "logical_id": "checkout",
        "runtime": RuntimeLabel.KUBERNETES,
        "kind": ResourceKind.DEPLOYMENT,
        "authority": {"api_group": "apps", "namespace": "checkout", "name": "checkout"},
    }
    if selection is not None:
        kwargs["selection"] = {"mode": selection}
    return TargetScope(**kwargs)


def test_selects_the_sole_running_pod() -> None:
    pod = _pod("checkout-abc")
    assert select_one(_graph([pod]), _scope()) == pod


def test_picks_lexicographically_first_among_running() -> None:
    pods = [_pod(f"checkout-{suffix}") for suffix in ("aaa", "zzz", "mmm")]
    assert select_one(_graph(pods), _scope()) == pods[0]


def test_skips_terminating_pods() -> None:
    running = _pod("checkout-run")
    term = _pod("checkout-term", deletion_timestamp="2026-09-12T10:00:00Z")
    graph = _graph([term, running])
    assert select_one(graph, _scope()) == running


def test_skips_non_running_states() -> None:
    graph = _graph([_pod("checkout-pending", state="Pending")])
    with pytest.raises(SelectionError) as exc:
        select_one(graph, _scope())
    assert exc.value.code == "selection.no_eligible_pods"


def test_multi_mode_selection_returns_full_set() -> None:
    """k-plan-4 §4.2: reserved modes are now implemented — all selects every
    eligible pod instead of refusing (SP-4.1 reserved-mode flip)."""
    pods = [_pod(f"checkout-{s}") for s in ("aaa", "zzz", "mmm")]
    from mayhem.domain.target_selector import select_many

    picks = select_many(_graph(pods), _scope(selection=SelectionMode.ALL))
    assert picks is not None
    assert len(picks) == 3


def test_k8s_node_has_no_mode_one_pick_until_kplan5() -> None:
    node_scope = TargetScope(
        logical_id="node-a",
        runtime=RuntimeLabel.KUBERNETES,
        kind=ResourceKind.K8S_NODE,
        authority={"name": "node-a"},
    )
    with pytest.raises(SelectionError) as exc:
        select_one(TopologyGraph(), node_scope)
    assert exc.value.code == "selection.node_target_unsupported"


def test_absent_workload_is_logically_pinned() -> None:
    assert select_one(_graph([]), _scope()) is None


def test_planner_gate_allows_eligible_workload() -> None:
    graph = _graph([_pod("checkout-abc")])
    _gate_k8s_selection_eligibility(graph, _scope())  # no exception


def test_planner_gate_blocks_zero_eligible_pods() -> None:
    graph = _graph([_pod("checkout-bad", state="CrashLoopBackOff")])
    with pytest.raises(SelectionError) as exc:
        _gate_k8s_selection_eligibility(graph, _scope())
    assert exc.value.code == "selection.no_eligible_pods"


def test_planner_gate_ignores_absent_workload() -> None:
    _gate_k8s_selection_eligibility(_graph([]), _scope())  # no exception


def test_planner_gate_skips_non_kubernetes_runtimes() -> None:
    docker_scope = TargetScope(
        logical_id="web",
        runtime=RuntimeLabel.PODMAN,
        kind=ResourceKind.CONTAINER,
        authority={"container_name": "web"},
    )
    _gate_k8s_selection_eligibility(_graph([]), docker_scope)  # no exception
