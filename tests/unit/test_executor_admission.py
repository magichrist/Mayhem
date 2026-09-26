from __future__ import annotations

from mayhem.domain.admission import admit_resolved_target, target_type
from mayhem.domain.resolution import ResolvedNodeTarget, ResolvedPodTarget


def _pod() -> ResolvedPodTarget:
    return ResolvedPodTarget(namespace="default", pod="api-0", container="api")


def _node() -> ResolvedNodeTarget:
    return ResolvedNodeTarget(node="node-a")


def test_target_type_distinguishes_pod_and_node() -> None:
    assert target_type(_pod()) == "pod"
    assert target_type(_node()) == "node"
    assert target_type(object()) is None


def test_admission_allows_matching_pod_target() -> None:
    decision = admit_resolved_target(
        "k8s.pod_kill",
        _pod(),
        required_target_types=("pod",),
        compensation_complete=True,
    )
    assert decision.allowed is True
    assert decision.code == ""
    assert decision.required_target_types == ("pod",)


def test_admission_refuses_node_pod_mismatch() -> None:
    decision = admit_resolved_target(
        "k8s.pod_kill",
        _node(),
        required_target_types=("pod",),
        compensation_complete=True,
    )
    assert decision.allowed is False
    assert decision.code == "target.type_mismatch"
    assert "pod" in decision.reason


def test_admission_refuses_unresolved_target() -> None:
    decision = admit_resolved_target(
        "k8s.pod_kill",
        None,
        required_target_types=("pod",),
        compensation_complete=True,
    )
    assert decision.allowed is False
    assert decision.code == "target.unresolved"


def test_admission_refuses_incomplete_compensation() -> None:
    decision = admit_resolved_target(
        "k8s.pod_kill",
        _pod(),
        required_target_types=("pod",),
        compensation_complete=False,
    )
    assert decision.allowed is False
    assert decision.code == "compensation.incomplete"


def test_admission_supports_container_service_and_workload_strings() -> None:
    for target_type_name in ("container", "service", "workload"):
        decision = admit_resolved_target(
            "fault",
            target_type_name,
            required_target_types=(target_type_name,),
            compensation_complete=True,
        )
        assert decision.allowed is False
        assert decision.code == "target.type_mismatch"
