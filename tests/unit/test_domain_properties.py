"""Property-based domain invariants (hypothesis).

The state-machine table is the law; these tests prove the implementation never
deviates from it, and that serialization round-trips preserve value equality.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from mayhem.domain.common import parse_duration
from mayhem.domain.errors import InvalidTransitionError
from mayhem.domain.leases import FaultLease, LeaseState
from mayhem.domain.topology import Edge, EdgeKind, ServiceNode, TopologyGraph

_ALL_STATES = sorted(LeaseState, key=lambda s: s.value)
_TRANSITION_TABLE: dict[LeaseState, frozenset[LeaseState]] = {
    LeaseState.PENDING: frozenset({LeaseState.ACTIVE, LeaseState.EXPIRED}),
    LeaseState.ACTIVE: frozenset({LeaseState.RELEASING, LeaseState.EXPIRED, LeaseState.ORPHANED}),
    LeaseState.RELEASING: frozenset({LeaseState.RELEASED, LeaseState.DIRTY}),
    LeaseState.RELEASED: frozenset(),
    LeaseState.EXPIRED: frozenset(),
    LeaseState.DIRTY: frozenset(),
    LeaseState.ORPHANED: frozenset({LeaseState.RELEASING}),
}


def _minimal_lease(state: LeaseState) -> FaultLease:
    payload: dict[str, object] = {
        "id": "l-prop",
        "run_id": "r-prop",
        "fault_id": "cpu.burn",
        "owner_agent": "ag-1",
        "targets": ["n1"],
        "undo_ops": [{"op": "kill", "args": {"pid": "7"}}],
        "verify_probes": [{"probe": "exec", "args": {"cmd": ["true"]}}],
        "state": state.value,
    }
    if state is LeaseState.DIRTY:  # dirty requires escalation notes by invariant
        payload["escalation_notes"] = "synthetic dirty for property test"
    return FaultLease.model_validate(payload)


@settings(max_examples=200, deadline=None)
@given(st.sampled_from(_ALL_STATES), st.sampled_from(_ALL_STATES))
def test_transition_table_is_exactly_the_documented_law(
    source: LeaseState, target: LeaseState
) -> None:
    lease = _minimal_lease(source)
    legal = target in _TRANSITION_TABLE[source]
    assert lease.can_transition(target) == legal
    if not legal:
        try:
            lease.transition(target)
        except InvalidTransitionError as exc:
            assert exc.current == source.value
            assert exc.requested == target.value
        else:  # pragma: no cover — must never happen
            raise AssertionError(f"illegal transition {source}->{target} was accepted")


@settings(max_examples=100, deadline=None)
@given(st.integers(min_value=0, max_value=86_400))
def test_duration_seconds_round_trip(seconds: int) -> None:
    assert parse_duration(f"{seconds}s") == float(seconds)


@settings(max_examples=100, deadline=None)
@given(st.lists(st.integers(min_value=1, max_value=999), min_size=0, max_size=5))
def test_topology_json_round_trip(ids: list[int]) -> None:
    nodes = tuple(ServiceNode(id=f"n-{pos}", name=f"svc-{v}") for pos, v in enumerate(ids))
    edges = tuple(
        Edge(src=f"n-{pos}", dst=f"n-{pos + 1}", kind=EdgeKind.CONNECTS_VIA)
        for pos in range(len(ids) - 1)
    )
    graph = TopologyGraph(nodes=nodes, edges=edges)
    restored = TopologyGraph.model_validate(graph.model_dump(mode="json"))
    assert restored == graph


@settings(max_examples=100, deadline=None)
@given(st.text(alphabet="abcdef0123456789", min_size=4, max_size=12))
def test_lease_json_round_trip(suffix: str) -> None:
    lease = _minimal_lease(LeaseState.PENDING).model_copy(update={"id": f"l-{suffix}"})
    restored = FaultLease.model_validate(lease.model_dump(mode="json"))
    assert restored == lease
    assert isinstance(restored.targets, frozenset)
