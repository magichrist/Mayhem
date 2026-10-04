"""Plan 14 Phase 5 — negative controls for the prediction's pure layer.

`test_prediction.py` (52), `test_prediction_service.py` (69) and
`test_prediction_evidence.py` (51) assert what the prediction *is*. This file
asserts the three things underneath it are **load-bearing**, which is the claim
that survives a topology change:

* **The graph identity is the pin that makes drift detectable.** Identical graphs
  hash alike; a graph with one extra node does not. If the identity were
  insensitive to content — or if it were re-derived per call rather than from the
  graph — the staleness machinery in Phase 4 would have nothing to compare, and
  `test_a_prediction_over_a_drifted_graph_is_marked_stale` (pinned by name below)
  would be asserting a property of a constant.
* **The affected set is closed under dependencies and closed to everything else.**
  Adding an isolated service changes nothing, and that service is never a member.
  The dangerous failure is a traversal that leaks: an affected set containing a
  node with no dependency path would inflate every blast-radius ceiling in the
  plan behind it.
* **Fan-out depth counts hops.** Cutting one edge in the four-deep chain both
  shrinks the affected set *and* lowers the measured depth — so a depth of 3 is a
  measurement of this graph, not a constant of the code. The case this rules out
  is a traversal that keeps counting membership after the path it counted is gone.

The two properties that live behind the engine's ports — a drifted prediction
being refused for approval use, and a preview never being accepted as a
preflight — are guarded by name-pin rather than rebuilt here, because
reconstructing their collaborators would duplicate the suites that own them. The
docstring on that test says so, rather than dressing a weaker check up as the
real thing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.unit.test_prediction import _graph, _plan

from mayhem.domain.prediction import (
    affected_node_ids,
    dependency_fan_out,
    graph_identity,
    plan_identity,
)
from mayhem.domain.topology import EdgeKind, ServiceNode, TopologyGraph

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The deepest chain in the fixture: ``n-db`` <- ``n-api`` <- ``n-web`` <- ``n-edge``.
ROOT = "n-db"
CHAIN = ("n-db", "n-api", "n-web", "n-edge")

#: The engine-level properties Phase 5 names, and the suite that owns each.
NAMED_ENGINE_PROPERTIES: tuple[tuple[str, str], ...] = (
    ("tests/unit/test_prediction.py", "test_a_prediction_over_a_drifted_graph_is_marked_stale"),
    (
        "tests/unit/test_prediction_evidence.py",
        "test_a_stale_prediction_is_refused_for_approval_use",
    ),
    (
        "tests/unit/test_prediction_service.py",
        "test_a_prediction_over_a_drifted_graph_is_refused_for_approval_use",
    ),
    ("tests/unit/test_prediction_service.py", "test_a_preview_is_never_accepted_as_a_preflight"),
    (
        "tests/unit/test_prediction_evidence.py",
        "test_the_preview_and_the_gate_agree_on_which_ceiling_fires",
    ),
    (
        "tests/unit/test_prediction_evidence.py",
        "test_the_protected_list_matches_targets_not_the_whole_blast",
    ),
)


def _cut_the_last_hop(graph: TopologyGraph) -> TopologyGraph:
    """The same graph with the ``n-edge -> n-web`` dependency removed.

    ``TopologyGraph`` is a frozen pydantic model, so a variant is a
    ``model_copy`` — ``dataclasses.replace`` raises on it.
    """
    return graph.model_copy(
        update={
            "edges": tuple(
                edge for edge in graph.edges if not (edge.src == "n-edge" and edge.dst == "n-web")
            )
        }
    )


# ── the identity is the pin ─────────────────────────────────────────────────


def test_the_graph_identity_senses_content_and_nothing_else() -> None:
    """Same graph twice, then the same graph plus one node.

    Both halves are needed. Sensitivity alone would be satisfied by an identity
    that changed on every call, and stability alone by one that returned a
    constant.
    """
    graph = _graph()
    extra = ServiceNode(id="n-extra", name="extra")

    assert graph_identity(graph) == graph_identity(_graph())
    assert graph_identity(graph) != graph_identity(
        graph.model_copy(update={"nodes": (*graph.nodes, extra)})
    )


def test_the_plan_identity_changes_when_the_plan_changes() -> None:
    """The plan half of the pin: one extra step is a different plan.

    Two compilations of the same plan hash alike, so a diff between two runs does
    not fire on arrival order; one added step does not, so a stale prediction
    cannot be reused across it.
    """
    plan = _plan(("net.latency", "n-db", 30.0))

    assert plan_identity(plan) == plan_identity(_plan(("net.latency", "n-db", 30.0)))
    assert plan_identity(plan) != plan_identity(
        _plan(("net.latency", "n-db", 30.0), ("net.latency", "n-api", 30.0))
    )


# ── the closure is closed ────────────────────────────────────────────────────


def test_the_affected_set_ignores_a_service_no_dependency_path_reaches() -> None:
    """An isolated service is not affected, and adding it changes nothing.

    The equality half is the load-bearing one: a traversal that recomputed
    differently per call would pass a membership assertion and fail here.
    """
    graph = _graph()
    extra = ServiceNode(id="n-extra", name="extra")
    before = affected_node_ids(graph, [ROOT])

    after = affected_node_ids(graph.model_copy(update={"nodes": (*graph.nodes, extra)}), [ROOT])

    assert before == after
    assert "n-extra" not in after
    assert set(CHAIN) <= before


def test_cutting_one_dependency_shrinks_the_affected_set() -> None:
    """Remove a single edge and the node behind it leaves the closure.

    This is the property that makes a blast-radius ceiling mean anything: if a
    cut edge left the fan-out intact, every ceiling in the plan behind it would be
    computed against a set that no longer describes the topology.
    """
    intact = affected_node_ids(_graph(), [ROOT])
    cut = affected_node_ids(_cut_the_last_hop(_graph()), [ROOT])

    assert "n-edge" in intact
    assert "n-edge" not in cut
    assert cut < intact


# ── depth counts hops ───────────────────────────────────────────────────────


def test_fan_out_depth_counts_hops_and_falls_when_a_path_is_cut() -> None:
    """Three hops in the full chain, fewer once the last one is removed.

    Asserted against this graph rather than as a literal so that a traversal
    which stopped counting hops — reporting membership depth instead — would fail
    rather than quietly agree on the one number in the suite.
    """
    intact = dependency_fan_out(_graph(), [ROOT])
    cut = dependency_fan_out(_cut_the_last_hop(_graph()), [ROOT])

    assert intact.max_depth == 3
    assert cut.max_depth < intact.max_depth
    assert intact.dependent_count > cut.dependent_count


# ── the properties that live behind the engine's ports ───────────────────────


@pytest.mark.parametrize(("path", "test_name"), NAMED_ENGINE_PROPERTIES)
def test_the_engine_level_properties_the_phase_names_are_still_pinned(
    path: str, test_name: str
) -> None:
    """A name-pin, and weaker than a behaviour test — stated as such.

    What this guards is narrow and still worth guarding: that the coverage the
    phase's own negative controls name has not been deleted from the suites that
    own those collaborators.
    """
    source = (REPO_ROOT / path).read_text(encoding="utf-8")

    assert f"def {test_name}(" in source, f"{path} no longer pins {test_name}"


def test_the_pinned_property_names_are_the_ones_the_phase_names() -> None:
    """So the pin list cannot be quietly emptied by deleting an entry."""
    pinned = {name for _, name in NAMED_ENGINE_PROPERTIES}

    assert {"test_a_prediction_over_a_drifted_graph_is_marked_stale"} <= pinned
    assert {"test_a_preview_is_never_accepted_as_a_preflight"} <= pinned
    assert len(NAMED_ENGINE_PROPERTIES) == len(
        {(path, name) for path, name in NAMED_ENGINE_PROPERTIES}
    )


def test_the_edge_cut_helper_really_cuts_the_edge_it_names() -> None:
    """Guards the helpers above: a no-op cut would make every one of them vacuous."""
    graph = _graph()

    cut = _cut_the_last_hop(graph)

    assert len(cut.edges) == len(graph.edges) - 1
    assert not any(edge.kind is EdgeKind.DEPENDS_ON and edge.src == "n-edge" for edge in cut.edges)
