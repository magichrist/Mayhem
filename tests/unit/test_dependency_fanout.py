"""Plan 05 Phase 4 — dependency fan-out accounting.

The gap this covers: :func:`mayhem.controller.safety._affected_node_ids` flattens
targets and their dependents into one ``frozenset`` and hands it to the caps.
That set is correct, and it is **silent** — a service that was targeted and a
service that was reached because something it depends on was targeted arrive as
the same kind of string. So a plan whose fan-out tripled looked exactly like the
plan it replaced, and nothing recorded which nodes were collateral.

These tests pin the accounting. The first one is the load-bearing claim: the
projection here and the closure the blast gate walks must **never** disagree,
because a record that named a different affected set than the gate enforced would
be worse than no record at all.
"""

from __future__ import annotations

import json

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, check_blast_radius
from mayhem.domain.dependency_fanout import (
    RULE_DEPENDENCY_NO_EDGES,
    RULE_DEPENDENCY_UNRESOLVED,
    dependency_fanout,
    fanout_ledger,
    require_resolved_dependencies,
    unresolved_dependency,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import BlastRadiusBudget
from mayhem.domain.hashing import canonical_json, sha256_hex
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    ExternalDependencyNode,
    NodeKind,
    ServiceNode,
    TopologyGraph,
)

FP = "f" * 64


def _graph() -> TopologyGraph:
    """A checkout-shaped dependency chain plus one dependency nothing reaches.

    Two details are load-bearing rather than decorative:

    * ``n-web -> n-api -> x-pg`` gives the walk a chain, so ``depth`` can be 2 and
      a test can tell a compounded consequence from a first hop;
    * ``n-cron`` reaches ``x-pg`` only through ``CONNECTS_VIA``. ``n-cron`` would
      be invisible to a projection that walked ``DEPENDS_ON`` alone, and since the
      module's central claim is agreement with ``TopologyGraph.dependents_closure``
      -- which walks both -- a fixture without this edge would let that claim pass
      on a module that disagreed with the gate.

    ``x-stripe`` is declared but nothing depends on it. It is here so
    ``unreached_dependencies`` has something true to report: a record that only
    listed hits would look complete without it.
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-web", name="web"),
            ServiceNode(id="n-api", name="api"),
            ServiceNode(id="n-worker", name="worker"),
            ServiceNode(id="n-cron", name="cron"),
            ExternalDependencyNode(id="x-pg", name="postgres", endpoint="postgres:5432"),
            ExternalDependencyNode(id="x-stripe", name="stripe", endpoint="api.stripe.com"),
        ),
        edges=(
            Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON),
            Edge(src="n-api", dst="x-pg", kind=EdgeKind.DEPENDS_ON),
            Edge(src="n-worker", dst="x-pg", kind=EdgeKind.DEPENDS_ON),
            Edge(src="n-cron", dst="x-pg", kind=EdgeKind.CONNECTS_VIA),
        ),
    )


class TestProjectionMatchesBlastClosure:
    def test_affected_is_targets_plus_the_closure_the_gate_walks(self) -> None:
        """The load-bearing claim: no disagreement with ``dependents_closure``.

        Checked for *every* node, so it cannot pass by choosing one convenient
        target. If the two ever diverge, the record would name an affected set
        the blast gate does not actually enforce.
        """
        graph = _graph()
        for node in graph.nodes:
            fanout = dependency_fanout(graph, fault_id="dep.latency", targets=[node.id])
            expected = frozenset({node.id}) | graph.dependents_closure(node.id)
            assert fanout.affected == expected, node.id

    def test_collateral_is_exactly_the_closure_minus_the_targets(self) -> None:
        graph = _graph()
        fanout = dependency_fanout(graph, fault_id="dep.latency", targets=["x-pg"])
        assert fanout.collateral == graph.dependents_closure("x-pg")
        assert not (fanout.collateral & fanout.aimed)

    def test_a_connects_via_link_is_walked_like_a_depends_on_one(self) -> None:
        """Named rather than incidental, so dropping either edge kind is caught.

        ``n-cron`` reaches ``x-pg`` through no other edge. The blast gate's
        closure follows ``CONNECTS_VIA`` because a service that opens a socket to
        a dependency breaks when that dependency does, whether or not a health
        check gates the call. A projection that walked only ``DEPENDS_ON`` would
        under-report the gate -- so this names the case.
        """
        fanout = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"])
        assert "n-cron" in fanout.collateral

    def test_a_target_is_never_reported_as_reached(self) -> None:
        """Aiming at two nodes where one reaches the other must not double-count.

        Without this, the record would list an aimed node as collateral and
        ``widened`` would report a widening the planner actually asked for.
        """
        fanout = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg", "n-api"])
        assert "n-api" in fanout.aimed
        assert "n-api" not in fanout.collateral
        # n-web is still reached, and correctly so: it depends on n-api, which
        # was aimed at. Aiming at a node does not stop the walk through it.
        assert fanout.collateral == frozenset({"n-worker", "n-web", "n-cron"})
        assert fanout.affected == frozenset({"x-pg", "n-api", "n-worker", "n-web", "n-cron"})


class TestPathsAndDepth:
    def test_depth_counts_edges_from_the_nearest_aimed_node(self) -> None:
        fanout = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"])
        assert {node.node_id: node.depth for node in fanout.reached} == {
            "n-api": 1,
            "n-worker": 1,
            "n-cron": 1,
            "n-web": 2,
        }
        assert fanout.max_depth == 2

    def test_each_reached_node_names_the_node_it_was_reached_through(self) -> None:
        """``via`` is the proof of the path, not a restatement of the target."""
        fanout = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"])
        via = {node.node_id: node.via for node in fanout.reached}
        assert via == {
            "n-api": "x-pg",
            "n-worker": "x-pg",
            "n-cron": "x-pg",
            "n-web": "n-api",
        }

    def test_reached_at_depth_separates_first_hops_from_compounding(self) -> None:
        fanout = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"])
        assert {n.node_id for n in fanout.reached_at_depth(1)} == {
            "n-api",
            "n-worker",
            "n-cron",
        }
        assert {n.node_id for n in fanout.reached_at_depth(2)} == {"n-web"}
        assert fanout.reached_at_depth(3) == ()

    def test_a_cycle_terminates_and_names_each_node_once(self) -> None:
        """A dependency cycle is legal in a topology; the walk must not hang."""
        graph = TopologyGraph(
            nodes=(
                ServiceNode(id="n-a", name="a"),
                ServiceNode(id="n-b", name="b"),
                ServiceNode(id="n-c", name="c"),
            ),
            edges=(
                Edge(src="n-a", dst="n-b", kind=EdgeKind.DEPENDS_ON),
                Edge(src="n-b", dst="n-c", kind=EdgeKind.DEPENDS_ON),
                Edge(src="n-c", dst="n-a", kind=EdgeKind.DEPENDS_ON),
            ),
        )
        fanout = dependency_fanout(graph, fault_id="dep.latency", targets=["n-a"])
        assert fanout.collateral == frozenset({"n-b", "n-c"})
        assert len(fanout.reached) == 2


class TestWidening:
    def test_a_dependency_nobody_depends_on_does_not_widen(self) -> None:
        fanout = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-stripe"])
        assert fanout.widened is False
        assert fanout.collateral == frozenset()
        assert fanout.max_depth == 0

    def test_a_widened_fault_says_so(self) -> None:
        assert dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"]).widened is True

    def test_exposed_dependents_are_the_services_that_go_down(self) -> None:
        """The question a reviewer actually asks: which of my services break?"""
        fanout = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"])
        assert fanout.undeclared_dependents == frozenset({"n-api", "n-worker", "n-web", "n-cron"})


class TestUnreachedDependencies:
    def test_it_names_the_dependencies_the_fault_does_not_touch(self) -> None:
        fanout = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"])
        assert fanout.unreached_dependencies == frozenset({"x-stripe"})

    def test_aiming_at_every_dependency_leaves_an_empty_and_real_statement(self) -> None:
        """Empty here means "nothing was missed", not "we did not look".

        The two cases together are what make it meaningful: the same field is
        non-empty one target earlier, so the emptiness below is a finding about
        the plan rather than a field that is always empty.
        """
        graph = _graph()
        every = {n.id for n in graph.of_kind(NodeKind.EXTERNAL_DEPENDENCY)}
        one = dependency_fanout(graph, fault_id="dep.latency", targets=["x-pg"])
        assert one.unreached_dependencies == every - {"x-pg"}

        both = dependency_fanout(graph, fault_id="dep.latency", targets=sorted(every))
        assert both.unreached_dependencies == frozenset()


class TestUnresolvableDependency:
    def test_an_aimed_at_dependency_that_does_not_exist_refuses(self) -> None:
        """The negative control: never inject nowhere and report success."""
        refusal = unresolved_dependency(_graph(), fault_id="dep.latency", targets=["x-mysql"])
        assert refusal is not None
        assert refusal.rule == RULE_DEPENDENCY_UNRESOLVED

    def test_the_refusal_names_the_missing_id_and_the_real_ones(self) -> None:
        refusal = unresolved_dependency(_graph(), fault_id="dep.latency", targets=["x-mysql"])
        assert refusal is not None
        message = str(refusal)
        assert "x-mysql" in message
        assert "x-pg" in message and "x-stripe" in message
        assert "silent success" in message

    def test_a_graph_with_no_dependencies_says_so_rather_than_listing_nothing(self) -> None:
        graph = TopologyGraph(nodes=(ServiceNode(id="n-a", name="a"),))
        refusal = unresolved_dependency(graph, fault_id="dep.latency", targets=["x-pg"])
        assert refusal is not None
        assert "no dependency nodes at all" in str(refusal)

    def test_a_resolvable_target_refuses_nothing(self) -> None:
        assert unresolved_dependency(_graph(), fault_id="dep.latency", targets=["x-pg"]) is None
        assert unresolved_dependency(_graph(), fault_id="dep.latency", targets=[]) is None

    def test_only_targets_are_checked_not_the_closure(self) -> None:
        """A transitively reached node is in the graph by construction.

        Checking it would be the walker auditing its own bookkeeping, and a
        closure that somehow contained a stranger should surface as a closure
        bug -- not as a second, redundant refusal at the same rule id.
        """
        fanout = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"])
        require_resolved_dependencies(
            _graph(), fault_id="dep.latency", targets=sorted(fanout.affected)
        )

    def test_require_raises_with_the_same_rule(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            require_resolved_dependencies(_graph(), fault_id="dep.latency", targets=["x-mysql"])
        assert caught.value.rule == RULE_DEPENDENCY_UNRESOLVED

    def test_the_unresolved_rule_is_distinct_from_the_unobserved_one(self) -> None:
        """Two rules, two meanings -- so a reader cannot conflate them."""
        assert RULE_DEPENDENCY_UNRESOLVED != RULE_DEPENDENCY_NO_EDGES


class TestLedger:
    def test_the_union_is_not_the_sum(self) -> None:
        """Three steps each reaching one service is not three services."""
        ledger = fanout_ledger(
            _graph(),
            [("dep.latency", ["x-pg"]), ("dep.latency", ["x-stripe"])],
        )
        assert ledger.affected == frozenset(
            {"x-pg", "x-stripe", "n-api", "n-worker", "n-web", "n-cron"}
        )

    def test_widened_steps_name_the_offending_faults(self) -> None:
        ledger = fanout_ledger(
            _graph(),
            [("dep.latency", ["x-stripe"]), ("dep.timeout", ["x-pg"])],
        )
        assert ledger.widened_steps() == ("dep.timeout",)

    def test_an_unresolvable_step_refuses_before_any_projection_is_computed(self) -> None:
        """Otherwise the plan could be *reported* as a clean zero-width fan-out."""
        with pytest.raises(InvariantViolationError) as caught:
            fanout_ledger(
                _graph(),
                [("dep.latency", ["x-pg"]), ("dep.timeout", ["x-mysql"])],
            )
        assert caught.value.rule == RULE_DEPENDENCY_UNRESOLVED

    def test_the_diagnostic_escape_hatch_is_named_and_opt_in(self) -> None:
        ledger = fanout_ledger(
            _graph(),
            [("dep.timeout", ["x-mysql"])],
            require_resolved=False,
        )
        # The aim is still reported -- the plan *did* name it -- but nothing was
        # reached through it, which is the thing a reader must not mistake for
        # an injection.
        assert ledger.affected == frozenset({"x-mysql"})
        assert ledger.collateral == frozenset()
        assert ledger.max_depth == 0
        assert ledger.widened_steps() == ()

    def test_an_empty_plan_is_described_rather_than_dividing_by_zero(self) -> None:
        assert fanout_ledger(_graph(), []).describe() == "no steps, no fan-out"

    def test_the_ledger_describes_its_own_widening(self) -> None:
        ledger = fanout_ledger(_graph(), [("dep.latency", ["x-pg"])])
        text = ledger.describe()
        assert "widened: ['dep.latency']" in text
        # 5 of 6 nodes: x-pg plus the four services, and not x-stripe.
        assert "5 node(s)" in text
        assert "4 of them reached rather than aimed at" in text


class TestSealedRecord:
    def test_the_digest_covers_the_whole_payload(self) -> None:
        fanout = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"])
        record = fanout.record
        body = {k: v for k, v in record.items() if k != "sealed_digest"}
        assert record["sealed_digest"] == sha256_hex(canonical_json(body))

    def test_an_edited_reach_is_detectable(self) -> None:
        """The point of the digest: a record cannot be quietly widened."""
        record = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"]).record
        record["reached"] = []
        body = {k: v for k, v in record.items() if k != "sealed_digest"}
        assert record["sealed_digest"] != sha256_hex(canonical_json(body))

    def test_the_record_survives_a_json_round_trip(self) -> None:
        """It has to be storable, so nothing in it may be a non-JSON value."""
        record = dependency_fanout(_graph(), fault_id="dep.latency", targets=["x-pg"]).record
        assert json.loads(canonical_json(record)) == record

    def test_the_ledger_record_covers_the_aggregate_too(self) -> None:
        record = fanout_ledger(_graph(), [("dep.latency", ["x-pg"])]).to_dict()
        body = {k: v for k, v in record.items() if k != "sealed_digest"}
        assert record["sealed_digest"] == sha256_hex(canonical_json(body))
        aggregate = record["aggregate"]
        assert isinstance(aggregate, dict)
        assert aggregate["collateral"] == ["n-api", "n-cron", "n-web", "n-worker"]


class TestItDoesNotChangeTheDecision:
    """Accounting, not a new blast-radius rule.

    The module's claim is that it *reports* what the gate already enforces. If
    feeding its output to the gate could produce a refusal the raw targets do
    not, it would be a second blast-radius rule wearing an accounting hat.
    """

    def _ctx(self, budget: BlastRadiusBudget) -> SafetyContext:
        return SafetyContext(policy=PolicyCfg(), budget=budget, fingerprint=FP)

    @pytest.mark.parametrize("budget_pct", [50.0, 34.0, 20.0])
    def test_the_gate_gives_the_same_answer_from_targets_and_from_the_record(
        self, budget_pct: float
    ) -> None:
        budget = BlastRadiusBudget(max_services_pct=budget_pct, max_hosts=1)
        fanout = dependency_fanout(_graph(), fault_id="proc.pause", targets=["x-pg"])

        def outcome(node_ids: frozenset[str]) -> str:
            try:
                check_blast_radius(
                    _graph(),
                    node_ids,
                    10.0,
                    (),
                    "proc.pause",
                    ctx=self._ctx(budget),
                )
            except SafetyRefusedError as refused:
                assert refused.decision is not None
                return refused.decision.rule_id
            return "allowed"

        assert outcome(fanout.aimed) == outcome(fanout.affected)

    def test_it_refuses_a_plan_the_raw_targets_also_refuse(self) -> None:
        """And the refusal is the real one, from the real cap."""
        budget = BlastRadiusBudget(max_services_pct=34.0, max_hosts=1)
        fanout = dependency_fanout(_graph(), fault_id="proc.pause", targets=["x-pg"])
        with pytest.raises(SafetyRefusedError) as caught:
            check_blast_radius(
                _graph(), fanout.affected, 10.0, (), "proc.pause", ctx=self._ctx(budget)
            )
        decision = caught.value.decision
        assert decision is not None
        assert decision.rule_id == "blast_radius.max_services_pct"

    def test_the_record_makes_the_absorbed_fan_out_visible_as_a_number(self) -> None:
        """What the flattened set hid: the widening shows up in the percentage."""
        budget = BlastRadiusBudget(max_services_pct=100.0, max_hosts=1)
        narrow = dependency_fanout(_graph(), fault_id="proc.pause", targets=["n-web"])
        wide = dependency_fanout(_graph(), fault_id="proc.pause", targets=["x-pg"])
        # 4 services in the graph; aiming at web touches 1, at postgres touches 4.
        services = {n.id for n in _graph().of_kind(NodeKind.SERVICE)}
        assert len(narrow.affected & services) == 1
        assert len(wide.affected & services) == 4
        stats = check_blast_radius(
            _graph(), wide.affected, 10.0, (), "proc.pause", ctx=self._ctx(budget)
        )
        assert stats["services_pct"] == 100.0


class TestItDoesNotSeeWhatTheGraphDoesNotDeclare:
    def test_an_undeclared_dependency_is_absent_and_that_is_reported(self) -> None:
        """The honest limit: fan-out is only as good as the topology snapshot.

        ``n-worker`` calls Stripe in reality but the graph declares no edge, so
        the projection cannot reach it. The record says what it reached and what
        it missed; it does not pretend to be complete.
        """
        graph = _graph()
        fanout = dependency_fanout(graph, fault_id="dep.latency", targets=["x-pg"])
        # Nothing in the graph connects n-worker to x-stripe, so the projection
        # cannot reach it, and the record's own unreached field is where that
        # incompleteness shows up rather than being hidden behind a clean total.
        assert not [e for e in graph.edges if {"n-worker", "x-stripe"} == {e.src, e.dst}]
        assert "x-stripe" in fanout.unreached_dependencies
        assert "depth 1" in fanout.describe()

        # Declare the edge and the same call sees it. The limit was the input,
        # not the walk.
        graphier = TopologyGraph(
            nodes=graph.nodes,
            edges=(
                *graph.edges,
                Edge(src="n-worker", dst="x-stripe", kind=EdgeKind.DEPENDS_ON),
            ),
        )
        wider = dependency_fanout(graphier, fault_id="dep.latency", targets=["x-pg"])
        assert "x-stripe" in wider.unreached_dependencies
        assert "x-stripe" not in wider.collateral  # reached the other way round
