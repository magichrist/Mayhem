"""Plan 21 Phase 5 — negative controls for the advisor.

The other three advisor suites assert what the engine *does*. This one asserts
that those properties are **load-bearing**, which is a different claim and the
only one that survives a future edit:

* :mod:`tests.unit.test_advisor_service` proves the analysis finds the gap, cites
  its facts, and refuses an untraceable replay. It proves the behaviour.
* This file breaks one collaborator or one seam at a time and asserts the
  property **still holds** — or, where the break is the property's only trigger,
  that the refusal **still fires**.

The distinction matters because a refusal test a regression would also pass is a
test that cannot fail. ``test_the_analysis_stays_pure_even_when_the_detachment_
is_regressed_to_a_no_op`` is the clearest example: the purity claim does not rest
on :meth:`~mayhem.controller.advisor_service.AdvisorService.detached` being called
correctly, it rests on there being no call site at all — so the test removes the
detachment entirely and the answer must not move.

Every break here is on the *collaborator* side. Nothing in
``src/mayhem`` is monkeypatched except the one delegated symbol whose delegation
is itself the property under test, and that one is restored by the ``monkeypatch``
fixture rather than by hand.
"""

from __future__ import annotations

import pytest
from tests.unit.test_advisor_service import (
    CRITERIA,
    GAP_CELL,
    SEALED_DIGEST,
    DeployedReleases,
    SealedCoverage,
    SealedEvidenceLedger,
    SealedIncidents,
    SealedTopology,
    propose,
    service,
    weight,
)

from mayhem.controller import advisor_service
from mayhem.controller.advisor_service import (
    RULE_REPLAY_TOPOLOGY_PIN_MISMATCH,
    AdvisorService,
    SealedCell,
)
from mayhem.controller.policy_gate import MutationSink
from mayhem.domain.advisor import RULE_LANDSCAPE_EMPTY
from mayhem.domain.errors import InvariantViolationError

#: A sink that is already loaded, so ``calls == 0`` could only mean "nothing was
#: written" and never "nothing was there to write".
LOADED_SINK = MutationSink(calls=(("post", "checkout"), ("inject", "net.latency")))


# -- purity: the property is the absence of a call site, not a correct method -----


def test_the_analysis_stays_pure_even_when_the_detachment_is_regressed_to_a_no_op(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Break ``detached`` so the analysis runs *with* the sink attached.

    The purity claim must be unchanged, because it was never carried by that
    method: :class:`~mayhem.controller.advisor_service.AdvisorService` holds no
    statement handle, no lease client and no executor, so there is nothing that
    *could* be called through the sink. If this test ever goes red, the property
    had been resting on a method call rather than on the object's shape.
    """
    monkeypatch.setattr(AdvisorService, "detached", lambda self: self)

    report = service(sink=LOADED_SINK).analyse(propose, CRITERIA, weight)

    assert report.purity.backend_attached is False
    assert report.purity.calls == 2
    assert report.purity.calls_detail == LOADED_SINK.calls
    # The findings themselves are unaffected too: a regression that leaked the
    # sink would not change *what* was found, which is why this is asserted on
    # the measurement and not inferred from the report shape.
    assert [f.cell.key for f in report.findings] == [GAP_CELL.key]


def test_the_reported_call_detail_is_the_caller_s_own_sink_and_nothing_was_appended() -> None:
    """A recording sink returns a *new* object, so a write cannot hide in a report.

    ``MutationSink.record`` is append-by-copy. That means "the analysis recorded
    nothing" and "the analysis recorded something and threw it away" are the same
    observable state — which is precisely why this test pins the reported detail
    against the caller's own tuple instead of against a count. A future change to
    a mutating sink would have to change this test, not quietly widen the claim.
    """
    sink = MutationSink()

    report = service(sink=sink).analyse(propose, CRITERIA, weight)

    assert report.purity.calls_detail == ()
    assert sink.calls == ()
    assert sink.record("inject", "net.latency").calls == (("inject", "net.latency"),)


# -- the four checks the engine makes, each shown to decide the answer -------------


def test_the_established_evidence_suppression_is_load_bearing() -> None:
    """Same landscape, same graph, same capture — only the sealed ledger moves.

    If the suppression were decorative, both analyses would produce the same
    finding. It does not: the finding exists only while nothing sealed it, which
    is the whole claim of "a cell sealed evidence already established is not an
    uncovered failure mode".
    """
    established = SealedCell(
        cell_key=GAP_CELL.key, evidence_digest=SEALED_DIGEST, run_label="run-sealed-1"
    )
    sealed = service(evidence=SealedEvidenceLedger((established,)))
    unsealed = service(evidence=SealedEvidenceLedger(()))

    with_chain = sealed.analyse(propose, CRITERIA, weight)
    without_chain = unsealed.analyse(propose, CRITERIA, weight)

    assert [f.cell.key for f in without_chain.findings] == [GAP_CELL.key]
    assert with_chain.findings == ()
    assert GAP_CELL.key in {cell.cell_key for cell in with_chain.suppressed}
    assert GAP_CELL.key not in {cell.cell_key for cell in without_chain.suppressed}
    # The decline names the run that settled it and the digest it settled with,
    # so the difference is auditable rather than a bare count.
    reasons = {cell.cell_key: cell.detail for cell in with_chain.suppressed}
    assert "run-sealed-1" in reasons[GAP_CELL.key]
    assert SEALED_DIGEST[:8] in reasons[GAP_CELL.key]


def test_a_topology_port_that_cannot_name_the_graph_it_read_is_refused() -> None:
    """A blank snapshot id is refused, and naming it is the only thing that differs.

    The break is the collaborator's, not the engine's: the graph is byte-identical
    to the passing case and only the identifier is whitespace. Without a nameable
    snapshot every finding would be pinned to a graph nobody can cite, so this is
    the refusal that keeps a finding from being an assertion about nothing.
    """
    nameless = service(topology=SealedTopology(snapshot="   "))
    named = service(topology=SealedTopology(snapshot="graph-7f3c"))

    with pytest.raises(InvariantViolationError) as excinfo:
        nameless.analyse(propose, CRITERIA, weight)
    assert excinfo.value.rule == RULE_REPLAY_TOPOLOGY_PIN_MISMATCH

    assert named.analyse(propose, CRITERIA, weight).findings


def test_a_coverage_port_that_declares_one_cell_twice_is_refused() -> None:
    """A duplicated cell is a landscape that cannot be read, not a landscape to dedupe.

    Silently collapsing the duplicate would pick a winner for a question the
    declaration does not answer, and the finding derived from it would cite a
    cell that appears once in the report and twice in the record.
    """
    duplicated = service(coverage=SealedCoverage(cells=(GAP_CELL, GAP_CELL)))

    with pytest.raises(InvariantViolationError):
        duplicated.analyse(propose, CRITERIA, weight)


def test_the_graph_identity_is_delegated_to_the_one_digest_everybody_else_uses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The engine must not re-derive the identity admission also computes.

    If it did, "the graph changed" would mean two different things depending on
    who asked, and a replay pinned to one digest could be admitted against
    another. The break replaces the delegated function with a sentinel: if the
    engine computed its own digest instead of calling through, the sentinel would
    never appear and this test would fail.
    """
    sentinel = "delegated-identity-not-recomputed"
    monkeypatch.setattr(advisor_service, "compute_graph_identity", lambda graph: sentinel)

    assert service().graph_identity() == sentinel


# -- and one that keeps the whole surface honest under a total collaborator loss --


def test_a_coverage_port_that_declares_nothing_is_refused_rather_than_read_as_all_clear() -> None:
    """The total collaborator loss: every other port silenced, the landscape empty.

    This is the one place where "an advisor that found no gaps" and "an advisor
    that looked at nothing" have to be told apart, and the engine refuses the
    empty landscape rather than answering. That is stronger than reporting an
    empty result: an empty report would be read as *looked and found none*, which
    is a claim about a system nobody declared a landscape for.
    """
    silent = service(
        coverage=SealedCoverage(cells=(), states={}),
        incidents=SealedIncidents(captures=()),
        deployments=DeployedReleases(releases={}),
        evidence=SealedEvidenceLedger(()),
        sink=LOADED_SINK,
    )

    with pytest.raises(InvariantViolationError) as excinfo:
        silent.analyse(propose, CRITERIA, weight)
    assert excinfo.value.rule == RULE_LANDSCAPE_EMPTY
    # Nothing was consulted past the refusal, and nothing was written on the way.
    assert LOADED_SINK.calls == (("post", "checkout"), ("inject", "net.latency"))
