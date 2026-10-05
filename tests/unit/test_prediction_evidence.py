"""Plan 14 Phase 4 — the five ceilings enforced, the prediction sealed, and the
run scored against it.

Phase 2's suite (``test_prediction_service.py``) proved the preview never mutates
and never comes out calmer than the gate. Phase 2 also left three debts, and this
suite is where they are paid:

===================================  ================================================
Phase 2's debt                        the test that closes it
===================================  ================================================
five ceilings modelled, reported,    ``test_each_ceiling_is_refused_by_the_real_``
and enforced by nobody               ``gate_on_its_own_rule_id`` (all five)
``PENDING_ADMISSION_WIRING`` claimed  ``test_the_wiring_debt_is_empty_and_the_gate``
five rules the gate never emits       ``_agrees_with_it``
the agreement split was emergent —    ``test_an_unmodelled_refusal_is_its_own_
some refusals disqualified a preview  named_state_and_it_disqualifies_the_report``
predictions were never sealed, so     ``test_a_sealed_prediction_round_trips_
nothing could score a run             through_the_attestation_chain``
===================================  ================================================

The order of the file is the order of the debts, and the negative controls are
first-class rather than an afterthought at the end: a ceiling breach refused
*before* mutation, a stale prediction refused for approval use, a blast that
outgrew its forecast opening a finding instead of passing silently, and a seal
with no cited evidence refusing outright.

Two properties are worth stating up front because most of the file rests on them.

**The gate's rule ids and the preview's are the same strings.** ``safety.py``
spells its five ceiling ids as literals (see
:data:`~mayhem.controller.safety.RULE_CEILING_MAX_AFFECTED_NODES`) rather than
importing the constants from ``domain.prediction``, which is what keeps them
visible to the source-scanning completeness test in ``test_proof_compiler.py``.
That is only safe while the two spellings agree, so
``test_the_gates_ceiling_rule_ids_are_the_preview_s_vocabulary`` pins them equal.
If it ever fails, the never-permissive invariant would be comparing two disjoint
vocabularies and passing vacuously — the failure mode Phase 1's comment on the
rule ids warns about by name.

**A hash chain guarantees the bytes were not edited, never that they are the
right bytes.** So :func:`verify_sealed_prediction` re-verifies the chain, then
the manifest, then the payload's own digest. The last of those is what catches an
event body swapped after the fact, and
``test_an_event_body_edited_after_sealing_is_refused_on_its_digest`` is the test
that would fail if it were dropped.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from test_prediction_service import FP, STEP_S, _ctx, _graph, _plan, _service

from mayhem.controller import safety as safety_mod
from mayhem.domain.policy_gate import MutationSink
from mayhem.controller.prediction_service import (
    ADMISSION_WIRING_NOTE,
    ENFORCED_CEILING_RULE_IDS,
    EVENT_PREDICTION_SEALED,
    PENDING_ADMISSION_WIRING,
    PREDICTION_ATTESTATION_SCOPE,
    RULE_PREDICTION_BLAST_EXCEEDED,
    RULE_PREDICTION_NOT_CITED,
    AgreementState,
    PredictionSealingError,
    PredictionService,
    SealedPrediction,
    prediction_scope,
    score_prediction_accuracy,
    seal_prediction,
    verify_sealed_prediction,
)
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, validate_plan
from mayhem.domain.attestation import GENESIS_DIGEST, AttestedTimestamp
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan
from mayhem.domain.prediction import (
    RULE_MAX_AFFECTED_NODES,
    RULE_MAX_AFFECTED_PCT,
    RULE_MAX_CUSTOMER_FACING_SERVICES,
    RULE_MAX_DEPENDENCY_DEPTH,
    RULE_PROTECTED_NODE,
    BlastCeilings,
    graph_identity,
    predict_impact,
)
from mayhem.domain.safety_proof import ObligationName, ObligationStatus
from mayhem.infra.attestation_store import (
    AttestationRepository,
    SigningNotImplementedError,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
RUN_ID = "r-evidence"

#: Every ceiling-breaching configuration in this file, as
#: ``(label, ceilings, expected rule id)``.
#:
#: Built from the fixture graph's own numbers rather than tuned until they pass:
#: ``n-db`` is the deepest target, so its blast reaches four nodes over three
#: dependency hops — 4 of 10 nodes (40%), one of which (``n-web``) exposes a port.
#: Each ceiling is then set strictly inside that, so exactly one fires and the
#: gate stops there. A ceiling set *at* the observed value would breach nothing,
#: which is the "a rule that fires on every plan is a rule nobody can act on"
#: failure Phase 2's suite already guards against.
CEILING_CASES: tuple[tuple[str, BlastCeilings, str], ...] = (
    (
        "protected service list",
        BlastCeilings(protected_node_ids=frozenset({"n-db"})),
        RULE_PROTECTED_NODE,
    ),
    (
        "maximum dependency depth",
        BlastCeilings(max_dependency_depth=1),
        RULE_MAX_DEPENDENCY_DEPTH,
    ),
    (
        "maximum customer-facing services",
        BlastCeilings(max_customer_facing_services=0),
        RULE_MAX_CUSTOMER_FACING_SERVICES,
    ),
    ("maximum percentage", BlastCeilings(max_affected_pct=5.0), RULE_MAX_AFFECTED_PCT),
    ("blast-radius ceiling", BlastCeilings(max_affected_nodes=2), RULE_MAX_AFFECTED_NODES),
)

#: Golden rendering of a full validation pass with **no ceilings configured**.
#:
#: This is the regression anchor for the whole Phase 4 change to
#: ``controller/safety.py``. The field is optional and defaults to ``None``, so a
#: context that configures nothing must produce byte-identical decisions — same
#: rule ids, same order, same reasons, same input keys. A reworded message, a
#: reordered check, or an extra ``stats`` key on the allow path all break this
#: line, which is the point: "additive" is a claim, and this is what checks it.
#:
#: Captured *before* the ceilings landed, then re-asserted after. Two steps with
#: different targets so the walk covers more than one fault, and a permissive
#: budget so the only rule ids in the output are the two allow decisions per step.
GOLDEN_NO_CEILINGS = "\n".join(
    (
        "policy.allow|allow|net.latency: admitted||['fault_id', 'risk']",
        "blast_radius.allow|allow|net.latency: blast radius within budget||"
        "['fault_id', 'stats']",
        "policy.allow|allow|net.latency: admitted||['fault_id', 'risk']",
        "blast_radius.allow|allow|net.latency: blast radius within budget||"
        "['fault_id', 'stats']",
    )
)


def _dump(ctx: SafetyContext) -> str:
    """A context's decisions as ``rule|outcome|reason|remediation|input keys``."""
    return "\n".join(
        f"{d.rule_id}|{d.outcome}|{d.reason}|{d.remediation}|{sorted(d.inputs)}"
        for d in ctx.decisions
    )


def _ceiling_ctx(ceilings: BlastCeilings) -> SafetyContext:
    """A context with the ceilings admission enforces, and nothing else changed."""
    return replace(_ctx(), blast_ceilings=ceilings)


def _reading() -> AttestedTimestamp:
    """A fixed clock. Nothing in this file reads a real one."""
    return AttestedTimestamp(
        wall_clock=T0, monotonic_ns=1_000_000, uncertainty_ms=0.0, source="test"
    )


def _store(tmp_path) -> Store:
    """A migrated store. Plan 12's real migration list, on a temporary file."""
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


def _prediction(
    ceilings: BlastCeilings | None = None, graph=None, plan: ExecutionPlan | None = None
):
    """One prediction off the fixture graph, with optional ceilings."""
    live = graph if graph is not None else _graph()
    frozen = plan if plan is not None else _plan(("net.latency", "n-db", STEP_S))
    return _service(graph=live, ceilings=ceilings).predict(frozen, _ctx())


def _seal(store: Store, prediction, *, run_id: str = RUN_ID, evidence_ref: str = "preflight:a1"):
    return seal_prediction(
        store, prediction, run_id=run_id, recorded_at=_reading(), evidence_ref=evidence_ref
    )


# =========================================================================== #
# 1. The five ceilings, through the real gate
# =========================================================================== #


def test_the_gates_ceiling_rule_ids_are_the_preview_s_vocabulary():
    """The two spellings of every ceiling id agree, string for string.

    ``safety.py`` spells these as literals so the source-scanning completeness
    test in ``test_proof_compiler.py`` can find them;
    ``domain.prediction`` owns the constants. If the two ever drift, the gate
    refuses on a rule the preview has never heard of, the never-permissive check
    files it under "unmodelled", and every ceiling breach would silently degrade
    from a modelled agreement into a preview that refuses itself for approval —
    with no error anywhere. That is why this is a test and not a convention.
    """
    pairs = {
        safety_mod.RULE_CEILING_PROTECTED_NODE: RULE_PROTECTED_NODE,
        safety_mod.RULE_CEILING_MAX_DEPENDENCY_DEPTH: RULE_MAX_DEPENDENCY_DEPTH,
        safety_mod.RULE_CEILING_MAX_CUSTOMER_FACING_SERVICES: (
            RULE_MAX_CUSTOMER_FACING_SERVICES
        ),
        safety_mod.RULE_CEILING_MAX_AFFECTED_PCT: RULE_MAX_AFFECTED_PCT,
        safety_mod.RULE_CEILING_MAX_AFFECTED_NODES: RULE_MAX_AFFECTED_NODES,
    }
    for gate_rule, preview_rule in pairs.items():
        assert gate_rule == preview_rule, (gate_rule, preview_rule)
    assert set(pairs.values()) == ENFORCED_CEILING_RULE_IDS


#: Parametrisation ids, named so a failure says *which* ceiling rather than
#: "case 3".
CEILING_IDS = [case[0] for case in CEILING_CASES]


@pytest.mark.parametrize(("label", "ceilings", "rule_id"), CEILING_CASES, ids=CEILING_IDS)
def test_each_ceiling_is_refused_by_the_real_gate_on_its_own_rule_id(
    label: str, ceilings: BlastCeilings, rule_id: str
):
    """All five, one at a time, through ``validate_plan`` itself.

    The gate is called directly rather than through the preview, so this says what
    admission does and not merely what a report claims. Each case asserts three
    things: the gate raised, it raised on *this* ceiling's id and not another,
    and the decision recorded the observed value beside the limit — a refusal an
    operator cannot act on is half a refusal.
    """
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = _ceiling_ctx(ceilings)
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(plan, graph, ctx)
    decision = excinfo.value.decision
    assert decision is not None
    assert decision.rule_id == rule_id
    assert decision.outcome == "deny"
    assert rule_id in decision.reason
    # The four numeric ceilings all compare an observed value against a limit, so
    # their messages name the ceiling. The protected list is a membership rule
    # with no limit at all — any hit is a breach, however small the number — so
    # its message names the protected ids instead. Asserting the shape each one
    # actually has is the point: a message that implied a limit the rule does not
    # have would send an operator looking for a number to raise.
    if rule_id == RULE_PROTECTED_NODE:
        assert "protected node(s)" in decision.reason
        assert decision.inputs["protected"]
    else:
        assert "plan-14 ceiling" in decision.reason
        assert decision.inputs["ceiling"] is not None
    assert decision.remediation
    # The refusal is on the context's own decision log, reachable the same way as
    # every other gate refusal.
    assert [d.rule_id for d in ctx.decisions][-1] == rule_id


@pytest.mark.parametrize(("label", "ceilings", "rule_id"), CEILING_CASES, ids=CEILING_IDS)
def test_the_preview_and_the_gate_agree_on_which_ceiling_fires(
    label: str, ceilings: BlastCeilings, rule_id: str
):
    """The gate's refusal is inside the prediction's flagged set.

    This is the invariant that only became checkable in Phase 4. Before the
    ceilings were wired, the gate could not refuse on any of these five ids at
    all, so "the preview is never calmer than the gate" had nothing to say about
    them. Now the gate refuses on exactly the id
    :func:`~mayhem.domain.prediction.predict_impact` flags for the same plan, and
    the agreement lands on :attr:`AgreementState.AGREES` rather than sliding into
    ``UNMODELLED`` — which is the difference between a preview that checked a
    rule and one that cannot speak to it.
    """
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    report = _service(graph, ceilings=ceilings).simulate_plan(plan, _ctx())
    assert report.agreement.gate_refused == {rule_id}
    assert report.agreement.modelled == {rule_id}
    assert report.agreement.unmodelled == frozenset()
    assert report.agreement.state is AgreementState.AGREES
    assert rule_id in report.prediction.rule_ids
    assert report.admitted_by_gate is False
    assert report.dimension(_name_of(rule_id)).breached is True
    assert report.dimension(_name_of(rule_id)).enforced_by_gate is True


def _name_of(rule_id: str):
    """The :class:`CeilingName` a rule id belongs to, for the dimension lookup."""
    from mayhem.controller.prediction_service import CeilingName

    return CeilingName[
        {
            RULE_PROTECTED_NODE: "PROTECTED_SERVICES",
            RULE_MAX_DEPENDENCY_DEPTH: "MAX_DEPENDENCY_DEPTH",
            RULE_MAX_CUSTOMER_FACING_SERVICES: "MAX_CUSTOMER_FACING_SERVICES",
            RULE_MAX_AFFECTED_PCT: "MAX_AFFECTED_PCT",
            RULE_MAX_AFFECTED_NODES: "BLAST_RADIUS_CEILING",
        }[rule_id]
    ]


def test_a_ceiling_breach_is_refused_before_any_mutation():
    """Negative control: plan-time refusal, and the sink is still empty.

    The gate runs at plan time over every step before a run opens, so a ceiling
    breach must stop the plan at admission. The sink is *loaded* first, which is
    what makes the zero informative: a report that hard-coded ``calls == 0``
    would pass this and fail the loaded variant. Without the pre-existing call,
    "nothing was written" and "nothing could be written" look identical.
    """
    sink = MutationSink().record("prior.run", "already happened")
    assert len(sink) == 1
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    service = PredictionService(graph=graph, backend=sink)

    with pytest.raises(SafetyRefusedError):
        validate_plan(plan, graph, _ceiling_ctx(BlastCeilings(max_affected_nodes=2)))

    assert len(sink) == 1
    assert sink.calls == (("prior.run", "already happened"),)
    # And through the preview: it refuses nothing and reaches a verdict, because
    # simulate is inert by construction even when the gate says no.
    report = service.with_config(
        type(service.config)(ceilings=BlastCeilings(max_affected_nodes=2))
    ).simulate_plan(plan, _ctx())
    assert report.agreement.gate_refused == {RULE_MAX_AFFECTED_NODES}
    assert len(sink) == 1


def test_a_ceiling_the_blast_lands_inside_admits_through_the_real_gate():
    """The other direction, and it matters: a ceiling that always fires is inert.

    Every ceiling set *at* the fixture's own measurement — 4 nodes, 3 hops, 40% of
    the graph, 1 customer-facing service — admits. The gate evaluates these rules
    now, so a rule that fired on every plan would be a rule nobody could act on,
    and this is what rules that out.
    """
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    at_the_limit = BlastCeilings(
        max_affected_nodes=4,
        max_dependency_depth=3,
        max_customer_facing_services=1,
        max_affected_pct=40.0,
    )
    validate_plan(plan, graph, _ceiling_ctx(at_the_limit))  # no raise
    report = _service(graph, ceilings=at_the_limit).simulate_plan(plan, _ctx())
    assert report.admitted_by_gate is True
    assert report.agreement.gate_refused == frozenset()
    assert report.breached_dimensions() == ()


def test_an_unconfigured_ceiling_is_unchecked_not_a_silent_pass():
    """``blast_ceilings=BlastCeilings()`` names no limit, so nothing is enforced.

    The all-defaults ceiling set is *not* "all limits zero" — that would refuse
    every plan on the protected list alone. It is "nothing configured", and the
    gate admits. This distinction is the one that made the feature safe to add: a
    caller who constructs a default ceiling set and hands it in gets Phase 2's
    behaviour, not a gate that refuses everything.
    """
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    validate_plan(plan, graph, _ceiling_ctx(BlastCeilings()))
    report = _service(graph).simulate_plan(plan, replace(_ctx(), blast_ceilings=BlastCeilings()))
    assert report.admitted_by_gate is True
    assert report.configured_dimensions == ()
    assert all(d.configured is False for d in report.dimensions)


def test_a_percentage_ceiling_on_an_empty_graph_is_unchecked_not_zero():
    """No nodes means no share to divide by — an unmeasurable ceiling, not a breach.

    With one node targeted the share is 100% of nothing. Treating that as 0.0%
    would admit a plan against an unmeasured dimension, and treating it as 100%
    would refuse every plan against an empty topology. ``domain.prediction``
    skips the rule on an empty graph; the gate must agree, or the two would
    disagree on the very plan this invariant exists to keep them honest about.
    """
    from mayhem.domain.topology import TopologyGraph

    empty = TopologyGraph(nodes=(), edges=())
    plan = _plan(("net.latency", "n-db", STEP_S))
    measured_only = BlastCeilings(max_affected_pct=0.0)
    validate_plan(plan, empty, _ceiling_ctx(measured_only))
    report = _service(empty).simulate_plan(
        plan, replace(_ctx(), blast_ceilings=measured_only)
    )
    verdict = report.dimension(_name_of(RULE_MAX_AFFECTED_PCT))
    assert verdict.configured is True
    assert verdict.observed is None
    assert verdict.breached is False


def test_the_protected_list_matches_targets_not_the_whole_blast():
    """An unavoidable dependent of a protected service is a finding, not a refusal.

    ``n-db`` and ``n-web`` are both on the list, but the plan only *targets*
    ``n-db``; ``n-web`` merely depends on it. Refusing on the dependent would
    make the rule unsatisfiable for any plan touching anything upstream of a
    front door, which is most plans. The preview makes the same distinction, so
    the two agree on which of the two ids is in the set.
    """
    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    protected = BlastCeilings(protected_node_ids=frozenset({"n-db", "n-web"}))
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(plan, graph, _ceiling_ctx(protected))
    assert excinfo.value.decision is not None
    assert excinfo.value.decision.inputs["protected"] == ["n-db"]

    report = _service(graph, ceilings=protected).simulate_plan(plan, _ctx())
    rule = next(r for r in report.prediction.violated_rules if r.rule_id == RULE_PROTECTED_NODE)
    assert rule.observed_ids == ("n-db",)
    assert "n-web" in report.prediction.affected_node_ids  # protected, but only a dependent


def test_no_ceiling_pass_is_byte_identical_to_the_golden():
    """The regression anchor. See :data:`GOLDEN_NO_CEILINGS` for why this matters."""
    ctx = _ctx()
    assert ctx.blast_ceilings is None  # the field's default, so nothing is configured
    validate_plan(
        _plan(("net.latency", "n-db", STEP_S), ("net.latency", "n-edge", STEP_S)),
        _graph(),
        ctx,
    )
    assert _dump(ctx) == GOLDEN_NO_CEILINGS
    assert ctx.warnings == []


def test_a_context_built_without_the_field_is_unchanged():
    """Positional-and-keyword construction of the pre-Phase-4 signature still works.

    A new field with a default is only additive if the old call sites keep working
    unchanged. Every construction in the tree passes keywords, but this asserts the
    property directly rather than relying on that being true forever.
    """
    legacy = SafetyContext(policy=_ctx().policy, budget=BlastRadiusBudget(), fingerprint=FP)
    assert legacy.blast_ceilings is None
    # And ``policy_gate`` is still the last field, which
    # ``tests/unit/test_policy_gate.py`` pins.
    from dataclasses import fields

    assert [f.name for f in fields(SafetyContext)][-1] == "policy_gate"


def test_the_wiring_debt_is_empty_and_the_gate_agrees_with_it():
    """Phase 2's tripwire, inverted. See the module docstring's table.

    The negative form Phase 2 used ("no pending rule is one the gate can emit")
    was *designed to fire* when Phase 4 landed, and it did. The surviving form is
    the other direction: every ceiling the preview reports as enforced must be one
    the gate actually raises, observed by running it rather than by reading a list.
    """
    assert PENDING_ADMISSION_WIRING == ()
    emitted: set[str] = set()
    for _, ceilings, _ in CEILING_CASES:
        try:
            validate_plan(
                _plan(("net.latency", "n-db", STEP_S)),
                _graph(),
                _ceiling_ctx(ceilings),
            )
        except SafetyRefusedError as exc:
            if exc.decision is not None:
                emitted.add(exc.decision.rule_id)
    # The battery refused something, or this proves nothing.
    assert emitted == ENFORCED_CEILING_RULE_IDS


def test_the_admission_wiring_note_no_longer_claims_the_ceilings_are_unenforced():
    """A note that lies is worse than no note.

    Phase 2's note said "enforced by nobody" on every report. Now that admission
    enforces all five, leaving that text would put an active misstatement in front
    of every approver — and it would read as a *disclosure*, which is the exact
    register a reader trusts.
    """
    assert "nobody" not in ADMISSION_WIRING_NOTE
    assert "enforced" in ADMISSION_WIRING_NOTE
    report = _service().simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert ADMISSION_WIRING_NOTE in report.notes


# =========================================================================== #
# 2. The explicit UNMODELLED state
# =========================================================================== #


def test_an_unmodelled_refusal_is_its_own_named_state_and_disqualifies_the_report():
    """The debt Phase 2 left emergent, stated as a rule and tested.

    Phase 2's note: folding unmodelled refusals into the one-directional check
    "would make ``agrees`` false for every correctly-scoped preview… They go to
    ``GateAgreement.unmodelled`` and make the report unusable for approval
    instead." That consequence was real but it lived in a different function from
    the split that produced it, so a reader had to reconstruct it. Phase 4 makes
    it :attr:`AgreementState.UNMODELLED` — a member of a closed three, with its own
    ``usable_for_approval`` answer — and this asserts the whole chain: modelled
    side strict, unmodelled side disqualifying, ``agrees`` still true.
    """
    from mayhem.config import PolicyCfg

    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = replace(_ctx(), policy=PolicyCfg(deny_faults=frozenset({"net.latency"})))
    report = _service(graph).simulate_plan(plan, ctx)

    # The modelled side is untouched: nothing modelled, nothing missed, agreement.
    assert report.agreement.modelled == frozenset()
    assert report.agreement.agrees is True
    # The unmodelled side is a named state, and it disqualifies.
    assert report.agreement.unmodelled == {"policy.deny_faults"}
    assert report.agreement.state is AgreementState.UNMODELLED
    assert report.agreement.usable_for_approval is False
    assert report.agreement_state is AgreementState.UNMODELLED
    assert report.usable_for_approval is False
    # Named by a rule id, so a surface can render it as a finding.
    assert "prediction.unmodelled_gate_refusal" in report.approval_refusal
    # …and described as such in the one-screen summary.
    assert "[agreement: unmodelled]" in report.describe()


def test_an_unmodelled_refusal_does_not_make_the_preview_look_in_agreement():
    """``agrees`` stays true, and that is *not* a pass.

    The subtle part of the Phase 2 debt, and the one a naive "just fold them in"
    fix would destroy: ``agrees is True`` while the report is unusable. Asserting
    both together is the point — a boolean that reads ``True`` on a report nobody
    may approve with is the trap, and the named state is what makes it safe to
    leave the boolean true.
    """
    from mayhem.config import PolicyCfg

    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = replace(_ctx(), policy=PolicyCfg(deny_faults=frozenset({"net.latency"})))
    report = _service().simulate_plan(plan, ctx)
    assert report.agreement.agrees is True
    assert report.usable_for_approval is False
    assert AgreementState.UNMODELLED.usable_for_approval is False
    assert AgreementState.AGREES.usable_for_approval is True
    assert AgreementState.DISAGREES.usable_for_approval is False


def test_a_prediction_that_missed_a_modelled_rule_still_raises_and_stays_strict():
    """The modelled side is strict: a defect raises rather than becoming a state.

    Phase 4 added a third state but did not soften this half. A prediction that
    misses a rule the gate refused on is a bug in the preview, and the answer is
    still an exception — because a returned report would travel, and would show an
    approver "fine" for a plan that cannot run.
    """
    from mayhem.controller.prediction_service import PredictionDisagreementError

    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    # A 25% service cap the gate refuses (n-db's blast reaches every service), and
    # a prediction computed through a budget nothing trips. That is the shape of a
    # drifting duplicate implementation, and the shape the raise exists for.
    gate_budget = BlastRadiusBudget(
        max_services_pct=25.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
    )
    permissive_budget = BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
    )
    too_calm = predict_impact(graph, plan, budget=permissive_budget)
    assert not too_calm.rule_ids  # the injected forecast sees nothing wrong

    from mayhem.controller import prediction_service

    original = prediction_service.predict_impact

    def _injected(*args, **kwargs):
        return too_calm

    prediction_service.predict_impact = _injected
    try:
        with pytest.raises(PredictionDisagreementError):
            _service(graph).simulate_plan(plan, replace(_ctx(), budget=gate_budget))
    finally:
        prediction_service.predict_impact = original

    # The state the comparison would have reached, asserted directly so the raise
    # is not mistaken for the mechanism.
    landed = prediction_service._agreement(
        too_calm, frozenset({"blast_radius.max_services_pct"})
    )
    assert landed.state is AgreementState.DISAGREES
    assert landed.usable_for_approval is False
    assert "never be calmer" in landed.reason


def test_an_agreement_record_cannot_assert_a_state_its_own_fields_contradict():
    """The negative control on the state: the record refuses to lie about itself.

    Giving the record a ``state`` field without this check would have *moved* the
    Phase 2 problem rather than closed it — a caller could build
    ``state=UNMODELLED`` beside ``agrees=False`` and every surface reading the
    state would be told something the record's own fields deny. So
    ``__post_init__`` re-derives the state and refuses a mismatch, and omitting it
    is a ``TypeError`` rather than a silent default.
    """
    from mayhem.controller.prediction_service import GateAgreement

    base = {
        "gate_refused": frozenset({"policy.deny_faults"}),
        "modelled": frozenset(),
        "unmodelled": frozenset({"policy.deny_faults"}),
        "flagged": frozenset(),
        "agrees": True,
        "reason": "",
    }
    with pytest.raises(TypeError):
        GateAgreement(**base)  # type: ignore[arg-type]
    with pytest.raises(InvariantViolationError):
        GateAgreement(**base, state=AgreementState.AGREES)  # type: ignore[arg-type]
    assert (
        GateAgreement(**base, state=AgreementState.UNMODELLED).state  # type: ignore[arg-type]
        is AgreementState.UNMODELLED
    )


# =========================================================================== #
# 3. Sealing the prediction with the plan
# =========================================================================== #


def test_a_sealed_prediction_round_trips_through_the_attestation_chain(tmp_path):
    """Seal, reload, and get *the object back* — not a summary of it.

    The load-bearing assertion is equality with the original
    :class:`~mayhem.domain.prediction.ImpactPrediction`, not merely that something
    came back. Post-run scoring compares the observed blast against the numbers
    that were sealed; a reload that silently dropped a field or coerced a tuple to
    a list would score the run against a prediction nobody ever made, and the
    finding it opens would be about the wrong thing.
    """
    store = _store(tmp_path)
    prediction = _prediction()

    sealed = _seal(store, prediction)
    loaded, reason = verify_sealed_prediction(store, RUN_ID)

    assert reason == ""
    assert loaded is not None
    assert loaded.prediction == prediction
    assert loaded.prediction_digest == sealed.prediction_digest
    assert loaded.scope == sealed.scope
    assert loaded.evidence_ref == sealed.evidence_ref
    # Every nested structure survived, including the parts a shallow round trip
    # would flatten: the fan-out, the per-step impacts, the cost breakdown, the
    # violated rules with their observed values.
    assert loaded.prediction.fan_out.nodes == prediction.fan_out.nodes
    assert loaded.prediction.steps == prediction.steps
    assert loaded.prediction.cost == prediction.cost
    assert loaded.prediction.replica_loss == prediction.replica_loss
    assert loaded.prediction.violated_rules == prediction.violated_rules
    assert loaded.prediction.basis == prediction.basis
    assert isinstance(loaded.prediction.affected_node_ids, tuple)


def test_the_seal_reuses_plan_twelve_s_existing_tables_and_verifies_offline(tmp_path):
    """Reuse, not a second sealer: same tables, same verifier, no new schema.

    Mirrors ``tests/unit/test_proof_compiler.py``'s reuse assertion for the proof
    seal. If this module had built its own chain, an auditor running plan 12's
    verifier would find nothing to check, and there would be two places where
    "was this sealed?" has an answer.
    """
    store = _store(tmp_path)
    sealed = _seal(store, _prediction())

    # Plan 12's own repository verifies the stored bytes.
    verification = AttestationRepository(store).verify_run_chain(sealed.scope)
    assert verification.valid, verification.errors
    # And it lands under its own scope, so it cannot overwrite the run-close chain
    # or the proof seal — the three are keyed differently.
    assert sealed.scope == f"{RUN_ID}{PREDICTION_ATTESTATION_SCOPE}"
    assert sealed.scope != RUN_ID
    assert sealed.scope != f"{RUN_ID}:proof"
    assert verification.root_digest == sealed.chain_root


def test_the_seal_attests_integrity_and_never_authorship(tmp_path):
    """Unsigned, with the reason stored — plan 12's honesty gate, not bypassed.

    A sealed prediction is evidence; evidence that claimed authorship without a
    signature would turn "the bytes were not edited" into "somebody stood behind
    this", which is the overclaim plan 12 exists to remove.
    """
    store = _store(tmp_path)
    sealed = _seal(store, _prediction())
    assert sealed.signed is False
    assert sealed.signature_state == "unsigned_no_signing"
    assert "no signature bytes" in sealed.signature_reason
    assert sealed.chain_verification.valid is True
    assert sealed.manifest_verification.valid is True


def test_a_prediction_cannot_be_sealed_with_a_named_signer(tmp_path):
    """Naming a signer is refused, for plan 12's reason, not this module's."""
    store = _store(tmp_path)
    with pytest.raises(SigningNotImplementedError):
        seal_prediction(
            store,
            _prediction(),
            run_id=RUN_ID,
            recorded_at=_reading(),
            evidence_ref="preflight:a1",
            signer=object(),
        )
    # Nothing was written.
    loaded, reason = verify_sealed_prediction(store, RUN_ID)
    assert loaded is None
    assert EVENT_PREDICTION_SEALED in reason


def test_a_seal_needs_a_non_blank_run_id():
    """The scope is a primary key; an empty one would key a whole chain to nothing."""
    with pytest.raises(InvariantViolationError):
        prediction_scope("   ")


def test_a_sealed_forecast_may_be_one_that_flagged_breaches(tmp_path):
    """An inaccurate forecast is sealed, not refused.

    The obvious-looking "only seal clean predictions" rule would be a serious
    defect: the predictions worth scoring are the ones that were wrong. Refusing
    them would mean the over-predictions get recorded and the under-predictions —
    the findings — get thrown away, which inverts the whole purpose.
    """
    store = _store(tmp_path)
    wrong = _prediction(ceilings=BlastCeilings(max_affected_nodes=1))
    assert wrong.rule_ids  # a flagged, truncated prediction
    sealed = _seal(store, wrong)
    loaded, reason = verify_sealed_prediction(store, RUN_ID)
    assert reason == ""
    assert loaded is not None
    assert loaded.prediction == wrong
    assert sealed.prediction_digest


def test_an_event_body_edited_after_sealing_is_refused_on_its_digest(tmp_path):
    """A hash chain proves the bytes were not edited, never that they are right.

    The chain links over the event digests, so re-hashing a *tampered* event still
    produces a self-consistent chain — which is why the reload re-computes the
    payload's own digest and compares it to the value recorded beside it. Without
    that last check, editing the sealed body to name a different prediction would
    verify cleanly and post-run analysis would score the run against the
    substitute.
    """
    store = _store(tmp_path)
    sealed = _seal(store, _prediction())
    other = _prediction(ceilings=BlastCeilings(max_affected_nodes=1))

    with store.write() as conn:
        payload = dict(sealed.events[0].payload)
        payload["prediction"] = _payload_of(other)
        payload["prediction_digest"] = sealed.prediction_digest  # keep the old digest
        conn.execute(
            "UPDATE attestation_events SET event_json = ? WHERE run_id = ? AND sequence = 0",
            (
                sealed.events[0].model_copy(update={"payload": payload}).model_dump_json(),
                sealed.scope,
            ),
        )

    loaded, reason = verify_sealed_prediction(store, RUN_ID)
    assert loaded is None
    assert "digest" in reason


def _payload_of(prediction) -> dict:
    """The JSON-native body :func:`prediction_seal_event` would have stored."""
    from mayhem.controller.prediction_service import _prediction_payload

    return _prediction_payload(prediction)


def test_a_seal_with_no_cited_evidence_is_refused(tmp_path):
    """Negative control: a prediction with no cited evidence cannot back a decision.

    ``evidence_ref`` is required and must be non-blank. A sealed forecast that
    names nothing it was computed from is a number with no provenance, and "we
    predicted this" is not the whole of a record somebody has to stand behind. The
    refusal happens *before* any chain is built, so nothing is written.
    """
    store = _store(tmp_path)
    prediction = _prediction()
    for blank in ("", "   "):
        with pytest.raises(PredictionSealingError) as excinfo:
            seal_prediction(
                store, prediction, run_id=RUN_ID, recorded_at=_reading(), evidence_ref=blank
            )
        assert excinfo.value.rule == RULE_PREDICTION_NOT_CITED
        assert "cites no evidence" in str(excinfo.value)
    loaded, reason = verify_sealed_prediction(store, RUN_ID)
    assert loaded is None
    assert EVENT_PREDICTION_SEALED in reason


def test_an_uncited_seal_is_refused_on_read_back_too():
    """The citation is checked on the way back in, not only on the way out.

    Enforcing it in ``seal_prediction`` alone would leave a gap for a payload
    that arrived uncited by some other route, and reading a seal back is exactly
    the moment an uncited forecast would be handed to a scorer as though it could
    back a decision. So the reload re-checks, with the same named rule.

    Tested through the helper rather than by editing a stored row, because
    editing the row is caught one layer earlier — the chain digest fires, which is
    the *stronger* answer and is what
    ``test_an_event_body_edited_after_sealing_is_refused_on_its_digest`` pins.
    Deliberately editing a byte would only ever reach this branch if the chain
    check were removed, and a test that has to be broken before it can pass is not
    a test.
    """
    from mayhem.controller.prediction_service import _cited_evidence

    reason, cited = _cited_evidence({"evidence_ref": ""}, RUN_ID)
    assert cited == ""
    assert "cites no evidence" in reason
    assert "cannot back a decision" in reason

    reason, cited = _cited_evidence({"evidence_ref": "proof:9f2c1a"}, RUN_ID)
    assert reason == ""
    assert cited == "proof:9f2c1a"
    # A key that is entirely absent is the same refusal, not a KeyError.
    reason, cited = _cited_evidence({}, RUN_ID)
    assert cited == "" and reason


def test_an_unsealed_run_reports_that_named_rather_than_a_bare_none(tmp_path):
    """The post-run analysis has to distinguish "no forecast" from "broken seal"."""
    store = _store(tmp_path)
    loaded, reason = verify_sealed_prediction(store, "r-never-sealed")
    assert loaded is None
    assert EVENT_PREDICTION_SEALED in reason
    assert prediction_scope("r-never-sealed") in reason


# =========================================================================== #
# 4. Scoring a run against its forecast
# =========================================================================== #


def test_a_run_whose_blast_exceeded_its_prediction_opens_a_finding(tmp_path):
    """The plan's acceptance criterion, as a test.

    Plan 14 §Phase 4: "a run whose actual blast exceeded prediction opens a
    finding, not a silent pass". The severity is the load-bearing part and it is
    why this reads as a *set* comparison rather than a count: six affected nodes
    against a five-node forecast is not "20% worse", it is one node nobody told an
    approver about. So any observed id the prediction did not name opens the
    finding, and the ids are named so a reader can go and look at them.
    """
    store = _store(tmp_path)
    sealed = _seal(store, _prediction())
    predicted = sealed.prediction.affected_node_ids
    assert predicted  # the fixture predicts something

    actual = (*predicted, "n-unexpected")
    accuracy = score_prediction_accuracy(sealed, actual_node_ids=actual)

    assert accuracy.understated is True
    assert accuracy.holds is False
    assert accuracy.unpredicted_node_ids == ("n-unexpected",)
    assert accuracy.overstated_node_ids == ()
    assert accuracy.actual_node_ids == tuple(sorted(actual))
    assert accuracy.predicted_node_ids == predicted
    assert accuracy.finding
    assert "n-unexpected" in accuracy.finding
    assert RULE_PREDICTION_BLAST_EXCEEDED in accuracy.describe()
    assert "understated" in accuracy.describe()


def test_a_prediction_that_named_the_blast_reports_no_finding(tmp_path):
    """The control: an accurate forecast must not be scored as a finding.

    Without this, a scorer that always opened a finding would pass the test above.
    """
    store = _store(tmp_path)
    sealed = _seal(store, _prediction())
    actual = sealed.prediction.affected_node_ids

    accuracy = score_prediction_accuracy(sealed, actual_node_ids=actual)
    assert accuracy.understated is False
    assert accuracy.holds is True
    assert accuracy.unpredicted_node_ids == ()
    assert accuracy.overstated_node_ids == ()
    assert accuracy.accuracy_pct == 100.0
    assert accuracy.finding == ""
    assert RULE_PREDICTION_BLAST_EXCEEDED not in accuracy.describe()


def test_a_prediction_that_over_estimated_is_recorded_but_is_not_a_finding(tmp_path):
    """The conservative direction is disclosed, never treated as a match or a fault.

    A preview that over-estimated is the failure this whole module is built
    around — over-reporting is always allowed, because a preview reads a snapshot
    and the gate reads live state. So the extra nodes are named (an analyst can
    see a pessimistic forecast without diffing numbers later) but they open no
    finding about the run, because the run did not exceed anything.
    """
    store = _store(tmp_path)
    sealed = _seal(store, _prediction())
    predicted = sealed.prediction.affected_node_ids
    actual = predicted[:2]

    accuracy = score_prediction_accuracy(sealed, actual_node_ids=actual)
    assert accuracy.understated is False
    assert accuracy.holds is True
    assert accuracy.finding == ""
    assert accuracy.overstated_node_ids == tuple(sorted(predicted[2:]))
    assert accuracy.accuracy_pct == 100.0
    assert "over-estimating" in accuracy.describe()


def test_accuracy_is_scored_against_the_reloaded_seal_not_an_in_memory_object(tmp_path):
    """The end-to-end path: seal, reload off disk, then score what came back.

    Scoring a prediction still in memory would pass while the *sealed* one — the
    one an auditor has — was unreadable. So this goes through
    :func:`verify_sealed_prediction` and scores the reloaded object, which is the
    only object a post-run analysis can legitimately have.
    """
    store = _store(tmp_path)
    _seal(store, _prediction())
    loaded, reason = verify_sealed_prediction(store, RUN_ID)
    assert loaded is not None and reason == ""

    # The reloaded record is scored directly. ``score_prediction_accuracy`` takes
    # both the seal-time and the read-back record, because a post-run analysis
    # hours later holds only the second — and a scorer that accepted only the
    # first would push that analysis into fabricating a record it does not have.
    scored = score_prediction_accuracy(
        loaded, actual_node_ids=[*loaded.prediction.affected_node_ids, "n-late"]
    )
    assert scored.understated is True
    assert scored.unpredicted_node_ids == ("n-late",)
    assert scored.evidence_ref == loaded.evidence_ref
    assert scored.plan_identity == loaded.prediction.plan_identity


def test_the_finding_quotes_the_evidence_the_forecast_rests_on(tmp_path):
    """A finding a reader cannot follow is not actionable.

    The accuracy record carries ``evidence_ref`` so the finding names what the
    forecast was computed from. An analyst reading "the blast exceeded prediction"
    needs to be able to go and get the prediction that was wrong.
    """
    store = _store(tmp_path)
    sealed = _seal(store, _prediction(), evidence_ref="proof:9f2c1a")
    accuracy = score_prediction_accuracy(
        sealed, actual_node_ids=[*sealed.prediction.affected_node_ids, "n-x"]
    )
    assert accuracy.evidence_ref == "proof:9f2c1a"
    assert accuracy.plan_identity == sealed.prediction.plan_identity


def test_an_unmeasured_actual_blast_is_none_rather_than_a_passing_zero(tmp_path):
    """No observed nodes means no ratio — not "100% accurate".

    ``0.0`` would read as "the prediction named none of it", which is a different
    and much worse claim than "we did not observe anything". The record says which.
    """
    store = _store(tmp_path)
    sealed = _seal(store, _prediction())
    accuracy = score_prediction_accuracy(sealed, actual_node_ids=[])
    assert accuracy.accuracy_pct is None
    assert accuracy.actual_node_ids == ()
    assert accuracy.understated is False


def test_an_unmeasured_depth_is_reported_as_unmeasured_not_as_the_forecast(tmp_path):
    """The depth column must not silently inherit the prediction's number.

    Defaulting ``actual_fan_out_depth`` to ``predicted_fan_out_depth`` would make
    an unmeasured run look accurate in a second, independent column. ``None`` says
    "we did not look".
    """
    store = _store(tmp_path)
    sealed = _seal(store, _prediction())
    unmeasured = score_prediction_accuracy(
        sealed, actual_node_ids=sealed.prediction.affected_node_ids
    )
    assert unmeasured.actual_fan_out_depth is None
    assert unmeasured.predicted_fan_out_depth == sealed.prediction.fan_out.max_depth

    measured = score_prediction_accuracy(
        sealed,
        actual_node_ids=sealed.prediction.affected_node_ids,
        actual_fan_out_depth=sealed.prediction.fan_out.max_depth,
    )
    assert measured.actual_fan_out_depth == sealed.prediction.fan_out.max_depth


def test_a_prediction_computed_over_an_empty_graph_cannot_back_a_decision():
    """The Phase 1 refusal, and the reason a seal of it is worthless.

    An empty-graph prediction has an empty affected set that describes *nothing
    observed*, not an unaffected system. Scoring a run against it would open a
    finding for every node the run touched — correct by accident, and useless,
    because the forecast was never a measurement.
    """
    from mayhem.domain.topology import TopologyGraph

    empty = TopologyGraph(nodes=(), edges=())
    report = _service(empty).simulate_plan(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    assert report.usable_for_approval is False
    assert "empty topology" in report.approval_refusal
    review = _service(empty).review(report.prediction)
    assert review.usable_for_approval is False
    assert "empty topology" in review.reason


def test_a_stale_prediction_is_refused_for_approval_use():
    """Negative control: numbers from a topology that has since changed.

    A prediction sealed against one graph and read after a topology change
    describes the past. The review re-derives identities rather than trusting a
    timestamp, and refuses — naming the staleness, so the operator re-predicts
    against current state instead of re-reading old numbers as current.
    """
    from mayhem.domain.topology import Edge, EdgeKind

    before = _graph()
    after = type(before)(
        nodes=before.nodes,
        edges=(*before.edges, Edge(src="n-db", dst="n-web", kind=EdgeKind.DEPENDS_ON)),
    )
    prediction = _prediction(graph=before)
    assert graph_identity(before) != graph_identity(after)

    review = _service(after).review(prediction)
    assert review.usable_for_approval is False
    assert "stale" in review.reason
    assert "re-predict" in review.reason
    assert review.graph_identity == prediction.graph_identity


def test_a_prediction_over_a_re_planned_plan_is_also_refused():
    """Drift in *either* input invalidates it: the plan moved, so the numbers did too."""
    service = _service()
    prediction = service.predict(_plan(("net.latency", "n-db", STEP_S)), _ctx())
    other = _plan(("net.latency", "n-edge", STEP_S))
    assert service.review(prediction, plan=other).usable_for_approval is False


# =========================================================================== #
# 5. THE DEBT THIS LANE RECORDED, AND WHAT CLOSED IT
# =========================================================================== #
#
# REQUIREMENT 2 OF WORK ITEM W014e, RECORDED RATHER THAN PAPERED OVER — and then
# paid, rather than left as a standing failure.
#
# `controller/safety_proof.OBLIGATION_FOR_RULE` maps every rule a gate can refuse
# to the obligation that owns it, and `_blame` turns a rule with no owning line
# into a whole-proof `VOID`. Phase 4 added five refusals to `controller/safety.py`
# and the mapping was **not** in `safety_proof.py` — which this lane was forbidden
# to edit, because several lanes were in it concurrently.
#
# The consequence was real and was measured here rather than assumed: a run refused
# on a plan-14 ceiling compiled to a `VOID` proof naming a rule the compiler could
# not place. Fail-closed — never a silent PASS — but strictly worse than the `FAIL`
# the `target_policy` line could report, because it told an operator "no obligation
# owns this" instead of "this obligation failed".
#
# The block below originally asserted that debt was still owed, and said in its own
# docstring that whoever added the five rows would delete it in the same change.
# That is what happened. What is here now is the claim that is true instead.
#
# THE MAPPING THAT LANDED — five rows in `OBLIGATION_FOR_RULE` in
# `src/mayhem/controller/safety_proof.py`:
#
#     RULE_PROTECTED_NODE:               ObligationName.TARGET_POLICY.value,
#     RULE_MAX_DEPENDENCY_DEPTH:         ObligationName.TARGET_POLICY.value,
#     RULE_MAX_CUSTOMER_FACING_SERVICES: ObligationName.TARGET_POLICY.value,
#     RULE_MAX_AFFECTED_PCT:             ObligationName.TARGET_POLICY.value,
#     RULE_MAX_AFFECTED_NODES:           ObligationName.TARGET_POLICY.value,
#
# `TARGET_POLICY` is the right owner for all five and for a reason already stated
# in that module: the nine-name spine has no line of its own for "how much of the
# system may this plan touch", and these five are exactly that question. The
# module's own comment on the existing target-side caps says as much — see the
# `-- target-side caps, fault combinations, and target support` block, which is
# where these five belong beside `RULE_MAX_HOSTS` and `RULE_FORBIDDEN_FAULT_PAIRS`.
#
# 1. `GATE_RULE_IDS` in the same module. Without it a prediction that *flagged* a
#    ceiling breach was filtered out of the blame set entirely, because
#    `compile_safety_evidence` intersects `prediction.rule_ids & GATE_RULE_IDS` —
#    the same hole in the opposite direction, and quieter still: the artifact
#    simply did not mention the finding.
#
# 2. `controller/check_gate.py`'s `RULE_CHECK`. This lane's note said nothing was
#    owed there, on the grounds that `DEFAULT_RULE_CHECK` resolves the five
#    already. The mapping went further and enumerated them, because that is what
#    the default is *not* for: `DEFAULT_RULE_CHECK` answers for a rule id nobody
#    in this repository authored, and these five are `check_blast_radius`'s own.
#    Leaving them on the default would have reported a blast-radius ceiling breach
#    under the safety-policy check, which is the wrong board for an operator to
#    be sent to.
#
# All three landed in one change:
#
# 1. `OBLIGATION_FOR_RULE` in `safety_proof.py` gained the five rows below.
# 2. `GATE_RULE_IDS` gained them, closing the quieter mirror of the same gap.
# 3. `check_gate.RULE_CHECK` gained them, at `CheckScope.BLAST_RADIUS`.
#
# `test_every_rule_the_gates_can_raise_has_an_owning_proof_line` is green, and it
# is green because the mapping exists — not because the guard went quiet. The
# negative control below is what pins that distinction: it proves the scanner
# still sees all five rule ids in `safety.py` source, so the guard would fail by
# name again the moment a sixth ceiling was added without a row.

CEILING_RULES: tuple[str, ...] = (
    "blast_radius.max_affected_nodes",
    "blast_radius.max_affected_pct",
    "blast_radius.max_customer_facing_services",
    "blast_radius.max_dependency_depth",
    "blast_radius.protected_node",
)


def test_the_five_ceiling_rules_are_owned_by_the_target_policy_line():
    """The debt, paid: all five are blameable, and on the line that describes them.

    This test is the mirror image of the one it replaces, which asserted the debt
    was still owed and was written to fail the moment it stopped being true. An
    assertion that a mapping is *absent* is only safe while it is absent; leaving
    it in place would have been a lie of the opposite kind, so it is gone.

    What replaces it is the claim that is actually true now, and the owner is not
    free: it is the line whose question these five *are* — how much of the system
    this plan may touch — beside ``RULE_MAX_HOSTS`` and
    ``RULE_FORBIDDEN_FAULT_PAIRS``, which the same function raises alongside them.
    """
    from mayhem.controller.safety_proof import (
        CEILING_RULE_IDS,
        GATE_RULE_IDS,
        OBLIGATION_FOR_RULE,
    )

    assert set(CEILING_RULES) == set(CEILING_RULE_IDS), (
        "the ceiling rule ids this file names and the ones safety_proof narrows out "
        f"of GATE_RULE_IDS have diverged: {sorted(set(CEILING_RULES) ^ CEILING_RULE_IDS)}"
    )
    for rule in CEILING_RULES:
        assert OBLIGATION_FOR_RULE[rule] == ObligationName.TARGET_POLICY.value, rule
        # Also blameable from a *prediction*, not only from the gate. Without this
        # a prediction flagging a breached ceiling contributed no blame entry and
        # the artifact did not mention it — the same hole, quieter.
        assert rule in GATE_RULE_IDS, rule


def test_a_ceiling_breach_reaches_the_blast_radius_check_not_the_default():
    """``RULE_CHECK`` enumerates the five, so the default never gets a vote.

    ``DEFAULT_RULE_CHECK`` is right for a bundle-authored rule id and wrong for a
    gate's own: it would file a ceiling breach under ``safety_policy``, sending an
    operator to read about approvals when the thing that happened was that a blast
    radius exceeded a plan-14 ceiling.
    """
    from mayhem.controller.check_gate import (
        DEFAULT_RULE_CHECK,
        RULE_CHECK,
        CheckScope,
        check_for_rule,
    )
    from mayhem.controller.safety_proof import OBLIGATION_FOR_RULE

    for rule in CEILING_RULES:
        assert rule in RULE_CHECK, rule
        assert check_for_rule(rule) is CheckScope.BLAST_RADIUS, rule
    # Still total: a bundle's own rule id keeps falling to the default, which is
    # the one behaviour this table must not change.
    assert "checkout.blocklist_v3" not in RULE_CHECK
    assert check_for_rule("checkout.blocklist_v3") is DEFAULT_RULE_CHECK
    # And the two tables cover the same set, which is what the completeness guard
    # in test_proof_compiler.py enforces from the other side.
    assert set(RULE_CHECK) == set(OBLIGATION_FOR_RULE), (
        "OBLIGATION_FOR_RULE and check_gate.RULE_CHECK must cover the same rule set: "
        f"only in OBLIGATION_FOR_RULE {sorted(set(OBLIGATION_FOR_RULE) - set(RULE_CHECK))}; "
        f"only in RULE_CHECK {sorted(set(RULE_CHECK) - set(OBLIGATION_FOR_RULE))}"
    )


def test_the_ceiling_rules_are_still_found_by_the_completeness_guard():
    """The five are STILL visible to ``test_proof_compiler``'s source scanner.

    This is the negative control on the *whole* reason the ids are inlined as
    literals in ``safety.py`` rather than passed as module constants. The scanner
    resolves a rule id from a ``_deny_decision`` call only when the first argument
    is a plain literal; a bare ``Name`` is skipped as one of the module's dynamic
    refusals. Had the five been passed as constants, this assertion would fail —
    and with it, ``test_every_rule_the_gates_can_raise_has_an_owning_proof_line``
    would go green *while the mapping was still missing*, which is the silent
    ``VOID`` this whole block exists to prevent.

    It stays after the mapping lands, and that is the point of keeping it: it is
    what makes the guard in ``test_proof_compiler.py`` trustworthy *now* too. A
    sixth ceiling added to ``safety.py`` next wave, or the five being quietly
    refactored to use the module constants "to tidy up", both break this first —
    and the completeness guard goes quiet without anyone noticing, which is the
    failure mode the inlining exists to rule out permanently rather than for one
    release.
    """
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "_tpc_scan", Path(__file__).with_name("test_proof_compiler.py")
    )
    scanner = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(scanner)
    found = scanner.blameable_rule_ids(
        (Path(__file__).resolve().parents[2] / "src/mayhem/controller/safety.py").read_text(
            encoding="utf-8"
        )
    )
    assert set(CEILING_RULES) <= found


def test_a_ceiling_refusal_now_fails_the_target_policy_line_rather_than_voiding():
    """The flip this block's last test named as the acceptance criterion for the debt.

    It asserted the ``VOID`` because that is what the missing mapping produced.
    With the rows in place the same run produces a ``FAIL`` on ``target_policy``
    naming the rule in the line's own detail, and the proof is no longer ``VOID``:
    an operator reading it is told *which obligation failed and why*, not that a
    rule exists that nobody owns.

    The run is the same one — a protected node in the plan's target set — and the
    gate is the real one, so this is the same measurement rather than a new claim
    about a different path.
    """
    import importlib.util
    from pathlib import Path

    from mayhem.controller.safety_proof import ProofVerdict, compile_safety_evidence

    spec = importlib.util.spec_from_file_location(
        "_tpc_scan2", Path(__file__).with_name("test_proof_compiler.py")
    )
    scanner = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(scanner)

    graph = _graph()
    plan = _plan(("net.latency", "n-db", STEP_S))
    ctx = _ceiling_ctx(BlastCeilings(protected_node_ids=frozenset({"n-db"})))
    compilation = compile_safety_evidence(plan, graph, ctx, adapter=scanner._Adapter())

    # The refusal itself is still recorded — the gate's rule was never lost, only
    # unowned before.
    assert RULE_PROTECTED_NODE in compilation.gate_refusals
    assert compilation.proof.verdict is ProofVerdict.FAIL
    assert compilation.proof.void_reason == ""
    line = compilation.proof.obligation(ObligationName.TARGET_POLICY.value)
    assert line is not None
    assert line.status is ObligationStatus.FAIL
    assert RULE_PROTECTED_NODE in line.detail
    # And now the refusal has somewhere to land: `target_policy` carries it, and
    # no line claims to have no blame at all. This was the mirror assertion of the
    # `VOID` version above — same run, opposite outcome, and the only thing that
    # changed is the five rows in `OBLIGATION_FOR_RULE`.
    assert ObligationName.TARGET_POLICY.value in compilation.blame
    assert any(
        RULE_PROTECTED_NODE in reason
        for reasons in compilation.blame.values()
        for reason in reasons
    ), compilation.blame


# =========================================================================== #
# 6. The layering contract, restated for the sealing half
# =========================================================================== #


def test_the_service_reaches_no_io_of_its_own_for_the_prediction_half():
    """The simulate path's purity claim still holds after Phase 4.

    ``test_prediction_service.py`` asserts this over the whole module, which is
    the right scope — but the sealing half is the half that *does* take a store,
    so it is worth being explicit that the store arrives as an argument and the
    module opens nothing itself.
    """
    import ast
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "mayhem"
        / "controller"
        / "prediction_service.py"
    )
    tree = ast.parse(source.read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module)
    assert not {
        name
        for name in imported
        if name in {"os", "pathlib", "sqlite3", "subprocess", "socket", "shutil"}
    }, sorted(imported)
    assert not {name for name in imported if name.startswith("mayhem.cli")}


def test_the_sealed_event_payload_is_json_serialisable_and_canonical(tmp_path):
    """The chain stores JSON, so the payload must survive a round trip unchanged.

    The digest is taken over the prediction body via ``domain.hashing.digest``, so
    the body has to be canonical — two seals of one prediction must produce the
    same digest, or "did the approver sign this prediction" stops being a
    checkable question.
    """
    store = _store(tmp_path)
    prediction = _prediction()
    first = _seal(store, prediction)
    second = seal_prediction(
        store, prediction, run_id=RUN_ID, recorded_at=_reading(), evidence_ref="preflight:a1"
    )
    assert first.prediction_digest == second.prediction_digest
    # …and the payload is plain JSON, so a verifier years later needs no import of
    # this module to read it.
    json.dumps(first.events[0].payload)
    assert first.events[0].event_kind == EVENT_PREDICTION_SEALED
    assert first.events[0].run_id == first.scope


def test_a_sealed_prediction_is_not_an_approval_and_does_not_pretend_to_be(tmp_path):
    """The seal says the forecast existed; it never says the run was allowed."""
    store = _store(tmp_path)
    sealed = _seal(store, _prediction())
    for forbidden in ("verdict", "approved", "allowed", "signature"):
        assert forbidden not in json.dumps(sealed.events[0].payload)
    # The digest and citation are there; authority is not.
    assert "prediction_digest" in sealed.events[0].payload
    assert "evidence_ref" in sealed.events[0].payload
    assert isinstance(sealed, SealedPrediction)
    assert sealed.manifest_digest
    assert sealed.chain_root != GENESIS_DIGEST
