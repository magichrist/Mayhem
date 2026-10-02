"""Plan 21 Phase 4 — the advisor's safety and evidence integration.

The load-bearing claim in this file is negative and it is asserted more than
once, because "the advisor cannot acquire authority" is the one property of this
plan that must not regress quietly:

* a sealed advisory artifact is **not** an approval and **not** an authorization —
  enforced by what the types can carry, by the existing
  :func:`~mayhem.domain.advisor.is_certified_evidence` predicate, by a
  :attr:`AdvisorySeal.grants_authorization` that is a literal ``False``, and by
  the persisted bytes saying so in data;
* the analysis context still cannot mint execution intent, and Phase 4's additions
  (sealing, audit recording, scenario submission) gave it no store, no sink and
  no intent parameter to do it with;
* a sealed recommendation cannot be replayed as an approval.

The positive half is that sealing *works* — a claim is hashed into plan 12's
chain, verified, persisted, and re-reads byte-identically — and that an
incident-replay compilation is recorded in the audit stream as a privileged
action carrying the incident fact behind every parameter.

Also here, because it is Phase 4's open question: the ``required_approvals`` line
reports ``PASS`` with "No intent presented at compile time", and this file
asserts the *decision* rather than the ambiguity. The answer is that the ``PASS``
is honest, that :attr:`AdvisorSubmission.authorized` is ``False`` for it anyway,
and that the state is derived from which gate produced the line rather than from
its prose — so no reader has to interpret a status string.
"""

from __future__ import annotations

import inspect
from dataclasses import fields as dataclass_fields
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

import pytest
from pydantic import ValidationError
from tests.unit.test_advisor_service import (
    CONFIG_SNAPSHOT_ID,
    CRITERIA,
    FINGERPRINT,
    RUN_ID,
    SERVICE,
    SNAPSHOT_ID,
    gate_context,
    incident,
    propose,
    replay,
    replay_request,
    service,
    weight,
)

from mayhem.controller import advisor_service, safety, safety_proof
from mayhem.controller.advisor_service import (
    ADVISORY_CHAIN_PREFIX,
    KIND_ADVISORY_CLAIM_SEALED,
    KIND_ADVISORY_REPLAY_COMPILED,
    RULE_ADVISORY_SEAL_CARRIES_APPROVAL,
    RULE_ADVISORY_SEAL_UNTRACEABLE,
    RULE_SUBMISSION_SPEC_NOT_BOUND,
    AdvisorService,
    AdvisorSubmission,
    AdvisoryClaim,
    SubmissionAuthorization,
    advisory_chain_id,
    record_advisory_seal,
    record_replay_compilation,
    seal_advisory_claim,
    submit_scenario,
)
from mayhem.domain.advisor import (
    RULE_GENERATED_CANNOT_BE_APPROVED,
    AdvisorAuthority,
    Approval,
    RecommendationOrigin,
    is_certified_evidence,
)
from mayhem.domain.attestation import verify_chain, verify_manifest
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_intent import (
    INTENT_REQUIRED,
    ExecutionIntentRefused,
    require_execution_intent,
)
from mayhem.domain.safety_proof import ObligationStatus
from mayhem.domain.scenarios import (
    SCENARIO_TEMPLATES,
    RecoveryPlan,
    ScenarioError,
    ScenarioInstantiation,
    ScenarioTemplate,
    TimelineStep,
    scenario_library,
)
from mayhem.infra.attestation_store import AttestationRepository, RunAuthorization
from mayhem.infra.audit_stream import AuditError, AuditStream, verify_audit_chain
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from mayhem.domain.advisor import Recommendation

#: The field names no advisor artifact may carry: an approval, an authorization,
#: a policy decision, or a certified-evidence digest. Named once so every
#: structural assertion below compares against the same list.
FORBIDDEN_ON_ADVISORY_ARTIFACTS = frozenset(
    {
        "approval",
        "approved_by",
        "intent",
        "execution_intent",
        "run_id",
        "policy_decision",
        "approval_state",
        "evidence_digest",
    }
)


# --- fixtures ---------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> Store:
    """A fully migrated store on disk — real tables, triggers, and constraints."""
    built = Store(tmp_path / "advisor-evidence.db")
    built.migrate()
    return built


@pytest.fixture
def engine() -> AdvisorService:
    return service()


@pytest.fixture
def recommendation(engine: AdvisorService) -> Recommendation:
    """The fixture finding, compiled into a generated and unapproved recommendation."""
    report = engine.analyse(propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})
    return ranked[0]


@pytest.fixture
def submission(engine: AdvisorService, recommendation: Recommendation) -> AdvisorSubmission:
    """That recommendation, all the way through compile → proof → policy."""
    return engine.submit(
        recommendation,
        gate_context(),
        fault_id=replay_request().fault_id,
        target=SERVICE,
        duration_s=41.0,
        parameters=replay(engine).parameter_values,
        run_id=RUN_ID,
        config_snapshot_id=CONFIG_SNAPSHOT_ID,
        environment_fingerprint=FINGERPRINT,
    )


def template(template_id: str = "pod-churn") -> ScenarioInstantiation:
    """A shipped multi-fault template, bound to the fixture's coverage cell.

    ``pod-churn`` by default because its three faults all apply to a container,
    which is the only node kind the fixture topology has — so the instantiated
    scenario really does compile through ``plan_drill`` rather than being refused
    for a fault the target cannot take.
    """
    shipped = next(t for t in SCENARIO_TEMPLATES if t.template_id == template_id)
    return shipped.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )


# -- sealing: advisory, and advisory *only* -----------------------------------------


def test_a_sealed_recommendation_stands_only_as_a_claim_about_cited_facts(
    store: Store, recommendation: Recommendation
) -> None:
    """The seal records what the recommendation claims and every fact it cited."""
    seal = seal_advisory_claim(store, AdvisoryClaim.from_recommendation(recommendation))

    assert seal.verified is True
    assert seal.standing == "advisory"
    assert seal.claim.recommendation_digest == recommendation.recommendation_digest
    assert seal.claim.finding_id == recommendation.finding.finding_id
    assert seal.claim.cell_key == recommendation.finding.cell_key
    assert [fact.ref for fact in seal.claim.cited_facts] == [
        fact.ref for fact in recommendation.cited_facts
    ]
    assert seal.claim.priority_total == pytest.approx(recommendation.total)
    assert seal.claim.origin is RecommendationOrigin.GENERATED
    assert seal.manifest.signed is False  # plan 12 Phase 2 mints no signature bytes


def test_every_persisted_chain_member_states_what_the_seal_does_not_grant(
    store: Store, recommendation: Recommendation
) -> None:
    """So an operator reading the JSON is told the standing, not left to infer it."""
    seal = seal_advisory_claim(store, AdvisoryClaim.from_recommendation(recommendation))

    assert len(seal.events) == 2
    for event in seal.events:
        assert event.event_kind.startswith("advisory.")
        assert event.payload["standing"] == "advisory"
        assert event.payload["grants_approval"] is False
        assert event.payload["grants_authorization"] is False
    payload = seal.to_dict()
    assert payload["standing"] == "advisory"
    assert payload["grants_approval"] is False
    assert payload["grants_authorization"] is False


def test_a_seal_is_not_an_approval_and_not_an_authorization(
    store: Store, recommendation: Recommendation
) -> None:
    """The distinction is structural, so it is asserted against the types.

    Four independent mechanisms, and the guarantee would be weaker with any one of
    them removed: a property that is a literal ``False``; a field set with nowhere
    to *store* a decision; the predicate a verifier already asks
    (:func:`is_certified_evidence`), which is ``False`` because neither type
    carries an ``evidence_digest``; and the persisted bytes, which say so in data.
    """
    claim = AdvisoryClaim.from_recommendation(recommendation)
    seal = seal_advisory_claim(store, claim)

    assert seal.grants_authorization is False
    assert claim.standing == "advisory" and seal.standing == "advisory"
    for artifact in (claim, seal):
        assert is_certified_evidence(artifact) is False
        stored = {f.name for f in dataclass_fields(type(artifact))}
        assert stored.isdisjoint(FORBIDDEN_ON_ADVISORY_ARTIFACTS), stored
        for name in FORBIDDEN_ON_ADVISORY_ARTIFACTS:
            assert not hasattr(artifact, name), (type(artifact).__name__, name)


def test_a_seal_cannot_be_dressed_up_as_a_run_authorization(
    store: Store, recommendation: Recommendation
) -> None:
    """``RunAuthorization`` is how plan 12 says "why was this allowed?" — and it
    is built from a policy decision and an approval state. An advisory seal has
    neither, so the overclaim is unrepresentable rather than merely discouraged.
    """
    seal = seal_advisory_claim(store, AdvisoryClaim.from_recommendation(recommendation))

    assert {"policy_decision", "approval_state"} <= set(
        inspect.signature(RunAuthorization).parameters
    )
    assert not hasattr(seal, "policy_decision")
    assert not hasattr(seal, "approval_state")
    assert seal.claim.grants_authorization if hasattr(seal.claim, "grants_authorization") else (
        seal.claim.payload()["grants_authorization"]
    ) is False


def test_a_seal_chain_is_namespaced_and_reloads_byte_identically(
    store: Store, recommendation: Recommendation
) -> None:
    """Plan 12's law is one chain per run; an advisory claim is not a run."""
    seal = seal_advisory_claim(store, AdvisoryClaim.from_recommendation(recommendation))

    assert seal.chain_id == f"{ADVISORY_CHAIN_PREFIX}:{seal.claim.recommendation_digest[:16]}"
    assert seal.chain_id == advisory_chain_id(seal.claim.recommendation_digest)
    assert all(event.run_id == seal.chain_id for event in seal.events)
    assert [event.event_kind for event in seal.events] == [
        "advisory.recorded",
        "advisory.sealed",
    ]

    repository = AttestationRepository(store)
    reloaded = repository.load_chain(seal.chain_id)
    assert [e.model_dump() for e in reloaded] == [e.model_dump() for e in seal.events]
    assert verify_chain(reloaded).valid is True
    assert verify_manifest(seal.manifest, reloaded).valid is True
    assert repository.verify_run_chain(seal.chain_id).valid is True
    stored_manifest = repository.load_manifest(seal.manifest_id)
    assert stored_manifest is not None
    assert stored_manifest.manifest_digest == seal.manifest.manifest_digest


def test_a_chain_is_addressed_by_the_claim_it_seals_and_reproducible_for_one_reading(
    store: Store, recommendation: Recommendation
) -> None:
    """Same bytes + same reading ⇒ the same chain root, so a seal is re-derivable.

    The reading is part of the attested bytes (plan 12's rule), so two seals taken
    at different instants are different chains by root and the same chain by id —
    which is why the identity that matters for *lookup* is the recommendation
    digest, and the identity that matters for *integrity* is the root.
    """
    from mayhem.domain.attestation import AttestedTimestamp

    claim = AdvisoryClaim.from_recommendation(recommendation)
    reading = AttestedTimestamp(
        wall_clock=datetime(2026, 3, 4, 12, 30, tzinfo=UTC), monotonic_ns=7_000_000
    )
    first = seal_advisory_claim(store, claim, recorded_at=reading)
    again = seal_advisory_claim(store, claim, recorded_at=reading)
    later = seal_advisory_claim(store, claim)

    assert again.chain_id == first.chain_id
    assert again.chain_root == first.chain_root
    assert later.chain_id == first.chain_id
    assert later.chain_root != first.chain_root  # a different reading is a different record

    reweighed = replace(claim, priority_total=claim.priority_total + 0.01)
    assert reweighed.recommendation_digest == claim.recommendation_digest
    assert reweighed.payload() != claim.payload()


def test_a_recommendation_that_already_carries_an_approval_cannot_be_sealed(
    recommendation: Recommendation,
) -> None:
    """An approval is its own record; sealing it again re-attests a decision."""
    authored = replace(recommendation, origin=RecommendationOrigin.AUTHORED)
    approved = replace(
        authored,
        approval=Approval(
            approved_by="sre-oncall", recommendation_digest=authored.recommendation_digest
        ),
    )
    assert approved.authority is AdvisorAuthority.APPROVED

    with pytest.raises(InvariantViolationError) as caught:
        AdvisoryClaim.from_recommendation(approved)

    assert caught.value.rule == RULE_ADVISORY_SEAL_CARRIES_APPROVAL
    assert "already carries an approval" in str(caught.value)
    assert "the advisor did not make" in str(caught.value)


def test_a_recommendation_without_traceable_facts_cannot_be_sealed(
    recommendation: Recommendation,
) -> None:
    """The chain is read later and cold; it cannot accept an unchecked claim."""
    untraceable = replace(recommendation, rationale="checkout cache loss is worth fixing")

    with pytest.raises(InvariantViolationError) as caught:
        AdvisoryClaim.from_recommendation(untraceable)

    assert caught.value.rule == RULE_ADVISORY_SEAL_UNTRACEABLE
    assert "customer_impact" in str(caught.value)
    assert "no analyst in the room" in str(caught.value)


def test_an_advisory_claim_with_no_citations_or_authority_is_not_constructible(
    recommendation: Recommendation,
) -> None:
    """The constructor is the enforcement, so the refusals are unit tests of it."""
    claim = AdvisoryClaim.from_recommendation(recommendation)

    with pytest.raises(InvariantViolationError) as caught:
        replace(claim, cited_facts=())
    assert caught.value.rule == RULE_ADVISORY_SEAL_UNTRACEABLE
    assert "cites no facts" in str(caught.value)

    with pytest.raises(InvariantViolationError) as caught:
        replace(claim, authority=AdvisorAuthority.APPROVED)
    assert caught.value.rule == RULE_ADVISORY_SEAL_CARRIES_APPROVAL

    with pytest.raises(InvariantViolationError) as caught:
        replace(claim, recommendation_digest="not-a-digest")
    assert caught.value.rule == RULE_ADVISORY_SEAL_UNTRACEABLE

    with pytest.raises(InvariantViolationError) as caught:
        replace(claim, priority_total=float("nan"))
    assert caught.value.rule == RULE_ADVISORY_SEAL_UNTRACEABLE


def test_a_sealed_recommendation_cannot_be_replayed_as_an_approval(
    store: Store, recommendation: Recommendation
) -> None:
    """The negative control for "sealing must not grant authority".

    The direct attack: take the seal's own root digest, build an ``Approval``
    naming it, and attach it to the generated recommendation. Refused by the
    domain, because a generated origin cannot carry an approval at all — and note
    the digest mismatch is never even reached, so this is not "the seal was
    mistaken for the recommendation"; it is "an approval cannot be composed onto
    generated output at all".
    """
    seal = seal_advisory_claim(store, AdvisoryClaim.from_recommendation(recommendation))
    forged = Approval(approved_by="attacker", recommendation_digest=seal.chain_root)

    with pytest.raises(InvariantViolationError) as caught:
        replace(recommendation, approval=forged)

    assert caught.value.rule == RULE_GENERATED_CANNOT_BE_APPROVED
    assert "must be reviewed as one" in str(caught.value)
    assert forged.recommendation_digest == seal.chain_root  # the attacker aimed at the seal


# -- the audit stream: an incident turned into an experiment -----------------------


def test_an_incident_replay_compilation_is_recorded_as_a_privileged_action(
    store: Store, engine: AdvisorService
) -> None:
    """The requirement, asserted on the persisted rows rather than on the call."""
    compiled = engine.replay(replay_request(), incident(), engine.landscape())
    stream = AuditStream(store)

    event = record_replay_compilation(stream, compiled, principal="sre-oncall")

    assert event.event_kind == KIND_ADVISORY_REPLAY_COMPILED
    assert event.payload["principal"] == "sre-oncall"
    assert event.payload["target"] == compiled.incident.incident_id
    assert event.payload["decision_digest"] == compiled.replay_digest
    detail = event.payload["detail"]
    assert detail["incident_id"] == compiled.incident.incident_id
    assert detail["cell_key"] == compiled.cell.key
    assert detail["topology_snapshot_id"] == SNAPSHOT_ID
    assert detail["graph_identity"] == compiled.graph_identity
    traced = {p["parameter"]: p["source"] for p in detail["parameters"]}
    assert traced == {
        "seconds": "incident.duration_s",
        "jitter_ms": 'incident.percentile("p99")',
    }
    assert stream.entry_count() == 1
    assert verify_audit_chain(stream.load()).valid is True


def test_an_advisory_replay_entry_carries_no_approval_or_policy_digest(
    store: Store, engine: AdvisorService
) -> None:
    """Nothing the advisor records may name a decision it did not receive."""
    compiled = engine.replay(replay_request(), incident(), engine.landscape())
    stream = AuditStream(store)
    record_replay_compilation(stream, compiled, principal="sre-oncall")

    entry = stream.load()[0]
    assert entry.payload["approval_digest"] == ""
    assert entry.payload["policy_digest"] == ""
    assert entry.payload["detail"]["standing"] == "advisory"
    # it is filed against the stream, not against a run it does not have
    assert stream.entries_for_run(RUN_ID) == ()


def test_an_advisory_seal_is_recorded_beside_the_replay(
    store: Store, engine: AdvisorService, recommendation: Recommendation
) -> None:
    """Both privileged actions land in one append-only stream, in order."""
    compiled = engine.replay(replay_request(), incident(), engine.landscape())
    seal = seal_advisory_claim(store, AdvisoryClaim.from_recommendation(recommendation))

    stream = AuditStream(store)
    record_replay_compilation(stream, compiled, principal="sre-oncall")
    record_advisory_seal(stream, seal, principal="sre-oncall")

    assert [entry.event_kind for entry in stream.load()] == [
        KIND_ADVISORY_REPLAY_COMPILED,
        KIND_ADVISORY_CLAIM_SEALED,
    ]
    sealed = stream.load()[1]
    assert sealed.payload["target"] == recommendation.recommendation_id
    assert sealed.payload["decision_digest"] == seal.chain_root
    assert sealed.payload["approval_digest"] == ""
    assert sealed.payload["detail"]["grants_authorization"] is False
    assert verify_audit_chain(stream.load()).valid is True


def test_an_advisor_audit_entry_needs_a_named_principal(
    store: Store, engine: AdvisorService
) -> None:
    compiled = engine.replay(replay_request(), incident(), engine.landscape())
    with pytest.raises(AuditError, match="principal"):
        record_replay_compilation(AuditStream(store), compiled, principal="  ")


# -- the open question, decided: required_approvals -------------------------------


def test_required_approvals_passes_and_authorizes_nothing(
    submission: AdvisorSubmission, recommendation: Recommendation
) -> None:
    """Phase 4's decision, stated as a test rather than left as an open question.

    The line is ``PASS`` with "No intent presented at compile time" and that is
    correct: the line's subject is the *requirements* and the rule that any
    approval must bind this plan digest. So ``submit`` does not refuse it, and the
    submission reports :data:`SubmissionAuthorization.REQUIREMENTS_ONLY` with
    ``authorized is False`` — a reader must not have to interpret a status string
    to learn that nothing was granted.
    """
    line = submission.compilation.proof.obligation("required_approvals")

    assert line is not None
    assert line.status is ObligationStatus.PASS
    assert "no intent presented at compile time" in line.detail.lower()
    assert submission.authorization is SubmissionAuthorization.REQUIREMENTS_ONLY
    assert submission.authorized is False
    assert recommendation.authority is AdvisorAuthority.NONE
    assert "authorization: requirements_only (nothing granted)" in submission.describe()
    assert submission.to_dict()["authorized"] is False


def test_the_authorization_state_is_read_from_whether_a_gate_was_configured(
    submission: AdvisorSubmission,
) -> None:
    """Structural derivation, asserted against the two facts it actually reads.

    ``ctx.approval_gate is None`` and the line's status — nothing else. In
    particular not the line's ``detail``, which is prose another module composes
    and which a verdict parsed out of would break the first time somebody
    improves the sentence.
    """
    from mayhem.controller.safety import SafetyContext

    compilation = submission.compilation
    ungated = SafetyContext(
        policy=gate_context().policy,
        budget=gate_context().budget,
        fingerprint=FINGERPRINT,
        policy_gate=gate_context().policy_gate,
    )
    gated = replace(ungated, approval_gate=cast("Any", object()))

    assert advisor_service._authorization_state(ungated, compilation) is (
        SubmissionAuthorization.REQUIREMENTS_ONLY
    )
    assert advisor_service._authorization_state(gated, compilation) is (
        SubmissionAuthorization.GATE_AUTHORIZED
    )
    # flipping the line's status is the only other thing that can move it
    line = compilation.proof.obligation("required_approvals")
    assert line is not None
    failing = replace(
        compilation,
        proof=compilation.proof.model_copy(
            update={
                "obligations": tuple(
                    line.model_copy(update={"status": ObligationStatus.FAIL})
                    if o.name == "required_approvals"
                    else o
                    for o in compilation.proof.obligations
                )
            }
        ),
    )
    refusing = advisor_service._authorization_state(gated, failing)
    assert refusing is SubmissionAuthorization.GATE_REFUSED
    # and a context with no gate stays requirements-only even on a FAIL, because
    # nothing could have been authorised by a gate that does not exist
    assert advisor_service._authorization_state(ungated, failing) is (
        SubmissionAuthorization.REQUIREMENTS_ONLY
    )


def test_a_gate_refusal_is_reported_as_a_refusal_and_never_as_authorized(
    submission: AdvisorSubmission,
) -> None:
    """The one state that must not read as a pass, and it is a gate's own verdict."""
    line = submission.compilation.proof.obligation("required_approvals")
    assert line is not None
    refused = replace(
        submission.compilation,
        proof=submission.compilation.proof.model_copy(
            update={
                "obligations": tuple(
                    line.model_copy(update={"status": ObligationStatus.FAIL})
                    if o.name == "required_approvals"
                    else o
                    for o in submission.compilation.proof.obligations
                )
            }
        ),
    )
    gated = replace(gate_context(), approval_gate=cast("Any", object()))

    state = advisor_service._authorization_state(gated, refused)
    assert state is SubmissionAuthorization.GATE_REFUSED
    assert replace(submission, authorization=state).authorized is False


def test_a_submission_seal_records_the_authorization_state_as_data(
    submission: AdvisorSubmission,
) -> None:
    """The state travels into the seal so a cold reader need not reconstruct it."""
    claim = AdvisoryClaim.from_submission(submission)
    payload = claim.payload()

    assert claim.plan_digest == submission.plan_digest
    assert claim.proof_verdict == submission.proof_verdict
    assert claim.policy_allowed == submission.policy_allowed
    assert payload["authorization"] == "requirements_only"
    assert payload["grants_authorization"] is False


# -- the scenario library, through the ordinary path -------------------------------


def test_a_scenario_is_a_claim_and_not_a_fault_list() -> None:
    """Enforced by the constructor: the four parts are required, not optional."""
    step = TimelineStep(
        at_s=0.0, fault_id="dns.servfail", duration_s=60.0, expects="names stop resolving"
    )
    base: dict[str, Any] = {
        "template_id": "x",
        "version": "1.0.0",
        "title": "X",
        "hypothesis": "h",
        "timeline": (step,),
        "stop_conditions": ("abort if resolution failure exceeds 50%",),
    }
    recovery = RecoveryPlan(
        expects="resolution succeeds again",
        compensation="restore the resolver",
        verified_by="a probe answers",
    )

    complete = ScenarioTemplate(**base, recovery=recovery)
    assert complete.ref == "x@1.0.0"
    assert complete.duration_s == 60.0
    assert complete.fault_ids == ("dns.servfail",)
    assert complete.probes() == ("dns.servfail@0s (expect: names stop resolving)",)

    # A fault list is not expressible: drop any one of the four parts.
    for dropped, message in (
        ("recovery", "recovery"),
        ("timeline", "fault list"),
        ("stop_conditions", "stop"),
    ):
        payload: dict[str, Any] = {**base, "recovery": recovery, dropped: ()}
        with pytest.raises(ValidationError, match=message):
            ScenarioTemplate(**payload)
    # And the fourth part cannot be left out at all: it is required, so a template
    # with no recovery does not reach any rule before it is refused.
    with pytest.raises(ValidationError, match="recovery"):
        ScenarioTemplate(**base)


def test_a_timeline_step_with_no_expectation_is_refused() -> None:
    """The one field that stops a step being a wish rather than a claim."""
    with pytest.raises(ValidationError, match="fault list"):
        TimelineStep(at_s=0.0, fault_id="dns.servfail", duration_s=60.0, expects="  ")


def test_a_timeline_that_runs_backwards_is_refused() -> None:
    recovery = RecoveryPlan(expects="back", compensation="undo", verified_by="a probe answers")
    with pytest.raises(ValidationError, match="backwards"):
        ScenarioTemplate(
            template_id="x",
            version="1.0.0",
            title="X",
            hypothesis="h",
            timeline=(
                TimelineStep(at_s=10.0, fault_id="dns.servfail", duration_s=5.0, expects="late"),
                TimelineStep(at_s=0.0, fault_id="dns.timeout", duration_s=5.0, expects="early"),
            ),
            stop_conditions=("abort if p99 > 2s",),
            recovery=recovery,
        )


def test_an_instantiation_must_be_bound_to_a_declared_cell() -> None:
    """No implied target dimension: a scenario in an unlookupable cell is refused."""
    shipped = SCENARIO_TEMPLATES[0]
    for blank in ("", "  "):
        with pytest.raises(ScenarioError, match="instantiated without"):
            shipped.instantiate(target=blank, execution_context="container", parameter_band="d")
    instantiated = shipped.instantiate(
        target=SERVICE, execution_context="container", parameter_band="default"
    )
    assert instantiated.cell.key == f"{SERVICE}\x1f{shipped.fault_ids[0]}\x1fcontainer\x1fdefault"
    assert instantiated.duration_s == shipped.duration_s


def test_a_library_is_versioned_and_refuses_a_duplicate_version() -> None:
    library = scenario_library()

    assert library.get("cache-outage", "1.0.0") is not None
    assert library.get("cache-outage", "9.9.9") is None
    assert library.get("not-a-scenario", "1.0.0") is None
    latest = library.latest("cache-outage")
    assert latest is not None
    assert latest.ref == "cache-outage@1.0.0"
    assert library.latest("not-a-scenario") is None
    assert "cache-outage" in library.ids()
    assert len(library.refs()) == len(SCENARIO_TEMPLATES)

    with pytest.raises(ValidationError, match="twice"):
        type(library)(name=library.name, templates=(library.templates[0], *library.templates))


def test_a_version_the_library_cannot_sort_is_refused() -> None:
    """``latest`` sorts lexically, so an unsortable version scheme is refused here."""
    with pytest.raises(ValidationError, match=r"N\.N\.N"):
        ScenarioTemplate(
            template_id="x",
            version="1.10",
            title="X",
            hypothesis="h",
            timeline=(
                TimelineStep(at_s=0.0, fault_id="dns.servfail", duration_s=5.0, expects="nx"),
            ),
            stop_conditions=("abort if p99 > 2s",),
            recovery=RecoveryPlan(
                expects="back", compensation="undo", verified_by="probe 200"
            ),
        )


def test_every_shipped_template_names_faults_the_catalog_defines() -> None:
    """A library entry that will not compile is a broken library, not a curiosity."""
    from mayhem.domain.catalog import definition_for

    for shipped in SCENARIO_TEMPLATES:
        for fault_id in shipped.fault_ids:
            assert definition_for(fault_id).id == fault_id
        assert shipped.stop_conditions
        assert shipped.recovery.verified_by


def test_a_scenario_is_proposed_through_the_ordinary_door(engine: AdvisorService) -> None:
    """An instantiation is a proposal function — the injection point already there."""
    instantiation = template()
    report = engine.analyse(instantiation.propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})

    assert instantiation.ref == "pod-churn@1.0.0"
    assert ranked[0].candidate.experiment_id.startswith("exp:scenario:pod-churn@1.0.0")
    assert ranked[0].candidate.hypothesis == instantiation.hypothesis
    assert instantiation.hypothesis in ranked[0].render()
    assert ranked[0].origin is RecommendationOrigin.GENERATED
    assert ranked[0].authority is AdvisorAuthority.NONE


def test_a_scenario_submission_is_indistinguishable_downstream_from_an_authored_one(
    engine: AdvisorService, submission: AdvisorSubmission, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same stages, same functions, same artifact shape — asserted by stage and field."""
    stages: list[str] = []
    original_proof = safety_proof.compile_safety_evidence
    original_policy = safety.simulate_plan_policy

    def traced(name: str, real: Callable[..., object]) -> Callable[..., object]:
        def _spy(*args: object, **kwargs: object) -> object:
            stages.append(name)
            return real(*args, **kwargs)

        return _spy

    monkeypatch.setattr(
        "mayhem.controller.advisor_service.compile_safety_evidence",
        traced("proof", original_proof),
    )
    monkeypatch.setattr(
        "mayhem.controller.advisor_service.simulate_plan_policy",
        traced("policy", original_policy),
    )

    instantiation = template()
    report = engine.analyse(instantiation.propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})
    scenario = submit_scenario(
        engine,
        instantiation,
        ranked[0],
        gate_context(),
        run_id=RUN_ID,
        config_snapshot_id=CONFIG_SNAPSHOT_ID,
        environment_fingerprint=FINGERPRINT,
    )

    assert stages == ["proof", "policy"]
    assert scenario.to_dict().keys() == submission.to_dict().keys()
    assert scenario.proof_verdict == submission.proof_verdict
    assert scenario.policy_allowed == submission.policy_allowed
    assert scenario.authorized is False
    assert scenario.authorization is SubmissionAuthorization.REQUIREMENTS_ONLY
    assert [s.fault.fault_id for s in scenario.plan.steps if s.fault] == list(
        instantiation.fault_ids
    )
    assert scenario.plan.topology_snapshot_id == SNAPSHOT_ID


def test_a_scenario_cannot_supply_a_plan_that_says_something_else(
    engine: AdvisorService, recommendation: Recommendation
) -> None:
    """The binding check is what keeps the spec path from being a side channel."""
    with pytest.raises(InvariantViolationError) as caught:
        submit_scenario(
            engine,
            template(),
            recommendation,
            gate_context(),
            run_id=RUN_ID,
            config_snapshot_id=CONFIG_SNAPSHOT_ID,
            environment_fingerprint=FINGERPRINT,
        )

    assert caught.value.rule == RULE_SUBMISSION_SPEC_NOT_BOUND
    assert "different experiment in front of a reviewer" in str(caught.value)


def test_a_shipped_template_compiles_through_the_planner_for_a_container(
    engine: AdvisorService,
) -> None:
    """The library is only useful if its entries are plans the planner accepts.

    Caught the hard way while writing this suite: an early ``pod-churn`` timeline
    used ``process.startup_delay``, which the catalog refuses outright
    ("startup gating requires an application-aware readiness hook"). A library
    that will not compile is a document, not a library, so the shipped data is
    held to the same planner every authored plan goes through.
    """
    instantiation = template()
    report = engine.analyse(instantiation.propose, CRITERIA, weight)
    ranked = report.rank(CRITERIA, {f.finding_id: dict(weight(f)) for f in report.findings})

    submission = submit_scenario(
        engine,
        instantiation,
        ranked[0],
        gate_context(),
        run_id=RUN_ID,
        config_snapshot_id=CONFIG_SNAPSHOT_ID,
        environment_fingerprint=FINGERPRINT,
    )

    assert submission.plan.steps
    assert [s.fault.fault_id for s in submission.plan.steps if s.fault] == [
        "container.kill",
        "container.restart",
        "process.crash_loop",
    ]


def test_a_scenario_instantiation_carries_no_authority_vocabulary() -> None:
    """The library hands the engine a claim; it has no door of its own."""
    instantiation = template()

    assert is_certified_evidence(instantiation) is False
    assert set(ScenarioInstantiation.model_fields).isdisjoint(
        FORBIDDEN_ON_ADVISORY_ARTIFACTS | {"authority", "compile", "execute"}
    )
    for name in FORBIDDEN_ON_ADVISORY_ARTIFACTS:
        assert not hasattr(instantiation, name), name


# -- the invariant: the advisor context still cannot acquire authority --------------


def test_phase_4_gave_the_analysis_context_no_way_to_write() -> None:
    """The field set is unchanged from Phase 2 — that is the whole boundary."""
    assert {f.name for f in dataclass_fields(AdvisorService)} == {
        "topology",
        "coverage",
        "incidents",
        "deployments",
        "evidence",
        "sink",
    }
    for name in ("seal", "seal_advisory_claim", "record", "write", "store", "persist"):
        assert not hasattr(AdvisorService, name), name


def test_the_advisor_context_still_cannot_mint_execution_intent(
    submission: AdvisorSubmission,
) -> None:
    """The real gate, on a real plan digest, with a real recommendation in hand."""
    with pytest.raises(ExecutionIntentRefused) as caught:
        require_execution_intent(
            None, plan_hash=submission.plan_digest, engine="docker", target_identity=SERVICE
        )
    assert caught.value.code == INTENT_REQUIRED

    # and nothing Phase 4 added is a place an intent could be smuggled through
    assert "intent" not in inspect.signature(AdvisorService.submit).parameters
    assert "intent" not in inspect.signature(submit_scenario).parameters
    assert "intent" not in inspect.signature(seal_advisory_claim).parameters
    assert "intent" not in inspect.signature(record_replay_compilation).parameters
    assert "intent" not in inspect.signature(record_advisory_seal).parameters
    assert "intent" not in {f.name for f in dataclass_fields(AdvisoryClaim)}


def test_the_advisor_never_supplies_an_intent_to_the_proof_compiler(
    engine: AdvisorService, recommendation: Recommendation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The strongest form of the invariant, asserted on the call that could break it.

    ``compile_safety_evidence`` accepts an ``intent`` and will happily verify one
    against the plan digest. The advisor has no intent to pass, so the argument is
    checked at the boundary rather than inferred from the absence of a field.
    """
    seen: list[dict[str, object]] = []
    real: Callable[..., object] = safety_proof.compile_safety_evidence

    def spy(*args: object, **kwargs: object) -> object:
        seen.append(dict(kwargs))
        return real(*args, **kwargs)

    monkeypatch.setattr("mayhem.controller.advisor_service.compile_safety_evidence", spy)
    engine.submit(
        recommendation,
        gate_context(),
        fault_id=replay_request().fault_id,
        target=SERVICE,
        duration_s=41.0,
        parameters=replay(engine).parameter_values,
        run_id=RUN_ID,
        config_snapshot_id=CONFIG_SNAPSHOT_ID,
        environment_fingerprint=FINGERPRINT,
    )

    assert len(seen) == 1
    assert "intent" not in seen[0]
    assert set(seen[0]) == {"adapter"}


def test_a_recommendation_only_seal_carries_no_plan_no_proof_and_no_authority(
    store: Store, recommendation: Recommendation
) -> None:
    """Sealing a recommendation alone asserts the claim, and nothing it did not do."""
    seal = seal_advisory_claim(store, AdvisoryClaim.from_recommendation(recommendation))
    payload = seal.claim.payload()

    assert payload["plan_digest"] == ""
    assert payload["proof_verdict"] == ""
    assert payload["policy_allowed"] is None
    assert payload["authorization"] == "requirements_only"
    assert seal.grants_authorization is False


def test_the_purity_measurement_still_holds_after_phase_4(
    engine: AdvisorService, recommendation: Recommendation
) -> None:
    """The mutation sink is pre-loaded, so a reported count is a measurement."""
    from mayhem.controller.policy_gate import MutationSink

    loaded = MutationSink().record("lease", "acquire run lease")
    measured = replace(engine, sink=loaded)
    report = measured.analyse(propose, CRITERIA, weight)
    measured.replay(replay_request(), incident(), measured.landscape())
    measured.submit(
        recommendation,
        gate_context(),
        fault_id=replay_request().fault_id,
        target=SERVICE,
        duration_s=41.0,
        parameters=replay(measured).parameter_values,
        run_id=RUN_ID,
        config_snapshot_id=CONFIG_SNAPSHOT_ID,
        environment_fingerprint=FINGERPRINT,
    )

    assert report.purity.calls == 1
    assert len(loaded) == 1
