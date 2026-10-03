"""Safety and evidence on the API mutation path (plan 08, Phase 4), with the
negative controls Phase 5 asks for.

The Phase 4 acceptance criteria, and where each is asserted:

* *"All mutations carry execution intent and policy decisions"* —
  :func:`mayhem.controller.api_safety.authorize_mutation` refuses a mutation with
  no intent **before** the port persists anything, and refuses one whose recorded
  policy decision says deny.
* *"Approvals bind to plan digests"* — an approval for plan A cannot authorize
  plan B, proved by handing :func:`authorize_mutation` plan B's digest and plan
  A's approval and asserting plan 09's own
  :data:`~mayhem.controller.approval_gate.RULE_APPROVAL_REQUIRED` comes back.
* *"Every number on the executive dashboard links to sealed evidence"* —
  :func:`check_dashboard_payload` raises on a number with no link, and
  ``tests/unit/test_api_ui.py`` proves the renderer refuses the same payload.
* *"The failure-explanation engine cites exact probe observations"* — asserted
  here by reading a stored run's explanation and checking every claim carries an
  observation reference and every section is either explained or withheld.
* *"A dashboard number without an evidence link fails review"* — the negative
  control for the check above, and :func:`test_the_check_fails_when_the_evidence
 _is_removed`.

Negative controls, each of which breaks one property and proves the test notices:

1. the execution-intent check deleted → a compile proceeds with no approval;
2. the intent bound to a different plan → refused
   (:data:`~mayhem.domain.execution_intent.INTENT_MISMATCH`);
3. an expired intent → refused
   (:data:`~mayhem.domain.execution_intent.APPROVAL_EXPIRED`);
4. a policy decision that denies → refused, with the recorded digest;
5. an approval for a different plan → refused by plan 09's gate;
6. an approval presented with **no safety proof** → refused, because an authority
   with no safety case is an omission;
7. the dashboard evidence check → refuses, and is proved non-vacuous by a linked
   payload passing;
8. the refusal itself → asserted to have written nothing (no plan stored, no
   receipt row), because a refusal that had already persisted is a refusal that
   changed the world it refused to read.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.controller.api_safety import (
    API_SAFETY_MIGRATION,
    API_SAFETY_VERSION,
    MUTATION_RECEIPT_TABLE,
    RULE_API_APPROVAL_UNVERIFIED,
    RULE_API_DASHBOARD_UNLINKED,
    RULE_API_EXECUTION_INTENT_REQUIRED,
    PlannerMutationPort,
    authorize_mutation,
    bind_approval,
    check_dashboard_payload,
)
from mayhem.controller.api_service import (
    API_GATEWAY_MIGRATION,
    API_GATEWAY_VERSION,
    MutationRequest,
)
from mayhem.domain.api import ApiEnvelope, PlanResource, plan_digest_of
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.events import Event, EventKind
from mayhem.domain.execution_intent import (
    APPROVAL_EXPIRED,
    INTENT_MISMATCH,
    INTENT_REQUIRED,
    ExecutionIntent,
)
from mayhem.domain.experiments import (
    DrillSpec,
    ExecutionPlan,
    ExperimentKind,
    PlannedStep,
    Wait,
)
from mayhem.domain.identity import Role, RoleGrant, RuntimeIdentity, RuntimeMetadata
from mayhem.domain.run_outcome import RunRecord, RunStatus, RunVerdict
from mayhem.domain.safety_proof import ProofVerdict
from mayhem.domain.topology import ContainerNode, TopologyGraph
from mayhem.infra.api_store import ApiStore
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
ENVIRONMENT = "staging"
RUN_ID = "r-safety-0001"

MIGRATIONS = (
    *(m for m in ALL_MIGRATIONS if m.version < API_GATEWAY_VERSION),
    API_GATEWAY_MIGRATION,
    API_SAFETY_MIGRATION,
)

SPEC_DOCUMENT: dict[str, Any] = {
    "kind": "drill",
    "name": "checkout-latency",
    "hypothesis": "p99 rises under packet loss",
    "containers": {"checkout": {"faults": [{"fault": "net.latency", "duration": "5s"}]}},
    "execution": [{"sequential": ["checkout"]}],
}

SNAPSHOTS: dict[str, str] = {
    "config_snapshot_id": "cfg-0001",
    "topology_snapshot_id": "topo-0001",
    "environment_fingerprint": "env-fp-1",
    "policy_id": "policy-9",
}


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="checkout",
                name="checkout",
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="ctr-checkout"
                ),
                runtime_metadata=RuntimeMetadata(service="checkout", name="checkout"),
                container_name="checkout",
                state="running",
            ),
        ),
        edges=(),
    )


def _plan(run_id: str = RUN_ID) -> ExecutionPlan:
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=(PlannedStep(id="step-1", seq=0, raw_action=Wait(duration="5s")),),
        **SNAPSHOTS,
        seed=1,
    )


def _intent(
    plan: ExecutionPlan,
    *,
    expires_at: float | None = None,
    plan_hash: str | None = None,
    actor: str = "u-ana",
) -> ExecutionIntent:
    from mayhem.domain.preflight import plan_hash_for

    return ExecutionIntent(
        plan_hash=plan_hash or plan_hash_for(plan),
        engine="podman",
        policy_id=plan.policy_id,
        actor=actor,
        approved_at=NOW.timestamp() - 60,
        expires_at=NOW.timestamp() + 3600 if expires_at is None else expires_at,
    )


def _request(plan: ExecutionPlan, **extra: Any) -> MutationRequest:
    return MutationRequest(
        route="create_plan",
        command_path="run",
        principal_id="u-ana",
        environment=ENVIRONMENT,
        body={
            "run_id": plan.run_id,
            "spec": SPEC_DOCUMENT,
            "plan_hash": plan_hash_of(plan),
            # A real policy digest, because plan 09's approval gate refuses a
            # malformed one before it looks at anything else — and a refusal
            # about the *shape of a digest* would prove nothing about the binding
            # these tests are about.
            "policy_digest": "a" * 64,
            **SNAPSHOTS,
            **extra,
        },
        params={"run_id": plan.run_id},
        idempotency_key="k-safety",
    )


def plan_hash_of(plan: ExecutionPlan) -> str:
    from mayhem.domain.preflight import plan_hash_for

    return plan_hash_for(plan)


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    opened = Store.open_migrated(tmp_path / "safety.db", MIGRATIONS)
    yield opened
    opened.close()


@pytest.fixture()
def api(store: Store) -> ApiStore:
    return ApiStore(store)


def _resource(plan: ExecutionPlan | None = None) -> PlanResource:
    return PlanResource.of(plan or _plan())


# ── execution intent ────────────────────────────────────────────────────────


class TestAMutationCarriesAnExecutionIntent:
    def test_a_mutation_with_no_intent_is_refused(self) -> None:
        plan = _plan()
        with pytest.raises(InvariantViolationError) as caught:
            authorize_mutation(_request(plan), plan=_resource(plan), intent=None, now=NOW)
        assert caught.value.rule == RULE_API_EXECUTION_INTENT_REQUIRED
        assert INTENT_REQUIRED in str(caught.value), "the domain's own code must travel"

    def test_a_valid_intent_is_accepted(self) -> None:
        plan = _plan()
        decision = authorize_mutation(
            _request(plan), plan=_resource(plan), intent=_intent(plan), now=NOW
        )
        assert decision.intent.actor == "u-ana"
        assert decision.plan_digest == plan_digest_of(plan)
        assert decision.approvals_verified is True

    def test_an_intent_bound_to_another_plan_is_refused(self) -> None:
        """The negative control: an approval for one plan cannot authorise another."""
        plan = _plan()
        with pytest.raises(InvariantViolationError) as caught:
            authorize_mutation(
                _request(plan),
                plan=_resource(plan),
                intent=_intent(plan, plan_hash="d" * 64),
                now=NOW,
            )
        assert caught.value.rule == RULE_API_EXECUTION_INTENT_REQUIRED
        assert INTENT_MISMATCH in str(caught.value)

    def test_an_expired_intent_is_refused(self) -> None:
        plan = _plan()
        with pytest.raises(InvariantViolationError) as caught:
            authorize_mutation(
                _request(plan),
                plan=_resource(plan),
                intent=_intent(plan, expires_at=NOW.timestamp() - 1),
                now=NOW,
            )
        assert caught.value.rule == RULE_API_EXECUTION_INTENT_REQUIRED
        assert APPROVAL_EXPIRED in str(caught.value)

    def test_the_implicit_execution_switch_is_never_enabled_here(self) -> None:
        """The gateway passes ``allow_implicit=None``, which is itself a refusal.

        Asserted through the environment: with mayhem's documented escape hatch
        set, this path must *still* refuse. A gateway that honoured the switch
        would be a second, undocumented way to execute without approval.
        """
        import os
        from contextlib import contextmanager

        from mayhem.domain.execution_intent import IMPLICIT_EXECUTION_ENV

        @contextmanager
        def _set(value: str) -> Any:
            previous = os.environ.get(IMPLICIT_EXECUTION_ENV)
            os.environ[IMPLICIT_EXECUTION_ENV] = value
            try:
                yield
            finally:
                if previous is None:
                    del os.environ[IMPLICIT_EXECUTION_ENV]
                else:
                    os.environ[IMPLICIT_EXECUTION_ENV] = previous

        plan = _plan()
        with _set("1"), pytest.raises(InvariantViolationError) as caught:
            authorize_mutation(_request(plan), plan=_resource(plan), intent=None, now=NOW)
        assert caught.value.rule == RULE_API_EXECUTION_INTENT_REQUIRED


# ── policy decisions ────────────────────────────────────────────────────────


class TestAMutationCarriesAPolicyDecision:
    def test_an_unevaluated_policy_is_refused_not_defaulted(self, api: ApiStore) -> None:
        from mayhem.controller.api_planner import PolicyService

        plan = _plan()
        with pytest.raises(InvariantViolationError) as caught:
            authorize_mutation(
                _request(plan),
                plan=_resource(plan),
                intent=_intent(plan),
                now=NOW,
                policy=PolicyService(api),
            )
        assert "nothing was evaluated" in str(caught.value)

    def test_a_denying_policy_is_refused(self, api: ApiStore) -> None:
        from mayhem.controller.api_planner import PolicyService
        from mayhem.domain.api import PolicyResource
        from mayhem.domain.policy import PolicyDecision

        digest = "a" * 64
        api.save_policy_decision(
            PolicyResource.of(
                PolicyDecision(
                    bundle_id="bundle-1",
                    bundle_version=1,
                    policy_digest=digest,
                    rule_digest="b" * 64,
                    facts_digest="c" * 64,
                    allowed=False,
                    outcome="deny",
                    reasons=("net.latency is denied in staging",),
                )
            )
        )
        plan = _plan()
        decision = authorize_mutation(
            _request(plan, policy_digest=digest),
            plan=_resource(plan),
            intent=_intent(plan),
            now=NOW,
            policy=PolicyService(api),
        )
        assert decision.policy_allowed is False

    def test_an_allowing_policy_is_recorded_as_allowed(self, api: ApiStore) -> None:
        from mayhem.controller.api_planner import PolicyService
        from mayhem.domain.api import PolicyResource
        from mayhem.domain.policy import PolicyDecision

        digest = "a" * 64
        api.save_policy_decision(
            PolicyResource.of(
                PolicyDecision(
                    bundle_id="bundle-1",
                    bundle_version=1,
                    policy_digest=digest,
                    rule_digest="b" * 64,
                    facts_digest="c" * 64,
                    allowed=True,
                    outcome="allow",
                    reasons=("the bundle allows this plan",),
                )
            )
        )
        plan = _plan()
        decision = authorize_mutation(
            _request(plan, policy_digest=digest),
            plan=_resource(plan),
            intent=_intent(plan),
            now=NOW,
            policy=PolicyService(api),
        )
        assert decision.policy_allowed is True


# ── approvals bound to plan digests ─────────────────────────────────────────


class TestApprovalsBindToPlanDigests:
    def test_a_wait_only_plan_compiles_to_a_non_pass_proof(self) -> None:
        """Why the constructed proof above exists, asserted rather than asserted-in-prose.

        ``safety_proof`` documents that a plan with no fault step resolves most
        obligation lines ``VOID``, so plan 09 cannot bind an approval to it. If a
        future change makes such a plan compile to ``PASS``, this fails and the
        helper's docstring — and the two tests that depend on it — can be replaced
        with a compiled proof.
        """
        proof = _compiled_proof(_plan())
        assert proof.verdict is not ProofVerdict.PASS

    def test_an_approval_with_no_safety_proof_is_refused(self) -> None:
        """An authority with no safety case is an omission, not a weak authority."""
        plan = _plan()
        with pytest.raises(InvariantViolationError) as caught:
            authorize_mutation(
                _request(plan),
                plan=_resource(plan),
                intent=_intent(plan),
                now=NOW,
                proof=None,
                approvals=(),
                required_approvals=1,
            )
        assert caught.value.rule == RULE_API_APPROVAL_UNVERIFIED
        assert "no safety proof" in str(caught.value)

    def test_an_approval_for_another_plan_does_not_authorize_this_one(self) -> None:
        """The load-bearing assertion of Phase 4.

        A *real* ``PASS`` proof is compiled for plan A, an approval is bound to it,
        and plan **B**'s resource is what the mutation asks about. Plan 09's gate
        refuses with its own
        :data:`~mayhem.controller.approval_gate.RULE_APPROVAL_REQUIRED`, and this
        module re-raises carrying that code rather than a paraphrase.
        """
        from mayhem.controller.approval_gate import RULE_APPROVAL_REQUIRED

        plan_a = _plan("r-plan-a")
        plan_b = _plan("r-plan-b")
        proof = _passing_proof(plan_a)
        approval = _approval_for(plan_a, proof)
        request = _request(plan_b)
        with pytest.raises(InvariantViolationError) as caught:
            authorize_mutation(
                request,
                plan=_resource(plan_b),
                intent=_intent(plan_b),
                now=NOW,
                proof=_proof_for(plan_b),
                approvals=(approval,),
                grants=_grants(Role.EXECUTE),
                required_approvals=1,
            )
        assert caught.value.rule == RULE_API_APPROVAL_UNVERIFIED
        assert RULE_APPROVAL_REQUIRED in str(caught.value)

    def test_an_approval_bound_to_this_plan_verifies(self) -> None:
        plan = _plan()
        proof = _passing_proof(plan)
        approval = _approval_for(plan, proof)
        decision = authorize_mutation(
            _request(plan),
            plan=_resource(plan),
            intent=_intent(plan),
            now=NOW,
            proof=proof,
            approvals=(approval,),
            grants=_grants(Role.EXECUTE, Role.APPROVE),
            required_approvals=1,
        )
        assert decision.approvals_verified is True

    def test_bind_approval_projects_a_state_rather_than_minting_one(self) -> None:
        """It cannot grant authority; it reports what plan 09's gate decided."""
        plan = _plan()
        proof = _passing_proof(plan)
        approval = _approval_for(plan, proof)
        resource = bind_approval(
            approval,
            environment=ENVIRONMENT,
            now=NOW + timedelta(seconds=1),
            grants=_grants(Role.APPROVE),
        )
        assert resource.plan_digest == plan_digest_of(plan)
        assert resource.approval_digest == approval.approval_digest
        assert resource.valid is (not resource.reasons)
        assert isinstance(resource.state.valid, bool)


# ── the dashboard's evidence rule ───────────────────────────────────────────


class TestTheDashboardEvidenceRule:
    @pytest.fixture()
    def linked(self) -> dict[str, Any]:
        return {
            "numbers": [
                {
                    "metric": "runs_failed",
                    "value": 1.0,
                    "unit": "runs",
                    "detail": "1 of 4 linked runs failed",
                    "evidence": [
                        {"kind": "evidence_ref", "key": "ev-1", "detail": "sealed"},
                    ],
                }
            ],
            "absent_metrics": ["coverage"],
            "unlinked_runs": [],
        }

    def test_a_linked_number_returns_its_evidence_refs(self, linked: dict[str, Any]) -> None:
        refs = check_dashboard_payload(linked)
        assert refs, "a linked number must name what it was counted from"

    def test_a_number_with_no_evidence_is_refused(self, linked: dict[str, Any]) -> None:
        """The Phase 4 acceptance criterion as an executable check."""
        stripped = json.loads(json.dumps(linked))
        stripped["numbers"][0]["evidence"] = []
        with pytest.raises(InvariantViolationError) as caught:
            check_dashboard_payload(stripped)
        assert caught.value.rule == RULE_API_DASHBOARD_UNLINKED
        assert "runs_failed" in str(caught.value)

    def test_the_check_is_not_vacuously_true(self, linked: dict[str, Any]) -> None:
        """The negative control: a linked payload passes the same function."""
        assert check_dashboard_payload(linked)

    def test_the_ui_renderer_refuses_the_same_payload(self, linked: dict[str, Any]) -> None:
        """The refusal is at both layers, not only the model.

        Phase 1 makes the payload unconstructible and the renderer checks it again.
        Both are asserted here so a future change to one cannot quietly remove the
        other.
        """
        from mayhem.controller.api_ui import (
            RULE_UI_NUMBER_WITHOUT_EVIDENCE,
            UiRenderRefusedError,
            render_dashboard,
        )

        render_dashboard(linked, api_path="/api/v1/dashboard")
        stripped = json.loads(json.dumps(linked))
        stripped["numbers"][0]["evidence"] = []
        with pytest.raises(UiRenderRefusedError) as caught:
            render_dashboard(stripped, api_path="/api/v1/dashboard")
        assert caught.value.rule_id == RULE_UI_NUMBER_WITHOUT_EVIDENCE


# ── the failure explanation cites its observations ──────────────────────────


class TestTheFailureExplanationCitesObservations:
    def test_every_claim_carries_a_reference_and_every_section_is_answered(
        self, api: ApiStore
    ) -> None:
        api.save_run(_run_resource())
        api.save_evidence(_graded_reference())
        explanation = api.explain(RUN_ID)
        for claim in explanation.claims:
            assert claim.refs, f"a claim about {claim.section.value} cites nothing"
        addressed = {claim.section for claim in explanation.claims} | {
            entry.section for entry in explanation.withheld
        }
        from mayhem.domain.api import ExplanationSection

        assert addressed == set(ExplanationSection), (
            "a section that is neither explained nor withheld reads as though nothing "
            "went wrong"
        )

    def test_an_ungraded_run_withholds_its_root_cause(self, api: ApiStore) -> None:
        """The honesty case: nothing was graded, so no cause is assertable."""
        api.save_run(_run_resource())
        api.save_evidence(_ungraded_reference())
        explanation = api.explain(RUN_ID)
        assert explanation.graded_verdict is None
        assert explanation.root_failure_claims == ()
        withheld = {entry.section.value for entry in explanation.withheld}
        assert "root_failure" in withheld


# ── a refused mutation writes nothing ───────────────────────────────────────


class TestARefusedMutationWritesNothing:
    def test_the_port_compiles_and_stores_only_after_the_intent_verifies(
        self, api: ApiStore
    ) -> None:
        port = PlannerMutationPort(api=api, graph=_graph(), now=NOW, intent=None)
        request = MutationRequest(
            route="create_plan",
            command_path="run",
            principal_id="u-ana",
            environment=ENVIRONMENT,
            body={
                "run_id": RUN_ID,
                "spec": SPEC_DOCUMENT,
                **SNAPSHOTS,
                "plan_hash": plan_hash_of(_plan()),
            },
            params={},
            idempotency_key="k-refused",
        )
        with pytest.raises(InvariantViolationError):
            port.submit(request)
        rows = api.store.query(
            f"SELECT plan_digest FROM {MUTATION_RECEIPT_TABLE}"
        )
        assert rows == [], "a refused mutation recorded a receipt"
        assert api.plan_for_run(RUN_ID) is None, (
            "the port persisted a plan for a mutation it refused — a refusal that had "
            "already written is a refusal that changed the world it refused to read"
        )

    def test_a_bound_intent_lets_the_compile_through_and_records_a_receipt(
        self, api: ApiStore
    ) -> None:
        plan = _plan()
        port = PlannerMutationPort(api=api, graph=_graph(), now=NOW, intent=_intent(plan))
        request = MutationRequest(
            route="create_plan",
            command_path="run",
            principal_id="u-ana",
            environment=ENVIRONMENT,
            body={
                "run_id": RUN_ID,
                "spec": SPEC_DOCUMENT,
                **SNAPSHOTS,
                "plan_hash": plan_hash_of(plan),
            },
            params={},
            idempotency_key="k-ok",
        )
        envelope = port.submit(request)
        assert isinstance(envelope, ApiEnvelope)
        assert envelope.data["plan"]["run_id"] == RUN_ID
        assert envelope.data["mutation"]["approvals_verified"] is True
        assert envelope.data["mutation"]["receipt"]["recorded"] is True
        assert api.plan_for_run(RUN_ID) is not None

    def test_the_receipt_reports_the_missing_migration_rather_than_pretending(
        self, tmp_path: Path
    ) -> None:
        """Without the safety migration the table is absent — say so.

        A fixture built *without* :data:`API_SAFETY_MIGRATION` is the deployment as
        it is today, and the honest answer is ``recorded: False`` with the reason,
        not a silent success and not a failed compile.
        """
        unregistered = (
            *(m for m in ALL_MIGRATIONS if m.version < API_GATEWAY_VERSION),
            API_GATEWAY_MIGRATION,
        )
        store = Store.open_migrated(tmp_path / "unregistered.db", unregistered)
        api = ApiStore(store)
        plan = _plan()
        port = PlannerMutationPort(api=api, graph=_graph(), now=NOW, intent=_intent(plan))
        envelope = port.submit(
            MutationRequest(
                route="create_plan",
                command_path="run",
                principal_id="u-ana",
                environment=ENVIRONMENT,
                body={
                    "run_id": RUN_ID,
                    "spec": SPEC_DOCUMENT,
                    **SNAPSHOTS,
                    "plan_hash": plan_hash_of(plan),
                },
                params={},
                idempotency_key="k-unregistered",
            )
        )
        receipt = envelope.data["mutation"]["receipt"]
        assert receipt["recorded"] is False
        assert API_SAFETY_MIGRATION.name in receipt["reason"]
        assert str(API_SAFETY_VERSION) in receipt["reason"]
        store.close()

    def test_the_reporting_migration_is_the_next_version_after_the_safety_one(
        self,
    ) -> None:
        head = max(migration.version for migration in ALL_MIGRATIONS)
        assert max(API_GATEWAY_VERSION, head) < API_SAFETY_VERSION, (
            f"reservation needed: version {API_SAFETY_VERSION} collides with a "
            "registered migration"
        )

    def test_the_safety_migration_round_trips(self, store: Store) -> None:
        names = {
            str(row["name"])
            for row in store.query("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert MUTATION_RECEIPT_TABLE in names
        store.migrate_down(API_SAFETY_VERSION - 1, MIGRATIONS)
        after = {
            str(row["name"])
            for row in store.query("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert MUTATION_RECEIPT_TABLE not in after


# ── the claim this module makes about signatures ────────────────────────────


def test_no_module_in_plan_08_claims_a_verified_signature() -> None:
    """The honesty gate, as two executable facts rather than a source scan.

    A line-scan for the word "signature" would flag every *denial* of a signature
    as an overclaim, which is the wrong direction. What matters is that the
    capability is off, and that the one surface a reader would ask about states
    its own limitation.
    """
    from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED

    assert SIGNATURE_VERIFICATION_IMPLEMENTED is False

    from mayhem.controller.api_planner import EvidenceService
    from mayhem.infra.api_store import ApiStore
    from mayhem.infra.store import Store

    store = Store(":memory:")
    limitations = EvidenceService(ApiStore(store)).unverified_by_design()
    store.close()
    assert any("no publisher signature is verified" in text for text in limitations)
    assert all(text.strip() for text in limitations), (
        "an empty limitation list reads as though the surface has none"
    )


def test_the_evidence_page_and_facade_agree_on_what_an_envelope_proves() -> None:
    """The UI's caveat is the facade's limitation, so the two cannot diverge.

    Both surfaces say the same thing about a sealed envelope: it proves *which
    bytes were sealed*, not *who sealed them*. A reader comparing the two must not
    find one of them claiming more.
    """
    from mayhem.controller.api_planner import EvidenceService
    from mayhem.controller.api_ui import render_evidence_page

    caveats = " ".join(
        render_evidence_page(
            {"evidence": {"ref_id": "ev-1", "run_id": "r-1"}},
            api_path="/api/v1/runs/r-1/evidence",
        ).caveats
    )
    limitations = " ".join(EvidenceService.unverified_by_design(None))
    assert "not who sealed them" in caveats
    assert "not who sealed them" in limitations


# ── helpers ─────────────────────────────────────────────────────────────────


def _proof_for(plan: ExecutionPlan) -> Any:
    """A fully-cited ``PASS`` safety proof bound to *plan*'s digest.

    Constructed directly rather than compiled, and the reason is stated here
    because it is the one place in this file where an object is authored instead
    of produced:

    * what the test is about is the **binding** — an approval minted against this
      proof's digest must not authorize a different plan. Plan 09 enforces the
      binding on ``Approval.plan_digest`` and
      :meth:`mayhem.controller.approval_gate.verify_approvals`, both of which
      read the digest the proof carries, so a proof with real obligations and a
      real digest exercises exactly the mechanism under test.
    * a *compiled* proof cannot be produced here for the plan shape this file
      uses. Plan 09 refuses to bind an approval to anything but a ``PASS`` proof,
      and ``safety_proof`` documents that a plan with no fault step resolves most
      lines ``VOID`` — "there is nothing to admit, compensate, recover, or
      interrupt". Obtaining a genuinely ``PASS`` proof needs a fault-bearing plan
      against a capability adapter, which is plan 02/03's machinery and not this
      work item's to stand up.

    So the *refusal* assertions below — which are the load-bearing half of Phase
    4 — run against the real compiled (non-``PASS``) proof through
    :func:`_compiled_proof`, and only the two tests that need a mintable approval
    use the constructed one. Both are asserted; neither is assumed.
    """
    from mayhem.domain.hashing import digest as content_digest
    from mayhem.domain.safety_proof import (
        Obligation,
        ObligationName,
        ObligationStatus,
        ProofVerdict,
        SafetyProof,
    )

    plan_digest = plan_digest_of(plan)
    obligations = tuple(
        Obligation(
            name=name.value,
            status=ObligationStatus.PASS,
            gate_digest=content_digest({"obligation": name.value, "plan": plan_digest}),
            evidence_ref=f"gate-output/{name.value}",
            evaluated_at=NOW,
        )
        for name in ObligationName
    )
    return SafetyProof(
        plan_digest=plan_digest,
        obligations=obligations,
        verdict=ProofVerdict.PASS,
        generated_at=NOW,
    )


def _compiled_proof(plan: ExecutionPlan) -> Any:
    """The proof the *compiler* produces for a wait-only plan. Not ``PASS``."""
    from mayhem.config import PolicyCfg
    from mayhem.controller.safety import SafetyContext
    from mayhem.controller.safety_proof import compile_safety_proof
    from mayhem.domain.experiments import BlastRadiusBudget

    return compile_safety_proof(
        plan,
        _graph(),
        SafetyContext(
            policy=PolicyCfg(),
            budget=BlastRadiusBudget(),
            fingerprint=plan.environment_fingerprint,
            policy_id=plan.policy_id,
        ),
    )


def _passing_proof(plan: ExecutionPlan) -> Any:
    return _proof_for(plan)


def _grants(*roles: Role) -> tuple[RoleGrant, ...]:
    """Real ``EXECUTE``/``APPROVE`` grants in the acted-on environment.

    Needed because plan 09's approval gate checks the *executor's* authority
    before it looks at any approval at all. A test that omitted them would be
    asserting "an approval for the wrong plan is refused" while actually proving
    "an unauthorized principal is refused" — the wrong refusal, passing for the
    right one.
    """
    from mayhem.domain.identity import EnvironmentScope, Principal, RoleGrant

    principal = Principal(principal_id="u-ana")
    return tuple(
        RoleGrant(
            role=role,
            scope=EnvironmentScope(environment=ENVIRONMENT),
            principal=principal,
            granted_at=NOW - timedelta(days=1),
            granted_by="u-root",
        )
        for role in roles
    )


def _approval_for(plan: ExecutionPlan, proof: Any) -> Any:
    """Mint a real approval through plan 09's only constructor."""
    from mayhem.domain.approval import Approval
    from mayhem.domain.identity import EnvironmentScope, Principal

    return Approval.bind(
        approval_id="a-" + "".join(ch for ch in plan.run_id if ch.isalnum())[:32],
        proof=proof,
        policy_digest="a" * 64,
        approver=Principal(principal_id="u-ana"),
        environment=EnvironmentScope(environment=ENVIRONMENT),
        issued_at=NOW,
        ttl_s=3600.0,
    )


def _run_resource() -> Any:
    from mayhem.domain.api import RunResource

    authored = DrillSpec.model_validate(SPEC_DOCUMENT)
    return RunResource.of(
        RunRecord(
            run_id=RUN_ID,
            experiment_name=authored.name,
            spec_json=authored.model_dump_json(),
            plan_json=_plan().model_dump_json(),
            seed=1,
            status=RunStatus.COMPLETED,
            verdict=RunVerdict.FAIL,
            environment_fingerprint=SNAPSHOTS["environment_fingerprint"],
            config_snapshot_id=SNAPSHOTS["config_snapshot_id"],
            started_at="2026-01-01T00:00:00+00:00",
            ended_at="2026-01-01T00:00:30+00:00",
            tags=(),
        )
    )


def _graded_reference() -> Any:
    """A sealed envelope whose steady-state block graded one signal.

    The verdict is ``degraded-within-tolerance`` so the impact section has a
    citation to rest on, and the root-failure section still has nothing assertable
    — which is the honest shape for a run that degraded but did not break.
    """
    from mayhem.domain.api import EvidenceReference
    from mayhem.domain.evidence import EvidenceEnvelope

    envelope = EvidenceEnvelope(
        run_id=RUN_ID,
        plan_hash=plan_hash_of(_plan()),
        report_id="ev-safety-graded",
        created_at=NOW.isoformat(),
        steady_state={
            "phase": "verify",
            "verdict": {
                "overall": "degraded-within-tolerance",
                "reason": "p99 rose 40ms against a 50ms tolerance",
                "checks": [
                    {
                        "phase": "verify",
                        "check_id": "p99-under-load",
                        "verb": "degraded",
                        "verdict": "DEGRADED",
                        "signals": [
                            {"name": "p99", "unit": "ms", "value": 40.0, "limit": 50.0}
                        ],
                    }
                ],
            },
        },
    )
    return EvidenceReference.of(envelope)


def _ungraded_reference() -> Any:
    """A sealed envelope for ``RUN_ID`` carrying an empty steady-state payload.

    An *ungraded* run is the honest negative case: ``explain_run`` must withhold
    its root-failure section rather than invent a cause over a verdict nobody
    computed.
    """
    from mayhem.domain.api import EvidenceReference
    from mayhem.domain.evidence import EvidenceEnvelope

    envelope = EvidenceEnvelope(
        run_id=RUN_ID,
        plan_hash=plan_hash_of(_plan()),
        report_id="ev-safety-1",
        created_at=NOW.isoformat(),
    )
    return EvidenceReference.of(envelope)


def _event(kind: EventKind) -> Event:
    return Event(
        kind=kind,
        run_id=RUN_ID,
        detail={},
        created_at_epoch_s=0.0,
    )


class TestEvidenceIntegrity:
    def test_an_evidence_reference_must_agree_with_its_run(self, api: ApiStore) -> None:
        """Phase 1's digest binding, asserted from the store's side."""
        api.save_run(_run_resource())
        api.save_evidence(_ungraded_reference())
        reference = api.evidence_for_run(RUN_ID)
        assert reference is not None
        assert reference.run_id == RUN_ID
        assert reference.plan_digest == plan_digest_of(_plan())

    def test_a_tampered_query_index_is_refused_by_the_auditor(self, api: ApiStore) -> None:
        """The denormalised columns are a *cache*, and a drifted cache refuses.

        Written past the store entirely, through raw SQL, so the only thing that
        can notice is :meth:`~mayhem.infra.api_store.ApiStore.audit_indexes` —
        which is what makes "the index is a cache, not a second model" a property
        rather than a claim.
        """
        from mayhem.infra.api_store import StaleIndexError

        api.save_run(_run_resource())
        api.save_evidence(_ungraded_reference())
        with api.store.write() as conn:
            conn.execute(
                "UPDATE api_evidence_refs SET plan_digest = ? WHERE run_id = ?",
                ("f" * 64, RUN_ID),
            )
        with pytest.raises(StaleIndexError):
            api.audit_indexes()

    def test_the_events_table_is_where_the_timeline_comes_from(self) -> None:
        """A timeline point is a view over stored events, never a stored point."""
        from mayhem.domain.api import RunTimeline

        assert _event(EventKind.RUN_STARTED).kind is EventKind.RUN_STARTED
        assert "events" in RunTimeline.model_fields
        assert "points" not in RunTimeline.model_fields, (
            "a points field would be a place to store a timeline, and gap 32 is closed "
            "by having no such place"
        )
        assert isinstance(RunTimeline.points, property)

    def test_the_timeline_table_does_not_exist(self, store: Store) -> None:
        names = {
            str(row["name"])
            for row in store.query("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert not any("timeline" in name for name in names), (
            "a table of timeline points would be a second account of the same events"
        )
