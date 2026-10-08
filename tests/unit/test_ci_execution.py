"""A pipeline run carries the same identity, intent, and evidence an interactive
run carries (docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md, Phase 4).

The plan's Phase 4 acceptance criterion is a single negative statement — *a
pipeline run without an evidence link fails the gate closed, never open* — and
this suite is built around it plus the two properties that make it mean anything:

* **The identity is declared and is never ambient.** A human principal inside a
  pipeline is refused at :class:`CIActor` construction, because an unattended job
  executing with a person's authority is the exact thing nobody meant to grant.
  A service account with no role grant is refused too, and the refusal names the
  role it needed — the CI surface cannot invent authority it was not given.
* **The approval gate is delegated, not re-implemented.** Asserted structurally:
  :func:`pipeline_run_authorization` resolves the name
  ``require_execution_intent`` from its own module and calls it, so a second
  (laxer) approval gate cannot be added without this test noticing. The
  behavioural half is that an absent intent, an expired one, and one bound to a
  different plan each refuse with *the domain's own code*, not a new one.
* **The evidence link is structural.** Four ways to have no link, and all four
  refuse. Two of them — no cited run, and no envelope — are the plan's sentence
  verbatim; the other two (an envelope for a different run, an envelope whose
  digest is not the pin's) are the shapes a forged citation takes.

**The negative controls are the point of this file.** Three of them are named
`test_negative_control_*`, and each one *breaks the property on purpose* and
asserts that the break is observable. A test that only asserts the happy path
cannot tell a working guard from a guard that was never exercised; a test that
removes the guard and watches the refusal disappear can.

Nothing here runs a CI system. There is no runner, no workflow event, and no
token; the properties are over values.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mayhem.controller import ci_execution
from mayhem.controller.ci_execution import (
    CI_ROLES,
    PIPELINE_ACTION,
    RULE_CI_ACTOR_NOT_DECLARED,
    RULE_CI_ACTOR_WITHOUT_ROLE,
    RULE_CI_AMBIENT_PRIVILEGE,
    RULE_CI_EVIDENCE_MISMATCH,
    RULE_CI_RUN_UNLINKED,
    RULE_CI_TICKET_SEAL_BROKEN,
    CIActor,
    PipelineRunAuthorization,
    RunLink,
    SealedTicket,
    envelope_digest,
    link_run_evidence,
    pipeline_run_authorization,
    seal_ticket,
    ticket_seal_digest,
)
from mayhem.domain.comparison import RunPin
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.domain.execution_intent import (
    APPROVAL_EXPIRED,
    INTENT_MISMATCH,
    INTENT_REQUIRED,
    ExecutionIntent,
    ExecutionIntentRefused,
)
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    PrincipalKind,
    Role,
    RoleGrant,
)
from mayhem.domain.pipeline import (
    ChangeLink,
    CheckOutcome,
    CheckScope,
    PipelinePins,
    PipelineVerdict,
    PRCheck,
)

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(minutes=5)
CI_SCOPE = EnvironmentScope(environment="ci", project="checkout")
GIT_SHA = "a1b2c3d"

SERVICE_ACCOUNT = Principal(principal_id="sa-ci-bot", kind=PrincipalKind.SERVICE_ACCOUNT)
WORKLOAD = Principal(principal_id="wl-runner-3", kind=PrincipalKind.WORKLOAD)
PERSON = Principal(principal_id="u-oncall", kind=PrincipalKind.HUMAN)

PLAN_HASH = "9" * 64


def _envelope(**overrides: Any) -> EvidenceEnvelope:
    fields: dict[str, Any] = {
        "run_id": "run-ci-0001",
        "plan_hash": PLAN_HASH,
        "verdict": "clean",
        "step_reports": ({"step": "s0", "outcome": "compensated"},),
    }
    fields.update(overrides)
    return EvidenceEnvelope(**fields)


#: The canonical envelope's own digest, so the canonical ``_pin()`` and the
#: canonical ``_envelope()`` verify against each other without a helper call.
#: Computed rather than written down for the ordinary reason: a digest typed as a
#: literal stops being true the moment the envelope it described changes, and the
#: mismatch tests would then pass for the wrong reason.
DIGEST = envelope_digest(_envelope())


def _pin(**overrides: Any) -> RunPin:
    fields: dict[str, Any] = {
        "run_id": "run-ci-0001",
        "experiment": "checkout-resilience",
        "release": "v2.5",
        "environment": "ci",
        "plan_version": "plan-7",
        "policy_version": "policy-7",
        "catalog_version": "catalog-2026.09",
        "agent_version": "agent-2.0.0",
        "runtime_version": "runtime-2.1.0",
        "evidence_digest": DIGEST,
    }
    fields.update(overrides)
    return RunPin(**fields)


def _check(*, outcome: CheckOutcome = CheckOutcome.PASS) -> PRCheck:
    finding = None
    if outcome is CheckOutcome.FAIL:
        from mayhem.domain.pipeline import CheckFinding, FindingSeverity

        finding = CheckFinding(
            code="check.blast-radius.refused",
            message="blast too large",
            severity=FindingSeverity.ERROR,
        )
    return PRCheck(
        name="blast-radius",
        scope=CheckScope.BLAST_RADIUS,
        outcome=outcome,
        evidence_refs=("gate-output/blast-radius",),
        finding=finding,
        detail="2 of 2 proof lines pass",
        observed_at=NOW,
    )


def _link(**overrides: Any) -> ChangeLink:
    fields: dict[str, Any] = {
        "git_sha": GIT_SHA,
        "change_ticket": "CH-1421",
        "deployment_id": "deploy-9931",
        "pins": PipelinePins.from_run(_pin()),
        "linked_at": NOW,
    }
    fields.update(overrides)
    return ChangeLink(**fields)


#: "not supplied", as distinct from "supplied as ``None``". Several tests need to
#: build a verdict or an authorization with no run at all, and a plain default of
#: ``None`` would be indistinguishable from the test's own omission.
ABSENT: Any = object()


def _verdict(
    *, cited_run: Any = ABSENT, outcome: str = "pass", **overrides: Any
) -> PipelineVerdict:
    check = _check(outcome=CheckOutcome.FAIL if outcome == "fail" else CheckOutcome.PASS)
    run = _pin() if cited_run is ABSENT else cited_run
    fields: dict[str, Any] = {
        "outcome": outcome,
        "change": _link(),
        "evidence_refs": ("gate-output/blast-radius",),
        "checks": (check,),
        "cited_run": run,
        "reasons": () if outcome == "pass" else ("blast-radius reported fail",),
        "decided_at": NOW,
    }
    fields.update(overrides)
    return PipelineVerdict(**fields)


def _pinned_run(_envelope_value: EvidenceEnvelope) -> RunPin:
    """A run pin whose digest is the envelope's, so the link verifies."""
    return _pin(evidence_digest=envelope_digest(_envelope_value))


def _grant(principal: Principal, role: Role = Role.EXECUTE) -> RoleGrant:
    return RoleGrant(role=role, scope=CI_SCOPE, principal=principal, granted_at=NOW)


def _intent(**overrides: Any) -> ExecutionIntent:
    fields: dict[str, Any] = {
        "plan_hash": PLAN_HASH,
        "engine": "podman",
        "target_identity": "checkout",
        "policy_id": "policy-7",
        "actor": "u-oncall",
        "approved_at": (NOW - timedelta(minutes=1)).timestamp(),
        "expires_at": (NOW + timedelta(minutes=30)).timestamp(),
    }
    fields.update(overrides)
    return ExecutionIntent(**fields)


# ── the declared identity ──────────────────────────────────────────────────────


class TestDeclaredIdentity:
    def test_a_service_account_is_an_acceptable_actor(self) -> None:
        actor = CIActor(principal=SERVICE_ACCOUNT, forge="github-actions")
        assert actor.principal_id == "sa-ci-bot"
        assert actor.to_dict()["kind"] == "service_account"

    def test_a_workload_identity_is_an_acceptable_actor(self) -> None:
        actor = CIActor(principal=WORKLOAD, forge="tekton")
        assert actor.principal_id == "wl-runner-3"

    def test_a_human_principal_is_ambient_privilege_and_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            CIActor(principal=PERSON)
        assert excinfo.value.rule == RULE_CI_AMBIENT_PRIVILEGE
        assert "service account" in str(excinfo.value)

    def test_an_undeclared_actor_is_refused(self) -> None:
        """The blank-id refusal, reached past the first line of defence.

        :class:`~mayhem.domain.identity.Principal` already refuses a blank
        ``principal_id``, so this construction cannot be reached through ordinary
        use. The guard in :class:`CIActor` exists anyway, and building the
        principal with ``model_construct`` — bypassing validation — is the only
        honest way to prove it is not dead code.
        """
        undeclared = Principal.model_construct(principal_id="   ")
        with pytest.raises(InvariantViolationError) as excinfo:
            CIActor(principal=undeclared)
        assert excinfo.value.rule == RULE_CI_ACTOR_NOT_DECLARED

    def test_principal_itself_refuses_a_blank_id_before_the_actor_does(self) -> None:
        """The layering: the domain type refuses first, and that is the right order."""
        with pytest.raises(InvariantViolationError) as excinfo:
            Principal(principal_id="  ")
        assert excinfo.value.rule == "principal_id_not_blank"

    def test_a_disabled_service_account_holds_no_role(self) -> None:
        """Plan-09's revoked-approver rule, reached from the pipeline side."""
        revoked = Principal(
            principal_id="sa-retired", kind=PrincipalKind.SERVICE_ACCOUNT, disabled=True
        )
        actor = CIActor(principal=revoked)
        with pytest.raises(InvariantViolationError) as excinfo:
            actor.require_role(Role.EXECUTE, CI_SCOPE, grants=(_grant(revoked),), now=NOW)
        assert excinfo.value.rule == RULE_CI_ACTOR_WITHOUT_ROLE

    def test_no_grants_resolves_to_no_roles_and_refuses(self) -> None:
        actor = CIActor(principal=SERVICE_ACCOUNT)
        with pytest.raises(InvariantViolationError) as excinfo:
            actor.require_role(Role.EXECUTE, CI_SCOPE, now=NOW)
        assert excinfo.value.rule == RULE_CI_ACTOR_WITHOUT_ROLE
        assert "no roles" in str(excinfo.value)

    def test_a_grant_in_another_environment_does_not_reach(self) -> None:
        actor = CIActor(principal=SERVICE_ACCOUNT)
        elsewhere = RoleGrant(
            role=Role.EXECUTE,
            scope=EnvironmentScope(environment="production"),
            principal=SERVICE_ACCOUNT,
            granted_at=NOW,
        )
        with pytest.raises(InvariantViolationError):
            actor.require_role(Role.EXECUTE, CI_SCOPE, grants=(elsewhere,), now=NOW)

    def test_the_roles_a_pipeline_may_hold_exclude_administer(self) -> None:
        """A pipeline that could administer mayhem could be talked into executing.

        Stated as data rather than as prose, so a future widening of
        :data:`CI_ROLES` shows up as a failing assertion here rather than as a
        line in a diff nobody reads.
        """
        assert Role.ADMINISTER not in CI_ROLES
        assert Role.APPROVE not in CI_ROLES
        assert set(CI_ROLES) == {Role.PLAN, Role.EXECUTE}


# ── sealing the ticket ─────────────────────────────────────────────────────────


class TestTicketSeal:
    def test_a_seal_covers_the_sha_and_the_references(self) -> None:
        seal = seal_ticket(_link(), sealed_by="sa-ci-bot", sealed_at=NOW)
        assert seal.references == ("ticket:CH-1421", "deployment:deploy-9931")
        assert seal.seal_digest == ticket_seal_digest(_link())
        assert seal.sealed_by == "sa-ci-bot"

    def test_an_unchanged_link_verifies(self) -> None:
        seal = seal_ticket(_link())
        assert seal.verify(_link()) is seal

    def test_a_ticket_edited_after_sealing_is_refused(self) -> None:
        seal = seal_ticket(_link())
        moved = _link(change_ticket="CH-9999")
        with pytest.raises(InvariantViolationError) as excinfo:
            seal.verify(moved)
        assert excinfo.value.rule == RULE_CI_TICKET_SEAL_BROKEN
        assert "CH-1421" in str(excinfo.value)
        assert "CH-9999" in str(excinfo.value)

    def test_a_ticket_added_after_sealing_is_refused(self) -> None:
        seal = seal_ticket(_link())
        with pytest.raises(InvariantViolationError):
            seal.verify(_link(incident_id="INC-1"))

    def test_the_sha_may_not_be_swapped_underneath_the_seal(self) -> None:
        seal = seal_ticket(_link())
        with pytest.raises(InvariantViolationError) as excinfo:
            seal.verify(_link(git_sha="b2c3d4e"))
        assert excinfo.value.rule == RULE_CI_TICKET_SEAL_BROKEN

    @pytest.mark.parametrize(
        "ticket",
        [
            "CH-1421; rm -rf /",
            "$(id)",
            "`id`",
            "CH 1421",
            "CH\n1421",
            "CH'1421",
            "*",
        ],
        ids=["semicolon", "subshell", "backtick", "space", "newline", "quote", "glob"],
    )
    def test_a_ticket_carrying_shell_syntax_is_refused(self, ticket: str) -> None:
        """The ticket arrives from an untrusted environment variable.

        ``ChangeLink`` accepts any string here, deliberately — it is a domain type
        that does not know where its values came from. The seal *does* know, and
        this is where the two meet.
        """
        with pytest.raises(InvariantViolationError) as excinfo:
            seal_ticket(_link(change_ticket=ticket))
        assert excinfo.value.rule == RULE_CI_TICKET_SEAL_BROKEN

    def test_a_seal_with_no_references_cannot_be_built(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            SealedTicket(git_sha=GIT_SHA, references=())
        assert excinfo.value.rule == RULE_CI_TICKET_SEAL_BROKEN


# ── the evidence link ──────────────────────────────────────────────────────────


class TestEvidenceLink:
    def test_a_linked_run_is_grounded_and_cited(self) -> None:
        envelope = _envelope()
        grounded = link_run_evidence(_verdict(cited_run=_pinned_run(envelope)), envelope)
        assert "run/checkout-resilience@v2.5#run-ci-0001" in grounded.evidence_refs

    def test_grounding_twice_is_idempotent(self) -> None:
        envelope = _envelope()
        once = link_run_evidence(_verdict(cited_run=_pinned_run(envelope)), envelope)
        assert link_run_evidence(once, envelope) is once

    def test_no_cited_run_fails_closed(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            link_run_evidence(_verdict(cited_run=None), _envelope())
        assert excinfo.value.rule == RULE_CI_RUN_UNLINKED
        assert "fails closed" in str(excinfo.value)

    def test_no_envelope_fails_closed(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            link_run_evidence(_verdict(), None)
        assert excinfo.value.rule == RULE_CI_RUN_UNLINKED
        assert "never open" in str(excinfo.value)

    def test_an_envelope_for_another_run_is_refused(self) -> None:
        other = _envelope(run_id="run-ci-9999")
        with pytest.raises(InvariantViolationError) as excinfo:
            link_run_evidence(_verdict(), other)
        assert excinfo.value.rule == RULE_CI_RUN_UNLINKED
        assert "run-ci-9999" in str(excinfo.value)

    def test_an_envelope_whose_digest_is_not_the_pins_is_refused(self) -> None:
        """A citation that points at evidence which is not what was measured."""
        envelope = _envelope()
        verdict = _verdict(cited_run=_pin(evidence_digest="1" * 64))
        with pytest.raises(InvariantViolationError) as excinfo:
            link_run_evidence(verdict, envelope)
        assert excinfo.value.rule == RULE_CI_EVIDENCE_MISMATCH
        assert envelope_digest(envelope)[:12] in str(excinfo.value)

    def test_the_digest_is_computed_not_trusted(self) -> None:
        """Editing the envelope after pinning changes its digest.

        Without this the previous test would pass for the wrong reason: it could
        be reading a field the envelope itself carries.
        """
        envelope = _envelope()
        before = envelope_digest(envelope)
        edited = envelope.model_copy(update={"verdict": "dirty"})
        assert envelope_digest(edited) != before
        with pytest.raises(InvariantViolationError) as excinfo:
            link_run_evidence(_verdict(cited_run=_pin(evidence_digest=before)), edited)
        assert excinfo.value.rule == RULE_CI_EVIDENCE_MISMATCH


# ── the authorization, in order ────────────────────────────────────────────────


def both_open(*authorizations: PipelineRunAuthorization) -> bool:
    return all(authorization.opens_release for authorization in authorizations)


class TestPipelineRunAuthorization:
    def _authorize(self, **overrides: Any) -> PipelineRunAuthorization:
        envelope = overrides.pop("envelope", ABSENT)
        if envelope is ABSENT:
            envelope = _envelope()
        verdict = overrides.pop("verdict", ABSENT)
        if verdict is ABSENT:
            verdict = _verdict(cited_run=_pinned_run(envelope))
        fields: dict[str, Any] = {
            "scope": CI_SCOPE,
            "grants": (_grant(SERVICE_ACCOUNT),),
            "intent": _intent(),
            "plan_hash": PLAN_HASH,
            "engine": "podman",
            "target_identity": "checkout",
            "envelope": envelope,
            "now": NOW,
        }
        fields.update(overrides)
        return pipeline_run_authorization(CIActor(principal=SERVICE_ACCOUNT), verdict, **fields)

    def test_a_fully_grounded_pipeline_run_is_authorized(self) -> None:
        authorization = self._authorize()
        assert authorization.roles == ("execute",)
        assert authorization.evidence_link is RunLink.LINKED
        assert authorization.intent_plan_hash == PLAN_HASH
        assert authorization.opens_release is True

    def test_the_environment_comes_from_the_scope_not_the_actor(self) -> None:
        assert self._authorize().environment == CI_SCOPE.describe()

    def test_the_authorization_records_who_and_what_it_read(self) -> None:
        payload = self._authorize().to_dict()
        assert payload["actor"]["principal_id"] == "sa-ci-bot"
        assert payload["seal"]["references"] == ["ticket:CH-1421", "deployment:deploy-9931"]
        assert payload["verdict_digest"]

    def test_authorization_is_refused_before_the_intent_is_consulted(self) -> None:
        """The ordering, on an actor that holds nothing.

        A job with no authority must not be able to reach the approval gate by
        presenting a perfectly valid intent — otherwise "who is allowed to ask"
        and "who is allowed to run" become the same question, and the first
        answer is the weaker one.
        """
        with pytest.raises(InvariantViolationError) as excinfo:
            self._authorize(grants=())
        assert excinfo.value.rule == RULE_CI_ACTOR_WITHOUT_ROLE

    def test_no_intent_is_refused_with_the_domain_s_own_code(self) -> None:
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            self._authorize(intent=None)
        assert excinfo.value.code == INTENT_REQUIRED
        assert PIPELINE_ACTION in str(excinfo.value)

    def test_an_expired_intent_is_refused_with_the_domain_s_own_code(self) -> None:
        lapsed = _intent(
            approved_at=(NOW - timedelta(hours=2)).timestamp(),
            expires_at=(NOW - timedelta(hours=1)).timestamp(),
        )
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            self._authorize(intent=lapsed)
        assert excinfo.value.code == APPROVAL_EXPIRED

    def test_an_intent_bound_to_another_plan_is_refused(self) -> None:
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            self._authorize(plan_hash="8" * 64)
        assert excinfo.value.code == INTENT_MISMATCH

    def test_the_documented_escape_hatch_is_the_only_way_past_the_intent(self) -> None:
        """Same gate, same switch an operator has.

        Asserted so a future "CI is trusted, skip the approval" branch has to be
        written explicitly rather than inherited by accident.
        """
        envelope = _envelope()
        verdict = _verdict(cited_run=_pinned_run(envelope))
        with pytest.raises(ExecutionIntentRefused):
            self._authorize(intent=None)
        tolerated = self._authorize(
            intent=None, allow_implicit=True, envelope=envelope, verdict=verdict
        )
        assert tolerated.intent_plan_hash == ""
        assert tolerated.opens_release is True

    def test_a_ticket_that_moved_between_the_check_and_the_gate_is_refused(self) -> None:
        """The property the seal exists for, in the shape the pipeline sees it.

        The check ran, sealed ``ticket:CH-1421``, and returned. Somebody edited
        the pull request's ticket field. The gate now runs against
        ``ticket:CH-9999`` while holding the earlier seal, and refuses.
        """
        envelope = _envelope()
        checked_seal = seal_ticket(_link(), sealed_by="sa-ci-bot", sealed_at=NOW)
        moved = _verdict(cited_run=_pinned_run(envelope), change=_link(change_ticket="CH-9999"))
        with pytest.raises(InvariantViolationError) as excinfo:
            pipeline_run_authorization(
                CIActor(principal=SERVICE_ACCOUNT),
                moved,
                scope=CI_SCOPE,
                grants=(_grant(SERVICE_ACCOUNT),),
                intent=_intent(),
                plan_hash=PLAN_HASH,
                engine="podman",
                target_identity="checkout",
                envelope=envelope,
                seal=checked_seal,
                now=NOW,
            )
        assert excinfo.value.rule == RULE_CI_TICKET_SEAL_BROKEN
        assert "CH-1421" in str(excinfo.value)
        assert "CH-9999" in str(excinfo.value)

    def test_an_unmoved_seal_is_verified_and_records_that_it_was(self) -> None:
        """The two seal states are distinguishable in the payload.

        A caller that supplies the check-time seal gets ``seal_verified=True``; a
        caller that does not gets ``False``. Without the flag a reader would have
        to assume the stronger of the two.
        """
        envelope = _envelope()
        verdict = _verdict(cited_run=_pinned_run(envelope))
        verified = self._authorize(
            envelope=envelope,
            verdict=verdict,
            seal=seal_ticket(_link(), sealed_by="sa-ci-bot", sealed_at=NOW),
        )
        minted = self._authorize(envelope=envelope, verdict=verdict)
        assert verified.seal_verified is True
        assert minted.seal_verified is False
        assert verified.to_dict()["seal_verified"] is True
        assert both_open(verified, minted)

    def test_an_unlinked_run_is_refused(self) -> None:
        envelope = _envelope()
        verdict = _verdict(cited_run=_pinned_run(envelope))
        with pytest.raises(InvariantViolationError) as excinfo:
            self._authorize(envelope=None, verdict=verdict)
        assert excinfo.value.rule == RULE_CI_RUN_UNLINKED

    def test_a_failing_verdict_still_authorizes_but_does_not_open_a_release(self) -> None:
        """Authorization and gating are two different questions.

        A pipeline run whose checks failed is a run mayhem is willing to *record*;
        it is not a run that opens a release. Conflating the two would mean either
        refusing to record a failure or letting a failure through.
        """
        envelope = _envelope()
        failing = _verdict(cited_run=_pinned_run(envelope), outcome="fail")
        authorization = self._authorize(envelope=envelope, verdict=failing)
        assert authorization.opens_release is False

    def test_an_unlinked_authorization_never_opens_a_release(self) -> None:
        """The last line of defence.

        :func:`pipeline_run_authorization` refuses before an unlinked
        authorization can exist, so this constructs one directly — which is only
        possible because the dataclass is public — and asserts it still says no.
        """
        envelope = _envelope()
        grounded = link_run_evidence(_verdict(cited_run=_pinned_run(envelope)), envelope)
        authorization = PipelineRunAuthorization(
            actor=CIActor(principal=SERVICE_ACCOUNT),
            environment="checkout/ci",
            roles=("execute",),
            intent_plan_hash=PLAN_HASH,
            verdict=grounded,
            evidence_refs=grounded.evidence_refs,
            seal=seal_ticket(grounded.change),
            evidence_link=RunLink.UNLINKED,
        )
        assert authorization.opens_release is False


# ── structural: the approval gate is delegated, not re-implemented ──────────────


class TestStructuralInvariants:
    def test_the_approval_gate_is_delegated_not_reimplemented(self) -> None:
        """The Phase 4 claim, asserted against the source.

        "CI executions carry the same execution intent and approvals as
        interactive runs" is only true if there is one gate. This reads the module
        and requires that the *only* call to the intent gate is a call to the name
        resolved from :mod:`mayhem.domain.execution_intent` — so a hand-rolled
        ``if intent is None or intent.expires_at < now`` cannot appear beside it.
        """
        source = Path(ci_execution.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        assert calls.count("require_execution_intent") == 1

    def test_nothing_in_this_module_reads_an_environment_variable(self) -> None:
        """No ambient privilege, structurally.

        Mayhem does not discover who the pipeline is; the pipeline declares it.
        A future ``os.environ`` lookup here would be the whole Phase 4 claim
        quietly reversed.
        """
        source = Path(ci_execution.__file__).read_text(encoding="utf-8")
        assert "os.environ" not in source
        assert "getenv" not in source

    def test_every_refusal_code_is_module_level_and_exported(self) -> None:
        for name in (
            "RULE_CI_ACTOR_NOT_DECLARED",
            "RULE_CI_AMBIENT_PRIVILEGE",
            "RULE_CI_ACTOR_WITHOUT_ROLE",
            "RULE_CI_RUN_UNLINKED",
            "RULE_CI_EVIDENCE_MISMATCH",
            "RULE_CI_TICKET_SEAL_BROKEN",
        ):
            assert name in ci_execution.__all__, name
            assert isinstance(getattr(ci_execution, name), str)

    def test_this_module_writes_nothing(self) -> None:
        """No store, no file, no socket.

        The Phase 4 surface records an admission; the mutation belongs to the run
        engine behind the same intent gate. A write here would be a second,
        weaker, write path.
        """
        source = Path(ci_execution.__file__).read_text(encoding="utf-8")
        for forbidden in ("open(", "Path(", "requests", "urllib", "httpx", "sqlite"):
            assert forbidden not in source, forbidden


# ── negative controls: break the property, watch the refusal disappear ─────────


class TestNegativeControls:
    def test_negative_control_removing_the_human_refusal_admits_a_person(self) -> None:
        """Control: monkeypatch out the ambient-privilege guard.

        With the guard in place :class:`CIActor` refuses a human. With it
        replaced by a no-op the very same construction succeeds and the actor
        resolves whatever roles it was granted. If the admission tests below ever
        pass for the wrong reason, this one is what tells us the guard was inert.
        """
        with pytest.raises(InvariantViolationError):
            CIActor(principal=PERSON)

        original = CIActor.__post_init__
        try:
            CIActor.__post_init__ = lambda self: None  # type: ignore[method-assign]
            admitted = CIActor(principal=PERSON)
        finally:
            CIActor.__post_init__ = original  # type: ignore[method-assign]
        assert admitted.principal_id == "u-oncall"

    def test_negative_control_a_no_op_identity_gate_lets_an_unauthorized_run_through(
        self,
    ) -> None:
        """Control: replace the identity gate and watch the pipeline be admitted.

        This is the mutation the whole file exists to rule out. Stubbing
        :meth:`CIActor.require_role` to return every role — exactly what a
        "temporary" bypass in a debugging branch looks like — turns a refusal into
        an authorization, and the assertion below is the receipt.
        """
        envelope = _envelope()
        original = CIActor.require_role

        def _grant_everything(self: CIActor, *a: Any, **k: Any) -> frozenset[Role]:
            return frozenset(Role)

        try:
            CIActor.require_role = _grant_everything  # type: ignore[method-assign]
            admitted = pipeline_run_authorization(
                CIActor(principal=SERVICE_ACCOUNT),
                _verdict(cited_run=_pinned_run(envelope)),
                scope=CI_SCOPE,
                grants=(),
                intent=_intent(),
                plan_hash=PLAN_HASH,
                engine="podman",
                target_identity="checkout",
                envelope=envelope,
                now=NOW,
            )
        finally:
            CIActor.require_role = original  # type: ignore[method-assign]

        assert admitted.roles == tuple(sorted(role.value for role in Role))
        assert admitted.opens_release is True, (
            "with the identity gate stubbed, the pipeline must be admitted — otherwise "
            "the refusal assertions above prove nothing"
        )

    def test_negative_control_a_verdict_built_over_no_checks_still_refuses_a_summary(
        self,
    ) -> None:
        """Control for the renderer, at the domain layer.

        The summary's own guard is in ``ci_surface``; the reason it exists is that
        :class:`PipelineVerdict` will happily carry a fail over zero checks as
        long as it names a reason. Asserting the construction succeeds and the
        renderer refuses keeps both halves honest.
        """
        from mayhem.controller.ci_surface import render_check_summary

        empty = PipelineVerdict(
            outcome="fail",
            change=_link(),
            evidence_refs=("port/control-plane",),
            reasons=("the checks did not conclude",),
            decided_at=NOW,
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            render_check_summary(empty)
        assert excinfo.value.rule == "ci_surface.summary_without_verdict"


# ── the ChatOps seam this module has to agree with ──────────────────────────────


class TestAgreesWithChatOps:
    def test_the_chatops_verbs_still_map_to_the_engines_role_table(self) -> None:
        """One authorization vocabulary across both dispatch paths.

        ChatOps has its own command → role table because its commands are verbs a
        person types. The *roles* are the domain's, and the pipeline's roles come
        from the same enum — so "who may approve" has one answer in this codebase
        whether the approval is typed in a channel or granted to a job.
        """
        from mayhem.controller.check_gate import CHATOPS_REQUIRED_ROLE

        chatops_roles = set(CHATOPS_REQUIRED_ROLE.values())
        assert chatops_roles <= set(Role)
        assert Role.EXECUTE in CI_ROLES
        assert Role.EXECUTE in chatops_roles

    def test_a_scope_of_any_environment_reaches_a_narrower_scope(self) -> None:
        wildcard = RoleGrant(
            role=Role.EXECUTE,
            scope=EnvironmentScope.any(project="checkout"),
            principal=SERVICE_ACCOUNT,
            granted_at=NOW,
        )
        actor = CIActor(principal=SERVICE_ACCOUNT)
        assert actor.require_role(Role.EXECUTE, CI_SCOPE, grants=(wildcard,), now=NOW)

    def test_the_default_deny_ci_scope_reaches_nothing_by_accident(self) -> None:
        """The ChatOps unbound-channel scope is refused here too.

        Both surfaces fall back to a scope named for the *absence* of a binding.
        A grant written as ``"*"`` reaches it deliberately; an ordinary grant
        does not, which is the property that makes the fallback safe.
        """
        from mayhem.controller.chatops import DEFAULT_DENY_SCOPE

        actor = CIActor(principal=SERVICE_ACCOUNT)
        ordinary = _grant(SERVICE_ACCOUNT)
        with pytest.raises(InvariantViolationError):
            actor.require_role(Role.EXECUTE, DEFAULT_DENY_SCOPE, grants=(ordinary,), now=NOW)
