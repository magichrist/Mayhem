"""The execution-intent contract (v0.9.0).

Execution is an approved act: a plan is only executed when an intent says *who*
approved *which* plan, on *which* engine and target, and *until when*. These
tests pin the three stable refusal codes and the compatibility switch.
"""

from __future__ import annotations

import time

import pytest

from mayhem.domain.errors import DomainError
from mayhem.domain.execution_intent import (
    APPROVAL_EXPIRED,
    IMPLICIT_EXECUTION_ENV,
    INTENT_MISMATCH,
    INTENT_REQUIRED,
    ExecutionIntent,
    ExecutionIntentRefused,
    implicit_execution_allowed,
    intent_for_plan,
    require_execution_intent,
    require_explicit_approval,
)
from mayhem.domain.experiments import ExperimentKind, ExecutionPlan, PlannedStep, Wait
from mayhem.domain.preflight import plan_hash_for
from mayhem.infra.evidence import build_evidence

PLAN = ExecutionPlan(
    run_id="r-intent-1",
    kind=ExperimentKind.DRILL,
    steps=(PlannedStep(id="s1", seq=1, raw_action=Wait(timeout=1.0)),),
    config_snapshot_id="c1",
    topology_snapshot_id="t1",
    environment_fingerprint="fp-1",
)
PLAN_HASH = plan_hash_for(PLAN)


def _intent(**overrides: object) -> ExecutionIntent:
    now = time.time()
    base: dict[str, object] = {
        "plan_hash": PLAN_HASH,
        "engine": "podman",
        "target_identity": "podman",
        "policy_id": "allow",
        "blast_radius": {"containers": 2},
        "actor": "tester",
        "approved_at": now,
        "expires_at": now + 900.0,
    }
    base.update(overrides)
    return ExecutionIntent(**base)  # type: ignore[arg-type]


class TestIntentShape:
    def test_interface_carries_every_approved_fact(self) -> None:
        payload = _intent(break_glass=True).to_dict()
        assert set(payload) == {
            "plan_hash",
            "engine",
            "target_identity",
            "policy_id",
            "blast_radius",
            "actor",
            "approved_at",
            "expires_at",
            "break_glass",
        }
        assert payload["blast_radius"] == {"containers": 2}
        assert payload["break_glass"] is True

    def test_round_trips_through_a_dict(self) -> None:
        intent = _intent(break_glass=True)
        assert ExecutionIntent.from_dict(intent.to_dict()) == intent

    def test_intent_for_plan_binds_the_preflight_plan_hash(self) -> None:
        intent = intent_for_plan(PLAN, engine="podman", target_identity="podman")
        assert intent.plan_hash == PLAN_HASH
        assert intent.expires_at is not None
        assert intent.expires_at > intent.approved_at

    def test_intent_for_plan_can_mint_a_non_expiring_approval(self) -> None:
        intent = intent_for_plan(PLAN, engine="podman", ttl_s=None)
        assert intent.expires_at is None
        assert intent.is_expired() is False


class TestPresence:
    def test_no_intent_is_refused(self) -> None:
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            require_execution_intent(None, plan_hash=PLAN_HASH, action="run")
        assert excinfo.value.code == INTENT_REQUIRED

    def test_refusal_is_a_domain_error(self) -> None:
        with pytest.raises(DomainError):
            require_execution_intent(None, plan_hash=PLAN_HASH)

    def test_refusal_names_the_action_and_the_escape_hatch(self) -> None:
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            require_execution_intent(None, plan_hash=PLAN_HASH, action="maniac")
        assert excinfo.value.details["action"] == "maniac"
        assert excinfo.value.details["implicit_execution_env"] == IMPLICIT_EXECUTION_ENV
        assert excinfo.value.remediation

    def test_compatibility_switch_allows_the_implicit_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(IMPLICIT_EXECUTION_ENV, raising=False)
        assert implicit_execution_allowed() is False
        monkeypatch.setenv(IMPLICIT_EXECUTION_ENV, "1")
        assert implicit_execution_allowed() is True
        assert require_execution_intent(None, plan_hash=PLAN_HASH, action="run") is None

    def test_explicit_allow_implicit_argument_wins(self) -> None:
        assert require_execution_intent(
            None, plan_hash=PLAN_HASH, allow_implicit=True, action="run"
        ) is None
        with pytest.raises(ExecutionIntentRefused):
            require_execution_intent(None, plan_hash=PLAN_HASH, allow_implicit=False)

    def test_valid_intent_is_returned(self) -> None:
        intent = _intent()
        assert (
            require_execution_intent(
                intent, plan_hash=PLAN_HASH, engine="podman", target_identity="podman"
            )
            is intent
        )


class TestExpiry:
    def test_expired_intent_is_refused(self) -> None:
        now = time.time()
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            require_execution_intent(
                _intent(approved_at=now - 100.0, expires_at=now - 1.0),
                plan_hash=PLAN_HASH,
                engine="podman",
            )
        assert excinfo.value.code == APPROVAL_EXPIRED
        assert "re-approve" in excinfo.value.remediation

    def test_expiry_boundary_is_inclusive(self) -> None:
        now = 1000.0
        assert _intent(approved_at=now - 10, expires_at=now).is_expired(now) is True
        assert _intent(approved_at=now - 10, expires_at=now + 0.001).is_expired(now) is False

    def test_expiry_is_checked_before_the_bindings(self) -> None:
        now = time.time()
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            require_execution_intent(
                _intent(approved_at=now - 100.0, expires_at=now - 1.0),
                plan_hash="a-different-plan",
                engine="docker",
            )
        assert excinfo.value.code == APPROVAL_EXPIRED

    def test_non_expiring_intent_never_expires(self) -> None:
        assert _intent(expires_at=None).is_expired(10_000_000.0) is False


class TestBindingMismatch:
    def test_different_plan_hash_is_refused(self) -> None:
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            require_execution_intent(_intent(), plan_hash="0" * 64, engine="podman")
        assert excinfo.value.code == INTENT_MISMATCH
        assert "plan_hash" in excinfo.value.details["mismatched"]

    def test_different_engine_is_refused(self) -> None:
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            require_execution_intent(_intent(), plan_hash=PLAN_HASH, engine="docker")
        assert excinfo.value.code == INTENT_MISMATCH
        assert excinfo.value.details["mismatched"] == ["engine"]

    def test_different_target_is_refused(self) -> None:
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            require_execution_intent(
                _intent(), plan_hash=PLAN_HASH, engine="podman", target_identity="prod-cluster"
            )
        assert excinfo.value.code == INTENT_MISMATCH
        assert excinfo.value.details["mismatched"] == ["target_identity"]

    def test_every_mismatch_is_reported_at_once(self) -> None:
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            require_execution_intent(
                _intent(),
                plan_hash="0" * 64,
                engine="kubernetes",
                target_identity="staging",
            )
        assert set(excinfo.value.details["mismatched"]) == {
            "plan_hash",
            "engine",
            "target_identity",
        }

    def test_an_intent_that_binds_no_plan_authorizes_nothing(self) -> None:
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            require_execution_intent(_intent(plan_hash=""), plan_hash=PLAN_HASH)
        assert excinfo.value.code == INTENT_MISMATCH
        assert excinfo.value.details["mismatched"] == ["plan_hash"]

    def test_unbound_optional_bindings_are_not_compared(self) -> None:
        intent = _intent(engine="", target_identity="")
        assert intent.mismatches(plan_hash=PLAN_HASH, engine="docker", target_identity="x") == ()
        assert (
            require_execution_intent(
                intent, plan_hash=PLAN_HASH, engine="docker", target_identity="x"
            )
            is intent
        )

    def test_caller_that_cannot_resolve_the_binding_does_not_invalidate(self) -> None:
        intent = _intent()
        assert intent.mismatches(plan_hash=PLAN_HASH, engine="", target_identity="") == ()


class TestExplicitApproval:
    def test_approved_action_passes(self) -> None:
        assert require_explicit_approval("janitor --execute", approved=True) is None

    def test_unapproved_action_is_refused(self) -> None:
        with pytest.raises(ExecutionIntentRefused) as excinfo:
            require_explicit_approval("explore", approved=False, allow_implicit=False)
        assert excinfo.value.code == INTENT_REQUIRED
        assert excinfo.value.details["action"] == "explore"

    def test_compatibility_switch_covers_simple_approvals(self) -> None:
        assert (
            require_explicit_approval("explore", approved=False, allow_implicit=True) is None
        )


class TestEvidence:
    def test_the_approving_intent_travels_with_the_evidence(self) -> None:
        intent = _intent()
        envelope = build_evidence(
            run_id=PLAN.run_id,
            plan=PLAN,
            target_profile=None,
            engine="podman",
            safety_decisions=("allow",),
            step_reports=({"step_id": "s1", "ok": True},),
            lease_timeline=(),
            observations=(),
            verdict="completed",
            recovery_state="recovered",
            remediation=(),
            execution_intent=intent.to_dict(),
        )
        assert envelope.execution_intent is not None
        assert envelope.execution_intent["plan_hash"] == PLAN_HASH
        assert envelope.execution_intent["actor"] == "tester"
        # It survives a JSON round trip through the store envelope.
        assert ExecutionIntent.from_dict(envelope.execution_intent).plan_hash == PLAN_HASH

    def test_evidence_without_an_intent_is_still_valid(self) -> None:
        envelope = build_evidence(
            run_id=PLAN.run_id,
            plan=PLAN,
            target_profile=None,
            engine="podman",
            safety_decisions=(),
            step_reports=(),
            lease_timeline=(),
            observations=(),
            verdict="",
            recovery_state="",
            remediation=(),
        )
        assert envelope.execution_intent is None
