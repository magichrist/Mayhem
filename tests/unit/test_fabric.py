"""Tests for the distributed execution fabric vocabulary (v1.1.0 plan 03, Phase 1).

The fabric's Phase 1 acceptance is a *type* property, so these tests are mostly
negative controls: they show the shapes that must be impossible are impossible
(constructing an unsigned envelope, replaying a nonce, minting an unbounded
loop), and that the predicates which make those shapes decidable agree with the
constructors that refuse them.

Everything is a value here, so nothing is mocked: no clock reads (callers pass
``now``), no crypto, no IO.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.fabric import (
    FABRIC_PLAN_MISMATCH,
    FABRIC_PROTOCOL_VERSION,
    FABRIC_REPLAYED_NONCE,
    FABRIC_RESERVATION_EXPIRED,
    FABRIC_RESOURCE_CONFLICT,
    FABRIC_STALE_FENCE,
    SEMANTIC_REQUIRED_FIELDS,
    CommandBodyRef,
    FabricCommand,
    FabricCommandRefused,
    FabricCommandType,
    FencingToken,
    NonceLedger,
    Reservation,
    StepSemantics,
    StepSpec,
    assert_fence_current,
    assert_plan_digest_matches,
    assert_reservation_available,
    is_well_formed,
    require_well_formed,
    reservation_conflicts,
    step_semantics_violations,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
PLAN_DIGEST = "a" * 64
OTHER_PLAN_DIGEST = "b" * 64
BODY_DIGEST = "c" * 64
NONCE = "d" * 32
SIGNATURE = "sig" * 8

#: One well-formed field set per semantic — the positive control each negative
#: control is measured against.
_WELL_FORMED: tuple[tuple[StepSemantics, dict[str, object]], ...] = (
    (StepSemantics.SERIAL, {}),
    (StepSemantics.PARALLEL, {"fan_out_step_ids": ("s-2", "s-3")}),
    (StepSemantics.CONDITIONAL, {"condition_ref": "cond-1"}),
    (StepSemantics.LOOP, {"bound": 3, "budget_ref": "budget-team-a"}),
    (StepSemantics.RETRY, {"retry_limit": 2, "backoff_ref": "backoff-1"}),
    (StepSemantics.TIMEOUT, {"timeout_s": 30.0}),
    (StepSemantics.BRANCH, {"condition_ref": "cond-1", "branch_targets": ("s-2",)}),
    (StepSemantics.JOIN, {"join_step_ids": ("s-2", "s-3")}),
    (StepSemantics.WAIT, {"wait_ref": "w-1", "timeout_s": 60.0}),
    (StepSemantics.APPROVAL, {"approval_ref": "appr-1"}),
    (StepSemantics.COMPENSATE, {"compensates_step_id": "s-1", "verify_probe_ref": "probe-1"}),
)
_FIELDS_BY_SEMANTIC: dict[StepSemantics, dict[str, object]] = dict(_WELL_FORMED)


def _fence(*, epoch: int = 1, run_id: str = "r-fabric-1", step_id: str = "s-1") -> FencingToken:
    return FencingToken(
        run_id=run_id,
        step_id=step_id,
        holder="agent-1",
        epoch=epoch,
        issued_at=NOW,
        supersedes_epoch=epoch - 1 if epoch > 1 else None,
    )


def _body(ref: str = "blob-1", digest: str = BODY_DIGEST) -> CommandBodyRef:
    return CommandBodyRef(
        command_type=FabricCommandType.INJECT,
        body_digest=digest,
        body_ref=ref,
    )


def _envelope(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "protocol": FABRIC_PROTOCOL_VERSION,
        "command_id": "fc-1",
        "run_id": "r-fabric-1",
        "step_id": "s-1",
        "agent_id": "agent-1",
        "plan_digest": PLAN_DIGEST,
        "nonce": NONCE,
        "idempotency_key": "idem-1",
        "fencing_token": _fence(),
        "command": _body(),
        "issued_at": NOW,
        "signing_key_id": "key-1",
        "signature": SIGNATURE,
    }
    base.update(overrides)
    return base


def _command(**overrides: object) -> FabricCommand:
    return FabricCommand.model_validate(_envelope(**overrides))


class TestFabricCommandEnvelope:
    def test_well_formed_envelope_validates(self) -> None:
        command = _command()
        assert command.plan_digest == PLAN_DIGEST
        assert command.nonce == NONCE
        assert command.idempotency_key == "idem-1"
        assert command.command.command_type is FabricCommandType.INJECT
        assert command.fencing_token.epoch == 1

    def test_every_envelope_field_is_required(self) -> None:
        assert set(FabricCommand.model_fields) == {
            "protocol",
            "command_id",
            "run_id",
            "step_id",
            "agent_id",
            "plan_digest",
            "nonce",
            "idempotency_key",
            "fencing_token",
            "command",
            "issued_at",
            "signing_key_id",
            "signature",
        }
        # No default anywhere: an omitted field is a validation error, not a
        # silently-empty envelope.
        for name, field in FabricCommand.model_fields.items():
            assert field.is_required(), f"envelope field {name!r} has a default and is a bypass"

    def test_constructed_command_is_signed(self) -> None:
        assert _command().is_signed is True

    def test_binds_to_its_plan_digest_and_not_another(self) -> None:
        command = _command()
        assert command.binds_to(PLAN_DIGEST) is True
        assert command.binds_to(OTHER_PLAN_DIGEST) is False

    def test_same_effect_as_compares_key_and_body(self) -> None:
        command = _command()
        retry = _command(command_id="fc-2", nonce="e" * 32)
        # Same key, same body under a different locator: the same effect.
        relocated = _command(command_id="fc-3", nonce="f" * 32, command=_body("blob-2"))
        # Same key, different body: an idempotency-key collision, not a retry.
        collision = _command(
            command_id="fc-4",
            nonce="a1" * 16,
            command=_body("blob-3", digest="e" * 64),
        )
        assert command.same_effect_as(retry) is True
        assert command.same_effect_as(relocated) is True
        assert command.same_effect_as(collision) is False

    def test_a_different_key_is_not_a_retry(self) -> None:
        assert _command().same_effect_as(_command(idempotency_key="idem-2")) is False

    def test_signing_payload_covers_every_field_but_the_signature(self) -> None:
        command = _command()
        payload = command.signing_payload()
        assert "signature" not in payload
        for signed in ("plan_digest", "nonce", "idempotency_key", "fencing_token", "command"):
            assert signed in payload
        assert payload == command.signing_payload()
        # The signature does not cover itself: a re-signed command signs the
        # same payload.
        assert payload == _command(signature="other" + SIGNATURE).signing_payload()
        # Any signed field changing changes the payload.
        assert payload != _command(plan_digest=OTHER_PLAN_DIGEST).signing_payload()
        assert payload != _command(issued_at=NOW + timedelta(seconds=1)).signing_payload()

    def test_frozen_envelope_is_immutable(self) -> None:
        command = _command()
        with pytest.raises(ValidationError):
            command.nonce = "0" * 32  # type: ignore[misc]

    def test_extra_fields_are_refused(self) -> None:
        with pytest.raises(ValidationError) as excinfo:
            _command(compensates_step_id="s-0")
        assert any(err["type"] == "extra_forbidden" for err in excinfo.value.errors())


class TestUnsignedCommandIsUnrepresentable:
    def test_command_without_a_signature_cannot_be_built(self) -> None:
        payload = _envelope()
        del payload["signature"]
        with pytest.raises(ValidationError) as excinfo:
            FabricCommand.model_validate(payload)
        assert any(err["type"] == "missing" for err in excinfo.value.errors())

    def test_command_without_a_signing_key_cannot_be_built(self) -> None:
        payload = _envelope()
        del payload["signing_key_id"]
        with pytest.raises(ValidationError):
            FabricCommand.model_validate(payload)

    def test_blank_signature_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            _command(signature=" " * 20)

    def test_short_signature_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            _command(signature="sig")

    def test_punctuation_signature_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            _command(signature="!" * 32)

    def test_missing_plan_digest_is_refused(self) -> None:
        payload = _envelope()
        del payload["plan_digest"]
        with pytest.raises(ValidationError) as excinfo:
            FabricCommand.model_validate(payload)
        assert any(err["loc"] == ("plan_digest",) for err in excinfo.value.errors())

    def test_empty_plan_digest_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            _command(plan_digest="")

    def test_non_hex_plan_digest_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            _command(plan_digest="not-a-digest")

    def test_missing_fencing_token_is_refused(self) -> None:
        payload = _envelope()
        del payload["fencing_token"]
        with pytest.raises(ValidationError):
            FabricCommand.model_validate(payload)

    def test_missing_idempotency_key_is_refused(self) -> None:
        payload = _envelope()
        del payload["idempotency_key"]
        with pytest.raises(ValidationError):
            FabricCommand.model_validate(payload)

    def test_missing_command_body_ref_is_refused(self) -> None:
        payload = _envelope()
        del payload["command"]
        with pytest.raises(ValidationError):
            FabricCommand.model_validate(payload)

    def test_missing_nonce_is_refused(self) -> None:
        payload = _envelope()
        del payload["nonce"]
        with pytest.raises(ValidationError):
            FabricCommand.model_validate(payload)

    def test_foreign_protocol_version_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _command(protocol="mayhem/2")
        assert excinfo.value.rule == "fabric_protocol_version"

    def test_naive_issue_time_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _command(issued_at=datetime(2026, 1, 2, 3, 4, 5))  # noqa: DTZ001
        assert excinfo.value.rule == "fabric_command_time"


class TestCommandReplay:
    def test_fresh_nonce_is_not_a_replay(self) -> None:
        assert _command().is_replayed([]) is False
        assert _command().is_replayed(["0" * 32]) is False

    def test_consumed_nonce_is_a_replay(self) -> None:
        assert _command().is_replayed([NONCE]) is True

    def test_ledger_records_a_fresh_nonce(self) -> None:
        ledger = NonceLedger().accept(_command())
        assert ledger.knows(NONCE)
        assert len(ledger.consumed) == 1

    def test_ledger_refuses_a_replayed_nonce(self) -> None:
        ledger = NonceLedger().accept(_command())
        with pytest.raises(FabricCommandRefused) as excinfo:
            ledger.accept(_command(command_id="fc-2"))
        assert excinfo.value.code == FABRIC_REPLAYED_NONCE
        assert excinfo.value.details["command_id"] == "fc-2"

    def test_refused_replay_does_not_advance_the_ledger(self) -> None:
        ledger = NonceLedger().accept(_command())
        with pytest.raises(FabricCommandRefused):
            ledger.accept(_command(command_id="fc-2"))
        assert ledger.consumed == frozenset({NONCE})

    def test_ledger_is_immutable(self) -> None:
        ledger = NonceLedger().accept(_command())
        assert ledger.accept(_command(nonce="e" * 32)).consumed == frozenset({NONCE, "e" * 32})
        assert ledger.consumed == frozenset({NONCE})

    def test_a_retry_may_share_a_key_but_never_a_nonce(self) -> None:
        first = _command()
        ledger = NonceLedger().accept(first)
        retry = _command(command_id="fc-2", nonce="e" * 32)
        assert retry.same_effect_as(first) is True
        assert retry.is_replayed(ledger.consumed) is False
        with pytest.raises(FabricCommandRefused) as excinfo:
            NonceLedger().accept(first).accept(_command(command_id="fc-3", nonce=NONCE))
        assert excinfo.value.code == FABRIC_REPLAYED_NONCE


class TestFencingTokens:
    def test_first_fence_starts_at_epoch_one(self) -> None:
        fence = FencingToken.issue(run_id="r-fabric-1", step_id="s-1", holder="agent-1", now=NOW)
        assert fence.epoch == 1
        assert fence.supersedes_epoch is None
        assert fence.issued_at == NOW

    def test_epoch_zero_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            _fence(epoch=0)

    def test_epoch_must_be_positive_integer(self) -> None:
        with pytest.raises(ValidationError):
            _fence(epoch=-3)

    def test_successor_is_strictly_newer(self) -> None:
        fence = _fence()
        successor = fence.next_fence(holder="agent-2", now=NOW + timedelta(seconds=5))
        assert successor.epoch == fence.epoch + 1
        assert successor.supersedes_epoch == fence.epoch
        assert successor.holder == "agent-2"
        assert successor.is_after(fence) is True
        assert fence.is_after(successor) is False

    def test_a_handshake_must_strictly_increase(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            FencingToken(
                run_id="r-fabric-1",
                step_id="s-1",
                holder="agent-2",
                epoch=2,
                issued_at=NOW,
                supersedes_epoch=2,
            )
        assert excinfo.value.rule == "fence_supersede_ordering"

    def test_a_handshake_may_not_go_backwards(self) -> None:
        with pytest.raises(InvariantViolationError):
            FencingToken(
                run_id="r-fabric-1",
                step_id="s-1",
                holder="agent-2",
                epoch=1,
                issued_at=NOW,
                supersedes_epoch=4,
            )

    def test_naive_issue_time_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            FencingToken(
                run_id="r-fabric-1",
                step_id="s-1",
                holder="agent-1",
                epoch=1,
                issued_at=datetime(2026, 1, 2, 3, 4, 5),  # noqa: DTZ001
            )
        assert excinfo.value.rule == "fence_time_ordering"

    def test_ordering_is_per_step(self) -> None:
        mine = _fence(epoch=5, step_id="s-1")
        theirs = _fence(epoch=2, step_id="s-2")
        assert mine.same_scope(theirs) is False
        assert mine.is_after(theirs) is False
        assert mine.is_at_least(theirs) is False

    def test_is_at_least_is_inclusive(self) -> None:
        fence = _fence(epoch=3)
        assert fence.is_at_least(_fence(epoch=3)) is True
        assert fence.is_at_least(_fence(epoch=4)) is False
        assert fence.outranks(_fence(epoch=4)) is True

    def test_command_guarded_by_its_own_fence(self) -> None:
        served = _fence(epoch=2)
        assert _command(fencing_token=served).guards(served) is True

    def test_command_under_a_stale_fence_is_refused(self) -> None:
        stale = _command(fencing_token=_fence(epoch=2))
        served = _fence(epoch=3)
        assert stale.guards(served) is False
        assert stale.is_stale_against(served) is True
        with pytest.raises(FabricCommandRefused) as excinfo:
            assert_fence_current(stale, served_fence=served)
        assert excinfo.value.code == FABRIC_STALE_FENCE

    def test_command_under_a_current_fence_passes(self) -> None:
        command = _command(fencing_token=_fence(epoch=4))
        assert_fence_current(command, served_fence=_fence(epoch=3))
        assert command.is_stale_against(_fence(epoch=4)) is False


class TestPlanBinding:
    def test_command_against_the_frozen_plan_is_accepted(self) -> None:
        assert_plan_digest_matches(_command(), current_plan_digest=PLAN_DIGEST)

    def test_command_against_a_superseded_plan_is_refused(self) -> None:
        with pytest.raises(FabricCommandRefused) as excinfo:
            assert_plan_digest_matches(_command(), current_plan_digest=OTHER_PLAN_DIGEST)
        assert excinfo.value.code == FABRIC_PLAN_MISMATCH
        assert excinfo.value.details["command_id"] == "fc-1"


class TestStepSemanticsWellFormedness:
    def test_every_semantic_is_declared(self) -> None:
        assert {semantic.value for semantic in StepSemantics} == {
            "serial",
            "parallel",
            "conditional",
            "loop",
            "retry",
            "timeout",
            "branch",
            "join",
            "wait",
            "approval",
            "compensate",
        }

    def test_required_field_table_covers_every_semantic(self) -> None:
        assert set(SEMANTIC_REQUIRED_FIELDS) == set(StepSemantics)

    @pytest.mark.parametrize(("semantic", "fields"), _WELL_FORMED)
    def test_well_formed_fields_are_accepted(
        self, semantic: StepSemantics, fields: Mapping[str, object]
    ) -> None:
        assert step_semantics_violations(semantic, fields) == ()
        assert is_well_formed(semantic, fields) is True
        require_well_formed(semantic, fields)

    @pytest.mark.parametrize(
        ("semantic", "missing"),
        [
            (StepSemantics.PARALLEL, "fan_out_step_ids"),
            (StepSemantics.CONDITIONAL, "condition_ref"),
            (StepSemantics.LOOP, "bound"),
            (StepSemantics.LOOP, "budget_ref"),
            (StepSemantics.RETRY, "retry_limit"),
            (StepSemantics.RETRY, "backoff_ref"),
            (StepSemantics.TIMEOUT, "timeout_s"),
            (StepSemantics.BRANCH, "condition_ref"),
            (StepSemantics.BRANCH, "branch_targets"),
            (StepSemantics.JOIN, "join_step_ids"),
            (StepSemantics.WAIT, "wait_ref"),
            (StepSemantics.WAIT, "timeout_s"),
            (StepSemantics.APPROVAL, "approval_ref"),
            (StepSemantics.COMPENSATE, "compensates_step_id"),
            (StepSemantics.COMPENSATE, "verify_probe_ref"),
        ],
    )
    def test_each_semantic_names_its_missing_field(
        self, semantic: StepSemantics, missing: str
    ) -> None:
        complete = _FIELDS_BY_SEMANTIC[semantic]
        assert is_well_formed(semantic, complete) is True
        violations = step_semantics_violations(semantic, {**complete, missing: None})
        assert violations == (f"{semantic.value}.{missing} is required",)

    def test_serial_needs_nothing_extra(self) -> None:
        assert SEMANTIC_REQUIRED_FIELDS[StepSemantics.SERIAL] == frozenset()
        assert step_semantics_violations(StepSemantics.SERIAL, {}) == ()

    def test_empty_collections_count_as_unstated(self) -> None:
        assert step_semantics_violations(
            StepSemantics.BRANCH, {"condition_ref": "cond-1", "branch_targets": ()}
        ) == ("branch.branch_targets is required",)

    def test_blank_reference_counts_as_unstated(self) -> None:
        assert step_semantics_violations(StepSemantics.LOOP, {"bound": 2, "budget_ref": "  "}) == (
            "loop.budget_ref is required",
        )

    def test_zero_bound_is_rejected_as_a_value(self) -> None:
        violations = step_semantics_violations(
            StepSemantics.LOOP, {"bound": 0, "budget_ref": "budget-1"}
        )
        assert violations == ("loop.bound must be a positive integer, got 0",)

    def test_boolean_bound_is_rejected(self) -> None:
        violations = step_semantics_violations(
            StepSemantics.LOOP, {"bound": True, "budget_ref": "budget-1"}
        )
        assert violations == ("loop.bound must be a positive integer, got True",)

    def test_non_positive_timeout_is_rejected(self) -> None:
        violations = step_semantics_violations(StepSemantics.TIMEOUT, {"timeout_s": -1.0})
        assert violations == ("timeout.timeout_s must be a positive number, got -1.0",)

    def test_zero_retry_limit_is_rejected(self) -> None:
        violations = step_semantics_violations(
            StepSemantics.RETRY, {"retry_limit": 0, "backoff_ref": "backoff-1"}
        )
        assert violations == ("retry.retry_limit must be a positive integer, got 0",)

    def test_require_well_formed_raises_with_a_stable_rule(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            require_well_formed(StepSemantics.LOOP, {"bound": 2})
        assert excinfo.value.rule == "step_semantics_ill_formed"
        assert "loop.budget_ref is required" in str(excinfo.value)

    def test_require_well_formed_is_silent_for_a_good_step(self) -> None:
        require_well_formed(StepSemantics.SERIAL, {})


class TestStepSpec:
    def test_well_formed_spec_constructs(self) -> None:
        spec = StepSpec(
            step_id="s-loop",
            semantic=StepSemantics.LOOP,
            bound=3,
            budget_ref="budget-team-a",
        )
        assert spec.iteration_cap() == 3
        assert spec.is_compensating is False

    def test_unbounded_loop_is_unrepresentable(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            StepSpec(step_id="s-loop", semantic=StepSemantics.LOOP, budget_ref="budget-1")
        assert excinfo.value.rule == "step_semantics_ill_formed"
        assert "loop.bound is required" in str(excinfo.value)

    def test_loop_with_a_bound_but_no_budget_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            StepSpec(step_id="s-loop", semantic=StepSemantics.LOOP, bound=3)
        assert "loop.budget_ref is required" in str(excinfo.value)

    def test_loop_with_a_bound_of_zero_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError):
            StepSpec(step_id="s-loop", semantic=StepSemantics.LOOP, bound=0, budget_ref="budget-1")

    def test_conditionless_branch_is_unrepresentable(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            StepSpec(
                step_id="s-branch",
                semantic=StepSemantics.BRANCH,
                branch_targets=("s-2",),
            )
        assert "branch.condition_ref is required" in str(excinfo.value)

    def test_compensate_without_a_verify_probe_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            StepSpec(
                step_id="s-comp",
                semantic=StepSemantics.COMPENSATE,
                compensates_step_id="s-1",
            )
        assert "compensate.verify_probe_ref is required" in str(excinfo.value)

    def test_compensate_spec_is_flagged(self) -> None:
        spec = StepSpec(
            step_id="s-comp",
            semantic=StepSemantics.COMPENSATE,
            compensates_step_id="s-1",
            verify_probe_ref="probe-1",
        )
        assert spec.is_compensating is True
        assert spec.compensates_step_id == "s-1"

    def test_approval_step_needs_an_approval_ref(self) -> None:
        with pytest.raises(InvariantViolationError):
            StepSpec(step_id="s-approve", semantic=StepSemantics.APPROVAL)

    def test_retry_cap_is_reported(self) -> None:
        spec = StepSpec(
            step_id="s-retry",
            semantic=StepSemantics.RETRY,
            retry_limit=2,
            backoff_ref="backoff-1",
        )
        assert spec.iteration_cap() == 2

    def test_non_iterating_step_has_no_cap(self) -> None:
        assert StepSpec(step_id="s-1", semantic=StepSemantics.SERIAL).iteration_cap() is None

    def test_duration_string_is_accepted_for_timeout(self) -> None:
        spec = StepSpec(
            step_id="s-wait",
            semantic=StepSemantics.WAIT,
            wait_ref="w-1",
            timeout_s="5m",
        )
        assert float(spec.timeout_s) == 300.0

    def test_zero_timeout_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            StepSpec(
                step_id="s-timeout",
                semantic=StepSemantics.TIMEOUT,
                timeout_s=0,
            )
        assert "timeout.timeout_s must be a positive number" in str(excinfo.value)

    def test_spec_is_frozen(self) -> None:
        spec = StepSpec(step_id="s-1", semantic=StepSemantics.SERIAL)
        with pytest.raises(ValidationError):
            spec.step_id = "s-2"  # type: ignore[misc]

    def test_unknown_carrier_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            StepSpec(step_id="s-1", semantic=StepSemantics.SERIAL, nope=1)  # type: ignore[call-arg]


class TestReservations:
    def _reservation(
        self,
        *,
        resource_id: str = "svc/checkout",
        run_id: str = "r-fabric-1",
        step_id: str = "s-1",
        holder: str = "agent-1",
        epoch: int = 1,
        ttl_seconds: float = 60.0,
        acquired_at: datetime = NOW,
    ) -> Reservation:
        return Reservation(
            resource_id=resource_id,
            run_id=run_id,
            step_id=step_id,
            holder=holder,
            fencing_token=_fence(epoch=epoch, run_id=run_id, step_id=step_id),
            ttl_seconds=ttl_seconds,
            acquired_at=acquired_at,
        )

    def test_reservation_names_resource_owner_and_expiry(self) -> None:
        reservation = self._reservation()
        assert reservation.resource_id == "svc/checkout"
        assert reservation.owner == ("r-fabric-1", "s-1")
        assert reservation.expires_at == NOW + timedelta(seconds=60)

    def test_expiry_is_reached_after_the_ttl(self) -> None:
        reservation = self._reservation(ttl_seconds=30.0)
        assert reservation.is_expired(NOW + timedelta(seconds=29)) is False
        assert reservation.is_expired(NOW + timedelta(seconds=30)) is True

    def test_remaining_never_goes_negative(self) -> None:
        reservation = self._reservation(ttl_seconds=10.0)
        assert reservation.remaining_s(NOW + timedelta(seconds=4)) == 6.0
        assert reservation.remaining_s(NOW + timedelta(seconds=99)) == 0.0

    def test_zero_ttl_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            self._reservation(ttl_seconds=0.0)
        assert excinfo.value.rule == "reservation_positive_ttl"

    def test_fence_from_another_step_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            Reservation(
                resource_id="svc/checkout",
                run_id="r-fabric-1",
                step_id="s-9",
                holder="agent-1",
                fencing_token=_fence(step_id="s-1"),
            )
        assert excinfo.value.rule == "reservation_fence_scope"

    def test_naive_acquisition_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            Reservation(
                resource_id="svc/checkout",
                run_id="r-fabric-1",
                step_id="s-1",
                holder="agent-1",
                fencing_token=_fence(),
                acquired_at=datetime(2026, 1, 2, 3, 4, 5),  # noqa: DTZ001
            )
        assert excinfo.value.rule == "reservation_time_ordering"

    def test_two_owners_of_one_resource_conflict(self) -> None:
        first = self._reservation(step_id="s-1")
        second = self._reservation(step_id="s-2", holder="agent-2")
        assert first.conflicts_with(second, now=NOW) is True
        assert reservation_conflicts([first, second], now=NOW) == (second,)

    def test_a_step_does_not_conflict_with_itself(self) -> None:
        reservation = self._reservation()
        assert reservation.conflicts_with(reservation, now=NOW) is False
        assert reservation_conflicts([reservation], now=NOW) == ()

    def test_different_resources_do_not_conflict(self) -> None:
        first = self._reservation(resource_id="svc/checkout", step_id="s-1")
        second = self._reservation(resource_id="node/worker-3", step_id="s-2")
        assert first.conflicts_with(second, now=NOW) is False

    def test_an_expired_lock_is_not_contention(self) -> None:
        stale = self._reservation(step_id="s-1", ttl_seconds=1.0)
        late = self._reservation(step_id="s-2", acquired_at=NOW + timedelta(seconds=30))
        # While the short TTL holds, the second claim collides.
        assert stale.conflicts_with(late, now=NOW) is True
        # Once it has lapsed, nobody is locked out.
        assert stale.conflicts_with(late, now=NOW + timedelta(seconds=30)) is False
        assert reservation_conflicts([stale, late], now=NOW + timedelta(seconds=30)) == ()

    def test_conflicting_claim_is_refused_at_dispatch(self) -> None:
        held = self._reservation(step_id="s-1")
        wanted = self._reservation(step_id="s-2", holder="agent-2")
        with pytest.raises(FabricCommandRefused) as excinfo:
            assert_reservation_available(wanted, held=[held], now=NOW)
        assert excinfo.value.code == FABRIC_RESOURCE_CONFLICT

    def test_free_resource_is_granted(self) -> None:
        assert_reservation_available(
            self._reservation(step_id="s-2", holder="agent-2"), now=NOW
        )

    def test_renewal_extends_the_ttl(self) -> None:
        renewed = self._reservation(ttl_seconds=60.0).renew(
            ttl_seconds=120.0, now=NOW + timedelta(seconds=30)
        )
        assert float(renewed.ttl_seconds) == 120.0
        assert renewed.expires_at == NOW + timedelta(seconds=150)

    def test_expired_lock_cannot_be_renewed(self) -> None:
        with pytest.raises(FabricCommandRefused) as excinfo:
            self._reservation(ttl_seconds=10.0).renew(
                ttl_seconds=60.0, now=NOW + timedelta(seconds=20)
            )
        assert excinfo.value.code == FABRIC_RESERVATION_EXPIRED

    def test_reservation_is_bound_to_its_fence(self) -> None:
        reservation = self._reservation(epoch=2)
        assert reservation.is_authorised_by(_fence(epoch=1)) is True
        assert reservation.is_authorised_by(_fence(epoch=2)) is True
        assert reservation.is_authorised_by(_fence(epoch=3)) is False

    def test_reservation_is_frozen(self) -> None:
        reservation = self._reservation()
        with pytest.raises(ValidationError):
            reservation.resource_id = "svc/other"  # type: ignore[misc]
