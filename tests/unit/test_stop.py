"""Emergency stop as types — reason coverage, the escalation ladder, and the
postflight report (docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md, Phase 1).

The module's acceptance criterion is "every stop path maps to exactly one reason;
unknown reasons unrepresentable", and that is what the first block below tests
directly: the mapping is checked in both directions (every signal has a reason,
every reason is claimed by exactly one signal) rather than spot-checked, because
a stop path added without its reason is the exact failure the criterion names.

The ladder tests check the property the design rests on — raising the
cancellation level never *removes* an owed stage — across every (run state,
level) pair, not just a happy path. A ladder that shrinks under escalation would
skip the residue scan on precisely the hard-kill runs that need it.

The negative controls are the honesty gates: an unrecognised reason cannot be
constructed at all, a stop reason that claims a condition id it cannot own is
refused, a ``pass`` line with no evidence reference is refused, and a report with
no checks verdicts ``UNKNOWN`` rather than ``CLEAN``. If any of these could be
written, sealed evidence could say "recovered" about a system nobody checked.

Timestamps are fixed and ``now`` is injected everywhere, so every assertion is
about the rules rather than about the clock.
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from mayhem.domain import stop
from mayhem.domain.cancellation import CancellationLevel
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.stop import (
    STOP_FLOW,
    CheckStatus,
    ObservedValue,
    PostflightCheck,
    PostflightReport,
    PostflightVerdict,
    RunState,
    StopCommand,
    StopEscalation,
    StopReason,
    StopScope,
    StopSignal,
    StopStage,
    StopTrigger,
    is_complete,
    mandatory_stages,
    next_stage,
    reason_for,
    required_level,
    stop_flow,
)

MOMENT = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
LATER = MOMENT + timedelta(seconds=30)
MUCH_LATER = MOMENT + timedelta(hours=2)


def naive_moment() -> datetime:
    """A deliberately naive datetime — the input every tz-discipline check refuses."""
    return datetime(2026, 9, 30, 12, 0)  # noqa: DTZ001


RUN_ID = "run-001"
ENVIRONMENT = "prod-eu-west"

FORBIDDEN_IMPORTS = frozenset(
    {
        "asyncio",
        "os",
        "pathlib",
        "socket",
        "sqlite3",
        "subprocess",
        "mayhem.agents",
        "mayhem.controller",
        "mayhem.infra",
        "mayhem.toolkit",
    }
)


# --- helpers -----------------------------------------------------------------


def operator_stop(**kwargs: object) -> StopTrigger:
    return StopTrigger(reason=StopReason.HUMAN, detail="operator pressed stop", **kwargs)  # type: ignore[arg-type]


def condition_stop(
    condition_id: str = "slo.error_rate",
    observed: tuple[ObservedValue, ...] = (),
) -> StopTrigger:
    return StopTrigger.for_signal(
        StopSignal.CONDITION_TRIPPED,
        condition_id=condition_id,
        observed_values=observed,
    )


def run_command(**kwargs: object) -> StopCommand:
    payload: dict[str, object] = {
        "id": "sc-abc123",
        "scope": StopScope.RUN,
        "run_id": RUN_ID,
        "principal": "operator:ana",
        "trigger": operator_stop(),
        "issued_at": MOMENT,
    }
    payload.update(kwargs)
    return StopCommand.model_validate(payload)


def env_command(**kwargs: object) -> StopCommand:
    payload: dict[str, object] = {
        "id": "sc-def456",
        "scope": StopScope.ENVIRONMENT,
        "environment": ENVIRONMENT,
        "principal": "operator:ana",
        "trigger": operator_stop(),
        "issued_at": MOMENT,
    }
    payload.update(kwargs)
    return StopCommand.model_validate(payload)


def passing_check(
    name: str, *, observed_at: datetime = MOMENT, ttl: float = 900.0
) -> PostflightCheck:
    return PostflightCheck(
        name=name,
        status=CheckStatus.PASS,
        evidence_refs=(f"residue-scan/{name}",),
        observed_at=observed_at,
        ttl_seconds=ttl,
    )


def failing_check(name: str) -> PostflightCheck:
    return PostflightCheck(
        name=name,
        status=CheckStatus.FAIL,
        evidence_refs=(f"residue-scan/{name}",),
        detail="tc qdisc still present on eth0",
        observed_at=MOMENT,
    )


def report_of(*checks: PostflightCheck, **kwargs: object) -> PostflightReport:
    payload: dict[str, object] = {
        "run_id": RUN_ID,
        "stop": operator_stop(),
        "checks": checks,
        "generated_at": MOMENT,
    }
    payload.update(kwargs)
    return PostflightReport.model_validate(payload)


# --- reason coverage matrix ---------------------------------------------------


class TestReasonCoverage:
    """Every stop path maps to exactly one reason, and only those reasons exist."""

    @pytest.mark.parametrize(
        ("signal", "expected"),
        [
            (StopSignal.OPERATOR_REQUEST, StopReason.HUMAN),
            (StopSignal.CONDITION_TRIPPED, StopReason.CONDITION_FIRED),
            (StopSignal.PREFLIGHT_REFUSAL, StopReason.PREFLIGHT_FAILED),
            (StopSignal.CONTROLLER_LOST, StopReason.CONTROLLER_LOST),
            (StopSignal.OVERRIDE_APPLIED, StopReason.OVERRIDE),
        ],
    )
    def test_each_path_maps_to_its_one_reason(
        self, signal: StopSignal, expected: StopReason
    ) -> None:
        """``for_signal`` binds the reason, so a caller cannot choose a different one.

        A condition-tripped trigger needs its condition id to be legal at all —
        which is itself the rule under test, so it is supplied here.
        """
        condition_id = "slo.error_rate" if signal is StopSignal.CONDITION_TRIPPED else ""
        assert reason_for(signal) is expected
        trigger = StopTrigger.for_signal(signal, condition_id=condition_id)
        assert trigger.reason is expected

    def test_every_signal_has_a_reason(self) -> None:
        """Total in the forward direction: no path is left unmapped."""
        assert set(StopSignal) == set(stop._REASON_FOR_SIGNAL)

    def test_every_reason_is_claimed_by_exactly_one_path(self) -> None:
        """Total and injective in the reverse direction.

        A reason with no path is unreachable vocabulary; a reason with two paths
        is a path that could produce two different meanings for the same sealed
        evidence, which is the thing the acceptance criterion forbids.
        """
        mapped = list(stop._REASON_FOR_SIGNAL.values())
        assert set(mapped) == set(StopReason)
        assert len(mapped) == len(set(mapped))

    def test_reason_set_is_closed_and_exact(self) -> None:
        assert {r.value for r in StopReason} == {
            "human",
            "condition_fired",
            "preflight_failed",
            "controller_lost",
            "override",
        }

    @pytest.mark.parametrize("reason", list(StopReason))
    def test_every_reason_is_constructible_as_a_trigger(self, reason: StopReason) -> None:
        """Each reason has a legal trigger shape — the matrix is total."""
        trigger = StopTrigger(
            reason=reason,
            condition_id="slo.error_rate" if reason is StopReason.CONDITION_FIRED else "",
        )
        assert trigger.reason is reason

    def test_controller_lost_is_a_reason_not_a_detail(self) -> None:
        """The controller-kill path (Phase 2's acceptance case) names its cause."""
        trigger = StopTrigger.for_signal(StopSignal.CONTROLLER_LOST)
        assert trigger.reason is StopReason.CONTROLLER_LOST
        assert trigger.describe() == "controller_lost"

    def test_condition_trigger_carries_id_and_observed_values(self) -> None:
        trigger = condition_stop(observed=(ObservedValue(name="error_rate", value="0.97"),))
        assert trigger.condition_id == "slo.error_rate"
        assert trigger.observed_values[0].describe() == "error_rate=0.97"
        assert trigger.describe() == "condition_fired:slo.error_rate (error_rate=0.97)"

    def test_mapping_rejects_an_unknown_signal(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            reason_for("gremlins")  # type: ignore[arg-type]
        assert excinfo.value.rule == "stop_signal_without_reason"


class TestNegativeControlsReasons:
    """Unknown or contradictory reasons must be unrepresentable, not tolerated."""

    def test_unknown_reason_is_refused_at_construction(self) -> None:
        with pytest.raises(ValidationError) as excinfo:
            StopTrigger(reason="gremlins", detail="something happened")  # type: ignore[arg-type]
        assert "reason" in str(excinfo.value)

    @pytest.mark.parametrize(
        "reason",
        [r for r in StopReason if r is not StopReason.CONDITION_FIRED],
    )
    def test_non_condition_reason_refuses_a_condition_id(self, reason: StopReason) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            StopTrigger(reason=reason, condition_id="slo.error_rate")
        assert excinfo.value.rule == "condition_id_only_for_condition"

    def test_condition_fired_without_a_condition_id_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            StopTrigger(reason=StopReason.CONDITION_FIRED, condition_id="   ")
        assert excinfo.value.rule == "condition_fired_requires_condition_id"

    def test_condition_tripped_signal_without_condition_id_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError):
            StopTrigger.for_signal(StopSignal.CONDITION_TRIPPED)

    def test_duplicate_observed_value_names_are_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            condition_stop(
                observed=(
                    ObservedValue(name="error_rate", value="0.9"),
                    ObservedValue(name="error_rate", value="0.97"),
                )
            )
        assert excinfo.value.rule == "observed_values_unique"

    def test_blank_observed_value_name_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            ObservedValue(name="  ", value="1")
        assert excinfo.value.rule == "observed_value_name_not_blank"

    def test_trigger_round_trips_through_json_without_decaying(self) -> None:
        trigger = condition_stop(observed=(ObservedValue(name="p99", value="4.2", unit="s"),))
        revived = StopTrigger.model_validate_json(trigger.model_dump_json())
        assert revived == trigger


# --- stop command -------------------------------------------------------------


class TestStopCommand:
    def test_run_scoped_command_names_its_run(self) -> None:
        command = run_command()
        assert command.scope is StopScope.RUN
        assert command.run_id == RUN_ID
        assert command.reason is StopReason.HUMAN
        assert not command.is_environment_wide

    def test_environment_wide_command_names_its_environment(self) -> None:
        command = env_command()
        assert command.is_environment_wide
        assert command.environment == ENVIRONMENT

    def test_run_scope_without_run_id_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            run_command(run_id="")
        assert excinfo.value.rule == "run_scope_requires_run_id"

    def test_environment_scope_without_environment_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            env_command(environment="")
        assert excinfo.value.rule == "environment_scope_requires_environment"

    def test_environment_wide_command_cannot_smuggle_a_run_id(self) -> None:
        """'Stop everything except that one run' is a bug with a blast radius."""
        with pytest.raises(InvariantViolationError) as excinfo:
            env_command(run_id=RUN_ID)
        assert excinfo.value.rule == "environment_scope_has_no_run_id"

    def test_run_scoped_command_cannot_claim_an_environment(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            run_command(environment=ENVIRONMENT)
        assert excinfo.value.rule == "run_scope_has_no_environment"

    def test_blank_principal_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            run_command(principal="   ")
        assert excinfo.value.rule == "stop_principal_not_blank"

    def test_naive_issued_at_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            run_command(issued_at=naive_moment())
        assert excinfo.value.rule == "stop_command_issued_at_aware"

    def test_command_carries_exactly_one_reason_from_its_path(self) -> None:
        command = env_command(trigger=condition_stop())
        assert command.reason is StopReason.CONDITION_FIRED

    def test_expiry_is_issued_at_plus_ttl(self) -> None:
        command = run_command(ttl_seconds=60.0)
        assert command.expires_at == MOMENT + timedelta(seconds=60)

    def test_is_stale_uses_the_injected_clock(self) -> None:
        command = run_command(ttl_seconds=60.0)
        assert not command.is_stale(now=MOMENT)
        assert not command.is_stale(now=MOMENT + timedelta(seconds=59))
        assert command.is_stale(now=MOMENT + timedelta(seconds=60))
        assert command.is_stale(now=MOMENT + timedelta(seconds=300))
        # The default 300s TTL has not elapsed 30s in.
        assert not run_command().is_stale(now=LATER)

    def test_is_stale_refuses_a_naive_clock(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            run_command().is_stale(now=naive_moment())
        assert excinfo.value.rule == "stop_command_now_aware"


# --- escalation ladder ---------------------------------------------------------


class TestEscalationLadder:
    def test_ladder_reuses_the_cancellation_levels_by_reference(self) -> None:
        """Every stage names a level owned by cancellation.py, not a local scale."""
        for stage in STOP_FLOW:
            assert isinstance(required_level(stage), CancellationLevel)
        assert {required_level(s) for s in STOP_FLOW} == {
            CancellationLevel.GRACE,
            CancellationLevel.TERM,
            CancellationLevel.KILL,
        }

    def test_stop_flow_is_the_plans_flow_in_order(self) -> None:
        assert STOP_FLOW == (
            StopStage.FREEZE,
            StopStage.CANCEL_PENDING,
            StopStage.COMPENSATE_ACTIVE,
            StopStage.RECONCILE,
            StopStage.RESIDUE_SCAN,
            StopStage.VERIFY,
            StopStage.SEAL,
        )

    def test_pending_run_flow_skips_the_stages_with_no_subject(self) -> None:
        assert stop_flow(RunState.PENDING) == (
            StopStage.FREEZE,
            StopStage.CANCEL_PENDING,
            StopStage.SEAL,
        )

    def test_running_run_flow_is_the_whole_flow(self) -> None:
        assert stop_flow(RunState.RUNNING) == STOP_FLOW

    @pytest.mark.parametrize("state", [RunState.FINISHED, RunState.STOPPED])
    def test_terminal_run_owes_nothing(self, state: RunState) -> None:
        assert stop_flow(state) == ()
        for level in CancellationLevel:
            assert mandatory_stages(state, level) == ()
            assert is_complete(state, level)

    def test_terminal_states_are_terminal(self) -> None:
        assert RunState.FINISHED.is_terminal
        assert RunState.STOPPED.is_terminal
        assert not RunState.RUNNING.is_terminal
        assert not RunState.PENDING.is_terminal

    def test_none_level_owes_nothing(self) -> None:
        """Not stopping is not a stop with stages; it is no stop."""
        assert mandatory_stages(RunState.RUNNING, CancellationLevel.NONE) == ()
        assert is_complete(RunState.RUNNING, CancellationLevel.NONE)

    @pytest.mark.parametrize("state", list(RunState))
    def test_escalation_never_shrinks_the_owed_set(self, state: RunState) -> None:
        """The load-bearing property: raising the level only ever adds stages."""
        for lower, higher in (
            (CancellationLevel.NONE, CancellationLevel.GRACE),
            (CancellationLevel.GRACE, CancellationLevel.TERM),
            (CancellationLevel.TERM, CancellationLevel.KILL),
            (CancellationLevel.NONE, CancellationLevel.KILL),
        ):
            owed_lower = set(mandatory_stages(state, lower))
            owed_higher = set(mandatory_stages(state, higher))
            assert owed_lower <= owed_higher, f"{lower}->{higher} lost stages for {state}"

    def test_hard_kill_oweds_the_residue_scan(self) -> None:
        """A hard kill is exactly when 'the payload died' cannot be trusted."""
        owed = mandatory_stages(RunState.RUNNING, CancellationLevel.KILL)
        assert StopStage.RESIDUE_SCAN in owed
        assert StopStage.VERIFY in owed

    def test_grace_oweds_freeze_and_a_seal_but_no_compensation(self) -> None:
        assert mandatory_stages(RunState.RUNNING, CancellationLevel.GRACE) == (
            StopStage.FREEZE,
            StopStage.CANCEL_PENDING,
            StopStage.SEAL,
        )

    def test_term_level_compensates_and_reconciles(self) -> None:
        assert mandatory_stages(RunState.RUNNING, CancellationLevel.TERM) == (
            StopStage.FREEZE,
            StopStage.CANCEL_PENDING,
            StopStage.COMPENSATE_ACTIVE,
            StopStage.RECONCILE,
            StopStage.SEAL,
        )

    def test_seal_is_owed_at_every_level_that_constitutes_a_stop(self) -> None:
        for level in (CancellationLevel.GRACE, CancellationLevel.TERM, CancellationLevel.KILL):
            assert StopStage.SEAL in mandatory_stages(RunState.RUNNING, level)

    def test_mandatory_stages_are_a_flow_ordered_subset(self) -> None:
        for state in RunState:
            for level in CancellationLevel:
                owed = mandatory_stages(state, level)
                assert list(owed) == [s for s in STOP_FLOW if s in set(owed)]

    def test_next_stage_walks_the_flow_in_order(self) -> None:
        done: tuple[StopStage, ...] = ()
        walked: list[StopStage] = []
        while (stage := next_stage(RunState.RUNNING, CancellationLevel.KILL, done)) is not None:
            walked.append(stage)
            done = (*done, stage)
        assert tuple(walked) == STOP_FLOW
        assert is_complete(RunState.RUNNING, CancellationLevel.KILL, done)

    def test_next_stage_ignores_stages_owed_at_a_lower_level(self) -> None:
        done = (StopStage.FREEZE, StopStage.CANCEL_PENDING)
        assert next_stage(RunState.RUNNING, CancellationLevel.GRACE, done) is StopStage.SEAL
        assert next_stage(RunState.RUNNING, CancellationLevel.KILL, done) is (
            StopStage.COMPENSATE_ACTIVE
        )

    def test_next_stage_on_a_terminal_run_is_none(self) -> None:
        assert next_stage(RunState.FINISHED, CancellationLevel.KILL) is None

    def test_unknown_stage_lookup_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            required_level("vaporise")  # type: ignore[arg-type]
        assert excinfo.value.rule == "stop_stage_not_on_ladder"


class TestStopEscalation:
    def test_starts_at_the_first_owed_stage(self) -> None:
        escalation = StopEscalation(state=RunState.RUNNING, level=CancellationLevel.KILL)
        assert escalation.current is StopStage.FREEZE
        assert escalation.outstanding == STOP_FLOW
        assert not escalation.complete

    def test_advance_walks_to_completion(self) -> None:
        escalation = StopEscalation(state=RunState.RUNNING, level=CancellationLevel.KILL)
        for _ in STOP_FLOW:
            escalation = escalation.advance(escalation.current)  # type: ignore[arg-type]
        assert escalation.complete
        assert escalation.outstanding == ()
        assert escalation.current is None

    def test_advance_refuses_a_stage_that_was_not_owed(self) -> None:
        escalation = StopEscalation(state=RunState.PENDING, level=CancellationLevel.KILL)
        with pytest.raises(InvariantViolationError) as excinfo:
            escalation.advance(StopStage.COMPENSATE_ACTIVE)
        assert excinfo.value.rule == "stage_not_outstanding"

    def test_advance_refuses_a_repeated_stage(self) -> None:
        escalation = StopEscalation(state=RunState.RUNNING, level=CancellationLevel.KILL)
        escalated = escalation.advance(StopStage.FREEZE)
        with pytest.raises(InvariantViolationError):
            escalated.advance(StopStage.FREEZE)

    def test_escalation_position_is_frozen(self) -> None:
        escalation = StopEscalation(state=RunState.RUNNING, level=CancellationLevel.TERM)
        with pytest.raises(AttributeError):
            escalation.state = RunState.FINISHED  # type: ignore[misc]


# --- postflight report ---------------------------------------------------------


class TestPostflightReport:
    def test_all_checks_passing_with_evidence_is_clean(self) -> None:
        report = report_of(passing_check("residue:net.latency"), passing_check("leases_held"))
        assert report.verdict() is PostflightVerdict.CLEAN
        assert report.recovery_verified(now=MOMENT)
        assert report.failed_checks == ()

    def test_one_failure_dirties_the_whole_report(self) -> None:
        report = report_of(passing_check("residue:net.latency"), failing_check("no_tc_rules"))
        assert report.verdict() is PostflightVerdict.DIRTY
        assert not report.recovery_verified()
        assert [c.name for c in report.failed_checks] == ["no_tc_rules"]

    def test_dirty_beats_unknown_when_evidence_is_also_stale(self) -> None:
        """A found residue is a fact about the world; staleness is only absence."""
        report = report_of(
            failing_check("no_tc_rules"),
            passing_check("leases_held", observed_at=MOMENT, ttl=1.0),
            generated_at=MUCH_LATER,
        )
        assert report.verdict() is PostflightVerdict.DIRTY

    def test_empty_report_is_unknown_never_clean(self) -> None:
        """A preflight refusal genuinely has no postflight checks."""
        report = report_of()
        assert report.checks == ()
        assert report.verdict() is PostflightVerdict.UNKNOWN
        assert not report.recovery_verified()

    def test_stale_evidence_is_unknown(self) -> None:
        report = report_of(
            passing_check("residue:net.latency", ttl=60.0),
            generated_at=MOMENT + timedelta(seconds=120),
        )
        assert report.verdict(now=MOMENT) is PostflightVerdict.CLEAN
        assert report.verdict(now=MOMENT + timedelta(seconds=120)) is PostflightVerdict.UNKNOWN

    def test_stale_checks_are_reported_against_the_fixed_generation_point(self) -> None:
        report = report_of(
            passing_check("residue:net.latency", ttl=60.0),
            passing_check("leases_held", ttl=900.0),
            generated_at=MOMENT + timedelta(seconds=120),
        )
        assert [c.name for c in report.stale_checks] == ["residue:net.latency"]

    def test_report_names_the_stop_it_postflights(self) -> None:
        report = report_of(stop=condition_stop(), generated_at=MOMENT)
        assert report.stop_reason is StopReason.CONDITION_FIRED
        assert report.stop.condition_id == "slo.error_rate"

    def test_check_lookup_by_name(self) -> None:
        report = report_of(passing_check("leases_held"))
        assert report.check("leases_held") is not None
        assert report.check("absent") is None

    def test_duplicate_check_names_are_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            report_of(passing_check("leases_held"), failing_check("leases_held"))
        assert excinfo.value.rule == "postflight_check_names_unique"

    def test_digest_is_stable_and_distinguishes_evidence(self) -> None:
        one = report_of(passing_check("leases_held"))
        same = report_of(passing_check("leases_held"))
        other = report_of(passing_check("no_tc_rules"))
        assert one.report_digest == same.report_digest
        assert one.report_digest != other.report_digest
        assert len(one.report_digest) == 64

    def test_digest_changes_when_the_verdict_inputs_change(self) -> None:
        clean = report_of(passing_check("leases_held"))
        dirty = report_of(failing_check("leases_held"))
        assert clean.report_digest != dirty.report_digest

    def test_naive_timestamps_are_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            report_of(generated_at=naive_moment())
        assert excinfo.value.rule == "postflight_timestamp_aware"

    def test_blank_run_id_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            report_of(run_id=" ")
        assert excinfo.value.rule == "postflight_run_id_not_blank"


class TestPostflightCheckNegativeControls:
    def test_pass_without_evidence_ref_is_refused(self) -> None:
        """The forged-PASS guard: an uncited pass is malformed, not passing."""
        with pytest.raises(InvariantViolationError) as excinfo:
            PostflightCheck(name="residue:net.latency", status=CheckStatus.PASS)
        assert excinfo.value.rule == "pass_requires_evidence_ref"

    def test_pass_with_blank_evidence_ref_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            PostflightCheck(
                name="residue:net.latency",
                status=CheckStatus.PASS,
                evidence_refs=("  ",),
            )
        assert excinfo.value.rule == "postflight_evidence_ref_not_blank"

    def test_pass_with_empty_evidence_tuple_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            PostflightCheck(
                name="residue:net.latency",
                status=CheckStatus.PASS,
                evidence_refs=(),
            )
        assert excinfo.value.rule == "pass_requires_evidence_ref"

    def test_fail_may_stand_uncited(self) -> None:
        """A found problem is admissible on the report of what found it."""
        check = PostflightCheck(name="no_tc_rules", status=CheckStatus.FAIL, observed_at=MOMENT)
        assert not check.is_pass
        assert check.evidence_refs == ()

    def test_unknown_check_status_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            PostflightCheck(name="no_tc_rules", status="probably")  # type: ignore[arg-type]

    def test_duplicate_evidence_refs_are_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            PostflightCheck(
                name="no_tc_rules",
                status=CheckStatus.PASS,
                evidence_refs=("residue/1", "residue/1"),
            )
        assert excinfo.value.rule == "postflight_evidence_refs_unique"

    def test_check_staleness_uses_the_injected_clock(self) -> None:
        check = passing_check("leases_held", ttl=60.0)
        assert not check.is_stale(now=MOMENT)
        assert not check.is_stale(now=MOMENT + timedelta(seconds=59))
        assert check.is_stale(now=MOMENT + timedelta(seconds=60))

    def test_check_refuses_a_naive_clock(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            passing_check("leases_held").is_stale(now=naive_moment())
        assert excinfo.value.rule == "postflight_now_aware"

    def test_check_refuses_a_naive_observation(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            PostflightCheck(
                name="leases_held",
                status=CheckStatus.PASS,
                evidence_refs=("residue/1",),
                observed_at=naive_moment(),
            )
        assert excinfo.value.rule == "postflight_observed_at_aware"


# --- domain law ----------------------------------------------------------------


def test_domain_module_imports_nothing_forbidden() -> None:
    """The layering contract, asserted locally so it fails with this file."""
    source = Path(inspect.getfile(stop)).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert not (imported & FORBIDDEN_IMPORTS), f"forbidden imports: {imported & FORBIDDEN_IMPORTS}"


def test_domain_module_does_not_redefine_the_cancellation_scale() -> None:
    """The ladder extends cancellation.py; it must not fork a second ladder."""
    source = Path(inspect.getfile(stop)).read_text(encoding="utf-8")
    assert "class CancellationLevel" not in source
    assert "class CancellationToken" not in source
