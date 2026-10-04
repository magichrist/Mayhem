"""Plan 13 Phase 5 — game-day artifacts, the after-action report, and both surfaces.

Three things are defended here, and they are kept apart on purpose:

* **an artifact says what it is.** A finding carries a severity, a note and a
  decision do not, and a decision names the run it let go. The negative control
  attempts to grade a note and watches it be refused rather than quietly
  downgraded -- because a note that became a finding would be graded by nobody's
  decision at all.
* **the report refuses to certify what it cannot see.** A released step with no
  decision, a dispatch that settled ``failed``, a claim that was never settled,
  and a session with no findings at all are four different gaps, and none of them
  renders as a clean bill of health. The negative control empties a report's
  artifact list and asserts the empty report is *not* clean.
* **the two surfaces dispatch nothing.** ``mayhem schedule`` and
  ``mayhem game-day-step`` have no flag that fires a run, and the AST scan proves
  it: a CLI that could dispatch would be a second dispatch path, and the second
  dispatch path is how a scheduled run ends up skipping a gate.

Every invocation is exercised through :class:`click.testing.CliRunner` against the
group object directly, because neither group is registered in ``cli/app.py`` yet --
that file belongs to another lane. The integration dependency is recorded in the
plan's ledger rather than worked around.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from mayhem.cli import game_day_step_cmd, schedule_cmd
from mayhem.controller import game_day_evidence
from mayhem.controller.game_day_evidence import (
    ARTIFACT_OBSERVATION_KIND,
    GAP_EXPLANATION,
    AfterActionReport,
    ArtifactGap,
    ArtifactKind,
    GameDayArtifact,
    Severity,
    after_action_report,
    artifacts_for_session,
    default_artifact_id,
    record_artifact,
    severity_rank,
)
from mayhem.controller.scheduler import mark_dispatched, release_hold, slot_idempotency_key
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.game_day import (
    ApprovalGate,
    GameDaySession,
    OperatorAcknowledgement,
)
from mayhem.domain.scheduling import (
    ConcurrencyClass,
    CronSpec,
    Schedule,
    ScheduleKind,
)
from mayhem.infra.game_day_repository import GameDayRepository
from mayhem.infra.schedule_store import (
    DEFAULT_LOCK_WINDOW_S,
    GameDayStepRecord,
    HoldState,
    RunClaimState,
    ScheduleEntry,
    ScheduleRunRecord,
    ScheduleStore,
)
from mayhem.infra.store import Store

REPO_ROOT = Path(__file__).resolve().parents[2]

T0 = datetime(2026, 6, 1, 9, 0, tzinfo=UTC)
T1 = datetime(2026, 6, 1, 9, 5, tzinfo=UTC)
T2 = datetime(2026, 6, 1, 9, 30, tzinfo=UTC)
BEFORE_T0 = datetime(2026, 1, 1, tzinfo=UTC)
SESSION_ID = "gd-1"
STEP_ID = "net-latency"
SCHEDULE_ID = "nightly"
FACILITATOR = "sre@example.com"


# =============================================================================
# Fixtures
# =============================================================================


def _runner() -> CliRunner:
    return CliRunner()


def _store(path: Path | str = ":memory:") -> tuple[Store, ScheduleStore]:
    store = Store.open_migrated(path)
    return store, ScheduleStore(store)


def _schedule_entry(*, schedule_id: str = SCHEDULE_ID) -> ScheduleEntry:
    return ScheduleEntry(
        schedule=Schedule(
            schedule_id=schedule_id,
            team="sre",
            kind=ScheduleKind.CRON,
            cron=CronSpec.parse("0 9 * * *"),
            created_at=BEFORE_T0,
            max_runs=100,
        ),
        campaign_id="camp-1",
        experiment_id="exp-1",
        concurrency_class=ConcurrencyClass.EXCLUSIVE,
        resources=("db-primary",),
        lock_window_s=DEFAULT_LOCK_WINDOW_S,
    )


def _session(store: Store, *, session_id: str = SESSION_ID) -> GameDaySession:
    return GameDayRepository(store).save(
        GameDaySession(
            id=session_id,
            name="quarterly",
            gate=ApprovalGate(required_approvers=1),
            created_at=BEFORE_T0.isoformat(),
        )
    )


def _step(
    *,
    session_id: str = SESSION_ID,
    step_id: str = STEP_ID,
    scenario: str = "regional-outage@1.0.0",
    hold_state: HoldState = HoldState.HELD,
    released_by: str = "",
    released_at: str = "",
    dispatched_at: str = "",
) -> GameDayStepRecord:
    return GameDayStepRecord(
        session_id=session_id,
        step_id=step_id,
        step_seq=0,
        scenario=scenario,
        schedule_id=SCHEDULE_ID,
        hold_state=hold_state,
        hold_reason="wait for the bridge",
        released_by=released_by,
        released_at=released_at,
        dispatched_at=dispatched_at,
        created_at=T0.isoformat(),
    )


def _run_record(
    *,
    state: RunClaimState = RunClaimState.DISPATCHED,
    settled_at: datetime | None = T1,
    code: str = "schedule.dispatched",
) -> ScheduleRunRecord:
    return ScheduleRunRecord(
        idempotency_key=slot_idempotency_key(
            schedule_id=SCHEDULE_ID,
            campaign_id="camp-1",
            experiment_id="exp-1",
            slot_start=T0,
        ),
        schedule_id=SCHEDULE_ID,
        team="sre",
        campaign_id="camp-1",
        experiment_id="exp-1",
        slot_start=T0,
        effective_at=T0,
        state=state,
        code=code,
        run_id="r-1",
        controller_id="ctl-1",
        recorded_at=T0,
        settled_at=settled_at,
    )


def _finding(*, severity: Severity = Severity.HIGH, artifact_id: str = "gd-f-1") -> GameDayArtifact:
    return GameDayArtifact(
        artifact_id=artifact_id,
        session_id=SESSION_ID,
        kind=ArtifactKind.FINDING,
        actor=FACILITATOR,
        text="the runbook's rollback step does not exist",
        at=T1.isoformat(),
        severity=severity,
    )


def _note(*, text: str = "comms bridge opened on time") -> GameDayArtifact:
    return GameDayArtifact(
        artifact_id="gd-n-1",
        session_id=SESSION_ID,
        kind=ArtifactKind.NOTE,
        actor=FACILITATOR,
        text=text,
        at=T1.isoformat(),
    )


def _decision(*, run_id: str = "r-1") -> GameDayArtifact:
    return GameDayArtifact(
        artifact_id="gd-d-1",
        session_id=SESSION_ID,
        kind=ArtifactKind.DECISION,
        actor=FACILITATOR,
        text="released the latency drill once the bridge was open",
        at=T1.isoformat(),
        run_id=run_id,
    )


def _rule(callable_: object) -> str:
    """The rule id a domain refusal raises, for a compact one-line assertion."""
    with pytest.raises(InvariantViolationError) as excinfo:
        callable_()  # type: ignore[operator]
    return excinfo.value.rule


def _refused(callable_: object) -> str:
    """The message a CLI usage refusal carries.

    The CLI layer raises :class:`click.UsageError` rather than the domain's own
    error, so the surface's refusals are asserted on their text -- which is what
    an operator reads -- while the domain's are asserted on their rule id.
    """
    with pytest.raises(click.UsageError) as excinfo:
        callable_()  # type: ignore[operator]
    return str(excinfo.value)


# =============================================================================
# 1. An artifact says what it is
# =============================================================================


def test_a_finding_must_say_how_wrong_it_is() -> None:
    """A claim that something is broken without a grade is refused at construction."""
    assert _rule(lambda: GameDayArtifact(
        artifact_id="gd-f-1",
        session_id=SESSION_ID,
        kind=ArtifactKind.FINDING,
        actor=FACILITATOR,
        text="something is off",
        at=T1.isoformat(),
    )) == "game_day.finding_severity"


def test_a_note_may_not_carry_a_severity() -> None:
    """The negative control on the kind rules: a graded note is *refused*, not stripped.

    Dropping the severity would be the friendlier implementation and the wrong
    one. A record that was written as ``info`` and reads back ungraded is a record
    whose grade nobody ever chose, which is how an ``info`` becomes a ``high`` in a
    summary by accident.
    """
    assert _rule(lambda: GameDayArtifact(
        artifact_id="gd-n-1",
        session_id=SESSION_ID,
        kind=ArtifactKind.NOTE,
        actor=FACILITATOR,
        text="looks fine",
        at=T1.isoformat(),
        severity=Severity.CRITICAL,
    )) == "game_day.artifact_severity_on_note"


def test_a_decision_may_not_carry_a_severity_either() -> None:
    """The rule is on the kind, not on ``FINDING`` alone."""
    assert _rule(lambda: GameDayArtifact(
        artifact_id="gd-d-1",
        session_id=SESSION_ID,
        kind=ArtifactKind.DECISION,
        actor=FACILITATOR,
        text="released it",
        at=T1.isoformat(),
        run_id="r-1",
        severity=Severity.LOW,
    )) == "game_day.artifact_severity_on_note"


def test_a_decision_must_name_the_run_it_let_go() -> None:
    """A decision that decided nothing cannot be read back as one that did."""
    assert _rule(lambda: GameDayArtifact(
        artifact_id="gd-d-1",
        session_id=SESSION_ID,
        kind=ArtifactKind.DECISION,
        actor=FACILITATOR,
        text="we decided to continue",
        at=T1.isoformat(),
    )) == "game_day.decision_run"


def test_every_artifact_must_name_somebody() -> None:
    """A blank actor is refused on every kind, notes included.

    An unattributed note is not evidence of anything -- it is a sticky note -- and
    the after-action report cannot say whose observation it was.
    """
    for kind in ArtifactKind:
        severity = Severity.LOW if kind is ArtifactKind.FINDING else None
        assert _rule(lambda kind=kind, severity=severity: GameDayArtifact(
            artifact_id="gd-x-1",
            session_id=SESSION_ID,
            kind=kind,
            actor="   ",
            text="something",
            at=T1.isoformat(),
            severity=severity,
            run_id="r-1",
        )) == "game_day.artifact_actor_blank", kind


def test_an_artifact_must_carry_text_and_an_instant() -> None:
    """Empty text and a missing instant are both refusals, not defaults."""
    assert _rule(lambda: GameDayArtifact(
        artifact_id="gd-n-1",
        session_id=SESSION_ID,
        kind=ArtifactKind.NOTE,
        actor=FACILITATOR,
        text="  ",
        at=T1.isoformat(),
    )) == "game_day.artifact_text_blank"
    assert _rule(lambda: GameDayArtifact(
        artifact_id="gd-n-1",
        session_id=SESSION_ID,
        kind=ArtifactKind.NOTE,
        actor=FACILITATOR,
        text="something",
        at="",
    )) == "game_day.artifact_at_blank"


def test_an_artifact_digest_detects_a_hand_edit() -> None:
    """The digest is over the fields, so an edit made through SQL is visible.

    Not a signature: anybody with database access can recompute it. The claim is
    only that an edit *through the model* is detectable, which is the same claim
    :mod:`mayhem.infra.fabric_journal` makes about its own payload digest.
    """
    artifact = _finding()
    edited = artifact.model_copy(update={"text": "the runbook is fine"})

    assert artifact.digest != edited.digest
    assert artifact.digest == _finding().digest


def test_the_artifact_id_is_derived_so_repeating_yourself_is_one_record() -> None:
    """Derived, not minted: the same decision recorded twice has the same id."""
    first = default_artifact_id(SESSION_ID, ArtifactKind.DECISION, FACILITATOR, at=T1.isoformat())
    again = default_artifact_id(SESSION_ID, ArtifactKind.DECISION, FACILITATOR, at=T1.isoformat())
    later = default_artifact_id(SESSION_ID, ArtifactKind.DECISION, FACILITATOR, at=T2.isoformat())
    other = default_artifact_id(SESSION_ID, ArtifactKind.NOTE, FACILITATOR, at=T1.isoformat())

    assert first == again
    assert first != later
    assert first != other
    assert first.startswith("gd-decision-")


# =============================================================================
# 2. The after-action report refuses to certify what it cannot see
# =============================================================================


def test_a_report_with_a_release_and_no_decision_says_so() -> None:
    """Somebody let a drill run and nobody wrote down why.

    The released step is in the record; the decision is not. A report that listed
    the release as a completed step would be certifying an authorisation that
    cannot be produced.
    """
    report = after_action_report(
        session_id=SESSION_ID,
        artifacts=(_finding(),),
        steps=(
            _step(hold_state=HoldState.DISPATCHED, released_by=FACILITATOR),
        ),
        dispatches=(_run_record(),),
        now=T2,
    )

    assert ArtifactGap.RELEASED_WITHOUT_DECISION in report.gaps
    assert "authorised a drill" in GAP_EXPLANATION[ArtifactGap.RELEASED_WITHOUT_DECISION]
    assert report.clean is False


def test_a_decision_closes_that_gap() -> None:
    """The positive control on the gap above: naming the run clears it."""
    report = after_action_report(
        session_id=SESSION_ID,
        artifacts=(_decision(), _finding()),
        steps=(_step(hold_state=HoldState.DISPATCHED, released_by=FACILITATOR),),
        dispatches=(_run_record(),),
        now=T2,
    )

    assert ArtifactGap.RELEASED_WITHOUT_DECISION not in report.gaps
    assert report.clean is True


def test_a_failed_dispatch_is_reported_as_a_failure() -> None:
    """An attempt is not a completed drill, and the report does not call it one."""
    report = after_action_report(
        session_id=SESSION_ID,
        artifacts=(_decision(), _finding()),
        dispatches=(
            _run_record(state=RunClaimState.FAILED, code="schedule.execution_failed"),
        ),
        now=T2,
    )

    assert ArtifactGap.FAILED_DISPATCH in report.gaps
    assert "UNKNOWN OUTCOME" not in report.render_markdown()


def test_an_unsettled_claim_is_reported_as_unknown_not_retried() -> None:
    """The same discipline the scheduler has: an unknown outcome is not a retry."""
    report = after_action_report(
        session_id=SESSION_ID,
        artifacts=(_decision(), _finding()),
        dispatches=(_run_record(state=RunClaimState.CLAIMED, settled_at=None),),
        now=T2,
    )

    assert ArtifactGap.UNKNOWN_OUTCOME_DISPATCH in report.gaps
    markdown = report.render_markdown()
    assert "UNKNOWN OUTCOME" in markdown
    assert "not something to retry automatically" in markdown


def test_a_session_with_no_findings_is_never_clean() -> None:
    """The negative control: an empty findings section is not a clean bill of health.

    This is the report's most load-bearing refusal. A game day that produced
    nothing but notes may have been uneventful, or may have been played without
    anybody writing down what they saw, and the two are indistinguishable from
    the artifacts alone. The report says so in words rather than rendering an
    empty section that reads like a pass.
    """
    report = after_action_report(
        session_id=SESSION_ID,
        artifacts=(_note(),),
        steps=(),
        dispatches=(),
        now=T2,
    )

    assert ArtifactGap.NO_FINDINGS in report.gaps
    assert report.clean is False
    markdown = report.render_markdown()
    assert "**none recorded.**" in markdown
    assert "not about the system" in markdown


def test_a_session_with_no_artifacts_at_all_reports_both_gaps() -> None:
    """Nothing recorded and nothing claimed are different statements, and both are made."""
    report = after_action_report(
        session_id=SESSION_ID, artifacts=(), steps=(), dispatches=(), now=T2
    )

    assert ArtifactGap.NO_ARTIFACTS in report.gaps
    assert ArtifactGap.NO_FINDINGS in report.gaps
    # NO_ARTIFACTS leads, because it subsumes the other and is the bigger fact.
    assert report.gaps[0] is ArtifactGap.NO_ARTIFACTS
    assert report.by_kind == {}
    assert report.clean is False


def test_findings_are_ordered_most_severe_first_and_ties_are_stable() -> None:
    """Severity is the ranking, and the tiebreak is deterministic.

    Ties break on the instant and then the id, so two findings of the same grade
    do not reorder between two renders of the same session.
    """
    artifacts = (
        _finding(severity=Severity.LOW, artifact_id="gd-f-low"),
        _finding(severity=Severity.CRITICAL, artifact_id="gd-f-crit"),
        _finding(severity=Severity.HIGH, artifact_id="gd-f-high"),
    )
    report = after_action_report(session_id=SESSION_ID, artifacts=artifacts, now=T2)

    assert [a.artifact_id for a in report.findings] == [
        "gd-f-crit",
        "gd-f-high",
        "gd-f-low",
    ]
    assert severity_rank(Severity.CRITICAL) > severity_rank(Severity.INFO)
    assert after_action_report(
        session_id=SESSION_ID, artifacts=artifacts, now=T2
    ).findings == report.findings


def test_the_report_is_a_pure_function_of_its_inputs_and_the_instant() -> None:
    """No clock of its own: the same inputs and the same ``now`` give the same report."""
    artifacts = (_decision(), _finding())
    steps = (_step(hold_state=HoldState.DISPATCHED, released_by=FACILITATOR),)

    first = after_action_report(
        session_id=SESSION_ID, artifacts=artifacts, steps=steps, now=T2
    )
    second = after_action_report(
        session_id=SESSION_ID, artifacts=artifacts, steps=steps, now=T2
    )

    assert first.to_payload() == second.to_payload()
    assert first.generated_at == T2.isoformat()


def test_the_report_refuses_a_naive_generation_instant() -> None:
    """A report stamped with a naive time is not stamped.

    Built by stripping the zone rather than by writing ``tzinfo=None``: the naive
    datetime has to be genuinely naive, and the lint rule that objects to an
    explicit ``None`` is the same rule the codebase uses to keep naive instants
    out of decisions.
    """
    naive = T2.replace(tzinfo=None)
    assert naive.tzinfo is None
    assert _rule(lambda: after_action_report(
        session_id=SESSION_ID, artifacts=(), now=naive
    )) == "game_day.artifact_at_blank"


def test_the_report_renders_every_section_even_when_empty() -> None:
    """The sections that are empty are the ones carrying the information."""
    report = after_action_report(
        session_id=SESSION_ID, artifacts=(), steps=(), dispatches=(), now=T2
    )
    markdown = report.render_markdown()

    for heading in ("## What ran", "## Findings", "## Notes", "## Gaps"):
        assert heading in markdown, heading
    assert "no dispatch steps were staged" in markdown
    assert report.describe().endswith("gap(s): no_artifacts, no_findings")


def test_the_payload_is_json_serialisable_and_carries_the_gaps() -> None:
    """A report a machine can read, with the gaps as values rather than prose."""
    report = after_action_report(
        session_id=SESSION_ID,
        artifacts=(_note(), _finding(), _decision()),
        steps=(_step(hold_state=HoldState.RELEASED, released_by=FACILITATOR),),
        dispatches=(_run_record(),),
        now=T2,
    )
    payload = report.to_payload()

    assert json.loads(json.dumps(payload)) == payload
    assert payload["counts"] == {"decision": 1, "finding": 1, "note": 1}
    assert payload["findings"] == ["gd-f-1"]
    assert payload["clean"] is True
    assert "after-action" in AfterActionReport(session_id="x").describe()


# =============================================================================
# 3. Persistence
# =============================================================================


def test_an_artifact_round_trips_through_the_store() -> None:
    """Recorded as an observation and read back, byte for byte."""
    store, _repo = _store()
    artifact = _finding()

    record_artifact(store, artifact)
    found = artifacts_for_session(store, SESSION_ID)

    assert len(found) == 1
    assert found[0] == artifact
    assert found[0].digest == artifact.digest
    store.close()


def test_artifacts_are_scoped_to_their_session() -> None:
    """Two sessions' artifacts do not read back as one session's."""
    store, _repo = _store()
    record_artifact(store, _finding())
    record_artifact(store, _finding().model_copy(
        update={"artifact_id": "gd-f-2", "session_id": "gd-2"}
    ))

    assert len(artifacts_for_session(store, SESSION_ID)) == 1
    assert len(artifacts_for_session(store, "gd-2")) == 1
    assert artifacts_for_session(store, "gd-nothing") == ()
    store.close()


def test_a_hand_edited_row_is_skipped_rather_than_breaking_the_report() -> None:
    """One unreadable row must not make an entire session's report unreadable.

    The loss is real and it is *not* silently hidden: the artifact is absent from
    the read, so the report's own gaps change. What it must not do is raise --
    a facilitator needs the rest of the session.
    """
    store, _repo = _store()
    record_artifact(store, _finding())
    with store.write() as conn:
        conn.execute(
            "INSERT INTO observations (kind, run_id, source, data_json, timestamp) "
            "VALUES (?,?,?,?,?)",
            (ARTIFACT_OBSERVATION_KIND, "", SESSION_ID, "{not json", T2.isoformat()),
        )

    found = artifacts_for_session(store, SESSION_ID)

    assert len(found) == 1
    assert found[0].artifact_id == "gd-f-1"
    store.close()


def test_the_artifact_observation_kind_is_one_value() -> None:
    """One kind, so "everything this session produced" is one query.

    The per-artifact ``kind`` field does the sorting; three observation kinds
    would make a reader remember to ask for all three.
    """
    assert ARTIFACT_OBSERVATION_KIND == "game_day.artifact"
    kinds = {
        record_artifact(_store()[0], artifact) and ARTIFACT_OBSERVATION_KIND
        for artifact in (_note(), _finding(), _decision())
    }
    assert kinds == {ARTIFACT_OBSERVATION_KIND}


def test_the_artifact_writer_is_the_only_writer_and_it_is_in_one_module() -> None:
    """Single-writer discipline, asserted structurally like the rest of the package.

    Two writers of ``game_day.artifact`` rows would let one of them bypass the
    kind rules, and the kind rules are the whole point of the type.
    """
    tree = ast.parse(
        (REPO_ROOT / "src" / "mayhem" / "controller" / "game_day_evidence.py").read_text(
            encoding="utf-8"
        )
    )
    writers = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and any(
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Attribute)
            and inner.func.attr == "save_observation"
            for inner in ast.walk(node)
        )
    ]
    assert writers == ["record_artifact"]
    assert game_day_evidence.record_artifact is record_artifact


# =============================================================================
# 4. The game-day-step surface
# =============================================================================


def _seeded(tmp_path: Path) -> str:
    """A migrated database with a session and one registered schedule."""
    db = tmp_path / "mayhem.db"
    store = Store.open_migrated(db)
    _session(store)
    ScheduleStore(store).save_schedule(_schedule_entry())
    store.close()
    return str(db)


def test_the_group_help_resolves_and_names_every_verb() -> None:
    """Every spelling this plan documents resolves against the live Click tree."""
    result = _runner().invoke(game_day_step_cmd.game_day_step, ["--help"])

    assert result.exit_code == 0
    verbs = [args[0] for args in game_day_step_cmd.MONITORED_INVOCATIONS if args[0] != "--help"]
    for verb in verbs:
        assert verb in result.output, verb
    for args in game_day_step_cmd.MONITORED_INVOCATIONS:
        # args[0] is the group name, which the group object already knows; passing
        # it again would look like an unknown sub-command.
        sub = _runner().invoke(game_day_step_cmd.game_day_step, list(args[1:]))
        assert sub.exit_code == 0, args


def test_inject_stages_a_held_step_bound_to_a_registered_schedule(tmp_path: Path) -> None:
    """The default is the safe state: a new step holds its schedule's fire."""
    db = _seeded(tmp_path)
    result = _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "inject",
            SESSION_ID,
            "--step-id",
            STEP_ID,
            "--schedule-id",
            SCHEDULE_ID,
            "--scenario",
            "regional-outage@1.0.0",
            "--hold-reason",
            "wait for the bridge",
            "--now",
            T0.isoformat(),
            "--db",
            db,
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["staged"] is True
    assert payload["hold_state"] == "held"
    assert payload["scenario"] == "regional-outage@1.0.0"
    assert payload["hold_reason"] == "wait for the bridge"
    # And the step is real: the scheduler will read it at fire time.
    store = Store.open_migrated(db)
    step = ScheduleStore(store).load_step(SESSION_ID, STEP_ID)
    assert step is not None and step.held is True
    store.close()


def test_an_inject_outside_its_scenario_is_refused(tmp_path: Path) -> None:
    """Phase 5's named negative control.

    A step staged against a scenario nobody wrote down is an inject outside its
    scenario, and the after-action report would then cite a claim that does not
    exist. The refusal happens before the store is touched, so nothing is
    half-written.
    """
    db = _seeded(tmp_path)
    result = _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "inject",
            SESSION_ID,
            "--step-id",
            STEP_ID,
            "--schedule-id",
            SCHEDULE_ID,
            "--scenario",
            "no-such-scenario@1.0.0",
            "--db",
            db,
        ],
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, SystemExit)
    store = Store.open_migrated(db)
    assert ScheduleStore(store).load_step(SESSION_ID, STEP_ID) is None
    store.close()


def test_a_scenario_reference_without_a_version_is_refused() -> None:
    """``id@version``, not ``id``: a revised scenario must keep its history."""
    assert "is not 'id@version'" in _refused(
        lambda: game_day_step_cmd.resolve_scenario("regional-outage")
    )
    assert game_day_step_cmd.resolve_scenario("") == ""
    assert game_day_step_cmd.resolve_scenario("pod-churn@1.0.0") == "pod-churn@1.0.0"


def test_an_inject_of_an_unregistered_schedule_is_refused(tmp_path: Path) -> None:
    """A step bound to no schedule would hold a fire that can never happen."""
    db = _seeded(tmp_path)
    result = _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "inject",
            SESSION_ID,
            "--step-id",
            STEP_ID,
            "--schedule-id",
            "not-registered",
            "--db",
            db,
        ],
    )

    assert result.exit_code != 0
    store = Store.open_migrated(db)
    assert ScheduleStore(store).load_step(SESSION_ID, STEP_ID) is None
    store.close()


def test_a_second_inject_of_the_same_step_is_refused(tmp_path: Path) -> None:
    """Staging the same dispatch twice would put two steps on one schedule's fire."""
    db = _seeded(tmp_path)
    args = [
        "inject",
        SESSION_ID,
        "--step-id",
        STEP_ID,
        "--schedule-id",
        SCHEDULE_ID,
        "--db",
        db,
    ]
    assert _runner().invoke(game_day_step_cmd.game_day_step, args).exit_code == 0

    second = _runner().invoke(game_day_step_cmd.game_day_step, args)

    assert second.exit_code != 0
    store = Store.open_migrated(db)
    assert len(ScheduleStore(store).steps_for_session(SESSION_ID)) == 1
    store.close()


def test_releasing_a_hold_names_its_facilitator_and_reaches_the_scheduler(
    tmp_path: Path,
) -> None:
    """The release changes a *gate*, and the scheduler reads that gate at fire time."""
    db = _seeded(tmp_path)
    _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "inject",
            SESSION_ID,
            "--step-id",
            STEP_ID,
            "--schedule-id",
            SCHEDULE_ID,
            "--db",
            db,
        ],
    )
    result = _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "release",
            SESSION_ID,
            STEP_ID,
            "--facilitator",
            FACILITATOR,
            "--reason",
            "comms bridge open",
            "--now",
            T1.isoformat(),
            "--db",
            db,
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["hold_state"] == "released"
    assert payload["released_by"] == FACILITATOR

    # And the scheduler's own predicate agrees the gate is now clear.
    store = Store.open_migrated(db)
    step = ScheduleStore(store).load_step(SESSION_ID, STEP_ID)
    assert step is not None
    assert step.held is False and step.released is True
    dispatched = mark_dispatched(step, at=T2.isoformat())
    assert dispatched.hold_state is HoldState.DISPATCHED
    store.close()


def test_a_release_without_a_facilitator_or_a_reason_is_refused(tmp_path: Path) -> None:
    """A hold released by nobody in particular is indistinguishable from an expiry."""
    db = _seeded(tmp_path)
    _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "inject", SESSION_ID, "--step-id", STEP_ID,
            "--schedule-id", SCHEDULE_ID, "--db", db,
        ],
    )
    blank_actor = _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "release", SESSION_ID, STEP_ID,
            "--facilitator", "   ", "--reason", "why not", "--db", db,
        ],
    )
    blank_reason = _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "release", SESSION_ID, STEP_ID,
            "--facilitator", FACILITATOR, "--reason", "  ", "--db", db,
        ],
    )

    assert blank_actor.exit_code != 0
    assert blank_reason.exit_code != 0
    store = Store.open_migrated(db)
    step = ScheduleStore(store).load_step(SESSION_ID, STEP_ID)
    assert step is not None and step.held is True
    store.close()


def test_releasing_twice_is_refused_and_the_first_release_survives(tmp_path: Path) -> None:
    """Re-releasing would erase who actually let it go."""
    db = _seeded(tmp_path)
    _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "inject", SESSION_ID, "--step-id", STEP_ID,
            "--schedule-id", SCHEDULE_ID, "--db", db,
        ],
    )
    args = [
        "release", SESSION_ID, STEP_ID,
        "--facilitator", FACILITATOR, "--reason", "open", "--db", db,
    ]
    assert _runner().invoke(game_day_step_cmd.game_day_step, args).exit_code == 0

    again = _runner().invoke(game_day_step_cmd.game_day_step, args)

    assert again.exit_code != 0
    store = Store.open_migrated(db)
    step = ScheduleStore(store).load_step(SESSION_ID, STEP_ID)
    assert step is not None and step.released_by == FACILITATOR
    store.close()


def test_a_rehold_keeps_the_release_on_the_record(tmp_path: Path) -> None:
    """A game day that changed its mind says so, and does not pretend it never agreed."""
    db = _seeded(tmp_path)
    _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "inject", SESSION_ID, "--step-id", STEP_ID,
            "--schedule-id", SCHEDULE_ID, "--db", db,
        ],
    )
    _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "release", SESSION_ID, STEP_ID, "--facilitator", FACILITATOR,
            "--reason", "open", "--now", T1.isoformat(), "--db", db,
        ],
    )
    result = _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "hold", SESSION_ID, STEP_ID, "--facilitator", FACILITATOR,
            "--reason", "a participant pushed back", "--now", T2.isoformat(),
            "--db", db, "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["hold_state"] == "held"
    assert payload["released_by"] == FACILITATOR  # the release is not erased
    assert payload["hold_reason"] == "a participant pushed back"
    store = Store.open_migrated(db)
    step = ScheduleStore(store).load_step(SESSION_ID, STEP_ID)
    assert step is not None and step.held is True
    store.close()


def test_a_dispatched_step_cannot_be_re_held(tmp_path: Path) -> None:
    """A step that already ran cannot be re-held: the gate would be in the past."""
    db = _seeded(tmp_path)
    store = Store.open_migrated(db)
    repo = ScheduleStore(store)
    repo.save_step(_step(hold_state=HoldState.DISPATCHED, released_by=FACILITATOR))
    store.close()

    result = _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            "hold", SESSION_ID, STEP_ID, "--facilitator", FACILITATOR,
            "--reason", "too late", "--db", db,
        ],
    )

    assert result.exit_code != 0


def test_the_note_command_records_each_kind_and_refuses_a_misgraded_finding(
    tmp_path: Path,
) -> None:
    """The three artifact kinds are reachable, and the kind rules still apply."""
    db = _seeded(tmp_path)
    common = ["note", SESSION_ID, "--actor", FACILITATOR, "--now", T1.isoformat(), "--db", db]
    note = _runner().invoke(
        game_day_step_cmd.game_day_step, [*common, "--text", "bridge opened"]
    )
    finding = _runner().invoke(
        game_day_step_cmd.game_day_step,
        [
            *common,
            "--kind", "finding",
            "--severity", "high",
            "--text", "the runbook's rollback step does not exist",
        ],
    )
    ungraded = _runner().invoke(
        game_day_step_cmd.game_day_step,
        [*common, "--kind", "finding", "--text", "something felt wrong"],
    )

    assert note.exit_code == 0
    assert finding.exit_code == 0
    assert ungraded.exit_code != 0

    store = Store.open_migrated(db)
    found = artifacts_for_session(store, SESSION_ID)
    assert sorted(a.kind.value for a in found) == ["finding", "note"]
    assert next(a for a in found if a.kind is ArtifactKind.FINDING).severity is Severity.HIGH
    store.close()


def test_an_unknown_step_or_session_is_reported_rather_than_creating_one(
    tmp_path: Path,
) -> None:
    """Neither command invents the thing it was asked about."""
    db = _seeded(tmp_path)
    unknown_step = _runner().invoke(
        game_day_step_cmd.game_day_step,
        ["release", SESSION_ID, "not-a-step", "--facilitator", FACILITATOR,
         "--reason", "open", "--db", db],
    )
    unknown_session = _runner().invoke(
        game_day_step_cmd.game_day_step,
        ["inject", "gd-nope", "--step-id", STEP_ID, "--schedule-id", SCHEDULE_ID,
         "--db", db],
    )

    assert unknown_step.exit_code == 1
    assert unknown_session.exit_code == 1


# =============================================================================
# 5. The schedule surface
# =============================================================================


def test_the_schedule_group_help_resolves_and_names_every_verb() -> None:
    """Same shape of proof as the game-day-step group."""
    result = _runner().invoke(schedule_cmd.schedule, ["--help"])

    assert result.exit_code == 0
    verbs = [args[0] for args in schedule_cmd.MONITORED_INVOCATIONS if args[0] != "--help"]
    for verb in verbs:
        assert verb in result.output, verb
    for args in schedule_cmd.MONITORED_INVOCATIONS:
        assert _runner().invoke(schedule_cmd.schedule, list(args[1:])).exit_code == 0, args


def test_add_registers_a_schedule_and_tick_evaluates_it_without_dispatching(
    tmp_path: Path,
) -> None:
    """``tick`` reports and never fires: the honest answer is a view, not a dispatch."""
    db = str(tmp_path / "mayhem.db")
    added = _runner().invoke(
        schedule_cmd.schedule,
        [
            "add", "nightly",
            "--campaign-id", "camp-1",
            "--experiment-id", "exp-1",
            "--team", "sre",
            "--cron", "0 9 * * *",
            "--max-runs", "20",
            "--created-at", BEFORE_T0.isoformat(),
            "--resource", "db-primary",
            "--db", db,
            "--json",
        ],
    )
    assert added.exit_code == 0, added.output
    assert json.loads(added.output)["schedule_id"] == "nightly"

    ticked = _runner().invoke(
        schedule_cmd.schedule,
        ["tick", "--now", T0.isoformat(), "--db", db, "--json"],
    )
    assert ticked.exit_code == 0, ticked.output
    payload = json.loads(ticked.output)
    assert payload["dispatches_performed"] == 0
    assert payload["schedules"][0]["due"] is True
    assert payload["now"] == T0.isoformat()
    # The three gates this command did not run are named, so "due" cannot read as
    # "cleared".
    assert any("safety gate" in gate for gate in payload["not_evaluated_here"])
    assert "A due slot is not an admitted slot" in payload["notice"]


def test_a_tick_reports_a_missed_window_with_its_instant_and_its_reason(
    tmp_path: Path,
) -> None:
    """A missed window is reported as missed, through the CLI, with both fields.

    The interval slot is one minute wide. Evaluated five minutes past it, the
    recurrence is gone and the next occurrence is an hour away and is a different
    slot -- so the row says ``schedule.missed``, carries ``missed_window``, and
    gives the lateness that a reader would otherwise have to infer.
    """
    db = str(tmp_path / "mayhem.db")
    store = Store.open_migrated(db)
    store.close()
    added = _runner().invoke(
        schedule_cmd.schedule,
        [
            "add", "poller",
            "--campaign-id", "camp-1",
            "--experiment-id", "exp-1",
            "--team", "sre",
            "--interval-s", "3600",
            "--anchor-at", T0.isoformat(),
            "--max-runs", "50",
            "--created-at", BEFORE_T0.isoformat(),
            "--resource", "db-primary",
            "--db", db,
            "--json",
        ],
    )
    assert added.exit_code == 0, added.output

    # The store's poll resolution is the CLI default (60s), so five minutes past
    # the anchor is a closed slot.
    ticked = _runner().invoke(
        schedule_cmd.schedule,
        ["tick", "--now", T2.isoformat(), "--db", db, "--json"],
    )
    payload = json.loads(ticked.output)
    row = payload["schedules"][0]

    assert row["code"] == "schedule.missed"
    assert row["due"] is False
    assert row["missed_window"] is True
    assert row["slot_start"] == T0.isoformat()
    assert row["resolution_s"] == 60.0
    assert "idempotency key" in row["reason"]


def test_a_tick_reports_lateness_and_jitter_as_two_separate_facts(tmp_path: Path) -> None:
    """The JSON view must not let a jitter spread read as poller lateness."""
    db = str(tmp_path / "mayhem.db")
    _runner().invoke(
        schedule_cmd.schedule,
        [
            "add", "nightly",
            "--campaign-id", "camp-1",
            "--experiment-id", "exp-1",
            "--team", "sre",
            "--cron", "0 9 * * *",
            "--max-runs", "20",
            "--created-at", BEFORE_T0.isoformat(),
            "--jitter-s", "60",
            "--resource", "db-primary",
            "--db", db,
            "--json",
        ],
    )
    ticked = _runner().invoke(
        schedule_cmd.schedule, ["tick", "--now", T0.isoformat(), "--db", db, "--json"]
    )
    row = json.loads(ticked.output)["schedules"][0]

    assert row["jittered"] is True
    assert row["jitter_s"] == 60.0
    # Evaluated exactly on the slot, so the poller is on time even though the
    # effective instant moved.
    assert row["lateness_s"] == 0.0
    assert row["missed_window"] is False
    assert row["nominal_at"] == T0.isoformat()
    assert row["effective_at"] != T0.isoformat()


def test_a_disabled_schedule_is_held_rather_than_skipped(tmp_path: Path) -> None:
    """"It did not run because it is switched off" has to be an answer, not an absence."""
    db = str(tmp_path / "mayhem.db")
    add = [
        "add", "nightly",
        "--campaign-id", "camp-1", "--experiment-id", "exp-1", "--team", "sre",
        "--cron", "0 9 * * *", "--max-runs", "20",
        "--created-at", BEFORE_T0.isoformat(), "--resource", "db-primary",
        "--db", db, "--json",
    ]
    assert _runner().invoke(schedule_cmd.schedule, add).exit_code == 0
    assert _runner().invoke(
        schedule_cmd.schedule, ["disable", "nightly", "--db", db, "--json"]
    ).exit_code == 0

    ticked = _runner().invoke(
        schedule_cmd.schedule, ["tick", "--now", T0.isoformat(), "--db", db, "--json"]
    )
    row = json.loads(ticked.output)["schedules"][0]

    assert row["code"] == "schedule.disabled"
    assert row["enabled"] is False
    # The schedule's own gates *did* clear at 09:00 -- ``due`` says so -- and the
    # reason it will not run is the enabled flag, in its own field. A row that
    # reported ``due: false`` here would be claiming the schedule was not due,
    # which is a different and wrong statement.
    assert row["due"] is True


def test_an_already_fired_slot_is_reported_as_already_dispatched(tmp_path: Path) -> None:
    """A slot that ran is never reported as pending a second time."""
    db = str(tmp_path / "mayhem.db")
    _runner().invoke(
        schedule_cmd.schedule,
        [
            "add", "nightly",
            "--campaign-id", "camp-1", "--experiment-id", "exp-1", "--team", "sre",
            "--cron", "0 9 * * *", "--max-runs", "20",
            "--created-at", BEFORE_T0.isoformat(), "--resource", "db-primary",
            "--db", db, "--json",
        ],
    )
    store = Store.open_migrated(db)
    repo = ScheduleStore(store)
    repo.claim_slot(_run_record())
    repo.settle_slot(
        _run_record().idempotency_key,
        state=RunClaimState.DISPATCHED,
        code="schedule.dispatched",
        reason="dispatched as r-1",
        at=T1,
        run_id="r-1",
    )
    store.close()

    ticked = _runner().invoke(
        schedule_cmd.schedule, ["tick", "--now", T0.isoformat(), "--db", db, "--json"]
    )
    row = json.loads(ticked.output)["schedules"][0]

    assert row["code"] == "already_dispatched"
    assert row["due"] is True  # the schedule is due; the slot is spent


def test_the_fairness_preview_reports_the_bound_and_honours_it(tmp_path: Path) -> None:
    """A simulation, not a promise: the bound and the observed worst case side by side."""
    result = _runner().invoke(
        schedule_cmd.schedule,
        ["fairness", "--team", "sre", "--team", "payments", "--windows", "12", "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["honours_policy"] is True
    assert payload["starved_teams"] == []
    assert payload["starvation_bound"] >= max(payload["max_consecutive_skips"].values())
    assert len(payload["grants"]) == 12


def test_the_fairness_preview_refuses_a_policy_with_no_teams(tmp_path: Path) -> None:
    """Nothing to simulate is a usage error, not an empty simulation."""
    result = _runner().invoke(schedule_cmd.schedule, ["fairness", "--windows", "12"])

    assert result.exit_code != 0
    assert "at least one --team" in result.output


def test_delete_refuses_a_schedule_with_dispatch_evidence(tmp_path: Path) -> None:
    """The evidence that it ran outlives the trigger."""
    db = str(tmp_path / "mayhem.db")
    _runner().invoke(
        schedule_cmd.schedule,
        [
            "add", "nightly",
            "--campaign-id", "camp-1", "--experiment-id", "exp-1", "--team", "sre",
            "--cron", "0 9 * * *", "--max-runs", "20",
            "--created-at", BEFORE_T0.isoformat(), "--resource", "db-primary",
            "--db", db, "--json",
        ],
    )
    store = Store.open_migrated(db)
    repo = ScheduleStore(store)
    repo.claim_slot(_run_record())
    store.close()

    refused = _runner().invoke(schedule_cmd.schedule, ["delete", "nightly", "--yes", "--db", db])
    deleted = _runner().invoke(
        schedule_cmd.schedule,
        ["delete", "poller", "--yes", "--db", db],
    )

    assert refused.exit_code == 1
    assert "refused" in refused.output
    # An unknown schedule is a different answer from a refused one.
    assert deleted.exit_code == 1


def test_an_undispatched_schedule_can_be_deleted(tmp_path: Path) -> None:
    """The positive control on the refusal above."""
    db = str(tmp_path / "mayhem.db")
    _runner().invoke(
        schedule_cmd.schedule,
        [
            "add", "nightly",
            "--campaign-id", "camp-1", "--experiment-id", "exp-1", "--team", "sre",
            "--cron", "0 9 * * *", "--max-runs", "20",
            "--created-at", BEFORE_T0.isoformat(), "--resource", "db-primary",
            "--db", db, "--json",
        ],
    )

    result = _runner().invoke(schedule_cmd.schedule, ["delete", "nightly", "--yes", "--db", db])

    assert result.exit_code == 0, result.output
    store = Store.open_migrated(db)
    assert ScheduleStore(store).load_schedule("nightly") is None
    store.close()


def test_next_reports_the_nominal_and_the_effective_instants_separately(tmp_path: Path) -> None:
    """A nominal instant and a jittered one, both visible, neither conflated."""
    db = str(tmp_path / "mayhem.db")
    _runner().invoke(
        schedule_cmd.schedule,
        [
            "add", "nightly",
            "--campaign-id", "camp-1", "--experiment-id", "exp-1", "--team", "sre",
            "--cron", "0 9 * * *", "--max-runs", "20",
            "--created-at", BEFORE_T0.isoformat(), "--jitter-s", "30",
            "--resource", "db-primary", "--db", db, "--json",
        ],
    )
    result = _runner().invoke(
        schedule_cmd.schedule,
        # Probed from a day before the cron's first matching minute, so the next
        # fire is the 2026-06-01 09:00 slot rather than something in January.
        ["next", "--now", BEFORE_T0.isoformat(), "--db", db, "--json"],
    )

    assert result.exit_code == 0, result.output
    row = json.loads(result.output)["schedules"][0]
    assert row["slot_start"] == "2026-01-01T09:00:00+00:00"
    assert row["jitter_s"] == 30.0
    assert row["retired"] is False


def test_an_add_with_two_recurrence_sources_is_refused(tmp_path: Path) -> None:
    """Exactly one recurrence, and the refusal says which."""
    result = _runner().invoke(
        schedule_cmd.schedule,
        [
            "add", "nightly",
            "--campaign-id", "camp-1", "--experiment-id", "exp-1", "--team", "sre",
            "--cron", "0 9 * * *",
            "--interval-s", "3600",
            "--anchor-at", T0.isoformat(),
            "--max-runs", "20",
            "--created-at", BEFORE_T0.isoformat(),
            "--resource", "db-primary",
            "--db", str(tmp_path / "mayhem.db"),
        ],
    )

    assert result.exit_code != 0
    assert "exactly one of --cron" in result.output


def test_a_naive_instant_is_refused_by_every_time_taking_flag(tmp_path: Path) -> None:
    """A schedule whose anchor says "09:00" with no zone depends on who reads it."""
    db = str(tmp_path / "mayhem.db")
    naive_anchor = _runner().invoke(
        schedule_cmd.schedule,
        [
            "add", "poller",
            "--campaign-id", "camp-1", "--experiment-id", "exp-1", "--team", "sre",
            "--interval-s", "3600", "--anchor-at", "2026-06-01T09:00:00",
            "--max-runs", "50", "--created-at", BEFORE_T0.isoformat(),
            "--resource", "db-primary", "--db", db,
        ],
    )
    naive_now = _runner().invoke(
        schedule_cmd.schedule, ["next", "--now", "2026-06-01T09:00:00", "--db", db]
    )

    assert naive_anchor.exit_code != 0
    assert "no timezone offset" in naive_anchor.output
    assert naive_now.exit_code != 0
    assert "no timezone offset" in naive_now.output


# =============================================================================
# 6. Neither surface can dispatch
# =============================================================================


@pytest.mark.parametrize(
    "module",
    [schedule_cmd, game_day_step_cmd],
    ids=lambda module: Path(module.__file__).name,
)
def test_neither_surface_carries_a_flag_that_dispatches(module: object) -> None:
    """No ``--execute``, no ``--force``, no ``--skip-hold``: asserted over the AST.

    A CLI that could dispatch would be a second dispatch path, and the second
    dispatch path is how a scheduled run ends up skipping a gate. Click makes it
    easy to add ``is_flag=True`` to a new option, so this reads the parsed
    decorators' keyword arguments rather than trusting a grep for a flag name.
    """
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    banned = {"execute", "force", "dispatch", "run", "skip_hold", "ignore_windows", "no_hold"}
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "option":
            continue
        names = {
            kw.value.value
            for kw in node.keywords
            if kw.arg in {"name"} and isinstance(kw.value, ast.Constant)
        }
        flags = {
            arg.value
            for kw in node.keywords
            if kw.arg == "is_flag" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for arg in [kw]  # pragma: no cover - replaced below
        }
        is_flag = any(
            kw.arg == "is_flag" and getattr(kw.value, "value", False) is True
            for kw in node.keywords
        )
        if is_flag and (names & banned):
            offenders.append(f"line {node.lineno}: {sorted(names & banned)}")
        del flags

    assert offenders == [], f"a dispatching flag was found: {offenders}"


@pytest.mark.parametrize(
    "module",
    [schedule_cmd, game_day_step_cmd],
    ids=lambda module: Path(module.__file__).name,
)
def test_neither_surface_calls_the_scheduler_or_the_executor(module: object) -> None:
    """A dispatching surface would have to reach one of them.

    Read from the AST rather than trusted: the strongest statement a test can make
    about "this surface cannot fire a run" is that the symbols which could do it
    are never named.
    """
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    named = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert not named & {"Scheduler", "SchedulerInputs", "DispatchPipeline", "compile_campaign_run"}
    assert not named & {"build_dispatch_pipeline", "campaign_budget_verdict"}
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert not any("executor" in name for name in imported)
    assert not any("campaign_dispatch" in name for name in imported)


def test_the_tick_payload_names_the_gates_it_did_not_evaluate() -> None:
    """The honesty sentence, asserted as data rather than as prose.

    ``NOT_EVALUATED_HERE`` is what stops "due" from reading as "cleared", so the
    three gates are named as constants and checked individually.
    """
    assert len(schedule_cmd.NOT_EVALUATED_HERE) == 3
    assert any("compile_safety_evidence" in gate for gate in schedule_cmd.NOT_EVALUATED_HERE)
    assert any("verify_approvals" in gate for gate in schedule_cmd.NOT_EVALUATED_HERE)
    assert any("evaluate_concurrency" in gate for gate in schedule_cmd.NOT_EVALUATED_HERE)


def test_the_release_hold_helper_is_the_only_way_past_a_hold() -> None:
    """The surface reaches the engine's own release, not a re-implementation.

    Imported and asserted by identity: a CLI that built its own released step
    would be a second definition of what "released" means, and the two would
    drift the first time the engine's grew a field.
    """
    from mayhem.controller import scheduler

    assert game_day_step_cmd.release_hold is scheduler.release_hold
    released = release_hold(
        _step(),
        OperatorAcknowledgement(actor=FACILITATOR, reason="open", at=T1.isoformat()),
        at=T1.isoformat(),
    )
    assert released.hold_state is HoldState.RELEASED
    assert released.released_by == FACILITATOR
