"""v0.9.0 expansion task 15: campaign checkpoints."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from mayhem.domain.campaign_checkpoint import (
    CampaignCheckpoint,
    CheckpointState,
    plan_resume,
)
from mayhem.infra.campaign_checkpoint_repository import CampaignCheckpointRepository
from mayhem.infra.store import Store


def _cp(experiment_id: str, state: CheckpointState, **overrides) -> CampaignCheckpoint:
    payload = {
        "campaign_id": "camp-1",
        "experiment_id": experiment_id,
        "state": state,
        "attempt": 1,
        "fingerprint": "fp-1",
    }
    payload.update(overrides)
    return CampaignCheckpoint(**payload)  # type: ignore[arg-type]


# ── state vocabulary ─────────────────────────────────────────────────────────
def test_all_nine_states_exist() -> None:
    assert {state.value for state in CheckpointState} == {
        "pending",
        "running",
        "verified",
        "compensating",
        "compensated",
        "retryable",
        "blocked",
        "completed",
        "aborted",
    }


def test_terminal_and_in_flight_classification() -> None:
    assert _cp("a", CheckpointState.VERIFIED).terminal is True
    assert _cp("a", CheckpointState.COMPLETED).terminal is True
    assert _cp("a", CheckpointState.COMPENSATED).terminal is True
    assert _cp("a", CheckpointState.RUNNING).in_flight is True
    assert _cp("a", CheckpointState.COMPENSATING).in_flight is True
    assert _cp("a", CheckpointState.PENDING).terminal is False


def test_checkpoint_key_and_serialisation() -> None:
    checkpoint = _cp("exp-1", CheckpointState.VERIFIED)
    assert checkpoint.key == "camp-1:exp-1"
    payload = checkpoint.to_dict()
    assert payload["state"] == "verified"
    assert payload["terminal"] is True
    assert json.loads(json.dumps(payload))["experiment_id"] == "exp-1"


def test_with_state_preserves_unrelated_fields() -> None:
    checkpoint = _cp("exp-1", CheckpointState.PENDING, lease_id="L1", detail="note")
    moved = checkpoint.with_state(CheckpointState.RUNNING, attempt=2)
    assert moved.state is CheckpointState.RUNNING
    assert moved.attempt == 2
    assert moved.lease_id == "L1"
    assert moved.detail == "note"
    assert checkpoint.state is CheckpointState.PENDING  # frozen


# ── resume planning ──────────────────────────────────────────────────────────
def test_normal_progression_resumes_pending_work() -> None:
    plan = plan_resume(
        (_cp("done", CheckpointState.VERIFIED),),
        "camp-1",
        pending_experiments=("done", "next"),
    )
    assert plan.resume == ("next",)
    assert plan.skip_verified == ("done",)
    assert plan.safe is True


def test_controller_loss_leaves_in_flight_work_on_hold() -> None:
    plan = plan_resume(
        (_cp("crashed", CheckpointState.RUNNING, lease_id="L9"),),
        "camp-1",
        pending_experiments=("crashed",),
    )
    assert plan.resume == ()
    assert plan.in_flight == ("crashed",)
    assert plan.safe is False


def test_compensation_in_progress_is_never_restarted() -> None:
    plan = plan_resume(
        (_cp("mid", CheckpointState.COMPENSATING),),
        "camp-1",
        pending_experiments=("mid",),
    )
    assert plan.in_flight == ("mid",)
    assert plan.resume == ()


def test_resume_never_repeats_a_verified_experiment_without_retry_intent() -> None:
    checkpoints = (_cp("done", CheckpointState.VERIFIED, attempt=1),)
    without = plan_resume(checkpoints, "camp-1", pending_experiments=("done",))
    assert without.resume == ()
    assert without.skip_verified == ("done",)

    with_intent = plan_resume(
        checkpoints, "camp-1", pending_experiments=("done",), retry_verified=True
    )
    assert with_intent.resume == ("done",)
    assert with_intent.skip_verified == ()


def test_retry_budget_exhaustion_is_reported() -> None:
    plan = plan_resume(
        (_cp("flaky", CheckpointState.RETRYABLE, attempt=3),),
        "camp-1",
        pending_experiments=("flaky",),
        max_attempts=3,
    )
    assert plan.exhausted == ("flaky",)
    assert plan.resume == ()
    assert plan.safe is False


def test_retry_budget_allows_a_further_attempt() -> None:
    plan = plan_resume(
        (_cp("flaky", CheckpointState.RETRYABLE, attempt=1),),
        "camp-1",
        pending_experiments=("flaky",),
        max_attempts=3,
    )
    assert plan.resume == ("flaky",)


def test_stale_fingerprint_is_reported_not_resumed() -> None:
    plan = plan_resume(
        (_cp("moved", CheckpointState.RETRYABLE, fingerprint="fp-old"),),
        "camp-1",
        pending_experiments=("moved",),
        current_fingerprint="fp-new",
    )
    assert plan.stale == ("moved",)
    assert plan.resume == ()
    assert plan.safe is False


def test_matching_fingerprint_resumes_normally() -> None:
    plan = plan_resume(
        (_cp("moved", CheckpointState.RETRYABLE, fingerprint="fp-new"),),
        "camp-1",
        pending_experiments=("moved",),
        current_fingerprint="fp-new",
    )
    assert plan.resume == ("moved",)


def test_blocked_and_aborted_are_never_resumed() -> None:
    plan = plan_resume(
        (
            _cp("blocked", CheckpointState.BLOCKED),
            _cp("killed", CheckpointState.ABORTED),
        ),
        "camp-1",
        pending_experiments=("blocked", "killed"),
    )
    assert set(plan.blocked) == {"blocked", "killed"}
    assert plan.resume == ()


def test_unsafe_checkpoint_is_not_resumed() -> None:
    plan = plan_resume(
        (_cp("dirty", CheckpointState.PENDING, resume_safe=False),),
        "camp-1",
        pending_experiments=("dirty",),
    )
    assert plan.blocked == ("dirty",)


def test_unknown_experiment_is_resumable() -> None:
    plan = plan_resume((), "camp-1", pending_experiments=("fresh",))
    assert plan.resume == ("fresh",)


def test_plan_is_deterministic() -> None:
    checkpoints = (
        _cp("a", CheckpointState.VERIFIED),
        _cp("b", CheckpointState.RUNNING),
        _cp("c", CheckpointState.RETRYABLE),
    )
    first = plan_resume(checkpoints, "camp-1", pending_experiments=("a", "b", "c"))
    second = plan_resume(checkpoints, "camp-1", pending_experiments=("a", "b", "c"))
    assert first.to_dict() == second.to_dict()


def test_plan_dict_is_json_serializable() -> None:
    payload = plan_resume((), "camp-1", pending_experiments=("x",)).to_dict()
    assert json.loads(json.dumps(payload))["campaign_id"] == "camp-1"


# ── persistence ──────────────────────────────────────────────────────────────
def test_repository_round_trip(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "cp.db")
    try:
        repo = CampaignCheckpointRepository(store)
        repo.save(_cp("exp-1", CheckpointState.RUNNING, lease_id="L1"))
        repo.save(_cp("exp-2", CheckpointState.VERIFIED))
        loaded = repo.load("camp-1")
        assert [c.experiment_id for c in loaded] == ["exp-1", "exp-2"]
        assert loaded[0].state is CheckpointState.RUNNING
        assert loaded[0].lease_id == "L1"
        assert loaded[0].updated_at
        assert repo.get("camp-1", "exp-2").state is CheckpointState.VERIFIED
        assert repo.get("camp-1", "missing") is None
        assert repo.load("other") == ()
    finally:
        store.close()


def test_repository_save_is_idempotent(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "cp.db")
    try:
        repo = CampaignCheckpointRepository(store)
        repo.save(_cp("exp-1", CheckpointState.RUNNING))
        repo.save(_cp("exp-1", CheckpointState.VERIFIED))
        loaded = repo.load("camp-1")
        assert len(loaded) == 1
        assert loaded[0].state is CheckpointState.VERIFIED
    finally:
        store.close()


def test_repository_survives_reopen(tmp_path) -> None:
    db = tmp_path / "cp.db"
    store = Store.open_migrated(db)
    try:
        CampaignCheckpointRepository(store).save(_cp("exp-1", CheckpointState.COMPENSATING))
    finally:
        store.close()
    store = Store.open_migrated(db)
    try:
        assert CampaignCheckpointRepository(store).load("camp-1")[0].state is CheckpointState.COMPENSATING
    finally:
        store.close()


def test_repository_delete_campaign(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "cp.db")
    try:
        repo = CampaignCheckpointRepository(store)
        repo.save(_cp("exp-1", CheckpointState.PENDING))
        assert repo.delete_campaign("camp-1") == 1
        assert repo.load("camp-1") == ()
    finally:
        store.close()


# ── CLI ──────────────────────────────────────────────────────────────────────
def _ctx(db):
    from mayhem.cli.context import CliContext

    return CliContext(db=str(db))


def test_cli_record_and_show_checkpoints(tmp_path) -> None:
    from mayhem.cli.campaign import campaign_checkpoints, record_checkpoint

    db = tmp_path / "cp.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    recorded = runner.invoke(
        record_checkpoint,
        ["camp-1", "exp-1", "--state", "running", "--attempt", "1", "--lease-id", "L1"],
        obj=_ctx(db),
    )
    assert recorded.exit_code == 0, recorded.output
    shown = runner.invoke(campaign_checkpoints, ["camp-1", "--json"], obj=_ctx(db))
    assert shown.exit_code == 0, shown.output
    payload = json.loads(shown.output)
    assert payload["checkpoints"][0]["state"] == "running"
    assert payload["checkpoints"][0]["lease_id"] == "L1"


def test_cli_rejects_an_unknown_checkpoint_state(tmp_path) -> None:
    from mayhem.cli.campaign import record_checkpoint

    db = tmp_path / "cp.db"
    Store.open_migrated(db).close()
    result = CliRunner().invoke(
        record_checkpoint, ["camp-1", "exp-1", "--state", "nope"], obj=_ctx(db)
    )
    assert result.exit_code == 2


def test_cli_resume_plan_is_plan_only_and_reports_skips(tmp_path) -> None:
    from mayhem.cli.campaign import record_checkpoint, resume_plan

    db = tmp_path / "cp.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    runner.invoke(
        record_checkpoint, ["camp-1", "done", "--state", "verified"], obj=_ctx(db)
    )
    result = runner.invoke(
        resume_plan, ["camp-1", "--experiment", "done", "--experiment", "next"], obj=_ctx(db)
    )
    assert result.exit_code == 0, result.output
    assert "resume  next" in result.output
    assert "already verified" in result.output
    assert "nothing was executed" not in result.output  # no false claim either way


def test_cli_resume_plan_json_and_retry_intent(tmp_path) -> None:
    from mayhem.cli.campaign import record_checkpoint, resume_plan

    db = tmp_path / "cp.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    runner.invoke(record_checkpoint, ["camp-1", "done", "--state", "verified"], obj=_ctx(db))
    plain = runner.invoke(
        resume_plan, ["camp-1", "--experiment", "done", "--json"], obj=_ctx(db)
    )
    assert json.loads(plain.output)["skip_verified"] == ["done"]
    retried = runner.invoke(
        resume_plan,
        ["camp-1", "--experiment", "done", "--retry-verified", "--json"],
        obj=_ctx(db),
    )
    assert json.loads(retried.output)["resume"] == ["done"]


def test_cli_resume_plan_flags_an_unsafe_plan(tmp_path) -> None:
    from mayhem.cli.campaign import record_checkpoint, resume_plan

    db = tmp_path / "cp.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    runner.invoke(
        record_checkpoint, ["camp-1", "mid", "--state", "compensating"], obj=_ctx(db)
    )
    result = runner.invoke(
        resume_plan, ["camp-1", "--experiment", "mid", "--json"], obj=_ctx(db)
    )
    payload = json.loads(result.output)
    assert payload["safe"] is False
    assert payload["in_flight"] == ["mid"]


def test_cli_resume_plan_never_builds_an_engine(tmp_path, monkeypatch) -> None:
    from mayhem.cli.campaign import resume_plan

    def explode(*args: object, **kwargs: object) -> object:
        raise AssertionError("resume-plan must not build an execution engine")

    monkeypatch.setattr("mayhem.controller.executor.RunEngine", explode)
    db = tmp_path / "cp.db"
    Store.open_migrated(db).close()
    result = CliRunner().invoke(resume_plan, ["camp-1", "--experiment", "x"], obj=_ctx(db))
    assert result.exit_code == 0, result.output
