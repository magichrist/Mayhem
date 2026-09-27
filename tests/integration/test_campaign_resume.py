"""Campaign resume across a controller loss (v0.9.0 expansion task 15)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from mayhem.domain.campaign_checkpoint import CampaignCheckpoint, CheckpointState, plan_resume
from mayhem.infra.campaign_checkpoint_repository import CampaignCheckpointRepository
from mayhem.infra.store import Store


def _ctx(db):
    from mayhem.cli.context import CliContext

    return CliContext(db=str(db))


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


def test_checkpoints_survive_the_controller_process(tmp_path) -> None:
    """Write checkpoints, drop the store, reopen: the campaign can still resume."""
    db = tmp_path / "campaign.db"
    store = Store.open_migrated(db)
    try:
        repo = CampaignCheckpointRepository(store)
        repo.save(_cp("exp-1", CheckpointState.VERIFIED))
        repo.save(_cp("exp-2", CheckpointState.RUNNING, lease_id="L42"))
    finally:
        store.close()  # the controller "dies" here

    store = Store.open_migrated(db)
    try:
        plan = plan_resume(
            CampaignCheckpointRepository(store).load("camp-1"),
            "camp-1",
            pending_experiments=("exp-1", "exp-2", "exp-3"),
            current_fingerprint="fp-1",
        )
    finally:
        store.close()
    assert plan.resume == ("exp-3",)
    assert plan.skip_verified == ("exp-1",)
    assert plan.in_flight == ("exp-2",)
    assert plan.safe is False, "in-flight work must block an automatic resume"


def test_resume_after_compensation_finishes_progression(tmp_path) -> None:
    db = tmp_path / "campaign.db"
    store = Store.open_migrated(db)
    try:
        repo = CampaignCheckpointRepository(store)
        repo.save(_cp("exp-1", CheckpointState.COMPENSATING))
    finally:
        store.close()

    # The compensator finishes before the resume is planned.
    store = Store.open_migrated(db)
    try:
        repo = CampaignCheckpointRepository(store)
        repo.save(repo.get("camp-1", "exp-1").with_state(CheckpointState.COMPENSATED))  # type: ignore[union-attr]
        plan = plan_resume(repo.load("camp-1"), "camp-1", pending_experiments=("exp-1",))
    finally:
        store.close()
    assert plan.resume == ()
    assert plan.skip_verified == ("exp-1",)
    assert plan.safe is True


def test_resume_never_repeats_verified_work_after_controller_loss(tmp_path) -> None:
    db = tmp_path / "campaign.db"
    store = Store.open_migrated(db)
    try:
        repo = CampaignCheckpointRepository(store)
        repo.save(_cp("verified-1", CheckpointState.VERIFIED))
        repo.save(_cp("verified-2", CheckpointState.COMPLETED))
    finally:
        store.close()

    store = Store.open_migrated(db)
    try:
        repo = CampaignCheckpointRepository(store)
        planned = plan_resume(
            repo.load("camp-1"),
            "camp-1",
            pending_experiments=("verified-1", "verified-2"),
        )
    finally:
        store.close()
    assert planned.resume == ()
    assert set(planned.skip_verified) == {"verified-1", "verified-2"}

    # Only an explicit retry intent re-opens them.
    store = Store.open_migrated(db)
    try:
        retried = plan_resume(
            CampaignCheckpointRepository(store).load("camp-1"),
            "camp-1",
            pending_experiments=("verified-1", "verified-2"),
            retry_verified=True,
        )
    finally:
        store.close()
    assert set(retried.resume) == {"verified-1", "verified-2"}


def test_stale_fingerprint_after_environment_change_is_reported(tmp_path) -> None:
    db = tmp_path / "campaign.db"
    store = Store.open_migrated(db)
    try:
        CampaignCheckpointRepository(store).save(
            _cp("exp-1", CheckpointState.RETRYABLE, fingerprint="fp-old")
        )
    finally:
        store.close()

    store = Store.open_migrated(db)
    try:
        plan = plan_resume(
            CampaignCheckpointRepository(store).load("camp-1"),
            "camp-1",
            pending_experiments=("exp-1",),
            current_fingerprint="fp-new",
        )
    finally:
        store.close()
    assert plan.stale == ("exp-1",)
    assert plan.safe is False


def test_cli_checkpoints_and_resume_plan_after_reopen(tmp_path) -> None:
    from mayhem.cli.campaign import campaign_checkpoints, record_checkpoint, resume_plan

    db = tmp_path / "campaign.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    runner.invoke(
        record_checkpoint,
        ["camp-1", "exp-1", "--state", "verified", "--fingerprint", "fp-1"],
        obj=_ctx(db),
    )
    runner.invoke(
        record_checkpoint,
        ["camp-1", "exp-2", "--state", "running", "--fingerprint", "fp-1"],
        obj=_ctx(db),
    )

    shown = runner.invoke(campaign_checkpoints, ["camp-1", "--json"], obj=_ctx(db))
    assert shown.exit_code == 0, shown.output
    checkpoints = json.loads(shown.output)["checkpoints"]
    assert [c["experiment_id"] for c in checkpoints] == ["exp-1", "exp-2"]

    plan = runner.invoke(
        resume_plan,
        [
            "camp-1",
            "--experiment",
            "exp-1",
            "--experiment",
            "exp-2",
            "--experiment",
            "exp-3",
            "--fingerprint",
            "fp-1",
            "--json",
        ],
        obj=_ctx(db),
    )
    assert plan.exit_code == 0, plan.output
    payload = json.loads(plan.output)
    assert payload["resume"] == ["exp-3"]
    assert payload["safe"] is False
    assert payload["in_flight"] == ["exp-2"]


def test_cli_resume_plan_is_idempotent_across_repeated_invocations(tmp_path) -> None:
    from mayhem.cli.campaign import record_checkpoint, resume_plan

    db = tmp_path / "campaign.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    runner.invoke(record_checkpoint, ["camp-1", "exp-1", "--state", "verified"], obj=_ctx(db))
    args = ["camp-1", "--experiment", "exp-1", "--experiment", "exp-2", "--json"]
    first = runner.invoke(resume_plan, args, obj=_ctx(db))
    second = runner.invoke(resume_plan, args, obj=_ctx(db))
    assert first.output == second.output


def test_deleting_a_campaign_clears_its_checkpoints(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "campaign.db")
    try:
        repo = CampaignCheckpointRepository(store)
        repo.save(_cp("exp-1", CheckpointState.PENDING))
        assert repo.delete_campaign("camp-1") == 1
        assert plan_resume(
            repo.load("camp-1"), "camp-1", pending_experiments=("exp-1",)
        ).resume == ("exp-1",)
    finally:
        store.close()
