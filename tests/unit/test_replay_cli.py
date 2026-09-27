from __future__ import annotations

import json

from mayhem.domain.replay import ReplayCapsule, validate_replay_capsule
from mayhem.infra.replay_repository import ReplayRepository, build_capsule
from mayhem.infra.store import Store


def _seed_run(store: Store, run_id: str) -> None:
    with store.write() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO config_snapshots (id, resolved_json, source_map, created_at) "
            "VALUES (?,?,?,datetime('now'))",
            ("cfg-1", "{}", "{}"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO runs (id, experiment_name, kind, spec_json, plan_json, "
            "seed, status, environment_fingerprint, config_snapshot_id) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                "replay-demo",
                "deterministic",
                json.dumps({"faults": ["proc.pause"]}),
                json.dumps({"steps": [{"id": "s1"}]}),
                7,
                "completed",
                "env-fingerprint-1",
                "cfg-1",
            ),
        )


def test_build_capsule_from_run_is_deterministic(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "replay.db")
    try:
        _seed_run(store, "run-1")
        capsule = build_capsule(store, "run-1", engine="kubernetes")
        assert capsule is not None
        assert capsule.run_id == "run-1"
        assert capsule.spec["faults"] == ["proc.pause"]
        assert capsule.fingerprints["environment"] == "env-fingerprint-1"
        assert capsule.digests["capsule"] == capsule.digest()
        again = build_capsule(store, "run-1", engine="kubernetes")
        assert again is not None
        assert again.digest() == capsule.digest()
    finally:
        store.close()


def test_build_capsule_returns_none_for_unknown_run(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "replay.db")
    try:
        assert build_capsule(store, "nope") is None
    finally:
        store.close()


def test_captured_capsule_validates_in_both_modes(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "replay.db")
    try:
        _seed_run(store, "run-1")
        capsule = build_capsule(store, "run-1", engine="kubernetes")
        assert capsule is not None
        ReplayRepository(store).save(capsule)
        loaded = ReplayRepository(store).load("run-1")
        assert loaded is not None
        assert validate_replay_capsule(loaded, mode="validate").valid is True
        assert validate_replay_capsule(loaded, mode="dry_run").valid is True
    finally:
        store.close()


def test_cli_replay_export_and_validate(tmp_path) -> None:
    from click.testing import CliRunner

    from mayhem.cli.inspect import replay_group

    db = tmp_path / "replay.db"
    store = Store.open_migrated(db)
    try:
        _seed_run(store, "run-1")
    finally:
        store.close()

    runner = CliRunner()
    from mayhem.cli.context import CliContext

    ctx_obj = CliContext(db=str(db))

    exported = runner.invoke(replay_group, ["export", "run-1", "--json"], obj=ctx_obj)
    assert exported.exit_code == 0, exported.output
    payload = json.loads(exported.output)
    assert payload["run_id"] == "run-1"
    assert payload["digests"]["capsule"]

    out_file = tmp_path / "capsule.json"
    written = runner.invoke(replay_group, ["export", "run-1", "--out", str(out_file)], obj=ctx_obj)
    assert written.exit_code == 0, written.output
    assert json.loads(out_file.read_text())["run_id"] == "run-1"

    validated = runner.invoke(replay_group, ["validate", "run-1", "--json"], obj=ctx_obj)
    assert validated.exit_code == 0, validated.output
    assert json.loads(validated.output)["valid"] is True

    text = runner.invoke(replay_group, ["validate", "run-1"], obj=ctx_obj)
    assert text.exit_code == 0
    assert "valid: true" in text.output


def test_cli_replay_validate_fails_on_stale_fingerprint(tmp_path) -> None:
    from click.testing import CliRunner

    from mayhem.cli.inspect import replay_group

    db = tmp_path / "replay.db"
    store = Store.open_migrated(db)
    try:
        _seed_run(store, "run-1")
        capsule = build_capsule(store, "run-1", engine="kubernetes")
        assert capsule is not None
        ReplayRepository(store).save(capsule)
    finally:
        store.close()

    from mayhem.cli.context import CliContext

    ctx_obj = CliContext(db=str(db))
    result = CliRunner().invoke(
        replay_group,
        ["validate", "run-1", "--current-fingerprint", "different"],
        obj=ctx_obj,
    )
    assert result.exit_code == 1
    assert "environment fingerprint is stale" in result.output


def test_cli_replay_validate_unknown_run_exits_nonzero(tmp_path) -> None:
    from click.testing import CliRunner

    from mayhem.cli.context import CliContext
    from mayhem.cli.inspect import replay_group

    ctx_obj = CliContext(db=str(tmp_path / "replay.db"))
    Store.open_migrated(ctx_obj.db).close()
    result = CliRunner().invoke(replay_group, ["validate", "missing"], obj=ctx_obj)
    assert result.exit_code == 1


def test_tampered_capsule_fails_validation(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "replay.db")
    try:
        _seed_run(store, "run-1")
        capsule = build_capsule(store, "run-1", engine="kubernetes")
        assert capsule is not None
        tampered = ReplayCapsule.model_validate({**capsule.model_dump(mode="json"), "seed": 999})
        result = validate_replay_capsule(tampered, mode="validate")
        assert result.valid is False
        assert "capsule digest mismatch" in result.errors
    finally:
        store.close()
