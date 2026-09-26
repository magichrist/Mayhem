from __future__ import annotations

from mayhem.domain.replay import ReplayCapsule, validate_replay_capsule
from mayhem.infra.replay_repository import ReplayRepository
from mayhem.infra.store import Store


def test_replay_capsule_round_trips_through_sqlite(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "replay.db")
    try:
        repository = ReplayRepository(store)
        capsule = ReplayCapsule(
            run_id="run-1",
            spec={"kind": "drill"},
            plan={"run_id": "run-1"},
            fingerprints={"environment": "env-1"},
        ).with_digests()
        repository.save(capsule)
        loaded = repository.load("run-1")
        assert loaded is not None
        assert loaded.run_id == capsule.run_id
        assert loaded.plan == capsule.plan
        assert validate_replay_capsule(loaded).valid is True
        assert repository.list_run_ids() == ("run-1",)
    finally:
        store.close()
