from __future__ import annotations

from mayhem.domain.replay import ReplayCapsule, validate_replay_capsule


def _capsule() -> ReplayCapsule:
    return ReplayCapsule(
        run_id="run-1",
        spec={"kind": "drill", "name": "demo"},
        plan={"run_id": "run-1", "steps": []},
        policy={"risk_ceiling": "critical"},
        target={"profile": "dev"},
        runtime={"engine": "podman"},
        versions={"mayhem": "0.9.0"},
        seed=7,
        fingerprints={"environment": "env-1"},
    )


def test_capsule_serialization_is_deterministic() -> None:
    capsule = _capsule()
    assert capsule.canonical_json() == capsule.canonical_json()
    assert capsule.digest() == capsule.digest()
    assert capsule.with_digests().digests["capsule"] == capsule.digest()


def test_validation_accepts_a_complete_capsule() -> None:
    capsule = _capsule().with_digests()
    result = validate_replay_capsule(capsule, mode="dry_run")
    assert result.valid is True
    assert result.errors == ()
    assert result.plan_hash


def test_validation_rejects_digest_tampering() -> None:
    capsule = _capsule().with_digests()
    tampered = capsule.model_copy(update={"plan": {"run_id": "run-2"}})
    result = validate_replay_capsule(tampered)
    assert result.valid is False
    assert "capsule digest mismatch" in result.errors


def test_validation_rejects_stale_environment_fingerprint() -> None:
    capsule = _capsule().with_digests()
    result = validate_replay_capsule(capsule, current_fingerprint="env-2")
    assert result.valid is False
    assert "environment fingerprint is stale" in result.errors


def test_validation_warns_when_dry_run_has_no_spec() -> None:
    capsule = _capsule().model_copy(update={"spec": {}}).with_digests()
    result = validate_replay_capsule(capsule, mode="dry_run")
    assert result.valid is True
    assert result.warnings
