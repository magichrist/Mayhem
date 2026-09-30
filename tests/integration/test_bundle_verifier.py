"""Bundle verification end to end, offline (v0.9.0 expansion task 20)."""

from __future__ import annotations

import json
from dataclasses import replace

from click.testing import CliRunner

from mayhem.domain.evidence_bundle import build_bundle, verify_bundle
from mayhem.infra.evidence import build_evidence
from mayhem.infra.evidence_bundle_io import load_bundle, write_bundle


def _real_evidence() -> dict:
    envelope = build_evidence(
        run_id="bundle-run",
        plan=None,
        target_profile="checkout",
        engine="kubernetes",
        safety_decisions=("impact-gate:pass",),
        step_reports=(
            {"step_id": "s1", "ok": True, "detail": "ok", "password": "hunter2-plaintext"},
        ),
        lease_timeline=(),
        observations=({"metric": "http.latency", "value": 0.5},),
        verdict="pass",
        recovery_state="none",
        remediation=(),
        replay_digest="abc123",
    )
    return envelope.model_dump(mode="json")


def test_a_bundle_built_from_real_evidence_verifies(tmp_path) -> None:
    bundle = build_bundle(
        evidence=_real_evidence(),
        replay={"run_id": "bundle-run", "plan": {"steps": []}},
        capabilities={"capabilities": []},
        signature="sig",
        signer="acme",
    )
    target = write_bundle(bundle, tmp_path / "bundle")

    result = verify_bundle(load_bundle(target))
    assert result.valid is True, result.errors
    assert result.signed is True


def test_bundle_never_carries_a_secret_from_real_evidence(tmp_path) -> None:
    bundle = build_bundle(evidence=_real_evidence())
    for name, payload in bundle.artifacts.items():
        assert "hunter2-plaintext" not in json.dumps(payload), name


def test_tampering_with_a_written_bundle_is_detected(tmp_path) -> None:
    bundle = build_bundle(evidence=_real_evidence(), signature="sig", signer="acme")
    target = write_bundle(bundle, tmp_path / "bundle")

    evidence_path = target / "evidence.json"
    payload = json.loads(evidence_path.read_text())
    payload["verdict"] = "fail"
    evidence_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    result = verify_bundle(load_bundle(target))
    assert result.valid is False
    assert any("digest mismatch" in error for error in result.errors)


def test_deleting_an_artifact_is_detected(tmp_path) -> None:
    bundle = build_bundle(evidence=_real_evidence(), replay={"run_id": "bundle-run"})
    target = write_bundle(bundle, tmp_path / "bundle")
    (target / "replay.json").unlink()

    result = verify_bundle(load_bundle(target))
    assert result.valid is False
    assert any("missing from the bundle" in error for error in result.errors)


def test_swapping_an_artifact_is_detected(tmp_path) -> None:
    bundle = build_bundle(evidence=_real_evidence(), replay={"run_id": "bundle-run"})
    target = write_bundle(bundle, tmp_path / "bundle")
    evidence = json.loads((target / "evidence.json").read_text())
    replay = json.loads((target / "replay.json").read_text())
    (target / "evidence.json").write_text(json.dumps(replay, indent=2, sort_keys=True))
    (target / "replay.json").write_text(json.dumps(evidence, indent=2, sort_keys=True))
    evidence_path = target / "evidence.json"
    evidence_path.write_text(
        json.dumps(json.loads((target / "replay.json").read_text()), indent=2, sort_keys=True)
    )

    result = verify_bundle(load_bundle(target))
    assert result.valid is False


def test_chained_bundles_verify_against_their_predecessor(tmp_path) -> None:

    evidence = _real_evidence()
    first = build_bundle(evidence=evidence)
    second = build_bundle(evidence=evidence, previous_root=first.root_digest)
    assert verify_bundle(load_bundle(write_bundle(second, tmp_path / "b2"))).valid is True


def test_verifier_command_needs_no_database_or_runtime(tmp_path) -> None:
    from mayhem.cli.verify_bundle import verify as check

    bundle = build_bundle(evidence=_real_evidence(), signature="sig", signer="acme")
    target = write_bundle(bundle, tmp_path / "bundle")

    def explode(*args: object, **kwargs: object) -> object:
        raise AssertionError("bundle verification must not touch a runtime or database")

    import mayhem.infra.store as store_mod

    original = store_mod.Store.open_migrated
    store_mod.Store.open_migrated = staticmethod(explode)  # type: ignore[assignment]
    try:
        result = CliRunner().invoke(check, [str(target), "--json"])
    finally:
        store_mod.Store.open_migrated = original  # type: ignore[assignment]

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["valid"] is True
    assert payload["signed"] is True


def test_verifier_command_fails_on_a_tampered_bundle(tmp_path) -> None:
    from mayhem.cli.verify_bundle import verify as check

    bundle = build_bundle(evidence=_real_evidence())
    target = write_bundle(bundle, tmp_path / "bundle")
    payload = json.loads((target / "evidence.json").read_text())
    payload["verdict"] = "fail"
    (target / "evidence.json").write_text(json.dumps(payload, indent=2, sort_keys=True))

    result = CliRunner().invoke(check, [str(target)])
    assert result.exit_code == 1
    assert "digest mismatch" in result.output


def test_verifier_command_reports_an_unreadable_bundle(tmp_path) -> None:
    from mayhem.cli.verify_bundle import verify as check

    (tmp_path / "empty").mkdir()
    result = CliRunner().invoke(check, [str(tmp_path / "empty"), "--json"])
    assert result.exit_code == 1
    assert json.loads(result.output)["valid"] is False


def test_verifier_show_prints_the_manifest(tmp_path) -> None:
    from mayhem.cli.verify_bundle import show

    bundle = build_bundle(evidence=_real_evidence(), signature="sig", signer="acme")
    target = write_bundle(bundle, tmp_path / "bundle")
    result = CliRunner().invoke(show, [str(target), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["signed"] is True


def test_bundle_digest_is_stable_for_the_same_evidence(tmp_path) -> None:
    # Same evidence bytes ⇒ same digest. (Two *different* envelopes differ,
    # because build_evidence stamps created_at — that is the point.)
    evidence = _real_evidence()
    first = build_bundle(evidence=evidence)
    second = build_bundle(evidence=evidence)
    assert first.root_digest == second.root_digest
    assert first.manifest.artifacts[0]["digest"] == second.manifest.artifacts[0]["digest"]


def test_manifest_digest_covers_the_previous_root(tmp_path) -> None:
    first = build_bundle(evidence=_real_evidence())
    forked = build_bundle(evidence=_real_evidence(), previous_root="different-root")
    assert forked.root_digest != first.root_digest
    skewed = replace(first, manifest=replace(first.manifest, previous_root="different-root"))
    assert verify_bundle(skewed).valid is False
