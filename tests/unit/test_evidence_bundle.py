"""v0.9.0 expansion task 20: evidence bundle verification."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from mayhem.domain.evidence_bundle import (
    BUNDLE_SCHEMA_VERSION,
    BundleManifest,
    BundleVerificationError,
    build_bundle,
    verify_bundle,
)
from mayhem.infra.evidence_bundle_io import load_bundle, write_bundle

EVIDENCE = {
    "run_id": "r1",
    "plan_hash": "abc",
    "verdict": "pass",
    "redaction_metrics": {"policy_version": "1", "redacted_path_count": 0},
}
REPLAY = {"run_id": "r1", "plan": {"steps": [{"id": "s1"}]}}


def _bundle(**kwargs):
    return build_bundle(evidence=EVIDENCE, replay=REPLAY, **kwargs)


# ── building ─────────────────────────────────────────────────────────────────
def test_bundle_serialisation_is_deterministic() -> None:
    assert _bundle().root_digest == _bundle().root_digest
    assert json.dumps(_bundle().to_dict(), sort_keys=True) == json.dumps(
        _bundle().to_dict(), sort_keys=True
    )


def test_bundle_lists_artifacts_in_canonical_order() -> None:
    names = [artifact["name"] for artifact in _bundle().manifest.artifacts]
    assert names == sorted(names)
    assert names == ["evidence.json", "replay.json"]


def test_bundle_chains_from_a_previous_root() -> None:
    first = _bundle()
    second = _bundle(previous_root=first.root_digest)
    assert second.manifest.previous_root == first.root_digest
    assert second.root_digest != first.root_digest


def test_bundle_records_the_redaction_policy() -> None:
    assert _bundle().manifest.redaction_policy == "1"


def test_optional_artifacts_are_included_when_given() -> None:
    bundle = build_bundle(evidence=EVIDENCE, capabilities={"capabilities": []})
    assert "capabilities.json" in bundle.artifacts


# ── verification ─────────────────────────────────────────────────────────────
def test_a_valid_signed_bundle_verifies() -> None:
    result = verify_bundle(_bundle(signature="sig", signer="acme"))
    assert result.valid is True
    assert result.signed is True
    assert result.artifacts_checked == 2
    assert result.errors == ()


def test_unsigned_bundle_warns_but_still_verifies_integrity() -> None:
    result = verify_bundle(_bundle())
    assert result.valid is True
    assert result.signed is False
    assert any("unsigned" in warning for warning in result.warnings)


def test_changed_payload_fails_the_digest_check() -> None:
    bundle = _bundle()
    tampered = replace(
        bundle, artifacts={**bundle.artifacts, "evidence.json": {**EVIDENCE, "verdict": "fail"}}
    )
    result = verify_bundle(tampered)
    assert result.valid is False
    assert any("digest mismatch" in error for error in result.errors)


def test_reordered_artifacts_fail_the_chain() -> None:
    bundle = _bundle()
    reversed_manifest = BundleManifest(
        schema_version=bundle.manifest.schema_version,
        artifacts=tuple(reversed(bundle.manifest.artifacts)),
        root_digest=bundle.manifest.root_digest,
        previous_root=bundle.manifest.previous_root,
        redaction_policy=bundle.manifest.redaction_policy,
    )
    result = verify_bundle(replace(bundle, manifest=reversed_manifest))
    assert result.valid is False
    assert any("canonical" in error or "chain" in error for error in result.errors)


def test_missing_artifact_is_reported() -> None:
    bundle = _bundle()
    stripped = replace(bundle, artifacts={"evidence.json": EVIDENCE})
    result = verify_bundle(stripped)
    assert result.valid is False
    assert any("missing from the bundle" in error for error in result.errors)


def test_undeclared_artifact_is_reported() -> None:
    bundle = _bundle()
    extended = replace(bundle, artifacts={**bundle.artifacts, "observations.json": {"count": 1}})
    result = verify_bundle(extended)
    assert result.valid is False
    assert any("not in the manifest" in error for error in result.errors)


def test_invalid_signature_metadata_is_reported() -> None:
    result = verify_bundle(_bundle(signature="sig", signer=""))
    assert result.valid is False
    assert any("names no signer" in error for error in result.errors)


def test_unsupported_schema_is_reported() -> None:
    bundle = _bundle()
    bad = replace(bundle, manifest=replace(bundle.manifest, schema_version="9.9"))
    result = verify_bundle(bad)
    assert result.valid is False
    assert any("unsupported bundle schema" in error for error in result.errors)


@pytest.mark.parametrize("name", ["secrets.json", "kubeconfig.json", "env_dump.json", "token.json"])
def test_secret_bearing_extras_are_refused(name: str) -> None:
    bundle = _bundle()
    smuggled = replace(bundle, artifacts={**bundle.artifacts, name: {"k": "v"}})
    result = verify_bundle(smuggled)
    assert result.valid is False
    assert any("secret-shaped name" in error for error in result.errors)


def test_evidence_without_a_redaction_marker_fails() -> None:
    bundle = build_bundle(evidence={"run_id": "r1", "verdict": "pass"})
    result = verify_bundle(bundle)
    assert result.valid is False
    assert any("no redaction marker" in error for error in result.errors)


def test_redaction_policy_mismatch_is_reported() -> None:
    bundle = _bundle()
    skewed = replace(bundle, manifest=replace(bundle.manifest, redaction_policy="99"))
    result = verify_bundle(skewed)
    assert result.valid is False
    assert any("redaction policy mismatch" in error for error in result.errors)


def test_every_problem_is_reported_at_once() -> None:
    bundle = _bundle()
    broken = replace(
        bundle,
        manifest=replace(bundle.manifest, schema_version="9.9", redaction_policy=""),
        artifacts={**bundle.artifacts, "evidence.json": {"run_id": "r1"}},
    )
    result = verify_bundle(broken)
    assert result.valid is False
    assert len(result.errors) >= 3


def test_verification_dict_is_json_serializable() -> None:
    payload = verify_bundle(_bundle(signature="sig", signer="acme")).to_dict()
    assert json.loads(json.dumps(payload))["valid"] is True


# ── disk round trip ──────────────────────────────────────────────────────────
def test_bundle_round_trips_through_disk(tmp_path) -> None:
    bundle = _bundle(signature="sig", signer="acme")
    target = write_bundle(bundle, tmp_path / "bundle")
    assert (target / "manifest.json").exists()
    reloaded = load_bundle(target)
    assert verify_bundle(reloaded).valid is True


def test_loading_a_directory_without_a_manifest_raises(tmp_path) -> None:
    (tmp_path / "empty").mkdir()
    with pytest.raises(BundleVerificationError, match="no manifest.json"):
        load_bundle(tmp_path / "empty")


def test_loading_invalid_manifest_json_raises(tmp_path) -> None:
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "manifest.json").write_text("{not json")
    with pytest.raises(BundleVerificationError, match="not valid JSON"):
        load_bundle(tmp_path / "b")


def test_loading_invalid_artifact_json_raises(tmp_path) -> None:
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "manifest.json").write_text("{}")
    (tmp_path / "b" / "evidence.json").write_text("{nope")
    with pytest.raises(BundleVerificationError, match="not valid JSON"):
        load_bundle(tmp_path / "b")


def test_schema_version_is_the_documented_one() -> None:
    assert _bundle().manifest.schema_version == BUNDLE_SCHEMA_VERSION
