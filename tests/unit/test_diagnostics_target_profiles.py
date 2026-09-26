"""v0.9.0 task 4 — doctor/diagnostics speak about target profiles.

The selected target, the engine it needs, and the reason no target was selected
are reported explicitly, and the target is resolved from the *effective*
configuration (base document plus the ``--profile`` overlay) — the same one
topology and preflight resolve. The stable machine-readable contract is
unchanged: ``config.target.selected`` keeps its id, message, and ``config``
category, ``config.profile.mismatch`` keeps its id for a `--profile` that does
not resolve, no diagnostic category is added, and the engine family stays one
record per binary.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.domain.target_profiles import parse_profiles_mapping
from mayhem.infra.diagnostics import (
    DiagnosticCategory,
    check_engine,
    check_profile_identity,
    check_target_profile_policy,
    check_target_profiles,
    check_target_selection,
    run_diagnostics,
)

CONFIG = """\
apiVersion: mayhem/v1
targets:
  dev:
    engine: docker
  prod:
    engine: kubernetes
    namespace: checkout
"""


def _ids(records) -> list[str]:
    return [record.id for record in records]


# --- the selected target is reported explicitly ------------------------------


def test_an_explicitly_selected_target_is_reported(tmp_path: Path):
    path = tmp_path / "mayhem.yaml"
    path.write_text(CONFIG)
    records = check_target_selection(str(path), "dev")
    selected = [r for r in records if r.id == "config.target.selected"]
    assert len(selected) == 1
    assert selected[0].message == "target 'dev' selected (engine=docker)"
    assert selected[0].category is DiagnosticCategory.config
    assert selected[0].severity.value == "info"
    assert selected[0].evidence_ref == "dev"


def test_a_single_configured_target_is_inferred_and_reported(tmp_path: Path):
    path = tmp_path / "mayhem.yaml"
    path.write_text("apiVersion: mayhem/v1\ntargets:\n  only:\n    engine: podman\n")
    records = check_target_selection(str(path), None)
    assert "config.target.selected" in _ids(records)
    assert "engine=podman" in records[0].message


def test_several_targets_without_a_selection_are_ambiguous(tmp_path: Path):
    path = tmp_path / "mayhem.yaml"
    path.write_text(CONFIG)
    records = check_target_selection(str(path), None)
    assert "config.target.selected" not in _ids(records)
    ambiguous = [r for r in records if r.id == "config.target.ambiguous"]
    assert len(ambiguous) == 1
    assert ambiguous[0].severity.value == "warning"
    assert "dev" in ambiguous[0].message and "prod" in ambiguous[0].message


def test_no_configured_targets_selects_nothing_and_warns_not(tmp_path: Path):
    path = tmp_path / "mayhem.yaml"
    path.write_text("apiVersion: mayhem/v1\n")
    assert check_target_selection(str(path), None) == []


def test_an_unknown_target_is_not_reported_as_selected(tmp_path: Path):
    path = tmp_path / "mayhem.yaml"
    path.write_text(CONFIG)
    assert "config.target.selected" not in _ids(check_target_selection(str(path), "staging"))


def test_an_invalid_profile_block_is_reported_as_a_target_error(tmp_path: Path):
    path = tmp_path / "mayhem.yaml"
    path.write_text("apiVersion: mayhem/v1\ntargets:\n  dev:\n    engine: nope\n")
    records = check_target_selection(str(path), "dev")
    assert _ids(records) == ["config.target.error"]
    assert records[0].severity.value == "error"


# --- the profile overlay is part of the effective configuration ---------------


def test_a_target_declared_only_in_the_overlay_is_reported(tmp_path: Path):
    base = tmp_path / "mayhem.yaml"
    base.write_text("apiVersion: mayhem/v1\ntargets:\n  dev:\n    engine: docker\n")
    (tmp_path / "mayhem.staging.yaml").write_text(
        "apiVersion: mayhem/v1\ntargets:\n  edge:\n    engine: kubernetes\n"
    )
    assert "config.target_profile.edge" in _ids(check_target_profiles(str(base), "staging"))
    assert "config.target_profile.edge" not in _ids(check_target_profiles(str(base)))
    records = check_target_selection(str(base), "edge", profile="staging")
    assert "config.target.selected" in _ids(records)
    assert "engine=kubernetes" in records[0].message


def test_the_overlay_replaces_a_same_named_profile_whole(tmp_path: Path):
    base = tmp_path / "mayhem.yaml"
    base.write_text(CONFIG)
    (tmp_path / "mayhem.staging.yaml").write_text(
        "apiVersion: mayhem/v1\ntargets:\n  prod:\n    engine: podman\n"
    )
    records = check_target_selection(str(base), "prod", profile="staging")
    assert records[0].message == "target 'prod' selected (engine=podman)"


# --- engines: one record per binary, annotated for the selected target -------


def test_engine_records_stay_one_per_binary(monkeypatch):
    monkeypatch.setattr(
        "mayhem.infra.diagnostics.shutil.which", lambda binary: f"/usr/bin/{binary}"
    )
    records = check_engine()
    # Exactly one record per binary — no second, target-specific availability
    # family. (The Kubernetes adapter record is environment-dependent and is
    # not asserted here.)
    assert _ids(records)[:3] == [
        "engine.docker.found",
        "engine.podman.found",
        "engine.kubectl.found",
    ]
    assert len([r for r in records if r.id.startswith("engine.") and "kubernetes" not in r.id]) == 3


def test_the_selected_target_engine_is_annotated_not_duplicated(monkeypatch):
    monkeypatch.setattr(
        "mayhem.infra.diagnostics.shutil.which", lambda binary: f"/usr/bin/{binary}"
    )
    records = check_engine("kubernetes")
    # Still three records — one per binary — and only `kubectl` is marked as
    # the one the selected target needs.
    assert _ids(records).count("engine.kubectl.found") == 1
    assert "engine.target" not in " ".join(_ids(records))
    kubectl = next(r for r in records if r.id == "engine.kubectl.found")
    assert "required by the selected target (engine=kubernetes)" in kubectl.message
    assert "does not prove" in kubectl.message
    for record in records:
        if record.id == "engine.docker.found":
            assert "required by the selected target" not in record.message


def test_a_missing_engine_the_selected_target_needs_says_so(monkeypatch):
    monkeypatch.setattr("mayhem.infra.diagnostics.shutil.which", lambda binary: None)
    records = check_engine("docker")
    assert _ids(records)[:3] == [
        "engine.docker.missing",
        "engine.podman.missing",
        "engine.kubectl.missing",
    ]
    docker = next(r for r in records if r.id == "engine.docker.missing")
    assert "the selected target's engine 'docker' cannot be used" in docker.message
    assert docker.remediation == (
        "install docker or select a target profile whose engine is present"
    )
    podman = next(r for r in records if r.id == "engine.podman.missing")
    assert "selected target" not in podman.message


def test_no_selected_target_leaves_the_engine_records_unannotated(monkeypatch):
    monkeypatch.setattr("mayhem.infra.diagnostics.shutil.which", lambda binary: None)
    for record in check_engine(None):
        assert "selected target" not in record.message
        assert "selected target" not in record.remediation


# --- an unresolvable target policy is the only thing worth reporting --------


def test_a_resolvable_target_policy_is_not_reported():
    profiles = parse_profiles_mapping({"dev": {"engine": "docker", "policy": "strict"}})
    assert check_target_profile_policy(profiles) == []


def test_an_unknown_target_policy_is_reported_once():
    profiles = parse_profiles_mapping({"dev": {"engine": "docker", "policy": "nonsense"}})
    records = check_target_profile_policy(profiles)
    assert _ids(records) == ["config.target_profile.dev.policy_unknown"]
    assert records[0].severity.value == "warning"
    assert records[0].category is DiagnosticCategory.config
    assert "nonsense" in records[0].message
    assert "available" in records[0].message


def test_a_profile_without_a_policy_says_nothing():
    profiles = parse_profiles_mapping({"dev": {"engine": "docker"}})
    assert check_target_profile_policy(profiles) == []


# --- --profile is a configuration overlay, not a target profile -------------


def test_profile_overlay_is_not_compared_against_target_names(tmp_path: Path):
    base = tmp_path / "mayhem.yaml"
    base.write_text(CONFIG)
    (tmp_path / "mayhem.staging.yaml").write_text("apiVersion: mayhem/v1\n")
    records = check_profile_identity(str(base), "staging")
    assert _ids(records) == ["config.profile.matched"]
    assert records[0].severity.value == "info"
    assert records[0].evidence_ref == "staging"


def test_a_missing_profile_overlay_keeps_the_pre_existing_record_id(tmp_path: Path):
    """`config.profile.mismatch` stays the id; only its meaning is corrected."""
    base = tmp_path / "mayhem.yaml"
    base.write_text(CONFIG)
    (tmp_path / "mayhem.prod.yaml").write_text("apiVersion: mayhem/v1\n")
    records = check_profile_identity(str(base), "absent")
    assert _ids(records) == ["config.profile.mismatch"]
    assert records[0].severity.value == "error"
    assert records[0].evidence_ref == "absent"
    message = records[0].message
    assert "profile 'absent' not found" in message
    # The message keeps its `not found; available: …` shape and now names the
    # overlays that do exist and the file that was expected.
    assert "available: mayhem.prod.yaml" in message
    assert "mayhem.absent.yaml" in message
    assert "--target" in records[0].remediation


def test_no_profile_flag_says_nothing(tmp_path: Path):
    base = tmp_path / "mayhem.yaml"
    base.write_text(CONFIG)
    assert check_profile_identity(str(base), None) == []


# --- the whole run -----------------------------------------------------------


def test_run_diagnostics_reports_target_and_engine_together(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "mayhem.infra.diagnostics.shutil.which", lambda binary: f"/usr/bin/{binary}"
    )
    base = tmp_path / "mayhem.yaml"
    base.write_text(CONFIG)
    records = run_diagnostics(
        config_path=str(base), target="dev", db_path=str(tmp_path / "absent.db")
    )
    ids = _ids(records)
    assert "config.target.selected" in ids
    assert "engine.docker.found" in ids
    assert "config.target.ambiguous" not in ids
    assert not any(i.startswith("engine.target") for i in ids)
    assert all(r.category in set(DiagnosticCategory) for r in records)


def test_run_diagnostics_resolves_the_overlay(tmp_path: Path):
    base = tmp_path / "mayhem.yaml"
    base.write_text(CONFIG)
    (tmp_path / "mayhem.staging.yaml").write_text(
        "apiVersion: mayhem/v1\ntargets:\n  edge:\n    engine: kubernetes\n"
    )
    records = run_diagnostics(
        config_path=str(base),
        profile="staging",
        target="edge",
        db_path=str(tmp_path / "absent.db"),
    )
    ids = _ids(records)
    assert "config.target.selected" in ids
    assert "config.target_profile.edge" in ids
    assert "config.profile.matched" in ids


def test_check_target_profiles_still_reports_a_valid_block(tmp_path: Path):
    base = tmp_path / "mayhem.yaml"
    base.write_text(CONFIG)
    ids = _ids(check_target_profiles(str(base)))
    assert "config.target_profile.dev" in ids
    assert "config.target_profile.prod" in ids


# --- the doctor command ------------------------------------------------------


def test_doctor_reports_the_selected_target_exactly_once(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        (Path("mayhem.yaml")).write_text(CONFIG)
        result = runner.invoke(
            app, ["--config", "mayhem.yaml", "--target", "dev", "doctor", "--json"]
        )
        payload = json.loads(result.output)
        selected = [r for r in payload["diagnostics"] if r["id"] == "config.target.selected"]
        assert len(selected) == 1
        assert selected[0]["category"] == "config"
        assert selected[0]["message"] == "target 'dev' selected (engine=docker)"


def test_doctor_warns_when_no_target_is_selected(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        (Path("mayhem.yaml")).write_text(CONFIG)
        result = runner.invoke(app, ["--config", "mayhem.yaml", "doctor", "--json"])
        payload = json.loads(result.output)
        ids = {r["id"] for r in payload["diagnostics"]}
        assert "config.target.ambiguous" in ids
        assert "config.target.selected" not in ids
        # An ambiguous target is a warning, not an error: the exit code is
        # driven by errors alone.
        assert result.exit_code != 4 or any(
            r["severity"] == "error" for r in payload["diagnostics"]
        )


def test_doctor_does_not_report_a_false_profile_mismatch(tmp_path, monkeypatch):
    """`--profile` names a configuration overlay, not a target profile."""
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        (Path("mayhem.yaml")).write_text(CONFIG)
        (Path("mayhem.staging.yaml")).write_text(
            "apiVersion: mayhem/v1\ntargets:\n  prod:\n    engine: podman\n"
        )
        result = runner.invoke(
            app, ["--config", "mayhem.yaml", "--profile", "staging", "doctor", "--json"]
        )
        payload = json.loads(result.output)
        by_id = {r["id"]: r for r in payload["diagnostics"]}
        assert "config.profile.matched" in by_id
        # The two target names in the base document are not "available profiles"
        # for --profile, and the overlay resolved, so there is no mismatch.
        mismatches = [r for r in payload["diagnostics"] if r["id"] == "config.profile.mismatch"]
        assert mismatches == []


def test_doctor_reports_a_missing_overlay_as_a_profile_mismatch(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        (Path("mayhem.yaml")).write_text(CONFIG)
        result = runner.invoke(
            app, ["--config", "mayhem.yaml", "--profile", "absent", "doctor", "--json"]
        )
        payload = json.loads(result.output)
        by_id = {r["id"]: r for r in payload["diagnostics"]}
        assert by_id["config.profile.mismatch"]["severity"] == "error"
        assert by_id["config.profile.mismatch"]["evidence_ref"] == "absent"
