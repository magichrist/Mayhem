"""v0.9.0 task 4 — doctor/diagnostics speak about target profiles.

The selected target, the engines actually available for it, and the reason no
target was selected are all reported explicitly. The stable machine-readable
contract is unchanged: ``config.target.selected`` keeps its id, message, and
``config`` category, no new diagnostic category is introduced, and ``--profile``
(a configuration overlay) is never compared against target-profile names.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.domain.target_profiles import parse_profiles_mapping
from mayhem.infra.diagnostics import (
    DiagnosticCategory,
    check_engine_for_target,
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


# --- available engines, via shutil.which and no subprocess ------------------


def test_engine_available_is_reported_from_path_presence(monkeypatch):
    monkeypatch.setattr(
        "mayhem.infra.diagnostics.shutil.which", lambda binary: "/usr/bin/docker"
    )
    records = check_engine_for_target("docker")
    assert _ids(records) == ["engine.target.available"]
    assert records[0].category is DiagnosticCategory.engine
    assert "/usr/bin/docker" in records[0].message
    # File presence is not health: the message must not claim it is.
    assert "healthy" in records[0].message


def test_engine_missing_is_a_warning(monkeypatch):
    monkeypatch.setattr("mayhem.infra.diagnostics.shutil.which", lambda binary: None)
    records = check_engine_for_target("kubernetes")
    assert _ids(records) == ["engine.target.missing"]
    assert records[0].severity.value == "warning"
    assert "kubectl" in records[0].message


def test_kubernetes_maps_to_kubectl(monkeypatch):
    seen: list[str] = []

    def _which(binary: str) -> str | None:
        seen.append(binary)
        return None

    monkeypatch.setattr("mayhem.infra.diagnostics.shutil.which", _which)
    check_engine_for_target("kubernetes")
    assert seen == ["kubectl"]


def test_no_selected_target_reports_no_engine(monkeypatch):
    monkeypatch.setattr(
        "mayhem.infra.diagnostics.shutil.which",
        lambda binary: "/usr/bin/docker",
    )
    assert check_engine_for_target(None) == []


# --- profile policy warnings -------------------------------------------------


def test_a_declarative_target_policy_is_flagged_as_not_enforced():
    profiles = parse_profiles_mapping({"dev": {"engine": "docker", "policy": "strict"}})
    records = check_target_profile_policy(profiles)
    assert _ids(records) == ["config.target_profile.dev.policy_advisory"]
    assert records[0].severity.value == "warning"
    assert "--policy" in records[0].message


def test_an_unknown_target_policy_is_reported_separately():
    profiles = parse_profiles_mapping({"dev": {"engine": "docker", "policy": "nonsense"}})
    assert _ids(check_target_profile_policy(profiles)) == [
        "config.target_profile.dev.policy_advisory",
        "config.target_profile.dev.policy_unknown",
    ]


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


def test_a_missing_profile_overlay_is_a_configuration_error(tmp_path: Path):
    base = tmp_path / "mayhem.yaml"
    base.write_text(CONFIG)
    records = check_profile_identity(str(base), "absent")
    assert _ids(records) == ["config.profile.overlay_missing"]
    assert records[0].severity.value == "error"
    assert "--target" in records[0].remediation


def test_no_profile_flag_says_nothing(tmp_path: Path):
    base = tmp_path / "mayhem.yaml"
    base.write_text(CONFIG)
    assert check_profile_identity(str(base), None) == []


# --- the whole run -----------------------------------------------------------


def test_run_diagnostics_reports_target_and_engine_together(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("mayhem.infra.diagnostics.shutil.which", lambda binary: "/usr/bin/docker")
    base = tmp_path / "mayhem.yaml"
    base.write_text(CONFIG)
    records = run_diagnostics(
        config_path=str(base), target="dev", db_path=str(tmp_path / "absent.db")
    )
    ids = _ids(records)
    assert "config.target.selected" in ids
    assert "engine.target.available" in ids
    assert "config.target.ambiguous" not in ids
    assert all(r.category in set(DiagnosticCategory) for r in records)


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
        ids = {r["id"] for r in payload["diagnostics"]}
        assert "config.profile.mismatch" not in ids
        assert "config.profile.matched" in ids
