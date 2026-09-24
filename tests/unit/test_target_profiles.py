import json
from pathlib import Path

import pytest
import yaml

from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.target_profiles import (
    load_profiles_from_file,
    load_profiles_from_mayhem_yaml,
    require_profile,
    select_profile,
)


def _write_yaml(path: Path, data: dict):
    path.write_text(yaml.safe_dump(data))


def test_profile_parsing_valid(tmp_path):
    p = tmp_path / "profiles.yaml"
    _write_yaml(
        p,
        {
            "targets": {
                "dev": {"engine": "docker", "compose": "docker-compose.yml"},
                "prod": {"engine": "kubernetes", "namespace": "prod"},
            }
        },
    )
    profiles = load_profiles_from_file(p)
    assert profiles["dev"].engine == "docker"
    assert profiles["prod"].engine == "kubernetes"
    assert profiles["prod"].namespace == "prod"


def test_profile_strict_unknown_key_rejection(tmp_path):
    p = tmp_path / "profiles.yaml"
    _write_yaml(p, {"targets": {"dev": {"engine": "docker", "unknown_key": "oops"}}})
    with pytest.raises(SchemaValidationError):
        load_profiles_from_file(p)


def test_profile_selection_single_auto(tmp_path):
    p = tmp_path / "profiles.yaml"
    _write_yaml(p, {"targets": {"only": {"engine": "docker"}}})
    profiles = load_profiles_from_file(p)
    selected = select_profile(profiles, None)
    assert selected is not None
    assert selected.name == "only"


def test_profile_selection_ambiguity_returns_none(tmp_path):
    p = tmp_path / "profiles.yaml"
    _write_yaml(p, {"targets": {"dev": {"engine": "docker"}, "prod": {"engine": "docker"}}})
    profiles = load_profiles_from_file(p)
    assert select_profile(profiles, None) is None


def test_profile_missing_target_refusal(tmp_path):
    p = tmp_path / "profiles.yaml"
    _write_yaml(p, {"targets": {"dev": {"engine": "docker"}}})
    profiles = load_profiles_from_file(p)
    with pytest.raises(SchemaValidationError, match="unknown target"):
        select_profile(profiles, "missing")


def test_require_profile_mutating_needs_explicit(tmp_path):
    p = tmp_path / "profiles.yaml"
    _write_yaml(p, {"targets": {"dev": {"engine": "docker"}, "prod": {"engine": "docker"}}})
    profiles = load_profiles_from_file(p)
    with pytest.raises(SchemaValidationError, match="--target is required"):
        require_profile(profiles, None, mutating=True)
    ok = require_profile(profiles, "dev", mutating=True)
    assert ok is not None and ok.name == "dev"


def test_profile_environment_isolation(tmp_path):
    p = tmp_path / "profiles.yaml"
    _write_yaml(
        p,
        {
            "targets": {
                "dev": {"engine": "docker", "compose": "a.yml"},
                "prod": {"engine": "kubernetes", "namespace": "prod"},
            }
        },
    )
    profiles = load_profiles_from_file(p)
    assert profiles["dev"].compose == "a.yml"
    assert profiles["prod"].namespace == "prod"
    assert profiles["dev"].namespace is None


def test_profile_inheritance_safe_defaults(tmp_path):
    p = tmp_path / "profiles.yaml"
    _write_yaml(
        p,
        {
            "targets": {
                "base": {"engine": "docker", "policy": "low"},
                "dev": {"extends": "base", "namespace": "dev-ns"},
            }
        },
    )
    profiles = load_profiles_from_file(p)
    assert profiles["dev"].engine == "docker"
    assert profiles["dev"].namespace == "dev-ns"


def test_profile_inheritance_prohibits_credentials(tmp_path):
    p = tmp_path / "profiles.yaml"
    _write_yaml(p, {"targets": {"bad": {"engine": "docker", "password": "secret"}}})
    with pytest.raises(SchemaValidationError, match="credential"):
        load_profiles_from_file(p)


def test_profile_visible_in_preflight(tmp_path):
    from click.testing import CliRunner

    from mayhem.cli.app import app

    mayhem_yaml = tmp_path / "mayhem.yaml"
    mayhem_yaml.write_text("apiVersion: mayhem/v1\ntargets:\n  dev:\n    engine: docker\n")
    runner = CliRunner()
    with runner.isolated_filesystem():
        import shutil

        shutil.copy(str(mayhem_yaml), "mayhem.yaml")
        result = runner.invoke(
            app,
            ["--config", "mayhem.yaml", "--target", "dev", "doctor", "--json"],
        )
        payload = json.loads(result.output)
        assert any(r["id"] == "config.target.selected" for r in payload["diagnostics"])


def test_load_from_mayhem_yaml(tmp_path):
    mayhem = tmp_path / "mayhem.yaml"
    mayhem.write_text("apiVersion: mayhem/v1\ntargets:\n  dev:\n    engine: docker\n")
    profiles = load_profiles_from_mayhem_yaml(mayhem)
    assert "dev" in profiles
    assert profiles["dev"].engine == "docker"
