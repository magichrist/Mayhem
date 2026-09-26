"""v0.9.0 task 4 — one pure validator behind every target-profile reader.

``parse_profiles_mapping`` is the single place the target-profile vocabulary is
validated. These tests pin the rules it enforces (valid profiles, inheritance,
duplicate names, invalid engines, credential keys, multiple-profile selection)
and the boundary that must never be crossed: a drill spec's own ``targets:``
block is its *logical targets* (k-plan-1 §1.2), not target profiles.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.target_profiles import (
    is_spec_document,
    load_profiles_from_file,
    load_profiles_from_mayhem_yaml,
    parse_profiles_mapping,
    require_profile,
    select_profile,
)

VALID_RAW: dict[str, dict[str, object]] = {
    "dev": {"engine": "docker", "compose": "docker-compose.yml"},
    "prod": {"engine": "kubernetes", "context": "prod-eu", "namespace": "checkout"},
}


def _write_yaml(path: Path, data: dict) -> Path:
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return path


# --- valid profiles ----------------------------------------------------------


def test_parse_valid_profiles():
    profiles = parse_profiles_mapping(VALID_RAW)
    assert sorted(profiles) == ["dev", "prod"]
    assert profiles["dev"].engine == "docker"
    assert profiles["dev"].compose == "docker-compose.yml"
    assert profiles["prod"].context == "prod-eu"
    assert profiles["prod"].namespace == "checkout"


def test_parse_is_pure_and_returns_independent_objects():
    first = parse_profiles_mapping(VALID_RAW)
    second = parse_profiles_mapping(VALID_RAW)
    assert first == second
    assert first["dev"] is not second["dev"]


def test_empty_and_absent_blocks_are_not_errors():
    assert parse_profiles_mapping(None) == {}
    assert parse_profiles_mapping({}) == {}
    # A profile declared as `name:` with no body is the default profile.
    assert parse_profiles_mapping({"bare": None})["bare"].engine == "docker"


def test_profile_name_is_taken_from_the_mapping_key():
    profiles = parse_profiles_mapping({"dev": {"name": "ignored", "engine": "podman"}})
    assert profiles["dev"].name == "dev"
    assert "ignored" not in profiles


# --- inheritance -------------------------------------------------------------


def test_inheritance_resolves_from_a_single_parent():
    profiles = parse_profiles_mapping(
        {
            "base": {"engine": "docker", "policy": "low", "compose": "a.yml"},
            "dev": {"extends": "base", "namespace": "dev-ns"},
        }
    )
    assert profiles["dev"].engine == "docker"
    assert profiles["dev"].policy == "low"
    assert profiles["dev"].compose == "a.yml"
    assert profiles["dev"].namespace == "dev-ns"
    assert profiles["dev"].extends is None


def test_inheritance_from_an_unknown_parent_is_refused():
    with pytest.raises(SchemaValidationError, match="extends unknown profile"):
        parse_profiles_mapping({"dev": {"extends": "ghost"}})


def test_inheritance_depth_beyond_one_is_refused():
    with pytest.raises(SchemaValidationError, match="depth"):
        parse_profiles_mapping(
            {
                "root": {"engine": "docker"},
                "mid": {"extends": "root"},
                "leaf": {"extends": "mid"},
            }
        )


def test_inherited_parent_may_not_smuggle_a_credential():
    with pytest.raises(SchemaValidationError, match="credential"):
        parse_profiles_mapping(
            {
                "base": {"engine": "docker", "observability": {"api_key": "leak"}},
                "dev": {"extends": "base"},
            }
        )


# --- duplicates --------------------------------------------------------------


def test_a_name_maps_to_exactly_one_profile():
    """The mapping key is the identity; a profile body cannot rename or add one."""
    profiles = parse_profiles_mapping({"dev": {"engine": "docker"}})
    assert list(profiles) == ["dev"]
    assert profiles["dev"].name == "dev"
    # Declaring a name that is not a mapping is refused rather than coerced.
    with pytest.raises(SchemaValidationError, match="must be a mapping"):
        parse_profiles_mapping({"dev": "engine: docker"})


# --- invalid engines and unknown keys ----------------------------------------


def test_invalid_engine_is_refused():
    with pytest.raises(SchemaValidationError, match="invalid engine"):
        parse_profiles_mapping({"dev": {"engine": "containerd"}})


@pytest.mark.parametrize("engine", ["docker", "podman", "kubernetes"])
def test_every_supported_engine_is_accepted(engine: str):
    assert parse_profiles_mapping({"t": {"engine": engine}})["t"].engine == engine


def test_unknown_key_is_refused():
    with pytest.raises(SchemaValidationError, match="invalid profile"):
        parse_profiles_mapping({"dev": {"engine": "docker", "frobnicate": True}})


def test_non_mapping_block_is_refused():
    with pytest.raises(SchemaValidationError, match="must be a mapping"):
        parse_profiles_mapping(["dev"])


def test_non_mapping_profile_is_refused():
    with pytest.raises(SchemaValidationError, match="must be a mapping"):
        parse_profiles_mapping({"dev": "docker"})


def test_invalid_profile_name_is_refused():
    with pytest.raises(SchemaValidationError, match="invalid target name"):
        parse_profiles_mapping({"bad name": {"engine": "docker"}})


# --- credentials -------------------------------------------------------------


@pytest.mark.parametrize("key", ["password", "secret", "token", "credentials", "api_key"])
def test_credential_keys_are_refused(key: str):
    with pytest.raises(SchemaValidationError, match="credential key forbidden"):
        parse_profiles_mapping({"dev": {"engine": "docker", key: "leak"}})


def test_credential_keys_are_refused_when_nested():
    with pytest.raises(SchemaValidationError, match="credential key forbidden"):
        parse_profiles_mapping({"dev": {"observability": {"token": "leak"}}})


# --- multiple-profile selection ----------------------------------------------


def test_single_profile_is_selected_without_a_name():
    profiles = parse_profiles_mapping({"only": {"engine": "docker"}})
    selected = select_profile(profiles, None)
    assert selected is not None
    assert selected.name == "only"


def test_multiple_profiles_are_ambiguous_and_select_nothing():
    profiles = parse_profiles_mapping(
        {"dev": {"engine": "docker"}, "prod": {"engine": "kubernetes"}}
    )
    assert select_profile(profiles, None) is None


def test_named_selection_among_multiple_profiles():
    profiles = parse_profiles_mapping(
        {"dev": {"engine": "docker"}, "prod": {"engine": "kubernetes"}}
    )
    selected = select_profile(profiles, "prod")
    assert selected is not None and selected.engine == "kubernetes"


def test_unknown_name_is_refused_with_the_available_names():
    profiles = parse_profiles_mapping(
        {"dev": {"engine": "docker"}, "prod": {"engine": "kubernetes"}}
    )
    with pytest.raises(SchemaValidationError, match="unknown target"):
        select_profile(profiles, "staging")


def test_mutating_operations_require_an_explicit_name_when_ambiguous():
    profiles = parse_profiles_mapping(
        {"dev": {"engine": "docker"}, "prod": {"engine": "kubernetes"}}
    )
    with pytest.raises(SchemaValidationError, match="--target is required"):
        require_profile(profiles, None, mutating=True)
    assert require_profile(profiles, "dev", mutating=True) is not None


# --- readers delegate to the validator ---------------------------------------


def test_profile_file_delegates_to_the_validator(tmp_path: Path):
    path = _write_yaml(tmp_path / "profiles.yaml", {"targets": VALID_RAW})
    assert load_profiles_from_file(path) == parse_profiles_mapping(VALID_RAW)


def test_profile_file_accepts_the_profiles_alias(tmp_path: Path):
    path = _write_yaml(tmp_path / "profiles.yaml", {"profiles": VALID_RAW})
    assert sorted(load_profiles_from_file(path)) == ["dev", "prod"]


def test_profile_file_accepts_a_bare_profile_document(tmp_path: Path):
    path = _write_yaml(tmp_path / "bare.yaml", VALID_RAW)
    assert sorted(load_profiles_from_file(path)) == ["dev", "prod"]


def test_mayhem_yaml_reader_needs_no_api_version(tmp_path: Path):
    path = _write_yaml(tmp_path / "mayhem.yaml", {"targets": VALID_RAW})
    assert sorted(load_profiles_from_mayhem_yaml(path)) == ["dev", "prod"]


def test_missing_mayhem_yaml_is_not_an_error(tmp_path: Path):
    assert load_profiles_from_mayhem_yaml(tmp_path / "absent.yaml") == {}


def test_mayhem_yaml_error_messages_name_the_source(tmp_path: Path):
    path = _write_yaml(tmp_path / "mayhem.yaml", {"targets": {"dev": {"engine": "nope"}}})
    with pytest.raises(SchemaValidationError, match="mayhem.yaml"):
        load_profiles_from_mayhem_yaml(path)


# --- a drill spec's targets: block is never a profile block -------------------

DRILL_SPEC: dict[str, object] = {
    "apiVersion": "mayhem/v1",
    "kind": "drill",
    "name": "checkout-chaos",
    "targets": {
        "api": {
            "runtime": "docker",
            "faults": [{"action": "net.latency", "target": {"name": "api"}}],
        },
        "db": {"runtime": "docker"},
    },
    "execution": [{"action": "wait", "duration": 1.0}],
}


def test_is_spec_document_detects_a_drill_spec():
    assert is_spec_document(DRILL_SPEC) is True
    assert is_spec_document({"apiVersion": "mayhem/v1", "targets": VALID_RAW}) is False


def test_mayhem_yaml_reader_ignores_a_drill_specs_targets(tmp_path: Path):
    path = _write_yaml(tmp_path / "mayhem.yaml", DRILL_SPEC)
    assert load_profiles_from_mayhem_yaml(path) == {}


def test_profile_file_reader_ignores_a_drill_specs_targets(tmp_path: Path):
    path = _write_yaml(tmp_path / "spec.yaml", DRILL_SPEC)
    assert load_profiles_from_file(path) == {}


def test_a_config_document_still_reads_its_targets(tmp_path: Path):
    """The guard is the spec marker, not the presence of ``targets:``."""
    path = _write_yaml(
        tmp_path / "mayhem.yaml", {"apiVersion": "mayhem/v1", "targets": VALID_RAW}
    )
    assert sorted(load_profiles_from_mayhem_yaml(path)) == ["dev", "prod"]
