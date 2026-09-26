"""v0.9.0 task 4 — target profiles are first-class configuration.

``mayhem.yaml`` carries its target profiles in ``targets:`` (or the
``profiles:`` alias) and ``load_config`` returns them as validated
:class:`~mayhem.domain.target_profiles.TargetProfile` objects, merged per
profile name across layers. These tests pin the configuration contract: the
field is accepted (not rejected as an unknown key), the alias normalizes, the
singular ``target:`` is untouched, later layers replace a same-named profile
whole, provenance is recorded, and a drill spec's own ``targets:`` block is
never mistaken for profiles.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mayhem.config import (
    API_VERSION,
    MayhemConfig,
    explain_config,
    load_config,
    select_target_profile,
    target_profiles,
)
from mayhem.domain.errors import SchemaValidationError

BASE = f"""
apiVersion: {API_VERSION}
targets:
  dev:
    engine: docker
    compose: docker-compose.yml
    namespace: dev-ns
  prod:
    engine: kubernetes
    context: prod-eu
    namespace: checkout
"""


def _write(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


# --- the field loads ---------------------------------------------------------


def test_mayhem_yaml_with_targets_loads_through_the_config_model(tmp_path: Path):
    base = _write(tmp_path / "mayhem.yaml", BASE)
    cfg, _sources = load_config(config_path=base, environ={})
    assert sorted(cfg.targets) == ["dev", "prod"]
    assert cfg.targets["dev"].engine == "docker"
    assert cfg.targets["dev"].compose == "docker-compose.yml"
    assert cfg.targets["prod"].engine == "kubernetes"
    assert cfg.targets["prod"].context == "prod-eu"
    assert cfg.targets["prod"].namespace == "checkout"
    # The mapping key is the profile's identity.
    assert all(profile.name == name for name, profile in cfg.targets.items())


def test_profiles_alias_normalizes_into_targets(tmp_path: Path):
    base = _write(
        tmp_path / "mayhem.yaml",
        f"apiVersion: {API_VERSION}\nprofiles:\n  dev:\n    engine: podman\n",
    )
    cfg, _sources = load_config(config_path=base, environ={})
    assert list(cfg.targets) == ["dev"]
    assert cfg.targets["dev"].engine == "podman"
    # The alias is not a second field: it serializes under the canonical name.
    assert "profiles" not in cfg.model_dump(mode="json", by_alias=True)
    assert "targets" in cfg.model_dump(mode="json", by_alias=True)


def test_singular_target_field_is_unchanged(tmp_path: Path):
    base = _write(
        tmp_path / "mayhem.yaml",
        f"apiVersion: {API_VERSION}\n"
        "target:\n  containers: [api, db]\n"
        "targets:\n  dev:\n    engine: docker\n",
    )
    cfg, _sources = load_config(config_path=base, environ={})
    assert cfg.target.containers == ["api", "db"]
    assert list(cfg.targets) == ["dev"]


def test_defaults_carry_no_profiles():
    cfg, sources = load_config(environ={})
    assert cfg.targets == {}
    assert sources["targets"] == "defaults"


def test_profiles_construct_programmatically_under_either_name():
    # `profiles` is a validation alias, so it is accepted on input the same way
    # the YAML reader accepts it; the canonical field name works too.
    by_name = MayhemConfig.model_validate({"targets": {"dev": {"engine": "docker"}}})
    by_alias = MayhemConfig.model_validate({"profiles": {"dev": {"engine": "docker"}}})
    assert by_name.targets["dev"] == by_alias.targets["dev"]
    assert by_name.targets["dev"].name == "dev"
    assert MayhemConfig(targets=by_name.targets).targets == by_name.targets


def test_unknown_keys_are_still_rejected(tmp_path: Path):
    base = _write(tmp_path / "mayhem.yaml", f"apiVersion: {API_VERSION}\nfrobnicate: true\n")
    with pytest.raises(SchemaValidationError):
        load_config(config_path=base, environ={})


# --- layering ----------------------------------------------------------------


def test_layers_merge_per_profile_name(tmp_path: Path):
    base = _write(tmp_path / "mayhem.yaml", BASE)
    overlay = _write(
        tmp_path / "mayhem.staging.yaml",
        f"""
apiVersion: {API_VERSION}
targets:
  prod:
    engine: podman
  staging:
    engine: kubernetes
    context: staging-eu
""",
    )
    assert overlay.exists()
    cfg, sources = load_config(config_path=base, profile="staging", environ={})
    assert sorted(cfg.targets) == ["dev", "prod", "staging"]
    # A later layer replaces a same-named profile whole — it does not deep-merge
    # into it, so the base layer's context/namespace are gone, not preserved.
    assert cfg.targets["prod"].engine == "podman"
    assert cfg.targets["prod"].context is None
    assert cfg.targets["prod"].namespace is None
    # A profile the overlay does not mention is untouched.
    assert cfg.targets["dev"].compose == "docker-compose.yml"
    assert sources["targets"] == "profile:staging"


def test_provenance_tracks_the_last_layer_that_supplied_profiles(tmp_path: Path):
    base = _write(tmp_path / "mayhem.yaml", BASE)
    _cfg, sources = load_config(config_path=base, environ={})
    assert sources["targets"] == "file"
    cfg, sources = load_config(
        config_path=base, cli_overrides={"targets": {"ci": {"engine": "docker"}}}, environ={}
    )
    assert sources["targets"] == "cli"
    assert "ci" in cfg.targets


def test_a_profile_may_inherit_from_a_profile_in_an_earlier_layer(tmp_path: Path):
    base = _write(
        tmp_path / "mayhem.yaml",
        f"""
apiVersion: {API_VERSION}
targets:
  base:
    engine: docker
    policy: low
""",
    )
    _write(
        tmp_path / "mayhem.derived.yaml",
        f"""
apiVersion: {API_VERSION}
targets:
  dev:
    extends: base
    namespace: dev-ns
""",
    )
    cfg, _sources = load_config(config_path=base, profile="derived", environ={})
    assert cfg.targets["dev"].engine == "docker"
    assert cfg.targets["dev"].policy == "low"
    assert cfg.targets["dev"].namespace == "dev-ns"


def test_the_same_name_in_targets_and_profiles_of_one_layer_is_a_duplicate(tmp_path: Path):
    base = _write(
        tmp_path / "mayhem.yaml",
        f"""
apiVersion: {API_VERSION}
targets:
  dev:
    engine: docker
profiles:
  dev:
    engine: podman
""",
    )
    with pytest.raises(SchemaValidationError, match="duplicate target name"):
        load_config(config_path=base, environ={})


def test_a_profile_only_layer_validates_too(tmp_path: Path):
    base = _write(tmp_path / "mayhem.yaml", f"apiVersion: {API_VERSION}\n")
    _write(
        tmp_path / "mayhem.bad.yaml",
        f"apiVersion: {API_VERSION}\ntargets:\n  dev:\n    engine: containerd\n",
    )
    with pytest.raises(SchemaValidationError, match="invalid engine"):
        load_config(config_path=base, profile="bad", environ={})


def test_a_credential_key_in_a_profile_is_refused(tmp_path: Path):
    base = _write(
        tmp_path / "mayhem.yaml",
        f"apiVersion: {API_VERSION}\ntargets:\n  dev:\n    engine: docker\n    token: leak\n",
    )
    with pytest.raises(SchemaValidationError, match="credential key forbidden"):
        load_config(config_path=base, environ={})


def test_a_non_mapping_targets_block_is_refused(tmp_path: Path):
    base = _write(tmp_path / "mayhem.yaml", f"apiVersion: {API_VERSION}\ntargets: [dev]\n")
    with pytest.raises(SchemaValidationError, match="must be a mapping"):
        load_config(config_path=base, environ={})


# --- a drill spec's targets: block is never a profile block -------------------

DRILL_SPEC = f"""
apiVersion: {API_VERSION}
kind: drill
name: checkout-chaos
config:
  log_level: DEBUG
targets:
  api:
    runtime: docker
    faults:
      - action: net.latency
        target:
          name: api
execution:
  - action: wait
    duration: 1.0
"""


def test_drill_spec_targets_are_not_target_profiles(tmp_path: Path):
    spec = _write(tmp_path / "mayhem.yaml", DRILL_SPEC)
    cfg, _sources = load_config(config_path=spec, environ={})
    assert cfg.targets == {}
    # The spec's own configuration vocabulary still projects onto the config.
    assert cfg.log_level == "DEBUG"
    assert select_target_profile(cfg, "api") is None
    assert target_profiles(cfg) == {}


def test_a_config_document_with_the_same_shape_is_still_validated(tmp_path: Path):
    """The spec guard is the ``kind:`` marker, not the presence of ``targets:``.

    Without that marker the block is a target-profile block, so a
    drill-shaped key (``runtime:``) is refused as an unknown profile key rather
    than quietly ignored.
    """
    base = _write(
        tmp_path / "mayhem.yaml",
        f"apiVersion: {API_VERSION}\n"
        "targets:\n"
        "  api:\n"
        "    runtime: docker\n",
    )
    with pytest.raises(SchemaValidationError, match="invalid profile"):
        load_config(config_path=base, environ={})


# --- the selection seam ------------------------------------------------------


def test_select_target_profile_infers_a_single_profile(tmp_path: Path):
    base = _write(
        tmp_path / "mayhem.yaml",
        f"apiVersion: {API_VERSION}\ntargets:\n  dev:\n    engine: docker\n",
    )
    cfg, _sources = load_config(config_path=base, environ={})
    selected = select_target_profile(cfg, None)
    assert selected is not None and selected.name == "dev"


def test_select_target_profile_refuses_to_guess(tmp_path: Path):
    base = _write(tmp_path / "mayhem.yaml", BASE)
    cfg, _sources = load_config(config_path=base, environ={})
    assert select_target_profile(cfg, None) is None
    prod = select_target_profile(cfg, "prod")
    assert prod is not None and prod.engine == "kubernetes"
    with pytest.raises(SchemaValidationError, match="unknown target"):
        select_target_profile(cfg, "staging")


def test_target_profiles_returns_a_copy(tmp_path: Path):
    base = _write(
        tmp_path / "mayhem.yaml",
        f"apiVersion: {API_VERSION}\ntargets:\n  dev:\n    engine: docker\n",
    )
    cfg, _sources = load_config(config_path=base, environ={})
    copied = target_profiles(cfg)
    copied.pop("dev")
    assert "dev" in cfg.targets


# --- machine-readable explanation -------------------------------------------


def test_explain_reports_the_profiles_with_provenance(tmp_path: Path):
    base = _write(tmp_path / "mayhem.yaml", BASE)
    cfg, sources = load_config(config_path=base, environ={})
    rows = explain_config(cfg, sources)
    row = next(r for r in rows if r["field"] == "targets")
    assert row["source"] == "file"
    assert row["safe_for_mutation"] is False
    assert sorted(row["value"]) == ["dev", "prod"]
    assert row["value"]["prod"]["engine"] == "kubernetes"


def test_explain_reports_an_empty_profile_section_by_default():
    cfg, sources = load_config(environ={})
    row = next(r for r in explain_config(cfg, sources) if r["field"] == "targets")
    assert row["value"] == {}
    assert row["source"] == "defaults"


def test_snapshots_round_trip_the_profiles(tmp_path: Path):
    base = _write(tmp_path / "mayhem.yaml", BASE)
    cfg, _sources = load_config(config_path=base, environ={})
    reloaded = MayhemConfig.model_validate_json(cfg.model_dump_json())
    assert reloaded.targets == cfg.targets
    assert select_target_profile(reloaded, "dev") == cfg.targets["dev"]
