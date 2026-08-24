"""ADR-0008: layered config, strict validation, snapshots."""
import pytest

from mayhem.config import (
    API_VERSION,
    load_config,
    snapshot_id_for,
)
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.risks import RiskLevel


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return path


def test_defaults_when_no_file(tmp_path):
    cfg, sources = load_config(config_path=None, environ={})
    assert cfg.api_version == API_VERSION
    assert cfg.storage.path == ".mayhem/state.db"
    assert all(v == "defaults" for v in sources.values())


def test_file_layer_and_profile_overlay(tmp_path):
    base = _write(tmp_path, "mayhem.yaml", f"""
apiVersion: {API_VERSION}
policy:
  risk_ceiling: medium
environment:
  name: shop
""")
    overlay = _write(tmp_path, "mayhem.staging.yaml", f"""
apiVersion: {API_VERSION}
policy:
  risk_ceiling: low
environment:
  klass: staging
""")
    assert overlay.exists()
    cfg, sources = load_config(
        config_path=base, profile="staging", environ={}
    )
    assert cfg.policy.risk_ceiling is RiskLevel.LOW  # profile wins over file
    assert cfg.environment.name == "shop"  # untouched by overlay
    assert cfg.environment.klass == "staging"
    assert sources["policy"] == "profile:staging"
    assert sources["environment"] == "profile:staging"  # last writer wins per section


def test_env_layer_only_allowlisted_keys(tmp_path):
    cfg, sources = load_config(
        environ={
            "MAYHEM_STORAGE_PATH": "/var/mayhem.db",
            "MAYHEM_POLICY_ALLOW_FAULTS": "net.latency",  # not allowlisted via env
        }
    )
    assert cfg.storage.path == "/var/mayhem.db"
    assert cfg.policy.allow_faults is None
    assert sources["storage"] == "env"


def test_cli_layer_wins(tmp_path):
    cfg, sources = load_config(
        cli_overrides={"log_level": "DEBUG"}, environ={"MAYHEM_LOG_LEVEL": "ERROR"}
    )
    assert cfg.log_level == "DEBUG"
    assert sources["log_level"] == "cli"


def test_unknown_key_rejected(tmp_path):
    bad = _write(tmp_path, "mayhem.yaml", f"""
apiVersion: {API_VERSION}
frobnicate: true
""")
    with pytest.raises(SchemaValidationError):
        load_config(config_path=bad, environ={})


def test_wrong_api_version_rejected(tmp_path):
    bad = _write(tmp_path, "mayhem.yaml", """
apiVersion: chaos/v9
""")
    with pytest.raises(SchemaValidationError, match="apiVersion"):
        load_config(config_path=bad, environ={})


def test_snapshot_id_is_content_addressed():
    cfg_a, _ = load_config(environ={})
    cfg_b, _ = load_config(environ={"MAYHEM_LOG_LEVEL": "INFO"})
    cfg_c, _ = load_config(cli_overrides={"log_level": "WARNING"}, environ={})
    assert snapshot_id_for(cfg_a) == snapshot_id_for(cfg_b)
    assert snapshot_id_for(cfg_a) != snapshot_id_for(cfg_c)
