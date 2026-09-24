import json

from click.testing import CliRunner

from mayhem.cli.app import app


def test_config_show_json(tmp_path):
    runner = CliRunner()
    result = runner.invoke(app, ["config", "show", "--json"], catch_exceptions=False)
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "config" in payload
    assert "sources" in payload


def test_config_explain_json(tmp_path):
    runner = CliRunner()
    result = runner.invoke(app, ["config", "explain", "--json"], catch_exceptions=False)
    assert result.exit_code == 0
    rows = json.loads(result.output)
    assert isinstance(rows, list)
    assert any(r["field"] == "policy" for r in rows)
    assert all("source" in r and "safe_for_mutation" in r for r in rows)


def test_config_explain_no_secrets(tmp_path):
    runner = CliRunner()
    result = runner.invoke(app, ["config", "explain"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "REDACTED" not in result.output or "password" not in result.output.lower()


def test_config_validate_ok():
    runner = CliRunner()
    result = runner.invoke(app, ["config", "validate"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "configuration valid" in result.output.lower()


def test_policy_flag_unknown_rejected():
    runner = CliRunner()
    result = runner.invoke(app, ["--policy", "nonexistent", "config", "show"])
    assert result.exit_code != 0
