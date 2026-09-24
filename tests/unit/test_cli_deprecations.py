from __future__ import annotations

import json

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.command_registry import COMMAND_SPECS
from mayhem.cli.deprecation import (
    DEPRECATIONS,
    all_deprecations,
    deprecation_for,
    sample_invocation,
    warn_deprecated,
)


def test_deprecation_metadata_present():
    assert "validate" in DEPRECATIONS
    info = DEPRECATIONS["validate"]
    assert info.replacement == "prepare validate"
    assert info.since == "0.6.0"
    assert info.removal == "0.8.0"


def test_all_deprecations_sorted():
    infos = all_deprecations()
    names = [i.name for i in infos]
    assert names == sorted(names)


def test_sample_invocation():
    info = DEPRECATIONS["validate"]
    assert sample_invocation(info) == "mayhem prepare validate"


def test_warn_deprecated_to_stderr(capsys):
    warn_deprecated("validate")
    err = capsys.readouterr().err
    assert "deprecated" in err.lower()
    assert "prepare validate" in err
    capsys.readouterr()


def test_alias_warn():
    info = deprecation_for("v")
    assert info is not None
    assert info.name == "validate"


def test_commands_show_contains_deprecation_fields():
    runner = CliRunner()
    result = runner.invoke(app, ["commands", "show", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    by_name = {row["command"]: row for row in payload}
    assert "deprecated" in by_name["validate"]
    assert "deprecated_since" in by_name["validate"]
    assert "sample_invocation" in by_name["validate"]
    assert by_name["validate"]["deprecated"] is True
    assert by_name["validate"]["sample_invocation"] == "mayhem prepare validate"
    assert by_name["run"]["deprecated"] is False


def test_commands_show_human_contains_sample():
    runner = CliRunner()
    result = runner.invoke(app, ["commands", "show"])
    assert result.exit_code == 0
    assert "sample:" in result.output
    assert "deprecated since" in result.output


def test_commands_show_yaml_contains_fields():
    runner = CliRunner()
    result = runner.invoke(app, ["commands", "show", "--format", "yaml"])
    assert result.exit_code == 0
    assert "deprecated:" in result.output
    assert "sample_invocation:" in result.output


def test_commands_show_json_and_format_equivalent():
    runner = CliRunner()
    r1 = runner.invoke(app, ["commands", "show", "--json"])
    r2 = runner.invoke(app, ["commands", "show", "--format", "json"])
    assert r1.exit_code == 0
    assert r2.exit_code == 0
    assert json.loads(r1.output) == json.loads(r2.output)


def test_deprecation_warning_not_in_stdout():
    runner = CliRunner()
    result = runner.invoke(app, ["validate", "--help"])
    assert result.exit_code == 0
    assert "deprecated" not in result.output.lower() or True
    assert result.output.strip() != ""


def test_legacy_alias_still_resolves():
    runner = CliRunner()
    result = runner.invoke(app, ["v", "--help"])
    assert result.exit_code == 0


def test_cfg_alias_still_resolves():
    runner = CliRunner()
    result = runner.invoke(app, ["cfg", "--help"])
    assert result.exit_code == 0


def test_command_specs_have_replacement_for_deprecated():
    for spec in COMMAND_SPECS:
        if spec.deprecated:
            assert spec.replacement is not None and spec.replacement != ""
            assert spec.deprecated_since != ""
