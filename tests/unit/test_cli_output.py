from __future__ import annotations

import json

from mayhem.cli.output import (
    OUTPUT_SCHEMA_LOCATION,
    OUTPUT_SCHEMA_VERSION,
    CommandResult,
    resolve_format,
)


def test_command_result_ok_to_dict():
    result = CommandResult.ok(
        data={"hello": "world"}, warnings=["w1"], evidence_refs=["e1"], meta={"renderer": "json"}
    )
    d = result.to_dict()
    assert d["status"] == "ok"
    assert d["schema_version"] == OUTPUT_SCHEMA_VERSION
    assert d["data"] == {"hello": "world"}
    assert d["warnings"] == ["w1"]
    assert d["errors"] == []
    assert d["evidence_refs"] == ["e1"]
    assert d["meta"]["renderer"] == "json"
    assert OUTPUT_SCHEMA_LOCATION == "src/mayhem/schemas/output_v1.json"


def test_command_result_fail_to_json_valid():
    result = CommandResult.fail(errors=["boom"], data={"x": 1})
    text = result.to_json()
    payload = json.loads(text)
    assert payload["status"] == "error"
    assert payload["errors"] == ["boom"]
    assert payload["data"] == {"x": 1}
    assert payload["schema_version"] == OUTPUT_SCHEMA_VERSION


def test_command_result_is_success():
    ok = CommandResult.ok(data=None)
    fail = CommandResult.fail(errors=["e"])
    assert ok.is_success() is True
    assert fail.is_success() is False


def test_resolve_format_prefers_explicit():
    assert resolve_format("json", False) == "json"
    assert resolve_format("yaml", True) == "yaml"
    assert resolve_format("text", True) == "text"


def test_resolve_format_preserves_json_flag():
    assert resolve_format(None, True) == "json"
    assert resolve_format(None, False) == "text"


def test_command_result_meta_sorted_keys():
    result = CommandResult.ok(data={}, meta={"z": 1, "a": 2})
    d = result.to_dict()
    assert list(d["meta"].keys()) == ["a", "z"]


def test_command_result_empty_data_null():
    result = CommandResult.ok(data=None)
    d = result.to_dict()
    assert d["data"] is None
    assert d["warnings"] == []
    assert d["errors"] == []


def test_command_result_json_stable_sort_keys():
    result = CommandResult.ok(data={"b": 2, "a": 1})
    first = result.to_json()
    second = result.to_json()
    assert first == second
    assert json.loads(first)["data"] == {"a": 1, "b": 2}
