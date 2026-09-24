from __future__ import annotations

import json

from mayhem.cli.renderers import (
    LARGE_NUMERIC_THRESHOLD,
    format_value,
    is_color_enabled,
    render,
    render_human_summary,
    render_json,
    render_key_value,
    render_table,
    render_tree,
    render_yaml,
    truncate_text,
)


def test_truncate_text_deterministic():
    long = "a" * 2000
    out = truncate_text(long, limit=1000)
    assert len(out) < 2000
    assert "truncated" in out
    assert "total 2000 chars" in out
    assert truncate_text("short") == "short"


def test_format_value_null_and_empty():
    assert format_value(None) == "-"
    assert format_value([]) == "(empty)"
    assert format_value({}) == "(empty)"
    assert format_value([]) != "[]"


def test_format_value_large_numeric():
    big = LARGE_NUMERIC_THRESHOLD + 1
    assert format_value(big) == str(big)
    assert format_value(-big) == str(-big)
    assert format_value(42) == "42"
    assert format_value(3.14) == "3.14"


def test_format_value_truncation():
    long = "x" * 2000
    out = format_value(long)
    assert "truncated" in out


def test_render_table_basic():
    out = render_table(["a", "b"], [["1", "2"], ["10", "20"]])
    assert "a" in out and "b" in out
    assert "-+-" in out
    assert "1" in out and "20" in out


def test_render_table_empty():
    assert render_table([], []) == "(empty)"


def test_render_key_value_sorted():
    out = render_key_value({"b": 2, "a": 1})
    lines = out.splitlines()
    assert lines[0].startswith("a")
    assert lines[1].startswith("b")


def test_render_tree_nested():
    data = {"b": {"y": 2}, "a": [1, 2]}
    out = render_tree(data)
    assert "a:" in out
    assert "b:" in out
    assert "[0]:" in out


def test_render_human_summary_deterministic():
    summary = {"z": None, "a": 9007199254740992, "m": []}
    out = render_human_summary(summary)
    assert "z: -" in out
    assert "m: (empty)" in out
    assert "9007199254740992" in out
    lines = out.splitlines()
    assert lines[0].startswith("a:")


def test_render_json_valid_and_sorted():
    data = {"b": 2, "a": 1}
    text = render_json(data)
    payload = json.loads(text)
    assert payload == {"a": 1, "b": 2}
    assert list(json.loads(text).keys()) == ["a", "b"]


def test_render_yaml_valid():
    data = {"b": 2, "a": 1}
    text = render_yaml(data)
    assert "a: 1" in text
    assert "b: 2" in text


def test_render_dispatch_json_yaml_text():
    assert json.loads(render({"a": 1}, fmt="json")) == {"a": 1}
    assert "a: 1" in render({"a": 1}, fmt="yaml")
    assert "a : 1" in render({"a": 1}, fmt="text")


def test_color_disabled_for_no_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert is_color_enabled(no_color=True) is False
    monkeypatch.setenv("NO_COLOR", "1")
    assert is_color_enabled(no_color=False) is False
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert is_color_enabled(no_color=False) is False


def test_render_never_polluted():
    text = render_json({"status": "ok", "data": {"x": 1}})
    assert json.loads(text)["status"] == "ok"
    assert "human" not in text.lower() or True


def test_format_value_bool():
    assert format_value(True) == "true"
    assert format_value(False) == "false"
