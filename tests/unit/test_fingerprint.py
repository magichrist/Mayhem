"""Environment fingerprint: determinism, sensitivity, tolerance."""

import platform
import sys

from mayhem.toolkit.fingerprint import (
    build_fingerprint,
    collect_tool_versions,
    interpreter_marker,
)


class TestBuildFingerprint:
    def test_deterministic(self) -> None:
        versions = {"docker": "Docker version 27.0.1", "tc": None}
        assert build_fingerprint(versions) == build_fingerprint(versions)

    def test_sensitive_to_tool_versions(self) -> None:
        old = build_fingerprint({"docker": "27"})
        new = build_fingerprint({"docker": "28"})
        assert old != new

    def test_sensitive_to_missing_tools(self) -> None:
        present = build_fingerprint({"tc": "tc utility"})
        absent = build_fingerprint({"tc": None})
        assert present != absent

    def test_key_order_irrelevant(self) -> None:
        assert build_fingerprint({"a": "1", "b": "2"}) == build_fingerprint({"b": "2", "a": "1"})


class TestCollect:
    def test_missing_tool_recorded_as_none(self) -> None:
        versions, _ = collect_tool_versions(probed=(("nope-xyz-42", ("nope-xyz-42", "--v")),))
        assert versions == {"nope-xyz-42": None}

    def test_real_python_probe(self) -> None:
        versions, evidence = collect_tool_versions(
            probed=(("python", (sys.executable, "--version")),)
        )
        assert versions["python"] is not None
        assert len(evidence) == 1

    def test_interpreter_marker(self) -> None:
        marker = interpreter_marker()
        assert marker.startswith("python-")
        assert platform.python_version().startswith(marker.removeprefix("python-"))
