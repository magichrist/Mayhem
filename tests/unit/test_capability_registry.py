"""Unit tests for the capability registry (ADR-0004 / ADR-0011)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml

if TYPE_CHECKING:
    from pathlib import Path

from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.risks import RiskLevel
from mayhem.toolkit import registry as reg
from mayhem.toolkit.registry import (
    CapabilityManifest,
    Privilege,
    ToolRegistry,
    default_registry,
    manifest_from_yaml,
)


def _manifest(**overrides) -> CapabilityManifest:
    base: dict[str, object] = {
        "tool": "stress-ng",
        "provides": ("cpu.pressure",),
        "probe_cmd": ("stress-ng", "--version"),
        "version_regex": r"version\s+(?P<v>[\d.]+)",
        "privilege": Privilege.NONE,
        "risk": RiskLevel.MEDIUM,
        "fallback_slots": {"cpu.pressure": "primary"},
    }
    return CapabilityManifest(**{**base, **overrides})


class TestManifestValidation:
    def test_rejects_empty_provides(self) -> None:
        with pytest.raises(SchemaValidationError):
            _manifest(provides=())

    def test_rejects_empty_argv(self) -> None:
        with pytest.raises(SchemaValidationError):
            _manifest(probe_cmd=())

    def test_slot_must_reference_provided_capability(self) -> None:
        with pytest.raises(SchemaValidationError, match="does not provide"):
            _manifest(fallback_slots={"net.latency": "primary"})

    def test_invalid_slot_name_rejected(self) -> None:
        with pytest.raises(SchemaValidationError, match="slot name"):
            _manifest(fallback_slots={"cpu.pressure": "backup"})

    def test_rank_for_primary_is_zero(self) -> None:
        assert _manifest().rank_for("cpu.pressure") == 0
        wide = _manifest(fallback_slots={"cpu.pressure": "fallback_3"})
        assert wide.rank_for("cpu.pressure") == 3


class TestProbingAndResolution:
    def test_probe_keeps_only_answered_tools(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeResult:
            exit_code = 0
            stdout = "probe version 1.2.3"
            stderr = ""
            succeeded = True

        monkeypatch.setattr(reg, "run_tool", lambda argv, timeout_s=None: FakeResult())
        registry = ToolRegistry((_manifest(),))
        report = registry.probe("h-local")
        assert report.has("cpu.pressure")
        assert report.tools[0].version == "1.2.3"

    def test_probe_drops_failing_tools(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(argv, timeout_s=None):
            raise FileNotFoundError(argv[0])

        monkeypatch.setattr(reg, "run_tool", boom)
        registry = ToolRegistry((_manifest(),))
        assert not registry.probe("h-x").has("cpu.pressure")
        assert registry.resolve("cpu.pressure", "h-x") == ()  # nothing capable here

    def test_resolve_ranks_fallback_chain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeResult:
            exit_code = 0
            stdout = "version 9.9.9"
            stderr = ""
            succeeded = True

        monkeypatch.setattr(reg, "run_tool", lambda argv, timeout_s=None: FakeResult())
        primary = _manifest(
            tool="tc", provides=("net.latency",), fallback_slots={"net.latency": "primary"}
        )
        fallback = _manifest(
            tool="toxiproxy",
            probe_cmd=("toxiproxy-cli", "--version"),
            provides=("net.latency",),
            fallback_slots={"net.latency": "fallback_1"},
        )
        registry = ToolRegistry((fallback, primary))  # deliberately out of order
        resolved = registry.resolve("net.latency", "h-local")
        assert [m.tool for m in resolved] == ["tc", "toxiproxy"]

    def test_refresh_is_explicit_and_updates_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Yes:
            exit_code = 0
            stdout = "version 1.0"
            stderr = ""
            succeeded = True

        class No:
            exit_code = 1
            stdout = ""
            stderr = "missing"
            succeeded = False

        monkeypatch.setattr(reg, "run_tool", lambda argv, timeout_s=None: No())
        registry = ToolRegistry((_manifest(),))
        assert not registry.report_for("h").has("cpu.pressure")
        monkeypatch.setattr(reg, "run_tool", lambda argv, timeout_s=None: Yes())
        registry.refresh("h")
        assert registry.resolve("cpu.pressure", "h")[0].tool == "stress-ng"


class TestYamlLoading:
    def test_manifest_from_yaml_maps_fields(self, tmp_path: Path) -> None:
        raw = {
            "tool": "tc",
            "provides": ["net.latency"],
            "probe": {"cmd": ["tc", "-Version"], "version_regex": r"(?P<v>[\w.\-]+)"},
            "privilege": "root",
            "risk": "high",
            "fallback_groups": {"net.latency": "primary"},
        }
        path = tmp_path / "tc.yaml"
        path.write_text(yaml.safe_dump(raw), encoding="utf-8")
        manifest = manifest_from_yaml(path)
        assert manifest.privilege is Privilege.ROOT
        assert manifest.risk is RiskLevel.HIGH
        assert manifest.rank_for("net.latency") == 0

    def test_default_registry_loads_builtin_manifests(self) -> None:
        registry = default_registry()
        tools = {m.tool for m in registry.manifests}
        assert {"stress-ng", "tc", "toxiproxy", "docker", "podman"} <= tools

    def test_default_registry_probes_real_host_without_raising(self) -> None:
        # On dev hosts some binaries are absent; probing must degrade gracefully.
        report = default_registry().probe()
        for probed in report.tools:
            assert probed.version
