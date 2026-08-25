"""Capability registry — declarative manifests + probing + fallback chains.

ADR-0004: every external tool is declared as data (a manifest), probed once at
handshake, and resolved per capability through an ordered fallback chain.
ADR-0011: this registry *is* the extension point — new tool = new manifest +
adapter; agents never hardcode binaries.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.risks import RiskLevel
from mayhem.toolkit.tool_runner import run_tool

BUILTIN_MANIFESTS_DIR = Path(__file__).parent / "manifests"


class Privilege(StrEnum):
    NONE = "none"
    SUDO_PATTERNS = "sudo_patterns"
    ROOT = "root"


_FALLBACK_NAME = re.compile(r"^(primary|fallback_(?P<n>[1-9]\d*))$")


def _fallback_rank(name: str) -> int:
    if name == "primary":
        return 0
    match = _FALLBACK_NAME.match(name)
    if match is None:
        raise SchemaValidationError(
            "fallback_rank", f"invalid slot name {name!r} (primary|fallback_N)"
        )
    return int(match.group("n"))


class CapabilityManifest(BaseModel):
    """One external tool, declared as data."""

    model_config = ConfigDict(frozen=True)

    tool: str
    provides: tuple[str, ...]
    probe_cmd: tuple[str, ...]
    version_regex: str
    privilege: Privilege = Privilege.NONE
    risk: RiskLevel = RiskLevel.MEDIUM
    fallback_slots: dict[str, str] = Field(default_factory=dict)  # capability → primary|fallback_N

    @field_validator("provides")
    @classmethod
    def _nonempty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise SchemaValidationError("manifest", "tool must provide ≥1 capability")
        return value

    @field_validator("probe_cmd")
    @classmethod
    def _argv_only(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(not part for part in value):
            raise SchemaValidationError("manifest", "probe_cmd must be a non-empty argv list")
        return value

    @field_validator("fallback_slots")
    @classmethod
    def _slots_reference_provided(
        cls, value: dict[str, str], info: ValidationInfo
    ) -> dict[str, str]:
        provides = info.data.get("provides", ())
        for capability, slot in value.items():
            if capability not in provides:
                raise SchemaValidationError(
                    "fallback_rank",
                    f"slot for {capability!r} but tool does not provide it",
                )
            _fallback_rank(slot)  # validates name shape
        return value

    def rank_for(self, capability: str) -> int | None:
        slot = self.fallback_slots.get(capability)
        return None if slot is None else _fallback_rank(slot)


class ProbedTool(BaseModel):
    model_config = ConfigDict(frozen=True)

    manifest: CapabilityManifest
    version: str


class CapabilityReport(BaseModel):
    """Cached probe outcome per host. Refreshed explicitly, never mid-run."""

    model_config = ConfigDict(frozen=True)

    host: str
    tools: tuple[ProbedTool, ...] = ()

    def has(self, capability_id: str) -> bool:
        return any(capability_id in t.manifest.provides for t in self.tools)


class ToolRegistry:
    """Registry of manifests + cached probes + ranked fallback resolution."""

    def __init__(self, manifests: tuple[CapabilityManifest, ...] = ()) -> None:
        self._manifests: dict[str, CapabilityManifest] = {}
        self._reports: dict[str, CapabilityReport] = {}
        for manifest in manifests:
            self.register(manifest)

    def register(self, manifest: CapabilityManifest) -> None:
        if manifest.tool in self._manifests:
            raise SchemaValidationError("registry", f"duplicate tool manifest: {manifest.tool}")
        self._manifests[manifest.tool] = manifest
        self._reports.clear()  # new tool may satisfy capabilities on known hosts

    @property
    def manifests(self) -> tuple[CapabilityManifest, ...]:
        return tuple(self._manifests.values())

    def probe(self, host: str = "local") -> CapabilityReport:
        """Run each manifest's probe_cmd; keep only tools that answer with a version."""
        probed: list[ProbedTool] = []
        for manifest in sorted(self._manifests.values(), key=lambda m: m.tool):
            try:
                result = run_tool(list(manifest.probe_cmd), timeout_s=10.0)
            except Exception:
                continue  # binary missing / not executable → simply not capable here
            match = re.search(manifest.version_regex, result.stdout + result.stderr)
            if result.succeeded and match:
                probed.append(ProbedTool(manifest=manifest, version=match.group("v")))
        report = CapabilityReport(host=host, tools=tuple(probed))
        self._reports[host] = report
        return report

    def report_for(self, host: str = "local") -> CapabilityReport:
        return self._reports.get(host) or self.probe(host)

    def refresh(self, host: str = "local") -> CapabilityReport:
        """Explicit re-probe; never called implicitly mid-run."""
        return self.probe(host)

    def resolve(self, capability_id: str, host: str = "local") -> tuple[CapabilityManifest, ...]:
        """Ranked candidates for a capability, filtered by the host's cached probe."""
        candidates: list[tuple[int, CapabilityManifest]] = []
        for probed in self.report_for(host).tools:
            manifest = probed.manifest
            if capability_id not in manifest.provides:
                continue
            rank = manifest.rank_for(capability_id)
            candidates.append((rank if rank is not None else 10**6, manifest))
        candidates.sort(key=lambda pair: pair[0])
        return tuple(m for _, m in candidates)


def manifest_from_yaml(path: Path) -> CapabilityManifest:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    slots_raw = raw.pop("fallback_groups", {}) or {}
    slots = {capability: slot for capability, slot in slots_raw.items() if slot is not None}
    return CapabilityManifest(
        tool=raw["tool"],
        provides=tuple(raw["provides"]),
        probe_cmd=tuple(raw["probe"]["cmd"]),
        version_regex=raw["probe"]["version_regex"],
        privilege=Privilege(raw.get("privilege", "none")),
        risk=RiskLevel(raw.get("risk", "medium")),
        fallback_slots=slots,
    )


def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    if BUILTIN_MANIFESTS_DIR.is_dir():
        for path in sorted(BUILTIN_MANIFESTS_DIR.glob("*.yaml")):
            registry.register(manifest_from_yaml(path))
    return registry
