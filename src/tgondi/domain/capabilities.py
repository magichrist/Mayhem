"""Capability and tool-manifest types (ADR-0004).

Agents declare *capabilities*; tools are wrapped behind manifests so faults ask
for outcomes, not binaries. Fallback groups let the executor pick any tool that
can deliver a capability on the current host.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")]
"""Lowercase dotted identifier, e.g. ``net.latency`` or ``tc-netem``."""


class PrivilegeMode(StrEnum):
    """How privileged operations are obtained on a host (ADR-0003)."""

    ROOT_VIA_SYSTEMD = "root_via_systemd"
    SUDO_PINNED = "sudo_pinned"
    UNPRIVILEGED = "unprivileged"


class Capability(StrEnum):
    """Named host abilities agents advertise during handshake."""

    NET_ADMIN = "net_admin"
    SYS_ADMIN = "sys_admin"
    CGROUP_CONTROL = "cgroup_control"
    PROCESS_CONTROL = "process_control"
    FS_CONTROL = "fs_control"
    DOCKER_ENGINE = "docker_engine"
    PODMAN_ENGINE = "podman_engine"


class ToolManifest(BaseModel):
    """Declarative wrapper around one native or external tool.

    In-tree YAML manifests deserialize into this model; adapters implement the
    behavior. ``fallback_group`` ties interchangeable tools together (ADR-0010).
    """

    model_config = ConfigDict(frozen=True)

    id: Identifier
    display_name: str
    binary: str
    capability_group: Identifier  # e.g. "net.emulation", "load.http"
    provides_capabilities: frozenset[Capability] = Field(default_factory=frozenset)
    requires_privilege_mode: PrivilegeMode | None = None
    version_flag: tuple[str, ...] = ("--version",)
    default_timeout_s: float = 30.0
    output_limit_bytes: int = 1_048_576  # truncation is always explicit


class ToolAvailability(BaseModel):
    """Result of probing one manifest on one host."""

    model_config = ConfigDict(frozen=True)

    manifest_id: Identifier
    available: bool
    version: str | None = None
    reason_if_unavailable: str | None = None


class CapabilityReport(BaseModel):
    """What an agent can actually do right now (handshake payload)."""

    model_config = ConfigDict(frozen=True)

    agent_id: str
    host: str
    privilege_mode: PrivilegeMode
    capabilities: frozenset[Capability] = Field(default_factory=frozenset)
    tools: tuple[ToolAvailability, ...] = ()

    def has_capability(self, cap: Capability) -> bool:
        return cap in self.capabilities

    def missing(self, needed: frozenset[Capability]) -> frozenset[Capability]:
        return needed - self.capabilities
