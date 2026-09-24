"""RuntimeAdapter contract and capability verdict matrix (ADR-M3-1, ADR-M3-2).

``RuntimeAdapter`` is the normalized interface that docker, podman, and
future runtimes implement.  ``AdapterCapabilities`` provides a static
snapshot of what the adapter supports; ``CapabilityRequirements`` captures
what a fault plan needs; and ``evaluate`` produces a verdict that the
planner uses to accept or refuse execution.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.errors import InvariantViolationError

if TYPE_CHECKING:
    from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
    from mayhem.topology.providers.base import PartialGraph


class EngineDescriptor(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    binary: str
    compose_supported: bool = True
    signals: tuple[str, ...] = ("SIGSTOP", "SIGCONT", "SIGTERM", "SIGKILL")
    network_capabilities: frozenset[str] = frozenset({"netem", "iptables", "tc"})
    storage_capabilities: frozenset[str] = frozenset({"overlay", "volume"})
    version: str | None = None
    binary_available: bool = False


_ENGINE_DESCRIPTORS: dict[str, EngineDescriptor] = {
    "docker": EngineDescriptor(
        name="docker",
        binary="docker",
        compose_supported=True,
        signals=("SIGSTOP", "SIGCONT", "SIGTERM", "SIGKILL", "SIGUSR1", "SIGUSR2"),
        network_capabilities=frozenset({"netem", "iptables", "tc", "bridge", "overlay"}),
        storage_capabilities=frozenset({"overlay", "volume", "bind"}),
    ),
    "podman": EngineDescriptor(
        name="podman",
        binary="podman",
        compose_supported=True,
        signals=("SIGSTOP", "SIGCONT", "SIGTERM", "SIGKILL", "SIGUSR1", "SIGUSR2"),
        network_capabilities=frozenset({"netem", "iptables", "tc", "bridge", "pasta"}),
        storage_capabilities=frozenset({"overlay", "volume", "bind"}),
    ),
}


def describe_engine(name: str) -> EngineDescriptor:
    desc = _ENGINE_DESCRIPTORS.get(name)
    if desc is None:
        raise LookupError(f"unknown engine {name!r}")
    return desc


def detect_available_engines() -> list[EngineDescriptor]:
    result: list[EngineDescriptor] = []
    for _key, base in _ENGINE_DESCRIPTORS.items():
        binary_available = shutil.which(base.binary) is not None
        version: str | None = None
        if binary_available:
            try:
                out = subprocess.run(
                    [base.binary, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                raw = (out.stdout or out.stderr or "").strip()
                version = raw.splitlines()[0][:120] if raw else None
            except Exception:
                version = None
        result.append(
            base.model_copy(update={"binary_available": binary_available, "version": version})
        )
    return result


def resolve_engine_selection(explicit: str | None) -> EngineDescriptor:
    if explicit is not None and explicit.strip():
        name = explicit.strip().lower()
        desc = _ENGINE_DESCRIPTORS.get(name)
        if desc is None:
            raise InvariantViolationError("engine_unknown", f"unknown engine {explicit!r}")
        available = detect_available_engines()
        match = next((d for d in available if d.name == name), None)
        if match is not None and not match.binary_available:
            raise InvariantViolationError(
                "engine_unavailable",
                f"engine {name!r} selected but binary {desc.binary!r} not on PATH",
            )
        if match is not None:
            return match
        return desc.model_copy(update={"binary_available": False})
    available = [d for d in detect_available_engines() if d.binary_available]
    if len(available) == 0:
        raise InvariantViolationError(
            "engine_unavailable",
            "no engine on PATH (checked docker, podman); install or pass --runtime",
        )
    if len(available) > 1:
        names = ", ".join(d.name for d in available)
        raise InvariantViolationError(
            "engine_ambiguous",
            f"multiple engines available ({names}); pass --runtime docker or podman",
        )
    return available[0]


def topology_fingerprint_for_engine(engine: str, graph: object) -> str:
    try:
        payload = json.dumps(
            {"engine": engine, "graph": getattr(graph, "model_dump", lambda **_: {})(mode="json")},
            sort_keys=True,
            default=str,
        )
    except Exception:
        payload = f"{engine}:{graph!s}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RuntimeCapability(StrEnum):
    """Named capability a runtime adapter may or may not support."""

    EXEC = "exec"
    PID = "pid"
    SIGNAL = "signal"
    NETNS = "netns"
    RESOURCE_LIMITS = "resource_limits"
    INSPECT = "inspect"
    COMPOSE_FILTER = "compose_filter"
    # k8s adapter only (ADR-M7-1 seam): node-level control-plane access
    # (``kubectl get nodes``) that the node-killer families require.
    NODE_CONTROL = "node_control"
    DNS_CONTROL = "dns_control"


class CapabilityVerdict(StrEnum):
    """Per-capability answer from the adapter's feasibility matrix."""

    SUPPORTED = "supported"
    ALTERNATIVE = "alternative"  # degraded but safe
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Capability snapshot
# ---------------------------------------------------------------------------


class AdapterCapabilities(BaseModel):
    """Static capability snapshot produced by a ``RuntimeAdapter``.

    Every adapter populates *supported* and *alternatives* at construction
    time (derived from engine version, rootless detection, etc.) so that
    ``verdict()`` is a pure lookup with no subprocess calls.
    """

    model_config = ConfigDict(frozen=True)

    engine: str
    rootless: bool = False
    supported: frozenset[RuntimeCapability] = Field(
        default_factory=frozenset,
    )
    alternatives: frozenset[RuntimeCapability] = Field(
        default_factory=frozenset,
    )
    version: str | None = None

    # -- lookup --------------------------------------------------------------

    def verdict(self, cap: RuntimeCapability) -> CapabilityVerdict:
        """Return the verdict for *cap* without subprocess calls."""
        if cap in self.supported:
            return CapabilityVerdict.SUPPORTED
        if cap in self.alternatives:
            return CapabilityVerdict.ALTERNATIVE
        return CapabilityVerdict.UNSUPPORTED


# ---------------------------------------------------------------------------
# Requirements
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityRequirements:
    """What a fault plan requires from the runtime adapter.

    The planner builds this from the plan's execution contexts and resolved
    targets; the adapter's ``evaluate`` method answers each requirement.
    """

    platforms: frozenset[str] = field(default_factory=frozenset)
    runtimes: frozenset[str] = field(default_factory=frozenset)
    target_kinds: frozenset[str] = field(default_factory=frozenset)
    privileges: frozenset[str] = field(default_factory=frozenset)
    namespaces: frozenset[str] = field(default_factory=frozenset)
    tools: frozenset[str] = field(default_factory=frozenset)
    kernel_features: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Verdict result
# ---------------------------------------------------------------------------


class VerdictResult(BaseModel):
    """Output of ``RuntimeAdapter.evaluate``.

    ``blocking`` is True when at least one requirement maps to UNSUPPORTED;
    the planner must refuse the plan in that case.  ALTERNATIVE verdicts are
    non-blocking but logged as warnings.
    """

    model_config = ConfigDict(frozen=True)

    engine: str
    requirements: CapabilityRequirements
    verdicts: dict[str, str]  # CapabilityRequirement summary -> CapabilityVerdict value
    blocking: bool

    def refuse_with_message(self) -> str | None:
        """Return a human-readable refusal message if *blocking*, else None."""
        if not self.blocking:
            return None
        unsupported = [k for k, v in self.verdicts.items() if v == CapabilityVerdict.UNSUPPORTED]
        return (
            f"runtime '{self.engine}' UNSUPPORTED capabilities block this plan: "
            f"{', '.join(sorted(unsupported))}"
        )


# ---------------------------------------------------------------------------
# Abstract adapter
# ---------------------------------------------------------------------------


class RuntimeAdapter(ABC):
    """Normalized runtime interface (ADR-M3-1).

    Docker and Podman are concrete implementations.  Remote and Kubernetes
    are stubs that return UNSUPPORTED verdicts (ADR-M3-5, ADR-M3-6).
    """

    # -- identity ------------------------------------------------------------

    @property
    @abstractmethod
    def id(self) -> str:
        """Stable adapter identifier, e.g. ``"docker"`` or ``"podman"``.

        Exposed as a property so adapters remain structurally compatible with
        the ``TopologyProvider`` protocol (``id`` is a property there).
        """

    @abstractmethod
    def is_available(self) -> bool:
        """True when the engine binary is reachable on this host."""

    # -- capabilities --------------------------------------------------------

    @abstractmethod
    def capabilities(self) -> AdapterCapabilities:
        """Static capability snapshot for this adapter instance."""

    def evaluate(self, reqs: CapabilityRequirements) -> VerdictResult:
        """Answer a set of requirements against the adapter's capabilities.

        Default implementation maps ``reqs.namespaces`` to NETNS,
        ``reqs.tools`` to tool availability, etc.  Override for richer
        engine-specific logic.
        """
        caps = self.capabilities()
        verdicts: dict[str, str] = {}
        blocking = False

        # namespace requirements -> NETNS capability
        if reqs.namespaces:
            v = caps.verdict(RuntimeCapability.NETNS)
            verdicts["namespaces"] = v.value
            if v == CapabilityVerdict.UNSUPPORTED:
                blocking = True

        # tool requirements -> EXEC capability (tools need exec to run)
        if reqs.tools:
            v = caps.verdict(RuntimeCapability.EXEC)
            verdicts["tools"] = v.value
            if v == CapabilityVerdict.UNSUPPORTED:
                blocking = True

        # resource limit requirements
        if reqs.permissions:
            v = caps.verdict(RuntimeCapability.RESOURCE_LIMITS)
            verdicts["permissions"] = v.value
            if v == CapabilityVerdict.UNSUPPORTED:
                blocking = True

        return VerdictResult(
            engine=self.id,
            requirements=reqs,
            verdicts=verdicts,
            blocking=blocking,
        )

    # -- container operations ------------------------------------------------

    @abstractmethod
    def ps(self) -> list[dict[str, Any]]:
        """List containers visible to this adapter (engine-native format)."""

    @abstractmethod
    def inspect(self, container_id: str) -> tuple[RuntimeIdentity, RuntimeMetadata | None]:
        """Resolve identity + metadata for a running container."""

    @abstractmethod
    def exec(self, container_id: str, cmd: list[str], *, timeout_s: float = 30) -> str:
        """Run *cmd* inside *container_id*, return stdout."""

    @abstractmethod
    def pid(self, container_id: str) -> int | None:
        """Return the main PID of *container_id*, or None if unavailable."""

    @abstractmethod
    def signal(self, container_id: str, signo: int) -> None:
        """Send signal *signo* to *container_id*'s main process."""

    @abstractmethod
    def netns(self, container_id: str) -> str | None:
        """Return the network-namespace path for *container_id*, or None."""

    # -- filtering (mutates state) -------------------------------------------

    @abstractmethod
    def filter_by_compose(
        self,
        project: str,
        services: tuple[str, ...] | None = None,
    ) -> None:
        """Scope to containers belonging to a compose project."""

    @abstractmethod
    def filter_by_names(self, names: list[str]) -> None:
        """Scope to containers matching explicit names."""

    # -- discovery -----------------------------------------------------------

    @abstractmethod
    def discover(self) -> PartialGraph:
        """Build a PartialGraph fragment from the engine's live state."""
