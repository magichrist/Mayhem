"""Runtime identity and runtime metadata value objects (ADR-M1-1, ADR-M1-2).

The container half of the codebase used to bind targets by authored name
(``container_name``, ADR-0019/0020) plus ad-hoc scalars. Those are now split
into two sharply different concepts:

* :class:`RuntimeIdentity` **is** the identity — equality and hashing operate on
  the three identity fields only. It is the key used by every persisted
  plan/lease/execution/recovery record.
* :class:`RuntimeMetadata` is descriptive context (project, service, labels,
  lifecycle timestamps). It is explicitly excluded from equality: metadata churn
  never changes the identity.

``container_name``/``service`` are *authoring resolver keys* that resolve to a
``RuntimeIdentity`` at planning time; they are never identity equality.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, field_validator

if TYPE_CHECKING:
    from collections.abc import Mapping


class RuntimeLabel(StrEnum):
    """Locked runtime labels (k-plan-1 §1.3) — docker/podman/kubernetes.

    ``RuntimeIdentity.runtime`` stays a free string in the model so persisted
    rows never need a migration, but the DSL and config surface now speak only
    this vocabulary. Enum values equal the historical strings, so any stored
    ``runtime`` parse is a no-op round-trip.
    """

    DOCKER = "docker"
    PODMAN = "podman"
    KUBERNETES = "kubernetes"


class RuntimeIdentity(BaseModel):
    """Equality key for a single running workload (a container, later a process).

    Attributes:
        runtime: Engine label (``"docker"``/``"podman"``) — label only, per
            ADR-0013.
        host_id: Host node the workload runs under (e.g. ``h-podman-local``).
        runtime_id: Engine-reported runtime object id (full container id).
    """

    model_config = ConfigDict(frozen=True)

    runtime: str
    host_id: str | None = None
    runtime_id: str

    @field_validator("runtime", "runtime_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("identity fields runtime and runtime_id must be non-empty")
        return value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RuntimeIdentity):
            return NotImplemented
        # Equality on the three identity fields ONLY (ADR-M1-1); names, labels,
        # and metadata never participate.
        return (self.runtime, self.host_id, self.runtime_id) == (
            other.runtime,
            other.host_id,
            other.runtime_id,
        )

    def __hash__(self) -> int:
        return hash((self.runtime, self.host_id, self.runtime_id))

    def resolve_key(self) -> str:
        """Canonical, opaque, store-safe identity key (round-trippable)."""
        return f"{self.runtime}|{self.host_id or ''}|{self.runtime_id}"

    def key(self) -> str:  # alias: key() == resolve_key()
        """Short canonical key, usable as a SQL/store column value."""
        return self.resolve_key()

    @classmethod
    def from_key(cls, key: str) -> RuntimeIdentity:
        """Rebuild an identity from a canonical ``resolve_key()`` string."""
        try:
            runtime, host_id, runtime_id = key.split("|", maxsplit=2)
        except ValueError as exc:
            raise ValueError(f"not a canonical identity key: {key!r}") from exc
        return cls(
            runtime=runtime,
            host_id=host_id or None,
            runtime_id=runtime_id,
        )


class ProcessRuntimeIdentity(BaseModel):
    """Equality key for a single running process (ADR-M2 Phase 2.4).

    A PID alone is not an identity: the kernel recycles PIDs after exit, so a
    short-lived process can exit and its PID be reused by an unrelated process
    while a lease is still active. The boot time (process start time, ``/proc/
    <pid>/stat`` field 22, expressed in clock ticks since boot) disambiguates.

    Attributes:
        host_id: Host node the process runs under (e.g. ``h-local``).
        pid: Host PID (or container-namespace PID for container-addressed runs).
        boot_time: Process start time in clock ticks since boot; ``None`` when
            the platform does not expose it (e.g. non-Linux), in which case the
            guard degrades to pid-only checks.
        container_name: Owning container name where applicable (ADR-0019/0020),
            part of the identity for container-addressed targets.
    """

    model_config = ConfigDict(frozen=True)

    host_id: str
    pid: int
    boot_time: int | None = None
    container_name: str | None = None

    @field_validator("pid")
    @classmethod
    def _positive_pid(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("pid must be positive")
        return value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProcessRuntimeIdentity):
            return NotImplemented
        return (self.host_id, self.pid, self.boot_time, self.container_name) == (
            other.host_id,
            other.pid,
            other.boot_time,
            other.container_name,
        )

    def __hash__(self) -> int:
        return hash((self.host_id, self.pid, self.boot_time, self.container_name))

    def resolve_key(self) -> str:
        """Canonical, opaque, store-safe identity key (round-trippable)."""
        return f"{self.host_id}|{self.pid}|{self.boot_time or ''}|{self.container_name or ''}"

    def key(self) -> str:  # alias: key() == resolve_key()
        return self.resolve_key()

    @classmethod
    def from_key(cls, key: str) -> ProcessRuntimeIdentity:
        """Rebuild an identity from a canonical ``resolve_key()`` string."""
        try:
            host_id, pid, boot_time, container_name = key.split("|", maxsplit=3)
        except ValueError as exc:
            raise ValueError(f"not a canonical process identity key: {key!r}") from exc
        return cls(
            host_id=host_id,
            pid=int(pid),
            boot_time=int(boot_time) if boot_time else None,
            container_name=container_name or None,
        )


class RuntimeMetadata(BaseModel):
    """Descriptive, non-identity runtime context (ADR-M1-2).

    All fields are mutable/descriptive and explicitly excluded from identity
    equality. ``project``/``service`` come from the engine's compose labels;
    ``name`` is the container name; lifecycle timestamps come from inspect.
    """

    model_config = ConfigDict(frozen=True)

    project: str | None = None
    service: str | None = None
    name: str | None = None
    labels: dict[str, str] = {}
    created_at: str | None = None
    started_at: str | None = None
    image: str | None = None

    @classmethod
    def from_compose_labels(
        cls, labels: Mapping[str, Any], name: str | None = None
    ) -> RuntimeMetadata:
        """Build metadata from engine compose labels (podman/docker)."""
        raw = {str(k): str(v) for k, v in (labels or {}).items()}
        return cls(
            project=raw.get("com.docker.compose.project"),
            service=raw.get("com.docker.compose.service"),
            name=name,
            labels=raw,
        )

    @classmethod
    def from_inspect(cls, info: Mapping[str, Any], name: str | None = None) -> RuntimeMetadata:
        """Build metadata from an engine ``inspect``-like mapping.

        Recognized keys: ``"labels"``, ``"project"``, ``"service"``,
        ``"created_at"``, ``"started_at"``, ``"image"``.
        """
        meta = cls.from_compose_labels(info.get("labels") or {}, name=name)
        overrides: dict[str, Any] = {}
        if info.get("created_at"):
            overrides["created_at"] = str(info["created_at"])
        if info.get("started_at"):
            overrides["started_at"] = str(info["started_at"])
        if info.get("image"):
            overrides["image"] = str(info["image"])
        return meta.model_copy(update=overrides)
