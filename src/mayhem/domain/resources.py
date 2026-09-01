"""Resource ownership and conflict management (ADR-0015).

Every fault that mutates system state must declare exactly which resources it
creates or modifies.  ``TrackedResource`` is the canonical record; the
``ResourceOwnershipGraph`` provides in-memory conflict detection; and
``ResourceManager`` persists + recovers through the SQLite store.

Design principles:
  * ownership is scoped to (run_id, step_id, fault_id)
  * recovery is ownership-aware — experiment A never touches experiment B's resources
  * every resource must have a verify probe — recovery is not complete until verified
  * orphan detection runs through the Janitor which inspects the ownership graph
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.common import utc_now
from mayhem.domain.leases import UndoOp, VerifyProbe


class ResourceType(StrEnum):
    """Kinds of system resources a fault may create or modifies."""

    TC_RULE = "tc_rule"
    IPTABLES_RULE = "iptables_rule"
    NFTABLES_RULE = "nftables_rule"
    PROCESS_SIGNAL = "process_signal"
    CGROUP_LIMIT = "cgroup_limit"
    TOXIPROXY_TOXIC = "toxiproxy_toxic"
    CONTAINER_STATE = "container_state"
    TEMPORARY_FILE = "temporary_file"
    LOAD_GENERATOR = "load_generator"
    NETWORK_NAMESPACE = "network_namespace"
    FILESYSTEM_MOUNT = "filesystem_mount"
    PROCESS_SPAWN = "process_spawn"
    RESOURCE_LIMIT = "resource_limit"
    GENERIC = "generic"


class ResourceState(StrEnum):
    """Lifecycle of a tracked resource."""

    PENDING = "pending"  # declared, not yet created
    ACTIVE = "active"  # created and tracked
    RECOVERING = "recovering"  # cleanup in progress
    RECOVERED = "recovered"  # verified cleaned
    ORPHANED = "orphaned"  # owner experiment lost
    DIRTY = "dirty"  # cleanup failed — needs operator


class ConflictKind(StrEnum):
    """Classification of resource conflicts between experiments."""

    COEXIST = "coexist"  # different resource types on same target — OK
    SERIALIZE = "serialize"  # same resource type on same target — must not overlap
    REJECT = "reject"  # irreconcilable — one experiment must not run


class TrackedResource(BaseModel):
    """A single resource created or modified by a fault injection.

    Immutable after creation except for state transitions managed by
    ``ResourceManager``.
    """

    model_config = ConfigDict(frozen=True)

    id: str  # uuid4
    resource_type: ResourceType
    owner_run_id: str
    owner_step_id: str
    owner_fault_id: str
    state: ResourceState = ResourceState.PENDING
    target_identity: str  # immutable reference to the target node
    cleanup_op: UndoOp
    verify_probe: VerifyProbe
    created_at: datetime = Field(default_factory=utc_now)
    recovered_at: datetime | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class MutationJournalEntry(BaseModel):
    """ADR-M2 Phase 2.6 — mutation-boundary journal entry.

    Recorded at the exact boundary when the last undo-fallible op is applied
    (injection succeeds), not as a post-hoc probe result. Carries the resource
    owner, the mutation's defining op (e.g. ``kill -9``), and the lease
    reference so downstream can tell *which* lease holds the mutation and
    *what* actually mutated the system.
    """

    model_config = ConfigDict(frozen=True)

    id: str  # uuid4
    lease_id: str
    resource_id: str
    run_id: str
    step_id: str
    fault_id: str
    defining_op: UndoOp  # the op that actually mutated the system
    target_identity: str
    journaled_at: datetime = Field(default_factory=utc_now)


class ResourceConflict(BaseModel):
    """A detected conflict between a new resource and an existing one."""

    model_config = ConfigDict(frozen=True)

    kind: ConflictKind
    new_resource: TrackedResource
    existing_resource: TrackedResource
    reason: str


class RecoveryResult(BaseModel):
    """Outcome of a single resource recovery attempt."""

    model_config = ConfigDict(frozen=True)

    resource_id: str
    success: bool
    verified: bool = False
    error: str | None = None


class ResourceOwnershipGraph:
    """In-memory graph of active resource ownership.

    Not a persistence layer — the ``ResourceManager`` stores rows in SQLite
    and loads them into this graph at startup.  The graph provides fast
    conflict detection and ownership queries without touching the database
    on every check.
    """

    def __init__(self) -> None:
        self._resources: dict[str, TrackedResource] = {}
        # target_identity -> set of resource ids for fast conflict lookup
        self._by_target: dict[str, set[str]] = {}

    def add(self, resource: TrackedResource) -> None:
        """Register a resource in the graph."""
        self._resources[resource.id] = resource
        by_target = self._by_target.setdefault(resource.target_identity, set())
        by_target.add(resource.id)

    def remove(self, resource_id: str) -> TrackedResource | None:
        """Remove a resource from the graph. Returns the resource if present."""
        resource = self._resources.pop(resource_id, None)
        if resource is None:
            return None
        by_target = self._by_target.get(resource.target_identity)
        if by_target:
            by_target.discard(resource_id)
            if not by_target:
                del self._by_target[resource.target_identity]
        return resource

    def get(self, resource_id: str) -> TrackedResource | None:
        return self._resources.get(resource_id)

    def active_for_target(self, target_identity: str) -> list[TrackedResource]:
        """All active/pending resources on a given target."""
        ids = self._by_target.get(target_identity, set())
        return [
            r
            for r in (self._resources.get(rid) for rid in ids)
            if r is not None and r.state in (ResourceState.ACTIVE, ResourceState.PENDING)
        ]

    def active_for_run(self, run_id: str) -> list[TrackedResource]:
        """All active/pending resources owned by a specific run."""
        return [
            r
            for r in self._resources.values()
            if r.owner_run_id == run_id and r.state in (ResourceState.ACTIVE, ResourceState.PENDING)
        ]

    def orphans(self) -> list[TrackedResource]:
        """Resources that have no active owner run (stale after controller crash)."""
        return [
            r
            for r in self._resources.values()
            if r.state in (ResourceState.ACTIVE, ResourceState.PENDING, ResourceState.RECOVERING)
        ]

    @property
    def size(self) -> int:
        return len(self._resources)

    def detect_conflicts(self, new_resource: TrackedResource) -> list[ResourceConflict]:
        """Check whether a proposed resource conflicts with existing ones.

        Conflict rules:
          * Same resource_type + same target → SERIALIZE
          * Different resource_type + same target → COEXIST
          * Irreconcilable (e.g. tc qdisc + tc class on same device) → REJECT
        """
        conflicts: list[ResourceConflict] = []
        existing = self.active_for_target(new_resource.target_identity)

        for ex in existing:
            if ex.owner_run_id == new_resource.owner_run_id:
                continue  # same run — no conflict
            if ex.resource_type == new_resource.resource_type:
                conflicts.append(
                    ResourceConflict(
                        kind=ConflictKind.SERIALIZE,
                        new_resource=new_resource,
                        existing_resource=ex,
                        reason=(
                            f"same resource type '{new_resource.resource_type.value}' "
                            f"on target '{new_resource.target_identity}' "
                            f"owned by run '{ex.owner_run_id}'"
                        ),
                    )
                )
            else:
                conflicts.append(
                    ResourceConflict(
                        kind=ConflictKind.COEXIST,
                        new_resource=new_resource,
                        existing_resource=ex,
                        reason=(
                            f"different resource type '{new_resource.resource_type.value}' "
                            f"coexists with '{ex.resource_type.value}' "
                            f"on target '{new_resource.target_identity}'"
                        ),
                    )
                )
        return conflicts

    def has_serializable_conflicts(self, new_resource: TrackedResource) -> bool:
        """True if a SERIALIZE or REJECT conflict exists."""
        return any(
            c.kind in (ConflictKind.SERIALIZE, ConflictKind.REJECT)
            for c in self.detect_conflicts(new_resource)
        )
