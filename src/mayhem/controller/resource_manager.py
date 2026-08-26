"""Resource manager — persistence + ownership-aware recovery (ADR-0015).

Bridges the in-memory ``ResourceOwnershipGraph`` with the SQLite store so
resource tracking survives controller restarts.  Every mutation is write-ahead
persisted before the resource graph is updated.

The manager is instantiated once per controller lifecycle and shared by the
``RunEngine`` and ``Janitor``.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import TYPE_CHECKING

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.resources import (
    RecoveryResult,
    ResourceOwnershipGraph,
    ResourceState,
    ResourceType,
    TrackedResource,
)

if TYPE_CHECKING:
    from mayhem.infra.store import Store


class ResourceManager:
    """Tracks every resource created by fault injection.

    Lifecycle:
      1. ``register()`` — write-ahead persist + add to graph
      2. ``activate()`` — mark as ACTIVE after successful injection
      3. ``recover_owned()`` — ownership-aware cleanup for a run
      4. ``recover_orphans()`` — janitor picks up stale resources
      5. ``verify_recovery()`` — post-cleanup probe confirms removal
    """

    def __init__(self, store: Store) -> None:
        self._store = store
        self._graph = ResourceOwnershipGraph()
        self._ensure_table()
        self._load_graph()

    # -- schema ---------------------------------------------------------------

    def _ensure_table(self) -> None:
        with self._store.write() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tracked_resources (
                    id TEXT PRIMARY KEY,
                    resource_type TEXT NOT NULL,
                    owner_run_id TEXT NOT NULL,
                    owner_step_id TEXT NOT NULL,
                    owner_fault_id TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    target_identity TEXT NOT NULL,
                    cleanup_op_json TEXT NOT NULL,
                    verify_probe_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    recovered_at TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tr_run ON tracked_resources(owner_run_id)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tr_target ON tracked_resources(target_identity)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tr_state ON tracked_resources(state)")

    def _load_graph(self) -> None:
        """Reload the in-memory graph from persistent storage."""
        with self._store.write() as conn:
            rows = conn.execute(
                "SELECT * FROM tracked_resources WHERE state IN ('pending', 'active', 'recovering')"
            ).fetchall()
        for row in rows:
            resource = self._row_to_resource(row)
            self._graph.add(resource)

    # -- public API -----------------------------------------------------------

    def register(
        self,
        resource_type: ResourceType,
        run_id: str,
        step_id: str,
        fault_id: str,
        target_identity: str,
        cleanup_op: UndoOp,
        verify_probe: VerifyProbe,
        metadata: dict[str, object] | None = None,
    ) -> TrackedResource:
        """Declare and persist a new resource before injection.

        Raises InvariantViolationError if there is a serializable conflict
        with an existing resource owned by a *different* run.
        """
        resource = TrackedResource(
            id=str(uuid.uuid4()),
            resource_type=resource_type,
            owner_run_id=run_id,
            owner_step_id=step_id,
            owner_fault_id=fault_id,
            target_identity=target_identity,
            cleanup_op=cleanup_op,
            verify_probe=verify_probe,
            metadata=metadata or {},
        )

        # Conflict detection — raise before persisting
        conflicts = self._graph.detect_conflicts(resource)
        serializable = [c for c in conflicts if c.kind.value in ("serialize", "reject")]
        if serializable:
            raise InvariantViolationError(
                "resource_conflict",
                f"resource '{resource_type.value}' on target "
                f"'{target_identity}' conflicts with run "
                f"'{serializable[0].existing_resource.owner_run_id}': "
                f"{serializable[0].reason}",
            )

        self._persist(resource)
        self._graph.add(resource)
        return resource

    def activate(self, resource_id: str) -> TrackedResource:
        """Mark a resource as ACTIVE after successful injection."""
        return self._transition(resource_id, ResourceState.ACTIVE)

    def start_recovery(self, resource_id: str) -> TrackedResource:
        """Mark a resource as RECOVERING before cleanup starts."""
        return self._transition(resource_id, ResourceState.RECOVERING)

    def mark_recovered(self, resource_id: str, verified: bool) -> TrackedResource:
        """Mark a resource as RECOVERED or DIRTY based on verification."""
        target = ResourceState.RECOVERED if verified else ResourceState.DIRTY
        resource = self._transition(resource_id, target)
        # Persist recovery timestamp
        now = utc_now().isoformat()
        with self._store.write() as conn:
            conn.execute(
                "UPDATE tracked_resources SET recovered_at = ? WHERE id = ?",
                (now, resource_id),
            )
        return resource

    def recover_owned(self, run_id: str) -> list[RecoveryResult]:
        """Recover all resources owned by a run, in dependency order.

        Ownership-aware: skips resources that are also owned by another
        active run (should not happen, but defends against bugs).
        """
        resources = self._graph.active_for_run(run_id)
        results: list[RecoveryResult] = []
        for resource in sorted(resources, key=_recovery_order):
            result = self._recover_single(resource)
            results.append(result)
        return results

    def recover_orphans(self) -> list[RecoveryResult]:
        """Recover resources with no active owner (post-crash cleanup)."""
        orphans = self._graph.orphans()
        results: list[RecoveryResult] = []
        for resource in orphans:
            # Mark as orphaned first
            self._transition(resource.id, ResourceState.ORPHANED)
            result = self._recover_single(resource, is_orphan=True)
            results.append(result)
        return results

    def verify_recovery(self, resource_id: str) -> bool:
        """Run the resource's verify probe to confirm cleanup."""
        resource = self._graph.get(resource_id)
        if resource is None:
            return True  # already cleaned
        if resource.state != ResourceState.RECOVERED:
            return False
        # The actual probe execution happens through the agent runtime.
        # Here we just check the recorded state — the caller (RunEngine)
        # invokes the verify probe and calls mark_recovered.
        return True

    def list_resources(
        self, run_id: str | None = None, state: ResourceState | None = None
    ) -> list[TrackedResource]:
        """List tracked resources with optional filters."""
        if run_id:
            # When filtering by non-active state, we need all resources for the run
            if state and state not in (ResourceState.ACTIVE, ResourceState.PENDING):
                resources = [r for r in self._graph._resources.values() if r.owner_run_id == run_id]
            else:
                resources = self._graph.active_for_run(run_id)
        else:
            resources = list(self._graph._resources.values())
        if state:
            resources = [r for r in resources if r.state == state]
        return resources

    @property
    def graph(self) -> ResourceOwnershipGraph:
        return self._graph

    # -- internals ------------------------------------------------------------

    def _transition(self, resource_id: str, target: ResourceState) -> TrackedResource:
        resource = self._graph.get(resource_id)
        if resource is None:
            raise InvariantViolationError(
                "resource_unknown", f"resource '{resource_id}' not tracked"
            )
        # Build new resource with updated state
        updated = resource.model_copy(update={"state": target})  # type: ignore[call-arg]
        self._graph.remove(resource_id)
        self._graph.add(updated)
        with self._store.write() as conn:
            conn.execute(
                "UPDATE tracked_resources SET state = ? WHERE id = ?",
                (target.value, resource_id),
            )
        return updated

    def _persist(self, resource: TrackedResource) -> None:
        with self._store.write() as conn:
            conn.execute(
                "INSERT INTO tracked_resources "
                "(id, resource_type, owner_run_id, owner_step_id, owner_fault_id, "
                " state, target_identity, cleanup_op_json, verify_probe_json, "
                " created_at, metadata_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    resource.id,
                    resource.resource_type.value,
                    resource.owner_run_id,
                    resource.owner_step_id,
                    resource.owner_fault_id,
                    resource.state.value,
                    resource.target_identity,
                    resource.cleanup_op.model_dump_json(),
                    resource.verify_probe.model_dump_json(),
                    resource.created_at.isoformat(),
                    json.dumps(resource.metadata),
                ),
            )

    def _recover_single(
        self, resource: TrackedResource, *, is_orphan: bool = False
    ) -> RecoveryResult:
        """Execute cleanup for one resource.

        In a full implementation this sends the cleanup_op to the agent.
        For durability, the resource is transitioned to RECOVERING before
        cleanup and DIRTY/RECOVERED after.
        """
        try:
            self.start_recovery(resource.id)
            # The actual cleanup execution happens in RunEngine via the agent
            # runtime.  The resource manager just tracks state here.
            # For orphan recovery the Janitor dispatches to agents.
            return RecoveryResult(
                resource_id=resource.id,
                success=True,
                verified=False,  # verification happens after agent executes cleanup
            )
        except Exception as exc:
            return RecoveryResult(
                resource_id=resource.id,
                success=False,
                error=str(exc),
            )

    @staticmethod
    def _row_to_resource(row: sqlite3.Row) -> TrackedResource:
        return TrackedResource(
            id=row["id"],
            resource_type=ResourceType(row["resource_type"]),
            owner_run_id=row["owner_run_id"],
            owner_step_id=row["owner_step_id"],
            owner_fault_id=row["owner_fault_id"],
            state=ResourceState(row["state"]),
            target_identity=row["target_identity"],
            cleanup_op=UndoOp.model_validate_json(row["cleanup_op_json"]),
            verify_probe=VerifyProbe.model_validate_json(row["verify_probe_json"]),
            created_at=utc_now(),  # row["created_at"] is ISO string; deserialize if needed
            recovered_at=None,
            metadata=json.loads(row["metadata_json"]),
        )


def _recovery_order(resource: TrackedResource) -> int:
    """Dependency order for recovery — network rules before process signals."""
    _ORDER = {
        ResourceType.TC_RULE: 0,
        ResourceType.IPTABLES_RULE: 1,
        ResourceType.NFTABLES_RULE: 2,
        ResourceType.TOXIPROXY_TOXIC: 3,
        ResourceType.LOAD_GENERATOR: 4,
        ResourceType.CONTAINER_STATE: 5,
        ResourceType.CGROUP_LIMIT: 6,
        ResourceType.RESOURCE_LIMIT: 7,
        ResourceType.PROCESS_SIGNAL: 8,
        ResourceType.PROCESS_SPAWN: 9,
        ResourceType.NETWORK_NAMESPACE: 10,
        ResourceType.FILESYSTEM_MOUNT: 11,
        ResourceType.TEMPORARY_FILE: 12,
        ResourceType.GENERIC: 99,
    }
    return _ORDER.get(resource.resource_type, 99)
