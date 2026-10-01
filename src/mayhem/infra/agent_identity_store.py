"""Durable storage for agent identity state and backup descriptors (plan 19, Phase 1).

Phase 1 (:mod:`mayhem.domain.agent_identity`, :mod:`mayhem.domain.backup`) made
the rules pure: credential lifetimes and rotation windows, revocation ordering,
snapshot descriptors, and the derivation that refuses to call an unevidenced
restore a success. This module is the IO half — it persists those records behind
migration ``M0025_AGENT_IDENTITY_BACKUPS`` so a restarted controller reads back
the same identity a peer does, and so an audit can find what was stated.

What this module does NOT do
----------------------------

* **It does not verify anything.** No certificate chain, no signature, no mTLS
  handshake, no clock skew correction. It stores the ``trust_state`` Phase 1 is
  allowed to record (:data:`~mayhem.domain.agent_identity.CERTIFICATE_TRUST_UNVERIFIED`)
  and passes the decision to the domain predicates.
* **It does not take snapshots, restore, or drill.** No scheduler, no WAL
  archiving, no object-storage upload, no restore runner. It stores descriptors
  and restore *records* that something else produced. Scheduled snapshots and
  restore drills are Phase 2.
* **It is not a second authorization system.** :meth:`AgentIdentityRepository.usable_credential`
  delegates the decision to :func:`mayhem.domain.agent_identity.authorize_credential`;
  this module's job is to hand it the authoritative record and to make sure a
  revocation cannot be bypassed by reading only the identity row.
* **It is not wired into the executor.** :meth:`AgentIdentityRepository.usable_credential`
  is the seam a controller's dispatch path calls once Phase 2 ships mTLS; the
  controller is unchanged here.

Honesty rules inherited from Phase 1
------------------------------------

* **Every write is one transaction** (repo convention, ADR-0007): an identity and
  the revocation rows describing it land together or not at all.
* **Revocations are consulted on every authorization, not merged into the
  identity row.** ``agent_credential_revocations`` is append-only and is read by
  :meth:`AgentIdentityRepository.usable_credential`, so a revocation that landed
  after the last identity write is still in force. That is the propagation
  property Phase 1 states in the type; this is where it is enforced in IO.
* **No key material.** Every column is an id, a window, a reason, or a digest.
* **No achieved-RPO column.** ``recovery_objectives`` holds targets only;
  an achieved value is derived from ``backup_restore_verifications`` rows whose
  ``outcome`` is ``verified``, and ``data_loss_seconds`` stays NULL for a restore
  that never measured one.
* **No foreign key to ``runs``** (gap 101): credential and backup state must
  survive the control plane deleting the run it describes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from mayhem.domain.agent_identity import (
    AgentIdentity,
    AgentIdentityRegistry,
    CredentialGrant,
    CredentialRefusedError,
    Revocation,
    authorize_credential,
)
from mayhem.domain.backup import (
    RecoveryObjective,
    RestoreOutcome,
    RestoreVerification,
    SnapshotDescriptor,
    compare_against_objective,
    verified_restores,
)
from mayhem.domain.common import iso_utc
from mayhem.domain.errors import DomainError

if TYPE_CHECKING:
    import sqlite3

    from mayhem.domain.backup import ObjectiveReport, SnapshotKind
    from mayhem.infra.store import Store

#: What ``agent_credential_revocations.scope`` stores for a revoked credential
#: versus a revoked whole identity. A string rather than an enum because it is a
#: database value the domain type reconstructs; the CHECK constraint in
#: ``M0025`` is the second gate on it.
REVOCATION_SCOPE_CREDENTIAL = "credential"
REVOCATION_SCOPE_IDENTITY = "identity"


class SecurityStateError(DomainError):
    """Agent identity or backup persistence refused a request."""


def _now() -> datetime:
    return datetime.now(UTC)


def _stamp(moment: datetime | None = None) -> str:
    return iso_utc(_now() if moment is None else moment)


def _int(value: bool) -> int:
    return 1 if value else 0


class AgentIdentityRepository:
    """Reads and writes ``agent_identities`` and ``agent_credential_revocations``.

    The registry methods (:meth:`registry`, :meth:`revoke_credential`,
    :meth:`rotate_credential`) are the IO-backed counterparts of the pure
    :class:`~mayhem.domain.agent_identity.AgentIdentityRegistry`. They exist so
    the phase-1 type is the single implementation of the *rules* and this class
    only moves rows: every transition delegates to the domain method and
    re-validates through ``model_validate``.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    # -- reads ----------------------------------------------------------------
    def load(self, agent_id: str) -> AgentIdentity | None:
        """The identity for ``agent_id``, or ``None`` when it is not enrolled."""
        rows = self._store.query(
            "SELECT identity_json FROM agent_identities WHERE agent_id = ?", (agent_id,)
        )
        if not rows:
            return None
        return AgentIdentity.model_validate_json(str(dict(rows[0])["identity_json"]))

    def list_agents(self) -> tuple[AgentIdentity, ...]:
        """Every enrolled identity, ordered by agent id."""
        rows = self._store.query(
            "SELECT identity_json FROM agent_identities ORDER BY agent_id"
        )
        return tuple(
            AgentIdentity.model_validate_json(str(dict(row)["identity_json"])) for row in rows
        )

    def agents_for_controller(self, controller_id: str) -> tuple[AgentIdentity, ...]:
        """Every identity issued by ``controller_id``.

        The controller-mismatch refusal in Phase 1 is enforced against
        ``identity.controller_id``, which is why this index exists rather than a
        scan: a rogue controller asking "what agents are mine" is the query that
        has to be cheap enough not to matter.
        """
        rows = self._store.query(
            "SELECT identity_json FROM agent_identities WHERE controller_id = ? "
            "ORDER BY agent_id",
            (controller_id,),
        )
        return tuple(
            AgentIdentity.model_validate_json(str(dict(row)["identity_json"])) for row in rows
        )

    def expiring_before(self, cutoff: datetime) -> tuple[AgentIdentity, ...]:
        """Identities whose credential expires at or before ``cutoff``.

        This is the rotation scheduler's read. It is a query over a stored
        timestamp and nothing more: whether a credential is actually usable is
        still :meth:`~mayhem.domain.agent_identity.AgentIdentity.is_usable_at`'s
        decision at an explicit ``now``.
        """
        rows = self._store.query(
            "SELECT identity_json FROM agent_identities WHERE expires_at <= ? "
            "ORDER BY expires_at, agent_id",
            (iso_utc(cutoff),),
        )
        return tuple(
            AgentIdentity.model_validate_json(str(dict(row)["identity_json"])) for row in rows
        )

    def revocations(
        self, agent_id: str, *, scope: str | None = None
    ) -> tuple[Revocation, ...]:
        """Recorded revocations for ``agent_id``, oldest first.

        Args:
            agent_id: The agent to read the ledger for.
            scope: Restrict to ``credential`` or ``identity`` revocations. Left
                ``None``, both scopes are returned — the scope is part of the
                decision, not of the record, so a caller that ignores it gets
                everything and has to look at :attr:`Revocation.reason` alone.

        Raises:
            SecurityStateError: If ``scope`` is not a recognised scope.
        """
        if scope is not None and scope not in (
            REVOCATION_SCOPE_CREDENTIAL,
            REVOCATION_SCOPE_IDENTITY,
        ):
            msg = f"revocation scope must be credential or identity, got {scope!r}"
            raise SecurityStateError(msg)
        if scope is None:
            rows = self._store.query(
                "SELECT revocation_json FROM agent_credential_revocations "
                "WHERE agent_id = ? ORDER BY revoked_at",
                (agent_id,),
            )
        else:
            rows = self._store.query(
                "SELECT revocation_json FROM agent_credential_revocations "
                "WHERE agent_id = ? AND scope = ? ORDER BY revoked_at",
                (agent_id, scope),
            )
        return tuple(
            Revocation.model_validate_json(str(dict(row)["revocation_json"])) for row in rows
        )

    def registry(self) -> AgentIdentityRegistry:
        """Rebuild the whole :class:`AgentIdentityRegistry` from stored rows.

        The registry's ``version`` is the **maximum** stored
        ``identity_version`` rather than a count, so a rebuilt registry cannot
        look *older* than a grant somebody is holding — which is the direction
        that matters for :meth:`AgentIdentityRegistry.grant_is_current`.
        """
        identities = self.list_agents()
        version = max((identity.version for identity in identities), default=1)
        return AgentIdentityRegistry(identities=identities, version=max(version, 1))

    # -- writes ---------------------------------------------------------------
    def save(self, identity: AgentIdentity) -> AgentIdentity:
        """Insert or replace an identity row.

        The credential windows are mirrored into real columns so rotation
        scheduling and expiry sweeps are index-backed rather than JSON scans. The
        JSON column is authoritative; the mirrors are derived from it and cannot
        disagree, because both come from the same validated record.
        """
        stamp = _stamp(identity.recorded_at)
        with self._store.write() as conn:
            _upsert_identity(conn, identity, created_at=stamp, updated_at=stamp)
        return identity

    def record_revocation(
        self,
        agent_id: str,
        credential_id: str,
        revocation: Revocation,
        *,
        scope: str = REVOCATION_SCOPE_CREDENTIAL,
    ) -> None:
        """Append a revocation row. Idempotent per (agent, credential, scope, time).

        Raises:
            SecurityStateError: If ``scope`` is neither ``credential`` nor
                ``identity``. Checked here as well as by the CHECK constraint so
                the refusal names the caller.
        """
        if scope not in (REVOCATION_SCOPE_CREDENTIAL, REVOCATION_SCOPE_IDENTITY):
            msg = f"revocation scope must be credential or identity, got {scope!r}"
            raise SecurityStateError(msg)
        with self._store.write() as conn:
            _insert_revocation(conn, agent_id, credential_id, revocation, scope)

    def revoke_credential(
        self,
        agent_id: str,
        revocation: Revocation,
        *,
        credential_id: str | None = None,
    ) -> AgentIdentity:
        """Revoke a credential in the store: append the row *and* update the identity.

        Both writes are one transaction. The revocation row is the durable
        record; the identity row is updated too so a reader that only loads the
        identity still refuses. Neither alone is sufficient: the row survives a
        failed identity update, and the identity survives a rewrite that dropped
        the row — and :meth:`usable_credential` reads both, so neither gap opens.

        Raises:
            SecurityStateError: If the agent is not enrolled.
        """
        identity = self.load(agent_id)
        if identity is None:
            msg = f"cannot revoke a credential for unenrolled agent {agent_id!r}"
            raise SecurityStateError(msg)
        target = credential_id or identity.credential.credential_id
        revoked = identity.with_credential(identity.credential.revoke(revocation))
        with self._store.write() as conn:
            _insert_revocation(
                conn, agent_id, target, revocation, REVOCATION_SCOPE_CREDENTIAL
            )
            _upsert_identity(
                conn,
                revoked,
                created_at=_stamp(identity.recorded_at),
                updated_at=_stamp(),
            )
        return revoked

    def revoke_agent(self, agent_id: str, revocation: Revocation) -> AgentIdentity:
        """Revoke the whole identity in the store.

        Raises:
            SecurityStateError: If the agent is not enrolled.
        """
        identity = self.load(agent_id)
        if identity is None:
            msg = f"cannot revoke unenrolled agent {agent_id!r}"
            raise SecurityStateError(msg)
        revoked = identity.revoke(revocation)
        with self._store.write() as conn:
            _insert_revocation(
                conn,
                agent_id,
                revoked.credential.credential_id,
                revocation,
                REVOCATION_SCOPE_IDENTITY,
            )
            _upsert_identity(
                conn,
                revoked,
                created_at=_stamp(identity.recorded_at),
                updated_at=_stamp(),
            )
        return revoked

    def rotate_credential(
        self,
        agent_id: str,
        *,
        credential_id: str,
        ttl_s: float,
        now: datetime | None = None,
    ) -> AgentIdentity:
        """Rotate a credential in the store: mint a successor and save the identity.

        Delegates to :meth:`mayhem.domain.agent_identity.AgentIdentityRegistry.rotate_credential`
        through a one-agent registry so the rotation rules (strictly newer, old
        credential retained as superseded, revoked identities refuse to rotate)
        have exactly one implementation.

        Raises:
            SecurityStateError: If the agent is not enrolled.
            InvariantViolationError: If the identity is revoked or the ttl is not
                positive — surfaced from the domain, never worked around here.
        """
        identity = self.load(agent_id)
        if identity is None:
            msg = f"cannot rotate a credential for unenrolled agent {agent_id!r}"
            raise SecurityStateError(msg)
        moment = _now() if now is None else now
        advanced = (
            AgentIdentityRegistry(identities=(identity,), version=identity.version)
            .rotate_credential(
                agent_id,
                credential_id=credential_id,
                ttl_s=ttl_s,
                now=moment,
            )
            .get(agent_id)
        )
        if advanced is None:  # pragma: no cover - registry round-trip cannot drop an id
            msg = f"rotation of {agent_id!r} lost the identity it was given"
            raise SecurityStateError(msg)
        return self.save(advanced)

    # -- authorisation --------------------------------------------------------
    def usable_credential(
        self,
        agent_id: str,
        *,
        now: datetime,
        controller_id: str | None = None,
    ) -> CredentialGrant:
        """Authorize ``agent_id`` from stored state, or refuse.

        Reads the identity **and** the append-only revocation ledger, applies any
        identity-level revocation the ledger records but the identity row predates,
        and then hands the decision to
        :func:`~mayhem.domain.agent_identity.authorize_credential`. The ledger
        read is what makes revocation propagation hold across a crash between the
        two writes: a revocation row that landed without its identity update still
        refuses the agent here.

        Raises:
            CredentialRefusedError: Carrying every refusal reason, never the first.
                An agent that is **not enrolled** also lands here, with no reasons
                — the same default-deny answer
                :meth:`mayhem.domain.agent_identity.AgentIdentityRegistry.authorize`
                gives. It is a refusal rather than a store error because the caller
                of an authentication path must handle it either way.
        """
        identity = self.load(agent_id)
        if identity is None:
            raise CredentialRefusedError(
                agent_id,
                (),
                remediation="enrol the agent with a controller before it can authenticate",
            )
        revoked_by_ledger = self._ledger_identity_revocations(identity)
        if revoked_by_ledger:
            identity = identity.revoke(revoked_by_ledger[0])
        return authorize_credential(identity, now=now, controller_id=controller_id)

    def _ledger_identity_revocations(self, identity: AgentIdentity) -> tuple[Revocation, ...]:
        """**Identity-scoped** revocations the identity row does not carry yet.

        Scoped deliberately: a ``credential``-scoped row already reaches the
        decision through ``identity.credential.revocation``, and applying it a
        second time at identity level would turn "this key is burned" into "this
        agent is dead" — a strictly larger outage invented by a bookkeeping slip.

        A revocation predating the current credential is not re-applied either:
        the identity row's own validator refuses that ordering, and a rotation
        after a revocation is a different (and separately refused) situation. The
        filter keeps the ledger read total instead of raising on history.
        """
        recorded = self.revocations(identity.agent_id, scope=REVOCATION_SCOPE_IDENTITY)
        already = {existing.reason for existing in identity.revocations}
        return tuple(
            revocation
            for revocation in recorded
            if revocation.reason not in already
            and revocation.revoked_at >= identity.credential.issued_at
        )


def _upsert_identity(
    conn: sqlite3.Connection,
    identity: AgentIdentity,
    *,
    created_at: str,
    updated_at: str,
) -> None:
    """Insert or replace one ``agent_identities`` row.

    The credential windows are mirrored into real columns so rotation scheduling
    and expiry sweeps are index-backed rather than JSON scans; the JSON column
    stays authoritative. Both come from the same validated record, so they cannot
    disagree. Shared by all three write paths (save / revoke credential / revoke
    agent) so the mirrored columns cannot drift between them.
    """
    window = identity.rotation_window()
    conn.execute(
        "INSERT OR REPLACE INTO agent_identities "
        "(agent_id, controller_id, credential_id, credential_generation, "
        " rotation_state, identity_version, identity_digest, issued_at, expires_at, "
        " rotation_due_at, identity_revoked, identity_json, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            identity.agent_id,
            identity.controller_id,
            identity.credential.credential_id,
            identity.credential.generation,
            identity.credential.rotation_state.value,
            identity.version,
            identity.identity_digest(),
            iso_utc(identity.credential.issued_at),
            iso_utc(identity.credential.expires_at),
            iso_utc(window.due_at),
            _int(identity.revoked),
            identity.model_dump_json(),
            created_at,
            updated_at,
        ),
    )


def _insert_revocation(
    conn: sqlite3.Connection,
    agent_id: str,
    credential_id: str,
    revocation: Revocation,
    scope: str,
) -> None:
    """Append one ``agent_credential_revocations`` row.

    Idempotent on ``(agent_id, credential_id, scope, revoked_at)`` — re-recording
    the same revocation event is a no-op rather than a duplicate, which is what
    makes a retried revoke safe.
    """
    conn.execute(
        "INSERT OR REPLACE INTO agent_credential_revocations "
        "(agent_id, credential_id, scope, reason, revoked_at, revoked_by, "
        " note, revocation_json) VALUES (?,?,?,?,?,?,?,?)",
        (
            agent_id,
            credential_id,
            scope,
            revocation.reason.value,
            iso_utc(revocation.revoked_at),
            revocation.revoked_by,
            revocation.note,
            revocation.model_dump_json(),
        ),
    )


class BackupRepository:
    """Reads and writes snapshot descriptors, restore records, and objectives."""

    def __init__(self, store: Store) -> None:
        self._store = store

    # -- snapshots ------------------------------------------------------------
    def save_snapshot(self, descriptor: SnapshotDescriptor) -> SnapshotDescriptor:
        """Insert or replace a snapshot descriptor.

        There is deliberately no ``mark_restored`` on this class. A descriptor is
        bytes that were written; whether they came back is recorded in
        :meth:`record_restore`, as a separate row that must carry its own
        evidence.
        """
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO backup_snapshots "
                "(snapshot_id, kind, datastore, taken_at, covers_through, content_digest, "
                " parent_snapshot_id, wal_sequence, byte_size, replica_count, "
                " descriptor_digest, descriptor_json, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    descriptor.snapshot_id,
                    descriptor.kind.value,
                    descriptor.datastore,
                    iso_utc(descriptor.taken_at),
                    iso_utc(descriptor.covers_through),
                    descriptor.content_digest,
                    descriptor.parent_snapshot_id,
                    descriptor.wal_sequence,
                    descriptor.byte_size,
                    len(descriptor.replica_locators),
                    descriptor.descriptor_digest(),
                    descriptor.model_dump_json(),
                    _stamp(descriptor.taken_at),
                ),
            )
        return descriptor

    def load_snapshot(self, snapshot_id: str) -> SnapshotDescriptor | None:
        rows = self._store.query(
            "SELECT descriptor_json FROM backup_snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        )
        if not rows:
            return None
        return SnapshotDescriptor.model_validate_json(str(dict(rows[0])["descriptor_json"]))

    def list_snapshots(
        self,
        *,
        datastore: str | None = None,
        kind: SnapshotKind | None = None,
    ) -> tuple[SnapshotDescriptor, ...]:
        """Descriptors for a datastore and/or kind, newest capture first."""
        clauses: list[str] = []
        params: list[object] = []
        if datastore is not None:
            clauses.append("datastore = ?")
            params.append(datastore)
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind.value)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._store.query(
            f"SELECT descriptor_json FROM backup_snapshots{where} ORDER BY taken_at DESC, "
            "snapshot_id",
            tuple(params),
        )
        return tuple(
            SnapshotDescriptor.model_validate_json(str(dict(row)["descriptor_json"]))
            for row in rows
        )

    def snapshots_covering(
        self, *, datastore: str, at: datetime
    ) -> tuple[SnapshotDescriptor, ...]:
        """Descriptors whose ``covers_through`` reaches ``at``, newest first.

        The read a restore planner needs. It asks the descriptor's own
        ``covers_through`` — the position the capture is complete through — rather
        than its ``taken_at``, because a WAL archive written later can cover an
        earlier instant and a full taken earlier can cover nothing after it.
        """
        rows = self._store.query(
            "SELECT descriptor_json FROM backup_snapshots "
            "WHERE datastore = ? AND covers_through >= ? ORDER BY covers_through DESC",
            (datastore, iso_utc(at)),
        )
        return tuple(
            SnapshotDescriptor.model_validate_json(str(dict(row)["descriptor_json"]))
            for row in rows
        )

    # -- restore records ------------------------------------------------------
    def record_restore(self, verification: RestoreVerification) -> RestoreVerification:
        """Persist a restore record with its **derived** outcome.

        ``outcome`` is the domain's
        :attr:`~mayhem.domain.backup.RestoreVerification.status`, not a value the
        caller supplies, and ``data_loss_seconds`` is written as NULL when the
        restore never measured one. That combination is what makes "we have never
        actually measured our RPO" a visible fact in this table rather than a
        zero that reads like a good result.
        """
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO backup_restore_verifications "
                "(restore_id, snapshot_id, target_cell, drill, outcome, data_loss_seconds, "
                " duration_seconds, started_at, completed_at, plan_json, "
                " verification_json, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    verification.restore_id,
                    verification.snapshot_id,
                    verification.plan.target_cell,
                    _int(verification.plan.drill),
                    verification.status.value,
                    verification.data_loss_seconds,
                    verification.duration_seconds,
                    iso_utc(verification.started_at),
                    iso_utc(verification.completed_at),
                    verification.plan.model_dump_json(),
                    verification.model_dump_json(),
                    _stamp(verification.completed_at),
                ),
            )
        return verification

    def load_restore(self, restore_id: str) -> RestoreVerification | None:
        rows = self._store.query(
            "SELECT verification_json FROM backup_restore_verifications WHERE restore_id = ?",
            (restore_id,),
        )
        if not rows:
            return None
        return RestoreVerification.model_validate_json(
            str(dict(rows[0])["verification_json"])
        )

    def list_restores(
        self, *, snapshot_id: str | None = None, outcome: RestoreOutcome | None = None
    ) -> tuple[RestoreVerification, ...]:
        """Restore records, newest completion first."""
        clauses: list[str] = []
        params: list[object] = []
        if snapshot_id is not None:
            clauses.append("snapshot_id = ?")
            params.append(snapshot_id)
        if outcome is not None:
            clauses.append("outcome = ?")
            params.append(outcome.value)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._store.query(
            f"SELECT verification_json FROM backup_restore_verifications{where} "
            "ORDER BY completed_at DESC, restore_id",
            tuple(params),
        )
        return tuple(
            RestoreVerification.model_validate_json(str(dict(row)["verification_json"]))
            for row in rows
        )

    def verified_restores(self) -> tuple[RestoreVerification, ...]:
        """Only the restores that derived :data:`RestoreOutcome.VERIFIED`.

        Re-derives from the stored records rather than trusting the ``outcome``
        column, so a hand-edited row cannot promote itself: the domain verdict is
        recomputed from the plan and the recorded observations.
        """
        return verified_restores(self.list_restores())

    # -- objectives -----------------------------------------------------------
    def save_objective(self, objective: RecoveryObjective) -> RecoveryObjective:
        """Persist a stated objective. Targets only — no achieved columns exist.

        The primary key is ``(datastore, stated_at)`` rather than ``datastore``:
        objectives are revised over time and the revision history is the evidence
        of what was promised when.
        """
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO recovery_objectives "
                "(datastore, stated_at, rpo_seconds, rto_seconds, stated_by, "
                " objective_json, created_at) VALUES (?,?,?,?,?,?,?)",
                (
                    objective.datastore,
                    iso_utc(objective.stated_at),
                    objective.rpo_seconds,
                    objective.rto_seconds,
                    objective.stated_by,
                    objective.model_dump_json(),
                    _stamp(objective.stated_at),
                ),
            )
        return objective

    def load_objective(self, datastore: str) -> RecoveryObjective | None:
        """The most recently stated objective for ``datastore``, or ``None``."""
        rows = self._store.query(
            "SELECT objective_json FROM recovery_objectives WHERE datastore = ? "
            "ORDER BY stated_at DESC LIMIT 1",
            (datastore,),
        )
        if not rows:
            return None
        return RecoveryObjective.model_validate_json(str(dict(rows[0])["objective_json"]))

    def list_objectives(self) -> tuple[RecoveryObjective, ...]:
        rows = self._store.query(
            "SELECT objective_json FROM recovery_objectives ORDER BY datastore, stated_at DESC"
        )
        return tuple(
            RecoveryObjective.model_validate_json(str(dict(row)["objective_json"]))
            for row in rows
        )

    # -- reporting ------------------------------------------------------------
    def objective_report(self, datastore: str) -> ObjectiveReport | None:
        """The honest report for ``datastore``, or ``None`` when nothing is stated.

        Delegates straight to
        :func:`mayhem.domain.backup.compare_against_objective` over the *stored*
        restore records, so the report cannot be assembled from a target and a
        claim. A datastore with a stated objective and no verified drill returns a
        report whose ``demonstrated`` is ``False`` — the "never measured" answer,
        derived rather than asserted.
        """
        objective = self.load_objective(datastore)
        if objective is None:
            return None
        return compare_against_objective(objective, self.list_restores())
