"""Durable promotion and standby records (plan 19, Phase 3/4 persistence).

Why this table exists at all
----------------------------

Promoting a standby is the highest-consequence operation in the system, and
:mod:`mayhem.domain.failover` decides it *purely*. A pure decision with no record
is a decision somebody can re-run with different evidence and get a different
answer from, which is precisely the operation that must not be re-runnable. So this
module owns the durable half: who was promoted, out of which term, on whose
authority, with which evidence, and what was excluded.

Two tables
----------

``control_plane_standbys``
    Who has registered as a standby for a scope. Registration is a *claim*: it
    proves a controller wrote this row, and it does not prove the controller is
    alive, is reachable, or is where it says it is. Nothing in the promotion path
    treats a registered standby as evidence of anything — registration exists so
    the cluster view has a roster and so a promotion can name a known member rather
    than an arbitrary id typed at a prompt.

``control_plane_promotions``
    One row per promotion decision, **including the refused ones**. A refused
    promotion is the interesting record: "the partition was observed, the evidence
    did not establish death, and we did not promote" is the sentence an incident
    review needs, and a table that only stored successes could not produce it.

Both rows carry their own canonical document plus a ``document_digest`` recomputed
on read, the same discipline :mod:`mayhem.infra.fabric_journal` uses. A row whose
digest disagrees with its payload is refused rather than believed.

What this table deliberately has no columns for
-----------------------------------------------

* **No ``promoted`` boolean that could be set without a term.** The status column
  is CHECK-pinned to ``'promoted'``/``'refused'``, and a ``promoted`` row must
  carry ``new_term > deposed_term``; a ``refused`` row carries ``new_term = 0``.
  The database, not a validator somebody can forget, is where "a promotion that
  did not move the term" stops being storable.
* **No key material.** This table holds no secret, no certificate body, no
  signature. It names a ``signer_key_id`` nowhere at all.
* **No foreign key to ``runs``** (gap 101, as in ``M0023``/``M0032``): a control
  plane outlives the runs it dispatched, and a promotion row is exactly the record
  that has to survive the incident that caused it.
* **No achieved-RPO or achieved-RTO column.** Recovery objectives are targets and
  are measured by restore drills (Phase 2); a promotion table that grew an
  "availability achieved" column would be inventing a number.

Evidence boundary
-----------------

Both writers call
:func:`~mayhem.infra.secret_resolver.require_persistable_document` and therefore
need a ``BOUNDARY_CALL_SITES`` row in ``tests/unit/test_evidence_boundary.py`` --
a file this work item does not own. The two required rows are::

    ("mayhem.infra.failover_store", "FailoverPromotionStore.record_promotion")
        -> {"require_persistable_document"}
    ("mayhem.infra.failover_store", "FailoverPromotionStore.register_standby")
        -> {"require_persistable_document"}

The argument that binds them is the same one that bound plan 03's journal: these
rows are persisted, read back by the Phase 4 evidence recorder, and covered by the
same export and retention machinery that covers the audit stream, so they are
evidence by the same argument. The gate is in the code now; the table row is a
one-line registration the next lane makes.

Registration
------------

This migration **is** registered in :data:`mayhem.infra.migrations.ALL_MIGRATIONS`
as :data:`FAILOVER_VERSION`. The DDL, the migration object, and the row
discipline live here together so the registration could not give the DDL a second,
divergent spelling -- ``migrations.py`` *imports* ``FAILOVER_MIGRATION`` from
this module rather than re-spelling it, exactly as it does for
:mod:`mayhem.infra.fabric_journal`.

The id moved from 36 to **37** on registration. ``Migration.version`` *is* the
migration id, and plan 11's ``probe_seal`` had independently reserved 36 -- which
its own tests already published as ``36`` / ``"0036_probe_seal"``. Two migrations
cannot occupy one id: ``run_migrations`` refuses duplicates outright ("migrations
must be strictly increasing"), so the collision would have been a startup failure
in every migrated store in the repository rather than one broken test. The lower id
was already published by another lane, so this one took the next free one.
``reserved_versions()`` derives from :data:`FAILOVER_VERSION`, so it moved with it.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from mayhem.domain.attestation import canonical_event_json, content_digest
from mayhem.domain.common import iso_utc, utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.infra.certificate_authority import MTLS_ARTIFACT, MtlsRole
from mayhem.infra.migrator import Migration
from mayhem.infra.secret_resolver import require_persistable_document

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mayhem.infra.store import Store

#: The migration id reserved for this work item. The chain head is 33
#: (``fabric_journal``); 34/35 belong to the API-gateway lane and 36 to plan 11's
#: probe seal, so this one takes 37 rather than renumbering anything shipped.
#: ``Migration.version`` *is* the id, so two lanes cannot both hold 36 — the
#: migrator refuses duplicate and inverted versions at startup, and a duplicate
#: would surface as a loud failure rather than a silent overwrite.
FAILOVER_VERSION = 37

PROMOTIONS_TABLE = "control_plane_promotions"
STANDBYS_TABLE = "control_plane_standbys"

#: ``status`` values, CHECK-pinned so a row cannot carry a word the domain cannot
#: produce. There is no ``pending`` and no ``promoting``: a promotion that has not
#: taken the term has not happened.
PROMOTION_STATUSES: tuple[str, ...] = ("promoted", "refused")

_ID = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"
_IDENT = Annotated[str, StringConstraints(pattern=_ID)]

#: Boundary artifact labels, per write path, for the reason
#: :mod:`mayhem.infra.fabric_journal` names its own: an operator reading a refusal
#: has to be able to tell which write path refused.
PROMOTION_ARTIFACT = f"failover:promotion:{PROMOTIONS_TABLE}"
STANDBY_ARTIFACT = f"failover:standby:{STANDBYS_TABLE}"


def _require_aware(moment: datetime, rule: str, subject: str) -> None:
    if moment.tzinfo is None:
        raise InvariantViolationError(
            rule, f"{subject} must be timezone-aware, got naive {moment!r}"
        )


def _require_digest(value: str, rule: str, subject: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        msg = f"{subject} must be a lowercase 64-hex sha256 digest, got {value!r}"
        raise InvariantViolationError(rule, msg)
    return value


def _require_digest_if_present(value: str, rule: str, subject: str) -> None:
    """Validate ``value`` only when it is set.

    **Why the empty string is allowed.** Both row models are built in two steps: an
    unstamped draft, then :meth:`StandbyRecord.stamped` /
    :meth:`PromotionRecord.stamped`, which compute the digest over the very body
    they are validating. A validator that demanded a 64-hex digest *before*
    stamping would make the first step unrepresentable and the two ``stamped()``
    methods unreachable — the record could then only ever be constructed by a
    caller that had already computed the digest itself, which is the one thing the
    factory exists to prevent. So a model may hold ``document_digest == ""``
    meaning "not stamped yet", and the three places that must not accept one are
    explicit: :meth:`PromotionRecord.describes_itself` is ``False``, the table's
    ``CHECK`` rejects the row on write, and nothing in the read path treats an
    unstamped row as verified.
    """
    if value:
        _require_digest(value, rule, subject)


# --------------------------------------------------------------------------- #
# Schema                                                                        #
# --------------------------------------------------------------------------- #

#: Forward DDL. Kept as module constants so ``migrations.py`` can import the
#: migration object whole and a reader of that tuple never has to diff a hundred
#: lines of string to see what this lane added.
MIGRATION_SQL: tuple[str, ...] = (
    f"""
    CREATE TABLE {STANDBYS_TABLE} (
        standby_id TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        -- The role a promoted standby will present. Recorded, not granted: nothing
        -- reads this column to authorise anything; it is what an operator sees.
        role TEXT NOT NULL,
        advertised_version TEXT NOT NULL DEFAULT '',
        -- The term the standby last observed. Evidence it was ever in sync; NOT
        -- evidence it still is.
        observed_term INTEGER NOT NULL CHECK (observed_term >= 0),
        document_digest TEXT NOT NULL CHECK (
            length(document_digest) = 64 AND document_digest NOT GLOB '*[^0-9a-f]*'
        ),
        registered_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    f"CREATE INDEX idx_standbys_scope ON {STANDBYS_TABLE}(scope)",
    f"""
    CREATE TABLE {PROMOTIONS_TABLE} (
        promotion_id TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        standby_id TEXT NOT NULL,
        -- The leader this promotion replaced, and the term it held. Empty leader /
        -- zero term is the cold-start case (no leader was ever recorded).
        deposed_leader_id TEXT NOT NULL DEFAULT '',
        deposed_term INTEGER NOT NULL CHECK (deposed_term >= 0),
        -- Zero on a refusal. A promoted row must strictly exceed deposed_term.
        new_term INTEGER NOT NULL CHECK (new_term >= 0),
        operator TEXT NOT NULL,
        reason TEXT NOT NULL,
        forced INTEGER NOT NULL CHECK (forced IN (0,1)),
        status TEXT NOT NULL CHECK (status IN ('promoted','refused')),
        refusals_json TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        document_digest TEXT NOT NULL CHECK (
            length(document_digest) = 64 AND document_digest NOT GLOB '*[^0-9a-f]*'
        ),
        promoted_at TEXT NOT NULL,
        CHECK (
            (status = 'promoted' AND new_term > deposed_term AND operator <> '')
            OR
            (status = 'refused' AND new_term = 0)
        )
    )
    """,
    f"CREATE INDEX idx_promotions_scope ON {PROMOTIONS_TABLE}(scope, promoted_at)",
    # One *promotion* per (scope, term). Two controllers promoting into the same
    # term is two owners; the database refuses the second rather than the
    # application noticing.
    #
    # **Partial, on ``status = 'promoted'``.** Refused rows carry ``new_term = 0``
    # by design, so an unconditional unique index here would make the *second
    # refusal in a scope* collide with the first and raise a split-brain error
    # about a takeover that never happened. Refusals are supposed to be the common
    # case — "we saw the partition and did not promote" is the record the incident
    # review needs — so they must be appendable without limit.
    f"CREATE UNIQUE INDEX idx_promotions_once ON {PROMOTIONS_TABLE}(scope, new_term) "
    "WHERE status = 'promoted'",
)

#: Reverse DDL. Dropped child-first, the shape ``run_down_migrations`` expects.
DOWN_SQL: tuple[str, ...] = (
    "DROP INDEX idx_promotions_once",
    "DROP INDEX idx_promotions_scope",
    f"DROP TABLE {PROMOTIONS_TABLE}",
    "DROP INDEX idx_standbys_scope",
    f"DROP TABLE {STANDBYS_TABLE}",
)

#: The migration object. Registered in :data:`~mayhem.infra.migrations.ALL_MIGRATIONS`
#: by import -- not re-spelled there -- as version :data:`FAILOVER_VERSION`; see the
#: module docstring for why that is 37 and not 36.
FAILOVER_MIGRATION = Migration(
    version=FAILOVER_VERSION,
    name="ha_promotions",
    statements=MIGRATION_SQL,
    down_statements=DOWN_SQL,
)


# --------------------------------------------------------------------------- #
# Row models                                                                    #
# --------------------------------------------------------------------------- #


class PromotionIntegrityError(InvariantViolationError):
    """A stored promotion row disagrees with the document it claims to summarise.

    ``InvariantViolationError`` on purpose, as in
    :class:`~mayhem.infra.fabric_journal.FabricJournalIntegrityError`: an
    incoherent stored record is the same kind of failure as an incoherent value,
    and a caller catching one should catch the other.
    """

    RULE_DIGEST = "failover_promotion_digest"
    RULE_DOCUMENT_SHAPE = "failover_promotion_document_shape"
    RULE_TERM_ORDERING = "failover_promotion_term_ordering"


class PromotionDuplicateError(InvariantViolationError):
    """Two promotions claim the same ``(scope, new_term)``.

    Not repaired. It means two controllers both believed they took the same term,
    which is the split brain this whole plan is arranged to prevent — so it is a
    loud refusal with a rule name, not a row quietly overwritten.
    """

    RULE_SCOPE_TERM = "failover_promotion_scope_term"


class StandbyRecord(BaseModel):
    """A registered standby. **A registration is a claim, not an authentication.**

    Attributes:
        standby_id: The controller that registered.
        scope: The leadership scope it stands by for.
        role: The role it will present if promoted.
        advertised_version: What it says it is running. Unverified.
        observed_term: The term it last saw. Evidence it was once in sync, not
            that it still is.
        document_digest: sha256 over :meth:`document`, recomputed on read.
        registered_at: When it first registered (tz-aware).
        updated_at: When the row was last written (tz-aware).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    standby_id: _IDENT
    scope: str = Field(min_length=1)
    role: MtlsRole = MtlsRole.STANDBY_CONTROLLER
    advertised_version: str = ""
    observed_term: Annotated[int, Field(ge=0)] = 0
    document_digest: str = ""
    registered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> StandbyRecord:
        _require_aware(self.registered_at, "standby.time_aware", f"standby {self.standby_id}")
        _require_aware(self.updated_at, "standby.time_aware", f"standby {self.standby_id}")
        _require_digest_if_present(
            self.document_digest,
            "standby.digest_shape",
            f"standby {self.standby_id} document_digest",
        )
        return self

    def document(self) -> dict[str, Any]:
        """The canonical fields the digest covers: everything but the digest itself."""
        payload = self.model_dump(mode="json", exclude={"document_digest"})
        return dict(sorted(payload.items()))

    def stamped(self, *, at: datetime | None = None) -> StandbyRecord:
        """This record with its digest computed. The only way to make a valid one.

        The digest is taken over a document produced by **the model itself**, never
        over a hand-assembled mapping. That is not fussiness: ``iso_utc`` renders
        ``2026-03-01T12:00:00+00:00`` where pydantic's JSON mode renders
        ``2026-03-01T12:00:00Z`` for the same instant, so a digest taken over the
        first spelling never matched :meth:`document` on read and every stored row
        refused itself as tampered.
        """
        moment = utc_now() if at is None else at
        body = self.model_dump(mode="json", exclude={"document_digest", "updated_at"})
        document = StandbyRecord.model_validate({**body, "updated_at": moment}).document()
        return StandbyRecord.model_validate(
            {**document, "document_digest": content_digest(document)}
        )

    def describes_itself(self) -> bool:
        """True when the stored digest matches :meth:`document`."""
        return self.document_digest == content_digest(self.document())

    @property
    def observed(self) -> bool:
        """True when the standby has ever reported a term.

        Deliberately named ``observed`` and not ``in_sync``: one observation is a
        fact about the past, and nothing here refreshes it.
        """
        return self.observed_term > 0

    def describe(self) -> str:
        return (
            f"standby {self.standby_id} for scope {self.scope!r} (role {self.role.value}, "
            f"advertises {self.advertised_version or '(unknown version)'}, last observed term "
            f"{self.observed_term}); registration is a claim, not an authentication"
        )


class PromotionRecord(BaseModel):
    """One promotion decision, promoted or refused.

    The validator is the load-bearing part and mirrors
    :class:`mayhem.domain.failover.PromotionDecision`: ``status`` is
    ``'promoted'`` only when ``new_term > deposed_term`` and an operator is named,
    and ``'refused'`` only when ``new_term`` is zero. So the row cannot say
    "promoted" without saying which term it took, and cannot say "promoted" while
    pointing at a term nobody moved to.

    ``evidence_json`` holds the assessment's admitted *and* excluded observations.
    The excluded ones are the point: they are what somebody thought they knew and
    why it did not count, and a table that stored only the admitted rows would make
    a refusal unauditable.

    Attributes:
        promotion_id: Stable id.
        scope: The leadership scope.
        standby_id: Who was promoted (a claim).
        deposed_leader_id: The leader replaced, ``""`` on a cold start.
        deposed_term: The term replaced, ``0`` when none.
        new_term: The term now held; ``0`` on a refusal.
        operator: Who did it. Required on a promotion.
        reason: Why, in the operator's words.
        forced: Whether a live lease was taken.
        status: ``'promoted'`` or ``'refused'``.
        refusals: Canonical refusal names; empty iff promoted.
        evidence: The assessment, verbatim.
        document_digest: sha256 over :meth:`document`.
        promoted_at: When the decision was made (tz-aware).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    promotion_id: _IDENT
    scope: str = Field(min_length=1)
    standby_id: _IDENT
    deposed_leader_id: str = ""
    deposed_term: Annotated[int, Field(ge=0)] = 0
    new_term: Annotated[int, Field(ge=0)] = 0
    operator: str = ""
    reason: str = Field(min_length=1)
    forced: bool = False
    status: str = "refused"
    refusals: tuple[str, ...] = ()
    evidence: dict[str, Any] = Field(default_factory=dict)
    document_digest: str = ""
    promoted_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> PromotionRecord:
        _require_aware(
            self.promoted_at, "promotion.time_aware", f"promotion {self.promotion_id}"
        )
        if self.status not in PROMOTION_STATUSES:
            msg = (
                f"promotion {self.promotion_id} has status {self.status!r}; only "
                f"{PROMOTION_STATUSES} are storable"
            )
            raise InvariantViolationError(PromotionIntegrityError.RULE_DOCUMENT_SHAPE, msg)
        if self.status == "promoted":
            if self.new_term <= self.deposed_term:
                msg = (
                    f"promotion {self.promotion_id} claims 'promoted' into term "
                    f"{self.new_term} over term {self.deposed_term}; a takeover must "
                    "strictly increase the term or it is a second owner, not a handover"
                )
                raise InvariantViolationError(PromotionIntegrityError.RULE_TERM_ORDERING, msg)
            if not self.operator.strip():
                msg = (
                    f"promotion {self.promotion_id} claims 'promoted' with no operator; a "
                    "takeover with nobody accountable is the one nobody can audit"
                )
                raise InvariantViolationError(PromotionIntegrityError.RULE_DOCUMENT_SHAPE, msg)
            if self.refusals:
                msg = (
                    f"promotion {self.promotion_id} is 'promoted' and also carries "
                    f"refusals {list(self.refusals)}"
                )
                raise InvariantViolationError(PromotionIntegrityError.RULE_DOCUMENT_SHAPE, msg)
        elif self.new_term != 0:
            msg = (
                f"promotion {self.promotion_id} is 'refused' but names term "
                f"{self.new_term}; the scope did not move and a reader must not be able "
                "to think it did"
            )
            raise InvariantViolationError(PromotionIntegrityError.RULE_TERM_ORDERING, msg)
        _require_digest_if_present(
            self.document_digest,
            PromotionIntegrityError.RULE_DIGEST,
            f"promotion {self.promotion_id} document_digest",
        )
        return self

    @property
    def promoted(self) -> bool:
        return self.status == "promoted"

    def document(self) -> dict[str, Any]:
        """The canonical fields the digest covers: everything but the digest itself."""
        payload = self.model_dump(mode="json", exclude={"document_digest"})
        return dict(sorted(payload.items()))

    def stamped(self) -> PromotionRecord:
        """This record with its digest computed. The only way to make a valid one."""
        body = self.model_dump(mode="json", exclude={"document_digest"})
        return PromotionRecord.model_validate(
            {**body, "document_digest": content_digest(body)}
        )

    def describes_itself(self) -> bool:
        """True when the stored digest matches :meth:`document`.

        Named as a predicate rather than a bare boolean so a caller cannot
        accidentally read ``if record.document_digest:`` as agreement.
        """
        return self.document_digest == content_digest(self.document())

    def describe(self) -> str:
        if self.promoted:
            return (
                f"promotion {self.promotion_id}: {self.standby_id} took scope "
                f"{self.scope!r} to term {self.new_term} (over "
                f"{self.deposed_leader_id or '(none)'} at term {self.deposed_term}) by "
                f"{self.operator}"
                + (" UNDER --force" if self.forced else "")
                + f": {self.reason}"
            )
        names = ", ".join(self.refusals) or "unspecified"
        return (
            f"promotion {self.promotion_id}: REFUSED {self.standby_id} onto scope "
            f"{self.scope!r} ({names}); the scope did not move. {self.reason}"
        )


# --------------------------------------------------------------------------- #
# The store                                                                     #
# --------------------------------------------------------------------------- #


class FailoverPromotionStore:
    """The durable side of failover: the roster and the promotion record.

    Args:
        store: The replicated SQLite store.

    Both writers are evidence write paths and both call the boundary gate, which
    is why this module needs the two ``BOUNDARY_CALL_SITES`` rows quoted in the
    module docstring.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    # -- standbys -------------------------------------------------------------
    def register_standby(
        self,
        standby_id: str,
        *,
        scope: str,
        advertised_version: str = "",
        observed_term: int = 0,
        role: MtlsRole = MtlsRole.STANDBY_CONTROLLER,
        at: datetime | None = None,
    ) -> StandbyRecord:
        """Register (or re-register) a standby for ``scope``.

        Idempotent on ``standby_id``: a controller that restarts and re-registers
        updates its row rather than accumulating one row per boot. ``registered_at``
        is preserved across updates because "when did this join" and "when was this
        row last written" are different questions.

        Raises:
            InvariantViolationError: If the record is not well-formed, or if
                ``standby_id`` is not a usable identifier.
        """
        moment = utc_now() if at is None else at
        _require_aware(moment, "standby.time_aware", "register_standby")
        existing = self.standby(standby_id)
        record = StandbyRecord(
            standby_id=standby_id,
            scope=scope,
            role=role,
            advertised_version=advertised_version,
            observed_term=max(0, int(observed_term)),
            registered_at=existing.registered_at if existing is not None else moment,
            updated_at=moment,
        ).stamped(at=moment)
        require_persistable_document(record.document(), artifact=STANDBY_ARTIFACT)
        with self._store.write() as conn:
            conn.execute(
                f"INSERT INTO {STANDBYS_TABLE} (standby_id, scope, role, advertised_version, "
                "observed_term, document_digest, registered_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(standby_id) DO UPDATE SET scope=excluded.scope, "
                "role=excluded.role, advertised_version=excluded.advertised_version, "
                "observed_term=excluded.observed_term, "
                "document_digest=excluded.document_digest, updated_at=excluded.updated_at",
                (
                    record.standby_id,
                    record.scope,
                    record.role.value,
                    record.advertised_version,
                    record.observed_term,
                    record.document_digest,
                    iso_utc(record.registered_at),
                    iso_utc(record.updated_at),
                ),
            )
        return record

    def standby(self, standby_id: str) -> StandbyRecord | None:
        rows = self._store.query(
            f"SELECT * FROM {STANDBYS_TABLE} WHERE standby_id = ?", (standby_id,)
        )
        if not rows:
            return None
        return self._standby_from_row(dict(rows[0]))

    def standbys(self, scope: str | None = None) -> tuple[StandbyRecord, ...]:
        """Every registered standby, ordered by id. ``None`` scope means all."""
        if scope is None:
            rows = self._store.query(f"SELECT * FROM {STANDBYS_TABLE} ORDER BY standby_id")
        else:
            rows = self._store.query(
                f"SELECT * FROM {STANDBYS_TABLE} WHERE scope = ? ORDER BY standby_id", (scope,)
            )
        return tuple(self._standby_from_row(dict(row)) for row in rows)

    # -- promotions -----------------------------------------------------------
    def record_promotion(
        self,
        record: PromotionRecord,
        *,
        at: datetime | None = None,
    ) -> PromotionRecord:
        """Persist one promotion decision, promoted or refused.

        Idempotent on ``promotion_id``: re-recording the same decision is not a
        second event, and the *stored* row is returned rather than the one passed
        in, so a retry after a crash reports what is actually on disk. That
        matters because the promotion path records the decision *after* the store
        has already moved the term, and a controller that crashed between those
        two writes must be able to retry without inventing a second promotion.

        Both refusals are decided by **reading first**, inside the transaction,
        rather than by pattern-matching SQLite's error text. It used to parse
        ``str(exc)`` for ``SCOPE``/``NEW_TERM``, which is how a plain
        re-record of the same row could be reported as a split brain: the two
        unique constraints fire on the same insert and SQLite names whichever it
        checked first. Two questions, two queries, no dependence on that.

        Raises:
            PromotionDuplicateError: If a *different* decision already claims this
                ``(scope, new_term)``. Two promotions into one term is two owners.
            PromotionIntegrityError: If the row disagrees with its own document.
        """
        moment = utc_now() if at is None else at
        _require_aware(moment, "promotion.time_aware", "record_promotion")
        stamped = record.stamped() if not record.document_digest else record
        require_persistable_document(stamped.document(), artifact=PROMOTION_ARTIFACT)
        with self._store.write() as conn:
            replay = conn.execute(
                f"SELECT promotion_id FROM {PROMOTIONS_TABLE} WHERE promotion_id = ?",
                (stamped.promotion_id,),
            ).fetchone()
            if replay is not None:
                # Same decision, already recorded. Not a second event.
                return self.promotion(stamped.promotion_id) or stamped
            if stamped.promoted:
                taken = conn.execute(
                    f"SELECT promotion_id FROM {PROMOTIONS_TABLE} "
                    "WHERE scope = ? AND new_term = ?",
                    (stamped.scope, stamped.new_term),
                ).fetchone()
                if taken is not None:
                    raise PromotionDuplicateError(
                        PromotionDuplicateError.RULE_SCOPE_TERM,
                        f"scope {stamped.scope!r} already has a promotion into term "
                        f"{stamped.new_term} (recorded as {str(taken['promotion_id'])!r}): "
                        "two controllers believe they took the same term",
                    )
            try:
                conn.execute(
                    f"INSERT INTO {PROMOTIONS_TABLE} (promotion_id, scope, standby_id, "
                    "deposed_leader_id, deposed_term, new_term, operator, reason, forced, "
                    "status, refusals_json, evidence_json, document_digest, promoted_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        stamped.promotion_id,
                        stamped.scope,
                        stamped.standby_id,
                        stamped.deposed_leader_id,
                        stamped.deposed_term,
                        stamped.new_term,
                        stamped.operator,
                        stamped.reason,
                        1 if stamped.forced else 0,
                        stamped.status,
                        canonical_event_json(list(stamped.refusals)),
                        canonical_event_json(stamped.evidence),
                        stamped.document_digest,
                        iso_utc(stamped.promoted_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                # A racing writer beat us to the row between the read and the
                # insert. The constraint is the authority, so translate it rather
                # than re-raise something a caller cannot read.
                raise PromotionDuplicateError(
                    PromotionDuplicateError.RULE_SCOPE_TERM,
                    f"promotion {stamped.promotion_id!r} could not be recorded: the store "
                    f"refused it as a duplicate or a shape violation ({exc})",
                ) from exc
        return stamped

    def promotion(self, promotion_id: str) -> PromotionRecord | None:
        rows = self._store.query(
            f"SELECT * FROM {PROMOTIONS_TABLE} WHERE promotion_id = ?", (promotion_id,)
        )
        if not rows:
            return None
        return self._promotion_from_row(dict(rows[0]))

    def promotions(self, scope: str | None = None) -> tuple[PromotionRecord, ...]:
        """Every recorded promotion decision, oldest first."""
        if scope is None:
            rows = self._store.query(f"SELECT * FROM {PROMOTIONS_TABLE} ORDER BY promoted_at")
        else:
            rows = self._store.query(
                f"SELECT * FROM {PROMOTIONS_TABLE} WHERE scope = ? ORDER BY promoted_at",
                (scope,),
            )
        return tuple(self._promotion_from_row(dict(row)) for row in rows)

    def last_promotion(self, scope: str) -> PromotionRecord | None:
        """The most recent decision for ``scope``, promoted or refused."""
        rows = self._store.query(
            f"SELECT * FROM {PROMOTIONS_TABLE} WHERE scope = ? ORDER BY promoted_at DESC LIMIT 1",
            (scope,),
        )
        return self._promotion_from_row(dict(rows[0])) if rows else None

    # -- row discipline -------------------------------------------------------
    def _standby_from_row(self, record: dict[str, object]) -> StandbyRecord:
        parsed = StandbyRecord.model_validate(
            {
                "standby_id": str(record["standby_id"]),
                "scope": str(record["scope"]),
                "role": str(record["role"]),
                "advertised_version": str(record["advertised_version"]),
                "observed_term": int(str(record["observed_term"])),
                "document_digest": str(record["document_digest"]),
                "registered_at": datetime.fromisoformat(str(record["registered_at"])),
                "updated_at": datetime.fromisoformat(str(record["updated_at"])),
            }
        )
        if not parsed.describes_itself():
            msg = (
                f"standby row {parsed.standby_id!r} does not match its own digest "
                f"({parsed.document_digest[:12]}…); the row was edited outside the model"
            )
            raise InvariantViolationError(PromotionIntegrityError.RULE_DIGEST, msg)
        return parsed

    def _promotion_from_row(self, record: dict[str, object]) -> PromotionRecord:
        parsed = PromotionRecord.model_validate(
            {
                "promotion_id": str(record["promotion_id"]),
                "scope": str(record["scope"]),
                "standby_id": str(record["standby_id"]),
                "deposed_leader_id": str(record["deposed_leader_id"]),
                "deposed_term": int(str(record["deposed_term"])),
                "new_term": int(str(record["new_term"])),
                "operator": str(record["operator"]),
                "reason": str(record["reason"]),
                "forced": bool(int(str(record["forced"]))),
                "status": str(record["status"]),
                "refusals": tuple(json.loads(str(record["refusals_json"]))),
                "evidence": dict(json.loads(str(record["evidence_json"]))),
                "document_digest": str(record["document_digest"]),
                "promoted_at": datetime.fromisoformat(str(record["promoted_at"])),
            }
        )
        if not parsed.describes_itself():
            msg = (
                f"promotion row {parsed.promotion_id!r} does not match its own digest "
                f"({parsed.document_digest[:12]}…); the row was edited outside the model"
            )
            raise InvariantViolationError(PromotionIntegrityError.RULE_DIGEST, msg)
        return parsed


def assessment_document(assessment: Any) -> dict[str, Any]:
    """A :class:`~mayhem.domain.failover.LivenessAssessment` as a plain document.

    Includes the excluded observations with their reasons, because a refusal's
    evidence is mostly made of what did *not* count. Kept here rather than in the
    controller layer so the document shape the table stores has exactly one
    definition.
    """
    payload = assessment.model_dump(mode="json")
    payload["mtls_artifact"] = MTLS_ARTIFACT
    return dict(sorted(payload.items()))


def reserved_versions() -> Sequence[int]:
    """The migration versions this module's DDL occupies. :data:`FAILOVER_VERSION` only."""
    return (FAILOVER_VERSION,)
