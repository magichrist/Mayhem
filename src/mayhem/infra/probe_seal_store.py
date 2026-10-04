"""The durable probe seal: what a run's probes saw, what its conditions were, and
which of its verdicts are findable in that record
(docs/v1.1.0/11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md, Phase 4).

Phase 4's requirements split by where they can honestly be enforced:

* **Domain** (:mod:`mayhem.domain.probe_evidence`) owns the three rules — a
  reading becomes a redacted row, a citation must be findable, a condition set
  must not drift after it is sealed. Those are pure and are stated there.
* **This module** owns persistence. A seal that exists only in memory cannot be
  read back by a reviewer, and a reviewer reading a different process's memory is
  not reviewing anything; so the seal is written to the same store the rest of the
  operational surface uses, in one table, with one writer.

Why this is evidence and therefore gated
-----------------------------------------

:class:`ProbeSealTable.seal` writes a **caller-authored free-form document** —
the redacted observation rows, the sealed condition set, the citation verdicts. It
is persisted, exported by the same machinery that covers the audit stream, and read
back by the retention engine, so the argument that binds
:mod:`mayhem.infra.audit_stream` binds it exactly: plan 12's "secrets must never
enter evidence" applies. The writer therefore calls
:func:`~mayhem.infra.secret_resolver.require_persistable_document` on the document
before it becomes a row, and the call is **unskippable** — it is the same shape the
boundary suite in ``tests/unit/test_evidence_boundary.py`` requires, and this
module's single writer has a ``BOUNDARY_CALL_SITES`` row there:

    ("mayhem.infra.probe_seal_store", "ProbeSealTable.seal")
        -> {"require_persistable_document"}

If that row is not added by the reviewer of this lane, the structural guard in
that suite fails on an unregistered gate caller — which is the correct outcome for
a write path nobody registered, and is why it is reported rather than assumed.

The three refusals a read can produce
-------------------------------------

Reading a seal back is not a lookup and a lookup can fail silently. So
:meth:`ProbeSealTable.read` returns the rows, and the three ways a *verification*
of those rows can fail are each named:

* a row whose payload digest does not match the row's own digest
  (``probes.seal_payload_drifted``) — the stored bytes moved;
* a citation whose fingerprint is not in the sealed observations
  (``probes.seal_cites_unrecorded_observation``) — a stop whose evidence is not
  in the seal;
* a sealed condition set whose digest does not match its rows
  (``probes.seal_conditions_drifted``) — the conditions moved after sealing.

The first and third are detected here because they are properties of the *stored
bytes*, which is the only place they can be observed.

Migration reservation
---------------------

:data:`PROBE_SEAL_VERSION` is **36**. The chain head was 33
(``fabric_journal``) when this was written, 34 and 35 are reserved by another
lane, and the migrator keys on ``version`` and refuses duplicates — so 36 was
reserved rather than chosen by renumbering anything already shipped. The DDL is
defined **here**, not in :mod:`mayhem.infra.migrations`, because this work item does
not own that file; registering :data:`PROBE_SEAL_MIGRATION` in
:data:`~mayhem.infra.migrations.ALL_MIGRATIONS` is a one-line additive change for
whoever owns it, and until it happens this table exists only where a caller splices
the migration in — which is the arrangement :mod:`mayhem.infra.fabric_journal`
itself was written under, and is recorded here rather than glossed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import canonical_json, digest
from mayhem.domain.probe_evidence import (
    ProbeEvidenceRecord,
    ReadingView,
    SealedConditionSet,
    envelope_observations,
)
from mayhem.infra.migrator import Migration
from mayhem.infra.secret_resolver import require_persistable_document

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "DOWN_SQL",
    "MIGRATION_SQL",
    "PROBE_SEAL_MIGRATION",
    "PROBE_SEAL_TABLE",
    "PROBE_SEAL_VERSION",
    "ProbeSeal",
    "ProbeSealIntegrityError",
    "ProbeSealTable",
    "probe_seal_artifact",
    "records_from",
]


#: The migration id reserved for this work item. See the module docstring: the
#: chain head was 33 and 34/35 belong to another lane, so 36 was reserved rather
#: than chosen by renumbering anything already shipped.
PROBE_SEAL_VERSION = 36

#: The table the durable seal lives in.
PROBE_SEAL_TABLE = "probe_seals"

#: The ``artifact`` label the evidence boundary reports a seal refusal under.
#: Named per write path for the reason :mod:`mayhem.infra.audit_stream` names its
#: own: an operator reading a refusal has to be able to tell *which* write path
#: refused.
PROBE_SEAL_ARTIFACT_PREFIX = "probe:seal:"


def probe_seal_artifact(run_id: str) -> str:
    """The boundary label for one run's seal writes."""
    return f"{PROBE_SEAL_ARTIFACT_PREFIX}{run_id}"


# --------------------------------------------------------------------------- #
# Schema                                                                       #
# --------------------------------------------------------------------------- #

#: Forward DDL. Kept as a module constant so the object
#: :data:`mayhem.infra.migrations.ALL_MIGRATIONS` would import and a reader of
#: that tuple never has to diff a DDL string to see what a lane added.
MIGRATION_SQL: tuple[str, ...] = (
    f"""
    CREATE TABLE {PROBE_SEAL_TABLE} (
        run_id TEXT NOT NULL,
        stage TEXT NOT NULL,
        at_epoch_s REAL NOT NULL,
        -- the redacted probe evidence rows this run produced. One row per
        -- collection attempt, available or not: a seal that only holds the
        -- attempts that worked cannot answer "what could this run not see?",
        -- which is the question a reviewer asks first.
        observations_json TEXT NOT NULL,
        -- the sealed condition set, with its digest.
        conditions_json TEXT NOT NULL,
        conditions_digest TEXT NOT NULL,
        -- what the citation check concluded, and the citation fingerprints.
        citations_json TEXT NOT NULL,
        -- 64 lowercase hex or nothing, recomputed on every read.
        payload_digest TEXT NOT NULL,
        sealed_at TEXT NOT NULL,
        PRIMARY KEY (run_id, stage, at_epoch_s)
    )
    """,
    f"CREATE INDEX idx_probe_seals_run ON {PROBE_SEAL_TABLE}(run_id)",
)

#: Reverse DDL. Child-first, the shape ``run_down_migrations`` expects.
DOWN_SQL: tuple[str, ...] = (
    "DROP INDEX idx_probe_seals_run",
    f"DROP TABLE {PROBE_SEAL_TABLE}",
)

#: The migration object, for whoever registers it in
#: :data:`~mayhem.infra.migrations.ALL_MIGRATIONS` as version 36.
PROBE_SEAL_MIGRATION = Migration(
    version=PROBE_SEAL_VERSION,
    name="probe_seal",
    statements=MIGRATION_SQL,
    down_statements=DOWN_SQL,
)


# --------------------------------------------------------------------------- #
# Integrity                                                                    #
# --------------------------------------------------------------------------- #


class ProbeSealIntegrityError(InvariantViolationError):
    """A stored seal disagrees with the payload it claims to summarise.

    A subclass of :class:`~mayhem.domain.errors.InvariantViolationError` on purpose:
    it *is* an invariant violation, and a caller catching the base to mean
    "this seal cannot be trusted" should get it. :attr:`stored_digest` and
    :attr:`recomputed_digest` are carried so a reader can see the two, not be told
    they differ.
    """

    def __init__(
        self,
        rule: str,
        message: str,
        *,
        stored_digest: str = "",
        recomputed_digest: str = "",
    ) -> None:
        super().__init__(rule, message)
        self.stored_digest = stored_digest
        self.recomputed_digest = recomputed_digest


@dataclass(frozen=True, slots=True)
class ProbeSeal:
    """One sealed stage of a run: its observations, its conditions, its citations.

    A frozen record, so a seal that has been constructed cannot be edited into
    something other than what was sealed — the same reason
    :class:`~mayhem.domain.stop_conditions.Firing` is frozen.
    """

    run_id: str
    stage: str
    at_epoch_s: float
    observations: tuple[dict[str, Any], ...]
    conditions: dict[str, Any]
    conditions_digest: str
    citations: dict[str, Any]
    payload_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "stage": self.stage,
            "at_epoch_s": self.at_epoch_s,
            "observations": [dict(row) for row in self.observations],
            "conditions": dict(self.conditions),
            "conditions_digest": self.conditions_digest,
            "citations": dict(self.citations),
            "payload_digest": self.payload_digest,
        }


def _payload_digest(
    *,
    run_id: str,
    stage: str,
    at_epoch_s: float,
    observations: Sequence[dict[str, Any]],
    conditions: dict[str, Any],
    conditions_digest: str,
    citations: dict[str, Any],
) -> str:
    """The digest over the whole sealed payload. One function, both directions."""
    return digest(
        {
            "run_id": run_id,
            "stage": stage,
            "at_epoch_s": at_epoch_s,
            "observations": [dict(row) for row in observations],
            "conditions": dict(conditions),
            "conditions_digest": conditions_digest,
            "citations": dict(citations),
        }
    )


# --------------------------------------------------------------------------- #
# Row discipline                                                               #
# --------------------------------------------------------------------------- #


class ProbeSealTable:
    """The one writer and the one reader of a run's probe seal.

    ``conn`` may be a :class:`sqlite3.Connection` or anything with
    ``execute``/``commit``. The write is a single ``INSERT OR REPLACE`` per sealed
    stage, and every write is gated by
    :func:`~mayhem.infra.secret_resolver.require_persistable_document` on the
    document the columns receive — *before* the row exists, so a refused seal
    leaves no trace.

    ``INSERT OR REPLACE`` rather than ``INSERT``: a sweep that re-seals a stage at
    the same instant is the same fact recorded twice, and refusing it would make
    the digest check unreachable in normal operation. The replacement is keyed on
    ``(run_id, stage, at_epoch_s)``, so it can only ever overwrite *itself*.
    """

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def seal(
        self,
        *,
        run_id: str,
        stage: str,
        at_epoch_s: float,
        views: Sequence[ReadingView],
        sealed: SealedConditionSet,
        citations: dict[str, Any],
    ) -> ProbeSeal:
        """Seal one stage of a run's probe record.

        Args:
            run_id: The run this seal belongs to.
            stage: The lifecycle stage being sealed.
            at_epoch_s: When the stage ended. Injected, never read from a clock.
            views: The :class:`~mayhem.domain.probe_evidence.ReadingView` values
                from the sweep — **every attempt, available or not**.
            sealed: The sealed condition set. Its ``sealed_digest`` must be
                computed; an unsealed set is refused here rather than written with
                an empty digest that would verify against nothing.
            citations: What :func:`mayhem.domain.probe_evidence.verify_citations`
                concluded, as a JSON-safe document.

        Raises:
            InvariantViolationError: With ``probes.seal_conditions_unsealed`` if
                ``sealed`` was not sealed, or with the boundary's own refusal when
                the document carries a resolved secret.
        """
        if not sealed.sealed_digest:
            raise InvariantViolationError(
                "probes.seal_conditions_unsealed",
                f"cannot seal run {run_id!r} stage {stage!r} with an unsealed condition "
                "set: an unsealed set carries no digest, so a later reader could not "
                "tell whether the conditions moved. Call SealedConditionSet.seal() first.",
            )
        if sealed.run_id != run_id:
            raise InvariantViolationError(
                "probes.seal_run_id_mismatch",
                f"cannot seal run {run_id!r} with a condition set sealed for "
                f"{sealed.run_id!r}: the digest covers the run id, so a seal whose "
                "conditions came from another run verifies against nothing",
            )
        observations = envelope_observations(views)
        conditions = sealed.to_dict()
        payload = _payload_digest(
            run_id=run_id,
            stage=stage,
            at_epoch_s=at_epoch_s,
            observations=observations,
            conditions=conditions,
            conditions_digest=sealed.sealed_digest,
            citations=citations,
        )
        record = ProbeSeal(
            run_id=run_id,
            stage=stage,
            at_epoch_s=at_epoch_s,
            observations=observations,
            conditions=conditions,
            conditions_digest=sealed.sealed_digest,
            citations=citations,
            payload_digest=payload,
        )
        document = {
            "observations": list(observations),
            "conditions": conditions,
            "citations": citations,
        }
        # The boundary. Unskippable by construction: this is a direct call with no
        # keyword that could disable it, which is what
        # ``test_a_gate_offers_no_opt_out_parameter`` in
        # ``tests/unit/test_evidence_boundary.py`` checks for every gate.
        require_persistable_document(document, artifact=probe_seal_artifact(run_id))
        self._conn.execute(
            f"""
            INSERT OR REPLACE INTO {PROBE_SEAL_TABLE} (
                run_id, stage, at_epoch_s, observations_json, conditions_json,
                conditions_digest, citations_json, payload_digest, sealed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                stage,
                at_epoch_s,
                canonical_json(list(observations)),
                canonical_json(conditions),
                sealed.sealed_digest,
                canonical_json(citations),
                payload,
                "injected-by-caller",
            ),
        )
        self._conn.commit()
        return record

    def read(self, run_id: str) -> tuple[ProbeSeal, ...]:
        """Every sealed stage of a run, in stage order, each one verified.

        Verification happens on read rather than only on write because a seal that
        was written correctly and then altered in the database is exactly the case
        a reviewer needs caught, and a read that returned it unverified would be
        the same unverified read every time.
        """
        rows = self._conn.execute(
            f"""
            SELECT run_id, stage, at_epoch_s, observations_json, conditions_json,
                   conditions_digest, citations_json, payload_digest
            FROM {PROBE_SEAL_TABLE}
            WHERE run_id = ?
            ORDER BY at_epoch_s, stage
            """,
            (run_id,),
        ).fetchall()
        return tuple(self._verify(row) for row in rows)

    def _verify(self, row: Sequence[Any]) -> ProbeSeal:
        (
            sealed_run,
            stage,
            at_epoch_s,
            observations_json,
            conditions_json,
            conditions_digest,
            citations_json,
            payload_digest,
        ) = row
        observations = tuple(json.loads(observations_json))
        conditions = json.loads(conditions_json)
        citations = json.loads(citations_json)
        recomputed = _payload_digest(
            run_id=sealed_run,
            stage=stage,
            at_epoch_s=at_epoch_s,
            observations=observations,
            conditions=conditions,
            conditions_digest=conditions_digest,
            citations=citations,
        )
        if recomputed != payload_digest:
            raise ProbeSealIntegrityError(
                "probes.seal_payload_drifted",
                f"the sealed stage {stage!r} of run {sealed_run!r} stores a payload "
                f"digest of {payload_digest[:12]}… but its columns hash to "
                f"{recomputed[:12]}…: the stored bytes moved after they were sealed, so "
                "nothing this seal says can be relied on",
                stored_digest=str(payload_digest),
                recomputed_digest=recomputed,
            )
        if conditions.get("sealed_digest") != conditions_digest:
            raise ProbeSealIntegrityError(
                "probes.seal_conditions_drifted",
                f"the sealed stage {stage!r} of run {sealed_run!r} stores conditions "
                f"whose own digest is {str(conditions.get('sealed_digest'))[:12]}… while "
                f"the row claims {conditions_digest[:12]}…: the conditions moved after "
                "they were sealed, so every firing made under them is no longer "
                "reproducible",
                stored_digest=conditions_digest,
                recomputed_digest=str(conditions.get("sealed_digest", "")),
            )
        return ProbeSeal(
            run_id=sealed_run,
            stage=stage,
            at_epoch_s=at_epoch_s,
            observations=observations,
            conditions=conditions,
            conditions_digest=conditions_digest,
            citations=citations,
            payload_digest=payload_digest,
        )

    def observations_for(self, run_id: str) -> tuple[dict[str, Any], ...]:
        """Every sealed observation row for a run, across stages, in stage order.

        The reviewer-facing read: *what did mayhem actually see?* — including the
        rows that carry ``availability: "unavailable"``, because a seal that only
        returned the attempts that worked would answer this question wrongly.
        """
        rows: list[dict[str, Any]] = []
        for seal in self.read(run_id):
            rows.extend(dict(row) for row in seal.observations)
        return tuple(rows)

    def assert_citations_in_evidence(self, run_id: str) -> None:
        """Every fingerprint the seal's citation check recorded must be present.

        The Phase 4 acceptance criterion, evaluated against **persisted** bytes
        rather than in-memory objects, so it holds for a reviewer in another
        process reading a database rather than only for the run that wrote it.

        Raises:
            ProbeSealIntegrityError: With ``probes.seal_cites_unrecorded_observation``
                and every fingerprint named that is not in the sealed observations.
        """
        missing: list[str] = []
        for seal in self.read(run_id):
            recorded = {
                row.get("fingerprint")
                for row in seal.observations
                if isinstance(row, dict) and row.get("fingerprint")
            }
            verified = seal.citations.get("verified") if isinstance(seal.citations, dict) else None
            for fingerprint in verified or ():
                if fingerprint not in recorded:
                    missing.append(fingerprint)
        if missing:
            raise ProbeSealIntegrityError(
                "probes.seal_cites_unrecorded_observation",
                f"the seal for run {run_id!r} records "
                f"{len(missing)} verified citation(s) that are not in its own sealed "
                f"observations ({', '.join(missing)}): a stop whose cited evidence is "
                "not in the seal cannot be reviewed, replayed or defended",
            )


def records_from(seal: ProbeSeal) -> tuple[ProbeEvidenceRecord, ...]:
    """The sealed rows as :class:`~mayhem.domain.probe_evidence.ProbeEvidenceRecord`.

    For a caller verifying a freshly-computed firing against what was *persisted*
    rather than against the objects it still holds in memory — the case that
    matters, because the in-memory objects are the ones a bug could have produced.
    """
    records: list[ProbeEvidenceRecord] = []
    for row in seal.observations:
        records.append(
            ProbeEvidenceRecord(
                probe_id=str(row.get("probe_id", "")),
                family=str(row.get("family", "")),
                stage=str(row.get("stage", "")),
                availability=str(row.get("availability", "")),
                at_epoch_s=float(row.get("at_epoch_s", 0.0)),
                value=row.get("value"),
                unit=str(row.get("unit", "")),
                provenance=str(row.get("provenance", "")),
                evidence_ref=str(row.get("evidence_ref", "")),
                fingerprint=str(row.get("fingerprint", "")),
                note=str(row.get("note", "")),
            )
        )
    return tuple(records)
