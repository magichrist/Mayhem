"""The audit log, as an attested event stream (plan 12, Phase 4).

Every privileged action in Mayhem — a run sealed, a manifest deleted, a hold
placed — is recorded here as an :class:`~mayhem.domain.attestation.AttestedEvent`
with its principal, its action, its target, and the digests of whatever
authorized it.

Why this is not a second logger
-------------------------------

A privileged-action log has existed in three ad-hoc shapes in this codebase:
``controller/recovery.py``'s ``recovery_audit_log`` table (state transitions, its
own format, no chain), the ``events`` journal, and the ``reason``/``hold_reason``
strings scattered through ``infra/retention.py``. None of them can answer "was
this record edited afterwards" or "who approved this, in a form I can re-verify
offline", and each invents its own columns.

This module invents none. It reuses, unchanged:

* :class:`~mayhem.domain.attestation.AttestedEvent` — the entry type;
* :func:`~mayhem.domain.attestation.canonical_event_json` — the one encoder;
* :func:`~mayhem.domain.attestation.seal_events` /
  :func:`~mayhem.domain.attestation.chain_root` — the sealing and root;
* :func:`~mayhem.domain.attestation.verify_chain` — the verifier.

An audit entry is the *same kind of object* a run-evidence event is, persisted in
a different table, and verified by the same function. If the format ever needs to
change, it changes in one place.

The one structural difference, and why a separate table exists
---------------------------------------------------------------

:func:`~mayhem.domain.attestation.verify_chain` requires every event in a chain
to share one ``run_id`` — a per-run chain. An audit log is by definition
*cross-run*: it records what people did to many different runs. So every entry
here carries the **stream's own id** as its ``run_id``, and the run being acted
on travels in the payload as ``subject_run_id``. The domain's law is respected
rather than worked around, and the audited run is still named in the sealed
bytes.

Append-only, enforced rather than promised
------------------------------------------

* The class exposes no update and no delete method. There is no code path here
  that can rewrite an entry.
* Writes are plain ``INSERT`` (not ``INSERT OR REPLACE``) and the head row is
  re-derived and checked inside the same transaction, so an append cannot silently
  overwrite a predecessor.
* M0029's ``BEFORE UPDATE`` / ``BEFORE DELETE`` triggers ``RAISE(ABORT)``, so even
  a direct SQL writer is refused.

None of that is tamper-*proofing* — with no signature (see below) a writer that
can insert can insert a *different* chain. What it does guarantee is the property
an audit log actually needs: an entry that was altered, reordered, or removed is
**detected** by :meth:`AuditStream.verify`, naming the entry, with no control
plane and no Mayhem process involved.

What this does NOT do
---------------------

* **It does not sign.** No key material, no signature bytes, no KMS/HSM, no
  Sigstore. The stream is integrity-chained and *named*, never authenticated —
  the same honesty rule :mod:`mayhem.domain.evidence_bundle` already follows. A
  reader must treat "this proves the action happened" as **integrity**, and
  "this proves *who* did it" as **not established**; the ``principal`` column is
  a recorded claim by the writer, not an authenticated identity. Phase 6 is where
  that changes, and no doc or output may imply otherwise before then.
* **It is not wired to the gates.** ``record_*`` methods exist and are called by
  :mod:`mayhem.infra.retention`; the policy/approval gates do not call in yet,
  because ``controller/policy_gate.py`` and ``controller/approval_gate.py`` are
  read-only for this phase. The seam is :meth:`AuditStream.record`.

What this IS inside
-------------------

An audit entry is evidence. It is persisted, exported, and covered by the
attestation and retention machinery, so plan 12's "secrets must never enter
evidence" binds this module as hard as it binds the envelope row or a sealed
bundle — and it binds it at the *free-form* ``detail`` dict, which is precisely
the surface a name-based rule cannot see. :meth:`AuditStream.record` therefore
calls :func:`~mayhem.infra.secret_resolver.require_persistable_document` before
the transaction opens, the same gate and the same two rules every other write
path uses. There is no audit-specific rule, no audit-specific guard, and no
opt-out parameter: :meth:`AuditStream.record` takes no ``guard=`` and reads no
configuration, exactly like the paths it now matches.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.attestation import (
    ATTESTATION_SCHEMA_VERSION,
    GENESIS_DIGEST,
    AttestedEvent,
    AttestedTimestamp,
    ChainVerification,
    RetentionClass,
    chain_root,
    seal_events,
    verify_chain,
)
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING as _SIGNATURE_UNSIGNED_NO_SIGNING,
)
from mayhem.infra.attestation_store import (
    UNSIGNED_REASON_NO_SIGNING as _UNSIGNED_REASON,
)
from mayhem.infra.attestation_store import (
    RunAuthorization,
    SealedRun,
    seal_run_evidence,
)
from mayhem.infra.secret_resolver import require_persistable_document

if TYPE_CHECKING:
    from mayhem.domain.evidence import EvidenceEnvelope
    from mayhem.infra.store import Store

#: The default stream id. One per store is the normal deployment; the id is a
#: parameter so a test (or a future per-tenant deployment) can keep streams apart
#: without a second table.
DEFAULT_STREAM_ID = "mayhem.audit"

#: The closed vocabulary of actions this module records. Every one names an
#: action, and the set is here rather than spelled inline at each call site so a
#: new action is a deliberate edit someone can grep for, and so the tests and the
#: writers cannot disagree about the spelling.
#:
#: These double as the ``event_kind`` of the resulting event (see
#: :class:`AuditEntry.action`), so an auditor filtering the stream by kind uses
#: the same strings the writers passed.
KIND_RUN_SEALED = "audit.run.sealed"
KIND_EVIDENCE_REGISTERED = "audit.evidence.registered"
KIND_EVIDENCE_ARCHIVED = "audit.evidence.archived"
KIND_EVIDENCE_DELETED = "audit.evidence.deleted"
KIND_LEGAL_HOLD_PLACED = "audit.legal_hold.placed"
KIND_LEGAL_HOLD_RELEASED = "audit.legal_hold.released"

#: The only ``signature_state`` this stream can report. Imported, not re-declared:
#: a second copy of the state string would be a second thing to keep honest, and
#: this module's entire claim is that it adds no second anything.
SIGNATURE_UNSIGNED_NO_SIGNING: str = _SIGNATURE_UNSIGNED_NO_SIGNING

#: Why the stream is unsigned. **Not restated here** — the sentence lives once, in
#: :mod:`mayhem.infra.attestation_store`, and is imported below. The reason this
#: stream is unsigned is the *same* reason every Phase 2 manifest is: no key
#: material, no KMS/HSM custody, no Sigstore, so no signature bytes were minted.
#: Entries prove the recorded bytes are unaltered and in order. They do **not**
#: prove who wrote them, and nothing in this module, its output, or any doc
#: describing it may imply otherwise before Phase 6.
UNSIGNED_REASON_NO_SIGNING: str = _UNSIGNED_REASON

#: The ``artifact`` label the evidence boundary reports under for this stream.
#:
#: Named here because an operator reading a refusal has to be able to tell which
#: write path refused, and "audit:mayhem.audit" answers that where a generic
#: "evidence" would not.
AUDIT_ARTIFACT_PREFIX = "audit:"

#: Why the stream is integrity-chained rather than being a new table format.
NO_SECOND_FORMAT_REASON = (
    "audit entries are mayhem.domain.attestation.AttestedEvent values, canonicalized by "
    "canonical_event_json and verified by verify_chain — the same types, the same "
    "encoder, and the same verifier as run-evidence attestation. A second audit format "
    "would be a second set of rules to keep honest, so there is none."
)


class AuditError(DomainError):
    """The audit stream refused a request. Nothing was written."""


class AuditStreamAppendError(AuditError):
    """An append would have broken the stream. The stream is unchanged."""


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One recorded privileged action, before it is sealed into the stream.

    A plain value, not a second event type: :meth:`to_event` turns it into the one
    event type the rest of plan 12 already uses.

    ``action`` is the event's ``event_kind`` verbatim. A separate kind field was
    tried and removed: it duplicated ``action`` and gave the two a way to
    disagree, and nothing in the verification needed the distinction.

    ``principal`` is *the identity the writer recorded*. Nothing here verifies it
    — there is no signature (see the module docstring) — so it is a claim, and
    this class is named accordingly rather than being called ``who_ran_this``.
    """

    principal: str
    action: str
    target: str
    subject_run_id: str = ""
    policy_digest: str = ""
    approval_digest: str = ""
    decision_digest: str = ""
    detail: dict[str, object] | None = None

    def __post_init__(self) -> None:
        """Refuse an entry that is not an audit record.

        Raises:
            AuditError: If the principal, action, or target is blank or untrimmed.
                An audit row with no actor is not an audit row, and the M0029
                CHECK constraints refuse it too — this is the same rule at the
                earliest possible point, with a message that says which field.
        """
        for name in ("principal", "action", "target"):
            value = str(getattr(self, name))
            if not value.strip():
                raise AuditError(f"an audit entry must name its {name}")
            if value != value.strip():
                raise AuditError(
                    f"audit entry {name} must be a trimmed non-blank string, got {value!r}"
                )

    def event_id(self, stream_id: str, sequence: int) -> str:
        """A stable, unique id: the stream, the sequence, and the action.

        Sequence-derived so two records of the same action on the same target at
        the same instant still get distinct ids — an audit log that silently
        deduplicated them would be lying about how many times something happened.
        The ``(stream_id, event_id)`` unique index then makes a replayed write fail
        loudly instead of overwriting.
        """
        return f"{stream_id}:{sequence:08d}:{self.action}"

    def payload(self) -> dict[str, object]:
        """The attested body. Names and digests, never a copy of the decision."""
        payload: dict[str, object] = {
            "principal": self.principal,
            "action": self.action,
            "target": self.target,
            "subject_run_id": self.subject_run_id,
            "policy_digest": self.policy_digest,
            "approval_digest": self.approval_digest,
            "decision_digest": self.decision_digest,
        }
        if self.detail:
            payload["detail"] = dict(self.detail)
        return payload

    def to_event(
        self,
        *,
        stream_id: str,
        sequence: int,
        recorded_at: AttestedTimestamp,
        previous_digest: str = GENESIS_DIGEST,
    ) -> AttestedEvent:
        """The unsealed :class:`AttestedEvent` for this entry.

        ``run_id`` is the *stream* id, for the reason in the module docstring:
        Phase 1's verifier requires one ``run_id`` per chain, and an audit log
        spans runs. The run acted on is in the payload as ``subject_run_id``.
        """
        return AttestedEvent(
            event_id=self.event_id(stream_id, sequence),
            event_kind=self.action,
            run_id=stream_id,
            sequence=sequence,
            payload=self.payload(),
            recorded_at=recorded_at,
            previous_digest=previous_digest,
        )


@dataclass(frozen=True, slots=True)
class AuditStreamHead:
    """The stream's recorded tip: what a verifier compares a reload against."""

    stream_id: str
    chain_root: str
    entry_count: int
    last_event_id: str
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "stream_id": self.stream_id,
            "chain_root": self.chain_root,
            "entry_count": self.entry_count,
            "last_event_id": self.last_event_id,
            "updated_at": self.updated_at,
        }


def _reading(recorded_at: AttestedTimestamp | None) -> AttestedTimestamp:
    """The caller's reading, or a fresh wall-clock + monotonic pair.

    Identical in shape to the run-evidence one, deliberately: one clock policy
    for the whole of plan 12, so an audit entry and a run event taken together
    are ordered by the same rule.
    """
    if recorded_at is not None:
        return recorded_at
    return AttestedTimestamp(
        wall_clock=utc_now(),
        monotonic_ns=time.monotonic_ns(),
        uncertainty_ms=0.0,
        source="system",
    )


class AuditStream:
    """Append-only, attested log of privileged actions.

    Three operations and no more:

    * :meth:`record` — append one :class:`AuditEntry`;
    * :meth:`load` — read the stream back, in order;
    * :meth:`verify` — re-verify it offline, and say whether it was truncated.

    There is deliberately no ``update``, ``delete``, or ``purge``. A caller that
    wants a different answer writes a new entry.
    """

    def __init__(self, store: Store, *, stream_id: str = DEFAULT_STREAM_ID) -> None:
        self._store = store
        self._stream_id = stream_id

    @property
    def stream_id(self) -> str:
        return self._stream_id

    @property
    def signature_state(self) -> str:
        """Always the unsigned state. Present so callers cannot assume otherwise."""
        return SIGNATURE_UNSIGNED_NO_SIGNING

    @property
    def signed(self) -> bool:
        """Always ``False``. Authorship is not established by this stream."""
        return False

    # -- reading ------------------------------------------------------------- #

    def load(self) -> tuple[AttestedEvent, ...]:
        """Every stored entry, in sequence order.

        Reload is exact: each row carries the same canonical JSON its digest was
        computed from, which is what makes re-verification meaningful.
        """
        rows = self._store.query(
            "SELECT event_json FROM audit_entries WHERE stream_id = ? ORDER BY sequence",
            (self._stream_id,),
        )
        return tuple(
            AttestedEvent.model_validate_json(str(dict(row)["event_json"])) for row in rows
        )

    def head(self) -> AuditStreamHead | None:
        """The recorded tip, or ``None`` for a stream nothing has been written to."""
        rows = self._store.query(
            "SELECT * FROM audit_stream_heads WHERE stream_id = ?", (self._stream_id,)
        )
        if not rows:
            return None
        row = dict(rows[0])
        return AuditStreamHead(
            stream_id=str(row["stream_id"]),
            chain_root=str(row["chain_root"]),
            entry_count=int(str(row["entry_count"])),
            last_event_id=str(row["last_event_id"]),
            updated_at=str(row["updated_at"]),
        )

    def entry_count(self) -> int:
        """How many entries are stored, whatever the head row claims."""
        rows = self._store.query(
            "SELECT COUNT(*) AS n FROM audit_entries WHERE stream_id = ?", (self._stream_id,)
        )
        return int(str(rows[0]["n"])) if rows else 0

    def entries_for_run(self, subject_run_id: str) -> tuple[AttestedEvent, ...]:
        """Every entry that acted on ``subject_run_id``, in order.

        Indexed (``idx_audit_entries_subject_run``) because the question an
        operator asks most is "what was done to this run", not "what happened".
        """
        rows = self._store.query(
            "SELECT event_json FROM audit_entries"
            " WHERE stream_id = ? AND subject_run_id = ? ORDER BY sequence",
            (self._stream_id, subject_run_id),
        )
        return tuple(
            AttestedEvent.model_validate_json(str(dict(row)["event_json"])) for row in rows
        )

    # -- writing ------------------------------------------------------------- #

    def record(
        self,
        entry: AuditEntry,
        *,
        recorded_at: AttestedTimestamp | None = None,
    ) -> AttestedEvent:
        """Append ``entry`` and return the sealed event that was written.

        The whole append is one transaction: the entry, its chain link, and the
        new head. The head is re-read and re-checked *inside* that transaction, so
        two writers racing cannot both believe they extended the same tip — the
        second sees a different root and refuses.

        The secrets gate runs before that transaction opens, not inside it: an
        audit entry is evidence (it is persisted, exported, and covered by the
        attestation and retention machinery), so plan 12's "secrets must never
        enter evidence" binds it exactly as it binds the envelope row or a sealed
        bundle. ``detail`` is free-form, so the byte rule is the one that matters
        here — a caller can plant a value under any field name — and the gate is
        the same :func:`~mayhem.infra.secret_resolver.require_persistable_document`
        every other write path calls, not a second rule. A refusal therefore
        leaves no row *and* no head update, which is stronger than a rollback.

        Raises:
            AuditError: If the entry is not a valid audit record (checked in
                :class:`AuditEntry`).
            InvariantViolationError: From the evidence boundary, if the entry
                carries a secret-classified field or a value this run resolved.
                Nothing was written.
            AuditStreamAppendError: If the stored head disagrees with the chain the
                entries actually form, or a unique constraint rejects the write.
                The stream is unchanged either way.
        """
        reading = _reading(recorded_at)
        existing = self.load()
        verification = verify_chain(existing)
        if not verification.valid:
            # Refuse to extend a stream that does not verify. Appending onto a
            # broken chain would launder the break: the new entry would inherit a
            # predecessor nobody can verify.
            raise AuditStreamAppendError(
                f"refusing to append to audit stream {self._stream_id!r}: the stored "
                f"stream does not verify ({'; '.join(verification.errors)}); appending "
                "would give the new entry a predecessor nobody can check"
            )
        head = self.head()
        if head is not None and head.entry_count != len(existing):
            raise AuditStreamAppendError(
                f"audit stream {self._stream_id!r} head records {head.entry_count} entries "
                f"but {len(existing)} are stored; the recorded head and the rows disagree"
            )
        if head is not None and existing and head.chain_root != chain_root(existing):
            raise AuditStreamAppendError(
                f"audit stream {self._stream_id!r} head records root {head.chain_root[:12]} "
                f"but the stored entries chain to {chain_root(existing)[:12]}"
            )

        previous_digest = existing[-1].chain_link if existing else GENESIS_DIGEST
        sequence = len(existing)
        unsealed = entry.to_event(
            stream_id=self._stream_id,
            sequence=sequence,
            recorded_at=reading,
            previous_digest=previous_digest,
        )
        (sealed,) = seal_events([unsealed], previous_digest=previous_digest)

        # The evidence boundary, before the transaction opens. Gating the sealed
        # event rather than ``entry.payload()`` because the sealed event is the
        # document whose JSON reaches the column: a gate on a different rendering
        # than the writer emits is a gate on the wrong artifact.
        require_persistable_document(
            sealed.model_dump(mode="json"),
            artifact=f"{AUDIT_ARTIFACT_PREFIX}{self._stream_id}",
        )

        stamp = reading.wall_clock.isoformat()
        try:
            with self._store.write() as conn:
                conn.execute(
                    "INSERT INTO audit_entries"
                    " (stream_id, sequence, event_id, event_kind, principal, action, target,"
                    "  subject_run_id, policy_digest, approval_digest, decision_digest,"
                    "  previous_digest, digest, chain_link, recorded_at, event_json)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        self._stream_id,
                        sealed.sequence,
                        sealed.event_id,
                        sealed.event_kind,
                        str(sealed.payload.get("principal", "")),
                        str(sealed.payload.get("action", "")),
                        str(sealed.payload.get("target", "")),
                        str(sealed.payload.get("subject_run_id", "")),
                        str(sealed.payload.get("policy_digest", "")),
                        str(sealed.payload.get("approval_digest", "")),
                        str(sealed.payload.get("decision_digest", "")),
                        sealed.previous_digest,
                        sealed.digest,
                        sealed.chain_link,
                        reading.wall_clock.isoformat(),
                        sealed.model_dump_json(),
                    ),
                )
                conn.execute(
                    "INSERT INTO audit_stream_heads"
                    " (stream_id, chain_root, entry_count, last_event_id, updated_at)"
                    " VALUES (?,?,?,?,?)"
                    " ON CONFLICT(stream_id) DO UPDATE SET"
                    " chain_root = excluded.chain_root,"
                    " entry_count = excluded.entry_count,"
                    " last_event_id = excluded.last_event_id,"
                    " updated_at = excluded.updated_at",
                    (
                        self._stream_id,
                        sealed.chain_link,
                        len(existing) + 1,
                        sealed.event_id,
                        stamp,
                    ),
                )
        except Exception as exc:  # sqlite3.Error and the M0029 triggers
            raise AuditStreamAppendError(
                f"refusing to append to audit stream {self._stream_id!r}: {exc}"
            ) from exc
        return sealed

    # -- verification -------------------------------------------------------- #

    def verify(self) -> ChainVerification:
        """Re-verify the stream offline, including whether it was truncated.

        Delegates to :func:`~mayhem.domain.attestation.verify_chain` for the chain
        itself and adds the one thing only the stored head can answer: a chain
        whose tail was removed still verifies internally, so the head's recorded
        root and count are compared against what the rows now produce. That is
        the check that makes deletion detectable rather than merely forbidden by
        a trigger.
        """
        entries = self.load()
        verification = verify_chain(entries)
        errors = list(verification.errors)
        head = self.head()
        if head is None:
            if entries:
                errors.append(
                    f"audit stream {self._stream_id!r} has {len(entries)} entries but no "
                    "recorded head; the stream cannot be shown to be complete"
                )
        else:
            if head.entry_count != len(entries):
                errors.append(
                    f"audit stream {self._stream_id!r} head records {head.entry_count} "
                    f"entries but {len(entries)} are stored; entries were removed"
                )
            if entries and head.chain_root != verification.root_digest:
                errors.append(
                    f"audit stream {self._stream_id!r} head records root "
                    f"{head.chain_root[:12]} but the stored entries chain to "
                    f"{verification.root_digest[:12]}"
                )
        return ChainVerification(
            valid=not errors,
            checked=len(entries),
            errors=tuple(errors),
            root_digest=verification.root_digest,
        )

    def is_append_only_intact(self) -> bool:
        """Whether every stored entry still hashes and links as it did when written."""
        return self.verify().valid

    # -- named entries ------------------------------------------------------- #

    def record_run_sealed(
        self,
        *,
        principal: str,
        run_id: str,
        manifest_id: str,
        policy_digest: str = "",
        approval_digest: str = "",
        decision_digest: str = "",
        detail: dict[str, object] | None = None,
        recorded_at: AttestedTimestamp | None = None,
    ) -> AttestedEvent:
        """Record that a run's evidence was sealed.

        ``subject_run_id`` is the run, ``target`` is the manifest: a deletion that
        removes the manifest still leaves this entry naming it.
        """
        return self.record(
            AuditEntry(
                principal=principal,
                action=KIND_RUN_SEALED,
                target=manifest_id,
                subject_run_id=run_id,
                policy_digest=policy_digest,
                approval_digest=approval_digest,
                decision_digest=decision_digest,
                detail=detail,
            ),
            recorded_at=recorded_at,
        )

    def record_evidence_deleted(
        self,
        *,
        principal: str,
        manifest_id: str,
        run_id: str,
        approver: str = "",
        policy_digest: str = "",
        approval_digest: str = "",
        decision_digest: str = "",
        detail: dict[str, object] | None = None,
        recorded_at: AttestedTimestamp | None = None,
    ) -> AttestedEvent:
        """Record a retention deletion, naming *both* halves of the dual control.

        This is the entry that must survive the deletion it records, which is why
        the tombstone's two approvers travel in the payload rather than only in
        the retention table the deletion also touches.
        """
        merged: dict[str, object] = {"approver": approver}
        if detail:
            merged.update(detail)
        return self.record(
            AuditEntry(
                principal=principal,
                action=KIND_EVIDENCE_DELETED,
                target=manifest_id,
                subject_run_id=run_id,
                policy_digest=policy_digest,
                approval_digest=approval_digest,
                decision_digest=decision_digest,
                detail=merged,
            ),
            recorded_at=recorded_at,
        )

    def record_legal_hold(
        self,
        *,
        principal: str,
        manifest_id: str,
        run_id: str,
        placed: bool,
        reason: str = "",
        recorded_at: AttestedTimestamp | None = None,
    ) -> AttestedEvent:
        """Record a hold being placed or released."""
        return self.record(
            AuditEntry(
                principal=principal,
                action=KIND_LEGAL_HOLD_PLACED if placed else KIND_LEGAL_HOLD_RELEASED,
                target=manifest_id,
                subject_run_id=run_id,
                detail={"reason": reason} if reason else None,
            ),
            recorded_at=recorded_at,
        )

    def record_evidence_archived(
        self,
        *,
        principal: str,
        manifest_id: str,
        run_id: str,
        backend: str,
        key: str,
        recorded_at: AttestedTimestamp | None = None,
    ) -> AttestedEvent:
        """Record a manifest being written to external immutable storage."""
        return self.record(
            AuditEntry(
                principal=principal,
                action=KIND_EVIDENCE_ARCHIVED,
                target=manifest_id,
                subject_run_id=run_id,
                detail={"backend": backend, "key": key},
            ),
            recorded_at=recorded_at,
        )


# --------------------------------------------------------------------------- #
# Run-close seam (documented, deliberately not wired)                          #
# --------------------------------------------------------------------------- #


def seal_run_evidence_at_run_close(
    store: Store,
    envelope: EvidenceEnvelope,
    *,
    run_status: str,
    verdict: str,
    authorization: RunAuthorization | None = None,
    audit: AuditStream | None = None,
    principal: str = "mayhem.controller",
    retention_class: RetentionClass = RetentionClass.HOT,
    manifest_id: str = "",
    previous_manifest_digest: str = GENESIS_DIGEST,
    recorded_at: AttestedTimestamp | None = None,
) -> SealedRun:
    """The one call a run-close path makes: seal the evidence, then audit it.

    Phase 4 did **not** wire this into ``controller/executor.py``, and
    :func:`seal_run_evidence` alone is the seam. This function exists so the
    later lane has one call rather than two, and so the ordering between the seal
    and the audit entry is decided here instead of at the call site.

    ## Why the executor is not the call site

    ``controller/executor.py`` never builds an ``EvidenceEnvelope`` — the type
    does not appear in that file at all. The envelope is assembled *after*
    ``RunEngine.execute`` returns, by
    ``mayhem/cli/lifecycle.py::_write_evidence_after_run``, which is the first
    place the store, the redacted envelope, and the run result all exist.
    Sealing inside ``_close_run`` would therefore mean constructing a second
    envelope inside the executor, which is the duplication
    :mod:`mayhem.infra.attestation_store` exists to avoid. Requirement 3's
    "additive or documented" branch is the documented one, and this is the
    documentation.

    ## The exact call site for the lane that owns ``cli/``

    ``src/mayhem/cli/lifecycle.py``, in ``_write_evidence_after_run``, immediately
    after the ``write_evidence(store, envelope)`` call (line 1076 at the time of
    writing) and before the ``write_evidence_file`` call:

    .. code-block:: python

        seal_run_evidence_at_run_close(
            store,
            envelope,
            run_status=str(result.status),
            verdict=str(result.verdict),
            authorization=run_authorization,   # RunAuthorization | None
        )

    ``run_authorization`` must be plumbed from the admission gate: the
    :class:`~mayhem.domain.policy.PolicyDecision` from
    ``controller.policy_gate.evaluate_gate`` and the
    :class:`~mayhem.domain.approval.ApprovalState` from
    ``controller.approval_gate.verify_approvals``, with
    ``plan_digest=plan_content_digest(plan.model_dump(mode="json"))``. Until that
    plumbing lands, pass ``authorization=None`` and the chain seals **incomplete**
    for every mutating run — which is the honest state, and exactly what
    :func:`chain_completeness` is for.

    Args:
        store: The migrated store.
        envelope: The written, redacted envelope.
        run_status: Run status at close.
        verdict: Criteria-derived verdict at close, or ``""``.
        authorization: The run's policy decision and approval state, if available.
        audit: The stream to record the seal in. ``None`` constructs a default
            :class:`~mayhem.infra.audit_stream.AuditStream` over ``store``, so the
            seal is audited by default rather than by opt-in.
        principal: Who is performing the seal. A recorded claim, not an
            authenticated identity — nothing here is signed.
        retention_class: The class the retention engine will enforce (gap 57).
        manifest_id: Manifest identifier; defaults to ``<run_id>:manifest``.
        previous_manifest_digest: Prior manifest root, for a manifest chain.
        recorded_at: The reading to stamp the events with (tests inject one).

    Returns:
        The :class:`SealedRun`, after the audit entry for the seal is written.

    Raises:
        Everything :func:`seal_run_evidence` raises, plus
            :class:`~mayhem.infra.audit_stream.AuditStreamAppendError` if the seal
            succeeded but its audit entry could not be written. The chain is
            already durable at that point; the error is raised rather than
            swallowed so a caller is never told a seal was audited when it was not.
    """
    sealed = seal_run_evidence(
        store,
        envelope,
        run_status=run_status,
        verdict=verdict,
        retention_class=retention_class,
        manifest_id=manifest_id,
        previous_manifest_digest=previous_manifest_digest,
        recorded_at=recorded_at,
        authorization=authorization,
    )
    stream = audit if audit is not None else AuditStream(store)
    stream.record_run_sealed(
        principal=principal,
        run_id=sealed.run_id,
        manifest_id=sealed.manifest.manifest_id,
        policy_digest=(
            str(sealed.events[1].payload.get("policy_digest", ""))
            if authorization is not None
            else ""
        ),
        approval_digest=(
            str(sealed.events[1].payload.get("approval_state_digest", ""))
            if authorization is not None
            else ""
        ),
        detail={
            "chain_root": sealed.chain_root,
            "manifest_digest": sealed.manifest.manifest_digest,
            "complete": sealed.complete,
            "mutating": sealed.completeness.mutating if sealed.completeness else None,
            "signature_state": sealed.signature_state,
        },
    )
    return sealed


def verify_audit_chain(events: tuple[AttestedEvent, ...]) -> ChainVerification:
    """Verify a stream of audit events by their own bytes. No store, no control plane.

    Named separately from :func:`~mayhem.domain.attestation.verify_chain` and
    delegating straight to it, so an auditor holding a list of entries — with no
    database, no Mayhem install, and no process running — has one function to
    call and knows which law it is applying. It is the same law; the wrapper is a
    statement about intent, not about behaviour.
    """
    return verify_chain(events)


__all__ = [
    "ATTESTATION_SCHEMA_VERSION",
    "AUDIT_ARTIFACT_PREFIX",
    "DEFAULT_STREAM_ID",
    "KIND_EVIDENCE_ARCHIVED",
    "KIND_EVIDENCE_DELETED",
    "KIND_EVIDENCE_REGISTERED",
    "KIND_LEGAL_HOLD_PLACED",
    "KIND_LEGAL_HOLD_RELEASED",
    "KIND_RUN_SEALED",
    "NO_SECOND_FORMAT_REASON",
    "SIGNATURE_UNSIGNED_NO_SIGNING",
    "UNSIGNED_REASON_NO_SIGNING",
    "AuditEntry",
    "AuditError",
    "AuditStream",
    "AuditStreamAppendError",
    "AuditStreamHead",
    "verify_audit_chain",
]
