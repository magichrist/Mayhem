"""Backup descriptors, restore plans, and RPO/RTO as data (plan 19, Phase 1).

Plan ``docs/v1.1.0/19_HA_DR_SECURITY.md`` Phase 1 asks for "snapshot
descriptors, RPO/RTO objectives as data, restore plans" and, in Phase 2, for
"restore drills that actually restore into an isolated cell and verify". Its
acceptance for Phase 2 says the drills must *prove* RPO/RTO "rather than
asserting them". This module is the type-level half of that sentence: it is
built so that asserting is not an available operation.

The three properties this module exists to make unrepresentable
-----------------------------------------------------------------------

1. **A stated objective is a target, never a measurement.**
   :class:`RecoveryObjective` holds *only* what somebody committed to, and its
   fields are named ``rpo_seconds``/``rto_seconds`` under a class whose
   docstring says "target". It has no ``achieved`` field, no ``met`` field, and
   no method that returns a boolean about performance — because the honest answer
   to "did we hit our RPO?" is not a property of the objective, it is a
   comparison against :class:`RestoreVerification` records that exist. The only
   way out is :meth:`RecoveryObjective.achieved_rpo` /
   :meth:`RecoveryObjective.achieved_rto`, which return ``None`` when no
   verified restore evidence exists. **A stated RPO with no restore evidence is
   never an achieved RPO**, because the achieved value is a
   :class:`Measurement` that *requires* its evidence as a field.
2. **An unverified restore cannot be reported as successful.**
   :class:`RestoreVerification` has no success flag. Its :attr:`status` is
   *derived* — ``VERIFIED`` only when every required check actually ran and
   passed **and** data loss was actually measured — and
   :meth:`RestoreVerification.claim_success` raises
   :class:`UnverifiedRestoreError` otherwise. There is no constructor path that
   writes "the restore worked", only one that records what was observed and lets
   the arithmetic decide.
3. **A snapshot descriptor claims nothing about restorability.**
   :class:`SnapshotDescriptor` describes *bytes that were written*. It has no
   ``restored``/``verified``/``good`` field at all, and a
   :class:`RestoreCheckResult` that claims ``passed`` must carry the observation
   that passed — a bare "passed" with no detail is refused at construction,
   because "the row count matched" and "I clicked the button" are the same
   value in a boolean and only one of them is evidence.

What this module is NOT
-----------------------

* **No backup engine.** No scheduler, no WAL archiving, no object-storage upload,
  no ``sqlite3 .backup``. Scheduled snapshots and evidence replication to object
  storage (plan 12) are Phase 2.
* **No restore runner.** A :class:`RestoreVerification` is *recorded* by whatever
  performed the restore; this module verifies the record's internal consistency
  and derives the verdict. It cannot restore anything, so it cannot prove that a
  restore happened either — it can only refuse to call an unevidenced restore a
  success.
* **No claim that any RPO/RTO has ever been met.** Nothing in this module can
  produce an achieved value without restore evidence attached to it, so a doc
  that quotes an achieved number has to quote a restore id.

Pure by construction: no IO, no clock read (``now`` is an argument), no store,
consistent with the "Domain layer has zero IO and no upward imports" contract.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

_SHA256_HEX = r"^[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"

#: Refusal code for a restore that is being reported as successful without proof.
RESTORE_UNVERIFIED = "restore_unverified"
#: Refusal code for a measurement quoted without restore evidence.
MEASUREMENT_WITHOUT_EVIDENCE = "measurement_without_evidence"


def _require_aware(moment: datetime, rule: str, subject: str) -> None:
    """Refuse naive datetimes — the same discipline :mod:`mayhem.domain.fabric` uses."""
    if moment.tzinfo is None:
        raise InvariantViolationError(
            rule, f"{subject} must be timezone-aware, got naive {moment!r}"
        )


class UnverifiedRestoreError(InvariantViolationError):
    """Somebody tried to report a restore as successful without evidence."""

    def __init__(
        self,
        restore_id: str,
        status: str,
        missing_checks: Sequence[str] = (),
        failed_checks: Sequence[str] = (),
    ) -> None:
        self.code = RESTORE_UNVERIFIED
        self.restore_id = restore_id
        self.status = status
        self.missing_checks = tuple(missing_checks)
        self.failed_checks = tuple(failed_checks)
        parts = [f"restore outcome is {status}"]
        if self.missing_checks:
            parts.append(f"required checks never ran: {', '.join(self.missing_checks)}")
        if self.failed_checks:
            parts.append(f"checks failed: {', '.join(self.failed_checks)}")
        super().__init__(RESTORE_UNVERIFIED, f"restore {restore_id}: " + "; ".join(parts))


# --------------------------------------------------------------------------- #
# Snapshots                                                                    #
# --------------------------------------------------------------------------- #


class SnapshotKind(StrEnum):
    """What a snapshot is, which decides what it can be restored from.

    ``EVIDENCE`` is plan 12's evidence replication arriving as a backup target:
    evidence is the one artifact whose loss cannot be re-derived by re-running
    anything, so it is a first-class snapshot kind rather than a tag.
    """

    FULL = "full"
    INCREMENTAL = "incremental"
    WAL_ARCHIVE = "wal_archive"
    EVIDENCE = "evidence"


class EncryptionDescriptor(BaseModel):
    """How a snapshot at rest is encrypted. A *reference*, never a key.

    There is deliberately no field a key could occupy. Plan 29 owns secret
    resolution and its ``secret_grants`` table already holds permissions rather
    than values; this follows the same rule, so no code path can persist a key
    through this repository even if a future author tries.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: str = Field(min_length=1)
    key_ref: str = Field(pattern=_ID)
    key_custodian: str = Field(min_length=1)


class SnapshotDescriptor(BaseModel):
    """A record of bytes that were written somewhere. **Not** a claim they restore.

    Note what is absent: there is no ``restored``, ``verified``, ``good``, or
    ``healthy`` field, and adding one would be a category error rather than a
    missing feature. A descriptor is written by the thing that wrote the bytes;
    whether those bytes can be restored is a question only a
    :class:`RestoreVerification` answers, and only with observations attached.

    Attributes:
        snapshot_id: Stable id (``snap-2026-03-01T02:00Z``).
        kind: One of :class:`SnapshotKind`.
        datastore: What was captured (``mayhem-sqlite``, ``evidence-store``).
        taken_at: When the capture was written.
        covers_through: The data position the capture is complete through. This
            is the field an RPO is measured against, and it is required: a
            snapshot that does not say what it covers cannot support a recovery
            claim.
        content_digest: Digest of the captured payload.
        storage_locator: Where the bytes live (plan 08's replicated store).
        replica_locators: Additional copies, when the bytes were replicated.
        byte_size: Size of the captured payload.
        parent_snapshot_id: The base a full/incremental chain is read from.
        wal_sequence: Log sequence for a WAL archive or an incremental.
        encryption: At-rest encryption reference, if any.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot_id: str = Field(pattern=_ID)
    kind: SnapshotKind
    datastore: str = Field(min_length=1)
    taken_at: datetime
    covers_through: datetime
    content_digest: str = Field(pattern=_SHA256_HEX)
    storage_locator: str = Field(min_length=1)
    replica_locators: tuple[str, ...] = ()
    byte_size: Annotated[int, Field(ge=0)] = 0
    parent_snapshot_id: str | None = None
    wal_sequence: Annotated[int, Field(ge=0)] | None = None
    encryption: EncryptionDescriptor | None = None
    note: str = ""

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(self.taken_at, "snapshot.time_aware", f"snapshot {self.snapshot_id}")
        _require_aware(
            self.covers_through, "snapshot.time_aware", f"snapshot {self.snapshot_id}"
        )
        if self.covers_through > self.taken_at:
            msg = (
                f"snapshot {self.snapshot_id} claims to cover data through "
                f"{self.covers_through.isoformat()} but was only written at "
                f"{self.taken_at.isoformat()}; a capture cannot contain the future"
            )
            raise InvariantViolationError("snapshot.covers_future", msg)
        if self.kind is SnapshotKind.INCREMENTAL and not self.parent_snapshot_id:
            msg = (
                f"incremental snapshot {self.snapshot_id} names no parent; an incremental "
                "with nothing to apply it to is not restorable"
            )
            raise InvariantViolationError("snapshot.incremental_without_parent", msg)
        if self.wal_sequence is None and self.kind in (
            SnapshotKind.INCREMENTAL,
            SnapshotKind.WAL_ARCHIVE,
        ):
            msg = (
                f"{self.kind.value} snapshot {self.snapshot_id} names no wal_sequence; "
                "without a log position there is no point-in-time to restore to"
            )
            raise InvariantViolationError("snapshot.wal_sequence_required", msg)
        if self.kind is SnapshotKind.FULL and self.parent_snapshot_id is not None:
            msg = f"full snapshot {self.snapshot_id} names a parent; a full is its own base"
            raise InvariantViolationError("snapshot.full_with_parent", msg)
        if len(set(self.replica_locators)) != len(self.replica_locators):
            msg = f"snapshot {self.snapshot_id} lists a replica locator twice"
            raise InvariantViolationError("snapshot.duplicate_replica", msg)
        return self

    @property
    def is_replicated(self) -> bool:
        """True when at least one replica of the bytes exists elsewhere.

        This is a statement about *locators recorded in this row*, not about a
        replica having been read back. Reading it back is a
        :class:`RestoreCheckKind` obligation.
        """
        return bool(self.replica_locators)

    @property
    def is_encrypted(self) -> bool:
        return self.encryption is not None

    def data_loss_at(self, incident_at: datetime) -> timedelta:
        """How much data is lost if the incident happened at ``incident_at``.

        Derived from :attr:`covers_through`, which is the honest basis for an RPO
        measurement: zero when the capture covers the incident, growing to the
        full gap when it does not. Negative values mean the capture runs past the
        incident (a capture taken afterwards), which is not a negative loss.
        """
        _require_aware(incident_at, "snapshot.time_aware", "incident")
        gap = incident_at - self.covers_through
        return gap if gap > timedelta(0) else timedelta(0)

    def descriptor_digest(self) -> str:
        """Canonical digest of the descriptor, window and locators included.

        The window is *inside* the digest so a descriptor cannot be re-stamped
        with a later ``covers_through`` while keeping an id an audit trail
        already recorded — the same rule ``Approval.approval_digest`` follows.
        """
        return digest(self.model_dump(mode="json"))

    def describe(self) -> str:
        replicas = f", {len(self.replica_locators)} replica(s)" if self.is_replicated else ""
        return (
            f"{self.snapshot_id} [{self.kind.value}] {self.datastore} through "
            f"{self.covers_through.isoformat()} ({self.byte_size} bytes, "
            f"{self.storage_locator}{replicas})"
        )


# --------------------------------------------------------------------------- #
# Restore plans and checks                                                     #
# --------------------------------------------------------------------------- #


class RestoreCheckKind(StrEnum):
    """What a restore has to *observe* before it counts as a restore.

    These are the plan-19 Phase 2 obligations made explicit as a vocabulary, so
    a plan can name them and a verdict can compare against them. ``ROW_COUNT``
    and ``DIGEST_MATCH`` catch "the bytes came back"; ``WAL_REPLAY`` catches
    "the bytes came back *complete* through the point in time" (this is the one
    an RPO rests on); ``SERVICE_HEALTHY`` catches "the system came back";
    ``EVIDENCE_CHAIN`` catches "the restored evidence still verifies"; and
    ``MTLS_HANDSHAKE`` is where plan 19's mTLS would be proven rather than
    asserted. In Phase 1 the kind is vocabulary only — nothing runs a check.
    """

    ROW_COUNT = "row_count"
    DIGEST_MATCH = "digest_match"
    WAL_REPLAY = "wal_replay"
    SERVICE_HEALTHY = "service_healthy"
    EVIDENCE_CHAIN = "evidence_chain"
    MTLS_HANDSHAKE = "mtls_handshake"


class RestoreCheckSpec(BaseModel):
    """A check a restore plan requires, before the restore is attempted.

    Plans carry no results. A plan says "these must be observed"; a
    :class:`RestoreVerification` says which of them were, and what was seen.
    Keeping them separate types is what stops a plan from being edited to match
    whatever the restore happened to do.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    check_id: str = Field(pattern=_ID)
    kind: RestoreCheckKind
    expectation: str = Field(min_length=1)

    def describe(self) -> str:
        return f"{self.check_id} ({self.kind.value}): {self.expectation}"


class RestorePlan(BaseModel):
    """What a restore is going to do, and what it will have to show to count.

    ``isolated`` is required to be true for a drill: restoring over the live
    cell proves nothing about recovery, it just adds a second way to lose data.
    A plan that is not a drill (``drill=False``) may name a live target, and
    then it says so in the record rather than pretending otherwise.

    Attributes:
        restore_id: Stable id for this restore.
        snapshot_id: The snapshot being restored.
        target_cell: Isolated cell the restore lands in.
        drill: True when this is a drill rather than a live recovery.
        required_checks: Non-empty — a plan that requires nothing verifies
            nothing, so it is unrepresentable.
        max_acceptable_data_loss_seconds: The loss budget the drill is run
            against. Compared against the *measured* loss, not the stated one.
        expected_rto_seconds: Target time to restore, for the drill report.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    restore_id: str = Field(pattern=_ID)
    snapshot_id: str = Field(pattern=_ID)
    target_cell: str = Field(min_length=1)
    drill: bool = True
    isolated: bool = True
    required_checks: tuple[RestoreCheckSpec, ...]
    max_acceptable_data_loss_seconds: Annotated[float, Field(ge=0)]
    expected_rto_seconds: Annotated[float, Field(gt=0)]
    planned_at: datetime = Field(default_factory=utc_now)
    approved_by: str = ""

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(self.planned_at, "restore_plan.time_aware", f"plan {self.restore_id}")
        if not self.required_checks:
            msg = (
                f"restore plan {self.restore_id} requires no checks; a restore that "
                "verifies nothing is not a verified restore"
            )
            raise InvariantViolationError("restore_plan.no_required_checks", msg)
        ids = [check.check_id for check in self.required_checks]
        if len(set(ids)) != len(ids):
            msg = f"restore plan {self.restore_id} names a required check twice: {ids}"
            raise InvariantViolationError("restore_plan.duplicate_check_id", msg)
        if self.drill and not self.isolated:
            msg = (
                f"restore plan {self.restore_id} is a drill but targets a non-isolated "
                f"cell ({self.target_cell!r}); a drill must restore into an isolated cell"
            )
            raise InvariantViolationError("restore_plan.drill_requires_isolation", msg)
        return self

    @property
    def required_check_ids(self) -> tuple[str, ...]:
        return tuple(check.check_id for check in self.required_checks)

    @property
    def required_kinds(self) -> frozenset[RestoreCheckKind]:
        return frozenset(check.kind for check in self.required_checks)

    def requires_kind(self, kind: RestoreCheckKind) -> bool:
        return kind in self.required_kinds

    def describe(self) -> str:
        shape = "drill" if self.drill else "live recovery"
        return (
            f"{self.restore_id} ({shape}) of {self.snapshot_id} into {self.target_cell}: "
            f"{len(self.required_checks)} required check(s), loss budget "
            f"{self.max_acceptable_data_loss_seconds:g}s"
        )


class RestoreCheckResult(BaseModel):
    """One observation a restore actually made.

    ``passed`` alone is not accepted: :attr:`detail` must say *what was observed*.
    A check with ``passed=True`` and an empty detail is a claim, not an
    observation, and it is refused here rather than being allowed to prop up a
    :class:`RestoreVerification`. This is the row-level version of "prove it
    rather than assert it".
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    check_id: str = Field(pattern=_ID)
    kind: RestoreCheckKind
    passed: bool
    detail: str = ""
    observed_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(
            self.observed_at, "restore_check.time_aware", f"check {self.check_id}"
        )
        if self.passed and not self.detail.strip():
            msg = (
                f"restore check {self.check_id} claims it passed but records no "
                "observation; 'the row count matched' and 'I clicked the button' are "
                "the same boolean and only one of them is evidence"
            )
            raise InvariantViolationError("restore_check.pass_without_detail", msg)
        return self

    def describe(self) -> str:
        mark = "pass" if self.passed else "FAIL"
        return f"{self.check_id} [{self.kind.value}] {mark}: {self.detail or 'no detail'}"


class RestoreOutcome(StrEnum):
    """The three verdicts a restore record can carry.

    There is deliberately no ``SUCCESS``/``OK`` member. :data:`VERIFIED` is
    reachable only through the derivation in :attr:`RestoreVerification.status`,
    which requires every required check to have run and passed and the data loss
    to have been measured. Everything else is :data:`FAILED` or
    :data:`INCOMPLETE` — the distinction an operator needs, because "the drill was
    never finished" and "the drill finished and the data was wrong" lead to
    completely different next steps.
    """

    VERIFIED = "verified"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


# --------------------------------------------------------------------------- #
# Restore verification — the only source of an achieved number                 #
# --------------------------------------------------------------------------- #


class RestoreVerification(BaseModel):
    """What a restore drill actually **proved**. Not what was hoped for.

    The load-bearing member is :attr:`status`, which is *derived* and cannot be
    set:

    * every required check of the plan must appear in :attr:`results`
      (:attr:`missing_required`);
    * every check that appears must have passed (:attr:`failed`);
    * data loss must have been **measured**, not estimated — an unmeasured
      restore is :data:`RestoreOutcome.INCOMPLETE` even if all its checks passed,
      because an RPO cannot be quoted from a restore that never measured one.

    There is no way to construct a "successful" restore: :meth:`claim_success`
    raises :class:`UnverifiedRestoreError` unless :attr:`status` is
    :data:`RestoreOutcome.VERIFIED`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    restore_id: str = Field(pattern=_ID)
    plan: RestorePlan
    snapshot_id: str = Field(pattern=_ID)
    started_at: datetime
    completed_at: datetime
    results: tuple[RestoreCheckResult, ...] = ()
    data_loss_seconds: Annotated[float, Field(ge=0)] | None = None
    operator: str = ""

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(
            self.started_at, "restore.time_aware", f"restore {self.restore_id}"
        )
        _require_aware(
            self.completed_at, "restore.time_aware", f"restore {self.restore_id}"
        )
        if self.completed_at < self.started_at:
            msg = (
                f"restore {self.restore_id} completed ({self.completed_at.isoformat()}) "
                f"before it started ({self.started_at.isoformat()})"
            )
            raise InvariantViolationError("restore.time_order", msg)
        if self.plan.restore_id != self.restore_id:
            msg = (
                f"restore {self.restore_id} was executed against plan "
                f"{self.plan.restore_id}; the record must name the plan it ran"
            )
            raise InvariantViolationError("restore.plan_mismatch", msg)
        if self.plan.snapshot_id != self.snapshot_id:
            msg = (
                f"restore {self.restore_id} claims snapshot {self.snapshot_id} but its "
                f"plan restores {self.plan.snapshot_id}"
            )
            raise InvariantViolationError("restore.snapshot_mismatch", msg)
        if self.plan.planned_at > self.started_at:
            msg = (
                f"restore {self.restore_id} started ({self.started_at.isoformat()}) "
                f"before it was planned ({self.plan.planned_at.isoformat()})"
            )
            raise InvariantViolationError("restore.planned_after_start", msg)
        seen = [result.check_id for result in self.results]
        if len(set(seen)) != len(seen):
            msg = f"restore {self.restore_id} records a check twice: {seen}"
            raise InvariantViolationError("restore.duplicate_check", msg)
        for result in self.results:
            if not self.plan.requires_kind(result.kind):
                msg = (
                    f"restore {self.restore_id} recorded check {result.check_id} of kind "
                    f"{result.kind.value}, which plan {self.plan.restore_id} does not "
                    "require; a plan is the contract, not a suggestion"
                )
                raise InvariantViolationError("restore.unplanned_check", msg)
        return self

    # -- derivation ------------------------------------------------------------
    @property
    def duration_seconds(self) -> float:
        """Wall time the restore took — the raw material for an RTO measurement."""
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def missing_required(self) -> tuple[str, ...]:
        """Required check ids that were never observed."""
        observed = {result.check_id for result in self.results}
        return tuple(
            check_id for check_id in self.plan.required_check_ids if check_id not in observed
        )

    @property
    def failed(self) -> tuple[str, ...]:
        """Ids of checks that ran and did not pass."""
        return tuple(result.check_id for result in self.results if not result.passed)

    @property
    def has_measured_data_loss(self) -> bool:
        """True when data loss was measured rather than left unstated."""
        return self.data_loss_seconds is not None

    @property
    def within_loss_budget(self) -> bool:
        """True when the *measured* loss is inside the plan's budget.

        False for an unmeasured restore: an absent measurement does not pass a
        budget, it fails one.
        """
        if self.data_loss_seconds is None:
            return False
        return self.data_loss_seconds <= self.plan.max_acceptable_data_loss_seconds

    @property
    def status(self) -> RestoreOutcome:
        """The verdict, derived. There is no setter and no stored flag."""
        if self.missing_required or self.failed:
            return RestoreOutcome.FAILED
        if not self.has_measured_data_loss:
            return RestoreOutcome.INCOMPLETE
        if not self.within_loss_budget:
            return RestoreOutcome.FAILED
        return RestoreOutcome.VERIFIED

    @property
    def verified(self) -> bool:
        return self.status is RestoreOutcome.VERIFIED

    @property
    def incomplete(self) -> bool:
        return self.status is RestoreOutcome.INCOMPLETE

    def claim_success(self) -> RestoreOutcome:
        """Return :data:`RestoreOutcome.VERIFIED`, or refuse.

        This is the method a report writer calls, so that "the restore drill
        passed" is a *derived* statement at every call site rather than a flag
        somebody remembered to set.

        Raises:
            UnverifiedRestoreError: If the restore is not :data:`RestoreOutcome.VERIFIED`.
        """
        status = self.status
        if status is not RestoreOutcome.VERIFIED:
            raise UnverifiedRestoreError(
                self.restore_id,
                status.value,
                missing_checks=self.missing_required,
                failed_checks=self.failed,
            )
        return status

    def describe(self) -> str:
        loss = (
            "unmeasured"
            if self.data_loss_seconds is None
            else f"{self.data_loss_seconds:g}s"
        )
        return (
            f"{self.restore_id} of {self.snapshot_id}: {self.status.value} "
            f"({len(self.results)}/{len(self.plan.required_checks)} required checks, "
            f"data loss {loss}, {self.duration_seconds:g}s elapsed)"
        )


# --------------------------------------------------------------------------- #
# Objectives (targets) and measurements (evidence)                             #
# --------------------------------------------------------------------------- #


class MetricKind(StrEnum):
    """Which objective a measurement speaks to."""

    RPO = "rpo"
    RTO = "rto"


class RecoveryObjective(BaseModel):
    """The **target**, stated. Never an achieved value.

    Every field here is a commitment somebody made: what was targeted, for which
    datastore, by whom, and when. There is deliberately no ``achieved_*`` field
    and no ``met`` boolean, because those are not facts about an objective —
    they are facts about restore evidence, and the only way to reach them is
    :meth:`achieved_rpo` / :meth:`achieved_rto`, which return ``None`` unless
    :class:`RestoreVerification` records exist.

    Read this class as the sentence: *"we committed to losing at most N seconds
    and to recovering within M seconds."* Whether we did is
    :func:`compare_against_objective` over real evidence.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    datastore: str = Field(min_length=1)
    rpo_seconds: Annotated[float, Field(ge=0)]
    rto_seconds: Annotated[float, Field(gt=0)]
    stated_at: datetime = Field(default_factory=utc_now)
    stated_by: str = Field(min_length=1)
    note: str = ""

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(self.stated_at, "recovery_objective.time_aware", "objective")
        if not self.stated_by.strip():
            msg = "a recovery objective must name who stated it"
            raise InvariantViolationError("recovery_objective.unattributed", msg)
        return self

    @property
    def is_measured(self) -> bool:
        """Always ``False``.

        Present so that a caller asking "is this a measurement?" gets told no
        rather than having to know which half of the module it is holding. A
        :class:`Measurement` is the type that can say yes.
        """
        return False

    # -- the only honest path to an achieved number ---------------------------
    def achieved_rpo(self, verifications: Iterable[RestoreVerification]) -> Measurement | None:
        """The worst *measured* RPO over verified restores, or ``None``.

        ``None`` — not zero, not the stated target — when there is no verified
        restore evidence. **This is the rule the plan's Phase 2 acceptance turns
        on**: a stated RPO with no restore evidence is never an achieved RPO, and
        the type makes the conflation impossible rather than merely discouraged.

        The value is the loss the restore *measured*, which is the only figure
        that was observed rather than asserted. A point-in-time question ("how
        much would we lose if the incident were at T?") is a different one and
        belongs to :meth:`SnapshotDescriptor.data_loss_at`, which is derived from
        the capture's own ``covers_through`` rather than from a drill.
        """
        return _worst(self, verifications, kind=MetricKind.RPO, value_of=_rpo_of)

    def achieved_rto(self, verifications: Iterable[RestoreVerification]) -> Measurement | None:
        """The worst *measured* RTO over verified restores, or ``None``.

        Same rule as :meth:`achieved_rpo`: no verified restore evidence means no
        achieved RTO.
        """
        return _worst(self, verifications, kind=MetricKind.RTO, value_of=_rto_of)

    def describe(self) -> str:
        return (
            f"TARGET for {self.datastore}: RPO <= {self.rpo_seconds:g}s, "
            f"RTO <= {self.rto_seconds:g}s (stated by {self.stated_by} at "
            f"{self.stated_at.isoformat()})"
        )


class Measurement(BaseModel):
    """An achieved number, with the restore that proves it attached.

    The evidence is a **required** field, not an optional annotation. That single
    requirement is the type-level form of "no doc may claim an HA or security
    property without naming the test that proves it" (plan 19 Phase 6): there is
    no constructor path for a number that cannot name its drill.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: MetricKind
    value_seconds: Annotated[float, Field(ge=0)]
    datastore: str = Field(min_length=1)
    evidence: RestoreVerification
    measured_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(self.measured_at, "measurement.time_aware", "measurement")
        if not self.evidence.verified:
            msg = (
                f"a {self.metric.value} measurement of {self.value_seconds:g}s cites restore "
                f"{self.evidence.restore_id}, whose outcome is "
                f"{self.evidence.status.value}; only a verified restore can evidence a "
                "measurement"
            )
            raise InvariantViolationError("measurement.unverified_evidence", msg)
        if self.evidence.plan.snapshot_id != self.evidence.snapshot_id:
            msg = f"measurement evidence {self.evidence.restore_id} is internally inconsistent"
            raise InvariantViolationError("measurement.inconsistent_evidence", msg)
        return self

    @property
    def restore_id(self) -> str:
        """The restore that proves this number — quoted by every doc that does."""
        return self.evidence.restore_id

    def is_within(self, target_seconds: float) -> bool:
        """True when this measured value meets ``target_seconds``."""
        return self.value_seconds <= target_seconds

    def describe(self) -> str:
        return (
            f"MEASURED {self.metric.value.upper()} for {self.datastore}: "
            f"{self.value_seconds:g}s (proven by restore {self.restore_id})"
        )


class ObjectiveComparison(BaseModel):
    """A target and the measured value against it — or the absence of one.

    ``met`` is ``measured is not None and measured.is_within(target)``: with no
    evidence the answer is ``False``, never ``True`` and never ``None``. A missing
    measurement is a failure to demonstrate, and this type refuses to let that be
    read as success.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: MetricKind
    target_seconds: float
    measured: Measurement | None = None
    evidence_restore_ids: tuple[str, ...] = ()
    considered_restore_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        if self.measured is not None and self.measured.metric is not self.metric:
            msg = (
                f"comparison for {self.metric.value} carries a "
                f"{self.measured.metric.value} measurement"
            )
            raise InvariantViolationError("objective_comparison.metric_mismatch", msg)
        if self.measured is not None and self.measured.restore_id not in self.evidence_restore_ids:
            msg = (
                f"comparison for {self.metric.value} cites restore "
                f"{self.measured.restore_id} as evidence but does not list it"
            )
            raise InvariantViolationError("objective_comparison.unlisted_evidence", msg)
        if not set(self.evidence_restore_ids) <= set(self.considered_restore_ids):
            msg = (
                f"comparison for {self.metric.value} lists evidence restores that were "
                "never considered"
            )
            raise InvariantViolationError("objective_comparison.unconsidered_evidence", msg)
        return self

    @property
    def has_evidence(self) -> bool:
        return self.measured is not None

    @property
    def met(self) -> bool:
        return self.measured is not None and self.measured.is_within(self.target_seconds)

    @property
    def verdict(self) -> str:
        if self.measured is None:
            considered = len(self.considered_restore_ids)
            if considered == 0:
                detail = "no restore was attempted"
            else:
                detail = (
                    f"no verified restore evidence ({considered} restore(s) ran, none verified)"
                )
            return (
                f"{self.metric.value} not demonstrated: target {self.target_seconds:g}s, "
                f"{detail}"
            )
        mark = "within" if self.met else "OVER"
        return (
            f"{self.metric.value} {mark} target {self.target_seconds:g}s: measured "
            f"{self.measured.value_seconds:g}s (restore {self.measured.restore_id})"
        )

    def describe(self) -> str:
        return self.verdict


# --------------------------------------------------------------------------- #
# Derivation helpers                                                           #
# --------------------------------------------------------------------------- #


def verified_restores(
    verifications: Iterable[RestoreVerification],
) -> tuple[RestoreVerification, ...]:
    """Only the restores that actually proved something.

    The filter every caller wants and none should re-implement: a drill that was
    never finished is not evidence, and mixing it into an RPO roll-up is how an
    unmeasured restore ends up quoted as a measured one.
    """
    return tuple(verification for verification in verifications if verification.verified)


def _worst(
    objective: RecoveryObjective,
    verifications: Iterable[RestoreVerification],
    *,
    kind: MetricKind,
    value_of: Callable[[RestoreVerification], float | None],
) -> Measurement | None:
    """The worst verified value for ``objective``, or ``None`` when there is none.

    "Worst" is deliberate and is the honest choice for both metrics: an RPO/RTO
    record that quotes the *best* drill ever run is a marketing number, and the
    operational question is how bad it got. Unverified restores are skipped here
    rather than filtered by the caller, so the "only verified evidence counts"
    rule lives in exactly one place.
    """
    considered: list[tuple[float, RestoreVerification]] = []
    for verification in verifications:
        if not verification.verified:
            continue
        value = value_of(verification)
        if value is None:
            continue
        considered.append((float(value), verification))
    if not considered:
        return None
    value, evidence = max(considered, key=lambda pair: pair[0])
    return Measurement(
        metric=kind,
        value_seconds=value,
        datastore=objective.datastore,
        evidence=evidence,
        measured_at=evidence.completed_at,
    )


def _rpo_of(verification: RestoreVerification) -> float | None:
    """The measured data loss a verified restore contributes, in seconds."""
    return verification.data_loss_seconds


def _rto_of(verification: RestoreVerification) -> float | None:
    """The measured restore duration a verified restore contributes, in seconds."""
    return verification.duration_seconds


class ObjectiveReport(BaseModel):
    """Both halves of one objective's story: the target and the evidence.

    Returned as one value rather than a tuple so a caller cannot quote the RPO
    and drop the RTO on the floor — reporting the half that flatters is the
    failure mode this type exists to make awkward.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    objective: RecoveryObjective
    rpo: ObjectiveComparison
    rto: ObjectiveComparison
    verified_restore_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        if self.objective.is_measured:
            msg = "an objective can never be a measurement; check the comparison inputs"
            raise InvariantViolationError("objective_report.objective_is_measurement", msg)
        return self

    @property
    def demonstrated(self) -> bool:
        """True only when *both* metrics have verified evidence behind them.

        Neither half alone is enough: a programme that can restore fast but loses
        an hour of data has demonstrated nothing about its RPO, and vice versa.
        """
        return self.rpo.has_evidence and self.rto.has_evidence

    @property
    def met(self) -> bool:
        """True when both metrics are evidenced *and* inside target."""
        return self.rpo.met and self.rto.met

    def describe(self) -> str:
        state = "met" if self.met else ("demonstrated" if self.demonstrated else "undemonstrated")
        return f"{self.objective.datastore}: {state} — {self.rpo.verdict}; {self.rto.verdict}"


def compare_against_objective(
    objective: RecoveryObjective,
    verifications: Iterable[RestoreVerification],
) -> ObjectiveReport:
    """Compare a stated target against the restore evidence that actually exists.

    The only supported way to produce a report about performance. Both halves are
    computed from :meth:`RecoveryObjective.achieved_rpo` /
    :meth:`RecoveryObjective.achieved_rto`, so a caller cannot accidentally mix a
    stated target in as a measured value — and with no verified evidence both
    comparisons come back with ``measured is None``, which reads as
    "not demonstrated" rather than as a pass.

    Args:
        objective: The stated target.
        verifications: Restore evidence. Unverified records are ignored, so an
            all-failed drill set yields a report with nothing demonstrated rather
            than a number derived from failures.

    Returns:
        An :class:`ObjectiveReport`.
    """
    records = tuple(verifications)
    proven = verified_restores(records)
    considered = tuple(record.restore_id for record in records)
    proven_ids = tuple(record.restore_id for record in proven)
    return ObjectiveReport(
        objective=objective,
        rpo=ObjectiveComparison(
            metric=MetricKind.RPO,
            target_seconds=objective.rpo_seconds,
            measured=_worst(objective, proven, kind=MetricKind.RPO, value_of=_rpo_of),
            evidence_restore_ids=proven_ids,
            considered_restore_ids=considered,
        ),
        rto=ObjectiveComparison(
            metric=MetricKind.RTO,
            target_seconds=objective.rto_seconds,
            measured=_worst(objective, proven, kind=MetricKind.RTO, value_of=_rto_of),
            evidence_restore_ids=proven_ids,
            considered_restore_ids=considered,
        ),
        verified_restore_ids=proven_ids,
    )
