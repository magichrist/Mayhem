"""Certification records: one honest live claim per runtime cell (plan 01).

A ``LiveRunRecord`` in :mod:`mayhem.infra.promotion` is the evidence *of a
run*. This module is the layer above it. It answers the questions a bare run
record cannot:

* **where** the run happened — the :class:`MatrixCell`: engine and engine
  version, OS distribution, kernel version, architecture, privilege mode, and
  the capabilities the cell had to offer;
* **until when** the claim holds — ``expires_at`` plus a warning window, so a
  claim about to lapse is visibly distinct from one that already has; and
* **what happens when the world moves** — a kernel bump or a provider upgrade
  does not make the old evidence wrong, it makes it *about a different cell*,
  which is :data:`CertificationState.INCOMPATIBLE`.

The state machine is small and closed::

    pending ──certify──▶ certified ──expiring window──▶ expiring
       │                    │                             │
       │                    └──────────┬──────────────────┘
       │                               ▼
       │                             stale
       ▼
    failed / incompatible            (expired: the claim is time-decayed)

``incompatible`` is terminal, and so is every transition *out* of a stale or
expired record: a lapsed claim cannot be revived by editing the record. It has
to be earned again, on the cell that exists now, which is a new record.

Every transition here is a **pure function** returning a new frozen record.
Nothing reads a clock, a registry, or a filesystem: the caller supplies ``now``
and the cell that is current. That is what makes a record falsifiable — a
certification story can be replayed, and the same inputs always produce the
same state.

Fabricated evidence is unrepresentable rather than merely discouraged. A
:class:`CertificationRecord` may only be *constructed* in a certified state if
it carries at least one :class:`EvidenceBundleRef` whose digest set covers
every claim the promotion criteria make (:data:`REQUIRED_EVIDENCE_DIGESTS`).
A ref whose ``bundle_hash`` is not a sha256 hex digest cannot be written, so
the negative control in the test suite — a record whose evidence would be
rejected downstream — cannot even be built here.

The record store is read by :func:`mayhem.infra.promotion.evaluate_maturity`,
which stays the only function that decides a reported maturity level. This
module decides nothing about rungs; it only says whether a live claim exists
for a fault on a cell.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.capabilities import Capability
from mayhem.domain.faults import EngineLane, FaultCategory

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "BUNDLE_DIGEST_RE",
    "DEFAULT_CERTIFICATION_TTL",
    "DEFAULT_EXPIRY_WARNING",
    "LEGAL_TRANSITIONS",
    "REQUIRED_EVIDENCE_DIGESTS",
    "Arch",
    "CellPrivilege",
    "CertificationRecord",
    "CertificationState",
    "CertificationTransitionError",
    "EvidenceBundleRef",
    "MatrixCell",
    "certified_engines",
    "certify",
    "expire_by_time",
    "invalidate_on_change",
    "mark_failed",
    "mark_incompatible",
]

#: SHA-256 hex of an evidence bundle, or of one artifact inside it. Anything
#: else is not a reference to a bundle.
BUNDLE_DIGEST_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

#: Content digests a certification's bundle must carry. Each maps onto a claim
#: the promotion criteria make, so a bundle that omits one cannot support the
#: claim it is being cited for.
REQUIRED_EVIDENCE_DIGESTS: Final[tuple[str, ...]] = (
    "params",
    "target",
    "observed_effect",
    "undo",
    "residue",
)

#: How long a fresh certification holds before it needs re-running. A policy
#: default, not a fact: callers may certify with their own expiry.
DEFAULT_CERTIFICATION_TTL: Final[timedelta] = timedelta(days=30)

#: How close to expiry a record starts reporting :data:`CertificationState.EXPIRING`.
#: A claim that lapses without warning is the same thing as one that was never
#: made, so the warning window is part of the contract rather than cosmetics.
DEFAULT_EXPIRY_WARNING: Final[timedelta] = timedelta(days=7)


class CertificationState(StrEnum):
    """Where one fault-on-one-cell claim currently stands.

    Attributes:
        PENDING: Recorded, not yet certified. Carries no live claim.
        CERTIFIED: Passed on the cell, with evidence, inside its validity
            window. This is the only state that means "run it, it worked".
        EXPIRING: Still certified, but close enough to ``expires_at`` that the
            claim should be re-earned before it lapses. Counts as certified;
            flagged so a report can say "renew me".
        STALE: The claim was certified once and has since expired. Not
            evidence; not restorable by editing the record.
        FAILED: A re-run of the same cell did not reproduce the claim. The
            fault has *lost* a certification rather than never had one.
        INCOMPATIBLE: Terminal. The cell this was certified on no longer
            describes the runtime — the engine, kernel, or injector moved — so
            the evidence is about a machine that is not there any more.
    """

    PENDING = "pending"
    CERTIFIED = "certified"
    EXPIRING = "expiring"
    STALE = "stale"
    FAILED = "failed"
    INCOMPATIBLE = "incompatible"


#: The closed transition table. Every predicate in this module is checked
#: against it, so "which moves are legal" is data rather than folklore, and a
#: state with no outgoing edge is terminal by construction.
LEGAL_TRANSITIONS: Final[dict[CertificationState, frozenset[CertificationState]]] = {
    CertificationState.PENDING: frozenset(
        {
            CertificationState.CERTIFIED,
            CertificationState.STALE,
            CertificationState.FAILED,
            CertificationState.INCOMPATIBLE,
        }
    ),
    CertificationState.CERTIFIED: frozenset(
        {
            CertificationState.EXPIRING,
            CertificationState.STALE,
            CertificationState.FAILED,
            CertificationState.INCOMPATIBLE,
        }
    ),
    CertificationState.EXPIRING: frozenset(
        {
            CertificationState.STALE,
            CertificationState.FAILED,
            CertificationState.INCOMPATIBLE,
        }
    ),
    CertificationState.STALE: frozenset(
        {CertificationState.FAILED, CertificationState.INCOMPATIBLE}
    ),
    CertificationState.FAILED: frozenset({CertificationState.INCOMPATIBLE}),
    CertificationState.INCOMPATIBLE: frozenset(),
}


class CertificationTransitionError(ValueError):
    """A transition was attempted that the state machine does not allow."""


class CellPrivilege(StrEnum):
    """How the injector obtained privilege *on the certification cell*.

    Distinct from :class:`mayhem.domain.capabilities.PrivilegeMode`, which asks
    how a host hands out privilege; this asks whether the cell ran the fault as
    ``root`` or ``rootless``, because a rootless cell is a different claim than
    a rootful one and must not be reported as the same verification.
    """

    ROOT = "root"
    ROOTLESS = "rootless"


class Arch(StrEnum):
    """CPU architecture of a certification cell."""

    AMD64 = "amd64"
    ARM64 = "arm64"


class MatrixCell(BaseModel):
    """One point in the certification matrix: a runtime a claim can be made *about*.

    A record without its cell is a claim about "a machine somewhere", which is
    exactly the claim the existing harness refused to make. Freezing the cell
    into the record's identity is what makes drift detectable later: compare
    the recorded cell against the cell that exists now and the difference is
    named, not averaged away.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    engine: EngineLane
    engine_version: str = Field(min_length=1, max_length=64)
    os_distro: str = Field(min_length=1, max_length=64)
    kernel_version: str = Field(min_length=1, max_length=64)
    arch: Arch
    privilege: CellPrivilege = CellPrivilege.ROOTLESS
    capabilities: frozenset[Capability] = Field(default_factory=frozenset)

    @property
    def label(self) -> str:
        """Single-line cell identity, for reports and refusal messages."""
        return (
            f"{self.engine.value}@{self.engine_version}/{self.os_distro}"
            f"/kernel-{self.kernel_version}/{self.arch.value}/{self.privilege.value}"
        )

    @property
    def fingerprint(self) -> str:
        """Every dimension that a later invalidation could notice."""
        return "|".join(
            (
                self.engine.value,
                self.engine_version,
                self.os_distro,
                self.kernel_version,
                self.arch.value,
                self.privilege.value,
                ",".join(sorted(capability.value for capability in self.capabilities)),
            )
        )


class EvidenceBundleRef(BaseModel):
    """A reference — never an embedding — to a sealed certification bundle.

    A bundle hash on its own proves nothing: anyone can write 64 hex characters
    into a file. The ref therefore also carries digests of the *contents* the
    certification rests on, and the record below refuses to be certified unless
    every one of :data:`REQUIRED_EVIDENCE_DIGESTS` is present.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    bundle_hash: str = Field(min_length=64, max_length=64)
    mayhem_version: str = Field(min_length=1, max_length=64)
    digests: dict[str, str] = Field(default_factory=dict)
    bundle_path: str | None = None

    @field_validator("bundle_hash")
    @classmethod
    def _is_sha256(cls, value: str) -> str:
        if BUNDLE_DIGEST_RE.match(value) is None:
            raise ValueError("bundle_hash must be 64 lowercase hex characters (sha256)")
        return value

    @model_validator(mode="after")
    def _digests_are_digests(self) -> EvidenceBundleRef:
        for name, digest in self.digests.items():
            if BUNDLE_DIGEST_RE.match(digest) is None:
                raise ValueError(f"digest for {name!r} must be 64 lowercase hex characters")
        return self

    def missing_digests(self) -> tuple[str, ...]:
        """Required content digests this bundle does not carry."""
        return tuple(name for name in REQUIRED_EVIDENCE_DIGESTS if name not in self.digests)


class CertificationRecord(BaseModel):
    """What one fault did on one cell, and for how long that counts.

    The record is frozen and every field is either observed or supplied: there
    is no ``verified: bool`` a caller can set to skip the checks. The
    state/certified invariants below are model validators, so a ``certified``
    record with no evidence cannot be constructed at all — the negative control
    the plan asks for is a construction-time refusal, not a runtime check.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fault_id: str
    cell: MatrixCell
    injector_version: str = Field(min_length=1, max_length=64)
    expires_at: datetime
    evidence: tuple[EvidenceBundleRef, ...] = ()
    state: CertificationState = CertificationState.PENDING
    outcome: str = ""
    certified_at: datetime | None = None
    reason: str = ""

    # -- identity ------------------------------------------------------------

    @field_validator("fault_id")
    @classmethod
    def _plausible_fault_id(cls, value: str) -> str:
        if re.match(r"^[a-z][a-z0-9_]*\.[a-z0-9_.]+$", value) is None:
            raise ValueError("fault_id must look like '<family>.<kind>'")
        FaultCategory.from_fault_id(value)  # raises on an unknown family prefix
        return value

    # -- time discipline -----------------------------------------------------

    @field_validator("expires_at")
    @classmethod
    def _aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        return value

    @field_validator("certified_at")
    @classmethod
    def _aware_certification(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("certified_at must be timezone-aware")
        return value

    # -- the invariant that makes a claim checkable -------------------------

    @model_validator(mode="after")
    def _certified_claims_carry_evidence(self) -> CertificationRecord:
        """A certified claim must say what observed it.

        Without this, ``state=certified`` is a self-asserted badge: the same
        failure mode the promotion harness exists to kill, one layer down. A
        certified record therefore needs a bundle whose digests cover every
        claim the criteria make, a recorded outcome, and a certification time.
        """
        if self.state in (CertificationState.CERTIFIED, CertificationState.EXPIRING):
            if not self.evidence:
                raise ValueError(
                    f"{self.fault_id} claims to be certified on {self.cell.label} with no evidence "
                    "bundle: an unreferenced certification is not a certification"
                )
            gaps = tuple(sorted({name for ref in self.evidence for name in ref.missing_digests()}))
            if gaps:
                missing = ", ".join(gaps)
                raise ValueError(
                    f"certification of {self.fault_id} on {self.cell.label} has no {missing} "
                    f"digest in its evidence bundle; a bundle missing {missing} does not support "
                    "the claim it is cited for"
                )
            if not self.outcome.strip():
                raise ValueError(
                    f"{self.fault_id} is certified on {self.cell.label} without a recorded outcome"
                )
            if self.certified_at is None:
                raise ValueError(
                    f"{self.fault_id} is certified on {self.cell.label} with no certification time"
                )
        if (
            self.state in (CertificationState.FAILED, CertificationState.INCOMPATIBLE)
            and not self.reason.strip()
        ):
            raise ValueError(
                f"{self.fault_id} on {self.cell.label} is {self.state.value} without saying why"
            )
        return self

    # -- derived facts -------------------------------------------------------

    @property
    def label(self) -> str:
        """``fault@cell`` — the identity a report or refusal should quote."""
        return f"{self.fault_id}@{self.cell.label}"

    @property
    def grants_live_verification(self) -> bool:
        """True when this record is a live claim the promotion engine may count.

        ``expiring`` still counts: it is a warning about the future, not a
        withdrawal of the past. ``pending``, ``stale``, ``failed``, and
        ``incompatible`` do not, which is why deleting a record, or letting it
        go stale, drops the reported level with it.
        """
        return self.state in (CertificationState.CERTIFIED, CertificationState.EXPIRING)

    @property
    def warning_window_entered(self) -> bool:
        """True when the record sits inside its expiry warning window."""
        return self.state is CertificationState.EXPIRING


def certified_engines(records: Iterable[CertificationRecord]) -> frozenset[EngineLane]:
    """Engine lanes on which at least one of ``records`` is a live claim.

    Pure: it reads only what the caller hands it. Stale, failed, pending, and
    incompatible records contribute nothing, so the set shrinks the moment a
    record lapses or the runtime moves on.
    """
    return frozenset(record.cell.engine for record in records if record.grants_live_verification)


# ── transitions ─────────────────────────────────────────────────────────────


def _aware(moment: datetime, label: str) -> datetime:
    if moment.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return moment


def _replace(record: CertificationRecord, **changes: object) -> CertificationRecord:
    """Rebuild a record through validation, so every transition re-checks it.

    ``model_copy`` would bypass the validators; going through
    ``model_validate`` means a transition can never produce a record that
    construction would have refused.
    """
    return CertificationRecord.model_validate({**record.model_dump(), **changes})


def _require(record: CertificationRecord, target: CertificationState) -> None:
    allowed = LEGAL_TRANSITIONS[record.state]
    if target not in allowed:
        raise CertificationTransitionError(
            f"{record.label} cannot move from {record.state.value} to {target.value}; "
            f"legal from {record.state.value}: "
            f"{', '.join(sorted(state.value for state in allowed)) or 'nothing (terminal)'}"
        )


def certify(
    record: CertificationRecord,
    *,
    at: datetime,
    expires_at: datetime | None = None,
    evidence: tuple[EvidenceBundleRef, ...] = (),
    outcome: str = "",
    injector_version: str | None = None,
) -> CertificationRecord:
    """Turn a pending record into a certified one, on the strength of evidence.

    ``at`` is when the run happened and ``expires_at`` defaults to
    :data:`DEFAULT_CERTIFICATION_TTL` after it. ``evidence`` must be non-empty
    and complete; an empty tuple or a bundle missing a required digest is
    refused here rather than discovered later by a reader.

    Raises:
        CertificationTransitionError: If ``record`` is not pending. A lapsed or
            failed record has to be re-earned as a new record, not revived.
        ValueError: If no usable evidence was supplied.
    """
    _require(record, CertificationState.CERTIFIED)
    certified_at = _aware(at, "at")
    if not evidence:
        raise ValueError(
            f"certifying {record.label} requires at least one evidence bundle reference"
        )
    deadline = (
        _aware(expires_at, "expires_at")
        if expires_at is not None
        else certified_at + DEFAULT_CERTIFICATION_TTL
    )
    return _replace(
        record,
        injector_version=injector_version or record.injector_version,
        expires_at=deadline,
        evidence=evidence,
        state=CertificationState.CERTIFIED,
        outcome=outcome,
        certified_at=certified_at,
        reason="",
    )


def expire_by_time(
    record: CertificationRecord,
    *,
    now: datetime,
    warning_window: timedelta = DEFAULT_EXPIRY_WARNING,
) -> CertificationRecord:
    """Age a record against the wall clock the caller supplies.

    Pure: ``now`` is an argument, so an expiry policy can be replayed and a
    test can prove the demotion without waiting. Three outcomes, in order of
    precedence: past ``expires_at`` the claim is :data:`CertificationState.STALE`;
    inside the warning window a certified claim becomes
    :data:`CertificationState.EXPIRING`; otherwise the record is returned
    unchanged. Terminal and lapsed states never move.
    """
    moment = _aware(now, "now")
    if not LEGAL_TRANSITIONS[record.state]:
        return record  # terminal: the clock observes, it does not transition
    target = record.state
    if moment >= record.expires_at:
        target = CertificationState.STALE
    elif (
        record.state is CertificationState.CERTIFIED
        and record.expires_at - moment <= warning_window
    ):
        target = CertificationState.EXPIRING
    if target is record.state:
        return record
    _require(record, target)
    reason = {
        CertificationState.EXPIRING: (
            f"certification of {record.label} expires at "
            f"{record.expires_at.isoformat()}, inside the "
            f"{warning_window.days}-day warning window"
        ),
        CertificationState.STALE: (
            f"certification of {record.label} lapsed at "
            f"{record.expires_at.isoformat()}: a time-expired claim is not evidence"
        ),
    }[target]
    return _replace(record, state=target, reason=reason)


def invalidate_on_change(
    record: CertificationRecord,
    *,
    cell: MatrixCell | None = None,
    injector_version: str | None = None,
) -> CertificationRecord:
    """Invalidate a record when the cell or the injector no longer matches.

    Gap item 107 (drift detection). Engine, kernel, OS, architecture, privilege,
    and capabilities all live in :class:`MatrixCell`, so passing the cell that
    exists *now* covers every runtime dimension in one comparison; the injector
    or provider version is checked separately because it can move without the
    cell moving at all. When nothing differs the record is returned untouched —
    this predicate observes drift, it does not manufacture it.
    """
    drift: list[str] = []
    if cell is not None and cell != record.cell:
        drift.append(f"the runtime cell moved from {record.cell.label} to {cell.label}")
    if injector_version is not None and injector_version != record.injector_version:
        drift.append(
            f"the injector/provider version moved from {record.injector_version!r} "
            f"to {injector_version!r}"
        )
    if not drift or record.state is CertificationState.INCOMPATIBLE:
        return record
    return mark_incompatible(record, reason="; ".join(drift))


def mark_failed(record: CertificationRecord, *, reason: str) -> CertificationRecord:
    """Record that a re-run of the same cell did not reproduce the claim.

    Raises:
        CertificationTransitionError: If ``record`` is already incompatible,
            which is terminal — a failed claim on a cell that no longer exists
            is not a new fact about the current runtime.
        ValueError: If ``reason`` is empty.
    """
    _require(record, CertificationState.FAILED)
    if not reason.strip():
        raise ValueError(f"marking {record.label} failed requires a reason")
    return _replace(record, state=CertificationState.FAILED, reason=reason)


def mark_incompatible(record: CertificationRecord, *, reason: str) -> CertificationRecord:
    """Move a record to its terminal state: the cell it was made on is gone.

    Raises:
        ValueError: If ``reason`` is empty.
    """
    if record.state is CertificationState.INCOMPATIBLE:
        return record
    _require(record, CertificationState.INCOMPATIBLE)
    if not reason.strip():
        raise ValueError(f"marking {record.label} incompatible requires a reason")
    return _replace(record, state=CertificationState.INCOMPATIBLE, reason=reason)
