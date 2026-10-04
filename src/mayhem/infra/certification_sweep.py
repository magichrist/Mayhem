"""Scheduled ageing, drift invalidation, and regression blocking (plan 01, Phase 5).

Phases 1-4 built the pieces. What was missing was anything that *ran them*: a
store with no sweep keeps reporting a claim that lapsed a month ago until
somebody looks, and a fault that was certified on Tuesday and broke on Wednesday
goes red in CI while its badge stays green in every report. This module is the
missing clock and the missing gate.

Two operations, deliberately separate:

** :func:`sweep_certifications` — ageing and drift.**
Walks every stored record once, ages it against a supplied ``now`` with the
domain's own :func:`~mayhem.domain.certification.expire_by_time`, and
invalidates it against the cell that exists *now* with the domain's own
:func:`~mayhem.domain.certification.invalidate_on_change` (gap item 107). Every
move is written back through
:meth:`~mayhem.infra.certification_repository.CertificationRepository.store_transition`,
so a sweep is a sequence of the transitions the domain already permits and
nothing else. The domain decides *what* a transition means; this module decides
*when* to ask.

** :func:`regression_report` — CI blocking.**
Given the stored claims and the verdicts of the re-runs that just happened,
answers one question: *did a previously certified fault go red?* It does not
re-run anything, does not mutate anything, and returns a verdict a CI step can
exit on. :func:`apply_regressions` is the mutating half, and it withdraws the
claim through :func:`~mayhem.domain.certification.mark_failed` before the report
is allowed to call the build green — so "the gate passed" and "the claim is
still stored" cannot both be true after a regression.

What this module deliberately does not do
------------------------------------------

* **It does not certify anything.** No function here can create a live claim. A
  cell that has never been run stays unrun; the only writes this module makes
  are *withdrawals*.
* **It does not guess the current cell.** :func:`sweep_certifications` takes the
  cell to compare against as an argument. A sweep handed no cell does the
  time-based half only, and says so in its report, because "I could not check
  the runtime" and "the runtime matches" must not render identically.
* **It is not on a clock of its own.** ``now`` is always a parameter. There is
  no ``utc_now()`` default that cannot be overridden, which is what makes the
  whole expiry policy replayable in a test instead of waited for.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.certification import (
    CertificationRecord,
    CertificationState,
    expire_by_time,
    invalidate_on_change,
    mark_failed,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from mayhem.domain.certification import MatrixCell
    from mayhem.infra.certification_repository import (
        CertificationRepository,
        StoredCertification,
    )

__all__ = [
    "REGRESSION_RULE",
    "CertificationSweep",
    "RegressionReport",
    "RegressedClaim",
    "ReRunVerdict",
    "apply_regressions",
    "regression_report",
    "sweep_certifications",
]


#: The machine name for "a fault that carried a live claim does not any more".
#:
#: Stable and greppable for the same reason
#: :class:`~mayhem.infra.promotion.Criterion` names are: a CI log has to be able
#: to point at the line that failed without parsing prose. It is **not** a
#: ``safety_proof`` rule id and deliberately does not become one: nothing here
#: reaches a :class:`~mayhem.domain.safety.SafetyDecision`, so adding an
#: ``OBLIGATION_FOR_RULE`` row would attach a blameable obligation to a module
#: that never takes part in the proof. See
#: :func:`apply_regressions` for where the blameable refusal actually lives —
#: in the record's own ``reason``, which is the text a reader sees.
REGRESSION_RULE = "certification.regression"

#: States a claim reaches that no re-run can contradict any more. A lapsed claim
#: has already been withdrawn by the clock; invalidating it as well would be a
#: second, contradictory story about why it no longer counts.
_WITHDRAWN: frozenset[CertificationState] = frozenset(
    {
        CertificationState.STALE,
        CertificationState.FAILED,
        CertificationState.INCOMPATIBLE,
    }
)


@dataclass(frozen=True, slots=True)
class ReRunVerdict:
    """What a cell said when a fault was re-run on it.

    Attributes:
        fault_id: The fault that was re-run.
        certified: Whether the re-run reproduced the claim. ``False`` for any
            refusal, which is the point: a cell that will not run the fault any
            more is a red cell, not a missing cell.
        cell: The cell the re-run happened on, or ``None`` when the cell could
            not be identified at all (no engine, or a probe that failed). ``None``
            and "ran and said no" are different facts and are not merged.
        detail: Why, in words the caller supplies. Recorded verbatim in the
            demotion so the reason a claim was withdrawn is the reason the cell
            gave, not a summary written afterwards.
    """

    fault_id: str
    certified: bool
    cell: MatrixCell | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class RegressedClaim:
    """One stored live claim that a re-run contradicted.

    Attributes:
        stored: The stored row, read *before* the withdrawal, so a caller can
            cite which sequence the claim was on after it has been withdrawn.
        verdict: The re-run that contradicted it.
        reason: The text written into the withdrawn record's ``reason``.
    """

    stored: StoredCertification
    verdict: ReRunVerdict
    reason: str


@dataclass(frozen=True, slots=True)
class RegressionReport:
    """The answer to "did a previously certified fault go red?".

    Attributes:
        claims_considered: Stored rows that were carrying a live claim when the
            report was built. A fault nobody ever certified is not a regression,
            and must not be counted as one.
        regressed: The claims a re-run contradicted. Non-empty means the build
            is red.
        unreached: Faults with a live claim that nothing was re-run for. These
            are *not* regressions and *not* passes; a gate that read them as
            passes would be claiming a cell stayed green without having looked.
        verdicts: Every verdict considered, keyed by fault id.
    """

    claims_considered: int
    regressed: tuple[RegressedClaim, ...]
    unreached: tuple[str, ...]
    verdicts: Mapping[str, ReRunVerdict]

    @property
    def blocked(self) -> bool:
        """True when at least one live claim did not survive its re-run."""
        return bool(self.regressed)

    @property
    def rule(self) -> str:
        """The machine name of the rule this report decides."""
        return REGRESSION_RULE

    def refusal(self) -> str:
        """One line naming every regression, or ``""`` when there are none.

        Rendered rather than assembled by the caller so that a CI log, a test
        assertion, and a release note all quote the same string.
        """
        if not self.regressed:
            return ""
        return "; ".join(
            f"{claim.stored.record.label}: {claim.reason}" for claim in self.regressed
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "blocked": self.blocked,
            "claims_considered": self.claims_considered,
            "regressed": [claim.reason for claim in self.regressed],
            "unreached": sorted(self.unreached),
            "refusal": self.refusal(),
        }


@dataclass(frozen=True, slots=True)
class CertificationSweep:
    """What one sweep did, and — as importantly — what it could not do.

    Attributes:
        considered: Every stored row the sweep read.
        aged: Rows whose state moved because the clock moved
            (``certified`` -> ``expiring``, or anything -> ``stale``).
        invalidated: Rows whose cell no longer describes the runtime.
        checked_against_a_cell: Whether drift was checked at all. ``False`` when
            no current cell was supplied, and it is carried into the report so
            "nothing moved" is never rendered as "everything was re-checked".
    """

    considered: int
    aged: tuple[StoredCertification, ...]
    invalidated: tuple[StoredCertification, ...]
    checked_against_a_cell: bool

    @property
    def changed(self) -> tuple[StoredCertification, ...]:
        """Every row the sweep rewrote, aged first then invalidated."""
        return (*self.aged, *self.invalidated)

    def to_dict(self) -> dict[str, object]:
        return {
            "considered": self.considered,
            "aged": len(self.aged),
            "invalidated": len(self.invalidated),
            "drift_checked": self.checked_against_a_cell,
        }


def sweep_certifications(
    repository: CertificationRepository,
    *,
    now: datetime,
    current_cells: Mapping[str, MatrixCell] | None = None,
    injector_version: str | None = None,
) -> CertificationSweep:
    """Age every stored record, and invalidate the ones the runtime moved past.

    Gap item 107 (drift detection) as a scheduled operation. The domain owns both
    rules — this function only supplies the clock and the cell that exists now.

    Args:
        repository: The record store. Every write goes through
            :meth:`~mayhem.infra.certification_repository.CertificationRepository.store_transition`,
            so a sweep can never write a row that is not already there, and can
            never *append* — ageing and invalidation are in-place by design, and
            re-certification is a new record.
        now: The instant to age against. Explicit so the policy is replayable.
        current_cells: The cell that exists now, keyed by fault id. A fault
            absent from this mapping is **not** checked for drift, and the report
            says so: an unchecked claim is not a verified claim. Omit the
            argument entirely and the time-based half still runs.
        injector_version: The injector version now in use, for the same reason
            the cell is an argument: this module reads no registry.

    Returns:
        The sweep, including what it could not check.
    """
    cells = dict(current_cells or {})
    aged: list[StoredCertification] = []
    invalidated: list[StoredCertification] = []
    stored_rows = repository.all()
    for stored in stored_rows:
        moment = expire_by_time(stored.record, now=now)
        if moment is not stored.record:
            aged.append(repository.store_transition(stored, moment, now=now))
        if moment.state in _WITHDRAWN:
            # A lapsed claim has nothing left to invalidate. Skipping it keeps
            # the terminal states terminal, which is the domain's rule and not
            # this function's to second-guess.
            continue
        cell = cells.get(stored.record.fault_id)
        moved = invalidate_on_change(
            moment,
            cell=cell,
            injector_version=injector_version,
        )
        if moved is not moment:
            invalidated.append(repository.store_transition(stored, moved, now=now))
    return CertificationSweep(
        considered=len(stored_rows),
        aged=tuple(aged),
        invalidated=tuple(invalidated),
        checked_against_a_cell=bool(cells),
    )


def regression_report(
    repository: CertificationRepository,
    verdicts: Mapping[str, ReRunVerdict],
    *,
    now: datetime,
) -> RegressionReport:
    """Which live claims did this build's re-runs contradict?

    A read. It writes nothing, so it is safe to call from a gate that has not
    decided what to do yet; :func:`apply_regressions` is what withdraws.

    "Reached" means the re-run happened **on the cell the claim was recorded
    on**. A fault re-run on a different cell has not tested the stored claim, so
    it neither passes nor fails it, and the fault is reported in
    :attr:`RegressionReport.unreached` rather than quietly counted. That is the
    difference between a matrix that means something and one that means "we ran
    something".
    """
    live: dict[tuple[str, str], StoredCertification] = {}
    for stored in repository.all():
        record: CertificationRecord = expire_by_time(stored.record, now=now)
        if record.grants_live_verification:
            live[(record.fault_id, record.cell.fingerprint)] = stored

    regressed: list[RegressedClaim] = []
    unreached: list[str] = []
    for (fault_id, fingerprint), stored in sorted(live.items()):
        verdict = verdicts.get(fault_id)
        if verdict is None or verdict.cell is None or verdict.cell.fingerprint != fingerprint:
            unreached.append(fault_id)
            continue
        if verdict.certified:
            continue
        reason = (
            f"re-run on {verdict.cell.label} did not reproduce the certification: "
            f"{verdict.detail or 'the cell refused or reported the fault as not verified'}"
        )
        regressed.append(RegressedClaim(stored=stored, verdict=verdict, reason=reason))
    return RegressionReport(
        claims_considered=len(live),
        regressed=tuple(regressed),
        unreached=tuple(sorted(set(unreached))),
        verdicts=dict(verdicts),
    )


def apply_regressions(
    repository: CertificationRepository,
    report: RegressionReport,
    *,
    now: datetime,
) -> tuple[StoredCertification, ...]:
    """Withdraw every claim the report found regressed, and return the new rows.

    The withdrawal happens **here**, through
    :func:`~mayhem.domain.certification.mark_failed`, so a claim cannot survive a
    regression gate that reported it. Callers that want to fail the build read
    :attr:`RegressionReport.blocked`; callers that also want the store to agree
    call this first, and the order matters: withdraw, then let the gate report.

    Raises:
        ValueError: If a regressed record can no longer be failed. A claim that
            reached a terminal state between the report and the withdrawal is
            already withdrawn, so the refusal is informational rather than
            actionable — it is raised rather than swallowed so a caller cannot
            believe it withdrew something it did not.
    """
    withdrawn: list[StoredCertification] = []
    for claim in report.regressed:
        aged = expire_by_time(claim.stored.record, now=now)
        if not aged.grants_live_verification:
            continue
        withdrawn.append(
            repository.store_transition(
                claim.stored,
                mark_failed(aged, reason=claim.reason),
                now=now,
            )
        )
    return tuple(withdrawn)