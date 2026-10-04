"""Plan 01 Phase 5 — the nightly certification jobs, as executable tests.

**This suite is why the ``nightly`` marker used to be empty.** Plan 01's Phase 5
names three things that belong on a clock rather than in a unit suite: the expiry
and drift sweep, the release-time regression check, and regression blocking in
CI. The marker was registered in ``pyproject.toml`` and the conformance workflow
ran::

    uv run pytest tests/unit -m nightly -q

but **no test carried the marker**, so that job selected nothing and passed
vacuously — a green CI line standing for a certification sweep that had never run.
The marker is attached here, which is the phase's own acceptance criterion ("the
``nightly`` marker gap is closed by attaching real tests to it").

``infra/certification_sweep.py`` had **no tests at all** before this file. The two
properties below are the ones CI depends on, and each is asserted from both sides
so neither can pass vacuously:

* **The sweep needs a clock and a cell, and says when it had neither.** A sweep
  with ``now`` past the expiry ages the claim; with a ``current_cells`` map that
  no longer describes the runtime it invalidates; with neither the cell check did
  not happen, and ``checked_against_a_cell`` is ``False`` — because "nothing moved"
  and "nothing was looked at" are different findings and a sweep that reported
  the first while doing the second would be lying by omission.
* **A previously certified fault going red blocks the build, and a fault re-run
  on a different cell does not count either way.** A verdict on the cell the claim
  was recorded on either reproduces it or regresses it; a verdict from *another*
  cell has not tested the stored claim, so it lands in ``unreached`` rather than
  being counted as a pass. That distinction is the difference between a matrix
  that means something and one that means "we ran something".

These run on a real migrated SQLite store rather than a fake, because the sweep's
value is that every write goes through ``store_transition`` and a fake would not
notice if it stopped doing so.
"""

from __future__ import annotations

import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from mayhem.domain.certification import (
    REQUIRED_EVIDENCE_DIGESTS,
    CertificationRecord,
    CertificationState,
    EvidenceBundleRef,
    MatrixCell,
)
from mayhem.infra.certification_repository import CertificationRepository, StoredCertification
from mayhem.infra.certification_sweep import (
    ReRunVerdict,
    apply_regressions,
    regression_report,
    sweep_certifications,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]

NOW = datetime(2026, 3, 4, 12, 0, tzinfo=UTC)
HASH = "a" * 64
FAULT = "net.latency"


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    opened = Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)
    yield opened
    opened.close()


@pytest.fixture
def repository(store: Store) -> CertificationRepository:
    return CertificationRepository(store)


def _cell(**overrides: object) -> MatrixCell:
    payload: dict[str, object] = {
        "engine": "podman",
        "engine_version": "5.1.0",
        "os_distro": "debian12",
        "kernel_version": "6.1.0",
        "arch": "amd64",
    }
    payload.update(overrides)
    return MatrixCell.model_validate(payload)


def _bundle() -> EvidenceBundleRef:
    return EvidenceBundleRef(
        bundle_hash=HASH,
        mayhem_version="1.1.0.test",
        digests=dict.fromkeys(REQUIRED_EVIDENCE_DIGESTS, HASH),
        bundle_path="/tmp/certification/bundle.json",
    )


def _certified(cell: MatrixCell, *, ttl_days: int = 30) -> CertificationRecord:
    return CertificationRecord(
        fault_id=FAULT,
        cell=cell,
        injector_version="1.2.3",
        expires_at=NOW + timedelta(days=ttl_days),
        evidence=(_bundle(),),
        state=CertificationState.CERTIFIED,
        outcome="pass",
        certified_at=NOW - timedelta(days=1),
    )


def _stored(repository: CertificationRepository, cell: MatrixCell) -> StoredCertification:
    return repository.append(_certified(cell), run_id="run-nightly", now=NOW)


# ── the sweep needs a clock and a cell ───────────────────────────────────────


@pytest.mark.nightly
def test_a_lapsed_claim_is_aged_by_the_clock(
    repository: CertificationRepository,
) -> None:
    """Ageing is a *scheduled* operation, so it is driven by an explicit clock.

    The clock is a parameter rather than a hidden ``utc_now`` so the policy is
    replayable: this test does not sleep for thirty days and hope.
    """
    _stored(repository, _cell())

    sweep = sweep_certifications(repository, now=NOW + timedelta(days=90))

    assert sweep.considered == 1
    assert len(sweep.aged) == 1
    assert sweep.aged[0].record.state is not CertificationState.CERTIFIED


@pytest.mark.nightly
def test_a_claim_whose_cell_moved_is_invalidated(repository: CertificationRepository) -> None:
    """Gap item 107: the runtime moving under a claim withdraws it.

    Drift detection with the cell the runtime *has now*, so a claim cannot keep
    reporting a level for an engine, kernel or tool version it was never
    certified on.
    """
    _stored(repository, _cell(kernel_version="6.1.0"))

    sweep = sweep_certifications(
        repository,
        now=NOW,
        current_cells={FAULT: _cell(kernel_version="6.6.0")},
    )

    assert sweep.checked_against_a_cell is True
    assert [row.record.state for row in sweep.invalidated] == [CertificationState.INCOMPATIBLE]


@pytest.mark.nightly
def test_a_sweep_with_no_current_cell_says_drift_was_not_checked(
    repository: CertificationRepository,
) -> None:
    """ "Nothing moved" and "nothing was looked at" are different findings.

    A caller reading ``invalidated == ()`` from a sweep that had no cell would
    conclude the runtime still matches the claim, which is not what was learned.
    """
    _stored(repository, _cell())

    sweep = sweep_certifications(repository, now=NOW)

    assert sweep.checked_against_a_cell is False
    assert sweep.invalidated == ()
    assert sweep.changed == ()


@pytest.mark.nightly
def test_a_healthy_claim_on_an_unchanged_cell_changes_nothing(
    repository: CertificationRepository,
) -> None:
    """The control for the two above: a sweep that finds nothing leaves the row alone."""
    _stored(repository, _cell())

    sweep = sweep_certifications(repository, now=NOW, current_cells={FAULT: _cell()})

    assert sweep.checked_against_a_cell is True
    assert sweep.changed == ()
    latest = repository.latest(FAULT)
    assert latest is not None
    assert latest.record.state is CertificationState.CERTIFIED


# ── regression blocking ──────────────────────────────────────────────────────


@pytest.mark.nightly
def test_a_previously_certified_fault_going_red_blocks_the_build(
    repository: CertificationRepository,
) -> None:
    """The CI question the phase names: a stored claim a re-run contradicted.

    ``blocked`` is what a caller turns into a non-zero exit, so it is the property
    under test — not merely that the report *mentions* the fault.
    """
    cell = _cell()
    _stored(repository, cell)

    report = regression_report(
        repository,
        {FAULT: ReRunVerdict(fault_id=FAULT, certified=False, cell=cell, detail="failed again")},
        now=NOW,
    )

    assert report.claims_considered == 1
    assert [claim.stored.record.fault_id for claim in report.regressed] == [FAULT]
    assert report.blocked is True
    assert report.unreached == ()


@pytest.mark.nightly
def test_a_re_run_on_another_cell_neither_passes_nor_fails_the_stored_claim(
    repository: CertificationRepository,
) -> None:
    """A green verdict from a *different* cell is not evidence about this claim.

    Counting it as a pass would make the matrix mean "we ran something"; counting
    it as a failure would withdraw a claim that was never tested. It lands in
    ``unreached``, which is the only honest bucket.
    """
    _stored(repository, _cell())

    report = regression_report(
        repository,
        {FAULT: ReRunVerdict(fault_id=FAULT, certified=True, cell=_cell(kernel_version="6.6.0"))},
        now=NOW,
    )

    assert report.regressed == ()
    assert report.blocked is False
    assert report.unreached == (FAULT,)


@pytest.mark.nightly
def test_a_re_run_that_reproduces_the_claim_does_not_block(
    repository: CertificationRepository,
) -> None:
    """The other side of the blocking half: a green re-run must not fail the build."""
    cell = _cell()
    _stored(repository, cell)

    report = regression_report(
        repository,
        {FAULT: ReRunVerdict(fault_id=FAULT, certified=True, cell=cell)},
        now=NOW,
    )

    assert report.blocked is False
    assert report.regressed == ()


@pytest.mark.nightly
def test_applying_the_regression_withdraws_the_claim(repository: CertificationRepository) -> None:
    """The withdrawal happens, then the gate reports — so the store and the gate agree.

    The order matters and is documented on :func:`apply_regressions`: a claim
    cannot survive a regression gate that reported it.
    """
    cell = _cell()
    _stored(repository, cell)
    report = regression_report(
        repository,
        {FAULT: ReRunVerdict(fault_id=FAULT, certified=False, cell=cell)},
        now=NOW,
    )

    withdrawn = apply_regressions(repository, report, now=NOW)

    assert [row.record.state for row in withdrawn] == [CertificationState.FAILED]
    latest = repository.latest(FAULT)
    assert latest is not None
    assert latest.record.state is CertificationState.FAILED


# ── the marker itself ────────────────────────────────────────────────────────


def test_the_nightly_marker_is_registered_rather_than_spelled_wrong() -> None:
    """Guards the vacuity that made this suite necessary.

    An unregistered marker does not error under ``--strict-markers`` — it is
    simply never selected, so ``-m nightly`` runs nothing and the job goes green.
    Asserting the marker's presence in the config means a rename fails here.
    """
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    markers = config["tool"]["pytest"]["ini_options"]["markers"]

    assert any(marker.startswith("nightly:") for marker in markers)


def test_every_job_test_in_this_suite_carries_the_nightly_marker() -> None:
    """The eight job tests, named, so a lost marker fails here.

    ``-m nightly`` selecting nothing exits zero. That is the whole failure mode
    this file exists to end, so the jobs are pinned by name rather than trusted
    to a decorator that nobody would notice losing.
    """
    import sys

    module = sys.modules[__name__]
    jobs = (
        "test_a_lapsed_claim_is_aged_by_the_clock",
        "test_a_claim_whose_cell_moved_is_invalidated",
        "test_a_sweep_with_no_current_cell_says_drift_was_not_checked",
        "test_a_healthy_claim_on_an_unchanged_cell_changes_nothing",
        "test_a_previously_certified_fault_going_red_blocks_the_build",
        "test_a_re_run_on_another_cell_neither_passes_nor_fails_the_stored_claim",
        "test_a_re_run_that_reproduces_the_claim_does_not_block",
        "test_applying_the_regression_withdraws_the_claim",
    )

    unmarked = [
        name
        for name in jobs
        if not any(
            mark.name == "nightly" for mark in getattr(module.__dict__[name], "pytestmark", [])
        )
    ]

    assert unmarked == [], f"these nightly jobs lost their marker: {unmarked}"
    assert len(jobs) == 8
