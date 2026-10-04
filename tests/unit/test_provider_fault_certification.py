"""Plan 01 x plan 17 — a provider's own fault id reaches the certification record.

**This suite exists because of a real defect.** ``CertificationRecord`` carries a
provider branch in :meth:`_plausible_fault_id` whose whole purpose is to let
plan 17's provider faults into the certification pipeline on a cell that pins the
provider at a named version. That branch was **unreachable**: the catalogue
lookup it guards with

    try:
        FaultCategory.from_fault_id(value)
    except ValueError as exc:
        catalog_refusal = str(exc)

never took its ``except`` clause, because
:func:`~mayhem.domain.faults.FaultCategory.from_fault_id` raises
``SchemaValidationError`` — which subclasses ``DomainError``, *not* ``ValueError``.
The exception therefore propagated straight out of the validator and every
provider fault id was refused by the catalogue lookup, whichever provider the
cell pinned. The refusal was fail-closed, so nothing unsafe ever happened; what
happened is that a documented capability did not exist and every test asserting
the refusal passed for the wrong reason.

Every test below is two-sided: the accepting case and the refusal that must
survive it. A suite that asserted only the refusals would have been green over
the dead branch, which is what happened.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError
from tests.unit.test_provider_participation import _cell, _metadata

from mayhem.domain.certification import CertificationRecord, MatrixCell
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.domain.faults import FaultCategory

OTHER_PROVIDER = "other.injector"


def _record(fault_id: str, cell: MatrixCell, version: str) -> CertificationRecord:
    return CertificationRecord(
        fault_id=fault_id,
        cell=cell,
        injector_version=version,
        expires_at=utc_now() + timedelta(days=30),
    )


@pytest.fixture
def pinned_cell() -> MatrixCell:
    """A cell carrying a *complete* provider pin."""
    metadata = _metadata()
    return MatrixCell(
        **{
            **_cell().model_dump(),
            "provider_id": metadata.provider_id,
            "provider_version": metadata.version,
        }
    )


@pytest.fixture
def provider_fault_id() -> str:
    """A fault id scoped to the provider this suite's cell pins.

    ``FaultCategory`` owns the first segment, so a provider's ids cannot use a
    catalogue family (``net.something`` reads as mayhem's own) — they carry the
    provider's own id as their prefix.
    """
    return f"{_metadata().provider_id}.slow"


# ── the branch that was dead ─────────────────────────────────────────────────


def test_a_providers_own_fault_is_certifiable_on_a_cell_that_pins_it(
    pinned_cell: MatrixCell, provider_fault_id: str
) -> None:
    metadata = _metadata()

    record = _record(provider_fault_id, pinned_cell, metadata.version)

    assert record.fault_id == provider_fault_id
    assert record.cell.provider_pin is not None


def test_the_same_fault_is_refused_on_a_cell_with_no_pin(provider_fault_id: str) -> None:
    """Fails closed: no pin means there is nothing to scope the id to.

    This is the half that keeps the fix honest. Widening the handler to catch
    ``DomainError`` must not have widened *what* is accepted — a provider id on an
    unpinned cell is still refused, because any string would otherwise be
    certifiable, which is the one outcome a certification record exists to
    prevent.
    """
    with pytest.raises(ValidationError, match="complete provider pin"):
        _record(provider_fault_id, _cell(), "1.2.3")


def test_a_fault_of_a_different_provider_is_refused_on_our_cell(
    pinned_cell: MatrixCell,
) -> None:
    """A cell may only certify the faults of the provider it names."""
    with pytest.raises(ValidationError, match="does not belong to provider"):
        _record(f"{OTHER_PROVIDER}.slow", pinned_cell, "1.2.3")


def test_a_half_written_pin_cannot_certify_a_provider_fault(provider_fault_id: str) -> None:
    """An id with no version is *no* pin, not a weaker one.

    ``MatrixCell`` stays permissive here on purpose — a half-written pin is a
    describable fact about a runtime — so the refusal belongs at the record, which
    is where a claim is made.
    """
    metadata = _metadata()
    half = MatrixCell(**{**_cell().model_dump(), "provider_id": metadata.provider_id})

    with pytest.raises(ValidationError, match="complete provider pin"):
        _record(provider_fault_id, half, metadata.version)


def test_a_mayhem_catalogue_fault_is_unaffected_by_the_pin(pinned_cell: MatrixCell) -> None:
    """The catalogue branch is untouched, on a pinned cell and on an unpinned one."""
    metadata = _metadata()

    assert _record("net.latency", pinned_cell, metadata.version).fault_id == "net.latency"
    assert _record("net.latency", _cell(), metadata.version).fault_id == "net.latency"


# ── the exception type the dead branch depended on ───────────────────────────


def test_the_catalogue_lookup_raises_a_domain_error_not_a_value_error() -> None:
    """The regression itself, pinned at its source.

    ``except ValueError`` around a call that raises a ``DomainError`` is a handler
    that never fires. Asserting the raise type here means a future change to the
    exception hierarchy cannot silently make the provider branch unreachable
    again — which is exactly what happened, and no behavioural test caught it
    because every behavioural test asserted a refusal.
    """
    with pytest.raises(DomainError):
        FaultCategory.from_fault_id("acme.injector.slow")

    assert not issubclass(DomainError, ValueError), (
        "this suite documents that DomainError is NOT a ValueError; if that "
        "changes the handler in _plausible_fault_id should be re-read"
    )


def test_the_catalogue_branch_still_recognises_mayhems_own_ids() -> None:
    """Guards the other side: the catalogue branch must not have been loosened."""
    assert FaultCategory.from_fault_id("net.latency")
