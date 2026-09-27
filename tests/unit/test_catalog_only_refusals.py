"""Refusal text is the deliverable of a catalog-only fault.

A `catalog_only` entry does one useful thing: it tells an operator that the
fault they wanted does not exist here, and points at what does. Both halves rot
silently — a fault can be renamed out from under a refusal, or a param mode can
be added and the text left naming one that never existed.

`mem.oom_kill` shipped once already pointing at `mem.exhaust mode=exhaust`,
which no such mode ever had. These tests are the guard.
"""

from __future__ import annotations

import re

import pytest

from mayhem.controller.compensation import (
    _CONN_EXHAUST_MODES,
    _DB_QUERY_ERROR_MODES,
    _DB_SLOW_QUERY_MODES,
    _FD_EXHAUST_MODES,
    _MEM_EXHAUST_MODES,
)
from mayhem.domain.catalog import CATALOG, definition_for

#: Refusal prefixes. The container lane uses ``catalog.unsupported``; the k8s
#: lane uses its own, and k8s faults are exempt from the container-lane gate
#: below because gate_fault() never routes them through _CATALOG_ONLY_FAULTS.
_PREFIXES = ("catalog.unsupported", "k8s.unsupported")
_PREFIX = "catalog.unsupported"

#: Which mode vocabulary a fault's `mode`/`error` param draws from.
_MODE_POOLS: dict[str, frozenset[str] | set[str]] = {
    "mem.exhaust": _MEM_EXHAUST_MODES,
    "fd.exhaust": _FD_EXHAUST_MODES,
    "net.conn_exhaust": _CONN_EXHAUST_MODES,
    "db.query_error": set(_DB_QUERY_ERROR_MODES),
    "db.slow_query": set(_DB_SLOW_QUERY_MODES),
}

CATALOG_ONLY = [d for d in CATALOG if d.catalog_only]
FAULT_ID = re.compile(r"\b([a-z]+\.[a-z_0-9]+)\b")
MODE_REF = re.compile(r"\bmode=(\w+)")


def test_there_are_catalog_only_entries() -> None:
    assert CATALOG_ONLY, "the catalog-only refusal path is untested if this is empty"


@pytest.mark.parametrize("definition", CATALOG_ONLY, ids=lambda d: d.id)
class TestCatalogOnlyContract:
    def test_refusal_names_the_code_and_is_substantial(self, definition) -> None:
        reason = definition.refusal_reason or ""
        assert any(reason.startswith(f"{p}: ") for p in _PREFIXES), reason[:60]
        assert len(reason) > 30

    def test_refusal_points_at_a_fault_that_exists(self, definition) -> None:
        """A refusal naming a renamed or removed fault is worse than none."""
        for ref in FAULT_ID.findall(definition.refusal_reason or ""):
            if ref == _PREFIX:
                continue
            assert ref in {d.id for d in CATALOG}, (
                f"{definition.id} points at {ref!r}, which is not in the catalog"
            )

    def test_refusal_points_at_a_mode_that_exists(self, definition) -> None:
        for mode in MODE_REF.findall(definition.refusal_reason or ""):
            pool = _MODE_POOLS.get(definition.id)
            if pool is None:
                continue
            assert mode in pool, (
                f"{definition.id} points at mode={mode!r}; valid modes are {sorted(pool)}"
            )

    def test_stays_experimental_and_unverified(self, definition) -> None:
        assert definition.maturity.value == "experimental"
        assert definition.verification_date is None

    def test_has_no_compensation_template(self, definition) -> None:
        from mayhem.controller.compensation import template_for

        assert template_for(definition.id) is None

    def test_gate_reports_it_as_inert_and_probed(self, definition) -> None:
        """Not being in _CATALOG_ONLY_FAULTS makes the gate claim it can inject.

        Skipped for k8s-lane entries: gate_fault() is the container-lane gate
        and deliberately does not carry them.
        """
        from mayhem.agents.impact import gate_fault

        if definition.id.startswith("k8s."):
            pytest.skip("k8s-lane refusals are enforced by the kubectl driver")
        verdict = gate_fault(definition.id, "some-container", "podman")
        assert verdict.probed is True
        assert verdict.impact_possible is False
        assert "catalog-only" in verdict.note


@pytest.mark.parametrize(
    ("fault_id", "param"), [("db.query_error", "error"), ("db.slow_query", "mode")]
)
def test_mode_param_default_is_a_real_mode(fault_id: str, param: str) -> None:
    spec = next(p for p in definition_for(fault_id).params_schema if p.name == param)
    assert spec.default in _MODE_POOLS[fault_id]
