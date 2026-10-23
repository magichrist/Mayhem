"""The environment-driven binding: ``module:attribute`` to gate or guard.

``mayhem.cli.execution`` lets a deployment attach the two refusing controls it
owns — plan 10's preflight gate (``MAYHEM_GATE_WITNESSES``) and plan 23's
resource budget guard (``MAYHEM_BUDGET_GUARD``) — by naming an import spec.
Before this suite the whole mechanism had zero coverage, so the properties
pinned here are the ones the block comment in ``execution.py`` claims:

* **every accepted shape resolves.** An attribute holding a configured
  ``PreflightGate`` is returned *verbatim* (the deployment narrowed it itself
  and mayhem does not widen it back); a ``PreflightPorts``, a mapping of
  witness name to witness, and a zero-arg callable returning any of those all
  resolve to the same gate the value would have. The factory is not a wider
  door than the value it names.
* **unconfigured is ``None``, never a refusing gate.** ``PreflightPorts()``
  with nothing bound, a factory returning one, an unset env var, and an env
  var of pure whitespace all mean *no gate was configured*: nothing attached,
  run path unchanged. Attaching a gate over them would refuse every run for
  five systems nobody can answer for.
* **a binding that cannot load is refused loudly.** Malformed spec, missing
  module, missing attribute, a raising factory, an unusable shape — each
  raises :class:`~mayhem.domain.errors.InvariantViolationError` naming its
  own stable rule, never degrades to ``None``. An operator who asked for a
  gate and silently got none would be told the safe thing is on while it is
  off.
* **the budget binding is run-scoped.** Its factory is called *with* the
  run's id, a guard resolved for run A is not reused for run B, and a
  factory in the gate's zero-arg shape is refused (``budget_binding_call``)
  rather than leaking the bare ``TypeError`` from the wrong calling
  convention.
* **the environment seam closes end to end.** ``MAYHEM_GATE_WITNESSES`` set,
  ``mayhem.cli.app.run_gate`` read, ``mayhem.cli.services.engine_for``
  attached — the only path a deployment can actually reach.

Timestamps are injected or fixed; nothing here reads a wall clock, and no
test touches docker/podman/kubernetes — only the resolution seam.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.unit import binding_fixtures as fixtures

from mayhem.cli.app import run_budget_guard, run_gate
from mayhem.cli.execution import (
    BUDGET_GUARD_ENV,
    GATE_WITNESSES_ENV,
    budget_guard_from_spec,
    gate_for_ports,
    gate_from_spec,
)
from mayhem.controller.preflight_gate import ALL_CHECKS, CHECK_CLUSTER_READY
from mayhem.controller.preflight_gate import PreflightGate as Gate
from mayhem.controller.preflight_gate import PreflightPorts as Ports
from mayhem.domain.errors import InvariantViolationError

FIXTURES = "tests.unit.binding_fixtures"


# ---------------------------------------------------------------------------
# The four accepted shapes
# ---------------------------------------------------------------------------


def test_attribute_holding_a_configured_gate_is_returned_verbatim() -> None:
    gate = gate_from_spec(f"{FIXTURES}:ready_gate")
    assert gate is fixtures.ready_gate  # `is`, not `==`: verbatim, never rebuilt.


def test_attribute_holding_ports_builds_a_gate_over_the_whole_catalogue() -> None:
    gate = gate_from_spec(f"{FIXTURES}:five_ports")
    assert isinstance(gate, Gate)
    assert gate.ports is fixtures.five_ports
    assert gate.checks == ALL_CHECKS


def test_mapping_of_witness_names_builds_a_gate() -> None:
    gate = gate_from_spec(f"{FIXTURES}:witness_mapping")
    assert isinstance(gate, Gate)
    assert gate.ports.bound() == ("cluster", "incident", "deployment", "backup", "replication")


def test_zero_arg_factory_resolves_exactly_like_the_value_directly() -> None:
    direct = gate_from_spec(f"{FIXTURES}:five_ports")
    via_factory = gate_from_spec(f"{FIXTURES}:gate_factory")
    assert via_factory == direct
    assert via_factory.ports is fixtures.five_ports


# ---------------------------------------------------------------------------
# Unconfigured is None, not a refusing gate
# ---------------------------------------------------------------------------


def test_ports_with_nothing_bound_is_no_gate() -> None:
    assert gate_for_ports(Ports()) is None


def test_an_empty_ports_attribute_is_no_gate() -> None:
    assert gate_from_spec(f"{FIXTURES}:empty_ports") is None


def test_a_factory_returning_empty_ports_is_no_gate() -> None:
    assert gate_from_spec(f"{FIXTURES}:empty_ports_factory") is None


def test_run_gate_with_the_env_var_unset_is_none() -> None:
    assert run_gate(environ={}) is None


def test_run_gate_with_whitespace_in_the_env_var_is_none() -> None:
    assert run_gate(environ={GATE_WITNESSES_ENV: "   \t "}) is None


def test_run_budget_guard_with_the_env_var_unset_or_blank_is_none() -> None:
    assert run_budget_guard("run-A", environ={}) is None
    assert run_budget_guard("run-A", environ={BUDGET_GUARD_ENV: "  "}) is None


# ---------------------------------------------------------------------------
# Refusals: named rules, never None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "rule"),
    [
        ("tests.unit.binding_fixtures", "gate_binding_spec"),
        (f"{FIXTURES}:not_an_attribute", "gate_binding_import"),
        ("no_such_module_at_all:attr", "gate_binding_import"),
        (f"{FIXTURES}:raising_factory", "gate_binding_call"),
        (f"{FIXTURES}:object_factory", "gate_binding_shape"),
        (f"{FIXTURES}:bad_shape", "gate_binding_shape"),
        (f"{FIXTURES}:unknown_witness_mapping", "gate_binding_witness_name"),
    ],
)
def test_every_unusable_gate_binding_raises_a_named_rule(spec: str, rule: str) -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        gate_from_spec(spec)
    assert excinfo.value.rule == rule


def test_gate_binding_failure_chains_the_factory_exception() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        gate_from_spec(f"{FIXTURES}:raising_factory")
    assert isinstance(excinfo.value.__cause__, RuntimeError)


@pytest.mark.parametrize(
    ("spec", "rule"),
    [
        ("tests.unit.binding_fixtures", "budget_binding_spec"),
        ("no_such_module_at_all:attr", "budget_binding_import"),
        (f"{FIXTURES}:raising_budget_factory", "budget_binding_call"),
        (f"{FIXTURES}:bad_shape", "budget_binding_shape"),
    ],
)
def test_every_unusable_budget_binding_raises_a_named_rule(spec: str, rule: str) -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        budget_guard_from_spec(spec, run_id="run-A")
    assert excinfo.value.rule == rule


# ---------------------------------------------------------------------------
# The budget factory is run-scoped
# ---------------------------------------------------------------------------


def test_the_budget_factory_is_called_with_the_run_id_passed_in() -> None:
    guard = budget_guard_from_spec(f"{FIXTURES}:budget_guard", run_id="run-A")
    assert guard is not None
    assert guard.enforcer.run_id == "run-A"


def test_a_zero_arg_budget_factory_is_refused_not_leaked_as_a_type_error() -> None:
    """A factory in the gate's zero-arg shape must not escape as bare ``TypeError``.

    ``budget_guard_from_spec`` calls whatever it resolved with ``run_id``; a
    zero-arg callable therefore raises ``TypeError`` at the call site. The
    binding wraps *every* factory exception, so the operator sees the named
    ``budget_binding_call`` refusal with the ``TypeError`` chained beneath it
    — a bare ``TypeError`` escaping here would be the defect this test guards
    against.
    """
    with pytest.raises(InvariantViolationError) as excinfo:
        budget_guard_from_spec(f"{FIXTURES}:zero_arg_budget_factory", run_id="run-A")
    assert excinfo.value.rule == "budget_binding_call"
    assert isinstance(excinfo.value.__cause__, TypeError)


def test_run_budget_guard_scopes_the_guard_by_run_id() -> None:
    environ = {BUDGET_GUARD_ENV: f"{FIXTURES}:budget_guard"}
    guard_a = run_budget_guard("run-A", environ=environ)
    guard_b = run_budget_guard("run-B", environ=environ)
    assert guard_a is not None and guard_b is not None
    assert guard_a is not guard_b
    assert guard_a.enforcer.run_id == "run-A"
    assert guard_b.enforcer.run_id == "run-B"


# ---------------------------------------------------------------------------
# The environment seam, end to end
# ---------------------------------------------------------------------------


def test_env_var_through_run_gate_and_engine_for_attaches_a_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The only seam a deployment can reach: env var -> run_gate -> engine.

    ``mayhem.cli.lifecycle`` does exactly this — ``gate = run_gate()`` then
    ``engine_for(..., gate=gate)`` — so the test walks the same two calls and
    asserts the engine came back gated over the bound witnesses.
    """
    from mayhem.cli.services import engine_for
    from mayhem.infra.store import Store

    monkeypatch.setenv(GATE_WITNESSES_ENV, f"{FIXTURES}:five_ports")
    gate = run_gate()
    assert isinstance(gate, Gate)

    store = Store.open_migrated(Path(":memory:"))
    try:
        engine = engine_for(store, "podman", gate=gate)
    finally:
        store.close()
    assert engine.preflight_gate is not None
    assert engine.preflight_gate.ports is fixtures.five_ports
    assert CHECK_CLUSTER_READY in engine.preflight_gate.checks
