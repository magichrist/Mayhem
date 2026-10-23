"""Import-spec fixtures for ``tests/unit/test_binding_spec.py``.

The binding mechanism in :mod:`mayhem.cli.execution` resolves a
``module:attribute`` spec through :func:`importlib.import_module`, so the
fixtures under test must live in a real importable module rather than being
built inside a test function. This module is that module: it is importable as
``tests.unit.binding_fixtures`` (rootdir on ``sys.path`` via
``pythonpath = ["."]``, namespace packages), and every attribute a test names
through a spec string is defined here at module level.

The witnesses are *trivial but real*: each port implementation satisfies the
structural protocol in :mod:`mayhem.controller.preflight_gate` exactly —
keyword-only arguments, ``PortObservation`` return, non-blank
``evidence_ref`` — so the gate is genuinely constructible over them. They are
not ``object()`` stubs, because the point of the suite is that a bound gate
resolves, and a gate over fake witnesses would not prove that.

The factories mirror the two calling conventions the two bindings have: a gate
factory takes *no* arguments (it closes over its own wiring) while a budget
factory takes *this run's* ``run_id``. Both conventions are represented, plus
the deliberately wrong ones the refusal tests need.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from mayhem.cli.execution import resource_budget_guard
from mayhem.controller.preflight_gate import (
    CHECK_CLUSTER_READY,
    PortObservation,
    PreflightGate,
    PreflightPorts,
)
from mayhem.domain.budgets import ResourceScope

if TYPE_CHECKING:
    from mayhem.infra.budget_enforcement import RunBudgetGuard


def _observation(subject: str) -> PortObservation:
    return PortObservation(
        healthy=True,
        evidence_ref=f"probe://{subject}/ok",
        detail=f"{subject} reports healthy",
    )


class StaticClusterPort:
    def cluster_ready(self, *, environment: str) -> PortObservation:
        return _observation(f"cluster/{environment}")


class StaticIncidentPort:
    def active_incidents(self, *, environment: str) -> PortObservation:
        return _observation(f"incidents/{environment}")


class StaticDeploymentPort:
    def recent_deployment(self, *, environment: str) -> PortObservation:
        return _observation(f"deployments/{environment}")


class StaticBackupPort:
    def backup_state(self, *, target: str) -> PortObservation:
        return _observation(f"backups/{target}")


class StaticReplicationPort:
    def replication_health(self, *, environment: str) -> PortObservation:
        return _observation(f"replication/{environment}")


#: A fully bound port set — all five witnesses the gate can consult.
five_ports = PreflightPorts(
    cluster=StaticClusterPort(),
    incident=StaticIncidentPort(),
    deployment=StaticDeploymentPort(),
    backup=StaticBackupPort(),
    replication=StaticReplicationPort(),
)

#: The unconfigured state: no witness bound. Must resolve to *no gate*.
empty_ports = PreflightPorts()

#: A configured gate, narrowed by the deployment itself. The verbatim case:
#: handing one over means the narrowing decision was already made.
ready_gate = PreflightGate(ports=five_ports, checks=(CHECK_CLUSTER_READY,))

#: The mapping shape: witness name -> witness, all five names.
witness_mapping: dict[str, object] = {
    "cluster": five_ports.cluster,
    "incident": five_ports.incident,
    "deployment": five_ports.deployment,
    "backup": five_ports.backup,
    "replication": five_ports.replication,
}

#: A mapping under a name the five do not include — refused by name.
unknown_witness_mapping: dict[str, object] = {"incident_manager": StaticIncidentPort()}

#: An attribute holding a shape the binding accepts none of.
bad_shape = object()


def gate_factory() -> PreflightPorts:
    """Zero-arg factory (the gate convention), returning bound ports."""
    return five_ports


def empty_ports_factory() -> PreflightPorts:
    """Zero-arg factory returning the unconfigured state."""
    return empty_ports


def object_factory() -> object:
    """Zero-arg factory returning an unusable shape."""
    return bad_shape


def raising_factory() -> PreflightPorts:
    msg = "wiring exploded before a gate could be built"
    raise RuntimeError(msg)


def budget_guard(run_id: str) -> RunBudgetGuard:
    """The run-scoped budget factory: takes ``run_id``, returns a guard for it.

    No budgets govern, which is fine here — the binding tests only need the
    factory to be *called with* the right run and to return the right type;
    what the guard would refuse is plan 23's own suite's subject.
    """
    return resource_budget_guard(
        budgets=(),
        scope=ResourceScope.RUN,
        anchor=datetime(2026, 1, 1, tzinfo=UTC),
        run_id=run_id,
    )


def zero_arg_budget_factory() -> RunBudgetGuard:
    """A budget factory in the *gate's* shape — takes no arguments.

    The budget path calls it with ``run_id`` anyway, so the mismatch must be
    refused loudly, not surfaced as a bare ``TypeError``.
    """
    return budget_guard("never-scoped")


def raising_budget_factory(run_id: str) -> RunBudgetGuard:
    msg = f"budget ledger unreachable for run {run_id}"
    raise RuntimeError(msg)
