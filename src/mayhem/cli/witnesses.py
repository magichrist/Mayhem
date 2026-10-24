"""The worked example for the two deployment bindings — and nothing more.

mayhem attaches a preflight gate to a run by *importing* whatever a deployment
points it at, not by reading a config file it owns. Two environment variables do
the pointing, each naming a ``module:attribute`` import spec:

============================  =====================================================
``MAYHEM_GATE_WITNESSES``    the port witnesses a gate consults — here,
                             ``mayhem.cli.witnesses:unavailable_ports``
``MAYHEM_BUDGET_GUARD``      the run's resource budget guard, which lives in
                             *your* module: ``your.module:budget_for_run``
============================  =====================================================

The gate side accepts a :class:`~mayhem.controller.preflight_gate.PreflightGate`,
a :class:`~mayhem.controller.preflight_gate.PreflightPorts`, a mapping of witness
name to witness, or a zero-argument callable returning any of those. The budget
side accepts a
:class:`~mayhem.infra.budget_enforcement.RunBudgetGuard` or a callable taking
this run's ``run_id``. Both are resolved in :mod:`mayhem.cli.execution`, and a
spec that cannot be loaded is refused loudly rather than degraded into "no gate"
— an operator who asked for gating and silently got none has been told the safe
thing is on while it is off.


Why every witness here answers ``UNAVAILABLE``
----------------------------------------------

mayhem owns no incident manager, no deployment feed, no backup system and no
replication peer. It therefore has *no honest answer* to any of the five port
questions, and the five witnesses below say so by raising: the gate records the
failure to get an answer, names the system it could not consult, and refuses.

That refusal is the entire product of this module. A witness here that answered
``HEALTHY`` would be a fabrication wearing the costume of a check — it would let
a run begin against a control plane it never reached and an incident list it
never read, and would do so while producing a sealed, signed, entirely fictional
record that it had. ``UNAVAILABLE`` is the only answer mayhem is entitled to give
on its own behalf, so it is the only answer these witnesses give.


Start here: :func:`empty_ports`
-------------------------------

:func:`unavailable_ports` **refuses every run it is attached to**, by design and
without exception. It is here to show the shape of the answer, not to be
deployed. The documented starting point for an operator is :func:`empty_ports`,
which binds nothing and resolves to *no gate at all* — the unconfigured state,
where the run path is exactly what it was before this lane existed. Wire up the
witnesses you actually have, and leave the rest unbound.


Binding a witness for real
--------------------------

Import :func:`unavailable_ports` for the shape, then replace each port with your
own implementation — one object satisfying the matching protocol in
:mod:`mayhem.controller.preflight_gate`:

.. code-block:: python

   from mayhem.cli.witnesses import unavailable_ports
   from mayhem.controller.preflight_gate import PreflightPorts

   _shape = unavailable_ports()          # the shape, not the wiring

   real_ports = PreflightPorts(
       cluster=PagerDutyControlPlane(),    # def cluster_ready(self, *, environment) ...
       incident=PagerDutyIncidents(),      # def active_incidents(self, *, environment) ...
       deployment=ArgoDeployments(),       # def recent_deployment(self, *, environment) ...
       backup=VeleroRestorePoints(),       # def backup_state(self, *, target) ...
       replication=ReplicationPeer(),      # def replication_health(self, *, environment) ...
   )

then point the environment at it::

   MAYHEM_GATE_WITNESSES=your.module:real_ports

Each replacement must answer in
:class:`~mayhem.controller.preflight_gate.PortObservation` and cite non-blank
evidence — that is the whole contract. A port that returns ``None`` has not
answered; a port that raises has refused to answer; only an observation is a
witness. And because an unbound port is *also* ``UNAVAILABLE``, the gate refuses
a half-built set too, naming the port you forgot rather than passing it silently.


This is a template, not a deployment
------------------------------------

Nothing here talks to a real system, and nothing here is a claim about one. This
module exists because the binding mechanism is otherwise documented nowhere in
the repository: a deployment that wants gating has to author this file from
scratch against type definitions alone. Copy it into your own package, and make
it true.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NoReturn

from mayhem.controller.preflight_gate import PORT_SUBJECTS, PreflightPorts

if TYPE_CHECKING:
    from mayhem.controller.preflight_gate import PortObservation
    from mayhem.infra.budget_enforcement import RunBudgetGuard

__all__ = ["empty_ports", "noop_budget_guard", "unavailable_ports"]


class WitnessUnavailableError(Exception):
    """A witness with nothing to report, raised rather than guessed.

    Named in the module's namespace but not in :data:`__all__`: it is not part
    of the surface a deployment binds to. It *is* what an operator sees, though
    — :func:`~mayhem.controller.preflight_gate._port_check` reads the exception's
    type and message straight into the check detail, so this is the wording of
    the refusal as much as the refusal itself.

    It is an ordinary :class:`Exception` rather than an
    :class:`~mayhem.domain.errors.InvariantViolationError` on purpose: nothing is
    broken. The wire is fine and the gate is working; mayhem simply has no client
    for the system it was asked about, and the gate is *supposed* to treat that
    as no answer.
    """


class _UnavailableWitness:
    """The shared refusal behind all five witnesses.

    Subclasses pin one port and answer its one question, so a witness can never
    be bound into a slot it knows nothing about. The refusal itself is written
    once, here, so the five cannot drift apart in wording and each names its
    subject from :data:`~mayhem.controller.preflight_gate.PORT_SUBJECTS` — the
    same table the gate names it from, which is what makes the two halves of the
    detail agree instead of merely rhyme.
    """

    def _refuse(self, port: str, asked_about: str) -> NoReturn:
        """Give the gate no answer, and say which system was never asked.

        *asked_about* is the environment or target the gate was probing. The
        check detail the gate builds does not mention it, so carrying it here is
        the only place a reader learns *which* question went unanswered rather
        than merely that one did.
        """
        subject = PORT_SUBJECTS[port]
        msg = (
            f"mayhem ships no {port} witness; it never asked about {subject} "
            f"(asked {asked_about!r})"
        )
        raise WitnessUnavailableError(msg)


class _UnavailableClusterPort(_UnavailableWitness):
    """Stands in for the control plane's own readiness."""

    def cluster_ready(self, *, environment: str) -> PortObservation:
        return self._refuse("cluster", environment)


class _UnavailableIncidentPort(_UnavailableWitness):
    """Stands in for the incident manager — the check that should be first."""

    def active_incidents(self, *, environment: str) -> PortObservation:
        return self._refuse("incident", environment)


class _UnavailableDeploymentPort(_UnavailableWitness):
    """Stands in for the deployment feed — what changed since the plan compiled."""

    def recent_deployment(self, *, environment: str) -> PortObservation:
        return self._refuse("deployment", environment)


class _UnavailableBackupPort(_UnavailableWitness):
    """Stands in for the backup system's own record of its last good restore point."""

    def backup_state(self, *, target: str) -> PortObservation:
        return self._refuse("backup", target)


class _UnavailableReplicationPort(_UnavailableWitness):
    """Stands in for the replication peer's health."""

    def replication_health(self, *, environment: str) -> PortObservation:
        return self._refuse("replication", environment)


def unavailable_ports() -> PreflightPorts:
    """All five ports bound to witnesses that can only answer ``UNAVAILABLE``.

    The refusing shape: :func:`mayhem.cli.execution.gate_from_spec` builds a real
    gate over this, and every check in it refuses, because mayhem owns no
    incident manager, deployment feed, backup system or replication peer to ask.
    Each refusal names the system it could not consult, from
    :data:`~mayhem.controller.preflight_gate.PORT_SUBJECTS`.

    Bind it with ``MAYHEM_GATE_WITNESSES=mayhem.cli.witnesses:unavailable_ports``.
    It is zero-argument so it resolves through the factory convention, and it
    builds a fresh set per call rather than sharing one, so a deployment that
    replaces a single port cannot mutate wiring another run is mid-way through.

    **This refuses every run it is attached to.** That is what it is for: to be
    the worked example of an honest refusal, and to be the starting shape to copy
    when replacing each port with a real witness. An operator wanting a run to
    proceed wants :func:`empty_ports` and real witnesses, not this.

    Returns:
        Five ports, each bound, each of which refuses to answer.
    """
    return PreflightPorts(
        cluster=_UnavailableClusterPort(),
        incident=_UnavailableIncidentPort(),
        deployment=_UnavailableDeploymentPort(),
        backup=_UnavailableBackupPort(),
        replication=_UnavailableReplicationPort(),
    )


def empty_ports() -> PreflightPorts:
    """Nothing bound — the documented "empty binding is no gate" state.

    :func:`mayhem.cli.execution.gate_from_spec` reports this as ``None``: no gate
    is attached, and a run behaves exactly as it did before the gating lane
    existed. That is deliberately *not* the same answer as
    :func:`unavailable_ports`, even though both block a run in practice — one
    says "mayhem cannot see", the other says "this deployment configured
    nothing", and an operator reading a refusal needs to know which.

    **Start here.** This is the right first binding for a deployment that wants
    gating without having wired anything yet, and the right shape to grow: bound
    the ports you have real witnesses for, leave the rest ``None``, and let the
    gate refuse on exactly those rather than on the ones you never intended to
    consult.

    Bind it with ``MAYHEM_GATE_WITNESSES=mayhem.cli.witnesses:empty_ports``.

    Returns:
        A :class:`~mayhem.controller.preflight_gate.PreflightPorts` with all
        five fields ``None``, whose :meth:`~mayhem.controller.preflight_gate.\
PreflightPorts.bound` is empty.
    """
    return PreflightPorts()


def noop_budget_guard(run_id: str) -> RunBudgetGuard | None:
    """No guard — the "a binding that resolves to ``None``" case, made bindable.

    :func:`mayhem.cli.execution.budget_guard_from_spec` calls a budget factory
    with this run's ``run_id`` and passes a ``None`` result through, leaving plan
    23's admission and continuity hooks inert for that run. That is the honest
    answer for a deployment that budgets nothing, and it is otherwise awkward to
    reach from a spec, because an unset ``MAYHEM_BUDGET_GUARD`` takes a different
    path entirely (no import happens at all).

    *run_id* is accepted and deliberately unused. It is the parameter the binding
    contract requires, and the signature is the point: a zero-argument factory is
    refused here rather than called, so a deployment copying this cannot quietly
    become run-independent.

    Bind it with ``MAYHEM_BUDGET_GUARD=mayhem.cli.witnesses:noop_budget_guard``.

    Returns:
        Always ``None`` — this run is not budgeted, and no import of
        :mod:`mayhem.infra.budget_enforcement` is needed to say so.
    """
    return None
