"""The preflight *gate*: preflight that refuses, and the postflight verdict beside it
(docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md, Phase 3, engine half).

The v1.0.0 preflight (:mod:`mayhem.controller.preflight`) *reports*. It builds a
:class:`~mayhem.domain.preflight.Preflight`, fills in a blast-radius preview, and
puts anything concerning in ``warnings`` — which the run path then reads past. That
is the shape the plan calls a bug: "a preflight that warns-and-continues is a bug,
not a feature." This module is the half that decides.

Nothing here re-derives what the existing preflight already computes. The
``plan:admitted`` check reads the :class:`~mayhem.domain.preflight.Preflight` the
caller already built — its ``blocked_items``, its blast-radius verdict — rather than
calling ``check_blast_radius`` a second time and hoping two copies agree. The same
holds on the other side: the postflight verdict is
:func:`mayhem.controller.stop_engine.postflight_report`'s, reached through
:class:`~mayhem.controller.stop_engine.StopExecution`, and this module adds a
*consumer* predicate over it rather than a second implementation of it.

Three commitments shape the code.

**A check is either judged or it refuses.** A check reports ``PASS``, ``FAIL``, or
``UNAVAILABLE``, and :func:`refuses_gate` returns ``True`` for everything that is not
``PASS``. There is no "unknown", no "warn", no "carry on and note it" — a third
state that neither passes nor blocks would be exactly the warn-and-continue the plan
forbids. A gate that evaluated *no* checks at all is refused too
(:attr:`PreflightReport.vacuous`): a gate that checked nothing and passed is worse
than no gate, because it launders the absence of a check into the appearance of one.

**An unreachable witness is ``UNAVAILABLE``, and ``UNAVAILABLE`` refuses.** The
catalogue splits in two, and the split is about honesty rather than convenience:

* **Real checks** — :data:`REAL_CHECKS` — are computed from data mayhem already
  holds: the preflight preview, the topology graph, the agent registry, the policy
  decision, and the resource budget. When their data is *absent* they report
  ``FAIL``, because mayhem has the witness and the witness says it cannot prove
  health. ``"no topology graph: cannot resolve any target"`` is a ``FAIL``.
* **Port checks** — :data:`PORT_CHECKS` — need a system mayhem does not own and
  cannot synthesise: the incident manager, the backup system, the deployment feed,
  the cluster control plane, the replication peer. Each is an **injected port**
  (:class:`IncidentPort` and friends) answering with one :class:`PortObservation`.
  An unbound port, a port that raises, a port that answers ``None``, and a port
  that answers in some other shape are the same finding — ``UNAVAILABLE`` — and
  ``UNAVAILABLE`` refuses the run. **A preflight that cannot see an incident
  manager cannot certify that no incident is open**, so it certifies nothing: the
  absence of the ability to ask is not an answer.

The two words are deliberately different, because an operator triaging a refused run
needs to know which one they are looking at. ``FAIL`` says "mayhem looked, and the
answer was no" — an operational fact about the environment. ``UNAVAILABLE`` says
"mayhem has no witness" — a wiring problem. Collapsing them would let a reviewer read
"the incident manager is down" as "the incident manager reports no incidents", and
those are opposite findings.

**The gate is additive, and absence is byte-identical.** :func:`admit` with
``gate=None`` returns ``None`` without reading a single input: no port is called, no
decision is recorded, no object is mutated. That is the same contract
:mod:`mayhem.controller.policy_gate` and :mod:`mayhem.controller.safety` made for
their optional fields, and ``tests/unit/test_preflight_gate.py`` pins it with a golden
rendering of the whole admission sequence.

**And it is a refusal in the run path, not only on request.** The gate reaches
:meth:`mayhem.controller.executor.RunEngine.execute` through
:meth:`~mayhem.controller.executor.RunEngine.with_preflight_gate` — the same
shape :meth:`~mayhem.controller.executor.RunEngine.with_budget_guard` already had —
and is consulted in one ``is not None`` block immediately before ``_open_run``, so a
refusal leaves no run row, no step row, and no lease. There is deliberately no
counterpart that removes it: no ``skip_preflight`` keyword, no
``without_preflight_gate``, no flag. The only absent state is ``preflight_gate=None``,
which means *no gate was configured*, and that state reads nothing and refuses
nothing because there is nothing to refuse with. The engine supplies only the inputs
it holds — the plan, the clock, a live topology graph if it has one, and the attached
budget guard — and every other check reports ``FAIL`` naming what it lacked. This
module does not invent a preflight preview, an agent registry, or a policy decision
for it: a gate fed an opinion it manufactured would certify it.

:func:`admit` raises :class:`PreflightRefusedError`, which carries a
:class:`~mayhem.domain.stop.StopTrigger` for the ``PREFLIGHT_REFUSAL`` signal — so a
refused run's stop reason is ``preflight_failed`` and is spelled by the vocabulary
Phase 1 already owns, not by a private string invented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol

from mayhem.controller.policy_gate import plan_faults
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.stop import PostflightVerdict, StopSignal, StopTrigger
from mayhem.domain.topology import NodeKind

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from mayhem.agents.capabilities import AgentIdentity
    from mayhem.controller.stop_engine import StopExecution
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.policy import PolicyDecision
    from mayhem.domain.preflight import Preflight
    from mayhem.domain.stop import PostflightCheck, PostflightReport
    from mayhem.domain.topology import TopologyGraph

__all__ = [
    "ALL_CHECKS",
    "CHECK_AGENT_AVAILABILITY",
    "CHECK_AGENT_CAPABILITY",
    "CHECK_BACKUP_STATE",
    "CHECK_BUDGET_AVAILABLE",
    "CHECK_CLUSTER_READY",
    "CHECK_DEPENDENCY_HEALTH",
    "CHECK_DEPLOYMENT_RECENT",
    "CHECK_INCIDENT_ACTIVE",
    "CHECK_PLAN_ADMITTED",
    "CHECK_POLICY_AVAILABLE",
    "CHECK_REPLICATION_HEALTH",
    "CHECK_TARGET_HEALTH",
    "PORT_CHECKS",
    "REAL_CHECKS",
    "RESIDUE_CHECK_PREFIX",
    "BackupPort",
    "BudgetGuard",
    "CheckSource",
    "CheckStatus",
    "ClusterPort",
    "DeploymentPort",
    "IncidentPort",
    "PortObservation",
    "PreflightCheck",
    "PreflightGate",
    "PreflightInputs",
    "PreflightPorts",
    "PreflightRefusedError",
    "PreflightReport",
    "ReplicationPort",
    "admit",
    "evaluate",
    "may_close_clean",
    "obligation_verdict",
    "open_obligations",
    "port_status",
    "postflight_report_for",
    "postflight_verdict_for",
    "refuses_gate",
]


# =============================================================================
# Statuses, and the one predicate that decides them
# =============================================================================


class CheckStatus(StrEnum):
    """What one preflight check concluded. Three members and no more."""

    PASS = "pass"
    FAIL = "fail"
    UNAVAILABLE = "unavailable"


def refuses_gate(status: CheckStatus) -> bool:
    """True for every status that blocks the run. Total over :class:`CheckStatus`.

    The rule "unavailable must fail the gate, never pass silently" lives in exactly
    one expression, so a fourth status cannot be added without this function being
    forced to decide about it. It is written ``is not PASS`` rather than as a
    membership test so that an unrecognised status arriving from a boundary refuses
    rather than passes by omission.

    The asymmetry the plan's rule demands is right here: ``UNAVAILABLE`` is not a
    soft ``FAIL``. A witness that could not be reached has not cleared the check —
    it has failed to take part in it, and a preflight that cannot see an incident
    manager cannot certify that no incident is open.
    """
    return status is not CheckStatus.PASS


class CheckSource(StrEnum):
    """Where a check's answer came from — which is what makes it trustworthy."""

    REAL = "real"
    """Computed by mayhem from data it already holds."""

    PORT = "port"
    """Read through an injected port to a system mayhem does not own."""


# =============================================================================
# Evidence references
# =============================================================================


def _require_nonblank(value: str, rule: str, subject: str) -> str:
    if not value.strip():
        msg = f"{subject} must be a non-blank string"
        raise InvariantViolationError(rule, msg)
    if value != value.strip():
        msg = f"{subject} must be trimmed; got {value!r}"
        raise InvariantViolationError(rule, msg)
    return value


def plan_ref(run_id: str) -> str:
    """Evidence reference for a plan — the subject a requirement could not be met for."""
    return f"plan/{run_id}"


def fault_ref(fault_id: str) -> str:
    """Evidence reference for one fault whose capability requirement went unmet."""
    return f"fault/{fault_id}"


def topology_ref(node_id: str = "") -> str:
    """Evidence reference for the topology graph, or for one node in it."""
    return f"topology/{node_id}" if node_id else "topology/graph"


def agent_ref(agent_id: str) -> str:
    """Evidence reference for one registered agent."""
    return f"agent/{agent_id}"


def policy_ref(bundle_id: str, version: int) -> str:
    """Evidence reference for one policy bundle version, as ``policy/<id>@<version>``."""
    return f"policy/{bundle_id or 'unidentified'}@{version}"


def budget_ref(dimensions: tuple[str, ...]) -> str:
    """Evidence reference for the resource budget that governs this run."""
    return "budget/" + (",".join(dimensions) if dimensions else "none")


def port_ref(port: str) -> str:
    """Evidence reference for a port that produced no answer.

    The weakest reference in the vocabulary and it says so: the evidence of
    unavailability *is* the silence. It is non-blank and stable, which is exactly
    what a ``PASS`` would have needed and could not have had.
    """
    return f"port/{port}"


# =============================================================================
# Check records
# =============================================================================


@dataclass(frozen=True, slots=True)
class PreflightCheck:
    """One preflight check, its verdict, and the evidence behind it.

    **An evidence reference is required on every status, not only on ``PASS``.**
    That is stricter than :class:`~mayhem.domain.stop.PostflightCheck`, which admits
    an uncited ``FAIL`` on the grounds that a found problem is admissible on the
    report of the thing that found it. Here a refusal is the thing an operator acts
    on at 3am *and* the thing an auditor re-reads a week later, so it carries its
    witness too: which node did not resolve, which fault had no capable agent, which
    port could not be reached. A check that cannot say what it looked at is not a
    check, so a blank ``evidence_ref`` is refused at construction on every status.
    """

    name: str
    status: CheckStatus
    source: CheckSource
    detail: str
    evidence_ref: str
    port: str = ""
    """The port name, required iff ``source`` is ``PORT``."""

    def __post_init__(self) -> None:
        _require_nonblank(self.name, "preflight_check_name_not_blank", "preflight check name")
        _require_nonblank(self.detail, "preflight_check_detail_not_blank", "preflight check detail")
        _require_nonblank(
            self.evidence_ref,
            "preflight_check_evidence_ref_not_blank",
            f"preflight check {self.name!r} evidence reference",
        )
        if self.source is CheckSource.PORT:
            _require_nonblank(
                self.port, "preflight_check_port_not_blank", f"port check {self.name!r} port name"
            )
        elif self.port.strip():
            msg = (
                f"preflight check {self.name!r} names port {self.port!r} but its source is "
                f"{self.source.value!r}, not port"
            )
            raise InvariantViolationError("preflight_check_port_mismatch", msg)

    @property
    def is_pass(self) -> bool:
        return self.status is CheckStatus.PASS

    @property
    def is_unavailable(self) -> bool:
        return self.status is CheckStatus.UNAVAILABLE

    @property
    def refuses(self) -> bool:
        """Whether this check, on its own, blocks the run."""
        return refuses_gate(self.status)

    def describe(self) -> str:
        return f"{self.name}={self.status.value} ({self.evidence_ref})"


@dataclass(frozen=True, slots=True)
class PortObservation:
    """One port's answer, in the only shape a port is allowed to answer in.

    Uniform on purpose. If each port returned its own type, "the port did not
    answer" would become indistinguishable from "the port answered with an empty
    result" — and that distinction *is* the safety property. An incident manager
    that returns "none open" has certified that no incident is open; an incident
    manager that could not be reached has certified nothing whatsoever.

    ``healthy=False`` is an answer: the system was reached and it is not in a state
    to run a drill against. That is a ``FAIL``, and it cites the system, because the
    system *was* the witness. A port returning ``None`` is not an answer at all.
    """

    healthy: bool
    evidence_ref: str
    detail: str = ""

    def __post_init__(self) -> None:
        _require_nonblank(self.evidence_ref, "port_observation_ref_not_blank", "port observation")


def port_status(
    observation: PortObservation | None, *, error: BaseException | None = None
) -> CheckStatus:
    """The status a port answer implies — a pure function of its two arguments.

    The rule the plan states, isolated so it can be tested without a gate, a plan,
    or a port:

    ================================  ==============
    port answer                       status
    ================================  ==============
    ``observation is None``           ``UNAVAILABLE``
    ``error is not None``             ``UNAVAILABLE``
    ``observation.healthy``           ``PASS``
    not ``observation.healthy``       ``FAIL``
    ================================  ==============

    There is deliberately no fifth row. An error does not degrade to ``FAIL``,
    because the two are different findings: ``FAIL`` is "reached, and the answer was
    no", which is a fact about the environment worth acting on, while
    ``UNAVAILABLE`` is "no answer exists", which is a fact about the wiring.
    """

    if error is not None:
        return CheckStatus.UNAVAILABLE
    if observation is None:
        return CheckStatus.UNAVAILABLE
    return CheckStatus.PASS if observation.healthy else CheckStatus.FAIL


# =============================================================================
# Injected ports
# =============================================================================


class ClusterPort(Protocol):
    """The control plane's own readiness.

    A port rather than a real check even though the plan lists cluster health first:
    a topology graph describes what *should* exist, and whether the control plane
    will accept a write is a separate fact only the control plane has.
    """

    def cluster_ready(self, *, environment: str) -> PortObservation: ...


class IncidentPort(Protocol):
    """The incident manager. The check the plan names first, for a reason.

    Drilling into an environment that already has an open incident is how a drill
    becomes the second incident, and mayhem has no way at all to know one is open.
    """

    def active_incidents(self, *, environment: str) -> PortObservation: ...


class DeploymentPort(Protocol):
    """The deployment feed — has anything changed since the plan was compiled?"""

    def recent_deployment(self, *, environment: str) -> PortObservation: ...


class BackupPort(Protocol):
    """The backup system's own record of its last good restore point.

    The mirror of the incident manager: a fault whose undo *is* a restore cannot be
    certified recoverable without knowing a restore point exists.
    """

    def backup_state(self, *, target: str) -> PortObservation: ...


class ReplicationPort(Protocol):
    """The replication peer's health — an environment with a stale replica has a
    recovery story mayhem cannot read for itself."""

    def replication_health(self, *, environment: str) -> PortObservation: ...


@dataclass(frozen=True, slots=True)
class PreflightPorts:
    """The five systems mayhem cannot honestly answer for.

    Every field defaults to ``None``, and ``None`` means ``UNAVAILABLE`` — which
    refuses. There is intentionally no "no ports configured, assume healthy"
    default: that default *is* the bug the plan is about.
    """

    cluster: ClusterPort | None = None
    incident: IncidentPort | None = None
    deployment: DeploymentPort | None = None
    backup: BackupPort | None = None
    replication: ReplicationPort | None = None

    def bound(self) -> tuple[str, ...]:
        """The names of the ports that are actually bound, in declaration order."""
        return tuple(
            name
            for name in ("cluster", "incident", "deployment", "backup", "replication")
            if getattr(self, name) is not None
        )


#: What each port exists to tell us, in the plan's words. Used as the detail of an
#: unbound or unreachable port, so an operator reading a refusal learns *which*
#: system mayhem could not consult, not merely that something was unavailable.
PORT_SUBJECTS: Final[dict[str, str]] = {
    "cluster": "a reachable control plane",
    "incident": "the active incident state",
    "deployment": "the recent-deployment feed",
    "backup": "the backup system's restore point",
    "replication": "replication health",
}


# =============================================================================
# Real-check collaborators
# =============================================================================


class BudgetGuard(Protocol):
    """Plan 23's resource budgets, read-only.

    Declared structurally, and *read* rather than driven.
    :meth:`mayhem.infra.budget_enforcement.RunBudgetGuard.admit` would judge the
    same budget the executor's guard judges a moment later, and the gate has no
    business being the second judge of one budget: two judges is exactly the class
    of duplication that eventually produces two different answers.
    """

    @property
    def dimensions(self) -> tuple[object, ...]: ...

    @property
    def estimates(self) -> tuple[object, ...]: ...


@dataclass(frozen=True, slots=True)
class PreflightInputs:
    """Everything the gate reads, named explicitly.

    ``now`` has **no default**, for the reason
    :class:`~mayhem.controller.policy_gate.PolicyGateInputs` has none either: a
    clock with a default is a clock a test can forget to pin, and a gate whose
    verdict depends on when it ran must make the moment a chosen input. Every other
    field is likewise a declared input rather than something read from the
    environment, so a check can never be answered from ambient state that the sealed
    evidence does not name.
    """

    plan: ExecutionPlan
    now: datetime
    preflight: Preflight | None = None
    graph: TopologyGraph | None = None
    agents: tuple[AgentIdentity, ...] = ()
    policy: PolicyDecision | None = None
    budget: BudgetGuard | None = None
    environment: str = ""
    target: str = ""


# =============================================================================
# The report
# =============================================================================


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """The gate's verdict, and every check it reached to form one."""

    run_id: str
    checks: tuple[PreflightCheck, ...]
    generated_at: datetime

    def __post_init__(self) -> None:
        _require_nonblank(self.run_id, "preflight_report_run_id_not_blank", "preflight run_id")
        names = [c.name for c in self.checks]
        if len(set(names)) != len(names):
            repeated = sorted({n for n in names if names.count(n) > 1})
            msg = f"preflight report repeats a check name: {repeated}"
            raise InvariantViolationError("preflight_check_names_unique", msg)

    # -- projections ---------------------------------------------------------

    @property
    def refusing_checks(self) -> tuple[PreflightCheck, ...]:
        """Every check that blocks the run, in report order."""
        return tuple(c for c in self.checks if c.refuses)

    @property
    def failed_checks(self) -> tuple[PreflightCheck, ...]:
        """Only those that were reached and answered ``FAIL``."""
        return tuple(c for c in self.checks if c.status is CheckStatus.FAIL)

    @property
    def unavailable_checks(self) -> tuple[PreflightCheck, ...]:
        """Only those with no witness at all."""
        return tuple(c for c in self.checks if c.status is CheckStatus.UNAVAILABLE)

    @property
    def vacuous(self) -> bool:
        """True when the gate evaluated nothing at all.

        And a vacuous report never grants: a gate with an empty catalogue would
        otherwise report "every check passed" about a set of zero checks, which in a
        log reads exactly like a gate that verified everything.
        """
        return not self.checks

    @property
    def granted(self) -> bool:
        """Whether the run may proceed: at least one check ran, and none refuses."""
        return not self.vacuous and not self.refusing_checks

    def check(self, name: str) -> PreflightCheck | None:
        for candidate in self.checks:
            if candidate.name == name:
                return candidate
        return None

    @property
    def refusal_reason(self) -> str:
        """One line naming every refusal, in the order the gate reached them."""
        if self.vacuous:
            return (
                f"preflight for run {self.run_id} evaluated no checks: a gate that checked "
                "nothing cannot certify a run"
            )
        if not self.refusing_checks:
            return f"preflight for run {self.run_id} granted: all {len(self.checks)} checks passed"
        blocking = "; ".join(f"{c.name}={c.status.value}: {c.detail}" for c in self.refusing_checks)
        return (
            f"preflight for run {self.run_id} refused {len(self.refusing_checks)} of "
            f"{len(self.checks)} checks: {blocking}"
        )

    def describe(self) -> str:
        return self.refusal_reason

    def inputs(self) -> dict[str, object]:
        """The machine-readable half, in the shape the safety gate records."""
        return {
            "run_id": self.run_id,
            "granted": self.granted,
            "vacuous": self.vacuous,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "source": c.source.value,
                    "evidence_ref": c.evidence_ref,
                    "port": c.port,
                }
                for c in self.checks
            ],
        }


class PreflightRefusedError(InvariantViolationError):
    """A preflight that refuses the run, carrying the report that refused it.

    Subclasses :class:`~mayhem.domain.errors.InvariantViolationError` so it is
    caught by the same ``except`` that catches the existing safety refusals — a
    preflight refusal is not a new failure mode, it is the run-time answer to a
    question the plan already asked at plan time.

    :attr:`trigger` binds the refusal to the stop vocabulary's one reason for this
    path (``preflight_failed``), so a refused run's sealed evidence names its cause
    through :mod:`mayhem.domain.stop` rather than through a string invented here.
    """

    def __init__(self, report: PreflightReport) -> None:
        super().__init__("preflight.refused", report.refusal_reason)
        self.report = report

    @property
    def trigger(self) -> StopTrigger:
        """The stop trigger this refusal produces, with its evidence.

        The evidence is the list of refusing checks — except for the vacuous
        refusal, which has none, and there the whole report's reason is carried
        instead. Without that fallback a gate that checked nothing would seal a
        ``preflight_failed`` with an empty detail, which is the one refusal whose
        cause most needs saying and the one a reader would find blankest.
        """
        detail = "; ".join(
            f"{c.name}={c.status.value} @{c.evidence_ref}" for c in self.report.refusing_checks
        )
        return StopTrigger.for_signal(
            StopSignal.PREFLIGHT_REFUSAL,
            detail=detail or self.report.refusal_reason,
        )

    @property
    def refusing_checks(self) -> tuple[PreflightCheck, ...]:
        return self.report.refusing_checks


# =============================================================================
# The check catalogue
# =============================================================================

CHECK_PLAN_ADMITTED: Final[str] = "plan:admitted"
CHECK_TARGET_HEALTH: Final[str] = "target:health"
CHECK_DEPENDENCY_HEALTH: Final[str] = "dependency:health"
CHECK_AGENT_AVAILABILITY: Final[str] = "agent:availability"
CHECK_AGENT_CAPABILITY: Final[str] = "agent:capability"
CHECK_POLICY_AVAILABLE: Final[str] = "policy:available"
CHECK_BUDGET_AVAILABLE: Final[str] = "budget:available"
CHECK_CLUSTER_READY: Final[str] = "cluster:ready"
CHECK_INCIDENT_ACTIVE: Final[str] = "incident:active"
CHECK_DEPLOYMENT_RECENT: Final[str] = "deployment:recent"
CHECK_BACKUP_STATE: Final[str] = "backup:state"
CHECK_REPLICATION_HEALTH: Final[str] = "replication:health"

REAL_CHECKS: Final[tuple[str, ...]] = (
    CHECK_PLAN_ADMITTED,
    CHECK_TARGET_HEALTH,
    CHECK_DEPENDENCY_HEALTH,
    CHECK_AGENT_AVAILABILITY,
    CHECK_AGENT_CAPABILITY,
    CHECK_POLICY_AVAILABLE,
    CHECK_BUDGET_AVAILABLE,
)
"""Checks mayhem computes from data it already holds.

The plan's list, less the systems it names as external, plus the preflight preview
they all rest on. ``Target health``, ``agent availability``, ``policy/budget
availability`` and ``dependency health`` are here. ``Active incident state``,
``recent deployment``, ``backup state`` and ``replication health`` are
:data:`PORT_CHECKS`; ``cluster:ready`` is a port too, for the reason
:class:`ClusterPort` gives.
"""

PORT_CHECKS: Final[tuple[str, ...]] = (
    CHECK_CLUSTER_READY,
    CHECK_INCIDENT_ACTIVE,
    CHECK_DEPLOYMENT_RECENT,
    CHECK_BACKUP_STATE,
    CHECK_REPLICATION_HEALTH,
)

ALL_CHECKS: Final[tuple[str, ...]] = REAL_CHECKS + PORT_CHECKS
"""The full catalogue, in the order the gate evaluates it."""

_PORT_FOR_CHECK: Final[dict[str, str]] = {
    CHECK_CLUSTER_READY: "cluster",
    CHECK_INCIDENT_ACTIVE: "incident",
    CHECK_DEPLOYMENT_RECENT: "deployment",
    CHECK_BACKUP_STATE: "backup",
    CHECK_REPLICATION_HEALTH: "replication",
}
"""Port-check name -> the :class:`PreflightPorts` field it reads."""

_PORT_METHOD: Final[dict[str, str]] = {
    "cluster": "cluster_ready",
    "incident": "active_incidents",
    "deployment": "recent_deployment",
    "backup": "backup_state",
    "replication": "replication_health",
}
"""Port name -> the single method on its protocol."""

_PORT_ARGUMENT: Final[dict[str, str]] = {
    "cluster": "environment",
    "incident": "environment",
    "deployment": "environment",
    "backup": "target",
    "replication": "environment",
}
"""Port name -> which :class:`PreflightInputs` field it is asked about."""


# =============================================================================
# Real checks
# =============================================================================


def _fault_ids(inputs: PreflightInputs) -> tuple[str, ...]:
    return tuple(fault.fault_id for fault in plan_faults(inputs.plan))


def _target_node_ids(inputs: PreflightInputs) -> tuple[str, ...]:
    ids: set[str] = set()
    for fault in plan_faults(inputs.plan):
        for resolved in fault.targets:
            ids |= set(resolved.node_ids)
    return tuple(sorted(ids))


def check_plan_admitted(inputs: PreflightInputs) -> PreflightCheck:
    """Has the *existing* preflight admitted this plan?

    Reads :mod:`mayhem.controller.preflight`'s output rather than recomputing a blast
    radius. That module already runs the authoritative
    :func:`~mayhem.controller.safety.check_blast_radius` once per fault step against
    the real gate, with the real budget; a second opinion computed here would be a
    second implementation that eventually disagrees with the first, and the
    disagreement would be silent.

    An absent preview is a ``FAIL``, not a pass. "mayhem did not check" and "mayhem
    checked and it was fine" must not look alike in a log line.
    """
    run_id = inputs.plan.run_id
    preview = inputs.preflight
    if preview is None:
        return PreflightCheck(
            name=CHECK_PLAN_ADMITTED,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail="no preflight preview: the plan-time gate was never run for this plan",
            evidence_ref=plan_ref(run_id),
        )
    if preview.blocked_items:
        return PreflightCheck(
            name=CHECK_PLAN_ADMITTED,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail=f"preflight blocked the plan: {'; '.join(preview.blocked_items)}",
            evidence_ref=plan_ref(run_id),
        )
    blast_status = str(preview.blast_radius.get("status", "")) if preview.blast_radius else ""
    if not blast_status:
        # An absent verdict is the same finding as an absent preview, by the same
        # rule: "mayhem did not measure" must not read as "mayhem measured and it
        # was fine". ``build_preflight`` never produces a blast record without a
        # ``status``, so this is the hand-built-preview path — and a hand-built
        # preview is exactly where a missing field would otherwise slip through.
        return PreflightCheck(
            name=CHECK_PLAN_ADMITTED,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail=(
                "preflight preview carries no blast-radius verdict: nothing here measured what "
                "the fault would reach"
            ),
            evidence_ref=plan_ref(run_id),
        )
    if blast_status != "within_budget":
        reason = str(preview.blast_radius.get("error", "")) or blast_status
        return PreflightCheck(
            name=CHECK_PLAN_ADMITTED,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail=f"preflight blast radius is {blast_status}: {reason}",
            evidence_ref=topology_ref(preview.topology_snapshot_id),
        )
    return PreflightCheck(
        name=CHECK_PLAN_ADMITTED,
        status=CheckStatus.PASS,
        source=CheckSource.REAL,
        detail=f"preflight preview admits the plan; blast radius {blast_status}",
        evidence_ref=topology_ref(preview.topology_snapshot_id),
    )


def check_target_health(inputs: PreflightInputs) -> PreflightCheck:
    """Does every node this plan names exist in the topology mayhem was given?

    The one question a topology graph can answer about a plan's targets, and the
    question that separates "plan 10 injects into ``n-web``" from "plan 10 injects
    into a container that was renamed an hour ago".
    """
    run_id = inputs.plan.run_id
    graph = inputs.graph
    if graph is None:
        return PreflightCheck(
            name=CHECK_TARGET_HEALTH,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail="no topology graph: cannot resolve any target node",
            evidence_ref=plan_ref(run_id),
        )
    node_ids = _target_node_ids(inputs)
    unresolved = sorted(nid for nid in node_ids if graph.by_id(nid) is None)
    if unresolved:
        return PreflightCheck(
            name=CHECK_TARGET_HEALTH,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail=(
                f"{len(unresolved)} target node id(s) do not resolve in the topology: "
                f"{', '.join(unresolved)}"
            ),
            evidence_ref=topology_ref(unresolved[0]),
        )
    if not node_ids:
        return PreflightCheck(
            name=CHECK_TARGET_HEALTH,
            status=CheckStatus.PASS,
            source=CheckSource.REAL,
            detail="plan names no target node; it has nothing to target",
            evidence_ref=topology_ref(),
        )
    return PreflightCheck(
        name=CHECK_TARGET_HEALTH,
        status=CheckStatus.PASS,
        source=CheckSource.REAL,
        detail=f"all {len(node_ids)} target node id(s) resolve in the topology",
        evidence_ref=topology_ref(node_ids[0]),
    )


def check_dependency_health(inputs: PreflightInputs) -> PreflightCheck:
    """Is the topology whole enough for a blast radius to mean anything?

    A percentage blast radius is ``affected_services / total_services``. With no
    service nodes in the graph that division is zero, and every plan's blast radius
    reads ``0%`` — a pass produced by an empty topology. This check refuses that: the
    dependency health a blast-radius number rests on has to exist before the number
    is allowed to mean something.
    """
    run_id = inputs.plan.run_id
    graph = inputs.graph
    if graph is None:
        return PreflightCheck(
            name=CHECK_DEPENDENCY_HEALTH,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail="no topology graph: cannot compute a dependency closure",
            evidence_ref=plan_ref(run_id),
        )
    services = graph.of_kind(NodeKind.SERVICE)
    if not services:
        return PreflightCheck(
            name=CHECK_DEPENDENCY_HEALTH,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail=(
                "topology names no service node: a blast radius computed from it is 0% of "
                "nothing, which is not a measurement"
            ),
            evidence_ref=topology_ref(),
        )
    broken: set[str] = set()
    reach: set[str] = set()
    for node_id in _target_node_ids(inputs):
        closure = graph.dependents_closure(node_id)
        reach |= set(closure)
        broken |= {n for n in closure if graph.by_id(n) is None}
    if broken:
        ordered = sorted(broken)
        return PreflightCheck(
            name=CHECK_DEPENDENCY_HEALTH,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail=(
                f"{len(ordered)} node(s) in the target dependency closure do not resolve: "
                f"{', '.join(ordered)}"
            ),
            evidence_ref=topology_ref(ordered[0]),
        )
    return PreflightCheck(
        name=CHECK_DEPENDENCY_HEALTH,
        status=CheckStatus.PASS,
        source=CheckSource.REAL,
        detail=(
            f"{len(services)} service node(s) and {len(reach)} dependent node(s) resolve; "
            "a blast radius computed here is a measurement"
        ),
        evidence_ref=topology_ref(),
    )


def check_agent_availability(inputs: PreflightInputs) -> PreflightCheck:
    """Is there an agent to run this plan at all?"""
    run_id = inputs.plan.run_id
    if not inputs.agents:
        return PreflightCheck(
            name=CHECK_AGENT_AVAILABILITY,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail="no agent is registered to run this plan",
            evidence_ref=plan_ref(run_id),
        )
    ids = sorted(agent.agent_id for agent in inputs.agents)
    return PreflightCheck(
        name=CHECK_AGENT_AVAILABILITY,
        status=CheckStatus.PASS,
        source=CheckSource.REAL,
        detail=f"{len(ids)} agent(s) registered: {', '.join(ids)}",
        evidence_ref=agent_ref(ids[0]),
    )


def check_agent_capability(inputs: PreflightInputs) -> PreflightCheck:
    """Can some agent inject every fault — **and undo** every fault?

    Both halves, and the undo half is the one that is easy to forget. A plan whose
    injection is permitted and whose compensation is not is a plan that leaves a live
    payload behind with nobody able to remove it — which is precisely the failure the
    whole stop ladder exists to prevent, reached at the *start* of a run rather than
    at the end of a stop.

    Derived from :meth:`mayhem.agents.capabilities.AgentCapabilities.can_inject` and
    ``can_undo``: the same predicates dispatch enforces through
    :meth:`~mayhem.agents.capabilities.AgentIdentity.validate_fault_dispatch`. One
    implementation of "may this agent inject this fault", not two.
    """
    run_id = inputs.plan.run_id
    fault_ids = _fault_ids(inputs)
    if not inputs.agents:
        return PreflightCheck(
            name=CHECK_AGENT_CAPABILITY,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail="no agent is registered, so no fault has an injector or an undoer",
            evidence_ref=plan_ref(run_id),
        )
    missing: list[tuple[str, str]] = []
    for fault_id in fault_ids:
        if not any(agent.capabilities.can_inject(fault_id) for agent in inputs.agents):
            missing.append((fault_id, f"{fault_id}: no agent may inject it"))
        elif not any(agent.capabilities.can_undo(fault_id) for agent in inputs.agents):
            missing.append((fault_id, f"{fault_id}: injectable but no agent may undo it"))
    if missing:
        # The citation names the fault that actually went unmet, not simply the
        # first fault in the plan: a plan whose *second* fault has no undoer must
        # not produce evidence pointing at the first, which has both.
        return PreflightCheck(
            name=CHECK_AGENT_CAPABILITY,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail="; ".join(reason for _, reason in missing),
            evidence_ref=fault_ref(missing[0][0]),
        )
    return PreflightCheck(
        name=CHECK_AGENT_CAPABILITY,
        status=CheckStatus.PASS,
        source=CheckSource.REAL,
        detail=(
            f"{len(fault_ids)} fault(s) each have an injector and an undoer: "
            f"{', '.join(fault_ids) or 'none declared'}"
        ),
        evidence_ref=agent_ref(sorted(a.agent_id for a in inputs.agents)[0]),
    )


def check_policy_available(inputs: PreflightInputs) -> PreflightCheck:
    """Is there a policy decision, and does it permit this run?

    The check is *availability*, not permission: a gate that cannot see the policy
    cannot certify the run is permitted, so no decision at all is a ``FAIL``. A deny
    is a ``FAIL`` that quotes the deny's own reasons — plan 07 already computed them,
    with the right rules in the right order, and re-deriving them here would only
    create room to disagree.
    """
    run_id = inputs.plan.run_id
    decision = inputs.policy
    if decision is None:
        return PreflightCheck(
            name=CHECK_POLICY_AVAILABLE,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail=(
                "no policy decision was supplied: a gate that cannot see the policy cannot "
                "certify the run is permitted"
            ),
            evidence_ref=plan_ref(run_id),
        )
    ref = policy_ref(decision.bundle_id, decision.bundle_version)
    if decision.denied:
        return PreflightCheck(
            name=CHECK_POLICY_AVAILABLE,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail=f"policy denies the run: {'; '.join(decision.reasons) or 'denied'}",
            evidence_ref=ref,
        )
    return PreflightCheck(
        name=CHECK_POLICY_AVAILABLE,
        status=CheckStatus.PASS,
        source=CheckSource.REAL,
        detail=(
            f"policy {decision.describe()} allows the run; "
            f"matched={list(decision.matched_rules) or 'none'}"
        ),
        evidence_ref=ref,
    )


def check_budget_available(inputs: PreflightInputs) -> PreflightCheck:
    """Is there a resource budget that could actually judge this run? (plan 23)

    Availability, not headroom: the *executor's* guard owns the headroom question and
    answers it before the run opens. What preflight owns is the weaker and prior
    claim that a budget exists and would mean something. A guard with no governed
    dimension, or with no estimate to compare against a limit, is not a budget — it
    is a budget-shaped object that admits everything, and "admits everything" is
    indistinguishable from having no gate at all.
    """
    run_id = inputs.plan.run_id
    guard = inputs.budget
    if guard is None:
        return PreflightCheck(
            name=CHECK_BUDGET_AVAILABLE,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail=(
                "no resource budget is attached: a run nobody budgeted cannot be certified "
                "affordable"
            ),
            evidence_ref=plan_ref(run_id),
        )
    dimensions = tuple(str(getattr(dim, "value", dim)) for dim in guard.dimensions)
    if not dimensions:
        return PreflightCheck(
            name=CHECK_BUDGET_AVAILABLE,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail="the attached budget governs no dimension, so it would admit anything",
            evidence_ref=budget_ref(dimensions),
        )
    if not guard.estimates:
        return PreflightCheck(
            name=CHECK_BUDGET_AVAILABLE,
            status=CheckStatus.FAIL,
            source=CheckSource.REAL,
            detail=(
                f"the attached budget governs {', '.join(dimensions)} but carries no estimate "
                "to compare against a limit, so admission would be vacuous"
            ),
            evidence_ref=budget_ref(dimensions),
        )
    return PreflightCheck(
        name=CHECK_BUDGET_AVAILABLE,
        status=CheckStatus.PASS,
        source=CheckSource.REAL,
        detail=(
            f"resource budget governs {', '.join(dimensions)} against "
            f"{len(guard.estimates)} estimate(s)"
        ),
        evidence_ref=budget_ref(dimensions),
    )


_REAL_CHECKS: Final[dict[str, Callable[[PreflightInputs], PreflightCheck]]] = {
    CHECK_PLAN_ADMITTED: check_plan_admitted,
    CHECK_TARGET_HEALTH: check_target_health,
    CHECK_DEPENDENCY_HEALTH: check_dependency_health,
    CHECK_AGENT_AVAILABILITY: check_agent_availability,
    CHECK_AGENT_CAPABILITY: check_agent_capability,
    CHECK_POLICY_AVAILABLE: check_policy_available,
    CHECK_BUDGET_AVAILABLE: check_budget_available,
}


# =============================================================================
# Port checks
# =============================================================================


class _MalformedPortAnswerError(Exception):
    """A bound port answered in a shape other than :class:`PortObservation`.

    Private, because it is a defect in an injected adapter rather than anything
    a caller acts on. It exists so that boundary is handled like every other way
    of getting no answer — the whole point of :func:`port_status` is that
    "did not answer" is one finding, and a port returning ``object()`` has not
    answered any more than a port that raised has.
    """


def _port_check(
    check_name: str, port: str, bound: object, argument: str, value: str
) -> PreflightCheck:
    """One port, one check. Four ways to have no answer, one status for all four."""
    subject = PORT_SUBJECTS[port]
    if bound is None:
        return PreflightCheck(
            name=check_name,
            status=CheckStatus.UNAVAILABLE,
            source=CheckSource.PORT,
            detail=(
                f"no {port} port is bound: mayhem cannot see {subject}, and an unconsulted "
                "witness is not a passing one"
            ),
            evidence_ref=port_ref(port),
            port=port,
        )
    error: BaseException | None = None
    observation: PortObservation | None = None
    try:
        probe: Callable[..., object] = getattr(bound, _PORT_METHOD[port])
        answer = probe(**{argument: value})
        # The protocol is structural, so nothing stops a port that satisfies the
        # attribute lookup and returns something else. Reading ``.healthy`` off it
        # would raise out of ``evaluate`` — a crash where the honest answer is
        # "this witness cannot speak", which refuses.
        if not isinstance(answer, PortObservation):
            msg = (
                f"{type(answer).__name__} is not a PortObservation; the {port} port may only "
                "answer in that shape"
            )
            raise _MalformedPortAnswerError(msg)
        observation = answer
    except Exception as exc:
        # Any failure at all means "no answer", and that is precisely the point:
        # a timeout, a refused connection, a malformed reply and a bug in the port
        # are indistinguishable to mayhem, and none of them may read as a pass.
        error = exc
    status = port_status(observation, error=error)
    if status is CheckStatus.UNAVAILABLE:
        why = f"{type(error).__name__}: {error}" if error is not None else "returned no observation"
        return PreflightCheck(
            name=check_name,
            status=status,
            source=CheckSource.PORT,
            detail=f"{port} port is unreachable ({why}); mayhem cannot see {subject}",
            evidence_ref=port_ref(port),
            port=port,
        )
    # ``port_status`` returns PASS or FAIL only when an observation exists, so this
    # narrows the Optional for the type checker rather than deciding anything.
    assert observation is not None
    verdict = "healthy" if observation.healthy else "unhealthy"
    return PreflightCheck(
        name=check_name,
        status=status,
        source=CheckSource.PORT,
        detail=observation.detail or f"{port} reported {verdict}",
        evidence_ref=observation.evidence_ref,
        port=port,
    )


# =============================================================================
# The gate
# =============================================================================


@dataclass(frozen=True, slots=True)
class PreflightGate:
    """The gate: which checks to run, and the ports to run the external ones through.

    ``checks`` defaults to the whole catalogue. Narrowing it is an operator decision
    and it is visible: an omitted check shows up as an *absence* in
    :attr:`PreflightReport.checks`, never as a pass. Narrowing can therefore only
    ever refuse more or say less — it cannot convert a refusal into a pass, because
    a check that did not run cannot have passed.

    Every name is validated against :data:`ALL_CHECKS` at construction, so a typo
    cannot quietly produce a gate that evaluates nothing: the failure mode this
    module exists to make impossible.
    """

    ports: PreflightPorts = field(default_factory=PreflightPorts)
    checks: tuple[str, ...] = ALL_CHECKS

    def __post_init__(self) -> None:
        unknown = sorted(name for name in self.checks if name not in ALL_CHECKS)
        if unknown:
            msg = f"unknown preflight check(s): {unknown}; known: {list(ALL_CHECKS)}"
            raise InvariantViolationError("preflight_unknown_check", msg)
        repeated = sorted({n for n in self.checks if self.checks.count(n) > 1})
        if repeated:
            msg = f"preflight gate repeats a check: {repeated}"
            raise InvariantViolationError("preflight_duplicate_check", msg)

    def evaluate(self, inputs: PreflightInputs) -> PreflightReport:
        """Run every selected check and report what it found.

        Never *refuses* — a refusal is a returned report, not an exception, and
        only :meth:`admit` turns one into a raised
        :class:`PreflightRefusedError`. Nothing a caller can hand in makes this
        raise: an unbound port, a port that raises, a port that answers in the
        wrong shape, and an input the checks were written for all produce
        statuses. Only a defect *inside* a check propagates, which is correct —
        that is a bug in the gate, not an environment finding to be recorded as
        a refusal.
        """
        checks: list[PreflightCheck] = []
        for name in self.checks:
            port = _PORT_FOR_CHECK.get(name)
            if port is None:
                checks.append(_REAL_CHECKS[name](inputs))
                continue
            checks.append(
                _port_check(
                    name,
                    port,
                    getattr(self.ports, port),
                    _PORT_ARGUMENT[port],
                    inputs.target if port == "backup" else inputs.environment,
                )
            )
        return PreflightReport(
            run_id=inputs.plan.run_id, checks=tuple(checks), generated_at=inputs.now
        )

    def admit(self, inputs: PreflightInputs) -> PreflightReport:
        """Evaluate, then refuse unless the report grants.

        Raises:
            PreflightRefusedError: When any check refuses, or when the gate evaluated
                nothing at all.
        """
        report = self.evaluate(inputs)
        if not report.granted:
            raise PreflightRefusedError(report)
        return report

    def refusing_names(self, inputs: PreflightInputs) -> tuple[str, ...]:
        """The names of the checks that would refuse this run, without raising.

        A preview, for a surface that wants to render the checklist before deciding
        whether to start. It cannot be mistaken for a decision: the return type is a
        tuple of names, and :meth:`admit` is the only thing that grants.
        """
        return tuple(c.name for c in self.evaluate(inputs).refusing_checks)


# =============================================================================
# Entry points
# =============================================================================


def evaluate(gate: PreflightGate, inputs: PreflightInputs) -> PreflightReport:
    """Evaluate *gate* against *inputs*. Never raises; always reports."""
    return gate.evaluate(inputs)


def admit(gate: PreflightGate | None, inputs: PreflightInputs) -> PreflightReport | None:
    """Admit a run, or refuse it — and do nothing whatsoever when no gate is configured.

    **The additive contract, in one branch.** ``gate=None`` returns ``None``
    immediately: no check runs, no port is called, no field of ``inputs`` is read,
    and nothing is mutated. That is what makes binding this gate into a run path a
    no-op until somebody opts in, and it is why
    ``tests/unit/test_preflight_gate.py`` can pin the no-preflight path to a
    byte-identical golden.

    With a gate configured this either returns the granting report or raises
    :class:`PreflightRefusedError`. It never returns a report that does not grant,
    and never returns at all while refusing — there is no ``(report, ok)`` pair for
    a caller to forget to check.
    """
    if gate is None:
        return None
    return gate.admit(inputs)


# =============================================================================
# Postflight: the mirror, over the recovery output stop_engine already computed
# =============================================================================

RESIDUE_CHECK_PREFIX: Final[str] = "residue:"
"""Prefix of the check names :func:`mayhem.controller.stop_engine.postflight_report`
gives each residue finding — plus the passing ``residue:scan``, which is the receipt
for a scan that came back empty."""


def postflight_report_for(execution: StopExecution) -> PostflightReport | None:
    """The postflight report a stop produced, or ``None`` when the stop never sealed.

    Not a computation. Phase 2's
    :func:`mayhem.controller.stop_engine.postflight_report` already built this from
    the recovery execution result, the residue findings and the run-completion gate.
    This is the accessor, so a caller holding a :class:`StopExecution` can reach the
    report without going to the ledger for it — and cannot invent one.
    """
    return execution.report


def open_obligations(report: PostflightReport | None) -> tuple[PostflightCheck, ...]:
    """The residue obligations still standing: one entry per thing the undo missed.

    A ``FAIL`` residue check *is* an open obligation. The passing ``residue:scan``
    is excluded by the ``is_pass`` filter, so what comes back is exclusively open
    work and never a receipt.
    """
    if report is None:
        return ()
    return tuple(
        c for c in report.checks if c.name.startswith(RESIDUE_CHECK_PREFIX) and not c.is_pass
    )


def obligation_verdict(report: PostflightReport | None, *, now: datetime | None = None) -> bool:
    """``True`` only for a report that is clean *and* owes nothing.

    The conjunction the run-completion question is actually made of, as a pure
    predicate over a report: no open residue obligation, and a verdict the report
    itself recomputes as ``CLEAN``. It is exposed rather than folded into
    :func:`may_close_clean` so the rule is testable from outside the sealed-stop
    machinery, and because the second half is deliberately *not* re-implemented: the
    verdict comes from
    :meth:`~mayhem.domain.stop.PostflightReport.verdict`, so there is exactly one
    place in the tree that decides what "clean" means.

    An absent report is ``False``: a stop that stalled has established nothing, and
    nothing established is not a clean run.
    """
    if report is None:
        return False
    return not open_obligations(report) and report.verdict(now) is PostflightVerdict.CLEAN


def postflight_verdict_for(
    execution: StopExecution, *, now: datetime | None = None
) -> PostflightVerdict:
    """The verdict for a stopped run, recomputed by the report that produced it.

    Two rules, neither of them this module's to invent:

    * **A stop that stalled produced no report, and no report is ``UNKNOWN``** —
      never ``CLEAN``. Unchecked is not clean, and unchecked is not dirty either;
      :class:`~mayhem.domain.stop.PostflightVerdict` reserves ``UNKNOWN`` for exactly
      this case. This is the same ``UNKNOWN`` :attr:`StopExecution.verdict` returns
      for an unsealed stop, reached with an injectable clock.
    * **The verdict is recomputed from the checks on every read**, by
      :meth:`~mayhem.domain.stop.PostflightReport.verdict`, with precedence
      ``DIRTY > UNKNOWN > CLEAN`. It is read here, never re-derived and never taken
      on trust.

    **An open obligation can never read ``CLEAN`` here, by construction rather than
    by assertion.** :func:`mayhem.controller.stop_engine.postflight_report` emits one
    ``FAIL`` check per residue finding, and ``PostflightReport.verdict`` returns
    ``DIRTY`` the moment any check fails — so an open obligation settles the verdict
    before the stale-evidence branch is ever reached. :func:`obligation_verdict`
    restates that conjunction as a testable predicate, and
    ``tests/unit/test_preflight_gate.py`` pins it by showing the *same* stop reading
    ``CLEAN`` once the finding is gone from the report. A dropped residue is the only
    way to get a clean verdict here, which is the correct failure direction: the
    report can be made clean by proving the undo missed nothing, and by nothing
    else.
    """
    report = execution.report
    if report is None:
        return PostflightVerdict.UNKNOWN
    return report.verdict(now)


def may_close_clean(execution: StopExecution, *, now: datetime | None = None) -> bool:
    """Whether a stopped run may be closed clean — the run-completion question.

    Three conditions, all necessary:

    * the stop **sealed** — a stalled stop is recorded, not finished, and
      :attr:`StopExecution.sealed` is ``None`` for one;
    * a report **exists**;
    * and :func:`obligation_verdict` holds — no open residue obligation, and a
      verdict the report itself recomputes as ``CLEAN``.

    The obligation test is written as its own early return rather than left to the
    verdict. That is defence in depth over a property
    :meth:`~mayhem.domain.stop.PostflightReport.verdict` already has: it is
    redundant today, and it stays redundant if that precedence is ever edited, which
    is precisely when a redundant guard is worth its two lines.
    """
    report = execution.report
    if report is None or execution.sealed is None:
        return False
    if open_obligations(report):
        return False
    return postflight_verdict_for(execution, now=now) is PostflightVerdict.CLEAN
