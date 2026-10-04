from __future__ import annotations

import hashlib
import json
from dataclasses import fields
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from mayhem.domain.errors import InvariantViolationError
from mayhem.infra.report import artifact_name
from mayhem.toolkit.hashing import canonical_json

#: ``artifact_name`` is re-exported here so ``mayhem.cli`` callers keep one
#: import site; the definition lives in ``mayhem.infra.report`` because
#: ``infra.evidence`` needs it too and must not reach upward into ``cli``
#: (layered-architecture contract).
__all__ = [
    "BUDGET_GUARD_ENV",
    "GATE_WITNESSES_ENV",
    "artifact_name",
    "attach_preflight_gate",
    "attach_resource_budget",
    "budget_admission",
    "budget_guard_from_spec",
    "gate_for_ports",
    "gate_from_spec",
    "plan_hash_from_file",
    "resource_budget_guard",
]

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from mayhem.controller.executor import RunEngine
    from mayhem.controller.preflight_gate import PreflightGate, PreflightPorts
    from mayhem.controller.steady_state import SteadyStateReport
    from mayhem.domain.budgets import (
        ResourceBudget,
        ResourceEstimate,
        ResourceScope,
    )
    from mayhem.domain.steady_state import SteadyStateSpec
    from mayhem.infra.budget_enforcement import ConcurrentRunReservations, RunBudgetGuard
    from mayhem.infra.metering import AdmissionDecision, RunMeter
    from mayhem.infra.store import Store


# -- preflight (plan 10 Phase 3) -------------------------------------------------
# The refusing preflight gate reached the run path through exactly the shape plan
# 23's budget guard already had: one optional constructor keyword on
# ``RunEngine`` and one ``is not None`` block in ``execute``, plus the attach
# helper below. Before this, the gate existed but a refusal was reachable only by
# a caller who explicitly asked for one — which is not a refusal in the run path.
# There is deliberately no ``attach_no_preflight`` and no flag: see
# ``RunEngine.with_preflight_gate``.


def attach_preflight_gate(engine: RunEngine, gate: PreflightGate) -> RunEngine:
    """Attach ``gate`` to ``engine``; returns the engine.

    The refusal then runs inside ``RunEngine.execute``, before the run row opens,
    so every CLI surface that attaches one gets admission without knowing it and
    without a second decision to keep in step. A surface that attaches none is
    unchanged: :func:`mayhem.controller.preflight_gate.admit` is never called,
    no port is read, and the run proceeds exactly as it did before this lane.
    """
    return engine.with_preflight_gate(gate)


# -- the deployment's binding (plan 10 Phase 3, integration dependency 3) -------
# ``attach_preflight_gate`` was reachable and had nothing to attach: mayhem owns
# no incident manager, no deployment feed, no backup system, no replication peer,
# and cannot synthesise any of them. So a CLI surface had nothing to wire and
# every production run was correctly ungated. This block is the configuration
# path that gives one to them: a deployment that *does* own those systems binds
# its own objects and mayhem consults them before the run opens.
#
# Three rules, and they are the whole design.
#
# **Binding is explicit, and it can only add.** :data:`GATE_WITNESSES_ENV` and
# :data:`BUDGET_GUARD_ENV` name an import spec each; the only thing either can
# produce is a gate or a guard. Neither can remove one, narrow one away, or
# switch off what a deployment bound in-process, and there is no second spelling
# that gets past what a binding installed. A binding that cannot be loaded is
# **refused loudly** (an :class:`~mayhem.domain.errors.InvariantViolationError`
# before any store is touched) rather than degraded into "no gate", because an
# operator who asked for gating and silently got none has been told the safe
# thing is on when it is off.
#
# **An empty binding is no gate, not a refusing one.** A
# :class:`~mayhem.controller.preflight_gate.PreflightPorts` with nothing bound is
# the *unconfigured* state, and :func:`gate_for_ports` reports it as ``None`` so
# nothing is attached and ``RunEngine.execute`` behaves exactly as it did before
# this lane. Attaching a gate over it instead would refuse every run for five
# systems nobody can answer for, which on every screen reads as mayhem being
# broken rather than as mayhem being unable to see.
#
# **What a bound gate can still not see is documented, not papered over.** The
# engine supplies the gate only what it holds, so ``plan:admitted``,
# ``agent:availability``, ``agent:capability``, ``policy:available`` and
# ``budget:available`` are judged ``FAIL`` naming what they lacked. A
# deployment that binds all five witnesses therefore still gets a refusal until
# it also declares a narrower catalogue — which is its decision to make and is
# visible as an *absence* of checks, never as a pass.

#: Names the module attribute holding this deployment's preflight witnesses, as
#: ``module:attribute``. Read once at the CLI edge by
#: :func:`mayhem.cli.app.run_gate`, which is the only module that consults the
#: environment for it — the controller reads nothing and imports no CLI module,
#: the same discipline ``allow_implicit`` follows.
GATE_WITNESSES_ENV: Final[str] = "MAYHEM_GATE_WITNESSES"

#: Names the module attribute holding this deployment's
#: :class:`~mayhem.infra.budget_enforcement.RunBudgetGuard`, as
#: ``module:attribute``. Plan 23's guard has no configuration of its own in
#: ``mayhem.yaml``: a budget is a statement about somebody's infrastructure, so
#: the deployment states it and mayhem holds it.
BUDGET_GUARD_ENV: Final[str] = "MAYHEM_BUDGET_GUARD"


def gate_for_ports(
    ports: PreflightPorts | None,
    *,
    checks: Sequence[str] | None = None,
) -> PreflightGate | None:
    """The run's gate over *ports* — or ``None`` when no witness is bound.

    ``None`` means *no gate was configured*, the additive state
    :func:`mayhem.controller.preflight_gate.admit` and
    ``RunEngine.execute`` were both built around: nothing is consulted, no port
    is called, and the run proceeds exactly as it did before this lane. It is not
    a gate that passes, and it is not a gate that refuses.

    A binding that names at least one witness produces a gate over the whole of
    ``ports``, so the witnesses a deployment did **not** bind are ``UNAVAILABLE``
    inside a gate that exists and refuses. That is the honest shape: an operator
    who wired the incident manager and not the backup system learns exactly which
    one is missing, instead of learning that mayhem as a whole is unavailable.

    ``checks`` narrows the catalogue, and narrowing can only refuse more or say
    less — a check that did not run cannot have passed. The default is every
    check, which is the *refusing* choice: see the block comment above for why a
    fully-wired deployment still has to narrow it.
    """
    from mayhem.controller.preflight_gate import ALL_CHECKS
    from mayhem.controller.preflight_gate import PreflightGate as _Gate

    if ports is None or not ports.bound():
        return None
    return _Gate(ports=ports, checks=tuple(ALL_CHECKS if checks is None else checks))


def gate_from_spec(spec: str) -> PreflightGate | None:
    """The gate a deployment named by *spec* (``module:attribute``), or ``None``.

    The attribute may be a :class:`~mayhem.controller.preflight_gate.\
PreflightPorts`, a mapping of witness name to witness, a
    :class:`~mayhem.controller.preflight_gate.PreflightGate`, or a no-argument
    callable returning any of those. A gate is returned verbatim rather than
    rebuilt, because a deployment that hands over a configured gate has made the
    narrowing decision itself and mayhem has no business widening it back.

    ``None`` is the answer for a binding that resolves to ``None`` or to a
    ``PreflightPorts`` with nothing bound — the unconfigured state again, not a
    silently discarded gate.

    Raises:
        InvariantViolationError: The spec is malformed, the module or attribute
            cannot be imported, the factory raised, or the object is not one of
            the accepted shapes. Every one of those is refused rather than
            downgraded to "no gate": see the block comment.
    """
    found = _load_binding(spec, GATE_WITNESSES_ENV, "gate_binding")
    return _resolve_gate(found)


def _resolve_gate(found: Any) -> PreflightGate | None:
    """One gate binding to a gate — or to ``None``, which means *unconfigured*.

    The single place the accepted shapes are decided, so the attribute path and
    the factory path cannot drift: a witness name refused on one and accepted on
    the other is exactly the typo this module refuses to let through. The order
    is the conservative one — the three concrete shapes first, so a configured
    gate handed over directly is returned verbatim and never *called*, and only
    then the factory, and finally the refusal.

    A factory is called with no arguments (a gate closes over its own wiring)
    and whatever it returns is resolved by this same function, so a factory is
    not a wider door than the value it names: one returning ``object()`` is
    refused exactly as an attribute holding ``object()`` is, and one returning an
    empty :class:`~mayhem.controller.preflight_gate.PreflightPorts` is the
    unconfigured state rather than a gate refusing for five systems nobody bound.

    Raises:
        InvariantViolationError: The factory raised, or the object is not one of
            the accepted shapes.
    """
    from collections.abc import Mapping as _Mapping

    from mayhem.controller.preflight_gate import PreflightGate as _Gate
    from mayhem.controller.preflight_gate import PreflightPorts as _Ports

    if found is None:
        return None
    if isinstance(found, _Gate):
        return found
    if isinstance(found, _Ports):
        return gate_for_ports(found)
    if isinstance(found, _Mapping):
        return gate_for_ports(_ports_from_mapping(found))
    if callable(found):
        try:
            resolved = found()
        except Exception as exc:
            raise _binding_error(
                "gate_binding_call",
                f"{GATE_WITNESSES_ENV} factory raised: {type(exc).__name__}: {exc}",
            ) from exc
        # Bounded by construction, not by hope: each recursion consumes one layer
        # of the deployment's own object graph, and a finite graph bottoms out at
        # the shape check above.
        return _resolve_gate(resolved)
    raise _binding_error(
        "gate_binding_shape",
        f"{GATE_WITNESSES_ENV} must resolve to a PreflightGate, a PreflightPorts, a mapping of "
        f"witness name to witness, or a callable returning one; got {type(found).__name__}",
    )


def budget_guard_from_spec(spec: str, *, run_id: str) -> RunBudgetGuard | None:
    """The resource-budget guard a deployment named by *spec*, or ``None``.

    The attribute may be a :class:`~mayhem.infra.budget_enforcement.\
RunBudgetGuard`, or a callable taking this run's ``run_id`` and returning one.
    The run id is passed rather than declared because a guard's budgets are
    scoped to it (``ResourceScope.RUN`` resolves a scope key from it), so a
    deployment cannot write one guard for every run and mean it.

    Raises:
        InvariantViolationError: The spec cannot be loaded, the factory raised or
        returned the wrong shape, or the object is not a guard.
    """
    from mayhem.infra.budget_enforcement import RunBudgetGuard as _Guard

    found = _load_binding(spec, BUDGET_GUARD_ENV, "budget_binding")
    if callable(found):
        try:
            found = found(run_id)
        except Exception as exc:
            raise _binding_error(
                "budget_binding_call",
                f"{BUDGET_GUARD_ENV} factory raised for run {run_id}: {type(exc).__name__}: {exc}",
            ) from exc
    if found is None:
        return None
    if not isinstance(found, _Guard):
        raise _binding_error(
            "budget_binding_shape",
            f"{BUDGET_GUARD_ENV} must resolve to a RunBudgetGuard or a callable returning one; "
            f"got {type(found).__name__}",
        )
    return found


def _binding_error(rule: str, message: str) -> InvariantViolationError:
    return InvariantViolationError(rule, message)


def _load_binding(spec: str, variable: str, rule_prefix: str) -> Any:
    """Import ``module:attribute`` from *spec* and return the attribute, uncalled.

    The one import both bindings go through, so both are refused the same way for
    the same reasons. It deliberately **does not call** what it finds: each binding
    decides its own call, because the two need different arguments — a gate
    factory closes over its own wiring and is called with nothing, while a budget
    guard is run-scoped and is called with this run's id. Calling here, before
    the caller had a chance to supply its argument, would have made the
    run-scoped factory unreachable: every one of them would have been invoked with
    no arguments and refused for the ``TypeError`` that followed, which reads as a
    broken binding rather than as a binding that was never given its run.
    """
    from importlib import import_module

    module_name, separator, attribute = spec.partition(":")
    module_name, attribute = module_name.strip(), attribute.strip()
    if not separator or not module_name or not attribute:
        raise _binding_error(
            f"{rule_prefix}_spec",
            f"{variable} must name 'module:attribute'; got {spec!r}",
        )
    try:
        module = import_module(module_name)
    except Exception as exc:
        raise _binding_error(
            f"{rule_prefix}_import",
            f"{variable} cannot import {module_name!r}: {type(exc).__name__}: {exc}",
        ) from exc
    try:
        return getattr(module, attribute)
    except AttributeError as exc:
        raise _binding_error(
            f"{rule_prefix}_import",
            f"{module_name!r} has no attribute {attribute!r}, named by {variable}",
        ) from exc


def _ports_from_mapping(mapping: Mapping[str, object]) -> PreflightPorts:
    """Build a ``PreflightPorts`` from ``{witness name: witness}``.

    The five names are read off the dataclass rather than restated here, so a
    port added to ``PreflightPorts`` cannot be a name this rejects — and an
    unknown name is refused by name, because a typo in a witness name is the one
    mistake that would otherwise read as a witness nobody bound.
    """
    from mayhem.controller.preflight_gate import PreflightPorts as _Ports

    known = tuple(f.name for f in fields(_Ports))
    unknown = sorted(str(name) for name in mapping if name not in known)
    if unknown:
        raise _binding_error(
            "gate_binding_witness_name",
            f"unknown preflight witness name(s) {unknown}; the five are {list(known)}",
        )
    # Typed as ``Any`` because the witness types are structural protocols: the
    # dataclass declares what each field must satisfy, and mayhem checks a
    # witness when the gate asks it, not when it is bound.
    bound: dict[str, Any] = {str(name): witness for name, witness in mapping.items()}
    return _Ports(**bound)


# -- resource budgets (plan 23 Phase 3) -----------------------------------------
# The two call sites ``mayhem.infra.metering.ResourceBudgetEnforcer`` documented
# and could not reach itself. Both are here, at the CLI edge, plus the attach
# helper — and the executor consults the same guard from inside ``execute``, so a
# caller that attaches one gets admission *and* continuity without any CLI change.


def resource_budget_guard(
    *,
    budgets: Sequence[ResourceBudget],
    scope: ResourceScope,
    anchor: datetime,
    run_id: str,
    meter: RunMeter | None = None,
    reservations: ConcurrentRunReservations | None = None,
    estimates: Sequence[ResourceEstimate] = (),
) -> RunBudgetGuard:
    """Build the run's resource-budget guard: budgets + meter + concurrency.

    The one constructor a caller needs. ``meter`` and ``reservations`` are the
    run's measurement surfaces; a dimension whose seam has produced no reading
    is reported **unmeasured** rather than zero, so omitting one of these
    degrades a guard to "no opinion about that dimension", never to "that
    dimension cost nothing".

    Pre-execution estimates are *not* a parameter here: an ``ExecutionPlan``
    carries none, and deriving them in this module would mean inventing the basis
    :class:`~mayhem.domain.budgets.ResourceEstimate` requires. Pass them to
    :func:`budget_admission`, or let the check inside ``RunEngine.execute`` admit
    vacuously — which it reports through
    :attr:`~mayhem.infra.budget_enforcement.RunBudgetGuard.admission_is_vacuous`
    rather than as a pass.

    Exact call site for the CLI run path:
    ``mayhem.cli.lifecycle`` executes a compiled plan at
    ``result = run_engine.execute(compiled.plan)``. Build the guard there and
    :func:`attach_resource_budget` it onto the engine it just built from
    ``mayhem.cli.services.build_run_engine``; the admission check then runs
    inside ``execute`` before the run row is opened.
    """
    from mayhem.infra.budget_enforcement import RunBudgetGuard
    from mayhem.infra.metering import ResourceBudgetEnforcer

    return RunBudgetGuard(
        enforcer=ResourceBudgetEnforcer(
            budgets=budgets,
            scope=scope,
            anchor=anchor,
            run_id=run_id,
        ),
        meter=meter,
        reservations=reservations,
        estimates=tuple(estimates),
    )


def attach_resource_budget(engine: RunEngine, guard: RunBudgetGuard) -> RunEngine:
    """Attach ``guard`` to ``engine``; returns the engine.

    The additive attach point. ``build_run_engine`` is shared by every CLI
    surface, so requiring each of them to thread a budget keyword through would
    make budgeting a per-surface decision; attaching after construction keeps it
    one decision at one place and leaves every surface that does not attach one
    exactly as it was.
    """
    return engine.with_budget_guard(guard)


def budget_admission(
    guard: RunBudgetGuard,
    *,
    now: datetime,
    estimates: Sequence[ResourceEstimate] | None = None,
) -> AdmissionDecision:
    """Judge the estimates against the run's budgets *before* the engine runs.

    The admission seam for a caller that wants to fail fast — before it builds an
    engine, a lease sink, or anything else — rather than relying on the check
    inside ``RunEngine.execute``. Same enforcer, same refusal, same numbers; this
    is a second door to one decision, not a second decision.

    Raises:
        BudgetAdmissionRefused: When an estimate breaches a limit, naming the
            dimension, the number, the limit, and the overage.
    """
    return guard.admit(estimates, now=now)


def evaluate_steady_state(
    spec: SteadyStateSpec | None,
    *,
    run_id: str,
    config: Any,
    store: Store,
    engine: str = "podman",
    baseline_from: str | None = None,
    during: Mapping[str, float | None] | None = None,
    post: Mapping[str, float | None] | None = None,
    bypasses: Mapping[tuple[str, str], str] | None = None,
    collector: Any | None = None,
) -> SteadyStateReport | None:
    """Capture the baseline, grade the three phases, persist the verdict.

    Returns ``None`` — and touches nothing — when the drill declares no
    ``steady_state:`` block. That is the compatibility guarantee, enforced at
    the entry point rather than by each caller remembering: a run without the
    block performs no capture, writes no ``steady_state_evaluations`` row, and
    renders no extra byte.

    With ``baseline_from``, the baselines come from that earlier run's
    ``pre``-phase rows instead of a fresh capture (plan step 6), and the report
    records which run it was measured against.
    """
    from mayhem.controller.steady_state import (
        BaselineCapture,
        SteadyStateEvaluationRepository,
        baseline_from_run,
        capture_baselines,
        evaluate_run,
    )

    if spec is None or spec.empty:
        return None
    baseline_from = baseline_from or ""
    if baseline_from:
        reused = baseline_from_run(
            store, baseline_from, [str(signal.name) for signal in spec.signals]
        )
        capture = BaselineCapture(baselines=dict(reused), source_id=baseline_from)
    else:
        capture = (
            capture_baselines(spec, config=config, engine=engine, collector=collector)
            if collector is not None
            else capture_baselines(spec, config=config, engine=engine)
        )
    report = evaluate_run(
        spec,
        run_id=run_id,
        capture=capture,
        during=during,
        post=post,
        baseline_from=baseline_from,
        bypasses=bypasses,
    )
    SteadyStateEvaluationRepository(store).save(report)
    return report


def steady_state_display(report: SteadyStateReport | None) -> str:
    """Rendered exactly like the preflight block: absent report, absent output."""
    if report is None:
        return ""
    from mayhem.cli.render import render_steady_state_human

    return "\n".join(render_steady_state_human(report))


def plan_hash_from_file(path: str) -> str:
    text = Path(path).read_text()
    try:
        data = json.loads(text)
        return hashlib.sha256(canonical_json(data).encode()).hexdigest()
    except Exception:
        return hashlib.sha256(text.encode()).hexdigest()


def load_plan_file(path: str) -> dict[str, Any]:
    text = Path(path).read_text()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"raw": text}


def reject_if_stale(
    *,
    preflight_fingerprint: str,
    current_fingerprint: str,
    preflight_target: str | None,
    current_target: str | None,
    plan_hash: str | None = None,
) -> None:
    if (
        preflight_fingerprint
        and current_fingerprint
        and preflight_fingerprint != current_fingerprint
    ):
        raise ValueError(
            f"stale plan: fingerprint changed {preflight_fingerprint[:12]} -> {current_fingerprint[:12]}; re-plan"
        )
    if (
        preflight_target is not None
        and current_target is not None
        and preflight_target != current_target
    ):
        raise ValueError(
            f"stale plan: target changed {preflight_target!r} -> {current_target!r}; re-plan"
        )


def expected_evidence_display(expected: tuple[str, ...] | list[str]) -> str:
    if not expected:
        return "expected evidence: none"
    return "expected evidence: " + ", ".join(expected)


# Rendered order matches the order the gate enforces its limits in
# (``check_blast_radius``), so the first failing limit on screen is the first
# limit the run will be refused by.
_BLAST_LIMIT_ROWS: tuple[tuple[str, str, str], ...] = (
    ("services_pct", "max_services_pct", "%"),
    ("hosts", "max_hosts", ""),
    ("concurrent_faults", "max_concurrent_faults", ""),
    ("duration_per_fault", "max_duration_per_fault_s", "s"),
)


def blast_radius_display(blast: dict[str, Any]) -> str:
    if not blast:
        return "blast_radius: unknown"
    if blast.get("status") == "unknown":
        return (
            f"blast_radius: unknown — could not compute ({blast.get('error', 'no reason given')})"
        )

    lines: list[str] = []
    for key, cap, unit in _BLAST_LIMIT_ROWS:
        if key not in blast and cap not in blast:
            continue
        value = blast.get(key, "?")
        limit = blast.get(cap, "?")
        ok = blast.get(f"{key}_ok")
        mark = "" if ok is None else (" ok" if ok else " OVER BUDGET")
        lines.append(f"  {key}={value}{unit} of {cap}={limit}{unit}{mark}")

    violations = blast.get("violations") or []
    for violation in violations:
        lines.append(
            f"  WILL REFUSE [{violation.get('rule_id', '?')}] {violation.get('reason', '')}"
        )
        if violation.get("remediation"):
            lines.append(f"    remediation: {violation['remediation']}")

    shown = {key for key, _, _ in _BLAST_LIMIT_ROWS} | {f"{a}_ok" for a, _, _ in _BLAST_LIMIT_ROWS}
    shown |= {cap for _, cap, _ in _BLAST_LIMIT_ROWS} | {"status", "violations"}
    extras = [
        f"{k}={v}"
        for k, v in sorted(blast.items())
        if k not in shown and not isinstance(v, (list, dict))
    ]
    if extras:
        lines.append("  " + ", ".join(extras))
    return "blast_radius:\n" + "\n".join(lines)


def compensation_display(status: str) -> str:
    if not status:
        return "compensation: unknown"
    return f"compensation: {status}"


def build_execution_intent(
    *,
    action: str,
    target_profile: str | None,
    plan_id: str,
    plan_hash: str,
    policy_decision: str,
    approval_source: str,
    fingerprint: str = "",
    engine: str = "",
) -> dict[str, Any]:
    """Legacy evidence-shaped intent record.

    .. deprecated:: 0.9.0
        This is the *record* of an approval as it appeared in an evidence
        envelope, not the contract that gates execution. It has no call site in
        mayhem and nothing validates against it, so it cannot refuse anything.
        The gate is :func:`mayhem.domain.execution_intent.require_execution_intent`
        over :class:`mayhem.domain.execution_intent.ExecutionIntent`; the
        run's real intent now travels on the evidence envelope as its
        ``execution_intent`` field, produced by
        :func:`mayhem.infra.evidence.build_evidence`.

        Kept importable for external callers; do not add new ones.
    """
    return {
        "action": action,
        "target_profile": target_profile,
        "plan_id": plan_id,
        "plan_hash": plan_hash,
        "policy_decision": policy_decision,
        "approval_source": approval_source,
        "fingerprint": fingerprint,
        "engine": engine,
    }


def migration_warning() -> str:
    return "warning: implicit execution without --execute is unsafe; use --execute with explicit approval"


def resolve_plan_source(
    *,
    from_plan: str | None,
    plan_id: str | None,
    db: Any = None,
) -> dict[str, Any] | None:
    if from_plan is not None:
        return load_plan_file(from_plan)
    if plan_id is not None and db is not None:
        try:
            rows = db.query("SELECT plan_json FROM runs WHERE id = ?", (plan_id,))
            if rows:
                raw = rows[0]["plan_json"] if isinstance(rows[0], dict) else rows[0][0]
                try:
                    return json.loads(raw) if isinstance(raw, str) else dict(raw)
                except Exception:
                    return {"raw": raw}
        except Exception:
            return None
    return None
