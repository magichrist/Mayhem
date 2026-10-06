"""``mayhem certify`` — the surface that earns and reads live claims (plan 01).

Two commands, and the split between them is the point:

``mayhem certify run FAULT_ID``
    Certify one fault on one cell. Provisions a disposable environment, compiles
    a one-fault drill, executes it, residue-scans the cell, and records what the
    cell said. Mutating: it starts a container and injects a fault into it. It
    therefore requires ``--execute`` *and* honours the ordinary v0.9 execution
    intent contract, so it is gated exactly as ``mayhem run`` is.

``mayhem certify matrix [FAULT_ID]``
    Answer "can this fault run here, and is it certified here?" **without
    executing anything.** Compatibility questions are the common case and must
    never cost a container.

Why this module owns the live-cell path
---------------------------------------
:mod:`mayhem.infra.certification_runner` is where the policy lives, and it may
not import ``mayhem.controller`` — the layering contract forbids it and a
certification pipeline that reached around the controller to talk to executors
directly would be the "side channel" plan 01 rules out. So the runner's cell is
a protocol, and *this* module is the only place that binds it to
:meth:`mayhem.controller.executor.RunEngine.execute`.

The binding is explicit and one-directional:

* :class:`EngineCell` has no execution code at all. It receives a callable and
  calls it.
* :func:`_engine_execute` is the only thing that constructs a
  :class:`~mayhem.controller.executor.RunEngine`, and the only thing it does
  with a plan is ``return engine.execute(plan)``.

A certification therefore acquires leases, honours the approval gate, records
``step_runs``/``fault_invocations``/``recovery_records``, and emits the same
event journal as any other run. There is no second way to certify a fault.

Honesty properties this surface inherits and re-exports
-------------------------------------------------------
* **The certification gate is not optional here.** Every maturity number
  ``certify matrix`` reports is computed with ``records=`` supplied from the
  record store, so an empty store caps every fault at ``verified-unit``. There is
  no mode in which this command reports a live rung it cannot back. The mapping
  is the *sealed* gate, not merely the record store's: every live claim's
  attestation chain is re-verified on read, and one that no longer verifies is
  handed to ``evaluate_maturity`` withdrawn, so a claim whose bundle was deleted
  stops being reported rather than being reported as standing.
* **A claim this command mints is sealed.** ``certify run`` hands
  ``certify_fault`` a
  :class:`~mayhem.controller.certification_evidence.CertificationEvidenceStore`,
  so a claim that reaches a ``certified`` row is one whose bytes can be
  re-verified later with no control plane. The runner's sealer stays *optional*
  for the unit suite and for weaker callers — that is its own contract, not this
  surface's — but on this surface it is passed unconditionally, and a bundle that
  cannot be sealed is a refusal rather than a certification.
* **A refusal is a result.** ``certify run`` on a catalog-only fault exits
  non-zero *and* leaves a record naming the refusal. A certification attempt that
  proves nothing is not a pass, and not a pass must not look like success.
* **The live-verified count is zero until a real runtime says otherwise.** No
  code path here seeds a record, so ``certify matrix`` reports zero on a fresh
  database and the README's 0-of-N stays true (N is the live catalogue size,
  asserted against ``CATALOG`` rather than written down here). Sealing changes
  nothing about that count: a sealed chain still needs a cell that actually ran.

The live path is exercised only by a real container engine
----------------------------------------------------------
Provisioning, in-container residue scanning, and bundle capture are the parts CI
cannot run: they need docker or podman and a disposable container. They are
implemented here rather than stubbed, and they are honest about being untested —
``tests/unit/test_cli_certify.py`` asserts the *shape* of the binding (that the
cell's ``execute`` is ``RunEngine.execute`` and that nothing else in this module
can execute a plan) rather than pretending to have certified anything. Until a
real cell is certified, the README live-verified count must stay 0-of-N, with
N the live catalogue size.

Kubernetes cells are **not** implemented: plan 01 defers them to plan 02, so
``--engine kubernetes`` is refused here with a pointer rather than silently
falling back to a container lane.
"""

from __future__ import annotations

import contextlib
import json
import os
import platform
import shutil
import subprocess
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from mayhem.cli import style
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.controller.certification_evidence import CertificationEvidenceStore
from mayhem.domain.capabilities import Capability
from mayhem.domain.catalog import CATALOG, definition_for
from mayhem.domain.certification import (
    Arch,
    CellPrivilege,
    EvidenceBundleRef,
    MatrixCell,
    expire_by_time,
)
from mayhem.domain.common import utc_now
from mayhem.domain.experiments import DrillContainer, DrillFault, DrillSpec, ExecutionStep
from mayhem.domain.faults import EngineLane
from mayhem.infra.certification_repository import (
    CertificationRepository,
    StoredCertification,
)
from mayhem.infra.certification_runner import (
    CellRequest,
    CertificationRequest,
    CertifiedRun,
    DemotionEvent,
    RecoveryEvidence,
    ResidueFinding,
    ResidueScan,
    certify_fault,
    effective_lanes,
    expected_evidence_digests,
    planned_target_identity,
    requires_recovery_verification,
)
from mayhem.infra.certification_sweep import (
    ReRunVerdict,
    apply_regressions,
    regression_report,
    sweep_certifications,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from mayhem.cli.context import CliContext
    from mayhem.controller.executor import RunResult
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.faults import FaultDefinition
    from mayhem.infra.certification_runner import CertificationAttempt
    from mayhem.infra.store import Store

certify = make_group(
    "certify",
    "Certify faults on live runtime cells and query the certification matrix.",
)

#: The order the plan names for cell provisioning: Docker first, then Podman.
#: Kubernetes is absent on purpose — plan 01 defers Kubernetes cells to plan 02,
#: and a cell that silently fell back to a container lane would certify a claim
#: about a runtime that was never exercised.
CELL_ENGINE_ORDER: tuple[EngineLane, ...] = (EngineLane.DOCKER, EngineLane.PODMAN)

#: The probe name the live cell reports for its recovery signal. The container
#: lanes' compensation contract is a *state* contract — the fault's lease was
#: released and its verify probes confirmed the undo — so the numeric axis below
#: is the normalised distance from that state, not a latency measurement. The
#: real numbers live in the promotion engine's ``Observation`` records. Phase 4
#: upgrades this to a numeric baseline probe.
RECOVERY_PROBE = "lease.released"

#: The in-container residue checks, in the order they are run. Each is a command
#: the *disposable* cell answers about itself; a command that cannot run (the
#: image lacks ``iptables``, say) is recorded as an observation, never as clean.
RESIDUE_CHECKS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("tc_rule", ("tc", "qdisc", "show")),
    ("iptables_entry", ("sh", "-c", "iptables-save 2>/dev/null || true")),
    ("marker_process", ("sh", "-c", "ps -eo args= 2>/dev/null | grep -i mayhem | grep -v grep")),
    ("marker_file", ("sh", "-c", "ls -1 /tmp/mayhem* 2>/dev/null || true")),
    ("cgroup_override", ("sh", "-c", "cat /sys/fs/cgroup/*/mayhem* 2>/dev/null || true")),
)


# ── the live cell ───────────────────────────────────────────────────────────


@dataclass(slots=True)
class EngineCell:
    """A disposable container the attempt runs against.

    Holds no execution code. ``_execute`` is supplied by the caller and is
    :meth:`RunEngine.execute` in production — the whole point of this class is
    that it *cannot* do anything else.
    """

    cell: MatrixCell
    injector_version: str
    _execute: Callable[[ExecutionPlan], RunResult]
    _binary: str
    _container: str
    _store: Store
    _run_id: str = ""
    disposed: bool = False

    def execute(self, plan: ExecutionPlan) -> RunResult:
        """Hand the compiled plan to the normal run path. Nothing else."""
        self._run_id = plan.run_id
        return self._execute(plan)

    def recovery_evidence(self, run: CertifiedRun) -> RecoveryEvidence | None:
        """Read the durable recovery facts the normal path already recorded.

        The compensation contract for a container-lane fault is written ahead of
        the mutation (write-ahead undo ops plus verify probes), so "recovery
        happened" is a fact about the lease: it reached ``released``, and its
        recovery record is marked verified. Reading it back from the store
        rather than assuming it is the difference between evidence and a claim.

        Returns ``None`` when the run left no lease at all — the fault never
        applied, so there is nothing to have recovered, and the runner refuses
        rather than treating "no lease" as "clean recovery".
        """
        del run
        leases = self._store.query(
            "SELECT state, release_mechanism FROM fault_leases WHERE run_id = ?", (self._run_id,)
        )
        if not leases:
            return None
        released = [row for row in leases if str(dict(row)["state"]) == "released"]
        verified = self._store.query(
            "SELECT verified FROM recovery_records WHERE lease_id IN "
            "(SELECT id FROM fault_leases WHERE run_id = ?)",
            (self._run_id,),
        )
        all_verified = bool(verified) and all(int(dict(row)["verified"]) == 1 for row in verified)
        mechanisms = sorted({str(dict(row)["release_mechanism"] or "") for row in released} - {""})
        if not released:
            return None
        del mechanisms
        return RecoveryEvidence(
            probe=RECOVERY_PROBE,
            baseline=0.0,
            observed=0.0 if all_verified else 1.0,
            tolerance=0.0,
            undo_ran=True,
        )

    def residue_scan(self) -> ResidueScan:
        """Ask the disposable container whether anything survived the run."""
        findings: list[ResidueFinding] = []
        for kind, argv in RESIDUE_CHECKS:
            output = self._exec(argv)
            text = output.strip()
            if text:
                findings.append(ResidueFinding(kind=kind, detail=text[:200]))
        return ResidueScan(
            performed=True,
            findings=tuple(findings),
            note="checked inside the disposable container before it was removed",
        )

    def dispose(self) -> None:
        """Remove the disposable container. Idempotent, and never raises."""
        if self.disposed:
            return
        self.disposed = True
        # Best-effort: a container that outlives its cell is an operator problem
        # to notice, not a reason to mask the run's own result.
        with contextlib.suppress(Exception):
            subprocess.run(
                [self._binary, "rm", "-f", self._container],
                capture_output=True,
                check=False,
                timeout=60,
            )

    def _exec(self, argv: Sequence[str]) -> str:
        try:
            done = subprocess.run(
                [self._binary, "exec", self._container, *argv],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        except Exception as exc:
            return f"probe unavailable: {exc}"
        return (done.stdout or "").strip()


def _persist_attempt_evidence(
    store: Store,
    *,
    graph: Any,
    prepared: Any,
    plan: ExecutionPlan,
    result: Any,
    engine: str,
    intent: Any,
) -> None:
    """Write the run's evidence envelope — the artefact ``capture`` later cites.

    ``mayhem run`` writes an envelope after every run, and ``certify run``
    drives the same engine, so the same artefact has to exist on this path too:
    without it :meth:`RunEvidenceCapturer.capture` answers *nothing* to "what
    evidence does this run carry?" and every attempt would be refused
    ``no_evidence`` no matter how clean the cell was — which is exactly what a
    fresh database produced before this line existed, first as a crash (the
    envelope table does not exist until something writes it) and then, once
    readers tolerated its absence, as a permanent refusal.

    Written after the run and before the result is handed back, so the envelope
    is durable by the time ``certify_fault`` reaches the capture step. Failures
    are not raised at the caller: ``_write_evidence_after_run`` already
    degrades the envelope it can describe, and anything it cannot is reported
    the only way this pipeline reports missing evidence — ``capture`` returns
    ``None`` and the attempt is refused with ``no_evidence``. A certification
    with nothing to cite is refused, never certified, so the honest failure
    mode here is a refusal rather than an exception.
    """
    from mayhem.cli.lifecycle import _preflight_for_run, _write_evidence_after_run

    try:
        preflight = _preflight_for_run(
            graph=graph,
            store=store,
            prepared=prepared,
            plan=plan,
            target=None,
            engine=engine,
        )
    except Exception:
        return
    _write_evidence_after_run(
        store=store,
        preflight=preflight,
        result=result,
        engine=engine,
        evidence_dir=None,
        intent=intent,
    )


def _engine_execute(
    store: Store,
    graph: Any,
    prepared: Any,
    engine: str,
) -> Callable[[ExecutionPlan], RunResult]:
    """Bind the cell's ``execute`` to :meth:`RunEngine.execute`.

    The single line ``engine.execute(plan)`` below is the whole reason a
    certification is worth anything. Everything else in this file is
    provisioning, scanning, and reporting.
    """
    from mayhem.cli.app import implicit_execution_allowed
    from mayhem.cli.services import engine_for

    def execute(plan: ExecutionPlan) -> RunResult:
        # ``--execute`` *is* the approval this gate asks for, so mint the
        # intent it stands for, bound to the plan about to run — the same
        # shape ``cli/lifecycle`` mints for ``mayhem run --execute``, with the
        # same ``plan_hash_for`` the gate re-derives. Without this line the
        # live path could never succeed: ``require_intent=True`` and no intent
        # is a refusal by construction, and the only way through would have
        # been the implicit-execution compatibility switch — a certification
        # cell reached by bypassing the intent contract is not a cell this
        # command should be able to produce.
        from mayhem.domain.execution_intent import intent_for_plan

        intent = intent_for_plan(plan, engine=engine, actor="cli:certify --execute")
        runner = engine_for(
            store,
            engine,
            live_graph=lambda: graph,
            recovery_grace=prepared.recovery_grace,
            intent=intent,
            require_intent=True,
            allow_implicit=implicit_execution_allowed(),
        )
        result = runner.execute(plan)
        # The run's own evidence, persisted before the capturer can ask for it
        # — same artefact `mayhem run` writes after every run.
        _persist_attempt_evidence(
            store,
            graph=graph,
            prepared=prepared,
            plan=plan,
            result=result,
            engine=engine,
            intent=intent,
        )
        return result

    return execute


def _detect_cell_request(
    *,
    engine: str | None,
    os_distro: str | None,
    kernel: str | None,
    arch: str | None,
    privilege: str | None,
) -> CellRequest:
    """Resolve the requested cell, probing the host only where nothing was asked.

    An explicit ``--engine``/``--kernel``/… is used verbatim; anything omitted is
    probed, because a certification on a cell nobody named is a claim about "a
    machine somewhere". Probing failures degrade to ``unknown`` and say so in the
    cell label rather than inventing a version.
    """
    return CellRequest(
        engine=EngineLane(engine) if engine else _probe_engine(),
        engine_version=_probe_engine_version(engine),
        os_distro=os_distro or _probe_os_distro(),
        kernel_version=kernel or platform.release() or "unknown",
        arch=Arch(arch) if arch else _probe_arch(),
        privilege=CellPrivilege(privilege) if privilege else _probe_privilege(),
        capabilities=frozenset(),
    )


def _probe_engine() -> EngineLane:
    for lane in CELL_ENGINE_ORDER:
        if shutil.which(lane.value) is not None:
            return lane
    return CELL_ENGINE_ORDER[0]


def _probe_engine_version(engine: str | None) -> str:
    try:
        from mayhem.infra.engine_probe import detect_available_engines

        wanted = engine or _probe_engine().value
        for descriptor in detect_available_engines():
            if descriptor.name == wanted and isinstance(descriptor.version, str):
                return descriptor.version.split()[0] if descriptor.version else "unknown"
    except Exception:
        pass
    return "unknown"


def _probe_os_distro() -> str:
    try:
        with Path("/etc/os-release").open(encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')[:64]
    except OSError:
        pass
    return platform.system().lower() or "unknown"


def _probe_arch() -> Arch:
    machine = platform.machine().lower()
    return Arch.ARM64 if machine in ("arm64", "aarch64") else Arch.AMD64


def _probe_privilege() -> CellPrivilege:
    """Root or rootless, as the invoking user actually is.

    A cell is not rootless because the operator hoped so; the privilege the
    injector gets is the privilege the invoking uid has.
    """
    getter = getattr(os, "geteuid", None)
    return CellPrivilege.ROOT if getter is not None and getter() == 0 else CellPrivilege.ROOTLESS


def _provision(
    request: CertificationRequest,
    *,
    store: Store,
    graph: Any,
    prepared: Any,
    image: str,
) -> EngineCell:
    """Start a disposable container and return the cell bound to the run engine."""
    binary = request.cell.engine.value
    container = f"mayhem-certify-{uuid.uuid4().hex[:12]}"
    argv = [
        binary,
        "run",
        "-d",
        "--rm",
        "--name",
        container,
        "--label",
        "mayhem.certification=disposable",
        image,
        "sleep",
        "3600",
    ]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=180)
    except Exception as exc:
        raise click.ClickException(f"could not provision a {binary} cell: {exc}") from None
    if done.returncode != 0:
        raise click.ClickException(
            f"could not provision a {binary} cell from {image!r}: "
            f"{(done.stderr or done.stdout or '').strip()[:300]}"
        )
    return EngineCell(
        cell=request.cell.as_matrix_cell(),
        injector_version=prepared.fingerprint,
        _execute=_engine_execute(store, graph, prepared, binary),
        _binary=binary,
        _container=container,
        _store=store,
    )


# ── evidence capture ────────────────────────────────────────────────────────


@dataclass(slots=True)
class RunEvidenceCapturer:
    """Builds the sealed bundle a certification cites, from the *store*.

    The digests are computed from what the durable artifacts say, not from the
    in-memory run the runner is holding. That is deliberate: the runner derives
    the same digests from the plan, the step report, the recovery probe, and the
    residue scan, so the two agreeing is corroboration and disagreeing is a
    finding — the bundle on disk would then describe a different run, and
    :func:`mayhem.infra.certification_runner.certify_fault` refuses.
    """

    store: Store
    out_dir: Path | None = None
    mayhem_version: str = "0.0.0"

    def capture(
        self,
        run: CertifiedRun,
        *,
        request: CertificationRequest,
        cell: MatrixCell,
        plan: ExecutionPlan,
        residue: ResidueScan,
        recovery: RecoveryEvidence | None,
        demotions: tuple[DemotionEvent, ...] = (),
    ) -> EvidenceBundleRef | None:
        from mayhem.domain.evidence_bundle import build_bundle
        from mayhem.infra.evidence import load_evidence

        envelope = load_evidence(self.store, run.run_id)
        if envelope is None:
            return None
        stored_plan = self.store.query("SELECT plan_json FROM runs WHERE id = ?", (run.run_id,))
        if not stored_plan:
            # The executor writes the plan into `runs`; `m5_runs` has no writer
            # on this path (its legacy `save_run_record` has no callers), so
            # reading it made every capture a silent `no evidence` — a refusal
            # that looked like the run's fault rather than a query's.
            return None
        facts = json.loads(str(dict(stored_plan[0])["plan_json"]))
        digests = expected_evidence_digests(
            params=_stored_params(facts, request.fault_id),
            target=_stored_target(facts, request.fault_id),
            observed_effect=f"{_declared_effect(request.fault_id)}|"
            f"observed={_step_detail(run, plan, request.fault_id)}",
            recovery=recovery,
            residue=residue,
            demotions=demotions,
            compensated=not run.dirty_leases,
        )
        bundle = build_bundle(
            evidence=envelope.model_dump(mode="json"),
            observations={"certification": {"cell": cell.fingerprint, "digests": digests}},
            created_at=utc_now().isoformat(),
        )
        target = None
        if self.out_dir is not None:
            from mayhem.infra.evidence_bundle_io import write_bundle

            self.out_dir.mkdir(parents=True, exist_ok=True)
            target = write_bundle(bundle, self.out_dir / run.run_id)
        return EvidenceBundleRef(
            bundle_hash=bundle.manifest.root_digest,
            mayhem_version=self.mayhem_version,
            digests=digests,
            bundle_path=None if target is None else str(target),
        )


def _stored_params(facts: Mapping[str, Any], fault_id: str) -> dict[str, object]:
    for step in facts.get("steps", []):
        fault = step.get("fault") or {}
        if fault.get("fault_id") == fault_id:
            return dict(fault.get("params") or {})
    return {}


def _stored_target(facts: Mapping[str, Any], fault_id: str) -> str:
    for step in facts.get("steps", []):
        fault = step.get("fault") or {}
        if fault.get("fault_id") != fault_id:
            continue
        target = fault.get("target")
        if target:
            return planned_target_identity(_ScopeView(target))
        return ",".join(
            sorted(
                ",".join(sorted(entry.get("node_ids", ()))) for entry in fault.get("targets") or []
            )
        )
    return ""


class _ScopeView:
    """Adapts a serialised ``TargetScope`` back to the two fields the digest reads.

    The stored plan is JSON, so its target is a dict rather than a model. This
    lets :func:`planned_target_identity` stay the single definition of "what a
    target's identity is" instead of being re-implemented for the stored form.
    """

    __slots__ = ("logical_id", "runtime")

    def __init__(self, payload: Mapping[str, Any]) -> None:
        self.runtime = payload.get("runtime")
        self.logical_id = payload.get("logical_id", "")

    def __str__(self) -> str:
        return f"{self.runtime}/{self.logical_id}"


def _step_detail(run: CertifiedRun, plan: ExecutionPlan, fault_id: str) -> str:
    for step in plan.steps:
        if step.fault is None or step.fault.fault_id != fault_id:
            continue
        for report in run.steps:
            if report.step_id == step.id:
                return report.detail
    return ""


def _declared_effect(fault_id: str) -> str:
    return definition_for(fault_id).observable_effect


# ── compatibility queries ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CellQuery:
    """A compatibility question, asked without executing anything."""

    engine: EngineLane
    arch: Arch
    privilege: CellPrivilege
    kernel_version: str
    os_distro: str
    capabilities: frozenset[Capability] | None
    engine_version: str = "unknown"

    def as_matrix_cell(self) -> MatrixCell:
        return MatrixCell(
            engine=self.engine,
            engine_version=self.engine_version,
            os_distro=self.os_distro,
            kernel_version=self.kernel_version,
            arch=self.arch,
            privilege=self.privilege,
            capabilities=self.capabilities or frozenset(),
        )

    @property
    def fully_specified(self) -> bool:
        """True when every dimension the query can name was named.

        The engine *version* is deliberately not required: a compatibility
        question names a runtime family, not a build, and a stored claim's
        version is part of what the reader is asking about. The dimensions that
        must be supplied are the ones that would otherwise make the answer a
        guess: the kernel, the distribution, and the cell's capabilities.
        """
        return (
            self.capabilities is not None
            and self.kernel_version != "unknown"
            and self.os_distro != "unknown"
        )

    def matches(self, cell: MatrixCell) -> bool:
        """Does ``cell`` answer to this query, on every dimension both name?

        Compared field by field rather than by fingerprint, because the query
        deliberately does not pin the engine version: a claim certified on
        podman 5.3.1 is on the cell this query describes, and pretending
        otherwise would report a real claim as a different cell's.
        """
        if cell.engine is not self.engine or cell.arch is not self.arch:
            return False
        if cell.privilege is not self.privilege:
            return False
        if self.kernel_version not in ("unknown", cell.kernel_version):
            return False
        if self.os_distro not in ("unknown", cell.os_distro):
            return False
        return self.capabilities is None or self.capabilities == cell.capabilities


def _compatibility(
    definition: FaultDefinition,
    query: CellQuery,
) -> dict[str, Any]:
    """Can ``definition`` run on the queried cell? No execution, no provision."""
    reasons: list[str] = []
    lanes = effective_lanes(definition)
    engine_ok = not lanes or query.engine in lanes
    if not engine_ok:
        reasons.append(
            f"{definition.id} declares lanes "
            f"{', '.join(sorted(lane.value for lane in lanes))}; this cell is "
            f"{query.engine.value}"
        )
    missing: list[str] = []
    capability_state = "unknown"
    if query.capabilities is None:
        reasons.append(
            "the cell's capabilities were not supplied, so the capability requirement "
            f"({', '.join(sorted(cap.value for cap in definition.required_caps)) or 'none'}) "
            "cannot be checked without executing something"
        )
    else:
        capability_state = "known"
        missing = sorted(cap.value for cap in definition.required_caps - query.capabilities)
        if missing:
            reasons.append(
                f"the cell does not advertise {', '.join(missing)}, which {definition.id} requires"
            )
    if definition.catalog_only:
        reasons.append(
            f"{definition.id} is catalog-only and refuses to execute anywhere: "
            f"{definition.refusal_reason or 'no refusal reason recorded'}"
        )
    return {
        "allowed": not reasons,
        "engine_lane": "ok" if engine_ok else "unsupported",
        "capability_state": capability_state,
        "missing_capabilities": missing,
        "reasons": reasons,
    }


def _certification_state(
    definition: FaultDefinition,
    query: CellQuery,
    records: Mapping[str, Sequence[Any]],
    now: datetime,
) -> dict[str, Any]:
    """What the record store says about this fault, on this cell and any cell."""
    from mayhem.domain.certification import expire_by_time

    aged = [expire_by_time(record, now=now) for record in records.get(definition.id, ())]
    live = [record for record in aged if record.grants_live_verification]
    on_cell = [record for record in live if query.matches(record.cell)]
    return {
        "records": len(aged),
        "live": bool(live),
        "on_queried_cell": bool(on_cell) if query.fully_specified else None,
        "cells": [
            {
                "cell": record.cell.label,
                "engine": record.cell.engine.value,
                "fingerprint": record.cell.fingerprint,
                "state": record.state.value,
                "expires_at": record.expires_at.isoformat(),
                "injector_version": record.injector_version,
                "outcome": record.outcome,
                "reason": record.reason,
                "evidence": [ref.bundle_hash for ref in record.evidence],
            }
            for record in aged
        ],
    }


def _render_matrix(payload: Mapping[str, Any]) -> str:
    query = payload["query"]
    lines = [
        style.cyan("certification matrix"),
        f"  query: engine={query['engine']} arch={query['arch']} "
        f"privilege={query['privilege']} kernel={query['kernel_version']} "
        f"os={query['os_distro']}",
        f"  capabilities: {'supplied' if query['capabilities'] else 'not supplied'}",
        f"  certified faults: {payload['certified_faults']} of {payload['faults_total']}",
    ]
    for row in payload["faults"]:
        mark = "yes" if row["compatibility"]["allowed"] else "no "
        lines.append(
            f"  [{mark}] {row['fault_id']:<32} live={row['certification']['live']!s:<5} "
            f"maturity={row['maturity']['maturity']}"
        )
        for reason in row["compatibility"]["reasons"]:
            lines.append(f"        - {reason}")
        for refusal in row["maturity"]["refusals"]:
            lines.append(f"        - {refusal}")
    return "\n".join(lines)


# ── commands ────────────────────────────────────────────────────────────────


@certify.command("run")
@click.argument("fault_id")
@click.option("--compose", default=None, help="docker-compose.yaml to build the cell's topology.")
@click.option("--container", default="", help="Compose service the fault targets.")
@click.option("--target", default="", help="Target override passed to the planner.")
@click.option(
    "--param",
    "params",
    multiple=True,
    help="Fault parameter as key=value (repeatable).",
)
@click.option("--engine", default=None, help="Cell engine: docker or podman.")
@click.option("--image", default="alpine:3.20", show_default=True, help="Disposable cell image.")
@click.option("--duration", default=5.0, show_default=True, help="Seconds to hold the fault.")
@click.option("--seed", default=None, type=int, help="Seed for the compiled plan.")
@click.option("--ttl-days", default=30.0, show_default=True, help="Days the claim stays valid.")
@click.option("--kernel", default=None, help="Kernel version of the cell (probed when omitted).")
@click.option("--os-distro", default=None, help="OS distribution of the cell.")
@click.option("--arch", default=None, help="Cell architecture: amd64 or arm64.")
@click.option("--privilege", default=None, help="Cell privilege mode: root or rootless.")
@click.option(
    "--bundle-out",
    default=None,
    type=click.Path(),
    help="Directory the sealed evidence bundle is written to.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option(
    "--execute",
    is_flag=True,
    help="Required. Provisions a container and injects the fault into it.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress human output.")
@click.pass_context
def certify_run(
    ctx: click.Context,
    fault_id: str,
    compose: str | None,
    container: str,
    target: str,
    params: tuple[str, ...],
    engine: str | None,
    image: str,
    duration: float,
    seed: int | None,
    ttl_days: float,
    kernel: str | None,
    os_distro: str | None,
    arch: str | None,
    privilege: str | None,
    bundle_out: str | None,
    db_opt: str | None,
    execute: bool,
    as_json: bool,
    quiet: bool,
) -> None:
    """Certify one fault on one live cell. Requires --execute."""
    cli_ctx: CliContext = ctx.obj
    if engine == EngineLane.KUBERNETES.value:
        click.echo(
            "kubernetes certification cells are not implemented yet: plan 01 defers them to "
            "plan 02. Use --engine docker or --engine podman.",
            err=True,
        )
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
    try:
        definition = definition_for(fault_id)
    except LookupError as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    cell_request = _detect_cell_request(
        engine=engine, os_distro=os_distro, kernel=kernel, arch=arch, privilege=privilege
    )
    request = CertificationRequest(
        fault_id=fault_id,
        cell=cell_request,
        params=_parse_params(params),
        target=target,
        duration_s=duration,
        seed=seed,
        ttl=timedelta(days=ttl_days),
        injector_version=cell_request.engine_version,
        mayhem_version=_mayhem_version(),
    )

    if not execute:
        # Refused before anything is provisioned: no container, no run, no record.
        # The refusal is reported, not stored, because nothing was attempted.
        planned = {
            "fault_id": definition.id,
            "cell": cell_request.as_matrix_cell().label,
            "engine": cell_request.engine.value,
            "would_execute": True,
            "requires": "--execute provisions a disposable container and injects the fault",
            "catalog_only": definition.catalog_only,
            "refusal_reason": definition.refusal_reason or "",
        }
        if as_json:
            click.echo(json.dumps(planned, indent=2, sort_keys=True))
        else:
            click.echo(
                f"refused: {definition.id} on {cell_request.as_matrix_cell().label} was not "
                "attempted. --execute provisions a disposable container and injects the fault."
            )
        ctx.exit(int(ExitCode.SAFETY_REFUSAL))

    attempt = _execute_certification(
        ctx,
        request,
        compose=compose,
        container=container,
        image=image,
        bundle_out=bundle_out,
        db=db_opt or cli_ctx.db,
    )

    _emit_attempt(attempt, as_json=as_json, quiet=quiet)
    ctx.exit(int(ExitCode.SUCCESS) if attempt.certified else int(ExitCode.EXPERIMENT_FAILURE))


def _execute_certification(
    ctx: click.Context,
    request: CertificationRequest,
    *,
    compose: str | None,
    container: str | None,
    image: str,
    bundle_out: str | None,
    db: str,
) -> CertificationAttempt:
    """Run one certification attempt end to end, and return what it concluded.

    Extracted rather than copied, and that is the whole point of the exercise:
    a regression re-run (``mayhem certify regress --rerun``) has to execute
    through *the same* path that minted the claim it is testing, or "the re-run
    reproduced it" is a statement about a different pipeline. One function, two
    callers, and the cell is still provisioned and disposed exactly once.

    The sealer is not optional here either, for the reason ``certify run``
    documents: a re-run that appended an unsealed claim would be a second way
    to mint a live claim with nothing attesting it.
    """
    from mayhem.cli.lifecycle import _graph_from
    from mayhem.cli.services import open_store, prepare
    from mayhem.controller.planner import plan_drill

    cli_ctx: CliContext = ctx.obj
    graph, resolved_compose = _graph_from(ctx, compose)
    # After the graph: the fallback target is chosen against the topology that
    # will actually be planned against, not against the compose file alone.
    service = container or _first_container(ctx, compose, graph=graph)
    store = open_store(db)
    try:
        prepared = prepare(
            config_path=cli_ctx.config,
            profile=cli_ctx.profile,
            policy=cli_ctx.policy,
            allow_critical=cli_ctx.allow_critical,
            store=store,
            graph=graph,
            compose=resolved_compose,
        )
        run_id = f"r-certify-{uuid.uuid4().hex[:8]}"

        def compile_plan(cert_request: CertificationRequest) -> ExecutionPlan:
            return plan_drill(
                run_id,
                _single_fault_spec(cert_request.fault_id, service, cert_request),
                graph,
                config_snapshot_id=prepared.config_snapshot_id,
                topology_snapshot_id=prepared.topology_snapshot_id,
                environment_fingerprint=prepared.fingerprint,
                policy_id=cli_ctx.policy or "default",
                engine=cert_request.cell.engine.value,
            )

        cell = _provision(request, store=store, graph=graph, prepared=prepared, image=image)
        try:
            capturer = RunEvidenceCapturer(
                store=store,
                out_dir=None if bundle_out is None else Path(bundle_out),
                mayhem_version=_mayhem_version(),
            )
            repository = CertificationRepository(store)
            return certify_fault(
                request,
                provisioner=_StaticProvisioner(cell),
                compile_plan=compile_plan,
                capture=capturer,
                sink=repository,
                now=utc_now(),
                # Phase 5 plumbing. Phase 4 made the sealer optional so the
                # pre-Phase-4 surface kept working, and named this call site as the
                # place it belongs. On *this* surface it is not optional: a claim
                # that reaches a stored `certified` row is a claim whose bytes can be
                # re-verified later, and a claim whose bundle cannot be sealed is a
                # refusal. Leaving it off here would have meant this command was the
                # one way to mint a live claim with nothing attesting it.
                evidence_sealer=CertificationEvidenceStore(store, repository=repository),
            )
        finally:
            # `_provision` starts the container *outside* `certify_fault`'s own
            # try/finally, and `certify_fault` compiles the plan before it takes
            # ownership of the cell — so a planning refusal (a target the
            # topology does not know, seen live on `certify regress --rerun`)
            # raised a running disposable cell with nobody left to dispose it.
            # `EngineCell.dispose` is idempotent: the runner's disposal stays
            # the normal path and this is the backstop that makes "disposable"
            # true on every path, including the ones that never reach the runner.
            cell.dispose()
    finally:
        store.close()


@dataclass(slots=True)
class _StaticProvisioner:
    """Adapts one already-provisioned cell to the runner's provisioner protocol.

    The cell is built before the attempt so its identity (which engine, which
    image, which topology) is part of the request the runner sees; the runner
    still disposes it, so the lifecycle has exactly one owner.
    """

    cell: EngineCell
    requested: int = 0

    def provision(self, request: CertificationRequest) -> EngineCell:
        del request
        self.requested += 1
        return self.cell


@certify.command("matrix")
@click.argument("fault_id", required=False)
@click.option("--engine", default=None, help="Cell engine to answer about.")
@click.option("--kernel", default=None, help="Kernel version of the cell to answer about.")
@click.option("--os-distro", default=None, help="OS distribution of the cell.")
@click.option("--arch", default=None, help="Cell architecture: amd64 or arm64.")
@click.option("--privilege", default=None, help="Cell privilege mode: root or rootless.")
@click.option(
    "--capability",
    "capabilities",
    multiple=True,
    type=click.Choice([*sorted(cap.value for cap in Capability)]),
    help="Capability the cell advertises (repeatable). Omit to leave capabilities unknown.",
)
@click.option("--all", "show_all", is_flag=True, help="Report every catalog fault.")
@click.option(
    "--sweep",
    "sweep_now",
    is_flag=True,
    help=(
        "Persist expiry and drift transitions before reporting. Ages every stored "
        "record against the wall clock and withdraws claims whose cell no longer "
        "describes the runtime."
    ),
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress human output.")
@click.pass_context
def certify_matrix(
    ctx: click.Context,
    fault_id: str | None,
    engine: str | None,
    kernel: str | None,
    os_distro: str | None,
    arch: str | None,
    privilege: str | None,
    capabilities: tuple[str, ...],
    show_all: bool,
    sweep_now: bool,
    db_opt: str | None,
    as_json: bool,
    quiet: bool,
) -> None:
    """Show a fault's certification matrix, or answer one compatibility question.

    Executes nothing. Every reported maturity is computed with the certification
    record store supplied, so a fault with no live claim cannot be shown above
    ``verified-unit`` here.

    ``--sweep`` is the one exception, and it is opt-in: it persists ageing and
    drift transitions, and still executes no fault. Without it this command is
    a pure read and the report is not allowed to change what it reports on.
    """
    cli_ctx: CliContext = ctx.obj
    definitions: list[FaultDefinition]
    if fault_id:
        try:
            definitions = [definition_for(fault_id)]
        except LookupError as exc:
            click.echo(f"error: {exc}", err=True)
            ctx.exit(int(ExitCode.VALIDATION_ERROR))
    elif show_all:
        definitions = list(CATALOG)
    else:
        click.echo("error: pass a FAULT_ID, or --all to report the whole catalog", err=True)
        ctx.exit(int(ExitCode.USAGE_ERROR))

    query = CellQuery(
        engine=EngineLane(engine) if engine else _probe_engine(),
        arch=Arch(arch) if arch else _probe_arch(),
        privilege=CellPrivilege(privilege) if privilege else _probe_privilege(),
        kernel_version=kernel or "unknown",
        os_distro=os_distro or "unknown",
        capabilities=frozenset(Capability(value) for value in capabilities)
        if capabilities
        else None,
    )

    now = utc_now()
    store = _open_store(db_opt or cli_ctx.db)
    sweep: dict[str, object] = {"performed": False}
    try:
        repository = CertificationRepository(store)
        evidence = CertificationEvidenceStore(store, repository=repository)
        if sweep_now:
            # The only mutation this command performs, and only when asked for.
            # It is not on by default: `certify matrix` is a read, and a command
            # that quietly demoted claims while rendering a table would be a
            # command whose report changed the thing it reports on.
            result = sweep_certifications(
                repository,
                now=now,
                current_cells=None,
            )
            sweep = {"performed": True, **result.to_dict()}
        # THE GATE. An empty store returns an empty *mapping*, which is the
        # assertion that nothing is certified — and that caps every fault at
        # verified-unit. `records=None` would preserve 1.0.0 behaviour and let a
        # live rung be reported off run evidence alone; this surface never
        # passes it.
        #
        # Phase 5 switched this from `certification_gate` to
        # `sealed_certification_gate`, which is a drop-in for it: same shape,
        # same arming point, plus it re-verifies every live claim's sealed chain
        # and hands on the unverifiable one in the `failed` state. Until Phase 5
        # the stricter gate existed and nothing used it, so the matrix would
        # report a claim whose bundle had been deleted as though it were still
        # standing.
        records = evidence.gate(now=now)
        rows = [_row(definition, query, records, now=now) for definition in definitions]
    finally:
        store.close()

    payload = {
        "query": {
            "engine": query.engine.value,
            "arch": query.arch.value,
            "privilege": query.privilege.value,
            "kernel_version": query.kernel_version,
            "os_distro": query.os_distro,
            "capabilities": sorted(cap.value for cap in (query.capabilities or ())),
            "fully_specified": query.fully_specified,
        },
        "certified_faults": sum(1 for row in rows if row["certification"]["live"]),
        "faults_total": len(rows),
        "certification_gate": "armed: every reported maturity consulted the record store",
        "sealed_evidence_gate": (
            "armed: every live claim's sealed chain was re-verified; an unverifiable "
            "claim is reported in the failed state and grants nothing"
        ),
        "expiry_sweep": sweep,
        "faults": rows,
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
    elif not quiet:
        click.echo(_render_matrix(payload))
    ctx.exit(int(ExitCode.SUCCESS))


# ── regression blocking (plan 01 Phase 5) ─────────────────────────────────────

#: The schema tag on a verdicts file. A file without it is refused rather than
#: parsed, because a JSON object with a ``verdicts`` key is not a certification
#: verdict — it is whatever else happens to have one.
VERDICTS_SCHEMA = "mayhem.certification-verdicts/1"


#: Carried in the output whenever every considered claim landed in ``unreached``,
#: because "nothing regressed" and "nothing was tested" are different findings
#: and a gate that renders them identically teaches people to trust a green it
#: did not earn.
_NOTHING_TESTED = (
    "every live claim was unreached: no verdict names the cell a claim was "
    "recorded on, so this report does not say the catalogue stayed green -- it "
    "says nothing was tested"
)


def _verdict_from_attempt(attempt: CertificationAttempt) -> ReRunVerdict:
    """Turn one re-run into the verdict the regression gate compares with.

    The detail is the attempt's own words — its refusals, or the reason on the
    record it wrote — so the line that fails a build says what the cell said
    rather than a summary written afterwards.
    """
    detail = "; ".join(attempt.refusals) or attempt.record.reason or attempt.verdict
    return ReRunVerdict(
        fault_id=attempt.fault_id,
        certified=attempt.certified,
        cell=attempt.cell,
        detail=detail,
    )


def _verdict_to_dict(verdict: ReRunVerdict) -> dict[str, Any]:
    return {
        "fault_id": verdict.fault_id,
        "certified": verdict.certified,
        "cell": None if verdict.cell is None else verdict.cell.model_dump(mode="json"),
        "detail": verdict.detail,
    }


def _verdict_from_dict(payload: Mapping[str, Any]) -> ReRunVerdict:
    """Rebuild a verdict from a file, keeping "which cell" honest.

    A verdict with no cell is a verdict about *somewhere*, and the gate's own
    vocabulary already has a word for that: ``unreached``. It is not a pass. So a
    file that omits the cell is read, reported as unreached, and never used to
    fail a claim either.
    """
    raw_cell = payload.get("cell")
    cell = MatrixCell.model_validate(raw_cell) if isinstance(raw_cell, Mapping) else None
    return ReRunVerdict(
        fault_id=str(payload.get("fault_id", "")),
        certified=bool(payload.get("certified", False)),
        cell=cell,
        detail=str(payload.get("detail", "")),
    )


@certify.command("regress")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option(
    "--fault-id",
    "fault_ids",
    multiple=True,
    metavar="FAULT_ID",
    help="Restrict the gate to these faults (repeatable). Omit to gate every live claim.",
)
@click.option(
    "--rerun",
    "do_rerun",
    is_flag=True,
    help=(
        "Re-run every live claim through `certify run`'s own execution path, on "
        "the cell the claim was recorded on. Provisions a container per claim."
    ),
)
@click.option(
    "--verdicts",
    "verdicts_in",
    default=None,
    type=click.Path(),
    help="Read re-run verdicts from a JSON file instead of running anything.",
)
@click.option(
    "--verdicts-out",
    "verdicts_out",
    default=None,
    type=click.Path(),
    help="Write the verdicts this run produced here, for a later --verdicts gate.",
)
@click.option(
    "--withdraw",
    "do_withdraw",
    is_flag=True,
    help=(
        "Persist the demotion of every claim the gate found regressed, through "
        "`mark_failed`. Off by default: a report that changes what it reports on "
        "should have to be asked to."
    ),
)
@click.option("--compose", default=None, help="Compose file for the target graph.")
@click.option("--target", default="", help="Container/service target inside the cell.")
@click.option("--image", default="ghcr.io/mayhem/fault-lab:latest", help="Cell image.")
@click.option("--duration", default=5.0, type=float, help="Seconds to sustain the fault.")
@click.option("--seed", default=None, type=int, help="Fault seed for a repeatable re-run.")
@click.option("--ttl-days", default=90.0, type=float, help="Validity of the re-run's record.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress human output.")
@click.pass_context
def certify_regress(
    ctx: click.Context,
    db_opt: str | None,
    fault_ids: tuple[str, ...],
    do_rerun: bool,
    verdicts_in: str | None,
    verdicts_out: str | None,
    do_withdraw: bool,
    compose: str | None,
    target: str,
    image: str,
    duration: float,
    seed: int | None,
    ttl_days: float,
    as_json: bool,
    quiet: bool,
) -> None:
    """Fail when a previously certified fault went red. This is the CI gate.

    ``regression_report`` decides, and this command is the part that makes the
    verdict reach a build: it exits non-zero when
    :attr:`~mayhem.infra.certification_sweep.RegressionReport.blocked` is true,
    so a pipeline running it fails on a regression rather than on a human
    reading a table.

    Two properties are load-bearing and neither is a convenience:

    * **Verdicts must come from somewhere.** ``--rerun`` produces them by
      executing each live claim through ``certify run``'s own path;
      ``--verdicts`` reads them from a matrix job's file. With live claims and
      neither, this exits a usage error — because a gate that compared the last
      run against itself is a gate that proves nothing and says nothing.
    * **A verdict for the wrong cell is not a pass.** ``unreached`` is reported
      as unreached. A fault nobody re-ran is neither green nor red, and the
      count of claims considered is carried in the output so a reader can tell
      the difference between "nothing regressed" and "nothing was tested".
    """
    cli_ctx: CliContext = ctx.obj
    if do_rerun and verdicts_in:
        click.echo(
            "error: pass either --rerun or --verdicts, not both. --rerun executes; "
            "--verdicts reads. Running and reading at once would compare a claim "
            "against a verdict from a different run of the same fault.",
            err=True,
        )
        ctx.exit(int(ExitCode.USAGE_ERROR))

    now = utc_now()
    store = _open_store(db_opt or cli_ctx.db)
    try:
        repository = CertificationRepository(store)
        claims = _live_claims(repository, now=now, fault_ids=fault_ids)
        if fault_ids and not claims:
            # A named filter that selected nothing has gated nothing, and a gate
            # that reports success over an empty selection is how a typo in a
            # pipeline keeps a regression from ever being looked at.
            click.echo(
                f"error: --fault-id matched no live claim ({', '.join(sorted(fault_ids))}). "
                "Refusing to report a green gate over an empty selection: either the "
                "fault was never certified here, or it is not certified on this cell, "
                "or its claim has already lapsed. `mayhem certify matrix FAULT_ID` says "
                "which.",
                err=True,
            )
            ctx.exit(int(ExitCode.USAGE_ERROR))
        if claims and not do_rerun and verdicts_in is None:
            click.echo(
                f"error: {len(claims)} live claim(s) to gate and no verdicts. Pass "
                "--rerun to re-run them, or --verdicts PATH to read a matrix job's "
                "results. Without either this command would compare the stored claims "
                "against nothing.",
                err=True,
            )
            ctx.exit(int(ExitCode.USAGE_ERROR))

        verdicts, source = _verdicts_for(
            ctx,
            claims,
            rerun=do_rerun,
            verdicts_in=verdicts_in,
            compose=compose,
            target=target,
            image=image,
            duration=duration,
            seed=seed,
            ttl_days=ttl_days,
            db=db_opt or cli_ctx.db,
            quiet=quiet,
        )

        if verdicts_out is not None:
            # Written even when it is empty. A caller that asked for the file
            # gets a file: a matrix job that finds no verdicts then has an
            # artefact saying so, instead of a missing path it has to guess about.
            Path(verdicts_out).write_text(
                json.dumps(
                    {
                        "schema": VERDICTS_SCHEMA,
                        "generated_at": now.isoformat(),
                        "source": source,
                        "verdicts": [_verdict_to_dict(v) for v in verdicts.values()],
                    },
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

        report = regression_report(repository, verdicts, now=now)
        # Withdraw BEFORE reporting, so a claim cannot outlive a gate that named
        # it. `apply_regressions` is the only writer here and it goes through
        # `mark_failed`, so the row keeps its sequence and gains a reason.
        withdrawn = apply_regressions(repository, report, now=now) if do_withdraw else ()
    finally:
        store.close()

    payload = {
        **report.to_dict(),
        "verdicts_source": source,
        "verdicts_read": len(verdicts),
        "claims_gated": len(claims),
        "fault_filter": sorted(fault_ids),
        "withdrawn": [row.record.label for row in withdrawn],
        "withdraw_requested": do_withdraw,
        "nothing_tested": _NOTHING_TESTED
        if report.claims_considered and len(report.unreached) == report.claims_considered
        else "",
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
    elif not quiet:
        click.echo(f"regression gate ({report.rule}): {source}")
        click.echo(
            f"  {report.claims_considered} live claim(s) considered, "
            f"{len(verdicts)} verdict(s) read"
        )
        for fault_id in report.unreached:
            click.echo(f"  unreached: {fault_id} (no re-run on the cell it was recorded on)")
        for claim in report.regressed:
            click.echo(f"  regressed: {claim.reason}")
        if payload["nothing_tested"]:
            click.echo(f"  {payload['nothing_tested']}")
        if not report.blocked:
            click.echo("  no previously certified fault went red")
    ctx.exit(int(ExitCode.EXPERIMENT_FAILURE) if report.blocked else int(ExitCode.SUCCESS))


def _verdicts_for(
    ctx: click.Context,
    claims: tuple[StoredCertification, ...],
    *,
    rerun: bool,
    verdicts_in: str | None,
    compose: str | None,
    target: str,
    image: str,
    duration: float,
    seed: int | None,
    ttl_days: float,
    db: str,
    quiet: bool,
) -> tuple[dict[str, ReRunVerdict], str]:
    """The verdicts this gate compares with, and a sentence saying where from.

    The source string is part of the output rather than a log line, because a
    gate whose report does not say whether it executed anything is the failure
    this whole command exists to end.
    """
    if rerun:
        verdicts = _rerun_claims(
            ctx,
            claims,
            compose=compose,
            target=target,
            image=image,
            duration=duration,
            seed=seed,
            ttl_days=ttl_days,
            db=db,
            quiet=quiet,
        )
        return verdicts, "rerun: executed through `certify run`'s own path"
    if verdicts_in is None:
        return {}, "none: there is nothing to compare"
    try:
        return _read_verdicts(verdicts_in)
    except _VerdictsFileError:
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
        raise  # unreachable: ctx.exit raises. Kept so the type is not a lie.


def _live_claims(
    repository: CertificationRepository,
    *,
    now: datetime,
    fault_ids: tuple[str, ...],
) -> tuple[StoredCertification, ...]:
    """Every stored row still granting live verification, newest per fault/cell.

    The same expiry the rest of the surface reads through: a claim the clock has
    already expired is not gated, because withdrawing it is not a regression —
    ageing is what the sweep is for, and a gate that reported it as one would
    train people to ignore the gate.
    """
    wanted = set(fault_ids)
    live: dict[tuple[str, str], StoredCertification] = {}
    for stored in repository.all():
        if wanted and stored.record.fault_id not in wanted:
            continue
        record = expire_by_time(stored.record, now=now)
        if record.grants_live_verification:
            live[(record.fault_id, record.cell.fingerprint)] = stored
    return tuple(live[key] for key in sorted(live))


def _rerun_claims(
    ctx: click.Context,
    claims: tuple[StoredCertification, ...],
    *,
    compose: str | None,
    target: str,
    image: str,
    duration: float,
    seed: int | None,
    ttl_days: float,
    db: str,
    quiet: bool,
) -> dict[str, ReRunVerdict]:
    """Execute every live claim again, on the cell it was recorded on.

    The cell comes from the stored record, never from a probe of the current
    host: a verdict from a different cell has not tested the claim, and the
    report would file it as ``unreached`` — the gate would then be green over a
    claim it never looked at, which is the exact failure mode the sweep module
    exists to prevent.

    Parameters are the catalog defaults, as ``certify run`` uses when none are
    given, because a certification record does not store the parameters it was
    minted with. That is a real limit of the record, stated rather than papered
    over: a fault whose certification depended on a non-default parameter is
    re-run with defaults, and if the defaults do not reproduce it, the gate will
    report a regression. The honest fix belongs in the record, not here.
    """
    verdicts: dict[str, ReRunVerdict] = {}
    for stored in claims:
        cell = stored.record.cell
        request = CertificationRequest(
            fault_id=stored.record.fault_id,
            cell=CellRequest(
                engine=cell.engine,
                engine_version=cell.engine_version,
                os_distro=cell.os_distro,
                kernel_version=cell.kernel_version,
                arch=cell.arch,
                privilege=cell.privilege,
                capabilities=frozenset(cell.capabilities),
            ),
            target=target,
            duration_s=duration,
            seed=seed,
            ttl=timedelta(days=ttl_days),
            injector_version=cell.engine_version,
            mayhem_version=_mayhem_version(),
        )
        attempt = _execute_certification(
            ctx,
            request,
            compose=compose,
            container=None,
            image=image,
            bundle_out=None,
            db=db,
        )
        verdict = _verdict_from_attempt(attempt)
        verdicts[verdict.fault_id] = verdict
        if not quiet:
            click.echo(
                f"  re-ran {verdict.fault_id} on {cell.label}: "
                f"{'reproduced' if verdict.certified else 'did not reproduce'}"
            )
    return verdicts


def _read_verdicts(path: str) -> tuple[dict[str, ReRunVerdict], str]:
    """Load a verdicts file written by ``--verdicts-out`` or by a matrix job."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or raw.get("schema") != VERDICTS_SCHEMA:
        click.echo(
            f"error: {path} is not a certification verdicts file "
            f'(expected "schema": "{VERDICTS_SCHEMA}"). mayhem refuses to read a '
            "regression verdict out of a file it does not recognise.",
            err=True,
        )
        raise _VerdictsFileError
    entries = raw.get("verdicts")
    if not isinstance(entries, list):
        raise _VerdictsFileError
    verdicts = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise _VerdictsFileError
        verdict = _verdict_from_dict(entry)
        if verdict.fault_id:
            verdicts[verdict.fault_id] = verdict
    return verdicts, f"verdicts file {path}"


class _VerdictsFileError(Exception):
    """A verdicts file mayhem will not read. Reported by the command, not raised out."""


def _row(
    definition: FaultDefinition,
    query: CellQuery,
    records: Mapping[str, Sequence[Any]],
    *,
    now: datetime,
) -> dict[str, Any]:
    from mayhem.controller.catalog_report import build_catalog_probe
    from mayhem.infra.promotion import evaluate_maturity

    decision = evaluate_maturity(
        definition,
        probe=build_catalog_probe(definition),
        records=records,
    )
    return {
        "fault_id": definition.id,
        "declared_effect": definition.observable_effect,
        "reversible": definition.reversible,
        "requires_recovery_verification": requires_recovery_verification(definition),
        "required_capabilities": sorted(cap.value for cap in definition.required_caps),
        "engine_lanes": sorted(lane.value for lane in definition.engine_lanes),
        "catalog_only": definition.catalog_only,
        "compatibility": _compatibility(definition, query),
        "certification": _certification_state(definition, query, records, now),
        "maturity": decision.to_dict(),
    }


# ── small helpers ───────────────────────────────────────────────────────────


def _open_store(db: str) -> Store:
    """The same store resolution every other store-backed command uses."""
    from mayhem.cli.services import open_store

    return open_store(db)


def _parse_params(params: tuple[str, ...]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for item in params:
        key, separator, value = item.partition("=")
        if not separator or not key.strip():
            raise click.BadParameter(
                f"--param expects key=value, got {item!r}", param_hint="--param"
            )
        parsed[key.strip()] = _coerce(value)
    return parsed


def _coerce(value: str) -> object:
    lowered = value.strip().lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _single_fault_spec(fault_id: str, service: str, request: CertificationRequest) -> DrillSpec:
    """A one-fault drill: the smallest spec that can answer the certification question."""
    fault: dict[str, Any] = {
        "fault": fault_id,
        "duration": f"{max(request.duration_s, 0.1):.3f}s",
    }
    if request.target:
        fault["targets"] = [request.target]
    if request.params:
        fault["params"] = dict(request.params)
    return DrillSpec(
        kind="drill",
        name=f"certify-{fault_id.replace('.', '-')}",
        hypothesis=f"{fault_id} is certified on the cell this drill ran on",
        containers={service: DrillContainer(faults=(DrillFault.model_validate(fault),))},
        execution=(ExecutionStep(sequential=(service,)),),
    )


def _first_container(ctx: click.Context, compose: str | None, *, graph: Any) -> str:
    """The container to target when the caller (or a stored claim) named none.

    Chosen against the *graph*, not just the compose file: a compose file may
    call a service ``api`` while giving it ``container_name: testcase-api``, and
    the topology graph's subtree keys follow the container name — so guessing
    the alphabetically-first *service* name produced a plan the planner refuses
    (``container 'api' not found in topology``), which made ``certify regress
    --rerun`` — the nightly gate's own execution path — fail on exactly the
    bundled example stack people certify against. First entry whose name the
    graph recognises wins: the service's ``container_name`` if it has one, then
    the service name itself (graphs built from service keys). A graph that
    knows none of them falls back to its own first container, then to the first
    service, then to the historical placeholder.
    """
    from mayhem.cli.topology import _resolve_compose

    resolved = _resolve_compose(compose)
    candidates: list[str] = []
    if resolved is not None:
        try:
            import yaml

            with Path(resolved).open(encoding="utf-8") as handle:
                services = (yaml.safe_load(handle) or {}).get("services") or {}
            for name in sorted(services):
                spec = services.get(name)
                container_name = spec.get("container_name") if isinstance(spec, dict) else None
                if container_name:
                    candidates.append(str(container_name))
                candidates.append(str(name))
        except Exception:
            candidates = []
    del ctx
    if graph is not None:
        for candidate in candidates:
            try:
                if graph.node_ids_for_container(candidate):
                    return candidate
            except Exception:
                continue
        names = graph.container_names()
        if names:
            return names[0]
    if candidates:
        return candidates[0]
    return "mayhem-certify"


def _mayhem_version() -> str:
    try:
        from importlib.metadata import version

        return version("mayhem-cli")
    except Exception:
        return "0.0.0"


def _emit_attempt(attempt: CertificationAttempt, *, as_json: bool, quiet: bool) -> None:
    if as_json:
        click.echo(json.dumps(attempt.to_dict(), indent=2, sort_keys=True, default=str))
        return
    if not quiet:
        click.echo(attempt.summary())
        click.echo(f"  recorded: {attempt.outcome.value}")
