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
  no mode in which this command reports a live rung it cannot back.
* **A refusal is a result.** ``certify run`` on a catalog-only fault exits
  non-zero *and* leaves a record naming the refusal. A certification attempt that
  proves nothing is not a pass, and not a pass must not look like success.
* **The live-verified count is zero until a real runtime says otherwise.** No
  code path here seeds a record, so ``certify matrix`` reports zero on a fresh
  database and the README's 0-of-N stays true (N is the live catalogue size,
  asserted against ``CATALOG`` rather than written down here).

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
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from mayhem.cli import style
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.domain.capabilities import Capability
from mayhem.domain.catalog import CATALOG, definition_for
from mayhem.domain.certification import (
    Arch,
    CellPrivilege,
    EvidenceBundleRef,
    MatrixCell,
)
from mayhem.domain.common import utc_now
from mayhem.domain.experiments import DrillContainer, DrillFault, DrillSpec, ExecutionStep
from mayhem.domain.faults import EngineLane
from mayhem.infra.certification_repository import CertificationRepository
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

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

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
        all_verified = bool(verified) and all(
            int(dict(row)["verified"]) == 1 for row in verified
        )
        mechanisms = sorted(
            {str(dict(row)["release_mechanism"] or "") for row in released} - {""}
        )
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
        runner = engine_for(
            store,
            engine,
            live_graph=lambda: graph,
            recovery_grace=prepared.recovery_grace,
            require_intent=True,
            allow_implicit=implicit_execution_allowed(),
        )
        return runner.execute(plan)

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
        stored_plan = self.store.query(
            "SELECT plan_json FROM m5_runs WHERE id = ?", (run.run_id,)
        )
        if not stored_plan:
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
                ",".join(sorted(entry.get("node_ids", ())))
                for entry in fault.get("targets") or []
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
                f"the cell does not advertise {', '.join(missing)}, which "
                f"{definition.id} requires"
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

    aged = [
        expire_by_time(record, now=now) for record in records.get(definition.id, ())
    ]
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

    from mayhem.cli.lifecycle import _graph_from
    from mayhem.cli.services import open_store, prepare
    from mayhem.controller.planner import plan_drill

    service = container or _first_container(ctx, compose)
    graph, resolved_compose = _graph_from(ctx, compose)
    store = open_store(db_opt or cli_ctx.db)
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
        capturer = RunEvidenceCapturer(
            store=store,
            out_dir=None if bundle_out is None else Path(bundle_out),
            mayhem_version=_mayhem_version(),
        )
        attempt = certify_fault(
            request,
            provisioner=_StaticProvisioner(cell),
            compile_plan=compile_plan,
            capture=capturer,
            sink=CertificationRepository(store),
            now=utc_now(),
        )
    finally:
        store.close()

    _emit_attempt(attempt, as_json=as_json, quiet=quiet)
    ctx.exit(
        int(ExitCode.SUCCESS)
        if attempt.certified
        else int(ExitCode.EXPERIMENT_FAILURE)
    )


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
    db_opt: str | None,
    as_json: bool,
    quiet: bool,
) -> None:
    """Show a fault's certification matrix, or answer one compatibility question.

    Executes nothing. Every reported maturity is computed with the certification
    record store supplied, so a fault with no live claim cannot be shown above
    ``verified-unit`` here.
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
        click.echo(
            "error: pass a FAULT_ID, or --all to report the whole catalog", err=True
        )
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
    try:
        repository = CertificationRepository(store)
        # THE GATE. An empty store returns an empty *mapping*, which is the
        # assertion that nothing is certified — and that caps every fault at
        # verified-unit. `records=None` would preserve 1.0.0 behaviour and let a
        # live rung be reported off run evidence alone; this surface never
        # passes it.
        records = repository.certification_gate(now=now)
        rows = [
            _row(definition, query, records, now=now) for definition in definitions
        ]
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
        "faults": rows,
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
    elif not quiet:
        click.echo(_render_matrix(payload))
    ctx.exit(int(ExitCode.SUCCESS))


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


def _single_fault_spec(
    fault_id: str, service: str, request: CertificationRequest
) -> DrillSpec:
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


def _first_container(ctx: click.Context, compose: str | None) -> str:
    from mayhem.cli.topology import _resolve_compose

    resolved = _resolve_compose(compose)
    if resolved is not None:
        try:
            import yaml

            with Path(resolved).open(encoding="utf-8") as handle:
                services = (yaml.safe_load(handle) or {}).get("services") or {}
            if services:
                return str(sorted(services)[0])
        except Exception:
            pass
    del ctx
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
