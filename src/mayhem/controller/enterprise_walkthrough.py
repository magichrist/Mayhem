"""Plan 20 Phase 4 — the acceptance walkthrough as code.

The plan requires that "the 20 acceptance walkthrough (deploy → authenticate
→ policy → approve → execute → observe → stop → recover → verify → export)
runs without engineering intervention". This module is that walkthrough with
its seams injected: the container runtime is a
:class:`~mayhem.controller.sandbox_service.SandboxRunner`, the network is an
:class:`~mayhem.infra.network_policy.EgressTransport`, and the filesystem root
is a caller-supplied directory. Everything else is the real path — the real
provisioner, the real simulate path, the real verifier, the real support
bundle builder.

Two steps cannot be proven in a harness and say so instead of pretending:

* ``authenticate`` — there is no live identity provider here (plan 09 owns
  that), so the step is recorded with its live dependency named;
* ``approve`` — the flag-resolution half (``demo.mode`` granted for this model
  and mode) runs for real, but a human's sign-off has no harness stand-in.

:func:`run_walkthrough` therefore reports two things: ``harness_ok`` (every
runnable step passed) and ``live_open_items`` (what a live site must still
prove: an IdP, a human approver, a container runtime, a cluster for the Helm
chart). A green harness with named live items is PARTIAL, not DONE — and the
report is the list that makes it closable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.config import PolicyCfg
from mayhem.controller.sandbox_service import (
    DemoModeService,
    SandboxProvisioner,
    SandboxRefusedError,
    SandboxRequest,
    require_verified_run,
)
from mayhem.controller.support_bundle import (
    SupportBundle,
    SupportSection,
    build_support_bundle,
)
from mayhem.domain.deployment import (
    DeploymentModel,
    ExecutionMode,
    NetworkPolicy,
    air_gap_refusal,
    deployment_profile,
    production_presentation_refusal,
    resolve_flags,
    sealed_mode_marker,
)
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.secrets import DataClassification, FieldClassifications
from mayhem.domain.topology import (
    NodeKind,
    TargetSelector,
)
from mayhem.infra.network_policy import NetworkPolicyGuard

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from mayhem.controller.safety import SafetyContext
    from mayhem.controller.sandbox_service import (
        DemoRunEvidence,
        SandboxEnvironment,
        SandboxRunner,
    )
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.network_policy import EgressTransport

__all__ = [
    "STEP_NAMES",
    "WalkthroughReport",
    "WalkthroughStep",
    "run_walkthrough",
]

#: The ten acceptance steps, in the order the plan names them.
STEP_NAMES: tuple[str, ...] = (
    "deploy",
    "authenticate",
    "policy",
    "approve",
    "execute",
    "observe",
    "stop",
    "recover",
    "verify",
    "export",
)

_HARNESS_FINGERPRINT = "f" * 64
_WALKTHROUGH_BASIS = "plan 20 acceptance walkthrough (harness)"


@dataclass(frozen=True, slots=True)
class WalkthroughStep:
    """One acceptance step: what was run, whether the harness proved it."""

    name: str
    proven: bool
    detail: str
    live_item: str = ""


@dataclass(frozen=True, slots=True)
class WalkthroughReport:
    """The walkthrough outcome: harness evidence plus the live closers."""

    steps: tuple[WalkthroughStep, ...]
    live_open_items: tuple[str, ...]

    @property
    def harness_ok(self) -> bool:
        """True when every harness-runnable step passed.

        Steps carrying a ``live_item`` are proven on a live site, not here,
        so they are excluded: a green harness with named live items is
        PARTIAL (see :attr:`complete`), not failed.
        """
        return all(step.proven for step in self.steps if not step.live_item)

    @property
    def complete(self) -> bool:
        """True only when nothing is left for a live site to prove."""
        return self.harness_ok and not self.live_open_items

    def describe(self) -> str:
        lines = [
            f"{step.name}: {'proven' if step.proven else 'OPEN'} — {step.detail}"
            for step in self.steps
        ]
        if self.live_open_items:
            lines.append("live items still to prove:")
            lines.extend(f"  - {item}" for item in self.live_open_items)
        return "\n".join(lines)


def _permissive_budget() -> BlastRadiusBudget:
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(),
    )


def _safety_ctx() -> SafetyContext:
    from mayhem.controller.safety import SafetyContext

    return SafetyContext(
        policy=PolicyCfg(), budget=_permissive_budget(), fingerprint=_HARNESS_FINGERPRINT
    )


def _plan_for(node_id: str, run_id: str) -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr=node_id)
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id="s0",
                seq=0,
                raw_action=InjectFault(fault="net.latency", selectors=(selector,), duration=30.0),
                fault=PlannedFault(
                    fault_id="net.latency",
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({node_id})),),
                    duration=30.0,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=_HARNESS_FINGERPRINT,
    )


def run_walkthrough(
    runner: SandboxRunner,
    directory: Path,
    *,
    name: str = "mayhem-acceptance",
    policy: NetworkPolicy = NetworkPolicy(),
    model: DeploymentModel = DeploymentModel.LOCAL,
    transport: EgressTransport | None = None,
) -> WalkthroughReport:
    """Run the ten acceptance steps with injected seams.

    The runner answers compose commands, the transport answers egress, and the
    directory holds the rendered compose document — everything else (admission,
    simulation, verification, redaction) is the production path.
    """
    steps: list[WalkthroughStep] = []
    live: list[str] = []

    # deploy — the model descriptor and its agreement with the network policy.
    try:
        profile = deployment_profile(model)
        disagreement = air_gap_refusal(model, policy)
        if disagreement:
            raise SandboxRefusedError("deployment_model.disagreement", disagreement)
        steps.append(
            WalkthroughStep(
                name="deploy",
                proven=True,
                detail=f"{profile.model.value}: {profile.summary}",
            )
        )
    except (KeyError, SandboxRefusedError) as exc:
        steps.append(WalkthroughStep(name="deploy", proven=False, detail=str(exc)))
        return WalkthroughReport(steps=tuple(steps), live_open_items=tuple(live))

    # authenticate — no IdP in a harness. Recorded, named, not proven.
    live.append(
        "authenticate: prove operator authentication against the live identity "
        "provider (plan 09); the harness has no IdP and does not simulate one"
    )
    steps.append(
        WalkthroughStep(
            name="authenticate",
            proven=False,
            detail="not runnable in a harness: no identity provider is bound here",
            live_item=live[-1],
        )
    )

    # policy — resolve the declared network policy through the real guard.
    guard = NetworkPolicyGuard.build(policy, model=model, transport=transport)
    if guard.ready:
        steps.append(
            WalkthroughStep(
                name="policy",
                proven=True,
                detail=f"policy resolved and enforceable: {guard.describe()}",
            )
        )
    else:
        steps.append(
            WalkthroughStep(
                name="policy",
                proven=False,
                detail=f"policy refused: {guard.readiness_refusal()}",
            )
        )
        return WalkthroughReport(steps=tuple(steps), live_open_items=tuple(live))

    # approve — the flag half runs for real; the human half is a live item.
    resolution = resolve_flags(("demo.mode",), model=model, mode=ExecutionMode.SAFE_DEMO)
    if "demo.mode" in resolution.granted:
        live.append(
            "approve: prove a human approval was recorded before execution "
            "(plan 09 approvals); the harness proves flag eligibility, not sign-off"
        )
        steps.append(
            WalkthroughStep(
                name="approve",
                proven=True,
                detail="demo.mode eligible for local safe-demo; human sign-off is live-only",
            )
        )
    else:
        steps.append(
            WalkthroughStep(
                name="approve",
                proven=False,
                detail=f"demo.mode refused: {resolution.refusal_for('demo.mode')}",
            )
        )
        return WalkthroughReport(steps=tuple(steps), live_open_items=tuple(live))

    # execute — provision through the injected runner, then run the demo path
    # with the sandbox's own ceilings and admission.
    provisioner = SandboxProvisioner(runner=runner)
    demo = DemoModeService(guard=guard)
    environment: SandboxEnvironment | None = None
    evidence: DemoRunEvidence | None = None
    try:
        environment = provisioner.provision(
            SandboxRequest(name=name, directory=directory, policy=policy, model=model)
        )
        from mayhem.controller.sandbox_service import (
            DemoRunRequest,
            sandbox_topology,
        )

        graph: TopologyGraph = sandbox_topology(environment.compose_path)
        target = next(
            (node_id for node_id in environment.node_ids if node_id == "svc-cache"),
            environment.node_ids[0],
        )
        evidence = demo.run(
            DemoRunRequest(
                plan=_plan_for(target, "r-acceptance"),
                mode=ExecutionMode.SAFE_DEMO,
                deployment_model=model,
                basis=_WALKTHROUGH_BASIS,
                sandbox=environment.name,
            ),
            graph,
            _safety_ctx(),
        )
        steps.append(
            WalkthroughStep(
                name="execute",
                proven=True,
                detail=f"sandbox ready={environment.ready}; run sealed as {evidence.banner}",
            )
        )
    except SandboxRefusedError as exc:
        steps.append(WalkthroughStep(name="execute", proven=False, detail=f"{exc}"))
        return WalkthroughReport(steps=tuple(steps), live_open_items=tuple(live))

    # observe — read the evidence; the banner and the zero-mutation proof.
    assert evidence is not None
    steps.append(
        WalkthroughStep(
            name="observe",
            proven=True,
            detail=f"{evidence.banner} | mutations this run: {evidence.mutations_performed} | "
            f"admission: {evidence.admission.describe() if evidence.admission else 'none'}",
        )
    )

    # stop — tear the sandbox down through the same runner.
    assert environment is not None
    teardown = provisioner.teardown(environment)
    steps.append(
        WalkthroughStep(
            name="stop",
            proven=teardown.removed,
            detail=f"teardown removed={teardown.removed}"
            + (f": {teardown.refusal}" if teardown.refusal else ""),
        )
    )
    if not teardown.removed:
        return WalkthroughReport(steps=tuple(steps), live_open_items=tuple(live))

    # recover — the environment comes back: re-provision after teardown.
    try:
        recovered = provisioner.provision(
            SandboxRequest(name=name, directory=directory, policy=policy, model=model)
        )
        steps.append(
            WalkthroughStep(
                name="recover",
                proven=recovered.ready,
                detail=f"re-provisioned after teardown: ready={recovered.ready}",
            )
        )
        provisioner.teardown(recovered)
        if not recovered.ready:
            return WalkthroughReport(steps=tuple(steps), live_open_items=tuple(live))
    except SandboxRefusedError as exc:
        steps.append(WalkthroughStep(name="recover", proven=False, detail=f"{exc}"))
        return WalkthroughReport(steps=tuple(steps), live_open_items=tuple(live))

    # verify — the verifier accepts the run, and rejects it as production.
    try:
        require_verified_run(evidence)
        presented = production_presentation_refusal(evidence.claim)
        steps.append(
            WalkthroughStep(
                name="verify",
                proven=bool(presented),
                detail="verifier accepts the demo run; production presentation refused: "
                f"{presented[:120]}…"
                if presented
                else "verifier accepted AND production presentation allowed — marker failure",
            )
        )
        if not presented:
            return WalkthroughReport(steps=tuple(steps), live_open_items=tuple(live))
    except SandboxRefusedError as exc:
        steps.append(WalkthroughStep(name="verify", proven=False, detail=f"{exc}"))
        return WalkthroughReport(steps=tuple(steps), live_open_items=tuple(live))

    # export — a redacted support bundle sealed with the run's marker.
    bundle: SupportBundle = build_support_bundle(
        (
            SupportSection(
                name="run",
                fields={
                    "run_id": evidence.claim.run_id,
                    "banner": evidence.banner,
                    "admission": evidence.admission.describe() if evidence.admission else "none",
                },
                grades=FieldClassifications(
                    fields={
                        "run_id": DataClassification.INTERNAL,
                        "banner": DataClassification.PUBLIC,
                        "admission": DataClassification.INTERNAL,
                    }
                ),
            ),
        ),
        deployment_model=model,
        marker=sealed_mode_marker(evidence.mode, basis=_WALKTHROUGH_BASIS),
    )
    steps.append(
        WalkthroughStep(
            name="export",
            proven=True,
            detail=f"support bundle: {bundle.field_count} field(s), "
            f"dropped={list(bundle.dropped_fields) or 'none'}",
        )
    )

    live.append(
        "execute/stop/recover: re-prove provisioning against a live container "
        "runtime; the harness proves the sequence, not the runtime"
    )
    live.append(
        "deploy: install the Helm chart on a live cluster per "
        "docs/v1.1.0/20_ENTERPRISE_GUIDES.md; the harness proves the "
        "descriptors, not the install"
    )
    names = [step.name for step in steps]
    assert names == list(STEP_NAMES), f"walkthrough drifted from STEP_NAMES: {names}"
    return WalkthroughReport(steps=tuple(steps), live_open_items=tuple(live))


def _unused_import_guard(_: Sequence[str] = STEP_NAMES) -> None:  # pragma: no cover
    raise NotImplementedError
