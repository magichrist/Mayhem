"""Plan 20 Phase 5 — failure-mode coverage, sandbox/demo purity, network-policy,
and the negative controls (docs/v1.1.0/20_ENTERPRISE_PRODUCT_HARDENING.md).

Five properties, each defended by tests that use fakes, never live infra:

1. **Failure-mode coverage is total.** Every one of the 145 catalog faults maps
   to at least one failure mode, every mapping answers the six report
   questions, and the taxonomy has no empty member. This pins the plan's
   Phase 1 acceptance criterion at the Phase 5 gate rather than re-proving
   Phase 1 internals.
2. **Sandbox runs pass through admission with the sandbox's own ceilings.**
   Provisioning uses a recording fake; a run that breaches a ceiling is
   refused by name.
3. **Demo purity is a measurement.** A training run over a loaded mutation sink
   performs zero mutation calls, and a sink that moved across the call is
   refused.
4. **Network policy is honored or fails closed.** Proxy routing, declared-CA
   verification, enforced-allowlist denial, and the air gap (transport never
   reached) each get a decision test through the guard the walkthrough uses.
5. **Negative controls.** A demo-mode run presented as production evidence is
   rejected by the verifier; an air-gapped install attempting egress fails
   closed.

Negative controls (the group a reviewer should read first):

* a demo-as-production presentation is refused with the sealed banner named;
* an air-gapped egress attempt fails closed and the transport is never reached;
* a demo-mode flag requested for a production run is refused at resolution;
* a forged demo marker is refused;
* an unsealed digest cited in a compliance map is refused.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.compliance_map import (
    RULE_COMPLIANCE_DIGEST_UNSEALED,
    ComplianceEvidence,
    build_compliance_map,
)
from mayhem.controller.safety import SafetyContext
from mayhem.controller.sandbox_service import (
    RULE_DEMO_MARKER_FORGED,
    RULE_DEMO_MUTATION_OBSERVED,
    RULE_SANDBOX_ADMISSION_REFUSED,
    CommandOutcome,
    DemoModeService,
    DemoRunRequest,
    SandboxProvisioner,
    SandboxRefusedError,
    SandboxRequest,
    SandboxRunner,
    blueprint_services,
    sandbox_topology,
    verify_demo_run,
)
from mayhem.domain.catalog import CATALOG
from mayhem.domain.deployment import (
    DeploymentModel,
    ExecutionMode,
    NetworkPolicy,
    production_presentation_refusal,
    resolve_flags,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.failure_modes import (
    COMPLIANCE_TEMPLATES,
    FAILURE_MODES,
    mapped_fault_ids,
    mapping_for,
    taxonomy_coverage,
    unmapped_fault_ids,
    validate_mappings,
)
from mayhem.domain.policy_gate import MutationSink
from mayhem.domain.topology import NodeKind, TargetSelector, TopologyGraph
from mayhem.infra.network_policy import (
    RULE_AIR_GAPPED,
    RULE_ALLOWLIST_DENIED,
    RULE_CA_BUNDLE_UNREADABLE,
    RULE_EGRESS_PERMITTED,
    EgressRefusedError,
    EgressRequest,
    EgressTransport,
    NetworkPolicyGuard,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

FP = "f" * 64
_DIGEST = "b" * 64


# --- fakes -----------------------------------------------------------------------


class FakeRunner(SandboxRunner):
    """A recording fake: answers from a script, touches no runtime."""

    def __init__(self, *, running: Sequence[str] | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.running = running

    def run(self, argv: Sequence[str]) -> CommandOutcome:
        recorded = tuple(argv)
        self.calls.append(recorded)
        action = recorded[recorded.index("-f") + 2]
        if action == "ps":
            services = self.running if self.running is not None else blueprint_services()
            return CommandOutcome(argv=recorded, returncode=0, stdout="\n".join(services))
        return CommandOutcome(argv=recorded, returncode=0, stdout="")


class FakeTransport(EgressTransport):
    """Records every host the guard hands it; the air-gap test asserts none."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def fetch(self, request: EgressRequest, *, timeout_s: float) -> bytes:
        self.calls.append(request.host)
        return b'{"status": "ok"}'


def _permissive() -> BlastRadiusBudget:
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(),
    )


def _ctx() -> SafetyContext:
    return SafetyContext(policy=PolicyCfg(), budget=_permissive(), fingerprint=FP)


def _plan(node_id: str) -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr=node_id)
    return ExecutionPlan(
        run_id="r-phase5",
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
        environment_fingerprint=FP,
    )


def _provisioned(tmp_path: Path) -> TopologyGraph:
    provisioner = SandboxProvisioner(runner=FakeRunner())
    environment = provisioner.provision(SandboxRequest(name="sbx", directory=tmp_path))
    assert environment.ready
    return sandbox_topology(environment.compose_path)


def _service() -> DemoModeService:
    from mayhem.controller.sandbox_service import SANDBOX_CEILINGS

    guard = NetworkPolicyGuard.build(NetworkPolicy(), model=DeploymentModel.LOCAL)
    return DemoModeService(guard=guard, ceilings=SANDBOX_CEILINGS)


def _training_run(graph: TopologyGraph, **kwargs: object):  # type: ignore[no-untyped-def]
    from mayhem.domain.deployment import ExecutionMode as Mode

    service = _service()
    return service.run(
        DemoRunRequest(plan=_plan("svc-cache"), mode=Mode.TRAINING, **kwargs),  # type: ignore[arg-type]
        graph,
        _ctx(),
    )


# --- 1. failure-mode coverage ----------------------------------------------------


def test_all_145_catalog_faults_map_to_a_failure_mode() -> None:
    assert len(CATALOG) == 145
    assert unmapped_fault_ids() == ()
    assert len(mapped_fault_ids()) == 145
    validate_mappings()


def test_every_mapping_answers_all_six_report_questions() -> None:
    for fault_id in sorted(mapped_fault_ids()):
        mapping = mapping_for(fault_id)
        assert mapping.failure_modes, fault_id
        assert mapping.primary in mapping.failure_modes, fault_id
        assert mapping.mechanism.strip(), fault_id
        assert mapping.expected_symptom.strip(), fault_id
        assert mapping.recovery.strip(), fault_id
        assert mapping.verification.strip(), fault_id


def test_no_taxonomy_member_is_empty() -> None:
    coverage = taxonomy_coverage()
    assert len(FAILURE_MODES) == 18
    assert coverage.empty == ()
    assert coverage.complete


# --- 2. sandbox provisioning through admission -----------------------------------


def test_sandbox_provisioning_runs_the_documented_sequence(tmp_path: Path) -> None:
    runner = FakeRunner()
    provisioner = SandboxProvisioner(runner=runner)
    environment = provisioner.provision(SandboxRequest(name="sbx", directory=tmp_path))
    assert environment.ready is True
    actions = tuple(call[call.index("-f") + 2] for call in runner.calls)
    assert actions == ("config", "pull", "up", "ps")
    teardown = provisioner.teardown(environment)
    assert teardown.removed is True


def test_sandbox_run_passes_admission_with_the_sandbox_ceilings(tmp_path: Path) -> None:
    graph = _provisioned(tmp_path)
    evidence = _training_run(graph, sandbox="sbx")
    assert evidence.admission is not None
    assert evidence.admission.admitted is True
    assert evidence.verify().ok is True


def test_sandbox_run_breaching_a_ceiling_is_refused_by_name(tmp_path: Path) -> None:
    from mayhem.domain.topology import Edge, EdgeKind, ServiceNode

    nodes = tuple(ServiceNode(id=f"chain-{i}", name=f"chain-{i}") for i in range(1, 7))
    edges = tuple(
        Edge(src=f"chain-{i}", dst=f"chain-{i + 1}", kind=EdgeKind.DEPENDS_ON) for i in range(1, 6)
    )
    graph = TopologyGraph(nodes=nodes, edges=edges)
    with pytest.raises(SandboxRefusedError) as refusal:
        _service().run(
            DemoRunRequest(
                plan=_plan("chain-6"),
                mode=ExecutionMode.SAFE_DEMO,
                sandbox="synthetic",
            ),
            graph,
            _ctx(),
        )
    assert refusal.value.rule == RULE_SANDBOX_ADMISSION_REFUSED


# --- 3. demo purity --------------------------------------------------------------


def test_demo_run_performs_zero_mutation_calls(tmp_path: Path) -> None:
    graph = _provisioned(tmp_path)
    loaded = MutationSink().record("budget.charge", "payments/team:120s")
    evidence = _training_run(graph, backend=loaded)
    assert evidence.sink_calls_before == 1
    assert evidence.mutations_performed == 0
    assert len(loaded) == 1
    assert evidence.verify().ok is True


def test_a_moved_sink_is_refused_as_a_mutation(tmp_path: Path) -> None:
    from dataclasses import replace

    graph = _provisioned(tmp_path)
    evidence = _training_run(graph)
    moved = replace(evidence, sink_calls_before=evidence.sink_calls_before - 1)
    assert moved.mutations_performed == 1
    verification = verify_demo_run(moved)
    assert verification.ok is False
    assert verification.refusals[0].startswith(RULE_DEMO_MUTATION_OBSERVED)


# --- 4. network policy -----------------------------------------------------------


def test_proxy_is_the_route_a_permitted_call_takes() -> None:
    policy = NetworkPolicy(
        http_proxy="http://proxy.corp.example:3128",
        allowlist_enforced=True,
        outbound_allowlist=frozenset({"proxy.corp.example", "api.corp.example"}),
    )
    guard = NetworkPolicyGuard.build(policy)
    assert guard.ready is True
    decision = guard.record("http://api.corp.example/v1")
    assert decision.allowed is True
    assert decision.via_proxy == "http://proxy.corp.example:3128"
    assert decision.rule_id == RULE_EGRESS_PERMITTED


def test_declared_ca_verified_and_unreadable() -> None:
    policy = NetworkPolicy(custom_ca_bundle="/etc/mayhem/corp-ca.pem")
    ready = NetworkPolicyGuard.build(policy, ca_reader=lambda path: b"-----BEGIN CERT-----\n")
    assert ready.ready is True
    closed = NetworkPolicyGuard.build(policy, ca_reader=None)
    assert closed.ready is False
    assert closed.readiness_refusal().startswith(RULE_CA_BUNDLE_UNREADABLE)


def test_enforced_allowlist_denies_an_undeclared_host() -> None:
    policy = NetworkPolicy(
        allowlist_enforced=True, outbound_allowlist=frozenset({"registry.corp.example"})
    )
    guard = NetworkPolicyGuard.build(policy)
    decision = guard.record("https://evil.example.net/v2/")
    assert decision.allowed is False
    assert decision.rule_id == RULE_ALLOWLIST_DENIED


def test_air_gapped_egress_fails_closed_before_the_transport() -> None:
    transport = FakeTransport()
    guard = NetworkPolicyGuard.build(
        NetworkPolicy(air_gapped=True),
        model=DeploymentModel.AIR_GAPPED,
        transport=transport,
    )
    with pytest.raises(EgressRefusedError) as refusal:
        guard.fetch("https://registry.corp.example/v2/")
    assert refusal.value.rule == RULE_AIR_GAPPED
    assert transport.calls == []


# --- 5. negative controls --------------------------------------------------------


def test_demo_as_production_evidence_is_rejected(tmp_path: Path) -> None:
    graph = _provisioned(tmp_path)
    evidence = _training_run(graph)
    refusal = production_presentation_refusal(evidence.claim)
    assert refusal.startswith("evidence.non_production_mode")
    assert "no mutation was performed" in refusal
    assert evidence.may_back_production_evidence is False


def test_demo_mode_flag_is_refused_inside_a_production_run() -> None:
    resolution = resolve_flags(
        ["demo.mode"], model=DeploymentModel.LOCAL, mode=ExecutionMode.PRODUCTION
    )
    assert "demo.mode" not in resolution.granted
    assert [refusal.rule for refusal in resolution.refusals] == ["flag.production_unsafe"]


def test_forged_demo_marker_is_refused(tmp_path: Path) -> None:
    from dataclasses import replace

    graph = _provisioned(tmp_path)
    evidence = _training_run(graph)
    forged = replace(
        evidence,
        claim=replace(
            evidence.claim,
            marker=replace(evidence.claim.marker, marker="PRODUCTION", mutates=True),
        ),
    )
    verification = verify_demo_run(forged)
    assert verification.ok is False
    assert any(item.startswith(RULE_DEMO_MARKER_FORGED) for item in verification.refusals)


def test_unsealed_digest_in_a_compliance_map_is_refused() -> None:
    control = COMPLIANCE_TEMPLATES[0]
    with pytest.raises(InvariantViolationError) as caught:
        build_compliance_map(
            control,
            [
                ComplianceEvidence(
                    evidence_kind=control.required_evidence[0], evidence_digest="not-a-digest"
                )
            ],
        )
    assert caught.value.rule == RULE_COMPLIANCE_DIGEST_UNSEALED


def test_sealed_digest_cited_against_a_template_maps() -> None:
    control = COMPLIANCE_TEMPLATES[0]
    mapped = build_compliance_map(
        control,
        [ComplianceEvidence(evidence_kind=control.required_evidence[0], evidence_digest=_DIGEST)],
    )
    assert len(mapped.supplied) == 1
    assert len(mapped.missing) == len(control.required_evidence) - 1
    assert mapped.evidence_complete is False
