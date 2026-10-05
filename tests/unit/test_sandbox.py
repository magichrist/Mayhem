"""Plan 20 Phase 2 — sandbox provisioning, demo/training mode, network policy
(docs/v1.1.0/20_ENTERPRISE_PRODUCT_HARDENING.md).

Six properties, each defended by at least one test that fails if the property
stops holding. The negative controls are listed in the last group and each names
the failure it makes impossible.

1. **A sandbox is the existing compose blueprint, not a second topology stack.**
   :data:`~mayhem.controller.sandbox_service.SANDBOX_BLUEPRINT` covers
   :data:`~mayhem.domain.deployment.SANDBOX_COMPONENTS` exactly, the rendered
   document reads back through
   :class:`~mayhem.topology.providers.compose.ComposeFileProvider`, and the
   graph a sandbox run is planned against is the one that provider produced.
2. **Provisioning is driven by an injectable runner, and a failure is a
   refusal.** Every command in the sequence is asserted, every failure mode is
   asserted to raise with a rule id and a rollback, and no container runtime is
   involved: the module does not even import ``subprocess``.
3. **Demo mode is the existing simulate path.** The suite runs through
   :meth:`~mayhem.controller.prediction_service.PredictionService.simulate_plan`
   with a **pre-loaded** :class:`~mayhem.domain.policy_gate.MutationSink`, so
   the no-mutation proof is a difference of two readings of a real object rather
   than a constant — and the pre-existing calls cancel, which is what proves the
   measurement is real rather than merely absent.
4. **A training run cannot become a production run.** The marker is sealed and
   derived, the banner is a property, the verifier refuses a forged marker, a
   later flag is refused by name, and ``demo.mode`` is not production-safe.
5. **A sandbox is not a policy-free zone.** Sandbox runs carry the sandbox's own
   ceilings through the existing prediction seam, and a run whose admission was
   refused — or which carries no admission record — is refused.
6. **Network policy fails closed.** Proxy, custom CA, allowlist, and air gap each
   get a decision-matrix test, and each refusal names a cause. Under an air gap
   the transport is never reached, and a policy that cannot resolve refuses
   everything.

Negative controls (the group a reviewer should read first):

* a provisioning failure is refused, rolled back, and never reported as ready;
* a sandbox run whose evidence has no admission record is refused;
* a policy that cannot resolve fails closed for every host;
* a demo marker forged outside the sealed path is refused;
* an undeclared host is refused by an enforced allowlist;
* egress under an air gap fails closed with the cause named.
"""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from mayhem.config import PolicyCfg
from mayhem.domain.policy_gate import MutationSink
from mayhem.controller.prediction_service import CeilingName
from mayhem.controller.safety import SafetyContext
from mayhem.controller.sandbox_service import (
    COMPOSE_FILENAME,
    DEFAULT_POLICY,
    RULE_DEMO_FLAG_REFUSED,
    RULE_DEMO_MARKER_FORGED,
    RULE_DEMO_MARKER_MISSING,
    RULE_DEMO_MUTATION_OBSERVED,
    RULE_DEMO_PRODUCTION_MODE_REFUSED,
    RULE_SANDBOX_ADMISSION_MISSING,
    RULE_SANDBOX_ADMISSION_REFUSED,
    RULE_SANDBOX_BLUEPRINT_INVALID,
    RULE_SANDBOX_COMPONENTS_UNREADY,
    RULE_SANDBOX_FLAG_REFUSED,
    RULE_SANDBOX_IMAGE_EGRESS_REFUSED,
    RULE_SANDBOX_IMAGE_PULL_FAILED,
    RULE_SANDBOX_INVALID_NAME,
    RULE_SANDBOX_POLICY_UNRESOLVED,
    RULE_SANDBOX_PRODUCTION_MODE_REFUSED,
    RULE_SANDBOX_START_FAILED,
    SANDBOX_BLUEPRINT,
    SANDBOX_CEILINGS,
    CommandOutcome,
    DemoModeService,
    DemoRunEvidence,
    DemoRunRequest,
    SandboxAdmission,
    SandboxEnvironment,
    SandboxProvisioner,
    SandboxRefusedError,
    SandboxRequest,
    SandboxService,
    blueprint_registry_hosts,
    blueprint_services,
    image_registry,
    render_compose_document,
    sandbox_service,
    sandbox_topology,
    verify_demo_run,
)
from mayhem.domain.deployment import (
    NO_MUTATION_PHRASE,
    SANDBOX_COMPONENTS,
    DeploymentModel,
    ExecutionMode,
    NetworkPolicy,
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
from mayhem.domain.prediction import (
    RULE_MAX_AFFECTED_NODES,
    RULE_MAX_AFFECTED_PCT,
    RULE_MAX_DEPENDENCY_DEPTH,
)
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.infra.network_policy import (
    RULE_AIR_GAPPED,
    RULE_ALLOWLIST_DENIED,
    RULE_CA_BUNDLE_UNREADABLE,
    RULE_EGRESS_PERMITTED,
    RULE_NO_TRANSPORT,
    RULE_PROXY_NOT_ALLOWED,
    RULE_UNPARSEABLE_URL,
    RULE_UNRESOLVED_POLICY,
    EgressRefusedError,
    EgressRequest,
    EgressTransport,
    NetworkPolicyGuard,
    parse_egress_request,
    proxy_for,
    resolve_ca_bundle,
    resolve_egress,
    resolve_egress_url,
    resolve_policy,
)
from mayhem.observability.base import ConnectorError, fetch_json
from mayhem.topology.providers.compose import ComposeFileProvider

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

FP = "f" * 64
OTHER_FP = "e" * 64
STEP_S = 30.0

#: A proxy the enterprise policy declares, and the two hosts it is allowed to reach.
CORP_PROXY = "http://proxy.corp.example:3128"


# --- fakes -----------------------------------------------------------------------


class FakeRunner:
    """A :class:`~mayhem.controller.sandbox_service.SandboxRunner` with no runtime.

    Records every argv it is handed and answers from a script. ``fail_on`` names a
    compose action that should fail, and ``running`` overrides what ``ps``
    reports, so both a failed command and a partially-started stack are reachable
    without a container runtime.
    """

    def __init__(
        self,
        *,
        fail_on: str | None = None,
        also_fail_on: str | None = None,
        running: Sequence[str] | None = None,
        stderr: str = "compose: boom",
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail_on = fail_on
        self.also_fail_on = also_fail_on
        self.running = running
        self.stderr = stderr

    def run(self, argv: Sequence[str]) -> CommandOutcome:
        recorded = tuple(argv)
        self.calls.append(recorded)
        action = recorded[recorded.index("-f") + 2]
        if action in (self.fail_on, self.also_fail_on):
            return CommandOutcome(argv=recorded, returncode=1, stderr=self.stderr)
        if action == "ps":
            services = self.running if self.running is not None else blueprint_services()
            return CommandOutcome(argv=recorded, returncode=0, stdout="\n".join(services))
        return CommandOutcome(argv=recorded, returncode=0, stdout="")

    @property
    def actions(self) -> tuple[str, ...]:
        return tuple(call[call.index("-f") + 2] for call in self.calls)


class FakeTransport:
    """An :class:`~mayhem.infra.network_policy.EgressTransport` that records hosts."""

    def __init__(self, body: bytes = b'{"status": "ok"}') -> None:
        self.calls: list[tuple[str, float]] = []
        self.body = body

    def fetch(self, request: EgressRequest, *, timeout_s: float) -> bytes:
        self.calls.append((request.host, timeout_s))
        return self.body


# --- fixtures and builders --------------------------------------------------------


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def sandbox_dir(tmp_path: Path) -> Path:
    return tmp_path


def _provision(
    directory: Path,
    runner: FakeRunner | None = None,
    *,
    name: str = "mayhem-sandbox",
    **kwargs: object,
) -> tuple[SandboxProvisioner, SandboxEnvironment]:
    provisioner = SandboxProvisioner(runner=runner or FakeRunner())
    request = SandboxRequest(name=name, directory=directory, **kwargs)  # type: ignore[arg-type]
    return provisioner, provisioner.provision(request)


def _chain_graph(length: int) -> TopologyGraph:
    """``length`` services in a dependency chain: the last one fans out to all.

    Used to breach the sandbox ceilings through the real prediction seam rather
    than by handing the service a fabricated breach — targeting ``chain-N`` puts
    every node in the blast.
    """
    nodes = tuple(ServiceNode(id=f"chain-{i}", name=f"chain-{i}") for i in range(1, length + 1))
    edges = tuple(
        Edge(src=f"chain-{i}", dst=f"chain-{i + 1}", kind=EdgeKind.DEPENDS_ON)
        for i in range(1, length)
    )
    return TopologyGraph(nodes=nodes, edges=edges)


def _permissive() -> BlastRadiusBudget:
    """Per-step limits nothing here trips, so a refusal has exactly one cause.

    The default 50% service cap is lifted because a deep target breaches it
    first, and a test asserting "the sandbox ceiling refused this" has to mean
    it: the gate must admit the plan so the sandbox's own ceilings are the only
    thing standing between it and a run.
    """
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(),
    )


def _ctx(*, fingerprint: str = FP) -> SafetyContext:
    return SafetyContext(policy=PolicyCfg(), budget=_permissive(), fingerprint=fingerprint)


def _plan(
    node_id: str,
    graph: TopologyGraph,
    *,
    run_id: str = "r-demo",
    fault_id: str = "net.latency",
    duration: float = STEP_S,
    fingerprint: str = FP,
) -> ExecutionPlan:
    """A one-step frozen plan targeting ``node_id`` in ``graph``."""
    selector = TargetSelector(kind=NodeKind.SERVICE, expr=node_id)
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id="s0",
                seq=0,
                raw_action=InjectFault(
                    fault=fault_id, selectors=(selector,), duration=duration
                ),
                fault=PlannedFault(
                    fault_id=fault_id,
                    targets=(
                        ResolvedTarget(selector=selector, node_ids=frozenset({node_id})),
                    ),
                    duration=duration,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=fingerprint,
    )


def _demo_service(
    *,
    policy: NetworkPolicy = DEFAULT_POLICY,
    model: DeploymentModel = DeploymentModel.LOCAL,
    transport: EgressTransport | None = None,
) -> DemoModeService:
    guard = NetworkPolicyGuard.build(policy, model=model, transport=transport)
    return DemoModeService(guard=guard, ceilings=SANDBOX_CEILINGS)


def _training_run(
    service: DemoModeService,
    graph: TopologyGraph,
    plan: ExecutionPlan,
    *,
    backend: MutationSink | None = None,
    sandbox: str = "",
) -> DemoRunEvidence:
    return service.run(
        DemoRunRequest(
            plan=plan,
            mode=ExecutionMode.TRAINING,
            backend=backend,
            sandbox=sandbox,
            basis="plan 20 Phase 2 suite",
        ),
        graph,
        _ctx(),
    )


# --- the blueprint ----------------------------------------------------------------


def test_the_blueprint_covers_the_sandbox_vocabulary_exactly():
    """The blueprint is the vocabulary, not a hand-kept copy that can drift from it."""
    assert tuple(spec.component for spec in SANDBOX_BLUEPRINT) == SANDBOX_COMPONENTS
    assert blueprint_services() == tuple(component.value for component in SANDBOX_COMPONENTS)
    assert len({spec.service for spec in SANDBOX_BLUEPRINT}) == len(SANDBOX_BLUEPRINT)


def test_the_blueprint_depends_only_on_components_it_declares():
    """A ``depends_on`` naming a service outside the blueprint would be a phantom."""
    declared = set(SANDBOX_COMPONENTS)
    for spec in SANDBOX_BLUEPRINT:
        assert set(spec.depends_on) <= declared


def test_only_the_frontend_publishes_a_port():
    """The customer-facing ceiling is 1, so the blueprint must expose exactly one surface.

    If every component published a port, "at most one customer-facing service
    affected" would be unreachable in a sandbox and the ceiling would be a number
    nobody believed.
    """
    published = tuple(spec for spec in SANDBOX_BLUEPRINT if spec.ports)
    assert tuple(spec.component for spec in published) == (SANDBOX_COMPONENTS[0],)


def test_image_registry_separates_a_named_registry_from_a_library_image():
    assert image_registry("nginx:1.27-alpine") == "docker.io"
    assert image_registry("redis:7-alpine") == "docker.io"
    assert image_registry("ghcr.io/mayhem/sandbox-api:1.1.0") == "ghcr.io"
    assert image_registry("registry.corp.example:5000/team/api:2") == "registry.corp.example:5000"
    assert blueprint_registry_hosts() == ("docker.io", "ghcr.io")


def test_a_healthcheck_containing_a_quote_still_renders_a_parsable_document(tmp_path: Path):
    """The topology comes from parsing the rendered document, so rendering must not break it.

    A blueprint healthcheck with a double quote in it would otherwise produce a
    document no parser can read — and the failure would surface as an empty
    sandbox rather than as a quoting mistake.
    """
    spec = replace(SANDBOX_BLUEPRINT[0], healthcheck='sh -c "true"')
    document = render_compose_document((spec, *SANDBOX_BLUEPRINT[1:]), project_name="quoting")
    path = tmp_path / COMPOSE_FILENAME
    path.write_text(document, encoding="utf-8")
    assert tuple(ComposeFileProvider(path).service_names) == blueprint_services()


# --- provisioning -----------------------------------------------------------------


def test_provisioning_runs_the_documented_sequence_and_reports_a_ready_sandbox(
    sandbox_dir: Path, runner: FakeRunner
):
    """Four commands, in order, and an environment whose readiness is derived."""
    _, environment = _provision(sandbox_dir, runner)
    assert runner.actions == ("config", "pull", "up", "ps")
    assert environment.ready is True
    assert environment.name == "mayhem-sandbox"
    assert environment.compose_path == sandbox_dir / COMPOSE_FILENAME
    assert environment.compose_path.is_file()
    assert environment.components == SANDBOX_COMPONENTS


def test_the_sandbox_topology_is_the_one_the_compose_provider_produced(
    sandbox_dir: Path, runner: FakeRunner
):
    """Six services, healthcheck-gated edges, read back through the existing provider."""
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    assert tuple(node.id for node in graph.nodes) == tuple(
        f"svc-{service}" for service in blueprint_services()
    )
    # Weight 2.0 is the provider's marker for `condition: service_healthy`, so these
    # edges are real orderings rather than start-order hints.
    assert {edge.weight for edge in graph.edges} == {2.0}
    assert sum(1 for node in graph.nodes if getattr(node, "exposed_ports", ())) == 1


def test_provisioning_records_the_registry_egress_it_resolved(
    sandbox_dir: Path, runner: FakeRunner
):
    """Pulling images is egress, so every registry is resolved and the answers kept."""
    provisioner, environment = _provision(sandbox_dir, runner)
    assert provisioner is not None
    assert dict(environment.registry_egress) == {
        "docker.io": RULE_EGRESS_PERMITTED,
        "ghcr.io": RULE_EGRESS_PERMITTED,
    }
    assert [attempt.host for attempt in environment.attempts] == ["docker.io", "ghcr.io"]
    assert all(attempt.allowed for attempt in environment.attempts)


def test_a_teardown_removes_the_stack_and_reports_it(sandbox_dir: Path, runner: FakeRunner):
    provisioner, environment = _provision(sandbox_dir, runner)
    teardown = provisioner.teardown(environment)
    assert teardown.removed is True
    assert teardown.refusal == ""
    assert runner.actions[-1] == "down"
    assert "down" in teardown.outcome.command


def test_a_teardown_that_fails_is_reported_rather_than_raised(sandbox_dir: Path):
    """Teardown runs when something has already gone wrong; raising loses that message."""
    runner = FakeRunner(also_fail_on="down")
    provisioner, environment = _provision(sandbox_dir, runner)
    teardown = provisioner.teardown(environment)
    assert teardown.removed is False
    assert "teardown of sandbox" in teardown.refusal
    assert "may still be held" in teardown.refusal


def test_the_provisioner_shells_out_to_nothing_itself():
    """The runner is the only path to a container runtime, so the module needs no process API.

    Checked structurally rather than by observation: a future edit that reaches for
    ``subprocess`` would let the provisioner act outside the injected seam, and the
    unit suite would silently stop exercising the code the product runs.
    """
    source = Path(__file__).resolve().parents[2] / "src/mayhem/controller/sandbox_service.py"
    tree = ast.parse(source.read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "subprocess" not in imported
    assert "socket" not in imported


# --- provisioning failures are refusals -------------------------------------------


def test_an_invalid_name_is_refused_before_any_command_is_issued(sandbox_dir: Path):
    runner = FakeRunner()
    provisioner = SandboxProvisioner(runner=runner)
    with pytest.raises(SandboxRefusedError) as refusal:
        provisioner.provision(SandboxRequest(name="Not A Name", directory=sandbox_dir))
    assert refusal.value.rule == RULE_SANDBOX_INVALID_NAME
    assert runner.calls == []


def test_a_production_mode_is_refused_because_a_sandbox_is_not_production(
    sandbox_dir: Path, runner: FakeRunner
):
    provisioner = SandboxProvisioner(runner=runner)
    with pytest.raises(SandboxRefusedError) as refusal:
        provisioner.provision(
            SandboxRequest(
                name="sbx", directory=sandbox_dir, mode=ExecutionMode.PRODUCTION
            )
        )
    assert refusal.value.rule == RULE_SANDBOX_PRODUCTION_MODE_REFUSED
    assert "does not come through it" in str(refusal.value)
    assert runner.calls == []


def test_the_sandbox_flag_is_required_and_its_refusal_is_named(sandbox_dir: Path):
    runner = FakeRunner()
    provisioner = SandboxProvisioner(runner=runner)
    with pytest.raises(SandboxRefusedError) as refusal:
        provisioner.provision(
            SandboxRequest(
                name="sbx",
                directory=sandbox_dir,
                model=DeploymentModel.MANAGED_SAAS,
            )
        )
    assert refusal.value.rule == RULE_SANDBOX_FLAG_REFUSED
    assert "sandbox.provisioning" in str(refusal.value)
    assert runner.calls == []


@pytest.mark.parametrize(
    ("fail_on", "rule", "what"),
    [
        ("config", RULE_SANDBOX_BLUEPRINT_INVALID, "compose validation"),
        ("pull", RULE_SANDBOX_IMAGE_PULL_FAILED, "image pull"),
        ("up", RULE_SANDBOX_START_FAILED, "stack start"),
    ],
)
def test_a_failed_step_is_a_refusal_naming_the_command_and_rolling_back(
    sandbox_dir: Path, fail_on: str, rule: str, what: str
):
    """The failure names the rule, the command, the runtime's own stderr, and the rollback.

    All four, because an operator's two questions are "why did it fail" and "is
    anything left running"; a refusal that answers neither is a support ticket.
    """
    runner = FakeRunner(fail_on=fail_on, stderr="cannot reach registry")
    provisioner = SandboxProvisioner(runner=runner)
    with pytest.raises(SandboxRefusedError) as refusal:
        provisioner.provision(SandboxRequest(name="sbx", directory=sandbox_dir))
    assert refusal.value.rule == rule
    assert what in str(refusal.value)
    assert f"{fail_on}" in str(refusal.value)
    assert "cannot reach registry" in str(refusal.value)
    assert "rolled back" in str(refusal.value)
    assert runner.actions[-1] == "down"


def test_a_partially_started_stack_is_refused_and_rolled_back(sandbox_dir: Path):
    """Four of six components is not a sandbox, and reporting it as ready is how a
    rehearsal discovers its own gap at the worst possible moment."""
    runner = FakeRunner(running=("frontend", "api", "database", "cache"))
    provisioner = SandboxProvisioner(runner=runner)
    with pytest.raises(SandboxRefusedError) as refusal:
        provisioner.provision(SandboxRequest(name="sbx", directory=sandbox_dir))
    assert refusal.value.rule == RULE_SANDBOX_COMPONENTS_UNREADY
    assert "observability" in str(refusal.value)
    assert "queue" in str(refusal.value)
    assert "not returned as ready" in str(refusal.value)
    assert runner.actions[-1] == "down"


def test_a_rollback_that_also_fails_is_reported_rather_than_hidden(sandbox_dir: Path):
    runner = FakeRunner(fail_on="up", also_fail_on="down")
    provisioner = SandboxProvisioner(runner=runner)
    with pytest.raises(SandboxRefusedError) as refusal:
        provisioner.provision(SandboxRequest(name="sbx", directory=sandbox_dir))
    assert refusal.value.rule == RULE_SANDBOX_START_FAILED
    assert "ROLLBACK FAILED" in str(refusal.value)
    assert "may still be holding containers" in str(refusal.value)


def test_environment_readiness_is_derived_so_a_partial_record_cannot_claim_it(
    sandbox_dir: Path, runner: FakeRunner
):
    """``ready`` is computed from the recorded components, not passed in."""
    _, environment = _provision(sandbox_dir, runner)
    assert environment.ready is True
    truncated = replace(environment, components=SANDBOX_COMPONENTS[:-1])
    assert truncated.ready is False


# --- demo mode reuses the simulate path --------------------------------------------


def test_a_training_run_seals_the_training_marker_into_its_evidence(
    sandbox_dir: Path, runner: FakeRunner
):
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(_demo_service(), graph, _plan("svc-cache", graph))
    assert evidence.mode is ExecutionMode.TRAINING
    assert evidence.marker == "TRAINING — no mutation performed"
    assert NO_MUTATION_PHRASE in evidence.marker
    assert evidence.mutates is False
    assert evidence.banner.startswith("TRAINING — no mutation performed")
    assert evidence.may_back_production_evidence is False
    assert evidence.verify().ok is True


@pytest.mark.parametrize(
    ("mode", "banner"),
    [
        (ExecutionMode.SIMULATION, "SIMULATION — no mutation performed"),
        (ExecutionMode.TRAINING, "TRAINING — no mutation performed"),
        (ExecutionMode.SAFE_DEMO, "SAFE DEMO — no mutation performed"),
    ],
)
def test_every_demo_mode_runs_the_full_preview_with_no_mutation(
    sandbox_dir: Path, runner: FakeRunner, mode: ExecutionMode, banner: str
):
    """All three demo modes are the plan-14 simulate path wearing different labels."""
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    service = _demo_service()
    evidence = service.run(
        DemoRunRequest(plan=_plan("svc-cache", graph), mode=mode),
        graph,
        _ctx(),
    )
    assert evidence.marker == banner
    assert evidence.report.artifact == "prediction"
    # The whole preview, not a reduced second mechanism: the prediction, the real
    # gate's agreement, the ceilings as admission dimensions, and the cost
    # disclosure all come from `simulate_plan`.
    # Targeting the cache affects its dependents too: the api depends on it and
    # the frontend depends on the api, so the blast is three of the six.
    assert tuple(sorted(evidence.report.prediction.affected_node_ids)) == (
        "svc-api",
        "svc-cache",
        "svc-frontend",
    )
    assert evidence.report.agreement.agrees is True
    assert {dimension.dimension for dimension in evidence.report.dimensions} >= {
        CeilingName.BLAST_RADIUS_CEILING,
        CeilingName.MAX_AFFECTED_PCT,
    }
    assert evidence.report.cost.status == "unpriced"
    assert evidence.mutations_performed == 0


def test_the_no_mutation_proof_is_a_measurement_of_the_sink_and_not_a_constant(
    sandbox_dir: Path, runner: FakeRunner
):
    """The negative control on the purity proof itself.

    A pre-loaded sink makes the zero informative: this module reads the sink
    before and after the simulate call, so the pre-existing call appears in both
    readings and cancels. A hard-coded zero, or a check that only asserted
    ``calls == 0``, would fail here.
    """
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    loaded = MutationSink().record("budget.charge", "payments/team:120s")
    evidence = _training_run(_demo_service(), graph, _plan("svc-cache", graph), backend=loaded)
    assert evidence.sink_calls_before == 1
    assert evidence.mutation.calls == 1
    assert evidence.mutation.calls_detail == (("budget.charge", "payments/team:120s"),)
    assert evidence.mutations_performed == 0
    assert evidence.mutation.backend_attached is False
    # The pre-existing call is still the only one: the simulate added nothing.
    assert len(loaded) == 1
    assert evidence.verify().ok is True


def test_the_service_hands_the_sink_to_the_simulate_path_rather_than_detaching_it_first(
    sandbox_dir: Path, runner: FakeRunner
):
    """The detachment is the simulate path's, and it is what makes the count mean something."""
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    loaded = MutationSink().record("budget.charge", "x:1s")
    service = _demo_service()
    assert service.service_for(graph, loaded).backend is loaded


# --- a demo run cannot become a production run ------------------------------------


def test_a_training_run_cannot_be_presented_as_production_evidence(
    sandbox_dir: Path, runner: FakeRunner
):
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(_demo_service(), graph, _plan("svc-cache", graph))
    presentation = evidence.verify().presentation
    assert presentation.startswith("evidence.non_production_mode")
    assert "training" in presentation
    assert "no mutation was performed" in presentation
    assert evidence.may_back_production_evidence is False


def test_a_training_run_cannot_be_reclassified_by_a_later_flag(
    sandbox_dir: Path, runner: FakeRunner
):
    """The drift path, named. The flag changes the next run's mode, not this one's."""
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(_demo_service(), graph, _plan("svc-cache", graph))
    drift = evidence.refusal_for_mode(ExecutionMode.PRODUCTION)
    assert drift.startswith("evidence.flag_drift")
    assert "cannot be reclassified as 'production'" in drift
    # The sealed marker does not move, whatever is asked of it.
    assert evidence.claim.marker == sealed_mode_marker(
        ExecutionMode.TRAINING, basis="plan 20 Phase 2 suite"
    )
    assert evidence.marker == "TRAINING — no mutation performed"


def test_the_demo_flag_is_not_production_safe_so_a_production_run_is_refused_it():
    """Flag drift is refused at resolution time as well as at evidence time."""
    demo = resolve_flags(["demo.mode"], model=DeploymentModel.LOCAL, mode=ExecutionMode.TRAINING)
    assert "demo.mode" in demo.granted
    production = resolve_flags(
        ["demo.mode"], model=DeploymentModel.LOCAL, mode=ExecutionMode.PRODUCTION
    )
    assert "demo.mode" not in production.granted
    assert "demo.mode" in production.refusal_for("demo.mode")
    assert [refusal.rule for refusal in production.refusals] == ["flag.production_unsafe"]


def test_the_demo_service_refuses_a_production_mode_outright(
    sandbox_dir: Path, runner: FakeRunner
):
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    with pytest.raises(SandboxRefusedError) as refusal:
        _demo_service().run(
            DemoRunRequest(plan=_plan("svc-cache", graph), mode=ExecutionMode.PRODUCTION),
            graph,
            _ctx(),
        )
    assert refusal.value.rule == RULE_DEMO_PRODUCTION_MODE_REFUSED
    assert "does not come through here" in str(refusal.value)


def test_an_ungranted_demo_flag_is_refused_with_the_flags_own_reason(
    sandbox_dir: Path, runner: FakeRunner
):
    """``demo.mode`` is not permitted in a managed install, and the refusal says so."""
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    service = _demo_service(model=DeploymentModel.MANAGED_SAAS)
    with pytest.raises(SandboxRefusedError) as refusal:
        service.run(
            DemoRunRequest(
                plan=_plan("svc-cache", graph),
                mode=ExecutionMode.SAFE_DEMO,
                deployment_model=DeploymentModel.MANAGED_SAAS,
            ),
            graph,
            _ctx(),
        )
    assert refusal.value.rule == RULE_DEMO_FLAG_REFUSED
    assert "demo.mode" in str(refusal.value)


def test_a_demo_marker_forged_outside_the_sealed_path_is_refused(
    sandbox_dir: Path, runner: FakeRunner
):
    """The negative control on the marker itself.

    ``ModeMarker`` is a frozen dataclass, so a caller can construct one whose
    fields contradict the mode it names. This verifier refuses that: the banner
    and the ``mutates`` flag must both be the ones the mode derives, so no marker
    can say "training" and "may back production evidence" at once.
    """
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(_demo_service(), graph, _plan("svc-cache", graph))
    assert evidence.claim.marker.marker == evidence.claim.mode.marker

    forged_marker = replace(
        evidence.claim.marker, marker="PRODUCTION", mutates=True, basis="forged"
    )
    forged = replace(evidence, claim=replace(evidence.claim, marker=forged_marker))
    assert forged.claim.marker.marker == "PRODUCTION"
    assert forged.claim.marker.mutates is True
    # Phase 1 holds the line on its own: promotion needs the *mode* to be
    # production, not just the marker's fields to say so.
    assert forged.claim.marker.may_back_production_evidence is False
    assert verify_demo_run(forged).presentation != ""
    # And this layer refuses the forged record anyway, because the marker
    # disagrees with the mode it names.
    verification = verify_demo_run(forged)
    assert verification.ok is False
    assert any(item.startswith(RULE_DEMO_MARKER_FORGED) for item in verification.refusals)
    assert any(
        "sealed_mode_marker" in item
        for item in verification.refusals
        if item.startswith(RULE_DEMO_MARKER_FORGED)
    )


def test_a_banner_missing_the_no_mutation_phrase_is_refused(
    sandbox_dir: Path, runner: FakeRunner
):
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(_demo_service(), graph, _plan("svc-cache", graph))
    stripped = replace(
        evidence.claim.marker, marker="training", mutates=False, basis="stripped"
    )
    verification = verify_demo_run(
        replace(evidence, claim=replace(evidence.claim, marker=stripped))
    )
    assert verification.ok is False
    assert any(item.startswith(RULE_DEMO_MARKER_MISSING) for item in verification.refusals)


def test_a_run_that_performed_a_mutation_is_refused(
    sandbox_dir: Path, runner: FakeRunner
):
    """If the simulate path ever wrote a call, this layer refuses rather than reporting clean.

    Simulated by moving the pre-run reading, which is exactly the assertion: the
    sink's length moved across the call, so the run mutated something.
    """
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    loaded = MutationSink().record("budget.charge", "x:1s")
    evidence = _training_run(_demo_service(), graph, _plan("svc-cache", graph), backend=loaded)
    moved = replace(evidence, sink_calls_before=0)
    assert moved.mutations_performed == 1
    verification = verify_demo_run(moved)
    assert verification.ok is False
    assert verification.refusals[0].startswith(RULE_DEMO_MUTATION_OBSERVED)


def test_the_banner_is_a_property_and_cannot_be_dropped_by_a_renderer(
    sandbox_dir: Path, runner: FakeRunner
):
    """A field could be omitted in serialisation; a property read off the sealed marker cannot."""
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(_demo_service(), graph, _plan("svc-cache", graph))
    assert NO_MUTATION_PHRASE in evidence.banner
    with pytest.raises(FrozenInstanceError):
        evidence.banner = "all clear"  # type: ignore[misc]
    # The dataclass carries no mode field for a renderer to prefer.
    assert "mode" not in set(evidence.__dataclass_fields__)


def test_the_evidence_records_the_flags_that_were_in_force(
    sandbox_dir: Path, runner: FakeRunner
):
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(_demo_service(), graph, _plan("svc-cache", graph))
    assert "demo.mode" in evidence.flags.granted
    assert evidence.claim.active_flags == evidence.flags.granted


# --- a sandbox is not a policy-free zone -------------------------------------------


def test_a_sandbox_run_passes_admission_with_the_sandbox_ceilings(
    sandbox_dir: Path, runner: FakeRunner
):
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(
        _demo_service(), graph, _plan("svc-cache", graph), sandbox=environment.name
    )
    assert evidence.sandbox == "mayhem-sandbox"
    assert evidence.admission is not None
    assert evidence.admission.admitted is True
    assert evidence.admission.gate_refused == frozenset()
    assert evidence.admission.breached == ()
    assert evidence.admission.deployment_model is DeploymentModel.LOCAL


def test_the_sandbox_ceilings_are_read_off_the_preview_not_recomputed(
    sandbox_dir: Path, runner: FakeRunner
):
    """Same numbers, same source: the sandbox carries no private notion of a blast."""
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(
        _demo_service(), graph, _plan("svc-cache", graph), sandbox=environment.name
    )
    reported = {dimension.rule_id: dimension.limit for dimension in evidence.report.dimensions}
    assert reported[RULE_MAX_AFFECTED_NODES] == float(SANDBOX_CEILINGS.max_affected_nodes)
    assert reported[RULE_MAX_AFFECTED_PCT] == SANDBOX_CEILINGS.max_affected_pct
    assert reported[RULE_MAX_DEPENDENCY_DEPTH] == float(SANDBOX_CEILINGS.max_dependency_depth)
    assert evidence.admission.ceiling_breached_ids == ()


def test_a_sandbox_run_that_breaches_a_sandbox_ceiling_is_refused(
    sandbox_dir: Path, runner: FakeRunner
):
    """The ceiling is enforced here, which is why ``enforced_by_gate`` is false for it.

    The gate admits the plan (the budget's service cap is lifted in ``_ctx``), so
    the only thing that can refuse is the sandbox's own ceiling — which is the
    point of the test.
    """
    provisioner, _ = _provision(sandbox_dir, runner)
    graph = _chain_graph(6)
    plan = _plan("chain-6", graph)
    service = _demo_service()
    evidence = service.run(
        DemoRunRequest(
            plan=plan,
            mode=ExecutionMode.SAFE_DEMO,
            deployment_model=DeploymentModel.LOCAL,
        ),
        graph,
        _ctx(),
    )
    # Reported, not raised, without the sandbox name: a preview's value is that it
    # shows why.
    assert evidence.admission is not None
    assert evidence.admission.admitted is False
    assert set(evidence.admission.ceiling_breached_ids) >= {
        RULE_MAX_AFFECTED_NODES,
        RULE_MAX_AFFECTED_PCT,
    }
    assert provisioner.runner is runner
    with pytest.raises(SandboxRefusedError) as refusal:
        service.run(
            DemoRunRequest(
                plan=plan,
                mode=ExecutionMode.SAFE_DEMO,
                deployment_model=DeploymentModel.LOCAL,
                sandbox="synthetic",
            ),
            graph,
            _ctx(),
        )
    assert refusal.value.rule == RULE_SANDBOX_ADMISSION_REFUSED
    assert RULE_MAX_AFFECTED_NODES in str(refusal.value)


def test_a_sandbox_run_refused_by_the_real_gate_is_refused(sandbox_dir: Path, runner: FakeRunner):
    """Admission is the same admission: the real gate runs inside ``simulate_plan``."""
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    service = _demo_service()
    plan = _plan("svc-cache", graph)
    with pytest.raises(SandboxRefusedError) as refusal:
        service.run(
            DemoRunRequest(
                plan=plan,
                mode=ExecutionMode.SAFE_DEMO,
                sandbox=environment.name,
            ),
            graph,
            _ctx(fingerprint=OTHER_FP),
        )
    assert refusal.value.rule == RULE_SANDBOX_ADMISSION_REFUSED
    assert "environment.fingerprint_mismatch" in str(refusal.value)


def test_a_non_sandbox_demo_run_discloses_a_refusal_instead_of_raising(
    sandbox_dir: Path, runner: FakeRunner
):
    """A preview exists to show why a plan was refused, so only a *run* refuses."""
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _demo_service().run(
        DemoRunRequest(plan=_plan("svc-cache", graph), mode=ExecutionMode.SAFE_DEMO),
        graph,
        _ctx(fingerprint=OTHER_FP),
    )
    assert evidence.sandbox == ""
    assert evidence.admission is not None
    assert evidence.admission.admitted is False
    assert evidence.verify().ok is True


def test_a_sandbox_run_with_no_admission_record_is_refused(
    sandbox_dir: Path, runner: FakeRunner
):
    """The negative control: an unattested sandbox run is not evidence."""
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(
        _demo_service(), graph, _plan("svc-cache", graph), sandbox=environment.name
    )
    assert evidence.verify().ok is True
    unattested = replace(evidence, admission=None)
    verification = verify_demo_run(unattested)
    assert verification.ok is False
    assert verification.refusals[0].startswith(RULE_SANDBOX_ADMISSION_MISSING)
    assert "not a policy-free zone" in verification.refusals[0]


def test_the_admission_record_states_its_own_reasons(sandbox_dir: Path, runner: FakeRunner):
    _, environment = _provision(sandbox_dir, runner)
    graph = sandbox_topology(environment.compose_path)
    evidence = _training_run(
        _demo_service(), graph, _plan("svc-cache", graph), sandbox=environment.name
    )
    assert evidence.admission is not None
    assert "admitted" in evidence.admission.describe()
    assert "ceilings breached none" in evidence.admission.describe()


def test_the_facade_runs_against_the_provisioned_sandbox_and_its_own_guard(
    sandbox_dir: Path, runner: FakeRunner
):
    """One guard, shared by provisioning and runs, and the sandbox's own topology."""
    service = sandbox_service(runner, policy=DEFAULT_POLICY)
    environment = service.provision(SandboxRequest(name="sbx", directory=sandbox_dir))
    graph = service.topology(environment)
    evidence = service.run(environment, _plan("svc-cache", graph), _ctx())
    assert service.guard() is service.demo.guard
    assert evidence.sandbox == "sbx"
    assert evidence.network.resolved is True
    assert NO_MUTATION_PHRASE in evidence.banner
    assert isinstance(service, SandboxService)
    assert SandboxAdmission.from_report(
        evidence.report, ceilings=SANDBOX_CEILINGS, deployment_model=DeploymentModel.LOCAL
    ).admitted is True


def test_a_second_provision_of_the_same_directory_is_independent(
    sandbox_dir: Path, runner: FakeRunner
):
    """Two sandboxes, two names, two compose projects — nothing is shared implicitly."""
    provisioner = SandboxProvisioner(runner=runner)
    first = provisioner.provision(SandboxRequest(name="one", directory=sandbox_dir / "a"))
    second = provisioner.provision(SandboxRequest(name="two", directory=sandbox_dir / "b"))
    assert first.compose_path != second.compose_path
    assert "name: one" in first.compose_path.read_text(encoding="utf-8")
    assert "name: two" in second.compose_path.read_text(encoding="utf-8")
    assert first.ready and second.ready


# --- network policy: the decision matrix -------------------------------------------


def test_the_proxy_is_the_route_a_permitted_call_takes():
    policy = NetworkPolicy(
        http_proxy=CORP_PROXY,
        allowlist_enforced=True,
        outbound_allowlist=frozenset({"proxy.corp.example", "api.corp.example"}),
    )
    decision = resolve_egress(policy, "api.corp.example", scheme="http")
    assert decision.allowed is True
    assert decision.via_proxy == CORP_PROXY
    assert decision.rule_id == RULE_EGRESS_PERMITTED
    assert "routed through" in decision.reason


def test_a_proxy_the_allowlist_does_not_name_is_refused_rather_than_bypassed():
    """The whole point of a proxy: falling back to direct would be the unsanctioned egress."""
    policy = NetworkPolicy(
        http_proxy=CORP_PROXY,
        allowlist_enforced=True,
        outbound_allowlist=frozenset({"api.corp.example"}),
    )
    decision = resolve_egress(policy, "api.corp.example", scheme="http")
    assert decision.allowed is False
    assert decision.rule_id == RULE_PROXY_NOT_ALLOWED
    assert "would be an egress the operator did not sanction" in decision.reason
    assert decision.via_proxy == ""


def test_the_proxy_is_resolved_per_scheme():
    policy = NetworkPolicy(https_proxy="http://secure.corp.example:3128")
    assert proxy_for(policy, "https") == "http://secure.corp.example:3128"
    assert proxy_for(policy, "http") == ""
    assert proxy_for(policy, "ssh") == ""


def test_an_allowlist_permits_only_a_declared_host():
    policy = NetworkPolicy(
        allowlist_enforced=True,
        outbound_allowlist=frozenset({"registry.corp.example", "git.corp.example"}),
    )
    permitted = resolve_egress(policy, "registry.corp.example")
    assert permitted.allowed is True
    assert permitted.rule_id == RULE_EGRESS_PERMITTED
    assert resolve_egress(policy, "metrics.corp.example").allowed is False


def test_an_undeclared_host_is_refused_by_the_enforced_allowlist():
    """The negative control on the allowlist: an undeclared host does not get through."""
    policy = NetworkPolicy(
        allowlist_enforced=True, outbound_allowlist=frozenset({"registry.corp.example"})
    )
    decision = resolve_egress(policy, "evil.example.net")
    assert decision.allowed is False
    assert decision.rule_id == RULE_ALLOWLIST_DENIED
    assert "outbound allowlist is enforced" in decision.reason
    assert "registry.corp.example" in decision.reason


def test_an_enforced_but_empty_allowlist_permits_nothing():
    """Distinct from "no allowlist configured", and a valid way to run."""
    decision = resolve_egress(
        NetworkPolicy(allowlist_enforced=True), "anything.example"
    )
    assert decision.allowed is False
    assert decision.rule_id == RULE_ALLOWLIST_DENIED
    # Not enforced: unrestricted egress, disclosed as a configuration fact.
    unconfigured = resolve_egress(NetworkPolicy(), "anything.example")
    assert unconfigured.allowed is True
    assert "configuration fact, not a clearance" in unconfigured.reason


def test_a_declared_ca_bundle_is_resolved_and_verified():
    policy = NetworkPolicy(custom_ca_bundle="/etc/mayhem/corp-ca.pem")
    resolution = resolve_ca_bundle(policy, lambda path: b"-----BEGIN CERTIFICATE-----\n")
    assert resolution.declared == "/etc/mayhem/corp-ca.pem"
    assert resolution.verified is True
    assert resolution.byte_count == len(b"-----BEGIN CERTIFICATE-----\n")
    assert resolution.refusal == ""
    guard = NetworkPolicyGuard.build(
        policy, ca_reader=lambda path: b"-----BEGIN CERTIFICATE-----\n"
    )
    assert guard.ready is True
    assert guard.ca.refusal == ""


def test_a_declared_ca_that_cannot_be_read_fails_closed():
    """Declared-but-unreadable must not degrade to the platform trust store."""
    policy = NetworkPolicy(custom_ca_bundle="/etc/mayhem/missing-ca.pem")

    def _boom(path: str) -> bytes:
        raise OSError(f"no such file: {path}")

    resolution = resolve_ca_bundle(policy, _boom)
    assert resolution.verified is False
    assert resolution.rule_id == RULE_CA_BUNDLE_UNREADABLE
    assert "OSError" in resolution.reason

    readers: list[Callable[[str], bytes] | None] = [None, lambda path: b"   "]
    for reader in readers:
        guard = NetworkPolicyGuard.build(policy, ca_reader=reader)
        assert guard.ready is False
        assert guard.readiness_refusal().startswith(RULE_CA_BUNDLE_UNREADABLE)
        # The guard refuses the call; the pure resolver is only about reachability
        # and does not pretend to know what the CA reader did.
        assert guard.refusal_for("https://api.corp.example/v1").startswith(
            RULE_CA_BUNDLE_UNREADABLE
        )
        assert resolve_egress_url(policy, "https://api.corp.example/v1").allowed is True


def test_no_ca_declared_is_not_a_failure():
    resolution = resolve_ca_bundle(NetworkPolicy(), None)
    assert resolution.declared_and_unverified is False
    assert resolution.verified is False
    assert "platform trust store" in resolution.reason
    assert NetworkPolicyGuard.build(NetworkPolicy()).ready is True


def test_an_air_gapped_policy_refuses_every_host_and_names_the_air_gap():
    policy = NetworkPolicy(air_gapped=True)
    for host in ("api.example", "docker.io", "anything"):
        decision = resolve_egress(policy, host)
        assert decision.allowed is False
        assert decision.rule_id == RULE_AIR_GAPPED
        assert "air-gapped" in decision.reason


def test_a_policy_that_cannot_resolve_fails_closed_for_every_host():
    """The negative control: an air gap declared alongside an allowlist is neither enforced."""
    policy = NetworkPolicy(air_gapped=True, outbound_allowlist=frozenset({"a.example"}))
    resolution = resolve_policy(policy)
    assert resolution.resolved is False
    assert resolution.rule_id == "network_policy.air_gapped_with_allowlist"
    assert resolution.refusal().startswith("network_policy.air_gapped_with_allowlist")
    for host in ("a.example", "b.example"):
        decision = resolve_egress(policy, host)
        assert decision.allowed is False
        assert decision.rule_id == resolution.rule_id
        assert "mayhem will not enforce half of it" in decision.reason


def test_a_url_with_no_destination_is_refused():
    for url in ("not-a-url", "ssh://git.corp.example/repo.git", "file:///etc/passwd", ""):
        decision = resolve_egress_url(NetworkPolicy(), url)
        assert decision.allowed is False
        assert decision.rule_id == RULE_UNPARSEABLE_URL


def test_a_url_is_parsed_into_the_destination_the_allowlist_matches():
    request = parse_egress_request("https://Registry.Corp.Example:5000/v2/")
    assert request is not None
    assert request.scheme == "https"
    assert request.host == "registry.corp.example"
    assert request.port == 5000
    assert parse_egress_request("https://registry.corp.example/v2/").port is None
    assert parse_egress_request("https://registry.corp.example:notaport/") is None


def test_an_allowlist_entry_carrying_a_port_is_not_a_licence_for_the_whole_host():
    policy = NetworkPolicy(
        allowlist_enforced=True, outbound_allowlist=frozenset({"db.internal:5432"})
    )
    assert resolve_egress(policy, "db.internal", port=5432).allowed is True
    assert resolve_egress(policy, "db.internal", port=22).allowed is False


def test_policy_resolution_is_pure():
    """Same inputs, same answer, no clock and no file — so it can be reasoned about."""
    policy = NetworkPolicy(http_proxy=CORP_PROXY, allowlist_enforced=True)
    first = resolve_policy(policy, model=DeploymentModel.LOCAL)
    second = resolve_policy(policy, model=DeploymentModel.LOCAL)
    assert first == second
    assert first.resolved is True
    assert first.requires_egress is True
    assert resolve_policy(policy, model=DeploymentModel.AIR_GAPPED).resolved is False


def test_an_air_gapped_model_whose_policy_forgets_the_air_gap_fails_closed():
    """Two declarations, two files: the cross-check is the only thing that catches this."""
    resolution = resolve_policy(NetworkPolicy(), model=DeploymentModel.AIR_GAPPED)
    assert resolution.resolved is False
    assert resolution.rule_id == "deployment_model.air_gapped_without_policy"
    guard = NetworkPolicyGuard.build(NetworkPolicy(), model=DeploymentModel.AIR_GAPPED)
    assert guard.ready is False
    assert guard.refusal_for("https://api.example") != ""
    with pytest.raises(EgressRefusedError) as refusal:
        guard.fetch("https://api.example")
    assert refusal.value.rule == "deployment_model.air_gapped_without_policy"


# --- network policy: enforcement ---------------------------------------------------


def test_egress_under_an_air_gap_fails_closed_before_the_transport():
    """The negative control on the air gap: no socket is opened, and the cause is named."""
    transport = FakeTransport()
    guard = NetworkPolicyGuard.build(
        NetworkPolicy(air_gapped=True),
        model=DeploymentModel.AIR_GAPPED,
        transport=transport,
    )
    with pytest.raises(EgressRefusedError) as refusal:
        guard.fetch("https://registry.corp.example/v2/")
    assert refusal.value.rule == RULE_AIR_GAPPED
    assert "air-gapped" in str(refusal.value)
    assert transport.calls == []


def test_a_refused_egress_is_still_recorded_in_the_ledger():
    """A ledger holding only the calls that happened is empty on the install whose log
    somebody needs."""
    transport = FakeTransport()
    guard = NetworkPolicyGuard.build(
        NetworkPolicy(air_gapped=True),
        model=DeploymentModel.AIR_GAPPED,
        transport=transport,
    )
    with pytest.raises(EgressRefusedError):
        guard.fetch("https://registry.corp.example/v2/")
    assert len(guard.attempts) == 1
    assert guard.hosts() == ("registry.corp.example",)
    assert guard.attempts[0].allowed is False
    assert "refused 1" in guard.describe()


def test_a_permitted_call_reaches_the_transport_with_the_policy_answers():
    transport = FakeTransport(b'{"ok": true}')
    guard = NetworkPolicyGuard.build(NetworkPolicy(), transport=transport, timeout_s=1.5)
    assert guard.fetch("https://api.corp.example/v1/things") == b'{"ok": true}'
    assert transport.calls == [("api.corp.example", 1.5)]
    assert guard.hosts() == ("api.corp.example",)


def test_a_permitted_call_with_no_transport_is_refused_rather_than_skipped():
    """A caller waiting on a result must not be told it succeeded."""
    guard = NetworkPolicyGuard.build(NetworkPolicy())
    with pytest.raises(EgressRefusedError) as refusal:
        guard.fetch("https://api.corp.example/v1")
    assert refusal.value.rule == RULE_NO_TRANSPORT
    assert "refused rather than silently dropped" in str(refusal.value)


def test_a_transport_failure_is_named_and_wrapped():
    class Broken:
        def fetch(self, request: EgressRequest, *, timeout_s: float) -> bytes:
            raise TimeoutError("read timed out")

    guard = NetworkPolicyGuard.build(NetworkPolicy(), transport=Broken())
    with pytest.raises(EgressRefusedError) as refusal:
        guard.fetch("https://api.corp.example/v1")
    assert refusal.value.rule == "network_policy.transport_failed"
    assert "TimeoutError" in str(refusal.value)


def test_an_existing_connector_is_guarded_by_passing_the_opener():
    """The integration seam: one argument guards every request an existing helper makes."""
    transport = FakeTransport(b'{"result": [1]}')
    guard = NetworkPolicyGuard.build(
        NetworkPolicy(
            allowlist_enforced=True, outbound_allowlist=frozenset({"metrics.internal"})
        ),
        transport=transport,
    )
    assert fetch_json("http://metrics.internal/api/v1/query", opener=guard.opener()) == {
        "result": [1]
    }
    assert transport.calls == [("metrics.internal", 5.0)]
    assert guard.attempts[0].allowed is True

    with pytest.raises(ConnectorError) as refusal:
        fetch_json("http://prom.example/api/v1/query", opener=guard.opener())
    assert RULE_ALLOWLIST_DENIED in str(refusal.value)
    assert transport.calls == [("metrics.internal", 5.0)]


def test_a_connector_in_an_air_gapped_install_fails_with_a_named_cause():
    transport = FakeTransport()
    guard = NetworkPolicyGuard.build(
        NetworkPolicy(air_gapped=True),
        model=DeploymentModel.AIR_GAPPED,
        transport=transport,
    )
    with pytest.raises(ConnectorError) as refusal:
        fetch_json("http://metrics.internal/api/v1/query", opener=guard.opener())
    assert RULE_AIR_GAPPED in str(refusal.value)
    assert "air-gapped" in str(refusal.value)
    assert transport.calls == []


def test_the_guard_describes_its_policy_and_its_ca():
    transport = FakeTransport()
    guard = NetworkPolicyGuard.build(
        NetworkPolicy(http_proxy=CORP_PROXY, custom_ca_bundle="/etc/ca.pem"),
        ca_reader=lambda path: b"-----BEGIN CERTIFICATE-----",
        transport=transport,
    )
    described = guard.describe()
    assert "policy resolved" in described
    assert "custom CA" in described
    assert "external calls resolved: 0" in described
    guard.fetch("https://api.corp.example")
    assert "external calls resolved: 1 (permitted 1, refused 0)" in guard.describe()


# --- network policy: provisioning honours it ---------------------------------------


def test_sandbox_provisioning_refuses_before_any_command_under_an_air_gap(sandbox_dir: Path):
    """Pulling images is egress, so the air gap stops it before the runtime is asked."""
    runner = FakeRunner()
    # The guard is pinned: the provisioner honours the guard it was handed, which
    # is how an install whose resolved policy is air-gapped reaches this path at
    # all (`sandbox.provisioning` is a local-model flag, so the request stays on
    # the local model while the network answer comes from the pinned guard).
    provisioner = SandboxProvisioner(
        runner=runner,
        guard=NetworkPolicyGuard.build(
            NetworkPolicy(air_gapped=True),
            model=DeploymentModel.AIR_GAPPED,
        ),
    )
    with pytest.raises(SandboxRefusedError) as refusal:
        provisioner.provision(SandboxRequest(name="sbx", directory=sandbox_dir))
    assert refusal.value.rule == RULE_SANDBOX_IMAGE_EGRESS_REFUSED
    assert "air-gapped" in str(refusal.value)
    assert "No image was pulled and no stack was created" in str(refusal.value)
    assert runner.calls == []


def test_sandbox_provisioning_refuses_an_undeclared_registry_under_an_allowlist(
    sandbox_dir: Path,
):
    """`ghcr.io` is not on the allowlist, so the sandbox is not provisioned at all."""
    runner = FakeRunner()
    provisioner = SandboxProvisioner(
        runner=runner,
        guard=NetworkPolicyGuard.build(
            NetworkPolicy(
                allowlist_enforced=True, outbound_allowlist=frozenset({"docker.io"})
            ),
            model=DeploymentModel.LOCAL,
        ),
    )
    with pytest.raises(SandboxRefusedError) as refusal:
        provisioner.provision(
            SandboxRequest(
                name="sbx",
                directory=sandbox_dir,
                policy=NetworkPolicy(
                    allowlist_enforced=True, outbound_allowlist=frozenset({"docker.io"})
                ),
            )
        )
    assert refusal.value.rule == RULE_SANDBOX_IMAGE_EGRESS_REFUSED
    assert "ghcr.io" in str(refusal.value)
    assert RULE_ALLOWLIST_DENIED in str(refusal.value)
    assert runner.calls == []


def test_sandbox_provisioning_refuses_when_the_policy_cannot_be_enforced(
    sandbox_dir: Path, runner: FakeRunner
):
    """A contradictory policy stops provisioning; it is not half-enforced."""
    provisioner = SandboxProvisioner(runner=runner)
    with pytest.raises(SandboxRefusedError) as refusal:
        provisioner.provision(
            SandboxRequest(
                name="sbx",
                directory=sandbox_dir,
                policy=NetworkPolicy(
                    air_gapped=True, outbound_allowlist=frozenset({"docker.io"})
                ),
            )
        )
    assert refusal.value.rule == RULE_SANDBOX_POLICY_UNRESOLVED
    # The provisioner's rule plus the policy's own cause, both named.
    assert "network_policy.air_gapped_with_allowlist" in str(refusal.value)
    assert "before the first command" in str(refusal.value)
    assert runner.calls == []


def test_sandbox_provisioning_refuses_when_the_declared_ca_was_not_supplied(
    sandbox_dir: Path, runner: FakeRunner
):
    provisioner = SandboxProvisioner(runner=runner)
    with pytest.raises(SandboxRefusedError) as refusal:
        provisioner.provision(
            SandboxRequest(
                name="sbx",
                directory=sandbox_dir,
                policy=NetworkPolicy(custom_ca_bundle="/etc/mayhem/corp-ca.pem"),
            )
        )
    assert refusal.value.rule == RULE_SANDBOX_POLICY_UNRESOLVED
    assert RULE_CA_BUNDLE_UNREADABLE in str(refusal.value)
    assert runner.calls == []


def test_the_facade_shares_one_guard_between_provisioning_and_runs(
    sandbox_dir: Path, runner: FakeRunner
):
    """Two halves resolving egress differently is an install that disagrees with itself."""
    policy = NetworkPolicy(
        allowlist_enforced=True, outbound_allowlist=frozenset({"docker.io", "ghcr.io"})
    )
    service = sandbox_service(runner, policy=policy)
    environment = service.provision(SandboxRequest(name="sbx", directory=sandbox_dir))
    assert service.provisioner.guard_for(
        SandboxRequest(name="x", directory=sandbox_dir)
    ) is not service.guard()
    assert service.guard().policy == policy
    assert [attempt.host for attempt in environment.attempts] == ["docker.io", "ghcr.io"]


def test_the_enterprise_policy_matrix_end_to_end_through_one_guard():
    """The full gap-77 vocabulary in one object, resolved host by host."""
    policy = NetworkPolicy(
        http_proxy=CORP_PROXY,
        https_proxy=CORP_PROXY,
        custom_ca_bundle="/etc/mayhem/corp-ca.pem",
        private_registry="registry.corp.example",
        private_git="git@git.corp.example:platform.git",
        allowlist_enforced=True,
        outbound_allowlist=frozenset(
            {"proxy.corp.example", "registry.corp.example", "git.corp.example"}
        ),
    )
    transport = FakeTransport()
    guard = NetworkPolicyGuard.build(
        policy,
        ca_reader=lambda path: b"-----BEGIN CERTIFICATE-----",
        transport=transport,
    )
    assert guard.ready is True
    permitted = resolve_egress_url(
        policy, "https://registry.corp.example/v2/", model=DeploymentModel.LOCAL
    )
    assert permitted.allowed is True
    assert permitted.via_proxy == CORP_PROXY
    # Drop the proxy from the allowlist and the same destination is refused for a
    # different, named reason: a direct fallback would be unsanctioned egress.
    policy_without_proxy = replace(
        policy, outbound_allowlist=frozenset({"registry.corp.example"})
    )
    denied = resolve_egress_url(
        policy_without_proxy, "https://registry.corp.example/v2/", model=DeploymentModel.LOCAL
    )
    assert denied.allowed is False
    assert denied.rule_id == RULE_PROXY_NOT_ALLOWED
    assert guard.fetch("https://registry.corp.example/v2/", timeout_s=2.0) == b'{"status": "ok"}'


def test_the_guard_reports_the_policys_own_rule_id_and_not_a_generic_one():
    """"Your policy is inadmissible" is the conclusion; the rule id is the cause to fix."""
    guard = NetworkPolicyGuard.build(
        NetworkPolicy(air_gapped=True, outbound_allowlist=frozenset({"a.example"}))
    )
    with pytest.raises(EgressRefusedError) as refusal:
        guard.fetch("https://a.example/v1")
    assert refusal.value.rule == "network_policy.air_gapped_with_allowlist"
    assert RULE_UNRESOLVED_POLICY not in str(refusal.value)
    assert guard.readiness_refusal().startswith("network_policy.air_gapped_with_allowlist")
