"""Plan 20 Phase 2 — the sandbox provisioner, demo/training mode, and the
admission ceilings a sandbox run is held to.

Three things land here, and the reason they share a module is that they are
three faces of one claim: *this run cannot touch anything that matters, and here
is the evidence that it did not.*

**The sandbox is the existing compose blueprint, not a second topology stack.**
:func:`render_compose_document` turns :data:`SANDBOX_BLUEPRINT` — one entry per
:class:`~mayhem.domain.deployment.SandboxComponent`, so the vocabulary is the
blueprint and not a hand-kept copy of it — into a compose document, and the
provisioner reads that document back through
:class:`~mayhem.topology.providers.compose.ComposeFileProvider`, the same
provider that reads a customer's ``docker-compose.yaml``. :func:`sandbox_topology`
builds a real :class:`~mayhem.domain.topology.TopologyGraph` from what the
provider found, which is the graph a sandbox run's plan is planned against. A
sandbox that described its own services in its own data structure would be a
topology nothing else in the product could read.

**Provisioning is driven by an injected runner, so no container runtime is
required to test it.** :class:`SandboxRunner` is one method,
:meth:`~SandboxRunner.run`, returning a :class:`CommandOutcome`. The unit suite
supplies a recording fake; the CLI will supply the container runtime. Nothing in
this module shells out by itself.

**A failed provisioning is a refusal, never a half-built environment.** The
environment record is built *after* the last check passes, so there is no value
of :class:`SandboxEnvironment` describing a half-provisioned stack. Every failure
after the compose file exists attempts a rollback through the same runner and
then raises :class:`SandboxRefusedError` carrying the rule id, the command's own
stderr, and whether the rollback itself worked. :attr:`SandboxEnvironment.ready`
is *derived* from the recorded components rather than set by the caller, so a
miscounted environment cannot claim to be ready.

**Demo mode is the existing simulate path with a friendlier face.** This module
contains no second simulation mechanism and no second purity argument.
:class:`DemoModeService` builds a
:class:`~mayhem.controller.prediction_service.PredictionService`, hands it the
caller's :class:`~mayhem.domain.policy_gate.MutationSink`, and calls
:meth:`~mayhem.controller.prediction_service.PredictionService.simulate_plan` —
which evaluates through its own ``detached()`` copy and reports the *observed*
length of that sink afterwards.

That reported length is the sink's length, not the number of calls this run made,
so this module takes the *other* reading itself: the length before the call, kept
on the evidence as :attr:`DemoRunEvidence.sink_calls_before`. The assertion is that
the two are equal. A caller who hands over a pre-loaded sink therefore still gets a
run, and the proof is still a measurement of a real object — the same one
``tests/unit/test_prediction_service.py`` pre-loads to show its number is a reading
and not a constant — while a simulate path that ever wrote a call would move the
length and be refused. A regression in the simulate path cannot be laundered here.

**The marker cannot be forgotten or forged.** Every field of the evidence is
derived from Phase 1's sealed
:class:`~mayhem.domain.deployment.ModeMarker`, which
:func:`~mayhem.domain.deployment.sealed_mode_marker` builds from the mode alone.
:attr:`DemoRunEvidence.banner` is a property that reads the sealed marker, so a
renderer that "forgets" the banner cannot produce one without the phrase — and
:func:`verify_demo_run` refuses an evidence record whose banner does not carry
it. Promotion to production is refused from three directions: the sealed
marker (:func:`~mayhem.domain.deployment.production_presentation_refusal`), a
later flag (:func:`~mayhem.domain.deployment.flag_drift_refusal`, exposed as
:meth:`DemoRunEvidence.refusal_for_mode`), and flag *resolution* —
``demo.mode`` is not production-safe, so
:func:`~mayhem.domain.deployment.resolve_flags` refuses it in a production run.

**A sandbox is not a policy-free zone.** :data:`SANDBOX_CEILINGS` are the plan-14
ceilings a sandbox run is held to, and they are *tighter* than production's
defaults — the sandbox has six components, so a blast that would be unremarkable
in a fleet is most of a sandbox. They are enforced on the seam that already
exists: :meth:`DemoModeService.run` puts them in
:class:`~mayhem.controller.prediction_service.PredictionConfig`, the preview
reports them as :class:`~mayhem.controller.prediction_service.CeilingVerdict`
records, and :class:`SandboxAdmission` reads *those records* rather than
recomputing anything. The real gate still runs — ``simulate_plan`` calls
``validate_plan`` on a cloned context — so admission is the same admission, and
the sandbox's extra ceilings sit on top of it rather than replacing it.

**Network policy is enforced before the runtime is asked to do anything.**
Provisioning pulls images, which is egress, so every registry host the blueprint
names is resolved through :class:`~mayhem.infra.network_policy.NetworkPolicyGuard`
*before* the first command is issued; a denied resolution refuses with the cause
named and no environment is created. Stated plainly because it is a real limit:
the container runtime performs the transfer, so this is a pre-flight gate on the
command, not an interception of the runtime's own socket traffic.

Negative controls that must stay green, because each is the failure this module
exists to make impossible:

* a provisioning failure is a refusal, and a rollback is attempted;
* a sandbox run whose admission was refused, or whose evidence carries no
  admission record at all, is refused (:func:`verify_demo_run`);
* a policy that cannot resolve fails closed for every host;
* a declared custom CA that was not supplied fails closed;
* an undeclared host is refused by the enforced allowlist;
* an egress attempt under an air gap fails closed, naming the air gap, and the
  transport is never reached.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from mayhem.controller.prediction_service import (
    MutationProof,
    PredictionConfig,
    PredictionService,
)
from mayhem.domain.deployment import (
    NO_MUTATION_PHRASE,
    SANDBOX_COMPONENTS,
    SANDBOX_DEPLOYMENT_MODEL,
    DeploymentModel,
    ExecutionMode,
    FlagResolution,
    ModeClaim,
    NetworkPolicy,
    SandboxComponent,
    feature_flag,
    flag_drift_refusal,
    production_presentation_refusal,
    resolve_flags,
    sealed_mode_marker,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.prediction import BlastCeilings
from mayhem.domain.topology import TopologyGraph
from mayhem.infra.network_policy import NetworkPolicyGuard, PolicyResolution
from mayhem.infra.project_detection import find_compose_files
from mayhem.topology.providers.compose import ComposeFileProvider

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from mayhem.controller.prediction_service import CeilingVerdict, SimulateReport
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.policy_gate import MutationSink
    from mayhem.infra.network_policy import (
        CaResolution,
        EgressAttempt,
        EgressTransport,
    )

__all__ = [
    "COMPOSE_FILENAME",
    "DEFAULT_COMPOSE_ARGV",
    "DEFAULT_POLICY",
    "RULE_DEMO_FLAG_REFUSED",
    "RULE_DEMO_MARKER_FORGED",
    "RULE_DEMO_MARKER_MISSING",
    "RULE_DEMO_MARKER_PROMOTION",
    "RULE_DEMO_MUTATION_OBSERVED",
    "RULE_DEMO_PRODUCTION_MODE_REFUSED",
    "RULE_SANDBOX_ADMISSION_MISSING",
    "RULE_SANDBOX_ADMISSION_REFUSED",
    "RULE_SANDBOX_BLUEPRINT_INCOMPLETE",
    "RULE_SANDBOX_BLUEPRINT_INVALID",
    "RULE_SANDBOX_COMPONENTS_UNREADY",
    "RULE_SANDBOX_COMPOSE_UNDISCOVERABLE",
    "RULE_SANDBOX_FLAG_REFUSED",
    "RULE_SANDBOX_IMAGE_EGRESS_REFUSED",
    "RULE_SANDBOX_IMAGE_PULL_FAILED",
    "RULE_SANDBOX_INVALID_NAME",
    "RULE_SANDBOX_POLICY_UNRESOLVED",
    "RULE_SANDBOX_PRODUCTION_MODE_REFUSED",
    "RULE_SANDBOX_START_FAILED",
    "SANDBOX_BLUEPRINT",
    "SANDBOX_CEILINGS",
    "CommandOutcome",
    "DemoModeService",
    "DemoRunEvidence",
    "DemoRunRequest",
    "RunVerification",
    "SandboxAdmission",
    "SandboxEnvironment",
    "SandboxProvisioner",
    "SandboxRefusedError",
    "SandboxRequest",
    "SandboxRunner",
    "SandboxService",
    "SandboxTeardown",
    "blueprint_registry_hosts",
    "blueprint_services",
    "image_registry",
    "render_compose_document",
    "require_verified_run",
    "sandbox_service",
    "sandbox_topology",
    "verify_demo_run",
]

# --- stable rule ids -------------------------------------------------------------


class SandboxRefusedError(InvariantViolationError):
    """A sandbox or demo-mode operation was refused. The cause is always named.

    :class:`~mayhem.domain.errors.InvariantViolationError` is the base because
    every refusal in this product is a typed error safe to render, log, and
    persist, and because the sandbox's callers are the same callers that already
    catch domain errors. The separate type is because *this* refusal is
    actionable by an operator — permit the host, fix the bundle, lower the
    ceiling, change the mode — rather than a broken invariant in the code.
    """


#: The sandbox blueprint is a *file*, not a directory. One name, one compose
#: document, so "the sandbox" and "the compose file" cannot be two things.
COMPOSE_FILENAME = "docker-compose.yml"

#: How the runtime is invoked. Injectable so a caller driving podman or a
#: test double can say so; the argv shape after this prefix is stable.
DEFAULT_COMPOSE_ARGV: tuple[str, ...] = ("docker", "compose")

RULE_SANDBOX_INVALID_NAME = "sandbox.invalid_name"
RULE_SANDBOX_FLAG_REFUSED = "sandbox.flag_refused"
RULE_SANDBOX_PRODUCTION_MODE_REFUSED = "sandbox.production_mode_refused"
RULE_SANDBOX_POLICY_UNRESOLVED = "sandbox.policy_unresolved"
RULE_SANDBOX_IMAGE_EGRESS_REFUSED = "sandbox.image_egress_refused"
RULE_SANDBOX_COMPOSE_UNDISCOVERABLE = "sandbox.compose_undiscoverable"
RULE_SANDBOX_BLUEPRINT_INCOMPLETE = "sandbox.blueprint_incomplete"
RULE_SANDBOX_BLUEPRINT_INVALID = "sandbox.blueprint_invalid"
RULE_SANDBOX_IMAGE_PULL_FAILED = "sandbox.image_pull_failed"
RULE_SANDBOX_START_FAILED = "sandbox.start_failed"
RULE_SANDBOX_COMPONENTS_UNREADY = "sandbox.components_unready"
RULE_SANDBOX_ADMISSION_REFUSED = "sandbox.admission_refused"
RULE_SANDBOX_ADMISSION_MISSING = "sandbox.admission_missing"
RULE_DEMO_PRODUCTION_MODE_REFUSED = "demo.production_mode_refused"
RULE_DEMO_FLAG_REFUSED = "demo.flag_refused"
RULE_DEMO_MARKER_PROMOTION = "demo.marker_promotion"
RULE_DEMO_MARKER_MISSING = "demo.marker_missing_phrase"
RULE_DEMO_MARKER_FORGED = "demo.marker_forged"
RULE_DEMO_MUTATION_OBSERVED = "demo.mutation_observed"

#: The compose project name has to survive Docker's own normalisation, so the
#: name is validated here rather than discovered to be illegal after ``up``.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

#: The default policy: no air gap, no proxy, no enforced allowlist — which is a
#: *configuration fact* (unrestricted egress), never a clearance. A singleton
#: rather than a call in a default, because the dataclass defaults below must not
#: be rebuilt per instantiation.
DEFAULT_POLICY: NetworkPolicy = NetworkPolicy()

#: The feature flag that has to be granted before a sandbox may be provisioned.
#: Named from Phase 1's registry rather than spelled out, so deleting the flag
#: breaks this module loudly instead of leaving a check against nothing.
SANDBOX_FLAG = feature_flag("sandbox.provisioning").key

#: The flag that marks a run as a demonstration. Requested on every demo run so
#: that (a) the grant is recorded in the sealed claim's audit trail and (b) a
#: production run asking for it is refused by ``flag.production_unsafe``.
DEMO_FLAG = feature_flag("demo.mode").key


# --- the blueprint ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SandboxServiceSpec:
    """One compose service in the sandbox blueprint.

    ``depends_on`` is expressed in components rather than service names so the
    blueprint cannot name a service that is not in it: every entry resolves
    through :attr:`SandboxComponent`, and :func:`sandbox_topology` reads the
    result back through the compose provider, which drops a dependency on an
    unknown service rather than inventing a node for it.
    """

    component: SandboxComponent
    service: str
    image: str
    ports: tuple[int, ...] = ()
    depends_on: tuple[SandboxComponent, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    healthcheck: str = ""


#: The built-in test environment: frontend, api, database, cache, queue,
#: observability — every member of
#: :data:`~mayhem.domain.deployment.SANDBOX_COMPONENTS`, in that order, and no
#: others. ``SANDBOX_COMPONENTS`` is the vocabulary; this is the implementation
#: of it, and a test asserts the two agree so neither can drift from the other.
#:
#: Only ``frontend`` publishes a port, on purpose: the plan-14
#: customer-facing-services ceiling counts exposed services, so a blueprint that
#: published six of them would make that ceiling meaningless.
SANDBOX_BLUEPRINT: tuple[SandboxServiceSpec, ...] = (
    SandboxServiceSpec(
        component=SandboxComponent.FRONTEND,
        service="frontend",
        image="nginx:1.27-alpine",
        ports=(8080,),
        depends_on=(SandboxComponent.API,),
        healthcheck="wget -q -O /dev/null http://localhost:8080/ || exit 1",
    ),
    SandboxServiceSpec(
        component=SandboxComponent.API,
        service="api",
        image="ghcr.io/mayhem/sandbox-api:1.1.0",
        depends_on=(
            SandboxComponent.DATABASE,
            SandboxComponent.CACHE,
            SandboxComponent.QUEUE,
            SandboxComponent.OBSERVABILITY,
        ),
        environment=(("SANDBOX_COMPONENT", "api"),),
        healthcheck="wget -q -O /dev/null http://localhost:8000/healthz || exit 1",
    ),
    SandboxServiceSpec(
        component=SandboxComponent.DATABASE,
        service="database",
        image="postgres:16-alpine",
        environment=(("POSTGRES_PASSWORD", "sandbox"), ("SANDBOX_COMPONENT", "database")),
        healthcheck="pg_isready -U postgres",
    ),
    SandboxServiceSpec(
        component=SandboxComponent.CACHE,
        service="cache",
        image="redis:7-alpine",
        environment=(("SANDBOX_COMPONENT", "cache"),),
        healthcheck="redis-cli ping",
    ),
    SandboxServiceSpec(
        component=SandboxComponent.QUEUE,
        service="queue",
        image="rabbitmq:3.13-alpine",
        environment=(("SANDBOX_COMPONENT", "queue"),),
        healthcheck="rabbitmq-diagnostics -q ping",
    ),
    SandboxServiceSpec(
        component=SandboxComponent.OBSERVABILITY,
        service="observability",
        image="prom/prometheus:v2.54.1",
        environment=(("SANDBOX_COMPONENT", "observability"),),
        healthcheck="wget -q -O /dev/null http://localhost:9090/-/ready || exit 1",
    ),
)


def blueprint_services(
    blueprint: Sequence[SandboxServiceSpec] = SANDBOX_BLUEPRINT,
) -> tuple[str, ...]:
    """The compose service names the blueprint declares, in blueprint order."""
    return tuple(spec.service for spec in blueprint)


def image_registry(image: str) -> str:
    """The registry host an image reference resolves from.

    A first path segment containing a dot or a colon, or literally ``localhost``,
    is a registry host; anything else is a Docker Hub library name. This is the
    same rule the runtime uses, and it is here because pulling an image *is* an
    egress and the policy has to be resolved against a host before the pull is
    issued.
    """
    head, _, _ = image.partition("/")
    if "/" in image and ("." in head or ":" in head or head == "localhost"):
        return head.lower()
    return "docker.io"


def blueprint_registry_hosts(
    blueprint: Sequence[SandboxServiceSpec] = SANDBOX_BLUEPRINT,
) -> tuple[str, ...]:
    """Every registry host the blueprint would pull from, deduplicated in order."""
    seen: dict[str, None] = {}
    for spec in blueprint:
        seen.setdefault(image_registry(spec.image), None)
    return tuple(seen)


def _yaml_inline(value: str) -> str:
    """Escape ``value`` for a double-quoted YAML flow scalar.

    The healthcheck command is rendered inside ``["CMD-SHELL", "..."]``, so a
    command containing a double quote would otherwise produce a document that no
    parser can read — and the sandbox's topology comes from parsing that document.
    Escaping here is cheaper than discovering it through a parse error at
    provisioning time.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_compose_document(
    blueprint: Sequence[SandboxServiceSpec] = SANDBOX_BLUEPRINT, *, project_name: str
) -> str:
    """Render ``blueprint`` as a compose document.

    Hand-rendered rather than ``yaml.dump``-ed for two reasons: the field order
    a human reads (image, ports, environment, depends_on, healthcheck) is the
    order it is written in, and the output is byte-stable, so a rendered document
    can be compared in a test and diffed in a review.

    ``depends_on`` is emitted with ``condition: service_healthy`` because that is
    what makes the compose provider weight the edge 2.0 — a healthcheck-gated
    dependency is a real ordering, not a start-order hint.
    """
    lines: list[str] = [f"name: {project_name}", "services:"]
    for spec in blueprint:
        lines.append(f"  {spec.service}:")
        lines.append(f"    image: {spec.image}")
        if spec.ports:
            lines.append("    ports:")
            lines.extend(f'      - "{port}:{port}"' for port in spec.ports)
        if spec.environment:
            lines.append("    environment:")
            lines.extend(f"      {key}: {value}" for key, value in spec.environment)
        if spec.depends_on:
            lines.append("    depends_on:")
            for dependency in spec.depends_on:
                lines.append(f"      {dependency.value}:")
                lines.append("        condition: service_healthy")
        if spec.healthcheck:
            lines.append("    healthcheck:")
            lines.append(f'      test: ["CMD-SHELL", "{_yaml_inline(spec.healthcheck)}"]')
            lines.append("      interval: 5s")
            lines.append("      retries: 12")
    return "\n".join(lines) + "\n"


def sandbox_topology(compose_path: Path) -> TopologyGraph:
    """The sandbox's own topology, read through the existing compose provider.

    The point of this function is what it does *not* do: it does not describe the
    sandbox's services from :data:`SANDBOX_BLUEPRINT`. It hands the written
    compose document to :class:`~mayhem.topology.providers.compose.ComposeFileProvider`
    — the same provider a customer's ``docker-compose.yaml`` goes through — and
    builds a graph from what that provider found. So a blueprint that renders
    something the provider cannot read produces an empty graph and a refused
    sandbox, rather than a graph describing an environment that does not exist.
    """
    partial = ComposeFileProvider(compose_path).discover()
    return TopologyGraph(nodes=partial.nodes, edges=partial.edges)


# --- the runner seam -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    """One command's result: the argv that was issued and what came back.

    ``argv`` is carried so a refusal can name the exact command an operator can
    re-run by hand. A sandbox failure whose message does not include the command
    is a support ticket; a failure that includes it is a retry.
    """

    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def command(self) -> str:
        return " ".join(self.argv)

    @property
    def detail(self) -> str:
        """Exit code plus whatever the runtime said, with the noise stripped."""
        parts = [f"exit {self.returncode}"]
        for label, stream in (("stdout", self.stdout.strip()), ("stderr", self.stderr.strip())):
            if stream:
                parts.append(f"{label}: {stream}")
        return " | ".join(parts)

    def services(self) -> tuple[str, ...]:
        """Service names the runtime reported, one per line of stdout."""
        return tuple(line.strip() for line in self.stdout.splitlines() if line.strip())


@runtime_checkable
class SandboxRunner(Protocol):
    """The one method provisioning needs from a container runtime.

    Injected, never implemented here. That is what lets the whole provisioning
    path — including the rollback — be exercised by the unit suite with a
    recording fake and no container runtime installed, and it is why
    :mod:`mayhem.infra.network_policy`'s honest limit is a limit about the
    runtime's *own* egress rather than about this module's.
    """

    def run(self, argv: Sequence[str]) -> CommandOutcome: ...


# --- requests, environments, refusals --------------------------------------------


@dataclass(frozen=True, slots=True)
class SandboxRequest:
    """What to provision, where, and under which policy and mode.

    ``model`` defaults to :data:`~mayhem.domain.deployment.SANDBOX_DEPLOYMENT_MODEL`
    because the sandbox *is* the local model — a remote deployment model's
    sandbox would be somebody's production cluster. ``mode`` defaults to
    :attr:`ExecutionMode.SAFE_DEMO` for the same reason: the thing a sandbox is
    provisioned *for* is a safe first run or a rehearsal, and a production mode
    is refused rather than quietly accepted.
    """

    name: str
    directory: Path
    policy: NetworkPolicy = DEFAULT_POLICY
    mode: ExecutionMode = ExecutionMode.SAFE_DEMO
    model: DeploymentModel = SANDBOX_DEPLOYMENT_MODEL
    requested_flags: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class SandboxEnvironment:
    """A provisioned sandbox. Constructed only once every check has passed.

    There is deliberately no way to build one of these describing a stack that is
    not up: the provisioner raises before it reaches the constructor, and
    :attr:`ready` is *derived* from the recorded components rather than passed
    in, so a record that lost a component says so instead of claiming health.
    """

    name: str
    directory: Path
    compose_path: Path
    blueprint_services: tuple[str, ...]
    components: tuple[SandboxComponent, ...]
    deployment_model: DeploymentModel
    registry_egress: tuple[tuple[str, str], ...]
    attempts: tuple[EgressAttempt, ...]
    commands: tuple[CommandOutcome, ...]
    ca: CaResolution

    @property
    def ready(self) -> bool:
        """True when the record covers the whole sandbox vocabulary.

        Derived, not stored: a record naming five of the six components is a
        half-built environment, and this is the single field a caller checks
        before pointing a plan at it.
        """
        return self.components == SANDBOX_COMPONENTS and self.blueprint_services == tuple(
            spec.value for spec in SANDBOX_COMPONENTS
        )

    @property
    def node_ids(self) -> tuple[str, ...]:
        """The node ids the compose provider produced, ``svc-<service>`` per service."""
        return tuple(f"svc-{service}" for service in self.blueprint_services)

    def describe(self) -> str:
        lines = [
            f"sandbox {self.name!r} at {self.compose_path} "
            f"[{self.deployment_model.value}, ready={self.ready}]",
            "components: " + ", ".join(component.value for component in self.components),
        ]
        for host, rule in self.registry_egress:
            lines.append(f"registry egress {host}: {rule}")
        lines.append(f"commands: {'; '.join(command.command for command in self.commands)}")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class SandboxTeardown:
    """The result of tearing a sandbox down, including a rollback that failed."""

    name: str
    removed: bool
    outcome: CommandOutcome
    refusal: str = ""


# --- the provisioner -------------------------------------------------------------


def _write_text(path: Path, document: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")


@dataclass(frozen=True, slots=True)
class SandboxProvisioner:
    """Builds the built-in test environment, and refuses cleanly when it cannot.

    ``runner`` is the only thing that touches a container runtime.
    ``guard`` is the network seam; when it is ``None`` a guard is built per
    request from that request's own policy and model, so two provisioners with
    different policies cannot share one another's answer by accident.

    The provisioning sequence is fixed and every step is checked:

    ``config``
        The runtime parses the rendered document. A blueprint that does not
        validate is refused here, before anything is pulled or started.
    ``pull``
        Images are fetched. Egress was already resolved before this command was
        issued, so an air-gapped install refuses before the runtime is asked.
    ``up --detach``
        The stack starts.
    ``ps --services --filter status=running``
        Every blueprint service must be reported running. Anything less is
        :data:`RULE_SANDBOX_COMPONENTS_UNREADY` with the missing names, because a
        sandbox with four of six components is not a sandbox and reporting it as
        ready is how a rehearsal discovers its own gap at the worst moment.
    """

    runner: SandboxRunner
    blueprint: tuple[SandboxServiceSpec, ...] = SANDBOX_BLUEPRINT
    compose_argv: tuple[str, ...] = DEFAULT_COMPOSE_ARGV
    writer: Callable[[Path, str], None] = _write_text
    guard: NetworkPolicyGuard | None = None
    ca_reader: Callable[[str], bytes] | None = None

    # -- helpers ---------------------------------------------------------------

    def guard_for(self, request: SandboxRequest) -> NetworkPolicyGuard:
        """The guard a request is enforced under.

        The provisioner's own ``guard`` wins when it was supplied — that is how a
        caller pins one resolved policy across a whole session — and otherwise the
        request's own policy and model are resolved here, so a sandbox's egress is
        decided by the sandbox's configuration rather than by ambient state.
        """
        if self.guard is not None:
            return self.guard
        return NetworkPolicyGuard.build(
            request.policy,
            model=request.model,
            ca_reader=self.ca_reader,
        )

    def _invoke(self, action: str, compose_path: Path, *args: str) -> CommandOutcome:
        """Run one compose action and return what came back. Never raises."""
        argv = (*self.compose_argv, "-f", str(compose_path), action, *args)
        return self.runner.run(argv)

    def _rollback(self, compose_path: Path) -> tuple[CommandOutcome, str]:
        """Best-effort teardown of a stack that failed to come up.

        The rollback's own failure is reported rather than raised over the
        original refusal: the operator's first question is why provisioning
        failed, and the second is whether anything was left running. Losing the
        first to answer the second is the wrong trade.
        """
        outcome = self._invoke("down", compose_path, "--volumes", "--remove-orphans")
        if outcome.ok:
            return outcome, (
                f"the partially started stack was rolled back with "
                f"`{outcome.command}` ({outcome.detail})"
            )
        return outcome, (
            f"ROLLBACK FAILED: `{outcome.command}` returned {outcome.detail}. The sandbox is "
            "not clean and may still be holding containers, volumes, and a published port; "
            "remove it by hand before retrying"
        )

    def _refuse_before_commands(self, request: SandboxRequest, guard: NetworkPolicyGuard) -> None:
        """Every check that must fail *before* the runtime is asked for anything.

        Kept together, and ahead of the write, for one reason: the refusal a
        caller sees on a misconfigured sandbox must be about the configuration,
        never about a container runtime error caused by it.
        """
        if not request.name or not _NAME_RE.match(request.name):
            raise SandboxRefusedError(
                RULE_SANDBOX_INVALID_NAME,
                f"sandbox name {request.name!r} is not a valid compose project name; use "
                "lowercase letters, digits, '-', and '_', starting with a letter or digit. "
                "The name becomes the compose project name, and Docker normalises it, so an "
                "illegal name would become a different name than the one requested",
            )
        if request.mode.is_production:
            raise SandboxRefusedError(
                RULE_SANDBOX_PRODUCTION_MODE_REFUSED,
                f"sandbox {request.name!r} was requested in {request.mode.value} mode. The "
                "sandbox is the disposable local environment a safe run and a rehearsal are "
                "practised against; a production run does not come through it, and a "
                "production mode here would produce evidence sealed as production for a "
                "throwaway stack",
            )
        resolution = resolve_flags(
            (*request.requested_flags, SANDBOX_FLAG),
            model=request.model,
            mode=request.mode,
        )
        if SANDBOX_FLAG not in resolution.granted:
            raise SandboxRefusedError(
                RULE_SANDBOX_FLAG_REFUSED,
                f"sandbox {request.name!r} may not be provisioned: flag {SANDBOX_FLAG!r} was "
                f"refused — {resolution.refusal_for(SANDBOX_FLAG) or 'not granted'}",
            )
        if not guard.ready:
            raise SandboxRefusedError(
                RULE_SANDBOX_POLICY_UNRESOLVED,
                f"sandbox {request.name!r} may not be provisioned under the declared network "
                f"policy: {guard.readiness_refusal()}. Provisioning pulls images, so a policy "
                "mayhem cannot enforce must stop it before the first command rather than "
                "after",
            )

    def _resolve_registry_egress(
        self, guard: NetworkPolicyGuard, name: str
    ) -> tuple[tuple[str, str], ...]:
        """Resolve egress for every registry the blueprint pulls from.

        Recorded through the guard, so a refusal lands in the guard's ledger
        alongside permitted calls, and refused here — before ``pull`` — with the
        cause named. This is a pre-flight gate on the command, not an interception
        of the runtime's own socket traffic, and it is stated as such.
        """
        decisions: list[tuple[str, str]] = []
        for host in blueprint_registry_hosts(self.blueprint):
            decision = guard.record(f"https://{host}/v2/")
            decisions.append((host, decision.rule_id))
            if decision.refused:
                raise SandboxRefusedError(
                    RULE_SANDBOX_IMAGE_EGRESS_REFUSED,
                    f"sandbox {name!r} may not be provisioned: image host {host} is refused by "
                    f"the declared network policy — [{decision.rule_id}] {decision.reason}. No "
                    "image was pulled and no stack was created; provision the sandbox from "
                    "pre-pulled images or relax the policy deliberately",
                )
        return tuple(decisions)

    def _check_blueprint(self, compose_path: Path, name: str) -> None:
        """The rendered document must read back as the blueprint, through the provider.

        Read back rather than assumed: the sandbox's topology comes from the
        compose provider, so a document that parses to the wrong services would
        hand a run a graph describing an environment that was never created.
        """
        expected = blueprint_services(self.blueprint)
        provider = ComposeFileProvider(compose_path)
        if not provider.is_available():
            raise SandboxRefusedError(
                RULE_SANDBOX_COMPOSE_UNDISCOVERABLE,
                f"the sandbox compose document {compose_path} was written but cannot be read "
                "back, so nothing was started",
            )
        discovered = provider.service_names
        if tuple(sorted(discovered)) != tuple(sorted(expected)):
            raise SandboxRefusedError(
                RULE_SANDBOX_BLUEPRINT_INCOMPLETE,
                f"sandbox {name!r} blueprint mismatch: the compose provider read services "
                f"{sorted(discovered)} from {compose_path} but the blueprint declares "
                f"{sorted(expected)}",
            )
        detected = {path.resolve() for path in find_compose_files(compose_path.parent)}
        if compose_path.resolve() not in detected:
            raise SandboxRefusedError(
                RULE_SANDBOX_COMPOSE_UNDISCOVERABLE,
                f"the sandbox compose document {compose_path} was written but is not "
                "discoverable as a compose project by mayhem.infra.project_detection, so the "
                "stack would exist without any of the tooling being able to find it. Nothing "
                "was started",
            )

    # -- the two operations ---------------------------------------------------

    def provision(self, request: SandboxRequest) -> SandboxEnvironment:
        """Provision the sandbox, or raise. Never returns a partial environment.

        Raises:
            SandboxRefusedError: The request is inadmissible (name, mode, flags,
                policy, or image egress) or a provisioning step failed. In the
                failure case a rollback has already been attempted through the
                same runner, and the message says whether it worked.
        """
        guard = self.guard_for(request)
        self._refuse_before_commands(request, guard)
        egress = self._resolve_registry_egress(guard, request.name)

        compose_path = request.directory / COMPOSE_FILENAME
        self.writer(
            compose_path,
            render_compose_document(self.blueprint, project_name=request.name),
        )
        self._check_blueprint(compose_path, request.name)

        commands: list[CommandOutcome] = []
        try:
            for action, args, rule, what in (
                ("config", ("--quiet",), RULE_SANDBOX_BLUEPRINT_INVALID, "compose validation"),
                ("pull", (), RULE_SANDBOX_IMAGE_PULL_FAILED, "image pull"),
                ("up", ("--detach",), RULE_SANDBOX_START_FAILED, "stack start"),
            ):
                outcome = self._invoke(action, compose_path, *args)
                commands.append(outcome)
                if not outcome.ok:
                    _, rollback = self._rollback(compose_path)
                    raise SandboxRefusedError(
                        rule,
                        f"{what} failed for sandbox {request.name!r}: "
                        f"`{outcome.command}` returned {outcome.detail}. {rollback}",
                    )
            running = self._invoke("ps", compose_path, "--services", "--filter", "status=running")
            commands.append(running)
            expected = set(blueprint_services(self.blueprint))
            missing = sorted(expected - set(running.services()))
            if missing:
                _, rollback = self._rollback(compose_path)
                raise SandboxRefusedError(
                    RULE_SANDBOX_COMPONENTS_UNREADY,
                    f"sandbox {request.name!r} came up incompletely: {missing} did not report "
                    f"running after `{running.command}` returned {running.detail}. A partially "
                    f"provisioned sandbox is not a sandbox, so it was not returned as ready. "
                    f"{rollback}",
                )
        except SandboxRefusedError as exc:
            raise exc

        return SandboxEnvironment(
            name=request.name,
            directory=request.directory,
            compose_path=compose_path,
            blueprint_services=blueprint_services(self.blueprint),
            components=tuple(spec.component for spec in self.blueprint),
            deployment_model=request.model,
            registry_egress=egress,
            attempts=tuple(guard.attempts),
            commands=tuple(commands),
            ca=guard.ca,
        )

    def teardown(self, environment: SandboxEnvironment) -> SandboxTeardown:
        """Remove a sandbox. A teardown that fails is reported, not raised.

        Teardown is called by operators precisely when something has already gone
        wrong, so raising here would replace a useful failure message with an
        exception about the cleanup.
        """
        outcome = self._invoke("down", environment.compose_path, "--volumes", "--remove-orphans")
        if outcome.ok:
            return SandboxTeardown(name=environment.name, removed=True, outcome=outcome)
        return SandboxTeardown(
            name=environment.name,
            removed=False,
            outcome=outcome,
            refusal=(
                f"[{RULE_SANDBOX_COMPONENTS_UNREADY}] teardown of sandbox "
                f"{environment.name!r} failed: `{outcome.command}` returned {outcome.detail}. "
                "Containers, volumes, and the published port may still be held"
            ),
        )


# --- admission -------------------------------------------------------------------


#: The plan-14 ceilings a sandbox run is held to, and deliberately tighter than
#: anything production would use.
#:
#: The sandbox has six components. A blast of four is two thirds of the
#: environment, so the ceilings are sized for "most of a sandbox" rather than for
#: "a fraction of a fleet": four nodes, two dependency hops, one customer-facing
#: service (only ``frontend`` publishes a port, so more than one is a breach by
#: construction), and 60% of nodes. Nothing is protected, because the sandbox's
#: whole purpose is to be broken.
#:
#: These are the *same* ceilings the preview already reports — they are handed to
#: :class:`~mayhem.controller.prediction_service.PredictionConfig` and read back
#: off its :class:`~mayhem.controller.prediction_service.CeilingVerdict` records —
#: so the sandbox does not carry a second, private notion of what a blast is.
SANDBOX_CEILINGS: BlastCeilings = BlastCeilings(
    max_affected_nodes=4,
    max_dependency_depth=2,
    max_customer_facing_services=1,
    max_affected_pct=60.0,
)


@dataclass(frozen=True, slots=True)
class SandboxAdmission:
    """Whether a sandbox run passed admission, and every reason it did not.

    Built by :meth:`from_report` off the preview's own verdicts — the real gate's
    refusal set plus the ceilings the preview evaluated against the same ceilings
    this record names. Nothing is recomputed here, because a sandbox whose
    admission was decided by a different calculation than the one its evidence
    reports would be a sandbox that could pass admission it never ran.

    ``enforced_here`` is the honest part: the five plan-14 ceilings are *not*
    evaluated by ``validate_plan`` (that is plan 14 Phase 4's wiring, tracked in
    :data:`~mayhem.controller.prediction_service.PENDING_ADMISSION_WIRING`), so
    this record is where they start refusing. The gate refusals in the same
    record are the real gate's own, carried unchanged.
    """

    ceilings: BlastCeilings
    deployment_model: DeploymentModel
    gate_refused: frozenset[str]
    breached: tuple[CeilingVerdict, ...]
    admitted: bool
    reason: str

    @classmethod
    def from_report(
        cls,
        report: SimulateReport,
        *,
        ceilings: BlastCeilings,
        deployment_model: DeploymentModel,
    ) -> SandboxAdmission:
        """Read admission off a preview. Pure with respect to the preview."""
        configured = tuple(dimension for dimension in report.dimensions if dimension.configured)
        breached = tuple(dimension for dimension in configured if dimension.breached)
        gate_refused = report.agreement.gate_refused
        reasons: list[str] = []
        if gate_refused:
            reasons.append(
                f"the admission gate refused rule(s) {sorted(gate_refused)}: "
                f"{report.agreement.describe()}"
            )
        if breached:
            reasons.append(
                "the sandbox's own ceilings were breached: "
                + "; ".join(
                    f"{verdict.dimension.value} observed {verdict.observed!r} against "
                    f"limit {verdict.limit!r} [{verdict.rule_id}]"
                    for verdict in breached
                )
            )
        return cls(
            ceilings=ceilings,
            deployment_model=deployment_model,
            gate_refused=gate_refused,
            breached=breached,
            admitted=not reasons,
            reason="; ".join(reasons),
        )

    @property
    def ceiling_breached_ids(self) -> tuple[str, ...]:
        """The rule ids of the ceilings that fired, sorted. The stable handle on a breach."""
        return tuple(sorted(verdict.rule_id for verdict in self.breached))

    def describe(self) -> str:
        verdict = "admitted" if self.admitted else "REFUSED"
        return (
            f"sandbox admission: {verdict} "
            f"[{self.deployment_model.value}; gate refused "
            f"{sorted(self.gate_refused) or 'nothing'}; ceilings breached "
            f"{sorted(v.rule_id for v in self.breached) or 'none'}]"
            + (f" — {self.reason}" if self.reason else "")
        )


# --- demo / training mode --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DemoRunRequest:
    """One demo, training, or simulation run: the plan, the mode, and the proof.

    ``backend`` is the caller's mutation sink. It is handed to the
    :class:`~mayhem.controller.prediction_service.PredictionService` *unchanged*
    and never routed through by this module: ``simulate_plan`` evaluates through
    its own detached copy and then reads ``len(sink)`` off the real object. Its
    length is recorded before the call as well as after, so the difference — zero
    — is this module's own measurement rather than the simulate path's report.
    A caller that pre-loads the sink (as
    ``tests/unit/test_prediction_service.py`` does, to prove its number is a
    reading rather than a constant) is fine: the pre-existing calls are part of
    both readings and cancel.
    """

    plan: ExecutionPlan
    mode: ExecutionMode
    deployment_model: DeploymentModel = SANDBOX_DEPLOYMENT_MODEL
    requested_flags: frozenset[str] = frozenset()
    basis: str = ""
    backend: MutationSink | None = None
    sandbox: str = ""


@dataclass(frozen=True, slots=True)
class RunVerification:
    """Every named reason a run's evidence may not be used, and nothing else."""

    ok: bool
    refusals: tuple[str, ...]
    presentation: str

    @property
    def reason(self) -> str:
        return self.refusals[0] if self.refusals else ""


@dataclass(frozen=True, slots=True)
class DemoRunEvidence:
    """What a demo, training, or simulation run produced, and how it may be shown.

    Nothing here stores a mode. :attr:`claim` holds the sealed
    :class:`~mayhem.domain.deployment.ModeMarker` built by
    :func:`~mayhem.domain.deployment.sealed_mode_marker` from the mode alone, so
    every derived field below is a projection of a value that cannot be edited,
    and there is no second field anywhere in this record that a renderer could
    read instead.
    """

    claim: ModeClaim
    report: SimulateReport
    admission: SandboxAdmission | None
    flags: FlagResolution
    network: PolicyResolution
    sandbox: str = ""
    #: ``len(backend)`` as it stood *before* ``simulate_plan`` ran.
    #: :attr:`report`'s own ``mutation.calls`` is the length *after*; the two being
    #: equal is the no-mutation proof, and it is why a caller may hand over a
    #: pre-loaded sink without the run being refused for the calls it already had.
    sink_calls_before: int = 0

    @property
    def mode(self) -> ExecutionMode:
        """The sealed mode. Read-only by construction."""
        return self.claim.mode

    @property
    def marker(self) -> str:
        """The sealed banner, exactly as Phase 1 computed it."""
        return self.claim.marker.marker

    @property
    def mutates(self) -> bool:
        return self.claim.mutates

    @property
    def mutation(self) -> MutationProof:
        """The preview's own measurement of the caller's mutation sink."""
        return self.report.mutation

    @property
    def mutations_performed(self) -> int:
        """How many mutation calls *this run* added to the sink.

        Zero is the only admissible value, and it is a difference of two readings
        of one real object rather than an assertion in a docstring.
        """
        return self.report.mutation.calls - self.sink_calls_before

    @property
    def banner(self) -> str:
        """The one string a surface must show for this run.

        A property, not a field, so it cannot be dropped by a dataclass
        constructor or a stale serialisation: it reads the sealed marker, which
        carries the ``— no mutation performed`` phrase for all three demo modes.
        """
        return (
            f"{self.claim.marker.marker} — run {self.claim.run_id!r} in "
            f"{self.claim.deployment_model.value} mode"
            + (f" (sandbox {self.sandbox!r})" if self.sandbox else "")
        )

    @property
    def may_back_production_evidence(self) -> bool:
        """False for every demo mode, and it is not a formatting choice."""
        return self.claim.marker.may_back_production_evidence

    def refusal_for_mode(self, requested: ExecutionMode) -> str:
        """Why ``requested`` may not be substituted for this run's sealed mode."""
        return flag_drift_refusal(self.claim, requested)

    def verify(self) -> RunVerification:
        """The verifier a surface calls before showing this evidence."""
        return verify_demo_run(self)

    def describe(self) -> str:
        lines = [
            self.banner,
            f"mutation: {self.mutations_performed} call(s) performed by this run "
            f"(sink held {self.sink_calls_before} before, {self.mutation.calls} after)",
        ]
        if self.admission is not None:
            lines.append(self.admission.describe())
        if self.flags.refusals:
            lines.append(
                "flag refusals: " + "; ".join(f"{r.key} [{r.rule}]" for r in self.flags.refusals)
            )
        presentation = production_presentation_refusal(self.claim)
        if presentation:
            lines.append(f"not presentable as production: {presentation}")
        return "\n".join(lines)


def verify_demo_run(evidence: DemoRunEvidence) -> RunVerification:
    """Every reason ``evidence`` may not be used, as named refusals.

    Six checks, and each one exists because the alternative is a misreport:

    * the marker must agree with the mode it names, field for field. Phase 1's
      marker is derived by construction, but its dataclass is public, so a
      hand-built one could claim ``mutates`` on a training run;
    * the sealed marker may not back production evidence. Checked *both* ways —
      against the marker's own derived property and against
      :func:`~mayhem.domain.deployment.production_presentation_refusal` — because
      a record whose marker somehow could would otherwise pass on the strength of
      one of them;
    * a demo banner must carry the ``no mutation performed`` phrase, since that
      phrase is what makes a reader's eye catch the difference between a rehearsal
      and a result;
    * the simulate path must have added no mutation calls, with a detached
      backend. Checked as a *difference* of two readings of the caller's sink, so
      it is a measurement rather than an assertion — and it is the check that
      stops a regression in the simulate path from being absorbed here: if that
      path ever writes a call, the length moves and this refuses rather than
      reporting a clean run;
    * a sandbox run must carry an admission record (:data:`RULE_SANDBOX_ADMISSION_MISSING`)
      and it must have admitted (:data:`RULE_SANDBOX_ADMISSION_REFUSED`). A
      non-sandbox demo run discloses an admission refusal instead of raising on
      it, because showing a preview *is* showing why a plan was refused.

    Returns:
        RunVerification: ``ok`` is ``True`` only when there is nothing to refuse.
    """
    refusals: list[str] = []
    claim = evidence.claim
    if claim.mode.is_demo:
        # Phase 1 makes the marker *derived* by construction, but the dataclass
        # itself is public, so a caller can build one whose fields contradict the
        # mode it names. Requiring the banner and the `mutates` flag to be the
        # ones the mode itself derives is what closes that, and it is checked
        # before anything reads the marker as authoritative.
        if claim.marker.marker != claim.mode.marker or claim.marker.mutates != claim.mode.mutates:
            refusals.append(
                f"{RULE_DEMO_MARKER_FORGED}: run {claim.run_id!r} carries a marker saying "
                f"{claim.marker.marker!r}/mutates={claim.marker.mutates} for mode "
                f"{claim.mode.value!r}, whose own derived values are "
                f"{claim.mode.marker!r}/mutates={claim.mode.mutates}. A marker that "
                "disagrees with the mode it names was not built by "
                "sealed_mode_marker and is not evidence of anything"
            )
        if claim.marker.may_back_production_evidence:
            refusals.append(
                f"{RULE_DEMO_MARKER_PROMOTION}: run {claim.run_id!r} is sealed in "
                f"{claim.mode.value} mode but its marker claims it may back production "
                "evidence. The marker is derived from the mode and cannot say both, so this "
                "record was assembled outside the sealed path and must not be shown"
            )
        if NO_MUTATION_PHRASE not in claim.marker.marker:
            refusals.append(
                f"{RULE_DEMO_MARKER_MISSING}: the sealed marker {claim.marker.marker!r} does "
                f"not carry the phrase {NO_MUTATION_PHRASE!r}, so a reader cannot tell this "
                "run from a production one by looking at it"
            )
        presentation = production_presentation_refusal(claim)
        if not presentation:
            refusals.append(
                f"{RULE_DEMO_MARKER_PROMOTION}: run {claim.run_id!r} in {claim.mode.value} mode "
                "was accepted for production presentation, which the sealed marker forbids"
            )
    performed = evidence.mutations_performed
    if performed or evidence.mutation.backend_attached:
        refusals.append(
            f"{RULE_DEMO_MUTATION_OBSERVED}: the mutation sink held "
            f"{evidence.sink_calls_before} call(s) before the simulate path ran and "
            f"{evidence.mutation.calls} after, with backend_attached="
            f"{evidence.mutation.backend_attached}, so this run added {performed} mutation "
            f"call(s) and did not perform the full no-mutation UX it claims: "
            f"{evidence.mutation.calls_detail}"
        )
    if evidence.sandbox:
        if evidence.admission is None:
            refusals.append(
                f"{RULE_SANDBOX_ADMISSION_MISSING}: sandbox run {evidence.sandbox!r} carries no "
                "admission record. A sandbox is not a policy-free zone, so a run against one "
                "is only evidence if admission actually passed and was recorded"
            )
        elif not evidence.admission.admitted:
            refusals.append(
                f"{RULE_SANDBOX_ADMISSION_REFUSED}: sandbox run {evidence.sandbox!r} was not "
                f"admitted — {evidence.admission.reason}"
            )
    return RunVerification(
        ok=not refusals,
        refusals=tuple(refusals),
        presentation=production_presentation_refusal(claim),
    )


def require_verified_run(evidence: DemoRunEvidence) -> DemoRunEvidence:
    """Return ``evidence`` when it verifies, and refuse by name when it does not.

    Raises:
        SandboxRefusedError: The first verification refusal, with its rule id.
    """
    verification = verify_demo_run(evidence)
    if verification.ok:
        return evidence
    first = verification.refusals[0]
    rule, _, reason = first.partition(": ")
    raise SandboxRefusedError(rule or RULE_SANDBOX_ADMISSION_REFUSED, reason or first)


@dataclass(frozen=True, slots=True)
class DemoModeService:
    """Runs the full UX in a demo mode, reusing the existing simulate path.

    There is exactly one simulation mechanism in this codebase and this class is
    not it: :meth:`run` builds a
    :class:`~mayhem.controller.prediction_service.PredictionService` and calls
    :meth:`~mayhem.controller.prediction_service.PredictionService.simulate_plan`,
    which is what already evaluates through a service holding no mutation backend
    and reports the observed sink length. This class supplies the two things the
    simulate path has no opinion about — the sealed execution-mode marker, and the
    sandbox's own admission ceilings — and refuses anything that would let a demo
    run be presented as a production one.
    """

    guard: NetworkPolicyGuard
    ceilings: BlastCeilings | None = None

    def service_for(
        self, graph: TopologyGraph, backend: MutationSink | None = None
    ) -> PredictionService:
        """The prediction service a run is evaluated through.

        Takes the caller's ``backend`` so that ``simulate_plan``'s mutation proof
        is a measurement of a real sink rather than a hard-coded zero, and carries
        the sandbox ceilings in its config so the preview reports them as admission
        dimensions rather than this module re-deriving them. It does **not**
        detach the backend: ``simulate_plan`` evaluates through its own
        ``detached()`` copy, and handing it a live sink is what makes the reported
        count informative.
        """
        ceilings = self.ceilings if self.ceilings is not None else BlastCeilings()
        return PredictionService(
            graph=graph, config=PredictionConfig(ceilings=ceilings), backend=backend
        )

    def run(
        self, request: DemoRunRequest, graph: TopologyGraph, ctx: SafetyContext
    ) -> DemoRunEvidence:
        """Evaluate a plan in a demo mode and seal the result's mode marker.

        Refuses rather than returning:

        * a production mode (:data:`RULE_DEMO_PRODUCTION_MODE_REFUSED`) — the
          detached path is what makes a demo a demo, and a production run does not
          come through it;
        * an ungranted ``demo.mode`` flag (:data:`RULE_DEMO_FLAG_REFUSED`);
        * anything :func:`verify_demo_run` refuses, which includes a mutation
          measurement that is not zero and a sandbox run whose admission did not
          pass.

        Raises:
            SandboxRefusedError: As above. Everything else — the gate's own
                refusals, the breached ceilings, the unpriced-cost disclosure —
                is *reported* on the evidence, because a preview's value is
                precisely that it shows why.
        """
        if request.mode.is_production:
            raise SandboxRefusedError(
                RULE_DEMO_PRODUCTION_MODE_REFUSED,
                f"run {request.plan.run_id!r} was requested in {request.mode.value} mode through "
                "the demo-mode service. A demonstration, training, or simulation run is the "
                "plan-14 simulate path with a friendlier name, and it holds no mutation "
                "backend at all; a production run does not come through here, and admitting "
                "it would mean a run could be sealed into either mode by which door it used",
            )
        resolution = resolve_flags(
            (*request.requested_flags, DEMO_FLAG),
            model=request.deployment_model,
            mode=request.mode,
        )
        if DEMO_FLAG not in resolution.granted:
            raise SandboxRefusedError(
                RULE_DEMO_FLAG_REFUSED,
                f"run {request.plan.run_id!r} may not execute in {request.mode.value} mode: "
                f"flag {DEMO_FLAG!r} was refused — "
                f"{resolution.refusal_for(DEMO_FLAG) or 'not granted'}",
            )

        sink_calls_before = len(request.backend) if request.backend is not None else 0
        service = self.service_for(graph, request.backend)
        report = service.simulate_plan(request.plan, ctx)

        claim = ModeClaim(
            run_id=request.plan.run_id,
            marker=sealed_mode_marker(request.mode, basis=request.basis),
            deployment_model=request.deployment_model,
            plan_identity=report.prediction.plan_identity,
            active_flags=resolution.granted,
        )
        ceilings = self.ceilings if self.ceilings is not None else BlastCeilings()
        evidence = DemoRunEvidence(
            claim=claim,
            report=report,
            admission=SandboxAdmission.from_report(
                report, ceilings=ceilings, deployment_model=request.deployment_model
            ),
            flags=resolution,
            network=self.guard.resolution,
            sandbox=request.sandbox,
            sink_calls_before=sink_calls_before,
        )
        return require_verified_run(evidence)


@dataclass(frozen=True, slots=True)
class SandboxService:
    """The operator-facing surface: provision, admit, run, tear down.

    One façade over :class:`SandboxProvisioner` and :class:`DemoModeService` so
    the two cannot be wired up inconsistently — in particular so that a sandbox
    run always evaluates against *that sandbox's* network guard, and always
    carries the sandbox ceilings. :meth:`run` is where "a sandbox is not a
    policy-free zone" is enforced, and it enforces it by handing the sandbox's
    name to :meth:`DemoModeService.run`, which refuses a run whose admission did
    not pass.
    """

    provisioner: SandboxProvisioner
    demo: DemoModeService

    def guard(self) -> NetworkPolicyGuard:
        return self.demo.guard

    def provision(self, request: SandboxRequest) -> SandboxEnvironment:
        return self.provisioner.provision(request)

    def teardown(self, environment: SandboxEnvironment) -> SandboxTeardown:
        return self.provisioner.teardown(environment)

    def topology(self, environment: SandboxEnvironment) -> TopologyGraph:
        """The provisioned sandbox's topology, read back through the compose provider."""
        return sandbox_topology(environment.compose_path)

    def run(
        self,
        environment: SandboxEnvironment,
        plan: ExecutionPlan,
        ctx: SafetyContext,
        *,
        mode: ExecutionMode = ExecutionMode.SAFE_DEMO,
        requested_flags: frozenset[str] = frozenset(),
        basis: str = "",
        backend: MutationSink | None = None,
    ) -> DemoRunEvidence:
        """Run a plan against a provisioned sandbox, with admission enforced.

        The graph comes from the sandbox's own compose document, so the plan is
        planned against the environment that was actually provisioned. Admission
        is the same admission every other run gets — the real gate runs inside
        ``simulate_plan`` — plus the sandbox's own ceilings on top, and a refusal
        raises rather than returning a preview, because a caller that asked to
        *run* in a sandbox is not asking to be told why it might.
        """
        graph = self.topology(environment)
        return self.demo.run(
            DemoRunRequest(
                plan=plan,
                mode=mode,
                deployment_model=environment.deployment_model,
                requested_flags=requested_flags,
                basis=basis or f"plan 20 sandbox {environment.name!r}",
                backend=backend,
                sandbox=environment.name,
            ),
            graph,
            ctx,
        )


def sandbox_service(
    runner: SandboxRunner,
    *,
    blueprint: tuple[SandboxServiceSpec, ...] = SANDBOX_BLUEPRINT,
    compose_argv: tuple[str, ...] = DEFAULT_COMPOSE_ARGV,
    policy: NetworkPolicy = DEFAULT_POLICY,
    model: DeploymentModel = SANDBOX_DEPLOYMENT_MODEL,
    transport: EgressTransport | None = None,
    ca_reader: Callable[[str], bytes] | None = None,
) -> SandboxService:
    """Build a :class:`SandboxService` with one guard shared by provisioning and runs.

    The shared guard is the point. A provisioner that resolved egress with one
    policy and a run that resolved it with another would be an install whose two
    halves disagree about the network, and the disagreement would only show up as
    a failed call in one of them.
    """
    guard = NetworkPolicyGuard.build(policy, model=model, transport=transport, ca_reader=ca_reader)
    provisioner = SandboxProvisioner(
        runner=runner,
        blueprint=blueprint,
        compose_argv=compose_argv,
        ca_reader=ca_reader,
    )
    demo = DemoModeService(guard=guard, ceilings=SANDBOX_CEILINGS)
    return SandboxService(provisioner=provisioner, demo=demo)
