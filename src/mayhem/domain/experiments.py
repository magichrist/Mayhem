"""Experiment specs and execution plans.

``DrillSpec`` is the authored input format (ADR-0019); ``ExecutionPlan`` is
the frozen, validated output of compilation. The plan pins config/topology
snapshot ids so any later analysis knows what the controller knew when it
committed. Since the clean break (ADR-0021) the only supported kind is
``drill`` — the deterministic/random authoring surfaces were removed.
"""

from __future__ import annotations

import warnings
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from mayhem.domain.capabilities import Identifier
from mayhem.domain.checks import CheckLocus, CheckSpec, Probe
from mayhem.domain.common import Duration
from mayhem.domain.decisions import DecisionRef
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_context import ExecutionContextSpec
from mayhem.domain.faults import FaultCategory
from mayhem.domain.identity import RuntimeIdentity, RuntimeLabel
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.observability import ObservabilityConfig
from mayhem.domain.quota import DamageQuota
from mayhem.domain.risks import RiskLevel
from mayhem.domain.secrets import SpecCredentialRef
from mayhem.domain.steady_state import SteadyStateSpec
from mayhem.domain.success import SuccessCriteria
from mayhem.domain.target import (
    ResourceKind,
    SelectionSpec,
    TargetRef,
    TargetScope,
)
from mayhem.domain.topology import TargetSelector


class ExperimentKind(StrEnum):
    DETERMINISTIC = "deterministic"
    RANDOM = "random"
    DRILL = "drill"


class OnFailure(StrEnum):
    ABORT_AND_RECOVER = "abort_and_recover"
    CONTINUE = "continue"


class BlastRadiusBudget(BaseModel):
    """Topology-derived limits enforced by the scheduler (ADR-0012 §5)."""

    model_config = ConfigDict(frozen=True)

    max_services_pct: float = Field(default=50.0, gt=0, le=100)
    max_hosts: int = Field(default=2, ge=1)
    max_concurrent_faults: int = Field(default=3, ge=1)
    max_duration_per_fault_s: float = 300.0
    forbidden_fault_pairs: frozenset[frozenset[str]] = Field(default_factory=frozenset)
    # Cumulative damage across the whole plan, charged per target in
    # damage-seconds. The five limits above are per-step; this is the only
    # budget that sees the *sequence*. None means "use the default quota",
    # which is active rather than absent - a quota nobody configures is a
    # quota nobody gets.
    damage_quota: DamageQuota | None = None


class Constraints(BaseModel):
    model_config = ConfigDict(frozen=True)

    duration_cap: Duration | None = None
    abort_on_violation: bool = True
    require_dry_run_first: bool = True
    risk_ceiling: RiskLevel | None = None  # may only tighten policy ceiling
    blast_radius: BlastRadiusBudget | None = None


# -- step actions ------------------------------------------------------------------


class InjectFault(BaseModel):
    type: Literal["inject_fault"] = "inject_fault"
    fault: str
    selectors: tuple[TargetSelector, ...]
    target: TargetRef | None = None  # k-plan-1: targets:-authored faults
    params: dict[str, object] = Field(default_factory=dict)
    duration: Duration
    backend: Identifier | None = None
    execution: ExecutionContextSpec | None = None  # ADR-0014; None → infer from target

    @field_validator("fault")
    @classmethod
    def _known_category(cls, value: str) -> str:
        FaultCategory.from_fault_id(value)
        return value

    @model_validator(mode="after")
    def _has_locator(self) -> InjectFault:
        # ``containers:``-authored faults address targets by selector; a
        # ``targets:``-authored fault carries ``target`` instead and may have
        # no selectors at all (k-plan-1 §1.3). Runs after the whole model is
        # populated so the emptiness check sees both fields.
        if not self.selectors and self.target is None:
            raise InvariantViolationError(
                "step_requires_targets", "inject_fault needs >= 1 selector or a target"
            )
        return self


class Wait(BaseModel):
    type: Literal["wait"] = "wait"
    duration: Duration | None = None
    until_check_passes: str | None = None  # check id
    timeout: Duration = 120.0


class CheckHttp(BaseModel):
    """Inline HTTP health check for drill plans (ADR-0019)."""

    type: Literal["check_http"] = "check_http"
    url: str
    expected_status: int | None = None


class CheckSpecStep(BaseModel):
    """A drill check step compiled from a :class:`CheckSpec` (ADR-M4-2).

    Carries the fully-resolved probe and its execution locus so the executor
    can evaluate the check where it is declared to run.
    """

    type: Literal["check_spec"] = "check_spec"
    check_id: str
    probe: Probe
    execution: CheckLocus | None = None  # None → infer from fault target
    target: str | None = None


# The raw action of a planned step. Drill plans only ever emit inject_fault,
# wait and check_http — the start_load/stop_load/check/notify/parallel action
# types were authoring-only and removed with the deterministic/random surfaces.
StepAction = Annotated[InjectFault | Wait | CheckHttp | CheckSpecStep, Field(discriminator="type")]


# -- drill spec (ADR-0019) ------------------------------------------------------------------


class ManiacCfg(BaseModel):
    """Maniac-mode tuning — ``config.maniac`` in a drill spec or ``maniac:``
    in the layered ``mayhem.yaml`` config (spec-level wins, ADR-M5-1).

    ``level`` — the "level of randomness" dial:

    =====  ==================================================================
    level  behaviour
    =====  ==================================================================
    1      random container, first authored fault on it; no duration jitter
    2      random container, random one of its authored faults; no jitter
    3      random container, any fault from the whole spec (cross-locus); no jitter
    4      cross-locus pool + duration jitter of ±10 %
    5      cross-locus pool + duration jitter of ±20 % (full chaos)
    =====  ==================================================================

    Jitter is clamped to the fault's catalog maximum duration and never drops
    below 1 second; the spec's own safety gates (risk ceiling, blast radius,
    timeout) still apply to every round. (``config.max_faults`` used to be
    listed here too; it is deprecated and never enforced — see
    :class:`DrillConfig`.)
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    level: int = Field(default=2, ge=1, le=5)
    run_level: int = Field(default=10, ge=1, le=500)  # injection rounds
    seed: int | None = Field(default=None, ge=0)  # reproducible draws


class MaxFaultsNotEnforced(Warning):
    """``config.max_faults`` was authored but is not enforced.

    The field has been declared, parsed, and stored since the drill-spec
    format landed, and **no code path under ``src/`` has ever read it** — not
    the planner, not the scheduler, not the safety gate. A spec author who
    writes ``max_faults: 1`` reasonably believes the run is capped at one
    fault; it is not capped at all, and the type signature is the only place
    that says so. That is a documentation lie shaped like a safety control,
    which is the most expensive kind.

    v1 keeps the field parseable — removing it would break every existing
    spec, and quietly rejecting it would break them at *run* time — and makes
    it loudly deprecated instead. It deliberately does **not** start
    enforcing: turning a no-op into a hard cap mid-release would silently
    change what existing drills do, which is a breaking change wearing a
    bugfix's clothes. The budget that is actually enforced is
    ``blast_radius.max_concurrent_faults``, gated in
    :mod:`mayhem.controller.safety`.

    A plain :class:`Warning` rather than :class:`DeprecationWarning`, matching
    ``mayhem.config.SpecFileUsedAsConfig``: ``DeprecationWarning`` is filtered
    out of default displays outside ``__main__``, and the operator who needs
    this told is the one running ``mayhem run``. A dedicated subclass keeps it
    individually suppressible via ``warnings.filterwarnings``.
    """


class DrillConfig(BaseModel):
    """Configuration for a drill spec — replaces the separate mayhem.yml."""

    model_config = ConfigDict(frozen=True)

    risk_ceiling: RiskLevel = RiskLevel.HIGH
    # DEPRECATED (1.0.0) and NOT enforced. Parsed and stored for backward
    # compatibility; read by nothing. Setting it emits
    # :class:`MaxFaultsNotEnforced` once per config load. The real cap is
    # ``blast_radius.max_concurrent_faults`` (see :class:`BlastRadiusBudget`
    # and :mod:`mayhem.controller.safety`) — do not "fix" this into a limit.
    max_faults: int = Field(default=1, ge=0)
    timeout: Duration = "30m"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # True: auto-recover after each fault (undo contract runs, container restored).
    # False: keep the perturbation in place after injection — the container stays
    # faulted so downstream checks observe whether the stack self-heals.
    recovery: bool = True
    # Drill-wide failure policy: when a fault round fails, `abort_and_recover`
    # cancels the remaining steps and recovers, `continue` records the failure
    # and keeps testing the remaining faults (the run still ends `failed`).
    # A fault can override this per-fault via its own `on_failure`.
    on_failure: OnFailure = OnFailure.ABORT_AND_RECOVER
    # ADR-M5-1: when set, `mayhem maniac` replaces the authored execution with
    # `maniac.run_level` random (container, fault) rounds dialed by `maniac.level`.
    # Leave unset to keep `mayhem run` fully deterministic.
    maniac: ManiacCfg | None = None

    @model_validator(mode="before")
    @classmethod
    def _warn_max_faults_is_unenforced(cls, data: Any) -> Any:
        """Warn once per load if — and only if — ``max_faults`` was authored.

        A ``mode="before"`` validator sees the raw input mapping, which is the
        only place the authored keys are still distinguishable from the
        defaults. Key *presence* is the trigger, not the value: ``max_faults:
        1`` is the field default and is exactly what ``mayhem init``
        scaffolds, so keying on "differs from the default" would leave the one
        case this deprecation exists to catch completely silent. Omitting the
        key is silent by construction.

        Runs once per ``DrillConfig`` construction — a model validator is not
        re-entered on attribute access, ``model_dump``, or
        ``model_copy`` — so the warning is one-per-load, not one-per-read.
        """
        if not isinstance(data, dict) or "max_faults" not in data:
            return data
        warnings.warn(
            f"config.max_faults={data['max_faults']!r} is deprecated and is NOT "
            "enforced: no scheduler, planner, or executor reads it, so it caps "
            "nothing. The enforced concurrent-fault budget is "
            "blast_radius.max_concurrent_faults (the safety gate in "
            "mayhem.controller.safety) — set it under `blast_radius:` and drop "
            "`max_faults` to silence this warning.",
            MaxFaultsNotEnforced,
            stacklevel=2,
        )
        return data


class DrillFault(BaseModel):
    """A single fault to inject on a container."""

    model_config = ConfigDict(frozen=True, extra="allow")

    fault: str
    duration: Duration = "10s"
    # Per-fault override of ``config.on_failure``; None ⇒ inherit config.
    on_failure: OnFailure | None = None
    targets: tuple[str, ...] = ()  # for network faults: container names to partition
    network_path: str | None = None  # ADR-M3-7 optional path target for network faults
    # Optional per-fault override of ``config.recovery``; None ⇒ inherit config.
    recovery: bool | None = None


class DrillContainer(BaseModel):
    """Faults to run on a specific container (identified by container_name)."""

    model_config = ConfigDict(frozen=True)

    faults: tuple[DrillFault, ...] = ()


class CheckExpectation(BaseModel):
    """What to verify in a check probe."""

    model_config = ConfigDict(frozen=True)

    status: int | None = None


class CheckProbe(BaseModel):
    """A health check to run between execution rounds."""

    model_config = ConfigDict(frozen=True)

    http: str | None = None
    expect: CheckExpectation = CheckExpectation()


class ExecutionStep(BaseModel):
    """A single step in the execution plan — parallel, sequential, wait, or check."""

    model_config = ConfigDict(frozen=True)

    parallel: tuple[str, ...] | None = None  # container names to run concurrently
    sequential: tuple[str, ...] | None = None  # container names to run in order
    wait: Duration | None = None  # seconds to wait after this step
    check: tuple[CheckProbe, ...] | None = None  # health checks to run
    check_spec: tuple[CheckSpec, ...] | None = None  # locus-aware checks (ADR-M4-2)


class DockerTargetSpec(BaseModel):
    """Single-container locator for docker/podman targets (k-plan-1 §1.2)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    container_name: str = Field(min_length=1)


class KubernetesTargetSpec(BaseModel):
    """Locator material for a kubernetes target (k-plan-1 §1.2, §1.6).

    Configuration — not credentials. ``name`` is always the stable workload
    name (``Deployment/production/checkout``), never a generated pod name.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ResourceKind
    namespace: str
    name: str = Field(min_length=1)
    container: str | None = None  # optional single container (container-level faults)

    @field_validator("kind")
    @classmethod
    def _k8s_kinds_only(cls, value: ResourceKind) -> ResourceKind:
        if value == ResourceKind.CONTAINER:
            raise ValueError("kind 'container' is docker-scoped; use pod/deployment/...")
        return value


class DrillTarget(BaseModel):
    """One logical target under the ``targets:`` block (k-plan-1 §1.2).

    Cross-runtime: declares the runtime label and optional locator block.
    Kubernetes targets require a matching ``kubernetes:`` locator. Docker
    targets may omit the locator when the logical target key is the container
    name. The two locator blocks may not be mixed in one target.
    """

    model_config = ConfigDict(frozen=True)

    runtime: RuntimeLabel
    docker: DockerTargetSpec | None = None
    kubernetes: KubernetesTargetSpec | None = None
    selection: SelectionSpec | None = None
    faults: tuple[DrillFault, ...] = ()

    @field_validator("faults")
    @classmethod
    def _requires_fault(cls, value: tuple[DrillFault, ...]) -> tuple[DrillFault, ...]:
        if not value:
            raise InvariantViolationError("target_requires_faults", "each target needs >= 1 fault")
        return value

    @model_validator(mode="after")
    def _runtime_locator_matches(self) -> DrillTarget:
        if self.runtime == RuntimeLabel.KUBERNETES:
            if self.kubernetes is None:
                raise InvariantViolationError(
                    "target.runtime_mismatch",
                    "kubernetes runtime requires a `kubernetes:` locator block",
                )
            if self.docker is not None:
                raise InvariantViolationError(
                    "target.mixed_locators",
                    "a target may not carry both `docker:` and `kubernetes:` blocks",
                )
        elif self.kubernetes is not None:
            raise InvariantViolationError(
                "target.mixed_locators",
                f"target runtime {self.runtime.value} may not carry a `kubernetes:` block",
            )
        return self

    def to_scope(self, logical_id: str) -> TargetScope:
        """Normalize this authored target into the shared :class:`TargetScope`
        (k-plan-1 §1.3) — the single identity the planner pins."""
        if self.runtime == RuntimeLabel.KUBERNETES:
            assert self.kubernetes is not None
            scope = TargetScope(
                logical_id=logical_id,
                runtime=self.runtime,
                kind=self.kubernetes.kind,
                authority={
                    "api_group": _api_group_for_kind(self.kubernetes.kind),
                    "kind": self.kubernetes.kind.value,
                    "namespace": self.kubernetes.namespace,
                    "name": self.kubernetes.name,
                },
                container=self.kubernetes.container,
            )
        else:
            scope = TargetScope(
                logical_id=logical_id,
                runtime=self.runtime,
                kind=ResourceKind.CONTAINER,
                authority={
                    "container_name": self.docker.container_name
                    if self.docker is not None
                    else logical_id
                },
            )
        return scope.model_copy(update={"selection": self.selection})


def _api_group_for_kind(kind: ResourceKind) -> str:
    """Core kubernetes API group for the trusted locator material. Plumbing
    only: the live driver (k-plan-2/3) resolves the concrete group/version."""
    return {
        ResourceKind.DEPLOYMENT: "apps",
        ResourceKind.STATEFULSET: "apps",
        ResourceKind.DAEMONSET: "apps",
        ResourceKind.SERVICE: "core",
        ResourceKind.POD: "core",
        ResourceKind.K8S_NODE: "",
    }.get(kind, "")


class DrillSpec(BaseModel):
    """Unified drill spec — single YAML file replacing config + fault spec (ADR-0019)."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    kind: Literal["drill"]
    name: str
    hypothesis: str = ""
    config: DrillConfig = Field(default_factory=DrillConfig)
    containers: dict[str, DrillContainer] | None = None  # key = container_name from docker-compose
    targets: dict[str, DrillTarget] | None = None  # k-plan-1: cross-runtime logical targets
    execution: tuple[ExecutionStep, ...]
    success: SuccessCriteria | None = None  # optional machine verdict (ADR-M4-3)
    observability: ObservabilityConfig | None = None  # optional evidence sources (ADR-M4-4)
    # v0.9.0: provider-neutral SLO criteria with explicit units and windows.
    # Typed as plain dicts so the criterion vocabulary owns the values while
    # the domain model owns the shape (see mayhem.domain.observations).
    slo: tuple[dict[str, Any], ...] = ()
    # v1.0.0 (plan 03): the tolerance field the CNCF probes do not have. Purely
    # additive and entirely optional — a spec without `steady_state:` parses,
    # validates, and dumps exactly as it did before the block existed, and
    # `model_dump(exclude_none=True)` still omits the key, so every digest path
    # (toolkit.hashing.canonical_json, plan_diff) is byte-identical.
    steady_state: SteadyStateSpec | None = None
    # v1.1.0 (plan 29 Phase 3): the `credentialRef:` block the plan's reference
    # shape always described and this spec never had. Purely additive and
    # optional — a spec without it parses, validates and dumps byte-identically,
    # because the default is ``None`` and every digest path excludes none (the
    # same reasoning as `steady_state:` above). Authors may write one block (the
    # plan's shape) or a list of them; `credential_refs` is the one to read.
    credential_ref: tuple[SpecCredentialRef, ...] | None = Field(
        default=None, alias="credentialRef"
    )

    @property
    def credential_refs(self) -> tuple[SpecCredentialRef, ...]:
        """Every authored reference, as a tuple whether or not any exist."""
        return self.credential_ref or ()

    @field_validator("credential_ref", mode="before")
    @classmethod
    def _reference_block_or_list(cls, value: object) -> object:
        """Accept the plan's single ``credentialRef:`` mapping or a list of them.

        The plan documents one reference per spec, which is a shape rather than a
        limit; accepting both means an author is never told their second
        credential is unexpressible, and ``credentialRef: {}`` is still refused
        by the nested model rather than silently becoming no references.
        """
        if value is None:
            return None
        if isinstance(value, (list, tuple)) and not value:
            return None
        if isinstance(value, Mapping):
            return [value]
        return value

    @field_validator("containers")
    @classmethod
    def _no_empty_containers(
        cls, value: dict[str, DrillContainer] | None
    ) -> dict[str, DrillContainer] | None:
        if value is not None and not value:
            raise InvariantViolationError("drill_requires_containers", "no containers defined")
        return value

    @field_validator("execution")
    @classmethod
    def _at_least_one_step(cls, value: tuple[ExecutionStep, ...]) -> tuple[ExecutionStep, ...]:
        if not value:
            raise InvariantViolationError("drill_requires_execution", "no execution steps defined")
        return value

    @model_validator(mode="after")
    def _targets_or_containers(self) -> DrillSpec:
        """Exactly one of ``containers:`` / ``targets:`` may define the spec
        (k-plan-1 §1.2). Mixing both is a compile-time schema error, code
        ``targets.mixed_sources``; a spec with neither defines nothing."""
        has_containers = bool(self.containers)
        has_targets = bool(self.targets)
        if has_containers and has_targets:
            raise InvariantViolationError(
                "targets.mixed_sources",
                "a drill spec may not mix `containers:` and `targets:`",
            )
        if not has_containers and not has_targets:
            # Pydantic-wrapped → parsed as a schema error (`parse_drill`):
            # a spec with neither source defines nothing (k-plan-1 §1.2).
            raise ValueError("a drill spec must define one of `containers:` or `targets:`")
            raise InvariantViolationError(
                "drill_requires_containers", "no containers or targets defined"
            )
        return self


# -- compiled plan ------------------------------------------------------------------------


class ResolvedTarget(BaseModel):
    model_config = ConfigDict(frozen=True)

    selector: TargetSelector
    node_ids: frozenset[str]

    @field_validator("node_ids")
    @classmethod
    def _resolved(cls, value: frozenset[str]) -> frozenset[str]:
        if not value:
            raise InvariantViolationError("plan_targets_resolved", "selector matched no nodes")
        return value


class PlannedFault(BaseModel):
    """A fault invocation with compile-time resolution done.

    Carries its compensation contract (write-ahead undo ops + verify probes)
    decided at planning time — never discovered mid-execution.
    """

    model_config = ConfigDict(frozen=True)

    fault_id: str
    targets: tuple[ResolvedTarget, ...]
    target: TargetRef | None = None
    undo_ops: tuple[UndoOp, ...] = ()
    verify_probes: tuple[VerifyProbe, ...] = ()
    params: dict[str, object] = Field(default_factory=dict)
    duration: Duration
    backend: Identifier | None = None
    execution_context: ExecutionContextSpec | None = None  # ADR-0014
    runtime_identity: RuntimeIdentity | None = None  # planned identity (ADR-M1-1/1-3)
    execution_loci: dict[str, object] | None = None  # ADR-M3-3 target/agent/tool loci
    # False ⇒ executor keeps the perturbation in place instead of undoing it
    # after injection (self-healing observation mode).
    recovery: bool = True
    # Resolved failure policy (config default overridden per-fault at planning
    # time): abort_and_recover cancels the remaining steps on the first failing
    # round; continue records the failure and keeps testing the rest.
    on_failure: OnFailure = OnFailure.ABORT_AND_RECOVER


class ExecutionPlan(BaseModel):
    """Frozen contract handed from planning to execution."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    kind: ExperimentKind
    steps: tuple[PlannedStep, ...]
    config_snapshot_id: str
    topology_snapshot_id: str
    environment_fingerprint: str
    policy_id: str = ""
    seed: int | None = None
    success: SuccessCriteria | None = None  # copied from the spec (ADR-M4-3)
    observability: ObservabilityConfig | None = None  # copied from the spec (ADR-M4-4)
    # v0.9.0 task 13: provider-neutral SLO criteria with explicit units, windows
    # and failure semantics. Kept as plain dicts on the frozen plan so the
    # domain model owns the shape but the criterion vocabulary owns the values.
    slo: tuple[dict[str, Any], ...] = ()
    decision_refs: tuple[DecisionRef, ...] = ()  # governing ADR ids + timestamps

    @model_validator(mode="after")
    def _check_plan(self) -> ExecutionPlan:
        return self


class GroupMode(StrEnum):
    """Execution semantics of a fault group (ADR-M2-1)."""

    PARALLEL = "parallel"  # members run concurrently
    SEQUENTIAL = "sequential"  # members run one-at-a-time in order
    BEST_EFFORT = "best_effort"  # continue past member failures


class FaultGroup(BaseModel):
    """A set of fault members executed under one persistent identity.

    v1 semantics (ADR-M2-1): ``parallel`` runs members concurrently;
    ``sequential`` runs them in order; ``best_effort`` continues past member
    failures. ``atomic`` (strong all-or-nothing) is demoted to
    compensate-on-failure in v1. Every executed group carries a persistent
    ``execution_group_id`` and a ``group_path``; member faults share the id.
    Partial failure is a first-class result (which members succeeded/failed).
    """

    model_config = ConfigDict(frozen=True)

    execution_group_id: str
    parent_group_id: str | None = None
    mode: GroupMode = GroupMode.SEQUENTIAL
    path: str = "/"
    fault_ids: tuple[str, ...] = ()


class PlannedStep(BaseModel):
    """A step whose fault actions have been fully resolved against topology."""

    model_config = ConfigDict(frozen=True)

    id: str
    seq: int
    fault: PlannedFault | None = None
    target: TargetRef | None = None
    raw_action: StepAction  # for non-fault steps (wait/check)
    runtime_identity: RuntimeIdentity | None = None  # planned identity (ADR-M1-1/1-3)
    execution_group_id: str | None = None  # group attribution (ADR-M2-1/2-2)
    group_mode: GroupMode | None = None  # parallel|sequential|best_effort
    group_path: str | None = None  # hierarchical group location
