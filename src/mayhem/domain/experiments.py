"""Experiment specs and execution plans.

``DrillSpec`` is the authored input format (ADR-0019); ``ExecutionPlan`` is
the frozen, validated output of compilation. The plan pins config/topology
snapshot ids so any later analysis knows what the controller knew when it
committed. Since the clean break (ADR-0021) the only supported kind is
``drill`` — the deterministic/random authoring surfaces were removed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.capabilities import Identifier
from mayhem.domain.checks import CheckLocus, CheckSpec, Probe
from mayhem.domain.common import Duration
from mayhem.domain.decisions import DecisionRef
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_context import ExecutionContextSpec
from mayhem.domain.faults import FaultCategory
from mayhem.domain.identity import RuntimeIdentity
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.observability import ObservabilityConfig
from mayhem.domain.risks import RiskLevel
from mayhem.domain.success import SuccessCriteria
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
    params: dict[str, object] = Field(default_factory=dict)
    duration: Duration
    backend: Identifier | None = None
    execution: ExecutionContextSpec | None = None  # ADR-0014; None → infer from target

    @field_validator("fault")
    @classmethod
    def _known_category(cls, value: str) -> str:
        FaultCategory.from_fault_id(value)
        return value

    @field_validator("selectors")
    @classmethod
    def _non_empty_selectors(cls, value: tuple[TargetSelector, ...]) -> tuple[TargetSelector, ...]:
        if not value:
            raise InvariantViolationError(
                "step_requires_targets", "inject_fault needs >= 1 selector"
            )
        return value


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


class DrillConfig(BaseModel):
    """Configuration for a drill spec — replaces the separate mayhem.yml."""

    model_config = ConfigDict(frozen=True)

    risk_ceiling: RiskLevel = RiskLevel.HIGH
    max_faults: int = Field(default=1, ge=0)
    timeout: Duration = "30m"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"


class DrillFault(BaseModel):
    """A single fault to inject on a container."""

    model_config = ConfigDict(frozen=True, extra="allow")

    fault: str
    duration: Duration = "10s"
    on_failure: OnFailure = OnFailure.ABORT_AND_RECOVER
    targets: tuple[str, ...] = ()  # for network faults: container names to partition
    network_path: str | None = None  # ADR-M3-7 optional path target for network faults


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


class DrillSpec(BaseModel):
    """Unified drill spec — single YAML file replacing config + fault spec (ADR-0019)."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["drill"]
    name: str
    hypothesis: str = ""
    config: DrillConfig = Field(default_factory=DrillConfig)
    containers: dict[str, DrillContainer]  # key = container_name from docker-compose
    execution: tuple[ExecutionStep, ...]
    success: SuccessCriteria | None = None  # optional machine verdict (ADR-M4-3)
    observability: ObservabilityConfig | None = None  # optional evidence sources (ADR-M4-4)

    @field_validator("containers")
    @classmethod
    def _at_least_one_container(cls, value: dict[str, DrillContainer]) -> dict[str, DrillContainer]:
        if not value:
            raise InvariantViolationError("drill_requires_containers", "no containers defined")
        return value

    @field_validator("execution")
    @classmethod
    def _at_least_one_step(cls, value: tuple[ExecutionStep, ...]) -> tuple[ExecutionStep, ...]:
        if not value:
            raise InvariantViolationError("drill_requires_execution", "no execution steps defined")
        return value


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
    undo_ops: tuple[UndoOp, ...] = ()
    verify_probes: tuple[VerifyProbe, ...] = ()
    params: dict[str, object] = Field(default_factory=dict)
    duration: Duration
    backend: Identifier | None = None
    execution_context: ExecutionContextSpec | None = None  # ADR-0014
    runtime_identity: RuntimeIdentity | None = None  # planned identity (ADR-M1-1/1-3)
    execution_loci: dict[str, object] | None = None  # ADR-M3-3 target/agent/tool loci


class ExecutionPlan(BaseModel):
    """Frozen contract handed from planning to execution."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    kind: ExperimentKind
    steps: tuple[PlannedStep, ...]
    config_snapshot_id: str
    topology_snapshot_id: str
    environment_fingerprint: str
    seed: int | None = None
    success: SuccessCriteria | None = None  # copied from the spec (ADR-M4-3)
    observability: ObservabilityConfig | None = None  # copied from the spec (ADR-M4-4)
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
    raw_action: StepAction  # for non-fault steps (wait/check)
    runtime_identity: RuntimeIdentity | None = None  # planned identity (ADR-M1-1/1-3)
    execution_group_id: str | None = None  # group attribution (ADR-M2-1/2-2)
    group_mode: GroupMode | None = None  # parallel|sequential|best_effort
    group_path: str | None = None  # hierarchical group location
