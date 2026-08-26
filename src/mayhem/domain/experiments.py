"""Experiment specs and execution plans.

``DeterministicExperiment`` / ``RandomExperiment`` are authoring surfaces;
``ExecutionPlan`` is the frozen, validated output of compilation. The plan pins
config/topology snapshot ids so any later analysis knows what the controller
knew when it committed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.capabilities import Identifier
from mayhem.domain.checks import Expectation, OnPreFailure
from mayhem.domain.common import Duration
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_context import ExecutionContextSpec
from mayhem.domain.faults import FaultCategory
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import TargetSelector


class ExperimentKind(StrEnum):
    DETERMINISTIC = "deterministic"
    RANDOM = "random"


class ExperimentMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    hypothesis: str = ""
    labels: dict[str, str] = Field(default_factory=dict)


class OnFailure(StrEnum):
    ABORT_AND_RECOVER = "abort_and_recover"
    CONTINUE = "continue"


class RetryPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    attempts: int = Field(default=1, ge=1)
    backoff_seconds: Duration = 1.0


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


class LoadProfile(BaseModel):
    """Parameters for load tools (k6 et al.)."""

    model_config = ConfigDict(frozen=True)

    vus: int | None = Field(default=None, ge=1)
    duration: Duration | None = None


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


class StartLoad(BaseModel):
    type: Literal["start_load"] = "start_load"
    tool: Identifier
    script: str | None = None
    profile: LoadProfile | None = None
    name: str | None = None  # reference for stop_load


class StopLoad(BaseModel):
    type: Literal["stop_load"] = "stop_load"
    name: str


class Wait(BaseModel):
    type: Literal["wait"] = "wait"
    duration: Duration | None = None
    until_check_passes: str | None = None  # check id
    timeout: Duration = 120.0


class CheckStep(BaseModel):
    type: Literal["check"] = "check"
    ref: str  # steady-state check id


class Notify(BaseModel):
    type: Literal["notify"] = "notify"
    channel: Literal["slack", "webhook"]
    message: str


class Parallel(BaseModel):
    type: Literal["parallel"] = "parallel"
    branches: tuple[tuple[StepAction, ...], ...] = ()

    @field_validator("branches")
    @classmethod
    def _non_empty_branches(
        cls, value: tuple[tuple[StepAction, ...], ...]
    ) -> tuple[tuple[StepAction, ...], ...]:
        if not value:
            raise InvariantViolationError("parallel_requires_branches", ">= 1 branch required")
        return value


StepAction = Annotated[
    InjectFault | StartLoad | StopLoad | Wait | CheckStep | Notify | Parallel,
    Field(discriminator="type"),
]


class Step(BaseModel):
    """One scheduled unit of an experiment."""

    model_config = ConfigDict(frozen=True)

    id: str
    action: StepAction
    timeout: Duration | None = None
    retries: RetryPolicy = Field(default_factory=RetryPolicy)
    on_failure: OnFailure = OnFailure.ABORT_AND_RECOVER


# -- specs ------------------------------------------------------------------------------


class SteadyStateCheckSpec(BaseModel):
    """Authoring-side check; compiles to domain checks.SteadyStateCheck."""

    model_config = ConfigDict(frozen=True)

    id: str
    probe: object  # parsed by checks.parse_probe at compile time
    expect: Expectation = Field(default_factory=Expectation)
    on_pre_failure: OnPreFailure = OnPreFailure.SKIP_RUN
    description: str = ""


class SelectionPolicy(BaseModel):
    """Random-experiment selection inputs (ADR-0009)."""

    model_config = ConfigDict(frozen=True)

    count: int = Field(default=1, ge=1)
    categories: frozenset[FaultCategory] | None = None
    exclude_faults: frozenset[str] = Field(default_factory=frozenset)
    forbidden_pairs: frozenset[frozenset[str]] = Field(default_factory=frozenset)
    weights: dict[str, float] | None = None  # per-fault lottery weights; default 1.0
    diversity_window: int = Field(default=10, ge=1)


class DeterministicExperiment(BaseModel):
    kind: Literal[ExperimentKind.DETERMINISTIC] = ExperimentKind.DETERMINISTIC
    metadata: ExperimentMetadata
    method: str = ""
    constraints: Constraints = Field(default_factory=Constraints)
    steady_state: tuple[SteadyStateCheckSpec, ...] = ()
    steps: tuple[Step, ...]

    @field_validator("steps")
    @classmethod
    def _at_least_one_step(cls, value: tuple[Step, ...]) -> tuple[Step, ...]:
        if not value:
            raise InvariantViolationError("experiment_requires_steps", "no steps defined")
        return value


class RandomExperiment(BaseModel):
    kind: Literal[ExperimentKind.RANDOM] = ExperimentKind.RANDOM
    metadata: ExperimentMetadata
    constraints: Constraints = Field(default_factory=Constraints)
    seed: int | None = None  # None => derive & record
    selection: SelectionPolicy = Field(default_factory=SelectionPolicy)


ExperimentSpec = DeterministicExperiment | RandomExperiment


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

    @model_validator(mode="after")
    def _check_plan(self) -> ExecutionPlan:
        return self


class PlannedStep(BaseModel):
    """A step whose fault actions have been fully resolved against topology."""

    model_config = ConfigDict(frozen=True)

    id: str
    seq: int
    fault: PlannedFault | None = None
    raw_action: StepAction  # for non-fault steps (wait/check/load/notify)
