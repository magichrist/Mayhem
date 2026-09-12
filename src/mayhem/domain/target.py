"""Logical target identity — the normalized cross-runtime model (k-plan-1 §1.3).

Both DSL paths (``containers:`` and ``targets:``) desugar into a single
:class:`TargetScope`. The planner, executor, and recovery code touch **only**
this — never ``Pod.name == container_name``.

"Target" is the logical thing the user wants to perturb; the concrete runtime
object is a separate concern resolved at plan/execution time (k-plan-1 §1.4).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from mayhem.domain.identity import RuntimeLabel


class ResourceKind(StrEnum):
    """The concrete runtime object family a target locates (k-plan-1 §1.3)."""

    CONTAINER = "container"  # docker/podman (desugared from ``containers:``)
    DEPLOYMENT = "deployment"
    STATEFULSET = "statefulset"
    DAEMONSET = "daemonset"
    SERVICE = "service"
    POD = "pod"
    K8S_NODE = "k8s_node"


class SelectionMode(StrEnum):
    """Selection grammar (k-plan-1 §1.2). ``one`` is the only implemented mode.

    ``all`` / ``count`` / ``percentage`` / ``random`` are schema-valid but
    compile-refused with a "reserved until k-plan-4" plan error.
    """

    ONE = "one"
    ALL = "all"
    COUNT = "count"
    PERCENTAGE = "percentage"
    RANDOM = "random"



#: Modes accepted by the schema (full grammar) but refused at compile time.
RESERVED_SELECTION_MODES: frozenset[SelectionMode] = frozenset(
    {
        SelectionMode.ALL,
        SelectionMode.COUNT,
        SelectionMode.PERCENTAGE,
        SelectionMode.RANDOM,
    }
)


class SelectionSpec(BaseModel):
    """Which instances of a target are chosen (k-plan-1 §1.2 grammar).

    Validation is schema-level only: every mode parses (so the full grammar is
    documentable), but the planner refuses anything but ``mode: one`` with
    ``PlanningError`` — the reserved modes land in k-plan-4.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: SelectionMode = SelectionMode.ONE
    count: int | None = Field(default=None, ge=1)
    percentage: float | None = Field(default=None, gt=0, le=100)

    @field_validator("count", "percentage")
    @classmethod
    def _requires_companion_mode(
        cls, value: float | int | None, info: ValidationInfo
    ) -> float | int | None:
        # Companion-mode fields are meaningful only when the mode matches;
        # a value without its mode is a schema smell and refused eagerly.
        if value is not None:
            mode = info.data
            companion = (
                SelectionMode.COUNT if isinstance(value, int) else SelectionMode.PERCENTAGE
            )
            if mode.get("mode") != companion:
                raise ValueError(
                    f"{companion.value} requires selection.mode: {companion.value}"
                )
        return value


class TargetScope(BaseModel):
    """Normalized logical target — frozen, equality-bearing, planner-owned.

    ``authority`` carries the locator material per kind: docker/podman use
    ``container_name``, kubernetes uses ``api_group``/``namespace``/``name``
    (the stable workload name, never a generated pod name).
    """

    model_config = ConfigDict(frozen=True)

    logical_id: str = Field(min_length=1)
    runtime: RuntimeLabel
    kind: ResourceKind
    authority: dict[str, str] = Field(default_factory=dict)
    container: str | None = None  # k8s: container within the pod
    selection: SelectionSpec | None = None

    @field_validator("logical_id")
    @classmethod
    def _logical_id_clean(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("target logical_id must be non-empty")
        return value.strip()


#: ``TargetRef`` is the canonical concept name (k-plan-1 §1.3/§1.5); the
#: concrete identity is :class:`TargetScope`. Every planned fault pins one.
TargetRef = TargetScope
