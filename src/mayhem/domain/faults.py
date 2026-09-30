"""Fault definitions and invocations (ADR-0004, fault-taxonomy contract).

A ``FaultDefinition`` is exactly what safety/planning consumes; the coverage
matrix in ``docs/fault-catalog/`` is generated from these definitions and only
counts cells proven by tests.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.capabilities import Capability, Identifier
from mayhem.domain.common import Duration, parse_bytes, parse_duration
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.risks import EnvironmentClass, RiskLevel
from mayhem.domain.topology import NodeKind


class FaultCategory(StrEnum):
    PROCESS = "process"
    CPU = "cpu"
    MEMORY = "memory"
    STORAGE = "storage"
    NETWORK = "network"
    CONTAINER = "container"
    NODE = "node"
    HTTP_API = "http_api"
    DATABASE = "database"
    LOAD = "load"
    FUZZ = "fuzz"
    DNS = "dns"
    TLS = "tls"
    CLOCK = "clock"
    FD = "fd"
    DEPENDENCY = "dependency"
    K8S = "k8s"  # ADR-M7-3: capacity / network / preemption sub-categories

    @classmethod
    def from_fault_id(cls, fault_id: str) -> FaultCategory:
        prefix = fault_id.split(".", 1)[0]
        category = _PREFIX_TO_CATEGORY.get(prefix)
        if category is None:
            raise SchemaValidationError(
                "fault_id",
                f"unknown category prefix {prefix!r} in {fault_id!r}; "
                f"expected one of {sorted(_PREFIX_TO_CATEGORY)}",
            )
        return category


_PREFIX_TO_CATEGORY: dict[str, FaultCategory] = {
    "net": FaultCategory.NETWORK,
    "cpu": FaultCategory.CPU,
    "mem": FaultCategory.MEMORY,
    "fs": FaultCategory.STORAGE,
    "disk": FaultCategory.STORAGE,
    "storage": FaultCategory.STORAGE,
    "proc": FaultCategory.PROCESS,
    "process": FaultCategory.PROCESS,
    "container": FaultCategory.CONTAINER,
    "node": FaultCategory.NODE,
    "http": FaultCategory.HTTP_API,
    "app": FaultCategory.HTTP_API,
    "db": FaultCategory.DATABASE,
    "load": FaultCategory.LOAD,
    "fuzz": FaultCategory.FUZZ,
    "dns": FaultCategory.DNS,
    "tls": FaultCategory.TLS,
    "clock": FaultCategory.CLOCK,
    "fd": FaultCategory.FD,
    "dependency": FaultCategory.DEPENDENCY,
    "k8s": FaultCategory.K8S,
}


class FailureDomain(StrEnum):
    PROCESS = "process"
    CPU = "cpu"
    MEMORY = "memory"
    STORAGE = "storage"
    NETWORK = "network"
    APPLICATION = "application"
    DEPENDENCY = "dependency"
    PLATFORM = "platform"


class TargetKind(StrEnum):
    CONTAINER = "container"
    PROCESS = "process"
    SERVICE = "service"
    POD = "pod"
    WORKLOAD = "workload"
    NODE = "node"
    CLUSTER_OBJECT = "cluster_object"
    EXTERNAL_DEPENDENCY = "external_dependency"
    HPA = "hpa"
    PDB = "pdb"


class EngineLane(StrEnum):
    DOCKER = "docker"
    PODMAN = "podman"
    KUBERNETES = "kubernetes"
    HOST = "host"
    MULTI_ENGINE = "multi-engine"


class Reversibility(StrEnum):
    REVERSIBLE = "reversible"
    RECONCILED = "reconciled"
    IRREVERSIBLE = "irreversible"


class VerificationMethod(StrEnum):
    PROCESS_SIGNAL = "process-signal"
    PROCESS_EXIT = "process-exit"
    RESOURCE_METRIC = "resource-metric"
    HTTP_RESPONSE = "http-response"
    DEPENDENCY_RESPONSE = "dependency-response"
    NETWORK_PATH = "network-path"
    STORAGE_ACCESS = "storage-access"
    DNS_RESOLUTION = "dns-resolution"
    KUBERNETES_OBJECT = "kubernetes-object"
    PLATFORM_STATE = "platform-state"


class MaturityLevel(StrEnum):
    """How far a fault definition has actually been exercised.

    These are claims about *evidence*, ordered by how much evidence stands
    behind them. The order is enforced: a fault can only reach a rung by
    satisfying every lower rung's criteria first. The executable form of that
    rule — and the per-criterion evidence each rung requires — lives in
    ``infra.promotion``; :func:`evaluate_maturity` there is the only thing that
    decides a fault's *reported* level.

    ``FaultDefinition.maturity`` is the catalog's **declaration**, not the
    reported value. ``domain.catalog._define()`` stamps
    ``VERIFIED_UNIT`` (with a fixed ``verification_date``) onto every
    non-``catalog_only`` entry, so the declared field is a constant that
    distinguishes nothing. Reports therefore carry the derived level and, beside
    it, the declaration, so a stale badge stays visible.

    Attributes:
        EXPERIMENTAL: Not unit-verified. The catalog entry does not satisfy the
            ``verified-unit`` criteria recomputed at read time, or the fault is
            ``catalog_only`` and refuses to execute. Only ``catalog_only``
            entries may declare this.
        VERIFIED_UNIT: Verified **in isolation only**. The parameter grammar,
            the deterministic refusal path, and the compensation contract check
            out in-process. This is a guarantee about mayhem's own code — it is
            not a claim that the fault perturbs a real system.
        VERIFIED_LIVE: Injected into a running stack on the required container
            engines with a recorded evidence bundle; the declared effect was
            observed and the undo restored the pre-injection baseline within
            tolerance. Earned only from a recorded live run.
        STABLE: ``VERIFIED_LIVE`` plus strictly more: the whole declared
            engine-lane matrix verified, the same verification repeated across
            distinct days, and a documented deprecation and rollback policy.
            A single successful run on a subset of engines is not ``STABLE``.
    """

    EXPERIMENTAL = "experimental"
    VERIFIED_UNIT = "verified-unit"
    VERIFIED_LIVE = "verified-live"
    STABLE = "stable"

    @property
    def requires_evidence(self) -> bool:
        """True when the rung cannot be reached by catalog declaration alone."""
        return self in (MaturityLevel.VERIFIED_LIVE, MaturityLevel.STABLE)

    @classmethod
    def at_or_below(cls, ceiling: MaturityLevel) -> tuple[MaturityLevel, ...]:
        """Every rung up to and including ``ceiling``, in climb order."""
        ladder = (
            MaturityLevel.EXPERIMENTAL,
            MaturityLevel.VERIFIED_UNIT,
            MaturityLevel.VERIFIED_LIVE,
            MaturityLevel.STABLE,
        )
        return tuple(level for level in ladder if ladder.index(level) <= ladder.index(ceiling))


class ParamType(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    DURATION = "duration"
    PERCENT = "percent"
    BYTES = "bytes"


class ParamSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: Identifier
    type: ParamType
    required: bool = False
    default: str | int | float | bool | None = None
    minimum: float | None = None
    maximum: float | None = None
    min_length: int | None = None


class FaultDefinition(BaseModel):
    """Metadata contract for one fault (see docs/architecture/fault-taxonomy.md)."""

    model_config = ConfigDict(frozen=True)

    id: str
    category: FaultCategory
    risk: RiskLevel
    reversible: bool = True
    required_caps: frozenset[Capability] = Field(default_factory=frozenset)
    applicable_node_kinds: frozenset[NodeKind] = Field(default_factory=frozenset)
    max_duration_s: float = 300.0
    backends: tuple[Identifier, ...] = ()
    safe_env_classes: frozenset[EnvironmentClass] = Field(
        default_factory=lambda: frozenset(EnvironmentClass)
    )
    params_schema: tuple[ParamSpec, ...] = ()
    failure_domain: FailureDomain | None = None
    target_kind: TargetKind | None = None
    target_kinds: frozenset[TargetKind] = Field(default_factory=frozenset)
    engine_lanes: frozenset[EngineLane] = Field(default_factory=frozenset)
    observable_effect: str = ""
    compensation_evidence: tuple[str, ...] = ()
    verification_method: VerificationMethod | None = None
    reversibility: Reversibility | None = None
    maturity: MaturityLevel = MaturityLevel.EXPERIMENTAL
    verification_date: date | None = None
    catalog_only: bool = False
    refusal_reason: str | None = None
    replacement_fault_id: str | None = None
    deprecation_path: str | None = None

    @field_validator("id")
    @classmethod
    def _known_prefix(cls, value: str) -> str:
        FaultCategory.from_fault_id(value)  # raises on unknown prefix
        return value

    @model_validator(mode="after")
    def _category_matches_id(self) -> FaultDefinition:
        expected = FaultCategory.from_fault_id(self.id)
        if self.category is not expected:
            raise SchemaValidationError(
                "category",
                f"fault {self.id!r} declares category {self.category.value!r} "
                f"but prefix maps to {expected.value!r}",
            )
        return self

    def validate_params(self, params: dict[str, object]) -> dict[str, object]:
        """Validate raw params against ``params_schema``; returns normalized values.

        Raises:
            SchemaValidationError: On unknown, missing, or mistyped parameters.
        """
        known = {spec.name: spec for spec in self.params_schema}
        normalized: dict[str, object] = {}
        for name in params:
            if name not in known:
                raise SchemaValidationError(f"params[{self.id}]", f"unknown parameter {name!r}")
        for spec in self.params_schema:
            if spec.name not in params:
                if spec.required and spec.default is None:
                    raise SchemaValidationError(
                        f"params[{self.id}]",
                        f"missing required parameter {spec.name!r}",
                    )
                if spec.default is not None:
                    normalized[spec.name] = spec.default
                continue
            normalized[spec.name] = _coerce(spec, params[spec.name])
        return normalized


class FaultInvocation(BaseModel):
    """One concrete fault application against resolved targets."""

    model_config = ConfigDict(frozen=True)

    fault_id: str
    targets: frozenset[str]  # resolved node ids; non-empty enforced below
    params: dict[str, object] = Field(default_factory=dict)
    duration: Duration
    backend: Identifier | None = None  # None => executor picks via fallback group
    lease_id: str | None = None  # set when recovery machinery takes ownership

    @field_validator("targets")
    @classmethod
    def _at_least_one_target(cls, value: frozenset[str]) -> frozenset[str]:
        if not value:
            raise SchemaValidationError("targets", "fault invocation requires >= 1 target")
        return value

    @field_validator("fault_id")
    @classmethod
    def _valid_fault_id(cls, value: str) -> str:
        FaultCategory.from_fault_id(value)
        return value


def _numeric(raw: object) -> float:
    """Strict numeric coercion; bools are not numbers in fault params."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raise TypeError("expected a number")
    return float(raw)


def _convert_duration(raw: object) -> float:
    if isinstance(raw, (int, float)):
        return float(raw)
    return parse_duration(str(raw))


def _convert(spec: ParamSpec, raw: object) -> object:
    match spec.type:
        case ParamType.STRING:
            value: object = str(raw)
        case ParamType.INTEGER:
            number = _numeric(raw)
            if not number.is_integer():
                raise ValueError(f"{raw!r} is not an integer")
            value = int(number)
        case ParamType.FLOAT:
            value = _numeric(raw)
        case ParamType.BOOLEAN:
            if not isinstance(raw, bool):
                raise ValueError("expected boolean")
            value = raw
        case ParamType.DURATION:
            value = _convert_duration(raw)
        case ParamType.BYTES:
            value = parse_bytes(str(raw))
        case ParamType.PERCENT:
            number = _numeric(raw)
            if not 0.0 <= number <= 100.0:
                raise ValueError(f"{number} outside [0, 100]")
            value = number
        case _:
            raise AssertionError(f"unhandled param type {spec.type}")
    return value


def _coerce(spec: ParamSpec, raw: object) -> object:
    try:
        result = _convert(spec, raw)
    except (TypeError, ValueError) as exc:
        raise SchemaValidationError(
            f"params[{spec.name}]", f"{raw!r} is not a valid {spec.type.value}: {exc}"
        ) from exc
    if isinstance(result, (int, float)) and not isinstance(result, bool):
        if spec.minimum is not None and float(result) < spec.minimum:
            raise SchemaValidationError(f"params[{spec.name}]", f"below minimum {spec.minimum}")
        if spec.maximum is not None and float(result) > spec.maximum:
            raise SchemaValidationError(f"params[{spec.name}]", f"above maximum {spec.maximum}")
    if (
        spec.type is ParamType.STRING
        and spec.min_length is not None
        and len(str(result).strip()) < spec.min_length
    ):
        raise SchemaValidationError(
            f"params[{spec.name}]", f"must contain at least {spec.min_length} character(s)"
        )
    return result
