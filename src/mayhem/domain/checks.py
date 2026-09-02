"""Steady-state checks and evaluation records.

Checks are evaluated in three phases — pre (baseline gate), during (violation
policy), post (recovery proof). Measured values are recorded verbatim so
summaries can quote numbers rather than adjectives.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from mayhem.domain.common import Duration


class ProbeType(StrEnum):
    HTTP = "http"
    EXEC = "exec"
    TCP = "tcp"
    PROCESS = "process"
    METRIC = "metric"
    FILE = "file"


class HttpProbe(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[ProbeType.HTTP] = ProbeType.HTTP
    url: str
    method: str = "GET"
    timeout: Duration = 5.0
    expected_status: int = 200


class ExecProbe(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[ProbeType.EXEC] = ProbeType.EXEC
    cmd: tuple[str, ...]
    timeout: Duration = 10.0
    expected_exit_code: int = 0


class TcpProbe(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[ProbeType.TCP] = ProbeType.TCP
    host: str
    port: int = Field(ge=1, le=65535)
    timeout: Duration = 3.0


class ProcessProbe(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[ProbeType.PROCESS] = ProbeType.PROCESS
    name: str = ""  # process name/pattern (e.g. "nginx")
    pid: int | None = Field(default=None, ge=1)
    timeout: Duration = 5.0


class MetricProbe(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[ProbeType.METRIC] = ProbeType.METRIC
    endpoint: str = ""  # metrics endpoint (e.g. "http://svc:9090/metrics")
    query: str = ""  # metric name / label selector
    threshold: float | None = None  # lower bound for the sampled value
    timeout: Duration = 5.0


class FileProbe(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: Literal[ProbeType.FILE] = ProbeType.FILE
    path: str  # path to check inside the execution locus
    contains: str | None = None  # optional content substring to require
    timeout: Duration = 5.0


Probe = Annotated[
    HttpProbe | ExecProbe | TcpProbe | ProcessProbe | MetricProbe | FileProbe,
    Field(discriminator="type"),
]
_probe_adapter: TypeAdapter[Probe] = TypeAdapter(Probe)


def parse_probe(data: object) -> Probe:
    """Parse untyped probe data into the closed probe union."""
    return _probe_adapter.validate_python(data)


class Expectation(BaseModel):
    """Declarative pass criteria over measured probe results."""

    model_config = ConfigDict(frozen=True)

    status_eq: int | None = None
    exit_code_eq: int | None = None
    reachable: bool | None = None
    p99_ms_lt: float | None = None
    error_rate_lt: float | None = None  # fraction 0..1


class OnPreFailure(StrEnum):
    SKIP_RUN = "skip_run"
    ABORT = "abort"


class CheckLocus(StrEnum):
    """Where a check is evaluated — distinct from the fault target's locus.

    A bare (unqualified) check infers its locus from the fault target for
    backward compatibility (ADR-M4-2); an explicit locus is honored as-is.
    """

    HOST = "host"
    CONTAINER = "container"
    SERVICE = "service"
    PROCESS = "process"


class SteadyStateCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    probe: Probe
    expect: Expectation = Field(default_factory=Expectation)
    description: str = ""


class CheckSpec(BaseModel):
    """A drill check: a probe evaluated at an explicit or inferred locus (ADR-M4-2).

    ``execution`` declares where the check runs (host / container / service /
    process); when unset (None) the executor infers it from the fault target so
    pre-0.3.0 specs behave unchanged. ``target`` names the fault target container
    used for that inference.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    probe: Probe
    execution: CheckLocus | None = None  # None → infer from fault target
    expect: Expectation = Field(default_factory=Expectation)
    target: str | None = None  # fault target container for locus inference


class CheckPhase(StrEnum):
    PRE = "pre"
    DURING = "during"
    POST = "post"


class EvaluationResult(BaseModel):
    """One check evaluation in one phase; stored verbatim in history."""

    model_config = ConfigDict(frozen=True)

    check_id: str
    phase: CheckPhase
    passed: bool
    measured: dict[str, Any]  # e.g. {"status": 200, "p99_ms": 182.4}
    evaluated_at_epoch_s: float
    detail: str = ""

    def summary(self) -> str:
        verdict = "PASS" if self.passed else "FAIL"
        measured = ", ".join(f"{k}={v}" for k, v in self.measured.items())
        return f"[{self.phase.value}] {self.check_id}: {verdict} ({measured})"
