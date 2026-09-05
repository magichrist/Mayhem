"""Declarative observability collectors (ADR-M4-4).

Each declared source is collected within its own bounded timeout and the whole
pass respects the config's ``total_timeout``. Collection is **best-effort**:
a failing source is recorded as a failed collection with a note, never raised
to the run — evidence gathering must never break the drill.

Collected evidence is returned as :class:`SourceCollection` objects the
executor persists onto the run row and spools into the journal, so an observer
can replay exactly what was seen.
"""

from __future__ import annotations

import re
import time
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mayhem.agents.probes import run_probe
from mayhem.domain.checks import Probe, ProbeType
from mayhem.domain.common import utc_now
from mayhem.domain.leases import VerifyProbe
from mayhem.domain.observability import (
    InspectionSource,
    LogsSource,
    MetricsSource,
    ObservabilityConfig,
    ObservabilitySourceKind,
    ProbeSource,
    duration_seconds,
)
from mayhem.toolkit.tool_runner import run_tool

if TYPE_CHECKING:
    from mayhem.domain.observability import ObservabilitySource


_LEADING_NUMBER = re.compile(r"[-+]?[0-9]*\.?[0-9]+")


@dataclass(frozen=True)
class ObservabilitySample:
    """One measured value with its wall-clock timestamp."""

    at: str
    value: object

    @classmethod
    def now(cls, value: object) -> ObservabilitySample:
        return cls(at=utc_now().isoformat(), value=value)

    def to_jsonable(self) -> dict[str, object]:
        return {"at": self.at, "value": self.value}


@dataclass(frozen=True)
class SourceCollection:
    """Outcome of collecting one declared source."""

    source_id: str
    kind: ObservabilitySourceKind
    ok: bool
    note: str
    latency_ms: float
    samples: tuple[ObservabilitySample, ...] = ()
    skipped: bool = False

    def to_jsonable(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "kind": self.kind.value,
            "ok": self.ok,
            "note": self.note,
            "latency_ms": self.latency_ms,
            "skipped": self.skipped,
            "samples": [s.to_jsonable() for s in self.samples],
        }


def probe_to_verify(probe: Probe) -> VerifyProbe:
    """Canonical mapping of a domain ``Probe`` onto the agents ``VerifyProbe``.

    Lifted out of the executor so observability probe sources and check steps
    share the exact same runtime semantics (ADR-M4-2/4-4).
    """
    if probe.type is ProbeType.EXEC:
        return VerifyProbe(
            probe="exec",
            args={"cmd": list(probe.cmd), "timeout_s": float(probe.timeout)},
            expect_present=True,
        )
    if probe.type is ProbeType.TCP:
        return VerifyProbe(
            probe="tcp",
            args={
                "host": probe.host,
                "port": int(probe.port),
                "timeout_s": float(probe.timeout),
            },
            expect_present=True,
        )
    if probe.type is ProbeType.HTTP:
        return VerifyProbe(
            probe="http",
            args={
                "url": probe.url,
                "expect_status": int(probe.expected_status),
                "timeout_s": float(probe.timeout),
            },
            expect_present=True,
        )
    if probe.type is ProbeType.PROCESS:
        return VerifyProbe(
            probe="process",
            args={
                "name": probe.name,
                "pid": probe.pid,
                "timeout_s": float(probe.timeout),
            },
            expect_present=True,
        )
    if probe.type is ProbeType.METRIC:
        return VerifyProbe(
            probe="metric",
            args={
                "endpoint": probe.endpoint,
                "query": probe.query,
                "threshold": probe.threshold,
                "timeout_s": float(probe.timeout),
            },
            expect_present=True,
        )
    if probe.type is ProbeType.FILE:
        return VerifyProbe(
            probe="file",
            args={
                "path": probe.path,
                "contains": probe.contains,
                "timeout_s": float(probe.timeout),
            },
            expect_present=True,
        )
    raise AssertionError(f"unhandled probe type {probe.type!r}")


def _default_logs_runner(engine: str, timeout_s: float) -> Any:
    def run_container_logs(container: str, tail: int, since: str) -> tuple[str, float]:
        argv = [engine, "logs", "--tail", str(tail)]
        if since:
            argv += ["--since", since]
        argv.append(container)
        started = time.monotonic()
        result = run_tool(argv, timeout_s=timeout_s)
        latency_ms = round((time.monotonic() - started) * 1000, 3)
        if result.exit_code != 0:
            raise RuntimeError(f"{engine} logs exited {result.exit_code}: {result.stderr.strip()}")
        text = f"{result.stdout}\n{result.stderr}".strip()
        return text, latency_ms

    return run_container_logs


def _default_inspect_runner(engine: str, timeout_s: float) -> Any:
    def run_container_inspect(container: str) -> tuple[str, float]:
        started = time.monotonic()
        result = run_tool([engine, "inspect", container], timeout_s=timeout_s)
        latency_ms = round((time.monotonic() - started) * 1000, 3)
        if result.exit_code != 0:
            raise RuntimeError(
                f"{engine} inspect exited {result.exit_code}: {result.stderr.strip()}"
            )
        return result.stdout.strip(), latency_ms

    return run_container_inspect


def _default_probe_runner(timeout_s: float) -> Any:
    def run_domain_probe(probe: Probe) -> tuple[bool, str, float]:
        started = time.monotonic()
        result = run_probe(probe_to_verify(probe))
        latency_ms = round((time.monotonic() - started) * 1000, 3)
        return result.satisfied, result.detail, latency_ms

    return run_domain_probe


def _parse_prometheus_text(body: str, metric: str) -> float | None:
    """Resolve one metric's last sample value from Prometheus text format."""
    found: list[float] = []
    prefix = metric + "{"
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        name = parts[0]
        if name == metric or name.startswith(prefix):
            match = _LEADING_NUMBER.match(parts[1])
            if match is not None:
                found.append(float(match.group(0)))
    return found[-1] if found else None


def _default_metrics_runner(timeout_s: float) -> Any:
    def scrape_metric(endpoint: str, metric: str) -> tuple[float | None, str, float]:
        started = time.monotonic()
        with urllib.request.urlopen(endpoint, timeout=timeout_s) as response:
            body = response.read(1_048_576).decode("utf-8", errors="replace")
        latency_ms = round((time.monotonic() - started) * 1000, 3)
        value = _parse_prometheus_text(body, metric)
        note = "" if value is not None else f"metric {metric!r} not present in scrape"
        return value, note, latency_ms

    return scrape_metric


def collect_observability(
    cfg: ObservabilityConfig,
    *,
    engine: str = "podman",
) -> tuple[SourceCollection, ...]:
    """Collect every declared source within ``total_timeout`` (ADR-M4-4).

    Runners are module-level defaults that call ``toolkit.run_tool`` and the
    agents probe runner so real runs capture full tool evidence; tests inject
    fakes via the ``_collect_*`` helpers or monkeypatch the primitives.
    """
    if cfg.empty:
        return ()
    deadline = time.monotonic() + duration_seconds(cfg.total_timeout)
    default_cadence = duration_seconds(cfg.cadence)
    collections: list[SourceCollection] = []
    for source in cfg.sources:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            collections.append(
                SourceCollection(
                    source_id=source.source_id,
                    kind=ObservabilitySourceKind(source.kind),
                    ok=False,
                    note="pass total_timeout exhausted before this source",
                    latency_ms=0.0,
                    skipped=True,
                )
            )
            continue
        timeout_s = min(duration_seconds(getattr(source, "timeout", "10s")), remaining)
        cadence = duration_seconds(getattr(source, "cadence", "0s"))
        if cadence <= 0:
            cadence = default_cadence  # config-level cadence applies unless overridden
        collections.append(
            _collect_source(source, timeout_s=timeout_s, cadence=cadence, deadline=deadline)
        )
    return tuple(collections)


def _collect_source(
    source: ObservabilitySource,
    *,
    timeout_s: float,
    cadence: float,
    deadline: float,
) -> SourceCollection:
    if isinstance(source, LogsSource):
        return _collect_logs(source, timeout_s)
    if isinstance(source, InspectionSource):
        return _collect_inspection(source, timeout_s)
    if isinstance(source, ProbeSource):
        return _collect_probe(source, timeout_s, cadence, deadline)
    if isinstance(source, MetricsSource):
        return _collect_metrics(source, timeout_s, cadence, deadline)
    raise AssertionError(f"unhandled observability source {source!r}")


def _fail(source: ObservabilitySource, note: str) -> SourceCollection:
    return SourceCollection(
        source_id=source.source_id,
        kind=ObservabilitySourceKind(source.kind),
        ok=False,
        note=note,
        latency_ms=0.0,
    )


def _collect_logs(source: LogsSource, timeout_s: float) -> SourceCollection:
    try:
        text, latency = _default_logs_runner("podman", timeout_s)(
            source.container, source.tail, source.since
        )
        return SourceCollection(
            source_id=source.source_id,
            kind=ObservabilitySourceKind.LOGS,
            ok=True,
            note=f"collected {len(text)} chars",
            latency_ms=latency,
            samples=(ObservabilitySample.now(text),),
        )
    except Exception as exc:
        return _fail(source, f"collection failed: {type(exc).__name__}: {exc}")


def _collect_inspection(source: InspectionSource, timeout_s: float) -> SourceCollection:
    try:
        text, latency = _default_inspect_runner("podman", timeout_s)(source.container)
        return SourceCollection(
            source_id=source.source_id,
            kind=ObservabilitySourceKind.INSPECTION,
            ok=True,
            note=f"inspect {len(text)} chars",
            latency_ms=latency,
            samples=(ObservabilitySample.now(text),),
        )
    except Exception as exc:
        return _fail(source, f"collection failed: {type(exc).__name__}: {exc}")


def _collect_probe(
    source: ProbeSource, timeout_s: float, cadence: float, deadline: float
) -> SourceCollection:
    latency_ms_total = 0.0
    samples: list[ObservabilitySample] = []
    try:
        runner = _default_probe_runner(timeout_s)
        while True:
            satisfied, detail, latency = runner(source.probe)
            latency_ms_total += latency
            samples.append(ObservabilitySample.now({"satisfied": satisfied, "detail": detail}))
            if time.monotonic() >= deadline:
                break
            sleep_for = min(cadence, max(0.0, deadline - time.monotonic()))
            time.sleep(sleep_for)
            if time.monotonic() >= deadline:
                break
        return SourceCollection(
            source_id=source.source_id,
            kind=ObservabilitySourceKind.PROBE,
            ok=True,
            note=f"{len(samples)} probe sample(s)",
            latency_ms=round(latency_ms_total, 3),
            samples=tuple(samples),
        )
    except Exception as exc:
        return _fail(
            source,
            f"collection failed: {type(exc).__name__}: {exc}",
        )


def _collect_metrics(
    source: MetricsSource, timeout_s: float, cadence: float, deadline: float
) -> SourceCollection:
    latency_ms_total = 0.0
    samples: list[ObservabilitySample] = []
    note = ""
    try:
        runner = _default_metrics_runner(timeout_s)
        while True:
            value, scrape_note, latency = runner(source.endpoint, source.metric)
            latency_ms_total += latency
            samples.append(ObservabilitySample.now(value))
            if value is None and scrape_note:
                note = scrape_note
            if time.monotonic() >= deadline:
                break
            sleep_for = min(cadence, max(0.0, deadline - time.monotonic()))
            time.sleep(sleep_for)
            if time.monotonic() >= deadline:
                break
        return SourceCollection(
            source_id=source.source_id,
            kind=ObservabilitySourceKind.METRICS,
            ok=note == "" or bool(samples),
            note=note or f"{len(samples)} metric sample(s)",
            latency_ms=round(latency_ms_total, 3),
            samples=tuple(samples),
        )
    except Exception as exc:
        return _fail(source, f"collection failed: {type(exc).__name__}: {exc}")
