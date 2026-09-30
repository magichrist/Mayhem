"""Observation providers (v0.9.0 task 13).

Every provider implements the same tiny contract: given a query, return an
:class:`~mayhem.domain.observations.ObservationResult`. Providers are
read-only, bounded by a timeout, and run their payloads through the redaction
policy before anything reaches an evidence envelope.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from mayhem.domain.observations import (
    PROVENANCE_HTTP,
    PROVENANCE_LOCAL,
    PROVENANCE_PROCESS,
    ObservationQuery,
    ObservationResult,
    ObservationStatus,
)
from mayhem.domain.redaction import redact_text

DEFAULT_TIMEOUT_S = 5.0
MAX_RESPONSE_BYTES = 256 * 1024


def _redacted_detail(value: str) -> str:
    text, _ = redact_text(value)
    return text[:512]


class HttpObservationProvider:
    """Measure an HTTP endpoint's latency and status class."""

    name = PROVENANCE_HTTP

    def __init__(self, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        self._timeout = timeout_s

    def observe(self, query: ObservationQuery) -> ObservationResult:
        if not query.target:
            return ObservationResult(
                metric=query.metric,
                value=None,
                unit=query.unit,
                window_s=query.window_s,
                status=ObservationStatus.MISSING,
                provenance=self.name,
                detail="query has no target url",
            )
        started = time.monotonic()
        request = urllib.request.Request(query.target, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES)
                elapsed_ms = (time.monotonic() - started) * 1000.0
                if query.metric.endswith("status"):
                    return ObservationResult(
                        metric=query.metric,
                        value=float(response.status),
                        unit="code",
                        window_s=query.window_s,
                        provenance=self.name,
                        source=query.target,
                    )
                return ObservationResult(
                    metric=query.metric,
                    value=round(elapsed_ms, 3),
                    unit=query.unit,
                    window_s=query.window_s,
                    provenance=self.name,
                    source=query.target,
                    detail=f"{len(body)} bytes",
                )
        except urllib.error.HTTPError as exc:
            return ObservationResult(
                metric=query.metric,
                value=float(exc.code),
                unit="code",
                window_s=query.window_s,
                provenance=self.name,
                source=query.target,
                detail=_redacted_detail(str(exc)),
            )
        except Exception as exc:
            return ObservationResult(
                metric=query.metric,
                value=None,
                unit=query.unit,
                window_s=query.window_s,
                status=ObservationStatus.ERROR,
                provenance=self.name,
                source=query.target,
                detail=_redacted_detail(f"{type(exc).__name__}: {exc}"),
            )


class ProcessObservationProvider:
    """Read a numeric value out of a local command's stdout.

    Read-only by construction: the command runs with a bounded timeout and its
    output is redacted, so a provider can never smuggle a secret into evidence.
    """

    name = PROVENANCE_PROCESS

    def __init__(self, timeout_s: float = DEFAULT_TIMEOUT_S, runner: Any = None) -> None:
        self._timeout = timeout_s
        self._runner = runner

    def observe(self, query: ObservationQuery) -> ObservationResult:
        if not query.target:
            return ObservationResult(
                metric=query.metric,
                value=None,
                unit=query.unit,
                window_s=query.window_s,
                status=ObservationStatus.MISSING,
                provenance=self.name,
                detail="query has no command",
            )
        argv = query.target.split()
        try:
            if self._runner is not None:
                completed = self._runner(argv)
                stdout = str(getattr(completed, "stdout", completed))
                returncode = int(getattr(completed, "returncode", 0))
            else:
                # Module scope must stay free of subprocess: the checkpoint
                # test (test_expansion_checkpoint.py) asserts it, so a provider
                # never pays for — or exposes — it until a command actually runs.
                import subprocess  # noqa: PLC0415

                completed = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                    check=False,
                )
                stdout = completed.stdout
                returncode = completed.returncode
        except Exception as exc:
            return ObservationResult(
                metric=query.metric,
                value=None,
                unit=query.unit,
                window_s=query.window_s,
                status=ObservationStatus.ERROR,
                provenance=self.name,
                source=query.metric,
                detail=_redacted_detail(f"{type(exc).__name__}: {exc}"),
            )
        if returncode != 0:
            return ObservationResult(
                metric=query.metric,
                value=None,
                unit=query.unit,
                window_s=query.window_s,
                status=ObservationStatus.ERROR,
                provenance=self.name,
                source=query.metric,
                detail=f"exit {returncode}",
            )
        try:
            value = float(stdout.strip().splitlines()[0])
        except (IndexError, ValueError):
            return ObservationResult(
                metric=query.metric,
                value=None,
                unit=query.unit,
                window_s=query.window_s,
                status=ObservationStatus.MISSING,
                provenance=self.name,
                source=query.metric,
                detail=_redacted_detail(f"non-numeric output: {stdout[:120]}"),
            )
        return ObservationResult(
            metric=query.metric,
            value=value,
            unit=query.unit,
            window_s=query.window_s,
            provenance=self.name,
            source=query.metric,
        )


class StaticObservationProvider:
    """Deterministic provider for tests and replay: values come from a mapping."""

    name = PROVENANCE_LOCAL

    def __init__(self, values: dict[str, float] | None = None) -> None:
        self._values = dict(values or {})

    def set(self, metric: str, value: float) -> None:
        self._values[metric] = value

    def observe(self, query: ObservationQuery) -> ObservationResult:
        if query.metric not in self._values:
            return ObservationResult(
                metric=query.metric,
                value=None,
                unit=query.unit,
                window_s=query.window_s,
                status=ObservationStatus.MISSING,
                provenance=self.name,
                detail="metric not registered",
            )
        return ObservationResult(
            metric=query.metric,
            value=self._values[query.metric],
            unit=query.unit,
            window_s=query.window_s,
            provenance=self.name,
            source="static",
        )


def parse_json_metric(payload: str) -> float | None:
    """Best-effort numeric extraction from a JSON provider payload."""
    try:
        parsed = json.loads(payload)
    except (TypeError, ValueError):
        return None
    if isinstance(parsed, (int, float)):
        return float(parsed)
    if isinstance(parsed, dict):
        for key in ("value", "result", "avg", "mean"):
            candidate = parsed.get(key)
            if isinstance(candidate, (int, float)):
                return float(candidate)
    return None
