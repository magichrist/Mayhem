"""Read-only Prometheus connector."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mayhem.domain.observations import (
    PROVENANCE_PROMETHEUS,
    ObservationQuery,
    ObservationResult,
    ObservationStatus,
)
from mayhem.observability.base import (
    DEFAULT_TIMEOUT_S,
    ConnectorError,
    fetch_json,
    redacted,
)


@dataclass(frozen=True, slots=True)
class MetricQuery:
    """A Prometheus instant query."""

    promql: str
    time: str = ""
    step_s: float = 60.0
    labels: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "promql": self.promql,
            "time": self.time,
            "step_s": self.step_s,
            "labels": dict(self.labels),
        }


class PrometheusConnector:
    """Queries a Prometheus HTTP API. Read-only; never mutates remote state."""

    provenance = PROVENANCE_PROMETHEUS

    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_bytes: int = 256 * 1024,
        opener: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout_s
        self._max_bytes = max_bytes
        self._opener = opener
        self._headers = dict(headers or {})

    def query(self, query: MetricQuery) -> float | None:
        import urllib.parse

        params = {"query": query.promql}
        if query.time:
            params["time"] = query.time
        url = f"{self._base}/api/v1/query?{urllib.parse.urlencode(params)}"
        payload = fetch_json(
            url,
            headers=self._headers,
            timeout_s=self._timeout,
            max_bytes=self._max_bytes,
            opener=self._opener,
        )
        return _first_value(payload, query.promql)

    def observe(self, query: ObservationQuery) -> ObservationResult:
        try:
            value = self.query(MetricQuery(promql=query.labels.get("promql", query.metric)))
        except ConnectorError as exc:
            return ObservationResult(
                metric=query.metric,
                value=None,
                unit=query.unit,
                window_s=query.window_s,
                status=ObservationStatus.ERROR,
                provenance=self.provenance,
                source=self._base,
                detail=redacted(str(exc)),
            )
        if value is None:
            return ObservationResult(
                metric=query.metric,
                value=None,
                unit=query.unit,
                window_s=query.window_s,
                status=ObservationStatus.MISSING,
                provenance=self.provenance,
                source=self._base,
                detail="prometheus returned no samples",
            )
        return ObservationResult(
            metric=query.metric,
            value=value,
            unit=query.unit,
            window_s=query.window_s,
            provenance=self.provenance,
            source=self._base,
        )


def _first_value(payload: dict[str, Any], promql: str) -> float | None:
    if payload.get("status") != "success":
        raise ConnectorError(f"prometheus query failed: {redacted(str(payload.get('error')))}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ConnectorError("prometheus response has no data block")
    result = data.get("result")
    if not isinstance(result, list) or not result:
        return None
    first = result[0]
    if not isinstance(first, dict):
        return None
    raw = first.get("value")
    if isinstance(raw, list) and len(raw) == 2:
        try:
            return float(raw[1])
        except (TypeError, ValueError):
            return None
    return None
