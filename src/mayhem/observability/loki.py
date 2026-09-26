"""Read-only Loki connector."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mayhem.observability.base import (
    DEFAULT_TIMEOUT_S,
    ConnectorError,
    fetch_json,
    redacted,
)


@dataclass(frozen=True, slots=True)
class LogQuery:
    """A Loki range query."""

    selector: str
    start: str = ""
    end: str = ""
    limit: int = 100
    labels: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "selector": self.selector,
            "start": self.start,
            "end": self.end,
            "limit": self.limit,
            "labels": dict(self.labels),
        }


class LokiConnector:
    """Queries a Loki HTTP API. Read-only; log lines are redacted on the way in."""

    provenance = "loki"

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

    def query_lines(self, query: LogQuery) -> tuple[str, ...]:
        import urllib.parse

        params = {"query": query.selector, "limit": str(query.limit)}
        if query.start:
            params["start"] = query.start
        if query.end:
            params["end"] = query.end
        url = f"{self._base}/loki/api/v1/query_range?{urllib.parse.urlencode(params)}"
        payload = fetch_json(
            url,
            headers=self._headers,
            timeout_s=self._timeout,
            max_bytes=self._max_bytes,
            opener=self._opener,
        )
        return _extract_lines(payload)

    def count(self, query: LogQuery) -> int:
        return len(self.query_lines(query))


def _extract_lines(payload: dict[str, Any]) -> tuple[str, ...]:
    if payload.get("status") != "success":
        raise ConnectorError(f"loki query failed: {redacted(str(payload.get('error')))}")
    data = payload.get("data")
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, list):
        raise ConnectorError("loki response has no result list")
    lines: list[str] = []
    for stream in result:
        if not isinstance(stream, dict):
            continue
        entries = stream.get("values")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, list) and len(entry) == 2:
                lines.append(redacted(str(entry[1])))
    return tuple(lines)
