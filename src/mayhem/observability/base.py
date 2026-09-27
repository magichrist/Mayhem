"""Shared bounds for every remote connector.

A connector that can hang or stream unbounded data is a production hazard, so
timeout and response-size limits are enforced here rather than per connector.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

DEFAULT_TIMEOUT_S = 5.0
MAX_RESPONSE_BYTES = 256 * 1024


class ConnectorError(RuntimeError):
    """A connector failed. ``degraded`` is the honest state, never silent."""


def redacted(text: str) -> str:
    from mayhem.domain.redaction import redact_text

    cleaned, _ = redact_text(text)
    return cleaned


def fetch_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_bytes: int = MAX_RESPONSE_BYTES,
    opener: Any = None,
) -> dict[str, Any]:
    """GET a JSON document with a timeout and a hard response-size cap."""
    import json

    request = urllib.request.Request(url, headers=headers or {})
    open_fn = opener if opener is not None else urllib.request.urlopen
    try:
        with open_fn(request, timeout=timeout_s) as response:
            body = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise ConnectorError(f"HTTP {exc.code} from connector") from exc
    except Exception as exc:
        raise ConnectorError(f"{type(exc).__name__}: {redacted(str(exc))}") from exc
    if len(body) > max_bytes:
        raise ConnectorError(f"connector response exceeded {max_bytes} bytes")
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except ValueError as exc:
        raise ConnectorError("connector returned non-JSON content") from exc
    if not isinstance(parsed, dict):
        raise ConnectorError("connector returned an unexpected JSON shape")
    return parsed
