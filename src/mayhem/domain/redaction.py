"""Name- and pattern-based redaction. Backup, never policy.

Everything here triggers on how a value is *named* or on the shape of the text
around it: ``password=``, ``Bearer x``, a key called ``token``. That is a real
defence and it is the reason an artifact can be published without reading it —
but it is blind to a value interpolated into a message a caller composed, which is
why plan 29 Phase 4 does not rely on it. The authoritative check for evidence is
:func:`mayhem.infra.secret_resolver.require_envelope_boundary`, which compares
artifact bytes against the values the run actually resolved.

The log sweep below is the middle ground: it applies every rule in this module to
a structured event, and then the engine's byte gate is layered on top of it, so
"the formatter redacted it" is never the whole answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mayhem.domain.policy import _SECRET_KEYS

if TYPE_CHECKING:
    from collections.abc import Mapping

RULE_VERSION = "1"

_URL_CREDENTIALS = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^:/@\s]+):(?P<password>[^@/\s]+)@"
)
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|registry[_-]?token)\s*=\s*[^\s,;]+"
)
# ``Authorization: Bearer <token>`` and a bare ``Bearer <token>`` — the shape
# every connector credential takes on the wire.
_BEARER_TOKEN = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._~+/-]{8,})")
_AUTHORIZATION_HEADER = re.compile(
    r"(?i)(authorization\s*[:=]\s*)((?:bearer|basic|token)\s+)?([^\s,;]+)"
)
# `--password hunter2`, `--token abc`, `-p abc` — space-separated CLI secrets,
# which the assignment pattern above cannot see.
_FLAG_SECRET = re.compile(
    r"(?i)(--?(?:password|passwd|token|secret|api[_-]?key|registry[_-]?token)\s+)(\S+)"
)


@dataclass(frozen=True, slots=True)
class RedactionResult:
    value: Any
    removed_paths: tuple[str, ...] = ()
    rule_versions: tuple[str, ...] = (RULE_VERSION,)


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in _SECRET_KEYS or lowered.endswith(("_token", "_secret", "_password"))


def redact_text(value: str) -> tuple[str, bool]:
    redacted = _URL_CREDENTIALS.sub(r"\g<scheme>***:***@", value)
    redacted = _ASSIGNMENT_SECRET.sub(lambda match: f"{match.group(1)}=***REDACTED***", redacted)
    redacted = _FLAG_SECRET.sub(lambda match: f"{match.group(1)}***REDACTED***", redacted)
    # Bearer first: it consumes the scheme *and* the token, so the header
    # pattern below cannot stop at the space and leave the secret behind.
    redacted = _BEARER_TOKEN.sub(lambda match: f"{match.group(1)}***REDACTED***", redacted)

    def _header(match: re.Match[str]) -> str:
        # Keep the scheme so the reader still sees *what* kind of credential
        # was removed, but never its value.
        scheme = match.group(2) or ""
        return f"{match.group(1)}{scheme}***REDACTED***"

    redacted = _AUTHORIZATION_HEADER.sub(_header, redacted)
    return redacted, redacted != value


def redact(value: Any, *, path: str = "$") -> RedactionResult:
    removed: list[str] = []
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if _is_secret_key(str(key)):
                sanitized[str(key)] = "***REDACTED***"
                removed.append(child_path)
            else:
                result = redact(item, path=child_path)
                sanitized[str(key)] = result.value
                removed.extend(result.removed_paths)
        return RedactionResult(sanitized, tuple(removed))
    if isinstance(value, list):
        sanitized_list: list[Any] = []
        for index, item in enumerate(value):
            result = redact(item, path=f"{path}[{index}]")
            sanitized_list.append(result.value)
            removed.extend(result.removed_paths)
        return RedactionResult(sanitized_list, tuple(removed))
    if isinstance(value, tuple):
        result = redact(list(value), path=path)
        return RedactionResult(tuple(result.value), result.removed_paths)
    if isinstance(value, str):
        redacted, changed = redact_text(value)
        return RedactionResult(redacted, (path,) if changed else ())
    return RedactionResult(value)


def redact_log_event(event: str, fields: Mapping[str, Any] | None = None) -> RedactionResult:
    """Sweep one structured log event: ``event`` plus a flat field mapping.

    Both halves of a log line are covered because they fail differently. The
    event *name* is a single token, so :func:`redact_text` catches the case where
    an event name was itself built from a credential (``f"login:{value}"``), and
    :func:`redact` covers the fields by key name. What neither can do is see a
    value the caller interpolated into a field called ``detail`` — that is what
    :func:`mayhem.infra.secret_resolver.require_clean_log_line` is for, and it
    is why this function returns a value to check rather than a verdict.

    Returns the swept text as ``value`` and the fields it changed as
    ``removed_paths``, so a caller can log the line and count the sweep in the
    same step.
    """
    clean_event, event_changed = redact_text(event)
    removed: list[str] = ["$.event"] if event_changed else []
    if not fields:
        return RedactionResult(clean_event, tuple(removed))
    result = redact(dict(fields))
    removed.extend(result.removed_paths)
    return RedactionResult({"event": clean_event, **dict(result.value)}, tuple(removed))
