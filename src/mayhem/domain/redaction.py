from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from mayhem.domain.policy import _SECRET_KEYS

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
