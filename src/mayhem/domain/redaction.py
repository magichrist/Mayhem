from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from mayhem.domain.policy import _SECRET_KEYS


RULE_VERSION = "1"

_URL_CREDENTIALS = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^:/@\s]+):(?P<password>[^@/\s]+)@")
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|registry[_-]?token)\s*=\s*[^\s,;]+"
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
