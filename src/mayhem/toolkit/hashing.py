"""Canonical hashing helpers — one definition of 'same input' for the whole system."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Deterministic JSON encoding: sorted keys, no whitespace, stable unicode."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest(value: Any) -> str:
    """Hash any JSON-compatible value canonically."""
    return sha256_hex(canonical_json(value))


def digest_mapping(mapping: dict[str, Any]) -> str:
    """Hash a mapping by its canonical form."""
    return digest(dict(mapping))
