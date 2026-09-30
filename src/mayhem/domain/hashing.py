"""Canonical hashing — one definition of 'same input' for the whole system.

Lives in ``domain`` rather than ``toolkit`` because plan identity is a domain
concept: :mod:`mayhem.domain.preflight` hashes a plan through
:func:`canonical_json` and must not import upward into ``toolkit`` to reach it
("Domain layer has zero IO and no upward imports" contract).

These are pure functions over in-memory values — no IO — so they belong in the
bottom layer. :mod:`mayhem.toolkit.hashing` re-exports them unchanged so
callers outside the domain keep their existing import site.
"""

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
