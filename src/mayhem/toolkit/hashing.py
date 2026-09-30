"""Canonical hashing helpers — one definition of 'same input' for the whole system.

Re-exports :mod:`mayhem.domain.hashing`. The implementation moved into the
domain layer because ``mayhem.domain.preflight`` hashes a plan through it and
must not import upward into ``toolkit`` ("Domain layer has zero IO and no
upward imports" contract). The names are re-exported here so callers outside
the domain keep their existing import site.
"""

from __future__ import annotations

from mayhem.domain.hashing import canonical_json, digest, digest_mapping, sha256_hex

__all__ = ["canonical_json", "digest", "digest_mapping", "sha256_hex"]
