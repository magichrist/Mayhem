"""Filesystem readers for target profiles.

The profile *vocabulary* — what a profile may contain, how inheritance
resolves, how a mapping validates — is pure and lives in
:mod:`mayhem.domain.target_profiles`. Reading a profile file off disk is IO, so
it lives here in ``infra``: the domain layer has zero IO, so it must not import
``pathlib`` to load its own documents.

Both readers share the domain's one implementation of the profile-block rule
(:func:`mayhem.domain.target_profiles.profile_block`) and its one validator
(:func:`mayhem.domain.target_profiles.parse_profiles_mapping`); there is no
second implementation of the vocabulary anywhere in the tree.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.target_profiles import (
    TargetProfile,
    parse_profiles_mapping,
    profile_block,
)


def load_profiles_from_file(path: str | Path) -> dict[str, TargetProfile]:
    """Target profiles from a standalone profile document.

    A bare profile-only document (no ``apiVersion``, no ``targets:``/
    ``profiles:`` key) is accepted here: the document itself is the mapping.
    """
    p = Path(path)
    if not p.exists():
        raise SchemaValidationError("target_profile", f"profile file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as exc:
        raise SchemaValidationError("target_profile", f"invalid YAML in {p}: {exc}") from None
    if not isinstance(data, dict):
        raise SchemaValidationError("target_profile", f"{p} must contain a mapping")
    raw_profiles = profile_block(data, bare_document=True)
    if raw_profiles is None:
        return {}
    return parse_profiles_mapping(raw_profiles, source=str(p))


def load_profiles_from_mayhem_yaml(path: str | Path | None = None) -> dict[str, TargetProfile]:
    """Target profiles carried by a ``mayhem.yaml`` document.

    Unlike :func:`mayhem.config.load_config`, no ``apiVersion`` is required: a
    profile-only document is a valid input here, which is what the layered
    configuration and the runtime-context fixtures rely on.
    """
    base = Path(path) if path else Path("mayhem.yaml")
    if not base.exists():
        return {}
    try:
        data = yaml.safe_load(base.read_text()) or {}
    except yaml.YAMLError as exc:
        raise SchemaValidationError("target_profile", f"invalid YAML in {base}: {exc}") from None
    if not isinstance(data, dict):
        return {}
    raw = profile_block(data, bare_document=False)
    if raw is None:
        return {}
    return parse_profiles_mapping(raw, source=str(base))
