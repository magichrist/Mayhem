"""Filesystem serialization for evidence bundles (v0.9.0 expansion task 20).

The bundle *rules* — what a bundle may contain, how artifacts hash-chain, and
whether a bundle verifies — are pure and live in
:mod:`mayhem.domain.evidence_bundle`. Reading and writing those artifacts is IO,
so it lives here in ``infra``: the domain layer has zero IO and no upward
imports, so it must not import ``pathlib`` to persist its own model.

Callers use :func:`write_bundle` / :func:`load_bundle`; the domain model keeps
:func:`mayhem.domain.evidence_bundle.build_bundle` and
:func:`mayhem.domain.evidence_bundle.verify_bundle`.
"""

from __future__ import annotations

import json
from pathlib import Path

from mayhem.domain.evidence_bundle import (
    BUNDLE_SCHEMA_VERSION,
    BundleManifest,
    BundleVerificationError,
    EvidenceBundle,
)


def write_bundle(bundle: EvidenceBundle, directory: str | Path) -> Path:
    """Persist *bundle* into *directory*, creating it if needed."""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    for name, payload in bundle.artifacts.items():
        (target / name).write_text(json.dumps(payload, indent=2, sort_keys=True, default=str))
    (target / "manifest.json").write_text(
        json.dumps(bundle.manifest.to_dict(), indent=2, sort_keys=True)
    )
    return target


def load_bundle(directory: str | Path) -> EvidenceBundle:
    """Read a bundle from disk. Raises only when the bundle is unreadable."""
    base = Path(directory)
    manifest_path = base / "manifest.json"
    if not manifest_path.exists():
        raise BundleVerificationError(f"no manifest.json in {base}")
    try:
        manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise BundleVerificationError(f"manifest.json is not valid JSON: {exc}") from exc
    artifacts: dict[str, object] = {}
    for path in sorted(base.glob("*.json")):
        if path.name == "manifest.json":
            continue
        try:
            artifacts[path.name] = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise BundleVerificationError(f"{path.name} is not valid JSON: {exc}") from exc
    manifest = BundleManifest(
        schema_version=str(manifest_payload.get("schema_version", BUNDLE_SCHEMA_VERSION)),
        artifacts=tuple(
            {
                "name": str(item.get("name", "")),
                "digest": str(item.get("digest", "")),
                "chain": str(item.get("chain", "")),
            }
            for item in manifest_payload.get("artifacts", [])
        ),
        root_digest=str(manifest_payload.get("root_digest", "")),
        previous_root=str(manifest_payload.get("previous_root", "")),
        signature=str(manifest_payload.get("signature", "")),
        signer=str(manifest_payload.get("signer", "")),
        redaction_policy=str(manifest_payload.get("redaction_policy", "")),
        created_at=str(manifest_payload.get("created_at", "")),
    )
    return EvidenceBundle(manifest=manifest, artifacts=artifacts)
