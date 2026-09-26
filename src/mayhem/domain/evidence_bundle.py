"""Portable evidence bundles (v0.9.0 expansion task 20).

A bundle is a self-contained, verifiable package: the evidence envelope, the
replay capsule, the capability report, and a manifest that hash-chains every
artifact. Verification is offline — no database, no cluster, no runtime — so a
reviewer can confirm what happened months later on a laptop.

The rules that make a bundle trustworthy:

* artifacts are hashed individually *and* chained, so neither a changed payload
  nor a reordered set of artifacts can pass;
* an unsigned bundle is reported as unsigned, never as verified;
* a bundle carrying secret-shaped extras is refused outright; and
* the redaction marker must be present, so a bundle that skipped redaction fails.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BUNDLE_SCHEMA_VERSION = "1.0"
#: Files a bundle may contain. Anything else is a secret-shaped extra.
ALLOWED_ARTIFACTS: frozenset[str] = frozenset(
    {
        "evidence.json",
        "replay.json",
        "capabilities.json",
        "observations.json",
    }
)

#: Substrings that must never appear in a bundle file name.
FORBIDDEN_NAME_FRAGMENTS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "credential",
    "kubeconfig",
    "env",
)


class BundleVerificationError(ValueError):
    """The bundle could not be read or parsed at all."""


def _digest(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class BundleManifest:
    """The hash chain over a bundle's artifacts."""

    schema_version: str = BUNDLE_SCHEMA_VERSION
    artifacts: tuple[dict[str, str], ...] = ()
    root_digest: str = ""
    previous_root: str = ""
    signature: str = ""
    signer: str = ""
    redaction_policy: str = ""
    created_at: str = ""

    @property
    def signed(self) -> bool:
        return bool(self.signature)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifacts": [dict(artifact) for artifact in self.artifacts],
            "root_digest": self.root_digest,
            "previous_root": self.previous_root,
            "signature": self.signature,
            "signer": self.signer,
            "redaction_policy": self.redaction_policy,
            "created_at": self.created_at,
            "signed": self.signed,
        }


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """Artifacts plus their manifest."""

    manifest: BundleManifest
    artifacts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "artifacts": dict(self.artifacts),
        }

    def write(self, directory: str | Path) -> Path:
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        for name, payload in self.artifacts.items():
            (target / name).write_text(
                json.dumps(payload, indent=2, sort_keys=True, default=str)
            )
        (target / "manifest.json").write_text(
            json.dumps(self.manifest.to_dict(), indent=2, sort_keys=True)
        )
        return target

    @property
    def root_digest(self) -> str:
        return self.manifest.root_digest


@dataclass(frozen=True, slots=True)
class BundleVerification:
    """The verdict, with every reason spelled out."""

    valid: bool
    signed: bool
    artifacts_checked: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    root_digest: str = ""
    schema_version: str = BUNDLE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "signed": self.signed,
            "artifacts_checked": self.artifacts_checked,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "root_digest": self.root_digest,
            "schema_version": self.schema_version,
        }


def build_bundle(
    *,
    evidence: dict[str, Any],
    replay: dict[str, Any] | None = None,
    capabilities: dict[str, Any] | None = None,
    observations: dict[str, Any] | None = None,
    signature: str = "",
    signer: str = "",
    previous_root: str = "",
    created_at: str = "",
) -> EvidenceBundle:
    """Assemble a bundle and hash-chain it. Deterministic for equal input."""
    artifacts: dict[str, Any] = {"evidence.json": evidence}
    if replay is not None:
        artifacts["replay.json"] = replay
    if capabilities is not None:
        artifacts["capabilities.json"] = capabilities
    if observations is not None:
        artifacts["observations.json"] = observations

    chained: list[dict[str, str]] = []
    running = previous_root
    for name in sorted(artifacts):
        artifact_digest = _digest(artifacts[name])
        running = _digest({"previous": running, "name": name, "digest": artifact_digest})
        chained.append({"name": name, "digest": artifact_digest, "chain": running})

    manifest = BundleManifest(
        artifacts=tuple(chained),
        root_digest=running,
        previous_root=previous_root,
        signature=signature,
        signer=signer,
        redaction_policy=str(
            (evidence.get("redaction_metrics") or {}).get("policy_version", "")
        ),
        created_at=created_at,
    )
    return EvidenceBundle(manifest=manifest, artifacts=artifacts)


def verify_bundle(bundle: EvidenceBundle) -> BundleVerification:
    """Verify schema, hashes, chain order, signature metadata, and redaction.

    Offline by construction: the only inputs are the bundle's own bytes.
    """
    errors: list[str] = []
    warnings: list[str] = []
    manifest = bundle.manifest

    if manifest.schema_version != BUNDLE_SCHEMA_VERSION:
        errors.append(
            f"unsupported bundle schema {manifest.schema_version!r} "
            f"(supported: {BUNDLE_SCHEMA_VERSION})"
        )

    declared = {artifact["name"] for artifact in manifest.artifacts}
    present = set(bundle.artifacts)
    for name in sorted(present - declared):
        errors.append(f"artifact {name!r} is present but not in the manifest")
    for name in sorted(declared - present):
        errors.append(f"artifact {name!r} is in the manifest but missing from the bundle")

    for name in sorted(present):
        lowered = name.lower()
        for fragment in FORBIDDEN_NAME_FRAGMENTS:
            if fragment in lowered:
                errors.append(
                    f"artifact {name!r} has a secret-shaped name ({fragment!r}) and is refused"
                )

    ordered_names = [artifact["name"] for artifact in manifest.artifacts]
    if ordered_names != sorted(ordered_names):
        errors.append("manifest artifacts are not in canonical (sorted) order")

    running = manifest.previous_root
    for artifact in manifest.artifacts:
        payload = bundle.artifacts.get(artifact["name"])
        if payload is None:
            continue
        computed = _digest(payload)
        if computed != artifact["digest"]:
            errors.append(
                f"artifact {artifact['name']!r} digest mismatch: "
                f"declared {artifact['digest'][:12]}, computed {computed[:12]}"
            )
            continue
        expected_chain = _digest(
            {"previous": running, "name": artifact["name"], "digest": computed}
        )
        if expected_chain != artifact.get("chain", ""):
            errors.append(
                f"artifact {artifact['name']!r} is out of chain order or was reordered"
            )
            continue
        running = expected_chain

    if running != manifest.root_digest:
        errors.append(
            f"root digest mismatch: declared {manifest.root_digest[:12]}, computed {running[:12]}"
        )

    if not manifest.signed:
        warnings.append("bundle is unsigned: integrity is verified, authorship is not")
    elif not manifest.signer:
        errors.append("bundle carries a signature but names no signer")

    evidence = bundle.artifacts.get("evidence.json")
    if not isinstance(evidence, dict):
        errors.append("bundle has no evidence.json artifact")
    else:
        metrics = evidence.get("redaction_metrics") or {}
        if not metrics:
            errors.append("evidence carries no redaction marker")
        elif not manifest.redaction_policy:
            errors.append("manifest records no redaction policy version")
        elif manifest.redaction_policy != str(metrics.get("policy_version")):
            errors.append(
                f"redaction policy mismatch: manifest {manifest.redaction_policy!r}, "
                f"evidence {metrics.get('policy_version')!r}"
            )

    return BundleVerification(
        valid=not errors,
        signed=manifest.signed,
        artifacts_checked=len(present),
        errors=tuple(errors),
        warnings=tuple(warnings),
        root_digest=manifest.root_digest,
        schema_version=manifest.schema_version,
    )


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
    artifacts: dict[str, Any] = {}
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
