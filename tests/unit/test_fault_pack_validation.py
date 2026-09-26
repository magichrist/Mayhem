"""v0.9.0 expansion task 18: fault pack validation."""

from __future__ import annotations

import json

import pytest

from mayhem.domain.provider import ProviderPermission
from mayhem.providers.loader import PackLoader
from mayhem.providers.pack import (
    FaultPack,
    PackValidationError,
    ProviderManifest,
    load_pack,
    validate_pack,
)
from mayhem.providers.permissions import ProviderPermissionSet, SandboxRefusal

GRANTED = frozenset({ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE})


def _fault(**overrides) -> dict:
    payload = {
        "id": "pack.latency_spike",
        "target": "checkout",
        "risk": "medium",
        "reversible": True,
        "compensation": "restore the original latency profile",
        "observable_effect": "p99 latency rises",
    }
    payload.update(overrides)
    return payload


def _pack(**overrides) -> FaultPack:
    payload = {
        "schema_version": "1.0",
        "manifest": {"provider_id": "acme.packs", "version": "1.2.3"},
        "faults": [_fault()],
        "signature": "sig-abc",
        "signer": "acme",
    }
    payload.update(overrides)
    return FaultPack.model_validate(payload)


# ── happy path ───────────────────────────────────────────────────────────────
def test_a_signed_well_formed_pack_validates() -> None:
    report = validate_pack(_pack(), granted_permissions=GRANTED)
    assert report["loadable"] is True
    assert report["signed"] is True
    assert report["fault_count"] == 1
    assert report["digest"] == _pack().pack_digest()


def test_digest_is_deterministic_and_ignores_the_declared_digest() -> None:
    assert _pack().pack_digest() == _pack().pack_digest()
    stamped = _pack(declared_digest="whatever")
    assert stamped.pack_digest() == _pack().pack_digest()


def test_pack_dict_is_json_serializable() -> None:
    payload = _pack().to_dict()
    assert json.loads(json.dumps(payload))["signed"] is True


# ── schema version ───────────────────────────────────────────────────────────
def test_unsupported_schema_version_is_refused() -> None:
    with pytest.raises(PackValidationError, match="unsupported pack schema"):
        validate_pack(_pack(schema_version="9.9"), granted_permissions=GRANTED)


# ── digest / signature ───────────────────────────────────────────────────────
def test_declared_digest_mismatch_is_refused() -> None:
    with pytest.raises(PackValidationError, match="digest mismatch"):
        validate_pack(_pack(declared_digest="0" * 64), granted_permissions=GRANTED)


def test_expected_digest_mismatch_is_refused() -> None:
    with pytest.raises(PackValidationError, match="does not match the expected"):
        validate_pack(_pack(), expected_digest="f" * 64, granted_permissions=GRANTED)


def test_matching_expected_digest_is_accepted() -> None:
    pack = _pack()
    validate_pack(pack, expected_digest=pack.pack_digest(), granted_permissions=GRANTED)


def test_unsigned_pack_is_local_development_only() -> None:
    unsigned = _pack(signature="", signer="")
    with pytest.raises(PackValidationError, match="local development only"):
        validate_pack(unsigned, granted_permissions=GRANTED)
    report = validate_pack(
        unsigned, granted_permissions=GRANTED, allow_development_only=True
    )
    assert report["signed"] is False
    assert report["development_only"] is True


def test_signed_pack_without_a_signer_is_refused() -> None:
    with pytest.raises(PackValidationError, match="names no signer"):
        validate_pack(_pack(signer=""), granted_permissions=GRANTED)


# ── ids, targets, compensation ───────────────────────────────────────────────
def test_duplicate_fault_ids_are_refused() -> None:
    with pytest.raises(PackValidationError, match="duplicate fault id"):
        validate_pack(_pack(faults=[_fault(), _fault()]), granted_permissions=GRANTED)


def test_unnamespaced_fault_id_is_refused() -> None:
    with pytest.raises(PackValidationError, match="is not namespaced"):
        validate_pack(_pack(faults=[_fault(id="latency")]), granted_permissions=GRANTED)


@pytest.mark.parametrize(
    "target", ["host", "/etc/passwd", "node://n1", "ssh://root@host"]
)
def test_unsafe_targets_are_refused(target: str) -> None:
    with pytest.raises(PackValidationError, match="unsafe target"):
        validate_pack(_pack(faults=[_fault(target=target)]), granted_permissions=GRANTED)


def test_irreversible_fault_without_compensation_is_refused() -> None:
    with pytest.raises(PackValidationError, match="declares no compensation"):
        validate_pack(
            _pack(faults=[_fault(reversible=False, compensation="")]),
            granted_permissions=GRANTED,
        )


def test_reversible_fault_with_compensation_is_accepted() -> None:
    validate_pack(_pack(faults=[_fault(compensation="undo op")]), granted_permissions=GRANTED)


# ── permissions / compatibility ──────────────────────────────────────────────
def test_pack_requesting_ungranted_permissions_is_refused() -> None:
    pack = _pack(
        manifest={"provider_id": "acme.packs", "permissions": ["subprocess", "network"]}
    )
    with pytest.raises(PackValidationError, match="not granted"):
        validate_pack(pack, granted_permissions=GRANTED)


def test_fault_level_permissions_are_also_checked() -> None:
    pack = _pack(faults=[_fault(permissions=["subprocess"])])
    with pytest.raises(PackValidationError, match="subprocess"):
        validate_pack(pack, granted_permissions=GRANTED)


def test_manifest_api_version_must_match_the_pack_schema() -> None:
    pack = _pack(manifest={"provider_id": "acme.packs", "api_version": "0.1"})
    with pytest.raises(PackValidationError, match="manifest targets api"):
        validate_pack(pack, granted_permissions=GRANTED)


def test_every_problem_is_reported_at_once() -> None:
    pack = _pack(
        schema_version="9.9",
        faults=[_fault(target="host", compensation=""), _fault(id="pack.latency_spike")],
    )
    with pytest.raises(PackValidationError) as excinfo:
        validate_pack(pack, granted_permissions=GRANTED)
    message = str(excinfo.value)
    assert "unsupported pack schema" in message
    assert "unsafe target" in message
    assert "duplicate fault id" in message


# ── parsing ──────────────────────────────────────────────────────────────────
def test_load_pack_rejects_a_malformed_document() -> None:
    with pytest.raises(PackValidationError, match="invalid pack document"):
        load_pack({"manifest": {"nope": 1}})


def test_load_pack_rejects_an_unknown_field() -> None:
    with pytest.raises(PackValidationError, match="invalid pack document"):
        load_pack({"schema_version": "1.0", "manifest": {"provider_id": "p"}, "surprise": 1})


# ── opt-in loading ───────────────────────────────────────────────────────────
def test_loader_refuses_a_mutating_pack_without_an_explicit_grant() -> None:
    loader = PackLoader()
    with pytest.raises(SandboxRefusal, match="grant target:mutate"):
        loader.load(_pack().model_dump(mode="json"))


def test_loader_loads_a_mutating_pack_once_the_grant_exists() -> None:
    loader = PackLoader(grants={"acme.packs": ProviderPermissionSet.from_names("acme.packs", ("target:mutate",))})
    pack, report = loader.load(_pack().model_dump(mode="json"))
    assert pack.manifest.provider_id == "acme.packs"
    assert report["loadable"] is True


def test_loader_refuses_an_unsigned_pack_unless_development_only_is_allowed() -> None:
    grants = {"acme.packs": ProviderPermissionSet.from_names("acme.packs", ("target:mutate",))}
    unsigned = _pack(signature="", signer="").model_dump(mode="json")
    with pytest.raises(PackValidationError, match="local development only"):
        PackLoader(grants=grants).load(unsigned)
    pack, report = PackLoader(grants=grants, allow_development_only=True).load(unsigned)
    assert report["development_only"] is True


def test_loader_inspect_never_raises() -> None:
    loader = PackLoader()
    assert loader.inspect({"garbage": True})["loadable"] is False
    refused = loader.inspect(_pack().model_dump(mode="json"))
    assert refused["loadable"] is False
    assert "target:mutate" in refused["reason"]


def test_loader_grant_can_be_added_after_construction() -> None:
    loader = PackLoader()
    loader.grant("acme.packs", ProviderPermissionSet.from_names("acme.packs", ("target:mutate",)))
    _pack_obj, report = loader.load(_pack().model_dump(mode="json"))
    assert report["loadable"] is True


def test_loader_default_permissions_are_read_only() -> None:
    permissions = PackLoader().permissions_for("unknown.provider")
    assert permissions.mutating is False
    assert permissions.to_dict()["granted"] == ["target:read"]


def test_provider_manifest_serialises_permissions_sorted() -> None:
    manifest = ProviderManifest(
        provider_id="p", permissions=(ProviderPermission.SUBPROCESS, ProviderPermission.NETWORK)
    )
    assert manifest.to_dict()["permissions"] == ["network", "subprocess"]
