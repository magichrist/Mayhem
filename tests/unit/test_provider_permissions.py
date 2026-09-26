"""v0.9.0 expansion task 18: provider sandbox permissions."""

from __future__ import annotations

import pytest

from mayhem.domain.provider import ProviderPermission
from mayhem.providers.permissions import (
    DANGEROUS_PERMISSIONS,
    ProviderPermissionSet,
    SandboxRefusal,
    validate_pack_permissions,
)


def test_default_posture_allows_no_mutation_subprocess_network_or_env() -> None:
    permissions = ProviderPermissionSet.default("evil.provider")
    assert permissions.mutating is False
    for denied in (
        ProviderPermission.TARGET_MUTATE,
        ProviderPermission.SUBPROCESS,
        ProviderPermission.NETWORK,
        ProviderPermission.FILESYSTEM_WRITE,
    ):
        assert permissions.allows(denied) is False
        with pytest.raises(SandboxRefusal) as excinfo:
            permissions.require(denied)
        assert excinfo.value.permission == denied.value
        assert "evil.provider" in str(excinfo.value)


def test_default_posture_still_allows_read_only_target_access() -> None:
    permissions = ProviderPermissionSet.default("reader.provider")
    permissions.require(ProviderPermission.TARGET_READ)


def test_dangerous_set_covers_every_world_affecting_permission() -> None:
    assert ProviderPermission.TARGET_MUTATE in DANGEROUS_PERMISSIONS
    assert ProviderPermission.SUBPROCESS in DANGEROUS_PERMISSIONS
    assert ProviderPermission.NETWORK in DANGEROUS_PERMISSIONS
    assert ProviderPermission.FILESYSTEM_WRITE in DANGEROUS_PERMISSIONS
    assert ProviderPermission.TARGET_READ not in DANGEROUS_PERMISSIONS


def test_explicit_grant_unlocks_exactly_that_permission() -> None:
    permissions = ProviderPermissionSet.from_names("p", ("network",))
    permissions.require(ProviderPermission.NETWORK)
    with pytest.raises(SandboxRefusal, match="subprocess"):
        permissions.require(ProviderPermission.SUBPROCESS)


def test_grants_must_name_real_permissions() -> None:
    with pytest.raises(ValueError):
        ProviderPermissionSet.from_names("p", ("teleport",))


def test_mutating_flag_reflects_the_grant() -> None:
    assert ProviderPermissionSet.from_names("p", ("target:mutate",)).mutating is True
    assert ProviderPermissionSet.from_names("p", ("target:read",)).mutating is False


def test_check_lists_ungranted_permissions_sorted() -> None:
    permissions = ProviderPermissionSet.from_names("p", ("target:read",))
    missing = permissions.check(
        frozenset({ProviderPermission.SUBPROCESS, ProviderPermission.NETWORK})
    )
    assert missing == ("network", "subprocess")


def test_check_is_empty_when_everything_is_granted() -> None:
    permissions = ProviderPermissionSet.from_names("p", ("network", "subprocess"))
    assert permissions.check(frozenset({ProviderPermission.NETWORK})) == ()


def test_filesystem_write_is_denied_by_default() -> None:
    with pytest.raises(SandboxRefusal, match="filesystem:write"):
        ProviderPermissionSet.default("p").require(ProviderPermission.FILESYSTEM_WRITE)


def test_filesystem_read_can_be_granted_explicitly() -> None:
    ProviderPermissionSet.from_names("p", ("filesystem:read",)).require(
        ProviderPermission.FILESYSTEM_READ
    )


def test_environment_capture_is_not_a_granted_permission() -> None:
    """There is no environment-read grant in the vocabulary at all."""
    names = {permission.value for permission in ProviderPermission}
    assert not any("env" in name for name in names)
    with pytest.raises(ValueError):
        ProviderPermissionSet.from_names("p", ("environment:read",))


def test_validate_pack_permissions_refuses_an_overreaching_pack() -> None:
    permissions = ProviderPermissionSet.default("p")
    with pytest.raises(SandboxRefusal) as excinfo:
        validate_pack_permissions(
            "p",
            permissions,
            frozenset({ProviderPermission.TARGET_MUTATE, ProviderPermission.NETWORK}),
        )
    assert "target:mutate" in str(excinfo.value)
    assert excinfo.value.to_dict()["provider_id"] == "p"


def test_validate_pack_permissions_accepts_a_pack_inside_the_grant() -> None:
    permissions = ProviderPermissionSet.from_names("p", ("target:read",))
    validate_pack_permissions("p", permissions, frozenset({ProviderPermission.TARGET_READ}))


def test_refusal_message_is_deterministic() -> None:
    permissions = ProviderPermissionSet.default("p")
    messages = set()
    for _ in range(5):
        try:
            permissions.require(ProviderPermission.SUBPROCESS)
        except SandboxRefusal as exc:
            messages.add(str(exc))
    assert len(messages) == 1


def test_permission_set_serialises_grants_for_evidence() -> None:
    payload = ProviderPermissionSet.default("p").to_dict()
    assert payload["granted"] == ["target:read"]
    assert payload["mutating"] is False
    assert payload["grants"][0]["permission"] == "target:read"
