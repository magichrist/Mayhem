from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from mayhem.domain.provider import (
    PROVIDER_API_VERSION,
    CapabilityDescriptor,
    ProviderCompatibilityError,
    ProviderMetadata,
    ProviderRegistration,
    ProviderRegistrationError,
    ensure_api_compatible,
)
from mayhem.providers.builtin import create_builtin_registry
from mayhem.providers.registry import ProviderRegistry
from mayhem.topology.providers.docker_adapter import DockerAdapter
from mayhem.topology.providers.kubernetes import KubernetesProvider
from mayhem.topology.providers.podman_adapter import PodmanAdapter


def metadata(provider_id: str = "test.provider") -> ProviderMetadata:
    return ProviderMetadata(
        api_version=PROVIDER_API_VERSION,
        provider_id=provider_id,
        name="Test Provider",
        version="1.2.3",
        description="A declaration-only test provider.",
        permissions=frozenset(),
        capabilities=(
            CapabilityDescriptor(
                id="target.discovery",
                summary="Resolve declared test targets.",
            ),
        ),
        target_locators=(
            {
                "id": "test.target",
                "kind": "test_object",
                "selector_schema": {"name": "string"},
                "required_permissions": [],
            },
        ),
        evidence_schema={"name": "test-evidence", "version": "1.0", "fields": ("target",)},
    )


def registration(provider_id: str = "test.provider") -> ProviderRegistration:
    return ProviderRegistration(
        metadata=metadata(provider_id),
        implementation={"kind": "import", "target": "example:Provider", "factory": False},
    )


def test_capability_mutation_requires_declared_permission() -> None:
    raw = metadata().model_dump(mode="json")
    raw["capabilities"] = [
        {
            "id": "target.mutation",
            "summary": "Mutate a target.",
            "mutates_targets": True,
        }
    ]

    with pytest.raises(ValidationError):
        ProviderMetadata.model_validate(raw)


def test_registration_rejects_unknown_fault_dependency() -> None:
    raw = metadata().model_dump(mode="json")
    raw["fault_declarations"] = [
        {
            "id": "test.fault",
            "capability": "missing.capability",
            "summary": "Invalid declaration.",
        }
    ]

    with pytest.raises(ValidationError):
        ProviderMetadata.model_validate(raw)


def test_stable_registration_json_round_trip() -> None:
    encoded = registration().model_dump_json(by_alias=True)
    decoded = ProviderRegistration.model_validate_json(encoded)

    assert decoded == registration()
    assert json.loads(encoded)["metadata"]["apiVersion"] == PROVIDER_API_VERSION


def test_incompatible_provider_api_is_typed() -> None:
    with pytest.raises(ProviderCompatibilityError, match="provider_api_incompatible"):
        ensure_api_compatible(
            metadata().model_copy(update={"api_version": "mayhem.provider/v2"}),
        )


def test_registry_rejects_duplicate_registration() -> None:
    registry = ProviderRegistry()

    def factory() -> object:
        return object()

    registry.register(registration(), factory)

    with pytest.raises(ProviderRegistrationError, match="already_registered"):
        registry.register(registration(), factory)


def test_registry_keeps_factory_lazy() -> None:
    calls = 0
    registry = ProviderRegistry()

    def factory() -> object:
        nonlocal calls
        calls += 1
        return object()

    registry.register(registration(), factory)
    assert calls == 0
    assert registry.runtime("test.provider") is not None
    assert calls == 1


def test_builtin_registry_wraps_existing_implementations_lazily() -> None:
    registry = create_builtin_registry()
    registrations = {item.metadata.provider_id: item for item in registry.registrations()}

    assert set(registrations) == {"docker", "podman", "kubernetes"}
    assert registrations["docker"].metadata.source.value == "builtin"
    assert isinstance(registry.runtime("docker"), DockerAdapter)
    assert isinstance(registry.runtime("podman"), PodmanAdapter)
    assert isinstance(registry.runtime("kubernetes"), object)
    assert KubernetesProvider.__name__ == "KubernetesProvider"
