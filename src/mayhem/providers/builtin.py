from __future__ import annotations

from mayhem.domain.provider import (
    PROVIDER_API_VERSION,
    CapabilityDescriptor,
    EvidenceSchema,
    ProviderMetadata,
    ProviderPermission,
    ProviderRegistration,
    ProviderSource,
    TargetLocator,
)
from mayhem.providers.registry import ProviderRegistry


def _metadata(
    provider_id: str,
    name: str,
    capabilities: tuple[CapabilityDescriptor, ...],
    permissions: frozenset[ProviderPermission],
    evidence_name: str,
) -> ProviderMetadata:
    return ProviderMetadata(
        api_version=PROVIDER_API_VERSION,
        provider_id=provider_id,
        name=name,
        version="0.5.0",
        description=f"Built-in {name} runtime provider.",
        permissions=permissions,
        capabilities=capabilities,
        target_locators=(
            TargetLocator(
                id=f"{provider_id}.target",
                kind="runtime_target",
                required_permissions=frozenset({ProviderPermission.TARGET_READ}),
            ),
        ),
        evidence_schema=EvidenceSchema(name=evidence_name, version="1.0"),
        source=ProviderSource.BUILTIN,
    )


def _registration(metadata: ProviderMetadata) -> ProviderRegistration:
    return ProviderRegistration(
        metadata=metadata,
        implementation={
            "kind": "import",
            "target": f"{metadata.provider_id}:Provider",
            "factory": True,
        },
    )


def _docker() -> object:
    from mayhem.topology.providers.docker_adapter import DockerAdapter

    return DockerAdapter()


def _podman() -> object:
    from mayhem.topology.providers.podman_adapter import PodmanAdapter

    return PodmanAdapter()


def _kubernetes() -> object:
    from mayhem.domain.k8s_adapter import KubernetesAdapter

    return KubernetesAdapter()


def create_builtin_registry() -> ProviderRegistry:
    permissions = frozenset(ProviderPermission)
    registry = ProviderRegistry(allowed_permissions=permissions)
    runtime_capability = CapabilityDescriptor(
        id="runtime.control",
        summary="Discover and control runtime-managed targets.",
        required_permissions={
            ProviderPermission.FILESYSTEM_READ,
            ProviderPermission.SUBPROCESS,
            ProviderPermission.TARGET_MUTATE,
            ProviderPermission.TARGET_READ,
        },
        mutates_targets=True,
        compensable=True,
    )
    discovery_capability = CapabilityDescriptor(
        id="runtime.discovery",
        summary="Discover runtime-managed targets.",
        required_permissions=frozenset({ProviderPermission.TARGET_READ}),
    )
    definitions = (
        (
            _metadata(
                "docker",
                "Docker",
                (discovery_capability, runtime_capability),
                permissions,
                "docker-evidence",
            ),
            _docker,
        ),
        (
            _metadata(
                "podman",
                "Podman",
                (discovery_capability, runtime_capability),
                permissions,
                "podman-evidence",
            ),
            _podman,
        ),
        (
            _metadata(
                "kubernetes",
                "Kubernetes",
                (discovery_capability,),
                permissions,
                "kubernetes-evidence",
            ),
            _kubernetes,
        ),
    )
    for metadata, factory in definitions:
        registry.register(_registration(metadata), factory)
    return registry
