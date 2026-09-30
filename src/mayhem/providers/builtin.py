from __future__ import annotations

from mayhem.domain.provider import (
    PROVIDER_API_VERSION,
    CapabilityDescriptor,
    EvidenceSchema,
    ImplementationKind,
    ImplementationReference,
    ProviderMetadata,
    ProviderPermission,
    ProviderRegistration,
    ProviderSource,
    TargetLocator,
)
from mayhem.providers.registry import ProviderRegistry

# The built-in runtime providers ship with the distribution, so their declared
# version tracks the release line in pyproject.toml ([tool.hatch.version]
# fallback-version and the built-in provider metadata stay in lockstep).
PROVIDER_VERSION = "1.0.0"


def _metadata(
    provider_id: str,
    name: str,
    capabilities: tuple[CapabilityDescriptor, ...],
    permissions: frozenset[ProviderPermission],
    evidence_name: str,
) -> ProviderMetadata:
    # The four ignores below are one finding, not four: pydantic's mypy plugin
    # always synthesises the __init__ from the field *alias*, and ignores
    # `populate_by_name` (verified against a minimal repro on pydantic 2.13).
    # Runtime validation by field name works, so the field-name kwargs stay.
    return ProviderMetadata(  # type: ignore[call-arg]
        api_version=PROVIDER_API_VERSION,
        provider_id=provider_id,
        name=name,
        version=PROVIDER_VERSION,
        description=f"Built-in {name} runtime provider.",
        permissions=permissions,
        capabilities=capabilities,
        target_locators=(
            TargetLocator(  # type: ignore[call-arg]
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
        implementation=ImplementationReference(
            kind=ImplementationKind.IMPORT,
            target=f"{metadata.provider_id}:Provider",
            factory=True,
        ),
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
    runtime_capability = CapabilityDescriptor(  # type: ignore[call-arg]
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
    discovery_capability = CapabilityDescriptor(  # type: ignore[call-arg]
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
