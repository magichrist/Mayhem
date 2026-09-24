from __future__ import annotations

import re
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.errors import DomainError

if TYPE_CHECKING:
    from datetime import datetime

PROVIDER_API_VERSION = "mayhem.provider/v1"
PROVIDER_CATALOG_SCHEMA_VERSION = "mayhem.provider-catalog/v1"
PROVIDER_EVIDENCE_SCHEMA_VERSION = "mayhem.provider-evidence/v1"
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")


class ProviderError(DomainError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"[{code}] {message}")


class ProviderCompatibilityError(ProviderError):
    pass


class ProviderRegistrationError(ProviderError):
    pass


class ProviderNotFoundError(ProviderError):
    pass


class ProviderPermissionError(ProviderError):
    def __init__(self, provider_id: str, permissions: frozenset[ProviderPermission]) -> None:
        self.provider_id = provider_id
        self.permissions = permissions
        names = ", ".join(sorted(permission.value for permission in permissions))
        super().__init__(
            "provider_permission_denied",
            f"provider {provider_id!r} requests permissions not allowed by policy: {names}",
        )


class ProviderSource(StrEnum):
    BUILTIN = "builtin"
    CATALOG = "catalog"
    ENTRY_POINT = "entry_point"


class ProviderPermission(StrEnum):
    NETWORK = "network"
    FILESYSTEM_READ = "filesystem:read"
    FILESYSTEM_WRITE = "filesystem:write"
    SUBPROCESS = "subprocess"
    TARGET_READ = "target:read"
    TARGET_MUTATE = "target:mutate"


class ProviderMutation(StrEnum):
    READ_ONLY = "read_only"
    MUTATING = "mutating"


class CompensationStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    OBSERVED = "observed"
    FAILED = "failed"
    NOT_COMPENSABLE = "not_compensable"


class ImplementationKind(StrEnum):
    IMPORT = "import"
    ENTRY_POINT = "entry_point"


class FrozenDeclaration(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class CapabilityDescriptor(FrozenDeclaration):
    id: str
    summary: str = Field(min_length=1, max_length=500)
    required_permissions: frozenset[ProviderPermission] = Field(
        default_factory=frozenset,
        alias="requiredPermissions",
    )
    mutates_targets: bool = False
    compensable: bool = False

    @model_validator(mode="after")
    def validate_mutation_contract(self) -> CapabilityDescriptor:
        if not _IDENTIFIER.fullmatch(self.id):
            raise ValueError("capability id must be a lowercase dotted identifier")
        if (
            self.mutates_targets
            and ProviderPermission.TARGET_MUTATE not in self.required_permissions
        ):
            raise ValueError("mutating capabilities must require target:mutate")
        if self.compensable and not self.mutates_targets:
            raise ValueError("compensable capabilities must mutate targets")
        return self


class FaultDeclaration(FrozenDeclaration):
    id: str
    capability: str
    summary: str = Field(min_length=1, max_length=500)
    target_locator_ids: tuple[str, ...] = ()
    parameters: dict[str, str] = Field(default_factory=dict)
    mutation: ProviderMutation = ProviderMutation.READ_ONLY
    reversible: bool = True
    required_permissions: frozenset[ProviderPermission] = Field(
        default_factory=frozenset,
        alias="requiredPermissions",
    )

    @model_validator(mode="after")
    def validate_fault_contract(self) -> FaultDeclaration:
        if not _IDENTIFIER.fullmatch(self.id):
            raise ValueError("fault id must be a lowercase dotted identifier")
        if self.mutation is ProviderMutation.MUTATING:
            if ProviderPermission.TARGET_MUTATE not in self.required_permissions:
                raise ValueError("mutating faults must require target:mutate")
            if not self.reversible:
                raise ValueError("mutating provider faults must declare a compensation path")
        elif self.reversible and self.required_permissions:
            raise ValueError("read-only faults cannot require action permissions")
        return self


class TargetLocator(FrozenDeclaration):
    id: str
    kind: str
    selector_schema: dict[str, Any] = Field(
        default_factory=dict,
        alias="selectorSchema",
    )
    required_permissions: frozenset[ProviderPermission] = Field(
        default_factory=lambda: frozenset({ProviderPermission.TARGET_READ}),
        alias="requiredPermissions",
    )

    @model_validator(mode="after")
    def validate_locator(self) -> TargetLocator:
        if not _IDENTIFIER.fullmatch(self.id):
            raise ValueError("locator id must be a lowercase dotted identifier")
        if not self.kind or not self.kind.strip():
            raise ValueError("locator kind is required")
        return self


class EvidenceSchema(FrozenDeclaration):
    name: str
    version: str
    fields: tuple[str, ...] = ("recorded_at", "operation", "target", "outcome")

    @model_validator(mode="after")
    def validate_schema(self) -> EvidenceSchema:
        if not self.name or not self.fields:
            raise ValueError("evidence schema requires a name and fields")
        if not re.fullmatch(r"^\d+\.\d+(?:\.\d+)?$", self.version):
            raise ValueError("evidence schema version must be major.minor semantic versioning")
        return self


class ProviderMetadata(FrozenDeclaration):
    api_version: str = Field(default=PROVIDER_API_VERSION, alias="apiVersion")
    provider_id: str = Field(alias="providerId")
    name: str = Field(min_length=1, max_length=100)
    version: str
    description: str = Field(min_length=1, max_length=1000)
    permissions: frozenset[ProviderPermission] = Field(default_factory=frozenset)
    capabilities: tuple[CapabilityDescriptor, ...] = ()
    fault_declarations: tuple[FaultDeclaration, ...] = Field(
        default_factory=tuple,
        alias="faultDeclarations",
    )
    target_locators: tuple[TargetLocator, ...] = Field(
        default_factory=tuple,
        alias="targetLocators",
    )
    evidence_schema: EvidenceSchema = Field(alias="evidenceSchema")
    source: ProviderSource = ProviderSource.CATALOG
    homepage: str | None = None

    @model_validator(mode="after")
    def validate_declaration_graph(self) -> ProviderMetadata:
        if not _IDENTIFIER.fullmatch(self.provider_id):
            raise ValueError("provider id must be a lowercase dotted identifier")
        if not _SEMVER.fullmatch(self.version):
            raise ValueError("provider version must be semantic versioning")
        capability_ids = {capability.id for capability in self.capabilities}
        locator_ids = {locator.id for locator in self.target_locators}
        if len(capability_ids) != len(self.capabilities):
            raise ValueError("capability ids must be unique")
        if len(locator_ids) != len(self.target_locators):
            raise ValueError("target locator ids must be unique")
        for capability in self.capabilities:
            if not capability.required_permissions <= self.permissions:
                raise ValueError("capability permissions must be declared by the provider")
        for locator in self.target_locators:
            if not locator.required_permissions <= self.permissions:
                raise ValueError("locator permissions must be declared by the provider")
        for fault in self.fault_declarations:
            if fault.capability not in capability_ids:
                raise ValueError("fault capability must reference a declared capability")
            if not set(fault.target_locator_ids) <= locator_ids:
                raise ValueError("fault target locators must be declared by the provider")
            if not fault.required_permissions <= self.permissions:
                raise ValueError("fault permissions must be declared by the provider")
        return self


class ImplementationReference(FrozenDeclaration):
    kind: ImplementationKind
    target: str = Field(min_length=1)
    factory: bool = False

    @model_validator(mode="after")
    def validate_reference(self) -> ImplementationReference:
        if self.kind is ImplementationKind.IMPORT and ":" not in self.target:
            raise ValueError("import implementation target must be module:attribute")
        if self.kind is ImplementationKind.ENTRY_POINT and not _IDENTIFIER.fullmatch(self.target):
            raise ValueError("entry point target must be a provider identifier")
        return self


class ProviderRegistration(FrozenDeclaration):
    metadata: ProviderMetadata
    implementation: ImplementationReference


class ProviderCatalog(FrozenDeclaration):
    api_version: str = Field(
        default=PROVIDER_CATALOG_SCHEMA_VERSION,
        alias="apiVersion",
    )
    providers: tuple[ProviderRegistration, ...]

    @model_validator(mode="after")
    def validate_catalog(self) -> ProviderCatalog:
        if self.api_version != PROVIDER_CATALOG_SCHEMA_VERSION:
            raise ValueError(f"catalog apiVersion must be {PROVIDER_CATALOG_SCHEMA_VERSION}")
        provider_ids = [registration.metadata.provider_id for registration in self.providers]
        if len(provider_ids) != len(set(provider_ids)):
            raise ValueError("provider ids must be unique within a catalog")
        return self


class ProviderEvidenceRecord(FrozenDeclaration):
    api_version: str = Field(
        default=PROVIDER_EVIDENCE_SCHEMA_VERSION,
        alias="apiVersion",
    )
    provider_id: str
    operation_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    outcome: str = Field(min_length=1)
    recorded_at: AwareDatetime
    compensation_status: CompensationStatus
    compensation_token: str | None = None
    source: str = Field(min_length=1)
    details: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_evidence(self) -> ProviderEvidenceRecord:
        if self.api_version != PROVIDER_EVIDENCE_SCHEMA_VERSION:
            raise ValueError(f"evidence apiVersion must be {PROVIDER_EVIDENCE_SCHEMA_VERSION}")
        if self.compensation_status is CompensationStatus.OBSERVED and not self.compensation_token:
            raise ValueError("observed compensation requires a compensation token")
        return self


def ensure_api_compatible(
    metadata: ProviderMetadata,
    *,
    supported_api_version: str = PROVIDER_API_VERSION,
) -> None:
    expected_major = supported_api_version.rsplit("/", 1)[-1]
    actual_major = metadata.api_version.rsplit("/", 1)[-1]
    if actual_major != expected_major:
        raise ProviderCompatibilityError(
            "provider_api_incompatible",
            f"provider {metadata.provider_id!r} declares {metadata.api_version!r}; "
            f"Mayhem supports {supported_api_version!r}",
        )


def ensure_permissions(
    metadata: ProviderMetadata,
    allowed: frozenset[ProviderPermission],
) -> None:
    denied = metadata.permissions - allowed
    if denied:
        raise ProviderPermissionError(metadata.provider_id, denied)


def evidence_record(
    *,
    provider_id: str,
    operation_id: str,
    target_id: str,
    outcome: str,
    recorded_at: datetime,
    source: str,
    **values: Any,
) -> ProviderEvidenceRecord:
    return ProviderEvidenceRecord(
        provider_id=provider_id,
        operation_id=operation_id,
        target_id=target_id,
        outcome=outcome,
        recorded_at=recorded_at,
        source=source,
        **values,
    )
