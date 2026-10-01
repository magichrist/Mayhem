from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    model_validator,
)

from mayhem.domain.errors import DomainError
from mayhem.domain.risks import RiskLevel

if TYPE_CHECKING:
    from datetime import datetime

PROVIDER_API_VERSION = "mayhem.provider/v1"
PROVIDER_CATALOG_SCHEMA_VERSION = "mayhem.provider-catalog/v1"
PROVIDER_EVIDENCE_SCHEMA_VERSION = "mayhem.provider-evidence/v1"

#: The declaration document is its own versioned artifact. The three constants
#: above are *facets* of one declaration (identity, catalog envelope, evidence
#: record); this one versions the envelope of the whole thing, so an SDK can
#: stamp the document it emits without inventing a second meaning for
#: ``apiVersion``. It is the string an SDK writes and a loader recognises; it
#: says nothing about whether the core is willing to run what it describes.
PROVIDER_DECLARATION_SCHEMA_VERSION = "mayhem.provider-declaration/v1"

#: The api-version major this build implements. A declaration built against
#: ``mayhem.provider/v1`` keeps loading across core *minor* releases; crossing a
#: major is the declared signal that the wire shape itself moved, and is a
#: refusal rather than a warning.
PROVIDER_API_MAJOR: str = PROVIDER_API_VERSION.rsplit("/", 1)[-1]
SUPPORTED_PROVIDER_API_MAJORS: frozenset[str] = frozenset({PROVIDER_API_MAJOR})

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")
#: A *release* version, for compatibility bounds. Bounds are stated as releases
#: on purpose: a bound a prerelease may sit on either side of is not a bound
#: anyone can reason about.
_RELEASE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
#: A release with an optional pre-release suffix, for the *running* version. The
#: suffix separator is ``-`` (semver, ``1.2.0-rc1``) or ``.`` (PEP 440, the
#: ``1.0.0.dev0`` this repo's fallback version uses); both are read the same way,
#: which is all this needs since the suffix only decides *ordering* relative to
#: the release it precedes.
_VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-.]([0-9A-Za-z.+-]+))?$")
_PARAMETER_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_API_MAJOR = re.compile(r"^v\d+$")


def _version_key(value: str) -> tuple[int, int, int, bool]:
    """Sortable ``(major, minor, patch, is_prerelease)`` for a version string.

    A prerelease sorts *below* the release it precedes, which is the semantic
    versioning rule: ``1.1.0.dev0`` is inside a ``>=1.0.0`` window and outside a
    ``>=1.1.0`` one. Two prereleases of the same release are not ordered against
    each other — this build has no reason to, and guessing would be a comparison
    it cannot justify.
    """
    match = _VERSION.fullmatch(value)
    if match is None:
        raise ValueError(f"{value!r} is not a major.minor.patch version")
    major, minor, patch, prerelease = match.groups()
    return (int(major), int(minor), int(patch), prerelease is not None)


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


#: The declaration-level default posture, restated here because the *schema* is
#: where a permission is first asked for. A declaration that asks for nothing is
#: the only one that loads under the default; anything else needs an explicit
#: grant (see :func:`ensure_declared_permissions`).
#:
#: This is deliberately the same empty set as
#: ``mayhem.providers.permissions.DEFAULT_PERMISSION_SET`` and deliberately not
#: an import of it: the domain may not depend on the loader layer, and a second
#: literal that agrees with the first is safer than a dependency that cannot be
#: checked. If one ever changes, the other must change with it.
DEFAULT_DECLARED_PERMISSIONS: frozenset[ProviderPermission] = frozenset()


def _sorted_permissions(value: frozenset[ProviderPermission]) -> list[str]:
    """Serialise a permission set in a stable, sorted order.

    A ``frozenset`` has no iteration order, and CPython's is derived from the
    string hashes, which are salted per process. Left alone, pydantic dumps the
    members in whatever order this particular interpreter happens to produce, so
    the *same* declaration serialises to *different bytes* in two runs.

    That is not cosmetic here. This module's own docstring and
    ``test_canonical_json_is_byte_stable`` both promise that an SDK in Rust,
    Python or Go can hash the canonical form and get one answer, and the loader
    writes these dumps straight back out to a catalog file. An unsorted
    permission list makes the canonical form a function of ``PYTHONHASHSEED``:
    two machines hashing the same artifact disagree, and a re-serialised
    catalog diffs against itself.

    Sorting matches what ``mayhem.providers.pack`` already does for its own
    permission tuples, so both pack documents and provider declarations now
    canonicalise the same way.
    """
    return sorted(permission.value for permission in value)


#: A permission set that serialises deterministically. The *model* stays a
#: ``frozenset`` — comparison and ``<=`` against a grant are set semantics, and
#: the declared default posture is set-shaped — while only the wire form is
#: ordered.
PermissionSet = Annotated[
    frozenset[ProviderPermission],
    PlainSerializer(_sorted_permissions, return_type=list[str], when_used="json"),
]


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


class ParameterKind(StrEnum):
    """The value grammar a declared fault parameter is written in.

    Deliberately a closed, small vocabulary. A parameter type a core cannot
    interpret is a parameter the core would have to guess at, and guessing at
    fault parameters is how a declaration stops meaning what its author wrote.
    """

    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ENUM = "enum"
    DURATION_S = "duration_s"
    JSON = "json"


class FrozenDeclaration(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class CapabilityDescriptor(FrozenDeclaration):
    id: str
    summary: str = Field(min_length=1, max_length=500)
    required_permissions: PermissionSet = Field(
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


class ParameterDeclaration(FrozenDeclaration):
    """One declared parameter of a fault: its name, its grammar, its defaults.

    The grammar is data, not a callable — an SDK in Rust, Python or Go all
    serialise this same shape, and the core can check a call against it without
    ever having seen the provider's language.
    """

    name: str
    kind: ParameterKind = ParameterKind.STRING
    required: bool = True
    default: str | None = None
    summary: str = Field(default="", max_length=500)
    minimum: float | None = None
    maximum: float | None = None
    choices: tuple[str, ...] = ()
    pattern: str | None = None

    @model_validator(mode="after")
    def validate_parameter(self) -> ParameterDeclaration:
        if not _PARAMETER_NAME.fullmatch(self.name):
            raise ValueError("parameter name must be a lowercase identifier")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("parameter minimum cannot exceed its maximum")
        if self.choices and self.kind is not ParameterKind.ENUM:
            raise ValueError("only enum parameters may declare choices")
        if self.choices and len(set(self.choices)) != len(self.choices):
            raise ValueError("parameter choices must be unique")
        if self.pattern is not None:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"parameter pattern does not compile: {exc}") from exc
        if self.minimum is not None and self.kind in {
            ParameterKind.STRING,
            ParameterKind.BOOLEAN,
            ParameterKind.ENUM,
            ParameterKind.JSON,
        }:
            raise ValueError(f"parameter kind {self.kind.value!r} takes no numeric bounds")
        if not self.required and self.default is None:
            raise ValueError("an optional parameter must declare a default")
        return self


class FaultDeclaration(FrozenDeclaration):
    id: str
    capability: str
    summary: str = Field(min_length=1, max_length=500)
    target_locator_ids: tuple[str, ...] = ()
    parameters: dict[str, str] = Field(default_factory=dict)
    parameter_grammar: tuple[ParameterDeclaration, ...] = Field(
        default_factory=tuple,
        alias="parameterGrammar",
    )
    risk: RiskLevel = RiskLevel.MEDIUM
    mutation: ProviderMutation = ProviderMutation.READ_ONLY
    reversible: bool = True
    required_permissions: PermissionSet = Field(
        default_factory=frozenset,
        alias="requiredPermissions",
    )

    @model_validator(mode="after")
    def validate_fault_contract(self) -> FaultDeclaration:
        if not _IDENTIFIER.fullmatch(self.id):
            raise ValueError("fault id must be a lowercase dotted identifier")
        names = [parameter.name for parameter in self.parameter_grammar]
        if len(set(names)) != len(names):
            raise ValueError("parameter grammar names must be unique within a fault")
        if names:
            # Checked only when a grammar was actually declared. A v1
            # declaration may carry flat ``parameters`` with no grammar at all,
            # and refusing one would be a cross-minor break rather than a
            # stricter contract.
            undeclared = sorted(set(self.parameters) - set(names))
            if undeclared:
                raise ValueError(
                    "fault parameters must be described by the parameter grammar: "
                    + ", ".join(undeclared)
                )
        if self.mutation is ProviderMutation.MUTATING:
            if ProviderPermission.TARGET_MUTATE not in self.required_permissions:
                raise ValueError("mutating faults must require target:mutate")
            if not self.reversible:
                raise ValueError("mutating provider faults must declare a compensation path")
        elif self.reversible and self.required_permissions:
            raise ValueError("read-only faults cannot require action permissions")
        return self

    def parameter(self, name: str) -> ParameterDeclaration | None:
        """The grammar entry for *name*, or ``None`` when it is not declared."""
        return next(
            (entry for entry in self.parameter_grammar if entry.name == name),
            None,
        )


class TargetLocator(FrozenDeclaration):
    id: str
    kind: str
    selector_schema: dict[str, Any] = Field(
        default_factory=dict,
        alias="selectorSchema",
    )
    required_permissions: PermissionSet = Field(
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


class EvidenceMapping(FrozenDeclaration):
    """Which declared fault writes which evidence schema.

    The mapping is a reference, not a copy: it names a fault the provider
    declared and an evidence schema the provider published, and
    :meth:`ProviderMetadata.evidence_for` is the only way to resolve it. A copy
    would be a second place for the schema to drift.
    """

    fault_id: str
    schema_name: str
    schema_version: str
    fields: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_mapping(self) -> EvidenceMapping:
        if not _IDENTIFIER.fullmatch(self.fault_id):
            raise ValueError("evidence mapping fault id must be a lowercase dotted identifier")
        if not self.schema_name:
            raise ValueError("evidence mapping requires a schema name")
        if not re.fullmatch(r"^\d+\.\d+(?:\.\d+)?$", self.schema_version):
            raise ValueError("evidence mapping version must be major.minor semantic versioning")
        if len(set(self.fields)) != len(self.fields):
            raise ValueError("evidence mapping fields must be unique")
        return self


class CompatibilityBounds(FrozenDeclaration):
    """The Mayhem a provider declares it can run on.

    Three independent axes, all optional, all defaulting to "no opinion":

    * ``api_majors`` — which ``mayhem.provider/vN`` shapes it was written
      against. Defaults to this build's major only.
    * ``mayhem_min`` / ``mayhem_max`` — the core release window, lower bound
      inclusive, upper bound exclusive. The default window is "everything", so
      an unannotated provider is not silently narrowed by its own silence.
    * ``engines`` — engine lane names it supports, as lowercase dotted
      identifiers rather than a fixed enum, so a new lane in a later core
      minor does not invalidate a v1 declaration. An empty tuple means "no
      constraint".

    A bound is a claim by the *author*, checked by the core. It is not a
    capability grant, a trust signal, or evidence that the provider works on
    the core it names.
    """

    api_majors: tuple[str, ...] = Field(
        default_factory=lambda: (PROVIDER_API_MAJOR,),
        alias="apiMajors",
    )
    mayhem_min: str = Field(default="0.0.0", alias="mayhemMin")
    mayhem_max: str | None = Field(default=None, alias="mayhemMax")
    engines: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_bounds(self) -> CompatibilityBounds:
        if not self.api_majors:
            raise ValueError("compatibility bounds require at least one api major")
        for major in self.api_majors:
            if not _API_MAJOR.fullmatch(major):
                raise ValueError(f"api major {major!r} must look like 'v1'")
        if _RELEASE.fullmatch(self.mayhem_min) is None:
            raise ValueError("mayhem_min must be a major.minor.patch release")
        if self.mayhem_max is not None:
            if _RELEASE.fullmatch(self.mayhem_max) is None:
                raise ValueError("mayhem_max must be a major.minor.patch release")
            if _version_key(self.mayhem_min) >= _version_key(self.mayhem_max):
                raise ValueError("mayhem_min must be strictly below mayhem_max")
        for engine in self.engines:
            if not _IDENTIFIER.fullmatch(engine):
                raise ValueError(f"engine {engine!r} must be a lowercase dotted identifier")
        return self

    def admits(self, version: str) -> bool:
        """True when *version* is inside the declared release window.

        Raises :class:`ValueError` when *version* is not a readable version, so
        an unreadable version is never quietly treated as "inside" or "outside".
        Callers that want a typed refusal use :func:`ensure_compatibility_bounds`.
        """
        key = _version_key(version)
        if key < _version_key(self.mayhem_min):
            return False
        return self.mayhem_max is None or key < _version_key(self.mayhem_max)


class ProviderMetadata(FrozenDeclaration):
    """The whole provider declaration: the unit of the ``mayhem.provider/v1`` wire contract.

    Every field added after the first release of this contract carries a
    default. That is the whole compatibility story on the schema side: a
    declaration written against v1 stays valid when a later core *minor* adds an
    optional field, so the frozen fixture in the provider-declaration tests can
    never need editing. What a later minor may *not* do is add a field with no
    default, or narrow an existing constraint — both would break a v1
    declaration, and both are contract breaks rather than clarifications.
    """

    api_version: str = Field(default=PROVIDER_API_VERSION, alias="apiVersion")
    provider_id: str = Field(alias="providerId")
    name: str = Field(min_length=1, max_length=100)
    version: str
    description: str = Field(min_length=1, max_length=1000)
    permissions: PermissionSet = Field(default_factory=frozenset)
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
    evidence_mappings: tuple[EvidenceMapping, ...] = Field(
        default_factory=tuple,
        alias="evidenceMappings",
    )
    compatibility: CompatibilityBounds = Field(default_factory=CompatibilityBounds)
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
        self.validate_permissions_are_declared()
        self.validate_fault_graph(capability_ids, locator_ids)
        self.validate_evidence_mappings({fault.id for fault in self.fault_declarations})
        return self

    def validate_permissions_are_declared(self) -> None:
        """No part of the declaration may ask for a permission it did not declare.

        A capability, a locator and a fault each state what they need; the
        provider's own ``permissions`` set is the one an operator approves. A
        requirement that is not in that set is a request nobody approved, so it
        is refused here rather than discovered at execution time.
        """
        for capability in self.capabilities:
            if not capability.required_permissions <= self.permissions:
                raise ValueError("capability permissions must be declared by the provider")
        for locator in self.target_locators:
            if not locator.required_permissions <= self.permissions:
                raise ValueError("locator permissions must be declared by the provider")
        for fault in self.fault_declarations:
            if not fault.required_permissions <= self.permissions:
                raise ValueError("fault permissions must be declared by the provider")

    def validate_fault_graph(
        self,
        capability_ids: set[str],
        locator_ids: set[str],
    ) -> None:
        """Each declared fault hangs off a declared capability and locator."""
        fault_ids = [fault.id for fault in self.fault_declarations]
        if len(set(fault_ids)) != len(fault_ids):
            raise ValueError("fault ids must be unique within a provider declaration")
        for fault in self.fault_declarations:
            if fault.capability not in capability_ids:
                raise ValueError("fault capability must reference a declared capability")
            if not set(fault.target_locator_ids) <= locator_ids:
                raise ValueError("fault target locators must be declared by the provider")

    def validate_evidence_mappings(self, fault_ids: set[str]) -> None:
        """Every mapping names a declared fault and this provider's own schema.

        Split out so the rule reads as a rule rather than as a branch inside the
        graph walk, and so the refusal names the offending fault.
        """
        mapped = [mapping.fault_id for mapping in self.evidence_mappings]
        if len(set(mapped)) != len(mapped):
            raise ValueError("a fault may have only one evidence mapping")
        published = set(self.evidence_schema.fields)
        for mapping in self.evidence_mappings:
            if mapping.fault_id not in fault_ids:
                raise ValueError(f"evidence mapping names undeclared fault {mapping.fault_id!r}")
            if mapping.schema_name != self.evidence_schema.name:
                raise ValueError(
                    f"evidence mapping for {mapping.fault_id!r} names schema "
                    f"{mapping.schema_name!r}, but the provider publishes "
                    f"{self.evidence_schema.name!r}"
                )
            if mapping.schema_version != self.evidence_schema.version:
                raise ValueError(
                    f"evidence mapping for {mapping.fault_id!r} names version "
                    f"{mapping.schema_version!r}, but the provider publishes "
                    f"{self.evidence_schema.version!r}"
                )
            unknown = sorted(set(mapping.fields) - published)
            if unknown:
                raise ValueError(
                    f"evidence mapping for {mapping.fault_id!r} names fields the "
                    f"published schema does not have: {', '.join(unknown)}"
                )

    # -- read-only views over the declaration ---------------------------------
    #
    # Derived, never stored, so a caller cannot hold a second copy of the graph
    # that the declaration has since stopped agreeing with.

    @property
    def capability_ids(self) -> frozenset[str]:
        return frozenset(capability.id for capability in self.capabilities)

    @property
    def target_locator_ids(self) -> frozenset[str]:
        return frozenset(locator.id for locator in self.target_locators)

    @property
    def declared_fault_ids(self) -> frozenset[str]:
        return frozenset(fault.id for fault in self.fault_declarations)

    @property
    def fault_declaration(self) -> dict[str, FaultDeclaration]:
        return {fault.id: fault for fault in self.fault_declarations}

    @property
    def required_permissions(self) -> frozenset[ProviderPermission]:
        """Every permission any part of the declaration asks for.

        The union is what an operator must be shown before approving an
        install, and it is what a default-deny gate must compare against a
        grant: a permission asked for deep in a fault is still a permission.
        """
        requested: set[ProviderPermission] = set()
        for capability in self.capabilities:
            requested |= capability.required_permissions
        for locator in self.target_locators:
            requested |= locator.required_permissions
        for fault in self.fault_declarations:
            requested |= fault.required_permissions
        return frozenset(requested)

    def evidence_for(self, fault_id: str) -> EvidenceSchema | None:
        """The evidence schema *fault_id* writes through, or ``None``.

        ``None`` means the declaration says nothing about this fault's evidence,
        which is not the same as saying the fault writes no evidence.
        """
        for mapping in self.evidence_mappings:
            if mapping.fault_id == fault_id:
                return self.evidence_schema
        return None


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


#: The serialised field names of :class:`ProviderMetadata`, as a *frozen*
#: contract rather than a derived one. Written out by hand on purpose: deriving
#: it from the model would make the guard tautological, since a field added
#: carelessly would then be blessed by the very test meant to notice it. Every
#: serialised name of a new optional field is appended here in the same commit
#: that adds the field; a removal is a contract break.
PROVIDER_DECLARATION_WIRE_FIELDS: frozenset[str] = frozenset(
    {
        "apiVersion",
        "providerId",
        "name",
        "version",
        "description",
        "permissions",
        "capabilities",
        "faultDeclarations",
        "targetLocators",
        "evidenceSchema",
        "evidenceMappings",
        "compatibility",
        "source",
        "homepage",
    }
)

#: The serialised field names of :class:`FaultDeclaration`, frozen for the same
#: reason. ``risk`` and ``parameterGrammar`` arrived in the v1 contract's first
#: minor, both with defaults, which is what kept every earlier v1 declaration
#: loadable.
PROVIDER_FAULT_WIRE_FIELDS: frozenset[str] = frozenset(
    {
        "id",
        "capability",
        "summary",
        "target_locator_ids",
        "parameters",
        "parameterGrammar",
        "risk",
        "mutation",
        "reversible",
        "requiredPermissions",
    }
)


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


def ensure_declared_permissions(
    metadata: ProviderMetadata,
    allowed: frozenset[ProviderPermission] = DEFAULT_DECLARED_PERMISSIONS,
) -> None:
    """Default-deny gate for a declaration, with no grant supplied.

    The default posture is *nothing*, so the default call refuses every
    declaration that asks for a permission. It delegates to
    :func:`ensure_permissions` rather than re-implementing the comparison, so
    there is one refusal type and one message shape wherever a provider is
    gated — a divergence here would be a gate that reads differently from the
    one the loader uses.

    It compares the *declared* permission set, not
    :attr:`ProviderMetadata.required_permissions`. Those are equal by
    construction — the declaration validator refuses a part that asks for
    something the provider did not declare — so the gate stays exactly as
    narrow as the declared set, and a caller wanting the union reads the
    property.
    """
    ensure_permissions(metadata, allowed)


def ensure_compatibility_bounds(
    metadata: ProviderMetadata,
    *,
    running_version: str,
    running_engine: str | None = None,
    supported_api_version: str = PROVIDER_API_VERSION,
) -> None:
    """Refuse a declaration whose declared support excludes this core.

    Three checks, each an independent reason to refuse:

    1. :func:`ensure_api_compatible` — the wire major. A v1 declaration loading
       on a v1 core is the whole cross-minor promise, and a v2 declaration is
       the signal that the promise does not apply.
    2. the declared release window. A prerelease sorts below the release it
       precedes, so ``1.1.0.dev0`` is inside a ``>=1.0.0`` window and outside a
       ``>=1.1.0`` one.
    3. the engine lane, **only when the caller supplies one**. An engine axis
       that is declared but unchecked is an open question, not a pass: the
       caller is told in the docstring that omitting ``running_engine`` skips
       the check entirely. Supply it, or do not pretend the axis was verified.

    Passing here means "this core is inside the window the author declared".
    It says nothing about the provider being safe, correct, or even installed.
    """
    ensure_api_compatible(metadata, supported_api_version=supported_api_version)
    bounds = metadata.compatibility
    try:
        _version_key(running_version)
    except ValueError as exc:
        raise ProviderCompatibilityError(
            "provider_version_unreadable",
            f"cannot compare provider {metadata.provider_id!r} bounds against "
            f"running version {running_version!r}: {exc}",
        ) from exc
    if not bounds.admits(running_version):
        raise ProviderCompatibilityError(
            "provider_version_unsupported",
            f"provider {metadata.provider_id!r} supports Mayhem "
            f">={bounds.mayhem_min}"
            + (f",<{bounds.mayhem_max}" if bounds.mayhem_max else "")
            + f"; this Mayhem is {running_version}",
        )
    if bounds.engines and running_engine is not None and running_engine not in bounds.engines:
        raise ProviderCompatibilityError(
            "provider_engine_unsupported",
            f"provider {metadata.provider_id!r} declares support for engines "
            f"{', '.join(bounds.engines)}; this run is on {running_engine!r}",
        )


def fault_parameter_problems(
    fault: FaultDeclaration,
    values: dict[str, str],
) -> tuple[str, ...]:
    """Every way *values* fails the fault's declared parameter grammar.

    Pure and total: it returns the problems, it does not raise, so a caller
    that only wants to display them never has to catch anything. Checks run in
    a fixed order — unknown names, then missing, then value grammar — so the
    message is deterministic.

    A fault with no declared grammar is checked only against the flat
    ``parameters`` defaults it carries, which is the pre-grammar behaviour and
    is deliberately not an error: a v1 declaration that never declared a
    grammar must keep working.
    """
    problems: list[str] = []
    grammar = {entry.name: entry for entry in fault.parameter_grammar}
    for name in sorted(set(values) - set(grammar) - set(fault.parameters)):
        problems.append(f"parameter {name!r} is not declared by fault {fault.id!r}")
    for name, entry in sorted(grammar.items()):
        if name not in values:
            if entry.required and entry.default is None:
                problems.append(f"parameter {name!r} is required by fault {fault.id!r}")
            continue
        problem = _parameter_value_problem(fault.id, entry, values[name])
        if problem:
            problems.append(problem)
    return tuple(problems)


def _parameter_value_problem(
    fault_id: str,
    entry: ParameterDeclaration,
    raw: str,
) -> str:
    """Why *raw* is not a legal value for *entry*, or ``""`` when it is.

    One exit, so every path through the value grammar is in one place and a new
    kind cannot be added in a branch that quietly forgets to return.
    """
    where = f"parameter {entry.name!r} of fault {fault_id!r}"
    if entry.kind is ParameterKind.ENUM:
        problem = "" if raw in entry.choices else f"must be one of {', '.join(entry.choices)}"
    elif entry.kind is ParameterKind.BOOLEAN:
        problem = "" if raw in {"true", "false"} else "must be 'true' or 'false'"
    elif entry.kind is ParameterKind.JSON:
        problem = _json_problem(raw)
    elif entry.kind in {
        ParameterKind.INTEGER,
        ParameterKind.NUMBER,
        ParameterKind.DURATION_S,
    }:
        problem = _number_problem(entry, raw)
    else:
        problem = _string_problem(entry, raw)
    return f"{where} {problem}" if problem else ""


def _json_problem(raw: str) -> str:
    try:
        json.loads(raw)
    except ValueError as exc:
        return f"must be JSON: {exc}"
    return ""


def _number_problem(entry: ParameterDeclaration, raw: str) -> str:
    try:
        number = float(raw)
    except ValueError:
        return f"must be a number, got {raw!r}"
    if entry.kind is ParameterKind.INTEGER and not number.is_integer():
        return f"must be a whole number, got {raw!r}"
    if entry.minimum is not None and number < entry.minimum:
        return f"must be at least {entry.minimum}, got {raw!r}"
    if entry.maximum is not None and number > entry.maximum:
        return f"must be at most {entry.maximum}, got {raw!r}"
    return ""


def _string_problem(entry: ParameterDeclaration, raw: str) -> str:
    if entry.minimum is not None or entry.maximum is not None:
        return f"of kind {entry.kind.value!r} takes no numeric bounds"
    if entry.pattern is not None and re.fullmatch(entry.pattern, raw) is None:
        return f"must match {entry.pattern!r}, got {raw!r}"
    return ""


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
