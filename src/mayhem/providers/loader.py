from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib import import_module
from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from mayhem.domain.catalog import CATALOG, validate_catalog
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.faults import (
    EngineLane,
    FailureDomain,
    FaultCategory,
    FaultDefinition,
    MaturityLevel,
    Reversibility,
    TargetKind,
    VerificationMethod,
)
from mayhem.domain.provider import (
    PROVIDER_API_VERSION,
    CapabilityDescriptor,
    EvidenceSchema,
    FaultDeclaration,
    ImplementationKind,
    ImplementationReference,
    ProviderCatalog,
    ProviderError,
    ProviderMetadata,
    ProviderMutation,
    ProviderPermission,
    ProviderRegistration,
    ProviderSource,
    TargetLocator,
    ensure_api_compatible,
    ensure_permissions,
)
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import NodeKind
from mayhem.providers.builtin import create_builtin_registry
from mayhem.providers.pack import (
    SIGNATURE_TRUST_NOTICE,
    FaultPack,
    PackFault,
    PackValidationError,
    load_pack,
    pack_assurance,
    validate_pack,
)
from mayhem.providers.permissions import ProviderPermissionSet, SandboxRefusal

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from mayhem.providers.registry import ProviderRegistry

METADATA_ENTRY_POINT_GROUP = "mayhem.provider.metadata"
IMPLEMENTATION_ENTRY_POINT_GROUP = "mayhem.providers"


def _factory_for(runtime: object) -> Callable[[], object]:
    """Bind *runtime* into a zero-arg factory, by value.

    An already-materialized runtime is handed to the registry as-is; the
    default-argument lambda this replaces (``lambda runtime=runtime:
    runtime``) could not be typed because the default's own type was
    unresolvable.  A closure over a *parameter* gives the same bind-at-call
    semantics — each returned factory closes over its own ``runtime``.
    """

    def factory() -> object:
        return runtime

    return factory


#: The identifier shape ``ProviderMetadata`` enforces, restated so a bad pack id
#: is refused with a pack-worded message instead of a pydantic dump.
_PROVIDER_ID = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")

#: Permissions that mean "this fault touches the world". A read-only fault may
#: only ever declare :attr:`ProviderPermission.TARGET_READ`.
_ACTION_PERMISSIONS: frozenset[ProviderPermission] = frozenset(ProviderPermission) - {
    ProviderPermission.TARGET_READ
}


class ProviderLoadError(ProviderError, ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProviderLoadFailure:
    provider_id: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "provider_id": self.provider_id,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ProviderInspection:
    provider_id: str
    status: str
    source: str
    metadata: dict[str, Any] | None = None
    error: ProviderLoadFailure | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "provider_id": self.provider_id,
            "status": self.status,
            "source": self.source,
        }
        if self.metadata is not None:
            payload["metadata"] = self.metadata
        if self.error is not None:
            payload["error"] = self.error.to_dict()
        return payload


@dataclass(frozen=True, slots=True)
class ProviderLoadReport:
    providers: tuple[ProviderInspection, ...] = ()
    loaded: tuple[str, ...] = ()
    failures: tuple[ProviderLoadFailure, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "providers": [provider.to_dict() for provider in self.providers],
            "loaded": list(self.loaded),
            "failures": [failure.to_dict() for failure in self.failures],
        }


# ── fault packs: reading a file, establishing what it proves ─────────────────


def builtin_fault_ids() -> frozenset[str]:
    """Every fault id mayhem already owns, read live from the catalog.

    Read live rather than cached at import so a pack can never be admitted
    because this module was imported before the catalog grew.
    """
    return frozenset(definition.id for definition in CATALOG)


def read_pack_document(path: str | Path) -> tuple[dict[str, Any], str]:
    """Read a pack file into a document plus the sha256 of the bytes read.

    Every failure mode of a real filesystem — missing, unreadable, a directory,
    empty, non-UTF-8, not JSON, JSON but not an object — is reported as a
    :class:`PackValidationError` with a message a user can act on. Nothing here
    raises a bare ``OSError`` or lets a ``json``/``UnicodeDecodeError`` trace
    escape, because a stack trace is not an answer about someone else's file.
    """
    resolved = Path(path)
    try:
        raw = resolved.read_bytes()
    except IsADirectoryError as exc:
        raise PackValidationError(
            f"cannot read fault pack {resolved}: it is a directory, not a pack file"
        ) from exc
    except OSError as exc:
        detail = exc.strerror or str(exc)
        raise PackValidationError(f"cannot read fault pack {resolved}: {detail}") from exc
    if not raw.strip():
        raise PackValidationError(f"fault pack {resolved} is empty; expected a JSON pack document")
    try:
        document = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise PackValidationError(
            f"fault pack {resolved} is not UTF-8 text, so it is not a pack document"
        ) from exc
    except json.JSONDecodeError as exc:
        raise PackValidationError(
            f"fault pack {resolved} is not valid JSON: {exc.msg} "
            f"at line {exc.lineno} column {exc.colno}"
        ) from exc
    if not isinstance(document, dict):
        raise PackValidationError(
            f"fault pack {resolved} is a JSON {type(document).__name__}, "
            "not a JSON object describing a pack"
        )
    return document, hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class PackAssurance:
    """What loading a pack established — and, more importantly, what it did not.

    ``signature_verified`` is a real field with a real ``False`` value in this
    build, not an omitted one. A consumer must not read the presence of
    ``signature_present`` as permission to say "verified".
    """

    provider_id: str
    digest: str
    digest_verified: bool
    signature_present: bool
    signature_verified: bool
    signature_scheme: str
    signer_claimed: str
    signer_trusted: bool
    development_only: bool
    assurance: str
    notice: str = SIGNATURE_TRUST_NOTICE

    @classmethod
    def for_pack(cls, pack: FaultPack, *, digest_verified: bool) -> PackAssurance:
        values = pack_assurance(pack, digest_verified=digest_verified)
        return cls(
            provider_id=pack.manifest.provider_id,
            digest=str(values["digest"]),
            digest_verified=digest_verified,
            signature_present=bool(values["signature_present"]),
            signature_verified=bool(values["signature_verified"]),
            signature_scheme=str(values["signature_scheme"]),
            signer_claimed=str(values["signer_claimed"]),
            signer_trusted=bool(values["signer_trusted"]),
            development_only=bool(values["development_only"]),
            assurance=str(values["assurance"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "digest": self.digest,
            "digest_verified": self.digest_verified,
            "signature_present": self.signature_present,
            "signature_verified": self.signature_verified,
            "signature_scheme": self.signature_scheme,
            "signer_claimed": self.signer_claimed,
            "signer_trusted": self.signer_trusted,
            "development_only": self.development_only,
            "assurance": self.assurance,
            "notice": self.notice,
        }


@dataclass(frozen=True, slots=True)
class PackRuntime:
    """What a registered pack *is* in 1.0: catalog metadata, never code.

    ``executable`` is a field rather than an omission so that a caller reading
    the runtime object cannot infer executability from its mere existence.
    """

    provider_id: str
    signer_claimed: str
    digest: str
    fault_ids: tuple[str, ...]
    executable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "signer_claimed": self.signer_claimed,
            "digest": self.digest,
            "fault_ids": list(self.fault_ids),
            "executable": self.executable,
        }


@dataclass(frozen=True, slots=True)
class LoadedPack:
    """A pack that passed every gate, plus everything it did and did not prove."""

    pack: FaultPack
    registration: ProviderRegistration
    definitions: tuple[FaultDefinition, ...]
    assurance: PackAssurance
    report: dict[str, Any]
    path: str = ""

    def runtime(self) -> PackRuntime:
        return PackRuntime(
            provider_id=self.pack.manifest.provider_id,
            signer_claimed=self.pack.signer,
            digest=self.assurance.digest,
            fault_ids=tuple(fault.id for fault in self.pack.faults),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "pack": self.pack.to_dict(),
            "report": self.report,
            "assurance": self.assurance.to_dict(),
            "registration": self.registration.metadata.model_dump(mode="json", by_alias=True),
            "definitions": [definition.model_dump(mode="json") for definition in self.definitions],
        }


def _check_declared_digest(pack: FaultPack, path: str, computed: str, expected: str) -> list[str]:
    """Compare the pack's own digest claim against the bytes actually on disk.

    Both digests are printed in full. A truncated digest in a refusal is not
    enough to let an operator confirm which of two packs they were handed.
    """
    problems: list[str] = []
    if pack.declared_digest and pack.declared_digest != computed:
        problems.append(
            f"pack digest mismatch: {path} declares {pack.declared_digest} "
            f"but its content digests to {computed} "
            "(sha256 over the canonical pack document, excluding declared_digest); "
            "the file was modified after it was signed"
        )
    if expected and expected != computed:
        problems.append(
            f"pack digest does not match the expected {expected}: {path} digests to {computed}"
        )
    return problems


def _check_no_shadowing(
    pack: FaultPack, reserved: frozenset[str], builtin_providers: frozenset[str]
) -> list[str]:
    """A pack may add fault ids; it may never redeclare, shadow, or impersonate."""
    problems: list[str] = []
    provider_id = pack.manifest.provider_id
    if provider_id in builtin_providers:
        problems.append(
            f"pack provider id {provider_id!r} is already a built-in mayhem provider; "
            "choose an id that does not shadow a built-in provider"
        )
    for fault in pack.faults:
        if fault.id in reserved:
            problems.append(
                f"pack fault {fault.id!r} is already a mayhem catalog fault; "
                "a pack must not redeclare or shadow a built-in fault id"
            )
    return problems


def _check_catalog_joinable(pack: FaultPack) -> list[str]:
    """Every pack fault must be expressible in the existing catalog contract.

    A pack fault is surfaced as a ``catalog_only`` ``FaultDefinition`` so it uses
    the same machinery as every other refused fault. That machinery derives its
    category from the id prefix, so an id mayhem cannot classify cannot be
    surfaced at all — refuse it here rather than dropping it silently.
    """
    problems: list[str] = []
    for fault in pack.faults:
        try:
            FaultCategory.from_fault_id(fault.id)
        except SchemaValidationError as exc:
            problems.append(f"pack fault {fault.id!r} cannot join the fault catalog: {exc}")
        try:
            RiskLevel(fault.risk)
        except ValueError:
            problems.append(
                f"pack fault {fault.id!r} declares unknown risk {fault.risk!r} "
                f"(expected one of {[level.value for level in RiskLevel]})"
            )
    return problems


def _check_fault_contract(pack: FaultPack) -> list[str]:
    """A pack fault must be expressible as a ``FaultDeclaration``.

    The provider contract says a *mutating* fault must be reversible, and a
    *read-only* fault may not require action permissions. Those two rules do
    not bend to a pack, so a pack that lands between them is refused with the
    fix spelled out rather than quietly downgraded to read-only.
    """
    problems: list[str] = []
    for fault in pack.faults:
        action = set(fault.permissions) & _ACTION_PERMISSIONS
        if action and ProviderPermission.TARGET_MUTATE not in set(fault.permissions):
            names = sorted(permission.value for permission in action)
            problems.append(
                f"pack fault {fault.id!r} requests action permissions "
                f"({', '.join(names)}) without target:mutate; a pack fault that acts on "
                "anything must declare target:mutate so the grant is explicit"
            )
        if fault.reversible is False and ProviderPermission.TARGET_MUTATE in set(fault.permissions):
            problems.append(
                f"pack fault {fault.id!r} is irreversible and declares target:mutate, but a "
                "mutating provider fault must be reversible; publish it as a reversible "
                "fault with a compensation contract, or drop the fault"
            )
    return problems


def _check_registration_shape(pack: FaultPack) -> list[str]:
    """Provider id and version must satisfy the provider metadata contract."""
    problems: list[str] = []
    manifest = pack.manifest
    if not _PROVIDER_ID.fullmatch(manifest.provider_id):
        problems.append(
            f"provider id {manifest.provider_id!r} is not a lowercase dotted identifier "
            "of 2-64 characters"
        )
    if not _SEMVER.fullmatch(manifest.version):
        problems.append(
            f"provider version {manifest.version!r} is not semantic versioning (major.minor.patch)"
        )
    if not manifest.provider_id:
        problems.append("pack names no provider id")
    return problems


def _requested_permissions(pack: FaultPack) -> frozenset[ProviderPermission]:
    """Manifest permissions unioned with every fault's own permissions."""
    return frozenset(pack.manifest.permissions) | frozenset(
        permission for fault in pack.faults for permission in fault.permissions
    )


def _category_defaults(category: FaultCategory) -> tuple[FailureDomain, VerificationMethod]:
    """A category's failure domain and verification method, from the live catalog.

    Borrowed from the built-in entries for the same category rather than
    restated, so a pack fault is classified exactly the way a built-in fault of
    its category is and the two cannot drift apart.
    """
    for definition in CATALOG:
        if (
            definition.category is category
            and definition.failure_domain is not None
            and definition.verification_method is not None
        ):
            return (definition.failure_domain, definition.verification_method)
    raise PackValidationError(
        f"mayhem has no catalog entry for fault category {category.value!r}, "
        "so a pack fault of that category cannot be described"
    )


def _pack_refusal_reason(pack: FaultPack, fault: PackFault) -> str:
    """Why this pack fault is catalog-only, in the catalog's own vocabulary."""
    signer = pack.signer or "<no signer — pack is unsigned>"
    return (
        f"catalog.pack_fault_not_executable: {fault.id!r} is contributed by fault pack "
        f"{pack.manifest.provider_id!r} (signer claims {signer!r}, digest "
        f"{pack.pack_digest()[:12]}), whose signature mayhem cannot verify because the "
        "pack format declares no key or trust store; mayhem 1.0 surfaces pack faults in "
        "the catalog for inspection and refuses to plan or execute them"
    )


def pack_definition(pack: FaultPack, fault: PackFault) -> FaultDefinition:
    """Re-express one pack fault in the existing ``catalog_only`` machinery.

    Deliberately not a parallel mechanism: this is an ordinary
    :class:`FaultDefinition` with ``catalog_only=True`` and a populated
    ``refusal_reason``, so ``validate_catalog`` and the planner's catalog-only
    handling apply to it unchanged.
    """
    category = FaultCategory.from_fault_id(fault.id)
    failure_domain, verification_method = _category_defaults(category)
    return FaultDefinition(
        id=fault.id,
        category=category,
        risk=RiskLevel(fault.risk),
        reversible=fault.reversible,
        applicable_node_kinds=frozenset({NodeKind.SERVICE}),
        max_duration_s=300.0,
        observable_effect=(
            fault.observable_effect
            or "effect declared by fault pack "
            f"{pack.manifest.provider_id!r}, not verified by mayhem"
        ),
        compensation_evidence=(fault.compensation,),
        failure_domain=failure_domain,
        target_kind=TargetKind.SERVICE,
        target_kinds=frozenset({TargetKind.SERVICE}),
        engine_lanes=frozenset({EngineLane.MULTI_ENGINE}),
        verification_method=verification_method,
        reversibility=(
            Reversibility.REVERSIBLE if fault.reversible else Reversibility.IRREVERSIBLE
        ),
        maturity=MaturityLevel.EXPERIMENTAL,
        catalog_only=True,
        refusal_reason=_pack_refusal_reason(pack, fault),
    )


def pack_definitions(pack: FaultPack) -> tuple[FaultDefinition, ...]:
    """Every pack fault as a catalog-only definition, checked by ``validate_catalog``."""
    definitions = tuple(pack_definition(pack, fault) for fault in pack.faults)
    if definitions:
        validate_catalog(definitions)
    return definitions


def _fault_declaration(pack: FaultPack, fault: PackFault) -> FaultDeclaration:
    """One pack fault as a provider fault declaration."""
    provider_id = pack.manifest.provider_id
    mutating = ProviderPermission.TARGET_MUTATE in set(fault.permissions)
    return FaultDeclaration(
        id=fault.id,
        capability=f"{provider_id}.pack",
        summary=(
            fault.observable_effect or f"fault {fault.id!r} contributed by pack {provider_id!r}"
        )[:500],
        target_locator_ids=(f"{provider_id}.target",),
        requiredPermissions=frozenset(fault.permissions),
        mutation=ProviderMutation.MUTATING if mutating else ProviderMutation.READ_ONLY,
        reversible=fault.reversible,
    )


def _pack_metadata(pack: FaultPack) -> ProviderMetadata:
    """Pack faults expressed as provider metadata for the provider registry."""
    provider_id = pack.manifest.provider_id
    # The provider contract requires every target locator to hold target:read,
    # so a pack that addresses a target always declares it. This is a floor on
    # the *metadata* only: what the pack actually asked for is still gated
    # against the caller's grant in ``validate_pack``.
    permissions = _requested_permissions(pack) | {ProviderPermission.TARGET_READ}
    return ProviderMetadata(
        apiVersion=PROVIDER_API_VERSION,
        providerId=provider_id,
        name=pack.manifest.provider_id,
        version=pack.manifest.version,
        description=(
            f"Fault pack {pack.manifest.provider_id!r} "
            f"({len(pack.faults)} catalog-only fault(s)); "
            "its signature is unverified and mayhem does not execute pack faults."
        )[:1000],
        permissions=permissions,
        capabilities=(
            CapabilityDescriptor(
                id=f"{provider_id}.pack",
                summary="Faults contributed by a third-party fault pack.",
                requiredPermissions=permissions & _ACTION_PERMISSIONS,
                mutates_targets=ProviderPermission.TARGET_MUTATE in permissions,
                compensable=ProviderPermission.TARGET_MUTATE in permissions,
            ),
        ),
        faultDeclarations=tuple(_fault_declaration(pack, fault) for fault in pack.faults),
        targetLocators=(
            TargetLocator(
                id=f"{provider_id}.target",
                kind="pack_target",
                requiredPermissions=frozenset({ProviderPermission.TARGET_READ}),
            ),
        ),
        evidenceSchema=EvidenceSchema(name=f"{provider_id}-pack-evidence", version="1.0"),
        source=ProviderSource.CATALOG,
        homepage=pack.manifest.homepage or None,
    )


def pack_registration(pack: FaultPack) -> ProviderRegistration:
    """Build the provider registration a loaded pack contributes.

    The implementation reference is deliberately an ``entry_point`` for the
    pack's own id: a pack supplies no importable code, so this registration
    declares *metadata only*. Nothing in mayhem installs such an entry point,
    which is exactly why the pack faults it contributes are catalog-only.
    """
    problems = _check_registration_shape(pack)
    if problems:
        raise PackValidationError(
            f"pack {pack.manifest.provider_id!r} refused: " + "; ".join(problems)
        )
    try:
        metadata = _pack_metadata(pack)
    except (SchemaValidationError, ValueError) as exc:
        raise PackValidationError(
            f"pack {pack.manifest.provider_id!r} refused: it cannot be expressed as a "
            f"mayhem provider registration: {exc}"
        ) from exc
    return ProviderRegistration(
        metadata=metadata,
        implementation=ImplementationReference(
            kind=ImplementationKind.ENTRY_POINT,
            target=pack.manifest.provider_id,
            factory=True,
        ),
    )


class PackLoader:
    """Opt-in fault-pack loading behind explicit permission grants (task 18).

    Nothing loads unless the caller opts in: ``--allow-development-only`` for an
    unsigned pack, and a named permission grant for anything beyond the default
    read-only posture. Every refusal is deterministic and says what to change.
    """

    def __init__(
        self,
        *,
        grants: dict[str, ProviderPermissionSet] | None = None,
        allow_development_only: bool = False,
    ) -> None:
        self._grants = dict(grants or {})
        self._allow_development_only = allow_development_only

    def permissions_for(self, provider_id: str) -> ProviderPermissionSet:
        return self._grants.get(provider_id) or ProviderPermissionSet.default(provider_id)

    def grant(self, provider_id: str, permissions: ProviderPermissionSet) -> None:
        self._grants[provider_id] = permissions

    @staticmethod
    def _require_mutation_grant(pack: FaultPack, permissions: ProviderPermissionSet) -> None:
        if not pack.faults or permissions.mutating:
            return
        for fault in pack.faults:
            permissions.require(
                ProviderPermission.TARGET_MUTATE,
                reason=(
                    f"pack fault {fault.id!r} mutates a target; "
                    "grant target:mutate explicitly to load it"
                ),
            )

    def inspect(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Validate without loading; never raises for a merely invalid pack."""
        try:
            pack = load_pack(payload)
        except PackValidationError as exc:
            return {"loadable": False, "reason": str(exc)}
        permissions = self.permissions_for(pack.manifest.provider_id)
        try:
            self._require_mutation_grant(pack, permissions)
        except SandboxRefusal as exc:
            return {"loadable": False, "reason": str(exc)}
        try:
            return validate_pack(
                pack,
                granted_permissions=permissions.granted,
                allow_development_only=self._allow_development_only,
            )
        except PackValidationError as exc:
            return {"loadable": False, "reason": str(exc)}

    def load(self, payload: dict[str, Any]) -> tuple[FaultPack, dict[str, Any]]:
        """Validate and return the pack, or raise ``PackValidationError``."""
        pack = load_pack(payload)
        permissions = self.permissions_for(pack.manifest.provider_id)
        # The pack must not exceed its own grant, and a mutating pack needs an
        # explicit target:mutate grant rather than the default posture.
        self._require_mutation_grant(pack, permissions)
        report = validate_pack(
            pack,
            granted_permissions=permissions.granted,
            allow_development_only=self._allow_development_only,
        )
        return pack, report

    # -- reading a pack off disk ------------------------------------------------

    def assurance_for(self, pack: FaultPack, *, digest_verified: bool) -> PackAssurance:
        """The trust statement for a pack, independent of any registration."""
        return PackAssurance.for_pack(pack, digest_verified=digest_verified)

    def load_file(
        self,
        path: str | Path,
        *,
        expected_digest: str = "",
        reserved_fault_ids: frozenset[str] | None = None,
        require_grant: bool = True,
    ) -> LoadedPack:
        """Read a pack from disk and take it all the way to a registration.

        The gates, in order, and every one of them refuses:

        1. the file must be readable, UTF-8, and a JSON object;
        2. the document must parse against the pack schema;
        3. ``declared_digest`` must equal the digest of the bytes on disk, and
           must equal ``expected_digest`` when the caller pinned one;
        4. the pack must be schema-compatible, and unsigned or
           ``development_only`` packs are refused unless
           ``allow_development_only`` was set on this loader;
        5. the provider id and version must satisfy the provider contract;
        6. no fault id may be, or shadow, a fault mayhem already owns;
        7. every fault must be classifiable, risk-level'd, and expressible as a
           provider fault declaration;
        8. with ``require_grant``, the pack must not exceed the permissions
           granted to its provider.

        ``reserved_fault_ids`` defaults to the live catalog; pass an explicit
        set to check against something else (a second registry, a test fixture).

        ``require_grant=False`` answers "is this pack *sound*?" without also
        answering "am I *allowed* to use it?". Those are different questions
        and a read-only inspection should not require a grant to ask the first
        one — the permission verdict is reported either way, as
        ``report["permissions"]`` against the pack's own request.
        """
        resolved = str(path)
        document, _file_digest = read_pack_document(path)
        pack = load_pack(document)

        reserved = builtin_fault_ids() if reserved_fault_ids is None else reserved_fault_ids
        builtin_providers = frozenset(create_builtin_registry().ids())
        computed = pack.pack_digest()
        permissions = self.permissions_for(pack.manifest.provider_id)

        problems: list[str] = [
            *_check_declared_digest(pack, resolved, computed, expected_digest),
            *_check_registration_shape(pack),
            *_check_no_shadowing(pack, reserved, builtin_providers),
            *_check_catalog_joinable(pack),
            *_check_fault_contract(pack),
        ]
        if problems:
            raise PackValidationError(
                f"pack {pack.manifest.provider_id!r} refused: " + "; ".join(problems)
            )

        if require_grant:
            # _require_mutation_grant raises SandboxRefusal, which names the
            # permission and provider; convert it so a file-level refusal is
            # one exception type with one message shape.
            try:
                self._require_mutation_grant(pack, permissions)
            except SandboxRefusal as exc:
                raise PackValidationError(
                    f"pack {pack.manifest.provider_id!r} refused: {exc.reason}"
                ) from exc

        # The permission gate needs a grant set to compare against. A real load
        # already passed ``_require_mutation_grant`` above, so reuse the
        # loader's own grants; a read-only inspection grants the pack exactly
        # what it declared, so the gate checks the pack against itself and
        # cannot raise a spurious refusal. Nothing executes on this path, so
        # the widened grant is never exercised.
        granted = permissions.granted if require_grant else _requested_permissions(pack)
        report = validate_pack(
            pack,
            granted_permissions=granted,
            allow_development_only=self._allow_development_only,
        )
        digest_verified = bool(pack.declared_digest) and pack.declared_digest == computed
        assurance = self.assurance_for(pack, digest_verified=digest_verified)
        return LoadedPack(
            pack=pack,
            registration=pack_registration(pack),
            definitions=pack_definitions(pack),
            assurance=assurance,
            report=report,
            path=resolved,
        )

    def inspect_file(
        self,
        path: str | Path,
        *,
        expected_digest: str = "",
        reserved_fault_ids: frozenset[str] | None = None,
        require_grant: bool = True,
    ) -> dict[str, Any]:
        """Validate a pack file without loading it; never raises.

        The refusal is reported under ``loadable: False`` with its reason, so a
        caller rendering a verdict never has to catch anything to stay alive.
        """
        try:
            loaded = self.load_file(
                path,
                expected_digest=expected_digest,
                reserved_fault_ids=reserved_fault_ids,
                require_grant=require_grant,
            )
        except (PackValidationError, SandboxRefusal) as exc:
            return {"loadable": False, "reason": str(exc), "path": str(path)}
        return {"loadable": True, **loaded.to_dict()}

    def validate_file(
        self,
        path: str | Path,
        *,
        expected_digest: str = "",
        reserved_fault_ids: frozenset[str] | None = None,
    ) -> LoadedPack:
        """Answer "is this pack *sound*?" without answering "may I use it?".

        This is the read-only verdict: it applies every structural, digest,
        shadowing, and safety check, and skips only the permission grant.
        Asking whether a file is trustworthy must not itself require a grant.
        The permission verdict is still reported, as
        ``report["permissions"]`` against the pack's own request.
        """
        return self.load_file(
            path,
            expected_digest=expected_digest,
            reserved_fault_ids=reserved_fault_ids,
            require_grant=False,
        )

    def register(
        self,
        loaded: LoadedPack,
        registry: ProviderRegistry,
        *,
        reserved_fault_ids: frozenset[str] | None = None,
    ) -> ProviderRegistration:
        """Put a loaded pack into a provider registry the engine can see.

        The declared fault ids are checked against the ids the pack actually
        defines in both directions, so a registration that names a fault the
        pack does not contain — or omits one it does — is refused instead of
        being registered as a half-truth.
        """
        declarations = loaded.registration.metadata.fault_declarations
        declared = {declaration.id for declaration in declarations}
        defined = {fault.id for fault in loaded.pack.faults}
        if declared != defined:
            details: list[str] = []
            if undefined := sorted(declared - defined):
                details.append(f"declares faults it does not define: {', '.join(undefined)}")
            if undeclared := sorted(defined - declared):
                details.append(f"defines faults it does not declare: {', '.join(undeclared)}")
            raise PackValidationError(
                f"pack {loaded.pack.manifest.provider_id!r} refused: " + "; ".join(details)
            )

        reserved = builtin_fault_ids() if reserved_fault_ids is None else reserved_fault_ids
        shadows = sorted(d.id for d in loaded.definitions if d.id in reserved)
        if shadows:
            raise PackValidationError(
                f"pack {loaded.pack.manifest.provider_id!r} refused: "
                f"these fault ids are already mayhem catalog faults: {', '.join(shadows)}"
            )

        runtime = loaded.runtime()

        def factory() -> PackRuntime:
            return runtime

        registry.register(loaded.registration, factory)
        return loaded.registration

    def load_into(
        self,
        path: str | Path,
        registry: ProviderRegistry,
        *,
        expected_digest: str = "",
        reserved_fault_ids: frozenset[str] | None = None,
    ) -> LoadedPack:
        """``load_file`` plus :meth:`register`, the whole path in one call."""
        loaded = self.load_file(
            path, expected_digest=expected_digest, reserved_fault_ids=reserved_fault_ids
        )
        self.register(loaded, registry, reserved_fault_ids=reserved_fault_ids)
        return loaded


class ProviderLoader:
    def __init__(
        self,
        *,
        registry: ProviderRegistry | None = None,
        allowed_permissions: frozenset[ProviderPermission] = frozenset(),
        import_module_fn: Callable[[str], Any] | None = None,
        entry_points_fn: Callable[..., Iterable[Any]] | None = None,
    ) -> None:
        self.registry = registry if registry is not None else create_builtin_registry()
        self.allowed_permissions = allowed_permissions
        self._import_module = import_module_fn if import_module_fn is not None else import_module
        self._entry_points = entry_points_fn if entry_points_fn is not None else entry_points

    def inspect_catalog(self, catalog_path: str | Path) -> ProviderLoadReport:
        catalog = self._read_catalog(catalog_path)
        providers = tuple(
            ProviderInspection(
                provider_id=registration.metadata.provider_id,
                status="ready",
                source=ProviderSource.CATALOG.value,
                metadata=registration.metadata.model_dump(mode="json", by_alias=True),
            )
            for registration in catalog.providers
        )
        return ProviderLoadReport(providers=providers)

    def load_catalog(self, catalog_path: str | Path) -> ProviderLoadReport:
        catalog = self._read_catalog(catalog_path)
        providers: list[ProviderInspection] = []
        loaded: list[str] = []
        failures: list[ProviderLoadFailure] = []
        for registration in catalog.providers:
            provider_id = registration.metadata.provider_id
            self._validate_before_load(registration)
            try:
                runtime = self._load_registration_runtime(registration)
                self.registry.register(registration, _factory_for(runtime))
            except Exception as exc:
                failure = self._failure(provider_id, exc)
                failures.append(failure)
                providers.append(
                    ProviderInspection(
                        provider_id=provider_id,
                        status="failed",
                        source=ProviderSource.CATALOG.value,
                        metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                        error=failure,
                    )
                )
                continue
            loaded.append(provider_id)
            providers.append(
                ProviderInspection(
                    provider_id=provider_id,
                    status="loaded",
                    source=ProviderSource.CATALOG.value,
                    metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                )
            )
        return ProviderLoadReport(
            providers=tuple(providers),
            loaded=tuple(loaded),
            failures=tuple(failures),
        )

    def inspect_entry_points(self, provider_ids: Iterable[str] = ()) -> ProviderLoadReport:
        selected = set(provider_ids)
        registrations: list[ProviderRegistration] = []
        for entry_point in self._metadata_entry_points():
            if selected and entry_point.name not in selected:
                continue
            registrations.append(self._registration_from_metadata_entry_point(entry_point))
        return ProviderLoadReport(
            providers=tuple(
                ProviderInspection(
                    provider_id=registration.metadata.provider_id,
                    status="ready",
                    source=ProviderSource.ENTRY_POINT.value,
                    metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                )
                for registration in registrations
            )
        )

    def load_entry_points(self, provider_ids: Iterable[str] = ()) -> ProviderLoadReport:
        registrations = tuple(
            self._registration_from_metadata_entry_point(entry_point)
            for entry_point in self._metadata_entry_points()
            if not provider_ids or entry_point.name in set(provider_ids)
        )
        if not registrations:
            return ProviderLoadReport()
        implementations = {
            entry_point.name: entry_point
            for entry_point in self._entry_points(group=IMPLEMENTATION_ENTRY_POINT_GROUP)
        }
        providers: list[ProviderInspection] = []
        loaded: list[str] = []
        failures: list[ProviderLoadFailure] = []
        for registration in registrations:
            provider_id = registration.metadata.provider_id
            self._validate_before_load(registration)
            try:
                implementation = implementations.get(provider_id)
                if implementation is None:
                    raise ProviderLoadError(
                        "provider_implementation_missing",
                        f"entry point {provider_id!r} has no "
                        f"{IMPLEMENTATION_ENTRY_POINT_GROUP!r} registration",
                    )
                runtime = self._materialize(implementation.load(), registration.implementation)
                self.registry.register(registration, _factory_for(runtime))
            except Exception as exc:
                failure = self._failure(provider_id, exc)
                failures.append(failure)
                providers.append(
                    ProviderInspection(
                        provider_id=provider_id,
                        status="failed",
                        source=ProviderSource.ENTRY_POINT.value,
                        metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                        error=failure,
                    )
                )
                continue
            loaded.append(provider_id)
            providers.append(
                ProviderInspection(
                    provider_id=provider_id,
                    status="loaded",
                    source=ProviderSource.ENTRY_POINT.value,
                    metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                )
            )
        return ProviderLoadReport(
            providers=tuple(providers),
            loaded=tuple(loaded),
            failures=tuple(failures),
        )

    def _read_catalog(self, catalog_path: str | Path) -> ProviderCatalog:
        path = Path(catalog_path)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            message = f"cannot read provider catalog {path}: {exc}"
            raise ProviderLoadError("catalog_invalid", message) from exc
        try:
            return ProviderCatalog.model_validate(document)
        except ValidationError as exc:
            message = f"invalid provider catalog {path}: {exc}"
            raise ProviderLoadError("catalog_invalid", message) from exc

    def _metadata_entry_points(self) -> tuple[Any, ...]:
        return tuple(self._entry_points(group=METADATA_ENTRY_POINT_GROUP))

    def _registration_from_metadata_entry_point(self, entry_point: Any) -> ProviderRegistration:
        try:
            value = entry_point.load()
            metadata = (
                value
                if isinstance(value, ProviderMetadata)
                else ProviderMetadata.model_validate(value)
            ).model_copy(update={"source": ProviderSource.ENTRY_POINT})
        except (ValidationError, ValueError, TypeError, AttributeError, ImportError) as exc:
            raise ProviderLoadError(
                "provider_metadata_invalid",
                f"entry point {entry_point.name!r} has invalid metadata: {exc}",
            ) from exc
        if metadata.provider_id != entry_point.name:
            raise ProviderLoadError(
                "provider_metadata_invalid",
                f"entry point {entry_point.name!r} declares provider {metadata.provider_id!r}",
            )
        ensure_api_compatible(metadata)
        return ProviderRegistration(
            metadata=metadata,
            implementation=ImplementationReference(
                kind=ImplementationKind.ENTRY_POINT,
                target=entry_point.name,
                factory=False,
            ),
        )

    def _validate_before_load(self, registration: ProviderRegistration) -> None:
        ensure_api_compatible(registration.metadata)
        ensure_permissions(registration.metadata, self.allowed_permissions)

    def _load_registration_runtime(self, registration: ProviderRegistration) -> object:
        implementation = registration.implementation
        if implementation.kind is ImplementationKind.IMPORT:
            module_name, attribute = implementation.target.split(":", 1)
            value = getattr(self._import_module(module_name), attribute)
            return self._materialize(value, implementation)
        entry_point = next(
            (
                candidate
                for candidate in self._entry_points(group=IMPLEMENTATION_ENTRY_POINT_GROUP)
                if candidate.name == implementation.target
            ),
            None,
        )
        if entry_point is None:
            raise ProviderLoadError(
                "provider_implementation_missing",
                f"entry point {implementation.target!r} is not installed",
            )
        return self._materialize(entry_point.load(), implementation)

    @staticmethod
    def _materialize(value: object, implementation: Any) -> object:
        if not implementation.factory:
            return value
        if not callable(value):
            raise ProviderLoadError(
                "provider_factory_invalid",
                f"implementation {implementation.target!r} is not callable",
            )
        return value()

    @staticmethod
    def _failure(provider_id: str, exc: Exception) -> ProviderLoadFailure:
        if isinstance(exc, ProviderError):
            return ProviderLoadFailure(provider_id, exc.code, str(exc))
        return ProviderLoadFailure(
            provider_id,
            "provider_load_failed",
            f"{type(exc).__name__}: {exc}",
        )
