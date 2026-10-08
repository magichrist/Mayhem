"""Authoring a provider declaration — plan 17 Phase 3, plus the gap-74 display.

What an SDK is for, stated first because it is the whole constraint
--------------------------------------------------------------------
This module makes writing a declaration **convenient**. It does not make a
declaration worth more. Those are different properties and the second one is the
dangerous one, because an SDK that reads as a trust boundary is worse than no
SDK: an author who believes ``rust_declaration(...)`` vouched for their code will
ship it without reading the loader, and the person who installs it will believe
the vendor did.

So every value this module produces says the same thing, in
:data:`SDK_UNVERIFIED_NOTICE`, and says it *structurally*:

* :class:`AuthoredArtifact` has **no field for a signature** — not an empty one,
  not a nullable one. There is nowhere to put a signature even if some future
  change wanted to, so an artifact cannot become the thing that makes a reader
  believe one was checked. This is the same structural guarantee
  ``test_declaration_declares_no_signature_field`` pins on the wire contract, and
  it is why :attr:`AuthoredArtifact.authenticity` is an enum with one member
  rather than a boolean.
* :attr:`AuthoredArtifact.authenticity` is
  :data:`ArtifactAuthenticity.DECLARED_UNVERIFIED` and its validator **refuses**
  anything else, for the reason
  :attr:`mayhem.domain.lowlevel_report.PrimitiveExplanation.mechanism_applied`
  refuses ``True``: promoting it requires
  :data:`mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` to become
  ``True``, which requires a trust store and a key, neither of which exists here.
* Building through an SDK confers exactly three things, and :func:`author_artifact`
  enumerates them as :data:`SDK_CONFERRED` / :data:`SDK_NOT_CONFERRED` so a doc,
  a CLI and this docstring cannot drift apart: a declaration that validates
  against the v1 grammar, a byte-stable canonical form to hash, and a *named*
  author-supplied identity to show an operator.

Three front-ends, one contract
------------------------------
The plan names Rust, Python and Go. What ships in this build:

==============  =========================================================
``PYTHON``      Real. Decorators, below. Authored and shipped.
``RUST``        :func:`rust_declaration` — reads a Rust-shaped manifest
                (``provider_id``, ``fault_declarations``, …) and normalises
                it through :data:`RUST_FIELD_NAMES`.
``GO``          :func:`go_declaration` — reads a Go-shaped struct literal
                (``ProviderID``, ``FaultDeclarations``, …) and normalises it
                through :data:`GO_FIELD_TAGS`.
==============  =========================================================

:data:`RUST_SDK_SHIPPED` and :data:`GO_SDK_SHIPPED` are ``False``, and that is
stated rather than implied: **no ``.crate`` and no Go package is distributed by
this repository.** What exists for Rust and Go is the *wire contract* those SDKs
would generate — the field-name maps and the normalisers — plus a conformance
suite proving that the same provider authored through all three front-ends
produces a byte-identical canonical document and an identical loaded
registration. That is the part of "one protocol, three SDKs" a core can actually
check, and it is a real property: it fails the moment one front-end drops a key,
misses an acronym, or orders a set differently.

Saying so is the point. A Rust-shaped manifest reader shipped as "the Rust SDK"
with nothing marking it incomplete would be the exact overclaim this module
exists to prevent, and
``tests/unit/test_provider_sdk.py::TestTheOverclaimScan`` is what notices.

The permission display (gap 74)
-------------------------------
:func:`permission_display` answers *what this extension CAN and CANNOT do* as
data, with two properties a reader needs and almost nothing else has:

* **CAN and CANNOT are separated by the grant**, so a declared permission the
  operator has not granted appears under ``cannot_do`` with the reason, rather
  than appearing at all and being missed.
* **CAN is empty until someone approves.** :attr:`PermissionDisplay.approved` is
  ``False`` on a freshly-built display and :func:`approve_permission_display` is
  the only thing that sets it. This is the "requiring explicit approval before
  install or execution" half of gap 74, expressed as a type rather than as a
  checkbox.

Every ``can_do`` line also carries
:data:`~mayhem.providers.sandbox.SANDBOX_NOT_ENFORCED_NOTICE`, because being
*allowed* a permission in this build is not the same as being *confined* in it:
no seccomp filter, AppArmor profile, SELinux label or container is applied
anywhere in this repository.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from mayhem.domain.provider import (
    PROVIDER_DECLARATION_SCHEMA_VERSION,
    CapabilityDescriptor,
    CompatibilityBounds,
    EvidenceMapping,
    EvidenceSchema,
    FaultDeclaration,
    ImplementationKind,
    ImplementationReference,
    ParameterDeclaration,
    PermissionSet,
    ProviderError,
    ProviderMetadata,
    ProviderMutation,
    ProviderPermission,
    ProviderRegistration,
    ProviderSource,
    TargetLocator,
)
from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED
from mayhem.providers.sandbox import SANDBOX_NOT_ENFORCED_NOTICE

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

__all__ = [
    "FRONT_ENTRIES",
    "GO_FIELD_TAGS",
    "GO_SDK_SHIPPED",
    "PERMISSION_CONSEQUENCE",
    "PYTHON_SDK_SHIPPED",
    "RUST_FIELD_NAMES",
    "RUST_SDK_SHIPPED",
    "SDK_CONFERRED",
    "SDK_LANGUAGES",
    "SDK_NOT_CONFERRED",
    "SDK_UNVERIFIED_NOTICE",
    "ArtifactAuthenticity",
    "AuthoredArtifact",
    "ConformanceReport",
    "LanguageConformance",
    "PermissionDecision",
    "PermissionDisplay",
    "PermissionLine",
    "ProviderBuilder",
    "SdkBuildError",
    "SdkLanguage",
    "approve_permission_display",
    "author_artifact",
    "canonical_json",
    "conformance_report",
    "describe_permission_display",
    "go_declaration",
    "permission_display",
    "python_declaration",
    "rust_declaration",
    "sdk_identifiers",
]


#: The sentence every artifact and every permission display carries.
#:
#: A module constant for the reason
#: :data:`mayhem.providers.pack.SIGNATURE_TRUST_NOTICE` and
#: :data:`mayhem.providers.sandbox.SANDBOX_NOT_ENFORCED_NOTICE` are both module
#: constants: a surface that renders an SDK artifact must be able to render the
#: caveat next to it without having to remember the wording. Two clauses, and the
#: order matters — what the SDK *does* first, then what it does not.
SDK_UNVERIFIED_NOTICE: Final[str] = (
    "mayhem's SDK emits a declaration schema; it does not attest to the code that "
    "produced one. An SDK-built artifact is a claim of authorship by whoever ran the "
    "SDK, and mayhem verifies no signature over it in this build: "
    "mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED is False. Read a built "
    "artifact as 'this is what its author says it is', never as 'mayhem has checked "
    "who wrote it'."
)

#: What building a declaration through an SDK actually confers.
#:
#: Three items, all of them things about the *document*. None of them is a
#: statement about the code, the author's identity, or the artifact's integrity,
#: and the list is a constant so a doc cannot quietly add a fourth.
SDK_CONFERRED: Final[tuple[str, ...]] = (
    "the declaration validates against the mayhem.provider-declaration/v1 grammar",
    "the canonical form is byte-stable and safe to hash",
    "the author-supplied provider id and version are carried through unaltered, so an "
    "operator can see and compare them",
)

#: What it does not. Written next to :data:`SDK_CONFERRED` rather than in a
#: docstring so a surface that prints one has the other in the same import.
SDK_NOT_CONFERRED: Final[tuple[str, ...]] = (
    "that the provider's code is safe, correct, or free of malice",
    "that the provider id, version or homepage identifies a real party",
    "that the artifact was not modified between publication and installation",
    "that the provider will keep working after its author stops maintaining it",
)


class SdkLanguage(StrEnum):
    """The three authoring front-ends this plan names."""

    PYTHON = "python"
    RUST = "rust"
    GO = "go"


#: A Python SDK **is** shipped: the decorators in this module.
PYTHON_SDK_SHIPPED: Final[bool] = True

#: No Rust crate is distributed by this repository. What exists is the wire
#: contract a Rust derive macro would emit (:data:`RUST_FIELD_NAMES`) and the
#: normaliser that reads it. Stated as a constant rather than left to be inferred
#: from the absence of a ``Cargo.toml``, because "we have a Rust SDK" and "we
#: have the Rust SDK's field map" are different sentences.
RUST_SDK_SHIPPED: Final[bool] = False

#: Likewise for Go: no ``go.mod``, no Go package. :data:`GO_FIELD_TAGS` plus a
#: normaliser.
GO_SDK_SHIPPED: Final[bool] = False

#: The languages an SDK front-end exists for, in the plan's order.
SDK_LANGUAGES: Final[tuple[SdkLanguage, ...]] = (
    SdkLanguage.PYTHON,
    SdkLanguage.RUST,
    SdkLanguage.GO,
)


class ArtifactAuthenticity(StrEnum):
    """What mayhem knows about who wrote a built artifact.

    One member, and that is the design rather than an oversight. The alternative
    shapes all fail:

    * a ``verified: bool`` field invites ``True``, and setting it honestly
      requires the mechanism;
    * an ``UNVERIFIED`` member beside a ``VERIFIED`` one invites the second
      member being *written* by a caller, since an enum cannot be closed against
      a value the caller holds.

    With a single member and a validator that refuses anything else, the only way
    to construct an artifact that says something stronger is to change this
    module — which is the point. Changing it should require changing
    :data:`mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED`, and a test
    in this module's suite asserts the two still agree.
    """

    DECLARED_UNVERIFIED = "declared_unverified"


class SdkBuildError(ProviderError):
    """An SDK manifest that is not a declaration this core can read.

    A :class:`~mayhem.domain.provider.ProviderError` so it carries a ``code`` and
    is caught by the same ``except`` as every other provider refusal — an SDK
    that raises its own exception hierarchy would force every caller to learn a
    second vocabulary for what is, at bottom, the same failure: a provider
    declaration that does not parse.
    """


# =============================================================================
# What an SDK-built artifact is, structurally
# =============================================================================


@dataclass(frozen=True, slots=True)
class AuthoredArtifact:
    """One built declaration, and everything that is true about it.

    **There is no signature field.** Not ``signature: str = ""``, not
    ``signature: str | None = None`` — nothing. The absence is deliberate and it
    is the strongest guarantee this module can make: an artifact is not a type
    that *could* carry a signature, so no future change can set one on it and
    have a declaration, a report or a CLI render as though a signature had been
    checked. The same structural argument
    ``test_declaration_declares_no_signature_field`` makes about the wire
    contract, applied one layer out.

    Attributes:
        language: Which front-end built it.
        metadata: The validated declaration. Built *by* the SDK, not merely
            carried by it, so a caller cannot attach a hand-written metadata to
            an artifact and make the artifact's conformance claim about a
            different document.
        document: The wire document, ``by_alias=True``, so the keys are the ones
            a loader reads.
        canonical: ``document`` re-serialised with sorted keys and no
            whitespace. Three SDKs in three languages hash this, so its
            stability is a contract property, and :func:`canonical_json` is the
            single implementation.
        authenticity: Always :data:`ArtifactAuthenticity.DECLARED_UNVERIFIED`;
            the validator refuses anything else.
        notice: :data:`SDK_UNVERIFIED_NOTICE`, carried on every value so a
            renderer cannot print an artifact without the caveat available.
    """

    language: SdkLanguage
    metadata: ProviderMetadata
    document: Mapping[str, Any]
    canonical: str
    authenticity: ArtifactAuthenticity = ArtifactAuthenticity.DECLARED_UNVERIFIED
    notice: str = SDK_UNVERIFIED_NOTICE

    def __post_init__(self) -> None:
        # Widened to ``Any`` before the comparison, and that is not a typing
        # convenience: the enum has exactly one member, so a direct comparison is
        # statically vacuous and a type checker correctly reports the guard below
        # as unreachable — which would let a caller pass a value from *another*
        # enum, or a string, and reach an artifact that renders as something other
        # than what it says. The guard has to be real, so the value is treated as
        # untyped first.
        observed: Any = self.authenticity
        if observed is not ArtifactAuthenticity.DECLARED_UNVERIFIED:
            msg = (
                "an SDK artifact's authenticity cannot be anything but "
                f"{ArtifactAuthenticity.DECLARED_UNVERIFIED.value!r} while "
                "mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED is False; "
                "promoting it requires a trust store and a key, not a flag"
            )
            raise SdkBuildError("sdk_artifact_authenticity_refused", msg)
        if self.canonical != canonical_json(self.document):
            msg = (
                f"the canonical form of the {self.language.value} artifact does not match "
                "its own document; the canonicaliser is the only implementation and it "
                "must be the one that ran"
            )
            raise SdkBuildError("sdk_artifact_canonical_mismatch", msg)

    @property
    def schema_version(self) -> str:
        return PROVIDER_DECLARATION_SCHEMA_VERSION

    @property
    def provider_id(self) -> str:
        return self.metadata.provider_id

    @property
    def version(self) -> str:
        """The author's declared version — a claim, not an authenticated fact."""
        return self.metadata.version

    def registration(self, *, implementation: str | None = None) -> ProviderRegistration:
        """A :class:`ProviderRegistration` for this artifact.

        ``implementation`` defaults to ``module:attribute``, the shape an
        in-process provider is loaded through. There is no way to declare an
        artifact that claims to be something else: the implementation reference
        is *derived* from the artifact rather than authored beside it, because a
        registration whose implementation and metadata were written by different
        calls is exactly the split :meth:`ProviderLoader._register_runtime` exists
        to catch, and it is better not to be able to build one.
        """
        target = implementation or f"{self.metadata.provider_id}:build"
        return ProviderRegistration(
            metadata=self.metadata,
            implementation=ImplementationReference(
                kind=ImplementationKind.IMPORT,
                target=target,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language.value,
            "schema_version": self.schema_version,
            "provider_id": self.metadata.provider_id,
            "version": self.metadata.version,
            "permissions": sorted(p.value for p in self.metadata.permissions),
            "fault_ids": sorted(self.metadata.declared_fault_ids),
            "authenticity": self.authenticity.value,
            "signature_verification_implemented": SIGNATURE_VERIFICATION_IMPLEMENTED,
            "conferred": list(SDK_CONFERRED),
            "not_conferred": list(SDK_NOT_CONFERRED),
            "notice": self.notice,
        }


def canonical_json(document: Mapping[str, Any]) -> str:
    """The one canonical serialisation a provider declaration has.

    Sorted keys, no whitespace, UTF-8 text. Every SDK front-end routes through
    this, so "the Rust artifact and the Go artifact are the same bytes" is a fact
    about this function rather than about three independent formatters that
    happen to agree today.
    """
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# =============================================================================
# The Python front-end
# =============================================================================


class ProviderBuilder:
    """Author one provider declaration by calling methods, then :meth:`build`.

    This is the reference front-end. The Rust and Go ones normalise their input
    shape and then build through exactly this class, which is why the three
    artifacts are identical *structurally* rather than by three authors writing
    three careful tests: there is one builder, and the other two are front-ends
    onto it.

    Every method returns ``self`` so a declaration reads as one statement block,
    and every method validates its own arguments through the domain model rather
    than through a second set of rules here — a builder-side check that disagreed
    with :class:`~mayhem.domain.provider.ProviderMetadata`'s would be a check
    that fires on one language's front-end and not another's.
    """

    def __init__(
        self,
        provider_id: str,
        *,
        name: str,
        version: str,
        description: str,
        permissions: Iterable[str | ProviderPermission] = (),
        source: ProviderSource = ProviderSource.ENTRY_POINT,
        homepage: str | None = None,
    ) -> None:
        self._metadata: dict[str, Any] = {
            "providerId": provider_id,
            "name": name,
            "version": version,
            "description": description,
            "permissions": list(permissions),
            "source": source,
            "homepage": homepage,
        }
        self._capabilities: list[dict[str, Any]] = []
        self._faults: list[dict[str, Any]] = []
        self._locators: list[dict[str, Any]] = []
        self._mappings: list[dict[str, Any]] = []
        self._evidence: dict[str, Any] = {}
        self._compatibility: dict[str, Any] = {}

    # -- parts ------------------------------------------------------------------

    def capability(
        self,
        capability_id: str,
        *,
        summary: str,
        required_permissions: Iterable[str | ProviderPermission] = (),
        mutates_targets: bool = False,
        compensable: bool = False,
    ) -> ProviderBuilder:
        """Declare a capability the provider publishes."""
        self._capabilities.append(
            {
                "id": capability_id,
                "summary": summary,
                "requiredPermissions": list(required_permissions),
                "mutates_targets": mutates_targets,
                "compensable": compensable,
            }
        )
        return self

    def locator(
        self,
        locator_id: str,
        *,
        kind: str,
        required_permissions: Iterable[str | ProviderPermission] = (
            ProviderPermission.TARGET_READ,
        ),
        selector_schema: Mapping[str, Any] | None = None,
    ) -> ProviderBuilder:
        """Declare how the provider finds a target."""
        self._locators.append(
            {
                "id": locator_id,
                "kind": kind,
                "requiredPermissions": list(required_permissions),
                "selectorSchema": dict(selector_schema or {}),
            }
        )
        return self

    def fault(
        self,
        fault_id: str,
        *,
        capability: str,
        summary: str,
        required_permissions: Iterable[str | ProviderPermission] = (),
        target_locator_ids: Iterable[str] = (),
        mutation: ProviderMutation = ProviderMutation.READ_ONLY,
        reversible: bool = True,
        risk: str = "medium",
        parameters: Mapping[str, str] | None = None,
        parameter_grammar: Iterable[Mapping[str, Any]] = (),
    ) -> ProviderBuilder:
        """Declare one fault, and — critically — that it *is* or is not mutating.

        Nothing here infers the mutation character from the permissions passed in.
        A builder that inferred it would let ``mutation="mutating"`` and an empty
        permission list produce a declaration that says it changes a target and
        requires nothing to do it; the domain validator refuses that, and the
        refusal is the same one a Rust or Go author gets.
        """
        self._faults.append(
            {
                "id": fault_id,
                "capability": capability,
                "summary": summary,
                "requiredPermissions": list(required_permissions),
                "target_locator_ids": list(target_locator_ids),
                "mutation": ProviderMutation(mutation).value,
                "reversible": reversible,
                "risk": risk,
                "parameters": dict(parameters or {}),
                "parameterGrammar": [dict(entry) for entry in parameter_grammar],
            }
        )
        return self

    def parameter(
        self,
        name: str,
        *,
        kind: str = "string",
        required: bool = True,
        default: str | None = None,
        summary: str = "",
        minimum: float | None = None,
        maximum: float | None = None,
        choices: Sequence[str] = (),
        pattern: str | None = None,
    ) -> dict[str, Any]:
        """One entry of a fault's parameter grammar.

        Returns the mapping rather than mutating the builder, so a grammar entry
        can be written inline inside a :meth:`fault` call and reused elsewhere —
        which is how a real provider declares one parameter three faults share.
        """
        return {
            "name": name,
            "kind": kind,
            "required": required,
            "default": default,
            "summary": summary,
            "minimum": minimum,
            "maximum": maximum,
            "choices": list(choices),
            "pattern": pattern,
        }

    def evidence_schema(
        self,
        name: str,
        version: str,
        *,
        fields: Sequence[str] | None = None,
    ) -> ProviderBuilder:
        """Publish the evidence schema this provider's faults write.

        ``fields=None`` means *the contract's default field set*, which is what a
        provider that records the standard columns wants. Passing an **empty**
        sequence is not the same request: it is a declaration that publishes a
        schema with no fields, and :class:`~mayhem.domain.provider.EvidenceSchema`
        refuses it. Both readings have to be reachable, so an empty tuple is sent
        as written rather than silently replaced with the default.
        """
        self._evidence = {
            "name": name,
            "version": version,
            **({"fields": list(fields)} if fields is not None else {}),
        }
        return self

    def evidence_mapping(self, fault_id: str) -> ProviderBuilder:
        """Say that *fault_id* writes the published evidence schema.

        No schema name and no version parameters: they are the published ones,
        and a mapping that could name a different schema is a second place for
        the schema to drift. This mirrors
        :class:`~mayhem.domain.provider.EvidenceMapping`'s own design.
        """
        self._mappings.append({"fault_id": fault_id})
        return self

    def compatibility(
        self,
        *,
        api_majors: Sequence[str] | None = None,
        mayhem_min: str = "0.0.0",
        mayhem_max: str | None = None,
        engines: Sequence[str] = (),
    ) -> ProviderBuilder:
        """State the mayhem window this provider was written against."""
        self._compatibility = {
            "apiMajors": list(api_majors) if api_majors is not None else None,
            "mayhemMin": mayhem_min,
            "mayhemMax": mayhem_max,
            "engines": list(engines),
        }
        return self

    # -- the result -------------------------------------------------------------

    def build(self) -> ProviderMetadata:
        """Validate and return the declaration.

        Raises:
            SdkBuildError: When no evidence schema was published, which is the
                one part a declaration cannot supply a default for — it is a
                required field, and a default would mean every provider wrote the
                same evidence schema without saying so.
            pydantic.ValidationError: For everything else, straight from the
                domain model. Deliberately not wrapped: an SDK that re-typed the
                domain's errors would be a second, weaker validator.
        """
        if not self._evidence:
            msg = (
                f"provider {self._metadata['providerId']!r} declares no evidence schema; "
                "mayhem.providers.loader refuses a declaration whose evidence coverage it "
                "cannot check, so the SDK refuses to build one that has none"
            )
            raise SdkBuildError("sdk_evidence_schema_required", msg)
        compat = self._compatibility
        document: dict[str, Any] = {
            **self._metadata,
            "capabilities": self._capabilities,
            "faultDeclarations": self._faults,
            "targetLocators": self._locators,
            "evidenceSchema": self._evidence,
            "evidenceMappings": [
                {
                    "fault_id": mapping["fault_id"],
                    "schema_name": self._evidence["name"],
                    "schema_version": self._evidence["version"],
                }
                for mapping in self._mappings
            ],
        }
        if compat:
            document["compatibility"] = {
                key: value for key, value in compat.items() if value is not None
            }
        try:
            return ProviderMetadata.model_validate(document)
        except Exception as exc:
            raise SdkBuildError(
                "sdk_declaration_invalid",
                f"the SDK built a declaration mayhem cannot read: {exc}",
            ) from exc


#: The entry points each language's SDK entry point calls. One per language, so
#: a conformance report can name the callable rather than guessing which function
#: built the artifact it is comparing.
FRONT_ENTRIES: Final[Mapping[SdkLanguage, str]] = MappingProxyType(
    {
        SdkLanguage.PYTHON: "mayhem.providers.sdk.python_declaration",
        SdkLanguage.RUST: "mayhem.providers.sdk.rust_declaration",
        SdkLanguage.GO: "mayhem.providers.sdk.go_declaration",
    }
)


def python_declaration(builder: ProviderBuilder) -> AuthoredArtifact:
    """The Python front-end: hand it a :class:`ProviderBuilder`."""
    return _artifact(SdkLanguage.PYTHON, builder.build())


# =============================================================================
# The Rust and Go front-ends: manifest normalisation
# =============================================================================

#: Rust struct field name -> wire key.
#:
#: Written out by hand for the same reason
#: :data:`~mayhem.domain.provider.PROVIDER_DECLARATION_WIRE_FIELDS` is: deriving
#: it would make the guard tautological. This is what a
#: ``#[derive(Serialize)] #[serde(rename_all = "camelCase")]`` struct emits, and
#: it is a **frozen contract**: an unknown key here is refused rather than passed
#: through, because a Rust author who misspells ``providerId`` must get a
#: ``rust_unknown_field`` refusal at authoring time rather than a declaration
#: that silently drops its own identity.
#:
#: Two conventions meet inside one declaration. :class:`ProviderMetadata` and
#: three of its nested models declare ``camelCase`` aliases, so their Rust fields
#: are snake_case and serialise to camelCase; ``ParameterDeclaration``,
#: ``EvidenceSchema`` and ``EvidenceMapping`` declare **no** aliases, so their
#: wire keys stay snake_case all the way through. That mixed convention inside a
#: single document is exactly what a hand-rolled serialiser gets wrong, which is
#: why it is written out rather than computed.
RUST_FIELD_NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "api_version": "apiVersion",
        "provider_id": "providerId",
        "name": "name",
        "version": "version",
        "description": "description",
        "permissions": "permissions",
        "capabilities": "capabilities",
        "fault_declarations": "faultDeclarations",
        "target_locators": "targetLocators",
        "evidence_schema": "evidenceSchema",
        "evidence_mappings": "evidenceMappings",
        "compatibility": "compatibility",
        "source": "source",
        "homepage": "homepage",
        "id": "id",
        "summary": "summary",
        "required_permissions": "requiredPermissions",
        "mutates_targets": "mutates_targets",
        "compensable": "compensable",
        "kind": "kind",
        "selector_schema": "selectorSchema",
        "capability": "capability",
        "target_locator_ids": "target_locator_ids",
        "parameters": "parameters",
        "parameter_grammar": "parameterGrammar",
        "risk": "risk",
        "mutation": "mutation",
        "reversible": "reversible",
        "required": "required",
        "default": "default",
        "minimum": "minimum",
        "maximum": "maximum",
        "choices": "choices",
        "pattern": "pattern",
        "fields": "fields",
        "fault_id": "fault_id",
        "schema_name": "schema_name",
        "schema_version": "schema_version",
        "api_majors": "apiMajors",
        "mayhem_min": "mayhemMin",
        "mayhem_max": "mayhemMax",
        "engines": "engines",
    }
)


#: Go struct field name -> wire key, via ``json:"..."`` struct tags.
#:
#: Frozen for the same reason as :data:`RUST_FIELD_NAMES`, and additionally
#: because Go's acronym convention makes the naive mapping wrong in a way the
#: compiler will not catch. ``ProviderID`` lower-cased mechanically is
#: ``providerid``; ``FaultIDs`` is ``faultids``; ``TargetLocatorIDs`` is
#: ``targetlocatorids``. Only an explicit tag map gets these right, so the map is
#: the contract and the acronyms are the reason it is written out rather than
#: computed. Every key a Rust struct can spell is present here too, so a Go
#: manifest missing a tag is a refusal rather than a silently-dropped field.
GO_FIELD_TAGS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "APIVersion": "apiVersion",
        "ProviderID": "providerId",
        "Name": "name",
        "Version": "version",
        "Description": "description",
        "Permissions": "permissions",
        "Capabilities": "capabilities",
        "FaultDeclarations": "faultDeclarations",
        "TargetLocators": "targetLocators",
        "EvidenceSchema": "evidenceSchema",
        "EvidenceMappings": "evidenceMappings",
        "Compatibility": "compatibility",
        "Source": "source",
        "Homepage": "homepage",
        "ID": "id",
        "Summary": "summary",
        "RequiredPermissions": "requiredPermissions",
        "MutatesTargets": "mutates_targets",
        "Compensable": "compensable",
        "Kind": "kind",
        "SelectorSchema": "selectorSchema",
        "Capability": "capability",
        "TargetLocatorIDs": "target_locator_ids",
        "Parameters": "parameters",
        "ParameterGrammar": "parameterGrammar",
        "Risk": "risk",
        "Mutation": "mutation",
        "Reversible": "reversible",
        "Required": "required",
        "Default": "default",
        "Minimum": "minimum",
        "Maximum": "maximum",
        "Choices": "choices",
        "Pattern": "pattern",
        "Fields": "fields",
        "FaultID": "fault_id",
        "SchemaName": "schema_name",
        "SchemaVersion": "schema_version",
        "APIMajors": "apiMajors",
        "MayhemMin": "mayhemMin",
        "MayhemMax": "mayhemMax",
        "Engines": "engines",
    }
)


def _rename(
    value: Any,
    table: Mapping[str, str],
    language: SdkLanguage,
    path: str,
) -> Any:
    """Recursively rename *value*'s keys through *table*.

    Pure, total over the shapes a declaration contains (mappings, lists of
    mappings, and lists of scalars for the tuple-valued fields), and **refusing**
    an unknown key rather than passing it through. A key that reaches the wire
    unnamed is a declaration whose author believes a field was included when it
    was not, which is the failure mode a derive macro exists to prevent and the
    one thing a normaliser must not reintroduce.
    """
    if isinstance(value, Mapping):
        renamed: dict[str, Any] = {}
        for key, nested in value.items():
            if key in table:
                wire_key = table[key]
            else:
                msg = (
                    f"{language.value} manifest field {key!r} at {path} has no wire name; "
                    f"{FRONT_ENTRIES[language]} refuses it rather than dropping it, because a "
                    f"field that vanishes on the way to the wire is a declaration that "
                    f"silently says less than its author wrote. Known fields: "
                    f"{sorted(table)}"
                )
                raise SdkBuildError(f"{language.value}_unknown_field", msg)
            renamed[wire_key] = _rename(nested, table, language, f"{path}.{wire_key}")
        return renamed
    if isinstance(value, (list, tuple)):
        return [_rename(item, table, language, f"{path}[]") for item in value]
    return value


def _build_from_manifest(
    manifest: Mapping[str, Any],
    table: Mapping[str, str],
    language: SdkLanguage,
) -> ProviderMetadata:
    """Normalise a language-shaped manifest, then build it like any other.

    The normalisation is the only per-language code. Everything after it — the
    builder, the grammar, the evidence mapping, the canonical form — is shared,
    which is what makes the cross-SDK conformance claim checkable rather than
    aspirational.
    """
    document = _rename(manifest, table, language, language.value)
    builder = ProviderBuilder(
        str(document.get("providerId", "")),
        name=str(document.get("name", "")),
        version=str(document.get("version", "")),
        description=str(document.get("description", "")),
        permissions=document.get("permissions", ()),
        source=ProviderSource(str(document.get("source", ProviderSource.ENTRY_POINT.value))),
        homepage=document.get("homepage"),
    )
    for capability in document.get("capabilities", ()):
        builder.capability(
            capability["id"],
            summary=capability["summary"],
            required_permissions=capability.get("requiredPermissions", ()),
            mutates_targets=bool(capability.get("mutates_targets", False)),
            compensable=bool(capability.get("compensable", False)),
        )
    for locator in document.get("targetLocators", ()):
        builder.locator(
            locator["id"],
            kind=locator["kind"],
            required_permissions=locator.get("requiredPermissions", ()),
            selector_schema=locator.get("selectorSchema"),
        )
    for fault in document.get("faultDeclarations", ()):
        builder.fault(
            fault["id"],
            capability=fault["capability"],
            summary=fault["summary"],
            required_permissions=fault.get("requiredPermissions", ()),
            target_locator_ids=fault.get("target_locator_ids", ()),
            mutation=ProviderMutation(str(fault.get("mutation", "read_only"))),
            reversible=bool(fault.get("reversible", True)),
            risk=str(fault.get("risk", "medium")),
            parameters=fault.get("parameters"),
            parameter_grammar=tuple(fault.get("parameterGrammar", ())),
        )
    schema = document.get("evidenceSchema")
    if schema:
        builder.evidence_schema(
            schema["name"],
            schema["version"],
            fields=tuple(schema["fields"]) if "fields" in schema else None,
        )
    for mapping in document.get("evidenceMappings", ()):
        builder.evidence_mapping(mapping["fault_id"])
    compat = document.get("compatibility")
    if compat:
        builder.compatibility(
            api_majors=tuple(compat["apiMajors"]) if compat.get("apiMajors") else None,
            mayhem_min=str(compat.get("mayhemMin", "0.0.0")),
            mayhem_max=compat.get("mayhemMax"),
            engines=tuple(compat.get("engines", ())),
        )
    return builder.build()


def rust_declaration(manifest: Mapping[str, Any]) -> AuthoredArtifact:
    """The Rust front-end: read a Rust-shaped manifest.

    ``manifest`` is what a ``ProviderManifest`` struct literal looks like before
    its derive macro serialises it: ``provider_id``, ``fault_declarations``,
    ``required_permissions``, and so on, per :data:`RUST_FIELD_NAMES`.

    What this is **not**: a Rust crate. :data:`RUST_SDK_SHIPPED` is ``False`` and
    no ``.crate`` is built or shipped by this repository. What is shipped is the
    contract a Rust derive macro must implement plus the reader that checks a
    manifest against it — which is the half of an SDK that can be wrong in a way
    a compiler would not catch.
    """
    return _artifact(
        SdkLanguage.RUST,
        _build_from_manifest(manifest, RUST_FIELD_NAMES, SdkLanguage.RUST),
    )


def go_declaration(manifest: Mapping[str, Any]) -> AuthoredArtifact:
    """The Go front-end: read a Go-shaped struct literal.

    ``manifest`` is what a ``ProviderManifest`` Go struct literal looks like
    before its ``json:`` tags are applied: ``ProviderID``, ``FaultDeclarations``,
    ``RequiredPermissions``, and so on, per :data:`GO_FIELD_TAGS`.

    What this is **not**: a Go package. :data:`GO_SDK_SHIPPED` is ``False`` and no
    ``go.mod`` exists in this repository. See :func:`rust_declaration` for the
    same argument about the Rust side.
    """
    return _artifact(
        SdkLanguage.GO,
        _build_from_manifest(manifest, GO_FIELD_TAGS, SdkLanguage.GO),
    )


def _artifact(language: SdkLanguage, metadata: ProviderMetadata) -> AuthoredArtifact:
    """Build the artifact, deriving its document and canonical form from *metadata*.

    Both are *derived*, never supplied. A caller that could pass its own
    ``document`` could attach a document that does not match the metadata, and
    the artifact's whole claim is that the two agree.
    """
    document = metadata.model_dump(mode="json", by_alias=True)
    return AuthoredArtifact(
        language=language,
        metadata=metadata,
        document=document,
        canonical=canonical_json(document),
    )


def author_artifact(
    language: SdkLanguage,
    metadata: ProviderMetadata,
) -> AuthoredArtifact:
    """Wrap a validated declaration as an artifact for *language*.

    The single place an :class:`AuthoredArtifact` is constructed, and it takes
    only what an author can honestly supply: which front-end they used and the
    declaration itself. The document and the canonical form are derived here
    rather than passed in, because a caller who could supply its own document
    could attach a document that does not match the metadata — and the artifact's
    entire claim is that the two agree.

    Public rather than private because a third-party front-end (somebody's own
    ``.crate``, once one exists) must be able to produce a conforming artifact
    without reimplementing the derivation and without a way to produce a
    non-conforming one.
    """
    return _artifact(language, metadata)


# =============================================================================
# Cross-SDK conformance
# =============================================================================


@dataclass(frozen=True, slots=True)
class LanguageConformance:
    """What one language's front-end produced."""

    language: SdkLanguage
    entry_point: str
    shipped: bool
    canonical: str
    provider_id: str
    version: str
    fault_ids: tuple[str, ...]
    error: str = ""

    @property
    def built(self) -> bool:
        return not self.error

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language.value,
            "entry_point": self.entry_point,
            "shipped": self.shipped,
            "built": self.built,
            "provider_id": self.provider_id,
            "version": self.version,
            "fault_ids": list(self.fault_ids),
            "canonical_digest": _digest(self.canonical),
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    """Whether three front-ends produced the same declaration.

    :attr:`identical` is a byte comparison of the three canonical forms, and it
    is the property the plan's Phase 3 acceptance names ("identical loaded
    registrations" is the loader half of it, checked by the suite that drives a
    real :class:`~mayhem.providers.loader.ProviderLoader` through all three).

    :attr:`shipped_languages` is reported next to :attr:`languages` rather than
    folded into them, because "there are three SDK front-ends" and "three SDKs
    are installed" are different sentences and this report is the one place a
    reader will find both.
    """

    languages: tuple[LanguageConformance, ...]
    identical: bool
    shipped_languages: tuple[SdkLanguage, ...]
    notice: str = SDK_UNVERIFIED_NOTICE

    @property
    def all_built(self) -> bool:
        return all(entry.built for entry in self.languages)

    def to_dict(self) -> dict[str, Any]:
        return {
            "languages": [entry.to_dict() for entry in self.languages],
            "all_built": self.all_built,
            "identical_canonical_form": self.identical,
            "shipped_languages": [language.value for language in self.shipped_languages],
            "unshipped_languages": [
                entry.language.value for entry in self.languages if not entry.shipped
            ],
            "notice": self.notice,
        }


def _digest(canonical: str) -> str:
    """A short, stable digest of a canonical form, for report comparison only.

    Not a security digest and not named as one: the report compares the full
    canonical strings in :attr:`ConformanceReport.identical`, and this exists only
    so a printed report is readable.
    """
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


_SHIPPED: Final[Mapping[SdkLanguage, bool]] = MappingProxyType(
    {
        SdkLanguage.PYTHON: PYTHON_SDK_SHIPPED,
        SdkLanguage.RUST: RUST_SDK_SHIPPED,
        SdkLanguage.GO: GO_SDK_SHIPPED,
    }
)


def conformance_report(
    artifacts: Mapping[SdkLanguage, AuthoredArtifact],
) -> ConformanceReport:
    """Compare the canonical forms of whatever front-ends were handed artifacts.

    Total over *artifacts*: a language that produced nothing is reported as
    absent rather than skipped, because a conformance report that quietly omits
    the one front-end that could not build is a report that reads as a pass.

    A failed front-end cannot be compared, so :attr:`ConformanceReport.identical`
    is ``False`` unless every language built — "two of three agree" is not a
    conformance result, it is a coincidence.
    """
    entries = tuple(
        LanguageConformance(
            language=language,
            entry_point=FRONT_ENTRIES[language],
            shipped=_SHIPPED[language],
            canonical=artifacts[language].canonical,
            provider_id=artifacts[language].provider_id,
            version=artifacts[language].version,
            fault_ids=tuple(sorted(artifacts[language].metadata.declared_fault_ids)),
        )
        for language in SDK_LANGUAGES
        if language in artifacts
    )
    present = {entry.language for entry in entries}
    for language in SDK_LANGUAGES:
        if language not in present:
            entries = (
                *entries,
                LanguageConformance(
                    language=language,
                    entry_point=FRONT_ENTRIES[language],
                    shipped=_SHIPPED[language],
                    canonical="",
                    provider_id="",
                    version="",
                    fault_ids=(),
                    error="this front-end was not exercised by this run",
                ),
            )
    ordered = tuple(sorted(entries, key=lambda entry: entry.language.value))
    canonicls = {entry.canonical for entry in ordered if entry.built}
    identical = (
        len(ordered) == len(SDK_LANGUAGES)
        and all(entry.built for entry in ordered)
        and len(canonicls) == 1
    )
    return ConformanceReport(
        languages=ordered,
        identical=identical,
        shipped_languages=tuple(language for language in SDK_LANGUAGES if _SHIPPED[language]),
    )


# =============================================================================
# The gap-74 permission display
# =============================================================================


class PermissionDecision(StrEnum):
    """What may happen to one declared permission.

    Three members because "declared", "permitted" and "approved" are three
    different facts, and a display that collapses them is the bug gap 74 names: an
    operator sees a permission listed and cannot tell whether it is already
    happening.
    """

    #: Declared by the provider, present in the operator's grant, and approved for
    #: this install. This is the only member that means the extension *can*.
    CAN_DO = "can_do"

    #: Declared but **not** in the grant. Refused at load, every load, until the
    #: grant changes. Listed under ``cannot_do`` rather than omitted, because the
    #: point of the display is to show what was asked for.
    CANNOT_DO_NOT_GRANTED = "cannot_do_not_granted"

    #: In the grant, but the display has not been approved yet. This is gap 74's
    #: "explicit approval before install or execution": the grant is what the
    #: operator *could* allow, and approval is what they *did*.
    CANNOT_DO_NOT_APPROVED = "cannot_do_not_approved"


@dataclass(frozen=True, slots=True)
class PermissionLine:
    """One permission, what it would let the extension do, and where it stands."""

    permission: ProviderPermission
    required_by: tuple[str, ...]
    consequence: str
    decision: PermissionDecision

    @property
    def can(self) -> bool:
        return self.decision is PermissionDecision.CAN_DO

    def to_dict(self) -> dict[str, Any]:
        return {
            "permission": self.permission.value,
            "required_by": list(self.required_by),
            "consequence": self.consequence,
            "decision": self.decision.value,
            "can": self.can,
        }


#: What each permission would mean if the extension reached it. Written out as
#: data rather than derived from the enum, because "filesystem:read" is not
#: self-explanatory to the person being asked to approve it and the whole point
#: of the display is that they do not have to open the schema first.
PERMISSION_CONSEQUENCE: Final[Mapping[ProviderPermission, str]] = MappingProxyType(
    {
        ProviderPermission.TARGET_READ: ("reads the mayhem target through mayhem's own API"),
        ProviderPermission.TARGET_MUTATE: (
            "changes the target — which is why a compensating fault must exist"
        ),
        ProviderPermission.FILESYSTEM_READ: "reads paths outside the target",
        ProviderPermission.FILESYSTEM_WRITE: "writes paths outside the target",
        ProviderPermission.SUBPROCESS: "spawns processes on this host",
        ProviderPermission.NETWORK: "reaches the network from this host",
    }
)


@dataclass(frozen=True, slots=True)
class PermissionDisplay:
    """What one extension CAN and CANNOT do, and whether anyone approved it.

    :attr:`approved` is ``False`` on every freshly built display, and only
    :func:`approve_permission_display` sets it. That is gap 74's requirement —
    *explicit approval before install or execution* — expressed as a type rather
    than as a flag on a form.

    :attr:`can_do` is derived, never stored: a permission is in ``can_do`` exactly
    when its :class:`PermissionLine` says :data:`PermissionDecision.CAN_DO`, so
    the two cannot disagree.

    Every ``can_do`` line carries :attr:`sandbox_notice`, because in this build
    *allowed* is not *confined*: no seccomp filter, AppArmor profile, SELinux
    label or container is applied anywhere, so a permission here is a permission
    with nothing behind it. Omitting that from the display would make "approved"
    read as "safe".
    """

    provider_id: str
    version: str
    grant: frozenset[ProviderPermission]
    lines: tuple[PermissionLine, ...]
    approved: bool = False
    approved_by: str = ""
    approval_id: str = ""
    refusal_reason: str = ""
    sandbox_notice: str = SANDBOX_NOT_ENFORCED_NOTICE
    notice: str = SDK_UNVERIFIED_NOTICE

    @property
    def can_do(self) -> tuple[PermissionLine, ...]:
        return tuple(line for line in self.lines if line.can)

    @property
    def cannot_do(self) -> tuple[PermissionLine, ...]:
        return tuple(line for line in self.lines if not line.can)

    @property
    def requires_explicit_approval(self) -> bool:
        """Whether an approval is owed before this extension may be installed.

        ``True`` as soon as the declaration asks for *any* permission — including
        ``target:read``, which sounds harmless and is not: a provider that can
        read a target can exfiltrate what it reads, and the read is what the
        operator is being asked to permit.
        """
        return bool(self.lines)

    @property
    def installable(self) -> bool:
        """Whether the display says this install may proceed.

        Requires approval *and* an empty ``cannot_do``. A display that is approved
        while a declared permission is ungranted is still not installable, because
        approval of what was granted is not a grant of what was not.
        """
        return self.approved and not self.cannot_do

    @property
    def requested(self) -> frozenset[ProviderPermission]:
        return frozenset(line.permission for line in self.lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "version": self.version,
            "granted_permissions": sorted(permission.value for permission in self.grant),
            "requested_permissions": sorted(permission.value for permission in self.requested),
            "can_do": [line.to_dict() for line in self.can_do],
            "cannot_do": [line.to_dict() for line in self.cannot_do],
            "requires_explicit_approval": self.requires_explicit_approval,
            "approved": self.approved,
            "approved_by": self.approved_by,
            "approval_id": self.approval_id,
            "installable": self.installable,
            "refusal_reason": self.refusal_reason,
            "sandbox_notice": self.sandbox_notice,
            "notice": self.notice,
        }


def permission_display(
    metadata: ProviderMetadata,
    *,
    grant: frozenset[ProviderPermission] = frozenset(),
) -> PermissionDisplay:
    """Build the CAN / CANNOT display for one declaration.

    Every permission the declaration asks for gets a line — ``required_by``
    names the capabilities, locators and faults that asked for it, so an operator
    can see *which* part of the provider wants ``filesystem:write`` and not only
    that something does.

    Nothing here is approved. :attr:`PermissionDisplay.approved` is ``False`` on
    the value this returns, always, and that is the only state a display can be
    built in.
    """
    required_by: dict[ProviderPermission, list[str]] = {}
    for capability in metadata.capabilities:
        for permission in sorted(capability.required_permissions, key=lambda p: p.value):
            required_by.setdefault(permission, []).append(capability.id)
    for locator in metadata.target_locators:
        for permission in sorted(locator.required_permissions, key=lambda p: p.value):
            required_by.setdefault(permission, []).append(f"locator:{locator.id}")
    for fault in metadata.fault_declarations:
        for permission in sorted(fault.required_permissions, key=lambda p: p.value):
            required_by.setdefault(permission, []).append(f"fault:{fault.id}")

    lines: list[PermissionLine] = []
    for permission in sorted(required_by, key=lambda p: p.value):
        if permission not in grant:
            decision = PermissionDecision.CANNOT_DO_NOT_GRANTED
        else:
            # Not yet approved. ``permission_display`` never approves, so this
            # branch is every granted line until ``approve_permission_display``
            # runs.
            decision = PermissionDecision.CANNOT_DO_NOT_APPROVED
        lines.append(
            PermissionLine(
                permission=permission,
                required_by=tuple(sorted(required_by[permission])),
                consequence=PERMISSION_CONSEQUENCE[permission],
                decision=decision,
            )
        )
    return PermissionDisplay(
        provider_id=metadata.provider_id,
        version=metadata.version,
        grant=frozenset(grant),
        lines=tuple(lines),
        refusal_reason=(
            ""
            if not lines
            else (
                f"{metadata.provider_id} asks for "
                f"{', '.join(sorted(p.value for p in required_by))}; nothing has approved "
                "this install yet"
            )
        ),
    )


def approve_permission_display(
    display: PermissionDisplay,
    *,
    actor: str,
    approval_id: str,
) -> PermissionDisplay:
    """Approve *display* for this install, and return the approved copy.

    The one function in this module that grants anything, and it grants exactly
    one thing: that **this** declaration may reach **these** permissions **for
    this install**. It does not widen the loader's grant, it does not make the
    extension confined, and it does not touch any signature state — a display
    with nothing to approve is approved into an empty ``can_do``, which is a real
    answer rather than an error.

    Raises:
        SdkBuildError: With code ``sdk_approval_actor_blank`` for a blank actor
            and ``sdk_approval_id_blank`` for a blank approval id. Both are
            refusals rather than defaults, because an approval with nobody's name
            against it is not an approval and an approval with no id cannot be
            audited later.
    """
    if not actor.strip():
        msg = "an approval must name the actor who gave it"
        raise SdkBuildError("sdk_approval_actor_blank", msg)
    if not approval_id.strip():
        msg = (
            f"the approval of {display.provider_id!r} by {actor!r} needs an approval id, "
            "so it can be cited in evidence after the fact"
        )
        raise SdkBuildError("sdk_approval_id_blank", msg)
    return replace(
        display,
        approved=True,
        approved_by=actor,
        approval_id=approval_id,
        lines=tuple(
            replace(
                line,
                decision=(
                    line.decision
                    if line.decision is PermissionDecision.CANNOT_DO_NOT_GRANTED
                    else PermissionDecision.CAN_DO
                ),
            )
            for line in display.lines
        ),
    )


def describe_permission_display(display: PermissionDisplay) -> str:
    """Render a display as printable lines, caveat first and last.

    The two caveats are on separate lines rather than merged because they answer
    different questions: :attr:`PermissionDisplay.sandbox_notice` is about what
    mayhem applies, :data:`SDK_UNVERIFIED_NOTICE` is about what the artifact is.
    A reader who only skims will still reach both.
    """
    lines = [
        f"{display.provider_id} {display.version}",
        f"  notice: {display.notice}",
        f"  sandbox: {display.sandbox_notice}",
        f"  approved={str(display.approved).lower()}",
    ]
    if display.approved:
        lines.append(f"  approved by {display.approved_by} (id {display.approval_id})")
    for line in display.can_do:
        lines.append(
            f"  CAN     {line.permission.value}: {line.consequence} "
            f"(required by {', '.join(line.required_by)})"
        )
    for line in display.cannot_do:
        lines.append(
            f"  CANNOT  {line.permission.value}: {line.consequence} "
            f"[{line.decision.value}] (required by {', '.join(line.required_by)})"
        )
    if not display.lines:
        lines.append("  declares no permission: it can do nothing, which is the whole claim")
    if display.refusal_reason:
        lines.append(f"  refusal: {display.refusal_reason}")
    return "\n".join(lines)


# =============================================================================
# The overclaim scan's inputs
# =============================================================================


def sdk_identifiers() -> frozenset[str]:
    """Every public identifier this module's API contributes.

    Computed, not listed, so the scan in
    ``tests/unit/test_provider_sdk.py::TestTheOverclaimScan`` reads the module as
    it is rather than as it was when the test was written. Members are collected
    from the module's own namespace, so an identifier added to ``__all__`` and one
    added to a class are both covered.
    """
    module = sys.modules[__name__]
    found = set(__all__)
    found.update(FRONT_ENTRIES.values())
    found.update(SDK_CONFERRED)
    found.update(SDK_NOT_CONFERRED)
    for value in vars(module).values():
        if isinstance(value, type) and value.__module__ == module.__name__:
            found.update(value.__dict__.keys())
    return frozenset(name for name in found if not name.startswith("_"))


#: The authoring surface, re-exported from :mod:`mayhem.domain.provider`.
#:
#: An SDK author writes capability descriptors, locators, faults, parameter grammar
#: entries and evidence schemas. Importing those from the SDK rather than from the
#: domain is the difference between one import and two, and — more importantly —
#: it means the SDK's public surface *is* the wire contract's own model, so a
#: model change cannot leave the SDK exporting a stale re-definition of it.
__all__ += [
    "CapabilityDescriptor",
    "CompatibilityBounds",
    "EvidenceMapping",
    "EvidenceSchema",
    "FaultDeclaration",
    "ParameterDeclaration",
    "PermissionSet",
    "ProviderSource",
    "TargetLocator",
]
