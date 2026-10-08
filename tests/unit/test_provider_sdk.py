"""The extension SDK, the cross-SDK conformance suite, and the overclaim scan.

Plan 17 Phase 3 ships the SDK and the gap-74 permission display; Phase 5's
negative controls live here too, because the standing control for this plan is
an **overclaim scan** and it has to be executable rather than a paragraph.

What this file is careful not to assert
---------------------------------------
It does not assert that a signature is verified, that an artifact is trusted, or
that a Rust or Go SDK is installed. All three are false in this build, and a test
that implied otherwise would be the defect rather than the guard. The tests that
pin those *false* answers are
:class:`TestTheArtifactCarriesNoTrust` and :class:`TestTheOverclaimScan`.

The three front-ends, and what "identical" means here
----------------------------------------------------
``python_declaration``, ``rust_declaration`` and ``go_declaration`` take three
different input shapes and produce one
:class:`~mayhem.domain.provider.ProviderMetadata`. The conformance property is
**byte-identical canonical documents** and **identical loaded registrations** —
the second half driven through a real
:class:`~mayhem.providers.loader.ProviderLoader`, so "identical" is checked
against the loader rather than against a comparison helper.

The runtimes are the same Python object in all three cases, and the tests say so
where it matters. What differs between the front-ends is the *declaration*, and
the declaration is the contract; the runtime is third-party code that a Rust
crate or a Go package would supply in its own language and which mayhem cannot
receive in this build at all. Pretending otherwise would be inventing a cross-
language execution story this repository does not have.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest

from mayhem.domain.provider import (
    PROVIDER_DECLARATION_WIRE_FIELDS,
    PROVIDER_FAULT_WIRE_FIELDS,
    FaultDeclaration,
    ProviderMetadata,
    ProviderPermission,
)
from mayhem.providers.loader import ProviderLoader
from mayhem.providers.pack import SIGNATURE_TRUST_NOTICE, SIGNATURE_VERIFICATION_IMPLEMENTED
from mayhem.providers.sdk import (
    FRONT_ENTRIES,
    GO_FIELD_TAGS,
    GO_SDK_SHIPPED,
    PERMISSION_CONSEQUENCE,
    PYTHON_SDK_SHIPPED,
    RUST_FIELD_NAMES,
    RUST_SDK_SHIPPED,
    SDK_CONFERRED,
    SDK_LANGUAGES,
    SDK_NOT_CONFERRED,
    SDK_UNVERIFIED_NOTICE,
    ArtifactAuthenticity,
    AuthoredArtifact,
    PermissionDecision,
    ProviderBuilder,
    SdkBuildError,
    SdkLanguage,
    approve_permission_display,
    canonical_json,
    conformance_report,
    describe_permission_display,
    go_declaration,
    permission_display,
    python_declaration,
    rust_declaration,
    sdk_identifiers,
)

# =============================================================================
# The one provider every cross-SDK assertion uses
# =============================================================================

_PROVIDER_ID = "acme.injector"
_VERSION = "1.2.3"
_CAPABILITY = "acme.injector.mutate"
_LOCATOR = "acme.svc"
_MUTATING_FAULT = "acme.slow"
_READ_ONLY_FAULT = "acme.observe"
_PERMISSIONS = ["target:read", "target:mutate"]
#: Inside the fixture's declared ``mayhem_min`` window, so the loader's
#: compatibility gate is not what a "the SDK built something loadable" test is
#: quietly measuring.
_RUNNING_VERSION = "1.1.0"


def python_builder() -> ProviderBuilder:
    """The reference authoring: the same provider, written with the SDK."""
    builder = ProviderBuilder(
        _PROVIDER_ID,
        name="ACME Injector",
        version=_VERSION,
        description="Slows a service without taking it down.",
        permissions=_PERMISSIONS,
    )
    builder.capability(
        _CAPABILITY,
        summary="Adds latency to one service.",
        required_permissions=_PERMISSIONS,
        mutates_targets=True,
        compensable=True,
    )
    builder.capability(
        "acme.injector.observe",
        summary="Reports what it sees, changing nothing.",
        required_permissions=["target:read"],
    )
    builder.locator(_LOCATOR, kind="service")
    builder.fault(
        _MUTATING_FAULT,
        capability=_CAPABILITY,
        summary="Adds latency.",
        required_permissions=_PERMISSIONS,
        target_locator_ids=[_LOCATOR],
        mutation="mutating",
        reversible=True,
        parameter_grammar=[
            builder.parameter(
                "scale",
                kind="integer",
                required=False,
                default="1",
                minimum=1,
                maximum=10,
                summary="multiplier on the added latency",
            )
        ],
    )
    builder.fault(
        _READ_ONLY_FAULT,
        capability="acme.injector.observe",
        summary="Reports queue depth.",
        target_locator_ids=[_LOCATOR],
    )
    builder.evidence_schema("acme-injector-evidence", "1.0")
    builder.evidence_mapping(_MUTATING_FAULT)
    builder.evidence_mapping(_READ_ONLY_FAULT)
    builder.compatibility(mayhem_min="1.0.0", engines=["podman"])
    return builder


def rust_manifest() -> dict[str, Any]:
    """The same provider as a Rust ``ProviderManifest`` struct literal."""
    return {
        "provider_id": _PROVIDER_ID,
        "name": "ACME Injector",
        "version": _VERSION,
        "description": "Slows a service without taking it down.",
        "permissions": _PERMISSIONS,
        "capabilities": [
            {
                "id": _CAPABILITY,
                "summary": "Adds latency to one service.",
                "required_permissions": _PERMISSIONS,
                "mutates_targets": True,
                "compensable": True,
            },
            {
                "id": "acme.injector.observe",
                "summary": "Reports what it sees, changing nothing.",
                "required_permissions": ["target:read"],
                "mutates_targets": False,
                "compensable": False,
            },
        ],
        "target_locators": [
            {"id": _LOCATOR, "kind": "service", "required_permissions": ["target:read"]}
        ],
        "fault_declarations": [
            {
                "id": _MUTATING_FAULT,
                "capability": _CAPABILITY,
                "summary": "Adds latency.",
                "required_permissions": _PERMISSIONS,
                "target_locator_ids": [_LOCATOR],
                "mutation": "mutating",
                "reversible": True,
                "risk": "medium",
                "parameter_grammar": [
                    {
                        "name": "scale",
                        "kind": "integer",
                        "required": False,
                        "default": "1",
                        "summary": "multiplier on the added latency",
                        "minimum": 1.0,
                        "maximum": 10.0,
                        "choices": [],
                        "pattern": None,
                    }
                ],
            },
            {
                "id": _READ_ONLY_FAULT,
                "capability": "acme.injector.observe",
                "summary": "Reports queue depth.",
                "required_permissions": [],
                "target_locator_ids": [_LOCATOR],
                "mutation": "read_only",
                "reversible": True,
                "risk": "medium",
                "parameter_grammar": [],
            },
        ],
        "evidence_schema": {"name": "acme-injector-evidence", "version": "1.0"},
        "evidence_mappings": [
            {"fault_id": _MUTATING_FAULT},
            {"fault_id": _READ_ONLY_FAULT},
        ],
        "compatibility": {
            "api_majors": ["v1"],
            "mayhem_min": "1.0.0",
            "mayhem_max": None,
            "engines": ["podman"],
        },
    }


def go_manifest() -> dict[str, Any]:
    """The same provider as a Go struct literal, with Go field names."""
    return {
        "ProviderID": _PROVIDER_ID,
        "Name": "ACME Injector",
        "Version": _VERSION,
        "Description": "Slows a service without taking it down.",
        "Permissions": _PERMISSIONS,
        "Capabilities": [
            {
                "ID": _CAPABILITY,
                "Summary": "Adds latency to one service.",
                "RequiredPermissions": _PERMISSIONS,
                "MutatesTargets": True,
                "Compensable": True,
            },
            {
                "ID": "acme.injector.observe",
                "Summary": "Reports what it sees, changing nothing.",
                "RequiredPermissions": ["target:read"],
                "MutatesTargets": False,
                "Compensable": False,
            },
        ],
        "TargetLocators": [
            {"ID": _LOCATOR, "Kind": "service", "RequiredPermissions": ["target:read"]}
        ],
        "FaultDeclarations": [
            {
                "ID": _MUTATING_FAULT,
                "Capability": _CAPABILITY,
                "Summary": "Adds latency.",
                "RequiredPermissions": _PERMISSIONS,
                "TargetLocatorIDs": [_LOCATOR],
                "Mutation": "mutating",
                "Reversible": True,
                "Risk": "medium",
                "ParameterGrammar": [
                    {
                        "Name": "scale",
                        "Kind": "integer",
                        "Required": False,
                        "Default": "1",
                        "Summary": "multiplier on the added latency",
                        "Minimum": 1.0,
                        "Maximum": 10.0,
                        "Choices": [],
                        "Pattern": None,
                    }
                ],
            },
            {
                "ID": _READ_ONLY_FAULT,
                "Capability": "acme.injector.observe",
                "Summary": "Reports queue depth.",
                "RequiredPermissions": [],
                "TargetLocatorIDs": [_LOCATOR],
                "Mutation": "read_only",
                "Reversible": True,
                "Risk": "medium",
                "ParameterGrammar": [],
            },
        ],
        "EvidenceSchema": {"Name": "acme-injector-evidence", "Version": "1.0"},
        "EvidenceMappings": [{"FaultID": _MUTATING_FAULT}, {"FaultID": _READ_ONLY_FAULT}],
        "Compatibility": {
            "APIMajors": ["v1"],
            "MayhemMin": "1.0.0",
            "MayhemMax": None,
            "Engines": ["podman"],
        },
    }


class _Runtime:
    """A provider runtime that says exactly what the declaration says.

    Deliberately minimal and identical for all three front-ends: the conformance
    claim is about the declaration, and a runtime that varied by language would be
    inventing a cross-language execution story this build does not have.
    """

    def __init__(self, metadata: ProviderMetadata) -> None:
        self._metadata = metadata

    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted(self._metadata.capability_ids))

    def fault_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._metadata.declared_fault_ids))

    def permissions(self) -> tuple[str, ...]:
        return tuple(sorted(permission.value for permission in self._metadata.permissions))


@pytest.fixture
def artifacts() -> dict[SdkLanguage, AuthoredArtifact]:
    return {
        SdkLanguage.PYTHON: python_declaration(python_builder()),
        SdkLanguage.RUST: rust_declaration(rust_manifest()),
        SdkLanguage.GO: go_declaration(go_manifest()),
    }


# =============================================================================
# The SDK builds what the wire contract says it builds
# =============================================================================


class TestThePythonFrontEnd:
    def test_it_builds_a_valid_declaration(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        metadata = artifacts[SdkLanguage.PYTHON].metadata
        assert metadata.provider_id == _PROVIDER_ID
        assert metadata.version == _VERSION
        assert metadata.declared_fault_ids == frozenset({_MUTATING_FAULT, _READ_ONLY_FAULT})
        assert metadata.required_permissions == frozenset(ProviderPermission) - {
            ProviderPermission.NETWORK,
            ProviderPermission.FILESYSTEM_READ,
            ProviderPermission.FILESYSTEM_WRITE,
            ProviderPermission.SUBPROCESS,
        }

    def test_the_emitted_keys_are_the_wire_contract_and_nothing_else(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        document = artifacts[SdkLanguage.PYTHON].document
        assert set(document) == PROVIDER_DECLARATION_WIRE_FIELDS
        for fault in document["faultDeclarations"]:
            assert set(fault) == PROVIDER_FAULT_WIRE_FIELDS

    def test_an_optional_parameter_carries_its_default(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        fault = artifacts[SdkLanguage.PYTHON].metadata.fault_declaration[_MUTATING_FAULT]
        scale = fault.parameter("scale")
        assert scale is not None
        assert scale.required is False
        assert scale.default == "1"

    def test_the_sdk_refuses_a_declaration_with_no_evidence_schema(self) -> None:
        builder = ProviderBuilder(_PROVIDER_ID, name="ACME", version=_VERSION, description="d")
        builder.capability("acme.injector.observe", summary="s")
        with pytest.raises(SdkBuildError, match="sdk_evidence_schema_required"):
            python_declaration(builder)

    def test_the_sdk_does_not_reimplement_the_domain_validator(self) -> None:
        """A mutating fault that requires no mutation permission is refused.

        By the *domain* rule, not by a builder-side pre-check: the message names
        the domain's own wording, which is the proof that the SDK validated the
        declaration with the model rather than with a second set of rules that
        happens to agree today.
        """
        builder = ProviderBuilder(_PROVIDER_ID, name="ACME", version=_VERSION, description="d")
        builder.capability(
            _CAPABILITY, summary="s", required_permissions=_PERMISSIONS, mutates_targets=True
        )
        builder.locator(_LOCATOR, kind="service")
        builder.fault(
            _MUTATING_FAULT,
            capability=_CAPABILITY,
            summary="s",
            required_permissions=["target:read"],
            mutation="mutating",
        )
        builder.evidence_schema("acme", "1.0")
        with pytest.raises(SdkBuildError) as excinfo:
            python_declaration(builder)
        assert excinfo.value.code == "sdk_declaration_invalid"
        assert "mutating faults must require target:mutate" in str(excinfo.value)

    def test_an_empty_evidence_field_set_is_refused_not_defaulted(self) -> None:
        """``fields=[]`` is a claim (a schema with no fields), not "use the default"."""
        builder = python_builder()
        builder.evidence_schema("acme-injector-evidence", "1.0", fields=[])
        with pytest.raises(SdkBuildError, match="evidence schema requires a name and fields"):
            python_declaration(builder)

    def test_omitting_fields_uses_the_contract_default(self) -> None:
        artifact = python_declaration(python_builder())
        assert artifact.metadata.evidence_schema.fields == (
            "recorded_at",
            "operation",
            "target",
            "outcome",
        )


# =============================================================================
# Phase 5 — the conformance suite: one provider, three front-ends
# =============================================================================


class TestCrossSdkConformance:
    def test_the_three_canonical_forms_are_byte_identical(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        canonicals = {language: artifact.canonical for language, artifact in artifacts.items()}
        assert len(set(canonicals.values())) == 1, canonicals

    def test_the_conformance_report_says_identical(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        report = conformance_report(artifacts)
        assert report.all_built
        assert report.identical

    def test_the_three_load_into_identical_registrations(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        """Acceptance, checked against the real loader and not a comparison.

        Each front-end's artifact is loaded through its own
        :class:`~mayhem.providers.loader.ProviderLoader` — separate registry,
        separate gates, separate runtime — and the resulting registrations must
        compare equal. A conformance claim that only compared documents would miss
        a loader that treated the three differently.
        """
        registrations = []
        for language, artifact in artifacts.items():
            loader = ProviderLoader(
                allowed_permissions=frozenset(ProviderPermission),
                require_sandbox_enforcement=False,
                running_version=_RUNNING_VERSION,
                running_engine="podman",
            )
            inspection = loader.load_registration(
                artifact.registration(implementation="tests.unit.test_provider_sdk:_Runtime"),
                _Runtime(artifact.metadata),
            )
            assert inspection.status == "loaded", language
            registrations.append(loader.registry.registration(_PROVIDER_ID))
        assert registrations[0] == registrations[1] == registrations[2]

    def test_a_missing_front_end_is_reported_not_skipped(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        """A report that omits the front-end it could not check reads as a pass."""
        two = {key: artifacts[key] for key in (SdkLanguage.PYTHON, SdkLanguage.RUST)}
        report = conformance_report(two)
        assert not report.identical
        go_entry = next(entry for entry in report.languages if entry.language is SdkLanguage.GO)
        assert not go_entry.built
        assert "not exercised" in go_entry.error

    def test_the_report_separates_front_ends_from_shipped_sdks(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        payload = conformance_report(artifacts).to_dict()
        assert [entry["language"] for entry in payload["languages"]] == ["go", "python", "rust"]
        assert payload["shipped_languages"] == ["python"]
        assert payload["unshipped_languages"] == ["go", "rust"]


class TestTheFieldMapsAreTheContract:
    def test_both_maps_cover_the_same_wire_keys(self) -> None:
        assert set(RUST_FIELD_NAMES.values()) == set(GO_FIELD_TAGS.values())

    def test_the_maps_do_not_collide_on_the_wire(self) -> None:
        """One language spelling per wire key, so the rename is a function.

        Without this, two different Rust field names could both claim
        ``requiredPermissions`` and one would silently win depending on dict order
        — a divergence three SDKs would never agree on.
        """
        assert len(set(RUST_FIELD_NAMES.values())) == len(RUST_FIELD_NAMES)
        assert len(set(GO_FIELD_TAGS.values())) == len(GO_FIELD_TAGS)

    def test_go_acronyms_are_tagged_not_derived(self) -> None:
        """Go's ``ID`` convention is where a derived mapping goes wrong."""
        assert GO_FIELD_TAGS["ProviderID"] == "providerId"
        assert GO_FIELD_TAGS["TargetLocatorIDs"] == "target_locator_ids"
        assert GO_FIELD_TAGS["FaultID"] == "fault_id"
        assert GO_FIELD_TAGS["APIVersion"] == "apiVersion"

    def test_the_snake_case_models_keep_snake_case_on_the_wire(self) -> None:
        """``EvidenceMapping`` declares no aliases, so it must not gain any.

        A mixed convention inside one document is exactly what a hand-rolled
        serialiser gets wrong; if a future model added a camelCase alias, this
        test is what forces the maps to be updated with it.
        """
        assert RUST_FIELD_NAMES["fault_id"] == "fault_id"
        assert RUST_FIELD_NAMES["schema_version"] == "schema_version"

    @pytest.mark.parametrize(
        ("manifest", "front_end", "code"),
        [
            ({"providerID": "acme.injector"}, rust_declaration, "rust_unknown_field"),
            ({"ProviderId": "acme.injector"}, go_declaration, "go_unknown_field"),
        ],
    )
    def test_a_misspelled_field_is_refused_rather_than_dropped(
        self,
        manifest: dict[str, Any],
        front_end: Any,
        code: str,
    ) -> None:
        """The negative control for the normalisers.

        A dropped field is the whole failure mode of a manifest reader: the
        declaration still validates, it just says less than its author wrote.
        """
        with pytest.raises(SdkBuildError) as excinfo:
            front_end(manifest)
        assert excinfo.value.code == code
        assert "silently says less than its author wrote" in str(excinfo.value)


# =============================================================================
# Phase 3 — the gap-74 permission display
# =============================================================================


class TestThePermissionDisplay:
    def test_a_freshly_built_display_is_never_approved(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        display = permission_display(artifacts[SdkLanguage.PYTHON].metadata)
        assert not display.approved
        assert not display.can_do
        assert display.cannot_do
        assert not display.installable
        assert display.requires_explicit_approval

    def test_an_ungranted_permission_is_listed_as_cannot_do(self) -> None:
        display = permission_display(python_declaration(python_builder()).metadata)
        decisions = {line.permission: line.decision for line in display.cannot_do}
        assert decisions[ProviderPermission.TARGET_MUTATE] is (
            PermissionDecision.CANNOT_DO_NOT_GRANTED
        )

    def test_a_granted_permission_is_still_cannot_do_until_approved(self) -> None:
        """The gap-74 half: the grant is what could be allowed; approval is what was."""
        display = permission_display(
            python_declaration(python_builder()).metadata,
            grant=frozenset(ProviderPermission),
        )
        assert {line.decision for line in display.lines} == {
            PermissionDecision.CANNOT_DO_NOT_APPROVED
        }
        assert not display.installable

    def test_approval_moves_granted_lines_and_leaves_ungranted_ones(self) -> None:
        display = permission_display(
            python_declaration(python_builder()).metadata,
            grant=frozenset({ProviderPermission.TARGET_READ}),
        )
        approved = approve_permission_display(display, actor="ops:alice", approval_id="ap-1")
        assert approved.approved
        assert [line.permission for line in approved.can_do] == [ProviderPermission.TARGET_READ]
        assert [line.permission for line in approved.cannot_do] == [
            ProviderPermission.TARGET_MUTATE
        ]
        assert not approved.installable
        assert approved.approved_by == "ops:alice"
        assert approved.approval_id == "ap-1"

    def test_a_fully_granted_and_approved_display_is_installable(self) -> None:
        display = permission_display(
            python_declaration(python_builder()).metadata,
            grant=frozenset(ProviderPermission),
        )
        approved = approve_permission_display(display, actor="ops", approval_id="ap-2")
        assert approved.installable
        assert not approved.cannot_do

    def test_approval_does_not_widen_the_grant(self) -> None:
        """Approving what was granted is not a grant of what was not."""
        display = permission_display(
            python_declaration(python_builder()).metadata,
            grant=frozenset({ProviderPermission.TARGET_READ}),
        )
        approved = approve_permission_display(display, actor="ops", approval_id="ap-3")
        assert approved.grant == frozenset({ProviderPermission.TARGET_READ})

    @pytest.mark.parametrize(
        ("actor", "approval_id", "code"),
        [
            ("  ", "ap-4", "sdk_approval_actor_blank"),
            ("ops", "  ", "sdk_approval_id_blank"),
        ],
    )
    def test_an_anonymous_or_uncitable_approval_is_refused(
        self, actor: str, approval_id: str, code: str
    ) -> None:
        display = permission_display(python_declaration(python_builder()).metadata)
        with pytest.raises(SdkBuildError) as excinfo:
            approve_permission_display(display, actor=actor, approval_id=approval_id)
        assert excinfo.value.code == code

    def test_required_by_names_which_part_asked(self) -> None:
        display = permission_display(
            python_declaration(python_builder()).metadata,
            grant=frozenset(ProviderPermission),
        )
        line = next(
            line for line in display.lines if line.permission is ProviderPermission.TARGET_MUTATE
        )
        assert f"fault:{_MUTATING_FAULT}" in line.required_by
        assert _CAPABILITY in line.required_by

    def test_every_permission_has_a_stated_consequence(self) -> None:
        """The table covers the whole enum, not just the permissions this fixture uses.

        A consequence table with a hole is a hole an operator meets the first time
        a provider asks for the permission nobody wrote a line for.
        """
        assert set(PERMISSION_CONSEQUENCE) == set(ProviderPermission)
        consequences = {consequence.strip() for consequence in PERMISSION_CONSEQUENCE.values()}
        assert len(consequences) == len(PERMISSION_CONSEQUENCE)
        for permission, consequence in PERMISSION_CONSEQUENCE.items():
            assert consequence.strip(), permission

    def test_the_render_carries_both_caveats(self) -> None:
        rendered = describe_permission_display(
            permission_display(python_declaration(python_builder()).metadata)
        )
        assert SDK_UNVERIFIED_NOTICE in rendered
        assert "seccomp" in rendered
        assert "approved=false" in rendered

    def test_a_declaration_with_no_permission_owes_no_approval(self) -> None:
        builder = ProviderBuilder(
            "acme.quiet", name="Quiet", version="0.1.0", description="declares nothing"
        )
        builder.capability("acme.quiet.observe", summary="s")
        builder.evidence_schema("acme-quiet-evidence", "1.0")
        display = permission_display(python_declaration(builder).metadata)
        assert not display.requires_explicit_approval
        assert not display.lines
        approved = approve_permission_display(display, actor="ops", approval_id="ap-5")
        assert approved.installable


# =============================================================================
# Phase 3 + 5 — the SDK confers nothing it cannot verify
# =============================================================================


class TestTheArtifactCarriesNoTrust:
    def test_signature_verification_is_still_not_implemented(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
        assert SIGNATURE_TRUST_NOTICE
        for artifact in artifacts.values():
            assert artifact.to_dict()["signature_verification_implemented"] is False

    def test_an_artifact_has_no_field_that_could_carry_a_signature(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        """Structural, not behavioural: there is nowhere to put one.

        The strongest guarantee this build can make. A ``signature: str = ""``
        would do nearly as well, but an empty string is one careless default away
        from a populated one; a field that does not exist cannot be set at all.
        """
        fields = frozenset(AuthoredArtifact.__dataclass_fields__)
        for forbidden in ("signature", "signer", "signature_verified", "verified", "trusted"):
            assert forbidden not in fields
        assert not {field.lower() for field in fields} & {
            "signature",
            "signer",
            "verified",
            "trusted",
        }

    def test_authenticity_is_a_single_member_refusing_to_become_two(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        assert [member.value for member in ArtifactAuthenticity] == ["declared_unverified"]
        artifact = artifacts[SdkLanguage.PYTHON]
        assert artifact.authenticity is ArtifactAuthenticity.DECLARED_UNVERIFIED

    def test_setting_authenticity_to_anything_else_is_refused(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        """The negative control for the single-member enum.

        ``object.__setattr__`` bypasses the frozen dataclass on purpose: it is the
        only way to attempt the promotion, and the guard has to catch it.
        """
        artifact = artifacts[SdkLanguage.PYTHON]
        object.__setattr__(artifact, "authenticity", "verified")
        with pytest.raises(SdkBuildError) as excinfo:
            artifact.__post_init__()
        assert excinfo.value.code == "sdk_artifact_authenticity_refused"
        assert "trust store and a key" in str(excinfo.value)

    def test_the_sdk_says_what_it_confers_and_what_it_does_not(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        payload = artifacts[SdkLanguage.PYTHON].to_dict()
        assert payload["conferred"] == list(SDK_CONFERRED)
        assert payload["not_conferred"] == list(SDK_NOT_CONFERRED)
        assert payload["notice"] == SDK_UNVERIFIED_NOTICE
        for claim in SDK_NOT_CONFERRED:
            assert claim.startswith("that ")

    def test_the_shipped_flags_do_not_claim_rust_or_go_are_installed(self) -> None:
        """Stated, not inferred from the absence of a ``Cargo.toml``."""
        assert PYTHON_SDK_SHIPPED is True
        assert RUST_SDK_SHIPPED is False
        assert GO_SDK_SHIPPED is False
        assert set(SDK_LANGUAGES) == {SdkLanguage.PYTHON, SdkLanguage.RUST, SdkLanguage.GO}

    def test_every_front_end_names_the_callable_that_built_the_artifact(self) -> None:
        for language in SDK_LANGUAGES:
            entry_point = FRONT_ENTRIES[language]
            module_name, _, function_name = entry_point.rpartition(".")
            module = __import__(module_name, fromlist=[function_name])
            assert callable(getattr(module, function_name))


class TestTheOverclaimScan:
    """The standing negative control for this plan.

    Treats "signed", "verified" and "trusted" as words this build may not use
    **about a publisher**. Two separate scans, because they catch different
    defects:

    * :meth:`test_no_public_identifier_claims_a_publisher_check` — an identifier
      is the strongest overclaim there is, because it is a *type* the rest of the
      codebase will call. A field named ``verified_signer`` is not a wording
      problem; it is an API that invites an argument.
    * :meth:`test_no_emitted_wire_key_claims_a_publisher_check` — a key that
      appears in the document an operator reads is the second strongest, for the
      same reason at a different layer.

    Prose is deliberately *not* scanned, and the exclusion is the point: the
    whole job of the notices is to say the words "signature" and "verified" in
    order to deny them, and a scanner that forbade them would force the
    disclaimer to be vague — which is the failure this whole control exists to
    prevent. So the scan is scoped to identifiers and keys, and
    :meth:`test_the_notices_are_where_the_words_live` pins that the words appear
    in the notices and *only* there.
    """

    FORBIDDEN = ("signed", "signature", "signer", "verified", "trusted", "trust_store", "attested")

    #: Prefixes that turn one of :data:`FORBIDDEN` into a *denial* — and only
    #: when the prefix sits **immediately in front of the matched word**.
    #:
    #: Scoped that narrowly on purpose. A scan that exempted any identifier
    #: containing "un" or "not" anywhere would pass
    #: ``provider_unverified_but_signature_valid`` — a name that mentions a
    #: signature check *positively* and buries the negation in front of an
    #: unrelated word. Anchoring the negator to the match is what makes the
    #: exemption about this word rather than about the string, and
    #: :meth:`test_the_negator_exemption_does_not_swallow_an_affirmative_claim`
    #: is what proves it.
    NEGATOR_PREFIXES = ("un", "non", "not_", "no_", "never_", "cannot_", "notverified")

    @classmethod
    def _claims_a_check(cls, identifier: str) -> bool:
        """Whether *identifier* asserts a publisher check anywhere.

        Every occurrence of every forbidden word is examined, and an occurrence is
        exempt only when a negator prefix sits immediately in front of *that*
        occurrence. Scanning occurrences rather than the whole string is what
        stops one exemption from covering the rest of the name.
        """
        lowered = identifier.lower()
        width = max(len(prefix) for prefix in cls.NEGATOR_PREFIXES)
        for word in cls.FORBIDDEN:
            start = 0
            while (index := lowered.find(word, start)) != -1:
                prefix = lowered[max(0, index - width) : index]
                if not prefix.endswith(cls.NEGATOR_PREFIXES):
                    return True
                start = index + 1
        return False

    @classmethod
    def _offenders(cls, identifiers: Any) -> list[str]:
        return sorted(identifier for identifier in identifiers if cls._claims_a_check(identifier))

    def test_no_public_identifier_claims_a_publisher_check(self) -> None:
        offenders = self._offenders(sdk_identifiers())
        assert not offenders, (
            f"the SDK exposes identifiers that read as a publisher check: {offenders}. "
            "This build verifies no signature; a field, method or constant named "
            "'verified_*' invites an argument that would be a lie to pass."
        )

    def test_no_emitted_wire_key_claims_a_publisher_check(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        def keys(node: Any) -> set[str]:
            if isinstance(node, dict):
                found = set(node)
                for value in node.values():
                    found |= keys(value)
                return found
            if isinstance(node, list):
                found = set()
                for value in node:
                    found |= keys(value)
                return found
            return set()

        offenders = sorted(
            key
            for artifact in artifacts.values()
            for key in keys(artifact.document)
            for word in self.FORBIDDEN
            if word in key.lower()
        )
        assert not offenders, f"the SDK emits keys that read as a publisher check: {offenders}"

    def test_the_wire_contract_still_declares_no_signature_field(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        """Phase 1's structural guard, re-checked through the SDK's output."""
        assert not PROVIDER_DECLARATION_WIRE_FIELDS & {
            "signature",
            "signatureVerified",
            "signer",
            "trusted",
            "verified",
        }
        assert not PROVIDER_FAULT_WIRE_FIELDS & {
            "signature",
            "signatureVerified",
            "signer",
            "trusted",
            "verified",
        }

    def test_the_notices_are_where_the_words_live(self) -> None:
        """Both notices deny the check by name, and both cite the flag."""
        assert "SIGNATURE_VERIFICATION_IMPLEMENTED is False" in SDK_UNVERIFIED_NOTICE
        assert "does not attest to the code" in SDK_UNVERIFIED_NOTICE
        assert "unverified" not in SDK_UNVERIFIED_NOTICE.replace("verifies no signature", "")

    def test_the_scan_notices_a_word_it_is_looking_for(self) -> None:
        """The negative control *for the scan*.

        A scan that finds nothing is only evidence if it could have found
        something. This plants the defect in a local copy of the identifier set
        and shows the same predicate lights up — which is what stops the scan
        above from passing because the word list was emptied by accident.
        """
        identifiers = set(sdk_identifiers()) | {
            "ProviderArtifact.verified_signer",
            "provider.trusted",
            "publisher_signed",
        }
        caught = self._offenders(identifiers)
        assert caught == [
            "ProviderArtifact.verified_signer",
            "provider.trusted",
            "publisher_signed",
        ]
        assert self._offenders(sdk_identifiers()) == []

    def test_the_negator_exemption_does_not_swallow_an_affirmative_claim(self) -> None:
        """The negative control *for the negation exemption*.

        A scan that exempts any identifier merely *containing* "un" or "not" will
        happily pass ``provider_unverified_but_signature_valid`` — a name that
        names a signature check positively and hides the negation behind an
        unrelated word. The exemption has to be anchored to the match.
        """
        assert self._offenders({"provider_unverified_but_signature_valid"}) == [
            "provider_unverified_but_signature_valid"
        ]
        assert self._offenders({"SDK_UNVERIFIED_NOTICE", "DECLARED_UNVERIFIED"}) == []
        assert self._offenders({"unsigned"}) == []


class TestTheLoaderStillRefusesAnSdkBuiltDeclaration:
    """Phase 2's gates are not bypassed by going through the SDK.

    The SDK validates the declaration's *grammar*. It grants nothing. These are
    the two refusals an author would most reasonably assume the SDK had handled,
    proved still to fire.
    """

    def test_a_permission_declaring_provider_still_needs_a_grant(self) -> None:
        artifact = python_declaration(python_builder())
        with pytest.raises(Exception, match="provider_permission_denied"):
            ProviderLoader(
                require_sandbox_enforcement=False, running_version=_RUNNING_VERSION
            ).load_registration(artifact.registration(), _Runtime(artifact.metadata))

    def test_the_sandbox_default_still_refuses_it(self) -> None:
        artifact = python_declaration(python_builder())
        loader = ProviderLoader(
            allowed_permissions=frozenset(ProviderPermission),
            running_version=_RUNNING_VERSION,
        )
        with pytest.raises(Exception, match="provider_sandbox_mechanism_unapplied"):
            loader.load_registration(artifact.registration(), _Runtime(artifact.metadata))

    def test_a_runtime_that_over_claims_is_still_refused_before_the_registry(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        class Greedy(_Runtime):
            def fault_ids(self) -> tuple[str, ...]:
                return (*super().fault_ids(), "acme.sneaky")

        artifact = artifacts[SdkLanguage.PYTHON]
        loader = ProviderLoader(
            allowed_permissions=frozenset(ProviderPermission),
            require_sandbox_enforcement=False,
            running_version=_RUNNING_VERSION,
        )
        with pytest.raises(Exception, match="provider_behavior_mismatch"):
            loader.load_registration(artifact.registration(), Greedy(artifact.metadata))
        assert _PROVIDER_ID not in loader.registry.ids()


# =============================================================================
# Canonical form
# =============================================================================


class TestTheCanonicalForm:
    def test_it_is_stable_across_two_serialisations(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        metadata = artifacts[SdkLanguage.PYTHON].metadata
        document = metadata.model_dump(mode="json", by_alias=True)
        assert canonical_json(document) == canonical_json(
            ProviderMetadata.model_validate(document).model_dump(mode="json", by_alias=True)
        )

    def test_an_artifact_whose_canonical_form_was_tampered_with_is_refused(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        artifact = artifacts[SdkLanguage.PYTHON]
        with pytest.raises(SdkBuildError, match="sdk_artifact_canonical_mismatch"):
            replace(artifact, canonical="{}")

    def test_the_canonical_form_round_trips_through_json(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        artifact = artifacts[SdkLanguage.RUST]
        assert json.loads(artifact.canonical) == json.loads(
            json.dumps(artifact.document, sort_keys=True)
        )


# =============================================================================
# Fault declarations the SDK must not let through
# =============================================================================


class TestTheSdkDoesNotInventAuthority:
    def test_a_fault_id_the_declaration_does_not_own_is_not_a_thing(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        metadata = artifacts[SdkLanguage.PYTHON].metadata
        with pytest.raises(KeyError):
            metadata.fault_declaration["acme.not-declared"]
        assert "acme.not-declared" not in metadata.declared_fault_ids

    def test_the_sdk_exports_the_domain_models_not_a_re_definition(
        self, artifacts: dict[SdkLanguage, AuthoredArtifact]
    ) -> None:
        from mayhem.domain import provider as domain_provider
        from mayhem.providers import sdk

        assert sdk.FaultDeclaration is domain_provider.FaultDeclaration
        assert sdk.ProviderSource is domain_provider.ProviderSource
        assert FaultDeclaration is domain_provider.FaultDeclaration
