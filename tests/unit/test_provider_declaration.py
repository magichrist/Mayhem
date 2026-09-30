"""Unit tests for the provider declaration schema as a wire contract (plan 17 P1).

Phase 1 of ``docs/v1.1.0/17_EXTENSION_SDK_PROVIDER_PROTOCOL.md`` makes
``mayhem.domain.provider`` the versioned declaration schema an SDK generates
and the core consumes. These tests are the contract's regression guard. They are
deliberately written against the *wire* form (JSON keys, aliases) rather than
against the Python constructors, because the wire form is what a Rust, Python or
Go SDK is going to emit and what a frozen artifact from an older core has to
keep loading through.

Two things these tests deliberately do **not** claim:

* Passing them is not evidence that a provider is safe, correct, or
  trustworthy. It is evidence that a declaration says what it means and is
  refused when it does not.
* The engine axis of :class:`CompatibilityBounds` is only checked when a caller
  supplies the running engine. Omitting it is an unchecked axis, and the tests
  say so in the test that exercises it rather than reading the omission as a
  pass.

Nothing here claims a signature is verified. See
:data:`mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED`.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import ValidationError

from mayhem.domain.provider import (
    DEFAULT_DECLARED_PERMISSIONS,
    PROVIDER_API_MAJOR,
    PROVIDER_API_VERSION,
    PROVIDER_CATALOG_SCHEMA_VERSION,
    PROVIDER_DECLARATION_SCHEMA_VERSION,
    PROVIDER_DECLARATION_WIRE_FIELDS,
    PROVIDER_FAULT_WIRE_FIELDS,
    SUPPORTED_PROVIDER_API_MAJORS,
    CapabilityDescriptor,
    CompatibilityBounds,
    EvidenceMapping,
    EvidenceSchema,
    FaultDeclaration,
    ImplementationKind,
    ImplementationReference,
    ParameterDeclaration,
    ParameterKind,
    ProviderCatalog,
    ProviderCompatibilityError,
    ProviderMetadata,
    ProviderMutation,
    ProviderPermission,
    ProviderPermissionError,
    ProviderRegistration,
    ProviderSource,
    ensure_api_compatible,
    ensure_compatibility_bounds,
    ensure_declared_permissions,
    fault_parameter_problems,
)
from mayhem.providers.pack import SIGNATURE_TRUST_NOTICE, SIGNATURE_VERIFICATION_IMPLEMENTED
from mayhem.providers.permissions import DEFAULT_PERMISSION_SET
from mayhem.providers.registry import ProviderRegistry

if TYPE_CHECKING:
    from pathlib import Path

# ── frozen fixtures ──────────────────────────────────────────────────────────

#: A provider declaration **as it existed when ``mayhem.provider/v1`` shipped.**
#:
#: This is a frozen artifact, not a convenience. Do not add the fields Phase 1
#: introduced (``parameterGrammar``, ``evidenceMappings``, ``compatibility``,
#: ``risk``) to it: its entire value is that it is what an older core wrote and
#: a newer core must still read. Every key here must keep validating, and every
#: key must keep being emitted; if a future change makes this document fail to
#: load, that is a contract break, not a fixture to update.
_FROZEN_V1_DOCUMENT: dict[str, Any] = {
    "apiVersion": "mayhem.provider/v1",
    "providerId": "acme.injector",
    "name": "Acme Injector",
    "version": "0.3.1",
    "description": "Injects packet faults into a target container.",
    "permissions": ["target:read"],
    "capabilities": [
        {
            "id": "injector.inject",
            "summary": "Inject a fault into a discovered target.",
            "requiredPermissions": ["target:read"],
        }
    ],
    "targetLocators": [
        {
            "id": "acme.injector.target",
            "kind": "acme_container",
            "requiredPermissions": ["target:read"],
        }
    ],
    "faultDeclarations": [
        {
            "id": "acme.packet.drop",
            "capability": "injector.inject",
            "summary": "Drop a fraction of inbound packets.",
            "target_locator_ids": ["acme.injector.target"],
            "parameters": {"percent": "5"},
            "mutation": "read_only",
            "reversible": True,
        }
    ],
    "evidenceSchema": {"name": "acme-injector-evidence", "version": "1.0"},
    "source": "catalog",
}

_FROZEN_V1_FAULT_KEYS: frozenset[str] = frozenset(_FROZEN_V1_DOCUMENT["faultDeclarations"][0])

#: A declaration built against the same ``v1`` major, using everything Phase 1
#: added: a parameter grammar, an evidence-schema mapping, declared risk, and
#: explicit compatibility bounds. Frozen for the same reason as above.
_V1_MINOR1_DOCUMENT: dict[str, Any] = {
    "apiVersion": "mayhem.provider/v1",
    "providerId": "acme.chaos",
    "name": "Acme Chaos",
    "version": "1.4.0",
    "description": "A mutating provider with a full parameter grammar.",
    "permissions": ["target:mutate", "target:read"],
    "capabilities": [
        {
            "id": "chaos.mutate",
            "summary": "Perturb a target and offer a compensation.",
            "requiredPermissions": ["target:mutate", "target:read"],
            "mutates_targets": True,
            "compensable": True,
        }
    ],
    "targetLocators": [
        {
            "id": "acme.chaos.target",
            "kind": "acme_container",
            "selectorSchema": {},
            "requiredPermissions": ["target:read"],
        }
    ],
    "faultDeclarations": [
        {
            "id": "acme.packet.latency",
            "capability": "chaos.mutate",
            "summary": "Add latency to a fraction of packets.",
            "target_locator_ids": ["acme.chaos.target"],
            "parameters": {"percent": "10", "delay_s": "2"},
            "parameterGrammar": [
                {"name": "percent", "kind": "integer", "minimum": 0, "maximum": 100},
                {
                    "name": "delay_s",
                    "kind": "number",
                    "required": False,
                    "default": "1",
                    "minimum": 0,
                },
            ],
            "risk": "high",
            "mutation": "mutating",
            "reversible": True,
            "requiredPermissions": ["target:mutate"],
        }
    ],
    "evidenceSchema": {
        "name": "acme-chaos-evidence",
        "version": "1.0",
        "fields": ["recorded_at", "operation", "target", "outcome", "compensation_token"],
    },
    "evidenceMappings": [
        {
            "fault_id": "acme.packet.latency",
            "schema_name": "acme-chaos-evidence",
            "schema_version": "1.0",
            "fields": ["outcome", "compensation_token"],
        }
    ],
    "compatibility": {
        "apiMajors": ["v1"],
        "mayhemMin": "1.1.0",
        "mayhemMax": "2.0.0",
        "engines": ["docker"],
    },
    "homepage": None,
    "source": "catalog",
}


def _copy(document: dict[str, Any]) -> dict[str, Any]:
    """A deep copy, so a test that edits a fixture edits only its own copy.

    The fixtures are module-level and shared by every test in the file. A test
    that reaches two levels down to add a key would otherwise silently rewrite
    the artifact for whatever runs after it, and the failure would surface in a
    test that has nothing to do with the edit. Cheap enough to do everywhere.
    """
    return deepcopy(document)


def _metadata(document: dict[str, Any]) -> ProviderMetadata:
    return ProviderMetadata.model_validate(deepcopy(document))


def _dump(metadata: ProviderMetadata) -> dict[str, Any]:
    return metadata.model_dump(mode="json", by_alias=True)


def _registration(metadata: ProviderMetadata) -> ProviderRegistration:
    return ProviderRegistration(
        metadata=metadata,
        implementation=ImplementationReference(
            kind=ImplementationKind.ENTRY_POINT,
            target=metadata.provider_id,
        ),
    )


# ── round trip ───────────────────────────────────────────────────────────────


class TestDeclarationRoundTrip:
    def test_frozen_v1_document_validates_and_keeps_every_key(self) -> None:
        """The frozen v1 document still parses, and still says what it said.

        Equality against the input is deliberately *not* the assertion: a dump
        always emits defaults, so a document that omitted them could never be
        byte-equal to its own round-trip. That has been true since before Phase
        1. What must hold is that every key the frozen artifact uses still
        validates and is still emitted.
        """
        metadata = _metadata(_FROZEN_V1_DOCUMENT)
        assert set(_FROZEN_V1_DOCUMENT) <= set(_dump(metadata))

    def test_round_trip_is_idempotent_across_repeated_cycles(self) -> None:
        """Serialise → validate → serialise must be a fixed point.

        Idempotence is what makes a declaration *diffable* between core
        versions: if a re-serialised v1 document differs from its input, then
        "did anything change?" has no answer, and every core minor would show
        a spurious diff on every provider.
        """
        first = _dump(_metadata(_FROZEN_V1_DOCUMENT))
        second = _dump(_metadata(first))
        third = _dump(_metadata(second))
        assert first == second == third

    def test_minor1_document_round_trips_unchanged(self) -> None:
        """A declaration using every Phase 1 field is a fixed point.

        Compared dump-against-its-own-re-validation rather than
        dump-against-input, because permissions are a ``frozenset`` on the
        model: the serialised order is the model's, not the author's, and an
        author who reorders their document must not see the test fail. The
        *key* set is compared against the input exactly, below, because that one
        is a real contract.
        """
        first = _dump(_metadata(_V1_MINOR1_DOCUMENT))
        assert first == _dump(_metadata(first))
        assert set(first) == set(_V1_MINOR1_DOCUMENT)
        assert set(first["faultDeclarations"][0]) == set(
            _V1_MINOR1_DOCUMENT["faultDeclarations"][0]
        )

    def test_every_frozen_key_survives_on_the_wire(self) -> None:
        """Additive evolution only: old keys stay, new optional keys may appear.

        This is the cross-minor promise stated as a test. A later core may add an
        optional field; it may not rename or drop one the v1 fixture already
        used, because a frozen artifact carries that name forever.
        """
        dumped = _dump(_metadata(_FROZEN_V1_DOCUMENT))
        assert set(_FROZEN_V1_DOCUMENT) <= set(dumped)
        assert set(dumped) <= PROVIDER_DECLARATION_WIRE_FIELDS
        fault = dumped["faultDeclarations"][0]
        assert set(fault) >= _FROZEN_V1_FAULT_KEYS
        assert set(fault) <= PROVIDER_FAULT_WIRE_FIELDS

    def test_wire_fields_are_the_frozen_contract(self) -> None:
        """The serialised key set is exactly what the contract says it is.

        Not derived from the model on purpose: deriving it would let a field
        added carelessly bless itself.
        """
        assert set(_dump(_metadata(_FROZEN_V1_DOCUMENT))) <= PROVIDER_DECLARATION_WIRE_FIELDS
        assert set(_dump(_metadata(_V1_MINOR1_DOCUMENT))) <= PROVIDER_DECLARATION_WIRE_FIELDS
        assert set(PROVIDER_DECLARATION_WIRE_FIELDS) >= {
            "apiVersion",
            "providerId",
            "faultDeclarations",
            "targetLocators",
            "evidenceSchema",
            "evidenceMappings",
            "compatibility",
        }
        assert set(PROVIDER_FAULT_WIRE_FIELDS) >= {
            "id",
            "capability",
            "parameters",
            "parameterGrammar",
            "risk",
            "mutation",
            "reversible",
            "requiredPermissions",
        }

    def test_declaration_declares_no_signature_field(self) -> None:
        """No wire field may be readable as a signature check.

        ``SIGNATURE_VERIFICATION_IMPLEMENTED`` is ``False`` in this build and
        nothing in Phase 1 changes that. The strongest guard available at the
        schema layer is structural: there is no field on the declaration for a
        future change to set to ``True``, so a declaration can never be the
        thing that makes a reader believe a signature was checked.
        """
        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
        assert SIGNATURE_TRUST_NOTICE
        forbidden = {
            "signature",
            "signatureVerified",
            "signer",
            "signerVerified",
            "trusted",
            "verified",
            "attestation",
        }
        assert not PROVIDER_DECLARATION_WIRE_FIELDS & forbidden
        assert not PROVIDER_FAULT_WIRE_FIELDS & forbidden

    def test_catalog_round_trips_and_keeps_both_fixtures(self) -> None:
        catalog = ProviderCatalog(
            providers=(
                _registration(_metadata(_FROZEN_V1_DOCUMENT)),
                _registration(_metadata(_V1_MINOR1_DOCUMENT)),
            )
        )
        document = catalog.model_dump(mode="json", by_alias=True)
        assert document["apiVersion"] == PROVIDER_CATALOG_SCHEMA_VERSION
        reloaded = ProviderCatalog.model_validate(document)
        assert reloaded == catalog
        assert [registration.metadata.provider_id for registration in reloaded.providers] == [
            "acme.injector",
            "acme.chaos",
        ]

    def test_canonical_json_is_byte_stable(self) -> None:
        """Two serialisations of the same declaration agree byte for byte.

        SDKs in three languages will hash the canonical form, so a stable
        ordering is a contract property rather than a convenience. The
        comparison is dump-against-revalidated-dump, not dump-against-input,
        for the same reason as the round-trip tests: defaults are always
        emitted.
        """

        def canonical(metadata: ProviderMetadata) -> str:
            return json.dumps(_dump(metadata), sort_keys=True, separators=(",", ":"))

        metadata = _metadata(_FROZEN_V1_DOCUMENT)
        assert canonical(metadata) == canonical(_metadata(_dump(metadata)))

    def test_unknown_field_is_refused(self) -> None:
        document = {**_copy(_FROZEN_V1_DOCUMENT), "signatureVerified": True}
        with pytest.raises(ValidationError, match="signatureVerified"):
            _metadata(document)


# ── api compatibility ────────────────────────────────────────────────────────


class TestApiCompatibility:
    def test_supported_majors_are_v1_only(self) -> None:
        assert PROVIDER_API_MAJOR == "v1"
        assert sorted(SUPPORTED_PROVIDER_API_MAJORS) == ["v1"]
        assert PROVIDER_API_VERSION.endswith("/v1")
        assert PROVIDER_DECLARATION_SCHEMA_VERSION == "mayhem.provider-declaration/v1"

    def test_v1_fixture_still_loads(self) -> None:
        """The acceptance criterion: a provider built against v1 loads."""
        metadata = _metadata(_FROZEN_V1_DOCUMENT)
        ensure_api_compatible(metadata)
        registry = ProviderRegistry(allowed_permissions=frozenset({ProviderPermission.TARGET_READ}))
        registration = _registration(metadata)
        registry.register(registration, lambda: None)
        assert registry.ids() == frozenset({"acme.injector"})
        assert registry.registration("acme.injector") == registration

    def test_minor1_fixture_still_loads(self) -> None:
        metadata = _metadata(_V1_MINOR1_DOCUMENT)
        ensure_api_compatible(metadata)
        registry = ProviderRegistry(allowed_permissions=frozenset(ProviderPermission))
        registry.register(_registration(metadata), lambda: None)
        assert registry.ids() == frozenset({"acme.chaos"})

    def test_builtin_providers_still_construct(self) -> None:
        """The existing registry construction must be untouched by Phase 1."""
        from mayhem.providers.builtin import create_builtin_registry

        registry = create_builtin_registry()
        assert registry.ids() == frozenset({"docker", "podman", "kubernetes"})
        for registration in registry.registrations():
            ensure_api_compatible(registration.metadata)
            assert registration.metadata.api_version == PROVIDER_API_VERSION

    def test_a_future_major_is_refused(self) -> None:
        document = {**_copy(_FROZEN_V1_DOCUMENT), "apiVersion": "mayhem.provider/v2"}
        metadata = _metadata(document)
        with pytest.raises(ProviderCompatibilityError) as caught:
            ensure_api_compatible(metadata)
        assert caught.value.code == "provider_api_incompatible"
        assert "mayhem.provider/v2" in str(caught.value)


# ── cross-minor stability ────────────────────────────────────────────────────


class TestCrossMinorStability:
    """A frozen v1 provider keeps loading across core minor releases."""

    def test_frozen_fixture_has_no_phase1_fields(self) -> None:
        """Pins what "frozen" means.

        If this fails, somebody edited the artifact to match today's schema and
        the cross-minor test above it is no longer testing anything: it would be
        testing today's fields against today's fields.
        """
        metadata = _metadata(_FROZEN_V1_DOCUMENT)
        assert metadata.compatibility == CompatibilityBounds()
        assert metadata.evidence_mappings == ()
        assert metadata.fault_declarations[0].parameter_grammar == ()
        assert "compatibility" not in _FROZEN_V1_DOCUMENT
        assert "evidenceMappings" not in _FROZEN_V1_DOCUMENT

    @pytest.mark.parametrize("core", ["1.0.0", "1.0.7", "1.1.0", "1.9.9", "1.1.0.dev0"])
    def test_default_bounds_admit_later_minors(self, core: str) -> None:
        """An unannotated provider is not narrowed by its own silence.

        The default window is everything, so a declaration that says nothing
        about core versions keeps working on whatever minor it next meets.
        """
        metadata = _metadata(_FROZEN_V1_DOCUMENT)
        ensure_compatibility_bounds(metadata, running_version=core)
        assert metadata.compatibility.admits(core)

    def test_declared_bounds_admit_the_window_they_declare(self) -> None:
        metadata = _metadata(_V1_MINOR1_DOCUMENT)
        for core in ("1.1.0", "1.5.2", "1.1.0.dev0", "1.99.99"):
            assert metadata.compatibility.admits(core) is True
            ensure_compatibility_bounds(metadata, running_version=core)
        for core in ("0.9.9", "2.0.0", "1.0.9"):
            assert metadata.compatibility.admits(core) is False

    def test_minor_fixture_registers_on_every_core_in_its_window(self) -> None:
        metadata = _metadata(_V1_MINOR1_DOCUMENT)
        for core in ("1.1.0", "1.2.0", "1.3.0"):
            ensure_compatibility_bounds(metadata, running_version=core)
            registry = ProviderRegistry(allowed_permissions=frozenset(ProviderPermission))
            registry.register(_registration(metadata), lambda: None)
            assert registry.ids() == frozenset({"acme.chaos"})

    def test_engine_axis_is_checked_only_when_supplied(self) -> None:
        """An engine axis the caller does not supply is unchecked, not passed.

        Pinned as a test because it is the one place where "we did not look" and
        "we looked and it was fine" would otherwise be the same silence.
        """
        metadata = _metadata(_V1_MINOR1_DOCUMENT)
        ensure_compatibility_bounds(metadata, running_version="1.1.0", running_engine="docker")
        # Omitting running_engine skips the axis entirely.
        ensure_compatibility_bounds(metadata, running_version="1.1.0")
        with pytest.raises(ProviderCompatibilityError) as caught:
            ensure_compatibility_bounds(
                metadata, running_version="1.1.0", running_engine="kubernetes"
            )
        assert caught.value.code == "provider_engine_unsupported"
        assert "kubernetes" in str(caught.value)

    def test_unreadable_running_version_is_refused(self) -> None:
        metadata = _metadata(_FROZEN_V1_DOCUMENT)
        with pytest.raises(ProviderCompatibilityError) as caught:
            ensure_compatibility_bounds(metadata, running_version="1.1")
        assert caught.value.code == "provider_version_unreadable"

    def test_bounds_must_be_a_real_window(self) -> None:
        with pytest.raises(ValidationError, match="below mayhem_max"):
            CompatibilityBounds(mayhemMin="2.0.0", mayhemMax="1.0.0")
        with pytest.raises(ValidationError, match="release"):
            CompatibilityBounds(mayhemMin="1.1")
        with pytest.raises(ValidationError, match="api major"):
            CompatibilityBounds.model_validate({"apiMajors": ["1"]})
        with pytest.raises(ValidationError, match="dotted identifier"):
            CompatibilityBounds.model_validate({"engines": ["Docker"]})


# ── default-deny permissions ─────────────────────────────────────────────────


class TestPermissionDefaultDeny:
    def test_default_posture_is_nothing_at_both_layers(self) -> None:
        assert not DEFAULT_DECLARED_PERMISSIONS
        # The domain literal and the loader's default are the same empty set. They
        # are two literals on purpose (the domain may not import the loader
        # layer), so this is the test that stops them drifting apart.
        assert DEFAULT_DECLARED_PERMISSIONS == DEFAULT_PERMISSION_SET

    def test_permission_free_declaration_loads_with_no_grant(self) -> None:
        document = {**_copy(_FROZEN_V1_DOCUMENT), "permissions": []}
        document["capabilities"] = [{"id": "injector.inspect", "summary": "Describe a target."}]
        document["faultDeclarations"] = [
            {
                "id": "acme.packet.drop",
                "capability": "injector.inspect",
                "summary": "Drop a fraction of inbound packets.",
            }
        ]
        document["targetLocators"] = [
            {"id": "acme.injector.target", "kind": "acme_container", "requiredPermissions": []}
        ]
        metadata = _metadata(document)
        ensure_declared_permissions(metadata)
        assert metadata.permissions == frozenset()

    def test_declared_permission_is_refused_by_default(self) -> None:
        metadata = _metadata(_FROZEN_V1_DOCUMENT)
        with pytest.raises(ProviderPermissionError) as caught:
            ensure_declared_permissions(metadata)
        assert caught.value.provider_id == "acme.injector"
        assert "target:read" in str(caught.value)

    def test_explicit_grant_admits_the_declaration(self) -> None:
        metadata = _metadata(_FROZEN_V1_DOCUMENT)
        ensure_declared_permissions(metadata, frozenset({ProviderPermission.TARGET_READ}))
        with pytest.raises(ProviderPermissionError):
            ensure_declared_permissions(metadata, frozenset())

    def test_requested_permissions_are_the_union_of_every_part(self) -> None:
        """What an operator must be shown is the union, not the top-level set."""
        metadata = _metadata(_V1_MINOR1_DOCUMENT)
        assert metadata.required_permissions == frozenset(
            {ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE}
        )
        assert metadata.required_permissions <= metadata.permissions

    def test_a_part_may_not_require_an_undeclared_permission(self) -> None:
        document = {**_copy(_FROZEN_V1_DOCUMENT), "permissions": ["target:read"]}
        document["faultDeclarations"] = [
            {
                "id": "acme.packet.drop",
                "capability": "injector.inject",
                "summary": "Drop packets and open a socket.",
                "mutation": "mutating",
                "reversible": True,
                "requiredPermissions": ["target:mutate", "target:read"],
            }
        ]
        with pytest.raises(ValidationError, match="fault permissions must be declared"):
            _metadata(document)


# ── negative controls ────────────────────────────────────────────────────────


class TestNegativeControls:
    def test_fault_without_compensation_is_refused(self) -> None:
        """A mutating fault must declare a compensation path.

        The refusal is the existing rule, not a new one; Phase 1 adds no
        second enforcement point, so there is nothing to disagree with.
        """
        document = {**_copy(_V1_MINOR1_DOCUMENT), "permissions": ["target:mutate", "target:read"]}
        document["faultDeclarations"] = [
            {
                **document["faultDeclarations"][0],
                "reversible": False,
            }
        ]
        with pytest.raises(ValidationError, match="compensation path"):
            _metadata(document)

    def test_mutating_fault_must_require_target_mutate(self) -> None:
        document = {**_copy(_V1_MINOR1_DOCUMENT), "permissions": ["target:mutate", "target:read"]}
        document["faultDeclarations"] = [
            {
                **document["faultDeclarations"][0],
                "requiredPermissions": ["target:read"],
            }
        ]
        with pytest.raises(ValidationError, match="target:mutate"):
            _metadata(document)

    def test_fault_requesting_an_undeclared_capability_is_refused(self) -> None:
        document = {**_copy(_FROZEN_V1_DOCUMENT)}
        document["faultDeclarations"] = [
            {**document["faultDeclarations"][0], "capability": "injector.teleport"}
        ]
        with pytest.raises(ValidationError, match="declared capability"):
            _metadata(document)

    def test_fault_requesting_an_undeclared_capability_is_refused_at_load(
        self, tmp_path: Path
    ) -> None:
        """The same refusal, through the load path, not just the constructor.

        Loading a catalog is the boundary a third-party artifact actually
        crosses, so the refusal has to survive the trip through a document on
        disk rather than only through a Python call.
        """
        from mayhem.providers.loader import ProviderLoader

        document = {
            "providers": [
                {
                    "metadata": {
                        **_FROZEN_V1_DOCUMENT,
                        "faultDeclarations": [
                            {
                                **_FROZEN_V1_DOCUMENT["faultDeclarations"][0],
                                "capability": "injector.teleport",
                            }
                        ],
                    },
                    "implementation": {
                        "kind": "entry_point",
                        "target": "acme.injector",
                    },
                }
            ]
        }
        catalog = tmp_path / "catalog.json"
        catalog.write_text(json.dumps(document), encoding="utf-8")
        loader = ProviderLoader(registry=ProviderRegistry(allowed_permissions=frozenset()))
        with pytest.raises(Exception) as caught:  # the refusal type is loader-owned
            loader.load_catalog(catalog)
        assert "declared capability" in str(caught.value)

    def test_fault_requesting_an_undeclared_locator_is_refused(self) -> None:
        document = {**_copy(_FROZEN_V1_DOCUMENT)}
        document["faultDeclarations"] = [
            {**document["faultDeclarations"][0], "target_locator_ids": ["acme.other.target"]}
        ]
        with pytest.raises(ValidationError, match="target locators must be declared"):
            _metadata(document)

    def test_duplicate_fault_ids_are_refused(self) -> None:
        document = {**_copy(_FROZEN_V1_DOCUMENT)}
        declaration = document["faultDeclarations"][0]
        document["faultDeclarations"] = [declaration, dict(declaration)]
        with pytest.raises(ValidationError, match="fault ids must be unique"):
            _metadata(document)

    def test_compatibility_bounds_excluding_the_running_version_are_refused(self) -> None:
        metadata = _metadata(_V1_MINOR1_DOCUMENT)
        with pytest.raises(ProviderCompatibilityError) as caught:
            ensure_compatibility_bounds(metadata, running_version="2.1.0")
        assert caught.value.code == "provider_version_unsupported"
        assert "2.1.0" in str(caught.value)

    def test_bounds_excluding_this_core_block_registration(self) -> None:
        """The negative control at the gate the loader will use in Phase 2.

        ``ensure_compatibility_bounds`` is the check; the loader wiring that
        calls it during ``load_catalog`` is Phase 2's job and is deliberately
        not faked here — this test stops at the pure gate and says so.
        """
        metadata = _metadata(_V1_MINOR1_DOCUMENT)
        with pytest.raises(ProviderCompatibilityError):
            ensure_compatibility_bounds(metadata, running_version="1.0.9")

    def test_evidence_mapping_for_an_undeclared_fault_is_refused(self) -> None:
        document = {**_copy(_V1_MINOR1_DOCUMENT)}
        document["evidenceMappings"] = [
            {**document["evidenceMappings"][0], "fault_id": "acme.packet.loss"}
        ]
        with pytest.raises(ValidationError, match="undeclared fault"):
            _metadata(document)

    def test_evidence_mapping_must_name_the_published_schema(self) -> None:
        document = {**_copy(_V1_MINOR1_DOCUMENT)}
        document["evidenceMappings"] = [
            {**document["evidenceMappings"][0], "schema_name": "someone-elses-evidence"}
        ]
        with pytest.raises(ValidationError, match="names schema"):
            _metadata(document)

    def test_evidence_mapping_may_not_invent_fields(self) -> None:
        document = {**_copy(_V1_MINOR1_DOCUMENT)}
        document["evidenceMappings"] = [
            {**document["evidenceMappings"][0], "fields": ["outcome", "root_cause"]}
        ]
        with pytest.raises(ValidationError, match="does not have"):
            _metadata(document)

    def test_fault_may_not_carry_parameters_the_grammar_omits(self) -> None:
        document = {**_copy(_V1_MINOR1_DOCUMENT)}
        document["faultDeclarations"] = [
            {
                **document["faultDeclarations"][0],
                "parameters": {**document["faultDeclarations"][0]["parameters"], "burst": "3"},
            }
        ]
        with pytest.raises(ValidationError, match="parameter grammar"):
            _metadata(document)


# ── the declaration graph, read back ─────────────────────────────────────────


class TestDeclarationViews:
    def test_declared_ids_are_derived_not_stored(self) -> None:
        metadata = _metadata(_V1_MINOR1_DOCUMENT)
        assert metadata.capability_ids == frozenset({"chaos.mutate"})
        assert metadata.target_locator_ids == frozenset({"acme.chaos.target"})
        assert metadata.declared_fault_ids == frozenset({"acme.packet.latency"})
        assert metadata.fault_declaration["acme.packet.latency"].risk.value == "high"

    def test_evidence_for_resolves_through_the_mapping(self) -> None:
        metadata = _metadata(_V1_MINOR1_DOCUMENT)
        assert metadata.evidence_for("acme.packet.latency") is metadata.evidence_schema
        assert metadata.evidence_for("acme.packet.loss") is None

    def test_no_mapping_means_silence_not_absence(self) -> None:
        """A provider with no evidence mappings is not claiming to write none."""
        metadata = _metadata(_FROZEN_V1_DOCUMENT)
        assert metadata.evidence_for("acme.packet.drop") is None
        assert metadata.evidence_schema.name == "acme-injector-evidence"

    def test_source_and_homepage_survive_the_wire(self) -> None:
        metadata = _metadata(
            {**_copy(_V1_MINOR1_DOCUMENT), "source": "entry_point", "homepage": "https://x"}
        )
        assert metadata.source is ProviderSource.ENTRY_POINT
        assert _dump(metadata)["source"] == "entry_point"


# ── parameter grammar ────────────────────────────────────────────────────────


class TestParameterGrammar:
    def test_defaults_satisfy_optional_parameters(self) -> None:
        fault = _metadata(_V1_MINOR1_DOCUMENT).fault_declarations[0]
        assert fault_parameter_problems(fault, {"percent": "10"}) == ()
        delay = fault.parameter("delay_s")
        assert delay is not None
        assert delay.default == "1"

    @pytest.mark.parametrize(
        ("values", "expected"),
        [
            ({"percent": "101"}, "at most 100"),
            ({"percent": "10.5"}, "whole number"),
            ({"percent": "ten"}, "must be a number"),
            ({"percent": "10", "delay_s": "-1"}, "at least 0"),
            ({}, "is required"),
            ({"percent": "10", "burst": "3"}, "is not declared"),
        ],
    )
    def test_values_are_checked_against_the_grammar(
        self, values: dict[str, str], expected: str
    ) -> None:
        fault = _metadata(_V1_MINOR1_DOCUMENT).fault_declarations[0]
        problems = fault_parameter_problems(fault, values)
        assert any(expected in problem for problem in problems), problems

    def test_a_fault_without_a_grammar_still_checks_nothing(self) -> None:
        """Pre-grammar declarations keep working; a missing grammar is not an error."""
        fault = _metadata(_FROZEN_V1_DOCUMENT).fault_declarations[0]
        assert fault.parameter_grammar == ()
        assert fault_parameter_problems(fault, {"percent": "anything at all"}) == ()

    def test_enum_and_json_grammars(self) -> None:
        fault = FaultDeclaration.model_validate(
            {
                "id": "acme.packet.mode",
                "capability": "injector.inject",
                "summary": "Chooses a mode.",
                "parameterGrammar": [
                    {"name": "mode", "kind": "enum", "choices": ("drop", "duplicate")},
                    {
                        "name": "rules",
                        "kind": "json",
                        "required": False,
                        "default": "{}",
                    },
                ],
            }
        )
        assert fault_parameter_problems(fault, {"mode": "drop", "rules": '{"a": 1}'}) == ()
        assert "one of drop, duplicate" in fault_parameter_problems(fault, {"mode": "burst"})[0]
        assert "must be JSON" in fault_parameter_problems(fault, {"mode": "drop", "rules": "{"})[0]

    def test_parameter_grammar_rejects_contradictions(self) -> None:
        with pytest.raises(ValidationError, match="minimum cannot exceed"):
            ParameterDeclaration(name="n", kind=ParameterKind.INTEGER, minimum=5, maximum=1)
        with pytest.raises(ValidationError, match="enum parameters"):
            ParameterDeclaration(name="s", kind=ParameterKind.STRING, choices=("a",))
        with pytest.raises(ValidationError, match="numeric bounds"):
            ParameterDeclaration(name="s", kind=ParameterKind.STRING, minimum=1)
        with pytest.raises(ValidationError, match="must declare a default"):
            ParameterDeclaration(name="s", required=False)
        with pytest.raises(ValidationError, match="lowercase identifier"):
            ParameterDeclaration(name="Percent")
        with pytest.raises(ValidationError, match="pattern does not compile"):
            ParameterDeclaration(name="s", pattern="[unclosed")

    def test_duplicate_parameter_names_are_refused(self) -> None:
        document = {**_copy(_V1_MINOR1_DOCUMENT)}
        document["faultDeclarations"] = [
            {
                **document["faultDeclarations"][0],
                "parameterGrammar": [
                    {"name": "percent", "kind": "integer"},
                    {"name": "percent", "kind": "integer"},
                ],
            }
        ]
        with pytest.raises(ValidationError, match="unique"):
            _metadata(document)

    @pytest.mark.parametrize("kind", [kind.value for kind in ParameterKind])
    def test_every_parameter_kind_survives_the_wire(self, kind: str) -> None:
        """The value grammar is a closed vocabulary and every member is a contract.

        A kind added later must round-trip like the rest, or an SDK in one of the
        three languages would emit something a core silently misreads.
        """
        fault = FaultDeclaration.model_validate(
            {
                "id": "acme.packet.mode",
                "capability": "injector.inject",
                "summary": "Chooses a mode.",
                "parameterGrammar": [{"name": "value", "kind": kind}],
            }
        )
        dumped = fault.model_dump(mode="json", by_alias=True)
        assert dumped["parameterGrammar"][0]["kind"] == kind
        assert FaultDeclaration.model_validate(dumped) == fault


# ── the pieces, in isolation ─────────────────────────────────────────────────


class TestDescriptorsInIsolation:
    def test_capability_descriptor_keeps_its_contract(self) -> None:
        with pytest.raises(ValidationError, match="target:mutate"):
            CapabilityDescriptor(id="c.mutate", summary="s", mutates_targets=True)
        with pytest.raises(ValidationError, match="must mutate targets"):
            CapabilityDescriptor(id="c.read", summary="s", compensable=True)

    def test_evidence_mapping_validates_its_own_shape(self) -> None:
        with pytest.raises(ValidationError, match="dotted identifier"):
            EvidenceMapping(fault_id="Nope", schema_name="n", schema_version="1.0")
        with pytest.raises(ValidationError, match=r"major\.minor"):
            EvidenceMapping(fault_id="a.b", schema_name="n", schema_version="v1")
        with pytest.raises(ValidationError, match="unique"):
            EvidenceMapping(
                fault_id="a.b",
                schema_name="n",
                schema_version="1.0",
                fields=("x", "x"),
            )

    def test_evidence_schema_keeps_its_contract(self) -> None:
        with pytest.raises(ValidationError, match="name and fields"):
            EvidenceSchema(name="", version="1.0")
        with pytest.raises(ValidationError, match="semantic versioning"):
            EvidenceSchema(name="n", version="1")

    def test_mutation_enum_names_are_the_wire_values(self) -> None:
        assert ProviderMutation.READ_ONLY.value == "read_only"
        assert ProviderMutation.MUTATING.value == "mutating"
