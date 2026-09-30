"""Loading a fault pack off disk: what a load establishes, and what it refuses.

The load path is the only place in mayhem where content authored by someone
else becomes part of a chaos run, so these tests are written adversarially:
most of them assert a *refusal*, and the ones that assert success also assert
the exact trust statement that came with it.

The central claim under test, restated in code because it is the whole point of
the format: mayhem verifies a pack's **content digest** and cannot verify its
**signature**. ``FaultPack.signature`` is a bare string with no key, no
algorithm, and no trust store behind it, so ``signature_verified`` is a
``False`` that is reported rather than a ``True`` that is assumed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.domain.catalog import CATALOG
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.faults import FaultDefinition
from mayhem.providers.builtin import create_builtin_registry
from mayhem.providers.loader import (
    LoadedPack,
    PackLoader,
    PackRuntime,
    builtin_fault_ids,
    pack_definitions,
    read_pack_document,
)
from mayhem.providers.pack import (
    SIGNATURE_TRUST_NOTICE,
    SIGNATURE_VERIFICATION_IMPLEMENTED,
    FaultPack,
    PackValidationError,
    pack_assurance,
)
from mayhem.providers.permissions import ProviderPermissionSet

MUTATING = ("target:read", "target:mutate")

#: A free id in a category mayhem implements, so the fixture is refused for the
#: reason under test rather than for an incidental catalog collision.
FREE_FAULT_ID = "net.jitter_burst"
#: A real built-in fault, used to prove a pack cannot shadow it.
BUILTIN_FAULT_ID = "net.latency"


def _fault(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": FREE_FAULT_ID,
        "target": "checkout",
        "risk": "medium",
        "reversible": True,
        "compensation": "restore the original jitter profile",
        "observable_effect": "request jitter rises on the checkout path",
    }
    payload.update(overrides)
    return payload


def _document(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "manifest": {"provider_id": "acme.packs", "version": "1.2.3"},
        "faults": [_fault()],
        "signature": "sig-abc",
        "signer": "acme",
    }
    payload.update(overrides)
    return payload


def _stamped(document: dict[str, Any]) -> dict[str, Any]:
    """A document whose ``declared_digest`` genuinely matches its own content.

    Every "valid pack" fixture goes through this, so a test that expects a
    success is never accidentally passing because the digest check never ran.
    """
    pack = FaultPack.model_validate(document)
    signed = pack.model_copy(update={"declared_digest": pack.pack_digest()})
    return json.loads(signed.model_dump_json())


def _write(tmp_path: Path, document: Any, *, name: str = "pack.json") -> Path:
    path = tmp_path / name
    text = document if isinstance(document, str) else json.dumps(document)
    path.write_text(text, encoding="utf-8")
    return path


def _loader(*, allow_development_only: bool = False) -> PackLoader:
    return PackLoader(
        grants={"acme.packs": ProviderPermissionSet.from_names("acme.packs", MUTATING)},
        allow_development_only=allow_development_only,
    )


def _build_loader_for_test(
    path: Path, *, permissions: tuple[str, ...], allow_development_only: bool
) -> PackLoader:
    """The CLI's own grant-resolution helper, exercised directly.

    Imported rather than reimplemented so a change to the CLI's grant scoping
    cannot silently diverge from what this test asserts about it.
    """
    from mayhem.cli.pack import _build_loader

    return _build_loader(
        path, allow_development_only=allow_development_only, permissions=permissions
    )


# ── the format's signature scheme is not a signature scheme ─────────────────


def test_the_pack_format_declares_no_signature_verification_mechanism() -> None:
    """The premise of every other test in this file, asserted outright.

    If a future change makes ``SIGNATURE_VERIFICATION_IMPLEMENTED`` true, the
    whole refusal surface below needs re-examining, so this test is written to
    fail loudly rather than to be quietly updated.
    """
    assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
    assert "cannot verify" in SIGNATURE_TRUST_NOTICE
    assert "provenance" in SIGNATURE_TRUST_NOTICE


def test_a_signature_string_is_never_reported_as_verified() -> None:
    """Any non-empty signature string, of any shape, proves nothing."""
    for signature in ("sig-abc", "", "x", "a" * 512, "-----BEGIN FAKE-----", "🔏"):
        pack = FaultPack.model_validate(_document(signature=signature, signer="acme"))
        assurance = pack_assurance(pack, digest_verified=True)
        assert assurance["signature_verified"] is False
        assert assurance["signer_trusted"] is False
        if signature:
            # Present but unverified: the only honest reading of a claim.
            assert assurance["assurance"] == "integrity-only"
        else:
            assert assurance["assurance"] == "none"


# ── a well-formed pack loads and the registry can see it ─────────────────────


def test_a_well_formed_pack_loads_into_the_provider_registry(tmp_path: Path) -> None:
    registry = create_builtin_registry()
    before = set(registry.ids())
    loaded = _loader().load_into(_write(tmp_path, _stamped(_document())), registry)

    assert loaded.pack.manifest.provider_id == "acme.packs"
    assert "acme.packs" in registry.ids()
    assert before <= registry.ids(), "loading a pack must not evict a built-in provider"
    metadata = registry.registration("acme.packs").metadata
    assert metadata.source == "catalog"
    assert [d.id for d in metadata.fault_declarations] == [FREE_FAULT_ID]


def test_the_registered_runtime_is_truthful_about_not_being_executable(tmp_path: Path) -> None:
    registry = create_builtin_registry()
    _loader().load_into(_write(tmp_path, _stamped(_document())), registry)
    runtime = registry.runtime("acme.packs")

    assert isinstance(runtime, PackRuntime)
    assert runtime.executable is False
    assert runtime.fault_ids == (FREE_FAULT_ID,)
    assert runtime.signer_claimed == "acme"


def test_a_loaded_pack_reports_integrity_but_not_provenance(tmp_path: Path) -> None:
    loaded = _loader().load_file(_write(tmp_path, _stamped(_document())))

    assert loaded.assurance.digest_verified is True
    assert loaded.assurance.signature_present is True
    assert loaded.assurance.signature_verified is False
    assert loaded.assurance.signature_scheme == "none"
    assert loaded.assurance.assurance == "integrity-only"
    assert loaded.assurance.notice == SIGNATURE_TRUST_NOTICE
    assert loaded.report["assurance"]["signature_verified"] is False


def test_a_pack_without_a_declared_digest_loads_but_reports_no_integrity(
    tmp_path: Path,
) -> None:
    """A missing digest is not a verified digest; the flag must say so."""
    loaded = _loader().load_file(_write(tmp_path, _document()))

    assert loaded.assurance.digest_verified is False
    assert loaded.assurance.signature_verified is False


# ── the loader's output uses the existing catalog_only machinery ─────────────


def test_pack_faults_surface_as_catalog_only_definitions(tmp_path: Path) -> None:
    loaded = _loader().load_file(_write(tmp_path, _stamped(_document())))

    (definition,) = loaded.definitions
    assert isinstance(definition, FaultDefinition)
    assert definition.id == FREE_FAULT_ID
    assert definition.catalog_only is True
    assert definition.refusal_reason
    assert "cannot verify" in definition.refusal_reason
    # The refusal names the pack and the signer, so a verdict traces to source.
    assert "acme.packs" in definition.refusal_reason
    assert "acme" in definition.refusal_reason


def test_pack_definitions_satisfy_the_shared_catalog_contract() -> None:
    """The same ``validate_catalog`` that gates built-ins gates pack entries."""
    pack = FaultPack.model_validate(_document())
    definitions = pack_definitions(pack)
    assert definitions
    for definition in definitions:
        assert definition.catalog_only is True
        assert definition.failure_domain is not None
        assert definition.verification_method is not None
        assert definition.reversibility is not None
        assert definition.compensation_evidence


def test_a_pack_fault_id_that_mayhem_cannot_classify_is_refused() -> None:
    """A ``pack.``-prefixed id cannot join the catalog, and must not be dropped."""
    pack = FaultPack.model_validate(_document(faults=[_fault(id="pack.jitter")]))
    with pytest.raises(SchemaValidationError) as excinfo:
        pack_definitions(pack)
    assert "category prefix" in str(excinfo.value)


# ── digest refusals ──────────────────────────────────────────────────────────


def test_digest_mismatch_is_refused_naming_both_digests(tmp_path: Path) -> None:
    document = _stamped(_document())
    real = document["declared_digest"]
    document["declared_digest"] = "0" * 64
    path = _write(tmp_path, document)

    with pytest.raises(PackValidationError) as excinfo:
        _loader().load_file(path)

    message = str(excinfo.value)
    assert "digest mismatch" in message
    assert "0" * 64 in message, "the declared digest must be printed in full"
    assert real in message, "the computed digest must be printed in full"


def test_a_pinned_expected_digest_that_disagrees_is_refused(tmp_path: Path) -> None:
    document = _stamped(_document())
    real = document["declared_digest"]

    with pytest.raises(PackValidationError, match="does not match the expected"):
        _loader().load_file(_write(tmp_path, document), expected_digest="f" * 64)

    # ... and the matching pin is accepted, so the check is not a blanket refusal.
    loaded = _loader().load_file(_write(tmp_path, document), expected_digest=real)
    assert loaded.assurance.digest == real


# ── signature and development-only refusals ──────────────────────────────────


def test_an_unsigned_pack_is_refused_by_default_and_the_refusal_names_the_flag(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, _stamped(_document(signature="", signer="")))

    with pytest.raises(PackValidationError) as excinfo:
        _loader().load_file(path)

    assert "unsigned" in str(excinfo.value)
    assert "--allow-development-only" in str(excinfo.value)


def test_an_unsigned_pack_loads_only_when_explicitly_opted_in(tmp_path: Path) -> None:
    path = _write(tmp_path, _stamped(_document(signature="", signer="")))
    loaded = _loader(allow_development_only=True).load_file(path)

    assert loaded.assurance.signature_present is False
    assert loaded.assurance.signature_verified is False
    assert loaded.assurance.assurance == "none"
    assert loaded.assurance.development_only is True


def test_a_development_only_pack_is_refused_by_default_naming_the_flag(tmp_path: Path) -> None:
    """``development_only`` is honoured as a field, not only as a side effect."""
    path = _write(tmp_path, _stamped(_document(development_only=True)))

    with pytest.raises(PackValidationError) as excinfo:
        _loader().load_file(path)

    message = str(excinfo.value)
    assert "development_only" in message
    assert "--allow-development-only" in message


def test_a_development_only_pack_loads_when_opted_in(tmp_path: Path) -> None:
    path = _write(tmp_path, _stamped(_document(development_only=True)))
    loaded = _loader(allow_development_only=True).load_file(path)

    assert loaded.assurance.development_only is True
    # Opting in to a development-only pack buys no provenance whatsoever.
    assert loaded.assurance.signature_verified is False


def test_a_signed_pack_naming_no_signer_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, _stamped(_document(signer="")))
    with pytest.raises(PackValidationError, match="names no signer"):
        _loader().load_file(path)


def test_a_pack_with_a_signature_and_no_key_field_still_loads_only_as_unverified(
    tmp_path: Path,
) -> None:
    """There is no key field to check, so acceptance must be downgraded, not upgraded."""
    document = _stamped(_document(signature="-----BEGIN SIGNATURE-----\nZm9yZ2Vk\n"))
    assert "public_key" not in json.dumps(document)

    loaded = _loader().load_file(_write(tmp_path, document))
    assert loaded.assurance.signature_verified is False
    assert loaded.assurance.assurance == "integrity-only"


# ── shadowing refusals ───────────────────────────────────────────────────────


def test_a_pack_redeclaring_a_builtin_fault_id_is_refused(tmp_path: Path) -> None:
    assert BUILTIN_FAULT_ID in builtin_fault_ids()
    path = _write(tmp_path, _stamped(_document(faults=[_fault(id=BUILTIN_FAULT_ID)])))

    with pytest.raises(PackValidationError) as excinfo:
        _loader().load_file(path)

    message = str(excinfo.value)
    assert BUILTIN_FAULT_ID in message
    assert "shadow" in message


def test_a_pack_cannot_shadow_a_builtin_provider_id(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _stamped(_document(manifest={"provider_id": "docker", "version": "1.0.0"})),
    )
    with pytest.raises(PackValidationError, match="built-in mayhem provider"):
        _loader().load_file(path)


def test_register_refuses_definitions_that_entered_the_reserved_set_after_loading(
    tmp_path: Path,
) -> None:
    """Loading and registering are separate gates; a late collision still refuses."""
    registry = create_builtin_registry()
    loaded = _loader().load_file(_write(tmp_path, _stamped(_document())))

    with pytest.raises(PackValidationError, match="already mayhem catalog faults"):
        _loader().register(loaded, registry, reserved_fault_ids=frozenset({FREE_FAULT_ID}))

    assert "acme.packs" not in registry.ids()


def test_builtin_fault_ids_is_read_live_not_cached() -> None:
    assert builtin_fault_ids() == frozenset(definition.id for definition in CATALOG)


# ── the loader refuses to be tricked ─────────────────────────────────────────


def test_a_mutated_body_with_a_stale_digest_is_refused(tmp_path: Path) -> None:
    """Valid digest, edited body: the exact shape of a tampered pack."""
    document = _stamped(_document())
    document["faults"][0]["compensation"] = "do nothing at all"
    path = _write(tmp_path, document)

    with pytest.raises(PackValidationError, match="digest mismatch"):
        _loader().load_file(path)


def test_a_digest_covering_only_its_own_field_cannot_launder_a_body_change(
    tmp_path: Path,
) -> None:
    """Re-stamping the digest after an edit is *not* a forgery, and must be accepted.

    The digest is integrity, not authorship. Refusing this would mean claiming
    to detect tampering we cannot detect; accepting it while continuing to
    report ``signature_verified: False`` is the honest pair.
    """
    document = _stamped(_document())
    document["faults"][0]["observable_effect"] = "something else entirely"
    restamped = _stamped(document)
    loaded = _loader().load_file(_write(tmp_path, restamped))

    assert loaded.assurance.digest_verified is True
    assert loaded.assurance.signature_verified is False


def test_a_registration_declaring_a_fault_the_pack_does_not_define_is_refused(
    tmp_path: Path,
) -> None:
    """A hand-built or drifted registration must not register as a half-truth."""
    from mayhem.domain.provider import FaultDeclaration

    loaded = _loader().load_file(_write(tmp_path, _stamped(_document())))
    phantom = FaultDeclaration(
        id="net.phantom_fault",
        capability="acme.packs.pack",
        summary="a fault the pack never defined",
    )
    tampered = LoadedPack(
        pack=loaded.pack,
        registration=loaded.registration.model_copy(
            update={
                "metadata": loaded.registration.metadata.model_copy(
                    update={
                        "fault_declarations": (
                            *loaded.registration.metadata.fault_declarations,
                            phantom,
                        )
                    }
                )
            }
        ),
        definitions=loaded.definitions,
        assurance=loaded.assurance,
        report=loaded.report,
        path=loaded.path,
    )

    with pytest.raises(PackValidationError, match="declares faults it does not define"):
        _loader().register(tampered, create_builtin_registry())


def test_a_registration_dropping_a_fault_the_pack_defines_is_refused(tmp_path: Path) -> None:
    loaded = _loader().load_file(_write(tmp_path, _stamped(_document())))
    dropped = LoadedPack(
        pack=loaded.pack,
        registration=loaded.registration.model_copy(
            update={
                "metadata": loaded.registration.metadata.model_copy(
                    update={"fault_declarations": ()}
                )
            }
        ),
        definitions=loaded.definitions,
        assurance=loaded.assurance,
        report=loaded.report,
        path=loaded.path,
    )

    with pytest.raises(PackValidationError, match="defines faults it does not declare"):
        _loader().register(dropped, create_builtin_registry())


@pytest.mark.parametrize(
    "target",
    [
        "../../etc/passwd",
        "..",
        "a/../../b",
        "..\\windows\\system32",
        "~/root/.ssh",
        "~",
    ],
)
def test_path_traversal_in_a_pack_supplied_target_is_refused(tmp_path: Path, target: str) -> None:
    path = _write(tmp_path, _stamped(_document(faults=[_fault(target=target)])))
    with pytest.raises(PackValidationError, match="unsafe target"):
        _loader().load_file(path)


def test_a_nul_byte_in_a_target_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, _stamped(_document(faults=[_fault(target="checkout\x00/etc")])))
    with pytest.raises(PackValidationError, match="NUL byte"):
        _loader().load_file(path)


def test_path_traversal_in_a_pack_supplied_homepage_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _stamped(
            _document(
                manifest={
                    "provider_id": "acme.packs",
                    "version": "1.2.3",
                    "homepage": "https://acme.example/../../etc/passwd",
                }
            )
        ),
    )
    with pytest.raises(PackValidationError, match="homepage"):
        _loader().load_file(path)


def test_a_non_http_homepage_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _stamped(
            _document(
                manifest={
                    "provider_id": "acme.packs",
                    "version": "1.2.3",
                    "homepage": "file:///etc/shadow",
                }
            )
        ),
    )
    with pytest.raises(PackValidationError, match="not an http"):
        _loader().load_file(path)


def test_a_fault_asking_for_action_permissions_without_target_mutate_is_refused(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, _stamped(_document(faults=[_fault(permissions=["subprocess"])])))
    with pytest.raises(PackValidationError, match="without target:mutate"):
        _loader().load_file(path)


def test_an_irreversible_fault_claiming_target_mutate_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _stamped(
            _document(
                faults=[
                    _fault(reversible=False, compensation="reconcile later", permissions=["target:mutate"])
                ]
            )
        ),
    )
    with pytest.raises(PackValidationError, match="must be reversible"):
        _loader().load_file(path)


def test_an_unknown_risk_level_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, _stamped(_document(faults=[_fault(risk="catastrophic")])))
    with pytest.raises(PackValidationError, match="unknown risk"):
        _loader().load_file(path)


def test_a_non_semver_provider_version_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path, _stamped(_document(manifest={"provider_id": "acme.packs", "version": "v1"}))
    )
    with pytest.raises(PackValidationError, match="semantic versioning"):
        _loader().load_file(path)


def test_a_pack_without_an_explicit_mutate_grant_is_refused(tmp_path: Path) -> None:
    """The default posture is read-only; a mutating pack must be granted."""
    path = _write(tmp_path, _stamped(_document()))
    with pytest.raises(PackValidationError, match="target:mutate"):
        PackLoader().load_file(path)


# ── malformed input is a message, not a stack trace ──────────────────────────


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("{not json", "not valid JSON"),
        ("", "empty"),
        ("   \n ", "empty"),
        ("[1, 2, 3]", "not a JSON object"),
        ('"a string"', "not a JSON object"),
        ("42", "not a JSON object"),
        ("null", "not a JSON object"),
    ],
)
def test_a_malformed_pack_file_is_refused_readably(
    tmp_path: Path, body: str, expected: str
) -> None:
    path = _write(tmp_path, body)
    with pytest.raises(PackValidationError, match=expected):
        _loader().load_file(path)


def test_a_non_utf8_pack_file_is_refused_readably(tmp_path: Path) -> None:
    path = tmp_path / "pack.json"
    path.write_bytes(b"\xff\xfe\x00binary junk")
    with pytest.raises(PackValidationError, match="not UTF-8"):
        _loader().load_file(path)


def test_a_missing_pack_file_is_refused_readably(tmp_path: Path) -> None:
    with pytest.raises(PackValidationError, match="cannot read fault pack"):
        _loader().load_file(tmp_path / "absent.json")


def test_a_directory_is_refused_readably(tmp_path: Path) -> None:
    with pytest.raises(PackValidationError, match="directory"):
        _loader().load_file(tmp_path)


def test_a_schema_violating_document_is_refused_readably(tmp_path: Path) -> None:
    path = _write(tmp_path, {"schema_version": "1.0", "manifest": {"nope": 1}, "surprise": True})
    with pytest.raises(PackValidationError, match="invalid pack document"):
        _loader().load_file(path)


def test_inspect_file_never_raises_and_always_explains_itself(tmp_path: Path) -> None:
    loader = _loader()
    refused = loader.inspect_file(_write(tmp_path, {"garbage": True}))
    assert refused["loadable"] is False
    assert refused["reason"]

    ok = loader.inspect_file(_write(tmp_path, _stamped(_document())))
    assert ok["loadable"] is True
    assert ok["assurance"]["signature_verified"] is False
    assert json.dumps(ok, sort_keys=True)


def test_read_pack_document_returns_the_document_and_the_bytes_digest(tmp_path: Path) -> None:
    path = _write(tmp_path, _stamped(_document()))
    document, file_digest = read_pack_document(path)

    assert document["manifest"]["provider_id"] == "acme.packs"
    assert len(file_digest) == 64
    # The bytes digest and the pack digest are different things and both matter.
    assert file_digest != document["declared_digest"]


# ── the CLI reports the same honesty ─────────────────────────────────────────


def _invoke(*args: str) -> Any:
    return CliRunner().invoke(app, ["pack", *args])


def test_pack_validate_reports_the_trust_statement(tmp_path: Path) -> None:
    result = _invoke("validate", str(_write(tmp_path, _stamped(_document()))))

    assert result.exit_code == 0
    assert "NOT VERIFIED" in result.output
    assert "integrity-only" in result.output
    assert "cannot verify fault-pack signatures" in result.output


def test_pack_validate_json_carries_both_axes(tmp_path: Path) -> None:
    result = _invoke("validate", str(_write(tmp_path, _stamped(_document()))), "--json")

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["assurance"]["digest_verified"] is True
    assert payload["assurance"]["signature_verified"] is False
    assert payload["assurance"]["notice"] == SIGNATURE_TRUST_NOTICE


def test_pack_validate_refuses_a_bad_digest_with_a_nonzero_exit(tmp_path: Path) -> None:
    document = _stamped(_document())
    document["declared_digest"] = "0" * 64
    result = _invoke("validate", str(_write(tmp_path, document)))

    assert result.exit_code != 0
    assert "digest mismatch" in result.output
    assert "0" * 64 in result.output
    assert "Traceback" not in result.output


def test_pack_validate_refuses_an_unsigned_pack_and_names_the_flag(tmp_path: Path) -> None:
    path = _write(tmp_path, _stamped(_document(signature="", signer="")))
    result = _invoke("validate", str(path))

    assert result.exit_code != 0
    assert "--allow-development-only" in result.output


def test_pack_validate_loads_an_unsigned_pack_when_the_flag_is_passed(tmp_path: Path) -> None:
    path = _write(tmp_path, _stamped(_document(signature="", signer="")))
    result = _invoke("validate", str(path), "--allow-development-only")

    assert result.exit_code == 0
    assert "ABSENT (pack is unsigned)" in result.output
    # An unsigned pack earns no integrity-or-better claim, however it was loaded.
    assert "assurance       none" in result.output


def test_an_unsigned_pack_is_never_reported_as_signed(tmp_path: Path) -> None:
    """The one thing a pack with no signature must never be described as."""
    path = _write(tmp_path, _stamped(_document(signature="", signer="")))

    # Without the flag it is refused outright, so there is no verdict to parse.
    refused = _invoke("validate", str(path), "--json")
    assert refused.exit_code != 0
    assert "NOT VERIFIED" not in refused.output

    # With the flag it loads, and is reported as unsigned, never as signed.
    allowed = _invoke("validate", str(path), "--allow-development-only", "--json")
    assert allowed.exit_code == 0
    assurance = json.loads(allowed.output)["assurance"]
    assert assurance["signature_present"] is False
    assert assurance["signature_verified"] is False
    assert assurance["assurance"] == "none"


def test_pack_load_registers_and_reports_catalog_only(tmp_path: Path) -> None:
    result = _invoke(
        "load",
        str(_write(tmp_path, _stamped(_document()))),
        "--allow-permission",
        "target:mutate",
    )

    assert result.exit_code == 0
    assert "registered 'acme.packs'" in result.output
    assert "catalog-only" in result.output
    assert "cannot verify" in result.output


def test_pack_load_json_shows_the_registry_sees_the_pack(tmp_path: Path) -> None:
    result = _invoke(
        "load",
        str(_write(tmp_path, _stamped(_document()))),
        "--allow-permission",
        "target:mutate",
        "--json",
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["registry"]["registered"] is True
    assert payload["registry"]["pack_provider_id"] in payload["registry"]["provider_ids"]
    assert payload["registry"]["contributed_fault_ids"] == [FREE_FAULT_ID]
    assert "docker" in payload["registry"]["provider_ids"]


def test_pack_load_refuses_a_shadowing_pack(tmp_path: Path) -> None:
    path = _write(tmp_path, _stamped(_document(faults=[_fault(id=BUILTIN_FAULT_ID)])))
    result = _invoke("load", str(path), "--allow-permission", "target:mutate")

    assert result.exit_code != 0
    assert BUILTIN_FAULT_ID in result.output
    assert "Traceback" not in result.output


def test_pack_load_list_names_only_contributed_ids(tmp_path: Path) -> None:
    result = _invoke(
        "load",
        str(_write(tmp_path, _stamped(_document()))),
        "--allow-permission",
        "target:mutate",
        "--list",
    )

    assert result.exit_code == 0
    assert FREE_FAULT_ID in result.output
    assert BUILTIN_FAULT_ID not in result.output


def test_a_grant_to_one_provider_never_widens_another(tmp_path: Path) -> None:
    """A grant names one provider; it is not a global capability.

    This is the property that makes ``--allow-permission`` safe to pass on a
    per-pack command at all. The CLI resolves the grant against the pack's own
    provider id for the same reason.
    """
    other = _write(
        tmp_path,
        _stamped(
            _document(
                manifest={"provider_id": "other.packs", "version": "1.0.0"},
                faults=[_fault(permissions=["target:mutate"])],
            )
        ),
        name="other.json",
    )
    mine = _write(tmp_path, _stamped(_document()), name="mine.json")
    loader = PackLoader()
    loader.grant("acme.packs", ProviderPermissionSet.from_names("acme.packs", MUTATING))

    assert loader.load_file(mine).pack.faults
    with pytest.raises(PackValidationError, match="other.packs") as excinfo:
        loader.load_file(other)
    assert "target:mutate" in str(excinfo.value)


def test_the_cli_grant_is_scoped_to_the_packs_own_provider(tmp_path: Path) -> None:
    """``--allow-permission`` grants this pack's provider and no other."""
    other = _write(
        tmp_path,
        _stamped(
            _document(
                manifest={"provider_id": "other.packs", "version": "1.0.0"},
                faults=[_fault(permissions=["target:mutate"])],
            )
        ),
    )
    loader = _build_loader_for_test(
        other, permissions=("target:mutate",), allow_development_only=False
    )
    assert loader.permissions_for("other.packs").mutating is True
    assert loader.permissions_for("unrelated.provider").mutating is False


def test_the_pack_command_is_registered_and_never_mutating() -> None:
    from mayhem.cli.command_registry import COMMAND_SPECS

    specs = {spec.name: spec for spec in COMMAND_SPECS}
    assert "pack" in specs
    assert specs["pack"].mutating is False
    assert specs["pack"].workflow == "extend"
    assert specs["pack"].help_group == "extension"
    assert "pack" in app.commands
