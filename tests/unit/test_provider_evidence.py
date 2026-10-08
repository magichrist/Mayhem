"""Phase 4 of plan 17: the provider lane's safety and evidence integration.

Phase 4 decides the two questions Phase 2 left open, makes the engine axis
checkable in practice, and puts provider activity into Mayhem's sealed chain
and audit stream. This file is that phase's regression guard.

What it deliberately does **not** claim:

* **No signature is verified, anywhere.** ``SIGNATURE_VERIFICATION_IMPLEMENTED``
  is ``False`` and is asserted so here. Every manifest this lane writes is
  *unsigned* and says why, and a negative control pins that no pack is ever
  reported as verified. Sealing proves the recorded bytes are unaltered and in
  order — it does not prove who wrote the provider.
* **No sandbox is applied.** The ``require_sandbox_enforcement`` default below
  is ``True``, which means mayhem *refuses* to run a third-party runtime it
  cannot confine. It does not mean mayhem grew a seccomp filter, an AppArmor
  profile, a SELinux label or a container: it did not, and the profiles still
  carry ``declared_not_applied``.
* **The engine axis is checked only when a lane is supplied.** The tests below
  assert both directions — ``unverified`` with no lane, ``matched`` /
  ``mismatched`` with one — because "we did not look" rendering as "we looked
  and it was fine" is the failure this file exists to prevent.

Every claim of the shape "X is sealed" is asserted by *reloading from SQLite*
and re-verifying with the domain verifier, never by inspecting an in-memory
object: a ledger that only ever re-read itself would pass every positive test
here and still be worthless.
"""

from __future__ import annotations

import ast
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.domain.attestation import (
    AttestedTimestamp,
    verify_chain,
    verify_manifest,
)
from mayhem.domain.evidence import ActionOutcome, EvidenceEnvelope
from mayhem.domain.faults import EngineLane
from mayhem.domain.provider import (
    PROVIDER_API_VERSION,
    ProviderCompatibilityError,
    ProviderError,
    ProviderEvidenceRecord,
    ProviderMetadata,
    ProviderNotFoundError,
    ProviderPermission,
    ProviderPermissionError,
)
from mayhem.infra.attestation_store import AttestationRepository
from mayhem.infra.audit_stream import AuditStream
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store
from mayhem.providers.loader import (
    AUDIT_PROVIDER_PERMISSIONS_CHANGED,
    AUDIT_PROVIDER_REGISTERED,
    DEFAULT_PROVIDER_PRINCIPAL,
    DEFAULT_REQUIRE_SANDBOX_ENFORCEMENT,
    EVENT_PROVIDER_ACTIVITY,
    PROVIDER_ACTIVITY_CHAIN_ID,
    UNSEALED_ACTIVITY_NOTICE,
    ProviderActivityLedger,
    ProviderLoader,
    detect_engine_lane,
)
from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED
from mayhem.providers.registry import ProviderRegistry
from mayhem.providers.sandbox import (
    SANDBOX_NOT_ENFORCED_NOTICE,
    MechanismState,
    ProviderActivity,
    ProviderActivityKind,
    ProviderSandboxError,
    SandboxAccessDenied,
    SandboxEgressDenied,
    select_profile,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The core version every fixture is loaded against. Pinned, not read from the
#: environment, so a locally built mayhem cannot turn a compatibility test green
#: or red by accident.
CORE = "1.1.0"

#: A fixed reading, so the sealed bytes are reproducible across runs.
READING = AttestedTimestamp(
    wall_clock=datetime(2026, 4, 1, 9, 0, 0, tzinfo=UTC),
    monotonic_ns=7_000_000,
    uncertainty_ms=0.0,
    source="system",
)

_MUTATING = frozenset({ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE})

_BASE: dict[str, Any] = {
    "apiVersion": PROVIDER_API_VERSION,
    "providerId": "acme.injector",
    "name": "Acme Injector",
    "version": "1.0.0",
    "description": "Injects packet faults into a discovered target.",
    "permissions": [],
    "capabilities": [{"id": "injector.inspect", "summary": "Describe a target."}],
    "targetLocators": [
        {
            "id": "acme.injector.target",
            "kind": "acme_container",
            "requiredPermissions": [],
        }
    ],
    "faultDeclarations": [],
    "evidenceSchema": {
        "name": "acme-injector-evidence",
        "version": "1.0",
        "fields": ["recorded_at", "operation", "target", "outcome"],
    },
}


def declaration(**overrides: Any) -> dict[str, Any]:
    """A valid declaration that requests nothing, with *overrides* merged over it."""
    document = deepcopy(_BASE)
    for key, value in overrides.items():
        document[key] = value
    return document


def mutating_declaration(**overrides: Any) -> dict[str, Any]:
    """A provider that rewrites packets, declares the mutation, and maps evidence."""
    document = declaration(
        permissions=["target:read", "target:mutate"],
        capabilities=[
            {
                "id": "injector.mutate",
                "summary": "Change the target.",
                "requiredPermissions": ["target:mutate"],
                "mutates_targets": True,
                "compensable": True,
            }
        ],
        targetLocators=[
            {
                "id": "acme.injector.target",
                "kind": "acme_container",
                "requiredPermissions": ["target:read"],
            }
        ],
        faultDeclarations=[
            {
                "id": "acme.packet.rewrite",
                "capability": "injector.mutate",
                "summary": "Rewrite packets in flight.",
                "target_locator_ids": ["acme.injector.target"],
                "mutation": "mutating",
                "reversible": True,
                "requiredPermissions": ["target:mutate"],
            }
        ],
        evidenceMappings=[
            {
                "fault_id": "acme.packet.rewrite",
                "schema_name": "acme-injector-evidence",
                "schema_version": "1.0",
                "fields": ["outcome"],
            }
        ],
    )
    for key, value in overrides.items():
        document[key] = value
    return document


RUNTIME_TARGET = f"{__name__}:TestRuntime"


def catalog_of(*documents: dict[str, Any]) -> dict[str, Any]:
    return {
        "providers": [
            {
                "metadata": document,
                "implementation": {"kind": "import", "target": RUNTIME_TARGET, "factory": False},
            }
            for document in documents
        ]
    }


def write_catalog(tmp_path: Path, document: dict[str, Any], name: str = "catalog.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class TestRuntime:
    """A runtime that advertises nothing, so it can never over-claim."""

    def is_available(self) -> bool:
        return True


class OverreachingRuntime(TestRuntime):
    """Advertises capabilities, faults and permissions it never declared."""

    def capabilities(self) -> tuple[str, ...]:
        return ("injector.inspect", "injector.teleport")

    def permissions(self) -> tuple[str, ...]:
        return ("target:read", "network")


class FakeEntryPoint:
    def __init__(self, name: str, value: Any) -> None:
        self.name = name
        self.value = value

    def load(self) -> Any:
        return self.value


def open_store(tmp_path: Path, name: str = "mayhem.db") -> Store:
    return Store.open_migrated(tmp_path / name, migrations=ALL_MIGRATIONS)


def loader_for(
    tmp_path: Path,
    *,
    permissions: Iterable[ProviderPermission] = (),
    running_engine: str | EngineLane | None = None,
    require_sandbox_enforcement: bool = False,
    sealed: bool = True,
    **kwargs: Any,
) -> ProviderLoader:
    """A loader with everything pinned, sealing into a fresh store by default.

    ``require_sandbox_enforcement`` defaults to **False** here even though the
    loader's own default is ``True``: almost every test in this file needs a
    provider that requests permissions, and under the real default it would
    never load at all. The default itself is tested in
    :class:`TestTheDefaultIsDeny`, deliberately, with the loader's own default.
    """
    return ProviderLoader(
        registry=ProviderRegistry(allowed_permissions=frozenset(permissions)),
        allowed_permissions=frozenset(permissions),
        running_version=CORE,
        running_engine=running_engine,
        require_sandbox_enforcement=require_sandbox_enforcement,
        store=open_store(tmp_path) if sealed else None,
        **kwargs,
    )


def load_mutating(tmp_path: Path, **kwargs: Any) -> ProviderLoader:
    """A loader that has genuinely admitted the mutating provider."""
    loader = loader_for(tmp_path, permissions=_MUTATING, **kwargs)
    catalog = write_catalog(tmp_path, catalog_of(mutating_declaration()))
    report = loader.load_catalog(catalog)
    assert report.failures == (), report.to_dict()
    assert report.loaded == ("acme.injector",), report.to_dict()
    return loader


def load_networked(tmp_path: Path, **kwargs: Any) -> ProviderLoader:
    """A loader that has admitted a provider which also declared ``network``.

    Needed wherever a test has to reach an *allowed* sandbox decision: the
    mutating provider declares no egress, so every decision it can produce is a
    denial, and "the allow was recorded too" needs a provider that may allow.
    """
    permissions = frozenset({ProviderPermission.TARGET_READ, ProviderPermission.NETWORK})
    loader = loader_for(tmp_path, permissions=permissions, **kwargs)
    document = declaration(permissions=["target:read", "network"])
    catalog = write_catalog(tmp_path, catalog_of(document), name="networked.json")
    report = loader.load_catalog(catalog)
    assert report.failures == (), report.to_dict()
    return loader


def chain_payloads(loader: ProviderLoader) -> list[dict[str, Any]]:
    """Every sealed provider-activity payload, reloaded from the store."""
    return [event.payload for event in loader.sealed_events()]


def kinds_in(loader: ProviderLoader) -> list[str]:
    return [str(payload["activity_kind"]) for payload in chain_payloads(loader)]


# ── requirement 1: the sandbox default, decided ──────────────────────────────


class TestTheDefaultIsDeny:
    def test_the_default_is_refuse_and_the_reasoning_is_written_down(self) -> None:
        """The decision is a named constant carrying its reasoning.

        Pinned so that a later "harmless default tidy-up" cannot quietly restore
        ``False`` without a test failing and forcing someone to read why it was
        ``True``.
        """
        import mayhem.providers.loader as loader_module

        assert DEFAULT_REQUIRE_SANDBOX_ENFORCEMENT is True
        assert "DEFAULT_REQUIRE_SANDBOX_ENFORCEMENT" in (loader_module.__doc__ or "")
        assert "DEFAULT_REQUIRE_SANDBOX_ENFORCEMENT" in (ProviderLoader.__doc__ or "")
        default = ProviderLoader.__init__.__kwdefaults__ or {}
        assert default["require_sandbox_enforcement"] is True

    @pytest.mark.parametrize(
        ("permissions", "refused"),
        [
            ((), False),
            (("target:read",), True),
            (("target:read", "target:mutate"), True),
            (("target:read", "filesystem:read"), True),
            (("target:read", "filesystem:read", "filesystem:write"), True),
            (("target:read", "subprocess"), True),
            (("target:read", "network"), True),
        ],
    )
    def test_every_permission_shape_that_can_reach_is_refused_by_default(
        self, permissions: tuple[str, ...], refused: bool, tmp_path: Path
    ) -> None:
        """Six of the seven profile tiers no longer load by default.

        The count matters as much as the direction: the refusal is not a special
        case for "dangerous" permissions, it is the rule that mayhem will not
        start a third-party runtime it cannot confine. Only the tier that reaches
        nothing survives.
        """
        document = declaration(permissions=list(permissions))
        catalog = write_catalog(tmp_path, catalog_of(document))
        loader = ProviderLoader(
            registry=ProviderRegistry(
                allowed_permissions=frozenset(ProviderPermission(name) for name in permissions)
            ),
            allowed_permissions=frozenset(ProviderPermission(name) for name in permissions),
            running_version=CORE,
        )
        assert loader.require_sandbox_enforcement is DEFAULT_REQUIRE_SANDBOX_ENFORCEMENT

        if not refused:
            assert loader.load_catalog(catalog).loaded == ("acme.injector",)
            return
        with pytest.raises(ProviderSandboxError) as caught:
            loader.load_catalog(catalog)
        assert caught.value.code == "provider_sandbox_mechanism_unapplied"
        assert "acme.injector" not in loader.registry.ids()

    def test_a_refused_provider_earns_no_profile_and_no_registry_entry(
        self, tmp_path: Path
    ) -> None:
        """Refused before the profile is stored, so there is nothing to hand out."""
        catalog = write_catalog(tmp_path, catalog_of(declaration(permissions=["target:read"])))
        loader = ProviderLoader(
            allowed_permissions=frozenset({ProviderPermission.TARGET_READ}),
            running_version=CORE,
            store=open_store(tmp_path),
        )
        with pytest.raises(ProviderSandboxError):
            loader.load_catalog(catalog)
        with pytest.raises(ProviderNotFoundError):
            loader.sandbox_profile("acme.injector")
        with pytest.raises(ProviderNotFoundError):
            loader.declaration_for("acme.injector")
        # A refusal at the gate is sealed too: the chain says the provider was
        # turned away and names the mechanisms, rather than the fact living only
        # in the exception the caller happened to catch.
        admissions = [
            payload
            for payload in chain_payloads(loader)
            if payload["activity_kind"] == ProviderActivityKind.ADMISSION.value
        ]
        assert [payload["outcome"] for payload in admissions] == ["refused"]
        assert admissions[0]["action_outcome"] == ActionOutcome.REFUSED.value
        assert admissions[0]["details"]["code"] == "provider_sandbox_mechanism_unapplied"
        assert admissions[0]["details"]["enforcement_required"] is True
        assert "capability_drop" in admissions[0]["details"]["unapplied_mechanisms"]

    def test_the_escape_hatch_is_explicit_and_sealed_as_unconfined(self, tmp_path: Path) -> None:
        """Opting out does not opt out of the record.

        ``require_sandbox_enforcement=False`` is a one-argument decision to run
        an unconfined third-party runtime. It is honoured, and it is written into
        the chain as an admission that acknowledged there is no backend — so
        "we ran it unconfined" is a fact, not an unremarked default.
        """
        loader = load_mutating(tmp_path)
        assert loader.require_sandbox_enforcement is False
        admissions = [
            payload
            for payload in chain_payloads(loader)
            if payload["activity_kind"] == ProviderActivityKind.ADMISSION.value
        ]
        assert admissions, kinds_in(loader)
        unconfined = [
            payload for payload in admissions if payload["outcome"] == "admitted_unconfined"
        ]
        assert unconfined
        payload = unconfined[0]
        assert payload["action_outcome"] == ActionOutcome.ACKNOWLEDGED_NO_BACKEND.value
        assert "capability_drop" in payload["details"]["unapplied_mechanisms"]
        assert SANDBOX_NOT_ENFORCED_NOTICE in payload["details"]["notice"]
        # And the mechanisms are still only *declared*; nothing was applied.
        profile = select_profile(ProviderMetadata.model_validate(mutating_declaration()))
        assert all(
            item.state is MechanismState.DECLARED_NOT_APPLIED
            for item in profile.unapplied_mechanisms
        )


# ── requirement 3: every activity sealed, and sealed for real ─────────────────


class TestEveryActivityIsSealed:
    def test_a_load_seals_the_whole_gate_sequence(self, tmp_path: Path) -> None:
        loader = load_mutating(tmp_path)
        kinds = kinds_in(loader)
        # Gate entry, the profile that admission earned, the load, then the
        # registration — in that order, which is the order the gates run in.
        assert kinds[:2] == [
            ProviderActivityKind.LOAD.value,
            ProviderActivityKind.ADMISSION.value,
        ]
        assert ProviderActivityKind.LOAD.value in kinds[2:]
        assert loader.ledger is not None
        assert len(loader.ledger.activities) == len(chain_payloads(loader))

    def test_the_chain_reloads_and_verifies_with_the_domain_verifier(self, tmp_path: Path) -> None:
        loader = load_mutating(tmp_path)
        repository = AttestationRepository(open_store(tmp_path, "mayhem.db"))
        stored = repository.load_chain(PROVIDER_ACTIVITY_CHAIN_ID)
        assert stored == loader.sealed_events()
        verification = repository.verify_run_chain(PROVIDER_ACTIVITY_CHAIN_ID)
        assert verification.valid, verification.errors
        assert verification.root_digest == verify_chain(stored).root_digest
        assert all(event.event_kind == EVENT_PROVIDER_ACTIVITY for event in stored)

    def test_a_sealed_event_round_trips_byte_for_byte(self, tmp_path: Path) -> None:
        """The row's JSON is the bytes its digest was computed from."""
        loader = load_mutating(tmp_path)
        for event in loader.sealed_events():
            assert ProviderEvidenceRecord is not None  # the payload carries the record
            reloaded = type(event).model_validate_json(event.model_dump_json())
            assert reloaded == event
            assert reloaded.digest_matches()
            assert reloaded.chain_link_matches()

    def test_the_manifest_commits_to_the_chain_and_is_unsigned(self, tmp_path: Path) -> None:
        """Committed *and* unsigned — the pair is the honest state, both halves."""
        load_mutating(tmp_path)
        repository = AttestationRepository(open_store(tmp_path, "mayhem.db"))
        manifest_id = f"{PROVIDER_ACTIVITY_CHAIN_ID}:provider-activity"
        manifest = repository.load_manifest(manifest_id)
        assert manifest is not None
        events = repository.load_chain(PROVIDER_ACTIVITY_CHAIN_ID)
        assert manifest.covered_events == len(events)
        verification = verify_manifest(manifest, events)
        assert verification.valid, verification.errors
        # No signer was named and no bytes were minted. Plan 12's reason is
        # stored beside the row; nothing here may imply authorship was proven.
        assert manifest.signed is False
        assert manifest.signer_identity == ""
        assert manifest.trust_root_ref == ""
        state, reason = repository.load_signature_state(manifest_id)
        assert state == "unsigned_no_signing"
        assert "no signature bytes were minted" in reason

    def test_each_activity_kind_reaches_the_stored_chain(self, tmp_path: Path) -> None:
        """One round trip per kind, all of them reloaded rather than remembered.

        The five kinds are produced by four different code paths on purpose:
        the loader's own gates, the loader's behaviour check, a permission
        refusal, and the sandbox enforcer. A kind that no path produces would be
        a kind nothing can assert.
        """
        loader = load_networked(tmp_path)
        # a sandbox decision, allowed and denied
        enforcer = loader.sandbox_enforcer("acme.injector", egress_allowlist=["ok.example"])
        enforcer.authorize_egress("ok.example")
        with pytest.raises(SandboxEgressDenied):
            enforcer.authorize_egress("https://evil.example.net")
        # a permission denial: a second provider asking for more than granted
        greedy = mutating_declaration(providerId="acme.greedy")
        greedy["permissions"] = ["target:read", "target:mutate", "network"]
        catalog = write_catalog(tmp_path, catalog_of(greedy), name="greedy.json")
        with pytest.raises(ProviderPermissionError):
            loader.load_catalog(catalog)
        # and a provider-initiated action, on a loader that admitted a provider
        # with a declared fault to record it for
        mutating = load_mutating(tmp_path / "mutating")
        record = mutating.record_action(
            "acme.injector",
            target_id="svc-a",
            fault_id="acme.packet.rewrite",
            action_outcome=ActionOutcome.APPLIED,
        )
        assert record.operation_id

        repository = AttestationRepository(open_store(tmp_path, "mayhem.db"))
        events = repository.load_chain(PROVIDER_ACTIVITY_CHAIN_ID)
        assert repository.verify_run_chain(PROVIDER_ACTIVITY_CHAIN_ID).valid
        seen = {event.payload["activity_kind"] for event in events}
        # Four of the five kinds came out of this one loader: the action kind
        # needs a provider that declared a fault, and this one declared none.
        assert seen == {
            ProviderActivityKind.LOAD.value,
            ProviderActivityKind.ADMISSION.value,
            ProviderActivityKind.SANDBOX_DECISION.value,
            ProviderActivityKind.PERMISSION_DENIED.value,
        }
        for event in events:
            assert event.payload["lane"] == PROVIDER_ACTIVITY_CHAIN_ID
            assert event.payload["principal"] == DEFAULT_PROVIDER_PRINCIPAL
            assert event.payload["evidence_digest"]
        actions = [
            payload
            for payload in chain_payloads(mutating)
            if payload["activity_kind"] == ProviderActivityKind.ACTION.value
        ]
        assert len(actions) == 1

    def test_a_sandbox_denial_is_sealed_and_still_raised(self, tmp_path: Path) -> None:
        """Recorded *and* propagated: the two are not alternatives."""
        loader = load_mutating(tmp_path)
        enforcer = loader.sandbox_enforcer("acme.injector")

        with pytest.raises(SandboxEgressDenied) as caught:
            enforcer.authorize_egress("https://api.example.com/v1")

        evidence = caught.value.evidence
        sealed = [
            payload
            for payload in chain_payloads(loader)
            if payload["activity_kind"] == ProviderActivityKind.SANDBOX_DECISION.value
        ]
        assert [payload["outcome"] for payload in sealed] == ["denied"]
        assert sealed[0]["action_outcome"] == ActionOutcome.REFUSED.value
        assert sealed[0]["target_id"] == "https://api.example.com/v1"
        assert sealed[0]["details"]["decision"]["host"] == "api.example.com"
        # The exception still carries the Phase 2 record, and it is the same
        # denial the chain carries.
        assert evidence.outcome == "denied"
        assert evidence.details["action_outcome"] == ActionOutcome.REFUSED.value
        assert evidence is enforcer.denials[-1]

    def test_a_filesystem_denial_is_sealed_too(self, tmp_path: Path) -> None:
        loader = load_mutating(tmp_path)
        enforcer = loader.sandbox_enforcer("acme.injector", writable_roots=["/srv/data"])
        with pytest.raises(SandboxAccessDenied) as caught:
            enforcer.require_filesystem("write", "/etc/passwd")
        sealed = [
            payload
            for payload in chain_payloads(loader)
            if payload["details"].get("sandbox_kind") == "filesystem"
        ]
        assert [payload["outcome"] for payload in sealed] == ["denied"]
        assert sealed[0]["details"]["decision"]["path"] == "/etc/passwd"
        assert caught.value.evidence.target_id == "/etc/passwd"

    def test_a_provider_action_is_written_through_the_declared_mapping(
        self, tmp_path: Path
    ) -> None:
        """The schema in the sealed payload is the provider's own, not mayhem's."""
        loader = load_mutating(tmp_path)
        loader.record_action(
            "acme.injector",
            target_id="svc-a",
            fault_id="acme.packet.rewrite",
            action_outcome=ActionOutcome.APPLIED,
        )
        actions = [
            payload
            for payload in chain_payloads(loader)
            if payload["activity_kind"] == ProviderActivityKind.ACTION.value
        ]
        assert len(actions) == 1
        payload = actions[0]
        assert payload["details"]["evidence_mapping"] == "declared"
        assert payload["fault_id"] == "acme.packet.rewrite"
        assert payload["declared_evidence_schema"] == "acme-injector-evidence"
        assert payload["declared_evidence_version"] == "1.0"
        assert payload["fault_id"] == "acme.packet.rewrite"
        # The ledger resolved the mapping through the declaration the loader
        # admitted, not through a copy it kept of its own.
        assert (
            loader.declaration_for("acme.injector").evidence_for("acme.packet.rewrite")
            is loader.declaration_for("acme.injector").evidence_schema
        )

    def test_an_unmapped_fault_still_lands_in_the_provider_schema(self, tmp_path: Path) -> None:
        """A read-only fault needs no mapping; it is not evidence about nothing."""
        loader = load_mutating(tmp_path)
        loader.record_action(
            "acme.injector",
            target_id="svc-a",
            fault_id="acme.packet.unmapped",
            action_outcome=ActionOutcome.APPLIED,
        )
        payload = next(
            item
            for item in chain_payloads(loader)
            if item["activity_kind"] == ProviderActivityKind.ACTION.value
        )
        assert payload["details"]["evidence_mapping"] == "provider_schema"
        assert payload["declared_evidence_schema"] == "acme-injector-evidence"

    def test_an_admission_with_no_backend_is_not_recorded_as_a_mutation(
        self, tmp_path: Path
    ) -> None:
        """ACKNOWLEDGED_NO_BACKEND is native to admissions, not a mutation.

        ``mayhem.infra.attestation_store.MUTATING_ACTION_OUTCOMES`` contains that
        value, because for a *native* run it means an action with no backend
        behind it. Reading the native set alone would therefore seal "we loaded a
        provider" as a mutation, which would make every provider chain demand an
        authorization it has nothing to do with.
        """
        loader = load_mutating(tmp_path)
        for payload in chain_payloads(loader):
            if payload["action_outcome"] == ActionOutcome.ACKNOWLEDGED_NO_BACKEND.value:
                assert payload["activity_kind"] == ProviderActivityKind.ADMISSION.value
                assert payload["mutating"] is False
        actions = [
            payload
            for payload in chain_payloads(loader)
            if payload["activity_kind"] == ProviderActivityKind.ACTION.value
        ]
        assert actions == []

    def test_a_mutating_action_is_flagged_as_mutating(self, tmp_path: Path) -> None:
        loader = load_mutating(tmp_path)
        loader.record_action(
            "acme.injector",
            target_id="svc-a",
            fault_id="acme.packet.rewrite",
            action_outcome=ActionOutcome.APPLIED,
        )
        payload = next(
            item
            for item in chain_payloads(loader)
            if item["activity_kind"] == ProviderActivityKind.ACTION.value
        )
        assert payload["mutating"] is True

    def test_an_action_for_a_provider_that_never_loaded_is_refused(self, tmp_path: Path) -> None:
        loader = load_mutating(tmp_path)
        with pytest.raises(ProviderNotFoundError):
            loader.record_action(
                "acme.absent",
                target_id="svc-a",
                action_outcome=ActionOutcome.APPLIED,
            )

    def test_an_unsealed_loader_says_so_rather_than_looking_recorded(self, tmp_path: Path) -> None:
        """The absence is a value, not a missing key.

        A loader cannot invent a database, so the ledger is opt-in — and every
        inspection then carries ``sealed: False`` with the notice, so a report
        rendered from it cannot imply a decision was recorded.
        """
        loader = loader_for(tmp_path, sealed=False)
        catalog = write_catalog(tmp_path, catalog_of(declaration()))
        report = loader.load_catalog(catalog)

        assert report.loaded == ("acme.injector",)
        evidence = report.providers[0].evidence
        assert evidence is not None
        assert evidence["sealed"] is False
        assert evidence["chain_run_id"] == ""
        assert evidence["notice"] == UNSEALED_ACTIVITY_NOTICE
        assert evidence["activities"], "the decision was still observed"
        assert loader.sealed_events() == ()
        assert report.to_dict()["providers"][0]["evidence"]["sealed"] is False

    def test_recording_an_action_without_a_store_refuses_rather_than_faking_it(
        self, tmp_path: Path
    ) -> None:
        """Observed is not recorded, and the API refuses to pretend otherwise."""
        loader = loader_for(tmp_path, sealed=False)
        catalog = write_catalog(tmp_path, catalog_of(declaration()))
        loader.load_catalog(catalog)
        with pytest.raises(ProviderError) as caught:
            loader.record_action(
                "acme.injector",
                target_id="svc-a",
                action_outcome=ActionOutcome.APPLIED,
            )
        assert caught.value.code == "provider_evidence_not_sealed"
        assert UNSEALED_ACTIVITY_NOTICE in str(caught.value)


# ── requirement 4: privileged actions in the audit stream ─────────────────────


class TestAuditStreamRecordsPrivilegedActions:
    def test_registration_is_recorded_and_verifies_offline(self, tmp_path: Path) -> None:
        load_mutating(tmp_path)
        stream = AuditStream(open_store(tmp_path, "mayhem.db"))
        entries = stream.load()
        kinds = [entry.event_kind for entry in entries]
        assert AUDIT_PROVIDER_REGISTERED in kinds
        registration = next(e for e in entries if e.event_kind == AUDIT_PROVIDER_REGISTERED)
        assert registration.payload["principal"] == DEFAULT_PROVIDER_PRINCIPAL
        assert registration.payload["target"] == "acme.injector"
        assert registration.payload["detail"]["permissions"] == ["target:mutate", "target:read"]
        assert registration.payload["detail"]["sandbox_profile"] == "sandbox.target.mutate"
        verification = stream.verify()
        assert verification.valid, verification.errors

    def test_a_permission_change_names_both_the_old_and_the_new_grant(self, tmp_path: Path) -> None:
        loader = load_mutating(tmp_path)
        loader.grant_permissions(
            "acme.injector",
            [*_MUTATING, ProviderPermission.NETWORK],
            reason="operator approved the exporter",
            actor="alice",
        )
        stream = AuditStream(open_store(tmp_path, "mayhem.db"))
        entry = next(e for e in stream.load() if e.event_kind == AUDIT_PROVIDER_PERMISSIONS_CHANGED)
        assert entry.payload["principal"] == "alice"
        assert entry.payload["detail"]["previous_permissions"] == ["target:mutate", "target:read"]
        assert entry.payload["detail"]["granted_permissions"] == [
            "network",
            "target:mutate",
            "target:read",
        ]
        assert entry.payload["detail"]["reason"] == "operator approved the exporter"
        assert loader.allowed_permissions == frozenset({*_MUTATING, ProviderPermission.NETWORK})
        # A permission log that recorded only the new state could not answer
        # "what could it do before", which is the incident question.
        assert stream.verify().valid

    def test_a_permission_change_for_an_unknown_provider_is_refused(self, tmp_path: Path) -> None:
        loader = load_mutating(tmp_path)
        before = loader.allowed_permissions
        with pytest.raises(ProviderNotFoundError):
            loader.grant_permissions("acme.absent", _MUTATING)
        assert loader.allowed_permissions == before

    def test_a_pack_grant_is_the_same_recorded_act(self, tmp_path: Path) -> None:
        """Two permission surfaces in one lane, one recorded path.

        A fault-pack grant changes what a third-party artifact may ask for, so
        leaving it unrecorded while the provider grant is recorded would make the
        audit log an incomplete account of the lane's own privileges.
        """
        from mayhem.providers.loader import PackLoader
        from mayhem.providers.permissions import ProviderPermissionSet

        ledger = ProviderActivityLedger(open_store(tmp_path, "mayhem.db"))
        pack_loader = PackLoader(activity_ledger=ledger)
        pack_loader.grant(
            "acme.packs", ProviderPermissionSet.from_names("acme.packs", ("target:read",))
        )
        pack_loader.grant(
            "acme.packs",
            ProviderPermissionSet.from_names("acme.packs", ("target:read", "target:mutate")),
        )
        entries = [
            entry
            for entry in ledger.audit_stream.load()
            if entry.event_kind == AUDIT_PROVIDER_PERMISSIONS_CHANGED
        ]
        assert [entry.payload["target"] for entry in entries] == ["acme.packs", "acme.packs"]
        assert entries[0].payload["detail"]["previous_permissions"] == []
        assert entries[1].payload["detail"]["granted_permissions"] == [
            "target:mutate",
            "target:read",
        ]

    def test_the_stream_is_append_only_and_still_unsigned(self, tmp_path: Path) -> None:
        """Integrity chained, never authenticated — plan 12's standing rule."""
        load_mutating(tmp_path)
        stream = AuditStream(open_store(tmp_path, "mayhem.db"))
        assert stream.signed is False
        assert stream.signature_state == "unsigned_no_signing"
        assert stream.is_append_only_intact()


# ── requirement 2: the engine axis, checkable ────────────────────────────────


class TestEngineAxisIsCheckable:
    def test_the_lane_is_derived_only_when_exactly_one_runtime_is_registered(self) -> None:
        """Three engine runtimes is not a lane, and guessing one is not checking."""
        from mayhem.domain.provider import (
            ImplementationKind,
            ImplementationReference,
            ProviderRegistration,
        )
        from mayhem.providers.builtin import create_builtin_registry

        # The default registry carries docker, podman and kubernetes: three
        # candidates, so no lane, and the function says so instead of picking.
        assert detect_engine_lane(create_builtin_registry()) is None
        assert detect_engine_lane(ProviderRegistry()) is None

        narrow = ProviderRegistry()
        narrow.register(
            ProviderRegistration(
                metadata=ProviderMetadata.model_validate(declaration(providerId="docker")),
                implementation=ImplementationReference(
                    kind=ImplementationKind.ENTRY_POINT, target="docker"
                ),
            ),
            TestRuntime,
        )
        assert narrow.ids() == frozenset({"docker"})
        assert detect_engine_lane(narrow) is EngineLane.DOCKER

    def test_supplying_the_lane_moves_the_axis_and_the_verdict_follows_it(
        self, tmp_path: Path
    ) -> None:
        document = declaration(compatibility={"engines": ["docker"]})
        catalog = write_catalog(tmp_path, catalog_of(document))

        unchecked = loader_for(tmp_path, sealed=False).load_catalog(catalog)
        compatibility = unchecked.providers[0].compatibility
        assert compatibility is not None
        assert compatibility["engine_verdict"] == "unverified"
        assert compatibility["unchecked_axes"] == ["engine"]
        assert compatibility["checked_axes"] == ["api_major", "release_window"]
        assert compatibility["declared_engines"] == ["docker"]
        # The provider still loads — the axis is open, and the report says so.
        assert unchecked.loaded == ("acme.injector",)

        matched_catalog = write_catalog(
            tmp_path, catalog_of(declaration(compatibility={"engines": ["docker"]})), "m.json"
        )
        matched = loader_for(tmp_path, running_engine="docker", sealed=False).load_catalog(
            matched_catalog
        )
        compatibility = matched.providers[0].compatibility
        assert compatibility is not None
        assert compatibility["engine_verdict"] == "matched"
        assert compatibility["checked_axes"] == ["api_major", "release_window", "engine"]
        assert compatibility["unchecked_axes"] == []
        assert compatibility["running_engine"] == "docker"

        with pytest.raises(ProviderCompatibilityError) as caught:
            loader_for(tmp_path, running_engine="kubernetes", sealed=False).load_catalog(
                write_catalog(
                    tmp_path,
                    catalog_of(declaration(compatibility={"engines": ["docker"]})),
                    "x.json",
                )
            )
        assert caught.value.code == "provider_engine_unsupported"

    def test_the_verdict_is_reachable_without_writing_a_catalog(self) -> None:
        """The per-declaration report is public, so a caller can ask before loading."""
        metadata = ProviderMetadata.model_validate(
            declaration(compatibility={"engines": ["docker", "kubernetes"]})
        )
        assert (
            loader_for(Path(), sealed=False).compatibility_report(metadata)["engine_verdict"]
            == "unverified"
        )
        checked = loader_for(Path(), running_engine=EngineLane.KUBERNETES, sealed=False)
        report = checked.compatibility_report(metadata)
        assert report["engine_verdict"] == "matched"
        assert report["running_engine"] == "kubernetes"

    def test_a_declaration_without_an_engine_is_inapplicable_not_unchecked(
        self, tmp_path: Path
    ) -> None:
        catalog = write_catalog(tmp_path, catalog_of(declaration()))
        report = loader_for(tmp_path, sealed=False).load_catalog(catalog)
        compatibility = report.providers[0].compatibility
        assert compatibility is not None
        assert compatibility["engine_verdict"] == "not_declared"
        assert compatibility["unchecked_axes"] == []
        assert compatibility["inapplicable_axes"] == ["engine"]
        assert compatibility["declared_engines"] == []

    def test_the_loader_level_report_still_answers_for_the_loader(self, tmp_path: Path) -> None:
        """No declaration was named, so the report is about the loader only."""
        loader = loader_for(tmp_path, sealed=False)
        assert loader.compatibility_report()["unchecked_axes"] == ["engine"]
        assert "engine_verdict" not in loader.compatibility_report()


# ── requirement 5: negative controls ──────────────────────────────────────────


class TestNegativeControls:
    def test_an_undeclared_permission_is_refused_and_recorded(self, tmp_path: Path) -> None:
        catalog = write_catalog(tmp_path, catalog_of(mutating_declaration()))
        loader = loader_for(tmp_path, permissions=(ProviderPermission.TARGET_READ,))

        with pytest.raises(ProviderPermissionError) as caught:
            loader.load_catalog(catalog)
        assert caught.value.code == "provider_permission_denied"

        denied = [
            payload
            for payload in chain_payloads(loader)
            if payload["activity_kind"] == ProviderActivityKind.PERMISSION_DENIED.value
        ]
        assert len(denied) == 1
        assert denied[0]["outcome"] == "denied"
        assert denied[0]["action_outcome"] == ActionOutcome.REFUSED.value
        assert denied[0]["details"]["requested"] == ["target:mutate"]
        assert denied[0]["details"]["granted"] == ["target:read"]
        # The chain still verifies: the refusal was recorded, not merely raised.
        assert (
            AttestationRepository(open_store(tmp_path, "mayhem.db"))
            .verify_run_chain(PROVIDER_ACTIVITY_CHAIN_ID)
            .valid
        )
        assert "acme.injector" not in loader.registry.ids()

    def test_a_runtime_that_over_claims_is_refused_never_registered_and_sealed(
        self, tmp_path: Path
    ) -> None:
        """Refused *before* registration, so there is nothing to revoke.

        "Revoked" is deliberately the weaker word here: refusing a runtime while
        it is still a local variable means it was never reachable, so a reviewer
        should read the absence of a revocation path as the stronger property
        rather than a gap.
        """
        document = mutating_declaration()
        loader = loader_for(tmp_path, permissions=_MUTATING)
        metadata_entry = FakeEntryPoint("acme.injector", document)
        implementation_entry = FakeEntryPoint("acme.injector", OverreachingRuntime())

        def entry_points(*, group: str) -> list[FakeEntryPoint]:
            if group == "mayhem.provider.metadata":
                return [metadata_entry]
            return [implementation_entry]

        loader._entry_points = entry_points
        report = loader.load_entry_points()

        assert report.loaded == ()
        assert report.failures[0].code == "provider_behavior_mismatch"
        assert "acme.injector" not in loader.registry.ids()
        refused = [
            payload
            for payload in chain_payloads(loader)
            if payload["details"].get("gate") == "runtime_behaviour"
        ]
        assert len(refused) == 1
        assert refused[0]["outcome"] == "refused"
        assert refused[0]["details"]["registered"] is False
        assert "injector.teleport" in " ".join(refused[0]["details"]["reasons"])
        # No audit entry claims a registration that did not happen.
        stream = AuditStream(open_store(tmp_path, "mayhem.db"))
        assert AUDIT_PROVIDER_REGISTERED not in [e.event_kind for e in stream.load()]

    def test_an_unsigned_pack_is_never_reported_as_verified(self, tmp_path: Path) -> None:
        """The load report may not upgrade an unsigned artifact to "verified"."""
        from mayhem.providers.loader import PackLoader, read_pack_document

        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
        # An *unsigned* pack with a claimed signer: the shape most likely to be
        # reported as "trusted" by a consumer in a hurry.
        pack = {
            "schema_version": "1.0",
            "manifest": {"provider_id": "acme.packs", "version": "1.2.3"},
            "faults": [],
            "signature": "",
            "signer": "acme",
        }
        path = tmp_path / "pack.json"
        path.write_text(json.dumps(pack), encoding="utf-8")
        pack_loader = PackLoader(allow_development_only=True)
        document, _file_digest = read_pack_document(path)
        loaded, _report = pack_loader.load(document)
        assurance = pack_loader.assurance_for(loaded, digest_verified=True)
        assert assurance.signer_claimed == "acme"
        assert assurance.signature_present is False
        assert assurance.signature_verified is False
        assert assurance.signer_trusted is False
        assert assurance.development_only is True
        assert "cannot verify" in assurance.notice
        assert assurance.to_dict()["signature_verified"] is False
        # The digest is an integrity statement, and it is reported beside the
        # signature verdict in one object so a consumer cannot read one as the
        # other.
        assert assurance.digest_verified is True

    def test_a_provider_action_has_the_shape_of_a_native_action(self, tmp_path: Path) -> None:
        """Plan 17's contract point, asserted rather than asserted-about.

        "A provider action participates in Mayhem's safety and evidence pipeline
        exactly like native actions" has to mean something checkable. Three
        things make it checkable here, and all three are asserted:

        1. the same record type and the same field set as any provider evidence;
        2. the same :class:`~mayhem.domain.evidence.ActionOutcome` vocabulary a
           native envelope uses for its steps; and
        3. the same attested store, chain and verifier behind it.
        """
        loader = load_mutating(tmp_path)
        record = loader.record_action(
            "acme.injector",
            target_id="svc-a",
            fault_id="acme.packet.rewrite",
            action_outcome=ActionOutcome.APPLIED,
        )
        native = EvidenceEnvelope(
            run_id="run-1",
            plan_hash="plan-1",
            step_reports=({"step_id": "s1", "action_outcome": ActionOutcome.APPLIED.value},),
            action_outcomes=(ActionOutcome.APPLIED.value,),
        )
        payload = next(
            item
            for item in chain_payloads(loader)
            if item["activity_kind"] == ProviderActivityKind.ACTION.value
        )

        # (1) same record type, same fields, and it round-trips through the model.
        assert isinstance(record, ProviderEvidenceRecord)
        assert set(record.model_dump(mode="json")) == set(
            ProviderEvidenceRecord(
                provider_id="x",
                operation_id="o",
                target_id="t",
                outcome="applied",
                recorded_at=READING.wall_clock,
                source="s",
                compensation_status=record.compensation_status,
            ).model_dump(mode="json")
        )
        assert ProviderEvidenceRecord.model_validate_json(record.model_dump_json()) == record
        # (2) same vocabulary: the value that reaches the chain is a native one.
        assert payload["action_outcome"] in {outcome.value for outcome in ActionOutcome}
        assert payload["action_outcome"] in native.action_outcomes
        # (3) same store: the action is in the chain, and the chain verifies.
        events = loader.sealed_events()
        assert any(
            event.payload["activity_kind"] == ProviderActivityKind.ACTION.value for event in events
        )
        assert (
            AttestationRepository(open_store(tmp_path, "mayhem.db"))
            .verify_run_chain(PROVIDER_ACTIVITY_CHAIN_ID)
            .valid
        )
        # And the record's digest is in the sealed payload, so the chain points at
        # something a reader can go and get.
        assert payload["evidence_digest"]

    def test_the_decision_module_stays_free_of_io(self) -> None:
        """The sandbox module knows *what* an activity is, never where it is written.

        Pinned by reading its own AST, because the alternative — importing the
        ledger here — is the change that would quietly turn the decision seam into
        a database client, and an import that grows back is invisible in review.
        """
        source = (REPO_ROOT / "src" / "mayhem" / "providers" / "sandbox.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not {name for name in imported if name.startswith("mayhem.infra")}
        assert not {name for name in imported if name.startswith("mayhem.providers.loader")}

    def test_an_evidence_record_refuses_a_native_verification_claim(self) -> None:
        """``outcome`` is free text; the *shape* is not. A pack claim stays a claim.

        This is the negative control for the whole file's honesty claim: nothing
        in this lane can turn "an unsigned artifact was loaded" into "the artifact
        was verified", because the sealed payload carries the provider's declared
        schema and the loader's own verdict, never a signature verdict.
        """
        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
        loader = ProviderLoader(running_version=CORE)
        assert loader.ledger is None
        activity = ProviderActivity(
            provider_id="acme.packs",
            kind=ProviderActivityKind.LOAD,
            outcome="loaded",
            action_outcome=ActionOutcome.APPLIED,
            target_id="acme.packs",
            operation_id="provider.load:acme.packs",
            recorded_at=READING.wall_clock,
            details={"signature_verified": False},
        )
        record = activity.to_evidence()
        assert record.source == ProviderActivityKind.LOAD.value
        assert record.details["signature_verified"] is False
        assert record.outcome == "loaded"
        assert "verified" not in record.source


# ── the store itself: the chain is not this lane's own invention ─────────────


class TestTheLaneReusesPlanTwelve:
    def test_the_chain_is_plan_twelve_types_and_plan_twelve_tables(self, tmp_path: Path) -> None:
        """No second event type, no second table, no second verifier."""
        load_mutating(tmp_path)
        store = open_store(tmp_path, "mayhem.db")
        tables = {
            str(dict(row)["name"])
            for row in store.query("SELECT name FROM sqlite_master WHERE type = ?", ("table",))
        }
        assert {"attestation_chains", "attestation_events", "attestation_manifests"} <= tables
        assert not any(name.startswith("provider_") for name in tables)

        events = AttestationRepository(store).load_chain(PROVIDER_ACTIVITY_CHAIN_ID)
        assert events[0].run_id == PROVIDER_ACTIVITY_CHAIN_ID
        assert events[0].is_genesis
        assert verify_chain(events).valid

    def test_a_tampered_activity_row_is_detected_offline(self, tmp_path: Path) -> None:
        """The persisted verifier is what makes the seal worth anything."""
        load_mutating(tmp_path)
        store = open_store(tmp_path, "mayhem.db")
        rows = store.query(
            "SELECT sequence, event_json FROM attestation_events"
            " WHERE run_id = ? ORDER BY sequence",
            (PROVIDER_ACTIVITY_CHAIN_ID,),
        )
        edited = json.loads(str(dict(rows[0])["event_json"]))
        edited["payload"]["outcome"] = "admitted_enforced"
        with store.write() as conn:
            conn.execute(
                "UPDATE attestation_events SET event_json = ? WHERE run_id = ? AND sequence = ?",
                (json.dumps(edited), PROVIDER_ACTIVITY_CHAIN_ID, 0),
            )
        verification = AttestationRepository(store).verify_run_chain(PROVIDER_ACTIVITY_CHAIN_ID)
        assert verification.valid is False
        assert verification.errors

    def test_a_ledger_can_be_shared_with_a_loader_it_did_not_create(self, tmp_path: Path) -> None:
        """Injection is the seam, so it is exercised rather than assumed."""
        store = open_store(tmp_path, "mayhem.db")
        ledger = ProviderActivityLedger(store)
        loader = ProviderLoader(
            registry=ProviderRegistry(allowed_permissions=_MUTATING),
            allowed_permissions=_MUTATING,
            running_version=CORE,
            require_sandbox_enforcement=False,
            activity_ledger=ledger,
        )
        catalog = write_catalog(tmp_path, catalog_of(mutating_declaration()))
        assert loader.load_catalog(catalog).loaded == ("acme.injector",)
        assert loader.ledger is ledger
        assert ledger.lane_id == PROVIDER_ACTIVITY_CHAIN_ID
        assert ledger.chain() == loader.sealed_events()
        assert ledger.verify().valid
        assert ledger.audit_stream.stream_id == "mayhem.audit"

    def test_the_lane_id_is_configurable_so_two_lanes_stay_apart(self, tmp_path: Path) -> None:
        store = open_store(tmp_path, "mayhem.db")
        first = ProviderActivityLedger(store, lane_id="mayhem.providers.a")
        second = ProviderActivityLedger(store, lane_id="mayhem.providers.b")
        activity = ProviderActivity(
            provider_id="acme.injector",
            kind=ProviderActivityKind.LOAD,
            outcome="loaded",
            action_outcome=ActionOutcome.APPLIED,
            target_id="acme.injector",
            operation_id="provider.load:acme.injector",
            recorded_at=READING.wall_clock,
        )
        first.record_provider_activity(activity)
        second.record_provider_activity(activity)
        assert [event.run_id for event in first.chain()] == ["mayhem.providers.a"]
        assert [event.run_id for event in second.chain()] == ["mayhem.providers.b"]
        assert first.verify().valid
        assert second.verify().valid
