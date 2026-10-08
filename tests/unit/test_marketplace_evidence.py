"""Marketplace evidence: sealing, privileged-action audit, and the coupling fix.

Plan 18 Phase 4 (``docs/v1.1.0/18_MARKETPLACE_CATALOG.md``). Phase 1 proved the
rules and Phase 2 wired them to a store and a loader. This file asks the
question Phase 4 exists for: **after the dust settles, can anyone still tell what
happened?**

Four claims, each tested as a claim rather than as a code path:

* **Reconstruction.** A publish, a pin, an install, a revocation, a deprecation
  and a federation closure each seal one
  :class:`~mayhem.domain.attestation.AttestedEvent` and one
  :class:`~mayhem.domain.attestation.Manifest` through plan 12's own repository.
  Each payload names the artifact digest, the registry, and the **derived** trust
  class — so a consumer holding only the exported chain can answer "which bytes
  were admitted, under which label, from which digest" without this database.
  Every activity is re-verified offline with plan 12's own verifier, and the
  manifests chain, so the order the catalog moved in survives export too.
* **Privileged actions.** Install, revoke, and trust-publisher are recorded in
  :class:`~mayhem.infra.audit_stream.AuditStream` — the same event type, the
  same encoder, the same verifier, no second audit format.
* **The certification coupling, re-checked rather than restated.** Phase 2
  claimed the absence of a foreign key from ``marketplace_certifications`` to
  ``certification_records`` was free. It is not. A pairing stores a *snapshot*,
  and a snapshot cannot follow
  :meth:`~mayhem.infra.certification_repository.CertificationRepository.store_transition`,
  so a record demoted in place left the catalogue still promoting an artifact off
  ``certified``. :meth:`MarketplaceStore.certifications` now resolves each pairing
  against the authoritative record and fails closed when it cannot — and
  ``test_a_demoted_record_stops_being_evidence_the_moment_it_is_demoted`` is the
  proof, paired with ``test_time_ages_a_pairing_without_anybody_writing_anything``
  for the half that genuinely was free.
* **The one clock read that decides.** :data:`CLOCK_DECISION_NOTE` claims
  ``guarded_factory`` is the only place a wall clock can change a verdict, and
  that no other decision can be moved by a clock. Both halves are asserted
  behaviourally rather than by reading the source.

Honesty, asserted rather than assumed
-------------------------------------
Nothing in this system verifies a signature. A sealed marketplace manifest proves
**integrity** — these bytes are unaltered and in this order — and nothing about
who produced them. ``test_no_payload_ever_reports_a_signature_as_verified`` walks
*every* sealed payload, audit entry, and engine object this file produces and
fails on any key that reads as authentication, and the honesty regex the rest of
the suite uses is imported rather than restated so the two cannot drift.

Negative controls, each of which would pass for the wrong reason if the refusal
were missing: a tampered artifact is refused *and* recorded; a revoked artifact
cannot execute after its deadline even through the guarded runtime factory; an
unverified artifact never displays a certified state; and an install whose bytes
do not hash to the published digest leaves no trust standing anywhere — no pin,
no audit entry, no class above ``UNVERIFIED``.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import TYPE_CHECKING, cast

import pytest
from test_marketplace_store import (
    _ARTIFACT_DIGEST,
    _BEYOND,
    _NOW,
    _OTHER_DIGEST,
    _TAMPERED_DIGEST,
    ARTIFACT_ID,
    FAULT_ID,
    PROVIDER_ID,
    _artifact,
    _cell,
    _cert,
    _deprecation,
    _loaded_loader,
    _registry,
    _revocation,
    _supply_chain,
)
from test_readme_honesty import honesty_overclaims

import mayhem.infra.marketplace_store as engine
from mayhem.domain.attestation import GENESIS_DIGEST, verify_manifest
from mayhem.domain.certification import (
    REQUIRED_EVIDENCE_DIGESTS,
    CertificationRecord,
    CertificationState,
    EvidenceBundleRef,
    certify,
    expire_by_time,
    mark_failed,
    mark_incompatible,
)
from mayhem.domain.marketplace import (
    SIGNATURE_TRUST_NOTICE,
    Artifact,
    ArtifactCertification,
    ArtifactClass,
    RegistryScope,
    TrustLabelError,
)
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
)
from mayhem.infra.certification_repository import CertificationRepository
from mayhem.infra.marketplace_store import (
    ACTIVITY_ARTIFACT_DEPRECATED,
    ACTIVITY_ARTIFACT_INSTALLED,
    ACTIVITY_ARTIFACT_PINNED,
    ACTIVITY_ARTIFACT_PUBLISHED,
    ACTIVITY_ARTIFACT_UNPINNED,
    ACTIVITY_INSTALL_REFUSED,
    CLOCK_DECISION_NOTE,
    MARKETPLACE_ACTIVITY_KINDS,
    MARKETPLACE_PRIVILEGED_ACTIONS,
    MarketplaceError,
    MarketplaceEvidence,
    MarketplaceRegistry,
    MarketplaceStore,
)
from mayhem.infra.store import Store
from mayhem.providers.loader import ProviderLoader
from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED as PACK_SIGNATURE_FLAG

if TYPE_CHECKING:
    from pathlib import Path

    from mayhem.infra.audit_stream import AuditStream

#: The refusal code a tampered download must produce. Named rather than written
#: inline so a test that asserts on it fails with a readable message.
_TAMPERED_CODE = "marketplace.digest_mismatch"

#: Keys no sealed payload, audit entry, or engine object may carry.
#:
#: Shared with ``test_marketplace_store.py`` and deliberately *narrower* than
#: :data:`~mayhem.infra.marketplace_store.MARKETPLACE_PRIVILEGED_ACTIONS`: it
#: lists the words that would assert an *authentication*, which is the claim this
#: build cannot make. ``integrity_state`` and ``digest`` are the integrity axis
#: and are real, so they are absent.
_FORBIDDEN_KEYS = frozenset(
    {
        "signed",
        "signer",
        "signature",
        "signature_verified",
        "signatures_verified",
        "trusted",
        "trust_established",
        "verified",
        "authenticated",
        "publisher_authenticated",
        "provenance_established",
    }
)

#: Substrings that must not appear in any payload key. Catches the compound forms
#: a closed key set misses ("is_verified", "signature_ok").
_FORBIDDEN_KEY_SUBSTRINGS = ("signature", "signed", "trusted", "authent")

#: The one payload key allowed to *name* signing, because it is the negation.
#:
#: ``signature_verification_implemented: False`` is how a consumer reading only
#: the sealed bytes learns that no signature was checked. A payload that omitted
#: it would be silent on the subject, and silence is what this repository keeps
#: refusing. The allowance is for the name only — the value is asserted ``False``
#: below, so the key cannot be repurposed into a claim.
_HONEST_SIGNATURE_NAMED_KEYS = frozenset({"signature_verification_implemented"})


def _keys(node: object) -> set[str]:
    """Every mapping key anywhere in a JSON-ish structure."""
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(str(key))
            found |= _keys(value)
    elif isinstance(node, (list, tuple)):
        for item in node:
            found |= _keys(item)
    return found


# ── fixtures ────────────────────────────────────────────────────────────────


def _store() -> tuple[Store, MarketplaceStore, CertificationRepository]:
    store = Store.open_migrated(":memory:")
    certifications = CertificationRepository(store)
    return store, MarketplaceStore(store), certifications


def _catalog(
    loader: ProviderLoader | None = None,
    *,
    artifact: Artifact | None = None,
) -> tuple[MarketplaceRegistry, MarketplaceStore]:
    market = _store()[1]
    registry = MarketplaceRegistry(store=market, loader=loader or ProviderLoader())
    published = artifact if artifact is not None else _artifact()
    market.publish_artifact(published, supply_chain=_supply_chain(published), now=_NOW)
    return registry, market


def _kinds(evidence: MarketplaceEvidence) -> list[str]:
    """The ``event_kind`` of every sealed activity, in write order."""
    return [
        event.event_kind for activity in evidence.activities() for event in evidence.load(activity)
    ]


def _payloads(evidence: MarketplaceEvidence) -> list[dict[str, object]]:
    return [
        event.payload for activity in evidence.activities() for event in evidence.load(activity)
    ]


def _audit_actions(audit: AuditStream) -> list[str]:
    return [event.event_kind for event in audit.load()]


# ── 1. sealing: every activity kind round-trips ─────────────────────────────


def test_a_publish_is_sealed_and_verifies_offline() -> None:
    _, market = _catalog()
    evidence = market.evidence

    assert _kinds(evidence) == [ACTIVITY_ARTIFACT_PUBLISHED]

    (activity_id,) = evidence.activities()
    chain = evidence.verify(activity_id)
    manifest_check = evidence.verify_manifest(activity_id)
    (event,) = evidence.load(activity_id)

    assert chain.valid, chain.errors
    assert manifest_check.valid, manifest_check.errors
    assert chain.checked == 1
    assert event.is_sealed
    assert event.digest_matches()
    assert evidence.repository.verify_run_chain(activity_id).valid


def test_a_pin_and_an_unpin_are_sealed_as_distinct_activities() -> None:
    _, market = _catalog()
    evidence = market.evidence

    market.install(
        ARTIFACT_ID,
        "1.4.2",
        _ARTIFACT_DIGEST,
        "community.registry",
        PROVIDER_ID,
        now=_NOW,
    )
    market.remove(ARTIFACT_ID, "1.4.2", now=_NOW)

    assert _kinds(evidence) == [
        ACTIVITY_ARTIFACT_PUBLISHED,
        ACTIVITY_ARTIFACT_PINNED,
        ACTIVITY_ARTIFACT_UNPINNED,
    ]
    pinned = _payloads(evidence)[1]
    assert pinned["pin_state"] == "installed"
    assert pinned["artifact_digest"] == _ARTIFACT_DIGEST
    assert _payloads(evidence)[2]["pin_state"] == "removed"


def test_an_install_seals_which_bytes_were_admitted_under_which_label() -> None:
    """The phase's reconstruction question, answered from the chain alone."""
    registry, market = _catalog()
    market.link(_cert(), now=_NOW)

    registry.install(
        ARTIFACT_ID,
        version="1.4.2",
        digest=_ARTIFACT_DIGEST,
        provider_id=PROVIDER_ID,
        observed_digest=_ARTIFACT_DIGEST,
        now=_NOW,
    )

    (activity_id,) = [
        activity
        for activity in market.evidence.activities()
        if ACTIVITY_ARTIFACT_INSTALLED in activity
    ]
    (event,) = market.evidence.load(activity_id)
    payload = event.payload

    # Which bytes...
    assert payload["artifact_digest"] == _ARTIFACT_DIGEST
    assert payload["observed_digest"] == _ARTIFACT_DIGEST
    assert payload["integrity_state"] == "digest_matched"
    assert payload["integrity_verified"] is True
    # ...under which label...
    assert payload["artifact_class"] == ArtifactClass.VERIFIED_COMMUNITY.value
    assert payload["certified_fault_ids"] == [FAULT_ID]
    assert payload["may_display_certified_state"] is True
    # ...from which registry.
    assert payload["registry_id"] == "community.registry"
    # ...and the two fields that stop it reading as more than that.
    assert payload["signature_verification_implemented"] is False
    assert payload["trust_notice"] == SIGNATURE_TRUST_NOTICE


def test_a_revocation_is_sealed_with_its_deadline_and_whether_it_was_in_force() -> None:
    _, market = _catalog()
    in_force = _revocation(propagation_deadline=_NOW - timedelta(hours=1))
    market.revoke(in_force, now=_NOW)

    payload = next(p for p in _payloads(market.evidence) if "revocation_id" in p)

    assert payload["revocation_id"] == "acme.rev.0001"
    assert payload["revocation_scope"] == "artifact_version"
    assert payload["revocation_reason"] == "security_defect"
    assert payload["artifact_digest"] == _ARTIFACT_DIGEST
    assert payload["propagation_deadline"] == in_force.propagation_deadline.isoformat()
    # "announced" and "in force" are different claims, and a reader reconstructing
    # the catalogue later needs to know which one this was.
    assert payload["in_force_at_record"] is True

    market.revoke(
        _revocation(revocation_id="acme.rev.0002", propagation_deadline=_NOW + timedelta(hours=1)),
        now=_NOW,
    )
    pending = next(
        p for p in _payloads(market.evidence) if p.get("revocation_id") == "acme.rev.0002"
    )
    assert pending["in_force_at_record"] is False


def test_a_deprecation_is_sealed_once_not_as_a_republish_plus_a_deprecation() -> None:
    _, market = _catalog()
    market.deprecate(ARTIFACT_ID, "1.4.2", _deprecation(), now=_NOW)

    assert _kinds(market.evidence) == [
        ACTIVITY_ARTIFACT_PUBLISHED,
        ACTIVITY_ARTIFACT_DEPRECATED,
    ]
    payload = _payloads(market.evidence)[1]
    assert payload["deprecated"] is True
    assert payload["artifact_class"] == ArtifactClass.DEPRECATED.value
    assert payload["replaced_by"] == "acme.packs.net"


def test_a_federation_closure_is_sealed_and_grants_no_standing() -> None:
    registry, market = _catalog()
    market.publish_registry(_registry(), now=_NOW)
    market.publish_registry(
        _registry(
            registry_id="acme.private",
            scope=RegistryScope.ORGANIZATION_PRIVATE,
            organization="acme",
        ),
        now=_NOW,
    )

    activity = registry.seal_federation(now=_NOW)

    payload = activity.payload
    members = sorted(cast("list[str]", payload["registry_ids"]))
    assert members == ["acme.private", "community.registry"]
    assert payload["federation_size"] == 2
    assert payload["grants_any_standing"] is False
    assert payload["trust_notice"] == SIGNATURE_TRUST_NOTICE
    assert activity.sealed
    # Sealing a closure changes no listing's class: it is a distribution fact.
    assert registry.listing_entry(_artifact(), now=_NOW).artifact_class is (
        ArtifactClass.UNVERIFIED
    )


def test_sealing_an_empty_federation_is_refused_rather_than_attesting_to_nothing() -> None:
    empty = MarketplaceRegistry(store=_store()[1], loader=ProviderLoader())

    with pytest.raises(MarketplaceError) as excinfo:
        empty.seal_federation(now=_NOW)

    assert excinfo.value.code == "marketplace.no_federation"
    assert empty.federation() is None
    assert empty.store.evidence.activities() == ()


def test_every_sealed_activity_verifies_and_the_manifests_chain() -> None:
    _, market = _catalog()
    market.revoke(_revocation(), now=_NOW)
    market.deprecate(ARTIFACT_ID, "1.4.2", _deprecation(), now=_NOW)
    market.install(
        ARTIFACT_ID, "1.4.2", _ARTIFACT_DIGEST, "community.registry", PROVIDER_ID, now=_NOW
    )
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    registry.seal_federation(now=_NOW)

    previous = GENESIS_DIGEST
    for activity_id in market.evidence.activities():
        chain = market.evidence.verify(activity_id)
        assert chain.valid, (activity_id, chain.errors)
        manifest = market.evidence.repository.load_manifest(f"{activity_id}:manifest")
        assert manifest is not None
        assert manifest.previous_manifest_digest == previous
        assert verify_manifest(manifest, market.evidence.load(activity_id)).valid
        previous = manifest.manifest_digest


def test_replaying_the_same_activity_produces_the_same_chain_not_a_near_duplicate() -> None:
    """Idempotence is a property of the design, not of a caller being careful."""
    _, market = _catalog()
    market.revoke(_revocation(), now=_NOW)
    first = market.evidence.activities()
    market.revoke(_revocation(), now=_NOW)

    assert market.evidence.activities() == first


def test_an_unknown_activity_kind_is_refused() -> None:
    _, market = _catalog()

    with pytest.raises(MarketplaceError) as excinfo:
        market.evidence.seal("marketplace.not.a.kind", subject="x", payload={}, recorded_at=None)

    assert excinfo.value.code == "marketplace.unknown_activity_kind"
    assert ACTIVITY_ARTIFACT_PUBLISHED in "".join(market.evidence.activities())
    assert not any(
        event.event_kind == "marketplace.not.a.kind"
        for activity in market.evidence.activities()
        for event in market.evidence.load(activity)
    )


def test_the_activity_vocabulary_is_closed_and_greppable() -> None:
    assert len(set(MARKETPLACE_ACTIVITY_KINDS)) == len(MARKETPLACE_ACTIVITY_KINDS)
    for kind in MARKETPLACE_ACTIVITY_KINDS:
        assert kind.startswith("marketplace.")


# ── 2. the privileged-action audit ───────────────────────────────────────────


def test_trusting_a_publisher_is_recorded_as_a_privileged_action() -> None:
    _, market = _catalog()
    market.link(_cert(), now=_NOW, principal="ops@acme.invalid")

    entries = market.audit.load()

    assert _audit_actions(market.audit) == ["audit.marketplace.trust_publisher"]
    assert entries[0].payload["principal"] == "ops@acme.invalid"
    assert entries[0].payload["detail"]["artifact_digest"] == _ARTIFACT_DIGEST
    assert entries[0].payload["detail"]["publisher_is_declared_only"] is True


def test_an_install_and_a_revocation_are_recorded_as_privileged_actions() -> None:
    registry, market = _catalog()
    registry.install(
        ARTIFACT_ID,
        version="1.4.2",
        digest=_ARTIFACT_DIGEST,
        provider_id=PROVIDER_ID,
        observed_digest=_ARTIFACT_DIGEST,
        now=_NOW,
    )
    market.revoke(_revocation(), now=_NOW, principal="sec@mayhem.invalid")

    assert _audit_actions(market.audit) == [
        "audit.marketplace.artifact.installed",
        "audit.marketplace.artifact.revoked",
    ]
    assert set(_audit_actions(market.audit)).issubset(set(MARKETPLACE_PRIVILEGED_ACTIONS))
    assert market.audit.verify().valid
    head = market.audit.head()
    assert head is not None
    assert head.entry_count == 2


def test_a_publish_and_a_deprecation_are_sealed_but_not_privileged_actions() -> None:
    """Neither grants nor withdraws standing on a runtime, so neither is privileged."""
    _, market = _catalog()
    market.deprecate(ARTIFACT_ID, "1.4.2", _deprecation(), now=_NOW)

    assert _kinds(market.evidence) == [ACTIVITY_ARTIFACT_PUBLISHED, ACTIVITY_ARTIFACT_DEPRECATED]
    assert market.audit.entry_count() == 0


def test_the_audit_entry_is_the_plan_12_event_type_not_a_second_format() -> None:
    _, market = _catalog()
    market.link(_cert(), now=_NOW)

    entry = market.audit.load()[0]

    # The same sealed event type, canonicalized and verified by the same rules as
    # run evidence — one format in this repository, used by more than one writer.
    assert entry.is_sealed
    assert entry.digest == entry.computed_digest()
    assert entry.chain_link_matches()
    assert entry.payload["action"] == entry.event_kind


def test_a_refused_install_is_sealed_but_not_written_to_the_privileged_log() -> None:
    registry, market = _catalog()

    with pytest.raises(MarketplaceError):
        registry.install(
            ARTIFACT_ID,
            version="1.4.2",
            digest=_ARTIFACT_DIGEST,
            provider_id=PROVIDER_ID,
            observed_digest=_TAMPERED_DIGEST,
            now=_NOW,
        )

    assert _kinds(market.evidence) == [ACTIVITY_ARTIFACT_PUBLISHED, ACTIVITY_INSTALL_REFUSED]
    assert market.audit.entry_count() == 0


def test_an_unknown_privileged_action_is_refused() -> None:
    _, market = _catalog()

    with pytest.raises(MarketplaceError) as excinfo:
        market.audit_privileged(
            "audit.marketplace.did.a.thing", target="x", principal="p", detail={}
        )

    assert excinfo.value.code == "marketplace.unknown_privileged_action"


# ── 3. the certification coupling, re-checked ────────────────────────────────


def test_time_ages_a_pairing_without_anybody_writing_anything() -> None:
    """The half of the no-FK claim that is free, and it is free for a real reason.

    ``is_current_record`` compares ``expires_at`` against the caller's ``now``
    independently of the record's stored state, so the pairing stops counting the
    moment it lapses with nothing having been rewritten — in either table.
    """
    _, market = _catalog()
    market.link(_cert(), now=_NOW)
    artifact = _artifact()

    assert market.label(artifact, now=_NOW).artifact_class is ArtifactClass.VERIFIED_COMMUNITY
    assert market.label(artifact, now=_BEYOND).artifact_class is ArtifactClass.UNVERIFIED
    # And the row really was untouched: the stored snapshot still says certified.
    raw = market.certifications()[0].record.state
    assert raw is CertificationState.CERTIFIED


def test_a_record_can_age_in_place_while_the_pairing_stays_consistent() -> None:
    """The load-bearing claim, proved end to end through the real repositories."""
    store, market, certifications = _store()
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact), now=_NOW)
    record = _certified_record()
    stored = certifications.append(record, now=_NOW)
    market.link(ArtifactCertification(artifact_digest=artifact.digest, record=record), now=_NOW)

    assert market.label(artifact, now=_NOW).artifact_class is ArtifactClass.VERIFIED_COMMUNITY

    # Plan 01 ages the claim in place, at the same (fault_id, sequence).
    aged = expire_by_time(record, now=_BEYOND)
    certifications.store_transition(stored, aged, now=_BEYOND)

    # The pairing row survived — that is what the no-FK decision bought.
    rows = store.query(
        "SELECT certification_json FROM marketplace_certifications WHERE artifact_digest = ?",
        (_ARTIFACT_DIGEST,),
    )
    assert len(rows) == 1
    assert ArtifactCertification.model_validate_json(str(rows[0][0])).record.state is (
        CertificationState.CERTIFIED
    ), "the stored snapshot is untouched, which is the point of the no-FK column"

    # And the pairing's *standing* followed the authority, which is what the
    # Phase 2 docstring claimed and did not deliver.
    resolved = market.certifications()[0]
    assert resolved.record.state is CertificationState.STALE
    assert resolved.artifact_digest == _ARTIFACT_DIGEST
    assert market.label(artifact, now=_NOW).artifact_class is ArtifactClass.UNVERIFIED
    store.close()


def test_a_demoted_record_stops_being_evidence_the_moment_it_is_demoted() -> None:
    """The defect this phase found, and the reason the Phase 2 claim was wrong.

    ``store_transition`` rewrites ``state`` on the same row. A snapshot cannot
    follow that, so before Phase 4 the catalogue kept reporting
    ``verified_community`` for a claim that had been withdrawn — evidence about
    bytes that a human had just decided no longer stands.
    """
    store, market, certifications = _store()
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact), now=_NOW)
    record = _certified_record()
    stored = certifications.append(record, now=_NOW)
    market.link(ArtifactCertification(artifact_digest=artifact.digest, record=record), now=_NOW)

    assert market.label(artifact, now=_NOW).artifact_class is ArtifactClass.VERIFIED_COMMUNITY

    certifications.store_transition(
        stored, mark_failed(record, reason="re-run on the same cell did not reproduce"), now=_NOW
    )

    assert market.label(artifact, now=_NOW).artifact_class is ArtifactClass.UNVERIFIED
    assert market.certifications()[0].record.state is CertificationState.FAILED
    assert "did not reproduce" in market.certifications()[0].record.reason
    store.close()


def test_an_invalidated_record_is_terminal_for_the_pairing_too() -> None:
    store, market, certifications = _store()
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact), now=_NOW)
    record = _certified_record()
    stored = certifications.append(record, now=_NOW)
    market.link(ArtifactCertification(artifact_digest=artifact.digest, record=record), now=_NOW)

    certifications.store_transition(
        stored, mark_incompatible(record, reason="the kernel moved"), now=_NOW
    )

    resolved = market.certifications()[0]
    assert resolved.record.state is CertificationState.INCOMPATIBLE
    assert market.label(artifact, now=_NOW).artifact_class is ArtifactClass.UNVERIFIED
    store.close()


def test_a_pairing_the_record_store_cannot_confirm_fails_closed() -> None:
    """Fail closed, not fail open: an unconfirmable claim is not evidence."""
    store, market, certifications = _store()
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact), now=_NOW)
    certifications.append(_certified_record(), now=_NOW)
    # A pairing for the same fault and cell, but for a *different* certification:
    # a different bundle hash is a different claim, and the store knows this one
    # is not the claim it can see.
    other = _certified_record(bundle_suffix="1")
    market.link(ArtifactCertification(artifact_digest=artifact.digest, record=other), now=_NOW)

    resolved = market.certifications()[0]
    assert resolved.record.state is CertificationState.STALE
    assert "no longer stored under that identity" in resolved.record.reason
    assert market.label(artifact, now=_NOW).artifact_class is ArtifactClass.UNVERIFIED
    store.close()


def test_a_pairing_the_plan_01_store_has_never_heard_of_stands_on_its_own() -> None:
    """The other branch, so the fix is not 'always distrust the snapshot'.

    When the catalog recorded a pairing and no record store has ever heard of
    that fault, there is no authority that could move it — the catalog is the
    only authority, so the snapshot stands and ages by time as Phase 2
    described.
    """
    store, market, _ = _store()
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact), now=_NOW)
    market.link(_cert(), now=_NOW)

    assert market.certifications()[0].record.state is CertificationState.CERTIFIED
    assert market.label(artifact, now=_NOW).artifact_class is ArtifactClass.VERIFIED_COMMUNITY
    store.close()


def test_a_paired_digest_is_still_only_evidence_for_those_exact_bytes() -> None:
    """The resolution must not smuggle a record across digests."""
    store, market, certifications = _store()
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact), now=_NOW)
    record = _certified_record()
    certifications.append(record, now=_NOW)
    market.link(ArtifactCertification(artifact_digest=_OTHER_DIGEST, record=record), now=_NOW)

    assert market.label(artifact, now=_NOW).artifact_class is ArtifactClass.UNVERIFIED
    store.close()


def test_a_transition_cannot_move_the_identity_the_resolution_keys_on() -> None:
    """The resolution's own invariant, pinned against the repository.

    ``_claim_identity`` assumes ``store_transition`` cannot move ``fault_id``,
    ``cell``, ``certified_at`` or the evidence bundle set. The first two are
    refused by the repository; this test pins the other two against the real
    UPDATE, so a future edit to that statement list cannot quietly break the
    read-time resolution.
    """
    store, market, certifications = _store()
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact), now=_NOW)
    record = _certified_record()
    stored = certifications.append(record, now=_NOW)
    market.link(ArtifactCertification(artifact_digest=artifact.digest, record=record), now=_NOW)

    after = market.certifications()[0].record
    assert after.cell.fingerprint == record.cell.fingerprint
    assert after.certified_at == record.certified_at
    assert tuple(ref.bundle_hash for ref in after.evidence) == tuple(
        ref.bundle_hash for ref in record.evidence
    )
    assert stored.record.state is CertificationState.CERTIFIED
    store.close()


def _certified_record(*, bundle_suffix: str = "") -> CertificationRecord:
    """A real plan-01 record, built the way the certification runner builds one."""
    bundle_hash = (bundle_suffix or "a") * 64
    return certify(
        CertificationRecord(
            fault_id=FAULT_ID,
            cell=_cell(),
            injector_version="acme-tc 1.4.0",
            expires_at=_NOW + timedelta(days=90),
        ),
        at=_NOW - timedelta(days=1),
        expires_at=_NOW + timedelta(days=30),
        evidence=(
            EvidenceBundleRef(
                bundle_hash=bundle_hash,
                mayhem_version="1.1.0.test",
                digests=dict.fromkeys(REQUIRED_EVIDENCE_DIGESTS, bundle_hash),
            ),
        ),
        outcome="latency observed; undo restored the pre-injection baseline",
    )


# ── 4. the one clock read that decides ───────────────────────────────────────


def test_the_clock_decision_note_names_the_one_reading_that_decides() -> None:
    assert "guarded_factory" in CLOCK_DECISION_NOTE
    assert "stale" in CLOCK_DECISION_NOTE


def test_every_policy_decision_is_replayable_and_ignores_the_wall_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No decision may be moved by a clock the caller did not choose.

    The same catalog, the same records, and an injected ``now`` produce the same
    verdict whether the host clock says 2026 or 2031. That is the property that
    makes a revocation deadline testable rather than waitable, and it is what
    separates a *decision* from a *stamp*.
    """
    verdicts = []
    for year in (2026, 2031):
        monkeypatch.setattr(engine, "utc_now", lambda year=year: _NOW.replace(year=year))
        registry, market = _catalog()
        market.revoke(_revocation(), now=_NOW)
        artifact = _artifact()
        verdicts.append(
            (
                registry.resolve(
                    ARTIFACT_ID, version="1.4.2", digest=_ARTIFACT_DIGEST, now=_NOW
                ).label.artifact_class,
                registry.listing_entry(artifact, now=_NOW).artifact_class,
                registry.approval_gate(artifact, now=_NOW),
                registry.compatibility(artifact, _cell(), now=_NOW).compatible,
                registry.admit.__name__,
                market.evidence.activities(),
            )
        )
    assert verdicts[0] == verdicts[1]


def test_guarded_factory_follows_the_real_clock_and_takes_no_now(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The one read that decides, and it cannot be given a stale instant.

    ``guarded_factory`` has no ``now`` parameter at all. Under a clock before the
    deadline the runtime materialises; under a clock past it, the materialisation
    is refused by name. That is the whole argument for the exception, stated as a
    test rather than as a docstring: injecting a clock here would put the single
    safety property this phase cannot compromise behind a caller-supplied value.
    """
    loader = _loaded_loader(tmp_path)
    registry, market = _catalog(loader)
    registry.install(
        ARTIFACT_ID,
        version="1.4.2",
        digest=_ARTIFACT_DIGEST,
        provider_id=PROVIDER_ID,
        observed_digest=_ARTIFACT_DIGEST,
        now=_NOW,
    )
    guarded = registry.guarded_factory(ARTIFACT_ID, version="1.4.2", factory=lambda: "runtime")

    monkeypatch.setattr(engine, "utc_now", lambda: _NOW)
    assert guarded() == "runtime"

    market.revoke(_revocation(propagation_deadline=_NOW - timedelta(hours=1)), now=_NOW)
    monkeypatch.setattr(engine, "utc_now", lambda: _NOW)
    with pytest.raises(MarketplaceError) as excinfo:
        guarded()
    assert excinfo.value.code == "marketplace.revoked"
    assert "acme.rev.0001" in str(excinfo.value)


def test_guarded_factory_signatures_never_take_a_now() -> None:
    import inspect

    parameters = inspect.signature(MarketplaceRegistry.guarded_factory).parameters
    assert "now" not in parameters
    # ...while every other decision does, so the exception is narrow.
    for name in ("resolve", "admit", "listing", "compatibility", "install"):
        assert "now" in inspect.signature(getattr(MarketplaceRegistry, name)).parameters


# ── 5. negative controls ─────────────────────────────────────────────────────


def test_a_tampered_artifact_is_refused_and_recorded(tmp_path: Path) -> None:
    """Refused *and* recorded: the two halves of the negative control.

    The absence of a pin is not evidence that an attempt was made, so a refused
    install seals its own activity. A tampered download that only left a
    ``MarketplaceError`` in a log line would be indistinguishable from an
    ordinary version conflict six months later.
    """
    loader = _loaded_loader(tmp_path)
    registry, market = _catalog(loader)
    market.link(_cert(), now=_NOW)

    with pytest.raises(MarketplaceError) as excinfo:
        registry.install(
            ARTIFACT_ID,
            version="1.4.2",
            digest=_ARTIFACT_DIGEST,
            provider_id=PROVIDER_ID,
            observed_digest=_TAMPERED_DIGEST,
            now=_NOW,
        )

    assert excinfo.value.code == _TAMPERED_CODE
    assert _ARTIFACT_DIGEST in str(excinfo.value)
    assert _TAMPERED_DIGEST in str(excinfo.value)

    refusal = next(p for p in _payloads(market.evidence) if "refusal_code" in p)
    assert refusal["refusal_code"] == _TAMPERED_CODE
    assert refusal["requested_digest"] == _ARTIFACT_DIGEST
    assert refusal["observed_digest"] == _TAMPERED_DIGEST
    assert refusal["integrity_state"] == "digest_mismatched"
    assert refusal["artifact_class"] is None, "a refused install has no label to report"
    for activity_id in market.evidence.activities():
        assert market.evidence.verify(activity_id).valid


def test_an_install_of_bytes_whose_digest_does_not_match_leaves_no_trust_standing(
    tmp_path: Path,
) -> None:
    """Nothing anywhere says this artifact was installed, evidenced, or admitted."""
    loader = _loaded_loader(tmp_path)
    registry, market = _catalog(loader)
    market.link(_cert(), now=_NOW)
    artifact = _artifact()

    with pytest.raises(MarketplaceError):
        registry.install(
            ARTIFACT_ID,
            version="1.4.2",
            digest=_ARTIFACT_DIGEST,
            provider_id=PROVIDER_ID,
            observed_digest=_TAMPERED_DIGEST,
            now=_NOW,
        )

    # No pin, so nothing may dispatch.
    assert market.pins() == ()
    assert registry.installed(ARTIFACT_ID) == ()
    with pytest.raises(MarketplaceError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert excinfo.value.code == "marketplace.not_installed"

    # No privileged-action entry, because nothing was granted. The only entry is
    # the trust-publisher record from the link, which granted nothing either.
    assert "audit.marketplace.artifact.installed" not in _audit_actions(market.audit)
    assert market.audit.entry_count() == 1
    # No admission was ever sealed — only the refusal.
    assert all(
        payload.get("activity_kind") != ACTIVITY_ARTIFACT_INSTALLED
        for payload in _payloads(market.evidence)
    )
    # And the artifact still reads as it did before the attempt.
    assert registry.listing_entry(artifact, now=_NOW).artifact_class is (
        ArtifactClass.VERIFIED_COMMUNITY
    )


def test_a_revoked_artifact_cannot_execute_after_its_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both seams, and the guarded factory across the deadline.

    The clock is pinned to ``_NOW`` throughout, because ``guarded_factory``
    deliberately reads the wall clock: with the real clock (2026) the fictional
    deadline in :data:`_NOW` is already past, which is the point — the
    materialisation check does not take an instant from its caller and cannot be
    handed a stale one.
    """
    loader = _loaded_loader(tmp_path)
    registry, market = _catalog(loader)
    registry.install(
        ARTIFACT_ID,
        version="1.4.2",
        digest=_ARTIFACT_DIGEST,
        provider_id=PROVIDER_ID,
        observed_digest=_ARTIFACT_DIGEST,
        now=_NOW,
    )
    guarded = registry.guarded_factory(ARTIFACT_ID, version="1.4.2", factory=lambda: "runtime")
    monkeypatch.setattr(engine, "utc_now", lambda: _NOW)
    assert guarded() == "runtime"

    # Announced but not yet in force: the dispatch still proceeds and says so.
    market.revoke(_revocation(propagation_deadline=_NOW + timedelta(hours=1)), now=_NOW)
    admission = registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert admission.artifact_ref == f"{ARTIFACT_ID}@1.4.2"
    assert any("acme.rev.0001" in entry for entry in admission.announced_revocations)
    assert guarded() == "runtime"

    # In force: both seams refuse, by name.
    market.revoke(_revocation(propagation_deadline=_NOW - timedelta(hours=1)), now=_NOW)
    with pytest.raises(MarketplaceError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert excinfo.value.code == "marketplace.revoked"
    assert "acme.rev.0001" in str(excinfo.value)
    with pytest.raises(MarketplaceError) as matinfo:
        guarded()
    assert matinfo.value.code == "marketplace.revoked"
    assert "acme.rev.0001" in str(matinfo.value)


def test_an_unverified_artifact_never_displays_a_certified_state() -> None:
    registry, market = _catalog()
    artifact = _artifact()

    entry = registry.listing_entry(artifact, now=_NOW)

    assert entry.artifact_class is ArtifactClass.UNVERIFIED
    assert entry.label.may_display_certified_state is False
    assert entry.to_dict()["certified_fault_ids"] == []
    assert entry.to_dict()["may_display_certified_state"] is False
    assert entry.to_dict()["verification_state"] == "not_checked"

    with pytest.raises(TrustLabelError) as excinfo:
        registry.listing_entry(artifact, claimed=ArtifactClass.VERIFIED_COMMUNITY, now=_NOW)
    assert "no_certification_record" in str(excinfo.value)
    assert market.certifications() == ()


def test_an_unverified_artifact_never_displays_a_certified_state_in_evidence_either() -> None:
    """The sealed payload is a display surface too, and it is held to the same rule."""
    _, market = _catalog()
    market.link(_cert(digest=_OTHER_DIGEST), now=_NOW)

    for payload in _payloads(market.evidence):
        if payload["activity_kind"] == ACTIVITY_ARTIFACT_PUBLISHED:
            assert payload["artifact_class"] == ArtifactClass.UNVERIFIED.value
            assert payload["may_display_certified_state"] is False
            assert payload["certified_fault_ids"] == []
            assert payload["artifact_class_meaning"] == (
                "no certification record: nothing has been demonstrated on any runtime, and "
                "the publisher is only declared"
            )


def test_no_payload_ever_reports_a_signature_as_verified(tmp_path: Path) -> None:
    """Walk everything this phase writes and fail on any key that reads as trust.

    The walk covers sealed payloads, audit entries, and the engine objects a
    caller renders, because Phase 3's surfaces will render all three and this
    phase is the last point at which the shape is decided. The honesty *prose*
    is checked too, with the same regex the document gate uses.
    """
    loader = _loaded_loader(tmp_path)
    registry, market = _catalog(loader)
    market.link(_cert(), now=_NOW)
    registry.install(
        ARTIFACT_ID,
        version="1.4.2",
        digest=_ARTIFACT_DIGEST,
        provider_id=PROVIDER_ID,
        observed_digest=_ARTIFACT_DIGEST,
        now=_NOW,
    )
    # A pending revocation, so the artifact is still dispatchable and the
    # admission object exists to be walked alongside the rest.
    market.revoke(_revocation(propagation_deadline=_NOW + timedelta(days=365)), now=_NOW)
    market.deprecate(ARTIFACT_ID, "1.4.2", _deprecation(), now=_NOW)
    registry.seal_federation(now=_NOW)
    admitted = registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    registry.listing(now=_NOW)
    with pytest.raises(MarketplaceError):
        registry.install(
            ARTIFACT_ID,
            version="1.4.2",
            digest=_ARTIFACT_DIGEST,
            provider_id=PROVIDER_ID,
            observed_digest=_TAMPERED_DIGEST,
            now=_NOW,
        )

    documents: list[tuple[str, object]] = []
    for payload in _payloads(market.evidence):
        documents.append(("sealed payload", payload))
    for event in market.audit.load():
        documents.append(("audit entry", event.payload))
    for activity_id in market.evidence.activities():
        documents.append(
            ("activity", market.evidence.repository.load_manifest(f"{activity_id}:manifest"))
        )
    for entry in registry.listing(now=_NOW):
        documents.append(("listing entry", entry.to_dict()))
    documents.append(("dispatch admission", admitted.to_dict()))
    documents.append(
        (
            "resolved pin",
            registry.resolve(
                ARTIFACT_ID, version="1.4.2", digest=_ARTIFACT_DIGEST, now=_NOW
            ).to_dict(),
        )
    )

    assert documents, "the walk proved nothing because it collected nothing"
    for label, document in documents:
        for key in _keys(document):
            assert key not in _FORBIDDEN_KEYS, f"{label} carries a trust-claiming key {key!r}"
            lowered = key.lower()
            if key in _HONEST_SIGNATURE_NAMED_KEYS:
                continue
            for needle in _FORBIDDEN_KEY_SUBSTRINGS:
                assert needle not in lowered, f"{label} key {key!r} reads as authentication"
        assert not honesty_overclaims(json.dumps(document, default=str)), (
            f"{label} makes an overclaim in prose"
        )

    # The one allowance above is allowed to be the negation and nothing else.
    flagged = [
        payload
        for payload in _payloads(market.evidence)
        if _HONEST_SIGNATURE_NAMED_KEYS & set(payload)
    ]
    assert flagged, "no payload carried the honest signature flag, so the walk proved nothing"
    for payload in flagged:
        assert payload["signature_verification_implemented"] is False


def test_every_manifest_this_phase_writes_is_unsigned_with_the_reason_stored() -> None:
    _, market = _catalog()
    market.link(_cert(), now=_NOW)
    market.revoke(_revocation(), now=_NOW)

    assert market.evidence.signed is False
    assert market.evidence.signature_state == SIGNATURE_UNSIGNED_NO_SIGNING
    for activity_id in market.evidence.activities():
        state, reason = market.evidence.signature_state_of(activity_id)
        assert state == SIGNATURE_UNSIGNED_NO_SIGNING
        assert reason == UNSIGNED_REASON_NO_SIGNING
        manifest = market.evidence.repository.load_manifest(f"{activity_id}:manifest")
        assert manifest is not None
        assert manifest.signed is False
        assert manifest.signer_identity == ""
        assert manifest.trust_root_ref == ""


def test_the_three_signature_flags_still_agree_and_are_all_false() -> None:
    assert PACK_SIGNATURE_FLAG is False
    assert engine.SIGNATURE_VERIFICATION_IMPLEMENTED is False
    assert engine.SIGNATURE_VERIFICATION_IMPLEMENTED is PACK_SIGNATURE_FLAG


# ── housekeeping: the writers really did write ───────────────────────────────


def test_sealing_is_not_opt_in_a_store_with_no_collaborators_still_seals() -> None:
    """The collaborators are constructed by default, so no call site can forget."""
    store = Store.open_migrated(":memory:")
    market = MarketplaceStore(store)

    market.publish_artifact(_artifact(), supply_chain=_supply_chain(_artifact()), now=_NOW)

    assert _kinds(market.evidence) == [ACTIVITY_ARTIFACT_PUBLISHED]
    store.close()


def test_an_edited_sealed_event_is_detected_by_the_offline_verifier() -> None:
    """The chain's claim is tamper-*evidence*, and it is checked, not asserted.

    Plan 12's posture is inherited rather than re-litigated: the attestation
    chain is integrity-detectable, not write-protected (only ``audit_entries``
    has the ``BEFORE UPDATE``/``BEFORE DELETE`` refusal). So the test that matters
    is that a rewritten event makes :func:`verify_chain` say so, by name — which
    is what an auditor months later would run.
    """
    store, market, _ = _store()
    market.publish_artifact(_artifact(), supply_chain=_supply_chain(_artifact()), now=_NOW)
    activity_id = market.evidence.activities()[0]
    assert market.evidence.verify(activity_id).valid

    rows = store.query("SELECT event_json FROM attestation_events WHERE run_id = ?", (activity_id,))
    tampered = json.loads(str(rows[0][0]))
    tampered["payload"]["artifact_digest"] = _TAMPERED_DIGEST
    with store.write() as conn:
        conn.execute(
            "UPDATE attestation_events SET event_json = ? WHERE run_id = ?",
            (json.dumps(tampered), activity_id),
        )

    verdict = market.evidence.verify(activity_id)
    assert verdict.valid is False
    assert verdict.errors
    store.close()
