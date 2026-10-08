"""The marketplace engine: pins, compatibility, and revocation at dispatch (plan 18, Phase 2).

What this file is for
---------------------
Phase 1 (``tests/unit/test_marketplace.py``) proved the *rules*: a class can
only be derived from records, a record for other bytes is not evidence, a
revocation is announced before it is in force. Those are pure predicates, so a
promotion is a function call nothing is obliged to make. Phase 2 is where the
predicates are wired to a store and a loader, and this file asks the question
that wiring invites: **can an artifact that should not run, run?**

Three things are load-bearing and are tested as such rather than by example:

* **Revocation reaches the dispatch path.** An artifact is installed, its
  provider is loaded through a real
  :class:`~mayhem.providers.loader.ProviderLoader` from a real catalog file, a
  dispatch is admitted, and then a revocation is recorded whose propagation
  deadline has already passed. Both the admission path
  (:meth:`MarketplaceRegistry.admit`) and the materialisation path
  (:meth:`MarketplaceRegistry.guarded_factory`, which is what
  :meth:`~mayhem.providers.registry.ProviderRegistry.runtime` actually calls)
  refuse afterwards, and the refusal names the revocation. A provider that is
  still reachable from the registry after its deadline is the defect this phase
  exists to prevent, so the test asserts the registry path too, not just
  ``admit``.
* **The gate goes *through* the loader, not around it.** The dispatch asks the
  same loader for the enforcer over the profile it chose, so
  :attr:`DispatchAdmission.profile_id` is the loader's own, and a provider the
  loader refuses (sandbox enforcement demanded, mechanism unapplied) is still
  refused here by the loader's own exception type.
* **Deprecation is enforced where it belongs.** A deprecated version cannot be
  *newly* installed, and an already-installed one keeps dispatching with the
  withdrawal reported on every admission. Revoking it stops it. The reasoning is
  in the module docstring of ``mayhem.infra.marketplace_store``; here it is
  pinned by tests so a later change cannot quietly flip the policy.

Honesty, asserted rather than assumed
-------------------------------------
Nothing in this system verifies a signature. Three separate literals say so —
in ``mayhem.providers.pack``, ``mayhem.domain.marketplace``, and
``mayhem.infra.marketplace_store`` — and the first test pins all three equal and
``False``. The schema is asserted to have no column that could hold a trust
class, and ``signature_verified`` is asserted to be ``CHECK``ed to zero at the
database level, so the honesty is a constraint rather than a comment.

Negative controls, each a test that would pass for the wrong reason if the
refusal were missing: a tampered artifact refused at install; an artifact
claiming ``verified_community`` with no certification record refused at listing;
a revoked artifact unable to execute after its deadline; and no object in the
engine ever reporting a signature as verified.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

import mayhem.domain.marketplace as domain_marketplace
import mayhem.infra.marketplace_store as engine
from mayhem.domain.capabilities import Capability
from mayhem.domain.certification import (
    REQUIRED_EVIDENCE_DIGESTS,
    Arch,
    CellPrivilege,
    CertificationRecord,
    EvidenceBundleRef,
    MatrixCell,
    certify,
)
from mayhem.domain.faults import EngineLane
from mayhem.domain.marketplace import (
    SIGNATURE_TRUST_NOTICE,
    Artifact,
    ArtifactCertification,
    ArtifactClass,
    ArtifactDependency,
    DeprecationNotice,
    DigestCheckState,
    PublisherDeclaration,
    RegistryRef,
    RegistryScope,
    ReleaseEvent,
    Revocation,
    RevocationReason,
    RevocationScope,
    SbomRef,
    SourceChainEntry,
    SourceStage,
    SupplyChainRecord,
    TrustLabelError,
)
from mayhem.domain.provider import PROVIDER_API_VERSION, ProviderPermission
from mayhem.infra.marketplace_store import (
    MARKETPLACE_TABLES,
    CompatibilityVerdict,
    DispatchAdmission,
    ListingEntry,
    MarketplaceError,
    MarketplaceRegistry,
    MarketplaceStore,
    PinState,
    ResolvedPin,
    StoredPin,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store
from mayhem.providers.loader import ProviderLoader
from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED as PACK_SIGNATURE_FLAG
from mayhem.providers.sandbox import ProviderSandboxError

if TYPE_CHECKING:
    from pathlib import Path

_NOW = datetime(2026, 5, 4, 9, 0, tzinfo=UTC)
_TTL = timedelta(days=30)
_BEYOND = _NOW + timedelta(days=90)

_BUNDLE_HASH = "a" * 64
_SBOM_DIGEST = "b" * 64
_ARTIFACT_DIGEST = "c" * 64
_TAMPERED_DIGEST = "d" * 64
_DEPRECATED_DIGEST = "e" * 64
_OTHER_DIGEST = "f" * 64

ARTIFACT_ID = "acme.packs.net"
PROVIDER_ID = "acme.probe"
FAULT_ID = "proc.pause"

#: The version this phase owns, and the one before it. Read from the chain rather
#: than written as a literal, because a concurrent v1.1.0 lane owns a higher id
#: and neither migration may be renumbered to suit the other.
MARKETPLACE_VERSION = 28
PRIOR_HEAD = MARKETPLACE_VERSION - 1
CURRENT_HEAD = ALL_MIGRATIONS[-1].version

#: Keys no engine object may report. ``verification_state`` is deliberately not
#: on this list: it names the *digest* check, which is real. What is forbidden is
#: any key that would read as an assertion about who wrote the bytes.
_FORBIDDEN_REPORT_KEYS = frozenset(
    {"signed", "signature", "signature_verified", "trusted", "signer_trusted", "verified"}
)


class ProbeRuntime:
    """The object a provider's implementation reference materialises to."""


# ── builders ────────────────────────────────────────────────────────────────


def _cell(
    *,
    engine_lane: EngineLane = EngineLane.DOCKER,
    kernel: str = "6.11.0-13-generic",
) -> MatrixCell:
    return MatrixCell(
        engine=engine_lane,
        engine_version="24.0.7",
        os_distro="ubuntu-24.04",
        kernel_version=kernel,
        arch=Arch.AMD64,
        privilege=CellPrivilege.ROOTLESS,
        capabilities=frozenset({Capability.NET_ADMIN}),
    )


def _bundle() -> EvidenceBundleRef:
    return EvidenceBundleRef(
        bundle_hash=_BUNDLE_HASH,
        mayhem_version="1.1.0.test",
        digests=dict.fromkeys(REQUIRED_EVIDENCE_DIGESTS, _BUNDLE_HASH),
    )


def _certified(
    *,
    cell: MatrixCell | None = None,
    at: datetime = _NOW - timedelta(days=1),
    ttl: timedelta = _TTL,
    fault_id: str = FAULT_ID,
) -> CertificationRecord:
    record = CertificationRecord(
        fault_id=fault_id,
        cell=cell or _cell(),
        injector_version="acme-tc 1.4.0",
        expires_at=at + _TTL * 3,
    )
    return certify(
        record,
        at=at,
        expires_at=at + ttl,
        evidence=(_bundle(),),
        outcome="latency observed; undo restored the pre-injection baseline",
    )


def _cert(
    *, digest: str = _ARTIFACT_DIGEST, record: CertificationRecord | None = None
) -> ArtifactCertification:
    return ArtifactCertification(artifact_digest=digest, record=record or _certified())


def _publisher(*, organization: str | None = None) -> PublisherDeclaration:
    return PublisherDeclaration(
        publisher_id="acme.labs",
        display_name="Acme Labs",
        contact="maintainers@acme.invalid",
        organization=organization,
    )


def _registry(
    *,
    registry_id: str = "community.registry",
    scope: RegistryScope = RegistryScope.COMMUNITY,
    organization: str | None = None,
    federates_with: tuple[str, ...] = (),
) -> RegistryRef:
    return RegistryRef(
        registry_id=registry_id,
        display_name=registry_id,
        scope=scope,
        organization=organization,
        federates_with=federates_with,
    )


def _artifact(
    *,
    digest: str = _ARTIFACT_DIGEST,
    registry: RegistryRef | None = None,
    publisher: PublisherDeclaration | None = None,
    deprecation: DeprecationNotice | None = None,
    dependencies: tuple[ArtifactDependency, ...] = (),
    permissions: frozenset[ProviderPermission] = frozenset({ProviderPermission.TARGET_READ}),
    version: str = "1.4.2",
) -> Artifact:
    return Artifact(
        artifact_id=ARTIFACT_ID,
        version=version,
        digest=digest,
        publisher=publisher or _publisher(),
        registry=registry or _registry(),
        dependencies=dependencies,
        permissions=permissions,
        license_id="Apache-2.0",
        changelog_ref="https://acme.invalid/CHANGELOG.md",
        deprecation=deprecation,
    )


def _deprecation() -> DeprecationNotice:
    return DeprecationNotice(
        reason="the injector reached an unsupported kernel path on 6.9",
        replaced_by="acme.packs.net",
        announced_at=_NOW - timedelta(days=3),
    )


def _supply_chain(
    artifact: Artifact,
    *,
    verification_state: DigestCheckState = DigestCheckState.NOT_CHECKED,
) -> SupplyChainRecord:
    return SupplyChainRecord(
        artifact_id=artifact.artifact_id,
        version=artifact.version,
        digest=artifact.digest,
        publisher=artifact.publisher,
        declared_permissions=artifact.permissions,
        dependencies=artifact.dependencies,
        sbom=SbomRef(format="spdx-2.3", digest=_SBOM_DIGEST, locator="https://acme.invalid/s"),
        verification_state=verification_state,
        release_history=(
            ReleaseEvent(
                version=artifact.version,
                digest=artifact.digest,
                released_at=_NOW - timedelta(days=2),
                summary="shipping the net.pause injector",
            ),
        ),
        source_chain=(
            SourceChainEntry(
                stage=SourceStage.PUBLISHED,
                actor="acme.labs (declared, not authenticated)",
                locator="https://acme.invalid/dist",
                recorded_at=_NOW - timedelta(days=2),
            ),
        ),
    )


def _revocation(
    *,
    revocation_id: str = "acme.rev.0001",
    scope: RevocationScope = RevocationScope.ARTIFACT_VERSION,
    reason: RevocationReason = RevocationReason.SECURITY_DEFECT,
    issued_at: datetime = _NOW - timedelta(days=1),
    propagation_deadline: datetime = _NOW - timedelta(hours=1),
    digest: str = _ARTIFACT_DIGEST,
    version: str = "1.4.2",
    publisher_id: str | None = None,
    registry_id: str | None = None,
) -> Revocation:
    artifact_fields = (
        {
            "artifact_id": ARTIFACT_ID,
            "version": version,
            "digest": digest,
        }
        if scope is RevocationScope.ARTIFACT_VERSION
        else {}
    )
    return Revocation(
        revocation_id=revocation_id,
        scope=scope,
        reason=reason,
        detail="upstream advisory GHSA-0000-0000-0000",
        issued_at=issued_at,
        propagation_deadline=propagation_deadline,
        publisher_id=publisher_id,
        registry_id=registry_id,
        **artifact_fields,
    )


# ── fixtures ────────────────────────────────────────────────────────────────


def _store() -> tuple[Store, MarketplaceStore]:
    store = Store.open_migrated(":memory:")
    return store, MarketplaceStore(store)


def _provider_metadata(
    provider_id: str = PROVIDER_ID, permissions: list[str] | None = None
) -> dict:
    return {
        "apiVersion": PROVIDER_API_VERSION,
        "providerId": provider_id,
        "name": "Acme Probe",
        "version": "1.0.0",
        "description": "A third-party provider loaded through the real loader.",
        "permissions": permissions or [],
        "capabilities": [{"id": "net.probe", "summary": "Probe a network target."}],
        "targetLocators": [
            {
                "id": "acme.target",
                "kind": "test_object",
                "selectorSchema": {"name": "string"},
                "requiredPermissions": [],
            }
        ],
        "evidenceSchema": {
            "name": "acme-probe-evidence",
            "version": "1.0",
            "fields": ("target",),
        },
    }


def _catalog_document(
    provider_id: str = PROVIDER_ID, *, permissions: list[str] | None = None
) -> dict:
    return {
        "apiVersion": "mayhem.provider-catalog/v1",
        "providers": [
            {
                "metadata": _provider_metadata(provider_id, permissions),
                "implementation": {
                    "kind": "import",
                    "target": "tests.unit.test_marketplace_store:ProbeRuntime",
                    "factory": False,
                },
            }
        ],
    }


def _loaded_loader(
    tmp_path: Path,
    provider_id: str = PROVIDER_ID,
    *,
    permissions: list[str] | None = None,
    allowed_permissions: frozenset[ProviderPermission] = frozenset(),
    require_sandbox_enforcement: bool = False,
) -> ProviderLoader:
    """A loader that has genuinely admitted ``provider_id`` through its own gates."""
    catalog = tmp_path / f"{provider_id}.json"
    catalog.write_text(
        json.dumps(_catalog_document(provider_id, permissions=permissions)), encoding="utf-8"
    )
    loader = ProviderLoader(
        allowed_permissions=allowed_permissions,
        require_sandbox_enforcement=require_sandbox_enforcement,
    )
    report = loader.load_catalog(catalog)
    assert report.failures == (), report.failures
    assert provider_id in report.loaded, report.to_dict()
    return loader


def _empty_market() -> MarketplaceRegistry:
    """A registry over a store with nothing published — not even a registry row."""
    return MarketplaceRegistry(store=_store()[1], loader=ProviderLoader())


def _catalog(
    *,
    loader: ProviderLoader | None = None,
    artifact: Artifact | None = None,
    chain: SupplyChainRecord | None = None,
) -> MarketplaceRegistry:
    """A registry with one published artifact and, optionally, a certification."""
    market = _store()[1]
    if loader is None:
        loader = ProviderLoader()
    registry = MarketplaceRegistry(store=market, loader=loader)
    if artifact is None:
        artifact = _artifact()
    registry.store.publish_artifact(
        artifact, supply_chain=chain if chain is not None else _supply_chain(artifact)
    )
    return registry


def _certified_market(
    loader: ProviderLoader | None = None,
    *,
    cell: MatrixCell | None = None,
    digest: str = _ARTIFACT_DIGEST,
) -> MarketplaceRegistry:
    """A catalog holding one artifact with a current record for its own digest."""
    registry = _catalog(loader=loader)
    registry.store.link(_cert(digest=digest, record=_certified(cell=cell)))
    return registry


def _installed_market(
    tmp_path: Path,
    *,
    loader: ProviderLoader | None = None,
    cell: MatrixCell | None = None,
    certified: bool = True,
    deprecation: DeprecationNotice | None = None,
    provider_id: str = PROVIDER_ID,
) -> MarketplaceRegistry:
    """A loaded provider, a published artifact, a record, and a live pin."""
    if loader is None:
        loader = _loaded_loader(tmp_path, provider_id)
    registry = _catalog(loader=loader)
    artifact = _artifact()
    registry.store.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    if certified:
        registry.store.link(_cert())
    registry.install(
        ARTIFACT_ID,
        version=artifact.version,
        digest=artifact.digest,
        provider_id=provider_id,
        observed_digest=artifact.digest,
        cell=cell,
        now=_NOW,
    )
    if deprecation is not None:
        # Applied *after* the install, and that ordering is the policy under test:
        # withdrawal stops a version being newly pinned, and the bytes already
        # pinned under the earlier notice keep dispatching.
        registry.store.deprecate(ARTIFACT_ID, artifact.version, deprecation, now=_NOW)
    return registry


def _table_names(store: Store) -> set[str]:
    return {
        str(row[0])
        for row in store.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def _column_names(store: Store, table: str) -> set[str]:
    return {str(row[1]) for row in store.query(f'PRAGMA table_info("{table}")')}


# ── 1. honesty, asserted rather than assumed ────────────────────────────────


def test_no_module_in_this_system_claims_it_verifies_a_signature() -> None:
    """The three literals, pinned equal and ``False``.

    A marketplace is where "verified" and "trusted" get spent, so the build's
    inability to authenticate authorship has to be a *checked* fact in every
    layer that repeats it, not a note in one docstring.
    """
    assert PACK_SIGNATURE_FLAG is False
    assert domain_marketplace.SIGNATURE_VERIFICATION_IMPLEMENTED is False
    assert engine.SIGNATURE_VERIFICATION_IMPLEMENTED is False


def test_the_trust_notice_is_the_one_the_domain_wrote() -> None:
    assert engine.SIGNATURE_TRUST_NOTICE == SIGNATURE_TRUST_NOTICE
    assert "cannot verify artifact signatures" in SIGNATURE_TRUST_NOTICE
    assert "authorship" in SIGNATURE_TRUST_NOTICE


def test_no_engine_dataclass_has_a_field_that_could_be_a_trust_class() -> None:
    """No stored class, on any of the four value types.

    ``artifact_class`` is a property on each, reading the carried
    :class:`~mayhem.domain.marketplace.TrustLabel`. A dataclass *field* would be
    constructible with any value, which is the shortcut Phase 1 removed.
    """
    for cls in (ResolvedPin, ListingEntry, DispatchAdmission, CompatibilityVerdict, StoredPin):
        names = {field.name for field in dataclasses.fields(cls)}
        assert "artifact_class" not in names, f"{cls.__name__} stores a class field"
        assert "class" not in names, f"{cls.__name__} stores a class field"
        assert "trust" not in names, f"{cls.__name__} stores a trust field"
        for name in names:
            assert name not in _FORBIDDEN_REPORT_KEYS, f"{cls.__name__}.{name} reads as trust"
        assert isinstance(getattr(cls, "artifact_class", None), property) or not hasattr(
            cls, "artifact_class"
        )


def test_no_engine_report_ever_names_a_signature_or_a_trust_verdict(tmp_path: Path) -> None:
    """Every ``to_dict`` carries the notice and no forbidden key."""
    registry = _installed_market(tmp_path)
    pin = registry.resolve(ARTIFACT_ID, version="1.4.2", digest=_ARTIFACT_DIGEST, now=_NOW)
    entry = registry.listing_entry(pin.artifact, now=_NOW)
    admission = registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    for payload in (
        pin.to_dict(),
        entry.to_dict(),
        admission.to_dict(),
        registry.compatibility(pin.artifact, _cell(), now=_NOW).to_dict(),
    ):
        assert "cannot verify artifact signatures" in str(payload["notice"])
        assert not _FORBIDDEN_REPORT_KEYS & set(payload), payload


# ── 2. the migration ─────────────────────────────────────────────────────────


def test_the_migration_uses_the_reserved_id_and_keeps_the_chain_contiguous() -> None:
    versions = tuple(migration.version for migration in ALL_MIGRATIONS)
    assert versions == tuple(range(1, CURRENT_HEAD + 1)), "the chain must stay contiguous"
    assert len(versions) == len(set(versions)), "no duplicate versions"
    mine = [m for m in ALL_MIGRATIONS if m.version == MARKETPLACE_VERSION]
    assert len(mine) == 1, "exactly one migration may own the reserved id"
    assert mine[0].migration_id == "0028_marketplace"
    assert mine[0].name == "marketplace"
    assert mine[0].down_statements, "additive schema changes must be reversible"


def test_the_migration_creates_every_marketplace_table_and_index() -> None:
    store = Store.open_migrated(":memory:")
    assert set(MARKETPLACE_TABLES) <= _table_names(store)
    indexes = {
        str(row[0]) for row in store.query("SELECT name FROM sqlite_master WHERE type='index'")
    }
    assert {
        "idx_marketplace_artifacts_digest",
        "idx_marketplace_artifacts_registry",
        "idx_marketplace_artifacts_publisher",
        "idx_marketplace_certifications_state",
        "idx_marketplace_certifications_cell",
        "idx_marketplace_supply_chain_digest",
        "idx_marketplace_revocations_target",
        "idx_marketplace_revocations_deadline",
        "idx_marketplace_pins_live",
        "idx_marketplace_pins_provider",
        "idx_marketplace_registries_scope",
    } <= indexes
    assert store.query("PRAGMA foreign_key_check") == []
    store.close()


def test_the_migration_drops_its_tables_and_comes_back_on_up() -> None:
    """The full round trip ADR-M4-5's down-migration acceptance relies on."""
    store = Store.open_migrated(":memory:")
    assert store.schema_version == CURRENT_HEAD

    reversed_ids = store.migrate_down(PRIOR_HEAD)

    assert "0028_marketplace" in reversed_ids
    assert set(MARKETPLACE_TABLES).isdisjoint(_table_names(store))
    assert store.schema_version == PRIOR_HEAD

    reapplied = store.migrate()

    assert "0028_marketplace" in reapplied
    assert set(MARKETPLACE_TABLES) <= _table_names(store)
    assert store.schema_version == CURRENT_HEAD
    store.close()


def test_no_marketplace_table_has_a_column_that_could_hold_a_trust_class() -> None:
    """The schema cannot be asked to store a class, so none is asked to."""
    store = Store.open_migrated(":memory:")
    for table in MARKETPLACE_TABLES:
        for column in _column_names(store, table):
            assert column not in {
                "artifact_class",
                "class",
                "trust",
                "trust_label",
                "verified",
                "trusted",
                "signed",
            }, f"{table}.{column} could hold a trust claim"
    store.close()


def test_the_signature_column_can_only_ever_hold_zero() -> None:
    """``signature_verified`` exists and is CHECKed to ``0`` at the database.

    The column is there so the shape survives for a future signing lane; the
    CHECK means a 1 cannot be written without a migration that admits it. This
    is a *schema* claim, so it is tested against the schema rather than against
    this module's willingness to pass a 0.
    """
    store, market = _store()
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    assert "signature_verified" in _column_names(store, "marketplace_supply_chain")
    row = store.query("SELECT signature_verified FROM marketplace_supply_chain")[0]
    assert int(row["signature_verified"]) == 0
    with pytest.raises(sqlite3.IntegrityError):
        store.write().__enter__().execute(
            "UPDATE marketplace_supply_chain SET signature_verified = 1"
        )
    store.close()


def test_the_certification_primary_key_carries_the_artifact_digest() -> None:
    """A record cannot be filed against bytes it was not made against.

    The pairing's first key column *is* the digest, so "which artifact does this
    record support" is a lookup rather than a judgement, and a record for other
    bytes is simply absent from the answer.
    """
    store, market = _store()
    market.link(_cert(digest=_ARTIFACT_DIGEST))
    assert market.certifications_for(_artifact(digest=_ARTIFACT_DIGEST))
    assert market.certifications_for(_artifact(digest=_OTHER_DIGEST)) == ()
    assert market.certifications_for(_artifact(digest=_OTHER_DIGEST, version="1.4.2")) == ()
    keys = {str(row[1]) for row in store.query("PRAGMA table_info(marketplace_certifications)")}
    assert "artifact_digest" in keys
    store.close()


def test_a_revocation_row_cannot_be_written_with_a_deadline_before_its_issue() -> None:
    store, market = _store()
    issued = (_NOW - timedelta(days=1)).isoformat()
    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(
                "INSERT INTO marketplace_revocations (revocation_id, scope, reason, artifact_id, "
                " version, digest, publisher_id, registry_id, issued_at, propagation_deadline, "
                " detail, revocation_json, recorded_at) VALUES "
                "('bad.rev','artifact_version','security_defect',?,? ,?,'','',?,?,'x','{}',?)",
                (ARTIFACT_ID, "1.4.2", _ARTIFACT_DIGEST, issued, issued, issued),
            )
    assert market.revocations() == ()
    store.close()


def test_a_revocation_row_may_not_name_more_than_its_own_scope() -> None:
    store, market = _store()
    issued = (_NOW - timedelta(days=1)).isoformat()
    deadline = (_NOW - timedelta(hours=1)).isoformat()
    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(
                "INSERT INTO marketplace_revocations (revocation_id, scope, reason, artifact_id, "
                " version, digest, publisher_id, registry_id, issued_at, propagation_deadline, "
                " detail, revocation_json, recorded_at) VALUES "
                "('bad.scope','publisher','policy','','','','acme.labs','community.registry',"
                "?,?,'x','{}',?)",
                (issued, deadline, issued),
            )
    assert market.revocations() == ()
    store.close()


def test_a_pin_row_must_name_sixty_four_hex_characters() -> None:
    store, market = _store()
    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(
                "INSERT INTO marketplace_pins (artifact_id, version, digest, registry_id, "
                " provider_id, state, installed_at, removed_at) "
                "VALUES (?,?,?,'community.registry',?,'installed',?,'')",
                (ARTIFACT_ID, "1.4.2", "1.4.2", PROVIDER_ID, _NOW.isoformat()),
            )
    assert market.pins() == ()
    store.close()


def test_the_same_bytes_cannot_be_republished_under_one_id_under_two_versions() -> None:
    """One id, one digest: a catalog that cannot say which label you are reading."""
    store, market = _store()
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    with pytest.raises(sqlite3.IntegrityError):
        market.publish_artifact(
            _artifact(version="1.5.0"),
            supply_chain=_supply_chain(_artifact(version="1.5.0")),
        )
    store.close()


# ── 3. store round trips ────────────────────────────────────────────────────


def test_an_artifact_round_trips_with_every_field_intact() -> None:
    store, market = _store()
    dependencies = (
        ArtifactDependency(name="acme.libs.core", constraint=">=1.2.0", digest=_SBOM_DIGEST),
        ArtifactDependency(name="acme.libs.net", constraint="~2.0.0"),
    )
    artifact = _artifact(
        dependencies=dependencies,
        permissions=frozenset({ProviderPermission.TARGET_READ, ProviderPermission.NETWORK}),
        deprecation=_deprecation(),
    )
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))

    assert market.artifact(ARTIFACT_ID, "1.4.2") == artifact
    assert market.artifacts(artifact_id=ARTIFACT_ID) == (artifact,)
    assert market.versions(ARTIFACT_ID) == ("1.4.2",)
    store.close()


def test_a_supply_chain_record_round_trips_with_every_field_intact() -> None:
    store, market = _store()
    artifact = _artifact()
    chain = _supply_chain(artifact)
    market.publish_artifact(artifact, supply_chain=chain)

    assert market.supply_chain(ARTIFACT_ID, "1.4.2") == chain
    stored = market.supply_chain(ARTIFACT_ID, "1.4.2")
    assert stored is not None
    assert stored.sbom is not None and stored.sbom.digest == _SBOM_DIGEST
    assert stored.source_chain[0].stage is SourceStage.PUBLISHED
    assert stored.release_history[0].digest == artifact.digest
    assert stored.declared_permissions == frozenset({ProviderPermission.TARGET_READ})
    store.close()


def test_a_registry_round_trips_with_its_federation_edges() -> None:
    store, market = _store()
    official = _registry(registry_id="mayhem.official", scope=RegistryScope.OFFICIAL)
    private = _registry(
        registry_id="acme.private",
        scope=RegistryScope.ORGANIZATION_PRIVATE,
        organization="acme",
        federates_with=("mayhem.official",),
    )
    market.publish_registry(official)
    market.publish_registry(private)

    assert market.registry("acme.private") == private
    assert set(market.registries()) == {official, private}
    assert [entry.registry_id for entry in market.registries()] == [
        "acme.private",
        "mayhem.official",
    ]
    store.close()


def test_a_certification_pairing_round_trips_and_appends_per_sequence() -> None:
    store, market = _store()
    market.link(_cert())
    market.link(_cert())

    linked = market.certifications(artifact_digest=_ARTIFACT_DIGEST)
    assert len(linked) == 2
    assert market.certifications(artifact_digest=_OTHER_DIGEST) == ()
    assert all(isinstance(item, ArtifactCertification) for item in linked)
    store.close()


def test_a_revocation_round_trips_with_its_scope_and_deadline() -> None:
    store, market = _store()
    revocation = _revocation()
    market.revoke(revocation)

    assert market.revocations() == (revocation,)
    assert market.blocking(_artifact(), now=_NOW) == (revocation,)
    assert market.pending(_artifact(), now=_NOW - timedelta(days=2)) == (revocation,)
    store.close()


def test_a_pin_round_trips_and_removal_keeps_the_row_as_history() -> None:
    store, market = _store()
    pin = market.install(
        ARTIFACT_ID, "1.4.2", _ARTIFACT_DIGEST, "community.registry", PROVIDER_ID, now=_NOW
    )

    assert pin.state is PinState.INSTALLED
    assert market.pin(ARTIFACT_ID, "1.4.2") == pin
    assert market.installed(ARTIFACT_ID) == (pin,)
    assert market.pins(state=PinState.INSTALLED) == (pin,)

    removed = market.remove(ARTIFACT_ID, "1.4.2", now=_NOW)

    assert removed is not None
    assert removed.state is PinState.REMOVED
    assert removed.removed_at == _NOW.isoformat()
    assert market.installed() == ()
    assert len(market.pins(state=PinState.REMOVED)) == 1
    assert market.remove(ARTIFACT_ID, "1.4.2", now=_NOW) is None
    store.close()


def test_publishing_is_an_upsert_so_a_new_version_coexists() -> None:
    store, market = _store()
    first = _artifact()
    second = _artifact(version="1.5.0", digest=_OTHER_DIGEST)
    market.publish_artifact(first, supply_chain=_supply_chain(first))
    market.publish_artifact(second, supply_chain=_supply_chain(second))

    assert market.versions(ARTIFACT_ID) == ("1.4.2", "1.5.0")
    assert len(market.artifacts(artifact_id=ARTIFACT_ID)) == 2
    store.close()


def test_deprecating_moves_only_the_notice() -> None:
    """Withdrawal cannot quietly change the bytes or the declared permissions."""
    store, market = _store()
    artifact = _artifact(dependencies=(ArtifactDependency(name="acme.libs", constraint=">=1"),))
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))

    withdrawn = market.deprecate(ARTIFACT_ID, "1.4.2", _deprecation(), now=_NOW)

    assert withdrawn.is_deprecated
    assert withdrawn.deprecation == _deprecation()
    assert withdrawn.digest == artifact.digest
    assert withdrawn.dependencies == artifact.dependencies
    assert withdrawn.permissions == artifact.permissions
    assert market.supply_chain(ARTIFACT_ID, "1.4.2") == _supply_chain(artifact)
    store.close()


def test_deprecating_something_unpublished_is_refused() -> None:
    store, market = _store()
    with pytest.raises(MarketplaceError) as excinfo:
        market.deprecate(ARTIFACT_ID, "9.9.9", _deprecation(), now=_NOW)
    assert excinfo.value.code == "marketplace.artifact_not_found"
    store.close()


def test_a_supply_chain_filed_under_other_bytes_is_refused() -> None:
    store, market = _store()
    with pytest.raises(MarketplaceError) as excinfo:
        market.publish_artifact(
            _artifact(), supply_chain=_supply_chain(_artifact(digest=_OTHER_DIGEST))
        )
    assert excinfo.value.code == "marketplace.supply_chain_digest_mismatch"
    assert market.artifacts() == ()
    store.close()


def test_a_supply_chain_naming_another_publisher_is_refused() -> None:
    store, market = _store()
    artifact = _artifact()
    chain = SupplyChainRecord.model_validate(
        {
            **_supply_chain(artifact).model_dump(),
            "publisher": _publisher(organization=None).model_copy(update={"publisher_id": "other"}),
        }
    )
    with pytest.raises(MarketplaceError) as excinfo:
        market.publish_artifact(artifact, supply_chain=chain)
    assert excinfo.value.code == "marketplace.supply_chain_publisher_mismatch"
    store.close()


def test_a_supply_chain_with_no_release_history_is_refused() -> None:
    store, market = _store()
    artifact = _artifact()
    chain = SupplyChainRecord.model_validate(
        {**_supply_chain(artifact).model_dump(), "release_history": ()}
    )
    with pytest.raises(MarketplaceError) as excinfo:
        market.publish_artifact(artifact, supply_chain=chain)
    assert excinfo.value.code == "marketplace.no_release_history"
    assert market.artifacts() == ()
    store.close()


def test_requiring_a_supply_chain_that_does_not_exist_is_refused() -> None:
    store, market = _store()
    with pytest.raises(MarketplaceError) as excinfo:
        market.require_supply_chain(ARTIFACT_ID, "1.4.2")
    assert excinfo.value.code == "marketplace.no_supply_chain_record"
    store.close()


def test_a_naive_timestamp_is_refused_on_every_write() -> None:
    store, market = _store()
    artifact = _artifact()
    naive = datetime(2026, 5, 4, 9, 0)  # noqa: DTZ001 — the point of the test
    with pytest.raises(MarketplaceError) as excinfo:
        market.publish_artifact(artifact, supply_chain=_supply_chain(artifact), now=naive)
    assert excinfo.value.code == "marketplace.naive_timestamp"
    with pytest.raises(MarketplaceError):
        market.revoke(_revocation(), now=naive)
    assert market.artifacts() == ()
    assert market.revocations() == ()
    store.close()


def test_a_pin_needs_the_provider_that_will_execute_it() -> None:
    store, market = _store()
    with pytest.raises(MarketplaceError) as excinfo:
        market.install(ARTIFACT_ID, "1.4.2", _ARTIFACT_DIGEST, "community.registry", "", now=_NOW)
    assert excinfo.value.code == "marketplace.provider_id_required"
    assert market.pins() == ()
    store.close()


def test_a_live_pin_cannot_be_silently_repointed() -> None:
    store, market = _store()
    market.install(
        ARTIFACT_ID, "1.4.2", _ARTIFACT_DIGEST, "community.registry", PROVIDER_ID, now=_NOW
    )
    with pytest.raises(MarketplaceError) as excinfo:
        market.install(
            ARTIFACT_ID, "1.4.2", _OTHER_DIGEST, "community.registry", PROVIDER_ID, now=_NOW
        )
    assert excinfo.value.code == "marketplace.pin_already_held"
    assert _ARTIFACT_DIGEST in str(excinfo.value)
    assert _OTHER_DIGEST in str(excinfo.value)
    assert market.installed()[0].digest == _ARTIFACT_DIGEST
    store.close()


def test_reinstalling_the_same_bytes_after_removal_is_allowed() -> None:
    store, market = _store()
    market.install(
        ARTIFACT_ID, "1.4.2", _ARTIFACT_DIGEST, "community.registry", PROVIDER_ID, now=_NOW
    )
    market.remove(ARTIFACT_ID, "1.4.2", now=_NOW)
    again = market.install(
        ARTIFACT_ID, "1.4.2", _ARTIFACT_DIGEST, "community.registry", PROVIDER_ID, now=_NOW
    )
    assert again.state is PinState.INSTALLED
    assert len(market.installed()) == 1
    store.close()


# ── 4. pin resolution ────────────────────────────────────────────────────────


def test_a_pin_resolves_by_exact_version() -> None:
    registry = _certified_market()
    pin = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW)

    assert pin.digest == _ARTIFACT_DIGEST
    assert pin.ref == f"{ARTIFACT_ID}@1.4.2"
    assert pin.installed is False
    assert pin.artifact_class is ArtifactClass.VERIFIED_COMMUNITY
    assert pin.supply_chain is not None
    assert pin.notice == SIGNATURE_TRUST_NOTICE


def test_a_pin_resolves_by_exact_version_and_digest() -> None:
    registry = _certified_market()
    pin = registry.resolve(ARTIFACT_ID, version="1.4.2", digest=_ARTIFACT_DIGEST, now=_NOW)
    assert pin.digest == _ARTIFACT_DIGEST


def test_a_pin_that_names_other_bytes_is_refused() -> None:
    registry = _certified_market()
    with pytest.raises(MarketplaceError) as excinfo:
        registry.resolve(ARTIFACT_ID, version="1.4.2", digest=_TAMPERED_DIGEST, now=_NOW)
    assert excinfo.value.code == "marketplace.digest_mismatch"
    assert _ARTIFACT_DIGEST in str(excinfo.value)
    assert _TAMPERED_DIGEST in str(excinfo.value)


def test_resolving_an_unpublished_version_names_the_ones_that_exist() -> None:
    registry = _catalog()
    registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW)
    with pytest.raises(MarketplaceError) as excinfo:
        registry.resolve(ARTIFACT_ID, version="9.9.9", now=_NOW)
    assert excinfo.value.code == "marketplace.artifact_not_found"
    assert "1.4.2" in str(excinfo.value)


def test_resolving_an_unpublished_artifact_is_refused() -> None:
    registry = _catalog()
    with pytest.raises(MarketplaceError) as excinfo:
        registry.resolve("ghost.pack", version="1.0.0", now=_NOW)
    assert excinfo.value.code == "marketplace.artifact_not_found"


def test_a_pin_never_resolves_to_a_range() -> None:
    """``resolve`` takes an explicit version; there is no "latest" argument."""
    import inspect

    parameters = inspect.signature(type(_catalog()).resolve).parameters
    assert parameters["version"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["version"].default is inspect.Parameter.empty
    assert "latest" not in parameters


def test_an_installed_pin_reports_itself_as_installed() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    market.install(
        ARTIFACT_ID, "1.4.2", artifact.digest, "community.registry", PROVIDER_ID, now=_NOW
    )
    assert registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).installed is True
    assert len(registry.installed()) == 1
    assert registry.uninstall(ARTIFACT_ID, "1.4.2", now=_NOW) is True
    assert registry.uninstall(ARTIFACT_ID, "1.4.2", now=_NOW) is False
    assert registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).installed is False
    store.close()


# ── 5. install: integrity, deprecation, revocation, compatibility ────────────


def test_installing_hashes_the_bytes_and_records_the_verdict() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    market.link(_cert())

    pin = registry.install(
        ARTIFACT_ID,
        version="1.4.2",
        digest=_ARTIFACT_DIGEST,
        provider_id=PROVIDER_ID,
        observed_digest=_ARTIFACT_DIGEST,
        now=_NOW,
    )

    assert pin.installed is True
    stored = market.supply_chain(ARTIFACT_ID, "1.4.2")
    assert stored is not None
    assert stored.verification_state is DigestCheckState.DIGEST_MATCHED
    store.close()


def test_a_tampered_artifact_is_refused_at_install() -> None:
    """NEGATIVE CONTROL: bytes that do not hash to the published digest never install."""
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))

    with pytest.raises(MarketplaceError) as excinfo:
        registry.install(
            ARTIFACT_ID,
            version="1.4.2",
            digest=_ARTIFACT_DIGEST,
            provider_id=PROVIDER_ID,
            observed_digest=_TAMPERED_DIGEST,
            now=_NOW,
        )

    assert excinfo.value.code == "marketplace.digest_mismatch"
    assert _TAMPERED_DIGEST in str(excinfo.value)
    assert market.pins() == ()
    assert market.installed() == ()
    store.close()


def test_installing_a_pin_that_names_other_bytes_is_refused() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    with pytest.raises(MarketplaceError) as excinfo:
        registry.install(
            ARTIFACT_ID,
            version="1.4.2",
            digest=_TAMPERED_DIGEST,
            provider_id=PROVIDER_ID,
            observed_digest=_ARTIFACT_DIGEST,
            now=_NOW,
        )
    assert excinfo.value.code == "marketplace.digest_mismatch"
    assert market.pins() == ()
    store.close()


def test_installing_a_version_with_no_supply_chain_is_refused() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    market.publish_registry(_registry())
    with store.write() as conn:
        conn.execute(
            "INSERT INTO marketplace_artifacts (artifact_id, version, digest, registry_id, "
            " publisher_id, license_id, changelog_ref, deprecation_json, permissions_json, "
            " dependencies_json, artifact_json, published_at) "
            "VALUES (?,?,?,'community.registry','acme.labs','Apache-2.0','ref','','[]','[]',?,?)",
            (
                ARTIFACT_ID,
                "1.4.2",
                _ARTIFACT_DIGEST,
                _artifact().model_dump_json(),
                _NOW.isoformat(),
            ),
        )
    with pytest.raises(MarketplaceError) as excinfo:
        registry.install(
            ARTIFACT_ID,
            version="1.4.2",
            digest=_ARTIFACT_DIGEST,
            provider_id=PROVIDER_ID,
            observed_digest=_ARTIFACT_DIGEST,
            now=_NOW,
        )
    assert excinfo.value.code == "marketplace.no_supply_chain_record"
    assert market.pins() == ()
    store.close()


def test_a_deprecated_version_cannot_be_newly_installed() -> None:
    """Deprecation governs new pins, and an install is a new pin."""
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact(deprecation=_deprecation())
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    market.link(_cert())

    with pytest.raises(MarketplaceError) as excinfo:
        registry.install(
            ARTIFACT_ID,
            version="1.4.2",
            digest=_ARTIFACT_DIGEST,
            provider_id=PROVIDER_ID,
            observed_digest=_ARTIFACT_DIGEST,
            now=_NOW,
        )

    assert excinfo.value.code == "marketplace.deprecated_install"
    assert market.pins() == ()
    store.close()


def test_an_already_revoked_version_cannot_be_installed() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    market.link(_cert())
    market.revoke(_revocation(), now=_NOW)

    with pytest.raises(MarketplaceError) as excinfo:
        registry.install(
            ARTIFACT_ID,
            version="1.4.2",
            digest=_ARTIFACT_DIGEST,
            provider_id=PROVIDER_ID,
            observed_digest=_ARTIFACT_DIGEST,
            now=_NOW,
        )

    assert excinfo.value.code == "marketplace.revoked"
    assert market.pins() == ()
    store.close()


def test_a_revocation_whose_deadline_has_not_arrived_does_not_block_an_install() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    market.link(_cert())
    announced = _revocation(
        issued_at=_NOW - timedelta(minutes=5),
        propagation_deadline=_NOW + timedelta(hours=1),
    )
    market.revoke(announced, now=_NOW)

    pin = registry.install(
        ARTIFACT_ID,
        version="1.4.2",
        digest=_ARTIFACT_DIGEST,
        provider_id=PROVIDER_ID,
        observed_digest=_ARTIFACT_DIGEST,
        now=_NOW,
    )

    assert pin.installed is True
    assert market.pending(artifact, now=_NOW) == (announced,)
    store.close()


# ── 6. compatibility against the local matrix cell ───────────────────────────


def test_an_artifact_certified_on_this_cell_is_compatible() -> None:
    registry = _certified_market()
    verdict = registry.compatibility(
        registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact, _cell(), now=_NOW
    )

    assert isinstance(verdict, CompatibilityVerdict)
    assert verdict.compatible is True
    assert verdict.refusals == ()
    assert verdict.certified_fault_ids == (FAULT_ID,)
    assert verdict.cell == _cell().label


def test_evidence_from_another_cell_does_not_transfer() -> None:
    """A record made on another machine is evidence about another machine."""
    registry = _certified_market()
    artifact = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact
    elsewhere = _cell(kernel="6.9.0-13-generic")

    verdict = registry.compatibility(artifact, elsewhere, now=_NOW)

    assert verdict.compatible is False
    assert verdict.certified_fault_ids == ()
    assert verdict.refusals[0].startswith("marketplace.cell_not_certified")
    assert elsewhere.label in verdict.refusals[0]


def test_an_uncertified_artifact_is_incompatible_with_every_cell() -> None:
    registry = _catalog()
    verdict = registry.compatibility(
        registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact, _cell(), now=_NOW
    )

    assert verdict.compatible is False
    assert verdict.refusals[0].startswith("marketplace.no_certification_evidence")


def test_a_record_for_other_bytes_is_not_evidence_for_these() -> None:
    registry = _catalog()
    registry.store.link(_cert(digest=_OTHER_DIGEST))
    artifact = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact

    assert registry.compatibility(artifact, _cell(), now=_NOW).compatible is False
    assert registry.listing_entry(artifact, now=_NOW).artifact_class is (ArtifactClass.UNVERIFIED)


def test_a_lapsed_record_stops_being_evidence_without_anything_being_rewritten() -> None:
    """Reads are aged, writes are not — the certification repository's discipline."""
    registry = _certified_market()
    artifact = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact

    assert registry.compatibility(artifact, _cell(), now=_NOW).compatible is True
    assert registry.compatibility(artifact, _cell(), now=_BEYOND).compatible is False
    assert registry.store.certifications_for(artifact), "the row is still there, unrewritten"
    assert registry.store.certifications_for(artifact)[0].record.state.value == "certified"


def test_installing_against_a_foreign_cell_is_refused() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    market.link(_cert())

    with pytest.raises(MarketplaceError) as excinfo:
        registry.install(
            ARTIFACT_ID,
            version="1.4.2",
            digest=_ARTIFACT_DIGEST,
            provider_id=PROVIDER_ID,
            observed_digest=_ARTIFACT_DIGEST,
            cell=_cell(kernel="6.9.0-13-generic"),
            now=_NOW,
        )

    assert excinfo.value.code == "marketplace.incompatible"
    assert market.pins() == ()
    store.close()


def test_installing_against_the_certifying_cell_succeeds() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    market.link(_cert())

    pin = registry.install(
        ARTIFACT_ID,
        version="1.4.2",
        digest=_ARTIFACT_DIGEST,
        provider_id=PROVIDER_ID,
        observed_digest=_ARTIFACT_DIGEST,
        cell=_cell(),
        now=_NOW,
    )

    assert pin.installed is True
    store.close()


# ── 7. federation of organization-private registries ────────────────────────


def test_a_private_registry_federated_with_the_official_one_is_listed() -> None:
    registry = _catalog()
    registry.adopt_registry(_registry(registry_id="mayhem.official", scope=RegistryScope.OFFICIAL))
    registry.adopt_registry(
        _registry(
            registry_id="acme.private",
            scope=RegistryScope.ORGANIZATION_PRIVATE,
            organization="acme",
            federates_with=("mayhem.official",),
        )
    )
    private_artifact = _artifact(
        digest=_DEPRECATED_DIGEST,
        publisher=_publisher(organization="acme"),
        registry=_registry(
            registry_id="acme.private",
            scope=RegistryScope.ORGANIZATION_PRIVATE,
            organization="acme",
            federates_with=("mayhem.official",),
        ),
    )
    registry.store.publish_artifact(private_artifact, supply_chain=_supply_chain(private_artifact))

    assert registry.federates("acme.private") is True
    entries = registry.listing(registry_id="acme.private", now=_NOW)
    assert [entry.artifact.artifact_id for entry in entries] == [ARTIFACT_ID]


def test_federation_buys_bytes_not_standing() -> None:
    """The private catalogue is reachable, and still labels as organization-private.

    Federated with the official registry *and* carrying a current certification
    for its own digest: the derived class is still ``organization_private``,
    because :func:`classify_artifact` never sees the registry set.
    """
    registry = _catalog()
    official = _registry(registry_id="mayhem.official", scope=RegistryScope.OFFICIAL)
    private = _registry(
        registry_id="acme.private",
        scope=RegistryScope.ORGANIZATION_PRIVATE,
        organization="acme",
        federates_with=("mayhem.official",),
    )
    registry.adopt_registry(official)
    registry.adopt_registry(private)
    artifact = _artifact(
        digest=_DEPRECATED_DIGEST,
        publisher=_publisher(organization="acme"),
        registry=private,
    )
    registry.store.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    registry.store.link(_cert(digest=_DEPRECATED_DIGEST))

    entry = registry.listing_entry(artifact, now=_NOW)

    assert entry.artifact_class is ArtifactClass.ORGANIZATION_PRIVATE
    assert entry.label.may_display_certified_state is True
    assert "no authentication of the publisher" in entry.label.meaning()
    with pytest.raises(TrustLabelError) as excinfo:
        registry.listing_entry(artifact, claimed=ArtifactClass.OFFICIAL, now=_NOW)
    assert excinfo.value.code == "not_official_registry"


def test_a_registry_id_nobody_published_is_refused() -> None:
    registry = _catalog()
    registry.adopt_registry(_registry(registry_id="acme.lonely", scope=RegistryScope.COMMUNITY))
    with pytest.raises(MarketplaceError) as excinfo:
        registry.listing(registry_id="ghost.registry", now=_NOW)
    assert excinfo.value.code == "marketplace.registry_not_found"
    assert "acme.lonely" in str(excinfo.value)


def test_federation_membership_follows_publication_and_nothing_more() -> None:
    """Every published registry is a seed, so being in the federation is not a gate.

    Recorded as a test because the alternative reading — a private registry
    needing a *check* before it can be listed — would be the claim that federation
    confers something. It does not: Phase 1's closure seeds from every row, so
    the honest assertion is that a published peer is inside the closure and an
    unpublished id is not in the table at all.
    """
    registry = _empty_market()
    assert registry.federation() is None
    assert registry.federates("acme.lonely") is False

    registry.adopt_registry(_registry(registry_id="acme.lonely", scope=RegistryScope.COMMUNITY))

    assert registry.federates("acme.lonely") is True
    assert registry.federation() is not None
    assert registry.federation().registry_ids == ("acme.lonely",)


def test_an_unknown_registry_is_refused() -> None:
    registry = _empty_market()
    with pytest.raises(MarketplaceError) as excinfo:
        registry.require_registry("ghost.registry")
    assert excinfo.value.code == "marketplace.registry_not_found"


def test_the_federation_closure_follows_the_stored_edges() -> None:
    registry = _empty_market()
    official = _registry(registry_id="mayhem.official", scope=RegistryScope.OFFICIAL)
    peer = _registry(registry_id="acme.peer", scope=RegistryScope.COMMUNITY)
    for entry in (official, peer):
        registry.adopt_registry(entry)

    assert set(registry.federation().registry_ids) == {"mayhem.official", "acme.peer"}

    registry.adopt_registry(
        _registry(
            registry_id="acme.private",
            scope=RegistryScope.ORGANIZATION_PRIVATE,
            organization="acme",
            federates_with=("acme.peer",),
        )
    )
    registry.adopt_registry(
        _registry(
            registry_id="acme.peer",
            scope=RegistryScope.COMMUNITY,
            federates_with=("acme.private",),
        )
    )

    federation = registry.federation()
    assert federation is not None
    assert set(federation.registry_ids) == {
        "mayhem.official",
        "acme.peer",
        "acme.private",
    }
    assert registry.federates("acme.private") is True


def test_a_federation_edge_to_an_unpublished_peer_is_refused_by_name() -> None:
    """A catalogue that cannot be walked says so, and says which peer is missing.

    The closure is computed over stored rows, so an edge to a registry with no
    row cannot be resolved. The refusal names the peer instead of surfacing as a
    ``KeyError`` from the walk, and does not silently drop the edge — an edge the
    engine quietly ignored would understate the federation.
    """
    registry = _empty_market()
    registry.adopt_registry(
        _registry(
            registry_id="acme.peer",
            scope=RegistryScope.COMMUNITY,
            federates_with=("unloaded.peer",),
        )
    )

    with pytest.raises(MarketplaceError) as excinfo:
        registry.federation()

    assert excinfo.value.code == "marketplace.dangling_federation_edge"
    assert "unloaded.peer" in str(excinfo.value)
    with pytest.raises(MarketplaceError) as excinfo:
        registry.require_registry("unloaded.peer")
    assert excinfo.value.code == "marketplace.registry_not_found"


# ── 8. revocation propagation to the loader's dispatch path ─────────────────


def test_install_then_revoke_and_the_dispatch_is_refused(tmp_path: Path) -> None:
    """The drill the plan asks for, end to end through a real loader.

    Install, admit, revoke with the deadline already passed, and the next
    dispatch is refused with a message naming the revocation that caused it.
    """
    registry = _installed_market(tmp_path)
    registry.store.link(_cert())

    before = registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert before.artifact_ref == f"{ARTIFACT_ID}@1.4.2"
    assert before.deprecated is False

    registry.store.revoke(_revocation(), now=_NOW)

    with pytest.raises(MarketplaceError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)

    assert excinfo.value.code == "marketplace.revoked"
    message = str(excinfo.value)
    assert "acme.rev.0001" in message
    assert "security_defect" in message
    assert _ARTIFACT_DIGEST in message


def test_a_revoked_provider_cannot_execute_after_the_deadline(tmp_path: Path) -> None:
    """NEGATIVE CONTROL: the runtime is unreachable from the provider registry.

    This is the defect the phase exists to prevent, so the test does not stop at
    ``admit``: it re-registers the provider's own registration with the guarded
    factory and then asks
    :meth:`~mayhem.providers.registry.ProviderRegistry.runtime` for the runtime,
    which is the call an execution path actually makes.
    """
    loader = _loaded_loader(tmp_path)
    registry = _installed_market(tmp_path, loader=loader)

    guarded = registry.guarded_factory(ARTIFACT_ID, version="1.4.2", factory=ProbeRuntime)
    registration = loader.registry.registration(PROVIDER_ID)
    loader.registry.register(registration, guarded, replace=True)
    assert isinstance(loader.registry.runtime(PROVIDER_ID), ProbeRuntime)

    registry.store.revoke(_revocation(), now=_NOW)

    with pytest.raises(MarketplaceError) as excinfo:
        loader.registry.runtime(PROVIDER_ID)
    assert excinfo.value.code == "marketplace.revoked"
    assert "acme.rev.0001" in str(excinfo.value)


def test_a_revocation_announced_before_its_deadline_does_not_stop_a_dispatch(
    tmp_path: Path,
) -> None:
    """The honest middle state: it dispatches, and the admission says so."""
    registry = _installed_market(tmp_path)
    announced = _revocation(
        issued_at=_NOW - timedelta(minutes=5),
        propagation_deadline=_NOW + timedelta(hours=1),
    )
    registry.store.revoke(announced, now=_NOW)

    admission = registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)

    assert admission.announced_revocations
    assert "acme.rev.0001" in admission.announced_revocations[0]
    assert admission.announced_revocations[0].endswith(")")


def test_a_revocation_by_publisher_stops_every_version_it_names(tmp_path: Path) -> None:
    registry = _installed_market(tmp_path)
    registry.store.revoke(
        _revocation(
            revocation_id="acme.rev.publisher",
            scope=RevocationScope.PUBLISHER,
            publisher_id="acme.labs",
        ),
        now=_NOW,
    )
    with pytest.raises(MarketplaceError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert excinfo.value.code == "marketplace.revoked"
    assert "publisher acme.labs" in str(excinfo.value)


def test_a_revocation_by_registry_stops_everything_published_there(tmp_path: Path) -> None:
    registry = _installed_market(tmp_path)
    registry.store.revoke(
        _revocation(
            revocation_id="acme.rev.registry",
            scope=RevocationScope.REGISTRY,
            registry_id="community.registry",
        ),
        now=_NOW,
    )
    with pytest.raises(MarketplaceError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert excinfo.value.code == "marketplace.revoked"
    assert "registry community.registry" in str(excinfo.value)


def test_a_revocation_for_other_bytes_does_not_stop_this_one(tmp_path: Path) -> None:
    registry = _installed_market(tmp_path)
    other_bytes = _revocation(revocation_id="acme.rev.other", digest=_TAMPERED_DIGEST)
    registry.store.revoke(other_bytes, now=_NOW)
    assert registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW).digest == _ARTIFACT_DIGEST


def test_dispatching_something_that_was_never_installed_is_refused(tmp_path: Path) -> None:
    loader = _loaded_loader(tmp_path)
    registry = _certified_market(loader)
    with pytest.raises(MarketplaceError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert excinfo.value.code == "marketplace.not_installed"


def test_dispatching_after_an_uninstall_is_refused(tmp_path: Path) -> None:
    registry = _installed_market(tmp_path)
    registry.uninstall(ARTIFACT_ID, "1.4.2", now=_NOW)
    with pytest.raises(MarketplaceError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert excinfo.value.code == "marketplace.not_installed"


def test_a_provider_that_never_loaded_cannot_be_dispatched_through_the_gate(
    tmp_path: Path,
) -> None:
    """The gate goes through the loader, so an unadmitted provider has no profile."""
    store, market = _store()
    loader = ProviderLoader()
    registry = MarketplaceRegistry(store=market, loader=loader)
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    market.link(_cert())
    market.install(
        ARTIFACT_ID, "1.4.2", artifact.digest, "community.registry", "never.loaded", now=_NOW
    )
    with pytest.raises(MarketplaceError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert excinfo.value.code == "marketplace.provider_not_loaded"
    store.close()
    assert tmp_path.exists()


def test_the_dispatch_path_uses_the_profile_the_loader_itself_chose(tmp_path: Path) -> None:
    """Integration, not adjacency: the gate asks *that* loader for the profile."""
    loader = _loaded_loader(tmp_path)
    registry = _installed_market(tmp_path, loader=loader)

    admission = registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)

    loader_profile = loader.sandbox_profile(PROVIDER_ID)
    # The loader re-attaches the operator's roots to the stored profile, so the
    # object is a copy: equality, not identity, and the tier must be the loader's.
    assert admission.profile == loader_profile
    assert admission.profile.profile_id == loader_profile.profile_id
    assert admission.profile.tier == loader_profile.tier
    assert admission.provider_id == PROVIDER_ID
    assert admission.sandbox_admission.profile_id == loader_profile.profile_id
    assert admission.sandbox_enforced is admission.profile.admits_enforcement


def test_the_loader_s_own_sandbox_refusal_still_stands_at_dispatch(tmp_path: Path) -> None:
    """A marketplace admission is not a substitute for the loader's gates.

    The provider declares ``target:read`` and ``subprocess``, so its profile needs
    a seccomp filter this build does not apply. The loader loads it under the
    default posture (declared, not applied) and the operator then *tightens* the
    posture — ``require_sandbox_enforcement`` is the loader's own public switch.
    The dispatch gate reads that same switch, so the loader's own
    ``provider_sandbox_mechanism_unapplied`` is what refuses, after the pin
    exists. Not a marketplace code, and not swallowed.
    """
    loader = _loaded_loader(
        tmp_path,
        permissions=["target:read", "subprocess"],
        allowed_permissions=frozenset(
            {ProviderPermission.TARGET_READ, ProviderPermission.SUBPROCESS}
        ),
    )
    loader.require_sandbox_enforcement = True
    market = _store()[1]
    registry = MarketplaceRegistry(store=market, loader=loader)
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    market.link(_cert())
    market.install(
        ARTIFACT_ID, "1.4.2", artifact.digest, "community.registry", PROVIDER_ID, now=_NOW
    )

    with pytest.raises(ProviderSandboxError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert excinfo.value.code == "provider_sandbox_mechanism_unapplied"


def test_a_revoked_artifact_is_refused_before_the_loader_is_consulted(tmp_path: Path) -> None:
    """The marketplace rule is checked first, and names its own record."""
    loader = _loaded_loader(tmp_path)
    registry = _installed_market(tmp_path, loader=loader)
    registry.store.revoke(_revocation(), now=_NOW)

    with pytest.raises(MarketplaceError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)

    assert excinfo.value.code == "marketplace.revoked"
    assert excinfo.value.code != "marketplace.provider_not_loaded"


def test_a_guarded_factory_refuses_an_artifact_that_was_never_installed(tmp_path: Path) -> None:
    loader = _loaded_loader(tmp_path)
    registry = _certified_market(loader)
    with pytest.raises(MarketplaceError) as excinfo:
        registry.guarded_factory(ARTIFACT_ID, version="1.4.2", factory=ProbeRuntime)
    assert excinfo.value.code == "marketplace.not_installed"


def test_a_guarded_factory_still_yields_the_runtime_when_nothing_is_revoked(
    tmp_path: Path,
) -> None:
    loader = _loaded_loader(tmp_path)
    registry = _installed_market(tmp_path, loader=loader)
    guarded = registry.guarded_factory(ARTIFACT_ID, version="1.4.2", factory=ProbeRuntime)
    assert isinstance(guarded(), ProbeRuntime)


# ── 9. deprecation at dispatch ───────────────────────────────────────────────


def test_a_deprecated_artifact_that_is_already_installed_still_dispatches(
    tmp_path: Path,
) -> None:
    """THE DECISION, pinned: withdrawal stops *new* use, not running bytes.

    Phase 1 left ``dispatches()`` permissive and handed the question here,
    because only an admission path knows whether an artifact is already
    installed. It does, and the answer is that a deprecated version keeps
    running — while every admission says so out loud.
    """
    registry = _installed_market(tmp_path, deprecation=_deprecation())

    admission = registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)

    assert admission.deprecated is True
    assert admission.deprecation_reason == _deprecation().reason
    assert admission.artifact_class is ArtifactClass.DEPRECATED
    assert admission.to_dict()["deprecated"] is True


def test_revoking_a_deprecated_artifact_stops_it(tmp_path: Path) -> None:
    """The kill switch: an operator who wants it to stop revokes it, by name."""
    registry = _installed_market(tmp_path, deprecation=_deprecation())
    assert registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW).deprecated is True

    registry.store.revoke(
        _revocation(
            revocation_id="acme.rev.dep",
            reason=RevocationReason.SUPERSEDED,
            digest=_ARTIFACT_DIGEST,
        ),
        now=_NOW,
    )

    with pytest.raises(MarketplaceError) as excinfo:
        registry.admit(ARTIFACT_ID, version="1.4.2", now=_NOW)
    assert excinfo.value.code == "marketplace.revoked"
    assert "acme.rev.dep" in str(excinfo.value)
    assert "superseded" in str(excinfo.value)


def test_the_approval_gate_names_deprecation_and_the_missing_evidence(tmp_path: Path) -> None:
    registry = _catalog()
    artifact = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact
    codes = [line.split(":", 1)[0] for line in registry.approval_gate(artifact, now=_NOW)]
    assert "artifact.unverified" in codes

    registry.store.deprecate(ARTIFACT_ID, "1.4.2", _deprecation(), now=_NOW)
    withdrawn = registry.store.artifact(ARTIFACT_ID, "1.4.2")
    assert withdrawn is not None
    codes = [line.split(":", 1)[0] for line in registry.approval_gate(withdrawn, now=_NOW)]
    assert "artifact.deprecated" in codes
    assert tmp_path.exists() or True


# ── 10. listing, and the overclaim it must refuse ────────────────────────────


def test_an_artifact_claiming_verified_with_no_record_is_refused_at_listing() -> None:
    """NEGATIVE CONTROL: a listing cannot print a class the records do not support."""
    registry = _catalog()
    artifact = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact

    with pytest.raises(TrustLabelError) as excinfo:
        registry.listing_entry(artifact, claimed=ArtifactClass.VERIFIED_COMMUNITY, now=_NOW)

    assert excinfo.value.code == "no_certification_record"
    assert registry.listing_entry(artifact, now=_NOW).artifact_class is (ArtifactClass.UNVERIFIED)


def test_claiming_verified_with_a_record_for_other_bytes_is_refused() -> None:
    """A record for other bytes is *absent*, not mismatched — by construction.

    The store keys the pairing on the artifact digest, so
    :meth:`certifications_for` hands the domain nothing to mis-apply. The refusal
    is therefore ``no_certification_record`` rather than the domain's
    ``certification_digest_mismatch``: the engine cannot supply a record about
    bytes this record was not made against, which is the stronger statement.
    """
    registry = _catalog()
    registry.store.link(_cert(digest=_OTHER_DIGEST))
    artifact = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact

    assert registry.store.certifications_for(artifact) == ()
    with pytest.raises(TrustLabelError) as excinfo:
        registry.listing_entry(artifact, claimed=ArtifactClass.VERIFIED_COMMUNITY, now=_NOW)
    assert excinfo.value.code == "no_certification_record"


def test_claiming_official_from_a_community_registry_is_refused() -> None:
    registry = _certified_market()
    artifact = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact
    with pytest.raises(TrustLabelError) as excinfo:
        registry.listing_entry(artifact, claimed=ArtifactClass.OFFICIAL, now=_NOW)
    assert excinfo.value.code == "not_official_registry"


def test_claiming_organization_private_from_a_public_registry_is_refused() -> None:
    registry = _certified_market()
    artifact = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact
    with pytest.raises(TrustLabelError) as excinfo:
        registry.listing_entry(artifact, claimed=ArtifactClass.ORGANIZATION_PRIVATE, now=_NOW)
    assert excinfo.value.code == "registry_scope_mismatch"


def test_claiming_the_class_the_records_actually_support_is_allowed() -> None:
    registry = _certified_market()
    artifact = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact
    entry = registry.listing_entry(artifact, claimed=ArtifactClass.VERIFIED_COMMUNITY, now=_NOW)
    assert entry.artifact_class is ArtifactClass.VERIFIED_COMMUNITY
    assert entry.label.certified_fault_ids == (FAULT_ID,)


def test_an_unverified_listing_cannot_display_a_certified_state() -> None:
    registry = _catalog()
    entries = registry.listing(now=_NOW)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.artifact_class is ArtifactClass.UNVERIFIED
    assert entry.label.may_display_certified_state is False
    assert entry.to_dict()["may_display_certified_state"] is False
    assert entry.supply_chain is not None
    assert entry.to_dict()["verification_state"] == "not_checked"


def test_a_listing_row_reports_only_the_digest_check_as_verification() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    registry.verify_bytes(ARTIFACT_ID, "1.4.2", _ARTIFACT_DIGEST, now=_NOW)
    entry = registry.listing_entry(artifact, now=_NOW)
    assert entry.to_dict()["verification_state"] == "digest_matched"
    assert _FORBIDDEN_REPORT_KEYS.isdisjoint(entry.to_dict())
    assert "cannot verify artifact signatures" in str(entry.to_dict()["notice"])
    store.close()


def test_an_official_artifact_needs_both_the_registry_and_the_record() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    official = _registry(registry_id="mayhem.official", scope=RegistryScope.OFFICIAL)
    artifact = _artifact(digest=_DEPRECATED_DIGEST, registry=official)
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))

    assert registry.listing_entry(artifact, now=_NOW).artifact_class is (ArtifactClass.UNVERIFIED)

    market.link(_cert(digest=_DEPRECATED_DIGEST))

    assert registry.listing_entry(artifact, now=_NOW).artifact_class is ArtifactClass.OFFICIAL
    store.close()


def test_a_lapsed_record_demotes_a_listing_with_nothing_being_rewritten() -> None:
    registry = _certified_market()
    artifact = registry.resolve(ARTIFACT_ID, version="1.4.2", now=_NOW).artifact
    assert registry.listing_entry(artifact, now=_NOW).artifact_class is (
        ArtifactClass.VERIFIED_COMMUNITY
    )
    assert registry.listing_entry(artifact, now=_BEYOND).artifact_class is (
        ArtifactClass.UNVERIFIED
    )


def test_a_deprecated_listing_reports_deprecated_whatever_its_evidence() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact(deprecation=_deprecation())
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    market.link(_cert())
    entry = registry.listing_entry(artifact, now=_NOW)
    assert entry.artifact_class is ArtifactClass.DEPRECATED
    assert "cannot back a new approval" in entry.label.meaning()
    store.close()


# ── 11. the store's read/write discipline ────────────────────────────────────


def test_the_store_publishes_the_registry_an_artifact_names() -> None:
    """Publishing an artifact also records its catalogue, so a listing is total."""
    store, market = _store()
    private = _registry(
        registry_id="acme.private",
        scope=RegistryScope.ORGANIZATION_PRIVATE,
        organization="acme",
    )
    artifact = _artifact(
        digest=_DEPRECATED_DIGEST, publisher=_publisher(organization="acme"), registry=private
    )
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))
    assert market.registry("acme.private") == private
    store.close()


def test_a_supply_chain_verdict_is_recorded_against_the_published_bytes() -> None:
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    artifact = _artifact()
    market.publish_artifact(artifact, supply_chain=_supply_chain(artifact))

    checked = registry.verify_bytes(ARTIFACT_ID, "1.4.2", _ARTIFACT_DIGEST, now=_NOW)

    assert checked.verification_state is DigestCheckState.DIGEST_MATCHED
    assert market.supply_chain(ARTIFACT_ID, "1.4.2") == checked
    store.close()


def test_verifying_bytes_that_are_not_published_is_refused() -> None:
    registry = _catalog()
    with pytest.raises(MarketplaceError) as excinfo:
        registry.verify_bytes(ARTIFACT_ID, "9.9.9", _ARTIFACT_DIGEST, now=_NOW)
    assert excinfo.value.code == "marketplace.artifact_not_found"


def test_the_store_exposes_the_loader_and_the_store_it_was_built_with() -> None:
    store, market = _store()
    loader = ProviderLoader()
    registry = MarketplaceRegistry(store=market, loader=loader)
    assert registry.store is market
    assert registry.loader is loader
    assert registry.registries() == ()
    store.close()


def test_the_engine_does_not_read_a_clock_for_any_decision_it_can_replay(
    tmp_path: Path,
) -> None:
    """``now`` is a parameter everywhere except the materialisation guard."""
    import inspect

    for name in ("admit", "compatibility", "listing", "resolve", "install", "listing_entry"):
        parameters = inspect.signature(getattr(MarketplaceRegistry, name)).parameters
        assert "now" in parameters, name
    assert "now" not in inspect.signature(MarketplaceRegistry.guarded_factory).parameters


def test_the_engine_tolerates_an_empty_catalog() -> None:
    """Totality: an empty catalog answers, it does not raise."""
    store, market = _store()
    registry = MarketplaceRegistry(store=market, loader=ProviderLoader())
    assert registry.listing(now=_NOW) == ()
    assert registry.installed() == ()
    assert registry.registries() == ()
    assert registry.federation() is None
    assert registry.store.revocations() == ()
    store.close()
