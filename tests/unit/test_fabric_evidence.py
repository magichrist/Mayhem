"""Plan 03 Phase 4: durable journal, command verification, and sealed evidence.

Phase 2's open items, closed here, and each one gets the test that would have
failed before it landed:

* ``FabricJournal`` was a protocol with no implementation. These tests run the
  crash-resume drill against a **real SQLite database** — migrated, closed, and
  reopened — rather than an in-memory double, and they roll the schema back to
  prove the down path.
* Signature *verification* was not implemented, so ``FABRIC_UNDERSIGNED`` was
  raised nowhere. Here it is raised, at two real sites, and the negative controls
  are the ones the plan names: an unsigned command, a replayed nonce, a deposed
  epoch, a superseded plan digest, and a journal row edited behind the model's
  back.

What is *reused* and what is *new*
----------------------------------

Verification is plan 19's
:class:`~mayhem.infra.agent_identity_verifier.AgentCommandVerifier`, bound
through :class:`~mayhem.controller.fabric_engine.FabricCommandVerifierPort`.
No HMAC, no key material, and no nonce table is reimplemented in this phase: the
tests assert the *port* is satisfied by plan 19's class, which is the check that
the two surfaces cannot drift apart.

Sealing is plan 12's
:class:`~mayhem.infra.attestation_store.AttestationRepository` and plan 12's
domain verifier, so "did the chain verify" is answered by reloading stored bytes,
never by re-running the sealer.

What is deliberately not asserted
---------------------------------

The manifests written here are **unsigned** — plan 12 Phase 2 mints no signature
bytes — and the tests assert that state and its stored reason, so they fail the
day sealing starts claiming authorship it has not earned.
"""

from __future__ import annotations

import inspect
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.agents.lease_client import LeaseClient
from mayhem.controller.fabric_engine import (
    FABRIC_COMMAND_UNVERIFIED,
    FABRIC_DUPLICATE_DISPATCH,
    FABRIC_INFLIGHT_UNRESOLVED,
    FABRIC_MALFORMED_ENVELOPE,
    DispatchClaim,
    DispatchRequest,
    DispatchResult,
    DispatchSettlement,
    FabricCommandVerifierPort,
    FabricEngine,
    FabricJournal,
    JournalEntry,
    ProviderResult,
)
from mayhem.controller.fabric_evidence import (
    EVENT_FABRIC_DISPATCHED,
    EVENT_FABRIC_DRIFT,
    EVENT_FABRIC_REFUSED,
    EVENT_FABRIC_RETRY,
    EVENT_FABRIC_SETTLED,
    FABRIC_EVENT_KINDS,
    FabricEvidenceRecorder,
    SqliteFabricJournal,
    decode_wire_command,
    fabric_chain_id,
    fabric_manifest_chain,
    fabric_timeline,
    load_fabric_chain,
    load_fabric_manifest,
    outcomes_of,
    run_id_of_chain,
    timeline_matches_journal,
    verify_dispatch_command,
    verify_fabric_chain,
)
from mayhem.domain.agent_identity import (
    AgentCredential,
    AgentIdentity,
    CertificateRef,
    TrustAnchorRef,
)
from mayhem.domain.attestation import GENESIS_DIGEST
from mayhem.domain.fabric import (
    FABRIC_PLAN_MISMATCH,
    FABRIC_PROTOCOL_VERSION,
    FABRIC_REPLAYED_NONCE,
    FABRIC_STALE_FENCE,
    FABRIC_UNDERSIGNED,
    CommandBodyRef,
    FabricCommand,
    FabricCommandRefused,
    FabricCommandType,
    FencingToken,
    StepSemantics,
    StepSpec,
)
from mayhem.domain.hashing import sha256_hex
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.domain.leases import (
    FaultLease,
    LeaseState,
    UndoOp,
    VerifyProbe,
    assert_all_recovered,
)
from mayhem.domain.outcomes import StepOutcome, TargetOutcome
from mayhem.infra.agent_identity_store import AgentIdentityRepository
from mayhem.infra.agent_identity_verifier import (
    ALGORITHM_HMAC_SHA256,
    SIGNATURE_PORT_UNAVAILABLE,
    AgentCommandVerifier,
    HmacSha256CommandSigner,
    HmacSha256SignatureVerifier,
    SignaturePortUnavailableError,
    SqliteNonceLedger,
    StaticKeyMaterial,
    X509CommandSignatureVerifier,
    signed_payload,
)
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationRepository,
)
from mayhem.infra.fabric_journal import (
    FABRIC_JOURNAL_MIGRATION,
    FABRIC_JOURNAL_TABLE,
    FABRIC_JOURNAL_VERSION,
    FabricJournalDuplicateEntryError,
    FabricJournalIntegrityError,
    FabricJournalRow,
    FabricJournalTable,
)
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

    from mayhem.infra.agent_identity_verifier import VerifiedCommand

#: The migration chain this phase applies: the production chain, unaltered.
#:
#: This used to be ``(*ALL_MIGRATIONS, FABRIC_JOURNAL_MIGRATION)`` — a splice, and
#: the "the test stays correct whatever a concurrent agent appends" trick. That
#: arrangement was wrong twice over, and registration fixed both halves:
#:
#: * **It was a broken chain.** Once ``FABRIC_JOURNAL_MIGRATION`` was registered,
#:   the splice registered version 33 a second time, so the migrator refused every
#:   fixture here with ``strictly increasing; got 33 after 33``.
#: * **It was a fixture built to fit the code under test.** Every database in this
#:   file was migrated through a chain no deployment ever runs. A chain spliced
#:   to contain the table under test cannot fail for want of that table, so these
#:   tests proved the row discipline and proved *nothing* about the table being
#:   present in production — which is exactly the defect registration removes, and
#:   exactly why the crash-resume drill was not entitled to call itself a
#:   crash-resume drill until now.
#:
#: So this is no longer a defensible *trick*; it is the plain production tuple.
#: The crash-resume tests below now migrate through ``ALL_MIGRATIONS`` itself,
#: which is what a deployment migrates to, and which makes their claim strictly
#: stronger than the splice ever supported.
MIGRATIONS = ALL_MIGRATIONS

#: The version the down path returns to: the one before the journal.
#:
#: Deliberately ``FABRIC_JOURNAL_VERSION - 1`` and deliberately *not*
#: ``len(ALL_MIGRATIONS) - 1``. The target of a rollback is a property of the
#: migration being rolled back ("undo the journal, leave its neighbour alone"),
#: not a property of how long the chain happens to be. Deriving it from
#: ``len()`` would silently retarget it at whatever landed next: register 34 and
#: ``migrate_down(33)`` becomes a no-op, so ``test_down_migration_removes_the_
#: table_and_restores_the_prior_head`` would stop exercising the journal's down
#: path while still reporting green. This form stays correct as the chain grows,
#: and the assertions above it are written to accommodate whatever else the
#: rollback necessarily also reverses.
PRIOR_HEAD = FABRIC_JOURNAL_VERSION - 1

NOW = datetime(2026, 3, 5, 9, 0, 0, tzinfo=UTC)
LATER = NOW + timedelta(seconds=45)

RUN_ID = "r-fabric-4"
STEP_ID = "s-1"
AGENT = "ag-1"
CONTROLLER = "ctl-a"
CREDENTIAL = "cr-1"
SECRET = b"m" * 32
OTHER_SECRET = b"w" * 32
PLAN = sha256_hex('{"steps":["inject"]}')
SUPERSEDED_PLAN = sha256_hex('{"steps":["inject","compensate"]}')
BODY_DIGEST = "d" * 64
TARGET = "pod/web-0"
OTHER_TARGET = "pod/web-1"
CERT_FINGERPRINT = "a" * 64


class ControllerKilled(BaseException):
    """Stands in for the controller process dying mid-dispatch.

    ``BaseException`` on purpose: the engine normalises ``Exception`` into a step
    outcome, and a process that is being killed must not be catchable there.
    """


class _Clock:
    def __init__(self, moment: datetime = NOW) -> None:
        self.moment = moment

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment = self.moment + timedelta(seconds=seconds)


# --------------------------------------------------------------------------- #
# Builders                                                                     #
# --------------------------------------------------------------------------- #


def _credential() -> AgentCredential:
    return AgentCredential(
        credential_id=CREDENTIAL,
        agent_id=AGENT,
        issued_at=NOW - timedelta(seconds=60),
        expires_at=NOW + timedelta(seconds=900),
        rotate_before=300.0,
    )


def _certificate() -> CertificateRef:
    return CertificateRef(
        subject=f"agent={AGENT}",
        issuer="ca-mesh-1",
        serial="01",
        sha256_fingerprint=CERT_FINGERPRINT,
        not_before=NOW - timedelta(hours=1),
        not_after=NOW + timedelta(hours=1),
    )


def _identity() -> AgentIdentity:
    return AgentIdentity(
        agent_id=AGENT,
        controller_id=CONTROLLER,
        principal=Principal(principal_id="sa-agent-1", kind=PrincipalKind.WORKLOAD),
        scope=EnvironmentScope(environment="staging"),
        credential=_credential(),
        certificate=_certificate(),
        trust_anchors=(
            TrustAnchorRef(
                ca_id="ca-mesh-1",
                subject="ca-mesh-1",
                sha256_fingerprint=CERT_FINGERPRINT,
            ),
        ),
    )


def keys(*secrets: tuple[str, bytes]) -> StaticKeyMaterial:
    material = StaticKeyMaterial()
    for key_id, secret in secrets or ((CREDENTIAL, SECRET),):
        material.add(key_id, secret)
    return material


def _fence(epoch: int = 1, *, holder: str = "agent-1", step_id: str = STEP_ID) -> FencingToken:
    return FencingToken(
        run_id=RUN_ID,
        step_id=step_id,
        holder=holder,
        epoch=epoch,
        issued_at=NOW,
        supersedes_epoch=epoch - 1 if epoch > 1 else None,
    )


def _command_fields(
    *,
    nonce: int = 1,
    epoch: int = 1,
    command_id: str = "fc-1",
    idempotency_key: str = "idem-1",
    plan_digest: str = PLAN,
    step_id: str = STEP_ID,
    holder: str = "agent-1",
    signing_key_id: str = CREDENTIAL,
    body_digest: str = BODY_DIGEST,
) -> dict[str, object]:
    """An *unsigned* field mapping. ``signature`` is deliberately absent."""
    return {
        "protocol": FABRIC_PROTOCOL_VERSION,
        "command_id": command_id,
        "run_id": RUN_ID,
        "step_id": step_id,
        "agent_id": AGENT,
        "plan_digest": plan_digest,
        "nonce": f"{nonce:032x}",
        "idempotency_key": idempotency_key,
        "fencing_token": _fence(epoch, holder=holder, step_id=step_id).model_dump(mode="json"),
        "command": CommandBodyRef(
            command_type=FabricCommandType.INJECT,
            body_digest=body_digest,
            body_ref="blob-1",
        ).model_dump(mode="json"),
        "issued_at": NOW.isoformat(),
        "signing_key_id": signing_key_id,
    }


def sign(material: StaticKeyMaterial, **overrides: object) -> FabricCommand:
    """Mint a validly signed envelope under the identity's current credential."""
    fields = _command_fields(**overrides)  # type: ignore[arg-type]
    return HmacSha256CommandSigner(material).sign_fields(fields)


def forge(command: FabricCommand, **changes: object) -> FabricCommand:
    """A well-formed envelope whose bytes changed after signing.

    ``model_validate`` rather than ``model_copy`` on purpose: the point is that a
    *well-formed* envelope can lie, and only the verifier catches it.
    """
    return FabricCommand.model_validate({**command.model_dump(), **changes})


def _step(step_id: str = STEP_ID) -> StepSpec:
    return StepSpec(step_id=step_id, semantic=StepSemantics.SERIAL, issued_at=NOW)


def _request(command: FabricCommand | None = None, **overrides: object) -> DispatchRequest:
    envelope = command if command is not None else sign(keys())
    fields: dict[str, object] = {
        "step": _step(envelope.step_id),
        "command": envelope,
        "current_plan_digest": PLAN,
        "expected_target": TARGET,
    }
    fields.update(overrides)
    return DispatchRequest.model_validate(fields)


def _lease(lease_id: str = "l-1", *, owner: str = AGENT, run_id: str = RUN_ID) -> FaultLease:
    return FaultLease(
        id=lease_id,
        run_id=run_id,
        fault_id="net.latency",
        owner_agent=owner,
        targets=frozenset({TARGET}),
        undo_ops=(UndoOp(op="tc.qdisc_add", args={"if": "eth0"}),),
        verify_probes=(VerifyProbe(probe="tc.qdisc_absent", args={"if": "eth0"}),),
        state=LeaseState.ACTIVE,
        created_at=NOW,
    )


def _applied(lease: FaultLease | None = None, *, target: str = TARGET) -> ProviderResult:
    return ProviderResult(ok=True, detail="qdisc added", target_ref=target, lease=lease)


def _drifted() -> ProviderResult:
    return ProviderResult(ok=True, detail="qdisc added", target_ref=OTHER_TARGET)


class ScriptedSession:
    """A controller-initiated session replaying a scripted provider.

    ``calls`` is the evidence for every "did not reach a provider" claim.
    """

    def __init__(self, *results: ProviderResult | BaseException) -> None:
        self._queue: list[ProviderResult | BaseException] = list(results)
        self.calls: list[FabricCommand] = []

    def dispatch(self, command: FabricCommand) -> ProviderResult:
        self.calls.append(command)
        if not self._queue:
            raise AssertionError(f"provider was dispatched unexpectedly: {command.command_id}")
        nxt = self._queue.pop(0)
        if isinstance(nxt, BaseException):
            raise nxt
        return nxt


class CrashingJournal:
    """A fault injector over a **real** journal.

    Not a fake store: the rows live in SQLite exactly as they would without it,
    and the crash happens *before* the delegate is called — which is what a
    process death mid-append looks like from the database's point of view.

    Args:
        delegate: The real journal.
        crash_on_settlement: 1-based index of the settlement append that dies.
    """

    def __init__(self, delegate: FabricJournal, *, crash_on_settlement: int = 0) -> None:
        self._delegate = delegate
        self._crash_on = crash_on_settlement
        self._settlements = 0

    def append(self, entry: JournalEntry) -> None:
        if isinstance(entry, DispatchSettlement):
            self._settlements += 1
            if self._settlements == self._crash_on:
                raise ControllerKilled("controller died while settling a dispatch")
        self._delegate.append(entry)

    def entries(self, run_id: str, step_id: str | None = None) -> tuple[JournalEntry, ...]:
        return self._delegate.entries(run_id, step_id)


def _verifier(
    store: Store,
    *,
    material: StaticKeyMaterial | None = None,
    enrol: bool = True,
    **overrides: object,
) -> AgentCommandVerifier:
    """Plan 19's verifier, bound to the real identity store and nonce ledger."""
    if enrol:
        AgentIdentityRepository(store).save(_identity())
    keys_map = material if material is not None else keys()
    return AgentCommandVerifier(
        identities=AgentIdentityRepository(store),
        signature=HmacSha256SignatureVerifier(keys_map),
        nonces=SqliteNonceLedger(store),
        controller_id=CONTROLLER,
        **overrides,  # type: ignore[arg-type]
    )


def _engine(
    store: Store,
    session: ScriptedSession,
    *,
    journal: FabricJournal | None = None,
    controller_id: str = CONTROLLER,
    verifier: object | None = None,
    evidence: object | None = None,
    clock: _Clock | None = None,
) -> FabricEngine:
    """An engine over the real store — real journal, real lease sink."""
    fields: dict[str, object] = {
        "session": session,
        "journal": journal if journal is not None else SqliteFabricJournal(store),
        "lease_sink": SQLiteLeaseSink(store),
        "controller_id": controller_id,
        "clock": clock or _Clock(),
    }
    if verifier is not None:
        fields["verifier"] = verifier
    if evidence is not None:
        fields["evidence"] = evidence
    return FabricEngine(**fields)  # type: ignore[arg-type]


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "fabric.db"


@pytest.fixture
def store(db_path: Path) -> Store:
    """A migrated store with the journal table applied, on a real file."""
    return Store.open_migrated(db_path, migrations=MIGRATIONS)


# --------------------------------------------------------------------------- #
# The durable journal                                                          #
# --------------------------------------------------------------------------- #


class TestMigration:
    def test_up_migration_creates_the_table_and_records_its_version(self, store: Store) -> None:
        assert FabricJournalTable(store).table_exists() is True
        # "Records its version" is asserted against ``_schema_migrations`` rather
        # than against the chain head. "The journal is the head" was true only
        # while nothing had been appended after it, and pinning this file to that
        # would re-break it on the next registration — the exact failure mode this
        # change exists to remove. The claim that matters is that *this*
        # migration was applied to *this* database.
        applied = {
            int(row["version"]): str(row["name"])
            for row in store.query("SELECT version, name FROM _schema_migrations")
        }
        assert applied[FABRIC_JOURNAL_VERSION] == FABRIC_JOURNAL_MIGRATION.name

    def test_down_migration_removes_the_table_and_restores_the_prior_head(
        self, db_path: Path
    ) -> None:
        store = Store.open_migrated(db_path, migrations=MIGRATIONS)
        journal = SqliteFabricJournal(store)
        journal.append(
            DispatchClaim(command=sign(keys()), controller_id=CONTROLLER, claimed_at=NOW)
        )
        assert journal.count() == 1

        reversed_ids = store.migrate_down(PRIOR_HEAD, migrations=MIGRATIONS)

        assert FABRIC_JOURNAL_MIGRATION.migration_id in reversed_ids
        assert store.schema_version == PRIOR_HEAD
        assert FabricJournalTable(store).table_exists() is False
        # Re-applying works, which is the other half of "the down path restores
        # the baseline" (ADR-M4-5). *Which* ids a re-apply from ``PRIOR_HEAD``
        # produces is a function of the chain's length, so it is asserted as
        # "every registered migration above the baseline, and the journal among
        # them" — not as a list pinned to today's head, which would fail the day
        # 34 is registered while the journal's down path stayed perfectly fine.
        reapplied = store.migrate(migrations=MIGRATIONS)
        assert set(reapplied) == {m.migration_id for m in MIGRATIONS if m.version > PRIOR_HEAD}
        assert FABRIC_JOURNAL_MIGRATION.migration_id in reapplied
        assert store.schema_version == MIGRATIONS[-1].version
        assert FabricJournalTable(store).table_exists() is True
        store.close()

    def test_the_schema_pins_the_phase_vocabulary(self, store: Store) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            with store.write() as conn:
                conn.execute(
                    f"INSERT INTO {FABRIC_JOURNAL_TABLE}"
                    " (run_id, step_id, phase, command_id, epoch, controller_id,"
                    " recorded_at, payload_digest, entry_json)"
                    " VALUES ('r','s','imagined','fc-1',1,'ctl','t','" + ("f" * 64) + "','{}')"
                )

    def test_the_schema_pins_the_digest_column_to_hex(self, store: Store) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            with store.write() as conn:
                conn.execute(
                    f"INSERT INTO {FABRIC_JOURNAL_TABLE}"
                    " (run_id, step_id, phase, command_id, epoch, controller_id,"
                    " recorded_at, payload_digest, entry_json)"
                    " VALUES ('r','s','claimed','fc-1',1,'ctl','t','not-a-digest','{}')"
                )


class TestDurableJournal:
    def test_claim_and_settlement_round_trip_in_append_order(self, store: Store) -> None:
        journal = SqliteFabricJournal(store)
        command = sign(keys())
        journal.append(DispatchClaim(command=command, controller_id=CONTROLLER, claimed_at=NOW))
        journal.append(
            DispatchSettlement(
                run_id=RUN_ID,
                step_id=STEP_ID,
                command_id=command.command_id,
                outcome=StepOutcome.COMPLETED,
                detail="applied",
                lease_id="l-1",
                settled_at=LATER,
            )
        )

        entries = journal.entries(RUN_ID)

        assert [type(entry).__name__ for entry in entries] == [
            "DispatchClaim",
            "DispatchSettlement",
        ]
        assert entries[0].command.nonce == command.nonce  # type: ignore[union-attr]
        assert entries[1].lease_id == "l-1"  # type: ignore[union-attr]

    def test_the_stored_row_keeps_the_whole_envelope_and_its_epoch(self, store: Store) -> None:
        command = sign(keys(), epoch=4)
        SqliteFabricJournal(store).append(
            DispatchClaim(command=command, controller_id=CONTROLLER, claimed_at=NOW)
        )

        (row,) = SqliteFabricJournal(store).rows(RUN_ID)

        assert row.epoch == 4
        assert row.controller_id == CONTROLLER
        assert row.phase == "claimed"
        assert row.payload()["command"]["command_id"] == command.command_id
        assert row.payload()["command"]["fencing_token"]["epoch"] == 4

    def test_entries_are_filterable_by_step(self, store: Store) -> None:
        journal = SqliteFabricJournal(store)
        for step_id, command_id in ((STEP_ID, "fc-1"), ("s-2", "fc-2")):
            journal.append(
                DispatchClaim(
                    command=sign(keys(), step_id=step_id, command_id=command_id),
                    controller_id=CONTROLLER,
                    claimed_at=NOW,
                )
            )

        assert [entry.command.step_id for entry in journal.entries(RUN_ID, "s-2")] == ["s-2"]
        assert len(journal.entries(RUN_ID)) == 2

    def test_a_run_id_that_dispatched_nothing_reads_as_empty_not_as_a_pass(
        self, store: Store
    ) -> None:
        assert SqliteFabricJournal(store).entries("r-nothing") == ()

    def test_a_reloaded_journal_equals_the_one_that_wrote(self, db_path: Path) -> None:
        store = Store.open_migrated(db_path, migrations=MIGRATIONS)
        written = SqliteFabricJournal(store)
        written.append(
            DispatchClaim(command=sign(keys()), controller_id=CONTROLLER, claimed_at=NOW)
        )
        expected = written.entries(RUN_ID)
        store.close()

        # A brand-new connection over the same file: this is what a controller
        # restart sees, not a Python object surviving in a dict.
        reopened = Store.open_migrated(db_path, migrations=MIGRATIONS)
        assert SqliteFabricJournal(reopened).entries(RUN_ID) == expected
        reopened.close()

    def test_a_duplicate_append_is_refused_by_name(self, store: Store) -> None:
        journal = SqliteFabricJournal(store)
        claim = DispatchClaim(command=sign(keys()), controller_id=CONTROLLER, claimed_at=NOW)
        journal.append(claim)

        with pytest.raises(FabricJournalDuplicateEntryError) as excinfo:
            journal.append(claim)

        assert excinfo.value.rule == FabricJournalDuplicateEntryError.RULE
        assert journal.count() == 1

    def test_two_commands_may_claim_the_same_step(self, store: Store) -> None:
        journal = SqliteFabricJournal(store)
        journal.append(
            DispatchClaim(command=sign(keys()), controller_id=CONTROLLER, claimed_at=NOW)
        )
        journal.append(
            DispatchClaim(
                command=sign(keys(), nonce=2, epoch=2, command_id="fc-2"),
                controller_id="ctl-b",
                claimed_at=LATER,
            )
        )
        assert journal.count(RUN_ID) == 2


# --------------------------------------------------------------------------- #
# Negative controls: a row that disagrees with its payload is refused          #
# --------------------------------------------------------------------------- #


def _rewrite(store: Store, assignment: str, value: object) -> None:
    """Edit a journal row behind the model's back, as a tampered DB would."""
    with store.write() as conn:
        conn.execute(
            f"UPDATE {FABRIC_JOURNAL_TABLE} SET {assignment} = ? WHERE sequence = 1", (value,)
        )


class TestJournalIntegrity:
    def test_an_edited_payload_is_refused_on_read(self, store: Store) -> None:
        journal = SqliteFabricJournal(store)
        journal.append(
            DispatchClaim(command=sign(keys()), controller_id=CONTROLLER, claimed_at=NOW)
        )
        _rewrite(store, "entry_json", '{"phase":"claimed","run_id":"r-fabric-4"}')

        with pytest.raises(FabricJournalIntegrityError) as excinfo:
            journal.entries(RUN_ID)

        assert excinfo.value.rule == FabricJournalIntegrityError.RULE_DIGEST
        assert "edited behind the model" in str(excinfo.value)

    def test_an_index_column_that_disagrees_with_the_payload_is_refused(self, store: Store) -> None:
        journal = SqliteFabricJournal(store)
        journal.append(
            DispatchClaim(command=sign(keys()), controller_id=CONTROLLER, claimed_at=NOW)
        )
        # Redirected at the query too, so the row is found — and refused for
        # being a row whose index columns do not describe its own payload.
        _rewrite(store, "run_id", "r-somebody-else")

        assert journal.entries(RUN_ID) == ()
        with pytest.raises(FabricJournalIntegrityError) as excinfo:
            journal.entries("r-somebody-else")

        assert excinfo.value.rule == FabricJournalIntegrityError.RULE_INDEX_COLUMNS
        assert "payload says" in str(excinfo.value)

    def test_a_command_id_edited_to_another_command_is_refused(self, store: Store) -> None:
        journal = SqliteFabricJournal(store)
        journal.append(
            DispatchClaim(command=sign(keys()), controller_id=CONTROLLER, claimed_at=NOW)
        )
        _rewrite(store, "command_id", "fc-fabricated")

        with pytest.raises(FabricJournalIntegrityError) as excinfo:
            journal.entries(RUN_ID)

        assert excinfo.value.rule == FabricJournalIntegrityError.RULE_INDEX_COLUMNS
        assert "fc-fabricated" in str(excinfo.value)

    def test_an_edited_epoch_is_refused(self, store: Store) -> None:
        journal = SqliteFabricJournal(store)
        journal.append(
            DispatchClaim(command=sign(keys(), epoch=7), controller_id=CONTROLLER, claimed_at=NOW)
        )
        _rewrite(store, "epoch", 1)

        with pytest.raises(FabricJournalIntegrityError) as excinfo:
            journal.entries(RUN_ID)

        assert excinfo.value.rule == FabricJournalIntegrityError.RULE_INDEX_COLUMNS

    def test_a_moved_stamp_is_refused(self, store: Store) -> None:
        journal = SqliteFabricJournal(store)
        journal.append(
            DispatchClaim(command=sign(keys()), controller_id=CONTROLLER, claimed_at=NOW)
        )
        _rewrite(store, "recorded_at", LATER.isoformat())

        with pytest.raises(FabricJournalIntegrityError) as excinfo:
            journal.entries(RUN_ID)

        assert excinfo.value.rule == FabricJournalIntegrityError.RULE_STAMP

    def test_unparsable_json_is_refused(self, store: Store) -> None:
        journal = SqliteFabricJournal(store)
        journal.append(
            DispatchClaim(command=sign(keys()), controller_id=CONTROLLER, claimed_at=NOW)
        )
        _rewrite(store, "entry_json", "not json at all")

        with pytest.raises(FabricJournalIntegrityError) as excinfo:
            journal.entries(RUN_ID)

        assert excinfo.value.rule == FabricJournalIntegrityError.RULE_PAYLOAD_SHAPE

    def test_a_row_whose_payload_names_nothing_is_refused_at_write_time(self, store: Store) -> None:
        with pytest.raises(FabricJournalIntegrityError) as excinfo:
            FabricJournalRow.of(
                run_id=RUN_ID,
                step_id=STEP_ID,
                phase="claimed",
                command_id="fc-1",
                epoch=1,
                entry={"phase": "claimed", "claimed_at": NOW.isoformat()},
                controller_id=CONTROLLER,
                recorded_at=NOW.isoformat(),
            )

        assert excinfo.value.rule == FabricJournalIntegrityError.RULE_PAYLOAD_SHAPE
        assert FabricJournalTable(store).count() == 0

    def test_every_append_crosses_the_evidence_boundary(
        self, store: Store, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The journal's ``entry_json`` is a free-form JSON column, which is
        # exactly the surface a resolved value could be planted on. This asserts
        # the gate is called on the document the column receives, before the
        # transaction opens — not merely that a clean write happens to succeed.
        from mayhem.infra import fabric_journal as module

        seen: list[tuple[object, str]] = []
        real = module.require_persistable_document

        def spy(document: object, *, artifact: str) -> None:
            seen.append((document, artifact))
            real(document, artifact=artifact)

        monkeypatch.setattr(module, "require_persistable_document", spy)
        journal = SqliteFabricJournal(store)
        journal.append(
            DispatchClaim(command=sign(keys()), controller_id=CONTROLLER, claimed_at=NOW)
        )

        assert len(seen) == 1
        document, artifact = seen[0]
        assert artifact == f"fabric:journal:{RUN_ID}"
        assert isinstance(document, dict)
        assert document["entry_json"]["command"]["command_id"] == "fc-1"


# --------------------------------------------------------------------------- #
# Crash-resume against the real store                                         #
# --------------------------------------------------------------------------- #


class TestDurableCrashResume:
    def test_a_resumed_controller_rebuilds_ownership_from_sqlite(self, store: Store) -> None:
        session_a = ScriptedSession(_applied(lease=_lease("l-1")))
        verifier = _verifier(store)
        engine_a = _engine(store, session_a, verifier=verifier)
        first = engine_a.dispatch(_request())
        assert first.ok is True

        # ---- controller A dies here. Nothing is handed to a successor: the
        # objects go away and only the database remains.
        del engine_a, session_a

        session_b = ScriptedSession()
        engine_b = _engine(store, session_b, controller_id="ctl-b")

        assert engine_b.verification_enabled is False  # this successor verifies nothing
        assert engine_b.served_fence(RUN_ID, STEP_ID) is not None
        assert engine_b.served_fence(RUN_ID, STEP_ID).epoch == 1  # type: ignore[union-attr]
        assert engine_b.nonce_ledger(RUN_ID, STEP_ID).knows("0" * 31 + "1")
        assert [claim.controller_id for claim in engine_b.claims(RUN_ID)] == [CONTROLLER]
        assert [lease.id for lease in engine_b.unreconciled_leases(RUN_ID)] == []
        assert engine_b.unrecovered_steps(RUN_ID) == (STEP_ID,)

        # Exactly one effect exists: one lease, from one owner.
        assert [lease.id for lease in SQLiteLeaseSink(store).active_leases()] == ["l-1"]

    def test_the_deposed_owner_is_refused_after_a_durable_resume(self, store: Store) -> None:
        _engine(store, ScriptedSession(_applied(lease=_lease("l-1")))).dispatch(_request())
        successor = _engine(store, ScriptedSession(_applied()), controller_id="ctl-b")
        successor.dispatch(
            _request(sign(keys(), nonce=2, epoch=2, command_id="fc-2", idempotency_key="idem-2"))
        )

        late_session = ScriptedSession(_applied())
        late = _engine(store, late_session, controller_id=CONTROLLER)

        with pytest.raises(FabricCommandRefused) as excinfo:
            late.dispatch(_request(sign(keys(), nonce=3, command_id="fc-a2")))

        assert excinfo.value.code == FABRIC_STALE_FENCE
        assert late_session.calls == []

    def test_a_crash_between_the_lease_and_the_settlement_is_visible_on_resume(
        self, store: Store
    ) -> None:
        real = SqliteFabricJournal(store)
        dying = _engine(
            store,
            ScriptedSession(_applied(lease=_lease("l-1"))),
            journal=CrashingJournal(real, crash_on_settlement=1),
        )
        with pytest.raises(ControllerKilled):
            dying.dispatch(_request())

        # Durable state after the kill: the claim landed in SQLite, the lease
        # landed in SQLite, the settlement did not. That pair is the signature.
        resumed = _engine(store, ScriptedSession(), controller_id="ctl-b")
        assert [claim.command.command_id for claim in resumed.open_claims(RUN_ID)] == ["fc-1"]
        assert [lease.id for lease in resumed.unreconciled_leases(RUN_ID)] == ["l-1"]

        # An effect that may already have happened is not dispatched again …
        session = ScriptedSession(_applied())
        with pytest.raises(FabricCommandRefused) as excinfo:
            _engine(store, session, controller_id="ctl-b").dispatch(
                _request(sign(keys(), nonce=2, command_id="fc-2"))
            )
        assert excinfo.value.code == FABRIC_INFLIGHT_UNRESOLVED
        assert session.calls == []

        # … it is reconciled instead: recover the lease, close the claim, and the
        # recovery guarantee holds before anything new is dispatched.
        client = LeaseClient(SQLiteLeaseSink(store), agent_id=AGENT)
        client.mark_orphaned("l-1", notes="settled after crash")
        client.mark_releasing("l-1")
        client.confirm_release("l-1", mechanism="watchdog")
        assert_all_recovered(list(SQLiteLeaseSink(store).all_leases()))

        resumed.settle_claim(
            RUN_ID,
            STEP_ID,
            outcome=StepOutcome.FAILED,
            target_outcome=TargetOutcome.FAILED_TO_APPLY,
            detail="undone during recovery",
        )
        assert resumed.open_claims(RUN_ID) == ()
        assert resumed.unreconciled_leases(RUN_ID) == ()

        retry_session = ScriptedSession(_applied(lease=_lease("l-2")))
        result = _engine(store, retry_session, controller_id="ctl-b").dispatch(
            _request(sign(keys(), nonce=3, epoch=2, command_id="fc-b1", idempotency_key="idem-b1"))
        )
        assert result.ok is True
        assert result.epoch == 2
        assert [lease.id for lease in SQLiteLeaseSink(store).active_leases()] == ["l-2"]

    def test_the_settled_outcome_survives_a_store_reopen(self, db_path: Path) -> None:
        store = Store.open_migrated(db_path, migrations=MIGRATIONS)
        command = sign(keys(), idempotency_key="idem-persist")
        _engine(store, ScriptedSession(_applied(lease=_lease("l-1")))).dispatch(_request(command))
        store.close()

        reopened = Store.open_migrated(db_path, migrations=MIGRATIONS)
        resumed_journal = SqliteFabricJournal(reopened)
        retry_session = ScriptedSession()

        retry = _engine(reopened, retry_session, journal=resumed_journal).dispatch(
            _request(sign(keys(), nonce=9, command_id="fc-retry", idempotency_key="idem-persist"))
        )

        assert retry.retried is True
        assert retry.outcome is StepOutcome.COMPLETED
        assert retry.lease_id == "l-1"
        assert retry_session.calls == [], "a retry across a restart must not re-run the provider"
        reopened.close()

    def test_a_second_effect_at_one_epoch_is_still_refused_durably(self, store: Store) -> None:
        _engine(store, ScriptedSession(_applied())).dispatch(_request())
        session = ScriptedSession(_applied())

        with pytest.raises(FabricCommandRefused) as excinfo:
            _engine(store, session).dispatch(
                _request(sign(keys(), nonce=2, command_id="fc-2", idempotency_key="idem-2"))
            )

        assert excinfo.value.code == FABRIC_DUPLICATE_DISPATCH
        assert session.calls == []
        assert SqliteFabricJournal(store).count(RUN_ID) == 2  # one claim, one settlement


# --------------------------------------------------------------------------- #
# Command verification at dispatch                                             #
# --------------------------------------------------------------------------- #


class TestVerificationWiring:
    def test_plan_19s_verifier_satisfies_the_fabrics_port(self, store: Store) -> None:
        # The assertion that the two surfaces cannot drift: the fabric depends on
        # a *shape*, and this is what proves plan 19's class provides it. The
        # structural check runs twice — once by mypy on the call below, once at
        # runtime here, because a static check alone is a claim about one version
        # of one checker.
        assert _accepts_port(_verifier(store)) is not None
        parameters = set(inspect.signature(AgentCommandVerifier.verify).parameters)
        assert {"command", "expected_plan_digest", "served_fence", "now"} <= parameters

    def test_a_validly_signed_command_dispatches_and_is_recorded_as_verified(
        self, store: Store
    ) -> None:
        verifier = _verifier(store)
        engine = _engine(
            store,
            ScriptedSession(_applied()),
            verifier=verifier,
            evidence=FabricEvidenceRecorder(store),
        )

        assert engine.verification_enabled is True
        assert engine.verification_algorithm == ALGORITHM_HMAC_SHA256

        result = engine.dispatch(_request())

        assert result.ok is True
        timeline = fabric_timeline(store, RUN_ID)
        (dispatch,) = timeline.dispatches
        assert dispatch.verified is True
        assert dispatch.algorithm == ALGORITHM_HMAC_SHA256

    def test_the_sealed_digest_is_over_the_bytes_the_verifier_checked(self, store: Store) -> None:
        command = sign(keys())
        _seal_dispatch(store, result=_applied(), command=command)

        dispatch = fabric_timeline(store, RUN_ID).dispatches[0]

        # The chain names the digest of the canonical envelope minus the
        # signature — the exact payload plan 19's MAC covered. Asserted here so
        # "what was signed" and "what is recorded" cannot mean two things.
        assert dispatch.envelope_digest == sha256_hex(signed_payload(command).decode("utf-8"))

    def test_an_unsigned_command_is_refused_with_fabric_undersigned(self, store: Store) -> None:
        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_verifier(store))
        forged = forge(sign(keys()), signature="A" * 43)

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(forged))

        assert excinfo.value.code == FABRIC_UNDERSIGNED
        assert excinfo.value.details["failed_checks"] == ["signature"]
        assert session.calls == []
        assert SqliteFabricJournal(store).count(RUN_ID) == 0

    def test_a_tampered_envelope_is_refused_with_fabric_undersigned(self, store: Store) -> None:
        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_verifier(store))
        tampered = forge(sign(keys()), idempotency_key="idem-tampered")

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(tampered))

        assert excinfo.value.code == FABRIC_UNDERSIGNED
        assert session.calls == []

    def test_a_command_signed_with_an_unknown_key_is_refused(self, store: Store) -> None:
        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_verifier(store))
        stranger = sign(keys(("cr-unknown", SECRET)), signing_key_id="cr-unknown")

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(stranger))

        assert excinfo.value.code == FABRIC_UNDERSIGNED
        assert session.calls == []

    def test_a_signature_from_the_wrong_secret_is_refused(self, store: Store) -> None:
        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_verifier(store))
        wrong = sign(keys((CREDENTIAL, OTHER_SECRET)))

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(wrong))

        assert excinfo.value.code == FABRIC_UNDERSIGNED
        assert session.calls == []

    def test_a_deposed_epoch_cannot_dispatch(self, store: Store) -> None:
        engine = _engine(store, ScriptedSession(_applied()), verifier=_verifier(store))
        engine.dispatch(_request())
        successor = _engine(
            store,
            ScriptedSession(_applied()),
            controller_id="ctl-b",
            verifier=_verifier(store, enrol=False),
        )
        successor.dispatch(
            _request(sign(keys(), nonce=2, epoch=2, command_id="fc-2", idempotency_key="idem-2"))
        )

        session = ScriptedSession(_applied())
        late = _engine(
            store,
            session,
            controller_id=CONTROLLER,
            verifier=_verifier(store, enrol=False),
        )

        with pytest.raises(FabricCommandRefused) as excinfo:
            late.dispatch(_request(sign(keys(), nonce=3, command_id="fc-a2")))

        assert excinfo.value.code == FABRIC_STALE_FENCE
        assert session.calls == []

    def test_a_superseded_plan_digest_is_refused(self, store: Store) -> None:
        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_verifier(store))

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(sign(keys(), plan_digest=SUPERSEDED_PLAN)))

        assert excinfo.value.code == FABRIC_PLAN_MISMATCH
        assert session.calls == []

    def test_a_replayed_nonce_is_refused(self, store: Store) -> None:
        engine = _engine(store, ScriptedSession(_applied()), verifier=_verifier(store))
        engine.dispatch(_request())
        session = ScriptedSession(_applied())

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(sign(keys(), command_id="fc-replay")))

        assert excinfo.value.code == FABRIC_REPLAYED_NONCE
        assert session.calls == []

    def test_a_replay_caught_by_plan_19s_own_ledger_is_refused_by_name(self, store: Store) -> None:
        # The controller's journal and the agent-side nonce ledger are two
        # different records of the same single-use property. This spends the
        # nonce in plan 19's table only, so the refusal can only come from there.
        ledger = SqliteNonceLedger(store)
        command = sign(keys())
        ledger.record(command, at=NOW)
        assert SqliteFabricJournal(store).count(RUN_ID) == 0

        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_verifier(store))

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(command))

        assert excinfo.value.code == FABRIC_REPLAYED_NONCE
        assert excinfo.value.details["failed_checks"] == ["nonce_freshness"]
        assert session.calls == []
        assert SqliteFabricJournal(store).count(RUN_ID) == 0

    def test_an_unenrolled_agent_is_refused_by_name(self, store: Store) -> None:
        verifier = _verifier(store, enrol=False)
        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=verifier)

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request())

        assert excinfo.value.code == FABRIC_COMMAND_UNVERIFIED
        failed = excinfo.value.details["failed_checks"]
        assert "key_binding" in failed and "identity_usable" in failed
        assert session.calls == []

    def test_a_rotated_out_credential_is_refused(self, store: Store) -> None:
        repository = AgentIdentityRepository(store)
        identity = repository.save(_identity())
        successor = AgentCredential(
            credential_id="cr-2",
            agent_id=AGENT,
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=900),
            rotate_before=300.0,
        )
        repository.save(identity.with_credential(successor))

        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_verifier(store, enrol=False))

        # Correctly signed with a key that *still resolves*, under a credential
        # that is no longer current. Only the key-binding check can catch this,
        # which is what makes rotation retire the key rather than only the row.
        retired = sign(keys((CREDENTIAL, SECRET)), signing_key_id=CREDENTIAL)

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(retired))

        assert excinfo.value.code == FABRIC_COMMAND_UNVERIFIED
        assert "key_binding" in excinfo.value.details["failed_checks"]
        assert session.calls == []

    def test_a_signature_port_that_cannot_verify_fails_closed(self, store: Store) -> None:
        AgentIdentityRepository(store).save(_identity())
        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_x509_verifier(store))

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request())

        # Plan 19's verifier catches the port's own refusal internally and reports
        # it as a failed SIGNATURE check, so "this build cannot check it" arrives
        # as *undersigned* rather than as a pass. Fail-closed either way.
        assert excinfo.value.code == FABRIC_UNDERSIGNED
        outcome = excinfo.value.details["failed_checks"]
        assert outcome == ["signature"]
        assert session.calls == []

    def test_a_port_that_raises_outside_the_verifier_is_refused_as_unverifiable(
        self, store: Store
    ) -> None:
        # The backstop: a verifier that propagates its own unavailability instead
        # of folding it into a check outcome still must not produce a dispatch.
        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_accepts_port(_UnavailableVerifier()))

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request())

        assert excinfo.value.code == FABRIC_COMMAND_UNVERIFIED
        assert "was not checked" in str(excinfo.value)
        assert session.calls == []
        assert SqliteFabricJournal(store).count(RUN_ID) == 0

    def test_the_x509_port_never_returns_true(self) -> None:
        verifier = X509CommandSignatureVerifier()
        with pytest.raises(SignaturePortUnavailableError) as excinfo:
            verifier.verify(payload=b"x", signature="y", signing_key_id="cr-1")
        assert excinfo.value.code == SIGNATURE_PORT_UNAVAILABLE

    def test_verification_runs_before_the_provider_is_touched(self, store: Store) -> None:
        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_verifier(store))

        with pytest.raises(FabricCommandRefused):
            engine.dispatch(_request(forge(sign(keys()), signature="A" * 43)))

        assert session.calls == []

    def test_a_refused_command_spends_no_nonce_in_the_agents_ledger(self, store: Store) -> None:
        # The placement of verification in the preflight is a decision, and this
        # is its consequence: a refusal leaves the agent-side nonce unspent, so a
        # legitimate retry of the same intent can still be minted.
        engine = _engine(store, ScriptedSession(_applied()), verifier=_verifier(store))
        command = forge(sign(keys()), signature="A" * 43)

        with pytest.raises(FabricCommandRefused):
            engine.dispatch(_request(command))

        assert SqliteNonceLedger(store).consumed_count() == 0
        fixed = sign(keys(), command_id="fc-fixed")
        result = _engine(
            store, ScriptedSession(_applied()), verifier=_verifier(store, enrol=False)
        ).dispatch(_request(fixed))
        assert result.ok is True


class _UnavailableVerifier:
    """A verifier bound to a build that cannot check anything.

    Plan 19's own :class:`AgentCommandVerifier` folds a port's unavailability into
    a failed ``SIGNATURE`` check outcome, so it never propagates
    :class:`SignaturePortUnavailableError` out of ``verify``. This stand-in
    represents the other shape a deployment could bind, and it is what makes the
    backstop in :meth:`FabricEngine._verify` a tested path rather than a
    decorative ``except``.
    """

    algorithm = ALGORITHM_HMAC_SHA256

    def verify(
        self,
        command: FabricCommand,
        *,
        expected_plan_digest: str | None = None,
        served_fence: FencingToken | None = None,
        now: datetime | None = None,
    ) -> VerifiedCommand:
        del command, expected_plan_digest, served_fence, now
        raise SignaturePortUnavailableError(
            ALGORITHM_HMAC_SHA256, "this build has no signature implementation"
        )


def _x509_verifier(store: Store) -> AgentCommandVerifier:
    """Plan 19's verifier over plan 19's port that refuses the algorithm it declares."""
    AgentIdentityRepository(store).save(_identity())
    return AgentCommandVerifier(
        identities=AgentIdentityRepository(store),
        signature=X509CommandSignatureVerifier(),
        nonces=SqliteNonceLedger(store),
        controller_id=CONTROLLER,
    )


def _accepts_port(verifier: FabricCommandVerifierPort) -> FabricCommandVerifierPort:
    """The structural assertion, written where mypy will check it.

    Returning the argument unchanged is the point: if plan 19's verifier stopped
    satisfying the fabric's port, this function would not type-check, and no test
    would have to notice.
    """
    return verifier


# --------------------------------------------------------------------------- #
# The wire receiver                                                            #
# --------------------------------------------------------------------------- #


class TestWireReceiver:
    def test_a_complete_frame_decodes_and_verifies(self, store: Store) -> None:
        command = decode_wire_command(sign(keys()).model_dump(mode="json"))
        record = verify_dispatch_command(
            command, verifier=_verifier(store), expected_plan_digest=PLAN, now=NOW
        )
        assert record.algorithm == ALGORITHM_HMAC_SHA256
        assert record.command_id == "fc-1"

    def test_a_frame_that_omits_its_signature_is_fabric_undersigned(self) -> None:
        fields = _command_fields()
        with pytest.raises(FabricCommandRefused) as excinfo:
            decode_wire_command(fields)
        assert excinfo.value.code == FABRIC_UNDERSIGNED
        assert excinfo.value.details["fields"]

    def test_a_frame_with_a_blank_signature_is_fabric_undersigned(self) -> None:
        fields = {**sign(keys()).model_dump(mode="json"), "signature": "   "}
        with pytest.raises(FabricCommandRefused) as excinfo:
            decode_wire_command(fields)
        assert excinfo.value.code == FABRIC_UNDERSIGNED

    def test_a_frame_that_is_malformed_in_another_way_is_not_called_undersigned(
        self,
    ) -> None:
        fields = sign(keys()).model_dump(mode="json")
        del fields["fencing_token"]
        with pytest.raises(FabricCommandRefused) as excinfo:
            decode_wire_command(fields)
        assert excinfo.value.code == FABRIC_MALFORMED_ENVELOPE
        assert "fencing_token" in excinfo.value.details["fields"]

    def test_json_text_is_accepted_as_well_as_a_mapping(self, store: Store) -> None:
        command = decode_wire_command(sign(keys()).model_dump_json())
        assert command.command_id == "fc-1"
        assert verify_dispatch_command(
            command, verifier=_verifier(store), expected_plan_digest=PLAN, now=NOW
        )

    def test_a_frame_for_another_plan_is_refused_by_name(self, store: Store) -> None:
        with pytest.raises(FabricCommandRefused) as excinfo:
            verify_dispatch_command(
                sign(keys(), plan_digest=SUPERSEDED_PLAN),
                verifier=_verifier(store),
                expected_plan_digest=PLAN,
                now=NOW,
            )
        assert excinfo.value.code == FABRIC_PLAN_MISMATCH

    def test_a_verification_refusal_names_the_failing_checks(self, store: Store) -> None:
        with pytest.raises(FabricCommandRefused) as excinfo:
            verify_dispatch_command(
                forge(sign(keys()), signature="A" * 43),
                verifier=_verifier(store),
                expected_plan_digest=PLAN,
                now=NOW,
            )
        assert excinfo.value.code == FABRIC_UNDERSIGNED
        assert excinfo.value.details["code"] == "agent_command_unverified"

    def test_a_verifier_whose_port_is_unavailable_is_refused_not_passed(self) -> None:
        with pytest.raises(SignaturePortUnavailableError):
            verify_dispatch_command(
                sign(keys()), verifier=_accepts_port(_UnavailableVerifier()), now=NOW
            )


# --------------------------------------------------------------------------- #
# Sealing                                                                      #
# --------------------------------------------------------------------------- #


def _seal_dispatch(
    store: Store,
    *,
    result: ProviderResult,
    verification: bool = True,
    command: FabricCommand | None = None,
) -> DispatchResult:
    engine = _engine(
        store,
        ScriptedSession(result),
        verifier=_verifier(store) if verification else None,
        evidence=FabricEvidenceRecorder(store),
    )
    return engine.dispatch(_request(command))


class TestSealing:
    def test_a_dispatch_and_its_settlement_are_sealed(self, store: Store) -> None:
        result = _seal_dispatch(store, result=_applied(lease=_lease("l-1")))
        assert result.ok is True

        timeline = fabric_timeline(store, RUN_ID)

        assert timeline.verified is True
        assert len(timeline.dispatches) == 1
        assert timeline.dispatches[0].epoch == 1
        assert timeline.dispatches[0].controller_id == CONTROLLER
        assert timeline.dispatches[0].verified is True
        assert len(timeline.settlements) == 1
        assert timeline.settlements[0].outcome == StepOutcome.COMPLETED.value
        assert timeline.settlements[0].lease_id == "l-1"

    def test_the_sealed_chain_reloads_and_verifies_from_stored_bytes(self, store: Store) -> None:
        _seal_dispatch(store, result=_applied())

        events = load_fabric_chain(store, RUN_ID)
        verification = verify_fabric_chain(store, RUN_ID)

        assert len(events) == 2
        assert [event.event_kind for event in events] == [
            EVENT_FABRIC_DISPATCHED,
            EVENT_FABRIC_SETTLED,
        ]
        assert verification.valid is True
        assert verification.checked == 2

    def test_a_drift_is_sealed_under_its_own_kind(self, store: Store) -> None:
        _seal_dispatch(store, result=_drifted())

        kinds = [event.event_kind for event in load_fabric_chain(store, RUN_ID)]

        assert kinds == [EVENT_FABRIC_DISPATCHED, EVENT_FABRIC_DRIFT]
        settlement = fabric_timeline(store, RUN_ID).settlements[0]
        assert settlement.outcome == StepOutcome.TARGET_DRIFT.value
        assert settlement.target_outcome == TargetOutcome.TARGET_DRIFT.value

    def test_an_idempotent_retry_is_sealed_as_a_retry(self, store: Store) -> None:
        _seal_dispatch(store, result=_applied(lease=_lease("l-1")))
        engine = _engine(
            store,
            ScriptedSession(),
            evidence=FabricEvidenceRecorder(store),
        )
        retry = engine.dispatch(_request(sign(keys(), nonce=2, command_id="fc-retry")))
        assert retry.retried is True

        # A retry is still a *dispatch*: the retry's own claim is sealed too, and
        # the settlement that follows it is the one marked as served-from-record.
        kinds = [event.event_kind for event in load_fabric_chain(store, RUN_ID)]
        assert kinds == [
            EVENT_FABRIC_DISPATCHED,
            EVENT_FABRIC_SETTLED,
            EVENT_FABRIC_DISPATCHED,
            EVENT_FABRIC_RETRY,
        ]
        assert fabric_timeline(store, RUN_ID).settlements[-1].retried is True

    def test_a_refusal_is_sealed_with_its_code(self, store: Store) -> None:
        engine = _engine(
            store,
            ScriptedSession(_applied()),
            evidence=FabricEvidenceRecorder(store),
        )
        with pytest.raises(FabricCommandRefused):
            engine.dispatch(_request(sign(keys(), plan_digest=SUPERSEDED_PLAN)))

        timeline = fabric_timeline(store, RUN_ID)

        assert len(timeline.dispatches) == 0
        (refusal,) = timeline.refusals
        assert refusal.code == FABRIC_PLAN_MISMATCH
        assert refusal.epoch == 1
        assert "superseded" in refusal.reason or "bound to plan" in refusal.reason

    def test_the_seal_records_how_the_envelope_was_checked(self, store: Store) -> None:
        _seal_dispatch(store, result=_applied())
        dispatch = fabric_timeline(store, RUN_ID).dispatches[0]

        assert dispatch.algorithm == ALGORITHM_HMAC_SHA256
        assert len(dispatch.envelope_digest) == 64
        assert dispatch.identity_version >= 1

    def test_the_seal_never_stores_the_signature_or_any_key(self, store: Store) -> None:
        command = sign(keys())
        _seal_dispatch(store, result=_applied())
        blob = "\n".join(event.model_dump_json() for event in load_fabric_chain(store, RUN_ID))

        assert command.signature not in blob
        assert SECRET.decode() not in blob
        assert CREDENTIAL in blob  # the key *id* is named; the secret is not

    def test_a_dispatch_without_a_verifier_says_so_explicitly(self, store: Store) -> None:
        _seal_dispatch(store, result=_applied(), verification=False)
        dispatch = fabric_timeline(store, RUN_ID).dispatches[0]

        assert dispatch.verified is False
        assert dispatch.algorithm == ""

    def test_the_manifest_is_unsigned_and_records_why(self, store: Store) -> None:
        _seal_dispatch(store, result=_applied())
        manifest = load_fabric_manifest(store, RUN_ID)

        assert manifest is not None
        assert manifest.signed is False
        state, reason = AttestationRepository(store).load_signature_state(manifest.manifest_id)
        assert state == SIGNATURE_UNSIGNED_NO_SIGNING
        assert reason == UNSIGNED_REASON_NO_SIGNING

    def test_each_seal_chains_the_manifest_it_replaced(self, store: Store) -> None:
        recorder = FabricEvidenceRecorder(store)
        recorder.seal(
            run_id=RUN_ID,
            kind=EVENT_FABRIC_REFUSED,
            identity="fc-first:refused:seed",
            payload={"run_id": RUN_ID, "refusal_code": "seed"},
        )
        first = load_fabric_manifest(store, RUN_ID)

        assert first is not None
        assert first.previous_manifest_digest == GENESIS_DIGEST

        recorder.seal(
            run_id=RUN_ID,
            kind=EVENT_FABRIC_REFUSED,
            identity="fc-second:refused:seed",
            payload={"run_id": RUN_ID, "refusal_code": "grown"},
        )
        second = load_fabric_manifest(store, RUN_ID)

        assert second is not None
        assert second.previous_manifest_digest == first.manifest_digest
        assert second.covered_events > first.covered_events
        assert fabric_manifest_chain(store, RUN_ID) == (
            first.manifest_digest,
            second.manifest_digest,
        )

    def test_a_run_with_no_manifest_has_no_manifest_chain(self, store: Store) -> None:
        assert fabric_manifest_chain(store, "r-dispatched-nothing") == ()

    def test_an_unknown_evidence_kind_is_refused(self, store: Store) -> None:
        from mayhem.domain.errors import DomainError

        recorder = FabricEvidenceRecorder(store)
        with pytest.raises(DomainError):
            recorder.seal(
                run_id=RUN_ID,
                kind="fabric.invented",
                identity="x",
                payload={"run_id": RUN_ID},
            )
        assert load_fabric_chain(store, RUN_ID) == ()

    def test_every_declared_kind_is_reachable_or_documented(self) -> None:
        # A kind in the tuple that nothing emits is a promise the codebase does not
        # keep; this pins the list so the tests above and the enum cannot drift.
        assert set(FABRIC_EVENT_KINDS) == {
            EVENT_FABRIC_DISPATCHED,
            EVENT_FABRIC_RETRY,
            EVENT_FABRIC_SETTLED,
            EVENT_FABRIC_DRIFT,
            EVENT_FABRIC_REFUSED,
        }

    def test_the_timeline_and_the_journal_agree(self, store: Store) -> None:
        _seal_dispatch(store, result=_applied(lease=_lease("l-1")))
        journal = SqliteFabricJournal(store)

        assert timeline_matches_journal(fabric_timeline(store, RUN_ID), journal, RUN_ID) == ()

    def test_a_journal_row_the_chain_does_not_attest_is_reported(self, store: Store) -> None:
        _seal_dispatch(store, result=_applied())
        journal = SqliteFabricJournal(store)
        journal.append(
            DispatchClaim(
                command=sign(keys(), nonce=99, epoch=9, command_id="fc-unsealed"),
                controller_id="ctl-z",
                claimed_at=LATER,
            )
        )

        problems = timeline_matches_journal(fabric_timeline(store, RUN_ID), journal, RUN_ID)

        assert problems == ("journal claims 'fc-unsealed' but no sealed dispatch attests it",)

    def test_a_chain_id_round_trips_back_to_its_run(self) -> None:
        assert fabric_chain_id(RUN_ID) == f"{RUN_ID}:fabric"
        assert run_id_of_chain(fabric_chain_id(RUN_ID)) == RUN_ID
        assert run_id_of_chain(RUN_ID) == RUN_ID

    def test_an_empty_chain_does_not_claim_to_be_verified(self, store: Store) -> None:
        timeline = fabric_timeline(store, "r-dispatched-nothing")

        assert timeline.dispatches == ()
        assert timeline.verified is False
        assert timeline.chain_verification.errors

    def test_settlement_outcomes_read_back_as_the_engine_spells_them(self, store: Store) -> None:
        _seal_dispatch(store, result=_drifted())
        settlement = fabric_timeline(store, RUN_ID).settlements[0]

        outcome, target = outcomes_of(settlement)

        assert outcome is StepOutcome.TARGET_DRIFT
        assert target is TargetOutcome.TARGET_DRIFT
