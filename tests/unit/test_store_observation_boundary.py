"""``Store.save_observation`` is inside the secret boundary (plan 13's ledger item 2).

``docs/v1.1.0/13_SCHEDULING_CAMPAIGNS_GAMEDAYS.md`` reported this as an open gap
rather than a claim of safety, and this file is where that claim is now cashed.
Two callers write through this one function —
``controller/game_day_evidence.py::record_artifact`` and
``infra/schedule_store.py::ScheduleStore.record_tick`` — so one gate covers both
and neither caller is edited to make the coverage true.

Why it is evidence
------------------

The argument is the one that binds the audit stream, and it is the same one:
``observations`` rows are persisted, read back by the reports that make a run
legible (a game-day after-action report, a scheduler tick ledger), and archived
by the retention machinery. Plan 12's "secrets must never enter evidence"
therefore binds the table. ``data`` is caller-authored and free-form, and the
callers are operator-facing: a facilitator's free-text note, a tick's decisions,
a stop record. The field names carry nothing — ``text``, ``detail``,
``report`` — so the byte rule is the only rule that can see a resolved value
planted in one, which is exactly the shape the gate exists for.

What is asserted here
---------------------

* **Negative control, both rules.** A field graded ``secret`` is refused with no
  guard registered at all, and a value this run actually resolved is refused
  under a live guard. Each refusal must *name* the offending field, or carry a
  digest and an offset but never the value.
* **Positive control.** An ordinary observation writes under a live guard, with
  ``data_json`` byte-identical to what the pre-gate implementation emitted: a
  gate that changed the rendering would change the artifact.
* **Ordering.** The gate runs before the transaction opens, so a refusal leaves
  no row, leaves the rows already there untouched, and never opens a write
  boundary at all.
* **Both writers.** ``record_artifact`` and ``record_tick`` are driven directly,
  because "one gate covers both" is a claim about callers and is only proved by
  calling them.
* **Registration.** The ``BOUNDARY_CALL_SITES`` row exists and the shared
  registered-writer check still passes.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from tests.unit.test_evidence_boundary import (
    BOUNDARY_CALL_SITES,
    TestTheGateCannotBeDeleted,
    _gate_calling_functions,
)

from mayhem.controller.game_day_evidence import (
    ArtifactKind,
    GameDayArtifact,
    record_artifact,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.secrets import (
    REFUSAL_SECRET_FIELD_PERSISTED,
    CredentialRef,
    CredentialScope,
    ScopeKind,
    SecretGrant,
    SecretProvider,
)
from mayhem.infra.schedule_store import ScheduleStore
from mayhem.infra.secret_resolver import (
    REFUSAL_SECRET_BYTES_IN_ARTIFACT,
    FilesystemFixtureProvider,
    SecretLeakGuard,
    SecretResolver,
    StaticGrantSource,
    active_guards,
    guard_evidence_writes,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    import sqlite3
    from collections.abc import Iterator
    from pathlib import Path

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
ALICE = "svc:alice"
PROD = "prod-eu"
STEP_ID = "inject-db"

#: The artifact label the boundary reports a refusal under.
ARTIFACT = "store:observations"

#: Long and unguessable: a match cannot be a coincidence of a short needle.
SECRET_VALUE = "vault-value-9f3c-4b71-must-not-be-persisted"

#: The row this work item registers.
OBSERVATION_ROW = ("mayhem.infra.store", "Store.save_observation")


# --- Fixtures ------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_guard_leaks_between_tests() -> Iterator[None]:
    """Fail loudly if a previous test left a process-global guard registered.

    Same discipline as the shared boundary suite, repeated here because a fixture
    is module-local: this file activates guards of its own, and a leaked entry
    would otherwise arrive in whichever test ran next.
    """
    assert active_guards() == (), "a guard leaked in from another test"
    yield
    assert active_guards() == (), "a guard leaked out of this test"


@pytest.fixture
def guard() -> SecretLeakGuard:
    """A guard that knows one resolved value. Not active on its own."""
    leaked = SecretLeakGuard()
    leaked.register_value(SECRET_VALUE)
    return leaked


@pytest.fixture
def active_guard(guard: SecretLeakGuard) -> Iterator[SecretLeakGuard]:
    """The guard, active for the duration of one test."""
    with guard_evidence_writes(guard) as registered:
        yield registered


@pytest.fixture
def secret_tree(tmp_path: Path) -> Path:
    """A provider tree holding the one value this module cares about."""
    root = tmp_path / "secrets"
    (root / SecretProvider.VAULT.value).mkdir(parents=True, exist_ok=True)
    (root / SecretProvider.VAULT.value / "prod__database").write_text(SECRET_VALUE, "utf-8")
    return root


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    migrated = Store.open_migrated(tmp_path / "mayhem.db")
    yield migrated
    migrated.close()


class _TransactionCountingStore(Store):
    """Counts write boundaries, so "the gate runs first" becomes observable.

    A behavioural assertion that no row was written cannot distinguish *refused
    before the transaction* from *wrote and rolled back*. Counting the boundaries
    can, and the difference is the whole reason the gate is placed where it is: a
    rollback is a weaker guarantee, because it leaves the write in the journal
    rather than never having made it.
    """

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.opened = 0

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        self.opened += 1
        with super().write() as conn:
            yield conn


# --- Payloads ------------------------------------------------------------------


def ordinary_data() -> dict[str, object]:
    """The positive control: an operator note carrying nothing sensitive."""
    return {
        "text": "db-1 stayed up through the lease hold; no manual intervention",
        "kind": "note",
        "actor": "facilitator-ana",
    }


def tick_report() -> dict[str, object]:
    """What a scheduler tick files when nothing unusual happened."""
    return {
        "controller_id": "controller-1",
        "evaluated": 12,
        "fired": 1,
        "refused": [
            {"schedule_id": "s-2", "code": "window.closed"},
            {"schedule_id": "s-3", "code": "hold.active"},
        ],
    }


def _observation_rows(store: Store) -> list[dict[str, object]]:
    return [dict(row) for row in store.query("SELECT * FROM observations ORDER BY id")]


def _grant() -> SecretGrant:
    return SecretGrant(
        principal=ALICE,
        credential_pattern="vault:prod/*",
        environments=(PROD,),
        scopes=(f"step:{STEP_ID}",),
        expires_at=NOW + timedelta(seconds=3600),
        issued_at=NOW,
    )


def _reference() -> CredentialRef:
    return CredentialRef(
        provider=SecretProvider.VAULT,
        secret="prod/database",
        purpose="inject the fault's database credential",
        scope=CredentialScope(kind=ScopeKind.STEP, ref=STEP_ID),
    )


@contextmanager
def _resolved_value(tree: Path, leaked: SecretLeakGuard) -> Iterator[str]:
    """Yield a credential value resolved for real, for one lexical block.

    The needles are registered by resolution, which is the whole point: a guard
    fed a hand-typed fixture string proves the byte scan works, and this proves
    the scan fires on a value that entered the process the only way one can. The
    value is handed out through ``ResolvedSecret.use``, so a caller that plants it
    in a payload is reproducing the defect — a live run composing a message that
    happened to include the credential — rather than inventing one.
    """
    resolver = SecretResolver(
        providers={SecretProvider.VAULT: FilesystemFixtureProvider(tree)},
        grant_source=StaticGrantSource((_grant(),)),
        clock=lambda: NOW,
        guard=leaked,
    )
    secret = resolver.resolve(_reference(), principal=ALICE, environment=PROD, step_id=STEP_ID)
    with secret.use() as value:
        assert value == SECRET_VALUE, "the run must actually have held the value"
        yield value
    secret.zero()


# --- Write path: the observations row ------------------------------------------


class TestObservationBoundary:
    def test_a_secret_classified_field_is_refused_with_no_guard_registered(
        self, store: Store
    ) -> None:
        """The stateless half: refused whether or not this run resolved anything."""
        with pytest.raises(InvariantViolationError) as excinfo:
            store.save_observation("game_day.artifact", data={"resolved_credentials": {"db": "x"}})
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        # A refusal that said only "refused" would be indistinguishable from a
        # schema error, so it must name the path that is not persistable.
        assert "resolved_credentials" in str(excinfo.value)
        assert ARTIFACT in str(excinfo.value)
        assert _observation_rows(store) == [], "a refusal must precede the transaction"
        store.close()

    def test_a_resolved_value_planted_in_a_facilitator_note_is_refused(
        self, store: Store, secret_tree: Path, guard: SecretLeakGuard
    ) -> None:
        """The reported gap, reproduced: an operator's note carrying a credential.

        ``text`` is graded SENSITIVE, not secret, so the grade rule alone would
        wave this through — which is why the payload is written as a free-text
        note rather than as an obviously-secret field.
        """
        with guard_evidence_writes(guard):
            with _resolved_value(secret_tree, guard) as value:
                assert guard.needle_count >= 1, "the guard must have registered the value"
                with pytest.raises(InvariantViolationError) as excinfo:
                    store.save_observation(
                        "game_day.artifact",
                        source="session-1",
                        data={
                            "kind": "note",
                            "actor": "facilitator-ana",
                            "text": (f"pasted the connection string while annotating: {value}"),
                        },
                    )
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert SECRET_VALUE not in str(excinfo.value), (
            "a refusal that carried the value would carry it into every log that "
            "captured the traceback"
        )
        assert ARTIFACT in str(excinfo.value)
        assert "offset" in str(excinfo.value)
        assert _observation_rows(store) == []
        store.close()

    def test_a_refusal_leaves_the_rows_already_there_untouched(
        self, store: Store, active_guard: SecretLeakGuard
    ) -> None:
        """A refused write must not disturb what a legitimate write persisted."""
        store.save_observation("campaign_resume", source="c-1", data={"recovery_status": "resumed"})
        before = _observation_rows(store)
        assert len(before) == 1
        with pytest.raises(InvariantViolationError):
            store.save_observation(
                "game_day.artifact",
                source="session-1",
                data={"detail": f"still {SECRET_VALUE}"},
            )
        assert _observation_rows(store) == before
        store.close()

    def test_the_byte_rule_catches_a_value_nested_deep_in_the_payload(
        self, store: Store, active_guard: SecretLeakGuard
    ) -> None:
        """No key in here is graded secret, so only the byte rule can see it."""
        planted: dict[str, object] = {
            "provider": {"stderr": f"FATAL: auth failed for {SECRET_VALUE}"},
            "attempts": [{"retry": f"still {SECRET_VALUE}"}],
        }
        with pytest.raises(InvariantViolationError) as excinfo:
            store.save_observation("schedule.tick", data=planted)
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert _observation_rows(store) == []
        store.close()

    def test_the_refusal_precedes_the_bytes_reaching_disk(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """Not merely "the row was rolled back": the needle is in no file at all."""
        database = tmp_path / "mayhem.db"
        store = Store.open_migrated(database)
        with pytest.raises(InvariantViolationError):
            store.save_observation("schedule.tick", data={"detail": f"used {SECRET_VALUE}"})
        store.close()
        assert SECRET_VALUE.encode() not in database.read_bytes()

    def test_the_gate_opens_no_transaction_at_all(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """Ordering, observed rather than inferred from an empty table."""
        counting = _TransactionCountingStore(tmp_path / "mayhem.db")
        counting.migrate()
        with pytest.raises(InvariantViolationError):
            counting.save_observation("schedule.tick", data={"detail": f"used {SECRET_VALUE}"})
        assert counting.opened == 0, "the gate must run before the write boundary opens"
        counting.save_observation("schedule.tick", data=tick_report())
        assert counting.opened == 1, "the positive control must still take the boundary"
        counting.close()


class TestObservationPositiveControl:
    def test_an_ordinary_observation_still_writes_byte_for_byte(
        self, store: Store, active_guard: SecretLeakGuard
    ) -> None:
        """A live guard must not cost an operator their note.

        ``data_json`` is compared against ``json.dumps`` of the same dict rather
        than against a load-and-dump round trip, so a gate that changed the
        rendering would fail here: the artifact is the bytes, not the structure.
        """
        data = ordinary_data()
        store.save_observation("game_day.artifact", run_id="r-1", source="session-1", data=data)
        rows = _observation_rows(store)
        assert len(rows) == 1
        row = rows[0]
        assert row["kind"] == "game_day.artifact"
        assert row["run_id"] == "r-1"
        assert row["source"] == "session-1"
        assert row["data_json"] == json.dumps(data)
        parsed = datetime.fromisoformat(str(row["timestamp"]))
        assert parsed.tzinfo is not None
        store.close()

    def test_an_observation_with_no_data_still_writes_the_empty_document(
        self, store: Store, active_guard: SecretLeakGuard
    ) -> None:
        """``data=None`` is a real call shape and must not change meaning."""
        store.save_observation("campaign_stop", source="c-1")
        rows = _observation_rows(store)
        assert len(rows) == 1
        assert rows[0]["data_json"] == "{}"
        assert rows[0]["run_id"] == ""
        store.close()


# --- Both callers, unedited ----------------------------------------------------


class TestBothCallersAreCovered:
    """One gate, two writers — asserted by driving both of them.

    Neither caller is edited. That is the point of registering the shared
    function rather than either call site: a gate at each call site would be two
    gates to keep, and the table would claim coverage it could not describe.
    """

    def test_record_artifact_refuses_a_note_carrying_a_resolved_value(
        self, store: Store, secret_tree: Path, guard: SecretLeakGuard
    ) -> None:
        with guard_evidence_writes(guard):
            with _resolved_value(secret_tree, guard) as value:
                artifact = GameDayArtifact(
                    artifact_id="a-1",
                    session_id="session-1",
                    kind=ArtifactKind.NOTE,
                    actor="facilitator-ana",
                    text=f"annotating the reset, the console echoed {value}",
                    at=NOW.isoformat(),
                )
                with pytest.raises(InvariantViolationError) as excinfo:
                    record_artifact(store, artifact)
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert (
            store.query("SELECT * FROM observations WHERE kind = ?", ("game_day.artifact",)) == []
        )
        store.close()

    def test_record_tick_refuses_a_report_carrying_a_resolved_value(
        self, store: Store, active_guard: SecretLeakGuard
    ) -> None:
        """The other half of the pair, which is why one row is the honest count."""
        schedule_store = ScheduleStore(store)
        with pytest.raises(InvariantViolationError) as excinfo:
            schedule_store.record_tick(
                {
                    "controller_id": "controller-1",
                    "refused": [{"schedule_id": "s-2", "reason": f"used {SECRET_VALUE}"}],
                },
                controller_id="controller-1",
            )
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert store.query("SELECT * FROM observations WHERE kind = ?", ("schedule.tick",)) == []
        store.close()

    def test_both_writers_still_record_ordinary_observations(
        self, store: Store, active_guard: SecretLeakGuard
    ) -> None:
        """The positive control for both: the gate costs neither writer its row."""
        record_artifact(
            store,
            GameDayArtifact(
                artifact_id="a-1",
                session_id="session-1",
                kind=ArtifactKind.NOTE,
                actor="facilitator-ana",
                text="the hold held; nobody touched the cluster",
                at=NOW.isoformat(),
            ),
        )
        ScheduleStore(store).record_tick(tick_report(), controller_id="controller-1")
        rows = store.query("SELECT kind, source FROM observations ORDER BY id")
        assert [str(row["kind"]) for row in rows] == ["game_day.artifact", "schedule.tick"]
        assert str(rows[1]["source"]) == "controller-1"
        store.close()


# --- Registration --------------------------------------------------------------


class TestTheObservationWriterIsRegistered:
    def test_the_row_exists_and_names_the_one_gate(self) -> None:
        assert BOUNDARY_CALL_SITES[OBSERVATION_ROW] == frozenset({"require_persistable_document"})

    def test_the_row_describes_the_source_rather_than_copying_it(self) -> None:
        """The table and the code must agree in both directions.

        Asserted against a scan of the installed source rather than against the
        table's own contents, so a row that survived while its gate was deleted
        fails here instead of passing on a row that no longer describes anything.
        """
        assert OBSERVATION_ROW in _gate_calling_functions()

    def test_the_shared_registered_writer_check_still_passes(self) -> None:
        """No module calls a gate without a row, and no row is stale."""
        TestTheGateCannotBeDeleted().test_every_module_calling_a_gate_is_registered()
