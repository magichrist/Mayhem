"""The evidence boundary is unskippable (plan 29 Phase 4).

Phase 2 shipped :class:`~mayhem.infra.secret_resolver.SecretLeakGuard` and
proved, correctly, that it works *when called*. Its author then wrote down the
hole this file exists to close: nothing called it, so a caller could write a
secret-classified value into an envelope, a store row, a bundle file, a rendered
report, or a log line and nothing would stop them. A check a caller may skip is
decoration.

So the tests here are shaped around a single claim — **there is no way to reach a
write path without passing the gate** — and each claim is attacked three ways:

* **Negative control, per write path.** Every path that persists, renders, or
  serialises evidence is given a document carrying a value the run resolved and
  is required to refuse. Two payloads per path, because the two rules catch
  different things: a field *named* ``secret_value`` (the stateless grade rule)
  and the same value planted under ``detail`` (the byte rule, which is the only
  one that can see it).
* **Positive control, per write path.** Ordinary evidence — no credential, no
  active guard — still writes. A gate that refuses everything is not a gate, and
  a suite that only proves refusal would not notice.
* **Structural conformance.** :class:`TestTheGateCannotBeDeleted` parses the
  owned modules and asserts every write entry point contains a call to one of the
  boundary functions. Deleting a gate call therefore fails the suite *statically*,
  even in a path whose behaviour is masked by a second gate further down (a real
  hazard here: ``write_evidence_file`` delegates to ``redact_envelope``, so
  removing only the file gate changes no behaviour — which is precisely why the
  static check is needed and not merely belt-and-braces).

The audit stream, added later
-----------------------------

An integrator reproduced a leak the original four-rule statement missed:
``AuditStream.record`` persisted a free-form ``AuditEntry.detail`` dict with no
gate, so a resolved value reached ``audit_entries`` while a guard was active. An
audit entry is evidence — persisted, exported, and covered by the attestation and
retention machinery — so plan 12's "secrets must never enter evidence" binds it
exactly as it binds the envelope row. :class:`TestAuditStreamBoundary` attacks it
the same way, with the addition that ``detail`` is *free-form*: the planted value
goes several levels down, where no key name is graded ``secret`` and only the
byte rule can see it.

What this suite still cannot prove
----------------------------------

The static check proves a **listed** entry point still calls its gates. It does
not prove the list is complete, and that gap is real — it is how the audit-stream
defect survived. One half is now closed:
:func:`TestTheGateCannotBeDeleted.test_every_module_calling_a_gate_is_registered`
fails when a module calls a boundary gate without a table row. The other half — a
brand-new write path with no gate call at all — is not decidable from source text
without an allowlist that reproduces the same hand-maintained table under a second
name, so it is stated as a limitation and left to review rather than simulated with
a check that would pass while the hole stayed open.

The bundle test is the plan's own acceptance criterion, run through the real
pipeline — resolve, build, persist, seal, and then read every byte back off disk
— rather than by calling the guard on a hand-built artifact.
"""

from __future__ import annotations

import ast
import inspect
import json
import threading
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.domain.attestation import AttestedTimestamp
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.evidence import EvidenceEnvelope, require_persistable_envelope
from mayhem.domain.evidence_bundle import build_bundle, verify_bundle
from mayhem.domain.redaction import redact_log_event
from mayhem.domain.secrets import (
    EVIDENCE_FIELD_CLASSIFICATIONS,
    REFUSAL_SECRET_FIELD_PERSISTED,
    CredentialRef,
    CredentialScope,
    ScopeKind,
    SecretGrant,
    SecretProvider,
)
from mayhem.infra.audit_stream import (
    KIND_RUN_SEALED,
    AuditEntry,
    AuditStream,
    seal_run_evidence_at_run_close,
)
from mayhem.infra.evidence import (
    build_evidence,
    redact_envelope,
    render_report,
    write_evidence,
    write_evidence_file,
)
from mayhem.infra.evidence_bundle_io import load_bundle, write_bundle
from mayhem.infra.report import (
    render_report_html,
    render_report_json,
    render_report_markdown,
    write_report_artifacts,
)
from mayhem.infra.secret_resolver import (
    REFUSAL_SECRET_BYTES_IN_ARTIFACT,
    FilesystemFixtureProvider,
    SecretGrantRepository,
    SecretLeakGuard,
    SecretResolver,
    StaticGrantSource,
    active_guards,
    guard_evidence_writes,
    require_clean_log_line,
    require_persistable_document,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
ALICE = "svc:alice"
PROD = "prod-eu"
RUN_ID = "r-boundary-1"

#: Long and unguessable: a match cannot be a coincidence of a short needle.
SECRET_VALUE = "vault-value-9f3c-4b71-must-not-be-persisted"


# --- Fixtures ------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_guard_leaks_between_tests() -> Iterator[None]:
    """Fail loudly if a previous test left a process-global guard registered.

    The registry is deliberately process-wide (see
    :func:`~mayhem.infra.secret_resolver.guard_evidence_writes`), which makes a
    leaked entry a cross-test failure nobody can explain. Asserting emptiness
    before and after every test in this module turns "some other test leaked"
    into a named failure instead of a mystery.
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


# --- Payloads: two shapes, because the two rules catch different things ---------


def graded_envelope() -> EvidenceEnvelope:
    """Carries a field *named* ``secret_value`` — what the grade rule refuses."""
    return EvidenceEnvelope(
        run_id=RUN_ID,
        plan_hash="h",
        verdict="pass",
        step_reports=({"step_id": "inject-db", "secret_value": SECRET_VALUE},),
    )


def planted_envelope() -> EvidenceEnvelope:
    """Carries the same value under a field *nobody graded* — the byte rule's job."""
    return EvidenceEnvelope(
        run_id=RUN_ID,
        plan_hash="h",
        verdict="pass",
        step_reports=(
            {
                "step_id": "inject-db",
                "status": "completed",
                "detail": f"provider stderr: connection reset for {SECRET_VALUE}",
            },
        ),
    )


def ordinary_envelope() -> EvidenceEnvelope:
    """The positive control: ordinary evidence, no credential anywhere."""
    return EvidenceEnvelope(
        run_id=RUN_ID,
        plan_hash="abcdef0123456789",
        plan_id="plan-1",
        engine="kubernetes",
        verdict="pass",
        recovery_state="recovered",
        safety_decisions=("impact gate: approved",),
        step_reports=({"step_id": "inject-db", "status": "completed", "detail": "reset applied"},),
        lease_timeline=({"lease": "db-1", "state": "held"},),
        observations=({"kind": "fault", "target": "db-1", "outcome": "applied"},),
    )


def _build(**overrides: Any) -> EvidenceEnvelope:
    """``build_evidence`` with the ordinary payload, plus any overrides."""
    payload: dict[str, Any] = {
        "run_id": RUN_ID,
        "plan": None,
        "target_profile": "local",
        "engine": "kubernetes",
        "safety_decisions": ("impact gate: approved",),
        "step_reports": ({"step_id": "inject-db", "status": "completed", "detail": "reset"},),
        "lease_timeline": (),
        "observations": ({"kind": "fault", "target": "db-1"},),
        "verdict": "pass",
        "recovery_state": "recovered",
        "remediation": (),
    }
    payload.update(overrides)
    return build_evidence(**payload)  # type: ignore[arg-type]


def grant(*, scopes: tuple[str, ...] = ()) -> SecretGrant:
    return SecretGrant(
        principal=ALICE,
        credential_pattern="vault:prod/*",
        environments=(PROD,),
        scopes=scopes,
        expires_at=NOW + timedelta(seconds=3600),
        issued_at=NOW,
    )


def _resolved_run(tree: Path, leaked: SecretLeakGuard) -> list[dict[str, object]]:
    """Resolve and spend a credential for real; return only its receipt metadata.

    The value is reachable only inside the ``with`` block, and this function
    returns before it builds anything — which is the discipline the whole plan
    rests on: evidence may carry *that* a credential was resolved, never it.
    """
    resolver = SecretResolver(
        providers={SecretProvider.VAULT: FilesystemFixtureProvider(tree)},
        grant_source=StaticGrantSource((grant(),)),
        clock=lambda: NOW,
        guard=leaked,
    )
    reference = CredentialRef(
        provider=SecretProvider.VAULT,
        secret="prod/database",
        purpose="inject the fault's database credential",
        scope=CredentialScope(kind=ScopeKind.STEP, ref="inject-db"),
    )
    secret = resolver.resolve(reference, principal=ALICE, environment=PROD, step_id="inject-db")
    with secret.use() as value:
        assert value == SECRET_VALUE, "the run must actually have held the value"
    secret.zero()
    return [receipt.to_dict() for receipt in resolver.receipts]


# --- The gate itself: two rules, and the second one needs no configuration ----


class TestTheGateItself:
    def test_the_grade_rule_holds_with_no_guard_registered(self) -> None:
        """Structural half: no run state, no registry, nothing to forget to set."""
        with pytest.raises(InvariantViolationError) as excinfo:
            require_persistable_document({"secret_value": "anything"}, artifact="probe")
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED

    def test_the_grade_rule_walks_nested_structures(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            require_persistable_document(
                {"steps": [{"detail": {"resolved_credentials": {"db": "x"}}}]},
                artifact="probe",
            )
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        assert "resolved_credentials" in str(excinfo.value)

    def test_an_ungraded_field_is_not_refused_by_the_grade_rule(self) -> None:
        """``detail`` grades SENSITIVE, which is why the byte rule has to exist."""
        require_persistable_document(
            {"detail": f"used {SECRET_VALUE}"}, artifact="probe"
        )  # no active guard: the grade rule alone must let this through

    def test_the_byte_rule_needs_an_active_guard_and_only_an_active_one(
        self, guard: SecretLeakGuard
    ) -> None:
        document = {"detail": f"used {SECRET_VALUE}"}
        require_persistable_document(document, artifact="probe")  # inactive: silent
        with guard_evidence_writes(guard):
            with pytest.raises(InvariantViolationError) as excinfo:
                require_persistable_document(document, artifact="probe")
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert SECRET_VALUE not in str(excinfo.value)

    def test_the_refusal_message_carries_a_digest_not_a_value(
        self, active_guard: SecretLeakGuard
    ) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            require_persistable_document({"detail": SECRET_VALUE}, artifact="probe")
        assert SECRET_VALUE not in str(excinfo.value)


# --- The registry: process-wide, and always released ---------------------------


class TestTheRegistry:
    def test_the_guard_is_registered_inside_and_gone_outside(
        self, guard: SecretLeakGuard
    ) -> None:
        assert active_guards() == ()
        with guard_evidence_writes(guard) as registered:
            assert registered is guard
            assert active_guards() == (guard,)
        assert active_guards() == ()

    def test_the_guard_is_released_even_when_the_block_raises(
        self, guard: SecretLeakGuard
    ) -> None:
        with pytest.raises(RuntimeError), guard_evidence_writes(guard):
            assert active_guards() == (guard,)
            raise RuntimeError("the run blew up mid-write")
        assert active_guards() == (), "a failed run must not leave a registry entry"

    def test_registration_is_idempotent_and_unwinds_once(self, guard: SecretLeakGuard) -> None:
        with guard_evidence_writes(guard), guard_evidence_writes(guard):
            assert active_guards() == (guard,)
        assert active_guards() == ()

    def test_a_worker_thread_write_is_gated_too(
        self, active_guard: SecretLeakGuard
    ) -> None:
        """Why the registry is a shared set and not a thread-local.

        A fault executes on a worker thread and writes its evidence from there. A
        guard scoped to the resolving thread would not be consulted, and the leak
        would appear exactly when the engine is busiest. Failing closed — scanning
        too much — is the correct bias, so the registry is process-wide.
        """
        seen: list[str] = []

        def worker() -> None:
            try:
                require_persistable_document({"detail": SECRET_VALUE}, artifact="worker")
            except InvariantViolationError as exc:
                seen.append(exc.rule)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        assert seen == [REFUSAL_SECRET_BYTES_IN_ARTIFACT]

    def test_release_zeroes_the_needles_the_registry_was_holding(
        self, guard: SecretLeakGuard
    ) -> None:
        with guard_evidence_writes(guard):
            guard.release()
            assert guard.released
            assert guard.scan_bytes(SECRET_VALUE) == ()
        assert active_guards() == ()


# --- Write path 1: envelope construction ---------------------------------------


class TestBuildEvidenceBoundary:
    def test_a_secret_classified_field_is_refused_before_the_envelope_exists(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _build(step_reports=({"step_id": "s", "secret_value": SECRET_VALUE},))
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED

    def test_a_resolved_value_planted_in_a_step_report_is_refused(
        self, active_guard: SecretLeakGuard
    ) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _build(step_reports=({"step_id": "s", "detail": f"used {SECRET_VALUE}"},))
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT

    def test_a_resolved_value_planted_in_observations_is_refused(
        self, active_guard: SecretLeakGuard
    ) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _build(observations=({"kind": "fault", "detail": f"resolved {SECRET_VALUE}"},))
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT

    def test_a_resolved_value_planted_in_execution_intent_is_refused(
        self, active_guard: SecretLeakGuard
    ) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _build(execution_intent={"actor": ALICE, "note": f"used {SECRET_VALUE}"})
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT

    def test_a_secret_classified_field_nested_in_execution_intent_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _build(execution_intent={"actor": ALICE, "resolved_credentials": {"db": "x"}})
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED

    def test_ordinary_evidence_still_builds(self) -> None:
        envelope = _build()
        assert envelope.run_id == RUN_ID
        assert envelope.verdict == "pass"
        assert envelope.step_reports

    def test_ordinary_evidence_still_builds_while_a_guard_is_active(
        self, active_guard: SecretLeakGuard
    ) -> None:
        """A live guard must not cost a legitimate run its evidence."""
        envelope = _build()
        assert envelope.step_reports[0]["detail"] == "reset"


# --- Write path 2: the store row ------------------------------------------------


class TestStoreWriteBoundary:
    def test_a_secret_classified_envelope_never_reaches_a_row(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        with pytest.raises(InvariantViolationError) as excinfo:
            write_evidence(store, graded_envelope())
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        assert "evidence_envelopes" not in _table_names(store), (
            "the refusal must precede the transaction, not roll one back"
        )
        store.close()

    def test_a_planted_value_never_reaches_a_row(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        with pytest.raises(InvariantViolationError) as excinfo:
            write_evidence(store, planted_envelope())
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert "evidence_envelopes" not in _table_names(store)
        store.close()

    def test_ordinary_evidence_still_writes_a_row(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        write_evidence(store, ordinary_envelope())
        rows = store.query(
            "SELECT envelope_json FROM evidence_envelopes WHERE run_id = ?", (RUN_ID,)
        )
        assert len(rows) == 1
        assert json.loads(str(rows[0]["envelope_json"]))["verdict"] == "pass"
        store.close()

    def test_the_migrated_schema_has_no_column_graded_secret(self, tmp_path: Path) -> None:
        """The schema is the guarantee for the tables a migration created.

        Phase 2 proved ``secret_grants`` has no value column. This widens that to
        every table the migration chain creates, using the same grading vocabulary
        the write boundary uses — so "no secret-classified column exists" is
        checked against a name set, not against an assertion in prose. It is also
        why this wave needs no ``M0028``: there is no table to add, only a rule to
        enforce at the writers.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        forbidden = set(EVIDENCE_FIELD_CLASSIFICATIONS.forbidden_fields())
        assert forbidden, "the grading vocabulary must name at least one secret field"
        offenders: list[str] = []
        for table in sorted(_table_names(store)):
            for row in store.query(f"PRAGMA table_info({table})"):
                name = str(row["name"])
                if name in forbidden or name.endswith(("_value", "_secret", "_password")):
                    offenders.append(f"{table}.{name}")
        assert offenders == [], f"a column a credential could occupy exists: {offenders}"
        store.close()

    def test_a_grant_row_refuses_a_planted_value(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """The other store writer in this module's ownership.

        ``secret_grants`` has no value column, but its *contents* are
        caller-supplied strings, and a caller-supplied string is exactly how a
        value reaches a row.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        poisoned = SecretGrant(
            principal=ALICE,
            credential_pattern="vault:prod/*",
            environments=(f"{SECRET_VALUE}",),
            expires_at=NOW + timedelta(seconds=3600),
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            SecretGrantRepository(store).save(poisoned)
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert store.query("SELECT * FROM secret_grants") == []
        store.close()

    def test_an_ordinary_grant_still_writes(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        SecretGrantRepository(store).save(grant(scopes=("step:inject-db",)))
        assert len(store.query("SELECT * FROM secret_grants")) == 1
        store.close()


# --- Write path 2b: the audit stream -------------------------------------------
#
# An audit entry is evidence. It is persisted, exported, and covered by the
# attestation and retention machinery, so plan 12's "secrets must never enter
# evidence" binds it — and it binds it at the free-form ``detail`` dict, which is
# the one surface a name-based rule structurally cannot see. The defect this
# closes was reproduced before it was fixed: with an active guard registered,
# ``AuditStream.record`` persisted a resolved value into ``audit_entries``.


class TestAuditStreamBoundary:
    @staticmethod
    def _stream(store: Store) -> AuditStream:
        return AuditStream(store)

    @staticmethod
    def _entry(**overrides: Any) -> AuditEntry:
        payload: dict[str, Any] = {
            "principal": ALICE,
            "action": KIND_RUN_SEALED,
            "target": "r-boundary-1:manifest",
            "subject_run_id": RUN_ID,
        }
        payload.update(overrides)
        return AuditEntry(**payload)  # type: ignore[arg-type]

    def test_a_secret_classified_field_is_refused_and_no_row_is_left(
        self, tmp_path: Path
    ) -> None:
        """The stateless half: refused with no guard registered at all."""
        store = Store.open_migrated(tmp_path / "mayhem.db")
        with pytest.raises(InvariantViolationError) as excinfo:
            self._stream(store).record(self._entry(detail={"resolved_credentials": {"db": "x"}}))
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        assert _audit_rows(store) == [], "a refusal must precede the transaction"
        store.close()

    def test_a_planted_value_is_refused_and_no_row_is_left(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """The reproduced defect, as the negative control.

        The refusal must leave neither the entry nor a head row, so a caller
        cannot observe a stream tip that records an append which never happened.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        with pytest.raises(InvariantViolationError) as excinfo:
            self._stream(store).record(
                self._entry(detail={"note": f"provider stderr: used {SECRET_VALUE}"})
            )
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert SECRET_VALUE not in str(excinfo.value)
        assert _audit_rows(store) == []
        assert _audit_head_rows(store) == []
        assert self._stream(store).entry_count() == 0
        store.close()

    def test_the_byte_rule_catches_a_value_nested_deep_in_detail(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """``detail`` is free-form, so nesting is the shape to attack.

        Neither ``detail`` nor any key inside it is graded ``secret``, so the grade
        rule alone would wave this through — the byte rule is the only thing that
        can see a value planted here, which is why both rules exist.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        planted = {
            "provider": {"stderr": f"FATAL: auth failed for {SECRET_VALUE}"},
            "attempts": [{"retry": f"still {SECRET_VALUE}"}],
        }
        with pytest.raises(InvariantViolationError) as excinfo:
            self._stream(store).record(self._entry(detail=planted))
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert _audit_rows(store) == []
        store.close()

    def test_the_refusal_precedes_the_bytes_reaching_disk(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """Not merely "the row was rolled back": the needle is in no file at all."""
        database = tmp_path / "mayhem.db"
        store = Store.open_migrated(database)
        with pytest.raises(InvariantViolationError):
            self._stream(store).record(
                self._entry(detail={"note": f"used {SECRET_VALUE}"})
            )
        store.close()
        assert SECRET_VALUE.encode() not in database.read_bytes()

    def test_an_ordinary_entry_still_records_while_a_guard_is_active(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """The positive control: a live guard must not cost a run its audit log."""
        store = Store.open_migrated(tmp_path / "mayhem.db")
        stream = self._stream(store)
        sealed = stream.record(
            self._entry(detail={"chain_root": "abc123", "complete": True}),
            recorded_at=_fixed_reading(),
        )
        assert stream.entry_count() == 1
        assert sealed.payload["detail"] == {"chain_root": "abc123", "complete": True}
        assert stream.verify().valid
        store.close()

    def test_the_named_record_helpers_are_gated_too(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """The helpers build an :class:`AuditEntry` and call :meth:`record`.

        They add no second write path, so they inherit the gate — asserted here
        because ``detail`` on ``record_evidence_deleted`` is *merged* into a new
        dict there, which is the one place this module could have assembled a
        document the gate would never see.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        stream = self._stream(store)
        with pytest.raises(InvariantViolationError) as excinfo:
            stream.record_evidence_deleted(
                principal=ALICE,
                manifest_id="r-boundary-1:manifest",
                run_id=RUN_ID,
                approver=ALICE,
                detail={"reason": f"rotated after {SECRET_VALUE}"},
            )
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert _audit_rows(store) == []
        store.close()

    def test_a_run_close_seal_still_audits_through_the_gate(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """``seal_run_evidence_at_run_close`` is the other entry into ``record``.

        It builds its own ``detail`` from seal metadata, so it is the one caller
        whose detail this module authors rather than receives; the positive
        control says that path still records under a live guard.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        sealed = seal_run_evidence_at_run_close(
            store,
            # Through ``redact_envelope`` first, as every real seal path does: an
            # envelope carrying no redaction marker is refused outright by
            # ``seal_run_evidence``, which is a different gate and not this test's.
            redact_envelope(ordinary_envelope()),
            run_status="completed",
            verdict="pass",
            recorded_at=_fixed_reading(),
        )
        assert AuditStream(store).entry_count() == 1
        assert sealed.run_id == RUN_ID
        store.close()


# --- Write path 3: the evidence file and its report artifacts -------------------


class TestFileWriteBoundary:
    def test_a_secret_classified_envelope_never_reaches_the_disk(
        self, tmp_path: Path
    ) -> None:
        directory = tmp_path / "evidence"
        with pytest.raises(InvariantViolationError) as excinfo:
            write_evidence_file(graded_envelope(), directory)
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        assert _files(directory) == [], "a refusal must not leave a partial artifact"

    def test_a_planted_value_never_reaches_the_disk(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        directory = tmp_path / "evidence"
        with pytest.raises(InvariantViolationError) as excinfo:
            write_evidence_file(planted_envelope(), directory)
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert _files(directory) == []

    def test_ordinary_evidence_still_writes_the_file_and_its_reports(
        self, tmp_path: Path
    ) -> None:
        directory = tmp_path / "evidence"
        target = write_evidence_file(ordinary_envelope(), directory)
        assert target.exists()
        assert json.loads(target.read_text())["run_id"] == RUN_ID
        assert any(path.name.startswith("report-") for path in _files(directory))


# --- Write path 4: report rendering ---------------------------------------------


class TestReportRenderBoundary:
    @pytest.mark.parametrize(
        "renderer",
        [render_report, render_report_markdown, render_report_json, render_report_html],
    )
    def test_a_secret_classified_envelope_is_refused_by_every_renderer(
        self, renderer: Any
    ) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            renderer(graded_envelope())
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED

    @pytest.mark.parametrize(
        "renderer",
        [render_report, render_report_markdown, render_report_json, render_report_html],
    )
    def test_a_planted_value_is_refused_by_every_renderer(
        self, renderer: Any, active_guard: SecretLeakGuard
    ) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            renderer(planted_envelope())
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT

    @pytest.mark.parametrize(
        "renderer",
        [render_report, render_report_markdown, render_report_json, render_report_html],
    )
    def test_ordinary_evidence_still_renders(self, renderer: Any) -> None:
        rendered = renderer(ordinary_envelope())
        assert RUN_ID in rendered
        assert SECRET_VALUE not in rendered

    def test_report_artifacts_refuse_a_planted_value(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            write_report_artifacts(planted_envelope(), artifact_dir=tmp_path / "artifacts")
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert _files(tmp_path / "artifacts") == [], (
            "the sweep runs per format, so a refused render must not have "
            "written the formats that were rendered before it"
        )

    def test_ordinary_evidence_still_writes_every_report_format(
        self, tmp_path: Path
    ) -> None:
        paths = write_report_artifacts(ordinary_envelope(), artifact_dir=tmp_path / "artifacts")
        assert set(paths) == {"markdown", "json", "html"}
        for path in paths.values():
            assert path.exists()
            assert SECRET_VALUE not in path.read_text()


# --- Write path 5: the sealed bundle --------------------------------------------


class TestBundleWriteBoundary:
    def test_a_planted_value_is_refused_and_nothing_is_written(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        bundle = build_bundle(
            evidence=planted_envelope().model_dump(mode="json"),
            created_at=NOW.isoformat(),
        )
        target = tmp_path / "bundle"
        with pytest.raises(InvariantViolationError) as excinfo:
            write_bundle(bundle, target)
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert not target.exists(), "the bundle must be gated before the first byte"

    def test_a_secret_classified_artifact_is_refused(
        self, tmp_path: Path
    ) -> None:
        bundle = build_bundle(
            evidence={"run_id": RUN_ID, "step_reports": [{"secret_value": SECRET_VALUE}]},
            created_at=NOW.isoformat(),
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            write_bundle(bundle, tmp_path / "bundle")
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED

    def test_ordinary_evidence_still_seals_and_round_trips(self, tmp_path: Path) -> None:
        # Through ``redact_envelope`` first, as every real write path does: that
        # is what stamps the redaction marker a bundle must carry to verify.
        bundle = build_bundle(
            evidence=redact_envelope(ordinary_envelope()).model_dump(mode="json"),
            created_at=NOW.isoformat(),
        )
        target = write_bundle(bundle, tmp_path / "bundle")
        reloaded = load_bundle(target)
        assert verify_bundle(reloaded).valid
        assert set(reloaded.artifacts) == set(bundle.artifacts)


# --- Write path 6: the log surface ---------------------------------------------


class TestLogBoundary:
    def test_a_log_line_carrying_a_value_is_refused(
        self, active_guard: SecretLeakGuard
    ) -> None:
        line = f"event=step_completed step=inject-db detail=resolved {SECRET_VALUE}"
        with pytest.raises(InvariantViolationError) as excinfo:
            require_clean_log_line(line, event="step_completed")
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert SECRET_VALUE not in str(excinfo.value)

    def test_an_ordinary_log_line_passes(self) -> None:
        require_clean_log_line(
            "event=step_completed step=inject-db detail=reset applied", event="step_completed"
        )

    def test_the_stateless_sweep_catches_what_the_name_rules_catch(self) -> None:
        """Backup, not policy: the name and pattern rules still do their own job.

        Asserted separately from the byte gate so a reviewer can see which layer
        catches what. ``token=`` inside a value is caught by pattern and
        ``registry_token`` is caught by key name — neither is caught by the byte
        gate, because neither value was ever resolved by this run. Conversely a
        field named ``detail`` is caught by neither, which is the next test.

        The key vocabulary here is :mod:`mayhem.domain.redaction`'s own, which is
        deliberately narrower than the token-level matcher in
        :mod:`mayhem.domain.secrets`: redaction fires on whole key names and
        suffixes, and widening it is a separate decision from this one.
        """
        swept = redact_log_event(
            "step_completed",
            {"registry_token": "abc123", "detail": "connected with token=hunter2 to db-1"},
        )
        assert swept.value["registry_token"] == "***REDACTED***"
        assert "hunter2" not in str(swept.value["detail"])
        assert swept.removed_paths == ("$.registry_token", "$.detail")

    def test_the_stateless_sweep_still_misses_a_composed_value(
        self, active_guard: SecretLeakGuard
    ) -> None:
        """Which is why the byte gate, not the sweep, is the boundary."""
        swept = redact_log_event("step_completed", {"detail": f"used {SECRET_VALUE}"})
        assert SECRET_VALUE in str(swept.value)
        with pytest.raises(InvariantViolationError) as excinfo:
            require_clean_log_line(json.dumps(swept.value, default=str), event="step_completed")
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT


# --- The plan's acceptance criterion, through the real pipeline ---------------


class TestSealedBundleFromARealRun:
    """Plan 29 Phase 4's acceptance test, end to end.

    The production sequence, in the order the engine does it: resolve a granted
    credential under a live guard, record only its receipt, build the envelope,
    persist it, seal the bundle, and then read every byte of every file back.
    """

    def test_a_secrets_bearing_run_seals_zero_credential_bytes(
        self, tmp_path: Path, secret_tree: Path, guard: SecretLeakGuard
    ) -> None:
        # Distinct directories on purpose: ``write_evidence_file`` writes the
        # envelope *and* its report artifacts, and ``load_bundle`` reads every
        # ``*.json`` in the directory it is given. Sharing one directory would
        # make the reloaded bundle carry files its manifest never listed, and the
        # verification below would fail for a reason that has nothing to do with
        # secrets.
        evidence_dir = tmp_path / "evidence"
        bundle_dir = tmp_path / "bundle"
        with guard_evidence_writes(guard):
            receipts = _resolved_run(secret_tree, guard)
            assert receipts, "the run must have produced a receipt to record"
            envelope = _build(step_reports=({"step_id": "inject-db", "receipts": receipts},))

            store = Store.open_migrated(tmp_path / "mayhem.db")
            write_evidence(store, envelope)
            write_evidence_file(envelope, evidence_dir)
            bundle = build_bundle(
                evidence=envelope.model_dump(mode="json"),
                replay={"steps": receipts},
                created_at=NOW.isoformat(),
            )
            written = write_bundle(bundle, bundle_dir)

        # Independent of the guard: read the bytes off disk and search them.
        files = sorted(
            path
            for directory in (evidence_dir, bundle_dir)
            for path in directory.rglob("*")
            if path.is_file()
        )
        assert files, "the pipeline must have produced files to inspect"
        needle = SECRET_VALUE.encode()
        for path in files:
            assert needle not in path.read_bytes(), f"{SECRET_VALUE!r} leaked into {path.name}"

        # Independent of the store: read the database file too.
        assert needle not in (tmp_path / "mayhem.db").read_bytes()

        # And the bundle still verifies — the gate is not the only thing it satisfies.
        assert verify_bundle(load_bundle(written)).valid
        store.close()

    def test_the_same_pipeline_refuses_a_value_planted_upstream(
        self, tmp_path: Path, secret_tree: Path, guard: SecretLeakGuard
    ) -> None:
        """The negative control for the test above.

        Without it, a pipeline that produced no files at all would satisfy a
        byte-scan trivially. Here a provider's stderr is captured into a step
        report — a name-based rule cannot see it — and the pipeline must refuse
        rather than seal it.
        """
        target = tmp_path / "bundle"
        with guard_evidence_writes(guard), pytest.raises(InvariantViolationError) as excinfo:
            receipts = _resolved_run(secret_tree, guard)
            poisoned = _build(
                step_reports=(
                    {
                        "step_id": "inject-db",
                        "receipts": receipts,
                        "detail": f"provider stderr: FATAL: auth failed for {SECRET_VALUE}",
                    },
                )
            )
            build_bundle(
                evidence=poisoned.model_dump(mode="json"),
                created_at=NOW.isoformat(),
            )
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert not target.exists()


# --- The domain seam ------------------------------------------------------------


class TestDomainSeam:
    def test_require_persistable_envelope_is_pure_and_raises_naming_the_field(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            require_persistable_envelope(graded_envelope())
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        assert "secret_value" in str(excinfo.value)

    def test_require_persistable_envelope_accepts_ordinary_evidence(self) -> None:
        require_persistable_envelope(ordinary_envelope())

    def test_redact_envelope_gates_the_copy_it_returns(self) -> None:
        """The lowest boundary every envelope write path passes through."""
        with pytest.raises(InvariantViolationError) as excinfo:
            redact_envelope(graded_envelope())
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED

    def test_redact_envelope_still_redacts_what_it_always_did(self) -> None:
        """The gate is additive; redaction keeps working, not replaced by it."""
        envelope = EvidenceEnvelope(
            run_id=RUN_ID,
            plan_hash="h",
            verdict="pass",
            step_reports=({"step_id": "s", "password": "hunter2"},),
        )
        stable = redact_envelope(envelope)
        assert stable.step_reports[0]["password"] == "***REDACTED***"
        assert stable.redaction_metrics["redacted_path_count"] >= 1


# --- The structural claim: delete a gate and the suite notices -----------------

#: ``(module, function) -> gates that function must call``. One entry per write
#: entry point. Adding a write path means adding a row here, which is the point:
#: the registry of gates and the registry of paths are the same list.
#:
#: What this table can and cannot prove is worth being exact about, because the
#: gap it leaves was found by an integrator rather than by this suite. It proves a
#: *listed* entry point still calls its gates — it cannot prove the list is
#: complete, because completeness is not a decidable property of "writes
#: evidence" from source text alone.
#:
#: The one direction that *is* decidable is closed separately, by
#: :meth:`TestTheGateCannotBeDeleted.test_every_module_calling_a_gate_is_registered`:
#: any module that imports a boundary gate must appear here. The remaining,
#: genuinely undecidable direction — a brand-new write path with no gate call at
#: all — is a review obligation and is named as such rather than papered over.
BOUNDARY_CALL_SITES: dict[tuple[str, str], frozenset[str]] = {
    ("mayhem.infra.audit_stream", "AuditStream.record"): frozenset(
        {"require_persistable_document"}
    ),
    ("mayhem.infra.evidence", "build_evidence"): frozenset({"require_persistable_document"}),
    ("mayhem.infra.evidence", "redact_envelope"): frozenset({"require_envelope_boundary"}),
    ("mayhem.infra.evidence", "write_evidence"): frozenset({"require_envelope_boundary"}),
    ("mayhem.infra.evidence", "write_evidence_file"): frozenset(
        {"require_envelope_boundary", "require_clean_artifact"}
    ),
    ("mayhem.infra.evidence", "render_report"): frozenset(
        {"require_envelope_boundary", "require_clean_artifact"}
    ),
    ("mayhem.infra.report", "_report_document"): frozenset(
        {"require_envelope_boundary", "require_persistable_document"}
    ),
    ("mayhem.infra.report", "write_report_artifacts"): frozenset({"require_clean_artifact"}),
    ("mayhem.infra.evidence_bundle_io", "write_bundle"): frozenset(
        {"require_persistable_document", "require_clean_artifact"}
    ),
    ("mayhem.infra.secret_resolver", "SecretGrantRepository.save"): frozenset(
        {"require_persistable_document"}
    ),
}

#: The boundary functions themselves. Each is a module-level ``def`` in
#: ``mayhem.infra.secret_resolver``.
BOUNDARY_FUNCTIONS: tuple[str, ...] = (
    "require_persistable_document",
    "require_envelope_boundary",
    "require_clean_artifact",
    "require_clean_log_line",
)


def _called_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names of every function this definition calls, ignoring attribute bases.

    ``obj.require_clean_artifact(...)`` counts: the point is that *a* call
    happens, not how it is spelled.
    """
    names: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            names.add(func.id)
        elif isinstance(func, ast.Attribute):
            names.add(func.attr)
    return names


def _function_node(module_name: str, function_name: str) -> ast.FunctionDef:
    module = __import__(module_name, fromlist=["_"])
    source = inspect.getsource(module)
    tree = ast.parse(source)
    head, _, method = function_name.partition(".")
    for node in ast.walk(tree):
        if method and isinstance(node, ast.ClassDef) and node.name == head:
            for child in node.body:
                if isinstance(child, ast.FunctionDef) and child.name == method:
                    return child
        if not method and isinstance(node, ast.FunctionDef) and node.name == function_name:
            return node
    raise AssertionError(f"{module_name}.{function_name} is no longer a plain function")


def _modules_calling_a_boundary_gate() -> set[str]:
    """Every ``mayhem.*`` module that *calls* one of :data:`BOUNDARY_FUNCTIONS`.

    Scans the installed source rather than a declared list, so the answer is a
    property of the code and not a copy of it. The defining module is not a match
    by construction: it declares these functions, it does not import them.
    """
    from pathlib import Path

    import mayhem.infra.secret_resolver as resolver_module

    # ``mayhem`` is a namespace package, so ``mayhem.__file__`` is None; anchor
    # on a module that definitely has one and walk up to the package root.
    package_root = Path(resolver_module.__file__).resolve().parent.parent
    found: set[str] = set()
    for path in sorted(package_root.rglob("*.py")):
        relative = path.relative_to(package_root).with_suffix("")
        dotted = ".".join(("mayhem", *relative.parts))
        if dotted.endswith(".__init__"):
            dotted = dotted[: -len(".__init__")]
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "mayhem.infra.secret_resolver":
                if {alias.name for alias in node.names} & set(BOUNDARY_FUNCTIONS):
                    found.add(dotted)
            elif isinstance(node, ast.Attribute) and node.attr in BOUNDARY_FUNCTIONS:
                found.add(dotted)
    return found


class TestTheGateCannotBeDeleted:
    """The static half of "unskippable".

    A behavioural negative control proves a gate fires *today*. It cannot prove
    the gate is still there tomorrow, and in this codebase it sometimes cannot
    prove it today either: ``write_evidence_file`` delegates to
    ``redact_envelope``, so deleting the file gate changes no observable behaviour
    while removing a real layer of the boundary. These tests read the source, so
    removing a call fails the suite whether or not another call happens to cover
    for it.
    """

    @pytest.mark.parametrize(
        ("module_name", "function_name", "required"),
        sorted(
            (module, function, gates)
            for (module, function), gates in BOUNDARY_CALL_SITES.items()
        ),
    )
    def test_every_write_entry_point_calls_the_gate(
        self, module_name: str, function_name: str, required: frozenset[str]
    ) -> None:
        called = _called_names(_function_node(module_name, function_name))
        missing = required - called
        assert not missing, (
            f"{module_name}.{function_name} no longer calls {sorted(missing)}; the "
            "evidence boundary is "
            "unskippable only while every write path calls it"
        )

    def test_every_module_calling_a_gate_is_registered(self) -> None:
        """Completeness, in the one direction that is decidable from source.

        The table above is hand-maintained, so "the listed gates are still called"
        says nothing about a path nobody listed. This closes the half of that
        hole a machine can close honestly: a module that *does* call a boundary
        gate has opted into the boundary, and an unlisted one means the table has
        drifted from the code — which is how a new write path escapes review.

        The other half is not decidable and is not faked here. Detecting a write
        path with no gate at all would need to decide "writes evidence" from source
        text, and the honest signal for that — a module issuing ``INSERT``
        against some table — matches roughly twenty modules of ordinary
        operational state (leases, KPIs, campaign rows, topology snapshots). An
        allowlist to exempt them would be the same hand-maintained table under a
        second name, so it would prove nothing. What it would produce is a green
        suite on a table that can still miss a path, which is worse than the named
        limitation. So: the gated-but-unregistered direction is enforced; the
        ungated direction is a reviewer obligation, stated here rather than
        simulated.
        """
        registered = {module for module, _ in BOUNDARY_CALL_SITES}
        unregistered = _modules_calling_a_boundary_gate() - registered
        assert not unregistered, (
            f"{sorted(unregistered)} call a boundary gate but have no "
            "BOUNDARY_CALL_SITES row, so the static conformance check does not "
            "cover them; add a row per write entry point or the table is a lie"
        )

    @pytest.mark.parametrize("name", BOUNDARY_FUNCTIONS)
    def test_a_gate_offers_no_opt_out_parameter(self, name: str) -> None:
        """No ``enabled=``, no ``guard=None``, no ``skip=``.

        A gate a caller can disable with a keyword is a gate whose enforcement is
        a decision, and the decision is exactly what this wave is closing.
        """
        import mayhem.infra.secret_resolver as resolver_module

        node = _function_node("mayhem.infra.secret_resolver", name)
        parameters = {
            argument.arg
            for argument in (*node.args.args, *node.args.kwonlyargs, *node.args.posonlyargs)
        }
        forbidden = {"enabled", "guard", "skip", "skip_gate", "check", "strict", "audit"}
        assert not parameters & forbidden, (
            f"{name} accepts {sorted(parameters & forbidden)}; a gate with an opt-out "
            "parameter is a convention, not a boundary"
        )
        assert resolver_module.__dict__[name].__module__ == "mayhem.infra.secret_resolver"

    def test_the_boundary_lives_in_one_module(self) -> None:
        """One import to audit, one place to route around."""
        import mayhem.infra.secret_resolver as resolver_module

        for name in BOUNDARY_FUNCTIONS:
            assert getattr(resolver_module, name).__module__ == "mayhem.infra.secret_resolver"

    def test_the_grade_rule_is_not_conditioned_on_the_registry(self) -> None:
        """The static form of "no active guard means no state, not no gate".

        If the grade check were inside ``if guards:``, deleting a registration
        would silently disable the structural rule too. The test asserts the call
        is unconditional in the source *and* observes it firing with an empty
        registry.
        """
        node = _function_node("mayhem.infra.secret_resolver", "require_persistable_document")
        conditional = [
            child
            for child in ast.walk(node)
            if isinstance(child, ast.If) and "require_persistable" in ast.unparse(child.test)
        ]
        assert conditional == [], (
            "the grade rule must run before any early return on the guard registry"
        )
        assert active_guards() == ()
        with pytest.raises(InvariantViolationError):
            require_persistable_document({"secret_value": "x"}, artifact="probe")


# --- Helpers --------------------------------------------------------------------


def _table_names(store: Store) -> set[str]:
    return {
        str(row["name"])
        for row in store.query("SELECT name FROM sqlite_master WHERE type='table'")
    }


def _audit_rows(store: Store) -> list[dict[str, object]]:
    return [dict(row) for row in store.query("SELECT * FROM audit_entries")]


def _audit_head_rows(store: Store) -> list[dict[str, object]]:
    return [dict(row) for row in store.query("SELECT * FROM audit_stream_heads")]


def _fixed_reading() -> AttestedTimestamp:
    """A deterministic reading, so an audit assertion is not wall-clock sensitive."""
    return AttestedTimestamp(
        wall_clock=NOW, monotonic_ns=0, uncertainty_ms=0.0, source="test"
    )


def _files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return sorted(path for path in directory.rglob("*") if path.is_file())
