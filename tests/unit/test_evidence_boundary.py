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

The audit stream, and then attestation, replay and coverage
-----------------------------------------------------------

The same defect class has now recurred, so this suite names each recurrence rather
than letting the newest one be the only one described.

An integrator first reproduced it in ``AuditStream.record``: it persisted a
free-form ``AuditEntry.detail`` dict with no gate, so a resolved value reached
``audit_entries`` while a guard was active. An audit entry is evidence —
persisted, exported, and covered by the attestation and retention machinery — so
plan 12's "secrets must never enter evidence" binds it exactly as it binds the
envelope row. :class:`TestAuditStreamBoundary` attacks it the same way, with the
addition that ``detail`` is *free-form*: the planted value goes several levels
down, where no key name is graded ``secret`` and only the byte rule can see it.

The same reasoning then bound ``infra/attestation_store.py``: an attestation row
is persisted, exported, and read by the retention engine (which holds and
archives its manifests), so it is evidence too. All three of that module's
writers are gated — :func:`seal_run_evidence`, and both
``AttestationRepository`` writers — and
:class:`TestAttestationBoundary` proves each on its own, because a gate proved
only through the wrapper that happens to be its only caller today is not a gate
on the repository. A final sweep of the tree for persist paths then found two
more ungated evidence surfaces, both of which persist a caller-authored free-form
document: the replay capsule (``spec``/``plan``, the document an operator is
handed in order to reproduce a run) and the coverage observation (``verdict`` and
``metadata``). :class:`TestReplayAndCoverageBoundary` covers those.

Plan 03 then added a fifth surface, ``infra/fabric_journal.py``: the append-only
table every dispatch claim and settlement is journalled into. It is persisted,
replayed after a crash, and read back by the same export and retention machinery
that covers the audit stream, so the argument that binds those binds it — and its
one writer, :meth:`~mayhem.infra.fabric_journal.FabricJournalTable.append`, gates
the document the columns receive. What makes the recurrence worth naming is that
it arrived from a different direction again: not a new writer in a module the
boundary already knew about, but a brand-new module in ``infra`` whose *own*
docstring had already reasoned its way to ``require_persistable_document`` and then
registered nowhere. The completeness guard below caught it on its first run, which
is the only reason it is a row here rather than a report.

Then it happened three more times at once. ``infra/probe_seal_store.py`` (a
caller-authored document of redacted probe readings, sealed condition set and
citation verdicts) and ``infra/failover_store.py`` (two writers: a standby
registration and a promotion record, both of which name a control-plane term that
cannot be re-derived afterwards) each argued their way to
``require_persistable_document`` in their own docstrings and registered nowhere.
The pattern is now consistent enough to be worth stating as the rule rather than
as four anecdotes: **a new ``infra`` writer that persists a caller-supplied
document is evidence by default**, and reaching the right gate is the easy half —
the row is what makes the static conformance check cover it, and reaching the gate
without registering is what the completeness guard exists to catch.
:func:`TestTheGateCannotBeDeleted.test_every_module_calling_a_gate_is_registered`
caught all three on their first run and they are now three rows.

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

from mayhem.domain.approval import ApprovalState
from mayhem.domain.attestation import AttestedEvent, AttestedTimestamp, seal_events
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.evidence import EvidenceEnvelope, require_persistable_envelope
from mayhem.domain.evidence_bundle import build_bundle, verify_bundle
from mayhem.domain.policy import PolicyDecision
from mayhem.domain.redaction import redact_log_event
from mayhem.domain.replay import ReplayCapsule
from mayhem.domain.secrets import (
    EVIDENCE_FIELD_CLASSIFICATIONS,
    REFUSAL_SECRET_FIELD_PERSISTED,
    CredentialRef,
    CredentialScope,
    ScopeKind,
    SecretGrant,
    SecretProvider,
)
from mayhem.infra.attestation_store import (
    AttestationRepository,
    RunAuthorization,
    seal_run_evidence,
)
from mayhem.infra.audit_stream import (
    KIND_RUN_SEALED,
    AuditEntry,
    AuditStream,
    seal_run_evidence_at_run_close,
)
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.evidence import (
    build_evidence,
    redact_envelope,
    render_report,
    write_evidence,
    write_evidence_file,
)
from mayhem.infra.evidence_bundle_io import load_bundle, write_bundle
from mayhem.infra.replay_repository import ReplayRepository
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

    from mayhem.infra.attestation_store import SealedRun

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
ALICE = "svc:alice"
PROD = "prod-eu"
RUN_ID = "r-boundary-1"

#: The plan digest a hand-built authorization binds. Matches
#: :func:`_marked_envelope`'s ``plan_hash`` so the plan-pin check passes and the
#: *evidence boundary* is what refuses, not the authorization mismatch.
PLAN_DIGEST = "9" * 64

#: One coverage cell. Constant rather than per-test so a refusal can be asserted
#: against a key that is known in advance.
CELL = CoverageCell(
    target="db-1",
    fault_kind="latency",
    execution_context="steady",
    parameter_band="p50",
)

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


# --- Write path 2c: attestation, replay and coverage -----------------------------
#
# An attestation row is evidence: it is persisted, exported, and covered by the
# retention and audit machinery — ``infra.retention`` reads these manifests for
# legal holds and expiry and archives their bytes externally. So the rule that
# binds the envelope row binds these rows identically.
#
# Two of the three surfaces here are genuinely free-form, which is what the byte
# rule is for and why gating the envelope was never enough:
#
# * ``AttestedEvent.payload`` is ``dict[str, Any]`` by construction, so any chain
#   written through ``AttestationRepository.save_chain`` can carry a value under a
#   key name nobody graded;
# * ``RunAuthorization.payload`` carries ``approval_detail`` — the approver and
#   rule strings a *caller* supplies, which is the free-form half of a sealed run.
#
# The derived run-close events deliberately *reference* the envelope by digest
# rather than embedding it, so most of what ``seal_run_evidence`` persists has
# already been through the envelope boundary by the time it arrives. The gate
# there is what makes the guarantee hold anyway, and what stops a caller-built
# authorization payload from being the one hole left.


def _sealed_event(run_id: str, payload: dict[str, Any]) -> tuple[AttestedEvent, ...]:
    """A one-event sealed chain carrying ``payload`` — for the repository writers."""
    unsealed = AttestedEvent(
        event_id=f"{run_id}:probe",
        event_kind="evidence.recorded",
        run_id=run_id,
        sequence=0,
        payload=payload,
        recorded_at=_fixed_reading(),
    )
    return seal_events([unsealed])


def _authorization(detail: tuple[str, ...] = ()) -> RunAuthorization:
    """A passing authorization whose ``approval_detail`` is caller-supplied."""
    return RunAuthorization(
        policy_decision=PolicyDecision(
            outcome="allow",
            reasons=("production permits this fault family",),
            matched_rules=("prod.family.allow",),
            bundle_id="production",
            bundle_version=2,
            rule_digest="2" * 64,
            policy_digest="3" * 64,
            facts_digest="4" * 64,
        ),
        approval_state=ApprovalState(
            valid=True, approvers=("ana",), required=1, detail=detail
        ),
        plan_digest=PLAN_DIGEST,
        proof_digest="5" * 64,
    )


class TestAttestationBoundary:
    @staticmethod
    def _repository(store: Store) -> AttestationRepository:
        return AttestationRepository(store)

    def test_a_secret_classified_event_payload_is_refused_and_leaves_no_row(
        self, tmp_path: Path
    ) -> None:
        """The stateless half, on the surface that is free-form by construction."""
        store = Store.open_migrated(tmp_path / "mayhem.db")
        events = _sealed_event(RUN_ID, {"resolved_credentials": {"db": "x"}})
        with pytest.raises(InvariantViolationError) as excinfo:
            self._repository(store).save_chain(RUN_ID, events, sealed_at=NOW)
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        assert _attestation_event_rows(store) == []
        assert _attestation_chain_rows(store) == []
        store.close()

    def test_a_planted_signature_reason_is_refused_and_leaves_no_row(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """``save_manifest``'s other two columns are caller *parameters*.

        ``signature_state`` and ``signature_reason`` are passed in, not derived, so
        they are the free-form surface of this writer — the same argument
        ``SecretGrantRepository.save`` makes about a table with no value column.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        sealed = _ordinary_seal(store)
        with pytest.raises(InvariantViolationError) as excinfo:
            self._repository(store).save_manifest(
                sealed.manifest, signature_reason=f"unsigned; key rotated after {SECRET_VALUE}"
            )
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert SECRET_VALUE not in str(excinfo.value)
        assert len(_attestation_manifest_rows(store)) == 1, "the clean row must survive"
        store.close()

    def test_the_byte_rule_catches_a_value_nested_deep_in_an_event_payload(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """No key here is graded ``secret``, so only the byte rule can see it."""
        store = Store.open_migrated(tmp_path / "mayhem.db")
        planted = {
            "provider": {"stderr": f"FATAL: auth failed for {SECRET_VALUE}"},
            "attempts": [{"retry": f"still {SECRET_VALUE}"}],
        }
        events = _sealed_event(RUN_ID, planted)
        with pytest.raises(InvariantViolationError) as excinfo:
            self._repository(store).save_chain(RUN_ID, events, sealed_at=NOW)
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert SECRET_VALUE not in str(excinfo.value)
        assert _attestation_event_rows(store) == []
        store.close()

    def test_the_byte_rule_catches_a_planted_approver_detail(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """The real free-form surface of a sealed run: the authorization payload.

        ``RunAuthorization.payload`` copies ``ApprovalState.detail`` — caller
        strings — straight into the chain, so a value can reach an attested event
        without ever touching the envelope the chain references by digest.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        with pytest.raises(InvariantViolationError) as excinfo:
            seal_run_evidence(
                store,
                _marked_envelope(),
                run_status="completed",
                verdict="pass",
                recorded_at=_fixed_reading(),
                authorization=_authorization(
                    detail=(f"rotated after a failed attempt with {SECRET_VALUE}",)
                ),
            )
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert SECRET_VALUE not in str(excinfo.value)
        # Neither half of the seal may survive: the gate runs before the first
        # transaction, so there is no chain-without-manifest state to clean up.
        assert _attestation_event_rows(store) == []
        assert _attestation_manifest_rows(store) == []
        assert _attestation_chain_rows(store) == []
        store.close()

    def test_the_refusal_precedes_the_bytes_reaching_disk(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """Not merely "the row was rolled back": the needle is in no file at all."""
        database = tmp_path / "mayhem.db"
        store = Store.open_migrated(database)
        events = _sealed_event(RUN_ID, {"note": f"used {SECRET_VALUE}"})
        with pytest.raises(InvariantViolationError):
            self._repository(store).save_chain(RUN_ID, events, sealed_at=NOW)
        store.close()
        assert SECRET_VALUE.encode() not in database.read_bytes()

    def test_ordinary_attestation_still_seals_reloads_and_re_verifies(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """The positive control: a live guard must not cost a run its attestation."""
        store = Store.open_migrated(tmp_path / "mayhem.db")
        sealed = _ordinary_seal(store)
        assert sealed.completeness is not None
        assert sealed.completeness.mutating is False, "no mutating facts were recorded"
        assert sealed.complete, "a read-only run needs no authorization"
        repository = self._repository(store)
        reloaded = repository.load_chain(RUN_ID)
        assert [event.event_kind for event in reloaded] == [
            "evidence.recorded",
            "run.closed",
        ]
        verification = repository.verify_run_chain(RUN_ID)
        assert verification.valid, verification.errors
        stored_manifest = repository.load_manifest(f"{RUN_ID}:manifest")
        assert stored_manifest is not None
        assert stored_manifest.manifest_digest == sealed.manifest.manifest_digest
        assert repository.verify_stored_manifest(f"{RUN_ID}:manifest").valid
        store.close()

        reopened = Store(tmp_path / "mayhem.db")
        assert AttestationRepository(reopened).verify_run_chain(RUN_ID).valid
        reopened.close()

    def test_an_ordinary_authorization_still_seals_a_complete_chain(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        sealed = seal_run_evidence(
            store,
            _mutating_envelope(),
            run_status="completed",
            verdict="pass",
            recorded_at=_fixed_reading(),
            authorization=_authorization(),
        )
        assert sealed.complete
        assert len(sealed.events) == 4
        assert AttestationRepository(store).verify_run_chain(RUN_ID).valid
        store.close()

    def test_the_repository_writers_are_gated_without_the_seal_in_front_of_them(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """``save_chain`` is public API; ``seal_run_evidence`` is not its only caller.

        Asserted directly so the repository gate is proved on its own, rather than
        inherited from a wrapper that happens to be the only caller today.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        repository = self._repository(store)
        sealed = _ordinary_seal(store)

        # A clean chain, then a poisoned one on the same run: the refusal must
        # leave the previously sealed rows exactly as they were.
        assert repository.verify_run_chain(RUN_ID).valid
        poisoned = _sealed_event(RUN_ID, {"detail": f"used {SECRET_VALUE}"})
        with pytest.raises(InvariantViolationError):
            repository.save_chain(RUN_ID, poisoned, sealed_at=NOW)
        assert repository.verify_run_chain(RUN_ID).valid
        assert [event.event_kind for event in repository.load_chain(RUN_ID)] == [
            "evidence.recorded",
            "run.closed",
        ]
        assert sealed.manifest.manifest_id
        store.close()


class TestReplayAndCoverageBoundary:
    """The two surfaces the final sweep found ungated.

    Both persist a caller-authored free-form document: a replay capsule carries the
    run spec and plan an operator is handed in order to reproduce a run, and a
    coverage observation carries the verdict and metadata of what a run did.
    """

    @staticmethod
    def _capsule(**overrides: Any) -> ReplayCapsule:
        payload: dict[str, Any] = {
            "run_id": RUN_ID,
            "spec": {"fault": "pod-delete", "namespace": "prod"},
            "plan": {"steps": [{"id": "s1", "target": "db-1"}]},
            "fingerprints": {"environment": PROD},
            "digests": {"plan": "a" * 64},
        }
        payload.update(overrides)
        return ReplayCapsule(**payload)

    def test_a_secret_classified_capsule_is_refused_and_leaves_no_row(
        self, tmp_path: Path
    ) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        capsule = self._capsule(spec={"resolved_credentials": {"db": "x"}})
        with pytest.raises(InvariantViolationError) as excinfo:
            ReplayRepository(store).save(capsule)
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        assert store.query("SELECT * FROM replay_capsules") == []
        store.close()

    def test_a_planted_value_in_the_plan_is_refused(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        capsule = self._capsule(
            plan={"steps": [{"id": "s1", "note": f"rotate before {SECRET_VALUE}"}]}
        )
        with pytest.raises(InvariantViolationError) as excinfo:
            ReplayRepository(store).save(capsule)
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        assert store.query("SELECT * FROM replay_capsules") == []
        store.close()

    def test_an_ordinary_capsule_still_writes_and_reloads(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        ReplayRepository(store).save(self._capsule())
        loaded = ReplayRepository(store).load(RUN_ID)
        assert loaded is not None
        assert loaded.spec["fault"] == "pod-delete"
        assert loaded.digest() == self._capsule().digest()
        store.close()

    def test_a_secret_classified_coverage_observation_is_refused(
        self, tmp_path: Path
    ) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        with pytest.raises(InvariantViolationError) as excinfo:
            SQLiteCoverageRepository(store).record(
                CELL,
                CellState.COVERED,
                run_id=RUN_ID,
                verdict={"secret_value": SECRET_VALUE},
            )
        assert excinfo.value.rule == REFUSAL_SECRET_FIELD_PERSISTED
        assert store.query("SELECT * FROM m5_coverage") == []
        store.close()

    def test_a_planted_coverage_observation_is_refused_on_both_branches(
        self, tmp_path: Path, active_guard: SecretLeakGuard
    ) -> None:
        """``record`` writes on an insert *and* on an update branch; both are gated.

        The refusal must also leave a previously recorded row untouched — the
        second call here takes the update branch precisely to prove it.
        """
        store = Store.open_migrated(tmp_path / "mayhem.db")
        repository = SQLiteCoverageRepository(store)
        repository.record(CELL, CellState.COVERED, run_id=RUN_ID, verdict={"covered": True})
        planted = {"detail": f"provider stderr: used {SECRET_VALUE}"}
        with pytest.raises(InvariantViolationError) as excinfo:
            repository.record(CELL, CellState.FAILED, run_id="run-2", verdict=planted)
        assert excinfo.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT
        rows = store.query("SELECT run_id, verdict_json FROM m5_coverage WHERE cell_key = ?",
                           (CELL.key,))
        assert len(rows) == 1
        assert str(rows[0]["run_id"]) == RUN_ID
        store.close()

    def test_an_ordinary_coverage_observation_still_writes(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "mayhem.db")
        repository = SQLiteCoverageRepository(store)
        repository.record(
            CELL,
            CellState.COVERED,
            run_id=RUN_ID,
            verdict={"result_status": "completed", "verdict": "pass"},
            metadata={"note": "steady"},
        )
        rows = store.query(
            "SELECT run_id, verdict_json, extra_json FROM m5_coverage WHERE cell_key = ?",
            (CELL.key,),
        )
        assert len(rows) == 1
        assert json.loads(str(rows[0]["verdict_json"]))["verdict"] == "pass"
        assert json.loads(str(rows[0]["extra_json"]))["note"] == "steady"
        assert repository.cell_state(CELL) is CellState.COVERED
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
    ("mayhem.infra.attestation_store", "seal_run_evidence"): frozenset(
        {"require_persistable_document"}
    ),
    ("mayhem.infra.attestation_store", "AttestationRepository.save_chain"): frozenset(
        {"require_persistable_document"}
    ),
    ("mayhem.infra.attestation_store", "AttestationRepository.save_manifest"): frozenset(
        {"require_persistable_document"}
    ),
    ("mayhem.infra.replay_repository", "ReplayRepository.save"): frozenset(
        {"require_persistable_document"}
    ),
    ("mayhem.infra.coverage_repository", "SQLiteCoverageRepository.record"): frozenset(
        {"require_persistable_document"}
    ),
    # Plan 03's execution-fabric journal is the fourth recurrence of this defect
    # class and lands in infra rather than the controller layer, so it arrives here
    # with no route from the module it lives in to the reasoning above: an
    # append-only journal of every dispatch claim and settlement is persisted,
    # replayed, and read back by exactly the machinery that covers the audit
    # stream, so it is evidence by the same argument. Its only writer is
    # ``FabricJournalTable.append`` — ``rows``/``count`` are readers — so one row
    # is the complete set for this module, and adding a second writer later fails
    # the guard above rather than passing on a partially registered module.
    ("mayhem.infra.fabric_journal", "FabricJournalTable.append"): frozenset(
        {"require_persistable_document"}
    ),
    # Three more modules joined ``infra`` in the same wave, and all three reached
    # for the same reason: their writer persists a *caller-authored free-form
    # document* into a row that is exported and read back by the retention
    # machinery, which is the argument that bound the audit stream. Each reasoned
    # its way to ``require_persistable_document`` in its own module docstring and
    # then registered nowhere, so all three arrived here together as one
    # completeness-guard failure rather than three.
    #
    # They are one row each, per write entry point, which is what makes the table
    # checkable entry by entry. ``probe_seal_store`` and ``failover_store`` each
    # hold exactly one writer; ``failover_store`` holds *two*, so it contributes
    # two rows and deleting either one now fails the guard rather than leaving a
    # row behind that no longer describes anything.
    ("mayhem.infra.probe_seal_store", "ProbeSealTable.seal"): frozenset(
        {"require_persistable_document"}
    ),
    ("mayhem.infra.failover_store", "FailoverPromotionStore.register_standby"): frozenset(
        {"require_persistable_document"}
    ),
    ("mayhem.infra.failover_store", "FailoverPromotionStore.record_promotion"): frozenset(
        {"require_persistable_document"}
    ),
    # Plan 13's game-day evidence: ``controller/game_day_evidence.py``'s
    # ``record_artifact`` and ``infra/schedule_store.py``'s ``record_tick`` both
    # write through ``Store.save_observation``, and neither call site was inside
    # the boundary. One row, because there is one function: registering only the
    # game-day caller would have left ``record_tick`` outside the boundary while
    # the table claimed to cover ``save_observation``. Two rows for two callers
    # would have been the dishonest granularity — one is what the code is.
    ("mayhem.infra.store", "Store.save_observation"): frozenset(
        {"require_persistable_document"}
    ),
    # Plan 23 Phase 4's benchmark and metering records. A published benchmark and
    # a run's metering series are both caller-authored documents destined for
    # storage and for comparison across releases, which is the same argument that
    # bound every row above. It is **one** row rather than two because both seal
    # functions route through a single ``_require_bound_digest`` helper, and that
    # helper is what calls the gates: registering the two callers instead would
    # have described a call graph the code does not have, and the guard would
    # have reported the real function as unregistered. One row is what the code
    # is; a future second writer that bypasses the helper fails the guard rather
    # than passing on a partially registered module.
    ("mayhem.infra.metering", "_require_bound_digest"): frozenset(
        {"require_persistable_document", "require_clean_artifact"}
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


def _gate_calling_functions() -> set[tuple[str, str]]:
    """Every ``(module, function)`` in ``mayhem`` that *calls* a boundary gate.

    Scans the installed source rather than a declared list, so the answer is a
    property of the code and not a copy of it.

    The unit is the *function*, not the module, and that is deliberate.
    ``mayhem.infra.attestation_store`` alone has three gated writers, and under a
    module-granular check deleting one of the three table rows still leaves the
    module registered — the guard would pass on a row that no longer describes
    anything. One row per write entry point is what makes the table checkable
    entry by entry.
    """
    from pathlib import Path

    import mayhem.infra.secret_resolver as resolver_module

    # ``mayhem`` is a namespace package, so ``mayhem.__file__`` is None; anchor
    # on a module that definitely has one and walk up to the package root.
    package_root = Path(resolver_module.__file__).resolve().parent.parent
    found: set[tuple[str, str]] = set()
    for path in sorted(package_root.rglob("*.py")):
        relative = path.relative_to(package_root).with_suffix("")
        dotted = ".".join(("mayhem", *relative.parts))
        if dotted.endswith(".__init__"):
            dotted = dotted[: -len(".__init__")]
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not _calls_a_boundary_gate(node):
                continue
            name = _enclosing_names(node, tree)
            if dotted == resolver_module.__name__ and name in BOUNDARY_FUNCTIONS:
                # A gate delegating to another gate is one implementation of one
                # boundary, not a second write path. Excluded by name rather than
                # by module, because that same module also holds
                # ``SecretGrantRepository.save``, which *is* a write path.
                continue
            found.add((dotted, name))
    return found


def _calls_a_boundary_gate(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether this definition calls one of :data:`BOUNDARY_FUNCTIONS`."""
    return bool(_called_names(node) & set(BOUNDARY_FUNCTIONS))


def _enclosing_names(
    node: ast.FunctionDef | ast.AsyncFunctionDef, tree: ast.Module
) -> str:
    """``name`` for a module function, ``Class.name`` for a direct method.

    The same spelling :data:`BOUNDARY_CALL_SITES` and :func:`_function_node` use,
    so the completeness check and the conformance check agree on what a row names.
    A gate call from anywhere else — a nested function, a closure, a comprehension
    body — gets a name the table cannot spell, so it is reported unspellable and
    fails loudly rather than matching a row it was never covered by.
    """
    for candidate in tree.body:
        if isinstance(candidate, ast.FunctionDef) and candidate is node:
            return node.name
        if isinstance(candidate, ast.ClassDef) and any(child is node for child in candidate.body):
            return f"{candidate.name}.{node.name}"
    return f"{node.name} (not a plain function or method)"


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
        hole a machine can close honestly: a function that *does* call a boundary
        gate has opted into the boundary, and an unregistered one means the table
        has drifted from the code — which is how a new write path escapes review.

        The unit is the write entry point, not its module. ``attestation_store``
        has three gated writers, and a module-granular check would stay green after
        one of the three rows was deleted — the guard would pass on a row that no
        longer describes anything. Deleting any single row now fails here.

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
        registered = set(BOUNDARY_CALL_SITES)
        unregistered = _gate_calling_functions() - registered
        assert not unregistered, (
            f"{sorted(unregistered)} call a boundary gate but have no "
            "BOUNDARY_CALL_SITES row, so the static conformance check does not "
            "cover them; add a row per write entry point or the table is a lie"
        )
        stale = registered - _gate_calling_functions()
        assert not stale, (
            f"{sorted(stale)} have a BOUNDARY_CALL_SITES row but no longer call a "
            "boundary gate, so the table claims coverage that does not exist; "
            "delete the row or restore the gate"
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


def _attestation_event_rows(store: Store) -> list[dict[str, object]]:
    return [dict(row) for row in store.query("SELECT * FROM attestation_events")]


def _attestation_chain_rows(store: Store) -> list[dict[str, object]]:
    return [dict(row) for row in store.query("SELECT * FROM attestation_chains")]


def _attestation_manifest_rows(store: Store) -> list[dict[str, object]]:
    return [dict(row) for row in store.query("SELECT * FROM attestation_manifests")]


def _fixed_reading() -> AttestedTimestamp:
    """A deterministic reading, so an audit assertion is not wall-clock sensitive."""
    return AttestedTimestamp(
        wall_clock=NOW, monotonic_ns=0, uncertainty_ms=0.0, source="test"
    )


def _marked_envelope() -> EvidenceEnvelope:
    """``ordinary_envelope`` with the redaction marker a seal requires.

    Every real seal path redacts first, so every attestation test here does too:
    an envelope with no marker is refused by ``_redaction_policy``, which is a
    different gate and not the one under test.
    """
    return redact_envelope(
        ordinary_envelope().model_copy(update={"plan_hash": PLAN_DIGEST})
    )


def _mutating_envelope() -> EvidenceEnvelope:
    """The marked envelope plus the two facts that make the run mutating.

    A mutating run's chain must carry its authorization, so this is the envelope
    the complete-chain positive control seals.
    """
    marked = _marked_envelope()
    return marked.model_copy(
        update={
            "action_outcomes": ("applied",),
            "execution_intent": {"actor": ALICE},
        }
    )


def _ordinary_seal(store: Store) -> SealedRun:
    """Seal the ordinary marked envelope: the positive control's setup."""
    return seal_run_evidence(
        store,
        _marked_envelope(),
        run_status="completed",
        verdict="pass",
        recorded_at=_fixed_reading(),
        created_at=_fixed_reading(),
    )


def _files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return sorted(path for path in directory.rglob("*") if path.is_file())
