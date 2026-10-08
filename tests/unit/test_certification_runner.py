"""Certification store, runner, and the negative controls that make them mean it.

Why this file exists
--------------------
Phase 2 landed a record store and a runner that can mint a ``verified-live``
claim. That is the most dangerous object in the repository, because unlike every
other rung it makes a claim about *the world* rather than about Mayhem's own
code, and unlike every other artifact a wrong one is invisible until someone is
relying on it. So the tests are written as three groups:

* **the store.** A record written is a record read back, byte-identical through
  the same validators that refused impossible records at construction. The
  migration goes down and comes back up, and the table is gone and then there.
  A store that cannot be rolled back is a store whose schema is permanent by
  accident.
* **the pipeline.** A record is minted from a **real** :class:`RunResult` — the
  actual dataclass the run engine returns, not a stand-in — and the checks that
  stand between a run and a claim are each exercised: recovery verification for
  a reversible fault, the residue scan, and automatic demotion when a re-run
  contradicts a claim already on file.
* **the negative controls.** Each of these is a way the certification could
  have been a rubber stamp, and each is asserted to *fail*:

  1. fabricated evidence cannot produce a certified record (the bundle's digests
     must equal the digests derived from the run's own facts);
  2. a reversible fault with no recovery evidence is refused;
  3. a catalog-only fault records a refusal rather than a pass;
  4. an expired claim stops counting, and the gate drops the reported level.

Two structural claims are pinned here as well, because they are the difference
between a certification pipeline and a parallel one: the runner may not import
``mayhem.controller`` (the layering contract forbids it, and a runner that
reached around the controller could bypass the run path), and re-certification
appends a new record instead of reviving a lapsed one.
"""

from __future__ import annotations

import ast
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from mayhem.controller.executor import RunResult, StepReport
from mayhem.domain.catalog import definition_for
from mayhem.domain.certification import (
    DEFAULT_CERTIFICATION_TTL,
    Arch,
    CellPrivilege,
    CertificationRecord,
    CertificationState,
    CertificationTransitionError,
    EvidenceBundleRef,
    MatrixCell,
    certify,
)
from mayhem.domain.errors import DomainError
from mayhem.domain.evidence import ActionOutcome
from mayhem.domain.experiments import (
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionPlan,
    ExecutionStep,
    ExperimentKind,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
    Wait,
)
from mayhem.domain.faults import EngineLane
from mayhem.domain.run_outcome import RunVerdict
from mayhem.domain.target import ResourceKind, RuntimeLabel, TargetScope
from mayhem.domain.topology import NodeKind, TargetSelector
from mayhem.infra.certification_repository import (
    CERTIFICATION_STATES,
    CertificationRepository,
    StoredCertification,
)
from mayhem.infra.certification_runner import (
    DEMOTION_DIGEST,
    CellRequest,
    CertificationAttempt,
    CertificationError,
    CertificationRequest,
    CertifiedRun,
    DemotionEvent,
    RecoveryEvidence,
    RecurrenceVerdict,
    RefusalClass,
    ResidueFinding,
    ResidueScan,
    certify_fault,
    effective_lanes,
    evidence_digest,
    expected_evidence_digests,
    planned_target_identity,
    requires_recovery_verification,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.promotion import (
    CERTIFICATION_RECORDED,
    REQUIRED_LIVE_ENGINES,
    EvidenceStore,
    build_probe,
    evaluate_maturity,
)
from mayhem.infra.store import Store

REPO_ROOT = Path(__file__).parents[2]
RUNNER_MODULE = REPO_ROOT / "src" / "mayhem" / "infra" / "certification_runner.py"
MIGRATION_MODULE = REPO_ROOT / "src" / "mayhem" / "infra" / "migrations.py"

#: The fault used for the happy paths: reversible, registered on docker and
#: podman, and *not* catalog-only.
FAULT_ID = "proc.pause"
#: A catalog-only entry: it refuses to execute, and that refusal is the claim.
CATALOG_ONLY_FAULT_ID = "process.startup_delay"

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
STEP_ID = "s1"


# ── fakes ───────────────────────────────────────────────────────────────────


def _cell(engine: EngineLane = EngineLane.DOCKER) -> MatrixCell:
    return MatrixCell(
        engine=engine,
        engine_version="27.1.1",
        os_distro="Alpine 3.20",
        kernel_version="6.6.13-0-lts",
        arch=Arch.AMD64,
        privilege=CellPrivilege.ROOT,
    )


def _plan(fault_id: str = FAULT_ID, params: dict[str, object] | None = None) -> ExecutionPlan:
    """A real frozen plan, compiled the way the planner would compile it."""
    scope = TargetScope(
        logical_id="testcase-api",
        runtime=RuntimeLabel.DOCKER,
        kind=ResourceKind.CONTAINER,
        authority={"container_name": "testcase-api"},
    )
    fault = PlannedFault(
        fault_id=fault_id,
        targets=(
            ResolvedTarget(
                selector=TargetSelector(kind=NodeKind.CONTAINER, expr="testcase-api"),
                node_ids=frozenset({"testcase-api"}),
            ),
        ),
        target=scope,
        params=dict(params or {}),
        duration="5.0s",
    )
    return ExecutionPlan(
        run_id="r-certify-test",
        kind=ExperimentKind.DRILL,
        steps=(
            PlannedStep(
                id=STEP_ID,
                seq=1,
                fault=fault,
                target=scope,
                raw_action=Wait(duration="5.0s"),
            ),
        ),
        config_snapshot_id="cfg-1",
        topology_snapshot_id="topo-1",
        environment_fingerprint="f" * 64,
    )


def _run(
    *,
    status: str = "completed",
    verdict: RunVerdict | None = RunVerdict.PASS,
    ok: bool = True,
    step_status: str = "compensated",
    outcome: ActionOutcome = ActionOutcome.COMPENSATED,
    detail: str = "proc.pause injected on testcase-api: undo: SIGCONT",
    dirty: tuple[str, ...] = (),
    with_step: bool = True,
) -> RunResult:
    """A real :class:`RunResult`, exactly the shape the run engine returns."""
    steps = (
        (StepReport(STEP_ID, ok, detail, status=step_status, measured={"injected": True}),)
        if with_step
        else ()
    )
    return RunResult(
        run_id="r-certify-test",
        status=status,
        started_at_epoch_s=NOW.timestamp(),
        ended_at_epoch_s=NOW.timestamp() + 1.0,
        steps=steps,
        dirty_leases=dirty,
        verdict=verdict,
    )


@dataclass
class FakeCell:
    """A disposable cell with no runtime behind it.

    Every field is a knob, so a test states the observation it wants rather than
    arranging a container. ``executed`` records that :meth:`execute` was reached
    at all, which is how the "never provisioned" refusals are distinguished from
    the ones that at least tried.
    """

    cell_value: MatrixCell = field(default_factory=_cell)
    injector: str = "1.0.0"
    run: RunResult = field(default_factory=_run)
    recovery: RecoveryEvidence | None = None
    residue: ResidueScan = field(default_factory=lambda: ResidueScan(performed=True))
    executed: int = 0
    disposed: int = 0

    @property
    def cell(self) -> MatrixCell:
        return self.cell_value

    @property
    def injector_version(self) -> str:
        return self.injector

    def execute(self, plan: ExecutionPlan) -> RunResult:
        del plan
        self.executed += 1
        return self.run

    def recovery_evidence(self, run: CertifiedRun) -> RecoveryEvidence | None:
        del run
        return self.recovery

    def residue_scan(self) -> ResidueScan:
        return self.residue

    def dispose(self) -> None:
        self.disposed += 1


@dataclass
class FakeProvisioner:
    cell: FakeCell = field(default_factory=FakeCell)
    provisioned: int = 0

    def provision(self, request: CertificationRequest) -> FakeCell:
        del request
        self.provisioned += 1
        return self.cell


@dataclass
class FakeCapturer:
    """Returns whatever bundle a test hands it, unmodified.

    A capturer that "fixed up" a bundle would make the fabrication control
    untestable, so this one is deliberately literal.
    """

    bundle: EvidenceBundleRef | None = None
    calls: int = 0

    def capture(
        self,
        run: CertifiedRun,
        *,
        request: CertificationRequest,
        cell: MatrixCell,
        plan: ExecutionPlan,
        residue: ResidueScan,
        recovery: RecoveryEvidence | None,
        demotions: tuple[DemotionEvent, ...] = (),
    ) -> EvidenceBundleRef | None:
        del run, request, cell, plan, residue, recovery, demotions
        self.calls += 1
        return self.bundle


class FakeSink:
    """An in-memory record store with the repository's append/transition split."""

    def __init__(self) -> None:
        self.rows: list[StoredCertification] = []

    def append(
        self,
        record: CertificationRecord,
        *,
        run_id: str = "",
        now: datetime | None = None,
    ) -> StoredCertification:
        del now
        sequence = 1 + sum(1 for row in self.rows if row.record.fault_id == record.fault_id)
        stored = StoredCertification(record=record, sequence=sequence, run_id=run_id)
        self.rows.append(stored)
        return stored

    def store_transition(
        self,
        stored: StoredCertification,
        record: CertificationRecord,
        *,
        now: datetime | None = None,
    ) -> StoredCertification:
        del now
        for index, row in enumerate(self.rows):
            if row is stored:
                self.rows[index] = StoredCertification(
                    record=record,
                    sequence=stored.sequence,
                    run_id=stored.run_id,
                    created_at=stored.created_at,
                    updated_at=stored.updated_at,
                )
                return self.rows[index]
        raise AssertionError("transition over a row that is not there")

    def latest_on_cell(self, fault_id: str, cell: MatrixCell) -> StoredCertification | None:
        for row in reversed(self.rows):
            if row.record.fault_id == fault_id and row.record.cell == cell:
                return row
        return None


#: The recovery a healthy cell reports: the undo ran and the probe came back to
#: where it started. Defined at module scope because it is also the default the
#: bundle factory needs, and a default is evaluated at definition time.
_GOOD_RECOVERY = RecoveryEvidence(
    probe="lease.released", baseline=0.0, observed=0.0, tolerance=0.0, undo_ran=True
)


def _honest_bundle(
    *,
    plan: ExecutionPlan | None = None,
    recovery: RecoveryEvidence | None = _GOOD_RECOVERY,
    residue: ResidueScan | None = None,
    demotions: tuple[DemotionEvent, ...] = (),
    compensated: bool = True,
) -> EvidenceBundleRef:
    """A bundle whose digests are the ones this run actually earns.

    Built with the same public function the runner uses, from the same facts, so
    a positive test proves the cross-check *agrees* rather than proving the
    cross-check is absent. ``recovery`` defaults to a healthy probe because a
    bundle that describes a different recovery than the cell reported is, by
    construction, a bundle that does not match.
    """
    plan = _plan() if plan is None else plan
    digests = expected_evidence_digests(
        params={},
        target=planned_target_identity(plan.steps[0].fault.target),  # type: ignore[union-attr]
        observed_effect=(
            f"{definition_for(FAULT_ID).observable_effect}"
            f"|observed=proc.pause injected on testcase-api: undo: SIGCONT"
        ),
        recovery=recovery,
        residue=residue if residue is not None else ResidueScan(performed=True),
        demotions=demotions,
        compensated=compensated,
    )
    return EvidenceBundleRef(
        bundle_hash=evidence_digest("bundle", digests),
        mayhem_version="1.0.0",
        digests=digests,
    )


def _good_recovery() -> RecoveryEvidence:
    return _GOOD_RECOVERY


class FaithfulCapturer:
    """Derives the bundle from the arguments, exactly as the live capturer does.

    Used where the bundle cannot be pre-built — the demotion case, because only
    the attempt knows which event it is recording. A capturer that derived its
    digests this way agrees with the runner when the run was honest, and
    disagrees when it was not, which is the property the cross-check exists for.
    """

    calls: int = 0
    bundle_path: str | None = None

    def capture(
        self,
        run: CertifiedRun,
        *,
        request: CertificationRequest,
        cell: MatrixCell,
        plan: ExecutionPlan,
        residue: ResidueScan,
        recovery: RecoveryEvidence | None,
        demotions: tuple[DemotionEvent, ...] = (),
    ) -> EvidenceBundleRef | None:
        self.calls += 1
        step_id, target, params = next(
            (
                step.id,
                planned_target_identity(step.fault.target),
                dict(step.fault.params),
            )
            for step in plan.steps
            if step.fault is not None and step.fault.fault_id == request.fault_id
        )
        detail = next((report.detail for report in run.steps if report.step_id == step_id), "")
        digests = expected_evidence_digests(
            params=params,
            target=target,
            observed_effect=f"{definition_for(request.fault_id).observable_effect}"
            f"|observed={detail}",
            recovery=recovery,
            residue=residue,
            demotions=demotions,
            compensated=not run.dirty_leases,
        )
        del cell
        return EvidenceBundleRef(
            bundle_hash=evidence_digest("bundle", digests),
            mayhem_version="1.0.0",
            digests=digests,
            bundle_path=self.bundle_path,
        )


def _request(
    *,
    fault_id: str = FAULT_ID,
    cell: CellRequest | None = None,
    params: dict[str, object] | None = None,
) -> CertificationRequest:
    return CertificationRequest(
        fault_id=fault_id,
        cell=cell
        or CellRequest(
            engine=EngineLane.DOCKER,
            engine_version="27.1.1",
            os_distro="Alpine 3.20",
            kernel_version="6.6.13-0-lts",
            arch=Arch.AMD64,
            privilege=CellPrivilege.ROOT,
        ),
        params=params if params is not None else {},
        target="testcase-api",
        injector_version="1.0.0",
    )


def _attempt(
    *,
    cell: FakeCell | None = None,
    bundle: EvidenceBundleRef | None = None,
    capturer: FakeCapturer | None = None,
    sink: FakeSink | None = None,
    request: CertificationRequest | None = None,
    now: datetime = NOW,
) -> tuple[CertificationAttempt, FakeCell, FakeProvisioner, FakeSink]:
    cell = cell if cell is not None else FakeCell(recovery=_good_recovery())
    provisioner = FakeProvisioner(cell=cell)
    capture = capturer if capturer is not None else FakeCapturer(bundle=bundle)
    store = sink if sink is not None else FakeSink()
    attempt = certify_fault(
        request if request is not None else _request(),
        provisioner=provisioner,
        compile_plan=lambda _request: _plan(),
        capture=capture,
        sink=store,
        now=now,
    )
    return attempt, cell, provisioner, store


def _migrated() -> tuple[Store, CertificationRepository]:
    store = Store.open_migrated(":memory:")
    return store, CertificationRepository(store)


def _pending(fault_id: str = FAULT_ID, cell: MatrixCell | None = None) -> CertificationRecord:
    return CertificationRecord(
        fault_id=fault_id,
        cell=cell or _cell(),
        injector_version="1.0.0",
        expires_at=NOW + DEFAULT_CERTIFICATION_TTL,
    )


# ── the store ───────────────────────────────────────────────────────────────


def test_record_round_trips_through_the_store() -> None:
    """What is written is what is read, through the same validators."""
    store, repository = _migrated()
    try:
        record = _pending()
        stored = repository.append(record, run_id="r-1", now=NOW)
        assert stored.sequence == 1
        assert stored.run_id == "r-1"

        loaded = repository.load(FAULT_ID)
        assert len(loaded) == 1
        assert loaded[0].record == record
        assert repository.latest(FAULT_ID) is not None
        assert repository.latest(FAULT_ID).record.fault_id == FAULT_ID  # type: ignore[union-attr]
        assert repository.latest_on_cell(FAULT_ID, _cell()) is not None
        assert repository.latest_on_cell(FAULT_ID, _cell(EngineLane.PODMAN)) is None
    finally:
        store.close()


def test_store_is_a_sequence_per_fault_not_a_mutable_row() -> None:
    """Re-certification appends. A lapsed claim is never revived in place."""
    store, repository = _migrated()
    try:
        first = repository.append(_pending(), now=NOW)
        second = repository.append(_pending(), now=NOW)
        assert (first.sequence, second.sequence) == (1, 2)
        assert [row.sequence for row in repository.load(FAULT_ID)] == [1, 2]

        # The illegal move is reviving an earned claim. Once sequence 1 is
        # certified it is not pending any more, so certifying *it* again — the
        # tempting "just re-run and overwrite" — is refused by the domain, and
        # the only way forward is sequence 2.
        certified = certify(
            first.record, at=NOW, evidence=(_honest_bundle(),), outcome="certified once"
        )
        repository.store_transition(first, certified, now=NOW)
        with pytest.raises(CertificationTransitionError):
            certify(certified, at=NOW, evidence=(_honest_bundle(),), outcome="again")
        assert repository.load(FAULT_ID)[1].record.state is CertificationState.PENDING
    finally:
        store.close()


def test_store_transition_refuses_to_move_identity() -> None:
    """A transition changes state; a different cell is a different record."""
    store, repository = _migrated()
    try:
        stored = repository.append(_pending(), now=NOW)
        with pytest.raises(ValueError, match="moves identity"):
            repository.store_transition(stored, _pending(cell=_cell(EngineLane.PODMAN)))
        with pytest.raises(ValueError, match="not there"):
            repository.store_transition(
                StoredCertification(
                    record=stored.record, sequence=99, run_id="", created_at="", updated_at=""
                ),
                stored.record,
            )
    finally:
        store.close()


def test_store_transition_persists_a_demotion_in_place() -> None:
    from mayhem.domain.certification import mark_failed

    store, repository = _migrated()
    try:
        stored = repository.append(_pending(), now=NOW)
        demoted = mark_failed(stored.record, reason="recovery regressed on re-run")
        written = repository.store_transition(stored, demoted, now=NOW)
        assert written.sequence == 1
        rows = repository.load(FAULT_ID)
        assert len(rows) == 1
        assert rows[0].record.state is CertificationState.FAILED
        assert rows[0].record.reason == "recovery regressed on re-run"
    finally:
        store.close()


def test_delete_removes_the_claim_and_the_gate_follows() -> None:
    """The negative control Phase 1 promised, made executable."""
    store, repository = _migrated()
    try:
        _certify_on_every_required_engine(repository)
        decision = _decision(repository, fault_id=FAULT_ID)
        assert not decision.live_verified, (
            "run evidence alone is not a certification; a full engine matrix is "
            "still required by the ladder's other rungs"
        )
        assert repository.delete_fault(FAULT_ID) == len(REQUIRED_LIVE_ENGINES)
        assert repository.load(FAULT_ID) == ()
        assert repository.certification_gate() == {}
    finally:
        store.close()


def test_migration_0024_is_contiguous_and_reversible() -> None:
    """24 is the reserved id, the chain stays contiguous, and the table comes back.

    The chain is asserted as ``1..N`` rather than as ending at 24, because other
    v1.1.0 lanes append their own migrations above this one; what must never
    change is that this migration is present, is 24, and is reversible.
    """
    versions = [migration.version for migration in ALL_MIGRATIONS]
    assert versions == list(range(1, len(versions) + 1))
    assert 24 in versions
    assert len(versions) == len(set(versions)), "no duplicate migration versions"
    migration = next(m for m in ALL_MIGRATIONS if m.version == 24)
    assert migration.migration_id == "0024_certification_records"
    assert migration.down_statements, "an additive migration must be reversible"
    assert any("certification_records" in statement for statement in migration.statements)

    head = len(ALL_MIGRATIONS)
    store = Store.open_migrated(":memory:")
    try:
        assert store.schema_version == head
        tables = {
            str(row[0])
            for row in store.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        assert "certification_records" in tables

        repository = CertificationRepository(store)
        repository.append(_pending(), now=NOW)
        assert len(repository.load(FAULT_ID)) == 1

        # Down: the table and its data go, and so does the migration row.
        store.migrate_down(23)
        assert store.schema_version == 23
        assert not list(
            store.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='certification_records'"
            )
        )

        # Up again: recreated empty, ready for the next attempt.
        assert "0024_certification_records" in store.migrate()
        assert store.schema_version == head
        assert CertificationRepository(store).load(FAULT_ID) == ()
    finally:
        store.close()


def test_name_snapshot_records_this_migration() -> None:
    """The additive-schema snapshot is append-only, so ours must be in it."""
    assert "certification_records" in [m.name for m in ALL_MIGRATIONS]
    snapshot = Path(__file__).with_name("test_additive_schema.py").read_text(encoding="utf-8")
    assert '"certification_records",' in snapshot, (
        "certification_records is missing from NAME_SNAPSHOT in test_additive_schema.py; "
        "the documented append-only procedure requires appending it"
    )


def test_state_check_constraint_matches_the_domain_states() -> None:
    """The SQL CHECK and the domain enum cannot drift into two vocabularies."""
    from mayhem.domain.certification import CertificationState as DomainStates

    assert tuple(state.value for state in DomainStates) == CERTIFICATION_STATES

    store = Store.open_migrated(":memory:")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            with store.write() as conn:
                conn.execute(
                    "INSERT INTO certification_records (fault_id, sequence, cell_label, "
                    "cell_fingerprint, engine, state, record_json, created_at, updated_at) "
                    "VALUES ('proc.pause', 1, 'c', 'f', 'docker', 'imaginary', '{}', '', '')"
                )
    finally:
        store.close()


# ── the gate ────────────────────────────────────────────────────────────────


def _decision(
    repository: CertificationRepository, *, fault_id: str = FAULT_ID, now: datetime = NOW
):
    definition = definition_for(fault_id)
    probe = build_probe(
        definition,
        executor_registered=lambda _id: True,
        compensation_registered=lambda _id: True,
        unit_evidence=("unit",),
    )
    return evaluate_maturity(
        definition,
        probe=probe,
        store=EvidenceStore(),
        records=repository.certification_gate(now=now),
    )


def _record_for(fault_id: str, engine: EngineLane) -> CertificationRecord:
    """One certified claim, on one engine's cell."""
    record = CertificationRecord(
        fault_id=fault_id,
        cell=_cell(engine),
        injector_version="1.0.0",
        expires_at=NOW + DEFAULT_CERTIFICATION_TTL,
    )
    return certify(
        record,
        at=NOW,
        evidence=(_honest_bundle(),),
        outcome="certified on a real cell",
    )


def _certify_on_every_required_engine(
    repository: CertificationRepository, fault_id: str = FAULT_ID
) -> None:
    """Store a claim on each of :data:`REQUIRED_LIVE_ENGINES` — a different cell each."""
    for engine in REQUIRED_LIVE_ENGINES:
        repository.append(_record_for(fault_id, engine), now=NOW)


def test_gate_is_armed_by_an_empty_mapping_not_by_none() -> None:
    """``{}`` caps the level; ``None`` is the caller's statement it is not using it."""
    definition = definition_for(FAULT_ID)
    probe = build_probe(
        definition,
        executor_registered=lambda _id: True,
        compensation_registered=lambda _id: True,
        unit_evidence=("unit",),
    )
    store, repository = _migrated()
    try:
        ungated = evaluate_maturity(definition, probe=probe, records=None)
        assert ungated.maturity.value in {"verified-unit", "experimental"}

        gated = evaluate_maturity(definition, probe=probe, records={})
        assert gated.maturity.value in {"experimental", "verified-unit"}
        assert any(CERTIFICATION_RECORDED in refusal for refusal in gated.refusals)

        _certify_on_every_required_engine(repository)
        certified = evaluate_maturity(
            definition, probe=probe, records=repository.certification_gate(now=NOW)
        )
        assert not [
            outcome
            for outcome in certified.outcomes
            if outcome.name == CERTIFICATION_RECORDED and not outcome.met
        ]
    finally:
        store.close()


def test_a_single_engine_record_does_not_certify_the_required_matrix() -> None:
    """``verified-live`` needs every required engine, and the refusal says which."""
    store, repository = _migrated()
    try:
        repository.append(_record_for(FAULT_ID, EngineLane.DOCKER), now=NOW)
        decision = _decision(repository)
        gate = [
            outcome
            for outcome in decision.outcomes
            if outcome.name == CERTIFICATION_RECORDED and not outcome.met
        ]
        assert gate, decision.refusals
        assert REQUIRED_LIVE_ENGINES[1].value in gate[0].observed
    finally:
        store.close()


def test_expiry_demotes_and_the_gate_stops_counting_the_record() -> None:
    """A lapsed claim is not evidence, and no sweep is needed to stop it."""
    store, repository = _migrated()
    try:
        _certify_on_every_required_engine(repository)
        later = NOW + DEFAULT_CERTIFICATION_TTL + timedelta(hours=1)
        gate = repository.certification_gate(now=later)
        stale = gate[FAULT_ID]
        assert all(record.state is CertificationState.STALE for record in stale)
        assert not any(record.grants_live_verification for record in stale)
        assert repository.live_records(now=later) == ()

        decision = _decision(repository, now=later)
        assert decision.maturity.value != "stable"
        assert any(CERTIFICATION_RECORDED in refusal for refusal in decision.refusals)
        # The stored rows are untouched by a read: ageing is not a mutation.
        assert all(
            row.record.state is CertificationState.CERTIFIED for row in repository.load(FAULT_ID)
        )
    finally:
        store.close()


def test_expire_all_persists_what_a_read_only_gate_computed() -> None:
    store, repository = _migrated()
    try:
        _certify_on_every_required_engine(repository)
        later = NOW + DEFAULT_CERTIFICATION_TTL + timedelta(hours=1)
        changed = repository.expire_all(now=later)
        assert [row.record.state for row in changed] == [CertificationState.STALE] * len(
            REQUIRED_LIVE_ENGINES
        )
        assert all(
            row.record.state is CertificationState.STALE for row in repository.load(FAULT_ID)
        )
        assert all("lapsed" in row.record.reason for row in repository.load(FAULT_ID))
    finally:
        store.close()


# ── the pipeline ────────────────────────────────────────────────────────────


def test_record_is_minted_from_a_real_run_result() -> None:
    """The happy path, end to end, on the actual ``RunResult`` dataclass."""
    bundle = _honest_bundle(recovery=_good_recovery())
    attempt, cell, provisioner, store = _attempt(bundle=bundle)
    assert attempt.certified is True
    assert attempt.outcome.value == "certified"
    assert attempt.record.state is CertificationState.CERTIFIED
    assert attempt.record.certified_at == NOW
    assert attempt.record.expires_at == NOW + DEFAULT_CERTIFICATION_TTL
    assert attempt.record.evidence[0].bundle_hash == bundle.bundle_hash
    assert attempt.recurrence is RecurrenceVerdict.RECOVERED
    assert attempt.refusals == ()

    # The plan was compiled once, executed once, and the cell was disposed.
    assert provisioner.provisioned == 1
    assert cell.executed == 1
    assert cell.disposed == 1
    assert len(store.rows) == 1
    assert store.rows[0].run_id == "r-certify-test"


def test_a_failed_run_is_not_certified_and_records_why() -> None:
    cell = FakeCell(
        recovery=_good_recovery(),
        run=_run(status="failed", verdict=None, ok=False, outcome=ActionOutcome.FAILED),
    )
    attempt, _, _, store = _attempt(cell=cell, bundle=_honest_bundle())
    assert attempt.certified is False
    assert attempt.record.state is CertificationState.PENDING
    assert any(RefusalClass.RUN_FAILED.value in reason for reason in attempt.refusals)
    assert store.rows[0].record.outcome == "refused"


def test_a_run_with_no_step_for_the_fault_is_not_certified() -> None:
    cell = FakeCell(recovery=_good_recovery(), run=_run(with_step=False))
    attempt, _, _, _ = _attempt(cell=cell, bundle=_honest_bundle())
    assert attempt.certified is False
    assert any(RefusalClass.EFFECT_NOT_OBSERVED.value in r for r in attempt.refusals)


def test_a_failed_step_is_not_an_observed_effect() -> None:
    cell = FakeCell(
        recovery=_good_recovery(),
        run=_run(ok=False, step_status="failed_to_apply", outcome=ActionOutcome.REFUSED),
    )
    attempt, _, _, _ = _attempt(cell=cell, bundle=_honest_bundle())
    assert attempt.certified is False
    assert any(RefusalClass.EFFECT_NOT_OBSERVED.value in r for r in attempt.refusals)


def test_dirty_leases_refuse_and_are_reported() -> None:
    cell = FakeCell(recovery=_good_recovery(), run=_run(dirty=("lease-1",)))
    attempt, _, _, _ = _attempt(cell=cell, bundle=_honest_bundle())
    assert attempt.certified is False
    assert any("lease-1" in reason for reason in attempt.refusals)
    assert attempt.recurrence is RecurrenceVerdict.REGRESSED


# ── recovery verification ───────────────────────────────────────────────────


def test_recovery_verification_is_required_for_a_reversible_fault() -> None:
    assert requires_recovery_verification(definition_for(FAULT_ID)) is True
    with_recovery = _attempt(bundle=_honest_bundle(recovery=_good_recovery()))
    assert with_recovery[0].certified is True

    without = _attempt(cell=FakeCell(recovery=None), bundle=_honest_bundle())
    assert without[0].certified is False
    assert any(RefusalClass.RECOVERY_UNVERIFIED.value in reason for reason in without[0].refusals)


def test_recovery_that_drifted_past_tolerance_is_refused() -> None:
    drifted = RecoveryEvidence(
        probe="lease.released", baseline=0.0, observed=4.0, tolerance=0.0, undo_ran=True
    )
    attempt, _, _, _ = _attempt(
        cell=FakeCell(recovery=drifted), bundle=_honest_bundle(recovery=drifted)
    )
    assert attempt.certified is False
    assert any("did not restore the baseline" in reason for reason in attempt.refusals)
    assert attempt.recurrence is RecurrenceVerdict.REGRESSED


def test_recovery_within_tolerance_is_accepted() -> None:
    tolerant = RecoveryEvidence(
        probe="latency", baseline=100.0, observed=101.0, tolerance=2.0, undo_ran=True
    )
    assert tolerant.within_tolerance is True
    attempt, _, _, _ = _attempt(
        cell=FakeCell(recovery=tolerant), bundle=_honest_bundle(recovery=tolerant)
    )
    assert attempt.certified is True


def test_undo_that_never_ran_is_not_recovery_however_small_the_drift() -> None:
    """``undo_ran=False`` with ``observed == baseline`` is still a failure."""
    never = RecoveryEvidence(
        probe="lease.released", baseline=0.0, observed=0.0, tolerance=0.0, undo_ran=False
    )
    assert never.drift == 0.0
    assert never.within_tolerance is False
    attempt, _, _, _ = _attempt(
        cell=FakeCell(recovery=never), bundle=_honest_bundle(recovery=never)
    )
    assert attempt.certified is False


# ── the residue obligation ──────────────────────────────────────────────────


def test_a_residue_scan_that_was_not_performed_refuses_certification() -> None:
    cell = FakeCell(recovery=_good_recovery(), residue=ResidueScan(performed=False))
    attempt, _, _, _ = _attempt(cell=cell, bundle=_honest_bundle())
    assert attempt.certified is False
    assert any("not checked" in reason for reason in attempt.refusals)
    assert attempt.residue.performed is False


def test_residue_left_on_the_cell_refuses_certification_and_names_it() -> None:
    residue = ResidueScan(
        performed=True,
        findings=(ResidueFinding(kind="tc_rule", detail="netem on eth0"),),
    )
    cell = FakeCell(recovery=_good_recovery(), residue=residue)
    attempt, _, _, _ = _attempt(cell=cell, bundle=_honest_bundle(residue=residue))
    assert attempt.certified is False
    assert any("netem on eth0" in reason for reason in attempt.refusals)


def test_a_clean_scan_certifies() -> None:
    residue = ResidueScan(performed=True)
    assert residue.clean is True
    cell = FakeCell(recovery=_good_recovery(), residue=residue)
    attempt, _, _, _ = _attempt(cell=cell, bundle=_honest_bundle(residue=residue))
    assert attempt.certified is True


# ── regression demotion ─────────────────────────────────────────────────────


def test_recovery_regression_demotes_the_existing_claim_and_records_the_event() -> None:
    """The headline acceptance of plan 01 Phase 4, exercised end to end."""
    store = FakeSink()
    first = _attempt(bundle=_honest_bundle(recovery=_good_recovery()), sink=store)[0]
    assert first.certified is True
    assert store.rows[0].record.state is CertificationState.CERTIFIED

    drifted = RecoveryEvidence(
        probe="lease.released", baseline=0.0, observed=9.0, tolerance=0.0, undo_ran=True
    )
    second, _, _, _ = _attempt(
        cell=FakeCell(recovery=drifted),
        capturer=FaithfulCapturer(),
        sink=store,
        now=NOW + timedelta(days=1),
    )
    assert second.certified is False
    assert second.demotions, "a regression with a live claim on file must demote it"
    event = second.demotions[0]
    assert event.previous_sequence == 1
    assert event.previous_state == "certified"
    assert event.new_state == "failed"
    # The demotion travels in evidence: the refused record references a bundle
    # whose digests include one derived from the demotion event itself.
    assert second.record.evidence, "a demotion must be recorded in a sealed bundle"
    assert DEMOTION_DIGEST in second.record.evidence[0].digests
    assert second.record.grants_live_verification is False
    # The old claim is gone from the file; the new attempt is a new record.
    assert [row.record.state for row in store.rows] == [
        CertificationState.FAILED,
        CertificationState.PENDING,
    ]
    assert store.rows[0].record.state is not CertificationState.CERTIFIED


def test_a_regression_on_a_different_cell_does_not_demote() -> None:
    """Drift is a claim about *a* cell; a claim elsewhere is untouched."""
    store = FakeSink()
    _attempt(bundle=_honest_bundle(recovery=_good_recovery()), sink=store)
    podman = FakeCell(
        cell_value=_cell(EngineLane.PODMAN),
        recovery=RecoveryEvidence(
            probe="lease.released", baseline=0.0, observed=9.0, tolerance=0.0, undo_ran=True
        ),
    )
    second, _, _, _ = _attempt(cell=podman, sink=store, now=NOW + timedelta(days=1))
    assert second.demotions == ()
    assert store.rows[0].record.state is CertificationState.CERTIFIED


def test_a_regression_demotes_only_claims_that_still_grant_live_verification() -> None:
    store = FakeSink()
    stale_pending = _pending()
    store.append(stale_pending, now=NOW)
    drifted = RecoveryEvidence(
        probe="lease.released", baseline=0.0, observed=9.0, tolerance=0.0, undo_ran=True
    )
    second, _, _, _ = _attempt(
        cell=FakeCell(recovery=drifted),
        capturer=FaithfulCapturer(),
        sink=store,
    )
    assert second.demotions == ()
    assert store.rows[0].record.state is CertificationState.PENDING


# ── negative controls ───────────────────────────────────────────────────────


def test_fabricated_evidence_cannot_produce_a_certified_record() -> None:
    """A plausible-looking bundle that does not match the run is refused.

    The bundle below is well formed in every way the domain can check: a real
    sha256 hash, and every required digest present. What it is not is evidence
    *of this run*, and the digest cross-check is what notices.
    """
    fabricated = EvidenceBundleRef(
        bundle_hash="a" * 64,
        mayhem_version="1.0.0",
        digests={
            name: evidence_digest(name, "something that is not what happened")
            for name in ("params", "target", "observed_effect", "undo", "residue")
        },
    )
    attempt, _, _, store = _attempt(bundle=fabricated)
    assert attempt.certified is False
    assert attempt.record.state is CertificationState.PENDING
    assert any(RefusalClass.EVIDENCE_MISMATCH.value in r for r in attempt.refusals)
    assert "does not match what this run did" in attempt.record.reason
    assert store.rows[0].record.evidence == ()


def test_a_bundle_missing_a_required_digest_is_refused() -> None:
    partial = _honest_bundle(recovery=_good_recovery())
    pruned = EvidenceBundleRef(
        bundle_hash=partial.bundle_hash,
        mayhem_version=partial.mayhem_version,
        digests={
            name: value for name, value in partial.digests.items() if name != "observed_effect"
        },
    )
    attempt, _, _, _ = _attempt(bundle=pruned)
    assert attempt.certified is False
    assert any("has no observed_effect digest" in reason for reason in attempt.refusals)


def test_no_bundle_at_all_is_refused() -> None:
    attempt, _, _, _ = _attempt(capturer=FakeCapturer(bundle=None))
    assert attempt.certified is False
    assert any(RefusalClass.NO_EVIDENCE.value in reason for reason in attempt.refusals)


def test_a_certified_record_with_no_evidence_cannot_be_constructed() -> None:
    """The domain's own guard, restated: the shortcut does not exist at all."""
    with pytest.raises(ValidationError, match="no evidence bundle"):
        CertificationRecord(
            fault_id=FAULT_ID,
            cell=_cell(),
            injector_version="1.0.0",
            expires_at=NOW + DEFAULT_CERTIFICATION_TTL,
            state=CertificationState.CERTIFIED,
            outcome="looks fine",
            certified_at=NOW,
        )
    with pytest.raises(ValidationError, match="digest"):
        certify(
            _pending(),
            at=NOW,
            evidence=(
                EvidenceBundleRef(
                    bundle_hash="b" * 64,
                    mayhem_version="1.0.0",
                    digests={"params": "c" * 64},
                ),
            ),
            outcome="looks fine",
        )


def test_a_catalog_only_fault_records_a_refusal_rather_than_a_pass() -> None:
    """The negative verification the plan names, and it never provisions a cell."""
    provisioner = FakeProvisioner(cell=FakeCell(recovery=_good_recovery()))
    store = FakeSink()
    attempt = certify_fault(
        _request(fault_id=CATALOG_ONLY_FAULT_ID, params={}),
        provisioner=provisioner,
        compile_plan=lambda _request: _plan(CATALOG_ONLY_FAULT_ID),
        capture=FakeCapturer(bundle=_honest_bundle()),
        sink=store,
        now=NOW,
    )
    assert attempt.certified is False
    assert attempt.outcome.value == "refused"
    assert any(RefusalClass.CATALOG_ONLY.value in reason for reason in attempt.refusals)
    assert "readiness hook" in attempt.record.reason
    assert provisioner.provisioned == 0, "a catalog-only fault must not cost a runtime"
    assert len(store.rows) == 1, "the refusal must be recorded, not merely returned"
    assert store.rows[0].record.state is CertificationState.PENDING
    assert store.rows[0].record.evidence == ()
    assert attempt.record.grants_live_verification is False


def test_a_catalog_only_fault_is_never_promoted_even_if_a_bundle_is_offered() -> None:
    """No amount of well-formed evidence can certify a fault that refuses to run."""
    store = FakeSink()
    attempt = certify_fault(
        _request(fault_id=CATALOG_ONLY_FAULT_ID, params={}),
        provisioner=FakeProvisioner(cell=FakeCell(recovery=_good_recovery())),
        compile_plan=lambda _request: _plan(CATALOG_ONLY_FAULT_ID),
        capture=FakeCapturer(bundle=_honest_bundle()),
        sink=store,
        now=NOW,
    )
    gate = store.rows[0].record
    assert gate.state is not CertificationState.CERTIFIED
    assert not gate.grants_live_verification
    assert attempt.record.evidence == ()


def test_a_fault_the_cell_does_not_declare_is_refused_before_provisioning() -> None:
    provisioner = FakeProvisioner(cell=FakeCell(recovery=_good_recovery()))
    attempt = certify_fault(
        _request(cell=CellRequest(engine=EngineLane.KUBERNETES)),
        provisioner=provisioner,
        compile_plan=lambda _request: _plan(),
        capture=FakeCapturer(bundle=_honest_bundle()),
        sink=FakeSink(),
        now=NOW,
    )
    assert attempt.certified is False
    assert any(RefusalClass.ENGINE_LANE.value in reason for reason in attempt.refusals)
    assert provisioner.provisioned == 0


def test_an_unknown_fault_is_an_error_not_a_refusal() -> None:
    """A request the runner cannot interpret is raised; a refusal is a result."""
    with pytest.raises(CertificationError, match="not in catalog"):
        certify_fault(
            _request(fault_id="nope.not_a_fault"),
            provisioner=FakeProvisioner(),
            compile_plan=lambda _request: _plan(),
            capture=FakeCapturer(),
            sink=FakeSink(),
            now=NOW,
        )


def test_parameters_the_catalog_refuses_are_an_error() -> None:
    with pytest.raises(CertificationError, match=RefusalClass.INVALID_PARAMS.value):
        certify_fault(
            _request(params={"unknown_parameter": 1}),
            provisioner=FakeProvisioner(),
            compile_plan=lambda _request: _plan(),
            capture=FakeCapturer(),
            sink=FakeSink(),
            now=NOW,
        )


def test_the_cell_is_disposed_even_when_the_run_raises() -> None:
    """A disposable environment that leaks is worse than a failed certification."""

    class ExplodingCell(FakeCell):
        def execute(self, plan: ExecutionPlan) -> RunResult:
            del plan
            self.executed += 1
            raise RuntimeError("injected cell failure")

    cell = ExplodingCell()
    with pytest.raises(RuntimeError, match="injected cell failure"):
        certify_fault(
            _request(),
            provisioner=FakeProvisioner(cell=cell),
            compile_plan=lambda _request: _plan(),
            capture=FakeCapturer(),
            sink=FakeSink(),
            now=NOW,
        )
    assert cell.disposed == 1


# ── structural guards ───────────────────────────────────────────────────────


def test_runner_does_not_import_the_controller() -> None:
    """No side channel: the runner cannot reach the executor even by accident.

    The layering contract in ``pyproject.toml`` forbids ``infra`` importing
    ``controller``, but the import-linter check needs an extra dependency and
    does not run on every commit. The AST walk here does, and it also catches a
    *deferred* import inside a function, which is how such a bypass is usually
    written.
    """
    tree = ast.parse(RUNNER_MODULE.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    forbidden = [name for name in imported if name.startswith("mayhem.controller")]
    assert not forbidden, forbidden
    assert "subprocess" not in imported, "the runner must not shell out to a runtime"
    assert "mayhem.infra.store" not in imported, "the runner must not open a database"


def test_the_migration_is_appended_and_not_rewritten() -> None:
    """The append-only contract: 24 is last and its down path is complete."""
    text = MIGRATION_MODULE.read_text(encoding="utf-8")
    assert "M0024_CERTIFICATION_RECORDS = Migration(" in text
    assert text.count("M0024_CERTIFICATION_RECORDS") >= 2  # definition + ALL_MIGRATIONS
    assert text.index("M0024_CERTIFICATION_RECORDS = Migration(") < text.index(
        "ALL_MIGRATIONS: tuple[Migration, ...]"
    )


def test_every_digest_name_is_inside_its_hashed_bytes() -> None:
    """A digest for one claim cannot be presented as a digest for another."""
    assert evidence_digest("undo", {"a": 1}) != evidence_digest("residue", {"a": 1})
    digests = expected_evidence_digests(
        params={},
        target="",
        observed_effect="",
        recovery=None,
        residue=ResidueScan(performed=True),
    )
    assert set(digests) == {"params", "target", "observed_effect", "undo", "residue"}
    assert all(len(value) == 64 for value in digests.values())
    assert len(set(digests.values())) == len(digests), "distinct claims must hash apart"


def test_effective_lanes_drops_the_multi_engine_sentinel() -> None:
    """``multi-engine`` is a planning instruction, not a lane you can execute on."""
    lanes = effective_lanes(definition_for("dependency.malformed_response"))
    assert EngineLane.MULTI_ENGINE not in lanes
    assert EngineLane.DOCKER in lanes


# ── the catalog stays the source of truth ───────────────────────────────────


def test_certification_never_contradicts_the_catalog_definition() -> None:
    """A certified record names the fault, the injector, and the observed run.

    The declared effect itself is not copied into the record's ``outcome`` — it
    is hashed into the ``observed_effect`` digest instead, so the record carries
    a *reference* to the claim rather than a second, editable copy of it.
    """
    attempt, _, _, _ = _attempt(bundle=_honest_bundle(recovery=_good_recovery()))
    assert attempt.certified is True
    assert attempt.record.fault_id == FAULT_ID
    assert attempt.record.injector_version == "1.0.0"
    assert "r-certify-test" in attempt.record.outcome
    assert definition_for(attempt.fault_id).observable_effect not in attempt.record.outcome
    assert "observed_effect" in attempt.record.evidence[0].digests


def test_uncertified_fault_cannot_report_a_live_level() -> None:
    """The Phase 1 consequence, re-asserted through the store the CLI will read."""
    store, repository = _migrated()
    try:
        gate = repository.certification_gate(now=NOW)
        assert gate == {}
        decision = _decision(repository)
        assert decision.live_verified is False
        assert decision.maturity.value in {"experimental", "verified-unit"}
    finally:
        store.close()


# ── helpers that keep the fixtures honest ───────────────────────────────────


def test_fixture_helpers_agree_with_the_fixtures() -> None:
    """The fakes are built from real domain objects, not from shaped dicts."""
    plan = _plan()
    assert plan.steps[0].fault is not None
    assert plan.steps[0].fault.fault_id == FAULT_ID  # type: ignore[union-attr]
    run = _run()
    assert isinstance(run, RunResult)
    assert run.steps[0].outcome is ActionOutcome.COMPENSATED
    spec = DrillSpec(
        kind="drill",
        name="certify",
        containers={"c": DrillContainer(faults=(DrillFault(fault=FAULT_ID, duration="1.0s"),))},
        execution=(ExecutionStep(sequential=("c",)),),
    )
    assert spec.name == "certify"


def test_domain_error_base_is_reused() -> None:
    """Certification failures speak the repository's error vocabulary."""
    assert issubclass(CertificationError, DomainError)
    assert isinstance(CertificationError("x"), Exception)
