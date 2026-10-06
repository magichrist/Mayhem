"""``mayhem certify``: the command surface, its JSON, and what it refuses.

What this file is for
---------------------
The certification surface is the only place a ``verified-live`` claim can be
earned, so its *refusals* matter more than its successes. The tests are grouped
accordingly:

* **the surface.** ``certify`` exists, is registered in the single inventory,
  resolves by prefix, and every sub-command's ``--help`` renders. A command that
  drifts out of the registry is a command nobody is reviewing.
* **the honest default.** On a fresh database ``certify matrix`` reports zero
  certified faults, and every maturity it reports is at or below
  ``verified-unit``. Nothing seeds a record, so the README's 0-of-N (N being
  the live catalogue size) stays true. This is the assertion that keeps the
  release honest while the pipeline is still being built out.
* **the gate is armed, not optional.** Every maturity this surface prints is
  computed with the record store supplied. The test proves the *arming* by
  planting a record and watching the answer change, and proves the shape by
  checking the payload says so.
* **no execution for a question.** ``certify matrix`` answers a compatibility
  question without provisioning anything, and says ``unknown`` about
  capabilities when it was not told any rather than guessing.
* **mutating means mutating.** ``certify run`` without ``--execute`` refuses,
  provisions nothing, and writes no record.
* **the live path is bound to the run engine, and only there.** The provisioning
  code cannot execute a plan; the single function that can is the one that calls
  ``RunEngine.execute``. The tests assert that structurally — the container
  engine is never needed to check the wiring.

Nothing here certifies anything. A test that needed docker to prove a refusal
would not be a test, and the honest count of live-verified faults stays zero
until a real environment says otherwise.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.certify import (
    CELL_ENGINE_ORDER,
    RECOVERY_PROBE,
    RESIDUE_CHECKS,
    EngineCell,
    _compatibility,
    _parse_params,
    _probe_privilege,
    _single_fault_spec,
    certify,
)
from mayhem.cli.command_registry import COMMAND_HELP, COMMAND_SPECS
from mayhem.domain.capabilities import Capability
from mayhem.domain.catalog import CATALOG
from mayhem.domain.certification import (
    DEFAULT_CERTIFICATION_TTL,
    DEFAULT_EXPIRY_WARNING,
    Arch,
    CellPrivilege,
    CertificationRecord,
    EvidenceBundleRef,
    MatrixCell,
)
from mayhem.domain.certification import (
    certify as certify_record,
)
from mayhem.domain.faults import EngineLane
from mayhem.infra.certification_repository import CertificationRepository
from mayhem.infra.certification_runner import (
    CellRequest,
    CertificationRequest,
    RecoveryEvidence,
    ResidueFinding,
    ResidueScan,
    effective_lanes,
    evidence_digest,
    expected_evidence_digests,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    import pytest

    from mayhem.cli.certify import CellQuery

REPO_ROOT = Path(__file__).parents[2]
CERTIFY_MODULE = REPO_ROOT / "src" / "mayhem" / "cli" / "certify.py"

FAULT_ID = "proc.pause"
CATALOG_ONLY_FAULT_ID = "process.startup_delay"
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
DIGEST = "d" * 64


def _definition(fault_id: str):
    from mayhem.domain.catalog import definition_for

    return definition_for(fault_id)


def _run(*args: str):
    return CliRunner().invoke(app, list(args), catch_exceptions=False)


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "certify.db")


def _query(**overrides: object) -> CellQuery:
    from mayhem.cli.certify import CellQuery

    base: dict[str, object] = {
        "engine": EngineLane.PODMAN,
        "arch": Arch.ARM64,
        "privilege": CellPrivilege.ROOTLESS,
        "kernel_version": "6.11.0",
        "os_distro": "Fedora 41",
        "capabilities": frozenset({Capability.PROCESS_CONTROL, Capability.NET_ADMIN}),
    }
    base.update(overrides)
    return CellQuery(**base)  # type: ignore[arg-type]


def _cell(engine: EngineLane = EngineLane.DOCKER) -> MatrixCell:
    return MatrixCell(
        engine=engine,
        engine_version="5.3.1",
        os_distro="Fedora 41",
        kernel_version="6.11.0",
        arch=Arch.ARM64,
        privilege=CellPrivilege.ROOTLESS,
        capabilities=frozenset({Capability.PROCESS_CONTROL, Capability.NET_ADMIN}),
    )


def _store_with_certification(
    tmp_path: Path,
    *engines: EngineLane,
    ttl: timedelta = DEFAULT_CERTIFICATION_TTL,
    seal: bool = True,
) -> str:
    """A migrated database holding one certified record per engine given.

    The instant is the wall clock so the record is *currently* live: a fixture
    stamped in the past would be honestly reported as lapsed, which is its own
    test (see ``test_a_lapsed_record_is_reported_as_not_live``).

    ``seal=True`` writes a real attestation chain behind each record, because
    this surface reads through ``sealed_certification_gate``: a claim with no
    verifiable chain is reported withdrawn, and a fixture that planted bare rows
    would therefore be asserting the *absence* of a certification while claiming
    to assert its presence. ``seal=False`` is the negative control for exactly
    that, used by ``test_a_claim_with_no_sealed_chain_is_reported_withdrawn``.
    """
    from mayhem.domain.common import utc_now

    at = utc_now()
    path = _db(tmp_path)
    store = Store.open_migrated(path)
    try:
        repository = CertificationRepository(store)
        for engine in engines or tuple(EngineLane):
            cell = _cell(engine)
            bundle = _sealed_bundle(engine)
            record = CertificationRecord(
                fault_id=FAULT_ID,
                cell=cell,
                injector_version="1.0.0",
                expires_at=at + ttl,
            )
            repository.append(
                certify_record(
                    record,
                    at=at,
                    expires_at=at + ttl,
                    evidence=(bundle,),
                    outcome="certified on a real cell",
                ),
                run_id=f"r-seed-{engine.value}",
                now=at,
            )
            if seal:
                _seal(store, bundle, cell)
    finally:
        store.close()
    return path


#: The recovery signal a container-lane ``proc.pause`` certification carries:
#: undo ran, the lease came back to released, and the observed distance from
#: that state is zero. ``proc.pause`` is reversible, so
#: ``requires_recovery_verification`` demands a probe and
#: ``CertificationEvidenceVerdict.grants_runtime_verification`` will not grant a
#: claim without one — a fixture that certified without recovery would be
#: claiming exactly what the gate is right to withdraw.
_GOOD_RECOVERY = RecoveryEvidence(
    probe="lease.released", baseline=0.0, observed=0.0, tolerance=0.0, undo_ran=True
)


def _sealed_bundle(engine: EngineLane) -> EvidenceBundleRef:
    """The bundle one cell's run would have produced, digests derived honestly.

    Cell-specific on purpose: two cells are two runs, so their observed effect
    strings differ and each bundle — and therefore each sealed chain — is
    distinct. A fixture that reused one bundle hash for both engines would have
    the second seal overwrite the first chain.
    """
    digests = expected_evidence_digests(
        params={},
        target=f"{engine.value}/testcase-api",
        observed_effect=(f"process execution state changes|observed=SIGSTOP on {engine.value}"),
        recovery=_GOOD_RECOVERY,
        residue=ResidueScan(performed=True),
    )
    return EvidenceBundleRef(
        bundle_hash=evidence_digest("bundle", digests),
        mayhem_version="1.1.0",
        digests=digests,
    )


def _seal(store: Store, bundle: EvidenceBundleRef, cell: MatrixCell) -> None:
    """Write the attestation chain a live claim has to be able to point at."""
    from mayhem.controller.certification_evidence import (
        CertificationFacts,
        seal_certification_evidence,
    )
    from mayhem.domain.attestation import AttestedTimestamp
    from mayhem.domain.common import utc_now

    at = utc_now()
    seal_certification_evidence(
        store,
        CertificationFacts(
            bundle=bundle,
            fault_id=FAULT_ID,
            cell_label=cell.label,
            cell_fingerprint=cell.fingerprint,
            injector_version="1.0.0",
            run_id="r-seed",
            residue=ResidueScan(performed=True),
            recovery=_GOOD_RECOVERY,
            recovery_required=True,
            compensated=True,
            outcome="certified on a real cell",
        ),
        recorded_at=AttestedTimestamp(wall_clock=at, monotonic_ns=1, source="system"),
    )


# ── the surface ─────────────────────────────────────────────────────────────


def test_certify_is_registered_in_the_single_inventory() -> None:
    """The registry, the Click tree, and the help text must agree."""
    names = {spec.name for spec in COMMAND_SPECS}
    assert "certify" in names
    assert "certify" in set(app.commands)
    spec = next(spec for spec in COMMAND_SPECS if spec.name == "certify")
    assert spec.mutating is True, "certify run provisions a container and injects a fault"
    assert spec.workflow in {
        "discover",
        "prepare",
        "experiment",
        "run",
        "inspect",
        "recover",
        "extend",
    }
    assert app.commands["certify"].help == COMMAND_HELP["certify"]
    assert "certify" in COMMAND_HELP


def test_certify_resolves_by_prefix_like_every_other_group() -> None:
    for path in (("cert", "--help"), ("certify", "--help"), ("certify", "mat", "--help")):
        result = _run(*path)
        assert result.exit_code == 0, path
        assert "Usage:" in result.output


def test_every_certify_subcommand_renders_help() -> None:
    for sub in ("run", "matrix", "regress"):
        result = _run("certify", sub, "--help")
        assert result.exit_code == 0, sub
        assert "Usage:" in result.output
        assert "Options:" in result.output
    # The group advertises exactly the three documented sub-commands. `regress` is
    # the regression gate Phase 5 wired to CI; its behaviour is tested in
    # tests/unit/test_certify_regress_gate.py.
    assert set(certify.commands) == {"run", "matrix", "regress"}


def test_the_database_is_migrated_to_the_head_before_anything_is_reported(
    tmp_path: Path,
) -> None:
    """A matrix query on a fresh path still gets a schema with the new table."""
    result = _run("--db", _db(tmp_path), "certify", "matrix", FAULT_ID, "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["faults"][0]["fault_id"] == FAULT_ID
    # The head is asserted as "the last migration in the list", never as a
    # literal. Migrations are appended by every lane, so a pinned number here
    # fails the next time one lands and proves nothing in the meantime:
    # contiguity is ``test_migrations_run_once``'s job, and the count itself is
    # the next line.
    assert ALL_MIGRATIONS[-1].version == len(ALL_MIGRATIONS)
    store = Store(_db(tmp_path))
    try:
        assert store.schema_version == len(ALL_MIGRATIONS)
        assert list(
            store.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='certification_records'"
            )
        )
    finally:
        store.close()


# ── the honest default ──────────────────────────────────────────────────────


def test_a_fresh_database_certifies_nothing_and_promotes_nothing(tmp_path: Path) -> None:
    """0 of N, and nothing above ``verified-unit`` — with no record store seeded."""
    result = _run("--db", _db(tmp_path), "certify", "matrix", "--all", "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["faults_total"] == len(CATALOG)
    assert payload["certified_faults"] == 0
    assert all(row["certification"]["live"] is False for row in payload["faults"])
    assert all(
        row["maturity"]["maturity"] in {"experimental", "verified-unit"}
        for row in payload["faults"]
    ), "no live cell has been certified, so no rung above verified-unit is reachable"
    assert all(row["maturity"]["live_verified"] is False for row in payload["faults"])


def test_the_payload_states_that_the_gate_was_armed() -> None:
    result = _run("certify", "matrix", FAULT_ID, "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "armed" in payload["certification_gate"]


def test_a_stored_record_changes_the_answer(tmp_path: Path) -> None:
    """The arming is real: plant records, and the matrix reports them."""
    db = _store_with_certification(tmp_path, EngineLane.DOCKER, EngineLane.PODMAN)
    result = _run("--db", db, "certify", "matrix", FAULT_ID, "--json")
    assert result.exit_code == 0, result.output
    row = json.loads(result.output)["faults"][0]
    assert row["certification"]["live"] is True
    assert row["certification"]["records"] == 2
    assert {cell["engine"] for cell in row["certification"]["cells"]} == {"docker", "podman"}
    assert all(cell["state"] == "certified" for cell in row["certification"]["cells"])
    assert all(cell["evidence"] for cell in row["certification"]["cells"])
    assert not [
        outcome
        for outcome in row["maturity"]["criteria"]
        if "certified certification record" in outcome["name"] and not outcome["met"]
    ], "with a record on every required engine the gate must be satisfied"


def test_a_claim_with_no_sealed_chain_is_reported_withdrawn(tmp_path: Path) -> None:
    """The strict gate is armed: a record nothing sealed grants nothing.

    This is the surface-level consequence of
    ``sealed_certification_gate`` replacing ``certification_gate`` here. The row
    still says ``certified`` — the row is history — but the report must not
    present it as a standing claim, and it must say *why* rather than quietly
    counting a fault that no longer has evidence behind it.
    """
    db = _store_with_certification(tmp_path, EngineLane.DOCKER, EngineLane.PODMAN, seal=False)
    result = _run("--db", db, "certify", "matrix", FAULT_ID, "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    row = payload["faults"][0]
    assert payload["certified_faults"] == 0
    assert row["certification"]["live"] is False
    assert all(cell["state"] == "failed" for cell in row["certification"]["cells"])
    assert all("sealed evidence" in cell["reason"] for cell in row["certification"]["cells"])
    assert row["maturity"]["maturity"] in {"experimental", "verified-unit"}


def test_a_chain_that_disappears_stops_being_reported_as_a_standing_claim(
    tmp_path: Path,
) -> None:
    """Deleting the evidence withdraws the claim; nothing else can restore it.

    The failure the whole plan exists to prevent is a claim that outlives what it
    is checked against. Asserted by removing the attestation rows behind a claim
    that was live a moment earlier — which is exactly what
    ``CertificationEvidenceHeldError`` and ``reconcile_certification_evidence``
    exist to make hard to do by accident, and what the read-time gate exists to
    catch when it happens anyway.
    """
    db = _store_with_certification(tmp_path, EngineLane.DOCKER, EngineLane.PODMAN)
    before = json.loads(_run("--db", db, "certify", "matrix", FAULT_ID, "--json").output)
    assert before["certified_faults"] == 1

    store = Store.open_migrated(db)
    try:
        with store.write() as conn:
            conn.execute("DELETE FROM attestation_events")
            conn.execute("DELETE FROM attestation_manifests")
    finally:
        store.close()

    after = json.loads(_run("--db", db, "certify", "matrix", FAULT_ID, "--json").output)
    assert after["certified_faults"] == 0
    row = after["faults"][0]
    assert row["certification"]["live"] is False
    assert all(cell["state"] == "failed" for cell in row["certification"]["cells"])
    assert row["maturity"]["maturity"] in {"experimental", "verified-unit"}


def test_the_matrix_sweep_persists_ageing_and_is_still_opt_in(tmp_path: Path) -> None:
    """``--sweep`` writes the transitions a plain read only reports.

    Two halves, both required: a read must not mutate what it reports on, and
    the command that does mutate must say so in its payload rather than leaving
    the operator to guess whether a demotion happened.
    """
    db = _store_with_certification(
        tmp_path,
        EngineLane.DOCKER,
        EngineLane.PODMAN,
        ttl=-timedelta(hours=1),  # already lapsed when it is written
    )

    read = json.loads(_run("--db", db, "certify", "matrix", FAULT_ID, "--json").output)
    assert read["expiry_sweep"] == {"performed": False}
    store = Store.open_migrated(db)
    try:
        assert all(
            row.record.state.value == "certified" for row in CertificationRepository(store).all()
        )
    finally:
        store.close()

    swept = json.loads(_run("--db", db, "certify", "matrix", FAULT_ID, "--sweep", "--json").output)
    assert swept["expiry_sweep"]["performed"] is True
    assert swept["expiry_sweep"]["aged"] == 2
    store = Store.open_migrated(db)
    try:
        assert sorted(row.record.state.value for row in CertificationRepository(store).all()) == [
            "stale",
            "stale",
        ]
    finally:
        store.close()


def test_a_lapsed_record_is_reported_as_not_live_without_any_sweep(
    tmp_path: Path,
) -> None:
    """Reads age; they do not mutate. A claim that lapsed stops counting.

    The records are written already-expired, and the query reports them as not
    live without anything having written a ``stale`` row first. That is the
    property the persistence sweep exists to make durable, not to make true.
    """
    db = _store_with_certification(
        tmp_path,
        EngineLane.DOCKER,
        EngineLane.PODMAN,
        ttl=-timedelta(hours=1),  # already lapsed when it is written
    )
    store = Store.open_migrated(db)
    try:
        repository = CertificationRepository(store)
        rows = repository.all()
        assert [row.record.state.value for row in rows] == ["certified", "certified"]
    finally:
        store.close()
    result = _run("--db", db, "certify", "matrix", FAULT_ID, "--json")
    assert result.exit_code == 0, result.output
    row = json.loads(result.output)["faults"][0]
    assert row["certification"]["records"] == 2
    assert row["certification"]["live"] is False
    assert all(cell["state"] == "stale" for cell in row["certification"]["cells"])
    store = Store.open_migrated(db)
    try:
        # ... and the stored rows are untouched: ageing is not a mutation.
        assert all(
            row.record.state.value == "certified" for row in CertificationRepository(store).all()
        )
    finally:
        store.close()


def test_a_record_inside_the_warning_window_is_reported_as_expiring(
    tmp_path: Path,
) -> None:
    """A claim about to lapse is visibly distinct from one that already has."""
    db = _store_with_certification(
        tmp_path,
        EngineLane.DOCKER,
        ttl=DEFAULT_EXPIRY_WARNING - timedelta(hours=1),
    )
    row = json.loads(_run("--db", db, "certify", "matrix", FAULT_ID, "--json").output)["faults"][0]
    assert [cell["state"] for cell in row["certification"]["cells"]] == ["expiring"]
    assert row["certification"]["live"] is True, "expiring still counts; it is a warning"


# ── compatibility questions answer without executing ─────────────────────────


def test_a_compatibility_question_answers_without_executing(tmp_path: Path) -> None:
    """The plan's own example: can ``net.latency`` run on podman/rootless/6.11?"""
    result = _run(
        "--db",
        _db(tmp_path),
        "certify",
        "matrix",
        "net.latency",
        "--engine",
        "podman",
        "--privilege",
        "rootless",
        "--kernel",
        "6.11.0",
        "--os-distro",
        "Fedora 41",
        "--arch",
        "arm64",
        "--json",
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    row = payload["faults"][0]
    assert payload["query"]["engine"] == "podman"
    assert payload["query"]["privilege"] == "rootless"
    assert payload["query"]["kernel_version"] == "6.11.0"
    assert row["compatibility"]["engine_lane"] == "ok"
    assert row["certification"]["live"] is False


def test_a_cell_the_fault_does_not_declare_is_reported_as_unsupported() -> None:
    definition = _definition("k8s.image_pull_slow")
    verdict = _compatibility(definition, _query(engine=EngineLane.DOCKER))
    assert verdict["engine_lane"] == "unsupported"
    assert verdict["allowed"] is False
    assert any("declares lanes kubernetes" in reason for reason in verdict["reasons"])


def test_missing_capabilities_are_named() -> None:
    definition = _definition(FAULT_ID)  # requires process_control
    verdict = _compatibility(definition, _query(capabilities=frozenset({Capability.NET_ADMIN})))
    assert verdict["capability_state"] == "known"
    assert verdict["missing_capabilities"] == ["process_control"]
    assert verdict["allowed"] is False


def test_unsupplied_capabilities_are_unknown_not_guessed() -> None:
    """A compatibility question must not invent a capability to pass on."""
    definition = _definition(FAULT_ID)
    verdict = _compatibility(definition, _query(capabilities=None))
    assert verdict["capability_state"] == "unknown"
    assert verdict["allowed"] is False
    assert any("cannot be checked without executing" in r for r in verdict["reasons"])


def test_a_catalog_only_fault_is_reported_as_never_runnable() -> None:
    definition = _definition(CATALOG_ONLY_FAULT_ID)
    verdict = _compatibility(definition, _query(engine=EngineLane.DOCKER))
    assert verdict["allowed"] is False
    assert any("catalog-only" in reason for reason in verdict["reasons"])


def test_an_incompletely_specified_cell_is_not_matched_against_a_stored_claim(
    tmp_path: Path,
) -> None:
    """``on_queried_cell`` is ``null``, not ``false``, when a dimension is unknown."""
    db = _store_with_certification(tmp_path, EngineLane.DOCKER, EngineLane.PODMAN)
    result = _run("--db", db, "certify", "matrix", FAULT_ID, "--engine", "podman", "--json")
    row = json.loads(result.output)["faults"][0]
    assert row["certification"]["on_queried_cell"] is None
    assert row["certification"]["live"] is True


def test_a_fully_specified_query_does_match_a_stored_cell(tmp_path: Path) -> None:
    db = _store_with_certification(tmp_path, EngineLane.PODMAN)
    result = _run(
        "--db",
        db,
        "certify",
        "matrix",
        FAULT_ID,
        "--engine",
        "podman",
        "--arch",
        "arm64",
        "--privilege",
        "rootless",
        "--kernel",
        "6.11.0",
        "--os-distro",
        "Fedora 41",
        "--capability",
        "process_control",
        "--capability",
        "net_admin",
        "--json",
    )
    row = json.loads(result.output)["faults"][0]
    assert row["certification"]["on_queried_cell"] is True


def test_matrix_requires_a_fault_id_or_all(tmp_path: Path) -> None:
    result = _run("--db", _db(tmp_path), "certify", "matrix")
    assert result.exit_code == 2
    assert "FAULT_ID" in result.output


def test_an_unknown_fault_id_is_a_validation_error(tmp_path: Path) -> None:
    result = _run("--db", _db(tmp_path), "certify", "matrix", "nope.nope", "--json")
    assert result.exit_code == 4
    assert "not in catalog" in result.output


def test_human_output_names_the_query_and_the_counts() -> None:
    result = _run("certify", "matrix", FAULT_ID, "--engine", "podman")
    assert result.exit_code == 0
    assert "certification matrix" in result.output
    assert "engine=podman" in result.output
    assert FAULT_ID in result.output
    assert "certified faults: 0 of 1" in result.output


# ── mutating means mutating ──────────────────────────────────────────────────


def test_certify_run_without_execute_refuses_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No container, no run, no record: the refusal precedes every side effect."""
    from mayhem.cli import certify as certify_module

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("nothing may be provisioned before --execute")

    monkeypatch.setattr(certify_module, "_provision", explode)
    monkeypatch.setattr(certify_module, "_engine_execute", explode)

    db = _db(tmp_path)
    result = _run("--db", db, "certify", "run", FAULT_ID)
    assert result.exit_code == 5, result.output
    assert "--execute" in result.output
    store = Store.open_migrated(db)
    try:
        assert CertificationRepository(store).all() == ()
    finally:
        store.close()


def test_the_refusal_before_execute_explains_the_cell_it_would_have_used(
    tmp_path: Path,
) -> None:
    result = _run(
        "--db",
        _db(tmp_path),
        "certify",
        "run",
        FAULT_ID,
        "--engine",
        "podman",
        "--json",
    )
    assert result.exit_code == 5
    payload = json.loads(result.output)
    assert payload["fault_id"] == FAULT_ID
    assert payload["engine"] == "podman"
    assert payload["would_execute"] is True
    assert "--execute" in payload["requires"]


def test_kubernetes_cells_are_refused_with_a_pointer_not_a_fallback(
    tmp_path: Path,
) -> None:
    result = _run(
        "--db", _db(tmp_path), "certify", "run", FAULT_ID, "--engine", "kubernetes", "--execute"
    )
    assert result.exit_code == 4
    assert "plan 02" in result.output


def test_an_unknown_fault_is_refused_before_anything_is_provisioned(
    tmp_path: Path,
) -> None:
    result = _run("--db", _db(tmp_path), "certify", "run", "nope.nope", "--execute")
    assert result.exit_code == 4
    assert "not in catalog" in result.output


def test_a_malformed_param_is_a_usage_error(tmp_path: Path) -> None:
    result = _run("--db", _db(tmp_path), "certify", "run", FAULT_ID, "--param", "nope")
    assert result.exit_code == 2
    assert "key=value" in result.output


def test_params_are_coerced_the_way_a_spec_would_coerce_them() -> None:
    assert _parse_params(("count=3",)) == {"count": 3}
    assert _parse_params(("ratio=0.5",)) == {"ratio": 0.5}
    assert _parse_params(("flag=true",)) == {"flag": True}
    assert _parse_params(("name=web",)) == {"name": "web"}


# ── the live path is bound to the run engine, and only there ────────────────


def test_the_only_execution_path_is_run_engine_execute() -> None:
    """``certify run`` has no second way to run a drill.

    Checked structurally rather than by mocking a container: the module must
    contain exactly one ``.execute(`` call, it must be on the
    :class:`~mayhem.controller.executor.RunEngine` instance the factory builds,
    and the cell itself must receive that as a callable rather than being able
    to reach an executor.
    """
    from mayhem.controller.executor import RunEngine

    tree = ast.parse(CERTIFY_MODULE.read_text(encoding="utf-8"))
    execute_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "runner"
    ]
    assert len(execute_calls) == 1, (
        "mayhem certify must reach RunEngine.execute exactly once, through the normal run path"
    )
    factories = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "engine_for"
    ]
    assert len(factories) == 1, "one place builds the run engine"
    assert RunEngine.__module__ + "." + RunEngine.__name__ == "mayhem.controller.executor.RunEngine"


def test_the_live_path_mints_the_intent_require_intent_demands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--execute`` mints the approval it stands for, bound to this plan.

    ``engine_for(..., require_intent=True)`` with no intent is a refusal by
    construction — which is exactly what the live path did before this: it
    demanded an intent and built none, so no certification cell could ever be
    reached except through the implicit-execution compatibility switch. A
    certification reached by bypassing the intent contract is not a
    certification this command should be able to produce, so the intent is
    minted here, from the same ``intent_for_plan``/``plan_hash_for`` the
    preflight gate re-derives, and this test pins all three properties: an
    intent exists, its hash is *this* plan's hash, and ``require_intent`` stays
    armed.
    """
    from mayhem.cli import services
    from mayhem.cli.certify import _engine_execute
    from mayhem.domain.experiments import ExecutionPlan, ExperimentKind
    from mayhem.domain.preflight import plan_hash_for

    captured: dict[str, object] = {}

    class FakeRunner:
        def __init__(self) -> None:
            self.plans: list[object] = []

        def execute(self, plan: object) -> str:
            self.plans.append(plan)
            return "ran"

    runner = FakeRunner()

    def capture(store: object, engine: str | None = None, **kwargs: object) -> FakeRunner:
        captured["engine"] = engine
        captured.update(kwargs)
        return runner

    # The import inside ``_engine_execute`` resolves when it is called, so the
    # patch has to be in place before the factory below is built.
    monkeypatch.setattr(services, "engine_for", capture)

    plan = ExecutionPlan(
        run_id="r-certify-intent",
        kind=ExperimentKind.DRILL,
        steps=(),
        config_snapshot_id="cfg-0001",
        topology_snapshot_id="topo-0001",
        environment_fingerprint="env-fp-1",
    )
    graph = object()
    execute = _engine_execute(
        Store.open_migrated(":memory:"),
        graph,
        SimpleNamespace(recovery_grace=123.0),
        "podman",
    )

    assert execute(plan) == "ran"

    intent = captured.get("intent")
    assert intent is not None, (
        "certify's execute path must mint the ExecutionIntent it demands: "
        "require_intent=True with no intent is a refusal by construction"
    )
    assert intent.plan_hash == plan_hash_for(plan), (
        "the intent must bind the plan about to run, with the same hash the "
        "preflight gate re-derives"
    )
    assert intent.engine == "podman"
    assert intent.actor == "cli:certify --execute"
    assert captured["require_intent"] is True, "the gate stays armed"
    assert captured["recovery_grace"] == 123.0
    assert captured["live_graph"]() is graph  # type: ignore[union-attr]
    assert runner.plans == [plan], "the bound plan is the plan that executes"


# ── the live capture chain: envelope written, envelope read, digests agree ────
#
# The three tests below are the ones a container engine would have found. The
# chain is: the run writes its evidence envelope (as `mayhem run` does),
# `RunEvidenceCapturer` reads that envelope plus the plan the executor stored,
# and the digests it derives from those durable artifacts must equal what the
# runner derives from the live plan. Each link had silently been broken — the
# crash, then a permanent `no_evidence` refusal, is what a live cell saw.


def test_a_store_that_never_wrote_evidence_says_so_instead_of_raising() -> None:
    """A fresh database answers ``no evidence``; it does not raise at the operator.

    ``evidence_envelopes`` is created lazily by :func:`write_evidence`, and a
    *refused* write deliberately leaves no table at all — so "no table" is the
    store's own answer to "is there any evidence here?". Before the readers
    tolerated it, ``certify run`` on a fresh ``--db`` crashed with
    ``OperationalError: no such table: evidence_envelopes`` *after* the run
    completed, having provisioned, injected, recovered, and disposed a cell.
    """
    from mayhem.infra.evidence import list_evidence, load_evidence

    store = Store.open_migrated(":memory:")
    try:
        tables = {
            str(row["name"])
            for row in store.query("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "evidence_envelopes" not in tables, (
            "precondition: nothing has written evidence, so the table must not exist"
        )
        assert load_evidence(store, "r-fresh-store") is None
        assert list_evidence(store) == []
    finally:
        store.close()


def test_the_fallback_target_is_chosen_against_the_graph_not_the_compose_alone(
    tmp_path: Path,
) -> None:
    """``regress --rerun``'s default target must be a container the graph knows.

    A compose file may call a service ``api`` and give it ``container_name:
    testcase-api``; the topology's subtree keys follow the container name, so
    guessing the alphabetically-first *service* produced a plan the planner
    refuses (``container 'api' not found in topology``) — which made the nightly
    gate's own execution path fail on exactly the bundled example stack people
    certify against. The fallback is chosen against the resolved graph.
    """
    from mayhem.cli.certify import _first_container

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  api:\n"
        "    container_name: testcase-api\n"
        "  web:\n"
        "    container_name: testcase-web\n",
        encoding="utf-8",
    )

    class Graph:
        def node_ids_for_container(self, name: str) -> frozenset[str]:
            return frozenset({"node"}) if name.startswith("testcase-") else frozenset()

        def container_names(self) -> tuple[str, ...]:
            return ("testcase-api", "testcase-web")

    ctx = SimpleNamespace()
    chosen = _first_container(ctx, str(compose), graph=Graph())  # type: ignore[arg-type]
    assert chosen == "testcase-api", (
        "the service name 'api' is not a topology subtree; the fallback must be "
        "the name the graph resolves"
    )

    # A graph that knows none of them still yields its own container, and an
    # absent compose still yields the historical placeholder rather than None.
    class Empty:
        def node_ids_for_container(self, name: str) -> frozenset[str]:
            return frozenset()

        def container_names(self) -> tuple[str, ...]:
            return ()

    assert _first_container(ctx, str(compose), graph=Empty()) == "testcase-api"  # type: ignore[arg-type]
    assert _first_container(ctx, None, graph=Empty()) == "mayhem-certify"  # type: ignore[arg-type]


def test_a_failure_after_provisioning_cannot_leave_the_cell_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever fails after ``_provision``, the disposable cell is disposed.

    The cell is started *outside* ``certify_fault``'s own try/finally, and
    ``certify_fault`` compiles the plan before it takes ownership — so a planning
    refusal used to raise with a running container behind it. Seen live:
    ``certify regress --rerun`` against a target the topology did not know left
    a ``mayhem-certify-*`` container up with nothing to ever remove it.
    ``EngineCell.dispose`` is idempotent, so the backstop costs nothing on the
    path where the runner already disposed.
    """
    import click

    from mayhem.cli import certify as certify_module

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  api:\n    container_name: testcase-api\n",
        encoding="utf-8",
    )

    class FakeCell:
        def __init__(self) -> None:
            self.disposals = 0

        def dispose(self) -> None:
            self.disposals += 1

    cells: list[FakeCell] = []

    def fake_provision(request: object, **kwargs: object) -> FakeCell:
        cell = FakeCell()
        cells.append(cell)
        return cell

    def boom(*args: object, **kwargs: object) -> None:
        raise click.ClickException("the planner refused the target")

    monkeypatch.setattr(certify_module, "_provision", fake_provision)
    monkeypatch.setattr(certify_module, "certify_fault", boom)

    result = _run(
        "--db",
        _db(tmp_path),
        "certify",
        "run",
        FAULT_ID,
        "--execute",
        "--engine",
        "docker",
        "--container",
        "testcase-api",
        "--compose",
        str(compose),
    )
    assert result.exit_code != 0
    assert "refused" in result.output
    assert cells, "the attempt provisioned before it failed"
    assert cells[0].disposals == 1, "the provisioned cell must be disposed exactly once"


def test_the_live_path_persists_the_evidence_capture_cites(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``execute`` writes the run's envelope before ``capture`` can ask for it.

    ``mayhem run`` writes an evidence envelope after every run; ``certify run``
    drives the same engine, so without this write the capturer answered *nothing*
    to "what evidence does this run carry?" and every attempt — however clean the
    cell — was refused ``no_evidence``. The test pins the seam itself: the
    callable ``_engine_execute`` returns must leave a durable, loadable envelope
    for the run id, carrying this plan's hash.
    """
    from mayhem.cli import services
    from mayhem.cli.certify import _engine_execute
    from mayhem.controller.executor import RunResult
    from mayhem.domain.experiments import ExecutionPlan, ExperimentKind
    from mayhem.domain.preflight import plan_hash_for
    from mayhem.infra.evidence import load_evidence

    class FakeRunner:
        def execute(self, plan: ExecutionPlan) -> RunResult:
            return RunResult(
                run_id=plan.run_id,
                status="completed",
                started_at_epoch_s=1.0,
                ended_at_epoch_s=2.0,
            )

    monkeypatch.setattr(services, "engine_for", lambda *args, **kwargs: FakeRunner())

    plan = ExecutionPlan(
        run_id="r-evidence-persist",
        kind=ExperimentKind.DRILL,
        steps=(),
        config_snapshot_id="cfg-0001",
        topology_snapshot_id="topo-0001",
        environment_fingerprint="env-fp-1",
    )
    store = Store.open_migrated(":memory:")
    try:
        execute = _engine_execute(store, None, SimpleNamespace(recovery_grace=300.0), "podman")
        result = execute(plan)
        assert result.status == "completed"
        envelope = load_evidence(store, plan.run_id)
        assert envelope is not None, (
            "the live path must persist the run's evidence envelope: capture reads "
            "it, and without it a clean cell is refused no_evidence"
        )
        assert envelope.plan_hash == plan_hash_for(plan)
    finally:
        store.close()


def test_the_capturer_cites_the_stored_plan_and_its_digests_agree() -> None:
    """``capture`` derives digests from the durable artifacts — and they match.

    This is the corroboration the capturer's docstring promises: its digests come
    from the store (the envelope + the plan row the executor wrote), while the
    runner derives its own from the in-memory plan and the step report. If the
    two derivations ever disagree, ``_evidence_refusals`` refuses the bundle as
    fabricate — so the store-side path must be exercised, not assumed. It reads
    ``runs.plan_json``, the table the executor actually writes; its earlier
    query of ``m5_runs`` (a table with no writer on this path) made every capture
    a silent ``no evidence``.
    """
    from mayhem.cli.certify import RunEvidenceCapturer
    from mayhem.domain.experiments import (
        ExecutionPlan,
        ExperimentKind,
        InjectFault,
        PlannedFault,
        PlannedStep,
        ResolvedTarget,
    )
    from mayhem.domain.topology import NodeKind, TargetSelector
    from mayhem.infra.evidence import build_evidence, write_evidence

    store = Store.open_migrated(":memory:")
    try:
        selector = TargetSelector(kind=NodeKind.CONTAINER, expr="testcase-api")
        step = PlannedStep(
            id="step-1",
            seq=0,
            raw_action=InjectFault(fault=FAULT_ID, selectors=(selector,), duration="5s"),
            fault=PlannedFault(
                fault_id=FAULT_ID,
                targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"testcase-api"})),),
                params={"hold": 2},
                duration=5.0,
            ),
        )
        plan = ExecutionPlan(
            run_id="r-capture-chain",
            kind=ExperimentKind.DRILL,
            steps=(step,),
            config_snapshot_id="cfg-0001",
            topology_snapshot_id="topo-0001",
            environment_fingerprint="env-fp-1",
        )
        detail = "SIGSTOP delivered to 4242"

        # What the live path writes before capture runs.
        write_evidence(
            store,
            build_evidence(
                run_id=plan.run_id,
                plan=plan,
                target_profile=None,
                engine="podman",
                safety_decisions=("safety: plan validated",),
                step_reports=(),
                lease_timeline=(),
                observations=(),
                verdict="pass",
                recovery_state="recovered",
                remediation=(),
            ),
        )
        # What the executor writes when the run opens.
        with store.write() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO config_snapshots (id, resolved_json, source_map, created_at)"
                " VALUES (?, '{}', '{}', ?)",
                (plan.config_snapshot_id, "2026-10-06T00:00:00+00:00"),
            )
            conn.execute(
                """INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed,
                    status, environment_fingerprint, config_snapshot_id, started_at,
                    governing_decisions_json, controller_pid)
                   VALUES (?, ?, 'drill', '{}', ?, NULL, 'completed', ?, ?, ?, '[]', 0)""",
                (
                    plan.run_id,
                    plan.run_id,
                    plan.model_dump_json(),
                    plan.environment_fingerprint,
                    plan.config_snapshot_id,
                    "2026-10-06T00:00:00+00:00",
                ),
            )

        residue = ResidueScan(performed=True, note="probe ran")
        run = SimpleNamespace(
            run_id=plan.run_id,
            status="completed",
            steps=(SimpleNamespace(step_id="step-1", detail=detail, ok=True),),
            dirty_leases=(),
        )
        request = CertificationRequest(
            fault_id=FAULT_ID,
            cell=CellRequest(
                engine=EngineLane.PODMAN,
                engine_version="5.3.1",
                os_distro="Fedora 41",
                kernel_version="6.11.0",
                arch=Arch.ARM64,
                privilege=CellPrivilege.ROOTLESS,
                capabilities=frozenset({Capability.PROCESS_CONTROL}),
            ),
            target="",
            duration_s=5.0,
            ttl=timedelta(days=30),
            injector_version="5.3.1",
            mayhem_version="1.1.0",
        )

        ref = RunEvidenceCapturer(store=store, mayhem_version="1.1.0").capture(
            run,  # type: ignore[arg-type]
            request=request,
            cell=_cell(EngineLane.PODMAN),
            plan=plan,
            residue=residue,
            recovery=None,
        )
        assert ref is not None, "a stored envelope + stored plan must yield a bundle"

        expected = expected_evidence_digests(
            params={"hold": 2},
            target="testcase-api",
            observed_effect=f"{_definition(FAULT_ID).observable_effect}|observed={detail}",
            recovery=None,
            residue=residue,
            demotions=(),
            compensated=True,
        )
        assert ref.digests == expected, (
            "store-derived digests must equal the runner's live derivation: this is "
            "the fabrication check _evidence_refusals performs"
        )
        assert len(ref.bundle_hash) == 64
    finally:
        store.close()


def test_the_cell_cannot_execute_anything_by_itself() -> None:
    """``EngineCell.execute`` delegates; it holds no executor and imports none."""

    class FakeEngine:
        def __init__(self) -> None:
            self.plans: list[object] = []

        def execute(self, plan: object) -> str:
            self.plans.append(plan)
            return "ran"

    engine = FakeEngine()  # type: ignore[arg-type]
    cell = EngineCell(
        cell=_cell(),
        injector_version="1.0.0",
        _execute=engine.execute,  # type: ignore[arg-type]
        _binary="docker",
        _container="c1",
        _store=Store.open_migrated(":memory:"),
    )
    plan = SimpleNamespace(run_id="r-cell")
    assert cell.execute(plan) == "ran"  # type: ignore[arg-type]
    assert len(engine.plans) == 1
    assert cell._run_id == "r-cell"


def test_disposing_a_cell_twice_is_idempotent() -> None:
    """A container that outlives its cell is an operator problem, not a crash."""
    cell = EngineCell(
        cell=_cell(),
        injector_version="1.0.0",
        _execute=lambda _plan: None,  # type: ignore[arg-type,return-value]
        _binary="/nonexistent/docker",
        _container="c1",
        _store=Store.open_migrated(":memory:"),
    )
    cell.dispose()
    cell.dispose()
    assert cell.disposed is True


def test_the_residue_checks_cover_every_class_the_plan_names() -> None:
    from mayhem.infra.certification_runner import RESIDUE_KINDS

    assert tuple(kind for kind, _argv in RESIDUE_CHECKS) == RESIDUE_KINDS


def test_a_residue_scan_records_a_probe_that_could_not_run() -> None:
    """'I could not look' is a finding, not a clean cell."""
    from mayhem.infra.certification_runner import RESIDUE_KINDS

    cell = EngineCell(
        cell=_cell(),
        injector_version="1.0.0",
        _execute=lambda _plan: None,  # type: ignore[arg-type,return-value]
        _binary="/nonexistent/docker",
        _container="c1",
        _store=Store.open_migrated(":memory:"),
    )
    scan = cell.residue_scan()
    assert scan.performed is True
    assert {finding.kind for finding in scan.findings} == set(RESIDUE_KINDS)
    assert all("probe unavailable" in finding.detail for finding in scan.findings)
    assert scan.clean is False


def test_recovery_evidence_is_none_when_the_run_left_no_lease() -> None:
    """No lease means the fault never applied, so nothing was recovered."""
    store = Store.open_migrated(":memory:")
    try:
        cell = EngineCell(
            cell=_cell(),
            injector_version="1.0.0",
            _execute=lambda _plan: None,  # type: ignore[arg-type,return-value]
            _binary="docker",
            _container="c1",
            _store=store,
        )
        cell._run_id = "r-absent"
        assert cell.recovery_evidence(None) is None  # type: ignore[arg-type]
        assert RECOVERY_PROBE == "lease.released"
    finally:
        store.close()


def test_recovery_evidence_reads_the_durable_lease_state() -> None:
    store = Store.open_migrated(":memory:")
    try:
        with store.write() as conn:
            conn.execute(
                "INSERT INTO fault_leases (id, state, owner_agent, undo_json, "
                "verify_json, ttl_seconds, expires_at, release_mechanism, run_id) "
                "VALUES ('l1','released','mayhem','[]','[]',60,"
                "'2026-03-01T00:10:00+00:00','normal','r-lease')"
            )
            conn.execute(
                "INSERT INTO recovery_records (id, lease_id, attempt, mechanism, "
                "undo_results_json, verified, at) "
                "VALUES ('rec1','l1',1,'normal','[]',1,'2026-03-01T00:00:00+00:00')"
            )
        cell = EngineCell(
            cell=_cell(),
            injector_version="1.0.0",
            _execute=lambda _plan: None,  # type: ignore[arg-type,return-value]
            _binary="docker",
            _container="c1",
            _store=store,
        )
        cell._run_id = "r-lease"
        evidence = cell.recovery_evidence(None)  # type: ignore[arg-type]
        assert evidence is not None
        assert evidence.probe == RECOVERY_PROBE
        assert evidence.undo_ran is True
        assert evidence.within_tolerance is True
    finally:
        store.close()


def test_recovery_evidence_is_refused_when_the_verification_did_not_pass() -> None:
    store = Store.open_migrated(":memory:")
    try:
        with store.write() as conn:
            conn.execute(
                "INSERT INTO fault_leases (id, state, owner_agent, undo_json, "
                "verify_json, ttl_seconds, expires_at, release_mechanism, run_id) "
                "VALUES ('l1','released','mayhem','[]','[]',60,"
                "'2026-03-01T00:10:00+00:00','normal','r-lease')"
            )
            conn.execute(
                "INSERT INTO recovery_records (id, lease_id, attempt, mechanism, "
                "undo_results_json, verified, at) "
                "VALUES ('rec1','l1',1,'normal','[]',0,'2026-03-01T00:00:00+00:00')"
            )
        cell = EngineCell(
            cell=_cell(),
            injector_version="1.0.0",
            _execute=lambda _plan: None,  # type: ignore[arg-type,return-value]
            _binary="docker",
            _container="c1",
            _store=store,
        )
        cell._run_id = "r-lease"
        evidence = cell.recovery_evidence(None)  # type: ignore[arg-type]
        assert evidence is not None
        assert evidence.within_tolerance is False
    finally:
        store.close()


# ── helpers, and the two they must agree on ─────────────────────────────────


def test_the_synthesised_drill_is_a_real_spec() -> None:
    request = CertificationRequest(
        fault_id=FAULT_ID,
        cell=CellRequest(engine=EngineLane.DOCKER),
        params={"percent": 50},
        target="testcase-api",
        duration_s=7.0,
    )
    spec = _single_fault_spec(FAULT_ID, "testcase-api", request)
    assert spec.name == "certify-proc-pause"
    assert spec.containers is not None
    faults = spec.containers["testcase-api"].faults
    assert len(faults) == 1
    assert faults[0].fault == FAULT_ID
    assert float(faults[0].duration) == 7.0
    assert spec.execution[0].sequential == ("testcase-api",)


def test_the_cell_request_defaults_to_the_probed_host() -> None:
    from mayhem.cli.certify import _detect_cell_request

    request = _detect_cell_request(
        engine=None, os_distro=None, kernel=None, arch=None, privilege=None
    )
    assert request.engine in CELL_ENGINE_ORDER
    assert request.kernel_version  # probed, never empty
    assert request.arch in set(Arch)
    assert request.privilege in set(CellPrivilege)
    assert _probe_privilege() in set(CellPrivilege)


def test_an_explicit_cell_dimension_is_used_verbatim() -> None:
    from mayhem.cli.certify import _detect_cell_request

    request = _detect_cell_request(
        engine="podman",
        os_distro="Alpine 3.20",
        kernel="6.6.13",
        arch="arm64",
        privilege="root",
    )
    cell = request.as_matrix_cell()
    assert cell.engine is EngineLane.PODMAN
    assert cell.os_distro == "Alpine 3.20"
    assert cell.kernel_version == "6.6.13"
    assert cell.arch is Arch.ARM64
    assert cell.privilege is CellPrivilege.ROOT


def test_effective_lanes_is_the_same_predicate_the_matrix_uses() -> None:
    definition = _definition(FAULT_ID)
    assert EngineLane.DOCKER in effective_lanes(definition)
    assert EngineLane.KUBERNETES not in effective_lanes(definition)
    verdict = _compatibility(definition, _query(engine=EngineLane.DOCKER))
    assert verdict["engine_lane"] == "ok"


def test_a_refused_attempt_cannot_display_a_certified_badge() -> None:
    """The Phase 6 overclaim scan, applied to the certification surface.

    A record that records a refusal must not serialise as a live claim anywhere
    the CLI can read it, so the refusal fields and the live flag are checked
    together.
    """
    from mayhem.infra.certification_runner import (
        AttemptOutcome,
        CertificationAttempt,
        RecurrenceVerdict,
    )

    record = CertificationRecord(
        fault_id=FAULT_ID,
        cell=_cell(),
        injector_version="1.0.0",
        expires_at=NOW + DEFAULT_CERTIFICATION_TTL,
    ).model_copy(update={"outcome": "refused", "reason": "refused:residue: netem on eth0"})
    attempt = CertificationAttempt(
        fault_id=FAULT_ID,
        cell=_cell(),
        run_id="r-1",
        outcome=AttemptOutcome.REFUSED,
        record=record,
        run_status="completed",
        verdict="pass",
        residue=ResidueScan(
            performed=True, findings=(ResidueFinding(kind="tc_rule", detail="netem"),)
        ),
        recovery=None,
        recurrence=RecurrenceVerdict.REGRESSED,
        refusals=("refused:residue: netem on eth0",),
    )
    payload = attempt.to_dict()
    assert payload["certified"] is False
    assert payload["state"] == "pending"
    assert payload["outcome"] == "refused"
    assert "evidence" not in payload, (
        "a refused attempt must not present a bundle reference as a claim"
    )
    assert payload["record"]["state"] == "pending"
    assert payload["record"]["evidence"] == []


def test_the_capture_hash_used_in_fixtures_is_a_real_digest() -> None:
    assert len(DIGEST) == 64
    assert evidence_digest("params", {}) != evidence_digest("params", {"a": 1})


def test_compatibility_is_the_only_running_decision_the_matrix_makes() -> None:
    """One predicate, one answer: it names the lane, the capabilities, and why not."""
    verdict = _compatibility(_definition(FAULT_ID), _query())
    assert set(verdict) == {
        "allowed",
        "engine_lane",
        "capability_state",
        "missing_capabilities",
        "reasons",
    }
