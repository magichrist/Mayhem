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
        observed_effect=(
            f"process execution state changes|observed=SIGSTOP on {engine.value}"
        ),
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
    assert spec.workflow in {"discover", "prepare", "experiment", "run", "inspect", "recover",
                             "extend"}
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
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='certification_records'"
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
    db = _store_with_certification(
        tmp_path, EngineLane.DOCKER, EngineLane.PODMAN, seal=False
    )
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

    swept = json.loads(
        _run("--db", db, "certify", "matrix", FAULT_ID, "--sweep", "--json").output
    )
    assert swept["expiry_sweep"]["performed"] is True
    assert swept["expiry_sweep"]["aged"] == 2
    store = Store.open_migrated(db)
    try:
        assert sorted(
            row.record.state.value for row in CertificationRepository(store).all()
        ) == ["stale", "stale"]
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
            row.record.state.value == "certified"
            for row in CertificationRepository(store).all()
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
        "mayhem certify must reach RunEngine.execute exactly once, through the "
        "normal run path"
    )
    factories = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "engine_for"
    ]
    assert len(factories) == 1, "one place builds the run engine"
    assert (
        RunEngine.__module__ + "." + RunEngine.__name__
        == "mayhem.controller.executor.RunEngine"
    )


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
    ).model_copy(
        update={"outcome": "refused", "reason": "refused:residue: netem on eth0"}
    )
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
