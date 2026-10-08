"""The certification gate is armed at every maturity-reporting call site.

Plan 01's Phase 4 ledger left one precise hole: the gate itself,
``evaluate_maturity(..., records=...)``, was wired on the certification surface,
but the *reporting* path — ``controller/catalog_report.py``, and through it
``mayhem discover capabilities``, the capability dashboard, and
``mayhem explain catalog fault`` — could still be called with no records at all.
A report that omits the gate is not lying about anything; it is 1.0.0 behaviour.
The danger is that it is *silent*: a reader has no way to tell a level a
certification store would contradict from one it would confirm.

So this file is about the seam, not about maturity arithmetic. Five properties, in
increasing order of how quietly they could fail:

* **Nothing is certified.** On a fresh store the honest answer is still zero, and
  every fault is capped at ``verified-unit``. These tests plant records by hand to
  prove the plumbing works, and that is the whole extent of the claim: the
  README's live-verified count stays ``0 of N`` (N the live catalogue size) until
  a real cell says otherwise.
* **A store-less read path stays store-less.** ``records=None`` is the caller's
  statement that *this* report does not use certification, and it preserves 1.0.0
  behaviour exactly. It is not a fallback for a path that simply forgot to open a
  store, and every payload states which state it was computed under.
* **Arming can only lower a level.** ``records={}`` never reports above
  ``verified-unit`` and never reports *higher* than the same fault reports ungated.
  Otherwise the conservative answer would be the optimistic one.
* **Arming is a gate, not a constant.** A record on every required engine does
  raise the level, so a cap that never moved would pass the test above while doing
  nothing.
* **The CLI hands the runner a real sealer.** Checked structurally, because that
  is a fact about wiring that no live cell can be asked about in CI.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from mayhem.controller import catalog_report
from mayhem.domain.capabilities import Capability
from mayhem.domain.catalog import all_definitions, definition_for
from mayhem.domain.certification import (
    REQUIRED_EVIDENCE_DIGESTS,
    Arch,
    CellPrivilege,
    CertificationRecord,
    EvidenceBundleRef,
    MatrixCell,
)
from mayhem.domain.certification import certify as certify_record
from mayhem.domain.faults import EngineLane, MaturityLevel
from mayhem.infra.certification_runner import evidence_digest
from mayhem.infra.promotion import (
    REQUIRED_BUNDLE_DIGESTS,
    REQUIRED_LIVE_ENGINES,
    BundleRef,
    EvidenceStore,
    LiveRunRecord,
    Observation,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

FAULT_ID = "proc.pause"
ENGINE = EngineLane.DOCKER
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
TTL = timedelta(days=30)
DIGEST = "d" * 64
CERTIFY_MODULE = Path(__file__).parents[2] / "src" / "mayhem" / "cli" / "certify.py"


def _cell(engine: EngineLane = ENGINE) -> MatrixCell:
    return MatrixCell(
        engine=engine,
        engine_version="5.3.1",
        os_distro="Fedora 41",
        kernel_version="6.11.0",
        arch=Arch.ARM64,
        privilege=CellPrivilege.ROOTLESS,
        capabilities=frozenset({Capability.PROCESS_CONTROL, Capability.NET_ADMIN}),
    )


def _bundle() -> EvidenceBundleRef:
    return EvidenceBundleRef(
        bundle_hash="a" * 64,
        mayhem_version="1.1.0.test",
        digests=dict.fromkeys(REQUIRED_EVIDENCE_DIGESTS, DIGEST),
    )


def _certified(engine: EngineLane = ENGINE) -> CertificationRecord:
    """A record that grants live verification on ``engine``'s cell.

    A different bundle per engine, so two records are two claims rather than one
    claim counted twice — the same reason the store is keyed per fault and
    sequence. The hash is real hex on purpose: ``CertificationRecord`` refuses a
    bundle reference that is not one, and a fixture that only passed because it
    skipped validation would be testing nothing.
    """
    bundle = _bundle().model_copy(update={"bundle_hash": evidence_digest("cell", engine.value)})
    return certify_record(
        CertificationRecord(
            fault_id=FAULT_ID,
            cell=_cell(engine),
            injector_version="1.0.0",
            expires_at=NOW + TTL,
        ),
        at=NOW,
        expires_at=NOW + TTL,
        evidence=(bundle,),
        outcome="certified on a real cell",
    )


def _records(*engines: EngineLane) -> Mapping[str, Sequence[CertificationRecord]]:
    """The arming point: a per-fault mapping naming only ``engines``."""
    return {FAULT_ID: tuple(_certified(engine) for engine in engines)}


def _rung_rank(maturity: MaturityLevel) -> int:
    return list(MaturityLevel).index(maturity)


def _rows_by_fault(payload: Mapping[str, object]) -> Mapping[str, Mapping[str, object]]:
    """Index a capability payload's rows by fault id.

    The payload is a plain ``dict[str, object]`` on purpose — it is a report, not
    a model — so indexing it is a cast, and doing it once here keeps the
    assertions that follow about the *values* rather than about the typing.
    """
    rows = payload["capabilities"]
    assert isinstance(rows, list)
    return {str(row["fault_id"]): row for row in rows}


def _observations() -> tuple[Observation, ...]:
    """A complete, passing run: injected, undone, and back inside tolerance."""
    return (
        Observation(
            stage="injected",
            probe="signal",
            baseline=10.0,
            observed=250.0,
            tolerance=5.0,
            passed=True,
        ),
        Observation(
            stage="undo",
            probe="signal",
            baseline=10.0,
            observed=11.0,
            tolerance=5.0,
            passed=True,
        ),
        Observation(
            stage="residue",
            probe="signal",
            baseline=10.0,
            observed=10.5,
            tolerance=5.0,
            passed=True,
        ),
    )


def _live_evidence() -> EvidenceStore:
    """Run evidence satisfying every ladder rung on every required engine.

    Two days per engine, because repetition across distinct observation days is
    itself a criterion — one run per engine is not ``verified-live`` however well
    it went. Built here rather than imported from another test file so this file
    stands on its own: the point under test is the gate, and a gate whose fixture
    comes from a sibling suite is one edit away from testing nothing.
    """
    definition = definition_for(FAULT_ID)
    store = EvidenceStore()
    for engine in REQUIRED_LIVE_ENGINES:
        for day in (1, 2):
            started = datetime(2026, 1, day, 12, 0, tzinfo=UTC)
            store = store.record(
                LiveRunRecord(
                    fault_id=FAULT_ID,
                    engine=engine.value,
                    platform="linux/arm64",
                    run_id=f"{engine.value}-{day}",
                    environment="fixture-stack",
                    target="fixture-api",
                    observed_effect=definition.observable_effect,
                    undo_performed=True,
                    undo_description="write-ahead undo and verification probe",
                    started_at=started,
                    finished_at=started + timedelta(seconds=1),
                    bundle=BundleRef(
                        bundle_hash="b" * 64,
                        mayhem_version="1.1.0.test",
                        bundle_path="/tmp/evidence/bundle.json",
                        digests=dict.fromkeys(REQUIRED_BUNDLE_DIGESTS, "c" * 64),
                    ),
                    observations=_observations(),
                )
            )
    return store


# ── nothing is certified ────────────────────────────────────────────────────


def test_a_fresh_store_certifies_nothing_and_promotes_nothing() -> None:
    """No store consulted, no records: every fault is capped at verified-unit.

    The regression guard for the whole plan. If any of this machinery ever began
    minting claims, this test would be the first thing to notice, and the README's
    ``0 of N`` would be wrong the moment it did.
    """
    for definition in all_definitions():
        decision = catalog_report.maturity_decision(definition)
        assert decision.live_verified is False, definition.id
        assert _rung_rank(decision.maturity) <= _rung_rank(MaturityLevel.VERIFIED_UNIT), (
            definition.id
        )


def test_a_store_less_report_reads_exactly_as_it_did_before_certification() -> None:
    """``records=None`` preserves 1.0.0 behaviour, and says so in the payload.

    The guard in the *other* direction: arming the gate everywhere must not
    quietly become "every report is capped", because a reader of an ungated level
    and a reader of a gated one is being told different things and the payload has
    to distinguish them.
    """
    definition = definition_for(FAULT_ID)
    uncapped = catalog_report.maturity_decision(definition)

    assert catalog_report.certification_gate_state(None) == "not-consulted"
    assert catalog_report.build_capability_report()["certification_gate"] == "not-consulted"
    assert catalog_report.build_coverage()["certification_gate"] == "not-consulted"
    assert catalog_report.explain_catalog_fault(FAULT_ID)["certification_gate"] == ("not-consulted")

    rows = _rows_by_fault(catalog_report.build_capability_report())
    assert rows[FAULT_ID]["maturity"] == uncapped.maturity.value
    assert catalog_report.explain_catalog_fault(FAULT_ID)["maturity"] == uncapped.maturity.value


def test_a_store_less_path_does_not_fabricate_an_empty_gate() -> None:
    """``{}`` is an *assertion about a store*, and a store-less path cannot make it.

    This is the distinction the seam exists to preserve. ``{}`` says "I consulted
    a certification store and it holds nothing", which caps every fault and is the
    honest answer on a surface that has a store. ``None`` says "this report does not
    use certification", which is the honest answer for a pure read path. Reporting
    a store-less path as ``asserted-empty`` would claim a provenance it does not
    have, and would make the report disagree with ``mayhem certify`` in the one
    direction a reader mistakes for verification.

    ``{fault_id: ()}`` is ``armed`` rather than ``asserted-empty`` and the
    difference is worth pinning: a store was consulted and it holds nothing *for
    this fault*, which is a stronger and more specific statement than holding
    nothing at all. Both cap identically — only the reader's information differs.
    """
    assert catalog_report.certification_gate_state(None) == "not-consulted"
    assert catalog_report.certification_gate_state({}) == "asserted-empty"
    assert catalog_report.certification_gate_state({FAULT_ID: ()}) == "armed"
    assert catalog_report.certification_gate_state(_records(ENGINE)) == "armed"

    named = catalog_report.maturity_decision(definition_for(FAULT_ID), records={FAULT_ID: ()})
    unnamed = catalog_report.maturity_decision(definition_for(FAULT_ID), records={})
    assert named.maturity is unnamed.maturity, "the two must cap identically"


def test_every_reporting_entry_point_threads_the_gate() -> None:
    """No maturity-reporting function may quietly drop the records it is given.

    Structural rather than behavioural: a function that accepts ``records`` and
    then does not forward it would pass every behavioural test above, because each
    of those hands the mapping straight to ``maturity_decision``.
    """
    import inspect

    for name in (
        "maturity_decision",
        "promotion_refusals",
        "capability_status",
        "build_capability_statuses",
        "build_capability_dashboard",
        "build_capability_report",
        "build_coverage",
        "explain_catalog_fault",
    ):
        parameters = inspect.signature(getattr(catalog_report, name)).parameters
        assert "records" in parameters, f"{name} cannot be armed with the gate"
        assert parameters["records"].default is None, (
            f"{name} must not default to a fabricated empty gate"
        )


# ── arming can only lower a level ───────────────────────────────────────────


def test_arming_the_gate_can_only_lower_a_reported_level() -> None:
    """The safety property, over the whole catalog.

    An empty gate asserts that nothing is certified. That assertion may *lower* a
    reported level and must never raise one.
    """
    allowed = MaturityLevel.at_or_below(MaturityLevel.VERIFIED_UNIT)
    for definition in all_definitions():
        uncapped = catalog_report.maturity_decision(definition)
        capped = catalog_report.maturity_decision(definition, records={})
        assert capped.maturity in allowed, definition.id
        assert capped.live_verified is False, definition.id
        assert _rung_rank(capped.maturity) <= _rung_rank(uncapped.maturity), definition.id


def test_a_planted_record_raises_the_level_so_the_cap_is_a_gate_not_a_constant() -> None:
    """With no records nothing rises; with them the answer genuinely changes.

    Both halves are load-bearing. A cap that never moved would pass the test above
    while doing nothing, and an arming seam that did not thread ``records`` through
    would fail this one.
    """
    definition = definition_for(FAULT_ID)
    evidence = _live_evidence()

    capped = catalog_report.maturity_decision(definition, evidence=evidence, records={})
    assert capped.live_verified is False
    assert _rung_rank(capped.maturity) <= _rung_rank(MaturityLevel.VERIFIED_UNIT)

    # Run evidence alone, with no gate at all, is what 1.0.0 reported. The gate
    # is what sits on top of it, so this is the level being capped.
    ungated = catalog_report.maturity_decision(definition, evidence=evidence)
    assert ungated.live_verified is True
    assert _rung_rank(ungated.maturity) > _rung_rank(capped.maturity), (
        "the ungated fixture must actually reach a live rung, or the cap above is proving nothing"
    )

    # One engine is not every engine: the gate is conjunctive across the required
    # matrix, which is what stops a single-cell certification from reading as a
    # general one.
    partial = catalog_report.maturity_decision(
        definition, evidence=evidence, records=_records(ENGINE)
    )
    assert partial.live_verified is False, "one engine does not satisfy the matrix"

    armed = catalog_report.maturity_decision(
        definition, evidence=evidence, records=_records(*REQUIRED_LIVE_ENGINES)
    )
    assert armed.live_verified is True
    assert _rung_rank(armed.maturity) > _rung_rank(capped.maturity), (
        "a satisfied gate must actually change the answer, or arming it is theatre"
    )


def test_a_lapsed_record_cannot_be_kept_alive_by_the_gate() -> None:
    """Ageing still applies on the armed path; a stored row is not a licence.

    Otherwise the strict gate would be a way to make an expired claim permanent.
    """
    from mayhem.domain.certification import expire_by_time

    lapsed_at = NOW + TTL + timedelta(seconds=1)
    lapsed = {
        FAULT_ID: tuple(
            expire_by_time(_certified(engine), now=lapsed_at) for engine in REQUIRED_LIVE_ENGINES
        )
    }
    assert all(not record.grants_live_verification for record in lapsed[FAULT_ID])

    decision = catalog_report.maturity_decision(
        definition_for(FAULT_ID), evidence=_live_evidence(), records=lapsed
    )
    assert decision.live_verified is False
    assert _rung_rank(decision.maturity) <= _rung_rank(MaturityLevel.VERIFIED_UNIT)


# ── the reports a reader actually sees ──────────────────────────────────────


def test_the_dashboard_the_coverage_summary_and_explain_all_report_one_gate() -> None:
    """Three payloads, three reports of the same fault, one answer.

    They are separate entry points and they were wired separately, so each is
    checked: a payload that shows a maturity without saying whether the gate was
    consulted is the silent hole this file exists to close.
    """
    assert catalog_report.build_capability_dashboard().rows
    for payload in (
        catalog_report.build_capability_report(),
        catalog_report.build_coverage(),
        catalog_report.explain_catalog_fault(FAULT_ID),
    ):
        assert payload["certification_gate"] == "not-consulted"
    for payload in (
        catalog_report.build_capability_report(records={}),
        catalog_report.build_coverage(records={}),
        catalog_report.explain_catalog_fault(FAULT_ID, records={}),
    ):
        assert payload["certification_gate"] == "asserted-empty"
    assert (
        catalog_report.build_capability_report(records=_records(ENGINE))["certification_gate"]
        == "armed"
    )


def test_a_capability_row_never_rises_when_the_gate_is_armed_empty() -> None:
    """The dashboard's rows carry the same cap as the standalone decision.

    ``capability_status`` recomputes the maturity per row, so it is a second place
    the gate could be dropped. Checked against the report a reader sees rather than
    the function, because the report is the thing that has to be true.
    """
    ungated = {
        fault_id: str(row["maturity"])
        for fault_id, row in _rows_by_fault(catalog_report.build_capability_report()).items()
    }
    gated = {
        fault_id: str(row["maturity"])
        for fault_id, row in _rows_by_fault(
            catalog_report.build_capability_report(records={})
        ).items()
    }
    allowed = {level.value for level in MaturityLevel.at_or_below(MaturityLevel.VERIFIED_UNIT)}
    assert ungated and ungated.keys() == gated.keys()
    for fault_id, maturity in gated.items():
        assert maturity in allowed, fault_id
        assert _rung_rank(MaturityLevel(maturity)) <= _rung_rank(
            MaturityLevel(ungated[fault_id])
        ), fault_id
    assert catalog_report.build_coverage(records={})["verified_live"] == 0


# ── the CLI hands the runner a sealer ───────────────────────────────────────


def test_the_certify_fault_call_site_hands_the_runner_a_sealer() -> None:
    """A claim minted by this surface must have sealed bytes behind it.

    Checked structurally rather than by running a container: the property is that
    the one ``certify_fault`` call site passes a ``CertificationEvidenceStore``,
    and that is a fact about wiring that CI cannot exercise.
    """
    tree = ast.parse(CERTIFY_MODULE.read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "certify_fault"
    ]
    assert len(calls) == 1, "one certify_fault call site, as the module documents"
    keywords = {keyword.arg: keyword.value for keyword in calls[0].keywords}
    assert "evidence_sealer" in keywords, (
        "certify run must pass a sealer: a claim whose bytes cannot be re-verified "
        "must not reach a certified row from the surface that mints claims"
    )
    assert "CertificationEvidenceStore" in ast.unparse(keywords["evidence_sealer"]), (
        "the sealer must be the real evidence store, not a no-op"
    )


def test_the_matrix_reads_through_the_sealed_gate_not_the_bare_one() -> None:
    """``certify matrix`` must consult the gate that re-verifies the chains.

    The stricter gate is a drop-in for ``certification_gate``, so a regression to
    the bare one would compile, pass the honest-zero test, and quietly report a
    claim whose bundle had been deleted. Asserted on the call, not on behaviour,
    because the behaviour only differs once a chain is deleted — and the sealed
    fixture in ``test_cli_certify.py`` does delete one.
    """
    tree = ast.parse(CERTIFY_MODULE.read_text(encoding="utf-8"))
    gates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "gate"
    ]
    assert len(gates) == 1, "one gate call, and it is the evidence store's"
    assert "evidence.gate" in ast.unparse(gates[0]), (
        "the matrix must read through CertificationEvidenceStore.gate, which is "
        "sealed_certification_gate, not the record store's bare certification_gate"
    )
    assert "certification_gate(" not in CERTIFY_MODULE.read_text(encoding="utf-8")


# ── the CLI's own matrix, end to end ────────────────────────────────────────


def test_the_cli_matrix_reports_zero_on_a_fresh_database(tmp_path: Path) -> None:
    """The count the README quotes, asserted against the live catalogue size.

    Duplicated here rather than only in ``test_cli_certify.py`` because this is the
    file that owns the gate-arming claim, and a reader of *this* file should not
    have to take the count on faith from another one.
    """
    from click.testing import CliRunner

    from mayhem.cli.app import app
    from mayhem.domain.catalog import CATALOG

    result = CliRunner().invoke(
        app, ["--db", str(tmp_path / "fresh.db"), "certify", "matrix", "--all", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["faults_total"] == len(CATALOG)
    assert payload["certified_faults"] == 0
    assert all(row["certification"]["live"] is False for row in payload["faults"])
    assert all(
        row["maturity"]["maturity"] in {"experimental", "verified-unit"}
        for row in payload["faults"]
    ), "no live cell has been certified, so no rung above verified-unit is reachable"
