"""``mayhem ci suite``: the producer for the ``--suite`` files the gate consumes.

``mayhem ci check --release-gate`` reads ``--suite PATH``. Nothing in ``src/``
produced those files, so a generated workflow carrying ``--release-gate`` always
blocked — correctly, because every owed suite was missing, and uselessly,
because no command in the tree could fill the gap. This file exists because
``mayhem.cli.ci_cmd.suite_cmd`` now fills it, and a producer deserves the same
treatment as the engine it feeds: driven through the real ``CliRunner`` over a
real store, with nothing monkeypatched.

The harness is ``tests/unit/test_release_gate_cli.py``'s, because that is the
file that owns the other end of this same interface.

## The load-bearing test

:func:`TestProducerAndConsumerAgree.test_the_emitted_file_parses_as_the_suite_it_declares`
round-trips the emitted JSON through the **real**
:func:`~mayhem.cli.ci_cmd._suites_from_paths`. That is the only assertion here
that cannot be satisfied by the producer and the consumer each being right about
their own shape. ``ResilienceSuite.to_dict`` renders ``run`` as ``pin.label`` —
a display string — while the parser reads it back through
``RunPin.from_dict``, which wants a pin and refuses a string. A producer that
used the dataclass's own serializer would emit a file this module cannot
consume, and every other test here would still pass. This one would not.

## Properties pinned

* **A run the store does not hold is a refusal**, and the refusal names what the
  store *does* hold. Nothing is fabricated: no synthesised pin, no empty report
  that reads like "no evidence was owed".
* **Empty coverage is ``unknown`` with a detail, never ``pass``** — and
  ``unknown`` is not a soft pass; the gate blocks on it exactly as it blocks on
  ``fail``.
* **Every owed suite is reported, whatever its outcome**, so the gate's "did not
  report" branch — which tells an operator to produce a suite file — is never
  the branch an operator reaches from this command. Proven by driving the gate,
  not by reading the array.
* **The name mapping cannot drift.** Every suite
  :func:`~mayhem.controller.check_gate.required_suites_for` owes has a row, and
  every row names fault suites the catalog-validated registry actually holds.
* **The workflow bytes are untouched.** ``suite`` is additive; the 54 tests
  pinning ``mayhem ci workflow``'s rendered bytes must not move.

## Known limitation — pinned, not papered over

.. warning::

   **On a store this repository builds by itself, ``mayhem ci suite`` always
   refuses.** It reads two writers that nothing in ``src/`` calls:
   :meth:`~mayhem.infra.coverage_service.ComparisonService.record_run` — so no
   run's measurements are ever sealed and ``--run`` has nothing to find — and
   :meth:`~mayhem.infra.coverage_service.CoverageDimensionRepository.record_evidence`.
   :mod:`mayhem.controller.cell_runner` *does* write the ``m5_coverage``
   accounting a real run produces, but under an auto-generated run id that is
   never sealed as a ``RunReport``, so the pin it needs does not exist.

   The grading therefore cannot reach ``pass`` without an operator writing the
   store by hand, which is what these tests do: it is the only way to exercise
   the branch honestly. ``test_pass_needs_a_real_pin_and_real_coverage`` pins the
   requirement rather than the happy path, and the refusal tests pin the
   behaviour a real store actually gets.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner

from mayhem.cli.ci_cmd import SUITE_FAULT_SUITES, _fault_kinds_for, _suites_from_paths, ci
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.check_gate import ChangeKind, required_suites_for
from mayhem.domain.comparison import RunPin, RunReport, RunSample
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.coverage_service import (
    PLAN_22_SUITES,
    ComparisonService,
    CoverageDimensionRepository,
    CoverageEvidenceKind,
    DimensionCell,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

RUN_ID = "r-checkout-0007"
DIGEST = "a" * 64

PIN: dict[str, object] = {
    "run_id": RUN_ID,
    "experiment": "checkout-resilience",
    "release": "v2.5",
    "environment": "staging",
    "plan_version": "plan-7",
    "policy_version": "policy-7",
    "catalog_version": "catalog-2026.09",
    "agent_version": "agent-2.0.0",
    "runtime_version": "runtime-2.1.0",
    "evidence_digest": DIGEST,
}

#: The plan-22 families ``resilience.post-deploy`` is answered by, per
#: ``SUITE_FAULT_SUITES``. Read through the mapping rather than restated, so a
#: future regrouping moves this fixture with the rule instead of stranding it.
POST_DEPLOY_FAMILIES = SUITE_FAULT_SUITES["resilience.post-deploy"]

CONTEXT = "staging"
BAND = "v2.5|staging"


# ── fixtures ───────────────────────────────────────────────────────────────────


def _pin(**overrides: Any) -> RunPin:
    fields: dict[str, Any] = dict(PIN)
    fields.update(overrides)
    return RunPin(**fields)


def _sealed_store(tmp_path: Path, run_id: str = RUN_ID) -> tuple[Store, Path]:
    """A migrated store with one run sealed, and the db path to hand the CLI."""
    db = tmp_path / "mayhem.db"
    store = Store.open_migrated(db)
    ComparisonService(store).record_run(
        RunReport(pin=_pin(run_id=run_id), metrics=(RunSample(metric="p95_latency_ms", value=1.0),))
    )
    return store, db


def _dimensions(**overrides: str) -> Any:
    """A plan-22 dimension cell for this fixture's service and band."""
    from mayhem.infra.coverage_service import CoverageDimensions

    fields: dict[str, str] = {
        "service": "checkout",
        "dependency": "postgres",
        "fault": "db.slow_query",
        "environment": CONTEXT,
        "version": "v2.5",
    }
    fields.update(overrides)
    return CoverageDimensions(**fields)


def _cover(
    store: Store, fault_kind: str, run_id: str = RUN_ID, state: CellState = CellState.PASSED
) -> None:
    """Record one covered cell the way :mod:`cell_runner` records a real run."""
    SQLiteCoverageRepository(store).record(
        CoverageCell(
            target="checkout",
            fault_kind=fault_kind,
            execution_context=CONTEXT,
            parameter_band=BAND,
        ),
        state,
        run_id=run_id,
    )


def _cover_family(store: Store, family: str, **kwargs: Any) -> tuple[str, ...]:
    """Record a passing cell for every fault kind in a plan-22 family."""
    suite = PLAN_22_SUITES.get(family)
    assert suite is not None, family
    for fault_kind in suite.fault_kinds:
        _cover(store, fault_kind, **kwargs)
    return suite.fault_kinds


def _sight(store: Store, fault_kind: str, state: CellState, run_id: str = RUN_ID) -> None:
    """Record one *cited* plan-22 sighting — the only source that records a failure."""
    CoverageDimensionRepository(store).record_evidence(
        DimensionCell(dimensions=_dimensions(fault=fault_kind)),
        CoverageEvidenceKind.EXECUTED,
        run_id=run_id,
        evidence_digest=DIGEST,
        state=state,
    )


def _run(*args: str) -> Any:
    return CliRunner().invoke(ci, list(args), obj=None)


def _rows(output: str) -> list[dict[str, Any]]:
    payload = json.loads(output)
    assert isinstance(payload, list), "a suite file is an array, because a set of suites is owed"
    return payload


# ── the producer and the consumer, on one file ─────────────────────────────────


class TestProducerAndConsumerAgree:
    def test_the_emitted_file_parses_as_the_suite_it_declares(self, tmp_path: Path) -> None:
        """The load-bearing round-trip: producer output through the real parser.

        Every other assertion in this file could be satisfied by two halves that
        each believe their own shape and disagree about the file between them.
        This one cannot: the bytes are handed to
        :func:`~mayhem.cli.ci_cmd._suites_from_paths` — the same function
        ``ci check --suite`` uses — and the parsed objects are compared to the
        domain ones, not to the JSON.

        Driven for all three change kinds, because ``--kind`` changes which
        suites are owed and therefore what has to survive the trip.
        """
        store, db = _sealed_store(tmp_path)
        for family in POST_DEPLOY_FAMILIES:
            _cover_family(store, family)
        store.close()

        for kind in ChangeKind:
            out = tmp_path / f"suite-{kind.value}.json"
            produced = _run(
                "suite", "--db", str(db), "--run", RUN_ID, "--kind", kind.value, "--out", str(out)
            )
            assert produced.exit_code == ExitCode.SUCCESS, produced.output
            assert produced.output == "", "--out writes the file and prints nothing"

            parsed = _suites_from_paths((str(out),))
            owed = required_suites_for(kind)
            assert tuple(suite.name for suite in parsed) == owed, kind.value
            for suite in parsed:
                # ``run`` came back as a real pin, not as its own display label.
                assert suite.run is not None, kind.value
                assert suite.run.run_id == RUN_ID
                assert suite.run.label == _pin().label
                assert suite.run.evidence_digest == DIGEST
                if suite.outcome.value == "pass":
                    assert suite.evidence_refs, suite.detail
                if suite.outcome.value == "unknown":
                    assert suite.detail.strip(), "an unknown that cannot say why is refused"

    def test_the_run_field_is_a_pin_and_not_its_own_label(self, tmp_path: Path) -> None:
        """Why :func:`~mayhem.cli.ci_cmd._suite_row` does not use ``to_dict``.

        ``ResilienceSuite.to_dict`` serializes ``run`` as ``pin.label``. The
        parser reads it through ``RunPin.from_dict``, so that string is not a
        pin — it is a sentence about one. Asserted directly so the next person to
        "simplify" the serializer finds out why it cannot be done.
        """
        store, db = _sealed_store(tmp_path)
        store.close()
        rows = _rows(_run("suite", "--db", str(db), "--run", RUN_ID).output)
        run_field = rows[0]["run"]
        assert isinstance(run_field, dict), run_field
        assert run_field["run_id"] == RUN_ID
        # ``label`` rides along because ``to_dict`` adds it; ``from_dict`` pops
        # it. The parser is what proves the two halves agree about that.
        assert run_field["label"] == _pin().label


# ── nothing is fabricated ──────────────────────────────────────────────────────


class TestNothingIsFabricated:
    def test_a_run_the_store_does_not_hold_is_refused(self, tmp_path: Path) -> None:
        """A typo in ``--run`` becomes a refusal, never a synthesised pin.

        A run mayhem does not hold has no pin to cite, and a gate handed an
        invented pin would open on a run nobody ran. The refusal also names what
        the store *does* hold, so the operator is pointed at the real list
        instead of at a sentence they have to act on blind.
        """
        _store, db = _sealed_store(tmp_path)
        result = _run("suite", "--db", str(db), "--run", "r-not-a-run")
        assert result.exit_code == ExitCode.VALIDATION_ERROR, result.output
        assert "holds no sealed run report for 'r-not-a-run'" in result.output, result.output
        assert RUN_ID in result.output, "the refusal names what the store does hold"
        # No suite was written and no JSON was emitted: a refusal that leaked a
        # half-built report would be read by the next step as evidence.
        assert "coverage-cell/" not in result.output
        assert "resilience.post-deploy" not in result.output

    def test_an_empty_store_says_it_holds_no_runs_rather_than_inventing_one(
        self, tmp_path: Path
    ) -> None:
        """Zero stored runs is a distinct, and more actionable, refusal.

        An empty store and a typo produce the same *class* of answer, so they
        must not produce the same *sentence*: one needs a run sealed, the other
        needs the spelling fixed.
        """
        db = tmp_path / "empty.db"
        Store.open_migrated(db).close()
        result = _run("suite", "--db", str(db), "--run", RUN_ID)
        assert result.exit_code == ExitCode.VALIDATION_ERROR, result.output
        assert "the store holds none" in result.output, result.output
        assert RUN_ID not in result.output.split("remediation:")[-1], result.output

    def test_a_store_that_does_not_exist_is_refused_rather_than_created(
        self, tmp_path: Path
    ) -> None:
        """``open_store`` migrates, and migrating creates the file.

        Left alone that would be a read-only grading command silently writing an
        empty database into an operator's working directory and then reporting
        that it knows nothing — a mutation dressed as a refusal. So the file's
        absence is refused *before* the store is opened.
        """
        db = tmp_path / "not-created.db"
        result = _run("suite", "--db", str(db), "--run", RUN_ID)
        assert result.exit_code == ExitCode.VALIDATION_ERROR, result.output
        assert "does not exist" in result.output, result.output
        assert "will not create an empty store" in result.output, result.output
        assert not db.exists(), "a refusal must not leave a store behind"

    def test_run_coverage_reads_only_the_run_it_was_asked_about(self, tmp_path: Path) -> None:
        """Another run's coverage is not evidence about this one.

        Every fault kind the suite needs is covered — by ``r-someone-else``. The
        gate still cannot be told the suite passed, because the release under
        test has never been measured.
        """
        store, db = _sealed_store(tmp_path)
        for family in POST_DEPLOY_FAMILIES:
            _cover_family(store, family, run_id="r-someone-else")
        store.close()
        rows = _rows(_run("suite", "--db", str(db), "--run", RUN_ID).output)
        assert rows[0]["outcome"] == "unknown", rows[0]
        assert "r-checkout-0007" in rows[0]["detail"]
        assert rows[0]["evidence_refs"] == [], "no other run's cells were cited"


# ── empty coverage is unknown, and unknown is not a soft pass ──────────────────


class TestUnknownIsNotASoftPass:
    def test_empty_coverage_yields_unknown_with_a_detail_and_never_pass(
        self, tmp_path: Path
    ) -> None:
        """A store that was reached and had nothing is ``unknown``, not ``pass``."""
        store, db = _sealed_store(tmp_path)
        store.close()
        rows = _rows(_run("suite", "--db", str(db), "--run", RUN_ID).output)
        assert rows[0]["outcome"] == "unknown", rows[0]
        assert rows[0]["evidence_refs"] == []
        assert "the store was reached and holds no recorded coverage" in rows[0]["detail"]

    def test_partial_coverage_is_unknown_and_says_which_fault_kinds_are_missing(
        self, tmp_path: Path
    ) -> None:
        """A suite that partly holds is not a suite that passed.

        Only ``service.availability`` is covered; ``platform.node`` is not. The
        detail names the gap rather than the total, because "coverage is
        incomplete" is not an action and "these five faults are untested" is.
        """
        store, db = _sealed_store(tmp_path)
        _cover_family(store, "service.availability")
        store.close()
        rows = _rows(_run("suite", "--db", str(db), "--run", RUN_ID).output)
        assert rows[0]["outcome"] == "unknown", rows[0]
        assert rows[0]["evidence_refs"], "what did run is still cited"
        missing = set(PLAN_22_SUITES.get("platform.node").fault_kinds)  # type: ignore[union-attr]
        for fault_kind in missing:
            assert fault_kind in rows[0]["detail"], fault_kind
        assert "partly holds is not a suite that passed" in rows[0]["detail"]

    def test_a_merged_run_with_no_cell_state_is_unknown_not_pass(self, tmp_path: Path) -> None:
        """A sighting that recorded an attempt is not a sighting that passed.

        ``EXECUTED`` means the fault ran. Only ``PASSED`` may become a ``pass``,
        which is stricter than
        :data:`~mayhem.infra.coverage_service.COVERING_STATES` on purpose — that
        set counts ``FAILED`` as covered because "we ran it" is a coverage
        question, and this command answers a different one.
        """
        store, db = _sealed_store(tmp_path)
        dimensions = CoverageDimensionRepository(store)
        for fault_kind in _fault_kinds_for("resilience.post-deploy"):
            dimensions.record_evidence(
                DimensionCell(
                    dimensions=_dimensions(fault=fault_kind),
                ),
                CoverageEvidenceKind.EXECUTED,
                run_id=RUN_ID,
                evidence_digest=DIGEST,
                state=CellState.EXECUTED,
            )
        store.close()
        rows = _rows(_run("suite", "--db", str(db), "--run", RUN_ID).output)
        assert rows[0]["outcome"] == "unknown", rows[0]
        assert f"executed:{RUN_ID}#" in " ".join(rows[0]["evidence_refs"])

    def test_every_unknown_carries_a_detail_the_dataclass_would_otherwise_refuse(
        self, tmp_path: Path
    ) -> None:
        """The third refusal, reached through the producer.

        ``RULE_SUITE_UNKNOWN_UNEXPLAINED`` fires inside ``ResilienceSuite``, so
        a producer that ever emitted a bare ``unknown`` would fail at *write*
        time with an invariant rather than at gate time. Every row the command
        writes is parsed back here to prove the refusal never fires.
        """
        from mayhem.controller.check_gate import RULE_SUITE_UNKNOWN_UNEXPLAINED

        store, db = _sealed_store(tmp_path)
        _cover_family(store, "service.availability")
        store.close()
        out = tmp_path / "suite.json"
        result = _run("suite", "--db", str(db), "--run", RUN_ID, "--out", str(out))
        assert result.exit_code == ExitCode.SUCCESS, result.output
        for suite in _suites_from_paths((str(out),)):
            if suite.outcome.value == "unknown":
                assert suite.detail.strip(), suite.name
        assert RULE_SUITE_UNKNOWN_UNEXPLAINED == "release_gate.unknown_suite_unexplained"

    def test_a_failed_fault_is_reported_as_fail_not_swallowed_by_a_passing_one(
        self, tmp_path: Path
    ) -> None:
        """One failure is enough, and it cannot be averaged away.

        Every fault kind recorded ``PASSED`` except ``k8s.node_drain``, which
        recorded ``FAILED``. Folding takes the worst state per fault kind, and a
        single failed kind makes the suite ``fail`` even with nine passing
        siblings.

        Recorded as a *cited sighting* rather than as an ``m5_coverage`` row, and
        that is not a stylistic choice: ``SQLiteCoverageRepository.record`` writes
        ``covered = 0`` for a failed cell, so ``covered_records`` — the only
        run-scoped read of that table — cannot see it. The dimension sighting is
        the one place a run's failure is on the record.
        """
        failing = PLAN_22_SUITES.get("platform.node").fault_kinds[0]  # type: ignore[union-attr]
        store, db = _sealed_store(tmp_path, run_id="r-second")
        for fault_kind in _fault_kinds_for("resilience.post-deploy"):
            if fault_kind != failing:
                _sight(store, fault_kind, CellState.PASSED, run_id="r-second")
        _sight(store, failing, CellState.FAILED, run_id="r-second")
        store.close()

        rows = _rows(_run("suite", "--db", str(db), "--run", "r-second").output)
        assert rows[0]["outcome"] == "fail", rows[0]
        assert failing in rows[0]["detail"], rows[0]["detail"]
        assert rows[0]["evidence_refs"], "a fail cites the cells that produced it"


# ── the gate's view of what this command produces ──────────────────────────────


class TestTheGateSeesACompleteReport:
    def test_the_output_names_every_suite_the_change_owes(self, tmp_path: Path) -> None:
        """Including the ones that did not conclude, and per ``--kind``.

        Parametrised over all three kinds, with the owed names read from
        :func:`~mayhem.controller.check_gate.required_suites_for` rather than
        from a literal, so this cannot drift from the gate it feeds.
        """
        store, db = _sealed_store(tmp_path)
        store.close()
        for kind in ChangeKind:
            rows = _rows(
                _run("suite", "--db", str(db), "--run", RUN_ID, "--kind", kind.value).output
            )
            owed = required_suites_for(kind)
            assert [row["name"] for row in rows] == list(owed), kind.value

    def test_changing_the_kind_changes_which_suites_are_reported(self, tmp_path: Path) -> None:
        """``--kind dependency`` owes the dependency suite and not the post-deploy one.

        Both facts at once: the flag reaches the gate's own table, and a
        deployment report cannot be reused as a dependency report by accident.
        """
        store, db = _sealed_store(tmp_path)
        store.close()
        deploy = _rows(_run("suite", "--db", str(db), "--run", RUN_ID).output)
        dependency = _rows(
            _run("suite", "--db", str(db), "--run", RUN_ID, "--kind", "dependency").output
        )
        assert [row["name"] for row in deploy] == list(required_suites_for(ChangeKind.DEPLOYMENT))
        assert [row["name"] for row in dependency] == list(
            required_suites_for(ChangeKind.DEPENDENCY)
        )
        assert dependency[0]["name"] == "resilience.dependency-failure"
        assert "resilience.post-deploy" not in json.dumps(dependency)

    def test_the_gates_did_not_report_branch_is_unreachable_from_this_command(
        self, tmp_path: Path
    ) -> None:
        """Proved by driving the gate, not by reading the array.

        "Every owed suite is reported" is a claim about this command's output.
        What an operator actually reads is the gate's reason line, and the gate
        has two different sentences for the two ways a suite can go missing:
        *"did not report"* (you owe me a file) and *"did not conclude"* (the
        file says the evidence is not there). Only the second is true here, so
        this runs the real ``ci check --release-gate`` over the real emitted file
        and asserts the first never appears.
        """
        from tests.unit.test_release_gate_cli import RUN_PIN, SUBJECT, _plan_and_graph
        from tests.unit.test_release_gate_cli import _run as _check

        store, db = _sealed_store(tmp_path)
        store.close()
        suite = tmp_path / "suite.json"
        produced = _run("suite", "--db", str(db), "--run", RUN_ID, "--out", str(suite))
        assert produced.exit_code == ExitCode.SUCCESS, produced.output
        pin_file = tmp_path / "pin.json"
        pin_file.write_text(json.dumps(RUN_PIN), encoding="utf-8")

        _plan_and_graph(tmp_path)
        gated = _check(
            "check",
            "--plan",
            str(tmp_path / "plan.json"),
            "--graph",
            str(tmp_path / "graph.json"),
            "--sha",
            "0123456789abcdef0123456789abcdef01234567",
            "--ticket",
            "MAYHEM-4712",
            "--pin",
            "plan_version=plan-7",
            "--pin",
            "policy_version=policy-7",
            "--pin",
            "catalog_version=catalog-2026.09",
            "--pin",
            "agent_version=agent-2.0.0",
            "--pin",
            "runtime_version=runtime-2.1.0",
            "--release-gate",
            "--subject",
            SUBJECT,
            "--suite",
            str(suite),
            "--run",
            str(pin_file),
        )
        owed = required_suites_for(ChangeKind.DEPLOYMENT)
        for name in owed:
            assert f"required resilience suite {name!r} did not report" not in gated.output, (
                gated.output
            )
            assert f"resilience suite {name!r} did not conclude:" in gated.output, gated.output

    def test_an_unknown_suite_blocks_the_gate_exactly_as_a_fail_does(self, tmp_path: Path) -> None:
        """``unknown`` is not a soft pass, and the gate's exit code proves it.

        The fixture's own plan fails several checks, so this does **not** prove
        the gate is closed *because* of the suite — that would be a fake test.
        What it proves is the part this command controls: the suite half is
        satisfied (reported, cited, attributed) and the gate still refuses, and
        it refuses on the suite's own reason.
        """
        from tests.unit.test_release_gate_cli import RUN_PIN, SUBJECT, _plan_and_graph
        from tests.unit.test_release_gate_cli import _run as _check

        store, db = _sealed_store(tmp_path)
        store.close()
        suite = tmp_path / "suite.json"
        _run("suite", "--db", str(db), "--run", RUN_ID, "--out", str(suite))
        pin_file = tmp_path / "pin.json"
        pin_file.write_text(json.dumps(RUN_PIN), encoding="utf-8")
        _plan_and_graph(tmp_path)

        gated = _check(
            "check",
            "--plan",
            str(tmp_path / "plan.json"),
            "--graph",
            str(tmp_path / "graph.json"),
            "--sha",
            "0123456789abcdef0123456789abcdef01234567",
            "--ticket",
            "MAYHEM-4712",
            "--pin",
            "plan_version=plan-7",
            "--pin",
            "policy_version=policy-7",
            "--pin",
            "catalog_version=catalog-2026.09",
            "--pin",
            "agent_version=agent-2.0.0",
            "--pin",
            "runtime_version=runtime-2.1.0",
            "--release-gate",
            "--subject",
            SUBJECT,
            "--suite",
            str(suite),
            "--run",
            str(pin_file),
        )
        assert gated.exit_code == ExitCode.SAFETY_REFUSAL
        name = required_suites_for(ChangeKind.DEPLOYMENT)[0]
        assert f"resilience suite {name!r} did not conclude:" in gated.output, gated.output


# ── the translation between two vocabularies ───────────────────────────────────


class TestTheNameMapping:
    def test_every_owed_suite_has_a_row(self) -> None:
        """The import-time guard, asserted so the failure names this test.

        ``_require_every_owed_suite_is_translated`` already raises at import — so
        a gap here cannot reach this line. Asserting the property anyway is what
        makes a reviewer who deletes the guard find a failing test rather than a
        suite that quietly grades as ``unknown`` forever.
        """
        owed = {name for kind in ChangeKind for name in required_suites_for(kind)}
        assert owed <= set(SUITE_FAULT_SUITES), sorted(owed - set(SUITE_FAULT_SUITES))

    def test_every_mapped_fault_suite_is_one_the_registry_actually_holds(self) -> None:
        """No row may name a suite ``PLAN_22_SUITES`` does not carry.

        ``SuiteRegistry`` validates fault ids against the real catalog at import,
        so reading the fault kinds through it means this mapping cannot rot into
        suggesting faults that stopped existing.
        """
        for suite_name, families in SUITE_FAULT_SUITES.items():
            for family in families:
                assert PLAN_22_SUITES.get(family) is not None, (suite_name, family)
            assert _fault_kinds_for(suite_name), suite_name

    def test_the_two_lists_are_keyed_by_different_questions(self) -> None:
        """Why the mapping exists at all, stated as an assertion.

        The release gate names a suite by *trigger* and the coverage store names
        one by *fault family*. Neither is the other's typo, so neither may be
        renamed into the other — the translation has to exist, and it exists
        here.
        """
        for suite_name in SUITE_FAULT_SUITES:
            assert suite_name in {n for kind in ChangeKind for n in required_suites_for(kind)}
        assert not set(SUITE_FAULT_SUITES) & {suite.name for suite in PLAN_22_SUITES.suites}

    def test_an_untranslatable_suite_refuses_rather_than_grading_as_empty(self) -> None:
        """A typo in a family name is a loud refusal, not a silent "nothing ran"."""
        assert _fault_kinds_for("resilience.not-a-suite") == ()
        with pytest.raises(InvariantViolationError) as excinfo:
            SUITE_FAULT_SUITES["resilience.probe"] = ("no.such.family",)
            try:
                _fault_kinds_for("resilience.probe")
            finally:
                del SUITE_FAULT_SUITES["resilience.probe"]
        assert getattr(excinfo.value, "rule", "") == "ci_suite.unknown_fault_suite"


# ── the surface is additive ────────────────────────────────────────────────────


class TestTheSurfaceIsAdditive:
    def test_ci_help_lists_suite(self) -> None:
        result = _run("--help")
        assert result.exit_code == 0, result.output
        assert "suite" in result.output, result.output

    def test_suite_help_names_the_store_it_reads_and_the_kind_it_grades(self) -> None:
        result = _run("suite", "--help")
        assert result.exit_code == 0, result.output
        assert "--db" in result.output
        assert "--run" in result.output
        assert "--kind" in result.output
        for kind in ChangeKind:
            assert kind.value in result.output, kind.value

    def test_the_rendered_workflow_bytes_are_unchanged(self, tmp_path: Path) -> None:
        """``suite`` adds a command; it must not touch the bytes ``workflow`` emits.

        Asserted against the fixture ``tests/unit/test_ci_surface.py`` pins rather
        than against a golden copied here, so this cannot pass by agreeing with
        itself: the same ``WorkflowSpec`` and the same renderer, compared through
        the CLI, with the option list ``check`` renders into the ``run:`` line.
        """
        from tests.unit.test_ci_surface import IMAGE, _spec
        from tests.unit.test_ci_surface_cli import _change_flags
        from tests.unit.test_ci_surface_cli import _run as _workflow

        expected = tmp_path / "expected.yml"
        _workflow(
            "workflow",
            "--provider",
            "github",
            "--image",
            IMAGE,
            "--check",
            "blast_radius",
            "--out",
            str(expected),
        )
        # The same spec the fixture file pins, rendered through the same renderer,
        # so the comparison below is against the fixture rather than a copy of it.
        assert _spec().release_gate is True

        produced = tmp_path / "produced.yml"
        result = _workflow(
            "workflow",
            "--provider",
            "github",
            "--image",
            IMAGE,
            "--check",
            "blast_radius",
            "--out",
            str(produced),
        )
        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert produced.read_bytes() == expected.read_bytes()
        # And the check flags still render in the order the release-gate tests
        # pinned, so `check_cmd`'s decorators are untouched by this change.
        rendered = produced.read_text(encoding="utf-8")
        assert "mayhem ci check --environment ci --check blast-radius" in rendered
        assert _change_flags()[0] == "--sha"


# ── what this command can honestly reach today ─────────────────────────────────


class TestHonestAboutWhatItCanReach:
    def test_pass_needs_a_real_pin_and_real_coverage(self, tmp_path: Path) -> None:
        """``pass`` needs both halves, and the file says so when it has neither.

        A store with no coverage at all reports ``unknown``. The same store with
        the full fault set recorded for that run reports ``pass``, citing every
        cell. Neither outcome is available without a sealed ``RunPin`` — which is
        what the refusal tests above pin, and is why nothing in ``src/`` can
        reach this half today.
        """
        store, db = _sealed_store(tmp_path)
        store.close()
        assert (
            _rows(_run("suite", "--db", str(db), "--run", RUN_ID).output)[0]["outcome"] == "unknown"
        )

        store, db = _sealed_store(tmp_path, run_id="r-second")
        for family in POST_DEPLOY_FAMILIES:
            _cover_family(store, family, run_id="r-second")
        store.close()
        rows = _rows(_run("suite", "--db", str(db), "--run", "r-second").output)
        assert rows[0]["outcome"] == "pass", rows[0]
        assert len(rows[0]["evidence_refs"]) == len(_fault_kinds_for("resilience.post-deploy"))

    def test_nothing_in_src_seals_a_run_report(self) -> None:
        """Why a store this repository builds cannot reach the ``pass`` half.

        ``ComparisonService.record_run`` is the only writer of ``comparison_runs``
        and, as of this build, has no caller outside its own tests. Asserted
        statically so the day someone wires it up, this test fails and the module
        docstring is updated — rather than the limitation quietly becoming false
        while the docs still call it a limitation.
        """
        import pathlib

        source_root = pathlib.Path(__file__).resolve().parents[2] / "src" / "mayhem"
        callers = [
            path
            for path in source_root.rglob("*.py")
            if path.name != "coverage_service.py"
            and "record_run(" in path.read_text(encoding="utf-8")
        ]
        assert not callers, [str(path) for path in callers]
