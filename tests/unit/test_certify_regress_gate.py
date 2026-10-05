"""``mayhem certify regress``: the gate a previously certified fault turns red in.

Plan 01 Phase 5 names the third of its three clock-bound things as "a
previously certified fault going red fails CI". Until this command existed,
regression blocking existed only as ``RegressionReport.blocked`` asserted
inside a test — the verdict was computed, checked by a unit test, and then
stopped. Nothing carried it to a build. This command is the part that carries
it: it exits non-zero when the report is blocked, so a pipeline running it fails
on a regression rather than on a human reading a table.

The properties below are the ones that make that exit code trustworthy, and each
is asserted from both sides so it cannot pass vacuously:

* **A green build means something was tested.** With live claims and neither
  ``--rerun`` nor ``--verdicts``, the command refuses rather than reporting no
  regressions — comparing stored claims against nothing is a pass for everything.
  A ``--fault-id`` filter that selects no live claim is refused for the same
  reason: a typo in a pipeline must not silence the gate.
* **A verdict for the wrong cell is not a pass.** It lands in ``unreached``, the
  claim survives, and the payload carries ``nothing_tested`` — because "nothing
  regressed" and "nothing was tested" are different findings and a report that
  renders them identically teaches people to trust a green it did not earn.
* **Withdrawing is opt-in and happens before reporting.** A report that changed
  what it reports on would be a report nobody could check twice, but a claim must
  also not outlive a gate that named it.
* **The verdicts file is a contract, not a suggestion.** An unrecognised file is
  refused rather than parsed, and ``--verdicts-out`` round-trips what
  ``--verdicts`` reads.

Every exit code asserted here is the one a pipeline sees. Nothing in this file
certifies anything: the re-runs come from a verdicts file, and the command says
so in its own output.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.certify import VERDICTS_SCHEMA
from mayhem.cli.exit_codes import ExitCode
from mayhem.domain.capabilities import Capability
from mayhem.domain.certification import (
    REQUIRED_EVIDENCE_DIGESTS,
    Arch,
    CellPrivilege,
    CertificationRecord,
    CertificationState,
    EvidenceBundleRef,
    MatrixCell,
)
from mayhem.domain.faults import EngineLane
from mayhem.infra.certification_repository import CertificationRepository
from mayhem.infra.store import Store

FAULT = "net.latency"
DIGEST = "d" * 64


def _cell(kernel: str = "6.1.0") -> MatrixCell:
    return MatrixCell(
        engine=EngineLane.DOCKER,
        engine_version="24.0.7",
        os_distro="debian 12",
        kernel_version=kernel,
        arch=Arch.AMD64,
        privilege=CellPrivilege.ROOT,
        capabilities=frozenset({Capability.NET_ADMIN}),
    )


def _live_record(*, cell: MatrixCell | None = None, now: datetime) -> CertificationRecord:
    """One claim that is live *against the wall clock*.

    The instant matters: this command reads the real clock, so a fixture stamped
    in the past would be honestly reported as lapsed and every assertion here
    would be about an empty gate.
    """
    bundle = EvidenceBundleRef(
        bundle_hash=DIGEST,
        mayhem_version="1.1.0.test",
        digests=dict.fromkeys(REQUIRED_EVIDENCE_DIGESTS, DIGEST),
        bundle_path="/tmp/certification/bundle.json",
    )
    return CertificationRecord(
        fault_id=FAULT,
        cell=cell or _cell(),
        injector_version="24.0.7",
        expires_at=now + timedelta(days=30),
        evidence=(bundle,),
        state=CertificationState.CERTIFIED,
        outcome="recovered",
        certified_at=now,
    )


def _db(tmp_path: Path, *, name: str = "regress.db", live: bool = True) -> str:
    """A migrated database, with one live claim unless asked otherwise."""
    from mayhem.domain.common import utc_now

    path = str(tmp_path / name)
    store = Store.open_migrated(path)
    try:
        if live:
            CertificationRepository(store).append(
                _live_record(now=utc_now()), run_id="r-seed", now=utc_now()
            )
    finally:
        store.close()
    return path


def _verdicts_file(
    tmp_path: Path,
    *,
    name: str = "verdicts.json",
    certified: bool,
    cell: MatrixCell | None,
    schema: str = VERDICTS_SCHEMA,
) -> str:
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "schema": schema,
                "generated_at": "2026-03-04T12:00:00+00:00",
                "source": "test",
                "verdicts": [
                    {
                        "fault_id": FAULT,
                        "certified": certified,
                        "cell": None if cell is None else cell.model_dump(mode="json"),
                        "detail": "the cell said no",
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return str(path)


def _run(*args: str) -> Any:
    return CliRunner().invoke(app, list(args), catch_exceptions=False)


def _payload(result: Any) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(result.output))


class TestTheGateFailsABuild:
    def test_a_red_claim_exits_non_zero(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        verdicts = _verdicts_file(tmp_path, certified=False, cell=_cell())

        result = _run("certify", "regress", "--db", db, "--verdicts", verdicts, "--json")

        assert result.exit_code == int(ExitCode.EXPERIMENT_FAILURE)
        assert _payload(result)["blocked"] is True

    def test_the_refusal_names_the_fault_and_the_cell(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        verdicts = _verdicts_file(tmp_path, certified=False, cell=_cell())

        payload = _payload(_run("certify", "regress", "--db", db, "--verdicts", verdicts, "--json"))

        assert FAULT in payload["refusal"]
        assert "6.1.0" in payload["refusal"]
        assert payload["regressed"], payload

    def test_and_a_reproduced_claim_exits_zero(self, tmp_path: Path) -> None:
        """Two-sided. A gate that always failed would pass this file's other half."""
        db = _db(tmp_path)
        verdicts = _verdicts_file(tmp_path, certified=True, cell=_cell())

        result = _run("certify", "regress", "--db", db, "--verdicts", verdicts, "--json")

        assert result.exit_code == int(ExitCode.SUCCESS)
        assert _payload(result)["blocked"] is False


class TestTheGateCannotPassWithoutTesting:
    def test_live_claims_and_no_verdicts_is_a_usage_error(self, tmp_path: Path) -> None:
        db = _db(tmp_path)

        result = _run("certify", "regress", "--db", db, "--json")

        assert result.exit_code == int(ExitCode.USAGE_ERROR)
        assert "no verdicts" in result.output

    def test_a_filter_matching_no_live_claim_is_refused(self, tmp_path: Path) -> None:
        """A typo in a pipeline must not turn the gate into a no-op."""
        db = _db(tmp_path)

        result = _run("certify", "regress", "--db", db, "--fault-id", "fs.inode", "--json")

        assert result.exit_code == int(ExitCode.USAGE_ERROR)
        assert "matched no live claim" in result.output

    def test_a_verdict_for_another_cell_is_unreached_not_a_pass(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        verdicts = _verdicts_file(tmp_path, certified=False, cell=_cell(kernel="6.6.0"))

        payload = _payload(_run("certify", "regress", "--db", db, "--verdicts", verdicts, "--json"))

        assert payload["blocked"] is False
        assert payload["unreached"] == [FAULT]

    def test_and_the_report_says_it_tested_nothing(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        verdicts = _verdicts_file(tmp_path, certified=False, cell=_cell(kernel="6.6.0"))

        result = _run("certify", "regress", "--db", db, "--verdicts", verdicts)

        assert "nothing was tested" in result.output

    def test_a_store_with_no_claims_gates_nothing_and_says_so(self, tmp_path: Path) -> None:
        """Distinct from the case above: zero claims is a real, honest zero."""
        db = _db(tmp_path, live=False)

        payload = _payload(_run("certify", "regress", "--db", db, "--json"))

        assert payload["claims_considered"] == 0
        assert payload["nothing_tested"] == ""
        assert payload["blocked"] is False


class TestWithdrawalIsOptIn:
    def _withdraw(self, tmp_path: Path) -> tuple[Any, str]:
        db = _db(tmp_path)
        verdicts = _verdicts_file(tmp_path, certified=False, cell=_cell())
        return _run("certify", "regress", "--db", db, "--verdicts", verdicts, "--json"), db

    def test_a_report_alone_withdraws_nothing(self, tmp_path: Path) -> None:
        result, db = self._withdraw(tmp_path)

        assert _payload(result)["withdrawn"] == []
        store = Store.open_migrated(db)
        try:
            latest = CertificationRepository(store).latest(FAULT)
        finally:
            store.close()
        assert latest is not None
        assert latest.record.state is CertificationState.CERTIFIED

    def test_withdraw_persists_the_demotion_through_mark_failed(self, tmp_path: Path) -> None:
        result, db = self._withdraw(tmp_path)
        result = _run(
            "certify",
            "regress",
            "--db",
            db,
            "--verdicts",
            _verdicts_file(tmp_path, name="again.json", certified=False, cell=_cell()),
            "--withdraw",
            "--json",
        )
        del result

        store = Store.open_migrated(db)
        try:
            latest = CertificationRepository(store).latest(FAULT)
        finally:
            store.close()
        assert latest is not None
        assert latest.record.state is CertificationState.FAILED
        assert "did not reproduce" in latest.record.reason


class TestTheVerdictsFileIsAContract:
    def test_an_unrecognised_file_is_refused_rather_than_parsed(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        verdicts = _verdicts_file(tmp_path, certified=True, cell=_cell(), schema="other/1")

        result = _run("certify", "regress", "--db", db, "--verdicts", verdicts)

        assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
        assert VERDICTS_SCHEMA in result.output

    def test_verdicts_out_round_trips_into_verdicts(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        written = tmp_path / "written.json"

        first = _run(
            "certify",
            "regress",
            "--db",
            db,
            "--verdicts",
            _verdicts_file(tmp_path, certified=True, cell=_cell()),
            "--verdicts-out",
            str(written),
        )

        assert first.exit_code == int(ExitCode.SUCCESS)
        assert written.is_file()
        assert json.loads(written.read_text(encoding="utf-8"))["schema"] == VERDICTS_SCHEMA
        assert _run("certify", "regress", "--db", db, "--verdicts", str(written)).exit_code == int(
            ExitCode.SUCCESS
        )

    def test_both_sources_at_once_is_refused(self, tmp_path: Path) -> None:
        db = _db(tmp_path)

        result = _run(
            "certify",
            "regress",
            "--db",
            db,
            "--rerun",
            "--verdicts",
            _verdicts_file(tmp_path, certified=True, cell=_cell()),
        )

        assert result.exit_code == int(ExitCode.USAGE_ERROR)


class TestTheSurfaceIsWired:
    """The command is in the inventories a pipeline reads to know it exists."""

    def test_it_is_registered_under_the_certify_group(self) -> None:
        import click

        assert isinstance(certify_group := _certify_group(), click.Group)
        assert "regress" in certify_group.commands

    def test_the_gate_does_not_execute_anything_unless_asked(self, tmp_path: Path) -> None:
        """`--rerun` provisions containers; the gate never does that by accident.

        A gate that provisions on a default path would start a container on every
        CI run of a pipeline nobody meant to run faults, so the default source is
        named in the output and is not a run.
        """
        db = _db(tmp_path, live=False)

        payload = _payload(_run("certify", "regress", "--db", db, "--json", "--quiet"))

        assert payload["verdicts_source"].startswith("none")
        assert "verdicts_read" in payload


def _certify_group() -> Any:
    from mayhem.cli.certify import certify

    return certify


# ── the schedule ─────────────────────────────────────────────────────────────

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/conformance.yml"
RELEASE_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"


class TestTheNightlyJobRunsOnAClock:
    """The trigger. A job that only runs when a human presses the button is a
    job nobody presses."""

    @staticmethod
    def _workflow() -> Any:
        import yaml

        return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    def test_the_workflow_declares_a_schedule(self) -> None:
        triggers = self._workflow()["on"] if "on" in self._workflow() else self._workflow()[True]

        assert "schedule" in triggers, triggers

    def test_and_the_schedule_is_a_cron_expression(self) -> None:
        triggers = self._workflow()["on"] if "on" in self._workflow() else self._workflow()[True]

        crons = [entry["cron"] for entry in triggers["schedule"]]
        assert crons
        assert all(len(cron.split()) == 5 for cron in crons), crons

    def test_the_manual_only_guard_does_not_silence_the_schedule(self) -> None:
        """``if: github.event_name == 'workflow_dispatch'`` on the job would keep
        the cron trigger from running anything at all — a green schedule that
        executes nothing, which is the failure this whole file exists to end."""
        job = self._workflow()["jobs"]["live-conformance"]

        assert "event_name" not in str(job.get("if", ""))

    def test_the_job_runs_the_regression_gate(self) -> None:
        steps = self._workflow()["jobs"]["live-conformance"]["steps"]
        runs = [str(step.get("run", "")) for step in steps]

        assert any("certify regress" in run for run in runs), runs

    def test_the_expiry_sweep_runs_on_a_clock_before_the_gate(self) -> None:
        """Ageing first, then gating.

        ``--sweep`` is opt-in because a read must not change what it reports on.
        The only place that should opt in is a job, and a job that gated before
        ageing would compare against claims the clock had already lapsed.
        """
        runs = [
            str(step.get("run", ""))
            for step in self._workflow()["jobs"]["live-conformance"]["steps"]
        ]
        sweep = next(index for index, run in enumerate(runs) if "--sweep" in run)
        gate = next(index for index, run in enumerate(runs) if "certify regress" in run)

        assert sweep < gate

    def test_and_the_release_pipeline_carries_the_same_gate(self) -> None:
        """One command, both pipelines.

        A gate that exists only in the nightly job is a gate nobody runs before
        a release, and plan 01 Phase 5 names both. On a fresh checkout it reports
        zero claims and exits clean — asserted below, so the step cannot be
        mistaken for coverage.
        """
        import yaml

        release = yaml.safe_load(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
        runs = [
            str(step.get("run", ""))
            for job in release["jobs"].values()
            for step in job.get("steps", [])
        ]

        assert any("certify regress" in run for run in runs), runs

    def test_the_shipped_gate_command_is_the_one_that_blocks(self, tmp_path: Path) -> None:
        """The workflows run a command; this is that command failing.

        Asserting the step exists proves the file says a thing. Driving the
        command it names is what proves the thing is true.
        """
        db = _db(tmp_path)
        verdicts = _verdicts_file(tmp_path, certified=False, cell=_cell())

        assert _run("certify", "regress", "--db", db, "--verdicts", verdicts).exit_code != 0, (
            "the workflow step would be green on a regression"
        )
