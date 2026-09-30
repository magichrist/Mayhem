"""`mayhem run --baseline-from`: reusing a previous run as the reference.

Plan 03 step 6. The first run establishes what "healthy" means for a stack and
every later fault is judged against *that* — the composable property neither
CNCF project has, because their probes are absolute numbers someone typed by
hand. That makes the reference a claim about provenance, and these tests pin the
three ways that claim can be broken:

* it is **threaded** — the flag reaches the evaluation that grades the run;
* it is **labelled** — the output names the reference run, or says the baseline
  was captured fresh, because an unlabelled baseline is an untrustworthy one;
* it is **refused, by name**, when the named run has nothing to offer — a silent
  fallback to a fresh capture would let an operator believe they compared
  against a reference when they did not.

The compatibility guarantee is pinned alongside: a drill with no
``steady_state:`` block renders byte-identically with and without the flag.

Every test here reaches the real ``main()`` and the real command; only the
engine is faked, because injecting a fault into a live container is not what is
under test.
"""

from __future__ import annotations

import io
import json
import re
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from mayhem.cli.app import app, main
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.steady_state import (
    Baseline,
    BaselineCapture,
    SteadyStateEvaluationRepository,
    evaluate_run,
)
from mayhem.domain.execution_intent import IMPLICIT_EXECUTION_ENV
from mayhem.domain.steady_state import SteadyStateSpec
from mayhem.infra.store import Store

TESTCASE = Path(__file__).resolve().parents[2] / "examples" / "testCase"
COMPOSE_FILE = TESTCASE / "docker-compose.yml"

#: The run id the reference lives under. Not shaped like a generated id on
#: purpose — the refusal message has to name whatever the user typed, so an
#: assertion built from a generated id would not prove that.
REFERENCE_RUN = "r-baseline-0000"

_DRILL_BODY = """\
kind: drill
apiVersion: mayhem/v1
name: {name}
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 10m
containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
execution:
  - parallel: [testcase-api]
"""

#: One signal, one `degraded` phase, one `recovered` phase: the smallest block
#: that can be graded at all. The short capture window with no declared
#: `observability` source means the fresh-capture path has nothing to read and
#: gives up at the end of the window — an ungraded report is the honest answer
#: here, and what is under test is the *provenance* label, not a grade.
_STEADY_BLOCK = """
steady_state:
  capture:
    samples: 1
    window: 1s
  signals:
    - name: api.latency.p99
      source_id: api.http
      metric: latency_ms
      tolerance:
        at_most_relative: 4.0
  phases:
    - during:
        assert_degraded: [api.latency.p99]
        within: 5.0
    - post:
        assert_recovered: [api.latency.p99]
"""

#: The reference drill's block: 80ms healthy, 300ms perturbed (inside
#: `within: 5.0`), 81ms after undo.
_REFERENCE_SPEC = SteadyStateSpec.model_validate(
    {
        "capture": {"samples": 5, "window": "10s"},
        "signals": [
            {
                "name": "api.latency.p99",
                "source_id": "api.http",
                "metric": "latency_ms",
                "tolerance": {"at_most_relative": 4.0},
            }
        ],
        "phases": [
            {"during": {"assert_degraded": ["api.latency.p99"], "within": 5.0}},
            {"post": {"assert_recovered": ["api.latency.p99"]}},
        ],
    }
)

_REFERENCE_CAPTURE = BaselineCapture(
    baselines={"api.latency.p99": Baseline(value=80.0, samples=5)},
    readings={"api.latency.p99": (80.0,) * 5},
)


def _write_spec(tmp_path: Path, name: str, *, steady_state: bool = False) -> Path:
    body = _DRILL_BODY.format(name=name)
    if steady_state:
        body += _STEADY_BLOCK
    path = tmp_path / f"{name}.yaml"
    path.write_text(body)
    return path


def _seed_run(store: Store, run_id: str) -> None:
    """The minimum a run row needs to exist for the evaluations foreign key."""
    with store.write() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO config_snapshots (id, resolved_json, source_map, created_at) "
            "VALUES (?,?,?,datetime('now'))",
            ("cfg-1", "{}", "{}"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO runs (id, experiment_name, kind, spec_json, plan_json, "
            "seed, status, environment_fingerprint, config_snapshot_id) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, "steady", "deterministic", "{}", "{}", 1, "completed", "fp-1", "cfg-1"),
        )


def _seed_reference(db: Path, run_id: str = REFERENCE_RUN) -> None:
    """A previous run that has actually graded a steady_state block."""
    store = Store.open_migrated(db)
    try:
        _seed_run(store, run_id)
        SteadyStateEvaluationRepository(store).save(
            evaluate_run(
                _REFERENCE_SPEC,
                run_id=run_id,
                capture=_REFERENCE_CAPTURE,
                during={"api.latency.p99": 300.0},
                post={"api.latency.p99": 81.0},
            )
        )
    finally:
        store.close()


class _FakeEngine:
    """Stands in for the executor: records the run, injects nothing.

    The real :class:`~mayhem.controller.executor.RunEngine` opens the run row
    before it touches the target, and ``steady_state_evaluations`` carries a
    foreign key to that row. The fake mirrors that one write — a fake that
    skipped it would only be exercising a state the tool never produces.
    """

    def __init__(self, db: Path) -> None:
        self._db = db
        self.executed: list[Any] = []

    def execute(self, plan: Any) -> Any:
        self.executed.append(plan)
        store = Store.open_migrated(self._db)
        try:
            _seed_run(store, str(plan.run_id))
        finally:
            store.close()
        return SimpleNamespace(
            run_id=plan.run_id,
            steps=(),
            observability=(),
            verdict="recovered",
            status="completed",
            dirty_leases=(),
            wall_seconds=1.0,
            summary_md=lambda: "run completed",
        )


@pytest.fixture(autouse=True)
def _no_implicit(monkeypatch: pytest.MonkeyPatch) -> None:
    """This lane is under test; the v0.9.0 default has to be what runs."""
    monkeypatch.delenv(IMPLICIT_EXECUTION_ENV, raising=False)


def _invoke(db: Path, spec: Path, *extra: str) -> tuple[int, str, str, _FakeEngine]:
    """Invoke ``mayhem run`` for real, with only the engine faked."""
    engine = _FakeEngine(db)
    out, err = io.StringIO(), io.StringIO()
    with (
        patch("mayhem.cli.services.RunEngine", return_value=engine),
        patch("mayhem.cli.lifecycle.engine_for", return_value=engine),
        redirect_stdout(out),
        redirect_stderr(err),
    ):
        code = main(
            [
                "--db",
                str(db),
                "--skip-gate",
                "run",
                str(spec),
                "-c",
                str(COMPOSE_FILE),
                "--execute",
                *extra,
            ]
        )
    return code, out.getvalue(), err.getvalue(), engine


# -- the option exists -------------------------------------------------------------


def test_run_help_documents_the_option_and_its_refusal() -> None:
    result = CliRunner().invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "--baseline-from RUN_ID" in result.output
    # Click re-wraps help to the terminal width and breaks *at* hyphens, so
    # "steady-state" can come out as "steady-\nstate". Dropping all whitespace
    # makes the sentence readable again without asserting on line breaks or on
    # where a hyphen happened to land.
    compact = "".join(result.output.split())
    # The help carries the reason the run can be refused, not just the
    # spelling: a reader who does not know a reference must be a graded run has
    # no other way to learn it before the error tells them.
    assert "mustalreadyhaverecordedsteady-stateevaluations" in compact


def test_the_option_is_declared_on_run_and_nowhere_else() -> None:
    """One command, one meaning.

    The frozen command inventories pin command *names*, not options, so a
    second command growing its own ``--baseline-from`` — with different
    semantics, or with none at all — would not turn any of them red. This is
    the assertion that notices.
    """
    declared: list[str] = []
    for name, command in app.commands.items():
        for param in command.params:
            if "--baseline-from" in getattr(param, "opts", ()):
                declared.append(name)
        for sub in getattr(command, "commands", {}).values():
            for param in sub.params:
                if "--baseline-from" in getattr(param, "opts", ()):
                    declared.append(f"{name} {sub.name}")
    assert declared == ["run"]


# -- the flag threads through -----------------------------------------------------


def test_the_flag_is_threaded_to_the_evaluation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "run.db"
    _seed_reference(db)
    spec = _write_spec(tmp_path, "steady-drill", steady_state=True)

    code, out, _err, engine = _invoke(db, spec, "--baseline-from", REFERENCE_RUN)

    assert code == int(ExitCode.SUCCESS), out
    assert len(engine.executed) == 1, "the drill did not run"
    assert f"steady_state: baseline from run {REFERENCE_RUN}" in out
    capsys.readouterr()


def test_the_report_names_the_reference_run_in_the_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The label is not decoration: it is in the persisted report.

    The operator reading the run on screen is one reader; the next person reads
    the bundle. A reference named in the first and absent from the second is a
    report nobody can check.
    """
    from mayhem.infra.evidence import load_evidence

    db = tmp_path / "run.db"
    _seed_reference(db)
    spec = _write_spec(tmp_path, "steady-drill", steady_state=True)

    code, out, _err, _engine = _invoke(db, spec, "--baseline-from", REFERENCE_RUN)
    assert code == int(ExitCode.SUCCESS), out
    capsys.readouterr()

    store = Store.open_migrated(db)
    try:
        rows = store.query(
            "SELECT DISTINCT run_id FROM steady_state_evaluations WHERE run_id != ?",
            (REFERENCE_RUN,),
        )
        assert len(rows) == 1, "the run graded nothing"
        envelope = load_evidence(store, str(rows[0]["run_id"]))
        assert envelope is not None
        assert envelope.steady_state is not None
        assert envelope.steady_state["baseline_from"] == REFERENCE_RUN
    finally:
        store.close()


def test_the_reference_baseline_is_what_gets_stored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reused numbers, not just the reused name.

    A label is cheap; the claim under it is that the run was graded against the
    reference's measurements. This reads them back out of the evaluations the
    run persisted: with the flag they are the reference's 80ms/5 samples, and
    without it they are null, because the drill declares no source to read and
    an unreadable signal is recorded as unmeasured rather than as zero.
    """
    db = tmp_path / "run.db"
    _seed_reference(db)
    spec = _write_spec(tmp_path, "steady-drill", steady_state=True)

    code, out, _err, _engine = _invoke(db, spec, "--baseline-from", REFERENCE_RUN)
    assert code == int(ExitCode.SUCCESS), out
    capsys.readouterr()
    assert _stored_baselines(db, exclude=REFERENCE_RUN) == [{"samples": 5, "value": 80.0}]

    fresh_db = tmp_path / "fresh.db"
    code, out, _err, _engine = _invoke(fresh_db, spec)
    assert code == int(ExitCode.SUCCESS), out
    capsys.readouterr()
    assert _stored_baselines(fresh_db) == [None]


def _stored_baselines(db: Path, *, exclude: str = "") -> list[Any]:
    """Every distinct baseline this database's runs stored, in rowid order."""
    store = Store.open_migrated(db)
    try:
        sql = "SELECT measured_json FROM steady_state_evaluations"
        params: tuple[Any, ...] = ()
        if exclude:
            sql += " WHERE run_id != ?"
            params = (exclude,)
        sql += " ORDER BY rowid"
        out: list[Any] = []
        for row in store.query(sql, params):
            baseline = json.loads(str(row["measured_json"])).get("baseline")
            if baseline not in out:
                out.append(baseline)
        return out
    finally:
        store.close()


def test_no_flag_captures_a_fresh_baseline_and_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Today's behaviour, labelled.

    With no flag the baseline is captured fresh, and the report says *that*
    rather than leaving the absence of a reference to be inferred. An operator
    who cannot tell whether the numbers were just measured or carried over from
    an earlier run cannot read the deltas printed underneath them.
    """
    db = tmp_path / "run.db"
    spec = _write_spec(tmp_path, "steady-drill", steady_state=True)

    code, out, _err, _engine = _invoke(db, spec)

    assert code == int(ExitCode.SUCCESS), out
    assert "baseline from run" not in out
    assert re.search(r"steady_state: baseline captured fresh for run \S+", out), out
    capsys.readouterr()


# -- the refusal ------------------------------------------------------------------


def test_a_run_with_no_recorded_evaluations_is_refused_by_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Named, explained, and before anything is injected.

    A silent fallback to a fresh capture is the failure this feature exists to
    prevent: the operator would believe they compared against one run when the
    numbers came from this run's own moment. So the refusal names the run id
    they typed, says what is missing, and reaches them before the fault is in
    the target.
    """
    db = tmp_path / "run.db"
    spec = _write_spec(tmp_path, "steady-drill", steady_state=True)
    store = Store.open_migrated(db)
    try:
        _seed_run(store, "r-known-but-ungraded")
    finally:
        store.close()

    code, _out, err, engine = _invoke(db, spec, "--baseline-from", "r-known-but-ungraded")

    assert code == int(ExitCode.USAGE_ERROR)
    assert "r-known-but-ungraded" in err
    assert "no steady-state evaluations are recorded" in err
    assert engine.executed == [], "the drill was injected despite a bad reference"
    capsys.readouterr()


def test_a_completely_unknown_run_id_is_refused_by_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "run.db"
    spec = _write_spec(tmp_path, "steady-drill", steady_state=True)

    code, _out, err, engine = _invoke(db, spec, "--baseline-from", "r-never-existed")

    assert code == int(ExitCode.USAGE_ERROR)
    assert "r-never-existed" in err
    assert "no steady-state evaluations are recorded" in err
    assert engine.executed == []
    capsys.readouterr()


def test_a_reference_missing_this_drill_s_signals_is_refused_by_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Partial reuse is refused, not half-applied.

    The reference graded a different signal set, so it has nothing to say about
    this one. Grading the signals it does have and leaving the rest bare would
    produce a report whose provenance changes line to line and still reads as a
    single comparison.
    """
    other = SteadyStateSpec.model_validate(
        {
            "capture": {"samples": 5, "window": "10s"},
            "signals": [
                {
                    "name": "api.error_rate",
                    "source_id": "api.logs",
                    "metric": "status_5xx_ratio",
                    "tolerance": {"at_most": 0.02},
                }
            ],
            "phases": [{"during": {"assert_unchanged": ["api.error_rate"]}}],
        }
    )
    db = tmp_path / "run.db"
    spec = _write_spec(tmp_path, "steady-drill", steady_state=True)
    store = Store.open_migrated(db)
    try:
        _seed_run(store, REFERENCE_RUN)
        SteadyStateEvaluationRepository(store).save(
            evaluate_run(
                other,
                run_id=REFERENCE_RUN,
                capture=BaselineCapture(
                    baselines={"api.error_rate": Baseline(value=0.001, samples=5)},
                    readings={"api.error_rate": (0.001,) * 5},
                ),
                during={"api.error_rate": 0.001},
            )
        )
    finally:
        store.close()

    code, _out, err, engine = _invoke(db, spec, "--baseline-from", REFERENCE_RUN)

    assert code == int(ExitCode.USAGE_ERROR)
    assert REFERENCE_RUN in err
    assert "api.latency.p99" in err, "the signal with no reference was not named"
    assert engine.executed == []
    capsys.readouterr()


def test_an_empty_reference_is_a_usage_error_not_a_fresh_capture(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--baseline-from "$REF"` with an unset ``$REF`` must not pass as "unset".

    The scripting hole is the whole reason: an empty value that resolved to
    "no reference" would capture a fresh baseline and print a report for a run
    the operator believes was compared against an earlier one. An empty value
    is named-but-nothing, and is refused.
    """
    spec = _write_spec(tmp_path, "steady-drill", steady_state=True)
    code, _out, err, engine = _invoke(tmp_path / "run.db", spec, "--baseline-from", "   ")

    assert code == int(ExitCode.USAGE_ERROR)
    assert "--baseline-from needs a run id" in err
    assert engine.executed == []
    capsys.readouterr()


def test_a_dry_run_previews_a_reference_it_never_needs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--dry-run` previews; it must not be refused over a reference.

    A preview reaches no engine and injects nothing, so validating the
    reference there would refuse a run the user is only looking at. The guard
    sits after the dry-run return for exactly this reason.
    """
    db = tmp_path / "run.db"
    spec = _write_spec(tmp_path, "steady-drill", steady_state=True)

    code = main(
        [
            "--db",
            str(db),
            "--skip-gate",
            "--dry-run",
            "run",
            str(spec),
            "-c",
            str(COMPOSE_FILE),
            "--execute",
            "--baseline-from",
            "r-never-existed",
        ]
    )
    assert code == int(ExitCode.SUCCESS)
    assert "r-never-existed" not in capsys.readouterr().err


# -- the compatibility guarantee --------------------------------------------------


def _normalised(text: str) -> str:
    """Blank what two invocations of *any* command cannot share, and nothing else.

    Two things are minted per invocation and are therefore unmatchable between
    two runs of the same command, flag or no flag: the run id, and the plan
    hash, which is a digest *over* that run id's snapshot pair. Everything else
    — every plan line, every safety decision, the summary, the trailing
    inspect hint — has to match byte for byte, and that is the whole point of
    the assertion.
    """
    text = re.sub(r"r-steady-drill-[0-9a-f]{8}", "r-steady-drill-XXXX", text)
    return re.sub(r"hash [0-9a-f]{12}", "hash XXXX", text)


def test_a_drill_with_no_steady_state_block_is_byte_identical(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The compatibility guarantee, with the flag on and off.

    A drill that declares no ``steady_state:`` block has nothing to compare, so
    the flag must be inert: same bytes on stdout, same bytes on stderr, same
    exit code. Any output at all here — even a note explaining that the flag
    did nothing — would change how every existing drill renders.
    """
    code_a, out_a, err_a, _ = _invoke(tmp_path / "a.db", _write_spec(tmp_path, "steady-drill"))
    code_b, out_b, err_b, _ = _invoke(
        tmp_path / "b.db",
        _write_spec(tmp_path, "steady-drill"),
        "--baseline-from",
        REFERENCE_RUN,
    )

    assert code_a == code_b
    assert _normalised(out_a) == _normalised(out_b)
    assert _normalised(err_a) == _normalised(err_b)
    assert "steady_state" not in out_b
    assert "baseline" not in out_b
    capsys.readouterr()


def test_a_drill_with_no_steady_state_block_ignores_an_unusable_reference(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Nothing to grade means nothing to validate.

    The guard resolves the reference only when the drill declares a block, so a
    run id that could never serve as a reference does not stop a drill that
    never asked for one. The two guarantees have to coexist: refusal where a
    comparison was requested, silence where none was.
    """
    spec = _write_spec(tmp_path, "steady-drill")
    code, out, _err, engine = _invoke(tmp_path / "run.db", spec, "--baseline-from", "r-nope")

    assert code == int(ExitCode.SUCCESS), out
    assert len(engine.executed) == 1
    capsys.readouterr()
