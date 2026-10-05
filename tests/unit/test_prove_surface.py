"""``mayhem prove`` — the safety proof as something a person reads (plan 30 Phase 3).

Phase 2's compiler ran the real gates and Phase 4 sealed the result, but both
were reachable only from Python: "here is why this plan is allowed" existed as an
object and not as an artifact a reviewer could be handed. This suite is about the
last link, and about the three properties of it that are easy to fake:

* **every ``pass`` line is printed beside its citation.** A citation nobody is
  shown is a citation nobody checks, so the golden rendering asserts a
  ``[cite <digest> | <evidence_ref>]`` on every established line and asserts the
  count of citations equals the count of lines that claim a gate ran.
* **a stale proof renders VOID with the diff that voided it**, driven end to end
  through the real CLI: prove a plan, move the plan in the store (a canonical
  digest mutation, the plan's own void-on-change test), re-check the artifact,
  and read the diff. The submitted lines are rendered as submitted — the artifact
  is the one the reviewer was handed, not a rewritten one.
* **a required line the proof does not carry prints ``absent``,** because "not
  checked" is not "checked and negative" and an artifact that quietly omitted it
  would read as a shorter proof rather than a weaker one.

Two honest facts about this build are pinned rather than hidden. First, the CLI
supplies no runtime adapter, so the capability line cannot be established here
and the compiled proof renders VOID with that reason named — the fail-closed
state, not a graceful one. Second, the FAIL verdict is reachable only where a
caller supplies an adapter, so it is asserted at the view-model layer with a
proof built the way the compiler builds one. Asserting a FAIL through the CLI
would require inventing a live engine this repository does not have.

One deviation is pinned as deliberately as the behaviour: the plan named this
command ``mayhem plan prove`` and it is registered as ``mayhem prove``, because
``plan`` is in the removal inventory and a retired name must stay retired.

Timestamps and digests are injected or masked; nothing here reads a wall clock to
decide a verdict.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner

from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.proof_cmd import (
    STATUS_ABSENT,
    ObligationDiff,
    build_proof_view,
    exit_code_for,
    proof_payload,
    prove,
    render_proof_lines,
)
from mayhem.controller.safety_proof import canonical_plan_digest, compile_safety_proof
from mayhem.domain.safety_proof import (
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    SafetyProof,
)

if TYPE_CHECKING:
    from pathlib import Path

    from mayhem.cli.services import RecordedRun
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.store import Store

RUN_ID = "r-prove"
FP = "fp-prove"
STEP_S = 30.0

_DIGEST = re.compile(r"\b[0-9a-f]{64}\b")


# ── fixtures: the recorded-run shape `risk-preview` and `prove` both read ─────


def _graph() -> TopologyGraph:
    from mayhem.domain.topology import Edge, EdgeKind, ServiceNode, TopologyGraph

    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-db", name="db"),
            ServiceNode(id="n-api", name="api"),
            ServiceNode(id="n-web", name="web"),
        ),
        edges=(
            Edge(src="n-api", dst="n-db", kind=EdgeKind.DEPENDS_ON),
            Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON),
        ),
    )


def _plan(*, run_id: str = RUN_ID, duration: float = STEP_S) -> ExecutionPlan:
    from mayhem.domain.experiments import (
        ExecutionPlan,
        ExperimentKind,
        InjectFault,
        PlannedFault,
        PlannedStep,
        ResolvedTarget,
    )
    from mayhem.domain.topology import TargetSelector

    graph = _graph()
    node = graph.by_id("n-web")
    assert node is not None
    selector = TargetSelector(kind=node.kind, expr=node.name)
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id="s0",
                seq=0,
                raw_action=InjectFault(
                    fault="net.latency", selectors=(selector,), duration=duration
                ),
                fault=PlannedFault(
                    fault_id="net.latency",
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-web"})),),
                    duration=duration,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id=f"t-{run_id}",
        environment_fingerprint=FP,
    )


def _seed_run(store: Store, the_plan: ExecutionPlan, *, snapshot: bool = True) -> None:
    snapshot_id = f"t-{the_plan.run_id}" if snapshot else None
    with store.write() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO config_snapshots (id, resolved_json, source_map, created_at)"
            " VALUES ('c', '{}', '{}', 'now')"
        )
        if snapshot:
            conn.execute(
                "INSERT INTO topology_snapshots (id, run_id, graph_json, drift_report, fingerprint)"
                " VALUES (?, NULL, ?, '{}', ?)",
                (snapshot_id, _graph().model_dump_json(), FP),
            )
        conn.execute(
            "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed, status,"
            " environment_fingerprint, config_snapshot_id, topology_snapshot_id)"
            " VALUES (?, 'exp', 'deterministic', '{}', ?, 1, 'created', ?, 'c', ?)",
            (the_plan.run_id, the_plan.model_dump_json(), FP, snapshot_id),
        )


def _move_plan(store: Store, run_id: str, *, duration: float) -> None:
    """The canonical-hash mutation: one field, a different digest, the same run."""
    with store.write() as conn:
        conn.execute(
            "UPDATE runs SET plan_json = ? WHERE id = ?",
            (_plan(run_id=run_id, duration=duration).model_dump_json(), run_id),
        )


def _ctx_obj(db: str) -> Any:
    from mayhem.cli.context import CliContext

    return CliContext(db=db)


def _invoke(db: str, *args: str) -> Any:
    return CliRunner().invoke(prove, list(args), obj=_ctx_obj(db), catch_exceptions=False)


@pytest.fixture()
def db(tmp_path: Path) -> str:
    """A migrated store with one recorded run, its path handed back for the CLI."""
    from mayhem.cli.services import open_store

    path = str(tmp_path / "prove.db")
    store = open_store(path)
    try:
        _seed_run(store, _plan())
    finally:
        store.close()
    return path


def _opened(db: str) -> Store:
    from mayhem.cli.services import open_store

    return open_store(db)


def _compiled(db: str, *, run_id: str = RUN_ID) -> SafetyProof:
    from mayhem.cli.services import gate_context_for_plan, load_recorded_run

    store = _opened(db)
    try:
        recorded: RecordedRun = load_recorded_run(store, run_id)
    finally:
        store.close()
    assert recorded.graph is not None
    return compile_safety_proof(
        recorded.plan,
        recorded.graph,
        gate_context_for_plan(fingerprint=recorded.environment_fingerprint),
        target_identity=run_id,
    )


def _golden(lines: tuple[str, ...]) -> list[str]:
    """The rendered artifact with every digest masked, so the golden is stable."""
    return [_DIGEST.sub("<digest>", line) for line in lines]


# ── the golden rendering ─────────────────────────────────────────────────────


class TestTheGoldenRendering:
    def test_the_rendered_artifact_is_exactly_these_lines(self, db: str) -> None:
        view = build_proof_view(_compiled(db), run_id=RUN_ID)
        golden = _golden(render_proof_lines(view))

        assert golden[0] == "SAFETY PROOF: VOID"
        assert golden[1] == f"run: {RUN_ID}"
        assert golden[2] == "plan digest: <digest>"
        assert golden[3] == "proof digest: <digest>"
        assert golden[4].startswith("void: lines not established: ")
        assert golden[5] == ""
        body = golden[6:]
        assert [line.split()[0] for line in body if line] == [
            "pass",  # max_concurrent_faults
            "pass",  # max_duration
            "pass",  # damage_budget
            "pass",  # target_policy
            "void",  # capability_requirements: no adapter in this build
            "fail",  # compensation: a bare fault carries no undo contract
            "fail",  # recovery_path: no verify probe promises nothing observable
            "pass",  # stop_conditions
            "pass",  # required_approvals
        ]
        assert golden[-1].split()[0] == "pass"
        assert golden[-1].split()[1] == "required_approvals"

    def test_the_spine_is_the_nine_lines_in_catalogue_order(self, db: str) -> None:
        from mayhem.domain.safety_proof import ObligationName

        view = build_proof_view(_compiled(db), run_id=RUN_ID)
        carried = [line.name for line in view.lines if line.status != STATUS_ABSENT]
        assert carried == [name.value for name in ObligationName]

    def test_every_established_line_cites_a_gate_output(self, db: str) -> None:
        view = build_proof_view(_compiled(db), run_id=RUN_ID)
        for line in view.lines:
            if line.status == STATUS_ABSENT:
                assert line.gate_digest == ""
                continue
            assert len(line.gate_digest) == 64, line
            assert line.evidence_ref.startswith("gate-output/"), line
            assert f"[cite {line.gate_digest[:12]} | {line.evidence_ref}]" in line.render()

    def test_the_cli_renders_the_same_lines_with_the_refusal_exit_code(
        self, db: str, tmp_path: Path
    ) -> None:
        result = _invoke(db, RUN_ID)
        assert result.exit_code == ExitCode.SAFETY_REFUSAL
        assert result.output.splitlines()[0] == "SAFETY PROOF: VOID"

    def test_the_json_payload_is_the_same_structure(self, db: str) -> None:
        view = build_proof_view(_compiled(db), run_id=RUN_ID)
        payload = proof_payload(view)
        assert payload["schema_version"] == "1.0"
        assert payload["verdict"] == "VOID"
        assert payload["stale"] is False
        assert payload["run_id"] == RUN_ID
        assert [line["name"] for line in payload["obligations"]] == [
            name.value for name in ObligationName
        ]
        # Both projections off one structure: every claim in the rendered lines
        # appears in the payload, which is what makes a second renderer unable
        # to drift.
        rendered = "\n".join(render_proof_lines(view))
        for line in payload["obligations"]:
            assert line["name"] in rendered
            assert line["status"] in rendered

    def test_writes_nothing(self, db: str) -> None:
        store = _opened(db)
        try:

            def counts() -> dict[str, int]:
                return {
                    table: store.query(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"]
                    for table in ("runs", "observations", "audit_entries")
                }

            before = counts()
        finally:
            store.close()
        _invoke(db, RUN_ID)
        store = _opened(db)
        try:
            assert counts() == before
        finally:
            store.close()


# ── absent lines ──────────────────────────────────────────────────────────────


class TestAbsentLines:
    def test_a_missing_required_line_prints_as_absent(self, db: str) -> None:
        proof = _compiled(db)
        trimmed = proof.model_validate(
            {
                **proof.model_dump(),
                "obligations": tuple(o for o in proof.obligations if o.name != "damage_budget"),
                "verdict": ProofVerdict.VOID,
                "void_reason": "missing lines",
            }
        )
        view = build_proof_view(trimmed, run_id=RUN_ID)
        absent = [line for line in view.lines if line.status == STATUS_ABSENT]
        assert [line.name for line in absent] == ["damage_budget"]
        rendered = "\n".join(render_proof_lines(view))
        assert f"{STATUS_ABSENT}  damage_budget" in rendered
        assert "not checked is not checked and passed" in rendered

    def test_absent_lines_cite_nothing(self, db: str) -> None:
        proof = _compiled(db)
        trimmed = proof.model_validate(
            {
                **proof.model_dump(),
                "obligations": proof.obligations[:3],
                "verdict": ProofVerdict.VOID,
                "void_reason": "missing lines",
            }
        )
        view = build_proof_view(trimmed, run_id=RUN_ID)
        assert all(line.gate_digest == "" for line in view.lines if line.status == STATUS_ABSENT)


# ── void on change ────────────────────────────────────────────────────────────


class TestVoidOnChange:
    def test_a_moved_plan_renders_void_with_the_diff(self, db: str, tmp_path: Path) -> None:
        # Prove the plan as recorded, then move one field of the frozen plan and
        # re-check the artifact. The digest is canonical over the plan, so this
        # is the plan's own void-on-change test driven through the surface.
        before = _compiled(db)
        artifact = tmp_path / "proof.json"
        result = _invoke(db, RUN_ID, "--json")
        artifact.write_text(result.output, encoding="utf-8")

        _move_plan(_opened(db), RUN_ID, duration=STEP_S + 10)
        after = _compiled(db)
        assert after.plan_digest != before.plan_digest

        checked = _invoke(db, RUN_ID, "--check", str(artifact))
        assert checked.exit_code == ExitCode.SAFETY_REFUSAL
        assert "SAFETY PROOF: VOID" in checked.output
        assert "THIS PROOF WAS COMPILED AGAINST A DIFFERENT PLAN" in checked.output
        assert before.plan_digest in checked.output

    def test_the_diff_names_the_line_that_moved(self, db: str, tmp_path: Path) -> None:
        submitted = _compiled(db)
        _move_plan(_opened(db), RUN_ID, duration=STEP_S + 10)
        current = _compiled(db)

        view = build_proof_view(
            submitted.voided(current.plan_digest), run_id=RUN_ID, current=current
        )
        assert view.stale
        assert view.verdict == "VOID"
        assert "plan superseded" in view.void_reason
        assert any(entry.was != entry.now or entry.citation_moved for entry in view.diffs), (
            view.diffs
        )
        assert any(entry.name == "max_duration" for entry in view.diffs), view.diffs
        rendered = "\n".join(render_proof_lines(view))
        assert "max_duration" in rendered

    def test_an_unchanged_plan_reports_no_diff(self, db: str) -> None:
        proof = _compiled(db)
        view = build_proof_view(proof, run_id=RUN_ID, current=_compiled(db))
        assert view.stale is False
        assert view.diffs == ()

    def test_the_diff_distinguishes_a_status_change_from_a_citation_change(self, db: str) -> None:
        proof = _compiled(db)
        first = next(o for o in proof.obligations if o.status is ObligationStatus.PASS)

        # Same verdict, different evidence: the line kept its answer and moved
        # what it cites, which is a change a status-only diff would hide.
        recited = Obligation(
            name=first.name,
            status=first.status,
            gate_digest="a" * 64,
            evidence_ref="gate-output/other:source",
            detail=first.detail,
        )
        swapped = proof.model_validate(
            {
                **proof.model_dump(),
                "obligations": tuple(
                    recited if o.name == first.name else o for o in proof.obligations
                ),
            }
        )
        view = build_proof_view(proof, run_id=RUN_ID, current=swapped)
        assert view.diffs == (
            ObligationDiff(
                name=first.name,
                was=first.status.value,
                now=first.status.value,
                citation_moved=True,
            ),
        )
        assert "(citation changed)" in view.diffs[0].render()

    def test_a_hand_written_pass_is_refused_rather_than_checked(
        self, db: str, tmp_path: Path
    ) -> None:
        # Plan 30's own negative control: a PASS without gate outputs fails
        # validation. The artifact never reaches the diff logic, because a proof
        # that does not validate was not produced by the compiler.
        forged = {
            "plan_digest": "b" * 64,
            "verdict": "PASS",
            "obligations": [{"name": name.value, "status": "pass"} for name in ObligationName],
        }
        path = tmp_path / "forged.json"
        path.write_text(json.dumps(forged), encoding="utf-8")
        with pytest.raises(MayhemCliError) as excinfo:
            _load(str(path))
        assert "not a safety proof mayhem will accept" in str(excinfo.value)
        assert "pass_requires_cited_gate_digest" in str(excinfo.value)


def _load(path: str) -> Any:
    """The loader the command uses, called directly for the refusal contract."""
    from mayhem.cli.proof_cmd import _load_proof

    return _load_proof(path)


# ── the refusals ──────────────────────────────────────────────────────────────


class TestTheRefusals:
    def test_an_unknown_run_is_refused(self, db: str) -> None:
        # The refusal is rendered by this surface's own handler, so the assertion
        # is the exit code and the rendered line, the way a pipeline reads it.
        result = _invoke(db, "r-nope")
        assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
        assert "no such run 'r-nope'" in result.output
        assert "mayhem inspect runs" in result.output

    def test_a_run_with_no_snapshot_is_refused(self, db: str) -> None:
        _seed_run(_opened(db), _plan(run_id="r-nosnap"), snapshot=False)
        result = _invoke(db, "r-nosnap")
        assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
        assert "no topology snapshot" in result.output
        assert "re-plan the run against current topology" in result.output

    def test_a_missing_artifact_is_refused_before_the_store_is_touched(
        self, db: str, tmp_path: Path
    ) -> None:
        with pytest.raises(MayhemCliError) as excinfo:
            _load(str(tmp_path / "absent.json"))
        assert "no proof artifact" in str(excinfo.value)

    def test_an_unparsable_artifact_is_refused_as_unreadable_not_stale(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "junk.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(MayhemCliError) as excinfo:
            _load(str(path))
        assert "cannot be read" in str(excinfo.value)


# ── residue, and the honest states of this build ─────────────────────────────


class TestResidueAndTheHonestStates:
    def test_residue_lines_are_additional_and_undischarged_is_said(self, db: str) -> None:
        from mayhem.cli.services import gate_context_for_plan, load_recorded_run

        store = _opened(db)
        try:
            recorded = load_recorded_run(store, RUN_ID)
        finally:
            store.close()
        assert recorded.graph is not None
        proof = compile_safety_proof(
            recorded.plan,
            recorded.graph,
            gate_context_for_plan(fingerprint=recorded.environment_fingerprint),
            target_identity=RUN_ID,
            include_residue=True,
        )
        view = build_proof_view(proof, run_id=RUN_ID)
        residue = [line for line in view.lines if line.name.startswith("residue:")]
        assert residue, "the plan's fault carries residue obligations"
        assert all(line.status == "void" for line in residue), residue

        # The disclosure that they are undischarged is the command's, so it is
        # asserted on the command's rendering rather than on the view-model.
        rendered = _invoke(db, RUN_ID, "--residue")
        assert any("undischarged" in line for line in rendered.output.splitlines())

    def test_this_build_supplies_no_adapter_so_capability_cannot_pass(self, db: str) -> None:
        # Pinned rather than apologized for: the CLI has no RuntimeAdapter to ask,
        # so the capability line is void with the reason, and the whole proof is
        # VOID because a proof that cannot vouch for all of its lines vouches for
        # none of them.
        view = build_proof_view(_compiled(db), run_id=RUN_ID)
        capability = next(line for line in view.lines if line.name == "capability_requirements")
        assert capability.status == "void"
        assert "no runtime adapter supplied" in capability.detail
        assert view.verdict == "VOID"

    def test_a_fail_renders_fail_and_refuses(self) -> None:
        # FAIL is reachable only where a caller supplies an adapter, so this is
        # asserted at the view-model layer with a proof built exactly the way the
        # compiler builds one: every line established, one failing.
        lines = [
            Obligation(
                name=name.value,
                status=ObligationStatus.PASS,
                gate_digest="c" * 64,
                evidence_ref="gate-output/test:fixture",
            )
            for name in ObligationName
            if name.value != "compensation"
        ] + [
            Obligation(
                name="compensation",
                status=ObligationStatus.FAIL,
                gate_digest="d" * 64,
                evidence_ref="gate-output/test:fixture",
                detail="1 fault(s) carry no write-ahead undo contract",
            )
        ]
        proof = SafetyProof(
            plan_digest=canonical_plan_digest(_plan()),
            obligations=tuple(lines),
            verdict=ProofVerdict.FAIL,
        )
        assert proof.verdict is ProofVerdict.FAIL
        view = build_proof_view(proof, run_id=RUN_ID)
        assert exit_code_for(view.verdict) == int(ExitCode.SAFETY_REFUSAL)
        assert "SAFETY PROOF: FAIL" in "\n".join(render_proof_lines(view))
        assert "no write-ahead undo contract" in "\n".join(render_proof_lines(view))

    def test_the_exit_code_mapping_is_the_documented_one(self) -> None:
        assert exit_code_for("PASS") == 0
        assert exit_code_for("FAIL") == int(ExitCode.SAFETY_REFUSAL)
        assert exit_code_for("VOID") == int(ExitCode.SAFETY_REFUSAL)


# ── the name ──────────────────────────────────────────────────────────────────


class TestTheName:
    def test_prove_is_registered_and_plan_is_still_retired(self) -> None:
        from mayhem.cli.app import app

        assert "prove" in app.commands
        # `plan` was removed from this CLI, and the inventory that asserts a
        # removed name stays removed is what kept the new surface off it.
        assert "plan" not in app.commands
