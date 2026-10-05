"""``mayhem prove`` — the safety proof as something a person reads.

Plan 30 Phase 1 built the proof type, Phase 2 built the compiler that runs the
real gates, Phase 4 sealed it and discharged its residue lines. Phase 3 was the
one phase with no surface: the compiler was reachable from Python and from
nothing else, so "here is why this plan is allowed" existed as an object rather
than as an artifact a reviewer could be handed. This module is that surface, and
it is the same shape as every other read-only surface in this package:

    compile over the recorded plan  ->  ProofView      # pure
                                        |-> render_proof_lines(view)   # the CLI
                                        `-> proof_payload(view)        # any UI

The view-model layer is where the rendering decisions live, so the acceptance
criterion — golden tests on the rendered artifact — is asserted against
:class:`ProofView` rather than against whatever strings this particular Click
handler happened to print. A second renderer cannot drift because there is no
vocabulary for "looks fine" outside the view.

**The plan named this ``mayhem plan prove``; the command is ``mayhem prove``.**
``plan`` is a name this CLI has *retired* — it sits in the removal inventory in
``tests/unit/test_cli_active_surface.py``, which asserts a removed name is not
dispatchable. Registering a new group under a retired name would make every
script still holding the old spelling hit a surface that answers a different
question, so the verb stands alone, the way ``stop`` does. The ledger records
the deviation rather than quietly renaming the plan.

Three refusals shape it, and each is a refusal rather than a rendering:

* **An uncited line cannot be printed as a pass.** ``pass`` without
  ``gate_digest`` and ``evidence_ref`` is refused at construction by the domain,
  so this layer has nothing to invent; it renders the citation beside every line
  it prints, because a citation nobody is shown is a citation nobody checks.

* **A stale proof renders VOID, with the diff that voided it.** ``--check``
  recompiles against the plan the store holds now and compares line by line. The
  submitted proof's lines are printed **as they were submitted**, next to the
  current verdict and the names that moved — never re-rendered as a PASS for a
  plan that no longer exists. The domain's ``voided`` already decides the
  verdict; this surface's job is to make the reason legible rather than to
  decide anything.

* **A missing required line prints as ``absent``, not as a failure and not as
  nothing.** "Not checked" is not "checked and negative"; the proof type already
  voids on it, and an artifact that quietly omitted it would read as a shorter
  proof rather than a weaker one.

Nothing here mutates: the store is opened, queried and closed, and the compiler
runs the same gates in simulation mode (``simulate_gate``) that the preview
surface uses, so asking "would this pass" cannot spend a budget or take a lock.
The exit code is ``0`` for PASS and :data:`~mayhem.cli.exit_codes.ExitCode.
SAFETY_REFUSAL` for both FAIL and VOID, because a proof that is not a PASS is
the refusal this command exists to report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.domain.errors import InvariantViolationError

if TYPE_CHECKING:
    from mayhem.domain.safety_proof import Obligation, SafetyProof

__all__ = [
    "PROOF_VIEW_SCHEMA_VERSION",
    "STATUS_ABSENT",
    "ObligationDiff",
    "ObligationLine",
    "ProofView",
    "build_proof_view",
    "exit_code_for",
    "proof_payload",
    "prove",
    "render_proof_lines",
]

#: Version of the presentation structure. Bumped when a field's *meaning*
#: changes, never when one is added — the payload is additive, and a consumer
#: reading an older one must not be broken by a newer renderer.
PROOF_VIEW_SCHEMA_VERSION = "1.0"

#: The status this layer prints for a required obligation the proof does not
#: carry. Not an :class:`~mayhem.domain.safety_proof.ObligationStatus`: "absent"
#: is a statement about the artifact, not a result a gate reported.
STATUS_ABSENT = "absent"

#: How much of a citation digest is printed. The full digest is in ``--json``
#: and in the artifact; a terminal line shows enough for a reviewer to compare
#: it against a gate log without wrapping.
_DIGEST_PREFIX = 12


@dataclass(frozen=True, slots=True)
class ObligationLine:
    """One rendered line: a name, a status, a detail, and the citation behind it."""

    name: str
    status: str
    detail: str = ""
    gate_digest: str = ""
    evidence_ref: str = ""

    def render(self) -> str:
        parts = [f"{self.status:>6}  {self.name}", self.detail]
        line = "  ".join(part for part in parts if part)
        if self.gate_digest:
            line = f"{line}  [cite {self.gate_digest[:_DIGEST_PREFIX]}"
            if self.evidence_ref:
                line = f"{line} | {self.evidence_ref}"
            line = f"{line}]"
        return line

    def to_payload(self) -> dict[str, str]:
        """The structure a UI renders. No renderer holds a word of its own."""
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "gate_digest": self.gate_digest,
            "evidence_ref": self.evidence_ref,
        }


@dataclass(frozen=True, slots=True)
class ObligationDiff:
    """One obligation that moved between the submitted proof and this compile."""

    name: str
    was: str
    now: str
    citation_moved: bool = False

    def render(self) -> str:
        moved = f"{self.was} -> {self.now}"
        if self.citation_moved and self.was == self.now:
            # A line that kept its verdict but changed what it cites is still a
            # change: it is the case where "same answer, different evidence", and
            # printing it as unchanged would hide a re-derived gate output.
            return f"{self.name}  {moved}  (citation changed)"
        return f"{self.name}  {moved}"

    def to_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "was": self.was,
            "now": self.now,
            "citation_moved": self.citation_moved,
        }


@dataclass(frozen=True, slots=True)
class ProofView:
    """Everything a renderer needs, and nothing a renderer has to derive."""

    verdict: str
    run_id: str
    plan_digest: str
    proof_digest: str
    void_reason: str = ""
    lines: tuple[ObligationLine, ...] = ()
    diffs: tuple[ObligationDiff, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def stale(self) -> bool:
        """True when a submitted proof was checked against a plan that moved."""
        return bool(self.diffs)

    @property
    def exit_code(self) -> int:
        return exit_code_for(self.verdict)

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": PROOF_VIEW_SCHEMA_VERSION,
            "verdict": self.verdict,
            "run_id": self.run_id,
            "plan_digest": self.plan_digest,
            "proof_digest": self.proof_digest,
            "void_reason": self.void_reason,
            "stale": self.stale,
            "obligations": [line.to_payload() for line in self.lines],
            "diff": [entry.to_payload() for entry in self.diffs],
            "notes": list(self.notes),
        }


def exit_code_for(verdict: str) -> int:
    """``0`` for PASS; the safety-refusal code for FAIL and for VOID.

    A proof that is not a PASS is the refusal this command exists to report, and
    VOID is refused rather than passed because "mayhem could not establish this"
    is not "this is fine".
    """
    if verdict == "PASS":
        return int(ExitCode.SUCCESS)
    return int(ExitCode.SAFETY_REFUSAL)


def _line_for(obligation: Obligation) -> ObligationLine:
    return ObligationLine(
        name=obligation.name,
        status=obligation.status.value,
        detail=obligation.detail,
        gate_digest=obligation.gate_digest,
        evidence_ref=obligation.evidence_ref,
    )


def _absent_lines(missing: tuple[str, ...]) -> tuple[ObligationLine, ...]:
    return tuple(
        ObligationLine(
            name=name,
            status=STATUS_ABSENT,
            detail="required obligation absent: not checked is not checked and passed",
        )
        for name in missing
    )


def _diffs_against(
    submitted: tuple[Obligation, ...],
    current: tuple[Obligation, ...],
) -> tuple[ObligationDiff, ...]:
    """Every obligation whose status or citation moved between two compiles."""
    before = {obligation.name: obligation for obligation in submitted}
    after = {obligation.name: obligation for obligation in current}
    diffs: list[ObligationDiff] = []
    for name in sorted(set(before) | set(after)):
        old = before.get(name)
        new = after.get(name)
        old_status = old.status.value if old is not None else STATUS_ABSENT
        new_status = new.status.value if new is not None else STATUS_ABSENT
        citation_moved = bool(
            old is not None
            and new is not None
            and (old.gate_digest != new.gate_digest or old.evidence_ref != new.evidence_ref)
        )
        if old_status != new_status or citation_moved:
            diffs.append(
                ObligationDiff(
                    name=name, was=old_status, now=new_status, citation_moved=citation_moved
                )
            )
    return tuple(diffs)


def build_proof_view(
    proof: SafetyProof,
    *,
    run_id: str,
    notes: tuple[str, ...] = (),
    current: SafetyProof | None = None,
) -> ProofView:
    """The presentation structure for one compiled proof.

    ``current`` is supplied only by ``--check``: it is the same compile run
    against the plan the store holds now. When it differs, the submitted proof's
    own lines are rendered unchanged beside a diff — the artifact a reviewer is
    being asked about is the one they were handed, not a rewritten one.
    """
    lines = tuple(_line_for(obligation) for obligation in proof.obligations)
    lines += _absent_lines(proof.missing_obligations())
    diffs = _diffs_against(proof.obligations, current.obligations) if current else ()
    return ProofView(
        verdict=proof.verdict.value,
        run_id=run_id,
        plan_digest=proof.plan_digest,
        proof_digest=proof.proof_digest,
        void_reason=proof.void_reason,
        lines=lines,
        diffs=diffs,
        notes=notes,
    )


def render_proof_lines(view: ProofView) -> tuple[str, ...]:
    """The rendered artifact. Pure, and the golden tests are written against it."""
    lines: list[str] = [f"SAFETY PROOF: {view.verdict}", f"run: {view.run_id}"]
    lines.append(f"plan digest: {view.plan_digest}")
    lines.append(f"proof digest: {view.proof_digest}")
    if view.void_reason:
        lines.append(f"void: {view.void_reason}")
    lines.append("")
    lines.extend(line.render() for line in view.lines)
    if view.diffs:
        lines.append("")
        lines.append("THIS PROOF WAS COMPILED AGAINST A DIFFERENT PLAN")
        lines.append(f"  was: {view.plan_digest}")
        lines.extend(f"  {entry.render()}" for entry in view.diffs)
    if view.notes:
        lines.append("")
        lines.extend(f"note: {note}" for note in view.notes)
    return tuple(lines)


def proof_payload(view: ProofView) -> dict[str, Any]:
    """The same structure as data, for a UI or a CI consumer."""
    return view.to_payload()


# =============================================================================
# The Click surface
# =============================================================================


def _db_for(ctx: click.Context) -> str:
    """The database this invocation reads. Same channel as every other reader."""
    return str(getattr(ctx.obj, "db", "") or "") or "mayhem.db"


def _fail(ctx: click.Context, exc: MayhemCliError) -> None:
    """Emit this surface's own refusal and exit with the code it carries."""
    exc.emit(debug=bool(getattr(ctx.obj, "debug", False)) if ctx.obj else False)
    ctx.exit(int(exc.exit_code))


def _load_proof(path: str) -> Any:
    """Read a submitted proof artifact, refusing anything unreadable."""
    from mayhem.domain.safety_proof import SafetyProof as _Proof

    raw = Path(path)
    if not raw.is_file():
        raise MayhemCliError(
            code="validation_error",
            message=f"no proof artifact at {path!r}: there is nothing to check",
            details={"path": path},
            remediation="produce one first: mayhem prove RUN_ID --json > proof.json",
        )
    try:
        document = json.loads(raw.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise MayhemCliError(
            code="validation_error",
            message=(
                f"the proof artifact at {path!r} cannot be read: {exc}. mayhem refuses "
                "to check a proof it could not parse, because an unreadable artifact "
                "would be reported as a stale one and the two are different findings"
            ),
            details={"path": path},
            remediation="re-export the artifact with mayhem prove RUN_ID --json",
        ) from None
    try:
        return _Proof.model_validate(document)
    except (ValueError, InvariantViolationError) as exc:
        # SafetyProof re-derives its verdict on construction, so a hand-written
        # PASS over a failing line is refused here rather than rendered. The
        # domain's own refusal type is caught too, because "a forged artifact" is
        # a refusal this surface renders, not a traceback it dumps.
        raise MayhemCliError(
            code="validation_error",
            message=f"the artifact at {path!r} is not a safety proof mayhem will accept: {exc}",
            details={"path": path},
            remediation="a proof that does not validate was not produced by the compiler",
        ) from None


@click.command("prove")
@click.argument("run_id")
@click.option(
    "--check",
    "check_path",
    default="",
    metavar="PROOF_JSON",
    help="Check a submitted proof artifact against the plan recorded now, and render "
    "it VOID with the diff if the plan moved.",
)
@click.option(
    "--residue",
    "include_residue",
    is_flag=True,
    default=False,
    help="Include the per-fault residue obligations. They are additional to the nine "
    "required lines, and undischarged they VOID the proof rather than fail it.",
)
@click.option(
    "--fingerprint",
    "fingerprint",
    default="",
    metavar="FP",
    help="Environment fingerprint to evaluate against. Defaults to the plan's own "
    "recorded identity, which means the drift check does not run.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit the presentation structure as JSON instead of the rendered lines.",
)
@click.pass_context
def prove(
    ctx: click.Context,
    run_id: str,
    check_path: str,
    include_residue: bool,
    fingerprint: str,
    as_json: bool,
) -> None:
    """Render the safety proof for a run's frozen plan, with per-line citations.

    Read-only: the store is opened, queried and closed, and the compiler runs the
    gates in simulation mode, so this cannot spend a budget or take a lock.
    Exits 0 for PASS and 5 for FAIL or VOID.
    """
    from mayhem.cli.services import gate_context_for_plan, load_recorded_run, open_store
    from mayhem.controller.safety_proof import compile_safety_proof

    db = _db_for(ctx)
    store = open_store(db)
    try:
        recorded = load_recorded_run(store, run_id)
        if recorded.graph is None:
            raise MayhemCliError(
                code="validation_error",
                message=(
                    f"run {run_id!r} recorded no topology snapshot, so mayhem has no "
                    "graph to measure a blast radius against. Every obligation that "
                    "measures damage would be computed over nothing, and a proof over "
                    "an empty topology reads as 'this plan is safe'"
                ),
                details={"run_id": run_id, "topology_snapshot_id": recorded.snapshot_id},
                remediation="re-plan the run against current topology, then prove it",
            )
        ctx_gate = gate_context_for_plan(
            fingerprint=fingerprint or recorded.environment_fingerprint
        )
        compiled = compile_safety_proof(
            recorded.plan,
            recorded.graph,
            ctx_gate,
            include_residue=include_residue,
            target_identity=run_id,
        )
        submitted = _load_proof(check_path) if check_path else None
    except MayhemCliError as exc:
        _fail(ctx, exc)
        raise
    finally:
        store.close()

    notes: list[str] = []
    if not fingerprint:
        notes.append(
            "environment fingerprint adopted from the recorded plan: mayhem did not "
            "re-derive the live environment identity, so the drift check did not run. "
            "Pass --fingerprint to ask the stricter question."
        )
    if include_residue:
        notes.append(
            "residue obligations are included but undischarged: they assert that this "
            "plan left nothing behind and are discharged by the post-run scan, not here."
        )

    if submitted is None:
        view = build_proof_view(compiled, run_id=run_id, notes=tuple(notes))
    else:
        # The verdict shown is the *submitted* proof's verdict re-derived against
        # the plan recorded now, so a stale artifact cannot be read as the PASS it
        # once was. The diff is computed against the fresh compile, which is the
        # only thing here that knows what "moved" means.
        rederived = (
            submitted.voided(compiled.plan_digest) if _stale(submitted, compiled) else submitted
        )
        view = build_proof_view(
            rederived,
            run_id=run_id,
            notes=tuple(notes),
            current=compiled,
        )
    _emit(ctx, view, as_json=as_json)


def _stale(submitted: SafetyProof, current: SafetyProof) -> bool:
    """True when the artifact cannot speak for the plan recorded now."""
    return submitted.plan_digest != current.plan_digest


def _emit(ctx: click.Context, view: ProofView, *, as_json: bool) -> None:
    from mayhem.cli.output import echo_machine

    if echo_machine(proof_payload(view), as_json=as_json):
        ctx.exit(view.exit_code)
    for line in render_proof_lines(view):
        click.echo(line)
    ctx.exit(view.exit_code)
