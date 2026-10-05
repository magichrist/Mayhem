"""``mayhem policy`` — the authoring and explanation surface (plan 07 Phase 3).

Plan 07 built a policy vocabulary, put it inside the real gate, and sealed what
the gate decided. What it did not build was anywhere to *write one down*: the
authoring module was an in-memory registry that no surface reached, so every run
still reached the gate with the older ``config.py`` policy block deciding alone.
A safety engine with no authoring surface is a library, not a policy system.

Six verbs, and the split between them is the point:

``mayhem policy publish PATH``
    Author a bundle document (YAML or JSON) into the stored catalog. The catalog
    is the authority on immutability, version ordering and retirement; this
    command is the only way in, so a bundle nobody published cannot decide
    anything.

``mayhem policy list`` / ``show`` / ``resolve``
    What is published, what a version contains, and which version a run would
    decide under. ``resolve`` never silently substitutes: it prints the version
    it resolved, because "which policy was this" must be answerable afterwards.

``mayhem policy retire BUNDLE_ID --version N``
    Tombstone a version. There is no delete, and that is the design rather than
    a missing feature: an approval, an evidence record, or a replay from six
    weeks ago still names that version.

``mayhem policy explain PLAN``
    The explanation. Every denial names the rule, what it observed, and what it
    wanted instead, and approval requirements surface as part of the decision.
    The four-line block this prints is plan 07's own "Example result", produced
    by the engine rather than written by hand.

Two properties this surface refuses to trade away:

* **An explanation is not an admission.** ``explain`` calls ``simulate_gate``,
  Phase 2's zero-mutation evaluation, so asking "would this be denied" cannot
  spend a budget, take a lock, or leave a mark. It reports the verdict it found
  and exits non-zero on a DENY, which is what makes it usable as a pre-flight
  check; the mutation-free half is what makes it safe to run one.
* **A missing policy is a refusal, not a default.** With no bundle published for
  the requested id, ``explain`` exits with a usage error naming what to publish.
  Silently deciding under "no policy" is the one answer this surface must not be
  able to give.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.domain.policy import PolicyDimension

if TYPE_CHECKING:
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.infra.policy_store import PolicyStore

policy_cmd = make_group(
    "policy",
    "Author, publish and explain policy bundles.",
)


def _ctx(ctx: click.Context) -> CliContext:
    obj = ctx.obj
    return obj if isinstance(obj, CliContext) else CliContext()


def _open(ctx: click.Context, db_opt: str | None) -> tuple[Any, PolicyStore]:
    """Open the store and the policy registry over it. The caller closes it."""
    from mayhem.cli.services import open_store
    from mayhem.infra.policy_store import PolicyStore

    store = open_store(db_opt or _ctx(ctx).db)
    return store, PolicyStore(store)


def _read_document(path: str) -> dict[str, Any]:
    """A bundle document from YAML or JSON, whichever the file is."""
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith((".yaml", ".yml")):
        import yaml

        loaded = yaml.safe_load(text)
    else:
        loaded = json.loads(text)
    if not isinstance(loaded, dict):
        msg = (
            f"{path} is not a policy bundle document: expected a mapping, "
            f"got {type(loaded).__name__}"
        )
        raise click.ClickException(msg)
    return loaded


@policy_cmd.command("publish")
@click.argument("path", type=click.Path(exists=True))
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option(
    "--by",
    "published_by",
    default="",
    help="Who is publishing, as declared. Nothing authenticates it.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def publish(
    ctx: click.Context, path: str, db_opt: str | None, published_by: str, as_json: bool
) -> None:
    """Author a bundle document and publish it as a new, immutable version."""
    from mayhem.domain.policy_authoring import PolicyAuthoringError

    try:
        document = _read_document(path)
    except (OSError, ValueError) as exc:
        click.echo(f"cannot read {path}: {exc}", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    store, policies = _open(ctx, db_opt)
    try:
        resolved = policies.publish(document, published_by=published_by)
    except PolicyAuthoringError as exc:
        click.echo(f"refused: {exc}", err=True)
        ctx.exit(int(ExitCode.SAFETY_REFUSAL))
    finally:
        store.close()

    payload = {
        "bundle_id": resolved.bundle_id,
        "version": resolved.version,
        "content_digest": resolved.digest,
        "rules": len(resolved.bundle.rules),
        "compatibility_edges": len(resolved.bundle.compatibility_edges),
    }
    from mayhem.cli.output import echo_machine

    if echo_machine(payload, as_json=as_json):
        return
    click.echo(
        f"published {resolved.bundle_id} v{resolved.version} "
        f"(digest {resolved.digest[:12]}, {payload['rules']} rule(s))"
    )


@policy_cmd.command("list")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def list_bundles(ctx: click.Context, db_opt: str | None, as_json: bool) -> None:
    """Every published policy version, live and retired."""
    store, policies = _open(ctx, db_opt)
    try:
        rows = policies.rows()
    finally:
        store.close()

    payload = {
        "bundles": [
            {
                "bundle_id": row.bundle_id,
                "version": row.version,
                "content_digest": row.content_digest,
                "published_at": row.published_at,
                "published_by": row.published_by,
                "retired_at": row.retired_at,
                "state": "retired" if row.retired_at else "published",
            }
            for row in rows
        ],
        "count": len(rows),
        "note": (
            "a retired version is tombstoned, not deleted: an approval or an evidence "
            "record still names it"
        ),
    }
    from mayhem.cli.output import echo_machine

    if echo_machine(payload, as_json=as_json):
        return
    if not rows:
        click.echo("no policy bundle is published; author one with `mayhem policy publish`")
        return
    for row in rows:
        state = "retired" if row.retired_at else "published"
        click.echo(f"{row.bundle_id} v{row.version} {row.content_digest[:12]} {state}")
    ctx.exit(int(ExitCode.SUCCESS))


@policy_cmd.command("show")
@click.argument("bundle_id")
@click.option("--version", "version", type=int, default=None, help="Version to show.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def show(
    ctx: click.Context, bundle_id: str, version: int | None, db_opt: str | None, as_json: bool
) -> None:
    """Print one published version: its rules, its edges, and its digest."""
    from mayhem.domain.policy_authoring import PolicyAuthoringError

    store, policies = _open(ctx, db_opt)
    try:
        resolved = policies.resolve(bundle_id, version)
        bundle = resolved.bundle
    except PolicyAuthoringError as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
    finally:
        store.close()

    document = bundle.model_dump(mode="json")
    from mayhem.cli.output import echo_machine

    if echo_machine(document, as_json=as_json):
        return
    pinned = bundle.content_digest or "unpinned"
    click.echo(f"{bundle.describe()} (digest {pinned[:12]})")
    if bundle.description:
        click.echo(f"  {bundle.description}")
    for rule in bundle.rules:
        click.echo(f"  {rule.rule_id}: {rule.effect.value} on {rule.dimension.value}")
    for edge in bundle.compatibility_edges:
        click.echo(f"  collision: {edge.describe()}")


@policy_cmd.command("retire")
@click.argument("bundle_id")
@click.option("--version", "version", type=int, required=True, help="Version to retire.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def retire(
    ctx: click.Context, bundle_id: str, version: int, db_opt: str | None, as_json: bool
) -> None:
    """Tombstone a published version. There is no delete, by design."""
    from mayhem.domain.policy_authoring import PolicyAuthoringError

    store, policies = _open(ctx, db_opt)
    try:
        policies.retire(bundle_id, version)
    except PolicyAuthoringError as exc:
        click.echo(f"refused: {exc}", err=True)
        ctx.exit(int(ExitCode.SAFETY_REFUSAL))
    finally:
        store.close()

    from mayhem.cli.output import echo_machine

    payload = {
        "bundle_id": bundle_id,
        "version": version,
        "state": "retired",
        "note": (
            "the version and its digest are still readable; it can no longer be "
            "resolved for a new run and cannot be republished"
        ),
    }
    if not echo_machine(payload, as_json=as_json):
        click.echo(f"retired {bundle_id} v{version}; it stays readable for anything that names it")


@policy_cmd.command("resolve")
@click.argument("bundle_id")
@click.option("--version", "version", type=int, default=None, help="Version to resolve.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def resolve(
    ctx: click.Context, bundle_id: str, version: int | None, db_opt: str | None, as_json: bool
) -> None:
    """Which version a run would decide under. Never silently substitutes."""
    from mayhem.domain.policy_authoring import PolicyAuthoringError

    store, policies = _open(ctx, db_opt)
    try:
        resolved = policies.resolve(bundle_id, version)
    except PolicyAuthoringError as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
    finally:
        store.close()

    payload = {
        "bundle_id": resolved.bundle_id,
        "version": resolved.version,
        "content_digest": resolved.digest,
        "asked_for_version": version,
        "resolved_by": "the exact version named" if version is not None else "newest published",
    }
    from mayhem.cli.output import echo_machine

    if not echo_machine(payload, as_json=as_json):
        click.echo(
            f"{resolved.bundle_id} v{resolved.version} (digest {resolved.digest[:12]}, "
            f"{payload['resolved_by']})"
        )


def _load_plan(path: str) -> ExecutionPlan | None:
    """The plan, or ``None`` — which this surface reports rather than assumes."""
    from mayhem.domain.errors import InvariantViolationError
    from mayhem.domain.experiments import ExecutionPlan

    try:
        return ExecutionPlan.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))
    except (OSError, ValueError, InvariantViolationError):
        return None


@policy_cmd.command("explain")
@click.argument("plan", type=click.Path(exists=True))
@click.option("--policy", "bundle_id", required=True, help="Policy bundle id to decide under.")
@click.option(
    "--version", "version", type=int, default=None, help="Policy version to decide under."
)
@click.option("--environment", default=None, help="Environment name the decision is scoped to.")
@click.option(
    "--team",
    "team",
    default="",
    help="Team dimension, when the bundle's rules read it (the gate cannot derive it).",
)
@click.option(
    "--approval-held",
    "approvals_held",
    multiple=True,
    help="An approval level already granted (repeatable). Omit them all to see "
    "what is still outstanding.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress the per-rule detail.")
@click.pass_context
def explain(
    ctx: click.Context,
    plan: str,
    bundle_id: str,
    version: int | None,
    environment: str | None,
    team: str,
    approvals_held: tuple[str, ...],
    db_opt: str | None,
    as_json: bool,
    quiet: bool,
) -> None:
    """Explain the verdict a plan would get, without admitting it.

    Prints the four-line block plan 07 documents, produced by the engine, and
    under it every rule that was evaluated with what it observed and what it
    wanted instead. Exits non-zero on a DENY so this can be a pre-flight check.
    Nothing is mutated: the evaluation is Phase 2's simulation mode.
    """
    from mayhem.controller.safety_proof import canonical_plan_digest
    from mayhem.domain.common import utc_now
    from mayhem.domain.policy_authoring import (
        PolicyAuthoringError,
        explain_facts,
        explain_refusal,
        with_pending_approvals,
    )
    from mayhem.domain.policy_gate import simulate_gate

    loaded = _load_plan(plan)
    if loaded is None:
        click.echo(
            f"error: {plan} is not a plan mayhem can read. An unreadable plan is not an "
            "allowed plan: mayhem refuses rather than explaining a decision it did "
            "not evaluate.",
            err=True,
        )
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    store, policies = _open(ctx, db_opt)
    try:
        try:
            inputs = policies.gate_inputs(
                loaded,
                bundle_id,
                now=utc_now(),
                version=version,
                observed=_observed(team, approvals_held),
            )
            # Through the authoring module's own seam, not a hand-rolled fact:
            # a bundle's `approval_level` rules are unreachable without a value
            # on that dimension, and the plan's own example shows the `Required:`
            # line they produce.
            inputs = with_pending_approvals(inputs)
        except PolicyAuthoringError as exc:
            click.echo(
                f"error: {exc}. mayhem will not decide a plan under no policy, and it will "
                "not fall back to a version nobody named.",
                err=True,
            )
            ctx.exit(int(ExitCode.VALIDATION_ERROR))
        result = simulate_gate(loaded, inputs, environment=environment)
    finally:
        store.close()

    digest = canonical_plan_digest(loaded)
    rendered = explain_refusal(result, plan_digest=digest)
    payload = {
        "verdict": "ALLOW" if result.allowed else "DENY",
        "plan_digest": digest,
        "bundle_id": inputs.bundle.bundle_id,
        "bundle_version": inputs.bundle.version,
        "policy_digest": inputs.bundle.content_digest,
        "simulated": result.simulated,
        "mutated": False,
        "reason": result.refusal.reason if result.refusal else "",
        "rule_ids": list(result.refusal.rule_ids()) if result.refusal else [],
        "required_approvals": [a.describe() for a in result.required_approvals],
        "facts": explain_facts(result.facts),
        "rendered": rendered,
    }
    from mayhem.cli.output import echo_machine

    if not echo_machine(payload, as_json=as_json):
        if quiet:
            click.echo(rendered.split("\n\n")[0])
        else:
            click.echo(rendered)
    ctx.exit(int(ExitCode.SUCCESS) if result.allowed else int(ExitCode.SAFETY_REFUSAL))


def _observed(team: str, approvals_held: tuple[str, ...]) -> dict[PolicyDimension, tuple[str, ...]]:
    """The dimensions a plan cannot carry, as facts.

    Only what the caller declared: the team, and the approval levels already
    granted. "None granted" is **not** spelled here — that is
    :func:`~mayhem.domain.policy_authoring.with_pending_approvals`'s job, and
    duplicating it here would be a second answer to "what does an unheld approval
    look like as a fact".
    """
    observed: dict[PolicyDimension, tuple[str, ...]] = {}
    if team:
        observed[PolicyDimension.TEAM] = (team,)
    if approvals_held:
        observed[PolicyDimension.APPROVAL_LEVEL] = tuple(sorted(approvals_held))
    return observed
