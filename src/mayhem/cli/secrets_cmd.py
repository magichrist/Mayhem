"""``mayhem secrets`` — grant administration, and what each grant actually permits.

Plan 29 built the resolver, the grant type and the table behind it
(``M0022_SECRET_GRANTS``). Phase 3 recorded the surface as missing: a grant could
be written by a test and read by the resolver, and no command anywhere issued or
revoked one. **A permission nobody can grant or withdraw is not a permission
model**, it is a fixture.

Four verbs over the existing repository, and none of them is a second policy:

``mayhem secrets grant``
    Issue one grant: who, what shape of credential, which environments, which
    scopes, and when it lapses. All five are required by the type rather than by
    this command — a grant with no environment scope or no expiry is a standing
    permission, and the domain refuses to mint one.

``mayhem secrets revoke``
    Withdraw by ``(principal, credential_pattern)``. Revocation is by pattern
    rather than by row id because that is the pair the resolver looks a grant up
    by; a revocation that named anything else would leave the permission live.

``mayhem secrets list``
    What is outstanding, for one principal or all of them.

``mayhem secrets explain``
    The acceptance criterion, made operable: given a principal, a credential
    pattern, an environment and a scope, say **which grant answers and which
    clause of it matched**. A permission an operator cannot read is one they will
    not audit, and the clauses are exactly the four the grant is made of.

What this surface does not do
-----------------------------

* **It never handles a value.** Nothing here reads, prints, or stores a
  credential. ``--pattern`` is a glob over a reference's canonical key, never the
  key itself; that is why the table has no value column and why this command
  needs no ``BOUNDARY_CALL_SITES`` row for one.
* **It is not an identity surface.** ``--principal`` is a declared string.
  Nothing here authenticates the person typing it, and nothing binds it to plan
  09's principals — so an operator reading a grant learns who it *claims* to be
  for, which is what the table records and all the table can know.
* **It does not decide.** ``explain`` evaluates the grants' own predicates
  against the question asked; the resolver remains the only thing that decides
  whether a run may resolve a value.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import click

from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from mayhem.domain.secrets import CredentialRef, SecretGrant
    from mayhem.infra.secret_resolver import SecretGrantRepository

secrets_cmd = make_group(
    "secrets",
    "Issue, revoke and explain credential grants.",
)


def _ctx(ctx: click.Context) -> CliContext:
    obj = ctx.obj
    return obj if isinstance(obj, CliContext) else CliContext()


def _grants(ctx: click.Context, db_opt: str | None) -> tuple[Any, SecretGrantRepository]:
    """The store and its grant repository. The caller closes the store."""
    from mayhem.cli.services import open_store
    from mayhem.infra.secret_resolver import SecretGrantRepository

    store = open_store(db_opt or _ctx(ctx).db)
    return store, SecretGrantRepository(store)


def _describe(grant: SecretGrant) -> str:
    expiry = grant.expires_at.isoformat()
    scopes = ", ".join(grant.scopes) if grant.scopes else "any scope"
    environments = ", ".join(grant.environments)
    return (
        f"{grant.principal} may resolve {grant.credential_pattern} in "
        f"{environments} ({scopes}) until {expiry}"
    )


@secrets_cmd.command("grant")
@click.option("--principal", required=True, help="Who the grant is issued to, as declared.")
@click.option(
    "--pattern",
    "credential_pattern",
    required=True,
    metavar="GLOB",
    help="Glob over a reference's canonical key, e.g. vault:prod/db. Never a value.",
)
@click.option(
    "--environment",
    "environments",
    multiple=True,
    required=True,
    metavar="GLOB",
    help="Environment covered (repeatable). Globs allowed, e.g. prod-*.",
)
@click.option(
    "--scope",
    "scopes",
    multiple=True,
    metavar="GLOB",
    help="Scope token covered (repeatable), e.g. step:inject-db. Omit for any scope.",
)
@click.option(
    "--expires-in",
    "expires_in",
    required=True,
    type=float,
    metavar="DAYS",
    help="Days until the grant lapses. A grant with no expiry is refused by the type.",
)
@click.option(
    "--allow-development-only",
    "development_only",
    is_flag=True,
    help=(
        "Record that this grant covers a development-only provider. Resolution still "
        "requires the per-run marker; this grants nothing on its own."
    ),
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def grant_cmd(
    ctx: click.Context,
    principal: str,
    credential_pattern: str,
    environments: tuple[str, ...],
    scopes: tuple[str, ...],
    expires_in: float,
    development_only: bool,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Issue one grant. Every bound on it is required, not defaulted."""
    from mayhem.domain.common import utc_now
    from mayhem.domain.errors import InvariantViolationError
    from mayhem.domain.secrets import SecretGrant

    if expires_in <= 0:
        click.echo(
            f"error: --expires-in must be positive, got {expires_in}. A grant with no "
            "deadline is a standing permission and the type refuses to mint one.",
            err=True,
        )
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    moment = utc_now()
    payload: dict[str, Any] = {
        "principal": principal,
        "credential_pattern": credential_pattern,
        "environments": tuple(environments),
        "scopes": tuple(scopes),
        "expires_at": moment + timedelta(days=expires_in),
        "issued_at": moment,
    }
    try:
        grant = SecretGrant(**payload)
    except (InvariantViolationError, ValueError) as exc:
        click.echo(f"refused: {exc}", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    store, repository = _grants(ctx, db_opt)
    try:
        repository.save(grant)
    finally:
        store.close()

    from mayhem.cli.output import echo_machine

    body = {
        "principal": grant.principal,
        "credential_pattern": grant.credential_pattern,
        "environments": list(grant.environments),
        "scopes": list(grant.scopes),
        "expires_at": grant.expires_at.isoformat(),
        "issued_at": grant.issued_at.isoformat() if grant.issued_at else "",
        "development_only_marker_recorded": development_only,
        "development_only_note": (
            "recorded as declared; resolution of a development-only provider still "
            "requires the per-run marker sealed into evidence"
        )
        if development_only
        else "",
    }
    if not echo_machine(body, as_json=as_json):
        click.echo(f"granted: {_describe(grant)}")


@secrets_cmd.command("revoke")
@click.option("--principal", required=True, help="Principal the grant was issued to.")
@click.option(
    "--pattern",
    "credential_pattern",
    required=True,
    metavar="GLOB",
    help="The exact credential pattern to withdraw.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def revoke_cmd(
    ctx: click.Context, principal: str, credential_pattern: str, db_opt: str | None, as_json: bool
) -> None:
    """Withdraw the grants matching this principal and pattern.

    Refuses when nothing matched: a revocation that quietly revoked nothing is a
    reader's belief that a permission is gone.
    """
    store, repository = _grants(ctx, db_opt)
    try:
        revoked = repository.revoke(principal, credential_pattern)
    finally:
        store.close()

    from mayhem.cli.output import echo_machine

    if revoked == 0:
        click.echo(
            f"error: no live grant for {principal!r} on {credential_pattern!r}. Nothing was "
            "withdrawn; if you expected one, the pattern is not the one it was issued under.",
            err=True,
        )
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
    if not echo_machine(
        {"principal": principal, "pattern": credential_pattern, "revoked": revoked}, as_json=as_json
    ):
        click.echo(f"revoked {revoked} grant(s) for {principal} on {credential_pattern}")


@secrets_cmd.command("list")
@click.option("--principal", default="", help="Only this principal's grants.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def list_cmd(ctx: click.Context, principal: str, db_opt: str | None, as_json: bool) -> None:
    """Every outstanding grant, and what each one permits."""
    store, repository = _grants(ctx, db_opt)
    try:
        grants = repository.grants_for(principal) if principal else repository.load_all()
    finally:
        store.close()

    from mayhem.cli.output import echo_machine

    payload = {
        "grants": [
            {
                "principal": grant.principal,
                "credential_pattern": grant.credential_pattern,
                "environments": list(grant.environments),
                "scopes": list(grant.scopes),
                "expires_at": grant.expires_at.isoformat(),
                "issued_at": grant.issued_at.isoformat() if grant.issued_at else "",
                "permits": _describe(grant),
            }
            for grant in grants
        ],
        "count": len(grants),
        "note": "a principal is a declared string; nothing here authenticates it",
    }
    if echo_machine(payload, as_json=as_json):
        return
    if not grants:
        click.echo("no credential grant is outstanding")
        return
    for grant in grants:
        click.echo(f"  {_describe(grant)}")


# --- The grant explanation view-model -----------------------------------------
#
# Plan 29 Phase 3's acceptance criterion — "grants render with
# effective-permission explanations" — as data. The CLI's ``explain`` verb and
# :func:`mayhem.controller.api_service.secret_grant_explain_payload` are two
# projections off this one view-model, so "rendered identically in CLI and UI"
# is a property of the code rather than an agreement two renderers happen to
# have reached. The view-model stays owned by this module; the API projection
# imports it function-locally (the ``cli.api_cmd`` cycle is why
# ``risk_preview_payload`` does the same).


@dataclass(frozen=True, slots=True)
class GrantExplanation:
    """One grant question answered: who asked, what was considered, what won.

    ``considered`` carries one entry per grant consulted, each with the five
    clauses the grant is made of (principal, pattern, environment, scope,
    unexpired) and whether all of them held. ``answered_by`` names the winning
    grant's pattern, or ``""`` when none answers. The principal throughout is a
    declared string — nothing here authenticates it, and the payload says so.
    """

    principal: str
    canonical_key: str
    environment: str
    scope_token: str
    grants_considered: int
    answered_by: str
    permitted: bool
    considered: tuple[dict[str, Any], ...]


_EXPLAIN_NOTE = (
    "the resolver is the only thing that decides; this evaluates the grants' own "
    "clauses and reports which one answers"
)


def build_grant_explanation(
    grants: Sequence[SecretGrant],
    reference: CredentialRef,
    *,
    principal: str,
    environment: str,
    now: datetime,
) -> GrantExplanation:
    """Answer a grant question against live grants, purely.

    ``grants`` are the grants issued to ``principal`` (or all of them — grants
    for another principal simply fail the principal clause rather than being
    skipped, which is what makes "consulted nothing" for a stranger exact).
    ``reference`` is the concrete question phrased as a reference; ``now`` is
    the clock the expiry clause reads, passed in so two projections of the same
    question cannot disagree by a tick.
    """
    considered: list[dict[str, Any]] = []
    for grant in grants:
        clauses = {
            "principal": grant.covers_principal(principal),
            "pattern": grant.covers_reference(reference),
            "environment": grant.covers_environment(environment),
            "scope": grant.covers_scope(reference.scope_token),
            "unexpired": not grant.is_expired(now),
        }
        considered.append(
            {
                "pattern": grant.credential_pattern,
                "environments": list(grant.environments),
                "scopes": list(grant.scopes),
                "expires_at": grant.expires_at.isoformat(),
                "clauses": clauses,
                "covers": all(clauses.values()),
            }
        )

    answered = [entry for entry in considered if entry["covers"]]
    return GrantExplanation(
        principal=principal,
        canonical_key=reference.canonical_key,
        environment=environment,
        scope_token=reference.scope_token,
        grants_considered=len(considered),
        answered_by=answered[0]["pattern"] if answered else "",
        permitted=bool(answered),
        considered=tuple(considered),
    )


def explain_payload(explanation: GrantExplanation) -> dict[str, Any]:
    """The machine-readable answer both surfaces emit, byte for byte."""
    return {
        "question": {
            "principal": explanation.principal,
            "canonical_key": explanation.canonical_key,
            "environment": explanation.environment,
            "scope_token": explanation.scope_token,
        },
        "grants_considered": explanation.grants_considered,
        "answered_by": explanation.answered_by,
        "permitted": explanation.permitted,
        "considered": [dict(entry) for entry in explanation.considered],
        "note": _EXPLAIN_NOTE,
    }


@secrets_cmd.command("explain")
@click.option("--principal", required=True, help="Principal to ask about, as declared.")
@click.option(
    "--pattern",
    "credential_pattern",
    required=True,
    metavar="KEY",
    help="The concrete canonical key being resolved, e.g. vault:prod/db.",
)
@click.option("--environment", required=True, help="Environment the run executes in.")
@click.option(
    "--scope",
    "scope_token",
    default="",
    help="Scope token the reference is bound to, e.g. step:inject-db.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def explain_cmd(
    ctx: click.Context,
    principal: str,
    credential_pattern: str,
    environment: str,
    scope_token: str,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Say which grant answers this question, and which clause of it matched.

    Exits non-zero when no outstanding grant covers the question, so this is
    usable as the pre-flight check the phase asks for. The four clauses are the
    grant's own: principal, pattern, environment, scope.
    """
    from mayhem.domain.common import utc_now
    from mayhem.domain.errors import InvariantViolationError
    from mayhem.domain.secrets import CredentialRef, CredentialScope, ScopeKind, SecretProvider

    store, repository = _grants(ctx, db_opt)
    try:
        grants = repository.grants_for(principal)
    finally:
        store.close()

    # The pattern is a glob over a canonical key ("vault:prod/db"); the concrete
    # question names one, so the reference is built from the key's own halves.
    provider, _, key = credential_pattern.partition(":")
    kind_name, _, ref = (scope_token or "run:").partition(":")
    try:
        reference = CredentialRef(
            provider=SecretProvider(provider),
            secret=key or "unspecified",
            purpose="cli-explain",
            scope=CredentialScope(kind=ScopeKind(kind_name or "run"), ref=ref or "unspecified"),
        )
    except (InvariantViolationError, ValueError) as exc:
        click.echo(
            f"error: mayhem cannot build a reference from --pattern/--scope: {exc}. A question "
            "it cannot phrase is a question it will not answer.",
            err=True,
        )
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    moment = utc_now()
    explanation = build_grant_explanation(
        grants,
        reference,
        principal=principal,
        environment=environment,
        now=moment,
    )
    payload = explain_payload(explanation)
    answered = [entry for entry in explanation.considered if entry["covers"]]
    from mayhem.cli.output import echo_machine

    if not echo_machine(payload, as_json=as_json):
        if answered:
            click.echo(f"PERMITTED by {answered[0]['pattern']}")
            for clause, matched in answered[0]["clauses"].items():
                click.echo(f"  {clause}: {'yes' if matched else 'no'}")
        else:
            click.echo(
                f"DENIED: no outstanding grant for {principal} covers {reference.canonical_key} "
                f"in {environment} at {reference.scope_token}"
            )
            for entry in explanation.considered:
                failed = [name for name, ok in entry["clauses"].items() if not ok]
                click.echo(f"  {entry['pattern']} did not match: {', '.join(failed)}")
    ctx.exit(int(ExitCode.SUCCESS) if answered else int(ExitCode.SAFETY_REFUSAL))
