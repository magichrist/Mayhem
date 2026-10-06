"""``mayhem agent`` — enrollment and identity state, the fabric's Phase 3 surface.

Plan 19 built the identity record, its verification, its rotation policy and
its revocation ledger — and nothing in the tree ever *created* one. Storage
with no entry path is a schema: the first enrollment is what makes every other
half a fact. This group is that entry path, and its split is deliberate:

``mayhem agent enroll``
    Write the first record for an agent. Enrollment bootstraps *identity*, not
    key material: ``AgentCredential`` holds no secret by design (plan 29's rule
    — no column a credential value could occupy), so this command issues ids,
    windows and a rotation lifecycle, and prints that fact rather than letting
    a reader assume a key was minted. An id on this surface is **declared**,
    exactly like ``policy publish --by``: nothing here authenticates the
    declarer, and the ledger says so.

``mayhem agent list`` / ``show``
    What is enrolled and whether it may authenticate *now*, through the
    domain's own ``refusals_at`` — the same predicates the verifier reaches —
    so a surface and a verifier cannot disagree about an agent's state.
    ``show`` exits non-zero when the identity may not authenticate, which is
    what makes it usable as a pre-flight check.

``mayhem agent revoke``
    Pull the whole identity. A revocation is absolute and the *first* one
    wins, so a second revoke with a different reason is refused rather than
    silently recorded — the surface refuses rather than reporting a no-op as
    if it were a change.

Every verb is refused rather than defaulted: enrolling over an existing id,
revoking an unenrolled agent, or revoking twice all end with a named refusal
and a remediation, because each of them is somebody acting on the wrong
belief about an agent's state.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import click

from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group

if TYPE_CHECKING:
    from mayhem.domain.agent_identity import AgentIdentity
    from mayhem.infra.agent_identity_store import AgentIdentityRepository

agent = make_group(
    "agent",
    "Enroll agents, read their identity state, and revoke them.",
)


def _ctx(ctx: click.Context) -> CliContext:
    obj = ctx.obj
    return obj if isinstance(obj, CliContext) else CliContext()


def _open(ctx: click.Context, db_opt: str | None) -> tuple[Any, AgentIdentityRepository]:
    """Open the store and the identity repository over it. The caller closes it."""
    from mayhem.cli.services import open_store
    from mayhem.infra.agent_identity_store import AgentIdentityRepository as Repository

    store = open_store(db_opt or _ctx(ctx).db)
    return store, Repository(store)


def _now() -> datetime:
    return datetime.now(UTC)


def _state_of(identity: AgentIdentity, now: datetime) -> tuple[str, list[str]]:
    """``(state, refusal names)`` from the domain's own predicates.

    Read through ``refusals_at`` rather than re-deriving expiry or revocation
    here: a surface that checks a different question than the verifier is how
    an operator ends up trusting a state the agent cannot actually use.
    """
    refusals = [refusal.value for refusal in identity.refusals_at(now=now)]
    if refusals:
        return "unusable", refusals
    if identity.needs_rotation(now=now):
        return "rotation_due", []
    return "usable", []


def _payload(identity: AgentIdentity, now: datetime) -> dict[str, Any]:
    state, refusals = _state_of(identity, now)
    return {
        "agent_id": identity.agent_id,
        "controller_id": identity.controller_id,
        "principal": identity.principal.principal_id,
        "principal_kind": identity.principal.kind.value,
        "environment": identity.scope.environment,
        "credential_id": identity.credential.credential_id,
        "issued_at": identity.credential.issued_at.isoformat(),
        "expires_at": identity.credential.expires_at.isoformat(),
        "generation": identity.credential.generation,
        "version": identity.version,
        "state": state,
        "refusals": refusals,
        "revoked": identity.revoked,
        "revocations": [revocation.describe() for revocation in identity.revocations],
        "needs_rotation": identity.needs_rotation(now=now),
    }


@agent.command("enroll")
@click.option("--agent-id", "agent_id", required=True, metavar="ID", help="Agent id to enroll.")
@click.option(
    "--controller-id",
    "controller_id",
    required=True,
    metavar="ID",
    help="The controller that owns this agent's credentials.",
)
@click.option(
    "--principal",
    "principal_id",
    required=True,
    metavar="ID",
    help="Principal this agent acts as (declared; nothing authenticates it).",
)
@click.option(
    "--principal-kind",
    "principal_kind",
    type=click.Choice(["human", "service_account", "workload"]),
    default="workload",
    show_default=True,
    help="Issuer class of the principal.",
)
@click.option(
    "--environment",
    required=True,
    metavar="NAME",
    help="Environment the agent's authority is bounded by.",
)
@click.option(
    "--ttl-seconds",
    "ttl_seconds",
    type=float,
    default=3600.0,
    show_default=True,
    help="Credential lifetime; an eternal credential is unrepresentable.",
)
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def enroll(
    ctx: click.Context,
    agent_id: str,
    controller_id: str,
    principal_id: str,
    principal_kind: str,
    environment: str,
    ttl_seconds: float,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Enroll an agent identity: the first record, with a bounded credential.

    Writes identity, not key material: no secret is generated, read, or stored
    here. An already-enrolled agent is refused rather than overwritten — the
    upgrade path from an existing record is `rotate` (plan 19), not a second
    enrollment that would reset its version to 1.
    """
    from mayhem.domain.agent_identity import AgentCredential, AgentIdentity
    from mayhem.domain.errors import InvariantViolationError
    from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
    from pydantic import ValidationError

    store, identities = _open(ctx, db_opt)
    try:
        if identities.load(agent_id) is not None:
            click.echo(
                f"error: agent {agent_id!r} is already enrolled. Enrollment writes the first "
                "record and refuses to replace one: re-enrolling would reset its version to 1 "
                "and launder its revocation history. Rotate its credential (`mayhem ha rotate`) "
                "or revoke it (`mayhem agent revoke`) instead.",
                err=True,
            )
            ctx.exit(int(ExitCode.SAFETY_REFUSAL))
        issued = _now()
        try:
            identity = AgentIdentity(
                agent_id=agent_id,
                controller_id=controller_id,
                principal=Principal(principal_id=principal_id, kind=PrincipalKind(principal_kind)),
                scope=EnvironmentScope(environment=environment),
                credential=AgentCredential(
                    credential_id=f"cred-{agent_id}-{int(issued.timestamp())}",
                    agent_id=agent_id,
                    issued_at=issued,
                    expires_at=issued + timedelta(seconds=ttl_seconds),
                ),
            )
        except (InvariantViolationError, ValidationError) as exc:
            click.echo(
                f"error: {exc}. A credential window must be a positive, timezone-aware "
                "interval over well-formed ids; enrollment refuses to write a record that "
                "cannot authenticate.",
                err=True,
            )
            ctx.exit(int(ExitCode.VALIDATION_ERROR))
        saved = identities.save(identity)
    finally:
        store.close()

    payload = _payload(saved, issued)
    payload["key_material"] = "none"
    payload["note"] = (
        "identity record only: no key material is generated, read, or stored by this "
        "command; the credential names a window, not a secret"
    )
    from mayhem.cli.output import echo_machine

    if echo_machine(payload, as_json=as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    click.echo(
        f"enrolled {saved.agent_id} as {saved.principal.principal_id} "
        f"({saved.scope.environment}) controller={saved.controller_id}"
    )
    click.echo(
        f"credential {saved.credential.credential_id} valid until "
        f"{saved.credential.expires_at.isoformat()}"
    )
    click.echo("no key material was generated or stored; the record names a window, not a secret")
    ctx.exit(int(ExitCode.SUCCESS))


@agent.command("list")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def list_agents(ctx: click.Context, db_opt: str | None, as_json: bool) -> None:
    """Every enrolled agent, with the state the verifier would reach now."""
    now = _now()
    store, identities = _open(ctx, db_opt)
    try:
        rows = [_payload(identity, now) for identity in identities.list_agents()]
    finally:
        store.close()

    payload = {"agents": rows, "count": len(rows), "as_of": now.isoformat()}
    from mayhem.cli.output import echo_machine

    if echo_machine(payload, as_json=as_json):
        return
    if not rows:
        click.echo("no agent is enrolled; enroll one with `mayhem agent enroll`")
        return
    for row in rows:
        refusals = ",".join(row["refusals"]) if row["refusals"] else "-"
        click.echo(
            f"{row['agent_id']:<24} {row['principal']:<20} {row['environment']:<14} "
            f"{row['state']:<12} expires={row['expires_at']} refusals={refusals}"
        )
    ctx.exit(int(ExitCode.SUCCESS))


@agent.command("show")
@click.argument("agent_id")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def show(ctx: click.Context, agent_id: str, db_opt: str | None, as_json: bool) -> None:
    """One enrolled agent, and whether it may authenticate right now.

    Exits non-zero when the identity may not authenticate, so a pipeline reads
    the same verdict the verifier would reach rather than a rendering of it.
    """
    now = _now()
    store, identities = _open(ctx, db_opt)
    try:
        identity = identities.load(agent_id)
    finally:
        store.close()
    if identity is None:
        click.echo(
            f"error: agent {agent_id!r} is not enrolled; there is no record to show. "
            "Enroll it with `mayhem agent enroll`.",
            err=True,
        )
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    payload = _payload(identity, now)
    payload["as_of"] = now.isoformat()
    from mayhem.cli.output import echo_machine

    if echo_machine(payload, as_json=as_json):
        ctx.exit(int(ExitCode.SUCCESS if payload["state"] == "usable" else ExitCode.SAFETY_REFUSAL))
    click.echo(f"agent {identity.agent_id} controller={identity.controller_id}")
    click.echo(f"principal {identity.principal.principal_id} ({identity.principal.kind.value})")
    click.echo(f"scope {identity.scope.environment} version={identity.version}")
    click.echo(
        f"credential {identity.credential.credential_id} "
        f"{identity.credential.issued_at.isoformat()} -> {identity.credential.expires_at.isoformat()}"
    )
    click.echo(f"state {payload['state']}")
    for revocation in payload["revocations"]:
        click.echo(f"revocation {revocation}")
    if payload["refusals"]:
        click.echo(f"refusals {','.join(payload['refusals'])}")
    ctx.exit(int(ExitCode.SUCCESS if payload["state"] == "usable" else ExitCode.SAFETY_REFUSAL))


@agent.command("revoke")
@click.option("--agent-id", "agent_id", required=True, metavar="ID", help="Agent to revoke.")
@click.option(
    "--reason",
    type=click.Choice(
        ["expired", "rotation_overdue", "compromised", "decommissioned", "operator_request"]
    ),
    required=True,
    help="Why the identity is being pulled; travels with the record.",
)
@click.option(
    "--by",
    "revoked_by",
    required=True,
    metavar="WHO",
    help="Who is revoking, as declared. Nothing authenticates it.",
)
@click.option("--note", default="", help="Free-form context for an incident review.")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def revoke(
    ctx: click.Context,
    agent_id: str,
    reason: str,
    revoked_by: str,
    note: str,
    db_opt: str | None,
    as_json: bool,
) -> None:
    """Pull an enrolled identity: absolute, and the first revocation wins."""
    from mayhem.domain.agent_identity import Revocation, RevocationReason

    if not revoked_by.strip():
        click.echo(
            "error: --by must be a non-blank actor. A revocation with no revoker is the one "
            "provenance an incident review cannot reconstruct.",
            err=True,
        )
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    now = _now()
    failure: tuple[ExitCode, str] | None = None
    revoked = None
    store, identities = _open(ctx, db_opt)
    try:
        existing = identities.load(agent_id)
        if existing is None:
            failure = (
                ExitCode.VALIDATION_ERROR,
                f"agent {agent_id!r} is not enrolled; there is nothing to revoke. "
                "Revoking a name nobody enrolled would record an event against a record "
                "that does not exist. Enroll it with `mayhem agent enroll` first.",
            )
        elif existing.revoked:
            failure = (
                ExitCode.SAFETY_REFUSAL,
                f"agent {agent_id!r} is already revoked "
                f"({existing.revocations[0].describe()}). A revocation is absolute and the "
                "first one wins; refusing rather than recording a second reason over the "
                "actor the incident review needs.",
            )
        else:
            revoked = identities.revoke_agent(
                agent_id,
                Revocation(
                    reason=RevocationReason(reason),
                    revoked_at=now,
                    revoked_by=revoked_by,
                    note=note,
                ),
            )
    finally:
        store.close()
    if failure is not None:
        code, message = failure
        click.echo(f"error: {message}", err=True)
        ctx.exit(int(code))
    assert revoked is not None

    payload = _payload(revoked, now)
    from mayhem.cli.output import echo_machine

    if echo_machine(payload, as_json=as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    click.echo(f"revoked {revoked.agent_id} ({reason}) by {revoked_by}")
    click.echo("the identity may not authenticate from now on; revocation has no expiry")
    ctx.exit(int(ExitCode.SUCCESS))
