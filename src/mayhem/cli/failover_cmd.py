"""``mayhem ha`` — the operator surface for plan 19's HA/DR decisions.

This module is **not registered** in :mod:`mayhem.cli.command_registry`; it is
invoked directly (``CliRunner().invoke(failover_cmd.ha, …)``) and reached through
whatever mounts it, exactly as the ledger for this plan states. Four commands, one
per thing an operator does when the control plane is in trouble or a release has
to be checked before it is installed:

``ha promote``
    Take the leadership scope, or be refused by name. The evidence is **read from
    the replicated store, not typed at the prompt**: an expired lease for the
    recorded term is a durable fact, so it can be established without reaching the
    primary. There is deliberately **no flag for "we cannot reach it, so take
    over"** — the dangerous branch is the one a CLI most makes easy and must least
    offer.

    Break-glass is two flags, because it is two separate claims. ``--forced`` says
    "I am taking this from a live lease"; ``--attest-process-gone`` supplies the
    only death evidence this surface can honestly offer, the operator's own
    attested account of an out-of-process witness, recorded with their name as the
    observation's source. Neither flag alone promotes: forcing without evidence is
    refused, and evidence without forcing is refused while the lease is live. Both
    are recorded on the promotion row and in the sealed evidence, and the term
    still strictly increases, so the deposed leader loses authority at once.

``ha rotate``
    Apply the deployment's rotation policy: ``--agent`` rotates one credential,
    ``--all`` sweeps the due ones. The output says whether a signing key was
    provisioned, because a rotation without one leaves the agent holding a
    credential it cannot authenticate with — a fail-closed window, not a done
    rotation.

``ha cert verify``
    Verify a presented certificate against a configured fixture authority. Six
    refusals have names, and ``--algorithm x509`` **raises**
    ``agent_signature_port_unavailable`` rather than passing: CA-backed mTLS is
    not implemented in this build, and a CLI that returned "trusted" for an
    algorithm it cannot check would be the worst possible place for that lie.

``ha update check``
    Verify a signed update manifest *before* anything is applied and refuse with
    every reason that fired. It never installs: the applier is a separate call that
    requires the verdict this command prints.

Honesty commitments the code makes structurally
-----------------------------------------------

* **A secret is never an argument.** Every key is read from a named environment
  variable (``--key-env``), so nothing sensitive lands in shell history, in
  ``ps``, or in a CI log line.
* **A refusal is the interesting output.** Promotion refusals exit
  ``SAFETY_REFUSAL`` and print every reason; they are not swallowed and turned
  into a zero exit code.
* **An unavailable port is not a refusal.** It exits ``TOOLKIT_ERROR``, because
  "we could not check" and "checked and wrong" are different facts and an operator
  must be able to tell them apart in a script.
* **No command here can bypass a gate.** There is no ``--force`` on rotation, no
  ``--skip-verify`` on the update check, and no ``--trust-me`` on certificates.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from mayhem.cli import style
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from mayhem.controller.credential_rotation import CredentialRotationService, RotationOutcome
    from mayhem.controller.failover_service import FailoverService
    from mayhem.domain.failover import LivenessObservation
    from mayhem.infra.certificate_authority import IssuedCertificate, MtlsRole, TrustVerdict
    from mayhem.infra.update_manifest import ManifestVerdict, UpdateChannel, UpdateVerifier

__all__ = [
    "DEFAULT_CONTROLLER_ID",
    "DEFAULT_SCOPE",
    "KEY_ENV_PREFIX",
    "PromoteResult",
    "ha",
    "render_promotion",
    "render_rotation",
    "render_trust",
    "render_update_verdict",
    "run_cert_verify",
    "run_promote",
    "run_rotate",
    "run_update_check",
    "secret_from_env",
]

DEFAULT_CONTROLLER_ID = "ctl-local"
DEFAULT_SCOPE = "control-plane"
DEFAULT_POLICY_ID = "p-default"
KEY_ENV_PREFIX = "MAYHEM_HA_"

#: Refusal codes this surface turns into ``SAFETY_REFUSAL`` rather than a crash.
#: They are matched by prefix, so a new ``mtls_*`` or ``update_*`` code is covered
#: without editing this list.
_REFUSAL_PREFIXES = ("failover_", "mtls_", "update_manifest_")


def secret_from_env(name: str, *, env: Mapping[str, str] | None = None) -> bytes:
    """Read a secret from ``env[name]`` (or the process environment).

    Args:
        name: The environment variable to read. The caller chooses the name; the
            convention is :data:`KEY_ENV_PREFIX` plus the key id.
        env: Injected for tests.

    Raises:
        MayhemCliError: ``config_error`` when the variable is unset or empty. An
            unset key is never treated as an empty key: minting or verifying with
            an empty secret would make the check vacuous.
    """
    source = os.environ if env is None else env
    raw = str(source.get(name, "")).strip()
    if not raw:
        raise MayhemCliError(
            code="config_error",
            message=f"environment variable {name!r} is not set",
            details={"variable": name},
            remediation=(
                f"export {name}=<secret>; mayhem reads keys from the environment so a "
                "secret never appears in a command line, in shell history, or in a "
                "process listing"
            ),
        )
    return raw.encode("utf-8")


def _refusal_code(code: str) -> str:
    return "safety_refusal" if code.startswith(_REFUSAL_PREFIXES) else "general_failure"


def _exit_for(code: str) -> ExitCode:
    return (
        ExitCode.SAFETY_REFUSAL if code.startswith(_REFUSAL_PREFIXES) else ExitCode.GENERAL_FAILURE
    )


# --------------------------------------------------------------------------- #
# ha promote                                                                     #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PromoteResult:
    """What ``ha promote`` did, and what it decided on.

    Attributes:
        promoted: Whether this controller now holds the scope.
        claimed: True when no lease was recorded and the command *campaigned*.
            Claiming an empty scope is not a failover, and the two are rendered
            differently so a first controller's claim never reads as a takeover.
        term_before: The term the stored lease held before the command (``0`` when
            nothing held the scope).
        term_after: The term the scope holds now, or ``0`` on a refusal.
        scope / standby_id / operator / reason / forced: What was asked for.
        refusals: The canonical refusal names, empty on success.
        detail: The account a reader gets.
    """

    promoted: bool
    claimed: bool
    term_before: int
    term_after: int
    scope: str
    standby_id: str
    operator: str
    reason: str
    forced: bool
    refusals: tuple[str, ...]
    detail: str

    def payload(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "standby_id": self.standby_id,
            "operator": self.operator,
            "reason": self.reason,
            "forced": self.forced,
            "promoted": self.promoted,
            "claimed": self.claimed,
            "term_before": self.term_before,
            "term_after": self.term_after,
            "refusals": list(self.refusals),
            "detail": self.detail,
            # Stated in the payload, not just in prose: the record proves this
            # process wrote these bytes, not who the controller was.
            "standby_id_is_a_claim": True,
        }


def run_promote(
    *,
    service: FailoverService,
    observations: Sequence[LivenessObservation],
    operator: str,
    reason: str,
    forced: bool = False,
    attested_process_gone: bool = False,
    at: datetime | None = None,
) -> PromoteResult:
    """Promote, or return the refusal. Everything the CLI needs, no Click.

    The observations come from the caller, which in this surface means the
    leadership store's own record — see :func:`lease_expiry_observation`.

    Args:
        service: The failover service, built over the replicated store.
        observations: The evidence the decision may be built on.
        operator: Who is performing it. Required.
        reason: Why, in the operator's words. Required.
        forced: Take the scope from a lease that has not expired. Recorded as such.
        attested_process_gone: Add the operator's claim that an out-of-process
            witness (a service manager, a PID namespace, a container runtime)
            reported the primary's process as absent. **A claim, not a
            observation mayhem made**, and the sealed record names the operator as
            its source so nobody later reads it as a measurement.
        at: Injected instant.

    Raises:
        MayhemCliError: ``validation_error`` when no operator or reason is named —
            a takeover with nobody accountable is the one nobody can audit.
    """
    if not operator.strip() or not reason.strip():
        raise MayhemCliError(
            code="validation_error",
            message="--operator and --reason are both required",
            details={"operator": operator, "reason": reason},
            remediation=(
                "a promotion names who did it and why; both are recorded on the "
                "promotion row and in the sealed evidence"
            ),
        )
    moment = at
    lease = service.current_lease()
    if lease is None:
        claimed = service.campaign(at=moment)
        return PromoteResult(
            promoted=True,
            claimed=True,
            term_before=0,
            term_after=claimed.term,
            scope=service.scope,
            standby_id=service.controller_id,
            operator=operator,
            reason=reason,
            forced=forced,
            refusals=(),
            detail=(
                f"no lease was recorded for scope {service.scope!r}, so nothing was "
                f"deposed: {service.controller_id} campaigned onto term {claimed.term}. "
                "No promotion record claims a deposed leader it never had."
            ),
        )
    evidence: tuple[LivenessObservation, ...] = tuple(observations)
    if attested_process_gone:
        # A stamped observation needs a real instant, so an omitted ``at`` falls
        # back to the wall clock the service itself would have read.
        evidence = (
            *evidence,
            *_process_gone_claims(
                term=lease.term,
                at=moment if moment is not None else utc_now(),
                operator=operator,
            ),
        )
    decision = service.promote_if_dead(
        evidence, operator=operator, reason=reason, forced=forced, now=moment
    )
    return PromoteResult(
        promoted=decision.promoted,
        claimed=False,
        term_before=lease.term,
        term_after=decision.new_term if decision.new_term is not None else lease.term,
        scope=decision.request.scope,
        standby_id=decision.request.standby_id,
        operator=operator,
        reason=reason,
        forced=forced,
        refusals=tuple(reason.value for reason in decision.refusals),
        detail=decision.detail,
    )


def lease_expiry_observation(
    *, term: int, at: datetime, expired: bool
) -> tuple[LivenessObservation, ...]:
    """The observation a store read can honestly support.

    A lease that **is** expired produces
    :attr:`~mayhem.domain.failover.LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED` — a
    durable fact. A lease that is **not** expired produces
    :attr:`~mayhem.domain.failover.LivenessEvidenceKind.NO_EVIDENCE`, and that
    choice is deliberate in both directions: a live lease is *not* evidence the
    primary answered, so calling it liveness evidence would contradict the
    operator's attested process-absence and refuse a legitimate break-glass
    handover; and it is equally not evidence of death. ``NO_EVIDENCE`` says
    exactly what the store can say — the ledger records a leader, and mayhem cannot
    show it is gone. Either way the observation names ``lease-store`` as its
    source, because it is the store's record and nobody's guess.
    """
    from mayhem.domain.failover import LivenessEvidenceKind, LivenessObservation

    kind = (
        LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED if expired else LivenessEvidenceKind.NO_EVIDENCE
    )
    return (
        LivenessObservation(
            kind=kind,
            observed_term=term,
            observed_at=at,
            source="lease-store",
            detail=(
                f"the leadership lease for term {term} is past its expiry in the replicated store"
                if expired
                else f"the leadership lease for term {term} has NOT expired in the "
                "replicated store, so this is not evidence the primary is gone"
            ),
        ),
    )


def _process_gone_claims(
    *, term: int, at: datetime, operator: str
) -> tuple[LivenessObservation, ...]:
    """The operator's own "the process is gone", as an explicitly-attributed claim.

    ``PRIMARY_PROCESS_GONE`` is one of the two kinds that can establish death, and
    the only way this surface can supply one: the store records a *leader*, and
    "I watched the service manager report it absent" is not something a database
    row says. The source is therefore the operator's name, not a machine, and the
    detail says so in the evidence itself rather than only in a help string.
    """
    from mayhem.domain.failover import LivenessEvidenceKind, LivenessObservation

    return (
        LivenessObservation(
            kind=LivenessEvidenceKind.PRIMARY_PROCESS_GONE,
            observed_term=term,
            observed_at=at,
            source=f"operator:{operator}",
            detail=(
                f"{operator} attests that an out-of-process witness reported the "
                "primary's process absent; this is an operator's claim recorded as "
                "evidence, not an observation mayhem made, and it cannot be verified "
                "from here"
            ),
        ),
    )


def render_promotion(result: PromoteResult) -> list[str]:
    """The operator-facing account. Every refusal is named."""
    lines = [f"scope {result.scope!r}: term {result.term_before} → {result.term_after}"]
    if result.claimed:
        lines.append(
            style.ok(
                f"claimed by {result.standby_id} for {result.operator}",
                err=False,
            )
        )
    elif result.promoted:
        lines.append(style.ok(f"promoted {result.standby_id} by {result.operator}", err=False))
    else:
        names = ", ".join(result.refusals) or "unspecified"
        lines.append(style.warn(f"REFUSED promotion ({names})"))
    lines.append(f"  {result.detail}")
    lines.append(
        "  standby_id is a claim this process wrote; no handshake or certificate "
        "exchange authenticated it"
    )
    return lines


# --------------------------------------------------------------------------- #
# ha rotate                                                                      #
# --------------------------------------------------------------------------- #


def run_rotate(
    service: CredentialRotationService,
    *,
    agent_id: str = "",
    sweep: bool = False,
    limit: int | None = None,
    at: datetime | None = None,
) -> tuple[RotationOutcome, ...]:
    """Rotate one agent or sweep the due ones.

    Raises:
        MayhemCliError: ``usage_error`` unless exactly one of ``agent_id`` and
            ``sweep`` is named. "Rotate everything" must be typed, because it is a
            different act from "rotate this one".
    """
    if bool(agent_id) == bool(sweep):
        raise MayhemCliError(
            code="usage_error",
            message="name exactly one target: --agent AGENT_ID, or --all",
            details={"agent": agent_id, "sweep": sweep},
            remediation="a sweep is an explicit act; naming one agent is not",
        )
    if agent_id:
        return (service.rotate(agent_id, at=at),)
    return service.rotate_due(at=at, limit=limit)


def render_rotation(outcomes: Sequence[RotationOutcome]) -> list[str]:
    """One line per agent, plus the summary that makes a broken sweep visible."""
    lines = [line for outcome in outcomes for line in (f"  {outcome.describe()}",)]
    rolled = sum(1 for outcome in outcomes if outcome.rotated)
    keyless = sum(1 for outcome in outcomes if outcome.rotated and not outcome.key_provisioned)
    failed = sum(1 for outcome in outcomes if outcome.failed)
    lines.append(f"rotated {rolled}, failed {failed}, rotated-without-a-key {keyless}")
    if keyless:
        lines.append(
            style.warn(
                f"{keyless} agent(s) now hold a credential they cannot authenticate "
                "with until a key provisioner issues one; the command verifier refuses "
                "an unknown signing key, so this fails closed"
            )
        )
    return lines


# --------------------------------------------------------------------------- #
# ha cert verify                                                                 #
# --------------------------------------------------------------------------- #


def run_cert_verify(
    *,
    certificate: IssuedCertificate | None,
    ca_id: str,
    secret: bytes,
    pinned_fingerprint: str = "",
    required_role: MtlsRole,
    at: datetime,
    algorithm: str = "fixture",
    revoked_serials: Sequence[str] = (),
) -> TrustVerdict:
    """Verify one presented certificate, or return the refusal naming itself.

    Args:
        certificate: What the peer presented. ``None`` is a refusal, not a pass.
        ca_id: The authority the anchors name.
        secret: The authority's shared key, resolved by the caller from the
            environment rather than passed on a command line.
        pinned_fingerprint: The leaf fingerprint the deployment pins. Empty means
            nothing is pinned, which is a **refusal** — never an implicit trust.
        required_role: The role this link needs.
        at: Injected instant.
        algorithm: ``fixture`` or ``x509``. ``x509`` refuses with
            ``agent_signature_port_unavailable`` and never returns a verdict.
        revoked_serials: Serials the authority has revoked.

    Raises:
        MayhemCliError: ``unavailable_engine`` for an algorithm this build cannot
            check. Never ``safety_refusal``: nothing was checked.
        MayhemCliError: ``config_error`` when the authority key is too short to be
            an HMAC key — minting with it would produce a certificate every
            verifier accepts.
    """
    from mayhem.domain.agent_identity import TrustAnchorRef
    from mayhem.infra.agent_identity_verifier import ALGORITHM_X509, SIGNATURE_PORT_UNAVAILABLE
    from mayhem.infra.certificate_authority import (
        CA_ALGORITHM_FIXTURE,
        CaKeyMaterial,
        FixtureCertificateAuthority,
        MtlsTrustService,
        RecordedRevocations,
    )

    if algorithm == ALGORITHM_X509:
        # Deliberately before anything else is read: an algorithm we cannot check
        # must not produce a verdict about a certificate we did look at.
        raise MayhemCliError(
            code="unavailable_engine",
            message=SIGNATURE_PORT_UNAVAILABLE,
            details={"algorithm": algorithm, "role": required_role.value},
            remediation=(
                "CA-backed X.509 mTLS is not implemented in this build: there is no "
                "X.509 parser, chain builder, or revocation protocol, and the plan adds "
                "no third-party dependency. Configure the fixture authority, which "
                f"reports its algorithm as {CA_ALGORITHM_FIXTURE} and proves only that a "
                "holder of that shared key issued these bytes"
            ),
        )
    if len(secret) < FixtureCertificateAuthority.minimum_key_bytes:
        raise MayhemCliError(
            code="config_error",
            message=(
                f"the authority key is {len(secret)} bytes; the fixture authority needs "
                f"at least {FixtureCertificateAuthority.minimum_key_bytes}"
            ),
            details={"ca_id": ca_id},
            remediation="a short shared key buys no size and would be brute-forceable",
        )
    anchors = (
        (
            TrustAnchorRef(
                ca_id=ca_id,
                subject=ca_id,
                sha256_fingerprint=pinned_fingerprint,
            ),
        )
        if pinned_fingerprint
        else ()
    )
    service = MtlsTrustService(
        FixtureCertificateAuthority(CaKeyMaterial({ca_id: secret})),
        anchors=anchors,
        revoked=RecordedRevocations(revoked_serials),
    )
    return service.authorize(certificate, required_role=required_role, at=at)


def render_trust(verdict: TrustVerdict) -> list[str]:
    """One line, with the algorithm on it so a fixture verdict cannot read as PKI."""
    mark = style.ok("trusted", err=False) if verdict.trusted else style.warn("REFUSED")
    return [f"{mark} {verdict.describe()}"]


# --------------------------------------------------------------------------- #
# ha update check                                                                #
# --------------------------------------------------------------------------- #


def run_update_check(
    *,
    verifier: UpdateVerifier,
    manifest_path: Path,
    component: str | None = None,
    installed_version: str | None = None,
    expected_channel: UpdateChannel | None = None,
    at: datetime | None = None,
) -> ManifestVerdict:
    """Verify a manifest document from disk. **Never installs anything.**

    Raises:
        MayhemCliError: ``config_error`` for an unreadable or non-JSON document,
            with the manifest id when the file parsed far enough to name one.
    """
    from mayhem.infra.update_manifest import UpdateComponent, UpdateManifest

    try:
        raw = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MayhemCliError(
            code="config_error",
            message=f"cannot read an update manifest from {manifest_path}: {exc}",
            details={"path": str(manifest_path)},
            remediation="pass the path of a JSON manifest the release channel published",
        ) from exc
    try:
        manifest = UpdateManifest.model_validate(raw)
    except Exception as exc:  # pydantic's error type is not this module's contract
        raise MayhemCliError(
            code="config_error",
            message=f"the manifest at {manifest_path} is not a valid update manifest: {exc}",
            details={"path": str(manifest_path)},
            remediation=(
                "a manifest must carry its component, versions, artifact digest, "
                "channel, validity window, signer key id, signature, and its SBOM and "
                "provenance references"
            ),
        ) from exc
    return verifier.verify(
        manifest,
        component=UpdateComponent(component) if component else None,
        installed_version=installed_version,
        downgrade_approval=os.environ.get(f"{KEY_ENV_PREFIX}DOWNGRADE_APPROVAL", ""),
        at=at,
    )


def render_update_verdict(verdict: ManifestVerdict) -> list[str]:
    """The verdict verbatim. The word ``APPLICABLE`` is emitted only when it is true."""
    if verdict.applicable:
        return [style.ok(verdict.describe(), err=False)]
    names = ", ".join(reason.value for reason in verdict.refusals) or "unspecified"
    return [style.warn(f"REFUSED ({names})"), f"  {verdict.detail}"]


# --------------------------------------------------------------------------- #
# The Click group                                                                #
# --------------------------------------------------------------------------- #


def _db_path(ctx: click.Context) -> str:
    return str(getattr(ctx.obj, "db", "mayhem.db"))


def utc_now() -> datetime:
    """The wall clock, imported once here so a helper can stamp a real instant."""
    from mayhem.domain.common import utc_now as _now

    return _now()


def _now() -> datetime:
    return utc_now()


@click.group("ha", invoke_without_command=False)
@click.pass_context
def ha(ctx: click.Context) -> None:
    """High availability: promote a standby, rotate credentials, check trust and updates."""
    del ctx


@ha.command("promote")
@click.option("--controller", "controller_id", default=DEFAULT_CONTROLLER_ID, show_default=True)
@click.option("--scope", default=DEFAULT_SCOPE, show_default=True)
@click.option(
    "--operator",
    "operator",
    default="",
    metavar="ID",
    help="Who is promoting. Required.",
)
@click.option("--reason", default="", metavar="TEXT", help="Why. Required.")
@click.option(
    "--forced",
    is_flag=True,
    default=False,
    help="Take the scope from a lease that has not expired. Recorded as forced; the "
    "term still strictly increases, so the deposed leader loses authority at once.",
)
@click.option(
    "--attest-process-gone",
    is_flag=True,
    default=False,
    help="Add the operator's claim that an out-of-process witness reported the "
    "primary's process absent. Recorded with the operator as its source; mayhem "
    "cannot verify it, and the claim travels into the sealed evidence.",
)
@click.option("--lease-ttl", default=30.0, show_default=True, help="Leadership lease lifetime.")
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def promote_command(
    ctx: click.Context,
    controller_id: str,
    scope: str,
    operator: str,
    reason: str,
    forced: bool,
    attest_process_gone: bool,
    lease_ttl: float,
    as_json: bool,
) -> None:
    """Promote this controller, or be refused and say why.

    The evidence is the leadership store's own record of the lease. There is
    deliberately no flag for "we cannot reach the primary, so take over": that
    is the branch which turns a partition into a split brain, and a CLI is the
    worst place to make it easy.
    """
    from mayhem.cli.services import open_store
    from mayhem.controller.failover_service import FailoverService
    from mayhem.controller.leader_election import LeaderElection, SqliteLeadershipStore
    from mayhem.infra.failover_store import FailoverPromotionStore

    now = _now()
    store = open_store(_db_path(ctx))
    try:
        election = LeaderElection(
            store=SqliteLeadershipStore(store),
            controller_id=controller_id,
            ttl_s=lease_ttl,
            scope=scope,
            clock=lambda: now,
        )
        service = FailoverService(
            store=FailoverPromotionStore(store),
            election=election,
            controller_id=controller_id,
            scope=scope,
            clock=lambda: now,
        )
        lease = service.current_lease()
        observations: tuple[LivenessObservation, ...] = (
            ()
            if lease is None
            else lease_expiry_observation(term=lease.term, at=now, expired=lease.is_expired_at(now))
        )
        result = run_promote(
            service=service,
            observations=observations,
            operator=operator,
            reason=reason,
            forced=forced,
            attested_process_gone=attest_process_gone,
            at=now,
        )
    finally:
        store.close()

    if as_json:
        click.echo(json.dumps(result.payload(), indent=2, sort_keys=True, default=str))
    else:
        for line in render_promotion(result):
            click.echo(line)
    ctx.exit(int(ExitCode.SUCCESS if result.promoted else ExitCode.SAFETY_REFUSAL))


@ha.command("rotate")
@click.option("--controller", "controller_id", default=DEFAULT_CONTROLLER_ID, show_default=True)
@click.option("--policy-id", default=DEFAULT_POLICY_ID, show_default=True)
@click.option("--agent", "agent_id", default="", metavar="AGENT_ID", help="Rotate one agent.")
@click.option("--all", "sweep", is_flag=True, default=False, help="Sweep every due agent.")
@click.option("--limit", default=None, type=int, help="Bound a sweep.")
@click.option("--ttl", "ttl_s", default=900.0, show_default=True)
@click.option("--rotate-before", "rotate_before_s", default=300.0, show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def rotate_command(
    ctx: click.Context,
    controller_id: str,
    policy_id: str,
    agent_id: str,
    sweep: bool,
    limit: int | None,
    ttl_s: float,
    rotate_before_s: float,
    as_json: bool,
) -> None:
    """Apply the deployment's rotation policy to credentials."""
    from mayhem.cli.services import open_store
    from mayhem.controller.credential_rotation import CredentialRotationService, RotationPolicy
    from mayhem.infra.agent_identity_store import AgentIdentityRepository

    now = _now()
    store = open_store(_db_path(ctx))
    try:
        service = CredentialRotationService(
            identities=AgentIdentityRepository(store),
            policy=RotationPolicy(
                policy_id=policy_id,
                credential_ttl_s=ttl_s,
                rotate_before_s=rotate_before_s,
            ),
            clock=lambda: now,
        )
        outcomes = run_rotate(service, agent_id=agent_id, sweep=sweep, limit=limit, at=now)
    finally:
        store.close()

    if as_json:
        click.echo(
            json.dumps(
                [outcome.model_dump(mode="json") for outcome in outcomes],
                indent=2,
                sort_keys=True,
                default=str,
            )
        )
    else:
        for line in render_rotation(outcomes):
            click.echo(line)
    ctx.exit(
        int(
            ExitCode.SUCCESS
            if all(not outcome.failed for outcome in outcomes)
            else ExitCode.SAFETY_REFUSAL
        )
    )


@ha.command("cert")
@click.option("--certificate", "certificate_path", default="", metavar="PATH")
@click.option("--ca-id", default="", metavar="ID", help="Which authority issued it.")
@click.option(
    "--key-env",
    default=f"{KEY_ENV_PREFIX}CA_KEY",
    show_default=True,
    help="Environment variable holding the authority key. Never a flag value.",
)
@click.option("--pin", "pinned_fingerprint", default="", metavar="HEX")
@click.option("--role", default="agent", show_default=True, help="The role this link requires.")
@click.option("--algorithm", default="fixture", show_default=True, help="fixture or x509.")
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def cert_command(
    ctx: click.Context,
    certificate_path: str,
    ca_id: str,
    key_env: str,
    pinned_fingerprint: str,
    role: str,
    algorithm: str,
    as_json: bool,
) -> None:
    """Verify a presented certificate against the configured authority."""
    from mayhem.infra.certificate_authority import IssuedCertificate, MtlsRole

    now = _now()
    certificate = None
    if certificate_path:
        try:
            certificate = IssuedCertificate.model_validate_json(
                Path(certificate_path).read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise MayhemCliError(
                code="config_error",
                message=f"cannot read a certificate from {certificate_path}: {exc}",
                details={"path": certificate_path},
                remediation="pass the path of a JSON certificate document",
            ) from exc
    verdict = run_cert_verify(
        certificate=certificate,
        ca_id=ca_id,
        secret=secret_from_env(key_env),
        pinned_fingerprint=pinned_fingerprint,
        required_role=MtlsRole(role),
        at=now,
        algorithm=algorithm,
    )
    if as_json:
        click.echo(
            json.dumps(
                {
                    "trusted": verdict.trusted,
                    "reason": verdict.reason.value,
                    "algorithm": verdict.algorithm,
                    "refusal_code": verdict.refusal_code,
                    "detail": verdict.detail,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for line in render_trust(verdict):
            click.echo(line)
    ctx.exit(int(ExitCode.SUCCESS if verdict.trusted else ExitCode.SAFETY_REFUSAL))


@ha.command("update")
@click.option("--manifest", "manifest_path", required=True, metavar="PATH")
@click.option("--signer-key-id", default="", metavar="ID")
@click.option(
    "--key-env",
    default=f"{KEY_ENV_PREFIX}RELEASE_KEY",
    show_default=True,
    help="Environment variable holding the release signing key.",
)
@click.option("--channel", default="stable", show_default=True)
@click.option("--component", default="", metavar="NAME", help="agent or controller.")
@click.option("--installed", "installed_version", default="", metavar="VERSION")
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def update_command(
    ctx: click.Context,
    manifest_path: str,
    signer_key_id: str,
    key_env: str,
    channel: str,
    component: str,
    installed_version: str,
    as_json: bool,
) -> None:
    """Verify a signed update manifest. This command never installs anything."""
    from mayhem.infra.agent_identity_verifier import HmacSha256SignatureVerifier, StaticKeyMaterial
    from mayhem.infra.update_manifest import UpdateChannel, UpdateVerifier

    now = _now()
    try:
        channel_value = UpdateChannel(channel)
    except ValueError as exc:
        raise MayhemCliError(
            code="usage_error",
            message=f"{channel!r} is not a release channel",
            details={"channel": channel},
            remediation=f"choose one of {[c.value for c in UpdateChannel]}",
        ) from exc
    keys = StaticKeyMaterial({signer_key_id: secret_from_env(key_env)})
    verdict = run_update_check(
        verifier=UpdateVerifier(
            signature=HmacSha256SignatureVerifier(keys),
            signer_keys=keys,
            expected_channel=channel_value,
        ),
        manifest_path=Path(manifest_path),
        component=component or None,
        installed_version=installed_version or None,
        expected_channel=channel_value,
        at=now,
    )
    if as_json:
        click.echo(
            json.dumps(
                {
                    "manifest_id": verdict.manifest_id,
                    "applicable": verdict.applicable,
                    "verified": verdict.verified,
                    "algorithm": verdict.algorithm,
                    "refusals": [reason.value for reason in verdict.refusals],
                    "detail": verdict.detail,
                    "manifest_digest": verdict.manifest_digest,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for line in render_update_verdict(verdict):
            click.echo(line)
    ctx.exit(int(ExitCode.SUCCESS if verdict.applicable else ExitCode.SAFETY_REFUSAL))
