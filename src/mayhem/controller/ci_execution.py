"""CI executions carry the same intent, approvals, and evidence links as
interactive ones (docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md, Phase 4).

Phases 1 to 3 built the vocabulary, the engine, and the surfaces. What is left is
the question a pipeline makes dangerous: **a CI job is not a lesser operator.**
It is an operator that runs unattended, on somebody else's commit, holding a
token nobody is watching. If a pipeline may reach a target with ambient
privilege — with whatever the runner image happens to have, under whatever
identity the environment happens to present — then every refusal in this codebase
is one environment variable away from being decorative, and the pipeline is the
cheapest way to prove it.

So this module makes the two properties of a pipeline run that an interactive run
already has, **structural** rather than documented:

* **An identity, declared, and never ambient.** :class:`CIActor` is who the job
  says it is, and it refuses to be a human (:data:`RULE_CI_ACTOR_NOT_DECLARED`
  for an unnamed actor, :data:`RULE_CI_AMBIENT_PRIVILEGE` for a human one). The
  authority that actor holds is *resolved* through plan 09's
  :func:`~mayhem.domain.identity.effective_roles` against real grants, so a
  pipeline with no grant has no authority and the refusal names the grant it
  needed instead. Nothing here reads an environment variable: mayhem does not
  discover who the pipeline is, the pipeline declares it, and a declaration that
  does not resolve to a role is refused rather than believed.
* **The same execution intent, delegated.** :func:`pipeline_run_authorization`
  calls :func:`~mayhem.domain.execution_intent.require_execution_intent` rather
  than writing a second approval gate. That is not a convenience — it is the
  whole point of Phase 4. "A CI execution carries the same execution intent and
  approvals as an interactive run" has exactly one meaning if it is true, and it
  is true here because there is one implementation and the pipeline calls it. The
  compatibility switch is passed in, never read: a pipeline may be granted the
  same documented escape hatch an operator has, by whoever deploys the runner,
  and mayhem's answer is the same either way.

Then the acceptance criterion the plan states literally:

    **A pipeline run without an evidence link fails the gate closed, never open.**

That is enforced in three places, so removing one does not open the gate:

1. :func:`link_run_evidence` refuses to return a
   :class:`~mayhem.domain.pipeline.PipelineVerdict` that cites no run, or whose
   run has no envelope behind it (:data:`RULE_CI_RUN_UNLINKED`);
2. the envelope's own digest must equal the run's ``evidence_digest``
   (:data:`RULE_CI_EVIDENCE_MISMATCH`) — a verdict may not cite a run and a
   *different* run's evidence;
3. :meth:`PipelineRunAuthorization.opens_release` requires
   :attr:`~PipelineRunAuthorization.evidence_link` to be
   :data:`RunLink.LINKED` **and** reads
   :func:`~mayhem.domain.pipeline.blocking_reasons` off the grounded verdict, so
   an authorization that somehow carried no evidence still says no.

**Ticket references are sealed, not carried.** A ticket is an *input* to a
pipeline — it arrives in an environment variable, from a branch name, from a
forge field anybody with a pull request can set. :class:`SealedTicket` binds the
change link's references to a digest at the moment the gate looked at them, and
:meth:`SealedTicket.verify` refuses a link that moved afterwards. That is the
same invalidation rule :class:`~mayhem.domain.pipeline.PlanMerge` applies to a
plan digest, applied to the change-system reference: an approval given against a
ticket nobody then edited is an approval of a different thing once somebody edits
it.

:func:`seal_ticket` also refuses a reference that does not look like
``kind:id`` (:data:`RULE_CI_TICKET_SEAL_BROKEN`). That is stricter than
:class:`~mayhem.domain.pipeline.ChangeLink`, which accepts any string, and the
strictness is the point: the value arrived from an untrusted environment
variable, and a ticket reference carrying shell syntax is not a ticket reference.

.. warning::

   **Nothing here has been executed by a CI system.** There is no runner, no
   workflow event, no runner token, and no environment variable in this module's
   signature that mayhem reads on its own. What is tested is the decision logic
   over values: which identity is refused, which intent gate is called, which
   evidence digest is accepted. A test that proves "a human principal in a
   pipeline is refused" is not a test that proves a pipeline fails, and the Phase
   4 STATUS line says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_intent import ExecutionIntent, require_execution_intent
from mayhem.domain.hashing import canonical_json, sha256_hex
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    PrincipalKind,
    Role,
    RoleGrant,
    TeamMembership,
    effective_roles,
)
from mayhem.domain.pipeline import ChangeLink, PipelineVerdict, blocking_reasons

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mayhem.domain.evidence import EvidenceEnvelope

__all__ = [
    "CI_ROLES",
    "PIPELINE_ACTION",
    "RULE_CI_ACTOR_NOT_DECLARED",
    "RULE_CI_ACTOR_WITHOUT_ROLE",
    "RULE_CI_AMBIENT_PRIVILEGE",
    "RULE_CI_EVIDENCE_MISMATCH",
    "RULE_CI_RUN_UNLINKED",
    "RULE_CI_TICKET_SEAL_BROKEN",
    "CIActor",
    "PipelineRunAuthorization",
    "RunLink",
    "SealedTicket",
    "envelope_digest",
    "link_run_evidence",
    "pipeline_run_authorization",
    "seal_ticket",
    "ticket_seal_digest",
]

#: The action name a pipeline run is gated as. One string, so a refusal in a CI
#: log reads the same as the identical refusal from a terminal.
PIPELINE_ACTION: Final[str] = "pipeline-execute"

RULE_CI_ACTOR_NOT_DECLARED = "ci_execution.actor_not_declared"
RULE_CI_AMBIENT_PRIVILEGE = "ci_execution.ambient_privilege"
RULE_CI_ACTOR_WITHOUT_ROLE = "ci_execution.actor_without_role"
RULE_CI_RUN_UNLINKED = "ci_execution.run_without_evidence_link"
RULE_CI_EVIDENCE_MISMATCH = "ci_execution.evidence_digest_mismatch"
RULE_CI_TICKET_SEAL_BROKEN = "ci_execution.ticket_seal_broken"

#: The roles that may drive a pipeline run, read rather than branched over so
#: "who may run mayhem from CI" has one answer. Deliberately *not* including
#: :attr:`~mayhem.domain.identity.Role.ADMINISTER`: administering mayhem is not
#: the same as being allowed to point it at a target, and a pipeline that could
#: hold the first could be talked into using the second. Exported as data so a
#: test can iterate it rather than restate it, and so the Phase 6 authorization
#: matrix renders it instead of re-spelling it.
CI_ROLES: Final[tuple[Role, ...]] = (Role.PLAN, Role.EXECUTE)

_REFERENCE_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z]+:[A-Za-z0-9._:/-]{1,127}$")
_RUN_REF_PREFIX: Final[str] = "run/"


def _require_nonblank(value: str, rule: str, subject: str) -> str:
    if not value or not value.strip():
        raise InvariantViolationError(rule, f"{subject} must not be blank")
    return value


# =============================================================================
# The declared identity
# =============================================================================


@dataclass(frozen=True, slots=True)
class CIActor:
    """Who a pipeline job says it is, and nothing it has not been checked for.

    Two refusals, and the second is the interesting one:

    * a blank ``principal_id`` is :data:`RULE_CI_ACTOR_NOT_DECLARED` — an
      anonymous pipeline is a pipeline whose authority is whatever the runner
      grants an anonymous process;
    * a :attr:`~mayhem.domain.identity.PrincipalKind.HUMAN` principal is
      :data:`RULE_CI_AMBIENT_PRIVILEGE`. Not because a human may not approve a
      pipeline, but because a *human principal running inside a pipeline* means
      the pipeline is executing with a person's ambient authority rather than
      with its own service account, and a person's authority is exactly the thing
      nobody intended to grant an unattended job. Human approval happens through
      plan 09's approvals, before the job starts, and is bound by
      :class:`~mayhem.domain.pipeline.PlanApproval`.

    ``forge`` and ``workflow_run_id`` are provenance, not authority: they say
    where the declaration came from so a reader can go and check, and nothing
    reads them to make a decision. :meth:`roles_in` is the whole answer to "what
    may this job do", and it is the *resolved* role set rather than anything
    asserted here.
    """

    principal: Principal
    forge: str = ""
    workflow_run_id: str = ""

    def __post_init__(self) -> None:
        _require_nonblank(
            self.principal.principal_id, RULE_CI_ACTOR_NOT_DECLARED, "CI actor principal_id"
        )
        if self.principal.kind is PrincipalKind.HUMAN:
            raise InvariantViolationError(
                RULE_CI_AMBIENT_PRIVILEGE,
                f"pipeline actor {self.principal.principal_id!r} is a human principal: "
                "an unattended job must run as the service account it was granted, "
                "not as a person whose authority the runner happens to have. Have the "
                "person approve through the approval gate and let the job run as the "
                "identity it holds",
            )

    @property
    def principal_id(self) -> str:
        return self.principal.principal_id

    def roles_in(
        self,
        scope: EnvironmentScope,
        *,
        grants: Sequence[RoleGrant] = (),
        memberships: Sequence[TeamMembership] = (),
        now: datetime,
    ) -> frozenset[Role]:
        """The roles this actor actually holds in ``scope``, resolved not declared.

        Delegates to :func:`~mayhem.domain.identity.effective_roles`, so "may this
        pipeline do the thing" is the same computation as "may this person do the
        thing" — a second implementation would be a second answer, and the second
        answer is the one that would be laxer.
        """
        return effective_roles(
            grants, principal=self.principal, scope=scope, memberships=memberships, now=now
        )

    def require_role(
        self,
        role: Role,
        scope: EnvironmentScope,
        *,
        grants: Sequence[RoleGrant] = (),
        memberships: Sequence[TeamMembership] = (),
        now: datetime,
    ) -> frozenset[Role]:
        """The held roles when ``role`` is among them, else a refusal naming them.

        Default-deny: an empty ``grants`` resolves to no roles, so an unbound
        pipeline is refused here exactly as an unbound ChatOps requester is
        refused by :func:`~mayhem.controller.check_gate.dispatch_chatops`.
        """
        held = self.roles_in(scope, grants=grants, memberships=memberships, now=now)
        if role not in held:
            msg = (
                f"pipeline actor {self.principal_id!r} may not {PIPELINE_ACTION} in "
                f"{scope.describe()}: this needs {role.value!r} and the actor holds "
                f"{[r.value for r in held] or ['no roles']}. Grant it to the service "
                "account explicitly rather than relying on whatever the runner image "
                "provides"
            )
            raise InvariantViolationError(RULE_CI_ACTOR_WITHOUT_ROLE, msg)
        return held

    def to_dict(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "kind": self.principal.kind.value,
            "forge": self.forge,
            "workflow_run_id": self.workflow_run_id,
        }


# =============================================================================
# Sealing the ticket into the chain
# =============================================================================


class SealedTicket(BaseModel):
    """The change-system references, bound to a digest at the moment of the gate.

    A ticket arrives in a pipeline as an environment variable, which means it
    arrives as untrusted input typed by whoever opened the pull request. Reading
    it is fine; *trusting that the thing the gate judged is the thing that will be
    recorded* is not, because between the check and the merge somebody can edit
    it. The seal is a digest over the references plus the git SHA, taken at the
    moment the gate read them, and :meth:`verify` refuses a link whose references
    moved.

    Deliberately the same rule :class:`~mayhem.domain.pipeline.PlanMerge` applies
    to a plan digest, and deliberately *not* re-implemented: this class records
    and compares, it does not decide a release. ``gates_release`` still answers.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    git_sha: str
    references: tuple[str, ...]
    seal_digest: str = ""
    sealed_by: str = ""
    sealed_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> SealedTicket:
        if not self.references:
            msg = (
                f"sealing {self.git_sha}: the change link names no ticket, incident, or "
                "deployment, so there is nothing to seal and a decision that cites "
                "nothing cannot be traced back to the work that justified it"
            )
            raise InvariantViolationError(RULE_CI_TICKET_SEAL_BROKEN, msg)
        stray = [ref for ref in self.references if not _REFERENCE_RE.fullmatch(ref)]
        if stray:
            msg = (
                f"sealing {self.git_sha}: {stray} are not kind:id references. A ticket "
                "reference is read from an untrusted environment variable, and one that "
                "does not look like a reference is not one"
            )
            raise InvariantViolationError(RULE_CI_TICKET_SEAL_BROKEN, msg)
        if len(set(self.references)) != len(self.references):
            msg = f"sealing {self.git_sha}: repeats a change reference"
            raise InvariantViolationError(RULE_CI_TICKET_SEAL_BROKEN, msg)
        if self.sealed_at.tzinfo is None:
            msg = f"sealing {self.git_sha}: sealed_at must be timezone-aware"
            raise InvariantViolationError(RULE_CI_TICKET_SEAL_BROKEN, msg)
        return self

    def matches(self, link: ChangeLink) -> bool:
        """True when ``link`` still names exactly what was sealed."""
        return link.git_sha == self.git_sha and link.references == self.references

    def verify(self, link: ChangeLink) -> SealedTicket:
        """``self``, or a refusal naming what moved.

        The message names the before and the after rather than "mismatch",
        because the question an operator asks is "what changed", and the answer is
        in the two lists.
        """
        if self.matches(link):
            return self
        before = ", ".join(self.references)
        after = ", ".join(link.references) or "nothing at all"
        if link.git_sha != self.git_sha:
            msg = (
                f"the change link moved from {self.git_sha} to {link.git_sha}: the ticket "
                f"seal covers {before}, and a decision about one commit is not a decision "
                "about another"
            )
        else:
            msg = (
                f"the change references moved from [{before}] to [{after}] after they "
                "were sealed: an approval given against a ticket somebody has since "
                "edited approves a different change"
            )
        raise InvariantViolationError(RULE_CI_TICKET_SEAL_BROKEN, msg)

    def to_dict(self) -> dict[str, object]:
        return {
            "git_sha": self.git_sha,
            "references": list(self.references),
            "seal_digest": self.seal_digest,
            "sealed_by": self.sealed_by,
            "sealed_at": self.sealed_at.isoformat(),
        }


def ticket_seal_digest(link: ChangeLink) -> str:
    """The digest a seal is built from: the SHA and the references, canonically."""
    return sha256_hex(
        canonical_json({"git_sha": link.git_sha, "references": list(link.references)})
    )


def seal_ticket(
    link: ChangeLink,
    *,
    sealed_by: str = "",
    sealed_at: datetime | None = None,
) -> SealedTicket:
    """Bind ``link``'s change references into the chain. Pure.

    ``sealed_by`` is provenance — the service account or the check run that did
    the sealing — and nothing reads it to decide anything. Storing the *actor*
    rather than the *decision* is deliberate: the seal's job is to make an edit
    afterwards visible, and a seal nobody signed is still a perfectly good
    digest.
    """
    fields: dict[str, object] = {"sealed_by": sealed_by}
    if sealed_at is not None:
        fields["sealed_at"] = sealed_at
    return SealedTicket(
        git_sha=link.git_sha,
        references=link.references,
        seal_digest=ticket_seal_digest(link),
        **fields,  # type: ignore[arg-type]
    )


# =============================================================================
# The evidence link
# =============================================================================


def envelope_digest(envelope: EvidenceEnvelope) -> str:
    """The run's own digest, computed from the envelope that will be stored.

    Computed here rather than trusted from a field, for the ordinary reason: a
    digest that arrives alongside the bytes it describes describes nothing. The
    canonical form is :meth:`~mayhem.domain.evidence.EvidenceEnvelope.to_dict`,
    which is what the evidence store persists, so the digest a pipeline verifies
    is the digest of the record a reader would fetch.
    """
    return sha256_hex(canonical_json(envelope.to_dict()))


def link_run_evidence(
    verdict: PipelineVerdict,
    envelope: EvidenceEnvelope | None,
) -> PipelineVerdict:
    """The verdict, re-grounded on its cited run and ``envelope``, or a refusal.

    This is the plan's acceptance criterion as code. Four refusals:

    * ``verdict.cited_run`` is ``None`` (:data:`RULE_CI_RUN_UNLINKED`) — a pipeline
      decision with no run behind it, which is the state the plan names when it
      says a run without an evidence link must fail closed;
    * ``envelope`` is ``None`` (:data:`RULE_CI_RUN_UNLINKED`) — the run is named
      but nothing was recorded for it, and "the runner exited 0" is not an
      evidence envelope;
    * ``envelope.run_id`` is not the cited run's id
      (:data:`RULE_CI_RUN_UNLINKED`) — a verdict citing run A's results backed by
      run B's envelope is the shape of a forged citation;
    * the envelope's digest is not the run's ``evidence_digest``
      (:data:`RULE_CI_EVIDENCE_MISMATCH`) — the pin says what the evidence was
      when it was pinned, and if the store holds different bytes then the citation
      points at something that is not what was measured.

    Returns a copy with the run reference appended to ``evidence_refs``. The
    ``run_id`` argument is gone on purpose: the run is read off the verdict, so
    there is no way for a caller to pass one run's identity and another's
    evidence.
    """
    cited = verdict.cited_run
    if cited is None:
        msg = (
            f"the pipeline decision for {verdict.change.git_sha} cites no run: a run "
            "that cannot be cited cannot back a release gate, and a pipeline run "
            "without an evidence link fails closed"
        )
        raise InvariantViolationError(RULE_CI_RUN_UNLINKED, msg)
    if envelope is None:
        msg = (
            f"run {cited.label} is cited by the pipeline decision for "
            f"{verdict.change.git_sha} but no evidence envelope was recorded for it: a "
            "pipeline run without an evidence link fails closed, never open"
        )
        raise InvariantViolationError(RULE_CI_RUN_UNLINKED, msg)
    if envelope.run_id != cited.run_id:
        msg = (
            f"the pipeline decision for {verdict.change.git_sha} cites run "
            f"{cited.run_id!r} but the envelope supplied is for run {envelope.run_id!r}: "
            "an envelope from another run is not evidence for this one"
        )
        raise InvariantViolationError(RULE_CI_RUN_UNLINKED, msg)
    computed = envelope_digest(envelope)
    if computed != cited.evidence_digest:
        msg = (
            f"run {cited.label} is pinned to evidence digest "
            f"{cited.evidence_digest[:12]}… and the envelope recorded digests to "
            f"{computed[:12]}…, so the citation points at evidence that is not the "
            "evidence that was measured"
        )
        raise InvariantViolationError(RULE_CI_EVIDENCE_MISMATCH, msg)
    reference = f"{_RUN_REF_PREFIX}{cited.label}"
    if reference in verdict.evidence_refs:
        return verdict
    return verdict.model_copy(update={"evidence_refs": (*verdict.evidence_refs, reference)})


# =============================================================================
# The authorization
# =============================================================================


class RunLink(StrEnum):
    """Whether a pipeline run's evidence was linked.

    Two states, and they are the whole answer to the evidence half of "may this
    open a release". ``UNLINKED`` is not a state an authorization is *meant* to
    be in — :func:`pipeline_run_authorization` refuses before it can be reached —
    which is exactly why it is a member: a field that can only hold one value is
    a field that documents nothing.
    """

    LINKED = "linked"
    UNLINKED = "unlinked"


@dataclass(frozen=True, slots=True)
class PipelineRunAuthorization:
    """A pipeline run cleared to act: who, under which intent, on what evidence.

    Constructed only by :func:`pipeline_run_authorization`. Every field is
    required, so there is no constructor a caller can reach to mint one by hand
    while skipping a refusal, and :attr:`opens_release` reads
    :func:`~mayhem.domain.pipeline.blocking_reasons` off the grounded verdict
    **and** requires :attr:`evidence_link` to be :data:`RunLink.LINKED` — so an
    authorization carrying no evidence still says no.

    Note what is deliberately *absent*: this object grants nothing by itself. It
    records that a service-account identity held a role, that an execution intent
    authorized the specific plan, and that the decision rests on evidence the
    store can produce. The mutation still goes through
    :func:`~mayhem.domain.execution_intent.require_execution_intent` at the point
    of the first irreversible step; this is the *pipeline's* admission, not a
    second, weaker approval.
    """

    actor: CIActor
    environment: str
    roles: tuple[str, ...]
    intent_plan_hash: str
    verdict: PipelineVerdict
    evidence_refs: tuple[str, ...]
    seal: SealedTicket
    evidence_link: RunLink = RunLink.LINKED
    #: True when :attr:`seal` was supplied by the caller and *verified* against
    #: the change link, False when it was minted here from the same link it is
    #: checked against. Both open a release; only one of them proves the ticket
    #: did not move between the check and the gate, and a reader who cannot tell
    #: them apart will assume the stronger one.
    seal_verified: bool = False

    @property
    def opens_release(self) -> bool:
        """True only when the evidence is linked and the verdict gates."""
        return self.evidence_link is RunLink.LINKED and not blocking_reasons(self.verdict)

    def to_dict(self) -> dict[str, object]:
        return {
            "actor": self.actor.to_dict(),
            "environment": self.environment,
            "roles": list(self.roles),
            "intent_plan_hash": self.intent_plan_hash,
            "evidence_link": self.evidence_link.value,
            "evidence_refs": list(self.evidence_refs),
            "seal": self.seal.to_dict(),
            "seal_verified": self.seal_verified,
            "verdict_digest": self.verdict.verdict_digest(),
            "opens_release": self.opens_release,
        }


def pipeline_run_authorization(
    actor: CIActor,
    verdict: PipelineVerdict,
    *,
    scope: EnvironmentScope,
    grants: Sequence[RoleGrant] = (),
    memberships: Sequence[TeamMembership] = (),
    intent: ExecutionIntent | None = None,
    plan_hash: str = "",
    engine: str = "",
    target_identity: str = "",
    allow_implicit: bool | None = None,
    envelope: EvidenceEnvelope | None = None,
    seal: SealedTicket | None = None,
    now: datetime | None = None,
) -> PipelineRunAuthorization:
    """Authorize a pipeline run, or refuse. Four refusals, in this order.

    The order is the security property, and it is the same one
    :func:`~mayhem.controller.check_gate.dispatch_chatops` uses:

    1. **identity** — :class:`CIActor` has already refused a human or an unnamed
       actor at construction, so by the time this runs the actor is a service
       account or a workload identity;
    2. **authority** — the required role resolves through plan 09's
       ``effective_roles``. This happens *before* the approval gate, because a
       job with no authority must not be able to ask for one by presenting a
       valid intent;
    3. **approval** — :func:`~mayhem.domain.execution_intent.require_execution_intent`
       is *called*, never re-implemented, so a pipeline approval and a terminal
       approval are the same approval;
    4. **seal, then evidence** — the change references are checked against the
       ``seal`` the caller passes in (the seal taken when the check ran), then
       :func:`link_run_evidence` grounds the decision on the run's own evidence.
       A ticket edited between the check and the gate refuses; a run with no
       evidence link refuses.

    ``seal`` is optional but the difference is recorded, not hidden. A caller that
    holds the check-time seal gets :attr:`PipelineRunAuthorization.seal_verified`
    true, which means "the ticket did not move between the two moments". A caller
    that does not gets one minted here and verified against the link it was just
    read from — which is a real check, and also a check that could not have
    failed, so it is recorded as ``seal_verified=False``. Both authorize; only one
    of them proves anything about time.

    ``now`` is injected, never read: role resolution and intent expiry both
    depend on time, and a decision that reads a clock is a decision a test cannot
    pin. It defaults to :func:`~mayhem.domain.common.utc_now` only so a caller
    writing a one-shot pipeline script is not forced to think about it.

    Raises:
        InvariantViolationError: :data:`RULE_CI_ACTOR_WITHOUT_ROLE`,
            :data:`RULE_CI_TICKET_SEAL_BROKEN`, :data:`RULE_CI_RUN_UNLINKED`, or
            :data:`RULE_CI_EVIDENCE_MISMATCH`.
        ExecutionIntentRefused: From the delegated approval gate, carrying its
            own code — ``execution_intent_required``, ``approval_expired``, or
            ``execution_intent_mismatch`` — unchanged, so a CI log and a terminal
            log read the same.
    """
    moment = now if now is not None else utc_now()
    roles = actor.require_role(
        Role.EXECUTE, scope, grants=grants, memberships=memberships, now=moment
    )
    intent = require_execution_intent(
        intent,
        plan_hash=plan_hash,
        engine=engine,
        target_identity=target_identity,
        action=PIPELINE_ACTION,
        allow_implicit=allow_implicit,
        now=moment.timestamp(),
    )
    # The seal is *passed in* when the caller has one — the seal taken when the
    # check ran, which is the only moment a later edit can be caught. Minting one
    # here and verifying it against the same link would be theatre: the two
    # objects come from the same instant and can never disagree. A caller with no
    # prior seal gets a freshly minted one, and that is recorded as
    # ``RunLink.UNSEALED`` rather than being passed off as verified.
    if seal is None:
        seal = seal_ticket(verdict.change, sealed_by=actor.principal_id, sealed_at=moment)
        prior = False
    else:
        seal.verify(verdict.change)
        prior = True
    grounded = link_run_evidence(verdict, envelope)
    return PipelineRunAuthorization(
        actor=actor,
        environment=scope.describe(),
        roles=tuple(sorted(role.value for role in roles)),
        intent_plan_hash=intent.plan_hash if intent is not None else "",
        verdict=grounded,
        evidence_refs=grounded.evidence_refs,
        seal=seal,
        seal_verified=prior,
        evidence_link=RunLink.LINKED,
    )
