"""The Terraform surface: ``mayhem_experiment`` as a resource over plan 08's API
(docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md, Phase 3).

The plan's GitOps half asks for a Terraform resource so an experiment is
declared next to the infrastructure it drills rather than in a wiki. That is a
reasonable ask with one sharp edge: **Terraform's model of the world is a plan,
and a plan is a promise about state that may already have moved.** Every function
here exists to make that promise checkable rather than assumed.

Three commitments shape the code.

**Reading is the only thing ``plan`` does, and it may fail.** A Terraform
resource that cannot read its current state has nothing to diff against, so
:func:`terraform_plan` calls ``read_experiment`` and refuses
(:data:`RULE_TF_STATE_UNREADABLE`) when the API cannot answer. It refuses *rather
than treating the world as empty*, because "I could not ask whether this
experiment exists" and "this experiment does not exist" are different facts and
conflating them makes a re-created experiment look like a fresh one — silently
orphaning whatever the old one was attached to.

**A ``None`` from ``read_experiment`` means *absent*, not *unavailable*.** That
split is the whole honesty story of the port, and it is the same one
:func:`~mayhem.controller.preflight_gate.port_status` makes: a system that
answers "none open" has certified something; a system that could not be reached
has certified nothing. :func:`api_reach` is the total function that decides it,
and an unbound port, a raising port, a port answering in the wrong shape and a
port answering ``None`` are three different findings — respectively *unavailable*,
*unavailable*, *unavailable*, and *absent*.

**``apply`` re-reads and refuses on drift.** :func:`terraform_apply` re-reads the
resource before writing and compares the digest against what
:func:`terraform_plan` observed. If they differ, it refuses
(:data:`RULE_TF_PLAN_STALE`) and writes nothing. This is the Terraform analogue
of the plan-16 negative control — *a merged plan that differs from the checked
plan invalidates prior approvals* — and it is deliberately implemented rather
than documented, because a Terraform run is exactly where a human reads "apply"
as "do what you said".

There is no ``terraform`` binary here and no HTTP client. :class:`ExperimentApiPort`
is a structural protocol the caller implements over plan 08's own service, and
the round-trip is proven against a fake that speaks
:class:`~mayhem.domain.api.ExperimentResource` — including a write that comes
back with a *different* digest, which is refused as unconfirmed
(:data:`RULE_TF_WRITE_UNCONFIRMED`).

.. warning::

   **No ``terraform apply`` has ever run against a real state file.** What is
   tested is the decision logic: plan, drift refusal, and the round trip
   read → write → read over a fake API. Terraform's own plugin handshake, state
   locking, and ``terraform plan`` output format are *not* modelled here, and a
   reader should not mistake a passing conformance test for a working plugin.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol

from mayhem.domain.api import ExperimentResource, spec_digest_of
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import canonical_json, sha256_hex

if TYPE_CHECKING:
    from mayhem.domain.experiments import DrillSpec

__all__ = [
    "RULE_TF_INVALID_NAME",
    "RULE_TF_PLAN_STALE",
    "RULE_TF_STATE_UNREADABLE",
    "RULE_TF_TOKEN_IN_CONFIG",
    "RULE_TF_WRITE_UNCONFIRMED",
    "TF_PROVIDER_NAME",
    "TF_RESOURCE_TYPE",
    "ApiReach",
    "ExperimentApiPort",
    "ExperimentConfig",
    "TerraformApplyResult",
    "TerraformChange",
    "TerraformPlan",
    "TerraformRefusedError",
    "api_reach",
    "conformance_reasons",
    "parse_import_id",
    "render_hcl",
    "terraform_apply",
    "terraform_plan",
]

TF_PROVIDER_NAME: Final[str] = "mayhem"
TF_RESOURCE_TYPE: Final[str] = "mayhem_experiment"

RULE_TF_INVALID_NAME = "terraform.invalid_resource_label"
RULE_TF_STATE_UNREADABLE = "terraform.state_unreadable"
RULE_TF_PLAN_STALE = "terraform.plan_stale"
RULE_TF_WRITE_UNCONFIRMED = "terraform.write_unconfirmed"
RULE_TF_TOKEN_IN_CONFIG = "terraform.credential_in_config"

_IMPORT_PREFIX: Final[str] = f"{TF_RESOURCE_TYPE}/"
_LABEL_CHARS: Final[frozenset[str]] = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789_-"
)
#: An HCL identifier starts with a letter or an underscore. Enforced here rather
#: than left to terraform, which rejects it deep inside a parse with a message
#: that says nothing about mayhem.
_LABEL_FIRST: Final[frozenset[str]] = frozenset("abcdefghijklmnopqrstuvwxyz_")


class TerraformRefusedError(InvariantViolationError):
    """A Terraform operation refused, carrying the rule that refused it.

    An :class:`~mayhem.domain.errors.InvariantViolationError` so the CLI error
    surface renders it unchanged and so a caller catching the other plan-16
    refusals catches this one too.
    """


class ApiReach(StrEnum):
    """What a read of the API established.

    Three states, and the middle one is the reason this enum exists: ``ABSENT``
    is a *reachable* answer, and collapsing it into ``UNAVAILABLE`` would make a
    real create indistinguishable from a lost connection.
    """

    REACHABLE = "reachable"
    ABSENT = "absent"
    UNAVAILABLE = "unavailable"


def api_reach(answer: object | None, *, error: BaseException | None = None) -> ApiReach:
    """The reach a read implies — pure, total, and the only place it is decided.

    ==================================  ==============
    read answer                          reach
    ==================================  ==============
    an :class:`~mayhem.domain.api.ExperimentResource`  ``REACHABLE``
    ``None`` (no such experiment)       ``ABSENT``
    raised                               ``UNAVAILABLE``
    any other shape                      ``UNAVAILABLE``
    ==================================  ==============

    The last row matters as much as the first. The protocol is structural, so
    nothing stops an adapter that answers with a dict; reading ``.spec_digest``
    off it would raise out of the middle of a plan, where the honest answer is
    "this witness cannot speak", which refuses.
    """
    if error is not None:
        return ApiReach.UNAVAILABLE
    if answer is None:
        return ApiReach.ABSENT
    if not isinstance(answer, ExperimentResource):
        return ApiReach.UNAVAILABLE
    return ApiReach.REACHABLE


# =============================================================================
# The resource configuration
# =============================================================================


@dataclass(frozen=True, slots=True)
class ExperimentConfig:
    """One declared ``mayhem_experiment`` resource.

    ``api_token`` exists only so it can be **refused**
    (:data:`RULE_TF_TOKEN_IN_CONFIG`). Terraform state is plaintext on disk and in
    the backend, so a token in a provider block is a token in a bucket; refusing
    it here is cheaper than explaining that afterwards. The credential belongs in
    the environment the provider reads, and mayhem says so in the message.

    The label (``tf_label``) is validated separately from the experiment name
    because Terraform identifiers and mayhem names have different rules: a
    Terraform label cannot start with a digit and cannot contain a dash, and a
    config that violates that fails deep inside Terraform with a message that
    says nothing about mayhem.
    """

    name: str
    spec: DrillSpec
    tf_label: str = ""
    api_endpoint: str = ""
    api_token: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise InvariantViolationError(
                RULE_TF_INVALID_NAME, "a mayhem_experiment resource must name an experiment"
            )
        if self.spec.name != self.name:
            msg = (
                f"resource declares experiment {self.name!r} but its spec is named "
                f"{self.spec.name!r}: mayhem refuses to declare one resource holding "
                "two names, because the API would store the spec's name and the "
                "resource would manage a name that is not there"
            )
            raise InvariantViolationError(RULE_TF_INVALID_NAME, msg)
        label = self.tf_label or self.name
        if not label or label[0] not in _LABEL_FIRST or any(c not in _LABEL_CHARS for c in label):
            msg = (
                f"terraform label {label!r} is not a valid identifier: use lowercase "
                "letters, digits, '_' and '-', and do not start with a digit"
            )
            raise InvariantViolationError(RULE_TF_INVALID_NAME, msg)
        if self.api_token.strip():
            msg = (
                f"resource {label!r} carries an api_token: terraform state is plaintext "
                "in the backend and on disk, so a token here is a token in a bucket. "
                "Read it from the environment instead (MAYHEM_API_TOKEN) and leave "
                "this empty"
            )
            raise InvariantViolationError(RULE_TF_TOKEN_IN_CONFIG, msg)

    @property
    def label(self) -> str:
        return self.tf_label or self.name

    @property
    def address(self) -> str:
        """``mayhem_experiment.<label>`` — the Terraform address."""
        return f"{TF_RESOURCE_TYPE}.{self.label}"

    @property
    def import_id(self) -> str:
        """``mayhem_experiment/<name>`` — the id ``terraform import`` accepts."""
        return f"{_IMPORT_PREFIX}{self.name}"

    @property
    def spec_digest(self) -> str:
        return spec_digest_of(self.spec)

    def to_resource(self) -> ExperimentResource:
        """The plan-08 resource this config declares. Round-trips by construction."""
        return ExperimentResource.of(self.spec)

    def to_dict(self) -> dict[str, object]:
        return {
            "address": self.address,
            "name": self.name,
            "spec_digest": self.spec_digest,
            "api_endpoint": self.api_endpoint,
        }


def parse_import_id(value: str) -> str:
    """The experiment name in a ``mayhem_experiment/<name>`` import id.

    Refuses a bare name and a second slash. A bare name is refused because the
    import id is the *only* place a caller can widen a resource's scope by
    accident, and ``terraform import mayhem_experiment.checkout checkout`` reads
    as if it worked; it does not, and the failure lands in the state file.
    """
    if not value.startswith(_IMPORT_PREFIX):
        msg = (
            f"import id {value!r} is not a mayhem_experiment id: the form is "
            f"{TF_RESOURCE_TYPE}/<experiment-name>"
        )
        raise InvariantViolationError(RULE_TF_INVALID_NAME, msg)
    name = value[len(_IMPORT_PREFIX) :]
    if not name.strip() or "/" in name:
        msg = (
            f"import id {value!r} does not name exactly one experiment: the form is "
            f"{TF_RESOURCE_TYPE}/<experiment-name>"
        )
        raise InvariantViolationError(RULE_TF_INVALID_NAME, msg)
    return name


def render_hcl(config: ExperimentConfig) -> str:
    """Render the ``.tf`` body for ``config``. Deterministic, and inert.

    No interpolation of mayhem values into HCL beyond the JSON-encoded spec,
    which is emitted through :func:`json.dumps` with sorted keys and no shell
    involved at all — a Terraform file is not a shell script, and the failure mode
    this module is most careful about is confined to the *workflow* generator in
    :mod:`mayhem.controller.ci_surface`.
    """
    spec_json = json.dumps(config.spec.model_dump(mode="json", exclude_none=True), sort_keys=True)
    escaped = spec_json.replace("\\", "\\\\").replace('"', '\\"')
    lines = [
        "# Generated by `mayhem ci terraform-config`. Do not edit by hand.",
        "#",
        "# The credential is NOT in this file and must not be: terraform state is",
        "# plaintext, so a token in a provider block is a token in a bucket.",
        "terraform {",
        "  required_providers {",
        f'    {TF_PROVIDER_NAME} = {{',
        '      source  = "mayhemlabs/mayhem"',
        '      version = "~> 2.4"',
        "    }",
        "  }",
        "}",
        "",
        f'resource "{TF_RESOURCE_TYPE}" "{config.label}" {{',
        f"  name         = {json.dumps(config.name)}",
        f"  spec_digest  = {json.dumps(config.spec_digest)}",
        f"  spec         = {json.dumps(escaped)}",
        "}",
        "",
    ]
    if config.api_endpoint:
        lines.insert(
            1,
            f"# endpoint: {config.api_endpoint} "
            "(a variable in a real configuration; recorded here for review)",
        )
    return "\n".join(lines)


# =============================================================================
# The port
# =============================================================================


class ExperimentApiPort(Protocol):
    """What an adapter over plan 08's API implements. Three methods.

    ``read_experiment`` returns ``object | None`` on purpose: ``None`` is the API
    saying "no experiment by that name", which is a reachable answer, and a
    protocol typed ``-> ExperimentResource`` would force an adapter to invent a
    sentinel and would hide the distinction this module is built on.

    The other two return ``object`` because mayhem *checks* what comes back: a
    write that does not echo the resource it was handed is an unconfirmed write,
    not a success.
    """

    def read_experiment(self, *, name: str) -> object | None: ...

    def write_experiment(self, *, resource: ExperimentResource) -> object: ...

    def delete_experiment(self, *, name: str) -> object: ...


def _read(port: ExperimentApiPort | None, name: str) -> tuple[ExperimentResource | None, ApiReach]:
    """One read, and the reach it established. Never raises."""
    if port is None:
        return None, ApiReach.UNAVAILABLE
    error: BaseException | None = None
    answer: object | None = None
    try:
        answer = port.read_experiment(name=name)
    except Exception as exc:  # any failure means "no answer", and that is the point
        error = exc
    reach = api_reach(answer, error=error)
    if reach is not ApiReach.REACHABLE:
        return None, reach
    assert isinstance(answer, ExperimentResource)
    return answer, reach


# =============================================================================
# Plan and apply
# =============================================================================


class TerraformChange(StrEnum):
    """What the plan proposes. Four states, no fifth."""

    CREATE = "create"
    UPDATE = "update"
    NO_OP = "no_op"
    DESTROY = "destroy"


@dataclass(frozen=True, slots=True)
class TerraformPlan:
    """A computed plan: the change, the state it was computed against, and a digest.

    :attr:`observed_digest` is the load-bearing field. It is the fingerprint of
    the API state this plan was derived from, and :func:`terraform_apply` refuses
    unless the state still has it. A plan without it would be a set of intentions
    with no memory of what it assumed.
    """

    address: str
    name: str
    change: TerraformChange
    desired: ExperimentResource
    observed_digest: str
    config_digest: str

    @property
    def plan_digest(self) -> str:
        """Digest over the plan itself: address, change, both digests, the resource."""
        return sha256_hex(
            canonical_json(
                {
                    "address": self.address,
                    "name": self.name,
                    "change": self.change.value,
                    "desired": self.desired.to_payload(),
                    "observed": self.observed_digest,
                    "config": self.config_digest,
                }
            )
        )

    @property
    def has_change(self) -> bool:
        return self.change is not TerraformChange.NO_OP

    def to_dict(self) -> dict[str, object]:
        return {
            "address": self.address,
            "name": self.name,
            "change": self.change.value,
            "observed_digest": self.observed_digest,
            "config_digest": self.config_digest,
            "plan_digest": self.plan_digest,
            "desired_spec_digest": self.desired.spec_digest,
        }


@dataclass(frozen=True, slots=True)
class TerraformApplyResult:
    """What the apply did, and the state it left behind."""

    address: str
    change: TerraformChange
    resource: ExperimentResource
    confirmed: bool
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "address": self.address,
            "change": self.change.value,
            "confirmed": self.confirmed,
            "spec_digest": self.resource.spec_digest,
            "detail": self.detail,
        }


#: Digest standing for "the API said this experiment does not exist". A distinct
#: sentinel rather than the empty string, because an empty digest and an absent
#: resource are different facts and the plan's ``observed_digest`` should say which.
ABSENT_DIGEST: Final[str] = "-" * 64


def terraform_plan(
    config: ExperimentConfig,
    *,
    port: ExperimentApiPort | None,
    destroy: bool = False,
) -> TerraformPlan:
    """Compute the plan for ``config``, or refuse. Fails closed on a silent API.

    Raises:
        TerraformRefusedError: When the API cannot be read
            (:data:`RULE_TF_STATE_UNREADABLE`). The plan is *not* returned as a
            create: an unreadable state is not an absent one.
    """
    desired = config.to_resource()
    observed, reach = _read(port, config.name)
    if reach is ApiReach.UNAVAILABLE:
        msg = (
            f"cannot plan {config.address}: the experiment API could not be read "
            f"({_read_detail(port, config.name)}), so mayhem cannot tell whether "
            f"{config.name!r} exists. A state that could not be read is not an "
            "absent state, and planning a create against it would orphan whatever "
            "is already there"
        )
        raise TerraformRefusedError(RULE_TF_STATE_UNREADABLE, msg)
    if destroy:
        if observed is None:
            msg = (
                f"cannot plan a destroy of {config.address}: the API says "
                f"{config.name!r} does not exist, so there is nothing to destroy"
            )
            raise TerraformRefusedError(RULE_TF_STATE_UNREADABLE, msg)
        change = TerraformChange.DESTROY
    elif observed is None:
        change = TerraformChange.CREATE
    elif observed.spec_digest == desired.spec_digest:
        change = TerraformChange.NO_OP
    else:
        change = TerraformChange.UPDATE
    return TerraformPlan(
        address=config.address,
        name=config.name,
        change=change,
        desired=desired,
        observed_digest=ABSENT_DIGEST if observed is None else _resource_digest(observed),
        config_digest=config.spec_digest,
    )


def _read_detail(port: ExperimentApiPort | None, name: str) -> str:
    """Why the last read of ``name`` produced nothing, in one clause."""
    if port is None:
        return "no API port is bound"
    try:
        port.read_experiment(name=name)
    except Exception as exc:
        return f"the port raised {type(exc).__name__}: {exc}"
    return "the port answered in a shape that is not an ExperimentResource"


def _resource_digest(resource: ExperimentResource) -> str:
    """A digest over the resource's own wire form — its identity in the API."""
    return sha256_hex(canonical_json(resource.to_payload()))


def terraform_apply(
    plan: TerraformPlan,
    *,
    port: ExperimentApiPort | None,
) -> TerraformApplyResult:
    """Apply ``plan``, re-reading first and refusing on drift.

    The re-read is the point, and it is what makes this function different from
    "write whatever the plan says": between :func:`terraform_plan` and this call,
    somebody may have changed the experiment. Applying then would overwrite their
    change with a plan computed before it, and the resulting state file would
    carry no trace that it ever disagreed with anybody.

    Raises:
        TerraformRefusedError: On an unreadable API
            (:data:`RULE_TF_STATE_UNREADABLE`), on drift
            (:data:`RULE_TF_PLAN_STALE`), or on a write the API did not echo back
            (:data:`RULE_TF_WRITE_UNCONFIRMED`).
    """
    observed, reach = _read(port, plan.name)
    if reach is ApiReach.UNAVAILABLE:
        msg = (
            f"refusing to apply {plan.address}: the experiment API could not be read "
            f"({_read_detail(port, plan.name)}), and mayhem will not write on the "
            "strength of a state it could not see"
        )
        raise TerraformRefusedError(RULE_TF_STATE_UNREADABLE, msg)
    current = ABSENT_DIGEST if observed is None else _resource_digest(observed)
    if current != plan.observed_digest:
        msg = (
            f"refusing to apply {plan.address}: the plan was computed against state "
            f"{plan.observed_digest[:12]}… and the API now holds {current[:12]}…, so "
            "the plan is stale. Re-plan; an apply that acts on a plan whose "
            "assumptions moved is how one pipeline overwrites another"
        )
        raise TerraformRefusedError(RULE_TF_PLAN_STALE, msg)

    if plan.change is TerraformChange.NO_OP:
        assert observed is not None
        return TerraformApplyResult(
            address=plan.address,
            change=plan.change,
            resource=observed,
            confirmed=True,
            detail=f"{plan.name} already matches the declared spec; nothing was written",
        )

    if plan.change is TerraformChange.DESTROY:
        if port is None:  # unreachable: _read already refused, kept for the checker
            msg = f"refusing to destroy {plan.address}: no API port is bound"
            raise TerraformRefusedError(RULE_TF_STATE_UNREADABLE, msg)
        try:
            port.delete_experiment(name=plan.name)
        except Exception as exc:
            msg = f"the delete of {plan.name!r} raised {type(exc).__name__}: {exc}"
            raise TerraformRefusedError(RULE_TF_WRITE_UNCONFIRMED, msg) from exc
        return TerraformApplyResult(
            address=plan.address,
            change=plan.change,
            resource=plan.desired,
            confirmed=False,
            detail=f"{plan.name} was deleted; the result carries no current resource",
        )

    if port is None:  # unreachable: _read already refused, kept for the checker
        msg = f"refusing to write {plan.address}: no API port is bound"
        raise TerraformRefusedError(RULE_TF_STATE_UNREADABLE, msg)
    try:
        answer = port.write_experiment(resource=plan.desired)
    except Exception as exc:
        msg = (
            f"the write of {plan.name!r} raised {type(exc).__name__}: {exc}, so mayhem "
            "cannot confirm the experiment was stored"
        )
        raise TerraformRefusedError(RULE_TF_WRITE_UNCONFIRMED, msg) from exc
    if not isinstance(answer, ExperimentResource) or answer.spec_digest != (
        plan.desired.spec_digest
    ):
        echoed = (
            f"{type(answer).__name__}"
            if not isinstance(answer, ExperimentResource)
            else f"spec digest {answer.spec_digest[:12]}…"
        )
        msg = (
            f"the API accepted {plan.name!r} but returned {echoed}, not the "
            f"{plan.desired.spec_digest[:12]}… that was written: mayhem reports an "
            "unconfirmed write rather than a success it cannot re-derive"
        )
        raise TerraformRefusedError(RULE_TF_WRITE_UNCONFIRMED, msg)
    return TerraformApplyResult(
        address=plan.address,
        change=plan.change,
        resource=answer,
        confirmed=True,
        detail=f"{plan.name} stored as {answer.spec_digest[:12]}… ({plan.change.value})",
    )


def conformance_reasons(config: ExperimentConfig, observed: object | None) -> tuple[str, ...]:
    """Why the stored experiment does not conform to ``config``, in sentences.

    Every reason is citable, and the empty tuple is the only passing answer — so
    a conformance check that cannot decide has to say so rather than return empty.
    ``observed`` of the wrong shape, or absent, is *not* conformance: those are
    the two failures this function exists to report.
    """
    reasons: list[str] = []
    if observed is None:
        return (
            f"the API reports no experiment named {config.name!r}, but the "
            "configuration declares one",
        )
    if not isinstance(observed, ExperimentResource):
        return (
            f"the API returned {type(observed).__name__} for {config.name!r}, which is "
            "not an ExperimentResource, so conformance cannot be evaluated",
        )
    if observed.name != config.name:
        reasons.append(f"the stored experiment is named {observed.name!r}")
    if observed.spec_digest != config.spec_digest:
        reasons.append(
            f"the stored spec digest is {observed.spec_digest[:12]}… and the "
            f"configuration declares {config.spec_digest[:12]}…"
        )
    return tuple(reasons)
