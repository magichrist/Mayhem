"""The evidence envelope: the artifact a reviewer reads, and its one hard rule.

Plan 29 Phase 4's boundary. An :class:`EvidenceEnvelope` is the only shape
Mayhem hands to a human, a reviewer tool, or a downstream system, so it is the
narrowest place to say what may never be inside one: a field graded ``secret``
in :data:`mayhem.domain.secrets.EVIDENCE_FIELD_CLASSIFICATIONS`. The rule lives
here, in the domain, as a pure predicate over the envelope's own payload —
:func:`require_persistable_envelope` — because a rule that needed IO to state
could not be checked from the type, and a rule that needed a resolved value to
state would only protect the runs that happened to resolve one.

What this module deliberately does *not* do is catch a value planted under a
field name nobody graded. That is a byte scan, it needs the value the run
actually resolved, and it therefore lives in
:mod:`mayhem.infra.secret_resolver`, which is also where every write path calls
it. The two rules compose at the write boundary and neither subsumes the other.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.secrets import EVIDENCE_FIELD_CLASSIFICATIONS


class ActionOutcome(StrEnum):
    APPLIED = "applied"
    VERIFIED = "verified"
    COMPENSATED = "compensated"
    ACKNOWLEDGED_NO_BACKEND = "acknowledged_no_backend"
    REFUSED = "refused"
    FAILED = "failed"


class EvidenceEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str
    plan_hash: str
    report_id: str = ""
    plan_id: str = ""
    target_profile: str | None = None
    engine: str = ""
    safety_decisions: tuple[str, ...] = ()
    step_reports: tuple[dict[str, Any], ...] = ()
    lease_timeline: tuple[dict[str, Any], ...] = ()
    observations: tuple[dict[str, Any], ...] = ()
    verdict: str = ""
    recovery_state: str = ""
    remediation: tuple[str, ...] = ()
    environment_fingerprint: str = ""
    target_identity: str = ""
    blast_radius: dict[str, Any] = Field(default_factory=dict)
    compensation_status: str = ""
    logical_target: str = ""
    resolved_target: str = ""
    drift_status: str = ""
    k8s_context: str = ""
    k8s_namespace: str = ""
    k8s_capability_verdict: str = ""
    k8s_wait_strategy: str = ""
    k8s_recovery_guidance: str = ""
    created_at: str = ""
    engine_version: str | None = None
    topology_fingerprint: str | None = None
    verification_basis: str = "unit_tested"
    # v0.9.0: the execution intent that authorized this run (plan hash, engine,
    # target, policy, actor, approval window). ``None`` for evidence recorded by
    # a caller that did not mint an intent — e.g. a unit-level run.
    execution_intent: dict[str, Any] | None = None
    replay_digest: str = ""
    evidence_status: str = "complete"
    action_outcomes: tuple[str, ...] = ()
    redaction_metrics: dict[str, Any] = Field(default_factory=dict)
    # v0.9.0 task 13: where each observation came from, and how many criteria
    # passed. Counts and provenance only — never a raw provider payload.
    observation_provenance: dict[str, Any] = Field(default_factory=dict)
    slo_outcomes: tuple[dict[str, Any], ...] = ()
    # v0.9.0 task 16: before/after comparison proving the system returned.
    residual_impact: dict[str, Any] = Field(default_factory=dict)
    # v0.9.0 task 19: which observability spans a run emitted. Names only —
    # span attributes are redacted at the sink and never persisted here.
    emitted_spans: tuple[str, ...] = ()
    # v1.0.0 plan 03: the graded steady-state verdict and its per-signal
    # detail. Structured and JSON-safe by construction - a zero baseline
    # serialises as null with a note, never as inf/nan, because this payload
    # is hash-chained and a reader must be able to interpret every number.
    steady_state: dict[str, Any] = Field(default_factory=dict)

    def completeness_errors(self) -> list[str]:
        missing: list[str] = []
        if not self.run_id:
            missing.append("run_id missing")
        if not self.plan_hash:
            missing.append("plan_hash missing")
        if not self.verdict:
            missing.append("verdict missing")
        if len(self.step_reports) == 0:
            missing.append("step_reports empty")
        return missing

    def is_complete(self) -> bool:
        return len(self.completeness_errors()) == 0

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def require_persistable_envelope(envelope: EvidenceEnvelope, *, artifact: str = "evidence") -> None:
    """Refuse an envelope carrying a field graded ``secret``, or return.

    Pure and IO-free, so it is callable from the domain and from any write path
    without dragging the engine in. The walk is recursive and name-based, which
    is exactly :meth:`FieldClassifications.find_forbidden`'s contract: a
    ``resolved_credentials`` key nested inside one step report is refused for the
    same reason a top-level one is.

    This is the *structural* half of the boundary — it needs no run state, so it
    holds on a run that resolved nothing. The byte half, which catches a value
    under an ungraded field name, is
    :func:`mayhem.infra.secret_resolver.require_envelope_boundary`.

    Raises:
        InvariantViolationError: With
            ``mayhem.domain.secrets.REFUSAL_SECRET_FIELD_PERSISTED`` and every
            offending path named.
    """
    EVIDENCE_FIELD_CLASSIFICATIONS.require_persistable(envelope.to_dict(), path=artifact)
