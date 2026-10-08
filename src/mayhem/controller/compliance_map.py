"""Plan 20 Phase 4 — compliance mappings over sealed evidence only.

A compliance map answers one question: for a customer's control, which sealed
evidence digests address which required evidence kinds, and what is still
missing. It is a *mapping*, never a certification:

* the input is (control, evidence) pairs where each evidence record carries the
  sha256 digest of a sealed bundle — the same 64-hex shape
  :func:`mayhem.domain.advisor._is_sealed_digest` recognises. A record without
  a digest-shaped value is refused, because a mapping that cites unsealed or
  unidentified material is a claim about material nobody can re-verify.
* the output names ``supplied`` evidence kinds and ``missing`` evidence kinds.
  "Nothing missing" means every kind of evidence the template asked for was
  cited — it is a statement about the *supplied* evidence, never about
  conformance, and :func:`map_statement` says so in the same disclosure
  language :class:`~mayhem.domain.failure_modes.ComplianceControl` uses.
* the control itself must pass
  :func:`~mayhem.domain.failure_modes.require_non_asserting_template` first.
  A template that asserts compliance is refused before any mapping is read,
  so the honesty rule is enforced at both ends of the pipeline.

Pure: no clock, no file, no store. The CLI renders the answer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.failure_modes import (
    ComplianceControl,
    require_non_asserting_template,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "RULE_COMPLIANCE_DIGEST_UNSEALED",
    "RULE_COMPLIANCE_EVIDENCE_KIND_UNKNOWN",
    "ComplianceEvidence",
    "ComplianceMap",
    "build_compliance_map",
    "map_statement",
]

RULE_COMPLIANCE_DIGEST_UNSEALED = "compliance.digest_unsealed"
RULE_COMPLIANCE_EVIDENCE_KIND_UNKNOWN = "compliance.evidence_kind_unknown"

_SEALED_HEX = re.compile(r"^[0-9a-f]{64}$")


def _is_sealed_digest(value: str) -> bool:
    return bool(_SEALED_HEX.match(value.strip()))


@dataclass(frozen=True, slots=True)
class ComplianceEvidence:
    """One sealed evidence record cited against a control.

    ``evidence_kind`` must name one of the control's ``required_evidence``
    kinds (matched on containment, because the template states kinds as
    sentences such as "sealed evidence bundle digest for each run"). An exact
    enum would force the template to speak in ids and the customer to speak in
    prose; containment is the documented matching rule and it is asserted in
    the tests.
    """

    evidence_kind: str
    evidence_digest: str
    run_id: str = ""


@dataclass(frozen=True, slots=True)
class ComplianceMap:
    """What a control's evidence mapping found: supplied kinds and missing kinds."""

    control: ComplianceControl
    supplied: tuple[tuple[str, str], ...]
    missing: tuple[str, ...]

    @property
    def evidence_complete(self) -> bool:
        """True when every required kind was cited. A statement about the
        supplied evidence, never about conformance."""
        return not self.missing

    @property
    def cited_digests(self) -> tuple[str, ...]:
        return tuple(digest for _, digest in self.supplied)


def build_compliance_map(
    control: ComplianceControl,
    evidence: Sequence[ComplianceEvidence],
) -> ComplianceMap:
    """Map sealed evidence digests onto a control's required evidence kinds.

    Raises:
        InvariantViolationError: the control asserts compliance
            (``compliance.template_must_not_assert`` and friends, from
            :func:`require_non_asserting_template`), an evidence record cites
            a non-digest value (``compliance.digest_unsealed``), or a record
            names a kind the control does not ask for
            (``compliance.evidence_kind_unknown``).
    """
    require_non_asserting_template(control)
    supplied: list[tuple[str, str]] = []
    covered: set[str] = set()
    for record in evidence:
        if not _is_sealed_digest(record.evidence_digest):
            raise InvariantViolationError(
                RULE_COMPLIANCE_DIGEST_UNSEALED,
                f"evidence for kind {record.evidence_kind!r} cites "
                f"{record.evidence_digest!r}, which is not a sealed sha256 digest: "
                "a mapping may only cite sealed evidence a verifier can re-check",
            )
        matched = next(
            (
                kind
                for kind in control.required_evidence
                if record.evidence_kind.strip().lower() in kind.strip().lower()
                or kind.strip().lower() in record.evidence_kind.strip().lower()
            ),
            None,
        )
        if matched is None:
            raise InvariantViolationError(
                RULE_COMPLIANCE_EVIDENCE_KIND_UNKNOWN,
                f"evidence kind {record.evidence_kind!r} is not one of the kinds "
                f"{control.framework} {control.control_id!r} asks for: a mapping "
                "may only cite evidence the template requested",
            )
        supplied.append((matched, record.evidence_digest.strip()))
        covered.add(matched)
    missing = tuple(kind for kind in control.required_evidence if kind not in covered)
    return ComplianceMap(control=control, supplied=tuple(supplied), missing=missing)


def map_statement(mapped: ComplianceMap) -> str:
    """The only sentence a compliance map may produce about conformance.

    Structurally incapable of asserting compliance: it names the control, the
    cited digests, what is still missing, and it says plainly that the map is
    not a finding. Every branch ends in the same disclosure.
    """
    control = mapped.control
    cited = ", ".join(f"{digest[:12]}…" for digest in mapped.cited_digests) or "none cited"
    missing = "; ".join(mapped.missing) or "none — every requested kind was cited"
    return (
        f"{control.framework} {control.control_id} ({control.title}): "
        f"{len(mapped.supplied)} sealed evidence record(s) cited ({cited}); "
        f"missing evidence kinds: {missing}. "
        f"{control.statement()}"
    )
